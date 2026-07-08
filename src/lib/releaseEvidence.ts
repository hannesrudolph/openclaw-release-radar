import { createHash, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { inflateRawSync } from 'node:zlib';
import { config } from '../config';
import { createAbortError, throwIfAborted } from './cooperativeCancellation';

const USER_AGENT = 'openclaw-release-radar';
const RELEASE_EVIDENCE_REPO = 'releases';
const FULL_VALIDATION_WORKFLOW_NAME = 'Full Release Validation';
const FULL_VALIDATION_WORKFLOW_PATH = '.github/workflows/full-release-validation.yml';
const FULL_VALIDATION_EVENT = 'workflow_dispatch';
const FULL_VALIDATION_MANIFEST = 'full-release-validation-manifest.json';

const REQUEST_TIMEOUT_MS = 15_000;
const TOTAL_TIMEOUT_MS = 45_000;
const MAX_REQUESTS = 10;
const MAX_ARTIFACT_REDIRECTS = 2;
const MAX_PRIMARY_BODY_BYTES = 1_048_576;
const MAX_API_BODY_BYTES = 1_048_576;
const MAX_ERROR_BODY_BYTES = 8_192;
const MAX_ARCHIVE_BYTES = 16_777_216;
const MAX_TOTAL_BODY_BYTES = 20_971_520;
const MAX_ZIP_ENTRIES = 32;
const MAX_ZIP_ENTRY_NAME_BYTES = 256;
const MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES = 524_288;
const MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 1_048_576;
const MAX_COMPRESSION_RATIO = 200;

export interface EvidenceReportVerification {
  url: string | null;
  rawUrl: string | null;
  fallbackUrl: string | null;
  fallbackKind: 'github_actions_run' | null;
  fallbackArtifactCount: number;
  contentDigest: string | null;
  fallbackArtifactDigest: string | null;
  expectedReleaseTag: string | null;
  expectedReleaseSha: string | null;
  verified: boolean;
  mismatch: string | null;
}

export interface EvidenceReportVerificationOptions {
  expectedReleaseTag?: string | null;
  expectedReleaseSha?: string | null;
  signal?: AbortSignal;
  requestTimeoutMs?: number;
}

interface ExpectedReleaseIdentity {
  tag: string;
  version: string;
  sha: string;
}

interface VerifiedActionRun {
  id: string;
  attempt: string;
  headSha: string;
  headBranch: string;
  repositoryId: number;
}

class VerificationFailure extends Error {}

class VerificationBudget {
  private requests = 0;
  private bodyBytes = 0;
  private decompressedBytes = 0;
  private readonly deadline: number;
  private readonly requestTimeoutMs: number;

  constructor(
    readonly signal?: AbortSignal,
    requestTimeoutMs = REQUEST_TIMEOUT_MS,
  ) {
    if (
      !Number.isInteger(requestTimeoutMs) ||
      requestTimeoutMs <= 0 ||
      requestTimeoutMs > REQUEST_TIMEOUT_MS
    ) {
      throw new Error(
        `release evidence requestTimeoutMs must be an integer from 1 to ` +
        `${REQUEST_TIMEOUT_MS}, got ${String(requestTimeoutMs)}`,
      );
    }
    this.requestTimeoutMs = requestTimeoutMs;
    this.deadline = Date.now() + TOTAL_TIMEOUT_MS;
  }

  takeRequest(): number {
    throwIfAborted(this.signal);
    this.requests += 1;
    if (this.requests > MAX_REQUESTS) {
      throw new VerificationFailure(`request budget exceeded (${MAX_REQUESTS})`);
    }
    const remainingMs = this.deadline - Date.now();
    if (remainingMs <= 0) throw new VerificationFailure('request deadline exceeded');
    return Math.max(1, Math.min(this.requestTimeoutMs, remainingMs));
  }

  takeBody(bytes: number): void {
    throwIfAborted(this.signal);
    this.bodyBytes += bytes;
    if (this.bodyBytes > MAX_TOTAL_BODY_BYTES) {
      throw new VerificationFailure(`response body budget exceeded (${MAX_TOTAL_BODY_BYTES} bytes)`);
    }
  }

  takeDecompressed(bytes: number): void {
    throwIfAborted(this.signal);
    this.decompressedBytes += bytes;
    if (this.decompressedBytes > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES) {
      throw new VerificationFailure(
        `ZIP decompression budget exceeded (${MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES} bytes)`,
      );
    }
  }
}

export function rawGitHubUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.hostname.toLowerCase() !== 'github.com') return url;
    const parts = parsed.pathname.split('/').filter(Boolean);
    if (parts.length >= 5 && parts[2] === 'blob') {
      const [owner, repo, , branch, ...path] = parts;
      return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path.join('/')}`;
    }
  } catch {
    return url;
  }
  return url;
}

export async function verifyEvidenceReportUrl(
  url: string | null,
  fallbackActionRunUrl: string | null = null,
  options: EvidenceReportVerificationOptions = {},
): Promise<EvidenceReportVerification> {
  const expectedBinding = canonicalExpectedReleaseBinding(options);
  if (!url) {
    if (fallbackActionRunUrl) {
      return verifyActionRunFallback({
        url,
        rawUrl: null,
        fallbackActionRunUrl,
        options,
        budget: new VerificationBudget(options.signal, options.requestTimeoutMs),
      });
    }
    return verificationResult({
      url: null,
      rawUrl: null,
      ...expectedBinding,
    });
  }

  const budget = new VerificationBudget(options.signal, options.requestTimeoutMs);
  let rawUrl: string | null = null;
  try {
    const expected = expectedReleaseIdentity(options);
    rawUrl = structuredEvidenceUrl(url, expected);
    const fetched = await fetchWithRedirectPolicy(
      rawUrl,
      {
        headers: { 'user-agent': USER_AGENT },
      },
      budget,
      0,
      assertPrimaryEvidenceUrl,
    );
    try {
      if (fetched.response.status === 404) {
        cancelResponseBody(fetched.response, 'release evidence report not found');
        if (fallbackActionRunUrl) {
          return verifyActionRunFallback({
            url,
            rawUrl,
            fallbackActionRunUrl,
            options,
            budget,
          });
        }
        return verificationResult({
          url,
          rawUrl,
          ...expectedBinding,
          mismatch: 'release evidence report not found',
        });
      }
      if (!fetched.response.ok) {
        const detail = await responseErrorDetail(
          fetched.response,
          budget,
          fetched.signal,
        );
        throw new VerificationFailure(
          `release evidence report ${fetched.response.status}${detail ? `: ${detail}` : ''}`,
        );
      }

      const body = await readLimitedBody(
        fetched.response,
        MAX_PRIMARY_BODY_BYTES,
        'release evidence report',
        budget,
        fetched.signal,
      );
      const report = parseJsonObject(body, 'release evidence report');
      validateStructuredEvidenceReport(report, expected);
      return verificationResult({
        url,
        rawUrl,
        expectedReleaseTag: expected.tag,
        expectedReleaseSha: expected.sha,
        verified: true,
        contentDigest: sha256Digest(body),
      });
    } finally {
      fetched.dispose();
    }
  } catch (error) {
    if (!(error instanceof VerificationFailure)) throw error;
    return verificationResult({
      url,
      rawUrl,
      ...expectedBinding,
      mismatch: `release evidence report rejected: ${error.message}`,
    });
  }
}

function verificationResult(input: {
  url: string | null;
  rawUrl: string | null;
  fallbackUrl?: string | null;
  fallbackKind?: 'github_actions_run' | null;
  fallbackArtifactCount?: number;
  contentDigest?: string | null;
  fallbackArtifactDigest?: string | null;
  expectedReleaseTag?: string | null;
  expectedReleaseSha?: string | null;
  verified?: boolean;
  mismatch?: string | null;
}): EvidenceReportVerification {
  return {
    url: input.url,
    rawUrl: input.rawUrl,
    fallbackUrl: input.fallbackUrl ?? null,
    fallbackKind: input.fallbackKind ?? null,
    fallbackArtifactCount: input.fallbackArtifactCount ?? 0,
    contentDigest: input.contentDigest ?? null,
    fallbackArtifactDigest: input.fallbackArtifactDigest ?? null,
    expectedReleaseTag: input.expectedReleaseTag ?? null,
    expectedReleaseSha: input.expectedReleaseSha ?? null,
    verified: input.verified ?? false,
    mismatch: input.mismatch ?? null,
  };
}

function canonicalExpectedReleaseBinding(
  options: EvidenceReportVerificationOptions,
): Pick<EvidenceReportVerification, 'expectedReleaseTag' | 'expectedReleaseSha'> {
  const tag = options.expectedReleaseTag?.trim() ?? '';
  const sha = options.expectedReleaseSha?.trim().toLowerCase() ?? '';
  return {
    expectedReleaseTag:
      /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(tag) ? tag : null,
    expectedReleaseSha: /^[0-9a-f]{40}$/.test(sha) ? sha : null,
  };
}

function expectedReleaseIdentity(
  options: EvidenceReportVerificationOptions,
): ExpectedReleaseIdentity {
  const tag = options.expectedReleaseTag?.trim() ?? '';
  const sha = options.expectedReleaseSha?.trim().toLowerCase() ?? '';
  if (!tag || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(tag)) {
    throw new VerificationFailure('expected release tag is missing or invalid');
  }
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new VerificationFailure('expected release SHA must be a full 40-character commit SHA');
  }
  return {
    tag,
    version: tag.replace(/^v/, ''),
    sha,
  };
}

function structuredEvidenceUrl(input: string, expected: ExpectedReleaseIdentity): string {
  let original: URL;
  try {
    original = new URL(input);
  } catch {
    throw new VerificationFailure('URL is invalid');
  }
  assertHttpsPublicUrl(original);
  if (original.search || original.hash) {
    throw new VerificationFailure('URL query strings and fragments are not allowed');
  }

  const raw = rawGitHubUrl(original.toString());
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new VerificationFailure('raw URL is invalid');
  }
  assertPrimaryEvidenceUrl(parsed);
  const parts = safePathSegments(parsed);
  if (parts.length !== 6) {
    throw new VerificationFailure('URL must identify one release-evidence file');
  }
  const [owner, repo, ref, evidenceDirectory, releaseId, filename] = parts;
  if (owner.toLowerCase() !== config.github.owner.toLowerCase()
    || repo.toLowerCase() !== RELEASE_EVIDENCE_REPO) {
    throw new VerificationFailure(
      `URL must use ${config.github.owner}/${RELEASE_EVIDENCE_REPO}`,
    );
  }
  if (ref !== 'main' && !/^[0-9a-f]{40}$/i.test(ref)) {
    throw new VerificationFailure('URL ref must be main or an immutable commit SHA');
  }
  if (evidenceDirectory !== 'evidence' || releaseId !== expected.version) {
    throw new VerificationFailure(`URL release identity does not match ${expected.tag}`);
  }
  if (filename !== 'release-evidence.md' && filename !== 'release-evidence.json') {
    throw new VerificationFailure('URL must end in release-evidence.md or release-evidence.json');
  }
  parts[5] = 'release-evidence.json';
  parsed.pathname = `/${parts.map(encodeURIComponent).join('/')}`;
  return parsed.toString();
}

function validateStructuredEvidenceReport(
  report: Record<string, unknown>,
  expected: ExpectedReleaseIdentity,
): void {
  if (report.schemaVersion !== 1) {
    throw new VerificationFailure('structured evidence schemaVersion must be 1');
  }

  const generatedBy = recordField(report, 'generatedBy', 'structured evidence');
  if (stringField(generatedBy, 'repository', 'structured evidence generatedBy').toLowerCase()
    !== `${config.github.owner}/${RELEASE_EVIDENCE_REPO}`.toLowerCase()) {
    throw new VerificationFailure('structured evidence generator repository is not trusted');
  }

  const release = recordField(report, 'release', 'structured evidence');
  if (stringField(release, 'id', 'structured evidence release') !== expected.version
    || stringField(release, 'ref', 'structured evidence release') !== expected.tag) {
    throw new VerificationFailure('structured evidence release tag does not match');
  }

  const provenance = recordField(report, 'provenance', 'structured evidence');
  const releaseRef = recordField(provenance, 'releaseRef', 'structured evidence provenance');
  if (stringField(releaseRef, 'input', 'structured evidence releaseRef') !== expected.tag
    || stringField(releaseRef, 'status', 'structured evidence releaseRef') !== 'resolved'
    || stringField(releaseRef, 'kind', 'structured evidence releaseRef') !== 'tag'
    || stringField(releaseRef, 'name', 'structured evidence releaseRef') !== expected.tag
    || stringField(releaseRef, 'ref', 'structured evidence releaseRef')
      !== `refs/tags/${expected.tag}`
    || stringField(releaseRef, 'resolvedSha', 'structured evidence releaseRef').toLowerCase()
      !== expected.sha
    || stringField(releaseRef, 'objectType', 'structured evidence releaseRef') !== 'commit') {
    throw new VerificationFailure('structured evidence resolved release tag/SHA does not match');
  }

  const configuredRepository = configuredRepositoryName();
  const sourceRepositories = report.sourceRepositories;
  if (!Array.isArray(sourceRepositories)
    || !sourceRepositories.some(
      (value) => typeof value === 'string'
        && value.toLowerCase() === configuredRepository.toLowerCase(),
    )) {
    throw new VerificationFailure(
      `structured evidence is not bound to ${configuredRepository}`,
    );
  }

  const summary = recordField(report, 'summary', 'structured evidence');
  const blockingPassed = nonNegativeIntegerField(summary, 'blockingPassed', 'structured evidence');
  const blockingFailed = nonNegativeIntegerField(summary, 'blockingFailed', 'structured evidence');
  const blockingSkipped = nonNegativeIntegerField(summary, 'blockingSkipped', 'structured evidence');
  const blockingIncomplete = nonNegativeIntegerField(
    summary,
    'blockingIncomplete',
    'structured evidence',
  );
  if (blockingPassed <= 0
    || blockingFailed !== 0
    || blockingSkipped !== 0
    || blockingIncomplete !== 0) {
    throw new VerificationFailure('structured evidence blocking checks are not fully successful');
  }

  if (!Array.isArray(report.runs) || report.runs.length === 0 || report.runs.length > 256) {
    throw new VerificationFailure('structured evidence runs are missing or invalid');
  }
  const runs = report.runs.map((value, index) => {
    if (!isRecord(value)) {
      throw new VerificationFailure(`structured evidence run ${index} is invalid`);
    }
    return value;
  });
  const blockingRuns = runs.filter((run) => run.blocking === true);
  if (blockingRuns.length !== blockingPassed) {
    throw new VerificationFailure('structured evidence blocking run count does not match summary');
  }
  for (const run of blockingRuns) {
    if (run.status !== 'completed'
      || run.conclusion !== 'success'
      || String(run.headSha ?? '').toLowerCase() !== expected.sha) {
      throw new VerificationFailure('structured evidence contains an invalid blocking run');
    }
  }
  const fullValidationRun = runs.find(
    (run) => run.label === 'full-release-validation'
      && typeof run.repo === 'string'
      && run.repo.toLowerCase() === configuredRepository.toLowerCase(),
  );
  if (!fullValidationRun
    || fullValidationRun.workflowName !== FULL_VALIDATION_WORKFLOW_NAME
    || fullValidationRun.event !== FULL_VALIDATION_EVENT
    || fullValidationRun.path !== FULL_VALIDATION_WORKFLOW_PATH
    || fullValidationRun.status !== 'completed'
    || fullValidationRun.conclusion !== 'success'
    || String(fullValidationRun.headSha ?? '').toLowerCase() !== expected.sha) {
    throw new VerificationFailure('structured evidence full validation run is invalid');
  }
}

function githubHeaders(accept = 'application/vnd.github+json'): Record<string, string> {
  const headers: Record<string, string> = {
    accept,
    'user-agent': USER_AGENT,
  };
  if (config.github.token) headers.authorization = `Bearer ${config.github.token}`;
  return headers;
}

function parseGitHubActionsRunUrl(url: string): { runId: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new VerificationFailure('fallback action URL invalid');
  }
  assertGitHubWebUrl(parsed);
  if (parsed.search || parsed.hash) {
    throw new VerificationFailure('fallback action URL query strings and fragments are not allowed');
  }
  const parts = safePathSegments(parsed);
  if (parts.length !== 5
    || parts[0].toLowerCase() !== config.github.owner.toLowerCase()
    || parts[1].toLowerCase() !== config.github.repo.toLowerCase()
    || parts[2] !== 'actions'
    || parts[3] !== 'runs'
    || !/^[1-9][0-9]{0,19}$/.test(parts[4])) {
    throw new VerificationFailure(
      `fallback action URL must identify ${configuredRepositoryName()}`,
    );
  }
  return { runId: parts[4] };
}

async function verifyActionRunFallback(input: {
  url: string | null;
  rawUrl: string | null;
  fallbackActionRunUrl: string;
  options: EvidenceReportVerificationOptions;
  budget: VerificationBudget;
}): Promise<EvidenceReportVerification> {
  let artifactCount = 0;
  try {
    const expected = expectedReleaseIdentity(input.options);
    const parsed = parseGitHubActionsRunUrl(input.fallbackActionRunUrl);
    const repositoryPath = `${encodeURIComponent(config.github.owner)}/${encodeURIComponent(config.github.repo)}`;
    const base = `https://api.github.com/repos/${repositoryPath}/actions/runs/${parsed.runId}`;

    const runObject = await fetchGitHubJson(base, input.budget, 'fallback action');
    const run = validateActionRun(runObject, parsed.runId);
    if (runObject.status !== 'completed' || runObject.conclusion !== 'success') {
      throw new VerificationFailure(
        `fallback action ${String(runObject.status ?? 'unknown')}/${String(runObject.conclusion ?? 'unknown')}`,
      );
    }

    const artifactsObject = await fetchGitHubJson(
      `${base}/artifacts?per_page=100`,
      input.budget,
      'fallback artifacts',
    );
    const artifacts = artifactsObject.artifacts;
    if (!Array.isArray(artifacts) || artifacts.length > 100) {
      throw new VerificationFailure('fallback artifacts payload invalid');
    }
    const totalCount = nonNegativeIntegerField(
      artifactsObject,
      'total_count',
      'fallback artifacts',
    );
    if (totalCount > artifacts.length) {
      throw new VerificationFailure('fallback artifacts require pagination beyond the request budget');
    }
    const eligibleArtifacts = artifacts.filter(
      (artifact) => isRecord(artifact)
        && artifact.expired !== true
        && Number.isInteger(artifact.size_in_bytes)
        && Number(artifact.size_in_bytes) > 0,
    );
    artifactCount = eligibleArtifacts.length;
    const expectedArtifactName = `full-release-validation-${parsed.runId}`;
    const matchingArtifacts = eligibleArtifacts.filter(
      (artifact) => artifact.name === expectedArtifactName,
    );
    if (matchingArtifacts.length === 0) {
      throw new VerificationFailure('fallback action artifact identity not found');
    }
    if (matchingArtifacts.length !== 1) {
      throw new VerificationFailure('fallback action artifact identity is ambiguous');
    }

    const artifact = matchingArtifacts[0] as Record<string, unknown>;
    const artifactId = positiveIntegerField(artifact, 'id', 'fallback artifact');
    const artifactSize = positiveIntegerField(artifact, 'size_in_bytes', 'fallback artifact');
    if (artifactSize > MAX_ARCHIVE_BYTES) {
      throw new VerificationFailure(`fallback artifact exceeds ${MAX_ARCHIVE_BYTES} bytes`);
    }
    const artifactDigest = normalizedSha256Digest(
      stringField(artifact, 'digest', 'fallback artifact'),
      'fallback artifact digest',
    );
    const expectedArchiveUrl =
      `https://api.github.com/repos/${repositoryPath}/actions/artifacts/${artifactId}/zip`;
    const archiveUrl = stringField(artifact, 'archive_download_url', 'fallback artifact');
    if (archiveUrl !== expectedArchiveUrl) {
      throw new VerificationFailure('fallback artifact download URL does not match its identity');
    }
    validateArtifactWorkflowRun(artifact, run);

    const fetchedArchive = await fetchWithRedirectPolicy(
      archiveUrl,
      { headers: githubHeaders() },
      input.budget,
      MAX_ARTIFACT_REDIRECTS,
      assertArtifactDownloadUrl,
    );
    let archive: Buffer;
    try {
      if (!fetchedArchive.response.ok) {
        const detail = await responseErrorDetail(
          fetchedArchive.response,
          input.budget,
          fetchedArchive.signal,
        );
        throw new VerificationFailure(
          `fallback artifact ${fetchedArchive.response.status}${detail ? `: ${detail}` : ''}`,
        );
      }
      archive = await readLimitedBody(
        fetchedArchive.response,
        MAX_ARCHIVE_BYTES,
        'fallback artifact',
        input.budget,
        fetchedArchive.signal,
      );
    } finally {
      fetchedArchive.dispose();
    }
    if (archive.length !== artifactSize) {
      throw new VerificationFailure(
        `fallback artifact size ${archive.length} != ${artifactSize}`,
      );
    }
    const actualArtifactDigest = sha256Digest(archive);
    if (!equalDigest(actualArtifactDigest, artifactDigest)) {
      throw new VerificationFailure('fallback artifact digest mismatch');
    }

    const manifestBytes = extractManifestFromZip(archive, input.budget);
    const manifest = parseJsonObject(manifestBytes, 'fallback action manifest');
    validateFallbackManifest(manifest, expected, run);
    return verificationResult({
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: artifactCount,
      contentDigest: sha256Digest(manifestBytes),
      fallbackArtifactDigest: artifactDigest,
      expectedReleaseTag: expected.tag,
      expectedReleaseSha: expected.sha,
      verified: true,
    });
  } catch (error) {
    if (!(error instanceof VerificationFailure)) throw error;
    return verificationResult({
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: artifactCount,
      ...canonicalExpectedReleaseBinding(input.options),
      mismatch: `release evidence report not found; ${error.message}`,
    });
  }
}

async function fetchGitHubJson(
  url: string,
  budget: VerificationBudget,
  label: string,
): Promise<Record<string, unknown>> {
  const fetched = await fetchWithRedirectPolicy(
    url,
    { headers: githubHeaders() },
    budget,
    0,
    assertGitHubApiUrl,
  );
  try {
    if (!fetched.response.ok) {
      const detail = await responseErrorDetail(
        fetched.response,
        budget,
        fetched.signal,
      );
      throw new VerificationFailure(
        `${label} ${fetched.response.status}${detail ? `: ${detail}` : ''}`,
      );
    }
    const body = await readLimitedBody(
      fetched.response,
      MAX_API_BODY_BYTES,
      label,
      budget,
      fetched.signal,
    );
    return parseJsonObject(body, label);
  } finally {
    fetched.dispose();
  }
}

function validateActionRun(run: Record<string, unknown>, expectedRunId: string): VerifiedActionRun {
  if (String(run.id ?? '') !== expectedRunId) {
    throw new VerificationFailure('fallback action run id does not match URL');
  }
  if (run.name !== FULL_VALIDATION_WORKFLOW_NAME
    || run.path !== FULL_VALIDATION_WORKFLOW_PATH
    || run.event !== FULL_VALIDATION_EVENT) {
    throw new VerificationFailure('fallback action workflow/event identity does not match');
  }
  positiveIntegerField(run, 'workflow_id', 'fallback action');
  const attempt = String(positiveIntegerField(run, 'run_attempt', 'fallback action'));
  const headSha = stringField(run, 'head_sha', 'fallback action').toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(headSha)) {
    throw new VerificationFailure('fallback action head SHA is invalid');
  }
  const headBranch = stringField(run, 'head_branch', 'fallback action');
  const repository = recordField(run, 'repository', 'fallback action');
  const headRepository = recordField(run, 'head_repository', 'fallback action');
  const repositoryName = stringField(repository, 'full_name', 'fallback action repository');
  const headRepositoryName = stringField(
    headRepository,
    'full_name',
    'fallback action head repository',
  );
  const configuredRepository = configuredRepositoryName();
  if (repositoryName.toLowerCase() !== configuredRepository.toLowerCase()
    || headRepositoryName.toLowerCase() !== configuredRepository.toLowerCase()) {
    throw new VerificationFailure(`fallback action is not bound to ${configuredRepository}`);
  }
  const repositoryId = positiveIntegerField(repository, 'id', 'fallback action repository');
  if (positiveIntegerField(headRepository, 'id', 'fallback action head repository')
    !== repositoryId) {
    throw new VerificationFailure('fallback action head repository id does not match');
  }
  const expectedApiUrl =
    `https://api.github.com/repos/${config.github.owner}/${config.github.repo}/actions/runs/${expectedRunId}`;
  const expectedHtmlUrl =
    `https://github.com/${config.github.owner}/${config.github.repo}/actions/runs/${expectedRunId}`;
  if (stringField(run, 'url', 'fallback action') !== expectedApiUrl
    || stringField(run, 'html_url', 'fallback action') !== expectedHtmlUrl) {
    throw new VerificationFailure('fallback action API/HTML identity does not match');
  }
  return {
    id: expectedRunId,
    attempt,
    headSha,
    headBranch,
    repositoryId,
  };
}

function validateArtifactWorkflowRun(
  artifact: Record<string, unknown>,
  run: VerifiedActionRun,
): void {
  const workflowRun = recordField(artifact, 'workflow_run', 'fallback artifact');
  if (String(workflowRun.id ?? '') !== run.id
    || positiveIntegerField(
      workflowRun,
      'repository_id',
      'fallback artifact workflow_run',
    ) !== run.repositoryId
    || positiveIntegerField(
      workflowRun,
      'head_repository_id',
      'fallback artifact workflow_run',
    ) !== run.repositoryId
    || stringField(
      workflowRun,
      'head_sha',
      'fallback artifact workflow_run',
    ).toLowerCase() !== run.headSha
    || stringField(
      workflowRun,
      'head_branch',
      'fallback artifact workflow_run',
    ) !== run.headBranch) {
    throw new VerificationFailure('fallback artifact workflow run identity does not match');
  }
}

function validateFallbackManifest(
  manifest: Record<string, unknown>,
  expected: ExpectedReleaseIdentity,
  run: VerifiedActionRun,
): void {
  if (manifest.version !== 2
    || manifest.workflowName !== FULL_VALIDATION_WORKFLOW_NAME
    || String(manifest.runId ?? '') !== run.id
    || String(manifest.runAttempt ?? '') !== run.attempt
    || manifest.workflowRef !== run.headBranch) {
    throw new VerificationFailure('fallback action manifest workflow identity does not match');
  }
  const targetSha = stringField(manifest, 'targetSha', 'fallback action manifest').toLowerCase();
  if (targetSha !== expected.sha) {
    throw new VerificationFailure(
      `fallback action targetSha ${targetSha || 'missing'} != ${expected.sha}`,
    );
  }
  const targetRef = stringField(manifest, 'targetRef', 'fallback action manifest');
  const baseVersion = expected.version.split('-')[0];
  const allowedRefs = new Set([
    expected.tag,
    `refs/tags/${expected.tag}`,
    expected.sha,
    `release/${expected.version}`,
    `release/${baseVersion}`,
  ]);
  if (!allowedRefs.has(targetRef)) {
    throw new VerificationFailure(
      `fallback action targetRef ${targetRef || 'missing'} != ${expected.tag}`,
    );
  }
  stringField(manifest, 'releaseProfile', 'fallback action manifest');
  if (manifest.rerunGroup !== 'all'
    || (manifest.runReleaseSoak !== 'true' && manifest.runReleaseSoak !== 'false')) {
    throw new VerificationFailure('fallback action manifest validation controls are invalid');
  }
  const controls = recordField(manifest, 'controls', 'fallback action manifest');
  if (typeof controls.stableSoakRequired !== 'boolean'
    || controls.performanceBlocking !== true) {
    throw new VerificationFailure('fallback action manifest controls are invalid');
  }
  const childRuns = recordField(manifest, 'childRuns', 'fallback action manifest');
  for (const field of ['normalCi', 'pluginPrerelease', 'releaseChecks']) {
    if (!/^[1-9][0-9]*$/.test(stringField(childRuns, field, 'fallback action childRuns'))) {
      throw new VerificationFailure(`fallback action child run ${field} is invalid`);
    }
  }
  const productPerformance = recordField(
    childRuns,
    'productPerformance',
    'fallback action childRuns',
  );
  if (!/^[1-9][0-9]*$/.test(
    stringField(productPerformance, 'runId', 'fallback action productPerformance'),
  )
    || productPerformance.conclusion !== 'success'
    || productPerformance.blocking !== true) {
    throw new VerificationFailure('fallback action product performance identity is invalid');
  }
}

async function fetchWithRedirectPolicy(
  input: string,
  init: RequestInit,
  budget: VerificationBudget,
  maxRedirects: number,
  validateUrl: (url: URL, redirectIndex: number) => void,
): Promise<{
  response: Response;
  url: URL;
  signal: AbortSignal;
  dispose(): void;
}> {
  let current = new URL(input);
  let headers = new Headers(init.headers);
  for (let redirectIndex = 0; ; redirectIndex++) {
    validateUrl(current, redirectIndex);
    const timeoutMs = budget.takeRequest();
    const requestAbort = createRequestAbortScope(budget.signal, timeoutMs);
    let response: Response;
    try {
      response = await fetchWithAbort(current, {
        ...init,
        headers,
        redirect: 'manual',
        signal: requestAbort.signal,
      }, requestAbort.signal);
    } catch (error) {
      requestAbort.dispose();
      throw error;
    }
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      return {
        response,
        url: current,
        signal: requestAbort.signal,
        dispose: requestAbort.dispose,
      };
    }
    try {
      if (redirectIndex >= maxRedirects) {
        throw new VerificationFailure(`redirect budget exceeded (${maxRedirects})`);
      }
      const location = response.headers.get('location');
      if (!location) {
        throw new VerificationFailure('redirect is missing Location');
      }
      let next: URL;
      try {
        next = new URL(location, current);
      } catch {
        throw new VerificationFailure('redirect Location is invalid');
      }
      validateUrl(next, redirectIndex + 1);
      if (next.origin !== current.origin) {
        headers = new Headers(headers);
        headers.delete('authorization');
      }
      current = next;
    } finally {
      cancelResponseBody(response, 'release evidence redirect consumed');
      requestAbort.dispose();
    }
  }
}

function createRequestAbortScope(
  callerSignal: AbortSignal | undefined,
  timeoutMs: number,
): {
  signal: AbortSignal;
  dispose(): void;
} {
  const controller = new AbortController();
  let disposed = false;
  const abortFromCaller = (): void => {
    if (!controller.signal.aborted) controller.abort(callerSignal?.reason);
  };
  if (callerSignal?.aborted) abortFromCaller();
  else callerSignal?.addEventListener('abort', abortFromCaller, { once: true });
  const timeout = setTimeout(() => {
    if (!controller.signal.aborted) {
      controller.abort(new DOMException(
        `release evidence request timed out after ${timeoutMs}ms`,
        'TimeoutError',
      ));
    }
  }, timeoutMs);
  return {
    signal: controller.signal,
    dispose(): void {
      if (disposed) return;
      disposed = true;
      clearTimeout(timeout);
      callerSignal?.removeEventListener('abort', abortFromCaller);
    },
  };
}

function cancelResponseBody(response: Response, reason?: unknown): void {
  void response.body?.cancel(reason).catch(() => undefined);
}

function assertPrimaryEvidenceUrl(url: URL): void {
  assertHttpsPublicUrl(url);
  if (url.hostname.toLowerCase() !== 'raw.githubusercontent.com') {
    throw new VerificationFailure('release evidence host is not approved');
  }
  if (url.search || url.hash) {
    throw new VerificationFailure('release evidence URL query strings and fragments are not allowed');
  }
}

function assertGitHubWebUrl(url: URL): void {
  assertHttpsPublicUrl(url);
  if (url.hostname.toLowerCase() !== 'github.com') {
    throw new VerificationFailure('GitHub web host is not approved');
  }
}

function assertGitHubApiUrl(url: URL): void {
  assertHttpsPublicUrl(url);
  if (url.hostname.toLowerCase() !== 'api.github.com') {
    throw new VerificationFailure('GitHub API host is not approved');
  }
}

function assertArtifactDownloadUrl(url: URL, redirectIndex: number): void {
  assertHttpsPublicUrl(url);
  const hostname = url.hostname.toLowerCase();
  if (redirectIndex === 0) {
    if (hostname !== 'api.github.com' || url.search || url.hash) {
      throw new VerificationFailure('fallback artifact API URL is not approved');
    }
    return;
  }
  const approved = hostname === 'objects.githubusercontent.com'
    || hostname.endsWith('.actions.githubusercontent.com')
    || hostname.endsWith('.blob.core.windows.net');
  if (!approved) throw new VerificationFailure('fallback artifact redirect host is not approved');
}

function assertHttpsPublicUrl(url: URL): void {
  if (url.protocol !== 'https:') throw new VerificationFailure('only HTTPS URLs are allowed');
  if (url.username || url.password) {
    throw new VerificationFailure('URL credentials are not allowed');
  }
  if (url.port && url.port !== '443') {
    throw new VerificationFailure('non-default URL ports are not allowed');
  }
  const hostname = normalizedHostname(url.hostname);
  if (!hostname) throw new VerificationFailure('URL hostname is missing');
  if (hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname.endsWith('.local')
    || isPrivateIpAddress(hostname)) {
    throw new VerificationFailure('private or local network addresses are not allowed');
  }
}

function normalizedHostname(hostname: string): string {
  const lower = hostname.toLowerCase();
  if (lower.startsWith('[') && lower.endsWith(']')) return lower.slice(1, -1);
  return lower;
}

function isPrivateIpAddress(hostname: string): boolean {
  const family = isIP(hostname);
  if (family === 4) {
    const [a, b] = hostname.split('.').map(Number);
    return a === 0
      || a === 10
      || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 0 || b === 168))
      || (a === 198 && (b === 18 || b === 19 || b === 51))
      || (a === 203 && b === 0)
      || a >= 224;
  }
  if (family === 6) {
    const lower = hostname.toLowerCase();
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIpAddress(mapped[1]);
    return lower === '::'
      || lower === '::1'
      || /^f[cd]/.test(lower)
      || /^fe[89ab]/.test(lower)
      || /^ff/.test(lower)
      || lower.startsWith('2001:db8:');
  }
  return false;
}

function safePathSegments(url: URL): string[] {
  return url.pathname.split('/').filter(Boolean).map((part) => {
    let decoded: string;
    try {
      decoded = decodeURIComponent(part);
    } catch {
      throw new VerificationFailure('URL path contains invalid encoding');
    }
    if (!decoded || decoded === '.' || decoded === '..' || /[\/\\\0]/.test(decoded)) {
      throw new VerificationFailure('URL path contains an unsafe segment');
    }
    return decoded;
  });
}

async function readLimitedBody(
  response: Response,
  maxBytes: number,
  label: string,
  budget: VerificationBudget,
  signal: AbortSignal = budget.signal ?? new AbortController().signal,
): Promise<Buffer> {
  const contentLength = response.headers.get('content-length');
  if (contentLength != null && contentLength !== '') {
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared < 0) {
      cancelResponseBody(response, `${label} Content-Length is invalid`);
      throw new VerificationFailure(`${label} Content-Length is invalid`);
    }
    if (declared > maxBytes) {
      cancelResponseBody(response, `${label} exceeds ${maxBytes} bytes`);
      throw new VerificationFailure(`${label} exceeds ${maxBytes} bytes`);
    }
  }
  if (!response.body) return Buffer.alloc(0);

  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      throwIfAborted(signal);
      const { done, value } = await readBodyChunk(reader, signal);
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        void reader.cancel(`${label} exceeds ${maxBytes} bytes`).catch(() => undefined);
        throw new VerificationFailure(`${label} exceeds ${maxBytes} bytes`);
      }
      try {
        budget.takeBody(value.byteLength);
      } catch (error) {
        void reader.cancel(error).catch(() => undefined);
        throw error;
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Cancellation may leave an ignored read pending until the stream settles.
    }
  }
  return Buffer.concat(chunks, total);
}

async function fetchWithAbort(
  input: string | URL,
  init: RequestInit,
  signal: AbortSignal,
): Promise<Response> {
  throwIfAborted(signal);
  return new Promise<Response>((resolve, reject) => {
    let settled = false;
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      reject(createAbortError(signal.reason));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    void fetch(input, init).then(
      (response) => {
        if (settled) {
          void response.body?.cancel(signal.reason).catch(() => undefined);
          return;
        }
        settled = true;
        signal.removeEventListener('abort', onAbort);
        resolve(response);
      },
      (error) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

type ReadBodyChunkResult = Awaited<
  ReturnType<ReadableStreamDefaultReader<Uint8Array>['read']>
>;

async function readBodyChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal?: AbortSignal,
): Promise<ReadBodyChunkResult> {
  if (!signal) return reader.read();
  throwIfAborted(signal);
  return new Promise<ReadBodyChunkResult>((resolve, reject) => {
    let settled = false;
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      const error = createAbortError(signal.reason);
      void reader.cancel(error).catch(() => undefined);
      reject(error);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    void reader.read().then(
      (chunk) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        resolve(chunk);
      },
      (error) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

async function responseErrorDetail(
  response: Response,
  budget: VerificationBudget,
  signal?: AbortSignal,
): Promise<string> {
  const body = await readLimitedBody(
    response,
    MAX_ERROR_BODY_BYTES,
    'error response',
    budget,
    signal,
  );
  return body.toString('utf8').replace(/\s+/g, ' ').trim().slice(0, 256);
}

function parseJsonObject(buffer: Buffer, label: string): Record<string, unknown> {
  if (buffer.length === 0) throw new VerificationFailure(`${label} is empty`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(buffer.toString('utf8'));
  } catch {
    throw new VerificationFailure(`${label} is not valid JSON`);
  }
  if (!isRecord(parsed)) throw new VerificationFailure(`${label} must be a JSON object`);
  return parsed;
}

function extractManifestFromZip(buffer: Buffer, budget: VerificationBudget): Buffer {
  const eocdOffset = findEndOfCentralDirectory(buffer);
  if (eocdOffset < 0) throw new VerificationFailure('fallback artifact ZIP directory not found');
  if (buffer.readUInt16LE(eocdOffset + 4) !== 0
    || buffer.readUInt16LE(eocdOffset + 6) !== 0) {
    throw new VerificationFailure('fallback artifact multi-disk ZIP is not allowed');
  }
  const entriesOnDisk = buffer.readUInt16LE(eocdOffset + 8);
  const entryCount = buffer.readUInt16LE(eocdOffset + 10);
  if (entriesOnDisk !== entryCount || entryCount !== 1 || entryCount > MAX_ZIP_ENTRIES) {
    throw new VerificationFailure('fallback artifact must contain exactly one ZIP entry');
  }
  const centralSize = buffer.readUInt32LE(eocdOffset + 12);
  const centralOffset = buffer.readUInt32LE(eocdOffset + 16);
  if (centralOffset === 0xffffffff || centralSize === 0xffffffff) {
    throw new VerificationFailure('fallback artifact ZIP64 is not allowed');
  }
  if (centralOffset + centralSize !== eocdOffset
    || centralOffset + 46 > buffer.length
    || buffer.readUInt32LE(centralOffset) !== 0x02014b50) {
    throw new VerificationFailure('fallback artifact ZIP directory is invalid');
  }

  const flags = buffer.readUInt16LE(centralOffset + 8);
  const method = buffer.readUInt16LE(centralOffset + 10);
  const compressedSize = buffer.readUInt32LE(centralOffset + 20);
  const uncompressedSize = buffer.readUInt32LE(centralOffset + 24);
  const fileNameLength = buffer.readUInt16LE(centralOffset + 28);
  const extraLength = buffer.readUInt16LE(centralOffset + 30);
  const commentLength = buffer.readUInt16LE(centralOffset + 32);
  const localHeaderOffset = buffer.readUInt32LE(centralOffset + 42);
  if (compressedSize === 0xffffffff
    || uncompressedSize === 0xffffffff
    || localHeaderOffset === 0xffffffff) {
    throw new VerificationFailure('fallback artifact ZIP64 entry is not allowed');
  }
  const centralEnd = centralOffset + 46 + fileNameLength + extraLength + commentLength;
  if (centralEnd !== eocdOffset
    || fileNameLength > MAX_ZIP_ENTRY_NAME_BYTES
    || uncompressedSize > MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES
    || uncompressedSize > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES
    || compressedSize > MAX_ARCHIVE_BYTES) {
    throw new VerificationFailure('fallback artifact ZIP entry budget exceeded');
  }
  if ((flags & 0x0001) !== 0 || (method !== 0 && method !== 8)) {
    throw new VerificationFailure('fallback artifact ZIP compression is not allowed');
  }
  const fileName = buffer.subarray(
    centralOffset + 46,
    centralOffset + 46 + fileNameLength,
  ).toString('utf8');
  if (fileName !== FULL_VALIDATION_MANIFEST) {
    throw new VerificationFailure('fallback artifact manifest identity not found');
  }

  if (localHeaderOffset + 30 > centralOffset
    || buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
    throw new VerificationFailure('fallback artifact ZIP local header is invalid');
  }
  const localFlags = buffer.readUInt16LE(localHeaderOffset + 6);
  const localMethod = buffer.readUInt16LE(localHeaderOffset + 8);
  const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
  const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
  const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
  const dataEnd = dataStart + compressedSize;
  if (localFlags !== flags
    || localMethod !== method
    || localNameLength !== fileNameLength
    || dataEnd > centralOffset
    || buffer.subarray(
      localHeaderOffset + 30,
      localHeaderOffset + 30 + localNameLength,
    ).toString('utf8') !== fileName) {
    throw new VerificationFailure('fallback artifact ZIP entry headers do not match');
  }
  if (uncompressedSize > 0
    && (compressedSize === 0 || uncompressedSize / compressedSize > MAX_COMPRESSION_RATIO)) {
    throw new VerificationFailure('fallback artifact ZIP compression ratio exceeds budget');
  }

  const compressed = buffer.subarray(dataStart, dataEnd);
  let manifest: Buffer;
  if (method === 0) {
    if (compressedSize !== uncompressedSize) {
      throw new VerificationFailure('fallback artifact stored ZIP size is invalid');
    }
    manifest = Buffer.from(compressed);
  } else {
    try {
      manifest = inflateRawSync(compressed, {
        maxOutputLength: MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES,
      });
    } catch {
      throw new VerificationFailure('fallback artifact ZIP decompression failed');
    }
  }
  if (manifest.length !== uncompressedSize) {
    throw new VerificationFailure('fallback artifact ZIP uncompressed size does not match');
  }
  budget.takeDecompressed(manifest.length);
  return manifest;
}

function findEndOfCentralDirectory(buffer: Buffer): number {
  const minimum = Math.max(0, buffer.length - 22 - 0xffff);
  for (let offset = buffer.length - 22; offset >= minimum; offset--) {
    if (buffer.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = buffer.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength === buffer.length) return offset;
  }
  return -1;
}

function configuredRepositoryName(): string {
  return `${config.github.owner}/${config.github.repo}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function recordField(
  object: Record<string, unknown>,
  field: string,
  label: string,
): Record<string, unknown> {
  const value = object[field];
  if (!isRecord(value)) throw new VerificationFailure(`${label} ${field} is invalid`);
  return value;
}

function stringField(
  object: Record<string, unknown>,
  field: string,
  label: string,
): string {
  const value = object[field];
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) {
    throw new VerificationFailure(`${label} ${field} is invalid`);
  }
  return value;
}

function positiveIntegerField(
  object: Record<string, unknown>,
  field: string,
  label: string,
): number {
  const value = object[field];
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new VerificationFailure(`${label} ${field} is invalid`);
  }
  return Number(value);
}

function nonNegativeIntegerField(
  object: Record<string, unknown>,
  field: string,
  label: string,
): number {
  const value = object[field];
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new VerificationFailure(`${label} ${field} is invalid`);
  }
  return Number(value);
}

function sha256Digest(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

function normalizedSha256Digest(value: string, label: string): string {
  const lower = value.toLowerCase();
  if (!/^sha256:[0-9a-f]{64}$/.test(lower)) {
    throw new VerificationFailure(`${label} is invalid`);
  }
  return lower.slice('sha256:'.length);
}

function equalDigest(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
