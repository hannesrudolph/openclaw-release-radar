import { createHash } from 'node:crypto';
import {
  ARTIFACT_VERIFICATION_SCHEMA_VERSION,
  SUPPORTED_SRI_ALGORITHMS,
  canonicalizeGitSha,
  canonicalizeSri,
  replayArtifactVerificationEvidence,
  type ArtifactVerificationEvidence,
  type SupportedSriAlgorithm,
} from './artifactVerification';
import { canonicalJson } from './operationReceipts';
import type { EvidenceReportVerification } from './releaseEvidence';

export const RELEASE_ARTIFACT_RECEIPT_SCHEMA_VERSION = 2 as const;
export const RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION = 1 as const;

export interface ReleaseArtifactIdentity {
  repository: string;
  tag: string;
  releaseNodeId: string;
  catalogTagCommitOid: string;
  publishedAt: string;
}

export interface ReleaseArtifactMetadata {
  npmPackageUrl: string | null;
  releaseTarballUrl: string | null;
  releaseIntegrity: string | null;
  releaseSha: string | null;
  ciReportUrl: string | null;
  fullReleaseValidationUrl: string | null;
}

export interface ReleaseArtifactReceiptPayload {
  schemaVersion: typeof RELEASE_ARTIFACT_RECEIPT_SCHEMA_VERSION;
  release: ReleaseArtifactIdentity;
  releaseMetadata: ReleaseArtifactMetadata;
  artifact: ArtifactVerificationEvidence;
  evidenceReport: EvidenceReportVerification;
  evidenceReportIdentity: string;
}

export interface ReleaseArtifactReceipt extends ReleaseArtifactReceiptPayload {
  receiptId: string;
  evidenceIdentity: string;
  canonicalReceiptJson: string;
  previousContentHash: string | null;
  contentHash: string;
}

export interface ReleaseArtifactObservationPayload {
  schemaVersion: typeof RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION;
  observationId: string;
  runId: string;
  observedAt: string;
  release: ReleaseArtifactIdentity;
  receiptId: string;
  receiptContentHash: string;
}

export interface ReleaseArtifactObservation extends ReleaseArtifactObservationPayload {
  canonicalObservationJson: string;
  previousContentHash: string | null;
  contentHash: string;
}

export interface ReleaseArtifactReceiptInput {
  release: ReleaseArtifactIdentity;
  releaseMetadata: ReleaseArtifactMetadata;
  artifact: ArtifactVerificationEvidence;
  evidenceReport: EvidenceReportVerification;
  previousContentHash: string | null;
}

export interface ReleaseArtifactReceiptStorageRecord {
  receipt_id: string;
  schema_version: number;
  release_repository: string;
  release_tag: string;
  release_node_id: string;
  release_tag_commit_oid: string;
  release_published_at: string;
  evidence_identity: string;
  canonical_receipt_json: string;
  previous_content_hash: string | null;
  content_hash: string;
}

export interface ReleaseArtifactObservationStorageRecord {
  observation_id: string;
  schema_version: number;
  run_id: string;
  observed_at: string;
  release_repository: string;
  release_tag: string;
  release_node_id: string;
  release_tag_commit_oid: string;
  release_published_at: string;
  receipt_id: string;
  receipt_content_hash: string;
  canonical_observation_json: string;
  previous_content_hash: string | null;
  content_hash: string;
}

export function buildReleaseArtifactReceipt(
  input: ReleaseArtifactReceiptInput,
): ReleaseArtifactReceipt {
  const release = canonicalReleaseIdentity(input.release);
  const releaseMetadata = canonicalReleaseMetadata(input.releaseMetadata);
  const artifact = canonicalArtifactEvidence(input.artifact);
  const evidenceReport = canonicalEvidenceReport(input.evidenceReport);
  const evidenceReportIdentity = releaseEvidenceReportIdentity(
    release,
    evidenceReport,
  );
  const payload: ReleaseArtifactReceiptPayload = {
    schemaVersion: RELEASE_ARTIFACT_RECEIPT_SCHEMA_VERSION,
    release,
    releaseMetadata,
    artifact,
    evidenceReport,
    evidenceReportIdentity,
  };
  const problems = releaseArtifactPayloadProblems(payload);
  if (problems.length > 0) {
    throw new Error(`Invalid release artifact receipt payload: ${problems.join('; ')}`);
  }
  assertOptionalSha256(input.previousContentHash, 'artifact receipt previous content hash');
  const canonicalReceiptJson = canonicalJson(payload);
  const evidenceIdentity = sha256(
    'release_artifact_evidence_v2',
    canonicalReceiptJson,
  );
  const receiptId = `artifact-receipt-v2:${evidenceIdentity}`;
  const contentHash = sha256(
    'release_artifact_receipt_ledger_v1',
    input.previousContentHash,
    receiptId,
    canonicalReceiptJson,
  );
  return {
    ...payload,
    receiptId,
    evidenceIdentity,
    canonicalReceiptJson,
    previousContentHash: input.previousContentHash,
    contentHash,
  };
}

export function buildReleaseArtifactObservation(input: {
  runId: string;
  observedAt: string;
  release: ReleaseArtifactIdentity;
  receipt: Pick<ReleaseArtifactReceipt, 'receiptId' | 'contentHash'>;
  previousContentHash: string | null;
}): ReleaseArtifactObservation {
  const release = canonicalReleaseIdentity(input.release);
  const runId = requiredCanonicalString(input.runId, 'artifact observation run ID');
  const observedAt = canonicalTimestamp(input.observedAt, 'artifact observation observedAt');
  assertSha256(input.receipt.contentHash, 'artifact observation receipt content hash');
  assertOptionalSha256(
    input.previousContentHash,
    'artifact observation previous content hash',
  );
  if (!/^artifact-receipt-v2:[0-9a-f]{64}$/.test(input.receipt.receiptId)) {
    throw new Error('Artifact observation receipt ID is invalid');
  }
  const observationId = `artifact-observation-v1:${sha256(
    'release_artifact_observation_identity_v1',
    runId,
    release.repository,
    release.releaseNodeId,
    release.catalogTagCommitOid,
  )}`;
  const payload: ReleaseArtifactObservationPayload = {
    schemaVersion: RELEASE_ARTIFACT_OBSERVATION_SCHEMA_VERSION,
    observationId,
    runId,
    observedAt,
    release,
    receiptId: input.receipt.receiptId,
    receiptContentHash: input.receipt.contentHash,
  };
  const canonicalObservationJson = canonicalJson(payload);
  const contentHash = sha256(
    'release_artifact_observation_ledger_v1',
    input.previousContentHash,
    canonicalObservationJson,
  );
  return {
    ...payload,
    canonicalObservationJson,
    previousContentHash: input.previousContentHash,
    contentHash,
  };
}

export function assertReleaseArtifactReceipt(
  receipt: ReleaseArtifactReceipt,
): void {
  const rebuilt = buildReleaseArtifactReceipt({
    release: receipt.release,
    releaseMetadata: receipt.releaseMetadata,
    artifact: receipt.artifact,
    evidenceReport: receipt.evidenceReport,
    previousContentHash: receipt.previousContentHash,
  });
  if (canonicalJson(rebuilt) !== canonicalJson(receipt)) {
    throw new Error(`Release artifact receipt ${receipt.receiptId} failed verification`);
  }
}

export function assertReleaseArtifactObservation(
  observation: ReleaseArtifactObservation,
): void {
  const rebuilt = buildReleaseArtifactObservation({
    runId: observation.runId,
    observedAt: observation.observedAt,
    release: observation.release,
    receipt: {
      receiptId: observation.receiptId,
      contentHash: observation.receiptContentHash,
    },
    previousContentHash: observation.previousContentHash,
  });
  if (canonicalJson(rebuilt) !== canonicalJson(observation)) {
    throw new Error(
      `Release artifact observation ${observation.observationId} failed verification`,
    );
  }
}

export function releaseArtifactReceiptFromStorageRecord(
  row: ReleaseArtifactReceiptStorageRecord,
): ReleaseArtifactReceipt {
  let payload: unknown;
  try {
    payload = JSON.parse(row.canonical_receipt_json);
  } catch (error) {
    throw new Error(
      `Release artifact receipt ${JSON.stringify(row.receipt_id)} contains invalid JSON`,
      { cause: error },
    );
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error(
      `Release artifact receipt ${JSON.stringify(row.receipt_id)} payload is not an object`,
    );
  }
  const receipt = {
    ...(payload as Record<string, unknown>),
    receiptId: row.receipt_id,
    evidenceIdentity: row.evidence_identity,
    canonicalReceiptJson: row.canonical_receipt_json,
    previousContentHash: row.previous_content_hash,
    contentHash: row.content_hash,
  } as unknown as ReleaseArtifactReceipt;
  assertReleaseArtifactReceipt(receipt);
  if (
    Number(row.schema_version) !== receipt.schemaVersion ||
    row.release_repository !== receipt.release.repository ||
    row.release_tag !== receipt.release.tag ||
    row.release_node_id !== receipt.release.releaseNodeId ||
    row.release_tag_commit_oid !== receipt.release.catalogTagCommitOid ||
    row.release_published_at !== receipt.release.publishedAt
  ) {
    throw new Error(
      `Release artifact receipt ${JSON.stringify(row.receipt_id)} storage ` +
      'does not match its canonical payload',
    );
  }
  return receipt;
}

export function releaseArtifactObservationFromStorageRecord(
  row: ReleaseArtifactObservationStorageRecord,
): ReleaseArtifactObservation {
  let payload: unknown;
  try {
    payload = JSON.parse(row.canonical_observation_json);
  } catch (error) {
    throw new Error(
      `Release artifact observation ${JSON.stringify(row.observation_id)} ` +
      'contains invalid JSON',
      { cause: error },
    );
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error(
      `Release artifact observation ${JSON.stringify(row.observation_id)} ` +
      'payload is not an object',
    );
  }
  const observation = {
    ...(payload as Record<string, unknown>),
    canonicalObservationJson: row.canonical_observation_json,
    previousContentHash: row.previous_content_hash,
    contentHash: row.content_hash,
  } as unknown as ReleaseArtifactObservation;
  assertReleaseArtifactObservation(observation);
  if (
    Number(row.schema_version) !== observation.schemaVersion ||
    row.observation_id !== observation.observationId ||
    row.run_id !== observation.runId ||
    row.observed_at !== observation.observedAt ||
    row.release_repository !== observation.release.repository ||
    row.release_tag !== observation.release.tag ||
    row.release_node_id !== observation.release.releaseNodeId ||
    row.release_tag_commit_oid !== observation.release.catalogTagCommitOid ||
    row.release_published_at !== observation.release.publishedAt ||
    row.receipt_id !== observation.receiptId ||
    row.receipt_content_hash !== observation.receiptContentHash
  ) {
    throw new Error(
      `Release artifact observation ${JSON.stringify(row.observation_id)} storage ` +
      'does not match its canonical payload',
    );
  }
  return observation;
}

export function releaseArtifactPayloadProblems(
  payload: ReleaseArtifactReceiptPayload,
): string[] {
  const problems: string[] = [];
  if (payload.schemaVersion !== RELEASE_ARTIFACT_RECEIPT_SCHEMA_VERSION) {
    problems.push(
      `schemaVersion must equal ${RELEASE_ARTIFACT_RECEIPT_SCHEMA_VERSION}`,
    );
  }
  let release: ReleaseArtifactIdentity | null = null;
  try {
    release = canonicalReleaseIdentity(payload.release);
  } catch (error) {
    problems.push(errorMessage(error));
  }
  let metadata: ReleaseArtifactMetadata | null = null;
  try {
    metadata = canonicalReleaseMetadata(payload.releaseMetadata);
  } catch (error) {
    problems.push(errorMessage(error));
  }
  let artifact: ArtifactVerificationEvidence | null = null;
  try {
    artifact = canonicalArtifactEvidence(payload.artifact);
  } catch (error) {
    problems.push(errorMessage(error));
  }
  let report: EvidenceReportVerification | null = null;
  try {
    report = canonicalEvidenceReport(payload.evidenceReport);
  } catch (error) {
    problems.push(errorMessage(error));
  }

  if (release && metadata && artifact) {
    const requestedVersion = release.tag.replace(/^v/, '');
    if (artifact.requestedVersion !== requestedVersion) {
      problems.push(
        `artifact requestedVersion ${artifact.requestedVersion} != ${requestedVersion}`,
      );
    }
    if (artifact.expectedIntegrity !== metadata.releaseIntegrity) {
      problems.push('artifact expected integrity does not match release metadata');
    }
    if (artifact.expectedTarballUrl !== metadata.releaseTarballUrl) {
      problems.push('artifact expected tarball URL does not match release metadata');
    }
    if (artifact.expectedReleaseSha !== metadata.releaseSha) {
      problems.push('artifact expected release SHA does not match release metadata');
    }
    const releaseSha = canonicalizeGitSha(metadata.releaseSha, 'release metadata SHA');
    if (
      releaseSha.value &&
      releaseSha.value !== release.catalogTagCommitOid
    ) {
      problems.push(
        `release metadata SHA ${releaseSha.value} != catalog tag commit ` +
          release.catalogTagCommitOid,
      );
    }
    if (
      artifact.releaseBound &&
      artifact.canonicalExpectedReleaseSha !== release.catalogTagCommitOid
    ) {
      problems.push('release-bound artifact is not bound to the catalog tag commit');
    }
  }
  if (release && report) {
    if (metadata && report.url !== metadata.ciReportUrl) {
      problems.push('evidence report URL does not match release metadata');
    }
    if (
      metadata &&
      (report.fallbackUrl != null || report.fallbackKind != null) &&
      report.fallbackUrl !== metadata.fullReleaseValidationUrl
    ) {
      problems.push('evidence report fallback URL does not match release metadata');
    }
    if (report.expectedReleaseTag !== release.tag) {
      problems.push('evidence report expected release tag does not match release');
    }
    if (report.expectedReleaseSha !== release.catalogTagCommitOid) {
      problems.push('evidence report expected release SHA does not match release');
    }
    const expectedReportIdentity = releaseEvidenceReportIdentity(release, report);
    if (payload.evidenceReportIdentity !== expectedReportIdentity) {
      problems.push('evidenceReportIdentity does not match release/report content');
    }
  }
  return problems;
}

export function releaseEvidenceReportIdentity(
  release: ReleaseArtifactIdentity,
  report: EvidenceReportVerification,
): string {
  return `release-evidence-v1:sha256:${sha256(
    'release_evidence_report_identity_v1',
    canonicalJson(canonicalReleaseIdentity(release)),
    canonicalJson(canonicalEvidenceReport(report)),
  )}`;
}

function canonicalReleaseIdentity(
  value: ReleaseArtifactIdentity,
): ReleaseArtifactIdentity {
  const repository = requiredCanonicalString(
    value.repository,
    'artifact release repository',
  );
  if (!/^[^/\s]+\/[^/\s]+$/.test(repository)) {
    throw new Error('Artifact release repository must be owner/name');
  }
  const tag = requiredCanonicalString(value.tag, 'artifact release tag');
  const releaseNodeId = requiredCanonicalString(
    value.releaseNodeId,
    'artifact release node ID',
  );
  const catalogTagCommitOid = canonicalizeGitSha(
    value.catalogTagCommitOid,
    'artifact catalog tag commit OID',
  );
  if (!catalogTagCommitOid.value) {
    throw new Error(catalogTagCommitOid.problem ?? 'Artifact catalog tag commit OID invalid');
  }
  return {
    repository,
    tag,
    releaseNodeId,
    catalogTagCommitOid: catalogTagCommitOid.value,
    publishedAt: canonicalTimestamp(
      value.publishedAt,
      'artifact release publishedAt',
    ),
  };
}

function canonicalReleaseMetadata(
  value: ReleaseArtifactMetadata,
): ReleaseArtifactMetadata {
  return {
    npmPackageUrl: optionalCanonicalString(
      value.npmPackageUrl,
      'release npm package URL',
    ),
    releaseTarballUrl: optionalCanonicalString(
      value.releaseTarballUrl,
      'release tarball URL',
    ),
    releaseIntegrity: optionalCanonicalString(
      value.releaseIntegrity,
      'release integrity',
    ),
    releaseSha: optionalCanonicalString(value.releaseSha, 'release SHA'),
    ciReportUrl: optionalCanonicalString(value.ciReportUrl, 'CI report URL'),
    fullReleaseValidationUrl: optionalCanonicalString(
      value.fullReleaseValidationUrl,
      'full release validation URL',
    ),
  };
}

function canonicalArtifactEvidence(
  value: ArtifactVerificationEvidence,
): ArtifactVerificationEvidence {
  if (value.schemaVersion !== ARTIFACT_VERIFICATION_SCHEMA_VERSION) {
    throw new Error(
      `Artifact evidence schemaVersion must equal ` +
        `${ARTIFACT_VERIFICATION_SCHEMA_VERSION}`,
    );
  }
  const replayed = replayArtifactVerificationEvidence(value);
  if (canonicalJson(replayed) !== canonicalJson(value)) {
    throw new Error('Artifact evidence does not replay from its retained source facts');
  }
  if (value.packageName !== 'openclaw') {
    throw new Error('Artifact evidence packageName must equal openclaw');
  }
  requiredCanonicalString(value.requestedVersion, 'artifact requested version');
  if (value.metadataContentDigest != null) {
    assertSha256(value.metadataContentDigest, 'artifact metadata content digest');
  }
  if (
    value.tarballByteCount != null &&
    (!Number.isSafeInteger(value.tarballByteCount) || value.tarballByteCount < 0)
  ) {
    throw new Error('Artifact tarball byte count must be a non-negative safe integer');
  }
  for (const { name, digestBytes } of SUPPORTED_SRI_ALGORITHMS) {
    assertOptionalBase64Digest(value.actualDigests[name], digestBytes, name);
  }
  const canonicalRegistrySri = canonicalizeSri(
    value.canonicalIntegrity,
    'artifact canonical registry integrity',
  );
  if (
    value.registryVerified &&
    (!canonicalRegistrySri.value ||
      value.actualDigests[canonicalRegistrySri.value.algorithm] !==
        canonicalRegistrySri.value.digestBase64 ||
      value.tarballByteCount == null ||
      value.tarballByteCount <= 0 ||
      !value.registryIdentity)
  ) {
    throw new Error(
      'Registry-verified artifact must retain matching digest, byte count, and identity',
    );
  }
  if (value.releaseBound !== value.verified) {
    throw new Error('Artifact releaseBound and verified flags must agree');
  }
  if (
    value.releaseBound &&
    (value.releaseBindingState !== 'release_bound' ||
      !value.releaseBindingIdentity ||
      !value.canonicalExpectedIntegrity ||
      !value.canonicalExpectedTarballUrl ||
      !value.canonicalExpectedReleaseSha)
  ) {
    throw new Error('Release-bound artifact is missing canonical binding evidence');
  }
  if (value.mismatch != null && value.state !== 'mismatch') {
    throw new Error('Artifact mismatch detail requires mismatch state');
  }
  return JSON.parse(canonicalJson(value)) as ArtifactVerificationEvidence;
}

function canonicalEvidenceReport(
  value: EvidenceReportVerification,
): EvidenceReportVerification {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Evidence report must be an object');
  }
  const url = optionalCanonicalString(value.url, 'evidence report URL');
  const rawUrl = optionalCanonicalString(value.rawUrl, 'evidence report raw URL');
  if (url === null && rawUrl !== null) {
    throw new Error('Evidence report raw URL requires a primary report URL');
  }
  if (!Number.isSafeInteger(value.fallbackArtifactCount) ||
      value.fallbackArtifactCount < 0) {
    throw new Error('Evidence report fallback artifact count is invalid');
  }
  for (const [label, digest] of [
    ['content digest', value.contentDigest],
    ['fallback artifact digest', value.fallbackArtifactDigest],
  ] as const) {
    if (digest != null) assertSha256(digest, `evidence report ${label}`);
  }
  if (
    value.fallbackKind !== null &&
    value.fallbackKind !== 'github_actions_run'
  ) {
    throw new Error('Evidence report fallback kind is invalid');
  }
  const fallbackUrl = optionalCanonicalString(
    value.fallbackUrl,
    'evidence report fallback URL',
  );
  const mismatch = optionalCanonicalString(
    value.mismatch,
    'evidence report mismatch',
  );
  const hasFallbackKind = value.fallbackKind !== null;
  const hasFallbackUrl = fallbackUrl !== null;
  if (hasFallbackKind !== hasFallbackUrl) {
    throw new Error(
      'Evidence report fallback kind and URL must both be present or null',
    );
  }
  if (value.verified && value.mismatch != null) {
    throw new Error('Verified evidence report cannot also carry mismatch detail');
  }
  if (typeof value.verified !== 'boolean') {
    throw new Error('Evidence report verified flag is invalid');
  }
  if (!hasFallbackKind) {
    if (value.fallbackArtifactCount !== 0) {
      throw new Error(
        'Evidence report without fallback must have zero artifact count',
      );
    }
    if (value.fallbackArtifactDigest !== null) {
      throw new Error(
        'Evidence report without fallback cannot retain fallback artifact digest',
      );
    }
    if (value.verified && value.contentDigest === null) {
      throw new Error(
        'Verified primary evidence report must retain a content digest',
      );
    }
    if (value.verified && (url === null || rawUrl === null)) {
      throw new Error(
        'Verified primary evidence report must retain its source URLs',
      );
    }
    if (!value.verified && value.contentDigest !== null) {
      throw new Error(
        'Failed primary evidence report cannot retain a success digest',
      );
    }
  } else if (value.verified) {
    if (value.fallbackArtifactCount <= 0) {
      throw new Error(
        'Verified fallback evidence report must retain a positive artifact count',
      );
    }
    if (
      value.contentDigest === null ||
      value.fallbackArtifactDigest === null
    ) {
      throw new Error(
        'Verified fallback evidence report must retain manifest and artifact digests',
      );
    }
  } else {
    if (
      value.contentDigest !== null ||
      value.fallbackArtifactDigest !== null
    ) {
      throw new Error(
        'Failed fallback evidence report cannot retain success digests',
      );
    }
    if (mismatch === null) {
      throw new Error(
        'Failed fallback evidence report must retain mismatch detail',
      );
    }
  }
  const expectedReleaseTag = optionalCanonicalString(
    value.expectedReleaseTag,
    'evidence report expected release tag',
  );
  const expectedReleaseSha = canonicalizeGitSha(
    value.expectedReleaseSha,
    'evidence report expected release SHA',
  );
  if (value.expectedReleaseSha != null && !expectedReleaseSha.value) {
    throw new Error(
      expectedReleaseSha.problem ?? 'Evidence report expected release SHA is invalid',
    );
  }
  if (
    value.verified &&
    (!expectedReleaseTag || !expectedReleaseSha.value)
  ) {
    throw new Error('Verified evidence report must retain its release tag and SHA binding');
  }
  return {
    url,
    rawUrl,
    fallbackUrl,
    fallbackKind: value.fallbackKind,
    fallbackArtifactCount: value.fallbackArtifactCount,
    contentDigest: value.contentDigest,
    fallbackArtifactDigest: value.fallbackArtifactDigest,
    expectedReleaseTag,
    expectedReleaseSha: expectedReleaseSha.value,
    verified: value.verified,
    mismatch,
  };
}

function assertOptionalBase64Digest(
  value: string | null,
  digestBytes: number,
  algorithm: SupportedSriAlgorithm,
): void {
  if (value == null) return;
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== digestBytes || bytes.toString('base64') !== value) {
    throw new Error(`Artifact ${algorithm} digest is malformed`);
  }
}

function requiredCanonicalString(value: string, label: string): string {
  if (!value || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value;
}

function optionalCanonicalString(
  value: string | null,
  label: string,
): string | null {
  if (value == null) return null;
  if (!value || value.trim() !== value) {
    throw new Error(`${label} must be null or a non-empty canonical string`);
  }
  return value;
}

function canonicalTimestamp(value: string, label: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be a valid timestamp`);
  const canonical = new Date(parsed).toISOString();
  if (canonical !== value) throw new Error(`${label} must be canonical ISO-8601`);
  return canonical;
}

function assertSha256(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertOptionalSha256(value: string | null, label: string): void {
  if (value != null) assertSha256(value, label);
}

function sha256(domain: string, ...parts: unknown[]): string {
  const hash = createHash('sha256');
  hash.update(domain);
  hash.update('\0');
  for (const part of parts) {
    hash.update(canonicalJson(part));
    hash.update('\0');
  }
  return hash.digest('hex');
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
