import { config } from '../config';
import { inflateRawSync } from 'node:zlib';

export interface EvidenceReportVerification {
  url: string | null;
  rawUrl: string | null;
  fallbackUrl: string | null;
  fallbackKind: 'github_actions_run' | null;
  fallbackArtifactCount: number;
  verified: boolean;
  mismatch: string | null;
}

export interface EvidenceReportVerificationOptions {
  expectedReleaseTag?: string | null;
  expectedReleaseSha?: string | null;
}

export function rawGitHubUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.hostname !== 'github.com') return url;
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
  if (!url) {
    if (fallbackActionRunUrl) return verifyActionRunFallback({ url, rawUrl: null, fallbackActionRunUrl, ...options });
    return {
      url: null,
      rawUrl: null,
      fallbackUrl: null,
      fallbackKind: null,
      fallbackArtifactCount: 0,
      verified: false,
      mismatch: null,
    };
  }
  const rawUrl = rawGitHubUrl(url);
  const response = await fetch(rawUrl, {
    headers: { 'user-agent': 'openclaw-release-radar' },
  });
  if (response.status === 404) {
    if (fallbackActionRunUrl) return verifyActionRunFallback({ url, rawUrl, fallbackActionRunUrl, ...options });
    return {
      url,
      rawUrl,
      fallbackUrl: null,
      fallbackKind: null,
      fallbackArtifactCount: 0,
      verified: false,
      mismatch: 'release evidence report not found',
    };
  }
  if (!response.ok) {
    throw new Error(`release evidence report ${response.status}: ${await response.text()}`);
  }
  const body = await response.text();
  if (!body.trim()) {
    return {
      url,
      rawUrl,
      fallbackUrl: null,
      fallbackKind: null,
      fallbackArtifactCount: 0,
      verified: false,
      mismatch: 'release evidence report empty',
    };
  }
  return {
    url,
    rawUrl,
    fallbackUrl: null,
    fallbackKind: null,
    fallbackArtifactCount: 0,
    verified: true,
    mismatch: null,
  };
}

function githubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    accept: 'application/vnd.github+json',
    'user-agent': 'openclaw-release-radar',
  };
  if (config.github.token) headers.authorization = `Bearer ${config.github.token}`;
  return headers;
}

function parseGitHubActionsRunUrl(url: string): { owner: string; repo: string; runId: string } | null {
  try {
    const parsed = new URL(url);
    if (parsed.hostname !== 'github.com') return null;
    const parts = parsed.pathname.split('/').filter(Boolean);
    if (parts.length !== 5 || parts[2] !== 'actions' || parts[3] !== 'runs') return null;
    return { owner: parts[0], repo: parts[1], runId: parts[4] };
  } catch {
    return null;
  }
}

async function verifyActionRunFallback(input: {
  url: string | null;
  rawUrl: string | null;
  fallbackActionRunUrl: string;
  expectedReleaseTag?: string | null;
  expectedReleaseSha?: string | null;
}): Promise<EvidenceReportVerification> {
  const parsed = parseGitHubActionsRunUrl(input.fallbackActionRunUrl);
  if (!parsed) {
    return {
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: 0,
      verified: false,
      mismatch: 'release evidence report not found; fallback action URL invalid',
    };
  }
  const base = `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/actions/runs/${parsed.runId}`;
  const [runResponse, artifactsResponse] = await Promise.all([
    fetch(base, { headers: githubHeaders() }),
    fetch(`${base}/artifacts`, { headers: githubHeaders() }),
  ]);
  if (!runResponse.ok) {
    return {
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: 0,
      verified: false,
      mismatch: `release evidence report not found; fallback action ${runResponse.status}`,
    };
  }
  if (!artifactsResponse.ok) {
    return {
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: 0,
      verified: false,
      mismatch: `release evidence report not found; fallback artifacts ${artifactsResponse.status}`,
    };
  }
  const run = await runResponse.json() as { status?: string; conclusion?: string };
  const artifacts = await artifactsResponse.json() as {
    artifacts?: Array<{ expired?: boolean; size_in_bytes?: number; archive_download_url?: string }>;
  };
  const candidateArtifacts = (artifacts.artifacts ?? [])
    .filter((artifact) => artifact.expired !== true && Number(artifact.size_in_bytes ?? 0) > 0)
    .filter((artifact: any) => typeof artifact.archive_download_url === 'string');
  const artifactCount = candidateArtifacts.length;
  if (run.status !== 'completed' || run.conclusion !== 'success') {
    return {
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: artifactCount,
      verified: false,
      mismatch: `release evidence report not found; fallback action ${run.status ?? 'unknown'}/${run.conclusion ?? 'unknown'}`,
    };
  }
  if (artifactCount <= 0) {
    return {
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: 0,
      verified: false,
      mismatch: 'release evidence report not found; fallback action artifact not found',
    };
  }
  const manifestResult = await verifyFallbackManifest(candidateArtifacts, {
    expectedReleaseTag: input.expectedReleaseTag,
    expectedReleaseSha: input.expectedReleaseSha,
  });
  if (!manifestResult.verified) {
    return {
      url: input.url,
      rawUrl: input.rawUrl,
      fallbackUrl: input.fallbackActionRunUrl,
      fallbackKind: 'github_actions_run',
      fallbackArtifactCount: artifactCount,
      verified: false,
      mismatch: `release evidence report not found; ${manifestResult.mismatch}`,
    };
  }
  return {
    url: input.url,
    rawUrl: input.rawUrl,
    fallbackUrl: input.fallbackActionRunUrl,
    fallbackKind: 'github_actions_run',
    fallbackArtifactCount: artifactCount,
    verified: true,
    mismatch: null,
  };
}

async function verifyFallbackManifest(
  artifacts: Array<{ archive_download_url?: string }>,
  options: EvidenceReportVerificationOptions,
): Promise<{ verified: boolean; mismatch: string | null }> {
  let firstMismatch: string | null = null;
  for (const artifact of artifacts) {
    if (!artifact.archive_download_url) continue;
    const response = await fetch(artifact.archive_download_url, { headers: githubHeaders() });
    if (!response.ok) continue;
    const archive = Buffer.from(await response.arrayBuffer());
    for (const jsonText of extractJsonFilesFromZip(archive)) {
      const manifest = parseManifest(jsonText);
      if (!manifest) continue;
      const mismatch = validationManifestMismatch(manifest, options);
      if (!mismatch) return { verified: true, mismatch: null };
      firstMismatch ??= mismatch;
    }
  }
  return { verified: false, mismatch: firstMismatch ?? 'fallback action manifest not found' };
}

function parseManifest(jsonText: string): { targetRef?: string; targetSha?: string } | null {
  try {
    const parsed = JSON.parse(jsonText);
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed as { targetRef?: string; targetSha?: string };
  } catch {
    return null;
  }
}

function validationManifestMismatch(
  manifest: { targetRef?: string; targetSha?: string },
  options: EvidenceReportVerificationOptions,
): string | null {
  const expectedSha = options.expectedReleaseSha?.toLowerCase() ?? null;
  if (expectedSha && String(manifest.targetSha ?? '').toLowerCase() !== expectedSha) {
    return `fallback action targetSha ${manifest.targetSha ?? 'missing'} != ${options.expectedReleaseSha}`;
  }
  const expectedTag = options.expectedReleaseTag ?? null;
  if (expectedTag) {
    const expectedVersion = expectedTag.replace(/^v/, '');
    const allowedRefs = new Set([expectedTag, `release/${expectedVersion}`]);
    if (!allowedRefs.has(String(manifest.targetRef ?? ''))) {
      return `fallback action targetRef ${manifest.targetRef ?? 'missing'} != ${expectedTag}`;
    }
  }
  return null;
}

function extractJsonFilesFromZip(buffer: Buffer): string[] {
  const eocdOffset = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocdOffset < 0 || eocdOffset + 22 > buffer.length) return [];
  const entries = buffer.readUInt16LE(eocdOffset + 10);
  let cursor = buffer.readUInt32LE(eocdOffset + 16);
  const out: string[] = [];
  for (let i = 0; i < entries && cursor + 46 <= buffer.length; i++) {
    if (buffer.readUInt32LE(cursor) !== 0x02014b50) break;
    const method = buffer.readUInt16LE(cursor + 10);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const fileNameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localHeaderOffset = buffer.readUInt32LE(cursor + 42);
    const fileName = buffer.subarray(cursor + 46, cursor + 46 + fileNameLength).toString('utf8');
    cursor += 46 + fileNameLength + extraLength + commentLength;
    if (!fileName.endsWith('.json')) continue;
    if (localHeaderOffset + 30 > buffer.length || buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) continue;
    const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > buffer.length) continue;
    const compressed = buffer.subarray(dataStart, dataEnd);
    if (method === 0) out.push(compressed.toString('utf8'));
    else if (method === 8) out.push(inflateRawSync(compressed).toString('utf8'));
  }
  return out;
}
