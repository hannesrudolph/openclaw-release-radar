import { config } from '../config';

export interface EvidenceReportVerification {
  url: string | null;
  rawUrl: string | null;
  fallbackUrl: string | null;
  fallbackKind: 'github_actions_run' | null;
  fallbackArtifactCount: number;
  verified: boolean;
  mismatch: string | null;
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
): Promise<EvidenceReportVerification> {
  if (!url) {
    if (fallbackActionRunUrl) return verifyActionRunFallback({ url, rawUrl: null, fallbackActionRunUrl });
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
    if (fallbackActionRunUrl) return verifyActionRunFallback({ url, rawUrl, fallbackActionRunUrl });
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
  const artifacts = await artifactsResponse.json() as { artifacts?: Array<{ expired?: boolean; size_in_bytes?: number }> };
  const artifactCount = (artifacts.artifacts ?? [])
    .filter((artifact) => artifact.expired !== true && Number(artifact.size_in_bytes ?? 0) > 0)
    .length;
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
