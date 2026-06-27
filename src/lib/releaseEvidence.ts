export interface EvidenceReportVerification {
  url: string | null;
  rawUrl: string | null;
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

export async function verifyEvidenceReportUrl(url: string | null): Promise<EvidenceReportVerification> {
  if (!url) {
    return {
      url: null,
      rawUrl: null,
      verified: false,
      mismatch: null,
    };
  }
  const rawUrl = rawGitHubUrl(url);
  const response = await fetch(rawUrl, {
    headers: { 'user-agent': 'openclaw-release-radar' },
  });
  if (response.status === 404) {
    return {
      url,
      rawUrl,
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
      verified: false,
      mismatch: 'release evidence report empty',
    };
  }
  return {
    url,
    rawUrl,
    verified: true,
    mismatch: null,
  };
}
