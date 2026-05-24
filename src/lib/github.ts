import { config } from '../config';

const API = 'https://api.github.com';

export interface GhRelease {
  tag_name: string;
  name: string | null;
  published_at: string | null;
  html_url: string;
  prerelease: boolean;
  draft: boolean;
}

export interface GhIssue {
  number: number;
  title: string;
  body: string | null;
  state: 'open' | 'closed';
  user: { login: string } | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  html_url: string;
  comments: number;
  labels: { name: string }[];
  pull_request?: unknown; // present => PR, skip
}

export interface GhComment {
  id: number;
  user: { login: string } | null;
  body: string;
  created_at: string;
}

function headers(): Record<string, string> {
  const h: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'openclaw-release-radar',
  };
  if (config.github.token) h.Authorization = `Bearer ${config.github.token}`;
  return h;
}

async function gh<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`, { headers: headers() });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`GitHub ${res.status} ${path}: ${body.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

export async function listReleases(limit = 10): Promise<GhRelease[]> {
  // We fetch a wider page than `limit` because GitHub returns prereleases interleaved
  // with stable; on openclaw, betas outnumber stables ~3:1, so a 10-item page can
  // contain only 2-3 actual stable releases. Cap at 100 (GitHub's per_page max) and
  // trim to `limit` after filtering.
  const { owner, repo } = config.github;
  const fetchSize = Math.min(100, limit * 6);
  const data = await gh<GhRelease[]>(`/repos/${owner}/${repo}/releases?per_page=${fetchSize}`);
  return data.filter((r) => !r.draft && !r.prerelease).slice(0, limit);
}

// Stream issues sorted by updated_at descending, one page at a time. PRs are stripped
// at the source so consumers only see real issues. The caller decides when to stop —
// typically when it has seen a full page of already-known issues, or paginated past the
// oldest release it cares about. Yields an empty array if a page was 100% PRs (caller
// should keep iterating in that case).
export async function* paginateIssues(perPage = 100): AsyncGenerator<GhIssue[], void, void> {
  const { owner, repo } = config.github;
  for (let page = 1; ; page++) {
    const data = await gh<GhIssue[]>(
      `/repos/${owner}/${repo}/issues?state=all&sort=updated&direction=desc&per_page=${perPage}&page=${page}`,
    );
    if (data.length === 0) return; // dataset exhausted
    yield data.filter((i) => !i.pull_request);
    if (data.length < perPage) return; // short page → no more after this
  }
}

export async function listIssueComments(issueNumber: number): Promise<GhComment[]> {
  const { owner, repo } = config.github;
  return gh<GhComment[]>(`/repos/${owner}/${repo}/issues/${issueNumber}/comments?per_page=100`);
}

// GitHub Security Advisories. Maintainer-filed CVEs with structured version
// ranges — we use these as the authoritative "which release patches/is
// vulnerable to which CVE" signal. No LLM, no body parsing, no guessing.
export interface GhAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  state: 'published' | 'closed' | 'withdrawn' | 'triage' | 'draft';
  published_at: string | null;
  html_url: string;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string | null } | null;
    vulnerable_version_range: string | null;
    patched_versions: string | null;
  }>;
}

export async function listSecurityAdvisories(): Promise<GhAdvisory[]> {
  const { owner, repo } = config.github;
  // Single endpoint returns ALL advisories for the repo — backfill comes free.
  // per_page max is 100; openclaw currently has ~30, plenty of headroom.
  const data = await gh<GhAdvisory[]>(
    `/repos/${owner}/${repo}/security-advisories?per_page=100&state=published`,
  );
  return data.filter((a) => a.state === 'published');
}
