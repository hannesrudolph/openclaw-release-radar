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
  const { owner, repo } = config.github;
  const data = await gh<GhRelease[]>(`/repos/${owner}/${repo}/releases?per_page=${limit}`);
  return data.filter((r) => !r.draft);
}

export async function listIssues(limit = 80): Promise<GhIssue[]> {
  // The /issues endpoint returns BOTH issues and PRs (GitHub treats PRs as a kind of issue).
  // On active repos like openclaw/openclaw, the first page is dominated by PRs (~80%) and
  // a single 100-item page yields only ~20 real issues. We paginate until we either:
  //   - collect `limit` non-PR issues, or
  //   - exhaust MAX_PAGES (safety cap against runaway fetches), or
  //   - GitHub returns a short page (end of dataset).
  const { owner, repo } = config.github;
  const MAX_PAGES = 10; // 10 × 100 = up to ~1000 raw items, plenty even with heavy PR traffic
  const out: GhIssue[] = [];
  for (let page = 1; page <= MAX_PAGES && out.length < limit; page++) {
    const data = await gh<GhIssue[]>(
      `/repos/${owner}/${repo}/issues?state=all&sort=updated&direction=desc&per_page=100&page=${page}`,
    );
    for (const i of data) {
      if (!i.pull_request) out.push(i);
      if (out.length >= limit) break;
    }
    if (data.length < 100) break; // last page
  }
  return out.slice(0, limit);
}

export async function listIssueComments(issueNumber: number): Promise<GhComment[]> {
  const { owner, repo } = config.github;
  return gh<GhComment[]>(`/repos/${owner}/${repo}/issues/${issueNumber}/comments?per_page=100`);
}
