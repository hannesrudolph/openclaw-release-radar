import { config } from '../config';
import { firstPatchedVersion } from './versionMatch';

const API = 'https://api.github.com/graphql';
const GRAPHQL_PAGE_SIZE = 100;
const COMMENT_BATCH_SIZE = 25;
const RECENT_COMMENT_LIMIT = 100;

export interface GhRelease {
  tag_name: string;
  name: string | null;
  published_at: string | null;
  html_url: string;
  prerelease: boolean;
  draft: boolean;
  // Release-notes markdown. Mined for maintainer-signal counts
  // (### Breaking / ### Fixes / etc.) — see lib/releaseNotes.ts.
  body: string | null;
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
  pull_request?: unknown; // REST compatibility; GraphQL repository.issues never returns PRs.
}

export interface GhComment {
  id: number;
  user: { login: string } | null;
  body: string;
  created_at: string;
}

interface GraphqlResponse<T> {
  data?: T;
  errors?: Array<{ message: string; type?: string; path?: Array<string | number> }>;
}

interface PageInfo {
  hasNextPage: boolean;
  endCursor: string | null;
}

interface ActorNode {
  login: string;
}

interface ReleaseNode {
  tagName: string;
  name: string | null;
  publishedAt: string | null;
  url: string;
  isPrerelease: boolean;
  isDraft: boolean;
  description: string | null;
}

interface IssueNode {
  number: number;
  title: string;
  body: string | null;
  state: 'OPEN' | 'CLOSED';
  author: ActorNode | null;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  url: string;
  comments: { totalCount: number };
  labels: { nodes: Array<{ name: string } | null> | null } | null;
}

interface CommentNode {
  databaseId: number | null;
  author: ActorNode | null;
  body: string;
  createdAt: string;
}

interface SecurityVulnerabilityNode {
  vulnerableVersionRange: string;
  firstPatchedVersion: { identifier: string } | null;
  package: { ecosystem: string; name: string | null };
  advisory: {
    ghsaId: string;
    identifiers: Array<{ type: 'CVE' | 'GHSA'; value: string }>;
    summary: string;
    severity: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
    publishedAt: string;
    permalink: string | null;
    withdrawnAt: string | null;
  };
}

interface ReleasesQueryData {
  repository: {
    releases: {
      nodes: Array<ReleaseNode | null> | null;
      pageInfo: PageInfo;
    };
  } | null;
}

interface IssuesQueryData {
  repository: {
    issues: {
      nodes: Array<IssueNode | null> | null;
      pageInfo: PageInfo;
    };
  } | null;
}

interface IssueCommentsQueryData {
  repository: Record<string, { comments: { nodes: Array<CommentNode | null> | null } } | null> | null;
}

interface SecurityVulnerabilitiesQueryData {
  securityVulnerabilities: {
    nodes: Array<SecurityVulnerabilityNode | null> | null;
    pageInfo: PageInfo;
  };
}

function headers(): Record<string, string> {
  if (!config.github.token) {
    throw new Error('GITHUB_TOKEN is required because GitHub GraphQL API requests must be authenticated');
  }
  return {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'User-Agent': 'openclaw-release-radar',
    Authorization: `Bearer ${config.github.token}`,
  };
}

async function gh<T>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
  const res = await fetch(API, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ query, variables }),
  });
  const body = await res.text();
  if (!res.ok) {
    throw new Error(`GitHub GraphQL ${res.status}: ${body.slice(0, 300)}`);
  }

  let parsed: GraphqlResponse<T>;
  try {
    parsed = JSON.parse(body) as GraphqlResponse<T>;
  } catch {
    throw new Error(`GitHub GraphQL returned non-JSON: ${body.slice(0, 300)}`);
  }

  if (parsed.errors?.length) {
    const details = parsed.errors
      .map((e) => [e.type, e.path?.join('.'), e.message].filter(Boolean).join(' '))
      .join('; ');
    throw new Error(`GitHub GraphQL error: ${details}`);
  }
  if (!parsed.data) throw new Error('GitHub GraphQL response did not include data');
  return parsed.data;
}

function repoVars(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { owner: config.github.owner, repo: config.github.repo, ...extra };
}

function assertRepo<T>(repo: T | null | undefined): T {
  if (!repo) throw new Error(`GitHub repository not found: ${config.github.owner}/${config.github.repo}`);
  return repo;
}

function mapRelease(node: ReleaseNode): GhRelease {
  return {
    tag_name: node.tagName,
    name: node.name,
    published_at: node.publishedAt,
    html_url: node.url,
    prerelease: node.isPrerelease,
    draft: node.isDraft,
    body: node.description,
  };
}

function mapIssue(node: IssueNode): GhIssue {
  return {
    number: node.number,
    title: node.title,
    body: node.body,
    state: node.state === 'OPEN' ? 'open' : 'closed',
    user: node.author ? { login: node.author.login } : null,
    created_at: node.createdAt,
    updated_at: node.updatedAt,
    closed_at: node.closedAt,
    html_url: node.url,
    comments: node.comments.totalCount,
    labels: (node.labels?.nodes ?? [])
      .filter((label): label is { name: string } => !!label)
      .map((label) => ({ name: label.name })),
  };
}

function mapComment(node: CommentNode): GhComment {
  return {
    id: node.databaseId ?? 0,
    user: node.author ? { login: node.author.login } : null,
    body: node.body,
    created_at: node.createdAt,
  };
}

function severityFromGraphql(severity: SecurityVulnerabilityNode['advisory']['severity']): GhAdvisory['severity'] {
  if (severity === 'MODERATE') return 'medium';
  return severity.toLowerCase() as GhAdvisory['severity'];
}

function mapSecurityVulnerabilities(nodes: SecurityVulnerabilityNode[]): GhAdvisory[] {
  const advisories = new Map<string, GhAdvisory>();

  for (const node of nodes) {
    if (node.advisory.withdrawnAt) continue;

    const existing = advisories.get(node.advisory.ghsaId);
    const advisory = existing ?? {
      ghsa_id: node.advisory.ghsaId,
      cve_id: node.advisory.identifiers.find((id) => id.type === 'CVE')?.value ?? null,
      summary: node.advisory.summary,
      severity: severityFromGraphql(node.advisory.severity),
      state: 'published',
      published_at: node.advisory.publishedAt,
      html_url: node.advisory.permalink ?? `https://github.com/advisories/${node.advisory.ghsaId}`,
      vulnerabilities: [],
    };

    advisory.vulnerabilities.push({
      package: {
        ecosystem: node.package.ecosystem.toLowerCase(),
        name: node.package.name,
      },
      vulnerable_version_range: node.vulnerableVersionRange,
      patched_versions: node.firstPatchedVersion?.identifier ?? firstPatchedVersion(node.vulnerableVersionRange),
    });

    advisories.set(advisory.ghsa_id, advisory);
  }

  return [...advisories.values()];
}

// Fetch releases through GraphQL. Each GraphQL page is capped at GitHub's 100-node
// connection maximum; callers can request a larger logical window and we'll page it.
export async function listReleases(fetchSize = 60): Promise<GhRelease[]> {
  const wanted = Math.max(1, fetchSize);
  const releases: GhRelease[] = [];
  let after: string | null = null;

  while (releases.length < wanted) {
    const first = Math.min(GRAPHQL_PAGE_SIZE, wanted - releases.length);
    const data: ReleasesQueryData = await gh<ReleasesQueryData>(
      `query Releases($owner: String!, $repo: String!, $first: Int!, $after: String) {
        repository(owner: $owner, name: $repo) {
          releases(first: $first, after: $after, orderBy: {field: CREATED_AT, direction: DESC}) {
            nodes {
              tagName
              name
              publishedAt
              url
              isPrerelease
              isDraft
              description
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }`,
      repoVars({ first, after }),
    );

    const connection = assertRepo(data.repository).releases;
    releases.push(
      ...(connection.nodes ?? [])
        .filter((node): node is ReleaseNode => !!node)
        .map(mapRelease)
        .filter((r) => !r.draft),
    );

    if (!connection.pageInfo.hasNextPage || !connection.pageInfo.endCursor) break;
    after = connection.pageInfo.endCursor;
  }

  return releases.slice(0, wanted);
}

// Stream issues sorted by updated_at descending, one GraphQL page at a time.
// GraphQL repository.issues excludes pull requests, so no PR stripping is needed.
export async function* paginateIssues(perPage = GRAPHQL_PAGE_SIZE): AsyncGenerator<GhIssue[], void, void> {
  const first = Math.min(GRAPHQL_PAGE_SIZE, Math.max(1, perPage));
  let after: string | null = null;

  for (;;) {
    const data: IssuesQueryData = await gh<IssuesQueryData>(
      `query Issues($owner: String!, $repo: String!, $first: Int!, $after: String) {
        repository(owner: $owner, name: $repo) {
          issues(
            first: $first
            after: $after
            states: [OPEN, CLOSED]
            orderBy: {field: UPDATED_AT, direction: DESC}
          ) {
            nodes {
              number
              title
              body
              state
              author { login }
              createdAt
              updatedAt
              closedAt
              url
              comments { totalCount }
              labels(first: 100) { nodes { name } }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }`,
      repoVars({ first, after }),
    );

    const connection = assertRepo(data.repository).issues;
    const page = (connection.nodes ?? [])
      .filter((node): node is IssueNode => !!node)
      .map(mapIssue);
    if (page.length === 0) return;
    yield page;

    if (!connection.pageInfo.hasNextPage || !connection.pageInfo.endCursor) return;
    after = connection.pageInfo.endCursor;
  }
}

export async function listIssueComments(issueNumber: number): Promise<GhComment[]> {
  const comments = await listIssueCommentsBatch([issueNumber]);
  return comments.get(issueNumber) ?? [];
}

export async function listIssueCommentsBatch(issueNumbers: number[]): Promise<Map<number, GhComment[]>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n));
  const all = new Map<number, GhComment[]>();
  for (const issueNumber of uniqueIssueNumbers) all.set(issueNumber, []);

  for (let offset = 0; offset < uniqueIssueNumbers.length; offset += COMMENT_BATCH_SIZE) {
    const chunk = uniqueIssueNumbers.slice(offset, offset + COMMENT_BATCH_SIZE);
    if (chunk.length === 0) continue;
    const data: IssueCommentsQueryData = await gh<IssueCommentsQueryData>(
      buildIssueCommentsBatchQuery(chunk.length),
      repoVars({
        last: RECENT_COMMENT_LIMIT,
        ...Object.fromEntries(chunk.map((issueNumber, idx) => [`number${idx}`, issueNumber])),
      }),
    );

    const repo = assertRepo(data.repository);
    for (let idx = 0; idx < chunk.length; idx++) {
      const issue = repo[`issue${idx}`];
      all.set(
        chunk[idx],
        (issue?.comments.nodes ?? [])
          .filter((node): node is CommentNode => !!node)
          .map(mapComment),
      );
    }
  }

  return all;
}

function buildIssueCommentsBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      comments(last: $last, orderBy: {field: UPDATED_AT, direction: ASC}) {
        nodes {
          databaseId
          author { login }
          body
          createdAt
        }
      }
    }`).join('\n');

  return `query IssueComments($owner: String!, $repo: String!, $last: Int!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      ${fields}
    }
  }`;
}

// GitHub Advisory Database data for the package this radar tracks. GraphQL exposes
// advisories through package vulnerabilities rather than the REST-only repository
// security-advisories endpoint, so we filter to the tracked repo/package name.
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
  const vulnerabilities: SecurityVulnerabilityNode[] = [];
  let after: string | null = null;

  for (;;) {
    const data: SecurityVulnerabilitiesQueryData = await gh<SecurityVulnerabilitiesQueryData>(
      `query SecurityVulnerabilities($package: String!, $after: String) {
        securityVulnerabilities(
          first: 100
          after: $after
          ecosystem: NPM
          package: $package
          orderBy: {field: UPDATED_AT, direction: DESC}
        ) {
          nodes {
            vulnerableVersionRange
            firstPatchedVersion { identifier }
            package { ecosystem name }
            advisory {
              ghsaId
              identifiers { type value }
              summary
              severity
              publishedAt
              permalink
              withdrawnAt
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }`,
      { package: config.github.repo, after },
    );

    vulnerabilities.push(
      ...(data.securityVulnerabilities.nodes ?? [])
        .filter((node): node is SecurityVulnerabilityNode => !!node),
    );

    if (!data.securityVulnerabilities.pageInfo.hasNextPage || !data.securityVulnerabilities.pageInfo.endCursor) break;
    after = data.securityVulnerabilities.pageInfo.endCursor;
  }

  return mapSecurityVulnerabilities(vulnerabilities);
}

export const __githubTest = {
  buildIssueCommentsBatchQuery,
  mapComment,
  mapIssue,
  mapRelease,
  mapSecurityVulnerabilities,
};
