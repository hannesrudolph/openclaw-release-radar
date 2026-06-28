import { config } from '../config';
import { firstPatchedVersion } from './versionMatch';

const API = 'https://api.github.com/graphql';
const GRAPHQL_PAGE_SIZE = 100;
const COMMENT_BATCH_SIZE = 25;
const COMMENT_PAGE_SIZE = 100;

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
  author_association?: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  html_url: string;
  comments: number;
  maintainer_commenters?: number;
  contributor_commenters?: number;
  reaction_total?: number;
  positive_reactions?: number;
  labels: { name: string }[];
  pull_request?: unknown; // REST compatibility; GraphQL repository.issues never returns PRs.
}

export interface GhComment {
  id: number;
  user: { login: string } | null;
  author_association?: string | null;
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
  authorAssociation: string | null;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  url: string;
  comments: { totalCount: number };
  reactionGroups: Array<ReactionGroupNode | null> | null;
  labels: { nodes: Array<{ name: string } | null> | null; pageInfo?: PageInfo | null } | null;
}

interface CommentNode {
  databaseId: number | null;
  author: ActorNode | null;
  authorAssociation: string | null;
  body: string;
  createdAt: string;
}

interface ReactionGroupNode {
  content: string;
  reactors: { totalCount: number };
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
  repository: Record<string, { comments: { nodes: Array<CommentNode | null> | null; pageInfo: PageInfo } } | null> | null;
}

interface SecurityVulnerabilitiesQueryData {
  securityVulnerabilities: {
    nodes: Array<SecurityVulnerabilityNode | null> | null;
    pageInfo: PageInfo;
  };
}

export interface GhReleaseCommit {
  tag: string;
  oid: string | null;
  committedAt: string | null;
  checkState: string | null;
  checkTotal: number;
  checkSuccess: number;
  checkFailure: number;
  checkPending: number;
  checkSkipped: number;
  checkContexts: GhReleaseCheckContext[];
}

export interface GhReleaseCheckContext {
  type: string;
  name: string;
  workflowName: string | null;
  appSlug: string | null;
  status: string | null;
  conclusion: string | null;
  url: string | null;
}

export interface GhPullRequestFix {
  number: number;
  title: string | null;
  url: string | null;
  state: string | null;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitOid: string | null;
  baseRefName: string | null;
}

export interface GhIssueClosureEvent {
  issueNumber: number;
  eventId: string;
  closedAt: string | null;
  actorLogin: string | null;
  stateReason: string | null;
  closerType: string | null;
  closerNumber: number | null;
  closerOid: string | null;
  raw: unknown;
}

export interface GhIssueReopenEvent {
  issueNumber: number;
  eventId: string;
  reopenedAt: string | null;
  actorLogin: string | null;
  raw: unknown;
}

export interface GhIssuePrLink {
  issueNumber: number;
  prNumber: number;
  source: string;
  willCloseTarget: boolean | null;
  referencedAt: string | null;
}

export interface GhIssueLabelEvent {
  issueNumber: number;
  eventId: string;
  action: 'labeled' | 'unlabeled';
  labelName: string;
  actorLogin: string | null;
  createdAt: string;
}

export interface GhIssueFixEvidence {
  issueNumber: number;
  closureEvents: GhIssueClosureEvent[];
  reopenEvents: GhIssueReopenEvent[];
  prLinks: GhIssuePrLink[];
  pullRequests: GhPullRequestFix[];
}

export interface ClosureCommentPrMention {
  issueNumber: number;
  prNumber: number;
  referencedAt: string | null;
  author: string | null;
  authorAssociation: string | null;
  trustedSource: boolean;
}

export interface ClosureCommentCommitMention {
  issueNumber: number;
  commitOid: string;
  referencedAt: string | null;
  sourceIssueNumber: number;
  snippet: string;
  source: 'ClosureComment.fixProof' | 'ClosedEvent.closer';
  author: string | null;
  authorAssociation: string | null;
  trustedSource: boolean;
}

export async function listIssueLabelEventsBatch(issueNumbers: number[]): Promise<Map<number, GhIssueLabelEvent[]>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n));
  const all = new Map<number, GhIssueLabelEvent[]>();
  for (const issueNumber of uniqueIssueNumbers) all.set(issueNumber, []);

  const batchSize = 10;
  for (let offset = 0; offset < uniqueIssueNumbers.length; offset += batchSize) {
    const chunk = uniqueIssueNumbers.slice(offset, offset + batchSize);
    const cursors = new Map<number, string | null>(chunk.map((issueNumber) => [issueNumber, null]));
    const done = new Set<number>();
    while (done.size < chunk.length) {
      const active = chunk.filter((issueNumber) => !done.has(issueNumber));
      const data = await gh<{ repository: Record<string, any> | null }>(
        buildIssueLabelEventsBatchQuery(active.length),
        repoVars(Object.fromEntries(active.flatMap((issueNumber, idx) => [
          [`number${idx}`, issueNumber],
          [`after${idx}`, cursors.get(issueNumber) ?? null],
        ]))),
      );
      const repo = assertRepo(data.repository);
      for (let idx = 0; idx < active.length; idx++) {
        const issueNumber = active[idx];
        const issue = repo[`issue${idx}`];
        const connection = issue?.timelineItems;
        const events = all.get(issueNumber) ?? [];
        for (const node of connection?.nodes ?? []) {
          const type = node?.__typename;
          if (type !== 'LabeledEvent' && type !== 'UnlabeledEvent') continue;
          const labelName = node.label?.name;
          if (!labelName) continue;
          events.push({
            issueNumber,
            eventId: node.id,
            action: type === 'LabeledEvent' ? 'labeled' : 'unlabeled',
            labelName,
            actorLogin: node.actor?.login ?? null,
            createdAt: node.createdAt,
          });
        }
        all.set(issueNumber, events);
        if (connection?.pageInfo?.hasNextPage && connection.pageInfo.endCursor) {
          cursors.set(issueNumber, connection.pageInfo.endCursor);
        } else {
          done.add(issueNumber);
        }
      }
    }
  }
  return all;
}

function buildIssueLabelEventsBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!, $after${idx}: String`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      timelineItems(first: 100, after: $after${idx}, itemTypes: [LABELED_EVENT, UNLABELED_EVENT]) {
        nodes {
          __typename
          ... on LabeledEvent { id createdAt actor { login } label { name } }
          ... on UnlabeledEvent { id createdAt actor { login } label { name } }
        }
        pageInfo { hasNextPage endCursor }
      }
    }`).join('\n');

  return `query IssueLabelEvents($owner: String!, $repo: String!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      ${fields}
    }
  }`;
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function retryDelayMs(attempt: number, res?: Response): number {
  const retryAfter = res?.headers.get('retry-after');
  const parsedRetryAfter = retryAfter ? Number(retryAfter) : NaN;
  if (Number.isFinite(parsedRetryAfter) && parsedRetryAfter > 0) {
    return Math.min(parsedRetryAfter * 1000, 300_000);
  }
  return Math.min(300_000, 15_000 * Math.pow(2, attempt));
}

async function gh<T>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    let res: Response;
    try {
      res = await fetch(API, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ query, variables }),
      });
    } catch (e) {
      if (attempt < 8) {
        const delay = retryDelayMs(attempt);
        console.warn(`[github] network error; retrying in ${Math.round(delay / 1000)}s: ${(e as Error).message}`);
        await sleep(delay);
        continue;
      }
      throw e;
    }
    const body = await res.text();
    if (!res.ok) {
      const retryable = res.status === 403 || res.status === 429 || res.status >= 500;
      if (retryable && attempt < 8) {
        const delay = retryDelayMs(attempt, res);
        console.warn(`[github] ${res.status}; retrying in ${Math.round(delay / 1000)}s`);
        await sleep(delay);
        continue;
      }
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

function mapIssue(node: IssueNode, extraLabelNodes: Array<{ name: string } | null> = []): GhIssue {
  const reactions = summarizeReactions(node.reactionGroups ?? []);
  const labelNames = new Set(
    [...(node.labels?.nodes ?? []), ...extraLabelNodes]
      .filter((label): label is { name: string } => !!label)
      .map((label) => label.name),
  );
  return {
    number: node.number,
    title: node.title,
    body: node.body,
    state: node.state === 'OPEN' ? 'open' : 'closed',
    user: node.author ? { login: node.author.login } : null,
    author_association: node.authorAssociation,
    created_at: node.createdAt,
    updated_at: node.updatedAt,
    closed_at: node.closedAt,
    html_url: node.url,
    comments: node.comments.totalCount,
    reaction_total: reactions.total,
    positive_reactions: reactions.positive,
    labels: [...labelNames].sort().map((name) => ({ name })),
  };
}

function mapComment(node: CommentNode): GhComment {
  return {
    id: node.databaseId ?? 0,
    user: node.author ? { login: node.author.login } : null,
    author_association: node.authorAssociation,
    body: node.body,
    created_at: node.createdAt,
  };
}

function summarizeReactions(nodes: Array<ReactionGroupNode | null>): {
  total: number;
  positive: number;
} {
  let total = 0;
  let positive = 0;
  for (const node of nodes) {
    const count = node?.reactors.totalCount ?? 0;
    total += count;
    if (['THUMBS_UP', 'HOORAY', 'HEART', 'ROCKET'].includes(node?.content ?? '')) {
      positive += count;
    }
  }
  return { total, positive };
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
    if (after && config.refresh.githubPageDelayMs > 0) {
      await sleep(config.refresh.githubPageDelayMs);
    }
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
              authorAssociation
              createdAt
              updatedAt
              closedAt
              url
              comments { totalCount }
              reactionGroups { content reactors { totalCount } }
              labels(first: 100) {
                nodes { name }
                pageInfo { hasNextPage endCursor }
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }`,
      repoVars({ first, after }),
    );

    const connection = assertRepo(data.repository).issues;
    const issueNodes = (connection.nodes ?? []).filter((node): node is IssueNode => !!node);
    const extraLabels = await remainingIssueLabelsForNodes(issueNodes);
    const page = issueNodes.map((node) => mapIssue(node, extraLabels.get(node.number) ?? []));
    if (page.length === 0) return;
    yield page;

    if (!connection.pageInfo.hasNextPage || !connection.pageInfo.endCursor) return;
    after = connection.pageInfo.endCursor;
  }
}

export async function listIssuesBatch(issueNumbers: number[]): Promise<Map<number, GhIssue>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n) && n > 0);
  const all = new Map<number, GhIssue>();
  const batchSize = 25;
  for (let offset = 0; offset < uniqueIssueNumbers.length; offset += batchSize) {
    const chunk = uniqueIssueNumbers.slice(offset, offset + batchSize);
    const data = await gh<{ repository: Record<string, IssueNode | null> | null }>(
      buildIssuesBatchQuery(chunk.length),
      repoVars(Object.fromEntries(chunk.map((issueNumber, idx) => [`number${idx}`, issueNumber]))),
    );
    const repo = assertRepo(data.repository);
    for (let idx = 0; idx < chunk.length; idx++) {
      const node = repo[`issue${idx}`];
      if (!node?.number) continue;
      const extraLabels = await remainingIssueLabelNodes(node.number, node.labels?.pageInfo ?? null);
      all.set(node.number, mapIssue(node, extraLabels));
    }
  }
  return all;
}

function buildIssuesBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      number
      title
      body
      state
      author { login }
      authorAssociation
      createdAt
      updatedAt
      closedAt
      url
      comments { totalCount }
      reactionGroups {
        content
        reactors { totalCount }
      }
      labels(first: 100) {
        nodes { name }
        pageInfo { hasNextPage endCursor }
      }
    }`).join('\n');
  return `query IssuesByNumber($owner: String!, $repo: String!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      ${fields}
    }
  }`;
}

async function remainingIssueLabelsForNodes(nodes: IssueNode[]): Promise<Map<number, Array<{ name: string } | null>>> {
  const out = new Map<number, Array<{ name: string } | null>>();
  await Promise.all(nodes.map(async (node) => {
    const labels = await remainingIssueLabelNodes(node.number, node.labels?.pageInfo ?? null);
    if (labels.length) out.set(node.number, labels);
  }));
  return out;
}

async function remainingIssueLabelNodes(
  issueNumber: number,
  pageInfo: PageInfo | null,
): Promise<Array<{ name: string } | null>> {
  const labels: Array<{ name: string } | null> = [];
  let after = pageInfo?.hasNextPage ? pageInfo.endCursor : null;
  while (after) {
    const data = await gh<{ repository: { issue: { labels: { nodes: Array<{ name: string } | null> | null; pageInfo: PageInfo } | null } | null } | null }>(
      buildIssueLabelsQuery(),
      repoVars({ number: issueNumber, after }),
    );
    const connection = assertRepo(data.repository).issue?.labels;
    labels.push(...(connection?.nodes ?? []));
    after = connection?.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
  }
  return labels;
}

function buildIssueLabelsQuery(): string {
  return `query IssueLabels($owner: String!, $repo: String!, $number: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      issue(number: $number) {
        labels(first: 100, after: $after) {
          nodes { name }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }`;
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
    const cursors = new Map<number, string | null>(chunk.map((issueNumber) => [issueNumber, null]));
    const done = new Set<number>();
    while (done.size < chunk.length) {
      const active = chunk.filter((issueNumber) => !done.has(issueNumber));
      let data: IssueCommentsQueryData;
      try {
        data = await gh<IssueCommentsQueryData>(
          buildIssueCommentsBatchQuery(active.length),
          repoVars({
            first: COMMENT_PAGE_SIZE,
            ...Object.fromEntries(active.flatMap((issueNumber, idx) => [
              [`number${idx}`, issueNumber],
              [`after${idx}`, cursors.get(issueNumber) ?? null],
            ])),
          }),
        );
      } catch (error) {
        const missingIndexes = missingIssueIndexesFromGraphqlError(error);
        if (!missingIndexes.length) throw error;
        let skipped = 0;
        for (const idx of missingIndexes) {
          const missingIssueNumber = active[idx];
          if (missingIssueNumber != null) {
            done.add(missingIssueNumber);
            skipped++;
          }
        }
        if (skipped === 0) throw error;
        continue;
      }

      const repo = assertRepo(data.repository);
      for (let idx = 0; idx < active.length; idx++) {
        const issueNumber = active[idx];
        const issue = repo[`issue${idx}`];
        const comments = all.get(issueNumber) ?? [];
        comments.push(...((issue?.comments.nodes ?? [])
          .filter((node): node is CommentNode => !!node)
          .map(mapComment)));
        all.set(issueNumber, comments);
        if (issue?.comments.pageInfo.hasNextPage && issue.comments.pageInfo.endCursor) {
          cursors.set(issueNumber, issue.comments.pageInfo.endCursor);
        } else {
          done.add(issueNumber);
        }
      }
    }
  }

  return all;
}

function missingIssueIndexesFromGraphqlError(error: unknown): number[] {
  const message = error instanceof Error ? error.message : String(error ?? '');
  const indexes = new Set<number>();
  for (const match of message.matchAll(/\brepository\.issue(\d+)\b(?=[^;]*Could not resolve to an Issue)/g)) {
    const idx = Number(match[1]);
    if (Number.isInteger(idx) && idx >= 0) indexes.add(idx);
  }
  return [...indexes].sort((a, b) => a - b);
}

function buildIssueCommentsBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!, $after${idx}: String`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      comments(first: $first, after: $after${idx}, orderBy: {field: UPDATED_AT, direction: ASC}) {
        nodes {
          databaseId
          author { login }
          authorAssociation
          body
          createdAt
        }
        pageInfo { hasNextPage endCursor }
      }
    }`).join('\n');

  return `query IssueComments($owner: String!, $repo: String!, $first: Int!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      ${fields}
    }
  }`;
}

export async function getReleaseCommit(tag: string): Promise<GhReleaseCommit> {
  const contexts: GhReleaseCheckContext[] = [];
  let after: string | null = null;
  let release: ReleaseCommitRelease | null = null;
  let rollup: ReleaseCommitRollup | null = null;

  for (;;) {
    const data: ReleaseCommitQueryData = await gh<ReleaseCommitQueryData>(buildReleaseCommitQuery(), repoVars({ tag, after }));
    release = assertRepo(data.repository).release;
    rollup = release?.tagCommit?.statusCheckRollup ?? null;
    contexts.push(...mapReleaseCheckContexts(rollup?.contexts.nodes ?? []));
    const pageInfo: PageInfo | undefined = rollup?.contexts.pageInfo;
    if (!pageInfo?.hasNextPage || !pageInfo.endCursor) break;
    after = pageInfo.endCursor;
  }

  const counts = countReleaseCheckContexts(contexts);
  return {
    tag,
    oid: release?.tagCommit?.oid ?? null,
    committedAt: release?.tagCommit?.committedDate ?? null,
    checkState: rollup?.state ?? null,
    checkTotal: rollup?.contexts.totalCount ?? contexts.length,
    checkSuccess: counts.success,
    checkFailure: counts.failure,
    checkPending: counts.pending,
    checkSkipped: counts.skipped,
    checkContexts: contexts,
  };
}

interface ReleaseCommitQueryData {
  repository: {
    release: {
      tagCommit: {
        oid: string;
        committedDate?: string;
        statusCheckRollup?: {
          state: string | null;
          contexts: {
            totalCount: number;
            nodes: Array<{
              __typename: string;
              name?: string | null;
              context?: string | null;
              status?: string | null;
              conclusion?: string | null;
              state?: string | null;
              detailsUrl?: string | null;
              targetUrl?: string | null;
              checkSuite?: {
                app?: { slug: string } | null;
                workflowRun?: { workflow?: { name: string } | null } | null;
              } | null;
            } | null> | null;
            pageInfo: PageInfo;
          };
        } | null;
      } | null;
    } | null;
  } | null;
}

type ReleaseCommitRepository = NonNullable<ReleaseCommitQueryData['repository']>;
type ReleaseCommitRelease = ReleaseCommitRepository['release'];
type ReleaseCommitRollup = NonNullable<NonNullable<NonNullable<ReleaseCommitRelease>['tagCommit']>['statusCheckRollup']>;

function buildReleaseCommitQuery(): string {
  return `query ReleaseCommit($owner: String!, $repo: String!, $tag: String!, $after: String) {
    repository(owner: $owner, name: $repo) {
      release(tagName: $tag) {
        tagCommit {
          oid
          ... on Commit {
            committedDate
            statusCheckRollup {
              state
              contexts(first: 100, after: $after) {
                totalCount
                nodes {
                  __typename
                  ... on CheckRun {
                    name
                    status
                    conclusion
                    detailsUrl
                    checkSuite {
                      app { slug }
                      workflowRun { workflow { name } }
                    }
                  }
                  ... on StatusContext {
                    context
                    state
                    targetUrl
                  }
                }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }
      }
    }
  }`;
}

function mapReleaseCheckContexts(nodes: Array<any | null>): GhReleaseCheckContext[] {
  return nodes
    .filter((node): node is NonNullable<typeof node> => !!node)
    .map((node) => {
      if (node.__typename === 'StatusContext') {
        return {
          type: 'StatusContext',
          name: node.context ?? 'status',
          workflowName: null,
          appSlug: null,
          status: null,
          conclusion: node.state ?? null,
          url: node.targetUrl ?? null,
        };
      }
      return {
        type: node.__typename ?? 'CheckRun',
        name: node.name ?? 'check',
        workflowName: node.checkSuite?.workflowRun?.workflow?.name ?? null,
        appSlug: node.checkSuite?.app?.slug ?? null,
        status: node.status ?? null,
        conclusion: node.conclusion ?? null,
        url: node.detailsUrl ?? null,
      };
    });
}

function countReleaseCheckContexts(contexts: GhReleaseCheckContext[]): {
  success: number;
  failure: number;
  pending: number;
  skipped: number;
} {
  let success = 0;
  let failure = 0;
  let pending = 0;
  let skipped = 0;
  for (const context of contexts) {
    const conclusion = (context.conclusion ?? '').toUpperCase();
    const status = (context.status ?? '').toUpperCase();
    if (['SUCCESS'].includes(conclusion)) success++;
    else if (['SKIPPED', 'NEUTRAL'].includes(conclusion)) skipped++;
    else if (['FAILURE', 'ERROR', 'TIMED_OUT', 'CANCELLED', 'ACTION_REQUIRED'].includes(conclusion)) failure++;
    else if (status && status !== 'COMPLETED') pending++;
  }
  return { success, failure, pending, skipped };
}

export async function listIssueFixEvidenceBatch(issueNumbers: number[]): Promise<Map<number, GhIssueFixEvidence>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n));
  const all = new Map<number, GhIssueFixEvidence>();
  for (const issueNumber of uniqueIssueNumbers) {
    all.set(issueNumber, { issueNumber, closureEvents: [], reopenEvents: [], prLinks: [], pullRequests: [] });
  }

  const batchSize = 10;
  for (let offset = 0; offset < uniqueIssueNumbers.length; offset += batchSize) {
    const chunk = uniqueIssueNumbers.slice(offset, offset + batchSize);
    const data = await gh<{ repository: Record<string, any> | null }>(
      buildIssueFixEvidenceBatchQuery(chunk.length),
      repoVars(Object.fromEntries(chunk.map((issueNumber, idx) => [`number${idx}`, issueNumber]))),
    );
    const repo = assertRepo(data.repository);
    for (let idx = 0; idx < chunk.length; idx++) {
      const issueNumber = chunk[idx];
      const issue = repo[`issue${idx}`];
      const evidence = all.get(issueNumber);
      if (!issue || !evidence) continue;

      appendClosedByPullRequestReferences(evidence, issueNumber, issue.closedByPullRequestsReferences?.nodes ?? []);
      appendFixTimelineNodes(evidence, issueNumber, issue.timelineItems?.nodes ?? []);
      await appendRemainingClosedByPullRequestReferences(
        evidence,
        issueNumber,
        issue.closedByPullRequestsReferences?.pageInfo ?? null,
      );
      await appendRemainingFixTimelineNodes(evidence, issueNumber, issue.timelineItems?.pageInfo ?? null);
    }
  }
  return all;
}

function appendClosedByPullRequestReferences(
  evidence: GhIssueFixEvidence,
  issueNumber: number,
  nodes: Array<any | null>,
): void {
  for (const pr of nodes) {
    if (!pr?.number) continue;
    evidence.prLinks.push({
      issueNumber,
      prNumber: pr.number,
      source: 'closedByPullRequestsReferences',
      willCloseTarget: true,
      referencedAt: pr.mergedAt ?? null,
    });
    evidence.pullRequests.push(mapPullRequestFix(pr));
  }
}

function appendFixTimelineNodes(
  evidence: GhIssueFixEvidence,
  issueNumber: number,
  nodes: Array<any | null>,
): void {
  for (const node of nodes) {
    if (!node?.__typename) continue;
    if (node.__typename === 'ClosedEvent') {
      const closer = node.closer ?? null;
      evidence.closureEvents.push({
        issueNumber,
        eventId: node.id,
        closedAt: node.createdAt ?? null,
        actorLogin: node.actor?.login ?? null,
        stateReason: node.stateReason ?? null,
        closerType: closer?.__typename ?? null,
        closerNumber: typeof closer?.number === 'number' ? closer.number : null,
        closerOid: typeof closer?.oid === 'string' ? closer.oid : closer?.mergeCommit?.oid ?? null,
        raw: node,
      });
      if (closer?.__typename === 'PullRequest' && typeof closer.number === 'number') {
        evidence.prLinks.push({
          issueNumber,
          prNumber: closer.number,
          source: 'ClosedEvent.closer',
          willCloseTarget: true,
          referencedAt: node.createdAt ?? null,
        });
        evidence.pullRequests.push(mapPullRequestFix(closer));
      }
    } else if (node.__typename === 'ReopenedEvent') {
      evidence.reopenEvents.push({
        issueNumber,
        eventId: node.id,
        reopenedAt: node.createdAt ?? null,
        actorLogin: node.actor?.login ?? null,
        raw: node,
      });
    } else if (node.__typename === 'CrossReferencedEvent') {
      const source = node.source;
      if (source?.__typename === 'PullRequest' && typeof source.number === 'number') {
        evidence.prLinks.push({
          issueNumber,
          prNumber: source.number,
          source: 'CrossReferencedEvent',
          willCloseTarget: typeof node.willCloseTarget === 'boolean' ? node.willCloseTarget : null,
          referencedAt: node.createdAt ?? null,
        });
        evidence.pullRequests.push(mapPullRequestFix(source));
      }
    }
  }
}

async function appendRemainingClosedByPullRequestReferences(
  evidence: GhIssueFixEvidence,
  issueNumber: number,
  pageInfo: PageInfo | null,
): Promise<void> {
  let after = pageInfo?.hasNextPage ? pageInfo.endCursor : null;
  while (after) {
    const data = await gh<{ repository: { issue: { closedByPullRequestsReferences: { nodes: Array<any | null>; pageInfo: PageInfo } } | null } | null }>(
      buildIssueClosedByPrRefsQuery(),
      repoVars({ number: issueNumber, after }),
    );
    const connection = assertRepo(data.repository).issue?.closedByPullRequestsReferences;
    appendClosedByPullRequestReferences(evidence, issueNumber, connection?.nodes ?? []);
    after = connection?.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
  }
}

async function appendRemainingFixTimelineNodes(
  evidence: GhIssueFixEvidence,
  issueNumber: number,
  pageInfo: PageInfo | null,
): Promise<void> {
  let after = pageInfo?.hasNextPage ? pageInfo.endCursor : null;
  while (after) {
    const data = await gh<{ repository: { issue: { timelineItems: { nodes: Array<any | null>; pageInfo: PageInfo } } | null } | null }>(
      buildIssueFixTimelineQuery(),
      repoVars({ number: issueNumber, after }),
    );
    const connection = assertRepo(data.repository).issue?.timelineItems;
    appendFixTimelineNodes(evidence, issueNumber, connection?.nodes ?? []);
    after = connection?.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
  }
}

export async function listPullRequestFixesBatch(prNumbers: number[]): Promise<Map<number, GhPullRequestFix>> {
  const uniquePrNumbers = [...new Set(prNumbers)].filter((n) => Number.isInteger(n) && n > 0);
  const all = new Map<number, GhPullRequestFix>();

  const batchSize = 25;
  for (let offset = 0; offset < uniquePrNumbers.length; offset += batchSize) {
    const chunk = uniquePrNumbers.slice(offset, offset + batchSize);
    let data: { repository: Record<string, any> | null };
    try {
      data = await gh<{ repository: Record<string, any> | null }>(
        buildPullRequestFixesBatchQuery(chunk.length),
        repoVars(Object.fromEntries(chunk.map((prNumber, idx) => [`number${idx}`, prNumber]))),
      );
    } catch (e) {
      if (chunk.length > 1 && isMissingPullRequestError(e)) {
        const fallback = await listPullRequestFixesBatch(chunk.slice(0, Math.ceil(chunk.length / 2)));
        for (const [number, pr] of fallback) all.set(number, pr);
        const rest = await listPullRequestFixesBatch(chunk.slice(Math.ceil(chunk.length / 2)));
        for (const [number, pr] of rest) all.set(number, pr);
        continue;
      }
      if (chunk.length === 1 && isMissingPullRequestError(e)) continue;
      throw e;
    }
    const repo = assertRepo(data.repository);
    for (let idx = 0; idx < chunk.length; idx++) {
      const pr = repo[`pr${idx}`];
      if (!pr?.number) continue;
      all.set(pr.number, mapPullRequestFix(pr));
    }
  }

  return all;
}

function isMissingPullRequestError(e: unknown): boolean {
  const message = e instanceof Error ? e.message : String(e);
  return /Could not resolve to a PullRequest with the number/i.test(message);
}

export function closureCommentPrMentions(
  issueNumber: number,
  comments: Array<{
    body?: string | null;
    created_at?: string | null;
    createdAt?: string | null;
    user?: { login?: string | null } | null;
    author?: string | null;
    author_association?: string | null;
    authorAssociation?: string | null;
  }>,
): ClosureCommentPrMention[] {
  const byPr = new Map<number, ClosureCommentPrMention>();
  for (const comment of comments) {
    const body = comment.body ?? '';
    const trust = closureProofCommentTrust(comment);
    if (!trust.trustedSource) continue;
    for (const prNumber of extractClosureCommentPrNumbers(body)) {
      if (prNumber === issueNumber) continue;
      const existing = byPr.get(prNumber);
      const referencedAt = comment.created_at ?? comment.createdAt ?? null;
      if (!existing || (referencedAt && (!existing.referencedAt || referencedAt < existing.referencedAt))) {
        byPr.set(prNumber, { issueNumber, prNumber, referencedAt, ...trust });
      }
    }
  }
  return [...byPr.values()].sort((a, b) => a.prNumber - b.prNumber);
}

export function closureCommentCommitMentions(
  issueNumber: number,
  comments: Array<{
    body?: string | null;
    created_at?: string | null;
    createdAt?: string | null;
    user?: { login?: string | null } | null;
    author?: string | null;
    author_association?: string | null;
    authorAssociation?: string | null;
  }>,
  sourceIssueNumber = issueNumber,
): ClosureCommentCommitMention[] {
  const byCommit = new Map<string, ClosureCommentCommitMention>();
  for (const comment of comments) {
    const body = comment.body ?? '';
    const text = body.replace(/\s+/g, ' ');
    const trust = closureProofCommentTrust(comment);
    if (!trust.trustedSource) continue;
    if (!isClosureCommitFixProofComment(text)) continue;
    const referencedAt = comment.created_at ?? comment.createdAt ?? null;
    for (const commitOid of extractCommitOids(text)) {
      const existing = byCommit.get(commitOid);
      if (!existing || (referencedAt && (!existing.referencedAt || referencedAt < existing.referencedAt))) {
        byCommit.set(commitOid, {
          issueNumber,
          commitOid,
          referencedAt,
          sourceIssueNumber,
          snippet: text.slice(0, 500),
          source: 'ClosureComment.fixProof',
          ...trust,
        });
      }
    }
  }
  return [...byCommit.values()].sort((a, b) => a.commitOid.localeCompare(b.commitOid));
}

const TRUSTED_CLOSURE_PROOF_AUTHORS = new Set(['clawsweeper']);
const TRUSTED_CLOSURE_PROOF_ASSOCIATIONS = new Set(['OWNER', 'MEMBER', 'COLLABORATOR']);

function closureProofCommentTrust(comment: {
  user?: { login?: string | null } | null;
  author?: string | null;
  author_association?: string | null;
  authorAssociation?: string | null;
}): { author: string | null; authorAssociation: string | null; trustedSource: boolean } {
  const author = comment.user?.login ?? comment.author ?? null;
  const authorAssociation = comment.author_association ?? comment.authorAssociation ?? null;
  const trustedSource = TRUSTED_CLOSURE_PROOF_ASSOCIATIONS.has(authorAssociation ?? '') ||
    TRUSTED_CLOSURE_PROOF_AUTHORS.has(String(author ?? '').toLowerCase());
  return { author, authorAssociation, trustedSource };
}

function extractClosureCommentPrNumbers(body: string): number[] {
  const numbers = new Set<number>();
  const text = body.replace(/\s+/g, ' ');
  if (!isClosureFixProofComment(text)) return [];

  for (const match of text.matchAll(/https?:\/\/(?:api\.)?github\.com\/repos\/openclaw\/openclaw\/pulls?\/(\d+)|https?:\/\/github\.com\/openclaw\/openclaw\/pull\/(\d+)/gi)) {
    addPrNumber(numbers, match[1] ?? match[2]);
  }

  const qualifiedMentionRe = /\b(?:merged\s+PR|merged\s+pull request|PR|pull request)\s*(?:that appears to have closed this:?\s*)?(?:\[)?#(\d+)\b/gi;
  for (const match of text.matchAll(qualifiedMentionRe)) {
    addPrNumber(numbers, match[1]);
  }

  const fixedByIssueOrPrRefRe = /\b(?:fix(?:e[sd])?|implemented|addressed)\s+(?:on\s+`?main`?\s+)?by\s+#(\d+)\b/gi;
  for (const match of text.matchAll(fixedByIssueOrPrRefRe)) {
    addPrNumber(numbers, match[1]);
  }

  return [...numbers].sort((a, b) => a - b);
}

function isClosureFixProofComment(text: string): boolean {
  return (
    /\b(?:fix(?:e[sd])?|implemented|addressed)\s+(?:on\s+`?main`?\s+)?by\s+#\d+\b/i.test(text) ||
    /\bfound\s+the\s+merged\s+(?:pr|pull request)\b.{0,160}\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\b/i.test(text) ||
    /\bmerged\s+(?:pr|pull request)\b.{0,160}\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\b/i.test(text) ||
    /\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\b.{0,160}\bmerged\s+(?:pr|pull request)\b/i.test(text) ||
    /\b(?:pr|pull request)\s*#?\d+\b.{0,120}\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\s+(?:this|the report|the issue)\b/i.test(text)
  );
}

function isClosureCommitFixProofComment(text: string): boolean {
  return (
    /\bfix(?:ed)?\s+(?:on\s+`?main`?\s+)?in\s+`?[0-9a-f]{40}`?/i.test(text) ||
    /\bfixed\s+by\s+commit\s+`?[0-9a-f]{40}`?/i.test(text) ||
    /\bfix\s+provenance\b.{0,220}\bcommit\b/i.test(text) ||
    /\bcanonical\s+fix\b.{0,220}\bcommit\b/i.test(text) ||
    /\bfix\s+evidence\b.{0,220}\bcommit\b/i.test(text) ||
    /\brelease\s+provenance\b.{0,260}\b(v20\d{2}\.\d+\.\d+|release|tag)\b/i.test(text)
  );
}

function extractCommitOids(text: string): string[] {
  const commits = new Set<string>();
  for (const match of text.matchAll(/\b[0-9a-f]{40}\b/gi)) {
    commits.add(match[0].toLowerCase());
  }
  for (const match of text.matchAll(/github\.com\/openclaw\/openclaw\/commit\/([0-9a-f]{40})\b/gi)) {
    commits.add(match[1].toLowerCase());
  }
  return [...commits].sort();
}

function addPrNumber(numbers: Set<number>, raw: string | undefined): void {
  const n = Number(raw);
  if (Number.isInteger(n) && n > 0) numbers.add(n);
}

function mapPullRequestFix(pr: any): GhPullRequestFix {
  return {
    number: pr.number,
    title: pr.title ?? null,
    url: pr.url ?? null,
    state: pr.state ?? null,
    merged: pr.merged === true,
    mergedAt: pr.mergedAt ?? null,
    mergeCommitOid: pr.mergeCommit?.oid ?? null,
    baseRefName: pr.baseRefName ?? null,
  };
}

function buildIssueFixEvidenceBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      closedByPullRequestsReferences(first: 100, includeClosedPrs: true) {
        nodes {
          number title url state merged mergedAt baseRefName
          mergeCommit { oid }
        }
        pageInfo { hasNextPage endCursor }
      }
      timelineItems(first: 100, itemTypes: [CLOSED_EVENT, REOPENED_EVENT, CROSS_REFERENCED_EVENT]) {
        nodes {
          __typename
          ... on ClosedEvent {
            id createdAt stateReason actor { login }
            closer {
              __typename
              ... on PullRequest {
                number title url state merged mergedAt baseRefName
                mergeCommit { oid }
              }
              ... on Commit { oid committedDate url }
            }
          }
          ... on ReopenedEvent {
            id createdAt actor { login }
          }
          ... on CrossReferencedEvent {
            id createdAt willCloseTarget
            source {
              __typename
              ... on PullRequest {
                number title url state merged mergedAt baseRefName
                mergeCommit { oid }
              }
            }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }`).join('\n');
  return `query IssueFixEvidence($owner: String!, $repo: String!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      ${fields}
    }
  }`;
}

function buildIssueClosedByPrRefsQuery(): string {
  return `query IssueClosedByPrRefs($owner: String!, $repo: String!, $number: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      issue(number: $number) {
        closedByPullRequestsReferences(first: 100, after: $after, includeClosedPrs: true) {
          nodes {
            number title url state merged mergedAt baseRefName
            mergeCommit { oid }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }`;
}

function buildIssueFixTimelineQuery(): string {
  return `query IssueFixTimeline($owner: String!, $repo: String!, $number: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      issue(number: $number) {
        timelineItems(first: 100, after: $after, itemTypes: [CLOSED_EVENT, REOPENED_EVENT, CROSS_REFERENCED_EVENT]) {
          nodes {
            __typename
            ... on ClosedEvent {
              id createdAt stateReason actor { login }
              closer {
                __typename
                ... on PullRequest {
                  number title url state merged mergedAt baseRefName
                  mergeCommit { oid }
                }
                ... on Commit { oid committedDate url }
              }
            }
            ... on ReopenedEvent {
              id createdAt actor { login }
            }
            ... on CrossReferencedEvent {
              id createdAt willCloseTarget
              source {
                __typename
                ... on PullRequest {
                  number title url state merged mergedAt baseRefName
                  mergeCommit { oid }
                }
              }
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }`;
}

function buildPullRequestFixesBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    pr${idx}: pullRequest(number: $number${idx}) {
      number title url state merged mergedAt baseRefName
      mergeCommit { oid }
    }`).join('\n');
  return `query PullRequestFixes($owner: String!, $repo: String!, ${vars}) {
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
  buildReleaseCommitQuery,
  buildIssuesBatchQuery,
  buildIssueLabelsQuery,
  buildIssueFixEvidenceBatchQuery,
  buildIssueClosedByPrRefsQuery,
  buildIssueFixTimelineQuery,
  buildPullRequestFixesBatchQuery,
  closureCommentCommitMentions,
  closureCommentPrMentions,
  buildIssueCommentsBatchQuery,
  missingIssueIndexesFromGraphqlError,
  buildIssueLabelEventsBatchQuery,
  mapComment,
  mapIssue,
  mapRelease,
  mapSecurityVulnerabilities,
};
