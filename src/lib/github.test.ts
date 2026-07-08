import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  __githubTest,
  fetchSecurityAdvisorySourceObservations,
  fetchRepositoryCollaboratorPermissionSnapshot,
  getReleaseCommit,
  listIssueFixEvidenceBatch,
  listIssueLabelEvidenceSnapshotsBatch,
  listIssueLabelEventsBatch,
  listIssuesBatch,
  listSecurityAdvisories,
  pullRequestKey,
  type GhRelease,
  type GhReleaseCatalog,
  type GithubReleaseCatalogActiveRelease,
} from './github.ts';
import { ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION } from './stateEventSnapshot.ts';

const TEST_REPOSITORY_NODE_ID = 'REPO-node-openclaw';
const RELEASE_CATALOG_OPERATION_BINDING = {
  operationRunId: 'refresh-run-release-catalog-test',
  operation: 'refresh',
  operationAttemptContentHash: 'a'.repeat(64),
};

function graphqlSelectionBodies(query: string, fieldName: string): string[] {
  const bodies: string[] = [];
  const fieldPattern = new RegExp(`\\b${fieldName}\\s*\\{`, 'g');

  for (const match of query.matchAll(fieldPattern)) {
    const braceStart = query.indexOf('{', match.index);
    let depth = 0;
    let braceEnd = -1;
    for (let idx = braceStart; idx < query.length; idx++) {
      if (query[idx] === '{') depth++;
      if (query[idx] === '}') {
        depth--;
        if (depth === 0) {
          braceEnd = idx;
          break;
        }
      }
    }
    assert.notEqual(braceEnd, -1, `unterminated ${fieldName} selection`);
    bodies.push(query.slice(braceStart + 1, braceEnd));
  }

  return bodies;
}

function graphqlTopLevelNames(selectionBody: string): string[] {
  const names: string[] = [];
  let depth = 0;
  for (let idx = 0; idx < selectionBody.length;) {
    const char = selectionBody[idx];
    if (char === '{') {
      depth++;
      idx++;
      continue;
    }
    if (char === '}') {
      depth--;
      idx++;
      continue;
    }
    if (depth === 0 && /[A-Za-z_]/.test(char)) {
      let end = idx + 1;
      while (end < selectionBody.length && /[A-Za-z0-9_]/.test(selectionBody[end])) end++;
      names.push(selectionBody.slice(idx, end));
      idx = end;
      continue;
    }
    idx++;
  }
  return names;
}

function assertNodeBackedActorSelections(
  query: string,
  fieldName: 'author' | 'actor' | 'closer',
  expectedNodeBackedCount: number,
): void {
  const bodies = graphqlSelectionBodies(query, fieldName);
  for (const body of bodies) {
    assert.equal(
      graphqlTopLevelNames(body).includes('id'),
      false,
      `${fieldName} must select id only through the Node fragment`,
    );
  }
  const nodeBackedBodies = bodies.filter((body) => (
    /\.\.\.\s+on\s+Node\s*\{\s*id\s*\}/.test(body)
  ));
  assert.equal(
    nodeBackedBodies.length,
    expectedNodeBackedCount,
    `${fieldName} Node-backed selection count`,
  );
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error('Timed out waiting for test condition');
}

function immediateScheduler(rateLimitDelays: number[] = []) {
  return {
    run<T>(task: () => Promise<T>): Promise<T> {
      return task();
    },
    noteRateLimit(delay = 0): number {
      rateLimitDelays.push(delay);
      return delay;
    },
  };
}

function serialScheduler(
  events: string[],
  rateLimitDelays: number[] = [],
) {
  let tail = Promise.resolve();
  return {
    run<T>(task: () => Promise<T>): Promise<T> {
      const result = tail.then(task, task);
      tail = result.then(() => undefined, () => undefined);
      return result;
    },
    noteRateLimit(delay = 0): number {
      events.push('cooldown');
      rateLimitDelays.push(delay);
      return delay;
    },
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function aliasedIssueNumbers(variables: Record<string, unknown>): number[] {
  return Object.entries(variables)
    .filter(([key, value]) => /^number\d+$/.test(key) && typeof value === 'number')
    .sort(([left], [right]) => Number(left.slice(6)) - Number(right.slice(6)))
    .map(([, value]) => value as number);
}

function gatedChunkRequest(
  respond: (
    query: string,
    variables: Record<string, unknown>,
    issueNumbers: number[],
  ) => unknown,
) {
  const gate = deferred();
  const gatedChunks = new Set<number>();
  const startedChunks: number[] = [];
  let activeChunks = 0;
  let maxActiveChunks = 0;

  return {
    request: async <T>(
      query: string,
      variables: Record<string, unknown> = {},
    ): Promise<T> => {
      const issueNumbers = aliasedIssueNumbers(variables);
      const chunkStart = issueNumbers[0];
      if (chunkStart != null && !gatedChunks.has(chunkStart)) {
        gatedChunks.add(chunkStart);
        startedChunks.push(chunkStart);
        activeChunks++;
        maxActiveChunks = Math.max(maxActiveChunks, activeChunks);
        await gate.promise;
        activeChunks--;
      }
      return respond(query, variables, issueNumbers) as T;
    },
    release: gate.resolve,
    startedChunks,
    activeChunks: () => activeChunks,
    maxActiveChunks: () => maxActiveChunks,
  };
}

function commentNode(id: number | null, body = `comment ${String(id)}`) {
  return {
    id: `COMMENT-node-${String(id)}`,
    __typename: 'IssueComment' as const,
    databaseId: id,
    url: `https://github.com/openclaw/openclaw/issues/7#issuecomment-${String(id)}`,
    author: {
      id: 'ACTOR-maintainer',
      __typename: 'User' as const,
      login: 'maintainer',
    },
    authorAssociation: 'MEMBER',
    body,
    createdAt: '2026-07-03T00:00:00Z',
    updatedAt: '2026-07-03T00:00:00Z',
  };
}

function issueLookupNode(number: number) {
  return {
    id: `ISSUE-node-${number}`,
    __typename: 'Issue' as const,
    number,
    title: `Issue ${number}`,
    body: `Body ${number}`,
    state: 'OPEN' as const,
    author: {
      id: `ACTOR-reporter-${number}`,
      __typename: 'User' as const,
      login: `reporter-${number}`,
    },
    authorAssociation: 'CONTRIBUTOR',
    createdAt: '2026-07-03T00:00:00Z',
    updatedAt: '2026-07-03T01:00:00Z',
    closedAt: null,
    url: `https://github.com/openclaw/openclaw/issues/${number}`,
    comments: { totalCount: 0 },
    reactionGroups: [],
    labels: {
      totalCount: 1,
      nodes: [{ name: `label-${number}` }],
      pageInfo: { hasNextPage: false, endCursor: null },
    },
  };
}

function repositorySecurityAdvisoryNode(
  overrides: {
    ghsaId?: string;
    cveId?: string | null;
    severity?: string;
    state?: string;
    summary?: string;
    updatedAt?: string;
    publishedAt?: string | null;
    withdrawnAt?: string | null;
    htmlUrl?: string;
    identifiers?: Array<{ type: string; value: string } | null> | null;
    vulnerabilities?: Array<{
      package: { ecosystem: string | null; name: string | null } | null;
      vulnerable_version_range: string | null;
      patched_versions: string | null;
    } | null> | null;
  } = {},
) {
  const ghsaId = overrides.ghsaId ?? 'GHSA-wgq8-x5wm-g4rw';
  const cveId = overrides.cveId === undefined ? null : overrides.cveId;
  return {
    ghsa_id: ghsaId,
    cve_id: cveId,
    summary: overrides.summary ?? `Summary for ${ghsaId}`,
    severity: overrides.severity ?? 'medium',
    state: overrides.state ?? 'published',
    updated_at: overrides.updatedAt ?? '2026-07-01T00:00:00Z',
    published_at: overrides.publishedAt === undefined
      ? '2026-06-30T00:00:00Z'
      : overrides.publishedAt,
    withdrawn_at: overrides.withdrawnAt ?? null,
    html_url: overrides.htmlUrl ??
      `https://github.com/openclaw/openclaw/security/advisories/${ghsaId}`,
    identifiers: overrides.identifiers === undefined
      ? [
        { type: 'GHSA', value: ghsaId },
        ...(cveId == null ? [] : [{ type: 'CVE', value: cveId }]),
      ]
      : overrides.identifiers,
    vulnerabilities: overrides.vulnerabilities ?? [{
      package: { ecosystem: 'npm', name: 'openclaw' },
      vulnerable_version_range: '>= 2026.6.5, < 2026.6.9',
      patched_versions: '2026.6.9',
    }],
  };
}

function securityVulnerabilityNode(
  overrides: {
    ghsaId?: string;
    cveId?: string | null;
    summary?: string;
    severity?: string;
    permalink?: string | null;
    publishedAt?: string;
    withdrawnAt?: string | null;
    identifiers?: Array<{ type: string; value: string } | null> | null;
    ecosystem?: string | null;
    packageName?: string | null;
    vulnerableVersionRange?: string | null;
    firstPatchedVersion?: string | null;
    updatedAt?: string;
  } = {},
) {
  const ghsaId = overrides.ghsaId ?? 'GHSA-wgq8-x5wm-g4rw';
  const cveId = overrides.cveId === undefined ? 'CVE-2026-27208' : overrides.cveId;
  return {
    advisory: {
      ghsaId,
      identifiers: overrides.identifiers === undefined
        ? [
          { type: 'GHSA', value: ghsaId },
          ...(cveId == null ? [] : [{ type: 'CVE', value: cveId }]),
        ]
        : overrides.identifiers,
      permalink: overrides.permalink === undefined
        ? `https://github.com/advisories/${ghsaId}`
        : overrides.permalink,
      publishedAt: overrides.publishedAt ?? '2026-06-30T00:00:00Z',
      severity: overrides.severity ?? 'HIGH',
      summary: overrides.summary ?? `Summary for ${ghsaId}`,
      withdrawnAt: overrides.withdrawnAt ?? null,
    },
    package: {
      ecosystem: overrides.ecosystem === undefined ? 'NPM' : overrides.ecosystem,
      name: overrides.packageName === undefined ? 'openclaw' : overrides.packageName,
    },
    vulnerableVersionRange: overrides.vulnerableVersionRange === undefined
      ? '>= 2026.6.5, < 2026.6.9'
      : overrides.vulnerableVersionRange,
    firstPatchedVersion: overrides.firstPatchedVersion === undefined
      ? { identifier: '2026.6.9' }
      : overrides.firstPatchedVersion == null
        ? null
        : { identifier: overrides.firstPatchedVersion },
    updatedAt: overrides.updatedAt ?? '2026-07-01T00:00:00Z',
  };
}

function securityVulnerabilitiesPage(
  totalCount: number,
  nodes: Array<ReturnType<typeof securityVulnerabilityNode> | null>,
  nextCursor: string | null = null,
) {
  return {
    securityVulnerabilities: {
      totalCount,
      nodes,
      pageInfo: {
        hasNextPage: nextCursor != null,
        endCursor: nextCursor,
      },
    },
  };
}

function stableSecurityVulnerabilityRequest(
  nodes: Array<ReturnType<typeof securityVulnerabilityNode> | null>,
) {
  return async <T>(
    _query: string,
    variables: Record<string, unknown> = {},
  ): Promise<T> => {
    assert.equal(variables.package, 'openclaw');
    assert.equal(variables.first, 100);
    assert.equal(variables.after, null);
    return securityVulnerabilitiesPage(nodes.length, nodes) as T;
  };
}

function cursorTerminalAdvisoryPage(
  nodes: Array<ReturnType<typeof repositorySecurityAdvisoryNode> | null>,
) {
  return {
    nodes,
    nextCursor: null,
    completeness: {
      terminal: true,
      proven: true,
      evidence: 'link' as const,
      linkHeaderPresent: true,
    },
  };
}

function cursorNonTerminalAdvisoryPage(
  nodes: Array<ReturnType<typeof repositorySecurityAdvisoryNode> | null>,
  nextCursor: string,
) {
  return {
    nodes,
    nextCursor,
    completeness: {
      terminal: false,
      proven: true,
      evidence: 'link' as const,
      linkHeaderPresent: true,
    },
  };
}

function unprovenAdvisoryPage(
  nodes: Array<ReturnType<typeof repositorySecurityAdvisoryNode> | null>,
) {
  return {
    nodes,
    nextCursor: null,
    completeness: {
      terminal: false,
      proven: false,
      evidence: 'missing-link' as const,
      linkHeaderPresent: false,
    },
  };
}

function repositorySecurityAdvisoryPaginationLink(
  direction: 'asc' | 'desc',
  relation: 'next' | 'prev',
  cursor: string,
): string {
  const url = new URL(
    'https://api.github.com/repositories/1103012935/security-advisories',
  );
  url.searchParams.set('state', 'published');
  url.searchParams.set('sort', 'updated');
  url.searchParams.set('direction', direction);
  url.searchParams.set('per_page', '100');
  url.searchParams.set(relation === 'next' ? 'after' : 'before', cursor);
  return `<${url.toString()}>; rel="${relation}"`;
}

function repositorySecurityAdvisoryHttpRequester(
  respond: (url: URL) => Response | Promise<Response>,
) {
  return __githubTest.createRepositorySecurityAdvisoryPageRequester({
    fetchImpl: (async (input: string | URL | Request) =>
      respond(new URL(String(input)))) as typeof fetch,
    scheduler: immediateScheduler(),
    requestHeaders: () => ({}),
    maxRetries: 0,
  });
}

function commentIssue(
  updatedAt: string,
  totalCount: number,
  nodes: ReturnType<typeof commentNode>[],
  nextCursor: string | null = null,
  issueNumber = 7,
) {
  return {
    id: `ISSUE-node-${issueNumber}`,
    __typename: 'Issue' as const,
    number: issueNumber,
    author: {
      id: `ACTOR-reporter-${issueNumber}`,
      __typename: 'User' as const,
      login: `reporter-${issueNumber}`,
    },
    updatedAt,
    comments: {
      totalCount,
      nodes,
      pageInfo: {
        hasNextPage: nextCursor != null,
        endCursor: nextCursor,
      },
    },
  };
}

function releaseNode(input: {
  id: string;
  tagName: string;
  tagOid?: string;
  name?: string | null;
  publishedAt?: string | null;
  createdAt?: string;
  updatedAt?: string;
  isPrerelease?: boolean;
  isDraft?: boolean;
}) {
  return {
    id: input.id,
    tagName: input.tagName,
    tagCommit: { oid: input.tagOid ?? 'a'.repeat(40) },
    name: input.name === undefined ? input.tagName : input.name,
    publishedAt: input.publishedAt ?? '2026-07-01T00:00:00Z',
    createdAt: input.createdAt ?? '2026-07-01T00:00:00Z',
    updatedAt: input.updatedAt ?? '2026-07-01T00:00:00Z',
    url: `https://github.com/openclaw/openclaw/releases/tag/${input.tagName}`,
    isPrerelease: input.isPrerelease ?? false,
    isDraft: input.isDraft ?? false,
    description: `Notes for ${input.tagName}`,
  };
}

function releaseCheckContext(
  name: string,
  conclusion: string | null = 'SUCCESS',
  id = `CHECK_${name}`,
  status = 'COMPLETED',
) {
  return {
    __typename: 'CheckRun',
    id,
    name,
    status,
    conclusion,
    detailsUrl: `https://github.com/openclaw/openclaw/actions/runs/${name}`,
    checkSuite: {
      app: { slug: 'github-actions' },
      workflowRun: { workflow: { name: 'CI' } },
    },
  };
}

function releaseStatusContext(
  name: string,
  state: string | null,
  id = `STATUS_${name}`,
) {
  return {
    __typename: 'StatusContext',
    id,
    context: name,
    state,
    targetUrl: `https://github.com/openclaw/openclaw/status/${name}`,
  };
}

function releaseCommitPage(input: {
  tagOid?: string;
  rollupId?: string | null;
  rollupState?: string | null;
  totalCount?: number;
  nodes?: Array<
    ReturnType<typeof releaseCheckContext> |
    ReturnType<typeof releaseStatusContext>
  >;
  nextCursor?: string | null;
}) {
  const rollupId = input.rollupId === undefined ? 'ROLLUP_1' : input.rollupId;
  return {
    repository: {
      id: TEST_REPOSITORY_NODE_ID,
      release: {
        tagCommit: {
          oid: input.tagOid ?? 'a'.repeat(40),
          committedDate: '2026-07-01T00:00:00Z',
          statusCheckRollup: rollupId == null
            ? null
            : {
                id: rollupId,
                state: input.rollupState === undefined ? 'SUCCESS' : input.rollupState,
                contexts: {
                  totalCount: input.totalCount ?? input.nodes?.length ?? 0,
                  nodes: input.nodes ?? [],
                  pageInfo: {
                    hasNextPage: input.nextCursor != null,
                    endCursor: input.nextCursor ?? null,
                  },
                },
              },
        },
      },
    },
  };
}

function releasePage(
  totalCount: number,
  nodes: Array<ReturnType<typeof releaseNode> | null>,
  nextCursor: string | null = null,
) {
  return {
    repository: {
      id: TEST_REPOSITORY_NODE_ID,
      nameWithOwner: 'openclaw/openclaw',
      releases: {
        totalCount,
        nodes,
        pageInfo: {
          hasNextPage: nextCursor != null,
          endCursor: nextCursor,
        },
      },
    },
  };
}

function activeReleaseRow(
  release: GhRelease,
): GithubReleaseCatalogActiveRelease {
  assert.ok(release.published_at);
  return {
    node_id: release.node_id,
    catalog_tag_commit_oid: release.tag_commit_oid,
    tag: release.tag_name,
    name: release.name,
    published_at: release.published_at,
    created_at: release.created_at,
    updated_at: release.updated_at,
    html_url: release.html_url,
    prerelease: release.prerelease,
    body: release.body,
  };
}

function activeReleaseRows(
  catalog: GhReleaseCatalog,
): GithubReleaseCatalogActiveRelease[] {
  return catalog.releases
    .filter((release) => !release.draft)
    .map(activeReleaseRow)
    .sort(
      (left, right) =>
        Date.parse(right.published_at) - Date.parse(left.published_at),
    );
}

async function fetchBoundReleaseCatalog(
  nodes: Array<ReturnType<typeof releaseNode>>,
): Promise<GhReleaseCatalog> {
  return __githubTest.fetchReleaseCatalog({
    request: async <T>(): Promise<T> =>
      releasePage(nodes.length, nodes) as T,
    operationBinding: RELEASE_CATALOG_OPERATION_BINDING,
  });
}

function stateEventPage(
  state: 'OPEN' | 'CLOSED',
  updatedAt: string,
  totalCount: number,
  nodes: any[],
  nextCursor: string | null = null,
  issueNumber = 42,
  issueNodeId = `ISSUE-node-${issueNumber}`,
  issueNodeType = 'Issue',
) {
  return {
    id: issueNodeId,
    __typename: issueNodeType,
    number: issueNumber,
    state,
    updatedAt,
    stateEvents: {
      totalCount,
      nodes,
      pageInfo: {
        hasNextPage: nextCursor != null,
        endCursor: nextCursor,
      },
    },
  };
}

function fixEvidenceIssue(input: {
  issueNumber?: number;
  issueNodeId?: string;
  issueNodeType?: string;
  state?: 'OPEN' | 'CLOSED';
  updatedAt?: string;
  totalCount?: number;
  stateNodes?: any[];
  stateCursor?: string | null;
  closedByNodes?: any[];
  closedByTotalCount?: number;
  closedByCursor?: string | null;
  referenceNodes?: any[];
  referenceTotalCount?: number;
  referenceCursor?: string | null;
}) {
  const state = input.state ?? 'CLOSED';
  const updatedAt = input.updatedAt ?? '2026-07-03T03:00:00Z';
  const issueNumber = input.issueNumber ?? 42;
  return {
    ...stateEventPage(
      state,
      updatedAt,
      input.totalCount ?? input.stateNodes?.length ?? 0,
      input.stateNodes ?? [],
      input.stateCursor ?? null,
      issueNumber,
      input.issueNodeId ?? `ISSUE-node-${issueNumber}`,
      input.issueNodeType ?? 'Issue',
    ),
    closedByPullRequestsReferences: {
      totalCount: input.closedByTotalCount ?? input.closedByNodes?.length ?? 0,
      nodes: input.closedByNodes ?? [],
      pageInfo: {
        hasNextPage: input.closedByCursor != null,
        endCursor: input.closedByCursor ?? null,
      },
    },
    referenceEvents: {
      totalCount: input.referenceTotalCount ?? input.referenceNodes?.length ?? 0,
      nodes: input.referenceNodes ?? [],
      pageInfo: {
        hasNextPage: input.referenceCursor != null,
        endCursor: input.referenceCursor ?? null,
      },
    },
  };
}

function closedEvent(id: string, createdAt: string, closer: any = undefined) {
  const canonicalCloser = closer === undefined
    ? {
        __typename: 'Commit',
        id: `CLOSER-${id}`,
        oid: id.padEnd(40, '0').slice(0, 40),
      }
    : closer == null
      ? null
      : {
          ...closer,
          id: closer.id ?? `CLOSER-${id}`,
        };
  return {
    __typename: 'ClosedEvent',
    id,
    createdAt,
    stateReason: 'COMPLETED',
    actor: {
      id: 'ACTOR-maintainer',
      __typename: 'User',
      login: 'maintainer',
    },
    closer: canonicalCloser,
  };
}

function reopenedEvent(id: string, createdAt: string) {
  return {
    __typename: 'ReopenedEvent',
    id,
    createdAt,
    actor: {
      id: 'ACTOR-reporter',
      __typename: 'User',
      login: 'reporter',
    },
  };
}

let closureProofCommentSequence = 0;

function canonicalClosureProofComment<T extends {
  user?: { login?: string | null } | null;
  author?: string | null;
}>(comment: T, actorNodeId?: string) {
  const login = comment.user?.login ?? comment.author ?? 'unknown';
  closureProofCommentSequence++;
  return {
    ...comment,
    node_id: `COMMENT-proof-${closureProofCommentSequence}`,
    node_type: 'IssueComment',
    user: comment.user == null
      ? null
      : {
          ...comment.user,
          id: actorNodeId ?? `ACTOR-${login}`,
          type: 'User',
        },
  };
}

function canonicalClosureProofComments<T extends {
  user?: { login?: string | null } | null;
  author?: string | null;
}>(comments: T[]) {
  return comments.map((comment) => canonicalClosureProofComment(comment));
}

function finalClosureActorIdentity(login: string) {
  return {
    nodeId: `ACTOR-${login}`,
    nodeType: 'User',
  };
}

function referencedEvent(index: number) {
  const commitOid = index.toString(16).padStart(40, '0');
  return {
    __typename: 'ReferencedEvent',
    id: `reference-${index}`,
    createdAt: new Date(Date.UTC(2026, 6, 3, 0, 0, index)).toISOString(),
    isCrossRepository: false,
    isDirectReference: true,
    actor: { login: 'maintainer' },
    commit: {
      oid: commitOid,
      messageHeadline: `fix reference ${index}`,
    },
    commitRepository: {
      name: 'openclaw',
      nameWithOwner: 'openclaw/openclaw',
      owner: { login: 'openclaw' },
    },
  };
}

function labelEvent(
  id: string,
  overrides: {
    type?: 'LabeledEvent' | 'UnlabeledEvent';
    createdAt?: string;
    actorNodeId?: string;
    actorLogin?: string | null;
    actorType?: string;
    labelNodeId?: string;
    labelName?: string;
  } = {},
) {
  const labelName = overrides.labelName ?? 'bug';
  return {
    __typename: overrides.type ?? 'LabeledEvent',
    id,
    createdAt: overrides.createdAt ?? '2026-07-03T01:00:00Z',
    actor: overrides.actorLogin === null
      ? null
      : {
          id: overrides.actorNodeId ?? 'ACTOR_maintainer',
          __typename: overrides.actorType ?? 'User',
          login: overrides.actorLogin ?? 'maintainer',
        },
    label: {
      id: overrides.labelNodeId ?? `LABEL-node-${labelName.replaceAll(':', '-')}`,
      name: labelName,
    },
  };
}

function labelTimelineIssue(
  issueNumber: number,
  timelineItems: Record<string, unknown>,
  overrides: {
    issueNodeId?: string;
    issueNodeType?: string;
    issueUpdatedAt?: string;
  } = {},
) {
  return {
    id: overrides.issueNodeId ?? `ISSUE-node-${issueNumber}`,
    __typename: overrides.issueNodeType ?? 'Issue',
    number: issueNumber,
    updatedAt: overrides.issueUpdatedAt ?? '2026-07-03T03:00:00Z',
    timelineItems,
  };
}

function labelTimelineRepository(
  issues: Record<string, unknown>,
  repositoryNodeId = 'REPO-node-openclaw',
) {
  return {
    id: repositoryNodeId,
    ...issues,
  };
}

describe('GitHub GraphQL mapping', () => {
  it('maps releases into the existing REST-shaped contract', () => {
    const release = __githubTest.mapRelease({
      id: 'R_kwDORelease',
      tagName: 'v2026.6.11',
      tagCommit: { oid: 'a'.repeat(40) },
      name: 'openclaw 2026.6.11',
      publishedAt: '2026-06-24T23:37:32Z',
      createdAt: '2026-06-24T22:00:00Z',
      updatedAt: '2026-06-25T01:00:00Z',
      url: 'https://github.com/openclaw/openclaw/releases/tag/v2026.6.11',
      isPrerelease: false,
      isDraft: false,
      description: '### Fixes',
    });

    assert.deepEqual(release, {
      node_id: 'R_kwDORelease',
      tag_name: 'v2026.6.11',
      tag_commit_oid: 'a'.repeat(40),
      name: 'openclaw 2026.6.11',
      published_at: '2026-06-24T23:37:32Z',
      created_at: '2026-06-24T22:00:00Z',
      updated_at: '2026-06-25T01:00:00Z',
      html_url: 'https://github.com/openclaw/openclaw/releases/tag/v2026.6.11',
      prerelease: false,
      draft: false,
      body: '### Fixes',
    });
  });

  it('treats GitHub prerelease metadata as authoritative over tag spelling', () => {
    for (const tagName of [
      'v2.0.0-beta5',
      'v2026.5.3-1',
      'v2099.1.1-preview.1',
      'v2099.1.1-canary',
    ]) {
      const release = __githubTest.mapRelease({
        id: `R_${tagName}`,
        tagName,
        tagCommit: { oid: 'a'.repeat(40) },
        name: tagName,
        publishedAt: '2026-07-01T00:00:00Z',
        createdAt: '2026-07-01T00:00:00Z',
        updatedAt: '2026-07-01T00:00:00Z',
        url: `https://example.test/releases/${tagName}`,
        isPrerelease: false,
        isDraft: false,
        description: null,
      });
      assert.equal(release.prerelease, false, tagName);
    }
  });

  it('keeps a stable-looking tag prerelease when GitHub marks it prerelease', () => {
    const release = __githubTest.mapRelease({
      id: 'R_stable-looking-prerelease',
      tagName: 'v2099.7.1',
      tagCommit: { oid: 'a'.repeat(40) },
      name: 'openclaw 2099.7.1 beta',
      publishedAt: '2026-07-01T00:00:00Z',
      createdAt: '2026-07-01T00:00:00Z',
      updatedAt: '2026-07-01T00:00:00Z',
      url: 'https://github.com/openclaw/openclaw/releases/tag/v2099.7.1',
      isPrerelease: true,
      isDraft: false,
      description: 'Beta release',
    });

    assert.equal(release.prerelease, true);
  });

  it('preserves an exact beta tag when its GitHub release name looks stable', async () => {
    const catalog = await fetchBoundReleaseCatalog([
      releaseNode({
        id: 'R_beta-with-stable-name',
        tagName: 'v2.0.0-beta.1',
        tagOid: '2'.repeat(40),
        name: 'OpenClaw v2.0.0',
        isPrerelease: true,
      }),
    ]);

    assert.equal(catalog.releases[0].tag_name, 'v2.0.0-beta.1');
    assert.equal(catalog.releases[0].name, 'OpenClaw v2.0.0');
    assert.equal(catalog.releases[0].prerelease, true);
    assert.equal(activeReleaseRows(catalog)[0].tag, 'v2.0.0-beta.1');
  });

  it('exhausts and stabilizes the full release connection with explicit metadata', async () => {
    const newestCreated = releaseNode({
      id: 'R_newest-created',
      tagName: 'v2099.7.2-beta.1',
      publishedAt: '2026-07-02T00:00:00Z',
      createdAt: '2026-07-02T00:00:00Z',
      isPrerelease: true,
    });
    const middle = releaseNode({
      id: 'R_middle',
      tagName: 'v2099.7.1',
      publishedAt: '2026-07-01T00:00:00Z',
      createdAt: '2026-07-01T00:00:00Z',
    });
    const latePublishedOldCreated = releaseNode({
      id: 'R_late-published',
      tagName: 'v2099.7.3',
      publishedAt: '2026-07-03T00:00:00Z',
      createdAt: '2026-06-01T00:00:00Z',
    });
    const responses = [
      releasePage(3, [newestCreated, middle], 'cursor-1'),
      releasePage(3, [latePublishedOldCreated]),
      releasePage(3, [newestCreated, middle], 'cursor-1'),
      releasePage(3, [latePublishedOldCreated]),
    ];
    const cursors: Array<string | null> = [];
    let query = '';
    const catalog = await __githubTest.fetchReleaseCatalog({
      request: async <T>(requestQuery: string, variables: Record<string, unknown> = {}): Promise<T> => {
        query = requestQuery;
        cursors.push((variables.after as string | null | undefined) ?? null);
        return responses.shift() as T;
      },
      maxPagesPerConnection: 2,
    });

    assert.deepEqual(cursors, [null, 'cursor-1', null, 'cursor-1']);
    assert.deepEqual(
      catalog.releases.map((release) => release.tag_name),
      ['v2099.7.2-beta.1', 'v2099.7.1', 'v2099.7.3'],
    );
    assert.deepEqual(catalog.metadata, {
      exhausted: true,
      stabilized: true,
      totalCount: 3,
      nodeCount: 3,
      pageCount: 2,
      pagesFetched: 4,
      sweepCount: 2,
      sweepPageCounts: [2, 2],
      digest: catalog.metadata.digest,
      sourceOrder: 'CREATED_AT_DESC',
    });
    assert.match(catalog.metadata.digest, /^[0-9a-f]{64}$/);
    assert.match(query, /releases\(first: \$first, after: \$after, orderBy: \{field: CREATED_AT, direction: DESC\}\)/);
    assert.match(query, /totalCount/);
    assert.match(query, /\bid\s+tagName/);
    assert.match(query, /tagCommit \{ oid \}/);
    assert.match(query, /publishedAt\s+createdAt\s+updatedAt/);
  });

  it('binds release catalog stabilization and final attestation digests to tag commit OIDs', async () => {
    const fetchAtOid = (tagOid: string) => __githubTest.fetchReleaseCatalog({
      request: async <T>(): Promise<T> => releasePage(1, [
        releaseNode({ id: 'R_1', tagName: 'v1', tagOid }),
      ]) as T,
    });
    const initial = await fetchAtOid('a'.repeat(40));
    const final = await fetchAtOid('b'.repeat(40));
    assert.notEqual(initial.metadata.digest, final.metadata.digest);

    let calls = 0;
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => {
          calls++;
          return releasePage(1, [
            releaseNode({
              id: 'R_1',
              tagName: 'v1',
              tagOid: (calls % 2 === 0 ? 'b' : 'a').repeat(40),
            }),
          ]) as T;
        },
      }),
      /failed to stabilize after 3 complete sweeps/,
    );
  });

  it('accepts a release catalog that changes once and stabilizes on the third complete sweep', async () => {
    let calls = 0;
    const catalog = await __githubTest.fetchReleaseCatalog({
      request: async <T>(): Promise<T> => {
        calls++;
        return releasePage(1, [
          releaseNode({
            id: 'R_1',
            tagName: 'v1',
            updatedAt: calls === 1 ? '2026-07-03T00:00:01Z' : '2026-07-03T00:00:02Z',
          }),
        ]) as T;
      },
    });

    assert.equal(calls, 3);
    assert.equal(catalog.metadata.sweepCount, 3);
    assert.equal(catalog.metadata.pagesFetched, 3);
    assert.equal(catalog.releases[0].updated_at, '2026-07-03T00:00:02Z');
  });

  it('rejects null, duplicate-identity, and duplicate-tag release nodes', async () => {
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => releasePage(1, [null]) as T,
      }),
      /repository\.releases connection returned null node at index 0/,
    );

    const first = releaseNode({ id: 'R_duplicate', tagName: 'v1' });
    const duplicateIdentity = releaseNode({ id: 'R_duplicate', tagName: 'v2' });
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => releasePage(2, [first, duplicateIdentity]) as T,
      }),
      /duplicate node id R_duplicate/,
    );

    const duplicateTag = releaseNode({ id: 'R_other', tagName: 'v1' });
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => releasePage(2, [first, duplicateTag]) as T,
      }),
      /duplicate tag v1/,
    );
  });

  it('rejects non-boolean GraphQL isPrerelease metadata', async () => {
    for (const isPrerelease of [0, 1, 'false', null]) {
      const node = {
        ...releaseNode({
          id: `R_invalid-prerelease-${String(isPrerelease)}`,
          tagName: `v-invalid-prerelease-${String(isPrerelease)}`,
        }),
        isPrerelease,
      } as unknown as ReturnType<typeof releaseNode>;

      await assert.rejects(
        __githubTest.fetchReleaseCatalog({
          request: async <T>(): Promise<T> =>
            releasePage(1, [node]) as T,
        }),
        /returned release .* with non-boolean isPrerelease/,
        String(isPrerelease),
      );
    }
  });

  it('rejects non-boolean GraphQL isDraft metadata', async () => {
    for (const isDraft of [0, 1, 'false', null]) {
      const node = {
        ...releaseNode({
          id: `R_invalid-draft-${String(isDraft)}`,
          tagName: `v-invalid-draft-${String(isDraft)}`,
        }),
        isDraft,
      } as unknown as ReturnType<typeof releaseNode>;

      await assert.rejects(
        __githubTest.fetchReleaseCatalog({
          request: async <T>(): Promise<T> =>
            releasePage(1, [node]) as T,
        }),
        /returned release .* with non-boolean isDraft/,
        String(isDraft),
      );
    }
  });

  it('rejects release count mismatches, repeated cursors, and page-cap truncation', async () => {
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => releasePage(
          2,
          [releaseNode({ id: 'R_1', tagName: 'v1' })],
        ) as T,
      }),
      /exhausted with 1 nodes, but totalCount was 2/,
    );

    let repeatedCursorCalls = 0;
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => {
          repeatedCursorCalls++;
          return releasePage(
            3,
            [releaseNode({ id: `R_${repeatedCursorCalls}`, tagName: `v${repeatedCursorCalls}` })],
            'cursor-1',
          ) as T;
        },
        maxPagesPerConnection: 10,
      }),
      /repeated pagination cursor cursor-1/,
    );
    assert.equal(repeatedCursorCalls, 2);

    let pageCapCalls = 0;
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => {
          pageCapCalls++;
          return releasePage(
            3,
            [releaseNode({ id: `R_cap_${pageCapCalls}`, tagName: `v-cap-${pageCapCalls}` })],
            `cursor-${pageCapCalls}`,
          ) as T;
        },
        maxPagesPerConnection: 2,
      }),
      /exceeded 2 pages before pagination completed/,
    );
    assert.equal(pageCapCalls, 2);
  });

  it('fails closed when three complete release sweeps never stabilize', async () => {
    let calls = 0;
    await assert.rejects(
      __githubTest.fetchReleaseCatalog({
        request: async <T>(): Promise<T> => {
          calls++;
          return releasePage(1, [
            releaseNode({
              id: 'R_1',
              tagName: 'v1',
              updatedAt: `2026-07-03T00:00:0${calls}Z`,
            }),
          ]) as T;
        },
      }),
      /failed to stabilize after 3 complete sweeps/,
    );
    assert.equal(calls, 3);
  });

  it('does not let an injected requester mint authoritative release catalog provenance', async () => {
    const catalog = await fetchBoundReleaseCatalog([
      releaseNode({
        id: 'R_injected_v1',
        tagName: 'v1.0.0',
        tagOid: '1'.repeat(40),
      }),
    ]);

    assert.equal(catalog.metadata.exhausted, true);
    assert.equal(catalog.metadata.stabilized, true);
    assert.throws(
      () => __githubTest.authorizeGithubReleaseCatalogPublication(
        catalog,
        activeReleaseRows(catalog),
      ),
      /requires the built-in production GitHub GraphQL requester; injected requesters are untrusted/,
    );
  });

  it('rejects a stable-looking phantom tag without the exact fetched catalog object', async () => {
    const fetchedCatalog = await fetchBoundReleaseCatalog([
      releaseNode({
        id: 'R_fetched_v1',
        tagName: 'v1.0.0',
        tagOid: '1'.repeat(40),
      }),
    ]);
    const forgedCatalog = structuredClone(fetchedCatalog);
    forgedCatalog.releases = [{
      ...forgedCatalog.releases[0],
      node_id: 'R_phantom_v9',
      tag_name: 'v9.9.9',
      tag_commit_oid: '9'.repeat(40),
      name: 'OpenClaw v9.9.9',
      html_url:
        'https://github.com/openclaw/openclaw/releases/tag/v9.9.9',
    }];

    assert.throws(
      () => __githubTest.authorizeGithubReleaseCatalogPublication(
        forgedCatalog,
        activeReleaseRows(forgedCatalog),
      ),
      /requires the exact object returned by fetchReleaseCatalog/,
    );
  });

  it('rejects in-place mutation of the exact fetched catalog object', async () => {
    const catalog = await fetchBoundReleaseCatalog([
      releaseNode({
        id: 'R_fetched_v1',
        tagName: 'v1.0.0',
        tagOid: '1'.repeat(40),
      }),
    ]);
    catalog.releases[0] = {
      ...catalog.releases[0],
      node_id: 'R_phantom_v9',
      tag_name: 'v9.9.9',
      tag_commit_oid: '9'.repeat(40),
      name: 'OpenClaw v9.9.9',
      html_url:
        'https://github.com/openclaw/openclaw/releases/tag/v9.9.9',
    };

    assert.throws(
      () => __githubTest.authorizeGithubReleaseCatalogPublication(
        catalog,
        activeReleaseRows(catalog),
      ),
      /changed after GraphQL provenance was captured/,
    );
  });

  it('does not allow draft releases into authorized active rows', async () => {
    const catalog = await fetchBoundReleaseCatalog([
      releaseNode({
        id: 'R_draft_v2',
        tagName: 'v2.0.0',
        tagOid: '2'.repeat(40),
        publishedAt: '2026-07-02T00:00:00Z',
        isDraft: true,
      }),
      releaseNode({
        id: 'R_stable_v1',
        tagName: 'v1.0.0',
        tagOid: '1'.repeat(40),
        publishedAt: '2026-07-01T00:00:00Z',
      }),
    ]);
    const activeRows = activeReleaseRows(catalog);
    const draft = catalog.releases.find((release) => release.draft);
    assert.ok(draft);

    assert.throws(
      () => __githubTest.validateGithubReleaseCatalogPublication(
        catalog,
        [activeReleaseRow(draft), ...activeRows],
      ),
      /must contain every non-draft release .* in exact publication order/,
    );

    const validation =
      __githubTest.validateGithubReleaseCatalogPublication(
        catalog,
        activeRows,
      );
    assert.equal(validation.draftCount, 1);
    assert.equal(validation.publishedCount, 1);
    assert.equal(validation.activeReleaseCount, 1);
  });

  it('rejects omitted, reordered, and altered active publication rows', async () => {
    const catalog = await fetchBoundReleaseCatalog([
      releaseNode({
        id: 'R_v3',
        tagName: 'v3.0.0',
        tagOid: '3'.repeat(40),
        publishedAt: '2026-07-03T00:00:00Z',
      }),
      releaseNode({
        id: 'R_v2',
        tagName: 'v2.0.0',
        tagOid: '2'.repeat(40),
        publishedAt: '2026-07-02T00:00:00Z',
      }),
      releaseNode({
        id: 'R_v1',
        tagName: 'v1.0.0',
        tagOid: '1'.repeat(40),
        publishedAt: '2026-07-01T00:00:00Z',
      }),
    ]);
    const activeRows = activeReleaseRows(catalog);
    const adversarialRows: Array<{
      name: string;
      rows: GithubReleaseCatalogActiveRelease[];
    }> = [
      {
        name: 'omitted',
        rows: activeRows.slice(0, -1),
      },
      {
        name: 'reordered',
        rows: [activeRows[1], activeRows[0], activeRows[2]],
      },
      {
        name: 'altered',
        rows: activeRows.map((row, index) =>
          index === 1
            ? {
                ...row,
                catalog_tag_commit_oid: '9'.repeat(40),
              }
            : row),
      },
    ];

    for (const testCase of adversarialRows) {
      assert.throws(
        () => __githubTest.validateGithubReleaseCatalogPublication(
          catalog,
          testCase.rows,
        ),
        /must contain every non-draft release .* in exact publication order/,
        testCase.name,
      );
    }

    const validation =
      __githubTest.validateGithubReleaseCatalogPublication(
        catalog,
        activeRows,
      );
    assert.equal(validation.activeReleaseCount, activeRows.length);
    assert.equal(
      validation.activeReleaseDigest,
      __githubTest.githubReleaseCatalogActiveReleaseDigest(activeRows),
    );
  });

  it('maps issues and labels into the existing REST-shaped contract', () => {
    const issue = __githubTest.mapIssue({
      id: 'ISSUE-node-42',
      __typename: 'Issue',
      number: 42,
      title: 'Regression in gateway',
      body: 'Observed on v2026.7.4 with complete reproduction steps.',
      state: 'CLOSED',
      author: {
        id: 'ACTOR-maintainer',
        __typename: 'User',
        login: 'maintainer',
      },
      authorAssociation: 'MEMBER',
      createdAt: '2026-06-20T00:00:00Z',
      updatedAt: '2026-06-22T00:00:00Z',
      closedAt: '2026-06-22T00:00:00Z',
      url: 'https://github.com/openclaw/openclaw/issues/42',
      comments: { totalCount: 3 },
      reactionGroups: [
        { content: 'THUMBS_UP', reactors: { totalCount: 4 } },
        { content: 'CONFUSED', reactors: { totalCount: 1 } },
      ],
      labels: {
        totalCount: 2,
        nodes: [{ name: 'bug' }, { name: 'impact:discord' }],
        pageInfo: { hasNextPage: false, endCursor: null },
      },
    });

    assert.equal(issue.state, 'closed');
    assert.equal(issue.node_id, 'ISSUE-node-42');
    assert.equal(issue.node_type, 'Issue');
    assert.equal(issue.body, 'Observed on v2026.7.4 with complete reproduction steps.');
    assert.deepEqual(issue.user, {
      id: 'ACTOR-maintainer',
      type: 'User',
      login: 'maintainer',
    });
    assert.equal(issue.author_association, 'MEMBER');
    assert.equal(issue.comments, 3);
    assert.equal(issue.reaction_total, 5);
    assert.equal(issue.positive_reactions, 4);
    assert.deepEqual(issue.labels, [{ name: 'bug' }, { name: 'impact:discord' }]);
  });

  it('fails closed when issue score evidence connections are missing', () => {
    const issueNode = {
      id: 'ISSUE-node-42',
      __typename: 'Issue',
      number: 42,
      title: 'Regression in gateway',
      body: null,
      state: 'CLOSED',
      author: {
        id: 'ACTOR-maintainer',
        __typename: 'User',
        login: 'maintainer',
      },
      authorAssociation: 'MEMBER',
      createdAt: '2026-06-20T00:00:00Z',
      updatedAt: '2026-06-22T00:00:00Z',
      closedAt: '2026-06-22T00:00:00Z',
      url: 'https://github.com/openclaw/openclaw/issues/42',
      comments: { totalCount: 3 },
      reactionGroups: [],
      labels: { totalCount: 0, nodes: [], pageInfo: { hasNextPage: false, endCursor: null } },
    };

    assert.throws(
      () => __githubTest.mapIssue({ ...issueNode, labels: null }),
      /issue #42 labels connection/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issueNode,
        labels: { totalCount: 0, nodes: null, pageInfo: { hasNextPage: false, endCursor: null } },
      }),
      /issue #42 labels connection missing nodes/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issueNode,
        labels: { totalCount: 1, nodes: [null], pageInfo: { hasNextPage: false, endCursor: null } },
      }),
      /issue #42 labels connection returned null node at index 0/,
    );
    assert.throws(
      () => __githubTest.mapIssue({ ...issueNode, reactionGroups: null }),
      /issue #42 missing reactionGroups/,
    );
  });

  it('requires exact issue state, closedAt consistency, and valid reaction groups', () => {
    const issue = issueLookupNode(42);

    assert.throws(
      () => __githubTest.mapIssue({ ...issue, state: 'open' }),
      /unsupported state "open"/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issue,
        state: 'OPEN',
        closedAt: '2026-07-03T01:00:00Z',
      }),
      /is OPEN but closedAt is not null/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issue,
        state: 'CLOSED',
        closedAt: null,
      }),
      /is CLOSED but closedAt is invalid/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issue,
        state: 'CLOSED',
        closedAt: '2026-07-03T02:00:00Z',
      }),
      /inconsistent closedAt chronology/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issue,
        state: 'CLOSED',
        closedAt: 'not-a-timestamp',
      }),
      /is CLOSED but closedAt is invalid/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issue,
        reactionGroups: [null],
      }),
      /reactionGroups returned null group at index 0/,
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...issue,
        reactionGroups: [{ content: 'FUTURE_REACTION', reactors: { totalCount: 1 } }],
      }),
      /unsupported content "FUTURE_REACTION"/,
    );
    for (const totalCount of [
      -1,
      1.5,
      Number.MAX_SAFE_INTEGER + 1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      assert.throws(
        () => __githubTest.mapIssue({
          ...issue,
          reactionGroups: [{ content: 'THUMBS_UP', reactors: { totalCount } }],
        }),
        /invalid count for THUMBS_UP/,
      );
    }
    assert.throws(
      () => __githubTest.mapIssue({
        ...issue,
        reactionGroups: [{ content: 'THUMBS_UP', reactors: null }],
      }),
      /invalid count for THUMBS_UP/,
    );
  });

  it('accepts bounded GitHub closedAt skew without rewriting timestamps', () => {
    const liveIssue = {
      ...issueLookupNode(96622),
      state: 'CLOSED' as const,
      createdAt: '2026-06-25T01:42:52Z',
      updatedAt: '2026-06-25T01:59:23Z',
      closedAt: '2026-06-25T01:59:24Z',
    };
    const mapped = __githubTest.mapIssue(liveIssue);

    assert.equal(mapped.state, 'closed');
    assert.equal(mapped.created_at, liveIssue.createdAt);
    assert.equal(mapped.updated_at, liveIssue.updatedAt);
    assert.equal(mapped.closed_at, liveIssue.closedAt);
    assert.equal(
      __githubTest.mapIssue({
        ...liveIssue,
        closedAt: '2026-06-25T01:59:25Z',
      }).closed_at,
      '2026-06-25T01:59:25Z',
    );
    assert.throws(
      () => __githubTest.mapIssue({
        ...liveIssue,
        closedAt: '2026-06-25T01:59:26Z',
      }),
      /inconsistent closedAt chronology/,
    );
  });

  it('validates GraphQL connections and pagination cursors', () => {
    const connection = __githubTest.requireGraphqlConnection(
      { nodes: [{ name: 'bug' }], pageInfo: { hasNextPage: false, endCursor: null } },
      'test.labels',
    );

    assert.equal(connection.nodes.length, 1);
    assert.equal(__githubTest.nextGraphqlPageCursor(connection.pageInfo, 'test.labels'), null);
    assert.equal(
      __githubTest.nextGraphqlPageCursor({ hasNextPage: true, endCursor: 'cursor-1' }, 'test.labels'),
      'cursor-1',
    );
    assert.throws(
      () => __githubTest.requireGraphqlConnection({ nodes: null, pageInfo: { hasNextPage: false, endCursor: null } }, 'test.labels'),
      /test\.labels connection missing nodes/,
    );
    assert.throws(
      () => __githubTest.requireGraphqlConnection({ nodes: [{ name: 'bug' }, null], pageInfo: { hasNextPage: false, endCursor: null } }, 'test.labels'),
      /test\.labels connection returned null node at index 1/,
    );
    assert.throws(
      () => __githubTest.requireGraphqlConnection({ nodes: [], pageInfo: null }, 'test.labels'),
      /test\.labels connection missing pageInfo/,
    );
    assert.throws(
      () => __githubTest.nextGraphqlPageCursor({ hasNextPage: true, endCursor: null }, 'test.labels'),
      /test\.labels pageInfo hasNextPage without endCursor/,
    );
  });

  it('completes an issue connection after more than 500 pages', async () => {
    const totalPages = 501;
    let calls = 0;
    let yielded = 0;
    const request = async <T>(): Promise<T> => {
      calls++;
      const hasNextPage = calls < totalPages;
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issues: {
            totalCount: totalPages,
            nodes: [issueLookupNode(calls)],
            pageInfo: {
              hasNextPage,
              endCursor: hasNextPage ? `issue-cursor-${calls}` : null,
            },
          },
        },
      } as T;
    };

    for await (const page of __githubTest.paginateIssues(100, {
      request,
      maxPagesPerConnection: 2_000,
      pageDelayMs: 0,
    })) {
      yielded += page.issues.length;
      assert.equal(page.metadata.totalCount, totalPages);
    }

    assert.equal(calls, totalPages);
    assert.equal(yielded, totalPages);
  });

  it('fails closed when issue pagination reaches its configured cap', async () => {
    let calls = 0;
    const request = async <T>(): Promise<T> => {
      calls++;
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issues: {
            totalCount: 10_000,
            nodes: [issueLookupNode(calls)],
            pageInfo: {
              hasNextPage: true,
              endCursor: `issue-cap-cursor-${calls}`,
            },
          },
        },
      } as T;
    };

    await assert.rejects(
      async () => {
        for await (const _page of __githubTest.paginateIssues(100, {
          request,
          maxPagesPerConnection: 500,
          pageDelayMs: 0,
        })) {
          // Exhaust the generator.
        }
      },
      /repository\.issues exceeded 500 pages before pagination completed/,
    );
    assert.equal(calls, 500);
  });

  it('requires issue totalCount in the GraphQL query', () => {
    const incrementalQuery = __githubTest.buildIssuesQuery();
    const exhaustiveQuery = __githubTest.buildIssuesQuery('CREATED_AT_ASC');
    const boundaryQuery = __githubTest.buildIssueCatalogBoundaryQuery();

    assert.match(incrementalQuery, /orderBy: \{field: UPDATED_AT, direction: DESC\}/);
    assert.match(exhaustiveQuery, /orderBy: \{field: CREATED_AT, direction: ASC\}/);
    assert.match(exhaustiveQuery, /\) \{\s+totalCount\s+nodes \{\s+id\s+number/);
    assert.match(
      exhaustiveQuery,
      /author \{ __typename login \.\.\. on Node \{ id \} \}/,
    );
    assert.match(exhaustiveQuery, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(boundaryQuery, /orderBy: \{field: CREATED_AT, direction: ASC\}/);
    assert.match(boundaryQuery, /\) \{\s+totalCount\s+nodes \{\s+id\s+__typename\s+number\s+createdAt/);
    assert.doesNotMatch(boundaryQuery, /\btitle\b|\bbody\b|\blabels\b|\bcomments\b/);
  });

  it('honors the configured exhaustive issue page size', async () => {
    const requestedSizes: number[] = [];
    const catalog = await __githubTest.fetchIssueCatalog({
      perPage: 2,
      pageDelayMs: 0,
      request: async <T>(_query: string, variables: Record<string, unknown> = {}): Promise<T> => {
        requestedSizes.push(Number(variables.first));
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: {
              totalCount: 2,
              nodes: [issueLookupNode(1), issueLookupNode(2)],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        } as T;
      },
    });

    assert.deepEqual(requestedSizes, [100, 2]);
    assert.equal(catalog.metadata.pageCount, 1);
    assert.equal(catalog.metadata.sweepCount, 2);
  });

  it('stabilizes a catalog containing bounded GitHub closedAt skew', async () => {
    const liveIssue = {
      ...issueLookupNode(96622),
      state: 'CLOSED' as const,
      createdAt: '2026-06-25T01:42:52Z',
      updatedAt: '2026-06-25T01:59:23Z',
      closedAt: '2026-06-25T01:59:24Z',
    };
    const catalog = await __githubTest.fetchIssueCatalog({
      pageDelayMs: 0,
      request: async <T>(): Promise<T> => ({
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issues: {
            totalCount: 1,
            nodes: [liveIssue],
            pageInfo: { hasNextPage: false, endCursor: null },
          },
        },
      } as T),
    });

    assert.equal(catalog.metadata.sweepCount, 2);
    assert.equal(catalog.issues.length, 1);
    assert.equal(catalog.issues[0]?.updated_at, liveIssue.updatedAt);
    assert.equal(catalog.issues[0]?.closed_at, liveIssue.closedAt);
  });

  it('rejects a terminal issue page with fewer unique rows than totalCount', async () => {
    await assert.rejects(
      async () => {
        for await (const _page of __githubTest.paginateIssues(100, {
          request: async <T>(): Promise<T> => ({
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issues: {
                totalCount: 2,
                nodes: [issueLookupNode(1)],
                pageInfo: { hasNextPage: false, endCursor: null },
              },
            },
          } as T),
          pageDelayMs: 0,
        })) {
          // Exhaust the generator.
        }
      },
      /repository\.issues terminal unique count 1 did not match totalCount 2/,
    );
  });

  it('stabilizes complete issue sweeps and returns auditable catalog metadata', async () => {
    const requestedCursors: Array<string | null> = [];
    const catalog = await __githubTest.fetchIssueCatalog({
      request: async <T>(_query: string, variables: Record<string, unknown> = {}): Promise<T> => {
        const after = (variables.after as string | null | undefined) ?? null;
        requestedCursors.push(after);
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: after == null
              ? {
                totalCount: 2,
                nodes: [issueLookupNode(1)],
                pageInfo: { hasNextPage: true, endCursor: 'issue-cursor-1' },
              }
              : {
                totalCount: 2,
                nodes: [issueLookupNode(2)],
                pageInfo: { hasNextPage: false, endCursor: null },
              },
          },
        } as T;
      },
      pageDelayMs: 0,
    });

    assert.deepEqual(requestedCursors, [null, 'issue-cursor-1', null, 'issue-cursor-1']);
    assert.deepEqual(catalog.issues.map((issue) => issue.number), [1, 2]);
    assert.equal(catalog.metadata.totalCount, 2);
    assert.equal(catalog.metadata.observedTotalCount, 2);
    assert.equal(catalog.metadata.postBoundaryGrowthCount, 0);
    assert.equal(catalog.metadata.nodeCount, 2);
    assert.equal(catalog.metadata.uniqueCount, 2);
    assert.equal(catalog.metadata.pageCount, 2);
    assert.equal(catalog.metadata.pagesFetched, 4);
    assert.equal(catalog.metadata.sweepCount, 2);
    assert.equal(catalog.metadata.exhausted, true);
    assert.equal(catalog.metadata.stabilized, true);
    assert.equal(catalog.metadata.nextCursor, null);
    assert.equal(catalog.metadata.sourceOrder, 'CREATED_AT_ASC');
    assert.equal(catalog.metadata.digest, catalog.metadata.membershipDigest);
    assert.match(catalog.metadata.contentDigest, /^[0-9a-f]{64}$/);
    assert.deepEqual(catalog.metadata.snapshotBoundary.terminalIssue, {
      nodeId: 'ISSUE-node-2',
      issueNumber: 2,
      createdAt: '2026-07-03T00:00:00Z',
    });
    assert.match(catalog.metadata.digest, /^[0-9a-f]{64}$/);
  });

  // Keep this historical test identity stable for the accepted baseline. The
  // assertions now enforce the corrected behavior: retain first-N and defer growth.
  it('restarts at a new boundary when totalCount grows instead of omitting new issues', async () => {
    let call = 0;
    const queries: string[] = [];
    const catalog = await __githubTest.fetchIssueCatalog({
      request: async <T>(
        query: string,
        _variables: Record<string, unknown> = {},
      ): Promise<T> => {
        call++;
        queries.push(query);
        const totalCount = call <= 1 ? 2 : 3;
        const nodes = [issueLookupNode(1), issueLookupNode(2)];
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: {
              totalCount,
              nodes,
              pageInfo: totalCount > nodes.length
                ? { hasNextPage: true, endCursor: 'post-boundary-cursor' }
                : { hasNextPage: false, endCursor: null },
            },
          },
        } as T;
      },
      pageDelayMs: 0,
    });

    assert.equal(call, 2);
    assert.ok(queries.every((query) =>
      /orderBy: \{field: CREATED_AT, direction: ASC\}/.test(query)));
    assert.deepEqual(catalog.issues.map((issue) => issue.number), [1, 2]);
    assert.equal(catalog.metadata.totalCount, 2);
    assert.equal(catalog.metadata.observedTotalCount, 3);
    assert.equal(catalog.metadata.postBoundaryGrowthCount, 1);
    assert.equal(catalog.metadata.snapshotBoundary.totalCount, 2);
    assert.equal(catalog.metadata.snapshotBoundary.terminalIssue?.issueNumber, 2);
    assert.equal(catalog.metadata.membershipDigest, catalog.metadata.digest);
    assert.match(catalog.metadata.contentDigest, /^[0-9a-f]{64}$/);
  });

  // Keep this historical test identity stable for the accepted baseline. The
  // assertions now prove mutable content does not invalidate stable membership.
  it('requires two identical full-content sweeps, not only stable membership', async () => {
    let call = 0;
    const catalog = await __githubTest.fetchIssueCatalog({
      request: async <T>(): Promise<T> => {
        call++;
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: {
              totalCount: 1,
              nodes: [{
                ...issueLookupNode(1),
                title: call === 1 ? 'Changing title' : 'Stable title',
              }],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        } as T;
      },
      pageDelayMs: 0,
    });

    assert.equal(call, 2);
    assert.equal(catalog.issues[0].title, 'Stable title');
    assert.equal(catalog.metadata.sweepCount, 2);
  });

  it('rejects duplicate identities, count decreases, missing first-N rows, and unstable membership', async () => {
    await assert.rejects(
      () => __githubTest.fetchIssueCatalogSweep({
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: {
              totalCount: 2,
              nodes: [issueLookupNode(1), issueLookupNode(1)],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        } as T),
        pageDelayMs: 0,
      }),
      /duplicate node id ISSUE-node-1/,
    );

    await assert.rejects(
      () => __githubTest.fetchIssueCatalogSweep({
        request: async <T>(_query: string, variables: Record<string, unknown> = {}): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: variables.after == null
              ? {
                totalCount: 2,
                nodes: [issueLookupNode(1)],
                pageInfo: { hasNextPage: true, endCursor: 'issue-cursor-1' },
              }
              : {
                totalCount: 1,
                nodes: [issueLookupNode(2)],
                pageInfo: { hasNextPage: false, endCursor: null },
              },
          },
        } as T),
        pageDelayMs: 0,
      }),
      /totalCount decreased below frozen snapshot boundary from 2 to 1/,
    );

    await assert.rejects(
      () => __githubTest.fetchIssueCatalogSweep({
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: {
              totalCount: 2,
              nodes: [issueLookupNode(1)],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        } as T),
        pageDelayMs: 0,
      }),
      /terminal unique count 1 did not match frozen snapshot boundary 2/,
    );

    await assert.rejects(
      () => __githubTest.fetchIssueCatalogSweep({
        request: async <T>(_query: string, variables: Record<string, unknown> = {}): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issues: variables.after == null
              ? {
                totalCount: 3,
                nodes: [issueLookupNode(1)],
                pageInfo: { hasNextPage: true, endCursor: 'issue-cursor-1' },
              }
              : {
                totalCount: 3,
                nodes: [issueLookupNode(2)],
                pageInfo: { hasNextPage: true, endCursor: 'issue-cursor-1' },
              },
          },
        } as T),
        pageDelayMs: 0,
      }),
      /repository\.issues repeated pagination cursor issue-cursor-1/,
    );

    let calls = 0;
    await assert.rejects(
      () => __githubTest.fetchIssueCatalog({
        request: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          calls++;
          const sweep = Math.ceil(calls / 2);
          const after = (variables.after as string | null | undefined) ?? null;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issues: after == null
                ? {
                    totalCount: 2,
                    nodes: [{
                      ...issueLookupNode(10 + sweep),
                      createdAt: '2026-07-02T00:00:00Z',
                    }],
                    pageInfo: { hasNextPage: true, endCursor: `cursor-${sweep}` },
                  }
                : {
                    totalCount: 2,
                    nodes: [issueLookupNode(2)],
                    pageInfo: { hasNextPage: false, endCursor: null },
                  },
            },
          } as T;
        },
        pageDelayMs: 0,
      }),
      /repository\.issues immutable membership changed across frozen-boundary sweeps/,
    );
    assert.equal(calls, 4);
  });

  it('returns stable multipage issue comment snapshot metadata', async () => {
    const requestedCursors: Array<string | null> = [];
    const pages = [
      { id: 1, next: 'cursor-1' },
      { id: 2, next: null },
      { id: 1, next: 'cursor-1' },
      { id: 2, next: null },
    ];
    const request = async <T>(_query: string, variables: Record<string, unknown> = {}): Promise<T> => {
      const page = pages[requestedCursors.length];
      requestedCursors.push((variables.after0 as string | null | undefined) ?? null);
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: commentIssue(
            '2026-07-03T01:00:00Z',
            2,
            [commentNode(page.id)],
            page.next,
          ),
        },
      } as T;
    };

    const snapshots = await __githubTest.listIssueCommentSnapshotsBatch([7], {
      request,
      maxPagesPerConnection: 2,
    });
    const snapshot = snapshots.get(7);

    assert.deepEqual(requestedCursors, [null, 'cursor-1', null, 'cursor-1']);
    assert.equal(snapshot?.issueNumber, 7);
    assert.equal(snapshot?.issueUpdatedAt, '2026-07-03T01:00:00Z');
    assert.equal(snapshot?.totalCount, 2);
    assert.deepEqual(snapshot?.comments.map((comment) => comment.id), [1, 2]);
    assert.match(snapshot?.commentsDigest ?? '', /^[0-9a-f]{64}$/);
  });

  it('covers exact 100 and 101 issue-comment connection boundaries', async () => {
    for (const totalCount of [100, 101]) {
      const nodes = Array.from(
        { length: totalCount },
        (_, index) => commentNode(index + 1),
      );
      const requestedCursors: Array<string | null> = [];
      const snapshots = await __githubTest.listIssueCommentSnapshotsBatch([7], {
        request: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          assert.equal(variables.first, 100);
          const after = (variables.after0 as string | null | undefined) ?? null;
          requestedCursors.push(after);
          assert.ok(after === null || after === 'comments-100');
          const start = after === null ? 0 : 100;
          const nextCursor = start + 100 < totalCount ? 'comments-100' : null;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: commentIssue(
                '2026-07-03T01:00:00Z',
                totalCount,
                nodes.slice(start, start + 100),
                nextCursor,
              ),
            },
          } as T;
        },
      });

      assert.deepEqual(
        requestedCursors,
        totalCount === 100
          ? [null, null]
          : [null, 'comments-100', null, 'comments-100'],
      );
      assert.equal(snapshots.get(7)?.totalCount, totalCount);
      assert.equal(snapshots.get(7)?.comments.length, totalCount);
      assert.equal(snapshots.get(7)?.comments.at(-1)?.id, totalCount);
    }
  });

  it('queries zero-count issues and discovers a new comment after a restart', async () => {
    let calls = 0;
    const delays: number[] = [];
    const request = async <T>(): Promise<T> => {
      calls++;
      const hasComment = calls > 1;
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: commentIssue(
            hasComment ? '2026-07-03T02:00:00Z' : '2026-07-03T01:00:00Z',
            hasComment ? 1 : 0,
            hasComment ? [commentNode(1)] : [],
          ),
        },
      } as T;
    };

    const snapshots = await __githubTest.listIssueCommentSnapshotsBatch([7], {
      request,
      snapshotMaxAttempts: 3,
      snapshotRetryBaseMs: 25,
      snapshotRetryMaxMs: 100,
      sleep: async (ms: number) => {
        delays.push(ms);
      },
    });

    assert.equal(calls, 4);
    assert.deepEqual(delays, [25]);
    assert.equal(snapshots.get(7)?.totalCount, 1);
    assert.deepEqual(snapshots.get(7)?.comments.map((comment) => comment.id), [1]);
  });

  it('restarts the entire chunk from null cursors after between-page token drift', async () => {
    let calls = 0;
    const requests: Array<{
      numbers: number[];
      cursors: Array<string | null>;
    }> = [];
    const request = async <T>(_query: string, variables: Record<string, unknown> = {}): Promise<T> => {
      calls++;
      const numbers = [variables.number0, variables.number1]
        .filter((value): value is number => typeof value === 'number');
      const cursors = numbers.map((_, idx) => (
        (variables[`after${idx}`] as string | null | undefined) ?? null
      ));
      requests.push({ numbers, cursors });

      const firstPage = cursors[0] == null;
      const stableAttempt = calls >= 3;
      const issue0UpdatedAt = stableAttempt
        ? '2026-07-03T03:00:00Z'
        : firstPage
          ? '2026-07-03T01:00:00Z'
          : '2026-07-03T02:00:00Z';
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: commentIssue(
            issue0UpdatedAt,
            2,
            [commentNode(firstPage ? 1 : 2)],
            firstPage ? 'cursor-1' : null,
            7,
          ),
          ...(numbers.length > 1
            ? { issue1: commentIssue('2026-07-03T00:30:00Z', 0, [], null, 8) }
            : {}),
        },
      } as T;
    };

    const snapshots = await __githubTest.listIssueCommentSnapshotsBatch([7, 8], {
      request,
      maxPagesPerConnection: 2,
      sleep: async () => undefined,
    });

    assert.deepEqual(requests, [
      { numbers: [7, 8], cursors: [null, null] },
      { numbers: [7], cursors: ['cursor-1'] },
      { numbers: [7, 8], cursors: [null, null] },
      { numbers: [7], cursors: ['cursor-1'] },
      { numbers: [7, 8], cursors: [null, null] },
      { numbers: [7], cursors: ['cursor-1'] },
    ]);
    assert.deepEqual(snapshots.get(7)?.comments.map((comment) => comment.id), [1, 2]);
    assert.equal(snapshots.get(8)?.totalCount, 0);
  });

  it('restarts when complete sweeps have the same token and IDs but different digests', async () => {
    let calls = 0;
    const delays: number[] = [];
    const request = async <T>(): Promise<T> => {
      calls++;
      const body = calls === 2 ? 'edited between sweeps' : 'stable body';
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: commentIssue(
            '2026-07-03T01:00:00Z',
            1,
            [commentNode(1, body)],
          ),
        },
      } as T;
    };

    const snapshots = await __githubTest.listIssueCommentSnapshotsBatch([7], {
      request,
      snapshotMaxAttempts: 3,
      snapshotRetryBaseMs: 25,
      snapshotRetryMaxMs: 100,
      sleep: async (ms: number) => {
        delays.push(ms);
      },
    });

    assert.equal(calls, 4);
    assert.deepEqual(delays, [25]);
    assert.equal(snapshots.get(7)?.comments[0].body, 'stable body');
  });

  it('fails closed after three unstable snapshot attempts', async () => {
    let calls = 0;
    const delays: number[] = [];
    const request = async <T>(): Promise<T> => {
      calls++;
      const secondSweep = calls % 2 === 0;
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: commentIssue(
            secondSweep ? '2026-07-03T02:00:00Z' : '2026-07-03T01:00:00Z',
            1,
            [commentNode(1)],
          ),
        },
      } as T;
    };

    await assert.rejects(
      __githubTest.listIssueCommentSnapshotsBatch([7], {
        request,
        snapshotMaxAttempts: 3,
        snapshotRetryBaseMs: 25,
        snapshotRetryMaxMs: 100,
        sleep: async (ms: number) => {
          delays.push(ms);
        },
      }),
      /failed to stabilize after 3 attempts.*token changed between sweeps/,
    );
    assert.equal(calls, 6);
    assert.deepEqual(delays, [25, 50]);
  });

  it('fails closed on invalid and duplicate comment database IDs', async () => {
    let invalidCalls = 0;
    await assert.rejects(
      __githubTest.listIssueCommentSnapshotsBatch([7], {
        request: async <T>(): Promise<T> => {
          invalidCalls++;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: commentIssue('2026-07-03T01:00:00Z', 1, [commentNode(0)]),
            },
          } as T;
        },
      }),
      /invalid databaseId 0/,
    );
    assert.equal(invalidCalls, 1);

    let duplicateCalls = 0;
    await assert.rejects(
      __githubTest.listIssueCommentSnapshotsBatch([7], {
        request: async <T>(): Promise<T> => {
          duplicateCalls++;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: commentIssue(
                '2026-07-03T01:00:00Z',
                2,
                [commentNode(1), commentNode(1)],
              ),
            },
          } as T;
        },
        snapshotMaxAttempts: 3,
        snapshotRetryBaseMs: 25,
        snapshotRetryMaxMs: 100,
        sleep: async () => undefined,
      }),
      /failed to stabilize after 3 attempts.*duplicate databaseId 1/,
    );
    assert.equal(duplicateCalls, 3);
  });

  it('fails closed when a terminal page count never matches totalCount', async () => {
    let calls = 0;
    await assert.rejects(
      __githubTest.listIssueCommentSnapshotsBatch([7], {
        request: async <T>(): Promise<T> => {
          calls++;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: commentIssue('2026-07-03T01:00:00Z', 2, [commentNode(1)]),
            },
          } as T;
        },
        snapshotMaxAttempts: 3,
        snapshotRetryBaseMs: 25,
        snapshotRetryMaxMs: 100,
        sleep: async () => undefined,
      }),
      /failed to stabilize after 3 attempts.*terminal unique count 1 did not match totalCount 2/,
    );
    assert.equal(calls, 3);
  });

  it('preserves listIssueCommentsBatch compatibility', async () => {
    let calls = 0;
    const comments = await __githubTest.listIssueCommentsBatch([7], {
      request: async <T>(): Promise<T> => {
        calls++;
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: commentIssue('2026-07-03T01:00:00Z', 1, [commentNode(1)]),
          },
        } as T;
      },
    });

    assert.equal(calls, 2);
    assert.deepEqual(comments.get(7)?.map((comment) => comment.id), [1]);
  });

  it('rejects stable issue-comment alias swaps before evidence attribution', async () => {
    await assert.rejects(
      __githubTest.listIssueCommentSnapshotsBatch([42, 43], {
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: commentIssue(
              '2026-07-03T01:00:00Z',
              1,
              [commentNode(43)],
              null,
              43,
            ),
            issue1: commentIssue(
              '2026-07-03T01:00:00Z',
              1,
              [commentNode(42)],
              null,
              42,
            ),
          },
        }) as T,
      }),
      /issue #42 comments returned issue #43 for requested issue #42/,
    );
  });

  it('keeps missing issue alias recovery explicit for comment snapshots', async () => {
    const missingError = new Error(
      'GitHub GraphQL error: NOT_FOUND repository.issue0 Could not resolve to an Issue with the number of 7.',
    );
    await assert.rejects(
      __githubTest.listIssueCommentSnapshotsBatch([7], {
        request: async () => {
          throw missingError;
        },
      }),
      missingError,
    );

    const missing: Array<{ issueNumber: number; aliasIndex: number }> = [];
    const comments = await __githubTest.listIssueCommentsBatch([7], {
      request: async () => {
        throw missingError;
      },
      onMissingIssueAlias: (event) => {
        missing.push(event);
      },
    });

    assert.deepEqual(missing, [{ issueNumber: 7, aliasIndex: 0 }]);
    assert.deepEqual(comments.get(7), []);
  });

  it('fails closed on repeated nested pagination cursors', async () => {
    let calls = 0;
    const request = async <T>(): Promise<T> => {
      calls++;
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: commentIssue(
            '2026-07-03T01:00:00Z',
            3,
            [commentNode(calls)],
            'cursor-1',
          ),
        },
      } as T;
    };

    await assert.rejects(
      __githubTest.listIssueCommentsBatch([7], {
        request,
        maxPagesPerConnection: 10,
        snapshotMaxAttempts: 3,
        snapshotRetryBaseMs: 25,
        snapshotRetryMaxMs: 100,
        sleep: async () => undefined,
      }),
      /failed to stabilize after 3 attempts.*repeated pagination cursor cursor-1/,
    );
    assert.equal(calls, 6);
  });

  it('fails closed when nested pagination exceeds its configured page limit', async () => {
    let calls = 0;
    const request = async <T>(): Promise<T> => {
      calls++;
      return {
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: commentIssue(
            '2026-07-03T01:00:00Z',
            3,
            [commentNode(calls)],
            `cursor-${calls}`,
          ),
        },
      } as T;
    };

    await assert.rejects(
      __githubTest.listIssueCommentsBatch([7], {
        request,
        maxPagesPerConnection: 2,
        snapshotMaxAttempts: 3,
        snapshotRetryBaseMs: 25,
        snapshotRetryMaxMs: 100,
        sleep: async () => undefined,
      }),
      /failed to stabilize after 3 attempts.*exceeded 2 pages before pagination completed/,
    );
    assert.equal(calls, 6);
  });

  it('builds one GraphQL query with aliased issue comment lookups', () => {
    const query = __githubTest.buildIssueCommentsBatchQuery(2);

    assert.match(query, /\$number0: Int!/);
    assert.match(query, /\$number1: Int!/);
    assert.match(query, /\$after0: String/);
    assert.match(query, /\$after1: String/);
    assert.match(query, /issue0: issue\(number: \$number0\)/);
    assert.match(query, /issue1: issue\(number: \$number1\)/);
    assert.match(query, /issue0: issue\(number: \$number0\) \{\s+id\s+__typename\s+number/);
    assertNodeBackedActorSelections(query, 'author', 4);
    assert.match(query, /comments\(first: \$first, after: \$after0, orderBy: \{field: UPDATED_AT, direction: ASC\}\)/);
    assert.match(query, /comments\([^)]*\) \{\s+totalCount/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(query, /databaseId\s+url/);
    assert.match(query, /authorAssociation/);
    assert.match(query, /updatedAt/);
  });

  it('maps issue comments with edit timestamps', () => {
    const comment = __githubTest.mapComment({
      id: 'COMMENT-node-42',
      __typename: 'IssueComment',
      databaseId: 42,
      url: 'https://github.com/openclaw/openclaw/issues/1#issuecomment-42',
      author: {
        id: 'ACTOR-clawsweeper',
        __typename: 'User',
        login: 'clawsweeper',
      },
      authorAssociation: 'CONTRIBUTOR',
      body: 'Close: current main and v2026.6.8 implement this behavior.',
      createdAt: '2026-06-07T15:44:06Z',
      updatedAt: '2026-06-19T15:29:09Z',
    });

    assert.deepEqual(comment, {
      id: 42,
      node_id: 'COMMENT-node-42',
      node_type: 'IssueComment',
      url: 'https://github.com/openclaw/openclaw/issues/1#issuecomment-42',
      user: {
        id: 'ACTOR-clawsweeper',
        type: 'User',
        login: 'clawsweeper',
      },
      author_association: 'CONTRIBUTOR',
      body: 'Close: current main and v2026.6.8 implement this behavior.',
      created_at: '2026-06-07T15:44:06Z',
      updated_at: '2026-06-19T15:29:09Z',
    });
  });

  it('builds one GraphQL query with aliased issue lookups by number', () => {
    const query = __githubTest.buildIssuesBatchQuery(2);

    assert.match(query, /\$number0: Int!/);
    assert.match(query, /\$number1: Int!/);
    assert.match(query, /issue0: issue\(number: \$number0\)/);
    assert.match(query, /issue1: issue\(number: \$number1\)/);
    assert.match(query, /body/);
    assertNodeBackedActorSelections(query, 'author', 2);
    assert.match(query, /authorAssociation/);
    assert.match(query, /labels\(first: 100\)/);
    assert.match(query, /labels\(first: 100\) \{\s+totalCount/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('paginates current issue labels', () => {
    const query = __githubTest.buildIssueLabelsQuery();

    assert.match(query, /\$after: String/);
    assert.match(query, /issue\(number: \$number\) \{\s+id\s+__typename\s+number\s+updatedAt/);
    assert.match(query, /labels\(first: 100, after: \$after\)/);
    assert.match(query, /labels\(first: 100, after: \$after\) \{\s+totalCount/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('builds one GraphQL query with aliased issue label timeline lookups', () => {
    const query = __githubTest.buildIssueLabelEventsBatchQuery(2);

    assert.match(query, /\$after0: String/);
    assert.match(query, /\$after1: String/);
    assert.match(query, /LABELED_EVENT/);
    assert.match(query, /UNLABELED_EVENT/);
    assert.match(query, /issue0: issue\(number: \$number0\)/);
    assert.match(query, /issue1: issue\(number: \$number1\)/);
    assert.match(query, /issue0: issue\(number: \$number0\) \{\s+id\s+__typename\s+number/);
    assert.match(query, /timelineItems\(first: 100, after: \$after0/);
    assert.match(query, /timelineItems\(first: 100, after: \$after0[^)]*\) \{\s+totalCount/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(query, /label \{ id name \}/);
    assertNodeBackedActorSelections(query, 'actor', 4);
    assert.match(
      query,
      /\.\.\. on LabeledEvent \{\s*id createdAt actor \{ __typename login \.\.\. on Node \{ id \} \}/,
    );
    assert.match(
      query,
      /\.\.\. on UnlabeledEvent \{\s*id createdAt actor \{ __typename login \.\.\. on Node \{ id \} \}/,
    );
  });

  it('builds an exhaustive repository collaborator permission query', () => {
    const query = __githubTest.buildRepositoryCollaboratorsQuery();

    assert.match(query, /collaborators\(first: \$first, after: \$after, affiliation: ALL\)/);
    assert.match(query, /repository\(owner: \$owner, name: \$repo\) \{\s+id/);
    assert.match(query, /totalCount/);
    assert.match(query, /edges \{\s+permission\s+node \{ id __typename login \}/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('bounds concurrent issue lookup chunks and preserves complete deterministic results', async () => {
    const expectedIssueNumbers = Array.from({ length: 51 }, (_, idx) => idx + 1);
    const controlled = gatedChunkRequest((_query, _variables, issueNumbers) => ({
      repository: Object.fromEntries(issueNumbers.map((issueNumber, idx) => [
        `issue${idx}`,
        issueLookupNode(issueNumber),
      ])),
    }));

    const pending = listIssuesBatch(
      [...expectedIssueNumbers, 1, 26],
      {
        batchConcurrency: 2,
        request: controlled.request,
      },
    );

    await waitFor(() => controlled.activeChunks() === 2);
    try {
      assert.deepEqual(controlled.startedChunks, [1, 26]);
    } finally {
      controlled.release();
    }

    const issues = await pending;
    assert.equal(controlled.maxActiveChunks(), 2);
    assert.deepEqual(controlled.startedChunks, [1, 26, 51]);
    assert.deepEqual([...issues.keys()], expectedIssueNumbers);
    assert.equal(new Set(issues.keys()).size, expectedIssueNumbers.length);
    assert.deepEqual(
      [...issues.values()].map((issue) => issue.labels[0]?.name),
      expectedIssueNumbers.map((issueNumber) => `label-${issueNumber}`),
    );
  });

  it('aborts active issue batch siblings, suppresses queued chunks, and preserves the primary error', async () => {
    const primaryError = new Error('primary issue chunk failure');
    const secondStarted = deferred();
    const startedChunks: number[] = [];
    let siblingAborted = false;
    let siblingSettled = false;
    const issueNumbers = Array.from({ length: 76 }, (_, index) => index + 1);

    const failure = await listIssuesBatch(issueNumbers, {
      batchConcurrency: 2,
      request: async <T>(
        _query: string,
        variables: Record<string, unknown> = {},
        signal?: AbortSignal,
      ): Promise<T> => {
        const chunkStart = aliasedIssueNumbers(variables)[0];
        assert.ok(chunkStart != null);
        startedChunks.push(chunkStart);
        if (chunkStart === 1) {
          await secondStarted.promise;
          throw primaryError;
        }
        assert.equal(chunkStart, 26);
        assert.ok(signal);
        secondStarted.resolve();
        return await new Promise<T>((_resolve, reject) => {
          const onAbort = () => {
            siblingAborted = true;
            setImmediate(() => {
              siblingSettled = true;
              reject(signal.reason);
            });
          };
          signal.addEventListener('abort', onAbort, { once: true });
          if (signal.aborted) onAbort();
        });
      },
    }).then(
      () => null,
      (error) => error,
    );

    assert.equal(failure, primaryError);
    assert.deepEqual(startedChunks, [1, 26]);
    assert.equal(siblingAborted, true);
    assert.equal(siblingSettled, true);
  });

  it('fails closed on null, partial, wrong-number, and duplicate-number issue aliases', async () => {
    const cases: Array<{
      name: string;
      issueNumbers: number[];
      repository: Record<string, unknown>;
      expected: RegExp;
    }> = [
      {
        name: 'null alias',
        issueNumbers: [42],
        repository: { issue0: null },
        expected: /returned null alias issue0 for requested issue #42/,
      },
      {
        name: 'partial alias set',
        issueNumbers: [42],
        repository: {},
        expected: /omitted alias issue0 for requested issue #42/,
      },
      {
        name: 'wrong issue number',
        issueNumbers: [42],
        repository: { issue0: issueLookupNode(43) },
        expected: /alias issue0 returned issue #43 for requested issue #42/,
      },
      {
        name: 'duplicate issue number',
        issueNumbers: [42, 43],
        repository: {
          issue0: issueLookupNode(42),
          issue1: issueLookupNode(42),
        },
        expected: /aliases issue0 and issue1 returned duplicate issue number #42/,
      },
    ];

    for (const testCase of cases) {
      await assert.rejects(
        listIssuesBatch(testCase.issueNumbers, {
          request: async <T>(): Promise<T> => ({
            repository: testCase.repository,
          }) as T,
        }),
        testCase.expected,
        testCase.name,
      );
    }
  });

  it('exhausts counted current-label connections and rejects incomplete or duplicate labels', async () => {
    const issue = issueLookupNode(42);
    issue.labels = {
      totalCount: 2,
      nodes: [{ name: 'bug' }],
      pageInfo: { hasNextPage: true, endCursor: 'labels-next' },
    };
    const issues = await listIssuesBatch([42], {
      request: async <T>(
        query: string,
        variables: Record<string, unknown> = {},
      ): Promise<T> => {
        if (query.includes('query IssuesByNumber')) {
          return { repository: { id: TEST_REPOSITORY_NODE_ID, issue0: issue } } as T;
        }
        const after = variables.after ?? null;
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue: {
              id: issue.id,
              __typename: issue.__typename,
              number: issue.number,
              updatedAt: issue.updatedAt,
              labels: {
                totalCount: 2,
                nodes: after == null
                  ? [{ name: 'bug' }]
                  : [{ name: 'impact:discord' }],
                pageInfo: after == null
                  ? { hasNextPage: true, endCursor: 'labels-next' }
                  : { hasNextPage: false, endCursor: null },
              },
            },
          },
        } as T;
      },
    });
    assert.deepEqual(issues.get(42)?.labels, [
      { name: 'bug' },
      { name: 'impact:discord' },
    ]);

    await assert.rejects(
      listIssuesBatch([42], {
        request: async <T>(): Promise<T> => {
          const truncated = issueLookupNode(42);
          truncated.labels = {
            totalCount: 2,
            nodes: [{ name: 'bug' }],
            pageInfo: { hasNextPage: false, endCursor: null },
          };
          return { repository: { id: TEST_REPOSITORY_NODE_ID, issue0: truncated } } as T;
        },
      }),
      /issue #42 labels terminal unique count 1 did not match totalCount 2/,
    );

    await assert.rejects(
      listIssuesBatch([42], {
        request: async <T>(): Promise<T> => {
          const duplicated = issueLookupNode(42);
          duplicated.labels = {
            totalCount: 2,
            nodes: [{ name: 'bug' }, { name: 'bug' }],
            pageInfo: { hasNextPage: false, endCursor: null },
          };
          return { repository: { id: TEST_REPOSITORY_NODE_ID, issue0: duplicated } } as T;
        },
      }),
      /issue #42 labels returned duplicate label bug/,
    );
  });

  it('covers exact 100 and 101 current-label connection boundaries', async () => {
    for (const totalCount of [100, 101]) {
      const labels = Array.from({ length: totalCount }, (_, index) => ({
        name: `label-${String(index + 1).padStart(3, '0')}`,
      }));
      const issue = issueLookupNode(42);
      issue.labels = {
        totalCount,
        nodes: labels.slice(0, 100),
        pageInfo: {
          hasNextPage: totalCount > 100,
          endCursor: totalCount > 100 ? 'labels-100' : null,
        },
      };
      const requests: Array<{ query: 'batch' | 'labels'; after: string | null }> = [];
      const issues = await listIssuesBatch([42], {
        request: async <T>(
          query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          if (query.includes('query IssuesByNumber')) {
            requests.push({ query: 'batch', after: null });
            return {
              repository: { id: TEST_REPOSITORY_NODE_ID, issue0: issue },
            } as T;
          }
          const after = (variables.after as string | null | undefined) ?? null;
          requests.push({ query: 'labels', after });
          assert.ok(after === null || after === 'labels-100');
          const start = after === null ? 0 : 100;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: {
                id: issue.id,
                __typename: issue.__typename,
                number: issue.number,
                updatedAt: issue.updatedAt,
                labels: {
                  totalCount,
                  nodes: labels.slice(start, start + 100),
                  pageInfo: {
                    hasNextPage: start + 100 < totalCount,
                    endCursor: start + 100 < totalCount ? 'labels-100' : null,
                  },
                },
              },
            },
          } as T;
        },
      });

      assert.deepEqual(
        requests,
        totalCount === 100
          ? [{ query: 'batch', after: null }]
          : [
              { query: 'batch', after: null },
              { query: 'labels', after: 'labels-100' },
              { query: 'labels', after: null },
              { query: 'labels', after: 'labels-100' },
            ],
      );
      assert.equal(issues.get(42)?.labels.length, totalCount);
      assert.equal(
        issues.get(42)?.labels.at(-1)?.name,
        `label-${String(totalCount).padStart(3, '0')}`,
      );
    }
  });

  it('rejects null nodes, count drift, and repeated cursors in current-label continuations', async () => {
    async function rejectContinuation(
      continuation: {
        totalCount: number;
        nodes: Array<{ name: string } | null>;
        pageInfo: { hasNextPage: boolean; endCursor: string | null };
      },
      expected: RegExp,
    ): Promise<void> {
      const issue = issueLookupNode(42);
      issue.labels = {
        totalCount: 2,
        nodes: [{ name: 'bug' }],
        pageInfo: { hasNextPage: true, endCursor: 'labels-next' },
      };
      await assert.rejects(
        listIssuesBatch([42], {
          request: async <T>(query: string): Promise<T> => (
            query.includes('query IssuesByNumber')
              ? { repository: { id: TEST_REPOSITORY_NODE_ID, issue0: issue } }
              : {
                  repository: {
                    id: TEST_REPOSITORY_NODE_ID,
                    issue: {
                      id: issue.id,
                      __typename: issue.__typename,
                      number: issue.number,
                      updatedAt: issue.updatedAt,
                      labels: continuation,
                    },
                  },
                }
          ) as T,
        }),
        expected,
      );
    }

    await rejectContinuation(
      {
        totalCount: 2,
        nodes: [null],
        pageInfo: { hasNextPage: false, endCursor: null },
      },
      /issue #42 labels connection returned null node at index 0/,
    );
    await rejectContinuation(
      {
        totalCount: 3,
        nodes: [{ name: 'impact:discord' }],
        pageInfo: { hasNextPage: false, endCursor: null },
      },
      /issue #42 labels totalCount changed within sweep from 2 to 3/,
    );
    await rejectContinuation(
      {
        totalCount: 2,
        nodes: [{ name: 'impact:discord' }],
        pageInfo: { hasNextPage: true, endCursor: 'labels-next' },
      },
      /issue #42 labels repeated pagination cursor labels-next/,
    );
  });

  it('fails closed on same-count current-label replacement across complete sweeps', async () => {
    const issue = issueLookupNode(42);
    issue.labels = {
      totalCount: 2,
      nodes: [{ name: 'bug' }],
      pageInfo: { hasNextPage: true, endCursor: 'initial-next' },
    };
    let labelCalls = 0;

    await assert.rejects(
      listIssuesBatch([42], {
        request: async <T>(
          query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          if (query.includes('query IssuesByNumber')) {
            return { repository: { id: TEST_REPOSITORY_NODE_ID, issue0: issue } } as T;
          }
          labelCalls++;
          const after = variables.after ?? null;
          const replacement = labelCalls === 3
            ? 'impact:security'
            : 'impact:discord';
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: {
                id: issue.id,
                __typename: issue.__typename,
                number: issue.number,
                updatedAt: issue.updatedAt,
                labels: {
                  totalCount: 2,
                  nodes: after == null
                    ? [{ name: 'bug' }]
                    : [{ name: replacement }],
                  pageInfo: after == null
                    ? { hasNextPage: true, endCursor: `sweep-${labelCalls}` }
                    : { hasNextPage: false, endCursor: null },
                },
              },
            },
          } as T;
        },
      }),
      /labels failed to stabilize identity and content after 3 complete sweeps/,
    );
    assert.equal(labelCalls, 5);
  });

  it('fails closed when issue updatedAt drifts during current-label pagination', async () => {
    const issue = issueLookupNode(42);
    issue.labels = {
      totalCount: 2,
      nodes: [{ name: 'bug' }],
      pageInfo: { hasNextPage: true, endCursor: 'labels-next' },
    };

    await assert.rejects(
      listIssuesBatch([42], {
        request: async <T>(query: string): Promise<T> => (
          query.includes('query IssuesByNumber')
            ? { repository: { id: TEST_REPOSITORY_NODE_ID, issue0: issue } }
            : {
                repository: {
                  id: TEST_REPOSITORY_NODE_ID,
                  issue: {
                    id: issue.id,
                    __typename: issue.__typename,
                    number: issue.number,
                    updatedAt: '2026-07-03T02:00:00Z',
                    labels: {
                      totalCount: 2,
                      nodes: [{ name: 'impact:discord' }],
                      pageInfo: { hasNextPage: false, endCursor: null },
                    },
                  },
                },
              }
        ) as T,
      }),
      /labels updatedAt drifted during pagination/,
    );
  });

  it('binds current-label continuation pages to the requested issue identity', async () => {
    const cases = [
      {
        continuationIssueNumber: 43,
        continuationIssueNodeId: 'ISSUE-node-43',
        expected: /issue #42 labels returned issue #43 for requested issue #42/,
      },
      {
        continuationIssueNumber: 42,
        continuationIssueNodeId: 'ISSUE-node-replaced-42',
        expected: /issue #42 labels issue identity drifted during pagination/,
      },
    ];

    for (const testCase of cases) {
      const issue = issueLookupNode(42);
      issue.labels = {
        totalCount: 2,
        nodes: [{ name: 'bug' }],
        pageInfo: { hasNextPage: true, endCursor: 'labels-next' },
      };

      await assert.rejects(
        listIssuesBatch([42], {
          request: async <T>(query: string): Promise<T> => (
            query.includes('query IssuesByNumber')
              ? { repository: { issue0: issue } }
              : {
                  repository: {
                    issue: {
                      id: testCase.continuationIssueNodeId,
                      __typename: 'Issue',
                      number: testCase.continuationIssueNumber,
                      updatedAt: issue.updatedAt,
                      labels: {
                        totalCount: 2,
                        nodes: [{ name: 'impact:discord' }],
                        pageInfo: { hasNextPage: false, endCursor: null },
                      },
                    },
                  },
                }
          ) as T,
        }),
        testCase.expected,
      );
    }
  });

  it('bounds concurrent label-event chunks without duplicate or missing events', async () => {
    const expectedIssueNumbers = Array.from({ length: 21 }, (_, idx) => idx + 1);
    const controlled = gatedChunkRequest((_query, _variables, issueNumbers) => ({
      repository: labelTimelineRepository(Object.fromEntries(
        issueNumbers.map((issueNumber, idx) => [
          `issue${idx}`,
          labelTimelineIssue(issueNumber, {
            totalCount: 1,
            nodes: [{
              __typename: 'LabeledEvent',
              id: `label-event-${issueNumber}`,
              createdAt: '2026-07-03T01:00:00Z',
              actor: {
                id: `ACTOR_${issueNumber}`,
                __typename: 'User',
                login: 'maintainer',
              },
              label: {
                id: `LABEL-node-${issueNumber}`,
                name: `label-${issueNumber}`,
              },
            }],
            pageInfo: { hasNextPage: false, endCursor: null },
          }),
        ]),
      )),
    }));

    const pending = listIssueLabelEventsBatch(
      [...expectedIssueNumbers, 1, 11],
      {
        batchConcurrency: 2,
        request: controlled.request,
      },
    );

    await waitFor(() => controlled.activeChunks() === 2);
    try {
      assert.deepEqual(controlled.startedChunks, [1, 11]);
    } finally {
      controlled.release();
    }

    const events = await pending;
    assert.equal(controlled.maxActiveChunks(), 2);
    assert.deepEqual(controlled.startedChunks, [1, 11, 21]);
    assert.deepEqual([...events.keys()], expectedIssueNumbers);
    assert.deepEqual(
      [...events.values()].flat().map((event) => event.eventId),
      expectedIssueNumbers.map((issueNumber) => `label-event-${issueNumber}`),
    );
  });

  it('rejects stable label-event alias swaps before evidence attribution', async () => {
    await assert.rejects(
      listIssueLabelEvidenceSnapshotsBatch([42, 43], {
        request: async <T>(): Promise<T> => ({
          repository: labelTimelineRepository({
            issue0: labelTimelineIssue(43, {
              totalCount: 1,
              nodes: [labelEvent('label-43')],
              pageInfo: { hasNextPage: false, endCursor: null },
            }),
            issue1: labelTimelineIssue(42, {
              totalCount: 1,
              nodes: [labelEvent('label-42')],
              pageInfo: { hasNextPage: false, endCursor: null },
            }),
          }),
        }) as T,
      }),
      /issue #42 label timeline returned issue #43 for requested issue #42/,
    );
  });

  it('exhausts and stabilizes counted label timelines across pages', async () => {
    const cursors: Array<string | null> = [];
    const events = await listIssueLabelEventsBatch([42], {
      request: async <T>(
        _query: string,
        variables: Record<string, unknown> = {},
      ): Promise<T> => {
        const after = (variables.after0 as string | null | undefined) ?? null;
        cursors.push(after);
        return {
          repository: labelTimelineRepository({
            issue0: labelTimelineIssue(
              42,
              after == null
                ? {
                    totalCount: 2,
                    nodes: [labelEvent('label-1')],
                    pageInfo: { hasNextPage: true, endCursor: 'label-next' },
                  }
                : {
                    totalCount: 2,
                    nodes: [labelEvent('label-2', {
                      type: 'UnlabeledEvent',
                      createdAt: '2026-07-03T02:00:00Z',
                    })],
                    pageInfo: { hasNextPage: false, endCursor: null },
                  },
            ),
          }),
        } as T;
      },
    });

    assert.deepEqual(cursors, [null, 'label-next', null, 'label-next']);
    assert.deepEqual(events.get(42)?.map((event) => [event.eventId, event.action]), [
      ['label-1', 'labeled'],
      ['label-2', 'unlabeled'],
    ]);
  });

  it('covers exact 100 and 101 label-timeline connection boundaries', async () => {
    for (const totalCount of [100, 101]) {
      const nodes = Array.from(
        { length: totalCount },
        (_, index) => labelEvent(`label-boundary-${index + 1}`),
      );
      const cursors: Array<string | null> = [];
      const snapshots = await listIssueLabelEvidenceSnapshotsBatch([42], {
        request: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          const after = (variables.after0 as string | null | undefined) ?? null;
          cursors.push(after);
          assert.ok(after === null || after === 'label-boundary-100');
          const start = after === null ? 0 : 100;
          return {
            repository: labelTimelineRepository({
              issue0: labelTimelineIssue(42, {
                totalCount,
                nodes: nodes.slice(start, start + 100),
                pageInfo: {
                  hasNextPage: start + 100 < totalCount,
                  endCursor: start + 100 < totalCount
                    ? 'label-boundary-100'
                    : null,
                },
              }),
            }),
          } as T;
        },
      });

      assert.deepEqual(
        cursors,
        totalCount === 100
          ? [null, null]
          : [null, 'label-boundary-100', null, 'label-boundary-100'],
      );
      assert.equal(snapshots.get(42)?.totalCount, totalCount);
      assert.equal(snapshots.get(42)?.fetchedCount, totalCount);
      assert.equal(snapshots.get(42)?.pageCount, totalCount === 100 ? 1 : 2);
      assert.equal(
        snapshots.get(42)?.events.at(-1)?.eventId,
        `label-boundary-${totalCount}`,
      );
    }
  });

  it('returns immutable label evidence metadata bound to repository and issue node identity', async () => {
    const snapshots = await listIssueLabelEvidenceSnapshotsBatch([42], {
      request: async <T>(): Promise<T> => ({
        repository: labelTimelineRepository({
          issue0: labelTimelineIssue(42, {
            totalCount: 1,
            nodes: [labelEvent('label-authority', {
              labelNodeId: 'LABEL-node-authority',
            })],
            pageInfo: { hasNextPage: false, endCursor: null },
          }),
        }),
      }) as T,
    });

    const snapshot = snapshots.get(42);
    assert.ok(snapshot);
    assert.equal(snapshot.schemaVersion, 2);
    assert.equal(snapshot.repositoryNodeId, 'REPO-node-openclaw');
    assert.equal(snapshot.issueNumber, 42);
    assert.equal(snapshot.issueNodeId, 'ISSUE-node-42');
    assert.equal(snapshot.issueNodeType, 'Issue');
    assert.equal(snapshot.issueUpdatedAt, '2026-07-03T03:00:00Z');
    assert.equal(snapshot.totalCount, 1);
    assert.equal(snapshot.fetchedCount, 1);
    assert.equal(snapshot.pageCount, 1);
    assert.equal(snapshot.sweepCount, 2);
    assert.equal(snapshot.stabilized, true);
    assert.ok(Number.isFinite(Date.parse(snapshot.capturedAt)));
    assert.deepEqual(snapshot.events.map((event) => ({
      issueNodeId: event.issueNodeId,
      labelNodeId: event.labelNodeId,
      actorNodeId: event.actorNodeId,
      actorType: event.actorType,
    })), [{
      issueNodeId: 'ISSUE-node-42',
      labelNodeId: 'LABEL-node-authority',
      actorNodeId: 'ACTOR_maintainer',
      actorType: 'User',
    }]);
  });

  it('retries label timelines when actor, timestamp, or action changes between sweeps', async () => {
    const mutations = [
      (node: ReturnType<typeof labelEvent>) => ({
        ...node,
        actor: {
          id: 'ACTOR_other',
          __typename: 'User',
          login: 'maintainer',
        },
      }),
      (node: ReturnType<typeof labelEvent>) => ({
        ...node,
        actor: {
          id: 'ACTOR_maintainer',
          __typename: 'User',
          login: 'other-maintainer',
        },
      }),
      (node: ReturnType<typeof labelEvent>) => ({
        ...node,
        actor: {
          id: 'ACTOR_maintainer',
          __typename: 'Bot',
          login: 'maintainer',
        },
      }),
      (node: ReturnType<typeof labelEvent>) => ({ ...node, createdAt: '2026-07-03T01:01:00Z' }),
      (node: ReturnType<typeof labelEvent>) => ({ ...node, __typename: 'UnlabeledEvent' }),
    ];
    for (const mutate of mutations) {
      let calls = 0;
      const delays: number[] = [];
      const events = await listIssueLabelEventsBatch([42], {
        snapshotMaxAttempts: 2,
        snapshotRetryBaseMs: 25,
        snapshotRetryMaxMs: 100,
        sleep: async (ms: number) => {
          delays.push(ms);
        },
        request: async <T>(): Promise<T> => {
          calls++;
          const baseline = labelEvent('label-stable');
          return {
            repository: labelTimelineRepository({
              issue0: labelTimelineIssue(42, {
                  totalCount: 1,
                  nodes: [calls === 2 ? mutate(baseline) : baseline],
                  pageInfo: { hasNextPage: false, endCursor: null },
              }),
            }),
          } as T;
        },
      });
      assert.equal(calls, 4);
      assert.deepEqual(delays, [25]);
      assert.equal(events.get(42)?.[0].actorNodeId, 'ACTOR_maintainer');
      assert.equal(events.get(42)?.[0].actorLogin, 'maintainer');
      assert.equal(events.get(42)?.[0].actorType, 'User');
      assert.equal(events.get(42)?.[0].action, 'labeled');
      assert.equal(events.get(42)?.[0].createdAt, '2026-07-03T01:00:00Z');
    }
  });

  it('retains label actor node IDs and fails closed on malformed actor identity', async () => {
    const events = await listIssueLabelEventsBatch([42], {
      request: async <T>(): Promise<T> => ({
        repository: labelTimelineRepository({
          issue0: labelTimelineIssue(42, {
              totalCount: 2,
              nodes: [
                labelEvent('label-with-actor'),
                labelEvent('label-without-actor', {
                  actorLogin: null,
                  type: 'UnlabeledEvent',
                }),
              ],
              pageInfo: { hasNextPage: false, endCursor: null },
          }),
        }),
      }) as T,
    });
    assert.deepEqual(
      events.get(42)?.map((event) => ({
        eventId: event.eventId,
        actorNodeId: event.actorNodeId,
        actorLogin: event.actorLogin,
        actorType: event.actorType,
      })),
      [
        {
          eventId: 'label-with-actor',
          actorNodeId: 'ACTOR_maintainer',
          actorLogin: 'maintainer',
          actorType: 'User',
        },
        {
          eventId: 'label-without-actor',
          actorNodeId: null,
          actorLogin: null,
          actorType: null,
        },
      ],
    );

    const malformedActors: Array<{ actor: unknown; expected: RegExp }> = [
      {
        actor: { __typename: 'User', login: 'maintainer' },
        expected: /actor node ID is missing or non-canonical/,
      },
      {
        actor: { id: ' ACTOR_maintainer', __typename: 'User', login: 'maintainer' },
        expected: /actor node ID is missing or non-canonical/,
      },
      {
        actor: { id: 42, __typename: 'User', login: 'maintainer' },
        expected: /actor node ID is missing or non-canonical/,
      },
      {
        actor: { id: 'ACTOR_maintainer', __typename: '', login: 'maintainer' },
        expected: /actor type is missing or non-canonical/,
      },
      {
        actor: { id: 'ACTOR_maintainer', __typename: 'User', login: ' maintainer' },
        expected: /actor login is missing or non-canonical/,
      },
    ];
    for (const { actor, expected } of malformedActors) {
      await assert.rejects(
        listIssueLabelEventsBatch([42], {
          request: async <T>(): Promise<T> => ({
            repository: labelTimelineRepository({
              issue0: labelTimelineIssue(42, {
                  totalCount: 1,
                  nodes: [{ ...labelEvent('malformed-actor'), actor }],
                  pageInfo: { hasNextPage: false, endCursor: null },
              }),
            }),
          }) as T,
        }),
        expected,
      );
    }
  });

  it('fails closed on malformed repository, issue, and label authority identities', async () => {
    const cases: Array<{
      repository: Record<string, unknown>;
      expected: RegExp;
    }> = [
      {
        repository: {
          issue0: labelTimelineIssue(42, {
            totalCount: 1,
            nodes: [labelEvent('label-missing-repository-id')],
            pageInfo: { hasNextPage: false, endCursor: null },
          }),
        },
        expected: /repository node ID is missing or non-canonical/,
      },
      {
        repository: labelTimelineRepository({
          issue0: labelTimelineIssue(42, {
            totalCount: 1,
            nodes: [labelEvent('label-missing-issue-id')],
            pageInfo: { hasNextPage: false, endCursor: null },
          }, { issueNodeId: '' }),
        }),
        expected: /issue node ID is missing or non-canonical/,
      },
      {
        repository: labelTimelineRepository({
          issue0: labelTimelineIssue(42, {
            totalCount: 1,
            nodes: [labelEvent('label-wrong-issue-type')],
            pageInfo: { hasNextPage: false, endCursor: null },
          }, { issueNodeType: 'PullRequest' }),
        }),
        expected: /unexpected issue node type PullRequest/,
      },
      {
        repository: labelTimelineRepository({
          issue0: labelTimelineIssue(42, {
            totalCount: 1,
            nodes: [labelEvent('label-invalid-issue-revision')],
            pageInfo: { hasNextPage: false, endCursor: null },
          }, { issueUpdatedAt: 'not-a-timestamp' }),
        }),
        expected: /returned invalid issue updatedAt/,
      },
      {
        repository: labelTimelineRepository({
          issue0: labelTimelineIssue(42, {
            totalCount: 1,
            nodes: [{
              ...labelEvent('label-missing-label-id'),
              label: { name: 'bug' },
            }],
            pageInfo: { hasNextPage: false, endCursor: null },
          }),
        }),
        expected: /label node ID is missing or non-canonical/,
      },
    ];

    for (const { repository, expected } of cases) {
      await assert.rejects(
        listIssueLabelEvidenceSnapshotsBatch([42], {
          request: async <T>(): Promise<T> => ({ repository }) as T,
        }),
        expected,
      );
    }
  });

  it('rejects malformed, duplicate, truncated, and cursor-unstable label timelines', async () => {
    await assert.rejects(
      listIssueLabelEventsBatch([42], {
        snapshotMaxAttempts: 1,
        request: async <T>(): Promise<T> => ({
          repository: labelTimelineRepository({
            issue0: labelTimelineIssue(42, {
                totalCount: 2,
                nodes: [labelEvent('label-1')],
                pageInfo: { hasNextPage: false, endCursor: null },
            }),
          }),
        }) as T,
      }),
      /terminal unique count 1 did not match totalCount 2/,
    );

    await assert.rejects(
      listIssueLabelEventsBatch([42], {
        request: async <T>(): Promise<T> => ({
          repository: labelTimelineRepository({
            issue0: labelTimelineIssue(42, {
                totalCount: 2,
                nodes: [labelEvent('label-1'), labelEvent('label-1')],
                pageInfo: { hasNextPage: false, endCursor: null },
            }),
          }),
        }) as T,
      }),
      /label timeline returned duplicate event ID label-1/,
    );

    await assert.rejects(
      listIssueLabelEventsBatch([42], {
        request: async <T>(): Promise<T> => ({
          repository: labelTimelineRepository({
            issue0: labelTimelineIssue(42, {
                totalCount: 1,
                nodes: [null],
                pageInfo: { hasNextPage: false, endCursor: null },
            }),
          }),
        }) as T,
      }),
      /label timeline connection returned null node at index 0/,
    );

    await assert.rejects(
      listIssueLabelEventsBatch([42], {
        snapshotMaxAttempts: 1,
        request: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          const after = (variables.after0 as string | null | undefined) ?? null;
          return {
            repository: labelTimelineRepository({
              issue0: labelTimelineIssue(
                42,
                after == null
                  ? {
                      totalCount: 2,
                      nodes: [labelEvent('label-1')],
                      pageInfo: { hasNextPage: true, endCursor: 'label-next' },
                    }
                  : {
                      totalCount: 3,
                      nodes: [labelEvent('label-2')],
                      pageInfo: { hasNextPage: false, endCursor: null },
                    },
              ),
            }),
          } as T;
        },
      }),
      /label timeline totalCount changed within sweep from 2 to 3/,
    );

    await assert.rejects(
      listIssueLabelEventsBatch([42], {
        request: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          const after = (variables.after0 as string | null | undefined) ?? null;
          return {
            repository: labelTimelineRepository({
              issue0: labelTimelineIssue(42, {
                  totalCount: 2,
                  nodes: [labelEvent(after == null ? 'label-1' : 'label-2')],
                  pageInfo: { hasNextPage: true, endCursor: 'label-next' },
              }),
            }),
          } as T;
        },
      }),
      /label timeline repeated pagination cursor label-next/,
    );
  });

  it('rejects duplicate label event IDs across issues before persistence', async () => {
    await assert.rejects(
      listIssueLabelEventsBatch([42, 43], {
        request: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          const issueNumbers = aliasedIssueNumbers(variables);
          return {
            repository: labelTimelineRepository(Object.fromEntries(
              issueNumbers.map((issueNumber, idx) => [
                `issue${idx}`,
                labelTimelineIssue(issueNumber, {
                  totalCount: 1,
                  nodes: [labelEvent('duplicate-global-label-event', {
                    labelName: `label-${issueNumber}`,
                  })],
                  pageInfo: { hasNextPage: false, endCursor: null },
                }),
              ]),
            )),
          } as T;
        },
      }),
      /duplicate event ID duplicate-global-label-event for issues #42 and #43/,
    );
  });

  it('keeps missing label-event aliases isolated during concurrent chunk recovery', async () => {
    const expectedIssueNumbers = Array.from({ length: 21 }, (_, idx) => idx + 1);
    const missing: Array<{ issueNumber: number; aliasIndex: number }> = [];
    let reportedMissing = false;

    const events = await listIssueLabelEventsBatch(expectedIssueNumbers, {
      batchConcurrency: 2,
      onMissingIssueAlias: (event) => missing.push(event),
      request: async <T>(
        _query: string,
        variables: Record<string, unknown> = {},
      ): Promise<T> => {
        const issueNumbers = aliasedIssueNumbers(variables);
        if (!reportedMissing && issueNumbers.includes(12)) {
          reportedMissing = true;
          throw new Error(
            'GitHub GraphQL error: NOT_FOUND repository.issue1 Could not resolve to an Issue with the number of 12.',
          );
        }
        return {
          repository: labelTimelineRepository(Object.fromEntries(
            issueNumbers.map((issueNumber, idx) => [
              `issue${idx}`,
              labelTimelineIssue(issueNumber, {
                totalCount: 1,
                nodes: [{
                  __typename: 'LabeledEvent',
                  id: `label-event-${issueNumber}`,
                  createdAt: '2026-07-03T01:00:00Z',
                  actor: {
                    id: `ACTOR_${issueNumber}`,
                    __typename: 'User',
                    login: 'maintainer',
                  },
                  label: {
                    id: `LABEL-node-${issueNumber}`,
                    name: `label-${issueNumber}`,
                  },
                }],
                pageInfo: { hasNextPage: false, endCursor: null },
              }),
            ]),
          )),
        } as T;
      },
    });

    assert.deepEqual(missing, [{ issueNumber: 12, aliasIndex: 1 }]);
    assert.deepEqual([...events.keys()], expectedIssueNumbers);
    assert.deepEqual(events.get(12), []);
    assert.equal(
      [...events.entries()].every(([issueNumber, issueEvents]) => (
        issueNumber === 12
          ? issueEvents.length === 0
          : issueEvents.length === 1 && issueEvents[0].eventId === `label-event-${issueNumber}`
      )),
      true,
    );
  });

  it('paginates and stabilizes exhaustive repository collaborator permissions', async () => {
    const cursors: Array<string | null> = [];
    const snapshot = await fetchRepositoryCollaboratorPermissionSnapshot({
      now: () => Date.parse('2026-07-04T18:00:00Z'),
      request: async <T>(
        _query: string,
        variables: Record<string, unknown> = {},
      ): Promise<T> => {
        const after = (variables.after as string | null | undefined) ?? null;
        cursors.push(after);
        return {
          repository: {
            id: 'REPO-node-openclaw',
            collaborators: after == null
              ? {
                  totalCount: 2,
                  edges: [{
                    permission: 'MAINTAIN',
                    node: {
                      id: 'ACTOR-alice',
                      __typename: 'User',
                      login: 'Alice',
                    },
                  }],
                  pageInfo: { hasNextPage: true, endCursor: 'collaborator-next' },
                }
              : {
                  totalCount: 2,
                  edges: [{
                    permission: 'READ',
                    node: {
                      id: 'ACTOR-zed',
                      __typename: 'User',
                      login: 'Zed',
                    },
                  }],
                  pageInfo: { hasNextPage: false, endCursor: null },
                },
          },
        } as T;
      },
    });

    assert.deepEqual(cursors, [
      null,
      'collaborator-next',
      null,
      'collaborator-next',
    ]);
    assert.equal(snapshot.exhaustive, true);
    assert.equal(snapshot.complete, true);
    assert.equal(snapshot.totalCount, 2);
    assert.equal(snapshot.rowCount, 2);
    assert.equal(snapshot.pageCount, 2);
    assert.equal(snapshot.pagesFetched, 4);
    assert.equal(snapshot.sweepCount, 2);
    assert.equal(snapshot.observedAt, '2026-07-04T18:00:00.000Z');
    assert.equal(snapshot.repositoryNodeId, 'REPO-node-openclaw');
    assert.deepEqual(
      snapshot.rows.map((row) => [row.nodeId, row.login, row.actorType, row.permission]),
      [
        ['ACTOR-alice', 'alice', 'User', 'maintain'],
        ['ACTOR-zed', 'zed', 'User', 'read'],
      ],
    );
    assert.match(snapshot.contentDigest, /^[0-9a-f]{64}$/);
    assert.match(snapshot.sourceIdentity, /^github-graphql:repository\.collaborators:v2:/);
  });

  it('fails closed on collaborator count, edge, cursor, permission, and stability hazards', async () => {
    await assert.rejects(
      fetchRepositoryCollaboratorPermissionSnapshot({
        request: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => ({
          repository: {
            id: 'REPO-node-openclaw',
            collaborators: variables.after == null
              ? {
                  totalCount: 2,
                  edges: [{
                    permission: 'MAINTAIN',
                    node: {
                      id: 'ACTOR-alice',
                      __typename: 'User',
                      login: 'alice',
                    },
                  }],
                  pageInfo: { hasNextPage: true, endCursor: 'next' },
                }
              : {
                  totalCount: 3,
                  edges: [{
                    permission: 'READ',
                    node: {
                      id: 'ACTOR-zed',
                      __typename: 'User',
                      login: 'zed',
                    },
                  }],
                  pageInfo: { hasNextPage: false, endCursor: null },
                },
          },
        }) as T,
      }),
      /totalCount changed within sweep from 2 to 3/,
    );
    await assert.rejects(
      fetchRepositoryCollaboratorPermissionSnapshot({
        request: async <T>(): Promise<T> => ({
          repository: {
            id: 'REPO-node-openclaw',
            collaborators: {
              totalCount: 1,
              edges: [null],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        }) as T,
      }),
      /returned null edge/,
    );
    await assert.rejects(
      fetchRepositoryCollaboratorPermissionSnapshot({
        maxPagesPerConnection: 1,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: 'REPO-node-openclaw',
            collaborators: {
              totalCount: 2,
              edges: [{
                permission: 'READ',
                node: {
                  id: 'ACTOR-alice',
                  __typename: 'User',
                  login: 'alice',
                },
              }],
              pageInfo: { hasNextPage: true, endCursor: 'next' },
            },
          },
        }) as T,
      }),
      /exceeded 1 pages before pagination completed/,
    );
    await assert.rejects(
      fetchRepositoryCollaboratorPermissionSnapshot({
        request: async <T>(): Promise<T> => ({
          repository: {
            id: 'REPO-node-openclaw',
            collaborators: {
              totalCount: 1,
              edges: [{
                permission: 'OWNER',
                node: {
                  id: 'ACTOR-alice',
                  __typename: 'User',
                  login: 'alice',
                },
              }],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        }) as T,
      }),
      /Unsupported repository collaborator permission owner/,
    );

    let sweep = 0;
    await assert.rejects(
      fetchRepositoryCollaboratorPermissionSnapshot({
        maxSweeps: 3,
        request: async <T>(): Promise<T> => {
          sweep++;
          return {
            repository: {
              id: 'REPO-node-openclaw',
              collaborators: {
                totalCount: 1,
                edges: [{
                  permission: sweep % 2 === 0 ? 'READ' : 'MAINTAIN',
                  node: {
                    id: 'ACTOR-alice',
                    __typename: 'User',
                    login: 'alice',
                  },
                }],
                pageInfo: { hasNextPage: false, endCursor: null },
              },
            },
          } as T;
        },
      }),
      /failed to stabilize after 3 complete sweeps/,
    );
  });

  it('bounds concurrent stable comment sweeps without duplicate or missing snapshots', async () => {
    const expectedIssueNumbers = Array.from({ length: 51 }, (_, idx) => idx + 1);
    const controlled = gatedChunkRequest((_query, _variables, issueNumbers) => ({
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        ...Object.fromEntries(issueNumbers.map((issueNumber, idx) => [
          `issue${idx}`,
          commentIssue(
            '2026-07-03T01:00:00Z',
            1,
            [commentNode(issueNumber)],
            null,
            issueNumber,
          ),
        ])),
      },
    }));

    const pending = __githubTest.listIssueCommentSnapshotsBatch(
      [...expectedIssueNumbers, 1, 26],
      {
        batchConcurrency: 2,
        request: controlled.request,
      },
    );

    await waitFor(() => controlled.activeChunks() === 2);
    try {
      assert.deepEqual(controlled.startedChunks, [1, 26]);
    } finally {
      controlled.release();
    }

    const snapshots = await pending;
    assert.equal(controlled.maxActiveChunks(), 2);
    assert.deepEqual(controlled.startedChunks, [1, 26, 51]);
    assert.deepEqual([...snapshots.keys()], expectedIssueNumbers);
    assert.deepEqual(
      [...snapshots.values()].map((snapshot) => snapshot.comments[0]?.id),
      expectedIssueNumbers,
    );
    assert.equal(
      new Set([...snapshots.values()].map((snapshot) => snapshot.commentsDigest)).size,
      expectedIssueNumbers.length,
    );
  });

  it('bounds concurrent fix-evidence chunks while preserving verified state snapshots', async () => {
    const expectedIssueNumbers = Array.from({ length: 21 }, (_, idx) => idx + 1);
    const controlled = gatedChunkRequest((_query, _variables, issueNumbers) => ({
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        ...Object.fromEntries(issueNumbers.map((issueNumber, idx) => [
          `issue${idx}`,
          fixEvidenceIssue({
            issueNumber,
            state: 'OPEN',
            updatedAt: `2026-07-03T01:${String(issueNumber).padStart(2, '0')}:00Z`,
            totalCount: 0,
          }),
        ])),
      },
    }));

    const pending = listIssueFixEvidenceBatch(
      [...expectedIssueNumbers, 1, 11],
      {
        batchConcurrency: 2,
        request: controlled.request,
      },
    );

    await waitFor(() => controlled.activeChunks() === 2);
    try {
      assert.deepEqual(controlled.startedChunks, [1, 11]);
    } finally {
      controlled.release();
    }

    const evidence = await pending;
    assert.equal(controlled.maxActiveChunks(), 2);
    assert.deepEqual(controlled.startedChunks, [1, 11, 21]);
    assert.deepEqual([...evidence.keys()], expectedIssueNumbers);
    assert.deepEqual(
      [...evidence.values()].map((item) => item.stateSnapshot.issueNumber),
      expectedIssueNumbers,
    );
    assert.equal(
      [...evidence.values()].every((item) => (
        item.stateSnapshot.issueState === 'open' &&
        item.stateSnapshot.totalCount === 0 &&
        item.stateSnapshot.fetchedCount === 0 &&
        item.stateSnapshot.sweepCount === 2 &&
        item.stateSnapshot.stabilized === true
      )),
      true,
    );
  });

  it('extracts closure-comment PR evidence without trusting bare issue refs', () => {
    const mentions = __githubTest.closureCommentPrMentions(9000, canonicalClosureProofComments([
      {
        body: 'I found the merged PR that appears to have closed this: [#95532: fix path](https://api.github.com/repos/openclaw/openclaw/pulls/95532).',
        created_at: '2026-06-24T10:00:00Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'See also #12345 and issue #95532 for context; neither line says this is a PR.',
        created_at: '2026-06-24T11:00:00Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'The release note points at https://github.com/openclaw/openclaw/pull/96025.',
        created_at: '2026-06-24T12:00:00Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'The merged PR #96040 fixes this report.',
        created_at: '2026-06-24T13:00:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'I found the merged PR that appears to have closed this: #87998. This does not need to stay open separately.',
        created_at: '2026-06-24T14:00:00Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'This is fixed on `main` by #95900 / 2aa9d676356455102fe4189e5e5d470c06eead94. Closing as fixed on main; users on 2026.6.10 will pick this up with the next release.',
        created_at: '2026-06-25T15:05:01Z',
        user: { login: 'obviyus' },
        author_association: 'MEMBER',
      },
      {
        body: 'Fixed on current main, primarily by #88630 (`b4cdd9211957875df0d301ccc40e2935ba26829f`, merged June 10, 2026).',
        created_at: '2026-06-25T15:06:01Z',
        user: { login: 'steipete' },
        author_association: 'MEMBER',
      },
      {
        body: 'Marking this fixed by the linked upstream patch. Canonical PR: #85475.',
        created_at: '2026-06-25T15:07:01Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
    ]), {
      finalClosureActors: ['clawsweeper'],
      finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
    });

    assert.deepEqual(mentions, [
      {
        issueNumber: 9000,
        prNumber: 85475,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-25T15:07:01Z',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 87998,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-24T14:00:00Z',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 88630,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-25T15:06:01Z',
        author: 'steipete',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 95532,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-24T10:00:00Z',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 95900,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-25T15:05:01Z',
        author: 'obviyus',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 96040,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-24T13:00:00Z',
        author: 'maintainer',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
    ]);
  });

  it('extracts trusted canonical PR context without marking it fix proof', () => {
    const mentions = __githubTest.closureCommentPrMentions(97322, canonicalClosureProofComments([
      {
        body: 'Close as superseded: this is tracked in the active continuation work. Canonical path: Open PR https://github.com/openclaw/openclaw/pull/85651 owns this feature work.',
        created_at: '2026-06-27T20:23:27Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'Maybe the release note points at https://github.com/openclaw/openclaw/pull/85652.',
        created_at: '2026-06-27T20:24:27Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
    ]), {
      finalClosureActors: ['clawsweeper'],
      finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
    });

    assert.deepEqual(mentions, [{
      issueNumber: 97322,
      prNumber: 85651,
      prRepositoryOwner: 'openclaw',
      prRepositoryName: 'openclaw',
      prRepositoryNameWithOwner: 'openclaw/openclaw',
      source: 'ClosureComment.prMention',
      referencedAt: '2026-06-27T20:23:27Z',
      author: 'clawsweeper',
      authorAssociation: 'CONTRIBUTOR',
      trustedSource: true,
    }]);
  });

  it('preserves repository identity from trusted cross-repo PR URLs', () => {
    const mentions = __githubTest.closureCommentPrMentions(101, [
      canonicalClosureProofComment({
      body: 'Close as superseded: Canonical path: Open PR https://github.com/openclaw/clownfish/pull/147 owns the external adapter work.',
      created_at: '2026-06-27T20:23:27Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
      }),
    ], {
      finalClosureActors: ['clawsweeper'],
      finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
    });

    assert.deepEqual(mentions, [{
      issueNumber: 101,
      prNumber: 147,
      prRepositoryOwner: 'openclaw',
      prRepositoryName: 'clownfish',
      prRepositoryNameWithOwner: 'openclaw/clownfish',
      source: 'ClosureComment.prMention',
      referencedAt: '2026-06-27T20:23:27Z',
      author: 'clawsweeper',
      authorAssociation: 'CONTRIBUTOR',
      trustedSource: true,
    }]);
  });

  it('orders immutable PR evidence by binary repository identity', () => {
    const mentions = __githubTest.closureCommentPrMentions(101, [
      canonicalClosureProofComment({
        body:
          'Close as superseded: Canonical path: Open PR ' +
          'https://github.com/openclaw/a_b/pull/3, ' +
          'https://github.com/openclaw/a.b/pull/2, and ' +
          'https://github.com/openclaw/a-b/pull/1 own the work.',
        created_at: '2026-06-27T20:23:27Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      }),
    ], {
      finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
    });

    assert.deepEqual(
      mentions.map((mention) => mention.prRepositoryNameWithOwner),
      [
        'openclaw/a-b',
        'openclaw/a.b',
        'openclaw/a_b',
      ],
    );
  });

  it('canonicalizes PR repository casing and fails closed on malformed or conflicting identities', () => {
    assert.deepEqual(
      __githubTest.normalizePrRepositoryIdentity({
        owner: 'OpenClaw',
        name: 'ClownFish',
        nameWithOwner: 'OPENCLAW/CLOWNFISH',
        url: 'https://github.com/openclaw/clownfish/pull/147',
      }),
      {
        owner: 'openclaw',
        name: 'clownfish',
        nameWithOwner: 'openclaw/clownfish',
      },
    );
    assert.equal(pullRequestKey('OpenClaw/ClownFish', 147), 'openclaw/clownfish#147');

    const mapped = __githubTest.mapPullRequestFix({
      number: 147,
      title: 'External fix',
      url: 'https://github.com/OpenClaw/ClownFish/pull/147',
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-07-03T03:00:00Z',
      baseRefName: 'main',
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        name: 'ClownFish',
        nameWithOwner: 'OPENCLAW/CLOWNFISH',
        url: 'https://github.com/OpenClaw/ClownFish',
        owner: { login: 'OpenClaw' },
      },
      mergeCommit: { oid: 'a'.repeat(40) },
    });
    assert.equal(mapped.repositoryNameWithOwner, 'openclaw/clownfish');

    assert.throws(
      () => __githubTest.normalizePrRepositoryIdentity({ nameWithOwner: 'external-repo' }),
      /must contain one owner\/name pair/,
    );
    assert.throws(
      () => __githubTest.normalizePrRepositoryIdentity({
        owner: 'openclaw',
        name: 'clownfish',
        nameWithOwner: 'other/repo',
      }),
      /repository identity mismatch/,
    );
    assert.throws(
      () => __githubTest.mapPullRequestFix({
        number: 147,
        url: 'https://github.com/openclaw/clownfish/issues/147',
        repository: null,
      }),
      /does not contain a canonical GitHub repository identity/,
    );
  });

  it('extracts closure-comment commit proof without trusting incidental hashes', () => {
    const mentions = __githubTest.closureCommentCommitMentions(97222, canonicalClosureProofComments([
      {
        body: 'Fix provenance: Commit `cfeaf6897fd89201b71ff7d5285e48c5a382ac9a` is titled `fix(cron): clear payload model overrides`. Release provenance: v2026.6.10 contains the same behavior.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'Codex review notes: reviewed against c5d34c8376f8aa32744786cae0473c60e39ef444.',
        created_at: '2026-06-27T09:05:25Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'Fixed by commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.',
        created_at: '2026-06-27T09:06:25Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'Fixed on main in https://github.com/openclaw/openclaw/commit/dfb44912ed285a0163c576c727632d00cfdf39f3.',
        created_at: '2026-06-27T09:07:25Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'This traces the root cause to https://github.com/openclaw/openclaw/commit/ab0a633ab98b4676370eec31eee57d2fbe163647.',
        created_at: '2026-06-27T09:08:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
    ]), 97222, undefined, {
      finalClosureActors: ['clawsweeper'],
      finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
    });

    assert.deepEqual(mentions, [
      {
        issueNumber: 97222,
        commitOid: 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
        referencedAt: '2026-06-27T09:04:25Z',
        sourceIssueNumber: 97222,
        snippet: 'Fix provenance: Commit `cfeaf6897fd89201b71ff7d5285e48c5a382ac9a` is titled `fix(cron): clear payload model overrides`. Release provenance: v2026.6.10 contains the same behavior.',
        source: 'ClosureComment.fixProof',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 97222,
        commitOid: 'dfb44912ed285a0163c576c727632d00cfdf39f3',
        referencedAt: '2026-06-27T09:07:25Z',
        sourceIssueNumber: 97222,
        snippet: 'Fixed on main in https://github.com/openclaw/openclaw/commit/dfb44912ed285a0163c576c727632d00cfdf39f3.',
        source: 'ClosureComment.fixProof',
        author: 'maintainer',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
    ]);
  });

  it('limits long review proof to explicitly selected PR and fix commit lines', () => {
    const selectedCommit = 'd45b8be939a15c94e0c1286c2eff5660fc8320e6';
    const historicalCommit = '95e37f8e9517772ffd7448ebc3a874b7c66197ab';
    const releaseCommit = 'e085fa1a3ffd32d0ea6917e1e6fb4ecbffbb77d2';
    const body = [
      'Current main fixes this report, but the fix is current-main-only and not proven shipped.',
      'I found the merged PR that appears to have closed this: [#98955](https://api.github.com/repos/openclaw/openclaw/pulls/98955).',
      '',
      '<details>',
      `- Historical context: PR #96218 introduced commit ${historicalCommit}.`,
      `- Release provenance: v2026.6.11 commit ${releaseCommit}.`,
      `- Fix commit provenance: The fix commit is ${selectedCommit}.`,
      '</details>',
    ].join('\n');
    const comment = canonicalClosureProofComment({
      body,
      created_at: '2026-07-03T11:00:00Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
    });

    assert.deepEqual(
      __githubTest.closureCommentPrMentions(
        98528,
        [comment],
        {
          finalClosureActors: ['clawsweeper'],
          finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
        },
      ).map((item) => item.prNumber),
      [98955],
    );
    assert.deepEqual(
      __githubTest.closureCommentCommitMentions(
        98528,
        [comment],
        98528,
        undefined,
        {
          finalClosureActors: ['clawsweeper'],
          finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
        },
      ).map((item) => item.commitOid),
      [selectedCommit],
    );
  });

  it('does not treat release-provenance commit links as fix commits', () => {
    const releaseCommit = 'aa69b12d0086b631b139c1435c9621a5783e3a40';
    const actualFix = 'eb00d499d16feea600fceef92d575fa30f005649';
    const comment = canonicalClosureProofComment({
      body: [
        'Current main fixes this report, but the fix is not in the latest release.',
        `- Fix provenance: commit [${actualFix}](https://github.com/openclaw/openclaw/commit/${actualFix}) removes the broken path.`,
        `- Release provenance: v2026.6.10 still has the old behavior at [${releaseCommit}](https://github.com/openclaw/openclaw/commit/${releaseCommit}).`,
      ].join('\n'),
      created_at: '2026-06-30T13:30:57Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
    });

    assert.deepEqual(
      __githubTest.closureCommentCommitMentions(
        89589,
        [comment],
        89589,
        undefined,
        {
          finalClosureActors: ['clawsweeper'],
          finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
        },
      ).map((item) => item.commitOid),
      [actualFix],
    );
  });

  it('fails closed for negated, introduced-by, caused-by, root-cause, and regression references', () => {
    const negativeComments = canonicalClosureProofComments([
      'This is not a fix: the merged PR #91001 does not fix this report.',
      'This is not the actual fix: PR #91007 never fixed the report.',
      "PR #91008 isn't a fix and commit 7777777777777777777777777777777777777777 wasn't fixed proof.",
      'PR #91002 introduced the regression; commit 1111111111111111111111111111111111111111 caused it.',
      'The root cause is https://github.com/openclaw/openclaw/commit/2222222222222222222222222222222222222222.',
      'This was caused by PR #91003 and is not fixed by commit 3333333333333333333333333333333333333333.',
      'Fix provenance: commit 4444444444444444444444444444444444444444 is not a fix; it introduced the regression.',
      'The merged PR #91004 caused this regression, not fixed it.',
    ].map((body) => ({
      body,
      created_at: '2026-07-03T12:00:00Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
    })));

    for (const comment of negativeComments) {
      assert.deepEqual(__githubTest.closureCommentPrMentions(98528, [comment]), [], comment.body);
      assert.deepEqual(__githubTest.closureCommentCommitMentions(98528, [comment]), [], comment.body);
    }

    const selectedCommit = '5555555555555555555555555555555555555555';
    const mixedComment = canonicalClosureProofComment({
      body: [
        'Root cause: PR #91005 introduced this regression in commit 6666666666666666666666666666666666666666.',
        'Fixed by PR #91006.',
        `Fixed by commit ${selectedCommit}.`,
      ].join('\n'),
      created_at: '2026-07-03T12:05:00Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
    });

    assert.deepEqual(
      __githubTest.closureCommentPrMentions(
        98528,
        [mixedComment],
        {
          finalClosureActors: ['clawsweeper'],
          finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
        },
      ).map((item) => item.prNumber),
      [91006],
    );
    assert.deepEqual(
      __githubTest.closureCommentCommitMentions(
        98528,
        [mixedComment],
        98528,
        undefined,
        {
          finalClosureActors: ['clawsweeper'],
          finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
        },
      ).map((item) => item.commitOid),
      [selectedCommit],
    );
  });

  it('preserves exact source comment anchors for PR and commit proof', () => {
    const prComment = canonicalClosureProofComment({
      id: 123456,
      url: 'https://github.com/openclaw/openclaw/issues/97222#issuecomment-123456',
      body: 'The merged PR #95532 fixes this report.',
      created_at: '2026-06-27T09:04:25Z',
      user: { login: 'maintainer' },
      author_association: 'MEMBER',
    });
    const commitComment = {
      ...prComment,
      body: 'Fixed on main by commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a.',
    };
    const pr = __githubTest.closureCommentPrMentions(97222, [prComment])[0];
    const commit = __githubTest.closureCommentCommitMentions(97222, [commitComment])[0];

    assert.equal(pr.sourceCommentDatabaseId, 123456);
    assert.equal(pr.sourceCommentUrl, prComment.url);
    assert.equal(commit.sourceCommentDatabaseId, 123456);
    assert.equal(commit.sourceCommentUrl, commitComment.url);
  });

  it('does not extract fix proof from keep-open review comments', () => {
    const comments = canonicalClosureProofComments([{
      body: 'Codex review: keeping this open for maintainer follow-up. Keep open: current main and v2026.6.6 still lack the requested guard. Release provenance: v2026.6.6 commit 8c802aa683510c7f7503597b54c3021733245e59 is not sufficient.',
      created_at: '2026-06-15T16:31:00Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
    }]);

    assert.deepEqual(__githubTest.closureCommentCommitMentions(92315, comments), []);
    assert.deepEqual(__githubTest.closureCommentPrMentions(92315, comments), []);
  });

  it('keeps mixed-subject keep-open wording scoped to the current issue', () => {
    const distinctReportsRemainOpen = canonicalClosureProofComment({
      body: 'The merged PR #99731 fixes this issue; distinct package-parity reports remain open separately.',
      created_at: '2026-07-04T02:20:00Z',
      user: { login: 'maintainer' },
      author_association: 'MEMBER',
    });
    const currentIssueRemainsOpen = {
      ...distinctReportsRemainOpen,
      body: 'The merged PR #99731 may fix this issue, but keep this issue open while distinct package-parity reports remain open separately.',
    };

    assert.deepEqual(
      __githubTest.closureCommentPrMentions(
        99730,
        [distinctReportsRemainOpen],
      ).map((item) => item.prNumber),
      [99731],
    );
    assert.deepEqual(
      __githubTest.closureCommentPrMentions(99730, [currentIssueRemainsOpen]),
      [],
    );
  });

  it('trusts contributor PR and commit proof only for the selected final closer', () => {
    const commitOid = 'c'.repeat(40);
    const prComment = canonicalClosureProofComment({
      body: 'The merged PR #99731 fixes this issue.',
      created_at: '2026-07-04T02:20:00Z',
      user: { login: 'contributor-closer' },
      author_association: 'CONTRIBUTOR',
    });
    const commitComment = {
      ...prComment,
      body: `Fixed by commit ${commitOid}.`,
    };

    assert.deepEqual(__githubTest.closureCommentPrMentions(99730, [prComment]), []);
    assert.deepEqual(
      __githubTest.closureCommentPrMentions(
        99730,
        [prComment],
        {
          finalClosureActors: ['different-closer'],
          finalClosureActorIdentities: [finalClosureActorIdentity('different-closer')],
        },
      ),
      [],
    );
    assert.deepEqual(
      __githubTest.closureCommentPrMentions(
        99730,
        [prComment],
        {
          finalClosureActors: ['contributor-closer'],
          finalClosureActorIdentities: [finalClosureActorIdentity('contributor-closer')],
        },
      ).map((item) => item.prNumber),
      [99731],
    );
    assert.deepEqual(
      __githubTest.closureCommentCommitMentions(
        99730,
        [commitComment],
        99730,
        undefined,
        {
          finalClosureActors: ['different-closer'],
          finalClosureActorIdentities: [finalClosureActorIdentity('different-closer')],
        },
      ),
      [],
    );
    assert.deepEqual(
      __githubTest.closureCommentCommitMentions(
        99730,
        [commitComment],
        99730,
        undefined,
        {
          finalClosureActors: ['contributor-closer'],
          finalClosureActorIdentities: [finalClosureActorIdentity('contributor-closer')],
        },
      ).map((item) => item.commitOid),
      [commitOid],
    );
  });

  it('requires canonical comment and actor identities before trust policy can grant authority', () => {
    const canonical = canonicalClosureProofComment({
      body: 'Fixed by PR #99731.',
      user: { login: 'old-closer-name' },
      author_association: 'CONTRIBUTOR',
    }, 'ACTOR-final-closer');
    const options = {
      finalClosureActors: ['old-closer-name'],
      finalClosureActorIdentities: [{
        nodeId: 'ACTOR-final-closer',
        nodeType: 'User',
      }],
    };

    assert.equal(
      __githubTest.closureProofCommentTrust(canonical, options).trustedSource,
      true,
    );
    assert.equal(
      __githubTest.closureProofCommentTrust({
        ...canonical,
        user: {
          ...canonical.user,
          login: 'renamed-closer',
        },
      }, options).trustedSource,
      true,
    );
    assert.equal(
      __githubTest.closureProofCommentTrust({
        ...canonical,
        user: {
          ...canonical.user,
          id: 'ACTOR-impostor',
          login: 'old-closer-name',
        },
      }, options).trustedSource,
      false,
    );
    const { node_id: _missingCommentNodeId, ...withoutCommentNodeId } = canonical;
    assert.equal(
      __githubTest.closureProofCommentTrust(withoutCommentNodeId, options).trustedSource,
      false,
    );
    assert.equal(
      __githubTest.closureProofCommentTrust({
        ...canonical,
        user: {
          type: 'User',
          login: 'old-closer-name',
        },
      }, options).trustedSource,
      false,
    );
    assert.equal(
      __githubTest.closureProofCommentTrust(canonical, {
        finalClosureActors: ['old-closer-name'],
      }).trustedSource,
      false,
    );
  });

  it('preserves abbreviated commit hashes when the local cache cannot resolve them', () => {
    const mentions = __githubTest.closureCommentCommitMentions(97222, [
      canonicalClosureProofComment({
        body: 'Fixed by commit cfeaf6897fd8.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      }),
    ]);

    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].commitOid, 'cfeaf6897fd8');
    assert.equal(mentions[0].shortOid, 'cfeaf6897fd8');
    assert.equal(mentions[0].source, 'ClosureComment.fixProof');
  });

  it('retains unresolved short SHA evidence across a stale-cache resolver miss', () => {
    const resolverCalls: string[] = [];
    const mentions = __githubTest.closureCommentCommitMentions(97222, [
      canonicalClosureProofComment({
        body: 'Fixed by commit cfeaf6897fd8.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      }),
    ], 97222, (prefix) => {
      resolverCalls.push(prefix);
      return null;
    }, {
      finalClosureActors: ['clawsweeper'],
      finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
    });

    assert.deepEqual(resolverCalls, ['cfeaf6897fd8']);
    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].commitOid, 'cfeaf6897fd8');
    assert.equal(mentions[0].shortOid, 'cfeaf6897fd8');
  });

  it('expands abbreviated commit hashes only when the full identity matches the prefix', () => {
    const full = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const mentions = __githubTest.closureCommentCommitMentions(97222, [
      canonicalClosureProofComment({
        body: 'Fixed by commit cfeaf6897fd8.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      }),
    ], 97222, (prefix) => prefix === 'cfeaf6897fd8' ? full : null, {
      finalClosureActors: ['clawsweeper'],
      finalClosureActorIdentities: [finalClosureActorIdentity('clawsweeper')],
    });

    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].commitOid, full);
    assert.equal(mentions[0].shortOid, 'cfeaf6897fd8');
    assert.equal(mentions[0].source, 'ClosureComment.fixProof');
  });

  it('does not grant a resolver-provided full identity that does not match the short SHA', () => {
    const mentions = __githubTest.closureCommentCommitMentions(97222, [
      canonicalClosureProofComment({
        body: 'Fixed by commit cfeaf6897fd8.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      }),
    ], 97222, () => 'd'.repeat(40));

    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].commitOid, 'cfeaf6897fd8');
    assert.equal(mentions[0].shortOid, 'cfeaf6897fd8');
  });

  it('resolves fixed-on-current-main short SHA closure proof', () => {
    const full = 'd05e4a4bc6f22aaaa17ca566568556d46a67dee9';
    const mentions = __githubTest.closureCommentCommitMentions(88712, [
      canonicalClosureProofComment({
        body: 'Fixed on current `main` by `d05e4a4bc6` / #88698-era gateway channel runtime follow-up.',
        created_at: '2026-05-31T18:03:10Z',
        user: { login: 'steipete' },
        author_association: 'MEMBER',
      }),
    ], 88712, (prefix) => prefix === 'd05e4a4bc6' ? full : null);

    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].commitOid, full);
    assert.equal(mentions[0].shortOid, 'd05e4a4bc6');
    assert.equal(mentions[0].author, 'steipete');
  });

  it('identifies missing issue aliases in GraphQL partial-error messages', () => {
    const indexes = __githubTest.missingIssueIndexesFromGraphqlError(
      new Error('GitHub GraphQL error: NOT_FOUND repository.issue21 Could not resolve to an Issue with the number of 95854.'),
    );

    assert.deepEqual(indexes, [21]);
  });

  it('marks missing issue aliases done during partial-error recovery', () => {
    const done = new Set<number>();
    const missing: Array<{ issueNumber: number; aliasIndex: number }> = [];
    const skipped = __githubTest.skipMissingIssueAliases(
      new Error('GitHub GraphQL error: NOT_FOUND repository.issue1 Could not resolve to an Issue with the number of 95854.'),
      [100, 200, 300],
      done,
      (event: { issueNumber: number; aliasIndex: number }) => missing.push(event),
    );

    assert.equal(skipped, 1);
    assert.deepEqual([...done], [200]);
    assert.deepEqual(missing, [{ issueNumber: 200, aliasIndex: 1 }]);
  });

  it('refuses missing issue alias recovery without an explicit reporter', () => {
    const done = new Set<number>();
    const skipped = __githubTest.skipMissingIssueAliases(
      new Error('GitHub GraphQL error: NOT_FOUND repository.issue1 Could not resolve to an Issue with the number of 95854.'),
      [100, 200, 300],
      done,
    );

    assert.equal(skipped, 0);
    assert.deepEqual([...done], []);
  });

  it('rejects mixed GraphQL errors instead of recovering NOT_FOUND aliases', async () => {
    for (const transientType of ['RATE_LIMITED', 'INTERNAL']) {
      const mixedMessage = new Error(
        `GitHub GraphQL error: NOT_FOUND repository.issue0 ` +
          `Could not resolve to an Issue with the number of 7.; ` +
          `${transientType} repository.issue0 Something went wrong. Please retry.`,
      );
      const done = new Set<number>();
      const reported: Array<{ issueNumber: number; aliasIndex: number }> = [];
      assert.deepEqual(
        __githubTest.missingIssueIndexesFromGraphqlError(mixedMessage),
        [],
      );
      assert.equal(
        __githubTest.skipMissingIssueAliases(
          mixedMessage,
          [7],
          done,
          (event: { issueNumber: number; aliasIndex: number }) => reported.push(event),
        ),
        0,
      );
      assert.deepEqual([...done], []);
      assert.deepEqual(reported, []);

      const requester = __githubTest.createGraphqlRequester({
        fetchImpl: (async () => new Response(JSON.stringify({
          data: { repository: { issue0: null } },
          errors: [
            {
              type: 'NOT_FOUND',
              message: 'Could not resolve to an Issue with the number of 7.',
              path: ['repository', 'issue0'],
            },
            {
              type: transientType,
              message: 'Something went wrong. Please retry.',
              path: ['repository', 'issue0', 'comments'],
            },
          ],
        }), { status: 200 })) as typeof fetch,
        scheduler: immediateScheduler(),
        requestHeaders: () => ({}),
        maxRetries: 0,
        warn: () => undefined,
      });
      const structuredReports: Array<{ issueNumber: number; aliasIndex: number }> = [];
      await assert.rejects(
        __githubTest.listIssueCommentsBatch([7], {
          request: requester,
          onMissingIssueAlias: (event) => structuredReports.push(event),
        }),
        new RegExp(transientType),
      );
      assert.deepEqual(structuredReports, []);
    }
  });

  it('classifies transient GraphQL errors as retryable without retrying missing aliases', () => {
    assert.equal(__githubTest.shouldRetryGraphqlErrors([{
      type: 'RATE_LIMITED',
      message: 'You have exceeded a secondary rate limit. Please wait a few minutes before you try again.',
      path: ['repository', 'issues'],
    }]), true);
    assert.equal(__githubTest.shouldRetryGraphqlErrors([{
      type: 'INTERNAL',
      message: 'Something went wrong while executing your query. Please retry.',
    }]), true);
    assert.equal(__githubTest.shouldRetryGraphqlErrors([{
      type: 'NOT_FOUND',
      message: 'Could not resolve to an Issue with the number of 95854.',
      path: ['repository', 'issue1'],
    }]), false);
    assert.equal(__githubTest.shouldRetryGraphqlErrors([
      {
        type: 'RATE_LIMITED',
        message: 'You have exceeded a secondary rate limit.',
      },
      {
        type: 'NOT_FOUND',
        message: 'Could not resolve to an Issue with the number of 95854.',
        path: ['repository', 'issue1'],
      },
    ]), false);
    assert.equal(__githubTest.isRateLimitGraphqlError({
      type: 'RATE_LIMITED',
      message: 'You have exceeded a secondary rate limit.',
    }), true);
    assert.equal(__githubTest.isRateLimitGraphqlError({
      type: 'INTERNAL',
      message: 'Something went wrong while executing your query. Please retry.',
    }), false);
  });

  it('bounds concurrent GraphQL request execution', async () => {
    const limiter = __githubTest.createGraphqlRequestLimiter({
      concurrency: 2,
      minStartSpacingMs: 0,
      cooldownBaseMs: 100,
      cooldownMaxMs: 1_000,
    });
    let active = 0;
    let maxActive = 0;
    let releaseGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });

    const requests = Array.from({ length: 6 }, () => limiter.run(async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await gate;
      active--;
    }));

    await waitFor(() => active === 2);
    assert.equal(maxActive, 2);
    releaseGate();
    await Promise.all(requests);
    assert.equal(maxActive, 2);
  });

  it('removes aborted limiter work from the queue before it can start', async () => {
    const limiter = __githubTest.createGraphqlRequestLimiter({
      concurrency: 1,
      minStartSpacingMs: 0,
      cooldownBaseMs: 100,
      cooldownMaxMs: 1_000,
    });
    const activeGate = deferred();
    let activeStarted = false;
    let queuedStarted = false;
    const active = limiter.run(async () => {
      activeStarted = true;
      await activeGate.promise;
    });
    await waitFor(() => activeStarted);

    const controller = new AbortController();
    const abortReason = new Error('queued request cancelled');
    const queued = limiter.run(async () => {
      queuedStarted = true;
    }, controller.signal);
    controller.abort(abortReason);

    await assert.rejects(queued, (error) => error === abortReason);
    assert.equal(queuedStarted, false);
    activeGate.resolve();
    await active;
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(queuedStarted, false);
  });

  it('interrupts a limiter cooldown when its last queued request is cancelled', async () => {
    let markSleepStarted!: () => void;
    const sleepStarted = new Promise<void>((resolve) => {
      markSleepStarted = resolve;
    });
    let sleepAborted = false;
    const limiter = __githubTest.createGraphqlRequestLimiter({
      concurrency: 1,
      minStartSpacingMs: 0,
      cooldownBaseMs: 100,
      cooldownMaxMs: 1_000,
      clock: {
        now: () => 0,
        sleep: async (_ms: number, signal?: AbortSignal) => {
          markSleepStarted();
          assert.ok(signal);
          await new Promise<void>((_resolve, reject) => {
            const onAbort = () => {
              sleepAborted = true;
              reject(signal.reason);
            };
            signal.addEventListener('abort', onAbort, { once: true });
            if (signal.aborted) onAbort();
          });
        },
      },
    });
    limiter.noteRateLimit(60_000);
    const caller = new AbortController();
    let started = false;
    const queued = limiter.run(async () => {
      started = true;
    }, caller.signal);

    await sleepStarted;
    const abortReason = new Error('cancel limiter cooldown');
    caller.abort(abortReason);
    await assert.rejects(queued, (error) => error === abortReason);
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(started, false);
    assert.equal(sleepAborted, true);
  });

  it('enforces start spacing and adaptive single-flight cooldown', async () => {
    let now = 0;
    const sleeps: number[] = [];
    const clock = {
      now: () => now,
      sleep: async (ms: number) => {
        sleeps.push(ms);
        now += ms;
        await Promise.resolve();
      },
    };
    const spacedLimiter = __githubTest.createGraphqlRequestLimiter({
      concurrency: 3,
      minStartSpacingMs: 10,
      cooldownBaseMs: 40,
      cooldownMaxMs: 160,
      clock,
    });
    const starts: number[] = [];

    await Promise.all(Array.from({ length: 3 }, () => spacedLimiter.run(async () => {
      starts.push(now);
    })));
    assert.deepEqual(starts, [0, 10, 20]);

    const cooldownLimiter = __githubTest.createGraphqlRequestLimiter({
      concurrency: 3,
      minStartSpacingMs: 0,
      cooldownBaseMs: 40,
      cooldownMaxMs: 160,
      clock,
    });
    assert.equal(cooldownLimiter.noteRateLimit(), 40);
    assert.equal(cooldownLimiter.noteRateLimit(), 80);

    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let cooldownActive = 0;
    let cooldownMaxActive = 0;
    const cooldownStarts: number[] = [];
    const first = cooldownLimiter.run(async () => {
      cooldownStarts.push(now);
      cooldownActive++;
      cooldownMaxActive = Math.max(cooldownMaxActive, cooldownActive);
      await firstGate;
      cooldownActive--;
    });
    const second = cooldownLimiter.run(async () => {
      cooldownStarts.push(now);
      cooldownActive++;
      cooldownMaxActive = Math.max(cooldownMaxActive, cooldownActive);
      cooldownActive--;
    });

    await waitFor(() => cooldownStarts.length === 1);
    assert.equal(cooldownStarts[0], 100);
    releaseFirst();
    await Promise.all([first, second]);
    assert.equal(cooldownMaxActive, 1);
    assert.deepEqual(cooldownStarts, [100, 100]);
    assert.ok(sleeps.includes(80));

    const deadlineLimiter = __githubTest.createGraphqlRequestLimiter({
      concurrency: 2,
      minStartSpacingMs: 0,
      cooldownBaseMs: 100,
      cooldownMaxMs: 1_000,
      clock,
    });
    assert.equal(deadlineLimiter.noteRateLimit(120_000), 120_000);
  });

  it('classifies HTTP retries and applies deterministic jitter', () => {
    assert.deepEqual(
      __githubTest.classifyHttpRetry(new Response('', { status: 503 }), ''),
      { retryable: true, rateLimited: false, secondaryRateLimited: false },
    );
    assert.deepEqual(
      __githubTest.classifyHttpRetry(
        new Response('', { status: 403, headers: { 'x-ratelimit-remaining': '0' } }),
        '{"message":"API rate limit exceeded"}',
      ),
      { retryable: true, rateLimited: true, secondaryRateLimited: false },
    );
    assert.deepEqual(
      __githubTest.classifyHttpRetry(
        new Response('', { status: 403 }),
        '{"message":"You have exceeded a secondary rate limit"}',
      ),
      { retryable: true, rateLimited: true, secondaryRateLimited: true },
    );
    assert.deepEqual(
      __githubTest.classifyHttpRetry(
        new Response('', { status: 403 }),
        '{"message":"Resource not accessible by personal access token"}',
      ),
      { retryable: false, rateLimited: false, secondaryRateLimited: false },
    );
    assert.deepEqual(
      __githubTest.classifyHttpRetry(new Response('', { status: 422 }), ''),
      { retryable: false, rateLimited: false, secondaryRateLimited: false },
    );
    assert.equal(
      __githubTest.retryDelayMs(0, undefined, { baseMs: 100, maxMs: 1_000, random: () => 0 }),
      75,
    );
    assert.equal(
      __githubTest.retryDelayMs(0, undefined, { baseMs: 100, maxMs: 1_000, random: () => 1 }),
      125,
    );
    assert.equal(
      __githubTest.retryDelayMs(
        0,
        new Response('', { headers: { 'retry-after': '600' } }),
        { baseMs: 100, maxMs: 1_000, random: () => 0 },
      ),
      600_000,
    );
    assert.equal(
      __githubTest.retryDelayMs(
        0,
        new Response('', { headers: { 'x-ratelimit-reset': '160' } }),
        { baseMs: 100, maxMs: 1_000, random: () => 0, now: () => 100_000 },
      ),
      60_000,
    );
  });

  it('retries with uncapped server deadlines and a safe headerless secondary-limit fallback', async () => {
    const serverSleeps: number[] = [];
    const serverCooldowns: number[] = [];
    const serverResponses = [
      new Response('{"message":"rate limit"}', {
        status: 429,
        headers: { 'retry-after': '120' },
      }),
      new Response('{"data":{"ok":true}}', { status: 200 }),
    ];
    const serverRequester = __githubTest.createGraphqlRequester({
      fetchImpl: (async () => serverResponses.shift() as Response) as typeof fetch,
      scheduler: immediateScheduler(serverCooldowns),
      sleep: async (ms: number) => {
        serverSleeps.push(ms);
      },
      requestHeaders: () => ({}),
      retryBaseMs: 100,
      retryMaxMs: 1_000,
      maxRetries: 1,
      random: () => 0,
      warn: () => undefined,
    });

    assert.deepEqual(await serverRequester<{ ok: boolean }>('query Test'), { ok: true });
    assert.deepEqual(serverSleeps, [120_000]);
    assert.deepEqual(serverCooldowns, [120_000]);

    const secondarySleeps: number[] = [];
    const secondaryCooldowns: number[] = [];
    const secondaryResponses = [
      new Response('{"message":"You have exceeded a secondary rate limit"}', { status: 403 }),
      new Response('{"data":{"ok":true}}', { status: 200 }),
    ];
    const secondaryRequester = __githubTest.createGraphqlRequester({
      fetchImpl: (async () => secondaryResponses.shift() as Response) as typeof fetch,
      scheduler: immediateScheduler(secondaryCooldowns),
      sleep: async (ms: number) => {
        secondarySleeps.push(ms);
      },
      requestHeaders: () => ({}),
      retryBaseMs: 100,
      retryMaxMs: 1_000,
      maxRetries: 1,
      random: () => 0,
      warn: () => undefined,
    });

    assert.deepEqual(await secondaryRequester<{ ok: boolean }>('query Test'), { ok: true });
    assert.deepEqual(secondarySleeps, [60_000]);
    assert.deepEqual(secondaryCooldowns, [60_000]);
  });

  it('holds the GraphQL permit through body consumption and GraphQL cooldown registration', async () => {
    const gate = deferred();
    const events: string[] = [];
    const cooldowns: number[] = [];
    let fetchCalls = 0;
    const requester = __githubTest.createGraphqlRequester({
      fetchImpl: (async () => {
        fetchCalls++;
        events.push(`fetch-${fetchCalls}`);
        if (fetchCalls === 1) {
          const body = new ReadableStream<Uint8Array>({
            async pull(controller) {
              events.push('body-start');
              await gate.promise;
              controller.enqueue(new TextEncoder().encode(JSON.stringify({
                errors: [{
                  type: 'RATE_LIMITED',
                  message: 'You have exceeded a secondary rate limit.',
                }],
              })));
              events.push('body-consumed');
              controller.close();
            },
          }, { highWaterMark: 0 });
          return new Response(body, { status: 200 });
        }
        return new Response('{"data":{"ok":true}}', { status: 200 });
      }) as typeof fetch,
      scheduler: serialScheduler(events, cooldowns),
      requestHeaders: () => ({}),
      maxRetries: 0,
      random: () => 0,
      warn: () => undefined,
    });

    const first = requester<{ ok: boolean }>('query First');
    const second = requester<{ ok: boolean }>('query Second');
    await waitFor(() => events.includes('body-start'));
    assert.equal(fetchCalls, 1);

    gate.resolve();
    const results = await Promise.allSettled([first, second]);
    assert.equal(results[0].status, 'rejected');
    assert.deepEqual(
      results[1].status === 'fulfilled' ? results[1].value : null,
      { ok: true },
    );
    assert.deepEqual(cooldowns, [60_000]);
    assert.ok(events.indexOf('body-consumed') < events.indexOf('cooldown'));
    assert.ok(events.indexOf('cooldown') < events.indexOf('fetch-2'));
  });

  it('fails closed on streamed oversized GraphQL success bodies and cancels at the cap', async () => {
    let fetchCalls = 0;
    let pulls = 0;
    let cancels = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++;
        controller.enqueue(new Uint8Array(4));
      },
      cancel() {
        cancels++;
      },
    }, { highWaterMark: 0 });
    const requester = __githubTest.createGraphqlRequester({
      fetchImpl: (async () => {
        fetchCalls++;
        return new Response(body, { status: 200 });
      }) as typeof fetch,
      scheduler: immediateScheduler(),
      requestHeaders: () => ({}),
      responseBodyMaxBytes: 8,
      maxRetries: 5,
      warn: () => undefined,
    });

    await assert.rejects(
      requester('query Oversized'),
      /GraphQL response body exceeds 8 bytes/,
    );
    assert.equal(fetchCalls, 1);
    assert.equal(pulls, 3);
    assert.equal(cancels, 1);
  });

  it('releases the GraphQL permit when response cancellation never settles', async () => {
    for (const mode of ['declared-length', 'streamed'] as const) {
      const events: string[] = [];
      let fetchCalls = 0;
      let cancels = 0;
      const firstResponse = mode === 'declared-length'
        ? {
            ok: true,
            status: 200,
            headers: new Headers({ 'content-length': '33' }),
            body: {
              cancel() {
                cancels++;
                return new Promise<void>(() => undefined);
              },
            },
          } as unknown as Response
        : {
            ok: true,
            status: 200,
            headers: new Headers(),
            body: {
              getReader() {
                let reads = 0;
                return {
                  async read() {
                    reads++;
                    return {
                      done: false,
                      value: new Uint8Array(reads === 1 ? 17 : 16),
                    };
                  },
                  cancel() {
                    cancels++;
                    return new Promise<void>(() => undefined);
                  },
                  releaseLock() {
                    // Test reader has no external lock.
                  },
                };
              },
            },
          } as unknown as Response;
      const requester = __githubTest.createGraphqlRequester({
        fetchImpl: (async () => {
          fetchCalls++;
          events.push(`fetch-${fetchCalls}`);
          return fetchCalls === 1
            ? firstResponse
            : new Response('{"data":{"ok":true}}', { status: 200 });
        }) as typeof fetch,
        scheduler: serialScheduler(events),
        requestHeaders: () => ({}),
        responseBodyMaxBytes: 32,
        maxRetries: 0,
        warn: () => undefined,
      });

      const first = requester('query Oversized').then(
        () => ({ status: 'fulfilled' as const, error: null }),
        (error) => ({ status: 'rejected' as const, error }),
      );
      const second = requester<{ ok: boolean }>('query Next').then(
        (value) => ({ status: 'fulfilled' as const, value, error: null }),
        (error) => ({ status: 'rejected' as const, value: null, error }),
      );
      await waitFor(() => fetchCalls === 2);

      const firstResult = await first;
      const secondResult = await second;
      assert.equal(firstResult.status, 'rejected', mode);
      assert.match(String(firstResult.error), /exceeds 32 bytes/, mode);
      assert.equal(secondResult.status, 'fulfilled', mode);
      assert.deepEqual(secondResult.value, { ok: true }, mode);
      assert.equal(cancels, 1, mode);
    }
  });

  it('retries response body read failures and malformed successful responses', async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const bodyReadFailure = new Response(new ReadableStream<Uint8Array>({
      pull() {
        throw new Error('socket closed while reading body');
      },
    }, { highWaterMark: 0 }), { status: 200 });
    const responses = [
      bodyReadFailure,
      new Response('{malformed', { status: 200 }),
      new Response('{"data":{"ok":true}}', { status: 200 }),
    ];
    const requester = __githubTest.createGraphqlRequester({
      fetchImpl: (async () => {
        calls++;
        return responses.shift() as Response;
      }) as typeof fetch,
      scheduler: immediateScheduler(),
      sleep: async (ms: number) => {
        sleeps.push(ms);
      },
      requestHeaders: () => ({}),
      retryBaseMs: 100,
      retryMaxMs: 1_000,
      maxRetries: 2,
      random: () => 0,
      warn: () => undefined,
    });

    assert.deepEqual(await requester<{ ok: boolean }>('query Test'), { ok: true });
    assert.equal(calls, 3);
    assert.deepEqual(sleeps, [75, 150]);
  });

  it('times out stalled requests and stalled response bodies before retrying', async () => {
    let calls = 0;
    const stalledBody = new Response(new ReadableStream<Uint8Array>({
      pull: () => new Promise<void>(() => undefined),
    }, { highWaterMark: 0 }), { status: 200 });
    const requester = __githubTest.createGraphqlRequester({
      fetchImpl: (async () => {
        calls++;
        if (calls === 1) return new Promise<Response>(() => undefined);
        if (calls === 2) return stalledBody;
        return new Response('{"data":{"ok":true}}', { status: 200 });
      }) as typeof fetch,
      scheduler: immediateScheduler(),
      sleep: async () => undefined,
      requestHeaders: () => ({}),
      requestTimeoutMs: 5,
      bodyTimeoutMs: 5,
      retryBaseMs: 1,
      retryMaxMs: 1,
      maxRetries: 2,
      random: () => 0,
      warn: () => undefined,
    });

    assert.deepEqual(await requester<{ ok: boolean }>('query Test'), { ok: true });
    assert.equal(calls, 3);
  });

  it('cancels an active fetch and disposes a late response when fetch ignores abort', async () => {
    let resolveFetch!: (response: Response) => void;
    let fetchSignal: AbortSignal | null = null;
    let lateCancelReason: unknown;
    const lateBody = {
      cancel(reason?: unknown) {
        lateCancelReason = reason;
        return Promise.resolve();
      },
    } as unknown as ReadableStream<Uint8Array>;
    const requester = __githubTest.createGraphqlRequester({
      fetchImpl: ((_input, init) => {
        fetchSignal = init?.signal as AbortSignal;
        return new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        });
      }) as typeof fetch,
      scheduler: immediateScheduler(),
      requestHeaders: () => ({}),
      warn: () => undefined,
    });
    const controller = new AbortController();
    const abortReason = new Error('caller cancelled active fetch');
    const pending = requester('query IgnoreAbort', {}, controller.signal);

    await waitFor(() => fetchSignal != null);
    controller.abort(abortReason);
    await assert.rejects(pending, (error) => error === abortReason);
    assert.equal(fetchSignal?.aborted, true);
    assert.equal(fetchSignal?.reason, abortReason);

    resolveFetch({
      ok: true,
      status: 200,
      headers: new Headers(),
      body: lateBody,
    } as Response);
    await waitFor(() => lateCancelReason !== undefined);
    assert.equal(lateCancelReason, abortReason);
  });

  it('cancels a stalled response body read with the caller abort reason', async () => {
    let bodyReadStarted = false;
    let bodyCancelReason: unknown;
    let fetchCalls = 0;
    const reader = {
      read() {
        bodyReadStarted = true;
        return new Promise<ReadableStreamReadResult<Uint8Array>>(() => undefined);
      },
      cancel(reason?: unknown) {
        bodyCancelReason = reason;
        return Promise.resolve();
      },
      releaseLock() {
        // Test reader does not retain external resources.
      },
    };
    const response = {
      ok: true,
      status: 200,
      headers: new Headers(),
      body: {
        getReader: () => reader,
      },
    } as unknown as Response;
    const requester = __githubTest.createGraphqlRequester({
      fetchImpl: (async () => {
        fetchCalls++;
        return response;
      }) as typeof fetch,
      scheduler: immediateScheduler(),
      requestHeaders: () => ({}),
      warn: () => undefined,
    });
    const controller = new AbortController();
    const abortReason = new Error('caller cancelled body read');
    const pending = requester('query BodyAbort', {}, controller.signal);

    await waitFor(() => bodyReadStarted);
    controller.abort(abortReason);
    await assert.rejects(pending, (error) => error === abortReason);
    await waitFor(() => bodyCancelReason !== undefined);
    assert.equal(bodyCancelReason, abortReason);
    assert.equal(fetchCalls, 1);
  });

  it('builds one GraphQL query with aliased pull request fix lookups', () => {
    const query = __githubTest.buildPullRequestFixesBatchQuery(2);

    assert.match(query, /\$number0: Int!/);
    assert.match(query, /\$number1: Int!/);
    assert.match(query, /pr0: pullRequest\(number: \$number0\)/);
    assert.match(query, /pr1: pullRequest\(number: \$number1\)/);
    assert.match(query, /repository \{ name nameWithOwner url owner \{ login \} \}/);
    assert.match(query, /mergeCommit \{ oid \}/);
  });

  it('paginates issue closure proof connections', () => {
    const batch = __githubTest.buildIssueFixEvidenceBatchQuery(1);
    const prRefs = __githubTest.buildIssueClosedByPrRefsQuery();
    const stateTimeline = __githubTest.buildIssueStateTimelineQuery();
    const referenceTimeline = __githubTest.buildIssueReferenceTimelineQuery();

    assert.match(batch, /\$closedByFirst0: Int!/);
    assert.match(batch, /\$stateFirst0: Int!/);
    assert.match(batch, /\$referenceFirst0: Int!/);
    assert.match(batch, /closedByPullRequestsReferences\(first: \$closedByFirst0, includeClosedPrs: true\)/);
    assert.match(batch, /closedByPullRequestsReferences\([^)]*\) \{\s+totalCount/);
    assert.match(batch, /repository \{ name nameWithOwner url owner \{ login \} \}/);
    assert.match(batch, /id\s+__typename\s+number\s+state\s+updatedAt/);
    assert.match(batch, /stateEvents: timelineItems\(first: \$stateFirst0, itemTypes: \[CLOSED_EVENT, REOPENED_EVENT\]\)/);
    assert.match(batch, /stateEvents:[\s\S]*totalCount/);
    assert.match(batch, /referenceEvents: timelineItems\(first: \$referenceFirst0, itemTypes: \[CROSS_REFERENCED_EVENT, REFERENCED_EVENT\]\)/);
    assert.match(batch, /referenceEvents: timelineItems\([^)]*\) \{\s+totalCount/);
    assertNodeBackedActorSelections(batch, 'actor', 2);
    assertNodeBackedActorSelections(batch, 'closer', 1);
    assert.match(
      batch,
      /\.\.\. on ClosedEvent \{\s*id createdAt stateReason actor \{ __typename login \.\.\. on Node \{ id \} \}/,
    );
    assert.match(
      batch,
      /\.\.\. on ReopenedEvent \{\s*id createdAt actor \{ __typename login \.\.\. on Node \{ id \} \}\s*\}/,
    );
    assert.match(batch, /\.\.\. on ReferencedEvent \{\s*id createdAt isCrossRepository isDirectReference actor \{ login \}/);
    assert.match(batch, /commit \{ oid committedDate url messageHeadline \}/);
    assert.match(batch, /commitRepository \{\s*name\s*nameWithOwner\s*owner \{ login \}\s*\}/);
    assert.match(batch, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(prRefs, /\$first: Int!/);
    assert.match(prRefs, /closedByPullRequestsReferences\(first: \$first, after: \$after, includeClosedPrs: true\)/);
    assert.match(prRefs, /id\s+__typename\s+number\s+state\s+updatedAt[\s\S]*totalCount/);
    assert.match(prRefs, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(stateTimeline, /\$first: Int!/);
    assert.match(stateTimeline, /stateEvents: timelineItems\(first: \$first, after: \$after, itemTypes: \[CLOSED_EVENT, REOPENED_EVENT\]\)/);
    assert.match(stateTimeline, /totalCount/);
    assert.match(stateTimeline, /id\s+__typename\s+number\s+state\s+updatedAt/);
    assertNodeBackedActorSelections(stateTimeline, 'actor', 2);
    assertNodeBackedActorSelections(stateTimeline, 'closer', 1);
    assert.match(
      stateTimeline,
      /\.\.\. on ClosedEvent \{\s*id createdAt stateReason actor \{ __typename login \.\.\. on Node \{ id \} \}/,
    );
    assert.match(
      stateTimeline,
      /\.\.\. on ReopenedEvent \{\s*id createdAt actor \{ __typename login \.\.\. on Node \{ id \} \}\s*\}/,
    );
    assert.match(stateTimeline, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(referenceTimeline, /\$first: Int!/);
    assert.match(referenceTimeline, /referenceEvents: timelineItems\(first: \$first, after: \$after, itemTypes: \[CROSS_REFERENCED_EVENT, REFERENCED_EVENT\]\)/);
    assert.match(referenceTimeline, /id\s+__typename\s+number\s+state\s+updatedAt[\s\S]*totalCount/);
    assert.match(referenceTimeline, /\.\.\. on ReferencedEvent \{\s*id createdAt isCrossRepository isDirectReference actor \{ login \}/);
    assert.match(referenceTimeline, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('builds a verified state snapshot while independently exhausting reference pages', async () => {
    const pullRequest = {
      __typename: 'PullRequest',
      number: 77,
      title: 'Fix issue',
      url: 'https://github.com/openclaw/openclaw/pull/77',
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-07-03T03:00:00Z',
      baseRefName: 'main',
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        url: 'https://github.com/openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
      mergeCommit: { oid: 'a'.repeat(40) },
    };
    const calls: string[] = [];
    const result = await listIssueFixEvidenceBatch([42], {
      request: async <T>(query: string): Promise<T> => {
        calls.push(query.match(/query\s+(\w+)/)?.[1] ?? 'unknown');
        if (query.includes('query IssueFixEvidence')) {
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: fixEvidenceIssue({
                state: 'CLOSED',
                totalCount: 3,
                stateNodes: [
                  closedEvent('close-1', '2026-07-03T01:00:00Z'),
                  reopenedEvent('reopen-1', '2026-07-03T02:00:00Z'),
                ],
                stateCursor: 'state-1',
                referenceNodes: [{
                  __typename: 'CrossReferencedEvent',
                  id: 'cross-1',
                  createdAt: '2026-07-03T02:30:00Z',
                  willCloseTarget: true,
                  source: pullRequest,
                }],
                referenceTotalCount: 2,
                referenceCursor: 'reference-1',
              }),
            },
          } as T;
        }
        if (query.includes('query IssueStateTimeline')) {
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: stateEventPage(
                'CLOSED',
                '2026-07-03T03:00:00Z',
                3,
                [closedEvent('close-2', '2026-07-03T03:00:00Z', pullRequest)],
              ),
            },
          } as T;
        }
        if (query.includes('query IssueReferenceTimeline')) {
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: {
                id: 'ISSUE-node-42',
                __typename: 'Issue',
                number: 42,
                state: 'CLOSED',
                updatedAt: '2026-07-03T03:00:00Z',
                referenceEvents: {
                  totalCount: 2,
                  nodes: [{
                    __typename: 'ReferencedEvent',
                    id: 'commit-ref-1',
                    createdAt: '2026-07-03T02:45:00Z',
                    isCrossRepository: false,
                    isDirectReference: true,
                    actor: { login: 'maintainer' },
                    commit: {
                      oid: 'b'.repeat(40),
                      messageHeadline: 'fix: issue 42',
                    },
                    commitRepository: {
                      name: 'openclaw',
                      nameWithOwner: 'openclaw/openclaw',
                      owner: { login: 'openclaw' },
                    },
                  }],
                  pageInfo: { hasNextPage: false, endCursor: null },
                },
              },
            },
          } as T;
        }
        throw new Error(`Unexpected query: ${query}`);
      },
    });

    const evidence = result.get(42)!;
    assert.deepEqual(calls, [
      'IssueFixEvidence',
      'IssueStateTimeline',
      'IssueReferenceTimeline',
      'IssueFixEvidence',
      'IssueStateTimeline',
      'IssueReferenceTimeline',
    ]);
    assert.deepEqual(evidence.stateSnapshot, {
      schemaVersion: ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
      repositoryNodeId: TEST_REPOSITORY_NODE_ID,
      issueNumber: 42,
      issueState: 'closed',
      issueUpdatedAt: '2026-07-03T03:00:00Z',
      totalCount: 3,
      fetchedCount: 3,
      eventsDigest: evidence.stateSnapshot.eventsDigest,
      authorityDigest: evidence.stateSnapshot.authorityDigest,
      sweepIdentity: evidence.stateSnapshot.sweepIdentity,
      sweepCount: 2,
      stabilized: true,
      stabilization: evidence.stateSnapshot.stabilization,
    });
    assert.match(evidence.stateSnapshot.eventsDigest, /^[0-9a-f]{64}$/);
    assert.match(evidence.stateSnapshot.authorityDigest, /^[0-9a-f]{64}$/);
    assert.equal(evidence.stateSnapshot.sweepIdentity.sweepOrdinal, 2);
    assert.equal(evidence.stateSnapshot.stabilization?.sweepCount, 2);
    assert.equal(evidence.issueNodeId, 'ISSUE-node-42');
    assert.equal(evidence.issueNodeType, 'Issue');
    assert.deepEqual(evidence.closureEvents.map((event) => ({
      eventType: event.eventType,
      actorNodeId: event.actorNodeId,
      actorType: event.actorType,
      closerNodeId: event.closerNodeId,
      closerType: event.closerType,
    })), [
      {
        eventType: 'ClosedEvent',
        actorNodeId: 'ACTOR-maintainer',
        actorType: 'User',
        closerNodeId: 'CLOSER-close-1',
        closerType: 'Commit',
      },
      {
        eventType: 'ClosedEvent',
        actorNodeId: 'ACTOR-maintainer',
        actorType: 'User',
        closerNodeId: 'CLOSER-close-2',
        closerType: 'PullRequest',
      },
    ]);
    assert.deepEqual(evidence.closureEvents.map((event) => event.eventId), ['close-1', 'close-2']);
    assert.deepEqual(evidence.reopenEvents.map((event) => event.eventId), ['reopen-1']);
    assert.equal(evidence.commitReferences[0].eventId, 'commit-ref-1');
    assert.equal(evidence.prLinks.some((link) => link.source === 'CrossReferencedEvent'), true);
    assert.equal(evidence.prLinks.some((link) => link.source === 'ClosedEvent.closer'), true);
  });

  it('fails closed before stabilization when issue or state-event authority identities are incomplete', async () => {
    const scenarios = [
      {
        issue: fixEvidenceIssue({
          issueNodeId: '',
          state: 'OPEN',
          totalCount: 0,
        }),
        expected: /issue node ID/,
      },
      {
        issue: fixEvidenceIssue({
          issueNodeType: 'PullRequest',
          state: 'OPEN',
          totalCount: 0,
        }),
        expected: /unexpected issue node type PullRequest/,
      },
      {
        issue: fixEvidenceIssue({
          state: 'CLOSED',
          totalCount: 1,
          stateNodes: [{
            ...closedEvent('close-missing-actor', '2026-07-03T01:00:00Z'),
            actor: {
              __typename: 'User',
              login: 'maintainer',
            },
          }],
        }),
        expected: /actor node ID/,
      },
      {
        issue: fixEvidenceIssue({
          state: 'CLOSED',
          totalCount: 1,
          stateNodes: [
            closedEvent('close-missing-closer', '2026-07-03T01:00:00Z', null),
          ],
        }),
        expected: /requires a canonical closer identity/,
      },
      {
        issue: fixEvidenceIssue({
          state: 'CLOSED',
          totalCount: 1,
          stateNodes: [{
            id: 'close-missing-type',
            createdAt: '2026-07-03T01:00:00Z',
            stateReason: 'COMPLETED',
            actor: {
              id: 'ACTOR-maintainer',
              __typename: 'User',
              login: 'maintainer',
            },
            closer: {
              id: 'COMMIT-close-missing-type',
              __typename: 'Commit',
              oid: 'a'.repeat(40),
            },
          }],
        }),
        expected: /state event is missing __typename/,
      },
    ];

    for (const scenario of scenarios) {
      await assert.rejects(
        listIssueFixEvidenceBatch([42], {
          snapshotMaxAttempts: 1,
          request: async <T>(): Promise<T> => ({
            repository: { id: TEST_REPOSITORY_NODE_ID, issue0: scenario.issue },
          }) as T,
        }),
        scenario.expected,
      );
    }
  });

  it('freezes issue #83511 at 183 reference events while live totalCount grows to 209', async () => {
    const events = Array.from({ length: 209 }, (_, index) => referencedEvent(index + 1));
    const requests: Array<{ query: string; first: number; after: string | null }> = [];
    let sweep = 0;
    const result = await listIssueFixEvidenceBatch([83511], {
      snapshotMaxAttempts: 2,
      sleep: async () => undefined,
      request: async <T>(
        query: string,
        variables: Record<string, unknown> = {},
      ): Promise<T> => {
        if (query.includes('query IssueFixEvidence')) {
          sweep++;
          const totalCount = sweep === 1 ? 183 : 209;
          const first = Number(variables.referenceFirst0);
          requests.push({ query: 'batch', first, after: null });
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: fixEvidenceIssue({
                issueNumber: 83511,
                state: 'OPEN',
                updatedAt: '2026-07-03T03:00:00Z',
                totalCount: 0,
                referenceNodes: events.slice(0, first),
                referenceTotalCount: totalCount,
                referenceCursor: first < totalCount ? `reference-${first}` : null,
              }),
            },
          } as T;
        }
        if (query.includes('query IssueReferenceTimeline')) {
          const after = String(variables.after);
          const start = Number(after.slice('reference-'.length));
          const first = Number(variables.first);
          const totalCount = sweep === 1 ? 183 : 209;
          requests.push({ query: 'continuation', first, after });
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: {
                id: 'ISSUE-node-83511',
                __typename: 'Issue',
                number: 83511,
                state: 'OPEN',
                updatedAt: '2026-07-03T03:00:00Z',
                referenceEvents: {
                  totalCount,
                  nodes: events.slice(start, start + first),
                  pageInfo: {
                    hasNextPage: start + first < totalCount,
                    endCursor: start + first < totalCount
                      ? `reference-${start + first}`
                      : null,
                  },
                },
              },
            },
          } as T;
        }
        throw new Error(`Unexpected query: ${query}`);
      },
    });

    const evidence = result.get(83511)!;
    assert.deepEqual(requests, [
      { query: 'batch', first: 100, after: null },
      { query: 'continuation', first: 83, after: 'reference-100' },
      { query: 'batch', first: 100, after: null },
      { query: 'batch', first: 100, after: null },
      { query: 'continuation', first: 100, after: 'reference-100' },
      { query: 'continuation', first: 9, after: 'reference-200' },
      { query: 'batch', first: 100, after: null },
      { query: 'continuation', first: 100, after: 'reference-100' },
      { query: 'continuation', first: 9, after: 'reference-200' },
    ]);
    assert.equal(evidence.commitReferences.length, 209);
    assert.equal(evidence.commitReferences.at(-1)?.eventId, 'reference-209');
    assert.equal(evidence.commitReferences.some((event) => event.eventId === 'reference-184'), true);
    assert.equal(evidence.stateSnapshot.sweepCount, 3);
    assert.deepEqual(evidence.connectionSnapshots.referenceEvents, {
      totalCount: 209,
      observedTotalCount: 209,
      postBoundaryGrowthCount: 0,
      fetchedCount: 209,
      terminalFirstNIdentity: 'reference-209',
      identityDigest: evidence.connectionSnapshots.referenceEvents.identityDigest,
      contentDigest: evidence.connectionSnapshots.referenceEvents.contentDigest,
      sourceOrder: 'CONNECTION_ASC',
    });
  });

  it('covers exact 100 and 101 closed-by PR and state-event connection boundaries', async () => {
    const pullRequest = (number: number) => ({
      __typename: 'PullRequest',
      number,
      title: `Fix ${number}`,
      url: `https://github.com/openclaw/openclaw/pull/${number}`,
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-07-03T03:00:00Z',
      baseRefName: 'main',
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        url: 'https://github.com/openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
      mergeCommit: { oid: number.toString(16).padStart(40, '0') },
    });

    for (const totalCount of [100, 101]) {
      const pullRequests = Array.from(
        { length: totalCount },
        (_, index) => pullRequest(index + 1),
      );
      const stateNodes = Array.from({ length: totalCount }, (_, index) => {
        const id = `state-boundary-${index + 1}`;
        const createdAt = new Date(Date.UTC(2026, 6, 3, 0, 0, index)).toISOString();
        return index % 2 === 0
          ? closedEvent(id, createdAt)
          : reopenedEvent(id, createdAt);
      });
      const issueState = totalCount % 2 === 0 ? 'OPEN' as const : 'CLOSED' as const;
      const updatedAt = '2026-07-03T03:00:00Z';
      const requests: string[] = [];
      const result = await listIssueFixEvidenceBatch([42], {
        request: async <T>(
          query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          if (query.includes('query IssueFixEvidence')) {
            const closedByFirst = Number(variables.closedByFirst0);
            const stateFirst = Number(variables.stateFirst0);
            requests.push(`batch:${closedByFirst}:${stateFirst}`);
            return {
              repository: {
                id: TEST_REPOSITORY_NODE_ID,
                issue0: fixEvidenceIssue({
                  state: issueState,
                  updatedAt,
                  totalCount,
                  stateNodes: stateNodes.slice(0, stateFirst),
                  stateCursor: stateFirst < totalCount ? 'state-boundary-100' : null,
                  closedByNodes: pullRequests.slice(0, closedByFirst),
                  closedByTotalCount: totalCount,
                  closedByCursor: closedByFirst < totalCount
                    ? 'closed-boundary-100'
                    : null,
                }),
              },
            } as T;
          }
          if (query.includes('query IssueClosedByPrRefs')) {
            const after = String(variables.after);
            const first = Number(variables.first);
            requests.push(`closed:${after}:${first}`);
            assert.equal(after, 'closed-boundary-100');
            return {
              repository: {
                id: TEST_REPOSITORY_NODE_ID,
                issue: {
                  id: 'ISSUE-node-42',
                  __typename: 'Issue',
                  number: 42,
                  state: issueState,
                  updatedAt,
                  closedByPullRequestsReferences: {
                    totalCount,
                    nodes: pullRequests.slice(100, 100 + first),
                    pageInfo: { hasNextPage: false, endCursor: null },
                  },
                },
              },
            } as T;
          }
          if (query.includes('query IssueStateTimeline')) {
            const after = String(variables.after);
            const first = Number(variables.first);
            requests.push(`state:${after}:${first}`);
            assert.equal(after, 'state-boundary-100');
            return {
              repository: {
                id: TEST_REPOSITORY_NODE_ID,
                issue: stateEventPage(
                  issueState,
                  updatedAt,
                  totalCount,
                  stateNodes.slice(100, 100 + first),
                ),
              },
            } as T;
          }
          throw new Error(`Unexpected query: ${query}`);
        },
      });

      assert.deepEqual(
        requests,
        totalCount === 100
          ? ['batch:100:100', 'batch:100:100']
          : [
              'batch:100:100',
              'closed:closed-boundary-100:1',
              'state:state-boundary-100:1',
              'batch:100:100',
              'closed:closed-boundary-100:1',
              'state:state-boundary-100:1',
            ],
      );
      const evidence = result.get(42)!;
      for (const snapshot of [
        evidence.connectionSnapshots.closedByPullRequestsReferences,
        evidence.connectionSnapshots.stateEvents,
      ]) {
        assert.equal(snapshot.totalCount, totalCount);
        assert.equal(snapshot.observedTotalCount, totalCount);
        assert.equal(snapshot.fetchedCount, totalCount);
        assert.equal(snapshot.postBoundaryGrowthCount, 0);
      }
      assert.equal(
        evidence.connectionSnapshots.closedByPullRequestsReferences.terminalFirstNIdentity,
        `openclaw/openclaw#${totalCount}`,
      );
      assert.equal(
        evidence.connectionSnapshots.stateEvents.terminalFirstNIdentity,
        `state-boundary-${totalCount}`,
      );
      assert.equal(evidence.stateSnapshot.totalCount, totalCount);
      assert.equal(evidence.stateSnapshot.fetchedCount, totalCount);
    }
  });

  it('records post-boundary growth independently for state events and closed-by PR refs', async () => {
    const pullRequest = (number: number) => ({
      __typename: 'PullRequest',
      number,
      title: `Fix ${number}`,
      url: `https://github.com/openclaw/openclaw/pull/${number}`,
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-07-03T03:00:00Z',
      baseRefName: 'main',
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        url: 'https://github.com/openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
      mergeCommit: { oid: number.toString(16).padStart(40, '0') },
    });
    const scenarios = [
      {
        connection: 'stateEvents' as const,
        terminalIdentity: 'close-2',
        issue: (grew: boolean) => fixEvidenceIssue({
          state: 'CLOSED',
          totalCount: grew ? 2 : 1,
          stateNodes: grew
            ? [
                closedEvent('close-1', '2026-07-03T01:00:00Z'),
                closedEvent('close-2', '2026-07-03T02:00:00Z'),
              ]
            : [closedEvent('close-1', '2026-07-03T01:00:00Z')],
          closedByNodes: [pullRequest(77)],
          closedByTotalCount: 1,
        }),
      },
      {
        connection: 'closedByPullRequestsReferences' as const,
        terminalIdentity: 'openclaw/openclaw#78',
        issue: (grew: boolean) => fixEvidenceIssue({
          state: 'OPEN',
          totalCount: 0,
          closedByNodes: grew
            ? [pullRequest(77), pullRequest(78)]
            : [pullRequest(77)],
          closedByTotalCount: grew ? 2 : 1,
        }),
      },
    ];

    for (const scenario of scenarios) {
      let calls = 0;
      const result = await listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => {
          calls++;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: scenario.issue(calls >= 2),
            },
          } as T;
        },
      });

      const snapshot = result.get(42)!.connectionSnapshots[scenario.connection];
      assert.equal(calls, 4);
      assert.equal(snapshot.totalCount, 2);
      assert.equal(snapshot.observedTotalCount, 2);
      assert.equal(snapshot.postBoundaryGrowthCount, 0);
      assert.equal(snapshot.fetchedCount, 2);
      assert.equal(snapshot.terminalFirstNIdentity, scenario.terminalIdentity);
    }
  });

  it('fails closed when any nested append-only totalCount decreases below its frozen boundary', async () => {
    const pullRequest = (number: number) => ({
      __typename: 'PullRequest',
      number,
      title: `Fix ${number}`,
      url: `https://github.com/openclaw/openclaw/pull/${number}`,
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-07-03T03:00:00Z',
      baseRefName: 'main',
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        url: 'https://github.com/openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
      mergeCommit: { oid: number.toString(16).padStart(40, '0') },
    });
    const scenarios = [
      {
        context: 'state event timeline',
        issue: (decreased: boolean) => fixEvidenceIssue({
          state: 'CLOSED',
          totalCount: decreased ? 1 : 2,
          stateNodes: decreased
            ? [closedEvent('close-1', '2026-07-03T01:00:00Z')]
            : [
                closedEvent('close-1', '2026-07-03T01:00:00Z'),
                closedEvent('close-2', '2026-07-03T02:00:00Z'),
              ],
        }),
      },
      {
        context: 'closedByPullRequestsReferences',
        issue: (decreased: boolean) => fixEvidenceIssue({
          state: 'OPEN',
          totalCount: 0,
          closedByTotalCount: decreased ? 1 : 2,
          closedByNodes: decreased ? [pullRequest(77)] : [pullRequest(77), pullRequest(78)],
        }),
      },
      {
        context: 'reference timeline',
        issue: (decreased: boolean) => fixEvidenceIssue({
          state: 'OPEN',
          totalCount: 0,
          referenceTotalCount: decreased ? 1 : 2,
          referenceNodes: decreased ? [referencedEvent(1)] : [referencedEvent(1), referencedEvent(2)],
        }),
      },
    ];

    for (const scenario of scenarios) {
      let calls = 0;
      await assert.rejects(
        listIssueFixEvidenceBatch([42], {
          snapshotMaxAttempts: 1,
          request: async <T>(): Promise<T> => {
            calls++;
            return {
              repository: { id: TEST_REPOSITORY_NODE_ID, issue0: scenario.issue(calls === 2) },
            } as T;
          },
        }),
        new RegExp(`${scenario.context} totalCount decreased below frozen boundary from 2 to 1`),
      );
    }
  });

  it('uses connection ordinals to resolve equal-time state events after epoch normalization', async () => {
    const evidence = await listIssueFixEvidenceBatch([42], {
      request: async <T>(): Promise<T> => ({
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: fixEvidenceIssue({
            state: 'OPEN',
            updatedAt: '2026-07-03T03:00:00Z',
            totalCount: 2,
            stateNodes: [
              closedEvent('z-close', '2026-07-03T01:00:00-02:00'),
              reopenedEvent('a-reopen', '2026-07-03T03:00:00Z'),
            ],
          }),
        },
      }) as T,
    });

    assert.equal(evidence.get(42)?.stateSnapshot.issueState, 'open');
    assert.equal(evidence.get(42)?.closureEvents[0].connectionOrdinal, 0);
    assert.equal(evidence.get(42)?.reopenEvents[0].connectionOrdinal, 1);
    assert.equal(evidence.get(42)?.stateSnapshot.sweepCount, 2);
    assert.equal(evidence.get(42)?.stateSnapshot.stabilized, true);
  });

  it('retries changed state-event sweeps and records the complete sweep count', async () => {
    let calls = 0;
    const delays: number[] = [];
    const evidence = await listIssueFixEvidenceBatch([42], {
      snapshotMaxAttempts: 2,
      snapshotRetryBaseMs: 25,
      snapshotRetryMaxMs: 100,
      sleep: async (ms: number) => {
        delays.push(ms);
      },
      request: async <T>(): Promise<T> => {
        calls++;
        const actorNodeId = calls === 2
          ? 'ACTOR-changed-between-sweeps'
          : 'ACTOR-maintainer';
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'CLOSED',
              totalCount: 1,
              stateNodes: [{
                ...closedEvent('close-1', '2026-07-03T01:00:00Z'),
                actor: {
                  id: actorNodeId,
                  __typename: 'User',
                  login: 'maintainer',
                },
              }],
            }),
          },
        } as T;
      },
    });

    assert.equal(calls, 4);
    assert.deepEqual(delays, [25]);
    assert.equal(evidence.get(42)?.closureEvents[0].actorLogin, 'maintainer');
    assert.equal(evidence.get(42)?.closureEvents[0].actorNodeId, 'ACTOR-maintainer');
    assert.equal(evidence.get(42)?.stateSnapshot.sweepCount, 4);
    assert.equal(evidence.get(42)?.stateSnapshot.stabilized, true);
    assert.equal(
      evidence.get(42)?.stateSnapshot.stabilization?.firstSweep.sweepOrdinal,
      3,
    );
    assert.equal(
      evidence.get(42)?.stateSnapshot.stabilization?.secondSweep.sweepOrdinal,
      4,
    );
  });

  it('does not destabilize immutable state evidence when non-scoring raw metadata changes', async () => {
    let calls = 0;
    const evidence = await listIssueFixEvidenceBatch([42], {
      snapshotMaxAttempts: 2,
      sleep: async () => undefined,
      request: async <T>(): Promise<T> => {
        calls++;
        const committedDate = calls === 2
          ? '2026-07-03T01:01:00Z'
          : '2026-07-03T01:00:00Z';
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'CLOSED',
              totalCount: 1,
              stateNodes: [closedEvent(
                'close-raw',
                '2026-07-03T01:00:00Z',
                {
                  __typename: 'Commit',
                  oid: 'a'.repeat(40),
                  committedDate,
                  url: `https://github.com/openclaw/openclaw/commit/${'a'.repeat(40)}`,
                },
              )],
            }),
          },
        } as T;
      },
    });

    assert.equal(calls, 2);
    assert.equal(evidence.get(42)?.stateSnapshot.sweepCount, 2);
    assert.equal(
      (evidence.get(42)?.closureEvents[0].raw as any).closer.committedDate,
      '2026-07-03T01:01:00Z',
    );
  });

  it('keeps mutable PR metadata outside append-only evidence stabilization', async () => {
    const pullRequest = {
      __typename: 'PullRequest',
      number: 77,
      title: 'Fix issue',
      url: 'https://github.com/openclaw/openclaw/pull/77',
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-07-03T03:00:00Z',
      baseRefName: 'main',
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        url: 'https://github.com/openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
      mergeCommit: { oid: 'a'.repeat(40) },
    };
    let calls = 0;
    const evidence = await listIssueFixEvidenceBatch([42], {
      request: async <T>(): Promise<T> => {
        calls++;
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'OPEN',
              totalCount: 0,
              closedByNodes: [{
                ...pullRequest,
                title: calls === 2 ? 'Changed fix title' : pullRequest.title,
              }],
            }),
          },
        } as T;
      },
    });

    assert.equal(calls, 2);
    assert.equal(evidence.get(42)?.stateSnapshot.sweepCount, 2);
    assert.equal(evidence.get(42)?.pullRequests[0].title, 'Changed fix title');
  });

  it('retries when score-affecting cross-reference or commit evidence changes between sweeps', async () => {
    const pullRequest = {
      __typename: 'PullRequest',
      number: 77,
      title: 'Fix issue',
      url: 'https://github.com/openclaw/openclaw/pull/77',
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-07-03T03:00:00Z',
      baseRefName: 'main',
      repository: {
        id: TEST_REPOSITORY_NODE_ID,
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        url: 'https://github.com/openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
      mergeCommit: { oid: 'a'.repeat(40) },
    };
    const commitReference = {
      __typename: 'ReferencedEvent',
      id: 'commit-ref-1',
      createdAt: '2026-07-03T02:45:00Z',
      isCrossRepository: false,
      isDirectReference: true,
      actor: { login: 'maintainer' },
      commit: {
        oid: 'b'.repeat(40),
        messageHeadline: 'fix: issue 42',
      },
      commitRepository: {
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
    };
    const scenarios = [
      (changed: boolean) => fixEvidenceIssue({
        state: 'OPEN',
        totalCount: 0,
        referenceNodes: [{
          __typename: 'CrossReferencedEvent',
          id: 'cross-ref-1',
          createdAt: '2026-07-03T02:30:00Z',
          willCloseTarget: !changed,
          source: pullRequest,
        }],
      }),
      (changed: boolean) => fixEvidenceIssue({
        state: 'OPEN',
        totalCount: 0,
        referenceNodes: [{
          ...commitReference,
          actor: { login: changed ? 'other-maintainer' : 'maintainer' },
        }],
      }),
    ];

    for (const scenario of scenarios) {
      let calls = 0;
      const delays: number[] = [];
      const evidence = await listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        snapshotRetryBaseMs: 25,
        snapshotRetryMaxMs: 100,
        sleep: async (ms: number) => {
          delays.push(ms);
        },
        request: async <T>(): Promise<T> => {
          calls++;
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: scenario(calls === 2),
            },
          } as T;
        },
      });
      assert.equal(calls, 4);
      assert.deepEqual(delays, [25]);
      assert.equal(evidence.get(42)?.stateSnapshot.sweepCount, 4);
      assert.equal(evidence.get(42)?.stateSnapshot.stabilized, true);
    }
  });

  it('fails closed when state-event ordering never stabilizes across bounded sweep pairs', async () => {
    let calls = 0;
    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => {
          calls++;
          const order = calls % 2 === 0
            ? ['close-2', 'close-1']
            : ['close-1', 'close-2'];
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue0: fixEvidenceIssue({
                state: 'CLOSED',
                totalCount: 2,
                stateNodes: order.map((id) => closedEvent(id, '2026-07-03T01:00:00Z')),
              }),
            },
          } as T;
        },
      }),
      /failed to stabilize after 2 attempts.*first-N identity changed across frozen sweeps/,
    );
    assert.equal(calls, 4);
  });

  it('fails closed on truncated or metadata-unstable reference connections', async () => {
    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'OPEN',
              totalCount: 0,
              closedByTotalCount: 1,
            }),
          },
        }) as T,
      }),
      /closedByPullRequestsReferences terminal unique count 0 did not match totalCount 1/,
    );

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'OPEN',
              totalCount: 0,
              referenceTotalCount: 1,
            }),
          },
        }) as T,
      }),
      /reference timeline terminal unique count 0 did not match totalCount 1/,
    );

    const referenceNode = {
      __typename: 'ReferencedEvent',
      id: 'commit-ref-stable',
      createdAt: '2026-07-03T02:00:00Z',
      isCrossRepository: false,
      isDirectReference: true,
      actor: { login: 'maintainer' },
      commit: {
        oid: 'd'.repeat(40),
        messageHeadline: 'fix stable metadata',
      },
      commitRepository: {
        name: 'openclaw',
        nameWithOwner: 'openclaw/openclaw',
        owner: { login: 'openclaw' },
      },
    };
    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(query: string): Promise<T> => {
          if (query.includes('query IssueFixEvidence')) {
            return {
              repository: {
                id: TEST_REPOSITORY_NODE_ID,
                issue0: fixEvidenceIssue({
                  state: 'OPEN',
                  updatedAt: '2026-07-03T03:00:00Z',
                  totalCount: 0,
                  referenceNodes: [referenceNode],
                  referenceTotalCount: 2,
                  referenceCursor: 'reference-next',
                }),
              },
            } as T;
          }
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: {
                id: 'ISSUE-node-42',
                __typename: 'Issue',
                number: 42,
                state: 'OPEN',
                updatedAt: '2026-07-03T03:01:00Z',
                referenceEvents: {
                  totalCount: 2,
                  nodes: [{ ...referenceNode, id: 'commit-ref-drifted' }],
                  pageInfo: { hasNextPage: false, endCursor: null },
                },
              },
            },
          } as T;
        },
      }),
      /reference timeline metadata drifted during pagination/,
    );
  });

  it('rejects state snapshot drift, count mismatch, missing reopen, nulls, duplicates, and truncation', async () => {
    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(query: string): Promise<T> => {
          if (query.includes('query IssueFixEvidence')) {
            return {
              repository: {
                id: TEST_REPOSITORY_NODE_ID,
                issue0: fixEvidenceIssue({
                  state: 'CLOSED',
                  updatedAt: '2026-07-03T03:00:00Z',
                  totalCount: 2,
                  stateNodes: [closedEvent('close-1', '2026-07-03T01:00:00Z')],
                  stateCursor: 'state-1',
                }),
              },
            } as T;
          }
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: stateEventPage(
                'CLOSED',
                '2026-07-03T03:01:00Z',
                2,
                [closedEvent('close-2', '2026-07-03T03:00:00Z')],
              ),
            },
          } as T;
        },
      }),
      /metadata drifted during pagination/,
    );

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'CLOSED',
              totalCount: 2,
              stateNodes: [closedEvent('close-1', '2026-07-03T01:00:00Z')],
            }),
          },
        }) as T,
      }),
      /state event timeline terminal unique count 1 did not match totalCount 2/,
    );

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'OPEN',
              totalCount: 1,
              stateNodes: [closedEvent('close-1', '2026-07-03T01:00:00Z')],
            }),
          },
        }) as T,
      }),
      /a close or reopen event is missing/,
    );

    const repeatedCloseEvidence = await listIssueFixEvidenceBatch([42], {
      request: async <T>(): Promise<T> => ({
        repository: {
          id: TEST_REPOSITORY_NODE_ID,
          issue0: fixEvidenceIssue({
            state: 'CLOSED',
            totalCount: 2,
            stateNodes: [
              closedEvent('close-1', '2026-07-03T01:00:00Z'),
              closedEvent('close-2', '2026-07-03T02:00:00Z'),
            ],
          }),
        },
      }) as T,
    });
    assert.equal(repeatedCloseEvidence.get(42)?.closureEvents.length, 2);

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'CLOSED',
              totalCount: 1,
              stateNodes: [null],
            }),
          },
        }) as T,
      }),
      /returned null node at index 0/,
    );

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'CLOSED',
              totalCount: 2,
              stateNodes: [
                closedEvent('close-1', '2026-07-03T01:00:00Z'),
                closedEvent('close-1', '2026-07-03T02:00:00Z'),
              ],
            }),
          },
        }) as T,
      }),
      /duplicate identity close-1/,
    );

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        maxPagesPerConnection: 1,
        request: async <T>(): Promise<T> => ({
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              state: 'CLOSED',
              totalCount: 2,
              stateNodes: [closedEvent('close-1', '2026-07-03T01:00:00Z')],
              stateCursor: 'state-1',
            }),
          },
        }) as T,
      }),
      /exceeded 1 pages before pagination completed/,
    );

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(query: string): Promise<T> => {
          if (query.includes('query IssueFixEvidence')) {
            return {
              repository: {
                id: TEST_REPOSITORY_NODE_ID,
                issue0: fixEvidenceIssue({
                  state: 'OPEN',
                  totalCount: 3,
                  stateNodes: [closedEvent('close-1', '2026-07-03T01:00:00Z')],
                  stateCursor: 'state-1',
                }),
              },
            } as T;
          }
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: stateEventPage(
                'OPEN',
                '2026-07-03T03:00:00Z',
                3,
                [reopenedEvent('reopen-1', '2026-07-03T02:00:00Z')],
                'state-1',
              ),
            },
          } as T;
        },
      }),
      /repeated pagination cursor state-1/,
    );

    await assert.rejects(
      listIssueFixEvidenceBatch([42], {
        snapshotMaxAttempts: 2,
        sleep: async () => undefined,
        request: async <T>(query: string): Promise<T> => {
          if (query.includes('query IssueFixEvidence')) {
            return {
              repository: {
                id: TEST_REPOSITORY_NODE_ID,
                issue0: fixEvidenceIssue({
                  state: 'CLOSED',
                  totalCount: 2,
                  stateNodes: [closedEvent('close-1', '2026-07-03T01:00:00Z')],
                  stateCursor: 'state-next',
                }),
              },
            } as T;
          }
          return {
            repository: {
              id: TEST_REPOSITORY_NODE_ID,
              issue: stateEventPage(
                'CLOSED',
                '2026-07-03T03:00:00Z',
                3,
                [closedEvent('close-2', '2026-07-03T02:00:00Z')],
              ),
            },
          } as T;
        },
      }),
      /failed to stabilize after 2 attempts.*totalCount grew beyond frozen boundary from 2 to 3/,
    );
  });

  it('omits explicitly reported missing issue aliases from verified fix evidence', async () => {
    let calls = 0;
    const missing: Array<{ issueNumber: number; aliasIndex: number }> = [];
    const evidence = await listIssueFixEvidenceBatch([42, 43], {
      onMissingIssueAlias: (event) => missing.push(event),
      request: async <T>(): Promise<T> => {
        calls++;
        if (calls === 1) {
          throw new Error(
            'GitHub GraphQL error: repository.issue0: Could not resolve to an Issue with the number of 42',
          );
        }
        return {
          repository: {
            id: TEST_REPOSITORY_NODE_ID,
            issue0: fixEvidenceIssue({
              issueNumber: 43,
              state: 'OPEN',
              totalCount: 0,
            }),
          },
        } as T;
      },
    });

    assert.deepEqual(missing, [{ issueNumber: 42, aliasIndex: 0 }]);
    assert.equal(evidence.has(42), false);
    assert.equal(evidence.get(43)?.stateSnapshot.issueState, 'open');
  });

  it('paginates release status check contexts with remote identity fields', () => {
    const query = __githubTest.buildReleaseCommitQuery();

    assert.match(query, /\$after: String/);
    assert.match(query, /tagCommit \{\s+oid/);
    assert.match(query, /statusCheckRollup \{\s+id\s+state/);
    assert.match(query, /contexts\(first: 100, after: \$after\)/);
    assert.match(query, /totalCount/);
    assert.match(query, /\.\.\. on CheckRun \{\s+id/);
    assert.match(query, /\.\.\. on StatusContext \{\s+id/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('attests release status check pagination against tag, rollup, and count drift', async () => {
    const firstPage = releaseCommitPage({
      totalCount: 2,
      nodes: [releaseCheckContext('build')],
      nextCursor: 'cursor-1',
    });
    const stableSweep = [
      firstPage,
      releaseCommitPage({
        totalCount: 2,
        nodes: [releaseCheckContext('test')],
      }),
    ];
    const stablePages = [
      ...stableSweep,
      structuredClone(stableSweep[0]),
      structuredClone(stableSweep[1]),
    ];
    const commit = await getReleaseCommit('v1', {
      request: async <T>(): Promise<T> => stablePages.shift() as T,
    });
    assert.equal(commit.oid, 'a'.repeat(40));
    assert.equal(commit.checkTotal, 2);
    assert.deepEqual(commit.checkContexts.map((context) => context.name), ['build', 'test']);

    const driftCases = [
      {
        name: 'tag OID',
        second: releaseCommitPage({
          tagOid: 'b'.repeat(40),
          totalCount: 2,
          nodes: [releaseCheckContext('test')],
        }),
        error: /tag OID changed within pagination/,
      },
      {
        name: 'rollup identity',
        second: releaseCommitPage({
          rollupId: 'ROLLUP_2',
          totalCount: 2,
          nodes: [releaseCheckContext('test')],
        }),
        error: /status check rollup identity changed within pagination/,
      },
      {
        name: 'context totalCount',
        second: releaseCommitPage({
          totalCount: 3,
          nodes: [releaseCheckContext('test')],
        }),
        error: /status check context totalCount changed within pagination/,
      },
    ];
    for (const driftCase of driftCases) {
      const pages = [firstPage, driftCase.second];
      await assert.rejects(
        getReleaseCommit('v1', {
          request: async <T>(): Promise<T> => pages.shift() as T,
        }),
        driftCase.error,
        driftCase.name,
      );
    }
  });

  it('rejects a tag retargeted after catalog attestation', async () => {
    let calls = 0;
    await assert.rejects(
      getReleaseCommit('v1', {
        expectedTagOid: 'a'.repeat(40),
        request: async <T>(): Promise<T> => {
          calls++;
          return releaseCommitPage({
            tagOid: 'b'.repeat(40),
            totalCount: 1,
            nodes: [releaseCheckContext('build')],
          }) as T;
        },
      }),
      /tag OID does not match catalog attestation/,
    );
    assert.equal(calls, 1);
  });

  it('rejects a terminal release status check page that omits attested contexts', async () => {
    await assert.rejects(
      getReleaseCommit('v1', {
        request: async <T>(): Promise<T> => releaseCommitPage({
          totalCount: 2,
          nodes: [releaseCheckContext('build')],
        }) as T,
      }),
      /status check contexts exhausted with 1 nodes, but totalCount was 2/,
    );
  });

  it('rejects duplicate release check identities and stabilizes content across complete sweeps', async () => {
    await assert.rejects(
      getReleaseCommit('v1', {
        request: async <T>(): Promise<T> => releaseCommitPage({
          totalCount: 2,
          nodes: [
            releaseCheckContext('build', 'SUCCESS', 'CHECK_duplicate'),
            releaseCheckContext('test', 'SUCCESS', 'CHECK_duplicate'),
          ],
        }) as T,
      }),
      /duplicate context node ID CHECK_duplicate/,
    );

    const conclusions = ['SUCCESS', 'FAILURE', 'FAILURE'];
    let calls = 0;
    const commit = await getReleaseCommit('v1', {
      request: async <T>(): Promise<T> => {
        const conclusion = conclusions[calls++] ?? 'FAILURE';
        return releaseCommitPage({
          rollupState: conclusion === 'SUCCESS' ? 'SUCCESS' : 'FAILURE',
          totalCount: 1,
          nodes: [releaseCheckContext('build', conclusion)],
        }) as T;
      },
    });
    assert.equal(calls, 3);
    assert.equal(commit.checkFailure, 1);
    assert.equal(commit.checkContexts[0].conclusion, 'FAILURE');

    let unstableCalls = 0;
    await assert.rejects(
      getReleaseCommit('v1', {
        request: async <T>(): Promise<T> => {
          unstableCalls++;
          return releaseCommitPage({
            rollupState: unstableCalls % 2 === 0 ? 'FAILURE' : 'SUCCESS',
            totalCount: 1,
            nodes: [releaseCheckContext(
              'build',
              unstableCalls % 2 === 0 ? 'FAILURE' : 'SUCCESS',
            )],
          }) as T;
        },
      }),
      /failed to stabilize after 3 complete sweeps/,
    );
    assert.equal(unstableCalls, 3);
  });

  it('classifies every release-check state exhaustively and blocks unknown values', async () => {
    const nodes = [
      releaseCheckContext('success', 'SUCCESS'),
      releaseCheckContext('skipped', 'SKIPPED'),
      releaseCheckContext('neutral', 'NEUTRAL'),
      releaseCheckContext('action-required', 'ACTION_REQUIRED'),
      releaseCheckContext('cancelled', 'CANCELLED'),
      releaseCheckContext('failure', 'FAILURE'),
      releaseCheckContext('stale', 'STALE'),
      releaseCheckContext('startup-failure', 'STARTUP_FAILURE'),
      releaseCheckContext('timed-out', 'TIMED_OUT'),
      releaseCheckContext('in-progress', null, 'CHECK_in_progress', 'IN_PROGRESS'),
      releaseCheckContext('pending', null, 'CHECK_pending', 'PENDING'),
      releaseCheckContext('queued', null, 'CHECK_queued', 'QUEUED'),
      releaseCheckContext('requested', null, 'CHECK_requested', 'REQUESTED'),
      releaseCheckContext('waiting', null, 'CHECK_waiting', 'WAITING'),
      releaseCheckContext(
        'unknown-conclusion',
        'FUTURE_CONCLUSION',
        'CHECK_unknown_conclusion',
        'QUEUED',
      ),
      releaseCheckContext('unknown-status', null, 'CHECK_unknown_status', 'FUTURE_STATUS'),
      releaseStatusContext('status-success', 'SUCCESS'),
      releaseStatusContext('status-error', 'ERROR'),
      releaseStatusContext('status-failure', 'FAILURE'),
      releaseStatusContext('status-pending', 'PENDING'),
      releaseStatusContext('status-expected', 'EXPECTED'),
      releaseStatusContext('status-unknown', 'FUTURE_STATE'),
    ];
    const commit = await getReleaseCommit('v-all-states', {
      request: async <T>(): Promise<T> => releaseCommitPage({
        rollupState: 'FAILURE',
        totalCount: nodes.length,
        nodes,
      }) as T,
    });

    assert.deepEqual(
      {
        total: commit.checkTotal,
        success: commit.checkSuccess,
        failure: commit.checkFailure,
        pending: commit.checkPending,
        skipped: commit.checkSkipped,
      },
      {
        total: 22,
        success: 2,
        failure: 11,
        pending: 7,
        skipped: 2,
      },
    );
    assert.equal(
      commit.checkSuccess +
        commit.checkFailure +
        commit.checkPending +
        commit.checkSkipped,
      commit.checkTotal,
    );
  });

  it('rejects release-check aggregate states inconsistent with source buckets', async () => {
    await assert.rejects(
      getReleaseCommit('v-bad-aggregate', {
        request: async <T>(): Promise<T> => releaseCommitPage({
          rollupState: 'SUCCESS',
          totalCount: 1,
          nodes: [releaseCheckContext('build', 'STARTUP_FAILURE')],
        }) as T,
      }),
      /status check aggregate SUCCESS is inconsistent/,
    );

    await assert.rejects(
      getReleaseCommit('v-unknown-aggregate', {
        request: async <T>(): Promise<T> => releaseCommitPage({
          rollupState: 'FUTURE_STATE',
          totalCount: 1,
          nodes: [releaseCheckContext('build', 'SUCCESS')],
        }) as T,
      }),
      /unsupported status check rollup state "FUTURE_STATE"/,
    );
  });

  it('holds the advisory permit through body consumption and HTTP cooldown registration', async () => {
    const gate = deferred();
    const events: string[] = [];
    const cooldowns: number[] = [];
    let fetchCalls = 0;
    const request = __githubTest.createRepositorySecurityAdvisoryPageRequester({
      fetchImpl: (async () => {
        fetchCalls++;
        events.push(`fetch-${fetchCalls}`);
        if (fetchCalls === 1) {
          const body = new ReadableStream<Uint8Array>({
            async pull(controller) {
              events.push('body-start');
              await gate.promise;
              controller.enqueue(new TextEncoder().encode(
                '{"message":"You have exceeded a secondary rate limit"}',
              ));
              events.push('body-consumed');
              controller.close();
            },
          }, { highWaterMark: 0 });
          return new Response(body, { status: 403 });
        }
        return new Response('[]', { status: 200 });
      }) as typeof fetch,
      scheduler: serialScheduler(events, cooldowns),
      requestHeaders: () => ({}),
      maxRetries: 0,
      random: () => 0,
      warn: () => undefined,
    });
    const input = {
      owner: 'openclaw',
      repo: 'openclaw',
      after: null,
      pageSize: 100,
      state: 'published',
      sort: 'updated',
      direction: 'desc',
    } as const;

    const first = request(input);
    const second = request(input);
    await waitFor(() => events.includes('body-start'));
    assert.equal(fetchCalls, 1);

    gate.resolve();
    const results = await Promise.allSettled([first, second]);
    assert.equal(results[0].status, 'rejected');
    assert.deepEqual(
      results[1].status === 'fulfilled' ? results[1].value : null,
      {
        nodes: [],
        nextCursor: null,
        completeness: {
          terminal: false,
          proven: false,
          evidence: 'missing-link',
          linkHeaderPresent: false,
        },
      },
    );
    assert.deepEqual(cooldowns, [60_000]);
    assert.ok(events.indexOf('body-consumed') < events.indexOf('cooldown'));
    assert.ok(events.indexOf('cooldown') < events.indexOf('fetch-2'));
  });

  it('requires an exact HTTP 200 repository advisory response', async () => {
    const request = __githubTest.createRepositorySecurityAdvisoryPageRequester({
      fetchImpl: (async () =>
        new Response('[]', { status: 206 })) as typeof fetch,
      scheduler: immediateScheduler(),
      requestHeaders: () => ({}),
      maxRetries: 0,
      warn: () => undefined,
    });

    await assert.rejects(
      request({
        owner: 'openclaw',
        repo: 'openclaw',
        after: null,
        pageSize: 100,
        state: 'published',
        sort: 'updated',
        direction: 'desc',
      }),
      /repository security advisories HTTP 206/,
    );
  });

  it('cancels a repository advisory rate-limit retry delay without another fetch', async () => {
    let fetchCalls = 0;
    let sleepStarted = false;
    const request = __githubTest.createRepositorySecurityAdvisoryPageRequester({
      fetchImpl: (async () => {
        fetchCalls++;
        return new Response('{"message":"rate limit"}', {
          status: 429,
          headers: { 'retry-after': '120' },
        });
      }) as typeof fetch,
      scheduler: immediateScheduler(),
      sleep: async () => {
        sleepStarted = true;
        await new Promise<void>(() => undefined);
      },
      requestHeaders: () => ({}),
      maxRetries: 2,
      warn: () => undefined,
    });
    const controller = new AbortController();
    const abortReason = new Error('caller cancelled advisory retry');
    const pending = request({
      owner: 'openclaw',
      repo: 'openclaw',
      after: null,
      pageSize: 100,
      state: 'published',
      sort: 'updated',
      direction: 'desc',
      signal: controller.signal,
    });

    await waitFor(() => sleepStarted);
    controller.abort(abortReason);
    await assert.rejects(pending, (error) => error === abortReason);
    assert.equal(fetchCalls, 1);
  });

  it('rejects oversized advisory error Content-Length before reading and cancels the body', async () => {
    let fetchCalls = 0;
    let readerRequests = 0;
    let cancels = 0;
    const body = {
      getReader() {
        readerRequests++;
        throw new Error('body reader must not be acquired');
      },
      cancel() {
        cancels++;
        return Promise.resolve();
      },
    } as unknown as ReadableStream<Uint8Array>;
    const response = {
      ok: false,
      status: 503,
      headers: new Headers({ 'content-length': '9' }),
      body,
    } as Response;
    const request = __githubTest.createRepositorySecurityAdvisoryPageRequester({
      fetchImpl: (async () => {
        fetchCalls++;
        return response;
      }) as typeof fetch,
      scheduler: immediateScheduler(),
      requestHeaders: () => ({}),
      errorBodyMaxBytes: 8,
      maxRetries: 5,
      warn: () => undefined,
    });

    await assert.rejects(
      request({
        owner: 'openclaw',
        repo: 'openclaw',
        after: null,
        pageSize: 100,
        state: 'published',
        sort: 'updated',
        direction: 'desc',
      }),
      /advisory error response body exceeds 8 bytes/,
    );
    assert.equal(fetchCalls, 1);
    assert.equal(readerRequests, 0);
    assert.equal(cancels, 1);
  });

  it('builds the exhaustive repository advisory URL without a package filter', () => {
    const url = new URL(__githubTest.buildRepositorySecurityAdvisoriesUrl({
      owner: 'openclaw',
      repo: 'openclaw',
      after: 'cursor-value',
      pageSize: 100,
      direction: 'asc',
    }));

    assert.equal(url.pathname, '/repos/openclaw/openclaw/security-advisories');
    assert.equal(url.searchParams.get('state'), 'published');
    assert.equal(url.searchParams.get('sort'), 'updated');
    assert.equal(url.searchParams.get('direction'), 'asc');
    assert.equal(url.searchParams.get('per_page'), '100');
    assert.equal(url.searchParams.get('after'), 'cursor-value');
    assert.equal(url.searchParams.has('ecosystem'), false);
    assert.equal(url.searchParams.has('package'), false);
    assert.throws(
      () => __githubTest.buildRepositorySecurityAdvisoriesUrl({
        owner: 'openclaw',
        repo: 'openclaw',
        after: null,
        pageSize: 99,
        direction: 'desc',
      }),
      /page size must be exactly 100/,
    );

    const link =
      '<https://api.github.com/repositories/1103012935/security-advisories?' +
      'state=published&sort=updated&direction=desc&per_page=100&after=next%3D>; rel="next"';
    assert.equal(__githubTest.repositorySecurityAdvisoryNextCursor(link), 'next=');
    assert.throws(
      () => __githubTest.repositorySecurityAdvisoryNextCursor(link, 'asc'),
      /inconsistent direction/,
    );
    assert.throws(
      () => __githubTest.repositorySecurityAdvisoryNextCursor(
        '<https://example.com/security-advisories?state=published&sort=updated&' +
        'direction=desc&per_page=100&after=next>; rel="next"',
      ),
      /off-origin pagination link/,
    );
    assert.throws(
      () => __githubTest.repositorySecurityAdvisoryNextCursor(
        '<https://api.github.com/repositories/1/security-advisories?state=closed&' +
        'sort=updated&direction=desc&per_page=100&after=next>; rel="next"',
      ),
      /inconsistent state/,
    );
    assert.throws(
      () => __githubTest.repositorySecurityAdvisoryNextCursor(
        '<https://api.github.com/repositories/1/security-advisories?state=published&' +
        'sort=updated&direction=desc&per_page=99&after=next>; rel="next"',
      ),
      /invalid per_page/,
    );
    assert.throws(
      () => __githubTest.repositorySecurityAdvisoryNextCursor(
        '<https://api.github.com/repositories/1/security-advisories?state=published&' +
        'sort=updated&direction=desc&per_page=100&after=next&package=openclaw>; rel="next"',
      ),
      /unexpected package parameter/,
    );
    assert.throws(
      () => __githubTest.repositorySecurityAdvisoryNextCursor(
        '<https://api.github.com/not-a-repository/security-advisories?state=published&' +
        'sort=updated&direction=desc&per_page=100&after=next>; rel="next"',
      ),
      /non-canonical pagination link/,
    );
  });

  it('builds the counted NPM/openclaw securityVulnerabilities query', () => {
    const query = __githubTest.buildSecurityVulnerabilitiesQuery();
    assert.match(query, /securityVulnerabilities\(/);
    assert.match(query, /ecosystem:\s*NPM/);
    assert.match(query, /package:\s*\$package/);
    assert.match(query, /orderBy:\s*\{\s*field:\s*UPDATED_AT,\s*direction:\s*ASC\s*\}/);
    assert.match(query, /totalCount/);
    assert.match(query, /advisory\s*\{\s*ghsaId\s+identifiers\s*\{\s*type value\s*\}/);
    assert.match(query, /permalink\s+publishedAt\s+severity\s+summary\s+withdrawnAt/);
    assert.match(query, /pageInfo\s*\{\s*hasNextPage endCursor\s*\}/);
  });

  it('runs independent advisory source sweeps concurrently', async () => {
    const gate = deferred();
    const directions = new Set<string>();
    const stableGraphql = stableSecurityVulnerabilityRequest([]);
    let graphqlCalls = 0;
    let graphqlStarted = false;
    const pending = fetchSecurityAdvisorySourceObservations({
      request: repositorySecurityAdvisoryHttpRequester((url) => {
        directions.add(String(url.searchParams.get('direction')));
        return new Response('[]', { status: 200 });
      }),
      graphqlRequest: async <T>(
        query: string,
        variables: Record<string, unknown> = {},
      ): Promise<T> => {
        graphqlCalls++;
        if (graphqlCalls === 1) {
          graphqlStarted = true;
          await gate.promise;
        }
        return stableGraphql<T>(query, variables);
      },
    });

    let concurrencyError: unknown = null;
    try {
      await waitFor(() =>
        graphqlStarted &&
        directions.has('desc') &&
        directions.has('asc'));
    } catch (error) {
      concurrencyError = error;
    } finally {
      gate.resolve();
    }
    const catalog = await pending;
    if (concurrencyError) throw concurrencyError;

    assert.equal(graphqlCalls, 2);
    assert.deepEqual([...directions].sort(), ['asc', 'desc']);
    assert.equal(catalog.observations.securityVulnerabilities.totalCount, 0);
    assert.equal(catalog.observations.repositoryAdvisories.observedAdvisoryCount, 0);
  });

  it('proves a zero GraphQL range catalog while keeping no-Link REST empty unproven', async () => {
    const directions: string[] = [];
    const request = repositorySecurityAdvisoryHttpRequester((url) => {
      directions.push(String(url.searchParams.get('direction')));
      return new Response('[]', { status: 200 });
    });

    const empty = await fetchSecurityAdvisorySourceObservations({
      request,
      graphqlRequest: stableSecurityVulnerabilityRequest([]),
      captureNow: () => '2026-07-04T12:34:56Z',
    });

    assert.deepEqual(
      directions.slice().sort(),
      ['asc', 'asc', 'desc', 'desc'],
    );
    assert.equal(empty.advisories.length, 0);
    assert.equal(empty.metadata.exhausted, false);
    assert.equal(empty.metadata.totalCount, null);
    assert.equal(empty.metadata.pagesFetched, 4);
    assert.equal(empty.metadata.sweepCount, 4);
    assert.deepEqual(empty.metadata.completeness, {
      terminalPageProven: false,
      terminalPageEvidence: 'unproven-no-link',
      terminalPageLinkHeaderPresent: false,
      remoteTotalCount: null,
      enumeratedCount: 0,
      crossOrderVerified: true,
      boundaryEvidence: {
        updatedAtDesc: {
          mode: 'single-page-no-link',
          linkHeaderPresent: false,
          pageCount: 1,
          sweepCount: 2,
        },
        updatedAtAsc: {
          mode: 'single-page-no-link',
          linkHeaderPresent: false,
          pageCount: 1,
          sweepCount: 2,
        },
      },
    });
    assert.deepEqual(empty.observations.securityVulnerabilities.rangeIdentities, []);
    assert.equal(empty.observations.securityVulnerabilities.exhausted, true);
    assert.equal(empty.observations.securityVulnerabilities.stabilized, true);
    assert.equal(empty.observations.securityVulnerabilities.totalCount, 0);
    assert.equal(empty.observations.securityVulnerabilities.nodeCount, 0);
    assert.equal(empty.observations.securityVulnerabilities.pagesFetched, 2);
    assert.equal(empty.observations.securityVulnerabilities.sweepCount, 2);
    assert.deepEqual(empty.observations.securityVulnerabilities.retrieval, {
      startedAt: '2026-07-04T12:34:56.000Z',
      completedAt: '2026-07-04T12:34:56.000Z',
    });
    assert.equal(empty.observations.repositoryAdvisories.exhausted, false);
    assert.deepEqual(empty.observations.repositoryAdvisories.retrieval, {
      startedAt: '2026-07-04T12:34:56.000Z',
      completedAt: '2026-07-04T12:34:56.000Z',
    });
    assert.match(
      JSON.stringify(empty.observations),
      /"retrieval":\{"startedAt":"2026-07-04T12:34:56.000Z","completedAt":"2026-07-04T12:34:56.000Z"\}/,
    );
    assert.equal(empty.reconciliation.graphqlSecurityVulnerabilities.totalCount, 0);
    assert.equal(empty.reconciliation.repositoryAdvisories.totalCount, null);
  });

  it('reports a legitimate nonempty single-page REST observation as unproven', async () => {
    const advisory = repositorySecurityAdvisoryNode();
    let calls = 0;
    const request = repositorySecurityAdvisoryHttpRequester(() => {
      calls++;
      return new Response(JSON.stringify([advisory]), { status: 200 });
    });

    const catalog = await fetchSecurityAdvisorySourceObservations({
      request,
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode(),
      ]),
    });

    assert.equal(calls, 4);
    assert.deepEqual(catalog.advisories.map(({ ghsa_id }) => ghsa_id), [
      advisory.ghsa_id,
    ]);
    assert.equal(catalog.metadata.exhausted, false);
    assert.equal(catalog.metadata.totalCount, null);
    assert.equal(catalog.metadata.completeness.terminalPageProven, false);
    assert.match(catalog.metadata.identityDigest, /^[0-9a-f]{64}$/);
    assert.equal(
      catalog.metadata.completeness.boundaryEvidence.updatedAtDesc.mode,
      'single-page-no-link',
    );
    assert.equal(
      catalog.metadata.completeness.boundaryEvidence.updatedAtAsc.mode,
      'single-page-no-link',
    );
    await assert.rejects(
      () => listSecurityAdvisories({
        request,
        graphqlRequest: stableSecurityVulnerabilityRequest([
          securityVulnerabilityNode(),
        ]),
      }),
      /enumeration is unproven.*reconciliation is required/,
    );
  });

  it('fails closed on a full first REST page without Link evidence', async () => {
    const request = repositorySecurityAdvisoryHttpRequester(() =>
      new Response(
        JSON.stringify(Array.from({ length: 100 }, () => null)),
        { status: 200 },
      ));

    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({ request }),
      /full page of 100 without Link evidence; exhaustion is ambiguous/,
    );
  });

  it('rejects terminal REST Link evidence that is not backed by a paging cursor', async () => {
    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async () =>
          cursorTerminalAdvisoryPage([repositorySecurityAdvisoryNode()]),
      }),
      /terminal Link evidence is not cursor-backed/,
    );
  });

  it('fails closed on GraphQL securityVulnerabilities count and page drift', async () => {
    const older = securityVulnerabilityNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      updatedAt: '2026-07-01T00:00:00Z',
    });
    const newer = securityVulnerabilityNode({
      updatedAt: '2026-07-02T00:00:00Z',
    });
    await assert.rejects(
      () => __githubTest.fetchSecurityVulnerabilitySweep({
        graphqlRequest: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => (
          variables.after == null
            ? securityVulnerabilitiesPage(2, [older], 'cursor-1')
            : securityVulnerabilitiesPage(3, [newer])
        ) as T,
      }),
      /totalCount changed within sweep from 2 to 3/,
    );

    let rootRequests = 0;
    await assert.rejects(
      () => fetchSecurityAdvisorySourceObservations({
        graphqlRequest: async <T>(
          _query: string,
          variables: Record<string, unknown> = {},
        ): Promise<T> => {
          if (variables.after == null) {
            rootRequests++;
            return (
              rootRequests % 2 === 1
                ? securityVulnerabilitiesPage(2, [older, newer])
                : securityVulnerabilitiesPage(2, [older], 'cursor-2')
            ) as T;
          }
          return securityVulnerabilitiesPage(2, [newer]) as T;
        },
        request: async () => unprovenAdvisoryPage([]),
      }),
      /failed to stabilize after 3 complete sweeps/,
    );
    assert.equal(rootRequests, 3);
  });

  it('rejects omitted GraphQL vulnerability pages and duplicate canonical ranges', async () => {
    const range = securityVulnerabilityNode();
    await assert.rejects(
      () => __githubTest.fetchSecurityVulnerabilitySweep({
        graphqlRequest: async <T>(): Promise<T> =>
          securityVulnerabilitiesPage(2, [range]) as T,
      }),
      /terminal unique count 1 did not match totalCount 2/,
    );
    const duplicateRange = securityVulnerabilityNode({
      vulnerableVersionRange: '  >= 2026.6.5,   < 2026.6.9  ',
    });
    await assert.rejects(
      () => __githubTest.fetchSecurityVulnerabilitySweep({
        graphqlRequest: async <T>(): Promise<T> =>
          securityVulnerabilitiesPage(2, [range, duplicateRange]) as T,
      }),
      /duplicate canonical range/,
    );
  });

  it('rejects GraphQL vulnerability rows outside the NPM/openclaw filter', async () => {
    for (const node of [
      securityVulnerabilityNode({ ecosystem: 'PIP' }),
      securityVulnerabilityNode({ packageName: '@openclaw/feishu' }),
    ]) {
      await assert.rejects(
        () => __githubTest.fetchSecurityVulnerabilitySweep({
          graphqlRequest: async <T>(): Promise<T> =>
            securityVulnerabilitiesPage(1, [node]) as T,
        }),
        /outside NPM:openclaw/,
      );
    }
  });

  it('binds complete GraphQL advisory metadata and rejects unsupported authority fields', async () => {
    const range = await __githubTest.fetchSecurityVulnerabilitySweep({
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode({ severity: 'MODERATE' }),
      ]),
    });
    assert.deepEqual(
      range.ranges.map((item) => ({
        cveId: item.cveId,
        summary: item.summary,
        severity: item.severity,
        htmlUrl: item.htmlUrl,
        publishedAt: item.publishedAt,
        withdrawnAt: item.withdrawnAt,
      })),
      [{
        cveId: 'CVE-2026-27208',
        summary: 'Summary for GHSA-wgq8-x5wm-g4rw',
        severity: 'medium',
        htmlUrl: 'https://github.com/advisories/GHSA-wgq8-x5wm-g4rw',
        publishedAt: '2026-06-30T00:00:00Z',
        withdrawnAt: null,
      }],
    );

    const withdrawnRange = await __githubTest.fetchSecurityVulnerabilitySweep({
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode({
          withdrawnAt: '2026-07-01T00:00:00Z',
          updatedAt: '2026-07-01T00:00:01Z',
        }),
      ]),
    });
    assert.equal(
      withdrawnRange.ranges[0]?.withdrawnAt,
      '2026-07-01T00:00:00Z',
    );
    const canonicalPackageRange = await __githubTest.fetchSecurityVulnerabilitySweep({
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode({ packageName: 'OpenClaw' }),
      ]),
    });
    assert.equal(canonicalPackageRange.ranges[0]?.packageName, 'openclaw');

    for (const node of [
      securityVulnerabilityNode({ severity: 'UNKNOWN' }),
      securityVulnerabilityNode({ permalink: 'https://example.com/advisories/GHSA-wgq8-x5wm-g4rw' }),
      securityVulnerabilityNode({ withdrawnAt: '2026-06-29T00:00:00Z' }),
      securityVulnerabilityNode({ identifiers: [] }),
    ]) {
      await assert.rejects(
        () => __githubTest.fetchSecurityVulnerabilitySweep({
          graphqlRequest: async <T>(): Promise<T> =>
            securityVulnerabilitiesPage(1, [node]) as T,
        }),
        /unsupported advisory severity|inconsistent advisory permalink|withdrawnAt before advisory publication|inconsistent advisory identifiers/,
      );
    }
  });

  it('rejects stable same-count no-Link prefixes that disagree across ordered HTTP sweeps', async () => {
    const newest = repositorySecurityAdvisoryNode({
      updatedAt: '2026-07-02T00:00:00Z',
    });
    const oldest = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      updatedAt: '2026-07-01T00:00:00Z',
    });
    let calls = 0;
    const request = repositorySecurityAdvisoryHttpRequester((url) => {
      calls++;
      const direction = url.searchParams.get('direction');
      return new Response(JSON.stringify([direction === 'desc' ? newest : oldest]), {
        status: 200,
      });
    });

    await assert.rejects(
      () => fetchSecurityAdvisorySourceObservations({
        request,
        graphqlRequest: stableSecurityVulnerabilityRequest([]),
      }),
      /cross-order advisory\/range identity mismatch/,
    );
    assert.equal(calls, 4);
  });

  it('rejects cross-order HTTP catalogs with matching identities but different content', async () => {
    const descending = repositorySecurityAdvisoryNode({
      summary: 'Descending snapshot',
    });
    const ascending = repositorySecurityAdvisoryNode({
      summary: 'Ascending snapshot',
    });
    const request = repositorySecurityAdvisoryHttpRequester((url) =>
      new Response(JSON.stringify([
        url.searchParams.get('direction') === 'desc' ? descending : ascending,
      ]), { status: 200 }));

    await assert.rejects(
      () => fetchSecurityAdvisorySourceObservations({
        request,
        graphqlRequest: stableSecurityVulnerabilityRequest([]),
      }),
      /cross-order canonical content mismatch/,
    );
  });

  it('accepts multipage HTTP catalogs only after both orders exhaust Link pagination', async () => {
    const newer = repositorySecurityAdvisoryNode({
      updatedAt: '2026-07-02T00:00:00Z',
    });
    const older = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      updatedAt: '2026-07-01T00:00:00Z',
    });
    const requests: Array<{ direction: string; after: string | null }> = [];
    const request = repositorySecurityAdvisoryHttpRequester((url) => {
      const direction = url.searchParams.get('direction') as 'asc' | 'desc';
      const after = url.searchParams.get('after');
      requests.push({ direction, after });
      const first = direction === 'desc' ? newer : older;
      const second = direction === 'desc' ? older : newer;
      if (after == null) {
        return new Response(JSON.stringify([first]), {
          status: 200,
          headers: {
            link: repositorySecurityAdvisoryPaginationLink(
              direction,
              'next',
              `${direction}-page-2`,
            ),
          },
        });
      }
      assert.equal(after, `${direction}-page-2`);
      return new Response(JSON.stringify([second]), {
        status: 200,
        headers: {
          link: repositorySecurityAdvisoryPaginationLink(
            direction,
            'prev',
            `${direction}-page-1`,
          ),
        },
      });
    });

    const catalog = await listSecurityAdvisories({
      request,
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode({
          ghsaId: older.ghsa_id,
          updatedAt: older.updated_at,
        }),
        securityVulnerabilityNode({
          ghsaId: newer.ghsa_id,
          updatedAt: newer.updated_at,
        }),
      ]),
    });

    assert.equal(requests.length, 8);
    assert.equal(
      requests.filter(({ direction }) => direction === 'desc').length,
      4,
    );
    assert.equal(
      requests.filter(({ direction }) => direction === 'asc').length,
      4,
    );
    assert.deepEqual(catalog.advisories.map(({ ghsa_id }) => ghsa_id), [
      newer.ghsa_id,
      older.ghsa_id,
    ]);
    assert.equal(catalog.metadata.pageCount, 2);
    assert.equal(catalog.metadata.pagesFetched, 8);
    assert.equal(catalog.metadata.sweepCount, 4);
    assert.equal(catalog.metadata.completeness.terminalPageLinkHeaderPresent, true);
    assert.equal(catalog.metadata.completeness.terminalPageProven, true);
    assert.equal(catalog.metadata.completeness.terminalPageEvidence, 'link-exhausted');
    assert.equal(catalog.metadata.totalCount, 2);
    assert.equal(
      catalog.metadata.completeness.boundaryEvidence.updatedAtDesc.mode,
      'link-exhausted',
    );
    assert.equal(
      catalog.metadata.completeness.boundaryEvidence.updatedAtAsc.mode,
      'link-exhausted',
    );
  });

  it('rejects a multipage HTTP terminal response that omits Link after a cursor', async () => {
    const newer = repositorySecurityAdvisoryNode({
      updatedAt: '2026-07-02T00:00:00Z',
    });
    const older = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      updatedAt: '2026-07-01T00:00:00Z',
    });
    const calls = { asc: 0, desc: 0 };
    const request = repositorySecurityAdvisoryHttpRequester((url) => {
      const direction = url.searchParams.get('direction') as 'asc' | 'desc';
      calls[direction]++;
      if (url.searchParams.get('after') == null) {
        return new Response(JSON.stringify([newer]), {
          status: 200,
          headers: {
            link: repositorySecurityAdvisoryPaginationLink(
              direction,
              'next',
              'page-2',
            ),
          },
        });
      }
      return new Response(JSON.stringify([older]), { status: 200 });
    });

    await assert.rejects(
      () => listSecurityAdvisories({
        request,
        graphqlRequest: stableSecurityVulnerabilityRequest([]),
      }),
      /terminal page after a cursor omitted Link evidence/,
    );
    assert.ok(calls.asc >= 1 && calls.asc <= 2);
    assert.ok(calls.desc >= 1 && calls.desc <= 2);
  });

  it('maps repository-only advisories and retains every repository package row', () => {
    const preservedRange = '<= 2026.6.6 || >= 2026.7.0, < 2026.7.2';
    const mapped = __githubTest.mapRepositorySecurityAdvisories([
      repositorySecurityAdvisoryNode({
        ghsaId: 'GHSA-wgq8-x5wm-g4rw',
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '>= 2026.6.5, < 2026.6.9',
          patched_versions: '2026.6.9',
        }],
      }),
      repositorySecurityAdvisoryNode({
        ghsaId: 'GHSA-w8wf-3qvj-6xqf',
        severity: 'high',
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: '@openclaw/feishu' },
          vulnerable_version_range: preservedRange,
          patched_versions: '2026.6.9, 2026.7.2',
        }],
      }),
      repositorySecurityAdvisoryNode({
        ghsaId: 'GHSA-65rx-fvh6-r4h2',
        cveId: 'CVE-2026-27209',
        severity: 'high',
        withdrawnAt: '2026-07-01T00:00:00Z',
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '<= 2026.2.19-2',
          patched_versions: '>=2026.2.21',
        }],
      }),
    ]).map(({ advisory }) => advisory);

    assert.deepEqual(mapped.map((advisory) => advisory.ghsa_id), [
      'GHSA-wgq8-x5wm-g4rw',
      'GHSA-w8wf-3qvj-6xqf',
      'GHSA-65rx-fvh6-r4h2',
    ]);
    assert.equal(mapped[1].vulnerabilities[0].package?.name, '@openclaw/feishu');
    assert.equal(mapped[1].vulnerabilities[0].vulnerable_version_range, preservedRange);
    assert.equal(mapped[1].vulnerabilities[0].patched_versions, '2026.6.9, 2026.7.2');
    assert.equal(mapped[2].cve_id, 'CVE-2026-27209');
    assert.equal(mapped[2].severity, 'high');
    assert.equal(mapped[2].state, 'withdrawn');
    assert.equal(mapped[2].withdrawn_at, '2026-07-01T00:00:00Z');
  });

  it('returns mixed-package REST observations and target-only reconciliation identities', async () => {
    const advisory = repositorySecurityAdvisoryNode({
      vulnerabilities: [
        {
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '>= 2026.6.5, < 2026.6.9',
          patched_versions: '2026.6.9',
        },
        {
          package: { ecosystem: 'npm', name: '@openclaw/feishu' },
          vulnerable_version_range: '<= 2026.6.6',
          patched_versions: '2026.6.9',
        },
      ],
    });
    const catalog = await fetchSecurityAdvisorySourceObservations({
      request: repositorySecurityAdvisoryHttpRequester(() =>
        new Response(JSON.stringify([advisory]), { status: 200 })),
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode(),
      ]),
    });

    const rest = catalog.observations.repositoryAdvisories;
    assert.equal(rest.observedAdvisoryCount, 1);
    assert.equal(rest.observedRangeCount, 2);
    assert.equal(rest.targetRangeCount, 1);
    assert.equal(rest.allRangeIdentities.length, 2);
    assert.equal(rest.targetRangeIdentities.length, 1);
    assert.deepEqual(
      catalog.reconciliation.repositoryAdvisories.rangeIdentities,
      catalog.reconciliation.graphqlSecurityVulnerabilities.rangeIdentities,
    );
    assert.equal(
      catalog.reconciliation.repositoryAdvisories.identityDigest,
      catalog.reconciliation.graphqlSecurityVulnerabilities.identityDigest,
    );
    assert.equal(catalog.reconciliation.repositoryAdvisories.totalCount, null);
    assert.equal(catalog.reconciliation.repositoryAdvisories.completenessProven, false);
  });

  it('requires exact normalized repository advisory severity values', () => {
    for (const severity of ['HIGH', 'MODERATE', 'unknown']) {
      assert.throws(
        () => __githubTest.mapRepositorySecurityAdvisories([
          repositorySecurityAdvisoryNode({ severity }),
        ]),
        /invalid severity/,
      );
    }
  });

  it('exhausts repository advisory pagination and stabilizes complete canonical counts', async () => {
    const first = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-wgq8-x5wm-g4rw',
      updatedAt: '2026-07-02T00:00:00Z',
      vulnerabilities: [
        {
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '>= 2026.6.5, < 2026.6.9',
          patched_versions: '2026.6.9',
        },
        {
          package: { ecosystem: 'npm', name: '@openclaw/feishu' },
          vulnerable_version_range: '<= 2026.6.6',
          patched_versions: '2026.6.9',
        },
      ],
    });
    const second = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      severity: 'high',
      updatedAt: '2026-07-01T00:00:00Z',
    });
    const requests: Array<{
      owner: string;
      repo: string;
      after: string | null;
      pageSize: number;
      state: string;
      sort: string;
      direction: string;
    }> = [];
    const catalog = await listSecurityAdvisories({
      request: async (input) => {
        requests.push(input);
        const firstNode = input.direction === 'desc' ? first : second;
        const secondNode = input.direction === 'desc' ? second : first;
        return input.after == null
          ? cursorNonTerminalAdvisoryPage(
              [firstNode],
              `cursor-${input.direction}`,
            )
          : cursorTerminalAdvisoryPage([secondNode]);
      },
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode({
          ghsaId: second.ghsa_id,
          updatedAt: second.updated_at,
        }),
        securityVulnerabilityNode({
          ghsaId: first.ghsa_id,
          updatedAt: first.updated_at,
        }),
      ]),
    });

    for (const direction of ['desc', 'asc']) {
      const directional = requests.filter((request) =>
        request.direction === direction);
      assert.deepEqual(
        directional.map(({ after }) => after),
        [null, `cursor-${direction}`, null, `cursor-${direction}`],
      );
      assert.deepEqual(
        directional.map(({ owner, repo, pageSize, state, sort }) => ({
          owner,
          repo,
          pageSize,
          state,
          sort,
        })),
        Array.from({ length: 4 }, () => ({
          owner: 'openclaw',
          repo: 'openclaw',
          pageSize: 100,
          state: 'published',
          sort: 'updated',
        })),
      );
    }
    assert.deepEqual(catalog.metadata, {
      exhausted: true,
      stabilized: true,
      totalCount: 2,
      nodeCount: 2,
      pageCount: 2,
      pagesFetched: 8,
      sweepCount: 4,
      digest: catalog.metadata.digest,
      identityDigest: catalog.metadata.identityDigest,
      completeness: {
        terminalPageProven: true,
        terminalPageEvidence: 'link-exhausted',
        terminalPageLinkHeaderPresent: true,
        remoteTotalCount: null,
        enumeratedCount: 2,
        crossOrderVerified: true,
        boundaryEvidence: {
          updatedAtDesc: {
            mode: 'link-exhausted',
            linkHeaderPresent: true,
            pageCount: 2,
            sweepCount: 2,
          },
          updatedAtAsc: {
            mode: 'link-exhausted',
            linkHeaderPresent: true,
            pageCount: 2,
            sweepCount: 2,
          },
        },
      },
      sourceOrder: 'UPDATED_AT_DESC',
    });
    assert.match(catalog.metadata.digest, /^[0-9a-f]{64}$/);
    assert.match(catalog.metadata.identityDigest, /^[0-9a-f]{64}$/);
    assert.equal(catalog.advisories[0].ghsa_id, 'GHSA-wgq8-x5wm-g4rw');
    assert.equal(catalog.advisories[0].vulnerabilities.length, 2);
    assert.equal(catalog.advisories[0].vulnerabilities[1].package?.name, '@openclaw/feishu');
  });

  it('retries a mutated repository advisory sweep until consecutive digests match', async () => {
    const ranges = {
      desc: ['< 2.0.0', '< 2.1.0', '< 2.1.0'],
      asc: ['< 2.1.0', '< 2.1.0'],
    };
    const calls = { desc: 0, asc: 0 };
    const currentRange = { desc: '', asc: '' };
    const companion = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      updatedAt: '2026-07-01T00:00:00Z',
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: '@openclaw/feishu' },
        vulnerable_version_range: '< 1.0.0',
        patched_versions: '1.0.0',
      }],
    });
    const catalog = await listSecurityAdvisories({
      request: async ({ direction, after }) => {
        if (after == null) {
          currentRange[direction] = ranges[direction][calls[direction]++];
        }
        const range = currentRange[direction];
        const target = repositorySecurityAdvisoryNode({
          updatedAt: '2026-07-02T00:00:00Z',
          vulnerabilities: [{
            package: { ecosystem: 'npm', name: 'openclaw' },
            vulnerable_version_range: range,
            patched_versions: range === '< 2.0.0' ? '2.0.0' : '2.1.0',
          }],
        });
        const first = direction === 'desc' ? target : companion;
        const second = direction === 'desc' ? companion : target;
        return after == null
          ? cursorNonTerminalAdvisoryPage([first], `${direction}-page-2`)
          : cursorTerminalAdvisoryPage([second]);
      },
      graphqlRequest: stableSecurityVulnerabilityRequest([
        securityVulnerabilityNode({
          vulnerableVersionRange: '< 2.1.0',
          firstPatchedVersion: '2.1.0',
        }),
      ]),
    });

    assert.deepEqual(calls, { desc: 3, asc: 2 });
    assert.equal(catalog.metadata.sweepCount, 5);
    assert.equal(
      catalog.advisories[0].vulnerabilities[0].vulnerable_version_range,
      '< 2.1.0',
    );
  });

  it('fails closed when repository advisory sweeps never stabilize', async () => {
    const calls = { asc: 0, desc: 0 };
    const currentRange = { asc: '', desc: '' };
    const companion = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      updatedAt: '2026-07-01T00:00:00Z',
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: '@openclaw/feishu' },
        vulnerable_version_range: '< 1.0.0',
        patched_versions: '1.0.0',
      }],
    });
    await assert.rejects(
      () => listSecurityAdvisories({
        request: async ({ direction, after }) => {
          if (after == null) {
            calls[direction]++;
            currentRange[direction] = `< ${calls[direction] + 1}.0.0`;
          }
          const target = repositorySecurityAdvisoryNode({
            updatedAt: '2026-07-02T00:00:00Z',
            vulnerabilities: [{
              package: { ecosystem: 'npm', name: 'openclaw' },
              vulnerable_version_range: currentRange[direction],
              patched_versions: `${calls[direction] + 1}.0.0`,
            }],
          });
          const first = direction === 'desc' ? target : companion;
          const second = direction === 'desc' ? companion : target;
          return after == null
            ? cursorNonTerminalAdvisoryPage([first], `${direction}-page-2`)
            : cursorTerminalAdvisoryPage([second]);
        },
        graphqlRequest: stableSecurityVulnerabilityRequest([]),
      }),
      /failed to stabilize after 3 complete sweeps/,
    );
    assert.deepEqual(calls, { asc: 3, desc: 3 });
  });

  it('fails closed on malformed advisory identities, packages, ranges, and duplicates', () => {
    assert.throws(
      () => __githubTest.mapRepositorySecurityAdvisories([null]),
      /returned null advisory/,
    );
    assert.throws(
      () => __githubTest.mapRepositorySecurityAdvisories([
        repositorySecurityAdvisoryNode({ ghsaId: 'GHSA-invalid' }),
      ]),
      /invalid GHSA id/,
    );
    assert.throws(
      () => __githubTest.mapRepositorySecurityAdvisories([
        repositorySecurityAdvisoryNode({
          identifiers: [{ type: 'GHSA', value: 'GHSA-65rx-fvh6-r4h2' }],
        }),
      ]),
      /inconsistent GHSA identifier/,
    );
    assert.throws(
      () => __githubTest.mapRepositorySecurityAdvisories([
        repositorySecurityAdvisoryNode({ vulnerabilities: [null] }),
      ]),
      /returned null vulnerability/,
    );
    const incomplete = __githubTest.mapRepositorySecurityAdvisories([
      repositorySecurityAdvisoryNode({
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: '' },
          vulnerable_version_range: null,
          patched_versions: '2.0.0',
        }],
      }),
    ]);
    assert.deepEqual(incomplete[0].advisory.vulnerabilities, [{
      package: { ecosystem: 'npm', name: '' },
      vulnerable_version_range: null,
      patched_versions: '2.0.0',
    }]);
    assert.throws(
      () => __githubTest.mapRepositorySecurityAdvisories([
        repositorySecurityAdvisoryNode({
          vulnerabilities: [{
            package: { ecosystem: 42 as unknown as string, name: 'openclaw' },
            vulnerable_version_range: '< 2.0.0',
            patched_versions: '2.0.0',
          }],
        }),
      ]),
      /invalid package identity/,
    );
    assert.throws(
      () => __githubTest.mapRepositorySecurityAdvisories([
        repositorySecurityAdvisoryNode({
          vulnerabilities: [
            {
              package: { ecosystem: 'npm', name: 'openclaw' },
              vulnerable_version_range: '>= 1.0.0, < 2.0.0',
              patched_versions: '2.0.0',
            },
            {
              package: { ecosystem: 'NPM', name: 'OPENCLAW' },
              vulnerable_version_range: '>= 1.0.0,   < 2.0.0',
              patched_versions: '2.1.0',
            },
          ],
        }),
      ]),
      /duplicate advisory range identity/,
    );
  });

  it('fails closed on repository advisory pagination, ordering, and count hazards', async () => {
    const first = repositorySecurityAdvisoryNode({
      updatedAt: '2026-07-01T00:00:00Z',
    });
    const second = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      updatedAt: '2026-07-02T00:00:00Z',
    });
    const orderedSecond = repositorySecurityAdvisoryNode({
      ghsaId: 'GHSA-65rx-fvh6-r4h2',
      cveId: 'CVE-2026-27209',
      updatedAt: '2026-06-30T00:00:00Z',
    });

    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async () => ({ nodes: [first], nextCursor: 'cursor-1' }),
      }),
      /non-terminal page completeness evidence is missing/,
    );
    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async ({ after }) => after == null
          ? cursorNonTerminalAdvisoryPage([first], 'cursor-1')
          : cursorTerminalAdvisoryPage([structuredClone(first)]),
      }),
      /duplicate GHSA/,
    );
    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async ({ after }) => after == null
          ? cursorNonTerminalAdvisoryPage([first], 'cursor-1')
          : cursorNonTerminalAdvisoryPage([orderedSecond], 'cursor-1'),
      }),
      /repeated pagination cursor cursor-1/,
    );
    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async () => cursorNonTerminalAdvisoryPage([], 'cursor-1'),
      }),
      /empty non-terminal page/,
    );
    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async ({ after }) => after == null
          ? cursorNonTerminalAdvisoryPage([first], 'cursor-1')
          : cursorTerminalAdvisoryPage([]),
      }),
      /empty page after a cursor/,
    );
    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async () => cursorNonTerminalAdvisoryPage([first], 'cursor-1'),
        maxPagesPerConnection: 1,
      }),
      /exceeded 1 pages before pagination completed/,
    );
    await assert.rejects(
      () => __githubTest.fetchRepositorySecurityAdvisorySweep({
        request: async () =>
          cursorNonTerminalAdvisoryPage([first, second], 'cursor-1'),
      }),
      /violated updated_at descending order/,
    );

    const mapped = __githubTest.mapRepositorySecurityAdvisories([first]);
    assert.throws(
      () => __githubTest.canonicalAdvisoryCatalogDigest(2, mapped),
      /digest count 2 does not match 1 advisory nodes/,
    );
  });
});
