import { config } from '../config';
import { createHash } from 'node:crypto';
import { isClosureKeepOpenComment } from './closureProof';
import {
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
  type CommentEvidenceStabilizationIdentity,
  type CommentEvidenceSweepIdentity,
} from './commentEvidence';
import { CLOSURE_COMMENT_FIX_PROOF_SOURCE, CLOSURE_COMMENT_PR_MENTION_SOURCE } from './fixProvenance';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
  type IssueStateEventStabilizationIdentity,
  type IssueStateEventSweepIdentity,
  type NormalizedIssueStateEvent,
} from './stateEventSnapshot';
import {
  canonicalIssueContentDigest,
  canonicalIssueMembershipDigest,
} from './issueCatalogSnapshot';
import {
  buildRepositoryCollaboratorPermissionSnapshot,
  type RepositoryCollaboratorPermissionInputRow,
  type RepositoryCollaboratorPermissionSnapshot,
} from './labelAuthorityEvidenceIngestion';
import { repositoryAdvisoryCatalogContentDigest } from './advisoryCatalogDigest';
import { runCooperativeGroup } from './cooperativeCancellation';

const API = 'https://api.github.com/graphql';
const GRAPHQL_PAGE_SIZE = 100;
const COMMENT_BATCH_SIZE = 25;
const COMMENT_PAGE_SIZE = 100;
const COMMENT_SNAPSHOT_MAX_ATTEMPTS = 6;
const COMMENT_SNAPSHOT_RETRY_BASE_MS = 250;
const COMMENT_SNAPSHOT_RETRY_MAX_MS = 2_000;
const RELEASE_CATALOG_MAX_SWEEPS = 3;
const ISSUE_CATALOG_MAX_SWEEPS = 3;
const ISSUE_CLOSED_AT_SKEW_TOLERANCE_MS = 2_000;
const ISSUE_LABEL_MAX_SWEEPS = 3;
const ADVISORY_CATALOG_MAX_SWEEPS = 3;
const SECURITY_VULNERABILITY_MAX_SWEEPS = 3;
const RELEASE_CHECK_MAX_SWEEPS = 3;
const COLLABORATOR_PERMISSION_MAX_SWEEPS = 3;
const SECONDARY_RATE_LIMIT_FALLBACK_MS = 60_000;
const ADVISORY_TARGET_ECOSYSTEM = 'npm';
const ADVISORY_TARGET_GRAPHQL_ECOSYSTEM = 'NPM';
const ADVISORY_TARGET_PACKAGE = 'openclaw';

function positiveIntegerEnv(key: string, fallback: number): number {
  const raw = process.env[key];
  if (raw == null || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${key} must be a positive integer, got ${raw}`);
  }
  return value;
}

const GRAPHQL_REQUEST_TIMEOUT_MS = positiveIntegerEnv('GITHUB_GRAPHQL_REQUEST_TIMEOUT_MS', 30_000);
const GRAPHQL_BODY_TIMEOUT_MS = positiveIntegerEnv('GITHUB_GRAPHQL_BODY_TIMEOUT_MS', 30_000);
const GRAPHQL_MAX_PAGES_PER_CONNECTION = positiveIntegerEnv('GITHUB_GRAPHQL_MAX_PAGES_PER_CONNECTION', 8_192);
const GITHUB_RESPONSE_BODY_MAX_BYTES = positiveIntegerEnv(
  'GITHUB_RESPONSE_BODY_MAX_BYTES',
  32 * 1_024 * 1_024,
);
const GITHUB_ERROR_BODY_MAX_BYTES = positiveIntegerEnv(
  'GITHUB_ERROR_BODY_MAX_BYTES',
  64 * 1_024,
);

export interface GhRelease {
  node_id: string;
  tag_name: string;
  tag_commit_oid: string;
  name: string | null;
  published_at: string | null;
  created_at: string;
  updated_at: string;
  html_url: string;
  prerelease: boolean;
  draft: boolean;
  // Release-notes markdown. Mined for maintainer-signal counts
  // (### Breaking / ### Fixes / etc.) — see lib/releaseNotes.ts.
  body: string | null;
}

export interface GhReleaseCatalogMetadata {
  exhausted: boolean;
  stabilized: boolean;
  totalCount: number;
  nodeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  sweepPageCounts?: readonly number[];
  digest: string;
  sourceOrder: 'CREATED_AT_DESC';
}

export interface GhReleaseCatalog {
  releases: GhRelease[];
  metadata: GhReleaseCatalogMetadata;
}

export interface GithubReleaseCatalogActiveRelease {
  node_id: string;
  catalog_tag_commit_oid: string;
  tag: string;
  name: string | null;
  published_at: string;
  created_at: string;
  updated_at: string;
  html_url: string;
  prerelease: boolean;
  body: string | null;
}

export interface GithubReleaseCatalogPublicationAuthorization {
  readonly schemaVersion: 1;
}

export interface GithubReleaseCatalogOperationBinding {
  operationRunId: string;
  operation: string;
  operationAttemptContentHash: string;
}

export interface GithubReleaseCatalogPublicationEvidence {
  schemaVersion: 1;
  repository: string;
  observedAt: string;
  operationRunId: string;
  operation: string;
  operationAttemptContentHash: string;
  remoteCatalog: GhReleaseCatalogMetadata & {
    repositoryNodeId: string;
    repositoryNameWithOwner: string;
    publishedCount: number;
    draftCount: number;
    sweepPageCounts: readonly number[];
  };
  activeReleaseDigest: string;
  activeReleaseCount: number;
}

const fetchedReleaseCatalogs = new WeakMap<
  GhReleaseCatalog,
  {
    repository: string;
    repositoryNodeId: string;
    repositoryNameWithOwner: string;
    observedAt: string;
    operationBinding: Readonly<GithubReleaseCatalogOperationBinding> | null;
    requestAuthority: 'production' | 'injected';
    fingerprint: string;
  }
>();
const releaseCatalogPublicationAuthorizations = new WeakMap<
  object,
  Readonly<GithubReleaseCatalogPublicationEvidence>
>();

export interface GhIssue {
  node_id: string;
  node_type: 'Issue';
  number: number;
  title: string;
  body: string | null;
  state: 'open' | 'closed';
  user: { id: string; type: string; login: string } | null;
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

export interface GhIssuePageMetadata {
  totalCount: number;
  fetchedCount: number;
  uniqueCount: number;
  pageCount: number;
  requestCursor: string | null;
  nextCursor: string | null;
  hasNextPage: boolean;
  exhausted: boolean;
  digest: string | null;
  membershipDigest: string | null;
  contentDigest: string | null;
  sourceOrder: 'UPDATED_AT_DESC';
}

export interface GhIssuePage {
  issues: GhIssue[];
  metadata: GhIssuePageMetadata;
}

export interface GhIssueImmutableIdentity {
  nodeId: string;
  issueNumber: number;
  createdAt: string;
}

export interface GhIssueSnapshotBoundary {
  totalCount: number;
  terminalIssue: GhIssueImmutableIdentity | null;
  membershipDigest: string;
}

export interface GhIssueCatalogMetadata {
  exhausted: boolean;
  stabilized: boolean;
  totalCount: number;
  observedTotalCount: number;
  postBoundaryGrowthCount: number;
  nodeCount: number;
  uniqueCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  digest: string;
  membershipDigest: string;
  contentDigest: string;
  snapshotBoundary: GhIssueSnapshotBoundary;
  lastRequestCursor: string | null;
  nextCursor: null;
  hasNextPage: false;
  sourceOrder: 'CREATED_AT_ASC';
}

export interface GhIssueCatalogIssue extends GhIssue {
  node_id: string;
}

export interface GhIssueCatalog {
  issues: GhIssueCatalogIssue[];
  metadata: GhIssueCatalogMetadata;
}

export interface GhIssueIncrementalSweepMetadata {
  exhausted: true;
  stabilized: false;
  totalCount: number;
  nodeCount: number;
  uniqueCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: 1;
  digest: string;
  membershipDigest: string;
  contentDigest: string;
  lastRequestCursor: string | null;
  nextCursor: null;
  hasNextPage: false;
  sourceOrder: 'UPDATED_AT_DESC';
}

export interface GhComment {
  id: number;
  node_id: string;
  node_type: 'IssueComment';
  url?: string | null;
  user: { id: string; type: string; login: string } | null;
  author_association?: string | null;
  body: string;
  created_at: string;
  updated_at?: string | null;
}

export interface GhIssueCommentSnapshot {
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: 'Issue';
  issueAuthor: { nodeId: string; actorType: string; login: string } | null;
  issueUpdatedAt: string;
  totalCount: number;
  comments: GhComment[];
  commentsDigest: string;
  authorityDigest: string;
  stabilization: CommentEvidenceStabilizationIdentity;
}

interface GraphqlError {
  message: string;
  type?: string;
  path?: Array<string | number>;
}

interface GraphqlResponse<T> {
  data?: T;
  errors?: GraphqlError[];
}

class GithubGraphqlResponseError extends Error {
  readonly errors: readonly GraphqlError[];

  constructor(errors: GraphqlError[]) {
    super(`GitHub GraphQL error: ${graphqlErrorDetails(errors)}`);
    this.name = 'GithubGraphqlResponseError';
    this.errors = errors.map((error) => ({
      ...error,
      path: error.path?.slice(),
    }));
  }
}

interface PageInfo {
  hasNextPage: boolean;
  endCursor: string | null;
}

interface ActorNode {
  id: string;
  __typename: string;
  login: string;
}

interface ReleaseNode {
  id: string;
  tagName: string;
  tagCommit: {
    oid: string;
  } | null;
  name: string | null;
  publishedAt: string | null;
  createdAt: string;
  updatedAt: string;
  url: string;
  isPrerelease: boolean;
  isDraft: boolean;
  description: string | null;
}

interface IssueNode {
  id: string;
  __typename: 'Issue';
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
  labels: {
    totalCount?: number | null;
    nodes: Array<{ name: string } | null> | null;
    pageInfo?: PageInfo | null;
  } | null;
}

interface CommentNode {
  id: string;
  __typename: 'IssueComment';
  databaseId: number | null;
  url: string;
  author: ActorNode | null;
  authorAssociation: string | null;
  body: string;
  createdAt: string;
  updatedAt: string;
}

interface ReactionGroupNode {
  content: string;
  reactors: { totalCount: number };
}

interface RepositorySecurityAdvisoryVulnerabilityNode {
  package: {
    ecosystem: string | null;
    name: string | null;
  } | null;
  vulnerable_version_range: string | null;
  patched_versions: string | null;
}

interface RepositorySecurityAdvisoryNode {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: string;
  state: string;
  updated_at: string;
  published_at: string | null;
  withdrawn_at: string | null;
  html_url: string;
  identifiers: Array<{
    type: string;
    value: string;
  } | null> | null;
  vulnerabilities: Array<RepositorySecurityAdvisoryVulnerabilityNode | null> | null;
}

interface SecurityVulnerabilityNode {
  advisory: {
    ghsaId: string;
    identifiers: Array<{
      type: string;
      value: string;
    } | null> | null;
    permalink: string | null;
    publishedAt: string;
    severity: string;
    summary: string;
    withdrawnAt: string | null;
  } | null;
  package: {
    ecosystem: string | null;
    name: string | null;
  } | null;
  vulnerableVersionRange: string | null;
  firstPatchedVersion: {
    identifier: string;
  } | null;
  updatedAt: string;
}

interface SecurityVulnerabilitiesQueryData {
  securityVulnerabilities: {
    totalCount: number;
    nodes: Array<SecurityVulnerabilityNode | null> | null;
    pageInfo: PageInfo;
  } | null;
}

interface RepositorySecurityAdvisoryPage {
  nodes: Array<RepositorySecurityAdvisoryNode | null>;
  nextCursor: string | null;
  completeness?: RepositorySecurityAdvisoryPageCompleteness;
}

export interface RepositorySecurityAdvisoryPageCompleteness {
  terminal: boolean;
  proven: boolean;
  evidence: 'link' | 'missing-link';
  linkHeaderPresent: boolean;
}

export type RepositorySecurityAdvisoryDirection = 'asc' | 'desc';

export type RepositorySecurityAdvisoryPageRequest = (input: {
  owner: string;
  repo: string;
  after: string | null;
  pageSize: number;
  state: 'published';
  sort: 'updated';
  direction: RepositorySecurityAdvisoryDirection;
  signal?: AbortSignal;
}) => Promise<RepositorySecurityAdvisoryPage>;

interface MappedRepositorySecurityAdvisory {
  advisory: GhAdvisory;
  updatedAt: string;
}

interface ReleasesQueryData {
  repository: {
    id: string;
    nameWithOwner: string;
    releases: {
      totalCount: number;
      nodes: Array<ReleaseNode | null> | null;
      pageInfo: PageInfo;
    };
  } | null;
}

interface IssuesQueryData {
  repository: {
    issues: {
      totalCount: number;
      nodes: Array<IssueNode | null> | null;
      pageInfo: PageInfo;
    };
  } | null;
}

interface IssueCommentsQueryIssue {
    id: string;
    __typename: 'Issue';
    number: number;
    author: ActorNode | null;
    updatedAt: string;
    comments: {
      totalCount: number;
      nodes: Array<CommentNode | null> | null;
      pageInfo: PageInfo;
    };
}

interface IssueCommentsQueryData {
  repository: ({
    id: string;
  } & Record<`issue${number}`, IssueCommentsQueryIssue | null>) | null;
}

interface IssueLabelsQueryIssue {
  id: string;
  __typename: 'Issue';
  number: number;
  updatedAt: string;
  labels: {
    totalCount: number;
    nodes: Array<{ name: string } | null> | null;
    pageInfo: PageInfo;
  } | null;
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

export interface ReleaseCommitFetchOptions {
  request?: GraphqlRequest;
  maxPagesPerConnection?: number;
  expectedTagOid?: string;
  signal?: AbortSignal;
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
  repositoryOwner: string | null;
  repositoryName: string | null;
  repositoryNameWithOwner: string | null;
  repositoryUrl: string | null;
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
  eventType: 'ClosedEvent';
  closedAt: string | null;
  connectionOrdinal: number;
  actorNodeId: string | null;
  actorLogin: string | null;
  actorType: string | null;
  stateReason: string | null;
  closerType: string | null;
  closerNumber: number | null;
  closerNodeId: string | null;
  closerOid: string | null;
  raw: unknown;
}

export interface GhIssueReopenEvent {
  issueNumber: number;
  eventId: string;
  eventType: 'ReopenedEvent';
  reopenedAt: string | null;
  connectionOrdinal: number;
  actorNodeId: string | null;
  actorLogin: string | null;
  actorType: string | null;
  raw: unknown;
}

export interface GhIssuePrLink {
  issueNumber: number;
  prNumber: number;
  prRepositoryOwner: string | null;
  prRepositoryName: string | null;
  prRepositoryNameWithOwner: string | null;
  source: string;
  willCloseTarget: boolean | null;
  referencedAt: string | null;
}

export interface GhIssueCommitReference {
  issueNumber: number;
  eventId: string;
  commitOid: string;
  commitMessageHeadline: string | null;
  commitRepositoryOwner: string | null;
  commitRepositoryName: string | null;
  commitRepositoryNameWithOwner: string | null;
  isCrossRepository: boolean;
  isDirectReference: boolean;
  referencedAt: string | null;
  actorLogin: string | null;
  raw: unknown;
}

export interface GhIssueLabelEvent {
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: 'Issue';
  eventId: string;
  action: 'labeled' | 'unlabeled';
  labelNodeId: string;
  labelName: string;
  actorNodeId: string | null;
  actorLogin: string | null;
  actorType: string | null;
  createdAt: string;
  raw: unknown;
}

export interface GhIssueLabelEvidenceSnapshot {
  schemaVersion: 2;
  repository: string;
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: 'Issue';
  capturedAt: string;
  issueUpdatedAt: string;
  totalCount: number;
  fetchedCount: number;
  pageCount: number;
  sweepCount: number;
  stabilized: true;
  events: GhIssueLabelEvent[];
}

export interface GhIssueStateEventSnapshot {
  schemaVersion: typeof ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION;
  repositoryNodeId: string;
  issueNumber: number;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  totalCount: number;
  fetchedCount: number;
  eventsDigest: string;
  authorityDigest: string;
  sweepIdentity: IssueStateEventSweepIdentity;
  sweepCount: number;
  stabilized: boolean;
  stabilization: IssueStateEventStabilizationIdentity | null;
}

export interface GhIssueFixEvidenceConnectionSnapshot {
  totalCount: number;
  observedTotalCount: number;
  postBoundaryGrowthCount: number;
  fetchedCount: number;
  terminalFirstNIdentity: string | null;
  identityDigest: string;
  contentDigest: string;
  sourceOrder: 'CONNECTION_ASC';
}

export interface GhIssueFixEvidenceConnectionSnapshots {
  closedByPullRequestsReferences: GhIssueFixEvidenceConnectionSnapshot;
  stateEvents: GhIssueFixEvidenceConnectionSnapshot;
  referenceEvents: GhIssueFixEvidenceConnectionSnapshot;
}

export interface GhIssueFixEvidence {
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: 'Issue';
  stateSnapshot: GhIssueStateEventSnapshot;
  connectionSnapshots: GhIssueFixEvidenceConnectionSnapshots;
  closureEvents: GhIssueClosureEvent[];
  reopenEvents: GhIssueReopenEvent[];
  prLinks: GhIssuePrLink[];
  pullRequests: GhPullRequestFix[];
  commitReferences: GhIssueCommitReference[];
}

export interface ClosureCommentPrMention {
  issueNumber: number;
  prNumber: number;
  prRepositoryOwner: string | null;
  prRepositoryName: string | null;
  prRepositoryNameWithOwner: string | null;
  source: typeof CLOSURE_COMMENT_FIX_PROOF_SOURCE | typeof CLOSURE_COMMENT_PR_MENTION_SOURCE;
  referencedAt: string | null;
  sourceCommentDatabaseId?: number | null;
  sourceCommentUrl?: string | null;
  author: string | null;
  authorAssociation: string | null;
  trustedSource: boolean;
}

export interface ClosureCommentCommitMention {
  issueNumber: number;
  commitOid: string;
  shortOid?: string;
  referencedAt: string | null;
  sourceIssueNumber: number;
  sourceCommentDatabaseId?: number | null;
  sourceCommentUrl?: string | null;
  snippet: string;
  source: 'ClosureComment.fixProof' | 'ClosedEvent.closer' | 'ReferencedEvent.commit';
  author: string | null;
  authorAssociation: string | null;
  trustedSource: boolean;
}

type CommitOidResolver = (prefix: string) => string | null;

interface ExtractedCommitOid {
  commitOid: string;
  shortOid?: string;
}

type MissingIssueAliasCallback = (event: { issueNumber: number; aliasIndex: number }) => void;

export type GraphqlRequest = <T>(
  query: string,
  variables?: Record<string, unknown>,
  signal?: AbortSignal,
) => Promise<T>;

type GithubSleep = (ms: number, signal?: AbortSignal) => Promise<void>;

function abortSignalReason(signal: AbortSignal): unknown {
  if (signal.reason !== undefined) return signal.reason;
  const error = new Error('This operation was aborted');
  error.name = 'AbortError';
  return error;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortSignalReason(signal);
}

function forwardAbortSignal(
  source: AbortSignal | undefined,
  target: AbortController,
): () => void {
  if (!source) return () => undefined;
  const abort = () => {
    if (!target.signal.aborted) target.abort(abortSignalReason(source));
  };
  if (source.aborted) {
    abort();
    return () => undefined;
  }
  source.addEventListener('abort', abort, { once: true });
  return () => source.removeEventListener('abort', abort);
}

interface IssueBatchOptions {
  onMissingIssueAlias?: MissingIssueAliasCallback;
  batchConcurrency?: number;
  maxPagesPerConnection?: number;
  snapshotMaxAttempts?: number;
  snapshotRetryBaseMs?: number;
  snapshotRetryMaxMs?: number;
  request?: GraphqlRequest;
  sleep?: GithubSleep;
  signal?: AbortSignal;
}

function issueBatchConcurrency(options: IssueBatchOptions): number {
  const concurrency = options.batchConcurrency ?? config.github.graphql.concurrency;
  if (!Number.isInteger(concurrency) || concurrency <= 0) {
    throw new Error(`GitHub issue batch concurrency must be a positive integer, got ${String(concurrency)}`);
  }
  return concurrency;
}

async function mapIssueBatches<T>(
  issueNumbers: number[],
  batchSize: number,
  options: IssueBatchOptions,
  worker: (chunk: number[], options: IssueBatchOptions) => Promise<T>,
): Promise<T[]> {
  throwIfAborted(options.signal);
  const chunks: number[][] = [];
  for (let offset = 0; offset < issueNumbers.length; offset += batchSize) {
    chunks.push(issueNumbers.slice(offset, offset + batchSize));
  }
  if (chunks.length === 0) return [];

  const results = new Array<T>(chunks.length);
  const workerCount = Math.min(issueBatchConcurrency(options), chunks.length);
  const controller = new AbortController();
  const removeCallerAbortListener = forwardAbortSignal(options.signal, controller);
  const workerOptions = { ...options, signal: controller.signal };
  let nextChunkIndex = 0;
  let stopped = false;
  let hasPrimaryFailure = false;
  let primaryFailure: unknown;

  const fail = (error: unknown) => {
    if (!hasPrimaryFailure) {
      hasPrimaryFailure = true;
      primaryFailure = error;
    }
    stopped = true;
    if (!controller.signal.aborted) controller.abort(primaryFailure);
  };

  if (controller.signal.aborted) {
    fail(abortSignalReason(controller.signal));
  } else {
    controller.signal.addEventListener('abort', () => {
      if (!hasPrimaryFailure) fail(abortSignalReason(controller.signal));
    }, { once: true });
  }

  async function runWorker(): Promise<void> {
    while (!stopped) {
      const chunkIndex = nextChunkIndex++;
      if (chunkIndex >= chunks.length) return;
      try {
        results[chunkIndex] = await worker(chunks[chunkIndex], workerOptions);
      } catch (error) {
        fail(error);
      }
    }
  }

  try {
    await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  } finally {
    removeCallerAbortListener();
  }
  if (hasPrimaryFailure) throw primaryFailure;
  return results;
}

export async function listIssueLabelEventsBatch(
  issueNumbers: number[],
  options: IssueBatchOptions = {},
): Promise<Map<number, GhIssueLabelEvent[]>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)]
    .filter((issueNumber) => Number.isInteger(issueNumber));
  const snapshots = await listIssueLabelEvidenceSnapshotsBatch(
    uniqueIssueNumbers,
    options,
  );
  return new Map(
    uniqueIssueNumbers.map((issueNumber) => [
      issueNumber,
      snapshots.get(issueNumber)?.events ?? [],
    ]),
  );
}

export async function listIssueLabelEvidenceSnapshotsBatch(
  issueNumbers: number[],
  options: IssueBatchOptions = {},
): Promise<Map<number, GhIssueLabelEvidenceSnapshot>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n));
  const all = new Map<number, GhIssueLabelEvidenceSnapshot>();
  const eventIssueNumbers = new Map<string, number>();
  const request = options.request ?? gh;

  const batches = await mapIssueBatches(
    uniqueIssueNumbers,
    10,
    options,
    (chunk, workerOptions) =>
      listStableIssueLabelEventsChunk(chunk, request, workerOptions),
  );
  for (const batch of batches) {
    for (const [issueNumber, snapshot] of batch) {
      for (const event of snapshot.events) {
        const existingIssueNumber = eventIssueNumbers.get(event.eventId);
        if (existingIssueNumber != null) {
          throw new Error(
            `GitHub GraphQL label timeline returned duplicate event ID ${event.eventId} ` +
            `for issues #${existingIssueNumber} and #${issueNumber}`,
          );
        }
        eventIssueNumbers.set(event.eventId, issueNumber);
      }
      all.set(issueNumber, snapshot);
    }
  }
  return all;
}

interface IssueLabelEventSweepState {
  repositoryNodeId: string;
  issueNodeId: string;
  issueNodeType: 'Issue';
  issueUpdatedAt: string;
  totalCount: number;
  pageCount: number;
  events: GhIssueLabelEvent[];
  eventIds: Set<string>;
}

interface IssueLabelEventSweep {
  repositoryNodeId: string;
  issueNodeId: string;
  issueNodeType: 'Issue';
  issueUpdatedAt: string;
  totalCount: number;
  pageCount: number;
  events: GhIssueLabelEvent[];
  digest: string;
}

class IssueLabelTimelineInstabilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IssueLabelTimelineInstabilityError';
  }
}

async function listStableIssueLabelEventsChunk(
  chunk: number[],
  request: GraphqlRequest,
  options: IssueBatchOptions,
): Promise<Map<number, GhIssueLabelEvidenceSnapshot>> {
  const sleeper = options.sleep ?? sleep;
  const maxAttempts = options.snapshotMaxAttempts ?? COMMENT_SNAPSHOT_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts <= 0) {
    throw new Error(`GitHub issue label timeline max attempts must be positive, got ${String(maxAttempts)}`);
  }
  const missingIssueNumbers = new Set<number>();
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const firstSweep = await fetchIssueLabelEventsSweep(
        chunk,
        missingIssueNumbers,
        request,
        options,
      );
      const secondSweep = await fetchIssueLabelEventsSweep(
        chunk,
        missingIssueNumbers,
        request,
        options,
      );
      return requireMatchingIssueLabelEventSweeps(
        chunk.filter((issueNumber) => !missingIssueNumbers.has(issueNumber)),
        firstSweep,
        secondSweep,
      );
    } catch (error) {
      if (!(error instanceof IssueLabelTimelineInstabilityError)) throw error;
      if (attempt === maxAttempts) {
        throw new Error(
          `GitHub issue label timeline chunk failed to stabilize after ${maxAttempts} attempts: ${error.message}`,
        );
      }
      await sleepWithSignal(
        sleeper,
        commentSnapshotRetryDelayMs(attempt, options),
        options.signal,
      );
    }
  }
  throw new Error('GitHub issue label timeline chunk failed closed without a stable result');
}

async function fetchIssueLabelEventsSweep(
  chunk: number[],
  missingIssueNumbers: Set<number>,
  request: GraphqlRequest,
  options: IssueBatchOptions,
): Promise<Map<number, IssueLabelEventSweep>> {
  const sweepIssueNumbers = chunk.filter((issueNumber) => !missingIssueNumbers.has(issueNumber));
  const states = new Map<number, IssueLabelEventSweepState>();
  const cursors = new Map<number, string | null>(
    sweepIssueNumbers.map((issueNumber) => [issueNumber, null]),
  );
  const guards = new Map(sweepIssueNumbers.map((issueNumber) => [
    issueNumber,
    createGraphqlPaginationGuard(
      `issue #${issueNumber} label timeline`,
      options.maxPagesPerConnection,
    ),
  ]));
  const done = new Set<number>();
  while (done.size < sweepIssueNumbers.length) {
    const active = sweepIssueNumbers.filter((issueNumber) => !done.has(issueNumber));
    let data: { repository: Record<string, any> | null };
    try {
      data = await request<{ repository: Record<string, any> | null }>(
        buildIssueLabelEventsBatchQuery(active.length),
        repoVars(Object.fromEntries(active.flatMap((issueNumber, idx) => [
          [`number${idx}`, issueNumber],
          [`after${idx}`, cursors.get(issueNumber) ?? null],
        ]))),
        options.signal,
      );
    } catch (error) {
      const missingReporter = options.onMissingIssueAlias
        ? (event: { issueNumber: number; aliasIndex: number }) => {
            const firstReport = !missingIssueNumbers.has(event.issueNumber);
            missingIssueNumbers.add(event.issueNumber);
            states.delete(event.issueNumber);
            if (firstReport) options.onMissingIssueAlias?.(event);
          }
        : undefined;
      if (skipMissingIssueAliases(error, active, done, missingReporter) === 0) throw error;
      continue;
    }
    const repo = assertRepo(data.repository);
    const repositoryNodeId = requireCanonicalGraphqlIdentity(
      repo.id,
      'issue label timeline repository node ID',
    );
    const issueNodeNumbers = new Map<string, number>();
    for (let idx = 0; idx < active.length; idx++) {
      const issueNumber = active[idx];
      const issue = repo[`issue${idx}`];
      if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while fetching label timeline`);
      const context = `issue #${issueNumber} label timeline`;
      const { issueNodeId, issueNodeType } = requireRequestedIssueGraphqlIdentity(
        issue,
        issueNumber,
        context,
      );
      const existingIssueNumber = issueNodeNumbers.get(issueNodeId);
      if (existingIssueNumber != null && existingIssueNumber !== issueNumber) {
        throw new Error(
          `GitHub GraphQL label timeline aliases for issues #${existingIssueNumber} ` +
            `and #${issueNumber} returned duplicate issue node ID ${issueNodeId}`,
        );
      }
      issueNodeNumbers.set(issueNodeId, issueNumber);
      const issueUpdatedAt = requireCanonicalGraphqlIdentity(
        issue.updatedAt,
        `${context} issue updatedAt`,
      );
      if (!Number.isFinite(Date.parse(issueUpdatedAt))) {
        throw new Error(`${context} returned invalid issue updatedAt`);
      }
      const connection = requireCountedGraphqlConnection<any>(issue.timelineItems, context);
      const state = states.get(issueNumber) ?? {
        repositoryNodeId,
        issueNodeId,
        issueNodeType: 'Issue' as const,
        issueUpdatedAt,
        totalCount: connection.totalCount,
        pageCount: 0,
        events: [],
        eventIds: new Set<string>(),
      };
      if (connection.totalCount !== state.totalCount) {
        throw new IssueLabelTimelineInstabilityError(
          `GitHub GraphQL ${context} totalCount changed within sweep ` +
          `from ${state.totalCount} to ${connection.totalCount}`,
        );
      }
      if (
        state.repositoryNodeId !== repositoryNodeId ||
        state.issueNodeId !== issueNodeId ||
        state.issueNodeType !== issueNodeType ||
        state.issueUpdatedAt !== issueUpdatedAt
      ) {
        throw new IssueLabelTimelineInstabilityError(
          `GitHub GraphQL ${context} repository, issue identity, or revision changed within sweep`,
        );
      }
      state.pageCount++;
      appendIssueLabelEventNodes(
        state,
        issueNumber,
        issueNodeId,
        issueNodeType,
        connection.nodes,
      );
      states.set(issueNumber, state);
      const currentCursor = cursors.get(issueNumber) ?? null;
      const nextCursor = guards.get(issueNumber)?.next(connection.pageInfo, currentCursor) ?? null;
      if (nextCursor) {
        cursors.set(issueNumber, nextCursor);
      } else {
        if (state.eventIds.size !== state.totalCount) {
          throw new IssueLabelTimelineInstabilityError(
            `GitHub GraphQL ${context} terminal unique count ${state.eventIds.size} ` +
            `did not match totalCount ${state.totalCount}`,
          );
        }
        done.add(issueNumber);
      }
    }
  }

  return new Map([...states].map(([issueNumber, state]) => [
    issueNumber,
    {
      repositoryNodeId: state.repositoryNodeId,
      issueNodeId: state.issueNodeId,
      issueNodeType: state.issueNodeType,
      issueUpdatedAt: state.issueUpdatedAt,
      totalCount: state.totalCount,
      pageCount: state.pageCount,
      events: state.events,
      digest: issueLabelEventSweepDigest(
        state.repositoryNodeId,
        issueNumber,
        state.issueNodeId,
        state.issueUpdatedAt,
        state.totalCount,
        state.events,
      ),
    },
  ]));
}

function appendIssueLabelEventNodes(
  state: IssueLabelEventSweepState,
  issueNumber: number,
  issueNodeId: string,
  issueNodeType: 'Issue',
  nodes: any[],
): void {
  for (const node of nodes) {
    const type = node?.__typename;
    if (type !== 'LabeledEvent' && type !== 'UnlabeledEvent') {
      throw new Error(
        `GitHub GraphQL issue #${issueNumber} label timeline returned unexpected ${String(type)}`,
      );
    }
    if (typeof node.id !== 'string' || !node.id || node.id.trim() !== node.id) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} label event is missing canonical id`);
    }
    if (state.eventIds.has(node.id)) {
      throw new Error(
        `GitHub GraphQL issue #${issueNumber} label timeline returned duplicate event ID ${node.id}`,
      );
    }
    if (typeof node.label?.name !== 'string' || node.label.name.length === 0) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} label event ${node.id} is missing label name`);
    }
    const labelNodeId = requireCanonicalGraphqlIdentity(
      node.label?.id,
      `issue #${issueNumber} label event ${node.id} label node ID`,
    );
    if (typeof node.createdAt !== 'string' || !Number.isFinite(Date.parse(node.createdAt))) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} label event ${node.id} has invalid createdAt`);
    }
    const actorType = node.actor == null
      ? null
      : requireCanonicalGraphqlIdentity(
          node.actor.__typename,
          `issue #${issueNumber} label event ${node.id} actor type`,
        );
    const actorNodeId = node.actor == null
      ? null
      : requireCanonicalGraphqlIdentity(
          node.actor.id,
          `issue #${issueNumber} label event ${node.id} actor node ID`,
        );
    const actorLogin = node.actor == null
      ? null
      : requireCanonicalGraphqlIdentity(
          node.actor.login,
          `issue #${issueNumber} label event ${node.id} actor login`,
        );
    state.eventIds.add(node.id);
    state.events.push({
      issueNumber,
      issueNodeId,
      issueNodeType,
      eventId: node.id,
      action: type === 'LabeledEvent' ? 'labeled' : 'unlabeled',
      labelNodeId,
      labelName: node.label.name,
      actorNodeId,
      actorLogin,
      actorType,
      createdAt: node.createdAt,
      raw: node,
    });
  }
}

function issueLabelEventSweepDigest(
  repositoryNodeId: string,
  issueNumber: number,
  issueNodeId: string,
  issueUpdatedAt: string,
  totalCount: number,
  events: GhIssueLabelEvent[],
): string {
  const canonical = events
    .map((event) => [
      event.issueNumber,
      event.issueNodeId,
      event.issueNodeType,
      event.eventId,
      event.action,
      event.labelNodeId,
      event.labelName,
      event.actorNodeId,
      event.actorLogin,
      event.actorType,
      event.createdAt,
    ]);
  return createHash('sha256')
    .update(JSON.stringify([
      repositoryNodeId,
      issueNumber,
      issueNodeId,
      issueUpdatedAt,
      totalCount,
      canonical,
    ]))
    .digest('hex');
}

function requireMatchingIssueLabelEventSweeps(
  issueNumbers: number[],
  firstSweep: Map<number, IssueLabelEventSweep>,
  secondSweep: Map<number, IssueLabelEventSweep>,
): Map<number, GhIssueLabelEvidenceSnapshot> {
  const stable = new Map<number, GhIssueLabelEvidenceSnapshot>();
  const capturedAt = new Date().toISOString();
  for (const issueNumber of issueNumbers) {
    const first = firstSweep.get(issueNumber);
    const second = secondSweep.get(issueNumber);
    if (!first || !second) {
      throw new IssueLabelTimelineInstabilityError(
        `issue #${issueNumber} label timeline is missing from a complete sweep`,
      );
    }
    if (first.digest !== second.digest) {
      throw new IssueLabelTimelineInstabilityError(
        `issue #${issueNumber} label timeline content changed between complete sweeps ` +
        `(${first.digest} != ${second.digest})`,
      );
    }
    if (
      first.repositoryNodeId !== second.repositoryNodeId ||
      first.issueNodeId !== second.issueNodeId ||
      first.issueNodeType !== second.issueNodeType ||
      first.issueUpdatedAt !== second.issueUpdatedAt ||
      first.totalCount !== second.totalCount
    ) {
      throw new IssueLabelTimelineInstabilityError(
        `issue #${issueNumber} label timeline authority identity changed ` +
          'between complete sweeps',
      );
    }
    stable.set(issueNumber, {
      schemaVersion: 2,
      repository: `${config.github.owner}/${config.github.repo}`.toLowerCase(),
      repositoryNodeId: second.repositoryNodeId,
      issueNumber,
      issueNodeId: second.issueNodeId,
      issueNodeType: second.issueNodeType,
      capturedAt,
      issueUpdatedAt: second.issueUpdatedAt,
      totalCount: second.totalCount,
      fetchedCount: second.events.length,
      pageCount: second.pageCount,
      sweepCount: 2,
      stabilized: true,
      events: second.events,
    });
  }
  return stable;
}

function buildIssueLabelEventsBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!, $after${idx}: String`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      id
      __typename
      number
      updatedAt
      timelineItems(first: 100, after: $after${idx}, itemTypes: [LABELED_EVENT, UNLABELED_EVENT]) {
        totalCount
        nodes {
          __typename
          ... on LabeledEvent {
            id createdAt actor { __typename login ... on Node { id } } label { id name }
          }
          ... on UnlabeledEvent {
            id createdAt actor { __typename login ... on Node { id } } label { id name }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }`).join('\n');

  return `query IssueLabelEvents($owner: String!, $repo: String!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      id
      ${fields}
    }
  }`;
}

interface RepositoryCollaboratorPermissionEdge {
  permission: string;
  node: {
    id: string;
    __typename: string;
    login: string;
  } | null;
}

interface RepositoryCollaboratorPermissionSweep {
  repositoryNodeId: string;
  totalCount: number;
  pageCount: number;
  rows: RepositoryCollaboratorPermissionInputRow[];
  digest: string;
}

export interface RepositoryCollaboratorPermissionFetchOptions {
  request?: GraphqlRequest;
  maxPagesPerConnection?: number;
  maxSweeps?: number;
  now?: () => number;
  signal?: AbortSignal;
}

function buildRepositoryCollaboratorsQuery(): string {
  return `query RepositoryCollaborators($owner: String!, $repo: String!, $first: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      id
      collaborators(first: $first, after: $after, affiliation: ALL) {
        totalCount
        edges {
          permission
          node { id __typename login }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }`;
}

async function fetchRepositoryCollaboratorPermissionSweep(
  options: RepositoryCollaboratorPermissionFetchOptions = {},
): Promise<RepositoryCollaboratorPermissionSweep> {
  const request = options.request ?? gh;
  const rows: RepositoryCollaboratorPermissionInputRow[] = [];
  const seenLogins = new Set<string>();
  let after: string | null = null;
  let repositoryNodeId: string | null = null;
  let totalCount: number | null = null;
  let pageCount = 0;
  const pagination = createGraphqlPaginationGuard(
    'repository.collaborators',
    options.maxPagesPerConnection,
  );

  for (;;) {
    const requestCursor = after;
    const data = await request<{
      repository: {
        id: string;
        collaborators: {
          totalCount: number;
          edges: Array<RepositoryCollaboratorPermissionEdge | null> | null;
          pageInfo: PageInfo;
        } | null;
      } | null;
    }>(
      buildRepositoryCollaboratorsQuery(),
      repoVars({ first: GRAPHQL_PAGE_SIZE, after }),
      options.signal,
    );
    const repository = assertRepo(data.repository);
    const pageRepositoryNodeId = requireCanonicalGraphqlIdentity(
      repository.id,
      'repository collaborators repository node ID',
    );
    if (repositoryNodeId == null) {
      repositoryNodeId = pageRepositoryNodeId;
    } else if (repositoryNodeId !== pageRepositoryNodeId) {
      throw new Error(
        'GitHub GraphQL repository.collaborators repository node ID changed within sweep',
      );
    }
    const connection = repository.collaborators;
    if (!connection) {
      throw new Error('GitHub GraphQL missing repository.collaborators connection');
    }
    if (
      !Number.isInteger(connection.totalCount) ||
      connection.totalCount < 0
    ) {
      throw new Error('GitHub GraphQL repository.collaborators has invalid totalCount');
    }
    if (!Array.isArray(connection.edges)) {
      throw new Error('GitHub GraphQL repository.collaborators connection missing edges');
    }
    if (!isPageInfo(connection.pageInfo)) {
      throw new Error('GitHub GraphQL repository.collaborators connection missing pageInfo');
    }
    if (totalCount == null) {
      totalCount = connection.totalCount;
    } else if (connection.totalCount !== totalCount) {
      throw new Error(
        `GitHub GraphQL repository.collaborators totalCount changed within sweep ` +
          `from ${totalCount} to ${connection.totalCount}`,
      );
    }
    pageCount++;
    for (let index = 0; index < connection.edges.length; index++) {
      const edge = connection.edges[index];
      if (!edge) {
        throw new Error(
          `GitHub GraphQL repository.collaborators returned null edge at index ${index}`,
        );
      }
      if (!edge.node) {
        throw new Error(
          `GitHub GraphQL repository.collaborators returned null node at edge ${index}`,
        );
      }
      const login = requireCanonicalGraphqlIdentity(
        edge.node.login,
        `repository collaborator edge ${index} login`,
      ).toLowerCase();
      if (seenLogins.has(login)) {
        throw new Error(
          `GitHub GraphQL repository.collaborators returned duplicate login ${login}`,
        );
      }
      seenLogins.add(login);
      rows.push({
        nodeId: requireCanonicalGraphqlIdentity(
          edge.node.id,
          `repository collaborator ${login} actor node ID`,
        ),
        login,
        actorType: requireCanonicalGraphqlIdentity(
          edge.node.__typename,
          `repository collaborator ${login} actor type`,
        ),
        permission: requireCanonicalGraphqlIdentity(
          edge.permission,
          `repository collaborator ${login} permission`,
        ).toLowerCase() as RepositoryCollaboratorPermissionInputRow['permission'],
      });
    }
    after = pagination.next(connection.pageInfo, requestCursor);
    if (!after) break;
  }

  const expectedCount = totalCount ?? 0;
  if (rows.length !== expectedCount) {
    throw new Error(
      `GitHub GraphQL repository.collaborators exhausted with ${rows.length} rows, ` +
        `but totalCount was ${expectedCount}`,
    );
  }
  rows.sort((left, right) => compareBinary(left.login, right.login));
  return {
    repositoryNodeId: requireCanonicalGraphqlIdentity(
      repositoryNodeId,
      'repository collaborators repository node ID',
    ),
    totalCount: expectedCount,
    pageCount,
    rows,
    digest: createHash('sha256')
      .update(JSON.stringify([
        repositoryNodeId,
        expectedCount,
        rows.map((row) => [row.nodeId, row.login, row.actorType, row.permission]),
      ]))
      .digest('hex'),
  };
}

export async function fetchRepositoryCollaboratorPermissionSnapshot(
  options: RepositoryCollaboratorPermissionFetchOptions = {},
): Promise<RepositoryCollaboratorPermissionSnapshot> {
  const maxSweeps = options.maxSweeps ?? COLLABORATOR_PERMISSION_MAX_SWEEPS;
  if (!Number.isInteger(maxSweeps) || maxSweeps < 2) {
    throw new Error('GitHub collaborator permission snapshot max sweeps must be at least 2');
  }
  let previous: RepositoryCollaboratorPermissionSweep | null = null;
  let pagesFetched = 0;
  for (let sweepCount = 1; sweepCount <= maxSweeps; sweepCount++) {
    const current = await fetchRepositoryCollaboratorPermissionSweep(options);
    pagesFetched += current.pageCount;
    if (
      previous?.digest === current.digest &&
      (
        previous.totalCount !== current.totalCount ||
        previous.repositoryNodeId !== current.repositoryNodeId
      )
    ) {
      throw new Error(
        'GitHub repository collaborator digest matched across impossible authority identity',
      );
    }
    if (previous?.digest === current.digest) {
      return buildRepositoryCollaboratorPermissionSnapshot({
        repositoryNodeId: current.repositoryNodeId,
        repository: `${config.github.owner}/${config.github.repo}`,
        observedAt: new Date((options.now ?? Date.now)()).toISOString(),
        exhaustive: true,
        complete: true,
        totalCount: current.totalCount,
        pageCount: current.pageCount,
        pagesFetched,
        sweepCount,
        rows: current.rows,
      });
    }
    previous = current;
  }
  throw new Error(
    `GitHub GraphQL repository.collaborators failed to stabilize after ` +
      `${maxSweeps} complete sweeps`,
  );
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

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      reject(abortSignalReason(signal!));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

async function sleepWithSignal(
  sleeper: GithubSleep,
  ms: number,
  signal?: AbortSignal,
): Promise<void> {
  throwIfAborted(signal);
  if (!signal) {
    await sleeper(ms);
    return;
  }
  let removeAbortListener: () => void = () => undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    const onAbort = () => reject(abortSignalReason(signal));
    signal.addEventListener('abort', onAbort, { once: true });
    removeAbortListener = () => signal.removeEventListener('abort', onAbort);
    if (signal.aborted) onAbort();
  });
  try {
    await Promise.race([sleeper(ms, signal), aborted]);
  } finally {
    removeAbortListener();
  }
  throwIfAborted(signal);
}

interface RequestLimiterClock {
  now(): number;
  sleep: GithubSleep;
}

interface GraphqlRequestLimiterOptions {
  concurrency: number;
  minStartSpacingMs: number;
  cooldownBaseMs: number;
  cooldownMaxMs: number;
  clock?: RequestLimiterClock;
}

interface PendingGraphqlRequest {
  task: () => Promise<unknown>;
  resolve: (value: unknown) => void;
  reject: (error: unknown) => void;
  signal?: AbortSignal;
  abortListener?: () => void;
  started: boolean;
}

const GRAPHQL_LIMITER_WAKE = Symbol('graphql-limiter-wake');

class GraphqlRequestLimiter {
  private readonly concurrency: number;
  private readonly minStartSpacingMs: number;
  private readonly cooldownBaseMs: number;
  private readonly cooldownMaxMs: number;
  private readonly clock: RequestLimiterClock;
  private readonly queue: PendingGraphqlRequest[] = [];
  private active = 0;
  private draining = false;
  private nextStartAt = 0;
  private blockedUntil = 0;
  private singleFlightUntil = 0;
  private rateLimitLevel = 0;
  private waitController: AbortController | null = null;

  constructor(options: GraphqlRequestLimiterOptions) {
    this.concurrency = options.concurrency;
    this.minStartSpacingMs = options.minStartSpacingMs;
    this.cooldownBaseMs = options.cooldownBaseMs;
    this.cooldownMaxMs = options.cooldownMaxMs;
    this.clock = options.clock ?? { now: Date.now, sleep };
  }

  run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    try {
      throwIfAborted(signal);
    } catch (error) {
      return Promise.reject(error);
    }
    return new Promise<T>((resolve, reject) => {
      const request: PendingGraphqlRequest = {
        task,
        resolve: (value) => resolve(value as T),
        reject,
        signal,
        started: false,
      };
      if (signal) {
        request.abortListener = () => {
          if (request.started) return;
          const index = this.queue.indexOf(request);
          if (index >= 0) this.queue.splice(index, 1);
          this.clearAbortListener(request);
          request.reject(abortSignalReason(signal));
          this.wakeDrain();
          queueMicrotask(() => void this.drain());
        };
        signal.addEventListener('abort', request.abortListener, { once: true });
        if (signal.aborted) {
          request.abortListener();
          return;
        }
      }
      this.queue.push(request);
      void this.drain();
    });
  }

  noteRateLimit(retryAfterMs = 0): number {
    const now = this.clock.now();
    this.rateLimitLevel = now < this.singleFlightUntil
      ? Math.min(this.rateLimitLevel + 1, 20)
      : 1;
    const adaptiveMs = Math.min(
      this.cooldownMaxMs,
      this.cooldownBaseMs * Math.pow(2, this.rateLimitLevel - 1),
    );
    const cooldownMs = Math.max(adaptiveMs, retryAfterMs);
    this.blockedUntil = Math.max(this.blockedUntil, now + cooldownMs);
    this.singleFlightUntil = Math.max(this.singleFlightUntil, this.blockedUntil + adaptiveMs);
    this.wakeDrain();
    return cooldownMs;
  }

  private currentConcurrency(now = this.clock.now()): number {
    return now < this.singleFlightUntil ? 1 : this.concurrency;
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.queue.length > 0) {
        const now = this.clock.now();
        if (this.active >= this.currentConcurrency(now)) return;

        const earliestStart = Math.max(this.nextStartAt, this.blockedUntil);
        if (earliestStart > now) {
          await this.waitForStart(earliestStart - now);
          continue;
        }

        const request = this.queue.shift();
        if (!request) return;
        if (request.signal?.aborted) {
          this.clearAbortListener(request);
          request.reject(abortSignalReason(request.signal));
          continue;
        }
        request.started = true;
        this.active++;
        this.nextStartAt = this.clock.now() + this.minStartSpacingMs;
        void this.execute(request);
      }
    } finally {
      this.draining = false;
    }
  }

  private async execute(request: PendingGraphqlRequest): Promise<void> {
    try {
      const value = await request.task();
      request.resolve(value);
    } catch (error) {
      request.reject(error);
    } finally {
      this.active--;
      this.clearAbortListener(request);
    }
    this.wakeDrain();
    queueMicrotask(() => void this.drain());
  }

  private clearAbortListener(request: PendingGraphqlRequest): void {
    if (request.signal && request.abortListener) {
      request.signal.removeEventListener('abort', request.abortListener);
      request.abortListener = undefined;
    }
  }

  private async waitForStart(delayMs: number): Promise<void> {
    const controller = new AbortController();
    this.waitController = controller;
    try {
      await sleepWithSignal(this.clock.sleep, delayMs, controller.signal);
    } catch (error) {
      if (
        controller.signal.aborted &&
        controller.signal.reason === GRAPHQL_LIMITER_WAKE
      ) {
        return;
      }
      throw error;
    } finally {
      if (this.waitController === controller) this.waitController = null;
    }
  }

  private wakeDrain(): void {
    const controller = this.waitController;
    if (controller && !controller.signal.aborted) {
      controller.abort(GRAPHQL_LIMITER_WAKE);
    }
  }
}

function createGraphqlRequestLimiter(options: GraphqlRequestLimiterOptions): GraphqlRequestLimiter {
  return new GraphqlRequestLimiter(options);
}

const graphqlRequestLimiter = createGraphqlRequestLimiter({
  concurrency: config.github.graphql.concurrency,
  minStartSpacingMs: config.github.graphql.minStartSpacingMs,
  cooldownBaseMs: config.github.graphql.cooldownBaseMs,
  cooldownMaxMs: config.github.graphql.cooldownMaxMs,
});

interface RetryDelayOptions {
  baseMs?: number;
  maxMs?: number;
  random?: () => number;
  now?: () => number;
  fallbackMinMs?: number;
}

function explicitRetryDelayMs(res?: Response, now: () => number = Date.now): number | null {
  const retryAfter = res?.headers.get('retry-after');
  const parsedRetryAfter = retryAfter ? Number(retryAfter) : NaN;
  if (Number.isFinite(parsedRetryAfter) && parsedRetryAfter >= 0) {
    return Math.ceil(parsedRetryAfter * 1000);
  }

  const retryAt = retryAfter ? Date.parse(retryAfter) : NaN;
  if (Number.isFinite(retryAt)) {
    return Math.max(0, retryAt - now());
  }

  const resetAt = Number(res?.headers.get('x-ratelimit-reset'));
  if (Number.isFinite(resetAt) && resetAt > 0) {
    return Math.max(0, resetAt * 1000 - now());
  }
  return null;
}

function retryDelayMs(attempt: number, res?: Response, options: RetryDelayOptions = {}): number {
  const baseMs = options.baseMs ?? config.github.graphql.retryBaseMs;
  const maxMs = options.maxMs ?? config.github.graphql.retryMaxMs;
  const random = options.random ?? Math.random;
  const explicitMs = explicitRetryDelayMs(res, options.now);
  if (explicitMs != null) return explicitMs;
  const rawMs = Math.min(maxMs, baseMs * Math.pow(2, attempt));
  const jitteredMs = Math.min(maxMs, Math.round(rawMs * (0.75 + random() * 0.5)));
  return Math.max(options.fallbackMinMs ?? 0, jitteredMs);
}

function graphqlErrorDetails(errors: GraphqlError[]): string {
  return errors
    .map((e) => [e.type, e.path?.join('.'), e.message].filter(Boolean).join(' '))
    .join('; ');
}

function isRetryableGraphqlError(error: GraphqlError): boolean {
  const type = (error.type ?? '').toUpperCase();
  const message = (error.message ?? '').toLowerCase();
  if (['RATE_LIMITED', 'TIMEOUT', 'INTERNAL', 'SERVER_ERROR', 'SERVICE_UNAVAILABLE'].includes(type)) return true;
  return [
    'secondary rate limit',
    'rate limit',
    'abuse detection',
    'try again',
    'please retry',
    'timed out',
    'timeout',
    'temporarily unavailable',
    'something went wrong',
  ].some((needle) => message.includes(needle));
}

function isRateLimitGraphqlError(error: GraphqlError): boolean {
  const type = (error.type ?? '').toUpperCase();
  const message = (error.message ?? '').toLowerCase();
  return type === 'RATE_LIMITED' || [
    'secondary rate limit',
    'rate limit',
    'abuse detection',
  ].some((needle) => message.includes(needle));
}

function isSecondaryRateLimitGraphqlError(error: GraphqlError): boolean {
  const message = (error.message ?? '').toLowerCase();
  return message.includes('secondary rate limit') || message.includes('abuse detection');
}

function shouldRetryGraphqlErrors(errors: GraphqlError[]): boolean {
  return errors.length > 0 && errors.every(isRetryableGraphqlError);
}

interface HttpRetryClassification {
  retryable: boolean;
  rateLimited: boolean;
  secondaryRateLimited: boolean;
}

function classifyHttpRetry(res: Response, body: string): HttpRetryClassification {
  const normalizedBody = body.toLowerCase();
  const secondaryRateLimited = normalizedBody.includes('secondary rate limit') ||
    normalizedBody.includes('abuse detection');
  const rateLimited = res.status === 429 ||
    res.headers.get('retry-after') != null ||
    res.headers.get('x-ratelimit-remaining') === '0' ||
    secondaryRateLimited ||
    normalizedBody.includes('rate limit');
  return {
    retryable: res.status === 408 || res.status === 429 || res.status >= 500 ||
      (res.status === 403 && rateLimited),
    rateLimited,
    secondaryRateLimited,
  };
}

interface GraphqlRequestScheduler {
  run<T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T>;
  noteRateLimit(retryAfterMs?: number): number;
}

interface GraphqlRequesterOptions {
  fetchImpl?: typeof fetch;
  scheduler?: GraphqlRequestScheduler;
  sleep?: GithubSleep;
  now?: () => number;
  random?: () => number;
  requestTimeoutMs?: number;
  bodyTimeoutMs?: number;
  responseBodyMaxBytes?: number;
  errorBodyMaxBytes?: number;
  retryBaseMs?: number;
  retryMaxMs?: number;
  maxRetries?: number;
  requestHeaders?: () => Record<string, string>;
  warn?: (message: string) => void;
}

function timeoutError(stage: 'request' | 'body', timeoutMs: number): Error {
  return new Error(`GitHub GraphQL ${stage} timed out after ${timeoutMs}ms`);
}

class GithubResponseBodyLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GithubResponseBodyLimitError';
  }
}

function cancelResponseBody(res: Response, reason?: unknown): void {
  if (!res.body) return;
  try {
    void res.body.cancel(reason).catch(() => undefined);
  } catch {
    // A reader may already own the stream lock; its cancellation path still fails closed.
  }
}

async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  createTimeoutError: () => Error,
  signal?: AbortSignal,
): Promise<Response> {
  throwIfAborted(signal);
  const controller = new AbortController();
  return new Promise<Response>((resolve, reject) => {
    let settled = false;
    let timer: NodeJS.Timeout | null = null;
    let settledReason: unknown;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      signal?.removeEventListener('abort', onCallerAbort);
    };
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      settledReason = error;
      cleanup();
      controller.abort(error);
      reject(error);
    };
    const onCallerAbort = () => fail(abortSignalReason(signal!));
    signal?.addEventListener('abort', onCallerAbort, { once: true });
    if (signal?.aborted) {
      onCallerAbort();
      return;
    }
    timer = setTimeout(() => fail(createTimeoutError()), timeoutMs);
    let pending: Promise<Response>;
    try {
      pending = fetchImpl(url, { ...init, signal: controller.signal });
    } catch (error) {
      settled = true;
      cleanup();
      reject(error);
      return;
    }
    pending.then(
      (res) => {
        if (settled) {
          void cancelResponseBody(res, settledReason);
          return;
        }
        settled = true;
        cleanup();
        resolve(res);
      },
      (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

interface BoundedResponseBodyOptions {
  timeoutMs: number;
  maxBytes: number;
  label: string;
  createTimeoutError: () => Error;
  signal?: AbortSignal;
}

async function readBoundedResponseBody(
  res: Response,
  options: BoundedResponseBodyOptions,
): Promise<string> {
  if (options.signal?.aborted) {
    const reason = abortSignalReason(options.signal);
    cancelResponseBody(res, reason);
    throw reason;
  }
  if (!Number.isSafeInteger(options.maxBytes) || options.maxBytes <= 0) {
    throw new Error(
      `${options.label} byte limit must be a positive safe integer, got ${options.maxBytes}`,
    );
  }
  const rawLength = res.headers.get('content-length');
  if (rawLength != null) {
    if (!/^[0-9]+$/.test(rawLength)) {
      cancelResponseBody(res, `${options.label} Content-Length is invalid`);
      throw new GithubResponseBodyLimitError(`${options.label} Content-Length is invalid`);
    }
    const declaredLength = Number(rawLength);
    if (!Number.isSafeInteger(declaredLength)) {
      cancelResponseBody(res, `${options.label} Content-Length exceeds the safe integer range`);
      throw new GithubResponseBodyLimitError(
        `${options.label} Content-Length exceeds the safe integer range`,
      );
    }
    if (declaredLength > options.maxBytes) {
      cancelResponseBody(res, `${options.label} exceeds ${options.maxBytes} bytes`);
      throw new GithubResponseBodyLimitError(
        `${options.label} exceeds ${options.maxBytes} bytes`,
      );
    }
  }
  if (!res.body) return '';

  const reader = res.body.getReader();
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  let timer: NodeJS.Timeout | null = null;
  let removeAbortListener: () => void = () => undefined;
  let interrupted = false;
  const interruption = new Promise<never>((_resolve, reject) => {
    const interrupt = (error: unknown) => {
      if (interrupted) return;
      interrupted = true;
      void reader.cancel(error).catch(() => undefined);
      reject(error);
    };
    timer = setTimeout(() => {
      interrupt(options.createTimeoutError());
    }, options.timeoutMs);
    if (options.signal) {
      const onAbort = () => interrupt(abortSignalReason(options.signal!));
      options.signal.addEventListener('abort', onAbort, { once: true });
      removeAbortListener = () => options.signal?.removeEventListener('abort', onAbort);
      if (options.signal.aborted) onAbort();
    }
  });

  try {
    for (;;) {
      const chunk = await Promise.race([reader.read(), interruption]);
      if (chunk.done) break;
      if (!chunk.value) continue;
      totalBytes += chunk.value.byteLength;
      if (totalBytes > options.maxBytes) {
        const error = new GithubResponseBodyLimitError(
          `${options.label} exceeds ${options.maxBytes} bytes`,
        );
        void reader.cancel(error).catch(() => undefined);
        throw error;
      }
      chunks.push(Buffer.from(chunk.value));
    }
  } finally {
    if (timer) clearTimeout(timer);
    removeAbortListener();
    try {
      reader.releaseLock();
    } catch {
      // Cancellation can retain the lock until the pending read settles.
    }
  }
  return Buffer.concat(chunks, totalBytes).toString('utf8');
}

function createGraphqlRequester(options: GraphqlRequesterOptions = {}): GraphqlRequest {
  const fetchImpl = options.fetchImpl ?? fetch;
  const scheduler = options.scheduler ?? graphqlRequestLimiter;
  const sleeper = options.sleep ?? sleep;
  const now = options.now ?? Date.now;
  const random = options.random ?? Math.random;
  const requestTimeoutMs = options.requestTimeoutMs ?? GRAPHQL_REQUEST_TIMEOUT_MS;
  const bodyTimeoutMs = options.bodyTimeoutMs ?? GRAPHQL_BODY_TIMEOUT_MS;
  const responseBodyMaxBytes = options.responseBodyMaxBytes ?? GITHUB_RESPONSE_BODY_MAX_BYTES;
  const errorBodyMaxBytes = options.errorBodyMaxBytes ?? GITHUB_ERROR_BODY_MAX_BYTES;
  const retryBaseMs = options.retryBaseMs ?? config.github.graphql.retryBaseMs;
  const retryMaxMs = options.retryMaxMs ?? config.github.graphql.retryMaxMs;
  const maxRetries = options.maxRetries ?? 8;
  const requestHeaders = options.requestHeaders ?? headers;
  const warn = options.warn ?? ((message: string) => console.warn(message));

  return async function request<T>(
    query: string,
    variables: Record<string, unknown> = {},
    signal?: AbortSignal,
  ): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      throwIfAborted(signal);
      let outcome:
        | { kind: 'body-error'; response: Response; error: unknown }
        | { kind: 'http-error'; response: Response; body: string; retryable: boolean; delay: number }
        | { kind: 'malformed'; response: Response; body: string; delay: number }
        | {
            kind: 'graphql-error';
            details: string;
            errors: GraphqlError[];
            retryable: boolean;
            delay: number;
          }
        | { kind: 'data-less'; delay: number }
        | { kind: 'success'; data: T };
      try {
        outcome = await scheduler.run(async () => {
          throwIfAborted(signal);
          const res = await fetchWithTimeout(
            fetchImpl,
            API,
            {
              method: 'POST',
              headers: requestHeaders(),
              body: JSON.stringify({ query, variables }),
            },
            requestTimeoutMs,
            () => timeoutError('request', requestTimeoutMs),
            signal,
          );
          let body: string;
          try {
            body = await readBoundedResponseBody(res, {
              timeoutMs: bodyTimeoutMs,
              maxBytes: res.ok ? responseBodyMaxBytes : errorBodyMaxBytes,
              label: `GitHub GraphQL ${res.ok ? 'response' : 'error response'} body`,
              createTimeoutError: () => timeoutError('body', bodyTimeoutMs),
              signal,
            });
          } catch (error) {
            return { kind: 'body-error' as const, response: res, error };
          }

          if (!res.ok) {
            const classification = classifyHttpRetry(res, body);
            const delay = retryDelayMs(attempt, res, {
              baseMs: retryBaseMs,
              maxMs: retryMaxMs,
              random,
              now,
              fallbackMinMs: classification.secondaryRateLimited
                ? SECONDARY_RATE_LIMIT_FALLBACK_MS
                : 0,
            });
            if (classification.rateLimited) scheduler.noteRateLimit(delay);
            return {
              kind: 'http-error' as const,
              response: res,
              body,
              retryable: classification.retryable,
              delay,
            };
          }

          let parsed: GraphqlResponse<T>;
          try {
            const raw = JSON.parse(body) as unknown;
            if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
              throw new Error('response root is not an object');
            }
            parsed = raw as GraphqlResponse<T>;
          } catch {
            return {
              kind: 'malformed' as const,
              response: res,
              body,
              delay: retryDelayMs(attempt, res, {
                baseMs: retryBaseMs,
                maxMs: retryMaxMs,
                random,
                now,
              }),
            };
          }

          if (parsed.errors?.length) {
            const errors = parsed.errors.map((error) => ({
              ...error,
              path: error.path?.slice(),
            }));
            const details = graphqlErrorDetails(errors);
            const secondaryRateLimited = errors.some(isSecondaryRateLimitGraphqlError);
            const delay = retryDelayMs(attempt, res, {
              baseMs: retryBaseMs,
              maxMs: retryMaxMs,
              random,
              now,
              fallbackMinMs: secondaryRateLimited
                ? SECONDARY_RATE_LIMIT_FALLBACK_MS
                : 0,
            });
            if (errors.some(isRateLimitGraphqlError)) scheduler.noteRateLimit(delay);
            return {
              kind: 'graphql-error' as const,
              details,
              errors,
              retryable: shouldRetryGraphqlErrors(errors),
              delay,
            };
          }
          if (parsed.data == null) {
            return {
              kind: 'data-less' as const,
              delay: retryDelayMs(attempt, res, {
                baseMs: retryBaseMs,
                maxMs: retryMaxMs,
                random,
                now,
              }),
            };
          }
          return { kind: 'success' as const, data: parsed.data };
        }, signal);
      } catch (error) {
        throwIfAborted(signal);
        if (attempt < maxRetries) {
          const delay = retryDelayMs(attempt, undefined, {
            baseMs: retryBaseMs,
            maxMs: retryMaxMs,
            random,
            now,
          });
          warn(`[github] network error; retrying in ${Math.round(delay / 1000)}s: ${(error as Error).message}`);
          await sleepWithSignal(sleeper, delay, signal);
          continue;
        }
        throw error;
      }

      throwIfAborted(signal);
      if (outcome.kind === 'body-error') {
        throwIfAborted(signal);
        if (outcome.error instanceof GithubResponseBodyLimitError) throw outcome.error;
        if (attempt < maxRetries) {
          const delay = retryDelayMs(attempt, outcome.response, {
            baseMs: retryBaseMs,
            maxMs: retryMaxMs,
            random,
            now,
          });
          warn(
            `[github] response body error; retrying in ${Math.round(delay / 1000)}s: ` +
              `${outcome.error instanceof Error ? outcome.error.message : String(outcome.error)}`,
          );
          await sleepWithSignal(sleeper, delay, signal);
          continue;
        }
        throw outcome.error;
      }

      if (outcome.kind === 'http-error') {
        if (outcome.retryable && attempt < maxRetries) {
          warn(
            `[github] ${outcome.response.status}; retrying in ` +
              `${Math.round(outcome.delay / 1000)}s`,
          );
          await sleepWithSignal(sleeper, outcome.delay, signal);
          continue;
        }
        throw new Error(
          `GitHub GraphQL ${outcome.response.status}: ${outcome.body.slice(0, 300)}`,
        );
      }

      if (outcome.kind === 'malformed') {
        if (attempt < maxRetries) {
          warn(`[github] malformed response; retrying in ${Math.round(outcome.delay / 1000)}s`);
          await sleepWithSignal(sleeper, outcome.delay, signal);
          continue;
        }
        throw new Error(`GitHub GraphQL returned non-JSON: ${outcome.body.slice(0, 300)}`);
      }

      if (outcome.kind === 'graphql-error') {
        if (outcome.retryable && attempt < maxRetries) {
          warn(
            `[github] GraphQL transient error; retrying in ` +
              `${Math.round(outcome.delay / 1000)}s: ${outcome.details}`,
          );
          await sleepWithSignal(sleeper, outcome.delay, signal);
          continue;
        }
        throw new GithubGraphqlResponseError(outcome.errors);
      }

      if (outcome.kind === 'data-less') {
        if (attempt < maxRetries) {
          warn(`[github] data-less response; retrying in ${Math.round(outcome.delay / 1000)}s`);
          await sleepWithSignal(sleeper, outcome.delay, signal);
          continue;
        }
        throw new Error('GitHub GraphQL response did not include data');
      }
      return outcome.data;
    }
  };
}

const gh = createGraphqlRequester();

function repoVars(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { owner: config.github.owner, repo: config.github.repo, ...extra };
}

function assertRepo<T>(repo: T | null | undefined): T {
  if (!repo) throw new Error(`GitHub repository not found: ${config.github.owner}/${config.github.repo}`);
  return repo;
}

type GraphqlConnection<T> = {
  nodes: Array<T | null> | null;
  pageInfo?: PageInfo | null;
};

type CountedGraphqlConnection<T> = GraphqlConnection<T> & {
  totalCount?: number | null;
};

function requireGraphqlConnection<T>(
  connection: GraphqlConnection<T> | null | undefined,
  context: string,
): { nodes: T[]; pageInfo: PageInfo } {
  if (!connection) throw new Error(`GitHub GraphQL missing ${context} connection`);
  if (!Array.isArray(connection.nodes)) throw new Error(`GitHub GraphQL ${context} connection missing nodes`);
  const nullIndex = connection.nodes.findIndex((node) => node == null);
  if (nullIndex >= 0) throw new Error(`GitHub GraphQL ${context} connection returned null node at index ${nullIndex}`);
  if (!isPageInfo(connection.pageInfo)) throw new Error(`GitHub GraphQL ${context} connection missing pageInfo`);
  return { nodes: connection.nodes as T[], pageInfo: connection.pageInfo };
}

function requireCountedGraphqlConnection<T>(
  connection: CountedGraphqlConnection<T> | null | undefined,
  context: string,
): { nodes: T[]; pageInfo: PageInfo; totalCount: number } {
  const required = requireGraphqlConnection(connection, context);
  if (!Number.isInteger(connection?.totalCount) || Number(connection?.totalCount) < 0) {
    throw new Error(`GitHub GraphQL ${context} connection has invalid totalCount`);
  }
  return {
    ...required,
    totalCount: Number(connection?.totalCount),
  };
}
function isPageInfo(value: unknown): value is PageInfo {
  if (!value || typeof value !== 'object') return false;
  const pageInfo = value as Partial<PageInfo>;
  return typeof pageInfo.hasNextPage === 'boolean' &&
    (pageInfo.endCursor === null || typeof pageInfo.endCursor === 'string');
}

function nextGraphqlPageCursor(pageInfo: PageInfo, context: string): string | null {
  if (!pageInfo.hasNextPage) return null;
  if (!pageInfo.endCursor) {
    throw new Error(`GitHub GraphQL ${context} pageInfo hasNextPage without endCursor`);
  }
  return pageInfo.endCursor;
}

class GraphqlPaginationGuard {
  private readonly seenCursors = new Set<string>();
  private pages = 0;

  constructor(
    private readonly context: string,
    private readonly maxPages = GRAPHQL_MAX_PAGES_PER_CONNECTION,
  ) {
    if (!Number.isInteger(maxPages) || maxPages <= 0) {
      throw new Error(`GitHub GraphQL ${context} max pages must be a positive integer`);
    }
  }

  next(pageInfo: PageInfo, requestCursor: string | null): string | null {
    this.pages++;
    const nextCursor = nextGraphqlPageCursor(pageInfo, this.context);
    if (!nextCursor) return null;
    if (nextCursor === requestCursor || this.seenCursors.has(nextCursor)) {
      throw new Error(`GitHub GraphQL ${this.context} repeated pagination cursor ${nextCursor}`);
    }
    if (this.pages >= this.maxPages) {
      throw new Error(
        `GitHub GraphQL ${this.context} exceeded ${this.maxPages} pages before pagination completed`,
      );
    }
    this.seenCursors.add(nextCursor);
    return nextCursor;
  }
}

function createGraphqlPaginationGuard(
  context: string,
  maxPages = GRAPHQL_MAX_PAGES_PER_CONNECTION,
): GraphqlPaginationGuard {
  return new GraphqlPaginationGuard(context, maxPages);
}

function mapRelease(node: ReleaseNode): GhRelease {
  return {
    node_id: node.id,
    tag_name: node.tagName,
    tag_commit_oid: requireCanonicalGraphqlIdentity(
      node.tagCommit?.oid,
      `release ${node.tagName} tag commit OID`,
    ),
    name: node.name,
    published_at: node.publishedAt,
    created_at: node.createdAt,
    updated_at: node.updatedAt,
    html_url: node.url,
    prerelease: node.isPrerelease,
    draft: node.isDraft,
    body: node.description,
  };
}

function mapIssue(node: IssueNode, completeLabelNodes?: Array<{ name: string }>): GhIssue {
  requireIssueNode(node, `issue #${String(node.number)}`);
  const lifecycle = requireIssueLifecycle(node);
  if (!Array.isArray(node.reactionGroups)) {
    throw new Error(`GitHub GraphQL issue #${node.number} missing reactionGroups`);
  }
  const reactions = summarizeReactions(node.reactionGroups);
  const labels = requireCountedGraphqlConnection(node.labels, `issue #${node.number} labels`);
  const labelNames: string[] = [];
  const seenLabelNames = new Set<string>();
  appendIssueLabelNames(
    node.number,
    completeLabelNodes ?? labels.nodes,
    labelNames,
    seenLabelNames,
  );
  if (seenLabelNames.size !== labels.totalCount) {
    throw new Error(
      `GitHub GraphQL issue #${node.number} labels terminal unique count ${seenLabelNames.size} ` +
      `did not match totalCount ${labels.totalCount}`,
    );
  }
  return {
    node_id: requireCanonicalGraphqlIdentity(
      node.id,
      `issue #${node.number} node ID`,
    ),
    node_type: requireCanonicalGraphqlIdentity(
      node.__typename,
      `issue #${node.number} node type`,
    ) as 'Issue',
    number: node.number,
    title: node.title,
    body: node.body,
    state: lifecycle.state,
    user: node.author
      ? {
          id: requireCanonicalGraphqlIdentity(
            node.author.id,
            `issue #${node.number} author node ID`,
          ),
          type: requireCanonicalGraphqlIdentity(
            node.author.__typename,
            `issue #${node.number} author node type`,
          ),
          login: requireCanonicalGraphqlIdentity(
            node.author.login,
            `issue #${node.number} author login`,
          ),
        }
      : null,
    author_association: node.authorAssociation,
    created_at: node.createdAt,
    updated_at: node.updatedAt,
    closed_at: lifecycle.closedAt,
    html_url: node.url,
    comments: node.comments.totalCount,
    reaction_total: reactions.total,
    positive_reactions: reactions.positive,
    labels: labelNames.sort(compareBinary).map((name) => ({ name })),
  };
}

function requireIssueLifecycle(node: IssueNode): {
  state: GhIssue['state'];
  closedAt: string | null;
} {
  if (node.state !== 'OPEN' && node.state !== 'CLOSED') {
    throw new Error(
      `GitHub GraphQL issue #${node.number} returned unsupported state ${JSON.stringify(node.state)}`,
    );
  }
  if (node.state === 'OPEN') {
    if (node.closedAt !== null) {
      throw new Error(`GitHub GraphQL issue #${node.number} is OPEN but closedAt is not null`);
    }
    return { state: 'open', closedAt: null };
  }
  if (typeof node.closedAt !== 'string' || !Number.isFinite(Date.parse(node.closedAt))) {
    throw new Error(`GitHub GraphQL issue #${node.number} is CLOSED but closedAt is invalid`);
  }
  const closedAtMs = Date.parse(node.closedAt);
  if (
    closedAtMs < Date.parse(node.createdAt) ||
    closedAtMs > Date.parse(node.updatedAt) + ISSUE_CLOSED_AT_SKEW_TOLERANCE_MS
  ) {
    throw new Error(`GitHub GraphQL issue #${node.number} has inconsistent closedAt chronology`);
  }
  return { state: 'closed', closedAt: node.closedAt };
}

function appendIssueLabelNames(
  issueNumber: number,
  nodes: Array<{ name: string }>,
  labels: string[],
  seen: Set<string>,
): void {
  for (const label of nodes) {
    if (typeof label?.name !== 'string' || label.name.length === 0) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} labels returned invalid label name`);
    }
    if (seen.has(label.name)) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} labels returned duplicate label ${label.name}`);
    }
    seen.add(label.name);
    labels.push(label.name);
  }
}

function mapComment(node: CommentNode): GhComment {
  const nodeId = requireCanonicalGraphqlIdentity(node.id, 'issue comment node ID');
  const nodeType = requireCanonicalGraphqlIdentity(
    node.__typename,
    `issue comment ${nodeId} node type`,
  );
  if (nodeType !== 'IssueComment') {
    throw new Error(`GitHub GraphQL issue comment ${nodeId} returned node type ${nodeType}`);
  }
  return {
    id: node.databaseId ?? 0,
    node_id: nodeId,
    node_type: nodeType,
    url: node.url,
    user: node.author
      ? {
          id: requireCanonicalGraphqlIdentity(
            node.author.id,
            `issue comment ${nodeId} author node ID`,
          ),
          type: requireCanonicalGraphqlIdentity(
            node.author.__typename,
            `issue comment ${nodeId} author node type`,
          ),
          login: requireCanonicalGraphqlIdentity(
            node.author.login,
            `issue comment ${nodeId} author login`,
          ),
        }
      : null,
    author_association: node.authorAssociation,
    body: node.body,
    created_at: node.createdAt,
    updated_at: node.updatedAt,
  };
}

function summarizeReactions(nodes: Array<ReactionGroupNode | null>): {
  total: number;
  positive: number;
} {
  const supportedContent = new Set([
    'THUMBS_UP',
    'THUMBS_DOWN',
    'LAUGH',
    'HOORAY',
    'CONFUSED',
    'HEART',
    'ROCKET',
    'EYES',
  ]);
  const positiveContent = new Set(['THUMBS_UP', 'HOORAY', 'HEART', 'ROCKET']);
  const seenContent = new Set<string>();
  let total = 0;
  let positive = 0;
  for (let index = 0; index < nodes.length; index++) {
    const node = nodes[index];
    if (!node || typeof node !== 'object') {
      throw new Error(`GitHub GraphQL reactionGroups returned null group at index ${index}`);
    }
    if (typeof node.content !== 'string' || !supportedContent.has(node.content)) {
      throw new Error(
        `GitHub GraphQL reactionGroups returned unsupported content ` +
          `${JSON.stringify(node.content)} at index ${index}`,
      );
    }
    if (seenContent.has(node.content)) {
      throw new Error(`GitHub GraphQL reactionGroups returned duplicate content ${node.content}`);
    }
    seenContent.add(node.content);
    const count = node.reactors?.totalCount;
    if (!Number.isSafeInteger(count) || Number(count) < 0) {
      throw new Error(
        `GitHub GraphQL reactionGroups returned invalid count for ${node.content}`,
      );
    }
    if (!Number.isSafeInteger(total + Number(count))) {
      throw new Error('GitHub GraphQL reactionGroups total exceeds the safe integer range');
    }
    total += count;
    if (positiveContent.has(node.content)) {
      positive += count;
    }
  }
  return { total, positive };
}

export interface ReleaseCatalogFetchOptions {
  request?: GraphqlRequest;
  repository?: GithubRepositoryCoordinates;
  maxPagesPerConnection?: number;
  signal?: AbortSignal;
  operationBinding?: GithubReleaseCatalogOperationBinding;
}

export interface GithubRepositoryCoordinates {
  owner: string;
  repo: string;
}

export interface ReleaseCatalogRepositoryFetchOptions {
  owner: string;
  repo: string;
  token: string;
  maxPagesPerConnection?: number;
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
}

interface ReleaseCatalogSweep {
  releases: GhRelease[];
  repositoryNodeId: string;
  repositoryNameWithOwner: string;
  totalCount: number;
  pageCount: number;
  digest: string;
}

function buildReleasesQuery(): string {
  return `query Releases($owner: String!, $repo: String!, $first: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      id
      nameWithOwner
      releases(first: $first, after: $after, orderBy: {field: CREATED_AT, direction: DESC}) {
        totalCount
        nodes {
          id
          tagName
          tagCommit { oid }
          name
          publishedAt
          createdAt
          updatedAt
          url
          isPrerelease
          isDraft
          description
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }`;
}

function requireReleaseNode(node: ReleaseNode, context: string): ReleaseNode {
  if (typeof node.id !== 'string' || node.id.length === 0) {
    throw new Error(`GitHub GraphQL ${context} returned a release with missing immutable node id`);
  }
  if (typeof node.tagName !== 'string' || node.tagName.length === 0) {
    throw new Error(`GitHub GraphQL ${context} returned release ${node.id} with missing tag`);
  }
  if (!node.tagCommit) {
    throw new Error(`GitHub GraphQL ${context} returned release ${node.tagName} with missing tag commit`);
  }
  requireCanonicalGraphqlIdentity(
    node.tagCommit.oid,
    `${context} release ${node.tagName} tag commit OID`,
  );
  if (typeof node.createdAt !== 'string' || node.createdAt.length === 0) {
    throw new Error(`GitHub GraphQL ${context} returned release ${node.tagName} with missing createdAt`);
  }
  if (typeof node.updatedAt !== 'string' || node.updatedAt.length === 0) {
    throw new Error(`GitHub GraphQL ${context} returned release ${node.tagName} with missing updatedAt`);
  }
  return node;
}

function requireCanonicalGraphqlIdentity(value: unknown, context: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`GitHub GraphQL ${context} is missing or non-canonical`);
  }
  return value;
}

function requireRequestedIssueGraphqlIdentity(
  issue: { id?: unknown; __typename?: unknown; number?: unknown },
  requestedIssueNumber: number,
  context: string,
): { issueNodeId: string; issueNodeType: 'Issue' } {
  const issueNodeId = requireCanonicalGraphqlIdentity(
    issue.id,
    `${context} issue node ID`,
  );
  const issueNodeType = requireCanonicalGraphqlIdentity(
    issue.__typename,
    `${context} issue node type`,
  );
  if (issueNodeType !== 'Issue') {
    throw new Error(`${context} returned unexpected issue node type ${issueNodeType}`);
  }
  if (
    typeof issue.number !== 'number' ||
    !Number.isInteger(issue.number) ||
    issue.number <= 0
  ) {
    throw new Error(
      `${context} returned invalid issue number ${String(issue.number)}`,
    );
  }
  if (issue.number !== requestedIssueNumber) {
    throw new Error(
      `${context} returned issue #${String(issue.number)} ` +
        `for requested issue #${requestedIssueNumber}`,
    );
  }
  return { issueNodeId, issueNodeType: 'Issue' };
}

function compareBinary(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalReleaseCatalogDigest(totalCount: number, nodes: ReleaseNode[]): string {
  const canonical = nodes
    .slice()
    .sort((left, right) => compareBinary(left.id, right.id) || compareBinary(left.tagName, right.tagName))
    .map((node) => [
      node.id,
      node.tagName,
      node.tagCommit?.oid ?? null,
      node.name,
      node.publishedAt,
      node.createdAt,
      node.updatedAt,
      node.url,
      node.isPrerelease,
      node.isDraft,
      node.description,
    ]);
  return createHash('sha256')
    .update(JSON.stringify([totalCount, canonical]))
    .digest('hex');
}

function fetchedReleaseCatalogFingerprint(catalog: GhReleaseCatalog): string {
  const releases = catalog.releases
    .slice()
    .sort((left, right) =>
      compareBinary(left.node_id, right.node_id) ||
      compareBinary(left.tag_name, right.tag_name))
    .map((release) => [
      release.node_id,
      release.tag_name,
      release.tag_commit_oid,
      release.name,
      release.published_at,
      release.created_at,
      release.updated_at,
      release.html_url,
      release.prerelease,
      release.draft,
      release.body,
    ]);
  return createHash('sha256')
    .update(JSON.stringify([
      'fetched_github_release_catalog',
      1,
      catalog.metadata,
      releases,
    ]))
    .digest('hex');
}

function canonicalGithubReleaseCatalogActiveRelease(
  release: GithubReleaseCatalogActiveRelease,
): readonly unknown[] {
  if (!release.node_id || release.node_id.trim() !== release.node_id) {
    throw new Error('Active GitHub release catalog row has invalid node_id');
  }
  if (!release.tag || release.tag.trim() !== release.tag) {
    throw new Error('Active GitHub release catalog row has invalid tag');
  }
  if (!/^[0-9a-f]{40,64}$/i.test(release.catalog_tag_commit_oid)) {
    throw new Error(
      `Active GitHub release catalog row ${release.tag} has invalid tag commit OID`,
    );
  }
  for (const [field, value] of [
    ['published_at', release.published_at],
    ['created_at', release.created_at],
    ['updated_at', release.updated_at],
  ] as const) {
    if (
      typeof value !== 'string' ||
      !value ||
      !Number.isFinite(Date.parse(value))
    ) {
      throw new Error(
        `Active GitHub release catalog row ${release.tag} has invalid ${field}`,
      );
    }
  }
  if (
    typeof release.html_url !== 'string' ||
    !release.html_url.startsWith('https://github.com/')
  ) {
    throw new Error(
      `Active GitHub release catalog row ${release.tag} has invalid GitHub URL`,
    );
  }
  if (typeof release.prerelease !== 'boolean') {
    throw new Error(
      `Active GitHub release catalog row ${release.tag} has invalid prerelease flag`,
    );
  }
  if (release.name != null && typeof release.name !== 'string') {
    throw new Error(
      `Active GitHub release catalog row ${release.tag} has invalid name`,
    );
  }
  if (release.body != null && typeof release.body !== 'string') {
    throw new Error(
      `Active GitHub release catalog row ${release.tag} has invalid body`,
    );
  }
  return [
    release.node_id,
    release.catalog_tag_commit_oid.toLowerCase(),
    release.tag,
    release.name,
    release.published_at,
    release.created_at,
    release.updated_at,
    release.html_url,
    release.prerelease,
    release.body,
  ];
}

function activeReleaseFromGithubRelease(
  release: GhRelease,
): GithubReleaseCatalogActiveRelease {
  if (release.draft) {
    throw new Error(
      `Draft GitHub release ${release.tag_name} cannot enter the active catalog`,
    );
  }
  if (!release.published_at) {
    throw new Error(
      `Published GitHub release ${release.tag_name} is missing published_at`,
    );
  }
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

function orderGithubReleaseCatalogByPublication(
  releases: readonly GithubReleaseCatalogActiveRelease[],
): GithubReleaseCatalogActiveRelease[] {
  const timestamps = new Map<GithubReleaseCatalogActiveRelease, number>();
  for (const release of releases) {
    canonicalGithubReleaseCatalogActiveRelease(release);
    timestamps.set(release, Date.parse(release.published_at));
  }
  return [...releases].sort((left, right) => {
    const publishedDifference =
      (timestamps.get(right) ?? 0) - (timestamps.get(left) ?? 0);
    return publishedDifference ||
      compareBinary(left.tag, right.tag) ||
      compareBinary(left.node_id, right.node_id);
  });
}

export function githubReleaseCatalogActiveReleaseDigest(
  releases: readonly GithubReleaseCatalogActiveRelease[],
): string {
  const nodeIds = new Set<string>();
  const tags = new Set<string>();
  const canonical = releases.map((release) => {
    if (nodeIds.has(release.node_id)) {
      throw new Error(
        `Active GitHub release catalog contains duplicate node_id ${release.node_id}`,
      );
    }
    if (tags.has(release.tag)) {
      throw new Error(
        `Active GitHub release catalog contains duplicate tag ${release.tag}`,
      );
    }
    nodeIds.add(release.node_id);
    tags.add(release.tag);
    return canonicalGithubReleaseCatalogActiveRelease(release);
  });
  return createHash('sha256')
    .update(JSON.stringify(['github_active_release_catalog', 1, canonical]))
    .digest('hex');
}

interface GithubReleaseCatalogPublicationValidation {
  sweepPageCounts: readonly number[];
  publishedCount: number;
  draftCount: number;
  activeReleaseDigest: string;
  activeReleaseCount: number;
}

function validateGithubReleaseCatalogPublication(
  catalog: GhReleaseCatalog,
  activeReleases: readonly GithubReleaseCatalogActiveRelease[],
): GithubReleaseCatalogPublicationValidation {
  if (
    catalog.metadata.exhausted !== true ||
    catalog.metadata.stabilized !== true ||
    catalog.metadata.nodeCount !== catalog.metadata.totalCount ||
    catalog.releases.length !== catalog.metadata.nodeCount
  ) {
    throw new Error(
      'Release catalog publication authorization requires an exhaustive stabilized catalog',
    );
  }
  const sweepPageCounts = catalog.metadata.sweepPageCounts;
  if (
    !Array.isArray(sweepPageCounts) ||
    sweepPageCounts.length !== catalog.metadata.sweepCount ||
    sweepPageCounts.some(
      (pageCount) => !Number.isSafeInteger(pageCount) || pageCount <= 0,
    ) ||
    sweepPageCounts.reduce((sum, pageCount) => sum + pageCount, 0) !==
      catalog.metadata.pagesFetched ||
    sweepPageCounts.at(-1) !== catalog.metadata.pageCount
  ) {
    throw new Error(
      'Release catalog publication authorization requires exact per-sweep page counts',
    );
  }
  const published = catalog.releases
    .filter((release) => !release.draft)
    .map(activeReleaseFromGithubRelease);
  const canonicalPublished =
    orderGithubReleaseCatalogByPublication(published)
      .map(canonicalGithubReleaseCatalogActiveRelease);
  const canonicalActive = activeReleases
    .map(canonicalGithubReleaseCatalogActiveRelease);
  if (
    canonicalActive.length !== canonicalPublished.length ||
    JSON.stringify(canonicalActive) !== JSON.stringify(canonicalPublished)
  ) {
    throw new Error(
      'Active release catalog must contain every non-draft release from the fetched GraphQL catalog in exact publication order',
    );
  }
  return {
    sweepPageCounts: Object.freeze([...sweepPageCounts]),
    publishedCount: published.length,
    draftCount: catalog.releases.length - published.length,
    activeReleaseDigest:
      githubReleaseCatalogActiveReleaseDigest(activeReleases),
    activeReleaseCount: activeReleases.length,
  };
}

export function authorizeGithubReleaseCatalogPublication(
  catalog: GhReleaseCatalog,
  activeReleases: readonly GithubReleaseCatalogActiveRelease[],
): GithubReleaseCatalogPublicationAuthorization {
  const fetched = fetchedReleaseCatalogs.get(catalog);
  if (!fetched) {
    throw new Error(
      'Release catalog publication authorization requires the exact object returned by fetchReleaseCatalog',
    );
  }
  if (fetched.requestAuthority !== 'production') {
    throw new Error(
      'Release catalog publication authorization requires the built-in production GitHub GraphQL requester; injected requesters are untrusted',
    );
  }
  if (fetched.fingerprint !== fetchedReleaseCatalogFingerprint(catalog)) {
    throw new Error(
      'Fetched release catalog changed after GraphQL provenance was captured',
    );
  }
  if (!fetched.operationBinding) {
    throw new Error(
      'Release catalog publication authorization requires an exact refresh operation binding captured with the GraphQL fetch',
    );
  }
  const validation = validateGithubReleaseCatalogPublication(
    catalog,
    activeReleases,
  );
  const authorization = Object.freeze({
    schemaVersion: 1 as const,
  });
  const evidence = Object.freeze({
    schemaVersion: 1 as const,
    repository: fetched.repository,
    observedAt: fetched.observedAt,
    operationRunId: fetched.operationBinding.operationRunId,
    operation: fetched.operationBinding.operation,
    operationAttemptContentHash:
      fetched.operationBinding.operationAttemptContentHash,
    remoteCatalog: Object.freeze({
      ...catalog.metadata,
      sweepPageCounts: validation.sweepPageCounts,
      repositoryNodeId: fetched.repositoryNodeId,
      repositoryNameWithOwner: fetched.repositoryNameWithOwner,
      publishedCount: validation.publishedCount,
      draftCount: validation.draftCount,
    }),
    activeReleaseDigest: validation.activeReleaseDigest,
    activeReleaseCount: validation.activeReleaseCount,
  });
  releaseCatalogPublicationAuthorizations.set(authorization, evidence);
  return authorization;
}

export function githubReleaseCatalogPublicationEvidence(
  authorization: GithubReleaseCatalogPublicationAuthorization,
): Readonly<GithubReleaseCatalogPublicationEvidence> {
  const evidence = releaseCatalogPublicationAuthorizations.get(
    authorization as object,
  );
  if (!evidence) {
    throw new Error(
      'Release catalog publication authorization is missing its in-process GraphQL provenance',
    );
  }
  return evidence;
}

async function fetchReleaseCatalogSweep(
  options: ReleaseCatalogFetchOptions = {},
): Promise<ReleaseCatalogSweep> {
  const request = options.request ?? gh;
  const repositoryCoordinates = normalizeGithubRepositoryCoordinates(
    options.repository ?? {
      owner: config.github.owner,
      repo: config.github.repo,
    },
  );
  const nodes: ReleaseNode[] = [];
  const nodeIds = new Set<string>();
  const tags = new Set<string>();
  let after: string | null = null;
  let repositoryNodeId: string | null = null;
  let repositoryNameWithOwner: string | null = null;
  let totalCount: number | null = null;
  let pageCount = 0;
  const pagination = createGraphqlPaginationGuard(
    'repository.releases',
    options.maxPagesPerConnection,
  );

  for (;;) {
    const requestCursor: string | null = after;
    const data: ReleasesQueryData = await request<ReleasesQueryData>(
      buildReleasesQuery(),
      {
        owner: repositoryCoordinates.owner,
        repo: repositoryCoordinates.repo,
        first: GRAPHQL_PAGE_SIZE,
        after,
      },
      options.signal,
    );

    const repository = data.repository;
    if (!repository) {
      throw new Error(
        `GitHub repository not found: ` +
          `${repositoryCoordinates.owner}/${repositoryCoordinates.repo}`,
      );
    }
    const pageRepositoryNodeId = requireCanonicalGraphqlIdentity(
      repository.id,
      'repository node ID',
    );
    const pageRepositoryNameWithOwner = requireCanonicalGraphqlIdentity(
      repository.nameWithOwner,
      'repository nameWithOwner',
    );
    const requestedRepository =
      `${repositoryCoordinates.owner}/${repositoryCoordinates.repo}`;
    if (
      pageRepositoryNameWithOwner.toLowerCase() !==
      requestedRepository.toLowerCase()
    ) {
      throw new Error(
        `GitHub GraphQL repository identity ${pageRepositoryNameWithOwner} ` +
        `did not match requested ${requestedRepository}`,
      );
    }
    if (repositoryNodeId == null) {
      repositoryNodeId = pageRepositoryNodeId;
      repositoryNameWithOwner = pageRepositoryNameWithOwner;
    } else if (
      repositoryNodeId !== pageRepositoryNodeId ||
      repositoryNameWithOwner !== pageRepositoryNameWithOwner
    ) {
      throw new Error(
        'GitHub GraphQL repository identity changed within release catalog sweep',
      );
    }
    const connection = requireGraphqlConnection(
      repository.releases,
      'repository.releases',
    );
    const connectionTotalCount = repository.releases.totalCount;
    if (!Number.isInteger(connectionTotalCount) || connectionTotalCount < 0) {
      throw new Error(
        `GitHub GraphQL repository.releases returned invalid totalCount ${String(connectionTotalCount)}`,
      );
    }
    if (totalCount == null) {
      totalCount = connectionTotalCount;
    } else if (connectionTotalCount !== totalCount) {
      throw new Error(
        `GitHub GraphQL repository.releases totalCount changed within sweep ` +
        `from ${totalCount} to ${connectionTotalCount}`,
      );
    }
    pageCount++;
    for (let index = 0; index < connection.nodes.length; index++) {
      const node = requireReleaseNode(
        connection.nodes[index],
        `repository.releases page ${pageCount} node ${index}`,
      );
      if (nodeIds.has(node.id)) {
        throw new Error(`GitHub GraphQL repository.releases returned duplicate node id ${node.id}`);
      }
      if (tags.has(node.tagName)) {
        throw new Error(`GitHub GraphQL repository.releases returned duplicate tag ${node.tagName}`);
      }
      nodeIds.add(node.id);
      tags.add(node.tagName);
      nodes.push(node);
    }

    after = pagination.next(connection.pageInfo, requestCursor);
    if (!after) break;
  }

  const expectedCount = totalCount ?? 0;
  if (nodes.length !== expectedCount) {
    throw new Error(
      `GitHub GraphQL repository.releases exhausted with ${nodes.length} nodes, ` +
      `but totalCount was ${expectedCount}`,
    );
  }
  return {
    releases: nodes.map(mapRelease),
    repositoryNodeId: repositoryNodeId!,
    repositoryNameWithOwner: repositoryNameWithOwner!,
    totalCount: expectedCount,
    pageCount,
    digest: canonicalReleaseCatalogDigest(expectedCount, nodes),
  };
}

export async function fetchReleaseCatalog(
  options: ReleaseCatalogFetchOptions = {},
): Promise<GhReleaseCatalog> {
  const requestAuthority = options.request == null
    ? 'production'
    : 'injected';
  const repositoryCoordinates = normalizeGithubRepositoryCoordinates(
    options.repository ?? {
      owner: config.github.owner,
      repo: config.github.repo,
    },
  );
  const operationBinding = options.operationBinding == null
    ? null
    : normalizeGithubReleaseCatalogOperationBinding(
        options.operationBinding,
      );
  let previous: ReleaseCatalogSweep | null = null;
  let pagesFetched = 0;
  const sweepPageCounts: number[] = [];

  for (let sweepCount = 1; sweepCount <= RELEASE_CATALOG_MAX_SWEEPS; sweepCount++) {
    const current = await fetchReleaseCatalogSweep(options);
    pagesFetched += current.pageCount;
    sweepPageCounts.push(current.pageCount);
    if (previous?.digest === current.digest) {
      if (
        previous.repositoryNodeId !== current.repositoryNodeId ||
        previous.repositoryNameWithOwner !== current.repositoryNameWithOwner
      ) {
        throw new Error(
          'GitHub GraphQL repository identity changed between stabilized release sweeps',
        );
      }
      const catalog: GhReleaseCatalog = {
        releases: current.releases,
        metadata: {
          exhausted: true,
          stabilized: true,
          totalCount: current.totalCount,
          nodeCount: current.releases.length,
          pageCount: current.pageCount,
          pagesFetched,
          sweepCount,
          sweepPageCounts: [...sweepPageCounts],
          digest: current.digest,
          sourceOrder: 'CREATED_AT_DESC',
        },
      };
      fetchedReleaseCatalogs.set(catalog, {
        repository:
          `${repositoryCoordinates.owner}/${repositoryCoordinates.repo}`,
        repositoryNodeId: current.repositoryNodeId,
        repositoryNameWithOwner: current.repositoryNameWithOwner,
        observedAt: new Date().toISOString(),
        operationBinding,
        requestAuthority,
        fingerprint: fetchedReleaseCatalogFingerprint(catalog),
      });
      return catalog;
    }
    previous = current;
  }

  throw new Error(
    `GitHub GraphQL repository.releases failed to stabilize after ` +
    `${RELEASE_CATALOG_MAX_SWEEPS} complete sweeps`,
  );
}

export async function fetchReleaseCatalogForRepository(
  options: ReleaseCatalogRepositoryFetchOptions,
): Promise<GhReleaseCatalog> {
  const repository = normalizeGithubRepositoryCoordinates(options);
  const token = canonicalGithubToken(options.token);
  const request = createGraphqlRequester({
    fetchImpl: options.fetchImpl,
    requestHeaders: () => githubHeaders(token),
  });
  return fetchReleaseCatalog({
    request,
    repository,
    maxPagesPerConnection: options.maxPagesPerConnection,
    signal: options.signal,
  });
}

function normalizeGithubRepositoryCoordinates(
  value: GithubRepositoryCoordinates,
): GithubRepositoryCoordinates {
  const owner = canonicalGithubRepositoryPart(value.owner, 'owner');
  const repo = canonicalGithubRepositoryPart(value.repo, 'repository');
  return { owner, repo };
}

function canonicalGithubRepositoryPart(
  value: unknown,
  label: string,
): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.trim() !== value ||
    value.includes('/') ||
    /\s/.test(value)
  ) {
    throw new Error(`GitHub ${label} must be a canonical path component`);
  }
  return value;
}

function canonicalGithubToken(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.trim() !== value ||
    /[\r\n\0]/.test(value)
  ) {
    throw new Error(
      'GITHUB_TOKEN is required because GitHub GraphQL API requests must be authenticated',
    );
  }
  return value;
}

function githubHeaders(token: string): Record<string, string> {
  return {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'User-Agent': 'openclaw-release-radar',
    Authorization: `Bearer ${token}`,
  };
}

function normalizeGithubReleaseCatalogOperationBinding(
  binding: GithubReleaseCatalogOperationBinding,
): Readonly<GithubReleaseCatalogOperationBinding> {
  if (
    !binding.operationRunId ||
    binding.operationRunId.trim() !== binding.operationRunId
  ) {
    throw new Error(
      'Release catalog GraphQL operationRunId must be canonical',
    );
  }
  if (
    !binding.operation ||
    binding.operation.trim() !== binding.operation
  ) {
    throw new Error(
      'Release catalog GraphQL operation must be canonical',
    );
  }
  if (
    !/^[0-9a-f]{64}$/.test(binding.operationAttemptContentHash)
  ) {
    throw new Error(
      'Release catalog GraphQL operation attempt content hash must be sha256',
    );
  }
  return Object.freeze({ ...binding });
}

// Compatibility wrapper for callers that still need the old bounded array shape.
// The underlying catalog is always fetched to explicit exhaustion and stabilized.
export async function listReleases(
  fetchSize = 60,
  options: ReleaseCatalogFetchOptions = {},
): Promise<GhRelease[]> {
  const wanted = Math.max(1, fetchSize);
  const catalog = await fetchReleaseCatalog(options);
  return catalog.releases
    .filter((release) => !release.draft)
    .slice(0, wanted);
}

// Stream issues sorted by updated_at descending, one GraphQL page at a time.
// GraphQL repository.issues excludes pull requests, so no PR stripping is needed.
export interface IssuePaginationOptions extends Pick<
  IssueBatchOptions,
  'maxPagesPerConnection' | 'request' | 'signal'
> {
  perPage?: number;
  pageDelayMs?: number;
  sleep?: GithubSleep;
  frozenBoundary?: GhIssueSnapshotBoundary;
}

interface CanonicalIssueRecord {
  nodeId: string;
  issue: GhIssue;
}

interface IncrementalIssueSweep {
  issues: GhIssue[];
  totalCount: number;
  pageCount: number;
  membershipDigest: string;
  contentDigest: string;
  lastRequestCursor: string | null;
}

export interface GhIssueCatalogBoundaryVerification {
  issues: GhIssueCatalogIssue[];
  boundary: GhIssueSnapshotBoundary;
  observedTotalCount: number;
  pageCount: number;
  membershipDigest: string;
  contentDigest: string;
  lastRequestCursor: string | null;
}

function buildIssuesQuery(
  sourceOrder: 'UPDATED_AT_DESC' | 'CREATED_AT_ASC' = 'UPDATED_AT_DESC',
): string {
  const orderBy = sourceOrder === 'CREATED_AT_ASC'
    ? '{field: CREATED_AT, direction: ASC}'
    : '{field: UPDATED_AT, direction: DESC}';
  return `query Issues($owner: String!, $repo: String!, $first: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      issues(
        first: $first
        after: $after
        states: [OPEN, CLOSED]
        orderBy: ${orderBy}
      ) {
        totalCount
        nodes {
          id
          number
          title
          body
          state
          __typename
          author { __typename login ... on Node { id } }
          authorAssociation
          createdAt
          updatedAt
          closedAt
          url
          comments { totalCount }
          reactionGroups { content reactors { totalCount } }
          labels(first: 100) {
            totalCount
            nodes { name }
            pageInfo { hasNextPage endCursor }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }`;
}

function requireIssueNode(node: IssueNode, context: string): IssueNode {
  if (typeof node.id !== 'string' || node.id.length === 0) {
    throw new Error(`GitHub GraphQL ${context} returned an issue with missing immutable node id`);
  }
  if (node.__typename !== 'Issue') {
    throw new Error(
      `GitHub GraphQL ${context} returned unexpected node type ${String(node.__typename)}`,
    );
  }
  if (!Number.isInteger(node.number) || node.number <= 0) {
    throw new Error(`GitHub GraphQL ${context} returned invalid issue number ${String(node.number)}`);
  }
  if (typeof node.createdAt !== 'string' || !Number.isFinite(Date.parse(node.createdAt))) {
    throw new Error(`GitHub GraphQL ${context} returned issue #${node.number} with invalid createdAt`);
  }
  if (typeof node.updatedAt !== 'string' || !Number.isFinite(Date.parse(node.updatedAt))) {
    throw new Error(`GitHub GraphQL ${context} returned issue #${node.number} with invalid updatedAt`);
  }
  return node;
}

const canonicalIssueCatalogDigest = canonicalIssueContentDigest;

async function* paginateIncrementalIssueSweep(
  perPage = GRAPHQL_PAGE_SIZE,
  options: IssuePaginationOptions = {},
): AsyncGenerator<GhIssuePage, IncrementalIssueSweep, void> {
  const first = Math.min(GRAPHQL_PAGE_SIZE, Math.max(1, perPage));
  let after: string | null = null;
  let totalCount: number | null = null;
  let pageCount = 0;
  let lastRequestCursor: string | null = null;
  const issues: GhIssue[] = [];
  const records: CanonicalIssueRecord[] = [];
  const nodeIds = new Set<string>();
  const issueNumbers = new Set<number>();
  const pagination = createGraphqlPaginationGuard(
    'repository.issues',
    options.maxPagesPerConnection,
  );
  const request = options.request ?? gh;
  const pageDelayMs = options.pageDelayMs ?? config.refresh.githubPageDelayMs;
  const sleeper = options.sleep ?? sleep;

  for (;;) {
    if (after && pageDelayMs > 0) {
      await sleepWithSignal(sleeper, pageDelayMs, options.signal);
    }
    const requestCursor: string | null = after;
    lastRequestCursor = requestCursor;
    const data: IssuesQueryData = await request<IssuesQueryData>(
      buildIssuesQuery('UPDATED_AT_DESC'),
      repoVars({ first, after }),
      options.signal,
    );

    const connection = requireCountedGraphqlConnection(
      assertRepo(data.repository).issues,
      'repository.issues',
    );
    if (totalCount == null) {
      totalCount = connection.totalCount;
    } else if (connection.totalCount !== totalCount) {
      throw new Error(
        `GitHub GraphQL repository.issues totalCount changed within sweep ` +
        `from ${totalCount} to ${connection.totalCount}`,
      );
    }

    pageCount++;
    const pageNodes = connection.nodes.map((node, index) =>
      requireIssueNode(node, `repository.issues page ${pageCount} node ${index}`));
    for (const node of pageNodes) {
      if (nodeIds.has(node.id)) {
        throw new Error(`GitHub GraphQL repository.issues returned duplicate node id ${node.id}`);
      }
      if (issueNumbers.has(node.number)) {
        throw new Error(`GitHub GraphQL repository.issues returned duplicate issue number ${node.number}`);
      }
      nodeIds.add(node.id);
      issueNumbers.add(node.number);
    }

    const nextCursor = pagination.next(connection.pageInfo, requestCursor);
    if (!nextCursor && issueNumbers.size !== totalCount) {
      throw new Error(
        `GitHub GraphQL repository.issues terminal unique count ${issueNumbers.size} ` +
        `did not match totalCount ${totalCount}`,
      );
    }

    const completeLabels = await stableIssueLabelsForNodes(pageNodes, options);
    const pageIssues = pageNodes.map((node) =>
      mapIssue(node, completeLabels.get(node.number)));
    for (let index = 0; index < pageIssues.length; index++) {
      issues.push(pageIssues[index]);
      records.push({ nodeId: pageNodes[index].id, issue: pageIssues[index] });
    }

    const exhausted = nextCursor == null;
    const membershipDigest = exhausted
      ? canonicalIssueMembershipDigest(totalCount, records)
      : null;
    const contentDigest = exhausted
      ? canonicalIssueContentDigest(totalCount, records)
      : null;
    yield {
      issues: pageIssues,
      metadata: {
        totalCount,
        fetchedCount: issues.length,
        uniqueCount: issueNumbers.size,
        pageCount,
        requestCursor,
        nextCursor,
        hasNextPage: nextCursor != null,
        exhausted,
        digest: membershipDigest,
        membershipDigest,
        contentDigest,
        sourceOrder: 'UPDATED_AT_DESC',
      },
    };

    if (exhausted) {
      return {
        issues,
        totalCount,
        pageCount,
        membershipDigest: membershipDigest!,
        contentDigest: contentDigest!,
        lastRequestCursor,
      };
    }
    after = nextCursor;
  }
}

export async function* paginateIssues(
  perPage = GRAPHQL_PAGE_SIZE,
  options: IssuePaginationOptions = {},
): AsyncGenerator<GhIssuePage, GhIssueIncrementalSweepMetadata, void> {
  const sweep = yield* paginateIncrementalIssueSweep(perPage, options);
  return {
    exhausted: true,
    stabilized: false,
    totalCount: sweep.totalCount,
    nodeCount: sweep.issues.length,
    uniqueCount: sweep.issues.length,
    pageCount: sweep.pageCount,
    pagesFetched: sweep.pageCount,
    sweepCount: 1,
    digest: sweep.membershipDigest,
    membershipDigest: sweep.membershipDigest,
    contentDigest: sweep.contentDigest,
    lastRequestCursor: sweep.lastRequestCursor,
    nextCursor: null,
    hasNextPage: false,
    sourceOrder: 'UPDATED_AT_DESC',
  };
}

async function fetchIssueCatalogSweep(
  options: IssuePaginationOptions = {},
  frozenBoundary: GhIssueSnapshotBoundary | null = null,
): Promise<GhIssueCatalogBoundaryVerification> {
  const request = options.request ?? gh;
  const pageSize = Math.min(
    GRAPHQL_PAGE_SIZE,
    Math.max(1, options.perPage ?? config.refresh.issuePageSize),
  );
  const pageDelayMs = options.pageDelayMs ?? config.refresh.githubPageDelayMs;
  const sleeper = options.sleep ?? sleep;
  const maxPages = options.maxPagesPerConnection ?? GRAPHQL_MAX_PAGES_PER_CONNECTION;
  if (!Number.isInteger(maxPages) || maxPages <= 0) {
    throw new Error('GitHub GraphQL repository.issues max pages must be a positive integer');
  }

  let after: string | null = null;
  let boundaryTotalCount = frozenBoundary?.totalCount ?? null;
  let observedTotalCount = boundaryTotalCount ?? 0;
  let pageCount = 0;
  let lastRequestCursor: string | null = null;
  const seenCursors = new Set<string>();
  const issues: GhIssueCatalogIssue[] = [];
  const records: CanonicalIssueRecord[] = [];
  const nodeIds = new Set<string>();
  const issueNumbers = new Set<number>();

  for (;;) {
    if (after && pageDelayMs > 0) {
      await sleepWithSignal(sleeper, pageDelayMs, options.signal);
    }
    const requestCursor: string | null = after;
    lastRequestCursor = requestCursor;
    const remaining = boundaryTotalCount == null
      ? pageSize
      : Math.max(0, boundaryTotalCount - records.length);
    const first = Math.max(1, Math.min(pageSize, remaining || 1));
    const data = await request<IssuesQueryData>(
      buildIssuesQuery('CREATED_AT_ASC'),
      repoVars({ first, after }),
      options.signal,
    );
    const connection = requireCountedGraphqlConnection(
      assertRepo(data.repository).issues,
      'repository.issues',
    );
    if (boundaryTotalCount == null) boundaryTotalCount = connection.totalCount;
    if (connection.totalCount < boundaryTotalCount) {
      throw new Error(
        `GitHub GraphQL repository.issues totalCount decreased below frozen snapshot boundary ` +
        `from ${boundaryTotalCount} to ${connection.totalCount}`,
      );
    }
    observedTotalCount = Math.max(observedTotalCount, connection.totalCount);
    pageCount++;

    const pageNodes = connection.nodes.map((node, index) =>
      requireIssueNode(node, `repository.issues page ${pageCount} node ${index}`));
    const rowsRemaining = boundaryTotalCount - records.length;
    if (pageNodes.length > rowsRemaining) {
      throw new Error(
        `GitHub GraphQL repository.issues returned ${pageNodes.length} nodes with only ` +
        `${rowsRemaining} frozen snapshot row(s) remaining`,
      );
    }
    for (const node of pageNodes) {
      if (nodeIds.has(node.id)) {
        throw new Error(`GitHub GraphQL repository.issues returned duplicate node id ${node.id}`);
      }
      if (issueNumbers.has(node.number)) {
        throw new Error(`GitHub GraphQL repository.issues returned duplicate issue number ${node.number}`);
      }
      nodeIds.add(node.id);
      issueNumbers.add(node.number);
    }

    const nextCursor = nextGraphqlPageCursor(connection.pageInfo, 'repository.issues');
    if (
      nextCursor &&
      (nextCursor === requestCursor || seenCursors.has(nextCursor))
    ) {
      throw new Error(`GitHub GraphQL repository.issues repeated pagination cursor ${nextCursor}`);
    }
    if (nextCursor) seenCursors.add(nextCursor);

    if (rowsRemaining > 0) {
      const completeLabels = await stableIssueLabelsForNodes(pageNodes, options);
      const pageIssues = pageNodes.map((node) => ({
        ...mapIssue(node, completeLabels.get(node.number)),
        node_id: node.id,
      }));
      for (let index = 0; index < pageIssues.length; index++) {
        issues.push(pageIssues[index]);
        records.push({ nodeId: pageNodes[index].id, issue: pageIssues[index] });
      }
    }

    if (records.length === boundaryTotalCount) {
      if (connection.totalCount > boundaryTotalCount && nextCursor == null) {
        throw new Error(
          `GitHub GraphQL repository.issues omitted a cursor after the frozen snapshot boundary ` +
          `while totalCount was ${connection.totalCount}`,
        );
      }
      if (connection.totalCount === boundaryTotalCount && nextCursor != null) {
        throw new Error(
          `GitHub GraphQL repository.issues returned a cursor beyond frozen snapshot boundary ` +
          `${boundaryTotalCount} without post-boundary growth`,
        );
      }
      const membershipDigest = canonicalIssueMembershipDigest(boundaryTotalCount, records);
      const terminalRecord = records.at(-1);
      const terminalIssue = terminalRecord
        ? {
            nodeId: terminalRecord.nodeId,
            issueNumber: terminalRecord.issue.number,
            createdAt: terminalRecord.issue.created_at,
          }
        : null;
      const boundary = {
        totalCount: boundaryTotalCount,
        terminalIssue,
        membershipDigest,
      };
      if (
        frozenBoundary &&
        JSON.stringify(terminalIssue) !== JSON.stringify(frozenBoundary.terminalIssue)
      ) {
        throw new Error(
          `GitHub GraphQL repository.issues terminal immutable identity changed across ` +
          `frozen-boundary sweeps`,
        );
      }
      if (
        frozenBoundary &&
        membershipDigest !== frozenBoundary.membershipDigest
      ) {
        throw new Error(
          `GitHub GraphQL repository.issues immutable membership changed across ` +
          `frozen-boundary sweeps`,
        );
      }
      return {
        issues,
        boundary,
        observedTotalCount,
        pageCount,
        membershipDigest,
        contentDigest: canonicalIssueContentDigest(boundaryTotalCount, records),
        lastRequestCursor,
      };
    }

    if (!nextCursor) {
      throw new Error(
        `GitHub GraphQL repository.issues terminal unique count ${issueNumbers.size} ` +
        `did not match frozen snapshot boundary ${boundaryTotalCount}`,
      );
    }
    if (pageCount >= maxPages) {
      throw new Error(
        `GitHub GraphQL repository.issues exceeded ${maxPages} pages before frozen ` +
        `snapshot boundary was collected`,
      );
    }
    after = nextCursor;
  }
}

export async function verifyIssueCatalogBoundary(
  frozenBoundary: GhIssueSnapshotBoundary,
  options: IssuePaginationOptions = {},
): Promise<GhIssueCatalogBoundaryVerification> {
  return fetchIssueCatalogSweep(options, frozenBoundary);
}

export async function fetchIssueCatalog(
  options: IssuePaginationOptions = {},
): Promise<GhIssueCatalog> {
  let pagesFetched = 0;
  let frozenBoundary = options.frozenBoundary ?? null;
  let observedTotalCount = frozenBoundary?.totalCount ?? 0;
  let previousMembershipDigest: string | null = null;
  let previousContentDigest: string | null = null;

  for (let sweepCount = 1; sweepCount <= ISSUE_CATALOG_MAX_SWEEPS; sweepCount++) {
    const current = await fetchIssueCatalogSweep(options, frozenBoundary);
    frozenBoundary ??= current.boundary;
    observedTotalCount = Math.max(observedTotalCount, current.observedTotalCount);
    pagesFetched += current.pageCount;

    if (
      previousMembershipDigest === current.membershipDigest &&
      previousContentDigest === current.contentDigest
    ) {
      return {
        issues: current.issues,
        metadata: {
          exhausted: true,
          stabilized: true,
          totalCount: current.boundary.totalCount,
          observedTotalCount,
          postBoundaryGrowthCount:
            observedTotalCount - current.boundary.totalCount,
          nodeCount: current.issues.length,
          uniqueCount: current.issues.length,
          pageCount: current.pageCount,
          pagesFetched,
          sweepCount,
          digest: current.membershipDigest,
          membershipDigest: current.membershipDigest,
          contentDigest: current.contentDigest,
          snapshotBoundary: current.boundary,
          lastRequestCursor: current.lastRequestCursor,
          nextCursor: null,
          hasNextPage: false,
          sourceOrder: 'CREATED_AT_ASC',
        },
      };
    }
    previousMembershipDigest = current.membershipDigest;
    previousContentDigest = current.contentDigest;
  }

  throw new Error(
    `GitHub GraphQL repository.issues failed to stabilize frozen first-N ` +
    `membership and content after ${ISSUE_CATALOG_MAX_SWEEPS} complete sweeps`,
  );
}

export async function listIssuesBatch(
  issueNumbers: number[],
  options: IssueBatchOptions = {},
): Promise<Map<number, GhIssue>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n) && n > 0);
  const all = new Map<number, GhIssue>();
  const request = options.request ?? gh;
  const batches = await mapIssueBatches(
    uniqueIssueNumbers,
    25,
    options,
    (chunk, workerOptions) => listIssuesChunk(chunk, request, workerOptions),
  );
  for (const batch of batches) {
    for (const [issueNumber, issue] of batch) all.set(issueNumber, issue);
  }
  return all;
}

async function listIssuesChunk(
  chunk: number[],
  request: GraphqlRequest,
  options: IssueBatchOptions,
): Promise<Map<number, GhIssue>> {
  const issues = new Map<number, GhIssue>();
  const data = await request<{ repository: Record<string, IssueNode | null> | null }>(
    buildIssuesBatchQuery(chunk.length),
    repoVars(Object.fromEntries(chunk.map((issueNumber, idx) => [`number${idx}`, issueNumber]))),
    options.signal,
  );
  const repo = assertRepo(data.repository);
  const nodes: IssueNode[] = [];
  const returnedNumbers = new Map<number, number>();
  for (let idx = 0; idx < chunk.length; idx++) {
    const alias = `issue${idx}`;
    const requestedIssueNumber = chunk[idx];
    if (!Object.prototype.hasOwnProperty.call(repo, alias)) {
      throw new Error(
        `GitHub GraphQL IssuesByNumber response omitted alias ${alias} ` +
          `for requested issue #${requestedIssueNumber}`,
      );
    }
    const node = repo[alias];
    if (node == null) {
      throw new Error(
        `GitHub GraphQL IssuesByNumber response returned null alias ${alias} ` +
          `for requested issue #${requestedIssueNumber}`,
      );
    }
    requireIssueNode(node, `IssuesByNumber alias ${alias}`);
    const existingAliasIndex = returnedNumbers.get(node.number);
    if (existingAliasIndex != null) {
      throw new Error(
        `GitHub GraphQL IssuesByNumber aliases issue${existingAliasIndex} and ${alias} ` +
          `returned duplicate issue number #${node.number}`,
      );
    }
    returnedNumbers.set(node.number, idx);
    nodes.push(node);
  }

  for (let idx = 0; idx < chunk.length; idx++) {
    const requestedIssueNumber = chunk[idx];
    const node = nodes[idx];
    if (node.number !== requestedIssueNumber) {
      throw new Error(
        `GitHub GraphQL IssuesByNumber alias issue${idx} returned issue #${node.number} ` +
          `for requested issue #${requestedIssueNumber}`,
      );
    }
    const labelConnection = requireCountedGraphqlConnection(node.labels, `issue #${node.number} labels`);
    const completeLabels = await stableIssueLabelNodes(
      {
        issueNumber: requestedIssueNumber,
        issueNodeId: node.id,
        issueNodeType: node.__typename,
        issueUpdatedAt: node.updatedAt,
      },
      labelConnection,
      options,
    );
    issues.set(requestedIssueNumber, mapIssue(node, completeLabels));
  }
  return issues;
}

function buildIssuesBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      id
      number
      title
      body
      state
      __typename
      author { __typename login ... on Node { id } }
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
        totalCount
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

async function stableIssueLabelsForNodes(
  nodes: IssueNode[],
  options: Pick<IssueBatchOptions, 'maxPagesPerConnection' | 'request' | 'signal'> = {},
): Promise<Map<number, Array<{ name: string }>>> {
  throwIfAborted(options.signal);
  const out = new Map<number, Array<{ name: string }>>();
  const controller = new AbortController();
  const removeCallerAbortListener = forwardAbortSignal(options.signal, controller);
  const childOptions = { ...options, signal: controller.signal };
  let hasPrimaryFailure = false;
  let primaryFailure: unknown;
  const fail = (error: unknown) => {
    if (!hasPrimaryFailure) {
      hasPrimaryFailure = true;
      primaryFailure = error;
    }
    if (!controller.signal.aborted) controller.abort(primaryFailure);
  };
  if (controller.signal.aborted) {
    fail(abortSignalReason(controller.signal));
  } else {
    controller.signal.addEventListener('abort', () => {
      if (!hasPrimaryFailure) fail(abortSignalReason(controller.signal));
    }, { once: true });
  }
  try {
    await Promise.all(nodes.map(async (node) => {
      try {
        const connection = requireCountedGraphqlConnection(
          node.labels,
          `issue #${node.number} labels`,
        );
        const labels = await stableIssueLabelNodes(
          {
            issueNumber: node.number,
            issueNodeId: node.id,
            issueNodeType: node.__typename,
            issueUpdatedAt: node.updatedAt,
          },
          connection,
          childOptions,
        );
        out.set(node.number, labels);
      } catch (error) {
        fail(error);
      }
    }));
  } finally {
    removeCallerAbortListener();
  }
  if (hasPrimaryFailure) throw primaryFailure;
  return out;
}

interface IssueLabelSweep {
  issueUpdatedAt: string;
  totalCount: number;
  labels: Array<{ name: string }>;
  identityDigest: string;
  contentDigest: string;
}

interface IssueLabelAuthority {
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: string;
  issueUpdatedAt: string;
}

function issueLabelSweepDigest(
  totalCount: number,
  labelNames: string[],
  preserveOrder: boolean,
): string {
  const canonical = preserveOrder
    ? labelNames
    : labelNames.slice().sort(compareBinary);
  return createHash('sha256')
    .update(JSON.stringify([totalCount, canonical]))
    .digest('hex');
}

async function collectIssueLabelSweep(
  authority: IssueLabelAuthority,
  initialConnection: { nodes: Array<{ name: string }>; pageInfo: PageInfo; totalCount: number },
  options: Pick<IssueBatchOptions, 'maxPagesPerConnection' | 'request' | 'signal'> = {},
): Promise<IssueLabelSweep> {
  const {
    issueNumber,
    issueNodeId,
    issueNodeType,
    issueUpdatedAt,
  } = authority;
  requireCanonicalGraphqlIdentity(issueNodeId, `issue #${issueNumber} labels issue node ID`);
  if (issueNodeType !== 'Issue') {
    throw new Error(
      `GitHub GraphQL issue #${issueNumber} labels returned unexpected ` +
        `issue node type ${String(issueNodeType)}`,
    );
  }
  if (
    typeof issueUpdatedAt !== 'string' ||
    !Number.isFinite(Date.parse(issueUpdatedAt))
  ) {
    throw new Error(`GitHub GraphQL issue #${issueNumber} labels snapshot has invalid updatedAt`);
  }
  const labels: Array<{ name: string }> = [];
  const labelNames: string[] = [];
  const context = `issue #${issueNumber} labels`;
  const pagination = createGraphqlPaginationGuard(context, options.maxPagesPerConnection);
  const request = options.request ?? gh;
  const seen = new Set<string>();
  appendIssueLabelNames(issueNumber, initialConnection.nodes, labelNames, seen);
  labels.push(...initialConnection.nodes);
  const expectedTotalCount = initialConnection.totalCount;
  let after = pagination.next(initialConnection.pageInfo, null);
  while (after) {
    const requestCursor = after;
    const data = await request<{
      repository: { issue: IssueLabelsQueryIssue | null } | null;
    }>(
      buildIssueLabelsQuery(),
      repoVars({ number: issueNumber, after }),
      options.signal,
    );
    const issue = assertRepo(data.repository).issue;
    if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while paginating labels`);
    const pageIdentity = requireRequestedIssueGraphqlIdentity(
      issue,
      issueNumber,
      context,
    );
    if (
      pageIdentity.issueNodeId !== issueNodeId ||
      pageIdentity.issueNodeType !== issueNodeType
    ) {
      throw new Error(
        `GitHub GraphQL ${context} issue identity drifted during pagination ` +
          `from ${issueNodeId} to ${pageIdentity.issueNodeId}`,
      );
    }
    if (issue.updatedAt !== issueUpdatedAt) {
      throw new Error(
        `GitHub GraphQL ${context} updatedAt drifted during pagination ` +
          `from ${issueUpdatedAt} to ${String(issue.updatedAt)}`,
      );
    }
    const connection = requireCountedGraphqlConnection(issue.labels, context);
    if (connection.totalCount !== expectedTotalCount) {
      throw new Error(
        `GitHub GraphQL ${context} totalCount changed within sweep ` +
        `from ${expectedTotalCount} to ${connection.totalCount}`,
      );
    }
    const pageLabelNames: string[] = [];
    appendIssueLabelNames(issueNumber, connection.nodes, pageLabelNames, seen);
    labelNames.push(...pageLabelNames);
    labels.push(...pageLabelNames.map((name) => ({ name })));
    after = pagination.next(connection.pageInfo, requestCursor);
  }
  if (seen.size !== expectedTotalCount) {
    throw new Error(
      `GitHub GraphQL ${context} terminal unique count ${seen.size} ` +
      `did not match totalCount ${expectedTotalCount}`,
    );
  }
  return {
    issueUpdatedAt,
    totalCount: expectedTotalCount,
    labels,
    identityDigest: issueLabelSweepDigest(expectedTotalCount, labelNames, false),
    contentDigest: issueLabelSweepDigest(expectedTotalCount, labelNames, true),
  };
}

async function fetchIssueLabelSweep(
  authority: IssueLabelAuthority,
  options: Pick<IssueBatchOptions, 'maxPagesPerConnection' | 'request' | 'signal'> = {},
): Promise<IssueLabelSweep> {
  const {
    issueNumber,
    issueNodeId,
    issueNodeType,
    issueUpdatedAt: expectedIssueUpdatedAt,
  } = authority;
  const request = options.request ?? gh;
  const data = await request<{
    repository: { issue: IssueLabelsQueryIssue | null } | null;
  }>(
    buildIssueLabelsQuery(),
    repoVars({ number: issueNumber, after: null }),
    options.signal,
  );
  const issue = assertRepo(data.repository).issue;
  if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while sweeping labels`);
  const sweepIdentity = requireRequestedIssueGraphqlIdentity(
    issue,
    issueNumber,
    `issue #${issueNumber} labels`,
  );
  if (
    sweepIdentity.issueNodeId !== issueNodeId ||
    sweepIdentity.issueNodeType !== issueNodeType
  ) {
    throw new Error(
      `GitHub GraphQL issue #${issueNumber} labels issue identity changed ` +
        `between complete sweeps from ${issueNodeId} to ${sweepIdentity.issueNodeId}`,
    );
  }
  if (issue.updatedAt !== expectedIssueUpdatedAt) {
    throw new Error(
      `GitHub GraphQL issue #${issueNumber} labels updatedAt drifted between complete sweeps ` +
        `from ${expectedIssueUpdatedAt} to ${String(issue.updatedAt)}`,
    );
  }
  const connection = requireCountedGraphqlConnection(
    issue.labels,
    `issue #${issueNumber} labels`,
  );
  return collectIssueLabelSweep(authority, connection, options);
}

async function stableIssueLabelNodes(
  authority: IssueLabelAuthority,
  initialConnection: { nodes: Array<{ name: string }>; pageInfo: PageInfo; totalCount: number },
  options: Pick<IssueBatchOptions, 'maxPagesPerConnection' | 'request' | 'signal'> = {},
): Promise<Array<{ name: string }>> {
  const { issueNumber } = authority;
  const initial = await collectIssueLabelSweep(
    authority,
    initialConnection,
    options,
  );
  if (!initialConnection.pageInfo.hasNextPage) return initial.labels;

  let previous = initial;
  for (let sweepCount = 2; sweepCount <= ISSUE_LABEL_MAX_SWEEPS; sweepCount++) {
    const current = await fetchIssueLabelSweep(authority, options);
    if (
      previous.issueUpdatedAt === current.issueUpdatedAt &&
      previous.totalCount === current.totalCount &&
      previous.identityDigest === current.identityDigest &&
      previous.contentDigest === current.contentDigest
    ) {
      return current.labels;
    }
    previous = current;
  }
  throw new Error(
    `GitHub GraphQL issue #${issueNumber} labels failed to stabilize identity and content ` +
      `after ${ISSUE_LABEL_MAX_SWEEPS} complete sweeps`,
  );
}

function buildIssueLabelsQuery(): string {
  return `query IssueLabels($owner: String!, $repo: String!, $number: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      issue(number: $number) {
        id
        __typename
        number
        updatedAt
        labels(first: 100, after: $after) {
          totalCount
          nodes { name }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }`;
}

export async function listIssueComments(
  issueNumber: number,
  options: IssueBatchOptions = {},
): Promise<GhComment[]> {
  const comments = await listIssueCommentsBatch([issueNumber], options);
  return comments.get(issueNumber) ?? [];
}

export async function listIssueCommentsBatch(
  issueNumbers: number[],
  options: IssueBatchOptions = {},
): Promise<Map<number, GhComment[]>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n));
  const all = new Map<number, GhComment[]>();
  for (const issueNumber of uniqueIssueNumbers) all.set(issueNumber, []);

  const snapshots = await listIssueCommentSnapshotsBatch(uniqueIssueNumbers, options);
  for (const [issueNumber, snapshot] of snapshots) {
    all.set(issueNumber, snapshot.comments);
  }
  return all;
}

interface IssueCommentSweepSnapshot extends Omit<GhIssueCommentSnapshot, 'stabilization'> {
  token: string;
  commentIds: Set<number>;
  sweepIdentity: CommentEvidenceSweepIdentity;
}

interface IssueCommentSweepState {
  token: string;
  repositoryNodeId: string;
  issueNodeId: string;
  issueNodeType: 'Issue';
  issueAuthor: { nodeId: string; actorType: string; login: string } | null;
  issueUpdatedAt: string;
  totalCount: number;
  comments: GhComment[];
  commentIds: Set<number>;
}

class CommentSnapshotInstabilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CommentSnapshotInstabilityError';
  }
}

class IssueFixEvidenceInstabilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IssueFixEvidenceInstabilityError';
  }
}

type FrozenIssueFixEvidenceConnectionBoundary = Pick<
  GhIssueFixEvidenceConnectionSnapshot,
  'totalCount' | 'terminalFirstNIdentity' | 'identityDigest'
>;

class FrozenAppendOnlyConnectionCollector<T> {
  private boundaryTotalCount: number | null;
  private observedTotalCount: number;
  private readonly identities: string[] = [];
  private readonly contents: unknown[] = [];
  private readonly seenIdentities = new Set<string>();
  private readonly seenCursors = new Set<string>();
  private pageCount = 0;

  constructor(
    private readonly context: string,
    private readonly identityForNode: (node: T) => string,
    private readonly contentForNode: (node: T) => unknown,
    private readonly frozenBoundary: FrozenIssueFixEvidenceConnectionBoundary | null,
    private readonly maxPages = GRAPHQL_MAX_PAGES_PER_CONNECTION,
  ) {
    if (!Number.isInteger(maxPages) || maxPages <= 0) {
      throw new Error(`GitHub GraphQL ${context} max pages must be a positive integer`);
    }
    this.boundaryTotalCount = frozenBoundary?.totalCount ?? null;
    this.observedTotalCount = frozenBoundary?.totalCount ?? 0;
  }

  requestedPageSize(): number {
    if (this.boundaryTotalCount == null) return GRAPHQL_PAGE_SIZE;
    return Math.max(1, Math.min(
      GRAPHQL_PAGE_SIZE,
      this.boundaryTotalCount - this.identities.length,
    ));
  }

  appendPage(
    connection: { nodes: T[]; pageInfo: PageInfo; totalCount: number },
    requestCursor: string | null,
    appendNodes: (nodes: T[]) => void,
  ): string | null {
    this.pageCount++;
    if (this.boundaryTotalCount == null) this.boundaryTotalCount = connection.totalCount;
    if (connection.totalCount < this.boundaryTotalCount) {
      throw new Error(
        `GitHub GraphQL ${this.context} totalCount decreased below frozen boundary ` +
        `from ${this.boundaryTotalCount} to ${connection.totalCount}`,
      );
    }
    if (connection.totalCount > this.boundaryTotalCount) {
      throw new IssueFixEvidenceInstabilityError(
        `GitHub GraphQL ${this.context} totalCount grew beyond frozen boundary ` +
        `from ${this.boundaryTotalCount} to ${connection.totalCount}; restart from cursor null`,
      );
    }
    this.observedTotalCount = connection.totalCount;

    const remaining = this.boundaryTotalCount - this.identities.length;
    if (remaining < 0) {
      throw new Error(`GitHub GraphQL ${this.context} collected beyond its frozen boundary`);
    }
    if (remaining > 0 && connection.nodes.length > remaining) {
      throw new Error(
        `GitHub GraphQL ${this.context} returned ${connection.nodes.length} nodes with only ` +
        `${remaining} frozen row(s) remaining`,
      );
    }
    const selectedNodes = connection.nodes.slice(0, remaining);
    for (const node of selectedNodes) {
      const identity = this.identityForNode(node);
      if (typeof identity !== 'string' || !identity || identity.trim() !== identity) {
        throw new Error(`GitHub GraphQL ${this.context} returned a missing first-N identity`);
      }
      if (this.seenIdentities.has(identity)) {
        throw new Error(`GitHub GraphQL ${this.context} returned duplicate identity ${identity}`);
      }
      this.seenIdentities.add(identity);
      this.identities.push(identity);
      this.contents.push(canonicalGraphqlValue(this.contentForNode(node)));
    }
    appendNodes(selectedNodes);

    const nextCursor = nextGraphqlPageCursor(connection.pageInfo, this.context);
    if (
      nextCursor &&
      (nextCursor === requestCursor || this.seenCursors.has(nextCursor))
    ) {
      throw new Error(`GitHub GraphQL ${this.context} repeated pagination cursor ${nextCursor}`);
    }
    if (nextCursor) this.seenCursors.add(nextCursor);

    if (this.identities.length === this.boundaryTotalCount) {
      const snapshot = this.snapshot();
      if (
        this.frozenBoundary &&
        snapshot.terminalFirstNIdentity !== this.frozenBoundary.terminalFirstNIdentity
      ) {
        throw new IssueFixEvidenceInstabilityError(
          `GitHub GraphQL ${this.context} terminal first-N identity changed across frozen sweeps`,
        );
      }
      if (
        this.frozenBoundary &&
        snapshot.identityDigest !== this.frozenBoundary.identityDigest
      ) {
        throw new IssueFixEvidenceInstabilityError(
          `GitHub GraphQL ${this.context} immutable first-N identity changed across frozen sweeps`,
        );
      }
      if (nextCursor != null) {
        throw new Error(
          `GitHub GraphQL ${this.context} returned a cursor beyond frozen boundary ` +
          `${this.boundaryTotalCount}`,
        );
      }
      return null;
    }

    if (!nextCursor) {
      throw new Error(
        `GitHub GraphQL ${this.context} terminal unique count ${this.identities.length} ` +
        `did not match totalCount ${this.boundaryTotalCount}`,
      );
    }
    if (this.pageCount >= this.maxPages) {
      throw new Error(
        `GitHub GraphQL ${this.context} exceeded ${this.maxPages} pages before pagination completed`,
      );
    }
    return nextCursor;
  }

  snapshot(): GhIssueFixEvidenceConnectionSnapshot {
    if (this.boundaryTotalCount == null || this.identities.length !== this.boundaryTotalCount) {
      throw new Error(`GitHub GraphQL ${this.context} snapshot requested before boundary completion`);
    }
    if (this.observedTotalCount !== this.boundaryTotalCount) {
      throw new IssueFixEvidenceInstabilityError(
        `GitHub GraphQL ${this.context} cannot publish an incomplete stable observation: ` +
        `fetched ${this.identities.length}, totalCount ${this.boundaryTotalCount}, ` +
        `observedTotalCount ${this.observedTotalCount}`,
      );
    }
    return {
      totalCount: this.boundaryTotalCount,
      observedTotalCount: this.observedTotalCount,
      postBoundaryGrowthCount: 0,
      fetchedCount: this.identities.length,
      terminalFirstNIdentity: this.identities.at(-1) ?? null,
      identityDigest: createHash('sha256')
        .update(JSON.stringify([this.boundaryTotalCount, this.identities]))
        .digest('hex'),
      contentDigest: createHash('sha256')
        .update(JSON.stringify([this.boundaryTotalCount, this.contents]))
        .digest('hex'),
      sourceOrder: 'CONNECTION_ASC',
    };
  }
}

export async function listIssueCommentSnapshotsBatch(
  issueNumbers: number[],
  options: IssueBatchOptions = {},
): Promise<Map<number, GhIssueCommentSnapshot>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n));
  const all = new Map<number, GhIssueCommentSnapshot>();
  const request = options.request ?? gh;
  const sleeper = options.sleep ?? sleep;

  const batches = await mapIssueBatches(
    uniqueIssueNumbers,
    COMMENT_BATCH_SIZE,
    options,
    (chunk, workerOptions) =>
      listIssueCommentSnapshotsChunk(chunk, request, sleeper, workerOptions),
  );
  for (const batch of batches) {
    for (const [issueNumber, snapshot] of batch) all.set(issueNumber, snapshot);
  }

  return all;
}

async function listIssueCommentSnapshotsChunk(
  chunk: number[],
  request: GraphqlRequest,
  sleeper: GithubSleep,
  options: IssueBatchOptions,
): Promise<Map<number, GhIssueCommentSnapshot>> {
  const missingIssueNumbers = new Set<number>();
  const maxAttempts = options.snapshotMaxAttempts ?? COMMENT_SNAPSHOT_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts <= 0) {
    throw new Error(`GitHub comment snapshot max attempts must be positive, got ${String(maxAttempts)}`);
  }

  let completeSweepCount = 0;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const firstSweep = await fetchIssueCommentSweep(
        chunk,
        missingIssueNumbers,
        request,
        options,
        ++completeSweepCount,
      );
      const secondSweep = await fetchIssueCommentSweep(
        chunk,
        missingIssueNumbers,
        request,
        options,
        ++completeSweepCount,
      );
      return requireMatchingCommentSweeps(
        chunk.filter((issueNumber) => !missingIssueNumbers.has(issueNumber)),
        firstSweep,
        secondSweep,
        completeSweepCount,
      );
    } catch (error) {
      if (!(error instanceof CommentSnapshotInstabilityError)) throw error;
      if (attempt === maxAttempts) {
        throw new Error(
          `GitHub issue comment snapshot chunk failed to stabilize after ${maxAttempts} attempts: ${error.message}`,
        );
      }
      await sleepWithSignal(
        sleeper,
        commentSnapshotRetryDelayMs(attempt, options),
        options.signal,
      );
    }
  }

  throw new Error('GitHub issue comment snapshot chunk failed closed without a stable result');
}

async function fetchIssueCommentSweep(
  chunk: number[],
  missingIssueNumbers: Set<number>,
  request: GraphqlRequest,
  options: IssueBatchOptions,
  sweepOrdinal: number,
): Promise<Map<number, IssueCommentSweepSnapshot>> {
  const sweepIssueNumbers = chunk.filter((issueNumber) => !missingIssueNumbers.has(issueNumber));
  const states = new Map<number, IssueCommentSweepState>();
  const cursors = new Map<number, string | null>(
    sweepIssueNumbers.map((issueNumber) => [issueNumber, null]),
  );
  const guards = new Map(sweepIssueNumbers.map((issueNumber) => [
    issueNumber,
    createGraphqlPaginationGuard(
      `issue #${issueNumber} comments`,
      options.maxPagesPerConnection,
    ),
  ]));
  const done = new Set<number>();

  while (done.size < sweepIssueNumbers.length) {
    const active = sweepIssueNumbers.filter((issueNumber) => !done.has(issueNumber));
    let data: IssueCommentsQueryData;
    try {
      data = await request<IssueCommentsQueryData>(
        buildIssueCommentsBatchQuery(active.length),
        repoVars({
          first: COMMENT_PAGE_SIZE,
          ...Object.fromEntries(active.flatMap((issueNumber, idx) => [
            [`number${idx}`, issueNumber],
            [`after${idx}`, cursors.get(issueNumber) ?? null],
          ])),
        }),
        options.signal,
      );
    } catch (error) {
      const missingReporter = options.onMissingIssueAlias
        ? (event: { issueNumber: number; aliasIndex: number }) => {
            const firstReport = !missingIssueNumbers.has(event.issueNumber);
            missingIssueNumbers.add(event.issueNumber);
            states.delete(event.issueNumber);
            if (firstReport) options.onMissingIssueAlias?.(event);
          }
        : undefined;
      const skipped = skipMissingIssueAliases(error, active, done, missingReporter);
      if (skipped === 0) throw error;
      continue;
    }

    const repo = assertRepo(data.repository);
    const repositoryNodeId = requireCanonicalGraphqlIdentity(
      repo.id,
      'issue comment snapshot repository node ID',
    );
    const issueNodeNumbers = new Map<string, number>();
    for (let idx = 0; idx < active.length; idx++) {
      const issueNumber = active[idx];
      if (missingIssueNumbers.has(issueNumber)) continue;
      const issue = repo[`issue${idx}`];
      if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while fetching comments`);
      const context = `issue #${issueNumber} comments`;
      const { issueNodeId, issueNodeType } = requireRequestedIssueGraphqlIdentity(
        issue,
        issueNumber,
        context,
      );
      const existingIssueNumber = issueNodeNumbers.get(issueNodeId);
      if (existingIssueNumber != null && existingIssueNumber !== issueNumber) {
        throw new Error(
          `GitHub GraphQL comment aliases for issues #${existingIssueNumber} ` +
            `and #${issueNumber} returned duplicate issue node ID ${issueNodeId}`,
        );
      }
      issueNodeNumbers.set(issueNodeId, issueNumber);
      const connection = requireGraphqlConnection<CommentNode>(issue.comments, context);
      const token = issueCommentSnapshotToken(issue, context);
      const issueAuthor = issue.author == null
        ? null
        : {
            nodeId: requireCanonicalGraphqlIdentity(
              issue.author.id,
              `${context} issue author node ID`,
            ),
            actorType: requireCanonicalGraphqlIdentity(
              issue.author.__typename,
              `${context} issue author node type`,
            ),
            login: requireCanonicalGraphqlIdentity(
              issue.author.login,
              `${context} issue author login`,
            ),
          };
      const state = states.get(issueNumber) ?? {
        token,
        repositoryNodeId,
        issueNodeId,
        issueNodeType: 'Issue' as const,
        issueAuthor,
        issueUpdatedAt: issue.updatedAt,
        totalCount: issue.comments.totalCount,
        comments: [],
        commentIds: new Set<number>(),
      };
      if (state.token !== token) {
        throw new CommentSnapshotInstabilityError(
          `${context} token changed between pages (${state.token} != ${token})`,
        );
      }
      if (
        state.repositoryNodeId !== repositoryNodeId ||
        state.issueNodeId !== issueNodeId ||
        state.issueNodeType !== issueNodeType ||
        JSON.stringify(state.issueAuthor) !== JSON.stringify(issueAuthor)
      ) {
        throw new CommentSnapshotInstabilityError(
          `${context} immutable issue identity changed during pagination`,
        );
      }

      for (const node of connection.nodes) {
        const databaseId = node.databaseId;
        if (databaseId == null || !Number.isInteger(databaseId) || databaseId <= 0) {
          throw new Error(`${context} returned invalid databaseId ${String(databaseId)}`);
        }
        if (state.commentIds.has(databaseId)) {
          throw new CommentSnapshotInstabilityError(
            `${context} returned duplicate databaseId ${databaseId}`,
          );
        }
        state.commentIds.add(databaseId);
        state.comments.push(mapComment(node));
      }
      states.set(issueNumber, state);

      const currentCursor = cursors.get(issueNumber) ?? null;
      let nextCursor: string | null;
      try {
        nextCursor = guards.get(issueNumber)?.next(connection.pageInfo, currentCursor) ?? null;
      } catch (error) {
        throw new CommentSnapshotInstabilityError(
          `${context} page instability: ${(error as Error).message}`,
        );
      }
      if (nextCursor) {
        cursors.set(issueNumber, nextCursor);
      } else {
        if (state.commentIds.size !== state.totalCount) {
          throw new CommentSnapshotInstabilityError(
            `${context} terminal unique count ${state.commentIds.size} did not match totalCount ${state.totalCount}`,
          );
        }
        done.add(issueNumber);
      }
    }
  }

  return new Map([...states].map(([issueNumber, state]) => [
    issueNumber,
    (() => {
      const snapshotIdentity = {
        repositoryNodeId: state.repositoryNodeId,
        issueNodeId: state.issueNodeId,
        issueNodeType: state.issueNodeType,
        issueAuthor: state.issueAuthor,
      };
      const commentsDigest = commentEvidenceDigest(state.totalCount, state.comments);
      const authorityDigest = commentEvidenceDigest(
        state.totalCount,
        state.comments,
        snapshotIdentity,
      );
      const sweepIdentity = commentEvidenceSweepIdentity({
        sweepOrdinal,
        issueUpdatedAt: state.issueUpdatedAt,
        totalCount: state.totalCount,
        comments: state.comments,
        snapshotIdentity,
      });
      if (sweepIdentity.authorityDigest !== authorityDigest) {
        throw new Error(`issue #${issueNumber} comment sweep authority digest mismatch`);
      }
      return {
      repositoryNodeId: state.repositoryNodeId,
      issueNumber,
      issueNodeId: state.issueNodeId,
      issueNodeType: state.issueNodeType,
      issueAuthor: state.issueAuthor,
      issueUpdatedAt: state.issueUpdatedAt,
      totalCount: state.totalCount,
      comments: state.comments,
      commentsDigest,
      authorityDigest,
      token: state.token,
      commentIds: state.commentIds,
      sweepIdentity,
      };
    })(),
  ]));
}

function issueCommentSnapshotToken(
  issue: IssueCommentsQueryIssue,
  context: string,
): string {
  if (typeof issue.updatedAt !== 'string' || issue.updatedAt.length === 0) {
    throw new Error(`${context} missing issue updatedAt`);
  }
  if (!Number.isInteger(issue.comments.totalCount) || issue.comments.totalCount < 0) {
    throw new Error(`${context} returned invalid totalCount ${String(issue.comments.totalCount)}`);
  }
  return JSON.stringify([issue.updatedAt, issue.comments.totalCount]);
}

function requireMatchingCommentSweeps(
  issueNumbers: number[],
  firstSweep: Map<number, IssueCommentSweepSnapshot>,
  secondSweep: Map<number, IssueCommentSweepSnapshot>,
  sweepCount: number,
): Map<number, GhIssueCommentSnapshot> {
  const stable = new Map<number, GhIssueCommentSnapshot>();
  for (const issueNumber of issueNumbers) {
    const first = firstSweep.get(issueNumber);
    const second = secondSweep.get(issueNumber);
    if (!first || !second) {
      throw new CommentSnapshotInstabilityError(
        `issue #${issueNumber} comments missing from a complete snapshot sweep`,
      );
    }
    if (first.token !== second.token) {
      throw new CommentSnapshotInstabilityError(
        `issue #${issueNumber} comments token changed between sweeps (${first.token} != ${second.token})`,
      );
    }
    if (!sameNumberSet(first.commentIds, second.commentIds)) {
      throw new CommentSnapshotInstabilityError(
        `issue #${issueNumber} comment ID set changed between sweeps`,
      );
    }
    if (first.commentsDigest !== second.commentsDigest) {
      throw new CommentSnapshotInstabilityError(
        `issue #${issueNumber} comments digest changed between sweeps`,
      );
    }
    if (
      first.repositoryNodeId !== second.repositoryNodeId ||
      first.issueNodeId !== second.issueNodeId ||
      first.issueNodeType !== second.issueNodeType ||
      JSON.stringify(first.issueAuthor) !== JSON.stringify(second.issueAuthor) ||
      first.authorityDigest !== second.authorityDigest
    ) {
      throw new CommentSnapshotInstabilityError(
        `issue #${issueNumber} comment authority identity changed between sweeps`,
      );
    }
    const stabilization = commentEvidenceStabilizationIdentity(
      first.sweepIdentity,
      second.sweepIdentity,
      sweepCount,
    );
    stable.set(issueNumber, {
      repositoryNodeId: second.repositoryNodeId,
      issueNumber,
      issueNodeId: second.issueNodeId,
      issueNodeType: second.issueNodeType,
      issueAuthor: second.issueAuthor,
      issueUpdatedAt: second.issueUpdatedAt,
      totalCount: second.totalCount,
      comments: second.comments,
      commentsDigest: second.commentsDigest,
      authorityDigest: second.authorityDigest,
      stabilization,
    });
  }
  return stable;
}

function sameNumberSet(left: Set<number>, right: Set<number>): boolean {
  if (left.size !== right.size) return false;
  for (const value of left) {
    if (!right.has(value)) return false;
  }
  return true;
}

function commentSnapshotRetryDelayMs(
  attempt: number,
  options: Pick<IssueBatchOptions, 'snapshotRetryBaseMs' | 'snapshotRetryMaxMs'> = {},
): number {
  return Math.min(
    options.snapshotRetryMaxMs ?? COMMENT_SNAPSHOT_RETRY_MAX_MS,
    (options.snapshotRetryBaseMs ?? COMMENT_SNAPSHOT_RETRY_BASE_MS) * Math.pow(2, attempt - 1),
  );
}

function missingIssueIndexesFromGraphqlError(error: unknown): number[] {
  if (error instanceof GithubGraphqlResponseError) {
    if (error.errors.length === 0) return [];
    const indexes = new Set<number>();
    for (const graphqlError of error.errors) {
      if ((graphqlError.type ?? '').toUpperCase() !== 'NOT_FOUND') return [];
      if (
        !graphqlError.message.includes('Could not resolve to an Issue') ||
        !Array.isArray(graphqlError.path) ||
        graphqlError.path.length !== 2 ||
        graphqlError.path[0] !== 'repository' ||
        typeof graphqlError.path[1] !== 'string'
      ) {
        return [];
      }
      const match = /^issue(\d+)$/.exec(graphqlError.path[1]);
      if (!match) return [];
      const idx = Number(match[1]);
      if (!Number.isInteger(idx) || idx < 0) return [];
      indexes.add(idx);
    }
    return [...indexes].sort((a, b) => a - b);
  }

  const message = error instanceof Error ? error.message : String(error ?? '');
  const prefix = 'GitHub GraphQL error:';
  const details = message.startsWith(prefix)
    ? message.slice(prefix.length).trim()
    : message.trim();
  if (!details) return [];

  const indexes = new Set<number>();
  const segments = details.split(/;\s*/);
  for (const segment of segments) {
    const match = /^(?:NOT_FOUND\s+)?repository\.issue(\d+)\b\s*:?\s*Could not resolve to an Issue\b/.exec(
      segment,
    );
    if (!match) return [];
    const idx = Number(match[1]);
    if (!Number.isInteger(idx) || idx < 0) return [];
    indexes.add(idx);
  }
  return [...indexes].sort((a, b) => a - b);
}

function skipMissingIssueAliases(
  error: unknown,
  active: number[],
  done: Set<number>,
  onMissingIssueAlias?: MissingIssueAliasCallback,
): number {
  if (!onMissingIssueAlias) return 0;
  const missingIndexes = missingIssueIndexesFromGraphqlError(error);
  if (
    missingIndexes.length === 0 ||
    missingIndexes.some((idx) => idx >= active.length)
  ) {
    return 0;
  }
  let skipped = 0;
  for (const idx of missingIndexes) {
    const missingIssueNumber = active[idx];
    done.add(missingIssueNumber);
    onMissingIssueAlias({ issueNumber: missingIssueNumber, aliasIndex: idx });
    skipped++;
  }
  return skipped;
}

function buildIssueCommentsBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => `$number${idx}: Int!, $after${idx}: String`).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      id
      __typename
      number
      author { __typename login ... on Node { id } }
      updatedAt
      comments(first: $first, after: $after${idx}, orderBy: {field: UPDATED_AT, direction: ASC}) {
        totalCount
        nodes {
          id
          __typename
          databaseId
          url
          author { __typename login ... on Node { id } }
          authorAssociation
          body
          createdAt
          updatedAt
        }
        pageInfo { hasNextPage endCursor }
      }
    }`).join('\n');

  return `query IssueComments($owner: String!, $repo: String!, $first: Int!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      id
      ${fields}
    }
  }`;
}

export async function getReleaseCommit(
  tag: string,
  options: ReleaseCommitFetchOptions = {},
): Promise<GhReleaseCommit> {
  let previous: ReleaseCommitSweep | null = null;
  for (let sweepCount = 1; sweepCount <= RELEASE_CHECK_MAX_SWEEPS; sweepCount++) {
    const current = await fetchReleaseCommitSweep(tag, options);
    if (
      previous?.identityDigest === current.identityDigest &&
      previous.contentDigest === current.contentDigest
    ) {
      return current.commit;
    }
    previous = current;
  }
  throw new Error(
    `GitHub GraphQL release ${tag} status check contexts failed to stabilize after ` +
      `${RELEASE_CHECK_MAX_SWEEPS} complete sweeps`,
  );
}

interface ReleaseCommitSweep {
  commit: GhReleaseCommit;
  identityDigest: string;
  contentDigest: string;
}

interface ReleaseCheckContextRecord {
  nodeId: string;
  context: GhReleaseCheckContext;
}

async function fetchReleaseCommitSweep(
  tag: string,
  options: ReleaseCommitFetchOptions,
): Promise<ReleaseCommitSweep> {
  const request = options.request ?? gh;
  const contextRecords: ReleaseCheckContextRecord[] = [];
  const contextNodeIds = new Set<string>();
  let after: string | null = null;
  let release: ReleaseCommitRelease | null = null;
  let rollup: ReleaseCommitRollup | null = null;
  let tagOid: string | null = null;
  let committedAt: string | null = null;
  let committedAtInitialized = false;
  let rollupId: string | null = null;
  let rollupState: string | null = null;
  let contextTotalCount: number | null = null;
  const pagination = createGraphqlPaginationGuard(
    `release ${tag} status check contexts`,
    options.maxPagesPerConnection,
  );

  for (;;) {
    const requestCursor = after;
    const data: ReleaseCommitQueryData = await request<ReleaseCommitQueryData>(
      buildReleaseCommitQuery(),
      repoVars({ tag, after }),
      options.signal,
    );
    release = assertRepo(data.repository).release;
    if (!release) throw new Error(`GitHub GraphQL missing release ${tag}`);
    if (!release.tagCommit) throw new Error(`GitHub GraphQL missing tag commit for release ${tag}`);
    const currentTagOid = requireCanonicalGraphqlIdentity(
      release.tagCommit.oid,
      `release ${tag} tag commit OID`,
    );
    if (options.expectedTagOid != null && currentTagOid !== options.expectedTagOid) {
      throw new Error(
        `GitHub GraphQL release ${tag} tag OID does not match catalog attestation ` +
        `(${options.expectedTagOid} != ${currentTagOid})`,
      );
    }
    if (tagOid == null) {
      tagOid = currentTagOid;
    } else if (currentTagOid !== tagOid) {
      throw new Error(
        `GitHub GraphQL release ${tag} tag OID changed within pagination ` +
        `from ${tagOid} to ${currentTagOid}`,
      );
    }
    const currentCommittedAt = optionalCanonicalGraphqlString(
      release.tagCommit.committedDate,
      `release ${tag} committed date`,
    );
    if (!committedAtInitialized) {
      committedAt = currentCommittedAt;
      committedAtInitialized = true;
    } else if (currentCommittedAt !== committedAt) {
      throw new Error(
        `GitHub GraphQL release ${tag} committed date changed within pagination ` +
          `from ${committedAt} to ${currentCommittedAt ?? 'missing'}`,
      );
    }

    const currentRollup = release.tagCommit.statusCheckRollup ?? null;
    if (!currentRollup) {
      if (rollupId != null || contextTotalCount != null || requestCursor != null) {
        throw new Error(
          `GitHub GraphQL release ${tag} status check rollup identity changed within pagination ` +
          `from ${rollupId ?? 'present'} to missing`,
        );
      }
      rollup = null;
      after = null;
      break;
    }

    const currentRollupId = requireCanonicalGraphqlIdentity(
      currentRollup.id,
      `release ${tag} status check rollup identity`,
    );
    const connection = requireCountedGraphqlConnection(
      currentRollup.contexts,
      `release ${tag} status check contexts`,
    );
    if (rollupId == null) {
      rollupId = currentRollupId;
      contextTotalCount = connection.totalCount;
      rollupState = optionalCanonicalGraphqlString(
        currentRollup.state,
        `release ${tag} status check rollup state`,
      );
    } else {
      if (currentRollupId !== rollupId) {
        throw new Error(
          `GitHub GraphQL release ${tag} status check rollup identity changed within pagination ` +
          `from ${rollupId} to ${currentRollupId}`,
        );
      }
      if (connection.totalCount !== contextTotalCount) {
        throw new Error(
          `GitHub GraphQL release ${tag} status check context totalCount changed within pagination ` +
          `from ${contextTotalCount} to ${connection.totalCount}`,
        );
      }
      const currentRollupState = optionalCanonicalGraphqlString(
        currentRollup.state,
        `release ${tag} status check rollup state`,
      );
      if (currentRollupState !== rollupState) {
        throw new Error(
          `GitHub GraphQL release ${tag} status check rollup state changed within pagination ` +
            `from ${rollupState ?? 'missing'} to ${currentRollupState ?? 'missing'}`,
        );
      }
    }
    rollup = currentRollup;
    contextRecords.push(...mapReleaseCheckContexts(
      connection.nodes,
      `release ${tag} status check contexts`,
      contextNodeIds,
    ));
    after = pagination.next(connection.pageInfo, requestCursor);
    if (!after) break;
  }

  if (contextTotalCount != null && contextRecords.length !== contextTotalCount) {
    throw new Error(
      `GitHub GraphQL release ${tag} status check contexts exhausted with ` +
        `${contextRecords.length} nodes, ` +
      `but totalCount was ${contextTotalCount}`,
    );
  }
  const contexts = contextRecords.map((record) => record.context);
  const counts = countReleaseCheckContexts(contexts);
  assertReleaseCheckSourceContract(
    tag,
    rollupId != null,
    rollupState,
    contextTotalCount ?? 0,
    contexts,
    counts,
  );
  const commit: GhReleaseCommit = {
    tag,
    oid: tagOid,
    committedAt,
    checkState: rollupState,
    checkTotal: contextTotalCount ?? 0,
    checkSuccess: counts.success,
    checkFailure: counts.failure,
    checkPending: counts.pending,
    checkSkipped: counts.skipped,
    checkContexts: contexts,
  };
  return {
    commit,
    identityDigest: createHash('sha256')
      .update(JSON.stringify([
        tag,
        tagOid,
        rollupId,
        contextTotalCount ?? 0,
        contextRecords.map((record) => record.nodeId),
      ]))
      .digest('hex'),
    contentDigest: createHash('sha256')
      .update(JSON.stringify([
        tag,
        tagOid,
        committedAt,
        rollupId,
        rollupState,
        contextTotalCount ?? 0,
        contextRecords.map((record) => [
          record.nodeId,
          record.context.type,
          record.context.name,
          record.context.workflowName,
          record.context.appSlug,
          record.context.status,
          record.context.conclusion,
          record.context.url,
        ]),
      ]))
      .digest('hex'),
  };
}

interface ReleaseCommitQueryData {
  repository: {
    release: {
      tagCommit: {
        oid: string;
        committedDate?: string;
        statusCheckRollup?: {
          id: string;
          state: string | null;
          contexts: {
            totalCount: number;
            nodes: Array<{
              id: string;
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
              id
              state
              contexts(first: 100, after: $after) {
                totalCount
                nodes {
                  __typename
                  ... on CheckRun {
                    id
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
                    id
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

function optionalCanonicalGraphqlString(value: unknown, context: string): string | null {
  if (value == null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`GitHub GraphQL ${context} is invalid or non-canonical`);
  }
  return value;
}

function mapReleaseCheckContexts(
  nodes: any[],
  context = 'status check contexts',
  seenNodeIds = new Set<string>(),
): ReleaseCheckContextRecord[] {
  return nodes.map((node, index) => {
    const nodeContext = `${context} node ${index}`;
    const nodeId = requireCanonicalGraphqlIdentity(node?.id, `${nodeContext} identity`);
    if (seenNodeIds.has(nodeId)) {
      throw new Error(`GitHub GraphQL ${context} returned duplicate context node ID ${nodeId}`);
    }
    seenNodeIds.add(nodeId);

    if (node.__typename === 'StatusContext') {
      const name = requireCanonicalGraphqlIdentity(
        node.context,
        `${nodeContext} status context name`,
      );
      return {
        nodeId,
        context: {
          type: 'StatusContext',
          name,
          workflowName: null,
          appSlug: null,
          status: null,
          conclusion: optionalCanonicalGraphqlString(
            node.state,
            `${nodeContext} status context state`,
          ),
          url: optionalCanonicalGraphqlString(
            node.targetUrl,
            `${nodeContext} status context URL`,
          ),
        },
      };
    }
    if (node.__typename !== 'CheckRun') {
      throw new Error(
        `GitHub GraphQL ${nodeContext} returned unexpected type ` +
          `${String(node?.__typename)}`,
      );
    }
    const name = requireCanonicalGraphqlIdentity(node.name, `${nodeContext} check name`);
    return {
      nodeId,
      context: {
        type: 'CheckRun',
        name,
        workflowName: optionalCanonicalGraphqlString(
          node.checkSuite?.workflowRun?.workflow?.name,
          `${nodeContext} workflow name`,
        ),
        appSlug: optionalCanonicalGraphqlString(
          node.checkSuite?.app?.slug,
          `${nodeContext} app slug`,
        ),
        status: optionalCanonicalGraphqlString(node.status, `${nodeContext} check status`),
        conclusion: optionalCanonicalGraphqlString(
          node.conclusion,
          `${nodeContext} check conclusion`,
        ),
        url: optionalCanonicalGraphqlString(node.detailsUrl, `${nodeContext} check URL`),
      },
    };
  });
}

type ReleaseCheckDisposition = 'success' | 'failure' | 'pending' | 'skipped';

interface ReleaseCheckCounts {
  success: number;
  failure: number;
  pending: number;
  skipped: number;
}

function classifyReleaseCheckDisposition(
  context: GhReleaseCheckContext,
): ReleaseCheckDisposition {
  if (context.type === 'StatusContext') {
    switch ((context.conclusion ?? '').toUpperCase()) {
      case 'SUCCESS':
        return 'success';
      case 'PENDING':
      case 'EXPECTED':
        return 'pending';
      case 'ERROR':
      case 'FAILURE':
        return 'failure';
      default:
        return 'failure';
    }
  }

  const conclusion = (context.conclusion ?? '').toUpperCase();
  if (conclusion) {
    switch (conclusion) {
      case 'SUCCESS':
        return context.status?.toUpperCase() === 'COMPLETED' ? 'success' : 'failure';
      case 'SKIPPED':
      case 'NEUTRAL':
        return context.status?.toUpperCase() === 'COMPLETED' ? 'skipped' : 'failure';
      case 'ACTION_REQUIRED':
      case 'CANCELLED':
      case 'FAILURE':
      case 'STALE':
      case 'STARTUP_FAILURE':
      case 'TIMED_OUT':
        return 'failure';
      default:
        return 'failure';
    }
  }

  switch ((context.status ?? '').toUpperCase()) {
    case 'QUEUED':
    case 'IN_PROGRESS':
    case 'PENDING':
    case 'REQUESTED':
    case 'WAITING':
      return 'pending';
    default:
      return 'failure';
  }
}

function countReleaseCheckContexts(contexts: GhReleaseCheckContext[]): ReleaseCheckCounts {
  let success = 0;
  let failure = 0;
  let pending = 0;
  let skipped = 0;
  for (const context of contexts) {
    switch (classifyReleaseCheckDisposition(context)) {
      case 'success':
        success++;
        break;
      case 'failure':
        failure++;
        break;
      case 'pending':
        pending++;
        break;
      case 'skipped':
        skipped++;
        break;
    }
  }
  return { success, failure, pending, skipped };
}

function assertReleaseCheckSourceContract(
  tag: string,
  hasRollup: boolean,
  rollupState: string | null,
  totalCount: number,
  contexts: GhReleaseCheckContext[],
  counts: ReleaseCheckCounts,
): void {
  const bucketTotal = counts.success + counts.failure + counts.pending + counts.skipped;
  if (bucketTotal !== contexts.length || contexts.length !== totalCount) {
    throw new Error(
      `GitHub GraphQL release ${tag} status check bucket cardinality mismatch: ` +
        `${bucketTotal} bucketed, ${contexts.length} contexts, totalCount ${totalCount}`,
    );
  }
  if (!hasRollup) {
    if (rollupState !== null || totalCount !== 0) {
      throw new Error(`GitHub GraphQL release ${tag} missing rollup has inconsistent aggregate`);
    }
    return;
  }

  let aggregate: 'success' | 'failure' | 'pending';
  switch ((rollupState ?? '').toUpperCase()) {
    case 'SUCCESS':
      aggregate = 'success';
      break;
    case 'ERROR':
    case 'FAILURE':
      aggregate = 'failure';
      break;
    case 'EXPECTED':
    case 'PENDING':
      aggregate = 'pending';
      break;
    default:
      throw new Error(
        `GitHub GraphQL release ${tag} returned unsupported status check rollup state ` +
          `${JSON.stringify(rollupState)}`,
      );
  }

  const expectedAggregate = counts.failure > 0
    ? 'failure'
    : counts.pending > 0
      ? 'pending'
      : 'success';
  if (aggregate !== expectedAggregate) {
    throw new Error(
      `GitHub GraphQL release ${tag} status check aggregate ${String(rollupState)} ` +
        `is inconsistent with ${counts.success} success, ${counts.failure} failure, ` +
        `${counts.pending} pending, and ${counts.skipped} skipped contexts`,
    );
  }
}

function frozenConnectionPageSize(
  snapshot: GhIssueFixEvidenceConnectionSnapshot | undefined,
): number {
  return snapshot
    ? Math.max(1, Math.min(GRAPHQL_PAGE_SIZE, snapshot.totalCount))
    : GRAPHQL_PAGE_SIZE;
}

function closedByPullRequestIdentity(pr: any): string {
  if (!Number.isInteger(pr?.number) || pr.number <= 0) return '';
  return `${prRepositoryIdentityFromPullRequest(pr).nameWithOwner}#${pr.number}`;
}

function closedByPullRequestScoreContent(pr: any): unknown {
  return [closedByPullRequestIdentity(pr)];
}

function stateTimelineEventIdentity(node: any): string {
  return typeof node?.id === 'string' ? node.id : '';
}

function stateTimelineEventScoreContent(node: any): unknown {
  const closer = node?.closer ?? null;
  const closerContent = closer?.__typename === 'PullRequest'
    ? [
        'PullRequest',
        closer.id ?? null,
        prRepositoryIdentityFromPullRequest(closer).nameWithOwner,
        Number.isInteger(closer.number) ? closer.number : null,
        typeof closer.mergeCommit?.oid === 'string' ? closer.mergeCommit.oid : null,
      ]
    : closer?.__typename === 'Commit'
      ? ['Commit', closer.id ?? null, typeof closer.oid === 'string' ? closer.oid : null]
      : [closer?.__typename ?? null, closer?.id ?? null];
  return [
    node?.__typename ?? null,
    stateTimelineEventIdentity(node),
    node?.createdAt ?? null,
    node?.actor?.__typename ?? null,
    node?.actor?.id ?? null,
    node?.__typename === 'ClosedEvent' ? node?.stateReason ?? null : null,
    closerContent,
  ];
}

function referenceTimelineEventIdentity(node: any): string {
  return typeof node?.id === 'string' ? node.id : '';
}

function referenceTimelineEventScoreContent(node: any): unknown {
  if (node?.__typename === 'CrossReferencedEvent') {
    const source = node.source ?? null;
    const sourceContent = source?.__typename === 'PullRequest'
      ? [
          'PullRequest',
          prRepositoryIdentityFromPullRequest(source).nameWithOwner,
          Number.isInteger(source.number) ? source.number : null,
        ]
      : [source?.__typename ?? null];
    return [
      node.__typename,
      referenceTimelineEventIdentity(node),
      node.createdAt ?? null,
      typeof node.willCloseTarget === 'boolean' ? node.willCloseTarget : null,
      sourceContent,
    ];
  }
  if (node?.__typename === 'ReferencedEvent') {
    return [
      node.__typename,
      referenceTimelineEventIdentity(node),
      node.createdAt ?? null,
      node.actor?.login ?? null,
      node.isCrossRepository === true,
      node.isDirectReference === true,
      typeof node.commit?.oid === 'string' ? node.commit.oid.toLowerCase() : null,
      node.commit?.messageHeadline ?? null,
      node.commitRepository?.nameWithOwner ?? null,
      node.commitRepository?.owner?.login ?? null,
      node.commitRepository?.name ?? null,
    ];
  }
  return [
    node?.__typename ?? null,
    referenceTimelineEventIdentity(node),
    node?.createdAt ?? null,
  ];
}

type MutableIssueFixEvidence = Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'> & {
  stateSnapshot?: GhIssueStateEventSnapshot;
  connectionSnapshots?: GhIssueFixEvidenceConnectionSnapshots;
};

export async function listIssueFixEvidenceBatch(
  issueNumbers: number[],
  options: IssueBatchOptions = {},
): Promise<Map<number, GhIssueFixEvidence>> {
  const uniqueIssueNumbers = [...new Set(issueNumbers)].filter((n) => Number.isInteger(n));
  const request = options.request ?? gh;
  const all = new Map<number, GhIssueFixEvidence>();
  const batches = await mapIssueBatches(
    uniqueIssueNumbers,
    10,
    options,
    (chunk, workerOptions) =>
      listStableIssueFixEvidenceChunk(chunk, request, workerOptions),
  );
  for (const batch of batches) {
    for (const [issueNumber, evidence] of batch) all.set(issueNumber, evidence);
  }
  return all;
}

async function listStableIssueFixEvidenceChunk(
  chunk: number[],
  request: GraphqlRequest,
  options: IssueBatchOptions,
): Promise<Map<number, GhIssueFixEvidence>> {
  const sleeper = options.sleep ?? sleep;
  const maxAttempts = options.snapshotMaxAttempts ?? COMMENT_SNAPSHOT_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts <= 0) {
    throw new Error(`GitHub issue fix-evidence max attempts must be positive, got ${String(maxAttempts)}`);
  }
  const missingIssueNumbers = new Set<number>();
  let completeSweepCount = 0;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const firstSweep = await listIssueFixEvidenceChunk(
        chunk,
        missingIssueNumbers,
        request,
        options,
        completeSweepCount + 1,
      );
      completeSweepCount++;
      const frozenBoundaries = new Map(
        [...firstSweep].map(([issueNumber, evidence]) => [
          issueNumber,
          evidence.connectionSnapshots,
        ]),
      );
      const secondSweep = await listIssueFixEvidenceChunk(
        chunk,
        missingIssueNumbers,
        request,
        options,
        completeSweepCount + 1,
        frozenBoundaries,
      );
      completeSweepCount++;
      return requireMatchingIssueFixEvidenceSweeps(
        chunk.filter((issueNumber) => !missingIssueNumbers.has(issueNumber)),
        firstSweep,
        secondSweep,
        completeSweepCount,
      );
    } catch (error) {
      if (!(error instanceof IssueFixEvidenceInstabilityError)) throw error;
      if (attempt === maxAttempts) {
        throw new Error(
          `GitHub issue fix-evidence chunk failed to stabilize after ${maxAttempts} attempts: ${error.message}`,
        );
      }
      await sleepWithSignal(
        sleeper,
        commentSnapshotRetryDelayMs(attempt, options),
        options.signal,
      );
    }
  }
  throw new Error('GitHub issue fix-evidence chunk failed closed without a stable result');
}

async function listIssueFixEvidenceChunk(
  chunk: number[],
  missingIssueNumbers: Set<number>,
  request: GraphqlRequest,
  options: IssueBatchOptions,
  sweepOrdinal: number,
  frozenBoundaries: Map<number, GhIssueFixEvidenceConnectionSnapshots> | null = null,
): Promise<Map<number, GhIssueFixEvidence>> {
  const sweepIssueNumbers = chunk.filter((issueNumber) => !missingIssueNumbers.has(issueNumber));
  const all = new Map<number, MutableIssueFixEvidence>();

  const done = new Set<number>();
  let active = sweepIssueNumbers;
  let data: { repository: Record<string, any> | null } | null = null;
  for (;;) {
    active = sweepIssueNumbers.filter((issueNumber) => !done.has(issueNumber));
    if (active.length === 0) break;
    try {
      data = await request<{ repository: Record<string, any> | null }>(
        buildIssueFixEvidenceBatchQuery(active.length),
        repoVars(Object.fromEntries(active.flatMap((issueNumber, idx) => {
          const frozen = frozenBoundaries?.get(issueNumber);
          return [
            [`number${idx}`, issueNumber],
            [`closedByFirst${idx}`, frozenConnectionPageSize(frozen?.closedByPullRequestsReferences)],
            [`stateFirst${idx}`, frozenConnectionPageSize(frozen?.stateEvents)],
            [`referenceFirst${idx}`, frozenConnectionPageSize(frozen?.referenceEvents)],
          ];
        }))),
        options.signal,
      );
      break;
    } catch (error) {
      const missingReporter = options.onMissingIssueAlias
        ? (event: { issueNumber: number; aliasIndex: number }) => {
            const firstReport = !missingIssueNumbers.has(event.issueNumber);
            missingIssueNumbers.add(event.issueNumber);
            all.delete(event.issueNumber);
            if (firstReport) options.onMissingIssueAlias?.(event);
          }
        : undefined;
      if (skipMissingIssueAliases(error, active, done, missingReporter) === 0) throw error;
    }
  }
  for (const issueNumber of done) all.delete(issueNumber);
  if (!data || active.length === 0) return new Map();

  const repo = assertRepo(data.repository);
  const repositoryNodeId = requireCanonicalGraphqlIdentity(
    repo.id,
    'issue fix evidence repository node ID',
  );
  for (let idx = 0; idx < active.length; idx++) {
    const issueNumber = active[idx];
    const issue = repo[`issue${idx}`];
    if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while fetching fix evidence`);

    const closedByPullRequestsReferences = requireCountedGraphqlConnection(
      issue.closedByPullRequestsReferences,
      `issue #${issueNumber} closedByPullRequestsReferences`,
    );
    const stateEvents = requireCountedGraphqlConnection(
      issue.stateEvents,
      `issue #${issueNumber} state event timeline`,
    );
    const referenceEvents = requireCountedGraphqlConnection(
      issue.referenceEvents,
      `issue #${issueNumber} reference timeline`,
    );
    const frozen = frozenBoundaries?.get(issueNumber);
    const closedByMetadata = issueStateSnapshotMetadata(
      repositoryNodeId,
      issueNumber,
      issue,
      frozen?.closedByPullRequestsReferences.totalCount ??
        closedByPullRequestsReferences.totalCount,
    );
    const stateMetadata = issueStateSnapshotMetadata(
      repositoryNodeId,
      issueNumber,
      issue,
      frozen?.stateEvents.totalCount ?? stateEvents.totalCount,
    );
    const referenceMetadata = issueStateSnapshotMetadata(
      repositoryNodeId,
      issueNumber,
      issue,
      frozen?.referenceEvents.totalCount ?? referenceEvents.totalCount,
    );
    const evidence: MutableIssueFixEvidence = {
      repositoryNodeId,
      issueNumber,
      issueNodeId: stateMetadata.issueNodeId,
      issueNodeType: stateMetadata.issueNodeType,
      closureEvents: [],
      reopenEvents: [],
      prLinks: [],
      pullRequests: [],
      commitReferences: [],
    };
    all.set(issueNumber, evidence);
    const closedByCollector = new FrozenAppendOnlyConnectionCollector(
      `issue #${issueNumber} closedByPullRequestsReferences`,
      closedByPullRequestIdentity,
      closedByPullRequestScoreContent,
      frozen?.closedByPullRequestsReferences ?? null,
      options.maxPagesPerConnection,
    );
    const stateCollector = new FrozenAppendOnlyConnectionCollector(
      `issue #${issueNumber} state event timeline`,
      stateTimelineEventIdentity,
      stateTimelineEventScoreContent,
      frozen?.stateEvents ?? null,
      options.maxPagesPerConnection,
    );
    const referenceCollector = new FrozenAppendOnlyConnectionCollector(
      `issue #${issueNumber} reference timeline`,
      referenceTimelineEventIdentity,
      referenceTimelineEventScoreContent,
      frozen?.referenceEvents ?? null,
      options.maxPagesPerConnection,
    );
    const closedByKeys = new Set<string>();
    const stateEventIds = new Set<string>();
    const referenceEventIds = new Set<string>();
    let closedByAfter = closedByCollector.appendPage(
      closedByPullRequestsReferences,
      null,
      (nodes) => appendClosedByPullRequestReferences(evidence, issueNumber, nodes, closedByKeys),
    );
    let stateAfter = stateCollector.appendPage(
      stateEvents,
      null,
      (nodes) => appendStateTimelineNodes(evidence, issueNumber, nodes, stateEventIds),
    );
    let referenceAfter = referenceCollector.appendPage(
      referenceEvents,
      null,
      (nodes) => appendReferenceTimelineNodes(evidence, issueNumber, nodes, referenceEventIds),
    );
    await appendRemainingClosedByPullRequestReferences(
      evidence,
      issueNumber,
      closedByMetadata,
      closedByAfter,
      closedByCollector,
      closedByKeys,
      options,
    );
    await appendRemainingStateTimelineNodes(
      evidence,
      issueNumber,
      stateMetadata,
      stateAfter,
      stateCollector,
      stateEventIds,
      options,
    );
    await appendRemainingReferenceTimelineNodes(
      evidence,
      issueNumber,
      referenceMetadata,
      referenceAfter,
      referenceCollector,
      referenceEventIds,
      options,
    );
    evidence.connectionSnapshots = {
      closedByPullRequestsReferences: closedByCollector.snapshot(),
      stateEvents: stateCollector.snapshot(),
      referenceEvents: referenceCollector.snapshot(),
    };
    evidence.stateSnapshot = finalizeIssueStateSnapshot(
      evidence,
      stateMetadata,
      evidence.connectionSnapshots.stateEvents,
      sweepOrdinal,
    );
  }

  return new Map([...all].map(([issueNumber, evidence]) => {
    if (
      !evidence?.issueNodeId ||
      !evidence.repositoryNodeId ||
      evidence.issueNodeType !== 'Issue' ||
      !evidence.stateSnapshot ||
      !evidence.connectionSnapshots
    ) {
      throw new Error(`GitHub GraphQL missing verified fix evidence snapshot for issue #${issueNumber}`);
    }
    return [issueNumber, evidence as GhIssueFixEvidence];
  }));
}

function appendClosedByPullRequestReferences(
  evidence: Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'>,
  issueNumber: number,
  nodes: any[],
  seen = new Set<string>(),
): Set<string> {
  for (const pr of nodes) {
    if (!Number.isInteger(pr?.number) || pr.number <= 0) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} closedByPullRequestsReferences returned invalid PR number`);
    }
    const repo = prRepositoryIdentityFromPullRequest(pr);
    const key = `${repo.nameWithOwner}#${pr.number}`;
    if (seen.has(key)) {
      throw new Error(
        `GitHub GraphQL issue #${issueNumber} closedByPullRequestsReferences returned duplicate ${key}`,
      );
    }
    seen.add(key);
    evidence.prLinks.push({
      issueNumber,
      prNumber: pr.number,
      prRepositoryOwner: repo.owner,
      prRepositoryName: repo.name,
      prRepositoryNameWithOwner: repo.nameWithOwner,
      source: 'closedByPullRequestsReferences',
      willCloseTarget: true,
      referencedAt: pr.mergedAt ?? null,
    });
    evidence.pullRequests.push(mapPullRequestFix(pr));
  }
  return seen;
}

function appendStateTimelineNodes(
  evidence: Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'>,
  issueNumber: number,
  nodes: any[],
  seen = new Set<string>(),
): Set<string> {
  for (const node of nodes) {
    if (!node?.__typename) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} state event is missing __typename`);
    }
    if (typeof node.id !== 'string' || !node.id || node.id.trim() !== node.id) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} state event is missing canonical id`);
    }
    if (seen.has(node.id)) {
      throw new IssueFixEvidenceInstabilityError(
        `GitHub GraphQL issue #${issueNumber} state event timeline returned duplicate event ID ${node.id}`,
      );
    }
    seen.add(node.id);
    if (node.__typename === 'ClosedEvent') {
      const connectionOrdinal = evidence.closureEvents.length + evidence.reopenEvents.length;
      const closer = node.closer ?? null;
      const actorIdentity = stateTimelineActorIdentity(
        node.actor,
        `issue #${issueNumber} closed event ${node.id} actor`,
      );
      const closerIdentity = stateTimelineCloserIdentity(
        closer,
        `issue #${issueNumber} closed event ${node.id} closer`,
      );
      evidence.closureEvents.push({
        issueNumber,
        eventId: node.id,
        eventType: 'ClosedEvent',
        closedAt: node.createdAt ?? null,
        connectionOrdinal,
        actorNodeId: actorIdentity.nodeId,
        actorLogin: actorIdentity.login,
        actorType: actorIdentity.nodeType,
        stateReason: node.stateReason ?? null,
        closerType: closerIdentity.nodeType,
        closerNumber: typeof closer?.number === 'number' ? closer.number : null,
        closerNodeId: closerIdentity.nodeId,
        closerOid: typeof closer?.oid === 'string' ? closer.oid : closer?.mergeCommit?.oid ?? null,
        raw: node,
      });
      if (closer?.__typename === 'PullRequest' && typeof closer.number === 'number') {
        const repo = prRepositoryIdentityFromPullRequest(closer);
        evidence.prLinks.push({
          issueNumber,
          prNumber: closer.number,
          prRepositoryOwner: repo.owner,
          prRepositoryName: repo.name,
          prRepositoryNameWithOwner: repo.nameWithOwner,
          source: 'ClosedEvent.closer',
          willCloseTarget: true,
          referencedAt: node.createdAt ?? null,
        });
        evidence.pullRequests.push(mapPullRequestFix(closer));
      }
    } else if (node.__typename === 'ReopenedEvent') {
      const connectionOrdinal = evidence.closureEvents.length + evidence.reopenEvents.length;
      const actorIdentity = stateTimelineActorIdentity(
        node.actor,
        `issue #${issueNumber} reopened event ${node.id} actor`,
      );
      evidence.reopenEvents.push({
        issueNumber,
        eventId: node.id,
        eventType: 'ReopenedEvent',
        reopenedAt: node.createdAt ?? null,
        connectionOrdinal,
        actorNodeId: actorIdentity.nodeId,
        actorLogin: actorIdentity.login,
        actorType: actorIdentity.nodeType,
        raw: node,
      });
    } else {
      throw new Error(
        `GitHub GraphQL issue #${issueNumber} state event timeline returned unexpected ${node.__typename}`,
      );
    }
  }
  return seen;
}

function stateTimelineActorIdentity(
  actor: any,
  context: string,
): { nodeId: string | null; nodeType: string | null; login: string | null } {
  if (actor == null) return { nodeId: null, nodeType: null, login: null };
  return {
    nodeId: requireCanonicalGraphqlIdentity(actor.id, `${context} node ID`),
    nodeType: requireCanonicalGraphqlIdentity(actor.__typename, `${context} node type`),
    login: actor.login == null
      ? null
      : requireCanonicalGraphqlIdentity(actor.login, `${context} login`),
  };
}

function stateTimelineCloserIdentity(
  closer: any,
  context: string,
): { nodeId: string | null; nodeType: string | null } {
  if (closer == null) return { nodeId: null, nodeType: null };
  const nodeType = requireCanonicalGraphqlIdentity(
    closer.__typename,
    `${context} node type`,
  );
  if (!['Commit', 'ProjectV2', 'PullRequest'].includes(nodeType)) {
    throw new Error(`GitHub GraphQL ${context} returned unexpected node type ${nodeType}`);
  }
  return {
    nodeId: requireCanonicalGraphqlIdentity(closer.id, `${context} node ID`),
    nodeType,
  };
}

function appendReferenceTimelineNodes(
  evidence: Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'>,
  issueNumber: number,
  nodes: any[],
  seen = new Set<string>(),
): Set<string> {
  for (const node of nodes) {
    if (!node?.__typename) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} reference event is missing __typename`);
    }
    if (typeof node.id !== 'string' || node.id.length === 0) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} reference event is missing id`);
    }
    if (seen.has(node.id)) {
      throw new Error(`GitHub GraphQL issue #${issueNumber} reference timeline returned duplicate event ID ${node.id}`);
    }
    seen.add(node.id);
    if (node.__typename === 'CrossReferencedEvent') {
      const source = node.source;
      if (source?.__typename === 'PullRequest' && typeof source.number === 'number') {
        const repo = prRepositoryIdentityFromPullRequest(source);
        evidence.prLinks.push({
          issueNumber,
          prNumber: source.number,
          prRepositoryOwner: repo.owner,
          prRepositoryName: repo.name,
          prRepositoryNameWithOwner: repo.nameWithOwner,
          source: 'CrossReferencedEvent',
          willCloseTarget: typeof node.willCloseTarget === 'boolean' ? node.willCloseTarget : null,
          referencedAt: node.createdAt ?? null,
        });
        evidence.pullRequests.push(mapPullRequestFix(source));
      }
    } else if (node.__typename === 'ReferencedEvent') {
      const commitOid = node.commit?.oid;
      if (typeof commitOid === 'string' && /^[0-9a-f]{40}$/i.test(commitOid)) {
        evidence.commitReferences.push({
          issueNumber,
          eventId: node.id,
          commitOid: commitOid.toLowerCase(),
          commitMessageHeadline: node.commit?.messageHeadline ?? null,
          commitRepositoryOwner: node.commitRepository?.owner?.login ?? null,
          commitRepositoryName: node.commitRepository?.name ?? null,
          commitRepositoryNameWithOwner: node.commitRepository?.nameWithOwner ?? null,
          isCrossRepository: node.isCrossRepository === true,
          isDirectReference: node.isDirectReference === true,
          referencedAt: node.createdAt ?? null,
          actorLogin: node.actor?.login ?? null,
          raw: node,
        });
      }
    } else {
      throw new Error(
        `GitHub GraphQL issue #${issueNumber} reference timeline returned unexpected ${node.__typename}`,
      );
    }
  }
  return seen;
}

async function appendRemainingClosedByPullRequestReferences(
  evidence: Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'>,
  issueNumber: number,
  expectedMetadata: IssueStateSnapshotMetadata,
  after: string | null,
  collector: FrozenAppendOnlyConnectionCollector<any>,
  seen: Set<string>,
  options: Pick<IssueBatchOptions, 'request' | 'signal'> = {},
): Promise<void> {
  const context = `issue #${issueNumber} closedByPullRequestsReferences`;
  const request = options.request ?? gh;
  while (after) {
    const requestCursor = after;
    const data = await request<{
      repository: {
        id: string;
        issue: {
          id: string;
          __typename: 'Issue';
          number: number;
          state: 'OPEN' | 'CLOSED';
          updatedAt: string;
          closedByPullRequestsReferences: {
            totalCount: number;
            nodes: Array<any | null>;
            pageInfo: PageInfo;
          };
        } | null;
      } | null;
    }>(
      buildIssueClosedByPrRefsQuery(),
      repoVars({ number: issueNumber, first: collector.requestedPageSize(), after }),
      options.signal,
    );
    const repo = assertRepo(data.repository);
    const repositoryNodeId = requireCanonicalGraphqlIdentity(
      repo.id,
      `${context} repository node ID`,
    );
    const issue = repo.issue;
    if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while paginating closedByPullRequestsReferences`);
    const connection = requireCountedGraphqlConnection(
      issue.closedByPullRequestsReferences,
      context,
    );
    assertIssueStateSnapshotMetadataStable(
      issueNumber,
      expectedMetadata,
      issueStateSnapshotMetadata(
        repositoryNodeId,
        issueNumber,
        issue,
        expectedMetadata.totalCount,
      ),
      context,
    );
    after = collector.appendPage(
      connection,
      requestCursor,
      (nodes) => appendClosedByPullRequestReferences(evidence, issueNumber, nodes, seen),
    );
  }
}

interface IssueStateSnapshotMetadata {
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: 'Issue';
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  totalCount: number;
}

function issueStateSnapshotMetadata(
  repositoryNodeIdInput: unknown,
  issueNumber: number,
  issue: {
    id?: unknown;
    __typename?: unknown;
    number?: unknown;
    state?: unknown;
    updatedAt?: unknown;
  },
  totalCount: number,
): IssueStateSnapshotMetadata {
  const repositoryNodeId = requireCanonicalGraphqlIdentity(
    repositoryNodeIdInput,
    `issue #${issueNumber} state event snapshot repository node ID`,
  );
  const issueNodeId = requireCanonicalGraphqlIdentity(
    issue.id,
    `issue #${issueNumber} state event snapshot issue node ID`,
  );
  const issueNodeType = requireCanonicalGraphqlIdentity(
    issue.__typename,
    `issue #${issueNumber} state event snapshot issue node type`,
  );
  if (issueNodeType !== 'Issue') {
    throw new Error(
      `GitHub GraphQL issue #${issueNumber} state event snapshot returned ` +
      `unexpected issue node type ${issueNodeType}`,
    );
  }
  if (issue.number !== issueNumber) {
    throw new Error(
      `GitHub GraphQL requested issue #${issueNumber} state event snapshot but received ` +
      `issue #${String(issue.number)}`,
    );
  }
  const issueState = issue.state === 'OPEN'
    ? 'open'
    : issue.state === 'CLOSED'
      ? 'closed'
      : null;
  if (!issueState) {
    throw new Error(`GitHub GraphQL issue #${issueNumber} state event snapshot has invalid issue state`);
  }
  if (typeof issue.updatedAt !== 'string' || !Number.isFinite(Date.parse(issue.updatedAt))) {
    throw new Error(`GitHub GraphQL issue #${issueNumber} state event snapshot has invalid updatedAt`);
  }
  return {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType,
    issueState,
    issueUpdatedAt: issue.updatedAt,
    totalCount,
  };
}

function assertIssueStateSnapshotMetadataStable(
  issueNumber: number,
  expected: IssueStateSnapshotMetadata,
  actual: IssueStateSnapshotMetadata,
  context = 'state event snapshot',
): void {
  if (
    actual.repositoryNodeId === expected.repositoryNodeId &&
    actual.issueNumber === expected.issueNumber &&
    actual.issueNodeId === expected.issueNodeId &&
    actual.issueNodeType === expected.issueNodeType &&
    actual.issueState === expected.issueState &&
    actual.issueUpdatedAt === expected.issueUpdatedAt &&
    actual.totalCount === expected.totalCount
  ) {
    return;
  }
  throw new IssueFixEvidenceInstabilityError(
    `GitHub GraphQL issue #${issueNumber} ${context} metadata drifted during pagination: ` +
    `expected (${expected.repositoryNodeId},${expected.issueNodeType},${expected.issueNodeId},${expected.issueState},` +
    `${expected.issueUpdatedAt},${expected.totalCount}), received ` +
    `(${actual.repositoryNodeId},${actual.issueNodeType},${actual.issueNodeId},${actual.issueState},` +
    `${actual.issueUpdatedAt},${actual.totalCount})`,
  );
}

function normalizedStateEvents(
  evidence: Pick<GhIssueFixEvidence, 'closureEvents' | 'reopenEvents'>,
): NormalizedIssueStateEvent[] {
  return normalizeIssueStateEvents([
    ...evidence.closureEvents.map((event) => ({
      eventId: event.eventId,
      eventNodeType: event.eventType,
      type: 'closed' as const,
      occurredAt: event.closedAt ?? '',
      connectionOrdinal: event.connectionOrdinal,
      actorNodeId: event.actorNodeId,
      actorLogin: event.actorLogin,
      actorType: event.actorType,
      stateReason: event.stateReason,
      closerNodeId: event.closerNodeId,
      closerType: event.closerType,
      closerNumber: event.closerNumber,
      closerOid: event.closerOid,
    })),
    ...evidence.reopenEvents.map((event) => ({
      eventId: event.eventId,
      eventNodeType: event.eventType,
      type: 'reopened' as const,
      occurredAt: event.reopenedAt ?? '',
      connectionOrdinal: event.connectionOrdinal,
      actorNodeId: event.actorNodeId,
      actorLogin: event.actorLogin,
      actorType: event.actorType,
      stateReason: null,
      closerNodeId: null,
      closerType: null,
      closerNumber: null,
      closerOid: null,
    })),
  ]);
}

function finalizeIssueStateSnapshot(
  evidence: Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'>,
  metadata: IssueStateSnapshotMetadata,
  connectionSnapshot: GhIssueFixEvidenceConnectionSnapshot,
  sweepOrdinal: number,
): GhIssueStateEventSnapshot {
  const normalized = normalizedStateEvents(evidence);
  if (normalized.length !== connectionSnapshot.totalCount) {
    throw new Error(
      `GitHub GraphQL issue #${evidence.issueNumber} state event count mismatch: ` +
      `expected ${connectionSnapshot.totalCount}, fetched ${normalized.length}`,
    );
  }
  const latestEvent = normalized.at(-1) ?? null;
  const latestEventState = latestEvent?.type === 'closed'
    ? 'closed'
    : latestEvent?.type === 'reopened'
      ? 'open'
      : 'open';
  if (
    latestEventState !== metadata.issueState ||
    (metadata.issueState === 'closed' && latestEvent == null)
  ) {
    throw new Error(
      `GitHub GraphQL issue #${evidence.issueNumber} state event snapshot does not explain ` +
      `current ${metadata.issueState} state; a close or reopen event is missing`,
    );
  }
  const identity = {
    repositoryNodeId: metadata.repositoryNodeId,
    issueNodeId: evidence.issueNodeId,
    issueNodeType: evidence.issueNodeType,
  };
  const eventsDigest = issueStateEventsDigest(normalized, identity);
  const sweepIdentity = issueStateEventSweepIdentity({
    sweepOrdinal,
    repositoryNodeId: metadata.repositoryNodeId,
    issueNumber: evidence.issueNumber,
    issueNodeId: evidence.issueNodeId,
    issueNodeType: evidence.issueNodeType,
    issueState: metadata.issueState,
    issueUpdatedAt: metadata.issueUpdatedAt,
    totalCount: connectionSnapshot.totalCount,
    events: normalized,
  });
  return {
    schemaVersion: ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
    repositoryNodeId: metadata.repositoryNodeId,
    issueNumber: evidence.issueNumber,
    issueState: metadata.issueState,
    issueUpdatedAt: metadata.issueUpdatedAt,
    totalCount: connectionSnapshot.totalCount,
    fetchedCount: normalized.length,
    eventsDigest,
    authorityDigest: sweepIdentity.sweepDigest,
    sweepIdentity,
    sweepCount: sweepOrdinal,
    stabilized: false,
    stabilization: null,
  };
}

function issueFixEvidenceSweepDigest(evidence: GhIssueFixEvidence): string {
  return createHash('sha256')
    .update(JSON.stringify([
      evidence.stateSnapshot.schemaVersion,
      evidence.repositoryNodeId,
      evidence.issueNumber,
      evidence.issueNodeId,
      evidence.issueNodeType,
      evidence.stateSnapshot.repositoryNodeId,
      evidence.stateSnapshot.issueState,
      evidence.stateSnapshot.issueUpdatedAt,
      evidence.stateSnapshot.totalCount,
      evidence.stateSnapshot.eventsDigest,
      evidence.stateSnapshot.authorityDigest,
      evidence.stateSnapshot.sweepIdentity.sweepDigest,
      evidence.connectionSnapshots.closedByPullRequestsReferences.totalCount,
      evidence.connectionSnapshots.closedByPullRequestsReferences.observedTotalCount,
      evidence.connectionSnapshots.closedByPullRequestsReferences.postBoundaryGrowthCount,
      evidence.connectionSnapshots.closedByPullRequestsReferences.fetchedCount,
      evidence.connectionSnapshots.closedByPullRequestsReferences.identityDigest,
      evidence.connectionSnapshots.closedByPullRequestsReferences.contentDigest,
      evidence.connectionSnapshots.stateEvents.totalCount,
      evidence.connectionSnapshots.stateEvents.observedTotalCount,
      evidence.connectionSnapshots.stateEvents.postBoundaryGrowthCount,
      evidence.connectionSnapshots.stateEvents.fetchedCount,
      evidence.connectionSnapshots.stateEvents.identityDigest,
      evidence.connectionSnapshots.stateEvents.contentDigest,
      evidence.connectionSnapshots.referenceEvents.totalCount,
      evidence.connectionSnapshots.referenceEvents.observedTotalCount,
      evidence.connectionSnapshots.referenceEvents.postBoundaryGrowthCount,
      evidence.connectionSnapshots.referenceEvents.fetchedCount,
      evidence.connectionSnapshots.referenceEvents.identityDigest,
      evidence.connectionSnapshots.referenceEvents.contentDigest,
    ]))
    .digest('hex');
}

function canonicalGraphqlValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalGraphqlValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')))
        .map(([key, item]) => [key, canonicalGraphqlValue(item)]),
    );
  }
  return value;
}

function requireMatchingIssueFixEvidenceSweeps(
  issueNumbers: number[],
  firstSweep: Map<number, GhIssueFixEvidence>,
  secondSweep: Map<number, GhIssueFixEvidence>,
  sweepCount: number,
): Map<number, GhIssueFixEvidence> {
  const stable = new Map<number, GhIssueFixEvidence>();
  for (const issueNumber of issueNumbers) {
    const first = firstSweep.get(issueNumber);
    const second = secondSweep.get(issueNumber);
    if (!first || !second) {
      throw new IssueFixEvidenceInstabilityError(
        `issue #${issueNumber} fix evidence is missing from a complete state-event sweep`,
      );
    }
    const firstDigest = issueFixEvidenceSweepDigest(first);
    const secondDigest = issueFixEvidenceSweepDigest(second);
    if (firstDigest !== secondDigest) {
      throw new IssueFixEvidenceInstabilityError(
        `issue #${issueNumber} fix-evidence ordering or content changed between complete sweeps ` +
        `(${firstDigest} != ${secondDigest})`,
      );
    }
    const stabilization = issueStateEventStabilizationIdentity(
      first.stateSnapshot.sweepIdentity,
      second.stateSnapshot.sweepIdentity,
      sweepCount,
    );
    stable.set(issueNumber, {
      ...second,
      connectionSnapshots: {
        closedByPullRequestsReferences: mergeStableConnectionSnapshots(
          first.connectionSnapshots.closedByPullRequestsReferences,
          second.connectionSnapshots.closedByPullRequestsReferences,
        ),
        stateEvents: mergeStableConnectionSnapshots(
          first.connectionSnapshots.stateEvents,
          second.connectionSnapshots.stateEvents,
        ),
        referenceEvents: mergeStableConnectionSnapshots(
          first.connectionSnapshots.referenceEvents,
          second.connectionSnapshots.referenceEvents,
        ),
      },
      stateSnapshot: {
        ...second.stateSnapshot,
        sweepCount,
        stabilized: true,
        stabilization,
      },
    });
  }
  return stable;
}

function mergeStableConnectionSnapshots(
  first: GhIssueFixEvidenceConnectionSnapshot,
  second: GhIssueFixEvidenceConnectionSnapshot,
): GhIssueFixEvidenceConnectionSnapshot {
  for (const [sweep, snapshot] of [
    ['first', first],
    ['second', second],
  ] as const) {
    if (
      snapshot.fetchedCount !== snapshot.totalCount ||
      snapshot.observedTotalCount !== snapshot.totalCount ||
      snapshot.postBoundaryGrowthCount !== 0
    ) {
      throw new IssueFixEvidenceInstabilityError(
        `GitHub issue fix-evidence ${sweep} sweep cannot be published as complete: ` +
        `fetched ${snapshot.fetchedCount}, totalCount ${snapshot.totalCount}, ` +
        `observedTotalCount ${snapshot.observedTotalCount}, ` +
        `postBoundaryGrowthCount ${snapshot.postBoundaryGrowthCount}`,
      );
    }
  }
  if (first.totalCount !== second.totalCount) {
    throw new IssueFixEvidenceInstabilityError(
      `GitHub issue fix-evidence totalCount changed between complete sweeps ` +
      `from ${first.totalCount} to ${second.totalCount}`,
    );
  }
  return second;
}

async function appendRemainingStateTimelineNodes(
  evidence: Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'>,
  issueNumber: number,
  expectedMetadata: IssueStateSnapshotMetadata,
  after: string | null,
  collector: FrozenAppendOnlyConnectionCollector<any>,
  seen: Set<string>,
  options: Pick<IssueBatchOptions, 'request' | 'signal'> = {},
): Promise<void> {
  const context = `issue #${issueNumber} state event timeline`;
  const request = options.request ?? gh;
  while (after) {
    const requestCursor = after;
    const data = await request<{
      repository: {
        id: string;
        issue: {
          id: string;
          __typename: 'Issue';
          number: number;
          state: 'OPEN' | 'CLOSED';
          updatedAt: string;
          stateEvents: {
            totalCount: number;
            nodes: Array<any | null>;
            pageInfo: PageInfo;
          };
        } | null;
      } | null;
    }>(
      buildIssueStateTimelineQuery(),
      repoVars({ number: issueNumber, first: collector.requestedPageSize(), after }),
      options.signal,
    );
    const repo = assertRepo(data.repository);
    const repositoryNodeId = requireCanonicalGraphqlIdentity(
      repo.id,
      `${context} repository node ID`,
    );
    const issue = repo.issue;
    if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while paginating state events`);
    const connection = requireCountedGraphqlConnection(issue.stateEvents, context);
    assertIssueStateSnapshotMetadataStable(
      issueNumber,
      expectedMetadata,
      issueStateSnapshotMetadata(
        repositoryNodeId,
        issueNumber,
        issue,
        expectedMetadata.totalCount,
      ),
    );
    after = collector.appendPage(
      connection,
      requestCursor,
      (nodes) => appendStateTimelineNodes(evidence, issueNumber, nodes, seen),
    );
  }
}

async function appendRemainingReferenceTimelineNodes(
  evidence: Omit<GhIssueFixEvidence, 'stateSnapshot' | 'connectionSnapshots'>,
  issueNumber: number,
  expectedMetadata: IssueStateSnapshotMetadata,
  after: string | null,
  collector: FrozenAppendOnlyConnectionCollector<any>,
  seen: Set<string>,
  options: Pick<IssueBatchOptions, 'request' | 'signal'> = {},
): Promise<void> {
  const context = `issue #${issueNumber} reference timeline`;
  const request = options.request ?? gh;
  while (after) {
    const requestCursor = after;
    const data = await request<{
      repository: {
        id: string;
        issue: {
          id: string;
          __typename: 'Issue';
          number: number;
          state: 'OPEN' | 'CLOSED';
          updatedAt: string;
          referenceEvents: {
            totalCount: number;
            nodes: Array<any | null>;
            pageInfo: PageInfo;
          };
        } | null;
      } | null;
    }>(
      buildIssueReferenceTimelineQuery(),
      repoVars({ number: issueNumber, first: collector.requestedPageSize(), after }),
      options.signal,
    );
    const repo = assertRepo(data.repository);
    const repositoryNodeId = requireCanonicalGraphqlIdentity(
      repo.id,
      `${context} repository node ID`,
    );
    const issue = repo.issue;
    if (!issue) throw new Error(`GitHub GraphQL missing issue #${issueNumber} while paginating references`);
    const connection = requireCountedGraphqlConnection(issue.referenceEvents, context);
    assertIssueStateSnapshotMetadataStable(
      issueNumber,
      expectedMetadata,
      issueStateSnapshotMetadata(
        repositoryNodeId,
        issueNumber,
        issue,
        expectedMetadata.totalCount,
      ),
      context,
    );
    after = collector.appendPage(
      connection,
      requestCursor,
      (nodes) => appendReferenceTimelineNodes(evidence, issueNumber, nodes, seen),
    );
  }
}

export interface PullRequestLookup {
  prNumber: number;
  prRepositoryOwner?: string | null;
  prRepositoryName?: string | null;
  prRepositoryNameWithOwner?: string | null;
}

export interface PullRequestLookupOptions {
  onMissingPullRequest?: (event: { repositoryNameWithOwner: string; prNumber: number }) => void;
  request?: GraphqlRequest;
  signal?: AbortSignal;
}

export function pullRequestKey(repositoryNameWithOwner: string | null | undefined, prNumber: number): string {
  return `${normalizePrRepositoryIdentity({ nameWithOwner: repositoryNameWithOwner }).nameWithOwner}#${prNumber}`;
}

export async function listPullRequestFixesBatch(
  prLookups: PullRequestLookup[],
  options: PullRequestLookupOptions = {},
): Promise<Map<string, GhPullRequestFix>> {
  const byRepo = new Map<string, { owner: string; name: string; nameWithOwner: string; numbers: Set<number> }>();
  for (const lookup of prLookups) {
    if (!Number.isInteger(lookup.prNumber) || lookup.prNumber <= 0) continue;
    const repo = normalizePrRepositoryIdentity({
      owner: lookup.prRepositoryOwner ?? null,
      name: lookup.prRepositoryName ?? null,
      nameWithOwner: lookup.prRepositoryNameWithOwner ?? null,
    });
    const entry = byRepo.get(repo.nameWithOwner) ?? { ...repo, numbers: new Set<number>() };
    entry.numbers.add(lookup.prNumber);
    byRepo.set(repo.nameWithOwner, entry);
  }

  const all = new Map<string, GhPullRequestFix>();
  for (const repo of byRepo.values()) {
    const fetched = await listPullRequestFixesForRepo(repo, [...repo.numbers], options);
    for (const [key, pr] of fetched) all.set(key, pr);
  }
  return all;
}

async function listPullRequestFixesForRepo(
  repo: { owner: string; name: string; nameWithOwner: string },
  prNumbers: number[],
  options: PullRequestLookupOptions,
): Promise<Map<string, GhPullRequestFix>> {
  throwIfAborted(options.signal);
  const uniquePrNumbers = [...new Set(prNumbers)].filter((n) => Number.isInteger(n) && n > 0);
  const all = new Map<string, GhPullRequestFix>();
  const request = options.request ?? gh;
  const batchSize = 25;
  for (let offset = 0; offset < uniquePrNumbers.length; offset += batchSize) {
    throwIfAborted(options.signal);
    const chunk = uniquePrNumbers.slice(offset, offset + batchSize);
    let data: { repository: Record<string, any> | null };
    try {
      data = await request<{ repository: Record<string, any> | null }>(
        buildPullRequestFixesBatchQuery(chunk.length),
        {
          owner: repo.owner,
          repo: repo.name,
          ...Object.fromEntries(chunk.map((prNumber, idx) => [`number${idx}`, prNumber])),
        },
        options.signal,
      );
    } catch (e) {
      if (chunk.length > 1 && isMissingPullRequestError(e)) {
        const fallback = await listPullRequestFixesForRepo(repo, chunk.slice(0, Math.ceil(chunk.length / 2)), options);
        for (const [key, pr] of fallback) all.set(key, pr);
        const rest = await listPullRequestFixesForRepo(repo, chunk.slice(Math.ceil(chunk.length / 2)), options);
        for (const [key, pr] of rest) all.set(key, pr);
        continue;
      }
      if (chunk.length === 1 && isMissingPullRequestError(e)) {
        if (options.onMissingPullRequest) {
          options.onMissingPullRequest({ repositoryNameWithOwner: repo.nameWithOwner, prNumber: chunk[0] });
          continue;
        }
        throw new Error(`GitHub GraphQL missing pull request ${repo.nameWithOwner}#${chunk[0]} while resolving closure-comment PR evidence`);
      }
      throw e;
    }
    const responseRepo = assertRepo(data.repository);
    for (let idx = 0; idx < chunk.length; idx++) {
      const pr = responseRepo[`pr${idx}`];
      if (!pr?.number) {
        if (options.onMissingPullRequest) {
          options.onMissingPullRequest({ repositoryNameWithOwner: repo.nameWithOwner, prNumber: chunk[idx] });
          continue;
        }
        throw new Error(`GitHub GraphQL missing ${repo.nameWithOwner}#${chunk[idx]} pull request without a missing-PR error`);
      }
      const mapped = mapPullRequestFix(pr);
      if (mapped.number !== chunk[idx]) {
        throw new Error(
          `GitHub GraphQL requested ${repo.nameWithOwner}#${chunk[idx]} but received ` +
            `${mapped.repositoryNameWithOwner}#${mapped.number}`,
        );
      }
      if (mapped.repositoryNameWithOwner !== repo.nameWithOwner) {
        throw new Error(
          `GitHub GraphQL requested pull request repository ${repo.nameWithOwner} but received ` +
            `${mapped.repositoryNameWithOwner}`,
        );
      }
      all.set(pullRequestKey(mapped.repositoryNameWithOwner, mapped.number), mapped);
    }
  }
  return all;
}

function isMissingPullRequestError(e: unknown): boolean {
  const message = e instanceof Error ? e.message : String(e);
  return /Could not resolve to a PullRequest with the number/i.test(message);
}

interface ClosureProofCommentInput {
  body?: string | null;
  created_at?: string | null;
  createdAt?: string | null;
  updated_at?: string | null;
  updatedAt?: string | null;
  id?: number | null;
  databaseId?: number | null;
  node_id?: string | null;
  nodeId?: string | null;
  node_type?: string | null;
  nodeType?: string | null;
  __typename?: string | null;
  url?: string | null;
  user?: {
    id?: string | null;
    node_id?: string | null;
    nodeId?: string | null;
    type?: string | null;
    actor_type?: string | null;
    actorType?: string | null;
    __typename?: string | null;
    login?: string | null;
  } | null;
  author?: string | null;
  author_association?: string | null;
  authorAssociation?: string | null;
}

export function closureCommentPrMentions(
  issueNumber: number,
  comments: ClosureProofCommentInput[],
  options: ClosureProofCommentTrustOptions = {},
): ClosureCommentPrMention[] {
  const byPr = new Map<string, ClosureCommentPrMention>();
  const trackedRepository = normalizePrRepositoryIdentity({}).nameWithOwner;
  for (const comment of comments) {
    const body = comment.body ?? '';
    const text = body.replace(/\s+/g, ' ');
    const source = closureCommentPrMentionSource(body);
    if (!source) continue;
    const trust = closureProofCommentTrust(comment, options);
    if (!trust.trustedSource) continue;
    for (const ref of extractClosureCommentPrRefs(body, source)) {
      if (
        ref.prNumber === issueNumber &&
        ref.prRepositoryNameWithOwner === trackedRepository
      ) continue;
      const key = pullRequestKey(ref.prRepositoryNameWithOwner, ref.prNumber);
      const existing = byPr.get(key);
      const referencedAt = commentEffectiveAt(comment);
      if (shouldReplacePrMention(existing, source, referencedAt)) {
        const commentSource = closureCommentSource(comment, issueNumber);
        byPr.set(key, {
          issueNumber,
          prNumber: ref.prNumber,
          prRepositoryOwner: ref.prRepositoryOwner,
          prRepositoryName: ref.prRepositoryName,
          prRepositoryNameWithOwner: ref.prRepositoryNameWithOwner,
          source,
          referencedAt,
          ...commentSource,
          ...trust,
        });
      }
    }
  }
  return [...byPr.values()].sort((a, b) =>
    compareBinary(
      String(a.prRepositoryNameWithOwner ?? ''),
      String(b.prRepositoryNameWithOwner ?? ''),
    ) ||
    a.prNumber - b.prNumber);
}

export function closureCommentCommitMentions(
  issueNumber: number,
  comments: ClosureProofCommentInput[],
  sourceIssueNumber = issueNumber,
  resolveCommitOid?: CommitOidResolver,
  options: ClosureProofCommentTrustOptions = {},
): ClosureCommentCommitMention[] {
  const byCommit = new Map<string, ClosureCommentCommitMention>();
  for (const comment of comments) {
    const body = comment.body ?? '';
    const text = body.replace(/\s+/g, ' ');
    const trust = closureProofCommentTrust(comment, options);
    if (!trust.trustedSource) continue;
    if (!closureCommentLines(body).some(isClosureCommitFixProofComment)) continue;
    const referencedAt = commentEffectiveAt(comment);
    for (const commit of extractCommitOids(body, resolveCommitOid)) {
      const existing = byCommit.get(commit.commitOid);
      if (!existing || (referencedAt && (!existing.referencedAt || referencedAt < existing.referencedAt))) {
        const commentSource = closureCommentSource(comment, sourceIssueNumber);
        byCommit.set(commit.commitOid, {
          issueNumber,
          ...commit,
          referencedAt,
          sourceIssueNumber,
          ...commentSource,
          snippet: text.slice(0, 500),
          source: 'ClosureComment.fixProof',
          ...trust,
        });
      }
    }
  }
  return [...byCommit.values()].sort((a, b) => compareBinary(a.commitOid, b.commitOid));
}

const TRUSTED_CLOSURE_PROOF_ASSOCIATIONS = new Set(['OWNER', 'MEMBER', 'COLLABORATOR']);

export interface ClosureProofCommentTrustOptions {
  finalClosureActors?: readonly string[];
  finalClosureActorIdentities?: ReadonlyArray<{
    nodeId: string;
    nodeType: string;
  }>;
}

function closureProofCommentTrust(
  comment: ClosureProofCommentInput,
  options: ClosureProofCommentTrustOptions,
): {
  author: string | null;
  authorAssociation: string | null;
  trustedSource: boolean;
} {
  const author = comment.user?.login ?? comment.author ?? null;
  const authorAssociation = comment.author_association ?? comment.authorAssociation ?? null;
  const commentNodeId = canonicalIdentityAliases(
    [comment.node_id, comment.nodeId],
    'closure proof comment node ID',
  );
  const commentNodeType = canonicalIdentityAliases(
    [comment.node_type, comment.nodeType, comment.__typename],
    'closure proof comment node type',
  );
  const actorNodeId = canonicalIdentityAliases(
    [comment.user?.id, comment.user?.node_id, comment.user?.nodeId],
    'closure proof comment actor node ID',
  );
  const actorNodeType = canonicalIdentityAliases(
    [
      comment.user?.type,
      comment.user?.actor_type,
      comment.user?.actorType,
      comment.user?.__typename,
    ],
    'closure proof comment actor node type',
  );
  const finalClosureActorIdentities = new Set(
    (options.finalClosureActorIdentities ?? []).map((identity) => {
      const nodeId = requireCanonicalGraphqlIdentity(
        identity.nodeId,
        'final closure actor node ID',
      );
      const nodeType = requireCanonicalGraphqlIdentity(
        identity.nodeType,
        'final closure actor node type',
      );
      return `${nodeType}\0${nodeId}`;
    }),
  );
  const hasCanonicalCommentSource =
    commentNodeId != null && commentNodeType === 'IssueComment';
  const hasCanonicalActor = actorNodeId != null && actorNodeType != null;
  const trustedSource = hasCanonicalCommentSource && hasCanonicalActor && (
    TRUSTED_CLOSURE_PROOF_ASSOCIATIONS.has(authorAssociation ?? '') ||
    finalClosureActorIdentities.has(`${actorNodeType}\0${actorNodeId}`)
  );
  return { author, authorAssociation, trustedSource };
}

function canonicalIdentityAliases(
  values: unknown[],
  context: string,
): string | null {
  let canonical: string | null = null;
  for (const value of values) {
    if (value == null) continue;
    let current: string;
    try {
      current = requireCanonicalGraphqlIdentity(value, context);
    } catch {
      return null;
    }
    if (canonical != null && canonical !== current) return null;
    canonical = current;
  }
  return canonical;
}

function closureCommentSource(comment: {
  id?: number | null;
  databaseId?: number | null;
  url?: string | null;
}, issueNumber: number): {
  sourceCommentDatabaseId?: number | null;
  sourceCommentUrl?: string | null;
} {
  const rawId = Number(comment.id ?? comment.databaseId ?? 0);
  const sourceCommentDatabaseId = Number.isInteger(rawId) && rawId > 0 ? rawId : null;
  const explicitUrl = typeof comment.url === 'string' && comment.url ? comment.url : null;
  const sourceCommentUrl = explicitUrl ?? (sourceCommentDatabaseId
    ? `https://github.com/${config.github.owner}/${config.github.repo}/issues/${issueNumber}#issuecomment-${sourceCommentDatabaseId}`
    : null);
  return sourceCommentDatabaseId || sourceCommentUrl
    ? { sourceCommentDatabaseId, sourceCommentUrl }
    : {};
}

function extractClosureCommentPrRefs(
  body: string,
  source: ClosureCommentPrMention['source'],
): Array<{
  prNumber: number;
  prRepositoryOwner: string;
  prRepositoryName: string;
  prRepositoryNameWithOwner: string;
}> {
  const refs = new Map<string, {
    prNumber: number;
    prRepositoryOwner: string;
    prRepositoryName: string;
    prRepositoryNameWithOwner: string;
  }>();
  const relevantLines = body
    .split(/\n+/)
    .map((line) => line.replace(/\s+/g, ' ').trim())
    .filter((line) => source === CLOSURE_COMMENT_FIX_PROOF_SOURCE
      ? isClosureFixProofComment(line)
      : isClosurePrContextComment(line));
  const text = relevantLines.join(' ');

  for (const match of text.matchAll(/https?:\/\/github\.com\/([^/\s]+)\/([^/\s]+)\/pull\/(\d+)\b|https?:\/\/api\.github\.com\/repos\/([^/\s]+)\/([^/\s]+)\/pulls?\/(\d+)\b/gi)) {
    addPrRef(refs, {
      owner: match[1] ?? match[4],
      name: match[2] ?? match[5],
      number: match[3] ?? match[6],
    });
  }

  const qualifiedMentionRe = /\b(?:merged\s+PR|merged\s+pull request|PR|pull request)\s*(?:that appears to have closed this:?\s*)?(?:\[)?#(\d+)\b/gi;
  for (const match of text.matchAll(qualifiedMentionRe)) {
    addPrRef(refs, { number: match[1] });
  }

  const fixedByIssueOrPrRefRe = /\b(?:fix(?:e[sd])?|implemented|addressed)\s+(?:on\s+`?main`?\s+)?by\s+#(\d+)\b/gi;
  for (const match of text.matchAll(fixedByIssueOrPrRefRe)) {
    addPrRef(refs, { number: match[1] });
  }

  const qualifiedFixedByPrRefRe = /\b(?:fix(?:e[sd])?|implemented|addressed|resolved|marking\s+this\s+fixed)\b.{0,120}\b(?:primarily|partly|partially|notably|via|by)\s+(?:PR\s*)?#(\d+)\b/gi;
  for (const match of text.matchAll(qualifiedFixedByPrRefRe)) {
    addPrRef(refs, { number: match[1] });
  }

  const canonicalPrRefRe = /\bcanonical\s+(?:PR|pull request)\s*:\s*#(\d+)\b/gi;
  for (const match of text.matchAll(canonicalPrRefRe)) {
    addPrRef(refs, { number: match[1] });
  }

  return [...refs.values()].sort((a, b) =>
    compareBinary(a.prRepositoryNameWithOwner, b.prRepositoryNameWithOwner) ||
    a.prNumber - b.prNumber);
}

function closureCommentPrMentionSource(
  text: string,
): ClosureCommentPrMention['source'] | null {
  const lines = closureCommentLines(text);
  if (lines.some(isClosureKeepOpenComment)) return null;
  if (lines.some(isClosureFixProofComment)) return CLOSURE_COMMENT_FIX_PROOF_SOURCE;
  if (lines.some(isClosurePrContextComment)) return CLOSURE_COMMENT_PR_MENTION_SOURCE;
  return null;
}

function shouldReplacePrMention(
  existing: ClosureCommentPrMention | undefined,
  source: ClosureCommentPrMention['source'],
  referencedAt: string | null,
): boolean {
  if (!existing) return true;
  if (existing.source !== CLOSURE_COMMENT_FIX_PROOF_SOURCE && source === CLOSURE_COMMENT_FIX_PROOF_SOURCE) return true;
  if (existing.source === CLOSURE_COMMENT_FIX_PROOF_SOURCE && source !== CLOSURE_COMMENT_FIX_PROOF_SOURCE) return false;
  return !!referencedAt && (!existing.referencedAt || referencedAt < existing.referencedAt);
}

function isClosureFixProofComment(text: string): boolean {
  if (isNonFixProofContext(text)) return false;
  return (
    /\b(?:fix(?:e[sd])?|implemented|addressed)\s+(?:on\s+`?main`?\s+)?by\s+#\d+\b/i.test(text) ||
    /\b(?:fix(?:e[sd])?|implemented|addressed|resolved|marking\s+this\s+fixed)\b.{0,120}\b(?:primarily|partly|partially|notably|via|by)\s+(?:PR\s*)?#\d+\b/i.test(text) ||
    /\bcanonical\s+(?:PR|pull request)\s*:\s*#\d+\b/i.test(text) ||
    /\bfound\s+the\s+merged\s+(?:pr|pull request)\b.{0,160}\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\b/i.test(text) ||
    /\bmerged\s+(?:pr|pull request)\b.{0,160}\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\b/i.test(text) ||
    /\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\b.{0,160}\bmerged\s+(?:pr|pull request)\b/i.test(text) ||
    /\b(?:pr|pull request)\s*#?\d+\b.{0,120}\b(?:closed|fix(?:e[sd])?|implemented|addresses?)\s+(?:this|the report|the issue)\b/i.test(text)
  );
}

function isClosurePrContextComment(text: string): boolean {
  return (
    /\b(?:close[sd]?|closing)\b.{0,160}\b(?:duplicate|dupe|superseded|already tracked|covered by)\b.{0,240}\b(?:open\s+)?(?:pr|pull request|https?:\/\/github\.com\/openclaw\/openclaw\/pull\/\d+)/i.test(text) ||
    /\b(?:duplicate|dupe|superseded|canonical|tracked|active)\b.{0,200}\b(?:open\s+)?(?:pr|pull request|https?:\/\/github\.com\/openclaw\/openclaw\/pull\/\d+)/i.test(text) ||
    /\bcanonical path:\s*(?:open\s+)?(?:pr|pull request|https?:\/\/github\.com\/openclaw\/openclaw\/pull\/\d+)/i.test(text)
  );
}

function isClosureCommitFixProofComment(text: string): boolean {
  if (isClosureKeepOpenComment(text) || isNonFixProofContext(text)) return false;
  return (
    /\bfix(?:ed)?\s+(?:on\s+`?main`?\s+)?in\s+`?[0-9a-f]{7,40}`?/i.test(text) ||
    /\bfix(?:ed)?\s+(?:on\s+`?main`?\s+)?in\s+https?:\/\/github\.com\/openclaw\/openclaw\/commit\/[0-9a-f]{7,40}\b/i.test(text) ||
    /\bfixed\s+on\s+(?:current\s+)?(?:source|main)\s+by\s+commit\s+`?[0-9a-f]{7,40}`?/i.test(text) ||
    /\bfixed\s+on\s+(?:current\s+)?`?(?:source|main)`?\s+by\s+`?[0-9a-f]{7,40}`?/i.test(text) ||
    /\bfixed\s+by\s+commit\s+`?[0-9a-f]{7,40}`?/i.test(text) ||
    /\bproof:\b.{0,1000}\b[0-9a-f]{40}\b/i.test(text) ||
    /\bfix\s+(?:commit\s+)?provenance\b.{0,220}\bcommit\b/i.test(text) ||
    /\bcanonical\s+fix\b.{0,220}\bcommit\b/i.test(text) ||
    /\bfix\s+evidence\b.{0,220}\bcommit\b/i.test(text)
  );
}

function closureCommentLines(text: string): string[] {
  return text
    .split(/\n+/)
    .map((line) => line.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

function isNonFixProofContext(text: string): boolean {
  return (
    /\bnot[- ]a[- ]fix\b|\bnot\s+(?:actually\s+)?(?:the\s+|an?\s+)?(?:actual\s+)?fix\b|\bno\s+fix\b/i.test(text) ||
    /\b(?:isn't|aren't|wasn't|weren't)\s+(?:actually\s+)?(?:the\s+|an?\s+)?(?:actual\s+)?fix\b/i.test(text) ||
    /\b(?:do|does|did|will|would|can|could)\s+not\s+(?:actually\s+)?fix\b/i.test(text) ||
    /\b(?:don't|doesn't|didn't|won't|wouldn't|can't|couldn't)\s+(?:actually\s+)?fix\b/i.test(text) ||
    /\b(?:is|are|was|were)\s+not\s+(?:actually\s+)?fixed\b|\b(?:isn't|aren't|wasn't|weren't)\s+(?:actually\s+)?fixed\b/i.test(text) ||
    /\bnot\s+(?:actually\s+)?fixed\b|\bnever\s+(?:actually\s+)?fix(?:e[sd])?\b/i.test(text) ||
    /\bfail(?:s|ed)?\s+to\s+fix\b|\bnot\s+(?:sufficient|proven)\b/i.test(text) ||
    /\b(?:introduced|caused|triggered)\s+(?:this\s+|the\s+)?(?:bug|issue|regression|failure|breakage)?\s*(?:by|in|from)\b/i.test(text) ||
    /\b(?:introduced|caused|triggered)\s+(?:by|in|from)\b/i.test(text) ||
    /\broot[- ]cause(?:d)?\b|\bculprit\b/i.test(text) ||
    /\bregression\b.{0,120}\b(?:introduced|caused|triggered|from|by|in)\b/i.test(text) ||
    /\b(?:introduced|caused|triggered)\b.{0,120}\bregression\b/i.test(text) ||
    /\b(?:broke|broken|regressed)\s+(?:by|in|from)\b/i.test(text)
  );
}

function commentEffectiveAt(comment: {
  created_at?: string | null;
  createdAt?: string | null;
  updated_at?: string | null;
  updatedAt?: string | null;
}): string | null {
  const createdAt = comment.created_at ?? comment.createdAt ?? null;
  const updatedAt = comment.updated_at ?? comment.updatedAt ?? null;
  const createdMs = createdAt ? Date.parse(createdAt) : Number.NaN;
  const updatedMs = updatedAt ? Date.parse(updatedAt) : Number.NaN;
  if (Number.isFinite(updatedMs) && (!Number.isFinite(createdMs) || updatedMs > createdMs)) return updatedAt;
  return createdAt;
}

function extractCommitOids(
  text: string,
  resolveCommitOid?: CommitOidResolver,
): ExtractedCommitOid[] {
  const commits = new Map<string, ExtractedCommitOid>();
  const relevantLines = closureCommentLines(text)
    .filter((line) => isClosureCommitFixProofComment(line));
  const commitPatterns = [
    /github\.com\/openclaw\/openclaw\/commit\/([0-9a-f]{7,40})\b/gi,
    /\bfix\s+(?:commit\s+)?provenance\b.{0,160}\bcommit(?:\s+is|:)?\s+`?([0-9a-f]{7,40})`?\b/gi,
    /\bcanonical\s+fix\b.{0,160}\bcommit\s+`?([0-9a-f]{7,40})`?\b/gi,
    /\bfix\s+evidence\b.{0,160}\bcommit\s+`?([0-9a-f]{7,40})`?\b/gi,
    /\bfix(?:ed)?\s+(?:on\s+`?main`?\s+)?in\s+`?([0-9a-f]{7,40})`?\b/gi,
    /\bfixed\s+on\s+(?:current\s+)?`?(?:source|main)`?\s+by\s+(?:commit\s+)?`?([0-9a-f]{7,40})`?\b/gi,
    /\bfixed\s+by\s+commit\s+`?([0-9a-f]{7,40})`?\b/gi,
  ];
  for (const line of relevantLines) {
    for (const re of commitPatterns) {
      re.lastIndex = 0;
      for (const match of line.matchAll(re)) {
        const raw = match[1].toLowerCase();
        if (/^[0-9a-f]{40}$/.test(raw)) {
          commits.set(raw, { commitOid: raw });
          continue;
        }
        const resolved = resolveCommitOid?.(raw)?.trim().toLowerCase() ?? null;
        const commitOid = resolved &&
            /^[0-9a-f]{40}$/.test(resolved) &&
            resolved.startsWith(raw)
          ? resolved
          : raw;
        commits.set(commitOid, { commitOid, shortOid: raw });
      }
    }
  }
  return [...commits.values()].sort((left, right) =>
    compareBinary(left.commitOid, right.commitOid));
}

function mapPullRequestFix(pr: any): GhPullRequestFix {
  if (!Number.isInteger(pr?.number) || pr.number <= 0) {
    throw new Error(`GitHub GraphQL pull request returned invalid number ${String(pr?.number)}`);
  }
  const repo = prRepositoryIdentityFromPullRequest(pr);
  return {
    number: pr.number,
    repositoryOwner: repo.owner,
    repositoryName: repo.name,
    repositoryNameWithOwner: repo.nameWithOwner,
    repositoryUrl: pr.repository?.url ?? null,
    title: pr.title ?? null,
    url: pr.url ?? null,
    state: pr.state ?? null,
    merged: pr.merged === true,
    mergedAt: pr.mergedAt ?? null,
    mergeCommitOid: pr.mergeCommit?.oid ?? null,
    baseRefName: pr.baseRefName ?? null,
  };
}

function addPrRef(
  refs: Map<string, {
    prNumber: number;
    prRepositoryOwner: string;
    prRepositoryName: string;
    prRepositoryNameWithOwner: string;
  }>,
  input: { owner?: string | null; name?: string | null; number?: string | number | null },
): void {
  const prNumber = Number(input.number);
  if (!Number.isInteger(prNumber) || prNumber <= 0) return;
  const repo = normalizePrRepositoryIdentity({
    owner: input.owner ?? null,
    name: input.name ?? null,
  });
  refs.set(pullRequestKey(repo.nameWithOwner, prNumber), {
    prNumber,
    prRepositoryOwner: repo.owner,
    prRepositoryName: repo.name,
    prRepositoryNameWithOwner: repo.nameWithOwner,
  });
}

function prRepositoryIdentityFromPullRequest(pr: any): { owner: string; name: string; nameWithOwner: string } {
  return normalizePrRepositoryIdentity({
    owner: pr.repository?.owner?.login ?? null,
    name: pr.repository?.name ?? null,
    nameWithOwner: pr.repository?.nameWithOwner ?? null,
    url: pr.url ?? null,
  });
}

function normalizePrRepositoryIdentity(input: {
  owner?: string | null;
  name?: string | null;
  nameWithOwner?: string | null;
  url?: string | null;
}): { owner: string; name: string; nameWithOwner: string } {
  const candidates: Array<{ owner: string; name: string; nameWithOwner: string; source: string }> = [];
  if (input.nameWithOwner != null) {
    if (typeof input.nameWithOwner !== 'string' || input.nameWithOwner.trim() !== input.nameWithOwner) {
      throw new Error('GitHub pull request repository nameWithOwner is non-canonical');
    }
    const parts = input.nameWithOwner.split('/');
    if (parts.length !== 2) {
      throw new Error('GitHub pull request repository nameWithOwner must contain one owner/name pair');
    }
    candidates.push(canonicalPrRepositoryIdentity(parts[0], parts[1], 'nameWithOwner'));
  }

  const hasOwner = input.owner != null;
  const hasName = input.name != null;
  if (hasOwner !== hasName) {
    throw new Error('GitHub pull request repository owner and name must be provided together');
  }
  if (hasOwner && hasName) {
    if (
      typeof input.owner !== 'string' ||
      typeof input.name !== 'string' ||
      input.owner.trim() !== input.owner ||
      input.name.trim() !== input.name
    ) {
      throw new Error('GitHub pull request repository owner/name is non-canonical');
    }
    candidates.push(canonicalPrRepositoryIdentity(input.owner, input.name, 'owner/name'));
  }

  if (input.url != null) {
    if (typeof input.url !== 'string' || input.url.trim() !== input.url) {
      throw new Error('GitHub pull request URL is non-canonical');
    }
    let url: URL;
    try {
      url = new URL(input.url);
    } catch {
      throw new Error('GitHub pull request URL is invalid');
    }
    const match = /^\/([^/]+)\/([^/]+)\/pull\/[1-9]\d*(?:\/.*)?$/.exec(url.pathname);
    if (
      url.protocol !== 'https:' ||
      url.hostname.toLowerCase() !== 'github.com' ||
      url.port !== '' ||
      url.username !== '' ||
      url.password !== '' ||
      !match
    ) {
      throw new Error('GitHub pull request URL does not contain a canonical GitHub repository identity');
    }
    candidates.push(canonicalPrRepositoryIdentity(match[1], match[2], 'pull request URL'));
  }

  if (candidates.length === 0) {
    return canonicalPrRepositoryIdentity(
      config.github.owner,
      config.github.repo,
      'tracked repository',
    );
  }
  const canonical = candidates[0];
  for (const candidate of candidates.slice(1)) {
    if (candidate.nameWithOwner !== canonical.nameWithOwner) {
      throw new Error(
        `GitHub pull request repository identity mismatch between ${canonical.source} ` +
          `(${canonical.nameWithOwner}) and ${candidate.source} (${candidate.nameWithOwner})`,
      );
    }
  }
  return {
    owner: canonical.owner,
    name: canonical.name,
    nameWithOwner: canonical.nameWithOwner,
  };
}

function canonicalPrRepositoryIdentity(
  owner: string,
  name: string,
  source: string,
): { owner: string; name: string; nameWithOwner: string; source: string } {
  if (
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner) ||
    !/^[A-Za-z0-9_.-]{1,100}$/.test(name) ||
    name === '.' ||
    name === '..'
  ) {
    throw new Error(`GitHub pull request repository ${source} is malformed`);
  }
  const canonicalOwner = owner.toLowerCase();
  const canonicalName = name.toLowerCase();
  return {
    owner: canonicalOwner,
    name: canonicalName,
    nameWithOwner: `${canonicalOwner}/${canonicalName}`,
    source,
  };
}

function buildIssueFixEvidenceBatchQuery(size: number): string {
  const vars = Array.from({ length: size }, (_, idx) => [
    `$number${idx}: Int!`,
    `$closedByFirst${idx}: Int!`,
    `$stateFirst${idx}: Int!`,
    `$referenceFirst${idx}: Int!`,
  ].join(', ')).join(', ');
  const fields = Array.from({ length: size }, (_, idx) => `
    issue${idx}: issue(number: $number${idx}) {
      id
      __typename
      number
      state
      updatedAt
	      closedByPullRequestsReferences(first: $closedByFirst${idx}, includeClosedPrs: true) {
          totalCount
	        nodes {
	          number title url state merged mergedAt baseRefName
	          repository { name nameWithOwner url owner { login } }
	          mergeCommit { oid }
	        }
        pageInfo { hasNextPage endCursor }
      }
      stateEvents: timelineItems(first: $stateFirst${idx}, itemTypes: [CLOSED_EVENT, REOPENED_EVENT]) {
        totalCount
        nodes {
          __typename
          ... on ClosedEvent {
            id createdAt stateReason actor { __typename login ... on Node { id } }
            closer {
              __typename
              ... on Node { id }
	              ... on PullRequest {
	                number title url state merged mergedAt baseRefName
	                repository { name nameWithOwner url owner { login } }
	                mergeCommit { oid }
	              }
              ... on Commit { oid committedDate url }
            }
          }
          ... on ReopenedEvent {
            id createdAt actor { __typename login ... on Node { id } }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
      referenceEvents: timelineItems(first: $referenceFirst${idx}, itemTypes: [CROSS_REFERENCED_EVENT, REFERENCED_EVENT]) {
        totalCount
        nodes {
          __typename
          ... on CrossReferencedEvent {
            id createdAt willCloseTarget
            source {
              __typename
	              ... on PullRequest {
	                number title url state merged mergedAt baseRefName
	                repository { name nameWithOwner url owner { login } }
	                mergeCommit { oid }
	              }
            }
          }
          ... on ReferencedEvent {
            id createdAt isCrossRepository isDirectReference actor { login }
            commit { oid committedDate url messageHeadline }
            commitRepository {
              name
              nameWithOwner
              owner { login }
            }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }`).join('\n');
  return `query IssueFixEvidence($owner: String!, $repo: String!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      id
      ${fields}
    }
  }`;
}

function buildIssueClosedByPrRefsQuery(): string {
  return `query IssueClosedByPrRefs($owner: String!, $repo: String!, $number: Int!, $first: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      id
      issue(number: $number) {
        id
        __typename
        number
        state
        updatedAt
        closedByPullRequestsReferences(first: $first, after: $after, includeClosedPrs: true) {
          totalCount
	          nodes {
	            number title url state merged mergedAt baseRefName
	            repository { name nameWithOwner url owner { login } }
	            mergeCommit { oid }
	          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }`;
}

function buildIssueStateTimelineQuery(): string {
  return `query IssueStateTimeline($owner: String!, $repo: String!, $number: Int!, $first: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      id
      issue(number: $number) {
        id
        __typename
        number
        state
        updatedAt
        stateEvents: timelineItems(first: $first, after: $after, itemTypes: [CLOSED_EVENT, REOPENED_EVENT]) {
          totalCount
          nodes {
            __typename
            ... on ClosedEvent {
              id createdAt stateReason actor { __typename login ... on Node { id } }
              closer {
                __typename
                ... on Node { id }
	                ... on PullRequest {
	                  number title url state merged mergedAt baseRefName
	                  repository { name nameWithOwner url owner { login } }
	                  mergeCommit { oid }
	                }
                ... on Commit { oid committedDate url }
              }
            }
            ... on ReopenedEvent {
              id createdAt actor { __typename login ... on Node { id } }
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }`;
}

function buildIssueReferenceTimelineQuery(): string {
  return `query IssueReferenceTimeline($owner: String!, $repo: String!, $number: Int!, $first: Int!, $after: String) {
    repository(owner: $owner, name: $repo) {
      id
      issue(number: $number) {
        id
        __typename
        number
        state
        updatedAt
        referenceEvents: timelineItems(first: $first, after: $after, itemTypes: [CROSS_REFERENCED_EVENT, REFERENCED_EVENT]) {
          totalCount
          nodes {
            __typename
            ... on CrossReferencedEvent {
              id createdAt willCloseTarget
              source {
                __typename
	                ... on PullRequest {
	                  number title url state merged mergedAt baseRefName
	                  repository { name nameWithOwner url owner { login } }
	                  mergeCommit { oid }
	                }
              }
            }
            ... on ReferencedEvent {
              id createdAt isCrossRepository isDirectReference actor { login }
              commit { oid committedDate url messageHeadline }
              commitRepository {
                name
                nameWithOwner
                owner { login }
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
	      repository { name nameWithOwner url owner { login } }
	      mergeCommit { oid }
	    }`).join('\n');
  return `query PullRequestFixes($owner: String!, $repo: String!, ${vars}) {
    repository(owner: $owner, name: $repo) {
      ${fields}
    }
  }`;
}

// Repository-owned security advisories, including every vulnerable package row.
export interface GhAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  state: 'published' | 'closed' | 'withdrawn' | 'triage' | 'draft';
  published_at: string | null;
  withdrawn_at: string | null;
  updated_at: string | null;
  html_url: string;
  vulnerabilities: Array<{
    package: { ecosystem: string | null; name: string | null } | null;
    vulnerable_version_range: string | null;
    patched_versions: string | null;
  }>;
}

export interface GhAdvisoryCatalogMetadata {
  exhausted: boolean;
  stabilized: boolean;
  totalCount: number | null;
  nodeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  digest: string;
  identityDigest: string;
  completeness: {
    terminalPageProven: boolean;
    terminalPageEvidence:
      | 'link-exhausted'
      | 'unproven-no-link';
    terminalPageLinkHeaderPresent: boolean;
    remoteTotalCount: null;
    enumeratedCount: number;
    crossOrderVerified: true;
    boundaryEvidence: {
      updatedAtDesc: GhAdvisoryCatalogBoundaryEvidence;
      updatedAtAsc: GhAdvisoryCatalogBoundaryEvidence;
    };
  };
  sourceOrder: 'UPDATED_AT_DESC';
}

export interface GhAdvisoryCatalogBoundaryEvidence {
  mode: 'single-page-no-link' | 'link-exhausted';
  linkHeaderPresent: boolean;
  pageCount: number;
  sweepCount: number;
}

export interface GhSourceRetrievalWindow {
  startedAt: string;
  completedAt: string;
}

export interface GhSecurityVulnerabilityRangeObservation {
  ghsaId: string;
  cveId: string | null;
  summary: string;
  severity: GhAdvisory['severity'];
  htmlUrl: string;
  publishedAt: string;
  withdrawnAt: string | null;
  ecosystem: typeof ADVISORY_TARGET_ECOSYSTEM;
  packageName: typeof ADVISORY_TARGET_PACKAGE;
  vulnerableVersionRange: string;
  firstPatchedVersion: string | null;
  updatedAt: string;
  identity: string;
}

export interface GhSecurityVulnerabilityCatalogObservation {
  source: 'graphql-security-vulnerabilities';
  retrieval: GhSourceRetrievalWindow;
  ecosystem: typeof ADVISORY_TARGET_ECOSYSTEM;
  packageName: typeof ADVISORY_TARGET_PACKAGE;
  exhausted: true;
  stabilized: true;
  totalCount: number;
  nodeCount: number;
  uniqueRangeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  digest: string;
  identityDigest: string;
  ranges: GhSecurityVulnerabilityRangeObservation[];
  rangeIdentities: string[];
}

export interface GhRepositoryAdvisoryCatalogObservation {
  source: 'repository-security-advisories-rest';
  retrieval: GhSourceRetrievalWindow;
  stabilized: true;
  exhausted: boolean;
  totalCount: number | null;
  observedAdvisoryCount: number;
  observedRangeCount: number;
  targetRangeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  digest: string;
  identityDigest: string;
  targetIdentityDigest: string;
  allRangeIdentities: string[];
  targetRangeIdentities: string[];
  advisories: GhAdvisory[];
  completeness: GhAdvisoryCatalogMetadata['completeness'];
}

export interface GhAdvisoryReconciliationInputs {
  target: {
    ecosystem: typeof ADVISORY_TARGET_ECOSYSTEM;
    packageName: typeof ADVISORY_TARGET_PACKAGE;
  };
  graphqlSecurityVulnerabilities: {
    totalCount: number;
    rangeCount: number;
    identityDigest: string;
    rangeIdentities: string[];
  };
  repositoryAdvisories: {
    totalCount: number | null;
    observedAdvisoryCount: number;
    targetRangeCount: number;
    identityDigest: string;
    rangeIdentities: string[];
    completenessProven: boolean;
  };
}

export interface GhAdvisorySourceObservations {
  securityVulnerabilities: GhSecurityVulnerabilityCatalogObservation;
  repositoryAdvisories: GhRepositoryAdvisoryCatalogObservation;
}

export interface GhAdvisoryCatalog {
  advisories: GhAdvisory[];
  metadata: GhAdvisoryCatalogMetadata;
  observations: GhAdvisorySourceObservations;
  reconciliation: GhAdvisoryReconciliationInputs;
}

export interface AdvisoryCatalogFetchOptions {
  request?: RepositorySecurityAdvisoryPageRequest;
  graphqlRequest?: GraphqlRequest;
  maxPagesPerConnection?: number;
  captureNow?: () => string;
  signal?: AbortSignal;
}

interface AdvisoryCatalogSweep {
  advisories: GhAdvisory[];
  totalCount: number;
  pageCount: number;
  digest: string;
  identityDigest: string;
  boundaryCompleteness: {
    terminal: boolean;
    proven: boolean;
    mode: GhAdvisoryCatalogBoundaryEvidence['mode'];
    linkHeaderPresent: boolean;
  };
}

interface AdvisoryCatalogSweepFetchOptions extends AdvisoryCatalogFetchOptions {
  direction?: RepositorySecurityAdvisoryDirection;
}

interface StabilizedAdvisoryCatalogSweep {
  sweep: AdvisoryCatalogSweep;
  pagesFetched: number;
  sweepCount: number;
  retrieval: GhSourceRetrievalWindow;
}

interface SecurityVulnerabilitySweep {
  ranges: GhSecurityVulnerabilityRangeObservation[];
  totalCount: number;
  pageCount: number;
  digest: string;
  identityDigest: string;
  paginationDigest: string;
}

interface StabilizedSecurityVulnerabilitySweep {
  sweep: SecurityVulnerabilitySweep;
  pagesFetched: number;
  sweepCount: number;
  retrieval: GhSourceRetrievalWindow;
}

function advisorySourceCaptureTimestamp(
  captureNow: AdvisoryCatalogFetchOptions['captureNow'],
): string {
  const raw = (captureNow ?? (() => new Date().toISOString()))();
  const timestampMs = Date.parse(raw);
  if (!Number.isFinite(timestampMs)) {
    throw new Error(
      `GitHub advisory source capture clock returned invalid timestamp ${JSON.stringify(raw)}`,
    );
  }
  return new Date(timestampMs).toISOString();
}

function advisorySourceRetrievalWindow(
  startedAt: string,
  completedAt: string,
): GhSourceRetrievalWindow {
  const startedAtMs = Date.parse(startedAt);
  const completedAtMs = Date.parse(completedAt);
  if (
    !Number.isFinite(startedAtMs) ||
    !Number.isFinite(completedAtMs) ||
    completedAtMs < startedAtMs
  ) {
    throw new Error(
      `GitHub advisory source retrieval window is invalid ` +
      `(${JSON.stringify(startedAt)}..${JSON.stringify(completedAt)})`,
    );
  }
  return {
    startedAt: new Date(startedAtMs).toISOString(),
    completedAt: new Date(completedAtMs).toISOString(),
  };
}

function mergeAdvisorySourceRetrievalWindows(
  ...windows: GhSourceRetrievalWindow[]
): GhSourceRetrievalWindow {
  if (windows.length === 0) {
    throw new Error('GitHub advisory source retrieval windows are missing');
  }
  const startedAt = Math.min(...windows.map((window) => Date.parse(window.startedAt)));
  const completedAt = Math.max(...windows.map((window) => Date.parse(window.completedAt)));
  if (!Number.isFinite(startedAt) || !Number.isFinite(completedAt)) {
    throw new Error('GitHub advisory source retrieval windows contain an invalid timestamp');
  }
  return advisorySourceRetrievalWindow(
    new Date(startedAt).toISOString(),
    new Date(completedAt).toISOString(),
  );
}

const REPOSITORY_ADVISORY_SEVERITIES = new Set([
  'low',
  'medium',
  'high',
  'critical',
]);

function normalizedAdvisoryText(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

function canonicalAdvisoryRangeIdentityParts(
  ghsaId: string,
  ecosystem: string | null | undefined,
  packageName: string | null | undefined,
  vulnerableVersionRange: string | null | undefined,
): string {
  return [
    ghsaId,
    String(ecosystem ?? '').trim().toLowerCase(),
    String(packageName ?? '').trim().toLowerCase(),
    normalizedAdvisoryText(String(vulnerableVersionRange ?? '')),
  ].map((part) => encodeURIComponent(part)).join(':');
}

function canonicalAdvisoryRangeIdentity(
  ghsaId: string,
  vulnerability: GhAdvisory['vulnerabilities'][number],
): string {
  return canonicalAdvisoryRangeIdentityParts(
    ghsaId,
    String(vulnerability.package?.ecosystem ?? '').trim().toLowerCase(),
    String(vulnerability.package?.name ?? '').trim().toLowerCase(),
    normalizedAdvisoryText(String(vulnerability.vulnerable_version_range ?? '')),
  );
}

function buildSecurityVulnerabilitiesQuery(): string {
  return `query SecurityVulnerabilities(
    $after: String
    $first: Int!
    $package: String!
  ) {
    securityVulnerabilities(
      ecosystem: NPM
      package: $package
      first: $first
      after: $after
      orderBy: { field: UPDATED_AT, direction: ASC }
    ) {
      totalCount
      nodes {
        advisory {
          ghsaId
          identifiers { type value }
          permalink
          publishedAt
          severity
          summary
          withdrawnAt
        }
        package { ecosystem name }
        vulnerableVersionRange
        firstPatchedVersion { identifier }
        updatedAt
      }
      pageInfo { hasNextPage endCursor }
    }
  }`;
}

function requireAdvisoryGhsaId(value: unknown, context: string): string {
  if (
    typeof value !== 'string' ||
    !/^GHSA-[23456789cfghjmpqrvwxy]{4}-[23456789cfghjmpqrvwxy]{4}-[23456789cfghjmpqrvwxy]{4}$/.test(
      value,
    )
  ) {
    throw new Error(`GitHub ${context} returned invalid GHSA id`);
  }
  return value;
}

function requireAdvisoryTimestamp(
  value: unknown,
  field: string,
  context: string,
  nullable: boolean,
): string | null {
  if (value == null && nullable) return null;
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    !Number.isFinite(Date.parse(value))
  ) {
    throw new Error(`GitHub repository ${context} returned invalid ${field}`);
  }
  return value;
}

function mapRepositorySecurityAdvisory(
  node: RepositorySecurityAdvisoryNode | null,
  context: string,
): MappedRepositorySecurityAdvisory {
  if (!node || typeof node !== 'object') {
    throw new Error(`GitHub repository ${context} returned null advisory`);
  }
  const ghsaId = requireAdvisoryGhsaId(node.ghsa_id, `repository ${context}`);
  const cveId = node.cve_id == null
    ? null
    : typeof node.cve_id === 'string' && /^CVE-\d{4}-\d{4,}$/.test(node.cve_id)
      ? node.cve_id
      : null;
  if (node.cve_id != null && cveId == null) {
    throw new Error(`GitHub repository ${context} returned invalid CVE id for ${ghsaId}`);
  }
  if (typeof node.summary !== 'string' || node.summary.trim().length === 0) {
    throw new Error(`GitHub repository ${context} returned missing summary for ${ghsaId}`);
  }
  if (typeof node.severity !== 'string' || !REPOSITORY_ADVISORY_SEVERITIES.has(node.severity)) {
    throw new Error(
      `GitHub repository ${context} returned invalid severity ${JSON.stringify(node.severity)} for ${ghsaId}`,
    );
  }
  if (node.state !== 'published') {
    throw new Error(
      `GitHub repository ${context} returned non-published state ${JSON.stringify(node.state)} for ${ghsaId}`,
    );
  }
  if (
    typeof node.html_url !== 'string' ||
    node.html_url.trim() !== node.html_url ||
    node.html_url.length === 0
  ) {
    throw new Error(`GitHub repository ${context} returned missing HTML URL for ${ghsaId}`);
  }
  let htmlUrl: URL;
  try {
    htmlUrl = new URL(node.html_url);
  } catch {
    throw new Error(`GitHub repository ${context} returned invalid HTML URL for ${ghsaId}`);
  }
  if (
    htmlUrl.origin !== 'https://github.com' ||
    !htmlUrl.pathname.endsWith(`/security/advisories/${ghsaId}`)
  ) {
    throw new Error(`GitHub repository ${context} returned inconsistent HTML URL for ${ghsaId}`);
  }

  const updatedAt = requireAdvisoryTimestamp(node.updated_at, 'updated_at', context, false) as string;
  const publishedAt = requireAdvisoryTimestamp(
    node.published_at,
    'published_at',
    context,
    true,
  );
  const withdrawnAt = requireAdvisoryTimestamp(
    node.withdrawn_at,
    'withdrawn_at',
    context,
    true,
  );
  if (publishedAt == null) {
    throw new Error(`GitHub repository ${context} returned published advisory ${ghsaId} without published_at`);
  }
  if (Date.parse(updatedAt) < Date.parse(publishedAt)) {
    throw new Error(`GitHub repository ${context} returned updated_at before published_at for ${ghsaId}`);
  }
  if (
    withdrawnAt != null &&
    (
      Date.parse(withdrawnAt) < Date.parse(publishedAt) ||
      Date.parse(updatedAt) < Date.parse(withdrawnAt)
    )
  ) {
    throw new Error(`GitHub repository ${context} returned inconsistent withdrawal time for ${ghsaId}`);
  }
  const state: GhAdvisory['state'] = withdrawnAt == null ? 'published' : 'withdrawn';

  if (!Array.isArray(node.identifiers)) {
    throw new Error(`GitHub repository ${context} returned missing identifiers for ${ghsaId}`);
  }
  const identifiers = node.identifiers.map((identifier, index) => {
    if (
      !identifier ||
      typeof identifier.type !== 'string' ||
      typeof identifier.value !== 'string' ||
      !['GHSA', 'CVE'].includes(identifier.type)
    ) {
      throw new Error(
        `GitHub repository ${context} returned invalid identifier ${index} for ${ghsaId}`,
      );
    }
    return {
      type: identifier.type,
      value: identifier.value,
    };
  });
  const identifierKeys = identifiers.map((identifier) => `${identifier.type}\0${identifier.value}`);
  if (new Set(identifierKeys).size !== identifierKeys.length) {
    throw new Error(`GitHub repository ${context} returned duplicate identifiers for ${ghsaId}`);
  }
  const ghsaIdentifiers = identifiers.filter((identifier) =>
    identifier.type === 'GHSA' && identifier.value === ghsaId);
  const cveIdentifiers = identifiers.filter((identifier) =>
    identifier.type === 'CVE' && identifier.value === cveId);
  if (
    ghsaIdentifiers.length !== 1 ||
    cveIdentifiers.length !== (cveId == null ? 0 : 1) ||
    identifiers.length !== (cveId == null ? 1 : 2)
  ) {
    throw new Error(`GitHub repository ${context} returned inconsistent GHSA identifier for ${ghsaId}`);
  }

  if (!Array.isArray(node.vulnerabilities) || node.vulnerabilities.length === 0) {
    throw new Error(`GitHub repository ${context} returned no vulnerability rows for ${ghsaId}`);
  }
  const seenVulnerabilityIdentities = new Set<string>();
  const vulnerabilities = node.vulnerabilities.map((vulnerability, index) => {
    if (!vulnerability || typeof vulnerability !== 'object') {
      throw new Error(
        `GitHub repository ${context} returned null vulnerability ${index} for ${ghsaId}`,
      );
    }
    const rawPackage = vulnerability.package;
    const ecosystem = rawPackage?.ecosystem ?? null;
    const packageName = rawPackage?.name ?? null;
    if (
      (rawPackage != null && typeof rawPackage !== 'object') ||
      (ecosystem != null && typeof ecosystem !== 'string') ||
      (packageName != null && typeof packageName !== 'string')
    ) {
      throw new Error(
        `GitHub repository ${context} returned invalid package identity in vulnerability ` +
          `${index} for ${ghsaId}`,
      );
    }
    const range = vulnerability.vulnerable_version_range;
    if (range != null && typeof range !== 'string') {
      throw new Error(
        `GitHub repository ${context} returned invalid vulnerable version range in ` +
          `vulnerability ${index} for ${ghsaId}`,
      );
    }
    if (
      vulnerability.patched_versions != null &&
      typeof vulnerability.patched_versions !== 'string'
    ) {
      throw new Error(
        `GitHub repository ${context} returned invalid patched versions in vulnerability ` +
          `${index} for ${ghsaId}`,
      );
    }
    const mapped: GhAdvisory['vulnerabilities'][number] = {
      package: rawPackage == null ? null : { ecosystem, name: packageName },
      vulnerable_version_range: range,
      patched_versions: vulnerability.patched_versions,
    };
    const identity = canonicalAdvisoryRangeIdentity(ghsaId, mapped);
    if (seenVulnerabilityIdentities.has(identity)) {
      throw new Error(
        `GitHub repository ${context} returned duplicate advisory range identity ${identity}`,
      );
    }
    seenVulnerabilityIdentities.add(identity);
    return mapped;
  });

  return {
    advisory: {
      ghsa_id: ghsaId,
      cve_id: cveId,
      summary: node.summary,
      severity: node.severity as GhAdvisory['severity'],
      state,
      published_at: publishedAt,
      withdrawn_at: withdrawnAt,
      updated_at: updatedAt,
      html_url: node.html_url,
      vulnerabilities,
    },
    updatedAt,
  };
}

function mapRepositorySecurityAdvisories(
  nodes: Array<RepositorySecurityAdvisoryNode | null>,
  context = 'security advisories',
): MappedRepositorySecurityAdvisory[] {
  return nodes.map((node, index) =>
    mapRepositorySecurityAdvisory(node, `${context} node ${index}`));
}

function mapSecurityVulnerability(
  node: SecurityVulnerabilityNode | null,
  context: string,
): GhSecurityVulnerabilityRangeObservation {
  if (!node || typeof node !== 'object') {
    throw new Error(`GitHub GraphQL ${context} returned null vulnerability`);
  }
  const ghsaId = requireAdvisoryGhsaId(
    node.advisory?.ghsaId,
    `GraphQL ${context}`,
  );
  const advisory = node.advisory;
  if (!advisory) {
    throw new Error(`GitHub GraphQL ${context} returned missing advisory metadata`);
  }
  if (!Array.isArray(advisory.identifiers)) {
    throw new Error(`GitHub GraphQL ${context} returned missing advisory identifiers`);
  }
  const identifiers = advisory.identifiers.map((identifier, index) => {
    if (
      !identifier ||
      typeof identifier.type !== 'string' ||
      typeof identifier.value !== 'string' ||
      !['GHSA', 'CVE'].includes(identifier.type)
    ) {
      throw new Error(
        `GitHub GraphQL ${context} returned invalid advisory identifier ${index}`,
      );
    }
    return identifier;
  });
  const identifierKeys = identifiers.map((identifier) =>
    `${identifier.type}\0${identifier.value}`);
  if (new Set(identifierKeys).size !== identifierKeys.length) {
    throw new Error(`GitHub GraphQL ${context} returned duplicate advisory identifiers`);
  }
  const ghsaIdentifiers = identifiers.filter((identifier) =>
    identifier.type === 'GHSA' && identifier.value === ghsaId);
  const cveIdentifiers = identifiers.filter((identifier) => identifier.type === 'CVE');
  if (
    ghsaIdentifiers.length !== 1 ||
    cveIdentifiers.length > 1 ||
    identifiers.length !== 1 + cveIdentifiers.length
  ) {
    throw new Error(`GitHub GraphQL ${context} returned inconsistent advisory identifiers`);
  }
  const cveId = cveIdentifiers[0]?.value ?? null;
  if (cveId != null && !/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
    throw new Error(`GitHub GraphQL ${context} returned invalid advisory CVE id`);
  }
  if (typeof advisory.summary !== 'string' || advisory.summary.trim().length === 0) {
    throw new Error(`GitHub GraphQL ${context} returned missing advisory summary`);
  }
  const severityByGraphqlValue: Record<string, GhAdvisory['severity']> = {
    LOW: 'low',
    MODERATE: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical',
  };
  const severity = severityByGraphqlValue[advisory.severity];
  if (!severity) {
    throw new Error(
      `GitHub GraphQL ${context} returned unsupported advisory severity ` +
        JSON.stringify(advisory.severity),
    );
  }
  const publishedAt = requireAdvisoryTimestamp(
    advisory.publishedAt,
    'publishedAt',
    `GraphQL ${context}`,
    false,
  ) as string;
  const withdrawnAt = requireAdvisoryTimestamp(
    advisory.withdrawnAt,
    'withdrawnAt',
    `GraphQL ${context}`,
    true,
  );
  if (
    withdrawnAt != null &&
    Date.parse(withdrawnAt) < Date.parse(publishedAt)
  ) {
    throw new Error(
      `GitHub GraphQL ${context} returned withdrawnAt before advisory publication`,
    );
  }
  if (
    typeof advisory.permalink !== 'string' ||
    advisory.permalink.trim() !== advisory.permalink
  ) {
    throw new Error(`GitHub GraphQL ${context} returned invalid advisory permalink`);
  }
  let htmlUrl: URL;
  try {
    htmlUrl = new URL(advisory.permalink);
  } catch {
    throw new Error(`GitHub GraphQL ${context} returned invalid advisory permalink`);
  }
  if (
    htmlUrl.origin !== 'https://github.com' ||
    htmlUrl.pathname !== `/advisories/${ghsaId}` ||
    htmlUrl.search ||
    htmlUrl.hash
  ) {
    throw new Error(`GitHub GraphQL ${context} returned inconsistent advisory permalink`);
  }
  const packageName = node.package?.name;
  if (
    node.package?.ecosystem !== ADVISORY_TARGET_GRAPHQL_ECOSYSTEM ||
    typeof packageName !== 'string' ||
    packageName.trim() !== packageName ||
    packageName.toLowerCase() !== ADVISORY_TARGET_PACKAGE
  ) {
    throw new Error(
      `GitHub GraphQL ${context} returned package ` +
        `${JSON.stringify(node.package?.ecosystem)}:${JSON.stringify(node.package?.name)} ` +
        `outside ${ADVISORY_TARGET_GRAPHQL_ECOSYSTEM}:${ADVISORY_TARGET_PACKAGE}`,
    );
  }
  const vulnerableVersionRange = node.vulnerableVersionRange;
  if (
    typeof vulnerableVersionRange !== 'string' ||
    vulnerableVersionRange.trim().length === 0
  ) {
    throw new Error(`GitHub GraphQL ${context} returned missing vulnerable version range`);
  }
  const firstPatchedVersion = node.firstPatchedVersion == null
    ? null
    : node.firstPatchedVersion.identifier;
  if (
    firstPatchedVersion != null &&
    (
      typeof firstPatchedVersion !== 'string' ||
      firstPatchedVersion.length === 0 ||
      firstPatchedVersion.trim() !== firstPatchedVersion
    )
  ) {
    throw new Error(`GitHub GraphQL ${context} returned invalid first patched version`);
  }
  if (
    typeof node.updatedAt !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(node.updatedAt) ||
    !Number.isFinite(Date.parse(node.updatedAt))
  ) {
    throw new Error(`GitHub GraphQL ${context} returned invalid updatedAt`);
  }
  if (Date.parse(node.updatedAt) < Date.parse(withdrawnAt ?? publishedAt)) {
    throw new Error(
      `GitHub GraphQL ${context} returned updatedAt before its latest advisory state`,
    );
  }
  return {
    ghsaId,
    cveId,
    summary: advisory.summary,
    severity,
    htmlUrl: advisory.permalink,
    publishedAt,
    withdrawnAt,
    ecosystem: ADVISORY_TARGET_ECOSYSTEM,
    packageName: ADVISORY_TARGET_PACKAGE,
    vulnerableVersionRange,
    firstPatchedVersion,
    updatedAt: node.updatedAt,
    identity: canonicalAdvisoryRangeIdentityParts(
      ghsaId,
      ADVISORY_TARGET_ECOSYSTEM,
      ADVISORY_TARGET_PACKAGE,
      vulnerableVersionRange,
    ),
  };
}

function canonicalRangeIdentityList(
  identities: string[],
  context: string,
): string[] {
  if (identities.some((identity) =>
    typeof identity !== 'string' || identity.length === 0 || identity.trim() !== identity)) {
    throw new Error(`GitHub ${context} received invalid canonical range identity`);
  }
  const sorted = identities.slice().sort(compareBinary);
  if (new Set(sorted).size !== sorted.length) {
    throw new Error(`GitHub ${context} received duplicate canonical range identity`);
  }
  return sorted;
}

function canonicalRangeIdentityDigest(
  identities: string[],
  context: string,
): string {
  return createHash('sha256')
    .update(JSON.stringify(canonicalRangeIdentityList(identities, context)))
    .digest('hex');
}

function canonicalSecurityVulnerabilityDigest(
  totalCount: number,
  ranges: GhSecurityVulnerabilityRangeObservation[],
): string {
  if (!Number.isInteger(totalCount) || totalCount < 0 || totalCount !== ranges.length) {
    throw new Error(
      `GitHub GraphQL security vulnerability digest count ${String(totalCount)} ` +
        `does not match ${ranges.length} ranges`,
    );
  }
  const identities = canonicalRangeIdentityList(
    ranges.map((range) => range.identity),
    'GraphQL security vulnerability digest',
  );
  const byIdentity = new Map(ranges.map((range) => [range.identity, range]));
  const canonical = identities.map((identity) => {
    const range = byIdentity.get(identity);
    if (!range) {
      throw new Error('GitHub GraphQL security vulnerability digest lost canonical range');
    }
    return [
      identity,
      range.cveId,
      range.summary,
      range.severity,
      range.htmlUrl,
      range.publishedAt,
      range.withdrawnAt,
      range.firstPatchedVersion,
      range.updatedAt,
    ];
  });
  return createHash('sha256')
    .update(JSON.stringify([totalCount, canonical]))
    .digest('hex');
}

async function fetchSecurityVulnerabilitySweep(
  options: AdvisoryCatalogFetchOptions = {},
): Promise<SecurityVulnerabilitySweep> {
  const request = options.graphqlRequest ?? gh;
  const maxPages = options.maxPagesPerConnection ?? GRAPHQL_MAX_PAGES_PER_CONNECTION;
  const guard = createGraphqlPaginationGuard(
    'securityVulnerabilities',
    maxPages,
  );
  const ranges: GhSecurityVulnerabilityRangeObservation[] = [];
  const identities = new Set<string>();
  const pageSequences: string[][] = [];
  let totalCount: number | null = null;
  let after: string | null = null;
  let pageCount = 0;
  let previousUpdatedAtMs = Number.NEGATIVE_INFINITY;

  for (;;) {
    const requestCursor = after;
    const data = await request<SecurityVulnerabilitiesQueryData>(
      buildSecurityVulnerabilitiesQuery(),
      {
        after,
        first: GRAPHQL_PAGE_SIZE,
        package: ADVISORY_TARGET_PACKAGE,
      },
      options.signal,
    );
    const connection = requireCountedGraphqlConnection(
      data.securityVulnerabilities,
      'securityVulnerabilities',
    );
    if (connection.nodes.length > GRAPHQL_PAGE_SIZE) {
      throw new Error(
        `GitHub GraphQL securityVulnerabilities returned ${connection.nodes.length} nodes ` +
          `for page size ${GRAPHQL_PAGE_SIZE}`,
      );
    }
    if (totalCount == null) {
      totalCount = connection.totalCount;
    } else if (connection.totalCount !== totalCount) {
      throw new Error(
        `GitHub GraphQL securityVulnerabilities totalCount changed within sweep ` +
          `from ${totalCount} to ${connection.totalCount}`,
      );
    }
    pageCount++;
    const mappedPage = connection.nodes.map((node, index) =>
      mapSecurityVulnerability(node, `securityVulnerabilities page ${pageCount} node ${index}`));
    for (const range of mappedPage) {
      const updatedAtMs = Date.parse(range.updatedAt);
      if (updatedAtMs < previousUpdatedAtMs) {
        throw new Error(
          `GitHub GraphQL securityVulnerabilities violated updatedAt ascending order at ` +
            range.identity,
        );
      }
      previousUpdatedAtMs = updatedAtMs;
      if (identities.has(range.identity)) {
        throw new Error(
          `GitHub GraphQL securityVulnerabilities returned duplicate canonical range ` +
            range.identity,
        );
      }
      identities.add(range.identity);
      ranges.push(range);
    }
    pageSequences.push(mappedPage.map((range) => range.identity));

    const nextCursor = guard.next(connection.pageInfo, requestCursor);
    if (nextCursor != null) {
      if (mappedPage.length === 0) {
        throw new Error(
          'GitHub GraphQL securityVulnerabilities returned an empty non-terminal page',
        );
      }
      after = nextCursor;
      continue;
    }
    if (ranges.length !== totalCount) {
      throw new Error(
        `GitHub GraphQL securityVulnerabilities terminal unique count ${ranges.length} ` +
          `did not match totalCount ${totalCount}`,
      );
    }
    break;
  }

  const provenTotalCount = totalCount ?? 0;
  return {
    ranges,
    totalCount: provenTotalCount,
    pageCount,
    digest: canonicalSecurityVulnerabilityDigest(provenTotalCount, ranges),
    identityDigest: canonicalRangeIdentityDigest(
      ranges.map((range) => range.identity),
      'GraphQL securityVulnerabilities',
    ),
    paginationDigest: createHash('sha256')
      .update(JSON.stringify(pageSequences))
      .digest('hex'),
  };
}

async function stabilizeSecurityVulnerabilitySweep(
  options: AdvisoryCatalogFetchOptions = {},
): Promise<StabilizedSecurityVulnerabilitySweep> {
  let previous: {
    sweep: SecurityVulnerabilitySweep;
    startedAt: string;
    completedAt: string;
  } | null = null;
  let pagesFetched = 0;
  for (
    let sweepCount = 1;
    sweepCount <= SECURITY_VULNERABILITY_MAX_SWEEPS;
    sweepCount++
  ) {
    const startedAt = advisorySourceCaptureTimestamp(options.captureNow);
    const currentSweep = await fetchSecurityVulnerabilitySweep(options);
    const completedAt = advisorySourceCaptureTimestamp(options.captureNow);
    const current = { sweep: currentSweep, startedAt, completedAt };
    pagesFetched += current.sweep.pageCount;
    if (
      previous?.sweep.totalCount === current.sweep.totalCount &&
      previous.sweep.pageCount === current.sweep.pageCount &&
      previous.sweep.identityDigest === current.sweep.identityDigest &&
      previous.sweep.digest === current.sweep.digest &&
      previous.sweep.paginationDigest === current.sweep.paginationDigest
    ) {
      return {
        sweep: current.sweep,
        pagesFetched,
        sweepCount,
        retrieval: advisorySourceRetrievalWindow(
          previous.startedAt,
          current.completedAt,
        ),
      };
    }
    previous = current;
  }
  throw new Error(
    `GitHub GraphQL securityVulnerabilities failed to stabilize after ` +
      `${SECURITY_VULNERABILITY_MAX_SWEEPS} complete sweeps`,
  );
}

function securityVulnerabilityCatalogObservation(
  stabilized: StabilizedSecurityVulnerabilitySweep,
): GhSecurityVulnerabilityCatalogObservation {
  const ranges = stabilized.sweep.ranges;
  return {
    source: 'graphql-security-vulnerabilities',
    retrieval: stabilized.retrieval,
    ecosystem: ADVISORY_TARGET_ECOSYSTEM,
    packageName: ADVISORY_TARGET_PACKAGE,
    exhausted: true,
    stabilized: true,
    totalCount: stabilized.sweep.totalCount,
    nodeCount: ranges.length,
    uniqueRangeCount: ranges.length,
    pageCount: stabilized.sweep.pageCount,
    pagesFetched: stabilized.pagesFetched,
    sweepCount: stabilized.sweepCount,
    digest: stabilized.sweep.digest,
    identityDigest: stabilized.sweep.identityDigest,
    ranges,
    rangeIdentities: canonicalRangeIdentityList(
      ranges.map((range) => range.identity),
      'GraphQL securityVulnerabilities observation',
    ),
  };
}

function canonicalAdvisoryCatalogDigest(
  totalCount: number,
  advisories: MappedRepositorySecurityAdvisory[],
): string {
  if (!Number.isInteger(totalCount) || totalCount < 0 || totalCount !== advisories.length) {
    throw new Error(
      `GitHub repository security advisory digest count ${String(totalCount)} ` +
        `does not match ${advisories.length} advisory nodes`,
    );
  }
  const ghsaIds = advisories.map(({ advisory }) => advisory.ghsa_id);
  if (new Set(ghsaIds).size !== ghsaIds.length) {
    throw new Error('GitHub repository security advisory digest received duplicate GHSA nodes');
  }
  return repositoryAdvisoryCatalogContentDigest(
    advisories.map(({ advisory }) => advisory),
  );
}

function canonicalAdvisoryCatalogIdentityDigest(
  totalCount: number,
  advisories: MappedRepositorySecurityAdvisory[],
): string {
  if (!Number.isInteger(totalCount) || totalCount < 0 || totalCount !== advisories.length) {
    throw new Error(
      `GitHub repository security advisory identity digest count ${String(totalCount)} ` +
        `does not match ${advisories.length} advisory nodes`,
    );
  }
  const ghsaIds = advisories.map(({ advisory }) => advisory.ghsa_id);
  if (new Set(ghsaIds).size !== ghsaIds.length) {
    throw new Error(
      'GitHub repository security advisory identity digest received duplicate GHSA nodes',
    );
  }
  const canonical = advisories
    .slice()
    .sort((left, right) => compareBinary(left.advisory.ghsa_id, right.advisory.ghsa_id))
    .map(({ advisory }) => [
      advisory.ghsa_id,
      advisory.vulnerabilities
        .map((vulnerability) =>
          canonicalAdvisoryRangeIdentity(advisory.ghsa_id, vulnerability))
        .sort(compareBinary),
    ]);
  return createHash('sha256')
    .update(JSON.stringify([totalCount, canonical]))
    .digest('hex');
}

function repositoryAdvisoryRangeIdentities(
  advisories: GhAdvisory[],
  targetOnly: boolean,
): string[] {
  const identities = advisories.flatMap((advisory) =>
    advisory.vulnerabilities.flatMap((vulnerability) => {
      const ecosystem = String(vulnerability.package?.ecosystem ?? '').trim().toLowerCase();
      const packageName = String(vulnerability.package?.name ?? '').trim().toLowerCase();
      if (
        targetOnly &&
        (
          ecosystem !== ADVISORY_TARGET_ECOSYSTEM ||
          packageName !== ADVISORY_TARGET_PACKAGE
        )
      ) {
        return [];
      }
      return [canonicalAdvisoryRangeIdentity(
        advisory.ghsa_id,
        vulnerability,
      )];
    }));
  return canonicalRangeIdentityList(
    identities,
    targetOnly
      ? 'repository advisory target ranges'
      : 'repository advisory ranges',
  );
}

function buildRepositorySecurityAdvisoriesUrl(input: {
  owner: string;
  repo: string;
  after: string | null;
  pageSize: number;
  direction?: RepositorySecurityAdvisoryDirection;
}): string {
  if (!input.owner.trim() || input.owner.trim() !== input.owner) {
    throw new Error('GitHub repository security advisory owner must be non-empty and canonical');
  }
  if (!input.repo.trim() || input.repo.trim() !== input.repo) {
    throw new Error('GitHub repository security advisory repo must be non-empty and canonical');
  }
  if (input.pageSize !== 100) {
    throw new Error('GitHub repository security advisory page size must be exactly 100');
  }
  if (
    input.after !== null &&
    (
      typeof input.after !== 'string' ||
      input.after.length === 0 ||
      input.after.trim() !== input.after
    )
  ) {
    throw new Error('GitHub repository security advisory cursor must be null or a canonical string');
  }
  const direction = input.direction ?? 'desc';
  if (!['asc', 'desc'].includes(direction)) {
    throw new Error('GitHub repository security advisory direction must be asc or desc');
  }
  const url = new URL(
    `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}/security-advisories`,
    'https://api.github.com',
  );
  url.searchParams.set('state', 'published');
  url.searchParams.set('sort', 'updated');
  url.searchParams.set('direction', direction);
  url.searchParams.set('per_page', String(input.pageSize));
  if (input.after) url.searchParams.set('after', input.after);
  return url.toString();
}

interface RepositorySecurityAdvisoryLink {
  url: URL;
  relation: 'next' | 'prev';
}

function isCanonicalRepositorySecurityAdvisoryLinkPath(pathname: string): boolean {
  if (/^\/repositories\/[1-9]\d*\/security-advisories$/.test(pathname)) {
    return true;
  }
  const namedRepository = /^\/repos\/([^/]+)\/([^/]+)\/security-advisories$/.exec(pathname);
  if (!namedRepository) return false;
  try {
    return namedRepository[1] === encodeURIComponent(decodeURIComponent(namedRepository[1])) &&
      namedRepository[2] === encodeURIComponent(decodeURIComponent(namedRepository[2]));
  } catch {
    return false;
  }
}

function repositorySecurityAdvisoryLinks(
  linkHeader: string | null,
  direction: RepositorySecurityAdvisoryDirection = 'desc',
): RepositorySecurityAdvisoryLink[] {
  if (linkHeader == null) return [];
  if (linkHeader.trim().length === 0) {
    throw new Error('GitHub repository security advisories returned an empty Link header');
  }
  const seenRelations = new Set<RepositorySecurityAdvisoryLink['relation']>();
  return linkHeader.split(',').map((rawEntry) => {
    const entry = rawEntry.trim();
    const match = /^<([^>]+)>;\s*rel="?([a-z]+)"?\s*$/.exec(entry);
    if (!match || !['next', 'prev'].includes(match[2])) {
      throw new Error('GitHub repository security advisories returned malformed pagination link');
    }
    let url: URL;
    try {
      url = new URL(match[1]);
    } catch {
      throw new Error('GitHub repository security advisories returned malformed pagination link URL');
    }
    if (
      url.origin !== 'https://api.github.com' ||
      url.username !== '' ||
      url.password !== '' ||
      url.hash !== ''
    ) {
      throw new Error('GitHub repository security advisories returned an off-origin pagination link');
    }
    if (!isCanonicalRepositorySecurityAdvisoryLinkPath(url.pathname)) {
      throw new Error('GitHub repository security advisories returned a non-canonical pagination link');
    }
    const allowedParameters = new Set([
      'state',
      'sort',
      'direction',
      'per_page',
      'after',
      'before',
    ]);
    for (const key of url.searchParams.keys()) {
      if (!allowedParameters.has(key)) {
        throw new Error(
          `GitHub repository security advisories pagination link has unexpected ${key} parameter`,
        );
      }
    }
    for (const [key, expected] of [
      ['state', 'published'],
      ['sort', 'updated'],
      ['direction', direction],
    ] as const) {
      const values = url.searchParams.getAll(key);
      if (values.length !== 1 || values[0] !== expected) {
        throw new Error(
          `GitHub repository security advisories pagination link has inconsistent ${key}`,
        );
      }
    }
    const perPageValues = url.searchParams.getAll('per_page');
    if (perPageValues.length !== 1 || perPageValues[0] !== '100') {
      throw new Error('GitHub repository security advisories pagination link has invalid per_page');
    }
    const relation = match[2] as RepositorySecurityAdvisoryLink['relation'];
    if (seenRelations.has(relation)) {
      throw new Error(
        `GitHub repository security advisories returned multiple ${relation} links`,
      );
    }
    seenRelations.add(relation);
    const cursorParameter = relation === 'next' ? 'after' : 'before';
    const oppositeCursorParameter = relation === 'next' ? 'before' : 'after';
    const cursors = url.searchParams.getAll(cursorParameter);
    if (
      cursors.length !== 1 ||
      !cursors[0] ||
      cursors[0].trim() !== cursors[0] ||
      url.searchParams.has(oppositeCursorParameter)
    ) {
      throw new Error(
        `GitHub repository security advisories ${relation} link is missing ` +
        `${cursorParameter} cursor`,
      );
    }
    return {
      url,
      relation,
    };
  });
}

function repositorySecurityAdvisoryNextCursor(
  linkHeader: string | null,
  direction: RepositorySecurityAdvisoryDirection = 'desc',
): string | null {
  const links = repositorySecurityAdvisoryLinks(linkHeader, direction);
  const nextEntries = links.filter((entry) => entry.relation === 'next');
  if (nextEntries.length === 0) return null;
  if (nextEntries.length !== 1) {
    throw new Error('GitHub repository security advisories returned multiple next links');
  }
  const url = nextEntries[0].url;
  const cursors = url.searchParams.getAll('after');
  const cursor = cursors[0];
  if (
    cursors.length !== 1 ||
    !cursor ||
    cursor.trim() !== cursor ||
    url.searchParams.has('before')
  ) {
    throw new Error('GitHub repository security advisories next link is missing after cursor');
  }
  return cursor;
}

function repositorySecurityAdvisoryPageCompleteness(
  linkHeader: string | null,
  nextCursor: string | null,
  direction: RepositorySecurityAdvisoryDirection = 'desc',
): RepositorySecurityAdvisoryPageCompleteness {
  const links = repositorySecurityAdvisoryLinks(linkHeader, direction);
  if (nextCursor != null) {
    return {
      terminal: false,
      proven: true,
      evidence: 'link',
      linkHeaderPresent: true,
    };
  }
  const terminalProven = links.some((link) => link.relation === 'prev');
  return {
    terminal: terminalProven,
    proven: terminalProven,
    evidence: terminalProven ? 'link' : 'missing-link',
    linkHeaderPresent: linkHeader != null,
  };
}

function repositorySecurityAdvisoryHeaders(): Record<string, string> {
  if (!config.github.token) {
    throw new Error(
      'GITHUB_TOKEN is required because repository security advisory requests must be authenticated',
    );
  }
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'openclaw-release-radar',
    Authorization: `Bearer ${config.github.token}`,
  };
}

interface RepositorySecurityAdvisoryRequesterOptions {
  fetchImpl?: typeof fetch;
  scheduler?: GraphqlRequestScheduler;
  sleep?: GithubSleep;
  now?: () => number;
  random?: () => number;
  requestTimeoutMs?: number;
  bodyTimeoutMs?: number;
  responseBodyMaxBytes?: number;
  errorBodyMaxBytes?: number;
  retryBaseMs?: number;
  retryMaxMs?: number;
  maxRetries?: number;
  requestHeaders?: () => Record<string, string>;
  warn?: (message: string) => void;
}

function createRepositorySecurityAdvisoryPageRequester(
  options: RepositorySecurityAdvisoryRequesterOptions = {},
): RepositorySecurityAdvisoryPageRequest {
  const fetchImpl = options.fetchImpl ?? fetch;
  const scheduler = options.scheduler ?? graphqlRequestLimiter;
  const sleeper = options.sleep ?? sleep;
  const now = options.now ?? Date.now;
  const random = options.random ?? Math.random;
  const requestTimeoutMs = options.requestTimeoutMs ?? GRAPHQL_REQUEST_TIMEOUT_MS;
  const bodyTimeoutMs = options.bodyTimeoutMs ?? GRAPHQL_BODY_TIMEOUT_MS;
  const responseBodyMaxBytes = options.responseBodyMaxBytes ?? GITHUB_RESPONSE_BODY_MAX_BYTES;
  const errorBodyMaxBytes = options.errorBodyMaxBytes ?? GITHUB_ERROR_BODY_MAX_BYTES;
  const retryBaseMs = options.retryBaseMs ?? config.github.graphql.retryBaseMs;
  const retryMaxMs = options.retryMaxMs ?? config.github.graphql.retryMaxMs;
  const maxRetries = options.maxRetries ?? 8;
  const requestHeaders = options.requestHeaders ?? repositorySecurityAdvisoryHeaders;
  const warn = options.warn ?? ((message: string) => console.warn(message));

  return async function requestRepositorySecurityAdvisoryPage(
    input: Parameters<RepositorySecurityAdvisoryPageRequest>[0],
  ): Promise<RepositorySecurityAdvisoryPage> {
    const url = buildRepositorySecurityAdvisoriesUrl(input);
    for (let attempt = 0; ; attempt++) {
      throwIfAborted(input.signal);
      let outcome:
        | { kind: 'body-error'; response: Response; error: unknown }
        | { kind: 'http-error'; response: Response; body: string; retryable: boolean; delay: number }
        | { kind: 'malformed'; body: string }
        | { kind: 'invalid-root' }
        | { kind: 'success'; page: RepositorySecurityAdvisoryPage };
      try {
        outcome = await scheduler.run(async () => {
          throwIfAborted(input.signal);
          const response = await fetchWithTimeout(
            fetchImpl,
            url,
            {
              method: 'GET',
              headers: requestHeaders(),
            },
            requestTimeoutMs,
            () => new Error(
              `GitHub repository security advisory request timed out after ${requestTimeoutMs}ms`,
            ),
            input.signal,
          );
          const exactSuccess = response.status === 200;
          let body: string;
          try {
            body = await readBoundedResponseBody(response, {
              timeoutMs: bodyTimeoutMs,
              maxBytes: exactSuccess ? responseBodyMaxBytes : errorBodyMaxBytes,
              label: `GitHub repository security advisory ` +
                `${exactSuccess ? 'response' : 'error response'} body`,
              createTimeoutError: () => new Error(
                `GitHub repository security advisory body timed out after ${bodyTimeoutMs}ms`,
              ),
              signal: input.signal,
            });
          } catch (error) {
            return { kind: 'body-error' as const, response, error };
          }

          if (!exactSuccess) {
            const classification = classifyHttpRetry(response, body);
            const delay = retryDelayMs(attempt, response, {
              baseMs: retryBaseMs,
              maxMs: retryMaxMs,
              random,
              now,
              fallbackMinMs: classification.secondaryRateLimited
                ? SECONDARY_RATE_LIMIT_FALLBACK_MS
                : 0,
            });
            if (classification.rateLimited) scheduler.noteRateLimit(delay);
            return {
              kind: 'http-error' as const,
              response,
              body,
              retryable: classification.retryable,
              delay,
            };
          }

          let parsed: unknown;
          try {
            parsed = JSON.parse(body);
          } catch {
            return { kind: 'malformed' as const, body };
          }
          if (!Array.isArray(parsed)) return { kind: 'invalid-root' as const };
          const linkHeader = response.headers.get('link');
          const nextCursor = repositorySecurityAdvisoryNextCursor(
            linkHeader,
            input.direction,
          );
          return {
            kind: 'success' as const,
            page: {
              nodes: parsed as Array<RepositorySecurityAdvisoryNode | null>,
              nextCursor,
              completeness: repositorySecurityAdvisoryPageCompleteness(
                linkHeader,
                nextCursor,
                input.direction,
              ),
            },
          };
        }, input.signal);
      } catch (error) {
        throwIfAborted(input.signal);
        if (attempt < maxRetries) {
          const delay = retryDelayMs(attempt, undefined, {
            baseMs: retryBaseMs,
            maxMs: retryMaxMs,
            random,
            now,
          });
          warn(
            `[github] repository advisory network error; retrying in ` +
              `${Math.round(delay / 1000)}s: ${(error as Error).message}`,
          );
          await sleepWithSignal(sleeper, delay, input.signal);
          continue;
        }
        throw error;
      }

      throwIfAborted(input.signal);
      if (outcome.kind === 'body-error') {
        throwIfAborted(input.signal);
        if (outcome.error instanceof GithubResponseBodyLimitError) throw outcome.error;
        if (attempt < maxRetries) {
          const delay = retryDelayMs(attempt, outcome.response, {
            baseMs: retryBaseMs,
            maxMs: retryMaxMs,
            random,
            now,
          });
          warn(
            `[github] repository advisory body error; retrying in ` +
              `${Math.round(delay / 1000)}s: ` +
              `${outcome.error instanceof Error ? outcome.error.message : String(outcome.error)}`,
          );
          await sleepWithSignal(sleeper, delay, input.signal);
          continue;
        }
        throw outcome.error;
      }

      if (outcome.kind === 'http-error') {
        if (outcome.retryable && attempt < maxRetries) {
          warn(
            `[github] repository advisory HTTP ${outcome.response.status}; retrying in ` +
              `${Math.round(outcome.delay / 1000)}s`,
          );
          await sleepWithSignal(sleeper, outcome.delay, input.signal);
          continue;
        }
        throw new Error(
          `GitHub repository security advisories HTTP ${outcome.response.status}: ` +
            `${outcome.body.slice(0, 300)}`,
        );
      }
      if (outcome.kind === 'malformed') {
        throw new Error(
          `GitHub repository security advisories returned non-JSON: ${outcome.body.slice(0, 300)}`,
        );
      }
      if (outcome.kind === 'invalid-root') {
        throw new Error('GitHub repository security advisories response root is not an array');
      }
      return outcome.page;
    }
  };
}

const requestRepositorySecurityAdvisoryPage =
  createRepositorySecurityAdvisoryPageRequester();

function repositorySecurityAdvisoryBoundaryCompleteness(
  page: RepositorySecurityAdvisoryPage,
  requestCursor: string | null,
  pageSize: number,
): AdvisoryCatalogSweep['boundaryCompleteness'] {
  const completeness = page.completeness;
  if (!completeness) {
    throw new Error(
      'GitHub repository security advisories terminal page completeness is unproven',
    );
  }
  if (
    completeness.evidence === 'link' &&
    completeness.proven === true &&
    completeness.terminal === true &&
    completeness.linkHeaderPresent === true
  ) {
    if (requestCursor === null) {
      throw new Error(
        'GitHub repository security advisories terminal Link evidence is not cursor-backed',
      );
    }
    return {
      terminal: true,
      proven: true,
      mode: 'link-exhausted',
      linkHeaderPresent: true,
    };
  }
  if (
    completeness.evidence === 'missing-link' &&
    completeness.proven === false &&
    completeness.terminal === false &&
    completeness.linkHeaderPresent === false &&
    requestCursor === null
  ) {
    if (page.nodes.length === pageSize) {
      throw new Error(
        `GitHub repository security advisories returned a full page of ${pageSize} ` +
        'without Link evidence; exhaustion is ambiguous',
      );
    }
    return {
      terminal: false,
      proven: false,
      mode: 'single-page-no-link',
      linkHeaderPresent: false,
    };
  }
  if (
    completeness.evidence === 'missing-link' &&
    requestCursor !== null
  ) {
    throw new Error(
      'GitHub repository security advisories terminal page after a cursor omitted Link evidence',
    );
  }
  throw new Error(
    'GitHub repository security advisories terminal page completeness evidence is inconsistent',
  );
}

async function fetchRepositorySecurityAdvisorySweep(
  options: AdvisoryCatalogSweepFetchOptions = {},
): Promise<AdvisoryCatalogSweep> {
  const request = options.request ?? requestRepositorySecurityAdvisoryPage;
  const maxPages = options.maxPagesPerConnection ?? GRAPHQL_MAX_PAGES_PER_CONNECTION;
  const direction = options.direction ?? 'desc';
  if (!Number.isInteger(maxPages) || maxPages <= 0) {
    throw new Error('GitHub repository security advisories max pages must be a positive integer');
  }
  const pageSize = 100;
  const advisories: MappedRepositorySecurityAdvisory[] = [];
  const advisoryIds = new Set<string>();
  const seenCursors = new Set<string>();
  let after: string | null = null;
  let pageCount = 0;
  let previousUpdatedAtMs = direction === 'desc'
    ? Number.POSITIVE_INFINITY
    : Number.NEGATIVE_INFINITY;
  let boundaryCompleteness: AdvisoryCatalogSweep['boundaryCompleteness'] | null = null;

  for (;;) {
    const requestCursor: string | null = after;
    const page = await request({
      owner: config.github.owner,
      repo: config.github.repo,
      after,
      pageSize,
      state: 'published',
      sort: 'updated',
      direction,
      signal: options.signal,
    });
    if (!page || typeof page !== 'object' || !Array.isArray(page.nodes)) {
      throw new Error('GitHub repository security advisories returned malformed page');
    }
    if (page.nodes.length > pageSize) {
      throw new Error(
        `GitHub repository security advisories returned ${page.nodes.length} nodes ` +
          `for page size ${pageSize}`,
      );
    }
    if (
      page.nextCursor !== null &&
      (
        typeof page.nextCursor !== 'string' ||
        page.nextCursor.length === 0 ||
        page.nextCursor.trim() !== page.nextCursor
      )
    ) {
      throw new Error('GitHub repository security advisories returned invalid next cursor');
    }
    const nextCursor = page.nextCursor;
    if (nextCursor != null) {
      if (!page.completeness) {
        throw new Error(
          'GitHub repository security advisories non-terminal page completeness evidence is missing',
        );
      }
      if (
        page.completeness.terminal ||
        !page.completeness.proven ||
        page.completeness.evidence !== 'link' ||
        !page.completeness.linkHeaderPresent
      ) {
        throw new Error(
          'GitHub repository security advisories non-terminal completeness evidence is inconsistent',
        );
      }
    }
    if (page.nodes.length === 0 && requestCursor !== null) {
      throw new Error('GitHub repository security advisories returned an empty page after a cursor');
    }
    const currentBoundaryCompleteness = nextCursor == null
      ? repositorySecurityAdvisoryBoundaryCompleteness(
          page,
          requestCursor,
          pageSize,
        )
      : null;
    pageCount++;
    const mappedPage = mapRepositorySecurityAdvisories(
      page.nodes,
      `security advisories page ${pageCount}`,
    );
    for (const mapped of mappedPage) {
      const updatedAtMs = Date.parse(mapped.updatedAt);
      const outOfOrder = direction === 'desc'
        ? updatedAtMs > previousUpdatedAtMs
        : updatedAtMs < previousUpdatedAtMs;
      if (outOfOrder) {
        throw new Error(
          `GitHub repository security advisories violated updated_at ${direction === 'desc'
            ? 'descending'
            : 'ascending'} order at ` +
            `${mapped.advisory.ghsa_id}`,
        );
      }
      previousUpdatedAtMs = updatedAtMs;
      if (advisoryIds.has(mapped.advisory.ghsa_id)) {
        throw new Error(
          `GitHub repository security advisories returned duplicate GHSA ` +
            `${mapped.advisory.ghsa_id}`,
        );
      }
      advisoryIds.add(mapped.advisory.ghsa_id);
      advisories.push(mapped);
    }

    if (!nextCursor) {
      boundaryCompleteness = currentBoundaryCompleteness;
      break;
    }
    if (page.nodes.length === 0) {
      throw new Error('GitHub repository security advisories returned an empty non-terminal page');
    }
    if (nextCursor === requestCursor || seenCursors.has(nextCursor)) {
      throw new Error(
        `GitHub repository security advisories repeated pagination cursor ${nextCursor}`,
      );
    }
    if (pageCount >= maxPages) {
      throw new Error(
        `GitHub repository security advisories exceeded ${maxPages} pages before pagination completed`,
      );
    }
    seenCursors.add(nextCursor);
    after = nextCursor;
  }

  if (!boundaryCompleteness) {
    throw new Error('GitHub repository security advisories ended without boundary evidence');
  }
  const totalCount = advisories.length;
  return {
    advisories: advisories.map(({ advisory }) => advisory),
    totalCount,
    pageCount,
    digest: canonicalAdvisoryCatalogDigest(totalCount, advisories),
    identityDigest: canonicalAdvisoryCatalogIdentityDigest(totalCount, advisories),
    boundaryCompleteness,
  };
}

async function stabilizeRepositorySecurityAdvisorySweep(
  options: AdvisoryCatalogFetchOptions,
  direction: RepositorySecurityAdvisoryDirection,
): Promise<StabilizedAdvisoryCatalogSweep> {
  let previous: {
    sweep: AdvisoryCatalogSweep;
    startedAt: string;
    completedAt: string;
  } | null = null;
  let pagesFetched = 0;

  for (let sweepCount = 1; sweepCount <= ADVISORY_CATALOG_MAX_SWEEPS; sweepCount++) {
    const startedAt = advisorySourceCaptureTimestamp(options.captureNow);
    const currentSweep = await fetchRepositorySecurityAdvisorySweep({
      ...options,
      direction,
    });
    const completedAt = advisorySourceCaptureTimestamp(options.captureNow);
    const current = { sweep: currentSweep, startedAt, completedAt };
    pagesFetched += current.sweep.pageCount;
    if (
      previous?.sweep.identityDigest === current.sweep.identityDigest &&
      previous.sweep.totalCount !== current.sweep.totalCount
    ) {
      throw new Error(
        `GitHub repository security advisory identity digest matched across impossible counts ` +
          `${previous.sweep.totalCount} and ${current.sweep.totalCount}`,
      );
    }
    if (
      previous?.sweep.totalCount === current.sweep.totalCount &&
      previous.sweep.identityDigest === current.sweep.identityDigest &&
      previous.sweep.digest === current.sweep.digest &&
      previous.sweep.boundaryCompleteness.terminal ===
        current.sweep.boundaryCompleteness.terminal &&
      previous.sweep.boundaryCompleteness.proven ===
        current.sweep.boundaryCompleteness.proven &&
      previous.sweep.boundaryCompleteness.mode ===
        current.sweep.boundaryCompleteness.mode &&
      previous.sweep.boundaryCompleteness.linkHeaderPresent ===
        current.sweep.boundaryCompleteness.linkHeaderPresent
    ) {
      return {
        sweep: current.sweep,
        pagesFetched,
        sweepCount,
        retrieval: advisorySourceRetrievalWindow(
          previous.startedAt,
          current.completedAt,
        ),
      };
    }
    previous = current;
  }

  throw new Error(
    `GitHub repository security advisories failed to stabilize after ` +
    `${ADVISORY_CATALOG_MAX_SWEEPS} complete sweeps in updated_at ${direction} order`,
  );
}

function advisoryCatalogBoundaryEvidence(
  stabilized: StabilizedAdvisoryCatalogSweep,
): GhAdvisoryCatalogBoundaryEvidence {
  return {
    mode: stabilized.sweep.boundaryCompleteness.mode,
    linkHeaderPresent: stabilized.sweep.boundaryCompleteness.linkHeaderPresent,
    pageCount: stabilized.sweep.pageCount,
    sweepCount: stabilized.sweepCount,
  };
}

function repositoryAdvisoryCompleteness(
  descending: StabilizedAdvisoryCatalogSweep,
  ascending: StabilizedAdvisoryCatalogSweep,
): GhAdvisoryCatalogMetadata['completeness'] {
  const terminalPageProven =
    descending.sweep.boundaryCompleteness.terminal &&
    descending.sweep.boundaryCompleteness.proven &&
    ascending.sweep.boundaryCompleteness.terminal &&
    ascending.sweep.boundaryCompleteness.proven;
  return {
    terminalPageProven,
    terminalPageEvidence: terminalPageProven
      ? 'link-exhausted'
      : 'unproven-no-link',
    terminalPageLinkHeaderPresent:
      descending.sweep.boundaryCompleteness.linkHeaderPresent &&
      ascending.sweep.boundaryCompleteness.linkHeaderPresent,
    remoteTotalCount: null,
    enumeratedCount: descending.sweep.totalCount,
    crossOrderVerified: true,
    boundaryEvidence: {
      updatedAtDesc: advisoryCatalogBoundaryEvidence(descending),
      updatedAtAsc: advisoryCatalogBoundaryEvidence(ascending),
    },
  };
}

function repositoryAdvisoryCatalogObservation(
  descending: StabilizedAdvisoryCatalogSweep,
  ascending: StabilizedAdvisoryCatalogSweep,
): GhRepositoryAdvisoryCatalogObservation {
  const descSweep = descending.sweep;
  const completeness = repositoryAdvisoryCompleteness(descending, ascending);
  const allRangeIdentities = repositoryAdvisoryRangeIdentities(
    descSweep.advisories,
    false,
  );
  const targetRangeIdentities = repositoryAdvisoryRangeIdentities(
    descSweep.advisories,
    true,
  );
  return {
    source: 'repository-security-advisories-rest',
    retrieval: mergeAdvisorySourceRetrievalWindows(
      descending.retrieval,
      ascending.retrieval,
    ),
    stabilized: true,
    exhausted: completeness.terminalPageProven,
    totalCount: completeness.terminalPageProven ? descSweep.totalCount : null,
    observedAdvisoryCount: descSweep.totalCount,
    observedRangeCount: allRangeIdentities.length,
    targetRangeCount: targetRangeIdentities.length,
    pageCount: descSweep.pageCount,
    pagesFetched: descending.pagesFetched + ascending.pagesFetched,
    sweepCount: descending.sweepCount + ascending.sweepCount,
    digest: descSweep.digest,
    identityDigest: descSweep.identityDigest,
    targetIdentityDigest: canonicalRangeIdentityDigest(
      targetRangeIdentities,
      'repository advisory target observation',
    ),
    allRangeIdentities,
    targetRangeIdentities,
    advisories: descSweep.advisories,
    completeness,
  };
}

export async function fetchSecurityAdvisorySourceObservations(
  options: AdvisoryCatalogFetchOptions = {},
): Promise<GhAdvisoryCatalog> {
  const [
    securityVulnerabilitySweep,
    descending,
    ascending,
  ] = await runCooperativeGroup([
    (groupSignal) => stabilizeSecurityVulnerabilitySweep({
      ...options,
      signal: groupSignal,
    }),
    (groupSignal) => stabilizeRepositorySecurityAdvisorySweep({
      ...options,
      signal: groupSignal,
    }, 'desc'),
    (groupSignal) => stabilizeRepositorySecurityAdvisorySweep({
      ...options,
      signal: groupSignal,
    }, 'asc'),
  ] as const, { signal: options.signal });
  const securityVulnerabilities = securityVulnerabilityCatalogObservation(
    securityVulnerabilitySweep,
  );
  const descSweep = descending.sweep;
  const ascSweep = ascending.sweep;

  if (descSweep.totalCount !== ascSweep.totalCount) {
    throw new Error(
      `GitHub repository security advisories cross-order count mismatch: ` +
        `updated_at desc enumerated ${descSweep.totalCount}, ` +
        `updated_at asc enumerated ${ascSweep.totalCount}`,
    );
  }
  if (descSweep.identityDigest !== ascSweep.identityDigest) {
    throw new Error(
      'GitHub repository security advisories cross-order advisory/range identity mismatch',
    );
  }
  if (descSweep.digest !== ascSweep.digest) {
    throw new Error(
      'GitHub repository security advisories cross-order canonical content mismatch',
    );
  }

  const repositoryAdvisories = repositoryAdvisoryCatalogObservation(
    descending,
    ascending,
  );
  return {
    advisories: descSweep.advisories,
    metadata: {
      exhausted: repositoryAdvisories.exhausted,
      stabilized: true,
      totalCount: repositoryAdvisories.totalCount,
      nodeCount: descSweep.advisories.length,
      pageCount: descSweep.pageCount,
      pagesFetched: repositoryAdvisories.pagesFetched,
      sweepCount: repositoryAdvisories.sweepCount,
      digest: descSweep.digest,
      identityDigest: descSweep.identityDigest,
      completeness: repositoryAdvisories.completeness,
      sourceOrder: 'UPDATED_AT_DESC',
    },
    observations: {
      securityVulnerabilities,
      repositoryAdvisories,
    },
    reconciliation: {
      target: {
        ecosystem: ADVISORY_TARGET_ECOSYSTEM,
        packageName: ADVISORY_TARGET_PACKAGE,
      },
      graphqlSecurityVulnerabilities: {
        totalCount: securityVulnerabilities.totalCount,
        rangeCount: securityVulnerabilities.uniqueRangeCount,
        identityDigest: securityVulnerabilities.identityDigest,
        rangeIdentities: securityVulnerabilities.rangeIdentities,
      },
      repositoryAdvisories: {
        totalCount: repositoryAdvisories.totalCount,
        observedAdvisoryCount: repositoryAdvisories.observedAdvisoryCount,
        targetRangeCount: repositoryAdvisories.targetRangeCount,
        identityDigest: repositoryAdvisories.targetIdentityDigest,
        rangeIdentities: repositoryAdvisories.targetRangeIdentities,
        completenessProven: repositoryAdvisories.completeness.terminalPageProven,
      },
    },
  };
}

export async function listSecurityAdvisories(
  options: AdvisoryCatalogFetchOptions = {},
): Promise<GhAdvisoryCatalog> {
  const catalog = await fetchSecurityAdvisorySourceObservations(options);
  if (!catalog.metadata.exhausted || catalog.metadata.totalCount == null) {
    throw new Error(
      'GitHub repository security advisory enumeration is unproven; ' +
        'compound source reconciliation is required before destructive use',
    );
  }
  return catalog;
}

/*
 * The public GitHub GraphQL schema does not expose Repository.securityAdvisories.
 * Repository-owned advisories and package-filtered securityVulnerabilities are
 * retained as separate source observations for downstream reconciliation.
 */

export const __githubTest = {
  buildRepositorySecurityAdvisoriesUrl,
  buildSecurityVulnerabilitiesQuery,
  buildReleasesQuery,
  buildIssuesQuery,
  buildReleaseCommitQuery,
  buildIssuesBatchQuery,
  buildIssueLabelsQuery,
  buildRepositoryCollaboratorsQuery,
  buildIssueFixEvidenceBatchQuery,
  buildIssueClosedByPrRefsQuery,
  buildIssueStateTimelineQuery,
  buildIssueReferenceTimelineQuery,
  buildPullRequestFixesBatchQuery,
  closureCommentCommitMentions,
  closureCommentPrMentions,
  closureProofCommentTrust,
  buildIssueCommentsBatchQuery,
  classifyReleaseCheckDisposition,
  classifyHttpRetry,
  countReleaseCheckContexts,
  createGraphqlPaginationGuard,
  createGraphqlRequestLimiter,
  createGraphqlRequester,
  createRepositorySecurityAdvisoryPageRequester,
  explicitRetryDelayMs,
  authorizeGithubReleaseCatalogPublication,
  validateGithubReleaseCatalogPublication,
  fetchReleaseCatalog,
  fetchReleaseCatalogSweep,
  githubReleaseCatalogActiveReleaseDigest,
  githubReleaseCatalogPublicationEvidence,
  fetchIssueCatalog,
  fetchIssueCatalogSweep,
  verifyIssueCatalogBoundary,
  fetchRepositoryCollaboratorPermissionSweep,
  fetchRepositorySecurityAdvisorySweep,
  fetchSecurityVulnerabilitySweep,
  graphqlErrorDetails,
  isRateLimitGraphqlError,
  isRetryableGraphqlError,
  listIssueCommentSnapshotsBatch,
  listIssueCommentsBatch,
  paginateIssues,
  missingIssueIndexesFromGraphqlError,
  retryDelayMs,
  shouldRetryGraphqlErrors,
  skipMissingIssueAliases,
  buildIssueLabelEventsBatchQuery,
  nextGraphqlPageCursor,
  mapComment,
  mapIssue,
  mapPullRequestFix,
  mapRelease,
  mapReleaseCheckContexts,
  mapRepositorySecurityAdvisories,
  mapSecurityVulnerability,
  normalizePrRepositoryIdentity,
  repositorySecurityAdvisoryNextCursor,
  repositorySecurityAdvisoryPageCompleteness,
  canonicalAdvisoryCatalogDigest,
  canonicalAdvisoryCatalogIdentityDigest,
  canonicalAdvisoryRangeIdentity,
  canonicalRangeIdentityDigest,
  canonicalIssueCatalogDigest,
  canonicalIssueContentDigest,
  canonicalIssueMembershipDigest,
  canonicalReleaseCatalogDigest,
  requireGraphqlConnection,
  finalizeIssueStateSnapshot,
  issueFixEvidenceSweepDigest,
  requireMatchingIssueFixEvidenceSweeps,
};
