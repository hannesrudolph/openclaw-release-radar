import { createHash } from 'node:crypto';
import type {
  GhIssue,
  GhIssueCatalog,
  GhIssueCatalogIssue,
  GhIssueCatalogMetadata,
} from './github';

export const ISSUE_CATALOG_SNAPSHOT_SCHEMA_VERSION = 1;
export const ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_VERSION = 2;
export const ISSUE_CATALOG_SNAPSHOT_SOURCE = 'github.repository.issues';
export const ISSUE_CATALOG_SNAPSHOT_SOURCE_ORDER = 'CREATED_AT_ASC';
export const ISSUE_CATALOG_SNAPSHOT_DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000;

const ISSUE_CATALOG_SNAPSHOT_ROW_FIELDS = [
  'node_id',
  'node_type',
  'number',
  'title',
  'body',
  'state',
  'user.id',
  'user.type',
  'user.login',
  'author_association',
  'created_at',
  'updated_at',
  'closed_at',
  'html_url',
  'comments',
  'reaction_total',
  'positive_reactions',
  'labels[].name',
] as const;

export const ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_DIGEST = createHash('sha256')
  .update(JSON.stringify([
    ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_VERSION,
    ISSUE_CATALOG_SNAPSHOT_ROW_FIELDS,
  ]))
  .digest('hex');

export interface CanonicalIssueMembershipRecord {
  nodeId: string;
  issue: Pick<GhIssue, 'number' | 'created_at'>;
}

export interface CanonicalIssueCatalogRecord extends CanonicalIssueMembershipRecord {
  nodeId: string;
  issue: GhIssue;
}

export interface IssueCatalogSnapshotHeader {
  id: number;
  snapshotId: string;
  schemaVersion: number;
  rowSchemaVersion: number;
  repository: string;
  source: string;
  sourceOrder: string;
  capturedAt: string;
  boundaryTotalCount: number;
  observedTotalCount: number;
  postBoundaryGrowthCount: number;
  terminalNodeId: string | null;
  terminalIssueNumber: number | null;
  terminalCreatedAt: string | null;
  fetchedCount: number;
  uniqueCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  membershipDigest: string;
  contentDigest: string;
  lastRequestCursor: string | null;
  rowCount: number;
  rowSchemaDigest: string;
  rowsContentHash: string;
  previousContentHash: string | null;
  contentHash: string;
}

export interface IssueCatalogSnapshotRow {
  snapshotId: string;
  sourceOrdinal: number;
  issueNumber: number;
  nodeId: string;
  issueJson: string;
  contentHash: string;
  issue: GhIssueCatalogIssue;
}

export interface IssueCatalogSnapshot {
  header: IssueCatalogSnapshotHeader;
  rows: IssueCatalogSnapshotRow[];
}

export interface StagedIssueCatalogSnapshot {
  header: Omit<IssueCatalogSnapshotHeader, 'id'>;
  rows: IssueCatalogSnapshotRow[];
}

export interface IssueCatalogSnapshotLedgerProblem {
  snapshotId: string | null;
  detail: string;
}

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) > 0;
}

function normalizedIssueCatalogIssue(value: unknown): GhIssueCatalogIssue | null {
  if (!isRecord(value)) return null;
  const user = value.user;
  const normalizedUser = user == null
    ? null
    : isRecord(user) &&
        typeof user.id === 'string' &&
        user.id.length > 0 &&
        user.id.trim() === user.id &&
        typeof user.type === 'string' &&
        user.type.length > 0 &&
        user.type.trim() === user.type &&
        typeof user.login === 'string' &&
        user.login.length > 0 &&
        user.login.trim() === user.login
      ? { id: user.id, type: user.type, login: user.login }
      : undefined;
  if (normalizedUser === undefined) return null;
  if (!Array.isArray(value.labels)) return null;
  const labelNames: string[] = [];
  for (const label of value.labels) {
    if (!isRecord(label) || typeof label.name !== 'string' || label.name.length === 0) {
      return null;
    }
    labelNames.push(label.name);
  }
  if (new Set(labelNames).size !== labelNames.length) return null;
  const sortedLabelNames = [...labelNames].sort(compareBinary);
  if (JSON.stringify(sortedLabelNames) !== JSON.stringify(labelNames)) return null;
  if (
    typeof value.node_id !== 'string' ||
    value.node_id.length === 0 ||
    value.node_id.trim() !== value.node_id ||
    value.node_type !== 'Issue' ||
    !isPositiveInteger(value.number) ||
    typeof value.title !== 'string' ||
    !(value.body == null || typeof value.body === 'string') ||
    (value.state !== 'open' && value.state !== 'closed') ||
    !(value.author_association == null || typeof value.author_association === 'string') ||
    !isTimestamp(value.created_at) ||
    !isTimestamp(value.updated_at) ||
    !(value.closed_at == null || isTimestamp(value.closed_at)) ||
    typeof value.html_url !== 'string' ||
    value.html_url.length === 0 ||
    !isNonNegativeInteger(value.comments) ||
    !isNonNegativeInteger(value.reaction_total) ||
    !isNonNegativeInteger(value.positive_reactions)
  ) {
    return null;
  }
  return {
    node_id: value.node_id,
    node_type: value.node_type,
    number: value.number,
    title: value.title,
    body: value.body ?? null,
    state: value.state,
    user: normalizedUser,
    author_association: value.author_association ?? null,
    created_at: value.created_at,
    updated_at: value.updated_at,
    closed_at: value.closed_at ?? null,
    html_url: value.html_url,
    comments: value.comments,
    reaction_total: value.reaction_total,
    positive_reactions: value.positive_reactions,
    labels: labelNames.map((name) => ({ name })),
  };
}

export function canonicalIssueCatalogIssueJson(issue: GhIssueCatalogIssue): string {
  const normalized = normalizedIssueCatalogIssue({
    node_id: issue.node_id,
    node_type: issue.node_type,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: issue.user,
    author_association: issue.author_association ?? null,
    created_at: issue.created_at,
    updated_at: issue.updated_at,
    closed_at: issue.closed_at,
    html_url: issue.html_url,
    comments: issue.comments,
    reaction_total: issue.reaction_total ?? 0,
    positive_reactions: issue.positive_reactions ?? 0,
    labels: issue.labels,
  });
  if (!normalized) {
    throw new Error(`Issue catalog row #${String(issue.number)} has incompatible fetched metadata`);
  }
  return JSON.stringify(normalized);
}

export function parseIssueCatalogIssueJson(issueJson: string): GhIssueCatalogIssue | null {
  try {
    const parsed = normalizedIssueCatalogIssue(JSON.parse(issueJson));
    return parsed && JSON.stringify(parsed) === issueJson ? parsed : null;
  } catch {
    return null;
  }
}

export function canonicalIssueMembershipDigest(
  totalCount: number,
  records: CanonicalIssueMembershipRecord[],
): string {
  const canonical = records
    .map(({ nodeId, issue }) => [nodeId, issue.number, issue.created_at] as const)
    .sort((left, right) =>
      compareBinary(left[2], right[2]) ||
      left[1] - right[1] ||
      compareBinary(left[0], right[0]));
  return sha256([totalCount, canonical]);
}

export function canonicalIssueContentDigest(
  totalCount: number,
  records: CanonicalIssueCatalogRecord[],
): string {
  const canonical = records
    .slice()
    .sort((left, right) =>
      compareBinary(left.nodeId, right.nodeId) || left.issue.number - right.issue.number)
    .map(({ nodeId, issue }) => [
      nodeId,
      issue.node_type,
      issue.number,
      issue.title,
      issue.body,
      issue.state,
      issue.user?.id ?? null,
      issue.user?.type ?? null,
      issue.user?.login ?? null,
      issue.author_association ?? null,
      issue.created_at,
      issue.updated_at,
      issue.closed_at,
      issue.html_url,
      issue.comments,
      issue.reaction_total ?? 0,
      issue.positive_reactions ?? 0,
      issue.labels.map((label) => label.name),
    ]);
  return sha256([totalCount, canonical]);
}

export function issueCatalogSnapshotRowContentHash(input: {
  sourceOrdinal: number;
  nodeId: string;
  issueNumber: number;
  issueJson: string;
}): string {
  return sha256([
    'issue-catalog-snapshot-row-v2',
    ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_VERSION,
    input.sourceOrdinal,
    input.nodeId,
    input.issueNumber,
    input.issueJson,
  ]);
}

export function issueCatalogSnapshotRowsContentHash(
  rows: Array<Pick<IssueCatalogSnapshotRow, 'sourceOrdinal' | 'nodeId' | 'issueNumber' | 'contentHash'>>,
): string {
  return sha256([
    'issue-catalog-snapshot-rows-v1',
    rows.map((row) => [
      row.sourceOrdinal,
      row.nodeId,
      row.issueNumber,
      row.contentHash,
    ]),
  ]);
}

export function issueCatalogSnapshotHeaderContentHash(
  header: Omit<IssueCatalogSnapshotHeader, 'id' | 'snapshotId' | 'contentHash'>,
): string {
  return sha256([
    'issue-catalog-snapshot-header-v1',
    header.schemaVersion,
    header.rowSchemaVersion,
    header.repository,
    header.source,
    header.sourceOrder,
    header.capturedAt,
    header.boundaryTotalCount,
    header.observedTotalCount,
    header.postBoundaryGrowthCount,
    header.terminalNodeId,
    header.terminalIssueNumber,
    header.terminalCreatedAt,
    header.fetchedCount,
    header.uniqueCount,
    header.pageCount,
    header.pagesFetched,
    header.sweepCount,
    header.membershipDigest,
    header.contentDigest,
    header.lastRequestCursor,
    header.rowCount,
    header.rowSchemaDigest,
    header.rowsContentHash,
    header.previousContentHash,
  ]);
}

export function stageIssueCatalogSnapshot(input: {
  repository: string;
  capturedAt: string;
  catalog: GhIssueCatalog;
  previousContentHash: string | null;
}): StagedIssueCatalogSnapshot {
  const { repository, capturedAt, catalog, previousContentHash } = input;
  const metadata = catalog.metadata;
  if (!repository.trim()) throw new Error('Issue catalog snapshot repository must be non-empty');
  if (!isTimestamp(capturedAt)) throw new Error('Issue catalog snapshot capturedAt must be a valid timestamp');
  if (previousContentHash != null && !isSha256(previousContentHash)) {
    throw new Error('Issue catalog snapshot previous content hash must be SHA-256 or null');
  }
  if (
    metadata.exhausted !== true ||
    metadata.stabilized !== true ||
    metadata.sourceOrder !== ISSUE_CATALOG_SNAPSHOT_SOURCE_ORDER ||
    metadata.hasNextPage !== false ||
    metadata.nextCursor !== null ||
    metadata.nodeCount !== catalog.issues.length ||
    metadata.uniqueCount !== catalog.issues.length ||
    metadata.totalCount !== catalog.issues.length ||
    metadata.snapshotBoundary.totalCount !== metadata.totalCount ||
    metadata.observedTotalCount < metadata.totalCount ||
    metadata.postBoundaryGrowthCount !==
      metadata.observedTotalCount - metadata.totalCount ||
    metadata.sweepCount < 2
  ) {
    throw new Error(
      'Issue catalog snapshot requires a complete stabilized frozen-boundary catalog',
    );
  }

  const rows = catalog.issues.map((issue, sourceOrdinal): IssueCatalogSnapshotRow => {
    const issueJson = canonicalIssueCatalogIssueJson(issue);
    return {
      snapshotId: '',
      sourceOrdinal,
      issueNumber: issue.number,
      nodeId: issue.node_id,
      issueJson,
      contentHash: issueCatalogSnapshotRowContentHash({
        sourceOrdinal,
        nodeId: issue.node_id,
        issueNumber: issue.number,
        issueJson,
      }),
      issue,
    };
  });
  for (let index = 1; index < rows.length; index++) {
    if (compareBinary(rows[index - 1].issue.created_at, rows[index].issue.created_at) > 0) {
      throw new Error('Issue catalog snapshot rows are not in CREATED_AT_ASC source order');
    }
  }
  const records = rows.map((row) => ({ nodeId: row.nodeId, issue: row.issue }));
  const membershipDigest = canonicalIssueMembershipDigest(metadata.totalCount, records);
  const contentDigest = canonicalIssueContentDigest(metadata.totalCount, records);
  if (
    metadata.digest !== metadata.membershipDigest ||
    metadata.membershipDigest !== membershipDigest ||
    metadata.contentDigest !== contentDigest ||
    metadata.snapshotBoundary.membershipDigest !== membershipDigest
  ) {
    throw new Error('Issue catalog snapshot digests do not match the staged rows');
  }
  const terminal = rows.at(-1);
  const terminalIdentity = terminal
    ? {
        nodeId: terminal.nodeId,
        issueNumber: terminal.issueNumber,
        createdAt: terminal.issue.created_at,
      }
    : null;
  if (JSON.stringify(terminalIdentity) !== JSON.stringify(metadata.snapshotBoundary.terminalIssue)) {
    throw new Error('Issue catalog snapshot terminal boundary does not match the staged source order');
  }

  const headerWithoutIdentity = {
    schemaVersion: ISSUE_CATALOG_SNAPSHOT_SCHEMA_VERSION,
    rowSchemaVersion: ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_VERSION,
    repository,
    source: ISSUE_CATALOG_SNAPSHOT_SOURCE,
    sourceOrder: ISSUE_CATALOG_SNAPSHOT_SOURCE_ORDER,
    capturedAt,
    boundaryTotalCount: metadata.totalCount,
    observedTotalCount: metadata.observedTotalCount,
    postBoundaryGrowthCount: metadata.postBoundaryGrowthCount,
    terminalNodeId: terminalIdentity?.nodeId ?? null,
    terminalIssueNumber: terminalIdentity?.issueNumber ?? null,
    terminalCreatedAt: terminalIdentity?.createdAt ?? null,
    fetchedCount: metadata.nodeCount,
    uniqueCount: metadata.uniqueCount,
    pageCount: metadata.pageCount,
    pagesFetched: metadata.pagesFetched,
    sweepCount: metadata.sweepCount,
    membershipDigest,
    contentDigest,
    lastRequestCursor: metadata.lastRequestCursor,
    rowCount: rows.length,
    rowSchemaDigest: ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_DIGEST,
    rowsContentHash: issueCatalogSnapshotRowsContentHash(rows),
    previousContentHash,
  };
  const contentHash = issueCatalogSnapshotHeaderContentHash(headerWithoutIdentity);
  const snapshotId = contentHash;
  for (const row of rows) row.snapshotId = snapshotId;
  return {
    header: {
      snapshotId,
      ...headerWithoutIdentity,
      contentHash,
    },
    rows,
  };
}

export function issueCatalogSnapshotProblems(
  snapshot: IssueCatalogSnapshot,
  options: {
    repository?: string;
    expectedPreviousContentHash?: string | null;
  } = {},
): string[] {
  const problems: string[] = [];
  const { header, rows } = snapshot;
  if (header.schemaVersion !== ISSUE_CATALOG_SNAPSHOT_SCHEMA_VERSION) {
    problems.push(`schemaVersion must equal ${ISSUE_CATALOG_SNAPSHOT_SCHEMA_VERSION}`);
  }
  if (header.rowSchemaVersion !== ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_VERSION) {
    problems.push(`rowSchemaVersion must equal ${ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_VERSION}`);
  }
  if (header.rowSchemaDigest !== ISSUE_CATALOG_SNAPSHOT_ROW_SCHEMA_DIGEST) {
    problems.push('rowSchemaDigest is not compatible with this code');
  }
  if (!header.repository || (options.repository && header.repository !== options.repository)) {
    problems.push(`repository must equal ${options.repository ?? 'a non-empty repository identity'}`);
  }
  if (header.source !== ISSUE_CATALOG_SNAPSHOT_SOURCE) {
    problems.push(`source must equal ${ISSUE_CATALOG_SNAPSHOT_SOURCE}`);
  }
  if (header.sourceOrder !== ISSUE_CATALOG_SNAPSHOT_SOURCE_ORDER) {
    problems.push(`sourceOrder must equal ${ISSUE_CATALOG_SNAPSHOT_SOURCE_ORDER}`);
  }
  if (!isTimestamp(header.capturedAt)) problems.push('capturedAt must be a valid timestamp');
  for (const [name, value] of [
    ['boundaryTotalCount', header.boundaryTotalCount],
    ['observedTotalCount', header.observedTotalCount],
    ['postBoundaryGrowthCount', header.postBoundaryGrowthCount],
    ['fetchedCount', header.fetchedCount],
    ['uniqueCount', header.uniqueCount],
    ['pageCount', header.pageCount],
    ['pagesFetched', header.pagesFetched],
    ['sweepCount', header.sweepCount],
    ['rowCount', header.rowCount],
  ] as const) {
    if (!isNonNegativeInteger(value)) problems.push(`${name} must be a non-negative integer`);
  }
  if (header.sweepCount < 2) problems.push('sweepCount must be at least 2');
  if (
    header.observedTotalCount < header.boundaryTotalCount
  ) {
    problems.push('observedTotalCount cannot be less than boundaryTotalCount');
  } else if (
    header.postBoundaryGrowthCount !==
      header.observedTotalCount - header.boundaryTotalCount
  ) {
    problems.push(
      'postBoundaryGrowthCount must equal observedTotalCount minus boundaryTotalCount',
    );
  }
  if (
    header.fetchedCount !== header.boundaryTotalCount ||
    header.uniqueCount !== header.boundaryTotalCount ||
    header.rowCount !== header.boundaryTotalCount ||
    rows.length !== header.rowCount
  ) {
    problems.push('row, fetched, unique, and frozen-boundary counts must match');
  }
  if (header.pagesFetched < header.pageCount) {
    problems.push('pagesFetched cannot be less than pageCount');
  }
  if (!isSha256(header.membershipDigest)) problems.push('membershipDigest must be SHA-256');
  if (!isSha256(header.contentDigest)) problems.push('contentDigest must be SHA-256');
  if (!isSha256(header.rowsContentHash)) problems.push('rowsContentHash must be SHA-256');
  if (header.previousContentHash != null && !isSha256(header.previousContentHash)) {
    problems.push('previousContentHash must be SHA-256 or null');
  }
  if (
    Object.hasOwn(options, 'expectedPreviousContentHash') &&
    header.previousContentHash !== options.expectedPreviousContentHash
  ) {
    problems.push('previousContentHash does not match the preceding snapshot');
  }
  if (!isSha256(header.contentHash)) problems.push('contentHash must be SHA-256');
  if (header.snapshotId !== header.contentHash) problems.push('snapshotId must equal contentHash');

  const issueNumbers = new Set<number>();
  const nodeIds = new Set<string>();
  const validRows: IssueCatalogSnapshotRow[] = [];
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index];
    if (row.snapshotId !== header.snapshotId) {
      problems.push(`row ${index} snapshotId does not match its header`);
    }
    if (row.sourceOrdinal !== index) {
      problems.push(`row ${index} sourceOrdinal must be contiguous from zero`);
    }
    if (!isPositiveInteger(row.issueNumber)) problems.push(`row ${index} has invalid issueNumber`);
    if (!row.nodeId) problems.push(`row ${index} has an empty nodeId`);
    if (issueNumbers.has(row.issueNumber)) problems.push(`duplicate issue number ${row.issueNumber}`);
    if (nodeIds.has(row.nodeId)) problems.push(`duplicate node id ${row.nodeId}`);
    issueNumbers.add(row.issueNumber);
    nodeIds.add(row.nodeId);
    const parsed = parseIssueCatalogIssueJson(row.issueJson);
    if (!parsed) {
      problems.push(`row ${index} issueJson is not canonical or code-compatible`);
      continue;
    }
    if (
      parsed.node_id !== row.nodeId ||
      parsed.number !== row.issueNumber ||
      canonicalIssueCatalogIssueJson(row.issue) !== row.issueJson
    ) {
      problems.push(`row ${index} columns do not match issueJson`);
      continue;
    }
    const expectedHash = issueCatalogSnapshotRowContentHash(row);
    if (row.contentHash !== expectedHash) problems.push(`row ${index} contentHash mismatch`);
    validRows.push({ ...row, issue: parsed });
    if (
      index > 0 &&
      compareBinary(validRows.at(-2)?.issue.created_at ?? '', parsed.created_at) > 0
    ) {
      problems.push(`row ${index} violates CREATED_AT_ASC source order`);
    }
  }

  if (validRows.length === rows.length) {
    const records = validRows.map((row) => ({ nodeId: row.nodeId, issue: row.issue }));
    const membershipDigest = canonicalIssueMembershipDigest(header.boundaryTotalCount, records);
    const contentDigest = canonicalIssueContentDigest(header.boundaryTotalCount, records);
    if (header.membershipDigest !== membershipDigest) problems.push('membershipDigest mismatch');
    if (header.contentDigest !== contentDigest) problems.push('contentDigest mismatch');
    const rowsContentHash = issueCatalogSnapshotRowsContentHash(validRows);
    if (header.rowsContentHash !== rowsContentHash) problems.push('rowsContentHash mismatch');
    const terminal = validRows.at(-1);
    if (header.boundaryTotalCount === 0) {
      if (
        header.terminalNodeId != null ||
        header.terminalIssueNumber != null ||
        header.terminalCreatedAt != null
      ) {
        problems.push('empty snapshot must have a null terminal boundary');
      }
    } else if (
      !terminal ||
      header.terminalNodeId !== terminal.nodeId ||
      header.terminalIssueNumber !== terminal.issueNumber ||
      header.terminalCreatedAt !== terminal.issue.created_at
    ) {
      problems.push('terminal boundary does not match the final source row');
    }
  }
  const expectedHeaderHash = issueCatalogSnapshotHeaderContentHash({
    schemaVersion: header.schemaVersion,
    rowSchemaVersion: header.rowSchemaVersion,
    repository: header.repository,
    source: header.source,
    sourceOrder: header.sourceOrder,
    capturedAt: header.capturedAt,
    boundaryTotalCount: header.boundaryTotalCount,
    observedTotalCount: header.observedTotalCount,
    postBoundaryGrowthCount: header.postBoundaryGrowthCount,
    terminalNodeId: header.terminalNodeId,
    terminalIssueNumber: header.terminalIssueNumber,
    terminalCreatedAt: header.terminalCreatedAt,
    fetchedCount: header.fetchedCount,
    uniqueCount: header.uniqueCount,
    pageCount: header.pageCount,
    pagesFetched: header.pagesFetched,
    sweepCount: header.sweepCount,
    membershipDigest: header.membershipDigest,
    contentDigest: header.contentDigest,
    lastRequestCursor: header.lastRequestCursor,
    rowCount: header.rowCount,
    rowSchemaDigest: header.rowSchemaDigest,
    rowsContentHash: header.rowsContentHash,
    previousContentHash: header.previousContentHash,
  });
  if (header.contentHash !== expectedHeaderHash) problems.push('header contentHash mismatch');
  return [...new Set(problems)];
}

export function issueCatalogSnapshotResumeProblems(
  snapshot: IssueCatalogSnapshot,
  options: {
    repository: string;
    now: Date;
    maxAgeMs?: number;
  },
): string[] {
  const problems = issueCatalogSnapshotProblems(snapshot, {
    repository: options.repository,
  });
  const nowMs = options.now.getTime();
  const capturedAtMs = Date.parse(snapshot.header.capturedAt);
  const maxAgeMs = options.maxAgeMs ?? ISSUE_CATALOG_SNAPSHOT_DEFAULT_MAX_AGE_MS;
  if (!Number.isFinite(nowMs)) problems.push('resume observation time is invalid');
  if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) problems.push('resume max age is invalid');
  if (Number.isFinite(capturedAtMs) && Number.isFinite(nowMs)) {
    if (capturedAtMs > nowMs + 5 * 60 * 1000) {
      problems.push('capturedAt is implausibly in the future');
    } else if (nowMs - capturedAtMs > maxAgeMs) {
      problems.push(`snapshot exceeds resume age policy of ${maxAgeMs}ms`);
    }
  }
  return [...new Set(problems)];
}

export function issueCatalogSnapshotLedgerProblems(
  snapshots: IssueCatalogSnapshot[],
  orphanRowCount = 0,
): IssueCatalogSnapshotLedgerProblem[] {
  const problems: IssueCatalogSnapshotLedgerProblem[] = [];
  if (orphanRowCount > 0) {
    problems.push({
      snapshotId: null,
      detail: `${orphanRowCount} issue catalog snapshot row(s) have no header`,
    });
  }
  let previousContentHash: string | null = null;
  for (const snapshot of snapshots) {
    for (const detail of issueCatalogSnapshotProblems(snapshot, {
      expectedPreviousContentHash: previousContentHash,
    })) {
      problems.push({ snapshotId: snapshot.header.snapshotId, detail });
    }
    previousContentHash = snapshot.header.contentHash;
  }
  return problems;
}

export function issueCatalogSnapshotCatalog(snapshot: IssueCatalogSnapshot): GhIssueCatalog {
  const problems = issueCatalogSnapshotProblems(snapshot);
  if (problems.length > 0) {
    throw new Error(`Issue catalog snapshot is invalid: ${problems.join('; ')}`);
  }
  const header = snapshot.header;
  const metadata: GhIssueCatalogMetadata = {
    exhausted: true,
    stabilized: true,
    totalCount: header.boundaryTotalCount,
    observedTotalCount: header.observedTotalCount,
    postBoundaryGrowthCount: header.postBoundaryGrowthCount,
    nodeCount: header.fetchedCount,
    uniqueCount: header.uniqueCount,
    pageCount: header.pageCount,
    pagesFetched: header.pagesFetched,
    sweepCount: header.sweepCount,
    digest: header.membershipDigest,
    membershipDigest: header.membershipDigest,
    contentDigest: header.contentDigest,
    snapshotBoundary: {
      totalCount: header.boundaryTotalCount,
      terminalIssue: header.terminalNodeId == null
        ? null
        : {
            nodeId: header.terminalNodeId,
            issueNumber: header.terminalIssueNumber!,
            createdAt: header.terminalCreatedAt!,
          },
      membershipDigest: header.membershipDigest,
    },
    lastRequestCursor: header.lastRequestCursor,
    nextCursor: null,
    hasNextPage: false,
    sourceOrder: ISSUE_CATALOG_SNAPSHOT_SOURCE_ORDER,
  };
  return {
    issues: snapshot.rows.map((row) => row.issue),
    metadata,
  };
}
