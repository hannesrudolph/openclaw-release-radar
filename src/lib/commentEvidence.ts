import { createHash } from 'node:crypto';

const COMMENT_EVIDENCE_DIGEST_SCHEMA_VERSION = 4;
const COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION = 1;
export const AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION = 4;
const COMMENT_EVIDENCE_ROW_KEYS = new Set([
  'id',
  'node_id',
  'nodeId',
  'node_type',
  'nodeType',
  '__typename',
  'body',
  'created_at',
  'updated_at',
  'author_association',
  'url',
  'user',
]);
const COMMENT_EVIDENCE_ACTOR_KEYS = new Set([
  'id',
  'node_id',
  'nodeId',
  'login',
  'type',
  'actor_type',
  'actorType',
  '__typename',
]);
const COMMENT_EVIDENCE_SNAPSHOT_IDENTITY_KEYS = new Set([
  'repositoryNodeId',
  'issueNodeId',
  'issueNodeType',
  'issueAuthor',
]);
const ISSUE_AUTHOR_EVIDENCE_IDENTITY_KEYS = new Set([
  'nodeId',
  'login',
  'actorType',
]);

export interface CommentEvidenceActor {
  id?: string | null;
  node_id?: string | null;
  nodeId?: string | null;
  login?: string | null;
  type?: string | null;
  actor_type?: string | null;
  actorType?: string | null;
  __typename?: string | null;
}

export interface CommentEvidenceRow {
  id?: number | null;
  node_id?: string | null;
  nodeId?: string | null;
  node_type?: string | null;
  nodeType?: string | null;
  __typename?: string | null;
  body?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  author_association?: string | null;
  url?: string | null;
  user?: CommentEvidenceActor | null;
}

export interface IssueAuthorEvidenceIdentity {
  nodeId: string | null;
  login?: string | null;
  actorType?: string | null;
}

export interface CommentEvidenceSnapshotIdentity {
  repositoryNodeId?: string | null;
  issueNodeId?: string | null;
  issueNodeType?: string | null;
  issueAuthor?: IssueAuthorEvidenceIdentity | null;
}

export interface CanonicalCommentSourceIdentity {
  source: 'github';
  nodeType: 'IssueComment';
  nodeId: string;
}

export interface CanonicalCommentActorIdentity {
  source: 'github';
  nodeType: string;
  nodeId: string;
}

export interface CommentEvidenceSweepIdentity {
  schemaVersion: typeof COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION;
  sweepOrdinal: number;
  issueUpdatedAt: string;
  totalCount: number;
  authorityDigest: string;
  identityDigest: string;
}

export interface CommentEvidenceStabilizationIdentity {
  schemaVersion: typeof COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION;
  sweepCount: number;
  firstSweep: CommentEvidenceSweepIdentity;
  secondSweep: CommentEvidenceSweepIdentity;
  identityDigest: string;
}

export function commentEvidenceDigest(
  totalCommentCount: number,
  comments: CommentEvidenceRow[],
  snapshotIdentity?: CommentEvidenceSnapshotIdentity,
): string {
  assertValidCommentCount(totalCommentCount, comments.length);
  assertValidCommentEvidenceRows(comments);
  const digest = createHash('sha256');
  digest.update(JSON.stringify({
    schemaVersion: COMMENT_EVIDENCE_DIGEST_SCHEMA_VERSION,
    snapshotIdentity: normalizeCommentSnapshotIdentity(snapshotIdentity),
    totalCommentCount,
    comments: normalizedCommentEvidence(comments),
  }));
  return digest.digest('hex');
}

export function serializeCommentEvidence(comments: CommentEvidenceRow[]): string {
  return JSON.stringify(comments);
}

export function commentEvidenceDigestFromJson(
  totalCommentCount: number,
  commentsJson: string,
  snapshotIdentity?: CommentEvidenceSnapshotIdentity,
): string {
  let comments: unknown;
  try {
    comments = JSON.parse(commentsJson);
  } catch {
    throw new Error('Comment evidence JSON is invalid');
  }
  if (!Array.isArray(comments)) {
    throw new Error('Comment evidence JSON must be an array');
  }
  assertValidCommentCount(totalCommentCount, comments.length, 'Comment evidence JSON');
  assertValidCommentEvidenceRows(comments, 'Comment evidence JSON');
  return commentEvidenceDigest(totalCommentCount, comments, snapshotIdentity);
}

export function parseCachedCommentEvidence<T extends CommentEvidenceRow>(
  json: string | null,
  expectedCount: number,
  expectedDigest: string,
  snapshotIdentity?: CommentEvidenceSnapshotIdentity,
): T[] | null {
  if (json == null) return null;
  try {
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed) || parsed.length !== expectedCount) return null;
    if (!parsed.every(isCommentEvidenceRow)) return null;
    if (
      commentEvidenceDigestFromJson(expectedCount, json, snapshotIdentity) !==
      expectedDigest
    ) {
      return null;
    }
    return parsed as T[];
  } catch {
    return null;
  }
}

export function canonicalCommentSourceIdentity(
  comment: CommentEvidenceRow,
): CanonicalCommentSourceIdentity | null {
  assertValidCommentEvidenceRows([comment]);
  const nodeId = commentNodeId(comment);
  const nodeType = commentNodeType(comment);
  return nodeId == null || nodeType !== 'IssueComment'
    ? null
    : { source: 'github', nodeType: 'IssueComment', nodeId };
}

export function canonicalCommentActorIdentity(
  comment: CommentEvidenceRow,
): CanonicalCommentActorIdentity | null {
  assertValidCommentEvidenceRows([comment]);
  const actor = normalizedCommentActor(comment.user ?? null);
  return actor.nodeId == null || actor.type == null
    ? null
    : { source: 'github', nodeType: actor.type, nodeId: actor.nodeId };
}

export function isExactIssueReporterComment(
  issueAuthor: IssueAuthorEvidenceIdentity | null | undefined,
  comment: CommentEvidenceRow,
): boolean {
  try {
    if (!issueAuthor) return false;
    const issueAuthorNodeId = canonicalNullableString(
      issueAuthor.nodeId,
      'issue author node ID',
    );
    if (issueAuthorNodeId == null) return false;
    const issueAuthorType = canonicalNullableString(
      issueAuthor.actorType ?? null,
      'issue author actor type',
    );
    if (issueAuthorType == null) return false;
    const actor = canonicalCommentActorIdentity(comment);
    if (!actor || actor.nodeId !== issueAuthorNodeId) return false;
    return actor.nodeType === issueAuthorType;
  } catch {
    return false;
  }
}

export function assertAuthoritativeCommentEvidence(
  totalCommentCount: number,
  comments: CommentEvidenceRow[],
  snapshotIdentity: CommentEvidenceSnapshotIdentity,
): void {
  assertValidCommentCount(totalCommentCount, comments.length);
  assertValidCommentEvidenceRows(comments);
  const identity = normalizeCommentSnapshotIdentity(snapshotIdentity);
  if (identity.repositoryNodeId == null) {
    throw new Error('Authoritative comment evidence requires a canonical repository node identity');
  }
  if (identity.issueNodeId == null || identity.issueNodeType !== 'Issue') {
    throw new Error('Authoritative comment evidence requires a canonical Issue node identity');
  }
  if (identity.issueAuthorNodeId == null || identity.issueAuthorType == null) {
    throw new Error('Authoritative comment evidence requires a canonical issue author identity');
  }
  for (const comment of normalizedCommentEvidence(comments)) {
    if (comment.nodeId == null || comment.nodeType !== 'IssueComment') {
      throw new Error('Authoritative comment evidence requires canonical IssueComment node identities');
    }
    if (comment.authorNodeId == null || comment.authorType == null) {
      throw new Error(
        `Authoritative comment evidence ${comment.nodeId} requires a canonical actor identity`,
      );
    }
  }
}

export function commentEvidenceSweepIdentity(input: {
  sweepOrdinal: number;
  issueUpdatedAt: string;
  totalCount: number;
  comments: CommentEvidenceRow[];
  snapshotIdentity: CommentEvidenceSnapshotIdentity;
}): CommentEvidenceSweepIdentity {
  if (!Number.isInteger(input.sweepOrdinal) || input.sweepOrdinal <= 0) {
    throw new Error('Comment evidence sweep ordinal must be a positive integer');
  }
  const issueUpdatedAt = canonicalTimestamp(
    input.issueUpdatedAt,
    'Comment evidence sweep issue updatedAt',
  );
  assertAuthoritativeCommentEvidence(
    input.totalCount,
    input.comments,
    input.snapshotIdentity,
  );
  const authorityDigest = commentEvidenceDigest(
    input.totalCount,
    input.comments,
    input.snapshotIdentity,
  );
  const payload = {
    schemaVersion: COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION,
    sweepOrdinal: input.sweepOrdinal,
    issueUpdatedAt,
    totalCount: input.totalCount,
    authorityDigest,
  } satisfies Omit<CommentEvidenceSweepIdentity, 'identityDigest'>;
  return {
    ...payload,
    identityDigest: createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
  };
}

export function commentEvidenceStabilizationIdentity(
  firstSweep: CommentEvidenceSweepIdentity,
  secondSweep: CommentEvidenceSweepIdentity,
  sweepCount: number,
): CommentEvidenceStabilizationIdentity {
  if (!Number.isInteger(sweepCount) || sweepCount < 2) {
    throw new Error('Comment evidence stabilization sweep count must be at least 2');
  }
  const canonicalFirstSweep = validateCommentEvidenceSweepIdentity(
    firstSweep,
    'Comment evidence stabilization first sweep',
  );
  const canonicalSecondSweep = validateCommentEvidenceSweepIdentity(
    secondSweep,
    'Comment evidence stabilization second sweep',
  );
  if (
    canonicalFirstSweep.sweepOrdinal !== sweepCount - 1 ||
    canonicalSecondSweep.sweepOrdinal !== sweepCount
  ) {
    throw new Error('Comment evidence stabilization must bind the final consecutive sweeps');
  }
  if (
    canonicalFirstSweep.issueUpdatedAt !== canonicalSecondSweep.issueUpdatedAt ||
    canonicalFirstSweep.totalCount !== canonicalSecondSweep.totalCount ||
    canonicalFirstSweep.authorityDigest !== canonicalSecondSweep.authorityDigest
  ) {
    throw new Error('Comment evidence did not stabilize across consecutive sweeps');
  }
  const payload = {
    schemaVersion: COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION,
    sweepCount,
    firstSweep: canonicalFirstSweep,
    secondSweep: canonicalSecondSweep,
  } satisfies Omit<CommentEvidenceStabilizationIdentity, 'identityDigest'>;
  return {
    ...payload,
    identityDigest: createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
  };
}

export function parseCommentEvidenceStabilizationIdentity(
  json: string,
): CommentEvidenceStabilizationIdentity {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('Comment evidence stabilization JSON is invalid');
  }
  return validateCommentEvidenceStabilizationIdentity(parsed);
}

export function validateCommentEvidenceStabilizationIdentity(
  value: unknown,
): CommentEvidenceStabilizationIdentity {
  const record = strictRecord(
    value,
    [
      'schemaVersion',
      'sweepCount',
      'firstSweep',
      'secondSweep',
      'identityDigest',
    ],
    'Comment evidence stabilization',
  );
  if (record.schemaVersion !== COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION) {
    throw new Error('Comment evidence stabilization schema version is unsupported');
  }
  if (!Number.isInteger(record.sweepCount) || Number(record.sweepCount) < 2) {
    throw new Error('Comment evidence stabilization sweep count must be at least 2');
  }
  const firstSweep = validateCommentEvidenceSweepIdentity(
    record.firstSweep,
    'Comment evidence stabilization first sweep',
  );
  const secondSweep = validateCommentEvidenceSweepIdentity(
    record.secondSweep,
    'Comment evidence stabilization second sweep',
  );
  const identityDigest = canonicalSha256Digest(
    record.identityDigest,
    'Comment evidence stabilization identity digest',
  );
  const expected = commentEvidenceStabilizationIdentity(
    firstSweep,
    secondSweep,
    Number(record.sweepCount),
  );
  if (identityDigest !== expected.identityDigest) {
    throw new Error('Comment evidence stabilization identity digest mismatch');
  }
  return expected;
}

function validateCommentEvidenceSweepIdentity(
  value: unknown,
  context: string,
): CommentEvidenceSweepIdentity {
  const record = strictRecord(
    value,
    [
      'schemaVersion',
      'sweepOrdinal',
      'issueUpdatedAt',
      'totalCount',
      'authorityDigest',
      'identityDigest',
    ],
    context,
  );
  if (record.schemaVersion !== COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION) {
    throw new Error(`${context} schema version is unsupported`);
  }
  if (!Number.isInteger(record.sweepOrdinal) || Number(record.sweepOrdinal) <= 0) {
    throw new Error(`${context} ordinal must be a positive integer`);
  }
  if (!Number.isInteger(record.totalCount) || Number(record.totalCount) < 0) {
    throw new Error(`${context} total count must be a non-negative integer`);
  }
  const payload = {
    schemaVersion: COMMENT_EVIDENCE_STABILIZATION_SCHEMA_VERSION,
    sweepOrdinal: Number(record.sweepOrdinal),
    issueUpdatedAt: canonicalTimestamp(record.issueUpdatedAt, `${context} issue updatedAt`),
    totalCount: Number(record.totalCount),
    authorityDigest: canonicalSha256Digest(
      record.authorityDigest,
      `${context} authority digest`,
    ),
  } satisfies Omit<CommentEvidenceSweepIdentity, 'identityDigest'>;
  const identityDigest = canonicalSha256Digest(
    record.identityDigest,
    `${context} identity digest`,
  );
  const expectedDigest = createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');
  if (identityDigest !== expectedDigest) {
    throw new Error(`${context} identity digest mismatch`);
  }
  return { ...payload, identityDigest };
}

function normalizedCommentEvidence(comments: CommentEvidenceRow[]) {
  const normalized = comments.map(normalizeCommentEvidenceRow);
  const seenIds = new Set<number>();
  const seenNodeIds = new Set<string>();
  for (const comment of normalized) {
    if (comment.id != null) {
      if (seenIds.has(comment.id)) {
        throw new Error(`Duplicate comment evidence ID ${comment.id}`);
      }
      seenIds.add(comment.id);
    }
    if (comment.nodeId != null) {
      if (seenNodeIds.has(comment.nodeId)) {
        throw new Error(`Duplicate comment evidence node ID ${comment.nodeId}`);
      }
      seenNodeIds.add(comment.nodeId);
    }
  }

  normalized.sort(compareCommentEvidenceOrder);
  for (let index = 1; index < normalized.length; index++) {
    if (compareCommentEvidenceOrder(normalized[index - 1], normalized[index]) === 0) {
      throw new Error('Ambiguous comment evidence order for tied timestamps and ID');
    }
  }
  return normalized;
}

type NormalizedCommentEvidence = ReturnType<typeof normalizeCommentEvidenceRow>;

function normalizeCommentEvidenceRow(comment: CommentEvidenceRow) {
  const actor = normalizedCommentActor(comment.user ?? null);
  return {
    id: comment.id ?? null,
    nodeId: commentNodeId(comment),
    nodeType: commentNodeType(comment),
    url: comment.url ?? null,
    authorNodeId: actor.nodeId,
    author: actor.login,
    authorType: actor.type,
    association: comment.author_association ?? null,
    createdAt: comment.created_at ?? null,
    updatedAt: comment.updated_at ?? null,
    body: comment.body ?? null,
  };
}

function compareCommentEvidenceOrder(
  a: NormalizedCommentEvidence,
  b: NormalizedCommentEvidence,
): number {
  const createdAtComparison = compareNullableStrings(a.createdAt, b.createdAt);
  if (createdAtComparison !== 0) return createdAtComparison;
  const updatedAtComparison = compareNullableStrings(a.updatedAt, b.updatedAt);
  if (updatedAtComparison !== 0) return updatedAtComparison;
  const nodeIdComparison = compareNullableStrings(a.nodeId, b.nodeId);
  if (nodeIdComparison !== 0) return nodeIdComparison;
  if (a.id === b.id) return 0;
  if (a.id == null) return -1;
  if (b.id == null) return 1;
  return a.id < b.id ? -1 : 1;
}

function compareNullableStrings(a: string | null, b: string | null): number {
  if (a === b) return 0;
  if (a == null) return -1;
  if (b == null) return 1;
  return a < b ? -1 : 1;
}

function assertValidCommentEvidenceRows(
  comments: unknown[],
  context = 'Comment evidence',
): asserts comments is CommentEvidenceRow[] {
  for (let index = 0; index < comments.length; index++) {
    const problem = commentEvidenceRowProblem(comments[index]);
    if (problem) throw new Error(`${context} row ${index} ${problem}`);
  }
}

function isCommentEvidenceRow(value: unknown): value is CommentEvidenceRow {
  return commentEvidenceRowProblem(value) == null;
}

function commentEvidenceRowProblem(value: unknown): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return 'must be an object';
  }
  const row = value as Record<string, unknown>;
  if ('createdAt' in row || 'updatedAt' in row) {
    return 'must use snake-case created_at and updated_at timestamps';
  }
  const unknownRowKey = firstUnknownKey(row, COMMENT_EVIDENCE_ROW_KEYS);
  if (unknownRowKey != null) {
    return `has unknown field ${unknownRowKey}`;
  }
  if (
    row.id != null &&
    (!Number.isInteger(row.id) || Number(row.id) <= 0)
  ) {
    return 'has an invalid id';
  }
  try {
    aliasedCanonicalString(
      [row.node_id, row.nodeId],
      'comment node ID',
    );
    aliasedCanonicalString(
      [row.node_type, row.nodeType, row.__typename],
      'comment node type',
    );
  } catch (error) {
    return `has an invalid comment node ID: ${(error as Error).message}`;
  }
  if (row.body != null && typeof row.body !== 'string') return 'has an invalid body';
  if (typeof row.created_at !== 'string' || !Number.isFinite(Date.parse(row.created_at))) {
    return 'has an invalid created_at timestamp';
  }
  const createdAt = Date.parse(row.created_at);
  if (row.updated_at != null) {
    if (typeof row.updated_at !== 'string' || !Number.isFinite(Date.parse(row.updated_at))) {
      return 'has an invalid updated_at timestamp';
    }
    if (Date.parse(row.updated_at) < createdAt) {
      return 'has updated_at before created_at';
    }
  }
  if (row.author_association != null && typeof row.author_association !== 'string') {
    return 'has an invalid author_association';
  }
  if (row.url != null && typeof row.url !== 'string') return 'has an invalid url';
  if (row.user != null) {
    if (typeof row.user !== 'object' || Array.isArray(row.user)) {
      return 'has an invalid user';
    }
    const user = row.user as Record<string, unknown>;
    if (user.login != null && typeof user.login !== 'string') {
      return 'has an invalid user login';
    }
    const unknownUserKey = firstUnknownKey(user, COMMENT_EVIDENCE_ACTOR_KEYS);
    if (unknownUserKey != null) {
      return `has an invalid user identity: unknown field ${unknownUserKey}`;
    }
    try {
      normalizedCommentActor(user as CommentEvidenceActor);
    } catch (error) {
      return `has an invalid user identity: ${(error as Error).message}`;
    }
  }
  return null;
}

function assertValidCommentCount(
  totalCommentCount: number,
  actualCount: number,
  context = 'Comment evidence',
): void {
  if (!Number.isInteger(totalCommentCount) || totalCommentCount < 0) {
    throw new Error(`${context} total count must be a non-negative integer`);
  }
  if (actualCount !== totalCommentCount) {
    throw new Error(
      `${context} count ${actualCount} does not match total count ${totalCommentCount}`,
    );
  }
}

function normalizeCommentSnapshotIdentity(
  identity: CommentEvidenceSnapshotIdentity | undefined,
) {
  if (!identity) {
    return {
      repositoryNodeId: null,
      issueNodeId: null,
      issueNodeType: null,
      issueAuthorNodeId: null,
      issueAuthorLogin: null,
      issueAuthorType: null,
    };
  }
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) {
    throw new Error('Comment evidence snapshot identity must be an object');
  }
  const identityRecord = identity as unknown as Record<string, unknown>;
  const unknownIdentityKey = firstUnknownKey(
    identityRecord,
    COMMENT_EVIDENCE_SNAPSHOT_IDENTITY_KEYS,
  );
  if (unknownIdentityKey != null) {
    throw new Error(
      `Comment evidence snapshot identity has unknown field ${unknownIdentityKey}`,
    );
  }
  const repositoryNodeId = canonicalNullableString(
    identity.repositoryNodeId ?? null,
    'repository node ID',
  );
  const issueNodeId = canonicalNullableString(
    identity.issueNodeId ?? null,
    'issue node ID',
  );
  const issueNodeType = canonicalNullableString(
    identity.issueNodeType ?? null,
    'issue node type',
  );
  if (issueNodeId != null && issueNodeType == null) {
    throw new Error('Issue node ID requires a canonical issue node type');
  }
  const author = identity.issueAuthor ?? null;
  if (author != null) {
    if (typeof author !== 'object' || Array.isArray(author)) {
      throw new Error('Issue author identity must be an object');
    }
    const unknownAuthorKey = firstUnknownKey(
      author as unknown as Record<string, unknown>,
      ISSUE_AUTHOR_EVIDENCE_IDENTITY_KEYS,
    );
    if (unknownAuthorKey != null) {
      throw new Error(`Issue author identity has unknown field ${unknownAuthorKey}`);
    }
  }
  const issueAuthorNodeId = canonicalNullableString(
    author?.nodeId ?? null,
    'issue author node ID',
  );
  const issueAuthorLogin = canonicalNullableString(
    author?.login ?? null,
    'issue author login',
  );
  const issueAuthorType = canonicalNullableString(
    author?.actorType ?? null,
    'issue author actor type',
  );
  if (issueAuthorNodeId != null && issueAuthorType == null) {
    throw new Error('Issue author node ID requires a canonical issue author actor type');
  }
  return {
    repositoryNodeId,
    issueNodeId,
    issueNodeType,
    issueAuthorNodeId,
    issueAuthorLogin,
    issueAuthorType,
  };
}

function commentNodeId(comment: CommentEvidenceRow): string | null {
  return aliasedCanonicalString(
    [comment.node_id, comment.nodeId],
    'comment node ID',
  );
}

function commentNodeType(comment: CommentEvidenceRow): string | null {
  return aliasedCanonicalString(
    [comment.node_type, comment.nodeType, comment.__typename],
    'comment node type',
  );
}

function normalizedCommentActor(actor: CommentEvidenceActor | null) {
  if (actor == null) return { nodeId: null, login: null, type: null };
  const nodeId = aliasedCanonicalString(
    [actor.id, actor.node_id, actor.nodeId],
    'comment actor node ID',
  );
  const login = canonicalNullableString(actor.login ?? null, 'comment actor login');
  const type = aliasedCanonicalString(
    [actor.type, actor.actor_type, actor.actorType, actor.__typename],
    'comment actor type',
  );
  if (nodeId != null && type == null) {
    throw new Error('comment actor node ID requires a canonical actor type');
  }
  return { nodeId, login, type };
}

function aliasedCanonicalString(
  values: unknown[],
  context: string,
): string | null {
  let canonical: string | null = null;
  for (const value of values) {
    const current = canonicalNullableString(value, context);
    if (current == null) continue;
    if (canonical != null && canonical !== current) {
      throw new Error(`${context} aliases conflict`);
    }
    canonical = current;
  }
  return canonical;
}

function canonicalNullableString(value: unknown, context: string): string | null {
  if (value == null) return null;
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    throw new Error(`${context} must be a non-empty canonical string`);
  }
  return value;
}

function canonicalTimestamp(value: unknown, context: string): string {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${context} must be a valid timestamp`);
  }
  return new Date(Date.parse(value)).toISOString();
}

function canonicalSha256Digest(value: unknown, context: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${context} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function strictRecord(
  value: unknown,
  keys: readonly string[],
  context: string,
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${context} must be an object`);
  }
  const record = value as Record<string, unknown>;
  const actualKeys = Object.keys(record).sort();
  const expectedKeys = [...keys].sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error(`${context} has an invalid field set`);
  }
  return record;
}

function firstUnknownKey(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): string | null {
  return Object.keys(value).sort().find((key) => !allowed.has(key)) ?? null;
}
