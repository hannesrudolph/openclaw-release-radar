import { createHash } from 'node:crypto';
import { canonicalJson } from './operationReceipts';
import type {
  GhIssueLabelEvidenceSnapshot,
  GhIssueLabelEvent,
} from './github';

export const ISSUE_LABEL_EVIDENCE_SNAPSHOT_SCHEMA_VERSION = 2 as const;

export interface IssueLabelEvidenceRow {
  readonly connectionOrdinal: number;
  readonly eventNodeId: string;
  readonly action: 'labeled' | 'unlabeled';
  readonly labelName: string;
  readonly labelNodeId: string;
  readonly actorNodeId: string | null;
  readonly actorLogin: string | null;
  readonly actorType: string | null;
  readonly createdAt: string;
  readonly rawJson: string;
  readonly sourceIdentity: string;
  readonly contentHash: string;
}

export interface IssueLabelEvidenceSnapshot {
  readonly snapshotId: string;
  readonly schemaVersion:
    typeof ISSUE_LABEL_EVIDENCE_SNAPSHOT_SCHEMA_VERSION;
  readonly repository: string;
  readonly repositoryNodeId: string;
  readonly issueNumber: number;
  readonly issueNodeId: string;
  readonly capturedAt: string;
  readonly issueUpdatedAt: string;
  readonly totalCount: number;
  readonly fetchedCount: number;
  readonly pageCount: number;
  readonly sweepCount: number;
  readonly stabilized: true;
  readonly rowsContentHash: string;
  readonly sourceIdentity: string;
  readonly contentHash: string;
  readonly rows: readonly IssueLabelEvidenceRow[];
}

export function buildIssueLabelEvidenceSnapshot(
  input: GhIssueLabelEvidenceSnapshot,
): IssueLabelEvidenceSnapshot {
  if (input.schemaVersion !== ISSUE_LABEL_EVIDENCE_SNAPSHOT_SCHEMA_VERSION) {
    throw new TypeError(
      `Issue label evidence schemaVersion must be ` +
        ISSUE_LABEL_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    );
  }
  const repository = normalizeRepository(input.repository);
  const repositoryNodeId = requireIdentity(
    input.repositoryNodeId,
    'issue label evidence repository node ID',
  );
  const issueNodeId = requireIdentity(
    input.issueNodeId,
    'issue label evidence issue node ID',
  );
  if (input.issueNodeType !== 'Issue') {
    throw new TypeError('Issue label evidence issue node type must be Issue');
  }
  if (!Number.isInteger(input.issueNumber) || input.issueNumber <= 0) {
    throw new TypeError('Issue label evidence issue number is invalid');
  }
  const capturedAt = normalizeTimestamp(
    input.capturedAt,
    'issue label evidence capturedAt',
  );
  const issueUpdatedAt = normalizeTimestamp(
    input.issueUpdatedAt,
    'issue label evidence issueUpdatedAt',
  );
  if (
    !Number.isInteger(input.totalCount) ||
    input.totalCount < 0 ||
    !Number.isInteger(input.fetchedCount) ||
    input.fetchedCount < 0 ||
    input.fetchedCount !== input.totalCount
  ) {
    throw new TypeError(
      'Issue label evidence must fetch the complete timeline count',
    );
  }
  if (!Number.isInteger(input.pageCount) || input.pageCount <= 0) {
    throw new TypeError('Issue label evidence pageCount is invalid');
  }
  if (!Number.isInteger(input.sweepCount) || input.sweepCount < 2) {
    throw new TypeError(
      'Issue label evidence requires at least two complete sweeps',
    );
  }
  if (input.stabilized !== true) {
    throw new TypeError('Issue label evidence must be stabilized');
  }
  if (
    !Array.isArray(input.events) ||
    input.events.length !== input.fetchedCount
  ) {
    throw new TypeError(
      'Issue label evidence event count does not match fetchedCount',
    );
  }

  const captureRunHash = sha256(
    `issue-label-evidence-capture-v2\0${canonicalJson([
      repository,
      repositoryNodeId,
      input.issueNumber,
      issueNodeId,
      capturedAt,
      issueUpdatedAt,
      input.totalCount,
      input.fetchedCount,
      input.pageCount,
      input.sweepCount,
    ])}`,
  );
  const seenEventIds = new Set<string>();
  const rows = input.events.map((event, connectionOrdinal) =>
    buildIssueLabelEvidenceRow({
      event,
      connectionOrdinal,
      captureRunHash,
      repositoryNodeId,
      issueNumber: input.issueNumber,
      issueNodeId,
    }));
  for (const row of rows) {
    if (seenEventIds.has(row.eventNodeId)) {
      throw new TypeError(
        `Issue label evidence has duplicate event node ID ${row.eventNodeId}`,
      );
    }
    seenEventIds.add(row.eventNodeId);
  }

  const rowsContentHash = sha256(
    `issue-label-evidence-rows-v2\0${canonicalJson(
      rows.map((row) => [row.connectionOrdinal, row.contentHash]),
    )}`,
  );
  const contentHash = sha256(
    `issue-label-evidence-snapshot-v2\0${canonicalJson([
      repository,
      repositoryNodeId,
      input.issueNumber,
      issueNodeId,
      capturedAt,
      issueUpdatedAt,
      input.totalCount,
      input.fetchedCount,
      input.pageCount,
      input.sweepCount,
      rowsContentHash,
    ])}`,
  );
  return deepFreeze({
    snapshotId: `issue-label-evidence:v2:${contentHash}`,
    schemaVersion: ISSUE_LABEL_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    repository,
    repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId,
    capturedAt,
    issueUpdatedAt,
    totalCount: input.totalCount,
    fetchedCount: input.fetchedCount,
    pageCount: input.pageCount,
    sweepCount: input.sweepCount,
    stabilized: true,
    rowsContentHash,
    sourceIdentity:
      `github-graphql:issue.timelineItems:label-events:v2:${contentHash}`,
    contentHash,
    rows,
  });
}

export function issueLabelEvidenceSnapshotProblems(
  value: IssueLabelEvidenceSnapshot,
): string[] {
  try {
    const rebuilt = buildIssueLabelEvidenceSnapshot({
      schemaVersion: value.schemaVersion,
      repository: value.repository,
      repositoryNodeId: value.repositoryNodeId,
      issueNumber: value.issueNumber,
      issueNodeId: value.issueNodeId,
      issueNodeType: 'Issue',
      capturedAt: value.capturedAt,
      issueUpdatedAt: value.issueUpdatedAt,
      totalCount: value.totalCount,
      fetchedCount: value.fetchedCount,
      pageCount: value.pageCount,
      sweepCount: value.sweepCount,
      stabilized: value.stabilized,
      events: value.rows.map((row) => ({
        issueNumber: value.issueNumber,
        issueNodeId: value.issueNodeId,
        issueNodeType: 'Issue',
        eventId: row.eventNodeId,
        action: row.action,
        labelNodeId: row.labelNodeId,
        labelName: row.labelName,
        actorNodeId: row.actorNodeId,
        actorLogin: row.actorLogin,
        actorType: row.actorType,
        createdAt: row.createdAt,
        raw: JSON.parse(row.rawJson),
      })),
    });
    return canonicalJson(rebuilt) === canonicalJson(value)
      ? []
      : ['issue label evidence immutable metadata does not match its rows'];
  } catch (error) {
    return [error instanceof Error ? error.message : String(error)];
  }
}

function buildIssueLabelEvidenceRow(input: {
  event: GhIssueLabelEvent;
  connectionOrdinal: number;
  captureRunHash: string;
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
}): IssueLabelEvidenceRow {
  const event = input.event;
  if (
    event.issueNumber !== input.issueNumber ||
    event.issueNodeId !== input.issueNodeId ||
    event.issueNodeType !== 'Issue'
  ) {
    throw new TypeError(
      `Issue label event ${event.eventId} does not match snapshot issue identity`,
    );
  }
  const eventNodeId = requireIdentity(
    event.eventId,
    'issue label event node ID',
  );
  const labelNodeId = requireIdentity(
    event.labelNodeId,
    `issue label event ${eventNodeId} label node ID`,
  );
  const labelName = requireText(
    event.labelName,
    `issue label event ${eventNodeId} label name`,
  );
  const createdAt = normalizeTimestamp(
    event.createdAt,
    `issue label event ${eventNodeId} createdAt`,
  );
  const actorNodeId = optionalIdentity(
    event.actorNodeId,
    `issue label event ${eventNodeId} actor node ID`,
  );
  const actorLogin = optionalText(
    event.actorLogin,
    `issue label event ${eventNodeId} actor login`,
  )?.toLowerCase() ?? null;
  const actorType = optionalText(
    event.actorType,
    `issue label event ${eventNodeId} actor type`,
  );
  if (
    [actorNodeId, actorLogin, actorType].filter((value) => value != null)
      .length !== 0 &&
    [actorNodeId, actorLogin, actorType].some((value) => value == null)
  ) {
    throw new TypeError(
      `Issue label event ${eventNodeId} actor identity is incomplete`,
    );
  }
  const rawJson = canonicalJson(event.raw);
  const contentHash = sha256(
    `issue-label-evidence-row-v2\0${canonicalJson([
      input.repositoryNodeId,
      input.issueNumber,
      input.issueNodeId,
      input.captureRunHash,
      input.connectionOrdinal,
      eventNodeId,
      event.action,
      labelName,
      labelNodeId,
      actorNodeId,
      actorLogin,
      actorType,
      createdAt,
      rawJson,
    ])}`,
  );
  return deepFreeze({
    connectionOrdinal: input.connectionOrdinal,
    eventNodeId,
    action: event.action,
    labelName,
    labelNodeId,
    actorNodeId,
    actorLogin,
    actorType,
    createdAt,
    rawJson,
    sourceIdentity:
      `github-graphql:issue.timelineItems:label-event:row:v2:${contentHash}`,
    contentHash,
  });
}

function normalizeRepository(value: string): string {
  const normalized = requireText(
    value,
    'issue label evidence repository',
  ).toLowerCase();
  if (!/^[^/\s]+\/[^/\s]+$/.test(normalized)) {
    throw new TypeError(
      'Issue label evidence repository must be canonical owner/repo',
    );
  }
  return normalized;
}

function normalizeTimestamp(value: string, field: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new TypeError(`${field} is invalid`);
  }
  return new Date(timestamp).toISOString();
}

function requireIdentity(value: unknown, field: string): string {
  const normalized = requireText(value, field);
  if (/\s/.test(normalized)) {
    throw new TypeError(`${field} is non-canonical`);
  }
  return normalized;
}

function optionalIdentity(
  value: unknown,
  field: string,
): string | null {
  if (value == null) return null;
  return requireIdentity(value, field);
}

function optionalText(value: unknown, field: string): string | null {
  if (value == null) return null;
  return requireText(value, field);
}

function requireText(value: unknown, field: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    throw new TypeError(`${field} is missing or non-canonical`);
  }
  return value;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}
