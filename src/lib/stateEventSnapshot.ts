import { createHash } from 'node:crypto';

export const ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION = 3;
const ISSUE_STATE_EVENT_DIGEST_SCHEMA_VERSION = 4;
const ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION = 1;

export interface NormalizedIssueStateEvent {
  eventId: string;
  eventNodeType?: 'ClosedEvent' | 'ReopenedEvent';
  type: 'closed' | 'reopened';
  occurredAt: string;
  connectionOrdinal?: number;
  actorNodeId?: string | null;
  actorLogin: string | null;
  actorType?: string | null;
  stateReason: string | null;
  closerNodeId?: string | null;
  closerType: string | null;
  closerNumber: number | null;
  closerOid: string | null;
}

export interface IssueStateEventDigestIdentity {
  repositoryNodeId?: string | null;
  issueNodeId?: string | null;
  issueNodeType?: string | null;
}

export interface CanonicalStateEventSourceIdentity {
  source: 'github';
  nodeType: 'ClosedEvent' | 'ReopenedEvent';
  nodeId: string;
}

export interface CanonicalStateEventActorIdentity {
  source: 'github';
  nodeType: string;
  nodeId: string;
}

export interface IssueStateEventSweepIdentity {
  schemaVersion: typeof ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION;
  sweepOrdinal: number;
  sweepDigest: string;
  identityDigest: string;
}

export interface IssueStateEventStabilizationIdentity {
  schemaVersion: typeof ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION;
  sweepCount: number;
  firstSweep: IssueStateEventSweepIdentity;
  secondSweep: IssueStateEventSweepIdentity;
  identityDigest: string;
}

function compareBinary(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

export function normalizeIssueStateEvents(
  events: readonly NormalizedIssueStateEvent[],
): NormalizedIssueStateEvent[] {
  const normalized = events.map((event, inputOrdinal) => {
    if (typeof event.eventId !== 'string' || event.eventId.trim() !== event.eventId || !event.eventId) {
      throw new Error('Issue state event is missing a canonical event ID');
    }
    if (event.type !== 'closed' && event.type !== 'reopened') {
      throw new Error(`Issue state event ${event.eventId} has invalid type ${JSON.stringify(event.type)}`);
    }
    const expectedEventNodeType = event.type === 'closed' ? 'ClosedEvent' : 'ReopenedEvent';
    if (
      event.eventNodeType != null &&
      event.eventNodeType !== expectedEventNodeType
    ) {
      throw new Error(
        `Issue state event ${event.eventId} node type ${event.eventNodeType} ` +
        `does not match ${expectedEventNodeType}`,
      );
    }
    const occurredAtEpoch = Date.parse(event.occurredAt);
    if (!event.occurredAt || !Number.isFinite(occurredAtEpoch)) {
      throw new Error(`Issue state event ${event.eventId} has invalid timestamp`);
    }
    const actorNodeId = canonicalNullableString(
      event.actorNodeId ?? null,
      `Issue state event ${event.eventId} actor node ID`,
    );
    const actorLogin = canonicalNullableString(
      event.actorLogin ?? null,
      `Issue state event ${event.eventId} actor login`,
    );
    const actorType = canonicalNullableString(
      event.actorType ?? null,
      `Issue state event ${event.eventId} actor type`,
    );
    if (actorNodeId != null && actorType == null) {
      throw new Error(
        `Issue state event ${event.eventId} actor node ID requires a canonical actor type`,
      );
    }
    const connectionOrdinal = event.connectionOrdinal ?? inputOrdinal;
    if (!Number.isInteger(connectionOrdinal) || connectionOrdinal < 0) {
      throw new Error(`Issue state event ${event.eventId} has invalid connection ordinal`);
    }
    if (event.closerNumber != null && (!Number.isInteger(event.closerNumber) || event.closerNumber <= 0)) {
      throw new Error(`Issue state event ${event.eventId} has invalid closer number`);
    }
    const closerNodeId = canonicalNullableString(
      event.closerNodeId ?? null,
      `Issue state event ${event.eventId} closer node ID`,
    );
    const closerType = canonicalNullableString(
      event.closerType ?? null,
      `Issue state event ${event.eventId} closer type`,
    );
    if ((closerNodeId == null) !== (closerType == null)) {
      throw new Error(
        `Issue state event ${event.eventId} closer identity must include both ` +
        'canonical node ID and node type',
      );
    }
    if (
      closerNodeId == null &&
      (event.closerNumber != null || event.closerOid != null)
    ) {
      throw new Error(
        `Issue state event ${event.eventId} closer details require a canonical closer identity`,
      );
    }
    if (event.type === 'reopened' && (
      event.stateReason != null ||
      closerNodeId != null ||
      closerType != null ||
      event.closerNumber != null ||
      event.closerOid != null
    )) {
      throw new Error(`Reopened issue state event ${event.eventId} contains closer-only evidence`);
    }
    if (
      actorNodeId != null &&
      closerNodeId != null &&
      actorNodeId === closerNodeId &&
      actorType !== closerType
    ) {
      throw new Error(
        `Issue state event ${event.eventId} has conflicting actor and closer node ID ${actorNodeId}`,
      );
    }
    return {
      eventId: event.eventId,
      eventNodeType: event.eventNodeType,
      type: event.type,
      occurredAt: new Date(occurredAtEpoch).toISOString(),
      connectionOrdinal,
      actorNodeId,
      actorLogin,
      actorType,
      stateReason: event.type === 'closed' ? event.stateReason ?? null : null,
      closerNodeId: event.type === 'closed' ? closerNodeId : null,
      closerType: event.type === 'closed' ? closerType : null,
      closerNumber: event.type === 'closed' ? event.closerNumber ?? null : null,
      closerOid: event.type === 'closed' ? event.closerOid ?? null : null,
    };
  });
  const seenIds = new Set<string>();
  const seenOrdinals = new Set<number>();
  for (const event of normalized) {
    if (seenIds.has(event.eventId)) {
      throw new Error(`Issue state event snapshot contains duplicate event ID ${event.eventId}`);
    }
    if (seenOrdinals.has(event.connectionOrdinal)) {
      throw new Error(
        `Issue state event snapshot contains duplicate connection ordinal ${event.connectionOrdinal}`,
      );
    }
    seenIds.add(event.eventId);
    seenOrdinals.add(event.connectionOrdinal);
  }
  const connectionOrdered = normalized.slice().sort((left, right) =>
    left.connectionOrdinal - right.connectionOrdinal ||
    compareBinary(left.eventId, right.eventId));
  for (let ordinal = 0; ordinal < connectionOrdered.length; ordinal++) {
    const event = connectionOrdered[ordinal];
    if (event.connectionOrdinal !== ordinal) {
      throw new Error(
        `Issue state event ${event.eventId} has non-contiguous connection ordinal ` +
        `${event.connectionOrdinal}; expected ${ordinal}`,
      );
    }
    const previous = connectionOrdered[ordinal - 1];
    if (previous && Date.parse(previous.occurredAt) > Date.parse(event.occurredAt)) {
      throw new Error(
        `Issue state event ${event.eventId} is out of chronological connection order after ` +
        `${previous.eventId}`,
      );
    }
  }
  normalized.sort((left, right) => {
    const occurredAtDifference = Date.parse(left.occurredAt) - Date.parse(right.occurredAt);
    return occurredAtDifference ||
      left.connectionOrdinal - right.connectionOrdinal ||
      compareBinary(left.eventId, right.eventId);
  });
  return normalized;
}

export function canonicalStateEventSourceIdentity(
  event: NormalizedIssueStateEvent,
): CanonicalStateEventSourceIdentity | null {
  const normalized = normalizeIssueStateEvents([{
    ...event,
    connectionOrdinal: 0,
  }])[0];
  return normalized.eventNodeType == null
    ? null
    : {
        source: 'github',
        nodeType: normalized.eventNodeType,
        nodeId: normalized.eventId,
      };
}

export function canonicalStateEventActorIdentity(
  event: NormalizedIssueStateEvent,
): CanonicalStateEventActorIdentity | null {
  const normalized = normalizeIssueStateEvents([{
    ...event,
    connectionOrdinal: 0,
  }])[0];
  return normalized.actorNodeId == null || normalized.actorType == null
    ? null
    : {
        source: 'github',
        nodeType: normalized.actorType,
        nodeId: normalized.actorNodeId,
      };
}

export function canonicalStateEventCloserIdentity(
  event: NormalizedIssueStateEvent,
): CanonicalStateEventActorIdentity | null {
  const normalized = normalizeIssueStateEvents([{
    ...event,
    connectionOrdinal: 0,
  }])[0];
  return normalized.closerNodeId == null || normalized.closerType == null
    ? null
    : {
        source: 'github',
        nodeType: normalized.closerType,
        nodeId: normalized.closerNodeId,
      };
}

export function issueStateEventsDigest(
  events: readonly NormalizedIssueStateEvent[],
  identity?: IssueStateEventDigestIdentity,
): string {
  return createHash('sha256')
    .update(JSON.stringify({
      schemaVersion: ISSUE_STATE_EVENT_DIGEST_SCHEMA_VERSION,
      repositoryNodeId: canonicalNullableString(
        identity?.repositoryNodeId ?? null,
        'Issue state event snapshot repository node ID',
      ),
      issueNodeId: canonicalNullableString(
        identity?.issueNodeId ?? null,
        'Issue state event snapshot issue node ID',
      ),
      issueNodeType: canonicalNullableString(
        identity?.issueNodeType ?? null,
        'Issue state event snapshot issue node type',
      ),
      events: normalizeIssueStateEvents(events),
    }))
    .digest('hex');
}

export function issueStateEventSweepDigest(input: {
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: string;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  totalCount: number;
  events: readonly NormalizedIssueStateEvent[];
}): string {
  if (!Number.isInteger(input.issueNumber) || input.issueNumber <= 0) {
    throw new Error(`Issue state event sweep has invalid issue number ${String(input.issueNumber)}`);
  }
  if (input.issueState !== 'open' && input.issueState !== 'closed') {
    throw new Error(`Issue #${input.issueNumber} state event sweep has invalid issue state`);
  }
  const issueUpdatedAtEpoch = Date.parse(input.issueUpdatedAt);
  if (!input.issueUpdatedAt || !Number.isFinite(issueUpdatedAtEpoch)) {
    throw new Error(`Issue #${input.issueNumber} state event sweep has invalid updatedAt`);
  }
  if (!Number.isInteger(input.totalCount) || input.totalCount < 0) {
    throw new Error(`Issue #${input.issueNumber} state event sweep has invalid totalCount`);
  }
  const repositoryNodeId = canonicalNullableString(
    input.repositoryNodeId,
    `Issue #${input.issueNumber} state event sweep repository node ID`,
  );
  if (repositoryNodeId == null) {
    throw new Error(
      `Issue #${input.issueNumber} state event sweep requires a canonical repository node ID`,
    );
  }
  const issueNodeId = canonicalNullableString(
    input.issueNodeId,
    `Issue #${input.issueNumber} state event sweep issue node ID`,
  );
  if (issueNodeId == null) {
    throw new Error(
      `Issue #${input.issueNumber} state event sweep requires a canonical issue node ID`,
    );
  }
  const issueNodeType = canonicalNullableString(
    input.issueNodeType,
    `Issue #${input.issueNumber} state event sweep issue node type`,
  );
  if (issueNodeType !== 'Issue') {
    throw new Error(
      `Issue #${input.issueNumber} state event sweep requires issue node type Issue`,
    );
  }
  const events = normalizeIssueStateEvents(input.events);
  assertAuthoritativeIssueStateEvents(events);
  if (events.length !== input.totalCount) {
    throw new Error(
      `Issue #${input.issueNumber} state event sweep count mismatch: ` +
      `${events.length}/${input.totalCount}`,
    );
  }
  return createHash('sha256')
    .update(JSON.stringify({
      schemaVersion: ISSUE_STATE_EVENT_DIGEST_SCHEMA_VERSION,
      repositoryNodeId,
      issueNumber: input.issueNumber,
      issueNodeId,
      issueNodeType,
      issueState: input.issueState,
      issueUpdatedAt: new Date(issueUpdatedAtEpoch).toISOString(),
      totalCount: input.totalCount,
      events,
    }))
    .digest('hex');
}

export function assertAuthoritativeIssueStateEvents(
  events: readonly NormalizedIssueStateEvent[],
): void {
  for (const event of events) {
    if (!Number.isInteger(event.connectionOrdinal) || event.connectionOrdinal! < 0) {
      throw new Error(
        `Authoritative issue state event ${event.eventId} requires an explicit connection ordinal`,
      );
    }
    const expectedType = event.type === 'closed' ? 'ClosedEvent' : 'ReopenedEvent';
    if (event.eventNodeType !== expectedType) {
      throw new Error(
        `Authoritative issue state event ${event.eventId} requires node type ${expectedType}`,
      );
    }
    if (event.actorNodeId == null || event.actorType == null) {
      throw new Error(
        `Authoritative issue state event ${event.eventId} requires a canonical actor identity`,
      );
    }
  }
}

export function issueStateEventSweepIdentity(input: {
  sweepOrdinal: number;
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
  issueNodeType: string;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  totalCount: number;
  events: readonly NormalizedIssueStateEvent[];
}): IssueStateEventSweepIdentity {
  if (!Number.isInteger(input.sweepOrdinal) || input.sweepOrdinal <= 0) {
    throw new Error('Issue state event sweep ordinal must be a positive integer');
  }
  const sweepDigest = issueStateEventSweepDigest(input);
  const payload = {
    schemaVersion: ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION,
    sweepOrdinal: input.sweepOrdinal,
    sweepDigest,
  } satisfies Omit<IssueStateEventSweepIdentity, 'identityDigest'>;
  return {
    ...payload,
    identityDigest: createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
  };
}

export function issueStateEventStabilizationIdentity(
  firstSweep: IssueStateEventSweepIdentity,
  secondSweep: IssueStateEventSweepIdentity,
  sweepCount: number,
): IssueStateEventStabilizationIdentity {
  if (!Number.isInteger(sweepCount) || sweepCount < 2) {
    throw new Error('Issue state event stabilization sweep count must be at least 2');
  }
  if (
    firstSweep.sweepOrdinal !== sweepCount - 1 ||
    secondSweep.sweepOrdinal !== sweepCount
  ) {
    throw new Error('Issue state event stabilization must bind the final consecutive sweeps');
  }
  if (firstSweep.sweepDigest !== secondSweep.sweepDigest) {
    throw new Error('Issue state event evidence did not stabilize across consecutive sweeps');
  }
  const payload = {
    schemaVersion: ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION,
    sweepCount,
    firstSweep,
    secondSweep,
  } satisfies Omit<IssueStateEventStabilizationIdentity, 'identityDigest'>;
  return {
    ...payload,
    identityDigest: createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
  };
}

export function parseIssueStateEventStabilizationIdentity(
  json: string,
): IssueStateEventStabilizationIdentity {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('Issue state event stabilization JSON is invalid');
  }
  return validateIssueStateEventStabilizationIdentity(parsed);
}

export function validateIssueStateEventStabilizationIdentity(
  value: unknown,
): IssueStateEventStabilizationIdentity {
  const record = strictRecord(
    value,
    [
      'schemaVersion',
      'sweepCount',
      'firstSweep',
      'secondSweep',
      'identityDigest',
    ],
    'Issue state event stabilization',
  );
  if (record.schemaVersion !== ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION) {
    throw new Error('Issue state event stabilization schema version is unsupported');
  }
  if (!Number.isInteger(record.sweepCount) || Number(record.sweepCount) < 2) {
    throw new Error('Issue state event stabilization sweep count must be at least 2');
  }
  const firstSweep = validateIssueStateEventSweepIdentity(
    record.firstSweep,
    'Issue state event stabilization first sweep',
  );
  const secondSweep = validateIssueStateEventSweepIdentity(
    record.secondSweep,
    'Issue state event stabilization second sweep',
  );
  const identityDigest = canonicalSha256Digest(
    record.identityDigest,
    'Issue state event stabilization identity digest',
  );
  const expected = issueStateEventStabilizationIdentity(
    firstSweep,
    secondSweep,
    Number(record.sweepCount),
  );
  if (identityDigest !== expected.identityDigest) {
    throw new Error('Issue state event stabilization identity digest mismatch');
  }
  return expected;
}

function validateIssueStateEventSweepIdentity(
  value: unknown,
  context: string,
): IssueStateEventSweepIdentity {
  const record = strictRecord(
    value,
    [
      'schemaVersion',
      'sweepOrdinal',
      'sweepDigest',
      'identityDigest',
    ],
    context,
  );
  if (record.schemaVersion !== ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION) {
    throw new Error(`${context} schema version is unsupported`);
  }
  if (!Number.isInteger(record.sweepOrdinal) || Number(record.sweepOrdinal) <= 0) {
    throw new Error(`${context} ordinal must be a positive integer`);
  }
  const payload = {
    schemaVersion: ISSUE_STATE_EVENT_STABILIZATION_SCHEMA_VERSION,
    sweepOrdinal: Number(record.sweepOrdinal),
    sweepDigest: canonicalSha256Digest(record.sweepDigest, `${context} sweep digest`),
  } satisfies Omit<IssueStateEventSweepIdentity, 'identityDigest'>;
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
    throw new Error(`${context} contains unknown or missing fields`);
  }
  return record;
}

function canonicalSha256Digest(value: unknown, context: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${context} must be a lowercase SHA-256 digest`);
  }
  return value;
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
