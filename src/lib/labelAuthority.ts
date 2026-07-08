import { createHash } from 'node:crypto';

export const LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION = 2 as const;
export const LABEL_AUTHORITY_POLICY_VERSION = 2 as const;
export const LABEL_AUTHORITY_PERMISSION_MAX_AGE_MS = 24 * 60 * 60 * 1_000;
export const LABEL_AUTHORITY_PURPOSE = 'release_score_label_authority' as const;

export type RepositoryPermission =
  | 'admin'
  | 'maintain'
  | 'write'
  | 'triage'
  | 'read'
  | 'none';

export type LabelAuthority = 'maintainer_human' | 'automation' | 'unknown';
export type LabelAuthorityDecision = 'authorized_for_scoring' | 'denied_for_scoring';

export type LabelAuthoritySource =
  | 'repository_permission'
  | 'approved_roster'
  | 'repository_permission_and_approved_roster'
  | 'actor_identity'
  | 'repository_identity'
  | 'label_event'
  | 'conflicting_evidence'
  | 'invalid_evidence'
  | 'none';

export type LabelAuthorityReason =
  | 'authorized_by_repository_permission'
  | 'authorized_by_approved_roster'
  | 'authorized_by_repository_permission_and_approved_roster'
  | 'actor_is_bot'
  | 'actor_node_id_is_missing'
  | 'repository_node_id_is_missing'
  | 'actor_type_is_missing'
  | 'actor_is_not_user'
  | 'label_event_is_not_application'
  | 'malformed_event_evidence'
  | 'malformed_event_time'
  | 'malformed_authority_evidence'
  | 'conflicting_authority_evidence'
  | 'permission_repository_identity_mismatch'
  | 'permission_actor_identity_mismatch'
  | 'roster_repository_identity_mismatch'
  | 'roster_actor_identity_mismatch'
  | 'current_permission_cannot_prove_prior_authority'
  | 'stale_permission_observation'
  | 'insufficient_repository_permission'
  | 'approved_roster_not_effective_at_event'
  | 'authority_proof_absent';

export interface LabelAuthorityActorEvidence {
  readonly nodeId?: string | null;
  readonly login: string | null;
  readonly type: string | null;
  readonly association?: string | null;
}

export interface LabelAuthorityEventEvidence {
  readonly sourceIdentity: string;
  readonly repositoryNodeId?: string | null;
  readonly repository: string;
  readonly issueNumber: number;
  readonly eventId: string;
  readonly action: 'labeled' | 'unlabeled';
  readonly label: string;
  readonly eventTime: string;
  readonly actor: LabelAuthorityActorEvidence;
}

export interface RepositoryPermissionObservation {
  readonly kind: 'repository_permission_observation';
  readonly evidenceId: string;
  readonly sourceIdentity: string;
  readonly repositoryNodeId?: string | null;
  readonly repository: string;
  readonly actorNodeId?: string | null;
  readonly actorLogin: string;
  readonly actorType: string;
  readonly actorAssociation?: string | null;
  readonly permission: RepositoryPermission;
  readonly observedAt: string;
  readonly sourceOrdinal?: number | null;
  readonly rawJson?: string | null;
  readonly contentHash?: string | null;
  readonly rowHash?: string | null;
  readonly runHash?: string | null;
}

export interface ApprovedMaintainerRosterEntry {
  readonly kind: 'approved_roster_entry';
  readonly evidenceId: string;
  readonly sourceIdentity: string;
  readonly approvalId: string;
  readonly approvedAt: string;
  readonly repositoryNodeId?: string | null;
  readonly repository: string;
  readonly actorNodeId?: string | null;
  readonly actorLogin: string;
  readonly actorType: string;
  readonly actorAssociation?: string | null;
  readonly role: 'maintain' | 'admin';
  readonly effectiveFrom: string;
  readonly effectiveUntil: string | null;
  readonly rosterSequence?: number | null;
  readonly rosterRunDigest?: string | null;
  readonly signerKeyId?: string | null;
  readonly keyringDigest?: string | null;
  readonly signatureVerifiedAt?: string | null;
  readonly entryOrdinal?: number | null;
  readonly rawJson?: string | null;
  readonly contentHash?: string | null;
  readonly rowHash?: string | null;
}

export interface LabelAuthorityEvidence {
  readonly schemaVersion: typeof LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION;
  readonly event: LabelAuthorityEventEvidence;
  readonly permissionObservations?: readonly RepositoryPermissionObservation[];
  readonly approvedRosterEntries?: readonly ApprovedMaintainerRosterEntry[];
}

interface CanonicalLabelAuthorityEventEvidence {
  readonly sourceIdentity: string;
  readonly repositoryNodeId: string | null;
  readonly repository: string;
  readonly issueNumber: number;
  readonly eventId: string;
  readonly action: 'labeled' | 'unlabeled';
  readonly label: string;
  readonly eventTime: string;
  readonly actor: {
    readonly nodeId: string | null;
    readonly login: string | null;
    readonly type: string | null;
    readonly association: string | null;
  };
}

interface CanonicalRepositoryPermissionObservation {
  readonly kind: 'repository_permission_observation';
  readonly evidenceId: string;
  readonly sourceIdentity: string;
  readonly repositoryNodeId: string | null;
  readonly repository: string;
  readonly actorNodeId: string | null;
  readonly actorLogin: string;
  readonly actorType: string;
  readonly actorAssociation: string | null;
  readonly permission: RepositoryPermission;
  readonly observedAt: string;
  readonly sourceOrdinal: number | null;
  readonly rawJson: string | null;
  readonly contentHash: string | null;
  readonly rowHash: string | null;
  readonly runHash: string | null;
}

interface CanonicalApprovedMaintainerRosterEntry {
  readonly kind: 'approved_roster_entry';
  readonly evidenceId: string;
  readonly sourceIdentity: string;
  readonly approvalId: string;
  readonly approvedAt: string;
  readonly repositoryNodeId: string | null;
  readonly repository: string;
  readonly actorNodeId: string | null;
  readonly actorLogin: string;
  readonly actorType: string;
  readonly actorAssociation: string | null;
  readonly role: 'maintain' | 'admin';
  readonly effectiveFrom: string;
  readonly effectiveUntil: string | null;
  readonly rosterSequence: number | null;
  readonly rosterRunDigest: string | null;
  readonly signerKeyId: string | null;
  readonly keyringDigest: string | null;
  readonly signatureVerifiedAt: string | null;
  readonly entryOrdinal: number | null;
  readonly rawJson: string | null;
  readonly contentHash: string | null;
  readonly rowHash: string | null;
}

export interface CanonicalLabelAuthorityEvidence {
  readonly schemaVersion: typeof LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION;
  readonly event: CanonicalLabelAuthorityEventEvidence;
  readonly permissionObservations: readonly CanonicalRepositoryPermissionObservation[];
  readonly approvedRosterEntries: readonly CanonicalApprovedMaintainerRosterEntry[];
}

export interface LabelAuthorityResolution {
  readonly purpose: typeof LABEL_AUTHORITY_PURPOSE;
  readonly decision: LabelAuthorityDecision;
  readonly label: string;
  readonly eventId: string;
  readonly eventTime: string;
  readonly repositoryNodeId: string | null;
  readonly actorNodeId: string | null;
  readonly actorLogin: string | null;
  readonly actorType: string | null;
  readonly actorAssociation: string | null;
  readonly authority: LabelAuthority;
  readonly source: LabelAuthoritySource;
  readonly policyVersion: typeof LABEL_AUTHORITY_POLICY_VERSION;
  readonly reason: LabelAuthorityReason;
  readonly proofIds: readonly string[];
  readonly evidenceDigest: string;
  readonly authorizedForScoring: boolean;
}

export interface PartitionedLabelAuthority {
  readonly displayLabels: readonly string[];
  readonly authorizedScoringLabels: readonly string[];
}

const PERMISSION_KINDS = new Set<RepositoryPermission>([
  'admin',
  'maintain',
  'write',
  'triage',
  'read',
  'none',
]);
const AUTHORIZING_PERMISSIONS = new Set<RepositoryPermission>(['admin', 'maintain']);
const ACTOR_TYPES = new Set([
  'User',
  'Bot',
  'Mannequin',
  'Organization',
  'EnterpriseUserAccount',
]);
const EVIDENCE_KEYS = new Set([
  'schemaVersion',
  'event',
  'permissionObservations',
  'approvedRosterEntries',
]);
const EVENT_KEYS = new Set([
  'sourceIdentity',
  'repositoryNodeId',
  'repository',
  'issueNumber',
  'eventId',
  'action',
  'label',
  'eventTime',
  'actor',
]);
const ACTOR_KEYS = new Set(['nodeId', 'login', 'type', 'association']);
const PERMISSION_KEYS = new Set([
  'kind',
  'evidenceId',
  'sourceIdentity',
  'repositoryNodeId',
  'repository',
  'actorNodeId',
  'actorLogin',
  'actorType',
  'actorAssociation',
  'permission',
  'observedAt',
  'sourceOrdinal',
  'rawJson',
  'contentHash',
  'rowHash',
  'runHash',
]);
const ROSTER_KEYS = new Set([
  'kind',
  'evidenceId',
  'sourceIdentity',
  'approvalId',
  'approvedAt',
  'repositoryNodeId',
  'repository',
  'actorNodeId',
  'actorLogin',
  'actorType',
  'actorAssociation',
  'role',
  'effectiveFrom',
  'effectiveUntil',
  'rosterSequence',
  'rosterRunDigest',
  'signerKeyId',
  'keyringDigest',
  'signatureVerifiedAt',
  'entryOrdinal',
  'rawJson',
  'contentHash',
  'rowHash',
]);
const RESOLUTION_KEYS = new Set([
  'purpose',
  'decision',
  'label',
  'eventId',
  'eventTime',
  'repositoryNodeId',
  'actorNodeId',
  'actorLogin',
  'actorType',
  'actorAssociation',
  'authority',
  'source',
  'policyVersion',
  'reason',
  'proofIds',
  'evidenceDigest',
  'authorizedForScoring',
]);
const REASONS = new Set<LabelAuthorityReason>([
  'authorized_by_repository_permission',
  'authorized_by_approved_roster',
  'authorized_by_repository_permission_and_approved_roster',
  'actor_is_bot',
  'actor_node_id_is_missing',
  'repository_node_id_is_missing',
  'actor_type_is_missing',
  'actor_is_not_user',
  'label_event_is_not_application',
  'malformed_event_evidence',
  'malformed_event_time',
  'malformed_authority_evidence',
  'conflicting_authority_evidence',
  'permission_repository_identity_mismatch',
  'permission_actor_identity_mismatch',
  'roster_repository_identity_mismatch',
  'roster_actor_identity_mismatch',
  'current_permission_cannot_prove_prior_authority',
  'stale_permission_observation',
  'insufficient_repository_permission',
  'approved_roster_not_effective_at_event',
  'authority_proof_absent',
]);
const AUTHORIZING_REASON_SOURCES = new Map<
  LabelAuthorityReason,
  LabelAuthoritySource
>([
  ['authorized_by_repository_permission', 'repository_permission'],
  ['authorized_by_approved_roster', 'approved_roster'],
  [
    'authorized_by_repository_permission_and_approved_roster',
    'repository_permission_and_approved_roster',
  ],
]);

export function repositoryPermissionObservationRowHash(
  observation: RepositoryPermissionObservation,
): string {
  return sha256(
    `repository-permission-observation-row-v2\0${canonicalJson([
      observation.repositoryNodeId ?? null,
      normalizeRepository(observation.repository),
      observation.actorNodeId ?? null,
      normalizeLogin(observation.actorLogin) ?? '',
      observation.actorType,
      normalizeOptionalText(observation.actorAssociation),
      observation.permission,
      normalizeTimestamp(observation.observedAt),
    ])}`,
  );
}

export function approvedMaintainerRosterEntryRowHash(
  entry: ApprovedMaintainerRosterEntry,
): string {
  return sha256(
    `approved-maintainer-roster-entry-row-v2\0${canonicalJson([
      entry.approvalId,
      normalizeTimestamp(entry.approvedAt),
      entry.repositoryNodeId ?? null,
      normalizeRepository(entry.repository),
      entry.actorNodeId ?? null,
      normalizeLogin(entry.actorLogin) ?? '',
      entry.actorType,
      normalizeOptionalText(entry.actorAssociation),
      entry.role,
      normalizeTimestamp(entry.effectiveFrom),
      entry.effectiveUntil == null ? null : normalizeTimestamp(entry.effectiveUntil),
      entry.rosterSequence ?? null,
      entry.signerKeyId ?? null,
      entry.keyringDigest ?? null,
    ])}`,
  );
}

export function canonicalLabelAuthorityEvidence(
  evidence: LabelAuthorityEvidence,
): CanonicalLabelAuthorityEvidence {
  const event = evidence.event;
  return deepFreeze({
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: event.sourceIdentity,
      repositoryNodeId: event.repositoryNodeId ?? null,
      repository: normalizeRepository(event.repository),
      issueNumber: event.issueNumber,
      eventId: event.eventId,
      action: event.action,
      label: event.label,
      eventTime: normalizeTimestamp(event.eventTime),
      actor: {
        nodeId: event.actor?.nodeId ?? null,
        login: normalizeLogin(event.actor?.login ?? null),
        type: event.actor?.type ?? null,
        association: normalizeOptionalText(event.actor?.association),
      },
    },
    permissionObservations: [...(evidence.permissionObservations ?? [])]
      .map((observation) => ({
        kind: observation.kind,
        evidenceId: observation.evidenceId,
        sourceIdentity: observation.sourceIdentity,
        repositoryNodeId: observation.repositoryNodeId ?? null,
        repository: normalizeRepository(observation.repository),
        actorNodeId: observation.actorNodeId ?? null,
        actorLogin: normalizeLogin(observation.actorLogin) ?? '',
        actorType: observation.actorType,
        actorAssociation: normalizeOptionalText(observation.actorAssociation),
        permission: observation.permission,
        observedAt: normalizeTimestamp(observation.observedAt),
        sourceOrdinal: observation.sourceOrdinal ?? null,
        rawJson: observation.rawJson ?? null,
        contentHash: observation.contentHash ?? null,
        rowHash: observation.rowHash ?? null,
        runHash: observation.runHash ?? null,
      }))
      .sort(comparePermissionEvidence),
    approvedRosterEntries: [...(evidence.approvedRosterEntries ?? [])]
      .map((entry) => ({
        kind: entry.kind,
        evidenceId: entry.evidenceId,
        sourceIdentity: entry.sourceIdentity,
        approvalId: entry.approvalId,
        approvedAt: normalizeTimestamp(entry.approvedAt),
        repositoryNodeId: entry.repositoryNodeId ?? null,
        repository: normalizeRepository(entry.repository),
        actorNodeId: entry.actorNodeId ?? null,
        actorLogin: normalizeLogin(entry.actorLogin) ?? '',
        actorType: entry.actorType,
        actorAssociation: normalizeOptionalText(entry.actorAssociation),
        role: entry.role,
        effectiveFrom: normalizeTimestamp(entry.effectiveFrom),
        effectiveUntil: entry.effectiveUntil == null
          ? null
          : normalizeTimestamp(entry.effectiveUntil),
        rosterSequence: entry.rosterSequence ?? null,
        rosterRunDigest: entry.rosterRunDigest ?? null,
        signerKeyId: entry.signerKeyId ?? null,
        keyringDigest: entry.keyringDigest ?? null,
        signatureVerifiedAt: entry.signatureVerifiedAt == null
          ? null
          : normalizeTimestamp(entry.signatureVerifiedAt),
        entryOrdinal: entry.entryOrdinal ?? null,
        rawJson: entry.rawJson ?? null,
        contentHash: entry.contentHash ?? null,
        rowHash: entry.rowHash ?? null,
      }))
      .sort(compareRosterEvidence),
  });
}

export function canonicalLabelAuthorityEvidenceJson(
  evidence: LabelAuthorityEvidence,
): string {
  return JSON.stringify(canonicalLabelAuthorityEvidence(evidence));
}

export function labelAuthorityEvidenceDigest(evidence: LabelAuthorityEvidence): string {
  return sha256(
    `label-authority-evidence-v${LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION}\0` +
      canonicalLabelAuthorityEvidenceJson(evidence),
  );
}

export function labelAuthorityEvidenceProblems(value: unknown): string[] {
  if (!isRecord(value)) return ['evidence must be an object'];
  const problems: string[] = [];
  addUnknownKeyProblems(value, EVIDENCE_KEYS, 'evidence', problems);
  if (value.schemaVersion !== LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION) {
    problems.push(
      `schemaVersion must be ${LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION}`,
    );
  }
  problems.push(...labelAuthorityEventProblems(value.event));

  const permissions = value.permissionObservations ?? [];
  if (!Array.isArray(permissions)) {
    problems.push('permissionObservations must be an array');
  } else {
    permissions.forEach((item, index) => {
      problems.push(...permissionObservationProblems(item, index));
    });
  }

  const roster = value.approvedRosterEntries ?? [];
  if (!Array.isArray(roster)) {
    problems.push('approvedRosterEntries must be an array');
  } else {
    roster.forEach((item, index) => {
      problems.push(...approvedRosterEntryProblems(item, index));
    });
  }

  if (isRecord(value.event) && isRecord(value.event.actor)) {
    const repositoryNodeId = value.event.repositoryNodeId;
    const actorNodeId = value.event.actor.nodeId;
    if (typeof repositoryNodeId === 'string' && typeof actorNodeId === 'string') {
      if (Array.isArray(permissions)) {
        for (let index = 0; index < permissions.length; index++) {
          const item = permissions[index];
          if (!isRecord(item)) continue;
          if (
            typeof item.repositoryNodeId === 'string' &&
            item.repositoryNodeId !== repositoryNodeId
          ) {
            problems.push(
              `permissionObservations[${index}] repositoryNodeId does not match event`,
            );
          }
          if (
            typeof item.actorNodeId === 'string' &&
            item.actorNodeId !== actorNodeId
          ) {
            problems.push(
              `permissionObservations[${index}] actorNodeId does not match event`,
            );
          }
        }
      }
      if (Array.isArray(roster)) {
        for (let index = 0; index < roster.length; index++) {
          const item = roster[index];
          if (!isRecord(item)) continue;
          if (
            typeof item.repositoryNodeId === 'string' &&
            item.repositoryNodeId !== repositoryNodeId
          ) {
            problems.push(
              `approvedRosterEntries[${index}] repositoryNodeId does not match event`,
            );
          }
          if (
            typeof item.actorNodeId === 'string' &&
            item.actorNodeId !== actorNodeId
          ) {
            problems.push(
              `approvedRosterEntries[${index}] actorNodeId does not match event`,
            );
          }
        }
      }
    }
  }

  const allEvidence = [
    ...(Array.isArray(permissions) ? permissions : []),
    ...(Array.isArray(roster) ? roster : []),
  ];
  for (const field of ['evidenceId', 'sourceIdentity', 'rowHash'] as const) {
    const seen = new Set<string>();
    for (const item of allEvidence) {
      if (!isRecord(item) || typeof item[field] !== 'string' || !item[field]) continue;
      if (seen.has(item[field])) {
        problems.push(`authority evidence has duplicate ${field} ${item[field]}`);
      }
      seen.add(item[field]);
    }
  }
  return problems;
}

export function resolveLabelAuthority(
  evidence: LabelAuthorityEvidence,
): LabelAuthorityResolution {
  const canonical = canonicalLabelAuthorityEvidence(evidence);
  const event = canonical.event;
  const base = {
    purpose: LABEL_AUTHORITY_PURPOSE,
    label: event.label,
    eventId: event.eventId,
    eventTime: event.eventTime,
    repositoryNodeId: event.repositoryNodeId,
    actorNodeId: event.actor.nodeId,
    actorLogin: event.actor.login,
    actorType: event.actor.type,
    actorAssociation: event.actor.association,
    policyVersion: LABEL_AUTHORITY_POLICY_VERSION,
    proofIds: authorityProofIds(canonical),
    evidenceDigest: labelAuthorityEvidenceDigest(evidence),
  } as const;

  if (!isTimestamp(evidence.event?.eventTime)) {
    return resolution(base, 'unknown', 'invalid_evidence', 'malformed_event_time', false);
  }
  if (event.action !== 'labeled') {
    return resolution(base, 'unknown', 'label_event', 'label_event_is_not_application', false);
  }
  if (event.actor.type === 'Bot') {
    return resolution(base, 'automation', 'actor_identity', 'actor_is_bot', false);
  }
  if (event.actor.nodeId == null) {
    return resolution(base, 'unknown', 'actor_identity', 'actor_node_id_is_missing', false);
  }
  if (event.repositoryNodeId == null) {
    return resolution(
      base,
      'unknown',
      'repository_identity',
      'repository_node_id_is_missing',
      false,
    );
  }
  if (event.actor.type == null) {
    return resolution(base, 'unknown', 'actor_identity', 'actor_type_is_missing', false);
  }
  if (event.actor.type !== 'User') {
    return resolution(base, 'unknown', 'actor_identity', 'actor_is_not_user', false);
  }

  const eventProblems = labelAuthorityEventProblems(evidence.event)
    .filter((problem) =>
      !problem.includes('actor nodeId is missing') &&
      !problem.includes('repositoryNodeId is missing'));
  if (eventProblems.length > 0) {
    return resolution(
      base,
      'unknown',
      'invalid_evidence',
      'malformed_event_evidence',
      false,
    );
  }

  const permissionRepositoryMismatch = canonical.permissionObservations.some((item) =>
    item.repositoryNodeId != null &&
    item.repositoryNodeId !== event.repositoryNodeId);
  if (permissionRepositoryMismatch) {
    return resolution(
      base,
      'unknown',
      'conflicting_evidence',
      'permission_repository_identity_mismatch',
      false,
    );
  }
  const permissionActorMismatch = canonical.permissionObservations.some((item) =>
    item.actorNodeId != null && item.actorNodeId !== event.actor.nodeId);
  if (permissionActorMismatch) {
    return resolution(
      base,
      'unknown',
      'conflicting_evidence',
      'permission_actor_identity_mismatch',
      false,
    );
  }
  const rosterRepositoryMismatch = canonical.approvedRosterEntries.some((item) =>
    item.repositoryNodeId != null &&
    item.repositoryNodeId !== event.repositoryNodeId);
  if (rosterRepositoryMismatch) {
    return resolution(
      base,
      'unknown',
      'conflicting_evidence',
      'roster_repository_identity_mismatch',
      false,
    );
  }
  const rosterActorMismatch = canonical.approvedRosterEntries.some((item) =>
    item.actorNodeId != null && item.actorNodeId !== event.actor.nodeId);
  if (rosterActorMismatch) {
    return resolution(
      base,
      'unknown',
      'conflicting_evidence',
      'roster_actor_identity_mismatch',
      false,
    );
  }

  const authorityProblems = labelAuthorityEvidenceProblems(evidence).filter((problem) =>
    !problem.startsWith('event '));
  if (authorityProblems.length > 0) {
    const conflicting = authorityProblems.some((problem) =>
      problem.includes('duplicate evidenceId') ||
      problem.includes('duplicate sourceIdentity') ||
      problem.includes('duplicate rowHash'));
    return resolution(
      base,
      'unknown',
      conflicting ? 'conflicting_evidence' : 'invalid_evidence',
      conflicting
        ? 'conflicting_authority_evidence'
        : 'malformed_authority_evidence',
      false,
    );
  }

  const eventMs = Date.parse(event.eventTime);
  const permissions = canonical.permissionObservations;
  const priorPermissions = permissions.filter((item) =>
    Date.parse(item.observedAt) <= eventMs);
  const freshPermissions = priorPermissions.filter((item) =>
    eventMs - Date.parse(item.observedAt) <= LABEL_AUTHORITY_PERMISSION_MAX_AGE_MS);
  const latestPermissionMs = freshPermissions.reduce(
    (latest, item) => Math.max(latest, Date.parse(item.observedAt)),
    Number.NEGATIVE_INFINITY,
  );
  const latestPermissions = freshPermissions.filter((item) =>
    Date.parse(item.observedAt) === latestPermissionMs);
  const latestHasAuthority = latestPermissions.some((item) =>
    AUTHORIZING_PERMISSIONS.has(item.permission));
  const latestHasInsufficient = latestPermissions.some((item) =>
    !AUTHORIZING_PERMISSIONS.has(item.permission));
  const permissionConflict = latestHasAuthority && latestHasInsufficient;
  const permissionAuthorized = latestPermissions.length > 0 &&
    latestHasAuthority &&
    !latestHasInsufficient;

  const activeRoster = canonical.approvedRosterEntries.filter((entry) => {
    const effectiveFrom = Date.parse(entry.effectiveFrom);
    const effectiveUntil = entry.effectiveUntil == null
      ? Number.POSITIVE_INFINITY
      : Date.parse(entry.effectiveUntil);
    return effectiveFrom <= eventMs && eventMs <= effectiveUntil;
  });
  const rosterAuthorized = activeRoster.length > 0;

  if (permissionConflict || (rosterAuthorized && latestHasInsufficient)) {
    return resolution(
      base,
      'unknown',
      'conflicting_evidence',
      'conflicting_authority_evidence',
      false,
    );
  }
  if (permissionAuthorized && rosterAuthorized) {
    return resolution(
      base,
      'maintainer_human',
      'repository_permission_and_approved_roster',
      'authorized_by_repository_permission_and_approved_roster',
      true,
    );
  }
  if (permissionAuthorized) {
    return resolution(
      base,
      'maintainer_human',
      'repository_permission',
      'authorized_by_repository_permission',
      true,
    );
  }
  if (rosterAuthorized) {
    return resolution(
      base,
      'maintainer_human',
      'approved_roster',
      'authorized_by_approved_roster',
      true,
    );
  }
  if (latestHasInsufficient) {
    return resolution(
      base,
      'unknown',
      'repository_permission',
      'insufficient_repository_permission',
      false,
    );
  }
  if (priorPermissions.length > 0) {
    return resolution(
      base,
      'unknown',
      'repository_permission',
      'stale_permission_observation',
      false,
    );
  }
  if (permissions.length > 0) {
    return resolution(
      base,
      'unknown',
      'repository_permission',
      'current_permission_cannot_prove_prior_authority',
      false,
    );
  }
  if (canonical.approvedRosterEntries.length > 0) {
    return resolution(
      base,
      'unknown',
      'approved_roster',
      'approved_roster_not_effective_at_event',
      false,
    );
  }
  return resolution(base, 'unknown', 'none', 'authority_proof_absent', false);
}

export function partitionLabelAuthority(
  resolutions: readonly LabelAuthorityResolution[],
): PartitionedLabelAuthority {
  const byLabel = new Map<string, LabelAuthorityResolution[]>();
  for (const item of resolutions) {
    if (typeof item.label !== 'string' || !item.label.trim()) continue;
    const rows = byLabel.get(item.label) ?? [];
    rows.push(item);
    byLabel.set(item.label, rows);
  }
  const displayLabels = [...byLabel.keys()].sort(compareBinary);
  const authorizedScoringLabels = displayLabels.filter((label) => {
    const rows = byLabel.get(label) ?? [];
    return rows.length > 0 && rows.every((item) =>
      item.authorizedForScoring &&
      item.decision === 'authorized_for_scoring' &&
      item.authority === 'maintainer_human');
  });
  return deepFreeze({ displayLabels, authorizedScoringLabels });
}

export function canonicalLabelAuthorityResolutionJson(
  value: LabelAuthorityResolution,
): string {
  return JSON.stringify({
    purpose: value.purpose,
    decision: value.decision,
    label: value.label,
    eventId: value.eventId,
    eventTime: value.eventTime,
    repositoryNodeId: value.repositoryNodeId,
    actorNodeId: value.actorNodeId,
    actorLogin: value.actorLogin,
    actorType: value.actorType,
    actorAssociation: value.actorAssociation,
    authority: value.authority,
    source: value.source,
    policyVersion: value.policyVersion,
    reason: value.reason,
    proofIds: [...value.proofIds].sort(compareBinary),
    evidenceDigest: value.evidenceDigest,
    authorizedForScoring: value.authorizedForScoring,
  });
}

export function labelAuthorityResolutionProblems(
  value: unknown,
  evidence?: LabelAuthorityEvidence,
): string[] {
  if (!isRecord(value)) return ['resolution must be an object'];
  const problems: string[] = [];
  addUnknownKeyProblems(value, RESOLUTION_KEYS, 'resolution', problems);
  if (value.purpose !== LABEL_AUTHORITY_PURPOSE) {
    problems.push(`resolution purpose must be ${LABEL_AUTHORITY_PURPOSE}`);
  }
  if (
    value.decision !== 'authorized_for_scoring' &&
    value.decision !== 'denied_for_scoring'
  ) {
    problems.push('resolution decision is invalid');
  }
  if (!isNormalizedText(value.label)) problems.push('resolution label is invalid');
  if (!isNormalizedText(value.eventId)) problems.push('resolution eventId is invalid');
  if (!isTimestamp(value.eventTime)) problems.push('resolution eventTime is invalid');
  if (!(value.repositoryNodeId == null || isNodeId(value.repositoryNodeId))) {
    problems.push('resolution repositoryNodeId is invalid');
  }
  if (!(value.actorNodeId == null || isNodeId(value.actorNodeId))) {
    problems.push('resolution actorNodeId is invalid');
  }
  if (!(value.actorLogin == null || isLogin(value.actorLogin))) {
    problems.push('resolution actorLogin is invalid');
  }
  if (!(value.actorType == null || ACTOR_TYPES.has(String(value.actorType)))) {
    problems.push('resolution actorType is invalid');
  }
  if (!(value.actorAssociation == null || isNormalizedText(value.actorAssociation))) {
    problems.push('resolution actorAssociation is invalid');
  }
  if (!['maintainer_human', 'automation', 'unknown'].includes(String(value.authority))) {
    problems.push('resolution authority is invalid');
  }
  if (![
    'repository_permission',
    'approved_roster',
    'repository_permission_and_approved_roster',
    'actor_identity',
    'repository_identity',
    'label_event',
    'conflicting_evidence',
    'invalid_evidence',
    'none',
  ].includes(String(value.source))) {
    problems.push('resolution source is invalid');
  }
  if (value.policyVersion !== LABEL_AUTHORITY_POLICY_VERSION) {
    problems.push(`resolution policyVersion must be ${LABEL_AUTHORITY_POLICY_VERSION}`);
  }
  if (!REASONS.has(value.reason as LabelAuthorityReason)) {
    problems.push('resolution reason is invalid');
  }
  if (
    !Array.isArray(value.proofIds) ||
    value.proofIds.some((item) => !isNormalizedText(item)) ||
    !isSortedUnique(value.proofIds)
  ) {
    problems.push('resolution proofIds must be sorted unique normalized strings');
  }
  if (!isSha256(value.evidenceDigest)) {
    problems.push('resolution evidenceDigest must be SHA-256');
  }
  if (typeof value.authorizedForScoring !== 'boolean') {
    problems.push('resolution authorizedForScoring must be boolean');
  }
  if (
    (value.decision === 'authorized_for_scoring') !==
      (value.authorizedForScoring === true)
  ) {
    problems.push('resolution decision and scoring flag disagree');
  }
  const authorizingSource = AUTHORIZING_REASON_SOURCES.get(
    value.reason as LabelAuthorityReason,
  );
  if (value.decision === 'authorized_for_scoring') {
    if (value.authority !== 'maintainer_human') {
      problems.push('authorized scoring decisions require maintainer_human authority');
    }
    if (!authorizingSource) {
      problems.push('authorized scoring decisions require an authorizing reason');
    } else if (value.source !== authorizingSource) {
      problems.push('authorized scoring reason does not match its authority source');
    }
  }
  if (value.decision === 'denied_for_scoring') {
    if (value.authority === 'maintainer_human') {
      problems.push('denied scoring decisions cannot have maintainer_human authority');
    }
    if (authorizingSource) {
      problems.push('denied scoring decisions cannot use an authorizing reason');
    }
  }
  if (evidence && problems.length === 0) {
    const expected = resolveLabelAuthority(evidence);
    if (
      canonicalLabelAuthorityResolutionJson(value as unknown as LabelAuthorityResolution) !==
      canonicalLabelAuthorityResolutionJson(expected)
    ) {
      problems.push('resolution does not match canonical evidence resolution');
    }
  }
  return problems;
}

function labelAuthorityEventProblems(value: unknown): string[] {
  if (!isRecord(value)) return ['event must be an object'];
  const problems: string[] = [];
  addUnknownKeyProblems(value, EVENT_KEYS, 'event', problems);
  if (!isSourceIdentity(value.sourceIdentity)) {
    problems.push('event sourceIdentity must be a normalized non-empty string');
  }
  if (value.repositoryNodeId == null) {
    problems.push('event repositoryNodeId is missing');
  } else if (!isNodeId(value.repositoryNodeId)) {
    problems.push('event repositoryNodeId is invalid');
  }
  if (!isRepository(value.repository)) {
    problems.push('event repository must be canonical owner/repo');
  }
  if (!Number.isInteger(value.issueNumber) || Number(value.issueNumber) <= 0) {
    problems.push('event issueNumber must be a positive integer');
  }
  if (!isNormalizedText(value.eventId)) problems.push('event eventId is invalid');
  if (value.action !== 'labeled' && value.action !== 'unlabeled') {
    problems.push('event action must be labeled or unlabeled');
  }
  if (!isNormalizedText(value.label)) problems.push('event label is invalid');
  if (!isTimestamp(value.eventTime)) problems.push('event eventTime must be a valid timestamp');
  if (!isRecord(value.actor)) {
    problems.push('event actor must be an object');
  } else {
    addUnknownKeyProblems(value.actor, ACTOR_KEYS, 'event actor', problems);
    if (value.actor.nodeId == null) {
      problems.push('event actor nodeId is missing');
    } else if (!isNodeId(value.actor.nodeId)) {
      problems.push('event actor nodeId is invalid');
    }
    if (!(value.actor.login == null || isLogin(value.actor.login))) {
      problems.push('event actor login is invalid');
    }
    if (
      !(value.actor.type == null ||
        (typeof value.actor.type === 'string' && ACTOR_TYPES.has(value.actor.type)))
    ) {
      problems.push('event actor type is invalid');
    }
    if (!(value.actor.association == null || isNormalizedText(value.actor.association))) {
      problems.push('event actor association is invalid');
    }
  }
  return problems;
}

function permissionObservationProblems(value: unknown, index: number): string[] {
  const prefix = `permissionObservations[${index}]`;
  if (!isRecord(value)) return [`${prefix} must be an object`];
  const problems: string[] = [];
  addUnknownKeyProblems(value, PERMISSION_KEYS, prefix, problems);
  if (value.kind !== 'repository_permission_observation') {
    problems.push(`${prefix} kind is invalid`);
  }
  if (!isNormalizedText(value.evidenceId)) problems.push(`${prefix} evidenceId is invalid`);
  if (!isSourceIdentity(value.sourceIdentity)) problems.push(`${prefix} sourceIdentity is invalid`);
  if (!isNodeId(value.repositoryNodeId)) problems.push(`${prefix} repositoryNodeId is invalid`);
  if (!isRepository(value.repository)) problems.push(`${prefix} repository is invalid`);
  if (!isNodeId(value.actorNodeId)) problems.push(`${prefix} actorNodeId is invalid`);
  if (!isLogin(value.actorLogin)) problems.push(`${prefix} actorLogin is invalid`);
  if (value.actorType !== 'User') problems.push(`${prefix} actorType must be User`);
  if (!(value.actorAssociation == null || isNormalizedText(value.actorAssociation))) {
    problems.push(`${prefix} actorAssociation is invalid`);
  }
  if (!PERMISSION_KINDS.has(value.permission as RepositoryPermission)) {
    problems.push(`${prefix} permission is invalid`);
  }
  if (!isTimestamp(value.observedAt)) problems.push(`${prefix} observedAt is invalid`);
  if (
    !(value.sourceOrdinal == null ||
      (Number.isInteger(value.sourceOrdinal) && Number(value.sourceOrdinal) >= 0))
  ) {
    problems.push(`${prefix} sourceOrdinal is invalid`);
  }
  if (!(value.rawJson == null || isCanonicalJson(value.rawJson))) {
    problems.push(`${prefix} rawJson must be canonical JSON`);
  }
  if (!isSha256(value.rowHash)) {
    problems.push(`${prefix} rowHash must be SHA-256`);
  } else if (
    value.rowHash !==
    repositoryPermissionObservationRowHash(
      value as unknown as RepositoryPermissionObservation,
    )
  ) {
    problems.push(`${prefix} rowHash does not match canonical row`);
  }
  if (!(value.contentHash == null || value.contentHash === value.rowHash)) {
    problems.push(`${prefix} contentHash must equal rowHash`);
  }
  if (!isSha256(value.runHash)) problems.push(`${prefix} runHash must be SHA-256`);
  return problems;
}

function approvedRosterEntryProblems(value: unknown, index: number): string[] {
  const prefix = `approvedRosterEntries[${index}]`;
  if (!isRecord(value)) return [`${prefix} must be an object`];
  const problems: string[] = [];
  addUnknownKeyProblems(value, ROSTER_KEYS, prefix, problems);
  if (value.kind !== 'approved_roster_entry') problems.push(`${prefix} kind is invalid`);
  if (!isNormalizedText(value.evidenceId)) problems.push(`${prefix} evidenceId is invalid`);
  if (!isSourceIdentity(value.sourceIdentity)) problems.push(`${prefix} sourceIdentity is invalid`);
  if (!isNormalizedText(value.approvalId)) problems.push(`${prefix} approvalId is invalid`);
  if (!isTimestamp(value.approvedAt)) problems.push(`${prefix} approvedAt is invalid`);
  if (!isNodeId(value.repositoryNodeId)) problems.push(`${prefix} repositoryNodeId is invalid`);
  if (!isRepository(value.repository)) problems.push(`${prefix} repository is invalid`);
  if (!isNodeId(value.actorNodeId)) problems.push(`${prefix} actorNodeId is invalid`);
  if (!isLogin(value.actorLogin)) problems.push(`${prefix} actorLogin is invalid`);
  if (value.actorType !== 'User') problems.push(`${prefix} actorType must be User`);
  if (!(value.actorAssociation == null || isNormalizedText(value.actorAssociation))) {
    problems.push(`${prefix} actorAssociation is invalid`);
  }
  if (value.role !== 'maintain' && value.role !== 'admin') {
    problems.push(`${prefix} role must be maintain or admin`);
  }
  if (!isTimestamp(value.effectiveFrom)) problems.push(`${prefix} effectiveFrom is invalid`);
  if (!(value.effectiveUntil == null || isTimestamp(value.effectiveUntil))) {
    problems.push(`${prefix} effectiveUntil is invalid`);
  }
  if (
    isTimestamp(value.effectiveFrom) &&
    isTimestamp(value.effectiveUntil) &&
    Date.parse(value.effectiveUntil) < Date.parse(value.effectiveFrom)
  ) {
    problems.push(`${prefix} effectiveUntil precedes effectiveFrom`);
  }
  if (!Number.isInteger(value.rosterSequence) || Number(value.rosterSequence) <= 0) {
    problems.push(`${prefix} rosterSequence must be a positive integer`);
  }
  if (!isSha256(value.rosterRunDigest)) {
    problems.push(`${prefix} rosterRunDigest must be SHA-256`);
  }
  if (!isNormalizedText(value.signerKeyId)) problems.push(`${prefix} signerKeyId is invalid`);
  if (!isSha256(value.keyringDigest)) problems.push(`${prefix} keyringDigest must be SHA-256`);
  if (!isTimestamp(value.signatureVerifiedAt)) {
    problems.push(`${prefix} signatureVerifiedAt is invalid`);
  }
  if (
    !(value.entryOrdinal == null ||
      (Number.isInteger(value.entryOrdinal) && Number(value.entryOrdinal) >= 0))
  ) {
    problems.push(`${prefix} entryOrdinal is invalid`);
  }
  if (!(value.rawJson == null || isCanonicalJson(value.rawJson))) {
    problems.push(`${prefix} rawJson must be canonical JSON`);
  }
  if (!isSha256(value.rowHash)) {
    problems.push(`${prefix} rowHash must be SHA-256`);
  } else if (
    value.rowHash !==
    approvedMaintainerRosterEntryRowHash(
      value as unknown as ApprovedMaintainerRosterEntry,
    )
  ) {
    problems.push(`${prefix} rowHash does not match canonical row`);
  }
  if (!(value.contentHash == null || value.contentHash === value.rowHash)) {
    problems.push(`${prefix} contentHash must equal rowHash`);
  }
  return problems;
}

function authorityProofIds(evidence: CanonicalLabelAuthorityEvidence): readonly string[] {
  return deepFreeze([
    `label-event:${evidence.event.eventId}`,
    ...evidence.permissionObservations.map((item) => item.evidenceId),
    ...evidence.approvedRosterEntries.map((item) => item.evidenceId),
  ].sort(compareBinary).filter((item, index, items) => index === 0 || item !== items[index - 1]));
}

function resolution(
  base: Pick<
    LabelAuthorityResolution,
    'purpose' | 'label' | 'eventId' | 'eventTime' | 'repositoryNodeId' |
    'actorNodeId' | 'actorLogin' | 'actorType' | 'actorAssociation' |
    'policyVersion' | 'proofIds' | 'evidenceDigest'
  >,
  authority: LabelAuthority,
  source: LabelAuthoritySource,
  reason: LabelAuthorityReason,
  authorizedForScoring: boolean,
): LabelAuthorityResolution {
  return deepFreeze({
    purpose: base.purpose,
    decision: authorizedForScoring
      ? 'authorized_for_scoring'
      : 'denied_for_scoring',
    label: base.label,
    eventId: base.eventId,
    eventTime: base.eventTime,
    repositoryNodeId: base.repositoryNodeId,
    actorNodeId: base.actorNodeId,
    actorLogin: base.actorLogin,
    actorType: base.actorType,
    actorAssociation: base.actorAssociation,
    authority,
    source,
    policyVersion: base.policyVersion,
    reason,
    proofIds: base.proofIds,
    evidenceDigest: base.evidenceDigest,
    authorizedForScoring,
  });
}

function comparePermissionEvidence(
  left: CanonicalRepositoryPermissionObservation,
  right: CanonicalRepositoryPermissionObservation,
): number {
  return compareBinary(left.observedAt, right.observedAt) ||
    compareBinary(left.repositoryNodeId ?? '', right.repositoryNodeId ?? '') ||
    compareBinary(left.actorNodeId ?? '', right.actorNodeId ?? '') ||
    compareBinary(left.rowHash ?? '', right.rowHash ?? '') ||
    compareBinary(left.evidenceId, right.evidenceId);
}

function compareRosterEvidence(
  left: CanonicalApprovedMaintainerRosterEntry,
  right: CanonicalApprovedMaintainerRosterEntry,
): number {
  return (left.rosterSequence ?? 0) - (right.rosterSequence ?? 0) ||
    compareBinary(left.effectiveFrom, right.effectiveFrom) ||
    compareBinary(left.effectiveUntil ?? '', right.effectiveUntil ?? '') ||
    compareBinary(left.actorNodeId ?? '', right.actorNodeId ?? '') ||
    compareBinary(left.rowHash ?? '', right.rowHash ?? '') ||
    compareBinary(left.evidenceId, right.evidenceId);
}

function normalizeRepository(value: string): string {
  return typeof value === 'string' ? value.toLowerCase() : value;
}

function normalizeLogin(value: string | null): string | null {
  return typeof value === 'string' ? value.toLowerCase() : null;
}

function normalizeOptionalText(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function normalizeTimestamp(value: string): string {
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) ? new Date(epoch).toISOString() : value;
}

function isNodeId(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    value.trim() === value;
}

function isRepository(value: unknown): value is string {
  return typeof value === 'string' &&
    /^[a-z0-9](?:[a-z0-9-]{0,38})\/[a-z0-9_.-]{1,100}$/.test(value) &&
    !value.endsWith('/.') &&
    !value.endsWith('/..');
}

function isLogin(value: unknown): value is string {
  return typeof value === 'string' &&
    value.trim() === value &&
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$/.test(value);
}

function isSourceIdentity(value: unknown): value is string {
  return isNormalizedText(value) && value.length <= 512;
}

function isNormalizedText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.trim() === value;
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && Number.isFinite(Date.parse(value));
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isCanonicalJson(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    return canonicalJson(JSON.parse(value)) === value;
  } catch {
    return false;
  }
}

function isSortedUnique(values: unknown[]): values is string[] {
  return values.every((item, index) =>
    typeof item === 'string' &&
    (index === 0 || compareBinary(values[index - 1] as string, item) < 0));
}

function isRecord(value: unknown): value is Record<string, any> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function addUnknownKeyProblems(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  context: string,
  problems: string[],
): void {
  for (const key of Object.keys(value).sort(compareBinary)) {
    if (!allowed.has(key)) problems.push(`${context} has unknown key ${key}`);
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  return `{${Object.keys(value as Record<string, unknown>)
    .sort(compareBinary)
    .map((key) =>
      `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
    .join(',')}}`;
}

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value as Record<string, unknown>)) {
      deepFreeze(item);
    }
  }
  return value;
}
