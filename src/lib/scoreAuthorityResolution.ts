import { createHash } from 'node:crypto';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  LABEL_AUTHORITY_POLICY_VERSION,
  LABEL_AUTHORITY_PURPOSE,
  canonicalLabelAuthorityEvidence,
  labelAuthorityEvidenceProblems,
  labelAuthorityResolutionProblems,
  resolveLabelAuthority,
  type ApprovedMaintainerRosterEntry,
  type LabelAuthority,
  type LabelAuthorityDecision,
  type LabelAuthorityEvidence,
  type LabelAuthorityReason,
  type LabelAuthorityResolution,
  type LabelAuthoritySource,
  type RepositoryPermissionObservation,
} from './labelAuthority';
import {
  CLOSURE_CLAIM_KINDS,
  assertImmutableClosureClaimCandidate,
  type ClosureClaimCandidate,
  type ClosureClaimKind,
  type ClosureClaimSourceKind,
} from './closureClaimCandidates';

export const SCORE_AUTHORITY_RESOLUTION_SCHEMA_VERSION = 2 as const;
export const SCORE_AUTHORITY_RUN_SCHEMA_VERSION = 2 as const;
export const SCORE_AUTHORITY_PURPOSE = LABEL_AUTHORITY_PURPOSE;
export const RELEASE_SCORE_AUDIT_HISTORY_V2_SEAL_SCHEMA_VERSION = 2 as const;
export const SCORE_COMMENT_AUTHORITY_RESOLUTION_SCHEMA_VERSION = 1 as const;
export const SCORE_COMMENT_AUTHORITY_POLICY_VERSION = 1 as const;
export const SCORE_CLOSURE_CLAIM_AUTHORITY_RESOLUTION_SCHEMA_VERSION = 2 as const;
export const SCORE_CLOSURE_CLAIM_AUTHORITY_POLICY_VERSION = 2 as const;

export type ScoreAuthoritySubjectKind =
  | 'closure_claim'
  | 'comment'
  | 'label_event';
export type ScoreAuthority = LabelAuthority | 'independent_human';
export type ScoreAuthorityReason =
  | LabelAuthorityReason
  | 'independent_human_reproduction'
  | 'authorized_human_field_confirmation'
  | 'authorized_reporter_action'
  | 'field_confirmation_requires_human_text_source'
  | 'final_closure_evidence_absent'
  | 'final_closure_identity_mismatch'
  | 'issue_author_identity_missing'
  | 'reporter_identity_mismatch';

export type ScoreClosureClaimAuthoritySource =
  | LabelAuthoritySource
  | 'final_closure_event'
  | 'immutable_candidate_actor'
  | 'issue_author_identity';

const SCORE_AUTHORITY_REASONS = new Set<LabelAuthorityReason>([
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
const AUTHORIZING_REASONS = new Set<LabelAuthorityReason>([
  'authorized_by_repository_permission',
  'authorized_by_approved_roster',
  'authorized_by_repository_permission_and_approved_roster',
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
const AUTHORITIES = new Set<LabelAuthority>([
  'maintainer_human',
  'automation',
  'unknown',
]);
const SCORE_AUTHORITIES = new Set<ScoreAuthority>([
  ...AUTHORITIES,
  'independent_human',
]);
const SCORE_REASONS = new Set<ScoreAuthorityReason>([
  ...SCORE_AUTHORITY_REASONS,
  'independent_human_reproduction',
  'authorized_human_field_confirmation',
  'authorized_reporter_action',
  'field_confirmation_requires_human_text_source',
  'final_closure_evidence_absent',
  'final_closure_identity_mismatch',
  'issue_author_identity_missing',
  'reporter_identity_mismatch',
]);
const SOURCES = new Set<LabelAuthoritySource>([
  'repository_permission',
  'approved_roster',
  'repository_permission_and_approved_roster',
  'actor_identity',
  'repository_identity',
  'label_event',
  'conflicting_evidence',
  'invalid_evidence',
  'none',
]);

export interface ScoreAuthorityResolution {
  readonly schemaVersion: typeof SCORE_AUTHORITY_RESOLUTION_SCHEMA_VERSION;
  readonly purpose: typeof SCORE_AUTHORITY_PURPOSE;
  readonly decision: LabelAuthorityDecision;
  readonly reason: LabelAuthorityReason;
  readonly repositoryNodeId: string | null;
  readonly actorNodeId: string | null;
  readonly label: string;
  readonly eventId: string;
  readonly eventTime: string;
  readonly authority: LabelAuthority;
  readonly source: LabelAuthoritySource;
  readonly policyVersion: typeof LABEL_AUTHORITY_POLICY_VERSION;
  readonly proofIds: readonly string[];
  readonly evidenceDigest: string;
  readonly authorizedForScoring: boolean;
  readonly resolutionHash: string;
}

export interface ScoreCommentAuthorityEvidence {
  readonly issueNumber: number;
  readonly issueNodeId: string;
  readonly issueAuthorNodeId: string;
  readonly issueAuthorType: string;
  readonly commentNodeId: string;
  readonly commentId: number;
  readonly commentUrl: string;
  readonly actorNodeId: string;
  readonly actorType: 'User';
  readonly commentCreatedAt: string;
  readonly commentUpdatedAt: string;
  readonly commentBodyDigest: string;
  readonly claimSnippet: string;
}

export interface ScoreCommentAuthorityResolution {
  readonly schemaVersion:
    typeof SCORE_COMMENT_AUTHORITY_RESOLUTION_SCHEMA_VERSION;
  readonly purpose: typeof SCORE_AUTHORITY_PURPOSE;
  readonly decision: 'authorized_for_scoring';
  readonly reason: 'independent_human_reproduction';
  readonly issueNumber: number;
  readonly issueNodeId: string;
  readonly issueAuthorNodeId: string;
  readonly issueAuthorType: string;
  readonly commentNodeId: string;
  readonly commentId: number;
  readonly commentUrl: string;
  readonly actorNodeId: string;
  readonly actorType: 'User';
  readonly commentCreatedAt: string;
  readonly commentUpdatedAt: string;
  readonly commentBodyDigest: string;
  readonly claimSnippet: string;
  readonly authority: 'independent_human';
  readonly source: 'authoritative_comment_snapshot';
  readonly policyVersion: typeof SCORE_COMMENT_AUTHORITY_POLICY_VERSION;
  readonly evidenceDigest: string;
  readonly authorizedForScoring: true;
  readonly resolutionHash: string;
}

export interface ScoreClosureClaimFinalClosureEvidence {
  readonly sourceIdentity: string;
  readonly issueNodeId: string;
  readonly eventId: string;
  readonly occurredAt: string;
  readonly actorNodeId: string | null;
  readonly actorType: string | null;
}

export interface ScoreClosureClaimAuthorityEvidence {
  readonly candidate: ClosureClaimCandidate;
  readonly extractionReceiptId: string;
  readonly extractionReceiptContentHash: string;
  readonly issueAuthorNodeId: string | null;
  readonly issueAuthorType: string | null;
  readonly permissionObservations?: readonly RepositoryPermissionObservation[];
  readonly approvedRosterEntries?: readonly ApprovedMaintainerRosterEntry[];
  readonly finalClosure: ScoreClosureClaimFinalClosureEvidence | null;
}

export interface ScoreClosureClaimAuthorityResolution {
  readonly schemaVersion:
    typeof SCORE_CLOSURE_CLAIM_AUTHORITY_RESOLUTION_SCHEMA_VERSION;
  readonly purpose: typeof SCORE_AUTHORITY_PURPOSE;
  readonly decision: LabelAuthorityDecision;
  readonly reason: ScoreAuthorityReason;
  readonly repositoryNodeId: string;
  readonly issueNumber: number;
  readonly issueNodeId: string;
  readonly issueAuthorNodeId: string | null;
  readonly issueAuthorType: string | null;
  readonly candidateId: string;
  readonly sourceIdentity: string;
  readonly extractionReceiptId: string;
  readonly extractionReceiptContentHash: string;
  readonly claimKind: ClosureClaimKind;
  readonly sourceKind: ClosureClaimSourceKind;
  readonly actorNodeId: string;
  readonly actorType: string;
  readonly claimTime: string;
  readonly finalClosureEventId: string | null;
  readonly finalClosureActorNodeId: string | null;
  readonly authority: ScoreAuthority;
  readonly source: ScoreClosureClaimAuthoritySource;
  readonly policyVersion:
    typeof SCORE_CLOSURE_CLAIM_AUTHORITY_POLICY_VERSION;
  readonly proofIds: readonly string[];
  readonly evidenceDigest: string;
  readonly authorizedForScoring: boolean;
  readonly resolutionHash: string;
}

export type ScoreAuthoritySubjectResolution =
  | ScoreAuthorityResolution
  | ScoreCommentAuthorityResolution
  | ScoreClosureClaimAuthorityResolution;

export interface ScoreAuthorityResolutionSubject {
  readonly releaseTag: string | null;
  readonly issueNumber: number;
  readonly subjectKind: ScoreAuthoritySubjectKind;
  readonly subjectIdentity: string;
  readonly candidateId: string | null;
  readonly resolution: ScoreAuthoritySubjectResolution;
}

export interface ScoreAuthorityReference {
  readonly subjectKind: ScoreAuthoritySubjectKind;
  readonly subjectIdentity: string;
  readonly resolutionHash: string;
  readonly evidenceDigest: string;
  readonly authorizedForScoring: true;
}

export interface ScoreAuthorityResolutionRow {
  readonly authorityRunId: string;
  readonly rowOrdinal: number;
  readonly releaseTag: string | null;
  readonly issueNumber: number;
  readonly subjectKind: ScoreAuthoritySubjectKind;
  readonly subjectIdentity: string;
  readonly candidateId: string | null;
  readonly authority: ScoreAuthority;
  readonly reason: ScoreAuthorityReason;
  readonly authorizedForScoring: boolean;
  readonly evidenceDigest: string;
  readonly resolutionJson: string;
  readonly contentHash: string;
}

export interface ScoreAuthorityResolutionRun {
  readonly authorityRunId: string;
  readonly schemaVersion: typeof SCORE_AUTHORITY_RUN_SCHEMA_VERSION;
  readonly policyVersion: typeof LABEL_AUTHORITY_POLICY_VERSION;
  readonly sourceIdentitySchemaVersion: number;
  readonly sourceIdentityDigest: string;
  readonly recordedAt: string;
  readonly rowCount: number;
  readonly rowsContentHash: string;
  readonly previousContentHash: string | null;
  readonly contentHash: string;
  readonly rows: readonly ScoreAuthorityResolutionRow[];
}

export interface ReleaseScoreAuditHistoryV2Seal {
  readonly schemaVersion:
    typeof RELEASE_SCORE_AUDIT_HISTORY_V2_SEAL_SCHEMA_VERSION;
  readonly historyRunId: string;
  readonly authorityRunId: string;
  readonly sealedAt: string;
  readonly historyRowCount: number;
  readonly historyRowsContentHash: string;
  readonly authorityRowCount: number;
  readonly authorityRowsContentHash: string;
  readonly previousContentHash: string | null;
  readonly contentHash: string;
}

export function buildScoreAuthorityResolution(
  evidence: LabelAuthorityEvidence,
  suppliedResolution?: LabelAuthorityResolution,
): ScoreAuthorityResolution {
  const resolution = suppliedResolution ?? resolveLabelAuthority(evidence);
  const resolutionProblems = labelAuthorityResolutionProblems(resolution, evidence);
  if (resolutionProblems.length > 0) {
    throw new TypeError(
      `Invalid label authority resolution: ${resolutionProblems.join('; ')}`,
    );
  }
  const fields = {
    schemaVersion: SCORE_AUTHORITY_RESOLUTION_SCHEMA_VERSION,
    purpose: SCORE_AUTHORITY_PURPOSE,
    decision: resolution.decision,
    reason: resolution.reason,
    repositoryNodeId: resolution.repositoryNodeId,
    actorNodeId: resolution.actorNodeId,
    label: resolution.label,
    eventId: resolution.eventId,
    eventTime: resolution.eventTime,
    authority: resolution.authority,
    source: resolution.source,
    policyVersion: resolution.policyVersion,
    proofIds: sortedUnique(resolution.proofIds),
    evidenceDigest: resolution.evidenceDigest,
    authorizedForScoring: resolution.authorizedForScoring,
  } as const;
  return deepFreeze({
    ...fields,
    resolutionHash: scoreAuthorityResolutionHash(fields),
  });
}

export function buildScoreCommentAuthorityResolution(
  evidence: ScoreCommentAuthorityEvidence,
): ScoreCommentAuthorityResolution {
  const evidenceProblems = scoreCommentAuthorityEvidenceProblems(evidence);
  if (evidenceProblems.length > 0) {
    throw new TypeError(
      `Invalid score comment authority evidence: ${evidenceProblems.join('; ')}`,
    );
  }
  const normalizedEvidence = {
    issueNumber: evidence.issueNumber,
    issueNodeId: evidence.issueNodeId,
    issueAuthorNodeId: evidence.issueAuthorNodeId,
    issueAuthorType: evidence.issueAuthorType,
    commentNodeId: evidence.commentNodeId,
    commentId: evidence.commentId,
    commentUrl: evidence.commentUrl,
    actorNodeId: evidence.actorNodeId,
    actorType: evidence.actorType,
    commentCreatedAt: normalizeTimestamp(evidence.commentCreatedAt),
    commentUpdatedAt: normalizeTimestamp(evidence.commentUpdatedAt),
    commentBodyDigest: evidence.commentBodyDigest,
    claimSnippet: evidence.claimSnippet,
  } as const;
  const fields = {
    schemaVersion: SCORE_COMMENT_AUTHORITY_RESOLUTION_SCHEMA_VERSION,
    purpose: SCORE_AUTHORITY_PURPOSE,
    decision: 'authorized_for_scoring',
    reason: 'independent_human_reproduction',
    ...normalizedEvidence,
    authority: 'independent_human',
    source: 'authoritative_comment_snapshot',
    policyVersion: SCORE_COMMENT_AUTHORITY_POLICY_VERSION,
    evidenceDigest: scoreCommentAuthorityEvidenceDigest(normalizedEvidence),
    authorizedForScoring: true,
  } as const;
  return deepFreeze({
    ...fields,
    resolutionHash: scoreCommentAuthorityResolutionHash(fields),
  });
}

export function scoreCommentAuthorityEvidenceDigest(
  value: ScoreCommentAuthorityEvidence,
): string {
  return sha256(
    `score-comment-authority-evidence-v1\0${canonicalJson([
      value.issueNumber,
      value.issueNodeId,
      value.issueAuthorNodeId,
      value.issueAuthorType,
      value.commentNodeId,
      value.commentId,
      value.commentUrl,
      value.actorNodeId,
      value.actorType,
      normalizeTimestamp(value.commentCreatedAt),
      normalizeTimestamp(value.commentUpdatedAt),
      value.commentBodyDigest,
      value.claimSnippet,
    ])}`,
  );
}

export function scoreCommentAuthorityResolutionHash(
  value: Omit<ScoreCommentAuthorityResolution, 'resolutionHash'>,
): string {
  return sha256(
    `score-comment-authority-resolution-v1\0${canonicalJson({
      schemaVersion: value.schemaVersion,
      purpose: value.purpose,
      decision: value.decision,
      reason: value.reason,
      issueNumber: value.issueNumber,
      issueNodeId: value.issueNodeId,
      issueAuthorNodeId: value.issueAuthorNodeId,
      issueAuthorType: value.issueAuthorType,
      commentNodeId: value.commentNodeId,
      commentId: value.commentId,
      commentUrl: value.commentUrl,
      actorNodeId: value.actorNodeId,
      actorType: value.actorType,
      commentCreatedAt: normalizeTimestamp(value.commentCreatedAt),
      commentUpdatedAt: normalizeTimestamp(value.commentUpdatedAt),
      commentBodyDigest: value.commentBodyDigest,
      claimSnippet: value.claimSnippet,
      authority: value.authority,
      source: value.source,
      policyVersion: value.policyVersion,
      evidenceDigest: value.evidenceDigest,
      authorizedForScoring: value.authorizedForScoring,
    })}`,
  );
}

export function canonicalScoreCommentAuthorityResolutionJson(
  value: ScoreCommentAuthorityResolution,
): string {
  return canonicalJson({
    schemaVersion: value.schemaVersion,
    purpose: value.purpose,
    decision: value.decision,
    reason: value.reason,
    issueNumber: value.issueNumber,
    issueNodeId: value.issueNodeId,
    issueAuthorNodeId: value.issueAuthorNodeId,
    issueAuthorType: value.issueAuthorType,
    commentNodeId: value.commentNodeId,
    commentId: value.commentId,
    commentUrl: value.commentUrl,
    actorNodeId: value.actorNodeId,
    actorType: value.actorType,
    commentCreatedAt: normalizeTimestamp(value.commentCreatedAt),
    commentUpdatedAt: normalizeTimestamp(value.commentUpdatedAt),
    commentBodyDigest: value.commentBodyDigest,
    claimSnippet: value.claimSnippet,
    authority: value.authority,
    source: value.source,
    policyVersion: value.policyVersion,
    evidenceDigest: value.evidenceDigest,
    authorizedForScoring: value.authorizedForScoring,
    resolutionHash: value.resolutionHash,
  });
}

export function scoreCommentAuthorityResolutionProblems(
  value: unknown,
  evidence?: ScoreCommentAuthorityEvidence,
): string[] {
  if (!isRecord(value)) {
    return ['score comment authority resolution must be an object'];
  }
  const problems: string[] = [];
  addExactKeyProblems(value, [
    'schemaVersion',
    'purpose',
    'decision',
    'reason',
    'issueNumber',
    'issueNodeId',
    'issueAuthorNodeId',
    'issueAuthorType',
    'commentNodeId',
    'commentId',
    'commentUrl',
    'actorNodeId',
    'actorType',
    'commentCreatedAt',
    'commentUpdatedAt',
    'commentBodyDigest',
    'claimSnippet',
    'authority',
    'source',
    'policyVersion',
    'evidenceDigest',
    'authorizedForScoring',
    'resolutionHash',
  ], 'score comment authority resolution', problems);
  if (
    value.schemaVersion !==
      SCORE_COMMENT_AUTHORITY_RESOLUTION_SCHEMA_VERSION
  ) {
    problems.push(
      `score comment authority resolution schemaVersion must be ` +
        SCORE_COMMENT_AUTHORITY_RESOLUTION_SCHEMA_VERSION,
    );
  }
  if (value.purpose !== SCORE_AUTHORITY_PURPOSE) {
    problems.push(
      `score comment authority resolution purpose must be ${SCORE_AUTHORITY_PURPOSE}`,
    );
  }
  if (value.decision !== 'authorized_for_scoring') {
    problems.push(
      'score comment authority resolution decision must be authorized_for_scoring',
    );
  }
  if (value.reason !== 'independent_human_reproduction') {
    problems.push(
      'score comment authority resolution reason must be independent_human_reproduction',
    );
  }
  problems.push(...scoreCommentAuthorityEvidenceProblems({
    issueNumber: value.issueNumber,
    issueNodeId: value.issueNodeId,
    issueAuthorNodeId: value.issueAuthorNodeId,
    issueAuthorType: value.issueAuthorType,
    commentNodeId: value.commentNodeId,
    commentId: value.commentId,
    commentUrl: value.commentUrl,
    actorNodeId: value.actorNodeId,
    actorType: value.actorType,
    commentCreatedAt: value.commentCreatedAt,
    commentUpdatedAt: value.commentUpdatedAt,
    commentBodyDigest: value.commentBodyDigest,
    claimSnippet: value.claimSnippet,
  } as ScoreCommentAuthorityEvidence).map((problem) =>
    `score comment authority resolution ${problem}`));
  if (value.authority !== 'independent_human') {
    problems.push(
      'score comment authority resolution authority must be independent_human',
    );
  }
  if (value.source !== 'authoritative_comment_snapshot') {
    problems.push(
      'score comment authority resolution source must be authoritative_comment_snapshot',
    );
  }
  if (value.policyVersion !== SCORE_COMMENT_AUTHORITY_POLICY_VERSION) {
    problems.push(
      `score comment authority resolution policyVersion must be ` +
        SCORE_COMMENT_AUTHORITY_POLICY_VERSION,
    );
  }
  if (!isSha256(value.evidenceDigest)) {
    problems.push(
      'score comment authority resolution evidenceDigest must be SHA-256',
    );
  } else if (
    problems.length === 0 &&
    value.evidenceDigest !== scoreCommentAuthorityEvidenceDigest(
      value as unknown as ScoreCommentAuthorityEvidence,
    )
  ) {
    problems.push(
      'score comment authority resolution evidenceDigest does not match evidence',
    );
  }
  if (value.authorizedForScoring !== true) {
    problems.push(
      'score comment authority resolution authorizedForScoring must be true',
    );
  }
  if (!isSha256(value.resolutionHash)) {
    problems.push(
      'score comment authority resolution resolutionHash must be SHA-256',
    );
  } else if (
    problems.length === 0 &&
    value.resolutionHash !== scoreCommentAuthorityResolutionHash(
      value as unknown as Omit<
        ScoreCommentAuthorityResolution,
        'resolutionHash'
      >,
    )
  ) {
    problems.push(
      'score comment authority resolution hash does not match canonical resolution',
    );
  }
  if (evidence && problems.length === 0) {
    const expected = buildScoreCommentAuthorityResolution(evidence);
    if (
      canonicalScoreCommentAuthorityResolutionJson(
        value as unknown as ScoreCommentAuthorityResolution,
      ) !== canonicalScoreCommentAuthorityResolutionJson(expected)
    ) {
      problems.push(
        'score comment authority resolution does not match canonical evidence',
      );
    }
  }
  return problems;
}

export function buildScoreClosureClaimAuthorityResolution(
  evidence: ScoreClosureClaimAuthorityEvidence,
): ScoreClosureClaimAuthorityResolution {
  const evidenceProblems = scoreClosureClaimAuthorityEvidenceProblems(evidence);
  if (evidenceProblems.length > 0) {
    throw new TypeError(
      `Invalid score closure claim authority evidence: ` +
        evidenceProblems.join('; '),
    );
  }
  assertImmutableClosureClaimCandidate(evidence.candidate);
  const candidate = evidence.candidate;
  const repositoryNodeId = candidate.repository.nodeId as string;
  const issueNodeId = candidate.issue.nodeId as string;
  const actorNodeId = candidate.source.actor.nodeId as string;
  const actorType = candidate.source.actor.type as string;
  const claimTime = normalizeTimestamp(candidate.source.updatedAt);
  const finalClosure = evidence.finalClosure == null
    ? null
    : {
        ...evidence.finalClosure,
        occurredAt: normalizeTimestamp(evidence.finalClosure.occurredAt),
      };
  const labelEvidence = closureClaimLabelAuthorityEvidence(evidence);
  const evidenceDigest = scoreClosureClaimAuthorityEvidenceDigest(evidence);
  const baseProofIds = [
    `closure-candidate:${candidate.candidateId}`,
    `closure-source:${candidate.sourceIdentity}`,
    `closure-extraction-receipt:${evidence.extractionReceiptId}`,
    ...(finalClosure
      ? [
          `final-closure-event:${finalClosure.eventId}`,
          `final-closure-source:${finalClosure.sourceIdentity}`,
        ]
      : []),
  ];
  const base = {
    schemaVersion: SCORE_CLOSURE_CLAIM_AUTHORITY_RESOLUTION_SCHEMA_VERSION,
    purpose: SCORE_AUTHORITY_PURPOSE,
    repositoryNodeId,
    issueNumber: candidate.issue.number,
    issueNodeId,
    issueAuthorNodeId: evidence.issueAuthorNodeId,
    issueAuthorType: evidence.issueAuthorType,
    candidateId: candidate.candidateId,
    sourceIdentity: candidate.sourceIdentity,
    extractionReceiptId: evidence.extractionReceiptId,
    extractionReceiptContentHash: evidence.extractionReceiptContentHash,
    claimKind: candidate.claimKind,
    sourceKind: candidate.source.kind,
    actorNodeId,
    actorType,
    claimTime,
    finalClosureEventId: finalClosure?.eventId ?? null,
    finalClosureActorNodeId: finalClosure?.actorNodeId ?? null,
    policyVersion: SCORE_CLOSURE_CLAIM_AUTHORITY_POLICY_VERSION,
    evidenceDigest,
  } as const;
  const finish = (
    authority: ScoreAuthority,
    source: ScoreClosureClaimAuthoritySource,
    reason: ScoreAuthorityReason,
    authorizedForScoring: boolean,
    proofIds: readonly string[] = [],
  ): ScoreClosureClaimAuthorityResolution => {
    const fields = {
      ...base,
      decision: authorizedForScoring
        ? 'authorized_for_scoring'
        : 'denied_for_scoring',
      reason,
      authority,
      source,
      proofIds: sortedUnique([...baseProofIds, ...proofIds]),
      authorizedForScoring,
    } as const;
    return deepFreeze({
      ...fields,
      resolutionHash: scoreClosureClaimAuthorityResolutionHash(fields),
    });
  };

  if (actorType === 'Bot') {
    return finish('automation', 'actor_identity', 'actor_is_bot', false);
  }
  if (actorType !== 'User') {
    return finish('unknown', 'actor_identity', 'actor_is_not_user', false);
  }

  if (candidate.source.kind === 'closure_event') {
    if (finalClosure == null) {
      return finish(
        'unknown',
        'final_closure_event',
        'final_closure_evidence_absent',
        false,
      );
    }
    if (
      finalClosure.issueNodeId !== issueNodeId ||
      finalClosure.eventId !== candidate.source.nodeId ||
      finalClosure.actorNodeId !== actorNodeId ||
      finalClosure.actorType !== actorType ||
      finalClosure.occurredAt !== claimTime
    ) {
      return finish(
        'unknown',
        'conflicting_evidence',
        'final_closure_identity_mismatch',
        false,
      );
    }
  }

  if (candidate.claimKind === 'reporter_action') {
    if (
      evidence.issueAuthorNodeId == null ||
      evidence.issueAuthorType == null
    ) {
      return finish(
        'unknown',
        'issue_author_identity',
        'issue_author_identity_missing',
        false,
      );
    }
    if (
      evidence.issueAuthorType !== 'User' ||
      candidate.claim.kind !== 'reporter_action' ||
      candidate.claim.reporterNodeId !== evidence.issueAuthorNodeId ||
      actorNodeId !== evidence.issueAuthorNodeId
    ) {
      return finish(
        'unknown',
        'issue_author_identity',
        'reporter_identity_mismatch',
        false,
      );
    }
    return finish(
      'independent_human',
      'issue_author_identity',
      'authorized_reporter_action',
      true,
      [`issue-author:${evidence.issueAuthorNodeId}`],
    );
  }

  if (candidate.claimKind === 'field_confirmation') {
    if (
      candidate.source.kind !== 'comment' &&
      candidate.source.kind !== 'issue_body'
    ) {
      return finish(
        'unknown',
        'immutable_candidate_actor',
        'field_confirmation_requires_human_text_source',
        false,
      );
    }
    return finish(
      'independent_human',
      'immutable_candidate_actor',
      'authorized_human_field_confirmation',
      true,
      [`candidate-actor:${actorNodeId}`],
    );
  }

  const labelResolution = resolveLabelAuthority(labelEvidence);
  return finish(
    labelResolution.authority,
    labelResolution.source,
    labelResolution.reason,
    labelResolution.authorizedForScoring,
    labelResolution.proofIds,
  );
}

export function scoreClosureClaimAuthorityEvidenceDigest(
  evidence: ScoreClosureClaimAuthorityEvidence,
): string {
  assertImmutableClosureClaimCandidate(evidence.candidate);
  const finalClosure = evidence.finalClosure == null
    ? null
    : {
        sourceIdentity: evidence.finalClosure.sourceIdentity,
        issueNodeId: evidence.finalClosure.issueNodeId,
        eventId: evidence.finalClosure.eventId,
        occurredAt: normalizeTimestamp(evidence.finalClosure.occurredAt),
        actorNodeId: evidence.finalClosure.actorNodeId,
        actorType: evidence.finalClosure.actorType,
      };
  return sha256(
    `score-closure-claim-authority-evidence-v2\0${canonicalJson({
      candidate: evidence.candidate,
      extractionReceiptId: evidence.extractionReceiptId,
      extractionReceiptContentHash: evidence.extractionReceiptContentHash,
      issueAuthorNodeId: evidence.issueAuthorNodeId,
      issueAuthorType: evidence.issueAuthorType,
      authorityEvidence: canonicalLabelAuthorityEvidence(
        closureClaimLabelAuthorityEvidence(evidence),
      ),
      finalClosure,
    })}`,
  );
}

export function scoreClosureClaimAuthorityResolutionHash(
  value: Omit<ScoreClosureClaimAuthorityResolution, 'resolutionHash'>,
): string {
  return sha256(
    `score-closure-claim-authority-resolution-v2\0${canonicalJson({
      schemaVersion: value.schemaVersion,
      purpose: value.purpose,
      decision: value.decision,
      reason: value.reason,
      repositoryNodeId: value.repositoryNodeId,
      issueNumber: value.issueNumber,
      issueNodeId: value.issueNodeId,
      issueAuthorNodeId: value.issueAuthorNodeId,
      issueAuthorType: value.issueAuthorType,
      candidateId: value.candidateId,
      sourceIdentity: value.sourceIdentity,
      extractionReceiptId: value.extractionReceiptId,
      extractionReceiptContentHash: value.extractionReceiptContentHash,
      claimKind: value.claimKind,
      sourceKind: value.sourceKind,
      actorNodeId: value.actorNodeId,
      actorType: value.actorType,
      claimTime: normalizeTimestamp(value.claimTime),
      finalClosureEventId: value.finalClosureEventId,
      finalClosureActorNodeId: value.finalClosureActorNodeId,
      authority: value.authority,
      source: value.source,
      policyVersion: value.policyVersion,
      proofIds: sortedUnique(value.proofIds),
      evidenceDigest: value.evidenceDigest,
      authorizedForScoring: value.authorizedForScoring,
    })}`,
  );
}

export function canonicalScoreClosureClaimAuthorityResolutionJson(
  value: ScoreClosureClaimAuthorityResolution,
): string {
  return canonicalJson({
    schemaVersion: value.schemaVersion,
    purpose: value.purpose,
    decision: value.decision,
    reason: value.reason,
    repositoryNodeId: value.repositoryNodeId,
    issueNumber: value.issueNumber,
    issueNodeId: value.issueNodeId,
    issueAuthorNodeId: value.issueAuthorNodeId,
    issueAuthorType: value.issueAuthorType,
    candidateId: value.candidateId,
    sourceIdentity: value.sourceIdentity,
    extractionReceiptId: value.extractionReceiptId,
    extractionReceiptContentHash: value.extractionReceiptContentHash,
    claimKind: value.claimKind,
    sourceKind: value.sourceKind,
    actorNodeId: value.actorNodeId,
    actorType: value.actorType,
    claimTime: normalizeTimestamp(value.claimTime),
    finalClosureEventId: value.finalClosureEventId,
    finalClosureActorNodeId: value.finalClosureActorNodeId,
    authority: value.authority,
    source: value.source,
    policyVersion: value.policyVersion,
    proofIds: sortedUnique(value.proofIds),
    evidenceDigest: value.evidenceDigest,
    authorizedForScoring: value.authorizedForScoring,
    resolutionHash: value.resolutionHash,
  });
}

export function scoreClosureClaimAuthorityResolutionProblems(
  value: unknown,
  evidence?: ScoreClosureClaimAuthorityEvidence,
): string[] {
  if (!isRecord(value)) {
    return ['score closure claim authority resolution must be an object'];
  }
  const problems: string[] = [];
  addExactKeyProblems(value, [
    'schemaVersion',
    'purpose',
    'decision',
    'reason',
    'repositoryNodeId',
    'issueNumber',
    'issueNodeId',
    'issueAuthorNodeId',
    'issueAuthorType',
    'candidateId',
    'sourceIdentity',
    'extractionReceiptId',
    'extractionReceiptContentHash',
    'claimKind',
    'sourceKind',
    'actorNodeId',
    'actorType',
    'claimTime',
    'finalClosureEventId',
    'finalClosureActorNodeId',
    'authority',
    'source',
    'policyVersion',
    'proofIds',
    'evidenceDigest',
    'authorizedForScoring',
    'resolutionHash',
  ], 'score closure claim authority resolution', problems);
  if (
    value.schemaVersion !==
      SCORE_CLOSURE_CLAIM_AUTHORITY_RESOLUTION_SCHEMA_VERSION
  ) {
    problems.push(
      `score closure claim authority resolution schemaVersion must be ` +
        SCORE_CLOSURE_CLAIM_AUTHORITY_RESOLUTION_SCHEMA_VERSION,
    );
  }
  if (value.purpose !== SCORE_AUTHORITY_PURPOSE) {
    problems.push(
      `score closure claim authority resolution purpose must be ` +
        SCORE_AUTHORITY_PURPOSE,
    );
  }
  if (
    value.decision !== 'authorized_for_scoring' &&
    value.decision !== 'denied_for_scoring'
  ) {
    problems.push('score closure claim authority resolution decision is invalid');
  }
  if (!SCORE_REASONS.has(value.reason as ScoreAuthorityReason)) {
    problems.push('score closure claim authority resolution reason is invalid');
  }
  for (const [field, fieldValue] of [
    ['repositoryNodeId', value.repositoryNodeId],
    ['issueNodeId', value.issueNodeId],
    ['candidateId', value.candidateId],
    ['sourceIdentity', value.sourceIdentity],
    ['actorNodeId', value.actorNodeId],
    ['actorType', value.actorType],
  ] as const) {
    if (!isNormalizedText(fieldValue)) {
      problems.push(`score closure claim authority resolution ${field} is invalid`);
    }
  }
  for (const [field, fieldValue] of [
    ['extractionReceiptId', value.extractionReceiptId],
    ['extractionReceiptContentHash', value.extractionReceiptContentHash],
  ] as const) {
    if (!isSha256(fieldValue)) {
      problems.push(
        `score closure claim authority resolution ${field} must be SHA-256`,
      );
    }
  }
  if (!Number.isInteger(value.issueNumber) || Number(value.issueNumber) <= 0) {
    problems.push('score closure claim authority resolution issueNumber is invalid');
  }
  if (
    !(value.issueAuthorNodeId == null ||
      isNormalizedText(value.issueAuthorNodeId))
  ) {
    problems.push(
      'score closure claim authority resolution issueAuthorNodeId is invalid',
    );
  }
  if (
    !(value.issueAuthorType == null || isNormalizedText(value.issueAuthorType))
  ) {
    problems.push(
      'score closure claim authority resolution issueAuthorType is invalid',
    );
  }
  if (!CLOSURE_CLAIM_KINDS.includes(value.claimKind as ClosureClaimKind)) {
    problems.push('score closure claim authority resolution claimKind is invalid');
  }
  if (!['issue_body', 'comment', 'closure_event'].includes(
    String(value.sourceKind),
  )) {
    problems.push('score closure claim authority resolution sourceKind is invalid');
  }
  if (!isTimestamp(value.claimTime)) {
    problems.push('score closure claim authority resolution claimTime is invalid');
  }
  if (
    !(value.finalClosureEventId == null ||
      isNormalizedText(value.finalClosureEventId))
  ) {
    problems.push(
      'score closure claim authority resolution finalClosureEventId is invalid',
    );
  }
  if (
    !(value.finalClosureActorNodeId == null ||
      isNormalizedText(value.finalClosureActorNodeId))
  ) {
    problems.push(
      'score closure claim authority resolution finalClosureActorNodeId is invalid',
    );
  }
  if (!SCORE_AUTHORITIES.has(value.authority as ScoreAuthority)) {
    problems.push('score closure claim authority resolution authority is invalid');
  }
  if (!isClosureClaimAuthoritySource(value.source)) {
    problems.push('score closure claim authority resolution source is invalid');
  }
  if (
    value.policyVersion !== SCORE_CLOSURE_CLAIM_AUTHORITY_POLICY_VERSION
  ) {
    problems.push(
      `score closure claim authority resolution policyVersion must be ` +
        SCORE_CLOSURE_CLAIM_AUTHORITY_POLICY_VERSION,
    );
  }
  if (
    !Array.isArray(value.proofIds) ||
    value.proofIds.some((item) => !isNormalizedText(item)) ||
    canonicalJson(value.proofIds) !== canonicalJson(sortedUnique(value.proofIds))
  ) {
    problems.push(
      'score closure claim authority resolution proofIds must be sorted unique strings',
    );
  }
  if (!isSha256(value.evidenceDigest)) {
    problems.push(
      'score closure claim authority resolution evidenceDigest must be SHA-256',
    );
  }
  if (typeof value.authorizedForScoring !== 'boolean') {
    problems.push(
      'score closure claim authority resolution authorizedForScoring must be boolean',
    );
  }
  if (
    (value.decision === 'authorized_for_scoring') !==
      (value.authorizedForScoring === true)
  ) {
    problems.push(
      'score closure claim authority resolution decision and scoring flag disagree',
    );
  }
  if (value.authorizedForScoring === true) {
    const labelSource = AUTHORIZING_REASON_SOURCES.get(
      value.reason as LabelAuthorityReason,
    );
    const authorizedSpecial =
      (
        value.reason === 'authorized_human_field_confirmation' &&
        value.authority === 'independent_human' &&
        value.source === 'immutable_candidate_actor'
      ) ||
      (
        value.reason === 'authorized_reporter_action' &&
        value.authority === 'independent_human' &&
        value.source === 'issue_author_identity'
      );
    const authorizedMaintainer =
      labelSource != null &&
      value.authority === 'maintainer_human' &&
      value.source === labelSource;
    if (!authorizedSpecial && !authorizedMaintainer) {
      problems.push(
        'authorized closure claim resolution lacks a valid authority path',
      );
    }
  } else if (
    value.authority === 'maintainer_human' ||
    value.authority === 'independent_human'
  ) {
    problems.push(
      'denied closure claim resolution cannot retain human scoring authority',
    );
  }
  if (!isSha256(value.resolutionHash)) {
    problems.push(
      'score closure claim authority resolution resolutionHash must be SHA-256',
    );
  } else if (
    problems.length === 0 &&
    value.resolutionHash !== scoreClosureClaimAuthorityResolutionHash(
      value as unknown as Omit<
        ScoreClosureClaimAuthorityResolution,
        'resolutionHash'
      >,
    )
  ) {
    problems.push(
      'score closure claim authority resolution hash does not match canonical resolution',
    );
  }
  if (evidence && problems.length === 0) {
    const expected = buildScoreClosureClaimAuthorityResolution(evidence);
    if (
      canonicalScoreClosureClaimAuthorityResolutionJson(
        value as unknown as ScoreClosureClaimAuthorityResolution,
      ) !== canonicalScoreClosureClaimAuthorityResolutionJson(expected)
    ) {
      problems.push(
        'score closure claim authority resolution does not match canonical evidence',
      );
    }
  }
  return problems;
}

export function scoreAuthorityResolutionHash(
  value: Omit<ScoreAuthorityResolution, 'resolutionHash'>,
): string {
  return sha256(
    `score-authority-resolution-v2\0${canonicalJson({
      schemaVersion: value.schemaVersion,
      purpose: value.purpose,
      decision: value.decision,
      reason: value.reason,
      repositoryNodeId: value.repositoryNodeId,
      actorNodeId: value.actorNodeId,
      label: value.label,
      eventId: value.eventId,
      eventTime: normalizeTimestamp(value.eventTime),
      authority: value.authority,
      source: value.source,
      policyVersion: value.policyVersion,
      proofIds: sortedUnique(value.proofIds),
      evidenceDigest: value.evidenceDigest,
      authorizedForScoring: value.authorizedForScoring,
    })}`,
  );
}

export function canonicalScoreAuthorityResolutionJson(
  value: ScoreAuthorityResolution,
): string {
  return canonicalJson({
    schemaVersion: value.schemaVersion,
    purpose: value.purpose,
    decision: value.decision,
    reason: value.reason,
    repositoryNodeId: value.repositoryNodeId,
    actorNodeId: value.actorNodeId,
    label: value.label,
    eventId: value.eventId,
    eventTime: normalizeTimestamp(value.eventTime),
    authority: value.authority,
    source: value.source,
    policyVersion: value.policyVersion,
    proofIds: sortedUnique(value.proofIds),
    evidenceDigest: value.evidenceDigest,
    authorizedForScoring: value.authorizedForScoring,
    resolutionHash: value.resolutionHash,
  });
}

export function canonicalScoreAuthoritySubjectResolutionJson(
  value: ScoreAuthoritySubjectResolution,
): string {
  return isScoreClosureClaimAuthorityResolution(value)
    ? canonicalScoreClosureClaimAuthorityResolutionJson(value)
    : value.schemaVersion ===
      SCORE_COMMENT_AUTHORITY_RESOLUTION_SCHEMA_VERSION &&
      value.reason === 'independent_human_reproduction'
    ? canonicalScoreCommentAuthorityResolutionJson(
        value as ScoreCommentAuthorityResolution,
      )
    : canonicalScoreAuthorityResolutionJson(value as ScoreAuthorityResolution);
}

export function buildScoreAuthorityReference(
  subjectKind: ScoreAuthoritySubjectKind,
  subjectIdentity: string,
  resolution: ScoreAuthoritySubjectResolution,
): ScoreAuthorityReference {
  const identity = normalizedRequiredText(
    subjectIdentity,
    'score authority reference subjectIdentity',
  );
  if (!isSubjectKind(subjectKind)) {
    throw new TypeError('Score authority reference subjectKind is invalid');
  }
  if (resolution.authorizedForScoring !== true) {
    throw new TypeError(
      `Score authority reference ${subjectKind}:${identity} is not authorized for scoring`,
    );
  }
  const expectedIdentity = scoreAuthorityResolutionSubjectIdentity(
    subjectKind,
    resolution,
  );
  if (identity !== expectedIdentity) {
    throw new TypeError(
      `Score authority reference ${subjectKind}:${identity} does not match ` +
        `resolution subject ${expectedIdentity}`,
    );
  }
  const reference: ScoreAuthorityReference = {
    subjectKind,
    subjectIdentity: identity,
    resolutionHash: resolution.resolutionHash,
    evidenceDigest: resolution.evidenceDigest,
    authorizedForScoring: true,
  };
  const problems = scoreAuthorityReferenceProblems(reference);
  if (problems.length > 0) {
    throw new TypeError(
      `Invalid score authority reference: ${problems.join('; ')}`,
    );
  }
  return deepFreeze(reference);
}

export function canonicalScoreAuthorityReferenceJson(
  value: ScoreAuthorityReference,
): string {
  return canonicalJson({
    subjectKind: value.subjectKind,
    subjectIdentity: value.subjectIdentity,
    resolutionHash: value.resolutionHash,
    evidenceDigest: value.evidenceDigest,
    authorizedForScoring: value.authorizedForScoring,
  });
}

export function scoreAuthorityReferenceDigest(
  value: ScoreAuthorityReference,
): string {
  const problems = scoreAuthorityReferenceProblems(value);
  if (problems.length > 0) {
    throw new TypeError(
      `Cannot digest invalid score authority reference: ${problems.join('; ')}`,
    );
  }
  return sha256(
    `score-authority-reference-v1\0${canonicalScoreAuthorityReferenceJson(value)}`,
  );
}

export function scoreAuthorityReferenceProblems(value: unknown): string[] {
  if (!isRecord(value)) return ['score authority reference must be an object'];
  const problems: string[] = [];
  addExactKeyProblems(value, [
    'subjectKind',
    'subjectIdentity',
    'resolutionHash',
    'evidenceDigest',
    'authorizedForScoring',
  ], 'score authority reference', problems);
  if (!isSubjectKind(value.subjectKind)) {
    problems.push('score authority reference subjectKind is invalid');
  }
  if (!isNormalizedText(value.subjectIdentity)) {
    problems.push(
      'score authority reference subjectIdentity must be a normalized non-empty string',
    );
  }
  if (!isSha256(value.resolutionHash)) {
    problems.push('score authority reference resolutionHash must be SHA-256');
  }
  if (!isSha256(value.evidenceDigest)) {
    problems.push('score authority reference evidenceDigest must be SHA-256');
  }
  if (value.authorizedForScoring !== true) {
    problems.push(
      'score authority reference authorizedForScoring must be exactly true',
    );
  }
  return problems;
}

export function scoreAuthorityResolutionProblems(
  value: unknown,
  evidence?: LabelAuthorityEvidence,
): string[] {
  if (!isRecord(value)) return ['score authority resolution must be an object'];
  const problems: string[] = [];
  addExactKeyProblems(value, [
    'schemaVersion',
    'purpose',
    'decision',
    'reason',
    'repositoryNodeId',
    'actorNodeId',
    'label',
    'eventId',
    'eventTime',
    'authority',
    'source',
    'policyVersion',
    'proofIds',
    'evidenceDigest',
    'authorizedForScoring',
    'resolutionHash',
  ], 'score authority resolution', problems);
  if (value.schemaVersion !== SCORE_AUTHORITY_RESOLUTION_SCHEMA_VERSION) {
    problems.push(
      `score authority resolution schemaVersion must be ` +
        SCORE_AUTHORITY_RESOLUTION_SCHEMA_VERSION,
    );
  }
  if (value.purpose !== SCORE_AUTHORITY_PURPOSE) {
    problems.push(`score authority resolution purpose must be ${SCORE_AUTHORITY_PURPOSE}`);
  }
  if (
    value.decision !== 'authorized_for_scoring' &&
    value.decision !== 'denied_for_scoring'
  ) {
    problems.push('score authority resolution decision is invalid');
  }
  if (!SCORE_AUTHORITY_REASONS.has(value.reason as LabelAuthorityReason)) {
    problems.push('score authority resolution reason is invalid');
  }
  if (
    value.decision === 'authorized_for_scoring' &&
    !AUTHORIZING_REASONS.has(value.reason as LabelAuthorityReason)
  ) {
    problems.push('authorized score authority decisions require an authorizing reason');
  }
  if (
    value.decision === 'denied_for_scoring' &&
    AUTHORIZING_REASONS.has(value.reason as LabelAuthorityReason)
  ) {
    problems.push('denied score authority decisions cannot use an authorizing reason');
  }
  if (!(value.repositoryNodeId == null || isNodeId(value.repositoryNodeId))) {
    problems.push('score authority resolution repositoryNodeId is invalid');
  }
  if (!(value.actorNodeId == null || isNodeId(value.actorNodeId))) {
    problems.push('score authority resolution actorNodeId is invalid');
  }
  if (!isNormalizedText(value.label)) problems.push('score authority resolution label is invalid');
  if (!isNormalizedText(value.eventId)) {
    problems.push('score authority resolution eventId is invalid');
  }
  if (!isTimestamp(value.eventTime)) {
    problems.push('score authority resolution eventTime is invalid');
  }
  if (!AUTHORITIES.has(value.authority as LabelAuthority)) {
    problems.push('score authority resolution authority is invalid');
  }
  if (!SOURCES.has(value.source as LabelAuthoritySource)) {
    problems.push('score authority resolution source is invalid');
  }
  const authorizingSource = AUTHORIZING_REASON_SOURCES.get(
    value.reason as LabelAuthorityReason,
  );
  if (value.decision === 'authorized_for_scoring') {
    if (value.authority !== 'maintainer_human') {
      problems.push(
        'authorized score authority decisions require maintainer_human authority',
      );
    }
    if (authorizingSource && value.source !== authorizingSource) {
      problems.push('authorized score authority reason does not match its source');
    }
  }
  if (
    value.decision === 'denied_for_scoring' &&
    value.authority === 'maintainer_human'
  ) {
    problems.push(
      'denied score authority decisions cannot have maintainer_human authority',
    );
  }
  if (value.policyVersion !== LABEL_AUTHORITY_POLICY_VERSION) {
    problems.push(
      `score authority resolution policyVersion must be ${LABEL_AUTHORITY_POLICY_VERSION}`,
    );
  }
  if (
    !Array.isArray(value.proofIds) ||
    value.proofIds.some((item) => !isNormalizedText(item)) ||
    canonicalJson(value.proofIds) !== canonicalJson(sortedUnique(value.proofIds))
  ) {
    problems.push('score authority resolution proofIds must be sorted unique strings');
  }
  if (!isSha256(value.evidenceDigest)) {
    problems.push('score authority resolution evidenceDigest must be SHA-256');
  }
  if (typeof value.authorizedForScoring !== 'boolean') {
    problems.push('score authority resolution authorizedForScoring must be boolean');
  }
  if (
    value.authorizedForScoring !== (value.decision === 'authorized_for_scoring')
  ) {
    problems.push('score authority resolution decision and scoring flag disagree');
  }
  if (!isSha256(value.resolutionHash)) {
    problems.push('score authority resolution resolutionHash must be SHA-256');
  } else if (
    problems.length === 0 &&
    value.resolutionHash !== scoreAuthorityResolutionHash(
      value as unknown as Omit<ScoreAuthorityResolution, 'resolutionHash'>,
    )
  ) {
    problems.push('score authority resolution hash does not match canonical resolution');
  }
  if (evidence && problems.length === 0) {
    const expected = buildScoreAuthorityResolution(evidence);
    if (
      canonicalScoreAuthorityResolutionJson(
        value as unknown as ScoreAuthorityResolution,
      ) !== canonicalScoreAuthorityResolutionJson(expected)
    ) {
      problems.push('score authority resolution does not match canonical evidence');
    }
  }
  return problems;
}

export function buildScoreAuthorityResolutionRun(input: {
  authorityRunId: string;
  sourceIdentitySchemaVersion: number;
  sourceIdentityDigest: string;
  recordedAt: string;
  previousContentHash: string | null;
  rows: readonly ScoreAuthorityResolutionSubject[];
}): ScoreAuthorityResolutionRun {
  if (!isNormalizedText(input.authorityRunId)) {
    throw new TypeError('Score authority run authorityRunId is invalid');
  }
  if (
    !Number.isInteger(input.sourceIdentitySchemaVersion) ||
    input.sourceIdentitySchemaVersion <= 0
  ) {
    throw new TypeError('Score authority run sourceIdentitySchemaVersion is invalid');
  }
  if (!isSha256(input.sourceIdentityDigest)) {
    throw new TypeError('Score authority run sourceIdentityDigest must be SHA-256');
  }
  const recordedAt = normalizeTimestamp(input.recordedAt);
  if (!isTimestamp(recordedAt)) {
    throw new TypeError('Score authority run recordedAt is invalid');
  }
  if (!(input.previousContentHash == null || isSha256(input.previousContentHash))) {
    throw new TypeError('Score authority run previousContentHash must be SHA-256 or null');
  }

  const subjects = [...input.rows].sort(compareSubjects);
  const duplicateSubject = subjects.find((subject, index) =>
    index > 0 &&
    subject.subjectKind === subjects[index - 1].subjectKind &&
    subject.subjectIdentity === subjects[index - 1].subjectIdentity);
  if (duplicateSubject) {
    throw new TypeError(
      `Score authority run has duplicate subject ` +
        `${duplicateSubject.subjectKind}:${duplicateSubject.subjectIdentity}`,
    );
  }
  const rows = subjects.map((subject, rowOrdinal) =>
    buildScoreAuthorityResolutionRow({
      authorityRunId: input.authorityRunId,
      rowOrdinal,
      subject,
    }));
  const rowsContentHash = scoreAuthorityResolutionRowsContentHash(rows);
  const runWithoutHash = {
    authorityRunId: input.authorityRunId,
    schemaVersion: SCORE_AUTHORITY_RUN_SCHEMA_VERSION,
    policyVersion: LABEL_AUTHORITY_POLICY_VERSION,
    sourceIdentitySchemaVersion: input.sourceIdentitySchemaVersion,
    sourceIdentityDigest: input.sourceIdentityDigest,
    recordedAt,
    rowCount: rows.length,
    rowsContentHash,
    previousContentHash: input.previousContentHash,
    rows,
  } as const;
  return deepFreeze({
    ...runWithoutHash,
    contentHash: scoreAuthorityResolutionRunContentHash(runWithoutHash),
  });
}

export function scoreAuthorityResolutionRowContentHash(
  value: Omit<ScoreAuthorityResolutionRow, 'contentHash'>,
): string {
  return sha256(
    `score-authority-resolution-row-v2\0${canonicalJson([
      value.authorityRunId,
      value.rowOrdinal,
      value.releaseTag,
      value.issueNumber,
      value.subjectKind,
      value.subjectIdentity,
      value.candidateId,
      value.authority,
      value.reason,
      value.authorizedForScoring,
      value.evidenceDigest,
      value.resolutionJson,
    ])}`,
  );
}

export function scoreAuthorityResolutionRowsContentHash(
  rows: readonly ScoreAuthorityResolutionRow[],
): string {
  return sha256(
    `score-authority-resolution-rows-v2\0${canonicalJson(
      [...rows]
        .sort((left, right) => left.rowOrdinal - right.rowOrdinal)
        .map((row) => [row.rowOrdinal, row.contentHash]),
    )}`,
  );
}

export function scoreAuthorityResolutionRunContentHash(
  value: Omit<ScoreAuthorityResolutionRun, 'contentHash'>,
): string {
  return sha256(
    `score-authority-resolution-run-v2\0${value.previousContentHash ?? ''}\0` +
      canonicalJson([
        value.authorityRunId,
        value.schemaVersion,
        value.policyVersion,
        value.sourceIdentitySchemaVersion,
        value.sourceIdentityDigest,
        normalizeTimestamp(value.recordedAt),
        value.rowCount,
        value.rowsContentHash,
      ]),
  );
}

export function canonicalScoreAuthorityResolutionRunJson(
  value: ScoreAuthorityResolutionRun,
): string {
  return canonicalJson({
    authorityRunId: value.authorityRunId,
    schemaVersion: value.schemaVersion,
    policyVersion: value.policyVersion,
    sourceIdentitySchemaVersion: value.sourceIdentitySchemaVersion,
    sourceIdentityDigest: value.sourceIdentityDigest,
    recordedAt: normalizeTimestamp(value.recordedAt),
    rowCount: value.rowCount,
    rowsContentHash: value.rowsContentHash,
    previousContentHash: value.previousContentHash,
    contentHash: value.contentHash,
    rows: [...value.rows].sort((left, right) => left.rowOrdinal - right.rowOrdinal),
  });
}

export function scoreAuthorityResolutionRunProblems(value: unknown): string[] {
  if (!isRecord(value)) return ['score authority run must be an object'];
  const problems: string[] = [];
  addExactKeyProblems(value, [
    'authorityRunId',
    'schemaVersion',
    'policyVersion',
    'sourceIdentitySchemaVersion',
    'sourceIdentityDigest',
    'recordedAt',
    'rowCount',
    'rowsContentHash',
    'previousContentHash',
    'contentHash',
    'rows',
  ], 'score authority run', problems);
  if (!isNormalizedText(value.authorityRunId)) {
    problems.push('score authority run authorityRunId is invalid');
  }
  if (value.schemaVersion !== SCORE_AUTHORITY_RUN_SCHEMA_VERSION) {
    problems.push(
      `score authority run schemaVersion must be ${SCORE_AUTHORITY_RUN_SCHEMA_VERSION}`,
    );
  }
  if (value.policyVersion !== LABEL_AUTHORITY_POLICY_VERSION) {
    problems.push(
      `score authority run policyVersion must be ${LABEL_AUTHORITY_POLICY_VERSION}`,
    );
  }
  if (
    !Number.isInteger(value.sourceIdentitySchemaVersion) ||
    Number(value.sourceIdentitySchemaVersion) <= 0
  ) {
    problems.push('score authority run sourceIdentitySchemaVersion is invalid');
  }
  if (!isSha256(value.sourceIdentityDigest)) {
    problems.push('score authority run sourceIdentityDigest must be SHA-256');
  }
  if (!isTimestamp(value.recordedAt)) {
    problems.push('score authority run recordedAt is invalid');
  }
  if (!(value.previousContentHash == null || isSha256(value.previousContentHash))) {
    problems.push('score authority run previousContentHash is invalid');
  }
  if (!Array.isArray(value.rows)) {
    problems.push('score authority run rows must be an array');
  } else {
    const rows = value.rows as unknown as ScoreAuthorityResolutionRow[];
    rows.forEach((row, index) => {
      problems.push(...scoreAuthorityResolutionRowProblems(row)
        .map((problem) => `score authority run rows[${index}]: ${problem}`));
      if (row.rowOrdinal !== index) {
        problems.push(
          `score authority run rows[${index}] rowOrdinal must equal ${index}`,
        );
      }
      if (row.authorityRunId !== value.authorityRunId) {
        problems.push(
          `score authority run rows[${index}] authorityRunId does not match run`,
        );
      }
    });
    const subjects = rows.map((row) => `${row.subjectKind}\0${row.subjectIdentity}`);
    if (new Set(subjects).size !== subjects.length) {
      problems.push('score authority run has duplicate subject identities');
    }
  }
  if (
    !Number.isInteger(value.rowCount) ||
    !Array.isArray(value.rows) ||
    value.rowCount !== value.rows.length
  ) {
    problems.push('score authority run rowCount does not match rows');
  }
  if (!isSha256(value.rowsContentHash)) {
    problems.push('score authority run rowsContentHash must be SHA-256');
  } else if (
    Array.isArray(value.rows) &&
    value.rowsContentHash !== scoreAuthorityResolutionRowsContentHash(
      value.rows as unknown as ScoreAuthorityResolutionRow[],
    )
  ) {
    problems.push('score authority run rowsContentHash does not match rows');
  }
  if (!isSha256(value.contentHash)) {
    problems.push('score authority run contentHash must be SHA-256');
  } else if (
    problems.length === 0 &&
    value.contentHash !== scoreAuthorityResolutionRunContentHash(
      value as unknown as Omit<ScoreAuthorityResolutionRun, 'contentHash'>,
    )
  ) {
    problems.push('score authority run contentHash does not match canonical run');
  }
  return problems;
}

export function buildReleaseScoreAuditHistoryV2Seal(input: {
  historyRunId: string;
  authorityRunId: string;
  sealedAt: string;
  historyRowCount: number;
  historyRowsContentHash: string;
  authorityRowCount: number;
  authorityRowsContentHash: string;
  previousContentHash: string | null;
}): ReleaseScoreAuditHistoryV2Seal {
  const withoutHash = {
    schemaVersion: RELEASE_SCORE_AUDIT_HISTORY_V2_SEAL_SCHEMA_VERSION,
    historyRunId: input.historyRunId,
    authorityRunId: input.authorityRunId,
    sealedAt: normalizeTimestamp(input.sealedAt),
    historyRowCount: input.historyRowCount,
    historyRowsContentHash: input.historyRowsContentHash,
    authorityRowCount: input.authorityRowCount,
    authorityRowsContentHash: input.authorityRowsContentHash,
    previousContentHash: input.previousContentHash,
  } as const;
  const problems = releaseScoreAuditHistoryV2SealProblems({
    ...withoutHash,
    contentHash: '0'.repeat(64),
  }, { skipContentHashComparison: true });
  if (problems.length > 0) {
    throw new TypeError(
      `Invalid release score audit history v2 seal: ${problems.join('; ')}`,
    );
  }
  return deepFreeze({
    ...withoutHash,
    contentHash: releaseScoreAuditHistoryV2SealContentHash(withoutHash),
  });
}

export function releaseScoreAuditHistoryV2SealContentHash(
  value: Omit<ReleaseScoreAuditHistoryV2Seal, 'contentHash'>,
): string {
  return sha256(
    `release-score-audit-history-v2-seal-v2\0${value.previousContentHash ?? ''}\0` +
      canonicalJson([
        value.schemaVersion,
        value.historyRunId,
        value.authorityRunId,
        normalizeTimestamp(value.sealedAt),
        value.historyRowCount,
        value.historyRowsContentHash,
        value.authorityRowCount,
        value.authorityRowsContentHash,
      ]),
  );
}

export function canonicalReleaseScoreAuditHistoryV2SealJson(
  value: ReleaseScoreAuditHistoryV2Seal,
): string {
  return canonicalJson({
    schemaVersion: value.schemaVersion,
    historyRunId: value.historyRunId,
    authorityRunId: value.authorityRunId,
    sealedAt: normalizeTimestamp(value.sealedAt),
    historyRowCount: value.historyRowCount,
    historyRowsContentHash: value.historyRowsContentHash,
    authorityRowCount: value.authorityRowCount,
    authorityRowsContentHash: value.authorityRowsContentHash,
    previousContentHash: value.previousContentHash,
    contentHash: value.contentHash,
  });
}

export function releaseScoreAuditHistoryV2SealProblems(
  value: unknown,
  options: { skipContentHashComparison?: boolean } = {},
): string[] {
  if (!isRecord(value)) {
    return ['release score audit history v2 seal must be an object'];
  }
  const problems: string[] = [];
  addExactKeyProblems(value, [
    'schemaVersion',
    'historyRunId',
    'authorityRunId',
    'sealedAt',
    'historyRowCount',
    'historyRowsContentHash',
    'authorityRowCount',
    'authorityRowsContentHash',
    'previousContentHash',
    'contentHash',
  ], 'release score audit history v2 seal', problems);
  if (
    value.schemaVersion !==
      RELEASE_SCORE_AUDIT_HISTORY_V2_SEAL_SCHEMA_VERSION
  ) {
    problems.push(
      `release score audit history v2 seal schemaVersion must be ` +
        RELEASE_SCORE_AUDIT_HISTORY_V2_SEAL_SCHEMA_VERSION,
    );
  }
  if (!isNormalizedText(value.historyRunId)) {
    problems.push('release score audit history v2 seal historyRunId is invalid');
  }
  if (!isNormalizedText(value.authorityRunId)) {
    problems.push('release score audit history v2 seal authorityRunId is invalid');
  }
  if (!isTimestamp(value.sealedAt)) {
    problems.push('release score audit history v2 seal sealedAt is invalid');
  }
  if (!Number.isInteger(value.historyRowCount) || value.historyRowCount <= 0) {
    problems.push(
      'release score audit history v2 seal historyRowCount must be positive',
    );
  }
  if (!isSha256(value.historyRowsContentHash)) {
    problems.push(
      'release score audit history v2 seal historyRowsContentHash must be SHA-256',
    );
  }
  if (!Number.isInteger(value.authorityRowCount) || value.authorityRowCount < 0) {
    problems.push(
      'release score audit history v2 seal authorityRowCount must be non-negative',
    );
  }
  if (!isSha256(value.authorityRowsContentHash)) {
    problems.push(
      'release score audit history v2 seal authorityRowsContentHash must be SHA-256',
    );
  }
  if (!(value.previousContentHash == null || isSha256(value.previousContentHash))) {
    problems.push(
      'release score audit history v2 seal previousContentHash is invalid',
    );
  }
  if (!isSha256(value.contentHash)) {
    problems.push(
      'release score audit history v2 seal contentHash must be SHA-256',
    );
  } else if (
    !options.skipContentHashComparison &&
    problems.length === 0 &&
    value.contentHash !== releaseScoreAuditHistoryV2SealContentHash(
      value as unknown as Omit<ReleaseScoreAuditHistoryV2Seal, 'contentHash'>,
    )
  ) {
    problems.push(
      'release score audit history v2 seal contentHash does not match canonical seal',
    );
  }
  return problems;
}

function buildScoreAuthorityResolutionRow(input: {
  authorityRunId: string;
  rowOrdinal: number;
  subject: ScoreAuthorityResolutionSubject;
}): ScoreAuthorityResolutionRow {
  const { subject } = input;
  const resolutionProblems = subject.subjectKind === 'comment'
    ? scoreCommentAuthorityResolutionProblems(subject.resolution)
    : subject.subjectKind === 'closure_claim'
      ? scoreClosureClaimAuthorityResolutionProblems(subject.resolution)
      : scoreAuthorityResolutionProblems(subject.resolution);
  if (resolutionProblems.length > 0) {
    throw new TypeError(
      `Invalid score authority resolution: ${resolutionProblems.join('; ')}`,
    );
  }
  if (!Number.isInteger(subject.issueNumber) || subject.issueNumber <= 0) {
    throw new TypeError('Score authority subject issueNumber must be positive');
  }
  if (!(subject.releaseTag == null || isNormalizedText(subject.releaseTag))) {
    throw new TypeError('Score authority subject releaseTag is invalid');
  }
  if (!isSubjectKind(subject.subjectKind)) {
    throw new TypeError('Score authority subject kind is invalid');
  }
  if (!isNormalizedText(subject.subjectIdentity)) {
    throw new TypeError('Score authority subject identity is invalid');
  }
  if (!(subject.candidateId == null || isNormalizedText(subject.candidateId))) {
    throw new TypeError('Score authority subject candidateId is invalid');
  }
  if (
    subject.subjectKind === 'label_event' &&
    subject.subjectIdentity !==
      (subject.resolution as ScoreAuthorityResolution).eventId
  ) {
    throw new TypeError(
      'Label-event score authority subject identity must equal the event ID',
    );
  }
  if (
    subject.subjectKind === 'comment' &&
    subject.subjectIdentity !==
      (subject.resolution as ScoreCommentAuthorityResolution).commentNodeId
  ) {
    throw new TypeError(
      'Comment score authority subject identity must equal the comment node ID',
    );
  }
  if (
    subject.subjectKind === 'closure_claim' &&
    (
      subject.subjectIdentity !==
        (subject.resolution as ScoreClosureClaimAuthorityResolution).candidateId ||
      subject.candidateId !==
        (subject.resolution as ScoreClosureClaimAuthorityResolution).candidateId
    )
  ) {
    throw new TypeError(
      'Closure-claim score authority subject identity and candidate ID must ' +
        'equal the resolution candidate ID',
    );
  }
  if (
    subject.subjectKind !== 'closure_claim' &&
    subject.candidateId !== null
  ) {
    throw new TypeError(
      'Only closure-claim score authority subjects may carry a candidate ID',
    );
  }
  const withoutHash = {
    authorityRunId: input.authorityRunId,
    rowOrdinal: input.rowOrdinal,
    releaseTag: subject.releaseTag,
    issueNumber: subject.issueNumber,
    subjectKind: subject.subjectKind,
    subjectIdentity: subject.subjectIdentity,
    candidateId: subject.candidateId,
    authority: subject.resolution.authority,
    reason: subject.resolution.reason,
    authorizedForScoring: subject.resolution.authorizedForScoring,
    evidenceDigest: subject.resolution.evidenceDigest,
    resolutionJson: canonicalScoreAuthoritySubjectResolutionJson(
      subject.resolution,
    ),
  } as const;
  return deepFreeze({
    ...withoutHash,
    contentHash: scoreAuthorityResolutionRowContentHash(withoutHash),
  });
}

function scoreAuthorityResolutionRowProblems(value: unknown): string[] {
  if (!isRecord(value)) return ['row must be an object'];
  const problems: string[] = [];
  addExactKeyProblems(value, [
    'authorityRunId',
    'rowOrdinal',
    'releaseTag',
    'issueNumber',
    'subjectKind',
    'subjectIdentity',
    'candidateId',
    'authority',
    'reason',
    'authorizedForScoring',
    'evidenceDigest',
    'resolutionJson',
    'contentHash',
  ], 'score authority row', problems);
  if (!isNormalizedText(value.authorityRunId)) problems.push('authorityRunId is invalid');
  if (!Number.isInteger(value.rowOrdinal) || Number(value.rowOrdinal) < 0) {
    problems.push('rowOrdinal is invalid');
  }
  if (!(value.releaseTag == null || isNormalizedText(value.releaseTag))) {
    problems.push('releaseTag is invalid');
  }
  if (!Number.isInteger(value.issueNumber) || Number(value.issueNumber) <= 0) {
    problems.push('issueNumber is invalid');
  }
  if (!isSubjectKind(value.subjectKind)) problems.push('subjectKind is invalid');
  if (!isNormalizedText(value.subjectIdentity)) problems.push('subjectIdentity is invalid');
  if (!(value.candidateId == null || isNormalizedText(value.candidateId))) {
    problems.push('candidateId is invalid');
  }
  if (!SCORE_AUTHORITIES.has(value.authority as ScoreAuthority)) {
    problems.push('authority is invalid');
  }
  if (!SCORE_REASONS.has(value.reason as ScoreAuthorityReason)) {
    problems.push('reason is invalid');
  }
  if (typeof value.authorizedForScoring !== 'boolean') {
    problems.push('authorizedForScoring is invalid');
  }
  if (!isSha256(value.evidenceDigest)) problems.push('evidenceDigest is invalid');
  if (!isCanonicalJson(value.resolutionJson)) {
    problems.push('resolutionJson must be canonical JSON');
  } else {
    const resolution = JSON.parse(
      value.resolutionJson,
    ) as ScoreAuthoritySubjectResolution;
    const resolutionProblems = value.subjectKind === 'comment'
      ? scoreCommentAuthorityResolutionProblems(resolution)
      : value.subjectKind === 'closure_claim'
        ? scoreClosureClaimAuthorityResolutionProblems(resolution)
        : scoreAuthorityResolutionProblems(resolution);
    problems.push(...resolutionProblems
      .map((problem) => `resolutionJson: ${problem}`));
    if (
      resolution.authority !== value.authority ||
      resolution.reason !== value.reason ||
      resolution.authorizedForScoring !== value.authorizedForScoring ||
      resolution.evidenceDigest !== value.evidenceDigest
    ) {
      problems.push('resolutionJson does not match projected row fields');
    }
    if (
      value.subjectKind === 'closure_claim' &&
      (
        value.subjectIdentity !==
          (resolution as ScoreClosureClaimAuthorityResolution).candidateId ||
        value.candidateId !==
          (resolution as ScoreClosureClaimAuthorityResolution).candidateId
      )
    ) {
      problems.push(
        'closure-claim row identity does not match its resolution candidate ID',
      );
    }
    if (value.subjectKind !== 'closure_claim' && value.candidateId !== null) {
      problems.push('non-closure authority row cannot carry a candidate ID');
    }
  }
  if (!isSha256(value.contentHash)) {
    problems.push('contentHash must be SHA-256');
  } else if (
    problems.length === 0 &&
    value.contentHash !== scoreAuthorityResolutionRowContentHash(
      value as unknown as Omit<ScoreAuthorityResolutionRow, 'contentHash'>,
    )
  ) {
    problems.push('contentHash does not match canonical row');
  }
  return problems;
}

function compareSubjects(
  left: ScoreAuthorityResolutionSubject,
  right: ScoreAuthorityResolutionSubject,
): number {
  return compareBinary(left.subjectKind, right.subjectKind) ||
    compareBinary(left.subjectIdentity, right.subjectIdentity) ||
    compareBinary(left.releaseTag ?? '', right.releaseTag ?? '') ||
    compareBinary(left.candidateId ?? '', right.candidateId ?? '');
}

function isSubjectKind(value: unknown): value is ScoreAuthoritySubjectKind {
  return value === 'closure_claim' ||
    value === 'comment' ||
    value === 'label_event';
}

function scoreAuthorityResolutionSubjectIdentity(
  subjectKind: ScoreAuthoritySubjectKind,
  resolution: ScoreAuthoritySubjectResolution,
): string {
  if (subjectKind === 'closure_claim') {
    if (!isScoreClosureClaimAuthorityResolution(resolution)) {
      throw new TypeError(
        'Closure-claim score authority reference requires a closure-claim resolution',
      );
    }
    return normalizedRequiredText(
      resolution.candidateId,
      'closure-claim resolution candidateId',
    );
  }
  if (subjectKind === 'comment') {
    if (
      isScoreClosureClaimAuthorityResolution(resolution) ||
      resolution.reason !== 'independent_human_reproduction' ||
      !('commentNodeId' in resolution)
    ) {
      throw new TypeError(
        'Comment score authority reference requires a comment resolution',
      );
    }
    return normalizedRequiredText(
      resolution.commentNodeId,
      'comment resolution commentNodeId',
    );
  }
  if (
    isScoreClosureClaimAuthorityResolution(resolution) ||
    resolution.reason === 'independent_human_reproduction' ||
    !('eventId' in resolution)
  ) {
    throw new TypeError(
      'Label-event score authority reference requires a label-event resolution',
    );
  }
  return normalizedRequiredText(
    resolution.eventId,
    'label-event resolution eventId',
  );
}

function closureClaimLabelAuthorityEvidence(
  evidence: ScoreClosureClaimAuthorityEvidence,
): LabelAuthorityEvidence {
  assertImmutableClosureClaimCandidate(evidence.candidate);
  const candidate = evidence.candidate;
  return {
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: candidate.sourceIdentity,
      repositoryNodeId: candidate.repository.nodeId,
      repository: candidate.repository.nameWithOwner,
      issueNumber: candidate.issue.number,
      eventId: candidate.candidateId,
      action: 'labeled',
      label: `closure_claim:${candidate.claimKind}`,
      eventTime: candidate.source.updatedAt,
      actor: {
        nodeId: candidate.source.actor.nodeId,
        login: candidate.source.actor.login,
        type: candidate.source.actor.type,
        association: null,
      },
    },
    permissionObservations: evidence.permissionObservations ?? [],
    approvedRosterEntries: evidence.approvedRosterEntries ?? [],
  };
}

function scoreClosureClaimAuthorityEvidenceProblems(
  value: ScoreClosureClaimAuthorityEvidence,
): string[] {
  const problems: string[] = [];
  try {
    assertImmutableClosureClaimCandidate(value.candidate);
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
    return problems;
  }
  if (!isSha256(value.extractionReceiptId)) {
    problems.push('extractionReceiptId must be SHA-256');
  }
  if (!isSha256(value.extractionReceiptContentHash)) {
    problems.push('extractionReceiptContentHash must be SHA-256');
  }
  if (
    !(value.issueAuthorNodeId == null ||
      isNormalizedText(value.issueAuthorNodeId))
  ) {
    problems.push('issueAuthorNodeId must be a normalized string or null');
  }
  if (
    !(value.issueAuthorType == null || isNormalizedText(value.issueAuthorType))
  ) {
    problems.push('issueAuthorType must be a normalized string or null');
  }
  if (value.finalClosure != null) {
    if (!isNormalizedText(value.finalClosure.sourceIdentity)) {
      problems.push('finalClosure sourceIdentity is invalid');
    }
    if (!isNormalizedText(value.finalClosure.issueNodeId)) {
      problems.push('finalClosure issueNodeId is invalid');
    }
    if (!isNormalizedText(value.finalClosure.eventId)) {
      problems.push('finalClosure eventId is invalid');
    }
    if (!isTimestamp(value.finalClosure.occurredAt)) {
      problems.push('finalClosure occurredAt is invalid');
    }
    if (
      !(value.finalClosure.actorNodeId == null ||
        isNormalizedText(value.finalClosure.actorNodeId))
    ) {
      problems.push('finalClosure actorNodeId is invalid');
    }
    if (
      !(value.finalClosure.actorType == null ||
        isNormalizedText(value.finalClosure.actorType))
    ) {
      problems.push('finalClosure actorType is invalid');
    }
  }
  try {
    const labelEvidence = closureClaimLabelAuthorityEvidence(value);
    problems.push(...labelAuthorityEvidenceProblems(labelEvidence)
      .map((problem) => `maintainer authority evidence: ${problem}`));
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  }
  return problems;
}

function isScoreClosureClaimAuthorityResolution(
  value: ScoreAuthoritySubjectResolution,
): value is ScoreClosureClaimAuthorityResolution {
  return 'candidateId' in value &&
    'claimKind' in value &&
    CLOSURE_CLAIM_KINDS.includes(value.claimKind as ClosureClaimKind);
}

function isClosureClaimAuthoritySource(
  value: unknown,
): value is ScoreClosureClaimAuthoritySource {
  return SOURCES.has(value as LabelAuthoritySource) ||
    value === 'final_closure_event' ||
    value === 'immutable_candidate_actor' ||
    value === 'issue_author_identity';
}

function scoreCommentAuthorityEvidenceProblems(
  value: ScoreCommentAuthorityEvidence,
): string[] {
  const problems: string[] = [];
  if (!Number.isInteger(value.issueNumber) || value.issueNumber <= 0) {
    problems.push('issueNumber must be a positive integer');
  }
  for (const [field, fieldValue] of [
    ['issueNodeId', value.issueNodeId],
    ['issueAuthorNodeId', value.issueAuthorNodeId],
    ['issueAuthorType', value.issueAuthorType],
    ['commentNodeId', value.commentNodeId],
    ['commentUrl', value.commentUrl],
    ['actorNodeId', value.actorNodeId],
    ['claimSnippet', value.claimSnippet],
  ] as const) {
    if (!isNormalizedText(fieldValue)) {
      problems.push(`${field} must be a normalized non-empty string`);
    }
  }
  if (!Number.isInteger(value.commentId) || value.commentId <= 0) {
    problems.push('commentId must be a positive integer');
  }
  if (value.actorType !== 'User') {
    problems.push('actorType must be User');
  }
  if (!isTimestamp(value.commentCreatedAt)) {
    problems.push('commentCreatedAt must be a valid timestamp');
  }
  if (!isTimestamp(value.commentUpdatedAt)) {
    problems.push('commentUpdatedAt must be a valid timestamp');
  }
  if (
    isTimestamp(value.commentCreatedAt) &&
    isTimestamp(value.commentUpdatedAt) &&
    Date.parse(value.commentUpdatedAt) < Date.parse(value.commentCreatedAt)
  ) {
    problems.push('commentUpdatedAt cannot precede commentCreatedAt');
  }
  if (!isSha256(value.commentBodyDigest)) {
    problems.push('commentBodyDigest must be SHA-256');
  }
  if (
    value.actorNodeId === value.issueAuthorNodeId &&
    value.actorType === value.issueAuthorType
  ) {
    problems.push('comment actor must be independent from the issue author');
  }
  return problems;
}

function addExactKeyProblems(
  value: Record<string, unknown>,
  expected: readonly string[],
  context: string,
  problems: string[],
): void {
  const expectedSet = new Set(expected);
  for (const key of Object.keys(value).sort(compareBinary)) {
    if (!expectedSet.has(key)) problems.push(`${context} has unknown key ${key}`);
  }
  for (const key of expected) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      problems.push(`${context} is missing key ${key}`);
    }
  }
}

function sortedUnique(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareBinary);
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

function isNormalizedText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.trim() === value;
}

function normalizedRequiredText(value: unknown, context: string): string {
  if (!isNormalizedText(value)) {
    throw new TypeError(`${context} must be a normalized non-empty string`);
  }
  return value;
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
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

function isRecord(value: unknown): value is Record<string, any> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
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
