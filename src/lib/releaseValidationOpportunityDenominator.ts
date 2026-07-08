import { createHash } from 'node:crypto';
import { normalizeCodeRevision } from './codeRevision';
import {
  canonicalJson,
  verifyOperationReceiptLedger,
  type OperationAttemptLedgerRow,
  type OperationCaptureReceiptLedgerRow,
  type OperationLeaseLedgerRow,
  type OperationStageEventLedgerRow,
} from './operationReceipts';

const HOUR_MS = 3_600_000;

export const RELEASE_VALIDATION_OPPORTUNITIES = {
  first_verified_after_3h: {
    minAgeHours: 3,
    maxAgeHours: 6,
  },
  first_verified_after_24h: {
    minAgeHours: 24,
    maxAgeHours: 30,
  },
} as const;

export type ReleaseValidationOpportunityCode =
  keyof typeof RELEASE_VALIDATION_OPPORTUNITIES;

export const RELEASE_VALIDATION_OPPORTUNITY_ENROLLMENT_SCHEMA_VERSION = 1;
export const RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SCHEMA_VERSION = 3;
export const RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SOURCE_POLICY =
  'prospective_append_only_release_catalog_enrollment_v2';

export type ReleaseValidationOpportunityEnrollmentKind =
  | 'prospective'
  | 'late_discovery_missed';

export interface ReleaseValidationOpportunityEnrollmentInput {
  enrolled_at: string;
  cohort_inception_at: string;
  enrollment_kind: ReleaseValidationOpportunityEnrollmentKind;
  release_node_id: string;
  release_tag: string;
  release_tag_commit_oid: string;
  release_published_at: string;
  opportunity_code: ReleaseValidationOpportunityCode;
  opens_at: string;
  closes_at_exclusive: string;
  score_model_version: string;
  prompt_version: number;
  code_revision: string;
  enrollment_run_id: string;
  operation_attempt_content_hash: string;
  catalog_digest: string;
  catalog_release_count: number;
}

export interface ReleaseValidationOpportunityEnrollmentRow
  extends ReleaseValidationOpportunityEnrollmentInput {
  id: number;
  opportunity_id: string;
  previous_content_hash: string | null;
  content_hash: string;
}

export interface ReleaseValidationForecastForDenominator {
  decision_id: string;
  opportunity_code: string;
  recorded_at: string;
  latest_release_tag: string;
  latest_release_published_at: string;
  score_model_version: string;
  prompt_version: number;
  code_revision?: string | null;
  content_hash?: string;
}

export interface ReleaseValidationAuditHistoryForDenominator {
  run_id: string;
  recorded_at: string;
  score_model_version: string;
  prompt_version: number;
}

export interface ReleaseValidationOpportunityCaptureFailureEvidence {
  runId: string;
  receiptId: string;
  occurredAt: string;
  reason: string;
  attemptContentHash: string;
  stageEventId: string;
  stageEventContentHash: string;
  receiptContentHash: string;
}

export interface ReleaseValidationOpportunitySuccessEvidence {
  runId: string;
  receiptId: string;
  finishedAt: string;
  receiptContentHash: string;
}

export type ReleaseValidationOpportunityDisposition =
  | 'upcoming'
  | 'eligible'
  | 'captured'
  | 'missed'
  | 'failed';

export interface ReleaseValidationOpportunityDenominatorRow {
  opportunityId: string;
  enrollmentContentHash: string;
  stateContentHash: string;
  enrolledAt: string;
  cohortInceptionAt: string;
  enrollmentKind: ReleaseValidationOpportunityEnrollmentKind;
  releaseNodeId: string;
  releaseTag: string;
  releaseTagCommitOid: string;
  releasePublishedAt: string;
  opportunityCode: ReleaseValidationOpportunityCode;
  modelVersion: string;
  promptVersion: number;
  codeRevision: string;
  opensAt: string;
  closesAtExclusive: string;
  enrollmentRunId: string;
  operationAttemptContentHash: string;
  catalogDigest: string;
  catalogReleaseCount: number;
  disposition: ReleaseValidationOpportunityDisposition;
  terminal: boolean;
  capturedDecisionId: string | null;
  capturedContentHash: string | null;
  successEvidence: ReleaseValidationOpportunitySuccessEvidence[];
  failureCount: number;
  failures: ReleaseValidationOpportunityCaptureFailureEvidence[];
}

export interface ReleaseValidationOpportunityDenominatorLedger {
  schemaVersion: typeof RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SCHEMA_VERSION;
  sourcePolicy: typeof RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SOURCE_POLICY;
  asOf: string;
  rowCount: number;
  contentHash: string;
  counts: Record<ReleaseValidationOpportunityDisposition, number>;
  integrity: {
    valid: boolean;
    enrollmentLedgerValid: boolean;
    operationReceiptLedgerVerified: boolean;
    errorCount: number;
    errors: string[];
  };
  rows: ReleaseValidationOpportunityDenominatorRow[];
}

export interface ReleaseValidationOpportunityDenominatorCoverage {
  present: boolean;
  valid: boolean;
  ready: boolean;
  currentStratumKey: string;
  sourcePolicy: string | null;
  contentHash: string | null;
  rowCount: number;
  capturedCount: number;
  upcomingCount: number;
  eligibleCount: number;
  missedCount: number;
  failedCount: number;
  terminalCount: number;
  unmatchedForecastCount: number;
  integrityErrorCount: number;
  errors: string[];
  rows: ReleaseValidationOpportunityDenominatorRow[];
}

export const RELEASE_VALIDATION_OPPORTUNITY_RECONCILIATION_SCHEMA_VERSION = 2;
export const RELEASE_VALIDATION_CATALOG_ATTESTATION_SCHEMA_VERSION = 1;

export type ReleaseValidationOpportunityEligibilityCode =
  | 'eligible'
  | 'outside_scope'
  | 'draft'
  | 'prerelease'
  | 'pre_inception'
  | 'retired_before_open'
  | 'window_closed'
  | 'missing_identity'
  | 'duplicate_identity'
  | 'tag_reuse_conflict'
  | 'planner_error';

export type ReleaseValidationOpportunityReconciliationActionCode =
  | 'create_obligation'
  | 'create_late_missed_obligation'
  | 'retain_obligation'
  | 'exclude'
  | 'block';

export type ReleaseValidationCohortSplit = 'development' | 'holdout';

export interface ReleaseValidationCatalogMember {
  catalogMemberId: string;
  sourceOrder: number;
  firstSeenAt: string;
  nodeId?: string | null;
  tag?: string | null;
  tagCommitOid?: string | null;
  publishedAt?: string | null;
  retiredAt?: string | null;
  draft?: boolean | null;
  prerelease?: boolean | null;
  inScope?: boolean | null;
  plannerError?: string | null;
  contentHash: string;
}

export interface ReleaseValidationCatalogAttestation {
  schemaVersion:
    typeof RELEASE_VALIDATION_CATALOG_ATTESTATION_SCHEMA_VERSION;
  source: string;
  sequence: number;
  observedAt: string;
  previousContentHash: string | null;
  exhaustive: true;
  stabilized: true;
  memberCount: number;
  memberIdOrderedHash: string;
  memberContentOrderedHash: string;
  memberContentSetHash: string;
  releaseIdentitySetHash: string;
  sourceOrderOrderedHash: string;
  contentHash: string;
}

export interface ReleaseValidationCatalogSnapshot {
  attestation: ReleaseValidationCatalogAttestation;
  members: ReleaseValidationCatalogMember[];
}

export interface ReleaseValidationOpportunityPolicy {
  code: string;
  minAgeHours: number;
  maxAgeHours: number;
}

export interface ReleaseValidationReleaseSplitAssignment {
  assignmentId: string;
  cohortKey: string;
  cohortPolicyHash: string;
  cohortInceptionAt: string;
  cohortRetiredAt: string | null;
  releaseIdentity: string;
  catalogMemberId: string;
  catalogMemberContentHash: string;
  catalogAttestationContentHash: string;
  split: ReleaseValidationCohortSplit;
  admissionOrdinal: number;
  assignedAt: string;
  contentHash: string;
}

export interface ReleaseValidationOpportunityObligation {
  obligationId: string;
  cohortKey: string;
  cohortPolicyHash: string;
  cohortInceptionAt: string;
  cohortRetiredAt: string | null;
  releaseIdentity: string;
  catalogMemberId: string;
  catalogMemberContentHash: string;
  catalogAttestationContentHash: string;
  releaseNodeId: string;
  releaseTag: string;
  releaseTagCommitOid: string;
  releasePublishedAt: string;
  opportunityCode: string;
  kind: 'prospective' | 'late_missed';
  admittedAt: string;
  opensAt: string;
  closesAtExclusive: string;
  split: ReleaseValidationCohortSplit;
  contentHash: string;
}

export interface ReleaseValidationOpportunityReconciliationRow {
  reconciliationId: string;
  catalogIndex: number;
  catalogMemberId: string;
  sourceOrder: number;
  releaseIdentity: string | null;
  releaseNodeId: string | null;
  releaseTag: string | null;
  releaseTagCommitOid: string | null;
  releasePublishedAt: string | null;
  opportunityCode: string;
  opensAt: string | null;
  closesAtExclusive: string | null;
  eligibilityCode: ReleaseValidationOpportunityEligibilityCode;
  actionCode: ReleaseValidationOpportunityReconciliationActionCode;
  blocking: boolean;
  reason: string;
  obligationId: string | null;
  obligationKind: ReleaseValidationOpportunityObligation['kind'] | null;
  split: ReleaseValidationCohortSplit | null;
  persistedObligation: boolean;
}

export interface ReleaseValidationOpportunityReconciliationPlan {
  schemaVersion:
    typeof RELEASE_VALIDATION_OPPORTUNITY_RECONCILIATION_SCHEMA_VERSION;
  plannedAt: string;
  cohortKey: string;
  cohortPolicyHash: string;
  cohortInceptionAt: string;
  cohortRetiredAt: string | null;
  catalogSource: string | null;
  catalogAttestationContentHash: string | null;
  catalogHistoryLength: number;
  catalogComplete: boolean;
  catalogMemberCount: number;
  policyOpportunityCount: number;
  expectedRowCount: number;
  rowCount: number;
  blocked: boolean;
  blockingRowCount: number;
  errors: string[];
  rows: ReleaseValidationOpportunityReconciliationRow[];
  obligations: ReleaseValidationOpportunityObligation[];
  obligationsToPersist: ReleaseValidationOpportunityObligation[];
  splitAssignments: ReleaseValidationReleaseSplitAssignment[];
  splitAssignmentsToPersist: ReleaseValidationReleaseSplitAssignment[];
  contentHash: string;
}

interface ReleaseValidationOpportunityReconciliationDraft {
  catalogIndex: number;
  member: ReleaseValidationCatalogMember;
  catalogMemberId: string;
  sourceOrder: number;
  firstSeenAt: string | null;
  releaseIdentity: string | null;
  releaseNodeId: string | null;
  releaseTag: string | null;
  releaseTagCommitOid: string | null;
  releasePublishedAt: string | null;
  opportunity: ReleaseValidationOpportunityPolicy;
  opensAt: string | null;
  closesAtExclusive: string | null;
  eligibilityCode: ReleaseValidationOpportunityEligibilityCode;
  reason: string;
  existingObligation: ReleaseValidationOpportunityObligation | null;
  admissionMember: NormalizedReleaseValidationCatalogMember | null;
  admissionAttestationContentHash: string | null;
}

interface NormalizedReleaseValidationCatalogMember {
  catalogIndex: number;
  member: ReleaseValidationCatalogMember;
  catalogMemberId: string;
  sourceOrder: number;
  firstSeenAt: string | null;
  releaseIdentity: string | null;
  releaseNodeId: string | null;
  releaseTag: string | null;
  releaseTagCommitOid: string | null;
  releasePublishedAt: string | null;
  retiredAt: string | null;
  contentHash: string;
  problems: string[];
}

interface ValidatedReleaseValidationCatalog {
  errors: string[];
  source: string | null;
  currentAttestation: ReleaseValidationCatalogAttestation | null;
  currentMembers: NormalizedReleaseValidationCatalogMember[];
  admissionEvidenceByCatalogMemberId: Map<string, {
    member: NormalizedReleaseValidationCatalogMember;
    attestationContentHash: string;
  }>;
  evidenceByContentReference: Map<string, {
    member: NormalizedReleaseValidationCatalogMember;
    attestationContentHash: string;
  }>;
  reusedTags: Set<string>;
  duplicateReleaseIdentities: Set<string>;
  duplicateCatalogMemberIds: Set<string>;
  duplicateSourceOrders: Set<number>;
}

export function planReleaseValidationOpportunityReconciliation(input: {
  plannedAt: string;
  cohort: {
    modelVersion: string;
    promptVersion: number;
    codeRevision: string;
    inceptionAt: string;
    retiredAt?: string | null;
  };
  catalog: {
    complete: boolean;
    snapshots: ReleaseValidationCatalogSnapshot[];
  };
  policy?: {
    opportunities?: ReleaseValidationOpportunityPolicy[];
    developmentReleaseCount?: number;
  };
  existingObligations?: ReleaseValidationOpportunityObligation[];
  existingSplitAssignments?: ReleaseValidationReleaseSplitAssignment[];
}): ReleaseValidationOpportunityReconciliationPlan {
  const plannedAtMs = requiredTimestamp(input.plannedAt, 'reconciliation plannedAt');
  const plannedAt = new Date(plannedAtMs).toISOString();
  const inceptionAtMs = requiredTimestamp(
    input.cohort.inceptionAt,
    'reconciliation cohort inceptionAt',
  );
  const cohortRetiredAtMs = optionalTimestamp(
    input.cohort.retiredAt,
    'reconciliation cohort retiredAt',
  );
  const cohortInceptionAt = new Date(inceptionAtMs).toISOString();
  const cohortRetiredAt = cohortRetiredAtMs == null
    ? null
    : new Date(cohortRetiredAtMs).toISOString();
  const codeRevision = normalizeCodeRevision(input.cohort.codeRevision);
  if (
    !input.cohort.modelVersion.trim() ||
    !Number.isInteger(input.cohort.promptVersion) ||
    !codeRevision ||
    inceptionAtMs > plannedAtMs ||
    (cohortRetiredAtMs != null && cohortRetiredAtMs < inceptionAtMs)
  ) {
    throw new Error('Release validation reconciliation cohort is invalid');
  }
  const opportunities = input.policy?.opportunities ??
    canonicalOpportunityPolicies();
  const developmentReleaseCount =
    input.policy?.developmentReleaseCount ?? 0;
  if (
    !Number.isInteger(developmentReleaseCount) ||
    developmentReleaseCount < 0
  ) {
    throw new Error(
      'Release validation development release count must be a non-negative integer',
    );
  }
  const policyProblems = opportunityPolicyProblems(opportunities);
  const cohortPolicyHash = releaseValidationOpportunityPolicyHash({
    opportunities,
    developmentReleaseCount,
  });
  const catalogValidation = validateReleaseValidationCatalogHistory({
    complete: input.catalog.complete,
    snapshots: input.catalog.snapshots,
    cohortInceptionAt,
    plannedAt,
  });
  const cohortKey = validationCohortKey({
    modelVersion: input.cohort.modelVersion.trim(),
    promptVersion: input.cohort.promptVersion,
    codeRevision,
    inceptionAt: cohortInceptionAt,
    retiredAt: cohortRetiredAt,
    policyHash: cohortPolicyHash,
    catalogSource: catalogValidation.source,
  });
  const persisted = validatePersistedReleaseValidationReconciliationState({
    obligations: input.existingObligations ?? [],
    splitAssignments: input.existingSplitAssignments ?? [],
    cohortKey,
    cohortPolicyHash,
    cohortInceptionAt,
    cohortRetiredAt,
    opportunities,
    developmentReleaseCount,
    catalogValidation,
  });
  const errors = [
    ...(input.catalog.complete
      ? []
      : ['Release validation catalog is not complete']),
    ...(opportunities.length === 0
      ? ['Release validation policy has no opportunities']
      : []),
    ...policyProblems.errors,
    ...catalogValidation.errors,
    ...persisted.errors,
  ];
  const normalizedMembers = catalogValidation.currentMembers;

  const drafts: ReleaseValidationOpportunityReconciliationDraft[] = [];
  for (const member of normalizedMembers) {
    for (const [policyIndex, opportunity] of opportunities.entries()) {
      const policyProblem = policyProblems.byIndex.get(policyIndex) ?? null;
      const timing = member.releasePublishedAt == null || policyProblem
        ? null
        : opportunityTiming(member.releasePublishedAt, opportunity);
      const existingObligation = member.releaseIdentity == null
        ? null
        : persisted.obligationGroups.get(
          `${member.releaseIdentity}\0${opportunity.code.trim()}`,
        )?.[0] ?? null;
      const admissionEvidence =
        catalogValidation.admissionEvidenceByCatalogMemberId.get(
          member.catalogMemberId,
        ) ?? null;
      const classification = classifyReconciliationCell({
        catalogComplete:
          input.catalog.complete && catalogValidation.errors.length === 0,
        member,
        opportunity,
        policyProblem,
        plannedAtMs,
        inceptionAtMs,
        cohortRetiredAtMs,
        duplicateReleaseIdentities:
          catalogValidation.duplicateReleaseIdentities,
        reusedTags: catalogValidation.reusedTags,
        duplicateCatalogMemberIds:
          catalogValidation.duplicateCatalogMemberIds,
        duplicateSourceOrders: catalogValidation.duplicateSourceOrders,
        existingObligation,
        persistedStateInvalid: persisted.errors.length > 0,
      });
      drafts.push({
        catalogIndex: member.catalogIndex,
        member: member.member,
        catalogMemberId: member.catalogMemberId,
        sourceOrder: member.sourceOrder,
        firstSeenAt: member.firstSeenAt,
        releaseIdentity: member.releaseIdentity,
        releaseNodeId: member.releaseNodeId,
        releaseTag: member.releaseTag,
        releaseTagCommitOid: member.releaseTagCommitOid,
        releasePublishedAt: member.releasePublishedAt,
        opportunity,
        opensAt: timing?.opensAt ?? null,
        closesAtExclusive: timing?.closesAtExclusive ?? null,
        eligibilityCode: classification.code,
        reason: classification.reason,
        existingObligation,
        admissionMember: admissionEvidence?.member ?? null,
        admissionAttestationContentHash:
          admissionEvidence?.attestationContentHash ?? null,
      });
    }
  }

  const releasesNeedingSplit = uniqueBy(
    drafts.filter((draft) =>
      draft.releaseIdentity != null &&
      draft.admissionMember?.releasePublishedAt != null &&
      draft.admissionMember.firstSeenAt != null &&
      draft.admissionAttestationContentHash != null &&
      (
        draft.existingObligation != null ||
        reconciliationCreatesObligation(draft)
      ) &&
      !persisted.splitGroups.has(draft.releaseIdentity)),
    (draft) => draft.releaseIdentity!,
  ).sort((left, right) =>
    Date.parse(left.admissionMember!.firstSeenAt!) -
      Date.parse(right.admissionMember!.firstSeenAt!) ||
    left.admissionMember!.sourceOrder - right.admissionMember!.sourceOrder ||
    left.admissionMember!.catalogMemberId.localeCompare(
      right.admissionMember!.catalogMemberId,
    ) ||
    left.releaseIdentity!.localeCompare(right.releaseIdentity!));
  const maxExistingOrdinal = persisted.splitAssignments.reduce(
    (maximum, row) =>
      Number.isInteger(row.admissionOrdinal)
        ? Math.max(maximum, row.admissionOrdinal)
        : maximum,
    0,
  );
  const splitAssignmentsToPersist =
    releasesNeedingSplit.map((draft, index) => {
      const admissionOrdinal = maxExistingOrdinal + index + 1;
      const admissionMember = draft.admissionMember!;
      return sealReleaseValidationReleaseSplitAssignment({
        cohortKey,
        cohortPolicyHash,
        cohortInceptionAt,
        cohortRetiredAt,
        releaseIdentity: draft.releaseIdentity!,
        catalogMemberId: admissionMember.catalogMemberId,
        catalogMemberContentHash: admissionMember.contentHash,
        catalogAttestationContentHash:
          draft.admissionAttestationContentHash!,
        split: draft.existingObligation?.split ??
          (admissionOrdinal <= developmentReleaseCount
            ? 'development' as const
            : 'holdout' as const),
        admissionOrdinal,
        assignedAt: admissionMember.firstSeenAt!,
      });
    });
  const allSplitAssignments = [
    ...persisted.splitAssignments,
    ...splitAssignmentsToPersist,
  ].sort((left, right) =>
    left.admissionOrdinal - right.admissionOrdinal ||
    left.releaseIdentity.localeCompare(right.releaseIdentity));
  const admissionOrderedAssignments = allSplitAssignments
    .slice()
    .sort((left, right) => {
      const leftEvidence =
        catalogValidation.evidenceByContentReference.get(
          catalogContentReferenceKey(
            left.catalogAttestationContentHash,
            left.catalogMemberContentHash,
          ),
        )?.member;
      const rightEvidence =
        catalogValidation.evidenceByContentReference.get(
          catalogContentReferenceKey(
            right.catalogAttestationContentHash,
            right.catalogMemberContentHash,
          ),
        )?.member;
      return Date.parse(left.assignedAt) - Date.parse(right.assignedAt) ||
        (leftEvidence?.sourceOrder ?? Number.MAX_SAFE_INTEGER) -
          (rightEvidence?.sourceOrder ?? Number.MAX_SAFE_INTEGER) ||
        left.catalogMemberId.localeCompare(right.catalogMemberId) ||
        left.releaseIdentity.localeCompare(right.releaseIdentity);
    });
  for (const [index, assignment] of admissionOrderedAssignments.entries()) {
    if (assignment.admissionOrdinal !== index + 1) {
      errors.push(
        `Release validation split ${assignment.assignmentId} conflicts ` +
        'with authenticated first-seen admission order',
      );
    }
  }
  const splitByReleaseIdentity = new Map(
    allSplitAssignments.map((row) => [row.releaseIdentity, row]),
  );

  const obligationsToPersist: ReleaseValidationOpportunityObligation[] = [];
  const rows = drafts.map((draft) => {
    const splitAssignment = draft.releaseIdentity == null
      ? null
      : splitByReleaseIdentity.get(draft.releaseIdentity) ?? null;
    const action = reconciliationAction(draft, splitAssignment);
    let obligation = draft.existingObligation;
    if (
      obligation == null &&
      action.actionCode !== 'exclude' &&
      action.actionCode !== 'block' &&
      draft.releaseIdentity != null &&
      draft.admissionMember?.releaseNodeId != null &&
      draft.admissionMember.releaseTag != null &&
      draft.admissionMember.releaseTagCommitOid != null &&
      draft.admissionMember.releasePublishedAt != null &&
      draft.admissionMember.firstSeenAt != null &&
      draft.admissionAttestationContentHash != null &&
      draft.opensAt != null &&
      draft.closesAtExclusive != null &&
      splitAssignment != null
    ) {
      obligation = sealReleaseValidationOpportunityObligation({
        cohortKey,
        cohortPolicyHash,
        cohortInceptionAt,
        cohortRetiredAt,
        releaseIdentity: draft.releaseIdentity,
        catalogMemberId: draft.admissionMember.catalogMemberId,
        catalogMemberContentHash: draft.admissionMember.contentHash,
        catalogAttestationContentHash:
          draft.admissionAttestationContentHash,
        releaseNodeId: draft.admissionMember.releaseNodeId,
        releaseTag: draft.admissionMember.releaseTag,
        releaseTagCommitOid: draft.admissionMember.releaseTagCommitOid,
        releasePublishedAt: draft.admissionMember.releasePublishedAt,
        opportunityCode: draft.opportunity.code.trim(),
        kind: action.actionCode === 'create_late_missed_obligation'
          ? 'late_missed'
          : 'prospective',
        admittedAt: draft.admissionMember.firstSeenAt,
        opensAt: draft.opensAt,
        closesAtExclusive: draft.closesAtExclusive,
        split: splitAssignment.split,
      });
      obligationsToPersist.push(obligation);
    }
    const opportunityCode = draft.opportunity.code.trim();
    return {
      reconciliationId: hashValue(
        'release-validation-opportunity-reconciliation-row-v2',
        {
          cohortKey,
          catalogMemberId: draft.catalogMemberId,
          sourceOrder: draft.sourceOrder,
          releaseIdentity: draft.releaseIdentity,
          catalogMemberContentHash: draft.member.contentHash,
          catalogIndex: draft.catalogIndex,
          opportunityCode,
        },
      ),
      catalogIndex: draft.catalogIndex,
      catalogMemberId: draft.catalogMemberId,
      sourceOrder: draft.sourceOrder,
      releaseIdentity: draft.releaseIdentity,
      releaseNodeId: draft.releaseNodeId,
      releaseTag: draft.releaseTag,
      releaseTagCommitOid: draft.releaseTagCommitOid,
      releasePublishedAt: draft.releasePublishedAt,
      opportunityCode,
      opensAt: draft.opensAt,
      closesAtExclusive: draft.closesAtExclusive,
      eligibilityCode: draft.eligibilityCode,
      actionCode: action.actionCode,
      blocking: action.actionCode === 'block',
      reason: action.reason,
      obligationId: obligation?.obligationId ?? null,
      obligationKind: obligation?.kind ?? null,
      split: splitAssignment?.split ?? obligation?.split ?? null,
      persistedObligation: draft.existingObligation != null,
    };
  });
  const obligations = uniqueBy(
    [...persisted.obligations, ...obligationsToPersist],
    (row) => `${row.releaseIdentity}\0${row.opportunityCode}`,
  ).sort((left, right) =>
    left.releasePublishedAt.localeCompare(right.releasePublishedAt) ||
    left.releaseIdentity.localeCompare(right.releaseIdentity) ||
    left.opportunityCode.localeCompare(right.opportunityCode));
  const expectedRowCount =
    normalizedMembers.length * opportunities.length;
  if (rows.length !== expectedRowCount) {
    errors.push(
      `Release validation reconciliation cardinality mismatch: ` +
      `${rows.length} rows for ${expectedRowCount} expected`,
    );
  }
  const uniqueErrors = [...new Set(errors)];
  const blocked = rows.some((row) => row.blocking) || uniqueErrors.length > 0;
  const exposedObligations = blocked
    ? persisted.obligations
    : obligations;
  const exposedSplitAssignments = blocked
    ? persisted.splitAssignments
    : allSplitAssignments;
  const planWithoutHash: Omit<
    ReleaseValidationOpportunityReconciliationPlan,
    'contentHash'
  > = {
    schemaVersion:
      RELEASE_VALIDATION_OPPORTUNITY_RECONCILIATION_SCHEMA_VERSION,
    plannedAt,
    cohortKey,
    cohortPolicyHash,
    cohortInceptionAt,
    cohortRetiredAt,
    catalogSource: catalogValidation.source,
    catalogAttestationContentHash:
      catalogValidation.currentAttestation?.contentHash ?? null,
    catalogHistoryLength: input.catalog.snapshots.length,
    catalogComplete:
      input.catalog.complete && catalogValidation.errors.length === 0,
    catalogMemberCount: normalizedMembers.length,
    policyOpportunityCount: opportunities.length,
    expectedRowCount,
    rowCount: rows.length,
    blocked,
    blockingRowCount: rows.filter((row) => row.blocking).length,
    errors: uniqueErrors,
    rows,
    obligations: exposedObligations,
    obligationsToPersist: blocked ? [] : obligationsToPersist,
    splitAssignments: exposedSplitAssignments,
    splitAssignmentsToPersist: blocked ? [] : splitAssignmentsToPersist,
  };
  return {
    ...planWithoutHash,
    contentHash: hashValue(
      'release-validation-opportunity-reconciliation-plan-v2',
      planWithoutHash,
    ),
  };
}

export function releaseValidationReleaseIdentity(input: {
  nodeId: string;
  tagCommitOid: string;
  publishedAt: string;
}): string {
  return hashValue('release-validation-release-identity-v1', {
    nodeId: input.nodeId.trim(),
    tagCommitOid: input.tagCommitOid.trim().toLowerCase(),
    publishedAt: new Date(
      requiredTimestamp(input.publishedAt, 'release identity publishedAt'),
    ).toISOString(),
  });
}

export function releaseValidationOpportunityObligationId(input: {
  cohortKey: string;
  releaseIdentity: string;
  opportunityCode: string;
}): string {
  return hashValue('release-validation-opportunity-obligation-id-v2', {
    cohortKey: input.cohortKey,
    releaseIdentity: input.releaseIdentity,
    opportunityCode: input.opportunityCode,
  });
}

export function releaseValidationCatalogMemberContentHash(
  input: Omit<ReleaseValidationCatalogMember, 'contentHash'>,
): string {
  return hashValue('release-validation-catalog-member-v1', input);
}

export function releaseValidationCatalogAttestationContentHash(
  input: Omit<ReleaseValidationCatalogAttestation, 'contentHash'>,
): string {
  return hashValue('release-validation-catalog-attestation-v1', input);
}

export function sealReleaseValidationCatalogSnapshot(input: {
  source: string;
  sequence: number;
  observedAt: string;
  previousContentHash: string | null;
  members: ReleaseValidationCatalogMember[];
}): ReleaseValidationCatalogSnapshot {
  const observedAt = new Date(
    requiredTimestamp(input.observedAt, 'catalog observedAt'),
  ).toISOString();
  const orderedMembers = input.members
    .map((member, catalogIndex) => ({ member, catalogIndex }))
    .sort((left, right) =>
      catalogMemberSourceOrder(left.member, left.catalogIndex) -
        catalogMemberSourceOrder(right.member, right.catalogIndex) ||
      left.member.catalogMemberId.localeCompare(right.member.catalogMemberId) ||
      left.catalogIndex - right.catalogIndex)
    .map(({ member }) => member);
  const memberIds = orderedMembers.map((member) => member.catalogMemberId);
  const memberContentHashes = orderedMembers.map((member) => member.contentHash);
  const releaseIdentities = orderedMembers.map(
    (member) => catalogMemberReleaseIdentity(member),
  );
  const sourceOrders = orderedMembers.map((member) => member.sourceOrder);
  const row = {
    schemaVersion:
      RELEASE_VALIDATION_CATALOG_ATTESTATION_SCHEMA_VERSION as 1,
    source: input.source.trim(),
    sequence: input.sequence,
    observedAt,
    previousContentHash: input.previousContentHash,
    exhaustive: true as const,
    stabilized: true as const,
    memberCount: input.members.length,
    memberIdOrderedHash: orderedHash(
      'release-validation-catalog-member-ids-v1',
      memberIds,
    ),
    memberContentOrderedHash: orderedHash(
      'release-validation-catalog-member-content-v1',
      memberContentHashes,
    ),
    memberContentSetHash: exactSetHash(
      'release-validation-catalog-member-content-v1',
      memberContentHashes,
    ),
    releaseIdentitySetHash: exactSetHash(
      'release-validation-catalog-release-identities-v1',
      releaseIdentities,
    ),
    sourceOrderOrderedHash: orderedHash(
      'release-validation-catalog-source-orders-v1',
      sourceOrders,
    ),
  };
  return {
    attestation: {
      ...row,
      contentHash: releaseValidationCatalogAttestationContentHash(row),
    },
    members: input.members,
  };
}

export function releaseValidationOpportunityPolicyHash(input: {
  opportunities: ReleaseValidationOpportunityPolicy[];
  developmentReleaseCount: number;
}): string {
  return hashValue('release-validation-opportunity-policy-v1', {
    opportunities: input.opportunities.map((opportunity) => ({
      code: opportunity.code.trim(),
      minAgeHours: opportunity.minAgeHours,
      maxAgeHours: opportunity.maxAgeHours,
    })),
    developmentReleaseCount: input.developmentReleaseCount,
  });
}

export function releaseValidationReleaseSplitAssignmentId(input: {
  cohortKey: string;
  releaseIdentity: string;
}): string {
  return hashValue('release-validation-release-split-assignment-id-v1', {
    cohortKey: input.cohortKey,
    releaseIdentity: input.releaseIdentity,
  });
}

export function releaseValidationReleaseSplitAssignmentContentHash(
  input: Omit<ReleaseValidationReleaseSplitAssignment, 'contentHash'>,
): string {
  return hashValue(
    'release-validation-release-split-assignment-v1',
    input,
  );
}

export function sealReleaseValidationReleaseSplitAssignment(
  input: Omit<
    ReleaseValidationReleaseSplitAssignment,
    'assignmentId' | 'contentHash'
  >,
): ReleaseValidationReleaseSplitAssignment {
  const assignmentId = releaseValidationReleaseSplitAssignmentId(input);
  const row = { assignmentId, ...input };
  return {
    ...row,
    contentHash:
      releaseValidationReleaseSplitAssignmentContentHash(row),
  };
}

export function releaseValidationOpportunityObligationContentHash(
  input: Omit<ReleaseValidationOpportunityObligation, 'contentHash'>,
): string {
  return hashValue('release-validation-opportunity-obligation-v2', input);
}

export function sealReleaseValidationOpportunityObligation(
  input: Omit<
    ReleaseValidationOpportunityObligation,
    'obligationId' | 'contentHash'
  >,
): ReleaseValidationOpportunityObligation {
  const obligationId = releaseValidationOpportunityObligationId(input);
  const row = { obligationId, ...input };
  return {
    ...row,
    contentHash: releaseValidationOpportunityObligationContentHash(row),
  };
}

export function planReleaseValidationOpportunityEnrollments(input: {
  enrolledAt: string;
  release: {
    nodeId: string;
    tag: string;
    tagCommitOid: string;
    publishedAt: string;
  };
  cohort: {
    modelVersion: string;
    promptVersion: number;
    codeRevision: string;
  };
  evidence: {
    enrollmentRunId: string;
    operationAttemptContentHash: string;
    catalogDigest: string;
    catalogReleaseCount: number;
  };
  cohortInceptionAt?: string | null;
}): ReleaseValidationOpportunityEnrollmentInput[] {
  const enrolledAtMs = requiredTimestamp(input.enrolledAt, 'enrolledAt');
  const cohortInceptionAtMs = input.cohortInceptionAt == null
    ? enrolledAtMs
    : requiredTimestamp(input.cohortInceptionAt, 'cohortInceptionAt');
  const publishedAtMs = requiredTimestamp(
    input.release.publishedAt,
    'release publishedAt',
  );
  const codeRevision = normalizeCodeRevision(input.cohort.codeRevision);
  if (
    !input.release.nodeId.trim() ||
    !input.release.tag.trim() ||
    !isCommitOid(input.release.tagCommitOid) ||
    !input.cohort.modelVersion.trim() ||
    !Number.isInteger(input.cohort.promptVersion) ||
    !codeRevision ||
    !input.evidence.enrollmentRunId.trim() ||
    !isSha256(input.evidence.operationAttemptContentHash) ||
    !isSha256(input.evidence.catalogDigest) ||
    !Number.isInteger(input.evidence.catalogReleaseCount) ||
    input.evidence.catalogReleaseCount <= 0
  ) {
    throw new Error('Release validation opportunity enrollment input is invalid');
  }
  if (cohortInceptionAtMs > enrolledAtMs) {
    throw new Error('Release validation cohort inception cannot follow enrollment');
  }
  if (publishedAtMs > enrolledAtMs) {
    throw new Error('Release validation opportunity enrollment cannot predate publication');
  }

  return (
    Object.entries(RELEASE_VALIDATION_OPPORTUNITIES) as Array<[
      ReleaseValidationOpportunityCode,
      (typeof RELEASE_VALIDATION_OPPORTUNITIES)[ReleaseValidationOpportunityCode],
    ]>
  ).flatMap(([opportunityCode, opportunity]) => {
    const opensAt = new Date(
      publishedAtMs + opportunity.minAgeHours * HOUR_MS,
    ).toISOString();
    const closesAtExclusive = new Date(
      publishedAtMs + opportunity.maxAgeHours * HOUR_MS,
    ).toISOString();
    const closedBeforeDiscovery =
      enrolledAtMs >= Date.parse(closesAtExclusive);
    if (closedBeforeDiscovery && publishedAtMs < cohortInceptionAtMs) return [];
    return [{
      enrolled_at: new Date(enrolledAtMs).toISOString(),
      cohort_inception_at: new Date(cohortInceptionAtMs).toISOString(),
      enrollment_kind: closedBeforeDiscovery
        ? 'late_discovery_missed'
        : 'prospective',
      release_node_id: input.release.nodeId.trim(),
      release_tag: input.release.tag.trim(),
      release_tag_commit_oid: input.release.tagCommitOid.toLowerCase(),
      release_published_at: new Date(publishedAtMs).toISOString(),
      opportunity_code: opportunityCode,
      opens_at: opensAt,
      closes_at_exclusive: closesAtExclusive,
      score_model_version: input.cohort.modelVersion.trim(),
      prompt_version: input.cohort.promptVersion,
      code_revision: codeRevision,
      enrollment_run_id: input.evidence.enrollmentRunId.trim(),
      operation_attempt_content_hash:
        input.evidence.operationAttemptContentHash.toLowerCase(),
      catalog_digest: input.evidence.catalogDigest.toLowerCase(),
      catalog_release_count: input.evidence.catalogReleaseCount,
    }];
  });
}

export function releaseValidationOpportunityId(
  input: Pick<
    ReleaseValidationOpportunityEnrollmentInput,
    | 'release_node_id'
    | 'release_tag'
    | 'release_tag_commit_oid'
    | 'release_published_at'
    | 'opportunity_code'
    | 'opens_at'
    | 'closes_at_exclusive'
    | 'score_model_version'
    | 'prompt_version'
    | 'code_revision'
  >,
): string {
  return hashValue('release-validation-opportunity-identity-v1', {
    releaseNodeId: input.release_node_id,
    releaseTag: input.release_tag,
    releaseTagCommitOid: input.release_tag_commit_oid,
    releasePublishedAt: input.release_published_at,
    opportunityCode: input.opportunity_code,
    opensAt: input.opens_at,
    closesAtExclusive: input.closes_at_exclusive,
    modelVersion: input.score_model_version,
    promptVersion: input.prompt_version,
    codeRevision: normalizeCodeRevision(input.code_revision),
  });
}

export function releaseValidationOpportunityEnrollmentContentHash(
  input: ReleaseValidationOpportunityEnrollmentInput & {
    opportunity_id: string;
    previous_content_hash: string | null;
  },
): string {
  return hashValue('release-validation-opportunity-enrollment-v2', {
    previousContentHash: input.previous_content_hash,
    opportunityId: input.opportunity_id,
    enrolledAt: input.enrolled_at,
    cohortInceptionAt: input.cohort_inception_at,
    enrollmentKind: input.enrollment_kind,
    releaseNodeId: input.release_node_id,
    releaseTag: input.release_tag,
    releaseTagCommitOid: input.release_tag_commit_oid,
    releasePublishedAt: input.release_published_at,
    opportunityCode: input.opportunity_code,
    opensAt: input.opens_at,
    closesAtExclusive: input.closes_at_exclusive,
    modelVersion: input.score_model_version,
    promptVersion: input.prompt_version,
    codeRevision: normalizeCodeRevision(input.code_revision),
    enrollmentRunId: input.enrollment_run_id,
    operationAttemptContentHash: input.operation_attempt_content_hash,
    catalogDigest: input.catalog_digest,
    catalogReleaseCount: input.catalog_release_count,
  });
}

export function validateReleaseValidationOpportunityEnrollmentLedger(
  enrollments: ReleaseValidationOpportunityEnrollmentRow[],
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const seenIds = new Set<string>();
  const seenIdentities = new Set<string>();
  let previousContentHash: string | null = null;
  for (const row of enrollments.slice().sort((left, right) => left.id - right.id)) {
    const label = `${row.release_tag}/${row.opportunity_code}`;
    const opportunity = RELEASE_VALIDATION_OPPORTUNITIES[row.opportunity_code];
    const codeRevision = normalizeCodeRevision(row.code_revision);
    const enrolledAtMs = Date.parse(row.enrolled_at);
    const cohortInceptionAtMs = Date.parse(row.cohort_inception_at);
    const publishedAtMs = Date.parse(row.release_published_at);
    const opensAtMs = Date.parse(row.opens_at);
    const closesAtMs = Date.parse(row.closes_at_exclusive);
    if (
      !Number.isInteger(row.id) ||
      row.id <= 0 ||
      !opportunity ||
      !codeRevision ||
      !isCommitOid(row.release_tag_commit_oid) ||
      !Number.isFinite(enrolledAtMs) ||
      !Number.isFinite(cohortInceptionAtMs) ||
      !Number.isFinite(publishedAtMs) ||
      !Number.isFinite(opensAtMs) ||
      !Number.isFinite(closesAtMs) ||
      enrolledAtMs < publishedAtMs ||
      cohortInceptionAtMs > enrolledAtMs ||
      (
        row.enrollment_kind === 'prospective'
          ? enrolledAtMs >= closesAtMs
          : row.enrollment_kind === 'late_discovery_missed'
            ? enrolledAtMs < closesAtMs ||
              publishedAtMs < cohortInceptionAtMs
            : true
      ) ||
      opensAtMs !== publishedAtMs + opportunity.minAgeHours * HOUR_MS ||
      closesAtMs !== publishedAtMs + opportunity.maxAgeHours * HOUR_MS ||
      !isSha256(row.operation_attempt_content_hash) ||
      !isSha256(row.catalog_digest) ||
      !Number.isInteger(row.catalog_release_count) ||
      row.catalog_release_count <= 0
    ) {
      errors.push(`Enrollment ${label} has invalid immutable identity or timing`);
    }
    const identity = validationOpportunityIdentityKey(row);
    if (seenIdentities.has(identity)) {
      errors.push(`Duplicate validation opportunity enrollment identity ${label}`);
    }
    seenIdentities.add(identity);
    if (seenIds.has(row.opportunity_id)) {
      errors.push(`Duplicate validation opportunity ID ${row.opportunity_id}`);
    }
    seenIds.add(row.opportunity_id);
    if (row.opportunity_id !== releaseValidationOpportunityId(row)) {
      errors.push(`Enrollment ${label} opportunity ID mismatch`);
    }
    if (row.previous_content_hash !== previousContentHash) {
      errors.push(`Enrollment ${label} previous content hash mismatch`);
    }
    if (
      row.content_hash !==
      releaseValidationOpportunityEnrollmentContentHash({
        ...row,
        previous_content_hash: previousContentHash,
      })
    ) {
      errors.push(`Enrollment ${label} content hash mismatch`);
    }
    previousContentHash = row.content_hash;
  }
  return { valid: errors.length === 0, errors };
}

export function buildReleaseValidationOpportunityDenominatorLedger(input: {
  asOf: string;
  enrollments: ReleaseValidationOpportunityEnrollmentRow[];
  forecasts: ReleaseValidationForecastForDenominator[];
  operationLedger?: {
    attempts: OperationAttemptLedgerRow[];
    stageEvents: OperationStageEventLedgerRow[];
    receipts: OperationCaptureReceiptLedgerRow[];
    leases?: OperationLeaseLedgerRow[];
    auditHistory: ReleaseValidationAuditHistoryForDenominator[];
  };
}): ReleaseValidationOpportunityDenominatorLedger {
  const asOfMs = requiredTimestamp(input.asOf, 'denominator asOf');
  const asOf = new Date(asOfMs).toISOString();
  const enrollments = pointInTimeEvidenceRows(
    input.enrollments,
    asOfMs,
    'validation opportunity enrollment',
    (row) => row.enrolled_at,
  );
  const forecasts = pointInTimeEvidenceRows(
    input.forecasts,
    asOfMs,
    'validation forecast',
    (row) => row.recorded_at,
  );
  const operationLedger = input.operationLedger == null
    ? null
    : {
        attempts: pointInTimeEvidenceRows(
          input.operationLedger.attempts,
          asOfMs,
          'refresh operation attempt',
          (row) => row.started_at,
        ),
        stageEvents: pointInTimeEvidenceRows(
          input.operationLedger.stageEvents,
          asOfMs,
          'refresh operation stage event',
          (row) => row.occurred_at,
        ),
        receipts: pointInTimeEvidenceRows(
          input.operationLedger.receipts,
          asOfMs,
          'refresh capture receipt',
          (row) => row.finished_at,
        ),
        leases: input.operationLedger.leases == null
          ? undefined
          : pointInTimeEvidenceRows(
              input.operationLedger.leases,
              asOfMs,
              'refresh lease',
              (row) => row.acquired_at,
            ),
        auditHistory: pointInTimeEvidenceRows(
          input.operationLedger.auditHistory,
          asOfMs,
          'score audit history row',
          (row) => row.recorded_at,
        ),
      };
  const enrollmentIntegrity =
    validateReleaseValidationOpportunityEnrollmentLedger(enrollments);
  const errors = enrollmentIntegrity.errors.slice();
  const forecastsByDecision = new Map(
    forecasts.map((forecast) => [forecast.decision_id, forecast]),
  );
  const successEvidenceByDecision = new Map<
    string,
    ReleaseValidationOpportunitySuccessEvidence[]
  >();
  const failureEvidenceByOpportunity = new Map<
    string,
    ReleaseValidationOpportunityCaptureFailureEvidence[]
  >();
  let operationReceiptLedgerVerified = operationLedger == null;

  if (operationLedger) {
    const verification = verifyOperationReceiptLedger({
      attempts: operationLedger.attempts,
      stageEvents: operationLedger.stageEvents,
      receipts: operationLedger.receipts,
      leases: operationLedger.leases,
      observedAt: asOf,
    });
    operationReceiptLedgerVerified = verification.problems.length === 0;
    errors.push(
      ...verification.problems.map((problem) =>
        `Release validation operation receipt ledger: ${problem}`),
    );
    validateEnrollmentAttemptLinks(
      enrollments,
      operationLedger.attempts,
      errors,
    );
    if (operationReceiptLedgerVerified) {
      reconcileVerifiedSuccessReceipts({
        enrollments,
        forecastsByDecision,
        operationLedger,
        successEvidenceByDecision,
        errors,
      });
      reconcileVerifiedFailureReceipts({
        enrollments,
        operationLedger,
        failureEvidenceByOpportunity,
        errors,
      });
    }
  }

  const rows = enrollments
    .slice()
    .sort((left, right) => left.id - right.id)
    .map((enrollment) => {
      const matchingForecasts = forecasts.filter((forecast) =>
        forecastMatchesEnrollment(forecast, enrollment) &&
        Date.parse(forecast.recorded_at) >= Date.parse(enrollment.enrolled_at));
      if (matchingForecasts.length > 1) {
        errors.push(
          `Enrollment ${enrollment.opportunity_id} has multiple prospective forecasts`,
        );
      }
      const captured = matchingForecasts[0] ?? null;
      const successEvidence = captured
        ? (successEvidenceByDecision.get(captured.decision_id) ?? [])
        : [];
      if (
        captured &&
        operationLedger &&
        successEvidence.length === 0
      ) {
        errors.push(
          `Enrollment ${enrollment.opportunity_id} forecast ` +
          `${captured.decision_id} has no verified success receipt`,
        );
      }
      const failures = (
        failureEvidenceByOpportunity.get(enrollment.opportunity_id) ?? []
      ).slice().sort((left, right) =>
        Date.parse(left.occurredAt) - Date.parse(right.occurredAt) ||
        left.runId.localeCompare(right.runId));
      const nowBeforeOpen = asOfMs < Date.parse(enrollment.opens_at);
      const nowBeforeClose = asOfMs < Date.parse(enrollment.closes_at_exclusive);
      const disposition: ReleaseValidationOpportunityDisposition = captured
        ? 'captured'
        : failures.length > 0
          ? 'failed'
          : enrollment.enrollment_kind === 'late_discovery_missed'
            ? 'missed'
          : nowBeforeOpen
            ? 'upcoming'
            : nowBeforeClose
              ? 'eligible'
              : 'missed';
      const rowWithoutHash = {
        opportunityId: enrollment.opportunity_id,
        enrollmentContentHash: enrollment.content_hash,
        enrolledAt: enrollment.enrolled_at,
        cohortInceptionAt: enrollment.cohort_inception_at,
        enrollmentKind: enrollment.enrollment_kind,
        releaseNodeId: enrollment.release_node_id,
        releaseTag: enrollment.release_tag,
        releaseTagCommitOid: enrollment.release_tag_commit_oid,
        releasePublishedAt: enrollment.release_published_at,
        opportunityCode: enrollment.opportunity_code,
        modelVersion: enrollment.score_model_version,
        promptVersion: enrollment.prompt_version,
        codeRevision: enrollment.code_revision,
        opensAt: enrollment.opens_at,
        closesAtExclusive: enrollment.closes_at_exclusive,
        enrollmentRunId: enrollment.enrollment_run_id,
        operationAttemptContentHash: enrollment.operation_attempt_content_hash,
        catalogDigest: enrollment.catalog_digest,
        catalogReleaseCount: enrollment.catalog_release_count,
        disposition,
        terminal: captured != null ||
          enrollment.enrollment_kind === 'late_discovery_missed' ||
          asOfMs >= Date.parse(enrollment.closes_at_exclusive),
        capturedDecisionId: captured?.decision_id ?? null,
        capturedContentHash: captured?.content_hash ?? null,
        successEvidence,
        failureCount: failures.length,
        failures,
      };
      return {
        ...rowWithoutHash,
        stateContentHash: hashValue(
          'release-validation-opportunity-state-v3',
          { asOf, ...rowWithoutHash },
        ),
      };
    });

  const prospectiveForecasts = forecasts.filter((forecast) =>
    enrollments.some((enrollment) =>
      forecastMatchesEnrollment(forecast, enrollment) &&
      Date.parse(forecast.recorded_at) >= Date.parse(enrollment.enrolled_at)));
  for (const forecast of prospectiveForecasts) {
    const matches = enrollments.filter((enrollment) =>
      forecastMatchesEnrollment(forecast, enrollment) &&
      Date.parse(forecast.recorded_at) >= Date.parse(enrollment.enrolled_at));
    if (matches.length !== 1) {
      errors.push(
        `Forecast ${forecast.decision_id} does not reconcile to exactly one enrollment`,
      );
    }
  }

  const counts = denominatorCounts(rows);
  const integrity = {
    valid: errors.length === 0,
    enrollmentLedgerValid: enrollmentIntegrity.valid,
    operationReceiptLedgerVerified,
    errorCount: errors.length,
    errors,
  };
  const ledgerWithoutHash: Omit<
    ReleaseValidationOpportunityDenominatorLedger,
    'contentHash'
  > = {
    schemaVersion: RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SCHEMA_VERSION,
    sourcePolicy: RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SOURCE_POLICY,
    asOf,
    rowCount: rows.length,
    counts,
    integrity,
    rows,
  };
  return {
    ...ledgerWithoutHash,
    contentHash: releaseValidationOpportunityDenominatorContentHash(
      ledgerWithoutHash,
    ),
  };
}

export function releaseValidationOpportunityDenominatorContentHash(
  input: Omit<ReleaseValidationOpportunityDenominatorLedger, 'contentHash'>,
): string {
  return hashValue('release-validation-opportunity-denominator-v3', input);
}

export function releaseValidationOpportunityDenominatorCoverage(input: {
  ledger?: ReleaseValidationOpportunityDenominatorLedger;
  forecasts: ReleaseValidationForecastForDenominator[];
  currentModelVersion: string;
  currentPromptVersion: number;
  currentCodeRevision: string;
  errors?: string[];
}): ReleaseValidationOpportunityDenominatorCoverage {
  const errors = input.errors ?? [];
  const codeRevision = normalizeCodeRevision(input.currentCodeRevision);
  if (!codeRevision) {
    throw new Error('Current validation code revision is required');
  }
  const currentStratumKey = validationCohortKey({
    modelVersion: input.currentModelVersion,
    promptVersion: input.currentPromptVersion,
    codeRevision,
  });
  if (!input.ledger) {
    const message = 'Current validation opportunity denominator ledger is missing';
    errors.push(message);
    return emptyCoverage(currentStratumKey, [message]);
  }
  const localErrors: string[] = [];
  const ledger = input.ledger;
  const expectedHash = releaseValidationOpportunityDenominatorContentHash({
    schemaVersion: ledger.schemaVersion,
    sourcePolicy: ledger.sourcePolicy,
    asOf: ledger.asOf,
    rowCount: ledger.rowCount,
    counts: ledger.counts,
    integrity: ledger.integrity,
    rows: ledger.rows,
  });
  if (
    ledger.schemaVersion !==
      RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SCHEMA_VERSION ||
    ledger.sourcePolicy !==
      RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SOURCE_POLICY ||
    ledger.rowCount !== ledger.rows.length ||
    ledger.contentHash !== expectedHash
  ) {
    localErrors.push('Validation opportunity denominator header or content hash is invalid');
  }
  localErrors.push(...denominatorLedgerProblems(ledger));
  localErrors.push(...ledger.integrity.errors);
  const rows = ledger.rows.filter((row) =>
    validationCohortKey(row) === currentStratumKey);
  const currentForecasts = input.forecasts.filter((forecast) =>
    forecast.score_model_version === input.currentModelVersion &&
    forecast.prompt_version === input.currentPromptVersion &&
    normalizeCodeRevision(forecast.code_revision) === codeRevision);
  let unmatchedForecastCount = 0;
  for (const forecast of currentForecasts) {
    const matches = rows.filter((row) =>
      row.capturedDecisionId === forecast.decision_id &&
      row.capturedContentHash === (forecast.content_hash ?? null));
    if (matches.length !== 1) {
      unmatchedForecastCount++;
      localErrors.push(
        `Current-stratum forecast ${forecast.decision_id} does not reconcile ` +
        `to exactly one denominator row`,
      );
    }
  }
  for (const row of rows) {
    if (row.disposition === 'captured' &&
      !currentForecasts.some((forecast) =>
        forecast.decision_id === row.capturedDecisionId &&
        forecast.content_hash === row.capturedContentHash)) {
      localErrors.push(
        `Captured denominator row ${row.opportunityId} does not link a current forecast`,
      );
    }
  }
  errors.push(...localErrors);
  const counts = denominatorCounts(rows);
  return {
    present: true,
    valid: localErrors.length === 0,
    ready: localErrors.length === 0 && rows.length > 0,
    currentStratumKey,
    sourcePolicy: ledger.sourcePolicy,
    contentHash: ledger.contentHash,
    rowCount: rows.length,
    capturedCount: counts.captured,
    upcomingCount: counts.upcoming,
    eligibleCount: counts.eligible,
    missedCount: counts.missed,
    failedCount: counts.failed,
    terminalCount: rows.filter((row) => row.terminal).length,
    unmatchedForecastCount,
    integrityErrorCount: localErrors.length,
    errors: localErrors,
    rows,
  };
}

export function validationCohortKey(input: {
  modelVersion?: string;
  score_model_version?: string;
  promptVersion?: number;
  prompt_version?: number;
  codeRevision?: string | null;
  code_revision?: string | null;
  inceptionAt?: string | null;
  retiredAt?: string | null;
  policyHash?: string | null;
  catalogSource?: string | null;
}): string {
  const modelVersion = input.modelVersion ?? input.score_model_version ?? '';
  const promptVersion = input.promptVersion ?? input.prompt_version;
  const codeRevision = normalizeCodeRevision(
    input.codeRevision ?? input.code_revision,
  );
  return hashValue('release-validation-cohort-key-v2', {
    modelVersion,
    promptVersion: promptVersion ?? null,
    codeRevision,
    inceptionAt: input.inceptionAt ?? null,
    retiredAt: input.retiredAt ?? null,
    policyHash: input.policyHash ?? null,
    catalogSource: input.catalogSource ?? null,
  });
}

function canonicalOpportunityPolicies():
ReleaseValidationOpportunityPolicy[] {
  return Object.entries(RELEASE_VALIDATION_OPPORTUNITIES).map(
    ([code, policy]) => ({
      code,
      minAgeHours: policy.minAgeHours,
      maxAgeHours: policy.maxAgeHours,
    }),
  );
}

function opportunityPolicyProblems(
  opportunities: ReleaseValidationOpportunityPolicy[],
): {
  errors: string[];
  byIndex: Map<number, string>;
} {
  const byIndex = new Map<number, string>();
  const codeGroups = groupBy(
    opportunities.map((opportunity, index) => ({ opportunity, index })),
    ({ opportunity }) => opportunity.code.trim(),
  );
  for (const [index, opportunity] of opportunities.entries()) {
    if (
      !opportunity.code.trim() ||
      !Number.isFinite(opportunity.minAgeHours) ||
      !Number.isFinite(opportunity.maxAgeHours) ||
      opportunity.minAgeHours < 0 ||
      opportunity.maxAgeHours <= opportunity.minAgeHours
    ) {
      byIndex.set(index, `Invalid opportunity policy at index ${index}`);
    }
  }
  for (const [code, entries] of codeGroups) {
    if (code && entries.length > 1) {
      for (const entry of entries) {
        byIndex.set(
          entry.index,
          `Duplicate opportunity policy code ${code}`,
        );
      }
    }
  }
  return {
    errors: [...new Set(byIndex.values())],
    byIndex,
  };
}

function normalizeCatalogMember(
  member: ReleaseValidationCatalogMember,
  catalogIndex: number,
): NormalizedReleaseValidationCatalogMember {
  const problems: string[] = [];
  const { contentHash, ...hashInput } = member;
  if (
    !isSha256(contentHash) ||
    releaseValidationCatalogMemberContentHash(hashInput) !== contentHash
  ) {
    problems.push('catalog member content hash is invalid');
  }
  const validSourceOrder =
    Number.isInteger(member.sourceOrder) && member.sourceOrder >= 0;
  const sourceOrder = validSourceOrder ? member.sourceOrder : catalogIndex;
  if (!validSourceOrder) {
    problems.push('catalog source order is invalid');
  }
  const memberId = stringValue(member.catalogMemberId);
  if (!memberId) {
    problems.push('catalog member ID is missing');
  } else if (memberId !== member.catalogMemberId) {
    problems.push('catalog member ID is not canonical');
  }
  const catalogMemberId =
    memberId ?? `missing-catalog-member:${sourceOrder}:${catalogIndex}`;
  const firstSeenAt = normalizedTimestamp(member.firstSeenAt);
  if (!firstSeenAt) {
    problems.push('catalog first-seen timestamp is invalid');
  } else if (firstSeenAt !== member.firstSeenAt) {
    problems.push('catalog first-seen timestamp is not canonical');
  }
  const releaseNodeId = stringValue(member.nodeId);
  const releaseTag = stringValue(member.tag);
  if (releaseNodeId && releaseNodeId !== member.nodeId) {
    problems.push('catalog release node ID is not canonical');
  }
  if (releaseTag && releaseTag !== member.tag) {
    problems.push('catalog release tag is not canonical');
  }
  const rawCommitOid = stringValue(member.tagCommitOid);
  const releaseTagCommitOid = rawCommitOid?.toLowerCase() ?? null;
  if (rawCommitOid && !isCommitOid(rawCommitOid)) {
    problems.push('catalog tag commit OID is malformed');
  } else if (rawCommitOid && rawCommitOid !== releaseTagCommitOid) {
    problems.push('catalog tag commit OID is not canonical');
  }
  const rawPublishedAt = stringValue(member.publishedAt);
  const releasePublishedAt = normalizedTimestamp(rawPublishedAt);
  if (rawPublishedAt && !releasePublishedAt) {
    problems.push('catalog publication timestamp is malformed');
  } else if (rawPublishedAt && rawPublishedAt !== releasePublishedAt) {
    problems.push('catalog publication timestamp is not canonical');
  }
  const rawRetiredAt = stringValue(member.retiredAt);
  const retiredAt = normalizedTimestamp(rawRetiredAt);
  if (rawRetiredAt && !retiredAt) {
    problems.push('catalog retirement timestamp is malformed');
  } else if (rawRetiredAt && rawRetiredAt !== retiredAt) {
    problems.push('catalog retirement timestamp is not canonical');
  }
  if (
    firstSeenAt &&
    releasePublishedAt &&
    Date.parse(firstSeenAt) < Date.parse(releasePublishedAt)
  ) {
    problems.push('catalog member was observed before publication');
  }
  const explicitPlannerError = stringValue(member.plannerError);
  if (explicitPlannerError) {
    problems.push(explicitPlannerError);
  }
  const releaseIdentity =
    releaseNodeId &&
    releaseTag &&
    releaseTagCommitOid &&
    isCommitOid(releaseTagCommitOid) &&
    releasePublishedAt
      ? releaseValidationReleaseIdentity({
        nodeId: releaseNodeId,
        tagCommitOid: releaseTagCommitOid,
        publishedAt: releasePublishedAt,
      })
      : null;
  return {
    catalogIndex,
    member,
    catalogMemberId,
    sourceOrder,
    firstSeenAt,
    releaseIdentity,
    releaseNodeId,
    releaseTag,
    releaseTagCommitOid,
    releasePublishedAt,
    retiredAt,
    contentHash,
    problems,
  };
}

function validateReleaseValidationCatalogHistory(input: {
  complete: boolean;
  snapshots: ReleaseValidationCatalogSnapshot[];
  cohortInceptionAt: string;
  plannedAt: string;
}): ValidatedReleaseValidationCatalog {
  const errors: string[] = [];
  const admissionEvidenceByCatalogMemberId = new Map<string, {
    member: NormalizedReleaseValidationCatalogMember;
    attestationContentHash: string;
  }>();
  const evidenceByContentReference = new Map<string, {
    member: NormalizedReleaseValidationCatalogMember;
    attestationContentHash: string;
  }>();
  const tagOwners = new Map<string, string>();
  const reusedTags = new Set<string>();
  if (!input.complete) {
    errors.push('Release validation catalog is not complete');
  }
  if (input.snapshots.length === 0) {
    errors.push('Release validation catalog attestation history is missing');
  }

  let source: string | null = null;
  let previousSnapshot: {
    snapshot: ReleaseValidationCatalogSnapshot;
    members: NormalizedReleaseValidationCatalogMember[];
  } | null = null;
  let currentMembers: NormalizedReleaseValidationCatalogMember[] = [];
  for (const [snapshotIndex, snapshot] of input.snapshots.entries()) {
    const label = `Catalog attestation ${snapshotIndex + 1}`;
    const attestation = snapshot.attestation;
    const observedAt = normalizedTimestamp(attestation.observedAt);
    const normalizedMembers = snapshot.members.map((member, catalogIndex) =>
      normalizeCatalogMember(member, catalogIndex));
    const expectedSnapshot = observedAt
      ? sealReleaseValidationCatalogSnapshot({
        source: attestation.source,
        sequence: attestation.sequence,
        observedAt,
        previousContentHash: attestation.previousContentHash,
        members: snapshot.members,
      })
      : null;
    if (
      attestation.schemaVersion !==
        RELEASE_VALIDATION_CATALOG_ATTESTATION_SCHEMA_VERSION ||
      attestation.exhaustive !== true ||
      attestation.stabilized !== true ||
      !attestation.source.trim() ||
      attestation.source !== attestation.source.trim() ||
      !Number.isInteger(attestation.sequence) ||
      attestation.sequence !== snapshotIndex + 1 ||
      !observedAt ||
      observedAt !== attestation.observedAt ||
      attestation.previousContentHash !==
        (previousSnapshot?.snapshot.attestation.contentHash ?? null) ||
      !isSha256(attestation.contentHash) ||
      !expectedSnapshot ||
      canonicalJson(attestation) !==
        canonicalJson(expectedSnapshot.attestation)
    ) {
      errors.push(`${label} is not a canonical hash-chained attestation`);
    }
    if (source == null && attestation.source.trim()) {
      source = attestation.source;
    } else if (source != null && attestation.source !== source) {
      errors.push(`${label} changes the catalog source`);
    }
    if (
      snapshotIndex === 0 &&
      observedAt !== input.cohortInceptionAt
    ) {
      errors.push(
        'Release validation catalog history is not rooted at cohort inception',
      );
    }
    if (
      previousSnapshot &&
      observedAt &&
      Date.parse(observedAt) <=
        Date.parse(previousSnapshot.snapshot.attestation.observedAt)
    ) {
      errors.push(`${label} does not advance observation time`);
    }

    const memberIdGroups = groupBy(
      normalizedMembers,
      (member) => member.catalogMemberId,
    );
    const sourceOrderGroups = groupBy(
      normalizedMembers,
      (member) => String(member.sourceOrder),
    );
    for (const [memberId, members] of memberIdGroups) {
      if (members.length > 1) {
        errors.push(`${label} repeats catalog member ID ${memberId}`);
      }
    }
    for (const [sourceOrder, members] of sourceOrderGroups) {
      if (members.length > 1) {
        errors.push(`${label} repeats catalog source order ${sourceOrder}`);
      }
    }
    for (const member of normalizedMembers) {
      if (
        member.firstSeenAt &&
        observedAt &&
        Date.parse(member.firstSeenAt) > Date.parse(observedAt)
      ) {
        errors.push(
          `${label} contains ${member.catalogMemberId} before first-seen admission`,
        );
      }
      if (member.releaseIdentity && member.releaseTag) {
        const owner = tagOwners.get(member.releaseTag);
        if (owner && owner !== member.releaseIdentity) {
          reusedTags.add(member.releaseTag);
        } else {
          tagOwners.set(member.releaseTag, member.releaseIdentity);
        }
      }
      if (!admissionEvidenceByCatalogMemberId.has(member.catalogMemberId)) {
        admissionEvidenceByCatalogMemberId.set(member.catalogMemberId, {
          member,
          attestationContentHash: attestation.contentHash,
        });
      }
      evidenceByContentReference.set(
        catalogContentReferenceKey(attestation.contentHash, member.contentHash),
        { member, attestationContentHash: attestation.contentHash },
      );
    }

    if (previousSnapshot) {
      const previousByMemberId = groupBy(
        previousSnapshot.members,
        (member) => member.catalogMemberId,
      );
      const currentByMemberId = groupBy(
        normalizedMembers,
        (member) => member.catalogMemberId,
      );
      const previousMaxSourceOrder = previousSnapshot.members.reduce(
        (maximum, member) => Math.max(maximum, member.sourceOrder),
        -1,
      );
      for (const previous of previousSnapshot.members) {
        const current = currentByMemberId.get(previous.catalogMemberId) ?? [];
        if (current.length !== 1) {
          errors.push(
            `${label} does not retain prior catalog member ` +
            previous.catalogMemberId,
          );
          continue;
        }
        if (!catalogMemberTransitionIsAppendOnly({
          previous,
          current: current[0],
          previousObservedAt:
            previousSnapshot.snapshot.attestation.observedAt,
          currentObservedAt: attestation.observedAt,
        })) {
          errors.push(
            `${label} rewrites immutable catalog member ` +
            previous.catalogMemberId,
          );
        }
      }
      for (const current of normalizedMembers) {
        if (previousByMemberId.has(current.catalogMemberId)) continue;
        if (
          current.sourceOrder <= previousMaxSourceOrder ||
          current.firstSeenAt == null ||
          Date.parse(current.firstSeenAt) <= Date.parse(
            previousSnapshot.snapshot.attestation.observedAt,
          )
        ) {
          errors.push(
            `${label} backfills unauthenticated admission for ` +
            current.catalogMemberId,
          );
        }
      }
    }
    previousSnapshot = { snapshot, members: normalizedMembers };
    currentMembers = normalizedMembers;
  }

  const currentAttestation =
    input.snapshots.at(-1)?.attestation ?? null;
  if (
    currentAttestation &&
    currentAttestation.observedAt !== input.plannedAt
  ) {
    errors.push(
      'Release validation catalog attestation is stale for the plan time',
    );
  }
  if (currentMembers.length === 0) {
    errors.push('Release validation catalog has no attested members');
  }
  const releaseIdentityGroups = groupBy(
    currentMembers.filter((member) => member.releaseIdentity != null),
    (member) => member.releaseIdentity!,
  );
  const duplicateReleaseIdentities = new Set(
    [...releaseIdentityGroups]
      .filter(([, members]) => members.length > 1)
      .map(([identity]) => identity),
  );
  const catalogMemberIdGroups = groupBy(
    currentMembers,
    (member) => member.catalogMemberId,
  );
  const duplicateCatalogMemberIds = new Set(
    [...catalogMemberIdGroups]
      .filter(([, members]) => members.length > 1)
      .map(([memberId]) => memberId),
  );
  const sourceOrderGroups = groupBy(
    currentMembers,
    (member) => String(member.sourceOrder),
  );
  const duplicateSourceOrders = new Set(
    [...sourceOrderGroups]
      .filter(([, members]) => members.length > 1)
      .map(([sourceOrder]) => Number(sourceOrder)),
  );
  return {
    errors: [...new Set(errors)],
    source,
    currentAttestation,
    currentMembers,
    admissionEvidenceByCatalogMemberId,
    evidenceByContentReference,
    reusedTags,
    duplicateReleaseIdentities,
    duplicateCatalogMemberIds,
    duplicateSourceOrders,
  };
}

function catalogMemberTransitionIsAppendOnly(input: {
  previous: NormalizedReleaseValidationCatalogMember;
  current: NormalizedReleaseValidationCatalogMember;
  previousObservedAt: string;
  currentObservedAt: string;
}): boolean {
  const previousStable = {
    catalogMemberId: input.previous.catalogMemberId,
    sourceOrder: input.previous.sourceOrder,
    firstSeenAt: input.previous.firstSeenAt,
    releaseIdentity: input.previous.releaseIdentity,
    releaseNodeId: input.previous.releaseNodeId,
    releaseTagCommitOid: input.previous.releaseTagCommitOid,
    releasePublishedAt: input.previous.releasePublishedAt,
    draft: input.previous.member.draft ?? null,
    prerelease: input.previous.member.prerelease ?? null,
    inScope: input.previous.member.inScope ?? null,
    plannerError: input.previous.member.plannerError ?? null,
  };
  const currentStable = {
    catalogMemberId: input.current.catalogMemberId,
    sourceOrder: input.current.sourceOrder,
    firstSeenAt: input.current.firstSeenAt,
    releaseIdentity: input.current.releaseIdentity,
    releaseNodeId: input.current.releaseNodeId,
    releaseTagCommitOid: input.current.releaseTagCommitOid,
    releasePublishedAt: input.current.releasePublishedAt,
    draft: input.current.member.draft ?? null,
    prerelease: input.current.member.prerelease ?? null,
    inScope: input.current.member.inScope ?? null,
    plannerError: input.current.member.plannerError ?? null,
  };
  if (canonicalJson(previousStable) !== canonicalJson(currentStable)) {
    return false;
  }
  if (input.previous.retiredAt === input.current.retiredAt) return true;
  return input.previous.retiredAt == null &&
    input.current.retiredAt != null &&
    Date.parse(input.current.retiredAt) >=
      Date.parse(input.previousObservedAt) &&
    Date.parse(input.current.retiredAt) <=
      Date.parse(input.currentObservedAt) &&
    (
      input.current.firstSeenAt == null ||
      Date.parse(input.current.retiredAt) >=
        Date.parse(input.current.firstSeenAt)
    );
}

function validatePersistedReleaseValidationReconciliationState(input: {
  obligations: ReleaseValidationOpportunityObligation[];
  splitAssignments: ReleaseValidationReleaseSplitAssignment[];
  cohortKey: string;
  cohortPolicyHash: string;
  cohortInceptionAt: string;
  cohortRetiredAt: string | null;
  opportunities: ReleaseValidationOpportunityPolicy[];
  developmentReleaseCount: number;
  catalogValidation: ValidatedReleaseValidationCatalog;
}): {
  errors: string[];
  obligations: ReleaseValidationOpportunityObligation[];
  splitAssignments: ReleaseValidationReleaseSplitAssignment[];
  obligationGroups: Map<string, ReleaseValidationOpportunityObligation[]>;
  splitGroups: Map<string, ReleaseValidationReleaseSplitAssignment[]>;
} {
  const errors: string[] = [];
  const obligationGroups = groupBy(
    input.obligations,
    (row) => `${row.releaseIdentity}\0${row.opportunityCode}`,
  );
  const splitGroups = groupBy(
    input.splitAssignments,
    (row) => row.releaseIdentity,
  );
  for (const [key, rows] of obligationGroups) {
    if (rows.length > 1) {
      errors.push(`Duplicate persisted release validation obligation ${key}`);
    }
  }
  for (const [releaseIdentity, rows] of splitGroups) {
    if (rows.length > 1) {
      errors.push(
        `Duplicate persisted release validation split ${releaseIdentity}`,
      );
    }
  }
  const ordinalGroups = groupBy(
    input.splitAssignments,
    (row) => String(row.admissionOrdinal),
  );
  for (const [ordinal, rows] of ordinalGroups) {
    if (
      rows.length > 1 ||
      !Number.isInteger(rows[0].admissionOrdinal) ||
      rows[0].admissionOrdinal <= 0
    ) {
      errors.push(`Invalid persisted release validation split ordinal ${ordinal}`);
    }
  }

  const splitEvidence = new Map<string, {
    member: NormalizedReleaseValidationCatalogMember;
    attestationContentHash: string;
  }>();
  for (const split of input.splitAssignments) {
    const { contentHash, ...hashInput } = split;
    const evidence = input.catalogValidation.evidenceByContentReference.get(
      catalogContentReferenceKey(
        split.catalogAttestationContentHash,
        split.catalogMemberContentHash,
      ),
    ) ?? null;
    if (
      split.cohortKey !== input.cohortKey ||
      split.cohortPolicyHash !== input.cohortPolicyHash ||
      split.cohortInceptionAt !== input.cohortInceptionAt ||
      split.cohortRetiredAt !== input.cohortRetiredAt ||
      split.assignmentId !== releaseValidationReleaseSplitAssignmentId(split) ||
      !isSha256(contentHash) ||
      releaseValidationReleaseSplitAssignmentContentHash(hashInput) !==
        contentHash ||
      !evidence ||
      evidence.member.catalogMemberId !== split.catalogMemberId ||
      evidence.member.releaseIdentity !== split.releaseIdentity ||
      evidence.member.firstSeenAt !== split.assignedAt ||
      (split.split !== 'development' && split.split !== 'holdout') ||
      !Number.isInteger(split.admissionOrdinal) ||
      split.admissionOrdinal <= 0 ||
      normalizedTimestamp(split.assignedAt) !== split.assignedAt
    ) {
      errors.push(
        `Invalid persisted release validation split ${split.assignmentId}`,
      );
      continue;
    }
    splitEvidence.set(split.assignmentId, evidence);
    const expectedSplit = split.admissionOrdinal <= input.developmentReleaseCount
      ? 'development'
      : 'holdout';
    if (split.split !== expectedSplit) {
      errors.push(
        `Persisted release validation split ${split.assignmentId} ` +
        'does not match the bound policy',
      );
    }
  }
  const orderedSplits = input.splitAssignments.slice().sort((left, right) => {
    const leftEvidence = splitEvidence.get(left.assignmentId)?.member;
    const rightEvidence = splitEvidence.get(right.assignmentId)?.member;
    return Date.parse(left.assignedAt) - Date.parse(right.assignedAt) ||
      (leftEvidence?.sourceOrder ?? Number.MAX_SAFE_INTEGER) -
        (rightEvidence?.sourceOrder ?? Number.MAX_SAFE_INTEGER) ||
      left.catalogMemberId.localeCompare(right.catalogMemberId) ||
      left.releaseIdentity.localeCompare(right.releaseIdentity);
  });
  for (const [index, split] of orderedSplits.entries()) {
    if (split.admissionOrdinal !== index + 1) {
      errors.push(
        `Persisted release validation split ${split.assignmentId} ` +
        'does not follow authenticated first-seen admission order',
      );
    }
  }

  const opportunitiesByCode = groupBy(
    input.opportunities,
    (opportunity) => opportunity.code.trim(),
  );
  for (const obligation of input.obligations) {
    const { contentHash, ...hashInput } = obligation;
    const evidence = input.catalogValidation.evidenceByContentReference.get(
      catalogContentReferenceKey(
        obligation.catalogAttestationContentHash,
        obligation.catalogMemberContentHash,
      ),
    ) ?? null;
    const opportunity =
      opportunitiesByCode.get(obligation.opportunityCode)?.[0] ?? null;
    const timing = opportunity && evidence?.member.releasePublishedAt
      ? opportunityTiming(evidence.member.releasePublishedAt, opportunity)
      : null;
    const split = splitGroups.get(obligation.releaseIdentity)?.[0] ?? null;
    const expectedKind = timing && evidence?.member.firstSeenAt
      ? (
        Date.parse(evidence.member.firstSeenAt) >=
          Date.parse(timing.closesAtExclusive)
          ? 'late_missed'
          : 'prospective'
      )
      : null;
    if (
      obligation.cohortKey !== input.cohortKey ||
      obligation.cohortPolicyHash !== input.cohortPolicyHash ||
      obligation.cohortInceptionAt !== input.cohortInceptionAt ||
      obligation.cohortRetiredAt !== input.cohortRetiredAt ||
      obligation.obligationId !== releaseValidationOpportunityObligationId({
        cohortKey: obligation.cohortKey,
        releaseIdentity: obligation.releaseIdentity,
        opportunityCode: obligation.opportunityCode,
      }) ||
      !isSha256(contentHash) ||
      releaseValidationOpportunityObligationContentHash(hashInput) !==
        contentHash ||
      !evidence ||
      evidence.member.catalogMemberId !== obligation.catalogMemberId ||
      evidence.member.releaseIdentity !== obligation.releaseIdentity ||
      evidence.member.releaseNodeId !== obligation.releaseNodeId ||
      evidence.member.releaseTag !== obligation.releaseTag ||
      evidence.member.releaseTagCommitOid !== obligation.releaseTagCommitOid ||
      evidence.member.releasePublishedAt !== obligation.releasePublishedAt ||
      evidence.member.firstSeenAt !== obligation.admittedAt ||
      !timing ||
      timing.opensAt !== obligation.opensAt ||
      timing.closesAtExclusive !== obligation.closesAtExclusive ||
      expectedKind !== obligation.kind ||
      !split ||
      split.split !== obligation.split
    ) {
      errors.push(
        `Invalid persisted release validation obligation ` +
        obligation.obligationId,
      );
    }
  }
  for (const split of input.splitAssignments) {
    if (!input.obligations.some((obligation) =>
      obligation.releaseIdentity === split.releaseIdentity)) {
      errors.push(
        `Persisted release validation split ${split.assignmentId} ` +
        'has no obligation',
      );
    }
  }
  return {
    errors: [...new Set(errors)],
    obligations: input.obligations,
    splitAssignments: input.splitAssignments,
    obligationGroups,
    splitGroups,
  };
}

function classifyReconciliationCell(input: {
  catalogComplete: boolean;
  member: NormalizedReleaseValidationCatalogMember;
  opportunity: ReleaseValidationOpportunityPolicy;
  policyProblem: string | null;
  plannedAtMs: number;
  inceptionAtMs: number;
  cohortRetiredAtMs: number | null;
  duplicateReleaseIdentities: Set<string>;
  reusedTags: Set<string>;
  duplicateCatalogMemberIds: Set<string>;
  duplicateSourceOrders: Set<number>;
  existingObligation: ReleaseValidationOpportunityObligation | null;
  persistedStateInvalid: boolean;
}): {
  code: ReleaseValidationOpportunityEligibilityCode;
  reason: string;
} {
  if (!input.catalogComplete) {
    return {
      code: 'planner_error',
      reason: 'The catalog enumeration is incomplete',
    };
  }
  if (input.policyProblem) {
    return { code: 'planner_error', reason: input.policyProblem };
  }
  if (input.persistedStateInvalid) {
    return {
      code: 'planner_error',
      reason: 'Persisted obligation or split state is invalid',
    };
  }
  if (input.member.problems.length > 0) {
    return {
      code: 'planner_error',
      reason: input.member.problems.join('; '),
    };
  }
  if (
    input.duplicateCatalogMemberIds.has(input.member.catalogMemberId) ||
    input.duplicateSourceOrders.has(input.member.sourceOrder)
  ) {
    return {
      code: 'planner_error',
      reason: 'The catalog member ID or source order is not unique',
    };
  }
  if (
    !input.member.releaseIdentity ||
    !input.member.releaseNodeId ||
    !input.member.releaseTag ||
    !input.member.releaseTagCommitOid ||
    !input.member.releasePublishedAt
  ) {
    return {
      code: 'missing_identity',
      reason: 'The stable catalog member lacks complete release identity',
    };
  }
  if (input.member.firstSeenAt == null) {
    return {
      code: 'planner_error',
      reason: 'The catalog member lacks a valid first-seen timestamp',
    };
  }
  const publishedAtMs = Date.parse(input.member.releasePublishedAt);
  const firstSeenAtMs = Date.parse(input.member.firstSeenAt);
  if (
    publishedAtMs > input.plannedAtMs ||
    firstSeenAtMs > input.plannedAtMs
  ) {
    return {
      code: 'planner_error',
      reason: 'The catalog member identity is dated after the plan',
    };
  }
  if (input.duplicateReleaseIdentities.has(input.member.releaseIdentity)) {
    return {
      code: 'duplicate_identity',
      reason: 'The complete catalog repeats the same release identity',
    };
  }
  if (input.reusedTags.has(input.member.releaseTag)) {
    return {
      code: 'tag_reuse_conflict',
      reason: 'The same release tag resolves to multiple release identities',
    };
  }
  if (input.member.member.inScope === false) {
    return {
      code: 'outside_scope',
      reason: 'The catalog member is outside the validation policy scope',
    };
  }
  if (input.member.member.draft === true) {
    return { code: 'draft', reason: 'Draft releases are not admitted' };
  }
  if (input.member.member.prerelease === true) {
    return {
      code: 'prerelease',
      reason: 'Prereleases are not admitted',
    };
  }
  if (publishedAtMs < input.inceptionAtMs) {
    return {
      code: 'pre_inception',
      reason: 'The release predates the validation cohort',
    };
  }
  const timing = opportunityTiming(
    input.member.releasePublishedAt,
    input.opportunity,
  );
  const memberRetiredAtMs = input.member.retiredAt == null
    ? null
    : Date.parse(input.member.retiredAt);
  const retiredAtMs = minimumNumber([
    memberRetiredAtMs,
    input.cohortRetiredAtMs,
  ]);
  if (
    retiredAtMs != null &&
    retiredAtMs < Date.parse(timing.opensAt)
  ) {
    return {
      code: 'retired_before_open',
      reason: input.existingObligation
        ? 'The release retired before opening, but its admitted obligation remains'
        : 'The release retired before this opportunity opened',
    };
  }
  if (input.plannedAtMs >= Date.parse(timing.closesAtExclusive)) {
    return {
      code: 'window_closed',
      reason: input.existingObligation
        ? 'The opportunity closed after its obligation was admitted'
        : 'The opportunity window is closed',
    };
  }
  return {
    code: 'eligible',
    reason: 'The catalog member is eligible for a prospective obligation',
  };
}

function reconciliationCreatesObligation(
  draft: ReleaseValidationOpportunityReconciliationDraft,
): boolean {
  return draft.existingObligation == null &&
    (draft.eligibilityCode === 'eligible' ||
      draft.eligibilityCode === 'window_closed') &&
    draft.releaseIdentity != null &&
    draft.admissionMember?.releasePublishedAt != null &&
    draft.admissionMember.firstSeenAt != null &&
    draft.admissionAttestationContentHash != null &&
    draft.opensAt != null &&
    draft.closesAtExclusive != null;
}

function reconciliationAction(
  draft: ReleaseValidationOpportunityReconciliationDraft,
  splitAssignment: ReleaseValidationReleaseSplitAssignment | null,
): {
  actionCode: ReleaseValidationOpportunityReconciliationActionCode;
  reason: string;
} {
  if (
    draft.eligibilityCode === 'missing_identity' ||
    draft.eligibilityCode === 'duplicate_identity' ||
    draft.eligibilityCode === 'tag_reuse_conflict' ||
    draft.eligibilityCode === 'planner_error'
  ) {
    return { actionCode: 'block', reason: draft.reason };
  }
  if (draft.existingObligation) {
    return {
      actionCode: 'retain_obligation',
      reason: `${draft.reason}; the persisted obligation is append-only`,
    };
  }
  if (
    draft.eligibilityCode === 'outside_scope' ||
    draft.eligibilityCode === 'draft' ||
    draft.eligibilityCode === 'prerelease' ||
    draft.eligibilityCode === 'pre_inception' ||
    draft.eligibilityCode === 'retired_before_open'
  ) {
    return { actionCode: 'exclude', reason: draft.reason };
  }
  if (
    !splitAssignment ||
    !draft.firstSeenAt ||
    !draft.closesAtExclusive
  ) {
    return {
      actionCode: 'block',
      reason: 'The eligible catalog member has no persisted split assignment',
    };
  }
  if (Date.parse(draft.firstSeenAt) >= Date.parse(draft.closesAtExclusive)) {
    return {
      actionCode: 'create_late_missed_obligation',
      reason: 'The release was first discovered after the opportunity closed',
    };
  }
  return {
    actionCode: 'create_obligation',
    reason: draft.eligibilityCode === 'window_closed'
      ? 'A previously omitted prospective obligation must be reconciled'
      : draft.reason,
  };
}

function opportunityTiming(
  publishedAt: string,
  opportunity: ReleaseValidationOpportunityPolicy,
): {
  opensAt: string;
  closesAtExclusive: string;
} {
  const publishedAtMs = Date.parse(publishedAt);
  return {
    opensAt: new Date(
      publishedAtMs + opportunity.minAgeHours * HOUR_MS,
    ).toISOString(),
    closesAtExclusive: new Date(
      publishedAtMs + opportunity.maxAgeHours * HOUR_MS,
    ).toISOString(),
  };
}

function normalizedTimestamp(value: unknown): string | null {
  const text = stringValue(value);
  if (!text) return null;
  const timestamp = Date.parse(text);
  return Number.isFinite(timestamp)
    ? new Date(timestamp).toISOString()
    : null;
}

function optionalTimestamp(value: unknown, label: string): number | null {
  if (value == null || value === '') return null;
  return requiredTimestamp(String(value), label);
}

function minimumNumber(values: Array<number | null>): number | null {
  const present = values.filter((value): value is number => value != null);
  return present.length > 0 ? Math.min(...present) : null;
}

function groupBy<T>(
  values: T[],
  keyFor: (value: T) => string,
): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const value of values) {
    const key = keyFor(value);
    const rows = groups.get(key) ?? [];
    rows.push(value);
    groups.set(key, rows);
  }
  return groups;
}

function uniqueBy<T>(
  values: T[],
  keyFor: (value: T) => string,
): T[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    const key = keyFor(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function validateEnrollmentAttemptLinks(
  enrollments: ReleaseValidationOpportunityEnrollmentRow[],
  attempts: OperationAttemptLedgerRow[],
  errors: string[],
): void {
  const attemptsByRun = new Map(attempts.map((attempt) => [attempt.run_id, attempt]));
  for (const enrollment of enrollments) {
    const attempt = attemptsByRun.get(enrollment.enrollment_run_id);
    if (
      !attempt ||
      attempt.operation !== 'refresh' ||
      attempt.content_hash !== enrollment.operation_attempt_content_hash ||
      attempt.code_revision !== enrollment.code_revision ||
      Date.parse(attempt.started_at) > Date.parse(enrollment.enrolled_at)
    ) {
      errors.push(
        `Enrollment ${enrollment.opportunity_id} is not bound to its exact refresh attempt`,
      );
    }
  }
}

function reconcileVerifiedSuccessReceipts(input: {
  enrollments: ReleaseValidationOpportunityEnrollmentRow[];
  forecastsByDecision: Map<string, ReleaseValidationForecastForDenominator>;
  operationLedger: NonNullable<
    Parameters<typeof buildReleaseValidationOpportunityDenominatorLedger>[0]['operationLedger']
  >;
  successEvidenceByDecision: Map<
    string,
    ReleaseValidationOpportunitySuccessEvidence[]
  >;
  errors: string[];
}): void {
  const attemptsByRun = new Map(
    input.operationLedger.attempts.map((attempt) => [attempt.run_id, attempt]),
  );
  const auditsByRun = auditCohorts(input.operationLedger.auditHistory);
  for (const receipt of input.operationLedger.receipts) {
    const attempt = attemptsByRun.get(receipt.run_id);
    if (receipt.status !== 'success' || attempt?.operation !== 'refresh') continue;
    const payload = parseRecord(receipt.payload_json);
    const forecastPayload = parseRecord(payload?.forecast);
    const releaseCatalog = parseRecord(payload?.releaseCatalog);
    const latestStable = parseRecord(releaseCatalog?.attestation)?.latestStable;
    const latest = parseRecord(latestStable);
    const scoreHistory = parseRecord(payload?.scoreHistory);
    const scoreCommit = parseRecord(payload?.scoreCommit);
    const historyRunId = stringValue(scoreHistory?.runId);
    const cohort = historyRunId ? auditsByRun.get(historyRunId) : null;
    const releaseTag = stringValue(latest?.tag);
    const releasePublishedAt = timestampValue(latest?.publishedAt);
    const capturedAt = timestampValue(scoreCommit?.commitNotAfter);
    const codeRevision = normalizeCodeRevision(attempt.code_revision);
    if (
      !payload ||
      !forecastPayload ||
      !cohort ||
      !releaseTag ||
      !releasePublishedAt ||
      !capturedAt ||
      !codeRevision
    ) {
      input.errors.push(
        `Verified success receipt ${receipt.receipt_id} lacks exact denominator cohort evidence`,
      );
      continue;
    }
    const cohortInception = earliestCohortEnrollment(
      input.enrollments,
      cohort.modelVersion,
      cohort.promptVersion,
      codeRevision,
    );
    if (cohortInception == null || Date.parse(capturedAt) < cohortInception) continue;
    const relevant = input.enrollments.filter((enrollment) =>
      enrollment.release_tag === releaseTag &&
      enrollment.release_published_at === releasePublishedAt &&
      enrollment.score_model_version === cohort.modelVersion &&
      enrollment.prompt_version === cohort.promptVersion &&
      enrollment.code_revision === codeRevision &&
      Date.parse(enrollment.enrolled_at) <= Date.parse(capturedAt));
    const expectedCodes = relevant
      .filter((enrollment) =>
        Date.parse(capturedAt) >= Date.parse(enrollment.opens_at) &&
        Date.parse(capturedAt) < Date.parse(enrollment.closes_at_exclusive))
      .map((enrollment) => enrollment.opportunity_code)
      .sort();
    const captures = Array.isArray(forecastPayload.captures)
      ? forecastPayload.captures
        .map(parseRecord)
        .filter((capture): capture is Record<string, unknown> => capture != null)
      : [];
    const actualCodes = captures
      .map((capture) => stringValue(capture.opportunityCode) ?? '')
      .sort();
    if (canonicalJson(actualCodes) !== canonicalJson(expectedCodes)) {
      input.errors.push(
        `Verified success receipt ${receipt.receipt_id} forecast set does not ` +
        `exactly reconcile to persisted enrollment`,
      );
    }
    for (const capture of captures) {
      const decisionId = stringValue(capture.decisionId);
      const opportunityCode = stringValue(capture.opportunityCode);
      const forecast = decisionId
        ? input.forecastsByDecision.get(decisionId)
        : undefined;
      const enrollment = relevant.find((row) =>
        row.opportunity_code === opportunityCode);
      if (
        !decisionId ||
        !forecast ||
        !enrollment ||
        capture.opportunityId !== enrollment.opportunity_id ||
        capture.enrollmentContentHash !== enrollment.content_hash ||
        !forecastMatchesEnrollment(forecast, enrollment)
      ) {
        input.errors.push(
          `Verified success receipt ${receipt.receipt_id} has an unmatched forecast capture`,
        );
        continue;
      }
      const evidence = input.successEvidenceByDecision.get(decisionId) ?? [];
      evidence.push({
        runId: receipt.run_id,
        receiptId: receipt.receipt_id,
        finishedAt: receipt.finished_at,
        receiptContentHash: receipt.content_hash,
      });
      input.successEvidenceByDecision.set(decisionId, evidence);
    }
  }
}

function reconcileVerifiedFailureReceipts(input: {
  enrollments: ReleaseValidationOpportunityEnrollmentRow[];
  operationLedger: NonNullable<
    Parameters<typeof buildReleaseValidationOpportunityDenominatorLedger>[0]['operationLedger']
  >;
  failureEvidenceByOpportunity: Map<
    string,
    ReleaseValidationOpportunityCaptureFailureEvidence[]
  >;
  errors: string[];
}): void {
  const attemptsByRun = new Map(
    input.operationLedger.attempts.map((attempt) => [attempt.run_id, attempt]),
  );
  const stagesByRun = new Map<string, OperationStageEventLedgerRow[]>();
  for (const stage of input.operationLedger.stageEvents) {
    const rows = stagesByRun.get(stage.run_id) ?? [];
    rows.push(stage);
    stagesByRun.set(stage.run_id, rows);
  }
  for (const receipt of input.operationLedger.receipts) {
    const attempt = attemptsByRun.get(receipt.run_id);
    if (receipt.status !== 'failure' || attempt?.operation !== 'refresh') continue;
    const failedStage = (stagesByRun.get(receipt.run_id) ?? []).find((stage) =>
      stage.stage === 'forecast.capture' && stage.status === 'failed');
    if (!failedStage) continue;
    const details = parseRecord(failedStage.details_json);
    const plan = parseRecord(details?.forecastPlan);
    const codeRevision = normalizeCodeRevision(attempt.code_revision);
    const cohortInception = codeRevision
      ? earliestRevisionEnrollment(input.enrollments, codeRevision)
      : null;
    if (cohortInception == null ||
      Date.parse(failedStage.occurred_at) < cohortInception) {
      continue;
    }
    if (
      !plan ||
      plan.schemaVersion !== 1 ||
      !codeRevision ||
      normalizeCodeRevision(
        typeof plan.codeRevision === 'string' ? plan.codeRevision : null,
      ) !== codeRevision
    ) {
      input.errors.push(
        `Verified forecast capture failure ${receipt.receipt_id} lacks its exact enrollment plan`,
      );
      continue;
    }
    const releaseTag = stringValue(plan.latestReleaseTag);
    const releasePublishedAt = timestampValue(plan.latestReleasePublishedAt);
    const modelVersion = stringValue(plan.scoreModelVersion);
    const promptVersion = integerValue(plan.promptVersion);
    const slots = Array.isArray(plan.slots)
      ? plan.slots
        .map(parseRecord)
        .map((slot) => stringValue(slot?.opportunityCode))
        .filter((value): value is string => value != null)
      : [];
    const enrollmentEvidence = Array.isArray(details?.enrollments)
      ? details.enrollments
        .map(parseRecord)
        .filter((row): row is Record<string, unknown> => row != null)
      : [];
    if (
      !releaseTag ||
      !releasePublishedAt ||
      !modelVersion ||
      promptVersion == null
    ) {
      input.errors.push(
        `Verified forecast capture failure ${receipt.receipt_id} has malformed cohort evidence`,
      );
      continue;
    }
    const matching = input.enrollments.filter((enrollment) =>
      enrollment.release_tag === releaseTag &&
      enrollment.release_published_at === releasePublishedAt &&
      enrollment.score_model_version === modelVersion &&
      enrollment.prompt_version === promptVersion &&
      enrollment.code_revision === codeRevision &&
      slots.includes(enrollment.opportunity_code) &&
      Date.parse(failedStage.occurred_at) >= Date.parse(enrollment.opens_at) &&
      Date.parse(failedStage.occurred_at) <
        Date.parse(enrollment.closes_at_exclusive));
    if (matching.length === 0 && cohortInception != null) {
      input.errors.push(
        `Verified forecast capture failure ${receipt.receipt_id} does not match persisted enrollment`,
      );
      continue;
    }
    for (const enrollment of matching) {
      const boundEnrollment = enrollmentEvidence.find((row) =>
        row.opportunityId === enrollment.opportunity_id &&
        row.opportunityCode === enrollment.opportunity_code &&
        row.enrollmentContentHash === enrollment.content_hash);
      if (!boundEnrollment) {
        input.errors.push(
          `Verified forecast capture failure ${receipt.receipt_id} does not ` +
          `bind enrollment ${enrollment.opportunity_id}`,
        );
        continue;
      }
      const failures =
        input.failureEvidenceByOpportunity.get(enrollment.opportunity_id) ?? [];
      failures.push({
        runId: receipt.run_id,
        receiptId: receipt.receipt_id,
        occurredAt: failedStage.occurred_at,
        reason: failureReason(details, receipt.payload_json),
        attemptContentHash: attempt.content_hash,
        stageEventId: failedStage.event_id,
        stageEventContentHash: failedStage.content_hash,
        receiptContentHash: receipt.content_hash,
      });
      input.failureEvidenceByOpportunity.set(enrollment.opportunity_id, failures);
    }
  }
}

function forecastMatchesEnrollment(
  forecast: ReleaseValidationForecastForDenominator,
  enrollment: ReleaseValidationOpportunityEnrollmentRow,
): boolean {
  return forecast.latest_release_tag === enrollment.release_tag &&
    forecast.latest_release_published_at === enrollment.release_published_at &&
    forecast.opportunity_code === enrollment.opportunity_code &&
    forecast.score_model_version === enrollment.score_model_version &&
    forecast.prompt_version === enrollment.prompt_version &&
    normalizeCodeRevision(forecast.code_revision) === enrollment.code_revision &&
    Number.isFinite(Date.parse(forecast.recorded_at)) &&
    Date.parse(forecast.recorded_at) >= Date.parse(enrollment.opens_at) &&
    Date.parse(forecast.recorded_at) <
      Date.parse(enrollment.closes_at_exclusive);
}

function validationOpportunityIdentityKey(
  input: Pick<
    ReleaseValidationOpportunityEnrollmentInput,
    | 'release_tag'
    | 'opportunity_code'
    | 'score_model_version'
    | 'prompt_version'
    | 'code_revision'
  >,
): string {
  return [
    input.release_tag,
    input.opportunity_code,
    input.score_model_version,
    input.prompt_version,
    normalizeCodeRevision(input.code_revision),
  ].join('\0');
}

function auditCohorts(
  rows: ReleaseValidationAuditHistoryForDenominator[],
): Map<string, { modelVersion: string; promptVersion: number } | null> {
  const values = new Map<string, Array<{
    modelVersion: string;
    promptVersion: number;
  }>>();
  for (const row of rows) {
    const cohort = values.get(row.run_id) ?? [];
    cohort.push({
      modelVersion: row.score_model_version,
      promptVersion: row.prompt_version,
    });
    values.set(row.run_id, cohort);
  }
  return new Map([...values].map(([runId, cohorts]) => {
    const unique = new Map(
      cohorts.map((cohort) => [
        `${cohort.modelVersion}\0${cohort.promptVersion}`,
        cohort,
      ]),
    );
    return [runId, unique.size === 1 ? [...unique.values()][0] : null];
  }));
}

function earliestCohortEnrollment(
  enrollments: ReleaseValidationOpportunityEnrollmentRow[],
  modelVersion: string,
  promptVersion: number,
  codeRevision: string,
): number | null {
  return minimumTimestamp(enrollments
    .filter((row) =>
      row.score_model_version === modelVersion &&
      row.prompt_version === promptVersion &&
      row.code_revision === codeRevision)
    .map((row) => row.enrolled_at));
}

function earliestRevisionEnrollment(
  enrollments: ReleaseValidationOpportunityEnrollmentRow[],
  codeRevision: string,
): number | null {
  return minimumTimestamp(enrollments
    .filter((row) => row.code_revision === codeRevision)
    .map((row) => row.enrolled_at));
}

function minimumTimestamp(values: string[]): number | null {
  const timestamps = values
    .map((value) => Date.parse(value))
    .filter(Number.isFinite);
  return timestamps.length > 0 ? Math.min(...timestamps) : null;
}

function failureReason(
  details: Record<string, unknown> | null,
  receiptPayloadJson: string,
): string {
  const detailError = parseRecord(details?.error);
  const receiptError = parseRecord(parseRecord(receiptPayloadJson)?.error);
  return stringValue(detailError?.message) ??
    stringValue(receiptError?.message) ??
    'forecast_capture_failed';
}

function denominatorLedgerProblems(
  ledger: ReleaseValidationOpportunityDenominatorLedger,
): string[] {
  const problems: string[] = [];
  const asOf = normalizedTimestamp(ledger.asOf);
  const asOfMs = asOf == null ? Number.NaN : Date.parse(asOf);
  if (asOf == null || asOf !== ledger.asOf) {
    problems.push('Validation opportunity denominator asOf is not canonical');
  }
  const counts = denominatorCounts(ledger.rows);
  for (const disposition of [
    'upcoming',
    'eligible',
    'captured',
    'missed',
    'failed',
  ] as const) {
    if (ledger.counts[disposition] !== counts[disposition]) {
      problems.push(
        `Validation opportunity denominator ${disposition} count does not ` +
        'match its rows',
      );
    }
  }
  if (
    ledger.integrity.errorCount !== ledger.integrity.errors.length ||
    ledger.integrity.valid !== (
      ledger.integrity.enrollmentLedgerValid &&
      ledger.integrity.operationReceiptLedgerVerified &&
      ledger.integrity.errors.length === 0
    )
  ) {
    problems.push(
      'Validation opportunity denominator integrity summary is inconsistent',
    );
  }

  const seenOpportunityIds = new Set<string>();
  const seenCapturedDecisionIds = new Set<string>();
  for (const [index, row] of ledger.rows.entries()) {
    const label = `Validation opportunity denominator row ${index + 1}`;
    if (!isSha256(row.opportunityId)) {
      problems.push(`${label} opportunity ID is invalid`);
    } else if (seenOpportunityIds.has(row.opportunityId)) {
      problems.push(`${label} repeats opportunity ${row.opportunityId}`);
    } else {
      seenOpportunityIds.add(row.opportunityId);
    }
    if (
      !isSha256(row.enrollmentContentHash) ||
      !isSha256(row.stateContentHash)
    ) {
      problems.push(`${label} content hash is invalid`);
    }
    const codeRevision = normalizeCodeRevision(row.codeRevision);
    if (!codeRevision || codeRevision !== row.codeRevision) {
      problems.push(`${label} code revision is invalid`);
    }
    const enrolledAt = normalizedTimestamp(row.enrolledAt);
    const cohortInceptionAt = normalizedTimestamp(row.cohortInceptionAt);
    const publishedAt = normalizedTimestamp(row.releasePublishedAt);
    const opensAt = normalizedTimestamp(row.opensAt);
    const closesAtExclusive = normalizedTimestamp(row.closesAtExclusive);
    if (
      enrolledAt !== row.enrolledAt ||
      cohortInceptionAt !== row.cohortInceptionAt ||
      publishedAt !== row.releasePublishedAt ||
      opensAt !== row.opensAt ||
      closesAtExclusive !== row.closesAtExclusive
    ) {
      problems.push(`${label} timestamps are not canonical`);
    }
    if (
      enrolledAt &&
      cohortInceptionAt &&
      publishedAt &&
      opensAt &&
      closesAtExclusive &&
      (
        Date.parse(cohortInceptionAt) > Date.parse(enrolledAt) ||
        Date.parse(publishedAt) > Date.parse(enrolledAt) ||
        Date.parse(opensAt) >= Date.parse(closesAtExclusive)
      )
    ) {
      problems.push(`${label} timing is inconsistent`);
    }
    if (
      !['prospective', 'late_discovery_missed'].includes(row.enrollmentKind)
    ) {
      problems.push(`${label} enrollment kind is invalid`);
    }
    if (row.failureCount !== row.failures.length) {
      problems.push(`${label} failure count does not match its evidence`);
    }
    const hasCapturedDecision = row.capturedDecisionId != null;
    const hasCapturedHash = row.capturedContentHash != null;
    if (hasCapturedDecision !== hasCapturedHash) {
      problems.push(`${label} has partial captured forecast identity`);
    }
    if (row.capturedContentHash != null &&
      !isSha256(row.capturedContentHash)) {
      problems.push(`${label} captured forecast content hash is invalid`);
    }
    if (row.capturedDecisionId != null) {
      if (!row.capturedDecisionId.trim()) {
        problems.push(`${label} captured decision ID is invalid`);
      } else if (seenCapturedDecisionIds.has(row.capturedDecisionId)) {
        problems.push(
          `${label} repeats captured decision ${row.capturedDecisionId}`,
        );
      } else {
        seenCapturedDecisionIds.add(row.capturedDecisionId);
      }
    }
    const expectedDisposition: ReleaseValidationOpportunityDisposition =
      hasCapturedDecision && hasCapturedHash
        ? 'captured'
        : row.failureCount > 0
          ? 'failed'
          : row.enrollmentKind === 'late_discovery_missed'
            ? 'missed'
            : Number.isFinite(asOfMs) && opensAt &&
                asOfMs < Date.parse(opensAt)
              ? 'upcoming'
              : Number.isFinite(asOfMs) && closesAtExclusive &&
                  asOfMs < Date.parse(closesAtExclusive)
                ? 'eligible'
                : 'missed';
    if (row.disposition !== expectedDisposition) {
      problems.push(
        `${label} disposition ${row.disposition} does not match ` +
        expectedDisposition,
      );
    }
    const expectedTerminal =
      expectedDisposition === 'captured' ||
      row.enrollmentKind === 'late_discovery_missed' ||
      (
        Number.isFinite(asOfMs) &&
        closesAtExclusive != null &&
        asOfMs >= Date.parse(closesAtExclusive)
      );
    if (row.terminal !== expectedTerminal) {
      problems.push(`${label} terminal flag is inconsistent`);
    }
    const { stateContentHash: _stateContentHash, ...rowWithoutHash } = row;
    const expectedStateHash = hashValue(
      'release-validation-opportunity-state-v3',
      { asOf: ledger.asOf, ...rowWithoutHash },
    );
    if (row.stateContentHash !== expectedStateHash) {
      problems.push(`${label} state content hash mismatch`);
    }
  }
  return problems;
}

function denominatorCounts(
  rows: Array<{ disposition: ReleaseValidationOpportunityDisposition }>,
): Record<ReleaseValidationOpportunityDisposition, number> {
  return Object.fromEntries(
    (['upcoming', 'eligible', 'captured', 'missed', 'failed'] as const)
      .map((disposition) => [
        disposition,
        rows.filter((row) => row.disposition === disposition).length,
      ]),
  ) as Record<ReleaseValidationOpportunityDisposition, number>;
}

function emptyCoverage(
  currentStratumKey: string,
  errors: string[],
): ReleaseValidationOpportunityDenominatorCoverage {
  return {
    present: false,
    valid: false,
    ready: false,
    currentStratumKey,
    sourcePolicy: null,
    contentHash: null,
    rowCount: 0,
    capturedCount: 0,
    upcomingCount: 0,
    eligibleCount: 0,
    missedCount: 0,
    failedCount: 0,
    terminalCount: 0,
    unmatchedForecastCount: 0,
    integrityErrorCount: errors.length,
    errors,
    rows: [],
  };
}

function catalogMemberSourceOrder(
  member: ReleaseValidationCatalogMember,
  catalogIndex: number,
): number {
  return Number.isInteger(member.sourceOrder) && member.sourceOrder >= 0
    ? member.sourceOrder
    : catalogIndex;
}

function catalogMemberReleaseIdentity(
  member: ReleaseValidationCatalogMember,
): string | null {
  const nodeId = stringValue(member.nodeId);
  const tag = stringValue(member.tag);
  const tagCommitOid = stringValue(member.tagCommitOid)?.toLowerCase() ?? null;
  const publishedAt = normalizedTimestamp(member.publishedAt);
  return nodeId && tag && tagCommitOid && isCommitOid(tagCommitOid) && publishedAt
    ? releaseValidationReleaseIdentity({
      nodeId,
      tagCommitOid,
      publishedAt,
    })
    : null;
}

function catalogContentReferenceKey(
  attestationContentHash: string,
  memberContentHash: string,
): string {
  return canonicalJson([attestationContentHash, memberContentHash]);
}

function orderedHash(domain: string, values: unknown[]): string {
  return hashValue(`${domain}:ordered`, values);
}

function exactSetHash(domain: string, values: unknown[]): string {
  return hashValue(
    `${domain}:set`,
    values
      .map((value) => canonicalJson(value))
      .sort(),
  );
}

function hashValue(domain: string, value: unknown): string {
  return createHash('sha256')
    .update(`${domain}\0${canonicalJson(value)}`)
    .digest('hex');
}

function parseRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value === 'string') {
    try {
      return parseRecord(JSON.parse(value));
    } catch {
      return null;
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function timestampValue(value: unknown): string | null {
  const text = stringValue(value);
  return text && Number.isFinite(Date.parse(text)) ? text : null;
}

function integerValue(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) ? value : null;
}

function pointInTimeEvidenceRows<T>(
  rows: T[],
  asOfMs: number,
  label: string,
  timestampFor: (row: T) => unknown,
): T[] {
  if (!Array.isArray(rows)) {
    throw new Error(`${label} evidence must be an array`);
  }
  return rows.filter((row, index) =>
    requiredTimestamp(
      timestampFor(row),
      `${label} ${index + 1} authoritative timestamp`,
    ) <= asOfMs);
}

function requiredTimestamp(value: unknown, label: string): number {
  const timestamp = typeof value === 'string'
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${label} must be a valid timestamp`);
  }
  return timestamp;
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

function isCommitOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40,64}$/i.test(value);
}
