import { createHash } from 'node:crypto';
import { isRangeParseable, matchesRange } from './versionMatch';
import {
  COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
  DEFAULT_EXPECTED_ADVISORY_PACKAGE,
  advisorySnapshotContentHash,
  advisorySnapshotRowProblems,
  type AdvisorySnapshotRowProblem,
  type CompoundAdvisorySnapshotMetadata,
  type CompoundAdvisorySnapshotPublicationAuthorization,
  type ExpectedAdvisoryPackage,
} from './advisorySnapshot';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from './scoreHistoryLedger';
import {
  releaseScoreAuditHistoryV2SealProblems,
  scoreAuthorityResolutionRunProblems,
  type ReleaseScoreAuditHistoryV2Seal,
  type ScoreAuthorityResolutionRun,
} from './scoreAuthorityResolution';
import {
  commentEvidenceDigestFromJson,
  type CommentEvidenceRow,
} from './commentEvidence';
import { normalizeCodeRevision } from './codeRevision';
import {
  RELEASE_VALIDATION_OPPORTUNITIES,
  releaseValidationOpportunityDenominatorCoverage,
  type ReleaseValidationOpportunityCode,
  type ReleaseValidationOpportunityDenominatorLedger,
} from './releaseValidationOpportunityDenominator';
import {
  releaseValidationCohortCellKey,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationCohort,
  type ReleaseValidationPolicy,
  type ReleaseValidationProofBundle,
  type ReleaseValidationProofJsonValue,
} from './releaseValidationProof';
import {
  scoreLedgerV2Problems,
  type InstallInput,
} from './score';

export { advisorySnapshotContentHash } from './advisorySnapshot';
export {
  RELEASE_VALIDATION_OPPORTUNITIES,
  type ReleaseValidationOpportunityCode,
  type ReleaseValidationOpportunityDenominatorLedger,
} from './releaseValidationOpportunityDenominator';

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const WILSON_Z_95 = 1.959963984540054;

export const RELEASE_VALIDATION_HORIZONS = {
  field_regression_72h: {
    durationMs: 72 * HOUR_MS,
    observationGraceMs: 24 * HOUR_MS,
    label: '72h field regression',
  },
  security_30d: {
    durationMs: 30 * DAY_MS,
    observationGraceMs: 7 * DAY_MS,
    label: '30d security advisory',
  },
} as const;

export type ReleaseValidationHorizonCode = keyof typeof RELEASE_VALIDATION_HORIZONS;

export interface ReleaseCatalogSweepAttestation {
  digest: string;
  totalCount: number;
  nodeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  exhausted: true;
  stabilized: true;
  sourceOrder: 'CREATED_AT_DESC';
}

export interface ReleaseCatalogAttestation {
  schemaVersion: 4;
  initialRemoteCatalog: ReleaseCatalogSweepAttestation;
  finalRemoteCatalog: ReleaseCatalogSweepAttestation;
  finalObservedAt: string;
  projectedActiveCatalog: {
    digest: string;
    releaseCount: number;
  };
  localActiveCatalog: {
    digest: string;
    releaseCount: number;
  };
  latestStable: {
    nodeId: string;
    tag: string;
    tagCommitOid: string;
    publishedAt: string;
  };
  scoreBuiltAt: string;
}

export interface ReleaseValidationScoreCommitTiming {
  schemaVersion: 4;
  historyRunId: string;
  historyRunContentHash: string;
  authorityRunId: string;
  authorityRunContentHash: string;
  historyV2SealContentHash: string;
  historyRecordedAt: string;
  commitNotBefore: string;
  commitNotAfter: string;
  commitNotBeforeMs: number;
  commitNotAfterMs: number;
}

export interface ReleaseValidationForecastLedgerRow {
  id?: number;
  decision_id: string;
  opportunity_code: string;
  recorded_at: string;
  latest_release_tag: string;
  latest_release_published_at: string;
  selected_tag: string | null;
  audit_history_run_id: string;
  score_model_version: string;
  prompt_version: number;
  policy_code: string;
  candidate_scores_json: string;
  decision_json: string;
  source_identity_json: string;
  code_revision?: string | null;
  previous_content_hash?: string | null;
  content_hash?: string;
}

export interface ReleaseValidationOutcomeLedgerRow {
  id?: number;
  observation_id: string;
  decision_id: string;
  horizon_code: string;
  observed_at: string;
  status: string;
  outcome_json: string;
  source_identity_json: string;
  previous_content_hash?: string | null;
  content_hash?: string;
}

export interface ReleaseScoreAuditHistoryEvidenceRow {
  id?: number;
  run_id: string;
  recorded_at: string;
  release_tag: string;
  scored_at: string;
  score_model_version: string;
  prompt_version: number;
  final_score: number | null;
  status: string;
  band: string;
  recommended: number;
  input_json: string;
  components_json: string | null;
  issue_evidence_json: string;
  gate_evidence_json: string;
  source_identity_json: string;
  authority_run_id?: string | null;
}

export interface ReleaseScoreAuditHistoryRunSealEvidenceRow {
  id?: number;
  run_id: string;
  recorded_at: string;
  row_count: number;
  rows_content_hash: string;
  previous_content_hash: string | null;
  content_hash: string;
}

export type ReleaseScoreAuthorityRunEvidence = ScoreAuthorityResolutionRun;

export type ReleaseScoreAuditHistoryV2SealEvidence =
  ReleaseScoreAuditHistoryV2Seal & {
    readonly id?: number;
  };

export interface AdvisorySnapshotValidationRow {
  advisory_key: string;
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: string;
  html_url: string;
  published_at: string | null;
  package_ecosystem: string | null;
  package_name: string | null;
  vulnerable_version_range: string | null;
  patched_versions: string | null;
}

export interface AdvisorySnapshotValidationEvidence {
  schemaVersion?: 1 | 2;
  snapshotId: number;
  capturedAt: string;
  rowCount: number;
  contentHash: string;
  rows: AdvisorySnapshotValidationRow[];
  headerPresent?: boolean;
  provenance?: {
    schemaVersion: 2;
    metadata: CompoundAdvisorySnapshotMetadata;
    ledgerContentHash: string;
    previousLedgerContentHash: string | null;
    sourceHash: string;
    catalogHash: string;
    scoreHash: string;
    scoreContentDigest: string;
    metadataDigest: string;
    publication: {
      receiptId: string;
      runId: string;
      receiptSemanticIdentity: string;
      operationStartedAt: string;
      finishedAt: string;
    };
  };
}

export interface ReleaseValidationLedgerIntegrityReport {
  ok: boolean;
  failedCount: number;
  errors: string[];
  scoreAuthority: {
    authorityRunCount: number;
    historyV2SealCount: number;
    duplicateAuthorityRunIdCount: number;
    duplicateHistoryRunIdCount: number;
    authorityRunIntegrityFailureCount: number;
    authorityChainFailureCount: number;
    historyV2SealIntegrityFailureCount: number;
    historyV2ChainFailureCount: number;
    missingAuthorityRunReferenceCount: number;
    missingHistoryRunReferenceCount: number;
    bindingMismatchCount: number;
    failedCount: number;
  };
  forecasts: {
    rowCount: number;
    invalidRowIdCount: number;
    duplicateDecisionIdCount: number;
    duplicateSeriesIdentityCount: number;
    chainFailureCount: number;
    contentHashFailureCount: number;
    decisionIdFailureCount: number;
    missingRunSealCount: number;
    invalidRunSealCount: number;
    provenanceFailureCount: number;
    failedCount: number;
  };
  outcomes: {
    rowCount: number;
    invalidRowIdCount: number;
    duplicateObservationIdCount: number;
    chainFailureCount: number;
    contentHashFailureCount: number;
    observationIdFailureCount: number;
    missingDecisionCount: number;
    failedCount: number;
  };
  scoreHistory: {
    rowCount: number;
    runCount: number;
    duplicateRowIdentityCount: number;
    duplicateRunIdCount: number;
    missingSealCount: number;
    orphanSealCount: number;
    chainFailureCount: number;
    rowCountMismatchCount: number;
    recordedAtMismatchCount: number;
    scoreReplayFailureCount: number;
    rowsContentHashMismatchCount: number;
    contentHashMismatchCount: number;
    latestRunId: string | null;
    latestContentHash: string | null;
    failedCount: number;
  };
  advisorySnapshots: {
    snapshotCount: number;
    rowCount: number;
    duplicateSnapshotIdCount: number;
    invalidHeaderCount: number;
    orphanRowCount: number;
    rowCountMismatchCount: number;
    contentHashMismatchCount: number;
    provenanceFailureCount: number;
    malformedRowCount: number;
    packageMismatchCount: number;
    advisoryKeyMismatchCount: number;
    duplicateCanonicalIdentityCount: number;
    latestSnapshotId: number | null;
    latestSnapshotSchemaVersion: 1 | 2 | null;
    outcomeReferencedSnapshotIds: number[];
    outcomeReferencedSnapshotKeys: string[];
    semanticProblemCount: number;
    semanticSnapshotCount: number;
    legacySemanticProblemCount: number;
    legacySemanticSnapshotCount: number;
    legacySemanticSnapshotIds: number[];
    failedCount: number;
  };
}

interface AdvisorySnapshotSemanticScopeReport {
  latestSnapshotId: number | null;
  latestSnapshotSchemaVersion: 1 | 2 | null;
  outcomeReferencedSnapshotIds: number[];
  outcomeReferencedSnapshotKeys: string[];
  requiredSnapshotKeys: Set<string>;
  semanticProblemCount: number;
  semanticSnapshotCount: number;
  legacySemanticProblemCount: number;
  legacySemanticSnapshotCount: number;
  legacySemanticSnapshotIds: number[];
}

export interface ObservationAssessmentInput {
  forecast: ReleaseValidationForecastLedgerRow;
  horizonCode: ReleaseValidationHorizonCode;
  now: string;
  auditHistory: ReleaseScoreAuditHistoryEvidenceRow[];
  currentSourceIdentity: unknown;
  issueCrawl: unknown;
  scorePersistence: unknown;
  advisorySnapshots: AdvisorySnapshotValidationEvidence[];
  independentFieldEvidence?:
    | IndependentFieldEvidenceSnapshot
    | IndependentFieldEvidenceSnapshot[]
    | null;
  expectedAdvisoryPackage?: ExpectedAdvisoryPackage;
}

export type ObservationAssessment =
  | {
      status: 'pending';
      fatal: false;
      horizonCode: ReleaseValidationHorizonCode;
      targetReleaseTag: string;
      windowStartAt: string;
      windowEndAt: string;
      reason: string;
    }
  | {
      status: 'indeterminate';
      fatal: boolean;
      horizonCode: ReleaseValidationHorizonCode;
      targetReleaseTag: string;
      windowStartAt: string;
      windowEndAt: string;
      reason: string;
      details?: unknown;
    }
  | {
      status: 'matured';
      fatal: false;
      horizonCode: ReleaseValidationHorizonCode;
      targetReleaseTag: string;
      windowStartAt: string;
      windowEndAt: string;
      observedAt: string;
      outcome: ReleaseValidationOutcomePayload;
      sourceIdentity: JsonRecord;
    };

export interface ReleaseValidationOutcomePayload {
  schemaVersion: 2 | 3;
  decisionId: string;
  opportunityCode: string;
  horizonCode: ReleaseValidationHorizonCode;
  targetReleaseTag: string;
  windowStartAt: string;
  windowEndAt: string;
  observedAt: string;
  adverse: boolean;
  prediction: {
    recommended: boolean;
    recommendedLatest: boolean;
    selectedTag: string | null;
    targetReleaseScore: number | null;
  };
  auditEvidence: {
    runId: string;
    recordedAt: string;
    scoredAt: string;
    sourceIdentityDigest: string;
    scoreModelVersion: string;
    promptVersion: number;
  };
  policyAction?: {
    action: 'install_selected' | 'withhold_latest';
    targetReleaseTag: string;
    adverse: boolean;
  };
  candidateOutcomes?: ReleaseValidationCandidateOutcome[];
  fieldRegression?: {
    outcomeSourceClass: 'independent_raw_evidence';
    observedClass: 'observed-adverse' | 'observed-safe';
    evidenceScope: 'complete_exact_version_post_forecast_crawl';
    evidenceCompleteness: {
      capturedAt: string;
      issueUniverseCount: number;
      completeCommentSnapshotCount: number;
      incompleteIssueNumbers: number[];
    };
    issueCount: number;
    clusterCount: number;
    evidenceRefs: IndependentFieldAdverseEvidence[];
    evidenceSnapshot?: IndependentFieldEvidenceSnapshot;
    classifierProxy: ClassifierFieldOutcomeProxy;
  };
  security?: {
    snapshotSchemaVersion?: 1 | 2;
    snapshotId: number;
    snapshotCapturedAt: string;
    snapshotContentHash: string;
    snapshotProvenance?: NonNullable<
      AdvisorySnapshotValidationEvidence['provenance']
    >;
    advisoryCount: number;
    advisories: SecurityAdvisoryEvidence[];
  };
}

export interface ReleaseValidationCandidateOutcome {
  targetReleaseTag: string;
  roles: ReleaseValidationTargetRole[];
  candidateScore: number | null;
  adverse: boolean;
  auditEvidence: ReleaseValidationOutcomePayload['auditEvidence'];
  fieldRegression?: ReleaseValidationOutcomePayload['fieldRegression'];
  security?: ReleaseValidationOutcomePayload['security'];
}

export type ReleaseValidationTargetRole = 'candidate' | 'latest' | 'selected';

export interface ReleaseValidationObservationTarget {
  targetReleaseTag: string;
  roles: ReleaseValidationTargetRole[];
}

export interface ReleaseValidationIndeterminatePayload {
  schemaVersion: 1;
  kind: 'indeterminate';
  decisionId: string;
  opportunityCode: string;
  horizonCode: ReleaseValidationHorizonCode;
  targetReleaseTag: string;
  windowStartAt: string;
  windowEndAt: string;
  observedAt: string;
  reason: string;
  fatal: boolean;
  terminal: boolean;
  sourceIdentityFallback: boolean;
  prediction: ReleaseValidationOutcomePayload['prediction'];
  details?: unknown;
}

export interface FieldRegressionEvidence {
  evidenceIdentity: string;
  sourceClass:
    | 'exact_version_human_confirmation'
    | 'exact_version_trusted_later_fix'
    | 'exact_version_human_confirmation_and_trusted_later_fix';
  issueNumber: number;
  issueUrl: string;
  createdAt: string;
  state: string;
  versionLink: IndependentVersionLinkEvidence;
  confirmations: IndependentHumanConfirmationEvidence[];
  laterFixes: IndependentLaterFixEvidence[];
}

export type IndependentFieldAdverseEvidence = FieldRegressionEvidence;

export interface IndependentVersionLinkEvidence {
  source: 'title' | 'body' | 'comment';
  version: string;
  referenceUrl: string;
  commentId: number | null;
  author: string | null;
  snippet: string;
}

export interface IndependentHumanConfirmationEvidence {
  source: 'comment' | 'label_event';
  sourceClass: 'independent_human_reproduction' | 'human_applied_adverse_label';
  actor: string;
  occurredAt: string;
  referenceUrl: string;
  commentId: number | null;
  eventId: string | null;
  label: string | null;
  snippet: string | null;
}

export interface IndependentLaterFixEvidence {
  source: 'trusted_pull_request' | 'reachable_fix_commit';
  releaseTag: string;
  releasePublishedAt: string;
  proofStatus: string;
  referenceUrl: string;
  prNumber: number | null;
  commitOid: string | null;
}

export interface ClassifierFieldOutcomeProxy {
  sourceClass: 'classifier_score_bucket_proxy';
  validationEligible: false;
  adverse: boolean | null;
  issueCount: number | null;
  reason: string | null;
}

export interface IndependentFieldEvidenceSnapshot {
  schemaVersion: 1 | 2 | 3;
  contentHash?: string;
  capturedAt: string;
  targetReleaseTag: string;
  windowStartAt: string;
  windowEndAt: string;
  complete: boolean;
  issueUniverseCount: number;
  completeCommentSnapshotCount: number;
  incompleteIssueNumbers: number[];
  mutableIssueContentNumbers?: number[];
  issueUniverse?: IndependentFieldIssueUniverseEntry[];
  evidenceRefs: IndependentFieldAdverseEvidence[];
}

export interface IndependentFieldIssueUniverseEntry {
  issueNumber: number;
  issueUrl: string;
  createdAt: string;
  state: string;
  issueUpdatedAt?: string;
  issueContentFrozenAtHorizon?: boolean;
  issueEvidenceIdentity: string;
  commentSnapshotEvidenceIdentity: string | null;
  commentEvidenceIdentities: Array<{
    commentId: number;
    evidenceIdentity: string;
  }>;
  labelEventEvidenceIdentities: Array<{
    eventId: string;
    evidenceIdentity: string;
  }>;
  closureProofEvidenceIdentities: Array<{
    releaseTag: string;
    proofStatus: string;
    evidenceIdentity: string;
  }>;
  adverseEvidenceIdentity: string | null;
  evidenceIdentity: string;
}

export interface IndependentFieldEvidenceBuildInput {
  forecast: ReleaseValidationForecastLedgerRow;
  targetReleaseTag?: string;
  horizonEndAt: string;
  capturedAt: string;
  issues: Array<Record<string, unknown>>;
  commentSnapshots: Array<Record<string, unknown>>;
  labelEvents: Array<Record<string, unknown>>;
  closureProofs: Array<Record<string, unknown>>;
}

export interface SecurityAdvisoryEvidence {
  advisoryKey: string;
  ghsaId: string;
  cveId: string | null;
  severity: string;
  publishedAt: string;
  vulnerableVersionRange: string;
}

export interface ValidationSampleThresholds {
  independent: number;
  uniqueReleases: number;
  recommended: number;
  adverse: number;
  withheld: number;
  safe: number;
}

export const DEFAULT_VALIDATION_SAMPLE_THRESHOLDS: ValidationSampleThresholds = {
  independent: 20,
  uniqueReleases: 20,
  recommended: 20,
  adverse: 20,
  withheld: 20,
  safe: 20,
};

export interface ValidationQualityCriteria {
  recommendationPrecisionLowerBound: number;
  falseSafeUpperBound: number;
  accuracyLowerBound: number;
  safeVsAdverseAucMinimum: number;
}

export const DEFAULT_VALIDATION_QUALITY_CRITERIA: ValidationQualityCriteria = {
  recommendationPrecisionLowerBound: 0.7,
  falseSafeUpperBound: 0.3,
  accuracyLowerBound: 0.6,
  safeVsAdverseAucMinimum: 0.65,
};

export const RELEASE_VALIDATION_COHORT_LEDGER_SCHEMA_VERSION = 1;
export const RELEASE_VALIDATION_SPLIT_LEDGER_SCHEMA_VERSION = 1;
export const RELEASE_VALIDATION_LEDGER_MANIFEST_SCHEMA_VERSION = 1;

export interface ReleaseValidationReleaseIdentity {
  nodeId: string;
  tag: string;
  tagCommitOid: string;
  publishedAt: string;
  key: string;
}

export type ReleaseValidationCohortPurpose = 'production' | 'calibration';
export type ReleaseValidationCohortLifecycle = 'active' | 'retired';

export interface ReleaseValidationCohortLedgerRow {
  schemaVersion: typeof RELEASE_VALIDATION_COHORT_LEDGER_SCHEMA_VERSION;
  cohortKey: string;
  modelVersion: string;
  promptVersion: number;
  codeRevision: string;
  purpose: ReleaseValidationCohortPurpose;
  lifecycle: ReleaseValidationCohortLifecycle;
  activatedAt: string;
  retiredAt: string | null;
  previousContentHash: string | null;
  contentHash: string;
}

export type ReleaseValidationSplitRole = 'development' | 'holdout';

export interface ReleaseValidationSplitAssignmentRow {
  schemaVersion: typeof RELEASE_VALIDATION_SPLIT_LEDGER_SCHEMA_VERSION;
  assignmentId: string;
  cohortKey: string;
  releaseIdentity: ReleaseValidationReleaseIdentity;
  role: ReleaseValidationSplitRole;
  assignedAt: string;
  previousContentHash: string | null;
  contentHash: string;
}

export interface ReleaseValidationReconciliationRow {
  reconciliationId: string;
  cohortKey: string;
  releaseIdentityKey?: string | null;
  opportunityCode?: string | null;
  horizonCode?: string | null;
  recordedAt: string;
  status: 'resolved' | 'blocking';
  reason: string;
}

export interface ReleaseValidationObservationBatchEvidenceRow {
  id?: number;
  batch_id: string;
  observed_at: string;
  code_revision: string;
  source_identity_digest: string;
  forecast_count: number;
  intended_count: number;
  inserted_count: number;
  already_existing_count: number;
  pending_count: number;
  excluded_count: number;
  indeterminate_count: number;
  results_json: string;
  outcome_chain_previous_hash: string | null;
  outcome_chain_content_hash: string | null;
  previous_content_hash: string | null;
  content_hash: string;
}

export interface ReleaseValidationObservationBatchVerificationEvidence {
  failedCount: number;
  problems: string[];
}

export interface ReleaseValidationLedgerManifest {
  schemaVersion: typeof RELEASE_VALIDATION_LEDGER_MANIFEST_SCHEMA_VERSION;
  forecasts: ReleaseValidationLedgerManifestSection;
  outcomes: ReleaseValidationLedgerManifestSection;
  observationBatches: ReleaseValidationLedgerManifestSection & {
    outcomeTip: string | null;
    latestObservedAt: string | null;
  };
  opportunityDenominator: {
    rowCount: number;
    contentHash: string | null;
  };
  cohorts: ReleaseValidationLedgerManifestSection;
  splitAssignments: ReleaseValidationLedgerManifestSection;
  contentHash: string;
}

export interface ReleaseValidationLedgerManifestSection {
  rowCount: number;
  tipContentHash: string | null;
  identityDigest: string;
}

export interface ReleaseValidationProspectiveProofInput {
  canonicalProof?: ReleaseValidationProofBundle;
  cohorts?: ReleaseValidationCohortLedgerRow[];
  splitAssignments?: ReleaseValidationSplitAssignmentRow[];
  reconciliationRows?: ReleaseValidationReconciliationRow[];
  observationBatches?: ReleaseValidationObservationBatchEvidenceRow[];
  observationBatchVerification?: ReleaseValidationObservationBatchVerificationEvidence;
  expectedLedgerManifest?: ReleaseValidationLedgerManifest;
  evaluationPurpose?: 'production' | 'calibration';
}

export function releaseValidationReleaseIdentityKey(input: {
  nodeId: string;
  tag: string;
  tagCommitOid: string;
  publishedAt: string;
}): string {
  return proofHash('release-validation-release-identity-v1', {
    nodeId: input.nodeId,
    tag: input.tag,
    tagCommitOid: input.tagCommitOid.toLowerCase(),
    publishedAt: input.publishedAt,
  });
}

export function releaseValidationCohortContentHash(
  row: Omit<ReleaseValidationCohortLedgerRow, 'contentHash'>,
): string {
  return proofHash('release-validation-cohort-ledger-v1', row);
}

export function releaseValidationSplitAssignmentId(
  row: Pick<ReleaseValidationSplitAssignmentRow, 'cohortKey' | 'releaseIdentity'>,
): string {
  return proofHash('release-validation-split-assignment-identity-v1', {
    cohortKey: row.cohortKey,
    releaseIdentityKey: row.releaseIdentity.key,
  });
}

export function releaseValidationSplitAssignmentContentHash(
  row: Omit<ReleaseValidationSplitAssignmentRow, 'contentHash'>,
): string {
  return proofHash('release-validation-split-assignment-ledger-v1', row);
}

export function releaseValidationLedgerManifestContentHash(
  manifest: Omit<ReleaseValidationLedgerManifest, 'contentHash'>,
): string {
  return proofHash('release-validation-ledger-manifest-v1', manifest);
}

export function releaseValidationEvaluationExitCode(status: string): 0 | 1 | 2 {
  if (status === 'validated') return 0;
  if (status === 'insufficient') return 2;
  return 1;
}

type JsonRecord = Record<string, unknown>;

interface CommonObservationEvidence {
  audit: ReleaseScoreAuditHistoryEvidenceRow;
  auditInput: JsonRecord;
  auditComponents: JsonRecord;
  auditIssueEvidence: JsonRecord;
  auditGateEvidence: JsonRecord;
  sourceIdentity: JsonRecord;
  sourceIdentityDigest: string;
}

interface EvaluationCase {
  latestReleaseTag: string;
  latestReleaseIdentity: ReleaseValidationReleaseIdentity;
  releaseTag: string;
  opportunityCode: string;
  modelVersion: string;
  promptVersion: number;
  codeRevision: string | null;
  decisionId: string;
  recommended: boolean;
  adverse: boolean;
  score: number | null;
  observedAt: string;
  windowStartAt: string;
  windowEndAt: string;
  horizonCode: ReleaseValidationHorizonCode | 'combined';
  adverseHorizons?: ReleaseValidationHorizonCode[];
  targetRoles?: ReleaseValidationTargetRole[];
}

interface MaturedObservationResolution {
  schemaVersion: number;
  adverse: boolean;
  observedAt: string;
  windowStartAt: string;
  windowEndAt: string;
  targetOutcomes: Array<{
    targetReleaseTag: string;
    roles: ReleaseValidationTargetRole[];
    adverse: boolean;
  }>;
  completeCandidateCoverage: boolean;
}

interface IndeterminateObservationResolution {
  reason: string;
  fatal: boolean;
  terminal: boolean;
  observedAt: string;
}

interface ObservationResolution {
  matured: MaturedObservationResolution | null;
  indeterminate: IndeterminateObservationResolution[];
  nonValidatingProxyCount: number;
}

export interface ReleaseValidationForecastTiming {
  opportunityCode: string;
  ageHours: number | null;
  recordedAtMs: number | null;
  windowStartAt: string | null;
  windowEndAt: string | null;
  windowStartMs: number | null;
  windowEndMs: number | null;
  valid: boolean;
  reason:
    | 'within_window'
    | 'unknown_opportunity'
    | 'invalid_timestamp'
    | 'before_window'
    | 'after_window';
}

export function releaseValidationForecastTiming(
  forecast: Pick<
    ReleaseValidationForecastLedgerRow,
    'opportunity_code' | 'recorded_at' | 'latest_release_published_at'
  >,
): ReleaseValidationForecastTiming {
  const opportunity = RELEASE_VALIDATION_OPPORTUNITIES[
    forecast.opportunity_code as ReleaseValidationOpportunityCode
  ];
  if (!opportunity) {
    return {
      opportunityCode: forecast.opportunity_code,
      ageHours: null,
      recordedAtMs: null,
      windowStartAt: null,
      windowEndAt: null,
      windowStartMs: null,
      windowEndMs: null,
      valid: false,
      reason: 'unknown_opportunity',
    };
  }
  const recordedAtMs = Date.parse(forecast.recorded_at);
  const publishedAtMs = Date.parse(forecast.latest_release_published_at);
  if (!Number.isFinite(recordedAtMs) || !Number.isFinite(publishedAtMs)) {
    return {
      opportunityCode: forecast.opportunity_code,
      ageHours: null,
      recordedAtMs: null,
      windowStartAt: null,
      windowEndAt: null,
      windowStartMs: null,
      windowEndMs: null,
      valid: false,
      reason: 'invalid_timestamp',
    };
  }
  const windowStartMs = publishedAtMs + opportunity.minAgeHours * HOUR_MS;
  const windowEndMs = publishedAtMs + opportunity.maxAgeHours * HOUR_MS;
  const ageHours = (recordedAtMs - publishedAtMs) / HOUR_MS;
  const windowStartAt = new Date(windowStartMs).toISOString();
  const windowEndAt = new Date(windowEndMs).toISOString();
  return {
    opportunityCode: forecast.opportunity_code,
    ageHours: round(ageHours),
    recordedAtMs,
    windowStartAt,
    windowEndAt,
    windowStartMs,
    windowEndMs,
    valid: recordedAtMs >= windowStartMs && recordedAtMs < windowEndMs,
    reason: recordedAtMs < windowStartMs
      ? 'before_window'
      : recordedAtMs >= windowEndMs
        ? 'after_window'
        : 'within_window',
  };
}

export function releaseCatalogAttestationProblems(value: unknown): string[] {
  const problems: string[] = [];
  const attestation = asRecord(value);
  if (!attestation || attestation.schemaVersion !== 4) {
    return ['catalogAttestation must use schemaVersion 4'];
  }
  const initial = catalogSweepAttestationProblems(
    attestation.initialRemoteCatalog,
    'initialRemoteCatalog',
  );
  const final = catalogSweepAttestationProblems(
    attestation.finalRemoteCatalog,
    'finalRemoteCatalog',
  );
  problems.push(...initial.problems, ...final.problems);
  const finalObservedAt = timestampField(attestation, 'finalObservedAt');
  const scoreBuiltAt = timestampField(attestation, 'scoreBuiltAt');
  if (!finalObservedAt) problems.push('catalogAttestation finalObservedAt is invalid');
  if (!scoreBuiltAt) problems.push('catalogAttestation scoreBuiltAt is invalid');
  if (
    finalObservedAt &&
    scoreBuiltAt &&
    Date.parse(scoreBuiltAt) > Date.parse(finalObservedAt)
  ) {
    problems.push('catalogAttestation finalObservedAt predates scoreBuiltAt');
  }
  const projected = catalogIdentityAttestationProblems(
    attestation.projectedActiveCatalog,
    'projectedActiveCatalog',
  );
  const local = catalogIdentityAttestationProblems(
    attestation.localActiveCatalog,
    'localActiveCatalog',
  );
  problems.push(...projected.problems, ...local.problems);
  const latestStable = asRecord(attestation.latestStable);
  if (
    !latestStable ||
    !stringField(latestStable, 'nodeId') ||
    !stringField(latestStable, 'tag') ||
    !commitOidField(latestStable, 'tagCommitOid') ||
    !timestampField(latestStable, 'publishedAt')
  ) {
    problems.push('catalogAttestation latestStable identity is invalid');
  }
  if (
    initial.value &&
    final.value &&
    (
      initial.value.digest !== final.value.digest ||
      initial.value.totalCount !== final.value.totalCount ||
      initial.value.nodeCount !== final.value.nodeCount
    )
  ) {
    problems.push('catalogAttestation initial and final remote catalogs do not agree');
  }
  if (
    projected.value &&
    local.value &&
    (
      projected.value.digest !== local.value.digest ||
      projected.value.releaseCount !== local.value.releaseCount
    )
  ) {
    problems.push('catalogAttestation projected and local active catalogs do not agree');
  }
  return problems;
}

export function releaseValidationScoreCommitTimingProblems(
  value: unknown,
  expected: {
    recordedAt: string;
    historyRunId: string;
    historyRunContentHash?: string | null;
    historyRecordedAt?: string | null;
    authorityRunId?: string | null;
    authorityRunContentHash?: string | null;
    historyV2SealContentHash?: string | null;
  },
): string[] {
  const problems: string[] = [];
  const timing = asRecord(value);
  if (!timing || timing.schemaVersion !== 4) {
    return ['scoreCommit must use schemaVersion 4'];
  }
  const commitNotBefore = timestampField(timing, 'commitNotBefore');
  const commitNotAfter = timestampField(timing, 'commitNotAfter');
  const historyRecordedAt = timestampField(timing, 'historyRecordedAt');
  const commitNotBeforeMs = integerField(timing, 'commitNotBeforeMs');
  const commitNotAfterMs = integerField(timing, 'commitNotAfterMs');
  const historyRunId = stringField(timing, 'historyRunId');
  const historyRunContentHash = stringField(timing, 'historyRunContentHash');
  const authorityRunId = stringField(timing, 'authorityRunId');
  const authorityRunContentHash = stringField(
    timing,
    'authorityRunContentHash',
  );
  const historyV2SealContentHash = stringField(
    timing,
    'historyV2SealContentHash',
  );
  if (!commitNotBefore || commitNotBeforeMs == null ||
    Date.parse(commitNotBefore) !== commitNotBeforeMs) {
    problems.push('scoreCommit commitNotBefore is not exact integer-millisecond time');
  }
  if (!commitNotAfter || commitNotAfterMs == null ||
    Date.parse(commitNotAfter) !== commitNotAfterMs) {
    problems.push('scoreCommit commitNotAfter is not exact integer-millisecond time');
  }
  if (
    commitNotBeforeMs != null &&
    commitNotAfterMs != null &&
    commitNotAfterMs < commitNotBeforeMs
  ) {
    problems.push('scoreCommit commitNotAfter predates commitNotBefore');
  }
  if (commitNotAfter !== expected.recordedAt) {
    problems.push('scoreCommit commitNotAfter does not equal forecast recorded_at');
  }
  if (historyRunId !== expected.historyRunId) {
    problems.push('scoreCommit historyRunId does not match the forecast history run');
  }
  if (!isSha256Hex(historyRunContentHash)) {
    problems.push('scoreCommit historyRunContentHash is invalid');
  } else if (
    expected.historyRunContentHash &&
    historyRunContentHash !== expected.historyRunContentHash
  ) {
    problems.push('scoreCommit historyRunContentHash does not match the sealed history run');
  }
  if (!authorityRunId) {
    problems.push('scoreCommit authorityRunId is invalid');
  } else if (
    expected.authorityRunId &&
    authorityRunId !== expected.authorityRunId
  ) {
    problems.push('scoreCommit authorityRunId does not match the authority run');
  }
  if (!isSha256Hex(authorityRunContentHash)) {
    problems.push('scoreCommit authorityRunContentHash is invalid');
  } else if (
    expected.authorityRunContentHash &&
    authorityRunContentHash !== expected.authorityRunContentHash
  ) {
    problems.push(
      'scoreCommit authorityRunContentHash does not match the authority run',
    );
  }
  if (!isSha256Hex(historyV2SealContentHash)) {
    problems.push('scoreCommit historyV2SealContentHash is invalid');
  } else if (
    expected.historyV2SealContentHash &&
    historyV2SealContentHash !== expected.historyV2SealContentHash
  ) {
    problems.push(
      'scoreCommit historyV2SealContentHash does not match the history v2 seal',
    );
  }
  if (!historyRecordedAt) {
    problems.push('scoreCommit historyRecordedAt is invalid');
  } else {
    if (
      expected.historyRecordedAt &&
      historyRecordedAt !== expected.historyRecordedAt
    ) {
      problems.push('scoreCommit historyRecordedAt does not match the sealed history run');
    }
    if (
      commitNotAfterMs != null &&
      Date.parse(historyRecordedAt) > commitNotAfterMs
    ) {
      problems.push('scoreCommit historyRecordedAt is after forecast recorded_at');
    }
  }
  return problems;
}

export function releaseValidationObservationTargets(
  forecast: Pick<
    ReleaseValidationForecastLedgerRow,
    'latest_release_tag' | 'selected_tag' | 'candidate_scores_json'
  >,
): ReleaseValidationObservationTarget[] {
  const orderedTags: string[] = [];
  const parsed = parseJson(forecast.candidate_scores_json);
  const candidates = Array.isArray(parsed)
    ? parsed
    : recordArray(asRecord(parsed)?.candidates ?? asRecord(parsed)?.scores);
  for (const candidate of candidates) {
    const row = asRecord(candidate);
    if (!row) continue;
    const aliases = presentAliasValues(row, ['releaseTag', 'release_tag', 'tag']);
    if (aliasValuesConflict(aliases)) continue;
    const tag = nullableString(aliases[0]);
    if (tag && !orderedTags.includes(tag)) orderedTags.push(tag);
  }
  for (const requiredTag of [
    forecast.latest_release_tag,
    forecast.selected_tag,
  ]) {
    if (requiredTag && !orderedTags.includes(requiredTag)) {
      orderedTags.push(requiredTag);
    }
  }
  return orderedTags.map((targetReleaseTag) => ({
    targetReleaseTag,
    roles: [
      'candidate' as const,
      ...(targetReleaseTag === forecast.latest_release_tag
        ? ['latest' as const]
        : []),
      ...(targetReleaseTag === forecast.selected_tag
        ? ['selected' as const]
        : []),
    ],
  }));
}

export function assessReleaseValidationObservation(
  input: ObservationAssessmentInput,
): ObservationAssessment {
  const targetReleaseTag = validationTargetReleaseTag(input.forecast);
  const observationTargets = releaseValidationObservationTargets(input.forecast);
  if (releaseValidationDecisionSchemaVersion(input.forecast) !== 4) {
    return indeterminate(
      input,
      targetReleaseTag,
      input.forecast.recorded_at,
      input.forecast.recorded_at,
      'forecast_decision_schema_not_evaluable',
      true,
    );
  }
  const startMs = Date.parse(input.forecast.recorded_at);
  if (!Number.isFinite(startMs)) {
    return indeterminate(input, targetReleaseTag, input.forecast.recorded_at, input.forecast.recorded_at,
      'forecast_recorded_at_invalid', true);
  }
  const endMs = startMs + RELEASE_VALIDATION_HORIZONS[input.horizonCode].durationMs;
  const windowEndAt = new Date(endMs).toISOString();
  const nowMs = Date.parse(input.now);
  if (!Number.isFinite(nowMs)) {
    return indeterminate(input, targetReleaseTag, input.forecast.recorded_at, windowEndAt,
      'observation_time_invalid', true);
  }
  if (nowMs < endMs) {
    return {
      status: 'pending',
      fatal: false,
      horizonCode: input.horizonCode,
      targetReleaseTag,
      windowStartAt: input.forecast.recorded_at,
      windowEndAt,
      reason: 'horizon_not_reached',
    };
  }
  const latestObservationMs = endMs + RELEASE_VALIDATION_HORIZONS[input.horizonCode].observationGraceMs;
  if (nowMs > latestObservationMs) {
    return indeterminate(
      input,
      targetReleaseTag,
      input.forecast.recorded_at,
      windowEndAt,
      'observation_grace_window_missed',
      false,
      {
        latestObservationAt: new Date(latestObservationMs).toISOString(),
        observedAt: input.now,
      },
    );
  }

  const observedAt = input.now;
  const fieldEvidence = input.independentFieldEvidence == null
    ? []
    : Array.isArray(input.independentFieldEvidence)
      ? input.independentFieldEvidence
      : [input.independentFieldEvidence];
  const candidateOutcomes: ReleaseValidationCandidateOutcome[] = [];
  let sourceIdentity: JsonRecord | null = null;
  for (const target of observationTargets) {
    const common = qualifyPostHorizonEvidence(
      input,
      target.targetReleaseTag,
      endMs,
      nowMs,
    );
    if ('reason' in common) {
      return indeterminate(
        input,
        targetReleaseTag,
        input.forecast.recorded_at,
        windowEndAt,
        common.reason,
        common.fatal,
        observationTargetFailureDetails(target, common.details),
      );
    }
    const derived = input.horizonCode === 'field_regression_72h'
      ? deriveFieldRegressionOutcome(
          input.forecast,
          target.targetReleaseTag,
          common,
          endMs,
          fieldEvidence.find((item) =>
            item.targetReleaseTag === target.targetReleaseTag) ?? null,
        )
      : deriveSecurityOutcome(
          input.forecast,
          target.targetReleaseTag,
          common,
          input.advisorySnapshots,
          endMs,
          input.expectedAdvisoryPackage,
        );
    if ('reason' in derived) {
      return indeterminate(
        input,
        targetReleaseTag,
        input.forecast.recorded_at,
        windowEndAt,
        derived.reason,
        derived.fatal,
        observationTargetFailureDetails(target, derived.details),
      );
    }
    const auditEvidence = {
      runId: common.audit.run_id,
      recordedAt: common.audit.recorded_at,
      scoredAt: common.audit.scored_at,
      sourceIdentityDigest: common.sourceIdentityDigest,
      scoreModelVersion: common.audit.score_model_version,
      promptVersion: common.audit.prompt_version,
    };
    candidateOutcomes.push({
      targetReleaseTag: target.targetReleaseTag,
      roles: target.roles,
      candidateScore: candidateScoreForRelease(
        input.forecast.candidate_scores_json,
        target.targetReleaseTag,
      ),
      adverse: derived.adverse,
      auditEvidence,
      ...derived.payload,
    });
    sourceIdentity = common.sourceIdentity;
  }
  const policyOutcome = candidateOutcomes.find((item) =>
    item.targetReleaseTag === targetReleaseTag);
  if (!policyOutcome || !sourceIdentity) {
    return indeterminate(
      input,
      targetReleaseTag,
      input.forecast.recorded_at,
      windowEndAt,
      'observation_target_resolution_failed',
      true,
    );
  }
  const outcome: ReleaseValidationOutcomePayload = {
    schemaVersion: 3,
    decisionId: input.forecast.decision_id,
    opportunityCode: input.forecast.opportunity_code,
    horizonCode: input.horizonCode,
    targetReleaseTag,
    windowStartAt: input.forecast.recorded_at,
    windowEndAt,
    observedAt,
    adverse: policyOutcome.adverse,
    prediction: forecastPrediction(input.forecast),
    auditEvidence: policyOutcome.auditEvidence,
    policyAction: {
      action: input.forecast.selected_tag == null
        ? 'withhold_latest'
        : 'install_selected',
      targetReleaseTag,
      adverse: policyOutcome.adverse,
    },
    candidateOutcomes,
    ...(policyOutcome.fieldRegression
      ? { fieldRegression: policyOutcome.fieldRegression }
      : {}),
    ...(policyOutcome.security ? { security: policyOutcome.security } : {}),
  };
  return {
    status: 'matured',
    fatal: false,
    horizonCode: input.horizonCode,
    targetReleaseTag,
    windowStartAt: input.forecast.recorded_at,
    windowEndAt,
    observedAt,
    outcome,
    sourceIdentity,
  };
}

function observationTargetFailureDetails(
  target: ReleaseValidationObservationTarget,
  details?: unknown,
): JsonRecord {
  return {
    targetReleaseTag: target.targetReleaseTag,
    targetRoles: target.roles,
    ...(details === undefined ? {} : { cause: details }),
  };
}

export function buildReleaseValidationIndeterminatePayload(input: {
  forecast: ReleaseValidationForecastLedgerRow;
  assessment: Extract<ObservationAssessment, { status: 'indeterminate' }>;
  observedAt: string;
  sourceIdentityFallback?: boolean;
}): ReleaseValidationIndeterminatePayload {
  return {
    schemaVersion: 1,
    kind: 'indeterminate',
    decisionId: input.forecast.decision_id,
    opportunityCode: input.forecast.opportunity_code,
    horizonCode: input.assessment.horizonCode,
    targetReleaseTag: input.assessment.targetReleaseTag,
    windowStartAt: input.assessment.windowStartAt,
    windowEndAt: input.assessment.windowEndAt,
    observedAt: input.observedAt,
    reason: input.assessment.reason,
    fatal: input.assessment.fatal,
    terminal: input.assessment.reason === 'observation_grace_window_missed',
    sourceIdentityFallback: input.sourceIdentityFallback === true,
    prediction: forecastPrediction(input.forecast),
    ...(input.assessment.details === undefined ? {} : { details: input.assessment.details }),
  };
}

export function buildAdvisorySnapshotValidationEvidence(
  headers: Array<{
    id: unknown;
    captured_at: unknown;
    row_count: unknown;
    content_hash: unknown;
  }>,
  rows: Array<Record<string, unknown>>,
): AdvisorySnapshotValidationEvidence[] {
  const rowsBySnapshot = new Map<number, AdvisorySnapshotValidationRow[]>();
  for (const row of rows) {
    const snapshotId = Number(row.snapshot_id);
    const snapshotRows = rowsBySnapshot.get(snapshotId) ?? [];
    snapshotRows.push({
      advisory_key: String(row.advisory_key ?? ''),
      ghsa_id: String(row.ghsa_id ?? ''),
      cve_id: stringOrNull(row.cve_id),
      summary: String(row.summary ?? ''),
      severity: String(row.severity ?? ''),
      html_url: String(row.html_url ?? ''),
      published_at: stringOrNull(row.published_at),
      package_ecosystem: stringOrNull(row.package_ecosystem),
      package_name: stringOrNull(row.package_name),
      vulnerable_version_range: stringOrNull(row.vulnerable_version_range),
      patched_versions: stringOrNull(row.patched_versions),
    });
    rowsBySnapshot.set(snapshotId, snapshotRows);
  }
  const snapshots = headers.map((header) => {
    const snapshotId = Number(header.id);
    return {
      schemaVersion: 1 as const,
      snapshotId,
      capturedAt: String(header.captured_at ?? ''),
      rowCount: Number(header.row_count),
      contentHash: String(header.content_hash ?? ''),
      rows: rowsBySnapshot.get(snapshotId) ?? [],
      headerPresent: true,
    };
  });
  const headerIds = new Set(snapshots.map((snapshot) => snapshot.snapshotId));
  for (const [snapshotId, snapshotRows] of rowsBySnapshot) {
    if (headerIds.has(snapshotId)) continue;
    snapshots.push({
      schemaVersion: 1,
      snapshotId,
      capturedAt: '',
      rowCount: snapshotRows.length,
      contentHash: '',
      rows: snapshotRows,
      headerPresent: false,
    });
  }
  return snapshots;
}

export function buildCompoundAdvisorySnapshotValidationEvidence(
  snapshots: Array<{
    metadata: CompoundAdvisorySnapshotMetadata;
    scoreRows: AdvisorySnapshotValidationRow[];
  }>,
  authorizations: CompoundAdvisorySnapshotPublicationAuthorization[],
): AdvisorySnapshotValidationEvidence[] {
  const authorizationBySnapshot = new Map(
    authorizations.map((authorization) => [
      authorization.snapshotId,
      authorization,
    ]),
  );
  return snapshots.flatMap(({ metadata, scoreRows }) => {
    const authorization = authorizationBySnapshot.get(metadata.snapshotId);
    if (!authorization) return [];
    return [{
      schemaVersion: 2,
      snapshotId: metadata.snapshotId,
      capturedAt: metadata.capturedAt,
      rowCount: metadata.scoreRowCount,
      contentHash: metadata.scoreContentDigest,
      rows: scoreRows,
      headerPresent: true,
      provenance: {
        schemaVersion: 2,
        metadata,
        ledgerContentHash: metadata.contentHash,
        previousLedgerContentHash: metadata.previousContentHash,
        sourceHash: metadata.sourceHash,
        catalogHash: metadata.catalogHash,
        scoreHash: metadata.scoreHash,
        scoreContentDigest: metadata.scoreContentDigest,
        metadataDigest: authorization.metadataDigest,
        publication: {
          receiptId: authorization.receiptId,
          runId: authorization.runId,
          receiptSemanticIdentity: authorization.receiptSemanticIdentity,
          operationStartedAt: authorization.operationStartedAt,
          finishedAt: authorization.finishedAt,
        },
      },
    }];
  });
}

export function releaseValidationForecastContentHash(
  row: ReleaseValidationForecastLedgerRow,
  previousContentHash = row.previous_content_hash ?? null,
): string {
  return createHash('sha256')
    .update(
      `release-validation-forecast-v1\0${previousContentHash ?? ''}\0` +
      JSON.stringify([
        row.opportunity_code,
        row.recorded_at,
        row.latest_release_tag,
        row.latest_release_published_at,
        row.selected_tag,
        row.audit_history_run_id,
        row.score_model_version,
        row.prompt_version,
        row.policy_code,
        row.candidate_scores_json,
        row.decision_json,
        row.source_identity_json,
        row.code_revision ?? null,
      ]),
    )
    .digest('hex');
}

export function releaseValidationDecisionSchemaVersion(
  forecast: Pick<ReleaseValidationForecastLedgerRow, 'decision_json'>,
): number | null {
  const version = Number(parseRecord(forecast.decision_json)?.schemaVersion);
  return Number.isInteger(version) ? version : null;
}

export function releaseValidationForecastIsEvaluable(
  forecast: ReleaseValidationForecastLedgerRow,
): boolean {
  return releaseValidationDecisionSchemaVersion(forecast) === 4 &&
    releaseValidationForecastTiming(forecast).valid;
}

export function releaseValidationDecisionId(
  row: Pick<
    ReleaseValidationForecastLedgerRow,
    'opportunity_code' | 'latest_release_tag' | 'recorded_at'
  >,
  contentHash: string,
): string {
  return createHash('sha256')
    .update(
      `release-validation-decision-v1\0${row.opportunity_code}\0` +
      `${row.latest_release_tag}\0${row.recorded_at}\0${contentHash}`,
    )
    .digest('hex');
}

export function releaseValidationObservationId(
  row: ReleaseValidationOutcomeLedgerRow,
): string {
  return createHash('sha256')
    .update(`release-validation-observation-v1\0${releaseValidationOutcomeRecordContent(row)}`)
    .digest('hex');
}

export function releaseValidationOutcomeContentHash(
  row: ReleaseValidationOutcomeLedgerRow,
  previousContentHash = row.previous_content_hash ?? null,
): string {
  return createHash('sha256')
    .update(
      `release-validation-outcome-v1\0${previousContentHash ?? ''}\0` +
      releaseValidationOutcomeRecordContent(row),
    )
    .digest('hex');
}

export function validateReleaseValidationLedgerIntegrity(input: {
  forecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
  auditHistory: ReleaseScoreAuditHistoryEvidenceRow[];
  auditHistoryRuns: ReleaseScoreAuditHistoryRunSealEvidenceRow[];
  authorityRuns?: ReleaseScoreAuthorityRunEvidence[];
  historyV2Seals?: ReleaseScoreAuditHistoryV2SealEvidence[];
  advisorySnapshots: AdvisorySnapshotValidationEvidence[];
  expectedAdvisoryPackage?: ExpectedAdvisoryPackage;
}): ReleaseValidationLedgerIntegrityReport {
  const errors: string[] = [];
  const expectedAdvisoryPackage =
    input.expectedAdvisoryPackage ?? DEFAULT_EXPECTED_ADVISORY_PACKAGE;
  const scoreHistory = validateScoreHistoryIntegrity(
    input.auditHistory,
    input.auditHistoryRuns,
    errors,
  );
  const scoreAuthority = validateReleaseScoreAuthorityChains(
    input.authorityRuns ?? [],
    input.historyV2Seals ?? [],
    input.auditHistoryRuns,
    errors,
  );
  const forecasts = validateForecastLedgerIntegrity(
    input.forecasts,
    input.auditHistory,
    input.auditHistoryRuns,
    input.authorityRuns ?? [],
    input.historyV2Seals ?? [],
    scoreHistory.validRunIds,
    new Set(input.auditHistoryRuns.map((row) => row.run_id)),
    errors,
  );
  const outcomes = validateOutcomeLedgerIntegrity(
    input.observations,
    new Set(input.forecasts.map((row) => row.decision_id)),
    errors,
  );
  const advisorySnapshots = validateAdvisorySnapshotIntegrity(
    input.advisorySnapshots,
    expectedAdvisoryPackage,
    advisorySnapshotKeysReferencedByOutcomes(input.observations),
    errors,
  );
  const failedCount = forecasts.failedCount +
    outcomes.failedCount +
    scoreAuthority.failedCount +
    scoreHistory.report.failedCount +
    advisorySnapshots.failedCount;
  return {
    ok: failedCount === 0,
    failedCount,
    errors,
    scoreAuthority,
    forecasts,
    outcomes,
    scoreHistory: scoreHistory.report,
    advisorySnapshots,
  };
}

function validateReleaseScoreAuthorityChains(
  authorityRuns: readonly ReleaseScoreAuthorityRunEvidence[],
  historyV2Seals: readonly ReleaseScoreAuditHistoryV2SealEvidence[],
  historyRuns: readonly ReleaseScoreAuditHistoryRunSealEvidenceRow[],
  errors: string[],
): ReleaseValidationLedgerIntegrityReport['scoreAuthority'] {
  const authorityRunById = new Map<string, ReleaseScoreAuthorityRunEvidence>();
  const historyRunById = new Map<
    string,
    ReleaseScoreAuditHistoryRunSealEvidenceRow
  >();
  let duplicateAuthorityRunIdCount = 0;
  let duplicateHistoryRunIdCount = 0;
  let authorityRunIntegrityFailureCount = 0;
  let authorityChainFailureCount = 0;
  let historyV2SealIntegrityFailureCount = 0;
  let historyV2ChainFailureCount = 0;
  let missingAuthorityRunReferenceCount = 0;
  let missingHistoryRunReferenceCount = 0;
  let bindingMismatchCount = 0;

  for (const historyRun of historyRuns) {
    if (!historyRunById.has(historyRun.run_id)) {
      historyRunById.set(historyRun.run_id, historyRun);
    }
  }
  for (const run of authorityRuns) {
    if (authorityRunById.has(run.authorityRunId)) {
      duplicateAuthorityRunIdCount++;
      errors.push(`Duplicate score authority run ${run.authorityRunId}`);
    } else {
      authorityRunById.set(run.authorityRunId, run);
    }
    const runProblems = scoreAuthorityResolutionRunProblems(run);
    authorityRunIntegrityFailureCount += runProblems.length;
    for (const problem of runProblems) {
      errors.push(`${run.authorityRunId}: ${problem}`);
    }
  }
  authorityChainFailureCount = contentHashChainFailureCount(
    authorityRuns,
    (run) => run.authorityRunId,
    (run) => run.previousContentHash,
    (run) => run.contentHash,
    'authority chain',
    errors,
  );
  const seenHistoryV2RunIds = new Set<string>();
  for (const seal of historyV2Seals) {
    if (seenHistoryV2RunIds.has(seal.historyRunId)) {
      duplicateHistoryRunIdCount++;
      errors.push(`Duplicate score audit history v2 seal ${seal.historyRunId}`);
    } else {
      seenHistoryV2RunIds.add(seal.historyRunId);
    }
    const { id: _id, ...canonicalSeal } = seal;
    const sealProblems = releaseScoreAuditHistoryV2SealProblems(
      canonicalSeal,
    );
    historyV2SealIntegrityFailureCount += sealProblems.length;
    for (const problem of sealProblems) {
      errors.push(`${seal.historyRunId}: ${problem}`);
    }
    const authorityRun = authorityRunById.get(seal.authorityRunId);
    const historyRun = historyRunById.get(seal.historyRunId);
    if (!authorityRun) {
      missingAuthorityRunReferenceCount++;
      errors.push(
        `${seal.historyRunId}: history v2 seal references missing authority run ` +
        seal.authorityRunId,
      );
    }
    if (!historyRun) {
      missingHistoryRunReferenceCount++;
      errors.push(
        `${seal.historyRunId}: history v2 seal references missing history run`,
      );
    }
    if (
      authorityRun &&
      historyRun &&
      (
        seal.sealedAt !== historyRun.recorded_at ||
        seal.sealedAt !== authorityRun.recordedAt ||
        seal.historyRowCount !== historyRun.row_count ||
        seal.historyRowsContentHash !== historyRun.rows_content_hash ||
        seal.authorityRowCount !== authorityRun.rowCount ||
        seal.authorityRowsContentHash !== authorityRun.rowsContentHash
      )
    ) {
      bindingMismatchCount++;
      errors.push(
        `${seal.historyRunId}: history v2 seal does not exactly bind its ` +
        'history and authority runs',
      );
    }
  }
  historyV2ChainFailureCount = contentHashChainFailureCount(
    historyV2Seals,
    (seal) => seal.historyRunId,
    (seal) => seal.previousContentHash,
    (seal) => seal.contentHash,
    'history v2 chain',
    errors,
  );
  const failedCount = duplicateAuthorityRunIdCount +
    duplicateHistoryRunIdCount +
    authorityRunIntegrityFailureCount +
    authorityChainFailureCount +
    historyV2SealIntegrityFailureCount +
    historyV2ChainFailureCount +
    missingAuthorityRunReferenceCount +
    missingHistoryRunReferenceCount +
    bindingMismatchCount;
  return {
    authorityRunCount: authorityRuns.length,
    historyV2SealCount: historyV2Seals.length,
    duplicateAuthorityRunIdCount,
    duplicateHistoryRunIdCount,
    authorityRunIntegrityFailureCount,
    authorityChainFailureCount,
    historyV2SealIntegrityFailureCount,
    historyV2ChainFailureCount,
    missingAuthorityRunReferenceCount,
    missingHistoryRunReferenceCount,
    bindingMismatchCount,
    failedCount,
  };
}

function contentHashChainFailureCount<T>(
  rows: readonly T[],
  identity: (row: T) => string,
  previousContentHash: (row: T) => string | null,
  contentHash: (row: T) => string,
  chainName: string,
  errors: string[],
): number {
  if (rows.length === 0) return 0;
  let failedCount = 0;
  const rowsByContentHash = new Map<string, T[]>();
  const successorsByContentHash = new Map<string, T[]>();
  for (const row of rows) {
    const hash = contentHash(row);
    const matchingRows = rowsByContentHash.get(hash) ?? [];
    matchingRows.push(row);
    rowsByContentHash.set(hash, matchingRows);
  }
  for (const [hash, matchingRows] of rowsByContentHash) {
    if (matchingRows.length <= 1) continue;
    failedCount++;
    errors.push(
      `${chainName} has duplicate content hash ${hash} for ` +
      matchingRows.map(identity).join(', '),
    );
  }
  const genesisRows = rows.filter((row) => previousContentHash(row) == null);
  if (genesisRows.length !== 1) {
    failedCount++;
    errors.push(
      `${chainName} must have exactly one genesis row; found ${genesisRows.length}`,
    );
  }
  for (const row of rows) {
    const previous = previousContentHash(row);
    if (previous == null) continue;
    const predecessors = rowsByContentHash.get(previous) ?? [];
    if (predecessors.length !== 1) {
      failedCount++;
      errors.push(
        `${identity(row)}: previous content hash does not match ${chainName}`,
      );
      continue;
    }
    const successors = successorsByContentHash.get(previous) ?? [];
    successors.push(row);
    successorsByContentHash.set(previous, successors);
  }
  for (const [predecessorHash, successors] of successorsByContentHash) {
    if (successors.length <= 1) continue;
    failedCount++;
    errors.push(
      `${chainName} forks after ${predecessorHash}: ` +
      successors.map(identity).join(', '),
    );
  }
  if (failedCount > 0 || genesisRows.length !== 1) return failedCount;

  const visited = new Set<string>();
  let current: T | undefined = genesisRows[0];
  while (current) {
    const hash = contentHash(current);
    if (visited.has(hash)) {
      failedCount++;
      errors.push(`${chainName} contains a cycle at ${identity(current)}`);
      break;
    }
    visited.add(hash);
    current = successorsByContentHash.get(hash)?.[0];
  }
  if (failedCount === 0 && visited.size !== rows.length) {
    failedCount++;
    errors.push(
      `${chainName} is disconnected: reached ${visited.size} of ${rows.length} rows`,
    );
  }
  return failedCount;
}

function validateScoreHistoryIntegrity(
  rows: ReleaseScoreAuditHistoryEvidenceRow[],
  runs: ReleaseScoreAuditHistoryRunSealEvidenceRow[],
  errors: string[],
): {
  report: ReleaseValidationLedgerIntegrityReport['scoreHistory'];
  validRunIds: Set<string>;
} {
  const rowsByRun = new Map<string, ReleaseScoreAuditHistoryEvidenceRow[]>();
  const rowIdentities = new Set<string>();
  let duplicateRowIdentityCount = 0;
  for (const row of rows) {
    const identity = `${row.run_id}\0${row.release_tag}`;
    if (rowIdentities.has(identity)) {
      duplicateRowIdentityCount++;
      errors.push(`Duplicate score history row ${row.run_id}/${row.release_tag}`);
    }
    rowIdentities.add(identity);
    const runRows = rowsByRun.get(row.run_id) ?? [];
    runRows.push(row);
    rowsByRun.set(row.run_id, runRows);
  }

  const orderedRuns = runs
    .map((row, index) => ({ row, index }))
    .sort((left, right) => ledgerRowSort(left, right))
    .map((item) => item.row);
  const runsById = new Map<string, ReleaseScoreAuditHistoryRunSealEvidenceRow>();
  const invalidRunIds = new Set<string>();
  let duplicateRunIdCount = 0;
  let chainFailureCount = 0;
  let scoreReplayFailureCount = 0;
  for (const run of orderedRuns) {
    if (!Number.isInteger(run.id) || Number(run.id) <= 0) {
      chainFailureCount++;
      invalidRunIds.add(run.run_id);
      errors.push(`Score history run ${run.run_id || 'unknown'} has an invalid row ID`);
    }
    if (runsById.has(run.run_id)) {
      duplicateRunIdCount++;
      invalidRunIds.add(run.run_id);
      errors.push(`Duplicate score history run seal ${run.run_id}`);
      continue;
    }
    runsById.set(run.run_id, run);
  }
  for (const row of rows) {
    const replayProblems = scoreAuditHistoryReplayProblems(row);
    if (replayProblems.length === 0) continue;
    scoreReplayFailureCount++;
    invalidRunIds.add(row.run_id);
    for (const problem of replayProblems) {
      errors.push(
        `Score history row ${row.run_id}/${row.release_tag} ${problem}`,
      );
    }
  }

  let missingSealCount = 0;
  for (const runId of rowsByRun.keys()) {
    if (runsById.has(runId)) continue;
    missingSealCount++;
    errors.push(`Score history run ${runId} is missing its seal`);
  }

  let orphanSealCount = 0;
  let rowCountMismatchCount = 0;
  let recordedAtMismatchCount = 0;
  let rowsContentHashMismatchCount = 0;
  let contentHashMismatchCount = 0;
  let previousContentHash: string | null = null;
  for (const run of orderedRuns) {
    if (runsById.get(run.run_id) !== run) continue;
    if ((run.previous_content_hash ?? null) !== previousContentHash) {
      chainFailureCount++;
      invalidRunIds.add(run.run_id);
      errors.push(
        `Score history run ${run.run_id} previous hash does not match the prior run seal`,
      );
    }
    const runRows = (rowsByRun.get(run.run_id) ?? [])
      .slice()
      .sort((left, right) => left.release_tag.localeCompare(right.release_tag));
    if (runRows.length === 0) {
      orphanSealCount++;
      invalidRunIds.add(run.run_id);
      errors.push(`Score history run seal ${run.run_id} has no history rows`);
    }
    const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(
      runRows as unknown as Array<Record<string, unknown>>,
    );
    if (!Number.isInteger(run.row_count) || run.row_count !== runRows.length) {
      rowCountMismatchCount++;
      invalidRunIds.add(run.run_id);
      errors.push(
        `Score history run ${run.run_id} row count ${run.row_count} does not match ${runRows.length}`,
      );
    }
    const recordedAts = new Set(runRows.map((row) => row.recorded_at));
    if (recordedAts.size !== 1 || !recordedAts.has(run.recorded_at)) {
      recordedAtMismatchCount++;
      invalidRunIds.add(run.run_id);
      errors.push(`Score history run ${run.run_id} has inconsistent recorded_at values`);
    }
    if (run.rows_content_hash !== rowsContentHash) {
      rowsContentHashMismatchCount++;
      invalidRunIds.add(run.run_id);
      errors.push(`Score history run ${run.run_id} row-set hash does not match its rows`);
    }
    const contentHash = releaseScoreAuditHistoryRunContentHash({
      runId: run.run_id,
      recordedAt: run.recorded_at,
      rowCount: run.row_count,
      rowsContentHash: run.rows_content_hash,
      previousContentHash: run.previous_content_hash ?? null,
    });
    if (run.content_hash !== contentHash) {
      contentHashMismatchCount++;
      invalidRunIds.add(run.run_id);
      errors.push(`Score history run ${run.run_id} seal hash is invalid`);
    }
    previousContentHash = run.content_hash;
  }

  const failedCount = duplicateRowIdentityCount +
    duplicateRunIdCount +
    missingSealCount +
    orphanSealCount +
    chainFailureCount +
    rowCountMismatchCount +
    recordedAtMismatchCount +
    scoreReplayFailureCount +
    rowsContentHashMismatchCount +
    contentHashMismatchCount;
  const report = {
    rowCount: rows.length,
    runCount: runs.length,
    duplicateRowIdentityCount,
    duplicateRunIdCount,
    missingSealCount,
    orphanSealCount,
    chainFailureCount,
    rowCountMismatchCount,
    recordedAtMismatchCount,
    scoreReplayFailureCount,
    rowsContentHashMismatchCount,
    contentHashMismatchCount,
    latestRunId: orderedRuns.at(-1)?.run_id ?? null,
    latestContentHash: orderedRuns.at(-1)?.content_hash ?? null,
    failedCount,
  };
  return {
    report,
    validRunIds: new Set(
      [...runsById.keys()].filter((runId) =>
        rowsByRun.has(runId) && !invalidRunIds.has(runId)),
    ),
  };
}

function validateForecastLedgerIntegrity(
  rows: ReleaseValidationForecastLedgerRow[],
  auditHistory: ReleaseScoreAuditHistoryEvidenceRow[],
  auditHistoryRuns: ReleaseScoreAuditHistoryRunSealEvidenceRow[],
  authorityRuns: ReleaseScoreAuthorityRunEvidence[],
  historyV2Seals: ReleaseScoreAuditHistoryV2SealEvidence[],
  validRunIds: Set<string>,
  sealedRunIds: Set<string>,
  errors: string[],
): ReleaseValidationLedgerIntegrityReport['forecasts'] {
  const ordered = orderLedgerRows(rows);
  const seenRowIds = new Set<number>();
  const seenDecisionIds = new Set<string>();
  const seenSeriesIdentities = new Set<string>();
  let invalidRowIdCount = 0;
  let duplicateDecisionIdCount = 0;
  let duplicateSeriesIdentityCount = 0;
  let chainFailureCount = 0;
  let contentHashFailureCount = 0;
  let decisionIdFailureCount = 0;
  let missingRunSealCount = 0;
  let invalidRunSealCount = 0;
  let previousContentHash: string | null = null;
  for (const row of ordered) {
    const rowId = Number(row.id);
    if (!Number.isInteger(rowId) || rowId <= 0 || seenRowIds.has(rowId)) {
      invalidRowIdCount++;
      errors.push(`Forecast ${row.decision_id || 'unknown'} has an invalid or duplicate row ID`);
    } else {
      seenRowIds.add(rowId);
    }
    if (seenDecisionIds.has(row.decision_id)) {
      duplicateDecisionIdCount++;
      errors.push(`Duplicate validation forecast decision ID ${row.decision_id}`);
    }
    seenDecisionIds.add(row.decision_id);
    const seriesIdentity = forecastSeriesIdentity(row);
    if (seenSeriesIdentities.has(seriesIdentity)) {
      duplicateSeriesIdentityCount++;
      errors.push(
        `Duplicate validation forecast series identity ` +
        `${row.latest_release_tag}/${row.opportunity_code}/` +
        `${row.score_model_version}/prompt-${row.prompt_version}`,
      );
    }
    seenSeriesIdentities.add(seriesIdentity);
    if ((row.previous_content_hash ?? null) !== previousContentHash) {
      chainFailureCount++;
      errors.push(`Forecast ${row.decision_id} previous hash does not match the prior forecast`);
    }
    const contentHash = releaseValidationForecastContentHash(
      row,
      row.previous_content_hash ?? null,
    );
    if (row.content_hash !== contentHash) {
      contentHashFailureCount++;
      errors.push(`Forecast ${row.decision_id} content hash is invalid`);
    }
    const decisionId = releaseValidationDecisionId(row, row.content_hash ?? '');
    if (row.decision_id !== decisionId) {
      decisionIdFailureCount++;
      errors.push(`Forecast ${row.decision_id || 'unknown'} decision ID is invalid`);
    }
    if (!sealedRunIds.has(row.audit_history_run_id)) {
      missingRunSealCount++;
      errors.push(
        `Forecast ${row.decision_id} references missing score history seal ${row.audit_history_run_id}`,
      );
    } else if (!validRunIds.has(row.audit_history_run_id)) {
      invalidRunSealCount++;
      errors.push(
        `Forecast ${row.decision_id} references corrupt score history run ${row.audit_history_run_id}`,
      );
    }
    previousContentHash = row.content_hash ?? null;
  }
  const provenanceErrors = validateReleaseValidationForecastProvenance(
    rows,
    auditHistory,
    auditHistoryRuns,
    authorityRuns,
    historyV2Seals,
  );
  for (const error of provenanceErrors) errors.push(`Forecast provenance: ${error}`);
  const provenanceFailureCount = provenanceErrors.length;
  const failedCount = invalidRowIdCount +
    duplicateDecisionIdCount +
    duplicateSeriesIdentityCount +
    chainFailureCount +
    contentHashFailureCount +
    decisionIdFailureCount +
    missingRunSealCount +
    invalidRunSealCount +
    provenanceFailureCount;
  return {
    rowCount: rows.length,
    invalidRowIdCount,
    duplicateDecisionIdCount,
    duplicateSeriesIdentityCount,
    chainFailureCount,
    contentHashFailureCount,
    decisionIdFailureCount,
    missingRunSealCount,
    invalidRunSealCount,
    provenanceFailureCount,
    failedCount,
  };
}

function validateOutcomeLedgerIntegrity(
  rows: ReleaseValidationOutcomeLedgerRow[],
  decisionIds: Set<string>,
  errors: string[],
): ReleaseValidationLedgerIntegrityReport['outcomes'] {
  const ordered = orderLedgerRows(rows);
  const seenRowIds = new Set<number>();
  const seenObservationIds = new Set<string>();
  let invalidRowIdCount = 0;
  let duplicateObservationIdCount = 0;
  let chainFailureCount = 0;
  let contentHashFailureCount = 0;
  let observationIdFailureCount = 0;
  let missingDecisionCount = 0;
  let previousContentHash: string | null = null;
  for (const row of ordered) {
    const rowId = Number(row.id);
    if (!Number.isInteger(rowId) || rowId <= 0 || seenRowIds.has(rowId)) {
      invalidRowIdCount++;
      errors.push(`Outcome ${row.observation_id || 'unknown'} has an invalid or duplicate row ID`);
    } else {
      seenRowIds.add(rowId);
    }
    if (seenObservationIds.has(row.observation_id)) {
      duplicateObservationIdCount++;
      errors.push(`Duplicate validation outcome observation ID ${row.observation_id}`);
    }
    seenObservationIds.add(row.observation_id);
    if ((row.previous_content_hash ?? null) !== previousContentHash) {
      chainFailureCount++;
      errors.push(`Outcome ${row.observation_id} previous hash does not match the prior outcome`);
    }
    const contentHash = releaseValidationOutcomeContentHash(
      row,
      row.previous_content_hash ?? null,
    );
    if (row.content_hash !== contentHash) {
      contentHashFailureCount++;
      errors.push(`Outcome ${row.observation_id} content hash is invalid`);
    }
    const observationId = releaseValidationObservationId(row);
    if (row.observation_id !== observationId) {
      observationIdFailureCount++;
      errors.push(`Outcome ${row.observation_id || 'unknown'} observation ID is invalid`);
    }
    if (!decisionIds.has(row.decision_id)) {
      missingDecisionCount++;
      errors.push(
        `Outcome ${row.observation_id} references unknown decision ${row.decision_id}`,
      );
    }
    previousContentHash = row.content_hash ?? null;
  }
  const failedCount = invalidRowIdCount +
    duplicateObservationIdCount +
    chainFailureCount +
    contentHashFailureCount +
    observationIdFailureCount +
    missingDecisionCount;
  return {
    rowCount: rows.length,
    invalidRowIdCount,
    duplicateObservationIdCount,
    chainFailureCount,
    contentHashFailureCount,
    observationIdFailureCount,
    missingDecisionCount,
    failedCount,
  };
}

function validateAdvisorySnapshotIntegrity(
  snapshots: AdvisorySnapshotValidationEvidence[],
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
  outcomeReferencedSnapshotKeys: Set<string>,
  errors: string[],
): ReleaseValidationLedgerIntegrityReport['advisorySnapshots'] {
  const semanticScope = advisorySnapshotSemanticScope(
    snapshots,
    outcomeReferencedSnapshotKeys,
    expectedAdvisoryPackage,
  );
  const seenSnapshotKeys = new Set<string>();
  let rowCount = 0;
  let duplicateSnapshotIdCount = 0;
  let invalidHeaderCount = 0;
  let orphanRowCount = 0;
  let rowCountMismatchCount = 0;
  let contentHashMismatchCount = 0;
  let provenanceFailureCount = 0;
  let malformedRowCount = 0;
  let packageMismatchCount = 0;
  let advisoryKeyMismatchCount = 0;
  let duplicateCanonicalIdentityCount = 0;
  for (const snapshot of snapshots) {
    rowCount += snapshot.rows.length;
    const snapshotKey = advisorySnapshotKey(snapshot);
    if (seenSnapshotKeys.has(snapshotKey)) {
      duplicateSnapshotIdCount++;
      errors.push(`Duplicate advisory snapshot ${snapshotKey}`);
    }
    seenSnapshotKeys.add(snapshotKey);
    if (snapshot.headerPresent === false) {
      orphanRowCount += snapshot.rows.length;
      errors.push(
        `Advisory snapshot rows reference missing snapshot ${String(snapshot.snapshotId)}`,
      );
    } else {
      if (!Number.isInteger(snapshot.snapshotId) || snapshot.snapshotId <= 0 ||
        ![1, 2].includes(advisorySnapshotSchemaVersion(snapshot)) ||
        !Number.isFinite(Date.parse(snapshot.capturedAt)) ||
        !Number.isInteger(snapshot.rowCount) || snapshot.rowCount < 0 ||
        !snapshot.contentHash.trim()) {
        invalidHeaderCount++;
        errors.push(`Advisory snapshot ${String(snapshot.snapshotId)} header is malformed`);
      }
      if (snapshot.rows.length !== snapshot.rowCount) {
        rowCountMismatchCount++;
        errors.push(
          `Advisory snapshot ${String(snapshot.snapshotId)} row count ` +
          `${snapshot.rowCount} does not match ${snapshot.rows.length}`,
        );
      }
      if (snapshot.contentHash.trim()) {
        const computedHash = advisorySnapshotContentHash(snapshot.rows);
        if (computedHash !== snapshot.contentHash) {
          contentHashMismatchCount++;
          errors.push(`Advisory snapshot ${String(snapshot.snapshotId)} content hash is invalid`);
        }
      }
      const provenanceProblem = advisorySnapshotSchemaVersion(snapshot) === 2
        ? compoundAdvisoryValidationProvenanceProblem(
            snapshot,
            expectedAdvisoryPackage,
          )
        : snapshot.provenance !== undefined
          ? 'legacy advisory snapshot cannot carry v2 provenance'
          : null;
      if (provenanceProblem) {
        provenanceFailureCount++;
        errors.push(
          `Advisory snapshot ${snapshotKey} provenance is invalid: ` +
          provenanceProblem,
        );
      }
    }
    const rowProblems = advisorySnapshotRowProblems(snapshot.rows, expectedAdvisoryPackage);
    for (const problem of rowProblems) {
      if (isAdvisorySnapshotSemanticProblem(problem)) {
        if (semanticScope.requiredSnapshotKeys.has(snapshotKey)) {
          errors.push(
            `Advisory snapshot ${String(snapshot.snapshotId)} semantic incompatibility: ` +
            `${problem.detail}`,
          );
        }
        continue;
      }
      if (problem.code === 'malformed_row') malformedRowCount++;
      if (problem.code === 'package_mismatch') packageMismatchCount++;
      if (problem.code === 'advisory_key_mismatch') advisoryKeyMismatchCount++;
      if (problem.code === 'duplicate_canonical_identity') duplicateCanonicalIdentityCount++;
      errors.push(
        `Advisory snapshot ${String(snapshot.snapshotId)} ${problem.code}: ${problem.detail}`,
      );
    }
  }
  const failedCount = duplicateSnapshotIdCount +
    invalidHeaderCount +
    orphanRowCount +
    rowCountMismatchCount +
    contentHashMismatchCount +
    provenanceFailureCount +
    malformedRowCount +
    packageMismatchCount +
    advisoryKeyMismatchCount +
    duplicateCanonicalIdentityCount +
    semanticScope.semanticProblemCount;
  return {
    snapshotCount: snapshots.filter((snapshot) => snapshot.headerPresent !== false).length,
    rowCount,
    duplicateSnapshotIdCount,
    invalidHeaderCount,
    orphanRowCount,
    rowCountMismatchCount,
    contentHashMismatchCount,
    provenanceFailureCount,
    malformedRowCount,
    packageMismatchCount,
    advisoryKeyMismatchCount,
    duplicateCanonicalIdentityCount,
    latestSnapshotId: semanticScope.latestSnapshotId,
    latestSnapshotSchemaVersion: semanticScope.latestSnapshotSchemaVersion,
    outcomeReferencedSnapshotIds: semanticScope.outcomeReferencedSnapshotIds,
    outcomeReferencedSnapshotKeys: semanticScope.outcomeReferencedSnapshotKeys,
    semanticProblemCount: semanticScope.semanticProblemCount,
    semanticSnapshotCount: semanticScope.semanticSnapshotCount,
    legacySemanticProblemCount: semanticScope.legacySemanticProblemCount,
    legacySemanticSnapshotCount: semanticScope.legacySemanticSnapshotCount,
    legacySemanticSnapshotIds: semanticScope.legacySemanticSnapshotIds,
    failedCount,
  };
}

function advisorySnapshotKeysReferencedByOutcomes(
  observations: ReleaseValidationOutcomeLedgerRow[],
): Set<string> {
  const referencedKeys = new Set<string>();
  for (const observation of observations) {
    if (observation.status !== 'matured' ||
      observation.horizon_code !== 'security_30d') {
      continue;
    }
    const payload = parseRecord(observation.outcome_json);
    const security = asRecord(payload?.security);
    const snapshotId = Number(security?.snapshotId);
    const schemaVersion = advisorySnapshotSchemaVersionFromSecurityPayload(security);
    if (Number.isInteger(snapshotId) && snapshotId > 0) {
      referencedKeys.add(advisorySnapshotIdentityKey(schemaVersion, snapshotId));
    }
    for (const candidate of recordArray(payload?.candidateOutcomes)) {
      const candidateSecurity = asRecord(candidate.security);
      const candidateSnapshotId = Number(candidateSecurity?.snapshotId);
      const candidateSchemaVersion =
        advisorySnapshotSchemaVersionFromSecurityPayload(candidateSecurity);
      if (Number.isInteger(candidateSnapshotId) && candidateSnapshotId > 0) {
        referencedKeys.add(
          advisorySnapshotIdentityKey(
            candidateSchemaVersion,
            candidateSnapshotId,
          ),
        );
      }
    }
  }
  return referencedKeys;
}

function advisorySnapshotSemanticScope(
  snapshots: AdvisorySnapshotValidationEvidence[],
  outcomeReferencedSnapshotKeys: Set<string>,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
): AdvisorySnapshotSemanticScopeReport {
  const latestSnapshot = latestAdvisorySnapshot(snapshots);
  const requiredSnapshotKeys = new Set(outcomeReferencedSnapshotKeys);
  if (latestSnapshot) requiredSnapshotKeys.add(advisorySnapshotKey(latestSnapshot));
  const semanticProblemsBySnapshot = new Map<string, AdvisorySnapshotRowProblem[]>();
  for (const snapshot of snapshots) {
    const semanticProblems = advisorySnapshotRowProblems(
      snapshot.rows,
      expectedAdvisoryPackage,
    ).filter(isAdvisorySnapshotSemanticProblem);
    if (semanticProblems.length > 0) {
      semanticProblemsBySnapshot.set(advisorySnapshotKey(snapshot), semanticProblems);
    }
  }
  const semanticSnapshotKeys = [...semanticProblemsBySnapshot.keys()]
    .filter((snapshotKey) => requiredSnapshotKeys.has(snapshotKey))
    .sort();
  const legacySemanticSnapshotKeys = [...semanticProblemsBySnapshot.keys()]
    .filter((snapshotKey) => !requiredSnapshotKeys.has(snapshotKey))
    .sort();
  const outcomeReferencedSnapshotIds = [...outcomeReferencedSnapshotKeys]
    .map(advisorySnapshotIdFromKey)
    .filter((snapshotId): snapshotId is number => snapshotId != null);
  return {
    latestSnapshotId: latestSnapshot?.snapshotId ?? null,
    latestSnapshotSchemaVersion: latestSnapshot
      ? advisorySnapshotSchemaVersion(latestSnapshot) as 1 | 2
      : null,
    outcomeReferencedSnapshotIds: [...new Set(outcomeReferencedSnapshotIds)]
      .sort((left, right) => left - right),
    outcomeReferencedSnapshotKeys: [...outcomeReferencedSnapshotKeys].sort(),
    requiredSnapshotKeys,
    semanticProblemCount: semanticSnapshotKeys.reduce(
      (sum, snapshotKey) =>
        sum + (semanticProblemsBySnapshot.get(snapshotKey)?.length ?? 0),
      0,
    ),
    semanticSnapshotCount: semanticSnapshotKeys.length,
    legacySemanticProblemCount: legacySemanticSnapshotKeys.reduce(
      (sum, snapshotKey) =>
        sum + (semanticProblemsBySnapshot.get(snapshotKey)?.length ?? 0),
      0,
    ),
    legacySemanticSnapshotCount: legacySemanticSnapshotKeys.length,
    legacySemanticSnapshotIds: legacySemanticSnapshotKeys
      .map(advisorySnapshotIdFromKey)
      .filter((snapshotId): snapshotId is number => snapshotId != null),
  };
}

function latestAdvisorySnapshot(
  snapshots: AdvisorySnapshotValidationEvidence[],
): AdvisorySnapshotValidationEvidence | null {
  return snapshots
    .filter((snapshot) =>
      snapshot.headerPresent !== false &&
      Number.isInteger(snapshot.snapshotId) &&
      snapshot.snapshotId > 0 &&
      [1, 2].includes(advisorySnapshotSchemaVersion(snapshot)) &&
      Number.isFinite(Date.parse(snapshot.capturedAt)))
    .slice()
    .sort((left, right) =>
      Date.parse(right.capturedAt) - Date.parse(left.capturedAt) ||
      advisorySnapshotSchemaVersion(right) - advisorySnapshotSchemaVersion(left) ||
      right.snapshotId - left.snapshotId)[0] ?? null;
}

function advisorySnapshotSchemaVersion(
  snapshot: Pick<AdvisorySnapshotValidationEvidence, 'schemaVersion'>,
): number {
  return Number(snapshot.schemaVersion ?? 1);
}

function advisorySnapshotSchemaVersionFromSecurityPayload(
  security: JsonRecord | null,
): number {
  return Number(security?.snapshotSchemaVersion ?? 1);
}

function advisorySnapshotIdentityKey(
  schemaVersion: number,
  snapshotId: number,
): string {
  return `v${schemaVersion}:${snapshotId}`;
}

function advisorySnapshotKey(
  snapshot: Pick<
    AdvisorySnapshotValidationEvidence,
    'schemaVersion' | 'snapshotId'
  >,
): string {
  return advisorySnapshotIdentityKey(
    advisorySnapshotSchemaVersion(snapshot),
    snapshot.snapshotId,
  );
}

function advisorySnapshotIdFromKey(key: string): number | null {
  const match = /^v[12]:(\d+)$/.exec(key);
  if (!match) return null;
  const snapshotId = Number(match[1]);
  return Number.isSafeInteger(snapshotId) && snapshotId > 0
    ? snapshotId
    : null;
}

function isAdvisorySnapshotSemanticProblem(
  problem: AdvisorySnapshotRowProblem,
): boolean {
  return problem.code === 'malformed_row' &&
    /^(?:malformed_vulnerable_range|malformed_patch_metadata|patched_version_still_vulnerable):/
      .test(problem.detail);
}

function orderLedgerRows<T extends { id?: number }>(rows: T[]): T[] {
  return rows
    .map((row, index) => ({ row, index }))
    .sort((left, right) => ledgerRowSort(left, right))
    .map((item) => item.row);
}

function ledgerRowSort<T extends { id?: number }>(
  left: { row: T; index: number },
  right: { row: T; index: number },
): number {
  const leftId = Number(left.row.id);
  const rightId = Number(right.row.id);
  const leftValid = Number.isInteger(leftId) && leftId > 0;
  const rightValid = Number.isInteger(rightId) && rightId > 0;
  if (leftValid && rightValid && leftId !== rightId) return leftId - rightId;
  if (leftValid !== rightValid) return leftValid ? -1 : 1;
  return left.index - right.index;
}

function releaseValidationOutcomeRecordContent(
  row: ReleaseValidationOutcomeLedgerRow,
): string {
  return JSON.stringify([
    row.decision_id,
    row.horizon_code,
    row.observed_at,
    row.status,
    row.outcome_json,
    row.source_identity_json,
  ]);
}

export function evaluateReleaseValidationLedger(input: {
  forecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
  auditHistory: ReleaseScoreAuditHistoryEvidenceRow[];
  auditHistoryRuns?: ReleaseScoreAuditHistoryRunSealEvidenceRow[];
  authorityRuns?: ReleaseScoreAuthorityRunEvidence[];
  historyV2Seals?: ReleaseScoreAuditHistoryV2SealEvidence[];
  advisorySnapshots: AdvisorySnapshotValidationEvidence[];
  currentModelVersion: string;
  currentPromptVersion: number;
  currentCodeRevision: string;
  expectedAdvisoryPackage?: ExpectedAdvisoryPackage;
  generatedAt?: string;
  thresholds?: Partial<ValidationSampleThresholds>;
  qualityCriteria?: Partial<ValidationQualityCriteria>;
  opportunityDenominatorLedger?: ReleaseValidationOpportunityDenominatorLedger;
  prospectiveProof?: ReleaseValidationProspectiveProofInput;
}): JsonRecord {
  const thresholds = {
    ...DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
    ...input.thresholds,
  };
  const qualityCriteria = {
    ...DEFAULT_VALIDATION_QUALITY_CRITERIA,
    ...input.qualityCriteria,
  };
  const errors: string[] = [];
  const expectedAdvisoryPackage =
    input.expectedAdvisoryPackage ?? DEFAULT_EXPECTED_ADVISORY_PACKAGE;
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const generatedAtMs = Date.parse(generatedAt);
  if (!Number.isFinite(generatedAtMs)) {
    errors.push(`Evaluation generatedAt is invalid: ${generatedAt}`);
  }
  const pointInTimeObservations = input.observations.filter((observation) => {
    const observedAtMs = Date.parse(observation.observed_at);
    if (!Number.isFinite(observedAtMs)) {
      errors.push(
        `Outcome ${observation.observation_id || 'unknown'} has an invalid observed_at`,
      );
      return false;
    }
    return Number.isFinite(generatedAtMs) && observedAtMs <= generatedAtMs;
  });
  if (typeof input.currentModelVersion !== 'string' ||
    !input.currentModelVersion.trim() ||
    !Number.isInteger(input.currentPromptVersion)) {
    errors.push('Current model/prompt stratum is invalid');
  }
  const currentCodeRevision = normalizeCodeRevision(input.currentCodeRevision);
  if (!currentCodeRevision) {
    throw new Error('Current validation code revision is required');
  }
  errors.push(...validateReleaseValidationForecastProvenance(
    input.forecasts,
    input.auditHistory,
    input.auditHistoryRuns ?? [],
    input.authorityRuns ?? [],
    input.historyV2Seals ?? [],
  ));
  const auditHistoryByRunAndTag = indexAuditHistory(input.auditHistory, errors);
  const outcomeReferencedAdvisorySnapshotKeys =
    advisorySnapshotKeysReferencedByOutcomes(pointInTimeObservations);
  const advisorySnapshotSemantics = advisorySnapshotSemanticScope(
    input.advisorySnapshots,
    outcomeReferencedAdvisorySnapshotKeys,
    expectedAdvisoryPackage,
  );
  const advisorySnapshotsById = indexAdvisorySnapshots(
    input.advisorySnapshots,
    errors,
    expectedAdvisoryPackage,
    advisorySnapshotSemantics.requiredSnapshotKeys,
  );
  const timingAssessments = input.forecasts.map((forecast) => ({
    forecast,
    decisionSchemaVersion: releaseValidationDecisionSchemaVersion(forecast),
    timing: releaseValidationForecastTiming(forecast),
  }));
  const excludedForecasts = timingAssessments
    .filter((item) => item.decisionSchemaVersion !== 4 || !item.timing.valid)
    .map((item) => ({
      decisionId: item.forecast.decision_id,
      latestReleaseTag: item.forecast.latest_release_tag,
      opportunityCode: item.forecast.opportunity_code,
      modelVersion: item.forecast.score_model_version,
      promptVersion: item.forecast.prompt_version,
      codeRevision: normalizeCodeRevision(item.forecast.code_revision),
      reason: item.decisionSchemaVersion === 4
        ? item.timing.reason
        : 'legacy_decision_schema',
      decisionSchemaVersion: item.decisionSchemaVersion,
      ageHours: item.timing.ageHours,
      windowStartAt: item.timing.windowStartAt,
      windowEndAt: item.timing.windowEndAt,
      legacyTimingMetadata:
        Number(parseRecord(item.forecast.decision_json)?.schemaVersion ?? 2) < 3,
    }));
  const forecasts = deduplicateForecasts(
    timingAssessments
      .filter((item) => item.decisionSchemaVersion === 4 && item.timing.valid)
      .map((item) => item.forecast),
    errors,
  );
  const observations = observationsByDecisionAndHorizon(
    pointInTimeObservations,
    new Set(input.forecasts.map((forecast) => forecast.decision_id)),
    errors,
  );
  const resolutions = new Map<string, ObservationResolution>();
  for (const forecast of forecasts) {
    for (const horizonCode of Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[]) {
      const key = `${forecast.decision_id}\0${horizonCode}`;
      resolutions.set(key, resolveObservationLedger(
        forecast,
        horizonCode,
        observations.get(key) ?? [],
        auditHistoryByRunAndTag,
        input.advisorySnapshots,
        advisorySnapshotsById,
        expectedAdvisoryPackage,
        errors,
      ));
    }
  }
  const horizonCases = new Map<ReleaseValidationHorizonCode, EvaluationCase[]>(
    (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[])
      .map((code) => [code, []]),
  );
  const combinedCases: EvaluationCase[] = [];
  const candidateHorizonCases = new Map<ReleaseValidationHorizonCode, EvaluationCase[]>(
    (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[])
      .map((code) => [code, []]),
  );
  const candidateCombinedCases: EvaluationCase[] = [];

  for (const forecast of forecasts) {
    const targetReleaseTag = validationTargetReleaseTag(forecast);
    const score = candidateScoreForRelease(forecast.candidate_scores_json, targetReleaseTag);
    const latestReleaseIdentity = releaseIdentityForForecast(forecast, errors);
    const base = {
      releaseTag: targetReleaseTag,
      latestReleaseTag: forecast.latest_release_tag,
      latestReleaseIdentity,
      opportunityCode: forecast.opportunity_code,
      modelVersion: forecast.score_model_version,
      promptVersion: forecast.prompt_version,
      codeRevision: normalizeCodeRevision(forecast.code_revision),
      decisionId: forecast.decision_id,
      recommended: forecast.selected_tag != null,
      score,
    };
    const matured = new Map<ReleaseValidationHorizonCode, {
      adverse: boolean;
      observedAt: string;
    }>();
    for (const horizonCode of Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[]) {
      const parsed = resolutions.get(`${forecast.decision_id}\0${horizonCode}`)?.matured ?? null;
      if (!parsed) continue;
      matured.set(horizonCode, parsed);
      horizonCases.get(horizonCode)!.push({
        ...base,
        ...parsed,
        horizonCode,
      });
    }
    if (matured.size === Object.keys(RELEASE_VALIDATION_HORIZONS).length) {
      const adverseHorizons = [...matured.entries()]
        .filter(([, value]) => value.adverse)
        .map(([code]) => code);
      combinedCases.push({
        ...base,
        adverse: adverseHorizons.length > 0,
        observedAt: [...matured.values()]
          .map((value) => value.observedAt)
          .sort((left, right) => Date.parse(right) - Date.parse(left))[0],
        windowStartAt: forecast.recorded_at,
        windowEndAt: new Date(
          Date.parse(forecast.recorded_at) +
          Math.max(...Object.values(RELEASE_VALIDATION_HORIZONS).map((horizon) => horizon.durationMs)),
        ).toISOString(),
        horizonCode: 'combined',
        adverseHorizons,
      });
    }

    for (const target of releaseValidationObservationTargets(forecast)) {
      const candidateMatured = new Map<ReleaseValidationHorizonCode, {
        adverse: boolean;
        observedAt: string;
      }>();
      for (const horizonCode of Object.keys(RELEASE_VALIDATION_HORIZONS) as
        ReleaseValidationHorizonCode[]) {
        const resolution = resolutions.get(`${forecast.decision_id}\0${horizonCode}`)
          ?.matured ?? null;
        if (!resolution?.completeCandidateCoverage) continue;
        const targetOutcome = resolution.targetOutcomes.find((item) =>
          item.targetReleaseTag === target.targetReleaseTag);
        if (!targetOutcome) continue;
        const candidateCase = {
          latestReleaseTag: forecast.latest_release_tag,
          latestReleaseIdentity,
          releaseTag: target.targetReleaseTag,
          opportunityCode: forecast.opportunity_code,
          modelVersion: forecast.score_model_version,
          promptVersion: forecast.prompt_version,
          codeRevision: normalizeCodeRevision(forecast.code_revision),
          decisionId: forecast.decision_id,
          recommended: target.roles.includes('selected'),
          adverse: targetOutcome.adverse,
          score: candidateScoreForRelease(
            forecast.candidate_scores_json,
            target.targetReleaseTag,
          ),
          observedAt: resolution.observedAt,
          windowStartAt: resolution.windowStartAt,
          windowEndAt: resolution.windowEndAt,
          horizonCode,
          targetRoles: target.roles,
        } satisfies EvaluationCase;
        candidateHorizonCases.get(horizonCode)!.push(candidateCase);
        candidateMatured.set(horizonCode, {
          adverse: targetOutcome.adverse,
          observedAt: resolution.observedAt,
        });
      }
      if (candidateMatured.size === Object.keys(RELEASE_VALIDATION_HORIZONS).length) {
        const adverseHorizons = [...candidateMatured.entries()]
          .filter(([, value]) => value.adverse)
          .map(([code]) => code);
        candidateCombinedCases.push({
          latestReleaseTag: forecast.latest_release_tag,
          latestReleaseIdentity,
          releaseTag: target.targetReleaseTag,
          opportunityCode: forecast.opportunity_code,
          modelVersion: forecast.score_model_version,
          promptVersion: forecast.prompt_version,
          codeRevision: normalizeCodeRevision(forecast.code_revision),
          decisionId: forecast.decision_id,
          recommended: target.roles.includes('selected'),
          adverse: adverseHorizons.length > 0,
          score: candidateScoreForRelease(
            forecast.candidate_scores_json,
            target.targetReleaseTag,
          ),
          observedAt: [...candidateMatured.values()]
            .map((value) => value.observedAt)
            .sort((left, right) => Date.parse(right) - Date.parse(left))[0],
          windowStartAt: forecast.recorded_at,
          windowEndAt: new Date(
            Date.parse(forecast.recorded_at) +
            Math.max(...Object.values(RELEASE_VALIDATION_HORIZONS)
              .map((horizon) => horizon.durationMs)),
          ).toISOString(),
          horizonCode: 'combined',
          adverseHorizons,
          targetRoles: target.roles,
        });
      }
    }
  }

  const horizons = Object.fromEntries(
    (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[]).map((code) => [
      code,
      evaluationSection(horizonCases.get(code)!, thresholds, qualityCriteria),
    ]),
  );
  const combined = evaluationSection(combinedCases, thresholds, qualityCriteria);
  const candidateScoreQuality = {
    horizons: Object.fromEntries(
      (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[])
        .map((code) => [
          code,
          candidateScoreEvaluationSection(
            candidateHorizonCases.get(code)!,
            thresholds,
            qualityCriteria,
          ),
        ]),
    ),
    combined: candidateScoreEvaluationSection(
      candidateCombinedCases,
      thresholds,
      qualityCriteria,
    ),
  };
  const splitPlan = input.prospectiveProof?.canonicalProof
    ? buildCanonicalEvaluationSplitPlan(
        input.prospectiveProof.canonicalProof,
      )
    : buildEvaluationSplitPlan({
        denominatorLedger: input.opportunityDenominatorLedger,
        persistedAssignments: input.prospectiveProof?.splitAssignments,
        thresholds,
      });
  const currentModelForecasts = forecasts.filter((forecast) =>
    forecast.score_model_version === input.currentModelVersion &&
    forecast.prompt_version === input.currentPromptVersion);
  const currentRevisions = [...new Set(
    currentModelForecasts
      .map((forecast) => normalizeCodeRevision(forecast.code_revision))
      .filter((revision): revision is string => revision != null),
  )];
  const currentStratumKey =
    `${input.currentModelVersion}/prompt-${input.currentPromptVersion}/` +
    `revision-${currentCodeRevision}`;
  const currentStratum = {
    key: currentStratumKey,
    codeRevision: currentCodeRevision,
    ambiguous: false,
    availableCodeRevisions: currentRevisions,
    horizons: Object.fromEntries(
      (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[]).map((code) => [
        code,
        stratumEvaluationSection(
          horizonCases.get(code)!,
          currentStratumKey,
          thresholds,
          qualityCriteria,
          splitPlan,
        ),
      ]),
    ),
    combined: stratumEvaluationSection(
      combinedCases,
      currentStratumKey,
      thresholds,
      qualityCriteria,
      splitPlan,
    ),
  };
  const currentCandidateScoreQuality = {
    horizons: Object.fromEntries(
      (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[])
        .map((code) => [
          code,
          candidateScoreStratumEvaluationSection(
            candidateHorizonCases.get(code)!,
            currentStratumKey,
            thresholds,
            qualityCriteria,
            splitPlan,
          ),
        ]),
    ),
    combined: candidateScoreStratumEvaluationSection(
      candidateCombinedCases,
      currentStratumKey,
      thresholds,
      qualityCriteria,
      splitPlan,
    ),
  };
  const currentPolicyByOpportunity = Object.fromEntries(
    (Object.keys(RELEASE_VALIDATION_OPPORTUNITIES) as
      ReleaseValidationOpportunityCode[]).map((opportunityCode) => {
      const horizons = Object.fromEntries(
        (Object.keys(RELEASE_VALIDATION_HORIZONS) as
          ReleaseValidationHorizonCode[]).map((horizonCode) => [
          horizonCode,
          stratumEvaluationSection(
            horizonCases.get(horizonCode)!.filter((item) =>
              item.opportunityCode === opportunityCode),
            currentStratumKey,
            thresholds,
            qualityCriteria,
            splitPlan,
          ),
        ]),
      );
      const combined = stratumEvaluationSection(
        combinedCases.filter((item) =>
          item.opportunityCode === opportunityCode),
        currentStratumKey,
        thresholds,
        qualityCriteria,
        splitPlan,
      );
      return [opportunityCode, {
        horizons,
        combined,
        gateStatus: combinedEvaluationGateStatus([
          ...Object.values(horizons),
          combined,
        ]),
      }];
    }),
  );
  const currentCandidateByOpportunity = Object.fromEntries(
    (Object.keys(RELEASE_VALIDATION_OPPORTUNITIES) as
      ReleaseValidationOpportunityCode[]).map((opportunityCode) => {
      const horizons = Object.fromEntries(
        (Object.keys(RELEASE_VALIDATION_HORIZONS) as
          ReleaseValidationHorizonCode[]).map((horizonCode) => [
          horizonCode,
          candidateScoreStratumEvaluationSection(
            candidateHorizonCases.get(horizonCode)!.filter((item) =>
              item.opportunityCode === opportunityCode),
            currentStratumKey,
            thresholds,
            qualityCriteria,
            splitPlan,
          ),
        ]),
      );
      const combined = candidateScoreStratumEvaluationSection(
        candidateCombinedCases.filter((item) =>
          item.opportunityCode === opportunityCode),
        currentStratumKey,
        thresholds,
        qualityCriteria,
        splitPlan,
      );
      return [opportunityCode, {
        horizons,
        combined,
        gateStatus: combinedEvaluationGateStatus([
          ...Object.values(horizons),
          combined,
        ]),
      }];
    }),
  );
  const currentPolicyGateStatus = combinedEvaluationGateStatus([
    ...Object.values(currentPolicyByOpportunity),
  ]);
  const currentCandidateGateStatus = combinedEvaluationGateStatus([
    ...Object.values(currentCandidateByOpportunity),
  ]);
  const currentStratumSufficient =
    currentPolicyGateStatus !== 'insufficient' &&
    currentCandidateGateStatus !== 'insufficient';
  const currentStratumQualityPassed =
    currentPolicyGateStatus === 'passed' &&
    currentCandidateGateStatus === 'passed';
  const outcomeCoverage = observationCoverage(
    forecasts,
    resolutions,
    Number.isFinite(generatedAtMs) ? generatedAtMs : 0,
  );
  const currentForecasts = forecasts.filter((forecast) =>
    validationStratumKey(forecast) === currentStratumKey);
  const denominatorCoverage = releaseValidationOpportunityDenominatorCoverage({
    ledger: input.opportunityDenominatorLedger,
    forecasts: currentForecasts,
    currentModelVersion: input.currentModelVersion,
    currentPromptVersion: input.currentPromptVersion,
    currentCodeRevision,
    errors,
  });
  const currentOutcomeCoverage = observationCoverage(
    currentForecasts,
    resolutions,
    Number.isFinite(generatedAtMs) ? generatedAtMs : 0,
  );
  const currentCombinedCoverage = asRecord(currentOutcomeCoverage.combined);
  const currentTerminalAttritionCount = Number(
    currentCombinedCoverage?.terminalAttritionCount ?? 0,
  );
  const currentFatalIndeterminateCount = Number(
    currentCombinedCoverage?.fatalIndeterminateCount ?? 0,
  );
  const currentIndeterminateCount = Number(
    currentCombinedCoverage?.indeterminateCount ?? 0,
  );
  const denominatorFailedCount = Number(denominatorCoverage.failedCount ?? 0);
  const denominatorMissedCount = Number(denominatorCoverage.missedCount ?? 0);
  const denominatorReady = denominatorCoverage.ready === true;
  const prospectivePromotion = input.prospectiveProof?.canonicalProof
    ? assessCanonicalProspectivePromotion({
        proof: input.prospectiveProof.canonicalProof,
        evaluationPurpose:
          input.prospectiveProof.evaluationPurpose ?? 'production',
        forecasts,
        allForecasts: input.forecasts,
        observations: pointInTimeObservations,
        splitPlan,
        currentStratumKey,
        generatedAt,
        generatedAtMs: Number.isFinite(generatedAtMs) ? generatedAtMs : 0,
        thresholds,
        qualityCriteria,
        horizonCases,
        combinedCases,
        candidateHorizonCases,
        candidateCombinedCases,
      })
    : assessProspectivePromotion({
        proof: input.prospectiveProof,
        forecasts,
        allForecasts: input.forecasts,
        observations: pointInTimeObservations,
        resolutions,
        denominatorLedger: input.opportunityDenominatorLedger,
        splitPlan,
        currentStratumKey,
        generatedAtMs: Number.isFinite(generatedAtMs) ? generatedAtMs : 0,
        thresholds,
        qualityCriteria,
        horizonCases,
        combinedCases,
        candidateHorizonCases,
        candidateCombinedCases,
      });
  for (const error of prospectivePromotion.blockingErrors) {
    if (!errors.includes(error)) errors.push(error);
  }
  const status = errors.length > 0 ||
    currentFatalIndeterminateCount > 0 ||
    denominatorFailedCount > 0 ||
    prospectivePromotion.status === 'failed'
    ? 'measurable_but_failed'
    : currentStratumSufficient && !currentStratumQualityPassed
      ? 'measurable_but_failed'
    : currentIndeterminateCount > 0 ||
      currentTerminalAttritionCount > 0 ||
      denominatorMissedCount > 0 ||
      !denominatorReady ||
      !currentStratumSufficient ||
      prospectivePromotion.status === 'insufficient'
      ? 'insufficient'
      : currentStratumQualityPassed
        ? 'validated'
        : 'measurable_but_failed';
  const failureClass = errors.length > 0
    ? 'ledger_or_evidence_integrity'
    : currentFatalIndeterminateCount > 0
      ? 'fatal_observation_evidence'
    : denominatorFailedCount > 0
      ? 'forecast_capture_failure'
      : prospectivePromotion.status === 'failed'
        ? prospectivePromotion.failureClass
      : currentStratumSufficient && !currentStratumQualityPassed
        ? 'minimum_quality_criteria'
      : currentIndeterminateCount > 0
          ? 'outcome_censoring'
          : currentTerminalAttritionCount > 0
            ? 'outcome_attrition'
          : denominatorMissedCount > 0
            ? 'forecast_opportunity_attrition'
            : !denominatorReady
              ? 'forecast_opportunity_denominator'
              : prospectivePromotion.status === 'insufficient'
                ? prospectivePromotion.failureClass
              : !currentStratumSufficient
                ? 'sample_or_power'
                : null;

  return {
    schemaVersion: 4,
    generatedAt,
    forecastLedgerRowCount: input.forecasts.length,
    eligibleForecastCount: forecasts.length,
    excludedForecastCount: excludedForecasts.length,
    excludedForecasts,
    decisionLevelForecastCount: forecasts.length,
    primaryOpportunityPolicy:
      'retain_every_valid_forecast_decision_without_native_or_later-decision_collapse',
    dependencePolicy:
      'each_3h_and_24h_opportunity_is_gated_independently_on_non_overlapping_cases_and_a_later_temporal_holdout',
    outcomeLedgerRowCount: pointInTimeObservations.length,
    advisorySnapshotSemantics: {
      latestSnapshotId: advisorySnapshotSemantics.latestSnapshotId,
      outcomeReferencedSnapshotIds:
        advisorySnapshotSemantics.outcomeReferencedSnapshotIds,
      semanticProblemCount: advisorySnapshotSemantics.semanticProblemCount,
      semanticSnapshotCount: advisorySnapshotSemantics.semanticSnapshotCount,
      legacySemanticProblemCount:
        advisorySnapshotSemantics.legacySemanticProblemCount,
      legacySemanticSnapshotCount:
        advisorySnapshotSemantics.legacySemanticSnapshotCount,
      legacySemanticSnapshotIds:
        advisorySnapshotSemantics.legacySemanticSnapshotIds,
    },
    status,
    failureClass,
    interpretation: {
      policyActionSafety:
        'Policy safety evaluates install-selected versus withhold-latest actions using only the policy target outcome.',
      candidateScoreQuality:
        'Candidate score quality evaluates every sealed forecast candidate independently of the policy action.',
      scoreCalibration:
        'No probability calibration is claimed; score validation is ordinal and evaluated on a later temporal holdout.',
    },
    thresholds,
    qualityCriteria,
    errors,
    opportunityDenominator: denominatorCoverage,
    prospectiveEvaluation: prospectivePromotion.report,
    promotionDecision: prospectivePromotion.report.promotionDecision,
    currentStratum: {
      ...currentStratum,
      opportunities: currentPolicyByOpportunity,
      candidateScoreQuality: currentCandidateScoreQuality,
      candidateOpportunities: currentCandidateByOpportunity,
      policyGateStatus: currentPolicyGateStatus,
      candidateScoreGateStatus: currentCandidateGateStatus,
      status,
      failureClass,
      sampleSufficient: currentStratumSufficient,
      qualityPassed: currentStratumQualityPassed,
      outcomeCoverage: currentOutcomeCoverage,
    },
    outcomeCoverage: {
      scope: 'all_valid_forecast_decisions',
      ...outcomeCoverage,
    },
    pairedModelComparisons: {
      horizons: Object.fromEntries(
        (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[])
          .map((code) => [code, pairedModelComparisons(horizonCases.get(code)!)]),
      ),
      combined: pairedModelComparisons(combinedCases),
    },
    policyActionSafety: {
      horizons,
      combined,
    },
    candidateScoreQuality: {
      ...candidateScoreQuality,
      currentStratum: currentCandidateScoreQuality,
    },
    horizons,
    combined,
  };
}

export function validateReleaseValidationForecastProvenance(
  forecasts: ReleaseValidationForecastLedgerRow[],
  auditHistory: ReleaseScoreAuditHistoryEvidenceRow[],
  auditHistoryRuns: ReleaseScoreAuditHistoryRunSealEvidenceRow[] = [],
  authorityRuns: readonly ReleaseScoreAuthorityRunEvidence[] = [],
  historyV2Seals: readonly ReleaseScoreAuditHistoryV2SealEvidence[] = [],
): string[] {
  const errors: string[] = [];
  const historyByRunAndTag = new Map<string, ReleaseScoreAuditHistoryEvidenceRow>();
  const historyByRun = new Map<string, ReleaseScoreAuditHistoryEvidenceRow[]>();
  const historyRunSealById = uniqueEvidenceMap(
    auditHistoryRuns,
    (row) => row.run_id,
    'score audit history run seal',
    errors,
  );
  const authorityRunById = uniqueEvidenceMap(
    authorityRuns,
    (run) => run.authorityRunId,
    'score authority run',
    errors,
  );
  const historyV2SealByRunId = uniqueEvidenceMap(
    historyV2Seals,
    (seal) => seal.historyRunId,
    'score audit history v2 seal',
    errors,
  );
  for (const row of auditHistory) {
    const key = `${row.run_id}\0${row.release_tag}`;
    if (historyByRunAndTag.has(key)) {
      errors.push(`Duplicate score audit history row ${row.run_id}/${row.release_tag}`);
      continue;
    }
    historyByRunAndTag.set(key, row);
    const runRows = historyByRun.get(row.run_id) ?? [];
    runRows.push(row);
    historyByRun.set(row.run_id, runRows);
  }
  for (const forecast of forecasts) {
    const decision = parseRecord(forecast.decision_json);
    const candidates = recordArray(parseJson(forecast.candidate_scores_json));
    const historyRows = historyByRun.get(forecast.audit_history_run_id) ?? [];
    const historyAuthorityRunIds = new Set(
      historyRows.map((row) => row.authority_run_id),
    );
    if (!decision || candidates.length === 0) {
      errors.push(`Forecast ${forecast.decision_id} has malformed decision or candidate snapshots`);
      continue;
    }
    const decisionSchemaVersion = decision.schemaVersion ?? 2;
    if (decisionSchemaVersion !== 1 &&
      decisionSchemaVersion !== 2 &&
      decisionSchemaVersion !== 3 &&
      decisionSchemaVersion !== 4) {
      errors.push(`Forecast ${forecast.decision_id} has unsupported decision schema version`);
      continue;
    }
    if (decision.opportunityCode !== forecast.opportunity_code ||
      decision.recordedAt !== forecast.recorded_at ||
      decision.latestReleaseTag !== forecast.latest_release_tag ||
      decision.latestReleasePublishedAt !== forecast.latest_release_published_at ||
      decision.selectedTag !== forecast.selected_tag) {
      errors.push(`Forecast ${forecast.decision_id} decision metadata does not match its ledger row`);
    }
    if (decisionSchemaVersion >= 3) {
      const timing = releaseValidationForecastTiming(forecast);
      const persistedWindow = asRecord(decision.opportunityWindow);
      const opportunity = RELEASE_VALIDATION_OPPORTUNITIES[
        forecast.opportunity_code as ReleaseValidationOpportunityCode
      ];
      if (
        !opportunity ||
        !timing.valid ||
        decision.latestReleaseAgeHours !== timing.ageHours ||
        !persistedWindow ||
        persistedWindow.minAgeHours !== opportunity.minAgeHours ||
        persistedWindow.maxAgeHours !== opportunity.maxAgeHours ||
        persistedWindow.windowStartAt !== timing.windowStartAt ||
        persistedWindow.windowEndAt !== timing.windowEndAt ||
        (
          decisionSchemaVersion >= 4 &&
          (
            persistedWindow.windowStartMs !== timing.windowStartMs ||
            persistedWindow.windowEndMs !== timing.windowEndMs ||
            persistedWindow.observedAtMs !== timing.recordedAtMs
          )
        ) ||
        persistedWindow.observedAgeHours !== timing.ageHours ||
        persistedWindow.valid !== true
      ) {
        errors.push(
          `Forecast ${forecast.decision_id} opportunity timing metadata is invalid`,
        );
      }
    }
    if (decisionSchemaVersion >= 4) {
      const historyRunSeal = historyRunSealById.get(forecast.audit_history_run_id);
      const expectedAuthorityRunId =
        historyAuthorityRunIds.size === 1
          ? [...historyAuthorityRunIds][0]
          : null;
      const authorityRun = typeof expectedAuthorityRunId === 'string'
        ? authorityRunById.get(expectedAuthorityRunId)
        : undefined;
      const historyV2Seal = historyV2SealByRunId.get(
        forecast.audit_history_run_id,
      );
      const historyRowsContentHash = historyRows.length > 0
        ? releaseScoreAuditHistoryRowsContentHash(
            (
              historyRows
                .slice()
                .sort((left, right) =>
                  left.release_tag.localeCompare(right.release_tag))
            ) as unknown as Array<Record<string, unknown>>,
          )
        : null;
      if (historyRunSeal) {
        if (
          historyRunSeal.row_count !== historyRows.length ||
          historyRowsContentHash == null ||
          historyRunSeal.rows_content_hash !== historyRowsContentHash
        ) {
          errors.push(
            `Forecast ${forecast.decision_id} sealed history row projection is invalid`,
          );
        }
        if (
          historyRunSeal.content_hash !== releaseScoreAuditHistoryRunContentHash({
            runId: historyRunSeal.run_id,
            recordedAt: historyRunSeal.recorded_at,
            rowCount: historyRunSeal.row_count,
            rowsContentHash: historyRunSeal.rows_content_hash,
            previousContentHash: historyRunSeal.previous_content_hash,
          })
        ) {
          errors.push(
            `Forecast ${forecast.decision_id} history run seal hash is invalid`,
          );
        }
      } else {
        errors.push(
          `Forecast ${forecast.decision_id} score audit history run seal is missing`,
        );
      }
      if (authorityRun) {
        for (const problem of scoreAuthorityResolutionRunProblems(authorityRun)) {
          errors.push(`Forecast ${forecast.decision_id} ${problem}`);
        }
      } else if (expectedAuthorityRunId) {
        errors.push(
          `Forecast ${forecast.decision_id} score authority run ` +
          `${expectedAuthorityRunId} is missing`,
        );
      }
      if (historyV2Seal) {
        const { id: _id, ...canonicalSeal } = historyV2Seal;
        for (const problem of releaseScoreAuditHistoryV2SealProblems(
          canonicalSeal,
        )) {
          errors.push(`Forecast ${forecast.decision_id} ${problem}`);
        }
      } else {
        errors.push(
          `Forecast ${forecast.decision_id} score audit history v2 seal is missing`,
        );
      }
      if (authorityRun && historyRunSeal) {
        const sourceIdentity = parseRecord(forecast.source_identity_json);
        if (
          authorityRun.recordedAt !== historyRunSeal.recorded_at ||
          !sourceIdentity ||
          sourceIdentity.schemaVersion !==
            authorityRun.sourceIdentitySchemaVersion ||
          sourceIdentity.digest !== authorityRun.sourceIdentityDigest
        ) {
          errors.push(
            `Forecast ${forecast.decision_id} authority run does not match ` +
            'sealed history source identity',
          );
        }
      }
      if (historyV2Seal && historyRunSeal && authorityRun) {
        if (
          historyV2Seal.historyRunId !== historyRunSeal.run_id ||
          historyV2Seal.authorityRunId !== authorityRun.authorityRunId ||
          historyV2Seal.sealedAt !== historyRunSeal.recorded_at ||
          historyV2Seal.historyRowCount !== historyRunSeal.row_count ||
          historyV2Seal.historyRowsContentHash !==
            historyRunSeal.rows_content_hash ||
          historyV2Seal.authorityRowCount !== authorityRun.rowCount ||
          historyV2Seal.authorityRowsContentHash !==
            authorityRun.rowsContentHash
        ) {
          errors.push(
            `Forecast ${forecast.decision_id} history v2 seal does not ` +
            'exactly bind the history and authority runs',
          );
        }
      }
      const commitProblems = releaseValidationScoreCommitTimingProblems(
        decision.scoreCommit,
        {
          recordedAt: forecast.recorded_at,
          historyRunId: forecast.audit_history_run_id,
          historyRunContentHash: historyRunSeal?.content_hash ?? null,
          historyRecordedAt: historyRunSeal?.recorded_at ?? null,
          authorityRunId: expectedAuthorityRunId,
          authorityRunContentHash: authorityRun?.contentHash ?? null,
          historyV2SealContentHash: historyV2Seal?.contentHash ?? null,
        },
      );
      const catalogProblems = releaseCatalogAttestationProblems(
        decision.catalogAttestation,
      );
      for (const problem of [...commitProblems, ...catalogProblems]) {
        errors.push(`Forecast ${forecast.decision_id} ${problem}`);
      }
      if (!expectedAuthorityRunId) {
        errors.push(
          `Forecast ${forecast.decision_id} history rows do not reference one authority run`,
        );
      }
    }
    const recommendationDecision = asRecord(decision.recommendationDecision);
    if (!recommendationDecision ||
      recommendationDecision.selectedTag !== forecast.selected_tag ||
      recommendationDecision.policyCode !== forecast.policy_code) {
      errors.push(`Forecast ${forecast.decision_id} recommendation decision does not match its ledger row`);
    }

    const seenTags = new Set<string>();
    for (const candidate of candidates) {
      const releaseTagAliases = presentAliasValues(candidate, ['releaseTag', 'release_tag', 'tag']);
      const auditSnapshotAliases = presentAliasValues(candidate, ['auditSnapshot', 'audit_snapshot']);
      const scoreSnapshotAliases = presentAliasValues(candidate, ['scoreSnapshot', 'score_snapshot']);
      if (aliasValuesConflict(releaseTagAliases) ||
        aliasValuesConflict(auditSnapshotAliases) ||
        aliasValuesConflict(scoreSnapshotAliases)) {
        errors.push(`Forecast ${forecast.decision_id} has conflicting candidate aliases`);
        continue;
      }
      const releaseTag = nullableString(releaseTagAliases[0]);
      const auditSnapshot = asRecord(auditSnapshotAliases[0]);
      const scoreSnapshot = asRecord(scoreSnapshotAliases[0]);
      if (!releaseTag || !auditSnapshot || !scoreSnapshot || seenTags.has(releaseTag)) {
        errors.push(`Forecast ${forecast.decision_id} has malformed or duplicate candidate snapshots`);
        continue;
      }
      const scoredAtAliases = presentAliasValues(scoreSnapshot, ['scoredAt', 'scored_at']);
      const snapshotScoreAliases = presentAliasValues(scoreSnapshot, ['finalScore', 'final_score']);
      const topLevelScoreAliases = presentAliasValues(candidate, ['score', 'finalScore', 'final_score']);
      if (aliasValuesConflict(scoredAtAliases) ||
        aliasValuesConflict(snapshotScoreAliases) ||
        aliasValuesConflict([...snapshotScoreAliases, ...topLevelScoreAliases])) {
        errors.push(`Forecast ${forecast.decision_id} candidate ${releaseTag} has conflicting score aliases`);
        continue;
      }
      seenTags.add(releaseTag);
      const history = historyByRunAndTag.get(`${forecast.audit_history_run_id}\0${releaseTag}`);
      if (!history) {
        errors.push(`Forecast ${forecast.decision_id} is missing history row ${forecast.audit_history_run_id}/${releaseTag}`);
        continue;
      }
      if (
        decisionSchemaVersion < 4 &&
        history.recorded_at !== forecast.recorded_at
      ) {
        errors.push(
          `Forecast ${forecast.decision_id} history run recorded_at does not match forecast recorded_at`,
        );
      }
      if (!auditSnapshotMatchesHistory(
        auditSnapshot,
        history,
        decisionSchemaVersion >= 2,
      )) {
        errors.push(`Forecast ${forecast.decision_id} candidate ${releaseTag} does not match score audit history`);
      }
      for (const problem of scoreAuditHistoryReplayProblems(history)) {
        errors.push(
          `Forecast ${forecast.decision_id} candidate ${releaseTag} ${problem}`,
        );
      }
      if (scoredAtAliases[0] !== history.scored_at ||
        snapshotScoreAliases[0] !== history.final_score ||
        scoreSnapshot.status !== history.status ||
        scoreSnapshot.band !== history.band ||
        scoreSnapshot.recommended !== (history.recommended === 1)) {
        errors.push(`Forecast ${forecast.decision_id} candidate ${releaseTag} score snapshot does not match history`);
      }
      if (history.score_model_version !== forecast.score_model_version ||
        history.prompt_version !== forecast.prompt_version ||
        history.source_identity_json !== forecast.source_identity_json) {
        errors.push(`Forecast ${forecast.decision_id} candidate ${releaseTag} model/source metadata does not match`);
      }
    }
    if (!seenTags.has(forecast.latest_release_tag) ||
      forecast.selected_tag != null && !seenTags.has(forecast.selected_tag)) {
      errors.push(`Forecast ${forecast.decision_id} does not contain its latest/selected candidate`);
    }

    const historyTags = new Set(historyRows.map((row) => row.release_tag));
    if (!sameStringSet(seenTags, historyTags)) {
      errors.push(
        `Forecast ${forecast.decision_id} candidate tags do not exactly match history run ` +
        `${forecast.audit_history_run_id} (missing=${setDifference(historyTags, seenTags).join(',') || 'none'}; ` +
        `extra=${setDifference(seenTags, historyTags).join(',') || 'none'})`,
      );
    }
    const invalidRecommendationRows = historyRows.filter((row) => row.recommended !== 0 && row.recommended !== 1);
    if (invalidRecommendationRows.length > 0) {
      errors.push(`Forecast ${forecast.decision_id} history run contains invalid recommended flags`);
    }
    const recommendedHistoryTags = historyRows
      .filter((row) => row.recommended === 1)
      .map((row) => row.release_tag)
      .sort();
    const expectedRecommendedTags = forecast.selected_tag == null ? [] : [forecast.selected_tag];
    if (!sameJsonValue(recommendedHistoryTags, expectedRecommendedTags)) {
      errors.push(
        `Forecast ${forecast.decision_id} selected tag ${forecast.selected_tag ?? 'null'} does not equal ` +
        `the recommended history candidate ${recommendedHistoryTags.join(',') || 'null'}`,
      );
    }
  }
  return errors;
}

function uniqueEvidenceMap<T>(
  rows: readonly T[],
  keyFor: (row: T) => string,
  label: string,
  errors: string[],
): Map<string, T> {
  const result = new Map<string, T>();
  for (const row of rows) {
    const key = keyFor(row);
    if (result.has(key)) {
      errors.push(`Duplicate ${label} ${key}`);
      continue;
    }
    result.set(key, row);
  }
  return result;
}

function auditSnapshotMatchesHistory(
  snapshot: JsonRecord,
  history: ReleaseScoreAuditHistoryEvidenceRow,
  requireEmbeddedRunIdentity: boolean,
): boolean {
  return (!requireEmbeddedRunIdentity ||
      snapshot.run_id === history.run_id &&
      snapshot.recorded_at === history.recorded_at) &&
    (snapshot.run_id === undefined || snapshot.run_id === history.run_id) &&
    (snapshot.recorded_at === undefined || snapshot.recorded_at === history.recorded_at) &&
    snapshot.release_tag === history.release_tag &&
    snapshot.scored_at === history.scored_at &&
    snapshot.score_model_version === history.score_model_version &&
    snapshot.prompt_version === history.prompt_version &&
    snapshot.final_score === history.final_score &&
    snapshot.status === history.status &&
    snapshot.band === history.band &&
    snapshot.recommended === history.recommended &&
    snapshot.input_json === history.input_json &&
    snapshot.components_json === history.components_json &&
    snapshot.issue_evidence_json === history.issue_evidence_json &&
    snapshot.gate_evidence_json === history.gate_evidence_json &&
    snapshot.source_identity_json === history.source_identity_json &&
    snapshot.authority_run_id === history.authority_run_id;
}

function scoreAuditHistoryReplayProblems(
  history: ReleaseScoreAuditHistoryEvidenceRow,
): string[] {
  if (!Number.isFinite(Date.parse(history.scored_at))) {
    return ['has an invalid persisted scored_at'];
  }
  const components = parseRecord(history.components_json);
  const explanation = asRecord(components?.explanation);
  const ledger = asRecord(explanation?.scoreLedger);
  if (!ledger) return [];
  const input = parseRecord(history.input_json);
  if (!input) return ['has a ScoreLedgerV2 but malformed score input'];
  return scoreLedgerV2Problems(ledger, {
    input: input as unknown as InstallInput,
    scoredAt: history.scored_at,
  });
}

export function buildReleaseValidationForecastSnapshot(
  forecasts: ReleaseValidationForecastLedgerRow[],
  generatedAt = new Date().toISOString(),
): JsonRecord {
  return {
    schemaVersion: 3,
    generatedAt,
    source: 'release_validation_forecasts',
    forecastCount: forecasts.length,
    evaluableForecastCount: forecasts.filter(releaseValidationForecastIsEvaluable).length,
    validTimingCount: forecasts.filter((forecast) =>
      releaseValidationDecisionSchemaVersion(forecast) === 4 &&
      releaseValidationForecastTiming(forecast).valid).length,
    excludedLegacyDecisionSchemaCount: forecasts.filter((forecast) =>
      releaseValidationDecisionSchemaVersion(forecast) !== 4).length,
    excludedLegacyLateTimingCount: forecasts.filter((forecast) =>
      !releaseValidationForecastTiming(forecast).valid &&
      Number(parseRecord(forecast.decision_json)?.schemaVersion ?? 2) < 3).length,
    forecasts: forecasts.map((forecast) => ({
      ...forecast,
      opportunityTiming: releaseValidationForecastTiming(forecast),
    })),
  };
}

export function wilsonInterval(successes: number, total: number): {
  estimate: number;
  lower: number;
  upper: number;
  confidence: 0.95;
  method: 'wilson';
} | null {
  if (!Number.isInteger(successes) || !Number.isInteger(total) || total <= 0 ||
    successes < 0 || successes > total) {
    return null;
  }
  const p = successes / total;
  const z2 = WILSON_Z_95 ** 2;
  const denominator = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denominator;
  const margin = WILSON_Z_95 *
    Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total) /
    denominator;
  return {
    estimate: round(p),
    lower: round(Math.max(0, center - margin)),
    upper: round(Math.min(1, center + margin)),
    confidence: 0.95,
    method: 'wilson',
  };
}

function qualifyPostHorizonEvidence(
  input: ObservationAssessmentInput,
  targetReleaseTag: string,
  horizonEndMs: number,
  observationNowMs: number,
): CommonObservationEvidence | { reason: string; fatal: boolean; details?: unknown } {
  const forecastSource = parseRecord(input.forecast.source_identity_json);
  const currentSource = asRecord(input.currentSourceIdentity);
  const forecastDigest = stringField(forecastSource, 'digest');
  const currentDigest = stringField(currentSource, 'digest');
  if (!forecastDigest || !currentDigest) {
    return { reason: 'source_identity_missing_digest', fatal: true };
  }
  if (forecastDigest === currentDigest) {
    return { reason: 'no_new_source_snapshot_after_forecast', fatal: false };
  }

  const scorePersistence = asRecord(input.scorePersistence);
  const persistedAt = timestampField(scorePersistence, 'persistedAt');
  if (!persistedAt || Date.parse(persistedAt) < horizonEndMs ||
    Date.parse(persistedAt) > observationNowMs) {
    return { reason: 'post_horizon_score_persistence_missing', fatal: false };
  }
  if (stringField(scorePersistence, 'sourceIdentityDigest') !== currentDigest) {
    return { reason: 'score_persistence_source_identity_mismatch', fatal: true };
  }
  const releaseTags = stringArray(scorePersistence?.releaseTags);
  if (!releaseTags.includes(targetReleaseTag)) {
    return { reason: 'target_release_missing_from_post_horizon_score_run', fatal: false };
  }

  const issueCrawl = asRecord(input.issueCrawl);
  const crawlFinishedAt = timestampField(issueCrawl, 'finishedAt');
  const crawlScorePersistedAt = timestampField(issueCrawl, 'scorePersistedAt');
  if (!crawlFinishedAt || Date.parse(crawlFinishedAt) < horizonEndMs ||
    Date.parse(crawlFinishedAt) > observationNowMs ||
    !crawlScorePersistedAt || Date.parse(crawlScorePersistedAt) < horizonEndMs ||
    Date.parse(crawlScorePersistedAt) > observationNowMs) {
    return { reason: 'post_horizon_issue_crawl_missing', fatal: false };
  }
  if (issueCrawl?.scorePersisted !== true) {
    return { reason: 'post_horizon_issue_crawl_not_scored', fatal: false };
  }
  if (!['early_stop', 'exhausted'].includes(String(issueCrawl?.stopReason ?? ''))) {
    return { reason: 'post_horizon_issue_crawl_incomplete', fatal: false, details: issueCrawl?.stopReason };
  }
  if (issueCrawl?.backfillCompleteAfterRun !== true ||
    Number(issueCrawl?.commenterScanTruncatedCount ?? 0) !== 0 ||
    !Array.isArray(issueCrawl?.classificationFailures) ||
    issueCrawl.classificationFailures.length !== 0 ||
    !Array.isArray(issueCrawl?.evidenceRefreshFailures) ||
    issueCrawl.evidenceRefreshFailures.length !== 0) {
    return { reason: 'post_horizon_issue_evidence_incomplete', fatal: false };
  }
  if (timestampField(scorePersistence, 'issueCrawlFinishedAt') !== crawlFinishedAt) {
    return { reason: 'score_run_issue_crawl_provenance_mismatch', fatal: true };
  }
  if (crawlScorePersistedAt !== persistedAt ||
    timestampField(scorePersistence, 'issueCrawlScorePersistedAt') !== persistedAt) {
    return { reason: 'score_run_issue_crawl_persistence_mismatch', fatal: true };
  }

  const matchingAudits = input.auditHistory
    .filter((audit) => audit.release_tag === targetReleaseTag)
    .filter((audit) => audit.recorded_at === persistedAt)
    .filter((audit) => Date.parse(audit.scored_at) >= horizonEndMs &&
      Date.parse(audit.scored_at) <= observationNowMs)
    .filter((audit) => stringField(parseRecord(audit.source_identity_json), 'digest') === currentDigest);
  if (matchingAudits.length === 0) {
    return { reason: 'matching_post_horizon_audit_history_missing', fatal: false };
  }
  if (matchingAudits.length > 1) {
    return { reason: 'matching_post_horizon_audit_history_ambiguous', fatal: true };
  }
  const audit = matchingAudits[0];
  if (scorePersistence?.scoreModelVersion !== audit.score_model_version ||
    Number(scorePersistence?.promptVersion) !== audit.prompt_version) {
    return { reason: 'score_persistence_audit_version_mismatch', fatal: true };
  }
  const auditInput = parseRecord(audit.input_json);
  const auditComponents = parseRecord(audit.components_json);
  const auditIssueEvidence = parseRecord(audit.issue_evidence_json);
  const auditGateEvidence = parseRecord(audit.gate_evidence_json);
  if (!auditInput || !auditComponents || !auditIssueEvidence || !auditGateEvidence) {
    return { reason: 'post_horizon_audit_payload_malformed', fatal: true };
  }
  const rawIssueCount = nonnegativeInteger(auditInput.rawIssueCount);
  const classifiedIssueCount = nonnegativeInteger(auditInput.classifiedIssueCount);
  if (rawIssueCount == null || classifiedIssueCount == null ||
    rawIssueCount !== classifiedIssueCount) {
    return { reason: 'post_horizon_classification_coverage_incomplete', fatal: false };
  }
  if (!Array.isArray(auditIssueEvidence.unclassifiedIssues)) {
    return { reason: 'post_horizon_audit_payload_malformed', fatal: true };
  }
  if (auditIssueEvidence.unclassifiedIssues.length !== 0) {
    return { reason: 'post_horizon_unclassified_issue_evidence_present', fatal: false };
  }
  return {
    audit,
    auditInput,
    auditComponents,
    auditIssueEvidence,
    auditGateEvidence,
    sourceIdentity: currentSource!,
    sourceIdentityDigest: currentDigest,
  };
}

export function buildIndependentFieldEvidenceSnapshot(
  input: IndependentFieldEvidenceBuildInput,
): IndependentFieldEvidenceSnapshot {
  const targetReleaseTag =
    input.targetReleaseTag ?? validationTargetReleaseTag(input.forecast);
  const windowStartMs = Date.parse(input.forecast.recorded_at);
  const windowEndMs = Date.parse(input.horizonEndAt);
  const capturedAtMs = Date.parse(input.capturedAt);
  if (!Number.isFinite(windowStartMs) || !Number.isFinite(windowEndMs) ||
    !Number.isFinite(capturedAtMs) || capturedAtMs < windowEndMs) {
    throw new Error('Independent field evidence has invalid or pre-horizon timestamps');
  }

  const snapshotByIssue = uniqueRowsByIntegerKey(input.commentSnapshots, 'issue_number');
  const labelEventsByIssue = groupRowsByIntegerKey(input.labelEvents, 'issue_number');
  const closureProofsByIssue = groupRowsByIntegerKey(input.closureProofs, 'issue_number');
  const issues = input.issues
    .filter((row) => {
      const createdAtMs = Date.parse(String(row.created_at ?? ''));
      return Number.isFinite(createdAtMs) &&
        createdAtMs > windowStartMs &&
        createdAtMs <= windowEndMs;
    })
    .sort((left, right) =>
      Date.parse(String(left.created_at)) - Date.parse(String(right.created_at)) ||
      Number(left.number) - Number(right.number));
  const seenIssueNumbers = new Set<number>();
  const incompleteIssueNumbers: number[] = [];
  const mutableIssueContentNumbers: number[] = [];
  const evidenceRefs: IndependentFieldAdverseEvidence[] = [];
  const issueUniverse: IndependentFieldIssueUniverseEntry[] = [];
  let completeCommentSnapshotCount = 0;

  for (const issue of issues) {
    const issueNumber = Number(issue.number);
    const issueUrl = String(issue.html_url ?? '').trim();
    const createdAt = String(issue.created_at ?? '');
    const state = String(issue.state ?? '');
    const issueUpdatedAt = String(issue.updated_at ?? '');
    const issueUpdatedAtMs = Date.parse(issueUpdatedAt);
    const issueContentFrozenAtHorizon =
      Number.isFinite(issueUpdatedAtMs) && issueUpdatedAtMs <= windowEndMs;
    if (!Number.isInteger(issueNumber) || issueNumber <= 0 ||
      seenIssueNumbers.has(issueNumber) || !issueUrl ||
      !Number.isFinite(Date.parse(createdAt)) || !state ||
      !Number.isFinite(issueUpdatedAtMs)) {
      if (Number.isInteger(issueNumber) && issueNumber > 0) {
        incompleteIssueNumbers.push(issueNumber);
      }
      continue;
    }
    seenIssueNumbers.add(issueNumber);

    const snapshot = snapshotByIssue.get(issueNumber);
    const comments = completeIndependentComments(issue, snapshot);
    const labelEvents = labelEventsByIssue.get(issueNumber) ?? [];
    const closureProofs = closureProofsByIssue.get(issueNumber) ?? [];
    const issueEvidenceIdentity = independentEvidenceIdentity(
      'release-validation-field-issue-v2',
      {
        number: issueNumber,
        state,
        title: issueContentFrozenAtHorizon ? String(issue.title ?? '') : null,
        body: issueContentFrozenAtHorizon ? String(issue.body ?? '') : null,
        author: nullableString(issue.author),
        htmlUrl: issueUrl,
        createdAt,
        updatedAt: issueUpdatedAt,
        issueContentFrozenAtHorizon,
        comments: Number(issue.comments),
      },
    );
    const commentSnapshotEvidenceIdentity = comments && snapshot
      ? independentEvidenceIdentity(
          'release-validation-field-comment-snapshot-v1',
          {
            issueNumber,
            schemaVersion: Number(snapshot.schema_version),
            verifiedAt: String(snapshot.verified_at ?? ''),
            commentCount: Number(snapshot.comment_count),
            fetchedCommentCount: Number(snapshot.fetched_comment_count),
            latestCommentUpdatedAt: nullableString(snapshot.latest_comment_updated_at),
            commentsDigest: String(snapshot.comments_digest ?? ''),
            issueUpdatedAt: String(snapshot.issue_updated_at ?? ''),
          },
        )
      : null;
    const commentsThroughHorizon = comments
      ? comments.filter((comment) => evidenceRowAtOrBefore(comment, windowEndMs))
      : [];
    const commentEvidenceIdentities = commentsThroughHorizon
      .map((comment) => ({
        commentId: Number(comment.id),
        evidenceIdentity: independentEvidenceIdentity(
          'release-validation-field-comment-v1',
          comment,
        ),
      }))
      .filter((item) => Number.isInteger(item.commentId) && item.commentId > 0)
      .sort((left, right) => left.commentId - right.commentId);
    const labelEventEvidenceIdentities = labelEvents
      .filter((event) => {
        const occurredAtMs = Date.parse(String(event.created_at ?? ''));
        return Number.isFinite(occurredAtMs) &&
          occurredAtMs > windowStartMs &&
          occurredAtMs <= windowEndMs;
      })
      .map((event) => ({
        eventId: String(event.event_id ?? ''),
        evidenceIdentity: independentEvidenceIdentity(
          'release-validation-field-label-event-v1',
          event,
        ),
      }))
      .filter((item) => item.eventId)
      .sort((left, right) => left.eventId.localeCompare(right.eventId));
    const closureProofEvidenceIdentities = closureProofs
      .filter((proof) => {
        const publishedAtMs = Date.parse(String(proof.release_published_at ?? ''));
        return Number.isFinite(publishedAtMs) &&
          publishedAtMs > windowStartMs &&
          publishedAtMs <= windowEndMs;
      })
      .map((proof) => ({
        releaseTag: String(proof.release_tag ?? ''),
        proofStatus: String(proof.status ?? ''),
        evidenceIdentity: independentEvidenceIdentity(
          'release-validation-field-closure-proof-v1',
          proof,
        ),
      }))
      .filter((item) => item.releaseTag && item.proofStatus)
      .sort((left, right) =>
        left.releaseTag.localeCompare(right.releaseTag) ||
        left.proofStatus.localeCompare(right.proofStatus) ||
        left.evidenceIdentity.localeCompare(right.evidenceIdentity));
    let adverseEvidenceIdentity: string | null = null;
    if (!comments) {
      incompleteIssueNumbers.push(issueNumber);
    } else {
      completeCommentSnapshotCount++;
      if (!issueContentFrozenAtHorizon) {
        mutableIssueContentNumbers.push(issueNumber);
        incompleteIssueNumbers.push(issueNumber);
      }
      const versionLink = independentExactVersionLink(
        issueContentFrozenAtHorizon
          ? issue
          : { ...issue, title: '', body: '' },
        commentsThroughHorizon,
        targetReleaseTag,
        issueUrl,
      );
      if (versionLink) {
        const confirmations = independentHumanConfirmations(
          issue,
          commentsThroughHorizon,
          labelEvents,
          issueUrl,
          windowStartMs,
          windowEndMs,
        );
        const laterFixes = independentTrustedLaterFixes(
          closureProofs,
          windowStartMs,
          windowEndMs,
        );
        if (confirmations.length > 0 || laterFixes.length > 0) {
          const evidence = {
            sourceClass: confirmations.length > 0 && laterFixes.length > 0
              ? 'exact_version_human_confirmation_and_trusted_later_fix' as const
              : confirmations.length > 0
                ? 'exact_version_human_confirmation' as const
                : 'exact_version_trusted_later_fix' as const,
            issueNumber,
            issueUrl,
            createdAt,
            state,
            versionLink,
            confirmations,
            laterFixes,
          };
          adverseEvidenceIdentity = independentFieldAdverseEvidenceIdentity(evidence);
          evidenceRefs.push({
            evidenceIdentity: adverseEvidenceIdentity,
            ...evidence,
          });
        }
      }
    }
    const universeEntryWithoutIdentity = {
      issueNumber,
      issueUrl,
      createdAt,
      state,
      issueUpdatedAt,
      issueContentFrozenAtHorizon,
      issueEvidenceIdentity,
      commentSnapshotEvidenceIdentity,
      commentEvidenceIdentities,
      labelEventEvidenceIdentities,
      closureProofEvidenceIdentities,
      adverseEvidenceIdentity,
    };
    issueUniverse.push({
      ...universeEntryWithoutIdentity,
      evidenceIdentity: independentFieldIssueUniverseEntryIdentity(
        universeEntryWithoutIdentity,
      ),
    });
  }

  const snapshot = {
    schemaVersion: 3 as const,
    capturedAt: input.capturedAt,
    targetReleaseTag,
    windowStartAt: input.forecast.recorded_at,
    windowEndAt: input.horizonEndAt,
    complete: incompleteIssueNumbers.length === 0 &&
      seenIssueNumbers.size === issues.length,
    issueUniverseCount: issues.length,
    completeCommentSnapshotCount,
    incompleteIssueNumbers: [...new Set(incompleteIssueNumbers)].sort((a, b) => a - b),
    mutableIssueContentNumbers:
      [...new Set(mutableIssueContentNumbers)].sort((a, b) => a - b),
    issueUniverse: issueUniverse.sort((left, right) =>
      Date.parse(left.createdAt) - Date.parse(right.createdAt) ||
      left.issueNumber - right.issueNumber),
    evidenceRefs: evidenceRefs.sort((left, right) =>
      Date.parse(left.createdAt) - Date.parse(right.createdAt) ||
      left.issueNumber - right.issueNumber),
  };
  return {
    ...snapshot,
    contentHash: independentFieldEvidenceContentHash(snapshot),
  };
}

export function independentFieldAdverseEvidenceIdentity(
  evidence: Omit<IndependentFieldAdverseEvidence, 'evidenceIdentity'>,
): string {
  return independentEvidenceIdentity(
    'release-validation-field-adverse-evidence-v1',
    evidence,
  );
}

export function independentFieldIssueUniverseEntryIdentity(
  entry: Omit<IndependentFieldIssueUniverseEntry, 'evidenceIdentity'>,
): string {
  return independentEvidenceIdentity(
    'release-validation-field-issue-universe-v1',
    entry,
  );
}

export function independentFieldEvidenceContentHash(
  snapshot: Omit<IndependentFieldEvidenceSnapshot, 'contentHash'>,
): string {
  return independentEvidenceIdentity(
    snapshot.schemaVersion === 3
      ? 'release-validation-field-snapshot-v3'
      : 'release-validation-field-snapshot-v2',
    snapshot,
  );
}

function independentEvidenceIdentity(domain: string, value: unknown): string {
  return createHash('sha256')
    .update(`${domain}\0${JSON.stringify(canonicalJson(value))}`)
    .digest('hex');
}

function deriveFieldRegressionOutcome(
  forecast: ReleaseValidationForecastLedgerRow,
  targetReleaseTag: string,
  common: CommonObservationEvidence,
  horizonEndMs: number,
  independentEvidence: IndependentFieldEvidenceSnapshot | null,
): {
  adverse: boolean;
  payload: Pick<ReleaseValidationOutcomePayload, 'fieldRegression'>;
} | { reason: string; fatal: boolean; details?: unknown } {
  if (!independentEvidence) {
    return { reason: 'independent_field_evidence_missing', fatal: false };
  }
  const expectedWindowEndAt = new Date(horizonEndMs).toISOString();
  const capturedAtMs = Date.parse(independentEvidence.capturedAt);
  if (
    independentEvidence.schemaVersion !== 3 ||
    independentEvidence.targetReleaseTag !== targetReleaseTag ||
    independentEvidence.windowStartAt !== forecast.recorded_at ||
    independentEvidence.windowEndAt !== expectedWindowEndAt ||
    !Number.isFinite(capturedAtMs) ||
    capturedAtMs < horizonEndMs ||
    independentEvidence.capturedAt !== common.audit.recorded_at
  ) {
    return {
      reason: 'independent_field_evidence_provenance_mismatch',
      fatal: true,
    };
  }
  if (!independentEvidence.complete ||
    independentEvidence.incompleteIssueNumbers.length > 0 ||
    independentEvidence.mutableIssueContentNumbers?.length !== 0 ||
    independentEvidence.completeCommentSnapshotCount !==
      independentEvidence.issueUniverseCount ||
    independentEvidence.issueUniverse?.length !==
      independentEvidence.issueUniverseCount) {
    return {
      reason: 'independent_field_evidence_incomplete',
      fatal: false,
      details: {
        issueUniverseCount: independentEvidence.issueUniverseCount,
        completeCommentSnapshotCount: independentEvidence.completeCommentSnapshotCount,
        incompleteIssueNumbers: independentEvidence.incompleteIssueNumbers,
        mutableIssueContentNumbers:
          independentEvidence.mutableIssueContentNumbers ?? null,
      },
    };
  }
  const snapshotError = independentFieldEvidenceSnapshotShapeError(
    independentEvidence,
    targetReleaseTag,
    Date.parse(forecast.recorded_at),
    horizonEndMs,
  );
  if (snapshotError) {
    return {
      reason: 'independent_field_evidence_malformed',
      fatal: true,
      details: snapshotError,
    };
  }
  const evidenceError = independentFieldEvidenceShapeError(
    independentEvidence.evidenceRefs,
    targetReleaseTag,
    Date.parse(forecast.recorded_at),
    horizonEndMs,
  );
  if (evidenceError) {
    return {
      reason: 'independent_field_evidence_malformed',
      fatal: true,
      details: evidenceError,
    };
  }
  const classifierProxy = classifierFieldOutcomeProxy(common.auditIssueEvidence);
  return {
    adverse: independentEvidence.evidenceRefs.length > 0,
    payload: {
      fieldRegression: {
        outcomeSourceClass: 'independent_raw_evidence',
        observedClass: independentEvidence.evidenceRefs.length > 0
          ? 'observed-adverse'
          : 'observed-safe',
        evidenceScope: 'complete_exact_version_post_forecast_crawl',
        evidenceCompleteness: {
          capturedAt: independentEvidence.capturedAt,
          issueUniverseCount: independentEvidence.issueUniverseCount,
          completeCommentSnapshotCount:
            independentEvidence.completeCommentSnapshotCount,
          incompleteIssueNumbers: [],
        },
        issueCount: independentEvidence.evidenceRefs.length,
        clusterCount: independentEvidence.evidenceRefs.length,
        evidenceRefs: independentEvidence.evidenceRefs,
        evidenceSnapshot: independentEvidence,
        classifierProxy,
      },
    },
  };
}

const INDEPENDENT_RELEASE_TOKEN_RE =
  /(^|[^0-9A-Za-z])((?:[vV]\d+(?:\.\d+)*|\d+(?:\.\d+)+)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)(?=$|[^0-9A-Za-z])/g;
const INDEPENDENT_HUMAN_CONFIRMATION_RE =
  /\b(?:i\s+can\s+confirm|can\s+confirm|same\s+(?:issue|problem|here)|me\s+too|i\s+(?:also\s+)?reproduced|i\s+(?:can\s+)?reproduce|reproduced\s+(?:this|it)|confirmed\s+on)\b/i;
const INDEPENDENT_NEGATED_CONFIRMATION_RE =
  /\b(?:cannot|can't|could\s+not|couldn't|did\s+not|didn't|unable\s+to|not\s+able\s+to)\s+(?:confirm|reproduce)\b|\bnot\s+reproducible\b/i;
const INDEPENDENT_BOT_LOGIN_RE =
  /\[bot\]$|^(github-actions|dependabot|renovate(?:-bot)?|mergify|stale|clawsweeper|barnacle)$/i;
const INDEPENDENT_ADVERSE_LABELS = new Set(['p0', 'p1', 'regression']);

function uniqueRowsByIntegerKey(
  rows: Array<Record<string, unknown>>,
  key: string,
): Map<number, Record<string, unknown>> {
  const result = new Map<number, Record<string, unknown>>();
  for (const row of rows) {
    const value = Number(row[key]);
    if (!Number.isInteger(value) || value <= 0 || result.has(value)) continue;
    result.set(value, row);
  }
  return result;
}

function groupRowsByIntegerKey(
  rows: Array<Record<string, unknown>>,
  key: string,
): Map<number, Array<Record<string, unknown>>> {
  const result = new Map<number, Array<Record<string, unknown>>>();
  for (const row of rows) {
    const value = Number(row[key]);
    if (!Number.isInteger(value) || value <= 0) continue;
    const group = result.get(value) ?? [];
    group.push(row);
    result.set(value, group);
  }
  return result;
}

function completeIndependentComments(
  issue: Record<string, unknown>,
  snapshot: Record<string, unknown> | undefined,
): CommentEvidenceRow[] | null {
  if (!snapshot) return null;
  const issueNumber = Number(issue.number);
  const issueCommentCount = Number(issue.comments);
  const snapshotCommentCount = Number(snapshot.comment_count);
  const fetchedCommentCount = Number(snapshot.fetched_comment_count);
  const commentsJson = typeof snapshot.comments_json === 'string'
    ? snapshot.comments_json
    : null;
  if (
    Number(snapshot.schema_version) !== 2 ||
    !Number.isInteger(issueCommentCount) ||
    issueCommentCount < 0 ||
    snapshotCommentCount !== issueCommentCount ||
    fetchedCommentCount !== issueCommentCount ||
    snapshot.issue_updated_at !== issue.updated_at ||
    Number(snapshot.issue_number) !== issueNumber ||
    !commentsJson ||
    typeof snapshot.comments_digest !== 'string' ||
    !Number.isFinite(Date.parse(String(snapshot.verified_at ?? '')))
  ) {
    return null;
  }
  try {
    if (
      commentEvidenceDigestFromJson(issueCommentCount, commentsJson) !==
      snapshot.comments_digest
    ) {
      return null;
    }
    const parsed = JSON.parse(commentsJson);
    return Array.isArray(parsed) ? parsed as CommentEvidenceRow[] : null;
  } catch {
    return null;
  }
}

function evidenceRowAtOrBefore(
  row: { created_at?: string | null; updated_at?: string | null },
  cutoffMs: number,
): boolean {
  const createdAtMs = Date.parse(row.created_at ?? '');
  const updatedAtMs = Date.parse(row.updated_at ?? row.created_at ?? '');
  return Number.isFinite(createdAtMs) &&
    Number.isFinite(updatedAtMs) &&
    createdAtMs <= cutoffMs &&
    updatedAtMs <= cutoffMs;
}

function independentExactVersionLink(
  issue: Record<string, unknown>,
  comments: CommentEvidenceRow[],
  releaseTag: string,
  issueUrl: string,
): IndependentVersionLinkEvidence | null {
  const target = normalizeIndependentReleaseToken(releaseTag);
  const title = independentVersionLinkFromText(
    String(issue.title ?? ''),
    target,
    releaseTag,
    'title',
    issueUrl,
    null,
    nullableString(issue.author),
  );
  if (title) return title;
  const body = independentVersionLinkFromText(
    String(issue.body ?? ''),
    target,
    releaseTag,
    'body',
    issueUrl,
    null,
    nullableString(issue.author),
  );
  if (body) return body;
  for (const comment of comments) {
    const commentId = Number(comment.id);
    const commentUrl = String(comment.url ?? '').trim();
    if (!Number.isInteger(commentId) || commentId <= 0 || !commentUrl) continue;
    const evidence = independentVersionLinkFromText(
      String(comment.body ?? ''),
      target,
      releaseTag,
      'comment',
      commentUrl,
      commentId,
      nullableString(comment.user?.login),
    );
    if (evidence) return evidence;
  }
  return null;
}

function independentVersionLinkFromText(
  text: string,
  target: string,
  releaseTag: string,
  source: IndependentVersionLinkEvidence['source'],
  referenceUrl: string,
  commentId: number | null,
  author: string | null,
): IndependentVersionLinkEvidence | null {
  if (!text) return null;
  for (const match of text.matchAll(INDEPENDENT_RELEASE_TOKEN_RE)) {
    if (normalizeIndependentReleaseToken(String(match[2])) !== target) continue;
    const tokenStart = (match.index ?? 0) + String(match[1] ?? '').length;
    const tokenEnd = tokenStart + String(match[2]).length;
    const context = text.slice(
      Math.max(0, tokenStart - 100),
      Math.min(text.length, tokenEnd + 100),
    );
    if (independentReleaseMentionNegated(context, releaseTag)) continue;
    return {
      source,
      version: releaseTag,
      referenceUrl,
      commentId,
      author,
      snippet: independentEvidenceSnippet(context),
    };
  }
  return null;
}

function independentReleaseMentionNegated(context: string, releaseTag: string): boolean {
  const escaped = releaseTag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `(?:unaffected|not\\s+affected|not\\s+broken|not\\s+reproducible|works?|working|fixed|stable)` +
    `.{0,32}${escaped}|${escaped}.{0,32}` +
    `(?:unaffected|not\\s+affected|not\\s+broken|not\\s+reproducible|works?|working|fixed|stable)`,
    'i',
  ).test(context);
}

function independentHumanConfirmations(
  issue: Record<string, unknown>,
  comments: CommentEvidenceRow[],
  labelEvents: Array<Record<string, unknown>>,
  issueUrl: string,
  windowStartMs: number,
  windowEndMs: number,
): IndependentHumanConfirmationEvidence[] {
  const issueAuthor = String(issue.author ?? '').toLowerCase();
  const confirmations: IndependentHumanConfirmationEvidence[] = [];
  const seenActors = new Set<string>();
  for (const comment of comments) {
    const actor = String(comment.user?.login ?? '').trim();
    const normalizedActor = actor.toLowerCase();
    const body = String(comment.body ?? '').trim();
    const occurredAt = String(comment.created_at ?? '');
    const occurredAtMs = Date.parse(occurredAt);
    const commentId = Number(comment.id);
    const referenceUrl = String(comment.url ?? '').trim();
    if (
      !actor ||
      normalizedActor === issueAuthor ||
      INDEPENDENT_BOT_LOGIN_RE.test(actor) ||
      seenActors.has(normalizedActor) ||
      !Number.isInteger(commentId) ||
      commentId <= 0 ||
      !referenceUrl ||
      !Number.isFinite(occurredAtMs) ||
      occurredAtMs <= windowStartMs ||
      occurredAtMs > windowEndMs ||
      INDEPENDENT_NEGATED_CONFIRMATION_RE.test(body) ||
      !INDEPENDENT_HUMAN_CONFIRMATION_RE.test(body)
    ) {
      continue;
    }
    seenActors.add(normalizedActor);
    confirmations.push({
      source: 'comment',
      sourceClass: 'independent_human_reproduction',
      actor,
      occurredAt,
      referenceUrl,
      commentId,
      eventId: null,
      label: null,
      snippet: independentEvidenceSnippet(body),
    });
  }
  for (const event of labelEvents) {
    const action = String(event.action ?? '').toLowerCase();
    const label = String(event.label_name ?? '');
    const actor = String(event.actor_login ?? '').trim();
    const occurredAt = String(event.created_at ?? '');
    const occurredAtMs = Date.parse(occurredAt);
    const eventId = String(event.event_id ?? '').trim();
    if (
      action !== 'labeled' ||
      !INDEPENDENT_ADVERSE_LABELS.has(label.toLowerCase()) ||
      !actor ||
      INDEPENDENT_BOT_LOGIN_RE.test(actor) ||
      !eventId ||
      !Number.isFinite(occurredAtMs) ||
      occurredAtMs <= windowStartMs ||
      occurredAtMs > windowEndMs
    ) {
      continue;
    }
    confirmations.push({
      source: 'label_event',
      sourceClass: 'human_applied_adverse_label',
      actor,
      occurredAt,
      referenceUrl: issueUrl,
      commentId: null,
      eventId,
      label,
      snippet: null,
    });
  }
  return confirmations.sort((left, right) =>
    Date.parse(left.occurredAt) - Date.parse(right.occurredAt) ||
    left.actor.localeCompare(right.actor) ||
    left.source.localeCompare(right.source));
}

function independentTrustedLaterFixes(
  proofRows: Array<Record<string, unknown>>,
  windowStartMs: number,
  windowEndMs: number,
): IndependentLaterFixEvidence[] {
  const refs: IndependentLaterFixEvidence[] = [];
  for (const proofRow of proofRows) {
    if (proofRow.status !== 'fixed_in_release') continue;
    const releasePublishedAt = String(proofRow.release_published_at ?? '');
    const releasePublishedAtMs = Date.parse(releasePublishedAt);
    if (!Number.isFinite(releasePublishedAtMs) ||
      releasePublishedAtMs <= windowStartMs ||
      releasePublishedAtMs > windowEndMs) {
      continue;
    }
    const releaseTag = String(proofRow.release_tag ?? '');
    const evidence = parseRecord(String(proofRow.evidence_json ?? ''));
    if (!releaseTag || !evidence) continue;
    for (const pr of recordArray(evidence.linkedPrs)) {
      const prNumber = Number(pr.number);
      const referenceUrl = String(pr.url ?? pr.sourceCommentUrl ?? '').trim();
      if (
        Number(pr.trustedFixProof) !== 1 ||
        Number(pr.merged) !== 1 ||
        !Number.isInteger(prNumber) ||
        prNumber <= 0 ||
        !referenceUrl
      ) {
        continue;
      }
      refs.push({
        source: 'trusted_pull_request',
        releaseTag,
        releasePublishedAt,
        proofStatus: String(proofRow.status),
        referenceUrl,
        prNumber,
        commitOid: nullableString(pr.mergeCommitOid),
      });
    }
    for (const commit of recordArray(evidence.directFixCommitProof)) {
      const commitOid = String(commit.commitOid ?? '').trim();
      const referenceUrl = String(
        commit.sourceCommentUrl ?? proofRow.release_url ?? '',
      ).trim();
      if (
        commit.status !== 'reachable' ||
        commit.trustedSource !== true ||
        !/^[0-9a-f]{7,40}$/i.test(commitOid) ||
        !referenceUrl
      ) {
        continue;
      }
      refs.push({
        source: 'reachable_fix_commit',
        releaseTag,
        releasePublishedAt,
        proofStatus: String(proofRow.status),
        referenceUrl,
        prNumber: null,
        commitOid,
      });
    }
  }
  const seen = new Set<string>();
  return refs
    .filter((ref) => {
      const key = JSON.stringify([
        ref.source,
        ref.releaseTag,
        ref.prNumber,
        ref.commitOid,
        ref.referenceUrl,
      ]);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((left, right) =>
      Date.parse(left.releasePublishedAt) - Date.parse(right.releasePublishedAt) ||
      left.releaseTag.localeCompare(right.releaseTag) ||
      left.referenceUrl.localeCompare(right.referenceUrl));
}

function classifierFieldOutcomeProxy(
  issueEvidence: JsonRecord,
): ClassifierFieldOutcomeProxy {
  const counts = asRecord(issueEvidence.evidenceCounts);
  const opened = nonnegativeInteger(counts?.openedFeltSerious);
  const verified = nonnegativeInteger(counts?.verifiedDebt);
  if (opened == null || verified == null) {
    return {
      sourceClass: 'classifier_score_bucket_proxy',
      validationEligible: false,
      adverse: null,
      issueCount: null,
      reason: 'classifier_proxy_counts_missing_or_malformed',
    };
  }
  return {
    sourceClass: 'classifier_score_bucket_proxy',
    validationEligible: false,
    adverse: opened + verified > 0,
    issueCount: opened + verified,
    reason: null,
  };
}

function independentFieldEvidenceShapeError(
  refs: IndependentFieldAdverseEvidence[],
  targetReleaseTag: string,
  windowStartMs: number,
  windowEndMs: number,
): string | null {
  const issueNumbers = new Set<number>();
  for (const ref of refs) {
    const versionLink = asRecord((ref as unknown as JsonRecord).versionLink);
    const confirmations = Array.isArray((ref as unknown as JsonRecord).confirmations)
      ? (ref as unknown as JsonRecord).confirmations as IndependentHumanConfirmationEvidence[]
      : null;
    const laterFixes = Array.isArray((ref as unknown as JsonRecord).laterFixes)
      ? (ref as unknown as JsonRecord).laterFixes as IndependentLaterFixEvidence[]
      : null;
    if (
      !Number.isInteger(ref.issueNumber) ||
      ref.issueNumber <= 0 ||
      issueNumbers.has(ref.issueNumber) ||
      !ref.issueUrl ||
      !Number.isFinite(Date.parse(ref.createdAt)) ||
      Date.parse(ref.createdAt) <= windowStartMs ||
      Date.parse(ref.createdAt) > windowEndMs ||
      !ref.state ||
      !versionLink ||
      versionLink.version !== targetReleaseTag ||
      !stringField(versionLink, 'referenceUrl') ||
      !stringField(versionLink, 'snippet') ||
      !confirmations ||
      !laterFixes ||
      confirmations.length + laterFixes.length === 0
    ) {
      return `invalid evidence ref for issue ${ref.issueNumber}`;
    }
    issueNumbers.add(ref.issueNumber);
    if (confirmations.some((confirmation) =>
      !confirmation.actor ||
      INDEPENDENT_BOT_LOGIN_RE.test(confirmation.actor) ||
      !confirmation.referenceUrl ||
      !Number.isFinite(Date.parse(confirmation.occurredAt)) ||
      Date.parse(confirmation.occurredAt) <= windowStartMs ||
      Date.parse(confirmation.occurredAt) > windowEndMs)) {
      return `invalid confirmation evidence for issue ${ref.issueNumber}`;
    }
    if (laterFixes.some((fix) =>
      !fix.releaseTag ||
      !fix.referenceUrl ||
      !Number.isFinite(Date.parse(fix.releasePublishedAt)) ||
      Date.parse(fix.releasePublishedAt) <= windowStartMs ||
      Date.parse(fix.releasePublishedAt) > windowEndMs)) {
      return `invalid later-fix evidence for issue ${ref.issueNumber}`;
    }
  }
  return null;
}

function independentFieldEvidenceSnapshotShapeError(
  snapshot: IndependentFieldEvidenceSnapshot,
  targetReleaseTag: string,
  windowStartMs: number,
  windowEndMs: number,
): string | null {
  if (snapshot.schemaVersion !== 3 ||
    !isSha256Hex(snapshot.contentHash) ||
    !Array.isArray(snapshot.mutableIssueContentNumbers) ||
    !Array.isArray(snapshot.issueUniverse) ||
    snapshot.issueUniverse.length !== snapshot.issueUniverseCount) {
    return 'field evidence snapshot header or issue universe is invalid';
  }
  const {
    contentHash: _contentHash,
    ...snapshotWithoutHash
  } = snapshot;
  if (independentFieldEvidenceContentHash(snapshotWithoutHash) !== snapshot.contentHash) {
    return 'field evidence snapshot content hash mismatch';
  }
  const refsByIssue = new Map<number, IndependentFieldAdverseEvidence>();
  for (const ref of snapshot.evidenceRefs) {
    if (!isSha256Hex(ref.evidenceIdentity)) {
      return `invalid adverse evidence identity for issue ${ref.issueNumber}`;
    }
    const {
      evidenceIdentity,
      ...evidenceWithoutIdentity
    } = ref;
    if (independentFieldAdverseEvidenceIdentity(evidenceWithoutIdentity) !==
      evidenceIdentity) {
      return `adverse evidence identity mismatch for issue ${ref.issueNumber}`;
    }
    refsByIssue.set(ref.issueNumber, ref);
  }
  const seenIssues = new Set<number>();
  for (const entry of snapshot.issueUniverse) {
    if (!Number.isInteger(entry.issueNumber) ||
      entry.issueNumber <= 0 ||
      seenIssues.has(entry.issueNumber) ||
      !entry.issueUrl ||
      !Number.isFinite(Date.parse(entry.createdAt)) ||
      Date.parse(entry.createdAt) <= windowStartMs ||
      Date.parse(entry.createdAt) > windowEndMs ||
      !entry.state ||
      !Number.isFinite(Date.parse(entry.issueUpdatedAt ?? '')) ||
      entry.issueContentFrozenAtHorizon !== true ||
      Date.parse(entry.issueUpdatedAt ?? '') > windowEndMs ||
      !isSha256Hex(entry.issueEvidenceIdentity) ||
      entry.commentSnapshotEvidenceIdentity != null &&
        !isSha256Hex(entry.commentSnapshotEvidenceIdentity) ||
      !Array.isArray(entry.commentEvidenceIdentities) ||
      entry.commentEvidenceIdentities.some((item) =>
        !Number.isInteger(item.commentId) ||
        item.commentId <= 0 ||
        !isSha256Hex(item.evidenceIdentity)) ||
      !Array.isArray(entry.labelEventEvidenceIdentities) ||
      entry.labelEventEvidenceIdentities.some((item) =>
        !item.eventId || !isSha256Hex(item.evidenceIdentity)) ||
      !Array.isArray(entry.closureProofEvidenceIdentities) ||
      entry.closureProofEvidenceIdentities.some((item) =>
        !item.releaseTag ||
        !item.proofStatus ||
        !isSha256Hex(item.evidenceIdentity)) ||
      entry.adverseEvidenceIdentity != null &&
        !isSha256Hex(entry.adverseEvidenceIdentity) ||
      !isSha256Hex(entry.evidenceIdentity)) {
      return `invalid issue-universe entry for issue ${entry.issueNumber}`;
    }
    const {
      evidenceIdentity,
      ...entryWithoutIdentity
    } = entry;
    if (independentFieldIssueUniverseEntryIdentity(entryWithoutIdentity) !==
      evidenceIdentity) {
      return `issue-universe evidence identity mismatch for issue ${entry.issueNumber}`;
    }
    const ref = refsByIssue.get(entry.issueNumber);
    if ((ref?.evidenceIdentity ?? null) !== entry.adverseEvidenceIdentity) {
      return `issue-universe adverse evidence mismatch for issue ${entry.issueNumber}`;
    }
    seenIssues.add(entry.issueNumber);
  }
  if (refsByIssue.size !== snapshot.evidenceRefs.length ||
    [...refsByIssue.keys()].some((issueNumber) => !seenIssues.has(issueNumber)) ||
    snapshot.targetReleaseTag !== targetReleaseTag) {
    return 'field evidence refs do not exactly match the issue universe';
  }
  return null;
}

function normalizeIndependentReleaseToken(value: string): string {
  return value.trim().replace(/^v/i, '').toLowerCase();
}

function independentEvidenceSnippet(value: string, maxLength = 240): string {
  const compact = value.replace(/\s+/g, ' ').trim();
  return compact.length <= maxLength
    ? compact
    : `${compact.slice(0, maxLength - 3).trimEnd()}...`;
}

function deriveSecurityOutcome(
  forecast: ReleaseValidationForecastLedgerRow,
  targetReleaseTag: string,
  common: CommonObservationEvidence,
  snapshots: AdvisorySnapshotValidationEvidence[],
  horizonEndMs: number,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage = DEFAULT_EXPECTED_ADVISORY_PACKAGE,
): {
  adverse: boolean;
  payload: Pick<ReleaseValidationOutcomePayload, 'security'>;
} | { reason: string; fatal: boolean; details?: unknown } {
  const auditRecordedMs = Date.parse(common.audit.recorded_at);
  const selection = prospectiveAdvisorySnapshot(
    snapshots,
    horizonEndMs,
    auditRecordedMs,
    2,
  );
  if ('reason' in selection) return selection;
  return securityOutcomeFromSnapshot(
    forecast,
    targetReleaseTag,
    selection.snapshot,
    horizonEndMs,
    expectedAdvisoryPackage,
  );
}

function prospectiveAdvisorySnapshot(
  snapshots: AdvisorySnapshotValidationEvidence[],
  horizonEndMs: number,
  observedAtMs: number,
  requiredSchemaVersion: number,
): {
  snapshot: AdvisorySnapshotValidationEvidence;
} | {
  reason: string;
  fatal: boolean;
  details?: unknown;
} {
  const eligible = snapshots
    .map((snapshot) => ({
      snapshot,
      capturedAtMs: Date.parse(snapshot.capturedAt),
    }))
    .filter((item) =>
      advisorySnapshotSchemaVersion(item.snapshot) === requiredSchemaVersion &&
      Number.isFinite(item.capturedAtMs) &&
      item.capturedAtMs >= horizonEndMs &&
      item.capturedAtMs <= observedAtMs)
    .sort((left, right) =>
      left.capturedAtMs - right.capturedAtMs ||
      left.snapshot.snapshotId - right.snapshot.snapshotId);
  const first = eligible[0];
  if (!first) {
    return { reason: 'post_horizon_advisory_snapshot_missing', fatal: false };
  }
  const simultaneous = eligible.filter((item) =>
    item.capturedAtMs === first.capturedAtMs);
  if (simultaneous.length !== 1) {
    return {
      reason: 'post_horizon_advisory_snapshot_ambiguous',
      fatal: true,
      details: {
        capturedAt: first.snapshot.capturedAt,
        snapshotIds: simultaneous.map((item) => item.snapshot.snapshotId),
        contentHashes: simultaneous.map((item) => item.snapshot.contentHash),
      },
    };
  }
  return { snapshot: first.snapshot };
}

function securityOutcomeFromSnapshot(
  forecast: ReleaseValidationForecastLedgerRow,
  targetReleaseTag: string,
  snapshot: AdvisorySnapshotValidationEvidence,
  horizonEndMs: number,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage = DEFAULT_EXPECTED_ADVISORY_PACKAGE,
): {
  adverse: boolean;
  payload: Pick<ReleaseValidationOutcomePayload, 'security'>;
} | { reason: string; fatal: boolean; details?: unknown } {
  const snapshotError = advisorySnapshotError(snapshot, expectedAdvisoryPackage);
  if (snapshotError) return snapshotError;
  const startMs = Date.parse(forecast.recorded_at);
  const affected: SecurityAdvisoryEvidence[] = [];
  for (const advisory of snapshot.rows) {
    if (!isRangeParseable(advisory.vulnerable_version_range)) {
      return {
        reason: 'malformed_advisory_vulnerable_version_range',
        fatal: true,
        details: {
          advisoryKey: advisory.advisory_key,
          ghsaId: advisory.ghsa_id,
          vulnerableVersionRange: advisory.vulnerable_version_range,
        },
      };
    }
    if (!['medium', 'high', 'critical'].includes(advisory.severity.toLowerCase())) continue;
    const publishedMs = Date.parse(advisory.published_at ?? '');
    if (!Number.isFinite(publishedMs)) {
      return {
        reason: 'advisory_published_at_missing',
        fatal: false,
        details: { advisoryKey: advisory.advisory_key },
      };
    }
    if (publishedMs <= startMs || publishedMs > horizonEndMs) continue;
    if (!matchesRange(targetReleaseTag, advisory.vulnerable_version_range)) continue;
    affected.push({
      advisoryKey: advisory.advisory_key,
      ghsaId: advisory.ghsa_id,
      cveId: advisory.cve_id ?? null,
      severity: advisory.severity,
      publishedAt: advisory.published_at!,
      vulnerableVersionRange: advisory.vulnerable_version_range!,
    });
  }
  affected.sort((left, right) =>
    left.ghsaId.localeCompare(right.ghsaId) ||
    left.advisoryKey.localeCompare(right.advisoryKey));
  return {
    adverse: affected.length > 0,
    payload: {
      security: {
        ...(advisorySnapshotSchemaVersion(snapshot) === 2
          ? {
              snapshotSchemaVersion: 2 as const,
              snapshotProvenance: snapshot.provenance,
            }
          : {}),
        snapshotId: snapshot.snapshotId,
        snapshotCapturedAt: snapshot.capturedAt,
        snapshotContentHash: snapshot.contentHash,
        advisoryCount: new Set(affected.map((item) => item.ghsaId)).size,
        advisories: affected,
      },
    },
  };
}

function evaluationSection(
  candidateCases: EvaluationCase[],
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
  splitPlan?: EvaluationSplitPlan,
): JsonRecord {
  const cases = candidateCases.slice();
  const { included: nonOverlapping, excluded } = nonOverlappingCases(cases);
  const metrics = metricSet(cases, thresholds, qualityCriteria);
  const nonOverlappingMetrics = metricSet(
    nonOverlapping,
    thresholds,
    qualityCriteria,
  );
  const temporalBlocks = temporalBlockAnalysis(
    nonOverlapping,
    thresholds,
    qualityCriteria,
    'policy',
    splitPlan,
  );
  const gateAnalysis = evaluationGateAnalysis(
    nonOverlappingMetrics,
    temporalBlocks,
  );
  return {
    ...metrics,
    candidateCaseCount: candidateCases.length,
    retainedDecisionCount: cases.length,
    overlapExcludedCount: excluded.length,
    overlapExcludedCases: excluded.map((item) => ({
      releaseTag: item.releaseTag,
      decisionId: item.decisionId,
      windowStartAt: item.windowStartAt,
      windowEndAt: item.windowEndAt,
    })),
    nonOverlappingSensitivity: {
      policy: 'maximum_non_overlapping_windows_by_earliest_end',
      ...nonOverlappingMetrics,
    },
    temporalBlocks,
    gateAnalysis,
    strata: {
      byOpportunity: groupedMetrics(
        cases,
        (item) => item.opportunityCode,
        thresholds,
        qualityCriteria,
      ),
      byModel: groupedMetrics(
        cases,
        validationCaseStratumKey,
        thresholds,
        qualityCriteria,
      ),
    },
    cases: cases
      .slice()
      .sort((left, right) =>
        left.releaseTag.localeCompare(right.releaseTag) ||
        left.opportunityCode.localeCompare(right.opportunityCode))
      .map((item) => ({
        latestReleaseTag: item.latestReleaseTag,
        latestReleaseIdentity: item.latestReleaseIdentity,
        releaseTag: item.releaseTag,
        opportunityCode: item.opportunityCode,
        modelVersion: item.modelVersion,
        promptVersion: item.promptVersion,
        codeRevision: item.codeRevision,
        decisionId: item.decisionId,
        recommended: item.recommended,
        adverse: item.adverse,
        score: item.score,
        observedAt: item.observedAt,
        windowStartAt: item.windowStartAt,
        windowEndAt: item.windowEndAt,
        horizonCode: item.horizonCode,
        ...(item.adverseHorizons ? { adverseHorizons: item.adverseHorizons } : {}),
      })),
  };
}

function candidateScoreEvaluationSection(
  candidateCases: EvaluationCase[],
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
  splitPlan?: EvaluationSplitPlan,
): JsonRecord {
  const cases = candidateCases.slice();
  const { included: nonOverlapping, excluded } =
    nonOverlappingCandidateCases(cases);
  const metrics = candidateScoreMetricSet(cases, thresholds, qualityCriteria);
  const nonOverlappingMetrics = candidateScoreMetricSet(
    nonOverlapping,
    thresholds,
    qualityCriteria,
  );
  const temporalBlocks = temporalBlockAnalysis(
    nonOverlapping,
    thresholds,
    qualityCriteria,
    'candidate',
    splitPlan,
  );
  return {
    ...metrics,
    candidateCaseCount: cases.length,
    retainedCandidateCount: cases.length,
    overlapExcludedCount: excluded.length,
    overlapExcludedCases: excluded.map((item) => ({
      releaseTag: item.releaseTag,
      decisionId: item.decisionId,
      windowStartAt: item.windowStartAt,
      windowEndAt: item.windowEndAt,
    })),
    nonOverlappingSensitivity: {
      policy: 'maximum_non_overlapping_windows_by_earliest_end',
      ...nonOverlappingMetrics,
    },
    temporalBlocks,
    gateAnalysis: evaluationGateAnalysis(
      nonOverlappingMetrics,
      temporalBlocks,
    ),
    strata: {
      byOpportunity: groupedCandidateScoreMetrics(
        cases,
        (item) => item.opportunityCode,
        thresholds,
        qualityCriteria,
      ),
      byModel: groupedCandidateScoreMetrics(
        cases,
        validationCaseStratumKey,
        thresholds,
        qualityCriteria,
      ),
    },
    cases: cases
      .slice()
      .sort((left, right) =>
        left.releaseTag.localeCompare(right.releaseTag) ||
        left.opportunityCode.localeCompare(right.opportunityCode) ||
        left.decisionId.localeCompare(right.decisionId))
      .map(evaluationCaseReport),
  };
}

function evaluationCaseReport(item: EvaluationCase): JsonRecord {
  return {
    latestReleaseTag: item.latestReleaseTag,
    latestReleaseIdentity: item.latestReleaseIdentity,
    releaseTag: item.releaseTag,
    opportunityCode: item.opportunityCode,
    modelVersion: item.modelVersion,
    promptVersion: item.promptVersion,
    codeRevision: item.codeRevision,
    decisionId: item.decisionId,
    recommended: item.recommended,
    adverse: item.adverse,
    score: item.score,
    observedAt: item.observedAt,
    windowStartAt: item.windowStartAt,
    windowEndAt: item.windowEndAt,
    horizonCode: item.horizonCode,
    ...(item.targetRoles ? { targetRoles: item.targetRoles } : {}),
    ...(item.adverseHorizons ? { adverseHorizons: item.adverseHorizons } : {}),
  };
}

function metricSet(
  cases: EvaluationCase[],
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
): JsonRecord {
  const tp = cases.filter((item) => item.recommended && !item.adverse).length;
  const fp = cases.filter((item) => item.recommended && item.adverse).length;
  const tn = cases.filter((item) => !item.recommended && item.adverse).length;
  const fn = cases.filter((item) => !item.recommended && !item.adverse).length;
  const recommended = tp + fp;
  const withheld = tn + fn;
  const adverse = fp + tn;
  const safe = tp + fn;
  const uniqueReleases = new Set(
    cases.map((item) => item.latestReleaseIdentity.key),
  ).size;
  const sampleSufficiency = {
    status: cases.length > 0 &&
      uniqueReleases > 0 &&
      cases.length >= thresholds.independent &&
      uniqueReleases >= thresholds.uniqueReleases &&
      recommended >= thresholds.recommended &&
      withheld >= thresholds.withheld &&
      adverse >= thresholds.adverse &&
      safe >= thresholds.safe
      ? 'sufficient'
      : 'insufficient',
    counts: {
      independent: cases.length,
      uniqueReleases,
      recommended,
      withheld,
      adverse,
      safe,
    },
    minimums: thresholds,
    met: {
      independent: cases.length >= thresholds.independent,
      uniqueReleases: uniqueReleases >= thresholds.uniqueReleases,
      recommended: recommended >= thresholds.recommended,
      withheld: withheld >= thresholds.withheld,
      adverse: adverse >= thresholds.adverse,
      safe: safe >= thresholds.safe,
    },
  };
  const clusterAwareUncertainty = releaseClusterBootstrap(cases);
  const qualityAssessment = validationQualityAssessment(
    clusterAwareUncertainty,
    qualityCriteria,
  );
  return {
    independentSampleCount: cases.length,
    uniqueReleaseClusterCount: uniqueReleases,
    confusionMatrix: {
      definition: {
        positivePrediction: 'selected a release for installation',
        positiveOutcome: 'safe through horizon',
      },
      truePositiveRecommendedSafe: tp,
      falsePositiveRecommendedAdverse: fp,
      trueNegativeWithheldAdverse: tn,
      falseNegativeWithheldSafe: fn,
    },
    rates: {
      recommendationPrecisionSafe: wilsonInterval(tp, recommended),
      falseSafeRate: wilsonInterval(fp, recommended),
      safeRecall: wilsonInterval(tp, safe),
      adverseSpecificity: wilsonInterval(tn, adverse),
      accuracy: wilsonInterval(tp + tn, cases.length),
      recommendationRate: wilsonInterval(recommended, cases.length),
      adversePrevalence: wilsonInterval(adverse, cases.length),
    },
    sampleSufficiency,
    clusterAwareUncertainty,
    qualityAssessment,
    scoreAnalysis: scoreAnalysis(cases),
  };
}

function candidateScoreMetricSet(
  cases: EvaluationCase[],
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
): JsonRecord {
  const adverse = cases.filter((item) => item.adverse).length;
  const safe = cases.length - adverse;
  const independentWindows = new Set(cases.map((item) => item.decisionId)).size;
  const uniqueReleases = new Set(
    cases.map((item) => item.latestReleaseIdentity.key),
  ).size;
  const uniqueTargetReleases = new Set(cases.map((item) => item.releaseTag)).size;
  const score = scoreAnalysis(cases);
  const clusterAwareUncertainty = releaseClusterBootstrap(cases);
  const sampleSufficiency = {
    status: cases.length > 0 &&
      independentWindows >= thresholds.independent &&
      uniqueReleases >= thresholds.uniqueReleases &&
      adverse >= thresholds.adverse &&
      safe >= thresholds.safe
      ? 'sufficient'
      : 'insufficient',
    counts: {
      independent: independentWindows,
      candidates: cases.length,
      uniqueReleases,
      uniqueTargetReleases,
      adverse,
      safe,
    },
    minimums: {
      independent: thresholds.independent,
      uniqueReleases: thresholds.uniqueReleases,
      adverse: thresholds.adverse,
      safe: thresholds.safe,
    },
  };
  return {
    candidateCount: cases.length,
    independentSampleCount: independentWindows,
    uniqueReleaseCount: uniqueReleases,
    uniqueTargetReleaseCount: uniqueTargetReleases,
    outcomeCounts: { adverse, safe },
    sampleSufficiency,
    clusterAwareUncertainty,
    scoreAnalysis: score,
    qualityAssessment: candidateScoreQualityAssessment(
      clusterAwareUncertainty,
      qualityCriteria,
    ),
  };
}

function groupedMetrics(
  cases: EvaluationCase[],
  keyFor: (item: EvaluationCase) => string,
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
): JsonRecord[] {
  const groups = new Map<string, EvaluationCase[]>();
  for (const item of cases) {
    const key = keyFor(item);
    const rows = groups.get(key) ?? [];
    rows.push(item);
    groups.set(key, rows);
  }
  return [...groups.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, rows]) => {
      const { included, excluded } = nonOverlappingCases(rows);
      return {
        key,
        candidateDecisionCount: rows.length,
        ...metricSet(rows, thresholds, qualityCriteria),
        nonOverlappingSensitivity: {
          excludedCount: excluded.length,
          ...metricSet(included, thresholds, qualityCriteria),
        },
      };
    });
}

function groupedCandidateScoreMetrics(
  cases: EvaluationCase[],
  keyFor: (item: EvaluationCase) => string,
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
): JsonRecord[] {
  const groups = new Map<string, EvaluationCase[]>();
  for (const item of cases) {
    const key = keyFor(item);
    const rows = groups.get(key) ?? [];
    rows.push(item);
    groups.set(key, rows);
  }
  return [...groups.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, rows]) => ({
      key,
      candidateCount: rows.length,
      ...candidateScoreMetricSet(rows, thresholds, qualityCriteria),
    }));
}

function scoreAnalysis(cases: EvaluationCase[]): JsonRecord {
  const scored = cases.filter((item): item is EvaluationCase & { score: number } =>
    typeof item.score === 'number' && Number.isFinite(item.score));
  const safe = scored.filter((item) => !item.adverse);
  const adverse = scored.filter((item) => item.adverse);
  const bins = [
    { label: '0-<4', min: 0, max: 4 },
    { label: '4-<6', min: 4, max: 6 },
    { label: '6-<7', min: 6, max: 7 },
    { label: '7-<8', min: 7, max: 8 },
    { label: '8-<9', min: 8, max: 9 },
    { label: '9-10', min: 9, max: Number.POSITIVE_INFINITY },
  ];
  return {
    interpretation:
      'Scores are ordinal. No probability calibration is claimed without a separately trained and temporally held-out mapping.',
    scoredCount: scored.length,
    missingScoreCount: cases.length - scored.length,
    discrimination: {
      safeCount: safe.length,
      adverseCount: adverse.length,
      meanSafeScore: mean(safe.map((item) => item.score)),
      meanAdverseScore: mean(adverse.map((item) => item.score)),
      safeVsAdverseAuc: rankAuc(
        safe.map((item) => item.score),
        adverse.map((item) => item.score),
      ),
    },
    empiricalDiscriminationBins: bins.map((bin) => {
      const rows = scored.filter((item) => item.score >= bin.min && item.score < bin.max);
      const adverseCount = rows.filter((item) => item.adverse).length;
      return {
        scoreRange: bin.label,
        count: rows.length,
        meanScore: mean(rows.map((item) => item.score)),
        recommendedCount: rows.filter((item) => item.recommended).length,
        adverseCount,
        empiricalAdverseRate: wilsonInterval(adverseCount, rows.length),
      };
    }),
  };
}

function validationCaseStratumKey(item: EvaluationCase): string {
  return `${item.modelVersion}/prompt-${item.promptVersion}/` +
    `revision-${item.codeRevision ?? 'unspecified'}`;
}

function validationDenominatorStratumKey(input: {
  modelVersion?: string;
  score_model_version?: string;
  promptVersion?: number;
  prompt_version?: number;
  codeRevision?: string | null;
  code_revision?: string | null;
}): string {
  const modelVersion = input.modelVersion ?? input.score_model_version ?? '';
  const promptVersion = input.promptVersion ?? input.prompt_version;
  const codeRevision = normalizeCodeRevision(
    input.codeRevision ?? input.code_revision,
  );
  return `${modelVersion}/prompt-${promptVersion ?? 'invalid'}/` +
    `revision-${codeRevision ?? 'unspecified'}`;
}

function releaseClusterBootstrap(cases: EvaluationCase[]): JsonRecord {
  const groups = new Map<string, EvaluationCase[]>();
  for (const item of cases) {
    const rows = groups.get(item.latestReleaseIdentity.key) ?? [];
    rows.push(item);
    groups.set(item.latestReleaseIdentity.key, rows);
  }
  const clusters = [...groups.entries()].sort(([left], [right]) =>
    left.localeCompare(right));
  const iterations = clusters.length > 0 ? 1_000 : 0;
  const distributions = {
    recommendationPrecisionSafe: [] as number[],
    falseSafeRate: [] as number[],
    accuracy: [] as number[],
    safeVsAdverseAuc: [] as number[],
  };
  if (iterations > 0) {
    const seed = createHash('sha256')
      .update(cases.map((item) => item.decisionId).sort().join('\0'))
      .digest()
      .readUInt32BE(0);
    const random = seededRandom(seed);
    for (let iteration = 0; iteration < iterations; iteration++) {
      const sampled: EvaluationCase[] = [];
      for (let index = 0; index < clusters.length; index++) {
        const cluster = clusters[Math.floor(random() * clusters.length)]?.[1] ?? [];
        sampled.push(...cluster);
      }
      const rates = rawDecisionRates(sampled);
      if (rates.recommendationPrecisionSafe != null) {
        distributions.recommendationPrecisionSafe.push(rates.recommendationPrecisionSafe);
      }
      if (rates.falseSafeRate != null) {
        distributions.falseSafeRate.push(rates.falseSafeRate);
      }
      distributions.accuracy.push(rates.accuracy);
      if (rates.safeVsAdverseAuc != null) {
        distributions.safeVsAdverseAuc.push(rates.safeVsAdverseAuc);
      }
    }
  }
  return {
    method: 'release_cluster_percentile_bootstrap',
    confidence: 0.95,
    iterations,
    clusterKey: 'sealed_release_identity',
    uniqueReleaseClusterCount: clusters.length,
    metrics: Object.fromEntries(
      Object.entries(distributions).map(([key, values]) => [
        key,
        bootstrapInterval(values, iterations),
      ]),
    ),
  };
}

function rawDecisionRates(cases: EvaluationCase[]): {
  recommendationPrecisionSafe: number | null;
  falseSafeRate: number | null;
  accuracy: number;
  safeVsAdverseAuc: number | null;
} {
  const recommended = cases.filter((item) => item.recommended);
  const safeRecommended = recommended.filter((item) => !item.adverse).length;
  const correct = cases.filter((item) =>
    item.recommended ? !item.adverse : item.adverse).length;
  const safeScores = cases
    .filter((item): item is EvaluationCase & { score: number } =>
      !item.adverse && typeof item.score === 'number' && Number.isFinite(item.score))
    .map((item) => item.score);
  const adverseScores = cases
    .filter((item): item is EvaluationCase & { score: number } =>
      item.adverse && typeof item.score === 'number' && Number.isFinite(item.score))
    .map((item) => item.score);
  return {
    recommendationPrecisionSafe: recommended.length > 0
      ? safeRecommended / recommended.length
      : null,
    falseSafeRate: recommended.length > 0
      ? (recommended.length - safeRecommended) / recommended.length
      : null,
    accuracy: cases.length > 0 ? correct / cases.length : 0,
    safeVsAdverseAuc: rankAuc(safeScores, adverseScores),
  };
}

function bootstrapInterval(
  values: number[],
  iterations: number,
): JsonRecord | null {
  if (iterations === 0 || values.length < Math.ceil(iterations * 0.95)) return null;
  const ordered = values.slice().sort((left, right) => left - right);
  return {
    estimate: round(mean(ordered) ?? 0),
    lower: round(percentile(ordered, 0.025)),
    upper: round(percentile(ordered, 0.975)),
    availableIterations: ordered.length,
  };
}

function validationQualityAssessment(
  uncertainty: JsonRecord,
  criteria: ValidationQualityCriteria,
): JsonRecord {
  const metrics = asRecord(uncertainty.metrics);
  const precision = asRecord(metrics?.recommendationPrecisionSafe);
  const falseSafe = asRecord(metrics?.falseSafeRate);
  const accuracy = asRecord(metrics?.accuracy);
  const auc = asRecord(metrics?.safeVsAdverseAuc);
  const checks = {
    recommendationPrecisionLowerBound: {
      observed: nullableFiniteNumber(precision?.lower),
      minimum: criteria.recommendationPrecisionLowerBound,
      applicable: precision != null,
      passed: precision == null ||
        Number(precision.lower) >= criteria.recommendationPrecisionLowerBound,
    },
    falseSafeUpperBound: {
      observed: nullableFiniteNumber(falseSafe?.upper),
      maximum: criteria.falseSafeUpperBound,
      applicable: falseSafe != null,
      passed: falseSafe == null ||
        Number(falseSafe.upper) <= criteria.falseSafeUpperBound,
    },
    accuracyLowerBound: {
      observed: nullableFiniteNumber(accuracy?.lower),
      minimum: criteria.accuracyLowerBound,
      passed: nullableFiniteNumber(accuracy?.lower) != null &&
        Number(accuracy?.lower) >= criteria.accuracyLowerBound,
    },
    safeVsAdverseAucLowerBound: {
      observed: nullableFiniteNumber(auc?.lower),
      minimum: criteria.safeVsAdverseAucMinimum,
      applicable: true,
      passed: nullableFiniteNumber(auc?.lower) != null &&
        Number(auc?.lower) >= criteria.safeVsAdverseAucMinimum,
    },
  };
  return {
    status: Object.values(checks).every((check) => check.passed)
      ? 'passed'
      : 'failed',
    checks,
  };
}

function candidateScoreQualityAssessment(
  uncertainty: JsonRecord,
  criteria: ValidationQualityCriteria,
): JsonRecord {
  const metrics = asRecord(uncertainty.metrics);
  const auc = asRecord(metrics?.safeVsAdverseAuc);
  const checks = {
    safeVsAdverseAucLowerBound: {
      observed: nullableFiniteNumber(auc?.lower),
      minimum: criteria.safeVsAdverseAucMinimum,
      applicable: true,
      passed: nullableFiniteNumber(auc?.lower) != null &&
        Number(auc?.lower) >= criteria.safeVsAdverseAucMinimum,
    },
  };
  return {
    status: Object.values(checks).every((check) => check.passed)
      ? 'passed'
      : 'failed',
    checks,
  };
}

function pairedModelComparisons(cases: EvaluationCase[]): JsonRecord[] {
  const matchedOpportunities = new Map<string, EvaluationCase[]>();
  for (const item of cases) {
    const key = JSON.stringify([
      item.latestReleaseIdentity.key,
      item.opportunityCode,
      item.horizonCode,
    ]);
    const group = matchedOpportunities.get(key) ?? [];
    group.push(item);
    matchedOpportunities.set(key, group);
  }
  const pairs = new Map<string, Array<{
    opportunityKey: string;
    left: EvaluationCase;
    right: EvaluationCase;
  }>>();
  for (const [opportunityKey, rows] of matchedOpportunities) {
    const byModel = new Map(rows.map((row) => [validationCaseStratumKey(row), row]));
    const modelKeys = [...byModel.keys()].sort();
    for (let leftIndex = 0; leftIndex < modelKeys.length; leftIndex++) {
      for (let rightIndex = leftIndex + 1; rightIndex < modelKeys.length; rightIndex++) {
        const leftKey = modelKeys[leftIndex];
        const rightKey = modelKeys[rightIndex];
        const key = JSON.stringify([leftKey, rightKey]);
        const group = pairs.get(key) ?? [];
        group.push({
          opportunityKey,
          left: byModel.get(leftKey)!,
          right: byModel.get(rightKey)!,
        });
        pairs.set(key, group);
      }
    }
  }
  return [...pairs.entries()]
    .map(([key, rows]) => {
      const [leftModel, rightModel] = JSON.parse(key) as [string, string];
      return {
        leftModel,
        rightModel,
        matchedCaseCount: rows.length,
        recommendationAgreementCount: rows.filter((row) =>
          row.left.recommended === row.right.recommended).length,
        outcomeAgreementCount: rows.filter((row) =>
          row.left.adverse === row.right.adverse).length,
        leftCorrectCount: rows.filter((row) =>
          row.left.recommended ? !row.left.adverse : row.left.adverse).length,
        rightCorrectCount: rows.filter((row) =>
          row.right.recommended ? !row.right.adverse : row.right.adverse).length,
        cases: rows.map((row) => ({
          opportunityKey: JSON.parse(row.opportunityKey),
          releaseIdentityKey: row.left.latestReleaseIdentity.key,
          leftDecisionId: row.left.decisionId,
          rightDecisionId: row.right.decisionId,
          leftTargetReleaseTag: row.left.releaseTag,
          rightTargetReleaseTag: row.right.releaseTag,
        })),
      };
    })
    .sort((left, right) =>
      left.leftModel.localeCompare(right.leftModel) ||
      left.rightModel.localeCompare(right.rightModel));
}

function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ value >>> 15, value | 1);
    value ^= value + Math.imul(value ^ value >>> 7, value | 61);
    return ((value ^ value >>> 14) >>> 0) / 4_294_967_296;
  };
}

function percentile(values: number[], probability: number): number {
  if (values.length === 0) return 0;
  const index = (values.length - 1) * probability;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return values[lower];
  const weight = index - lower;
  return values[lower] * (1 - weight) + values[upper] * weight;
}

function rankAuc(safeScores: number[], adverseScores: number[]): number | null {
  if (safeScores.length === 0 || adverseScores.length === 0) return null;
  let wins = 0;
  for (const safe of safeScores) {
    for (const adverse of adverseScores) {
      if (safe > adverse) wins += 1;
      else if (safe === adverse) wins += 0.5;
    }
  }
  return round(wins / (safeScores.length * adverseScores.length));
}

function resolveObservationLedger(
  forecast: ReleaseValidationForecastLedgerRow,
  horizonCode: ReleaseValidationHorizonCode,
  rows: ReleaseValidationOutcomeLedgerRow[],
  auditHistoryByRunAndTag: Map<string, ReleaseScoreAuditHistoryEvidenceRow>,
  advisorySnapshots: AdvisorySnapshotValidationEvidence[],
  advisorySnapshotsById: Map<string, AdvisorySnapshotValidationEvidence>,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
  errors: string[],
): ObservationResolution {
  const matured: Array<{
    row: ReleaseValidationOutcomeLedgerRow;
    payload: JsonRecord;
  }> = [];
  const indeterminate: IndeterminateObservationResolution[] = [];
  let nonValidatingProxyCount = 0;
  for (const row of rows) {
    const payload = parseRecord(row.outcome_json);
    if (!payload) {
      errors.push(`Malformed outcome JSON for ${forecast.decision_id}/${horizonCode}`);
      continue;
    }
    if (row.status === 'matured') {
      if (horizonCode === 'field_regression_72h' && payload.schemaVersion === 1) {
        nonValidatingProxyCount++;
        continue;
      }
      const error = maturedObservationError(
        forecast,
        horizonCode,
        row,
        payload,
        auditHistoryByRunAndTag,
        advisorySnapshots,
        advisorySnapshotsById,
        expectedAdvisoryPackage,
      );
      if (error) {
        errors.push(`Invalid matured outcome ledger row ${row.observation_id}: ${error}`);
        continue;
      }
      matured.push({ row, payload });
      continue;
    }
    if (row.status === 'indeterminate') {
      const error = indeterminateObservationError(forecast, horizonCode, row, payload);
      if (error) {
        errors.push(`Invalid indeterminate outcome ledger row ${row.observation_id}: ${error}`);
        continue;
      }
      indeterminate.push({
        reason: payload.reason as string,
        fatal: payload.fatal as boolean,
        terminal: payload.terminal as boolean,
        observedAt: row.observed_at,
      });
      continue;
    }
    errors.push(`Unknown outcome status ${row.status} in ${row.observation_id}`);
  }
  matured.sort((left, right) => Date.parse(left.row.observed_at) - Date.parse(right.row.observed_at));
  indeterminate.sort((left, right) => Date.parse(left.observedAt) - Date.parse(right.observedAt));
  if (matured.length === 0) {
    return { matured: null, indeterminate, nonValidatingProxyCount };
  }
  if (matured.length > 1) {
    errors.push(`Multiple matured outcomes for ${forecast.decision_id}/${horizonCode}`);
    return { matured: null, indeterminate, nonValidatingProxyCount };
  }
  return {
    matured: {
      schemaVersion: Number(matured[0].payload.schemaVersion),
      adverse: matured[0].payload.adverse as boolean,
      observedAt: matured[0].row.observed_at,
      windowStartAt: matured[0].payload.windowStartAt as string,
      windowEndAt: matured[0].payload.windowEndAt as string,
      targetOutcomes: resolvedCandidateOutcomes(matured[0].payload, forecast),
      completeCandidateCoverage: matured[0].payload.schemaVersion === 3,
    },
    indeterminate,
    nonValidatingProxyCount,
  };
}

function resolvedCandidateOutcomes(
  payload: JsonRecord,
  forecast: ReleaseValidationForecastLedgerRow,
): MaturedObservationResolution['targetOutcomes'] {
  if (payload.schemaVersion === 3) {
    return recordArray(payload.candidateOutcomes).map((item) => ({
      targetReleaseTag: String(item.targetReleaseTag),
      roles: stringArray(item.roles)
        .filter((role): role is ReleaseValidationTargetRole =>
          role === 'candidate' || role === 'latest' || role === 'selected'),
      adverse: item.adverse === true,
    }));
  }
  const targetReleaseTag = validationTargetReleaseTag(forecast);
  return [{
    targetReleaseTag,
    roles: releaseValidationObservationTargets(forecast)
      .find((target) => target.targetReleaseTag === targetReleaseTag)?.roles ?? [],
    adverse: payload.adverse === true,
  }];
}

function maturedObservationError(
  forecast: ReleaseValidationForecastLedgerRow,
  horizonCode: ReleaseValidationHorizonCode,
  row: ReleaseValidationOutcomeLedgerRow,
  payload: JsonRecord,
  auditHistoryByRunAndTag: Map<string, ReleaseScoreAuditHistoryEvidenceRow>,
  advisorySnapshots: AdvisorySnapshotValidationEvidence[],
  advisorySnapshotsById: Map<string, AdvisorySnapshotValidationEvidence>,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
): string | null {
  const expectedTargetReleaseTag = validationTargetReleaseTag(forecast);
  const expectedWindowEndAt = new Date(
    Date.parse(forecast.recorded_at) + RELEASE_VALIDATION_HORIZONS[horizonCode].durationMs,
  ).toISOString();
  const observedMs = Date.parse(row.observed_at);
  const windowEndMs = Date.parse(expectedWindowEndAt);
  const sourceIdentity = parseRecord(row.source_identity_json);
  const sourceDigest = stringField(sourceIdentity, 'digest');
  const prediction = asRecord(payload.prediction);
  const expectedPrediction = forecastPrediction(forecast);
  const auditEvidence = asRecord(payload.auditEvidence);
  const auditRunId = stringField(auditEvidence, 'runId');
  const audit = auditRunId
    ? auditHistoryByRunAndTag.get(`${auditRunId}\0${expectedTargetReleaseTag}`)
    : undefined;
  const legacySchemaValid = horizonCode === 'field_regression_72h'
    ? payload.schemaVersion === 2
    : payload.schemaVersion === 1 || payload.schemaVersion === 2;
  if ((!legacySchemaValid && payload.schemaVersion !== 3) ||
    payload.decisionId !== forecast.decision_id ||
    payload.opportunityCode !== forecast.opportunity_code ||
    payload.horizonCode !== horizonCode ||
    payload.targetReleaseTag !== expectedTargetReleaseTag ||
    typeof payload.adverse !== 'boolean' ||
    payload.observedAt !== row.observed_at ||
    payload.windowStartAt !== forecast.recorded_at ||
    payload.windowEndAt !== expectedWindowEndAt ||
    !Number.isFinite(observedMs) ||
    observedMs < windowEndMs ||
    observedMs > windowEndMs + RELEASE_VALIDATION_HORIZONS[horizonCode].observationGraceMs) {
    return 'metadata_or_window_mismatch';
  }
  if (!prediction || !sameJsonValue(prediction, expectedPrediction)) {
    return 'prediction_mismatch';
  }
  if (payload.schemaVersion === 3) {
    return maturedCandidateOutcomesError(
      payload,
      horizonCode,
      forecast,
      row,
      sourceIdentity,
      auditHistoryByRunAndTag,
      advisorySnapshots,
      advisorySnapshotsById,
      expectedAdvisoryPackage,
    );
  }
  if (!sourceDigest || !auditEvidence || !audit) {
    return 'audit_history_row_missing';
  }
  const auditRecordedMs = Date.parse(audit.recorded_at);
  const auditScoredMs = Date.parse(audit.scored_at);
  const auditSourceIdentity = parseRecord(audit.source_identity_json);
  if (auditEvidence.recordedAt !== audit.recorded_at ||
    auditEvidence.scoredAt !== audit.scored_at ||
    auditEvidence.sourceIdentityDigest !== sourceDigest ||
    auditEvidence.scoreModelVersion !== audit.score_model_version ||
    auditEvidence.promptVersion !== audit.prompt_version ||
    !sameJsonValue(sourceIdentity, auditSourceIdentity) ||
    !Number.isFinite(auditRecordedMs) ||
    !Number.isFinite(auditScoredMs) ||
    auditRecordedMs < windowEndMs ||
    auditScoredMs < windowEndMs ||
    auditRecordedMs > observedMs ||
    auditScoredMs > observedMs) {
    return 'audit_history_evidence_mismatch';
  }
  return maturedPayloadShapeError(
    payload,
    horizonCode,
    forecast,
    audit,
    advisorySnapshots,
    advisorySnapshotsById,
    expectedAdvisoryPackage,
    expectedTargetReleaseTag,
    false,
  );
}

function maturedCandidateOutcomesError(
  payload: JsonRecord,
  horizonCode: ReleaseValidationHorizonCode,
  forecast: ReleaseValidationForecastLedgerRow,
  row: ReleaseValidationOutcomeLedgerRow,
  sourceIdentity: JsonRecord | null,
  auditHistoryByRunAndTag: Map<string, ReleaseScoreAuditHistoryEvidenceRow>,
  advisorySnapshots: AdvisorySnapshotValidationEvidence[],
  advisorySnapshotsById: Map<string, AdvisorySnapshotValidationEvidence>,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
): string | null {
  const sourceDigest = stringField(sourceIdentity, 'digest');
  const expectedTargets = releaseValidationObservationTargets(forecast);
  const candidateOutcomes = recordArray(payload.candidateOutcomes);
  if (!sourceDigest || candidateOutcomes.length !== expectedTargets.length) {
    return 'candidate_outcome_coverage_mismatch';
  }
  const seenTags = new Set<string>();
  for (const expected of expectedTargets) {
    const candidate = candidateOutcomes.find((item) =>
      item.targetReleaseTag === expected.targetReleaseTag);
    if (!candidate || seenTags.has(expected.targetReleaseTag) ||
      !sameJsonValue(stringArray(candidate.roles), expected.roles) ||
      candidate.candidateScore !== candidateScoreForRelease(
        forecast.candidate_scores_json,
        expected.targetReleaseTag,
      ) ||
      typeof candidate.adverse !== 'boolean') {
      return 'candidate_outcome_metadata_mismatch';
    }
    seenTags.add(expected.targetReleaseTag);
    const auditEvidence = asRecord(candidate.auditEvidence);
    const runId = stringField(auditEvidence, 'runId');
    const audit = runId
      ? auditHistoryByRunAndTag.get(`${runId}\0${expected.targetReleaseTag}`)
      : undefined;
    if (!audit || !auditEvidence) return 'candidate_audit_history_row_missing';
    const auditSourceIdentity = parseRecord(audit.source_identity_json);
    const auditRecordedMs = Date.parse(audit.recorded_at);
    const auditScoredMs = Date.parse(audit.scored_at);
    if (auditEvidence.recordedAt !== audit.recorded_at ||
      auditEvidence.scoredAt !== audit.scored_at ||
      auditEvidence.sourceIdentityDigest !== sourceDigest ||
      auditEvidence.scoreModelVersion !== audit.score_model_version ||
      auditEvidence.promptVersion !== audit.prompt_version ||
      !sameJsonValue(sourceIdentity, auditSourceIdentity) ||
      !Number.isFinite(auditRecordedMs) ||
      !Number.isFinite(auditScoredMs) ||
      auditRecordedMs < Date.parse(String(payload.windowEndAt)) ||
      auditScoredMs < Date.parse(String(payload.windowEndAt)) ||
      auditRecordedMs > Date.parse(row.observed_at) ||
      auditScoredMs > Date.parse(row.observed_at)) {
      return 'candidate_audit_history_evidence_mismatch';
    }
    const payloadError = maturedPayloadShapeError(
      {
        ...candidate,
        windowEndAt: payload.windowEndAt,
        observedAt: payload.observedAt,
      },
      horizonCode,
      forecast,
      audit,
      advisorySnapshots,
      advisorySnapshotsById,
      expectedAdvisoryPackage,
      expected.targetReleaseTag,
      true,
    );
    if (payloadError) return payloadError;
  }
  const policyTargetReleaseTag = validationTargetReleaseTag(forecast);
  const policyOutcome = candidateOutcomes.find((item) =>
    item.targetReleaseTag === policyTargetReleaseTag);
  const policyAction = asRecord(payload.policyAction);
  if (!policyOutcome ||
    !policyAction ||
    policyAction.action !== (forecast.selected_tag == null
      ? 'withhold_latest'
      : 'install_selected') ||
    policyAction.targetReleaseTag !== policyTargetReleaseTag ||
    policyAction.adverse !== policyOutcome.adverse ||
    payload.adverse !== policyOutcome.adverse ||
    !sameJsonValue(payload.auditEvidence, policyOutcome.auditEvidence) ||
    !sameJsonValue(payload.fieldRegression, policyOutcome.fieldRegression) ||
    !sameJsonValue(payload.security, policyOutcome.security)) {
    return 'policy_action_projection_mismatch';
  }
  return null;
}

function indeterminateObservationError(
  forecast: ReleaseValidationForecastLedgerRow,
  horizonCode: ReleaseValidationHorizonCode,
  row: ReleaseValidationOutcomeLedgerRow,
  payload: JsonRecord,
): string | null {
  const expectedWindowEndAt = new Date(
    Date.parse(forecast.recorded_at) + RELEASE_VALIDATION_HORIZONS[horizonCode].durationMs,
  ).toISOString();
  const observedMs = Date.parse(row.observed_at);
  const windowEndMs = Date.parse(expectedWindowEndAt);
  const latestObservationMs = windowEndMs + RELEASE_VALIDATION_HORIZONS[horizonCode].observationGraceMs;
  const reason = stringField(payload, 'reason');
  const terminal = reason === 'observation_grace_window_missed';
  if (payload.schemaVersion !== 1 ||
    payload.kind !== 'indeterminate' ||
    payload.decisionId !== forecast.decision_id ||
    payload.opportunityCode !== forecast.opportunity_code ||
    payload.horizonCode !== horizonCode ||
    payload.targetReleaseTag !== validationTargetReleaseTag(forecast) ||
    payload.windowStartAt !== forecast.recorded_at ||
    payload.windowEndAt !== expectedWindowEndAt ||
    payload.observedAt !== row.observed_at ||
    !reason ||
    typeof payload.fatal !== 'boolean' ||
    payload.terminal !== terminal ||
    typeof payload.sourceIdentityFallback !== 'boolean' ||
    !sameJsonValue(payload.prediction, forecastPrediction(forecast)) ||
    !stringField(parseRecord(row.source_identity_json), 'digest') ||
    !Number.isFinite(observedMs) ||
    observedMs < windowEndMs) {
    return 'metadata_or_payload_mismatch';
  }
  if (terminal ? observedMs <= latestObservationMs : observedMs > latestObservationMs) {
    return 'indeterminate_timing_mismatch';
  }
  return null;
}

function maturedPayloadShapeError(
  payload: JsonRecord,
  horizonCode: ReleaseValidationHorizonCode,
  forecast: ReleaseValidationForecastLedgerRow,
  audit: ReleaseScoreAuditHistoryEvidenceRow,
  advisorySnapshots: AdvisorySnapshotValidationEvidence[],
  advisorySnapshotsById: Map<string, AdvisorySnapshotValidationEvidence>,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
  targetReleaseTag = validationTargetReleaseTag(forecast),
  requireFieldSnapshot = false,
): string | null {
  if (horizonCode === 'field_regression_72h') {
    const field = asRecord(payload.fieldRegression);
    const issueCount = nonnegativeInteger(field?.issueCount);
    const clusterCount = nonnegativeInteger(field?.clusterCount);
    const evidenceRefs = recordArray(field?.evidenceRefs);
    const completeness = asRecord(field?.evidenceCompleteness);
    const evidenceCapturedAt = timestampField(completeness, 'capturedAt');
    const issueUniverseCount = nonnegativeInteger(completeness?.issueUniverseCount);
    const completeCommentSnapshotCount = nonnegativeInteger(
      completeness?.completeCommentSnapshotCount,
    );
    const classifierProxy = asRecord(field?.classifierProxy);
    const evidenceSnapshot = asRecord(field?.evidenceSnapshot);
    if (payload.security !== undefined ||
      field?.outcomeSourceClass !== 'independent_raw_evidence' ||
      !['observed-adverse', 'observed-safe'].includes(String(field?.observedClass ?? '')) ||
      field?.evidenceScope !== 'complete_exact_version_post_forecast_crawl' ||
      !evidenceCapturedAt ||
      Date.parse(evidenceCapturedAt) < Date.parse(String(payload.windowEndAt)) ||
      Date.parse(evidenceCapturedAt) > Date.parse(String(payload.observedAt)) ||
      evidenceCapturedAt !== audit.recorded_at ||
      issueUniverseCount == null ||
      completeCommentSnapshotCount !== issueUniverseCount ||
      !Array.isArray(completeness?.incompleteIssueNumbers) ||
      completeness.incompleteIssueNumbers.length !== 0 ||
      issueCount == null ||
      clusterCount == null ||
      evidenceRefs.length !== issueCount ||
      clusterCount !== issueCount ||
      field?.observedClass !== (issueCount > 0 ? 'observed-adverse' : 'observed-safe') ||
      payload.adverse !== (clusterCount > 0)) {
      return 'invalid_field_regression_payload';
    }
    if (requireFieldSnapshot) {
      if (!evidenceSnapshot) return 'field_evidence_snapshot_missing';
      const snapshot = evidenceSnapshot as unknown as IndependentFieldEvidenceSnapshot;
      const snapshotError = independentFieldEvidenceSnapshotShapeError(
        snapshot,
        targetReleaseTag,
        Date.parse(forecast.recorded_at),
        Date.parse(String(payload.windowEndAt)),
      );
      if (snapshotError ||
        snapshot.capturedAt !== audit.recorded_at ||
        snapshot.issueUniverseCount !== issueUniverseCount ||
        snapshot.completeCommentSnapshotCount !== completeCommentSnapshotCount ||
        !sameJsonValue(snapshot.incompleteIssueNumbers, []) ||
        !sameJsonValue(snapshot.evidenceRefs, evidenceRefs)) {
        return 'field_evidence_snapshot_provenance_mismatch';
      }
    }
    const auditIssueEvidence = parseRecord(audit.issue_evidence_json);
    if (!auditIssueEvidence || !classifierProxy ||
      !sameJsonValue(classifierProxy, classifierFieldOutcomeProxy(auditIssueEvidence))) {
      return 'classifier_proxy_mismatch';
    }
    const evidenceError = independentFieldEvidenceShapeError(
      evidenceRefs as unknown as IndependentFieldAdverseEvidence[],
      targetReleaseTag,
      Date.parse(forecast.recorded_at),
      Date.parse(String(payload.windowEndAt)),
    );
    if (evidenceError) {
      return 'independent_field_evidence_content_mismatch';
    }
    return null;
  }
  const security = asRecord(payload.security);
  const snapshotId = Number(security?.snapshotId);
  const snapshotSchemaVersion =
    advisorySnapshotSchemaVersionFromSecurityPayload(security);
  const capturedAt = timestampField(security, 'snapshotCapturedAt');
  const contentHash = stringField(security, 'snapshotContentHash');
  const advisoryCount = nonnegativeInteger(security?.advisoryCount);
  const advisories = recordArray(security?.advisories);
  const snapshot = advisorySnapshotsById.get(
    advisorySnapshotIdentityKey(snapshotSchemaVersion, snapshotId),
  );
  if (payload.fieldRegression !== undefined ||
    !Number.isInteger(snapshotId) || snapshotId <= 0 || !capturedAt || !contentHash ||
    advisoryCount == null || !snapshot) {
    return 'invalid_security_snapshot_payload';
  }
  const selection = prospectiveAdvisorySnapshot(
    advisorySnapshots,
    Date.parse(String(payload.windowEndAt)),
    Date.parse(audit.recorded_at),
    snapshotSchemaVersion,
  );
  if ('reason' in selection) return selection.reason;
  const expectedSnapshot = selection.snapshot;
  if (expectedSnapshot.snapshotId !== snapshotId ||
    capturedAt !== snapshot.capturedAt ||
    contentHash !== snapshot.contentHash ||
    Date.parse(capturedAt) < Date.parse(String(payload.windowEndAt)) ||
    Date.parse(capturedAt) > Date.parse(audit.recorded_at)) {
    return 'security_snapshot_provenance_mismatch';
  }
  const derived = securityOutcomeFromSnapshot(
    forecast,
    targetReleaseTag,
    snapshot,
    Date.parse(String(payload.windowEndAt)),
    expectedAdvisoryPackage,
  );
  if ('reason' in derived) return derived.reason;
  if (!sameJsonValue(security, derived.payload.security) ||
    payload.adverse !== derived.adverse ||
    advisories.length !== recordArray(derived.payload.security?.advisories).length) {
    return 'security_snapshot_content_mismatch';
  }
  return null;
}

function deduplicateForecasts(
  rows: ReleaseValidationForecastLedgerRow[],
  errors: string[],
): ReleaseValidationForecastLedgerRow[] {
  const grouped = new Map<string, ReleaseValidationForecastLedgerRow[]>();
  for (const row of rows) {
    if (!row.decision_id || !row.latest_release_tag || !row.opportunity_code ||
      !Number.isFinite(Date.parse(row.recorded_at))) {
      errors.push(`Malformed forecast ledger row ${row.decision_id || row.id || 'unknown'}`);
      continue;
    }
    if (!stringField(parseRecord(row.source_identity_json), 'digest')) {
      errors.push(`Forecast ${row.decision_id} has malformed source identity`);
      continue;
    }
    const key = forecastSeriesIdentity(row);
    const group = grouped.get(key) ?? [];
    group.push(row);
    grouped.set(key, group);
  }
  return [...grouped.values()].map((group) => {
    const ordered = group.slice().sort((left, right) =>
      Date.parse(left.recorded_at) - Date.parse(right.recorded_at) ||
      Number(left.id ?? 0) - Number(right.id ?? 0));
    if (ordered.length > 1) {
      const first = ordered[0];
      errors.push(
        `Duplicate forecast series identity ` +
        `${first.latest_release_tag}/${first.opportunity_code}/` +
        `${first.score_model_version}/prompt-${first.prompt_version}`,
      );
    }
    return ordered[0];
  });
}

function primaryForecastsByEvaluatedTarget(
  rows: ReleaseValidationForecastLedgerRow[],
): ReleaseValidationForecastLedgerRow[] {
  const grouped = new Map<string, ReleaseValidationForecastLedgerRow[]>();
  for (const row of rows) {
    const targetReleaseTag = validationTargetReleaseTag(row);
    const key = JSON.stringify([
      targetReleaseTag,
      row.score_model_version,
      row.prompt_version,
    ]);
    const group = grouped.get(key) ?? [];
    group.push(row);
    grouped.set(key, group);
  }
  return [...grouped.values()].map((group) =>
    group.slice().sort((left, right) => {
      const leftNativeRank = validationTargetReleaseTag(left) === left.latest_release_tag ? 0 : 1;
      const rightNativeRank = validationTargetReleaseTag(right) === right.latest_release_tag ? 0 : 1;
      const leftRank = validationOpportunityRank(left.opportunity_code);
      const rightRank = validationOpportunityRank(right.opportunity_code);
      return leftNativeRank - rightNativeRank ||
        leftRank - rightRank ||
        Date.parse(left.recorded_at) - Date.parse(right.recorded_at) ||
        Number(left.id ?? 0) - Number(right.id ?? 0) ||
        left.decision_id.localeCompare(right.decision_id);
    })[0]);
}

function forecastSeriesIdentity(row: Pick<
  ReleaseValidationForecastLedgerRow,
  | 'latest_release_tag'
  | 'opportunity_code'
  | 'score_model_version'
  | 'prompt_version'
  | 'code_revision'
>): string {
  return JSON.stringify([
    row.latest_release_tag,
    row.opportunity_code,
    row.score_model_version,
    row.prompt_version,
    normalizeCodeRevision(row.code_revision),
  ]);
}

function validationStratumKey(row: Pick<
  ReleaseValidationForecastLedgerRow,
  'score_model_version' | 'prompt_version' | 'code_revision'
>): string {
  const revision = normalizeCodeRevision(row.code_revision);
  return `${row.score_model_version}/prompt-${row.prompt_version}/` +
    `revision-${revision ?? 'unspecified'}`;
}

function validationOpportunityRank(code: string): number {
  if (code === 'first_verified_after_24h') return 0;
  if (code === 'first_verified_after_3h') return 1;
  return 2;
}

function observationsByDecisionAndHorizon(
  rows: ReleaseValidationOutcomeLedgerRow[],
  knownDecisionIds: Set<string>,
  errors: string[],
): Map<string, ReleaseValidationOutcomeLedgerRow[]> {
  const grouped = new Map<string, ReleaseValidationOutcomeLedgerRow[]>();
  for (const row of rows) {
    if (!knownDecisionIds.has(row.decision_id)) {
      errors.push(`Outcome ${row.observation_id} references unknown decision ${row.decision_id}`);
      continue;
    }
    if (!(row.horizon_code in RELEASE_VALIDATION_HORIZONS)) {
      errors.push(`Unknown validation horizon ${row.horizon_code} in ${row.observation_id}`);
      continue;
    }
    const key = `${row.decision_id}\0${row.horizon_code}`;
    const group = grouped.get(key) ?? [];
    group.push(row);
    grouped.set(key, group);
  }
  return grouped;
}

function validationTargetReleaseTag(forecast: ReleaseValidationForecastLedgerRow): string {
  return forecast.selected_tag ?? forecast.latest_release_tag;
}

function releaseIdentityForForecast(
  forecast: ReleaseValidationForecastLedgerRow,
  errors: string[],
): ReleaseValidationReleaseIdentity {
  const decision = parseRecord(forecast.decision_json);
  const catalogAttestation = asRecord(decision?.catalogAttestation);
  const latestStable = asRecord(catalogAttestation?.latestStable);
  const nodeId = stringField(latestStable, 'nodeId');
  const tag = stringField(latestStable, 'tag');
  const tagCommitOid = stringField(latestStable, 'tagCommitOid');
  const publishedAt = timestampField(latestStable, 'publishedAt');
  if (
    !nodeId ||
    tag !== forecast.latest_release_tag ||
    !tagCommitOid ||
    !/^[0-9a-f]{40}$/i.test(tagCommitOid) ||
    publishedAt !== forecast.latest_release_published_at
  ) {
    errors.push(
      `Forecast ${forecast.decision_id} lacks an exact sealed release identity`,
    );
    const fallback = {
      nodeId: nodeId ?? `invalid:${forecast.decision_id}`,
      tag: forecast.latest_release_tag,
      tagCommitOid: tagCommitOid ?? '0'.repeat(40),
      publishedAt: forecast.latest_release_published_at,
    };
    return {
      ...fallback,
      key: releaseValidationReleaseIdentityKey(fallback),
    };
  }
  const identity = {
    nodeId,
    tag,
    tagCommitOid: tagCommitOid.toLowerCase(),
    publishedAt,
  };
  return {
    ...identity,
    key: releaseValidationReleaseIdentityKey(identity),
  };
}

function candidateScoreForRelease(json: string, releaseTag: string): number | null {
  const parsed = parseJson(json);
  const candidates = Array.isArray(parsed)
    ? parsed
    : recordArray(asRecord(parsed)?.candidates ?? asRecord(parsed)?.scores);
  for (const candidate of candidates) {
    const row = asRecord(candidate);
    if (!row) continue;
    const tagAliases = presentAliasValues(row, ['releaseTag', 'release_tag', 'tag']);
    if (aliasValuesConflict(tagAliases)) continue;
    const tag = tagAliases[0];
    if (tag !== releaseTag) continue;
    const scoreSnapshotAliases = presentAliasValues(row, ['scoreSnapshot', 'score_snapshot']);
    if (aliasValuesConflict(scoreSnapshotAliases)) return null;
    const scoreSnapshot = asRecord(scoreSnapshotAliases[0]);
    if (!scoreSnapshot) return null;
    const scoreAliases = presentAliasValues(scoreSnapshot, ['finalScore', 'final_score']);
    if (aliasValuesConflict(scoreAliases)) return null;
    const score = scoreAliases[0];
    if (typeof score === 'number' && Number.isFinite(score)) return score;
    return null;
  }
  return null;
}

function forecastPrediction(
  forecast: ReleaseValidationForecastLedgerRow,
): ReleaseValidationOutcomePayload['prediction'] {
  const targetReleaseTag = validationTargetReleaseTag(forecast);
  return {
    recommended: forecast.selected_tag != null,
    recommendedLatest: forecast.selected_tag === forecast.latest_release_tag,
    selectedTag: forecast.selected_tag,
    targetReleaseScore: candidateScoreForRelease(
      forecast.candidate_scores_json,
      targetReleaseTag,
    ),
  };
}

function indexAuditHistory(
  rows: ReleaseScoreAuditHistoryEvidenceRow[],
  errors: string[],
): Map<string, ReleaseScoreAuditHistoryEvidenceRow> {
  const indexed = new Map<string, ReleaseScoreAuditHistoryEvidenceRow>();
  for (const row of rows) {
    const key = `${row.run_id}\0${row.release_tag}`;
    if (indexed.has(key)) {
      errors.push(`Duplicate score audit history row ${row.run_id}/${row.release_tag}`);
      continue;
    }
    indexed.set(key, row);
  }
  return indexed;
}

function indexAdvisorySnapshots(
  snapshots: AdvisorySnapshotValidationEvidence[],
  errors: string[],
  expectedAdvisoryPackage: ExpectedAdvisoryPackage = DEFAULT_EXPECTED_ADVISORY_PACKAGE,
  semanticRequiredSnapshotKeys: Set<string> = new Set(),
): Map<string, AdvisorySnapshotValidationEvidence> {
  const indexed = new Map<string, AdvisorySnapshotValidationEvidence>();
  for (const snapshot of snapshots) {
    const snapshotKey = advisorySnapshotKey(snapshot);
    if (indexed.has(snapshotKey)) {
      errors.push(`Duplicate advisory snapshot ${snapshotKey}`);
      continue;
    }
    const structuralError = advisorySnapshotStructuralError(
      snapshot,
      expectedAdvisoryPackage,
    );
    const semanticError = semanticRequiredSnapshotKeys.has(snapshotKey)
      ? advisorySnapshotSemanticError(snapshot, expectedAdvisoryPackage)
      : null;
    const error = structuralError ?? semanticError;
    if (error) {
      errors.push(`Invalid advisory snapshot ${snapshotKey}: ${error.reason}`);
    }
    indexed.set(snapshotKey, snapshot);
  }
  return indexed;
}

function advisorySnapshotError(
  snapshot: AdvisorySnapshotValidationEvidence,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage = DEFAULT_EXPECTED_ADVISORY_PACKAGE,
): { reason: string; fatal: boolean; details?: unknown } | null {
  return advisorySnapshotStructuralError(snapshot, expectedAdvisoryPackage) ??
    advisorySnapshotSemanticError(snapshot, expectedAdvisoryPackage);
}

function advisorySnapshotStructuralError(
  snapshot: AdvisorySnapshotValidationEvidence,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
): { reason: string; fatal: boolean; details?: unknown } | null {
  if (!Number.isInteger(snapshot.snapshotId) || snapshot.snapshotId <= 0 ||
    ![1, 2].includes(advisorySnapshotSchemaVersion(snapshot)) ||
    snapshot.headerPresent === false ||
    !Number.isFinite(Date.parse(snapshot.capturedAt)) ||
    !Number.isInteger(snapshot.rowCount) || snapshot.rowCount < 0 ||
    snapshot.rows.length !== snapshot.rowCount ||
    !snapshot.contentHash.trim()) {
    return {
      reason: 'post_horizon_advisory_snapshot_incomplete',
      fatal: false,
      details: {
        snapshotId: snapshot.snapshotId,
        expectedRows: snapshot.rowCount,
        observedRows: snapshot.rows.length,
      },
    };
  }
  if (advisorySnapshotSchemaVersion(snapshot) === 2) {
    const provenanceProblem = compoundAdvisoryValidationProvenanceProblem(
      snapshot,
      expectedAdvisoryPackage,
    );
    if (provenanceProblem) {
      return {
        reason: 'post_horizon_advisory_snapshot_provenance_invalid',
        fatal: true,
        details: {
          snapshotId: snapshot.snapshotId,
          problem: provenanceProblem,
        },
      };
    }
  } else if (snapshot.provenance !== undefined) {
    return {
      reason: 'post_horizon_advisory_snapshot_provenance_invalid',
      fatal: true,
      details: {
        snapshotId: snapshot.snapshotId,
        problem: 'legacy advisory snapshot cannot carry v2 provenance',
      },
    };
  }
  const rowProblems = advisorySnapshotRowProblems(
    snapshot.rows,
    expectedAdvisoryPackage,
  ).filter((problem) => !isAdvisorySnapshotSemanticProblem(problem));
  if (rowProblems.length > 0) {
    return {
      reason: 'post_horizon_advisory_snapshot_row_malformed',
      fatal: true,
      details: { snapshotId: snapshot.snapshotId, problems: rowProblems },
    };
  }
  const computedHash = advisorySnapshotContentHash(snapshot.rows);
  if (computedHash !== snapshot.contentHash) {
    return {
      reason: 'post_horizon_advisory_snapshot_hash_mismatch',
      fatal: true,
      details: {
        snapshotId: snapshot.snapshotId,
        expectedContentHash: snapshot.contentHash,
        computedContentHash: computedHash,
      },
    };
  }
  return null;
}

function compoundAdvisoryValidationProvenanceProblem(
  snapshot: AdvisorySnapshotValidationEvidence,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
): string | null {
  const provenance = snapshot.provenance;
  const metadata = provenance?.metadata;
  const publication = provenance?.publication;
  if (!provenance || !metadata || !publication) {
    return 'compound advisory snapshot publication provenance is missing';
  }
  const metadataDigest = createHash('sha256')
    .update(JSON.stringify(canonicalJson(metadata)))
    .digest('hex');
  const hashes = [
    provenance.ledgerContentHash,
    provenance.sourceHash,
    provenance.catalogHash,
    provenance.scoreHash,
    provenance.scoreContentDigest,
    provenance.metadataDigest,
    publication.receiptSemanticIdentity,
  ];
  if (hashes.some((value) => !/^[0-9a-f]{64}$/.test(value))) {
    return 'compound advisory snapshot provenance contains a malformed digest';
  }
  if (
    provenance.previousLedgerContentHash != null &&
    !/^[0-9a-f]{64}$/.test(provenance.previousLedgerContentHash)
  ) {
    return 'compound advisory snapshot previous ledger digest is malformed';
  }
  if (
    provenance.schemaVersion !== 2 ||
    metadata.schemaVersion !== COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION ||
    metadata.snapshotId !== snapshot.snapshotId ||
    metadata.capturedAt !== snapshot.capturedAt ||
    metadata.target.ecosystem !== expectedAdvisoryPackage.ecosystem ||
    metadata.target.packageName.toLowerCase() !==
      expectedAdvisoryPackage.packageName.toLowerCase() ||
    metadata.contentHash !== provenance.ledgerContentHash ||
    metadata.previousContentHash !== provenance.previousLedgerContentHash ||
    metadata.sourceHash !== provenance.sourceHash ||
    metadata.catalogHash !== provenance.catalogHash ||
    metadata.scoreHash !== provenance.scoreHash ||
    metadata.scoreContentDigest !== provenance.scoreContentDigest ||
    metadata.scoreContentDigest !== snapshot.contentHash ||
    metadata.scoreRowCount !== snapshot.rowCount ||
    metadata.rowCount < metadata.scoreRowCount ||
    metadata.scoreReady !== true ||
    provenance.metadataDigest !== metadataDigest
  ) {
    return 'compound advisory snapshot metadata binding is inconsistent';
  }
  if (
    !publication.receiptId ||
    !publication.runId ||
    !Number.isFinite(Date.parse(publication.operationStartedAt)) ||
    !Number.isFinite(Date.parse(publication.finishedAt)) ||
    Date.parse(publication.operationStartedAt) > Date.parse(snapshot.capturedAt) ||
    Date.parse(publication.finishedAt) < Date.parse(snapshot.capturedAt)
  ) {
    return 'compound advisory snapshot publication timing is invalid';
  }
  return null;
}

function advisorySnapshotSemanticError(
  snapshot: AdvisorySnapshotValidationEvidence,
  expectedAdvisoryPackage: ExpectedAdvisoryPackage,
): { reason: string; fatal: boolean; details?: unknown } | null {
  const rowProblems = advisorySnapshotRowProblems(
    snapshot.rows,
    expectedAdvisoryPackage,
  ).filter(isAdvisorySnapshotSemanticProblem);
  if (rowProblems.length === 0) return null;
  const malformedRange = rowProblems.find((problem) =>
    problem.detail.startsWith('malformed_vulnerable_range:'));
  return {
    reason: malformedRange
      ? 'malformed_advisory_vulnerable_version_range'
      : 'post_horizon_advisory_snapshot_row_malformed',
    fatal: true,
    details: { snapshotId: snapshot.snapshotId, problems: rowProblems },
  };
}

function nonOverlappingCases(cases: EvaluationCase[]): {
  included: EvaluationCase[];
  excluded: EvaluationCase[];
} {
  const ordered = cases.slice().sort((left, right) =>
    Date.parse(left.windowEndAt) - Date.parse(right.windowEndAt) ||
    Date.parse(left.windowStartAt) - Date.parse(right.windowStartAt) ||
    left.releaseTag.localeCompare(right.releaseTag) ||
    left.decisionId.localeCompare(right.decisionId));
  const included: EvaluationCase[] = [];
  const excluded: EvaluationCase[] = [];
  let lastWindowEndMs = Number.NEGATIVE_INFINITY;
  for (const item of ordered) {
    const startMs = Date.parse(item.windowStartAt);
    const endMs = Date.parse(item.windowEndAt);
    if (startMs >= lastWindowEndMs) {
      included.push(item);
      lastWindowEndMs = endMs;
    } else {
      excluded.push(item);
    }
  }
  return { included, excluded };
}

function nonOverlappingCandidateCases(cases: EvaluationCase[]): {
  included: EvaluationCase[];
  excluded: EvaluationCase[];
} {
  const groups = new Map<string, EvaluationCase[]>();
  for (const item of cases) {
    const rows = groups.get(item.decisionId) ?? [];
    rows.push(item);
    groups.set(item.decisionId, rows);
  }
  const representatives = [...groups.values()].map((rows) => rows[0]);
  const selectedDecisionIds = new Set(
    nonOverlappingCases(representatives).included.map((item) => item.decisionId),
  );
  return {
    included: cases.filter((item) => selectedDecisionIds.has(item.decisionId)),
    excluded: cases.filter((item) => !selectedDecisionIds.has(item.decisionId)),
  };
}

interface EvaluationSplitPlan {
  source:
    | 'canonical_obligation_assignments'
    | 'persisted_release_identity_assignments'
    | 'denominator_derived_non_authorizing';
  persisted: boolean;
  assignments: Map<string, ReleaseValidationSplitRole>;
  expectedAssignmentCount: number;
  persistedAssignmentCount: number;
  missingAssignmentKeys: string[];
  extraAssignmentKeys: string[];
  blockingErrors: string[];
}

function buildCanonicalEvaluationSplitPlan(
  proof: ReleaseValidationProofBundle,
): EvaluationSplitPlan {
  const verification = verifyReleaseValidationProofBundle(proof);
  const blockingErrors = verification.valid
    ? []
    : verification.problems.map((problem) =>
        `Canonical validation proof: ${problem}`);
  const cohortsById = new Map(
    proof.cohorts.map((cohort) => [cohort.cohortId, cohort]),
  );
  const obligationsById = new Map(
    proof.obligations.map((obligation) => [
      obligation.obligationId,
      obligation,
    ]),
  );
  const releaseArms = new Map<string, ReleaseValidationSplitRole>();
  const releaseAliases = new Map<string, {
    cohortKey: string;
    nodeId: string;
    tagCommitOid: string;
    publishedAt: string;
    aliases: readonly string[];
  }>();

  for (const assignment of proof.splitAssignments) {
    const cohort = cohortsById.get(assignment.cohortId);
    const obligation = obligationsById.get(assignment.obligationId);
    if (!cohort || !obligation) continue;
    const cohortKey = canonicalValidationCohortKey(cohort);
    if (!cohortKey) {
      blockingErrors.push(
        `Canonical cohort ${cohort.cohortId} has an invalid stratum`,
      );
      continue;
    }
    const releaseKey = `${cohort.cohortId}\0${obligation.release.releaseId}`;
    const role: ReleaseValidationSplitRole =
      assignment.arm === 'holdout' ? 'holdout' : 'development';
    const existing = releaseArms.get(releaseKey);
    if (existing && existing !== role) {
      blockingErrors.push(
        `Canonical release ${obligation.release.releaseId} crosses split arms`,
      );
      continue;
    }
    releaseArms.set(releaseKey, role);
    releaseAliases.set(releaseKey, {
      cohortKey,
      nodeId: obligation.release.nodeId,
      tagCommitOid: obligation.release.tagCommitOid,
      publishedAt: obligation.release.publishedAt,
      aliases: obligation.release.aliases,
    });
  }

  const assignments = new Map<string, ReleaseValidationSplitRole>();
  for (const [releaseKey, role] of releaseArms) {
    const release = releaseAliases.get(releaseKey);
    if (!release || release.aliases.length === 0) {
      blockingErrors.push(
        `Canonical split ${releaseKey} has no release alias`,
      );
      continue;
    }
    for (const tag of release.aliases) {
      const identityKey = releaseValidationReleaseIdentityKey({
        nodeId: release.nodeId,
        tag,
        tagCommitOid: release.tagCommitOid,
        publishedAt: release.publishedAt,
      });
      const mapKey = splitAssignmentMapKey(
        release.cohortKey,
        identityKey,
      );
      const existing = assignments.get(mapKey);
      if (existing && existing !== role) {
        blockingErrors.push(
          `Canonical split alias ${mapKey} maps to conflicting arms`,
        );
      } else {
        assignments.set(mapKey, role);
      }
    }
  }

  return {
    source: 'canonical_obligation_assignments',
    persisted: verification.valid && blockingErrors.length === 0,
    assignments,
    expectedAssignmentCount: releaseArms.size,
    persistedAssignmentCount: releaseArms.size,
    missingAssignmentKeys: [],
    extraAssignmentKeys: [],
    blockingErrors: [...new Set(blockingErrors)],
  };
}

function buildEvaluationSplitPlan(input: {
  denominatorLedger?: ReleaseValidationOpportunityDenominatorLedger;
  persistedAssignments?: ReleaseValidationSplitAssignmentRow[];
  thresholds: ValidationSampleThresholds;
}): EvaluationSplitPlan {
  const expected = new Map<string, {
    role: ReleaseValidationSplitRole;
    releaseIdentity: ReleaseValidationReleaseIdentity;
  }>();
  const rowsByCohort = new Map<
    string,
    Map<string, ReleaseValidationReleaseIdentity>
  >();
  for (const row of input.denominatorLedger?.rows ?? []) {
    const cohortKey = validationDenominatorStratumKey(row);
    const identity = releaseIdentityFromDenominatorRow(row);
    const releases = rowsByCohort.get(cohortKey) ?? new Map();
    releases.set(identity.key, identity);
    rowsByCohort.set(cohortKey, releases);
  }
  const developmentTarget = Math.max(
    1,
    Math.ceil(input.thresholds.uniqueReleases / 2),
  );
  for (const [cohortKey, releases] of rowsByCohort) {
    const ordered = [...releases.values()].sort((left, right) =>
      Date.parse(left.publishedAt) - Date.parse(right.publishedAt) ||
      left.key.localeCompare(right.key));
    for (const [index, identity] of ordered.entries()) {
      expected.set(splitAssignmentMapKey(cohortKey, identity.key), {
        role: index < developmentTarget ? 'development' : 'holdout',
        releaseIdentity: identity,
      });
    }
  }
  const derivedAssignments = new Map(
    [...expected.entries()].map(([key, value]) => [key, value.role]),
  );
  const persisted = input.persistedAssignments;
  if (!persisted || persisted.length === 0) {
    return {
      source: 'denominator_derived_non_authorizing',
      persisted: false,
      assignments: derivedAssignments,
      expectedAssignmentCount: expected.size,
      persistedAssignmentCount: 0,
      missingAssignmentKeys: [...expected.keys()].sort(),
      extraAssignmentKeys: [],
      blockingErrors: [],
    };
  }

  const blockingErrors: string[] = [];
  const persistedMap = new Map<string, ReleaseValidationSplitRole>();
  const seenAssignmentIds = new Set<string>();
  let previousContentHash: string | null = null;
  for (const row of persisted) {
    const identity = row.releaseIdentity;
    const expectedIdentityKey = releaseValidationReleaseIdentityKey(identity);
    const assignmentId = releaseValidationSplitAssignmentId(row);
    const mapKey = splitAssignmentMapKey(row.cohortKey, identity.key);
    const {
      contentHash: _contentHash,
      ...rowWithoutContentHash
    } = row;
    if (
      row.schemaVersion !== RELEASE_VALIDATION_SPLIT_LEDGER_SCHEMA_VERSION ||
      identity.key !== expectedIdentityKey ||
      row.assignmentId !== assignmentId ||
      !Number.isFinite(Date.parse(row.assignedAt)) ||
      !['development', 'holdout'].includes(row.role) ||
      row.previousContentHash !== previousContentHash ||
      row.contentHash !==
        releaseValidationSplitAssignmentContentHash(rowWithoutContentHash)
    ) {
      blockingErrors.push(
        `Split assignment ${row.assignmentId || mapKey} has invalid immutable content`,
      );
    }
    if (seenAssignmentIds.has(row.assignmentId) || persistedMap.has(mapKey)) {
      blockingErrors.push(`Duplicate persisted split assignment ${mapKey}`);
    }
    seenAssignmentIds.add(row.assignmentId);
    persistedMap.set(mapKey, row.role);
    previousContentHash = row.contentHash;
  }
  const missingAssignmentKeys = [...expected.keys()]
    .filter((key) => !persistedMap.has(key))
    .sort();
  const extraAssignmentKeys = [...persistedMap.keys()]
    .filter((key) => !expected.has(key))
    .sort();
  for (const [key, assignment] of expected) {
    const actualRole = persistedMap.get(key);
    if (actualRole && actualRole !== assignment.role) {
      blockingErrors.push(
        `Persisted split assignment ${key} violates the chronological split policy`,
      );
    }
  }
  if (missingAssignmentKeys.length > 0) {
    blockingErrors.push(
      `Persisted split ledger omits ${missingAssignmentKeys.length} release identity assignment(s)`,
    );
  }
  if (extraAssignmentKeys.length > 0) {
    blockingErrors.push(
      `Persisted split ledger contains ${extraAssignmentKeys.length} unknown release identity assignment(s)`,
    );
  }
  return {
    source: 'persisted_release_identity_assignments',
    persisted: blockingErrors.length === 0,
    assignments: blockingErrors.length === 0 ? persistedMap : derivedAssignments,
    expectedAssignmentCount: expected.size,
    persistedAssignmentCount: persisted.length,
    missingAssignmentKeys,
    extraAssignmentKeys,
    blockingErrors,
  };
}

function temporalPartitionReport(
  partition: Array<[string, EvaluationCase[]]>,
  role: ReleaseValidationSplitRole,
  kind: 'policy' | 'candidate',
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
): JsonRecord {
  const blockCases = partition.flatMap(([, rows]) => rows);
  const metrics = kind === 'policy'
    ? metricSet(blockCases, thresholds, qualityCriteria)
    : candidateScoreMetricSet(blockCases, thresholds, qualityCriteria);
  return {
    role,
    clusterCount: partition.length,
    clusterKeys: partition.map(([clusterKey]) => clusterKey),
    releaseIdentities: partition.map(([, rows]) => rows[0].latestReleaseIdentity),
    startAt: blockCases
      .map((item) => item.windowStartAt)
      .sort((left, right) => Date.parse(left) - Date.parse(right))[0] ?? null,
    endAt: blockCases
      .map((item) => item.windowEndAt)
      .sort((left, right) => Date.parse(right) - Date.parse(left))[0] ?? null,
    ...metrics,
  };
}

function splitAssignmentMapKey(
  cohortKey: string,
  releaseIdentityKey: string,
): string {
  return `${cohortKey}\0${releaseIdentityKey}`;
}

function releaseIdentityFromDenominatorRow(
  row: ReleaseValidationOpportunityDenominatorLedger['rows'][number],
): ReleaseValidationReleaseIdentity {
  const identity = {
    nodeId: row.releaseNodeId,
    tag: row.releaseTag,
    tagCommitOid: row.releaseTagCommitOid.toLowerCase(),
    publishedAt: row.releasePublishedAt,
  };
  return {
    ...identity,
    key: releaseValidationReleaseIdentityKey(identity),
  };
}

function temporalBlockAnalysis(
  cases: EvaluationCase[],
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
  kind: 'policy' | 'candidate',
  splitPlan?: EvaluationSplitPlan,
): JsonRecord {
  const clusters = new Map<string, EvaluationCase[]>();
  for (const item of cases) {
    const rows = clusters.get(item.latestReleaseIdentity.key) ?? [];
    rows.push(item);
    clusters.set(item.latestReleaseIdentity.key, rows);
  }
  const orderedClusters = [...clusters.entries()].sort(([, left], [, right]) =>
    Math.min(...left.map((item) => Date.parse(item.windowStartAt))) -
      Math.min(...right.map((item) => Date.parse(item.windowStartAt))) ||
    left[0].latestReleaseIdentity.publishedAt.localeCompare(
      right[0].latestReleaseIdentity.publishedAt,
    ) ||
    left[0].latestReleaseIdentity.key.localeCompare(
      right[0].latestReleaseIdentity.key,
    ));
  const developmentClusterTarget = Math.max(
    1,
    Math.ceil(thresholds.uniqueReleases / 2),
  );
  const missingAssignmentKeys: string[] = [];
  const partitions = splitPlan
    ? {
        development: orderedClusters.filter(([releaseIdentityKey, rows]) => {
          const assignmentKey = splitAssignmentMapKey(
            validationCaseStratumKey(rows[0]),
            releaseIdentityKey,
          );
          const role = splitPlan.assignments.get(assignmentKey);
          if (!role) missingAssignmentKeys.push(assignmentKey);
          return role === 'development';
        }),
        holdout: orderedClusters.filter(([releaseIdentityKey, rows]) =>
          splitPlan.assignments.get(splitAssignmentMapKey(
            validationCaseStratumKey(rows[0]),
            releaseIdentityKey,
          )) === 'holdout'),
      }
    : {
        development: orderedClusters.slice(
          0,
          Math.min(developmentClusterTarget, orderedClusters.length),
        ),
        holdout: orderedClusters.slice(
          Math.min(developmentClusterTarget, orderedClusters.length),
        ),
      };
  if (
    orderedClusters.length < 2 ||
    partitions.development.length === 0 ||
    partitions.holdout.length === 0 ||
    missingAssignmentKeys.length > 0
  ) {
    return {
      method: 'chronological_development_holdout',
      status: 'insufficient',
      qualityStatus: 'not_assessable',
      splitPolicy:
        'first_fixed_threshold_quota_development_all_later_release_identities_immutable_holdout',
      splitAssignmentSource: splitPlan?.source ?? 'surviving_case_legacy_fallback',
      splitAssignmentsPersisted: splitPlan?.persisted === true,
      missingAssignmentKeys: [...new Set(missingAssignmentKeys)].sort(),
      developmentClusterTarget,
      developmentClusterCount: partitions.development.length,
      holdoutClusterCount: partitions.holdout.length,
      development: partitions.development.length > 0
        ? temporalPartitionReport(
            partitions.development,
            'development',
            kind,
            scaledTemporalThresholds(thresholds, 2),
            qualityCriteria,
          )
        : null,
      holdout: partitions.holdout.length > 0
        ? temporalPartitionReport(
            partitions.holdout,
            'holdout',
            kind,
            scaledTemporalThresholds(thresholds, 2),
            qualityCriteria,
          )
        : null,
    };
  }
  const holdoutThresholds = scaledTemporalThresholds(thresholds, 2);
  const development = temporalPartitionReport(
    partitions.development,
    'development',
    kind,
    holdoutThresholds,
    qualityCriteria,
  );
  const holdout = temporalPartitionReport(
    partitions.holdout,
    'holdout',
    kind,
    holdoutThresholds,
    qualityCriteria,
  );
  const sufficient =
    asRecord(holdout.sampleSufficiency)?.status === 'sufficient';
  const qualityPassed = sufficient &&
    asRecord(holdout.qualityAssessment)?.status === 'passed';
  return {
    method: 'chronological_development_holdout',
    splitPolicy:
      'first_fixed_threshold_quota_development_all_later_release_identities_immutable_holdout',
    splitAssignmentSource: splitPlan?.source ?? 'surviving_case_legacy_fallback',
    splitAssignmentsPersisted: splitPlan?.persisted === true,
    missingAssignmentKeys: [],
    developmentClusterTarget,
    status: sufficient ? 'sufficient' : 'insufficient',
    qualityStatus: qualityPassed ? 'passed' : sufficient ? 'failed' : 'not_assessable',
    developmentClusterCount: partitions.development.length,
    holdoutClusterCount: partitions.holdout.length,
    thresholds: holdoutThresholds,
    development,
    holdout,
  };
}

function scaledTemporalThresholds(
  thresholds: ValidationSampleThresholds,
  blockCount: number,
): ValidationSampleThresholds {
  const scaled = (value: number) =>
    value === 0 ? 0 : Math.max(1, Math.ceil(value / blockCount));
  return {
    independent: scaled(thresholds.independent),
    uniqueReleases: scaled(thresholds.uniqueReleases),
    recommended: scaled(thresholds.recommended),
    adverse: scaled(thresholds.adverse),
    withheld: scaled(thresholds.withheld),
    safe: scaled(thresholds.safe),
  };
}

function evaluationGateAnalysis(
  nonOverlappingMetrics: JsonRecord,
  temporalBlocks: JsonRecord,
): JsonRecord {
  const nonOverlappingSufficient =
    asRecord(nonOverlappingMetrics.sampleSufficiency)?.status === 'sufficient';
  const nonOverlappingQualityPassed =
    asRecord(nonOverlappingMetrics.qualityAssessment)?.status === 'passed';
  const temporalSufficient = temporalBlocks.status === 'sufficient';
  const temporalQualityPassed = temporalBlocks.qualityStatus === 'passed';
  return {
    basis: [
      'maximum_non_overlapping_windows_by_earliest_end',
      'chronological_development_holdout',
    ],
    status: !nonOverlappingSufficient || !temporalSufficient
      ? 'insufficient'
      : nonOverlappingQualityPassed && temporalQualityPassed
        ? 'passed'
        : 'failed',
    nonOverlappingSufficient,
    nonOverlappingQualityPassed,
    temporalSufficient,
    temporalQualityPassed,
  };
}

function combinedEvaluationGateStatus(sections: unknown[]): 'passed' | 'failed' | 'insufficient' {
  const statuses = sections.map((section) => {
    const record = asRecord(section);
    return String(
      record?.gateStatus ??
      asRecord(record?.gateAnalysis)?.status ??
      'insufficient',
    );
  });
  if (statuses.includes('failed')) return 'failed';
  if (statuses.every((status) => status === 'passed')) return 'passed';
  return 'insufficient';
}

function stratumEvaluationSection(
  candidateCases: EvaluationCase[],
  key: string,
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
  splitPlan?: EvaluationSplitPlan,
): JsonRecord {
  const stratumCases = candidateCases.filter((item) =>
    validationCaseStratumKey(item) === key);
  return {
    present: stratumCases.length > 0,
    key,
    ...evaluationSection(stratumCases, thresholds, qualityCriteria, splitPlan),
  };
}

function candidateScoreStratumEvaluationSection(
  candidateCases: EvaluationCase[],
  key: string,
  thresholds: ValidationSampleThresholds,
  qualityCriteria: ValidationQualityCriteria,
  splitPlan?: EvaluationSplitPlan,
): JsonRecord {
  const stratumCases = candidateCases.filter((item) =>
    validationCaseStratumKey(item) === key);
  return {
    present: stratumCases.length > 0,
    key,
    ...candidateScoreEvaluationSection(
      stratumCases,
      thresholds,
      qualityCriteria,
      splitPlan,
    ),
  };
}

function observationCoverage(
  forecasts: ReleaseValidationForecastLedgerRow[],
  resolutions: Map<string, ObservationResolution>,
  generatedAtMs: number,
): JsonRecord {
  const horizonCases = new Map<ReleaseValidationHorizonCode, JsonRecord[]>(
    (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[])
      .map((code) => [code, []]),
  );
  for (const forecast of forecasts) {
    for (const horizonCode of Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[]) {
      const horizon = RELEASE_VALIDATION_HORIZONS[horizonCode];
      const windowEndMs = Date.parse(forecast.recorded_at) + horizon.durationMs;
      const latestObservationMs = windowEndMs + horizon.observationGraceMs;
      const resolution = resolutions.get(`${forecast.decision_id}\0${horizonCode}`) ?? {
        matured: null,
        indeterminate: [],
        nonValidatingProxyCount: 0,
      };
      const latestIndeterminate = resolution.indeterminate.at(-1);
      let status: string;
      let reason: string | null = null;
      let observedAt: string | null = null;
      let terminal = false;
      if (resolution.matured) {
        status = 'matured';
        observedAt = resolution.matured.observedAt;
      } else if (generatedAtMs > latestObservationMs) {
        status = 'grace_missed';
        reason = latestIndeterminate?.reason ?? 'grace_expired_without_matured_outcome';
        observedAt = latestIndeterminate?.observedAt ?? null;
        terminal = true;
      } else if (latestIndeterminate) {
        status = 'indeterminate';
        reason = latestIndeterminate.reason;
        observedAt = latestIndeterminate.observedAt;
      } else if (resolution.nonValidatingProxyCount > 0) {
        status = 'proxy_only';
        reason = 'classifier_proxy_outcome_not_validation_evidence';
      } else if (generatedAtMs < windowEndMs) {
        status = 'pending';
      } else {
        status = 'observation_grace_open';
      }
      horizonCases.get(horizonCode)!.push({
        horizonCode,
        releaseTag: validationTargetReleaseTag(forecast),
        decisionId: forecast.decision_id,
        opportunityCode: forecast.opportunity_code,
      status,
      reason,
      observedAt,
      terminal,
      fatal: resolution.matured ? false : latestIndeterminate?.fatal === true,
        windowEndAt: new Date(windowEndMs).toISOString(),
        latestObservationAt: new Date(latestObservationMs).toISOString(),
        persistedIndeterminateCount: resolution.indeterminate.length,
        nonValidatingProxyCount: resolution.nonValidatingProxyCount,
        persistedGraceMissed: resolution.indeterminate.some((item) =>
          item.reason === 'observation_grace_window_missed'),
      });
    }
  }

  const horizons = Object.fromEntries(
    [...horizonCases.entries()].map(([code, cases]) => {
      return [code, {
        ...horizonObservationCoverageSummary(cases),
        byOpportunity: Object.fromEntries(
          (Object.keys(RELEASE_VALIDATION_OPPORTUNITIES) as
            ReleaseValidationOpportunityCode[]).map((opportunityCode) => {
            const opportunityCases = cases.filter((item) =>
              item.opportunityCode === opportunityCode);
            return [opportunityCode, {
              ...horizonObservationCoverageSummary(opportunityCases),
              cases: opportunityCases,
            }];
          }),
        ),
        cases,
      }];
    }),
  );

  const combinedCases = forecasts.map((forecast) => {
    const cases = (Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[])
      .map((code) => (asRecord(horizons[code])?.cases as JsonRecord[] | undefined)?.find(
        (item) => item.decisionId === forecast.decision_id,
      ))
      .filter((item): item is JsonRecord => item != null);
    const complete = cases.length === Object.keys(RELEASE_VALIDATION_HORIZONS).length &&
      cases.every((item) => item.status === 'matured');
    const fatal = cases.some((item) => item.fatal === true);
    const terminal = cases.some((item) => item.terminal === true);
    const indeterminate = cases.some((item) => item.status === 'indeterminate');
    return {
      releaseTag: validationTargetReleaseTag(forecast),
      decisionId: forecast.decision_id,
      opportunityCode: forecast.opportunity_code,
      status: complete
        ? 'complete'
        : fatal
          ? 'fatal_indeterminate'
        : terminal
          ? 'terminal_attrition'
          : indeterminate
            ? 'indeterminate'
            : 'incomplete',
      horizons: cases.map((item) => ({
        horizonCode: item.horizonCode,
        status: item?.status,
        reason: item?.reason,
      })),
    };
  });
  return {
    horizons,
    combined: {
      ...combinedObservationCoverageSummary(combinedCases),
      byOpportunity: Object.fromEntries(
        (Object.keys(RELEASE_VALIDATION_OPPORTUNITIES) as
          ReleaseValidationOpportunityCode[]).map((opportunityCode) => {
          const opportunityCases = combinedCases.filter((item) =>
            item.opportunityCode === opportunityCode);
          return [opportunityCode, {
            ...combinedObservationCoverageSummary(opportunityCases),
            cases: opportunityCases,
          }];
        }),
      ),
      cases: combinedCases,
    },
  };
}

function horizonObservationCoverageSummary(cases: JsonRecord[]): JsonRecord {
  const byReason = new Map<string, number>();
  for (const item of cases) {
    const reason = nullableString(item.reason);
    if (reason) byReason.set(reason, (byReason.get(reason) ?? 0) + 1);
  }
  const maturedCount = cases.filter((item) => item.status === 'matured').length;
  return {
    expectedCount: cases.length,
    maturedCount,
    indeterminateCount: cases.filter((item) =>
      item.status === 'indeterminate').length,
    graceMissedCount: cases.filter((item) =>
      item.status === 'grace_missed').length,
    pendingCount: cases.filter((item) => item.status === 'pending').length,
    observationGraceOpenCount: cases.filter((item) =>
      item.status === 'observation_grace_open').length,
    proxyOnlyCount: cases.filter((item) =>
      Number(item.nonValidatingProxyCount ?? 0) > 0).length,
    nonValidatingProxyCount: cases.reduce(
      (sum, item) => sum + Number(item.nonValidatingProxyCount ?? 0),
      0,
    ),
    persistedIndeterminateCount: cases.reduce(
      (sum, item) => sum + Number(item.persistedIndeterminateCount ?? 0),
      0,
    ),
    persistedGraceMissedCount: cases.filter((item) =>
      item.persistedGraceMissed === true).length,
    fatalIndeterminateCount: cases.filter((item) => item.fatal === true).length,
    coverageRate: wilsonInterval(maturedCount, cases.length),
    indeterminateByReason: [...byReason.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([reason, count]) => ({ reason, count })),
  };
}

function combinedObservationCoverageSummary(cases: JsonRecord[]): JsonRecord {
  const completeCaseCount = cases.filter((item) =>
    item.status === 'complete').length;
  return {
    expectedCount: cases.length,
    completeCaseCount,
    terminalAttritionCount: cases.filter((item) =>
      item.status === 'terminal_attrition').length,
    fatalIndeterminateCount: cases.filter((item) =>
      item.status === 'fatal_indeterminate').length,
    indeterminateCount: cases.filter((item) =>
      item.status === 'indeterminate').length,
    incompleteCount: cases.filter((item) =>
      item.status === 'incomplete').length,
    completeCaseRate: wilsonInterval(completeCaseCount, cases.length),
  };
}

interface ProspectivePromotionAssessment {
  status: 'passed' | 'failed' | 'insufficient';
  failureClass: string | null;
  blockingErrors: string[];
  report: JsonRecord;
}

function assessCanonicalProspectivePromotion(input: {
  proof: ReleaseValidationProofBundle;
  evaluationPurpose: 'production' | 'calibration';
  forecasts: ReleaseValidationForecastLedgerRow[];
  allForecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
  splitPlan: EvaluationSplitPlan;
  currentStratumKey: string;
  generatedAt: string;
  generatedAtMs: number;
  thresholds: ValidationSampleThresholds;
  qualityCriteria: ValidationQualityCriteria;
  horizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
  combinedCases: EvaluationCase[];
  candidateHorizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
  candidateCombinedCases: EvaluationCase[];
}): ProspectivePromotionAssessment {
  const verification = verifyReleaseValidationProofBundle(input.proof);
  const blockingErrors = verification.valid
    ? []
    : verification.problems.map((problem) =>
        `Canonical validation proof: ${problem}`);
  blockingErrors.push(...input.splitPlan.blockingErrors);
  blockingErrors.push(...canonicalProofLegacyLinkProblems({
    proof: input.proof,
    forecasts: input.allForecasts,
    observations: input.observations,
  }));

  const retiredEpochIds = new Set(
    input.proof.retirements.map((retirement) => retirement.proofEpochId),
  );
  const activeCohorts = input.proof.cohorts
    .filter((cohort) =>
      !retiredEpochIds.has(cohort.proofEpochId) &&
      Date.parse(cohort.startsAt) <= input.generatedAtMs &&
      (
        cohort.retiredAt == null ||
        Date.parse(cohort.retiredAt) > input.generatedAtMs
      ))
    .slice()
    .sort((left, right) =>
      left.epochSequence - right.epochSequence ||
      left.cohortId.localeCompare(right.cohortId));
  const activeEpochIds = [...new Set(
    activeCohorts.map((cohort) => cohort.proofEpochId),
  )];
  if (activeEpochIds.length > 1) {
    blockingErrors.push(
      `Canonical validation proof has ${activeEpochIds.length} active epochs`,
    );
  }
  const policiesById = new Map(
    input.proof.policies.map((policy) => [policy.policyId, policy]),
  );
  const cohortEvaluations = activeCohorts.map((cohort) => {
    const evaluation = evaluateCanonicalProspectiveCohort({
      proof: input.proof,
      cohort,
      policy: policiesById.get(cohort.policyId) ?? null,
      generatedAtMs: input.generatedAtMs,
      thresholds: input.thresholds,
      qualityCriteria: input.qualityCriteria,
      splitPlan: input.splitPlan,
      horizonCases: input.horizonCases,
      candidateHorizonCases: input.candidateHorizonCases,
    });
    blockingErrors.push(...evaluation.blockingErrors);
    return evaluation.report;
  });
  const productionCohorts = cohortEvaluations.filter((row) =>
    row.purpose === 'production');
  const calibrationCohorts = cohortEvaluations.filter((row) =>
    row.purpose === 'calibration');
  const cohortStatuses = cohortEvaluations.map((row) =>
    String(row.status ?? 'insufficient'));
  const proofComplete =
    verification.valid &&
    input.splitPlan.persisted &&
    activeEpochIds.length === 1 &&
    activeCohorts.length > 0 &&
    blockingErrors.length === 0;
  const calibrationOnly = input.evaluationPurpose === 'calibration';
  const status: ProspectivePromotionAssessment['status'] =
    blockingErrors.length > 0 || cohortStatuses.includes('failed')
      ? 'failed'
      : calibrationOnly ||
        !proofComplete ||
        productionCohorts.length === 0 ||
        cohortStatuses.some((value) => value !== 'passed')
        ? 'insufficient'
        : 'passed';
  const failureClass = status === 'failed'
    ? blockingErrors.length > 0
      ? 'canonical_proof_integrity'
      : 'production_cohort_quality'
    : status === 'insufficient'
      ? calibrationOnly
        ? 'calibration_non_authorizing'
        : activeCohorts.length === 0
          ? 'canonical_cohort_registry_missing'
          : productionCohorts.length === 0
            ? 'production_cohort_missing'
            : 'production_cohort_incomplete'
      : null;
  const authorized = status === 'passed' && !calibrationOnly;
  const activeCohortIds = activeCohorts.map((cohort) => cohort.cohortId);
  const activeCohortIdSet = new Set(activeCohortIds);
  const requiredCellKeys = activeCohorts.flatMap((cohort) =>
    cohort.requiredCellIds.map((cellId) =>
      releaseValidationCohortCellKey(cohort.cohortId, cellId)));
  const observationBatchIds = input.proof.observationBatches
    .filter((batch) =>
      activeCohortIdSet.has(batch.cohortId) &&
      Date.parse(batch.observedAt) <= input.generatedAtMs)
    .map((batch) => batch.batchId);
  const outcomeIds = input.proof.outcomes
    .filter((outcome) =>
      activeCohortIdSet.has(outcome.cohortId) &&
      Date.parse(outcome.observedAt) <= input.generatedAtMs)
    .map((outcome) => outcome.outcomeId);

  return {
    status,
    failureClass,
    blockingErrors: [...new Set(blockingErrors)],
    report: {
      schemaVersion: 2,
      authority: 'canonical_release_validation_proof',
      evaluationPurpose: input.evaluationPurpose,
      evaluatedAt: input.generatedAt,
      proofComplete,
      proofVerification: {
        valid: verification.valid,
        problems: verification.problems,
      },
      activeProofEpochIds: activeEpochIds,
      activeCohortIds,
      requiredCellKeys,
      observationBatchIds,
      outcomeIds,
      splitAssignments: {
        source: input.splitPlan.source,
        persisted: input.splitPlan.persisted,
        expectedAssignmentCount: input.splitPlan.expectedAssignmentCount,
        persistedAssignmentCount: input.splitPlan.persistedAssignmentCount,
        missingAssignmentKeys: input.splitPlan.missingAssignmentKeys,
        extraAssignmentKeys: input.splitPlan.extraAssignmentKeys,
        errors: input.splitPlan.blockingErrors,
      },
      obligationPolicy:
        'every_closed_capture_window_and_due_outcome_is_accounted_for_while_each_required_cell_meets_policy_and_candidate_quality_gates',
      cohorts: cohortEvaluations,
      productionSummary: {
        activeCohortCount: activeCohorts.length,
        productionCohortCount: productionCohorts.length,
        calibrationCohortCount: calibrationCohorts.length,
        currentStratumCohortCount: cohortEvaluations.filter((row) =>
          row.cohortKey === input.currentStratumKey).length,
        everyActiveCohortPassed:
          activeCohorts.length > 0 &&
          cohortStatuses.every((value) => value === 'passed'),
        calibrationExcludedFromAuthorization: true,
      },
      promotionDecision: {
        decision: calibrationOnly
          ? 'calibration_only'
          : authorized
            ? 'authorize_production'
            : 'deny_production',
        productionAuthorized: authorized,
        insufficientAuthorizesProduction: false,
        calibrationAuthorizesProduction: false,
        status,
        failureClass,
      },
    },
  };
}

function evaluateCanonicalProspectiveCohort(input: {
  proof: ReleaseValidationProofBundle;
  cohort: ReleaseValidationCohort;
  policy: ReleaseValidationPolicy | null;
  generatedAtMs: number;
  thresholds: ValidationSampleThresholds;
  qualityCriteria: ValidationQualityCriteria;
  splitPlan: EvaluationSplitPlan;
  horizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
  candidateHorizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
}): { report: JsonRecord; blockingErrors: string[] } {
  const blockingErrors: string[] = [];
  const cohortKey = canonicalValidationCohortKey(input.cohort);
  if (!cohortKey) {
    blockingErrors.push(
      `Canonical cohort ${input.cohort.cohortId} has an invalid stratum`,
    );
  }
  if (!input.policy) {
    blockingErrors.push(
      `Canonical cohort ${input.cohort.cohortId} has no policy`,
    );
  }
  const policy = input.policy;
  const canonicalForecasts = input.proof.forecasts.filter((forecast) =>
    forecast.cohortId === input.cohort.cohortId);
  const decisionIds = new Set(
    canonicalForecasts.flatMap((forecast) => {
      const link = canonicalForecastLegacyLink(forecast.forecast);
      return link ? [link.decisionId] : [];
    }),
  );
  const cellReports = (policy?.requiredCells ?? []).map((cell) => {
    if (!(cell.horizonCode in RELEASE_VALIDATION_HORIZONS)) {
      blockingErrors.push(
        `Canonical policy cell ${cell.cellId} has an unsupported horizon`,
      );
      return {
        cellId: cell.cellId,
        opportunityCode: cell.opportunityCode,
        horizonCode: cell.horizonCode,
        status: 'failed',
      };
    }
    const horizonCode = cell.horizonCode as ReleaseValidationHorizonCode;
    const policyCases = input.horizonCases.get(horizonCode)!.filter((item) =>
      item.opportunityCode === cell.opportunityCode &&
      decisionIds.has(item.decisionId));
    const candidateCases = input.candidateHorizonCases
      .get(horizonCode)!
      .filter((item) =>
        item.opportunityCode === cell.opportunityCode &&
        decisionIds.has(item.decisionId));
    const policyQuality = stratumEvaluationSection(
      policyCases,
      cohortKey ?? 'invalid',
      input.thresholds,
      input.qualityCriteria,
      input.splitPlan,
    );
    const candidateQuality = candidateScoreStratumEvaluationSection(
      candidateCases,
      cohortKey ?? 'invalid',
      input.thresholds,
      input.qualityCriteria,
      input.splitPlan,
    );
    const qualityStatus = combinedEvaluationGateStatus([
      policyQuality,
      candidateQuality,
    ]);
    const coverage = canonicalCellCoverage({
      proof: input.proof,
      cohort: input.cohort,
      cellId: cell.cellId,
      generatedAtMs: input.generatedAtMs,
    });
    blockingErrors.push(...coverage.blockingErrors);
    const status = qualityStatus === 'failed' || coverage.status === 'failed'
      ? 'failed'
      : qualityStatus === 'passed' && coverage.status === 'passed'
        ? 'passed'
        : 'insufficient';
    return {
      cellId: cell.cellId,
      opportunityCode: cell.opportunityCode,
      horizonCode,
      status,
      qualityStatus,
      coverage: coverage.report,
      policy: policyQuality,
      candidate: candidateQuality,
    };
  });
  const cellStatuses = cellReports.map((cell) =>
    String(cell.status ?? 'insufficient'));
  const status = blockingErrors.length > 0 || cellStatuses.includes('failed')
    ? 'failed'
    : cellReports.length > 0 &&
      cellStatuses.every((value) => value === 'passed')
      ? 'passed'
      : 'insufficient';
  const purpose = policy?.developmentArm === 'calibration'
    ? 'calibration'
    : 'production';
  return {
    blockingErrors,
    report: {
      cohortId: input.cohort.cohortId,
      cohortKey,
      proofEpochId: input.cohort.proofEpochId,
      policyId: input.cohort.policyId,
      purpose,
      startsAt: input.cohort.startsAt,
      retiredAt: input.cohort.retiredAt,
      requiredCellCount: input.cohort.requiredCellCount,
      canonicalForecastCount: canonicalForecasts.length,
      linkedDecisionCount: decisionIds.size,
      status,
      cells: cellReports,
      errors: blockingErrors,
    },
  };
}

function canonicalCellCoverage(input: {
  proof: ReleaseValidationProofBundle;
  cohort: ReleaseValidationCohort;
  cellId: string;
  generatedAtMs: number;
}): {
  status: 'passed' | 'failed' | 'insufficient';
  report: JsonRecord;
  blockingErrors: string[];
} {
  const blockingErrors: string[] = [];
  const obligations = input.proof.obligations
    .filter((obligation) =>
      obligation.cohortId === input.cohort.cohortId &&
      obligation.cellId === input.cellId)
    .slice()
    .sort((left, right) =>
      Date.parse(left.release.publishedAt) -
        Date.parse(right.release.publishedAt) ||
      left.obligationId.localeCompare(right.obligationId));
  const assignmentsByObligation = new Map(
    input.proof.splitAssignments.map((assignment) => [
      assignment.obligationId,
      assignment,
    ]),
  );
  const forecastsByObligation = new Map(
    input.proof.forecasts.map((forecast) => [
      forecast.obligationId,
      forecast,
    ]),
  );
  const outcomesByForecast = new Map(
    input.proof.outcomes.map((outcome) => [outcome.forecastId, outcome]),
  );
  const batches = input.proof.observationBatches.filter((batch) =>
    batch.cohortId === input.cohort.cohortId &&
    Date.parse(batch.observedAt) <= input.generatedAtMs);
  const cases = obligations.map((obligation) => {
    const assignment = assignmentsByObligation.get(obligation.obligationId);
    const forecast = forecastsByObligation.get(obligation.obligationId);
    const outcome = forecast
      ? outcomesByForecast.get(forecast.forecastId)
      : undefined;
    if (!assignment) {
      blockingErrors.push(
        `Canonical obligation ${obligation.obligationId} has no split`,
      );
    }
    if (!forecast) {
      return {
        obligationId: obligation.obligationId,
        releaseId: obligation.release.releaseId,
        arm: assignment?.arm ?? null,
        status: input.generatedAtMs <
            Date.parse(obligation.closesAtExclusive)
          ? 'capture_window_open'
          : 'capture_attrition',
        terminal: input.generatedAtMs >=
          Date.parse(obligation.closesAtExclusive),
      };
    }
    if (!outcome) {
      return {
        obligationId: obligation.obligationId,
        releaseId: obligation.release.releaseId,
        arm: assignment?.arm ?? null,
        forecastId: forecast.forecastId,
        status: input.generatedAtMs < Date.parse(obligation.outcomeDueAt)
          ? 'outcome_pending'
          : 'outcome_overdue',
        terminal: false,
      };
    }
    const coveringBatches = batches.filter((batch) =>
      batch.cells.some((cell) =>
        cell.forecastId === forecast.forecastId &&
        cell.outcomeId === outcome.outcomeId &&
        cell.disposition === 'observed'));
    if (coveringBatches.length === 0) {
      blockingErrors.push(
        `Canonical outcome ${outcome.outcomeId} is absent from every ` +
        `observation batch`,
      );
    }
    return {
      obligationId: obligation.obligationId,
      releaseId: obligation.release.releaseId,
      arm: assignment?.arm ?? null,
      forecastId: forecast.forecastId,
      outcomeId: outcome.outcomeId,
      status: outcome.status,
      terminal: true,
      observationBatchIds: coveringBatches.map((batch) => batch.batchId),
    };
  });
  const captureAttritionCount = cases.filter((item) =>
    item.status === 'capture_attrition').length;
  const overdueCount = cases.filter((item) =>
    item.status === 'outcome_overdue').length;
  const censoredCount = cases.filter((item) =>
    item.status === 'censored').length;
  const status = blockingErrors.length > 0
    ? 'failed'
    : obligations.length === 0 ||
      captureAttritionCount > 0 ||
      overdueCount > 0 ||
      censoredCount > 0
      ? 'insufficient'
      : 'passed';
  return {
    status,
    blockingErrors,
    report: {
      status,
      obligationCount: obligations.length,
      forecastCount: cases.filter((item) => 'forecastId' in item).length,
      terminalOutcomeCount: cases.filter((item) =>
        item.status === 'safe' || item.status === 'adverse').length,
      censoredCount,
      captureAttritionCount,
      overdueCount,
      pendingCount: cases.filter((item) =>
        item.status === 'capture_window_open' ||
        item.status === 'outcome_pending').length,
      cases,
      errors: blockingErrors,
    },
  };
}

function canonicalProofLegacyLinkProblems(input: {
  proof: ReleaseValidationProofBundle;
  forecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
}): string[] {
  const problems: string[] = [];
  const forecastsByDecision = new Map(
    input.forecasts.map((forecast) => [forecast.decision_id, forecast]),
  );
  const observationsById = new Map(
    input.observations.map((observation) => [
      observation.observation_id,
      observation,
    ]),
  );
  const obligationsById = new Map(
    input.proof.obligations.map((obligation) => [
      obligation.obligationId,
      obligation,
    ]),
  );
  const cohortsById = new Map(
    input.proof.cohorts.map((cohort) => [cohort.cohortId, cohort]),
  );
  const canonicalForecastsById = new Map(
    input.proof.forecasts.map((forecast) => [
      forecast.forecastId,
      forecast,
    ]),
  );
  for (const forecast of input.proof.forecasts) {
    const link = canonicalForecastLegacyLink(forecast.forecast);
    const legacy = link ? forecastsByDecision.get(link.decisionId) : null;
    const obligation = obligationsById.get(forecast.obligationId);
    const cohort = cohortsById.get(forecast.cohortId);
    if (
      !link ||
      !legacy ||
      legacy.content_hash !== link.contentHash ||
      !obligation ||
      !cohort ||
      legacy.opportunity_code !== obligation.opportunityCode ||
      legacy.recorded_at !== forecast.recordedAt ||
      legacy.score_model_version !== cohort.modelVersion ||
      legacy.prompt_version !== cohort.promptVersion ||
      normalizeCodeRevision(legacy.code_revision) !==
        normalizeCodeRevision(cohort.codeRevision) ||
      legacy.latest_release_published_at !==
        forecast.latestRelease.publishedAt ||
      !forecast.latestRelease.aliases.includes(legacy.latest_release_tag)
    ) {
      problems.push(
        `Canonical forecast ${forecast.forecastId} lacks its exact legacy ` +
        `decision evidence`,
      );
    }
  }
  for (const outcome of input.proof.outcomes) {
    const forecast = canonicalForecastsById.get(outcome.forecastId);
    const obligation = obligationsById.get(outcome.obligationId);
    const payload = asRecord(outcome.outcome);
    const linkedForecast = asRecord(payload?.legacyForecast);
    const linkedObservation = asRecord(payload?.legacyObservation);
    const observationId = typeof linkedObservation?.observationId === 'string'
      ? linkedObservation.observationId
      : null;
    const legacy = observationId
      ? observationsById.get(observationId)
      : null;
    const parsedLegacy = legacy ? asRecord(parseJson(legacy.outcome_json)) : null;
    const expectedStatus = legacy?.status === 'matured'
      ? parsedLegacy?.adverse === true
        ? 'adverse'
        : parsedLegacy?.adverse === false
          ? 'safe'
          : null
      : legacy?.status === 'indeterminate'
        ? 'censored'
        : null;
    const forecastLink = forecast
      ? canonicalForecastLegacyLink(forecast.forecast)
      : null;
    if (
      !forecast ||
      !obligation ||
      !forecastLink ||
      !legacy ||
      linkedForecast?.decisionId !== forecastLink.decisionId ||
      linkedForecast?.contentHash !== forecastLink.contentHash ||
      linkedObservation?.contentHash !== legacy.content_hash ||
      linkedObservation?.status !== legacy.status ||
      linkedObservation?.observedAt !== legacy.observed_at ||
      legacy.decision_id !== forecastLink.decisionId ||
      legacy.horizon_code !== obligation.horizonCode ||
      outcome.observedAt !== legacy.observed_at ||
      expectedStatus !== outcome.status ||
      outcome.evidenceContentHashes.length !== 1 ||
      outcome.evidenceContentHashes[0] !== legacy.content_hash
    ) {
      problems.push(
        `Canonical outcome ${outcome.outcomeId} lacks its exact legacy ` +
        `observation evidence`,
      );
    }
  }
  return problems;
}

function canonicalForecastLegacyLink(
  value: ReleaseValidationProofJsonValue,
): { decisionId: string; contentHash: string } | null {
  const payload = asRecord(value);
  const legacy = asRecord(payload?.legacyForecast);
  const decisionId = typeof legacy?.decisionId === 'string'
    ? legacy.decisionId
    : null;
  const contentHash = typeof legacy?.contentHash === 'string'
    ? legacy.contentHash
    : null;
  return decisionId && contentHash && /^[0-9a-f]{64}$/.test(contentHash)
    ? { decisionId, contentHash }
    : null;
}

function canonicalValidationCohortKey(
  cohort: ReleaseValidationCohort,
): string | null {
  const codeRevision = normalizeCodeRevision(cohort.codeRevision);
  if (!codeRevision) return null;
  return `${cohort.modelVersion}/prompt-${cohort.promptVersion}/` +
    `revision-${codeRevision}`;
}

function assessProspectivePromotion(input: {
  proof?: ReleaseValidationProspectiveProofInput;
  forecasts: ReleaseValidationForecastLedgerRow[];
  allForecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
  resolutions: Map<string, ObservationResolution>;
  denominatorLedger?: ReleaseValidationOpportunityDenominatorLedger;
  splitPlan: EvaluationSplitPlan;
  currentStratumKey: string;
  generatedAtMs: number;
  thresholds: ValidationSampleThresholds;
  qualityCriteria: ValidationQualityCriteria;
  horizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
  combinedCases: EvaluationCase[];
  candidateHorizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
  candidateCombinedCases: EvaluationCase[];
}): ProspectivePromotionAssessment {
  const proof = input.proof;
  const cohortProof = validateProspectiveCohortLedger(
    proof?.cohorts,
    input.denominatorLedger,
    input.currentStratumKey,
  );
  const batchCoverage = exactObservationBatchCoverage({
    forecasts: input.allForecasts,
    eligibleForecasts: input.forecasts,
    observations: input.observations,
    batches: proof?.observationBatches,
    verification: proof?.observationBatchVerification,
    generatedAtMs: input.generatedAtMs,
  });
  const manifest = buildReleaseValidationLedgerManifest({
    forecasts: input.allForecasts,
    observations: input.observations,
    batches: proof?.observationBatches ?? [],
    denominatorLedger: input.denominatorLedger,
    cohorts: proof?.cohorts ?? [],
    splitAssignments: proof?.splitAssignments ?? [],
  });
  const manifestProof = validateExpectedLedgerManifest(
    proof?.expectedLedgerManifest,
    manifest,
  );
  const reconciliation = validationReconciliationReport(
    proof?.reconciliationRows ?? [],
  );
  const cohortRows = cohortProof.rows;
  const cohortEvaluations = cohortRows.map((cohort) =>
    evaluateProspectiveCohort({
      cohort,
      denominatorLedger: input.denominatorLedger,
      forecasts: input.forecasts,
      resolutions: input.resolutions,
      generatedAtMs: input.generatedAtMs,
      thresholds: input.thresholds,
      qualityCriteria: input.qualityCriteria,
      splitPlan: input.splitPlan,
      horizonCases: input.horizonCases,
      combinedCases: input.combinedCases,
      candidateHorizonCases: input.candidateHorizonCases,
      candidateCombinedCases: input.candidateCombinedCases,
    }));
  const productionCohorts = cohortEvaluations.filter((row) =>
    row.purpose === 'production');
  const calibrationCohorts = cohortEvaluations.filter((row) =>
    row.purpose === 'calibration');
  const activeProduction = productionCohorts.filter((row) =>
    row.lifecycle === 'active');
  const retiredProduction = productionCohorts.filter((row) =>
    row.lifecycle === 'retired');
  const productionCohortFailure = productionCohorts.some((row) =>
    row.status === 'failed');
  const productionCohortInsufficient =
    activeProduction.length === 0 ||
    activeProduction.some((row) => row.status !== 'passed') ||
    retiredProduction.some((row) =>
      row.status !== 'passed' && row.status !== 'zero_obligation');
  const blockingErrors = [
    ...cohortProof.blockingErrors,
    ...input.splitPlan.blockingErrors,
    ...batchCoverage.blockingErrors,
    ...manifestProof.blockingErrors,
    ...reconciliation.blockingErrors,
  ];
  const proofComplete =
    cohortProof.persisted &&
    input.splitPlan.persisted &&
    batchCoverage.complete &&
    manifestProof.verified;
  const cohortResultsAuthoritative =
    cohortProof.persisted &&
    input.splitPlan.persisted;
  const evaluationPurpose = proof?.evaluationPurpose ?? 'production';
  const calibrationOnly = evaluationPurpose === 'calibration';
  const status: ProspectivePromotionAssessment['status'] =
    blockingErrors.length > 0 ||
      (cohortResultsAuthoritative && productionCohortFailure)
      ? 'failed'
      : calibrationOnly ||
        !proofComplete ||
        productionCohortInsufficient
        ? 'insufficient'
        : 'passed';
  const failureClass = status === 'failed'
    ? blockingErrors.length > 0
      ? 'prospective_proof_reconciliation'
      : 'production_cohort_quality'
    : status === 'insufficient'
      ? calibrationOnly
        ? 'calibration_non_authorizing'
        : !cohortProof.persisted
          ? 'cohort_registry_missing'
          : !input.splitPlan.persisted
            ? 'split_assignment_proof_missing'
            : !batchCoverage.complete
              ? 'batch_coverage_incomplete'
              : !manifestProof.verified
                ? 'ledger_manifest_missing'
                : 'production_cohort_incomplete'
      : null;
  const authorized = status === 'passed' && !calibrationOnly;

  return {
    status,
    failureClass,
    blockingErrors,
    report: {
      schemaVersion: 1,
      evaluationPurpose,
      proofComplete,
      cohortLedger: cohortProof.report,
      splitAssignments: {
        source: input.splitPlan.source,
        persisted: input.splitPlan.persisted,
        expectedAssignmentCount: input.splitPlan.expectedAssignmentCount,
        persistedAssignmentCount: input.splitPlan.persistedAssignmentCount,
        missingAssignmentKeys: input.splitPlan.missingAssignmentKeys,
        extraAssignmentKeys: input.splitPlan.extraAssignmentKeys,
        errors: input.splitPlan.blockingErrors,
      },
      obligationPolicy:
        'every_due_release_opportunity_by_horizon_obligation_must_have_persisted_terminal_evidence',
      observationBatchCoverage: batchCoverage.report,
      ledgerManifest: {
        actual: manifest,
        expectedPresent: proof?.expectedLedgerManifest != null,
        verified: manifestProof.verified,
        errors: manifestProof.blockingErrors,
      },
      reconciliation: reconciliation.report,
      cohorts: cohortEvaluations,
      productionSummary: {
        activeCohortCount: activeProduction.length,
        retiredCohortCount: retiredProduction.length,
        calibrationCohortCount: calibrationCohorts.length,
        everyActiveProductionCohortPassed:
          activeProduction.length > 0 &&
          activeProduction.every((row) => row.status === 'passed'),
        everyRetiredProductionCohortPassedOrZeroObligation:
          retiredProduction.every((row) =>
            row.status === 'passed' || row.status === 'zero_obligation'),
        calibrationExcludedFromAuthorization: true,
      },
      promotionDecision: {
        decision: calibrationOnly
          ? 'calibration_only'
          : authorized
            ? 'authorize_production'
            : 'deny_production',
        productionAuthorized: authorized,
        insufficientAuthorizesProduction: false,
        calibrationAuthorizesProduction: false,
        status,
        failureClass,
      },
    },
  };
}

function validateProspectiveCohortLedger(
  persistedRows: ReleaseValidationCohortLedgerRow[] | undefined,
  denominatorLedger: ReleaseValidationOpportunityDenominatorLedger | undefined,
  currentStratumKey: string,
): {
  persisted: boolean;
  rows: ReleaseValidationCohortLedgerRow[];
  blockingErrors: string[];
  report: JsonRecord;
} {
  const denominatorKeys = [...new Set(
    (denominatorLedger?.rows ?? []).map((row) =>
      validationDenominatorStratumKey(row)),
  )].sort();
  if (!persistedRows || persistedRows.length === 0) {
    const derivedKeys = [...new Set([...denominatorKeys, currentStratumKey])].sort();
    const rows: ReleaseValidationCohortLedgerRow[] = derivedKeys.map((cohortKey) => {
      const parsed = parseValidationCohortKey(cohortKey);
      return {
        schemaVersion: RELEASE_VALIDATION_COHORT_LEDGER_SCHEMA_VERSION,
        cohortKey,
        modelVersion: parsed.modelVersion,
        promptVersion: parsed.promptVersion,
        codeRevision: parsed.codeRevision,
        purpose: 'production' as const,
        lifecycle: cohortKey === currentStratumKey ? 'active' as const : 'retired' as const,
        activatedAt: denominatorCohortStart(denominatorLedger, cohortKey) ??
          '1970-01-01T00:00:00.000Z',
        retiredAt: cohortKey === currentStratumKey
          ? null
          : denominatorCohortEnd(denominatorLedger, cohortKey),
        previousContentHash: null,
        contentHash: '',
      };
    });
    return {
      persisted: false,
      rows,
      blockingErrors: [],
      report: {
        persisted: false,
        source: 'derived_non_authorizing',
        rowCount: 0,
        missingCohortKeys: derivedKeys,
        errors: [],
      },
    };
  }
  const blockingErrors: string[] = [];
  const seen = new Set<string>();
  let previousContentHash: string | null = null;
  for (const row of persistedRows) {
    const normalizedRevision = normalizeCodeRevision(row.codeRevision);
    const expectedKey = `${row.modelVersion}/prompt-${row.promptVersion}/` +
      `revision-${normalizedRevision ?? 'invalid'}`;
    const { contentHash: _contentHash, ...withoutContentHash } = row;
    if (
      row.schemaVersion !== RELEASE_VALIDATION_COHORT_LEDGER_SCHEMA_VERSION ||
      !row.modelVersion ||
      !Number.isInteger(row.promptVersion) ||
      !normalizedRevision ||
      row.codeRevision !== normalizedRevision ||
      row.cohortKey !== expectedKey ||
      !['production', 'calibration'].includes(row.purpose) ||
      !['active', 'retired'].includes(row.lifecycle) ||
      !Number.isFinite(Date.parse(row.activatedAt)) ||
      (
        row.lifecycle === 'active'
          ? row.retiredAt !== null
          : !row.retiredAt ||
            !Number.isFinite(Date.parse(row.retiredAt)) ||
            Date.parse(row.retiredAt) < Date.parse(row.activatedAt)
      ) ||
      row.previousContentHash !== previousContentHash ||
      row.contentHash !== releaseValidationCohortContentHash(withoutContentHash)
    ) {
      blockingErrors.push(`Validation cohort ${row.cohortKey} has invalid immutable content`);
    }
    if (seen.has(row.cohortKey)) {
      blockingErrors.push(`Duplicate validation cohort ${row.cohortKey}`);
    }
    seen.add(row.cohortKey);
    previousContentHash = row.contentHash;
  }
  const missingCohortKeys = denominatorKeys.filter((key) => !seen.has(key));
  if (!seen.has(currentStratumKey)) missingCohortKeys.push(currentStratumKey);
  if (missingCohortKeys.length > 0) {
    blockingErrors.push(
      `Validation cohort ledger omits ${new Set(missingCohortKeys).size} required cohort(s)`,
    );
  }
  const current = persistedRows.find((row) => row.cohortKey === currentStratumKey);
  if (
    current &&
    (
      current.purpose !== 'production' ||
      current.lifecycle !== 'active'
    )
  ) {
    blockingErrors.push(
      `Current validation cohort ${currentStratumKey} is not active production`,
    );
  }
  return {
    persisted: blockingErrors.length === 0,
    rows: persistedRows,
    blockingErrors,
    report: {
      persisted: true,
      source: 'persisted_hash_chain',
      rowCount: persistedRows.length,
      tipContentHash: persistedRows.at(-1)?.contentHash ?? null,
      missingCohortKeys: [...new Set(missingCohortKeys)].sort(),
      errors: blockingErrors,
    },
  };
}

function evaluateProspectiveCohort(input: {
  cohort: ReleaseValidationCohortLedgerRow;
  denominatorLedger?: ReleaseValidationOpportunityDenominatorLedger;
  forecasts: ReleaseValidationForecastLedgerRow[];
  resolutions: Map<string, ObservationResolution>;
  generatedAtMs: number;
  thresholds: ValidationSampleThresholds;
  qualityCriteria: ValidationQualityCriteria;
  splitPlan: EvaluationSplitPlan;
  horizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
  combinedCases: EvaluationCase[];
  candidateHorizonCases: Map<ReleaseValidationHorizonCode, EvaluationCase[]>;
  candidateCombinedCases: EvaluationCase[];
}): JsonRecord {
  const denominatorRows = (input.denominatorLedger?.rows ?? []).filter((row) =>
    validationDenominatorStratumKey(row) === input.cohort.cohortKey);
  const cohortForecasts = input.forecasts.filter((forecast) =>
    validationStratumKey(forecast) === input.cohort.cohortKey);
  const matrix = buildProspectiveObligationMatrix({
    cohortKey: input.cohort.cohortKey,
    denominatorRows,
    forecasts: cohortForecasts,
    resolutions: input.resolutions,
    generatedAtMs: input.generatedAtMs,
  });
  const opportunityReports = Object.fromEntries(
    (Object.keys(RELEASE_VALIDATION_OPPORTUNITIES) as
      ReleaseValidationOpportunityCode[]).map((opportunityCode) => {
      const horizons = Object.fromEntries(
        (Object.keys(RELEASE_VALIDATION_HORIZONS) as
          ReleaseValidationHorizonCode[]).map((horizonCode) => {
          const policy = stratumEvaluationSection(
            input.horizonCases.get(horizonCode)!.filter((item) =>
              item.opportunityCode === opportunityCode),
            input.cohort.cohortKey,
            input.thresholds,
            input.qualityCriteria,
            input.splitPlan,
          );
          const candidate = candidateScoreStratumEvaluationSection(
            input.candidateHorizonCases.get(horizonCode)!.filter((item) =>
              item.opportunityCode === opportunityCode),
            input.cohort.cohortKey,
            input.thresholds,
            input.qualityCriteria,
            input.splitPlan,
          );
          const obligation = asRecord(
            asRecord(matrix.byOpportunity)?.[opportunityCode],
          )?.[horizonCode] as JsonRecord | undefined;
          const qualityStatus = combinedEvaluationGateStatus([policy, candidate]);
          const obligationStatus = String(obligation?.status ?? 'insufficient');
          const status = obligationStatus === 'failed' || qualityStatus === 'failed'
            ? 'failed'
            : obligationStatus === 'passed' && qualityStatus === 'passed'
              ? 'passed'
              : 'insufficient';
          return [horizonCode, {
            status,
            obligation,
            policy,
            candidate,
            qualityStatus,
          }];
        }),
      );
      return [opportunityCode, { horizons }];
    }),
  );
  const cellStatuses = Object.values(opportunityReports)
    .flatMap((opportunity) => {
      const horizons = asRecord(asRecord(opportunity)?.horizons) ?? {};
      return Object.values(horizons);
    })
    .map((cell) => String(asRecord(cell)?.status ?? 'insufficient'));
  const zeroObligation = denominatorRows.length === 0;
  const status = zeroObligation
    ? input.cohort.lifecycle === 'retired'
      ? 'zero_obligation'
      : 'insufficient'
    : Number(matrix.blockingFailureCount ?? 0) > 0 ||
      cellStatuses.includes('failed')
      ? 'failed'
      : matrix.allDueTerminal === true &&
        cellStatuses.length ===
          Object.keys(RELEASE_VALIDATION_OPPORTUNITIES).length *
          Object.keys(RELEASE_VALIDATION_HORIZONS).length &&
        cellStatuses.every((cell) => cell === 'passed')
        ? 'passed'
        : 'insufficient';
  return {
    cohortKey: input.cohort.cohortKey,
    purpose: input.cohort.purpose,
    lifecycle: input.cohort.lifecycle,
    authorizesProduction: input.cohort.purpose === 'production' &&
      status === 'passed',
    obligationCount: Number(matrix.obligationCount ?? 0),
    zeroObligation,
    allDueTerminal: matrix.allDueTerminal === true,
    status,
    matrix: opportunityReports,
    obligationSummary: matrix,
  };
}

function buildProspectiveObligationMatrix(input: {
  cohortKey: string;
  denominatorRows: ReleaseValidationOpportunityDenominatorLedger['rows'];
  forecasts: ReleaseValidationForecastLedgerRow[];
  resolutions: Map<string, ObservationResolution>;
  generatedAtMs: number;
}): JsonRecord {
  const cells = new Map<string, JsonRecord[]>();
  let blockingFailureCount = 0;
  let dueCount = 0;
  let dueTerminalCount = 0;
  for (const row of input.denominatorRows) {
    const forecast = row.capturedDecisionId
      ? input.forecasts.find((candidate) =>
          candidate.decision_id === row.capturedDecisionId &&
          candidate.content_hash === row.capturedContentHash)
      : undefined;
    for (const horizonCode of Object.keys(RELEASE_VALIDATION_HORIZONS) as
      ReleaseValidationHorizonCode[]) {
      const key = `${row.opportunityCode}\0${horizonCode}`;
      const entries = cells.get(key) ?? [];
      if (!forecast) {
        const due = row.terminal;
        if (due) {
          dueCount++;
          dueTerminalCount++;
        }
        if (row.disposition === 'failed') blockingFailureCount++;
        entries.push({
          opportunityId: row.opportunityId,
          releaseIdentity: releaseIdentityFromDenominatorRow(row),
          decisionId: null,
          due,
          terminal: row.terminal,
          status: row.disposition === 'failed'
            ? 'capture_failed'
            : row.disposition === 'missed'
              ? 'capture_attrition'
              : 'capture_pending',
        });
        cells.set(key, entries);
        continue;
      }
      const horizon = RELEASE_VALIDATION_HORIZONS[horizonCode];
      const latestObservationMs = Date.parse(forecast.recorded_at) +
        horizon.durationMs + horizon.observationGraceMs;
      const due = input.generatedAtMs > latestObservationMs;
      const resolution = input.resolutions.get(
        `${forecast.decision_id}\0${horizonCode}`,
      );
      const terminalIndeterminate = resolution?.indeterminate.find((item) =>
        item.terminal);
      const latestIndeterminate = resolution?.indeterminate.at(-1);
      const terminal = resolution?.matured != null || terminalIndeterminate != null;
      if (due) {
        dueCount++;
        if (terminal) dueTerminalCount++;
        else blockingFailureCount++;
      }
      if (latestIndeterminate?.fatal) blockingFailureCount++;
      entries.push({
        opportunityId: row.opportunityId,
        releaseIdentity: releaseIdentityFromDenominatorRow(row),
        decisionId: forecast.decision_id,
        due,
        terminal,
        status: resolution?.matured
          ? resolution.matured.schemaVersion === 3
            ? 'matured'
            : 'legacy_matured_non_authorizing'
          : terminalIndeterminate
            ? 'terminal_attrition'
            : latestIndeterminate
              ? latestIndeterminate.fatal
                ? 'fatal_indeterminate'
                : 'censored'
              : due
                ? 'unterminated_due'
                : 'pending',
        reason: latestIndeterminate?.reason ?? null,
      });
      cells.set(key, entries);
    }
  }
  const byOpportunity = Object.fromEntries(
    (Object.keys(RELEASE_VALIDATION_OPPORTUNITIES) as
      ReleaseValidationOpportunityCode[]).map((opportunityCode) => [
      opportunityCode,
      Object.fromEntries(
        (Object.keys(RELEASE_VALIDATION_HORIZONS) as
          ReleaseValidationHorizonCode[]).map((horizonCode) => {
          const entries = cells.get(`${opportunityCode}\0${horizonCode}`) ?? [];
          const failedCount = entries.filter((row) =>
            row.status === 'capture_failed' ||
            row.status === 'fatal_indeterminate' ||
            row.status === 'unterminated_due').length;
          const insufficientCount = entries.filter((row) =>
            row.status === 'capture_attrition' ||
            row.status === 'capture_pending' ||
            row.status === 'terminal_attrition' ||
            row.status === 'legacy_matured_non_authorizing' ||
            row.status === 'censored' ||
            row.status === 'pending').length;
          const status = failedCount > 0
              ? 'failed'
              : entries.length === 0 || insufficientCount > 0
                ? 'insufficient'
                : 'passed';
          return [horizonCode, {
            status,
            obligationCount: entries.length,
            dueCount: entries.filter((row) => row.due === true).length,
            terminalCount: entries.filter((row) => row.terminal === true).length,
            maturedCount: entries.filter((row) => row.status === 'matured').length,
            legacyMaturedCount: entries.filter((row) =>
              row.status === 'legacy_matured_non_authorizing').length,
            censoredCount: entries.filter((row) => row.status === 'censored').length,
            terminalAttritionCount: entries.filter((row) =>
              row.status === 'terminal_attrition').length,
            captureAttritionCount: entries.filter((row) =>
              row.status === 'capture_attrition').length,
            unterminatedDueCount: entries.filter((row) =>
              row.status === 'unterminated_due').length,
            blockingFailureCount: failedCount,
            cases: entries,
          }];
        }),
      ),
    ]),
  );
  return {
    cohortKey: input.cohortKey,
    obligationCount:
      input.denominatorRows.length * Object.keys(RELEASE_VALIDATION_HORIZONS).length,
    dueCount,
    dueTerminalCount,
    allDueTerminal: dueCount === dueTerminalCount,
    blockingFailureCount,
    byOpportunity,
  };
}

function exactObservationBatchCoverage(input: {
  forecasts: ReleaseValidationForecastLedgerRow[];
  eligibleForecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
  batches?: ReleaseValidationObservationBatchEvidenceRow[];
  verification?: ReleaseValidationObservationBatchVerificationEvidence;
  generatedAtMs: number;
}): {
  complete: boolean;
  blockingErrors: string[];
  report: JsonRecord;
} {
  const batches = (input.batches ?? []).slice().sort((left, right) =>
    Number(left.id ?? 0) - Number(right.id ?? 0));
  if (batches.length === 0) {
    return {
      complete: false,
      blockingErrors: [],
      report: {
        present: false,
        verified: false,
        complete: false,
        reason: 'observation_batch_ledger_missing',
      },
    };
  }
  const blockingErrors = input.verification && input.verification.failedCount > 0
    ? input.verification.problems.map((problem) =>
        `Observation batch ledger: ${problem}`)
    : [];
  if (!input.verification) {
    return {
      complete: false,
      blockingErrors,
      report: {
        present: true,
        verified: false,
        complete: false,
        batchCount: batches.length,
        reason: 'observation_batch_verification_missing',
      },
    };
  }
  const latest = batches.at(-1)!;
  const latestResults = parseBatchResults(latest.results_json, blockingErrors);
  const expectedPairs = new Map<
    string,
    ReleaseValidationForecastLedgerRow
  >(
    input.forecasts.flatMap((forecast) =>
      (Object.keys(RELEASE_VALIDATION_HORIZONS) as
        ReleaseValidationHorizonCode[]).map((horizonCode) => [
        `${forecast.decision_id}\0${horizonCode}`,
        forecast,
      ] as const)),
  );
  const actualPairs = new Map<string, JsonRecord>();
  for (const result of latestResults) {
    const decisionId = stringField(result, 'decisionId');
    const horizonCode = stringField(result, 'horizonCode');
    const key = `${decisionId ?? ''}\0${horizonCode ?? ''}`;
    if (actualPairs.has(key)) {
      blockingErrors.push(`Latest observation batch duplicates ${key}`);
      continue;
    }
    actualPairs.set(key, result);
    const forecast = decisionId
      ? input.forecasts.find((row) => row.decision_id === decisionId)
      : undefined;
    if (
      !forecast ||
      result.opportunityCode !== forecast.opportunity_code ||
      result.targetReleaseTag !== validationTargetReleaseTag(forecast)
    ) {
      blockingErrors.push(`Latest observation batch has an unknown result ${key}`);
    }
  }
  const missingPairs = [...expectedPairs.keys()]
    .filter((key) => !actualPairs.has(key))
    .sort();
  const extraPairs = [...actualPairs.keys()]
    .filter((key) => !expectedPairs.has(key))
    .sort();
  if (
    latest.forecast_count !== input.forecasts.length ||
    missingPairs.length > 0 ||
    extraPairs.length > 0
  ) {
    blockingErrors.push('Latest observation batch does not cover the exact forecast-horizon set');
  }
  const staleDuePairs: string[] = [];
  for (const forecast of input.eligibleForecasts) {
    for (const horizonCode of Object.keys(RELEASE_VALIDATION_HORIZONS) as
      ReleaseValidationHorizonCode[]) {
      const horizon = RELEASE_VALIDATION_HORIZONS[horizonCode];
      const dueAt = Date.parse(forecast.recorded_at) +
        horizon.durationMs + horizon.observationGraceMs;
      if (input.generatedAtMs <= dueAt) continue;
      const result = actualPairs.get(`${forecast.decision_id}\0${horizonCode}`);
      if (
        !result ||
        !['matured', 'indeterminate'].includes(String(result.status ?? '')) ||
        !['inserted', 'already_existing'].includes(String(result.persistence ?? '')) ||
        (
          result.status === 'indeterminate' &&
          result.reason !== 'observation_grace_window_missed'
        )
      ) {
        staleDuePairs.push(`${forecast.decision_id}/${horizonCode}`);
      }
    }
  }
  if (staleDuePairs.length > 0) {
    blockingErrors.push(
      `Latest observation batch leaves ${staleDuePairs.length} due obligation(s) nonterminal`,
    );
  }
  const insertedCoverage = new Map<string, number>();
  for (const batch of batches) {
    for (const result of parseBatchResults(batch.results_json, blockingErrors)) {
      if (result.persistence !== 'inserted') continue;
      const observationId = stringField(result, 'observationId');
      if (!observationId) continue;
      insertedCoverage.set(
        observationId,
        (insertedCoverage.get(observationId) ?? 0) + 1,
      );
    }
  }
  const uncoveredOutcomeIds = input.observations
    .map((row) => row.observation_id)
    .filter((observationId) => (insertedCoverage.get(observationId) ?? 0) === 0)
    .sort();
  const duplicateOutcomeIds = [...insertedCoverage.entries()]
    .filter(([, count]) => count > 1)
    .map(([observationId]) => observationId)
    .sort();
  if (uncoveredOutcomeIds.length > 0 || duplicateOutcomeIds.length > 0) {
    blockingErrors.push('Observation batch ledger does not introduce each outcome exactly once');
  }
  const complete = blockingErrors.length === 0 &&
    missingPairs.length === 0 &&
    extraPairs.length === 0 &&
    staleDuePairs.length === 0 &&
    uncoveredOutcomeIds.length === 0 &&
    duplicateOutcomeIds.length === 0;
  return {
    complete,
    blockingErrors,
    report: {
      present: true,
      verified: input.verification.failedCount === 0,
      complete,
      batchCount: batches.length,
      latestBatchId: latest.batch_id,
      latestBatchContentHash: latest.content_hash,
      latestBatchForecastCount: latest.forecast_count,
      expectedForecastCount: input.forecasts.length,
      expectedPairCount: expectedPairs.size,
      actualPairCount: actualPairs.size,
      missingPairs,
      extraPairs,
      staleDuePairs,
      uncoveredOutcomeIds,
      duplicateOutcomeIds,
      errors: blockingErrors,
    },
  };
}

function parseBatchResults(json: string, errors: string[]): JsonRecord[] {
  try {
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) throw new Error('results are not an array');
    const envelope = parsed.length === 1 ? asRecord(parsed[0]) : null;
    const rawResults = envelope?.kind === 'release_validation_observation_batch' &&
        envelope.schemaVersion === 2
      ? envelope.results
      : parsed;
    if (!Array.isArray(rawResults)) {
      throw new Error('v2 receipt results are not an array');
    }
    const results = rawResults.map(asRecord);
    if (results.some((row) => row == null)) {
      throw new Error('results contain a non-object entry');
    }
    return results as JsonRecord[];
  } catch (error) {
    errors.push(
      `Observation batch results JSON is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return [];
  }
}

export function releaseValidationObservationBatchResults(
  json: string,
): Array<Record<string, unknown>> {
  const errors: string[] = [];
  const results = parseBatchResults(json, errors);
  if (errors.length > 0) {
    throw new Error(errors.join('; '));
  }
  return results;
}

function buildReleaseValidationLedgerManifest(input: {
  forecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
  batches: ReleaseValidationObservationBatchEvidenceRow[];
  denominatorLedger?: ReleaseValidationOpportunityDenominatorLedger;
  cohorts: ReleaseValidationCohortLedgerRow[];
  splitAssignments: ReleaseValidationSplitAssignmentRow[];
}): ReleaseValidationLedgerManifest {
  const forecasts = manifestSection(
    input.forecasts,
    (row) => row.decision_id,
    (row) => row.content_hash ?? null,
  );
  const outcomes = manifestSection(
    input.observations,
    (row) => row.observation_id,
    (row) => row.content_hash ?? null,
  );
  const batches = manifestSection(
    input.batches,
    (row) => row.batch_id,
    (row) => row.content_hash,
  );
  const cohorts = manifestSection(
    input.cohorts,
    (row) => row.cohortKey,
    (row) => row.contentHash,
  );
  const splitAssignments = manifestSection(
    input.splitAssignments,
    (row) => row.assignmentId,
    (row) => row.contentHash,
  );
  const withoutContentHash: Omit<
    ReleaseValidationLedgerManifest,
    'contentHash'
  > = {
    schemaVersion: RELEASE_VALIDATION_LEDGER_MANIFEST_SCHEMA_VERSION,
    forecasts,
    outcomes,
    observationBatches: {
      ...batches,
      outcomeTip: input.batches.at(-1)?.outcome_chain_content_hash ?? null,
      latestObservedAt: input.batches.at(-1)?.observed_at ?? null,
    },
    opportunityDenominator: {
      rowCount: input.denominatorLedger?.rowCount ?? 0,
      contentHash: input.denominatorLedger?.contentHash ?? null,
    },
    cohorts,
    splitAssignments,
  };
  return {
    ...withoutContentHash,
    contentHash: releaseValidationLedgerManifestContentHash(withoutContentHash),
  };
}

function manifestSection<T>(
  rows: T[],
  identity: (row: T) => string,
  contentHash: (row: T) => string | null,
): ReleaseValidationLedgerManifestSection {
  return {
    rowCount: rows.length,
    tipContentHash: rows.at(-1) ? contentHash(rows.at(-1)!) : null,
    identityDigest: proofHash(
      'release-validation-ledger-manifest-identities-v1',
      rows.map(identity),
    ),
  };
}

function validateExpectedLedgerManifest(
  expected: ReleaseValidationLedgerManifest | undefined,
  actual: ReleaseValidationLedgerManifest,
): { verified: boolean; blockingErrors: string[] } {
  if (!expected) return { verified: false, blockingErrors: [] };
  const { contentHash: _contentHash, ...expectedWithoutHash } = expected;
  const blockingErrors: string[] = [];
  if (
    expected.schemaVersion !== RELEASE_VALIDATION_LEDGER_MANIFEST_SCHEMA_VERSION ||
    expected.contentHash !==
      releaseValidationLedgerManifestContentHash(expectedWithoutHash) ||
    !sameJsonValue(expected, actual)
  ) {
    blockingErrors.push(
      'Persisted release validation ledger manifest does not exactly match current ledger tips',
    );
  }
  return {
    verified: blockingErrors.length === 0,
    blockingErrors,
  };
}

function validationReconciliationReport(
  rows: ReleaseValidationReconciliationRow[],
): { blockingErrors: string[]; report: JsonRecord } {
  const blockingErrors: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    if (
      !row.reconciliationId ||
      seen.has(row.reconciliationId) ||
      !row.cohortKey ||
      !Number.isFinite(Date.parse(row.recordedAt)) ||
      !['resolved', 'blocking'].includes(row.status) ||
      !row.reason
    ) {
      blockingErrors.push(
        `Validation reconciliation row ${row.reconciliationId || 'unknown'} is invalid`,
      );
    }
    if (row.status === 'blocking') {
      blockingErrors.push(
        `Blocking validation reconciliation ${row.reconciliationId}: ${row.reason}`,
      );
    }
    seen.add(row.reconciliationId);
  }
  return {
    blockingErrors,
    report: {
      rowCount: rows.length,
      blockingCount: rows.filter((row) => row.status === 'blocking').length,
      resolvedCount: rows.filter((row) => row.status === 'resolved').length,
      rows,
      errors: blockingErrors,
    },
  };
}

function parseValidationCohortKey(key: string): {
  modelVersion: string;
  promptVersion: number;
  codeRevision: string;
} {
  const match = /^(.*)\/prompt-(\d+)\/revision-(.+)$/.exec(key);
  return {
    modelVersion: match?.[1] ?? key,
    promptVersion: Number(match?.[2] ?? 0),
    codeRevision: match?.[3] ?? 'invalid',
  };
}

function denominatorCohortStart(
  ledger: ReleaseValidationOpportunityDenominatorLedger | undefined,
  cohortKey: string,
): string | null {
  return (ledger?.rows ?? [])
    .filter((row) => validationDenominatorStratumKey(row) === cohortKey)
    .map((row) => row.cohortInceptionAt)
    .sort((left, right) => Date.parse(left) - Date.parse(right))[0] ?? null;
}

function denominatorCohortEnd(
  ledger: ReleaseValidationOpportunityDenominatorLedger | undefined,
  cohortKey: string,
): string | null {
  return (ledger?.rows ?? [])
    .filter((row) => validationDenominatorStratumKey(row) === cohortKey)
    .map((row) => row.closesAtExclusive)
    .sort((left, right) => Date.parse(right) - Date.parse(left))[0] ?? null;
}

function sameStringSet(left: Set<string>, right: Set<string>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function setDifference(left: Set<string>, right: Set<string>): string[] {
  return [...left].filter((value) => !right.has(value)).sort();
}

function sameJsonValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right));
}

function canonicalJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalJson);
  const record = asRecord(value);
  if (!record) return value;
  return Object.fromEntries(
    Object.keys(record).sort().map((key) => [key, canonicalJson(record[key])]),
  );
}

function proofHash(domain: string, value: unknown): string {
  return createHash('sha256')
    .update(`${domain}\0${JSON.stringify(canonicalJson(value))}`)
    .digest('hex');
}

function indeterminate(
  input: ObservationAssessmentInput,
  targetReleaseTag: string,
  windowStartAt: string,
  windowEndAt: string,
  reason: string,
  fatal: boolean,
  details?: unknown,
): ObservationAssessment {
  return {
    status: 'indeterminate',
    fatal,
    horizonCode: input.horizonCode,
    targetReleaseTag,
    windowStartAt,
    windowEndAt,
    reason,
    ...(details === undefined ? {} : { details }),
  };
}

function parseJson(value: string | null | undefined): unknown {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function parseRecord(value: string | null | undefined): JsonRecord | null {
  return asRecord(parseJson(value));
}

function asRecord(value: unknown): JsonRecord | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : null;
}

function recordArray(value: unknown): JsonRecord[] {
  return Array.isArray(value)
    ? value.map(asRecord).filter((item): item is JsonRecord => item !== null)
    : [];
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function catalogSweepAttestationProblems(
  value: unknown,
  label: string,
): {
  problems: string[];
  value: ReleaseCatalogSweepAttestation | null;
} {
  const record = asRecord(value);
  const problems: string[] = [];
  const digest = stringField(record, 'digest');
  const totalCount = nonnegativeInteger(record?.totalCount);
  const nodeCount = nonnegativeInteger(record?.nodeCount);
  const pageCount = nonnegativeInteger(record?.pageCount);
  const pagesFetched = nonnegativeInteger(record?.pagesFetched);
  const sweepCount = nonnegativeInteger(record?.sweepCount);
  if (!isSha256Hex(digest)) problems.push(`catalogAttestation ${label} digest is invalid`);
  if (totalCount == null || nodeCount == null || nodeCount !== totalCount) {
    problems.push(`catalogAttestation ${label} counts are invalid`);
  }
  if (pageCount == null || pagesFetched == null || sweepCount == null || sweepCount < 2) {
    problems.push(`catalogAttestation ${label} sweep metadata is invalid`);
  }
  if (
    record?.exhausted !== true ||
    record?.stabilized !== true ||
    record?.sourceOrder !== 'CREATED_AT_DESC'
  ) {
    problems.push(`catalogAttestation ${label} is not a complete stabilized release catalog`);
  }
  return {
    problems,
    value: problems.length === 0
      ? {
          digest: digest!,
          totalCount: totalCount!,
          nodeCount: nodeCount!,
          pageCount: pageCount!,
          pagesFetched: pagesFetched!,
          sweepCount: sweepCount!,
          exhausted: true,
          stabilized: true,
          sourceOrder: 'CREATED_AT_DESC',
        }
      : null,
  };
}

function catalogIdentityAttestationProblems(
  value: unknown,
  label: string,
): {
  problems: string[];
  value: { digest: string; releaseCount: number } | null;
} {
  const record = asRecord(value);
  const problems: string[] = [];
  const digest = stringField(record, 'digest');
  const releaseCount = nonnegativeInteger(record?.releaseCount);
  if (!isSha256Hex(digest)) problems.push(`catalogAttestation ${label} digest is invalid`);
  if (releaseCount == null || releaseCount === 0) {
    problems.push(`catalogAttestation ${label} releaseCount is invalid`);
  }
  return {
    problems,
    value: problems.length === 0
      ? { digest: digest!, releaseCount: releaseCount! }
      : null,
  };
}

function stringField(record: JsonRecord | null, key: string): string | null {
  const value = record?.[key];
  return typeof value === 'string' && value.trim() ? value : null;
}

function commitOidField(record: JsonRecord | null, key: string): string | null {
  const value = stringField(record, key);
  return value && /^[0-9a-f]{40,64}$/i.test(value) ? value.toLowerCase() : null;
}

function integerField(record: JsonRecord | null, key: string): number | null {
  const value = record?.[key];
  return typeof value === 'number' && Number.isInteger(value) ? value : null;
}

function timestampField(record: JsonRecord | null, key: string): string | null {
  const value = stringField(record, key);
  return value && Number.isFinite(Date.parse(value)) ? value : null;
}

function isSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function nullableString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function nullableBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function nullableFiniteNumber(value: unknown): number | null {
  if (value == null) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function nonnegativeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0
    ? value
    : null;
}

function presentAliasValues(record: JsonRecord, keys: string[]): unknown[] {
  return keys
    .filter((key) => Object.prototype.hasOwnProperty.call(record, key))
    .map((key) => record[key]);
}

function aliasValuesConflict(values: unknown[]): boolean {
  return values.length > 1 &&
    values.slice(1).some((value) => !sameJsonValue(value, values[0]));
}

function mean(values: number[]): number | null {
  return values.length > 0 ? round(values.reduce((sum, value) => sum + value, 0) / values.length) : null;
}

function round(value: number): number {
  return Math.round(value * 10_000) / 10_000;
}
