import { createHash } from 'node:crypto';
import {
  applyClosureRiskSentimentHint,
  applyLabelOverrides,
  applyTitleFunctionalityHint,
  applyTitleIssueShapeHint,
  labelUsesScoreAuthority,
} from '../../src/lib/labelOverrides.ts';
import { releaseArtifactScoreProjection } from '../../src/lib/artifactVerification.ts';
import {
  buildExclusiveIssueRiskLedger,
  buildScoreLedgerV2,
  installConfidence,
  REC_THRESHOLD,
  RECOMMENDATION_RECENCY_TOLERANCE,
  SCORE_COMPONENT_LIMITS,
  SCORE_LEDGER_TYPE,
  SCORE_MODEL_VERSION,
  scoreLedgerV2Problems,
  selectRecommendation,
} from '../../src/lib/score.ts';
import { publicIssueSummariesForRelease } from '../../src/lib/publicIssueSummary.ts';
import {
  RELEASE_ISSUE_EVIDENCE_TIERS,
  RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
  RELEASE_ISSUE_EVIDENCE_TIER_INFO,
} from '../../src/lib/releaseIssueEvidence.ts';
import {
  CLOSURE_PROOF_STATUSES,
  CLOSURE_RISK_DISPOSITIONS,
  CLOSURE_RISK_DISPOSITION_BY_STATUS,
  CLOSURE_RISK_DISPOSITION_WEIGHT,
  closureRiskDispositionLabel,
  closureRiskWeightLabel,
} from '../../src/lib/closureProofTaxonomy.ts';
import { CLOSURE_PROOF_ANALYZER_VERSION } from '../../src/lib/analysisVersions.ts';
import {
  REACHABILITY_METHOD,
  validateReachabilityEvidence,
} from '../../src/lib/reachabilityEvidence.ts';
import {
  ARTIFACT_VERIFICATION_SCHEMA_VERSION,
  GATE_EVIDENCE_SCHEMA_VERSION,
  ISSUE_EVIDENCE_SCHEMA_VERSION,
  LABEL_TIMELINE_SCHEMA_VERSION,
  RELEASE_CHECKS_SCHEMA_VERSION,
  SCORE_COMPONENTS_SCHEMA_VERSION,
  SCORE_EXPLANATION_SCHEMA_VERSION,
  SCORE_EXPLANATION_DETAIL_LABELS,
  SCORE_EXPLANATION_LIMIT_CODES,
  SCORE_EXPLANATION_POSITIVE_CODES,
  SCORE_INPUT_SCHEMA_VERSION,
  SCORE_LEDGER_SCHEMA_VERSION,
  humanRecommendationDecisionSummary,
  recommendationDecisionSummary,
} from '../../src/lib/releaseScoring.ts';
import {
  RELEASE_VALIDATION_OPPORTUNITIES,
  RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SCHEMA_VERSION,
  RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SOURCE_POLICY,
} from '../../src/lib/releaseValidationOpportunityDenominator.ts';
import {
  RELEASE_VALIDATION_OPPORTUNITY_STATUS_SCHEMA_VERSION,
} from '../../src/lib/releaseValidationOpportunityStatus.ts';
import { hasHotfixSuccessor } from '../../src/lib/releaseNotes.ts';
import {
  SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  scoreSourceIdentityManifestDigest,
  scoreSourceIdentityManifestProblems,
} from '../../src/lib/scoreSourceIdentity.ts';
import {
  COMPOUND_ADVISORY_AUDIT_PROJECTION_SCHEMA_VERSION,
  COMPOUND_ADVISORY_AUDIT_SOURCE_MODE,
} from '../../src/lib/advisorySnapshot.ts';
import {
  aggregateClosureRisk,
  buildIssueAliasGroups,
  canonicalIssueNumbersFromEvidence,
} from '../../src/lib/closureRiskAggregation.ts';
import { rawClassificationStorageProblems } from '../../src/lib/llm.ts';
import { releaseValidationForecastTiming } from '../../src/lib/releaseValidation.ts';
import {
  verifyRecommendationDecisionContract,
  verifyScoreAuditPayloadContracts,
} from '../../src/lib/scoreAuditContracts.ts';
import { assessIssueCrawlHealth } from './doctor-health.mjs';

export const knownProofStatuses = new Set(CLOSURE_PROOF_STATUSES);
const trackedRepositoryNameWithOwner = `${process.env.GITHUB_OWNER ?? 'openclaw'}/${process.env.GITHUB_REPO ?? 'openclaw'}`;

const directUnknownFixCommitStatuses = new Set([
  'not_planned_direct_fix_commit_reachability_unknown',
  'direct_fix_commit_reachability_unknown',
  'non_bug_direct_fix_commit_reachability_unknown',
]);
const knownCommitProofStatuses = new Set(['reachable', 'not_reachable', 'unknown']);
const knownReachabilityEvidenceReasons = new Set([
  'merge_commit_in_release_history',
  'fix_commit_in_release_history',
  'predecessor_release_in_target_history',
  'not_reachable_from_release_tag',
  'release_commit_unavailable',
  'release_commit_fetch_failed',
  'merge_commit_oid_unavailable',
  'commit_fetch_failed',
  'commit_unavailable',
  'merge_base_error',
]);
const knownRiskDispositions = new Set(CLOSURE_RISK_DISPOSITIONS);
const riskDispositionByProofStatus = new Map(Object.entries(CLOSURE_RISK_DISPOSITION_BY_STATUS));
const riskDispositionWeights = new Map(Object.entries(CLOSURE_RISK_DISPOSITION_WEIGHT));
const severityRiskWeights = new Map([
  ['critical', 4],
  ['high', 2.5],
  ['medium', 0.8],
  ['low', 0],
]);
const functionalityRiskWeights = new Map([
  ['core', 1.25],
  ['integration', 1],
  ['provider', 0.8],
  ['tooling', 0],
  ['docs', 0],
]);
const scopeRiskWeights = new Map([
  ['broad', 1.5],
  ['moderate', 1],
  ['niche', 0.4],
]);
const affectedUserRiskWeights = new Map([
  ['many', 1.3],
  ['some', 0.85],
  ['few', 0.35],
  ['unknown', 0.65],
]);
const fullCommitOidRe = /^[0-9a-f]{40}$/;
const sha256HexRe = /^[0-9a-f]{64}$/;
const authorityBoundClosureProofStatuses = new Set([
  'duplicate_to_non_actionable_canonical',
  'not_planned',
  'reporter_replaced',
  'reporter_self_closed',
  'reporter_withdrawn',
]);
const knownCommitProofSources = new Set(['ClosureComment.fixProof', 'ClosedEvent.closer', 'ReferencedEvent.commit']);
const requiredProofDependencySources = new Set([
  'issue_rows',
  'issue_fetches',
  'issue_comments',
  'classification_rows',
  'label_events',
  'label_snapshots',
  'issue_state_event_snapshots',
  'closure_events',
  'reopen_events',
  'issue_pr_links',
  'issue_commit_references',
  'pull_request_fixes',
  'release_pr_reachability',
  'release_closure_dependency_snapshots',
]);
const scoreAffectingFreshnessSources = [
  'classification_rows',
  'closure_events',
  'closure_proofs',
  'issue_comments',
  'issue_commit_references',
  'issue_fetches',
  'issue_pr_links',
  'issue_rows',
  'issue_state_event_snapshots',
  'label_events',
  'label_snapshots',
  'pull_request_fixes',
  'release_closure_dependency_snapshots',
  'release_metadata',
  'release_pr_reachability',
  'reopen_events',
];
const releaseFixCreditDecisionKeys = new Set([
  'schemaVersion',
  'issueNumber',
  'status',
  'reasonCode',
  'targetTag',
  'predecessorTag',
  'proofIdentities',
]);
const releaseFixCreditKeys = new Set([
  'schemaVersion',
  'targetTag',
  'predecessorTag',
  'countedClosedCount',
  'notCountedClosedCount',
  'analyzedClosedCount',
  'containedFixedCount',
  'containedNotCreditedCount',
  'decisionCounts',
  'decisions',
]);
const releaseFixCreditDecisionCountKeys = new Set(['credited', 'withheld', 'invalid']);
const releaseFixCreditTrustedPrKeys = new Set([
  'kind',
  'repositoryNameWithOwner',
  'prNumber',
  'sources',
  'merged',
  'mergeCommitOid',
  'baseRefName',
  'target',
  'predecessor',
]);
const releaseFixCreditDirectCommitKeys = new Set([
  'kind',
  'schemaVersion',
  'repositoryNameWithOwner',
  'commitOid',
  'targetTag',
  'predecessorTag',
  'status',
  'reasonCode',
  'creditEligible',
  'target',
  'predecessor',
  'releaseAncestry',
  'strictValid',
  'validationReasonCode',
]);
const releaseFixCreditDirectReachabilityKeys = new Set([
  'tag',
  'status',
  'tagCommitOid',
  'checkedCommitOid',
  'method',
  'evidence',
  'strictValid',
  'validationReasonCode',
]);
const releaseFixCreditReachabilityKeys = new Set([
  'tag',
  'status',
  'tagCommitOid',
  'checkedCommitOid',
  'baseRefName',
  'method',
  'checkedAt',
  'evidenceReason',
  'strictValid',
  'validationReasonCode',
]);
const releaseFixCreditStatuses = new Set(['credited', 'withheld', 'invalid']);
const releaseFixCreditReasonCodes = new Set([
  'first_containing_trusted_pr',
  'first_containing_direct_commit',
  'target_trusted_pr_missing',
  'target_reachability_missing',
  'target_reachability_unknown',
  'target_reachability_not_reachable',
  'target_reachability_invalid',
  'predecessor_reachability_missing',
  'predecessor_reachability_unknown',
  'predecessor_reachability_invalid',
  'predecessor_reachable',
  'predecessor_contains_other_trusted_pr',
  'direct_commit_only_predecessor_evidence_unavailable',
  'direct_commit_first_containing_proof_missing',
  'direct_commit_first_containing_proof_invalid',
  'direct_commit_not_first_containing',
  'direct_commit_first_containment_unproven',
  'missing_predecessor_boundary',
  'invalid_predecessor_boundary',
  'target_release_missing',
  'predecessor_release_missing',
  'target_closure_proof_missing',
]);
const creditedReleaseFixReasonCodes = new Set([
  'first_containing_trusted_pr',
  'first_containing_direct_commit',
]);
const directCommitFirstContainingReasonCodes = new Set([
  'first_containing_direct_commit',
  'repository_identity_mismatch',
  'invalid_commit_oid',
  'missing_predecessor_boundary',
  'target_release_missing',
  'predecessor_release_missing',
  'invalid_release_boundary',
  'release_retag_conflict',
  'release_alias_conflict',
  'repository_state_unavailable',
  'shallow_repository',
  'release_object_unavailable',
  'commit_object_unavailable',
  'ambiguous_release_ancestry',
  'target_commit_not_reachable',
  'predecessor_contains_commit',
  'git_evidence_unavailable',
]);
const invalidReleaseFixReasonCodes = new Set([
  'missing_predecessor_boundary',
  'invalid_predecessor_boundary',
  'target_release_missing',
  'predecessor_release_missing',
  'target_closure_proof_missing',
]);
const bugShapedTitleRe = /\b(bug|fail(?:s|ed|ure)?|error|crash|stuck|regression|broken|lost|timeout|leak|silently|dropped|corrupt|deadlock|stall)\b/i;
const scoreInputSchemaVersion = SCORE_INPUT_SCHEMA_VERSION;
const scoreComponentsSchemaVersion = SCORE_COMPONENTS_SCHEMA_VERSION;
const scoreAuditSummarySchemaVersion = 2;
const scoreAuditSummaryKeys = new Set([
  'schemaVersion',
  'reviewSchemaVersion',
  'auditDigest',
  'authorityRunId',
  'authorityRunContentHash',
  'historyV2SealContentHash',
  'modelVersion',
  'promptVersion',
  'evidenceCoverage',
  'rawIssueCount',
  'classifiedIssueCount',
]);
const scoreAuthorityBindingKeys = new Set([
  'runId',
  'contentHash',
  'historyV2SealContentHash',
]);
const localAuditSchemaVersion = 1;
const staleScoreAuditSchemaVersion = 1;
const staleAnalysisPrefix = 'Analysis is stale.';
const comparisonPayloadSchemaVersion = 1;
const comparisonUpstreamSchemaVersion = 1;
const comparisonDeltaSchemaVersion = 1;
const statusPayloadSchemaVersion = 1;
const validationOpportunityPayloadSchemaVersion =
  RELEASE_VALIDATION_OPPORTUNITY_STATUS_SCHEMA_VERSION;
const configPayloadSchemaVersion = 1;
const releaseRowSchemaVersion = 2;
const releaseHistoryRowSchemaVersion = 2;
const releaseSnapshotSchemaVersion = 1;
const publicReleaseSchemaVersion = 4;
const gateEvidenceSchemaVersion = GATE_EVIDENCE_SCHEMA_VERSION;
const closureProofSchemaVersion = 2;
const closureProofAuditSchemaVersion = 2;
const releaseFixCreditSchemaVersion = 1;
const issueEvidenceSchemaVersion = ISSUE_EVIDENCE_SCHEMA_VERSION;
const issueEvidenceAuditSchemaVersion = RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION;
const labelTimelineSchemaVersion = LABEL_TIMELINE_SCHEMA_VERSION;
const releaseChecksSchemaVersion = RELEASE_CHECKS_SCHEMA_VERSION;
const artifactVerificationSchemaVersion = ARTIFACT_VERIFICATION_SCHEMA_VERSION;
const scoreExplanationSchemaVersion = SCORE_EXPLANATION_SCHEMA_VERSION;
const publicPayloadSchemaVersion = 4;
const knownIssueEvidenceTiers = new Set(RELEASE_ISSUE_EVIDENCE_TIERS);
const knownExplanationLimitCodes = new Set(SCORE_EXPLANATION_LIMIT_CODES);
const knownExplanationPositiveCodes = new Set(SCORE_EXPLANATION_POSITIVE_CODES);
const expectedExplanationDetailLabels = new Map(Object.entries(SCORE_EXPLANATION_DETAIL_LABELS));
const publicTopLevelKeys = new Set([
  'repo',
  'releases',
  'schemaVersion',
  'snapshot',
  'snapshotId',
  'updatedAt',
]);
const releaseSnapshotKeys = new Set([
  'schemaVersion',
  'id',
  'generatedAt',
  'source',
  'retained',
  'stale',
  'actionable',
  'ageMs',
  'maxAgeMs',
]);
const validationOpportunityPayloadKeys = new Set([
  'schemaVersion',
  'asOf',
  'latestRelease',
  'currentSeries',
  'currentAudit',
  'counts',
  'denominatorLedger',
  'overallStatus',
  'currentStratum',
  'nextDeadlineAt',
  'recommendedAction',
  'opportunities',
]);
const validationOpportunityLatestReleaseKeys = new Set([
  'tag',
  'publishedAt',
  'ageMs',
  'ageHours',
]);
const validationOpportunityCurrentSeriesKeys = new Set([
  'key',
  'modelVersion',
  'promptVersion',
  'codeRevision',
  'ledgerForecastCount',
  'enrolledOpportunityCount',
]);
const validationOpportunityCurrentAuditKeys = new Set([
  'present',
  'current',
  'scoreModelVersion',
  'promptVersion',
  'scoredAt',
]);
const validationOpportunityCountKeys = new Set([
  'captured',
  'upcoming',
  'open',
  'missed',
  'failed',
  'invalidLegacyForecasts',
]);
const validationOpportunityDenominatorKeys = new Set([
  'schemaVersion',
  'sourcePolicy',
  'contentHash',
  'rowCount',
  'counts',
  'integrity',
  'rows',
]);
const validationOpportunityDenominatorCountKeys = new Set([
  'upcoming',
  'eligible',
  'captured',
  'missed',
  'failed',
]);
const validationOpportunityDenominatorIntegrityKeys = new Set([
  'valid',
  'enrollmentLedgerValid',
  'operationReceiptLedgerVerified',
  'errorCount',
  'errors',
]);
const validationOpportunityDenominatorRowKeys = new Set([
  'opportunityId',
  'enrollmentContentHash',
  'stateContentHash',
  'enrolledAt',
  'cohortInceptionAt',
  'enrollmentKind',
  'releaseNodeId',
  'releaseTag',
  'releaseTagCommitOid',
  'releasePublishedAt',
  'opportunityCode',
  'modelVersion',
  'promptVersion',
  'codeRevision',
  'opensAt',
  'closesAtExclusive',
  'enrollmentRunId',
  'operationAttemptContentHash',
  'catalogDigest',
  'catalogReleaseCount',
  'disposition',
  'terminal',
  'capturedDecisionId',
  'capturedContentHash',
  'successEvidence',
  'failureCount',
  'failures',
]);
const validationOpportunitySuccessEvidenceKeys = new Set([
  'runId',
  'receiptId',
  'finishedAt',
  'receiptContentHash',
]);
const validationOpportunityFailureKeys = new Set([
  'runId',
  'receiptId',
  'occurredAt',
  'reason',
  'attemptContentHash',
  'stageEventId',
  'stageEventContentHash',
  'receiptContentHash',
]);
const validationOpportunityCurrentStratumKeys = new Set([
  'key',
  'status',
  'denominatorReady',
  'counts',
]);
const validationOpportunityKeys = new Set([
  'opportunityId',
  'releaseTag',
  'releasePublishedAt',
  'code',
  'state',
  'opensAt',
  'closesAtExclusive',
  'enrolledAt',
  'enrollmentContentHash',
  'stateContentHash',
  'timeUntilOpenMs',
  'timeUntilCloseMs',
  'capturedDecisionId',
  'capturedContentHash',
  'failureCount',
  'failures',
  'invalidCurrentSeriesForecastCount',
  'otherSeriesForecastCount',
]);
const validationOpportunityStates = new Set([
  'not_enrolled',
  'upcoming',
  'open',
  'captured',
  'missed',
  'failed',
]);
const validationOpportunityDispositionStates = new Set([
  'upcoming',
  'eligible',
  'captured',
  'missed',
  'failed',
]);
const validationOpportunityCodes = new Set(Object.keys(RELEASE_VALIDATION_OPPORTUNITIES));
const validationOpportunityRecommendedActions = new Set([
  'observe_captured_forecasts',
  'schedule_verified_refresh_in_window',
  'run_verified_refresh_before_deadline',
  'refresh_current_model_before_deadline',
  'wait_for_next_release',
  'repair_denominator_integrity',
  'wait_for_prospective_enrollment',
]);
const scoreModelCapabilityMinimumVersion = Object.freeze({
  exclusiveRiskLedger: 20,
  rawClassificationProvenance: 21,
  missingEvidenceFailClosed: 26,
  affirmativeClosureRiskCeiling: 27,
});
const reviewPayloadKeys = new Set(['snapshotId', 'tag', 'local', 'auditLinks']);
const reviewLocalKeys = new Set([
  'schemaVersion',
  'score',
  'band',
  'status',
  'diagnosticStatus',
  'staleAudit',
  'recommended',
  'reason',
  'negativeIssues',
  'positiveIssues',
  'scoredAt',
  'dataFreshness',
  'sourceProvenance',
  'auditDigest',
  'modelVersion',
  'promptVersion',
  'input',
  'components',
  'issueEvidence',
  'gateEvidence',
]);
const comparisonPayloadKeys = new Set(['schemaVersion', 'snapshot', 'releases']);
const comparisonSnapshotKeys = new Set(['id', 'sourceUrl', 'capturedAt', 'pageTitle']);
const comparisonReleaseKeys = new Set(['tag', 'local', 'upstream', 'delta']);
const comparisonLocalKeys = new Set([
  'schemaVersion',
  'score',
  'band',
  'status',
  'diagnosticStatus',
  'staleAudit',
  'recommended',
  'reason',
  'negativeIssues',
  'positiveIssues',
  'scoredAt',
  'dataFreshness',
  'modelVersion',
  'components',
  'input',
  'gateEvidence',
]);
const comparisonUpstreamKeys = new Set([
  'schemaVersion',
  'snapshotId',
  'tag',
  'score',
  'band',
  'status',
  'recommended',
  'reason',
  'negativeIssues',
  'positiveIssues',
  'totalAttributedIssues',
  'visibleIssues',
  'rawCardText',
]);
const comparisonDeltaKeys = new Set(['schemaVersion', 'score', 'negativeIssues']);
const releaseRowKeys = new Set([
  'advisories',
  'auditLinks',
  'band',
  'brokenSurfaces',
  'closedSeriousFixed',
  'dataFreshness',
  'explanation',
  'finalScore',
  'htmlUrl',
  'maintainerSignals',
  'name',
  'negativeIssues',
  'openedSeriousDuringReign',
  'positiveIssues',
  'publishedAt',
  'reason',
  'recommended',
  'schemaVersion',
  'scoreAudit',
  'scoredAt',
  'snapshotId',
  'status',
  'diagnosticStatus',
  'staleAudit',
  'tag',
]);
const releaseHistoryRowKeys = new Set([
  'schemaVersion',
  'snapshotId',
  'tag',
  'publishedAt',
  'finalScore',
  'status',
  'diagnosticStatus',
  'staleAudit',
  'band',
  'recommended',
  'scoredAt',
  'scoreAudit',
  'dataFreshness',
  'auditLinks',
]);
const publicReleaseKeys = new Set([
  'auditLinks',
  'band',
  'dataFreshness',
  'explanation',
  'issues',
  'negativeIssues',
  'positiveIssues',
  'profileEvidence',
  'publishedAt',
  'reason',
  'recommended',
  'score',
  'scoreAudit',
  'scoredAt',
  'snapshotId',
  'schemaVersion',
  'status',
  'diagnosticStatus',
  'staleAudit',
  'tag',
  'totalAttributedIssues',
  'url',
  'watchIssues',
]);
const publicProfileEvidenceKeys = new Set([
  'schemaVersion',
  'sourceMode',
  'issueEvidenceSchemaVersion',
  'profileRowCount',
  'profileRowsDigest',
  'publicationBinding',
  'issueCount',
  'weightedIssueCount',
  'surfaceIssueCount',
  'surfaceWeight',
  'surfaces',
]);
const publicProfileEvidencePublicationBindingKeys = new Set([
  'schemaVersion',
  'auditDigest',
  'authorityRunId',
  'authorityRunContentHash',
  'historyV2SealContentHash',
  'sourceIdentityDigest',
  'scoreModelVersion',
  'promptVersion',
  'profileRowsDigest',
  'contentHash',
]);
const publicProfileEvidenceSurfaceKeys = new Set(['label', 'icon', 'count', 'weight', 'tiers', 'weightByTier']);
const publicIssueKeys = new Set([
  'affectedUsers',
  'closedAt',
  'hasWorkaround',
  'number',
  'scope',
  'sentiment',
  'severity',
  'state',
  'surface',
  'title',
  'url',
]);
const issueEvidenceAuditKeys = new Set([
  'schemaVersion',
  'snapshotId',
  'auditDigest',
  'auditIdentity',
  'tag',
  'sourceMode',
  'scoredAt',
  'staleAudit',
  'dataFreshness',
  'labelCutoffAt',
  'filters',
  'countsByTier',
  'summaryByTier',
  'unfilteredCountsByTier',
  'unfilteredSummaryByTier',
  'filteredCountsByTier',
  'filteredSummaryByTier',
  'filteredSummary',
  'tierInfo',
  'totals',
  'total',
  'totalRows',
  'distinctIssueCount',
  'limit',
  'cursor',
  'nextCursor',
  'links',
  'rows',
]);
const issueEvidenceAuditFilterKeys = new Set([
  'tier',
  'tiers',
  'impact',
  'impacts',
  'state',
  'states',
  'sentiment',
  'sentiments',
  'severity',
  'severities',
  'functionality',
  'functionalities',
  'scope',
  'scopes',
  'affectedUsers',
  'affectedUsersList',
  'issue',
  'issueNumber',
  'fieldConfirmed',
  'minWeight',
  'maxWeight',
  'sort',
  'direction',
  'summaryOnly',
]);
const issueEvidenceAuditTotalsKeys = new Set(['unfilteredRows', 'filteredRows', 'unfilteredDistinctIssues', 'filteredDistinctIssues']);
const issueEvidenceAuditRowKeys = new Set([
  'tier',
  'tierLabel',
  'tierDescription',
  'issue',
  'weight',
  'duplicateCluster',
  'aliasGroup',
  'adversePoints',
  'humanReporterCount',
  'commentCount',
  'fieldConfirmed',
  'confirmationReasons',
  'humanCommenterCount',
  'maintainerCommenterCount',
  'contributorCommenterCount',
  'reactionTotal',
  'positiveReactionCount',
  'commenterScanTruncated',
  'installImpactClass',
  'installImpactMultiplier',
  'clusterReleaseLocal',
  'releaseLocalEvidence',
  'debtClassification',
  'debtClassificationDiff',
  'fixCreditDecision',
  'scoreAffecting',
]);
const issueEvidenceIssueKeys = new Set([
  'number',
  'title',
  'url',
  'state',
  'createdAt',
  'updatedAt',
  'closedAt',
  'author',
  'authorAssociation',
  'isBot',
  'comments',
  'uniqueHumanCommenters',
  'maintainerCommenters',
  'contributorCommenters',
  'commenterScanTruncated',
  'reactionTotal',
  'positiveReactions',
  'labels',
  'currentLabels',
  'labelSource',
  'labelTimelineEventCount',
  'labelSnapshotCount',
  'labelCutoffAt',
  'classificationOrigin',
  'classificationPromptVersion',
  'classificationProvenance',
  'classifiedAt',
  'classifiedCommentsDigest',
  'classifiedUpdatedAt',
  'classifierSourceIdentity',
  'classifierSourceIdentityDigest',
  'rawModelOutput',
  'storedClassification',
  'rawClassification',
  'classification',
  'classificationDiff',
  'affectsVersion',
  'duplicateCluster',
  'missing',
]);
const closureProofAuditKeys = new Set([
  'schemaVersion',
  'snapshotId',
  'auditDigest',
  'auditIdentity',
  'tag',
  'sourceMode',
  'scoredAt',
  'staleAudit',
  'dataFreshness',
  'filters',
  'totals',
  'total',
  'totalRows',
  'distinctIssueCount',
  'unfilteredCountsByStatus',
  'filteredCountsByStatus',
  'unfilteredCountsByRiskDisposition',
  'filteredCountsByRiskDisposition',
  'limit',
  'cursor',
  'nextCursor',
  'links',
  'rows',
]);
const closureProofAuditFilterKeys = new Set(['issue', 'issueNumber', 'status', 'riskDisposition']);
const closureProofAuditTotalsKeys = new Set(['unfilteredRows', 'filteredRows', 'unfilteredDistinctIssues', 'filteredDistinctIssues']);
const closureProofAuditRowKeys = new Set([
  'issueNumber',
  'title',
  'url',
  'closedAt',
  'status',
  'summary',
  'riskDisposition',
  'riskDispositionLabel',
  'riskWeight',
  'riskWeightLabel',
  'checkedAt',
  'labels',
  'classification',
  'classificationDiff',
  'evidence',
]);
const closureProofAuditEvidenceKeys = new Set([
  'stateReasons',
  'closureActors',
  'closureContextCommentCount',
  'hasClosingLink',
  'hasMergedClosingPr',
  'hasReachableClosingPr',
  'hasNotReachableClosingPr',
  'hasReachableFixCommit',
  'hasNotReachableFixCommit',
  'hasUnknownFixCommit',
  'canonicalIssues',
  'canonicalIssueDetails',
  'canonicalResolution',
  'closingPrs',
  'linkedPrs',
  'relatedPrContext',
  'reachableTrustedFixProofPrs',
  'matchingComments',
  'nonActionableRationaleComments',
  'laterFixProof',
  'unscoredFixProof',
  'fixCommitProof',
  'canonicalFixCommitProof',
  'referencedCommitContext',
  'reachableFixCommits',
  'notReachableFixCommits',
  'unknownFixCommits',
]);
const closureProofAuditPrRefKeys = new Set([
  'number', 'repositoryNameWithOwner', 'source', 'willCloseTarget', 'referencedAt',
  'sourceCommentDatabaseId', 'sourceCommentUrl', 'title', 'url', 'state', 'merged', 'mergedAt',
  'reachabilityStatus', 'reachabilityMethod', 'reachabilityEvidence', 'mergeCommitOid', 'metadataMissing',
]);
const closureProofAuditCommentRefKeys = new Set([
  'databaseId', 'issueNumber', 'url', 'author', 'createdAt', 'updatedAt', 'snippet',
]);
const closureProofAuditCommitRefKeys = new Set([
  'issueNumber', 'sourceIssueNumber', 'sourceIssueUrl', 'commitOid', 'shortOid', 'commitUrl',
  'status', 'source', 'referencedAt', 'author', 'authorAssociation', 'trustedSource',
  'tagCommitOid', 'sourceCommentDatabaseId', 'sourceCommentUrl', 'evidence', 'snippet',
]);
const reachabilityAuditKeys = new Set([
  'schemaVersion',
  'snapshotId',
  'auditDigest',
  'auditIdentity',
  'tag',
  'sourceMode',
  'scoredAt',
  'staleAudit',
  'dataFreshness',
  'filters',
  'totals',
  'total',
  'totalRows',
  'distinctPullRequestCount',
  'countsByStatus',
  'filteredCountsByStatus',
  'unfilteredCountsByStatus',
  'limit',
  'cursor',
  'nextCursor',
  'links',
  'rows',
]);
const reachabilityAuditFilterKeys = new Set(['status', 'pr']);
const reachabilityAuditTotalsKeys = new Set(['unfilteredRows', 'filteredRows', 'unfilteredPullRequests', 'filteredPullRequests']);
const auditLinkKeys = new Set(['review', 'issues', 'closureProofs', 'reachability']);
const reviewPageLinkKeys = new Set(['self', 'next']);
const reviewPublicationBindingParams = new Set(['publicationSnapshot', 'auditDigest']);
const reviewAuditUnavailable = 'unavailable';
const reachabilityAuditRowKeys = new Set([
  'repositoryNameWithOwner',
  'number',
  'title',
  'url',
  'state',
  'merged',
  'mergedAt',
  'status',
  'method',
  'checkedAt',
  'tagCommitOid',
  'mergeCommitOid',
  'prMergeCommitOid',
  'baseRefName',
  'evidence',
]);
const publicSentimentRank = new Map([['negative', 0], ['positive', 1], ['neutral', 2]]);
const publicSeverityRank = new Map([['critical', 0], ['high', 1], ['medium', 2], ['low', 3]]);
const publicScopeRank = new Map([['broad', 0], ['moderate', 1], ['niche', 2]]);
const publicAffectedUsersRank = new Map([['many', 0], ['some', 1], ['few', 2], ['unknown', 3]]);
const componentLedgerRows = [
  ['base', 'Base'],
  ['verifiedDebt', 'Field blocker debt'],
  ['carryoverDebt', 'Open inherited/carryover context'],
  ['staleDebt', 'Weak or stale evidence'],
  ['closureRisk', 'Closed-issue proof gap'],
  ['coverage', 'Classification coverage'],
  ['survival', 'Stable survival'],
  ['shakeout', 'Beta shakeout'],
  ['regression', 'Opened vs fixed balance'],
  ['breaking', 'Breaking changes'],
  ['releaseVerification', 'Release checks'],
  ['artifactVerification', 'Artifact verification'],
];
const componentLedgerLabels = new Map(componentLedgerRows);
const gateLedgerLabels = new Map([
  ['cveGate', 'Security advisory install gate'],
  ['settleGate', 'Settle-time gate'],
]);
const optionalLedgerLabels = new Map([
  ['precisionAdjustment', 'Unrounded model adjustment'],
]);
const ledgerCapLabels = new Map([
  ['closureRiskCeiling', 'Closed issue proof ceiling'],
  ['hotfixCeiling', 'Hotfix successor ceiling'],
]);
const ledgerKeys = new Set([
  'schemaVersion',
  'ledgerType',
  'immutable',
  'formulaCode',
  'evaluatedAt',
  'finalScore',
  'status',
  'band',
  'thresholds',
  'operations',
  'evidence',
  'aliasElection',
  'cveGate',
  'gapToTen',
  'digest',
  'subtotalBeforeCaps',
  'scoreAfterCaps',
  'rows',
  'caps',
  'explanationAudit',
]);
const ledgerRowKeys = new Set(['key', 'label', 'points', 'kind', 'metric', 'note']);
const ledgerCapKeys = new Set(['key', 'label', 'ceiling', 'applied', 'before', 'after', 'reason']);
const explanationDetailKeys = new Set(['code', 'label', 'text', 'metrics', 'buckets', 'riskBuckets', 'issueRefs']);
const explanationIssueRefKeys = new Set(['number', 'title', 'url', 'state', 'status', 'tier', 'weight', 'fieldConfirmed', 'confirmationReasons', 'releaseLocal', 'releaseLocalEvidence', 'releaseScopedState', 'scoringReason', 'installImpactClass', 'installImpactMultiplier', 'proof']);
const confirmationReasonKeys = new Set([
  'code', 'source', 'author', 'association', 'occurredAt',
  'updatedAt', 'commentId', 'commentUrl', 'issueNodeId',
  'issueAuthorNodeId', 'issueAuthorType', 'commentNodeId',
  'commentNodeType', 'actorNodeId', 'actorType', 'commentBodyDigest',
  'label', 'eventId', 'snippet',
]);
const releaseLocalEvidenceKeys = new Set([
  'kind', 'source', 'version', 'snippet',
  'commentId', 'commentUrl', 'commentNodeId', 'author',
  'actorNodeId', 'actorType', 'association', 'occurredAt',
  'updatedAt', 'commentBodyDigest',
]);
const confirmationReasonCodeByLabel = new Map([
  ['P0', 'human_applied_p0'],
  ['P1', 'human_applied_p1'],
  ['regression', 'human_applied_regression'],
]);
const commentConfirmationRequiredKeys = [
  'updatedAt',
  'commentId',
  'commentUrl',
  'issueNodeId',
  'issueAuthorNodeId',
  'issueAuthorType',
  'commentNodeId',
  'commentNodeType',
  'actorNodeId',
  'actorType',
  'commentBodyDigest',
  'snippet',
];
const commentOnlyConfirmationReasonKeys = [
  'association',
  'updatedAt',
  'commentId',
  'commentUrl',
  'issueNodeId',
  'issueAuthorNodeId',
  'issueAuthorType',
  'commentNodeId',
  'commentNodeType',
  'actorNodeId',
  'actorType',
  'commentBodyDigest',
  'snippet',
];
const releaseLocalCommentKeys = [
  'commentId',
  'commentUrl',
  'commentNodeId',
  'author',
  'actorNodeId',
  'actorType',
  'association',
  'occurredAt',
  'updatedAt',
  'commentBodyDigest',
];
const explanationIssueProofKeys = new Set([
  'status', 'statusLabel', 'riskDisposition', 'riskDispositionLabel', 'summary', 'riskWeight',
  'canonicalIssue', 'canonicalPath', 'openPrs', 'reachablePrs', 'notReachablePrs',
  'unknownReachabilityPrs', 'closedUnmergedPrs', 'externalClosingPrs',
]);
const explanationLinkedRefKeys = new Set([
  'number', 'title', 'url', 'state', 'status', 'repositoryNameWithOwner', 'source', 'merged',
  'mergedAt', 'referencedAt', 'willCloseTarget', 'reachabilityMethod', 'mergeCommitOid',
  'sourceCommentUrl',
]);
const forbiddenPublicKeys = new Set([
  'comparison',
  'delta',
  'local',
  'pageText',
  'rawCardText',
  'snapshot',
  'sourceUrl',
  'upstream',
]);
const forbiddenReviewComparisonKeys = new Set([
  'comparison',
  'delta',
  'pageText',
  'rawCardText',
  'snapshot',
  'sourceUrl',
  'upstream',
]);

function releaseHasPersistedScore(release) {
  return release?.final_score != null ||
    release?.score != null ||
    release?.scored_at != null ||
    release?.scoredAt != null;
}

function verifyUnscoredReleaseStorage({ failures, tag, release }) {
  for (const field of [
    'final_score',
    'negative_issues',
    'positive_issues',
    'scored_at',
    'state',
    'score_reason',
    'broken_surfaces',
  ]) {
    expect(failures, tag, release?.[field] == null,
      `unscored release ${field} must be null, got ${JSON.stringify(release?.[field])}`);
  }
  for (const field of [
    'recommended',
    'closed_serious_fixed',
    'opened_serious_during_reign',
  ]) {
    expect(failures, tag, Number(release?.[field] ?? 0) === 0,
      `unscored release ${field} must be zero, got ${JSON.stringify(release?.[field])}`);
  }
}

export async function verifyReleaseAudit({ reader, apiBase = null, fetchJson = defaultFetchJson, limit = 10, scoredOnly = false }) {
  const releases = reader.listReleases(limit, { scoredOnly });
  const failures = [];
  const rows = [];
  let currentSourceIdentity = null;
  let scorePublication = null;
  let scorePublicationBaseline = null;
  let advisorySnapshotAuditProjection = null;
  if (typeof reader.scoreSourceIdentity === 'function') {
    try {
      currentSourceIdentity = reader.scoreSourceIdentity();
    } catch (error) {
      failures.push(`source-identity: current score source identity could not be computed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (typeof reader.scorePublicationIntegrity === 'function') {
    try {
      scorePublication = reader.scorePublicationIntegrity();
      scorePublicationBaseline = sortJson(scorePublication);
      for (const failure of scorePublicationFailuresForAudit(reader, scorePublication)) {
        failures.push(`score-publication: ${failure}`);
      }
    } catch (error) {
      failures.push(
        `score-publication: sealed audit verification failed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  if (typeof reader.advisorySnapshotAuditProjection === 'function') {
    try {
      advisorySnapshotAuditProjection =
        reader.advisorySnapshotAuditProjection();
      expect(
        failures,
        'advisory-snapshot',
        advisorySnapshotAuditProjection?.schemaVersion ===
          COMPOUND_ADVISORY_AUDIT_PROJECTION_SCHEMA_VERSION,
        `advisory snapshot audit schemaVersion ` +
        `(${advisorySnapshotAuditProjection?.schemaVersion}) must equal ` +
        COMPOUND_ADVISORY_AUDIT_PROJECTION_SCHEMA_VERSION,
      );
      expect(
        failures,
        'advisory-snapshot',
        advisorySnapshotAuditProjection?.sourceMode ===
          COMPOUND_ADVISORY_AUDIT_SOURCE_MODE,
        `advisory snapshot audit sourceMode ` +
        `(${advisorySnapshotAuditProjection?.sourceMode}) must equal ` +
        COMPOUND_ADVISORY_AUDIT_SOURCE_MODE,
      );
      expect(
        failures,
        'advisory-snapshot',
        advisorySnapshotAuditProjection?.verified === true &&
          Number(advisorySnapshotAuditProjection?.failedCount ?? -1) === 0,
        `receipt-authorized advisory snapshot v2 publication must verify: ` +
        `${
          (advisorySnapshotAuditProjection?.problems ?? []).join('; ') ||
          'unknown failure'
        }`,
      );
    } catch (error) {
      failures.push(
        `advisory-snapshot: v2 publication verification failed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  } else if (typeof reader.advisorySnapshotIntegrity === 'function') {
    try {
      const advisorySnapshot = reader.advisorySnapshotIntegrity();
      expect(
        failures,
        'advisory-snapshot',
        Number(advisorySnapshot?.failedCount ?? -1) === 0,
        `advisory snapshot completeness metadata/digest must be valid: ` +
        `${(advisorySnapshot?.problems ?? []).join('; ') || 'unknown failure'}`,
      );
    } catch (error) {
      failures.push(
        `advisory-snapshot: completeness verification failed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  const latestScoredStableRelease = releases.find(releaseHasPersistedScore);
  if (typeof reader.issueCrawlMetadata === 'function') {
    try {
      const crawl = reader.issueCrawlMetadata();
      const crawlHealth = assessIssueCrawlHealth(
        crawl?.issueCrawl ?? null,
        latestScoredStableRelease
          ? {
            tag: latestScoredStableRelease.tag,
            scoredAt: latestScoredStableRelease.scored_at ?? latestScoredStableRelease.scoredAt ?? null,
          }
          : null,
        {
          baseline: crawl?.baseline ?? null,
          repository: trackedRepositoryNameWithOwner,
        },
      );
      for (const failure of crawlHealth.failures) {
        failures.push(`issue-crawl: ${failure}`);
      }
    } catch (error) {
      failures.push(
        `issue-crawl: completeness verification failed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  if (typeof reader.issueCatalogSnapshotIntegrity === 'function') {
    try {
      const snapshots = reader.issueCatalogSnapshotIntegrity();
      if (Number(snapshots?.failedCount ?? 0) > 0) {
        const examples = Array.isArray(snapshots?.examples)
          ? snapshots.examples
            .slice(0, 5)
            .map((problem) => `${problem.snapshotId ?? 'ledger'}: ${problem.detail}`)
            .join('; ')
          : '';
        failures.push(
          `issue-catalog-snapshots: integrity failed ` +
          `(schema=${Number(snapshots?.schemaFailureCount ?? 0)}, ` +
          `ledger=${Number(snapshots?.ledgerFailureCount ?? 0)}, ` +
          `crawlLink=${Number(snapshots?.crawlLinkFailureCount ?? 0)}, ` +
          `orphans=${Number(snapshots?.orphanRowCount ?? 0)})` +
          (examples ? `: ${examples}` : ''),
        );
      }
    } catch (error) {
      failures.push(
        `issue-catalog-snapshots: integrity verification failed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  const strictEvidenceModel = typeof reader.fixCreditProofRowsForIssue === 'function';
  const reachabilityTagsToVerify = new Set();
  verifyRecommendedReleaseInvariant({ failures, releases });

  for (const release of releases) {
    const tag = release.tag;
    const closed = reader.closedDuringReign(tag);
    const rawClosed = typeof reader.rawClosedDuringReign === 'function'
      ? reader.rawClosedDuringReign(tag)
      : closed;
    const verified = reader.verifiedFixedForRelease(tag);
    const unverified = reader.unverifiedClosedForRelease(tag);
    const proofRows = reader.proofRowsFor(tag);
    const closureProofIssueNumbers = new Set(
      proofRows.map((row) => Number(row.issue_number)),
    );
    const unverifiedWithoutClosureProof = unverified.filter(
      (row) => !closureProofIssueNumbers.has(Number(row.number)),
    );
    const sourceFreshnessRows = typeof reader.sourceFreshnessFor === 'function'
      ? reader.sourceFreshnessFor(tag)
      : [];
    const audit = reader.getReleaseScoreAudit(tag);
    const persistedGate = audit ? parseJson(audit.gate_evidence_json, {}) : {};
    const persistedFixCredit = persistedGate?.fixProvenance?.releaseFixCredit;
    const fixedProof = proofRows.filter((row) => row.status === 'fixed_in_release');
    const notCountedProof = proofRows.filter((row) => row.status !== 'fixed_in_release');
    const releaseIsScored = releaseHasPersistedScore(release);
    if (!releaseIsScored) {
      verifyUnscoredReleaseStorage({ failures, tag, release });
    }
    const enforceRawClosedCoverage = releaseIsScored || proofRows.length > 0;
    const creditedDecisionCount = countFixCreditDecisions(persistedFixCredit?.decisions).credited;
    if (releaseIsScored) {
      reachabilityTagsToVerify.add(tag);
      if (typeof reader.issueStateSnapshotIntegrityForRelease === 'function') {
        verifyIssueStateSnapshotIntegrity({
          failures,
          tag,
          report: reader.issueStateSnapshotIntegrityForRelease(tag),
        });
      }
      if (typeof reader.closureDependencySnapshotIntegrityForRelease === 'function') {
        verifyClosureDependencySnapshotIntegrity({
          failures,
          tag,
          report: reader.closureDependencySnapshotIntegrityForRelease(tag),
        });
      }
    }

    rows.push({
      tag,
      closed: closed.length,
      verified: verified.length,
      unverified: unverified.length,
      proof: proofRows.length,
      counted: strictEvidenceModel ? creditedDecisionCount : fixedProof.length,
      notCounted: strictEvidenceModel ? proofRows.length - creditedDecisionCount : notCountedProof.length,
    });

    if (enforceRawClosedCoverage) {
      expect(failures, tag, rawClosed.length === closed.length,
        `raw closed release-window issues (${rawClosed.length}) must equal classified closed issues (${closed.length})`);
    }
    expect(failures, tag, closed.length === verified.length + unverified.length,
      `closedDuringReign (${closed.length}) must equal verified + unverified (${verified.length + unverified.length})`);
    expect(failures, tag, proofRows.length === (enforceRawClosedCoverage ? rawClosed.length : closed.length),
      enforceRawClosedCoverage
        ? `closure proofs (${proofRows.length}) must cover raw closed release-window issues (${rawClosed.length})`
        : `closure proofs (${proofRows.length}) must cover classified closed release-window issues (${closed.length})`);
    expect(failures, tag, fixedProof.length + notCountedProof.length === proofRows.length,
      'counted + not-counted proof rows must equal all proof rows');

    const verifiedNumbers = new Set(verified.map((row) => row.number));
    const rawClosedNumbers = new Set(rawClosed.map((row) => row.number));
    const proofByNumber = new Map(proofRows.map((row) => [row.issue_number, row]));
    for (const row of proofRows) {
      expect(failures, tag, rawClosedNumbers.has(row.issue_number),
        `proof issue #${row.issue_number} must belong to the raw closed release window`);
    }
    for (const row of fixedProof) {
      expect(failures, tag, verifiedNumbers.has(row.issue_number),
        `fixed_in_release issue #${row.issue_number} must be present in verifiedFixedForRelease`);
    }

    for (const row of verified) {
      const proof = proofByNumber.get(row.number);
      if (!proof) continue;
      const evidence = parseJson(proof.evidence_json, {});
      if (proof.status !== 'fixed_in_release') {
        expect(failures, tag, row.sentiment !== 'negative',
          `verified issue #${row.number} has proof status ${proof.status}; only non-negative verified closures may avoid fixed_in_release`);
      }
      expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
        `verified issue #${row.number} must have final COMPLETED closure evidence`);
    }

    for (const row of proofRows) {
      expect(failures, tag, knownProofStatuses.has(row.status), `unknown proof status ${row.status} for issue #${row.issue_number}`);
      const evidence = parseJson(row.evidence_json, {});
      verifyProofEvidenceShape({ failures, tag, row, evidence });
      if (
        scoreModelSupportsCapability(
          audit?.score_model_version,
          'missingEvidenceFailClosed',
        ) &&
        riskDispositionForStatus(row.status) === 'missing_evidence' &&
        closureRiskClassificationWeightForProofRow(row) > 0
      ) {
        failures.push(
          `${tag}: score-affecting negative missing_evidence issue #${row.issue_number} ` +
          `status=${row.status} makes the persisted analysis incomplete`,
        );
      }
      if (strictEvidenceModel) {
        expect(failures, tag, evidence.proofAnalyzerVersion === CLOSURE_PROOF_ANALYZER_VERSION,
          `proof issue #${row.issue_number} analyzer version (${evidence.proofAnalyzerVersion}) must equal ${CLOSURE_PROOF_ANALYZER_VERSION}`);
      }
      const prEvidence = typeof reader.prReachabilityEvidenceForIssue === 'function'
        ? reader.prReachabilityEvidenceForIssue(tag, row.issue_number)
        : [];
      verifyProofPrReachabilityEvidence({ failures, tag, row, evidence, prEvidence });
      if (row.status === 'fixed_in_release') {
        expect(failures, tag, evidence.hasReachableClosingPr === true || evidence.hasReachableFixCommit === true,
          `fixed_in_release issue #${row.issue_number} must have reachable PR or commit evidence`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_in_release issue #${row.issue_number} must have COMPLETED state reason`);
      }
      if (row.status === 'fixed_after_release') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `fixed_after_release issue #${row.issue_number} must have not-reachable PR or commit evidence`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_after_release issue #${row.issue_number} must have COMPLETED state reason`);
      }
      if (row.status === 'fixed_in_later_release') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `fixed_in_later_release issue #${row.issue_number} must have not-reachable PR or commit evidence for this tag`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_in_later_release issue #${row.issue_number} must have COMPLETED state reason`);
        expect(failures, tag, evidence.laterFixProof?.releaseTag && ['pr', 'commit'].includes(evidence.laterFixProof?.proofType),
          `fixed_in_later_release issue #${row.issue_number} must include laterFixProof metadata`);
      }
      if (row.status === 'fixed_not_in_scored_releases') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `fixed_not_in_scored_releases issue #${row.issue_number} must have not-reachable PR or commit evidence`);
        expect(failures, tag, !evidence.laterFixProof,
          `fixed_not_in_scored_releases issue #${row.issue_number} must not include laterFixProof metadata`);
      }
      if (row.status === 'fixed_after_latest_release') {
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'after_latest_release',
          `fixed_after_latest_release issue #${row.issue_number} must include after-latest unscoredFixProof metadata`);
        verifyAfterLatestFixProof({ failures, tag, row, evidence, latestScoredStableRelease });
      }
      if (row.status === 'fixed_skipped_by_later_releases') {
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'skipped_by_later_releases',
          `fixed_skipped_by_later_releases issue #${row.issue_number} must include skipped-by-later unscoredFixProof metadata`);
      }
      if (row.status === 'duplicate_to_fixed_after_release') {
        expect(failures, tag, canonicalFixedAfterRelease(evidence),
          `duplicate_to_fixed_after_release issue #${row.issue_number} must resolve to fixed-after canonical proof`);
      }
      if (row.status === 'duplicate_with_release_fix_proof') {
        expect(failures, tag, trustedReachableFixProofPrs(evidence).length > 0,
          `duplicate_with_release_fix_proof issue #${row.issue_number} must include trusted reachable closure-comment fix proof PR evidence`);
      }
      if (row.status === 'duplicate_to_fixed_in_release') {
        expect(failures, tag, evidence.canonicalResolution?.terminalProof?.status === 'fixed_in_release' ||
          canonicalFixCommitProof(evidence).some((proof) => proof.status === 'reachable'),
        `duplicate_to_fixed_in_release issue #${row.issue_number} must resolve to fixed-in-release canonical proof`);
      }
      if (row.status === 'duplicate_to_open_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'open',
          `duplicate_to_open_canonical issue #${row.issue_number} must resolve to an open terminal`);
      }
      if (row.status === 'superseded_to_open_pr') {
        expect(failures, tag, Array.isArray(evidence.canonicalOpenPrs) &&
          evidence.canonicalOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' &&
            Number(pr?.merged ?? 0) === 0 && pr?.source === 'ClosureComment.prMention'),
          `superseded_to_open_pr issue #${row.issue_number} must include trusted closure-comment open PR evidence`);
      }
      if (row.status === 'duplicate_with_open_pr_context') {
        expect(failures, tag, Array.isArray(evidence.relatedOpenPrs) &&
          evidence.relatedOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) === 0),
          `duplicate_with_open_pr_context issue #${row.issue_number} must include related open PR evidence`);
      }
      if (row.status === 'duplicate_related_closed_unmerged_pr_context') {
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `duplicate_related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'duplicate_related_merged_pr_not_reachable_context') {
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `duplicate_related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'duplicate_related_merged_pr_reachable_context_without_fix_credit') {
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `duplicate_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'duplicate_related_merged_pr_reachability_unknown') {
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `duplicate_related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'duplicate_related_pr_without_release_fix') {
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `duplicate_related_pr_without_release_fix issue #${row.issue_number} must include linked PR context`);
      }
      if (row.status === 'duplicate_to_closed_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_closed_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, !!evidence.canonicalResolution?.terminalProof,
          `duplicate_to_closed_canonical issue #${row.issue_number} must include terminal proof; missing terminal proof should use duplicate_to_closed_canonical_missing_proof`);
        expect(failures, tag, riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'unsupported_closure_claim',
          `duplicate_to_closed_canonical issue #${row.issue_number} must resolve to unsupported terminal proof; use a more specific canonical status for resolved/open/missing proof`);
      }
      if (row.status === 'duplicate_to_non_actionable_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_non_actionable_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        const terminalProof = evidence.canonicalResolution?.terminalProof;
        expect(failures, tag, riskDispositionForStatus(terminalProof?.status) === 'neutral_or_non_actionable',
          `duplicate_to_non_actionable_canonical issue #${row.issue_number} must resolve to neutral/non-actionable terminal proof`);
        if (terminalProof?.status === 'not_planned') {
          expect(failures, tag, terminalProof.concreteNonActionableRationale === true,
            `duplicate_to_non_actionable_canonical issue #${row.issue_number} with not_planned terminal proof must include concrete non-actionable rationale`);
        }
      }
      if (row.status === 'duplicate_to_known_not_in_release_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_known_not_in_release_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'known_not_in_release',
          `duplicate_to_known_not_in_release_canonical issue #${row.issue_number} must resolve to known-not-in-release terminal proof`);
      }
      if (row.status === 'duplicate_to_open_pr_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_open_pr_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag,
          riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'open_canonical_risk' ||
          evidence.canonicalResolution?.terminalProof?.status === 'related_open_pr_context',
          `duplicate_to_open_pr_canonical issue #${row.issue_number} must resolve to open-risk terminal proof`);
      }
      if (row.status === 'duplicate_to_unverified_closed_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_unverified_closed_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'unsupported_closure_claim' ||
          riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'missing_evidence',
          `duplicate_to_unverified_closed_canonical issue #${row.issue_number} must resolve to unsupported/missing terminal proof`);
      }
      if (row.status === 'duplicate_to_closed_canonical_missing_proof') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_closed_canonical_missing_proof issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, !evidence.canonicalResolution?.terminalProof ||
          ['no_timeline_event', 'unknown'].includes(evidence.canonicalResolution.terminalProof.status),
          `duplicate_to_closed_canonical_missing_proof issue #${row.issue_number} must have missing/incomplete terminal proof`);
      }
      if (row.status === 'admin_not_planned_unverified') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `admin_not_planned_unverified issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Number(evidence.closureContextCommentCount ?? 0) > 0,
          `admin_not_planned_unverified issue #${row.issue_number} must include close-time context; use admin_not_planned_no_context when none exists`);
        expect(failures, tag, evidence.hasReachableFixCommit !== true && evidence.hasReachableClosingPr !== true &&
          evidence.hasNotReachableFixCommit !== true && evidence.hasNotReachableClosingPr !== true &&
          evidence.hasUnknownFixCommit !== true,
          `admin_not_planned_unverified issue #${row.issue_number} must not have direct fix proof; use a not_planned_* proof status`);
        expect(failures, tag, !Array.isArray(evidence.linkedPrs) || evidence.linkedPrs.length === 0,
          `admin_not_planned_unverified issue #${row.issue_number} must not include linked PR context; use a not_planned_* proof status`);
      }
      if (row.status === 'admin_not_planned_no_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `admin_not_planned_no_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Number(evidence.closureContextCommentCount ?? -1) === 0,
          `admin_not_planned_no_context issue #${row.issue_number} must have zero close-time rationale comments`);
        expect(failures, tag, evidence.hasReachableFixCommit !== true && evidence.hasReachableClosingPr !== true &&
          evidence.hasNotReachableFixCommit !== true && evidence.hasNotReachableClosingPr !== true &&
          evidence.hasUnknownFixCommit !== true,
          `admin_not_planned_no_context issue #${row.issue_number} must not have direct fix proof; use a not_planned_* proof status`);
        expect(failures, tag, !Array.isArray(evidence.linkedPrs) || evidence.linkedPrs.length === 0,
          `admin_not_planned_no_context issue #${row.issue_number} must not include linked PR context; use a not_planned_* proof status`);
      }
      if (row.status === 'insufficient_info') {
        expect(failures, tag, Array.isArray(evidence.matchingComments) && evidence.matchingComments.length > 0,
          `insufficient_info issue #${row.issue_number} must include close-time matching rationale`);
      }
      if (row.status === 'not_planned_with_release_fix_proof') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_with_release_fix_proof issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, evidence.hasReachableFixCommit === true || evidence.hasReachableClosingPr === true ||
          trustedReachableFixProofPrs(evidence).length > 0,
          `not_planned_with_release_fix_proof issue #${row.issue_number} must have reachable PR or commit evidence`);
      }
      if (row.status === 'not_planned_fixed_after_release') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_fixed_after_release issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, evidence.hasNotReachableFixCommit === true || evidence.hasNotReachableClosingPr === true,
          `not_planned_fixed_after_release issue #${row.issue_number} must have not-reachable PR or commit evidence`);
      }
      if (row.status === 'not_planned_direct_fix_commit_reachability_unknown') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_direct_fix_commit_reachability_unknown issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, evidence.hasUnknownFixCommit === true && Array.isArray(evidence.unknownFixCommits) && evidence.unknownFixCommits.length > 0,
          `not_planned_direct_fix_commit_reachability_unknown issue #${row.issue_number} must include unknown direct fix commit evidence`);
      }
      if (row.status === 'not_planned_with_open_pr_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_with_open_pr_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Array.isArray(evidence.linkedPrs) &&
          evidence.linkedPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) !== 1),
          `not_planned_with_open_pr_context issue #${row.issue_number} must include open PR context`);
      }
      if (row.status === 'not_planned_linked_pr_not_merged') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_linked_pr_not_merged issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Array.isArray(evidence.linkedPrs) &&
          evidence.linkedPrs.some((pr) => Number(pr?.willCloseTarget ?? 0) === 1 && Number(pr?.merged ?? 0) !== 1),
          `not_planned_linked_pr_not_merged issue #${row.issue_number} must include an unmerged linked closing PR`);
      }
      if (row.status === 'not_planned_related_closed_unmerged_pr_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_closed_unmerged_pr_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `not_planned_related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'not_planned_related_merged_pr_not_reachable_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_merged_pr_not_reachable_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `not_planned_related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'not_planned_related_merged_pr_reachable_context_without_fix_credit') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `not_planned_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'not_planned_related_merged_pr_reachability_unknown') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_merged_pr_reachability_unknown issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `not_planned_related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'not_planned_related_pr_without_release_fix') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_pr_without_release_fix issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `not_planned_related_pr_without_release_fix issue #${row.issue_number} must include related PR references`);
      }
      if (row.status === 'linked_closing_pr_not_merged') {
        expect(failures, tag, evidence.hasClosingLink === true && evidence.hasMergedClosingPr !== true,
          `linked_closing_pr_not_merged issue #${row.issue_number} must have an unmerged/unknown closing PR`);
      }
      if (row.status === 'linked_closing_pr_open') {
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) !== 1),
          `linked_closing_pr_open issue #${row.issue_number} must have open linked closing PR evidence`);
      }
      if (row.status === 'linked_closing_pr_closed_unmerged') {
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'CLOSED' && Number(pr?.merged ?? 0) !== 1),
          `linked_closing_pr_closed_unmerged issue #${row.issue_number} must have closed-unmerged linked closing PR evidence`);
      }
      if (row.status === 'linked_closing_pr_reachability_unknown') {
        expect(failures, tag, evidence.hasClosingLink === true &&
          evidence.hasMergedClosingPr === true &&
          evidence.hasReachableClosingPr !== true &&
          evidence.hasNotReachableClosingPr !== true,
          `linked_closing_pr_reachability_unknown issue #${row.issue_number} must have merged closing PR with unknown reachability`);
      }
      if (row.status === 'related_pr_without_release_fix') {
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `related_pr_without_release_fix issue #${row.issue_number} must include related PR references`);
        expect(failures, tag, evidence.hasClosingLink !== true,
          `related_pr_without_release_fix issue #${row.issue_number} must not have a credited closing PR link`);
      }
      if (row.status === 'external_repo_closing_pr_unscored') {
        expect(failures, tag, relatedPrContext(evidence).externalClosing.length > 0,
          `external_repo_closing_pr_unscored issue #${row.issue_number} must include external closing PR context`);
      }
      if (row.status === 'related_open_pr_context') {
        expect(failures, tag, relatedPrContext(evidence).open.length > 0,
          `related_open_pr_context issue #${row.issue_number} must include open related PR context`);
      }
      if (row.status === 'related_closed_unmerged_pr_context') {
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'related_merged_pr_not_reachable_context') {
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'related_merged_pr_reachable_context_without_fix_credit') {
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'related_merged_pr_reachability_unknown') {
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'closed_without_release_fix_proof') {
        expect(failures, tag, evidence.hasClosingLink !== true,
          `closed_without_release_fix_proof issue #${row.issue_number} must not have a credited closing PR link`);
        expect(failures, tag, !Array.isArray(evidence.linkedPrs) || evidence.linkedPrs.length === 0,
          `closed_without_release_fix_proof issue #${row.issue_number} must not include related PR references`);
      }
      if (row.status === 'non_bug_fixed_in_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.hasReachableClosingPr === true || evidence.hasReachableFixCommit === true,
          `non_bug_fixed_in_release issue #${row.issue_number} must have reachable PR or commit evidence`);
      }
      if (row.status === 'non_bug_fixed_after_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `non_bug_fixed_after_release issue #${row.issue_number} must have not-reachable PR or commit evidence`);
      }
      if (row.status === 'non_bug_direct_fix_commit_reachability_unknown') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.hasUnknownFixCommit === true && Array.isArray(evidence.unknownFixCommits) && evidence.unknownFixCommits.length > 0,
          `non_bug_direct_fix_commit_reachability_unknown issue #${row.issue_number} must include unknown direct fix commit evidence`);
      }
      if (row.status === 'non_bug_fixed_in_later_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.laterFixProof?.releaseTag && ['pr', 'commit'].includes(evidence.laterFixProof?.proofType),
          `non_bug_fixed_in_later_release issue #${row.issue_number} must include laterFixProof metadata`);
      }
      if (row.status === 'non_bug_fixed_not_in_scored_releases') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, !evidence.laterFixProof,
          `non_bug_fixed_not_in_scored_releases issue #${row.issue_number} must not include laterFixProof metadata`);
      }
      if (row.status === 'non_bug_fixed_after_latest_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'after_latest_release',
          `non_bug_fixed_after_latest_release issue #${row.issue_number} must include after-latest unscoredFixProof metadata`);
        verifyAfterLatestFixProof({ failures, tag, row, evidence, latestScoredStableRelease });
      }
      if (row.status === 'non_bug_fixed_skipped_by_later_releases') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'skipped_by_later_releases',
          `non_bug_fixed_skipped_by_later_releases issue #${row.issue_number} must include skipped-by-later unscoredFixProof metadata`);
      }
      if (row.status === 'non_bug_linked_without_merge') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.hasClosingLink === true && evidence.hasMergedClosingPr !== true,
          `non_bug_linked_without_merge issue #${row.issue_number} must have an unmerged/unknown linked PR`);
      }
      if (row.status === 'non_bug_linked_pr_open') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) !== 1),
          `non_bug_linked_pr_open issue #${row.issue_number} must have open linked closing PR evidence`);
      }
      if (row.status === 'non_bug_linked_pr_closed_unmerged') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'CLOSED' && Number(pr?.merged ?? 0) !== 1),
          `non_bug_linked_pr_closed_unmerged issue #${row.issue_number} must have closed-unmerged linked closing PR evidence`);
      }
      if (row.status === 'non_bug_duplicate_to_fixed_in_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalProof?.status === 'fixed_in_release' ||
          canonicalFixCommitProof(evidence).some((proof) => proof.status === 'reachable'),
          `non_bug_duplicate_to_fixed_in_release issue #${row.issue_number} must resolve to fixed-in-release canonical proof`);
      }
      if (row.status === 'non_bug_duplicate_to_fixed_after_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, canonicalFixedAfterRelease(evidence),
          `non_bug_duplicate_to_fixed_after_release issue #${row.issue_number} must resolve to fixed-after canonical proof`);
      }
      if (row.status === 'non_bug_duplicate_to_open_canonical') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'open',
          `non_bug_duplicate_to_open_canonical issue #${row.issue_number} must resolve to an open terminal`);
      }
      if (row.status === 'non_bug_duplicate_to_closed_canonical') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed' &&
          !!evidence.canonicalResolution?.terminalProof,
          `non_bug_duplicate_to_closed_canonical issue #${row.issue_number} must resolve to a closed terminal with proof`);
      }
      if (row.status === 'non_bug_duplicate_to_closed_canonical_missing_proof') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `non_bug_duplicate_to_closed_canonical_missing_proof issue #${row.issue_number} must resolve to a closed terminal`);
      }
      if (row.status === 'non_bug_superseded_to_open_pr') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.canonicalOpenPrs) &&
          evidence.canonicalOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' &&
            Number(pr?.merged ?? 0) === 0 && pr?.source === 'ClosureComment.prMention'),
          `non_bug_superseded_to_open_pr issue #${row.issue_number} must include trusted closure-comment open PR evidence`);
      }
      if (row.status === 'non_bug_duplicate_with_open_pr_context') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.relatedOpenPrs) &&
          evidence.relatedOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) === 0),
          `non_bug_duplicate_with_open_pr_context issue #${row.issue_number} must include related open PR evidence`);
      }
      if (row.status === 'non_bug_duplicate_related_closed_unmerged_pr_context') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `non_bug_duplicate_related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_merged_pr_not_reachable_context') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `non_bug_duplicate_related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_merged_pr_reachability_unknown') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `non_bug_duplicate_related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_pr_without_release_fix') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `non_bug_duplicate_related_pr_without_release_fix issue #${row.issue_number} must include linked PR context`);
      }
      if (row.status === 'non_bug_duplicate_or_superseded') {
        expectNonNegativeProof({ failures, tag, row });
      }
      if (row.status === 'non_bug_not_actionable') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.nonActionableRationaleComments) &&
          evidence.nonActionableRationaleComments.length > 0,
          `non_bug_not_actionable issue #${row.issue_number} must include concrete non-actionable rationale`);
      }
      if (isNegativeBareNotPlannedNeutral(row, evidence)) {
        expect(failures, tag, false,
          `negative NOT_PLANNED issue #${row.issue_number} cannot be neutral/non-actionable without concrete close-time rationale`);
      }
      if (row.status === 'canonical_cycle_or_self_reference') {
        expect(failures, tag, evidence.canonicalResolution?.cycle === true || evidence.canonicalResolution?.selfReference === true,
          `canonical_cycle_or_self_reference issue #${row.issue_number} must record cycle/self-reference evidence`);
      }
    }

    if (audit && !releaseIsScored) {
      expect(failures, tag, false,
        'unscored release must not have a release score audit row');
    }
    if (audit) {
      const scoreInput = parseJson(audit.input_json, {});
      const scoreComponents = parseJson(audit.components_json, {});
      const gate = persistedGate;
      const issueEvidence = parseJson(audit.issue_evidence_json, {});
      failures.push(...verifyScoreAuditPayloadContracts({
        tag,
        scoredAt: audit.scored_at,
        input: scoreInput,
        components: scoreComponents,
        issueEvidence,
        gateEvidence: gate,
        versions: {
          scoreInput: scoreInputSchemaVersion,
          scoreComponents: scoreComponentsSchemaVersion,
          issueEvidence: issueEvidenceSchemaVersion,
          gateEvidence: gateEvidenceSchemaVersion,
        },
      }));
      verifyPersistedAuditTuple({ failures, tag, release, audit, scoreInput, scoreComponents });
      verifyPersistedScoreReplay({
        failures,
        tag,
        reader,
        release,
        audit,
        scoreInput,
        scoreComponents,
        issueEvidence,
        gate,
        proofRows,
      });
      verifyScoreSourceIdentity({
        failures,
        tag,
        persisted: parseJson(audit.source_identity_json, null),
        current: currentSourceIdentity,
      });
      expect(failures, tag, scoreInput.schemaVersion === scoreInputSchemaVersion,
        `persisted score input schemaVersion (${scoreInput.schemaVersion}) must equal ${scoreInputSchemaVersion}`);
      expect(failures, tag, scoreComponents.schemaVersion === scoreComponentsSchemaVersion,
        `persisted score components schemaVersion (${scoreComponents.schemaVersion}) must equal ${scoreComponentsSchemaVersion}`);
      expect(failures, tag, gate.schemaVersion === gateEvidenceSchemaVersion,
        `persisted gateEvidence schemaVersion (${gate.schemaVersion}) must equal ${gateEvidenceSchemaVersion}`);
      verifySourceFreshness({ failures, tag, sourceFreshnessRows, audit, strictEvidenceModel });
      verifyLabelTimelineGate({ failures, tag, labelTimeline: gate.labelTimeline });
      verifyReleaseChecksGate({ failures, tag, releaseChecks: gate.releaseChecks });
      verifyArtifactVerificationGate({ failures, tag, artifactVerification: gate.artifactVerification });
      verifyClosedClassificationPromptVersion({ failures, tag, closed, audit });
      if (
        scoreModelSupportsCapability(
          audit.score_model_version,
          'rawClassificationProvenance',
        ) &&
        typeof reader.issuesForVersion === 'function'
      ) {
        verifyRawClassificationProvenance({
          failures,
          tag,
          rows: reader.issuesForVersion(tag),
          audit,
        });
      }
      verifyProofFreshness({ failures, tag, proofRows, audit, reader, strictEvidenceModel });
      expect(failures, tag, issueEvidence.schemaVersion === issueEvidenceSchemaVersion,
        `persisted issueEvidence schemaVersion (${issueEvidence.schemaVersion}) must equal ${issueEvidenceSchemaVersion}`);
    const fix = gate.fixProvenance ?? {};
    expect(failures, tag, fix.verifiedFixedCount === verified.length,
      `audit verifiedFixedCount (${fix.verifiedFixedCount}) must match verifiedFixedForRelease (${verified.length})`);
    expect(
      failures,
      tag,
      fix.unverifiedClosedCount === unverifiedWithoutClosureProof.length,
      `audit unverifiedClosedCount (${fix.unverifiedClosedCount}) must match ` +
      `closed issues without any closure proof (${unverifiedWithoutClosureProof.length})`,
    );
    if (proofRows.length || (strictEvidenceModel && releaseIsScored)) {
      expect(failures, tag, !!fix.closureProof && !!fix.releaseFixCredit,
        'persisted audit gateEvidence must include closureProof and releaseFixCredit for scored releases');
      if (fix.closureProof && fix.releaseFixCredit) {
        let fixCreditResult = null;
        expect(failures, tag, fix.closureProof.schemaVersion === closureProofSchemaVersion,
          `persisted closureProof schemaVersion (${fix.closureProof.schemaVersion}) must equal ${closureProofSchemaVersion}`);
        expect(failures, tag, fix.releaseFixCredit.schemaVersion === releaseFixCreditSchemaVersion,
          `persisted releaseFixCredit schemaVersion (${fix.releaseFixCredit.schemaVersion}) must equal ${releaseFixCreditSchemaVersion}`);
        if (strictEvidenceModel) {
          fixCreditResult = verifyReleaseFixCreditPayload({
            failures,
            tag,
            reader,
            release,
            proofRows,
            fixedProof,
            closureProof: fix.closureProof,
            releaseFixCredit: fix.releaseFixCredit,
            predecessorBoundary: fix.predecessorBoundary,
            stableTagsNewestFirst: gate.stableTagsNewestFirst,
          });
          if (fixCreditResult.predecessorTag) {
            reachabilityTagsToVerify.add(fixCreditResult.predecessorTag);
          }
          expect(failures, tag, fix.creditedFixedCount === fixCreditResult.creditedCount,
            `audit creditedFixedCount (${fix.creditedFixedCount}) must match credited fix decisions (${fixCreditResult.creditedCount})`);
        } else {
          expect(failures, tag, fix.releaseFixCredit.countedClosedCount === fixedProof.length,
            `persisted countedClosedCount (${fix.releaseFixCredit.countedClosedCount}) must match fixed_in_release proof rows (${fixedProof.length})`);
          expect(failures, tag, fix.releaseFixCredit.notCountedClosedCount === notCountedProof.length,
            `persisted notCountedClosedCount (${fix.releaseFixCredit.notCountedClosedCount}) must match non-fixed proof rows (${notCountedProof.length})`);
          expect(failures, tag, fix.releaseFixCredit.analyzedClosedCount === proofRows.length,
            `persisted analyzedClosedCount (${fix.releaseFixCredit.analyzedClosedCount}) must match proof rows (${proofRows.length})`);
          expect(failures, tag, fix.closureProof.creditedCount === fixedProof.length,
            `persisted closureProof creditedCount (${fix.closureProof.creditedCount}) must match fixed proof rows (${fixedProof.length})`);
          expect(failures, tag, fix.closureProof.notCreditedCount === notCountedProof.length,
            `persisted closureProof notCreditedCount (${fix.closureProof.notCreditedCount}) must match non-fixed proof rows (${notCountedProof.length})`);
        }
        const expectedRisk = riskSummaryForProofRows(proofRows, fixCreditResult);
        expectJsonEqual(failures, tag, 'persisted closureProof byRiskDisposition must match proof row dispositions',
          fix.closureProof.byRiskDisposition, expectedRisk.counts);
        expectJsonEqual(failures, tag, 'persisted closureProof riskSummary must match proof row dispositions',
          fix.closureProof.riskSummary, expectedRisk.summary);
        const riskContract = scoreModelRiskContract(audit.score_model_version, scoreInput);
        expect(failures, tag, riskContract != null,
          `score model version (${audit.score_model_version}) has unsupported closure-risk semantics`);
        if (riskContract?.exclusiveRiskLedger) {
          expect(failures, tag,
            Number.isInteger(scoreInput.unresolvedClosureIssueCount) &&
            Number(scoreInput.unresolvedClosureIssueCount) >= 0 &&
            Number(scoreInput.unresolvedClosureIssueCount) <= Number(expectedRisk.summary.unresolvedForReleaseCount ?? 0),
            `score input unresolvedClosureIssueCount (${scoreInput.unresolvedClosureIssueCount}) must be an exclusive subset of raw closure risk (${expectedRisk.summary.unresolvedForReleaseCount})`);
          expect(failures, tag,
            Number.isFinite(Number(scoreInput.unresolvedClosureRiskWeight)) &&
            Number(scoreInput.unresolvedClosureRiskWeight) >= 0 &&
            roundMetric(Number(scoreInput.unresolvedClosureRiskWeight)) <= Number(expectedRisk.summary.unresolvedWeightedRisk ?? 0),
            `score input unresolvedClosureRiskWeight (${scoreInput.unresolvedClosureRiskWeight}) must be an exclusive subset of raw closure risk (${expectedRisk.summary.unresolvedWeightedRisk})`);
          if (riskContract.affirmativeClosureRiskCeiling) {
            expect(failures, tag,
              Number.isFinite(Number(scoreInput.affirmativeClosureRiskCeilingWeight)) &&
              Number(scoreInput.affirmativeClosureRiskCeilingWeight) >= 0 &&
              roundMetric(Number(scoreInput.affirmativeClosureRiskCeilingWeight)) ===
                Number(expectedRisk.summary.unresolvedWeightedRisk ?? 0),
              `score input affirmativeClosureRiskCeilingWeight (${scoreInput.affirmativeClosureRiskCeilingWeight}) must match deduplicated affirmative closure risk (${expectedRisk.summary.unresolvedWeightedRisk})`);
          }
        } else if (riskContract) {
          expect(failures, tag,
            Number(scoreInput.unresolvedClosureIssueCount ?? 0) === Number(expectedRisk.summary.unresolvedForReleaseCount ?? 0),
            `score input unresolvedClosureIssueCount (${scoreInput.unresolvedClosureIssueCount}) must match closureProof riskSummary unresolvedForReleaseCount (${expectedRisk.summary.unresolvedForReleaseCount})`);
          expect(failures, tag,
            roundMetric(Number(scoreInput.unresolvedClosureRiskWeight ?? 0)) === Number(expectedRisk.summary.unresolvedWeightedRisk ?? 0),
            `score input unresolvedClosureRiskWeight (${scoreInput.unresolvedClosureRiskWeight}) must match closureProof riskSummary unresolvedWeightedRisk (${expectedRisk.summary.unresolvedWeightedRisk})`);
        }
        for (const [disposition] of Object.entries(fix.closureProof.byRiskDisposition ?? {})) {
          expect(failures, tag, knownRiskDispositions.has(disposition),
            `closureProof byRiskDisposition contains unknown disposition ${disposition}`);
        }
        verifyClosureProofExamplesByStatus({
          failures,
          tag,
          proof: fix.closureProof,
          label: 'persisted closureProof',
        });
      }
    }
  } else if (releaseIsScored) {
      expect(failures, tag, false, 'release score audit row is missing');
    }
  }

  if (strictEvidenceModel && typeof reader.prReachabilityRowsForRelease === 'function') {
    for (const tag of reachabilityTagsToVerify) {
      verifyPersistedReachabilityRows({
        failures,
        tag,
        rows: reader.prReachabilityRowsForRelease(tag),
      });
    }
  }

  if (apiBase) {
    await verifyApi({
      apiBase: apiBase.replace(/\/$/, ''),
      fetchJson,
      reader,
      failures,
      scorePublication,
      advisorySnapshotAuditProjection,
    });
  }
  if (currentSourceIdentity && typeof reader.scoreSourceIdentity === 'function') {
    const finalSourceIdentity = reader.scoreSourceIdentity({ refresh: true });
    expectJsonEqual(failures, 'source-identity', 'score source identity must remain stable during audit verification',
      finalSourceIdentity, currentSourceIdentity);
  }
  if (scorePublicationBaseline && typeof reader.scorePublicationIntegrity === 'function') {
    try {
      const finalScorePublication = reader.scorePublicationIntegrity();
      const finalPublicationFailures =
        scorePublicationFailuresForAudit(reader, finalScorePublication);
      expectJsonEqual(
        failures,
        'score-publication',
        'complete score publication integrity report must remain stable during audit verification',
        finalScorePublication,
        scorePublicationBaseline,
      );
      if (stableJson(finalScorePublication) !== stableJson(scorePublicationBaseline)) {
        for (const failure of finalPublicationFailures) {
          failures.push(`score-publication-final: ${failure}`);
        }
      }
    } catch (error) {
      failures.push(
        `score-publication-final: sealed audit verification failed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  return { releases, rows, failures };
}

function verifyScoreSourceIdentity({ failures, tag, persisted, current }) {
  expect(failures, tag, isObject(persisted), 'persisted audit source identity must be present');
  if (!isObject(persisted)) return;
  const manifestProblems = scoreSourceIdentityManifestProblems(persisted);
  for (const problem of manifestProblems) {
    expect(failures, tag, false, `source identity manifest ${problem}`);
  }
  expect(failures, tag, isObject(current), 'current score source identity must be available');
  if (isObject(current) && manifestProblems.length === 0) {
    expectJsonEqual(failures, tag, 'persisted score source identity must match current score-input rows',
      persisted, current);
  }
}

function verifySourceFreshness({ failures, tag, sourceFreshnessRows, audit, strictEvidenceModel = false }) {
  const scoredAt = Date.parse(audit.scored_at ?? '');
  expect(failures, tag, Number.isFinite(scoredAt),
    `audit scored_at must be a valid timestamp, got ${audit.scored_at}`);
  if (!Number.isFinite(scoredAt)) return;
  const sourceNames = (sourceFreshnessRows ?? [])
    .map((row) => row?.source)
    .filter((source) => typeof source === 'string' && source.length > 0);
  const duplicateSources = sourceNames.filter(
    (source, index) => sourceNames.indexOf(source) !== index,
  );
  expect(
    failures,
    tag,
    duplicateSources.length === 0,
    `source freshness dependencies must not contain duplicates: ` +
    `${[...new Set(duplicateSources)].join(', ')}`,
  );
  expectJsonEqual(
    failures,
    tag,
    'source freshness dependencies must equal the complete score-affecting source set',
    sourceNames.slice().sort(),
    scoreAffectingFreshnessSources,
  );
  for (const row of sourceFreshnessRows ?? []) {
    if (!row?.max_ts) continue;
    const sourceAt = Date.parse(row.max_ts);
    expect(failures, tag, Number.isFinite(sourceAt),
      `${row.source} max timestamp must be valid, got ${row.max_ts}`);
    if (!Number.isFinite(sourceAt)) continue;
    expect(failures, tag, sourceAt <= scoredAt,
      `${row.source} changed at ${row.max_ts}, newer than audit scored_at ${audit.scored_at}`);
  }
}

function verifyLabelTimelineGate({ failures, tag, labelTimeline }) {
  expect(failures, tag, isObject(labelTimeline), 'persisted audit gateEvidence must include labelTimeline coverage');
  if (!isObject(labelTimeline)) return;
  expect(failures, tag, labelTimeline.schemaVersion === labelTimelineSchemaVersion,
    `labelTimeline schemaVersion (${labelTimeline.schemaVersion}) must equal ${labelTimelineSchemaVersion}`);
  for (const key of ['issueCount', 'currentLabelCount', 'timelineLabelCount', 'snapshotLabelCount', 'missingTimelineCount', 'missingTimelineWithCurrentLabelsCount']) {
    expect(failures, tag, Number.isInteger(labelTimeline[key]) && labelTimeline[key] >= 0,
      `labelTimeline ${key} must be a non-negative integer`);
  }
  const sourceTotal = Number(labelTimeline.currentLabelCount ?? -1) +
    Number(labelTimeline.timelineLabelCount ?? -1) +
    Number(labelTimeline.snapshotLabelCount ?? -1) +
    Number(labelTimeline.missingTimelineCount ?? -1);
  expect(failures, tag, sourceTotal === labelTimeline.issueCount,
    `labelTimeline source counts (${sourceTotal}) must equal issueCount (${labelTimeline.issueCount})`);
  expect(failures, tag, labelTimeline.missingTimelineWithCurrentLabelsCount <= labelTimeline.missingTimelineCount,
    'labelTimeline missingTimelineWithCurrentLabelsCount must not exceed missingTimelineCount');
  expect(failures, tag, typeof labelTimeline.historicalCurrentLabelFallbackAllowed === 'boolean',
    'labelTimeline historicalCurrentLabelFallbackAllowed must be boolean');
  if (labelTimeline.cutoffAt != null) {
    expect(failures, tag, labelTimeline.historicalCurrentLabelFallbackAllowed === false,
      'historical label cutoffs must not allow current-label fallback');
  }
}

function verifyReleaseChecksGate({ failures, tag, releaseChecks }) {
  if (releaseChecks == null) return;
  expect(failures, tag, isObject(releaseChecks), 'releaseChecks must be an object or null');
  if (!isObject(releaseChecks)) return;
  expect(failures, tag, releaseChecks.schemaVersion === releaseChecksSchemaVersion,
    `releaseChecks schemaVersion (${releaseChecks.schemaVersion}) must equal ${releaseChecksSchemaVersion}`);
  for (const key of ['total', 'success', 'failure', 'pending', 'skipped', 'contextCount', 'shownContextCount']) {
    expect(failures, tag, Number.isInteger(releaseChecks[key]) && releaseChecks[key] >= 0,
      `releaseChecks ${key} must be a non-negative integer`);
  }
  const counted = Number(releaseChecks.success ?? -1) + Number(releaseChecks.failure ?? -1) +
    Number(releaseChecks.pending ?? -1) + Number(releaseChecks.skipped ?? -1);
  expect(failures, tag, counted === releaseChecks.total,
    `releaseChecks counted contexts (${counted}) must equal total (${releaseChecks.total})`);
  expect(failures, tag, releaseChecks.contextCount === releaseChecks.total,
    `releaseChecks contextCount (${releaseChecks.contextCount}) must equal total (${releaseChecks.total})`);
  expect(failures, tag, typeof releaseChecks.contextsTruncated === 'boolean',
    'releaseChecks contextsTruncated must be boolean');
  expect(failures, tag, Array.isArray(releaseChecks.contexts),
    'releaseChecks contexts must be an array');
  if (Array.isArray(releaseChecks.contexts)) {
    expect(failures, tag, releaseChecks.contexts.length === releaseChecks.shownContextCount,
      `releaseChecks shownContextCount (${releaseChecks.shownContextCount}) must equal contexts length (${releaseChecks.contexts.length})`);
    expect(failures, tag, releaseChecks.shownContextCount <= releaseChecks.contextCount,
      `releaseChecks shownContextCount (${releaseChecks.shownContextCount}) must not exceed contextCount (${releaseChecks.contextCount})`);
    expect(failures, tag, releaseChecks.contextsTruncated === (releaseChecks.shownContextCount < releaseChecks.contextCount),
      'releaseChecks contextsTruncated must reflect whether contexts are omitted');
  }
}

function verifyArtifactVerificationGate({ failures, tag, artifactVerification }) {
  expect(failures, tag, isObject(artifactVerification), 'artifactVerification must be an object');
  if (!isObject(artifactVerification)) return;
  expect(failures, tag, artifactVerification.schemaVersion === artifactVerificationSchemaVersion,
    `artifactVerification schemaVersion (${artifactVerification.schemaVersion}) must equal ${artifactVerificationSchemaVersion}`);
  const proofFields = [
    'observationId',
    'receiptId',
    'evidenceIdentity',
    'evidenceReportIdentity',
    'runId',
    'observedAt',
    'observationContentHash',
    'receiptContentHash',
    'release',
    'releaseMetadata',
    'artifact',
    'evidenceReport',
  ];
  const proofCount = proofFields.filter((field) => artifactVerification[field] != null).length;
  expect(failures, tag, proofCount === 0 || proofCount === proofFields.length,
    'artifactVerification immutable proof fields must be all null or all present');
  if (proofCount === proofFields.length) {
    expect(failures, tag, isObject(artifactVerification.release),
      'artifactVerification release must be an object when proof is present');
    expect(failures, tag, isObject(artifactVerification.releaseMetadata),
      'artifactVerification releaseMetadata must be an object when proof is present');
    expect(failures, tag, isObject(artifactVerification.artifact),
      'artifactVerification artifact must be an object when proof is present');
    expect(failures, tag, isObject(artifactVerification.evidenceReport),
      'artifactVerification evidenceReport must be an object when proof is present');
    expect(failures, tag,
      artifactVerification.release?.tag === tag,
      `artifactVerification release tag (${artifactVerification.release?.tag}) must equal ${tag}`);
    expect(failures, tag,
      artifactVerification.artifact?.schemaVersion === artifactVerificationSchemaVersion,
      `artifactVerification nested artifact schemaVersion (${artifactVerification.artifact?.schemaVersion}) must equal ${artifactVerificationSchemaVersion}`);
  }
  expect(failures, tag, typeof artifactVerification.verified === 'boolean',
    'artifactVerification verified must be boolean');
  if (artifactVerification.releaseShaMatches != null) {
    expect(failures, tag, typeof artifactVerification.releaseShaMatches === 'boolean',
      'artifactVerification releaseShaMatches must be boolean or null');
  }
  expect(failures, tag, typeof artifactVerification.ciReportVerified === 'boolean',
    'artifactVerification ciReportVerified must be boolean');
  expect(failures, tag, typeof artifactVerification.releaseValidationVerified === 'boolean',
    'artifactVerification releaseValidationVerified must be boolean');
}

function verifyClosedClassificationPromptVersion({ failures, tag, closed, audit }) {
  const expected = Number(audit.prompt_version);
  expect(failures, tag, Number.isInteger(expected) && expected >= 0,
    `audit prompt_version must be a non-negative integer, got ${audit.prompt_version}`);
  if (!Number.isInteger(expected)) return;
  for (const row of closed) {
    expect(failures, tag, Number(row.prompt_version) === expected,
      `closed issue #${row.number} classification prompt_version (${row.prompt_version}) must match audit prompt_version (${expected})`);
  }
}

function verifyRawClassificationProvenance({ failures, tag, rows, audit }) {
  const expectedPromptVersion = Number(audit.prompt_version);
  const uniqueRows = new Map(rows.map((row) => [Number(row.number), row]));
  for (const [issueNumber, row] of uniqueRows) {
    const problems = rawClassificationStorageProblems(row, expectedPromptVersion);
    expect(
      failures,
      tag,
      problems.length === 0,
      `issue #${issueNumber} raw classification provenance is invalid: ${problems.join('; ')}`,
    );
  }
}

function verifyProofFreshness({ failures, tag, proofRows, audit, reader, strictEvidenceModel = false }) {
  const scoredAt = Date.parse(audit.scored_at ?? '');
  expect(failures, tag, Number.isFinite(scoredAt),
    `audit scored_at must be a valid timestamp, got ${audit.scored_at}`);
  if (!Number.isFinite(scoredAt)) return;
  for (const row of proofRows) {
    const checkedAt = Date.parse(row.checked_at ?? '');
    expect(failures, tag, Number.isFinite(checkedAt),
      `proof issue #${row.issue_number} checked_at must be a valid timestamp`);
    if (!Number.isFinite(checkedAt)) continue;
    expect(failures, tag, checkedAt <= scoredAt,
      `proof issue #${row.issue_number} checked_at (${row.checked_at}) must not be newer than audit scored_at (${audit.scored_at})`);
    const evidence = parseJson(row.evidence_json, {});
    const closedAt = evidence?.closedAt ? Date.parse(evidence.closedAt) : NaN;
    if (Number.isFinite(closedAt)) {
      expect(failures, tag, checkedAt >= closedAt,
        `proof issue #${row.issue_number} checked_at (${row.checked_at}) must be newer than closure time (${evidence.closedAt})`);
    }
    if (typeof reader.proofDependencyFreshnessForIssue === 'function') {
      const dependencyFreshness = reader.proofDependencyFreshnessForIssue(tag, row.issue_number) ?? [];
      const dependencySources = new Set(dependencyFreshness.map((source) => source?.source).filter(Boolean));
      for (const required of requiredProofDependencySources) {
        if (!strictEvidenceModel && (
          required === 'issue_state_event_snapshots' ||
          required === 'release_closure_dependency_snapshots'
        )) continue;
        expect(failures, tag, dependencySources.has(required),
          `proof issue #${row.issue_number} dependency freshness must include ${required}`);
      }
      for (const source of dependencyFreshness) {
        if (!source?.max_ts) continue;
        const sourceAt = Date.parse(source.max_ts);
        expect(failures, tag, Number.isFinite(sourceAt),
          `proof issue #${row.issue_number} ${source.source} dependency max timestamp must be valid, got ${source.max_ts}`);
        if (!Number.isFinite(sourceAt)) continue;
        const comparisonTime = source.source === 'release_closure_dependency_snapshots'
          ? scoredAt
          : checkedAt;
        const comparisonLabel = source.source === 'release_closure_dependency_snapshots'
          ? `audit scored_at (${audit.scored_at})`
          : `proof checked_at (${row.checked_at})`;
        expect(failures, tag, sourceAt <= comparisonTime,
          `proof issue #${row.issue_number} ${comparisonLabel} must be newer than ${source.source} dependency (${source.max_ts})`);
      }
    }
  }
}

function verifyIssueStateSnapshotIntegrity({ failures, tag, report }) {
  expect(failures, tag, isObject(report), 'issue state-event snapshot integrity report must be present');
  if (!isObject(report)) return;
  const countKeys = [
    'candidateIssueCount',
    'missingSnapshotCount',
    'invalidSnapshotCount',
    'metadataMismatchCount',
    'projectionMismatchCount',
    'latestStateMismatchCount',
    'failedCount',
  ];
  for (const key of countKeys) {
    expect(failures, tag, Number.isInteger(report[key]) && report[key] >= 0,
      `issue state-event snapshot integrity ${key} must be a non-negative integer`);
  }
  const expectedFailed =
    Number(report.missingSnapshotCount ?? 0) +
    Number(report.invalidSnapshotCount ?? 0) +
    Number(report.metadataMismatchCount ?? 0) +
    Number(report.projectionMismatchCount ?? 0) +
    Number(report.latestStateMismatchCount ?? 0);
  expect(failures, tag, report.failedCount === expectedFailed,
    `issue state-event snapshot failedCount (${report.failedCount}) must equal component failures (${expectedFailed})`);
  expect(failures, tag, report.failedCount === 0,
    `issue state-event snapshots must be complete/current for every scored release ` +
    `(candidates=${report.candidateIssueCount}, missing=${report.missingSnapshotCount}, ` +
    `invalid=${report.invalidSnapshotCount}, metadata=${report.metadataMismatchCount}, ` +
    `projection=${report.projectionMismatchCount}, latestState=${report.latestStateMismatchCount})`);
}

function verifyClosureDependencySnapshotIntegrity({ failures, tag, report }) {
  expect(failures, tag, isObject(report), 'release closure dependency snapshot integrity report must be present');
  if (!isObject(report)) return;
  for (const key of [
    'missingCount',
    'schemaMismatchCount',
    'membershipMismatchCount',
    'referencedIssueMissingCount',
    'evidenceInvalidCount',
    'identityMismatchCount',
    'failedCount',
  ]) {
    expect(failures, tag, Number.isInteger(report[key]) && report[key] >= 0,
      `release closure dependency snapshot integrity ${key} must be a non-negative integer`);
  }
  const expectedFailed =
    Number(report.missingCount ?? 0) +
    Number(report.schemaMismatchCount ?? 0) +
    Number(report.membershipMismatchCount ?? 0) +
    Number(report.referencedIssueMissingCount ?? 0) +
    Number(report.evidenceInvalidCount ?? 0) +
    Number(report.identityMismatchCount ?? 0);
  expect(failures, tag, report.failedCount === expectedFailed,
    `release closure dependency snapshot failedCount (${report.failedCount}) must equal component failures (${expectedFailed})`);
  if (report.snapshot) {
    expect(failures, tag, report.snapshot.release_tag === tag,
      `release closure dependency snapshot tag (${report.snapshot.release_tag}) must match ${tag}`);
    expect(failures, tag, typeof report.snapshot.captured_at === 'string' &&
      Number.isFinite(Date.parse(report.snapshot.captured_at)),
    'release closure dependency snapshot captured_at must be a valid timestamp');
    expect(failures, tag, typeof report.snapshot.dependency_digest === 'string' &&
      /^[0-9a-f]{64}$/.test(report.snapshot.dependency_digest),
    'release closure dependency snapshot digest must be lowercase SHA-256');
  }
  expect(failures, tag, report.failedCount === 0,
    `release closure dependency snapshot must match current closure evidence ` +
    `(missing=${report.missingCount}, schema=${report.schemaMismatchCount}, ` +
    `membership=${report.membershipMismatchCount}, ` +
    `missingIssues=${report.referencedIssueMissingCount}, ` +
    `invalidEvidence=${report.evidenceInvalidCount}, identity=${report.identityMismatchCount})`);
}

function verifyReleaseFixCreditPayload({
  failures,
  tag,
  reader,
  release,
  proofRows,
  fixedProof,
  closureProof,
  releaseFixCredit,
  predecessorBoundary,
  stableTagsNewestFirst,
}) {
  verifyAllowedKeys({
    failures,
    tag,
    label: 'persisted releaseFixCredit',
    value: releaseFixCredit,
    allowed: releaseFixCreditKeys,
  });
  const targetTag = releaseFixCredit?.targetTag;
  const predecessorTag = releaseFixCredit?.predecessorTag;
  expect(failures, tag, targetTag === tag,
    `releaseFixCredit targetTag (${targetTag}) must match ${tag}`);
  expect(failures, tag, typeof predecessorTag === 'string' && predecessorTag.length > 0,
    'releaseFixCredit predecessorTag must be a non-empty string');
  expect(failures, tag, isObject(predecessorBoundary),
    'fixProvenance predecessorBoundary must be present');
  if (isObject(predecessorBoundary)) {
    expect(failures, tag, predecessorBoundary.schemaVersion === 1,
      'predecessorBoundary schemaVersion must be 1');
    expect(failures, tag, predecessorBoundary.targetTag === tag,
      `predecessorBoundary targetTag (${predecessorBoundary.targetTag}) must match ${tag}`);
    expect(failures, tag, predecessorBoundary.predecessorTag === predecessorTag,
      'predecessorBoundary predecessorTag must match releaseFixCredit predecessorTag');
  }
  expect(failures, tag, closureProof.targetTag === tag,
    `closureProof targetTag (${closureProof.targetTag}) must match ${tag}`);
  expect(failures, tag, closureProof.predecessorTag === predecessorTag,
    'closureProof predecessorTag must match releaseFixCredit predecessorTag');

  if (Array.isArray(stableTagsNewestFirst)) {
    const targetIndex = stableTagsNewestFirst.indexOf(tag);
    expect(failures, tag, targetIndex >= 0,
      'gateEvidence stableTagsNewestFirst must contain the scored release');
    if (targetIndex >= 0) {
      expect(failures, tag, stableTagsNewestFirst[targetIndex + 1] === predecessorTag,
        `releaseFixCredit predecessorTag (${predecessorTag}) must be the immediate stable predecessor ` +
        `(${stableTagsNewestFirst[targetIndex + 1] ?? 'none'})`);
    }
  } else {
    expect(failures, tag, false, 'gateEvidence stableTagsNewestFirst must be an array');
  }

  const predecessorRelease = typeof reader.getRelease === 'function' && predecessorTag
    ? reader.getRelease(predecessorTag)
    : null;
  expect(failures, tag, !!predecessorRelease,
    `releaseFixCredit predecessor release ${predecessorTag ?? 'none'} must exist`);
  if (predecessorRelease) {
    expect(failures, tag, Number(predecessorRelease.prerelease ?? 0) === 0,
      `releaseFixCredit predecessor ${predecessorTag} must be stable`);
    const targetPublishedAt = Date.parse(release?.published_at ?? '');
    const predecessorPublishedAt = Date.parse(predecessorRelease.published_at ?? '');
    expect(failures, tag, Number.isFinite(targetPublishedAt) &&
      Number.isFinite(predecessorPublishedAt) &&
      predecessorPublishedAt < targetPublishedAt,
    `releaseFixCredit predecessor ${predecessorTag} must be older than ${tag}`);
  }

  const decisions = Array.isArray(releaseFixCredit?.decisions)
    ? releaseFixCredit.decisions
    : [];
  expect(failures, tag, Array.isArray(releaseFixCredit?.decisions),
    'releaseFixCredit decisions must be an array');
  expect(failures, tag, isObject(releaseFixCredit?.decisionCounts),
    'releaseFixCredit decisionCounts must be an object');
  if (isObject(releaseFixCredit?.decisionCounts)) {
    verifyAllowedKeys({
      failures,
      tag,
      label: 'releaseFixCredit decisionCounts',
      value: releaseFixCredit.decisionCounts,
      allowed: releaseFixCreditDecisionCountKeys,
    });
  }

  const proofByNumber = new Map(proofRows.map((row) => [Number(row.issue_number), row]));
  const decisionIssueNumbers = [];
  const seenIssueNumbers = new Set();
  for (const [index, decision] of decisions.entries()) {
    verifyAllowedKeys({
      failures,
      tag,
      label: `releaseFixCredit decisions[${index}]`,
      value: decision,
      allowed: releaseFixCreditDecisionKeys,
    });
    if (!isObject(decision)) continue;
    const issueNumber = Number(decision.issueNumber);
    expect(failures, tag, Number.isInteger(issueNumber) && issueNumber > 0,
      `releaseFixCredit decision ${index} issueNumber must be a positive integer`);
    expect(failures, tag, !seenIssueNumbers.has(issueNumber),
      `releaseFixCredit decision issueNumber ${issueNumber} must be unique`);
    seenIssueNumbers.add(issueNumber);
    decisionIssueNumbers.push(issueNumber);
    expect(failures, tag, decision.schemaVersion === 1,
      `releaseFixCredit decision #${issueNumber} schemaVersion must be 1`);
    expect(failures, tag, releaseFixCreditStatuses.has(decision.status),
      `releaseFixCredit decision #${issueNumber} status ${decision.status} must be known`);
    expect(failures, tag, releaseFixCreditReasonCodes.has(decision.reasonCode),
      `releaseFixCredit decision #${issueNumber} reasonCode ${decision.reasonCode} must be known`);
    expect(failures, tag,
      (decision.status === 'credited') === creditedReleaseFixReasonCodes.has(decision.reasonCode),
    `releaseFixCredit decision #${issueNumber} credited status/reasonCode must agree`);
    expect(failures, tag,
      (decision.status === 'invalid') === invalidReleaseFixReasonCodes.has(decision.reasonCode),
    `releaseFixCredit decision #${issueNumber} invalid status/reasonCode must agree`);
    expect(failures, tag, decision.status !== 'invalid',
      `releaseFixCredit decision #${issueNumber} must not persist an invalid decision`);
    expect(failures, tag, decision.targetTag === tag,
      `releaseFixCredit decision #${issueNumber} targetTag (${decision.targetTag}) must match ${tag}`);
    expect(failures, tag, decision.predecessorTag === predecessorTag,
      `releaseFixCredit decision #${issueNumber} predecessorTag must match releaseFixCredit`);
    expect(failures, tag, Array.isArray(decision.proofIdentities),
      `releaseFixCredit decision #${issueNumber} proofIdentities must be an array`);
    for (const [proofIndex, proofIdentity] of (decision.proofIdentities ?? []).entries()) {
      verifyFixCreditProofIdentityShape({
        failures,
        tag,
        issueNumber,
        proofIndex,
        proofIdentity,
        targetTag: tag,
        predecessorTag,
      });
    }

    const proofRow = proofByNumber.get(issueNumber);
    expect(failures, tag, proofRow?.status === 'fixed_in_release',
      `releaseFixCredit decision #${issueNumber} must match a fixed_in_release closure proof`);
    const expectedProof = expectedFixCreditProofIdentities({
      failures,
      tag,
      reader,
      issueNumber,
      predecessorTag,
      proofRow,
    });
    expectJsonEqual(
      failures,
      tag,
      `releaseFixCredit decision #${issueNumber} proofIdentities must match current strict proof identities`,
      decision.proofIdentities,
      expectedProof.proofIdentities,
    );
    const expectedOutcome = expectedFixCreditDecisionOutcome(
      expectedProof.proofIdentities,
      expectedProof.directSummary,
    );
    expect(failures, tag, decision.status === expectedOutcome.status,
      `releaseFixCredit decision #${issueNumber} status (${decision.status}) must equal ${expectedOutcome.status}`);
    expect(failures, tag, decision.reasonCode === expectedOutcome.reasonCode,
      `releaseFixCredit decision #${issueNumber} reasonCode (${decision.reasonCode}) must equal ${expectedOutcome.reasonCode}`);
  }

  const fixedIssueNumbers = fixedProof.map((row) => Number(row.issue_number)).sort((a, b) => a - b);
  decisionIssueNumbers.sort((a, b) => a - b);
  expectJsonEqual(
    failures,
    tag,
    'releaseFixCredit decision issue numbers must match fixed_in_release closure proof rows',
    decisionIssueNumbers,
    fixedIssueNumbers,
  );

  const decisionCounts = countFixCreditDecisions(decisions);
  expectJsonEqual(
    failures,
    tag,
    'releaseFixCredit decisionCounts must match decisions',
    releaseFixCredit.decisionCounts,
    decisionCounts,
  );
  expect(failures, tag, decisionCounts.invalid === 0,
    'releaseFixCredit decisionCounts.invalid must be zero');
  const creditedCount = decisionCounts.credited;
  const analyzedClosedCount = proofRows.length;
  const notCreditedCount = analyzedClosedCount - creditedCount;
  const containedFixedCount = fixedProof.length;
  const containedNotCreditedCount = containedFixedCount - creditedCount;
  expect(failures, tag, releaseFixCredit.countedClosedCount === creditedCount,
    `releaseFixCredit countedClosedCount (${releaseFixCredit.countedClosedCount}) must equal credited decisions (${creditedCount})`);
  expect(failures, tag, releaseFixCredit.notCountedClosedCount === notCreditedCount,
    `releaseFixCredit notCountedClosedCount (${releaseFixCredit.notCountedClosedCount}) must equal analyzed minus credited (${notCreditedCount})`);
  expect(failures, tag, releaseFixCredit.analyzedClosedCount === analyzedClosedCount,
    `releaseFixCredit analyzedClosedCount (${releaseFixCredit.analyzedClosedCount}) must match proof rows (${analyzedClosedCount})`);
  expect(failures, tag, releaseFixCredit.containedFixedCount === containedFixedCount,
    `releaseFixCredit containedFixedCount (${releaseFixCredit.containedFixedCount}) must match fixed_in_release bucket (${containedFixedCount})`);
  expect(failures, tag, releaseFixCredit.containedNotCreditedCount === containedNotCreditedCount,
    `releaseFixCredit containedNotCreditedCount (${releaseFixCredit.containedNotCreditedCount}) must equal contained minus credited (${containedNotCreditedCount})`);

  expect(failures, tag, closureProof.creditedCount === creditedCount,
    `closureProof creditedCount (${closureProof.creditedCount}) must equal credited decisions (${creditedCount})`);
  expect(failures, tag, closureProof.notCreditedCount === notCreditedCount,
    `closureProof notCreditedCount (${closureProof.notCreditedCount}) must equal analyzed minus credited (${notCreditedCount})`);
  expect(failures, tag, closureProof.analyzedClosedCount === analyzedClosedCount,
    `closureProof analyzedClosedCount (${closureProof.analyzedClosedCount}) must match proof rows (${analyzedClosedCount})`);
  expect(failures, tag, closureProof.containedFixedCount === containedFixedCount,
    `closureProof containedFixedCount (${closureProof.containedFixedCount}) must equal fixed_in_release bucket (${containedFixedCount})`);
  expect(failures, tag, closureProof.containedNotCreditedCount === containedNotCreditedCount,
    `closureProof containedNotCreditedCount (${closureProof.containedNotCreditedCount}) must equal contained minus credited (${containedNotCreditedCount})`);
  expect(failures, tag, Number(closureProof.byStatus?.fixed_in_release ?? 0) === containedFixedCount,
    'closureProof containedFixedCount must equal fixed_in_release bucket');
  expectJsonEqual(
    failures,
    tag,
    'closureProof fixCreditDecisionCounts must match releaseFixCredit decisionCounts',
    closureProof.fixCreditDecisionCounts,
    releaseFixCredit.decisionCounts,
  );
  expectJsonEqual(
    failures,
    tag,
    'closureProof fixCreditDecisions must match releaseFixCredit decisions',
    closureProof.fixCreditDecisions,
    releaseFixCredit.decisions,
  );
  if (isObject(closureProof.riskSummary)) {
    expect(failures, tag, closureProof.riskSummary.creditedReleaseFixCount === creditedCount,
      'closureProof riskSummary creditedReleaseFixCount must equal credited decisions');
    expect(failures, tag, closureProof.riskSummary.containedReleaseFixCount === containedFixedCount,
      'closureProof riskSummary containedReleaseFixCount must equal fixed_in_release bucket');
    expect(failures, tag,
      closureProof.riskSummary.containedWithoutFirstCreditCount === containedNotCreditedCount,
    'closureProof riskSummary containedWithoutFirstCreditCount must equal contained minus credited');
  }
  return { creditedCount, predecessorTag };
}

function verifyFixCreditProofIdentityShape({
  failures,
  tag,
  issueNumber,
  proofIndex,
  proofIdentity,
  targetTag,
  predecessorTag,
}) {
  expect(failures, tag, isObject(proofIdentity),
    `releaseFixCredit decision #${issueNumber} proofIdentities[${proofIndex}] must be an object`);
  if (!isObject(proofIdentity)) return;
  if (proofIdentity.kind === 'trusted_pull_request') {
    verifyAllowedKeys({
      failures,
      tag,
      label: `releaseFixCredit decision #${issueNumber} trusted PR proof`,
      value: proofIdentity,
      allowed: releaseFixCreditTrustedPrKeys,
    });
    expect(failures, tag,
      typeof proofIdentity.repositoryNameWithOwner === 'string' &&
      proofIdentity.repositoryNameWithOwner.includes('/'),
    `releaseFixCredit decision #${issueNumber} trusted PR proof must include repository identity`);
    expect(failures, tag, Number.isInteger(proofIdentity.prNumber) && proofIdentity.prNumber > 0,
      `releaseFixCredit decision #${issueNumber} trusted PR proof must include positive prNumber`);
    expect(failures, tag,
      Array.isArray(proofIdentity.sources) &&
      proofIdentity.sources.every((source) => typeof source === 'string' && source.length > 0),
    `releaseFixCredit decision #${issueNumber} trusted PR proof sources must be strings`);
    expect(failures, tag, typeof proofIdentity.merged === 'boolean',
      `releaseFixCredit decision #${issueNumber} trusted PR proof merged must be boolean`);
    verifyFixCreditReachabilityShape({
      failures,
      tag,
      issueNumber,
      label: 'target',
      proof: proofIdentity.target,
      expectedTag: targetTag,
    });
    verifyFixCreditReachabilityShape({
      failures,
      tag,
      issueNumber,
      label: 'predecessor',
      proof: proofIdentity.predecessor,
      expectedTag: predecessorTag,
    });
    return;
  }
  if (proofIdentity.kind === 'direct_commit') {
    verifyAllowedKeys({
      failures,
      tag,
      label: `releaseFixCredit decision #${issueNumber} direct commit proof`,
      value: proofIdentity,
      allowed: releaseFixCreditDirectCommitKeys,
    });
    expect(failures, tag, typeof proofIdentity.commitOid === 'string' &&
      fullCommitOidRe.test(proofIdentity.commitOid),
    `releaseFixCredit decision #${issueNumber} direct commit proof must include full commitOid`);
    expect(failures, tag,
      String(proofIdentity.repositoryNameWithOwner ?? '').toLowerCase() ===
        trackedRepositoryNameWithOwner.toLowerCase(),
    `releaseFixCredit decision #${issueNumber} direct commit repository identity must match tracked repository`);
    expect(failures, tag, proofIdentity.targetTag === targetTag,
      `releaseFixCredit decision #${issueNumber} direct commit targetTag must match ${targetTag}`);
    expect(failures, tag, proofIdentity.predecessorTag === predecessorTag,
      `releaseFixCredit decision #${issueNumber} direct commit predecessorTag must match ${predecessorTag}`);
    expect(failures, tag, typeof proofIdentity.strictValid === 'boolean',
      `releaseFixCredit decision #${issueNumber} direct commit strictValid must be boolean`);
    expect(failures, tag,
      proofIdentity.validationReasonCode == null ||
        typeof proofIdentity.validationReasonCode === 'string',
    `releaseFixCredit decision #${issueNumber} direct commit validationReasonCode must be null or string`);
    for (const [label, proof, expectedTag] of [
      ['target', proofIdentity.target, targetTag],
      ['predecessor', proofIdentity.predecessor, predecessorTag],
      ['release ancestry', proofIdentity.releaseAncestry, targetTag],
    ]) {
      verifyDirectCommitReachabilityShape({
        failures,
        tag,
        issueNumber,
        label,
        proof,
        expectedTag,
      });
    }
    return;
  }
  expect(failures, tag, false,
    `releaseFixCredit decision #${issueNumber} proof identity kind ${proofIdentity.kind} must be known`);
}

function verifyDirectCommitReachabilityShape({
  failures,
  tag,
  issueNumber,
  label,
  proof,
  expectedTag,
}) {
  if (proof == null) return;
  verifyAllowedKeys({
    failures,
    tag,
    label: `releaseFixCredit decision #${issueNumber} ${label} direct reachability proof`,
    value: proof,
    allowed: releaseFixCreditDirectReachabilityKeys,
  });
  if (!isObject(proof)) return;
  expect(failures, tag, proof.tag === expectedTag,
    `releaseFixCredit decision #${issueNumber} ${label} proof tag must match ${expectedTag}`);
  expect(failures, tag, knownCommitProofStatuses.has(proof.status),
    `releaseFixCredit decision #${issueNumber} ${label} proof status must be known`);
  expect(failures, tag, proof.method === REACHABILITY_METHOD,
    `releaseFixCredit decision #${issueNumber} ${label} proof method must be ${REACHABILITY_METHOD}`);
  expect(failures, tag, isObject(proof.evidence),
    `releaseFixCredit decision #${issueNumber} ${label} proof evidence must be an object`);
  expect(failures, tag, typeof proof.strictValid === 'boolean',
    `releaseFixCredit decision #${issueNumber} ${label} proof strictValid must be boolean`);
}

function verifyFixCreditReachabilityShape({ failures, tag, issueNumber, label, proof, expectedTag }) {
  if (proof == null) return;
  verifyAllowedKeys({
    failures,
    tag,
    label: `releaseFixCredit decision #${issueNumber} ${label} reachability proof`,
    value: proof,
    allowed: releaseFixCreditReachabilityKeys,
  });
  if (!isObject(proof)) return;
  expect(failures, tag, proof.tag === expectedTag,
    `releaseFixCredit decision #${issueNumber} ${label} proof tag (${proof.tag}) must match ${expectedTag}`);
  expect(failures, tag, knownCommitProofStatuses.has(proof.status),
    `releaseFixCredit decision #${issueNumber} ${label} proof status ${proof.status} must be known`);
  expect(failures, tag, proof.method === REACHABILITY_METHOD,
    `releaseFixCredit decision #${issueNumber} ${label} proof method must be ${REACHABILITY_METHOD}`);
  expect(failures, tag, typeof proof.strictValid === 'boolean',
    `releaseFixCredit decision #${issueNumber} ${label} proof strictValid must be boolean`);
  expect(failures, tag,
    proof.validationReasonCode == null || typeof proof.validationReasonCode === 'string',
  `releaseFixCredit decision #${issueNumber} ${label} proof validationReasonCode must be null or string`);
  expect(failures, tag,
    proof.checkedAt == null || typeof proof.checkedAt === 'string' && Number.isFinite(Date.parse(proof.checkedAt)),
  `releaseFixCredit decision #${issueNumber} ${label} proof checkedAt must be null or timestamp`);
}

function expectedFixCreditProofIdentities({
  failures,
  tag,
  reader,
  issueNumber,
  predecessorTag,
  proofRow,
}) {
  const evidence = parseJson(proofRow?.evidence_json, {});
  const trustedIdentities = trustedPullRequestProofIdentitiesFromEvidence(evidence);
  const rows = reader.fixCreditProofRowsForIssue(tag, predecessorTag, issueNumber) ?? [];
  const rowsByKey = new Map(rows.map((row) => [
    `${String(row.pr_repository_name_with_owner).toLowerCase()}#${Number(row.pr_number)}`,
    row,
  ]));
  const pullRequestProofs = trustedIdentities.map((identity) => {
    const row = rowsByKey.get(
      `${identity.repositoryNameWithOwner.toLowerCase()}#${identity.prNumber}`,
    ) ?? {
      pr_repository_name_with_owner: identity.repositoryNameWithOwner,
      pr_number: identity.prNumber,
      merged: 0,
    };
    if (row.target_release_tag_commit_oid != null) {
      expect(failures, tag, row.target_tag_commit_oid === row.target_release_tag_commit_oid,
        `releaseFixCredit decision #${issueNumber} target reachability tag commit must match release commit`);
    }
    if (row.predecessor_release_tag_commit_oid != null && row.predecessor_tag_commit_oid != null) {
      expect(failures, tag, row.predecessor_tag_commit_oid === row.predecessor_release_tag_commit_oid,
        `releaseFixCredit decision #${issueNumber} predecessor reachability tag commit must match release commit`);
    }
    return {
      kind: 'trusted_pull_request',
      repositoryNameWithOwner: identity.repositoryNameWithOwner,
      prNumber: identity.prNumber,
      sources: identity.sources,
      merged: Number(row.merged ?? 0) === 1,
      mergeCommitOid: row.pr_merge_commit_oid ?? null,
      baseRefName: row.pr_base_ref_name ?? null,
      target: expectedFixCreditReachabilityProof(row, 'target', tag),
      predecessor: expectedFixCreditReachabilityProof(row, 'predecessor', predecessorTag),
    };
  });
  const directSummary = expectedDirectCommitProofSummary({
    evidence,
    reader,
    targetTag: tag,
    predecessorTag,
  });
  return {
    proofIdentities: [...pullRequestProofs, ...directSummary.proofs],
    directSummary,
  };
}

function expectedDirectCommitProofSummary({
  evidence,
  reader,
  targetTag,
  predecessorTag,
}) {
  const empty = {
    proofs: [],
    candidateCommitOids: [],
    declaredCreditedCommitOids: [],
    creditedCommitOids: [],
    predecessorContainedCommitOids: [],
    unprovenCommitOids: [],
    missingProofCount: 0,
    invalidProofCount: 0,
  };
  const boundary = releaseFixBoundaryForAudit(reader, targetTag, predecessorTag);
  if (!boundary.valid) return { ...empty, invalidProofCount: 1 };
  const candidateCommitOids = normalizedAuditCommitArray(
    Array.isArray(evidence.fixCommitProof)
      ? evidence.fixCommitProof
        .filter((item) => isObject(item) && item.creditEligible !== false)
        .map((item) => item.commitOid)
      : [],
  );
  const declaredCreditedCommitOids = normalizedAuditCommitArray(
    Array.isArray(evidence.reachableFixCommits) ? evidence.reachableFixCommits : [],
  );
  const rawProofs = Array.isArray(evidence.directCommitFirstContainingProofs)
    ? evidence.directCommitFirstContainingProofs
    : [];
  const proofs = [];
  const seen = new Set();
  let invalidProofCount =
    Array.isArray(evidence.directCommitFirstContainingProofs) || candidateCommitOids.length === 0
      ? 0
      : 1;
  for (const rawProof of rawProofs) {
    if (!isObject(rawProof)) {
      invalidProofCount++;
      continue;
    }
    const commitOid = normalizeAuditOid(rawProof.commitOid);
    if (!commitOid || seen.has(commitOid)) {
      invalidProofCount++;
      continue;
    }
    seen.add(commitOid);
    const proof = expectedDirectCommitProofIdentity(
      rawProof,
      targetTag,
      predecessorTag,
      boundary,
    );
    proofs.push(proof);
    if (!proof.strictValid) invalidProofCount++;
  }
  const missingProofCount =
    candidateCommitOids.filter((commitOid) => !seen.has(commitOid)).length;
  invalidProofCount += proofs.filter((proof) =>
    !candidateCommitOids.includes(proof.commitOid)).length;
  const creditedCommitOids = proofs
    .filter((proof) => proof.strictValid && proof.creditEligible)
    .map((proof) => proof.commitOid)
    .sort();
  const predecessorContainedCommitOids = proofs
    .filter((proof) =>
      proof.strictValid && proof.reasonCode === 'predecessor_contains_commit')
    .map((proof) => proof.commitOid)
    .sort();
  const unprovenCommitOids = proofs
    .filter((proof) =>
      proof.strictValid &&
      !proof.creditEligible &&
      proof.reasonCode !== 'predecessor_contains_commit' &&
      proof.reasonCode !== 'target_commit_not_reachable')
    .map((proof) => proof.commitOid)
    .sort();
  return {
    proofs: proofs.sort((left, right) => left.commitOid.localeCompare(right.commitOid)),
    candidateCommitOids,
    declaredCreditedCommitOids,
    creditedCommitOids,
    predecessorContainedCommitOids,
    unprovenCommitOids,
    missingProofCount,
    invalidProofCount,
  };
}

function expectedDirectCommitProofIdentity(raw, targetTag, predecessorTag, boundary) {
  const commitOid = normalizeAuditOid(raw.commitOid) ?? String(raw.commitOid ?? '');
  const repositoryNameWithOwner =
    String(raw.repositoryNameWithOwner ?? '').trim().toLowerCase();
  const status = raw.status === 'credited' ? 'credited' : 'withheld';
  const reasonCode = String(raw.reasonCode ?? '');
  const creditEligible = raw.creditEligible === true;
  const target = expectedDirectReachabilityProof(raw.target, {
    tag: targetTag,
    tagCommitOid: boundary.targetCommitOid,
    checkedCommitOid: commitOid,
    kind: 'direct_commit',
    repositoryNameWithOwner,
  });
  const predecessor = expectedDirectReachabilityProof(raw.predecessor, {
    tag: predecessorTag,
    tagCommitOid: boundary.predecessorCommitOid,
    checkedCommitOid: commitOid,
    kind: 'direct_commit',
    repositoryNameWithOwner,
  });
  const releaseAncestry = expectedDirectReachabilityProof(raw.releaseAncestry, {
    tag: targetTag,
    tagCommitOid: boundary.targetCommitOid,
    checkedCommitOid: boundary.predecessorCommitOid,
    kind: 'release_boundary',
    repositoryNameWithOwner,
  });
  let validationReasonCode = null;
  const invalidate = (reason) => {
    validationReasonCode ??= reason;
  };
  if (raw.schemaVersion !== 1) invalidate('schema_version_mismatch');
  if (raw.kind !== 'direct_commit') invalidate('proof_kind_mismatch');
  if (raw.status !== 'credited' && raw.status !== 'withheld') invalidate('invalid_status');
  if (repositoryNameWithOwner !== trackedRepositoryNameWithOwner.toLowerCase()) {
    invalidate('repository_identity_mismatch');
  }
  if (!fullCommitOidRe.test(commitOid)) invalidate('invalid_commit_oid');
  if (raw.targetTag !== targetTag || raw.predecessorTag !== predecessorTag) {
    invalidate('release_boundary_mismatch');
  }
  if (!directCommitFirstContainingReasonCodes.has(reasonCode)) {
    invalidate('unknown_reason_code');
  }
  if ((status === 'credited') !== creditEligible) {
    invalidate('status_credit_eligibility_mismatch');
  }
  if ((reasonCode === 'first_containing_direct_commit') !== creditEligible) {
    invalidate('reason_credit_eligibility_mismatch');
  }
  for (const proof of [target, predecessor, releaseAncestry]) {
    if (proof && !proof.strictValid) invalidate('reachability_evidence_invalid');
  }
  if (reasonCode === 'first_containing_direct_commit') {
    if (
      target?.strictValid !== true ||
      target.status !== 'reachable' ||
      predecessor?.strictValid !== true ||
      predecessor.status !== 'not_reachable' ||
      releaseAncestry?.strictValid !== true ||
      releaseAncestry.status !== 'reachable'
    ) {
      invalidate('first_containing_outcome_mismatch');
    }
  } else if (reasonCode === 'predecessor_contains_commit') {
    if (
      target?.strictValid !== true ||
      target.status !== 'reachable' ||
      predecessor?.strictValid !== true ||
      predecessor.status !== 'reachable' ||
      releaseAncestry?.strictValid !== true ||
      releaseAncestry.status !== 'reachable'
    ) {
      invalidate('predecessor_containment_outcome_mismatch');
    }
  } else if (reasonCode === 'target_commit_not_reachable') {
    if (
      target?.strictValid !== true ||
      target.status !== 'not_reachable' ||
      releaseAncestry?.strictValid !== true ||
      releaseAncestry.status !== 'reachable'
    ) {
      invalidate('target_non_reachability_outcome_mismatch');
    }
  }
  if (raw.strictValid !== undefined || raw.validationReasonCode !== undefined) {
    invalidate('unexpected_derived_validation_fields');
  }
  return {
    kind: 'direct_commit',
    schemaVersion: Number(raw.schemaVersion),
    repositoryNameWithOwner,
    commitOid,
    targetTag: String(raw.targetTag ?? ''),
    predecessorTag: raw.predecessorTag == null ? null : String(raw.predecessorTag),
    status,
    reasonCode,
    creditEligible,
    target,
    predecessor,
    releaseAncestry,
    strictValid: validationReasonCode == null,
    validationReasonCode,
  };
}

function expectedDirectReachabilityProof(rawValue, expected) {
  if (!isObject(rawValue)) return null;
  const status = knownCommitProofStatuses.has(rawValue.status)
    ? rawValue.status
    : 'unknown';
  const tagCommitOid = normalizeAuditOid(rawValue.tagCommitOid);
  const checkedCommitOid = normalizeAuditOid(rawValue.checkedCommitOid);
  const method = String(rawValue.method ?? '');
  const evidence = isObject(rawValue.evidence) ? rawValue.evidence : null;
  const validation = validateReachabilityEvidence({
    evidence,
    method,
    status,
    identity: {
      kind: expected.kind,
      repositoryNameWithOwner: expected.repositoryNameWithOwner,
      tagCommitOid: expected.tagCommitOid,
      checkedCommitOid: expected.checkedCommitOid,
    },
  });
  let validationReasonCode = validation.valid ? null : validation.reasonCode;
  if (!validationReasonCode && rawValue.tag !== expected.tag) {
    validationReasonCode = 'release_tag_mismatch';
  }
  if (!validationReasonCode && tagCommitOid !== expected.tagCommitOid) {
    validationReasonCode = 'tag_commit_oid_mismatch';
  }
  if (!validationReasonCode && checkedCommitOid !== expected.checkedCommitOid) {
    validationReasonCode = 'checked_commit_oid_mismatch';
  }
  if (!validationReasonCode && rawValue.strictValid !== true) {
    validationReasonCode = 'persisted_strict_valid_mismatch';
  }
  if (!validationReasonCode && rawValue.validationReasonCode !== null) {
    validationReasonCode = 'persisted_validation_reason_mismatch';
  }
  return {
    tag: String(rawValue.tag ?? ''),
    status,
    tagCommitOid,
    checkedCommitOid,
    method,
    evidence,
    strictValid: validationReasonCode == null,
    validationReasonCode,
  };
}

function releaseFixBoundaryForAudit(reader, targetTag, predecessorTag) {
  const rows = typeof reader.stableReleaseBoundaryRows === 'function'
    ? reader.stableReleaseBoundaryRows()
    : [];
  const target = rows.find((row) => row.tag === targetTag);
  const predecessor = rows.find((row) => row.tag === predecessorTag);
  if (!target || !predecessor) return { valid: false };
  const ranks = rows.map((row) => row.catalog_rank);
  if (
    ranks.some((rank) => !Number.isInteger(rank) || Number(rank) < 0) ||
    new Set(ranks).size !== ranks.length
  ) {
    return { valid: false };
  }
  const catalogOrdered = rows.slice().sort((left, right) =>
    Number(left.catalog_rank) - Number(right.catalog_rank) ||
    left.tag.localeCompare(right.tag));
  const catalogIndex = catalogOrdered.findIndex((row) => row.tag === targetTag);
  if (catalogIndex < 0 || catalogOrdered[catalogIndex + 1]?.tag !== predecessorTag) {
    return { valid: false };
  }
  const timestamps = rows.map((row) =>
    row.published_at == null ? NaN : Date.parse(row.published_at));
  if (
    timestamps.some((timestamp) => !Number.isFinite(timestamp)) ||
    new Set(timestamps).size !== timestamps.length
  ) {
    return { valid: false };
  }
  const timeOrdered = rows.slice().sort((left, right) =>
    Date.parse(right.published_at) - Date.parse(left.published_at) ||
    left.tag.localeCompare(right.tag));
  const timeIndex = timeOrdered.findIndex((row) => row.tag === targetTag);
  if (timeIndex < 0 || timeOrdered[timeIndex + 1]?.tag !== predecessorTag) {
    return { valid: false };
  }
  const targetCatalogOid = normalizeAuditOid(target.catalog_tag_commit_oid);
  const targetResolvedOid = normalizeAuditOid(target.resolved_tag_commit_oid);
  const predecessorCatalogOid = normalizeAuditOid(predecessor.catalog_tag_commit_oid);
  const predecessorResolvedOid = normalizeAuditOid(predecessor.resolved_tag_commit_oid);
  if (
    !targetCatalogOid ||
    !targetResolvedOid ||
    !predecessorCatalogOid ||
    !predecessorResolvedOid ||
    targetCatalogOid !== targetResolvedOid ||
    predecessorCatalogOid !== predecessorResolvedOid
  ) {
    return { valid: false };
  }
  const aliases = new Map();
  for (const row of rows) {
    const oid = normalizeAuditOid(row.resolved_tag_commit_oid);
    if (oid) aliases.set(oid, (aliases.get(oid) ?? 0) + 1);
  }
  if (aliases.get(targetResolvedOid) !== 1 || aliases.get(predecessorResolvedOid) !== 1) {
    return { valid: false };
  }
  return {
    valid: true,
    targetCommitOid: targetResolvedOid,
    predecessorCommitOid: predecessorResolvedOid,
  };
}

function normalizedAuditCommitArray(values) {
  return [...new Set(values
    .map((value) => normalizeAuditOid(value))
    .filter(Boolean))]
    .sort();
}

function normalizeAuditOid(value) {
  const oid = String(value ?? '').trim().toLowerCase();
  return fullCommitOidRe.test(oid) ? oid : null;
}

function trustedPullRequestProofIdentitiesFromEvidence(evidence) {
  const identities = new Map();
  for (const proof of Array.isArray(evidence?.linkedPrs) ? evidence.linkedPrs : []) {
    const repositoryNameWithOwner = String(proof?.repositoryNameWithOwner ?? '');
    const prNumber = Number(proof?.number);
    const source = String(proof?.source ?? '');
    if (
      repositoryNameWithOwner.toLowerCase() !== trackedRepositoryNameWithOwner.toLowerCase() ||
      !Number.isInteger(prNumber) ||
      prNumber <= 0
    ) {
      continue;
    }
    const hasExplicitTrustMarker = Object.prototype.hasOwnProperty.call(proof, 'trustedFixProof');
    const explicitlyTrusted = proof.trustedFixProof === 1 || proof.trustedFixProof === true;
    const legacyTrustedSource = [
      'closedByPullRequestsReferences',
      'ClosedEvent.closer',
      'ClosureComment.fixProof',
    ].includes(source);
    if (hasExplicitTrustMarker ? !explicitlyTrusted : !legacyTrustedSource) continue;
    const key = `${trackedRepositoryNameWithOwner.toLowerCase()}#${prNumber}`;
    const identity = identities.get(key) ?? {
      repositoryNameWithOwner: trackedRepositoryNameWithOwner,
      prNumber,
      sources: new Set(),
    };
    if (source) identity.sources.add(source);
    identities.set(key, identity);
  }
  return [...identities.values()]
    .sort((left, right) =>
      left.repositoryNameWithOwner.localeCompare(right.repositoryNameWithOwner) ||
      left.prNumber - right.prNumber)
    .map((identity) => ({
      repositoryNameWithOwner: identity.repositoryNameWithOwner,
      prNumber: identity.prNumber,
      sources: [...identity.sources].sort(),
    }));
}

function expectedFixCreditReachabilityProof(row, prefix, tag) {
  const status = row[`${prefix}_status`];
  if (!status) return null;
  const tagCommitOid = row[`${prefix}_tag_commit_oid`] ?? null;
  const checkedCommitOid = row[`${prefix}_merge_commit_oid`] ?? null;
  const baseRefName = row[`${prefix}_base_ref_name`] ?? null;
  const method = row[`${prefix}_method`] ?? REACHABILITY_METHOD;
  const evidenceJson = row[`${prefix}_evidence_json`];
  const validation = validateReachabilityEvidence({
    evidence: evidenceJson,
    method,
    status,
    identity: {
      kind: 'pull_request',
      tagCommitOid: tagCommitOid ?? '',
      checkedCommitOid,
      baseRefName,
    },
  });
  return {
    tag,
    status,
    tagCommitOid,
    checkedCommitOid,
    baseRefName,
    method,
    checkedAt: row[`${prefix}_checked_at`] ?? null,
    evidenceReason: parseJson(evidenceJson, {})?.evidence ?? null,
    strictValid: validation.valid,
    validationReasonCode: validation.valid ? null : validation.reasonCode,
  };
}

function expectedFixCreditDecisionOutcome(proofIdentities, directSummary) {
  if (directSummary.missingProofCount > 0) {
    return { status: 'withheld', reasonCode: 'direct_commit_first_containing_proof_missing' };
  }
  if (
    directSummary.invalidProofCount > 0 ||
    JSON.stringify(directSummary.declaredCreditedCommitOids) !==
      JSON.stringify(directSummary.creditedCommitOids)
  ) {
    return { status: 'withheld', reasonCode: 'direct_commit_first_containing_proof_invalid' };
  }
  const pullRequests = proofIdentities.filter((proof) =>
    proof?.kind === 'trusted_pull_request' && proof.merged === true);
  if (pullRequests.length === 0) {
    if (directSummary.creditedCommitOids.length > 0) {
      return { status: 'credited', reasonCode: 'first_containing_direct_commit' };
    }
    if (directSummary.predecessorContainedCommitOids.length > 0) {
      return { status: 'withheld', reasonCode: 'direct_commit_not_first_containing' };
    }
    if (directSummary.unprovenCommitOids.length > 0 ||
      directSummary.candidateCommitOids.length > 0) {
      return { status: 'withheld', reasonCode: 'direct_commit_first_containment_unproven' };
    }
    return { status: 'withheld', reasonCode: 'target_trusted_pr_missing' };
  }
  if (pullRequests.some((proof) => proof.target == null)) {
    return { status: 'withheld', reasonCode: 'target_reachability_missing' };
  }
  if (pullRequests.some((proof) => proof.target?.strictValid === false)) {
    return { status: 'withheld', reasonCode: 'target_reachability_invalid' };
  }
  if (pullRequests.some((proof) => proof.target?.status === 'unknown')) {
    return { status: 'withheld', reasonCode: 'target_reachability_unknown' };
  }
  if (pullRequests.some((proof) => proof.predecessor == null)) {
    return { status: 'withheld', reasonCode: 'predecessor_reachability_missing' };
  }
  if (pullRequests.some((proof) => proof.predecessor?.strictValid === false)) {
    return { status: 'withheld', reasonCode: 'predecessor_reachability_invalid' };
  }
  if (pullRequests.some((proof) => proof.predecessor?.status === 'unknown')) {
    return { status: 'withheld', reasonCode: 'predecessor_reachability_unknown' };
  }
  if (pullRequests.some((proof) => proof.target?.status !== 'reachable')) {
    return { status: 'withheld', reasonCode: 'target_reachability_not_reachable' };
  }
  if (pullRequests.some((proof) => proof.predecessor?.status === 'reachable')) {
    return { status: 'withheld', reasonCode: 'predecessor_reachable' };
  }
  if (directSummary.creditedCommitOids.length > 0) {
    return { status: 'credited', reasonCode: 'first_containing_direct_commit' };
  }
  return { status: 'credited', reasonCode: 'first_containing_trusted_pr' };
}

function countFixCreditDecisions(decisions) {
  const counts = { credited: 0, withheld: 0, invalid: 0 };
  for (const decision of Array.isArray(decisions) ? decisions : []) {
    if (isObject(decision) && Object.hasOwn(counts, decision.status)) counts[decision.status]++;
  }
  return counts;
}

function verifyPersistedReachabilityRows({ failures, tag, rows }) {
  expect(failures, tag, Array.isArray(rows),
    `persisted PR reachability rows for ${tag} must be an array`);
  for (const row of rows ?? []) {
    const label = `${row.pr_repository_name_with_owner ?? 'unknown-repo'}#${row.pr_number ?? 'unknown'}`;
    expect(failures, tag,
      typeof row.pr_repository_name_with_owner === 'string' &&
      row.pr_repository_name_with_owner.includes('/'),
    `persisted PR reachability ${label} must include repository identity`);
    expect(failures, tag, Number.isInteger(Number(row.pr_number)) && Number(row.pr_number) > 0,
      `persisted PR reachability ${label} must include positive PR number`);
    expect(failures, tag, Number(row.merged ?? 0) === 1,
      `persisted PR reachability ${label} must reference a merged PR`);
    expect(failures, tag, knownCommitProofStatuses.has(row.status),
      `persisted PR reachability ${label} status ${row.status} must be known`);
    expect(failures, tag, row.method === REACHABILITY_METHOD,
      `persisted PR reachability ${label} method must be ${REACHABILITY_METHOD}`);
    if (row.release_tag_commit_oid != null) {
      expect(failures, tag, row.tag_commit_oid === row.release_tag_commit_oid,
        `persisted PR reachability ${label} tag commit must match release ${tag}`);
    }
    if (row.pr_merge_commit_oid != null && row.merge_commit_oid != null) {
      expect(failures, tag, row.merge_commit_oid === row.pr_merge_commit_oid,
        `persisted PR reachability ${label} checked commit must match PR merge commit`);
    }
    if (row.pr_base_ref_name != null && row.base_ref_name != null) {
      expect(failures, tag, row.base_ref_name === row.pr_base_ref_name,
        `persisted PR reachability ${label} base ref must match PR metadata`);
    }
    const validation = validateReachabilityEvidence({
      evidence: row.evidence_json,
      method: row.method,
      status: row.status,
      identity: {
        kind: 'pull_request',
        tagCommitOid: row.tag_commit_oid ?? '',
        checkedCommitOid: row.merge_commit_oid ?? null,
        baseRefName: row.base_ref_name ?? null,
      },
    });
    expect(failures, tag, validation.valid,
      `persisted PR reachability ${label} for ${tag} must have strict proof identity` +
      (validation.valid ? '' : ` (${validation.reasonCode})`));
  }
}

function verifyProofPrReachabilityEvidence({ failures, tag, row, evidence, prEvidence }) {
  verifyEmbeddedProofPrEvidenceShapes({ failures, tag, row, evidence });
  const prEvidenceByKey = new Map(prEvidence.map((pr) => [
    prKey(pr.pr_repository_name_with_owner, pr.pr_number),
    pr,
  ]));
  for (const linkedPr of Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs : []) {
    const repo = String(linkedPr?.repositoryNameWithOwner ?? '');
    const number = Number(linkedPr?.number ?? 0);
    const merged = Number(linkedPr?.merged ?? 0) === 1;
    if (!merged || !Number.isInteger(number) || number <= 0) continue;
    if (repo !== 'openclaw/openclaw') {
      expect(failures, tag, linkedPr.reachabilityStatus === 'external_repo_unchecked',
        `proof issue #${row.issue_number} external linked PR ${repo}#${number} must carry external_repo_unchecked reachabilityStatus`);
      expect(failures, tag, linkedPr.reachabilityEvidence === 'external_repository_not_checked_against_openclaw_release_tag',
        `proof issue #${row.issue_number} external linked PR ${repo}#${number} must explain why release reachability is not checked`);
      continue;
    }
    expect(failures, tag, ['reachable', 'not_reachable', 'unknown'].includes(linkedPr.reachabilityStatus),
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must carry reachabilityStatus`);
    expect(failures, tag, typeof linkedPr.reachabilityMethod === 'string' || linkedPr.reachabilityMethod == null,
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must carry reachabilityMethod`);
    expect(failures, tag, typeof linkedPr.reachabilityEvidence === 'string' && linkedPr.reachabilityEvidence.length > 0,
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must carry reachabilityEvidence`);
    const persisted = prEvidenceByKey.get(prKey(repo, number));
    expect(failures, tag, !!persisted,
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must have matching persisted reachability row`);
    if (persisted) {
      expect(failures, tag, linkedPr.reachabilityStatus === persisted.status,
        `proof issue #${row.issue_number} linked PR ${repo}#${number} reachabilityStatus (${linkedPr.reachabilityStatus}) must match persisted reachability (${persisted.status})`);
      if (linkedPr.mergeCommitOid != null && persisted.merge_commit_oid != null) {
        expect(failures, tag, linkedPr.mergeCommitOid === persisted.merge_commit_oid,
          `proof issue #${row.issue_number} linked PR ${repo}#${number} mergeCommitOid (${linkedPr.mergeCommitOid}) must match persisted reachability (${persisted.merge_commit_oid})`);
      }
    }
  }
  for (const pr of prEvidence) {
    const prLabel = `${pr.pr_repository_name_with_owner ?? 'unknown-repo'}#${pr.pr_number}`;
    expect(failures, tag, typeof pr.pr_repository_name_with_owner === 'string' && pr.pr_repository_name_with_owner.includes('/'),
      `proof issue #${row.issue_number} PR #${pr.pr_number} reachability evidence must include repository identity`);
    expect(failures, tag, ['reachable', 'not_reachable', 'unknown'].includes(pr.status),
      `proof issue #${row.issue_number} PR ${prLabel} reachability status ${pr.status} must be known`);
    if (pr.release_tag_commit_oid != null) {
      expect(failures, tag, pr.tag_commit_oid === pr.release_tag_commit_oid,
        `proof issue #${row.issue_number} PR ${prLabel} reachability tag commit (${pr.tag_commit_oid}) must match release commit (${pr.release_tag_commit_oid})`);
    }
    if (pr.status === 'unknown') {
      const prReachabilityEvidence = parseJson(pr.evidence_json, {});
      expect(failures, tag, typeof prReachabilityEvidence.evidence === 'string' && prReachabilityEvidence.evidence.length > 0,
        `proof issue #${row.issue_number} PR ${prLabel} unknown reachability must include evidence reason`);
    }
  }
  if (evidence.hasReachableClosingPr === true) {
    expect(failures, tag, linkedMergedPrEvidence(evidence).some((linkedPr) =>
      matchingReachabilityPr(prEvidenceByKey, linkedPr, 'reachable')),
      `proof issue #${row.issue_number} hasReachableClosingPr must have a merged reachable PR row`);
  }
  if (evidence.hasNotReachableClosingPr === true) {
    expect(failures, tag, linkedMergedPrEvidence(evidence).some((linkedPr) =>
      matchingReachabilityPr(prEvidenceByKey, linkedPr, 'not_reachable')),
      `proof issue #${row.issue_number} hasNotReachableClosingPr must have a merged not-reachable PR row`);
  }
}

function verifyEmbeddedProofPrEvidenceShapes({ failures, tag, row, evidence }) {
  for (const [idx, pr] of (Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs : []).entries()) {
    verifyEmbeddedProofPr({ failures, tag, row, pr, label: `linkedPrs[${idx}]` });
  }
  const context = relatedPrContext(evidence);
  for (const [bucket, prs] of Object.entries(context)) {
    for (const [idx, pr] of prs.entries()) {
      verifyEmbeddedProofPr({ failures, tag, row, pr, label: `relatedPrContext.${bucket}[${idx}]` });
    }
  }
  for (const [idx, pr] of (Array.isArray(evidence.canonicalOpenPrs) ? evidence.canonicalOpenPrs : []).entries()) {
    verifyEmbeddedProofPr({ failures, tag, row, pr, label: `canonicalOpenPrs[${idx}]` });
  }
  for (const [idx, pr] of (Array.isArray(evidence.relatedOpenPrs) ? evidence.relatedOpenPrs : []).entries()) {
    verifyEmbeddedProofPr({ failures, tag, row, pr, label: `relatedOpenPrs[${idx}]` });
  }
}

function verifyEmbeddedProofPr({ failures, tag, row, pr, label }) {
  expect(failures, tag, isObject(pr),
    `proof issue #${row.issue_number} ${label} must be a PR evidence object`);
  if (!isObject(pr)) return;
  const repo = String(pr.repositoryNameWithOwner ?? '');
  const number = Number(pr.number ?? 0);
  const state = String(pr.state ?? '');
  const merged = pr.merged;
  const source = String(pr.source ?? '');
  const metadataMissing = pr.metadataMissing === true || pr.metadataMissing === 1;
  expect(failures, tag, Number.isInteger(number) && number > 0,
    `proof issue #${row.issue_number} ${label} must include a positive PR number`);
  expect(failures, tag, repo.includes('/'),
    `proof issue #${row.issue_number} ${label} PR #${number || 'unknown'} must include repositoryNameWithOwner`);
  expect(failures, tag, source.length > 0,
    `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} must include source`);
  if (metadataMissing) {
    expect(failures, tag, isExpectedGitHubCommentUrl(pr.sourceCommentUrl, row.issue_number, pr.sourceCommentDatabaseId),
      `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} missing metadata must link its source comment`);
  } else {
    expect(failures, tag, ['OPEN', 'CLOSED', 'MERGED'].includes(state),
      `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} must include known state`);
    expect(failures, tag, merged === 0 || merged === 1 || merged === false || merged === true,
      `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} must include merged flag`);
  }
  if (merged === 1 || merged === true) {
    expect(failures, tag, state === 'MERGED',
      `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} merged PR must have MERGED state`);
    expect(failures, tag, typeof pr.mergedAt === 'string' && Number.isFinite(Date.parse(pr.mergedAt)),
      `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} merged PR must include mergedAt`);
  }
}

function prKey(repo, number) {
  return `${String(repo ?? '')}#${Number(number ?? 0)}`;
}

function matchingReachabilityPr(prEvidenceByKey, linkedPr, status) {
  const repo = String(linkedPr?.repositoryNameWithOwner ?? '');
  const number = Number(linkedPr?.number ?? 0);
  const persisted = prEvidenceByKey.get(prKey(repo, number));
  return !!persisted && persisted.merged === 1 && persisted.status === status;
}

function verifyAllowedKeys({ failures, tag, label, value, allowed }) {
  expect(failures, tag, isObject(value), `${label} must be an object`);
  if (!isObject(value)) return;
  const extra = Object.keys(value).filter((key) => !allowed.has(key)).sort();
  expect(failures, tag, extra.length === 0,
    `${label} must not expose unknown keys: ${extra.join(', ')}`);
}

function verifyRequiredOwnKeys({ failures, tag, label, value, required }) {
  for (const key of required) {
    expect(failures, tag, Object.hasOwn(value, key),
      `${label} is missing required field ${key}`);
  }
}

function verifyDataFreshness({
  failures,
  tag,
  dataFreshness,
  releaseTag,
  scoredAt = null,
  reader = null,
}) {
  expect(failures, tag, isObject(dataFreshness), 'dataFreshness must be present');
  if (!isObject(dataFreshness)) return;
  expect(failures, tag, dataFreshness.schemaVersion === 1,
    `dataFreshness schemaVersion must be 1, got ${JSON.stringify(dataFreshness.schemaVersion)}`);
  expect(failures, tag, dataFreshness.tag === releaseTag,
    `dataFreshness tag (${dataFreshness.tag}) must match release tag (${releaseTag})`);
  if (scoredAt != null) {
    expect(failures, tag, dataFreshness.scoredAt === scoredAt,
      `dataFreshness scoredAt (${dataFreshness.scoredAt}) must match release scored_at (${scoredAt})`);
  }
  expect(failures, tag, Array.isArray(dataFreshness.sources) && dataFreshness.sources.length > 0,
    'dataFreshness sources must be a non-empty array');
  const sourceRows = Array.isArray(dataFreshness.sources)
    ? dataFreshness.sources
    : [];
  const sourceNames = sourceRows.map((source) => source?.source);
  const duplicateSourceNames = sourceNames.filter(
    (source, index) =>
      typeof source === 'string' && sourceNames.indexOf(source) !== index,
  );
  expect(
    failures,
    tag,
    duplicateSourceNames.length === 0,
    `dataFreshness sources must not contain duplicate names: ` +
    `${[...new Set(duplicateSourceNames)].join(', ')}`,
  );
  const sortedSourceNames = sourceNames
    .filter((source) => typeof source === 'string' && source.length > 0)
    .sort();
  expectJsonEqual(
    failures,
    tag,
    'dataFreshness sources must equal the complete score-affecting source set',
    sortedSourceNames,
    scoreAffectingFreshnessSources,
  );
  const sources = new Map(sourceRows.map((source) => [source?.source, source]));
  if (reader && typeof reader.sourceFreshnessFor === 'function') {
    let expectedRows = [];
    try {
      expectedRows = reader.sourceFreshnessFor(releaseTag) ?? [];
    } catch (error) {
      failures.push(
        `${tag}: dataFreshness source rows could not be independently reconstructed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const expectedNames = expectedRows.map((row) => row?.source);
    const expectedDuplicates = expectedNames.filter(
      (source, index) =>
        typeof source === 'string' && expectedNames.indexOf(source) !== index,
    );
    expect(
      failures,
      tag,
      expectedDuplicates.length === 0,
      `independently reconstructed freshness rows must not contain duplicate names: ` +
      `${[...new Set(expectedDuplicates)].join(', ')}`,
    );
    expectJsonEqual(
      failures,
      tag,
      'API dataFreshness source/maxAt rows must equal independently reconstructed DB freshness rows',
      sourceRows
        .map((row) => ({ source: row?.source, maxAt: row?.maxAt ?? null }))
        .sort((left, right) => String(left.source).localeCompare(String(right.source))),
      expectedRows
        .map((row) => ({ source: row?.source, maxAt: row?.max_ts ?? null }))
        .sort((left, right) => String(left.source).localeCompare(String(right.source))),
    );
  }
  expect(failures, tag, dataFreshness.issueUpdatedAtMax === (sources.get('issue_rows')?.maxAt ?? null),
    'dataFreshness issueUpdatedAtMax must match issue_rows source');
  expect(failures, tag, dataFreshness.closureProofCheckedAtMax === (sources.get('closure_proofs')?.maxAt ?? null),
    'dataFreshness closureProofCheckedAtMax must match closure_proofs source');
  const sourceFetchedAtMax = maxFreshnessTimestamp(sourceRows.map((source) => source?.maxAt ?? null));
  expect(failures, tag, dataFreshness.sourceFetchedAtMax === sourceFetchedAtMax,
    `dataFreshness sourceFetchedAtMax (${dataFreshness.sourceFetchedAtMax}) must equal max source timestamp (${sourceFetchedAtMax})`);
  for (const source of sourceRows) {
    expect(failures, tag, typeof source?.source === 'string' && source.source.length > 0,
      'dataFreshness source name must be present');
    expect(failures, tag, Number.isInteger(source?.count) && source.count >= 0,
      `dataFreshness ${source?.source} count must be a non-negative integer`);
    expect(failures, tag, Number.isInteger(source?.nullCount) && source.nullCount >= 0,
      `dataFreshness ${source?.source} nullCount must be a non-negative integer`);
    expect(failures, tag, Number(source?.nullCount ?? 0) <= Number(source?.count ?? 0),
      `dataFreshness ${source?.source} nullCount (${source?.nullCount}) must not exceed count (${source?.count})`);
    expect(failures, tag, Number(source?.nullCount ?? 0) === 0,
      `dataFreshness ${source?.source} must not have null freshness timestamps`);
    if (source?.maxAt != null) {
      expect(failures, tag, Number.isFinite(Date.parse(source.maxAt)),
        `dataFreshness ${source.source} maxAt must be a valid timestamp`);
      if (dataFreshness.scoredAt != null && Number.isFinite(Date.parse(source.maxAt)) && Number.isFinite(Date.parse(dataFreshness.scoredAt))) {
        expect(failures, tag, Date.parse(source.maxAt) <= Date.parse(dataFreshness.scoredAt),
          `dataFreshness ${source.source} changed at ${source.maxAt}, newer than scoredAt ${dataFreshness.scoredAt}`);
      }
    }
    if (source?.ageHoursAtScore != null) {
      expect(failures, tag, typeof source.ageHoursAtScore === 'number' && Number.isFinite(source.ageHoursAtScore),
        `dataFreshness ${source.source} ageHoursAtScore must be numeric`);
      expect(failures, tag, source.ageHoursAtScore === ageHoursAtScore(source.maxAt, dataFreshness.scoredAt),
        `dataFreshness ${source.source} ageHoursAtScore (${source.ageHoursAtScore}) must equal scoredAt - maxAt (${ageHoursAtScore(source.maxAt, dataFreshness.scoredAt)})`);
    }
  }
  expect(failures, tag, dataFreshness.issueUpdatedAgeHoursAtScore === ageHoursAtScore(dataFreshness.issueUpdatedAtMax, dataFreshness.scoredAt),
    `dataFreshness issueUpdatedAgeHoursAtScore (${dataFreshness.issueUpdatedAgeHoursAtScore}) must equal scoredAt - issueUpdatedAtMax (${ageHoursAtScore(dataFreshness.issueUpdatedAtMax, dataFreshness.scoredAt)})`);
  expect(failures, tag, dataFreshness.sourceFetchedAgeHoursAtScore === ageHoursAtScore(dataFreshness.sourceFetchedAtMax, dataFreshness.scoredAt),
    `dataFreshness sourceFetchedAgeHoursAtScore (${dataFreshness.sourceFetchedAgeHoursAtScore}) must equal scoredAt - sourceFetchedAtMax (${ageHoursAtScore(dataFreshness.sourceFetchedAtMax, dataFreshness.scoredAt)})`);
  for (const key of ['issueUpdatedAgeHoursAtScore', 'sourceFetchedAgeHoursAtScore']) {
    const value = dataFreshness[key];
    if (value != null) {
      expect(failures, tag, typeof value === 'number' && Number.isFinite(value),
        `dataFreshness ${key} must be numeric`);
    }
  }
}

function verifyPersistedAuditTuple({ failures, tag, release, audit, scoreInput, scoreComponents }) {
  if ('final_score' in audit) {
    expect(failures, tag, sameNumberOrNull(audit.final_score, release.final_score),
      `audit final_score (${audit.final_score}) must match DB final_score (${release.final_score})`);
  }
  if ('status' in audit) {
    expect(failures, tag, audit.status === release.state,
      `audit status (${audit.status}) must match DB state (${release.state})`);
  }
  if ('band' in audit) {
    expect(failures, tag, typeof audit.band === 'string' && audit.band.length > 0,
      `audit band (${audit.band}) must be present`);
  }
  if ('recommended' in audit) {
    expect(failures, tag, Number(audit.recommended) === Number(release.recommended ?? 0),
      `audit recommended (${audit.recommended}) must match DB recommended (${release.recommended})`);
  }
  if ('scored_at' in audit) {
    expect(failures, tag, audit.scored_at === release.scored_at,
      `audit scored_at (${audit.scored_at}) must match DB scored_at (${release.scored_at})`);
  }
  if (scoreComponents?.reason != null) {
    expect(failures, tag, scoreComponents.reason === release.score_reason,
      `score components reason (${scoreComponents.reason}) must match DB score_reason (${release.score_reason})`);
  }
  const ledger = scoreComponents?.explanation?.scoreLedger;
  expect(failures, tag, isObject(ledger),
    'persisted score components must contain a non-null ScoreLedgerV2');
  if (isObject(ledger)) {
    expect(failures, tag, sameNumberOrNull(ledger.finalScore, release.final_score),
      `score ledger finalScore (${ledger.finalScore}) must match DB final_score (${release.final_score})`);
    expect(failures, tag, ledger.status === release.state,
      `score ledger status (${ledger.status}) must match DB state (${release.state})`);
  }
  if (typeof scoreInput.rawIssueCount === 'number' && typeof scoreInput.classifiedIssueCount === 'number') {
    expect(failures, tag, scoreInput.classifiedIssueCount === scoreInput.rawIssueCount,
      `score input classifiedIssueCount (${scoreInput.classifiedIssueCount}) must equal rawIssueCount (${scoreInput.rawIssueCount})`);
  }
}

function verifyPersistedScoreReplay({
  failures,
  tag,
  reader,
  release,
  audit,
  scoreInput,
  scoreComponents,
  issueEvidence,
  gate,
  proofRows,
}) {
  const explanation = scoreComponents?.explanation;
  const ledger = explanation?.scoreLedger;
  expect(failures, tag, isObject(ledger),
    'persisted score explanation must contain a ScoreLedgerV2 for semantic replay');
  if (!isObject(ledger)) return;
  expect(
    failures,
    tag,
    audit?.score_model_version === SCORE_MODEL_VERSION,
    `persisted score model (${audit?.score_model_version}) cannot be semantically replayed by current model ${SCORE_MODEL_VERSION}`,
  );
  if (audit?.score_model_version !== SCORE_MODEL_VERSION) return;

  const evaluatedAt = Date.parse(ledger.evaluatedAt ?? '');
  expect(failures, tag, Number.isFinite(evaluatedAt),
    `persisted scoreLedger evaluatedAt must be a valid timestamp, got ${ledger.evaluatedAt}`);
  if (!Number.isFinite(evaluatedAt)) return;

  let replayed;
  try {
    replayed = installConfidence(scoreInput, evaluatedAt);
  } catch (error) {
    failures.push(
      `${tag}: persisted score input could not be independently replayed: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    );
    return;
  }
  expectJsonEqual(
    failures,
    tag,
    'persisted score components must equal independently replayed InstallInput components',
    scoreComponents?.components ?? null,
    replayed.components,
  );
  expect(failures, tag, sameNumberOrNull(scoreComponents?.evidenceCoverage, replayed.evidenceCoverage),
    `persisted evidenceCoverage (${scoreComponents?.evidenceCoverage}) must equal replay (${replayed.evidenceCoverage})`);
  expect(failures, tag, scoreComponents?.hotfix === replayed.hotfix,
    `persisted hotfix (${scoreComponents?.hotfix}) must equal replay (${replayed.hotfix})`);
  expect(failures, tag, scoreComponents?.reason === replayed.reason,
    `persisted components.reason must equal independently replayed reason (${JSON.stringify(replayed.reason)})`);
  expect(failures, tag, release?.score_reason === replayed.reason,
    `release score_reason must equal independently replayed reason (${JSON.stringify(replayed.reason)})`);
  expect(failures, tag, sameNumberOrNull(release?.final_score, replayed.score),
    `release final_score (${release?.final_score}) must equal independently replayed score (${replayed.score})`);
  expect(failures, tag, release?.state === replayed.status,
    `release state (${release?.state}) must equal independently replayed status (${replayed.status})`);
  expect(failures, tag, sameNumberOrNull(ledger.finalScore, replayed.score),
    `persisted scoreLedger finalScore (${ledger.finalScore}) must equal replay (${replayed.score})`);
  expect(failures, tag, ledger.status === replayed.status,
    `persisted scoreLedger status (${ledger.status}) must equal replay (${replayed.status})`);
  expect(failures, tag, ledger.band === replayed.band,
    `persisted scoreLedger band (${ledger.band}) must equal replay (${replayed.band})`);

  const evidenceBindings = verifyScoreInputEvidenceBinding({
    failures,
    tag,
    reader,
    release,
    scoreInput,
    issueEvidence,
    gate,
  });
  verifyScoreExplanation({
    failures,
    tag,
    explanation,
    recommended: Number(release?.recommended ?? 0) === 1,
    expectedBand: replayed.band,
    source: 'persisted',
  });
  verifyScoreExplanationSemanticReplay({
    failures,
    tag,
    explanation,
    scoreInput,
    scoreComponents,
    gate,
  });

  const reconstruction = reconstructScoreLedgerForAudit({
    failures,
    tag,
    reader,
    release,
    audit,
    scoreInput,
    scoreComponents,
    issueEvidence,
    gate,
    proofRows,
    ledger,
    replayed,
    evidenceBindings,
  });
  if (!reconstruction) return;

  const expectedManifestByKey = new Map(
    (reconstruction.ledger.evidence?.manifests ?? [])
      .map((manifest) => [manifest.key, manifest]),
  );
  const actualManifestByKey = new Map(
    (ledger.evidence?.manifests ?? [])
      .map((manifest) => [manifest.key, manifest]),
  );
  for (const key of reconstruction.reconstructedManifestKeys) {
    expectJsonEqual(
      failures,
      tag,
      `scoreLedger ${key} manifest must match independently reconstructed evidence`,
      actualManifestByKey.get(key) ?? null,
      expectedManifestByKey.get(key) ?? null,
    );
  }
  if (reconstruction.aliasElectionComplete) {
    expectJsonEqual(
      failures,
      tag,
      'scoreLedger aliasElection must match independently reconstructed score-affecting operands',
      ledger.aliasElection,
      reconstruction.ledger.aliasElection,
    );
    expectJsonEqual(
      failures,
      tag,
      'scoreLedger aliasElection manifest must match independently reconstructed score-affecting operands',
      actualManifestByKey.get('aliasElection') ?? null,
      expectedManifestByKey.get('aliasElection') ?? null,
    );
  }
  if (!reconstruction.complete) return;

  expectJsonEqual(
    failures,
    tag,
    'persisted scoreLedger derivation must equal the independently reconstructed evidence-bound ledger before explanation receipt binding',
    scoreLedgerDerivationForAudit(ledger),
    scoreLedgerDerivationForAudit(reconstruction.ledger),
  );
}

function scoreLedgerDerivationForAudit(ledger) {
  if (!isObject(ledger)) return ledger;
  const derivation = structuredClone(ledger);
  delete derivation.digest;
  delete derivation.explanationAudit;
  return derivation;
}

function verifyScoreInputEvidenceBinding({
  failures,
  tag,
  reader,
  release,
  scoreInput,
  issueEvidence,
  gate,
}) {
  const releaseEvidence = releaseScoreEvidenceForAudit({
    failures,
    tag,
    reader,
    release,
  });
  for (const [field, expected] of Object.entries(releaseEvidence.input ?? {})) {
    expect(
      failures,
      tag,
      sameAuditScalar(scoreInput?.[field], expected),
      `score input ${field} (${JSON.stringify(scoreInput?.[field])}) must match bound evidence (${JSON.stringify(expected)})`,
    );
  }

  const targetAttributions = Array.isArray(issueEvidence?.targetEvidenceAttribution)
    ? issueEvidence.targetEvidenceAttribution
    : [];
  const targetAttributionCount =
    Number(issueEvidence?.evidenceCounts?.targetEvidenceAttribution ?? targetAttributions.length);
  expect(
    failures,
    tag,
    targetAttributionCount === 0 && targetAttributions.length === 0,
    'post-publication target evidence attribution cannot be independently reconstructed by the current audit reader',
  );
  if (typeof reader.issueNumbersForVersion === 'function') {
    const issueNumbers = reader.issueNumbersForVersion(tag);
    expect(
      failures,
      tag,
      Number(scoreInput?.rawIssueCount) === issueNumbers.length,
      `score input rawIssueCount (${scoreInput?.rawIssueCount}) must match the independently read DB issue universe (${issueNumbers.length})`,
    );
  }
  if (typeof reader.issuesForVersion === 'function') {
    const classifiedRows = reader.issuesForVersion(tag);
    expect(
      failures,
      tag,
      Number(scoreInput?.classifiedIssueCount) === classifiedRows.length,
      `score input classifiedIssueCount (${scoreInput?.classifiedIssueCount}) must match independently read classified rows (${classifiedRows.length})`,
    );
  }

  for (const [evidenceKey, inputWeightField, inputCountField, summaryKey] of [
    ['verifiedDebt', 'verifiedDebtWeight', 'verifiedDebtIssueCount', 'verified'],
    ['carryoverDebt', 'carryoverDebtWeight', 'carryoverDebtIssueCount', 'carryover'],
    ['staleDebt', 'staleDebtWeight', 'staleDebtIssueCount', 'stale'],
  ]) {
    const items = Array.isArray(issueEvidence?.[evidenceKey])
      ? issueEvidence[evidenceKey]
      : [];
    const persistedCount =
      Number(issueEvidence?.evidenceCounts?.[evidenceKey] ?? items.length);
    const summary = issueEvidence?.debtSummary?.[summaryKey];
    const independentlyEmpty =
      persistedCount === 0 &&
      items.length === 0 &&
      Number(summary?.count ?? 0) === 0 &&
      Number(summary?.weight ?? 0) === 0;
    expect(
      failures,
      tag,
      independentlyEmpty,
      `score-affecting ${evidenceKey} evidence cannot be independently reconstructed from the current audit reader`,
    );
    if (independentlyEmpty) {
      expect(failures, tag, Number(scoreInput?.[inputWeightField] ?? 0) === 0,
        `score input ${inputWeightField} must be zero when independently reconstructed ${evidenceKey} is empty`);
      expect(failures, tag, Number(scoreInput?.[inputCountField] ?? 0) === 0,
        `score input ${inputCountField} must be zero when independently reconstructed ${evidenceKey} is empty`);
    }
  }

  const openedItems = Array.isArray(issueEvidence?.openedFeltSerious)
    ? issueEvidence.openedFeltSerious
    : [];
  const openedCount =
    Number(issueEvidence?.evidenceCounts?.openedFeltSerious ?? openedItems.length);
  expect(
    failures,
    tag,
    openedCount === 0 &&
      openedItems.length === 0 &&
      Number(scoreInput?.feltOpenedWeight ?? 0) === 0,
    'score-affecting openedFeltSerious evidence cannot be independently reconstructed from the current audit reader',
  );
  expect(
    failures,
    tag,
    Number(scoreInput?.feltClosedWeight ?? 0) === 0,
    'score-affecting fixed-regression evidence cannot be independently reconstructed from the current audit reader',
  );

  const releaseChecks = releaseCheckEvidenceForAudit({
    failures,
    tag,
    reader,
  });
  if (releaseChecks.complete) {
    for (const [field, expected] of Object.entries(releaseChecks.input)) {
      expect(
        failures,
        tag,
        sameAuditScalar(scoreInput?.[field], expected),
        `score input ${field} (${JSON.stringify(scoreInput?.[field])}) must match independently read release-check evidence (${JSON.stringify(expected)})`,
      );
    }
  }

  const artifact = artifactEvidenceForAudit({
    failures,
    tag,
    reader,
    release,
    scoreInput,
    artifactVerification: gate?.artifactVerification,
  });

  expect(
    failures,
    tag,
    scoreInput?.cveAffected !== true && Number(scoreInput?.cveLoad ?? 0) === 0,
    'score-affecting advisory rows cannot be independently reconstructed from the current audit reader',
  );

  return {
    releaseEvidence,
    releaseChecks,
    artifact,
  };
}

function artifactEvidenceForAudit({
  failures,
  tag,
  reader,
  release,
  scoreInput,
  artifactVerification,
}) {
  const proofPresent = artifactVerification?.receiptId != null;
  const runId = artifactVerification?.runId ?? null;
  let selection = null;
  let releaseTagCommitOid = null;
  let complete = true;

  if (proofPresent || runId != null) {
    if (typeof runId !== 'string' || runId.length === 0) {
      complete = false;
      failures.push(
        `${tag}: score-affecting artifact proof is missing its observation run ID`,
      );
    } else if (typeof reader.releaseArtifactVerificationForAudit !== 'function') {
      complete = false;
      failures.push(
        `${tag}: score-affecting artifact evidence cannot be independently read from the current audit reader`,
      );
    } else {
      try {
        selection = reader.releaseArtifactVerificationForAudit(tag, runId);
        if (!selection) {
          complete = false;
          failures.push(
            `${tag}: artifact observation run ${runId} has no immutable selection for the scored release`,
          );
        }
      } catch (error) {
        complete = false;
        failures.push(
          `${tag}: artifact observation run ${runId} could not be independently reconstructed: ` +
          `${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  if (selection) {
    try {
      let row = null;
      if (typeof reader.releaseCommitForAudit === 'function') {
        row = reader.releaseCommitForAudit(tag);
      } else if (reader?.db?.prepare) {
        row = reader.db.prepare(`
          SELECT tag_commit_oid
          FROM release_commits
          WHERE tag=?
        `).get(tag) ?? null;
      }
      releaseTagCommitOid = normalizeAuditOid(row?.tag_commit_oid);
      if (!releaseTagCommitOid) {
        complete = false;
        failures.push(
          `${tag}: scored release commit OID is unavailable for artifact proof replay`,
        );
      }
    } catch (error) {
      complete = false;
      failures.push(
        `${tag}: scored release commit OID could not be read for artifact proof replay: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const projection = releaseArtifactScoreProjection(
    selection,
    releaseTagCommitOid,
  );
  if (stableJson(artifactVerification) !== stableJson(projection.gate)) {
    complete = false;
  }
  expectJsonEqual(
    failures,
    tag,
    'artifact verification gate must match independently reconstructed immutable observation and receipt evidence',
    artifactVerification,
    projection.gate,
  );
  for (const field of [
    'artifactVerified',
    'artifactMismatch',
    'ciReportVerified',
    'ciReportMismatch',
    'releaseIntegrityPresent',
    'releaseShaMatches',
  ]) {
    const actual = scoreInput?.[field] ?? null;
    const expected = projection.input[field] ?? null;
    if (!sameAuditScalar(actual, expected)) complete = false;
    expect(
      failures,
      tag,
      sameAuditScalar(actual, expected),
      `score input ${field} (${JSON.stringify(actual)}) must match independently reconstructed artifact evidence (${JSON.stringify(expected)})`,
    );
  }

  if (
    selection &&
    (
      selection.receipt?.release?.tag !== tag ||
      selection.receipt?.release?.catalogTagCommitOid !==
        release?.catalog_tag_commit_oid
    )
  ) {
    complete = false;
    failures.push(
      `${tag}: immutable artifact receipt release identity does not match the scored catalog release`,
    );
  }

  return {
    complete,
    selection,
    projection,
  };
}

function releaseScoreEvidenceForAudit({ failures, tag, reader, release }) {
  const stableRows = typeof reader.stableReleaseBoundaryRows === 'function'
    ? reader.stableReleaseBoundaryRows()
    : [];
  const activeRows = typeof reader.activeReleaseBoundaryRows === 'function'
    ? reader.activeReleaseBoundaryRows()
    : [];
  const stableTags = stableRows
    .map((row) => row?.tag)
    .filter((value) => typeof value === 'string' && value.length > 0);
  const activeTags = activeRows
    .map((row) => row?.tag)
    .filter((value) => typeof value === 'string' && value.length > 0);
  const duplicateStableTags = stableTags.filter(
    (value, index) => stableTags.indexOf(value) !== index,
  );
  const duplicateActiveTags = activeTags.filter(
    (value, index) => activeTags.indexOf(value) !== index,
  );
  expect(
    failures,
    tag,
    stableRows.length > 0 &&
      duplicateStableTags.length === 0 &&
      stableTags.includes(tag),
    'release score operands require a complete, unique stable release boundary projection',
  );
  expect(
    failures,
    tag,
    activeRows.length > 0 &&
      duplicateActiveTags.length === 0 &&
      activeTags.includes(tag),
    'release score operands require a complete, unique active release catalog projection',
  );
  if (
    stableRows.length === 0 ||
    duplicateStableTags.length > 0 ||
    !stableTags.includes(tag) ||
    activeRows.length === 0 ||
    duplicateActiveTags.length > 0 ||
    !activeTags.includes(tag)
  ) {
    return { complete: false, input: null, payload: null };
  }
  const input = {
    publishedAt: release?.published_at ?? null,
    isLatest: stableTags[0] === tag,
    hoursToNextStable: release?.hours_to_next_stable ?? null,
    hasHotfixSuccessor: hasHotfixSuccessor(activeRows, tag),
    betaCount: Number(release?.beta_count ?? 0),
    breakingCount: Number(release?.breaking_count ?? 0),
  };
  return {
    complete: true,
    input,
    payload: {
      tag,
      ...input,
    },
  };
}

function releaseCheckEvidenceForAudit({ failures, tag, reader }) {
  let row = null;
  try {
    if (typeof reader.releaseCommitForAudit === 'function') {
      row = reader.releaseCommitForAudit(tag);
    } else if (reader?.db?.prepare) {
      row = reader.db.prepare(`
        SELECT check_state, check_total, check_success, check_failure,
               check_pending, check_contexts_json
        FROM release_commits
        WHERE tag=?
      `).get(tag) ?? null;
    } else {
      expect(
        failures,
        tag,
        false,
        'release-check operands cannot be independently read from the current audit reader',
      );
      return { complete: false, input: {}, contexts: [] };
    }
  } catch (error) {
    failures.push(
      `${tag}: release-check operands could not be independently reconstructed: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    );
    return { complete: false, input: {}, contexts: [] };
  }
  const contexts = parseJson(row?.check_contexts_json, []);
  expect(failures, tag, Array.isArray(contexts),
    'independently read release-check contexts must be an array');
  if (!Array.isArray(contexts)) {
    return { complete: false, input: {}, contexts: [] };
  }
  return {
    complete: true,
    input: {
      releaseCheckState: row?.check_state ?? null,
      releaseCheckTotal: Number(row?.check_total ?? 0),
      releaseCheckSuccess: Number(row?.check_success ?? 0),
      releaseCheckFailure: Number(row?.check_failure ?? 0),
      releaseCheckPending: Number(row?.check_pending ?? 0),
    },
    contexts,
  };
}

function reconstructScoreLedgerForAudit({
  failures,
  tag,
  reader,
  release,
  scoreInput,
  scoreComponents,
  issueEvidence,
  gate,
  proofRows,
  ledger,
  replayed,
  evidenceBindings,
}) {
  const sources = [];
  const reconstructedManifestKeys = new Set();
  let complete = true;

  const releaseEvidence = evidenceBindings?.releaseEvidence;
  sources.push({
    key: 'release',
    refs: releaseEvidence?.complete ? [{
      kind: 'release',
      identity: `release:${tag}`,
      payload: releaseEvidence.payload,
    }] : [],
  });
  if (releaseEvidence?.complete) {
    reconstructedManifestKeys.add('release');
  } else {
    complete = false;
  }

  const debtItems = [];
  let issueRiskSourcesComplete = true;
  for (const [evidenceKey, ledgerKey, inputWeightField, inputCountField] of [
    ['verifiedDebt', 'verifiedDebt', 'verifiedDebtWeight', 'verifiedDebtIssueCount'],
    ['carryoverDebt', 'carryoverDebt', 'carryoverDebtWeight', 'carryoverDebtIssueCount'],
    ['staleDebt', 'staleDebt', 'staleDebtWeight', 'staleDebtIssueCount'],
  ]) {
    const items = Array.isArray(issueEvidence?.[evidenceKey])
      ? issueEvidence[evidenceKey]
      : [];
    const persistedCount =
      Number(issueEvidence?.evidenceCounts?.[evidenceKey] ?? items.length);
    const independentlyEmpty =
      persistedCount === 0 &&
      items.length === 0 &&
      scoreLedgerManifestCount(ledger, ledgerKey) === 0 &&
      Number(scoreInput?.[inputWeightField] ?? 0) === 0 &&
      Number(scoreInput?.[inputCountField] ?? 0) === 0;
    sources.push({ key: ledgerKey, refs: [] });
    if (independentlyEmpty) {
      reconstructedManifestKeys.add(ledgerKey);
    } else {
      issueRiskSourcesComplete = false;
      complete = false;
      failures.push(
        `${tag}: scoreLedger ${ledgerKey} source cannot be independently reconstructed: ` +
        'only an independently empty source is supported by the current audit reader',
      );
    }
  }

  const openedItems = Array.isArray(issueEvidence?.openedFeltSerious)
    ? issueEvidence.openedFeltSerious
    : [];
  const openedExpectedCount =
    Number(issueEvidence?.evidenceCounts?.openedFeltSerious ?? openedItems.length);
  const regressionOpenedEmpty =
    openedExpectedCount === 0 &&
    openedItems.length === 0 &&
    scoreLedgerManifestCount(ledger, 'regressionOpened') === 0 &&
    Number(scoreInput?.feltOpenedWeight ?? 0) === 0;
  sources.push({ key: 'regressionOpened', refs: [] });
  if (regressionOpenedEmpty) {
    reconstructedManifestKeys.add('regressionOpened');
  } else {
    issueRiskSourcesComplete = false;
    complete = false;
    failures.push(
      `${tag}: scoreLedger regressionOpened source cannot be independently reconstructed: ` +
      'only an independently empty source is supported by the current audit reader',
    );
  }
  const regressionOpenedPayloads = [];

  const scoreAuthorityCount = scoreLedgerManifestCount(ledger, 'scoreAuthority');
  const closureReconstruction = reconstructRawClosureRisk({
    failures,
    reader,
    tag,
    proofRows,
    scoreAuthorityCount,
  });
  const rawClosureRisk = closureReconstruction.risk;
  if (closureReconstruction.complete) {
    reconstructedManifestKeys.add('closureCeiling');
  } else {
    complete = false;
  }
  const aliasCandidates = [
    ...debtItems.map((item) => ({
      aliasGroup: item.aliasGroup,
      channel: item.channel,
      weight: Number(item.weight ?? 0),
      issueNumber: item.issueNumber,
    })),
    ...regressionOpenedPayloads.map((item) => ({
      aliasGroup: item.aliasGroup,
      channel: 'regression',
      weight: Number(item.countedWeight ?? item.weight ?? 0),
      issueNumber: item.issueNumber,
    })),
    ...rawClosureRisk.groups.map((item) => ({
      aliasGroup: item.key,
      channel: 'closureRisk',
      weight: Number(item.weight ?? 0),
      issueNumber: item.issueNumber,
    })),
  ];
  let aliasElection;
  let aliasElectionComplete =
    issueRiskSourcesComplete && closureReconstruction.complete;
  try {
    aliasElection = buildExclusiveIssueRiskLedger(aliasCandidates);
  } catch (error) {
    failures.push(
      `${tag}: scoreLedger alias election could not be independently reconstructed: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
  const expectedAliasTotals = {
    verified: Number(scoreInput?.verifiedDebtWeight ?? 0),
    carryover: Number(scoreInput?.carryoverDebtWeight ?? 0),
    stale: Number(scoreInput?.staleDebtWeight ?? 0),
    closureRisk: Number(scoreInput?.unresolvedClosureRiskWeight ?? 0),
    regression: Number(scoreInput?.feltOpenedWeight ?? 0),
  };
  for (const [channel, expected] of Object.entries(expectedAliasTotals)) {
    if (!sameNumber(Number(aliasElection.totalsByChannel?.[channel] ?? 0), expected)) {
      aliasElectionComplete = false;
      complete = false;
      failures.push(
        `${tag}: independently reconstructed alias election ${channel} total ` +
        `(${aliasElection.totalsByChannel?.[channel] ?? 0}) must equal score input (${expected})`,
      );
    }
  }
  const selectedClosureGroups = new Set(
    aliasElection.groups
      .filter((group) => group.selectedChannel === 'closureRisk')
      .map((group) => group.aliasGroup),
  );
  sources.push({
    key: 'closureRisk',
    refs: rawClosureRisk.groups
      .filter((group) => selectedClosureGroups.has(group.key))
      .map((group) => ({
        kind: 'closure_group',
        identity: `closure:${group.key}`,
        payload: group,
      })),
  });
  sources.push({
    key: 'closureCeiling',
    refs: rawClosureRisk.groups.map((group) => ({
      kind: 'closure_group',
      identity: `closure:${group.key}`,
      payload: group,
    })),
  });
  if (aliasElectionComplete) reconstructedManifestKeys.add('closureRisk');

  const regressionFixedCount = scoreLedgerManifestCount(ledger, 'regressionFixed');
  sources.push({ key: 'regressionFixed', refs: [] });
  if (regressionFixedCount === 0 && Number(scoreInput?.feltClosedWeight ?? 0) === 0) {
    reconstructedManifestKeys.add('regressionFixed');
  } else {
    complete = false;
    failures.push(
      `${tag}: scoreLedger regressionFixed source cannot be independently reconstructed from bound evidence`,
    );
  }

  const coverageRows = typeof reader.issuesForVersion === 'function'
    ? reader.issuesForVersion(tag)
    : [];
  const coverageIssueNumbers = typeof reader.issueNumbersForVersion === 'function'
    ? reader.issueNumbersForVersion(tag)
    : [];
  const targetAttributions = Array.isArray(issueEvidence?.targetEvidenceAttribution)
    ? issueEvidence.targetEvidenceAttribution
    : [];
  const targetAttributionCount =
    Number(issueEvidence?.evidenceCounts?.targetEvidenceAttribution ?? targetAttributions.length);
  const coverageRowsNeedSourceIdentityLookup = coverageRows.some(
    (row) => typeof row?.source_identity_digest !== 'string',
  );
  let classificationSourceIdentityStatement = null;
  if (coverageRowsNeedSourceIdentityLookup && reader?.db?.prepare) {
    try {
      classificationSourceIdentityStatement = reader.db.prepare(`
        SELECT source_identity_digest
        FROM classifications
        WHERE issue_number=?
      `);
    } catch (error) {
      failures.push(
        `${tag}: classification source identity provenance could not be independently read: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  let coverageComplete =
    coverageRows.length === Number(scoreInput?.classifiedIssueCount ?? -1) &&
    coverageIssueNumbers.length === Number(scoreInput?.rawIssueCount ?? -1) &&
    targetAttributionCount === 0 &&
    targetAttributions.length === 0 &&
    (!coverageRowsNeedSourceIdentityLookup || classificationSourceIdentityStatement != null);
  const coverageNumbers = new Set();
  const coverageRefs = coverageRows.map((row) => {
    const issueNumber = Number(row?.number);
    if (coverageNumbers.has(issueNumber)) coverageComplete = false;
    coverageNumbers.add(issueNumber);
    let classifierSourceIdentityDigest = row?.source_identity_digest ?? null;
    if (
      typeof classifierSourceIdentityDigest !== 'string' &&
      classificationSourceIdentityStatement
    ) {
      try {
        classifierSourceIdentityDigest =
          classificationSourceIdentityStatement.get(issueNumber)
            ?.source_identity_digest ?? null;
      } catch (error) {
        coverageComplete = false;
        failures.push(
          `${tag}: classification source identity for issue #${issueNumber} ` +
          `could not be independently read: ` +
          `${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    const fallbackLabels = parseJson(row?.labels, []);
    const labels = typeof reader.labelsForIssueAt === 'function'
      ? reader.labelsForIssueAt(
        issueNumber,
        fallbackLabels,
        gate?.labelTimeline?.cutoffAt ?? null,
        {
          useFallbackWhenNoEvents: gate?.labelTimeline?.cutoffAt == null,
          useSnapshotWhenNoEvents: gate?.labelTimeline?.cutoffAt != null,
        },
      )
      : fallbackLabels;
    const classification = effectiveClassificationForAuditIssue({
      reader,
      row,
      cutoff: gate?.labelTimeline?.cutoffAt ?? null,
    });
    if (
      !Number.isInteger(Number(row?.number)) ||
      typeof row?.updated_at !== 'string' ||
      typeof row?.classification_origin !== 'string' ||
      typeof classifierSourceIdentityDigest !== 'string' ||
      !sha256HexRe.test(classifierSourceIdentityDigest) ||
      !Array.isArray(labels) ||
      labels.some((label) => labelUsesScoreAuthority(label)) ||
      !classification
    ) {
      coverageComplete = false;
    }
    return {
      kind: 'classification',
      identity: `issue:${row?.number}:classification`,
      payload: {
        issueNumber: Number(row?.number),
        updatedAt: row?.updated_at,
        classification,
        classificationOrigin: row?.classification_origin,
        classifierSourceIdentityDigest,
      },
    };
  });
  if (
    coverageIssueNumbers.some((issueNumber) => !coverageNumbers.has(Number(issueNumber))) ||
    coverageNumbers.size !== coverageIssueNumbers.length
  ) {
    coverageComplete = false;
  }
  sources.push({ key: 'coverage', refs: coverageRefs });
  if (coverageComplete) {
    reconstructedManifestKeys.add('coverage');
  } else {
    complete = false;
    failures.push(
      `${tag}: scoreLedger coverage source cannot be independently reconstructed from complete classified DB rows`,
    );
  }

  const releaseChecks = evidenceBindings?.releaseChecks;
  const releaseCheckContexts = Array.isArray(releaseChecks?.contexts)
    ? releaseChecks.contexts
    : [];
  sources.push({
    key: 'releaseChecks',
    refs: releaseCheckContexts.map((context, index) => {
      const row = isObject(context) ? context : {};
      return {
        kind: 'release_check',
        identity:
          `check:${index}:${String(row.name ?? row.context ?? row.type ?? 'unknown')}:` +
          `${String(row.url ?? '')}`,
        payload: context,
      };
    }),
  });
  if (releaseChecks?.complete) {
    reconstructedManifestKeys.add('releaseChecks');
  } else {
    complete = false;
    failures.push(
      `${tag}: scoreLedger releaseChecks source cannot be independently reconstructed from DB release-check rows`,
    );
  }

  const artifactEvidence = evidenceBindings?.artifact;
  const artifactReceipt = artifactEvidence?.selection?.receipt ?? null;
  sources.push({
    key: 'artifact',
    refs: artifactEvidence?.complete && artifactReceipt ? [{
      kind: 'artifact',
      identity: artifactReceipt.receiptId,
      digest: artifactReceipt.evidenceIdentity,
      payload: artifactEvidence.projection.gate,
    }] : [],
  });
  if (artifactEvidence?.complete) {
    reconstructedManifestKeys.add('artifact');
  } else {
    complete = false;
    failures.push(
      `${tag}: scoreLedger artifact source cannot be independently reconstructed from immutable receipt evidence`,
    );
  }

  const advisoryCount = scoreLedgerManifestCount(ledger, 'advisories');
  sources.push({ key: 'advisories', refs: [] });
  if (
    advisoryCount === 0 &&
    scoreInput?.cveAffected !== true &&
    Number(scoreInput?.cveLoad ?? 0) === 0
  ) {
    reconstructedManifestKeys.add('advisories');
  } else {
    complete = false;
    failures.push(
      `${tag}: scoreLedger advisories source cannot be independently reconstructed from aggregate CVE gate evidence`,
    );
  }

  const explanationAuthorityReferences =
    scoreComponents?.explanation?.authorityReferences;
  sources.push({ key: 'scoreAuthority', refs: [] });
  if (
    scoreAuthorityCount === 0 &&
    Array.isArray(explanationAuthorityReferences) &&
    explanationAuthorityReferences.length === 0
  ) {
    reconstructedManifestKeys.add('scoreAuthority');
  } else {
    complete = false;
    failures.push(
      `${tag}: scoreLedger scoreAuthority source cannot be independently reconstructed from submitted explanation references`,
    );
  }

  let expectedLedger;
  try {
    expectedLedger = buildScoreLedgerV2({
      input: scoreInput,
      confidence: replayed,
      now: Date.parse(ledger.evaluatedAt),
      evidenceSources: sources,
      aliasElection,
    });
  } catch (error) {
    failures.push(
      `${tag}: scoreLedger independent evidence replay failed: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
  expect(
    failures,
    tag,
    expectedLedger.formulaCode === `install-confidence.${SCORE_MODEL_VERSION}.ledger-v2`,
    `independent scoreLedger formula must use current model ${SCORE_MODEL_VERSION}`,
  );
  if (ledger.formulaCode !== expectedLedger.formulaCode) {
    complete = false;
    failures.push(
      `${tag}: persisted scoreLedger formulaCode (${ledger.formulaCode}) cannot be replayed by current model (${expectedLedger.formulaCode})`,
    );
  }
  return {
    ledger: expectedLedger,
    reconstructedManifestKeys,
    aliasElectionComplete,
    complete,
  };
}

function reconstructRawClosureRisk({
  failures,
  reader,
  tag,
  proofRows,
  scoreAuthorityCount,
}) {
  let complete = scoreAuthorityCount === 0;
  if (!complete) {
    failures.push(
      `${tag}: closure-risk operands cannot be independently reconstructed while score-authority evidence is present`,
    );
  }
  for (const row of proofRows) {
    if (
      authorityBoundClosureProofStatuses.has(row?.status) ||
      !Array.isArray(row?.effective_labels) ||
      row.effective_labels.some((label) => labelUsesScoreAuthority(label))
    ) {
      complete = false;
      failures.push(
        `${tag}: closure-risk operands for issue #${row?.issue_number ?? 'unknown'} ` +
        'require authority-bound closure or label evidence unavailable to the current audit reader',
      );
    }
  }
  const issueRows = [
    ...(typeof reader.issuesForVersion === 'function' ? reader.issuesForVersion(tag) : []),
    ...(typeof reader.openedDuringReign === 'function' ? reader.openedDuringReign(tag) : []),
    ...(typeof reader.verifiedFixedForRelease === 'function' ? reader.verifiedFixedForRelease(tag) : []),
    ...(typeof reader.unverifiedClosedForRelease === 'function' ? reader.unverifiedClosedForRelease(tag) : []),
  ];
  const uniqueIssues = new Map();
  for (const row of issueRows) {
    const issueNumber = Number(row?.number);
    if (Number.isInteger(issueNumber) && issueNumber > 0) {
      uniqueIssues.set(issueNumber, row);
    }
  }
  const aliases = buildIssueAliasGroups([
    ...[...uniqueIssues.values()].map((row) => ({
      issueNumber: Number(row.number),
      duplicateCluster: row.duplicate_cluster ?? null,
    })),
    ...proofRows.map((row) => ({
      issueNumber: Number(row.issue_number),
      duplicateCluster: row.duplicate_cluster ?? null,
      canonicalIssueNumbers: canonicalIssueNumbersFromEvidence(row.evidence_json),
    })),
  ]);
  const risk = aggregateClosureRisk(proofRows.map((row) => {
    const canonicalIssueNumbers = canonicalIssueNumbersFromEvidence(row.evidence_json);
    return {
      issueNumber: Number(row.issue_number),
      disposition: riskDispositionForStatus(row.status),
      weight: closureRiskWeightForProofRow(row),
      duplicateCluster: row.duplicate_cluster ?? null,
      canonicalIssueNumbers,
      aliasGroup: aliases.keyFor({
        issueNumber: Number(row.issue_number),
        duplicateCluster: row.duplicate_cluster ?? null,
        canonicalIssueNumbers,
      }),
    };
  }));
  return { complete, risk };
}

function effectiveClassificationForAuditIssue({ reader, row, cutoff }) {
  if (
    !row?.sentiment ||
    !row?.severity ||
    !row?.scope ||
    !row?.functionality ||
    !row?.affected_users
  ) {
    return null;
  }
  const fallbackLabels = parseJson(row.labels, []);
  const labels = typeof reader.labelsForIssueAt === 'function'
    ? reader.labelsForIssueAt(row.number, fallbackLabels, cutoff, {
      useFallbackWhenNoEvents: cutoff == null,
      useSnapshotWhenNoEvents: cutoff != null,
    })
    : fallbackLabels;
  const raw = rawClassificationForAuditIssue(row);
  return applyTitleIssueShapeHint(
    applyLabelOverrides(
      applyTitleFunctionalityHint(raw, row.title ?? ''),
      labels,
    ),
    row.title ?? '',
    labels,
  );
}

function rawClassificationForAuditIssue(row) {
  const workaroundStatus = ['none', 'partial', 'confirmed', 'unknown'].includes(row.workaround_status ?? '')
    ? row.workaround_status
    : row.has_workaround === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment,
    severity: row.severity,
    scope: row.scope,
    functionality: row.functionality,
    affectedUsers: row.affected_users,
    hasWorkaround: row.has_workaround === 1,
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster ?? null,
    affectsVersion: row.affects_version ?? null,
    confidence: typeof row.confidence === 'number' ? row.confidence : 0.5,
    rationale: row.rationale ?? '',
  };
}

function scoreLedgerManifestCount(ledger, key) {
  const manifest = Array.isArray(ledger?.evidence?.manifests)
    ? ledger.evidence.manifests.find((item) => item?.key === key)
    : null;
  return Number(manifest?.count ?? 0);
}

function sameAuditScalar(actual, expected) {
  if (typeof expected === 'number') return sameNumber(Number(actual), expected);
  return actual === expected;
}

function verifyScoreExplanationSemanticReplay({
  failures,
  tag,
  explanation,
  scoreInput,
  scoreComponents,
  gate,
}) {
  if (!isObject(explanation)) return;
  const modelCeilingDetail = Array.isArray(explanation.limitDetails)
    ? explanation.limitDetails.find((item) =>
      item?.code === 'model_ceiling_and_capped_confidence')
    : null;
  if (isObject(modelCeilingDetail)) {
    expect(
      failures,
      tag,
      modelCeilingDetail.text ===
        'No field-blocker evidence is currently holding this release down; the remaining gap comes from the model ceiling and capped confidence signals.',
      'score explanation model-ceiling prose must equal the independently known canonical claim',
    );
  }
  const closureProof = gate?.fixProvenance?.closureProof;
  const detail = Array.isArray(explanation.limitDetails)
    ? explanation.limitDetails.find((item) =>
      item?.code === 'closed_issues_not_counted_as_release_fixes')
    : null;
  const shouldExplainClosureRisk =
    Number(closureProof?.notCreditedCount ?? 0) > 0 &&
    (
      Number(scoreInput?.unresolvedClosureIssueCount ?? 0) > 0 ||
      Number(scoreInput?.unresolvedClosureRiskWeight ?? 0) > 0 ||
      Number(scoreInput?.affirmativeClosureRiskCeilingWeight ?? 0) > 0
    );
  expect(
    failures,
    tag,
    !shouldExplainClosureRisk || isObject(detail),
    'score explanation must include the closed-issue release-fix claim when closure risk affects the score',
  );
  if (!isObject(detail)) return;

  const components = scoreComponents?.components ?? {};
  const riskSummary = closureProof?.riskSummary ?? {};
  const closureCap = explanation.scoreLedger?.caps?.find(
    (cap) => cap?.key === 'closureRiskCeiling',
  );
  const expectedMetrics = {
    countedClosedCount: Number(closureProof?.creditedCount ?? 0),
    scoredUnresolvedRiskGroupCount:
      Number(scoreInput?.unresolvedClosureIssueCount ?? 0),
    scoredUnresolvedRiskWeight:
      roundMetric(Number(scoreInput?.unresolvedClosureRiskWeight ?? 0)),
    affirmativeClosureRiskCeilingWeight:
      roundMetric(Number(scoreInput?.affirmativeClosureRiskCeilingWeight ?? 0)),
    rawUnresolvedRiskGroupCount:
      Number(riskSummary.unresolvedForReleaseCount ?? 0),
    rawNotCountedClosedIssueCount:
      Number(closureProof?.notCreditedCount ?? 0),
    rawAnalyzedClosedIssueCount:
      Number(closureProof?.analyzedClosedCount ?? 0),
    cappedPenalty: Math.abs(Number(components.closureRisk ?? 0)),
    maxPenalty: SCORE_COMPONENT_LIMITS.closureRiskMaxPenalty,
    capApplied: closureCap?.applied === true,
    scoreCeiling: Number(components.closureRiskCeiling ?? 0) || null,
    noticeableClosureRiskThreshold:
      SCORE_COMPONENT_LIMITS.noticeableClosureRiskThreshold,
    noticeableClosureScoreCap:
      SCORE_COMPONENT_LIMITS.noticeableClosureScoreCap,
    heavyClosureRiskThreshold:
      SCORE_COMPONENT_LIMITS.heavyClosureRiskThreshold,
    resolvedByCanonicalReleaseFixCount:
      Number(riskSummary.resolvedByCanonicalReleaseFixCount ?? 0),
    resolvedByReleaseFixProofCount:
      Number(riskSummary.resolvedByReleaseFixProofCount ?? 0),
    knownNotInReleaseCount:
      Number(riskSummary.knownNotInReleaseCount ?? 0),
    openCanonicalRiskCount:
      Number(riskSummary.openCanonicalRiskCount ?? 0),
    unsupportedClosureClaimCount:
      Number(riskSummary.unsupportedClosureClaimCount ?? 0),
    neutralOrNonActionableCount:
      Number(riskSummary.neutralOrNonActionableCount ?? 0),
    neutralHighImpactCount:
      Number(riskSummary.neutralHighImpactCount ?? 0),
    neutralBugShapedCount:
      Number(riskSummary.neutralBugShapedCount ?? 0),
    missingEvidenceCount:
      Number(riskSummary.missingEvidenceCount ?? 0),
  };
  for (const [field, expected] of Object.entries(expectedMetrics)) {
    expect(
      failures,
      tag,
      sameAuditScalar(detail.metrics?.[field], expected),
      `score explanation closed-issue claim metrics.${field} ` +
      `(${JSON.stringify(detail.metrics?.[field])}) must equal independently replayed value (${JSON.stringify(expected)})`,
    );
  }
  const expectedPrefix =
    `${expectedMetrics.scoredUnresolvedRiskGroupCount} deduplicated closed-issue risk groups contribute to this score, ` +
    `with scored risk weight ${expectedMetrics.scoredUnresolvedRiskWeight}. ` +
    `The separate deduplicated affirmative closure-risk ceiling weight is ` +
    `${expectedMetrics.affirmativeClosureRiskCeilingWeight}; alias groups retained in verified or stale debt can still limit the score without receiving a second closure penalty. ` +
    `Separately, the raw closure-proof audit contains ${expectedMetrics.rawUnresolvedRiskGroupCount} unresolved groups across ` +
    `${expectedMetrics.rawNotCountedClosedIssueCount} closed issues without direct release-fix credit; ` +
    `${expectedMetrics.rawAnalyzedClosedIssueCount} closed issues were analyzed. ` +
    `The scored contribution is ${auditPenaltyText(components.closureRisk)} and is capped at a ` +
    `${SCORE_COMPONENT_LIMITS.closureRiskMaxPenalty} point penalty.`;
  expect(
    failures,
    tag,
    typeof detail.text === 'string' && detail.text.startsWith(expectedPrefix),
    'score explanation closed-issue prose must start with the independently replayed canonical claim',
  );
}

function auditPenaltyText(value) {
  if (typeof value !== 'number') {
    return 'no additional point penalty under the active gate';
  }
  return `a ${roundMetric(Math.abs(value))} point penalty`;
}

function verifyReviewSourceProvenance({
  failures,
  tag,
  sourceProvenance,
  dataFreshness,
  scoredAt,
  scoreSourceIdentity,
  auditLinks,
  expectedAuthorityBinding,
  expectedAdvisorySnapshotAuditProjection,
}) {
  expect(failures, tag, isObject(sourceProvenance), 'review sourceProvenance must be present');
  if (!isObject(sourceProvenance)) return;
  expect(failures, tag, sourceProvenance.sourceMode === 'current_db',
    `review sourceProvenance sourceMode (${sourceProvenance.sourceMode}) must be current_db`);
  expect(failures, tag, sourceProvenance.scoreTable === 'release_score_audits',
    `review sourceProvenance scoreTable (${sourceProvenance.scoreTable}) must be release_score_audits`);
  expect(failures, tag, sourceProvenance.scoredAt === scoredAt,
    `review sourceProvenance scoredAt (${sourceProvenance.scoredAt}) must match DB scored_at (${scoredAt})`);
  expect(failures, tag, sourceProvenance.dataFreshnessScoredAt === dataFreshness?.scoredAt,
    `review sourceProvenance dataFreshnessScoredAt (${sourceProvenance.dataFreshnessScoredAt}) must match dataFreshness scoredAt (${dataFreshness?.scoredAt})`);
  expect(failures, tag, sourceProvenance.scoreTimestampAligned === (scoredAt === dataFreshness?.scoredAt),
    `review sourceProvenance scoreTimestampAligned (${sourceProvenance.scoreTimestampAligned}) must reflect scoredAt/dataFreshness alignment`);
  expectJsonEqual(failures, tag, 'review sourceProvenance scoreSourceIdentity must match persisted audit identity',
    sourceProvenance.scoreSourceIdentity, scoreSourceIdentity);
  expectJsonEqual(failures, tag, 'review sourceProvenance sources must match review dataFreshness sources',
    sourceProvenance.sources, dataFreshness?.sources);
  if (expectedAdvisorySnapshotAuditProjection != null) {
    expectJsonEqual(
      failures,
      tag,
      'review sourceProvenance advisorySnapshot must match the independently reconstructed v2 publication audit',
      sourceProvenance.advisorySnapshot,
      expectedAdvisorySnapshotAuditProjection,
    );
  }
  verifyScoreAuthorityBinding({
    failures,
    tag,
    label: 'review sourceProvenance scoreAuthority',
    actual: sourceProvenance.scoreAuthority,
    expected: isObject(expectedAuthorityBinding)
      ? {
          runId: expectedAuthorityBinding.authorityRunId,
          contentHash: expectedAuthorityBinding.authorityRunContentHash,
          historyV2SealContentHash:
            expectedAuthorityBinding.historyV2SealContentHash,
        }
      : null,
  });
  const expectedRawRows = isObject(auditLinks)
    ? {
      issues: auditLinks.issues,
      closureProofs: auditLinks.closureProofs,
      reachability: auditLinks.reachability,
    }
    : null;
  expectJsonEqual(failures, tag, 'review sourceProvenance rawRows must point at review row endpoints',
    sourceProvenance.rawRows, expectedRawRows);
}

function reviewAuditIdentity(auditDigest) {
  return auditDigest ?? reviewAuditUnavailable;
}

function expectedAuditLinks(tag, publicationSnapshot, auditDigest) {
  const encodedTag = encodeURIComponent(tag);
  const binding = new URLSearchParams({
    publicationSnapshot,
    auditDigest: reviewAuditIdentity(auditDigest),
  }).toString();
  return {
    review: `/api/releases/${encodedTag}/review?${binding}`,
    issues: `/api/releases/${encodedTag}/review/issues?${binding}`,
    closureProofs: `/api/releases/${encodedTag}/review/closure-proofs?${binding}`,
    reachability: `/api/releases/${encodedTag}/review/reachability?${binding}`,
  };
}

function reviewEndpointPath(tag, endpoint) {
  const encodedTag = encodeURIComponent(tag);
  const suffix = {
    review: '',
    issues: '/issues',
    closureProofs: '/closure-proofs',
    reachability: '/reachability',
  }[endpoint];
  return `/api/releases/${encodedTag}/review${suffix}`;
}

function verifyPublishedReviewUrl({
  failures,
  tag,
  label,
  value,
  endpoint,
  publicationSnapshot,
  auditDigest,
  allowFilterParams = false,
}) {
  if (typeof value !== 'string' || !value.startsWith('/')) {
    expect(failures, tag, false, `${label} must be a root-relative API URL`);
    return false;
  }
  let parsed;
  try {
    parsed = new URL(value, 'https://radar.invalid');
  } catch {
    expect(failures, tag, false, `${label} must be a valid URL`);
    return false;
  }
  let valid = true;
  const check = (condition, message) => {
    expect(failures, tag, condition, message);
    valid = valid && condition;
  };
  check(
    parsed.origin === 'https://radar.invalid',
    `${label} must not target another origin`,
  );
  check(
    parsed.pathname === reviewEndpointPath(tag, endpoint),
    `${label} must point at the exact ${tag} ${endpoint} endpoint`,
  );
  check(parsed.hash === '', `${label} must not contain a fragment`);

  const snapshotValues = parsed.searchParams.getAll('publicationSnapshot');
  const digestValues = parsed.searchParams.getAll('auditDigest');
  check(
    snapshotValues.length === 1,
    `${label} must contain exactly one publicationSnapshot parameter`,
  );
  check(
    digestValues.length === 1,
    `${label} must contain exactly one auditDigest parameter`,
  );
  check(
    snapshotValues[0] === publicationSnapshot,
    `${label} publicationSnapshot (${snapshotValues[0]}) must match ${publicationSnapshot}`,
  );
  const expectedDigest = reviewAuditIdentity(auditDigest);
  check(
    digestValues[0] === expectedDigest,
    `${label} auditDigest (${digestValues[0]}) must match ${expectedDigest}`,
  );
  check(
    typeof snapshotValues[0] === 'string' && sha256HexRe.test(snapshotValues[0]),
    `${label} publicationSnapshot must be lowercase SHA-256 hex`,
  );
  check(
    digestValues[0] === reviewAuditUnavailable ||
      (typeof digestValues[0] === 'string' && sha256HexRe.test(digestValues[0])),
    `${label} auditDigest must be lowercase SHA-256 hex or unavailable`,
  );
  if (!allowFilterParams) {
    const queryNames = [...new Set(parsed.searchParams.keys())];
    check(
      queryNames.length === reviewPublicationBindingParams.size &&
        queryNames.every((name) => reviewPublicationBindingParams.has(name)),
      `${label} must not contain non-binding query parameters`,
    );
  }
  return valid;
}

function verifyAuditLinks({
  failures,
  tag,
  label,
  auditLinks,
  publicationSnapshot,
  auditDigest,
}) {
  verifyAllowedKeys({ failures, tag, label, value: auditLinks, allowed: auditLinkKeys });
  if (!isObject(auditLinks)) return null;
  let valid = true;
  for (const endpoint of auditLinkKeys) {
    valid = verifyPublishedReviewUrl({
      failures,
      tag,
      label: `${label}.${endpoint}`,
      value: auditLinks[endpoint],
      endpoint,
      publicationSnapshot,
      auditDigest,
    }) && valid;
  }
  expectJsonEqual(failures, tag, `${label} must point at release audit endpoints`,
    auditLinks, expectedAuditLinks(tag, publicationSnapshot, auditDigest));
  return valid ? auditLinks : null;
}

function resolvePublishedApiUrl(apiBase, value) {
  return new URL(value, `${apiBase}/`).toString();
}

function reviewUrlWithQuery(url, entries) {
  const parsed = new URL(url);
  for (const [name, value] of entries) {
    if (reviewPublicationBindingParams.has(name)) {
      throw new Error(`review query helper cannot override ${name}`);
    }
    parsed.searchParams.append(name, String(value));
  }
  return parsed.toString();
}

function verifyReviewPageBinding({
  failures,
  tag,
  label,
  page,
  endpoint,
  publicationSnapshot,
  auditDigest,
}) {
  verifyReleaseSnapshotId({
    failures,
    tag,
    label,
    snapshotId: page?.snapshotId,
    expectedSnapshotId: publicationSnapshot,
  });
  expect(
    failures,
    tag,
    page?.auditDigest === auditDigest,
    `${label} auditDigest (${page?.auditDigest}) must match ${auditDigest}`,
  );
  expect(
    failures,
    tag,
    page?.auditIdentity === reviewAuditIdentity(auditDigest),
    `${label} auditIdentity (${page?.auditIdentity}) must match ` +
      `${reviewAuditIdentity(auditDigest)}`,
  );
  verifyAllowedKeys({
    failures,
    tag,
    label: `${label} links`,
    value: page?.links,
    allowed: reviewPageLinkKeys,
  });
  if (!isObject(page?.links)) return;
  verifyPublishedReviewUrl({
    failures,
    tag,
    label: `${label} links.self`,
    value: page.links.self,
    endpoint,
    publicationSnapshot,
    auditDigest,
    allowFilterParams: true,
  });
  let self;
  try {
    self = new URL(page.links.self, 'https://radar.invalid');
  } catch {
    self = null;
  }
  if (self) {
    expect(
      failures,
      tag,
      self.searchParams.get('cursor') === String(page?.cursor),
      `${label} links.self cursor must match page cursor`,
    );
    expect(
      failures,
      tag,
      self.searchParams.get('limit') === String(page?.limit),
      `${label} links.self limit must match page limit`,
    );
  }
  if (page?.nextCursor == null) {
    expect(
      failures,
      tag,
      page.links.next == null,
      `${label} links.next must be null when nextCursor is null`,
    );
    return;
  }
  verifyPublishedReviewUrl({
    failures,
    tag,
    label: `${label} links.next`,
    value: page.links.next,
    endpoint,
    publicationSnapshot,
    auditDigest,
    allowFilterParams: true,
  });
  let next;
  try {
    next = new URL(page.links.next, 'https://radar.invalid');
  } catch {
    next = null;
  }
  if (next) {
    expect(
      failures,
      tag,
      next.searchParams.get('cursor') === String(page.nextCursor),
      `${label} links.next cursor must match nextCursor`,
    );
    expect(
      failures,
      tag,
      next.searchParams.get('limit') === String(page.limit),
      `${label} links.next limit must match page limit`,
    );
  }
}

function ageHoursAtScore(sourceAt, scoredAt) {
  if (!sourceAt || !scoredAt) return null;
  const sourceMs = Date.parse(sourceAt);
  const scoredMs = Date.parse(scoredAt);
  if (!Number.isFinite(sourceMs) || !Number.isFinite(scoredMs)) return null;
  return Math.round(((scoredMs - sourceMs) / 3_600_000) * 100) / 100;
}

function maxFreshnessTimestamp(values) {
  return values
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

function verifyNoForbiddenPublicKeys({ failures, tag, value, path = 'public release', forbidden = forbiddenPublicKeys }) {
  if (Array.isArray(value)) {
    value.forEach((item, idx) => verifyNoForbiddenPublicKeys({ failures, tag, value: item, path: `${path}[${idx}]`, forbidden }));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    expect(failures, tag, !forbidden.has(key),
      `${path} must not expose internal/comparison key ${key}`);
    verifyNoForbiddenPublicKeys({ failures, tag, value: child, path: `${path}.${key}`, forbidden });
  }
}

function verifyPublicIssueSummaries({ failures, tag, publicRelease }) {
  const issues = Array.isArray(publicRelease.issues) ? publicRelease.issues : [];
  const watchIssues = Array.isArray(publicRelease.watchIssues) ? publicRelease.watchIssues : [];
  for (const [name, rows] of [['issues', issues], ['watchIssues', watchIssues]]) {
    rows.forEach((issue, index) => {
      verifyAllowedKeys({
        failures,
        tag,
        label: `public ${name}[${index}]`,
        value: issue,
        allowed: publicIssueKeys,
      });
      expect(failures, tag, Number.isInteger(issue.number) && issue.number > 0,
        `public ${name}[${index}] must expose a positive issue number`);
      expect(failures, tag, typeof issue.title === 'string' && issue.title.length > 0,
        `public ${name}[${index}] must expose a title`);
      expect(failures, tag, typeof issue.url === 'string' && /^https:\/\/github\.com\//.test(issue.url),
        `public ${name}[${index}] must expose a GitHub URL`);
      expect(failures, tag, typeof issue.affectedUsers === 'string' && publicAffectedUsersRank.has(issue.affectedUsers),
        `public ${name}[${index}] must expose affectedUsers`);
    });
  }
  for (let i = 1; i < issues.length; i++) {
    expect(failures, tag, publicIssueSortKey(issues[i - 1]) <= publicIssueSortKey(issues[i]),
      'public issues must be sorted by effective sentiment/severity/scope');
  }
  expect(failures, tag, issues.length <= 25, 'public issues must stay capped at 25');
  expect(failures, tag, watchIssues.length <= 25, 'public watchIssues must stay capped at 25');
  for (let i = 1; i < watchIssues.length; i++) {
    expect(failures, tag, publicIssueSortKey(watchIssues[i - 1]) <= publicIssueSortKey(watchIssues[i]),
      'public watchIssues must be sorted by effective sentiment/severity/scope');
  }
  for (const issue of watchIssues) {
    expect(failures, tag, issue.state === 'open',
      `public watch issue #${issue.number} must be open`);
    expect(failures, tag, issue.sentiment === 'negative',
      `public watch issue #${issue.number} must be negative`);
    expect(failures, tag, issue.severity === 'critical' || issue.severity === 'high',
      `public watch issue #${issue.number} must be high/critical`);
  }
}

function verifyPublicProfileEvidence({ failures, tag, publicRelease }) {
  const evidence = publicRelease.profileEvidence;
  verifyAllowedKeys({ failures, tag, label: 'public profileEvidence', value: evidence, allowed: publicProfileEvidenceKeys });
  if (!isObject(evidence)) return;
  const scoreAudit = publicRelease.scoreAudit;
  const audited = isObject(scoreAudit);
  expect(failures, tag, evidence.schemaVersion === 2,
    `public profileEvidence schemaVersion (${evidence.schemaVersion}) must be 2`);
  expect(
    failures,
    tag,
    evidence.sourceMode === (
      audited ? 'sealed_score_replay' : 'current_diagnostic_evidence'
    ),
    `public profileEvidence sourceMode (${evidence.sourceMode}) must match ` +
      `${audited ? 'sealed score replay' : 'current diagnostic evidence'}`,
  );
  expect(failures, tag, evidence.issueEvidenceSchemaVersion === issueEvidenceSchemaVersion || evidence.issueEvidenceSchemaVersion == null,
    `public profileEvidence issueEvidenceSchemaVersion (${evidence.issueEvidenceSchemaVersion}) must match issue evidence schema`);
  expect(failures, tag, Number.isInteger(evidence.profileRowCount) && evidence.profileRowCount >= 0,
    'public profileEvidence profileRowCount must be a non-negative integer');
  expect(failures, tag, sha256HexRe.test(String(evidence.profileRowsDigest ?? '')),
    'public profileEvidence profileRowsDigest must be a lowercase SHA-256 digest');
  expect(failures, tag, Number(evidence.profileRowCount) >= Number(evidence.surfaceIssueCount ?? 0),
    'public profileEvidence profileRowCount must cover every surface issue');
  if (audited) {
    const binding = evidence.publicationBinding;
    verifyAllowedKeys({
      failures,
      tag,
      label: 'public profileEvidence publicationBinding',
      value: binding,
      allowed: publicProfileEvidencePublicationBindingKeys,
    });
    if (isObject(binding)) {
      expect(failures, tag, binding.schemaVersion === 1,
        'public profileEvidence publicationBinding schemaVersion must be 1');
      for (const [key, expected] of [
        ['auditDigest', scoreAudit.auditDigest],
        ['authorityRunId', scoreAudit.authorityRunId],
        ['authorityRunContentHash', scoreAudit.authorityRunContentHash],
        ['historyV2SealContentHash', scoreAudit.historyV2SealContentHash],
        ['scoreModelVersion', scoreAudit.modelVersion],
        ['promptVersion', scoreAudit.promptVersion],
        ['profileRowsDigest', evidence.profileRowsDigest],
      ]) {
        expect(
          failures,
          tag,
          binding[key] === expected,
          `public profileEvidence publicationBinding ${key} must match the ` +
            'sealed score summary',
        );
      }
      expect(failures, tag, sha256HexRe.test(String(binding.sourceIdentityDigest ?? '')),
        'public profileEvidence publicationBinding sourceIdentityDigest must be a lowercase SHA-256 digest');
      const { contentHash, ...content } = binding;
      const expectedContentHash = createHash('sha256')
        .update('release-profile-evidence-binding-v1\0')
        .update(stableJson(content))
        .digest('hex');
      expect(failures, tag, contentHash === expectedContentHash,
        'public profileEvidence publicationBinding contentHash must verify');
    }
  } else {
    expect(failures, tag, evidence.publicationBinding == null,
      'diagnostic public profileEvidence must not claim a sealed publication binding');
  }
  for (const key of ['issueCount', 'weightedIssueCount', 'surfaceIssueCount']) {
    expect(failures, tag, Number.isInteger(evidence[key]) && evidence[key] >= 0,
      `public profileEvidence ${key} must be a non-negative integer`);
  }
  expect(failures, tag, typeof evidence.surfaceWeight === 'number' && Number.isFinite(evidence.surfaceWeight) && evidence.surfaceWeight >= 0,
    'public profileEvidence surfaceWeight must be a non-negative number');
  expect(failures, tag, Array.isArray(evidence.surfaces),
    'public profileEvidence surfaces must be an array');
  let surfaceWeight = 0;
  for (const [index, surface] of (evidence.surfaces ?? []).entries()) {
    verifyAllowedKeys({ failures, tag, label: `public profileEvidence surfaces[${index}]`, value: surface, allowed: publicProfileEvidenceSurfaceKeys });
    expect(failures, tag, typeof surface.label === 'string' && surface.label.length > 0,
      `public profileEvidence surfaces[${index}] label must be present`);
    expect(failures, tag, typeof surface.icon === 'string' && surface.icon.length > 0,
      `public profileEvidence surfaces[${index}] icon must be present`);
    expect(failures, tag, Number.isInteger(surface.count) && surface.count > 0,
      `public profileEvidence surfaces[${index}] count must be positive`);
    expect(failures, tag, typeof surface.weight === 'number' && Number.isFinite(surface.weight) && surface.weight > 0,
      `public profileEvidence surfaces[${index}] weight must be positive`);
    expect(failures, tag, isObject(surface.tiers), `public profileEvidence surfaces[${index}] tiers must be an object`);
    expect(failures, tag, isObject(surface.weightByTier), `public profileEvidence surfaces[${index}] weightByTier must be an object`);
    surfaceWeight += Number(surface.weight ?? 0);
  }
  expect(failures, tag, Math.abs(Math.round(surfaceWeight * 1000) / 1000 - Number(evidence.surfaceWeight ?? 0)) <= 0.002,
    `public profileEvidence surfaceWeight (${evidence.surfaceWeight}) must equal summed surface weights (${surfaceWeight})`);
}

function publicIssueSortKey(issue) {
  return [
    publicSentimentRank.get(issue.sentiment) ?? 9,
    publicSeverityRank.get(issue.severity) ?? 9,
    publicScopeRank.get(issue.scope) ?? 9,
    publicAffectedUsersRank.get(issue.affectedUsers) ?? 9,
  ].join(':');
}

function verifyProofEvidenceShape({ failures, tag, row, evidence }) {
  expect(failures, tag, isObject(evidence),
    `proof issue #${row.issue_number} evidence_json must parse to an object`);
  if (!isObject(evidence)) return;

  if ('stateReasons' in evidence) {
    expect(failures, tag, isStringArray(evidence.stateReasons),
      `proof issue #${row.issue_number} stateReasons must be a string array`);
  }
  if ('closureEventClosedAt' in evidence) {
    expect(failures, tag, isStringArray(evidence.closureEventClosedAt),
      `proof issue #${row.issue_number} closureEventClosedAt must be a string array when present`);
    if (isStringArray(evidence.closureEventClosedAt) && evidence.closedAt) {
      const issueClosedAtMs = Date.parse(evidence.closedAt);
      for (const closedAt of evidence.closureEventClosedAt) {
        const eventClosedAtMs = Date.parse(closedAt);
        const closeDeltaSeconds = Number.isFinite(issueClosedAtMs) && Number.isFinite(eventClosedAtMs)
          ? Math.abs(issueClosedAtMs - eventClosedAtMs) / 1000
          : Infinity;
        expect(failures, tag, closeDeltaSeconds <= 2,
          `proof issue #${row.issue_number} closure event timestamp ${closedAt} must match issue closedAt ${evidence.closedAt}`);
      }
    }
  }
  for (const flag of ['hasReachableFixCommit', 'hasNotReachableFixCommit']) {
    expect(failures, tag, typeof evidence[flag] === 'boolean',
      `proof issue #${row.issue_number} ${flag} must be boolean`);
  }
  if ('hasUnknownFixCommit' in evidence) {
    expect(failures, tag, typeof evidence.hasUnknownFixCommit === 'boolean',
      `proof issue #${row.issue_number} hasUnknownFixCommit must be boolean when present`);
  }

  const reachableFixCommits = normalizeStringArray(evidence.reachableFixCommits);
  const notReachableFixCommits = normalizeStringArray(evidence.notReachableFixCommits);
  const unknownFixCommits = normalizeStringArray(evidence.unknownFixCommits);
  const targetReachableFixCommits = normalizeStringArray(evidence.targetReachableFixCommits);
  const targetNotReachableFixCommits = normalizeStringArray(evidence.targetNotReachableFixCommits);
  const targetUnknownFixCommits = normalizeStringArray(evidence.targetUnknownFixCommits);
  const predecessorContainedFixCommits =
    normalizeStringArray(evidence.predecessorContainedFixCommits);
  const firstContainingUnknownFixCommits =
    normalizeStringArray(evidence.firstContainingUnknownFixCommits);
  const firstContainingProofs = Array.isArray(evidence.directCommitFirstContainingProofs)
    ? evidence.directCommitFirstContainingProofs
    : [];
  const fixCommitProof = Array.isArray(evidence.fixCommitProof) ? evidence.fixCommitProof : [];
  const canonicalCommitProof = canonicalFixCommitProof(evidence);

  expect(failures, tag, Array.isArray(evidence.reachableFixCommits),
    `proof issue #${row.issue_number} reachableFixCommits must be an array`);
  expect(failures, tag, Array.isArray(evidence.notReachableFixCommits),
    `proof issue #${row.issue_number} notReachableFixCommits must be an array`);
  if ('unknownFixCommits' in evidence) {
    expect(failures, tag, Array.isArray(evidence.unknownFixCommits),
      `proof issue #${row.issue_number} unknownFixCommits must be an array when present`);
  }
  for (const name of [
    'targetReachableFixCommits',
    'targetNotReachableFixCommits',
    'targetUnknownFixCommits',
    'predecessorContainedFixCommits',
    'firstContainingUnknownFixCommits',
    'directCommitFirstContainingProofs',
  ]) {
    expect(failures, tag, Array.isArray(evidence[name]),
      `proof issue #${row.issue_number} ${name} must be an array`);
  }
  if (directUnknownFixCommitStatuses.has(row.status)) {
    expect(failures, tag, evidence.hasUnknownFixCommit === true,
      `proof issue #${row.issue_number} ${row.status} must set hasUnknownFixCommit`);
    expect(failures, tag, unknownFixCommits.length > 0,
      `proof issue #${row.issue_number} ${row.status} must include unknownFixCommits`);
  }
  expect(failures, tag, Array.isArray(evidence.fixCommitProof),
    `proof issue #${row.issue_number} fixCommitProof must be an array`);
  if ('canonicalFixCommitProof' in evidence) {
    expect(failures, tag, Array.isArray(evidence.canonicalFixCommitProof),
      `proof issue #${row.issue_number} canonicalFixCommitProof must be an array when present`);
  }
  if ('referencedCommitContext' in evidence) {
    expect(failures, tag, Array.isArray(evidence.referencedCommitContext),
      `proof issue #${row.issue_number} referencedCommitContext must be an array when present`);
  }

  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'reachableFixCommits', commits: reachableFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'notReachableFixCommits', commits: notReachableFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'unknownFixCommits', commits: unknownFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'targetReachableFixCommits', commits: targetReachableFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'targetNotReachableFixCommits', commits: targetNotReachableFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'targetUnknownFixCommits', commits: targetUnknownFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'predecessorContainedFixCommits', commits: predecessorContainedFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'firstContainingUnknownFixCommits', commits: firstContainingUnknownFixCommits });
  expect(failures, tag, intersection(reachableFixCommits, notReachableFixCommits).length === 0,
    `proof issue #${row.issue_number} reachable and not-reachable fix commit arrays must not overlap`);
  expect(failures, tag, intersection(reachableFixCommits, unknownFixCommits).length === 0 &&
    intersection(notReachableFixCommits, unknownFixCommits).length === 0,
  `proof issue #${row.issue_number} unknown fix commit arrays must not overlap reachable or not-reachable commits`);

  const proofReachable = [];
  const proofNotReachable = [];
  const proofUnknown = [];
  for (const proof of fixCommitProof) {
    expect(failures, tag, isObject(proof),
      `proof issue #${row.issue_number} fixCommitProof entries must be objects`);
    if (!isObject(proof)) continue;
    expect(failures, tag, proof.issueNumber === row.issue_number,
      `proof issue #${row.issue_number} fixCommitProof issueNumber (${proof.issueNumber}) must match proof row`);
    expect(failures, tag, Number.isInteger(proof.sourceIssueNumber) && proof.sourceIssueNumber > 0,
      `proof issue #${row.issue_number} fixCommitProof sourceIssueNumber must be a positive integer`);
    expect(failures, tag, typeof proof.commitOid === 'string' && fullCommitOidRe.test(proof.commitOid),
      `proof issue #${row.issue_number} fixCommitProof commitOid must be a full lowercase 40-hex SHA`);
    expect(failures, tag, knownCommitProofSources.has(proof.source),
      `proof issue #${row.issue_number} fixCommitProof has unknown source ${proof.source}`);
    expect(failures, tag, knownCommitProofStatuses.has(proof.status),
      `proof issue #${row.issue_number} fixCommitProof has unknown status ${proof.status}`);
    expect(failures, tag, proof.tagCommitOid == null || (typeof proof.tagCommitOid === 'string' && fullCommitOidRe.test(proof.tagCommitOid)),
      `proof issue #${row.issue_number} fixCommitProof tagCommitOid must be null or full lowercase 40-hex SHA`);
    expect(failures, tag, typeof proof.evidence === 'string' && proof.evidence.length > 0,
      `proof issue #${row.issue_number} fixCommitProof evidence must be present`);
    expect(failures, tag, typeof proof.snippet === 'string' && proof.snippet.length > 0,
      `proof issue #${row.issue_number} fixCommitProof snippet must be present`);
    if (proof.source === 'ClosureComment.fixProof') {
      expect(failures, tag, proof.trustedSource === true,
        `proof issue #${row.issue_number} closure-comment commit proof must come from a trusted source`);
      expect(failures, tag, typeof proof.author === 'string' && proof.author.length > 0,
        `proof issue #${row.issue_number} closure-comment commit proof must record an author`);
    }
    if (proof.status === 'reachable' && typeof proof.commitOid === 'string') proofReachable.push(proof.commitOid);
    if (proof.status === 'not_reachable' && typeof proof.commitOid === 'string') proofNotReachable.push(proof.commitOid);
    if (proof.status === 'unknown' && typeof proof.commitOid === 'string') proofUnknown.push(proof.commitOid);
  }
  const firstContainingCredited = [];
  const firstContainingPredecessorContained = [];
  const firstContainingUnknown = [];
  const firstContainingCommitOids = [];
  for (const proof of firstContainingProofs) {
    expect(failures, tag, isObject(proof),
      `proof issue #${row.issue_number} directCommitFirstContainingProofs entries must be objects`);
    if (!isObject(proof)) continue;
    const targetCommitOid = normalizeAuditOid(proof.target?.tagCommitOid);
    const predecessorCommitOid =
      normalizeAuditOid(proof.predecessor?.tagCommitOid) ??
      normalizeAuditOid(proof.releaseAncestry?.checkedCommitOid);
    const predecessorTag = typeof proof.predecessorTag === 'string'
      ? proof.predecessorTag
      : '';
    if (!targetCommitOid || !predecessorCommitOid || !predecessorTag) {
      expect(failures, tag, false,
        `proof issue #${row.issue_number} direct first-containing proof must bind target and predecessor release commits`);
      continue;
    }
    const normalized = expectedDirectCommitProofIdentity(
      proof,
      tag,
      predecessorTag,
      { valid: true, targetCommitOid, predecessorCommitOid },
    );
    expect(failures, tag, normalized.strictValid,
      `proof issue #${row.issue_number} direct first-containing proof ${normalized.commitOid} must be strictly valid`);
    if (!fullCommitOidRe.test(normalized.commitOid)) continue;
    firstContainingCommitOids.push(normalized.commitOid);
    if (normalized.strictValid && normalized.creditEligible) {
      firstContainingCredited.push(normalized.commitOid);
    } else if (
      normalized.strictValid &&
      normalized.reasonCode === 'predecessor_contains_commit'
    ) {
      firstContainingPredecessorContained.push(normalized.commitOid);
    } else if (
      normalized.strictValid &&
      normalized.reasonCode !== 'target_commit_not_reachable'
    ) {
      firstContainingUnknown.push(normalized.commitOid);
    }
  }
  for (const proof of canonicalCommitProof) {
    expect(failures, tag, isObject(proof),
      `proof issue #${row.issue_number} canonicalFixCommitProof entries must be objects`);
    if (!isObject(proof)) continue;
    expect(failures, tag, proof.issueNumber === row.issue_number,
      `proof issue #${row.issue_number} canonicalFixCommitProof issueNumber (${proof.issueNumber}) must match proof row`);
    expect(failures, tag, Number.isInteger(proof.sourceIssueNumber) && proof.sourceIssueNumber > 0 && proof.sourceIssueNumber !== row.issue_number,
      `proof issue #${row.issue_number} canonicalFixCommitProof sourceIssueNumber must be a different positive integer`);
    expect(failures, tag, typeof proof.commitOid === 'string' && fullCommitOidRe.test(proof.commitOid),
      `proof issue #${row.issue_number} canonicalFixCommitProof commitOid must be a full lowercase 40-hex SHA`);
    expect(failures, tag, knownCommitProofStatuses.has(proof.status),
      `proof issue #${row.issue_number} canonicalFixCommitProof has unknown status ${proof.status}`);
  }
  for (const ref of Array.isArray(evidence.referencedCommitContext) ? evidence.referencedCommitContext : []) {
    expect(failures, tag, isObject(ref),
      `proof issue #${row.issue_number} referencedCommitContext entries must be objects`);
    if (!isObject(ref)) continue;
    expect(failures, tag, ref.issueNumber === row.issue_number,
      `proof issue #${row.issue_number} referencedCommitContext issueNumber (${ref.issueNumber}) must match proof row`);
    expect(failures, tag, Number.isInteger(ref.sourceIssueNumber) && ref.sourceIssueNumber > 0,
      `proof issue #${row.issue_number} referencedCommitContext sourceIssueNumber must be a positive integer`);
    expect(failures, tag, typeof ref.commitOid === 'string' && fullCommitOidRe.test(ref.commitOid),
      `proof issue #${row.issue_number} referencedCommitContext commitOid must be a full lowercase 40-hex SHA`);
    expect(failures, tag, ref.source === 'ReferencedEvent.commit',
      `proof issue #${row.issue_number} referencedCommitContext source must be ReferencedEvent.commit`);
    expect(failures, tag, !('status' in ref),
      `proof issue #${row.issue_number} referencedCommitContext must not carry reachability status or fix credit`);
  }

  const creditableProofCommits = uniqueSorted(fixCommitProof
    .filter((proof) => isObject(proof) && proof.creditEligible !== false)
    .map((proof) => proof.commitOid)
    .filter((commitOid) => typeof commitOid === 'string' && fullCommitOidRe.test(commitOid)));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} directCommitFirstContainingProofs`, uniqueSorted(firstContainingCommitOids), creditableProofCommits);
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} targetReachableFixCommits`, targetReachableFixCommits, uniqueSorted(proofReachable));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} targetNotReachableFixCommits`, targetNotReachableFixCommits, uniqueSorted(proofNotReachable));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} targetUnknownFixCommits`, targetUnknownFixCommits, uniqueSorted(proofUnknown));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} reachableFixCommits`, reachableFixCommits, uniqueSorted(firstContainingCredited));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} notReachableFixCommits`, notReachableFixCommits, uniqueSorted(proofNotReachable));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} predecessorContainedFixCommits`, predecessorContainedFixCommits, uniqueSorted(firstContainingPredecessorContained));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} firstContainingUnknownFixCommits`, firstContainingUnknownFixCommits, uniqueSorted(firstContainingUnknown));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} unknownFixCommits`, unknownFixCommits, uniqueSorted([
    ...proofUnknown,
    ...firstContainingUnknown,
  ]));
  expect(failures, tag, evidence.hasReachableFixCommit === (reachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasReachableFixCommit must match reachableFixCommits`);
  expect(failures, tag, evidence.hasNotReachableFixCommit === (notReachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasNotReachableFixCommit must match notReachableFixCommits`);
  if ('hasUnknownFixCommit' in evidence || 'unknownFixCommits' in evidence) {
    expect(failures, tag, evidence.hasUnknownFixCommit === (unknownFixCommits.length > 0),
      `proof issue #${row.issue_number} hasUnknownFixCommit must match unknownFixCommits`);
  }
}

function canonicalFixCommitProof(evidence) {
  return Array.isArray(evidence?.canonicalFixCommitProof) ? evidence.canonicalFixCommitProof : [];
}

function linkedClosingPrEvidence(evidence) {
  const linkedPrs = Array.isArray(evidence?.linkedPrs) ? evidence.linkedPrs : [];
  return linkedPrs.filter((pr) => {
    const source = String(pr?.source ?? '');
    return Number(pr?.willCloseTarget ?? 0) === 1 ||
      source === 'closedByPullRequestsReferences' ||
      source === 'ClosedEvent.closer';
  });
}

function linkedMergedPrEvidence(evidence) {
  const linkedPrs = Array.isArray(evidence?.linkedPrs) ? evidence.linkedPrs : [];
  return linkedPrs.filter((pr) => Number(pr?.merged ?? 0) === 1);
}

function relatedPrContext(evidence) {
  const context = evidence?.relatedPrContext && typeof evidence.relatedPrContext === 'object'
    ? evidence.relatedPrContext
    : {};
  return {
    externalClosing: Array.isArray(context.externalClosing) ? context.externalClosing : [],
    open: Array.isArray(context.open) ? context.open : [],
    closedUnmerged: Array.isArray(context.closedUnmerged) ? context.closedUnmerged : [],
    notReachable: Array.isArray(context.notReachable) ? context.notReachable : [],
    reachable: Array.isArray(context.reachable) ? context.reachable : [],
    unknownReachability: Array.isArray(context.unknownReachability) ? context.unknownReachability : [],
  };
}

function trustedReachableFixProofPrs(evidence) {
  return relatedPrContext(evidence).reachable.filter((pr) =>
    String(pr?.source ?? '') === 'ClosureComment.fixProof' &&
    String(pr?.repositoryNameWithOwner ?? '').toLowerCase() === 'openclaw/openclaw');
}

function canonicalFixedAfterRelease(evidence) {
  const terminalProof = evidence?.canonicalResolution?.terminalProof;
  return terminalProof?.status === 'fixed_after_release' ||
    (terminalProof?.crossRelease === true &&
      terminalProof?.timing === 'after' &&
      ['fixed_in_release', 'fixed_after_release'].includes(terminalProof?.status)) ||
    canonicalFixCommitProof(evidence).some((proof) => proof.status === 'not_reachable');
}

function verifyAfterLatestFixProof({ failures, tag, row, evidence, latestScoredStableRelease }) {
  const proof = evidence?.unscoredFixProof;
  expect(failures, tag, proof?.latestScoredReleaseTag === latestScoredStableRelease?.tag,
    `${row.status} issue #${row.issue_number} must name latest scored stable release ${latestScoredStableRelease?.tag ?? 'unknown'}`);
  const proofMs = proof?.proofTime ? Date.parse(proof.proofTime) : NaN;
  const latestPublishedMs = proof?.latestScoredReleasePublishedAt ? Date.parse(proof.latestScoredReleasePublishedAt) : NaN;
  expect(failures, tag, Number.isFinite(proofMs) && Number.isFinite(latestPublishedMs) && proofMs > latestPublishedMs,
    `${row.status} issue #${row.issue_number} must have proofTime after latest scored stable published_at`);
  expect(failures, tag, proof?.proofType === 'pr' ? Number.isInteger(Number(proof.prNumber)) && Number(proof.prNumber) > 0 : fullCommitOidRe.test(String(proof?.commitOid ?? '')),
    `${row.status} issue #${row.issue_number} must include a PR number or full commit OID for after-latest proof`);
  expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
    `${row.status} issue #${row.issue_number} must include not-reachable PR or commit evidence`);
}

function expectNonNegativeProof({ failures, tag, row }) {
  const classification = effectiveClassificationForProofRow(row);
  expect(failures, tag, classification.sentiment !== 'negative',
    `${row.status} issue #${row.issue_number} must not be effectively negative`);
}

function verifyCommitArray({ failures, tag, issueNumber, name, commits }) {
  for (const commit of commits) {
    expect(failures, tag, fullCommitOidRe.test(commit),
      `proof issue #${issueNumber} ${name} entries must be full lowercase 40-hex SHAs`);
  }
  expectArrayEqual(failures, tag, `proof issue #${issueNumber} ${name}`, commits, uniqueSorted(commits));
}

function parseJson(raw, fallback) {
  try {
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function scorePublicationFailuresForAudit(reader, publication) {
  const failures = Array.isArray(publication?.failures)
    ? publication.failures.filter((failure) => typeof failure === 'string')
    : [];
  const compatibleLegacyFailures = compatibleLegacyForecastManifestFailures(reader);
  if (compatibleLegacyFailures.size === 0) return failures;
  return failures.filter((failure) => !compatibleLegacyFailures.has(failure));
}

function compatibleLegacyForecastManifestFailures(reader) {
  if (!reader?.db || typeof reader.db.prepare !== 'function') return new Set();
  let forecasts;
  let historyRows;
  try {
    forecasts = reader.db.prepare(`
      SELECT decision_id, audit_history_run_id, opportunity_code, recorded_at,
             latest_release_published_at, decision_json, source_identity_json
      FROM release_validation_forecasts
      ORDER BY id
    `).all();
    historyRows = reader.db.prepare(`
      SELECT run_id, release_tag, source_identity_json
      FROM release_score_audit_history
      ORDER BY run_id, release_tag
    `).all();
  } catch {
    return new Set();
  }

  const historyByRun = new Map();
  for (const row of historyRows) {
    const rows = historyByRun.get(row.run_id) ?? [];
    rows.push(row);
    historyByRun.set(row.run_id, rows);
  }
  const compatibleFailures = new Set();
  for (const forecast of forecasts) {
    const decision = parseJson(forecast.decision_json, {});
    const timing = releaseValidationForecastTiming(forecast);
    const legacyExcluded = Number(decision?.schemaVersion ?? 2) < 3 &&
      (timing.reason === 'before_window' || timing.reason === 'after_window');
    if (!legacyExcluded) continue;

    const forecastAssessment = scoreSourceManifestAssessment(forecast.source_identity_json);
    if (forecastAssessment.obsoleteStructurallyValid) {
      compatibleFailures.add(
        `forecast ${forecast.decision_id} has invalid source provenance: ` +
        forecastAssessment.strictProblems.join(', '),
      );
    }
    for (const historyRow of historyByRun.get(forecast.audit_history_run_id) ?? []) {
      const historyAssessment = scoreSourceManifestAssessment(historyRow.source_identity_json);
      if (!historyAssessment.obsoleteStructurallyValid) continue;
      compatibleFailures.add(
        `forecast ${forecast.decision_id} references invalid history provenance ` +
        `${historyRow.run_id}/${historyRow.release_tag}: ` +
        historyAssessment.strictProblems.join(', '),
      );
    }
  }
  return compatibleFailures;
}

function scoreSourceManifestAssessment(raw) {
  const manifest = parseJson(raw, null);
  const strictProblems = scoreSourceIdentityManifestProblems(manifest);
  const obsoleteProblems = obsoleteScoreSourceManifestStructuralProblems(manifest);
  return {
    strictProblems,
    obsoleteStructurallyValid:
      strictProblems.length > 0 && obsoleteProblems.length === 0,
  };
}

function obsoleteScoreSourceManifestStructuralProblems(manifest) {
  if (!isObject(manifest)) return ['manifest must be an object'];
  const problems = [];
  const expectedManifestKeys = [
    'schemaVersion',
    'sourceMode',
    'scope',
    'algorithm',
    'rowCount',
    'sourceCount',
    'digest',
    'sources',
  ].sort();
  if (stableJson(Object.keys(manifest).sort()) !== stableJson(expectedManifestKeys)) {
    problems.push(`manifest keys must equal ${expectedManifestKeys.join(', ')}`);
  }
  const schemaVersion = Number(manifest.schemaVersion);
  if (!Number.isInteger(schemaVersion) || schemaVersion <= 0 ||
    schemaVersion >= SCORE_SOURCE_IDENTITY_SCHEMA_VERSION) {
    problems.push(
      `schemaVersion must be an obsolete positive integer below ` +
      `${SCORE_SOURCE_IDENTITY_SCHEMA_VERSION}`,
    );
  }
  if (manifest.sourceMode !== 'current_db') problems.push('sourceMode must equal current_db');
  if (manifest.scope !== 'score_input_database') problems.push('scope must equal score_input_database');
  if (manifest.algorithm !== 'sha256') problems.push('algorithm must equal sha256');
  if (!Number.isInteger(manifest.rowCount) || Number(manifest.rowCount) < 0) {
    problems.push('rowCount must be a non-negative integer');
  }
  if (!Number.isInteger(manifest.sourceCount) || Number(manifest.sourceCount) < 0) {
    problems.push('sourceCount must be a non-negative integer');
  }
  if (typeof manifest.digest !== 'string' || !/^[0-9a-f]{64}$/.test(manifest.digest)) {
    problems.push('digest must be a lowercase SHA-256 hex string');
  }
  if (!Array.isArray(manifest.sources)) {
    problems.push('sources must be an array');
    return problems;
  }

  const sourceNames = [];
  let rowCount = 0;
  for (let index = 0; index < manifest.sources.length; index++) {
    const source = manifest.sources[index];
    if (!isObject(source)) {
      problems.push(`sources[${index}] must be an object`);
      continue;
    }
    if (stableJson(Object.keys(source).sort()) !== stableJson(['count', 'digest', 'source'])) {
      problems.push(`sources[${index}] keys must equal source, count, digest`);
    }
    if (typeof source.source !== 'string' || !source.source) {
      problems.push(`sources[${index}].source must be a non-empty string`);
    } else {
      sourceNames.push(source.source);
    }
    if (!Number.isInteger(source.count) || Number(source.count) < 0) {
      problems.push(`sources[${index}].count must be a non-negative integer`);
    } else {
      rowCount += Number(source.count);
    }
    if (typeof source.digest !== 'string' || !/^[0-9a-f]{64}$/.test(source.digest)) {
      problems.push(`sources[${index}].digest must be a lowercase SHA-256 hex string`);
    }
  }
  if (manifest.sourceCount !== manifest.sources.length) {
    problems.push(`sourceCount must equal sources.length (${manifest.sources.length})`);
  }
  if (manifest.rowCount !== rowCount) {
    problems.push(`rowCount must equal the sum of source counts (${rowCount})`);
  }
  if (new Set(sourceNames).size !== sourceNames.length) {
    problems.push('sources must not contain duplicate source names');
  }
  if (problems.length === 0) {
    const digest = scoreSourceIdentityManifestDigest(manifest.sources, schemaVersion);
    if (manifest.digest !== digest) {
      problems.push('digest does not match the ordered source manifest');
    }
  }
  return problems;
}

export const __releaseAuditInvariantTest = {
  collectExhaustiveAuditPages,
  expectedAuditLinks,
  expectedDirectCommitProofIdentity,
  expectedFixCreditDecisionOutcome,
  reviewUrlWithQuery,
  scoreModelSupportsCapability,
  scorePublicationFailuresForAudit,
  verifyAuditLinks,
};

function riskDispositionForStatus(status) {
  return riskDispositionByProofStatus.get(status) ?? 'missing_evidence';
}

function riskDispositionCountsForProofRows(proofRows) {
  const counts = {};
  for (const row of proofRows) {
    const disposition = riskDispositionForStatus(row.status);
    counts[disposition] = (counts[disposition] ?? 0) + 1;
  }
  return counts;
}

function riskSummaryFromCounts(counts, neutralAuditCounts = { highImpact: 0, bugShaped: 0 }) {
  const summary = {
    creditedReleaseFixCount: counts.credited_release_fix ?? 0,
    resolvedByCanonicalReleaseFixCount: counts.resolved_by_canonical_release_fix ?? 0,
    resolvedByReleaseFixProofCount: counts.resolved_by_release_fix_proof ?? 0,
    knownNotInReleaseCount: counts.known_not_in_release ?? 0,
    openCanonicalRiskCount: counts.open_canonical_risk ?? 0,
    unsupportedClosureClaimCount: counts.unsupported_closure_claim ?? 0,
    neutralOrNonActionableCount: counts.neutral_or_non_actionable ?? 0,
    neutralHighImpactCount: neutralAuditCounts.highImpact ?? 0,
    neutralBugShapedCount: neutralAuditCounts.bugShaped ?? 0,
    missingEvidenceCount: counts.missing_evidence ?? 0,
  };
  return {
    ...summary,
    unresolvedForReleaseCount: summary.knownNotInReleaseCount +
      summary.openCanonicalRiskCount +
      summary.unsupportedClosureClaimCount +
      summary.missingEvidenceCount,
    unresolvedWeightedRisk: 0,
    weightedRiskByDisposition: {},
  };
}

function riskSummaryForProofRows(proofRows, fixCreditResult = null) {
  const counts = riskDispositionCountsForProofRows(proofRows);
  const neutralAuditCounts = neutralAuditSignalCountsForProofRows(proofRows);
  const summary = riskSummaryFromCounts(counts, neutralAuditCounts);
  const containedReleaseFixCount = Number(counts.credited_release_fix ?? 0);
  const creditedReleaseFixCount = fixCreditResult?.creditedCount ?? containedReleaseFixCount;
  const aggregated = aggregateClosureRisk(proofRows.map((row) => ({
    issueNumber: Number(row.issue_number),
    disposition: riskDispositionForStatus(row.status),
    weight: closureRiskWeightForProofRow(row),
    duplicateCluster: row.duplicate_cluster ?? null,
    canonicalIssueNumber: canonicalIssueNumberForProofRow(row),
  })));
  return {
    counts,
    summary: {
      ...summary,
      creditedReleaseFixCount,
      containedReleaseFixCount,
      containedWithoutFirstCreditCount:
        containedReleaseFixCount - creditedReleaseFixCount,
      unresolvedForReleaseCount: aggregated.unresolvedForReleaseCount,
      unresolvedWeightedRisk: roundMetric(aggregated.unresolvedWeightedRisk),
      weightedRiskByDisposition: roundRiskMap(aggregated.weightedRiskByDisposition),
    },
  };
}

function canonicalIssueNumberForProofRow(row) {
  const evidence = parseJson(row?.evidence_json, {});
  const number = Number(evidence?.canonicalResolution?.terminalIssue?.number);
  return Number.isInteger(number) && number > 0 ? number : null;
}

function neutralAuditSignalCountsForProofRows(proofRows) {
  let highImpact = 0;
  let bugShaped = 0;
  for (const row of proofRows) {
    if (riskDispositionForStatus(row.status) !== 'neutral_or_non_actionable') continue;
    const classification = effectiveClassificationForProofRow(row);
    if (classification.sentiment !== 'neutral') continue;
    if (classification.severity === 'high' || classification.severity === 'critical') highImpact++;
    if (bugShapedTitleRe.test(row.title ?? '')) bugShaped++;
  }
  return { highImpact, bugShaped };
}

function closureRiskWeightForProofRow(row) {
  const disposition = riskDispositionForStatus(row.status);
  const dispositionWeight = riskDispositionWeights.get(disposition) ?? 0;
  if (dispositionWeight <= 0) return 0;
  return dispositionWeight * closureRiskClassificationWeightForProofRow(row);
}

function closureRiskClassificationWeightForProofRow(row) {
  const classification = effectiveClassificationForProofRow(row);
  if (classification.sentiment !== 'negative') return 0;
  const severity = severityRiskWeights.get(classification.severity) ?? 0;
  const functionality = functionalityRiskWeights.get(classification.functionality) ?? 0;
  if (severity <= 0 || functionality <= 0) return 0;
  return severity *
    functionality *
    (scopeRiskWeights.get(classification.scope) ?? 1) *
    (affectedUserRiskWeights.get(classification.affectedUsers ?? 'unknown') ?? affectedUserRiskWeights.get('unknown'));
}

function effectiveClassificationForProofRow(row) {
  const labels = Array.isArray(row.effective_labels)
    ? row.effective_labels.filter((label) => typeof label === 'string')
    : [];
  return applyClosureRiskSentimentHint(
    applyTitleIssueShapeHint(
      applyLabelOverrides(
        applyTitleFunctionalityHint(rawClassificationForProofRow(row), row.title ?? ''),
        labels,
      ),
      row.title ?? '',
      labels,
    ),
    row.title ?? '',
    labels,
  );
}

function rawClassificationForProofRow(row) {
  const workaroundStatus = ['none', 'partial', 'confirmed', 'unknown'].includes(row.workaround_status ?? '')
    ? row.workaround_status
    : row.has_workaround === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment,
    severity: row.severity,
    scope: row.scope,
    functionality: row.functionality,
    affectedUsers: row.affected_users,
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster ?? null,
    affectsVersion: row.affects_version ?? null,
    confidence: typeof row.confidence === 'number' ? row.confidence : 0.5,
    rationale: row.rationale ?? '',
  };
}

function roundRiskMap(map) {
  const rounded = {};
  for (const [key, value] of Object.entries(map)) {
    const roundedValue = roundMetric(Number(value ?? 0));
    if (roundedValue > 0) rounded[key] = roundedValue;
  }
  return rounded;
}

function roundMetric(value) {
  return Math.round(Number(value ?? 0) * 1000) / 1000;
}

function expect(failures, tag, condition, message) {
  if (!condition) failures.push(`${tag}: ${message}`);
}

function verifyRecommendedReleaseInvariant({ failures, releases }) {
  const actualRecommendedTags = releases
    .filter((release) => release.recommended === true || Number(release.recommended ?? 0) === 1)
    .map((release) => release.tag);
  const expectedRecommendedTag = selectRecommendation(releases.map((release) => ({
    tag: release.tag,
    status: String(release.state ?? release.status ?? ''),
    score: releaseScoreValue(release),
  }))).selectedTag;
  const expectedRecommendedTags = expectedRecommendedTag ? [expectedRecommendedTag] : [];
  expect(failures, 'recommendation', stableJson(actualRecommendedTags) === stableJson(expectedRecommendedTags),
    `recommended release tags (${JSON.stringify(actualRecommendedTags)}) must match confidence-ranked eligible policy at threshold ${REC_THRESHOLD} (${JSON.stringify(expectedRecommendedTags)})`);
}

function releaseScoreValue(release) {
  const value = release.final_score ?? release.score ?? null;
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function expectArrayEqual(failures, tag, label, actual, expected) {
  expect(failures, tag, actual.length === expected.length && actual.every((item, idx) => item === expected[idx]),
    `${label} must equal sorted unique proof commits; got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

function expectJsonEqual(failures, tag, message, actual, expected) {
  expect(failures, tag, stableJson(actual) === stableJson(expected), message);
}

function stableJson(value) {
  return JSON.stringify(sortJson(value));
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key])]));
}

function isObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function normalizeStringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function intersection(left, right) {
  const rightSet = new Set(right);
  return left.filter((item) => rightSet.has(item));
}

const concreteNonActionableRationaleRe =
  /\b(won't fix|wont fix|expected behavior|working as intended|by design|outside\s+(?:the\s+)?OpenClaw\s+source|outside\s+(?:the\s+)?(?:repo|repository)|repo(?:sitory)?\s+boundary|plugin-owned|not\s+present\s+in\s+(?:the\s+)?OpenClaw\s+source|not\s+actionable|out\s+of\s+scope|unsupported)\b/i;

function isNegativeBareNotPlannedNeutral(row, evidence) {
  if (riskDispositionForStatus(row.status) !== 'neutral_or_non_actionable') return false;
  if (row.status !== 'not_planned') return false;
  const classification = effectiveClassificationForProofRow(row);
  if (classification.sentiment !== 'negative') return false;
  if (!Array.isArray(evidence.stateReasons) || !evidence.stateReasons.includes('NOT_PLANNED')) return false;
  return !hasConcreteNonActionableRationale(evidence);
}

function hasConcreteNonActionableRationale(evidence) {
  if (Array.isArray(evidence.nonActionableRationaleComments) && evidence.nonActionableRationaleComments.length > 0) {
    return true;
  }
  const comments = Array.isArray(evidence.matchingComments) ? evidence.matchingComments : [];
  return comments.some((comment) => concreteNonActionableRationaleRe.test(String(comment?.snippet ?? '')));
}

function scoreModelRiskContract(modelVersion, scoreInput) {
  if (scoreModelSupportsCapability(modelVersion, 'exclusiveRiskLedger')) {
    return {
      exclusiveRiskLedger: true,
      affirmativeClosureRiskCeiling: scoreModelSupportsCapability(
        modelVersion,
        'affirmativeClosureRiskCeiling',
      ),
    };
  }
  if (
    modelVersion == null &&
    scoreInput?.schemaVersion === SCORE_INPUT_SCHEMA_VERSION &&
    Object.prototype.hasOwnProperty.call(
      scoreInput,
      'affirmativeClosureRiskCeilingWeight',
    )
  ) {
    return {
      exclusiveRiskLedger: true,
      affirmativeClosureRiskCeiling: true,
    };
  }
  return null;
}

function scoreModelSupportsCapability(modelVersion, capability) {
  const minimumVersion = scoreModelCapabilityMinimumVersion[capability];
  const version = scoreModelEvidenceVersion(modelVersion);
  return Number.isInteger(minimumVersion) && version != null && version >= minimumVersion;
}

function scoreModelEvidenceVersion(modelVersion) {
  if (typeof modelVersion !== 'string') return null;
  const match = /^evidence-v(\d+)(?:-|$)/.exec(modelVersion);
  if (!match) return null;
  const version = Number(match[1]);
  return Number.isSafeInteger(version) ? version : null;
}

function verifyValidationOpportunityStatus({ failures, opportunityStatus }) {
  const tag = 'api/validation/opportunities';
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity payload',
    value: opportunityStatus,
    allowed: validationOpportunityPayloadKeys,
  });
  expect(failures, tag,
    opportunityStatus.schemaVersion === validationOpportunityPayloadSchemaVersion,
    `schemaVersion must be ${validationOpportunityPayloadSchemaVersion}, got ${JSON.stringify(opportunityStatus.schemaVersion)}`);
  const asOfMs = Date.parse(opportunityStatus.asOf);
  expect(failures, tag, Number.isFinite(asOfMs),
    `asOf must be a valid timestamp, got ${opportunityStatus.asOf}`);

  const latestRelease = opportunityStatus.latestRelease;
  expect(failures, tag, latestRelease == null || isObject(latestRelease),
    'latestRelease must be an object or null');
  if (isObject(latestRelease)) {
    verifyAllowedKeys({
      failures,
      tag,
      label: 'validation opportunity latestRelease',
      value: latestRelease,
      allowed: validationOpportunityLatestReleaseKeys,
    });
    const publishedAtMs = Date.parse(latestRelease.publishedAt);
    expect(failures, tag, typeof latestRelease.tag === 'string' && latestRelease.tag.length > 0,
      'latestRelease tag must be present');
    expect(failures, tag, Number.isFinite(publishedAtMs),
      `latestRelease publishedAt must be a valid timestamp, got ${latestRelease.publishedAt}`);
    expect(failures, tag,
      Number.isFinite(latestRelease.ageMs) && latestRelease.ageMs >= 0,
      `latestRelease ageMs must be non-negative, got ${latestRelease.ageMs}`);
    expect(failures, tag,
      Number.isFinite(latestRelease.ageHours) && latestRelease.ageHours >= 0,
      `latestRelease ageHours must be non-negative, got ${latestRelease.ageHours}`);
    if (Number.isFinite(asOfMs) && Number.isFinite(publishedAtMs)) {
      expect(failures, tag, latestRelease.ageMs === asOfMs - publishedAtMs,
        'latestRelease ageMs must match asOf minus publishedAt');
      expect(failures, tag,
        Math.abs(latestRelease.ageHours - latestRelease.ageMs / 3_600_000) < 1e-9,
        'latestRelease ageHours must match ageMs');
    }
  }

  const currentSeries = opportunityStatus.currentSeries;
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity currentSeries',
    value: currentSeries,
    allowed: validationOpportunityCurrentSeriesKeys,
  });
  expect(failures, tag, typeof currentSeries?.key === 'string' && currentSeries.key.length > 0,
    'currentSeries key must be present');
  expect(failures, tag,
    typeof currentSeries?.modelVersion === 'string' && currentSeries.modelVersion.length > 0,
    'currentSeries modelVersion must be present');
  expect(failures, tag, Number.isInteger(currentSeries?.promptVersion),
    'currentSeries promptVersion must be an integer');
  expect(failures, tag,
    typeof currentSeries?.codeRevision === 'string' && currentSeries.codeRevision.length > 0,
    'currentSeries codeRevision must be present');
  for (const field of ['ledgerForecastCount', 'enrolledOpportunityCount']) {
    expect(failures, tag, Number.isInteger(currentSeries?.[field]) && currentSeries[field] >= 0,
      `currentSeries ${field} must be a non-negative integer`);
  }

  const currentAudit = opportunityStatus.currentAudit;
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity currentAudit',
    value: currentAudit,
    allowed: validationOpportunityCurrentAuditKeys,
  });
  expect(failures, tag, typeof currentAudit?.present === 'boolean',
    'currentAudit present must be boolean');
  expect(failures, tag, typeof currentAudit?.current === 'boolean',
    'currentAudit current must be boolean');
  if (currentAudit?.present) {
    expect(failures, tag,
      typeof currentAudit.scoreModelVersion === 'string' &&
        currentAudit.scoreModelVersion.length > 0,
      'present currentAudit scoreModelVersion must be present');
    expect(failures, tag, Number.isInteger(currentAudit.promptVersion),
      'present currentAudit promptVersion must be an integer');
    expect(failures, tag, Number.isFinite(Date.parse(currentAudit.scoredAt)),
      'present currentAudit scoredAt must be a valid timestamp');
  } else if (isObject(currentAudit)) {
    expect(failures, tag,
      currentAudit.scoreModelVersion == null &&
        currentAudit.promptVersion == null &&
        currentAudit.scoredAt == null,
      'absent currentAudit identity fields must be null');
  }
  if (currentAudit?.current) {
    expect(failures, tag,
      currentAudit.present === true &&
        currentAudit.scoreModelVersion === currentSeries?.modelVersion &&
        currentAudit.promptVersion === currentSeries?.promptVersion,
      'current currentAudit must match currentSeries');
  }

  const counts = opportunityStatus.counts;
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity counts',
    value: counts,
    allowed: validationOpportunityCountKeys,
  });
  for (const field of validationOpportunityCountKeys) {
    expect(failures, tag, Number.isInteger(counts?.[field]) && counts[field] >= 0,
      `validation opportunity counts.${field} must be a non-negative integer`);
  }

  const denominator = opportunityStatus.denominatorLedger;
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity denominatorLedger',
    value: denominator,
    allowed: validationOpportunityDenominatorKeys,
  });
  expect(failures, tag,
    denominator?.schemaVersion === RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SCHEMA_VERSION,
    `denominatorLedger schemaVersion must be ${RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SCHEMA_VERSION}`);
  expect(failures, tag,
    denominator?.sourcePolicy === RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SOURCE_POLICY,
    `denominatorLedger sourcePolicy must be ${RELEASE_VALIDATION_OPPORTUNITY_DENOMINATOR_SOURCE_POLICY}`);
  expect(failures, tag,
    typeof denominator?.contentHash === 'string' && sha256HexRe.test(denominator.contentHash),
    'denominatorLedger contentHash must be a lowercase SHA-256 hex string');
  expect(failures, tag, Array.isArray(denominator?.rows),
    'denominatorLedger rows must be an array');
  expect(failures, tag,
    Number.isInteger(denominator?.rowCount) &&
      denominator.rowCount >= 0 &&
      denominator.rowCount === (denominator.rows?.length ?? -1),
    'denominatorLedger rowCount must match rows length');
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity denominatorLedger counts',
    value: denominator?.counts,
    allowed: validationOpportunityDenominatorCountKeys,
  });
  for (const field of validationOpportunityDenominatorCountKeys) {
    expect(failures, tag,
      Number.isInteger(denominator?.counts?.[field]) && denominator.counts[field] >= 0,
      `denominatorLedger counts.${field} must be a non-negative integer`);
  }
  expect(failures, tag,
    [...validationOpportunityDenominatorCountKeys].reduce(
      (sum, field) => sum + Number(denominator?.counts?.[field] ?? 0),
      0,
    ) === denominator?.rowCount,
    'denominatorLedger counts must sum to rowCount');
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity denominatorLedger integrity',
    value: denominator?.integrity,
    allowed: validationOpportunityDenominatorIntegrityKeys,
  });
  for (const field of [
    'valid',
    'enrollmentLedgerValid',
    'operationReceiptLedgerVerified',
  ]) {
    expect(failures, tag, typeof denominator?.integrity?.[field] === 'boolean',
      `denominatorLedger integrity.${field} must be boolean`);
  }
  expect(failures, tag, Array.isArray(denominator?.integrity?.errors),
    'denominatorLedger integrity.errors must be an array');
  expect(failures, tag,
    Number.isInteger(denominator?.integrity?.errorCount) &&
      denominator.integrity.errorCount === (denominator.integrity.errors?.length ?? -1),
    'denominatorLedger integrity.errorCount must match errors length');

  const denominatorRows = Array.isArray(denominator?.rows) ? denominator.rows : [];
  const denominatorById = new Map();
  const actualDenominatorCounts = Object.fromEntries(
    [...validationOpportunityDenominatorCountKeys].map((state) => [state, 0]),
  );
  for (const row of denominatorRows) {
    verifyAllowedKeys({
      failures,
      tag,
      label: 'validation opportunity denominator row',
      value: row,
      allowed: validationOpportunityDenominatorRowKeys,
    });
    expect(failures, tag,
      typeof row?.opportunityId === 'string' && sha256HexRe.test(row.opportunityId),
      'denominator row opportunityId must be a lowercase SHA-256 hex string');
    expect(failures, tag, !denominatorById.has(row?.opportunityId),
      `denominator row opportunityId must be unique, got ${row?.opportunityId}`);
    if (typeof row?.opportunityId === 'string') denominatorById.set(row.opportunityId, row);
    for (const field of [
      'enrollmentContentHash',
      'stateContentHash',
      'operationAttemptContentHash',
      'catalogDigest',
    ]) {
      expect(failures, tag, typeof row?.[field] === 'string' && sha256HexRe.test(row[field]),
        `denominator row ${field} must be a lowercase SHA-256 hex string`);
    }
    for (const field of [
      'enrolledAt',
      'cohortInceptionAt',
      'releasePublishedAt',
      'opensAt',
      'closesAtExclusive',
    ]) {
      expect(failures, tag, Number.isFinite(Date.parse(row?.[field])),
        `denominator row ${field} must be a valid timestamp`);
    }
    expect(failures, tag, validationOpportunityCodes.has(row?.opportunityCode),
      `denominator row opportunityCode must be known, got ${row?.opportunityCode}`);
    expect(failures, tag, validationOpportunityDispositionStates.has(row?.disposition),
      `denominator row disposition must be known, got ${row?.disposition}`);
    if (validationOpportunityDispositionStates.has(row?.disposition)) {
      actualDenominatorCounts[row.disposition]++;
    }
    expect(failures, tag, typeof row?.terminal === 'boolean',
      'denominator row terminal must be boolean');
    expect(failures, tag,
      Number.isInteger(row?.catalogReleaseCount) && row.catalogReleaseCount > 0,
      'denominator row catalogReleaseCount must be a positive integer');
    expect(failures, tag,
      Number.isInteger(row?.promptVersion),
      'denominator row promptVersion must be an integer');
    expect(failures, tag,
      Array.isArray(row?.successEvidence) && Array.isArray(row?.failures),
      'denominator row successEvidence and failures must be arrays');
    expect(failures, tag,
      Number.isInteger(row?.failureCount) &&
        row.failureCount === (row.failures?.length ?? -1),
      'denominator row failureCount must match failures length');
    for (const evidence of row?.successEvidence ?? []) {
      verifyAllowedKeys({
        failures,
        tag,
        label: 'validation opportunity success evidence',
        value: evidence,
        allowed: validationOpportunitySuccessEvidenceKeys,
      });
    }
    for (const failure of row?.failures ?? []) {
      verifyAllowedKeys({
        failures,
        tag,
        label: 'validation opportunity failure evidence',
        value: failure,
        allowed: validationOpportunityFailureKeys,
      });
    }
  }
  expectJsonEqual(
    failures,
    tag,
    'denominatorLedger counts must match row dispositions',
    denominator?.counts,
    actualDenominatorCounts,
  );

  expect(failures, tag, validationOpportunityStates.has(opportunityStatus.overallStatus),
    `overallStatus must be known, got ${opportunityStatus.overallStatus}`);
  verifyAllowedKeys({
    failures,
    tag,
    label: 'validation opportunity currentStratum',
    value: opportunityStatus.currentStratum,
    allowed: validationOpportunityCurrentStratumKeys,
  });
  expect(failures, tag,
    opportunityStatus.currentStratum?.key === currentSeries?.key,
    'currentStratum key must match currentSeries key');
  expect(failures, tag,
    opportunityStatus.currentStratum?.status === opportunityStatus.overallStatus,
    'currentStratum status must match overallStatus');
  expect(failures, tag,
    typeof opportunityStatus.currentStratum?.denominatorReady === 'boolean',
    'currentStratum denominatorReady must be boolean');
  expectJsonEqual(
    failures,
    tag,
    'currentStratum counts must match top-level counts',
    opportunityStatus.currentStratum?.counts,
    counts,
  );
  expect(failures, tag,
    opportunityStatus.nextDeadlineAt == null ||
      Number.isFinite(Date.parse(opportunityStatus.nextDeadlineAt)),
    'nextDeadlineAt must be null or a valid timestamp');
  expect(failures, tag,
    validationOpportunityRecommendedActions.has(opportunityStatus.recommendedAction),
    `recommendedAction must be known, got ${opportunityStatus.recommendedAction}`);

  expect(failures, tag, Array.isArray(opportunityStatus.opportunities),
    'opportunities must be an array');
  const opportunities = Array.isArray(opportunityStatus.opportunities)
    ? opportunityStatus.opportunities
    : [];
  expect(failures, tag, opportunities.length === denominatorRows.length,
    'opportunities length must match denominatorLedger rows length');
  const actualCounts = {
    captured: 0,
    upcoming: 0,
    open: 0,
    missed: 0,
    failed: 0,
  };
  for (const opportunity of opportunities) {
    verifyAllowedKeys({
      failures,
      tag,
      label: 'validation opportunity',
      value: opportunity,
      allowed: validationOpportunityKeys,
    });
    expect(failures, tag, validationOpportunityCodes.has(opportunity?.code),
      `opportunity code must be known, got ${opportunity?.code}`);
    expect(failures, tag, validationOpportunityStates.has(opportunity?.state),
      `opportunity state must be known, got ${opportunity?.state}`);
    if (opportunity?.state in actualCounts) actualCounts[opportunity.state]++;
    for (const field of [
      'releasePublishedAt',
      'opensAt',
      'closesAtExclusive',
      'enrolledAt',
    ]) {
      expect(failures, tag, Number.isFinite(Date.parse(opportunity?.[field])),
        `opportunity ${field} must be a valid timestamp`);
    }
    expect(failures, tag,
      Number.isInteger(opportunity?.failureCount) &&
        opportunity.failureCount === (opportunity.failures?.length ?? -1),
      'opportunity failureCount must match failures length');
    for (const failure of opportunity?.failures ?? []) {
      verifyAllowedKeys({
        failures,
        tag,
        label: 'validation opportunity failure evidence',
        value: failure,
        allowed: validationOpportunityFailureKeys,
      });
    }
    const denominatorRow = denominatorById.get(opportunity?.opportunityId);
    expect(failures, tag, !!denominatorRow,
      `opportunity ${opportunity?.opportunityId} must match a denominator row`);
    if (denominatorRow) {
      expect(failures, tag,
        opportunity.releaseTag === denominatorRow.releaseTag &&
          opportunity.releasePublishedAt === denominatorRow.releasePublishedAt &&
          opportunity.code === denominatorRow.opportunityCode &&
          opportunity.opensAt === denominatorRow.opensAt &&
          opportunity.closesAtExclusive === denominatorRow.closesAtExclusive &&
          opportunity.enrolledAt === denominatorRow.enrolledAt &&
          opportunity.enrollmentContentHash === denominatorRow.enrollmentContentHash &&
          opportunity.stateContentHash === denominatorRow.stateContentHash,
        `opportunity ${opportunity.opportunityId} must match its denominator row`);
    }
  }
  for (const field of Object.keys(actualCounts)) {
    expect(failures, tag, counts?.[field] === actualCounts[field],
      `counts.${field} must match opportunity states`);
  }
  expect(failures, tag,
    currentSeries?.enrolledOpportunityCount === denominatorRows.length,
    'currentSeries enrolledOpportunityCount must match denominator rows length');

  const latestDenominatorRow = denominatorRows.slice().sort((left, right) =>
    Date.parse(right.releasePublishedAt) - Date.parse(left.releasePublishedAt) ||
    String(right.releaseTag).localeCompare(String(left.releaseTag)))[0] ?? null;
  expect(failures, tag,
    latestDenominatorRow == null
      ? latestRelease == null
      : latestRelease?.tag === latestDenominatorRow.releaseTag &&
        latestRelease?.publishedAt === latestDenominatorRow.releasePublishedAt,
    'latestRelease must match the newest enrolled denominator row');
}

function verifyPublicReleaseSnapshot({ failures, publicPayload }) {
  const tag = 'api/public';
  const snapshot = publicPayload?.snapshot;
  verifyAllowedKeys({
    failures,
    tag,
    label: 'public release snapshot',
    value: snapshot,
    allowed: releaseSnapshotKeys,
  });
  const snapshotId = publicPayload?.snapshotId;
  expect(failures, tag,
    typeof snapshotId === 'string' && sha256HexRe.test(snapshotId),
    'public snapshotId must be a lowercase SHA-256 hex string');
  expect(failures, tag, snapshot?.schemaVersion === releaseSnapshotSchemaVersion,
    `public snapshot schemaVersion must be ${releaseSnapshotSchemaVersion}`);
  expect(failures, tag, snapshot?.id === snapshotId,
    'public snapshot id must match snapshotId');
  expect(failures, tag, Number.isFinite(Date.parse(snapshot?.generatedAt)),
    'public snapshot generatedAt must be a valid timestamp');
  expect(failures, tag, snapshot?.source === 'current' || snapshot?.source === 'retained',
    `public snapshot source must be current or retained, got ${snapshot?.source}`);
  for (const field of ['retained', 'stale', 'actionable']) {
    expect(failures, tag, typeof snapshot?.[field] === 'boolean',
      `public snapshot ${field} must be boolean`);
  }
  expect(failures, tag, Number.isFinite(snapshot?.ageMs) && snapshot.ageMs >= 0,
    'public snapshot ageMs must be non-negative');
  expect(failures, tag,
    snapshot?.maxAgeMs == null ||
      (Number.isFinite(snapshot.maxAgeMs) && snapshot.maxAgeMs >= 0),
    'public snapshot maxAgeMs must be null or non-negative');
  if (snapshot?.source === 'current') {
    expect(failures, tag,
      snapshot.retained === false &&
        snapshot.stale === false &&
        snapshot.actionable === true &&
        snapshot.ageMs === 0 &&
        snapshot.maxAgeMs == null,
      'current public snapshot flags must describe an actionable fresh snapshot');
  } else if (snapshot?.source === 'retained') {
    expect(failures, tag,
      snapshot.retained === true &&
        snapshot.stale === true &&
        snapshot.actionable === false &&
        Number.isFinite(snapshot.maxAgeMs),
      'retained public snapshot flags must describe stale diagnostic evidence');
  }
  return typeof snapshotId === 'string' ? snapshotId : null;
}

function verifyReleaseSnapshotId({ failures, tag, label, snapshotId, expectedSnapshotId }) {
  expect(failures, tag,
    typeof snapshotId === 'string' && sha256HexRe.test(snapshotId),
    `${label} snapshotId must be a lowercase SHA-256 hex string`);
  if (expectedSnapshotId != null) {
    expect(failures, tag, snapshotId === expectedSnapshotId,
      `${label} snapshotId (${snapshotId}) must match public snapshotId (${expectedSnapshotId})`);
  }
}

function verifyUnscoredStaleProjection({
  failures,
  tag,
  label,
  value,
  release,
  nullFields,
}) {
  const diagnosticStatus = release.state ?? 'eligible';
  expect(failures, tag, isObject(value), `${label} must be present`);
  if (!isObject(value)) return;
  expect(failures, tag, value.status === 'stale',
    `${label} status (${value.status}) must be stale`);
  expect(failures, tag, value.diagnosticStatus === diagnosticStatus,
    `${label} diagnosticStatus (${value.diagnosticStatus}) must preserve ${diagnosticStatus}`);
  expect(failures, tag, value.band === 'wait',
    `${label} band (${value.band}) must be wait`);
  expect(failures, tag, value.recommended === false,
    `${label} recommended must be false`);
  expect(failures, tag,
    typeof value.reason === 'string' && value.reason.startsWith(staleAnalysisPrefix),
    `${label} reason must explain that analysis is stale`);
  for (const field of nullFields) {
    expect(failures, tag, value[field] == null,
      `${label} ${field} must be null while the release is unscored`);
  }
  const staleAudit = value.staleAudit;
  expect(failures, tag, isObject(staleAudit),
    `${label} staleAudit diagnostics must be present`);
  if (!isObject(staleAudit)) return;
  expect(failures, tag, staleAudit.schemaVersion === staleScoreAuditSchemaVersion,
    `${label} staleAudit schemaVersion must be ${staleScoreAuditSchemaVersion}`);
  expect(failures, tag, staleAudit.state === 'stale',
    `${label} staleAudit state must be stale`);
  expect(failures, tag, staleAudit.message === value.reason,
    `${label} staleAudit message must match its stale reason`);
  expect(failures, tag, staleAudit.previousStatus === (release.state ?? null),
    `${label} staleAudit previousStatus must match the persisted release state`);
  expect(failures, tag, staleAudit.auditedAt == null,
    `${label} staleAudit auditedAt must be null while no score audit exists`);
  expect(failures, tag,
    isStringArray(staleAudit.causes) && staleAudit.causes.includes('audit_missing'),
    `${label} staleAudit causes must include audit_missing`);
}

function verifyApiTagRows({
  failures,
  label,
  rows,
  allowedTags = null,
  tagExists = null,
  requireExact = false,
}) {
  const tags = rows.map((row) => row?.tag);
  const duplicates = tags.filter(
    (tag, index) => typeof tag === 'string' && tags.indexOf(tag) !== index,
  );
  expect(
    failures,
    label,
    duplicates.length === 0,
    `${label} must not contain duplicate tags before map construction: ` +
    `${[...new Set(duplicates)].join(', ')}`,
  );
  for (const tag of tags) {
    if (typeof tag !== 'string' || tag.length === 0) continue;
    const known = allowedTags instanceof Set
      ? allowedTags.has(tag)
      : typeof tagExists === 'function'
        ? tagExists(tag)
        : true;
    expect(failures, label, known, `${label} contains unexpected tag ${tag}`);
  }
  if (requireExact && allowedTags instanceof Set) {
    const actual = new Set(tags.filter((tag) => typeof tag === 'string'));
    const missing = [...allowedTags].filter((tag) => !actual.has(tag));
    const extra = [...actual].filter((tag) => !allowedTags.has(tag));
    expect(
      failures,
      label,
      missing.length === 0 && extra.length === 0,
      `${label} tag set must exactly match DB releases ` +
      `(missing=${missing.join(', ') || 'none'}, extra=${extra.join(', ') || 'none'})`,
    );
  }
}

async function verifyApi({
  apiBase,
  fetchJson,
  reader,
  failures,
  scorePublication,
  advisorySnapshotAuditProjection,
}) {
  const publicationDigests = isObject(scorePublication?.publicationDigests)
    ? scorePublication.publicationDigests
    : {};
  const publicationAuthorityBindings =
    isObject(scorePublication?.publicationAuthorityBindings)
      ? scorePublication.publicationAuthorityBindings
      : {};
  const expectedAuthorityBindingByTag = new Map();
  const expectedAuthorityBindingFor = (tag) => {
    if (expectedAuthorityBindingByTag.has(tag)) {
      return expectedAuthorityBindingByTag.get(tag);
    }
    const binding = publicationAuthorityBindings[tag];
    expect(
      failures,
      tag,
      isObject(binding),
      'independently sealed score authority binding must be present',
    );
    if (!isObject(binding)) {
      expectedAuthorityBindingByTag.set(tag, null);
      return null;
    }
    expect(
      failures,
      tag,
      typeof binding.authorityRunId === 'string' &&
        binding.authorityRunId.length > 0,
      'independently sealed authorityRunId must be present',
    );
    for (const field of [
      'authorityRunContentHash',
      'historyV2SealContentHash',
    ]) {
      expect(
        failures,
        tag,
        typeof binding[field] === 'string' && sha256HexRe.test(binding[field]),
        `independently sealed ${field} must be lowercase SHA-256 hex`,
      );
    }
    expectedAuthorityBindingByTag.set(tag, binding);
    return binding;
  };
  const expectedAuditDigestFor = (tag, scoreAudit) => {
    const independentDigest = publicationDigests[tag];
    if (independentDigest != null) {
      expect(
        failures,
        tag,
        typeof independentDigest === 'string' && sha256HexRe.test(independentDigest),
        'sealed score publication digest must be lowercase SHA-256 hex',
      );
      expect(
        failures,
        tag,
        scoreAudit?.auditDigest === independentDigest,
        `scoreAudit auditDigest (${scoreAudit?.auditDigest}) must match independently ` +
          `sealed publication digest (${independentDigest})`,
      );
      return independentDigest;
    }
    return typeof scoreAudit?.auditDigest === 'string' ? scoreAudit.auditDigest : null;
  };
  const status = await fetchJson(`${apiBase}/api/status`);
  expect(failures, 'api/status', status.schemaVersion === statusPayloadSchemaVersion,
    `status schemaVersion must be ${statusPayloadSchemaVersion}, got ${JSON.stringify(status.schemaVersion)}`);
  expect(failures, 'api/status', status.refreshing === false, `refreshing must be false, got ${status.refreshing}`);
  expect(failures, 'api/status', status.lastError == null, `lastError must be null, got ${status.lastError}`);
  expect(failures, 'api/status', status.lastScoredAt == null || Number.isFinite(Date.parse(status.lastScoredAt)),
    `lastScoredAt must be null or a valid timestamp, got ${status.lastScoredAt}`);
  expect(failures, 'api/status', status.lastRefreshAt == null || Number.isFinite(Date.parse(status.lastRefreshAt)),
    `lastRefreshAt must be null or a valid timestamp, got ${status.lastRefreshAt}`);
  expect(failures, 'api/status', status.processLastRefreshAt == null || status.lastRefreshAt === status.processLastRefreshAt,
    `lastRefreshAt (${status.lastRefreshAt}) must match non-null processLastRefreshAt (${status.processLastRefreshAt})`);
  expect(failures, 'api/status', status.processLastRefreshAt == null || Number.isFinite(Date.parse(status.processLastRefreshAt)),
    `processLastRefreshAt must be null or a valid timestamp, got ${status.processLastRefreshAt}`);
  if (status.dataFreshness) {
    verifyDataFreshness({
      failures,
      tag: 'api/status',
      dataFreshness: status.dataFreshness,
      releaseTag: status.dataFreshness.tag,
      reader,
    });
  }

  const opportunityStatus = await fetchJson(`${apiBase}/api/validation/opportunities`);
  verifyValidationOpportunityStatus({ failures, opportunityStatus });

  const configPayload = await fetchJson(`${apiBase}/api/config`);
  expect(failures, 'api/config', configPayload.schemaVersion === configPayloadSchemaVersion,
    `config schemaVersion must be ${configPayloadSchemaVersion}, got ${JSON.stringify(configPayload.schemaVersion)}`);
  expect(failures, 'api/config', Number.isInteger(configPayload.releases) && configPayload.releases > 0,
    'config releases must be a positive integer');
  expect(failures, 'api/config', Number.isInteger(configPayload.refreshMinutes) && configPayload.refreshMinutes >= 0,
    'config refreshMinutes must be a non-negative integer; 0 means periodic refresh is disabled');
  let publicationReleases = null;
  if (
    Number.isInteger(configPayload.releases) &&
    configPayload.releases > 0 &&
    typeof reader.listReleases === 'function'
  ) {
    try {
      const selected = reader.listReleases(
        configPayload.releases,
        { scoredOnly: false },
      );
      if (!Array.isArray(selected)) {
        throw new Error('publication release query did not return an array');
      }
      publicationReleases = selected;
    } catch (error) {
      failures.push(
        `api/config: configured publication release scope could not be read: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  } else {
    failures.push(
      'api/config: configured publication release scope cannot be independently selected',
    );
  }

  const publicPayload = await fetchJson(`${apiBase}/api/public`);
  verifyAllowedKeys({ failures, tag: 'api/public', label: 'public top-level', value: publicPayload, allowed: publicTopLevelKeys });
  expect(failures, 'api/public', publicPayload.schemaVersion === publicPayloadSchemaVersion,
    `public schemaVersion must be ${publicPayloadSchemaVersion}, got ${JSON.stringify(publicPayload.schemaVersion)}`);
  const publicSnapshotId = verifyPublicReleaseSnapshot({ failures, publicPayload });
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('comparison'), 'public payload must not include comparison data');
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('upstream'), 'public payload must not include upstream data');
  if (status.lastScoredAt) {
    expect(failures, 'api/public', publicPayload.updatedAt === status.lastScoredAt,
      `public updatedAt (${publicPayload.updatedAt}) must equal status lastScoredAt (${status.lastScoredAt})`);
  }
  if (!publicationReleases) return;

  const releasesPayload = await fetchJson(`${apiBase}/api/releases`);
  const releaseApiRows = Array.isArray(releasesPayload) ? releasesPayload : [];
  const persistedReleaseTags = new Set(
    publicationReleases.map((release) => release.tag),
  );
  verifyApiTagRows({
    failures,
    label: 'releases API',
    rows: releaseApiRows,
    allowedTags: persistedReleaseTags,
    requireExact: true,
  });
  for (const row of releaseApiRows) {
    verifyReleaseSnapshotId({
      failures,
      tag: row?.tag ?? 'api/releases',
      label: 'releases row',
      snapshotId: row?.snapshotId,
      expectedSnapshotId: publicSnapshotId,
    });
  }
  const releaseApiByTag = new Map(releaseApiRows.map((release) => [release.tag, release]));
  const persistedReleaseByTag = new Map(
    publicationReleases.map((release) => [release.tag, release]),
  );
  verifyRecommendationDecisionSet({ failures, rows: releaseApiRows });
  const historyPayload = await fetchJson(`${apiBase}/api/releases/history`);
  expect(failures, 'api/releases/history', Array.isArray(historyPayload), 'history payload must be an array');
  verifyApiTagRows({
    failures,
    label: 'release history API',
    rows: Array.isArray(historyPayload) ? historyPayload : [],
    tagExists: (tag) =>
      persistedReleaseTags.has(tag) ||
      (typeof reader.getRelease === 'function' && !!reader.getRelease(tag)),
  });
  for (const row of historyPayload ?? []) {
    verifyAllowedKeys({ failures, tag: row?.tag ?? 'api/releases/history', label: 'history row', value: row, allowed: releaseHistoryRowKeys });
    verifyReleaseSnapshotId({
      failures,
      tag: row?.tag ?? 'api/releases/history',
      label: 'history row',
      snapshotId: row?.snapshotId,
      expectedSnapshotId: publicSnapshotId,
    });
    expect(failures, row?.tag ?? 'api/releases/history', row.schemaVersion === releaseHistoryRowSchemaVersion,
      `history row schemaVersion must be ${releaseHistoryRowSchemaVersion}, got ${JSON.stringify(row?.schemaVersion)}`);
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.tag === 'string' && row.tag.length > 0,
      'history row tag must be present');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.publishedAt === 'string' && row.publishedAt.length > 0,
      'history row publishedAt must be present');
    expect(failures, row?.tag ?? 'api/releases/history', row.finalScore == null || typeof row.finalScore === 'number',
      'history row finalScore must be numeric or null');
    expect(failures, row?.tag ?? 'api/releases/history', row.scoredAt == null || typeof row.scoredAt === 'string',
      'history row scoredAt must be string or null');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.status === 'string' && row.status.length > 0,
      'history row status must be present');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.band === 'string' && row.band.length > 0,
      'history row band must be present');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.recommended === 'boolean',
      'history row recommended must be boolean');
    verifyAuditLinks({
      failures,
      tag: row?.tag ?? 'api/releases/history',
      label: 'history row auditLinks',
      auditLinks: row.auditLinks,
      publicationSnapshot: publicSnapshotId,
      auditDigest: expectedAuditDigestFor(row?.tag, row?.scoreAudit),
    });
    const persistedRelease = persistedReleaseByTag.get(row.tag) ??
      (typeof reader.getRelease === 'function' ? reader.getRelease(row.tag) : null);
    if (persistedRelease) {
      expect(
        failures,
        row.tag,
        releaseHasPersistedScore(persistedRelease),
        'unscored releases must not appear in score history',
      );
    }
    const releaseApi = releaseApiByTag.get(row.tag);
    if (releaseApi) {
      expectJsonEqual(failures, row.tag, 'history row scoreAudit must match releases row scoreAudit',
        row.scoreAudit, releaseApi.scoreAudit);
      expectJsonEqual(failures, row.tag, 'history row dataFreshness must match releases row dataFreshness',
        row.dataFreshness, releaseApi.dataFreshness);
      expect(failures, row.tag, row.scoredAt === releaseApi.scoredAt,
        `history scoredAt (${row.scoredAt}) must match releases scoredAt (${releaseApi.scoredAt})`);
      expect(failures, row.tag, row.finalScore === releaseApi.finalScore,
        `history finalScore (${row.finalScore}) must match releases finalScore (${releaseApi.finalScore})`);
      expect(failures, row.tag, row.status === releaseApi.status,
        `history status (${row.status}) must match releases status (${releaseApi.status})`);
      expect(failures, row.tag, row.band === releaseApi.band,
        `history band (${row.band}) must match releases band (${releaseApi.band})`);
      expect(failures, row.tag, row.recommended === releaseApi.recommended,
        `history recommended (${row.recommended}) must match releases recommended (${releaseApi.recommended})`);
    } else {
      verifyScoreAuditSummary({
        failures,
        tag: row.tag,
        summary: row.scoreAudit,
        expectedAuthorityBinding: expectedAuthorityBindingFor(row.tag),
      });
      verifyDataFreshness({
        failures,
        tag: row.tag,
        dataFreshness: row.dataFreshness,
        releaseTag: row.tag,
        scoredAt: row.scoredAt,
        reader,
      });
    }
  }
  const publicReleaseRows = Array.isArray(publicPayload.releases)
    ? publicPayload.releases
    : [];
  verifyApiTagRows({
    failures,
    label: 'public API',
    rows: publicReleaseRows,
    allowedTags: persistedReleaseTags,
    requireExact: true,
  });
  const publicByTag = new Map(publicReleaseRows.map((release) => [release.tag, release]));
  const publishedAuditLinksByTag = new Map();
  for (const release of publicReleaseRows) {
    verifyAllowedKeys({ failures, tag: release.tag ?? 'api/public', label: 'public release', value: release, allowed: publicReleaseKeys });
    verifyReleaseSnapshotId({
      failures,
      tag: release.tag ?? 'api/public',
      label: 'public release',
      snapshotId: release.snapshotId,
      expectedSnapshotId: publicSnapshotId,
    });
    verifyNoForbiddenPublicKeys({ failures, tag: release.tag ?? 'api/public', value: release });
    expect(failures, release.tag ?? 'api/public', release.schemaVersion === publicReleaseSchemaVersion,
      `public release schemaVersion must be ${publicReleaseSchemaVersion}, got ${JSON.stringify(release.schemaVersion)}`);
    const validAuditLinks = verifyAuditLinks({
      failures,
      tag: release.tag ?? 'api/public',
      label: 'public release auditLinks',
      auditLinks: release.auditLinks,
      publicationSnapshot: publicSnapshotId,
      auditDigest: expectedAuditDigestFor(release.tag, release.scoreAudit),
    });
    if (validAuditLinks) publishedAuditLinksByTag.set(release.tag, validAuditLinks);
  }
  const comparisonPayload = await fetchOptionalComparisonPayload({ apiBase, fetchJson, failures });
  if (comparisonPayload) {
    verifyAllowedKeys({ failures, tag: 'api/comparison', label: 'comparison payload', value: comparisonPayload, allowed: comparisonPayloadKeys });
    expect(failures, 'api/comparison', comparisonPayload.schemaVersion === comparisonPayloadSchemaVersion,
      `comparison schemaVersion must be ${comparisonPayloadSchemaVersion}, got ${JSON.stringify(comparisonPayload.schemaVersion)}`);
    verifyComparisonSnapshot({ failures, label: 'api/comparison', snapshot: comparisonPayload.snapshot });
  }
  const comparisonReleaseRows = Array.isArray(comparisonPayload?.releases)
    ? comparisonPayload.releases
    : [];
  verifyApiTagRows({
    failures,
    label: 'comparison API',
    rows: comparisonReleaseRows,
    allowedTags: persistedReleaseTags,
    requireExact: comparisonPayload != null,
  });
  const comparisonByTag = new Map(
    comparisonReleaseRows.map((release) => [release.tag, release]),
  );

  for (const release of publicationReleases) {
    const releaseIsScored = releaseHasPersistedScore(release);
    const releaseApi = releaseApiByTag.get(release.tag);
    expect(failures, release.tag, !!releaseApi, 'releases API must include monitored release');
    if (releaseApi) {
      verifyAllowedKeys({ failures, tag: release.tag, label: 'releases row', value: releaseApi, allowed: releaseRowKeys });
      expect(failures, release.tag, releaseApi.schemaVersion === releaseRowSchemaVersion,
        `releases row schemaVersion must be ${releaseRowSchemaVersion}, got ${JSON.stringify(releaseApi.schemaVersion)}`);
      verifyAuditLinks({
        failures,
        tag: release.tag,
        label: 'releases row auditLinks',
        auditLinks: releaseApi.auditLinks,
        publicationSnapshot: publicSnapshotId,
        auditDigest: expectedAuditDigestFor(release.tag, releaseApi.scoreAudit),
      });
      if (releaseIsScored) {
        expect(failures, release.tag, releaseApi.finalScore === release.final_score,
          `releases finalScore (${releaseApi.finalScore}) must match DB final_score (${release.final_score})`);
        expect(failures, release.tag, releaseApi.status === release.state,
          `releases status (${releaseApi.status}) must match DB state (${release.state})`);
        expect(failures, release.tag, releaseApi.reason === release.score_reason,
          `releases reason (${releaseApi.reason}) must match DB score_reason (${release.score_reason})`);
        expect(failures, release.tag, releaseApi.negativeIssues === release.negative_issues,
          `releases negativeIssues (${releaseApi.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
        expect(failures, release.tag, releaseApi.positiveIssues === release.positive_issues,
          `releases positiveIssues (${releaseApi.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
        expect(failures, release.tag, releaseApi.recommended === (release.recommended === 1),
          `releases recommended (${releaseApi.recommended}) must match DB recommended (${release.recommended === 1})`);
        expect(failures, release.tag, releaseApi.scoredAt === release.scored_at,
          `releases scoredAt (${releaseApi.scoredAt}) must match DB scored_at (${release.scored_at})`);
        verifyScoreAuditSummary({
          failures,
          tag: release.tag,
          summary: releaseApi.scoreAudit,
          expectedAuthorityBinding: expectedAuthorityBindingFor(release.tag),
        });
        verifyScoreExplanation({
          failures,
          tag: release.tag,
          explanation: releaseApi.explanation,
          recommended: release.recommended === 1,
          expectedBand: releaseApi.band,
          source: 'releases',
        });
      } else {
        verifyUnscoredStaleProjection({
          failures,
          tag: release.tag,
          label: 'releases row',
          value: releaseApi,
          release,
          nullFields: [
            'finalScore',
            'negativeIssues',
            'positiveIssues',
            'closedSeriousFixed',
            'openedSeriousDuringReign',
            'scoredAt',
            'scoreAudit',
            'explanation',
          ],
        });
        expect(failures, release.tag,
          Array.isArray(releaseApi.brokenSurfaces) && releaseApi.brokenSurfaces.length === 0,
          'releases row brokenSurfaces must be empty while the release is unscored');
      }
      verifyDataFreshness({
        failures,
        tag: release.tag,
        dataFreshness: releaseApi.dataFreshness,
        releaseTag: release.tag,
        scoredAt: releaseIsScored ? release.scored_at : null,
        reader,
      });
    }

    const publicRelease = publicByTag.get(release.tag);
    expect(failures, release.tag, !!publicRelease, 'public API must include monitored release');
    if (publicRelease) {
      if (releaseIsScored) {
        expect(failures, release.tag, publicRelease.score === release.final_score,
          `public score (${publicRelease.score}) must match DB final_score (${release.final_score})`);
        expect(failures, release.tag, publicRelease.status === release.state,
          `public status (${publicRelease.status}) must match DB state (${release.state})`);
        expect(failures, release.tag, publicRelease.reason === release.score_reason,
          `public reason (${publicRelease.reason}) must match DB score_reason (${release.score_reason})`);
        expect(failures, release.tag, publicRelease.negativeIssues === Number(release.negative_issues ?? 0),
          `public negativeIssues (${publicRelease.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
        expect(failures, release.tag, publicRelease.positiveIssues === Number(release.positive_issues ?? 0),
          `public positiveIssues (${publicRelease.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
        expect(failures, release.tag, publicRelease.recommended === (release.recommended === 1),
          `public recommended (${publicRelease.recommended}) must match DB recommended (${release.recommended === 1})`);
        expect(failures, release.tag, publicRelease.scoredAt === release.scored_at,
          `public scoredAt (${publicRelease.scoredAt}) must match DB scored_at (${release.scored_at})`);
        verifyScoreAuditSummary({
          failures,
          tag: release.tag,
          summary: publicRelease.scoreAudit,
          expectedAuthorityBinding: expectedAuthorityBindingFor(release.tag),
        });
        expect(failures, release.tag, publicRelease.totalAttributedIssues === publicRelease.scoreAudit?.rawIssueCount,
          `public totalAttributedIssues (${publicRelease.totalAttributedIssues}) must match scoreAudit rawIssueCount (${publicRelease.scoreAudit?.rawIssueCount})`);
      } else {
        verifyUnscoredStaleProjection({
          failures,
          tag: release.tag,
          label: 'public release',
          value: publicRelease,
          release,
          nullFields: [
            'score',
            'negativeIssues',
            'positiveIssues',
            'scoredAt',
            'scoreAudit',
            'explanation',
          ],
        });
      }
      verifyDataFreshness({
        failures,
        tag: release.tag,
        dataFreshness: publicRelease.dataFreshness,
        releaseTag: release.tag,
        scoredAt: releaseIsScored ? release.scored_at : null,
        reader,
      });
      if (typeof reader.issueNumbersForVersion === 'function') {
        const issueUniverse = reader.issueNumbersForVersion(release.tag);
        const issueNumbers = new Set(issueUniverse);
        const expectedIssueCount = Math.min(25, issueUniverse.length);
        const actualIssueCount = Array.isArray(publicRelease.issues) ? publicRelease.issues.length : 0;
        expect(failures, release.tag, actualIssueCount === expectedIssueCount,
          `public issues length (${actualIssueCount}) must equal capped issue universe count (${expectedIssueCount})`);
        for (const issue of publicRelease.issues ?? []) {
          expect(failures, release.tag, issueNumbers.has(issue.number),
            `public issue #${issue.number} must belong to release issue universe`);
        }
        if (typeof reader.issuesForVersion === 'function') {
          const releaseIssues = reader.issuesForVersion(release.tag);
          const labelCutoff = publicRelease.dataFreshness?.labelCutoffAt ?? null;
          const expectedIssues = publicIssueSummariesForRelease({
            issues: releaseIssues,
            openedIssues: reader.openedDuringReign?.(release.tag) ?? [],
            labelCutoff,
            labelsForIssue: (issueNumber, fallbackLabels, cutoff, options) =>
              reader.labelsForIssueAt(issueNumber, fallbackLabels, cutoff, options),
          });
          expectArrayEqual(
            failures,
            release.tag,
            'public issues',
            (publicRelease.issues ?? []).map((issue) => issue.number),
            expectedIssues.topIssues.map((issue) => issue.number),
          );
          expectArrayEqual(
            failures,
            release.tag,
            'public watchIssues',
            (publicRelease.watchIssues ?? []).map((issue) => issue.number),
            expectedIssues.watchIssues.map((issue) => issue.number),
          );
        }
      } else if (publicRelease.totalAttributedIssues > 0) {
        const issueCount = Array.isArray(publicRelease.issues) ? publicRelease.issues.length : 0;
        expect(failures, release.tag, issueCount > 0,
          'public release with attributed issues must expose capped issue summaries');
      }
      verifyPublicProfileEvidence({ failures, tag: release.tag, publicRelease });
      verifyPublicIssueSummaries({ failures, tag: release.tag, publicRelease });
      if (releaseIsScored) {
        verifyScoreExplanation({
          failures,
          tag: release.tag,
          explanation: publicRelease.explanation,
          recommended: release.recommended === 1,
          expectedBand: publicRelease.band,
          source: 'public',
        });
      }
    }

    const comparison = comparisonByTag.get(release.tag);
    if (comparisonPayload) {
      verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison release row', value: comparison, allowed: comparisonReleaseKeys });
      expect(failures, release.tag, !!comparison?.local && 'upstream' in comparison && !!comparison?.delta,
        'comparison payload must include local, upstream, and delta objects');
      if (comparison?.local) {
        verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison local', value: comparison.local, allowed: comparisonLocalKeys });
      }
      if (comparison?.upstream) {
        verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison upstream', value: comparison.upstream, allowed: comparisonUpstreamKeys });
        expect(failures, release.tag, comparison.upstream.schemaVersion === comparisonUpstreamSchemaVersion,
          `comparison upstream schemaVersion (${comparison.upstream.schemaVersion}) must equal ${comparisonUpstreamSchemaVersion}`);
      }
      if (comparison?.delta) {
        verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison delta', value: comparison.delta, allowed: comparisonDeltaKeys });
        expect(failures, release.tag, comparison.delta.schemaVersion === comparisonDeltaSchemaVersion,
          `comparison delta schemaVersion (${comparison.delta.schemaVersion}) must equal ${comparisonDeltaSchemaVersion}`);
      }
      if (!releaseIsScored && comparison?.local) {
        verifyUnscoredStaleProjection({
          failures,
          tag: release.tag,
          label: 'comparison local',
          value: comparison.local,
          release,
          nullFields: [
            'score',
            'negativeIssues',
            'positiveIssues',
            'scoredAt',
            'modelVersion',
            'components',
            'input',
            'gateEvidence',
          ],
        });
      }
    }

    const expectedAuditDigest = expectedAuditDigestFor(
      release.tag,
      publicRelease?.scoreAudit ?? releaseApi?.scoreAudit,
    );
    const expectedAuthorityBinding = releaseIsScored
      ? expectedAuthorityBindingFor(release.tag)
      : null;
    const publishedAuditLinks = publishedAuditLinksByTag.get(release.tag);
    expect(
      failures,
      release.tag,
      !!publishedAuditLinks,
      'public API must expose a valid publication-bound audit link set',
    );
    if (!publishedAuditLinks) continue;
    if (releaseApi) {
      expectJsonEqual(
        failures,
        release.tag,
        'releases auditLinks must match public auditLinks',
        releaseApi.auditLinks,
        publishedAuditLinks,
      );
    }
    const review = await fetchJson(
      resolvePublishedApiUrl(apiBase, publishedAuditLinks.review),
    );
    const persistedAuditForReview = reader.getReleaseScoreAudit(release.tag);
    const persistedInput = parseJson(persistedAuditForReview?.input_json, null);
    const persistedComponents = parseJson(persistedAuditForReview?.components_json, null);
    const persistedIssueEvidence = parseJson(persistedAuditForReview?.issue_evidence_json, null);
    const persistedGateEvidence = parseJson(persistedAuditForReview?.gate_evidence_json, null);
    const persistedSourceIdentity = parseJson(persistedAuditForReview?.source_identity_json, null);
    verifyNoForbiddenPublicKeys({
      failures,
      tag: release.tag,
      value: review,
      path: 'review payload',
      forbidden: forbiddenReviewComparisonKeys,
    });
    verifyAllowedKeys({ failures, tag: release.tag, label: 'review payload', value: review, allowed: reviewPayloadKeys });
    verifyAllowedKeys({ failures, tag: release.tag, label: 'review local', value: review.local, allowed: reviewLocalKeys });
    verifyReleaseSnapshotId({
      failures,
      tag: release.tag,
      label: 'review payload',
      snapshotId: review.snapshotId,
      expectedSnapshotId: publicSnapshotId,
    });
    const reviewAuditLinks = verifyAuditLinks({
      failures,
      tag: release.tag,
      label: 'review auditLinks',
      auditLinks: review.auditLinks,
      publicationSnapshot: publicSnapshotId,
      auditDigest: expectedAuditDigest,
    });
    expectJsonEqual(
      failures,
      release.tag,
      'review auditLinks must match published public auditLinks',
      review.auditLinks,
      publishedAuditLinks,
    );
    expect(failures, release.tag, review.tag === release.tag,
      `review tag (${review.tag}) must match DB tag (${release.tag})`);
    expect(failures, release.tag, review.local?.schemaVersion === localAuditSchemaVersion,
      `review local schemaVersion (${review.local?.schemaVersion}) must equal ${localAuditSchemaVersion}`);
    if (!releaseIsScored) {
      expect(failures, release.tag, persistedAuditForReview == null,
        'unscored release must not have a persisted score audit');
      verifyUnscoredStaleProjection({
        failures,
        tag: release.tag,
        label: 'review local',
        value: review.local,
        release,
        nullFields: [
          'score',
          'negativeIssues',
          'positiveIssues',
          'scoredAt',
          'sourceProvenance',
          'auditDigest',
          'modelVersion',
          'promptVersion',
          'input',
          'components',
          'issueEvidence',
          'gateEvidence',
        ],
      });
      verifyDataFreshness({
        failures,
        tag: release.tag,
        dataFreshness: review.local?.dataFreshness,
        releaseTag: release.tag,
        reader,
      });
      if (releaseApi) {
        expectJsonEqual(failures, release.tag,
          'unscored releases staleAudit must match review staleAudit',
          releaseApi.staleAudit, review.local?.staleAudit);
        expectJsonEqual(failures, release.tag,
          'unscored releases dataFreshness must match review dataFreshness',
          releaseApi.dataFreshness, review.local?.dataFreshness);
      }
      if (publicRelease) {
        expectJsonEqual(failures, release.tag,
          'unscored public staleAudit must match review staleAudit',
          publicRelease.staleAudit, review.local?.staleAudit);
        expectJsonEqual(failures, release.tag,
          'unscored public dataFreshness must match review dataFreshness',
          publicRelease.dataFreshness, review.local?.dataFreshness);
      }
      if (comparison?.local) {
        expectJsonEqual(failures, release.tag,
          'unscored comparison staleAudit must match review staleAudit',
          comparison.local.staleAudit, review.local?.staleAudit);
        expectJsonEqual(failures, release.tag,
          'unscored comparison dataFreshness must match review dataFreshness',
          comparison.local.dataFreshness, review.local?.dataFreshness);
      }
      continue;
    }
    expect(failures, release.tag, review.local?.score === release.final_score,
      `review score (${review.local?.score}) must match DB final_score (${release.final_score})`);
    expect(failures, release.tag, review.local?.status === release.state,
      `review status (${review.local?.status}) must match DB state (${release.state})`);
    expect(failures, release.tag, review.local?.reason === release.score_reason,
      `review reason (${review.local?.reason}) must match DB score_reason (${release.score_reason})`);
    expect(failures, release.tag, review.local?.negativeIssues === release.negative_issues,
      `review negativeIssues (${review.local?.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
    expect(failures, release.tag, review.local?.positiveIssues === release.positive_issues,
      `review positiveIssues (${review.local?.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
    expect(failures, release.tag, review.local?.recommended === (release.recommended === 1),
      `review recommended (${review.local?.recommended}) must match DB recommended (${release.recommended === 1})`);
    expect(failures, release.tag, review.local?.scoredAt === release.scored_at,
      `review scoredAt (${review.local?.scoredAt}) must match DB scored_at (${release.scored_at})`);
    expect(failures, release.tag,
      typeof review.local?.auditDigest === 'string' && sha256HexRe.test(review.local.auditDigest),
    'review auditDigest must be a lowercase SHA-256 hex string');
    expect(
      failures,
      release.tag,
      review.local?.auditDigest === expectedAuditDigest,
      `review auditDigest (${review.local?.auditDigest}) must match sealed publication ` +
        `digest (${expectedAuditDigest})`,
    );
    expect(failures, release.tag,
      review.local?.auditDigest === review.local?.sourceProvenance?.auditDigest,
    'review auditDigest must match sourceProvenance auditDigest');
    verifyDataFreshness({
      failures,
      tag: release.tag,
      dataFreshness: review.local?.dataFreshness,
      releaseTag: release.tag,
      scoredAt: release.scored_at,
      reader,
    });
    verifyReviewSourceProvenance({
      failures,
      tag: release.tag,
      sourceProvenance: review.local?.sourceProvenance,
      dataFreshness: review.local?.dataFreshness,
      scoredAt: release.scored_at,
      scoreSourceIdentity: persistedSourceIdentity,
      auditLinks: reviewAuditLinks ?? publishedAuditLinks,
      expectedAuthorityBinding,
      expectedAdvisorySnapshotAuditProjection:
        advisorySnapshotAuditProjection,
    });
    if (releaseApi) {
      expect(failures, release.tag, releaseApi.band === review.local?.band,
        `releases band (${releaseApi.band}) must match review band (${review.local?.band})`);
    }
    expect(failures, release.tag, review.local?.input?.schemaVersion === scoreInputSchemaVersion,
      `review score input schemaVersion (${review.local?.input?.schemaVersion}) must equal ${scoreInputSchemaVersion}`);
    expect(failures, release.tag, review.local?.components?.schemaVersion === scoreComponentsSchemaVersion,
      `review score components schemaVersion (${review.local?.components?.schemaVersion}) must equal ${scoreComponentsSchemaVersion}`);
    expect(failures, release.tag, review.local?.gateEvidence?.schemaVersion === gateEvidenceSchemaVersion,
      `review gateEvidence schemaVersion (${review.local?.gateEvidence?.schemaVersion}) must equal ${gateEvidenceSchemaVersion}`);
    expect(failures, release.tag, review.local?.issueEvidence?.schemaVersion === issueEvidenceSchemaVersion,
      `review issueEvidence schemaVersion (${review.local?.issueEvidence?.schemaVersion}) must equal ${issueEvidenceSchemaVersion}`);
    expectJsonEqual(failures, release.tag, 'review input must match persisted audit input',
      review.local?.input, persistedInput);
    expectJsonEqual(failures, release.tag, 'review components must match persisted audit components',
      review.local?.components, persistedComponents);
    expectJsonEqual(failures, release.tag, 'review issueEvidence must match persisted audit issueEvidence',
      review.local?.issueEvidence, persistedIssueEvidence);
    expectJsonEqual(failures, release.tag, 'review gateEvidence must match persisted audit gateEvidence',
      review.local?.gateEvidence, persistedGateEvidence);
    await verifyIssueEvidenceAuditEndpoint({
      base: resolvePublishedApiUrl(apiBase, publishedAuditLinks.issues),
      fetchJson,
      failures,
      reader,
      tag: release.tag,
      issueEvidence: review.local?.issueEvidence,
      scoredAt: release.scored_at,
      publicationSnapshot: publicSnapshotId,
      auditDigest: expectedAuditDigest,
    });
    verifyReleaseChecksGate({
      failures,
      tag: release.tag,
      releaseChecks: review.local?.gateEvidence?.releaseChecks,
    });
    verifyArtifactVerificationGate({
      failures,
      tag: release.tag,
      artifactVerification: review.local?.gateEvidence?.artifactVerification,
    });
    if (publicRelease) {
      expect(failures, release.tag, publicRelease.band === review.local?.band,
        `public band (${publicRelease.band}) must match review band (${review.local?.band})`);
      expect(failures, release.tag, publicRelease.totalAttributedIssues === review.local?.input?.rawIssueCount,
        `public totalAttributedIssues (${publicRelease.totalAttributedIssues}) must match review rawIssueCount (${review.local?.input?.rawIssueCount})`);
    }
    verifyScoreExplanation({
      failures,
      tag: release.tag,
      explanation: review.local?.components?.explanation,
      recommended: release.recommended === 1,
      expectedBand: review.local?.band,
      source: 'review',
    });
    if (releaseApi) {
      expectJsonEqual(failures, release.tag, 'releases explanation must match review explanation',
        releaseApi.explanation, review.local?.components?.explanation);
    }
    if (publicRelease) {
      expectJsonEqual(failures, release.tag, 'public explanation must match review explanation',
        publicRelease.explanation, review.local?.components?.explanation);
    }
    if (comparison?.local) {
      expect(failures, release.tag, comparison.local.schemaVersion === localAuditSchemaVersion,
        `comparison local schemaVersion (${comparison.local.schemaVersion}) must equal ${localAuditSchemaVersion}`);
      for (const [field, expected] of Object.entries({
        score: review.local?.score,
        band: review.local?.band,
        status: review.local?.status,
        recommended: review.local?.recommended,
        reason: review.local?.reason,
        negativeIssues: review.local?.negativeIssues,
        positiveIssues: review.local?.positiveIssues,
        scoredAt: review.local?.scoredAt,
      })) {
        expect(failures, release.tag, comparison.local[field] === expected,
          `comparison local ${field} (${comparison.local[field]}) must match review (${expected})`);
      }
      expectJsonEqual(failures, release.tag, 'comparison local dataFreshness must match review dataFreshness',
        comparison.local.dataFreshness, review.local?.dataFreshness);
      expectJsonEqual(failures, release.tag, 'comparison local explanation must match review explanation',
        comparison.local.components?.explanation, review.local?.components?.explanation);
    }

    const proof = review.local?.gateEvidence?.fixProvenance?.closureProof;
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (proof || credit) {
      const persistedGate = parseJson(reader.getReleaseScoreAudit(release.tag)?.gate_evidence_json, {});
      const persistedFix = persistedGate?.fixProvenance ?? {};
      expect(failures, release.tag, !!proof && !!credit, 'review must expose closureProof and releaseFixCredit together');
      expectJsonEqual(failures, release.tag, 'review closureProof must match persisted audit closureProof',
        proof, persistedFix.closureProof);
      expectJsonEqual(failures, release.tag, 'review releaseFixCredit must match persisted audit releaseFixCredit',
        credit, persistedFix.releaseFixCredit);
      expect(failures, release.tag, proof.schemaVersion === closureProofSchemaVersion,
        `closureProof schemaVersion (${proof.schemaVersion}) must equal ${closureProofSchemaVersion}`);
      expect(failures, release.tag, credit.schemaVersion === releaseFixCreditSchemaVersion,
        `releaseFixCredit schemaVersion (${credit.schemaVersion}) must equal ${releaseFixCreditSchemaVersion}`);
      expect(failures, release.tag, credit.countedClosedCount === proof.creditedCount,
        'releaseFixCredit countedClosedCount must match closureProof creditedCount');
      expect(failures, release.tag, credit.notCountedClosedCount === proof.notCreditedCount,
        'releaseFixCredit notCountedClosedCount must match closureProof notCreditedCount');
      expect(failures, release.tag, credit.analyzedClosedCount === proof.creditedCount + proof.notCreditedCount,
        'releaseFixCredit analyzedClosedCount must equal credited + notCredited');
      if (Array.isArray(credit.decisions)) {
        const decisionCounts = countFixCreditDecisions(credit.decisions);
        expect(failures, release.tag, credit.countedClosedCount === decisionCounts.credited,
          'releaseFixCredit countedClosedCount must equal credited decisions');
        expect(failures, release.tag, credit.containedFixedCount === (proof.byStatus?.fixed_in_release ?? 0),
          'releaseFixCredit containedFixedCount must equal fixed_in_release bucket');
        expect(failures, release.tag, proof.containedFixedCount === (proof.byStatus?.fixed_in_release ?? 0),
          'closureProof containedFixedCount must equal fixed_in_release bucket');
        expect(failures, release.tag, proof.creditedCount <= proof.containedFixedCount,
          'closureProof creditedCount must not exceed containedFixedCount');
        expectJsonEqual(failures, release.tag, 'releaseFixCredit decisionCounts must match decisions',
          credit.decisionCounts, decisionCounts);
      } else {
        expect(failures, release.tag, (proof.byStatus?.fixed_in_release ?? 0) === proof.creditedCount,
          'closureProof creditedCount must equal fixed_in_release bucket');
      }
      expect(failures, release.tag, isObject(proof.byRiskDisposition),
        'closureProof must expose byRiskDisposition');
      expect(failures, release.tag, isObject(proof.riskSummary),
        'closureProof must expose riskSummary');
      if (isObject(proof.byRiskDisposition)) {
        for (const [disposition] of Object.entries(proof.byRiskDisposition)) {
          expect(failures, release.tag, knownRiskDispositions.has(disposition),
            `closureProof byRiskDisposition contains unknown disposition ${disposition}`);
        }
      }
      verifyClosureProofExamplesByStatus({
        failures,
        tag: release.tag,
        proof,
        label: 'closureProof',
      });
      for (const example of proof.examples ?? []) {
        expect(failures, release.tag, isObject(example.rawClassification),
          `closure proof example #${example.number} must expose rawClassification`);
        expect(failures, release.tag, isObject(example.classification),
          `closure proof example #${example.number} must expose effective classification`);
        expect(failures, release.tag, isObject(example.classificationDiff),
          `closure proof example #${example.number} must expose classificationDiff`);
        expect(failures, release.tag, typeof example.riskWeight === 'number',
          `closure proof example #${example.number} must expose numeric riskWeight`);
      }
      for (let i = 1; i < (proof.examples ?? []).length; i++) {
        expect(failures, release.tag,
          Number(proof.examples[i - 1].riskWeight ?? 0) >= Number(proof.examples[i].riskWeight ?? 0),
          'closure proof examples must be sorted by descending riskWeight');
      }
      await verifyClosureProofAuditEndpoint({
        base: resolvePublishedApiUrl(apiBase, publishedAuditLinks.closureProofs),
        fetchJson,
        failures,
        reader,
        proof,
        tag: release.tag,
        scoredAt: release.scored_at,
        publicationSnapshot: publicSnapshotId,
        auditDigest: expectedAuditDigest,
      });
      await verifyPrReachabilityAuditEndpoint({
        base: resolvePublishedApiUrl(apiBase, publishedAuditLinks.reachability),
        fetchJson,
        failures,
        reader,
        tag: release.tag,
        scoredAt: release.scored_at,
        publicationSnapshot: publicSnapshotId,
        auditDigest: expectedAuditDigest,
      });

      if (comparison?.local) {
        const comparisonFix = comparison.local.gateEvidence?.fixProvenance;
        const comparisonProof = comparisonFix?.closureProof;
        const comparisonCredit = comparisonFix?.releaseFixCredit;
        expect(failures, release.tag, !!comparisonProof && !!comparisonCredit,
          'comparison local gateEvidence must expose closureProof and releaseFixCredit when review does');
        expect(failures, release.tag, comparisonCredit?.countedClosedCount === credit.countedClosedCount,
          'comparison countedClosedCount must match review countedClosedCount');
        expect(failures, release.tag, comparisonCredit?.notCountedClosedCount === credit.notCountedClosedCount,
          'comparison notCountedClosedCount must match review notCountedClosedCount');
        expect(failures, release.tag, comparisonProof?.creditedCount === proof.creditedCount,
          'comparison closureProof creditedCount must match review');
        expect(failures, release.tag, comparisonProof?.notCreditedCount === proof.notCreditedCount,
          'comparison closureProof notCreditedCount must match review');
        expectJsonEqual(failures, release.tag, 'comparison closureProof byRiskDisposition must match review',
          comparisonProof?.byRiskDisposition, proof.byRiskDisposition);
        expectJsonEqual(failures, release.tag, 'comparison closureProof riskSummary must match review',
          comparisonProof?.riskSummary, proof.riskSummary);
        expectJsonEqual(failures, release.tag, 'comparison closureProof examplesByStatus must match review',
          comparisonProof?.examplesByStatus, proof.examplesByStatus);
      }
    }
  }
}

function verifyClosureProofExamplesByStatus({ failures, tag, proof, label }) {
  expect(failures, tag, isObject(proof?.examplesByStatus),
    `${label} must expose examplesByStatus`);
  for (const [status, count] of Object.entries(proof?.byStatus ?? {})) {
    if (status === 'fixed_in_release' || Number(count ?? 0) <= 0) continue;
    const statusExamples = proof?.examplesByStatus?.[status];
    expect(failures, tag, Array.isArray(statusExamples) && statusExamples.length > 0,
      `${label} examplesByStatus must include at least one ${status} example`);
    for (const example of statusExamples ?? []) {
      expect(failures, tag, example.status === status,
        `${label} examplesByStatus ${status} contains example with status ${example.status}`);
    }
  }
}

async function verifyIssueEvidenceAuditEndpoint({
  base,
  fetchJson,
  failures,
  reader,
  tag,
  issueEvidence,
  scoredAt,
  publicationSnapshot,
  auditDigest,
}) {
  const fetchBoundPage = async (url, label = 'issue evidence audit page') => {
    const page = await fetchJson(url);
    verifyReviewPageBinding({
      failures,
      tag,
      label,
      page,
      endpoint: 'issues',
      publicationSnapshot,
      auditDigest,
    });
    return page;
  };
  const firstPage = await fetchBoundPage(
    reviewUrlWithQuery(base, [['limit', 11]]),
    'issue evidence audit',
  );
  const invalidFilterCases = [
    ['issue evidence audit invalid tier', reviewUrlWithQuery(base, [['tier', 'not-a-tier']]), 'invalid tier'],
    ['issue evidence audit invalid issue', reviewUrlWithQuery(base, [['issue', 'bad']]), 'invalid issue'],
    ['issue evidence audit repeated issue', reviewUrlWithQuery(base, [['issue', 1], ['issue', 2]]), 'invalid issue'],
    ['issue evidence audit conflicting issue aliases', reviewUrlWithQuery(base, [['issue', 1], ['number', 2]]), 'invalid issue'],
    ['issue evidence audit invalid fieldConfirmed', reviewUrlWithQuery(base, [['fieldConfirmed', 'maybe']]), 'invalid fieldConfirmed'],
    ['issue evidence audit repeated fieldConfirmed', reviewUrlWithQuery(base, [['fieldConfirmed', 'true'], ['fieldConfirmed', 'maybe']]), 'invalid fieldConfirmed'],
    ['issue evidence audit invalid weight range', reviewUrlWithQuery(base, [['minWeight', 10], ['maxWeight', 1]]), 'invalid weight range'],
    ['issue evidence audit repeated minWeight', reviewUrlWithQuery(base, [['minWeight', 1], ['minWeight', 2]]), 'invalid minWeight'],
    ['issue evidence audit invalid sort', reviewUrlWithQuery(base, [['sort', 'not-a-sort']]), 'invalid sort'],
    ['issue evidence audit repeated sort', reviewUrlWithQuery(base, [['sort', 'rank'], ['sort', 'weight']]), 'invalid sort'],
    ['issue evidence audit invalid direction', reviewUrlWithQuery(base, [['direction', 'sideways']]), 'invalid direction'],
    ['issue evidence audit repeated direction', reviewUrlWithQuery(base, [['direction', 'asc'], ['direction', 'desc']]), 'invalid direction'],
    ['issue evidence audit invalid summaryOnly', reviewUrlWithQuery(base, [['summaryOnly', 'wat']]), 'invalid summaryOnly'],
    ['issue evidence audit invalid limit', reviewUrlWithQuery(base, [['limit', 'abc']]), 'invalid limit'],
    ['issue evidence audit decimal limit', reviewUrlWithQuery(base, [['limit', '1.9']]), 'invalid limit'],
    ['issue evidence audit repeated limit', reviewUrlWithQuery(base, [['limit', 1], ['limit', 2]]), 'invalid limit'],
    ['issue evidence audit invalid cursor', reviewUrlWithQuery(base, [['cursor', 'abc']]), 'invalid cursor'],
    ['issue evidence audit decimal cursor', reviewUrlWithQuery(base, [['cursor', '1.9']]), 'invalid cursor'],
    ['issue evidence audit repeated cursor', reviewUrlWithQuery(base, [['cursor', 0], ['cursor', 1]]), 'invalid cursor'],
  ];
  for (const [label, url, error] of invalidFilterCases) {
    await expectFetchJsonStatus({
      failures,
      tag,
      fetchJson,
      url,
      status: 400,
      label,
      payloadCheck: (payload) => payload?.error === error,
    });
  }
  expect(failures, tag, firstPage.schemaVersion === issueEvidenceAuditSchemaVersion,
    `issue evidence audit schemaVersion must be ${issueEvidenceAuditSchemaVersion}, got ${JSON.stringify(firstPage.schemaVersion)}`);
  verifyAllowedKeys({ failures, tag, label: 'issue evidence audit payload', value: firstPage, allowed: issueEvidenceAuditKeys });
  verifyAllowedKeys({ failures, tag, label: 'issue evidence audit filters', value: firstPage.filters, allowed: issueEvidenceAuditFilterKeys });
  verifyAllowedKeys({ failures, tag, label: 'issue evidence audit totals', value: firstPage.totals, allowed: issueEvidenceAuditTotalsKeys });
  expect(failures, tag, firstPage.tag === tag,
    `issue evidence audit tag (${firstPage.tag}) must match release tag (${tag})`);
  expect(failures, tag, firstPage.sourceMode === 'current_db',
    `issue evidence audit sourceMode (${firstPage.sourceMode}) must be current_db`);
  expect(failures, tag, firstPage.scoredAt === scoredAt,
    `issue evidence audit scoredAt (${firstPage.scoredAt}) must match DB scored_at (${scoredAt})`);
  verifyDataFreshness({
    failures,
    tag,
    dataFreshness: firstPage.dataFreshness,
    releaseTag: tag,
    scoredAt,
    reader,
  });
  expect(failures, tag, firstPage.limit === 11,
    `issue evidence audit limit must be 11, got ${firstPage.limit}`);
  expect(failures, tag, firstPage.cursor === 0,
    `issue evidence audit cursor must be 0, got ${firstPage.cursor}`);
  expect(failures, tag, isObject(firstPage.countsByTier),
    'issue evidence audit countsByTier must be an object');
  expect(failures, tag, isObject(firstPage.summaryByTier),
    'issue evidence audit summaryByTier must be an object');
  expect(failures, tag, isObject(firstPage.filteredSummary),
    'issue evidence audit filteredSummary must be an object');
  expect(failures, tag, firstPage.filters?.sort === 'rank',
    `issue evidence audit default sort (${firstPage.filters?.sort}) must be rank`);
  expect(failures, tag, firstPage.filters?.direction === 'asc',
    `issue evidence audit default direction (${firstPage.filters?.direction}) must be asc`);
  expect(failures, tag, firstPage.filters?.summaryOnly === false,
    `issue evidence audit default summaryOnly (${firstPage.filters?.summaryOnly}) must be false`);
  expectJsonEqual(failures, tag, 'issue evidence audit tierInfo must match shared tier metadata',
    firstPage.tierInfo, RELEASE_ISSUE_EVIDENCE_TIER_INFO);
  for (const [tier, count] of Object.entries(firstPage.countsByTier ?? {})) {
    expect(failures, tag, knownIssueEvidenceTiers.has(tier),
      `issue evidence audit countsByTier contains unknown tier ${tier}`);
    expect(failures, tag, Number.isInteger(count) && count >= 0,
      `issue evidence audit count for ${tier} must be a non-negative integer`);
    const summary = firstPage.summaryByTier?.[tier];
    expect(failures, tag, isObject(summary),
      `issue evidence audit summaryByTier.${tier} must be an object`);
    expect(failures, tag, summary?.count === count,
      `issue evidence audit summaryByTier.${tier}.count (${summary?.count}) must match countsByTier (${count})`);
    expect(failures, tag, typeof summary?.weight === 'number',
      `issue evidence audit summaryByTier.${tier}.weight must be numeric`);
  }
  const countSum = Object.values(firstPage.countsByTier ?? {}).reduce((sum, count) => sum + Number(count ?? 0), 0);
  expect(failures, tag, firstPage.total === countSum,
    `issue evidence audit total (${firstPage.total}) must equal countsByTier sum (${countSum})`);
  expect(failures, tag, firstPage.totalRows === firstPage.total,
    `issue evidence audit totalRows (${firstPage.totalRows}) must match filtered total (${firstPage.total})`);
  expect(failures, tag, isObject(firstPage.totals),
    'issue evidence audit totals must be an object');
  expect(failures, tag, firstPage.totals?.unfilteredRows === countSum,
    `issue evidence audit totals.unfilteredRows (${firstPage.totals?.unfilteredRows}) must equal countsByTier sum (${countSum})`);
  expect(failures, tag, firstPage.totals?.filteredRows === firstPage.total,
    `issue evidence audit totals.filteredRows (${firstPage.totals?.filteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, Number.isInteger(firstPage.distinctIssueCount) && firstPage.distinctIssueCount >= 0,
    `issue evidence audit distinctIssueCount (${firstPage.distinctIssueCount}) must be a non-negative integer`);
  expect(failures, tag, firstPage.totals?.filteredDistinctIssues === firstPage.distinctIssueCount,
    `issue evidence audit totals.filteredDistinctIssues (${firstPage.totals?.filteredDistinctIssues}) must match distinctIssueCount (${firstPage.distinctIssueCount})`);
  expectJsonEqual(failures, tag, 'issue evidence audit unfilteredCountsByTier must match countsByTier',
    firstPage.unfilteredCountsByTier, firstPage.countsByTier);
  expectJsonEqual(failures, tag, 'issue evidence audit filteredCountsByTier must match unfiltered counts without filters',
    firstPage.filteredCountsByTier, firstPage.countsByTier);
  expectJsonEqual(failures, tag, 'issue evidence audit unfilteredSummaryByTier must match summaryByTier',
    firstPage.unfilteredSummaryByTier, firstPage.summaryByTier);
  expectJsonEqual(failures, tag, 'issue evidence audit filteredSummaryByTier must match summaryByTier without filters',
    firstPage.filteredSummaryByTier, firstPage.summaryByTier);
  expect(failures, tag, firstPage.filteredSummary?.count === firstPage.total,
    `issue evidence audit filteredSummary count (${firstPage.filteredSummary?.count}) must match total (${firstPage.total})`);
  expect(failures, tag, Array.isArray(firstPage.rows),
    'issue evidence audit rows must be an array');
  expect(failures, tag, firstPage.rows.length <= 11,
    `issue evidence audit rows length must respect limit, got ${firstPage.rows.length}`);
  const issueAuditRows = await collectExhaustiveAuditPages({
    base,
    firstPage,
    fetchJson: fetchBoundPage,
    failures,
    tag,
    label: 'issue evidence audit',
    limit: 11,
    identity: (row) => `${row?.tier}:${row?.issue?.number ?? 'missing'}`,
    expectedIdentities: expectedIssueEvidenceAuditIdentities({
      reader,
      tag,
      issueEvidence,
    }),
    validatePage: (page) => {
      expect(failures, tag, page.schemaVersion === issueEvidenceAuditSchemaVersion,
        `issue evidence audit page schemaVersion must be ${issueEvidenceAuditSchemaVersion}`);
      verifyAllowedKeys({
        failures,
        tag,
        label: 'issue evidence audit payload',
        value: page,
        allowed: issueEvidenceAuditKeys,
      });
      expect(failures, tag, page.tag === tag,
        `issue evidence audit page tag (${page.tag}) must match ${tag}`);
      expect(failures, tag, page.sourceMode === 'current_db',
        `issue evidence audit page sourceMode (${page.sourceMode}) must be current_db`);
      expect(failures, tag, page.scoredAt === scoredAt,
        `issue evidence audit page scoredAt (${page.scoredAt}) must match ${scoredAt}`);
    },
  });
  const issueExample = (firstPage.rows ?? []).find((row) => Number.isInteger(row?.issue?.number) && row.issue.number > 0);
  if (issueExample) {
    const issuePage = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['issue', issueExample.issue.number],
      ['summaryOnly', 'true'],
    ]));
    expect(failures, tag, issuePage.filters?.issue === issueExample.issue.number,
      `issue evidence audit issue filter echo (${issuePage.filters?.issue}) must match ${issueExample.issue.number}`);
    expect(failures, tag, issuePage.filters?.issueNumber === issueExample.issue.number,
      `issue evidence audit issueNumber filter echo (${issuePage.filters?.issueNumber}) must match ${issueExample.issue.number}`);
    expect(failures, tag, issuePage.total >= 1,
      `issue evidence audit issue filter for #${issueExample.issue.number} must return at least one row`);
    const issueRows = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['issue', issueExample.issue.number],
      ['limit', 10],
    ]));
    expect(failures, tag, (issueRows.rows ?? []).every((row) => row.issue?.number === issueExample.issue.number),
      `issue evidence audit issue filter must return only #${issueExample.issue.number} rows`);
  }
  const summaryOnlyPage = await fetchBoundPage(reviewUrlWithQuery(base, [
    ['summaryOnly', 'true'],
    ['tier', 'carryoverDebt,staleDebt'],
  ]));
  const expectedSummaryOnlyTotal = Number(firstPage.countsByTier?.carryoverDebt ?? 0) + Number(firstPage.countsByTier?.staleDebt ?? 0);
  expect(failures, tag, summaryOnlyPage.filters?.summaryOnly === true,
    `issue evidence audit summaryOnly echo (${summaryOnlyPage.filters?.summaryOnly}) must be true`);
  expect(failures, tag, summaryOnlyPage.limit === 0,
    `issue evidence audit summaryOnly limit (${summaryOnlyPage.limit}) must be 0`);
  expect(failures, tag, summaryOnlyPage.cursor === 0,
    `issue evidence audit summaryOnly cursor (${summaryOnlyPage.cursor}) must be 0`);
  expect(failures, tag, summaryOnlyPage.nextCursor == null,
    `issue evidence audit summaryOnly nextCursor (${summaryOnlyPage.nextCursor}) must be null`);
  expect(failures, tag, Array.isArray(summaryOnlyPage.rows) && summaryOnlyPage.rows.length === 0,
    'issue evidence audit summaryOnly rows must be empty');
  expect(failures, tag, summaryOnlyPage.total === expectedSummaryOnlyTotal,
    `issue evidence audit summaryOnly total (${summaryOnlyPage.total}) must match selected tier counts (${expectedSummaryOnlyTotal})`);
  expect(failures, tag, summaryOnlyPage.totals?.unfilteredRows === countSum,
    `issue evidence audit summaryOnly unfilteredRows (${summaryOnlyPage.totals?.unfilteredRows}) must match unfiltered total (${countSum})`);
  expect(failures, tag, summaryOnlyPage.totals?.filteredRows === summaryOnlyPage.total,
    `issue evidence audit summaryOnly filteredRows (${summaryOnlyPage.totals?.filteredRows}) must match total (${summaryOnlyPage.total})`);
  expect(failures, tag, summaryOnlyPage.totalRows === summaryOnlyPage.total,
    `issue evidence audit summaryOnly totalRows (${summaryOnlyPage.totalRows}) must match total (${summaryOnlyPage.total})`);
  expect(failures, tag, summaryOnlyPage.filteredSummary?.count === summaryOnlyPage.total,
    `issue evidence audit summaryOnly filteredSummary count (${summaryOnlyPage.filteredSummary?.count}) must match total (${summaryOnlyPage.total})`);

  for (const row of issueAuditRows) {
    verifyAllowedKeys({ failures, tag, label: 'issue evidence audit row', value: row, allowed: issueEvidenceAuditRowKeys });
    verifyConfirmationReasons({
      failures,
      tag,
      path: 'issue evidence audit row confirmationReasons',
      value: row.confirmationReasons,
    });
    expect(failures, tag, knownIssueEvidenceTiers.has(row.tier),
      `issue evidence audit row tier must be known, got ${row.tier}`);
    const tierInfo = RELEASE_ISSUE_EVIDENCE_TIER_INFO[row.tier];
    expect(failures, tag, row.tierLabel === tierInfo?.label,
      `issue evidence audit row ${row.tier} tierLabel (${row.tierLabel}) must match ${tierInfo?.label}`);
    expect(failures, tag, row.tierDescription === tierInfo?.description,
      `issue evidence audit row ${row.tier} tierDescription must match shared metadata`);
    expect(failures, tag, isObject(row.issue),
      `issue evidence audit row ${row.tier} must expose issue object`);
    verifyAllowedKeys({ failures, tag, label: 'issue evidence audit row issue', value: row.issue, allowed: issueEvidenceIssueKeys });
    expect(failures, tag,
      Number.isInteger(row.issue?.number) && row.issue.number > 0 || row.issue?.missing === true,
      `issue evidence audit row ${row.tier} issue number must be positive or explicitly missing`);
    if (row.issue?.missing !== true) {
      expect(failures, tag, typeof row.issue?.title === 'string' && row.issue.title.length > 0,
        `issue evidence audit row #${row.issue?.number} title must be present`);
      expect(failures, tag, Array.isArray(row.issue?.labels),
        `issue evidence audit row #${row.issue?.number} labels must be an array`);
      if (['verifiedDebt', 'carryoverDebt', 'staleDebt', 'openedFeltSerious', 'verifiedFixed', 'unverifiedClosed'].includes(row.tier)) {
        expect(failures, tag, isObject(row.issue?.classification),
          `issue evidence audit row #${row.issue?.number} must expose effective classification`);
        expect(failures, tag, isObject(row.issue?.rawClassification),
          `issue evidence audit row #${row.issue?.number} must expose raw classification`);
        expect(failures, tag, isObject(row.issue?.classificationDiff),
          `issue evidence audit row #${row.issue?.number} must expose classificationDiff`);
      }
    }
    if (['verifiedDebt', 'carryoverDebt', 'staleDebt'].includes(row.tier)) {
      expect(failures, tag, typeof row.weight === 'number' && Number.isFinite(row.weight),
        `issue evidence audit debt row #${row.issue?.number} must expose numeric weight`);
      expect(failures, tag, typeof row.installImpactClass === 'string' && row.installImpactClass.length > 0,
        `issue evidence audit debt row #${row.issue?.number} must expose installImpactClass`);
      if (row.debtClassification != null) {
        expect(failures, tag, isObject(row.debtClassification),
          `issue evidence audit debt row #${row.issue?.number} debtClassification must be an object`);
      }
      if (row.debtClassificationDiff != null) {
        expect(failures, tag, isObject(row.debtClassificationDiff),
          `issue evidence audit debt row #${row.issue?.number} debtClassificationDiff must be an object`);
      }
    }
  }

  const expectedDebtCounts = {
    verifiedDebt: Number(issueEvidence?.debtSummary?.verified?.count ?? 0),
    carryoverDebt: Number(issueEvidence?.debtSummary?.carryover?.count ?? 0),
    staleDebt: Number(issueEvidence?.debtSummary?.stale?.count ?? 0),
  };
  for (const [tier, expected] of Object.entries(expectedDebtCounts)) {
    if (!Number.isFinite(expected)) continue;
    expect(failures, tag, Number(firstPage.countsByTier?.[tier] ?? 0) === expected,
      `issue evidence audit ${tier} count (${firstPage.countsByTier?.[tier]}) must match persisted debtSummary count (${expected})`);
  }
  if (typeof reader.verifiedFixedForRelease === 'function') {
    const expected = reader.verifiedFixedForRelease(tag).length;
    expect(failures, tag, Number(firstPage.countsByTier?.verifiedFixed ?? 0) === expected,
      `issue evidence audit verifiedFixed count (${firstPage.countsByTier?.verifiedFixed}) must match DB verified fixed (${expected})`);
  }
  if (typeof reader.unverifiedClosedForRelease === 'function') {
    const expected = reader.unverifiedClosedForRelease(tag).length;
    expect(failures, tag, Number(firstPage.countsByTier?.unverifiedClosed ?? 0) === expected,
      `issue evidence audit unverifiedClosed count (${firstPage.countsByTier?.unverifiedClosed}) must match DB unverified closed (${expected})`);
  }

  const tiersToProbe = Object.entries(firstPage.countsByTier ?? {})
    .filter(([, count]) => Number(count ?? 0) > 0)
    .slice(0, 3);
  for (const [tier, count] of tiersToProbe) {
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['tier', tier],
    ]));
    expect(failures, tag, page.total === Number(count),
      `issue evidence audit tier filter total (${page.total}) must match ${tier} count (${count})`);
    expect(failures, tag, page.totals?.unfilteredRows === countSum,
      `issue evidence audit tier filter unfilteredRows (${page.totals?.unfilteredRows}) must match unfiltered total (${countSum})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `issue evidence audit tier filter filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filteredCountsByTier?.[tier] === Number(count),
      `issue evidence audit filteredCountsByTier.${tier} (${page.filteredCountsByTier?.[tier]}) must match ${count}`);
    expect(failures, tag, page.filteredSummaryByTier?.[tier]?.count === Number(count),
      `issue evidence audit filteredSummaryByTier.${tier}.count (${page.filteredSummaryByTier?.[tier]?.count}) must match ${count}`);
    expect(failures, tag, page.filters?.tier === tier,
      `issue evidence audit tier filter echo (${page.filters?.tier}) must equal ${tier}`);
    expect(failures, tag, Array.isArray(page.filters?.tiers) && page.filters.tiers.length === 1 && page.filters.tiers[0] === tier,
      `issue evidence audit tiers filter echo must contain only ${tier}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit filteredSummary count (${page.filteredSummary?.count}) must match filtered total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.tier === tier),
      `issue evidence audit tier filter must return only ${tier} rows`);
  }
  if (tiersToProbe.length >= 2) {
    const selected = tiersToProbe.slice(0, 2);
    const tierParam = selected.map(([tier]) => tier).join(',');
    const expectedTotal = selected.reduce((sum, [, count]) => sum + Number(count), 0);
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['tier', tierParam],
    ]));
    expect(failures, tag, page.total === expectedTotal,
      `issue evidence audit multi-tier filter total (${page.total}) must match selected tier counts (${expectedTotal})`);
    expect(failures, tag, page.totals?.unfilteredRows === countSum,
      `issue evidence audit multi-tier unfilteredRows (${page.totals?.unfilteredRows}) must match unfiltered total (${countSum})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `issue evidence audit multi-tier filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filters?.tier == null,
      'issue evidence audit multi-tier filter must not echo singular tier');
    expectJsonEqual(failures, tag, 'issue evidence audit multi-tier filter echo',
      page.filters?.tiers, selected.map(([tier]) => tier));
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit multi-tier filteredSummary count (${page.filteredSummary?.count}) must match filtered total (${page.total})`);
    const selectedSet = new Set(selected.map(([tier]) => tier));
    expect(failures, tag, (page.rows ?? []).every((row) => selectedSet.has(row.tier)),
      `issue evidence audit multi-tier filter must return only ${tierParam} rows`);
  }
  const impactToProbe = Object.entries(firstPage.summaryByTier ?? {})
    .flatMap(([, summary]) => Object.entries(summary?.byInstallImpactClass ?? {}))
    .find(([, count]) => Number(count ?? 0) > 0)?.[0] ?? null;
  if (impactToProbe) {
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['impact', impactToProbe],
    ]));
    expect(failures, tag, page.filters?.impact === impactToProbe,
      `issue evidence audit impact filter echo (${page.filters?.impact}) must equal ${impactToProbe}`);
    expect(failures, tag, Array.isArray(page.filters?.impacts) && page.filters.impacts.length === 1 && page.filters.impacts[0] === impactToProbe,
      `issue evidence audit impacts filter echo must contain only ${impactToProbe}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit impact filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.installImpactClass === impactToProbe),
      `issue evidence audit impact filter must return only ${impactToProbe} rows`);
  }
  const stateToProbe = (firstPage.rows ?? []).find((row) => row.issue?.state === 'open' || row.issue?.state === 'closed')?.issue?.state ?? null;
  if (stateToProbe) {
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['state', stateToProbe],
    ]));
    expect(failures, tag, page.filters?.state === stateToProbe,
      `issue evidence audit state filter echo (${page.filters?.state}) must equal ${stateToProbe}`);
    expect(failures, tag, Array.isArray(page.filters?.states) && page.filters.states.length === 1 && page.filters.states[0] === stateToProbe,
      `issue evidence audit states filter echo must contain only ${stateToProbe}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit state filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.issue?.state === stateToProbe),
      `issue evidence audit state filter must return only ${stateToProbe} rows`);
  }
  const classificationFilters = [
    ['sentiment', 'sentiments'],
    ['severity', 'severities'],
    ['functionality', 'functionalities'],
    ['scope', 'scopes'],
    ['affectedUsers', 'affectedUsersList'],
  ];
  for (const [field, pluralField] of classificationFilters) {
    const value = (firstPage.rows ?? [])
      .map((row) => row.issue?.classification?.[field])
      .find((candidate) => typeof candidate === 'string');
    if (!value) continue;
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      [field, value],
    ]));
    expect(failures, tag, page.filters?.[field] === value,
      `issue evidence audit ${field} filter echo (${page.filters?.[field]}) must equal ${value}`);
    expect(failures, tag, Array.isArray(page.filters?.[pluralField]) && page.filters[pluralField].length === 1 && page.filters[pluralField][0] === value,
      `issue evidence audit ${pluralField} filter echo must contain only ${value}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit ${field} filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.issue?.classification?.[field] === value),
      `issue evidence audit ${field} filter must return only ${value} rows`);
  }
  const fieldConfirmedProbe = (firstPage.rows ?? []).find((row) => row.fieldConfirmed === true || row.fieldConfirmed === false);
  if (fieldConfirmedProbe) {
    const value = fieldConfirmedProbe.fieldConfirmed === true ? 'true' : 'false';
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['fieldConfirmed', value],
    ]));
    expect(failures, tag, page.filters?.fieldConfirmed === fieldConfirmedProbe.fieldConfirmed,
      `issue evidence audit fieldConfirmed filter echo (${page.filters?.fieldConfirmed}) must equal ${fieldConfirmedProbe.fieldConfirmed}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit fieldConfirmed filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.fieldConfirmed === fieldConfirmedProbe.fieldConfirmed),
      `issue evidence audit fieldConfirmed filter must return only ${value} rows`);
  }
  const weightedProbe = (firstPage.rows ?? []).find((row) => typeof row.weight === 'number' && Number.isFinite(row.weight));
  if (weightedProbe) {
    const minWeight = Math.max(0, Math.floor(Number(weightedProbe.weight)));
    const maxWeight = Math.ceil(Number(weightedProbe.weight));
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['minWeight', minWeight],
      ['maxWeight', maxWeight],
    ]));
    expect(failures, tag, page.filters?.minWeight === minWeight,
      `issue evidence audit minWeight filter echo (${page.filters?.minWeight}) must equal ${minWeight}`);
    expect(failures, tag, page.filters?.maxWeight === maxWeight,
      `issue evidence audit maxWeight filter echo (${page.filters?.maxWeight}) must equal ${maxWeight}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit weight filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) =>
      Number(row.weight ?? 0) >= minWeight && Number(row.weight ?? 0) <= maxWeight),
    `issue evidence audit weight filter must return only rows between ${minWeight} and ${maxWeight}`);
  }
  const weightSorted = await fetchBoundPage(reviewUrlWithQuery(base, [
    ['limit', 7],
    ['sort', 'weight'],
    ['direction', 'desc'],
  ]));
  expect(failures, tag, weightSorted.filters?.sort === 'weight',
    `issue evidence audit sort echo (${weightSorted.filters?.sort}) must be weight`);
  expect(failures, tag, weightSorted.filters?.direction === 'desc',
    `issue evidence audit direction echo (${weightSorted.filters?.direction}) must be desc`);
  expect(failures, tag, isNonIncreasing((weightSorted.rows ?? []).map((row) => Number(row.weight ?? 0))),
    'issue evidence audit weight desc sort must be non-increasing');
  const numberSorted = await fetchBoundPage(reviewUrlWithQuery(base, [
    ['limit', 7],
    ['sort', 'number'],
    ['direction', 'asc'],
  ]));
  expect(failures, tag, numberSorted.filters?.sort === 'number',
    `issue evidence audit sort echo (${numberSorted.filters?.sort}) must be number`);
  expect(failures, tag, numberSorted.filters?.direction === 'asc',
    `issue evidence audit direction echo (${numberSorted.filters?.direction}) must be asc`);
  expect(failures, tag, isNonDecreasing((numberSorted.rows ?? []).map((row) => Number(row.issue?.number ?? 0))),
    'issue evidence audit number asc sort must be non-decreasing');
  const closedSorted = await fetchBoundPage(reviewUrlWithQuery(base, [
    ['limit', 25],
    ['state', 'open,closed'],
    ['sort', 'closed'],
    ['direction', 'desc'],
  ]));
  expect(failures, tag, closedSorted.filters?.sort === 'closed',
    `issue evidence audit sort echo (${closedSorted.filters?.sort}) must be closed`);
  expect(failures, tag, closedSorted.filters?.direction === 'desc',
    `issue evidence audit direction echo (${closedSorted.filters?.direction}) must be desc`);
  const closedTimestamps = (closedSorted.rows ?? []).map((row) => timestampOrNull(row.issue?.closedAt));
  expect(failures, tag, sortValuesKeepMissingLast(closedTimestamps, 'desc'),
    'issue evidence audit closed desc sort must be non-increasing with missing closedAt values last');
  if (
    Number(closedSorted.filteredSummary?.openCount ?? 0) > 0 &&
    Number(closedSorted.filteredSummary?.closedCount ?? 0) > 0 &&
    (closedSorted.rows ?? []).length > 0
  ) {
    expect(failures, tag, closedTimestamps[0] != null,
      'issue evidence audit closed desc sort must not put open issues before closed issues with close timestamps');
  }
}

function isNonIncreasing(values) {
  for (let i = 1; i < values.length; i++) {
    if (values[i - 1] < values[i]) return false;
  }
  return true;
}

function isNonDecreasing(values) {
  for (let i = 1; i < values.length; i++) {
    if (values[i - 1] > values[i]) return false;
  }
  return true;
}

function sortValuesKeepMissingLast(values, direction) {
  let sawMissing = false;
  let previous = null;
  for (const value of values) {
    const missing = value == null || Number.isNaN(value);
    if (missing) {
      sawMissing = true;
      continue;
    }
    if (sawMissing) return false;
    if (previous != null) {
      if (direction === 'asc' && previous > value) return false;
      if (direction === 'desc' && previous < value) return false;
    }
    previous = value;
  }
  return true;
}

function timestampOrNull(value) {
  if (typeof value !== 'string') return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

async function verifyClosureProofAuditEndpoint({
  base,
  fetchJson,
  failures,
  reader,
  tag,
  proof,
  scoredAt,
  publicationSnapshot,
  auditDigest,
}) {
  const fetchBoundPage = async (url, label = 'closure proof audit page') => {
    const page = await fetchJson(url);
    verifyReviewPageBinding({
      failures,
      tag,
      label,
      page,
      endpoint: 'closureProofs',
      publicationSnapshot,
      auditDigest,
    });
    return page;
  };
  const firstPage = await fetchBoundPage(
    reviewUrlWithQuery(base, [['limit', 5]]),
    'closure proof audit',
  );
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: reviewUrlWithQuery(base, [['status', 'fixed-in-release']]),
    status: 400,
    label: 'closure proof audit invalid status',
    payloadCheck: (payload) => payload?.error === 'invalid status' && Array.isArray(payload.allowedStatuses),
  });
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: reviewUrlWithQuery(base, [
      ['status', 'fixed_in_release'],
      ['status', 'closed_without_release_fix_proof'],
    ]),
    status: 400,
    label: 'closure proof audit repeated status',
    payloadCheck: (payload) => payload?.error === 'invalid status' && Array.isArray(payload.allowedStatuses),
  });
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: reviewUrlWithQuery(base, [['riskDisposition', 'not-a-real-disposition']]),
    status: 400,
    label: 'closure proof audit invalid riskDisposition',
    payloadCheck: (payload) => payload?.error === 'invalid riskDisposition' && Array.isArray(payload.allowedRiskDispositions),
  });
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: reviewUrlWithQuery(base, [
      ['riskDisposition', 'credited_release_fix'],
      ['riskDisposition', 'known_not_in_release'],
    ]),
    status: 400,
    label: 'closure proof audit repeated riskDisposition',
    payloadCheck: (payload) => payload?.error === 'invalid riskDisposition' && Array.isArray(payload.allowedRiskDispositions),
  });
  for (const [label, url, error] of [
    ['closure proof audit invalid issue', reviewUrlWithQuery(base, [['issue', 'bad']]), 'invalid issue'],
    ['closure proof audit repeated issue', reviewUrlWithQuery(base, [['issue', 1], ['issue', 2]]), 'invalid issue'],
    ['closure proof audit conflicting issue aliases', reviewUrlWithQuery(base, [['issue', 1], ['number', 2]]), 'invalid issue'],
    ['closure proof audit invalid limit', reviewUrlWithQuery(base, [['limit', 'abc']]), 'invalid limit'],
    ['closure proof audit decimal limit', reviewUrlWithQuery(base, [['limit', '1.9']]), 'invalid limit'],
    ['closure proof audit repeated limit', reviewUrlWithQuery(base, [['limit', 1], ['limit', 2]]), 'invalid limit'],
    ['closure proof audit invalid cursor', reviewUrlWithQuery(base, [['cursor', 'abc']]), 'invalid cursor'],
    ['closure proof audit decimal cursor', reviewUrlWithQuery(base, [['cursor', '1.9']]), 'invalid cursor'],
    ['closure proof audit repeated cursor', reviewUrlWithQuery(base, [['cursor', 0], ['cursor', 1]]), 'invalid cursor'],
  ]) {
    await expectFetchJsonStatus({
      failures,
      tag,
      fetchJson,
      url,
      status: 400,
      label,
      payloadCheck: (payload) => payload?.error === error,
    });
  }
  expect(failures, tag, firstPage.schemaVersion === closureProofAuditSchemaVersion,
    `closure proof audit schemaVersion must be ${closureProofAuditSchemaVersion}, got ${JSON.stringify(firstPage.schemaVersion)}`);
  verifyAllowedKeys({ failures, tag, label: 'closure proof audit payload', value: firstPage, allowed: closureProofAuditKeys });
  verifyAllowedKeys({ failures, tag, label: 'closure proof audit filters', value: firstPage.filters, allowed: closureProofAuditFilterKeys });
  verifyAllowedKeys({ failures, tag, label: 'closure proof audit totals', value: firstPage.totals, allowed: closureProofAuditTotalsKeys });
  expect(failures, tag, firstPage.tag === tag,
    `closure proof audit tag (${firstPage.tag}) must match release tag (${tag})`);
  expect(failures, tag, firstPage.sourceMode === 'current_db',
    `closure proof audit sourceMode (${firstPage.sourceMode}) must be current_db`);
  expect(failures, tag, firstPage.scoredAt === scoredAt,
    `closure proof audit scoredAt (${firstPage.scoredAt}) must match DB scored_at (${scoredAt})`);
  verifyDataFreshness({
    failures,
    tag,
    dataFreshness: firstPage.dataFreshness,
    releaseTag: tag,
    scoredAt,
    reader,
  });
  expect(failures, tag, firstPage.total === proof.creditedCount + proof.notCreditedCount,
    `closure proof audit total (${firstPage.total}) must match analyzed proof count (${proof.creditedCount + proof.notCreditedCount})`);
  expect(failures, tag, firstPage.totalRows === firstPage.total,
    `closure proof audit totalRows (${firstPage.totalRows}) must match total (${firstPage.total})`);
  expect(failures, tag, isObject(firstPage.totals),
    'closure proof audit totals must be an object');
  expect(failures, tag, firstPage.totals?.unfilteredRows === firstPage.total,
    `closure proof audit totals.unfilteredRows (${firstPage.totals?.unfilteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, firstPage.totals?.filteredRows === firstPage.total,
    `closure proof audit totals.filteredRows (${firstPage.totals?.filteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, firstPage.totals?.filteredDistinctIssues === firstPage.distinctIssueCount,
    `closure proof audit filteredDistinctIssues (${firstPage.totals?.filteredDistinctIssues}) must match distinctIssueCount (${firstPage.distinctIssueCount})`);
  expectJsonEqual(failures, tag, 'closure proof audit unfilteredCountsByStatus must match proof byStatus',
    firstPage.unfilteredCountsByStatus ?? {}, proof.byStatus ?? {});
  expectJsonEqual(failures, tag, 'closure proof audit filteredCountsByStatus must match proof byStatus without filters',
    firstPage.filteredCountsByStatus ?? {}, proof.byStatus ?? {});
  expectJsonEqual(failures, tag, 'closure proof audit unfilteredCountsByRiskDisposition must match proof byRiskDisposition',
    firstPage.unfilteredCountsByRiskDisposition ?? {}, proof.byRiskDisposition ?? {});
  expectJsonEqual(failures, tag, 'closure proof audit filteredCountsByRiskDisposition must match proof byRiskDisposition without filters',
    firstPage.filteredCountsByRiskDisposition ?? {}, proof.byRiskDisposition ?? {});
  expect(failures, tag, firstPage.limit === 5, `closure proof audit limit must be 5, got ${firstPage.limit}`);
  expect(failures, tag, firstPage.cursor === 0, `closure proof audit cursor must be 0, got ${firstPage.cursor}`);
  expect(failures, tag, Array.isArray(firstPage.rows), 'closure proof audit rows must be an array');
  expect(failures, tag, firstPage.rows.length <= 5, `closure proof audit rows length must respect limit, got ${firstPage.rows.length}`);
  const proofRows = typeof reader.proofRowsFor === 'function'
    ? reader.proofRowsFor(tag)
    : [];
  const expectedClosureAuditRows = closureAuditRowsFromReader({
    failures,
    tag,
    reader,
    rows: proofRows,
  });
  const closureAuditRows = await collectExhaustiveAuditPages({
    base,
    firstPage,
    fetchJson: fetchBoundPage,
    failures,
    tag,
    label: 'closure proof audit',
    limit: 5,
    identity: (row) => `${row?.issueNumber}:${row?.status}`,
    expectedIdentities: proofRows.map((row) => `${row.issue_number}:${row.status}`),
    expectedRows: expectedClosureAuditRows,
    validatePage: (page) => {
      expect(failures, tag, page.schemaVersion === closureProofAuditSchemaVersion,
        `closure proof audit page schemaVersion must be ${closureProofAuditSchemaVersion}`);
      verifyAllowedKeys({
        failures,
        tag,
        label: 'closure proof audit payload',
        value: page,
        allowed: closureProofAuditKeys,
      });
      expect(failures, tag, page.tag === tag,
        `closure proof audit page tag (${page.tag}) must match ${tag}`);
      expect(failures, tag, page.sourceMode === 'current_db',
        `closure proof audit page sourceMode (${page.sourceMode}) must be current_db`);
      expect(failures, tag, page.scoredAt === scoredAt,
        `closure proof audit page scoredAt (${page.scoredAt}) must match ${scoredAt}`);
    },
  });
  const proofIssueExample = (firstPage.rows ?? []).find((row) => Number.isInteger(row?.issueNumber) && row.issueNumber > 0);
  if (proofIssueExample) {
    const issuePage = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['issue', proofIssueExample.issueNumber],
    ]));
    expect(failures, tag, issuePage.filters?.issue === proofIssueExample.issueNumber,
      `closure proof audit issue filter echo (${issuePage.filters?.issue}) must match ${proofIssueExample.issueNumber}`);
    expect(failures, tag, issuePage.filters?.issueNumber === proofIssueExample.issueNumber,
      `closure proof audit issueNumber filter echo (${issuePage.filters?.issueNumber}) must match ${proofIssueExample.issueNumber}`);
    expect(failures, tag, issuePage.total === 1,
      `closure proof audit issue filter for #${proofIssueExample.issueNumber} must return exactly one proof row`);
    expect(failures, tag, (issuePage.rows ?? []).every((row) => row.issueNumber === proofIssueExample.issueNumber),
      `closure proof audit issue filter must return only #${proofIssueExample.issueNumber} rows`);
  }
  for (const row of closureAuditRows) {
    verifyAllowedKeys({ failures, tag, label: 'closure proof audit row', value: row, allowed: closureProofAuditRowKeys });
    expect(failures, tag, Number.isInteger(row.issueNumber) && row.issueNumber > 0,
      `closure proof audit row issueNumber must be positive integer, got ${row.issueNumber}`);
    expect(failures, tag, typeof row.status === 'string' && knownProofStatuses.has(row.status),
      `closure proof audit row status must be known, got ${row.status}`);
    expect(failures, tag, typeof row.summary === 'string' && row.summary.length > 0,
      `closure proof audit row #${row.issueNumber} summary must be present`);
    expect(failures, tag, typeof row.riskDisposition === 'string' && knownRiskDispositions.has(row.riskDisposition),
      `closure proof audit row #${row.issueNumber} riskDisposition must be known, got ${row.riskDisposition}`);
    expect(failures, tag, typeof row.riskDispositionLabel === 'string' && row.riskDispositionLabel.length > 0,
      `closure proof audit row #${row.issueNumber} riskDispositionLabel must be present`);
    expect(failures, tag, typeof row.riskWeight === 'number',
      `closure proof audit row #${row.issueNumber} riskWeight must be numeric`);
    expect(failures, tag, typeof row.riskWeightLabel === 'string' && row.riskWeightLabel.length > 0,
      `closure proof audit row #${row.issueNumber} riskWeightLabel must be present`);
    expect(failures, tag, isObject(row.evidence),
      `closure proof audit row #${row.issueNumber} evidence must be present`);
    verifyAllowedKeys({ failures, tag, label: 'closure proof audit row evidence', value: row.evidence, allowed: closureProofAuditEvidenceKeys });
    for (const pr of row.evidence?.linkedPrs ?? []) {
      verifyAllowedKeys({ failures, tag, label: 'closure proof audit linked PR', value: pr, allowed: closureProofAuditPrRefKeys });
      expect(failures, tag, Number.isInteger(pr?.number) && pr.number > 0,
        `closure proof audit linked PR number must be positive for issue #${row.issueNumber}`);
      if (pr?.sourceCommentDatabaseId != null) {
        expect(failures, tag, isExpectedGitHubCommentUrl(pr.sourceCommentUrl, row.issueNumber, pr.sourceCommentDatabaseId),
          `closure proof audit linked PR source comment URL must match its database ID for issue #${row.issueNumber}`);
      }
    }
    for (const field of ['matchingComments', 'nonActionableRationaleComments']) {
      for (const comment of row.evidence?.[field] ?? []) {
        verifyAllowedKeys({ failures, tag, label: `closure proof audit ${field}`, value: comment, allowed: closureProofAuditCommentRefKeys });
        if (comment?.databaseId != null) {
          expect(failures, tag, isExpectedGitHubCommentUrl(comment.url, comment.issueNumber ?? row.issueNumber, comment.databaseId),
            `closure proof audit ${field} URL must match its database ID for issue #${row.issueNumber}`);
        }
      }
    }
    for (const field of ['fixCommitProof', 'canonicalFixCommitProof', 'referencedCommitContext']) {
      for (const commit of row.evidence?.[field] ?? []) {
        verifyAllowedKeys({ failures, tag, label: `closure proof audit ${field}`, value: commit, allowed: closureProofAuditCommitRefKeys });
        if (typeof commit?.commitOid === 'string' && fullCommitOidRe.test(commit.commitOid)) {
          expect(failures, tag, typeof commit.commitUrl === 'string' && commit.commitUrl.endsWith(`/commit/${commit.commitOid}`),
            `closure proof audit ${field} commit URL must match commit OID for issue #${row.issueNumber}`);
        }
        if (commit?.sourceCommentDatabaseId != null) {
          expect(failures, tag, isExpectedGitHubCommentUrl(
            commit.sourceCommentUrl,
            commit.sourceIssueNumber ?? row.issueNumber,
            commit.sourceCommentDatabaseId,
          ), `closure proof audit ${field} source comment URL must match its database ID for issue #${row.issueNumber}`);
        }
      }
    }
  }

  const [status, statusCount] = Object.entries(proof.byStatus ?? {}).find(([, count]) => Number(count ?? 0) > 0) ?? [];
  if (status) {
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 3],
      ['status', status],
    ]));
    expect(failures, tag, page.total === Number(statusCount ?? 0),
      `closure proof audit status filter total (${page.total}) must match ${status} count (${statusCount})`);
    expect(failures, tag, page.totals?.unfilteredRows === firstPage.total,
      `closure proof audit status filter unfilteredRows (${page.totals?.unfilteredRows}) must match unfiltered total (${firstPage.total})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `closure proof audit status filter filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filteredCountsByStatus?.[status] === Number(statusCount ?? 0),
      `closure proof audit filteredCountsByStatus.${status} (${page.filteredCountsByStatus?.[status]}) must match ${statusCount}`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.status === status),
      `closure proof audit status filter must return only ${status} rows`);
  }
  const proofMetadataStatuses = [
    ['fixed_in_later_release', 'laterFixProof', (proof) => proof?.releaseTag && ['pr', 'commit'].includes(proof?.proofType)],
    ['non_bug_fixed_in_later_release', 'laterFixProof', (proof) => proof?.releaseTag && ['pr', 'commit'].includes(proof?.proofType)],
    ['fixed_after_latest_release', 'unscoredFixProof', (proof) => proof?.timing === 'after_latest_release'],
    ['non_bug_fixed_after_latest_release', 'unscoredFixProof', (proof) => proof?.timing === 'after_latest_release'],
    ['fixed_skipped_by_later_releases', 'unscoredFixProof', (proof) => proof?.timing === 'skipped_by_later_releases'],
    ['non_bug_fixed_skipped_by_later_releases', 'unscoredFixProof', (proof) => proof?.timing === 'skipped_by_later_releases'],
  ];
  for (const [proofStatus, evidenceField, isValidProof] of proofMetadataStatuses) {
    if (Number(proof.byStatus?.[proofStatus] ?? 0) <= 0) continue;
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 3],
      ['status', proofStatus],
    ]));
    expect(failures, tag, (page.rows ?? []).length > 0,
      `closure proof audit ${proofStatus} filter must return at least one row`);
    expect(failures, tag, (page.rows ?? []).every((row) => isValidProof(row.evidence?.[evidenceField])),
      `closure proof audit ${proofStatus} rows must expose valid ${evidenceField} metadata`);
  }

  const [disposition, dispositionCount] = Object.entries(proof.byRiskDisposition ?? {}).find(([, count]) => Number(count ?? 0) > 0) ?? [];
  if (disposition) {
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 3],
      ['riskDisposition', disposition],
    ]));
    expect(failures, tag, page.total === Number(dispositionCount ?? 0),
      `closure proof audit riskDisposition filter total (${page.total}) must match ${disposition} count (${dispositionCount})`);
    expect(failures, tag, page.filteredCountsByRiskDisposition?.[disposition] === Number(dispositionCount ?? 0),
      `closure proof audit filteredCountsByRiskDisposition.${disposition} (${page.filteredCountsByRiskDisposition?.[disposition]}) must match ${dispositionCount}`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.riskDisposition === disposition),
      `closure proof audit riskDisposition filter must return only ${disposition} rows`);
  }
}

function isExpectedGitHubCommentUrl(url, issueNumber, databaseId) {
  const issue = Number(issueNumber);
  const comment = Number(databaseId);
  if (!Number.isInteger(issue) || issue <= 0 || !Number.isInteger(comment) || comment <= 0) return false;
  try {
    const parsed = new URL(String(url ?? ''));
    return parsed.protocol === 'https:' &&
      parsed.hostname === 'github.com' &&
      parsed.pathname.toLowerCase() === `/${trackedRepositoryNameWithOwner}/issues/${issue}`.toLowerCase() &&
      parsed.hash === `#issuecomment-${comment}`;
  } catch {
    return false;
  }
}

async function verifyPrReachabilityAuditEndpoint({
  base,
  fetchJson,
  failures,
  reader,
  tag,
  scoredAt,
  publicationSnapshot,
  auditDigest,
}) {
  if (typeof reader.prReachabilityRowsForRelease !== 'function') return;
  const rows = reader.prReachabilityRowsForRelease(tag);
  const fetchBoundPage = async (url, label = 'PR reachability audit page') => {
    const page = await fetchJson(url);
    verifyReviewPageBinding({
      failures,
      tag,
      label,
      page,
      endpoint: 'reachability',
      publicationSnapshot,
      auditDigest,
    });
    return page;
  };
  const firstPage = await fetchBoundPage(
    reviewUrlWithQuery(base, [['limit', 7]]),
    'PR reachability audit',
  );
  for (const [label, url, error] of [
    ['PR reachability audit invalid status', reviewUrlWithQuery(base, [['status', 'bad']]), 'invalid status'],
    ['PR reachability audit repeated status', reviewUrlWithQuery(base, [['status', 'reachable'], ['status', 'bad']]), 'invalid status'],
    ['PR reachability audit invalid pr', reviewUrlWithQuery(base, [['pr', 'not-a-pr']]), 'invalid pr filter'],
    ['PR reachability audit repeated pr', reviewUrlWithQuery(base, [['pr', '123'], ['pr', 'not-a-pr']]), 'invalid pr filter'],
    ['PR reachability audit invalid limit', reviewUrlWithQuery(base, [['limit', 'abc']]), 'invalid limit'],
    ['PR reachability audit decimal limit', reviewUrlWithQuery(base, [['limit', '1.9']]), 'invalid limit'],
    ['PR reachability audit repeated limit', reviewUrlWithQuery(base, [['limit', 1], ['limit', 2]]), 'invalid limit'],
    ['PR reachability audit invalid cursor', reviewUrlWithQuery(base, [['cursor', 'abc']]), 'invalid cursor'],
    ['PR reachability audit decimal cursor', reviewUrlWithQuery(base, [['cursor', '1.9']]), 'invalid cursor'],
    ['PR reachability audit repeated cursor', reviewUrlWithQuery(base, [['cursor', 0], ['cursor', 1]]), 'invalid cursor'],
  ]) {
    await expectFetchJsonStatus({
      failures,
      tag,
      fetchJson,
      url,
      status: 400,
      label,
      payloadCheck: (payload) => payload?.error === error,
    });
  }
  expect(failures, tag, firstPage.schemaVersion === 1,
    `PR reachability audit schemaVersion must be 1, got ${JSON.stringify(firstPage.schemaVersion)}`);
  verifyAllowedKeys({ failures, tag, label: 'PR reachability audit payload', value: firstPage, allowed: reachabilityAuditKeys });
  verifyAllowedKeys({ failures, tag, label: 'PR reachability audit filters', value: firstPage.filters, allowed: reachabilityAuditFilterKeys });
  verifyAllowedKeys({ failures, tag, label: 'PR reachability audit totals', value: firstPage.totals, allowed: reachabilityAuditTotalsKeys });
  expect(failures, tag, firstPage.tag === tag,
    `PR reachability audit tag (${firstPage.tag}) must match release tag (${tag})`);
  expect(failures, tag, firstPage.sourceMode === 'current_db',
    `PR reachability audit sourceMode (${firstPage.sourceMode}) must be current_db`);
  expect(failures, tag, firstPage.scoredAt === scoredAt,
    `PR reachability audit scoredAt (${firstPage.scoredAt}) must match DB scored_at (${scoredAt})`);
  verifyDataFreshness({
    failures,
    tag,
    dataFreshness: firstPage.dataFreshness,
    releaseTag: tag,
    scoredAt,
    reader,
  });
  expect(failures, tag, firstPage.total === rows.length,
    `PR reachability audit total (${firstPage.total}) must match DB rows (${rows.length})`);
  expect(failures, tag, firstPage.totalRows === firstPage.total,
    `PR reachability audit totalRows (${firstPage.totalRows}) must match total (${firstPage.total})`);
  expect(failures, tag, isObject(firstPage.totals),
    'PR reachability audit totals must be an object');
  expect(failures, tag, firstPage.totals?.unfilteredRows === rows.length,
    `PR reachability audit unfilteredRows (${firstPage.totals?.unfilteredRows}) must match DB rows (${rows.length})`);
  expect(failures, tag, firstPage.totals?.filteredRows === firstPage.total,
    `PR reachability audit filteredRows (${firstPage.totals?.filteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, firstPage.limit === 7,
    `PR reachability audit limit must be 7, got ${firstPage.limit}`);
  expect(failures, tag, firstPage.cursor === 0,
    `PR reachability audit cursor must be 0, got ${firstPage.cursor}`);
  expect(failures, tag, Array.isArray(firstPage.rows), 'PR reachability audit rows must be an array');
  expect(failures, tag, firstPage.rows.length <= 7,
    `PR reachability audit rows length must respect limit, got ${firstPage.rows.length}`);
  const expectedCounts = countBy(rows, (row) => row.status);
  expectJsonEqual(failures, tag, 'PR reachability audit countsByStatus must match DB rows',
    firstPage.countsByStatus ?? {}, expectedCounts);
  expectJsonEqual(failures, tag, 'PR reachability audit unfilteredCountsByStatus must match DB rows',
    firstPage.unfilteredCountsByStatus ?? {}, expectedCounts);
  expectJsonEqual(failures, tag, 'PR reachability audit filteredCountsByStatus must match countsByStatus without filters',
    firstPage.filteredCountsByStatus ?? {}, expectedCounts);
  const reachabilityAuditRows = await collectExhaustiveAuditPages({
    base,
    firstPage,
    fetchJson: fetchBoundPage,
    failures,
    tag,
    label: 'PR reachability audit',
    limit: 7,
    identity: (row) =>
      `${String(row?.repositoryNameWithOwner ?? '').toLowerCase()}#${row?.number}`,
    expectedIdentities: rows.map((row) =>
      `${String(row.pr_repository_name_with_owner ?? '').toLowerCase()}#${row.pr_number}`),
    expectedRows: rows.map(reachabilityAuditRowFromReader),
    expectedIdentity: (row) =>
      `${String(row?.repositoryNameWithOwner ?? '').toLowerCase()}#${row?.number}`,
    validatePage: (page) => {
      expect(failures, tag, page.schemaVersion === 1,
        `PR reachability audit page schemaVersion must be 1`);
      verifyAllowedKeys({
        failures,
        tag,
        label: 'PR reachability audit payload',
        value: page,
        allowed: reachabilityAuditKeys,
      });
      expect(failures, tag, page.tag === tag,
        `PR reachability audit page tag (${page.tag}) must match ${tag}`);
      expect(failures, tag, page.sourceMode === 'current_db',
        `PR reachability audit page sourceMode (${page.sourceMode}) must be current_db`);
      expect(failures, tag, page.scoredAt === scoredAt,
        `PR reachability audit page scoredAt (${page.scoredAt}) must match ${scoredAt}`);
    },
  });
  for (const row of reachabilityAuditRows) {
    verifyAllowedKeys({ failures, tag, label: 'PR reachability audit row', value: row, allowed: reachabilityAuditRowKeys });
    expect(failures, tag, Number.isInteger(row.number) && row.number > 0,
      `PR reachability audit row number must be positive integer, got ${row.number}`);
    expect(failures, tag, typeof row.repositoryNameWithOwner === 'string' && row.repositoryNameWithOwner.includes('/'),
      `PR reachability audit row repositoryNameWithOwner must be present, got ${row.repositoryNameWithOwner}`);
    expect(failures, tag, ['reachable', 'not_reachable', 'unknown'].includes(row.status),
      `PR reachability audit row status must be known, got ${row.status}`);
    expect(failures, tag, typeof row.method === 'string' && row.method.length > 0,
      `PR reachability audit row method must be present for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, typeof row.checkedAt === 'string' && Number.isFinite(Date.parse(row.checkedAt)),
      `PR reachability audit row checkedAt must be a timestamp for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, isObject(row.evidence),
      `PR reachability audit row evidence must be an object for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, row.evidence?.schemaVersion === 1,
      `PR reachability audit row evidence schemaVersion must be 1 for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, knownReachabilityEvidenceReasons.has(row.evidence?.evidence),
      `PR reachability audit row evidence reason must be known for ${row.repositoryNameWithOwner}#${row.number}, got ${row.evidence?.evidence}`);
    if (row.status === 'reachable' || row.status === 'not_reachable') {
      expect(failures, tag, typeof row.tagCommitOid === 'string' && fullCommitOidRe.test(row.tagCommitOid),
        `PR reachability ${row.status} row must include full tagCommitOid for ${row.repositoryNameWithOwner}#${row.number}`);
      expect(failures, tag, typeof row.mergeCommitOid === 'string' && fullCommitOidRe.test(row.mergeCommitOid),
        `PR reachability ${row.status} row must include full mergeCommitOid for ${row.repositoryNameWithOwner}#${row.number}`);
      expect(failures, tag, row.method === 'git-merge-base',
        `PR reachability ${row.status} row must use git-merge-base for ${row.repositoryNameWithOwner}#${row.number}`);
      expect(failures, tag, row.evidence.evidence !== 'merge_base_error',
        `PR reachability ${row.status} row must not use merge_base_error evidence for ${row.repositoryNameWithOwner}#${row.number}`);
    }
    if (row.status === 'unknown') {
      expect(failures, tag, row.evidence.evidence !== 'merge_commit_in_release_history' && row.evidence.evidence !== 'fix_commit_in_release_history',
        `unknown PR reachability row cannot use reachable evidence for ${row.repositoryNameWithOwner}#${row.number}`);
    }
  }
  const [status, statusCount] = Object.entries(expectedCounts).find(([, count]) => Number(count ?? 0) > 0) ?? [];
  if (status) {
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['status', status],
    ]));
    expect(failures, tag, page.total === statusCount,
      `PR reachability audit status filter total (${page.total}) must match ${status} count (${statusCount})`);
    expect(failures, tag, page.totals?.unfilteredRows === rows.length,
      `PR reachability audit status filter unfilteredRows (${page.totals?.unfilteredRows}) must match DB rows (${rows.length})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `PR reachability audit status filter filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filteredCountsByStatus?.[status] === statusCount,
      `PR reachability audit filteredCountsByStatus.${status} (${page.filteredCountsByStatus?.[status]}) must match ${statusCount}`);
    expectJsonEqual(failures, tag, 'PR reachability audit status filter unfilteredCountsByStatus must match DB rows',
      page.unfilteredCountsByStatus ?? {}, expectedCounts);
    expect(failures, tag, (page.rows ?? []).every((row) => row.status === status),
      `PR reachability audit status filter must return only ${status} rows`);
  }
  const first = rows[0];
  if (first) {
    const pr = `${first.pr_repository_name_with_owner}#${first.pr_number}`;
    const page = await fetchBoundPage(reviewUrlWithQuery(base, [
      ['limit', 5],
      ['pr', pr],
    ]));
    expect(failures, tag, page.total === rows.filter((row) =>
      row.pr_repository_name_with_owner === first.pr_repository_name_with_owner &&
      Number(row.pr_number) === Number(first.pr_number)).length,
    `PR reachability audit pr filter total (${page.total}) must match DB rows for ${pr}`);
    expect(failures, tag, (page.rows ?? []).every((row) =>
      row.repositoryNameWithOwner === first.pr_repository_name_with_owner &&
      Number(row.number) === Number(first.pr_number)),
    `PR reachability audit pr filter must return only ${pr}`);
  }
}

function countBy(rows, keyFn) {
  const out = {};
  for (const row of rows) {
    const key = keyFn(row);
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

function reachabilityAuditRowFromReader(row) {
  return {
    repositoryNameWithOwner: row.pr_repository_name_with_owner,
    number: row.pr_number,
    title: row.title,
    url: row.url,
    state: row.state,
    merged: row.merged === 1,
    mergedAt: row.merged_at,
    status: row.status,
    method: row.method,
    checkedAt: row.checked_at,
    tagCommitOid: row.tag_commit_oid,
    mergeCommitOid: row.merge_commit_oid,
    prMergeCommitOid: row.pr_merge_commit_oid,
    baseRefName: row.base_ref_name ?? row.pr_base_ref_name,
    evidence: parseJson(row.evidence_json, {}),
  };
}

function closureAuditRowsFromReader({ failures, tag, reader, rows }) {
  const issueRows = [
    ...(typeof reader.issuesForVersion === 'function'
      ? reader.issuesForVersion(tag)
      : []),
    ...(typeof reader.closedDuringReign === 'function'
      ? reader.closedDuringReign(tag)
      : []),
    ...(typeof reader.verifiedFixedForRelease === 'function'
      ? reader.verifiedFixedForRelease(tag)
      : []),
    ...(typeof reader.unverifiedClosedForRelease === 'function'
      ? reader.unverifiedClosedForRelease(tag)
      : []),
  ];
  const issueByNumber = new Map();
  for (const issue of issueRows) {
    const issueNumber = Number(issue?.number);
    if (!Number.isInteger(issueNumber) || issueNumber <= 0) continue;
    const current = issueByNumber.get(issueNumber);
    if (
      !current ||
      (
        current.html_url == null &&
        issue?.html_url != null
      ) ||
      (
        current.closed_at == null &&
        issue?.closed_at != null
      )
    ) {
      issueByNumber.set(issueNumber, issue);
    }
  }
  let complete = true;
  const projected = rows.map((row) => {
    const issueNumber = Number(row?.issue_number);
    const issue = issueByNumber.get(issueNumber);
    if (
      !issue ||
      typeof issue.title !== 'string' ||
      typeof issue.html_url !== 'string' ||
      typeof issue.closed_at !== 'string'
    ) {
      complete = false;
      failures.push(
        `${tag}: closure proof audit row #${row?.issue_number ?? 'unknown'} ` +
        'cannot be exactly reconstructed without complete independent issue metadata',
      );
    }
    if (
      issue &&
      typeof row?.title === 'string' &&
      row.title !== issue.title
    ) {
      complete = false;
      failures.push(
        `${tag}: closure proof audit row #${row.issue_number} title must match the independent issue row`,
      );
    }
    const labels = Array.isArray(row?.effective_labels)
      ? row.effective_labels.filter((label) => typeof label === 'string')
      : null;
    if (
      authorityBoundClosureProofStatuses.has(row?.status) ||
      labels == null ||
      labels.some((label) => labelUsesScoreAuthority(label))
    ) {
      complete = false;
      failures.push(
        `${tag}: closure proof audit row #${row?.issue_number ?? 'unknown'} ` +
        'cannot be exactly reconstructed without authority-bound closure and label evidence',
      );
    }
    const hasClassification =
      typeof row?.sentiment === 'string' &&
      typeof row?.severity === 'string' &&
      typeof row?.scope === 'string' &&
      typeof row?.functionality === 'string' &&
      typeof row?.affected_users === 'string';
    const rawClassification = hasClassification
      ? rawClassificationForProofRow(row)
      : null;
    const classification = hasClassification
      ? effectiveClassificationForProofRow(row)
      : null;
    const classificationDiff = {};
    if (rawClassification && classification) {
      for (const key of [
        'sentiment',
        'severity',
        'scope',
        'functionality',
        'affectedUsers',
        'workaroundStatus',
        'confidence',
      ]) {
        if (rawClassification[key] !== classification[key]) {
          classificationDiff[key] = {
            raw: rawClassification[key],
            effective: classification[key],
          };
        }
      }
    }
    const riskDisposition = riskDispositionForStatus(row?.status);
    const riskWeight = roundMetric(closureRiskWeightForProofRow(row));
    return {
      issueNumber: row?.issue_number,
      title: issue?.title ?? row?.title,
      url: issue?.html_url ?? null,
      closedAt: issue?.closed_at ?? null,
      status: row?.status,
      summary: row?.summary,
      riskDisposition,
      riskDispositionLabel: closureRiskDispositionLabel(riskDisposition),
      riskWeight,
      riskWeightLabel: closureRiskWeightLabel(riskWeight),
      checkedAt: row?.checked_at,
      labels: labels ?? [],
      classification,
      classificationDiff,
      evidence: compactClosureAuditEvidence(parseJson(row?.evidence_json, {})),
    };
  });
  return complete ? projected : null;
}

function compactClosureAuditEvidence(evidence) {
  const raw = isObject(evidence) ? evidence : {};
  return {
    stateReasons: compactClosureArray(raw.stateReasons, compactClosureScalar),
    closureActors: compactClosureArray(raw.closureActors, compactClosureScalar),
    closureContextCommentCount: raw.closureContextCommentCount ?? null,
    hasClosingLink: raw.hasClosingLink === true,
    hasMergedClosingPr: raw.hasMergedClosingPr === true,
    hasReachableClosingPr: raw.hasReachableClosingPr === true,
    hasNotReachableClosingPr: raw.hasNotReachableClosingPr === true,
    hasReachableFixCommit: raw.hasReachableFixCommit === true,
    hasNotReachableFixCommit: raw.hasNotReachableFixCommit === true,
    hasUnknownFixCommit: raw.hasUnknownFixCommit === true,
    canonicalIssues: compactClosureArray(raw.canonicalIssues, compactClosureScalar),
    canonicalIssueDetails: compactClosureArray(
      raw.canonicalIssueDetails,
      compactClosureIssueRef,
    ),
    canonicalResolution: compactClosureCanonicalResolution(raw.canonicalResolution),
    closingPrs: compactClosureArray(raw.closingPrs, compactClosureScalar),
    linkedPrs: compactClosureArray(raw.linkedPrs, compactClosurePrRef),
    relatedPrContext: compactClosureRelatedPrContext(raw.relatedPrContext),
    reachableTrustedFixProofPrs: compactClosureArray(
      raw.reachableTrustedFixProofPrs,
      compactClosurePrRef,
    ),
    matchingComments: compactClosureArray(
      raw.matchingComments,
      compactClosureCommentRef,
      5,
    ),
    nonActionableRationaleComments: compactClosureArray(
      raw.nonActionableRationaleComments,
      compactClosureCommentRef,
      5,
    ),
    laterFixProof: compactClosureLaterFixProof(raw.laterFixProof),
    unscoredFixProof: compactClosureUnscoredFixProof(raw.unscoredFixProof),
    fixCommitProof: compactClosureArray(raw.fixCommitProof, compactClosureCommitProof),
    canonicalFixCommitProof: compactClosureArray(
      raw.canonicalFixCommitProof,
      compactClosureCommitProof,
    ),
    referencedCommitContext: compactClosureArray(
      raw.referencedCommitContext,
      compactClosureCommitProof,
    ),
    reachableFixCommits: compactClosureArray(
      raw.reachableFixCommits,
      compactClosureScalar,
    ),
    notReachableFixCommits: compactClosureArray(
      raw.notReachableFixCommits,
      compactClosureScalar,
    ),
    unknownFixCommits: compactClosureArray(
      raw.unknownFixCommits,
      compactClosureScalar,
    ),
  };
}

function compactClosureRelatedPrContext(value) {
  const raw = isObject(value) ? value : {};
  return {
    externalClosing: compactClosureArray(raw.externalClosing, compactClosurePrRef),
    open: compactClosureArray(raw.open, compactClosurePrRef),
    closedUnmerged: compactClosureArray(raw.closedUnmerged, compactClosurePrRef),
    notReachable: compactClosureArray(raw.notReachable, compactClosurePrRef),
    reachable: compactClosureArray(raw.reachable, compactClosurePrRef),
    unknownReachability: compactClosureArray(
      raw.unknownReachability,
      compactClosurePrRef,
    ),
  };
}

function compactClosureCanonicalResolution(value) {
  if (!isObject(value)) return null;
  return {
    path: compactClosureArray(value.path, compactClosureScalar),
    terminalIssue: compactClosureIssueRef(value.terminalIssue),
    terminalProof: isObject(value.terminalProof)
      ? {
        status: value.terminalProof.status ?? null,
        summary: value.terminalProof.summary ?? null,
        crossRelease: value.terminalProof.crossRelease === true,
        releaseTag: value.terminalProof.releaseTag ?? null,
        timing: value.terminalProof.timing ?? null,
      }
      : null,
    cycle: value.cycle === true,
    selfReference: value.selfReference === true,
  };
}

function compactClosureArray(value, mapper, limit = 50) {
  if (!Array.isArray(value)) return [];
  return value
    .slice(0, limit)
    .map(mapper)
    .filter((item) => item != null);
}

function compactClosureScalar(value) {
  return typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
    ? value
    : null;
}

function compactClosureIssueRef(value) {
  if (!isObject(value)) return null;
  const issueNumber = Number(value.number ?? value.issueNumber);
  if (!Number.isInteger(issueNumber) || issueNumber <= 0) return null;
  return {
    number: issueNumber,
    title: typeof value.title === 'string' ? value.title : null,
    url: typeof value.url === 'string'
      ? value.url
      : typeof value.html_url === 'string'
        ? value.html_url
        : null,
    state: typeof value.state === 'string' ? value.state : null,
  };
}

function compactClosurePrRef(value) {
  if (!isObject(value)) return null;
  const number = Number(value.number ?? value.prNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    repositoryNameWithOwner:
      typeof value.repositoryNameWithOwner === 'string'
        ? value.repositoryNameWithOwner
        : null,
    source: typeof value.source === 'string' ? value.source : null,
    willCloseTarget:
      value.willCloseTarget === true || value.willCloseTarget === 1
        ? true
        : value.willCloseTarget === false || value.willCloseTarget === 0
          ? false
          : null,
    referencedAt: typeof value.referencedAt === 'string' ? value.referencedAt : null,
    sourceCommentDatabaseId:
      Number.isInteger(Number(value.sourceCommentDatabaseId)) &&
        Number(value.sourceCommentDatabaseId) > 0
        ? Number(value.sourceCommentDatabaseId)
        : null,
    sourceCommentUrl:
      typeof value.sourceCommentUrl === 'string' ? value.sourceCommentUrl : null,
    metadataMissing: value.metadataMissing === true || value.metadataMissing === 1,
    title: typeof value.title === 'string' ? value.title : null,
    url: typeof value.url === 'string' ? value.url : null,
    state: typeof value.state === 'string' ? value.state : null,
    merged:
      value.merged === 1 ||
      value.merged === true ||
      typeof value.mergedAt === 'string',
    mergedAt: typeof value.mergedAt === 'string' ? value.mergedAt : null,
    reachabilityStatus:
      typeof value.reachabilityStatus === 'string'
        ? value.reachabilityStatus
        : null,
    reachabilityMethod:
      typeof value.reachabilityMethod === 'string'
        ? value.reachabilityMethod
        : null,
    reachabilityEvidence:
      typeof value.reachabilityEvidence === 'string'
        ? value.reachabilityEvidence
        : null,
    mergeCommitOid:
      typeof value.mergeCommitOid === 'string' ? value.mergeCommitOid : null,
  };
}

function compactClosureCommentRef(value) {
  if (!isObject(value)) return null;
  return {
    databaseId:
      Number.isInteger(Number(value.databaseId)) && Number(value.databaseId) > 0
        ? Number(value.databaseId)
        : null,
    issueNumber:
      Number.isInteger(Number(value.issueNumber)) && Number(value.issueNumber) > 0
        ? Number(value.issueNumber)
        : null,
    url: typeof value.url === 'string' ? value.url : null,
    author: typeof value.author === 'string' ? value.author : null,
    createdAt: typeof value.createdAt === 'string' ? value.createdAt : null,
    updatedAt: typeof value.updatedAt === 'string' ? value.updatedAt : null,
    snippet: typeof value.snippet === 'string' ? value.snippet : null,
  };
}

function compactClosureCommitProof(value) {
  if (!isObject(value)) return null;
  const commitOid = typeof value.commitOid === 'string' ? value.commitOid : null;
  const sourceIssueNumber = Number(value.sourceIssueNumber);
  return {
    issueNumber:
      Number.isInteger(Number(value.issueNumber)) && Number(value.issueNumber) > 0
        ? Number(value.issueNumber)
        : null,
    sourceIssueNumber:
      Number.isInteger(sourceIssueNumber) && sourceIssueNumber > 0
        ? sourceIssueNumber
        : null,
    sourceIssueUrl:
      Number.isInteger(sourceIssueNumber) && sourceIssueNumber > 0
        ? `https://github.com/${trackedRepositoryNameWithOwner}/issues/${sourceIssueNumber}`
        : null,
    commitOid,
    shortOid: typeof value.shortOid === 'string' ? value.shortOid : null,
    commitUrl:
      commitOid && /^[0-9a-f]{40}$/i.test(commitOid)
        ? `https://github.com/${trackedRepositoryNameWithOwner}/commit/${commitOid}`
        : null,
    status: typeof value.status === 'string' ? value.status : null,
    source: typeof value.source === 'string' ? value.source : null,
    referencedAt: typeof value.referencedAt === 'string' ? value.referencedAt : null,
    author: typeof value.author === 'string' ? value.author : null,
    authorAssociation:
      typeof value.authorAssociation === 'string'
        ? value.authorAssociation
        : null,
    trustedSource: value.trustedSource === true,
    tagCommitOid:
      typeof value.tagCommitOid === 'string' ? value.tagCommitOid : null,
    sourceCommentDatabaseId:
      Number.isInteger(Number(value.sourceCommentDatabaseId)) &&
        Number(value.sourceCommentDatabaseId) > 0
        ? Number(value.sourceCommentDatabaseId)
        : null,
    sourceCommentUrl:
      typeof value.sourceCommentUrl === 'string' ? value.sourceCommentUrl : null,
    evidence: typeof value.evidence === 'string' ? value.evidence : null,
    snippet: typeof value.snippet === 'string' ? value.snippet : null,
  };
}

function compactClosureLaterFixProof(value) {
  if (!isObject(value)) return null;
  return {
    releaseTag: typeof value.releaseTag === 'string' ? value.releaseTag : null,
    publishedAt: typeof value.publishedAt === 'string' ? value.publishedAt : null,
    proofType: typeof value.proofType === 'string' ? value.proofType : null,
    prNumber: Number.isInteger(Number(value.prNumber))
      ? Number(value.prNumber)
      : null,
    prRepositoryNameWithOwner:
      typeof value.prRepositoryNameWithOwner === 'string'
        ? value.prRepositoryNameWithOwner
        : null,
    commitOid: typeof value.commitOid === 'string' ? value.commitOid : null,
  };
}

function compactClosureUnscoredFixProof(value) {
  if (!isObject(value)) return null;
  return {
    timing: typeof value.timing === 'string' ? value.timing : null,
    proofTime: typeof value.proofTime === 'string' ? value.proofTime : null,
    latestScoredReleaseTag:
      typeof value.latestScoredReleaseTag === 'string'
        ? value.latestScoredReleaseTag
        : null,
    latestScoredReleasePublishedAt:
      typeof value.latestScoredReleasePublishedAt === 'string'
        ? value.latestScoredReleasePublishedAt
        : null,
    proofType: typeof value.proofType === 'string' ? value.proofType : null,
    prNumber: Number.isInteger(Number(value.prNumber))
      ? Number(value.prNumber)
      : null,
    prRepositoryNameWithOwner:
      typeof value.prRepositoryNameWithOwner === 'string'
        ? value.prRepositoryNameWithOwner
        : null,
    commitOid: typeof value.commitOid === 'string' ? value.commitOid : null,
  };
}

function expectedIssueEvidenceAuditIdentities({ reader, tag, issueEvidence }) {
  const identities = [];
  for (const tier of [
    'verifiedDebt',
    'carryoverDebt',
    'staleDebt',
    'openedFeltSerious',
    'unclassifiedIssues',
  ]) {
    for (const row of Array.isArray(issueEvidence?.[tier]) ? issueEvidence[tier] : []) {
      const issueNumber = row?.issueNumber ?? row?.issue?.number ?? row?.number;
      if (Number.isInteger(issueNumber) && issueNumber > 0) {
        identities.push(`${tier}:${issueNumber}`);
      }
    }
  }
  if (typeof reader.verifiedFixedForRelease === 'function') {
    for (const row of reader.verifiedFixedForRelease(tag)) {
      if (Number.isInteger(row?.number) && row.number > 0) {
        identities.push(`verifiedFixed:${row.number}`);
      }
    }
  }
  if (typeof reader.unverifiedClosedForRelease === 'function') {
    for (const row of reader.unverifiedClosedForRelease(tag)) {
      if (Number.isInteger(row?.number) && row.number > 0) {
        identities.push(`unverifiedClosed:${row.number}`);
      }
    }
  }
  return identities;
}

async function collectExhaustiveAuditPages({
  base,
  firstPage,
  fetchJson,
  failures,
  tag,
  label,
  limit,
  identity,
  expectedIdentities,
  expectedRows = null,
  expectedIdentity = identity,
  actualContent = (row) => row,
  expectedContent = (row) => row,
  validatePage = null,
}) {
  const expectedTotal = Number(firstPage?.total);
  const expectedTotalRows = Number(firstPage?.totalRows);
  const expectedFilteredRows = Number(firstPage?.totals?.filteredRows);
  const expected = Array.isArray(expectedIdentities)
    ? expectedIdentities.filter((value) => typeof value === 'string' && value.length > 0)
    : [];
  const expectedSet = new Set(expected);
  if (expectedSet.size !== expected.length) {
    const duplicates = expected.filter((value, index) => expected.indexOf(value) !== index);
    expect(failures, tag, false,
      `${label} expected identities must be unique: ${[...new Set(duplicates)].slice(0, 5).join(', ')}`);
  }

  const rows = [];
  const seenIdentities = new Set();
  const seenCursors = new Set();
  let page = firstPage;
  let requestedCursor = 0;
  let pageCount = 0;
  const maxPages = Number.isInteger(expectedTotal) && expectedTotal >= 0
    ? expectedTotal + 2
    : 2;

  while (pageCount < maxPages) {
    pageCount++;
    seenCursors.add(requestedCursor);
    validatePage?.(page, pageCount);
    expect(failures, tag, page?.cursor === requestedCursor,
      `${label} page cursor (${page?.cursor}) must equal requested cursor (${requestedCursor})`);
    expect(failures, tag, Number(page?.total) === expectedTotal,
      `${label} total must remain stable at ${expectedTotal}, got ${page?.total}`);
    expect(failures, tag, Number(page?.totalRows) === expectedTotalRows,
      `${label} totalRows must remain stable at ${expectedTotalRows}, got ${page?.totalRows}`);
    expect(failures, tag, Number(page?.totals?.filteredRows) === expectedFilteredRows,
      `${label} filteredRows must remain stable at ${expectedFilteredRows}, got ${page?.totals?.filteredRows}`);
    const pageRows = Array.isArray(page?.rows) ? page.rows : [];
    expect(failures, tag, Array.isArray(page?.rows), `${label} rows must be an array on every page`);
    expect(failures, tag, pageRows.length <= limit,
      `${label} page rows length must respect limit ${limit}, got ${pageRows.length}`);

    for (const row of pageRows) {
      const rowIdentity = identity(row);
      expect(failures, tag, typeof rowIdentity === 'string' && rowIdentity.length > 0,
        `${label} row identity must be a non-empty string`);
      if (typeof rowIdentity !== 'string' || rowIdentity.length === 0) continue;
      expect(failures, tag, !seenIdentities.has(rowIdentity),
        `${label} pagination must not repeat identity ${rowIdentity}`);
      seenIdentities.add(rowIdentity);
      rows.push(row);
    }

    const nextCursor = page?.nextCursor;
    if (nextCursor == null) break;
    const expectedNextCursor = requestedCursor + pageRows.length;
    const advances =
      Number.isInteger(nextCursor) &&
      nextCursor === expectedNextCursor &&
      nextCursor > requestedCursor;
    expect(failures, tag, advances,
      `${label} nextCursor (${nextCursor}) must advance to ${expectedNextCursor}`);
    if (!advances || seenCursors.has(nextCursor)) {
      if (seenCursors.has(nextCursor)) {
        expect(failures, tag, false, `${label} pagination cursor cycle detected at ${nextCursor}`);
      }
      break;
    }
    requestedCursor = nextCursor;
    const nextLink = page?.links?.next;
    let nextUrl = null;
    try {
      const parsedBase = new URL(base);
      const parsedNext = typeof nextLink === 'string'
        ? new URL(nextLink, parsedBase)
        : null;
      const safeNext =
        typeof nextLink === 'string' &&
        nextLink.startsWith('/') &&
        parsedNext?.origin === parsedBase.origin &&
        parsedNext?.pathname === parsedBase.pathname;
      expect(
        failures,
        tag,
        safeNext,
        `${label} links.next must stay on the published audit endpoint`,
      );
      if (safeNext) nextUrl = parsedNext.toString();
    } catch {
      expect(failures, tag, false, `${label} links.next must be a valid URL`);
    }
    if (!nextUrl) break;
    try {
      page = await fetchJson(nextUrl);
    } catch (error) {
      failures.push(
        `${tag}: ${label} page fetch failed at cursor ${requestedCursor}: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
      break;
    }
  }
  if (pageCount >= maxPages && page?.nextCursor != null) {
    expect(failures, tag, false,
      `${label} pagination did not terminate within ${maxPages} page(s)`);
  }

  expect(failures, tag, rows.length === expectedTotal,
    `${label} exhausted row count (${rows.length}) must equal total (${expectedTotal})`);
  const actualSet = new Set(rows.map(identity));
  const missing = [...expectedSet].filter((value) => !actualSet.has(value));
  const extra = [...actualSet].filter((value) => !expectedSet.has(value));
  expect(failures, tag, missing.length === 0 && extra.length === 0,
    `${label} exhausted identities must match expected identities ` +
    `(missing=${missing.slice(0, 5).join(', ') || 'none'}, ` +
    `extra=${extra.slice(0, 5).join(', ') || 'none'})`);
  if (Array.isArray(expectedRows)) {
    const expectedRowsByIdentity = new Map();
    for (const expectedRow of expectedRows) {
      const rowIdentity = expectedIdentity(expectedRow);
      expect(
        failures,
        tag,
        typeof rowIdentity === 'string' && rowIdentity.length > 0,
        `${label} independently reconstructed row identity must be a non-empty string`,
      );
      if (typeof rowIdentity !== 'string' || rowIdentity.length === 0) continue;
      expect(
        failures,
        tag,
        !expectedRowsByIdentity.has(rowIdentity),
        `${label} independently reconstructed rows must not repeat identity ${rowIdentity}`,
      );
      expectedRowsByIdentity.set(rowIdentity, expectedRow);
    }
    const actualRowsByIdentity = new Map(
      rows.map((row) => [identity(row), row]),
    );
    for (const [rowIdentity, expectedRow] of expectedRowsByIdentity) {
      expectJsonEqual(
        failures,
        tag,
        `${label} row ${rowIdentity} must exactly match independently reconstructed DB content`,
        actualContent(actualRowsByIdentity.get(rowIdentity)),
        expectedContent(expectedRow),
      );
    }
  }
  return rows;
}

function verifyComparisonSnapshot({ failures, label, snapshot }) {
  if (snapshot == null) return;
  verifyAllowedKeys({ failures, tag: label, label: 'comparison snapshot', value: snapshot, allowed: comparisonSnapshotKeys });
  expect(failures, label, typeof snapshot.id === 'number', 'comparison snapshot id must be numeric');
  expect(failures, label, typeof snapshot.sourceUrl === 'string' && snapshot.sourceUrl.length > 0,
    'comparison snapshot sourceUrl must be present');
  expect(failures, label, typeof snapshot.capturedAt === 'string' && snapshot.capturedAt.length > 0,
    'comparison snapshot capturedAt must be present');
  expect(failures, label, typeof snapshot.pageTitle === 'string',
    'comparison snapshot pageTitle must be present');
  expect(failures, label, !('source_url' in snapshot) && !('captured_at' in snapshot) && !('page_text' in snapshot),
    'comparison snapshot must use normalized camelCase fields and omit page_text');
}

async function defaultFetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    const body = await res.text();
    const error = new Error(`${url} returned ${res.status}${body ? `: ${body}` : ''}`);
    error.status = res.status;
    error.body = body;
    try {
      error.payload = body ? JSON.parse(body) : null;
    } catch {
      error.payload = null;
    }
    throw error;
  }
  return res.json();
}

async function expectFetchJsonStatus({ failures, tag, fetchJson, url, status, label, payloadCheck = null }) {
  try {
    await fetchJson(url);
    expect(failures, tag, false, `${label} must return HTTP ${status}`);
  } catch (error) {
    const message = String(error?.message ?? error);
    const actual = Number(error?.status ?? (/returned\s+(\d+)/.exec(message)?.[1] ?? NaN));
    expect(failures, tag, actual === status,
      `${label} returned HTTP ${Number.isFinite(actual) ? actual : 'unknown'} instead of ${status}: ${message}`);
    if (payloadCheck) {
      const payload = error?.payload ?? parseJson(error?.body, null);
      expect(failures, tag, payloadCheck(payload),
        `${label} response body must expose expected error metadata`);
    }
  }
}

async function fetchOptionalComparisonPayload({ apiBase, fetchJson, failures }) {
  try {
    return await fetchJson(`${apiBase}/api/comparison`);
  } catch (error) {
    const message = String(error?.message ?? error);
    if (/\/api\/comparison returned 404\b/.test(message)) return null;
    failures.push(`api/comparison fetch failed: ${message}`);
    return null;
  }
}

function verifyScoreAuthorityBinding({
  failures,
  tag,
  label,
  actual,
  expected,
}) {
  expect(failures, tag, isObject(actual), `${label} must be present`);
  if (!isObject(actual)) return;
  verifyAllowedKeys({
    failures,
    tag,
    label,
    value: actual,
    allowed: scoreAuthorityBindingKeys,
  });
  expect(
    failures,
    tag,
    typeof actual.runId === 'string' && actual.runId.length > 0,
    `${label} runId must be present`,
  );
  for (const field of ['contentHash', 'historyV2SealContentHash']) {
    expect(
      failures,
      tag,
      typeof actual[field] === 'string' && sha256HexRe.test(actual[field]),
      `${label} ${field} must be lowercase SHA-256 hex`,
    );
  }
  if (isObject(expected)) {
    expectJsonEqual(
      failures,
      tag,
      `${label} must match the independently sealed authority binding`,
      actual,
      expected,
    );
  }
}

function verifyScoreAuditSummary({
  failures,
  tag,
  summary,
  expectedAuthorityBinding = null,
}) {
  expect(failures, tag, !!summary, 'scoreAudit summary must be present');
  if (!summary) return;
  verifyAllowedKeys({
    failures,
    tag,
    label: 'scoreAudit summary',
    value: summary,
    allowed: scoreAuditSummaryKeys,
  });
  expect(failures, tag, summary.schemaVersion === scoreAuditSummarySchemaVersion,
    `scoreAudit schemaVersion must be ${scoreAuditSummarySchemaVersion}, got ${JSON.stringify(summary.schemaVersion)}`);
  expect(failures, tag, summary.reviewSchemaVersion === localAuditSchemaVersion,
    `scoreAudit reviewSchemaVersion must be ${localAuditSchemaVersion}, got ${JSON.stringify(summary.reviewSchemaVersion)}`);
  expect(failures, tag, typeof summary.auditDigest === 'string' && sha256HexRe.test(summary.auditDigest),
    'scoreAudit auditDigest must be lowercase SHA-256 hex');
  verifyScoreAuthorityBinding({
    failures,
    tag,
    label: 'scoreAudit authority binding',
    actual: {
      runId: summary.authorityRunId,
      contentHash: summary.authorityRunContentHash,
      historyV2SealContentHash: summary.historyV2SealContentHash,
    },
    expected: isObject(expectedAuthorityBinding)
      ? {
          runId: expectedAuthorityBinding.authorityRunId,
          contentHash: expectedAuthorityBinding.authorityRunContentHash,
          historyV2SealContentHash:
            expectedAuthorityBinding.historyV2SealContentHash,
        }
      : null,
  });
  expect(failures, tag, typeof summary.modelVersion === 'string' && summary.modelVersion.length > 0,
    'scoreAudit modelVersion must be present');
  expect(failures, tag, Number.isInteger(summary.promptVersion),
    'scoreAudit promptVersion must be an integer');
  expect(failures, tag, typeof summary.evidenceCoverage === 'number' && summary.evidenceCoverage >= 0 && summary.evidenceCoverage <= 1,
    `scoreAudit evidenceCoverage must be in [0,1], got ${summary.evidenceCoverage}`);
  expect(failures, tag, Number.isInteger(summary.rawIssueCount) && summary.rawIssueCount >= 0,
    `scoreAudit rawIssueCount must be a non-negative integer, got ${summary.rawIssueCount}`);
  expect(failures, tag, Number.isInteger(summary.classifiedIssueCount) && summary.classifiedIssueCount >= 0,
    `scoreAudit classifiedIssueCount must be a non-negative integer, got ${summary.classifiedIssueCount}`);
}

function verifyScoreExplanation({ failures, tag, explanation, recommended, expectedBand = null, source }) {
  expect(failures, tag, isObject(explanation), `${source} score explanation must be present`);
  if (!isObject(explanation)) return;
  expect(failures, tag, explanation.schemaVersion === scoreExplanationSchemaVersion,
    `${source} score explanation schemaVersion must be ${scoreExplanationSchemaVersion}, got ${JSON.stringify(explanation.schemaVersion)}`);
  expect(failures, tag, explanation.title === 'Why not 10?',
    `${source} score explanation title must be "Why not 10?", got ${JSON.stringify(explanation.title)}`);
  verifyScoreLedger({ failures, tag, source, ledger: explanation.scoreLedger, expectedBand });
  expect(failures, tag, isStringArray(explanation.positives) && explanation.positives.length > 0,
    `${source} score explanation positives must be a non-empty string array`);
  expect(failures, tag, isStringArray(explanation.limits) && explanation.limits.length > 0,
    `${source} score explanation limits must be a non-empty string array`);
  verifyExplanationDetails({
    failures,
    tag,
    source,
    label: 'positiveDetails',
    details: explanation.positiveDetails,
    expectedCodes: knownExplanationPositiveCodes,
    text: explanation.positives,
  });
  verifyExplanationDetails({
    failures,
    tag,
    source,
    label: 'limitDetails',
    details: explanation.limitDetails,
    expectedCodes: knownExplanationLimitCodes,
    text: explanation.limits,
  });
  expect(failures, tag, typeof explanation.verdict === 'string' && explanation.verdict.length > 0,
    `${source} score explanation verdict must be present`);
  const recommendation = explanation.recommendationDecision;
  failures.push(...verifyRecommendationDecisionContract({
    tag,
    label: `${source} recommendationDecision`,
    decision: recommendation,
    expectedStatus: explanation.scoreLedger?.status,
    expectedScore: explanation.scoreLedger?.finalScore,
    expectedSelected: recommended,
  }));
  if (isObject(recommendation)) {
    expect(failures, tag, recommendation.threshold === REC_THRESHOLD,
      `${source} recommendationDecision threshold must be ${REC_THRESHOLD}`);
    expect(failures, tag, recommendation.recencyTolerance === RECOMMENDATION_RECENCY_TOLERANCE,
      `${source} recommendationDecision recencyTolerance must be ${RECOMMENDATION_RECENCY_TOLERANCE}`);
    if (
      typeof recommendation.decisionCode === 'string' &&
      typeof recommendation.releaseTag === 'string' &&
      (recommendation.releaseScore == null || typeof recommendation.releaseScore === 'number') &&
      (recommendation.selectedTag == null || typeof recommendation.selectedTag === 'string') &&
      (recommendation.selectedScore == null || typeof recommendation.selectedScore === 'number') &&
      (recommendation.highestScoringTag == null || typeof recommendation.highestScoringTag === 'string') &&
      (recommendation.highestScore == null || typeof recommendation.highestScore === 'number') &&
      typeof recommendation.threshold === 'number' &&
      typeof recommendation.recencyTolerance === 'number'
    ) {
      expect(failures, tag, recommendation.summary === recommendationDecisionSummary(recommendation),
        `${source} recommendationDecision summary must match its canonical decision fields`);
    }
    if (recommendation.selected === true) {
      const recommendedDetail = explanation.positiveDetails?.find((detail) => detail?.code === 'release_recommended');
      expect(failures, tag, recommendedDetail?.text === humanRecommendationDecisionSummary(recommendation),
        `${source} release_recommended positive detail must match human recommendation copy`);
    }
  }
  if (recommended) {
    expect(failures, tag, explanation.positives.some((line) => /recommended/i.test(line)),
      `${source} recommended release explanation must include a recommended positive signal`);
  }
  expect(failures, tag, !/looks safe to install|safe target|broadly safe/i.test(explanation.verdict),
    `${source} score explanation verdict must not overclaim safety`);
  for (const line of [...explanation.positives, ...explanation.limits]) {
    expect(failures, tag, !/\.\.\.\./.test(line), `${source} score explanation lines must not contain four-dot truncation`);
  }
}

function verifyRecommendationDecisionSet({ failures, rows }) {
  const scoreRanked = rows
    .filter((row) => row?.status === 'eligible' && typeof row?.finalScore === 'number')
    .slice()
    .sort((left, right) =>
      right.finalScore - left.finalScore ||
      rows.indexOf(left) - rows.indexOf(right)
    );
  const selection = selectRecommendation(rows.map((row) => ({
    tag: row?.tag,
    status: row?.status,
    score: row?.finalScore,
  })));
  for (const [index, row] of rows.entries()) {
    const decision = row?.explanation?.recommendationDecision;
    if (!isObject(decision)) continue;
    const scoreRankIndex = scoreRanked.findIndex((candidate) => candidate.tag === row.tag);
    expect(failures, row.tag, decision.recencyRank === index + 1,
      `releases recommendationDecision recencyRank (${decision.recencyRank}) must equal ${index + 1}`);
    expect(failures, row.tag, decision.scoreRank === (scoreRankIndex >= 0 ? scoreRankIndex + 1 : null),
      `releases recommendationDecision scoreRank (${decision.scoreRank}) must match score ordering`);
    expect(failures, row.tag, decision.selectedTag === selection.selectedTag,
      `releases recommendationDecision selectedTag (${decision.selectedTag}) must equal ${selection.selectedTag}`);
    expect(failures, row.tag, decision.selectedScore === selection.selectedScore,
      `releases recommendationDecision selectedScore (${decision.selectedScore}) must equal ${selection.selectedScore}`);
    expect(failures, row.tag, decision.highestScoringTag === selection.highestScoringTag,
      `releases recommendationDecision highestScoringTag (${decision.highestScoringTag}) must equal ${selection.highestScoringTag}`);
    expect(failures, row.tag, decision.highestScore === selection.highestScore,
      `releases recommendationDecision highestScore (${decision.highestScore}) must equal ${selection.highestScore}`);
    expect(failures, row.tag, decision.selected === (row.tag === selection.selectedTag),
      `releases recommendationDecision selected (${decision.selected}) must match selectedTag`);
  }
}

function verifyScoreLedger({ failures, tag, source, ledger, expectedBand = null }) {
  expect(failures, tag, isObject(ledger), `${source} score explanation scoreLedger must be present`);
  if (!isObject(ledger)) return;
  verifyAllowedKeys({ failures, tag, label: `${source} scoreLedger`, value: ledger, allowed: ledgerKeys });
  expect(failures, tag, ledger.schemaVersion === SCORE_LEDGER_SCHEMA_VERSION,
    `${source} scoreLedger schemaVersion must be ${SCORE_LEDGER_SCHEMA_VERSION}, got ${JSON.stringify(ledger.schemaVersion)}`);
  expect(failures, tag, ledger.ledgerType === SCORE_LEDGER_TYPE,
    `${source} scoreLedger ledgerType must be ${SCORE_LEDGER_TYPE}`);
  expect(failures, tag, ledger.immutable === true,
    `${source} scoreLedger immutable must be true`);
  expect(failures, tag, ledger.finalScore == null || typeof ledger.finalScore === 'number',
    `${source} scoreLedger finalScore must be numeric or null`);
  expect(failures, tag, typeof ledger.status === 'string' && ledger.status.length > 0,
    `${source} scoreLedger status must be present`);
  expect(failures, tag, typeof ledger.band === 'string' && ledger.band.length > 0,
    `${source} scoreLedger band must be present`);
  if (expectedBand != null) {
    expect(failures, tag, ledger.band === expectedBand,
      `${source} scoreLedger band (${ledger.band}) must match release band (${expectedBand})`);
  }
  for (const problem of scoreLedgerV2Problems(ledger)) {
    failures.push(`${tag}: ${source} ${problem}`);
  }
  expect(failures, tag, Array.isArray(ledger.operations) && ledger.operations.length > 0,
    `${source} scoreLedger operations must include the ordered derivation`);
  expect(failures, tag, Array.isArray(ledger.rows) && ledger.rows.length > 0,
    `${source} scoreLedger presentation rows must be present`);
  verifyScoreLedgerIdentity({ failures, tag, source, ledger });
  for (const row of ledger.rows ?? []) {
    expect(failures, tag, isObject(row), `${source} scoreLedger row must be an object`);
    if (!isObject(row)) continue;
    verifyAllowedKeys({ failures, tag, label: `${source} scoreLedger row ${String(row.key ?? '?')}`, value: row, allowed: ledgerRowKeys });
    expect(failures, tag, typeof row.key === 'string' && row.key.length > 0,
      `${source} scoreLedger row key must be present`);
    expect(failures, tag, typeof row.label === 'string' && row.label.length > 0,
      `${source} scoreLedger row label must be present`);
    expect(failures, tag, typeof row.points === 'number' && Number.isFinite(row.points),
      `${source} scoreLedger row ${row.key} points must be numeric`);
    expect(failures, tag, ['base', 'bonus', 'penalty', 'neutral'].includes(row.kind),
      `${source} scoreLedger row ${row.key} kind must be known`);
    const expectedKind = expectedScoreLedgerRowKind(row);
    expect(failures, tag, row.kind === expectedKind,
      `${source} scoreLedger row ${row.key} kind (${row.kind}) must match expected kind (${expectedKind}) for points ${row.points}`);
    if ('metric' in row) {
      expect(failures, tag, row.metric == null || ['number', 'string'].includes(typeof row.metric),
        `${source} scoreLedger row ${row.key} metric must be null, number, or string`);
    }
    if ('note' in row) {
      expect(failures, tag, row.note == null || typeof row.note === 'string',
        `${source} scoreLedger row ${row.key} note must be null or string`);
    }
  }
  expect(failures, tag, Array.isArray(ledger.caps), `${source} scoreLedger caps must be an array`);
  verifyScoreLedgerCapIdentity({ failures, tag, source, caps: ledger.caps ?? [] });
  for (const cap of ledger.caps ?? []) {
    expect(failures, tag, isObject(cap), `${source} scoreLedger cap must be an object`);
    if (!isObject(cap)) continue;
    verifyAllowedKeys({ failures, tag, label: `${source} scoreLedger cap ${String(cap.key ?? '?')}`, value: cap, allowed: ledgerCapKeys });
    expect(failures, tag, typeof cap.key === 'string' && cap.key.length > 0,
      `${source} scoreLedger cap key must be present`);
    expect(failures, tag, typeof cap.label === 'string' && cap.label.length > 0,
      `${source} scoreLedger cap ${cap.key} label must be present`);
    expect(failures, tag, typeof cap.ceiling === 'number' && Number.isFinite(cap.ceiling),
      `${source} scoreLedger cap ${cap.key} ceiling must be numeric`);
    expect(failures, tag, typeof cap.applied === 'boolean',
      `${source} scoreLedger cap ${cap.key} applied must be boolean`);
    expect(failures, tag, cap.reason == null || typeof cap.reason === 'string',
      `${source} scoreLedger cap ${cap.key} reason must be string`);
  }
}

function verifyScoreLedgerIdentity({ failures, tag, source, ledger }) {
  const rows = Array.isArray(ledger.rows) ? ledger.rows.filter(isObject) : [];
  const keys = rows.map((row) => row.key);
  const duplicateKeys = keys.filter((key, index) => typeof key === 'string' && keys.indexOf(key) !== index);
  expect(failures, tag, duplicateKeys.length === 0,
    `${source} scoreLedger rows must not contain duplicate keys: ${[...new Set(duplicateKeys)].join(', ')}`);

  const componentStatus = ledger.status === 'eligible' || ledger.status === 'skip-hotfix';
  if (componentStatus) {
    const expectedKeys = componentLedgerRows.map(([key]) => key);
    const prefix = keys.slice(0, expectedKeys.length);
    expect(failures, tag, stableJson(prefix) === stableJson(expectedKeys),
      `${source} scoreLedger component row order must be ${expectedKeys.join(', ')}, got ${keys.join(', ')}`);
    const trailing = keys.slice(expectedKeys.length);
    expect(failures, tag, trailing.length === 0 || stableJson(trailing) === stableJson(['precisionAdjustment']),
      `${source} scoreLedger precisionAdjustment must be the only optional trailing row, got ${trailing.join(', ')}`);
  } else {
    expect(failures, tag, keys.length === 1 && gateLedgerLabels.has(keys[0]),
      `${source} scoreLedger gate rows must contain exactly one known gate row, got ${keys.join(', ')}`);
  }

  for (const row of rows) {
    const expectedLabel = componentLedgerLabels.get(row.key) ?? optionalLedgerLabels.get(row.key) ?? gateLedgerLabels.get(row.key);
    expect(failures, tag, !!expectedLabel,
      `${source} scoreLedger unknown row key ${JSON.stringify(row.key)}`);
    if (expectedLabel) {
      expect(failures, tag, row.label === expectedLabel,
        `${source} scoreLedger row ${row.key} label (${JSON.stringify(row.label)}) must be ${JSON.stringify(expectedLabel)}`);
    }
  }
}

function verifyScoreLedgerCapIdentity({ failures, tag, source, caps }) {
  const validCaps = Array.isArray(caps) ? caps.filter(isObject) : [];
  const keys = validCaps.map((cap) => cap.key);
  const duplicateKeys = keys.filter((key, index) => typeof key === 'string' && keys.indexOf(key) !== index);
  expect(failures, tag, duplicateKeys.length === 0,
    `${source} scoreLedger caps must not contain duplicate keys: ${[...new Set(duplicateKeys)].join(', ')}`);
  const knownCapOrder = [...ledgerCapLabels.keys()];
  let lastOrder = -1;
  for (const cap of validCaps) {
    const expectedLabel = ledgerCapLabels.get(cap.key);
    expect(failures, tag, !!expectedLabel,
      `${source} scoreLedger unknown cap key ${JSON.stringify(cap.key)}`);
    if (expectedLabel) {
      const order = knownCapOrder.indexOf(cap.key);
      expect(failures, tag, order > lastOrder,
        `${source} scoreLedger cap order must be ${knownCapOrder.join(', ')}, got ${keys.join(', ')}`);
      lastOrder = order;
      expect(failures, tag, cap.label === expectedLabel,
        `${source} scoreLedger cap ${cap.key} label (${JSON.stringify(cap.label)}) must be ${JSON.stringify(expectedLabel)}`);
    }
  }
}

function scoreLedgerKindForPoints(points) {
  if (points > 0) return 'bonus';
  if (points < 0) return 'penalty';
  if (points === 0) return 'neutral';
  return null;
}

function expectedScoreLedgerRowKind(row) {
  if (row.key === 'base') return 'base';
  if (row.key === 'cveGate') return 'penalty';
  if (row.key === 'settleGate') return 'neutral';
  return scoreLedgerKindForPoints(row.points);
}

function sameNumber(left, right) {
  return typeof left === 'number' && typeof right === 'number' && Math.abs(left - right) <= 1e-9;
}

function sameNumberOrNull(left, right) {
  if (left == null || right == null) return left == null && right == null;
  return sameNumber(Number(left), Number(right));
}

function verifyExplanationDetails({ failures, tag, source, label, details, expectedCodes, text }) {
  expect(failures, tag, Array.isArray(details),
    `${source} score explanation ${label} must be an array`);
  if (!Array.isArray(details)) return;
  expect(failures, tag, details.length === text.length,
    `${source} score explanation ${label} length (${details.length}) must match text length (${text.length})`);
  for (let idx = 0; idx < details.length; idx++) {
    const detail = details[idx];
    expect(failures, tag, isObject(detail),
      `${source} score explanation ${label}[${idx}] must be an object`);
    if (!isObject(detail)) continue;
    verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}]`, value: detail, allowed: explanationDetailKeys });
    expect(failures, tag, typeof detail.code === 'string' && /^[a-z0-9_]+$/.test(detail.code),
      `${source} score explanation ${label}[${idx}] code must be snake_case`);
    expect(failures, tag, expectedCodes.has(detail.code),
      `${source} score explanation ${label}[${idx}] code ${JSON.stringify(detail.code)} must be known for ${label}`);
    expect(failures, tag, detail.text === text[idx],
      `${source} score explanation ${label}[${idx}] text must match prose line`);
    const expectedLabel = expectedExplanationDetailLabels.get(detail.code);
    expect(failures, tag, typeof detail.label === 'string' && detail.label.length > 0,
      `${source} score explanation ${label}[${idx}] label must be present`);
    if (expectedLabel) {
      expect(failures, tag, detail.label === expectedLabel,
        `${source} score explanation ${label}[${idx}] label (${JSON.stringify(detail.label)}) must be ${JSON.stringify(expectedLabel)}`);
    }
    if ('metrics' in detail) {
      expect(failures, tag, isObject(detail.metrics),
        `${source} score explanation ${label}[${idx}] metrics must be an object when present`);
      if (isObject(detail.metrics)) {
        for (const [metricKey, value] of Object.entries(detail.metrics)) {
          expect(failures, tag, isMetricValue(value),
            `${source} score explanation ${label}[${idx}] metrics.${metricKey} must be scalar or a scalar map`);
        }
      }
    }
    if ('buckets' in detail) {
      expect(failures, tag, isObject(detail.buckets),
        `${source} score explanation ${label}[${idx}] buckets must be an object when present`);
      if (isObject(detail.buckets)) verifyNumericMap({ failures, tag, source, label, idx, field: 'buckets', value: detail.buckets });
    }
    if ('riskBuckets' in detail) {
      expect(failures, tag, isObject(detail.riskBuckets),
        `${source} score explanation ${label}[${idx}] riskBuckets must be an object when present`);
      if (isObject(detail.riskBuckets)) verifyNumericMap({ failures, tag, source, label, idx, field: 'riskBuckets', value: detail.riskBuckets });
    }
    if ('issueRefs' in detail) {
      expect(failures, tag, Array.isArray(detail.issueRefs),
        `${source} score explanation ${label}[${idx}] issueRefs must be an array when present`);
      if (Array.isArray(detail.issueRefs)) {
        for (const issue of detail.issueRefs) {
          if (isObject(issue)) {
            verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}] issueRef`, value: issue, allowed: explanationIssueRefKeys });
            if (isObject(issue.proof)) verifyExplanationIssueProof({ failures, tag, source, label, idx, proof: issue.proof });
          }
          expect(failures, tag, isObject(issue) && Number.isInteger(issue.number) && issue.number > 0,
            `${source} score explanation ${label}[${idx}] issueRefs entries must include a positive issue number`);
          expect(failures, tag, isObject(issue) && typeof issue.title === 'string' && issue.title.length > 0,
            `${source} score explanation ${label}[${idx}] issueRefs entries must include a title`);
          expect(failures, tag, isObject(issue) && (issue.url == null || typeof issue.url === 'string'),
            `${source} score explanation ${label}[${idx}] issueRefs url must be null or string`);
          expect(failures, tag, isObject(issue) && (issue.fieldConfirmed == null || typeof issue.fieldConfirmed === 'boolean'),
            `${source} score explanation ${label}[${idx}] issueRefs fieldConfirmed must be null or boolean`);
          verifyConfirmationReasons({
            failures,
            tag,
            path: `${source} score explanation ${label}[${idx}] issueRef confirmationReasons`,
            value: issue?.confirmationReasons,
          });
          expect(failures, tag, isObject(issue) && (issue.releaseLocal == null || typeof issue.releaseLocal === 'boolean'),
            `${source} score explanation ${label}[${idx}] issueRefs releaseLocal must be null or boolean`);
          expect(failures, tag, isObject(issue) && (issue.releaseLocalEvidence == null || isObject(issue.releaseLocalEvidence)),
            `${source} score explanation ${label}[${idx}] issueRefs releaseLocalEvidence must be null or object`);
          if (isObject(issue?.releaseLocalEvidence)) {
            verifyAllowedKeys({
              failures,
              tag,
              label: `${source} score explanation ${label}[${idx}] issueRef releaseLocalEvidence`,
              value: issue.releaseLocalEvidence,
              allowed: releaseLocalEvidenceKeys,
            });
            verifyReleaseLocalEvidence({
              failures,
              tag,
              path: `${source} score explanation ${label}[${idx}] issueRefs releaseLocalEvidence`,
              value: issue.releaseLocalEvidence,
            });
          }
          expect(failures, tag, isObject(issue) && (
            issue.releaseScopedState == null ||
            ['open', 'closed', 'closed-unverified'].includes(issue.releaseScopedState)
          ), `${source} score explanation ${label}[${idx}] issueRefs releaseScopedState must be null or known state`);
          expect(failures, tag, isObject(issue) && (issue.scoringReason == null || typeof issue.scoringReason === 'string'),
            `${source} score explanation ${label}[${idx}] issueRefs scoringReason must be null or string`);
        }
      }
    }
  }
}

function verifyConfirmationReasons({ failures, tag, path, value }) {
  if (value == null) return;
  expect(failures, tag, Array.isArray(value), `${path} must be an array`);
  if (!Array.isArray(value)) return;
  for (const [index, reason] of value.entries()) {
    const reasonPath = `${path}[${index}]`;
    expect(failures, tag, isObject(reason), `${reasonPath} must be an object`);
    if (!isObject(reason)) continue;
    verifyAllowedKeys({
      failures,
      tag,
      label: reasonPath,
      value: reason,
      allowed: confirmationReasonKeys,
    });
    expect(failures, tag,
      ['independent_human_reproduction', 'human_applied_p0', 'human_applied_p1', 'human_applied_regression'].includes(reason.code),
      `${reasonPath} code must be known`);
    expect(failures, tag, ['comment', 'label_event'].includes(reason.source),
      `${reasonPath} source must be known`);
    expect(failures, tag, typeof reason.author === 'string' && reason.author.length > 0,
      `${reasonPath} author must be present`);
    expect(failures, tag,
      typeof reason.occurredAt === 'string' && Number.isFinite(Date.parse(reason.occurredAt)),
      `${reasonPath} occurredAt must be a timestamp`);
    if (Object.hasOwn(reason, 'association')) {
      expect(failures, tag,
        reason.association == null ||
          (typeof reason.association === 'string' && reason.association.length > 0),
        `${reasonPath} association must be a non-empty string or null`);
    }
    if (Object.hasOwn(reason, 'commentId')) {
      expect(failures, tag, Number.isInteger(reason.commentId) && reason.commentId > 0,
        `${reasonPath} commentId must be positive`);
    }
    for (const key of ['commentUrl', 'eventId', 'snippet']) {
      if (Object.hasOwn(reason, key)) {
        expect(failures, tag, typeof reason[key] === 'string' && reason[key].length > 0,
          `${reasonPath} ${key} must be present`);
      }
    }
    if (Object.hasOwn(reason, 'label')) {
      expect(failures, tag, ['P0', 'P1', 'regression'].includes(reason.label),
        `${reasonPath} label must be known`);
    }
    if (reason.source === 'comment') {
      verifyRequiredOwnKeys({
        failures,
        tag,
        label: reasonPath,
        value: reason,
        required: commentConfirmationRequiredKeys,
      });
      expect(failures, tag, reason.code === 'independent_human_reproduction',
        `${reasonPath} comment evidence code must be independent_human_reproduction`);
      expect(failures, tag,
        typeof reason.updatedAt === 'string' &&
          Number.isFinite(Date.parse(reason.updatedAt)) &&
          Date.parse(reason.updatedAt) >= Date.parse(reason.occurredAt),
        `${reasonPath} updatedAt must be a timestamp at or after occurredAt`);
      expect(failures, tag, Number.isInteger(reason.commentId) && reason.commentId > 0,
        `${reasonPath} commentId must be positive`);
      expect(failures, tag, typeof reason.commentUrl === 'string' && reason.commentUrl.length > 0,
        `${reasonPath} commentUrl must be present`);
      for (const key of [
        'issueNodeId',
        'issueAuthorNodeId',
        'issueAuthorType',
        'commentNodeId',
        'actorNodeId',
      ]) {
        expect(failures, tag, typeof reason[key] === 'string' && reason[key].length > 0,
          `${reasonPath} ${key} must be present`);
      }
      expect(failures, tag, reason.commentNodeType === 'IssueComment',
        `${reasonPath} commentNodeType must be IssueComment`);
      expect(failures, tag, reason.actorType === 'User',
        `${reasonPath} actorType must be User`);
      expect(failures, tag,
        reason.actorNodeId !== reason.issueAuthorNodeId ||
          reason.actorType !== reason.issueAuthorType,
        `${reasonPath} actor must be independent from the issue author`);
      expect(failures, tag,
        typeof reason.commentBodyDigest === 'string' &&
          /^[0-9a-f]{64}$/.test(reason.commentBodyDigest),
        `${reasonPath} commentBodyDigest must be SHA-256`);
      expect(failures, tag, typeof reason.snippet === 'string' && reason.snippet.length > 0,
        `${reasonPath} snippet must be present`);
      for (const key of ['label', 'eventId']) {
        expect(failures, tag, !Object.hasOwn(reason, key),
          `${reasonPath} ${key} is not allowed for comment evidence`);
      }
    } else if (reason.source === 'label_event') {
      verifyRequiredOwnKeys({
        failures,
        tag,
        label: reasonPath,
        value: reason,
        required: ['label', 'eventId'],
      });
      expect(failures, tag, ['P0', 'P1', 'regression'].includes(reason.label),
        `${reasonPath} label must be known`);
      expect(failures, tag, typeof reason.eventId === 'string' && reason.eventId.length > 0,
        `${reasonPath} eventId must be present`);
      if (confirmationReasonCodeByLabel.has(reason.label)) {
        expect(failures, tag, reason.code === confirmationReasonCodeByLabel.get(reason.label),
          `${reasonPath} code must match label ${reason.label}`);
      }
      for (const key of commentOnlyConfirmationReasonKeys) {
        expect(failures, tag, !Object.hasOwn(reason, key),
          `${reasonPath} ${key} is not allowed for label_event evidence`);
      }
    }
  }
}

function verifyReleaseLocalEvidence({ failures, tag, path, value }) {
  expect(failures, tag,
    value.kind === 'exact-version' &&
    ['title', 'body', 'comment'].includes(value.source) &&
    typeof value.version === 'string' &&
    value.version.length > 0 &&
    typeof value.snippet === 'string' &&
    value.snippet.length > 0,
    `${path} must describe exact-version evidence`);
  if (value.source === 'comment') {
    verifyRequiredOwnKeys({
      failures,
      tag,
      label: path,
      value,
      required: releaseLocalCommentKeys,
    });
    expect(failures, tag, Number.isInteger(value.commentId) && value.commentId > 0,
      `${path} commentId must be positive`);
    expect(failures, tag, typeof value.commentUrl === 'string' && value.commentUrl.length > 0,
      `${path} commentUrl must be present`);
    expect(failures, tag, typeof value.author === 'string' && value.author.length > 0,
      `${path} author must be present`);
    expect(failures, tag,
      typeof value.commentNodeId === 'string' && value.commentNodeId.length > 0,
      `${path} commentNodeId must be present`);
    expect(failures, tag,
      typeof value.actorNodeId === 'string' && value.actorNodeId.length > 0,
      `${path} actorNodeId must be present`);
    expect(failures, tag, value.actorType === 'User',
      `${path} actorType must be User`);
    expect(failures, tag,
      value.association == null ||
        (typeof value.association === 'string' && value.association.length > 0),
      `${path} association must be a non-empty string or null`);
    expect(failures, tag,
      typeof value.occurredAt === 'string' &&
        Number.isFinite(Date.parse(value.occurredAt)),
      `${path} occurredAt must be a timestamp`);
    expect(failures, tag,
      typeof value.updatedAt === 'string' &&
        Number.isFinite(Date.parse(value.updatedAt)) &&
        Date.parse(value.updatedAt) >= Date.parse(value.occurredAt),
      `${path} updatedAt must be a timestamp at or after occurredAt`);
    expect(failures, tag,
      typeof value.commentBodyDigest === 'string' &&
        /^[0-9a-f]{64}$/.test(value.commentBodyDigest),
      `${path} commentBodyDigest must be SHA-256`);
  } else if (['title', 'body'].includes(value.source)) {
    for (const key of releaseLocalCommentKeys) {
      expect(failures, tag, !Object.hasOwn(value, key),
        `${path} ${key} is not allowed for ${value.source} evidence`);
    }
  }
}

function isMetricValue(value) {
  if (value == null || ['number', 'string', 'boolean'].includes(typeof value)) return true;
  if (!isObject(value)) return false;
  return Object.values(value).every((child) => child == null || ['number', 'string', 'boolean'].includes(typeof child));
}

function verifyNumericMap({ failures, tag, source, label, idx, field, value }) {
  for (const [key, count] of Object.entries(value)) {
    expect(failures, tag, typeof key === 'string' && key.length > 0,
      `${source} score explanation ${label}[${idx}] ${field} keys must be non-empty strings`);
    expect(failures, tag, typeof count === 'number' && Number.isFinite(count),
      `${source} score explanation ${label}[${idx}] ${field}.${key} must be numeric`);
  }
}

function verifyExplanationIssueProof({ failures, tag, source, label, idx, proof }) {
  verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}] issueRef proof`, value: proof, allowed: explanationIssueProofKeys });
  for (const [key, value] of Object.entries(proof)) {
    if (key === 'canonicalPath' && value != null) {
      expect(failures, tag, Array.isArray(value) && value.every((item) => Number.isInteger(item) && item > 0),
        `${source} score explanation ${label}[${idx}] issueRef proof canonicalPath must contain positive issue numbers`);
    }
    if (key === 'canonicalIssue' && value != null) {
      verifyLinkedExplanationRef({ failures, tag, source, label, idx, key, value });
    }
    if ([
      'openPrs',
      'reachablePrs',
      'notReachablePrs',
      'unknownReachabilityPrs',
      'closedUnmergedPrs',
      'externalClosingPrs',
    ].includes(key) && value != null) {
      expect(failures, tag, Array.isArray(value),
        `${source} score explanation ${label}[${idx}] issueRef proof ${key} must be an array`);
      if (Array.isArray(value)) {
        for (const ref of value) verifyLinkedExplanationRef({ failures, tag, source, label, idx, key, value: ref });
      }
    }
  }
}

function verifyLinkedExplanationRef({ failures, tag, source, label, idx, key, value }) {
  expect(failures, tag, isObject(value),
    `${source} score explanation ${label}[${idx}] issueRef proof ${key} entries must be objects`);
  if (!isObject(value)) return;
  verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}] issueRef proof ${key}`, value, allowed: explanationLinkedRefKeys });
  expect(failures, tag, Number.isInteger(value.number) && value.number > 0,
    `${source} score explanation ${label}[${idx}] issueRef proof ${key} entries must include a positive number`);
  if ('title' in value) {
    expect(failures, tag, value.title == null || typeof value.title === 'string',
      `${source} score explanation ${label}[${idx}] issueRef proof ${key} title must be null or string`);
  }
  if ('url' in value) {
    expect(failures, tag, value.url == null || typeof value.url === 'string',
      `${source} score explanation ${label}[${idx}] issueRef proof ${key} url must be null or string`);
  }
}
