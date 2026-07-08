import { PROMPT_VERSION, type IssueClassification } from './llm';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { config } from '../config';
import {
  applyClosureRiskSentimentHint,
  applyLabelOverrides,
  applyTitleFunctionalityHint,
  applyTitleIssueShapeHint,
  labelAuthorizedForScoring,
  type LabelOverrideAuthority,
} from './labelOverrides';
import { releaseLabelCutoff } from './labelCutoff';
import {
  applyExclusiveIssueRiskLedger,
  bindScoreExplanationAudit,
  buildScoreLedgerV2,
  cveDecayLoad,
  explainFeltLoad,
  explainOpenDebtLoad,
  feltLoad,
  installConfidence,
  isFeltSignal,
  REC_THRESHOLD,
  RECOMMENDATION_RECENCY_TOLERANCE,
  semanticHumanConfirmationReasons,
  selectRecommendation,
  compareRecommendationRecency,
  SCORE_COMPONENT_LIMITS,
  SCORE_EXPLANATION_CANONICAL_LABELS,
  SCORE_LEDGER_SCHEMA_VERSION,
  SCORE_MODEL_VERSION,
  scoreLedgerV2Problems,
  adverseReproductionClaim,
  scoreCommentBodyDigest,
  type InstallConfidence,
  type InstallInput,
  type ConfirmationReason,
  type ReleaseLocalEvidence,
  type ScoreLedgerEvidenceSourceInput,
  type ScoreLedgerPresentationCap,
  type ScoreLedgerPresentationRow,
  type ScoreLedgerV2,
} from './score';
import { hasHotfixSuccessor } from './releaseNotes';
import { compareVersions, isRangeParseable, stableDistance, matchesRange } from './versionMatch';
import { topBrokenSurfaces } from './surfaces';
import {
  closureProofPayload,
  closureRiskDisposition,
  closureRiskWeightForRow,
  enrichGateEvidenceWithClosureProof,
  scoreAffectingMissingEvidenceClosureRows,
  type MissingClosureEvidenceDiagnostic,
} from './closureProofPayload';
import { closureRiskDispositionLabel } from './closureProofTaxonomy';
import {
  aggregateClosureRisk,
  buildIssueAliasGroups,
  canonicalIssueNumbersFromEvidence,
} from './closureRiskAggregation';
import {
  recommendationDecisionSummary as canonicalRecommendationDecisionSummary,
  validateRecommendationDecisionRun,
} from './recommendationDecision';
import {
  RELEASE_VALIDATION_HORIZONS,
  RELEASE_VALIDATION_OPPORTUNITIES,
  releaseValidationDecisionId,
  releaseValidationForecastContentHash,
  releaseCatalogAttestationProblems,
  releaseValidationForecastTiming,
  releaseValidationScoreCommitTimingProblems,
  validateReleaseValidationForecastProvenance,
  type ReleaseCatalogAttestation,
  type ReleaseValidationHorizonCode,
  type ReleaseValidationScoreCommitTiming,
} from './releaseValidation';
import { normalizeCodeRevision } from './codeRevision';
import { canonicalJson as canonicalOperationJson } from './operationReceipts';
import {
  ARTIFACT_VERIFICATION_SCHEMA_VERSION as ARTIFACT_EVIDENCE_SCHEMA_VERSION,
  releaseArtifactScoreProjection,
} from './artifactVerification';
import {
  completeIssueComments,
  closedBeforeReleaseCommentCandidates,
  assertCatalogAttestationMatchesCurrent,
  detectBot,
  getReleaseArtifactVerificationForScoring,
  getReleaseCommit,
  getIssue,
  issueLabelEventCount,
  issueLabelSnapshotCountAt,
  insertReleaseScoreAuditHistory,
  sealReleaseScoreAuditHistoryRun,
  insertReleaseValidationForecast,
  appendReleaseValidationProof,
  issueCountForVersion,
  issuesForVersion,
  labelsForIssueAt,
  latestIssueLabelEventAt,
  listReleaseScoreAuditHistoryForRun,
  listActiveReleaseCatalogDb,
  listAdvisories,
  listReleasesDb,
  openedDuringReign,
  formatReleaseClosureProofIntegrityFailure,
  formatReleaseIssueStateSnapshotIntegrityFailure,
  formatReleaseIssueTimelineIntegrityFailure,
  formatReleasePrReachabilityIntegrityFailure,
  formatStableReleaseWindowIntegrityFailure,
  clearReleaseScoresOutsideTags,
  classifierSourceIdentity,
  closureClaimAuthorityEvidenceForCandidate,
  closureProofRows,
  getRelease,
  getReleaseValidationForecastForSlot,
  readReleaseValidationProofBundle,
  getMeta,
  getReleaseScoreAuditHistoryV2Seal,
  getReleaseScoreAuditHistoryRunSeal,
  getScoreAuthorityResolutionRun,
  insertScoreAuthorityResolutionRun,
  labelAuthorityEvidenceForEvent,
  listScoreAuthorityResolutionRuns,
  releaseScoreAuditHistoryV2SealChainProblems,
  releaseFixCreditDecision,
  releaseFixCreditPayloadProblems,
  releaseClosureProofIntegrity,
  releaseCommentClassificationIntegrity,
  releaseIssueStateSnapshotIntegrity,
  releaseIssueTimelineIntegrity,
  releasePrReachabilityIntegrity,
  scoreSourceIdentity,
  scoreAuthorityResolutionRunChainProblems,
  setMeta,
  stableReleaseWindowIntegrity,
  unclassifiedIssuesForVersion,
  updateReleaseScore,
  upsertReleaseScoreAudit,
  runInWriteTransaction,
  runInReadTransaction,
  sealReleaseScoreAuditHistoryV2,
  unverifiedClosedForRelease,
  verifiedFixedForRelease,
  type JoinedIssue,
  type ReleaseAttributionCandidateRow,
  type ReleaseRow,
  type ReleaseScoreAuditInput,
  type ReleaseValidationForecastRow,
  type ReleaseValidationForecastInsertResult,
} from './db';
import {
  canonicalReleaseValidationProofJson,
  createReleaseValidationStableReleaseIdentity,
  sealReleaseValidationForecastV2,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationCohort,
  type ReleaseValidationForecastV2,
  type ReleaseValidationObligation,
  type ReleaseValidationProofBundle,
  type ReleaseValidationProofJsonValue,
  type ReleaseValidationSplitAssignment,
  type ReleaseValidationStableReleaseIdentity,
} from './releaseValidationProof';
import {
  buildScoreAuthorityReference,
  buildScoreCommentAuthorityResolution,
  buildScoreClosureClaimAuthorityResolution,
  buildScoreAuthorityResolution,
  buildScoreAuthorityResolutionRun,
  canonicalScoreAuthorityReferenceJson,
  canonicalScoreAuthoritySubjectResolutionJson,
  scoreAuthorityReferenceDigest,
  scoreAuthorityReferenceProblems,
  type ScoreCommentAuthorityEvidence,
  type ScoreAuthorityReference,
  type ScoreAuthorityResolution,
  type ScoreAuthorityResolutionRun,
  type ScoreAuthorityResolutionSubject,
} from './scoreAuthorityResolution';
import {
  scoringLabelInfoAtCutoff,
  scoringLabelsAtCutoff,
} from './scoringLabelAuthority';
export {
  scoringLabelInfoAtCutoff,
  scoringLabelsAtCutoff,
  type ScoringLabelInfoAtCutoff,
} from './scoringLabelAuthority';
import {
  canonicalCommentActorIdentity,
  canonicalCommentSourceIdentity,
  type CommentEvidenceRow,
} from './commentEvidence';
import {
  createReleaseClosureAuthorityEvaluation,
  selectAuthorizedReleaseNotAffectedClaim,
  selectClosureDispositionAuthority,
  type ClosureClaimAuthorityBinding,
} from './closureClaimAuthorityEvaluation';

export { PROMPT_VERSION, SCORE_LEDGER_SCHEMA_VERSION, SCORE_MODEL_VERSION };

export interface ReleaseScoreRunOptions {
  releases?: ReleaseRow[];
  releaseLimit?: number;
  allFetchedTags?: string[];
  stableTagsNewestFirst?: string[];
  oldestScoredStablePredecessorTag?: string | null;
  nowForRelease?: (release: ReleaseRow) => number;
  artifactObservationRunId?: string | null;
}

export interface ReleaseScoreResult {
  rel: ReleaseRow;
  scoredAt: string;
  analysisCompleteness: ScoreAnalysisCompleteness;
  conf: InstallConfidence;
  input: InstallInput;
  scoreLedger: ScoreLedgerV2;
  explanation: ScoreExplanation;
  debtEvidence: Record<string, unknown>;
  gateEvidence: Record<string, unknown>;
  neg: number;
  pos: number;
  openedSerious: number;
  closedSerious: number;
  brokenSurfaces: string;
  recommendationDecision?: RecommendationDecision;
  authorityReferences: ScoreAuthorityReference[];
}

export interface ScoreAnalysisCompleteness {
  complete: boolean;
  missingClosureEvidence: MissingClosureEvidenceDiagnostic[];
}

export interface CurrentScoreCompletenessDiagnostic {
  schemaVersion: 1;
  tag: string;
  complete: boolean;
  declaredComplete: boolean | null;
  causes: Array<
    'analysis_completeness_false' |
    'score_affecting_missing_closure_evidence'
  >;
  missingClosureEvidence: MissingClosureEvidenceDiagnostic[];
  missingClosureEvidenceCount: number;
  potentialMissingClosureRiskWeight: number;
  problems: string[];
}

export interface ReleaseScoreRun {
  scored: ReleaseScoreResult[];
  recommendedTag: string | null;
  sourceIdentity: ReturnType<typeof scoreSourceIdentity>;
  authoritySubjects: ScoreAuthorityResolutionSubject[];
  stableTagsNewestFirst: string[];
  oldestScoredStableTag: string | null;
  oldestScoredStablePredecessorTag: string | null;
  predecessorByReleaseTag: Record<string, string | null>;
  predecessorBoundaryProblems: string[];
  artifactObservationRunId: string | null;
}

export interface ReleaseScorePersistenceContext {
  source?: string;
  scope?: string | null;
  issueCrawl?: Record<string, unknown> | null;
  runId?: string | null;
  codeRevision?: string | null;
  catalogAttestation?: ReleaseCatalogAttestation | null;
  clock?: ScoreCommitClock;
}

export interface ScoreCommitClock {
  wallTimeMs: () => number;
  monotonicTimeMs: () => number;
}

export interface ReleaseScorePersistenceResult {
  source: string;
  persistedAt: string;
  historyRunId: string;
  historyRunContentHash: string;
  authorityRunId: string;
  authorityRunContentHash: string;
  historyV2SealContentHash: string;
  commitTiming: ReleaseValidationScoreCommitTiming;
  catalogAttestation: ReleaseCatalogAttestation | null;
  codeRevision: string | null;
  forecastPlan: ReleaseValidationForecastPublicationPlan | null;
  issueCrawlMetadata: Record<string, unknown> | null;
}

export interface ReleaseValidationForecastPublicationPlan {
  schemaVersion: 1;
  preflightAt: string;
  latestReleaseTag: string;
  latestReleasePublishedAt: string;
  selectedTag: string | null;
  scoreModelVersion: string;
  promptVersion: number;
  policyCode: string;
  codeRevision: string;
  slots: Array<{
    opportunityCode: string;
    existingDecisionId: string | null;
    existingContentHash: string | null;
  }>;
}

export interface ReleaseValidationForecastCaptureResult {
  eligibilityOutcome: 'eligible_and_captured' | 'already_captured' | 'not_eligible';
  forecasts: Array<{
    opportunityCode: string;
    status: 'inserted' | 'already_captured';
    decisionId: string;
    codeRevision: string;
  }>;
  canonicalForecasts: Array<{
    opportunityCode: string;
    horizonCode: ReleaseValidationHorizonCode;
    status: 'inserted' | 'already_captured';
    forecastId: string;
    contentHash: string;
    obligationId: string;
    splitAssignmentId: string;
    cohortId: string;
    legacyDecisionId: string;
    legacyContentHash: string;
  }>;
}

export interface ScoreExplanation {
  schemaVersion: number;
  title: string;
  scoreLedger: ScoreExplanationLedger;
  positives: string[];
  positiveDetails: ScoreExplanationDetail[];
  limits: string[];
  limitDetails: ScoreExplanationDetail[];
  verdict: string;
  recommendationDecision?: RecommendationDecision;
  authorityReferences: ScoreAuthorityReference[];
}

export interface RecommendationDecision {
  schemaVersion: 1;
  policyCode: 'highest_confidence_with_recency_tolerance';
  threshold: number;
  recencyTolerance: number;
  selectedTag: string | null;
  selectedScore: number | null;
  highestScoringTag: string | null;
  highestScore: number | null;
  releaseTag: string;
  releaseScore: number | null;
  qualifies: boolean;
  selected: boolean;
  recencyRank: number;
  scoreRank: number | null;
  scoreDeltaToHighest: number | null;
  decisionCode:
    | 'highest_confidence'
    | 'newest_within_confidence_tolerance'
    | 'higher_confidence_release_selected'
    | 'newer_release_within_tolerance_selected'
    | 'below_recommendation_threshold'
    | 'install_gate_active';
  summary: string;
}

export type ScoreExplanationLedger = ScoreLedgerV2;
export type ScoreExplanationLedgerRow = ScoreLedgerPresentationRow;
export type ScoreExplanationCap = ScoreLedgerPresentationCap;

export interface ScoreExplanationDetail {
  code: string;
  label: string;
  text: string;
  metrics?: Record<string, number | string | boolean | null>;
  buckets?: Record<string, number>;
  riskBuckets?: Record<string, number>;
  issueRefs?: ScoreExplanationIssueRef[];
}

export interface ScoreExplanationIssueRef {
  number: number;
  title: string;
  url: string | null;
  state?: string | null;
  status?: string | null;
  tier?: string | null;
  weight?: number | null;
  fieldConfirmed?: boolean | null;
  confirmationReasons?: ConfirmationReason[];
  releaseLocal?: boolean | null;
  releaseLocalEvidence?: ReleaseLocalEvidence | null;
  releaseScopedState?: string | null;
  scoringReason?: string | null;
  installImpactClass?: string | null;
  installImpactMultiplier?: number | null;
  proof?: ScoreExplanationIssueProof | null;
}

export interface ScoreExplanationIssueProof {
  status: string | null;
  statusLabel: string | null;
  riskDisposition: string | null;
  riskDispositionLabel: string | null;
  summary: string | null;
  riskWeight: number | null;
  canonicalIssue?: ScoreExplanationLinkedRef | null;
  canonicalPath?: number[] | null;
  openPrs?: ScoreExplanationLinkedRef[];
  reachablePrs?: ScoreExplanationLinkedRef[];
  notReachablePrs?: ScoreExplanationLinkedRef[];
  unknownReachabilityPrs?: ScoreExplanationLinkedRef[];
  closedUnmergedPrs?: ScoreExplanationLinkedRef[];
  externalClosingPrs?: ScoreExplanationLinkedRef[];
}

export interface ScoreExplanationLinkedRef {
  number: number;
  title?: string | null;
  url?: string | null;
  state?: string | null;
  status?: string | null;
  repositoryNameWithOwner?: string | null;
  source?: string | null;
  merged?: boolean | null;
  mergedAt?: string | null;
  referencedAt?: string | null;
  willCloseTarget?: boolean | null;
  reachabilityMethod?: string | null;
  mergeCommitOid?: string | null;
  sourceCommentUrl?: string | null;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const SHORT_ISSUE_TITLE_LENGTH = 110;
const RELEASE_CHECK_CONTEXT_LIMIT = 25;
const RELEASE_CHECK_FAILURE_STATES = new Set([
  'ACTION_REQUIRED',
  'CANCELLED',
  'ERROR',
  'FAILURE',
  'STALE',
  'STARTUP_FAILURE',
  'TIMED_OUT',
]);
const RELEASE_CHECK_PENDING_STATES = new Set([
  'EXPECTED',
  'IN_PROGRESS',
  'PENDING',
  'PENDING_REQUESTED',
  'QUEUED',
  'REQUESTED',
  'WAITING',
]);
const RELEASE_CHECK_SUCCESS_STATES = new Set(['SUCCESS']);
export const SCORE_INPUT_SCHEMA_VERSION = 2;
export const SCORE_COMPONENTS_SCHEMA_VERSION = 1;
export const SCORE_EXPLANATION_SCHEMA_VERSION = 5;
export const GATE_EVIDENCE_SCHEMA_VERSION = 1;
export const ISSUE_EVIDENCE_SCHEMA_VERSION = 3;
export const LABEL_TIMELINE_SCHEMA_VERSION = 1;
export const RELEASE_CHECKS_SCHEMA_VERSION = 2;
export const ARTIFACT_VERIFICATION_SCHEMA_VERSION =
  ARTIFACT_EVIDENCE_SCHEMA_VERSION;

export function currentScoreCompletenessDiagnostic(input: {
  tag: string;
  labelCutoff?: string | null;
  analysisCompleteness?: ScoreAnalysisCompleteness | null;
  currentMissingClosureEvidence?: MissingClosureEvidenceDiagnostic[];
}): CurrentScoreCompletenessDiagnostic {
  const currentMissingClosureEvidence = input.currentMissingClosureEvidence ??
    scoreAffectingMissingEvidenceClosureRows(input.tag, input.labelCutoff);
  const declaredMissingClosureEvidence =
    input.analysisCompleteness?.missingClosureEvidence ?? [];
  const missingClosureEvidence = mergeMissingClosureEvidence(
    currentMissingClosureEvidence,
    declaredMissingClosureEvidence,
  );
  const problems: string[] = [];
  const causes: CurrentScoreCompletenessDiagnostic['causes'] = [];
  if (input.analysisCompleteness && input.analysisCompleteness.complete !== true) {
    causes.push('analysis_completeness_false');
    problems.push(`${input.tag}: score result analysisCompleteness.complete must be true`);
  }
  if (missingClosureEvidence.length > 0) {
    causes.push('score_affecting_missing_closure_evidence');
    problems.push(
      `${input.tag} closure analysis is incomplete: score-affecting negative ` +
      `missing_evidence ${missingClosureEvidence.length === 1 ? 'row' : 'rows'} ` +
      `${missingClosureEvidence.map((row) =>
        `#${row.issueNumber} status=${row.status}`).join(', ')}`,
    );
  }
  return {
    schemaVersion: 1,
    tag: input.tag,
    complete: causes.length === 0,
    declaredComplete: input.analysisCompleteness?.complete ?? null,
    causes,
    missingClosureEvidence,
    missingClosureEvidenceCount: missingClosureEvidence.length,
    potentialMissingClosureRiskWeight: roundMetric(
      missingClosureEvidence.reduce((sum, row) => sum + row.potentialRiskWeight, 0),
    ),
    problems,
  };
}
export const SCORE_EXPLANATION_LIMIT_CODES = [
  'cve_install_gate',
  'settle_time_gate',
  'hotfix_successor_gate',
  'field_visible_reports_opened',
  'verified_field_blocker_debt',
  'open_unconfirmed_issue_risk',
  'stale_low_confidence_evidence',
  'incomplete_classification_coverage',
  'incomplete_closure_evidence',
  'closed_issues_not_counted_as_release_fixes',
  'audit_only_closed_issue_flags',
  'unverified_closed_fix_reachability',
  'artifact_verification_incomplete',
  'missing_full_release_evidence_report',
  'release_checks_failed',
  'release_checks_pending',
  'model_ceiling_and_capped_confidence',
  'no_remaining_score_gap',
  'score_rounding',
] as const;
export const SCORE_EXPLANATION_POSITIVE_CODES = [
  'no_verified_field_blocker_debt',
  'release_checks_passed',
  'artifact_verified',
  'release_recommended',
  'hard_gates_passed',
] as const;
type ScoreExplanationLimitCode = (typeof SCORE_EXPLANATION_LIMIT_CODES)[number];
type ScoreExplanationPositiveCode = (typeof SCORE_EXPLANATION_POSITIVE_CODES)[number];

export const SCORE_EXPLANATION_DETAIL_LABELS =
  SCORE_EXPLANATION_CANONICAL_LABELS as Record<
    ScoreExplanationLimitCode | ScoreExplanationPositiveCode,
    string
  >;

const RELEASE_SCORE_BINDING_FIELDS = [
  'tag',
  'node_id',
  'catalog_tag_commit_oid',
  'name',
  'published_at',
  'created_at',
  'updated_at',
  'html_url',
  'prerelease',
  'catalog_rank',
  'catalog_digest',
  'catalog_active',
  'body',
  'breaking_count',
  'fixes_count',
  'changes_count',
  'highlights_count',
  'pr_refs_count',
  'beta_count',
  'hours_to_next_release',
  'hours_to_next_stable',
] as const satisfies readonly (keyof ReleaseRow)[];

const CANONICAL_RELEASE_IDENTITY_FIELDS = [
  'tag',
  'node_id',
  'catalog_tag_commit_oid',
  'published_at',
] as const satisfies readonly (keyof ReleaseRow)[];

export function buildReleaseScoreRun(options: ReleaseScoreRunOptions): ReleaseScoreRun {
  return runInReadTransaction(() => buildReleaseScoreRunSnapshot(options));
}

function buildReleaseScoreRunSnapshot(options: ReleaseScoreRunOptions): ReleaseScoreRun {
  const artifactObservationRunId = options.artifactObservationRunId ?? null;
  const sourceIdentityOptions = { artifactObservationRunId };
  const sourceIdentityBefore = scoreSourceIdentity(sourceIdentityOptions);
  const activeCatalog = listActiveReleaseCatalogDb();
  assertFiniteReleasePublicationTimestamps(activeCatalog, 'active release catalog');
  const activeCatalogByTag = new Map(
    activeCatalog.map((release) => [release.tag, release] as const),
  );
  const activeTagWindow = {
    allFetchedTags: activeCatalog.map((release) => release.tag),
    stableTagsNewestFirst: activeCatalog
      .filter((release) => release.prerelease === 0)
      .map((release) => release.tag),
  };
  const canonicalLatestStable = canonicalLatestStableRelease(activeCatalog);
  const suppliedReleases = options.releases ?? listReleasesDb(options.releaseLimit ?? 20);
  const releases = bindSuppliedScoreReleases(
    suppliedReleases,
    activeCatalog,
    activeCatalogByTag,
  );
  validateSuppliedStableCatalog(
    releases,
    activeTagWindow.stableTagsNewestFirst,
    options.stableTagsNewestFirst,
  );
  const allFetchedTags = activeTagWindow.allFetchedTags;
  const oldestScoredStableTag = releases
    .filter((release) => release.prerelease === 0)
    .at(-1)?.tag ?? null;
  const oldestScoredStableIndex = oldestScoredStableTag == null
    ? -1
    : activeTagWindow.stableTagsNewestFirst.indexOf(oldestScoredStableTag);
  const activeOldestPredecessorTag = oldestScoredStableIndex >= 0
    ? activeTagWindow.stableTagsNewestFirst[oldestScoredStableIndex + 1] ?? null
    : null;
  if (
    options.oldestScoredStablePredecessorTag != null &&
    options.oldestScoredStablePredecessorTag !== activeOldestPredecessorTag
  ) {
    throw new Error(
      `Refusing supplied score catalog: oldest scored stable ${oldestScoredStableTag ?? 'none'} ` +
      `has active predecessor ${activeOldestPredecessorTag ?? 'none'}, not ` +
      `${options.oldestScoredStablePredecessorTag}`,
    );
  }
  const predecessorContext = deriveReleasePredecessors(
    releases,
    activeTagWindow.stableTagsNewestFirst,
    activeOldestPredecessorTag,
  );
  const artifactVerificationByTag = new Map(releases.map((release) => [
    release.tag,
    getReleaseArtifactVerificationForScoring({
      repository: `${config.github.owner}/${config.github.repo}`,
      tag: release.tag,
      releaseNodeId: release.node_id!,
      catalogTagCommitOid: release.catalog_tag_commit_oid!,
      publishedAt: new Date(release.published_at!).toISOString(),
    }, {
      runId: artifactObservationRunId,
    }),
  ] as const));
  if (
    artifactObservationRunId &&
    [...artifactVerificationByTag.values()].some((selection) => selection == null)
  ) {
    const missingTags = [...artifactVerificationByTag.entries()]
      .filter(([, selection]) => selection == null)
      .map(([tag]) => tag);
    throw new Error(
      `Artifact observation run ${artifactObservationRunId} is incomplete for ` +
      `${missingTags.join(', ')}`,
    );
  }
  const stableTagsNewestFirst = predecessorContext.stableTagsNewestFirst;
  const advisories = listAdvisories();
  assertAdvisoryPackageIdentity(advisories);
  assertAdvisoryRangesParseable(advisories);
  const cveFor = (tag: string): AdvisoryCveSignal =>
    advisoryCveSignal(tag, advisories, stableTagsNewestFirst);
  const authoritySubjectsByIdentity =
    new Map<string, ScoreAuthorityResolutionSubject>();
  const recordAuthoritySubject = (
    subject: ScoreAuthorityResolutionSubject,
  ): void => {
    const key = `${subject.subjectKind}\0${subject.subjectIdentity}`;
    const existing = authoritySubjectsByIdentity.get(key);
    if (
      existing &&
      canonicalOperationJson(existing) !== canonicalOperationJson(subject)
    ) {
      throw new Error(
        `Conflicting score authority resolution subject ${subject.subjectKind}:` +
          subject.subjectIdentity,
      );
    }
    authoritySubjectsByIdentity.set(key, subject);
  };

  const scoredWithoutExplanation = releases.map((release) => {
    const now = options.nowForRelease?.(release) ?? Date.now();
    return scoreRelease({
      release,
      isLatest: isCanonicalLatestStableRelease(
        release,
        canonicalLatestStable,
      ),
      allFetchedTags,
      stableTagsNewestFirst,
      predecessorTag: predecessorContext.predecessorByReleaseTag[release.tag] ?? null,
      oldestScoredStableTag: predecessorContext.oldestScoredStableTag,
      oldestScoredStablePredecessorTag: predecessorContext.oldestScoredStablePredecessorTag,
      cveFor,
      now,
      recordAuthoritySubject,
      artifactVerification:
        artifactVerificationByTag.get(release.tag) ?? null,
    });
  });
  const recommendation = selectRecommendation(
    scoredWithoutExplanation.map((s) => ({ tag: s.rel.tag, status: s.conf.status, score: s.conf.score })),
  );
  const recommendationDecisions = recommendationDecisionsForRun(scoredWithoutExplanation, recommendation);
  const recommendedTag = recommendation.selectedTag;
  const scored = scoredWithoutExplanation.map((result) => {
    const recommendationDecision = recommendationDecisions.get(result.rel.tag)!;
    const explanation = buildScoreExplanation(result, recommendationDecision);
    return {
      ...result,
      recommendationDecision,
      scoreLedger: explanation.scoreLedger,
      explanation,
    };
  });
  const sourceIdentity = scoreSourceIdentity(sourceIdentityOptions);
  assertScoreSourceIdentityEqual(sourceIdentityBefore, sourceIdentity, 'source rows changed while scores were being built');
  return {
    scored,
    recommendedTag,
    sourceIdentity,
    authoritySubjects: [...authoritySubjectsByIdentity.values()].sort(
      (left, right) =>
        left.subjectKind.localeCompare(right.subjectKind) ||
        left.subjectIdentity.localeCompare(right.subjectIdentity),
    ),
    stableTagsNewestFirst,
    oldestScoredStableTag: predecessorContext.oldestScoredStableTag,
    oldestScoredStablePredecessorTag: predecessorContext.oldestScoredStablePredecessorTag,
    predecessorByReleaseTag: predecessorContext.predecessorByReleaseTag,
    predecessorBoundaryProblems: predecessorContext.problems,
    artifactObservationRunId,
  };
}

function bindSuppliedScoreReleases(
  suppliedReleases: ReleaseRow[],
  activeCatalog: ReleaseRow[],
  activeCatalogByTag: ReadonlyMap<string, ReleaseRow> =
    new Map(activeCatalog.map((release) => [release.tag, release] as const)),
): ReleaseRow[] {
  const suppliedTags = new Set<string>();
  for (const [index, supplied] of suppliedReleases.entries()) {
    if (!supplied || typeof supplied !== 'object' || Array.isArray(supplied)) {
      throw new Error(
        `Refusing supplied score release at index ${index}: expected a release row`,
      );
    }
    const tag = typeof supplied.tag === 'string' ? supplied.tag.trim() : '';
    if (!tag) {
      throw new Error(
        `Refusing supplied score release at index ${index}: release tag is missing`,
      );
    }
    if (suppliedTags.has(tag)) {
      throw new Error(`Refusing supplied score releases: duplicate tag ${tag}`);
    }
    suppliedTags.add(tag);
    const canonical = activeCatalogByTag.get(tag);
    if (!canonical) {
      throw new Error(
        `Refusing supplied score release ${tag}: release is not in the active catalog`,
      );
    }
    if (canonical.prerelease !== 0) {
      throw new Error(
        `Refusing supplied score release ${tag}: release is not an active stable release`,
      );
    }
    const mismatchedFields = RELEASE_SCORE_BINDING_FIELDS.filter((field) =>
      !Object.is(supplied[field], canonical[field]));
    if (mismatchedFields.length > 0) {
      throw new Error(
        `Refusing supplied score release ${tag}: canonical release binding mismatch in ` +
        mismatchedFields.join(', '),
      );
    }
  }
  return activeCatalog.filter((release) => suppliedTags.has(release.tag));
}

function canonicalLatestStableRelease(
  activeCatalog: ReleaseRow[],
): ReleaseRow | null {
  return activeCatalog.find((release) => release.prerelease === 0) ?? null;
}

function isCanonicalLatestStableRelease(
  release: ReleaseRow,
  latestStable: ReleaseRow | null,
): boolean {
  return latestStable != null &&
    CANONICAL_RELEASE_IDENTITY_FIELDS.every((field) =>
      Object.is(release[field], latestStable[field]));
}

function validateSuppliedStableCatalog(
  releases: ReleaseRow[],
  activeStableTagsNewestFirst: string[],
  suppliedStableTagsNewestFirst: string[] | undefined,
): void {
  if (!Array.isArray(suppliedStableTagsNewestFirst)) return;
  for (const release of releases.filter((candidate) => candidate.prerelease === 0)) {
    const activeIndex = activeStableTagsNewestFirst.indexOf(release.tag);
    const suppliedIndex = suppliedStableTagsNewestFirst.indexOf(release.tag);
    const activePredecessor = activeIndex >= 0
      ? activeStableTagsNewestFirst[activeIndex + 1] ?? null
      : null;
    const suppliedPredecessor = suppliedIndex >= 0
      ? suppliedStableTagsNewestFirst[suppliedIndex + 1] ?? null
      : null;
    if (suppliedIndex < 0 || suppliedPredecessor !== activePredecessor) {
      throw new Error(
        `Refusing supplied score catalog: ${release.tag} active stable predecessor is ` +
        `${activePredecessor ?? 'none'}, but supplied catalog names ${suppliedPredecessor ?? 'none'}`,
      );
    }
  }
}

function deriveReleasePredecessors(
  releases: ReleaseRow[],
  suppliedStableTagsNewestFirst: string[] | undefined,
  suppliedOldestPredecessorTag: string | null | undefined,
): {
  stableTagsNewestFirst: string[];
  oldestScoredStableTag: string | null;
  oldestScoredStablePredecessorTag: string | null;
  predecessorByReleaseTag: Record<string, string | null>;
  problems: string[];
} {
  const stableTagsNewestFirst = Array.isArray(suppliedStableTagsNewestFirst)
    ? suppliedStableTagsNewestFirst.slice()
    : [];
  const problems: string[] = [];
  if (!Array.isArray(suppliedStableTagsNewestFirst)) {
    problems.push('stableTagsNewestFirst must be supplied explicitly');
  }
  if (
    stableTagsNewestFirst.some((tag) => typeof tag !== 'string' || !tag.trim()) ||
    new Set(stableTagsNewestFirst).size !== stableTagsNewestFirst.length
  ) {
    problems.push('stableTagsNewestFirst must contain unique non-empty tags');
  }
  const scoredStableTags = releases
    .filter((release) => release.prerelease === 0)
    .map((release) => release.tag);
  const oldestScoredStableTag = scoredStableTags.at(-1) ?? null;
  const predecessorByReleaseTag: Record<string, string | null> = {};
  for (const tag of scoredStableTags) {
    const index = stableTagsNewestFirst.indexOf(tag);
    const predecessorTag = index >= 0 ? stableTagsNewestFirst[index + 1] ?? null : null;
    predecessorByReleaseTag[tag] = predecessorTag;
    if (index < 0) problems.push(`scored stable ${tag} is absent from stableTagsNewestFirst`);
    else if (!predecessorTag) problems.push(`scored stable ${tag} has no immediate predecessor in stableTagsNewestFirst`);
  }
  const derivedOldestPredecessorTag = oldestScoredStableTag
    ? predecessorByReleaseTag[oldestScoredStableTag] ?? null
    : null;
  const oldestScoredStablePredecessorTag = suppliedOldestPredecessorTag ?? null;
  if (oldestScoredStableTag && !oldestScoredStablePredecessorTag) {
    problems.push(`oldest scored stable ${oldestScoredStableTag} is missing its explicit predecessor boundary`);
  } else if (
    oldestScoredStableTag &&
    oldestScoredStablePredecessorTag !== derivedOldestPredecessorTag
  ) {
    problems.push(
      `oldest scored stable ${oldestScoredStableTag} predecessor boundary ` +
      `${oldestScoredStablePredecessorTag} does not match supplied stableTagsNewestFirst predecessor ` +
      `${derivedOldestPredecessorTag ?? 'none'}`,
    );
  }
  return {
    stableTagsNewestFirst,
    oldestScoredStableTag,
    oldestScoredStablePredecessorTag,
    predecessorByReleaseTag,
    problems,
  };
}

function recommendationDecisionsForRun(
  scored: Array<Pick<ReleaseScoreResult, 'rel' | 'conf'>>,
  selection: ReturnType<typeof selectRecommendation>,
): Map<string, RecommendationDecision> {
  const recencyRankByTag = new Map(
    scored
      .slice()
      .sort((left, right) => compareRecommendationRecency(
        { tag: left.rel.tag, publishedAt: left.rel.published_at },
        { tag: right.rel.tag, publishedAt: right.rel.published_at },
      ))
      .map((result, index) => [result.rel.tag, index + 1]),
  );
  const scoreRanked = scored
    .filter((result) => result.conf.status === 'eligible' && result.conf.score != null)
    .slice()
    .sort((left, right) =>
      Number(right.conf.score) - Number(left.conf.score) ||
      compareRecommendationRecency(
        { tag: left.rel.tag, publishedAt: left.rel.published_at },
        { tag: right.rel.tag, publishedAt: right.rel.published_at },
      )
    );
  return new Map(scored.map((result) => {
    const score = result.conf.score;
    const qualifies = result.conf.status === 'eligible' && score != null && score >= REC_THRESHOLD;
    const selected = result.rel.tag === selection.selectedTag;
    const scoreRankIndex = scoreRanked.findIndex((candidate) => candidate.rel.tag === result.rel.tag);
    const decision: RecommendationDecision = {
      schemaVersion: 1,
      policyCode: 'highest_confidence_with_recency_tolerance',
      threshold: REC_THRESHOLD,
      recencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
      selectedTag: selection.selectedTag,
      selectedScore: selection.selectedScore,
      highestScoringTag: selection.highestScoringTag,
      highestScore: selection.highestScore,
      releaseTag: result.rel.tag,
      releaseScore: score,
      qualifies,
      selected,
      recencyRank: recencyRankByTag.get(result.rel.tag)!,
      scoreRank: scoreRankIndex >= 0 ? scoreRankIndex + 1 : null,
      scoreDeltaToHighest: score != null && selection.highestScore != null
        ? roundMetric(selection.highestScore - score)
        : null,
      decisionCode: 'install_gate_active',
      summary: '',
    };
    decision.decisionCode =
      result.conf.status !== 'eligible'
        ? 'install_gate_active'
        : !qualifies
          ? 'below_recommendation_threshold'
          : selected && result.rel.tag === selection.highestScoringTag
            ? 'highest_confidence'
            : selected
              ? 'newest_within_confidence_tolerance'
              : selection.selectedScore != null && score != null && score >= selection.selectedScore
                ? 'newer_release_within_tolerance_selected'
                : 'higher_confidence_release_selected';
    decision.summary = recommendationDecisionSummary(decision);
    return [result.rel.tag, decision];
  }));
}

export function recommendationDecisionSummary(decision: RecommendationDecision): string {
  return canonicalRecommendationDecisionSummary(decision);
}

export function humanRecommendationDecisionSummary(decision: RecommendationDecision): string {
  const selectedTag = decision.selectedTag ?? 'the recommended release';
  if (decision.decisionCode === 'highest_confidence') {
    return 'Recommended at the highest audited score; the newest release wins when scores are equal.';
  }
  if (decision.decisionCode === 'newest_within_confidence_tolerance') {
    return `Recommended as the newest qualifying release within ${formatRecommendationNumber(decision.recencyTolerance)} points of the highest audited score.`;
  }
  if (decision.decisionCode === 'higher_confidence_release_selected') {
    return `Not selected: ${selectedTag} has higher audited install confidence.`;
  }
  if (decision.decisionCode === 'newer_release_within_tolerance_selected') {
    return `Not selected: ${selectedTag} is newer and remains within ${formatRecommendationNumber(decision.recencyTolerance)} points of this score.`;
  }
  if (decision.decisionCode === 'below_recommendation_threshold') {
    const score = decision.releaseScore == null ? 'n/a' : formatRecommendationNumber(decision.releaseScore);
    return `Not selected: score ${score} is below the ${formatRecommendationNumber(decision.threshold)} recommendation threshold.`;
  }
  return 'Not selected: an install gate is active.';
}

function formatRecommendationNumber(value: number): string {
  return value.toFixed(1);
}

function assertAdvisoryRangesParseable(advisories: Array<{ ghsa_id?: string | null; vulnerable_version_range?: string | null }>): void {
  const malformed = advisories
    .filter((advisory) => !isRangeParseable(advisory.vulnerable_version_range))
    .map((advisory) => `${advisory.ghsa_id ?? 'unknown'}:${advisory.vulnerable_version_range ?? 'null'}`);
  if (malformed.length > 0) {
    throw new Error(`Refusing to score with malformed advisory vulnerable_version_range row(s): ${malformed.slice(0, 10).join(', ')}${malformed.length > 10 ? `, ... ${malformed.length - 10} more` : ''}`);
  }
}

function assertAdvisoryPackageIdentity(advisories: Array<{
  advisory_key?: string | null;
  package_ecosystem?: string | null;
  package_name?: string | null;
}>): void {
  const expectedPackage = config.github.repo.toLowerCase();
  const invalid = advisories.filter((advisory) =>
    String(advisory.package_ecosystem ?? '').toLowerCase() !== 'npm' ||
    String(advisory.package_name ?? '').toLowerCase() !== expectedPackage);
  if (invalid.length > 0) {
    const examples = invalid.slice(0, 10).map((advisory) =>
      `${advisory.advisory_key ?? 'unknown'}:${advisory.package_ecosystem ?? 'null'}/${advisory.package_name ?? 'null'}`);
    throw new Error(
      `Refusing to score advisory row(s) outside npm/${config.github.repo}: ${examples.join(', ')}` +
      (invalid.length > 10 ? `, ... ${invalid.length - 10} more` : ''),
    );
  }
}

interface AdvisoryCveEvidenceIdentity {
  advisoryKey: string;
  ghsaId: string;
  packageEcosystem: string;
  packageName: string;
  vulnerableVersionRange: string | null;
  patchedVersions: string | null;
  severity: string;
  distance: number;
  load: number;
  electedForLoad: boolean;
}

interface AdvisoryCveSignal {
  affected: boolean;
  load: number;
  advisories: AdvisoryCveEvidenceIdentity[];
}

function advisoryCveSignal(
  tag: string,
  advisories: Array<{
    advisory_key?: string | null;
    ghsa_id: string;
    severity: string;
    package_ecosystem?: string | null;
    package_name?: string | null;
    vulnerable_version_range?: string | null;
    patched_versions?: string | null;
  }>,
  stableTagsNewestFirst: string[],
): AdvisoryCveSignal {
  const matching = advisories.filter((advisory) =>
    matchesRange(tag, advisory.vulnerable_version_range));
  const affected = matching.some((advisory) =>
    (SEV_RANK[advisory.severity] ?? 0) >= 2);
  const strongestByAdvisoryPackage = new Map<
    string,
    AdvisoryCveEvidenceIdentity
  >();
  const evidence = matching.map((advisory): AdvisoryCveEvidenceIdentity => {
    const distance = stableDistance(tag, advisory.patched_versions, stableTagsNewestFirst);
    const load = cveDecayLoad([{ severity: advisory.severity, distance }]);
    return {
      advisoryKey: advisory.advisory_key ??
        [
          advisory.ghsa_id,
          advisory.package_ecosystem ?? '',
          advisory.package_name ?? '',
          advisory.vulnerable_version_range ?? '',
        ].join(':'),
      ghsaId: advisory.ghsa_id,
      packageEcosystem: String(advisory.package_ecosystem ?? '').toLowerCase(),
      packageName: String(advisory.package_name ?? '').toLowerCase(),
      vulnerableVersionRange: advisory.vulnerable_version_range ?? null,
      patchedVersions: advisory.patched_versions ?? null,
      severity: advisory.severity,
      distance,
      load,
      electedForLoad: false,
    };
  });
  for (const advisory of evidence) {
    const key = [
      advisory.ghsaId,
      advisory.packageEcosystem,
      advisory.packageName,
    ].join('\0');
    const current = strongestByAdvisoryPackage.get(key);
    if (
      !current ||
      advisory.load > current.load ||
      advisory.load === current.load && advisory.advisoryKey.localeCompare(current.advisoryKey) < 0
    ) {
      strongestByAdvisoryPackage.set(key, advisory);
    }
  }
  const electedKeys = new Set(
    [...strongestByAdvisoryPackage.values()].map((advisory) => advisory.advisoryKey),
  );
  const advisoryEvidence = evidence
    .map((advisory) => ({
      ...advisory,
      electedForLoad: electedKeys.has(advisory.advisoryKey),
    }))
    .sort((left, right) => left.advisoryKey.localeCompare(right.advisoryKey));
  return {
    affected,
    load: cveDecayLoad(
      [...strongestByAdvisoryPackage.values()]
        .map(({ severity, distance }) => ({ severity, distance })),
    ),
    advisories: advisoryEvidence,
  };
}

export function scoreTagWindow(releases: Array<{
  tag: string;
  prerelease?: number | boolean | null;
  published_at?: string | null;
}>): {
  allFetchedTags: string[];
  stableTagsNewestFirst: string[];
} {
  assertFiniteReleasePublicationTimestamps(releases, 'release tag window');
  const ordered = sortReleasesNewestFirst(releases);
  return {
    allFetchedTags: ordered.map((release) => release.tag),
    stableTagsNewestFirst: ordered
      .filter((release) => release.prerelease !== true && release.prerelease !== 1)
      .map((release) => release.tag),
  };
}

function assertFiniteReleasePublicationTimestamps(
  releases: Array<{ tag: string; published_at?: string | null }>,
  context: string,
): void {
  const invalid = releases
    .filter((release) =>
      !release.published_at || !Number.isFinite(Date.parse(release.published_at)))
    .map((release) => release.tag);
  if (invalid.length > 0) {
    throw new Error(
      `Refusing ${context} with invalid published_at timestamp(s): ${invalid.join(', ')}`,
    );
  }
}

function sortReleasesNewestFirst<T extends { tag: string; published_at?: string | null }>(releases: T[]): T[] {
  return releases.slice().sort(compareReleaseRecency);
}

function sortReleaseTagsNewestFirst<T extends { tag: string; published_at?: string | null }>(
  tags: string[],
  releases: T[],
): string[] {
  const releaseByTag = new Map(releases.map((release) => [release.tag, release]));
  return [...new Set(tags)].sort((leftTag, rightTag) => {
    const left = releaseByTag.get(leftTag);
    const right = releaseByTag.get(rightTag);
    if (left && right) return compareReleaseRecency(left, right);
    return compareVersions(rightTag, leftTag) || leftTag.localeCompare(rightTag);
  });
}

function compareReleaseRecency(
  left: { tag: string; published_at?: string | null },
  right: { tag: string; published_at?: string | null },
): number {
  const leftPublished = left.published_at ? Date.parse(left.published_at) : NaN;
  const rightPublished = right.published_at ? Date.parse(right.published_at) : NaN;
  const leftHasDate = Number.isFinite(leftPublished);
  const rightHasDate = Number.isFinite(rightPublished);
  if (leftHasDate && rightHasDate && leftPublished !== rightPublished) return rightPublished - leftPublished;
  if (leftHasDate !== rightHasDate) return leftHasDate ? -1 : 1;
  return compareVersions(right.tag, left.tag) || left.tag.localeCompare(right.tag);
}

function releaseScoreAuditInputForResult(
  run: ReleaseScoreRun,
  result: ReleaseScoreResult,
  authorityRunId: string | null = null,
): ReleaseScoreAuditInput {
  const ledgerProblems = scoreLedgerPersistenceProblems(result);
  if (ledgerProblems.length > 0) {
    throw new Error(
      `Refusing to serialize ${result.rel.tag} score audit with an invalid ScoreLedgerV2: ` +
      ledgerProblems.join('; '),
    );
  }
  const recommended = result.rel.tag === run.recommendedTag ? 1 : 0;
  return {
    release_tag: result.rel.tag,
    scored_at: result.scoredAt,
    score_model_version: SCORE_MODEL_VERSION,
    prompt_version: PROMPT_VERSION,
    final_score: result.conf.score,
    status: result.conf.status,
    band: result.conf.band,
    recommended,
    input_json: JSON.stringify(result.input),
    components_json: JSON.stringify({
      schemaVersion: SCORE_COMPONENTS_SCHEMA_VERSION,
      components: result.conf.components,
      evidenceCoverage: result.conf.evidenceCoverage,
      hotfix: result.conf.hotfix,
      reason: result.conf.reason,
      explanation: result.explanation,
      recommendationDecision: result.recommendationDecision,
    }),
    issue_evidence_json: JSON.stringify(result.debtEvidence),
    gate_evidence_json: JSON.stringify(result.gateEvidence),
    source_identity_json: JSON.stringify(run.sourceIdentity),
    authority_run_id: authorityRunId,
  };
}

function forecastSemanticAudit(value: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!value) return null;
  return {
    release_tag: value.release_tag,
    score_model_version: value.score_model_version,
    prompt_version: value.prompt_version,
    final_score: value.final_score,
    status: value.status,
    band: value.band,
    recommended: value.recommended,
    input_json: value.input_json,
    components_json: value.components_json ?? null,
    issue_evidence_json: value.issue_evidence_json,
    gate_evidence_json: value.gate_evidence_json,
    source_identity_json: value.source_identity_json,
  };
}

function parseForecastRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function parseForecastJsonObject(json: string): Record<string, unknown> | null {
  try {
    return parseForecastRecord(JSON.parse(json));
  } catch {
    return null;
  }
}

function parseForecastJsonArray(json: string): Record<string, unknown>[] {
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed)
      ? parsed.map(parseForecastRecord).filter(
          (value): value is Record<string, unknown> => value != null,
        )
      : [];
  } catch {
    return [];
  }
}

function forecastCatalogSemanticIdentity(
  attestation: ReleaseCatalogAttestation,
): Record<string, unknown> {
  return {
    schemaVersion: attestation.schemaVersion,
    initialRemoteCatalog: attestation.initialRemoteCatalog,
    finalRemoteCatalog: attestation.finalRemoteCatalog,
    projectedActiveCatalog: attestation.projectedActiveCatalog,
    localActiveCatalog: attestation.localActiveCatalog,
    latestStable: attestation.latestStable,
  };
}

function expectedForecastSemanticCandidates(run: ReleaseScoreRun): Array<Record<string, unknown>> {
  return run.scored
    .map((result) => {
      const audit = releaseScoreAuditInputForResult(run, result);
      return {
        releaseTag: result.rel.tag,
        releasePublishedAt: result.rel.published_at,
        scoreSnapshot: {
          finalScore: audit.final_score,
          status: audit.status,
          band: audit.band,
          recommended: audit.recommended === 1,
        },
        recommendationDecision:
          result.recommendationDecision ?? result.explanation.recommendationDecision ?? null,
        auditSnapshot: forecastSemanticAudit(audit as unknown as Record<string, unknown>),
      };
    })
    .sort((left, right) =>
      String(left.releaseTag).localeCompare(String(right.releaseTag)));
}

function existingForecastSemanticCandidates(
  row: ReleaseValidationForecastRow,
): Array<Record<string, unknown>> {
  return parseForecastJsonArray(row.candidate_scores_json)
    .map((candidate) => {
      const scoreSnapshot = parseForecastRecord(candidate.scoreSnapshot ?? candidate.score_snapshot);
      const auditSnapshot = parseForecastRecord(candidate.auditSnapshot ?? candidate.audit_snapshot);
      return {
        releaseTag: candidate.releaseTag ?? candidate.release_tag ?? candidate.tag ?? null,
        releasePublishedAt:
          candidate.releasePublishedAt ?? candidate.release_published_at ?? null,
        scoreSnapshot: scoreSnapshot ? {
          finalScore:
            scoreSnapshot.finalScore ?? scoreSnapshot.final_score ?? candidate.finalScore ??
            candidate.final_score ?? candidate.score ?? null,
          status: scoreSnapshot.status ?? null,
          band: scoreSnapshot.band ?? null,
          recommended: scoreSnapshot.recommended ?? null,
        } : null,
        recommendationDecision:
          candidate.recommendationDecision ?? candidate.recommendation_decision ?? null,
        auditSnapshot: forecastSemanticAudit(auditSnapshot),
      };
    })
    .sort((left, right) =>
      String(left.releaseTag).localeCompare(String(right.releaseTag)));
}

function existingForecastSemanticProblems(args: {
  row: ReleaseValidationForecastRow;
  run: ReleaseScoreRun;
  attestation: ReleaseCatalogAttestation;
  codeRevision: string;
  latestReleaseTag: string;
  latestReleasePublishedAt: string;
  selectedTag: string | null;
  policyCode: string;
}): string[] {
  const problems: string[] = [];
  const decision = parseForecastJsonObject(args.row.decision_json);
  if (Number(decision?.schemaVersion) !== 4) {
    problems.push('existing forecast does not use decision schemaVersion 4');
    return problems;
  }
  const historyRows = listReleaseScoreAuditHistoryForRun(args.row.audit_history_run_id);
  const historySeal = getReleaseScoreAuditHistoryRunSeal(args.row.audit_history_run_id);
  const authorityRuns = [...new Set(
    historyRows
      .map((row) => row.authority_run_id)
      .filter((runId): runId is string => typeof runId === 'string' && !!runId),
  )]
    .map((runId) => getScoreAuthorityResolutionRun(runId))
    .filter((run): run is ScoreAuthorityResolutionRun => run != null);
  const historyV2Seal = getReleaseScoreAuditHistoryV2Seal(
    args.row.audit_history_run_id,
  );
  const provenanceProblems = validateReleaseValidationForecastProvenance(
    [args.row],
    historyRows as any,
    historySeal ? [historySeal] : [],
    authorityRuns,
    historyV2Seal ? [historyV2Seal] : [],
  );
  problems.push(...provenanceProblems);
  if (
    releaseValidationForecastContentHash(args.row) !== args.row.content_hash ||
    releaseValidationDecisionId(args.row, args.row.content_hash) !== args.row.decision_id
  ) {
    problems.push('existing forecast ledger hash or decision ID is invalid');
  }
  if (
    args.row.latest_release_tag !== args.latestReleaseTag ||
    args.row.latest_release_published_at !== args.latestReleasePublishedAt ||
    args.row.selected_tag !== args.selectedTag ||
    args.row.policy_code !== args.policyCode ||
    args.row.score_model_version !== SCORE_MODEL_VERSION ||
    args.row.prompt_version !== PROMPT_VERSION ||
    args.row.code_revision !== args.codeRevision ||
    canonicalOperationJson(parseForecastJsonObject(args.row.source_identity_json)) !==
      canonicalOperationJson(args.run.sourceIdentity)
  ) {
    problems.push('existing forecast slot metadata differs from the pending score run');
  }
  if (
    JSON.stringify(existingForecastSemanticCandidates(args.row)) !==
    JSON.stringify(expectedForecastSemanticCandidates(args.run))
  ) {
    problems.push('existing forecast candidate semantics differ from the pending score run');
  }
  const existingAuthorityRun = authorityRuns.length === 1
    ? authorityRuns[0]
    : null;
  if (
    !existingAuthorityRun ||
    canonicalOperationJson(
      normalizedStoredAuthoritySubjects(existingAuthorityRun),
    ) !== canonicalOperationJson(
      normalizedPendingAuthoritySubjects(args.run),
    )
  ) {
    problems.push(
      'existing forecast authority semantics differ from the pending score run',
    );
  }
  const existingCatalog = parseForecastRecord(decision?.catalogAttestation);
  if (
    !existingCatalog ||
    releaseCatalogAttestationProblems(existingCatalog).length > 0 ||
    JSON.stringify(forecastCatalogSemanticIdentity(
      existingCatalog as unknown as ReleaseCatalogAttestation,
    )) !== JSON.stringify(forecastCatalogSemanticIdentity(args.attestation))
  ) {
    problems.push('existing forecast catalog semantics differ from the pending score run');
  }
  return problems;
}

function normalizedStoredAuthoritySubjects(
  run: ScoreAuthorityResolutionRun,
): Array<Record<string, unknown>> {
  return run.rows
    .map((row) => ({
      releaseTag: row.releaseTag,
      issueNumber: row.issueNumber,
      subjectKind: row.subjectKind,
      subjectIdentity: row.subjectIdentity,
      candidateId: row.candidateId,
      resolution: parseForecastJsonObject(row.resolutionJson),
    }))
    .sort((left, right) =>
      String(left.subjectKind).localeCompare(String(right.subjectKind)) ||
      String(left.subjectIdentity).localeCompare(String(right.subjectIdentity)));
}

function normalizedPendingAuthoritySubjects(
  run: ReleaseScoreRun,
): Array<Record<string, unknown>> {
  return validatedAuthoritySubjectsForPersistence(run)
    .map((subject) => ({
      releaseTag: subject.releaseTag,
      issueNumber: subject.issueNumber,
      subjectKind: subject.subjectKind,
      subjectIdentity: subject.subjectIdentity,
      candidateId: subject.candidateId,
      resolution: subject.resolution,
    }))
    .sort((left, right) =>
      String(left.subjectKind).localeCompare(String(right.subjectKind)) ||
      String(left.subjectIdentity).localeCompare(String(right.subjectIdentity)));
}

function preflightReleaseValidationForecasts(args: {
  run: ReleaseScoreRun;
  attestation: ReleaseCatalogAttestation;
  codeRevision: string;
  preflightAt: string;
}): ReleaseValidationForecastPublicationPlan {
  assertCatalogAttestationMatchesCurrent(args.attestation);
  const latestStable = getRelease(args.attestation.latestStable.tag);
  if (
    !latestStable?.published_at ||
    latestStable.node_id !== args.attestation.latestStable.nodeId ||
    latestStable.catalog_tag_commit_oid !== args.attestation.latestStable.tagCommitOid ||
    latestStable.published_at !== args.attestation.latestStable.publishedAt
  ) {
    throw new Error('Validation forecast preflight latest stable does not match catalog attestation');
  }
  const latestResult = args.run.scored.find((result) =>
    result.rel.tag === args.attestation.latestStable.tag);
  const decision = latestResult?.recommendationDecision ??
    latestResult?.explanation.recommendationDecision;
  if (
    !latestResult ||
    !decision ||
    decision.releaseTag !== latestStable.tag ||
    decision.selectedTag !== args.run.recommendedTag
  ) {
    throw new Error('Validation forecast preflight score run recommendation is inconsistent');
  }
  const preflightAtMs = Date.parse(args.preflightAt);
  if (!Number.isFinite(preflightAtMs)) {
    throw new Error('Validation forecast preflight time is invalid');
  }
  const slots = Object.entries(RELEASE_VALIDATION_OPPORTUNITIES)
    .filter(([, opportunity]) =>
      preflightAtMs <
      Date.parse(latestStable.published_at!) + opportunity.maxAgeHours * 3_600_000)
    .map(([opportunityCode]) => {
      const existing = getReleaseValidationForecastForSlot({
        opportunity_code: opportunityCode,
        latest_release_tag: latestStable.tag,
        score_model_version: SCORE_MODEL_VERSION,
        prompt_version: PROMPT_VERSION,
        code_revision: args.codeRevision,
      });
      if (existing) {
        const semanticProblems = existingForecastSemanticProblems({
          row: existing,
          run: args.run,
          attestation: args.attestation,
          codeRevision: args.codeRevision,
          latestReleaseTag: latestStable.tag,
          latestReleasePublishedAt: latestStable.published_at!,
          selectedTag: decision.selectedTag,
          policyCode: decision.policyCode,
        });
        if (semanticProblems.length > 0) {
          throw new Error(
            `Validation forecast preflight rejected occupied slot ` +
            `${latestStable.tag}/${opportunityCode}: ${semanticProblems.join('; ')}`,
          );
        }
      }
      return {
        opportunityCode,
        existingDecisionId: existing?.decision_id ?? null,
        existingContentHash: existing?.content_hash ?? null,
      };
    });
  return {
    schemaVersion: 1,
    preflightAt: args.preflightAt,
    latestReleaseTag: latestStable.tag,
    latestReleasePublishedAt: latestStable.published_at,
    selectedTag: decision.selectedTag,
    scoreModelVersion: SCORE_MODEL_VERSION,
    promptVersion: PROMPT_VERSION,
    policyCode: decision.policyCode,
    codeRevision: args.codeRevision,
    slots,
  };
}

function validatedAuthoritySubjectsForPersistence(
  run: ReleaseScoreRun,
): ScoreAuthorityResolutionSubject[] {
  if (!Array.isArray(run.authoritySubjects)) {
    throw new Error('Score persistence requires an authority subject ledger');
  }
  return run.authoritySubjects.map((subject) => {
    const subjectKind = (subject as { subjectKind?: unknown }).subjectKind;
    if (subjectKind === 'label_event') {
      const evidence = labelAuthorityEvidenceForEvent(subject.subjectIdentity);
      const expectedResolution = buildScoreAuthorityResolution(evidence);
      if (
        subject.releaseTag !== null ||
        subject.issueNumber !== evidence.event.issueNumber ||
        subject.candidateId !== null ||
        canonicalOperationJson(subject.resolution) !==
          canonicalOperationJson(expectedResolution)
      ) {
        throw new Error(
          `Score authority subject label_event:${subject.subjectIdentity} ` +
            'does not match immutable authority evidence',
        );
      }
      return subject;
    }
    if (subjectKind === 'comment') {
      const evidence = scoreCommentAuthorityEvidenceForStoredComment(
        subject.issueNumber,
        subject.subjectIdentity,
      );
      const expectedResolution = buildScoreCommentAuthorityResolution(evidence);
      if (
        subject.releaseTag !== null ||
        subject.candidateId !== null ||
        canonicalScoreAuthoritySubjectResolutionJson(subject.resolution) !==
          canonicalScoreAuthoritySubjectResolutionJson(expectedResolution)
      ) {
        throw new Error(
          `Score authority subject comment:${subject.subjectIdentity} ` +
            'does not match immutable authority evidence',
        );
      }
      return subject;
    }
    if (subjectKind === 'closure_claim') {
      if (
        subject.candidateId == null ||
        subject.subjectIdentity !== subject.candidateId
      ) {
        throw new Error(
          `Score authority subject closure_claim:${subject.subjectIdentity} ` +
            'does not carry one exact candidate identity',
        );
      }
      const evidence = closureClaimAuthorityEvidenceForCandidate(
        subject.candidateId,
      );
      const expectedResolution =
        buildScoreClosureClaimAuthorityResolution(evidence);
      if (
        subject.releaseTag !== null ||
        subject.issueNumber !== evidence.candidate.issue.number ||
        expectedResolution.candidateId !== subject.candidateId ||
        canonicalScoreAuthoritySubjectResolutionJson(subject.resolution) !==
          canonicalScoreAuthoritySubjectResolutionJson(expectedResolution)
      ) {
        throw new Error(
          `Score authority subject closure_claim:${subject.subjectIdentity} ` +
            'does not match immutable authority evidence',
        );
      }
      return subject;
    }
    throw new Error(
      `Score persistence does not support authority subject kind ` +
        String(subjectKind),
    );
  });
}

function scoreCommentAuthorityEvidenceForStoredComment(
  issueNumber: number,
  commentNodeId: string,
): ScoreCommentAuthorityEvidence {
  const issue = getIssue(issueNumber);
  if (
    !issue ||
    !issue.node_id ||
    !issue.author_node_id ||
    !issue.author_type
  ) {
    throw new Error(
      `Score comment authority subject ${commentNodeId} is missing canonical issue identity`,
    );
  }
  const comment = completeIssueComments(issueNumber).find((candidate) => {
    try {
      return canonicalCommentSourceIdentity(candidate)?.nodeId === commentNodeId;
    } catch {
      return false;
    }
  });
  if (!comment) {
    throw new Error(
      `Score comment authority subject ${commentNodeId} is missing from issue #${issueNumber}`,
    );
  }
  const reason = semanticHumanConfirmationReasons({
    issueNumber,
    issueNodeId: issue.node_id,
    issueAuthor: {
      nodeId: issue.author_node_id,
      login: issue.author,
      actorType: issue.author_type,
    },
    comments: [comment],
  }).find((candidate) => candidate.commentNodeId === commentNodeId);
  if (!reason) {
    throw new Error(
      `Score comment authority subject ${commentNodeId} is not an independent human reproduction`,
    );
  }
  return scoreCommentAuthorityEvidenceFromReason(issueNumber, reason);
}

export function persistReleaseScoreRun(
  run: ReleaseScoreRun,
  context: ReleaseScorePersistenceContext = {},
): ReleaseScorePersistenceResult {
  assertReleaseScoreRunPersistable(run);
  const source = context.source?.trim() || 'unknown';
  const catalogAttestation = context.catalogAttestation ?? null;
  const codeRevision = normalizeCodeRevision(context.codeRevision);
  const clock = context.clock ?? SYSTEM_SCORE_COMMIT_CLOCK;
  const commitNotBeforePoint = scoreCommitClockPoint(clock, 'before score commit');
  let forecastPlan: ReleaseValidationForecastPublicationPlan | null = null;
  if (source === 'refresh') {
    if (!context.runId?.trim()) {
      throw new Error('Refresh score persistence requires an operation run ID');
    }
    const problems = releaseCatalogAttestationProblems(catalogAttestation);
    if (problems.length > 0) {
      throw new Error(
        `Refresh score persistence requires valid final catalog attestation: ` +
        problems.join('; '),
      );
    }
    if (!codeRevision) {
      throw new Error('Refresh score persistence requires the startup code revision');
    }
    forecastPlan = preflightReleaseValidationForecasts({
      run,
      attestation: catalogAttestation!,
      codeRevision,
      preflightAt: new Date(commitNotBeforePoint.wallTimeMs).toISOString(),
    });
  } else if (catalogAttestation) {
    throw new Error('Only refresh score persistence may carry catalog attestation');
  } else if (codeRevision) {
    throw new Error('Only refresh score persistence may carry code revision provenance');
  }
  const requestedPersistedAt = new Date(commitNotBeforePoint.wallTimeMs).toISOString();
  const historyRunId = releaseScoreHistoryRunId(context, requestedPersistedAt);
  const authorityRunId = `score-authority:${historyRunId}`;
  const existingHistoryRun = getReleaseScoreAuditHistoryRunSeal(historyRunId);
  const persistedAt = existingHistoryRun?.recorded_at ?? requestedPersistedAt;
  const scoredAts = run.scored
    .map((result) => result.scoredAt)
    .filter((scoredAt): scoredAt is string => typeof scoredAt === 'string' && Number.isFinite(Date.parse(scoredAt)))
    .sort((a, b) => Date.parse(a) - Date.parse(b));
  const previousIssueCrawl = parseScorePersistenceJson(getMeta('issue_crawl_last_run'), null);
  const issueCrawl = context.issueCrawl ?? previousIssueCrawl;
  const persistedIssueCrawl = source === 'refresh' && context.issueCrawl
    ? {
      ...context.issueCrawl,
      scorePersisted: true,
      scorePersistedAt: requestedPersistedAt,
    }
    : issueCrawl;
  const meta = {
    schemaVersion: 2,
    source,
    scope: context.scope ?? null,
    persistedAt,
    operationRunId: source === 'refresh' ? context.runId ?? null : null,
    operationReceiptRequired: source === 'refresh',
    codeRevision: source === 'refresh' ? codeRevision : null,
    catalogAttestation,
    scoreModelVersion: SCORE_MODEL_VERSION,
    promptVersion: PROMPT_VERSION,
    scoredReleaseCount: run.scored.length,
    recommendedTag: run.recommendedTag,
    recommendationPolicyCode: 'highest_confidence_with_recency_tolerance',
    recommendationThreshold: REC_THRESHOLD,
    recommendationRecencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
    releaseTags: run.scored.map((result) => result.rel.tag),
    stableTagsNewestFirst: run.stableTagsNewestFirst,
    oldestScoredStableTag: run.oldestScoredStableTag,
    oldestScoredStablePredecessorTag: run.oldestScoredStablePredecessorTag,
    predecessorByReleaseTag: run.predecessorByReleaseTag,
    minScoredAt: scoredAts[0] ?? null,
    maxScoredAt: scoredAts[scoredAts.length - 1] ?? null,
    issueCrawlStartedAt: typeof issueCrawl?.startedAt === 'string' ? issueCrawl.startedAt : null,
    issueCrawlFinishedAt: typeof issueCrawl?.finishedAt === 'string' ? issueCrawl.finishedAt : null,
    issueCrawlStopReason: typeof issueCrawl?.stopReason === 'string' ? issueCrawl.stopReason : null,
    issueCrawlScorePersistedAt: source === 'refresh'
      ? requestedPersistedAt
      : typeof issueCrawl?.scorePersistedAt === 'string' ? issueCrawl.scorePersistedAt : null,
    issueCrawlMetadataDigest: source === 'refresh' && persistedIssueCrawl
      ? createHash('sha256').update(canonicalOperationJson(persistedIssueCrawl)).digest('hex')
      : null,
    sourceIdentitySchemaVersion: run.sourceIdentity.schemaVersion,
    sourceIdentityDigest: run.sourceIdentity.digest,
    sourceIdentityRowCount: run.sourceIdentity.rowCount,
    sourceIdentitySourceCount: run.sourceIdentity.sourceCount,
  };
  const transactionResult = runInWriteTransaction(() => {
    if (source === 'refresh') {
      const currentCatalog = assertCatalogAttestationMatchesCurrent(catalogAttestation!);
      const latestScored = run.scored.find((result) =>
        result.rel.tag === currentCatalog.latestStable?.tag);
      if (
        !latestScored ||
        latestScored.rel.node_id !== currentCatalog.latestStable?.nodeId ||
        latestScored.rel.catalog_tag_commit_oid !==
          currentCatalog.latestStable?.tagCommitOid ||
        latestScored.rel.published_at !== currentCatalog.latestStable?.publishedAt
      ) {
        throw new Error('Refresh score run does not contain the attested latest stable release');
      }
    }
    const sourceIdentityOptions = {
      artifactObservationRunId: run.artifactObservationRunId,
    };
    const currentSourceIdentity = scoreSourceIdentity(sourceIdentityOptions);
    assertScoreSourceIdentityEqual(
      run.sourceIdentity,
      currentSourceIdentity,
      'source rows changed after scores were built and before persistence',
    );
    const authorityChainProblems = scoreAuthorityResolutionRunChainProblems();
    const historyV2ChainProblems = releaseScoreAuditHistoryV2SealChainProblems();
    if (authorityChainProblems.length > 0 || historyV2ChainProblems.length > 0) {
      throw new Error(
        `Refusing score persistence with invalid authority provenance: ` +
          [...authorityChainProblems, ...historyV2ChainProblems].join('; '),
      );
    }
    const authoritySubjects = validatedAuthoritySubjectsForPersistence(run);
    const existingAuthorityRun = getScoreAuthorityResolutionRun(authorityRunId);
    const authorityChain = listScoreAuthorityResolutionRuns();
    const previousAuthorityContentHash = existingAuthorityRun
      ? existingAuthorityRun.previousContentHash
      : authorityChain.at(-1)?.contentHash ?? null;
    const authorityRun = buildScoreAuthorityResolutionRun({
      authorityRunId,
      sourceIdentitySchemaVersion: run.sourceIdentity.schemaVersion,
      sourceIdentityDigest: run.sourceIdentity.digest,
      recordedAt: persistedAt,
      previousContentHash: previousAuthorityContentHash,
      rows: authoritySubjects,
    });
    const storedAuthorityRun =
      insertScoreAuthorityResolutionRun(authorityRun, {
        sourceIdentityOptions,
      }).row;
    clearReleaseScoresOutsideTags(run.scored.map((result) => result.rel.tag));
    for (const result of run.scored) {
      const scoredAt = result.scoredAt;
      const recommended = result.rel.tag === run.recommendedTag ? 1 : 0;
      updateReleaseScore({
        tag: result.rel.tag,
        final_score: result.conf.score,
        negative_issues: result.neg,
        positive_issues: result.pos,
        state: result.conf.status,
        recommended,
        score_reason: result.conf.reason,
        broken_surfaces: result.brokenSurfaces,
        closed_serious_fixed: result.closedSerious,
        opened_serious_during_reign: result.openedSerious,
        scored_at: scoredAt,
      });
      const auditInput = releaseScoreAuditInputForResult(
        run,
        result,
        storedAuthorityRun.authorityRunId,
      );
      upsertReleaseScoreAudit(auditInput);
      insertReleaseScoreAuditHistory(historyRunId, persistedAt, auditInput);
    }
    const historyRunSeal = sealReleaseScoreAuditHistoryRun(historyRunId, persistedAt);
    const historyV2Seal = sealReleaseScoreAuditHistoryV2({
      historyRunId,
      authorityRunId: storedAuthorityRun.authorityRunId,
      sealedAt: persistedAt,
    });
    if (source === 'refresh' && context.issueCrawl) {
      setMeta('issue_crawl_last_run', JSON.stringify(persistedIssueCrawl));
    }
    setMeta('score_persistence_last_run', JSON.stringify({
      ...meta,
      historyRunId,
      historyRunContentHash: historyRunSeal.row.content_hash,
      authorityRunId: storedAuthorityRun.authorityRunId,
      authorityRunContentHash: storedAuthorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
    }));
    if (meta.maxScoredAt) setMeta('last_scored_at', meta.maxScoredAt);
    return {
      historyRunSeal: historyRunSeal.row,
      authorityRun: storedAuthorityRun,
      historyV2Seal: historyV2Seal.row,
    };
  });
  const commitNotAfterPoint = scoreCommitClockPoint(clock, 'after score commit');
  const commitNotAfterMs = normalizedCommitNotAfterMs(
    commitNotBeforePoint,
    commitNotAfterPoint,
  );
  const commitTiming: ReleaseValidationScoreCommitTiming = {
    schemaVersion: 4,
    historyRunId,
    historyRunContentHash: transactionResult.historyRunSeal.content_hash,
    authorityRunId: transactionResult.authorityRun.authorityRunId,
    authorityRunContentHash: transactionResult.authorityRun.contentHash,
    historyV2SealContentHash: transactionResult.historyV2Seal.contentHash,
    historyRecordedAt: persistedAt,
    commitNotBefore: new Date(commitNotBeforePoint.wallTimeMs).toISOString(),
    commitNotAfter: new Date(commitNotAfterMs).toISOString(),
    commitNotBeforeMs: commitNotBeforePoint.wallTimeMs,
    commitNotAfterMs,
  };
  return {
    source,
    persistedAt,
    historyRunId,
    historyRunContentHash: transactionResult.historyRunSeal.content_hash,
    authorityRunId: transactionResult.authorityRun.authorityRunId,
    authorityRunContentHash: transactionResult.authorityRun.contentHash,
    historyV2SealContentHash: transactionResult.historyV2Seal.contentHash,
    commitTiming,
    catalogAttestation,
    codeRevision: source === 'refresh' ? codeRevision : null,
    forecastPlan,
    issueCrawlMetadata: persistedIssueCrawl,
  };
}

function releaseScoreHistoryRunId(
  context: ReleaseScorePersistenceContext,
  persistedAt: string,
): string {
  const source = context.source?.trim() || 'unknown';
  const requested = context.runId?.trim();
  if (!requested) return `${source}:${persistedAt}`;
  return requested.startsWith(`${source}:`) ? requested : `${source}:${requested}`;
}

export function finalizeReleaseScorePublicationMetadata(
  scorePersistence: ReleaseScorePersistenceResult,
): void {
  if (
    scorePersistence.source !== 'refresh' ||
    !scorePersistence.codeRevision ||
    !scorePersistence.forecastPlan
  ) {
    throw new Error('Only preflighted refresh scores can be finalized for publication');
  }
  const meta = parseScorePersistenceJson<Record<string, unknown> | null>(
    getMeta('score_persistence_last_run'),
    null,
  );
  if (
    !meta ||
    meta.schemaVersion !== 2 ||
    meta.source !== 'refresh' ||
    meta.historyRunId !== scorePersistence.historyRunId ||
    meta.historyRunContentHash !== scorePersistence.historyRunContentHash ||
    meta.authorityRunId !== scorePersistence.authorityRunId ||
    meta.authorityRunContentHash !== scorePersistence.authorityRunContentHash ||
    meta.historyV2SealContentHash !== scorePersistence.historyV2SealContentHash ||
    meta.codeRevision !== scorePersistence.codeRevision
  ) {
    throw new Error('Current score persistence metadata changed before publication finalization');
  }
  setMeta('score_persistence_last_run', JSON.stringify({
    ...meta,
    commitTiming: scorePersistence.commitTiming,
    forecastPlan: scorePersistence.forecastPlan,
  }));
}

export function captureReleaseValidationForecasts(args: {
  run: ReleaseScoreRun;
  scorePersistence: ReleaseScorePersistenceResult;
}): ReleaseValidationForecastCaptureResult {
  if (args.scorePersistence.source !== 'refresh') {
    throw new Error('Validation forecasts may only be captured by refresh score persistence');
  }
  const attestation = args.scorePersistence.catalogAttestation;
  const attestationProblems = releaseCatalogAttestationProblems(attestation);
  if (attestationProblems.length > 0 || !attestation) {
    throw new Error(
      `Refresh validation forecast capture requires valid catalog attestation: ` +
      attestationProblems.join('; '),
    );
  }
  const codeRevision = normalizeCodeRevision(args.scorePersistence.codeRevision);
  const forecastPlan = args.scorePersistence.forecastPlan;
  if (!codeRevision || !forecastPlan) {
    throw new Error('Refresh validation forecast capture requires its preflight plan and code revision');
  }
  const currentPlan = preflightReleaseValidationForecasts({
    run: args.run,
    attestation,
    codeRevision,
    preflightAt: forecastPlan.preflightAt,
  });
  if (JSON.stringify(currentPlan) !== JSON.stringify(forecastPlan)) {
    throw new Error('Validation forecast capture slots changed after score preflight');
  }
  const historyRunSeal = getReleaseScoreAuditHistoryRunSeal(
    args.scorePersistence.historyRunId,
  );
  if (
    !historyRunSeal ||
    historyRunSeal.content_hash !== args.scorePersistence.historyRunContentHash
  ) {
    throw new Error('Validation forecast capture history run is missing or has the wrong seal hash');
  }
  const authorityRun = getScoreAuthorityResolutionRun(
    args.scorePersistence.authorityRunId,
  );
  if (
    !authorityRun ||
    authorityRun.contentHash !== args.scorePersistence.authorityRunContentHash
  ) {
    throw new Error(
      'Validation forecast capture authority run is missing or has the wrong content hash',
    );
  }
  const historyV2Seal = getReleaseScoreAuditHistoryV2Seal(
    args.scorePersistence.historyRunId,
  );
  if (
    !historyV2Seal ||
    historyV2Seal.authorityRunId !== authorityRun.authorityRunId ||
    historyV2Seal.contentHash !== args.scorePersistence.historyV2SealContentHash
  ) {
    throw new Error(
      'Validation forecast capture history v2 seal is missing or does not bind the authority run',
    );
  }
  const commitProblems = releaseValidationScoreCommitTimingProblems(
    args.scorePersistence.commitTiming,
    {
      recordedAt: args.scorePersistence.commitTiming.commitNotAfter,
      historyRunId: args.scorePersistence.historyRunId,
      historyRunContentHash: historyRunSeal.content_hash,
      historyRecordedAt: historyRunSeal.recorded_at,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.contentHash,
    },
  );
  if (commitProblems.length > 0) {
    throw new Error(
      `Validation forecast capture score commit timing is invalid: ${commitProblems.join('; ')}`,
    );
  }
  assertCatalogAttestationMatchesCurrent(attestation);
  const latestStable = getRelease(attestation.latestStable.tag);
  if (
    !latestStable?.published_at ||
    latestStable.node_id !== attestation.latestStable.nodeId ||
    latestStable.catalog_tag_commit_oid !== attestation.latestStable.tagCommitOid ||
    latestStable.published_at !== attestation.latestStable.publishedAt
  ) {
    throw new Error('Validation forecast latest stable does not match catalog attestation');
  }
  const latestStablePublishedAt = latestStable.published_at;
  const latestResult = args.run.scored.find((result) => result.rel.tag === latestStable.tag);
  if (!latestResult) {
    throw new Error(`Validation forecast score run is missing latest stable ${latestStable.tag}`);
  }
  const decision = latestResult.recommendationDecision ?? latestResult.explanation.recommendationDecision;
  if (!decision) {
    throw new Error(`Cannot record validation forecast for ${latestStable.tag} without recommendationDecision`);
  }
  if (decision.releaseTag !== latestStable.tag || decision.selectedTag !== args.run.recommendedTag) {
    throw new Error(
      `Cannot record validation forecast for ${latestStable.tag} with inconsistent recommendation decision`,
    );
  }
  const recordedAt = args.scorePersistence.commitTiming.commitNotAfter;
  const recordedAtMs = args.scorePersistence.commitTiming.commitNotAfterMs;
  const publishedAtMs = Date.parse(latestStable.published_at);
  if (!Number.isFinite(recordedAtMs) || !Number.isFinite(publishedAtMs)) {
    throw new Error('Validation forecast capture timestamps are invalid');
  }
  const historyAudits = listReleaseScoreAuditHistoryForRun(
    args.scorePersistence.historyRunId,
  );
  const auditByTag = new Map(historyAudits.map((audit) => [audit.release_tag, audit]));
  const historyTags = new Set(historyAudits.map((audit) => audit.release_tag));
  const scoredTags = new Set(args.run.scored.map((result) => result.rel.tag));
  if (
    historyTags.size !== scoredTags.size ||
    [...historyTags].some((tag) => !scoredTags.has(tag))
  ) {
    throw new Error('Validation forecast score run does not exactly match durable history tags');
  }
  const candidateScores = args.run.scored.map((result) => {
    const audit = auditByTag.get(result.rel.tag);
    if (!audit) {
      throw new Error(`Cannot record validation forecast without audit history snapshot for ${result.rel.tag}`);
    }
    return {
      releaseTag: result.rel.tag,
      releasePublishedAt: result.rel.published_at,
      scoreSnapshot: {
        scoredAt: audit.scored_at,
        finalScore: audit.final_score,
        status: audit.status,
        band: audit.band,
        recommended: audit.recommended === 1,
      },
      recommendationDecision: result.recommendationDecision ?? result.explanation.recommendationDecision ?? null,
      auditSnapshot: {
        ...audit,
      },
    };
  });
  const sourceIdentityJson = JSON.stringify(args.run.sourceIdentity);
  return runInWriteTransaction(() => {
    const persistedForecasts: ReleaseValidationForecastCaptureResult['forecasts'] = [];
    const capturedLegacyRows: Array<{
      capture: ReleaseValidationForecastCaptureResult['forecasts'][number];
      row: ReleaseValidationForecastRow;
    }> = [];
    for (const [opportunityCode, opportunity] of Object.entries(
      RELEASE_VALIDATION_OPPORTUNITIES,
    )) {
      const timing = releaseValidationForecastTiming({
        opportunity_code: opportunityCode,
        recorded_at: recordedAt,
        latest_release_published_at: latestStablePublishedAt,
      });
      if (!timing.valid) continue;
      const plannedSlot = forecastPlan.slots.find((slot) =>
        slot.opportunityCode === opportunityCode);
      if (!plannedSlot) {
        throw new Error(`Validation forecast preflight omitted ${opportunityCode}`);
      }
      if (plannedSlot.existingDecisionId) {
        const existing = getReleaseValidationForecastForSlot({
          opportunity_code: opportunityCode,
          latest_release_tag: latestStable.tag,
          score_model_version: SCORE_MODEL_VERSION,
          prompt_version: PROMPT_VERSION,
          code_revision: codeRevision,
        });
        if (
          !existing ||
          existing.decision_id !== plannedSlot.existingDecisionId ||
          existing.content_hash !== plannedSlot.existingContentHash
        ) {
          throw new Error(
            `Validation forecast occupied slot changed after preflight for ` +
            `${latestStable.tag}/${opportunityCode}`,
          );
        }
        const capture = {
          opportunityCode,
          status: 'already_captured' as const,
          decisionId: existing.decision_id,
          codeRevision,
        };
        persistedForecasts.push(capture);
        capturedLegacyRows.push({ capture, row: existing });
        continue;
      }
      const input = {
        opportunity_code: opportunityCode,
        recorded_at: recordedAt,
        latest_release_tag: latestStable.tag,
        latest_release_published_at: latestStablePublishedAt,
        selected_tag: decision.selectedTag,
        audit_history_run_id: args.scorePersistence.historyRunId,
        score_model_version: SCORE_MODEL_VERSION,
        prompt_version: PROMPT_VERSION,
        policy_code: decision.policyCode,
        candidate_scores_json: JSON.stringify(candidateScores),
        decision_json: JSON.stringify({
          schemaVersion: 4,
          opportunityCode,
          recordedAt,
          latestReleaseTag: latestStable.tag,
          latestReleasePublishedAt: latestStablePublishedAt,
          latestReleaseAgeHours: timing.ageHours,
          opportunityWindow: {
            minAgeHours: opportunity.minAgeHours,
            maxAgeHours: opportunity.maxAgeHours,
            windowStartAt: timing.windowStartAt,
            windowEndAt: timing.windowEndAt,
            windowStartMs: timing.windowStartMs,
            windowEndMs: timing.windowEndMs,
            observedAtMs: timing.recordedAtMs,
            observedAgeHours: timing.ageHours,
            valid: true,
          },
          selectedTag: decision.selectedTag,
          recommendationDecision: decision,
          scoreCommit: args.scorePersistence.commitTiming,
          catalogAttestation: attestation,
        }),
        source_identity_json: sourceIdentityJson,
        code_revision: codeRevision,
      };
      const result = insertReleaseValidationForecast(input);
      verifyReleaseValidationForecastResult(input, result);
      const capture = {
        opportunityCode,
        status: result.inserted ? 'inserted' as const : 'already_captured' as const,
        decisionId: result.row.decision_id,
        codeRevision,
      };
      persistedForecasts.push(capture);
      capturedLegacyRows.push({ capture, row: result.row });
    }
    const canonicalForecasts = captureCanonicalReleaseValidationForecasts({
      capturedLegacyRows,
      scorePersistence: args.scorePersistence,
      currentCatalogAttestation: attestation,
    });
    const insertedCount = persistedForecasts.filter((forecast) =>
      forecast.status === 'inserted').length;
    return {
      eligibilityOutcome: persistedForecasts.length === 0
        ? 'not_eligible'
        : insertedCount > 0
          ? 'eligible_and_captured'
          : 'already_captured',
      forecasts: persistedForecasts,
      canonicalForecasts,
    };
  });
}

interface CanonicalForecastLegacyCapture {
  capture: ReleaseValidationForecastCaptureResult['forecasts'][number];
  row: ReleaseValidationForecastRow;
}

function captureCanonicalReleaseValidationForecasts(args: {
  capturedLegacyRows: CanonicalForecastLegacyCapture[];
  scorePersistence: ReleaseScorePersistenceResult;
  currentCatalogAttestation: ReleaseCatalogAttestation;
}): ReleaseValidationForecastCaptureResult['canonicalForecasts'] {
  if (args.capturedLegacyRows.length === 0) return [];

  const bundle = readReleaseValidationProofBundle();
  const verification = verifyReleaseValidationProofBundle(bundle);
  if (!verification.valid) {
    throw new Error(
      `Canonical validation forecast capture requires a valid proof ledger: ` +
      verification.problems.join('; '),
    );
  }
  const repository = `${config.github.owner}/${config.github.repo}`;
  const codeRevision = normalizeCodeRevision(args.scorePersistence.codeRevision);
  if (!codeRevision) {
    throw new Error('Canonical validation forecast capture requires a code revision');
  }
  const matchingCohorts = bundle.cohorts.filter((cohort) =>
    cohort.modelVersion === SCORE_MODEL_VERSION &&
    cohort.promptVersion === PROMPT_VERSION &&
    cohort.codeRevision === codeRevision);
  if (matchingCohorts.length === 0) {
    throw new Error(
      `Canonical validation forecast capture has no cohort for ` +
      `${SCORE_MODEL_VERSION}/${PROMPT_VERSION}/${codeRevision}`,
    );
  }

  const newForecasts: ReleaseValidationForecastV2[] = [];
  const captures: ReleaseValidationForecastCaptureResult['canonicalForecasts'] = [];
  const workingForecasts = [...bundle.forecasts];
  const cohortState = new Map<string, {
    nextSequence: number;
    tip: string | null;
  }>();
  const expectedHorizons = Object.keys(
    RELEASE_VALIDATION_HORIZONS,
  ) as ReleaseValidationHorizonCode[];

  for (const legacy of args.capturedLegacyRows) {
    const legacyContext = canonicalLegacyForecastContext({
      row: legacy.row,
      repository,
      scorePersistence: args.scorePersistence,
      currentCatalogAttestation: args.currentCatalogAttestation,
    });
    const activeCohorts = matchingCohorts.filter((cohort) =>
      Date.parse(cohort.startsAt) <= Date.parse(legacy.row.recorded_at) &&
      (
        cohort.retiredAt == null ||
        Date.parse(legacy.row.recorded_at) < Date.parse(cohort.retiredAt)
      ));
    if (activeCohorts.length === 0) {
      const prospectiveCohorts = matchingCohorts.filter((cohort) =>
        Date.parse(legacyContext.latestRelease.publishedAt) <
        Date.parse(cohort.startsAt));
      if (prospectiveCohorts.length === matchingCohorts.length) {
        continue;
      }
      throw new Error(
        `Canonical validation forecast ${legacy.row.decision_id} has no ` +
        `cohort active at its original capture time`,
      );
    }
    if (activeCohorts.length !== 1) {
      throw new Error(
        `Canonical validation forecast ${legacy.row.decision_id} matches ` +
        `${activeCohorts.length} active cohorts`,
      );
    }
    const cohort = activeCohorts[0];
    const obligations = bundle.obligations.filter((obligation) =>
      obligation.cohortId === cohort.cohortId &&
      obligation.release.releaseId === legacyContext.latestRelease.releaseId &&
      obligation.opportunityCode === legacy.row.opportunity_code);
    if (obligations.length === 0) {
      if (
        Date.parse(legacyContext.latestRelease.publishedAt) <
        Date.parse(cohort.startsAt)
      ) {
        continue;
      }
      throw new Error(
        `Canonical validation forecast ${legacy.row.decision_id} is missing ` +
        `prospective obligations for ${legacy.row.opportunity_code}`,
      );
    }
    const proofSlots = canonicalForecastProofSlots({
      bundle,
      cohort,
      releaseId: legacyContext.latestRelease.releaseId,
      opportunityCode: legacy.row.opportunity_code,
      legacyDecisionId: legacy.row.decision_id,
      expectedHorizons,
    });

    const cohortChain = cohortState.get(cohort.cohortId) ?? {
      nextSequence: maximumReleaseValidationCohortSequence(bundle, cohort.cohortId),
      tip: verification.cohortChainTips[cohort.cohortId] ?? null,
    };
    cohortState.set(cohort.cohortId, cohortChain);

    for (const horizonCode of expectedHorizons) {
      const { obligation, assignment } = proofSlots.get(horizonCode)!;
      if (Date.parse(legacy.row.recorded_at) < Date.parse(obligation.recordedAt)) {
        throw new Error(
          `Canonical validation forecast ${legacy.row.decision_id} predates ` +
          `obligation ${obligation.obligationId}; historical backfill is forbidden`,
        );
      }
      const existing = workingForecasts.filter((forecast) =>
        forecast.obligationId === obligation.obligationId);
      if (existing.length > 1) {
        throw new Error(
          `Canonical validation obligation ${obligation.obligationId} has ` +
          `multiple immutable forecasts`,
        );
      }
      if (existing.length === 1) {
        assertCanonicalForecastReuse({
          forecast: existing[0],
          cohort,
          obligation,
          assignmentId: assignment.assignmentId,
          legacy,
          context: legacyContext,
        });
        captures.push(canonicalForecastCapture(
          existing[0],
          obligation,
          legacy,
          'already_captured',
        ));
        continue;
      }
      const forecast = sealReleaseValidationForecastV2({
        proofEpochId: cohort.proofEpochId,
        cohortId: cohort.cohortId,
        cohortSequence: ++cohortChain.nextSequence,
        previousCohortContentHash: cohortChain.tip,
        obligationId: obligation.obligationId,
        splitAssignmentId: assignment.assignmentId,
        policyId: cohort.policyId,
        policyContentHash: cohort.policyContentHash,
        recordedAt: legacy.row.recorded_at,
        latestRelease: legacyContext.latestRelease,
        candidates: legacyContext.candidates,
        selectedReleaseId: legacyContext.selectedReleaseId,
        forecast: legacyContext.forecastPayload,
      });
      cohortChain.tip = forecast.contentHash;
      newForecasts.push(forecast);
      workingForecasts.push(forecast);
      captures.push(canonicalForecastCapture(
        forecast,
        obligation,
        legacy,
        'inserted',
      ));
    }
  }

  if (newForecasts.length > 0) {
    const persistence = appendReleaseValidationProof({
      forecasts: newForecasts,
    });
    if (
      persistence.insertedByType.forecasts !== newForecasts.length ||
      persistence.equivalentByType.forecasts !== 0
    ) {
      throw new Error(
        `Canonical validation forecast append persisted ` +
        `${persistence.insertedByType.forecasts}/${newForecasts.length} new ` +
        `forecast rows`,
      );
    }
  }
  return captures;
}

interface CanonicalForecastProofSlot {
  obligation: ReleaseValidationObligation;
  assignment: ReleaseValidationSplitAssignment;
}

function canonicalForecastProofSlots(args: {
  bundle: ReleaseValidationProofBundle;
  cohort: ReleaseValidationCohort;
  releaseId: string;
  opportunityCode: string;
  legacyDecisionId: string;
  expectedHorizons?: readonly ReleaseValidationHorizonCode[];
}): Map<ReleaseValidationHorizonCode, CanonicalForecastProofSlot> {
  const expectedHorizons = args.expectedHorizons ?? (
    Object.keys(RELEASE_VALIDATION_HORIZONS) as ReleaseValidationHorizonCode[]
  );
  const obligations = args.bundle.obligations.filter((obligation) =>
    obligation.cohortId === args.cohort.cohortId &&
    obligation.release.releaseId === args.releaseId &&
    obligation.opportunityCode === args.opportunityCode);
  const obligationsByHorizon = new Map(
    obligations.map((obligation) => [obligation.horizonCode, obligation]),
  );
  if (
    obligations.length !== expectedHorizons.length ||
    obligationsByHorizon.size !== expectedHorizons.length ||
    expectedHorizons.some((horizonCode) =>
      !obligationsByHorizon.has(horizonCode))
  ) {
    throw new Error(
      `Canonical validation forecast ${args.legacyDecisionId} requires ` +
      `exactly one obligation for each horizon`,
    );
  }

  const slots = new Map<
    ReleaseValidationHorizonCode,
    CanonicalForecastProofSlot
  >();
  for (const horizonCode of expectedHorizons) {
    const obligation = obligationsByHorizon.get(horizonCode)!;
    if (
      obligation.proofEpochId !== args.cohort.proofEpochId ||
      obligation.cohortId !== args.cohort.cohortId ||
      obligation.horizonCode !== horizonCode
    ) {
      throw new Error(
        `Canonical validation obligation ${obligation.obligationId} ` +
        `does not match its cohort and horizon slot`,
      );
    }
    const assignments = args.bundle.splitAssignments.filter((assignment) =>
      assignment.obligationId === obligation.obligationId);
    if (assignments.length !== 1) {
      throw new Error(
        `Canonical validation obligation ${obligation.obligationId} has ` +
        `${assignments.length} split assignments`,
      );
    }
    const assignment = assignments[0];
    if (
      assignment.proofEpochId !== obligation.proofEpochId ||
      assignment.cohortId !== obligation.cohortId
    ) {
      throw new Error(
        `Canonical validation split assignment ${assignment.assignmentId} ` +
        `does not match obligation ${obligation.obligationId}`,
      );
    }
    slots.set(horizonCode, { obligation, assignment });
  }
  return slots;
}

interface CanonicalLegacyForecastContext {
  latestRelease: ReleaseValidationStableReleaseIdentity;
  candidates: ReleaseValidationStableReleaseIdentity[];
  selectedReleaseId: string | null;
  forecastPayload: ReleaseValidationProofJsonValue;
}

function canonicalLegacyForecastContext(args: {
  row: ReleaseValidationForecastRow;
  repository: string;
  scorePersistence: ReleaseScorePersistenceResult;
  currentCatalogAttestation: ReleaseCatalogAttestation;
}): CanonicalLegacyForecastContext {
  if (!/^[0-9a-f]{64}$/.test(args.row.content_hash)) {
    throw new Error(
      `Legacy validation forecast ${args.row.decision_id} has no valid content hash`,
    );
  }
  const codeRevision = normalizeCodeRevision(args.row.code_revision);
  if (!codeRevision || codeRevision !== args.scorePersistence.codeRevision) {
    throw new Error(
      `Legacy validation forecast ${args.row.decision_id} has the wrong code revision`,
    );
  }
  const candidateRows = parseRequiredJsonArray(
    args.row.candidate_scores_json,
    `legacy forecast ${args.row.decision_id} candidates`,
  );
  const candidateTags = candidateRows.map((candidate, index) => {
    const record = asJsonRecord(
      candidate,
      `legacy forecast ${args.row.decision_id} candidate ${index}`,
    );
    const releaseTag = typeof record.releaseTag === 'string'
      ? record.releaseTag.trim()
      : '';
    if (!releaseTag) {
      throw new Error(
        `Legacy validation forecast ${args.row.decision_id} has a candidate ` +
        `without releaseTag`,
      );
    }
    return releaseTag;
  });
  if (new Set(candidateTags).size !== candidateTags.length) {
    throw new Error(
      `Legacy validation forecast ${args.row.decision_id} repeats a candidate release`,
    );
  }
  const candidates = candidateTags.map((tag) =>
    canonicalReleaseIdentityForTag(tag, args.repository));
  const latestRelease = canonicalReleaseIdentityForTag(
    args.row.latest_release_tag,
    args.repository,
  );
  if (
    latestRelease.publishedAt !== args.row.latest_release_published_at ||
    !candidates.some((candidate) =>
      candidate.releaseId === latestRelease.releaseId)
  ) {
    throw new Error(
      `Legacy validation forecast ${args.row.decision_id} has an inconsistent ` +
      `latest release identity`,
    );
  }
  const selectedReleaseId = args.row.selected_tag == null
    ? null
    : candidates.find((candidate) =>
      candidate.aliases.includes(args.row.selected_tag!))?.releaseId ?? null;
  if (args.row.selected_tag != null && selectedReleaseId == null) {
    throw new Error(
      `Legacy validation forecast ${args.row.decision_id} selected release is ` +
      `absent from its candidate identities`,
    );
  }

  const decision = parseJsonRecord(
    args.row.decision_json,
    `legacy forecast ${args.row.decision_id} decision`,
  );
  const originalScoreCommit = asJsonRecord(
    decision.scoreCommit,
    `legacy forecast ${args.row.decision_id} scoreCommit`,
  );
  const originalCatalogAttestation = asJsonRecord(
    decision.catalogAttestation,
    `legacy forecast ${args.row.decision_id} catalogAttestation`,
  );
  const recommendationDecision = asJsonRecord(
    decision.recommendationDecision,
    `legacy forecast ${args.row.decision_id} recommendationDecision`,
  );
  const sourceIdentity = parseJsonRecord(
    args.row.source_identity_json,
    `legacy forecast ${args.row.decision_id} source identity`,
  );
  const sourceIdentityDigest = typeof sourceIdentity.digest === 'string'
    ? sourceIdentity.digest
    : '';
  if (!/^[0-9a-f]{64}$/.test(sourceIdentityDigest)) {
    throw new Error(
      `Legacy validation forecast ${args.row.decision_id} source identity ` +
      `has no valid digest`,
    );
  }
  const sourceIdentitySchemaVersion = Number(sourceIdentity.schemaVersion);
  if (!Number.isInteger(sourceIdentitySchemaVersion) || sourceIdentitySchemaVersion <= 0) {
    throw new Error(
      `Legacy validation forecast ${args.row.decision_id} source identity ` +
      `has no valid schema version`,
    );
  }
  const forecastPayload = {
    schemaVersion: 1,
    opportunityCode: args.row.opportunity_code,
    legacyForecast: {
      decisionId: args.row.decision_id,
      contentHash: args.row.content_hash,
      recordedAt: args.row.recorded_at,
      auditHistoryRunId: args.row.audit_history_run_id,
      latestReleaseTag: args.row.latest_release_tag,
      latestReleasePublishedAt: args.row.latest_release_published_at,
      selectedTag: args.row.selected_tag,
      scoreModelVersion: args.row.score_model_version,
      promptVersion: args.row.prompt_version,
      policyCode: args.row.policy_code,
      codeRevision,
    },
    originalScorePublication: {
      scoreCommit: originalScoreCommit,
      recommendationDecision,
      catalogAttestation: originalCatalogAttestation,
      sourceIdentity: {
        schemaVersion: sourceIdentitySchemaVersion,
        digest: sourceIdentityDigest,
      },
    },
    canonicalCapturePublication: {
      historyRunId: args.scorePersistence.historyRunId,
      historyRunContentHash: args.scorePersistence.historyRunContentHash,
      authorityRunId: args.scorePersistence.authorityRunId,
      authorityRunContentHash: args.scorePersistence.authorityRunContentHash,
      historyV2SealContentHash: args.scorePersistence.historyV2SealContentHash,
      persistedAt: args.scorePersistence.persistedAt,
      scoreCommit: args.scorePersistence.commitTiming,
      catalogAttestation: args.currentCatalogAttestation,
    },
  } as const;
  const canonicalForecastPayload = JSON.parse(
    canonicalReleaseValidationProofJson(forecastPayload),
  ) as ReleaseValidationProofJsonValue;
  return {
    latestRelease,
    candidates,
    selectedReleaseId,
    forecastPayload: canonicalForecastPayload,
  };
}

function canonicalReleaseIdentityForTag(
  tag: string,
  repository: string,
): ReleaseValidationStableReleaseIdentity {
  const release = getRelease(tag);
  if (
    !release?.node_id ||
    !release.catalog_tag_commit_oid ||
    !release.published_at
  ) {
    throw new Error(
      `Canonical validation forecast release ${JSON.stringify(tag)} lacks ` +
      `node, commit, or publication identity`,
    );
  }
  return createReleaseValidationStableReleaseIdentity({
    repository,
    nodeId: release.node_id,
    tagCommitOid: release.catalog_tag_commit_oid,
    publishedAt: release.published_at,
    aliases: [release.tag],
  });
}

function assertCanonicalForecastReuse(args: {
  forecast: ReleaseValidationForecastV2;
  cohort: ReleaseValidationCohort;
  obligation: ReleaseValidationObligation;
  assignmentId: string;
  legacy: CanonicalForecastLegacyCapture;
  context: CanonicalLegacyForecastContext;
}): void {
  const storedPayload = asJsonRecord(
    args.forecast.forecast,
    `canonical forecast ${args.forecast.forecastId} payload`,
  );
  const expectedPayload = asJsonRecord(
    args.context.forecastPayload,
    `canonical forecast ${args.forecast.forecastId} expected payload`,
  );
  if (
    args.forecast.cohortId !== args.cohort.cohortId ||
    args.forecast.obligationId !== args.obligation.obligationId ||
    args.forecast.splitAssignmentId !== args.assignmentId ||
    args.forecast.policyId !== args.cohort.policyId ||
    args.forecast.policyContentHash !== args.cohort.policyContentHash ||
    args.forecast.recordedAt !== args.legacy.row.recorded_at ||
    args.forecast.latestRelease.releaseId !==
      args.context.latestRelease.releaseId ||
    canonicalReleaseValidationProofJson(args.forecast.candidates) !==
      canonicalReleaseValidationProofJson(args.context.candidates) ||
    args.forecast.selectedReleaseId !== args.context.selectedReleaseId ||
    canonicalReleaseValidationProofJson(storedPayload.legacyForecast) !==
      canonicalReleaseValidationProofJson(expectedPayload.legacyForecast) ||
    canonicalReleaseValidationProofJson(storedPayload.originalScorePublication) !==
      canonicalReleaseValidationProofJson(expectedPayload.originalScorePublication)
  ) {
    throw new Error(
      `Canonical validation forecast ${args.forecast.forecastId} is not an ` +
      `exact reuse of legacy decision ${args.legacy.row.decision_id}`,
    );
  }
}

function canonicalForecastCapture(
  forecast: ReleaseValidationForecastV2,
  obligation: ReleaseValidationObligation,
  legacy: CanonicalForecastLegacyCapture,
  status: 'inserted' | 'already_captured',
): ReleaseValidationForecastCaptureResult['canonicalForecasts'][number] {
  return {
    opportunityCode: obligation.opportunityCode,
    horizonCode: obligation.horizonCode as ReleaseValidationHorizonCode,
    status,
    forecastId: forecast.forecastId,
    contentHash: forecast.contentHash,
    obligationId: forecast.obligationId,
    splitAssignmentId: forecast.splitAssignmentId,
    cohortId: forecast.cohortId,
    legacyDecisionId: legacy.row.decision_id,
    legacyContentHash: legacy.row.content_hash,
  };
}

function maximumReleaseValidationCohortSequence(
  bundle: ReleaseValidationProofBundle,
  cohortId: string,
): number {
  return Math.max(0, ...[
    ...bundle.obligations,
    ...bundle.splitAssignments,
    ...bundle.forecasts,
    ...bundle.outcomes,
    ...bundle.observationBatches,
  ].filter((row) => row.cohortId === cohortId)
    .map((row) => row.cohortSequence));
}

function parseRequiredJsonArray(json: string, label: string): unknown[] {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch (error) {
    throw new Error(`${label} is not valid JSON`, { cause: error });
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function parseJsonRecord(json: string, label: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch (error) {
    throw new Error(`${label} is not valid JSON`, { cause: error });
  }
  return asJsonRecord(value, label);
}

function asJsonRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

const SYSTEM_SCORE_COMMIT_CLOCK: ScoreCommitClock = {
  wallTimeMs: Date.now,
  monotonicTimeMs: () => performance.now(),
};

interface ScoreCommitClockPoint {
  wallTimeMs: number;
  monotonicTimeMs: number;
}

function scoreCommitClockPoint(
  clock: ScoreCommitClock,
  label: string,
): ScoreCommitClockPoint {
  const wallTimeMs = Math.trunc(clock.wallTimeMs());
  const monotonicTimeMs = Math.trunc(clock.monotonicTimeMs());
  if (!Number.isSafeInteger(wallTimeMs) || !Number.isSafeInteger(monotonicTimeMs)) {
    throw new Error(`Score commit clock ${label} returned a non-integer millisecond value`);
  }
  return { wallTimeMs, monotonicTimeMs };
}

function normalizedCommitNotAfterMs(
  before: ScoreCommitClockPoint,
  after: ScoreCommitClockPoint,
): number {
  const monotonicElapsedMs = after.monotonicTimeMs - before.monotonicTimeMs;
  if (monotonicElapsedMs < 0) {
    throw new Error('Score commit monotonic clock moved backward after score durability');
  }
  const monotonicFloorMs = before.wallTimeMs + monotonicElapsedMs;
  const normalized = Math.max(
    before.wallTimeMs,
    after.wallTimeMs,
    monotonicFloorMs,
  );
  if (!Number.isSafeInteger(normalized)) {
    throw new Error('Score commit clock could not produce a safe normalized timestamp');
  }
  return normalized;
}

function verifyReleaseValidationForecastResult(
  input: {
    opportunity_code: string;
    recorded_at: string;
    latest_release_tag: string;
    audit_history_run_id: string;
    score_model_version: string;
    prompt_version: number;
    code_revision: string;
  },
  result: ReleaseValidationForecastInsertResult,
): void {
  const validStatus =
    (result.status === 'inserted' && result.inserted && !result.equivalent) ||
    (result.status === 'equivalent' && !result.inserted && result.equivalent);
  if (!validStatus) {
    throw new Error('Validation forecast persistence returned an invalid status');
  }
  const row = result.row;
  if (
    row.opportunity_code !== input.opportunity_code ||
    row.recorded_at !== input.recorded_at ||
    row.latest_release_tag !== input.latest_release_tag ||
    row.audit_history_run_id !== input.audit_history_run_id ||
    row.score_model_version !== input.score_model_version ||
    row.prompt_version !== input.prompt_version ||
    row.code_revision !== input.code_revision
  ) {
    throw new Error(
      `Validation forecast persistence returned the wrong capture slot for ` +
      `${input.latest_release_tag}/${input.opportunity_code}`,
    );
  }
}

function parseScorePersistenceJson<T>(json: string | null, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function targetEvidenceAttributionDiagnostic(result: ReleaseScoreResult): {
  issueNumbers: number[];
  problems: string[];
} {
  const required = postPublicationTargetAttributions(result.rel, result.scoredAt);
  const issueNumbers = required.map(({ row }) => row.number).sort((left, right) => left - right);
  const payload = (result.debtEvidence as {
    targetEvidenceAttribution?: unknown;
  }).targetEvidenceAttribution;
  if (!Array.isArray(payload)) {
    return {
      issueNumbers,
      problems: issueNumbers.length > 0
        ? [`${result.rel.tag} target evidence attribution payload is missing`]
        : [],
    };
  }
  const rowsByIssue = new Map<number, Record<string, unknown>>();
  const problems: string[] = [];
  for (const raw of payload) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      problems.push(`${result.rel.tag} target evidence attribution contains a malformed row`);
      continue;
    }
    const row = raw as Record<string, unknown>;
    const issueNumber = Number(row.issueNumber);
    if (!Number.isInteger(issueNumber) || issueNumber <= 0 || rowsByIssue.has(issueNumber)) {
      problems.push(`${result.rel.tag} target evidence attribution has an invalid or duplicate issue number`);
      continue;
    }
    rowsByIssue.set(issueNumber, row);
  }
  const requiredByIssue = new Map(required.map((item) => [item.row.number, item]));
  for (const [issueNumber, item] of requiredByIssue) {
    const row = rowsByIssue.get(issueNumber);
    if (!row) {
      problems.push(
        `${result.rel.tag} post-publication exact-version reproduction issue #${issueNumber} ` +
        `is missing from target evidence`,
      );
      continue;
    }
    if (row.reasonCode !== 'post_publication_exact_version_human_reproduction') {
      problems.push(`${result.rel.tag} target evidence issue #${issueNumber} has the wrong reason code`);
    }
    if (JSON.stringify(row.releaseLocalEvidence) !== JSON.stringify(item.evidence)) {
      problems.push(`${result.rel.tag} target evidence issue #${issueNumber} does not match current comment evidence`);
    }
  }
  for (const issueNumber of rowsByIssue.keys()) {
    if (!requiredByIssue.has(issueNumber)) {
      problems.push(`${result.rel.tag} target evidence contains stale issue #${issueNumber}`);
    }
  }
  return { issueNumbers, problems };
}

function scoreAuthorityManifestProblems(run: ReleaseScoreRun): string[] {
  const problems: string[] = [];
  const requiredReferences = new Map<string, ScoreAuthorityReference>();
  for (const result of run.scored) {
    if (!Array.isArray(result.authorityReferences)) {
      problems.push(`${result.rel.tag} score authority references are missing`);
      continue;
    }
    const references = result.authorityReferences.slice().sort(
      (left, right) =>
        String(left.subjectKind).localeCompare(String(right.subjectKind)) ||
        String(left.subjectIdentity).localeCompare(String(right.subjectIdentity)),
    );
    const referenceKeys = references.map((reference) =>
      `${reference.subjectKind}\0${reference.subjectIdentity}`);
    if (new Set(referenceKeys).size !== referenceKeys.length) {
      problems.push(
        `${result.rel.tag} score authority references contain duplicate subjects`,
      );
    }
    for (const [index, reference] of references.entries()) {
      const referenceProblems = scoreAuthorityReferenceProblems(reference);
      if (referenceProblems.length > 0) {
        problems.push(
          `${result.rel.tag} score authority reference ${index} is invalid: ` +
            referenceProblems.join(', '),
        );
        continue;
      }
      const key = referenceKeys[index];
      const existing = requiredReferences.get(key);
      if (
        existing &&
        canonicalScoreAuthorityReferenceJson(existing) !==
          canonicalScoreAuthorityReferenceJson(reference)
      ) {
        problems.push(
          `${result.rel.tag} score authority reference ${key} conflicts across releases`,
        );
      } else {
        requiredReferences.set(key, reference);
      }
    }
    const explanationReferences = result.explanation?.authorityReferences;
    if (
      !Array.isArray(explanationReferences) ||
      canonicalOperationJson(explanationReferences) !==
        canonicalOperationJson(references)
    ) {
      problems.push(
        `${result.rel.tag} explanation authority references do not match the score result`,
      );
    }
    const authorityManifests = result.scoreLedger?.evidence?.manifests
      ?.filter((manifest) => manifest.key === 'scoreAuthority') ?? [];
    if (authorityManifests.length !== 1) {
      problems.push(
        `${result.rel.tag} score ledger must contain exactly one scoreAuthority manifest`,
      );
      continue;
    }
    const manifest = authorityManifests[0];
    const expectedManifestRefs = references.map((reference) => ({
      kind: 'score_authority',
      identity: `${reference.subjectKind}:${reference.subjectIdentity}`,
      digest: scoreAuthorityReferenceDigest(reference),
    })).sort((left, right) =>
      left.kind.localeCompare(right.kind) ||
      left.identity.localeCompare(right.identity) ||
      left.digest.localeCompare(right.digest));
    if (
      manifest.exhaustive !== true ||
      manifest.count !== expectedManifestRefs.length ||
      canonicalOperationJson(manifest.refs) !==
        canonicalOperationJson(expectedManifestRefs)
    ) {
      problems.push(
        `${result.rel.tag} scoreAuthority manifest does not exactly match ` +
          'the score authority references',
      );
    }
  }

  if (!Array.isArray(run.authoritySubjects)) {
    problems.push('score authority subject ledger is missing');
    return problems;
  }
  const suppliedReferences = new Map<string, ScoreAuthorityReference>();
  for (const subject of run.authoritySubjects) {
    let reference: ScoreAuthorityReference;
    try {
      reference = buildScoreAuthorityReference(
        subject.subjectKind,
        subject.subjectIdentity,
        subject.resolution,
      );
    } catch (error) {
      problems.push(
        `score authority subject ${String(subject.subjectKind)}:` +
          `${String(subject.subjectIdentity)} is invalid: ` +
          `${error instanceof Error ? error.message : String(error)}`,
      );
      continue;
    }
    const key = `${reference.subjectKind}\0${reference.subjectIdentity}`;
    if (suppliedReferences.has(key)) {
      problems.push(`score authority subject ledger contains duplicate ${key}`);
      continue;
    }
    suppliedReferences.set(key, reference);
    const required = requiredReferences.get(key);
    if (!required) {
      problems.push(`score authority subject ledger contains stale or extra ${key}`);
    } else if (
      canonicalScoreAuthorityReferenceJson(required) !==
        canonicalScoreAuthorityReferenceJson(reference)
    ) {
      problems.push(`score authority subject ledger mismatches required ${key}`);
    }
  }
  for (const key of requiredReferences.keys()) {
    if (!suppliedReferences.has(key)) {
      problems.push(`score authority subject ledger is missing required ${key}`);
    }
  }
  return problems;
}

function assertReleaseScoreRunPersistable(run: ReleaseScoreRun): void {
  const incomplete = run.scored.filter((result) =>
    Number(result.input.classifiedIssueCount ?? 0) !== Number(result.input.rawIssueCount ?? 0));
  const failures: string[] = [];
  const activeStableTagsNewestFirst = listActiveReleaseCatalogDb()
    .filter((release) => release.prerelease === 0)
    .map((release) => release.tag);
  const classifierKnownTags = run.scored.map((result) => result.rel.tag);
  const currentClassifierIdentity = classifierSourceIdentity(
    classifierKnownTags,
    PROMPT_VERSION,
  );
  failures.push(...validateRecommendationDecisionRun({
    rows: run.scored.map((result) => ({
      tag: result.rel.tag,
      publishedAt: result.rel.published_at ?? '',
      status: result.conf.status,
      score: result.conf.score,
      recommended: result.rel.tag === run.recommendedTag,
      componentsDecision: result.recommendationDecision,
      explanationDecision: result.explanation.recommendationDecision,
    })),
    expectedSelectedTag: run.recommendedTag,
    expectedThreshold: REC_THRESHOLD,
    expectedRecencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
  }));
  if (!run.sourceIdentity || typeof run.sourceIdentity.digest !== 'string' || !run.sourceIdentity.digest) {
    failures.push('score source identity is missing or malformed');
  }
  failures.push(...scoreAuthorityManifestProblems(run));
  if (run.predecessorBoundaryProblems.length > 0) {
    failures.push(`predecessor boundary is invalid: ${run.predecessorBoundaryProblems.join(', ')}`);
  }
  if (
    run.oldestScoredStableTag &&
    (
      !run.oldestScoredStablePredecessorTag ||
      run.predecessorByReleaseTag[run.oldestScoredStableTag] !==
        run.oldestScoredStablePredecessorTag
    )
  ) {
    failures.push('oldest scored stable predecessor boundary is missing or inconsistent');
  }
  if (
    run.oldestScoredStablePredecessorTag &&
    getRelease(run.oldestScoredStablePredecessorTag)?.catalog_active !== 1
  ) {
    failures.push(
      `predecessor boundary release ${run.oldestScoredStablePredecessorTag} is missing from the database`,
    );
  }
  for (const result of run.scored) {
    const ledgerProblems = scoreLedgerPersistenceProblems(result);
    if (ledgerProblems.length > 0) {
      failures.push(
        `${result.rel.tag} ScoreLedgerV2 is invalid: ${ledgerProblems.join(', ')}`,
      );
    }
    const stableIndex = activeStableTagsNewestFirst.indexOf(result.rel.tag);
    const catalogPredecessorTag = stableIndex >= 0
      ? activeStableTagsNewestFirst[stableIndex + 1] ?? null
      : null;
    const predecessorTag = run.predecessorByReleaseTag[result.rel.tag] ?? null;
    if (predecessorTag !== catalogPredecessorTag) {
      failures.push(
        `${result.rel.tag} predecessor ${predecessorTag ?? 'none'} does not match active stable catalog ` +
        `${catalogPredecessorTag ?? 'none'}`,
      );
      continue;
    }
    const predecessorRelease = predecessorTag ? getRelease(predecessorTag) : undefined;
    if (!predecessorRelease) {
      failures.push(`${result.rel.tag} predecessor release ${predecessorTag ?? 'none'} is missing`);
      continue;
    }
    const targetPublishedAt = result.rel.published_at
      ? Date.parse(result.rel.published_at)
      : NaN;
    const predecessorPublishedAt = predecessorRelease.published_at
      ? Date.parse(predecessorRelease.published_at)
      : NaN;
    if (
      predecessorRelease.catalog_active !== 1 ||
      predecessorRelease.prerelease === 1 ||
      !Number.isFinite(targetPublishedAt) ||
      !Number.isFinite(predecessorPublishedAt) ||
      predecessorPublishedAt >= targetPublishedAt
    ) {
      failures.push(`${result.rel.tag} predecessor release ${predecessorTag} is not an older stable boundary`);
    }
  }
  const stableWindowFailure = formatStableReleaseWindowIntegrityFailure(stableReleaseWindowIntegrity(3));
  if (stableWindowFailure) failures.push(stableWindowFailure);
  if (incomplete.length > 0) {
    const examples = incomplete
      .slice(0, 5)
      .map((result) => `${result.rel.tag} ${result.input.classifiedIssueCount}/${result.input.rawIssueCount}`)
      .join(', ');
    const suffix = incomplete.length > 5 ? `, +${incomplete.length - 5} more` : '';
    failures.push(`incomplete classification coverage: ${examples}${suffix}`);
  }
  for (const result of run.scored) {
    let targetEvidenceIssueNumbers: number[] = [];
    try {
      const targetEvidence = targetEvidenceAttributionDiagnostic(result);
      targetEvidenceIssueNumbers = targetEvidence.issueNumbers;
      failures.push(...targetEvidence.problems);
    } catch (error) {
      failures.push(
        `${result.rel.tag} post-publication target evidence could not be verified: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const commentIntegrity = releaseCommentClassificationIntegrity(
      result.rel.tag,
      PROMPT_VERSION,
      classifierKnownTags,
      targetEvidenceIssueNumbers,
    );
    if (commentIntegrity.failedCount > 0) {
      failures.push(
        `${result.rel.tag} comment/classification evidence is incomplete ` +
        `(issues=${commentIntegrity.issueCount}, missingSnapshots=${commentIntegrity.missingSnapshotCount}, ` +
        `invalidSnapshots=${commentIntegrity.invalidSnapshotCount}, ` +
        `commentDigestMismatches=${commentIntegrity.commentDigestMismatchCount}, ` +
        `missingClassifications=${commentIntegrity.missingClassificationCount}, ` +
        `staleClassifications=${commentIntegrity.staleClassificationCount}, ` +
        `classifierSourceIdentityMismatches=${commentIntegrity.classifierSourceIdentityMismatchCount}, ` +
        `invalidRawClassifications=${commentIntegrity.invalidRawClassificationCount}, ` +
        `expectedClassifierSourceIdentity=${currentClassifierIdentity.digest})`,
      );
    }
    const timelineFailure = formatReleaseIssueTimelineIntegrityFailure(
      releaseIssueTimelineIntegrity(result.rel.tag, 3),
    );
    if (timelineFailure) failures.push(timelineFailure);
    const stateSnapshotFailure = formatReleaseIssueStateSnapshotIntegrityFailure(
      releaseIssueStateSnapshotIntegrity(result.rel.tag, 3),
    );
    if (stateSnapshotFailure) failures.push(stateSnapshotFailure);
    const closureProofFailure = formatReleaseClosureProofIntegrityFailure(
      releaseClosureProofIntegrity(result.rel.tag, 3),
    );
    if (closureProofFailure) failures.push(closureProofFailure);
    failures.push(...currentScoreCompletenessDiagnostic({
      tag: result.rel.tag,
      labelCutoff: releaseLabelCutoff(result.rel, result.scoredAt),
      analysisCompleteness: result.analysisCompleteness,
    }).problems);
    const reachabilityFailure = formatReleasePrReachabilityIntegrityFailure(
      releasePrReachabilityIntegrity(result.rel.tag, 3),
    );
    if (reachabilityFailure) failures.push(reachabilityFailure);
    const releaseFixCredit = (result.gateEvidence as any)?.fixProvenance?.releaseFixCredit;
    const fixCreditProblems = releaseFixCredit && typeof releaseFixCredit === 'object'
      ? releaseFixCreditPayloadProblems(result.rel.tag, releaseFixCredit, {
        requireDecisionDetails: true,
      })
      : ['releaseFixCredit payload is missing'];
    if (fixCreditProblems.length > 0) {
      failures.push(`${result.rel.tag} fix-credit decisions are invalid: ${fixCreditProblems.join(', ')}`);
    }
  }
  if (
    run.oldestScoredStablePredecessorTag &&
    !run.scored.some((result) => result.rel.tag === run.oldestScoredStablePredecessorTag)
  ) {
    const reachabilityFailure = formatReleasePrReachabilityIntegrityFailure(
      releasePrReachabilityIntegrity(run.oldestScoredStablePredecessorTag, 3),
    );
    if (reachabilityFailure) failures.push(reachabilityFailure);
  }
  if (failures.length > 0) {
    throw new Error(`Refusing to persist scores until score evidence is complete: ${failures.join('; ')}`);
  }
}

function scoreLedgerPersistenceProblems(result: ReleaseScoreResult): string[] {
  const problems = scoreLedgerV2Problems(result.explanation?.scoreLedger, {
    input: result.input,
    confidence: result.conf,
    scoredAt: result.scoredAt,
  });
  if (
    result.scoreLedger !== result.explanation?.scoreLedger &&
    JSON.stringify(result.scoreLedger) !== JSON.stringify(result.explanation?.scoreLedger)
  ) {
    problems.push('result scoreLedger and explanation scoreLedger must be identical');
  }
  return problems;
}

function assertScoreSourceIdentityEqual(
  expected: ReturnType<typeof scoreSourceIdentity>,
  actual: ReturnType<typeof scoreSourceIdentity>,
  message: string,
): void {
  if (JSON.stringify(expected) === JSON.stringify(actual)) return;
  throw new Error(
    `Refusing to persist scores because ${message}: expected ${expected.digest}, got ${actual.digest}`,
  );
}

export const __releaseScorePersistenceTest = {
  assertReleaseScoreRunPersistable,
  scoreAuthorityManifestProblems,
};

interface PostPublicationTargetAttribution {
  row: ReleaseAttributionCandidateRow;
  evidence: ReleaseLocalEvidence;
}

function isClassifiedAttributionCandidate(
  row: ReleaseAttributionCandidateRow,
): row is JoinedIssue {
  return row.issue_number === row.number &&
    typeof row.sentiment === 'string' &&
    typeof row.severity === 'string' &&
    typeof row.scope === 'string' &&
    typeof row.functionality === 'string' &&
    typeof row.affected_users === 'string';
}

function postPublicationTargetAttributions(
  release: Pick<ReleaseRow, 'tag' | 'published_at'>,
  cutoff: string,
): PostPublicationTargetAttribution[] {
  return closedBeforeReleaseCommentCandidates(release.tag).flatMap((row) => {
    const comments = completeIssueComments(row.number).filter((comment) =>
      commentAvailableAtCutoff(comment, cutoff));
    const commentReasons = semanticHumanConfirmationReasons({
      issueNumber: row.number,
      issueNodeId: row.node_id,
      issueAuthor: {
        nodeId: row.author_node_id ?? null,
        login: row.author,
        actorType: row.author_type,
      },
      cutoff,
      comments,
    });
    const reasonsByCommentNodeId = new Map(
      commentReasons.map((reason) => [
        reason.commentNodeId!,
        reason,
      ] as const),
    );
    const authorizedCommentNodeIds = new Set(reasonsByCommentNodeId.keys());
    const authorizedComments = comments.filter((comment) => {
      try {
        const identity = canonicalCommentSourceIdentity(comment);
        return identity != null && authorizedCommentNodeIds.has(identity.nodeId);
      } catch {
        return false;
      }
    });
    const evidence = exactReleaseLocalCommentEvidence(
      authorizedComments,
      release.tag,
      release.published_at,
      (commentNodeId) =>
        reasonsByCommentNodeId.get(commentNodeId)?.authorityReference ?? null,
    );
    return evidence ? [{ row, evidence }] : [];
  });
}

function scoreRelease(args: {
  release: ReleaseRow;
  isLatest: boolean;
  allFetchedTags: string[];
  stableTagsNewestFirst: string[];
  predecessorTag: string | null;
  oldestScoredStableTag: string | null;
  oldestScoredStablePredecessorTag: string | null;
  cveFor: (tag: string) => AdvisoryCveSignal;
  now: number;
  recordAuthoritySubject: (
    subject: ScoreAuthorityResolutionSubject,
  ) => void;
  artifactVerification: ReturnType<
    typeof getReleaseArtifactVerificationForScoring
  >;
}): ReleaseScoreResult {
  const { release: rel } = args;
  const artifactReceipt = args.artifactVerification?.receipt ?? null;
  const scoredAt = new Date(args.now).toISOString();
  const authorityReferencesByIdentity =
    new Map<string, ScoreAuthorityReference>();
  const recordAuthoritySubject = (
    subject: ScoreAuthorityResolutionSubject,
  ): ScoreAuthorityReference => {
    const reference = buildScoreAuthorityReference(
      subject.subjectKind,
      subject.subjectIdentity,
      subject.resolution,
    );
    const key = `${reference.subjectKind}\0${reference.subjectIdentity}`;
    const existing = authorityReferencesByIdentity.get(key);
    if (
      existing &&
      canonicalScoreAuthorityReferenceJson(existing) !==
        canonicalScoreAuthorityReferenceJson(reference)
    ) {
      throw new Error(
        `Conflicting score authority reference ${reference.subjectKind}:` +
          reference.subjectIdentity,
      );
    }
    authorityReferencesByIdentity.set(key, reference);
    args.recordAuthoritySubject(subject);
    return reference;
  };
  const labelCutoff = releaseLabelCutoff(rel, args.now);
  const completeCommentsByIssue = new Map<number, ReturnType<typeof completeIssueComments>>();
  const commentsForIssue = (row: Pick<JoinedIssue, 'number'>) => {
    const cached = completeCommentsByIssue.get(row.number);
    if (cached) return cached;
    const comments = completeIssueComments(row.number);
    completeCommentsByIssue.set(row.number, comments);
    return comments;
  };
  const targetEvidenceComments = (row: Pick<JoinedIssue, 'number'>) =>
    commentsForIssue(row).filter((comment) => commentAvailableAtCutoff(comment, scoredAt));
  const authorizedTargetEvidenceCommentsByIssue =
    new Map<number, ReturnType<typeof completeIssueComments>>();
  const commentAuthorityReferencesByIssue =
    new Map<number, Map<string, ScoreAuthorityReference>>();
  const authorizedTargetEvidenceComments = (
    row: Pick<
      JoinedIssue,
      'number' | 'node_id' | 'author_node_id' | 'author' | 'author_type'
    >,
  ) => {
    const cached = authorizedTargetEvidenceCommentsByIssue.get(row.number);
    if (cached) return cached;
    const comments = targetEvidenceComments(row);
    const commentReasons = semanticHumanConfirmationReasons({
      issueNumber: row.number,
      issueNodeId: row.node_id,
      issueAuthor: {
        nodeId: row.author_node_id ?? null,
        login: row.author,
        actorType: row.author_type,
      },
      cutoff: scoredAt,
      comments,
    });
    const authorityReferences = new Map(
      commentReasons.map((reason) => [
        reason.commentNodeId!,
        reason.authorityReference,
      ] as const),
    );
    const authorizedNodeIds = new Set(authorityReferences.keys());
    const authorized = comments.filter((comment) => {
      try {
        const identity = canonicalCommentSourceIdentity(comment);
        return identity != null && authorizedNodeIds.has(identity.nodeId);
      } catch {
        return false;
      }
    });
    authorizedTargetEvidenceCommentsByIssue.set(row.number, authorized);
    commentAuthorityReferencesByIssue.set(row.number, authorityReferences);
    return authorized;
  };
  const closureClaimReferencesByCandidate =
    new Map<string, ScoreAuthorityReference>();
  const recordClosureClaim = (
    binding: ClosureClaimAuthorityBinding,
  ): ScoreAuthorityReference => {
    const candidateId = binding.candidate.candidateId;
    if (
      !candidateId ||
      binding.resolution.authorizedForScoring !== true ||
      binding.resolution.candidateId !== candidateId
    ) {
      throw new Error(
        'Only an authorized immutable closure claim may affect scoring',
      );
    }
    const cached = closureClaimReferencesByCandidate.get(candidateId);
    if (cached) return cached;
    const reference = recordAuthoritySubject({
      releaseTag: null,
      issueNumber: binding.candidate.issue.number,
      subjectKind: 'closure_claim',
      subjectIdentity: candidateId,
      candidateId,
      resolution: binding.resolution,
    });
    closureClaimReferencesByCandidate.set(candidateId, reference);
    return reference;
  };
  const closureAuthority = createReleaseClosureAuthorityEvaluation({
    onAuthorizedClaim: recordClosureClaim,
  });
  const targetUnaffected = (row: Pick<JoinedIssue, 'number'>): boolean => {
    return closureAuthority.releaseExplicitlyUnaffected(
      row.number,
      rel.tag,
    );
  };
  const releaseLocalEvidenceByIssue = new Map<number, ReleaseLocalEvidence | null>();
  const targetReleaseEvidence = (
    row: Pick<
      JoinedIssue,
      | 'number'
      | 'title'
      | 'body'
      | 'node_id'
      | 'author_node_id'
      | 'author'
      | 'author_type'
    >,
  ): ReleaseLocalEvidence | null => {
    if (releaseLocalEvidenceByIssue.has(row.number)) {
      return releaseLocalEvidenceByIssue.get(row.number) ?? null;
    }
    const evidence = targetUnaffected(row)
      ? null
      : exactReleaseLocalEvidence(
          row,
          rel.tag,
          authorizedTargetEvidenceComments(row),
          rel.published_at,
          (commentNodeId) =>
            commentAuthorityReferencesByIssue.get(row.number)?.get(commentNodeId) ??
              null,
        );
    releaseLocalEvidenceByIssue.set(row.number, evidence);
    return evidence;
  };
  const otherReleaseEvidenceByIssue =
    new Map<number, ReleaseLocalEvidence | null>();
  const releasePublishedAtByTag = new Map<string, string | null>([
    [rel.tag, rel.published_at ?? null],
  ]);
  const releasePublishedAtForEvidence = (tag: string): string | null => {
    if (releasePublishedAtByTag.has(tag)) {
      return releasePublishedAtByTag.get(tag) ?? null;
    }
    const publishedAt = getRelease(tag)?.published_at ?? null;
    releasePublishedAtByTag.set(tag, publishedAt);
    return publishedAt;
  };
  const otherReleaseEvidence = (
    row: Pick<
      JoinedIssue,
      | 'number'
      | 'title'
      | 'body'
      | 'affects_version'
      | 'node_id'
      | 'author_node_id'
      | 'author'
      | 'author_type'
    >,
  ): ReleaseLocalEvidence | null => {
    if (otherReleaseEvidenceByIssue.has(row.number)) {
      return otherReleaseEvidenceByIssue.get(row.number) ?? null;
    }
    if (
      targetReleaseEvidence(row) != null ||
      hasExplicitReleaseMismatch({
        ...row,
        releaseLocalEvidence: null,
        releaseExplicitlyUnaffected: false,
      }, rel.tag)
    ) {
      otherReleaseEvidenceByIssue.set(row.number, null);
      return null;
    }
    const comments = authorizedTargetEvidenceComments(row);
    let evidence: ReleaseLocalEvidence | null = null;
    for (const tag of args.allFetchedTags) {
      if (releaseVersionsMatch(tag, rel.tag)) continue;
      evidence = exactReleaseLocalEvidence(
        row,
        tag,
        comments,
        releasePublishedAtForEvidence(tag),
        (commentNodeId) =>
          commentAuthorityReferencesByIssue.get(row.number)?.get(commentNodeId) ??
            null,
      );
      if (evidence) break;
    }
    otherReleaseEvidenceByIssue.set(row.number, evidence);
    return evidence;
  };
  const releaseMatchEvidence = (
    row: Parameters<typeof otherReleaseEvidence>[0],
  ): ReleaseLocalEvidence | null =>
    targetReleaseEvidence(row) ?? otherReleaseEvidence(row);
  const labelInfoByIssue = new Map<number, {
    labels: string[];
    scoringLabels: string[];
    authorizedScoringLabels: string[];
    labelActors: Record<string, string | null>;
    authorityReferences: Record<string, ScoreAuthorityReference>;
    currentLabels: string[];
    timelineEventCount: number;
    source: 'current' | 'timeline' | 'snapshot' | 'missing_timeline';
  }>();
  const labelInfo = (row: JoinedIssue) => {
    const cached = labelInfoByIssue.get(row.number);
    if (cached) return cached;
    const currentLabels = safeParseLabels(row.labels);
    const timelineEventCount = issueLabelEventCount(row.number);
    const snapshotCount = issueLabelSnapshotCountAt(row.number, labelCutoff);
    const labels = labelsForIssueAt(row.number, currentLabels, labelCutoff, {
      useFallbackWhenNoEvents: labelCutoff == null,
      useSnapshotWhenNoEvents: labelCutoff != null,
    });
    const authorityReferenceByEventId =
      new Map<string, ScoreAuthorityReference>();
    const resolvedLabels = scoringLabelInfoAtCutoff(
      row.number,
      labels,
      labelCutoff,
      (eventId) => {
        let resolution: ScoreAuthorityResolution;
        try {
          const evidence = labelAuthorityEvidenceForEvent(eventId);
          resolution = buildScoreAuthorityResolution(evidence);
        } catch {
          return null;
        }
        if (!resolution.authorizedForScoring) return null;
        const reference = recordAuthoritySubject({
          releaseTag: null,
          issueNumber: row.number,
          subjectKind: 'label_event',
          subjectIdentity: eventId,
          candidateId: null,
          resolution,
        });
        authorityReferenceByEventId.set(eventId, reference);
        return reference;
      },
    );
    const source: 'current' | 'timeline' | 'snapshot' | 'missing_timeline' = labelCutoff == null
      ? 'current'
      : timelineEventCount > 0
        ? 'timeline'
        : snapshotCount > 0
          ? 'snapshot'
        : 'missing_timeline';
    const info = {
      labels,
      scoringLabels: resolvedLabels.labels,
      authorizedScoringLabels: resolvedLabels.authorizedScoringLabels,
      labelActors: resolvedLabels.labelActors,
      authorityReferences: Object.fromEntries(
        resolvedLabels.authorizedScoringLabels.flatMap((label) => {
          const event = latestIssueLabelEventAt(row.number, label, labelCutoff);
          const reference = event
            ? authorityReferenceByEventId.get(event.event_id)
            : null;
          return reference ? [[label, reference] as const] : [];
        }),
      ),
      currentLabels,
      timelineEventCount,
      source,
    };
    labelInfoByIssue.set(row.number, info);
    return info;
  };
  const effectiveLabels = (row: JoinedIssue): string[] => labelInfo(row).scoringLabels;
  const labelAuthority = (row: JoinedIssue): LabelOverrideAuthority => ({
    labelActors: labelInfo(row).labelActors,
    authorizedScoringLabels: labelInfo(row).authorizedScoringLabels,
    authorityReferences: labelInfo(row).authorityReferences,
  });
  const classify = (row: JoinedIssue): IssueClassification =>
    classifyIssueRowWithLabels(row, effectiveLabels(row), labelAuthority(row));
  const classifyDebt = (row: JoinedIssue): IssueClassification =>
    classifyIssueRowForOpenDebtWithLabels(row, effectiveLabels(row), labelAuthority(row));
  const fieldEvidenceByIssue = new Map<number, ReturnType<typeof issueFieldEvidence>>();
  const fieldEvidence = (row: JoinedIssue) => {
    const cached = fieldEvidenceByIssue.get(row.number);
    if (cached) return cached;
    const evidence = issueFieldEvidence(row, effectiveLabels(row), labelCutoff, {
      comments: commentsForIssue(row),
      labelAuthority: labelAuthority(row),
      recordAuthoritySubject,
      authorityReferenceForEvent: (eventId) =>
        authorityReferencesByIdentity.get(`label_event\0${eventId}`) ?? null,
    });
    fieldEvidenceByIssue.set(row.number, evidence);
    return evidence;
  };
  const scoringFieldEvidence = fieldEvidence;
  const countCoreSerious = (rows: JoinedIssue[]): number =>
    rows.reduce((n, r) => (isCoreSerious(classify(r)) ? n + 1 : n), 0);

  let neg = 0;
  let pos = 0;
  const intervalAttributed = issuesForVersion(rel.tag);
  const postPublicationAttributions = postPublicationTargetAttributions(rel, scoredAt);
  for (const attribution of postPublicationAttributions) {
    completeCommentsByIssue.set(attribution.row.number, completeIssueComments(attribution.row.number));
    releaseLocalEvidenceByIssue.set(attribution.row.number, attribution.evidence);
  }
  const attributed = [
    ...intervalAttributed,
    ...postPublicationAttributions
      .map((attribution) => attribution.row)
      .filter(isClassifiedAttributionCandidate),
  ];
  const unclassifiedIssues = [
    ...unclassifiedIssuesForVersion(rel.tag, 25),
    ...postPublicationAttributions
      .map((attribution) => attribution.row)
      .filter((row) => !isClassifiedAttributionCandidate(row)),
  ].slice(0, 25);
  for (const row of attributed) {
    const sentiment = classify(row).sentiment;
    if (sentiment === 'negative') neg++;
    else if (sentiment === 'positive') pos++;
  }

  const openedReign = openedDuringReign(rel.tag);
  const rawVerifiedFixed = verifiedFixedForRelease(rel.tag);
  const rawReleaseClosureProofs = closureProofRows(rel.tag);
  const rawUnverifiedClosed = unverifiedClosedForRelease(rel.tag);
  const issueRowsByNumber = new Map(
    [...attributed, ...openedReign, ...rawVerifiedFixed, ...rawUnverifiedClosed]
      .map((row) => [row.number, row] as const),
  );
  const verifiedFixed = rawVerifiedFixed.filter((row) => !targetUnaffected(row));
  const unverifiedClosed = rawUnverifiedClosed.filter((row) => !targetUnaffected(row));
  const releaseClosureProofs = rawReleaseClosureProofs;
  const authorityAdjustedClosureDisposition = (
    row: Parameters<typeof closureAuthority.closureDisposition>[0],
  ): ReturnType<typeof closureRiskDisposition> => {
    return closureAuthority.closureDisposition(row);
  };
  const closureRiskCandidateRows = releaseClosureProofs.filter(
    (row) => !targetUnaffected({ number: row.issue_number }),
  );
  const closureRiskCandidateNumbers = new Set(
    closureRiskCandidateRows.map((row) => row.issue_number),
  );
  const fixCreditDecisions = releaseClosureProofs
    .filter((row) => row.status === 'fixed_in_release')
    .sort((left, right) => left.issue_number - right.issue_number)
    .map((row) => releaseFixCreditDecision(row.issue_number, rel.tag, args.predecessorTag));
  const fixCreditDecisionByIssue = new Map(
    fixCreditDecisions.map((decision) => [decision.issueNumber, decision]),
  );
  const introducedVerifiedFixed = verifiedFixed.filter((row) =>
    fixCreditDecisionByIssue.get(row.number)?.status === 'credited');
  const issueAliasGroups = buildIssueAliasGroups([
    ...[...attributed, ...openedReign, ...verifiedFixed, ...unverifiedClosed].map((row) => ({
      issueNumber: row.number,
      duplicateCluster: row.duplicate_cluster,
    })),
    ...releaseClosureProofs.map((row) => ({
      issueNumber: row.issue_number,
      duplicateCluster: row.duplicate_cluster,
      canonicalIssueNumbers: canonicalIssueNumbersFromEvidence(row.evidence_json),
    })),
  ]);
  const aliasGroupForIssue = (row: { number: number; duplicate_cluster?: string | null }): string =>
    issueAliasGroups.keyFor({
      issueNumber: row.number,
      duplicateCluster: row.duplicate_cluster,
    });
  const resolvedForRiskNumbers = new Set(verifiedFixed.map((row) => row.number));
  for (const row of releaseClosureProofs) {
    if (
      !isAdverseClosureRiskDisposition(
        authorityAdjustedClosureDisposition(row),
      ) ||
      !closureRiskCandidateNumbers.has(row.issue_number)
    ) {
      resolvedForRiskNumbers.add(row.issue_number);
    }
  }
  const releaseClosureProofNumbers = new Set(
    releaseClosureProofs.map((row) => row.issue_number),
  );
  const unverifiedClosedWithoutClosureProof = unverifiedClosed.filter(
    (row) => !releaseClosureProofNumbers.has(row.number),
  );
  const scoreStateForIssue = (row: JoinedIssue): string =>
    releaseScopedDebtState(row, resolvedForRiskNumbers, releaseClosureProofNumbers);
  const feltInput = (row: JoinedIssue) => ({
    ...classify(row),
    ...scoringFieldEvidence(row),
    issueNumber: row.number,
    issueNodeId: row.node_id,
    title: row.title,
    duplicateCluster: row.duplicate_cluster,
    aliasGroup: aliasGroupForIssue(row),
    author: row.author,
    authorNodeId: row.author_node_id,
    authorType: row.author_type,
    authorAssociation: row.author_association,
    isBot: row.is_bot,
    comments: row.comments,
    uniqueHumanCommenterCount: row.unique_human_commenters,
    maintainerCommenterCount: row.maintainer_commenters,
    contributorCommenterCount: row.contributor_commenters,
    commenterScanTruncated: row.commenter_scan_truncated,
    reactionTotal: row.reaction_total,
    positiveReactionCount: row.positive_reactions,
    labels: effectiveLabels(row),
  });

  const releaseLinkedDebtRows = releaseLinkedIssueRows(
    attributed
      .filter((row) => !targetUnaffected(row))
      .map((row) => ({
        ...row,
        releaseLocalEvidence: releaseMatchEvidence(row),
        releaseExplicitlyUnaffected: false,
      })),
    rel.tag,
  );
  const debtInputs = releaseLinkedDebtRows.map((row) => {
    const baseClassification = classify(row);
    const debtClassification = classifyDebt(row);
    const debtClassificationDiff = classificationDiff(baseClassification, debtClassification);
    const releaseLocalEvidence = targetReleaseEvidence(row);
    return {
      ...feltInput(row),
      ...debtClassification,
      issueNumber: row.number,
      state: scoreStateForIssue(row),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      affectsVersion: row.affects_version,
      releaseLocal: releaseLocalEvidence != null,
      ...(releaseLocalEvidence ? { releaseLocalEvidence } : {}),
      ...(Object.keys(debtClassificationDiff).length
        ? { debtClassification, debtClassificationDiff }
      : {}),
    };
  });
  const rawDebt = explainOpenDebtLoad(debtInputs);
  const releaseLinkedOpenedRows = releaseLinkedIssueRows(
    openedReign
      .filter((row) => !targetUnaffected(row))
      .map((row) => ({
        ...row,
        releaseLocalEvidence: releaseMatchEvidence(row),
        releaseExplicitlyUnaffected: false,
      })),
    rel.tag,
  );
  const proofByIssue = new Map(releaseClosureProofs.map((row) => [row.issue_number, row]));
  const regressionOpenedRows = releaseLinkedOpenedRows.filter((row) => {
    if (scoreStateForIssue(row) === 'open') return false;
    const proof = proofByIssue.get(row.number);
    return !proof ||
      isAdverseClosureRiskDisposition(
        authorityAdjustedClosureDisposition(proof),
      );
  });
  const openedSerious = countCoreSerious(releaseLinkedOpenedRows);
  const closedSerious = countCoreSerious(introducedVerifiedFixed);
  const regressionFeltInputs = regressionOpenedRows.map(feltInput);
  const rawRegression = explainFeltLoad(regressionFeltInputs);
  const rawClosureRisk = aggregateClosureRisk(
    closureRiskCandidateRows.map((row) => {
      const issueRow = { ...row, number: row.issue_number } as unknown as JoinedIssue;
      const classification = classifyDebt(issueRow);
      const disposition = authorityAdjustedClosureDisposition(row);
      return {
        issueNumber: row.issue_number,
        disposition,
        weight: closureRiskWeightForRow({
          status: row.status,
          sentiment: classification.sentiment,
          severity: classification.severity,
          scope: classification.scope,
          functionality: classification.functionality,
          affected_users: classification.affectedUsers,
        }, disposition),
        duplicateCluster: row.duplicate_cluster,
        canonicalIssueNumbers: canonicalIssueNumbersFromEvidence(row.evidence_json),
        aliasGroup: issueAliasGroups.keyFor({
          issueNumber: row.issue_number,
          duplicateCluster: row.duplicate_cluster,
          canonicalIssueNumbers: canonicalIssueNumbersFromEvidence(row.evidence_json),
        }),
      };
    }),
  );
  const riskAccounting = applyExclusiveIssueRiskLedger({
    debt: rawDebt,
    regression: rawRegression,
    closureRisk: rawClosureRisk,
  });
  const activeDebt = riskAccounting.debt;
  const openedFeltAnalysis = riskAccounting.regression;
  const countedOpenedFeltRows = regressionOpenedRows.filter((_, rowIndex) =>
    openedFeltAnalysis.evidence[rowIndex]?.counted === true
  );
  const feltOpenedWeight = openedFeltAnalysis.load;
  const feltClosedWeight = feltLoad(introducedVerifiedFixed.map(feltInput));
  const brokenSurfaces = JSON.stringify(topBrokenSurfaces(countedOpenedFeltRows.map((row) => row.title)));
  const cve = args.cveFor(rel.tag);
  const releaseCommit = getReleaseCommit(rel.tag);
  const artifactScore = releaseArtifactScoreProjection(
    args.artifactVerification,
    releaseCommit?.tag_commit_oid ?? null,
  );
  const riskDispositionOverrides = new Map(
    releaseClosureProofs.map((row) => [
      row.issue_number,
      authorityAdjustedClosureDisposition(row),
    ] as const),
  );
  const closureProof = closureProofPayload(rel.tag, labelCutoff, {
    predecessorTag: args.predecessorTag,
    fixCreditDecisions,
    riskDispositionOverrides,
  });
  const completenessDiagnostic = currentScoreCompletenessDiagnostic({
    tag: rel.tag,
    labelCutoff,
  });
  const unresolvedClosureRiskWeight = riskAccounting.closureRisk.unresolvedWeightedRisk;
  const affirmativeClosureRiskCeilingWeight = rawClosureRisk.unresolvedWeightedRisk;
  const debtSummary = {
    verified: debtTierSummary(activeDebt.evidence, 'verified'),
    carryover: debtTierSummary(activeDebt.evidence, 'carryover'),
    stale: debtTierSummary(activeDebt.evidence, 'stale'),
  };
  const input: InstallInput = {
    schemaVersion: SCORE_INPUT_SCHEMA_VERSION,
    publishedAt: rel.published_at,
    isLatest: args.isLatest,
    hoursToNextStable: rel.hours_to_next_stable,
    hasHotfixSuccessor: hasHotfixSuccessor(args.allFetchedTags, rel.tag),
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    feltOpenedWeight,
    feltClosedWeight,
    verifiedDebtWeight: activeDebt.loads.verified,
    carryoverDebtWeight: activeDebt.loads.carryover,
    staleDebtWeight: activeDebt.loads.stale,
    verifiedDebtIssueCount: debtSummary.verified.count,
    carryoverDebtIssueCount: debtSummary.carryover.count,
    staleDebtIssueCount: debtSummary.stale.count,
    unresolvedClosureRiskWeight,
    affirmativeClosureRiskCeilingWeight,
    unresolvedClosureIssueCount: riskAccounting.closureRisk.unresolvedForReleaseCount,
    rawIssueCount: issueCountForVersion(rel.tag) + postPublicationAttributions.length,
    classifiedIssueCount: attributed.length,
    cveAffected: cve.affected,
    cveLoad: cve.load,
    releaseCheckState: releaseCommit?.check_state ?? null,
    releaseCheckTotal: releaseCommit?.check_total ?? 0,
    releaseCheckSuccess: releaseCommit?.check_success ?? 0,
    releaseCheckFailure: releaseCommit?.check_failure ?? 0,
    releaseCheckPending: releaseCommit?.check_pending ?? 0,
    ...artifactScore.input,
  };
  const conf = installConfidence(input, args.now);
  const issueByNumber = new Map(attributed.map((row) => [row.number, row]));
  const summarizeIssue = (row: JoinedIssue | undefined) => {
    if (!row) return null;
    const storedClassification = rowToClassification(row);
    const classification = classify(row);
    return {
      number: row.number,
      title: row.title,
      url: row.html_url,
      state: row.state,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      closedAt: row.closed_at,
      author: row.author,
      comments: row.comments,
      uniqueHumanCommenters: row.unique_human_commenters,
      maintainerCommenters: row.maintainer_commenters,
      contributorCommenters: row.contributor_commenters,
      commenterScanTruncated: row.commenter_scan_truncated,
      reactionTotal: row.reaction_total,
      positiveReactions: row.positive_reactions,
      labels: labelInfo(row).labels,
      currentLabels: labelInfo(row).currentLabels,
      labelCutoffAt: labelCutoff,
      labelTimelineEventCount: labelInfo(row).timelineEventCount,
      labelSource: labelInfo(row).source,
      affectsVersion: row.affects_version,
      duplicateCluster: row.duplicate_cluster,
      classificationOrigin: row.classification_origin,
      storedClassification,
      rawClassification: row.classification_origin === 'raw_model' ? storedClassification : null,
      classification,
      classificationDiff: classificationDiff(storedClassification, classification),
    };
  };

  const debtEvidence = {
    schemaVersion: ISSUE_EVIDENCE_SCHEMA_VERSION,
    evidenceCounts: {
      verifiedDebt: activeDebt.evidence.filter((item) => item.tier === 'verified').length,
      carryoverDebt: activeDebt.evidence.filter((item) => item.tier === 'carryover').length,
      staleDebt: activeDebt.evidence.filter((item) => item.tier === 'stale').length,
      openedFeltSerious: countedOpenedFeltRows.length,
      verifiedFixed: verifiedFixed.length,
      unverifiedClosed: unverifiedClosed.length,
      unclassifiedIssues: unclassifiedIssues.length,
      targetEvidenceAttribution: postPublicationAttributions.length,
    },
    targetEvidenceAttribution: postPublicationAttributions.map(({ row, evidence }) => ({
      issueNumber: row.number,
      reasonCode: 'post_publication_exact_version_human_reproduction',
      releaseLocalEvidence: evidence,
      issue: {
        number: row.number,
        title: row.title,
        url: row.html_url,
        state: row.state,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        closedAt: row.closed_at,
        author: row.author,
        comments: row.comments,
        affectsVersion: row.affects_version ?? null,
      },
    })),
    debtSummary,
    verifiedDebt: activeDebt.evidence
      .filter((item) => item.tier === 'verified')
      .slice(0, 25)
      .map((item) => ({ ...item, issue: summarizeIssue(item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined) })),
    carryoverDebt: activeDebt.evidence
      .filter((item) => item.tier === 'carryover')
      .slice(0, 25)
      .map((item) => ({ ...item, issue: summarizeIssue(item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined) })),
    staleDebt: activeDebt.evidence
      .filter((item) => item.tier === 'stale')
      .slice(0, 25)
      .map((item) => ({ ...item, issue: summarizeIssue(item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined) })),
    openedFeltSerious: regressionOpenedRows
      .map((row, index) => ({ row, index, evidence: openedFeltAnalysis.evidence[index] }))
      .filter((item) => item.evidence?.counted === true)
      .slice(0, 25)
      .map((item) => ({ ...item.evidence, issue: summarizeIssue(item.row) })),
    verifiedFixed: verifiedFixed
      .slice(0, 25)
      .map((row) => {
        const issue = summarizeIssue(row);
        return issue
          ? {
              ...issue,
              fixCreditDecision: fixCreditDecisionByIssue.get(row.number) ?? null,
            }
          : null;
      })
      .filter(Boolean),
    unverifiedClosed: unverifiedClosed
      .slice(0, 25)
      .map((row) => summarizeIssue(row)),
    unclassifiedIssues: unclassifiedIssues.map((row) => ({
      number: row.number,
      title: row.title,
      url: row.html_url,
      state: row.state,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      closedAt: row.closed_at,
      author: row.author,
      comments: row.comments,
      labels: safeParseLabels(row.labels),
    })),
  };
  const labelTimeline = labelTimelineCoverage(
    [...attributed, ...openedReign, ...verifiedFixed, ...unverifiedClosed],
    labelInfo,
    labelCutoff,
  );
  const allReleaseCheckContexts = releaseCommit
    ? parseJsonArray(releaseCommit.check_contexts_json)
    : [];
  const releaseCheckContexts = releaseCommit
    ? releaseCheckContextsForEvidence(allReleaseCheckContexts, {
        state: releaseCommit.check_state,
        failure: releaseCommit.check_failure,
        pending: releaseCommit.check_pending,
      })
    : [];
  const releaseCheckContextCount = Number(releaseCommit?.check_total ?? 0);
  const gateEvidence = enrichGateEvidenceWithClosureProof(rel.tag, {
    schemaVersion: GATE_EVIDENCE_SCHEMA_VERSION,
    cve: {
      affected: cve.affected,
      load: cve.load,
    },
    stableTagsNewestFirst: args.stableTagsNewestFirst,
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    hoursToNextStable: rel.hours_to_next_stable,
    hasHotfixSuccessor: input.hasHotfixSuccessor,
    releaseChecks: releaseCommit ? {
      schemaVersion: RELEASE_CHECKS_SCHEMA_VERSION,
      state: releaseCommit.check_state,
      total: releaseCommit.check_total,
      success: releaseCommit.check_success,
      failure: releaseCommit.check_failure,
      pending: releaseCommit.check_pending,
      skipped: releaseCommit.check_skipped,
      contextCount: releaseCheckContextCount,
      shownContextCount: releaseCheckContexts.length,
      contextsTruncated: releaseCheckContexts.length < releaseCheckContextCount,
      contexts: releaseCheckContexts,
    } : null,
    artifactVerification: artifactScore.gate,
    labelTimeline,
    fixProvenance: {
      verifiedFixedCount: verifiedFixed.length,
      creditedFixedCount: introducedVerifiedFixed.length,
      unverifiedClosedCount: unverifiedClosedWithoutClosureProof.length,
      predecessorBoundary: {
        schemaVersion: 1,
        oldestScoredStableTag: args.oldestScoredStableTag,
        oldestScoredStablePredecessorTag: args.oldestScoredStablePredecessorTag,
        targetTag: rel.tag,
        predecessorTag: args.predecessorTag,
      },
    },
  }, closureProof);
  const scoreLedgerEvidenceSources: ScoreLedgerEvidenceSourceInput[] = [
    {
      key: 'release',
      refs: [{
        kind: 'release',
        identity: `release:${rel.tag}`,
        payload: {
          tag: rel.tag,
          publishedAt: rel.published_at,
          isLatest: input.isLatest,
          hoursToNextStable: input.hoursToNextStable,
          hasHotfixSuccessor: input.hasHotfixSuccessor,
          betaCount: input.betaCount,
          breakingCount: input.breakingCount,
        },
      }],
    },
    ...(['verified', 'carryover', 'stale'] as const).map((tier) => ({
      key: tier === 'verified' ? 'verifiedDebt' : tier === 'carryover' ? 'carryoverDebt' : 'staleDebt',
      refs: activeDebt.evidence
        .filter((item) => item.tier === tier)
        .map((item) => ({
          kind: 'issue',
          identity: `issue:${item.issueNumber ?? 'unknown'}:alias:${item.aliasGroup}`,
          payload: item,
        })),
    })),
    {
      key: 'closureRisk',
      refs: riskAccounting.closureRisk.groups.map((group) => ({
        kind: 'closure_group',
        identity: `closure:${group.key}`,
        payload: group,
      })),
    },
    {
      key: 'closureCeiling',
      refs: rawClosureRisk.groups.map((group) => ({
        kind: 'closure_group',
        identity: `closure:${group.key}`,
        payload: group,
      })),
    },
    {
      key: 'regressionOpened',
      refs: regressionOpenedRows
        .map((row, index) => ({ row, evidence: openedFeltAnalysis.evidence[index] }))
        .filter((item) => item.evidence?.counted === true)
        .map(({ row, evidence: item }) => ({
          kind: 'issue',
          identity: `issue:${row.number}:alias:${item.aliasGroup}`,
          payload: item,
        })),
    },
    {
      key: 'regressionFixed',
      refs: introducedVerifiedFixed.map((row) => ({
        kind: 'issue_fix',
        identity: `issue:${row.number}:fix-credit`,
        payload: {
          issueNumber: row.number,
          classification: feltInput(row),
          decision: fixCreditDecisionByIssue.get(row.number) ?? null,
        },
      })),
    },
    {
      key: 'coverage',
      refs: attributed.map((row) => ({
        kind: 'classification',
        identity: `issue:${row.number}:classification`,
        payload: {
          issueNumber: row.number,
          updatedAt: row.updated_at,
          classification: classify(row),
          classificationOrigin: row.classification_origin,
          classifierSourceIdentityDigest: row.source_identity_digest,
        },
      })),
    },
    {
      key: 'releaseChecks',
      refs: allReleaseCheckContexts.map((context, index) => {
        const row = context && typeof context === 'object' && !Array.isArray(context)
          ? context as Record<string, unknown>
          : {};
        return {
          kind: 'release_check',
          identity:
            `check:${index}:${String(row.name ?? row.context ?? row.type ?? 'unknown')}:` +
            `${String(row.url ?? '')}`,
          payload: context,
        };
      }),
    },
    {
      key: 'artifact',
      refs: artifactReceipt ? [{
        kind: 'artifact',
        identity: artifactReceipt.receiptId,
        digest: artifactReceipt.evidenceIdentity,
        payload: gateEvidence.artifactVerification,
      }] : [],
    },
    {
      key: 'advisories',
      refs: cve.advisories.map((advisory) => ({
        kind: 'advisory',
        identity: `advisory:${advisory.advisoryKey}`,
        payload: advisory,
      })),
    },
  ];
  const authorityReferences = [...authorityReferencesByIdentity.values()].sort(
    (left, right) =>
      left.subjectKind.localeCompare(right.subjectKind) ||
      left.subjectIdentity.localeCompare(right.subjectIdentity),
  );
  scoreLedgerEvidenceSources.push({
    key: 'scoreAuthority',
    refs: authorityReferences.map((reference) => ({
      kind: 'score_authority',
      identity:
        `${reference.subjectKind}:${reference.subjectIdentity}`,
      digest: scoreAuthorityReferenceDigest(reference),
    })),
  });
  const scoreLedger = buildScoreLedgerV2({
    input,
    confidence: conf,
    now: args.now,
    evidenceSources: scoreLedgerEvidenceSources,
    aliasElection: riskAccounting.ledger,
  });

  return {
    rel,
    scoredAt,
    analysisCompleteness: {
      complete: completenessDiagnostic.complete,
      missingClosureEvidence: completenessDiagnostic.missingClosureEvidence,
    },
    conf,
    input,
    authorityReferences,
    scoreLedger,
    explanation: {
      schemaVersion: SCORE_EXPLANATION_SCHEMA_VERSION,
      title: 'Why not 10?',
      scoreLedger,
      positives: [],
      positiveDetails: [],
      limits: [],
      limitDetails: [],
      verdict: '',
      authorityReferences,
    },
    debtEvidence,
    gateEvidence,
    neg,
    pos,
    openedSerious,
    closedSerious,
    brokenSurfaces,
  };
}

function buildScoreExplanation(
  result: ReleaseScoreResult,
  recommendation: RecommendationDecision | boolean,
): ScoreExplanation {
  const recommendationDecision = typeof recommendation === 'boolean'
    ? legacyRecommendationDecision(result, recommendation)
    : recommendation;
  const recommended = recommendationDecision.selected;
  const scoredAtMs = Date.parse(result.scoredAt);
  const publishedAtMs = Date.parse(result.input.publishedAt ?? '');
  const ledgerNow = Number.isFinite(scoredAtMs)
    ? scoredAtMs
    : Number.isFinite(publishedAtMs)
      ? publishedAtMs + 48 * 60 * 60 * 1000
      : 0;
  const scoreLedger = result.scoreLedger ?? buildScoreLedgerV2({
    input: result.input,
    confidence: installConfidence(result.input, ledgerNow),
    now: ledgerNow,
  });
  const evidence = result.debtEvidence as any;
  const gate = result.gateEvidence as any;
  const input = result.input;
  const components = (result.conf.components ?? {}) as Partial<Record<string, number>>;
  const opened = Array.isArray(evidence.openedFeltSerious) ? evidence.openedFeltSerious : [];
  const openedIssues = opened.map((item: any) => item?.issue).filter(Boolean);
  const openedStillOpen = openedIssues.filter((issue: any) => issue.state === 'open');
  const carryoverDebt = Array.isArray(evidence.carryoverDebt) ? evidence.carryoverDebt : [];
  const carryover = carryoverDebt
    .map((row: any) => row.issue)
    .filter(Boolean);
  const stale = Array.isArray(evidence.staleDebt) ? evidence.staleDebt : [];
  const verified = Array.isArray(evidence.verifiedDebt) ? evidence.verifiedDebt : [];
  const debtSummary = evidence.debtSummary ?? {};
  const limits: string[] = [];
  const limitDetails: ScoreExplanationDetail[] = [];
  const addLimit = (
    code: ScoreExplanationLimitCode,
    text: string,
    extra: Omit<ScoreExplanationDetail, 'code' | 'label' | 'text'> = {},
  ) => {
    limits.push(text);
    limitDetails.push({ code, text, ...extra, label: SCORE_EXPLANATION_DETAIL_LABELS[code] });
  };

  addInstallGateLimit(result, addLimit);

  if (opened.length) {
    const examples = openedStillOpen.length ? openedStillOpen : openedIssues;
    const example = issueListText(examples, 3);
    addLimit(
      'field_visible_reports_opened',
      `${opened.length} high-impact negative reports were opened in this release window; ${openedStillOpen.length} are still open.` +
      ` Their deduplicated opened weight is ${roundMetric(input.feltOpenedWeight)}.` +
      sentenceSuffix('Examples', example),
      {
        metrics: {
          openedCount: opened.length,
          stillOpenCount: openedStillOpen.length,
          closedCount: Math.max(0, opened.length - openedStillOpen.length),
          openedWeight: roundMetric(input.feltOpenedWeight),
        },
        issueRefs: issueRefs(examples, 5),
      },
    );
  }

  if ((input.verifiedDebtWeight ?? 0) > 0) {
    const verifiedIssues = verified
      .map((row: any) => row.issue)
      .filter(Boolean);
    const example = issueListText(verifiedIssues, 3);
    addLimit(
      'verified_field_blocker_debt',
      `There is verified field-blocker debt: release-local, field/community-confirmed high-impact issue evidence is still open. This contributes ${penaltyText(components.verifiedDebt)}; this category is capped at a ${SCORE_COMPONENT_LIMITS.verifiedDebtMaxPenalty} point penalty.` +
      sentenceSuffix('Top examples', example),
      {
        metrics: {
          count: Number(debtSummary.verified?.count ?? verified.length),
          storedExampleCount: verified.length,
          rawWeight: roundMetric(input.verifiedDebtWeight),
          storedExampleWeight: roundMetric(debtSummary.verified?.storedWeight ?? verified.reduce((sum: number, item: any) => sum + Number(item.weight ?? 0), 0)),
          cappedPenalty: Math.abs(numberOrZero(components.verifiedDebt)),
          maxPenalty: SCORE_COMPONENT_LIMITS.verifiedDebtMaxPenalty,
          capApplied: Math.abs(numberOrZero(components.verifiedDebt)) >= SCORE_COMPONENT_LIMITS.verifiedDebtMaxPenalty,
          byInstallImpactClass: debtSummary.verified?.byInstallImpactClass ?? {},
        },
        issueRefs: issueRefs(verified, 5),
      },
    );
  }

  if ((input.carryoverDebtWeight ?? 0) > 0) {
    const example = issueListText(carryover, 3);
    addLimit(
      'open_unconfirmed_issue_risk',
      `There are open inherited/carryover issue groups linked to this release, but they are not proven release-local blockers. They remain visible for audit and follow-up, contribute 0 score points, and cannot apply a score ceiling; backlog volume is not treated as release instability.` +
      sentenceSuffix('Top examples', example),
      {
        metrics: {
          count: Number(debtSummary.carryover?.count ?? carryoverDebt.length),
          storedExampleCount: carryoverDebt.length,
          rawWeight: roundMetric(input.carryoverDebtWeight),
          storedExampleWeight: roundMetric(debtSummary.carryover?.storedWeight ?? carryoverDebt.reduce((sum: number, item: any) => sum + Number(item.weight ?? 0), 0)),
          cappedPenalty: Math.abs(numberOrZero(components.carryoverDebt)),
          maxPenalty: SCORE_COMPONENT_LIMITS.carryoverDebtMaxPenalty,
          capApplied: false,
          scoreAffecting: false,
          byInstallImpactClass: debtSummary.carryover?.byInstallImpactClass ?? {},
        },
        issueRefs: issueRefs(carryoverDebt, 5),
      },
    );
  }

  if ((input.staleDebtWeight ?? 0) > 0) {
    const example = issueListText(stale.map((row: any) => row.issue).filter(Boolean), 3);
    addLimit(
      'stale_low_confidence_evidence',
      `${Number(debtSummary.stale?.count ?? stale.length)} weak, stale, or low-confidence evidence items are still tracked. This contributes ${penaltyText(components.staleDebt)}; this category is capped at a ${SCORE_COMPONENT_LIMITS.staleDebtMaxPenalty} point penalty.` +
      sentenceSuffix('Top examples', example),
      {
        metrics: {
          count: Number(debtSummary.stale?.count ?? stale.length),
          storedExampleCount: stale.length,
          rawWeight: roundMetric(input.staleDebtWeight),
          storedExampleWeight: roundMetric(debtSummary.stale?.storedWeight ?? stale.reduce((sum: number, item: any) => sum + Number(item.weight ?? 0), 0)),
          cappedPenalty: Math.abs(numberOrZero(components.staleDebt)),
          maxPenalty: SCORE_COMPONENT_LIMITS.staleDebtMaxPenalty,
          capApplied: Math.abs(numberOrZero(components.staleDebt)) >= SCORE_COMPONENT_LIMITS.staleDebtMaxPenalty,
          byInstallImpactClass: debtSummary.stale?.byInstallImpactClass ?? {},
        },
        issueRefs: issueRefs(stale, 5),
      },
    );
  }

  const missingClassificationCount = Math.max(0, Number(input.rawIssueCount ?? 0) - Number(input.classifiedIssueCount ?? 0));
  if (missingClassificationCount > 0) {
    const coveragePercent = Math.round((result.conf.evidenceCoverage ?? 0) * 100);
    const unclassified = Array.isArray(evidence.unclassifiedIssues) ? evidence.unclassifiedIssues : [];
    addLimit(
      'incomplete_classification_coverage',
      `Classification coverage is ${coveragePercent}% (${input.classifiedIssueCount}/${input.rawIssueCount}); ${missingClassificationCount} attributed issues lack current classification evidence.` +
      ` This contributes ${penaltyText(components.coverage)} until evidence is complete.`,
      {
        metrics: {
          rawIssueCount: Number(input.rawIssueCount ?? 0),
          classifiedIssueCount: Number(input.classifiedIssueCount ?? 0),
          missingClassificationCount,
          evidenceCoverage: roundMetric(result.conf.evidenceCoverage ?? 0),
          cappedPenalty: Math.abs(numberOrZero(components.coverage)),
        },
        issueRefs: issueRefs(unclassified, 5),
      },
    );
  }

  const fix = gate.fixProvenance ?? {};
  const closureProof = fix.closureProof;
  const missingClosureEvidence = result.analysisCompleteness?.missingClosureEvidence ?? [];
  if (missingClosureEvidence.length > 0) {
    const diagnosticText = missingClosureEvidence
      .slice(0, 5)
      .map((row) => `#${row.issueNumber} status=${row.status}`)
      .join(', ');
    addLimit(
      'incomplete_closure_evidence',
      `Closure analysis is incomplete: ${missingClosureEvidence.length} negative ` +
      `${missingClosureEvidence.length === 1 ? 'closure row has' : 'closure rows have'} ` +
      `missing_evidence (${diagnosticText}). Missing evidence contributes 0 closure-risk points ` +
      `and cannot apply a score ceiling; score persistence is refused until the evidence is resolved.`,
      {
        metrics: {
          count: missingClosureEvidence.length,
          potentialRiskWeight: roundMetric(missingClosureEvidence.reduce(
            (sum, row) => sum + row.potentialRiskWeight,
            0,
          )),
          contributesScorePoints: false,
          appliesScoreCeiling: false,
          analysisComplete: false,
        },
        buckets: Object.fromEntries(
          missingClosureEvidence.reduce((counts, row) => {
            counts.set(row.status, (counts.get(row.status) ?? 0) + 1);
            return counts;
          }, new Map<string, number>()),
        ),
        issueRefs: issueRefs(missingClosureEvidence.map((row) => ({
          number: row.issueNumber,
          title: row.title,
          status: row.status,
          riskDisposition: 'missing_evidence',
          riskWeight: 0,
        })), 5),
      },
    );
  }
  const unresolvedClosureCount = Number(input.unresolvedClosureIssueCount ?? 0);
  const unresolvedClosureWeight = Number(input.unresolvedClosureRiskWeight ?? 0);
  const affirmativeClosureCeilingWeight =
    Number(input.affirmativeClosureRiskCeilingWeight ?? 0);
  const closureCeiling = scoreLedger?.caps.find((cap) => cap.key === 'closureRiskCeiling');
  if (
    closureProof?.notCreditedCount > 0 &&
    (
      unresolvedClosureCount > 0 ||
      unresolvedClosureWeight > 0 ||
      affirmativeClosureCeilingWeight > 0
    )
  ) {
    const bucketText = closureProofSummaryText(closureProof);
    const riskText = closureRiskSummaryText(closureProof);
    const buckets = proofBucketsExceptFixed(closureProof.byStatus);
    const riskBuckets = proofBucketsExceptFixed(closureProof.byRiskDisposition, [
      'credited_release_fix',
      'resolved_by_canonical_release_fix',
      'resolved_by_release_fix_proof',
      'neutral_or_non_actionable',
    ]);
    const riskSummary = closureProof.riskSummary ?? {};
    const rawUnresolvedClosureCount = Number(riskSummary.unresolvedForReleaseCount ?? 0);
    const closureExamples = closureProofExamplesForExplanation(closureProof, 5);
    const closureIssueRefs = issueRefs(closureExamples, 5);
    addLimit(
      'closed_issues_not_counted_as_release_fixes',
      `${unresolvedClosureCount} deduplicated closed-issue risk groups contribute to this score, with scored risk weight ${roundMetric(unresolvedClosureWeight)}.` +
      ` The separate deduplicated affirmative closure-risk ceiling weight is ${roundMetric(affirmativeClosureCeilingWeight)}; alias groups retained in verified or stale debt can still limit the score without receiving a second closure penalty.` +
      ` Separately, the raw closure-proof audit contains ${rawUnresolvedClosureCount} unresolved groups across ${closureProof.notCreditedCount} closed issues without direct release-fix credit; ${closureProof.analyzedClosedCount} closed issues were analyzed.` +
      ` The scored contribution is ${penaltyText(components.closureRisk)} and is capped at a ${SCORE_COMPONENT_LIMITS.closureRiskMaxPenalty} point penalty.` +
      (closureCeiling?.applied
        ? ` Because affirmative closure-risk ceiling weight is ${roundMetric(affirmativeClosureCeilingWeight)}, the final score is capped at ${components.closureRiskCeiling}.`
        : '') +
      (riskText ? ` Raw unresolved proof categories: ${riskText}.` : '') +
      (bucketText ? ` Raw proof statuses: ${bucketText}.` : ''),
      {
        metrics: {
          countedClosedCount: Number(closureProof.creditedCount ?? 0),
          scoredUnresolvedRiskGroupCount: unresolvedClosureCount,
          scoredUnresolvedRiskWeight: roundMetric(unresolvedClosureWeight),
          affirmativeClosureRiskCeilingWeight:
            roundMetric(affirmativeClosureCeilingWeight),
          rawUnresolvedRiskGroupCount: rawUnresolvedClosureCount,
          rawNotCountedClosedIssueCount: Number(closureProof.notCreditedCount ?? 0),
          rawAnalyzedClosedIssueCount: Number(closureProof.analyzedClosedCount ?? 0),
          cappedPenalty: Math.abs(numberOrZero(components.closureRisk)),
          maxPenalty: SCORE_COMPONENT_LIMITS.closureRiskMaxPenalty,
          capApplied: closureCeiling?.applied === true,
          scoreCeiling: Number(components.closureRiskCeiling ?? 0) || null,
          noticeableClosureRiskThreshold: SCORE_COMPONENT_LIMITS.noticeableClosureRiskThreshold,
          noticeableClosureScoreCap: SCORE_COMPONENT_LIMITS.noticeableClosureScoreCap,
          heavyClosureRiskThreshold: SCORE_COMPONENT_LIMITS.heavyClosureRiskThreshold,
          resolvedByCanonicalReleaseFixCount: Number(riskSummary.resolvedByCanonicalReleaseFixCount ?? 0),
          resolvedByReleaseFixProofCount: Number(riskSummary.resolvedByReleaseFixProofCount ?? 0),
          knownNotInReleaseCount: Number(riskSummary.knownNotInReleaseCount ?? 0),
          openCanonicalRiskCount: Number(riskSummary.openCanonicalRiskCount ?? 0),
          unsupportedClosureClaimCount: Number(riskSummary.unsupportedClosureClaimCount ?? 0),
          neutralOrNonActionableCount: Number(riskSummary.neutralOrNonActionableCount ?? 0),
          neutralHighImpactCount: Number(riskSummary.neutralHighImpactCount ?? 0),
          neutralBugShapedCount: Number(riskSummary.neutralBugShapedCount ?? 0),
          missingEvidenceCount: Number(riskSummary.missingEvidenceCount ?? 0),
        },
        buckets,
        riskBuckets,
        issueRefs: closureIssueRefs,
      },
    );
  } else if (missingClosureEvidence.length === 0 && (fix.unverifiedClosedCount ?? 0) > 0) {
    addLimit(
      'unverified_closed_fix_reachability',
      `${fix.unverifiedClosedCount} closed issues are not counted as fixes yet because release-tag reachability has not been analyzed for them.`,
      { metrics: { unverifiedClosedCount: Number(fix.unverifiedClosedCount ?? 0) } },
    );
  }

  const artifact = gate.artifactVerification;
  const artifactLimit = artifactVerificationLimit(artifact);
  if (result.conf.score !== 10 && artifactLimit) {
    addLimit(
      'artifact_verification_incomplete',
      artifactLimit.text,
      { metrics: artifactLimit.metrics },
    );
  }
  if (result.conf.score !== 10 && artifact?.ciReportVerified !== true) {
    const reportReason =
      artifact?.ciReportMismatch ??
      artifact?.evidenceReport?.mismatch ??
      'no verified full release evidence report is bound to this score';
    addLimit(
      'missing_full_release_evidence_report',
      `The full release evidence report is not verified: ${reportReason}.` +
        (artifact?.verified
          ? ' The npm tarball byte and release-binding checks passed separately.'
          : ''),
      {
        metrics: {
          ciReportVerified: false,
          ciReportMismatch: artifact?.ciReportMismatch ?? null,
          evidenceReportMismatch: artifact?.evidenceReport?.mismatch ?? null,
        },
      },
    );
  }

  const checks = gate.releaseChecks;
  const checkState = String(checks?.state ?? '').toUpperCase();
  const checkFailure = Number(checks?.failure ?? 0);
  const checkPending = Number(checks?.pending ?? 0);
  const checkSuccess = Number(checks?.success ?? 0);
  const checkTotal = Number(checks?.total ?? 0);
  const releaseChecksFailed =
    checkFailure > 0 ||
    ['FAILURE', 'ERROR', 'ACTION_REQUIRED'].includes(checkState);
  const releaseChecksPending = !releaseChecksFailed &&
    (checkPending > 0 || ['PENDING', 'EXPECTED'].includes(checkState));
  if (releaseChecksFailed) {
    addLimit(
      'release_checks_failed',
      `${checkFailure} release checks failed or the aggregate release-check state is ${checkState || 'unknown'}; this reduces audited install confidence.`,
      {
        metrics: {
          state: checkState || null,
          total: checkTotal,
          success: checkSuccess,
          failure: checkFailure,
          pending: checkPending,
        },
      },
    );
  } else if (releaseChecksPending) {
    addLimit(
      'release_checks_pending',
      `${checkPending} release checks are pending or the aggregate release-check state is ${checkState || 'pending'}; confidence remains limited until they finish.`,
      {
        metrics: {
          state: checkState || null,
          total: checkTotal,
          success: checkSuccess,
          failure: checkFailure,
          pending: checkPending,
        },
      },
    );
  }

  if (!limits.length && !verified.length && result.conf.status === 'eligible' && result.conf.score === 10) {
    addLimit(
      'no_remaining_score_gap',
      'The audited install confidence is exactly 10.0; no score gap remains under the current model.',
      { metrics: { finalScore: 10 } },
    );
  } else if (!limits.length && !verified.length && result.conf.status === 'eligible') {
    addLimit(
      'model_ceiling_and_capped_confidence',
      'No field-blocker evidence is currently holding this release down; the remaining gap comes from the model ceiling and capped confidence signals.',
    );
  }

  addScoreRoundingContext(scoreLedger, addLimit);

  const positives: string[] = [];
  const positiveDetails: ScoreExplanationDetail[] = [];
  const addPositive = (
    code: ScoreExplanationPositiveCode,
    text: string,
    extra: Omit<ScoreExplanationDetail, 'code' | 'label' | 'text'> = {},
  ) => {
    positives.push(text);
    positiveDetails.push({ code, text, ...extra, label: SCORE_EXPLANATION_DETAIL_LABELS[code] });
  };
  if (!verified.length) {
    addPositive(
      'no_verified_field_blocker_debt',
      'No verified field-blocker debt is currently scoring against this release.',
      { metrics: { verifiedDebtCount: verified.length } },
    );
  }
  if (!releaseChecksFailed && !releaseChecksPending && checkState === 'SUCCESS' && checkSuccess > 0) {
    const skipped = Math.max(0, checkTotal - checkSuccess - checkFailure - checkPending);
    addPositive(
      'release_checks_passed',
      `${checkSuccess} of ${checkTotal} release checks passed; none failed or are pending${skipped > 0 ? `, and ${skipped} ${skipped === 1 ? 'was' : 'were'} skipped` : ''}.`,
      {
        metrics: {
          state: checkState,
          total: checkTotal,
          success: checkSuccess,
          failure: checkFailure,
          pending: checkPending,
          skipped,
        },
      },
    );
  }
  if (artifact?.verified && artifact.releaseShaMatches === true) {
    const text =
      'The downloaded npm tarball bytes match the registry SRI digest, the release metadata identifies that exact tarball, and the retained release binding matches the release tag commit.';
    addPositive(
      'artifact_verified',
      text,
      {
        metrics: {
          artifactVerified: true,
          releaseShaMatches: artifact.releaseShaMatches === true,
          ciReportVerified: artifact.ciReportVerified === true,
          releaseValidationVerified: artifact.releaseValidationVerified === true,
        },
      },
    );
  }
  if (recommended) {
    addPositive('release_recommended', humanRecommendationDecisionSummary(recommendationDecision));
  } else if (result.conf.status === 'eligible') {
    addPositive('hard_gates_passed', 'The release passed install eligibility checks.');
  }

  const explanation = {
    schemaVersion: SCORE_EXPLANATION_SCHEMA_VERSION,
    title: 'Why not 10?',
    scoreLedger,
    positives,
    positiveDetails,
    limits,
    limitDetails,
    verdict: installVerdictText(result, recommendationDecision),
    recommendationDecision,
    authorityReferences: result.authorityReferences,
  };
  const auditedScoreLedger = bindScoreExplanationAudit(scoreLedger, explanation);
  return {
    ...explanation,
    scoreLedger: auditedScoreLedger,
  };
}

function artifactVerificationLimit(artifact: any): {
  text: string;
  metrics: Record<string, string | number | boolean | null>;
} | null {
  const evidence = artifact?.artifact;
  const metrics = {
    proofPresent: artifact?.receiptId != null,
    state: evidence?.state ?? null,
    registryState: evidence?.registryState ?? null,
    releaseBindingState: evidence?.releaseBindingState ?? null,
    registryAvailability: evidence?.registryAvailability ?? null,
    registryVerified: evidence?.registryVerified === true,
    releaseBound: evidence?.releaseBound === true,
    releaseShaMatches: artifact?.releaseShaMatches ?? null,
    tarballByteCount: evidence?.tarballByteCount ?? null,
    reason: evidence?.reason ?? null,
    mismatch: evidence?.mismatch ?? artifact?.mismatch ?? null,
  };
  if (!artifact?.receiptId) {
    return {
      text:
        'No immutable artifact observation is bound to this score, so the npm tarball bytes, registry SRI digest, release metadata, and release tag binding have not been independently verified.',
      metrics,
    };
  }
  if (artifact.releaseShaMatches !== true) {
    return {
      text:
        'The retained artifact receipt does not prove that its canonical release commit is the same commit currently being scored, so artifact confidence credit is withheld.',
      metrics,
    };
  }
  if (evidence?.registryState === 'mismatch' || evidence?.state === 'mismatch') {
    return {
      text:
        `The npm artifact verification found a mismatch: ${
          evidence?.mismatch ?? evidence?.reason ?? artifact?.mismatch ?? 'details unavailable'
        }.`,
      metrics,
    };
  }
  if (evidence?.registryState === 'unavailable') {
    return {
      text:
        `The npm registry artifact was unavailable, so its tarball bytes and SRI digest could not be verified${
          evidence?.reason ? `: ${evidence.reason}` : ''
        }.`,
      metrics,
    };
  }
  if (
    evidence?.registryState === 'unknown' ||
    evidence?.registryAvailability === 'unknown'
  ) {
    return {
      text:
        `The npm artifact state is unknown, so registry-byte verification cannot contribute confidence${
          evidence?.reason ? `: ${evidence.reason}` : ''
        }.`,
      metrics,
    };
  }
  if (
    evidence?.registryVerified === true &&
    evidence?.releaseBindingState !== 'release_bound'
  ) {
    return {
      text:
        `The npm tarball bytes match the registry SRI digest, but they are not fully bound to the release metadata and tag commit${
          evidence?.reason ? `: ${evidence.reason}` : ''
        }.`,
      metrics,
    };
  }
  if (artifact?.verified !== true) {
    return {
      text:
        `Artifact verification is incomplete${
          evidence?.reason ?? artifact?.mismatch
            ? `: ${evidence?.reason ?? artifact?.mismatch}`
            : ''
        }.`,
      metrics,
    };
  }
  return null;
}

function legacyRecommendationDecision(
  result: ReleaseScoreResult,
  selected: boolean,
): RecommendationDecision {
  const releaseTag = result.rel?.tag ?? 'unknown';
  const decision: RecommendationDecision = {
    schemaVersion: 1,
    policyCode: 'highest_confidence_with_recency_tolerance',
    threshold: REC_THRESHOLD,
    recencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
    selectedTag: selected ? releaseTag : null,
    selectedScore: selected ? result.conf.score : null,
    highestScoringTag: selected ? releaseTag : null,
    highestScore: selected ? result.conf.score : null,
    releaseTag,
    releaseScore: result.conf.score,
    qualifies: result.conf.status === 'eligible' && result.conf.score != null && result.conf.score >= REC_THRESHOLD,
    selected,
    recencyRank: 1,
    scoreRank: result.conf.score == null ? null : 1,
    scoreDeltaToHighest: selected ? 0 : null,
    decisionCode: selected ? 'highest_confidence' : result.conf.status === 'eligible'
      ? 'below_recommendation_threshold'
      : 'install_gate_active',
    summary: '',
  };
  decision.summary = recommendationDecisionSummary(decision);
  return decision;
}

function issueRefs(items: any[], limit = 2): ScoreExplanationIssueRef[] {
  return items
    .slice(0, limit)
    .map((item) => ({
      number: Number(item?.number ?? item?.issue?.number),
      title: shortIssueTitle(item?.issue ?? item),
      url: item?.url ?? item?.issue?.url ?? null,
      state: item?.state ?? item?.issue?.state ?? null,
      status: item?.status ?? null,
      tier: item?.tier ?? null,
      weight: typeof item?.weight === 'number' ? roundMetric(item.weight) : null,
      fieldConfirmed: typeof item?.fieldConfirmed === 'boolean' ? item.fieldConfirmed : null,
      confirmationReasons: Array.isArray(item?.confirmationReasons)
        ? item.confirmationReasons
        : [],
      releaseLocal: typeof item?.clusterReleaseLocal === 'boolean' ? item.clusterReleaseLocal : null,
      releaseLocalEvidence: item?.releaseLocalEvidence ?? null,
      releaseScopedState: typeof item?.releaseScopedState === 'string' ? item.releaseScopedState : null,
      scoringReason: issueRefScoringReason(item),
      installImpactClass: item?.installImpactClass ?? null,
      installImpactMultiplier: typeof item?.installImpactMultiplier === 'number' ? roundMetric(item.installImpactMultiplier) : null,
      proof: issueRefProof(item),
    }))
    .filter((item) => Number.isInteger(item.number) && item.number > 0 && item.title.length > 0);
}

function issueRefScoringReason(item: any): string | null {
  const tier = String(item?.tier ?? '');
  if (tier === 'verified') return 'Exact-version release-local field/community-confirmed blocker evidence.';
  if (tier === 'stale') {
    return hasSourceOnlyEvidenceLabel(item)
      ? 'Source/static reproduction without semantic human confirmation; retained as separately capped weak evidence.'
      : 'Weak, stale, low-confidence, low-severity, or needs-info evidence; capped separately from hard blocker debt.';
  }
  if (tier !== 'carryover') return null;

  const releaseLocal = typeof item?.clusterReleaseLocal === 'boolean' ? item.clusterReleaseLocal : null;
  const fieldConfirmed = typeof item?.fieldConfirmed === 'boolean' ? item.fieldConfirmed : null;
  const sourceOnly = hasSourceOnlyEvidenceLabel(item);
  if (releaseLocal === false && fieldConfirmed === true) {
    return 'Has field/community discussion, but lacks independent exact release-version evidence for hard blocker debt.';
  }
  if (releaseLocal === false) {
    return 'Overlaps this release, but lacks independent exact release-version evidence for hard blocker debt.';
  }
  if (sourceOnly && fieldConfirmed !== true) {
    return 'Source/static reproduction only; not field-confirmed as installed-release breakage.';
  }
  if (fieldConfirmed === false) {
    return 'Open negative issue, but not field-confirmed as installed-release breakage.';
  }
  return 'Open negative issue overlapping this release, but not enough evidence to count as hard release-local blocker debt.';
}

function hasSourceOnlyEvidenceLabel(item: any): boolean {
  const issue = item?.issue && typeof item.issue === 'object' ? item.issue : item;
  const labels = Array.isArray(issue?.labels) ? issue.labels : [];
  return labels.some((label: unknown) => label === 'clawsweeper:source-repro' || label === 'clawsweeper:current-main-repro');
}

function issueRefProof(item: any): ScoreExplanationIssueProof | null {
  const status = typeof item?.status === 'string' && item.status ? item.status : null;
  const summary = typeof item?.summary === 'string' && item.summary ? item.summary : null;
  const riskDisposition = typeof item?.riskDisposition === 'string' && item.riskDisposition
    ? item.riskDisposition
    : status ? closureRiskDisposition(status) : null;
  const evidence = item?.evidence && typeof item.evidence === 'object' ? item.evidence : {};
  const canonicalResolution = evidence.canonicalResolution && typeof evidence.canonicalResolution === 'object'
    ? evidence.canonicalResolution
    : null;
  const canonicalIssue = linkedIssueRef(canonicalResolution?.terminalIssue) ??
    linkedIssueRef(Array.isArray(evidence.canonicalIssueDetails) ? evidence.canonicalIssueDetails[0] : null);
  const canonicalPath = Array.isArray(canonicalResolution?.path)
    ? canonicalResolution.path.filter((number: unknown): number is number => Number.isInteger(number) && Number(number) > 0)
    : null;
  const relatedPrContext = evidence.relatedPrContext && typeof evidence.relatedPrContext === 'object'
    ? evidence.relatedPrContext
    : {};
  const openPrs = linkedRefs([
    ...(Array.isArray(evidence.canonicalOpenPrs) ? evidence.canonicalOpenPrs : []),
    ...(Array.isArray(evidence.relatedOpenPrs) ? evidence.relatedOpenPrs : []),
    ...(Array.isArray(relatedPrContext.open) ? relatedPrContext.open : []),
  ], 3);
  const reachablePrs = linkedRefs(Array.isArray(relatedPrContext.reachable) ? relatedPrContext.reachable : [], 3);
  const notReachablePrs = linkedRefs(Array.isArray(relatedPrContext.notReachable) ? relatedPrContext.notReachable : [], 3);
  const unknownReachabilityPrs = linkedRefs(
    Array.isArray(relatedPrContext.unknownReachability) ? relatedPrContext.unknownReachability : [],
    3,
  );
  const closedUnmergedPrs = linkedRefs(
    Array.isArray(relatedPrContext.closedUnmerged) ? relatedPrContext.closedUnmerged : [],
    3,
  );
  const externalClosingPrs = linkedRefs(
    Array.isArray(relatedPrContext.externalClosing) ? relatedPrContext.externalClosing : [],
    3,
  );
  const riskWeight = typeof item?.riskWeight === 'number' ? roundMetric(item.riskWeight) : null;
  if (!status && !summary && !riskDisposition && riskWeight == null && !canonicalIssue &&
    !openPrs.length && !reachablePrs.length && !notReachablePrs.length &&
    !unknownReachabilityPrs.length && !closedUnmergedPrs.length && !externalClosingPrs.length) {
    return null;
  }
  return {
    status,
    statusLabel: status ? closureStatusLabel(status) : null,
    riskDisposition,
    riskDispositionLabel: riskDisposition ? closureRiskDispositionLabel(riskDisposition) : null,
    summary,
    riskWeight,
    canonicalIssue,
    canonicalPath,
    openPrs,
    reachablePrs,
    notReachablePrs,
    unknownReachabilityPrs,
    closedUnmergedPrs,
    externalClosingPrs,
  };
}

function linkedRefs(values: unknown[], limit: number): ScoreExplanationLinkedRef[] {
  const seen = new Set<string>();
  const refs: ScoreExplanationLinkedRef[] = [];
  for (const value of values) {
    const ref = linkedIssueRef(value);
    if (!ref) continue;
    const key = `${ref.repositoryNameWithOwner ?? ''}#${ref.number}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push(ref);
    if (refs.length >= limit) break;
  }
  return refs;
}

function linkedIssueRef(value: unknown): ScoreExplanationLinkedRef | null {
  if (!value || typeof value !== 'object') return null;
  const raw = value as any;
  const number = Number(raw.number ?? raw.issueNumber ?? raw.prNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : typeof raw.html_url === 'string' ? raw.html_url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
    status: typeof raw.reachabilityStatus === 'string' ? raw.reachabilityStatus : typeof raw.status === 'string' ? raw.status : null,
    repositoryNameWithOwner: typeof raw.repositoryNameWithOwner === 'string' ? raw.repositoryNameWithOwner : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    merged: raw.merged === true || raw.merged === 1
      ? true
      : raw.merged === false || raw.merged === 0
        ? false
        : null,
    mergedAt: typeof raw.mergedAt === 'string' ? raw.mergedAt : null,
    referencedAt: typeof raw.referencedAt === 'string' ? raw.referencedAt : null,
    willCloseTarget: raw.willCloseTarget === true || raw.willCloseTarget === 1
      ? true
      : raw.willCloseTarget === false || raw.willCloseTarget === 0
        ? false
        : null,
    reachabilityMethod: typeof raw.reachabilityMethod === 'string' ? raw.reachabilityMethod : null,
    mergeCommitOid: typeof raw.mergeCommitOid === 'string' ? raw.mergeCommitOid : null,
    sourceCommentUrl: typeof raw.sourceCommentUrl === 'string' ? raw.sourceCommentUrl : null,
  };
}

function closureProofExamplesWithStatusCoverage(closureProof: any): any[] {
  const seen = new Set<number>();
  const merged: any[] = [];
  const add = (item: any) => {
    const number = Number(item?.number ?? item?.issue?.number);
    if (!Number.isInteger(number) || number <= 0 || seen.has(number)) return;
    seen.add(number);
    merged.push(item);
  };
  for (const item of closureProof?.examples ?? []) add(item);
  const examplesByStatus = closureProof?.examplesByStatus ?? {};
  if (examplesByStatus && typeof examplesByStatus === 'object') {
    for (const examples of Object.values(examplesByStatus)) {
      if (!Array.isArray(examples)) continue;
      for (const item of examples) add(item);
    }
  }
  return merged;
}

const CLOSURE_EXPLANATION_DISPOSITION_ORDER = [
  'open_canonical_risk',
  'known_not_in_release',
  'unsupported_closure_claim',
  'missing_evidence',
];
const CLOSURE_EXPLANATION_RISK_DISPOSITIONS = new Set(CLOSURE_EXPLANATION_DISPOSITION_ORDER);

const CLOSURE_EXPLANATION_STATUS_PREFERENCE: Record<string, string[]> = {
  open_canonical_risk: [
    'duplicate_to_open_canonical',
    'duplicate_to_open_pr_canonical',
    'superseded_to_open_pr',
    'duplicate_with_open_pr_context',
    'not_planned_with_open_pr_context',
    'linked_closing_pr_open',
    'related_open_pr_context',
  ],
  known_not_in_release: [
    'fixed_after_latest_release',
    'fixed_in_later_release',
    'fixed_after_release',
    'fixed_not_in_scored_releases',
    'main_only_claim',
    'duplicate_to_known_not_in_release_canonical',
  ],
  unsupported_closure_claim: [
    'admin_not_planned_no_context',
    'admin_not_planned_unverified',
    'already_present_claim',
    'closed_without_release_fix_proof',
    'no_code_proof',
    'duplicate_or_superseded',
    'repro_requested',
    'insufficient_info',
  ],
  missing_evidence: [
    'not_planned_direct_fix_commit_reachability_unknown',
    'direct_fix_commit_reachability_unknown',
    'no_timeline_event',
    'unknown',
    'linked_closing_pr_reachability_unknown',
    'duplicate_to_closed_canonical_missing_proof',
  ],
  resolved_by_release_fix_proof: [
    'duplicate_with_release_fix_proof',
    'not_planned_with_release_fix_proof',
  ],
};

function closureProofExamplesForExplanation(closureProof: any, limit: number): any[] {
  const cap = Math.max(0, limit);
  if (cap <= 0) return [];
  const candidates = closureProofExamplesWithStatusCoverage(closureProof)
    .filter((item: any) => {
      if (item.status === 'fixed_in_release') return false;
      const disposition = typeof item?.riskDisposition === 'string' && item.riskDisposition
        ? item.riskDisposition
        : typeof item?.status === 'string' ? closureRiskDisposition(item.status) : null;
      return typeof disposition === 'string' && CLOSURE_EXPLANATION_RISK_DISPOSITIONS.has(disposition);
    });
  const selected: any[] = [];
  const seen = new Set<number>();
  const add = (item: any) => {
    const number = Number(item?.number ?? item?.issue?.number);
    if (!Number.isInteger(number) || number <= 0 || seen.has(number) || selected.length >= cap) return;
    seen.add(number);
    selected.push(item);
  };
  const byDisposition = new Map<string, any>();
  for (const item of candidates) {
    const disposition = typeof item?.riskDisposition === 'string' && item.riskDisposition
      ? item.riskDisposition
      : typeof item?.status === 'string' ? closureRiskDisposition(item.status) : null;
    if (disposition && !byDisposition.has(disposition)) byDisposition.set(disposition, item);
  }
  const dispositionCounts = closureProof?.byRiskDisposition && typeof closureProof.byRiskDisposition === 'object'
    ? closureProof.byRiskDisposition
    : {};
  for (const disposition of CLOSURE_EXPLANATION_DISPOSITION_ORDER) {
    if (Number(dispositionCounts[disposition] ?? 0) > 0) {
      add(preferredClosureExampleForDisposition(disposition, candidates) ?? byDisposition.get(disposition));
    }
  }
  for (const [disposition, count] of Object.entries(dispositionCounts)) {
    if (CLOSURE_EXPLANATION_DISPOSITION_ORDER.includes(disposition)) continue;
    if (!CLOSURE_EXPLANATION_RISK_DISPOSITIONS.has(disposition)) continue;
    if (Number(count ?? 0) > 0) {
      add(preferredClosureExampleForDisposition(disposition, candidates) ?? byDisposition.get(disposition));
    }
  }
  for (const item of candidates) add(item);
  return selected;
}

function preferredClosureExampleForDisposition(disposition: string, candidates: any[]): any | null {
  const preferredStatuses = CLOSURE_EXPLANATION_STATUS_PREFERENCE[disposition] ?? [];
  for (const status of preferredStatuses) {
    const match = candidates.find((item) => item?.status === status && (
      item?.riskDisposition === disposition || closureRiskDisposition(String(item?.status ?? '')) === disposition
    ));
    if (match) return match;
  }
  return null;
}

function debtTierSummary(items: any[], tier: 'verified' | 'carryover' | 'stale'): {
  count: number;
  weight: number;
  storedWeight: number;
  byInstallImpactClass: Record<string, number>;
} {
  const tierItems = items.filter((item) => item.tier === tier);
  const byInstallImpactClass: Record<string, number> = {};
  for (const item of tierItems) {
    const key = String(item.installImpactClass ?? 'unknown');
    byInstallImpactClass[key] = (byInstallImpactClass[key] ?? 0) + 1;
  }
  return {
    count: tierItems.length,
    weight: roundMetric(tierItems.reduce((sum, item) => sum + Number(item.weight ?? 0), 0)),
    storedWeight: roundMetric(tierItems.slice(0, 25).reduce((sum, item) => sum + Number(item.weight ?? 0), 0)),
    byInstallImpactClass,
  };
}

function classificationDiff(
  raw: IssueClassification,
  effective: IssueClassification,
): Record<string, { raw: unknown; effective: unknown }> {
  const out: Record<string, { raw: unknown; effective: unknown }> = {};
  const keys: Array<keyof IssueClassification> = [
    'sentiment',
    'severity',
    'scope',
    'functionality',
    'affectedUsers',
    'hasWorkaround',
    'workaroundStatus',
    'duplicateCluster',
    'affectsVersion',
    'confidence',
  ];
  for (const key of keys) {
    if (raw[key] !== effective[key]) out[key] = { raw: raw[key], effective: effective[key] };
  }
  return out;
}

function labelTimelineCoverage(
  rows: JoinedIssue[],
  labelInfo: (row: JoinedIssue) => {
    labels: string[];
    scoringLabels: string[];
    currentLabels: string[];
    timelineEventCount: number;
    source: 'current' | 'timeline' | 'snapshot' | 'missing_timeline';
  },
  cutoffAt: string | null,
): Record<string, unknown> {
  const byIssue = new Map<number, JoinedIssue>();
  for (const row of rows) byIssue.set(row.number, row);
  let current = 0;
  let timeline = 0;
  let snapshot = 0;
  let missingTimeline = 0;
  let missingTimelineWithCurrentLabels = 0;
  for (const row of byIssue.values()) {
    const info = labelInfo(row);
    if (info.source === 'current') current++;
    else if (info.source === 'timeline') timeline++;
    else if (info.source === 'snapshot') snapshot++;
    else {
      missingTimeline++;
      if (info.currentLabels.length > 0) missingTimelineWithCurrentLabels++;
    }
  }
  return {
    schemaVersion: LABEL_TIMELINE_SCHEMA_VERSION,
    cutoffAt,
    issueCount: byIssue.size,
    currentLabelCount: current,
    timelineLabelCount: timeline,
    snapshotLabelCount: snapshot,
    missingTimelineCount: missingTimeline,
    missingTimelineWithCurrentLabelsCount: missingTimelineWithCurrentLabels,
    historicalCurrentLabelFallbackAllowed: cutoffAt == null,
  };
}

function proofBucketsExceptFixed(buckets: unknown, fixedKey: string | string[] = 'fixed_in_release'): Record<string, number> {
  if (!buckets || typeof buckets !== 'object' || Array.isArray(buckets)) return {};
  const fixedKeys = new Set(Array.isArray(fixedKey) ? fixedKey : [fixedKey]);
  const entries = Object.entries(buckets as Record<string, unknown>)
    .filter(([status]) => !fixedKeys.has(status))
    .map(([status, count]) => [status, Number(count)] as const)
    .filter(([, count]) => Number.isFinite(count) && count > 0);
  return Object.fromEntries(entries);
}

function isAdverseClosureRiskDisposition(disposition: string): boolean {
  return [
    'known_not_in_release',
    'open_canonical_risk',
    'unsupported_closure_claim',
    'missing_evidence',
  ].includes(disposition);
}

function numberOrZero(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function mergeMissingClosureEvidence(
  ...groups: MissingClosureEvidenceDiagnostic[][]
): MissingClosureEvidenceDiagnostic[] {
  const byIdentity = new Map<string, MissingClosureEvidenceDiagnostic>();
  for (const row of groups.flat()) {
    const key = `${row.issueNumber}:${row.status}`;
    const previous = byIdentity.get(key);
    if (!previous || row.potentialRiskWeight > previous.potentialRiskWeight) {
      byIdentity.set(key, row);
    }
  }
  return [...byIdentity.values()].sort((left, right) =>
    left.issueNumber - right.issueNumber ||
    left.status.localeCompare(right.status)
  );
}

function roundMetric(value: unknown): number {
  return Math.round(numberOrZero(value) * 1000) / 1000;
}

function releaseAgeHoursAtScore(publishedAt: string | null, scoredAt: string): number | null {
  const published = publishedAt ? Date.parse(publishedAt) : NaN;
  const scored = Date.parse(scoredAt);
  return Number.isFinite(published) && Number.isFinite(scored)
    ? roundMetric((scored - published) / 3_600_000)
    : null;
}

function installVerdictText(result: ReleaseScoreResult, decision: RecommendationDecision): string {
  const status = result.conf.status;
  const summary = humanRecommendationDecisionSummary(decision);
  if (decision.selected) {
    if (result.conf.score === 10) {
      return `${summary} The audited install confidence is exactly 10.0 under the current model; no score gap remains.`;
    }
    return `${summary} The audited limits above explain why the score remains below 10.`;
  }
  if (status === 'eligible') {
    return summary;
  }
  return `${summary} The limiting reason is ${installGateReason(result)}.`;
}

function addScoreRoundingContext(
  scoreLedger: ScoreLedgerV2,
  addLimit: (
    code: ScoreExplanationLimitCode,
    text: string,
    extra?: Omit<ScoreExplanationDetail, 'code' | 'label' | 'text'>,
  ) => void,
): void {
  const rounding = scoreLedger.operations.find((operation) =>
    operation.code === 'finalRound' &&
    operation.kind === 'round' &&
    operation.formulaCode === 'score.round_1_decimal.v1'
  );
  if (rounding?.before == null || rounding.after == null) return;

  const componentSubtotal = roundMetric(rounding.before);
  const finalScore = roundMetric(rounding.after);
  addLimit(
    'score_rounding',
    `Rounds the three-decimal component subtotal to the one-decimal final score: ` +
      `${componentSubtotal.toFixed(3)} to ${finalScore.toFixed(1)}. ` +
      'Any score ceilings are applied before this operation.',
    {
      metrics: {
        scoreAffecting: false,
        operationCode: rounding.code,
        operationSequence: rounding.sequence,
        formulaCode: rounding.formulaCode,
        componentSubtotal,
        finalScore,
        sourcePrecisionDecimals: 3,
        finalPrecisionDecimals: 1,
        roundingChangedScore: rounding.applied,
      },
    },
  );
}

function addInstallGateLimit(
  result: ReleaseScoreResult,
  addLimit: (
    code: ScoreExplanationLimitCode,
    text: string,
    extra?: Omit<ScoreExplanationDetail, 'code' | 'label' | 'text'>,
  ) => void,
): void {
  const metrics = {
    status: result.conf.status,
    reason: result.conf.reason,
  };
  if (result.conf.status === 'skip-cve') {
    addLimit(
      'cve_install_gate',
      `The security advisory install gate is active: ${result.conf.reason}. This gate, not a model ceiling, is the limiting reason.`,
      {
        metrics: {
          ...metrics,
          cveAffected: result.input.cveAffected,
          cveLoad: roundMetric(result.input.cveLoad),
        },
      },
    );
  } else if (result.conf.status === 'wait') {
    addLimit(
      'settle_time_gate',
      `The settle-time gate is active: ${result.conf.reason}. This release remains unscored until the settle window passes.`,
      {
        metrics: {
          ...metrics,
          publishedAt: result.input.publishedAt,
        },
      },
    );
  } else if (result.conf.status === 'skip-hotfix') {
    addLimit(
      'hotfix_successor_gate',
      `The hotfix successor gate is active: ${result.conf.reason}. This gate, not a model ceiling, is the limiting reason.`,
      {
        metrics: {
          ...metrics,
          hasHotfixSuccessor: result.input.hasHotfixSuccessor,
          hoursToNextStable: result.input.hoursToNextStable,
        },
      },
    );
  }
}

function installGateReason(result: ReleaseScoreResult): string {
  if (result.conf.status === 'skip-cve') return `the security advisory install gate: ${result.conf.reason}`;
  if (result.conf.status === 'wait') return `the settle-time gate: ${result.conf.reason}`;
  if (result.conf.status === 'skip-hotfix') return `the hotfix successor gate: ${result.conf.reason}`;
  return `the install gate: ${result.conf.reason}`;
}

function closureProofSummaryText(closureProof: any): string {
  const byStatus = closureProof?.byStatus ?? {};
  return Object.entries(byStatus)
    .filter(([status]) => status !== 'fixed_in_release')
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([status, count]) => `${count} ${closureStatusLabel(status)}`)
    .join(' · ');
}

function closureRiskSummaryText(closureProof: any): string {
  const risk = closureProof?.riskSummary ?? {};
  const parts = [
    [risk.knownNotInReleaseCount, 'known not in this tag'],
    [risk.openCanonicalRiskCount, 'open canonical issue or pull-request risk'],
    [risk.unsupportedClosureClaimCount, 'closure claims without enough proof'],
    [risk.missingEvidenceCount, 'missing proof evidence'],
  ];
  return parts
    .filter(([count]) => Number(count ?? 0) > 0)
    .map(([count, label]) => `${count} ${label}`)
    .join(' · ');
}

function closureStatusLabel(status: string): string {
  return ({
    fixed_in_release: 'fixed in this release',
    fixed_after_release: 'fixed after this release',
    fixed_in_later_release: 'fixed in later release',
    fixed_not_in_scored_releases: 'fixed outside scored releases',
    fixed_after_latest_release: 'fixed after latest release',
    fixed_skipped_by_later_releases: 'fix skipped by later releases',
    duplicate_to_fixed_in_release: 'canonical fixed in this release',
    duplicate_to_open_canonical: 'moved to open canonical',
    duplicate_to_closed_canonical: 'moved to closed canonical',
    duplicate_to_non_actionable_canonical: 'canonical non-actionable',
    duplicate_to_known_not_in_release_canonical: 'canonical not in this release',
    duplicate_to_open_pr_canonical: 'canonical open PR context',
    duplicate_to_unverified_closed_canonical: 'canonical unresolved closure',
    duplicate_to_closed_canonical_missing_proof: 'closed canonical proof missing',
    duplicate_to_fixed_after_release: 'canonical fixed after this release',
    duplicate_with_release_fix_proof: 'duplicate with release proof',
    superseded_to_open_pr: 'moved to open PR',
    duplicate_with_open_pr_context: 'related open PR context',
    duplicate_related_closed_unmerged_pr_context: 'duplicate related PR closed unmerged',
    duplicate_related_merged_pr_not_reachable_context: 'duplicate related PR not in tag',
    duplicate_related_merged_pr_reachable_context_without_fix_credit: 'duplicate related PR in tag, no fix credit',
    duplicate_related_merged_pr_reachability_unknown: 'duplicate related PR reachability unknown',
    duplicate_related_pr_without_release_fix: 'duplicate related PR without release-fix proof',
    canonical_cycle_or_self_reference: 'bad canonical reference',
    duplicate_or_superseded: 'duplicate/superseded',
    already_present_claim: 'already-present claim',
    admin_not_planned_unverified: 'unverified admin not-planned',
    admin_not_planned_no_context: 'admin not-planned without close context',
    not_planned_with_release_fix_proof: 'not-planned with release proof',
    not_planned_fixed_after_release: 'not-planned fixed after this release',
    not_planned_direct_fix_commit_reachability_unknown: 'not-planned direct fix commit reachability unknown',
    not_planned_with_open_pr_context: 'not-planned with open PR context',
    not_planned_linked_pr_not_merged: 'not-planned linked PR not merged',
    not_planned_related_closed_unmerged_pr_context: 'not-planned related PR closed unmerged',
    not_planned_related_merged_pr_not_reachable_context: 'not-planned related PR not in tag',
    not_planned_related_merged_pr_reachable_context_without_fix_credit: 'not-planned related PR in tag, no fix credit',
    not_planned_related_merged_pr_reachability_unknown: 'not-planned related PR reachability unknown',
    not_planned_related_pr_without_release_fix: 'not-planned related PR without release-fix proof',
    main_only_claim: 'main-only claim',
    reporter_replaced: 'reporter refiled/replaced',
    reporter_withdrawn: 'reporter withdrew',
    repro_requested: 'fresh repro requested',
    insufficient_info: 'insufficient repro info',
    reporter_self_closed: 'reporter self-closed',
    no_code_proof: 'no linked release fix',
    linked_closing_pr_reachability_unknown: 'merged closing PR reachability unknown',
    linked_closing_pr_not_merged: 'linked PR not merged',
    linked_closing_pr_open: 'linked PR still open',
    linked_closing_pr_closed_unmerged: 'linked PR closed unmerged',
    external_repo_closing_pr_unscored: 'external repo closing PR unscored',
    related_open_pr_context: 'related PR open',
    related_closed_unmerged_pr_context: 'related PR closed unmerged',
    related_merged_pr_not_reachable_context: 'related merged PR not in tag',
    related_merged_pr_reachable_context_without_fix_credit: 'related PR in tag, no fix credit',
    related_merged_pr_reachability_unknown: 'related merged PR reachability unknown',
    related_pr_without_release_fix: 'related PR without release-fix proof',
    direct_fix_commit_reachability_unknown: 'direct fix commit reachability unknown',
    closed_without_release_fix_proof: 'closed without release-fix proof',
    no_timeline_event: 'close event not fetched',
    non_bug_fixed_in_release: 'not bug evidence: fixed in release',
    non_bug_fixed_after_release: 'not bug evidence: fixed after release',
    non_bug_direct_fix_commit_reachability_unknown: 'not bug evidence: direct fix commit reachability unknown',
    non_bug_fixed_in_later_release: 'not bug evidence: fixed in later release',
    non_bug_fixed_not_in_scored_releases: 'not bug evidence: fixed outside scored releases',
    non_bug_fixed_after_latest_release: 'not bug evidence: fixed after latest',
    non_bug_fixed_skipped_by_later_releases: 'not bug evidence: skipped by later releases',
    non_bug_linked_without_merge: 'not bug evidence: unmerged link',
    non_bug_linked_pr_open: 'not bug evidence: linked PR open',
    non_bug_linked_pr_closed_unmerged: 'not bug evidence: linked PR closed unmerged',
    non_bug_duplicate_to_fixed_in_release: 'not bug evidence: canonical fixed in release',
    non_bug_duplicate_to_open_canonical: 'not bug evidence: open canonical',
    non_bug_duplicate_to_closed_canonical: 'not bug evidence: closed canonical',
    non_bug_duplicate_to_closed_canonical_missing_proof: 'not bug evidence: canonical proof missing',
    non_bug_duplicate_to_fixed_after_release: 'not bug evidence: canonical fixed after release',
    non_bug_superseded_to_open_pr: 'not bug evidence: open PR context',
    non_bug_duplicate_with_open_pr_context: 'not bug evidence: related open PR context',
    non_bug_duplicate_related_closed_unmerged_pr_context: 'not bug evidence: duplicate related PR closed unmerged',
    non_bug_duplicate_related_merged_pr_not_reachable_context: 'not bug evidence: duplicate related PR not in tag',
    non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit: 'not bug evidence: duplicate related PR in tag, no fix credit',
    non_bug_duplicate_related_merged_pr_reachability_unknown: 'not bug evidence: duplicate related PR reachability unknown',
    non_bug_duplicate_related_pr_without_release_fix: 'not bug evidence: duplicate related PR without release-fix proof',
    non_bug_duplicate_or_superseded: 'not bug evidence: duplicate/superseded',
    non_bug_not_actionable: 'not bug evidence: concrete non-actionable',
    non_bug_neutral: 'not bug evidence',
    not_planned: 'concrete non-actionable',
    unknown: 'not enough release evidence',
  } as Record<string, string>)[status] ?? String(status ?? 'unknown');
}

function issueListText(issues: any[], limit = 2): string {
  return issues
    .filter((issue) => !isPlaceholderIssueTitle(issue))
    .slice(0, limit)
    .map(issueRef)
    .filter(Boolean)
    .join('; ');
}

function sentenceSuffix(label: string, text: string): string {
  if (!text) return '';
  return ` ${label}: ${text}${/[.!?]$/.test(text) ? '' : '.'}`;
}

function issueRef(issue: any): string {
  if (!issue?.number) return '';
  return `#${issue.number} ${shortIssueTitle(issue)}`;
}

function shortIssueTitle(issue: any): string {
  const rawTitle = String(issue?.title ?? '').trim();
  if (isPlaceholderIssueTitle(issue)) return 'untitled report';
  const title = rawTitle.replace(/^\[bug\]:?\s*/i, '').replace(/^bug:?\s*/i, '').trim() || rawTitle;
  return truncateAtWordBoundary(title, SHORT_ISSUE_TITLE_LENGTH);
}

function isPlaceholderIssueTitle(issue: any): boolean {
  const rawTitle = String(issue?.title ?? '').trim();
  const content = rawTitle
    .replace(/^\[bug\]:?\s*/i, '')
    .replace(/^bug:?\s*/i, '')
    .replace(/[\s:;,.!?()[\]{}_-]+/g, '');
  return content.length === 0;
}

function penaltyText(value: unknown): string {
  if (typeof value !== 'number') return 'no additional point penalty under the active gate';
  const abs = roundMetric(Math.abs(value));
  return `a ${abs} point penalty`;
}

function truncateAtWordBoundary(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  const suffix = '...';
  const limit = Math.max(0, maxLength - suffix.length);
  const slice = text.slice(0, limit).trimEnd();
  const boundary = Math.max(slice.lastIndexOf(' '), slice.lastIndexOf('/'), slice.lastIndexOf('-'));
  if (boundary >= Math.floor(limit * 0.65)) return `${slice.slice(0, boundary).trimEnd()}${suffix}`;
  return `${slice}${suffix}`;
}

export const __releaseScoringTest = {
  advisoryCveSignal,
  bindSuppliedScoreReleases,
  buildScoreLedgerV2,
  buildScoreExplanation,
  canonicalLatestStableRelease,
  canonicalForecastProofSlots,
  compareReleaseRecency,
  deriveReleasePredecessors,
  exactReleaseLocalCommentEvidence,
  exactReleaseLocalEvidence,
  humanRecommendationDecisionSummary,
  isCanonicalLatestStableRelease,
  isReleaseLocalDebtIssue,
  releaseExplicitlyUnaffected,
  releaseClosureRiskCandidateRows,
  recommendationDecisionsForRun,
  recommendationDecisionSummary,
  releaseArtifactScoreProjection,
  selectAuthorizedReleaseNotAffectedClaim,
  selectClosureDispositionAuthority,
  releaseLinkedIssueRows,
  releaseCheckContextsForEvidence,
  releaseRegressionOpenedRows,
  releaseScopedDebtState,
  scoringLabelsAtCutoff,
  shortIssueTitle,
  sortReleasesNewestFirst,
  truncateAtWordBoundary,
};

type ReleaseCheckContextDisposition = 'failure' | 'pending' | 'success' | 'other';

function releaseCheckContextsForEvidence(
  contexts: unknown[],
  aggregate: {
    state?: unknown;
    failure?: unknown;
    pending?: unknown;
  },
): unknown[] {
  const ordered = contexts
    .map((context) => ({
      context,
      disposition: releaseCheckContextDisposition(context),
      stateRank: releaseCheckContextStateRank(context),
      sortKey: releaseCheckContextSortKey(context),
    }))
    .sort((left, right) =>
      releaseCheckContextDispositionRank(left.disposition) -
        releaseCheckContextDispositionRank(right.disposition) ||
      left.stateRank - right.stateRank ||
      compareReleaseCheckContextSortKey(left.sortKey, right.sortKey)
    );
  const aggregateAdverse = releaseCheckAggregateIsAdverse(aggregate);
  const exactAdverse = ordered.filter((item) =>
    item.disposition === 'failure' || item.disposition === 'pending');

  if (aggregateAdverse && exactAdverse.length === 0) return [];

  let retained = ordered.slice(0, RELEASE_CHECK_CONTEXT_LIMIT);
  if (
    aggregateAdverse &&
    retained.some((item) => releaseCheckContextHasLink(item.context)) &&
    retained
      .filter((item) => releaseCheckContextHasLink(item.context))
      .every((item) => item.disposition === 'success')
  ) {
    retained = retained.filter((item) =>
      item.disposition === 'failure' || item.disposition === 'pending');
  }

  return retained.map((item) => item.context);
}

function releaseCheckContextDisposition(context: unknown): ReleaseCheckContextDisposition {
  const conclusion = releaseCheckContextState(context, 'conclusion');
  const status = releaseCheckContextState(context, 'status');
  if (
    RELEASE_CHECK_FAILURE_STATES.has(conclusion) ||
    RELEASE_CHECK_FAILURE_STATES.has(status)
  ) {
    return 'failure';
  }
  if (
    RELEASE_CHECK_PENDING_STATES.has(conclusion) ||
    RELEASE_CHECK_PENDING_STATES.has(status) ||
    (status !== '' && status !== 'COMPLETED' && !RELEASE_CHECK_SUCCESS_STATES.has(status))
  ) {
    return 'pending';
  }
  if (
    RELEASE_CHECK_SUCCESS_STATES.has(conclusion) ||
    RELEASE_CHECK_SUCCESS_STATES.has(status)
  ) {
    return 'success';
  }
  return 'other';
}

function releaseCheckContextDispositionRank(disposition: ReleaseCheckContextDisposition): number {
  if (disposition === 'failure') return 0;
  if (disposition === 'pending') return 1;
  if (disposition === 'success') return 2;
  return 3;
}

function releaseCheckContextStateRank(context: unknown): number {
  const states = [
    releaseCheckContextState(context, 'conclusion'),
    releaseCheckContextState(context, 'status'),
  ];
  const priority = [
    'FAILURE',
    'ERROR',
    'ACTION_REQUIRED',
    'STARTUP_FAILURE',
    'TIMED_OUT',
    'CANCELLED',
    'STALE',
    'PENDING',
    'EXPECTED',
    'IN_PROGRESS',
    'QUEUED',
    'PENDING_REQUESTED',
    'REQUESTED',
    'WAITING',
    'SUCCESS',
  ];
  const index = priority.findIndex((state) => states.includes(state));
  return index >= 0 ? index : priority.length;
}

function releaseCheckContextState(context: unknown, key: 'conclusion' | 'status'): string {
  if (!context || typeof context !== 'object' || Array.isArray(context)) return '';
  const value = (context as Record<string, unknown>)[key];
  return typeof value === 'string'
    ? value.trim().toUpperCase().replace(/[\s-]+/g, '_')
    : '';
}

function releaseCheckContextSortKey(context: unknown): string {
  if (!context || typeof context !== 'object' || Array.isArray(context)) {
    return String(context ?? '');
  }
  const row = context as Record<string, unknown>;
  return [
    row.type,
    row.workflowName,
    row.name,
    row.appSlug,
    row.url,
    row.status,
    row.conclusion,
  ].map((value) => String(value ?? '').trim().toLowerCase()).join('\u0000');
}

function compareReleaseCheckContextSortKey(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function releaseCheckAggregateIsAdverse(aggregate: {
  state?: unknown;
  failure?: unknown;
  pending?: unknown;
}): boolean {
  const state = typeof aggregate.state === 'string'
    ? aggregate.state.trim().toUpperCase().replace(/[\s-]+/g, '_')
    : '';
  return Number(aggregate.failure ?? 0) > 0 ||
    Number(aggregate.pending ?? 0) > 0 ||
    ['FAILURE', 'ERROR', 'EXPECTED', 'ACTION_REQUIRED', 'PENDING'].includes(state);
}

function releaseCheckContextHasLink(context: unknown): boolean {
  if (!context || typeof context !== 'object' || Array.isArray(context)) return false;
  const url = (context as Record<string, unknown>).url;
  if (typeof url !== 'string' || !url.trim()) return false;
  if (/^\/(?!\/)/.test(url)) return true;
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

function hasExplicitReleaseMismatch(
  row: {
    affects_version?: string | null;
    title?: string | null;
    body?: string | null;
    releaseLocalEvidence?: ReleaseLocalEvidence | null;
    releaseExplicitlyUnaffected?: boolean;
  },
  releaseTag: string,
): boolean {
  if (row.releaseExplicitlyUnaffected === true) return true;
  if (
    row.releaseExplicitlyUnaffected !== false &&
    releaseExplicitlyUnaffected(row, releaseTag)
  ) {
    return true;
  }
  if (
    row.releaseLocalEvidence?.kind === 'exact-version' &&
    releaseVersionsMatch(row.releaseLocalEvidence.version, releaseTag)
  ) {
    return false;
  }
  if (exactReleaseLocalEvidence(row, releaseTag) != null) return false;
  if (
    row.releaseLocalEvidence?.kind === 'exact-version' &&
    RELEASE_TAG_RE.test(row.releaseLocalEvidence.version) &&
    !releaseVersionsMatch(row.releaseLocalEvidence.version, releaseTag)
  ) {
    return true;
  }
  const affectsVersion = String(row.affects_version ?? '').trim();
  if (
    RELEASE_TAG_RE.test(affectsVersion) &&
    !releaseVersionsMatch(affectsVersion, releaseTag)
  ) {
    return true;
  }
  return issueTextReleaseVersions(row).some((version) =>
    !releaseVersionsMatch(version, releaseTag) &&
    exactReleaseLocalEvidence(row, version) != null
  );
}

function isReleaseLocalDebtIssue(
  row: {
    affects_version?: string | null;
    created_at?: string | null;
    title?: string | null;
    body?: string | null;
  },
  release: { tag: string; published_at?: string | null },
): boolean {
  return exactReleaseLocalEvidence(row, release.tag) != null;
}

const EXPLICIT_RELEASE_TOKEN_RE =
  /(^|[^0-9A-Za-z])((?:[vV]\d+(?:\.\d+)*|\d+(?:\.\d+)+)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)(?=$|[^0-9A-Za-z])/g;
const RELEASE_TAG_RE =
  /^(?:[vV]\d+(?:\.\d+)*|\d+(?:\.\d+)+)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const NON_RELEASE_BUILD_RE =
  /\b((?:current\s+)?main(?:\s+branch|\s+build)?|master\s+branch|nightly|canary(?:\s+build|\s+channel)?|edge\s+(?:build|channel)|source\s+build|dev(?:elopment)?\s+build|unparsed\s+build)\b/i;
const NON_ADVERSE_RELEASE_CONTEXT_RE =
  /\b(?:milestone|roadmap|planning|planned|target(?:ed|ing)?|scheduled|backport(?:ed|ing)?|cherry[- ]pick(?:ed|ing)?|release notes?|changelog|documentation|informational|tracking|meta issue|future release|next release|candidate for|will be fixed|will fix|expected in|intended for)\b/i;
const ADVERSE_RELEASE_CLAUSE_RE =
  /\b(?:affect(?:s|ed|ing)?|break(?:s|ing|age)?|broken|bug|cannot|can't|corrupt(?:s|ed|ion)?|crash(?:es|ed|ing)?|deadlock|disconnect(?:s|ed)?|drop(?:s|ped|ping)?|error|exception|fail(?:s|ed|ing|ure)?|hang(?:s|ing)?|loss|lost|lose|loses|missing|not fixed|persists?|regression|reject(?:s|ed|ing)?|reproduc(?:e|ed|es|ible|ing)|stuck|timeout|unresponsive|unusable)\b/i;

function releaseVersionsMatch(left: string, right: string): boolean {
  if (!RELEASE_TAG_RE.test(left) || !RELEASE_TAG_RE.test(right)) {
    return normalizeReleaseToken(left) === normalizeReleaseToken(right);
  }
  try {
    return compareVersions(left, right) === 0;
  } catch {
    return normalizeReleaseToken(left) === normalizeReleaseToken(right);
  }
}

function issueTextReleaseVersions(
  row: { title?: string | null; body?: string | null },
): string[] {
  const versions = new Set<string>();
  for (const text of [String(row.title ?? ''), String(row.body ?? '')]) {
    for (const match of text.matchAll(EXPLICIT_RELEASE_TOKEN_RE)) {
      const version = String(match[2] ?? '');
      if (RELEASE_TAG_RE.test(version)) versions.add(version);
    }
  }
  return [...versions];
}

export interface IssueFieldEvidence {
  humanReporterCount: number;
  confirmationReasons: ConfirmationReason[];
  commentEvidenceComplete: boolean;
  commentsAtCutoff: CommentEvidenceRow[];
}

export function issueFieldEvidence(
  row: Pick<JoinedIssue, 'number' | 'author' | 'is_bot' | 'comments'> &
    Partial<Pick<JoinedIssue, 'node_id' | 'author_node_id' | 'author_type'>>,
  effectiveLabels: string[],
  cutoff: string | null,
  options: {
    requireCompleteComments?: boolean;
    comments?: ReturnType<typeof completeIssueComments>;
    commentCutoff?: string | null;
    labelAuthority?: LabelOverrideAuthority;
    recordAuthoritySubject?: (subject: ScoreAuthorityResolutionSubject) => void;
    authorityReferenceForEvent?: (
      eventId: string,
    ) => ScoreAuthorityReference | null;
  } = {},
): IssueFieldEvidence {
  let completeComments: ReturnType<typeof completeIssueComments>;
  let commentEvidenceComplete = true;
  if (options.comments) {
    completeComments = options.comments;
  } else {
    try {
      completeComments = completeIssueComments(row.number);
    } catch (error) {
      if (options.requireCompleteComments !== false) throw error;
      completeComments = [];
      commentEvidenceComplete = false;
    }
  }
  const commentsAtCutoff = completeComments.filter((comment) =>
    commentAvailableAtCutoff(comment, options.commentCutoff ?? cutoff));
  const commentReasons = semanticHumanConfirmationReasons({
    issueNumber: row.number,
    issueNodeId: row.node_id,
    issueAuthor: {
      nodeId: row.author_node_id ?? null,
      login: row.author,
      actorType: row.author_type,
    },
    cutoff,
    comments: commentsAtCutoff,
  });
  for (const reason of commentReasons) {
    const resolution = buildScoreCommentAuthorityResolution(
      scoreCommentAuthorityEvidenceFromReason(row.number, reason),
    );
    const authorityReference = buildScoreAuthorityReference(
      'comment',
      resolution.commentNodeId,
      resolution,
    );
    if (
      canonicalScoreAuthorityReferenceJson(reason.authorityReference) !==
        canonicalScoreAuthorityReferenceJson(authorityReference)
    ) {
      throw new Error(
        `Issue #${row.number} comment confirmation authority reference ` +
          `does not match ${resolution.commentNodeId}`,
      );
    }
    options.recordAuthoritySubject?.({
      releaseTag: null,
      issueNumber: row.number,
      subjectKind: 'comment',
      subjectIdentity: resolution.commentNodeId,
      candidateId: null,
      resolution,
    });
  }
  const labelReasons = humanAppliedConfirmationLabelReasons(
    row.number,
    effectiveLabels,
    cutoff,
    options.labelAuthority,
    options.authorityReferenceForEvent,
  );
  const reporterIdentities = new Set<string>();
  if (row.author_node_id && row.author_type === 'User') {
    reporterIdentities.add(`User\0${row.author_node_id}`);
  }
  for (const reason of commentReasons) {
    if (reason.actorNodeId && reason.actorType === 'User') {
      reporterIdentities.add(`User\0${reason.actorNodeId}`);
    }
  }
  return {
    humanReporterCount: reporterIdentities.size,
    confirmationReasons: [...commentReasons, ...labelReasons],
    commentEvidenceComplete,
    commentsAtCutoff,
  };
}

function scoreCommentAuthorityEvidenceFromReason(
  issueNumber: number,
  reason: ConfirmationReason,
): ScoreCommentAuthorityEvidence {
  if (
    reason.source !== 'comment' ||
    reason.code !== 'independent_human_reproduction' ||
    !reason.issueNodeId ||
    !reason.issueAuthorNodeId ||
    !reason.issueAuthorType ||
    !reason.commentNodeId ||
    reason.commentNodeType !== 'IssueComment' ||
    !Number.isInteger(reason.commentId) ||
    Number(reason.commentId) <= 0 ||
    !reason.commentUrl ||
    !reason.actorNodeId ||
    reason.actorType !== 'User' ||
    !reason.updatedAt ||
    !reason.commentBodyDigest ||
    !reason.snippet
  ) {
    throw new Error(
      `Issue #${issueNumber} comment confirmation is missing immutable authority evidence`,
    );
  }
  return {
    issueNumber,
    issueNodeId: reason.issueNodeId,
    issueAuthorNodeId: reason.issueAuthorNodeId,
    issueAuthorType: reason.issueAuthorType,
    commentNodeId: reason.commentNodeId,
    commentId: Number(reason.commentId),
    commentUrl: reason.commentUrl,
    actorNodeId: reason.actorNodeId,
    actorType: reason.actorType,
    commentCreatedAt: reason.occurredAt,
    commentUpdatedAt: reason.updatedAt,
    commentBodyDigest: reason.commentBodyDigest,
    claimSnippet: reason.snippet,
  };
}

function humanAppliedConfirmationLabelReasons(
  issueNumber: number,
  effectiveLabels: string[],
  cutoff: string | null,
  authority?: LabelOverrideAuthority,
  authorityReferenceForEvent?: (
    eventId: string,
  ) => ScoreAuthorityReference | null,
): ConfirmationReason[] {
  const codes = new Map<string, ConfirmationReason['code']>([
    ['P0', 'human_applied_p0'],
    ['P1', 'human_applied_p1'],
    ['regression', 'human_applied_regression'],
  ]);
  const reasons: ConfirmationReason[] = [];
  for (const [label, code] of codes) {
    if (!effectiveLabels.includes(label)) continue;
    const event = latestIssueLabelEventAt(issueNumber, label, cutoff);
    const authorityReference = event
      ? authorityReferenceForEvent?.(event.event_id) ?? null
      : null;
    if (
      !event ||
      event.action !== 'labeled' ||
      !labelAuthorizedForScoring(label, authority) ||
      !authorityReference
    ) {
      continue;
    }
    reasons.push({
      code,
      source: 'label_event',
      author: event.actor_login ?? 'unavailable',
      occurredAt: event.created_at,
      label: label as 'P0' | 'P1' | 'regression',
      eventId: event.event_id,
      authorityReference,
    });
  }
  return reasons;
}

function commentAvailableAtCutoff(
  comment: {
    created_at?: string | null;
    updated_at?: string | null;
  },
  cutoff: string | null,
): boolean {
  if (!cutoff) return true;
  const cutoffMs = Date.parse(cutoff);
  const createdMs = Date.parse(comment.created_at ?? '');
  const updatedMs = Date.parse(comment.updated_at ?? comment.created_at ?? '');
  return Number.isFinite(cutoffMs) &&
    Number.isFinite(createdMs) &&
    Number.isFinite(updatedMs) &&
    createdMs <= cutoffMs &&
    updatedMs <= cutoffMs;
}

export function exactReleaseLocalEvidence(
  row: { title?: string | null; body?: string | null },
  releaseTag: string,
  comments: CommentEvidenceRow[] = [],
  releasePublishedAt?: string | null,
  commentAuthorityReference?: (
    commentNodeId: string,
  ) => ScoreAuthorityReference | null,
): ReleaseLocalEvidence | null {
  if (!RELEASE_TAG_RE.test(releaseTag)) return null;
  if (releaseExplicitlyUnaffected(row, releaseTag, comments)) return null;
  const target = normalizeReleaseToken(releaseTag);
  const titleEvidence = exactVersionTextEvidence(
    String(row.title ?? ''),
    target,
    releaseTag,
    'title',
  );
  if (titleEvidence) return titleEvidence;
  const bodyEvidence = exactVersionTextEvidence(
    String(row.body ?? ''),
    target,
    releaseTag,
    'body',
  );
  if (bodyEvidence) return bodyEvidence;
  return exactReleaseLocalCommentEvidence(
    comments,
    releaseTag,
    releasePublishedAt,
    commentAuthorityReference,
  );
}

export function exactReleaseLocalCommentEvidence(
  comments: CommentEvidenceRow[],
  releaseTag: string,
  releasePublishedAt?: string | null,
  commentAuthorityReference?: (
    commentNodeId: string,
  ) => ScoreAuthorityReference | null,
): ReleaseLocalEvidence | null {
  if (!RELEASE_TAG_RE.test(releaseTag)) return null;
  const target = normalizeReleaseToken(releaseTag);
  const releasePublishedMs = Date.parse(releasePublishedAt ?? '');
  for (const comment of comments) {
    let commentIdentity;
    let actorIdentity;
    try {
      commentIdentity = canonicalCommentSourceIdentity(comment);
      actorIdentity = canonicalCommentActorIdentity(comment);
    } catch {
      continue;
    }
    if (
      !commentIdentity ||
      !actorIdentity ||
      actorIdentity.nodeType !== 'User'
    ) {
      continue;
    }
    const commentBody = String(comment.body ?? '');
    const author = String(comment.user?.login ?? actorIdentity.nodeId).trim();
    const commentCreatedMs = Date.parse(comment.created_at ?? '');
    const commentUpdatedAt = comment.updated_at ?? comment.created_at ?? null;
    const commentUpdatedMs = Date.parse(commentUpdatedAt ?? '');
    if (
      !author ||
      !adverseReproductionClaim(commentBody) ||
      !Number.isFinite(releasePublishedMs) ||
      !Number.isFinite(commentCreatedMs) ||
      !Number.isFinite(commentUpdatedMs) ||
      commentUpdatedMs < commentCreatedMs ||
      commentCreatedMs < releasePublishedMs
    ) {
      continue;
    }
    const evidence = exactVersionTextEvidence(
      commentBody,
      target,
      releaseTag,
      'comment',
    );
    const commentId = Number(comment.id);
    const commentUrl = String(comment.url ?? '').trim();
    const suppliedAuthorityReference = commentAuthorityReference?.(
      commentIdentity.nodeId,
    ) ?? null;
    const authorityReference =
      scoreAuthorityReferenceProblems(suppliedAuthorityReference).length === 0 &&
        suppliedAuthorityReference?.subjectKind === 'comment' &&
        suppliedAuthorityReference.subjectIdentity === commentIdentity.nodeId
        ? suppliedAuthorityReference
        : null;
    if (
      evidence &&
      Number.isInteger(commentId) &&
      commentId > 0 &&
      commentUrl &&
      authorityReference
    ) {
      return {
        ...evidence,
        commentId,
        commentUrl,
        commentNodeId: commentIdentity.nodeId,
        author,
        actorNodeId: actorIdentity.nodeId,
        actorType: actorIdentity.nodeType,
        association: comment.author_association ?? null,
        occurredAt: comment.created_at ?? undefined,
        updatedAt: commentUpdatedAt ?? undefined,
        commentBodyDigest: scoreCommentBodyDigest(commentBody),
        authorityReference,
      };
    }
  }
  return null;
}

function exactVersionTextEvidence(
  text: string,
  target: string,
  releaseTag: string,
  source: ReleaseLocalEvidence['source'],
): ReleaseLocalEvidence | null {
  if (!text) return null;
  if (releaseTextExplicitlyUnaffected(text, releaseTag)) return null;
  for (const match of text.matchAll(EXPLICIT_RELEASE_TOKEN_RE)) {
    const tokenIndex = (match.index ?? 0) + String(match[1] ?? '').length;
    const tokenLength = String(match[2] ?? '').length;
    if (normalizeReleaseToken(match[2]) !== target) continue;
    if (releaseMentionIsExplicitlyUnaffected(text, tokenIndex, tokenLength)) continue;
    if (!releaseMentionIsAdverse(text, tokenIndex, tokenLength)) continue;
    const context = text.slice(
      Math.max(0, tokenIndex - 80),
      Math.min(text.length, tokenIndex + tokenLength + 80),
    );
    if (NON_RELEASE_BUILD_RE.test(context)) continue;
    return {
      kind: 'exact-version',
      source,
      version: releaseTag,
      snippet: evidenceSnippet(context),
    };
  }
  return null;
}

function releaseMentionIsAdverse(
  text: string,
  matchIndex: number,
  matchLength: number,
): boolean {
  const clause = releaseMentionClause(text, matchIndex, matchLength);
  if (
    !clause ||
    NON_RELEASE_BUILD_RE.test(clause) ||
    NON_ADVERSE_RELEASE_CONTEXT_RE.test(clause)
  ) {
    return false;
  }
  return adverseReproductionClaim(clause) != null ||
    ADVERSE_RELEASE_CLAUSE_RE.test(clause);
}

function releaseMentionClause(
  text: string,
  matchIndex: number,
  matchLength: number,
): string {
  let clauseStart = 0;
  for (let index = matchIndex - 1; index >= 0; index--) {
    if (!isReleaseClauseBoundary(text, index)) continue;
    clauseStart = index + 1;
    break;
  }
  let clauseEnd = text.length;
  for (let index = matchIndex + matchLength; index < text.length; index++) {
    if (!isReleaseClauseBoundary(text, index)) continue;
    clauseEnd = index + 1;
    break;
  }
  return text.slice(clauseStart, clauseEnd).replace(/\s+/g, ' ').trim();
}

function isReleaseClauseBoundary(text: string, index: number): boolean {
  const character = text[index];
  if (character === '\n' || character === '\r' || character === '!' ||
      character === '?' || character === ';') {
    return true;
  }
  if (character !== '.') return false;
  return !/\d/.test(text[index - 1] ?? '') || !/\d/.test(text[index + 1] ?? '');
}

export function releaseExplicitlyUnaffected(
  row: { title?: string | null; body?: string | null },
  releaseTag: string,
  comments: CommentEvidenceRow[] = [],
): boolean {
  if (releaseTextExplicitlyUnaffected(
    `${String(row.title ?? '')}\n${String(row.body ?? '')}`,
    releaseTag,
  )) {
    return true;
  }
  return comments.some((comment) => {
    try {
      return canonicalCommentSourceIdentity(comment) != null &&
        canonicalCommentActorIdentity(comment)?.nodeType === 'User' &&
        releaseTextExplicitlyUnaffected(String(comment.body ?? ''), releaseTag);
    } catch {
      return false;
    }
  });
}

export function releaseClosureRiskCandidateRows<T extends {
  issue_number?: number;
  title?: string | null;
  body?: string | null;
}>(
  rows: T[],
  releaseTag: string,
  issuesByNumber?: ReadonlyMap<number, { body?: string | null }>,
): T[] {
  return rows.filter((row) => !releaseExplicitlyUnaffected({
    title: row.title,
    body: row.body ??
      (row.issue_number == null ? null : issuesByNumber?.get(row.issue_number)?.body),
  }, releaseTag));
}

function releaseTextExplicitlyUnaffected(text: string, releaseTag: string): boolean {
  if (!text) return false;
  if (
    /\bnot\s+in\s+any\s+released\s+builds?\b/i.test(text) ||
    /\bno\s+released\s+builds?\s+(?:is|are)\s+affected\b/i.test(text)
  ) {
    return true;
  }
  for (const alias of releaseReferenceAliases(releaseTag)) {
    const token = `v?${escapeRegExp(alias)}`;
    if (new RegExp(`\\bnot\\s+in\\s+any\\s+${token}\\s+releases?\\b`, 'i').test(text)) {
      return true;
    }
    if (new RegExp(
      `\\b(?:the\\s+)?(?:entire\\s+)?${token}\\s+` +
      `(?:builds?\\s*\\/\\s*line|builds?|line|ga(?:\\s+and\\s+(?:its\\s+)?betas?)?)\\s+` +
      `(?:is|are)\\s+clean\\b`,
      'i',
    ).test(text)) {
      return true;
    }
  }
  const target = normalizeReleaseToken(releaseTag);
  for (const match of text.matchAll(EXPLICIT_RELEASE_TOKEN_RE)) {
    const tokenIndex = (match.index ?? 0) + String(match[1] ?? '').length;
    const tokenLength = String(match[2] ?? '').length;
    if (normalizeReleaseToken(match[2]) !== target) continue;
    if (releaseMentionIsExplicitlyUnaffected(text, tokenIndex, tokenLength)) return true;
  }
  return false;
}

function releaseMentionIsExplicitlyUnaffected(
  title: string,
  matchIndex: number,
  matchLength: number,
): boolean {
  const before = title.slice(Math.max(0, matchIndex - 48), matchIndex);
  const after = title.slice(matchIndex + matchLength, matchIndex + matchLength + 48);
  if (
    /(?:not|isn't|wasn't|still\s+not)\s+(?:fixed|working)(?:\s+(?:on|in))?\s*$/i.test(before) ||
    /still\s+(?:broken|reproducing|reproducible)(?:\s+(?:on|in))?\s*$/i.test(before)
  ) {
    return false;
  }
  return (
    /(?:does\s+not|doesn't|did\s+not|didn't)\s+(?:affect|fail|break)\s*$/i.test(before) ||
    /(?:unaffected|not\s+affected|not\s+broken|not\s+reproducible|works?|working|fixed|okay|ok|stable)(?:\s+(?:on|in))?\s*$/i.test(before) ||
    /^\s*(?:is|was|remains?)?\s*(?:unaffected|not\s+affected|not\s+broken|not\s+reproducible|working|works|fixed|okay|ok|stable)\b/i.test(after)
  );
}

function normalizeReleaseToken(value: string): string {
  return value.trim().replace(/^v/i, '').toLowerCase();
}

function evidenceSnippet(value: string, maxLength = 240): string {
  const compact = value.replace(/\s+/g, ' ').trim();
  return compact.length <= maxLength
    ? compact
    : `${compact.slice(0, maxLength - 3).trimEnd()}...`;
}

export function releaseScopedDebtState(
  row: { number: number; state?: string | null },
  verifiedFixedNumbers: ReadonlySet<number>,
  releaseClosureProofNumbers: ReadonlySet<number>,
): 'open' | 'closed' | 'closed-unverified' {
  if (verifiedFixedNumbers.has(row.number)) return 'closed';
  if (row.state === 'open') return 'open';
  return releaseClosureProofNumbers.has(row.number) ? 'closed-unverified' : 'open';
}

export function releaseRegressionOpenedRows<T extends {
  state?: string | null;
  affects_version?: string | null;
  title?: string | null;
  body?: string | null;
  releaseLocalEvidence?: ReleaseLocalEvidence | null;
  releaseExplicitlyUnaffected?: boolean;
}>(rows: T[], releaseTag?: string): T[] {
  return rows.filter((row) =>
    row.state !== 'open' &&
    (!releaseTag || !hasExplicitReleaseMismatch(row, releaseTag))
  );
}

export function releaseLinkedIssueRows<T extends {
  affects_version?: string | null;
  title?: string | null;
  body?: string | null;
  releaseLocalEvidence?: ReleaseLocalEvidence | null;
  releaseExplicitlyUnaffected?: boolean;
}>(rows: T[], releaseTag: string): T[] {
  return rows.filter((row) => !hasExplicitReleaseMismatch(row, releaseTag));
}

function releaseReferenceAliases(releaseTag: string): string[] {
  const normalized = normalizeReleaseToken(releaseTag);
  const parts = normalized.split('.');
  const aliases = [normalized];
  if (parts.length >= 3 && /^\d{4}$/.test(parts[0])) {
    aliases.push(parts.slice(1).join('.'));
  }
  return [...new Set(aliases)];
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isCoreSerious(classification: IssueClassification): boolean {
  return classification.sentiment === 'negative' &&
    classification.functionality === 'core' &&
    (classification.severity === 'critical' || classification.severity === 'high');
}

export function safeParseLabels(json: string): string[] {
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function parseJsonArray(json: string | null | undefined): unknown[] {
  try {
    const value = json ? JSON.parse(json) : [];
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function rowToClassification(row: {
  sentiment: string;
  severity: string;
  scope: string;
  functionality: string;
  affected_users: string;
  has_workaround: number;
  workaround_status: string;
  duplicate_cluster: string | null;
  affects_version: string | null;
  confidence: number;
  rationale: string | null;
}): IssueClassification {
  const wsAllowed = ['none', 'partial', 'confirmed', 'unknown'] as const;
  const ws = wsAllowed.includes(row.workaround_status as (typeof wsAllowed)[number])
    ? (row.workaround_status as IssueClassification['workaroundStatus'])
    : row.has_workaround === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment as IssueClassification['sentiment'],
    severity: row.severity as IssueClassification['severity'],
    scope: row.scope as IssueClassification['scope'],
    functionality: row.functionality as IssueClassification['functionality'],
    affectedUsers: row.affected_users as IssueClassification['affectedUsers'],
    hasWorkaround: row.has_workaround === 1,
    workaroundStatus: ws,
    duplicateCluster: row.duplicate_cluster,
    affectsVersion: row.affects_version,
    confidence: row.confidence,
    rationale: row.rationale ?? '',
  };
}

export function classifyIssueRow(row: JoinedIssue): IssueClassification {
  const labelInfo = scoringLabelInfoAtCutoff(
    row.number,
    safeParseLabels(row.labels),
    null,
  );
  return classifyIssueRowWithLabels(row, labelInfo.labels, labelInfo);
}

export function classifyIssueRowWithLabels(
  row: JoinedIssue,
  labels: string[],
  authority?: LabelOverrideAuthority,
): IssueClassification {
  return applyTitleIssueShapeHint(
    applyLabelOverrides(
      applyTitleFunctionalityHint(rowToClassification(row), row.title),
      labels,
      authority,
    ),
    row.title,
    labels,
    authority,
  );
}

export function classifyIssueRowForOpenDebtWithLabels(
  row: JoinedIssue,
  labels: string[],
  authority?: LabelOverrideAuthority,
): IssueClassification {
  return applyClosureRiskSentimentHint(
    classifyIssueRowWithLabels(row, labels, authority),
    row.title,
    labels,
    authority,
  );
}

export function isOpenFeltSeriousIssue(row: JoinedIssue): boolean {
  const labelInfo = scoringLabelInfoAtCutoff(
    row.number,
    safeParseLabels(row.labels),
    null,
  );
  const c = classifyIssueRowWithLabels(row, labelInfo.labels, labelInfo);
  return row.state === 'open' && isFeltSignal({
    ...c,
    issueNumber: row.number,
    duplicateCluster: row.duplicate_cluster,
    author: row.author,
    authorAssociation: row.author_association,
    isBot: row.is_bot,
    comments: row.comments,
    uniqueHumanCommenterCount: row.unique_human_commenters,
    maintainerCommenterCount: row.maintainer_commenters,
    contributorCommenterCount: row.contributor_commenters,
    commenterScanTruncated: row.commenter_scan_truncated,
    reactionTotal: row.reaction_total,
    positiveReactionCount: row.positive_reactions,
    labels: labelInfo.labels,
  });
}
