import { createHash } from 'node:crypto';
import type { IssueClassification } from './llm';
import {
  canonicalCommentActorIdentity,
  canonicalCommentSourceIdentity,
  isExactIssueReporterComment,
  type CommentEvidenceRow,
  type IssueAuthorEvidenceIdentity,
} from './commentEvidence';
import {
  buildIssueAliasGroups,
  type AggregatedClosureRisk,
} from './closureRiskAggregation';
import {
  buildScoreAuthorityReference,
  buildScoreCommentAuthorityResolution,
  scoreAuthorityReferenceProblems,
  type ScoreAuthorityReference,
} from './scoreAuthorityResolution';
import { compareVersions } from './versionMatch';

// Evidence-based Install Confidence.
//
// This model answers "should I install this stable?" using install/recommendation gates
// plus explicit evidence tiers. Release-local blockers and regressions matter
// most. Historical unresolved backlog remains visible for audit, but contributes
// no points so a release is not penalized merely because old issues remain open.

const HOUR_MS = 60 * 60 * 1000;

export const SCORE_MODEL_VERSION = 'evidence-v30-tooling-exclusion';
export const REC_THRESHOLD = 7;
export const RECOMMENDATION_RECENCY_TOLERANCE = 0.5;

const SETTLE_HOURS = 24;
const HOTFIX_GAP_HOURS = 6;
const PIVOT_HOURS = 24;
const BASE = 7.5;
const HOTFIX_SCORE_CAP = 4.9;
const NOTICEABLE_CLOSURE_RISK_THRESHOLD = 40;
const NOTICEABLE_CLOSURE_SCORE_CAP = 8.4;
const HEAVY_CLOSURE_RISK_THRESHOLD = 60;
const HEAVY_CLOSURE_SCORE_CAP = 7.9;

const SURVIVAL_MIN = -2.5;
const SURVIVAL_MAX = 1.8;
const SHAKEOUT_MAX = 0.8;
const BREAKING_PER_BULLET = -0.25;
const BREAKING_MAX_BULLETS = 6;

const VERIFIED_DEBT_MAX = -2.0;
const CARRYOVER_DEBT_MAX = 0;
const STALE_DEBT_MAX = -0.2;
const CLOSURE_RISK_MAX = -0.5;
const COVERAGE_MAX = -2.5;
const REGRESSION_DOWN = -0.8;
const REGRESSION_UP = 0.4;
const RELEASE_CHECK_UP = 0.4;
const RELEASE_CHECK_DOWN = -1.4;
const ARTIFACT_UP = 0.35;
const ARTIFACT_DOWN = -1.2;
const PRIOR = 12;

export const SCORE_COMPONENT_LIMITS = {
  verifiedDebtMaxPenalty: Math.abs(VERIFIED_DEBT_MAX),
  carryoverDebtMaxPenalty: Math.abs(CARRYOVER_DEBT_MAX),
  staleDebtMaxPenalty: Math.abs(STALE_DEBT_MAX),
  closureRiskMaxPenalty: Math.abs(CLOSURE_RISK_MAX),
  noticeableClosureRiskThreshold: NOTICEABLE_CLOSURE_RISK_THRESHOLD,
  noticeableClosureScoreCap: NOTICEABLE_CLOSURE_SCORE_CAP,
  heavyClosureRiskThreshold: HEAVY_CLOSURE_RISK_THRESHOLD,
  heavyClosureScoreCap: HEAVY_CLOSURE_SCORE_CAP,
} as const;

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 2.5,
  medium: 0.8,
  low: 0,
};
const FUNCTIONALITY_WEIGHT: Record<string, number> = {
  core: 1.25,
  integration: 1,
  provider: 1,
  tooling: 0,
  docs: 0,
};
const SCOPE_WEIGHT: Record<string, number> = {
  broad: 1.5,
  moderate: 1,
  niche: 0.4,
};
const USERS_WEIGHT: Record<string, number> = {
  many: 1.3,
  some: 0.85,
  few: 0.35,
  unknown: 0.65,
};

export type InstallStatus = 'wait' | 'skip-cve' | 'skip-hotfix' | 'eligible';
export type InstallBand = 'solid' | 'ok' | 'caution' | 'weak' | 'skip' | 'wait';

export interface RecommendationCandidate {
  tag: string;
  status: InstallStatus;
  score: number | null;
  publishedAt?: string | null;
}

export interface InstallInput {
  schemaVersion?: number;
  publishedAt: string | null;
  isLatest: boolean;
  hoursToNextStable: number | null;
  hasHotfixSuccessor: boolean;
  betaCount: number;
  breakingCount: number;
  feltOpenedWeight: number;
  feltClosedWeight: number;
  verifiedDebtWeight: number;
  carryoverDebtWeight: number;
  staleDebtWeight: number;
  verifiedDebtIssueCount?: number;
  carryoverDebtIssueCount?: number;
  staleDebtIssueCount?: number;
  unresolvedClosureRiskWeight: number;
  affirmativeClosureRiskCeilingWeight: number;
  unresolvedClosureIssueCount?: number;
  rawIssueCount: number;
  classifiedIssueCount: number;
  cveAffected: boolean;
  cveLoad: number;
  releaseCheckState?: string | null;
  releaseCheckTotal?: number;
  releaseCheckSuccess?: number;
  releaseCheckFailure?: number;
  releaseCheckPending?: number;
  artifactVerified?: boolean;
  artifactMismatch?: string | null;
  ciReportVerified?: boolean;
  ciReportMismatch?: string | null;
  releaseIntegrityPresent?: boolean;
  releaseShaMatches?: boolean;
}

export interface InstallComponents {
  base: number;
  verifiedDebt: number;
  carryoverDebt: number;
  staleDebt: number;
  closureRisk: number;
  closureRiskCeiling: number;
  coverage: number;
  survival: number;
  shakeout: number;
  regression: number;
  breaking: number;
  releaseVerification: number;
  artifactVerification: number;
}

export interface InstallConfidence {
  score: number | null;
  status: InstallStatus;
  band: InstallBand;
  hotfix: boolean;
  components: InstallComponents | null;
  // Kept separate so audit ledgers do not mislabel range clamping as precision drift.
  scoreRangeClamp: number | null;
  evidenceCoverage: number;
  reason: string;
}

export const SCORE_LEDGER_SCHEMA_VERSION = 2;
export const SCORE_LEDGER_TYPE = 'ScoreLedgerV2';
export const SCORE_LEDGER_PREVIEW_LIMIT = 25;

export type ScoreLedgerOperandValue = number | string | boolean | null;
export type ScoreLedgerOperationKind =
  | 'predicate'
  | 'component'
  | 'clamp'
  | 'cap'
  | 'round'
  | 'gate';

export interface ScoreLedgerOperand {
  name: string;
  type: 'number' | 'string' | 'boolean' | 'null';
  value: ScoreLedgerOperandValue;
  unit: string | null;
}

export interface ScoreLedgerBounds {
  min: number | null;
  max: number | null;
}

export interface ScoreLedgerEvidenceRefInput {
  kind: string;
  identity: string;
  payload?: unknown;
  digest?: string;
  scoringOperand?: ScoreLedgerEvidenceOperand;
}

export interface ScoreLedgerEvidenceOperand {
  aliasGroup: string;
  channel: IssueRiskChannel;
  weight: number;
}

export interface ScoreLedgerEvidenceRef {
  kind: string;
  identity: string;
  digest: string;
  scoringOperand?: ScoreLedgerEvidenceOperand;
}

export interface ScoreLedgerEvidenceSourceInput {
  key: string;
  refs: readonly ScoreLedgerEvidenceRefInput[];
  previewLimit?: number;
}

export interface ScoreLedgerEvidenceManifest {
  key: string;
  exhaustive: true;
  count: number;
  digest: string;
  refs: ScoreLedgerEvidenceRef[];
}

export interface ScoreLedgerEvidencePreview {
  key: string;
  limit: number;
  totalCount: number;
  truncated: boolean;
  refs: ScoreLedgerEvidenceRef[];
}

export interface ScoreLedgerEvidenceBundle {
  schemaVersion: 1;
  manifests: ScoreLedgerEvidenceManifest[];
  previews: ScoreLedgerEvidencePreview[];
  digest: string;
}

export interface ScoreLedgerOperation {
  sequence: number;
  code: string;
  label: string;
  kind: ScoreLedgerOperationKind;
  formulaCode: string;
  operands: ScoreLedgerOperand[];
  rawPoints: number | null;
  boundedPoints: number | null;
  bounds: ScoreLedgerBounds;
  before: number | null;
  after: number | null;
  applied: boolean;
  predicateResult: boolean | null;
  evidenceManifestKeys: string[];
  evidenceDigest: string;
}

export interface ScoreLedgerGapItem {
  sequence: number;
  operationCode: string;
  label: string;
  points: number;
}

export interface ScoreLedgerGapToTen {
  applicable: boolean;
  target: 10;
  finalScore: number | null;
  total: number | null;
  items: ScoreLedgerGapItem[];
}

export interface ScoreLedgerCveGate {
  affected: boolean;
  load: number;
  rawGateScore: number | null;
  boundedGateScore: number | null;
  roundedGateScore: number | null;
  counterfactualStatus: InstallStatus | null;
  counterfactualScore: number | null;
  selectedScore: number | null;
  advisoryManifestKey: 'advisories';
}

export interface ScoreLedgerThresholds {
  settleHours: number;
  hotfixGapHours: number;
  hotfixScoreCap: number;
  noticeableClosureRiskWeight: number;
  noticeableClosureScoreCap: number;
  heavyClosureRiskWeight: number;
  heavyClosureScoreCap: number;
  scoreRangeMin: number;
  scoreRangeMax: number;
  scorePrecisionDecimals: number;
}

export interface ScoreLedgerAliasElection {
  schemaVersion: 1;
  manifestKey: 'aliasElection';
  groups: IssueRiskLedgerGroup[];
  totalsByChannel: Record<IssueRiskChannel, number>;
  digest: string;
}

// Compatibility projection for the current UI. V2 operations are authoritative.
export interface ScoreLedgerPresentationRow {
  key: string;
  label: string;
  points: number;
  kind: 'base' | 'bonus' | 'penalty' | 'neutral';
  metric?: number | string | null;
  note?: string | null;
}

export interface ScoreLedgerPresentationCap {
  key: string;
  label: string;
  ceiling: number;
  applied: boolean;
  before: number | null;
  after: number | null;
  reason: string;
}

export interface ScoreLedgerV2 {
  schemaVersion: 2;
  ledgerType: typeof SCORE_LEDGER_TYPE;
  immutable: true;
  formulaCode: string;
  evaluatedAt: string;
  finalScore: number | null;
  status: InstallStatus;
  band: InstallBand;
  thresholds: ScoreLedgerThresholds;
  operations: ScoreLedgerOperation[];
  evidence: ScoreLedgerEvidenceBundle;
  aliasElection: ScoreLedgerAliasElection;
  cveGate: ScoreLedgerCveGate;
  gapToTen: ScoreLedgerGapToTen;
  digest: string;
  rows: ScoreLedgerPresentationRow[];
  caps: ScoreLedgerPresentationCap[];
  subtotalBeforeCaps: number | null;
  scoreAfterCaps: number | null;
  explanationAudit?: ScoreLedgerExplanationAudit;
}

export interface BuildScoreLedgerV2Input {
  input: InstallInput;
  confidence: InstallConfidence;
  now: number;
  evidenceSources?: readonly ScoreLedgerEvidenceSourceInput[];
  aliasElection?: ExclusiveIssueRiskLedger;
}

export interface ScoreExplanationAuditDetailSource {
  code: string;
  label: string;
  text: string;
  metrics?: unknown;
  buckets?: unknown;
  riskBuckets?: unknown;
  issueRefs?: unknown;
}

export interface ScoreExplanationAuditSource {
  title: string;
  positives: readonly string[];
  positiveDetails: readonly ScoreExplanationAuditDetailSource[];
  limits: readonly string[];
  limitDetails: readonly ScoreExplanationAuditDetailSource[];
  verdict: string;
  recommendationDecision?: unknown;
}

export interface ScoreLedgerExplanationOperationReceipt {
  sequence: number;
  code: string;
  formulaCode: string;
  evidenceDigest: string;
}

export interface ScoreLedgerExplanationAuditDetail {
  section: 'limit' | 'positive';
  index: number;
  code: string;
  label: string;
  text: string;
  metricsDigest: string;
  bucketsDigest: string;
  riskBucketsDigest: string;
  issueRefsDigest: string;
  operations: ScoreLedgerExplanationOperationReceipt[];
}

export interface ScoreLedgerExplanationAudit {
  schemaVersion: 1;
  baseLedgerDigest: string;
  title: string;
  verdict: string;
  listsDigest: string;
  recommendationDecisionDigest: string;
  details: ScoreLedgerExplanationAuditDetail[];
  digest: string;
}

export const SCORE_EXPLANATION_CANONICAL_LABELS = {
  cve_install_gate: 'Security advisory install gate',
  settle_time_gate: 'Settle-time gate',
  hotfix_successor_gate: 'Hotfix successor gate',
  field_visible_reports_opened: 'High-impact negative reports',
  verified_field_blocker_debt: 'Field blocker debt',
  open_unconfirmed_issue_risk: 'Open inherited/carryover context',
  stale_low_confidence_evidence: 'Stale or weak evidence',
  incomplete_classification_coverage: 'Incomplete classification coverage',
  incomplete_closure_evidence: 'Incomplete closure evidence',
  closed_issues_not_counted_as_release_fixes: 'Closed issue release proof',
  audit_only_closed_issue_flags: 'Audit-only closed issue flags',
  unverified_closed_fix_reachability: 'Unverified closed fix reachability',
  artifact_verification_incomplete: 'Incomplete artifact verification',
  missing_full_release_evidence_report: 'Missing full release evidence report',
  release_checks_failed: 'Failed release checks',
  release_checks_pending: 'Pending release checks',
  model_ceiling_and_capped_confidence: 'Model ceiling and capped confidence',
  no_remaining_score_gap: 'No remaining score gap',
  score_rounding: 'Final score rounding',
  no_verified_field_blocker_debt: 'No verified field-blocker debt',
  release_checks_passed: 'Release checks passed',
  artifact_verified: 'Artifact verified',
  release_recommended: 'Release recommended',
  hard_gates_passed: 'Install eligibility passed',
} as const;

const SCORE_EXPLANATION_LIMIT_ORDER = [
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

const SCORE_EXPLANATION_POSITIVE_ORDER = [
  'no_verified_field_blocker_debt',
  'release_checks_passed',
  'artifact_verified',
  'release_recommended',
  'hard_gates_passed',
] as const;

const SCORE_EXPLANATION_OPERATION_CODES: Record<string, readonly string[]> = {
  cve_install_gate: [
    'cveGatePredicate',
    'cveRawScore',
    'cveRangeClamp',
    'cveRound',
    'cveCounterfactualMinimum',
  ],
  settle_time_gate: ['settlePredicate', 'waitGate'],
  hotfix_successor_gate: ['hotfixPredicate', 'hotfixCeiling'],
  field_visible_reports_opened: ['regression'],
  verified_field_blocker_debt: ['verifiedDebt'],
  open_unconfirmed_issue_risk: ['carryoverDebt'],
  stale_low_confidence_evidence: ['staleDebt'],
  incomplete_classification_coverage: ['coverage'],
  incomplete_closure_evidence: ['closureRisk'],
  closed_issues_not_counted_as_release_fixes: [
    'closureRisk',
    'noticeableClosurePredicate',
    'heavyClosurePredicate',
    'closureRiskCeiling',
  ],
  audit_only_closed_issue_flags: ['closureRisk'],
  unverified_closed_fix_reachability: ['closureRisk'],
  artifact_verification_incomplete: ['artifactVerification'],
  missing_full_release_evidence_report: ['artifactVerification'],
  release_checks_failed: ['releaseVerification'],
  release_checks_pending: ['releaseVerification'],
  model_ceiling_and_capped_confidence: ['scoreRangeClamp', 'closureRiskCeiling', 'hotfixCeiling', 'finalRound'],
  no_remaining_score_gap: ['scoreRangeClamp', 'closureRiskCeiling', 'hotfixCeiling', 'finalRound'],
  score_rounding: ['finalRound'],
  no_verified_field_blocker_debt: [
    'verifiedDebt',
    'cveGatePredicate',
    'settlePredicate',
    'hotfixPredicate',
  ],
  release_checks_passed: ['releaseVerification'],
  artifact_verified: ['artifactVerification'],
  release_recommended: [
    'cveGatePredicate',
    'settlePredicate',
    'hotfixPredicate',
    'finalRound',
  ],
  hard_gates_passed: [
    'cveGatePredicate',
    'settlePredicate',
    'hotfixPredicate',
    'finalRound',
  ],
};

interface IssueSignalFields {
  issueNumber?: number;
  issueNodeId?: string | null;
  title?: string | null;
  duplicateCluster?: string | null;
  canonicalIssueNumbers?: readonly number[] | null;
  aliasGroup?: string | null;
  author?: string | null;
  authorNodeId?: string | null;
  authorType?: string | null;
  authorAssociation?: string | null;
  isBot?: boolean | number;
  comments?: number;
  uniqueHumanCommenterCount?: number;
  maintainerCommenterCount?: number;
  contributorCommenterCount?: number;
  commenterScanTruncated?: boolean | number;
  reactionTotal?: number;
  positiveReactionCount?: number;
  clusterHumanReporterCount?: number;
  clusterExternalReporterCount?: number;
  clusterCommentCount?: number;
  clusterHumanCommenterCount?: number;
  clusterMaintainerCommenterCount?: number;
  clusterContributorCommenterCount?: number;
  clusterReactionTotal?: number;
  clusterPositiveReactionCount?: number;
  clusterReleaseLocal?: boolean;
  humanReporterCount?: number;
  confirmationReasons?: ConfirmationReason[];
  installImpactClass?: string;
}

export interface FeltClassification extends IssueSignalFields {
  sentiment: string;
  severity: string;
  functionality: string;
  scope: string;
  affectedUsers: string;
  workaroundStatus?: string;
  confidence?: number;
  labels?: string[];
  releaseLocalEvidence?: ReleaseLocalEvidence;
}

export interface ReleaseLocalEvidence {
  kind: 'exact-version';
  source: 'title' | 'body' | 'comment';
  version: string;
  snippet: string;
  commentId?: number;
  commentUrl?: string;
  commentNodeId?: string;
  author?: string;
  actorNodeId?: string;
  actorType?: 'User';
  association?: string | null;
  occurredAt?: string;
  updatedAt?: string;
  commentBodyDigest?: string;
  authorityReference?: ScoreAuthorityReference;
}

export type ConfirmationReasonCode =
  | 'independent_human_reproduction'
  | 'human_applied_p0'
  | 'human_applied_p1'
  | 'human_applied_regression';

export interface ConfirmationReason {
  code: ConfirmationReasonCode;
  source: 'comment' | 'label_event';
  author: string;
  association?: string | null;
  occurredAt: string;
  updatedAt?: string;
  commentId?: number;
  commentUrl?: string;
  issueNodeId?: string;
  issueAuthorNodeId?: string;
  issueAuthorType?: string;
  commentNodeId?: string;
  commentNodeType?: 'IssueComment';
  actorNodeId?: string;
  actorType?: 'User';
  commentBodyDigest?: string;
  label?: 'P0' | 'P1' | 'regression';
  eventId?: string;
  snippet?: string;
  authorityReference: ScoreAuthorityReference;
}

export interface DebtClassification extends FeltClassification {
  workaroundStatus?: string;
  confidence?: number;
  state?: string;
  createdAt?: string | null;
  updatedAt?: string | null;
  affectsVersion?: string | null;
  releaseLocal?: boolean;
  releaseLocalEvidence?: ReleaseLocalEvidence;
  labels?: string[];
  debtClassification?: IssueClassification;
  debtClassificationDiff?: Record<string, { raw: unknown; effective: unknown }>;
}

export interface DebtLoads {
  verified: number;
  carryover: number;
  stale: number;
}

export interface DebtEvidenceItem {
  issueNumber?: number;
  duplicateCluster?: string | null;
  aliasGroup: string;
  tier: keyof DebtLoads;
  weight: number;
  adversePoints: number;
  releaseScopedState?: string;
  humanReporterCount?: number;
  commentCount?: number;
  fieldConfirmed?: boolean;
  humanCommenterCount?: number;
  maintainerCommenterCount?: number;
  contributorCommenterCount?: number;
  reactionTotal?: number;
  positiveReactionCount?: number;
  commenterScanTruncated?: boolean;
  confirmationReasons?: ConfirmationReason[];
  installImpactClass?: string;
  installImpactMultiplier?: number;
  clusterReleaseLocal?: boolean;
  releaseLocalEvidence?: ReleaseLocalEvidence;
  debtClassification?: IssueClassification;
  debtClassificationDiff?: Record<string, { raw: unknown; effective: unknown }>;
}

export interface DebtExplanation {
  loads: DebtLoads;
  evidence: DebtEvidenceItem[];
}

export interface FeltEvidenceItem {
  issueNumber?: number;
  duplicateCluster?: string | null;
  aliasGroup: string;
  weight: number;
  countedWeight: number;
  counted: boolean;
  fieldConfirmed: boolean;
  confirmationReasons: ConfirmationReason[];
  releaseLocalEvidence?: ReleaseLocalEvidence;
}

export interface FeltExplanation {
  load: number;
  evidence: FeltEvidenceItem[];
}

export type IssueRiskChannel = keyof DebtLoads | 'closureRisk' | 'regression';

export interface IssueRiskCandidate {
  aliasGroup: string;
  channel: IssueRiskChannel;
  weight: number;
  issueNumber?: number;
}

export interface IssueRiskLedgerGroup {
  aliasGroup: string;
  selectedChannel: IssueRiskChannel;
  selectedWeight: number;
  adversePoints: number;
  issueNumber?: number;
  candidates: Array<IssueRiskCandidate & { adversePoints: number }>;
}

export interface ExclusiveIssueRiskLedger {
  schemaVersion: 1;
  groups: IssueRiskLedgerGroup[];
  totalsByChannel: Record<IssueRiskChannel, number>;
}

export interface ExclusiveIssueRiskAccounting {
  debt: DebtExplanation;
  regression: FeltExplanation;
  closureRisk: AggregatedClosureRisk;
  ledger: ExclusiveIssueRiskLedger;
}

export interface ExclusiveIssueRiskLedgerOptions {
  maxSearchNodes?: number;
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

function ageHours(publishedAt: string | null, now: number): number | null {
  if (!publishedAt || !Number.isFinite(now)) return null;
  const published = Date.parse(publishedAt);
  if (!Number.isFinite(published) || published > now) return null;
  return (now - published) / HOUR_MS;
}

function survivalPoints(input: InstallInput, age: number): number {
  const exposureHours = input.isLatest ? age : input.hoursToNextStable;
  if (exposureHours == null) return 0;
  return clamp(
    Math.log2(Math.max(1, exposureHours) / PIVOT_HOURS) * 0.7,
    input.isLatest ? 0 : SURVIVAL_MIN,
    SURVIVAL_MAX,
  );
}

function shakeoutPoints(betaCount: number): number {
  return clamp(Math.log2(1 + Math.max(0, betaCount)) * 0.25, 0, SHAKEOUT_MAX);
}

function workaroundMultiplier(status: string | undefined): number {
  if (status === 'confirmed') return 0.35;
  if (status === 'partial') return 0.6;
  return 1;
}

function isBotIssue(item: IssueSignalFields): boolean {
  if (item.isBot === true || item.isBot === 1) return true;
  return /\[bot\]$|^openclaw-barnacle$/i.test(item.author ?? '');
}

function enrichIssueSignals<T extends IssueSignalFields>(items: T[]): Array<T & Required<Pick<IssueSignalFields,
  'clusterHumanReporterCount' |
  'clusterExternalReporterCount' |
  'clusterCommentCount' |
  'clusterHumanCommenterCount' |
  'clusterMaintainerCommenterCount' |
  'clusterContributorCommenterCount' |
  'clusterReactionTotal' |
  'clusterPositiveReactionCount'
>> & { aliasGroup: string }> {
  const aliasGroups = buildIssueAliasGroups(items);
  return items.map((item, index) => {
    const aliasGroup = aliasGroups.keyFor(item, index);
    const releaseLocal = (item as IssueSignalFields & { releaseLocal?: boolean }).releaseLocal;
    const humanReporterCount = Math.max(
      0,
      item.humanReporterCount ?? 0,
    );
    return {
      ...item,
      aliasGroup,
      clusterHumanReporterCount: humanReporterCount,
      clusterExternalReporterCount: humanReporterCount,
      clusterCommentCount: Math.max(0, item.comments ?? 0),
      clusterHumanCommenterCount: Math.max(0, item.uniqueHumanCommenterCount ?? 0),
      clusterMaintainerCommenterCount: Math.max(0, item.maintainerCommenterCount ?? 0),
      clusterContributorCommenterCount: Math.max(0, item.contributorCommenterCount ?? 0),
      clusterReactionTotal: Math.max(0, item.reactionTotal ?? 0),
      clusterPositiveReactionCount: Math.max(0, item.positiveReactionCount ?? 0),
      clusterReleaseLocal: typeof releaseLocal === 'boolean' ? releaseLocal : undefined,
    };
  });
}

function installImpactClassWithoutSecurity(item: DebtClassification): string {
  const title = `${item.title ?? ''} ${item.duplicateCluster ?? ''} ${item.issueNumber ?? ''}`.toLowerCase();
  const labels = item.labels ?? [];
  if (labels.includes('impact:auth-provider') || item.functionality === 'provider') return 'provider';
  if (/\b(pricing|catalog|model list|models cannot|unknown model|vertex|doubao|byteplus|openrouter|oauth|provider)\b/i.test(title)) {
    return 'provider';
  }
  if (labels.includes('impact:message-loss')) return 'message_delivery';
  if (labels.includes('impact:data-loss') || labels.includes('impact:session-state')) return 'state_data';
  if (/\b(installer|install|upgrade|migration|bootstrap|doctor|backup|memory store|session|transcript|cron)\b/i.test(title)) {
    return 'state_data';
  }
  return 'general';
}

function installImpactClass(item: DebtClassification): string {
  return item.labels?.includes('security')
    ? 'security'
    : installImpactClassWithoutSecurity(item);
}

function installImpactMultiplierForClass(klass: string): number {
  if (klass === 'provider') return 0.65;
  if (klass === 'message_delivery') return 0.9;
  if (klass === 'state_data') return 1;
  return 0.75;
}

function installImpactMultiplier(item: DebtClassification): number {
  const klass = installImpactClass(item);
  if (klass === 'security') {
    return installImpactMultiplierForClass(installImpactClassWithoutSecurity(item));
  }
  return installImpactMultiplierForClass(klass);
}

function issueDebtWeight(item: DebtClassification): number {
  if (!isUnresolvedDebtState(item.state)) return 0;
  if (item.sentiment !== 'negative') return 0;

  const severity = SEVERITY_WEIGHT[item.severity] ?? 0;
  const functionality = FUNCTIONALITY_WEIGHT[item.functionality] ?? 0;
  if (severity === 0 || functionality === 0) return 0;

  const reach =
    (SCOPE_WEIGHT[item.scope] ?? 1) *
    (USERS_WEIGHT[item.affectedUsers] ?? 0.65);
  // Classifier confidence is self-reported metadata. Scoring authority comes
  // from the cited classification fields and independently verified evidence.
  const sourceShape = isSourceOnlySignal(item) ? 0.8 : 1;
  return severity *
    functionality *
    reach *
    workaroundMultiplier(item.workaroundStatus) *
    installImpactMultiplier(item) *
    sourceShape;
}

function hasAnyLabel(item: { labels?: string[] }, names: string[]): boolean {
  return names.some((name) => item.labels?.includes(name));
}

function isWeakEvidence(item: DebtClassification): boolean {
  return (
    hasAnyLabel(item, ['stale', 'clawsweeper:needs-info', 'clawsweeper:needs-live-repro', 'enhancement']) ||
    item.functionality === 'docs' ||
    item.severity === 'low'
  );
}

const BOT_LOGIN_RE = /\[bot\]$|^(github-actions|dependabot|renovate(?:-bot)?|mergify|stale|clawsweeper|barnacle|openclaw-barnacle)$/i;
const ADVERSE_REPRODUCTION_CLAIM_RE = new RegExp([
  String.raw`\blive\s+repro\s+on\b`,
  String.raw`\bcorroborating\s+repro\s+on\b`,
  String.raw`\bindependent\s+confirmation\s+of\s+this\b`,
  String.raw`\bsame\s+class\s+of\s+(?:leakage|failure)\s+observed\b`,
  String.raw`\badditional\s+live\s+reproduction\s+details\b`,
  String.raw`\badditional\s+anonymized\s+reproduction\b`,
  String.raw`\bslack\s+reproduction\b`,
  String.raw`\bproduction\s+data\s+point\s+confirming\s+user-visible\s+message\s+loss\b`,
  String.raw`\b[0-9a-z_.-]+\s+is\s+also\s+affected\b`,
  String.raw`\bhit\s+the\s+same\s+class\s+of\s+failure\b`,
  String.raw`\b(?:i|we)\s+(?:also\s+)?(?:hit|encountered|experienced|saw)\s+(?:the\s+)?(?:same\s+)?(?:error|failure|crash|issue|problem)\b`,
  String.raw`\b(?:i|we)\s+hit\s+a\s+(?:case|failure)\b`,
  String.raw`\b(?:i|we)\s+(?:also\s+)?(?:can\s+)?reproduc(?:e|ed)\b`,
  String.raw`\bconfirm(?:ing|ed)?\s+(?:this\s+)?(?:still\s+)?reproduces?\b`,
  String.raw`\breproduced\s+(?:this|it|the\s+same\s+(?:issue|problem|failure|error))\b`,
  String.raw`\bstill\s+(?:broken|reproducing|reproducible)\b`,
  String.raw`\bstill\s+not\s+fixed\b`,
  String.raw`\b(?:this|it|the\s+(?:issue|problem|bug|failure|error|regression))\s+(?:still\s+)?persists?\b`,
  String.raw`\bpersists?\s+(?:on|in|after|with)\b`,
  String.raw`\b100\s*%\s+reproducible\b`,
  String.raw`\b(?:the\s+)?fix\s+does\s+not\s+(?:resolve|fix)\b`,
  String.raw`\bsame\s+issue\s+here\b`,
].join('|'), 'i');
const NEGATED_CONFIRMATION_RE = /\b(?:cannot|can't|could\s+not|couldn't|did\s+not|didn't|unable\s+to|not\s+able\s+to)\s+(?:confirm|reproduce)\b|\bnot\s+reproducible\b/i;
const VAGUE_SIMILAR_ISSUE_RE = /\b(?:a\s+)?similar\s+issues?\b/i;
const VAGUE_STATUS_CLAIM_RE = /\bstill\s+broken\b|\bstill\s+not\s+fixed\b|\b(?:this|it|the\s+(?:issue|problem|bug|failure|error|regression)|issue)\s+(?:still\s+)?persists?\b|\bsame\s+issue\s+here\b|\b[0-9a-z_.-]+\s+is\s+also\s+affected\b/i;
const CONCRETE_ADVERSE_DETAIL_RE = /\b(?:error|exception|trace|stack|exit(?:s|ed)?|crash(?:es|ed)?|hang(?:s|ing)?|timeout|deadlock|loop|drop(?:s|ped)?|lose|lost|corrupt(?:s|ed|ion)?|delete(?:s|d)?|disconnect(?:s|ed)?|fail(?:s|ed|ure)?|reject(?:s|ed)?|return(?:s|ed)?|emit(?:s|ted)?|skip(?:s|ped)?|missing|blank|empty|stuck|unresponsive|unusable|cannot|can't|does\s+not|doesn't|never)\b|(?:^|\s)(?:npm|pnpm|yarn|openclaw|docker|kubectl|curl|git)\s+\S+|`[^`]+`|\b(?:windows|macos|linux|ubuntu|debian|android|ios)\b/i;

export function adverseReproductionClaim(body: string): string | null {
  const claims = body
    .split(/\r?\n+|(?<=[.!?])\s+|;\s+/)
    .map((claim) => claim.trim())
    .filter(Boolean);
  return claims.find((claim) =>
    !NEGATED_CONFIRMATION_RE.test(claim) &&
    !VAGUE_SIMILAR_ISSUE_RE.test(claim) &&
    ADVERSE_REPRODUCTION_CLAIM_RE.test(claim) &&
    (
      !VAGUE_STATUS_CLAIM_RE.test(claim) ||
      CONCRETE_ADVERSE_DETAIL_RE.test(
        claim.replace(VAGUE_STATUS_CLAIM_RE, ''),
      )
    )
  ) ?? null;
}

export function scoreCommentBodyDigest(body: string): string {
  return createHash('sha256')
    .update(`score-comment-body-v1\0${body}`)
    .digest('hex');
}

export function semanticHumanConfirmationReasons(input: {
  issueNumber: number;
  issueNodeId?: string | null;
  issueAuthor?: IssueAuthorEvidenceIdentity | null;
  cutoff?: string | null;
  comments: CommentEvidenceRow[];
}): ConfirmationReason[] {
  if (!Number.isInteger(input.issueNumber) || input.issueNumber <= 0) return [];
  const issueNodeId = String(input.issueNodeId ?? '').trim();
  const issueAuthorNodeId = String(input.issueAuthor?.nodeId ?? '').trim();
  const issueAuthorType = String(input.issueAuthor?.actorType ?? '').trim();
  if (!issueNodeId || !issueAuthorNodeId || !issueAuthorType) return [];
  const cutoffMs = input.cutoff ? Date.parse(input.cutoff) : NaN;
  const reasons: ConfirmationReason[] = [];
  const seenActors = new Set<string>();
  for (const comment of input.comments) {
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
      actorIdentity.nodeType !== 'User' ||
      isExactIssueReporterComment(input.issueAuthor, comment)
    ) {
      continue;
    }
    const author = String(comment.user?.login ?? actorIdentity.nodeId).trim();
    const rawBody = String(comment.body ?? '');
    const body = rawBody.trim();
    const adverseClaim = adverseReproductionClaim(body);
    const commentId = Number(comment.id);
    const commentUrl = String(comment.url ?? '').trim();
    const occurredAt = comment.created_at ?? null;
    const updatedAt = comment.updated_at ?? occurredAt;
    if (
      !author ||
      !Number.isInteger(commentId) ||
      commentId <= 0 ||
      !commentUrl ||
      !occurredAt ||
      !Number.isFinite(Date.parse(occurredAt)) ||
      !body ||
      !adverseClaim
    ) {
      continue;
    }
    if (
      Number.isFinite(cutoffMs) &&
      (
        Date.parse(occurredAt) > cutoffMs ||
        !updatedAt ||
        !Number.isFinite(Date.parse(updatedAt)) ||
        Date.parse(updatedAt) > cutoffMs
      )
    ) {
      continue;
    }
    const actorKey = `${actorIdentity.nodeType}\0${actorIdentity.nodeId}`;
    if (seenActors.has(actorKey)) continue;
    seenActors.add(actorKey);
    const reasonWithoutAuthority = {
      code: 'independent_human_reproduction',
      source: 'comment',
      author,
      association: comment.author_association ?? null,
      occurredAt,
      updatedAt: updatedAt ?? occurredAt,
      commentId,
      commentUrl,
      issueNodeId,
      issueAuthorNodeId,
      issueAuthorType,
      commentNodeId: commentIdentity.nodeId,
      commentNodeType: commentIdentity.nodeType,
      actorNodeId: actorIdentity.nodeId,
      actorType: actorIdentity.nodeType,
      commentBodyDigest: scoreCommentBodyDigest(rawBody),
      snippet: evidenceSnippet(adverseClaim),
    } as const;
    try {
      const resolution = buildScoreCommentAuthorityResolution({
        issueNumber: input.issueNumber,
        issueNodeId,
        issueAuthorNodeId,
        issueAuthorType,
        commentNodeId: commentIdentity.nodeId,
        commentId,
        commentUrl,
        actorNodeId: actorIdentity.nodeId,
        actorType: actorIdentity.nodeType,
        commentCreatedAt: occurredAt,
        commentUpdatedAt: updatedAt ?? occurredAt,
        commentBodyDigest: reasonWithoutAuthority.commentBodyDigest,
        claimSnippet: reasonWithoutAuthority.snippet,
      });
      reasons.push({
        ...reasonWithoutAuthority,
        authorityReference: buildScoreAuthorityReference(
          'comment',
          commentIdentity.nodeId,
          resolution,
        ),
      });
    } catch {
      continue;
    }
  }
  return reasons;
}

export function fieldConfirmationFor(
  item: IssueSignalFields & { labels?: string[] },
): { confirmed: boolean; reasons: ConfirmationReason[] } {
  const reasons = trustedConfirmationReasons(item);
  return {
    confirmed: hasFieldConfirmation(item),
    reasons,
  };
}

function hasFieldConfirmation(item: IssueSignalFields & { labels?: string[] }): boolean {
  const reasons = trustedConfirmationReasons(item);
  const humanReproduction = reasons.some((reason) =>
    reason.code === 'independent_human_reproduction');
  const sourceOrReproRequired = hasAnyLabel(item, [
    'clawsweeper:source-repro',
    'clawsweeper:current-main-repro',
    'clawsweeper:needs-live-repro',
  ]);
  if (sourceOrReproRequired) return humanReproduction;
  if (humanReproduction) return true;
  const humanP0 = reasons.some((reason) => reason.code === 'human_applied_p0');
  const humanP1 = reasons.some((reason) => reason.code === 'human_applied_p1');
  const humanRegression = reasons.some((reason) => reason.code === 'human_applied_regression');
  return humanP0 || (
    humanP1 &&
    humanRegression &&
    hasAnyLabel(item, ['bug', 'bug:behavior'])
  );
}

function trustedConfirmationReasons(
  item: IssueSignalFields & { labels?: string[] },
): ConfirmationReason[] {
  return (item.confirmationReasons ?? []).filter((reason) => {
    const author = String(reason.author ?? '').trim();
    if (
      !author ||
      !reason.occurredAt ||
      !Number.isFinite(Date.parse(reason.occurredAt))
    ) {
      return false;
    }
    if (
      Object.hasOwn(reason, 'association') &&
      !(
        reason.association == null ||
        (
          typeof reason.association === 'string' &&
          reason.association.trim().length > 0
        )
      )
    ) {
      return false;
    }
    if (reason.source === 'comment') {
      if (
        Object.hasOwn(reason, 'label') ||
        Object.hasOwn(reason, 'eventId')
      ) {
        return false;
      }
      return reason.code === 'independent_human_reproduction' &&
        reason.issueNodeId === item.issueNodeId &&
        reason.issueAuthorNodeId === item.authorNodeId &&
        reason.issueAuthorType === item.authorType &&
        typeof reason.commentNodeId === 'string' &&
        reason.commentNodeId.length > 0 &&
        reason.commentNodeType === 'IssueComment' &&
        typeof reason.actorNodeId === 'string' &&
        reason.actorNodeId.length > 0 &&
        reason.actorType === 'User' &&
        !(
          reason.actorNodeId === reason.issueAuthorNodeId &&
          reason.actorType === reason.issueAuthorType
        ) &&
        typeof reason.updatedAt === 'string' &&
        Number.isFinite(Date.parse(reason.updatedAt)) &&
        Date.parse(reason.updatedAt) >= Date.parse(reason.occurredAt) &&
        typeof reason.commentBodyDigest === 'string' &&
        /^[0-9a-f]{64}$/.test(reason.commentBodyDigest) &&
        Number.isInteger(reason.commentId) &&
        Number(reason.commentId) > 0 &&
        typeof reason.commentUrl === 'string' &&
        reason.commentUrl.length > 0 &&
        typeof reason.snippet === 'string' &&
        adverseReproductionClaim(reason.snippet) != null &&
        trustedScoreAuthorityReference(
          reason.authorityReference,
          'comment',
          reason.commentNodeId,
        );
    }
    const expectedLabel = ({
      human_applied_p0: 'P0',
      human_applied_p1: 'P1',
      human_applied_regression: 'regression',
    } as Partial<Record<ConfirmationReasonCode, ConfirmationReason['label']>>)[reason.code];
    for (const key of [
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
    ] as const) {
      if (Object.hasOwn(reason, key)) return false;
    }
    return reason.source === 'label_event' &&
      expectedLabel != null &&
      reason.label === expectedLabel &&
      item.labels?.includes(expectedLabel) === true &&
      typeof reason.eventId === 'string' &&
      reason.eventId.length > 0 &&
      trustedScoreAuthorityReference(
        reason.authorityReference,
        'label_event',
        reason.eventId,
      );
  });
}

function trustedScoreAuthorityReference(
  reference: ScoreAuthorityReference | null | undefined,
  subjectKind: ScoreAuthorityReference['subjectKind'],
  subjectIdentity: string | null | undefined,
): reference is ScoreAuthorityReference {
  return scoreAuthorityReferenceProblems(reference).length === 0 &&
    reference?.subjectKind === subjectKind &&
    reference.subjectIdentity === subjectIdentity;
}

function evidenceSnippet(value: string, maxLength = 240): string {
  const compact = value.replace(/\s+/g, ' ').trim();
  return compact.length <= maxLength ? compact : `${compact.slice(0, maxLength - 3).trimEnd()}...`;
}

function isSourceOnlySignal(item: IssueSignalFields & { labels?: string[] }): boolean {
  return hasAnyLabel(item, ['clawsweeper:source-repro', 'clawsweeper:current-main-repro']) &&
    !hasFieldConfirmation(item);
}

function trustedReleaseLocalEvidence(
  evidence: ReleaseLocalEvidence | null | undefined,
): evidence is ReleaseLocalEvidence {
  if (
    !evidence ||
    evidence.kind !== 'exact-version' ||
    typeof evidence.version !== 'string' ||
    evidence.version.trim().length === 0 ||
    typeof evidence.snippet !== 'string' ||
    evidence.snippet.trim().length === 0
  ) {
    return false;
  }
  const commentFields = [
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
    'authorityReference',
  ] as const;
  if (evidence.source === 'title' || evidence.source === 'body') {
    return commentFields.every((key) => !Object.hasOwn(evidence, key));
  }
  if (evidence.source !== 'comment') return false;
  if (!commentFields.every((key) => Object.hasOwn(evidence, key))) return false;
  if (
    !Number.isInteger(evidence.commentId) ||
    Number(evidence.commentId) <= 0 ||
    typeof evidence.commentUrl !== 'string' ||
    evidence.commentUrl.trim().length === 0 ||
    typeof evidence.commentNodeId !== 'string' ||
    evidence.commentNodeId.trim().length === 0 ||
    typeof evidence.author !== 'string' ||
    evidence.author.trim().length === 0 ||
    typeof evidence.actorNodeId !== 'string' ||
    evidence.actorNodeId.trim().length === 0 ||
    evidence.actorType !== 'User' ||
    !(
      evidence.association == null ||
      (
        typeof evidence.association === 'string' &&
        evidence.association.trim().length > 0
      )
    ) ||
    typeof evidence.occurredAt !== 'string' ||
    !Number.isFinite(Date.parse(evidence.occurredAt)) ||
    typeof evidence.updatedAt !== 'string' ||
    !Number.isFinite(Date.parse(evidence.updatedAt)) ||
    Date.parse(evidence.updatedAt) < Date.parse(evidence.occurredAt) ||
    typeof evidence.commentBodyDigest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(evidence.commentBodyDigest) ||
    !trustedScoreAuthorityReference(
      evidence.authorityReference,
      'comment',
      evidence.commentNodeId,
    )
  ) {
    return false;
  }
  return true;
}

export function isDefaultPathImpact(
  item: Pick<DebtClassification, 'functionality' | 'scope' | 'affectedUsers' | 'labels'>,
): boolean {
  return item.functionality !== 'docs' &&
    item.functionality !== 'tooling' &&
    (
      item.scope === 'broad' ||
      item.affectedUsers === 'many' ||
      hasAnyLabel(item, [
        'P0',
        'beta-blocker',
        'impact:data-loss',
        'impact:message-loss',
        'impact:session-state',
        'impact:crash-loop',
      ])
    );
}

function classifyDebtTier(item: DebtClassification): keyof DebtLoads {
  const releaseSpecific =
    trustedReleaseLocalEvidence(item.releaseLocalEvidence) &&
    item.releaseLocal === true;
  const defaultPathImpact = isDefaultPathImpact(item);
  const weak = isWeakEvidence(item);

  if (
    releaseSpecific &&
    hasFieldConfirmation(item) &&
    defaultPathImpact &&
    !weak &&
    (item.severity === 'critical' || item.severity === 'high')
  ) return 'verified';
  if (weak || item.severity === 'medium' || isSourceOnlySignal(item)) return 'stale';
  return 'carryover';
}

// Bucket current open debt. Only release-local field/community evidence can
// become hard debt. Source-only/static findings remain visible as capped context.
export function explainOpenDebtLoad(items: DebtClassification[]): DebtExplanation {
  const enrichedItems = enrichIssueSignals(items.filter((item) => isUnresolvedDebtState(item.state)));
  const candidatesByKey = new Map<string, DebtEvidenceItem[]>();
  for (const item of enrichedItems) {
    const weight = issueDebtWeight(item);
    if (weight <= 0) continue;
    const tier = classifyDebtTier(item);
    const releaseLocalEvidence = trustedReleaseLocalEvidence(item.releaseLocalEvidence)
      ? item.releaseLocalEvidence
      : undefined;
    const key = item.aliasGroup;
    const adversePoints = debtAdversePoints(tier, weight);
    const candidates = candidatesByKey.get(key) ?? [];
    candidates.push({
      issueNumber: item.issueNumber,
      duplicateCluster: item.duplicateCluster,
      aliasGroup: key,
      tier,
      weight,
      adversePoints,
      releaseScopedState: item.state,
      humanReporterCount: item.humanReporterCount ?? 0,
      commentCount: item.comments,
      fieldConfirmed: hasFieldConfirmation(item),
      humanCommenterCount: item.uniqueHumanCommenterCount,
      maintainerCommenterCount: item.maintainerCommenterCount,
      contributorCommenterCount: item.contributorCommenterCount,
      reactionTotal: item.reactionTotal,
      positiveReactionCount: item.positiveReactionCount,
      commenterScanTruncated: item.commenterScanTruncated === true || item.commenterScanTruncated === 1,
      confirmationReasons: trustedConfirmationReasons(item),
      installImpactClass: installImpactClass(item),
      installImpactMultiplier: installImpactMultiplier(item),
      clusterReleaseLocal: releaseLocalEvidence ? item.releaseLocal : false,
      releaseLocalEvidence,
      debtClassification: item.debtClassification,
      debtClassificationDiff: item.debtClassificationDiff,
    });
    candidatesByKey.set(key, candidates);
  }
  const evidence = selectDebtEvidenceRepresentatives(candidatesByKey);
  const loads = debtLoadsForEvidence(evidence);
  return {
    loads,
    evidence: evidence.sort((a, b) => b.weight - a.weight),
  };
}

const DEBT_TIER_RANK: Record<keyof DebtLoads, number> = { verified: 3, carryover: 2, stale: 1 };

function shouldReplaceDebtEvidence(
  candidate: Pick<DebtEvidenceItem, 'tier' | 'weight' | 'adversePoints'>,
  previous: Pick<DebtEvidenceItem, 'tier' | 'weight' | 'adversePoints'>,
): boolean {
  if (candidate.adversePoints !== previous.adversePoints) {
    return candidate.adversePoints > previous.adversePoints;
  }
  if (candidate.weight !== previous.weight) return candidate.weight > previous.weight;
  const rankDiff = DEBT_TIER_RANK[candidate.tier] - DEBT_TIER_RANK[previous.tier];
  if (rankDiff !== 0) return rankDiff > 0;
  return false;
}

function compareDebtEvidenceCandidates(
  left: DebtEvidenceItem,
  right: DebtEvidenceItem,
): number {
  if (shouldReplaceDebtEvidence(left, right)) return -1;
  if (shouldReplaceDebtEvidence(right, left)) return 1;
  return Number(left.issueNumber ?? Number.MAX_SAFE_INTEGER) -
    Number(right.issueNumber ?? Number.MAX_SAFE_INTEGER);
}

function selectDebtEvidenceRepresentatives(
  candidatesByKey: ReadonlyMap<string, readonly DebtEvidenceItem[]>,
): DebtEvidenceItem[] {
  const groups = [...candidatesByKey.entries()]
    .map(([key, candidates]) => ({
      key,
      candidates: candidates.slice().sort(compareDebtEvidenceCandidates),
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
  return groups.map((group) => group.candidates[0]);
}

export function openDebtLoad(items: DebtClassification[]): DebtLoads {
  return explainOpenDebtLoad(items).loads;
}

// Reach-weighted visible-bug load used for the opened/closed reign balance.
export function feltLoad(items: FeltClassification[]): number {
  return explainFeltLoad(items).load;
}

export function explainFeltLoad(items: FeltClassification[]): FeltExplanation {
  const byIssue = new Map<string, number>();
  const enriched = enrichIssueSignals(items);
  const rawWeights = enriched.map((item) => {
    if (!isFeltSignal(item)) return 0;
    const weight = (SCOPE_WEIGHT[item.scope] ?? 1)
      * (USERS_WEIGHT[item.affectedUsers] ?? 0.65)
      * workaroundMultiplier(item.workaroundStatus);
    const key = item.aliasGroup;
    byIssue.set(key, Math.max(byIssue.get(key) ?? 0, weight));
    return weight;
  });
  const countedKeys = new Set<string>();
  const evidence = enriched.map((item, index) => {
    const key = item.aliasGroup;
    const weight = rawWeights[index];
    const counted = weight > 0 && !countedKeys.has(key) && weight === byIssue.get(key);
    if (counted) countedKeys.add(key);
    return {
      issueNumber: item.issueNumber,
      duplicateCluster: item.duplicateCluster,
      aliasGroup: key,
      weight,
      countedWeight: counted ? weight : 0,
      counted,
      fieldConfirmed: hasFieldConfirmation(item),
      confirmationReasons: trustedConfirmationReasons(item),
      releaseLocalEvidence: trustedReleaseLocalEvidence(item.releaseLocalEvidence)
        ? item.releaseLocalEvidence
        : undefined,
    };
  });
  return {
    load: [...byIssue.values()].reduce((sum, weight) => sum + weight, 0),
    evidence,
  };
}

export function feltSignalMask(items: FeltClassification[]): boolean[] {
  return enrichIssueSignals(items).map((item) => isFeltSignal(item));
}

export function isFeltSignal(item: FeltClassification): boolean {
  if (item.sentiment !== 'negative') return false;
  if (!['core', 'integration', 'provider'].includes(item.functionality)) return false;
  if (!['critical', 'high'].includes(item.severity)) return false;
  if (hasAnyLabel(item, ['clawsweeper:needs-info', 'clawsweeper:needs-live-repro', 'stale', 'enhancement'])) {
    return false;
  }
  if (isSourceOnlySignal(item)) return false;
  return true;
}

function verifiedDebtPoints(load: number): number {
  return clamp(-Math.log1p(Math.max(0, load)) * 0.35, VERIFIED_DEBT_MAX, 0);
}

function carryoverDebtPoints(_load: number): number {
  return 0;
}

function staleDebtPoints(load: number): number {
  return clamp(-Math.log1p(Math.max(0, load)) * 0.05, STALE_DEBT_MAX, 0);
}

function closureRiskPoints(load: number): number {
  return clamp(-Math.log1p(Math.max(0, load)) * 0.08, CLOSURE_RISK_MAX, 0);
}

function closureRiskScoreCeiling(input: InstallInput): number {
  const weight = Math.max(0, input.affirmativeClosureRiskCeilingWeight ?? 0);
  if (weight >= HEAVY_CLOSURE_RISK_THRESHOLD) {
    return HEAVY_CLOSURE_SCORE_CAP;
  }
  if (weight >= NOTICEABLE_CLOSURE_RISK_THRESHOLD) {
    return NOTICEABLE_CLOSURE_SCORE_CAP;
  }
  return 0;
}

function coveragePoints(rawIssueCount: number, classifiedIssueCount: number): {
  points: number;
  ratio: number;
} {
  if (rawIssueCount <= 0) return { points: 0, ratio: 1 };
  const ratio = clamp(classifiedIssueCount / rawIssueCount, 0, 1);
  if (ratio >= 0.95) return { points: 0, ratio };
  if (ratio >= 0.8) return { points: -0.8, ratio };
  return { points: COVERAGE_MAX, ratio };
}

function regressionPoints(openedWeight: number, closedWeight: number): number {
  const opened = Math.max(0, openedWeight);
  const closed = Math.max(0, closedWeight);
  const total = opened + closed + PRIOR;
  const penalty = -(opened / total) * 1.1;
  const credit = (closed / total) * 0.8;
  return clamp(penalty + credit, REGRESSION_DOWN, REGRESSION_UP);
}

export function buildExclusiveIssueRiskLedger(
  candidates: readonly IssueRiskCandidate[],
  _options: ExclusiveIssueRiskLedgerOptions = {},
): ExclusiveIssueRiskLedger {
  const candidatesByGroup = new Map<string, Array<IssueRiskCandidate & { adversePoints: number }>>();
  for (const candidate of candidates) {
    if (!candidate.aliasGroup) continue;
    if (!Number.isFinite(candidate.weight)) {
      throw new Error(
        `Exclusive issue risk candidate ${candidate.aliasGroup}/${candidate.channel} has a non-finite weight`,
      );
    }
    if (candidate.weight <= 0) continue;
    const adversePoints = issueRiskAdversePoints(candidate.channel, candidate.weight);
    const groupCandidates = candidatesByGroup.get(candidate.aliasGroup) ?? [];
    groupCandidates.push({ ...candidate, adversePoints });
    candidatesByGroup.set(candidate.aliasGroup, groupCandidates);
  }

  const candidateGroups = [...candidatesByGroup.entries()]
    .map(([aliasGroup, groupCandidates]) => ({
      key: aliasGroup,
      candidates: groupCandidates.slice().sort(compareRiskCandidates),
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
  const groups = candidateGroups.map(({ key: aliasGroup, candidates: groupCandidates }): IssueRiskLedgerGroup => {
    const selected = groupCandidates[0];
    return {
      aliasGroup,
      selectedChannel: selected.channel,
      selectedWeight: selected.weight,
      adversePoints: selected.adversePoints,
      issueNumber: selected.issueNumber,
      candidates: groupCandidates,
    };
  });
  const totalsByChannel: Record<IssueRiskChannel, number> = {
    verified: 0,
    carryover: 0,
    stale: 0,
    closureRisk: 0,
    regression: 0,
  };
  for (const group of groups) totalsByChannel[group.selectedChannel] += group.selectedWeight;
  return { schemaVersion: 1, groups, totalsByChannel };
}

export function applyExclusiveIssueRiskLedger(input: {
  debt: DebtExplanation;
  regression: FeltExplanation;
  closureRisk: AggregatedClosureRisk;
}): ExclusiveIssueRiskAccounting {
  const ledger = buildExclusiveIssueRiskLedger([
    ...input.debt.evidence.map((item) => ({
      aliasGroup: item.aliasGroup,
      channel: item.tier,
      weight: item.weight,
      issueNumber: item.issueNumber,
    })),
    ...input.regression.evidence
      .filter((item) => item.counted && item.countedWeight > 0)
      .map((item) => ({
        aliasGroup: item.aliasGroup,
        channel: 'regression' as const,
        weight: item.countedWeight,
        issueNumber: item.issueNumber,
      })),
    ...input.closureRisk.groups.map((item) => ({
      aliasGroup: item.key,
      channel: 'closureRisk' as const,
      weight: item.weight,
      issueNumber: item.issueNumber,
    })),
  ]);
  const selectedByGroup = new Map(
    ledger.groups.map((group) => [group.aliasGroup, group.selectedChannel]),
  );
  const debtEvidence = input.debt.evidence.filter((item) =>
    selectedByGroup.get(item.aliasGroup) === item.tier
  );
  const regressionEvidence = input.regression.evidence.map((item) => {
    const counted = item.counted &&
      selectedByGroup.get(item.aliasGroup) === 'regression';
    return {
      ...item,
      counted,
      countedWeight: counted ? item.weight : 0,
    };
  });
  const closureGroups = input.closureRisk.groups.filter((item) =>
    selectedByGroup.get(item.key) === 'closureRisk'
  );
  const weightedRiskByDisposition: Record<string, number> = {};
  for (const group of closureGroups) {
    weightedRiskByDisposition[group.disposition] =
      (weightedRiskByDisposition[group.disposition] ?? 0) + group.weight;
  }
  return {
    debt: {
      loads: debtLoadsForEvidence(debtEvidence),
      evidence: debtEvidence,
    },
    regression: {
      load: regressionEvidence.reduce((sum, item) => sum + item.countedWeight, 0),
      evidence: regressionEvidence,
    },
    closureRisk: {
      unresolvedForReleaseCount: closureGroups.length,
      unresolvedWeightedRisk: closureGroups.reduce((sum, item) => sum + item.weight, 0),
      weightedRiskByDisposition,
      groups: closureGroups,
    },
    ledger,
  };
}

export function debtLoadsForEvidence(evidence: readonly DebtEvidenceItem[]): DebtLoads {
  return {
    verified: evidence
      .filter((item) => item.tier === 'verified')
      .reduce((sum, item) => sum + item.weight, 0),
    carryover: evidence
      .filter((item) => item.tier === 'carryover')
      .reduce((sum, item) => sum + item.weight, 0),
    stale: evidence
      .filter((item) => item.tier === 'stale')
      .reduce((sum, item) => sum + item.weight, 0),
  };
}

function breakingPoints(breakingCount: number): number {
  return Math.max(
    BREAKING_PER_BULLET * BREAKING_MAX_BULLETS,
    BREAKING_PER_BULLET * Math.max(0, breakingCount),
  );
}

function releaseVerificationPoints(input: InstallInput): number {
  const total = Math.max(0, input.releaseCheckTotal ?? 0);
  if (total === 0 && !input.releaseCheckState) return 0;
  const state = (input.releaseCheckState ?? '').toUpperCase();
  const failures = Math.max(0, input.releaseCheckFailure ?? 0);
  const pending = Math.max(0, input.releaseCheckPending ?? 0);
  const successes = Math.max(0, input.releaseCheckSuccess ?? 0);
  const failurePenalty = failures > 0 || ['FAILURE', 'ERROR', 'ACTION_REQUIRED'].includes(state)
    ? clamp(-0.8 - Math.log1p(failures) * 0.25, RELEASE_CHECK_DOWN, 0)
    : 0;
  const pendingPenalty = pending > 0 || ['PENDING', 'EXPECTED'].includes(state)
    ? clamp(-0.25 - Math.log1p(pending) * 0.08, RELEASE_CHECK_DOWN, 0)
    : 0;
  if (failurePenalty < 0 || pendingPenalty < 0) {
    return Math.min(failurePenalty, pendingPenalty);
  }
  if (state === 'SUCCESS' && successes > 0) {
    return clamp(Math.log1p(successes) * 0.18, 0, RELEASE_CHECK_UP);
  }
  return 0;
}

function artifactVerificationPoints(input: InstallInput): number {
  if (input.artifactMismatch) return ARTIFACT_DOWN;
  let points = 0;
  if (input.artifactVerified && input.releaseIntegrityPresent && input.releaseShaMatches === true) {
    points += 0.25;
  }
  if (input.ciReportVerified) points += 0.1;
  else if (input.ciReportMismatch) points -= 0.15;
  return clamp(points, ARTIFACT_DOWN, ARTIFACT_UP);
}

export function cveDecayLoad(items: Array<{ severity: string; distance: number }>): number {
  const severityWeight: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };
  return items.reduce((load, item) => {
    const severity = severityWeight[item.severity] ?? 0;
    const distance = Math.max(0, item.distance);
    if (!severity || distance >= 10) return load;
    return load + severity * Math.pow(0.3, distance);
  }, 0);
}

export function bandFor(score: number | null, status: InstallStatus): InstallBand {
  if (status === 'wait') return 'wait';
  if (status === 'skip-cve' || status === 'skip-hotfix') return 'skip';
  if (score == null) return 'wait';
  if (score >= 8) return 'solid';
  if (score >= 7) return 'ok';
  if (score >= 5.5) return 'caution';
  return 'weak';
}

function reasonFor(
  input: InstallInput,
  status: InstallStatus,
  age: number | null,
  coverage: number,
  debt: DebtLoads,
): string {
  if (status === 'skip-cve') return 'known medium-or-higher security advisory exposure';
  if (status === 'wait') {
    return age == null
      ? 'publication date unavailable, invalid, or in the future — no settle signal yet'
      : `only ${(age / 24).toFixed(1)}d old — no settle signal yet`;
  }
  if (status === 'skip-hotfix') {
    return input.hasHotfixSuccessor
      ? 'maintainers shipped a hotfix patch on top of it'
      : `replaced by the next stable within ${Math.round(input.hoursToNextStable ?? 0)}h`;
  }
  if (age == null) return 'publication date unavailable, invalid, or in the future';

  const bits: string[] = [];
  if (input.isLatest) {
    bits.push(`latest — stood ${(age / 24).toFixed(1)}d with no hotfix`);
  } else if (input.hoursToNextStable != null) {
    bits.push(`stood ${input.hoursToNextStable >= 24
      ? `${(input.hoursToNextStable / 24).toFixed(1)}d`
      : `${Math.round(input.hoursToNextStable)}h`} as current stable`);
  }
  const verifiedDebtCount = positiveInteger(input.verifiedDebtIssueCount);
  if (debt.verified > 0 || verifiedDebtCount != null) {
    const count = verifiedDebtCount;
    bits.push(count == null
      ? `${Math.round(debt.verified)} field-confirmed blocker risk`
      : `${count} field-confirmed blocker ${plural(count, 'issue', 'issues')} (risk weight ${Math.round(debt.verified)})`);
  }
  const carryoverDebtCount = positiveInteger(input.carryoverDebtIssueCount);
  if (debt.carryover > 0 || carryoverDebtCount != null) {
    const count = carryoverDebtCount;
    bits.push(count == null
      ? `${Math.round(debt.carryover)} inherited/carryover audit weight (0 score points)`
      : `${count} inherited/carryover ${plural(count, 'issue group', 'issue groups')} ` +
        `(audit weight ${Math.round(debt.carryover)}; 0 score points)`);
  }
  if (input.unresolvedClosureRiskWeight > 0) {
    const count = positiveInteger(input.unresolvedClosureIssueCount);
    bits.push(count == null
      ? `${Math.round(input.unresolvedClosureRiskWeight)} unresolved closed-release risk`
      : `${count} unresolved closed-release risk ${plural(count, 'group', 'groups')} (risk weight ${Math.round(input.unresolvedClosureRiskWeight)})`);
  }
  if (
    input.affirmativeClosureRiskCeilingWeight > 0 &&
    input.affirmativeClosureRiskCeilingWeight !== input.unresolvedClosureRiskWeight
  ) {
    bits.push(
      `${Math.round(input.affirmativeClosureRiskCeilingWeight)} deduplicated affirmative ` +
      `closure-risk ceiling weight`,
    );
  }
  if (input.feltClosedWeight > input.feltOpenedWeight && input.feltClosedWeight > 2) {
    bits.push('net-fixing high-impact reports');
  } else if (input.feltOpenedWeight > input.feltClosedWeight && input.feltOpenedWeight > 2) {
    bits.push('net-opening high-impact reports');
  }
  if ((input.releaseCheckFailure ?? 0) > 0) {
    bits.push(`${input.releaseCheckFailure} failed release checks`);
  } else if ((input.releaseCheckPending ?? 0) > 0) {
    bits.push(`${input.releaseCheckPending} pending release checks`);
  } else if ((input.releaseCheckSuccess ?? 0) > 0 && (input.releaseCheckState ?? '').toUpperCase() === 'SUCCESS') {
    bits.push(`${input.releaseCheckSuccess} release checks passed`);
  }
  if (input.artifactMismatch) {
    bits.push('artifact verification mismatch');
  } else if (input.artifactVerified && input.releaseShaMatches === true) {
    bits.push('npm artifact verified');
  } else if (input.artifactVerified) {
    bits.push('artifact release binding unverified');
  }
  if (input.ciReportMismatch) bits.push('release evidence report missing');
  if (input.betaCount > 0) bits.push(`${input.betaCount} betas baked`);
  if (input.breakingCount > 0) bits.push(`${input.breakingCount} breaking`);
  if (coverage < 0.95) bits.push(`${Math.round(coverage * 100)}% evidence coverage`);
  return bits.join(', ') || 'no adverse signal';
}

function positiveInteger(value: number | undefined): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  const rounded = Math.round(value);
  return rounded > 0 ? rounded : null;
}

function plural(count: number, singular: string, pluralText: string): string {
  return count === 1 ? singular : pluralText;
}

export function installConfidence(input: InstallInput, now: number = Date.now()): InstallConfidence {
  assertFiniteInstallInputWeights(input);
  const age = ageHours(input.publishedAt, now);
  const coverage = coveragePoints(input.rawIssueCount, input.classifiedIssueCount);
  const hotfix =
    !input.isLatest &&
    (input.hasHotfixSuccessor ||
      (input.hoursToNextStable != null && input.hoursToNextStable < HOTFIX_GAP_HOURS));

  if (input.cveAffected) {
    const cveLoad = Number.isFinite(input.cveLoad) ? Math.max(0, input.cveLoad) : 0;
    const gateScore = round1(clamp(4.9 * (1 - Math.min(1, cveLoad / 30)), 0, 4.9));
    const ungatedScore = installConfidence({
      ...input,
      cveAffected: false,
      cveLoad: 0,
    }, now).score;
    const score = ungatedScore == null ? gateScore : Math.min(gateScore, ungatedScore);
    return {
      score,
      status: 'skip-cve',
      band: 'skip',
      hotfix,
      components: null,
      scoreRangeClamp: null,
      evidenceCoverage: coverage.ratio,
      reason: reasonFor(input, 'skip-cve', age, coverage.ratio, {
        verified: input.verifiedDebtWeight,
        carryover: input.carryoverDebtWeight,
        stale: input.staleDebtWeight,
      }),
    };
  }

  if (age == null || age < SETTLE_HOURS) {
    return {
      score: null,
      status: 'wait',
      band: 'wait',
      hotfix,
      components: null,
      scoreRangeClamp: null,
      evidenceCoverage: coverage.ratio,
      reason: reasonFor(input, 'wait', age, coverage.ratio, {
        verified: input.verifiedDebtWeight,
        carryover: input.carryoverDebtWeight,
        stale: input.staleDebtWeight,
      }),
    };
  }

  const verifiedDebt = verifiedDebtPoints(input.verifiedDebtWeight);
  const carryoverDebt = carryoverDebtPoints(input.carryoverDebtWeight);
  const staleDebt = staleDebtPoints(input.staleDebtWeight);
  const closureRisk = closureRiskPoints(input.unresolvedClosureRiskWeight);
  const survival = survivalPoints(input, age);
  const shakeout = shakeoutPoints(input.betaCount);
  const regression = regressionPoints(input.feltOpenedWeight, input.feltClosedWeight);
  const breaking = breakingPoints(input.breakingCount);
  const releaseVerification = releaseVerificationPoints(input);
  const artifactVerification = artifactVerificationPoints(input);
  const closureRiskCeiling = closureRiskScoreCeiling(input);
  const scoreBeforeRangeClamp =
    BASE + verifiedDebt + carryoverDebt + staleDebt + closureRisk + coverage.points +
    survival + shakeout + regression + breaking + releaseVerification + artifactVerification;
  let score = clamp(scoreBeforeRangeClamp, 0, 10);
  const scoreRangeClamp = score - scoreBeforeRangeClamp;
  if (closureRiskCeiling > 0) score = Math.min(score, closureRiskCeiling);
  if (hotfix) score = Math.min(score, HOTFIX_SCORE_CAP);

  const rounded = round1(score);
  return {
    score: rounded,
    status: hotfix ? 'skip-hotfix' : 'eligible',
    band: bandFor(rounded, hotfix ? 'skip-hotfix' : 'eligible'),
    hotfix,
    components: {
      // Preserve calculation precision; ledger/UI layers own display rounding.
      base: BASE,
      verifiedDebt,
      carryoverDebt,
      staleDebt,
      closureRisk,
      closureRiskCeiling,
      coverage: coverage.points,
      survival,
      shakeout,
      regression,
      breaking,
      releaseVerification,
      artifactVerification,
    },
    scoreRangeClamp,
    evidenceCoverage: coverage.ratio,
    reason: reasonFor(input, hotfix ? 'skip-hotfix' : 'eligible', age, coverage.ratio, {
      verified: input.verifiedDebtWeight,
      carryover: input.carryoverDebtWeight,
      stale: input.staleDebtWeight,
    }),
  };
}

const SCORE_LEDGER_EVIDENCE_KEYS = [
  'release',
  'verifiedDebt',
  'carryoverDebt',
  'staleDebt',
  'closureRisk',
  'closureCeiling',
  'regressionOpened',
  'regressionFixed',
  'coverage',
  'releaseChecks',
  'artifact',
  'advisories',
  'scoreAuthority',
  'aliasElection',
] as const;

const SCORE_LEDGER_RISK_EVIDENCE = {
  verified: {
    manifestKey: 'verifiedDebt',
    inputField: 'verifiedDebtWeight',
  },
  carryover: {
    manifestKey: 'carryoverDebt',
    inputField: 'carryoverDebtWeight',
  },
  stale: {
    manifestKey: 'staleDebt',
    inputField: 'staleDebtWeight',
  },
  closureRisk: {
    manifestKey: 'closureRisk',
    inputField: 'unresolvedClosureRiskWeight',
  },
  regression: {
    manifestKey: 'regressionOpened',
    inputField: 'feltOpenedWeight',
  },
} as const satisfies Record<
  IssueRiskChannel,
  {
    manifestKey: typeof SCORE_LEDGER_EVIDENCE_KEYS[number];
    inputField: keyof InstallInput;
  }
>;

const SCORE_LEDGER_COMPONENT_PRESENTATION = {
  base: {
    label: 'Base',
    note: 'Starting confidence for an eligible stable before evidence adjustments.',
  },
  verifiedDebt: {
    label: 'Field blocker debt',
    note: 'Release-local field/community blocker evidence.',
  },
  carryoverDebt: {
    label: 'Open inherited/carryover context',
    note: 'Linked inherited or carryover debt retained for audit; it contributes zero score points.',
  },
  staleDebt: {
    label: 'Weak or stale evidence',
    note: 'Weak or stale evidence risk, heavily capped.',
  },
  closureRisk: {
    label: 'Closed-issue proof gap',
    note: 'Closed issues not proven fixed in this release tag.',
  },
  coverage: {
    label: 'Classification coverage',
    note: 'Penalty only when attributed issue classification coverage is incomplete.',
  },
  survival: {
    label: 'Stable survival',
    note: 'Observed stable exposure before replacement or at the score timestamp.',
  },
  shakeout: {
    label: 'Beta shakeout',
    note: 'Small reward for beta/prerelease bake time.',
  },
  regression: {
    label: 'Opened vs fixed balance',
    note: 'Weighted, deduplicated high-impact reports opened versus first-containing verified fixes.',
  },
  breaking: {
    label: 'Breaking changes',
    note: 'Penalty for documented breaking changes in the stable/beta chain.',
  },
  releaseVerification: {
    label: 'Release checks',
    note: 'Release commit check confidence.',
  },
  artifactVerification: {
    label: 'Artifact verification',
    note: 'Downloaded npm tarball bytes, registry SRI, release binding, and release evidence verification.',
  },
} as const;

export function buildScoreLedgerV2(args: BuildScoreLedgerV2Input): ScoreLedgerV2 {
  const recomputed = installConfidence(args.input, args.now);
  assertLedgerConfidenceMatches(args.confidence, recomputed);
  const confidence = recomputed;
  const aliasLedger = cloneJson(args.aliasElection ?? {
    schemaVersion: 1,
    groups: [],
    totalsByChannel: {
      verified: 0,
      carryover: 0,
      stale: 0,
      closureRisk: 0,
      regression: 0,
    },
  }) as ExclusiveIssueRiskLedger;
  assertExclusiveIssueRiskLedger(aliasLedger);
  assertAliasElectionMatchesInput(aliasLedger, args.input);
  const evidence = buildScoreLedgerEvidenceBundle(args.evidenceSources ?? [], aliasLedger);
  assertScoreLedgerRiskEvidenceCoupling(aliasLedger, evidence, args.input);
  const manifestDigestByKey = new Map(
    evidence.manifests.map((manifest) => [manifest.key, manifest.digest]),
  );
  const operations: ScoreLedgerOperation[] = [];
  let current: number | null = null;

  const addOperation = (operation: Omit<ScoreLedgerOperation, 'sequence' | 'evidenceDigest'>) => {
    const evidenceDigest = scoreLedgerDigest(
      operation.evidenceManifestKeys
        .slice()
        .sort()
        .map((key) => ({ key, digest: manifestDigestByKey.get(key) ?? null })),
    );
    operations.push({
      sequence: operations.length,
      ...operation,
      evidenceDigest,
    });
  };
  const addPredicate = (
    code: string,
    label: string,
    formulaCode: string,
    operands: ScoreLedgerOperand[],
    result: boolean,
    evidenceManifestKeys: string[],
  ) => addOperation({
    code,
    label,
    kind: 'predicate',
    formulaCode,
    operands,
    rawPoints: null,
    boundedPoints: null,
    bounds: { min: null, max: null },
    before: current,
    after: current,
    applied: result,
    predicateResult: result,
    evidenceManifestKeys,
  });
  const addComponent = (
    code: keyof typeof SCORE_LEDGER_COMPONENT_PRESENTATION,
    formulaCode: string,
    operands: ScoreLedgerOperand[],
    rawPoints: number,
    boundedPoints: number,
    bounds: ScoreLedgerBounds,
    evidenceManifestKeys: string[],
  ) => {
    const before = current ?? 0;
    const after = before + boundedPoints;
    addOperation({
      code,
      label: SCORE_LEDGER_COMPONENT_PRESENTATION[code].label,
      kind: 'component',
      formulaCode,
      operands,
      rawPoints,
      boundedPoints,
      bounds,
      before,
      after,
      applied: boundedPoints !== 0 || code === 'base',
      predicateResult: null,
      evidenceManifestKeys,
    });
    current = after;
  };
  const addSuppressedComponent = (
    code: keyof typeof SCORE_LEDGER_COMPONENT_PRESENTATION,
    formulaCode: string,
    operands: ScoreLedgerOperand[],
    rawPoints: number,
    boundedPoints: number,
    bounds: ScoreLedgerBounds,
    evidenceManifestKeys: string[],
  ) => {
    addOperation({
      code,
      label: SCORE_LEDGER_COMPONENT_PRESENTATION[code].label,
      kind: 'component',
      formulaCode,
      operands: [
        ...operands,
        ledgerOperand('suppressedByStatus', confidence.status, 'status'),
      ],
      rawPoints,
      boundedPoints,
      bounds,
      before: current,
      after: current,
      applied: false,
      predicateResult: null,
      evidenceManifestKeys,
    });
  };
  const addTransform = (
    code: string,
    label: string,
    kind: 'clamp' | 'cap' | 'round' | 'gate',
    formulaCode: string,
    operands: ScoreLedgerOperand[],
    after: number | null,
    bounds: ScoreLedgerBounds,
    evidenceManifestKeys: string[],
  ) => {
    const before = current;
    addOperation({
      code,
      label,
      kind,
      formulaCode,
      operands,
      rawPoints: before,
      boundedPoints: after,
      bounds,
      before,
      after,
      applied: !sameLedgerNumber(before, after),
      predicateResult: null,
      evidenceManifestKeys,
    });
    current = after;
  };

  const age = ageHours(args.input.publishedAt, args.now);
  const hotfix =
    !args.input.isLatest &&
    (
      args.input.hasHotfixSuccessor ||
      args.input.hoursToNextStable != null && args.input.hoursToNextStable < HOTFIX_GAP_HOURS
    );
  const closureWeight = Math.max(0, args.input.affirmativeClosureRiskCeilingWeight ?? 0);
  addPredicate(
    'cveGatePredicate',
    'Security advisory gate predicate',
    'predicate.cve_affected.v1',
    [ledgerOperand('cveAffected', args.input.cveAffected, 'boolean')],
    args.input.cveAffected,
    ['advisories'],
  );
  addPredicate(
    'settlePredicate',
    'Settle-time predicate',
    'predicate.age_gte_settle_hours.v1',
    [
      ledgerOperand('ageHours', age, 'hours'),
      ledgerOperand('settleHours', SETTLE_HOURS, 'hours'),
    ],
    age != null && age >= SETTLE_HOURS,
    ['release'],
  );
  addPredicate(
    'hotfixPredicate',
    'Hotfix successor predicate',
    'predicate.hotfix_successor_or_gap_lt.v1',
    [
      ledgerOperand('isLatest', args.input.isLatest, 'boolean'),
      ledgerOperand('hasHotfixSuccessor', args.input.hasHotfixSuccessor, 'boolean'),
      ledgerOperand('hoursToNextStable', args.input.hoursToNextStable, 'hours'),
      ledgerOperand('hotfixGapHours', HOTFIX_GAP_HOURS, 'hours'),
    ],
    hotfix,
    ['release'],
  );
  addPredicate(
    'noticeableClosurePredicate',
    'Noticeable closure-risk predicate',
    'predicate.closure_weight_gte_noticeable.v1',
    [
      ledgerOperand('affirmativeClosureRiskCeilingWeight', closureWeight, 'weight'),
      ledgerOperand('threshold', NOTICEABLE_CLOSURE_RISK_THRESHOLD, 'weight'),
    ],
    closureWeight >= NOTICEABLE_CLOSURE_RISK_THRESHOLD,
    ['closureCeiling'],
  );
  addPredicate(
    'heavyClosurePredicate',
    'Heavy closure-risk predicate',
    'predicate.closure_weight_gte_heavy.v1',
    [
      ledgerOperand('affirmativeClosureRiskCeilingWeight', closureWeight, 'weight'),
      ledgerOperand('threshold', HEAVY_CLOSURE_RISK_THRESHOLD, 'weight'),
    ],
    closureWeight >= HEAVY_CLOSURE_RISK_THRESHOLD,
    ['closureCeiling'],
  );

  const addSuppressedExplanationComponents = () => {
    const coverage = coveragePoints(
      args.input.rawIssueCount,
      args.input.classifiedIssueCount,
    );
    addSuppressedComponent(
      'verifiedDebt',
      'component.verified_debt_log_penalty.v1',
      [
        ledgerOperand(
          'load',
          finiteNonNegative(args.input.verifiedDebtWeight),
          'weight',
        ),
        ledgerOperand('coefficient', -0.35, 'points_per_log_weight'),
      ],
      -Math.log1p(finiteNonNegative(args.input.verifiedDebtWeight)) * 0.35,
      verifiedDebtPoints(args.input.verifiedDebtWeight),
      { min: VERIFIED_DEBT_MAX, max: 0 },
      ['verifiedDebt', 'aliasElection'],
    );
    addSuppressedComponent(
      'carryoverDebt',
      'component.carryover_audit_only.v1',
      [
        ledgerOperand(
          'load',
          finiteNonNegative(args.input.carryoverDebtWeight),
          'weight',
        ),
      ],
      0,
      carryoverDebtPoints(args.input.carryoverDebtWeight),
      { min: 0, max: 0 },
      ['carryoverDebt', 'aliasElection'],
    );
    addSuppressedComponent(
      'staleDebt',
      'component.stale_debt_log_penalty.v1',
      [
        ledgerOperand(
          'load',
          finiteNonNegative(args.input.staleDebtWeight),
          'weight',
        ),
        ledgerOperand('coefficient', -0.05, 'points_per_log_weight'),
      ],
      -Math.log1p(finiteNonNegative(args.input.staleDebtWeight)) * 0.05,
      staleDebtPoints(args.input.staleDebtWeight),
      { min: STALE_DEBT_MAX, max: 0 },
      ['staleDebt', 'aliasElection'],
    );
    addSuppressedComponent(
      'closureRisk',
      'component.closure_risk_log_penalty.v1',
      [
        ledgerOperand(
          'load',
          finiteNonNegative(args.input.unresolvedClosureRiskWeight),
          'weight',
        ),
        ledgerOperand('coefficient', -0.08, 'points_per_log_weight'),
      ],
      -Math.log1p(
        finiteNonNegative(args.input.unresolvedClosureRiskWeight),
      ) * 0.08,
      closureRiskPoints(args.input.unresolvedClosureRiskWeight),
      { min: CLOSURE_RISK_MAX, max: 0 },
      ['closureRisk', 'aliasElection'],
    );
    addSuppressedComponent(
      'coverage',
      'component.classification_coverage.v1',
      [
        ledgerOperand('rawIssueCount', args.input.rawIssueCount, 'count'),
        ledgerOperand(
          'classifiedIssueCount',
          args.input.classifiedIssueCount,
          'count',
        ),
        ledgerOperand('ratio', coverage.ratio, 'ratio'),
      ],
      coverage.points,
      coverage.points,
      { min: COVERAGE_MAX, max: 0 },
      ['coverage'],
    );
    addSuppressedComponent(
      'regression',
      'component.opened_fixed_balance.v1',
      [
        ledgerOperand(
          'openedWeight',
          finiteNonNegative(args.input.feltOpenedWeight),
          'weight',
        ),
        ledgerOperand(
          'fixedWeight',
          finiteNonNegative(args.input.feltClosedWeight),
          'weight',
        ),
        ledgerOperand('prior', PRIOR, 'weight'),
      ],
      rawRegressionPoints(
        args.input.feltOpenedWeight,
        args.input.feltClosedWeight,
      ),
      regressionPoints(
        args.input.feltOpenedWeight,
        args.input.feltClosedWeight,
      ),
      { min: REGRESSION_DOWN, max: REGRESSION_UP },
      ['regressionOpened', 'regressionFixed', 'aliasElection'],
    );
    addSuppressedComponent(
      'releaseVerification',
      'component.release_checks.v1',
      [
        ledgerOperand(
          'state',
          args.input.releaseCheckState ?? null,
          'status',
        ),
        ledgerOperand(
          'total',
          args.input.releaseCheckTotal ?? 0,
          'count',
        ),
        ledgerOperand(
          'success',
          args.input.releaseCheckSuccess ?? 0,
          'count',
        ),
        ledgerOperand(
          'failure',
          args.input.releaseCheckFailure ?? 0,
          'count',
        ),
        ledgerOperand(
          'pending',
          args.input.releaseCheckPending ?? 0,
          'count',
        ),
      ],
      rawReleaseVerificationPoints(args.input),
      releaseVerificationPoints(args.input),
      { min: RELEASE_CHECK_DOWN, max: RELEASE_CHECK_UP },
      ['releaseChecks'],
    );
    addSuppressedComponent(
      'artifactVerification',
      'component.artifact_verification.v1',
      [
        ledgerOperand(
          'artifactVerified',
          args.input.artifactVerified ?? false,
          'boolean',
        ),
        ledgerOperand(
          'artifactMismatch',
          args.input.artifactMismatch ?? null,
          'status',
        ),
        ledgerOperand(
          'ciReportVerified',
          args.input.ciReportVerified ?? false,
          'boolean',
        ),
        ledgerOperand(
          'ciReportMismatch',
          args.input.ciReportMismatch ?? null,
          'status',
        ),
        ledgerOperand(
          'releaseIntegrityPresent',
          args.input.releaseIntegrityPresent ?? false,
          'boolean',
        ),
        ledgerOperand(
          'releaseShaMatches',
          args.input.releaseShaMatches ?? null,
          'boolean',
        ),
      ],
      rawArtifactVerificationPoints(args.input),
      artifactVerificationPoints(args.input),
      { min: ARTIFACT_DOWN, max: ARTIFACT_UP },
      ['artifact'],
    );
  };

  let cveGate: ScoreLedgerCveGate = {
    affected: args.input.cveAffected,
    load: finiteNonNegative(args.input.cveLoad),
    rawGateScore: null,
    boundedGateScore: null,
    roundedGateScore: null,
    counterfactualStatus: null,
    counterfactualScore: null,
    selectedScore: confidence.score,
    advisoryManifestKey: 'advisories',
  };

  if (args.input.cveAffected) {
    current = 0;
    const cveLoad = finiteNonNegative(args.input.cveLoad);
    const rawGateScore = 4.9 * (1 - Math.min(1, cveLoad / 30));
    addTransform(
      'cveRawScore',
      'Security advisory raw gate score',
      'gate',
      'gate.cve_raw_score.v1',
      [
        ledgerOperand('cveLoad', cveLoad, 'weight'),
        ledgerOperand('loadSaturation', 30, 'weight'),
        ledgerOperand('gateMaximum', 4.9, 'points'),
      ],
      rawGateScore,
      { min: null, max: null },
      ['advisories'],
    );
    const boundedGateScore = clamp(rawGateScore, 0, 4.9);
    addTransform(
      'cveRangeClamp',
      'Security advisory score range clamp',
      'clamp',
      'score.range_clamp.v1',
      [
        ledgerOperand('value', rawGateScore, 'points'),
        ledgerOperand('minimum', 0, 'points'),
        ledgerOperand('maximum', 4.9, 'points'),
      ],
      boundedGateScore,
      { min: 0, max: 4.9 },
      ['advisories'],
    );
    const roundedGateScore = round1(boundedGateScore);
    addTransform(
      'cveRound',
      'Security advisory score rounding',
      'round',
      'score.round_1_decimal.v1',
      [
        ledgerOperand('value', boundedGateScore, 'points'),
        ledgerOperand('decimals', 1, 'count'),
      ],
      roundedGateScore,
      { min: 0, max: 4.9 },
      ['advisories'],
    );
    const counterfactual = installConfidence({
      ...args.input,
      cveAffected: false,
      cveLoad: 0,
    }, args.now);
    const selectedScore = counterfactual.score == null
      ? roundedGateScore
      : Math.min(roundedGateScore, counterfactual.score);
    addTransform(
      'cveCounterfactualMinimum',
      'Security advisory counterfactual minimum',
      'cap',
      'gate.cve_counterfactual_min.v1',
      [
        ledgerOperand('gateScore', roundedGateScore, 'points'),
        ledgerOperand('counterfactualStatus', counterfactual.status, 'status'),
        ledgerOperand('counterfactualScore', counterfactual.score, 'points'),
      ],
      selectedScore,
      { min: 0, max: 4.9 },
      ['advisories', 'release'],
    );
    cveGate = {
      affected: true,
      load: cveLoad,
      rawGateScore,
      boundedGateScore,
      roundedGateScore,
      counterfactualStatus: counterfactual.status,
      counterfactualScore: counterfactual.score,
      selectedScore,
      advisoryManifestKey: 'advisories',
    };
    addSuppressedExplanationComponents();
  } else if (age == null || age < SETTLE_HOURS) {
    addTransform(
      'waitGate',
      'Settle-time install gate',
      'gate',
      'gate.wait_null_score.v1',
      [
        ledgerOperand('ageHours', age, 'hours'),
        ledgerOperand('settleHours', SETTLE_HOURS, 'hours'),
      ],
      null,
      { min: null, max: null },
      ['release'],
    );
    addSuppressedExplanationComponents();
  } else {
    const components = confidence.components;
    if (!components) {
      throw new Error('ScoreLedgerV2 requires components for eligible and hotfix statuses');
    }
    current = 0;
    const exposureHours = args.input.isLatest ? age : args.input.hoursToNextStable;
    const survivalRaw = exposureHours == null
      ? 0
      : Math.log2(Math.max(1, exposureHours) / PIVOT_HOURS) * 0.7;
    const shakeoutRaw = Math.log2(1 + Math.max(0, args.input.betaCount)) * 0.25;
    const regressionRaw = rawRegressionPoints(
      args.input.feltOpenedWeight,
      args.input.feltClosedWeight,
    );
    const releaseVerificationRaw = rawReleaseVerificationPoints(args.input);
    const artifactVerificationRaw = rawArtifactVerificationPoints(args.input);
    const coverage = coveragePoints(args.input.rawIssueCount, args.input.classifiedIssueCount);
    addComponent(
      'base',
      'component.base.v1',
      [ledgerOperand('base', BASE, 'points')],
      BASE,
      components.base,
      { min: null, max: null },
      ['release'],
    );
    addComponent(
      'verifiedDebt',
      'component.verified_debt_log_penalty.v1',
      [
        ledgerOperand('load', finiteNonNegative(args.input.verifiedDebtWeight), 'weight'),
        ledgerOperand('coefficient', -0.35, 'points_per_log_weight'),
      ],
      -Math.log1p(finiteNonNegative(args.input.verifiedDebtWeight)) * 0.35,
      components.verifiedDebt,
      { min: VERIFIED_DEBT_MAX, max: 0 },
      ['verifiedDebt', 'aliasElection'],
    );
    addComponent(
      'carryoverDebt',
      'component.carryover_audit_only.v1',
      [ledgerOperand('load', finiteNonNegative(args.input.carryoverDebtWeight), 'weight')],
      0,
      components.carryoverDebt,
      { min: 0, max: 0 },
      ['carryoverDebt', 'aliasElection'],
    );
    addComponent(
      'staleDebt',
      'component.stale_debt_log_penalty.v1',
      [
        ledgerOperand('load', finiteNonNegative(args.input.staleDebtWeight), 'weight'),
        ledgerOperand('coefficient', -0.05, 'points_per_log_weight'),
      ],
      -Math.log1p(finiteNonNegative(args.input.staleDebtWeight)) * 0.05,
      components.staleDebt,
      { min: STALE_DEBT_MAX, max: 0 },
      ['staleDebt', 'aliasElection'],
    );
    addComponent(
      'closureRisk',
      'component.closure_risk_log_penalty.v1',
      [
        ledgerOperand('load', finiteNonNegative(args.input.unresolvedClosureRiskWeight), 'weight'),
        ledgerOperand('coefficient', -0.08, 'points_per_log_weight'),
      ],
      -Math.log1p(finiteNonNegative(args.input.unresolvedClosureRiskWeight)) * 0.08,
      components.closureRisk,
      { min: CLOSURE_RISK_MAX, max: 0 },
      ['closureRisk', 'aliasElection'],
    );
    addComponent(
      'coverage',
      'component.classification_coverage.v1',
      [
        ledgerOperand('rawIssueCount', args.input.rawIssueCount, 'count'),
        ledgerOperand('classifiedIssueCount', args.input.classifiedIssueCount, 'count'),
        ledgerOperand('ratio', coverage.ratio, 'ratio'),
      ],
      coverage.points,
      components.coverage,
      { min: COVERAGE_MAX, max: 0 },
      ['coverage'],
    );
    addComponent(
      'survival',
      'component.stable_survival_log2.v1',
      [
        ledgerOperand('isLatest', args.input.isLatest, 'boolean'),
        ledgerOperand('exposureHours', exposureHours, 'hours'),
        ledgerOperand('pivotHours', PIVOT_HOURS, 'hours'),
      ],
      survivalRaw,
      components.survival,
      { min: args.input.isLatest ? 0 : SURVIVAL_MIN, max: SURVIVAL_MAX },
      ['release'],
    );
    addComponent(
      'shakeout',
      'component.beta_shakeout_log2.v1',
      [
        ledgerOperand('betaCount', args.input.betaCount, 'count'),
        ledgerOperand('coefficient', 0.25, 'points_per_log_count'),
      ],
      shakeoutRaw,
      components.shakeout,
      { min: 0, max: SHAKEOUT_MAX },
      ['release'],
    );
    addComponent(
      'regression',
      'component.opened_fixed_balance.v1',
      [
        ledgerOperand('openedWeight', finiteNonNegative(args.input.feltOpenedWeight), 'weight'),
        ledgerOperand('fixedWeight', finiteNonNegative(args.input.feltClosedWeight), 'weight'),
        ledgerOperand('prior', PRIOR, 'weight'),
      ],
      regressionRaw,
      components.regression,
      { min: REGRESSION_DOWN, max: REGRESSION_UP },
      ['regressionOpened', 'regressionFixed', 'aliasElection'],
    );
    addComponent(
      'breaking',
      'component.breaking_bullets.v1',
      [
        ledgerOperand('breakingCount', args.input.breakingCount, 'count'),
        ledgerOperand('pointsPerBullet', BREAKING_PER_BULLET, 'points'),
        ledgerOperand('maximumBullets', BREAKING_MAX_BULLETS, 'count'),
      ],
      BREAKING_PER_BULLET * Math.max(0, args.input.breakingCount),
      components.breaking,
      { min: BREAKING_PER_BULLET * BREAKING_MAX_BULLETS, max: 0 },
      ['release'],
    );
    addComponent(
      'releaseVerification',
      'component.release_checks.v1',
      [
        ledgerOperand('state', args.input.releaseCheckState ?? null, 'status'),
        ledgerOperand('total', args.input.releaseCheckTotal ?? 0, 'count'),
        ledgerOperand('success', args.input.releaseCheckSuccess ?? 0, 'count'),
        ledgerOperand('failure', args.input.releaseCheckFailure ?? 0, 'count'),
        ledgerOperand('pending', args.input.releaseCheckPending ?? 0, 'count'),
      ],
      releaseVerificationRaw,
      components.releaseVerification,
      { min: RELEASE_CHECK_DOWN, max: RELEASE_CHECK_UP },
      ['releaseChecks'],
    );
    addComponent(
      'artifactVerification',
      'component.artifact_verification.v1',
      [
        ledgerOperand('artifactVerified', args.input.artifactVerified ?? false, 'boolean'),
        ledgerOperand('artifactMismatch', args.input.artifactMismatch ?? null, 'status'),
        ledgerOperand('ciReportVerified', args.input.ciReportVerified ?? false, 'boolean'),
        ledgerOperand('ciReportMismatch', args.input.ciReportMismatch ?? null, 'status'),
        ledgerOperand('releaseIntegrityPresent', args.input.releaseIntegrityPresent ?? false, 'boolean'),
        ledgerOperand('releaseShaMatches', args.input.releaseShaMatches ?? null, 'boolean'),
      ],
      artifactVerificationRaw,
      components.artifactVerification,
      { min: ARTIFACT_DOWN, max: ARTIFACT_UP },
      ['artifact'],
    );
    addTransform(
      'scoreRangeClamp',
      'Score range clamp',
      'clamp',
      'score.range_clamp.v1',
      [
        ledgerOperand('value', current, 'points'),
        ledgerOperand('minimum', 0, 'points'),
        ledgerOperand('maximum', 10, 'points'),
      ],
      clamp(current ?? 0, 0, 10),
      { min: 0, max: 10 },
      [],
    );
    if (components.closureRiskCeiling > 0) {
      addTransform(
        'closureRiskCeiling',
        'Closed issue proof ceiling',
        'cap',
        'score.closure_risk_ceiling.v1',
        [
          ledgerOperand('value', current, 'points'),
          ledgerOperand('ceiling', components.closureRiskCeiling, 'points'),
          ledgerOperand('affirmativeClosureRiskCeilingWeight', closureWeight, 'weight'),
        ],
        Math.min(current ?? 0, components.closureRiskCeiling),
        { min: 0, max: components.closureRiskCeiling },
        ['closureCeiling'],
      );
    }
    if (hotfix) {
      addTransform(
        'hotfixCeiling',
        'Hotfix successor ceiling',
        'cap',
        'score.hotfix_ceiling.v1',
        [
          ledgerOperand('value', current, 'points'),
          ledgerOperand('ceiling', HOTFIX_SCORE_CAP, 'points'),
        ],
        Math.min(current ?? 0, HOTFIX_SCORE_CAP),
        { min: 0, max: HOTFIX_SCORE_CAP },
        ['release'],
      );
    }
    addTransform(
      'finalRound',
      'Final score rounding',
      'round',
      'score.round_1_decimal.v1',
      [
        ledgerOperand('value', current, 'points'),
        ledgerOperand('decimals', 1, 'count'),
      ],
      round1(current ?? 0),
      { min: 0, max: 10 },
      [],
    );
  }

  const aliasElectionWithoutDigest = {
    schemaVersion: 1 as const,
    manifestKey: 'aliasElection' as const,
    groups: aliasLedger.groups,
    totalsByChannel: aliasLedger.totalsByChannel,
  };
  const aliasElection: ScoreLedgerAliasElection = {
    ...aliasElectionWithoutDigest,
    digest: scoreLedgerDigest(aliasElectionWithoutDigest),
  };
  const thresholds: ScoreLedgerThresholds = {
    settleHours: SETTLE_HOURS,
    hotfixGapHours: HOTFIX_GAP_HOURS,
    hotfixScoreCap: HOTFIX_SCORE_CAP,
    noticeableClosureRiskWeight: NOTICEABLE_CLOSURE_RISK_THRESHOLD,
    noticeableClosureScoreCap: NOTICEABLE_CLOSURE_SCORE_CAP,
    heavyClosureRiskWeight: HEAVY_CLOSURE_RISK_THRESHOLD,
    heavyClosureScoreCap: HEAVY_CLOSURE_SCORE_CAP,
    scoreRangeMin: 0,
    scoreRangeMax: 10,
    scorePrecisionDecimals: 1,
  };
  const gapToTen = buildGapToTen(operations, confidence.score);
  const presentation = buildScoreLedgerPresentation(operations, confidence, args.input);
  const withoutDigest = {
    schemaVersion: SCORE_LEDGER_SCHEMA_VERSION as 2,
    ledgerType: SCORE_LEDGER_TYPE,
    immutable: true as const,
    formulaCode: `install-confidence.${SCORE_MODEL_VERSION}.ledger-v2`,
    evaluatedAt: new Date(args.now).toISOString(),
    finalScore: confidence.score,
    status: confidence.status,
    band: confidence.band,
    thresholds,
    operations,
    evidence,
    aliasElection,
    cveGate,
    gapToTen,
    rows: presentation.rows,
    caps: presentation.caps,
    subtotalBeforeCaps: presentation.subtotalBeforeCaps,
    scoreAfterCaps: presentation.scoreAfterCaps,
  };
  return deepFreeze({
    ...withoutDigest,
    digest: scoreLedgerDigest(withoutDigest),
  }) as ScoreLedgerV2;
}

export function bindScoreExplanationAudit(
  ledger: ScoreLedgerV2,
  explanation: ScoreExplanationAuditSource,
): ScoreLedgerV2 {
  const baseLedger = scoreLedgerWithoutExplanationAudit(ledger);
  const baseProblems = scoreLedgerV2Problems(baseLedger);
  if (baseProblems.length > 0) {
    throw new Error(
      `Cannot bind explanation audit to an invalid ScoreLedgerV2: ${baseProblems.join('; ')}`,
    );
  }
  const explanationProblems = canonicalScoreExplanationProblems(explanation);
  if (explanationProblems.length > 0) {
    throw new Error(
      `Cannot bind non-canonical score explanation: ${explanationProblems.join('; ')}`,
    );
  }
  const explanationAudit = buildScoreExplanationAudit(explanation, baseLedger);
  const withoutDigest = {
    ...baseLedger,
    explanationAudit,
  };
  delete (withoutDigest as Partial<ScoreLedgerV2>).digest;
  return deepFreeze({
    ...withoutDigest,
    digest: scoreLedgerDigest(withoutDigest),
  }) as ScoreLedgerV2;
}

export function scoreExplanationAuditProblems(
  explanation: unknown,
  ledger: unknown,
): string[] {
  const problems: string[] = [];
  if (!isPlainRecord(explanation)) return ['score explanation must be an object'];
  if (!isPlainRecord(ledger)) return ['score explanation ledger must be an object'];
  const scoreLedger = ledger as unknown as ScoreLedgerV2;
  const audit = scoreLedger.explanationAudit;
  if (audit == null) {
    return ['score explanation ledger is missing the required canonical explanation replay receipt'];
  }
  problems.push(...canonicalScoreExplanationProblems(
    explanation as unknown as ScoreExplanationAuditSource,
  ));
  try {
    const expected = buildScoreExplanationAudit(
      explanation as unknown as ScoreExplanationAuditSource,
      scoreLedgerWithoutExplanationAudit(scoreLedger),
    );
    if (scoreLedgerCanonicalJson(expected) !== scoreLedgerCanonicalJson(audit)) {
      problems.push(
        'score explanation canonical replay does not match the ledger-bound explanation audit',
      );
    }
  } catch (error) {
    problems.push(
      `score explanation canonical replay failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  return [...new Set(problems)];
}

function buildScoreExplanationAudit(
  explanation: ScoreExplanationAuditSource,
  ledger: ScoreLedgerV2,
): ScoreLedgerExplanationAudit {
  const operationByCode = new Map(
    ledger.operations.map((operation) => [operation.code, operation]),
  );
  const details = [
    ...explanation.limitDetails.map((detail, index) =>
      explanationAuditDetail('limit', index, detail, operationByCode)),
    ...explanation.positiveDetails.map((detail, index) =>
      explanationAuditDetail('positive', index, detail, operationByCode)),
  ];
  const withoutDigest = {
    schemaVersion: 1 as const,
    baseLedgerDigest: ledger.digest,
    title: explanation.title,
    verdict: explanation.verdict,
    listsDigest: scoreLedgerDigest({
      limits: explanation.limits,
      positives: explanation.positives,
    }),
    recommendationDecisionDigest: scoreLedgerDigest(
      explanation.recommendationDecision ?? null,
    ),
    details,
  };
  return {
    ...withoutDigest,
    digest: scoreLedgerDigest(withoutDigest),
  };
}

function explanationAuditDetail(
  section: 'limit' | 'positive',
  index: number,
  detail: ScoreExplanationAuditDetailSource,
  operationByCode: ReadonlyMap<string, ScoreLedgerOperation>,
): ScoreLedgerExplanationAuditDetail {
  const operationCodes = SCORE_EXPLANATION_OPERATION_CODES[detail.code] ?? [];
  const operations = operationCodes
    .map((code) => operationByCode.get(code))
    .filter((operation): operation is ScoreLedgerOperation => operation != null)
    .sort((left, right) => left.sequence - right.sequence)
    .map((operation) => ({
      sequence: operation.sequence,
      code: operation.code,
      formulaCode: operation.formulaCode,
      evidenceDigest: operation.evidenceDigest,
    }));
  if (operations.length === 0) {
    throw new Error(
      `score explanation detail ${section}[${index}] code ${detail.code} has no authoritative ledger operation`,
    );
  }
  return {
    section,
    index,
    code: detail.code,
    label: detail.label,
    text: detail.text,
    metricsDigest: scoreLedgerDigest(detail.metrics ?? null),
    bucketsDigest: scoreLedgerDigest(detail.buckets ?? null),
    riskBucketsDigest: scoreLedgerDigest(detail.riskBuckets ?? null),
    issueRefsDigest: scoreLedgerDigest(detail.issueRefs ?? null),
    operations,
  };
}

function canonicalScoreExplanationProblems(
  explanation: ScoreExplanationAuditSource,
): string[] {
  const problems: string[] = [];
  if (explanation.title !== 'Why not 10?') {
    problems.push('score explanation title must be the canonical Why not 10? heading');
  }
  if (!Array.isArray(explanation.limits) || !Array.isArray(explanation.limitDetails)) {
    problems.push('score explanation limits and limitDetails must be arrays');
  } else {
    verifyCanonicalExplanationSection(
      'limit',
      explanation.limits,
      explanation.limitDetails,
      SCORE_EXPLANATION_LIMIT_ORDER,
      problems,
    );
  }
  if (!Array.isArray(explanation.positives) || !Array.isArray(explanation.positiveDetails)) {
    problems.push('score explanation positives and positiveDetails must be arrays');
  } else {
    verifyCanonicalExplanationSection(
      'positive',
      explanation.positives,
      explanation.positiveDetails,
      SCORE_EXPLANATION_POSITIVE_ORDER,
      problems,
    );
  }
  if (typeof explanation.verdict !== 'string' || explanation.verdict.length === 0) {
    problems.push('score explanation verdict must be a non-empty string');
  }
  return problems;
}

function verifyCanonicalExplanationSection(
  section: 'limit' | 'positive',
  summaries: readonly string[],
  details: readonly ScoreExplanationAuditDetailSource[],
  canonicalOrder: readonly string[],
  problems: string[],
): void {
  if (summaries.length !== details.length) {
    problems.push(
      `score explanation ${section} summaries must have one exact entry per detail`,
    );
  }
  const orderByCode = new Map(canonicalOrder.map((code, index) => [code, index]));
  const seen = new Set<string>();
  let priorOrder = -1;
  for (const [index, detail] of details.entries()) {
    if (!isPlainRecord(detail)) {
      problems.push(`score explanation ${section}Details[${index}] must be an object`);
      continue;
    }
    const code = detail.code;
    const order = orderByCode.get(code);
    if (order == null) {
      problems.push(`score explanation ${section}Details[${index}] has unknown code ${code}`);
      continue;
    }
    if (seen.has(code)) {
      problems.push(`score explanation ${section} detail code ${code} must be unique`);
    }
    seen.add(code);
    if (order <= priorOrder) {
      problems.push(
        `score explanation ${section} detail code ${code} is out of canonical order`,
      );
    }
    priorOrder = order;
    const canonicalLabel =
      SCORE_EXPLANATION_CANONICAL_LABELS[
        code as keyof typeof SCORE_EXPLANATION_CANONICAL_LABELS
      ];
    if (detail.label !== canonicalLabel) {
      problems.push(
        `score explanation ${section} detail ${code} label must be ${canonicalLabel}`,
      );
    }
    if (typeof detail.text !== 'string' || detail.text.length === 0) {
      problems.push(
        `score explanation ${section} detail ${code} text must be non-empty`,
      );
    }
    if (summaries[index] !== detail.text) {
      problems.push(
        `score explanation ${section}[${index}] must exactly match ${section}Details[${index}].text`,
      );
    }
  }
}

function scoreLedgerWithoutExplanationAudit(ledger: ScoreLedgerV2): ScoreLedgerV2 {
  const copy = cloneJson(ledger) as ScoreLedgerV2;
  const audit = copy.explanationAudit;
  delete copy.explanationAudit;
  if (audit?.baseLedgerDigest) copy.digest = audit.baseLedgerDigest;
  return copy;
}

export function scoreLedgerV2Problems(
  ledger: unknown,
  expected: {
    input?: InstallInput;
    confidence?: Pick<InstallConfidence, 'score' | 'status' | 'band' | 'hotfix' | 'components'>;
    scoredAt?: string;
  } = {},
): string[] {
  const problems: string[] = [];
  if (!isPlainRecord(ledger)) return ['scoreLedger must be a non-null object'];
  const value = ledger as unknown as ScoreLedgerV2;
  if (value.schemaVersion !== SCORE_LEDGER_SCHEMA_VERSION) {
    problems.push(`scoreLedger schemaVersion must be ${SCORE_LEDGER_SCHEMA_VERSION}`);
  }
  if (value.ledgerType !== SCORE_LEDGER_TYPE) problems.push(`scoreLedger ledgerType must be ${SCORE_LEDGER_TYPE}`);
  if (value.immutable !== true) problems.push('scoreLedger immutable must be true');
  const ledgerEvaluatedAtMs = Date.parse(value.evaluatedAt);
  if (!Number.isFinite(ledgerEvaluatedAtMs)) {
    problems.push('scoreLedger evaluatedAt must be a valid timestamp');
  }
  const persistedScoredAtMs = expected.scoredAt === undefined
    ? ledgerEvaluatedAtMs
    : Date.parse(expected.scoredAt);
  if (
    expected.scoredAt !== undefined &&
    !Number.isFinite(persistedScoredAtMs)
  ) {
    problems.push('persisted scoredAt must be a valid timestamp');
  } else if (
    expected.scoredAt !== undefined &&
    value.evaluatedAt !== expected.scoredAt
  ) {
    problems.push(
      'scoreLedger evaluatedAt must exactly match persisted scoredAt',
    );
  }
  if (!Array.isArray(value.operations) || value.operations.length === 0) {
    problems.push('scoreLedger operations must be a non-empty array');
  }
  const operationCodes = new Set<string>();
  let priorArithmeticAfter: number | null | undefined;
  for (const [index, operation] of (value.operations ?? []).entries()) {
    if (!isPlainRecord(operation)) {
      problems.push(`scoreLedger operations[${index}] must be an object`);
      continue;
    }
    if (operation.sequence !== index) problems.push(`scoreLedger operation sequence ${operation.sequence} must equal ${index}`);
    if (typeof operation.code !== 'string' || !operation.code) {
      problems.push(`scoreLedger operations[${index}] code must be present`);
    } else if (operationCodes.has(operation.code)) {
      problems.push(`scoreLedger operation code ${operation.code} must be unique`);
    } else {
      operationCodes.add(operation.code);
    }
    if (!Array.isArray(operation.operands)) {
      problems.push(`scoreLedger operation ${operation.code} operands must be an array`);
    } else {
      for (const operand of operation.operands) {
        if (!isPlainRecord(operand) || operand.type !== scoreLedgerOperandType(operand.value)) {
          problems.push(`scoreLedger operation ${operation.code} operand types must match their values`);
          break;
        }
      }
    }
    if (!Array.isArray(operation.evidenceManifestKeys)) {
      problems.push(`scoreLedger operation ${operation.code} evidenceManifestKeys must be an array`);
    }
    if (operation.kind === 'predicate') {
      if (operation.predicateResult !== operation.applied) {
        problems.push(`scoreLedger predicate ${operation.code} applied must equal predicateResult`);
      }
      if (!sameLedgerNumber(operation.before, operation.after)) {
        problems.push(`scoreLedger predicate ${operation.code} must not change the running score`);
      }
      continue;
    }
    if (operation.kind === 'component') {
      const expectedAfter = operation.applied
        ? (
          typeof operation.before === 'number' &&
            typeof operation.boundedPoints === 'number'
            ? operation.before + operation.boundedPoints
            : operation.before
        )
        : operation.before;
      if (!sameLedgerNumber(operation.after, expectedAfter)) {
        problems.push(
          `scoreLedger component ${operation.code} must ${
            operation.applied ? 'apply boundedPoints to' : 'preserve'
          } the running score`,
        );
      }
    }
    if (priorArithmeticAfter !== undefined && !sameLedgerNumber(operation.before, priorArithmeticAfter)) {
      problems.push(`scoreLedger operation ${operation.code} before must match the prior arithmetic after`);
    }
    priorArithmeticAfter = operation.after;
  }
  verifyScoreLedgerEvidence(value.evidence, problems);
  verifyScoreLedgerAliasElection(value.aliasElection, value.evidence, problems);
  verifyScoreLedgerRiskEvidenceCoupling(
    value.aliasElection,
    value.evidence,
    expected.input,
    problems,
  );
  verifyScoreLedgerOperationEvidence(value.operations, value.evidence, problems);
  verifyScoreLedgerExplanationAuditEnvelope(value, problems);
  verifyScoreLedgerGap(value.gapToTen, value.operations, value.finalScore, problems);
  if (value.status === 'skip-cve') {
    const advisoryManifest = value.evidence?.manifests?.find((manifest) =>
      manifest.key === value.cveGate?.advisoryManifestKey);
    if (!value.cveGate?.affected || !advisoryManifest || advisoryManifest.count === 0) {
      problems.push(
        'scoreLedger skip-cve compatibility status requires affected security advisory evidence identities',
      );
    }
  }
  const withoutDigest = { ...value } as Record<string, unknown>;
  delete withoutDigest.digest;
  if (value.digest !== scoreLedgerDigest(withoutDigest)) {
    problems.push('scoreLedger digest does not match its canonical content');
  }
  if (expected.confidence) {
    if (!sameLedgerNumber(value.finalScore, expected.confidence.score)) {
      problems.push('scoreLedger finalScore does not match expected confidence');
    }
    if (value.status !== expected.confidence.status) {
      problems.push('scoreLedger status does not match expected confidence');
    }
    if (value.band !== expected.confidence.band) {
      problems.push('scoreLedger band does not match expected confidence');
    }
  }
  if (expected.input && Number.isFinite(persistedScoredAtMs)) {
    try {
      const now = persistedScoredAtMs;
      const confidence = installConfidence(expected.input, now);
      const previewByKey = new Map(
        (value.evidence?.previews ?? []).map((preview) => [preview.key, preview]),
      );
      const evidenceSources = (value.evidence?.manifests ?? []).map((manifest) => ({
        key: manifest.key,
        refs: manifest.refs.map((ref) => ({ ...ref })),
        previewLimit: previewByKey.get(manifest.key)?.limit ?? SCORE_LEDGER_PREVIEW_LIMIT,
      }));
      const rebuilt = buildScoreLedgerV2({
        input: expected.input,
        confidence,
        now,
        evidenceSources,
        aliasElection: {
          schemaVersion: 1,
          groups: value.aliasElection.groups,
          totalsByChannel: value.aliasElection.totalsByChannel,
        },
      });
      const persistedBaseLedger = value.explanationAudit
        ? scoreLedgerWithoutExplanationAudit(value)
        : value;
      if (
        scoreLedgerCanonicalJson(rebuilt) !==
        scoreLedgerCanonicalJson(persistedBaseLedger)
      ) {
        problems.push('scoreLedger semantic replay does not match the persisted derivation');
      }
    } catch (error) {
      problems.push(`scoreLedger semantic replay failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return [...new Set(problems)];
}

function buildScoreLedgerEvidenceBundle(
  sources: readonly ScoreLedgerEvidenceSourceInput[],
  aliasLedger: ExclusiveIssueRiskLedger,
): ScoreLedgerEvidenceBundle {
  const byKey = new Map<string, ScoreLedgerEvidenceSourceInput>();
  for (const source of sources) {
    if (!source.key || byKey.has(source.key)) {
      throw new Error(`ScoreLedgerV2 evidence source key is missing or duplicated: ${source.key}`);
    }
    byKey.set(source.key, source);
  }
  byKey.set('aliasElection', {
    key: 'aliasElection',
    refs: aliasLedger.groups.map((group) => ({
      kind: 'alias_group',
      identity: `alias:${group.aliasGroup}`,
      payload: group,
    })),
    previewLimit: SCORE_LEDGER_PREVIEW_LIMIT,
  });
  for (const key of SCORE_LEDGER_EVIDENCE_KEYS) {
    if (!byKey.has(key)) byKey.set(key, { key, refs: [] });
  }
  const manifests: ScoreLedgerEvidenceManifest[] = [];
  const previews: ScoreLedgerEvidencePreview[] = [];
  for (const source of [...byKey.values()].sort((left, right) => left.key.localeCompare(right.key))) {
    const refs = source.refs
      .map((ref) => scoreLedgerEvidenceRef(ref, source.key))
      .sort(compareScoreLedgerEvidenceRefs);
    const identities = new Set<string>();
    for (const ref of refs) {
      const identity = `${ref.kind}\0${ref.identity}`;
      if (identities.has(identity)) {
        throw new Error(`ScoreLedgerV2 evidence identity is duplicated in ${source.key}: ${ref.kind}/${ref.identity}`);
      }
      identities.add(identity);
    }
    const manifestWithoutDigest = {
      key: source.key,
      exhaustive: true as const,
      count: refs.length,
      refs,
    };
    manifests.push({
      ...manifestWithoutDigest,
      digest: scoreLedgerDigest(manifestWithoutDigest),
    });
    const limit = Number.isInteger(source.previewLimit) && Number(source.previewLimit) >= 0
      ? Number(source.previewLimit)
      : SCORE_LEDGER_PREVIEW_LIMIT;
    previews.push({
      key: source.key,
      limit,
      totalCount: refs.length,
      truncated: refs.length > limit,
      refs: refs.slice(0, limit),
    });
  }
  const withoutDigest = {
    schemaVersion: 1 as const,
    manifests,
    previews,
  };
  return {
    ...withoutDigest,
    digest: scoreLedgerDigest(withoutDigest),
  };
}

function buildGapToTen(
  operations: readonly ScoreLedgerOperation[],
  finalScore: number | null,
): ScoreLedgerGapToTen {
  if (finalScore == null) {
    return {
      applicable: false,
      target: 10,
      finalScore: null,
      total: null,
      items: [],
    };
  }
  const arithmetic = operations.filter((operation) =>
    operation.kind !== 'predicate' &&
    typeof operation.before === 'number' &&
    typeof operation.after === 'number'
  );
  const items: ScoreLedgerGapItem[] = [];
  for (const [index, operation] of arithmetic.entries()) {
    const points = index === 0
      ? 10 - Number(operation.after)
      : Number(operation.before) - Number(operation.after);
    if (Math.abs(points) <= 1e-12) continue;
    items.push({
      sequence: items.length,
      operationCode: operation.code,
      label: operation.label,
      points: ledgerNumber(points),
    });
  }
  return {
    applicable: true,
    target: 10,
    finalScore,
    total: ledgerNumber(10 - finalScore),
    items,
  };
}

function buildScoreLedgerPresentation(
  operations: readonly ScoreLedgerOperation[],
  confidence: InstallConfidence,
  input: InstallInput,
): {
  rows: ScoreLedgerPresentationRow[];
  caps: ScoreLedgerPresentationCap[];
  subtotalBeforeCaps: number | null;
  scoreAfterCaps: number | null;
} {
  if (confidence.status === 'wait') {
    return {
      rows: [{
        key: 'settleGate',
        label: 'Settle-time gate',
        points: 0,
        kind: 'neutral',
        metric: input.publishedAt,
        note: 'Release is not scored until it has had enough time to settle.',
      }],
      caps: [],
      subtotalBeforeCaps: null,
      scoreAfterCaps: null,
    };
  }
  if (confidence.status === 'skip-cve') {
    const gateReduction = roundLedgerMetric((confidence.score ?? 0) - 10);
    return {
      rows: [{
        key: 'cveGate',
        label: 'Security advisory install gate',
        points: gateReduction,
        kind: 'penalty',
        metric: roundLedgerMetric(input.cveLoad),
        note: 'Reduction from 10 caused by a known medium-or-higher security advisory affecting this release.',
      }],
      caps: [],
      subtotalBeforeCaps: confidence.score,
      scoreAfterCaps: confidence.score,
    };
  }
  const componentOperations = operations.filter((operation) =>
    operation.kind === 'component' &&
    Object.hasOwn(SCORE_LEDGER_COMPONENT_PRESENTATION, operation.code)
  );
  const metricByCode: Record<string, number | string | null> = {
    verifiedDebt: roundLedgerMetric(input.verifiedDebtWeight),
    carryoverDebt: roundLedgerMetric(input.carryoverDebtWeight),
    staleDebt: roundLedgerMetric(input.staleDebtWeight),
    closureRisk: roundLedgerMetric(input.unresolvedClosureRiskWeight),
    coverage: `${input.classifiedIssueCount}/${input.rawIssueCount}`,
    survival: roundLedgerMetric(input.hoursToNextStable ?? 0),
    shakeout: input.betaCount,
    regression: `${roundLedgerMetric(input.feltOpenedWeight)} opened weight / ${roundLedgerMetric(input.feltClosedWeight)} fixed weight`,
    breaking: input.breakingCount,
    releaseVerification:
      `${input.releaseCheckSuccess ?? 0} of ${input.releaseCheckTotal ?? 0} passed / ` +
      `${input.releaseCheckFailure ?? 0} failed / ${input.releaseCheckPending ?? 0} pending`,
    artifactVerification:
      input.artifactVerified && input.releaseShaMatches === true
        ? 'tarball bytes and release binding verified'
        : input.artifactMismatch
          ? 'artifact mismatch'
          : 'not fully verified',
  };
  let rows = componentOperations.map((operation): ScoreLedgerPresentationRow => {
    const points = roundLedgerMetric(operation.boundedPoints ?? 0);
    return {
      key: operation.code,
      label: operation.label,
      points,
      kind: scoreLedgerPresentationKind(operation.code, points),
      ...(Object.hasOwn(metricByCode, operation.code) ? { metric: metricByCode[operation.code] } : {}),
      note: SCORE_LEDGER_COMPONENT_PRESENTATION[
        operation.code as keyof typeof SCORE_LEDGER_COMPONENT_PRESENTATION
      ].note,
    };
  });
  let subtotalBeforeCaps = roundLedgerMetric(rows.reduce((sum, row) => sum + row.points, 0));
  const capOperations = operations.filter((operation) =>
    operation.kind === 'cap' &&
    (operation.code === 'closureRiskCeiling' || operation.code === 'hotfixCeiling')
  );
  const caps = capOperations.map((operation): ScoreLedgerPresentationCap => {
    const ceiling = Number(operandValue(operation, 'ceiling') ?? operation.bounds.max ?? 0);
    return {
      key: operation.code,
      label: operation.label,
      ceiling: roundLedgerMetric(ceiling),
      applied: operation.applied,
      before: operation.before == null ? null : roundLedgerMetric(operation.before),
      after: operation.after == null ? null : roundLedgerMetric(operation.after),
      reason: operation.code === 'closureRiskCeiling'
        ? 'Deduplicated affirmative closure risk limits confidence without duplicating its numeric penalty.'
        : 'A release replaced quickly by a later stable is not an install target.',
    };
  });
  let scoreAfterCaps = subtotalBeforeCaps;
  for (const cap of caps) scoreAfterCaps = roundLedgerMetric(Math.min(scoreAfterCaps, cap.ceiling));
  if (confidence.score != null) {
    const adjustment = roundLedgerMetric(confidence.score - scoreAfterCaps);
    if (adjustment !== 0) {
      rows = [...rows, {
        key: 'precisionAdjustment',
        label: 'Unrounded model adjustment',
        points: adjustment,
        kind: scoreLedgerPresentationKind('precisionAdjustment', adjustment),
        note: 'Presentation-only reconciliation to the authoritative explicit clamp, cap, and rounding operations.',
      }];
      subtotalBeforeCaps = roundLedgerMetric(rows.reduce((sum, row) => sum + row.points, 0));
      scoreAfterCaps = subtotalBeforeCaps;
      for (const cap of caps) scoreAfterCaps = roundLedgerMetric(Math.min(scoreAfterCaps, cap.ceiling));
    }
  }
  return { rows, caps, subtotalBeforeCaps, scoreAfterCaps };
}

function rawRegressionPoints(openedWeight: number, closedWeight: number): number {
  const opened = finiteNonNegative(openedWeight);
  const closed = finiteNonNegative(closedWeight);
  const total = opened + closed + PRIOR;
  return -(opened / total) * 1.1 + (closed / total) * 0.8;
}

function rawReleaseVerificationPoints(input: InstallInput): number {
  const total = finiteNonNegative(input.releaseCheckTotal ?? 0);
  if (total === 0 && !input.releaseCheckState) return 0;
  const state = (input.releaseCheckState ?? '').toUpperCase();
  const failures = finiteNonNegative(input.releaseCheckFailure ?? 0);
  const pending = finiteNonNegative(input.releaseCheckPending ?? 0);
  const successes = finiteNonNegative(input.releaseCheckSuccess ?? 0);
  const failurePenalty = failures > 0 || ['FAILURE', 'ERROR', 'ACTION_REQUIRED'].includes(state)
    ? -0.8 - Math.log1p(failures) * 0.25
    : 0;
  const pendingPenalty = pending > 0 || ['PENDING', 'EXPECTED'].includes(state)
    ? -0.25 - Math.log1p(pending) * 0.08
    : 0;
  if (failurePenalty < 0 || pendingPenalty < 0) return Math.min(failurePenalty, pendingPenalty);
  if (state === 'SUCCESS' && successes > 0) return Math.log1p(successes) * 0.18;
  return 0;
}

function rawArtifactVerificationPoints(input: InstallInput): number {
  if (input.artifactMismatch) return ARTIFACT_DOWN;
  let points = 0;
  if (input.artifactVerified && input.releaseIntegrityPresent && input.releaseShaMatches === true) {
    points += 0.25;
  }
  if (input.ciReportVerified) points += 0.1;
  else if (input.ciReportMismatch) points -= 0.15;
  return points;
}

function assertLedgerConfidenceMatches(
  provided: InstallConfidence,
  recomputed: InstallConfidence,
): void {
  const fields: Array<keyof Pick<InstallConfidence, 'score' | 'status' | 'band' | 'hotfix' | 'scoreRangeClamp' | 'evidenceCoverage'>> = [
    'score',
    'status',
    'band',
    'hotfix',
    'scoreRangeClamp',
    'evidenceCoverage',
  ];
  for (const field of fields) {
    const left = provided[field];
    const right = recomputed[field];
    const matches = typeof left === 'number' || typeof right === 'number'
      ? sameLedgerNumber(left as number | null, right as number | null)
      : left === right;
    if (!matches) {
      throw new Error(`ScoreLedgerV2 confidence ${field} does not match recomputed scoring`);
    }
  }
  if (scoreLedgerCanonicalJson(provided.components) !== scoreLedgerCanonicalJson(recomputed.components)) {
    throw new Error('ScoreLedgerV2 confidence components do not match recomputed scoring');
  }
}

function assertExclusiveIssueRiskLedger(
  ledger: ExclusiveIssueRiskLedger,
): void {
  if (ledger.schemaVersion !== 1 || !Array.isArray(ledger.groups)) {
    throw new Error('ScoreLedgerV2 alias election must be a schema-v1 ledger');
  }
  const candidates = ledger.groups.flatMap((group) =>
    (group.candidates ?? []).map((candidate) => ({
      aliasGroup: candidate.aliasGroup,
      channel: candidate.channel,
      weight: candidate.weight,
      issueNumber: candidate.issueNumber,
    }))
  );
  const rebuilt = buildExclusiveIssueRiskLedger(candidates);
  if (
    scoreLedgerCanonicalJson(rebuilt.groups) !== scoreLedgerCanonicalJson(ledger.groups) ||
    scoreLedgerCanonicalJson(rebuilt.totalsByChannel) !==
      scoreLedgerCanonicalJson(ledger.totalsByChannel)
  ) {
    throw new Error(
      'ScoreLedgerV2 alias election must select the strongest adverse candidate within each group',
    );
  }
}

function assertAliasElectionMatchesInput(
  ledger: ExclusiveIssueRiskLedger,
  input: InstallInput,
): void {
  for (const channel of Object.keys(SCORE_LEDGER_RISK_EVIDENCE) as IssueRiskChannel[]) {
    const inputField = SCORE_LEDGER_RISK_EVIDENCE[channel].inputField;
    if (!sameLedgerNumber(ledger.totalsByChannel[channel], Number(input[inputField]))) {
      throw new Error(
        `ScoreLedgerV2 alias election ${channel} total must match InstallInput.${String(inputField)}`,
      );
    }
  }
}

function assertScoreLedgerRiskEvidenceCoupling(
  ledger: ExclusiveIssueRiskLedger,
  evidence: ScoreLedgerEvidenceBundle,
  input: InstallInput,
): void {
  const problems: string[] = [];
  verifyScoreLedgerRiskEvidenceCoupling(
    {
      schemaVersion: 1,
      manifestKey: 'aliasElection',
      groups: ledger.groups,
      totalsByChannel: ledger.totalsByChannel,
      digest: '',
    },
    evidence,
    input,
    problems,
  );
  if (problems.length > 0) {
    throw new Error(`ScoreLedgerV2 risk evidence is not exhaustive: ${problems.join('; ')}`);
  }
}

function verifyScoreLedgerEvidence(
  evidence: ScoreLedgerEvidenceBundle,
  problems: string[],
): void {
  if (!isPlainRecord(evidence) || evidence.schemaVersion !== 1) {
    problems.push('scoreLedger evidence must be a schema-v1 object');
    return;
  }
  if (!Array.isArray(evidence.manifests) || !Array.isArray(evidence.previews)) {
    problems.push('scoreLedger evidence manifests and previews must be arrays');
    return;
  }
  const manifestByKey = new Map<string, ScoreLedgerEvidenceManifest>();
  for (const manifest of evidence.manifests) {
    if (!isPlainRecord(manifest) || typeof manifest.key !== 'string' || manifestByKey.has(manifest.key)) {
      problems.push('scoreLedger evidence manifest keys must be unique non-empty strings');
      continue;
    }
    manifestByKey.set(manifest.key, manifest);
    if (manifest.exhaustive !== true) problems.push(`scoreLedger evidence manifest ${manifest.key} must be exhaustive`);
    if (!Array.isArray(manifest.refs) || manifest.count !== manifest.refs?.length) {
      problems.push(`scoreLedger evidence manifest ${manifest.key} count must match refs`);
      continue;
    }
    const sorted = manifest.refs.slice().sort(compareScoreLedgerEvidenceRefs);
    if (scoreLedgerCanonicalJson(sorted) !== scoreLedgerCanonicalJson(manifest.refs)) {
      problems.push(`scoreLedger evidence manifest ${manifest.key} refs must be canonically ordered`);
    }
    const identities = new Set<string>();
    for (const ref of manifest.refs) {
      const identity = `${ref.kind}\0${ref.identity}`;
      if (identities.has(identity)) problems.push(`scoreLedger evidence manifest ${manifest.key} has duplicate identity ${identity}`);
      identities.add(identity);
      if (!/^[0-9a-f]{64}$/.test(ref.digest)) {
        problems.push(`scoreLedger evidence manifest ${manifest.key} has an invalid ref digest`);
      }
      if (
        ref.scoringOperand != null &&
        !isScoreLedgerEvidenceOperand(ref.scoringOperand)
      ) {
        problems.push(
          `scoreLedger evidence manifest ${manifest.key} has an invalid scoring operand`,
        );
      }
    }
    const withoutDigest = {
      key: manifest.key,
      exhaustive: true,
      count: manifest.count,
      refs: manifest.refs,
    };
    if (manifest.digest !== scoreLedgerDigest(withoutDigest)) {
      problems.push(`scoreLedger evidence manifest ${manifest.key} digest does not match refs`);
    }
  }
  const previewByKey = new Map<string, ScoreLedgerEvidencePreview>();
  for (const preview of evidence.previews) {
    if (!isPlainRecord(preview) || typeof preview.key !== 'string' || previewByKey.has(preview.key)) {
      problems.push('scoreLedger evidence preview keys must be unique non-empty strings');
      continue;
    }
    previewByKey.set(preview.key, preview);
    const manifest = manifestByKey.get(preview.key);
    if (!manifest) {
      problems.push(`scoreLedger evidence preview ${preview.key} has no exhaustive manifest`);
      continue;
    }
    if (!Number.isInteger(preview.limit) || preview.limit < 0) {
      problems.push(`scoreLedger evidence preview ${preview.key} limit must be non-negative`);
    }
    if (preview.totalCount !== manifest.count || preview.truncated !== (manifest.count > preview.limit)) {
      problems.push(`scoreLedger evidence preview ${preview.key} totals must match its manifest`);
    }
    if (scoreLedgerCanonicalJson(preview.refs) !== scoreLedgerCanonicalJson(manifest.refs.slice(0, preview.limit))) {
      problems.push(`scoreLedger evidence preview ${preview.key} must be the capped manifest prefix`);
    }
  }
  for (const key of manifestByKey.keys()) {
    if (!previewByKey.has(key)) problems.push(`scoreLedger evidence manifest ${key} is missing its separate preview`);
  }
  const withoutDigest = {
    schemaVersion: 1,
    manifests: evidence.manifests,
    previews: evidence.previews,
  };
  if (evidence.digest !== scoreLedgerDigest(withoutDigest)) {
    problems.push('scoreLedger evidence digest does not match manifests and previews');
  }
}

function verifyScoreLedgerAliasElection(
  aliasElection: ScoreLedgerAliasElection,
  evidence: ScoreLedgerEvidenceBundle,
  problems: string[],
): void {
  if (!isPlainRecord(aliasElection) || aliasElection.schemaVersion !== 1) {
    problems.push('scoreLedger aliasElection must be a schema-v1 object');
    return;
  }
  const withoutDigest = {
    schemaVersion: 1,
    manifestKey: 'aliasElection',
    groups: aliasElection.groups,
    totalsByChannel: aliasElection.totalsByChannel,
  };
  if (aliasElection.digest !== scoreLedgerDigest(withoutDigest)) {
    problems.push('scoreLedger aliasElection digest does not match its groups');
  }
  try {
    const candidates = (aliasElection.groups ?? []).flatMap((group) =>
      (group.candidates ?? []).map((candidate) => ({
        aliasGroup: candidate.aliasGroup,
        channel: candidate.channel,
        weight: candidate.weight,
        issueNumber: candidate.issueNumber,
      }))
    );
    const rebuilt = buildExclusiveIssueRiskLedger(candidates);
    if (
      scoreLedgerCanonicalJson(rebuilt.groups) !== scoreLedgerCanonicalJson(aliasElection.groups) ||
      scoreLedgerCanonicalJson(rebuilt.totalsByChannel) !== scoreLedgerCanonicalJson(aliasElection.totalsByChannel)
    ) {
      problems.push('scoreLedger aliasElection does not match complete exclusive channel election');
    }
    const manifest = evidence?.manifests?.find((item) => item.key === 'aliasElection');
    const expectedRefs = rebuilt.groups
      .map((group) => scoreLedgerEvidenceRef({
        kind: 'alias_group',
        identity: `alias:${group.aliasGroup}`,
        payload: group,
      }, 'aliasElection'))
      .sort(compareScoreLedgerEvidenceRefs);
    if (!manifest || scoreLedgerCanonicalJson(manifest.refs) !== scoreLedgerCanonicalJson(expectedRefs)) {
      problems.push('scoreLedger aliasElection manifest does not match elected groups');
    }
  } catch (error) {
    problems.push(`scoreLedger aliasElection could not be replayed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function verifyScoreLedgerExplanationAuditEnvelope(
  ledger: ScoreLedgerV2,
  problems: string[],
): void {
  const audit = ledger.explanationAudit;
  if (audit == null) return;
  if (!isPlainRecord(audit) || audit.schemaVersion !== 1) {
    problems.push('scoreLedger explanationAudit must be a schema-v1 object');
    return;
  }
  const baseWithoutDigest = { ...ledger } as Record<string, unknown>;
  delete baseWithoutDigest.digest;
  delete baseWithoutDigest.explanationAudit;
  const expectedBaseDigest = scoreLedgerDigest(baseWithoutDigest);
  if (audit.baseLedgerDigest !== expectedBaseDigest) {
    problems.push(
      'scoreLedger explanationAudit baseLedgerDigest does not match the authoritative ledger derivation',
    );
  }
  const auditWithoutDigest = { ...audit } as Record<string, unknown>;
  delete auditWithoutDigest.digest;
  if (audit.digest !== scoreLedgerDigest(auditWithoutDigest)) {
    problems.push('scoreLedger explanationAudit digest does not match its canonical content');
  }
  if (!Array.isArray(audit.details)) {
    problems.push('scoreLedger explanationAudit details must be an array');
    return;
  }
  const operationBySequence = new Map(
    (ledger.operations ?? []).map((operation) => [operation.sequence, operation]),
  );
  for (const [detailIndex, detail] of audit.details.entries()) {
    if (!isPlainRecord(detail)) {
      problems.push(
        `scoreLedger explanationAudit details[${detailIndex}] must be an object`,
      );
      continue;
    }
    if (!Array.isArray(detail.operations) || detail.operations.length === 0) {
      problems.push(
        `scoreLedger explanationAudit details[${detailIndex}] must cite authoritative operations`,
      );
      continue;
    }
    let priorSequence = -1;
    for (const receipt of detail.operations) {
      if (!isPlainRecord(receipt)) {
        problems.push(
          `scoreLedger explanationAudit details[${detailIndex}] operation receipt must be an object`,
        );
        continue;
      }
      const operation = operationBySequence.get(Number(receipt.sequence));
      if (
        !operation ||
        operation.code !== receipt.code ||
        operation.formulaCode !== receipt.formulaCode ||
        operation.evidenceDigest !== receipt.evidenceDigest
      ) {
        problems.push(
          `scoreLedger explanationAudit details[${detailIndex}] operation receipt does not match the ordered ledger`,
        );
      }
      if (Number(receipt.sequence) <= priorSequence) {
        problems.push(
          `scoreLedger explanationAudit details[${detailIndex}] operation receipts must be in ledger order`,
        );
      }
      priorSequence = Number(receipt.sequence);
    }
  }
}

function verifyScoreLedgerRiskEvidenceCoupling(
  aliasElection: ScoreLedgerAliasElection,
  evidence: ScoreLedgerEvidenceBundle,
  input: InstallInput | undefined,
  problems: string[],
): void {
  if (!isPlainRecord(aliasElection) || !isPlainRecord(evidence)) return;
  const manifestByKey = new Map(
    (evidence.manifests ?? []).map((manifest) => [manifest.key, manifest]),
  );
  for (const channel of Object.keys(SCORE_LEDGER_RISK_EVIDENCE) as IssueRiskChannel[]) {
    const { manifestKey, inputField } = SCORE_LEDGER_RISK_EVIDENCE[channel];
    const expectedGroups = (aliasElection.groups ?? [])
      .filter((group) => group.selectedChannel === channel);
    const expectedTotal = expectedGroups.reduce(
      (sum, group) => sum + Number(group.selectedWeight ?? 0),
      0,
    );
    const ledgerTotal = Number(aliasElection.totalsByChannel?.[channel]);
    if (!sameLedgerNumber(ledgerTotal, expectedTotal)) {
      problems.push(
        `scoreLedger aliasElection ${channel} total does not match selected groups`,
      );
    }
    if (input && !sameLedgerNumber(Number(input[inputField]), ledgerTotal)) {
      problems.push(
        `scoreLedger aliasElection ${channel} total does not match InstallInput.${String(inputField)}`,
      );
    }
    const manifest = manifestByKey.get(manifestKey);
    if (!manifest) {
      problems.push(`scoreLedger risk evidence is missing manifest ${manifestKey}`);
      continue;
    }
    const operandByAlias = new Map<string, ScoreLedgerEvidenceOperand>();
    for (const ref of manifest.refs ?? []) {
      const operand = ref.scoringOperand;
      if (!isScoreLedgerEvidenceOperand(operand)) {
        problems.push(
          `scoreLedger evidence manifest ${manifestKey} must bind every source row to a scoring operand`,
        );
        continue;
      }
      if (operand.channel !== channel) {
        problems.push(
          `scoreLedger evidence manifest ${manifestKey} has operand channel ${operand.channel}, expected ${channel}`,
        );
      }
      if (operandByAlias.has(operand.aliasGroup)) {
        problems.push(
          `scoreLedger evidence manifest ${manifestKey} has duplicate alias operand ${operand.aliasGroup}`,
        );
      }
      operandByAlias.set(operand.aliasGroup, operand);
    }
    for (const group of expectedGroups) {
      const operand = operandByAlias.get(group.aliasGroup);
      if (!operand) {
        problems.push(
          `scoreLedger evidence manifest ${manifestKey} is missing elected alias ${group.aliasGroup}`,
        );
        continue;
      }
      if (!sameLedgerNumber(operand.weight, group.selectedWeight)) {
        problems.push(
          `scoreLedger evidence manifest ${manifestKey} weight for ${group.aliasGroup} does not match the elected operand`,
        );
      }
    }
    for (const aliasGroup of operandByAlias.keys()) {
      if (!expectedGroups.some((group) => group.aliasGroup === aliasGroup)) {
        problems.push(
          `scoreLedger evidence manifest ${manifestKey} contains unelected alias ${aliasGroup}`,
        );
      }
    }
    const manifestTotal = [...operandByAlias.values()].reduce(
      (sum, operand) => sum + operand.weight,
      0,
    );
    if (!sameLedgerNumber(manifestTotal, ledgerTotal)) {
      problems.push(
        `scoreLedger evidence manifest ${manifestKey} operand total does not match aliasElection ${channel} total`,
      );
    }
    if (ledgerTotal > 0 && manifest.refs.length === 0) {
      problems.push(
        `scoreLedger evidence manifest ${manifestKey} cannot be empty for nonzero ${channel} debt`,
      );
    }
  }
}

function verifyScoreLedgerOperationEvidence(
  operations: readonly ScoreLedgerOperation[],
  evidence: ScoreLedgerEvidenceBundle,
  problems: string[],
): void {
  const digestByKey = new Map((evidence?.manifests ?? []).map((manifest) => [manifest.key, manifest.digest]));
  for (const operation of operations ?? []) {
    const missing = (operation.evidenceManifestKeys ?? []).filter((key) => !digestByKey.has(key));
    if (missing.length > 0) {
      problems.push(`scoreLedger operation ${operation.code} references missing evidence manifests ${missing.join(', ')}`);
      continue;
    }
    const expectedDigest = scoreLedgerDigest(
      operation.evidenceManifestKeys
        .slice()
        .sort()
        .map((key) => ({ key, digest: digestByKey.get(key) ?? null })),
    );
    if (operation.evidenceDigest !== expectedDigest) {
      problems.push(`scoreLedger operation ${operation.code} evidenceDigest does not match referenced manifests`);
    }
  }
}

function verifyScoreLedgerGap(
  gap: ScoreLedgerGapToTen,
  operations: readonly ScoreLedgerOperation[],
  finalScore: number | null,
  problems: string[],
): void {
  const expected = buildGapToTen(operations ?? [], finalScore);
  if (scoreLedgerCanonicalJson(gap) !== scoreLedgerCanonicalJson(expected)) {
    problems.push('scoreLedger gapToTen items must exactly reconcile to 10 - finalScore');
  }
  if (gap?.applicable && typeof gap.total === 'number') {
    const sum = ledgerNumber((gap.items ?? []).reduce((total, item) => total + Number(item.points ?? 0), 0));
    if (!sameLedgerNumber(sum, gap.total)) {
      problems.push('scoreLedger gapToTen item sum must equal gapToTen total');
    }
  }
}

function scoreLedgerEvidenceRef(
  input: ScoreLedgerEvidenceRefInput,
  manifestKey: string,
): ScoreLedgerEvidenceRef {
  if (!input.kind || !input.identity) {
    throw new Error('ScoreLedgerV2 evidence refs require kind and identity');
  }
  const digest = input.digest ?? scoreLedgerDigest(
    Object.hasOwn(input, 'payload') ? input.payload : input.identity,
  );
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error(`ScoreLedgerV2 evidence ref ${input.kind}/${input.identity} has an invalid digest`);
  }
  const scoringOperand = input.scoringOperand ??
    scoreLedgerEvidenceOperandFromPayload(manifestKey, input.payload);
  if (scoringOperand != null && !isScoreLedgerEvidenceOperand(scoringOperand)) {
    throw new Error(
      `ScoreLedgerV2 evidence ref ${input.kind}/${input.identity} has an invalid scoring operand`,
    );
  }
  return {
    kind: input.kind,
    identity: input.identity,
    digest,
    ...(scoringOperand == null ? {} : { scoringOperand }),
  };
}

function scoreLedgerEvidenceOperandFromPayload(
  manifestKey: string,
  payload: unknown,
): ScoreLedgerEvidenceOperand | undefined {
  if (!isPlainRecord(payload)) return undefined;
  if (manifestKey === 'aliasElection') {
    return {
      aliasGroup: String(payload.aliasGroup ?? ''),
      channel: payload.selectedChannel as IssueRiskChannel,
      weight: Number(payload.selectedWeight),
    };
  }
  const channel = (Object.keys(SCORE_LEDGER_RISK_EVIDENCE) as IssueRiskChannel[])
    .find((candidate) =>
      SCORE_LEDGER_RISK_EVIDENCE[candidate].manifestKey === manifestKey);
  if (!channel) return undefined;
  const aliasGroup = channel === 'closureRisk'
    ? payload.key
    : payload.aliasGroup;
  const weight = channel === 'regression'
    ? payload.countedWeight
    : payload.weight;
  return {
    aliasGroup: String(aliasGroup ?? ''),
    channel,
    weight: Number(weight),
  };
}

function isScoreLedgerEvidenceOperand(
  value: unknown,
): value is ScoreLedgerEvidenceOperand {
  return isPlainRecord(value) &&
    typeof value.aliasGroup === 'string' &&
    value.aliasGroup.length > 0 &&
    (
      value.channel === 'verified' ||
      value.channel === 'carryover' ||
      value.channel === 'stale' ||
      value.channel === 'closureRisk' ||
      value.channel === 'regression'
    ) &&
    typeof value.weight === 'number' &&
    Number.isFinite(value.weight) &&
    value.weight > 0;
}

function compareScoreLedgerEvidenceRefs(
  left: ScoreLedgerEvidenceRef,
  right: ScoreLedgerEvidenceRef,
): number {
  return left.kind.localeCompare(right.kind) ||
    left.identity.localeCompare(right.identity) ||
    left.digest.localeCompare(right.digest);
}

function ledgerOperand(name: string, value: ScoreLedgerOperandValue | undefined, unit: string): ScoreLedgerOperand {
  const normalized = value === undefined ? null : value;
  return {
    name,
    type: scoreLedgerOperandType(normalized) as ScoreLedgerOperand['type'],
    value: normalized,
    unit,
  };
}

function scoreLedgerOperandType(value: unknown): ScoreLedgerOperand['type'] | 'invalid' {
  if (value == null) return 'null';
  if (typeof value === 'number' && Number.isFinite(value)) return 'number';
  if (typeof value === 'string') return 'string';
  if (typeof value === 'boolean') return 'boolean';
  return 'invalid';
}

function operandValue(operation: ScoreLedgerOperation, name: string): ScoreLedgerOperandValue | undefined {
  return operation.operands.find((operand) => operand.name === name)?.value;
}

function scoreLedgerPresentationKind(
  code: string,
  points: number,
): ScoreLedgerPresentationRow['kind'] {
  if (code === 'base') return 'base';
  if (points > 0) return 'bonus';
  if (points < 0) return 'penalty';
  return 'neutral';
}

function finiteNonNegative(value: number): number {
  return Number.isFinite(value) ? Math.max(0, value) : 0;
}

function assertFiniteInstallInputWeights(input: InstallInput): void {
  for (const field of [
    'feltOpenedWeight',
    'feltClosedWeight',
    'verifiedDebtWeight',
    'carryoverDebtWeight',
    'staleDebtWeight',
    'unresolvedClosureRiskWeight',
    'affirmativeClosureRiskCeilingWeight',
    'cveLoad',
  ] as const) {
    if (!Number.isFinite(input[field])) {
      throw new Error(`InstallInput.${field} must be a finite number`);
    }
  }
}

function roundLedgerMetric(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function ledgerNumber(value: number): number {
  return Math.round(value * 1e12) / 1e12;
}

function sameLedgerNumber(left: number | null | undefined, right: number | null | undefined): boolean {
  if (left == null || right == null) return left == null && right == null;
  return Number.isFinite(left) && Number.isFinite(right) && Math.abs(left - right) <= 1e-9;
}

function scoreLedgerDigest(value: unknown): string {
  return createHash('sha256').update(scoreLedgerCanonicalJson(value)).digest('hex');
}

function scoreLedgerCanonicalJson(value: unknown): string {
  return JSON.stringify(canonicalScoreLedgerValue(value));
}

function canonicalScoreLedgerValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => canonicalScoreLedgerValue(item));
  if (!isPlainRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => [key, canonicalScoreLedgerValue(value[key])]),
  );
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function isPlainRecord(value: unknown): value is Record<string, any> {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

function deepFreeze<T>(value: T): T {
  if (value == null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  return Object.freeze(value);
}

export function pickRecommended(
  scored: RecommendationCandidate[],
): string | null {
  return selectRecommendation(scored).selectedTag;
}

export function selectRecommendation(
  scored: RecommendationCandidate[],
): {
  selectedTag: string | null;
  selectedScore: number | null;
  highestScoringTag: string | null;
  highestScore: number | null;
} {
  const candidates = scored.filter((release): release is {
    tag: string;
    status: 'eligible';
    score: number;
  } =>
    release.status === 'eligible' &&
    typeof release.score === 'number' &&
    Number.isFinite(release.score) &&
    release.score >= REC_THRESHOLD);
  if (!candidates.length) {
    return {
      selectedTag: null,
      selectedScore: null,
      highestScoringTag: null,
      highestScore: null,
    };
  }
  candidates.sort(compareRecommendationRecency);
  const highestScore = Math.max(...candidates.map((release) => release.score));
  const highestScoring = candidates.find((release) => release.score === highestScore)!;
  const selected = candidates.find((release) =>
    withinDecimalTolerance(release.score, highestScore, RECOMMENDATION_RECENCY_TOLERANCE)
  )!;
  return {
    selectedTag: selected.tag,
    selectedScore: selected.score,
    highestScoringTag: highestScoring.tag,
    highestScore,
  };
}

export function compareRecommendationRecency(
  left: Pick<RecommendationCandidate, 'tag' | 'publishedAt'>,
  right: Pick<RecommendationCandidate, 'tag' | 'publishedAt'>,
): number {
  const leftPublished = recommendationPublishedAt(left.publishedAt);
  const rightPublished = recommendationPublishedAt(right.publishedAt);
  if (
    leftPublished != null &&
    rightPublished != null &&
    leftPublished !== rightPublished
  ) {
    return rightPublished - leftPublished;
  }
  if (leftPublished != null || rightPublished != null) {
    return leftPublished != null ? -1 : 1;
  }
  try {
    const versionComparison = compareVersions(right.tag, left.tag);
    if (versionComparison !== 0) return versionComparison;
  } catch {
    // Non-version labels still get a deterministic fallback.
  }
  return right.tag.localeCompare(left.tag);
}

function recommendationPublishedAt(value: string | null | undefined): number | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function withinDecimalTolerance(
  candidate: number,
  highest: number,
  tolerance: number,
): boolean {
  if (![candidate, highest, tolerance].every(Number.isFinite) || tolerance < 0) return false;
  const scale = 1_000_000_000;
  return Math.round(candidate * scale) + Math.round(tolerance * scale) >=
    Math.round(highest * scale);
}

function isUnresolvedDebtState(state: string | undefined): boolean {
  return state === 'open' || state === 'closed-unverified';
}

function debtAdversePoints(tier: keyof DebtLoads, weight: number): number {
  if (tier === 'verified') return Math.abs(verifiedDebtPoints(weight));
  if (tier === 'carryover') return Math.abs(carryoverDebtPoints(weight));
  return Math.abs(staleDebtPoints(weight));
}

function issueRiskAdversePoints(channel: IssueRiskChannel, weight: number): number {
  if (channel === 'verified' || channel === 'carryover' || channel === 'stale') {
    return debtAdversePoints(channel, weight);
  }
  if (channel === 'closureRisk') return Math.abs(closureRiskPoints(weight));
  return Math.abs(regressionPoints(weight, 0));
}

function compareRiskCandidates(
  left: IssueRiskCandidate & { adversePoints: number },
  right: IssueRiskCandidate & { adversePoints: number },
): number {
  return right.adversePoints - left.adversePoints ||
    right.weight - left.weight ||
    riskChannelRank(right.channel) - riskChannelRank(left.channel) ||
    Number(left.issueNumber ?? Number.MAX_SAFE_INTEGER) -
      Number(right.issueNumber ?? Number.MAX_SAFE_INTEGER);
}

function riskChannelRank(channel: IssueRiskChannel): number {
  return ({
    verified: 5,
    carryover: 4,
    stale: 3,
    closureRisk: 2,
    regression: 1,
  } as Record<IssueRiskChannel, number>)[channel];
}
