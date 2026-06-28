// Evidence-based Install Confidence.
//
// This model answers "should I install this stable?" using hard safety gates
// plus explicit evidence tiers. Release-local blockers and regressions matter
// most. Historical unresolved backlog is shown, but capped so the latest release
// is not buried just because old issues remain open.

const HOUR_MS = 60 * 60 * 1000;

export const SCORE_MODEL_VERSION = 'evidence-v11-closure-risk';
export const REC_THRESHOLD = 5.5;

const SETTLE_HOURS = 24;
const HOTFIX_GAP_HOURS = 6;
const PIVOT_HOURS = 24;
const BASE = 7.5;
const HOTFIX_SCORE_CAP = 4.9;

const SURVIVAL_MIN = -2.5;
const SURVIVAL_MAX = 1.8;
const SHAKEOUT_MAX = 0.8;
const BREAKING_PER_BULLET = -0.25;
const BREAKING_MAX_BULLETS = 6;

const VERIFIED_DEBT_MAX = -2.0;
const CARRYOVER_DEBT_MAX = -0.6;
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

export interface InstallInput {
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
  unresolvedClosureRiskWeight: number;
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
  evidenceCoverage: number;
  reason: string;
}

interface IssueSignalFields {
  issueNumber?: number;
  title?: string | null;
  duplicateCluster?: string | null;
  author?: string | null;
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
  clusterCommentCount?: number;
  clusterHumanCommenterCount?: number;
  clusterMaintainerCommenterCount?: number;
  clusterContributorCommenterCount?: number;
  clusterReactionTotal?: number;
  clusterPositiveReactionCount?: number;
  clusterReleaseLocal?: boolean;
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
}

export interface DebtClassification extends FeltClassification {
  workaroundStatus?: string;
  confidence?: number;
  state?: string;
  createdAt?: string | null;
  updatedAt?: string | null;
  affectsVersion?: string | null;
  releaseLocal?: boolean;
  labels?: string[];
}

export interface DebtLoads {
  verified: number;
  carryover: number;
  stale: number;
}

export interface DebtEvidenceItem {
  issueNumber?: number;
  duplicateCluster?: string | null;
  tier: keyof DebtLoads;
  weight: number;
  humanReporterCount?: number;
  commentCount?: number;
  fieldConfirmed?: boolean;
  humanCommenterCount?: number;
  maintainerCommenterCount?: number;
  contributorCommenterCount?: number;
  reactionTotal?: number;
  positiveReactionCount?: number;
  commenterScanTruncated?: boolean;
  installImpactClass?: string;
  clusterReleaseLocal?: boolean;
}

export interface DebtExplanation {
  loads: DebtLoads;
  evidence: DebtEvidenceItem[];
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

function ageHours(publishedAt: string | null, now: number): number {
  if (!publishedAt) return Infinity;
  return (now - Date.parse(publishedAt)) / HOUR_MS;
}

function survivalPoints(input: InstallInput, age: number): number {
  if (input.isLatest) {
    return clamp(Math.log2(Math.max(1, age) / 48) * 0.45, 0, 1.5);
  }
  if (input.hoursToNextStable == null) return 0;
  return clamp(
    Math.log2(Math.max(1, input.hoursToNextStable) / PIVOT_HOURS) * 0.7,
    SURVIVAL_MIN,
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

function issueKey(item: IssueSignalFields, index: number): string {
  return item.duplicateCluster || `issue:${item.issueNumber ?? index}`;
}

function isBotIssue(item: IssueSignalFields): boolean {
  if (item.isBot === true || item.isBot === 1) return true;
  return /\[bot\]$/i.test(item.author ?? '');
}

function enrichIssueSignals<T extends IssueSignalFields>(items: T[]): Array<T & Required<Pick<IssueSignalFields,
  'clusterHumanReporterCount' |
  'clusterCommentCount' |
  'clusterHumanCommenterCount' |
  'clusterMaintainerCommenterCount' |
  'clusterContributorCommenterCount' |
  'clusterReactionTotal' |
  'clusterPositiveReactionCount'
>>> {
  const stats = new Map<string, {
    reporters: Set<string>;
    comments: number;
    humanCommenters: number;
    maintainerCommenters: number;
    contributorCommenters: number;
    reactions: number;
    positiveReactions: number;
    releaseLocalValues: boolean[];
  }>();
  items.forEach((item, index) => {
    const key = issueKey(item, index);
    const current = stats.get(key) ?? {
      reporters: new Set<string>(),
      comments: 0,
      humanCommenters: 0,
      maintainerCommenters: 0,
      contributorCommenters: 0,
      reactions: 0,
      positiveReactions: 0,
      releaseLocalValues: [],
    };
    if (!isBotIssue(item) && item.author) current.reporters.add(item.author);
    current.comments += Math.max(0, item.comments ?? 0);
    current.humanCommenters += Math.max(0, item.uniqueHumanCommenterCount ?? 0);
    current.maintainerCommenters += Math.max(0, item.maintainerCommenterCount ?? 0);
    current.contributorCommenters += Math.max(0, item.contributorCommenterCount ?? 0);
    current.reactions += Math.max(0, item.reactionTotal ?? 0);
    current.positiveReactions += Math.max(0, item.positiveReactionCount ?? 0);
    const releaseLocal = (item as IssueSignalFields & { releaseLocal?: boolean }).releaseLocal;
    if (typeof releaseLocal === 'boolean') current.releaseLocalValues.push(releaseLocal);
    stats.set(key, current);
  });
  return items.map((item, index) => {
    const current = stats.get(issueKey(item, index));
    return {
      ...item,
      clusterHumanReporterCount: current?.reporters.size ?? 0,
      clusterCommentCount: current?.comments ?? 0,
      clusterHumanCommenterCount: current?.humanCommenters ?? 0,
      clusterMaintainerCommenterCount: current?.maintainerCommenters ?? 0,
      clusterContributorCommenterCount: current?.contributorCommenters ?? 0,
      clusterReactionTotal: current?.reactions ?? 0,
      clusterPositiveReactionCount: current?.positiveReactions ?? 0,
      clusterReleaseLocal: current?.releaseLocalValues.length
        ? current.releaseLocalValues.every(Boolean)
        : undefined,
    };
  });
}

function hasCommunityConfirmation(item: IssueSignalFields): boolean {
  return (item.clusterHumanReporterCount ?? 0) >= 2 || (item.clusterHumanCommenterCount ?? 0) >= 2;
}

function communityMultiplier(item: IssueSignalFields): number {
  const reporters = Math.max(0, item.clusterHumanReporterCount ?? (isBotIssue(item) ? 0 : item.author ? 1 : 0));
  const commenters = Math.max(0, item.clusterHumanCommenterCount ?? item.uniqueHumanCommenterCount ?? 0);
  const contributors = Math.max(0, item.clusterContributorCommenterCount ?? item.contributorCommenterCount ?? 0);
  const positiveReactions = Math.max(0, item.clusterPositiveReactionCount ?? item.positiveReactionCount ?? 0);
  const reporterLift = Math.log1p(Math.max(0, reporters - 1)) * 0.25;
  const commenterLift = Math.log1p(commenters) * 0.18;
  const contributorLift = Math.log1p(contributors) * 0.08;
  const reactionLift = Math.log1p(positiveReactions) * 0.04;
  return clamp(1 + reporterLift + commenterLift + contributorLift + reactionLift, 0.75, 1.65);
}

function installImpactClass(item: DebtClassification): string {
  const title = `${item.title ?? ''} ${item.duplicateCluster ?? ''} ${item.issueNumber ?? ''}`.toLowerCase();
  const labels = item.labels ?? [];
  if (labels.includes('security')) return 'security';
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

function installImpactMultiplier(item: DebtClassification): number {
  const klass = installImpactClass(item);
  if (klass === 'security') return 0.45;
  if (klass === 'provider') return 0.65;
  if (klass === 'message_delivery') return 0.9;
  if (klass === 'state_data') return 1;
  return 0.75;
}

function issueDebtWeight(item: DebtClassification): number {
  if (item.state !== 'open') return 0;
  if (item.sentiment !== 'negative') return 0;

  const severity = SEVERITY_WEIGHT[item.severity] ?? 0;
  const functionality = FUNCTIONALITY_WEIGHT[item.functionality] ?? 0;
  if (severity === 0 || functionality === 0) return 0;

  const reach =
    (SCOPE_WEIGHT[item.scope] ?? 1) *
    (USERS_WEIGHT[item.affectedUsers] ?? 0.65);
  const confidence = 0.5 + 0.5 * clamp(item.confidence ?? 0.5, 0, 1);
  const sourceShape = isSourceOnlySignal(item) ? 0.8 : 1;
  return severity *
    functionality *
    reach *
    confidence *
    workaroundMultiplier(item.workaroundStatus) *
    communityMultiplier(item) *
    installImpactMultiplier(item) *
    sourceShape;
}

function hasAnyLabel(item: { labels?: string[] }, names: string[]): boolean {
  return names.some((name) => item.labels?.includes(name));
}

function isWeakEvidence(item: DebtClassification): boolean {
  return (
    hasAnyLabel(item, ['stale', 'clawsweeper:needs-info', 'clawsweeper:needs-live-repro', 'enhancement']) ||
    item.confidence != null && item.confidence < 0.65 ||
    item.functionality === 'docs' ||
    item.severity === 'low'
  );
}

function hasFieldConfirmation(item: IssueSignalFields & { labels?: string[] }): boolean {
  const emergency = hasAnyLabel(item, ['P0', 'beta-blocker']);
  const fieldRegression =
    hasAnyLabel(item, ['P1']) &&
    hasAnyLabel(item, ['bug', 'bug:behavior']) &&
    hasAnyLabel(item, ['regression']);
  const maintainerConfirmed =
    hasAnyLabel(item, ['maintainer']) &&
    hasAnyLabel(item, ['bug', 'bug:behavior', 'P1', 'regression']);
  return emergency || fieldRegression || maintainerConfirmed || hasCommunityConfirmation(item);
}

function isSourceOnlySignal(item: IssueSignalFields & { labels?: string[] }): boolean {
  return hasAnyLabel(item, ['clawsweeper:source-repro', 'clawsweeper:current-main-repro']) &&
    !hasFieldConfirmation(item);
}

function classifyDebtTier(item: DebtClassification): keyof DebtLoads {
  const releaseSpecific = (item.clusterReleaseLocal ?? item.releaseLocal) === true;
  const defaultPathImpact =
    item.functionality === 'core' &&
    (item.scope === 'broad' || item.affectedUsers === 'many' || hasAnyLabel(item, ['P0', 'beta-blocker']));
  const weak = isWeakEvidence(item);

  if (
    releaseSpecific &&
    hasFieldConfirmation(item) &&
    defaultPathImpact &&
    !weak &&
    (item.severity === 'critical' || item.severity === 'high')
  ) return 'verified';
  if (weak || item.severity === 'medium') return 'stale';
  return 'carryover';
}

// Bucket current open debt. Only release-local field/community evidence can
// become hard debt. Source-only/static findings remain visible as capped context.
export function explainOpenDebtLoad(items: DebtClassification[]): DebtExplanation {
  const enrichedItems = enrichIssueSignals(items);
  const evidenceByKey = new Map<string, DebtEvidenceItem>();
  for (const [index, item] of enrichedItems.entries()) {
    const weight = issueDebtWeight(item);
    if (weight <= 0) continue;
    const tier = classifyDebtTier(item);
    const key = issueKey(item, index);
    const previous = evidenceByKey.get(key);
    if (!previous || shouldReplaceDebtEvidence({ tier, weight }, previous)) {
      evidenceByKey.set(key, {
        issueNumber: item.issueNumber,
        duplicateCluster: item.duplicateCluster,
        tier,
        weight,
        humanReporterCount: item.clusterHumanReporterCount,
        commentCount: item.clusterCommentCount,
        fieldConfirmed: hasFieldConfirmation(item),
        humanCommenterCount: item.clusterHumanCommenterCount,
        maintainerCommenterCount: item.clusterMaintainerCommenterCount,
        contributorCommenterCount: item.clusterContributorCommenterCount,
        reactionTotal: item.clusterReactionTotal,
        positiveReactionCount: item.clusterPositiveReactionCount,
        commenterScanTruncated: item.commenterScanTruncated === true || item.commenterScanTruncated === 1,
        installImpactClass: installImpactClass(item),
        clusterReleaseLocal: item.clusterReleaseLocal,
      });
    }
  }
  const evidence = [...evidenceByKey.values()];
  const loads = {
    verified: evidence.filter((item) => item.tier === 'verified').reduce((sum, item) => sum + item.weight, 0),
    carryover: evidence.filter((item) => item.tier === 'carryover').reduce((sum, item) => sum + item.weight, 0),
    stale: evidence.filter((item) => item.tier === 'stale').reduce((sum, item) => sum + item.weight, 0),
  };
  return {
    loads,
    evidence: evidence.sort((a, b) => b.weight - a.weight),
  };
}

const DEBT_TIER_RANK: Record<keyof DebtLoads, number> = { verified: 3, carryover: 2, stale: 1 };

function shouldReplaceDebtEvidence(
  candidate: Pick<DebtEvidenceItem, 'tier' | 'weight'>,
  previous: Pick<DebtEvidenceItem, 'tier' | 'weight'>,
): boolean {
  const rankDiff = DEBT_TIER_RANK[candidate.tier] - DEBT_TIER_RANK[previous.tier];
  if (rankDiff !== 0) return rankDiff > 0;
  return candidate.weight > previous.weight;
}

export function openDebtLoad(items: DebtClassification[]): DebtLoads {
  return explainOpenDebtLoad(items).loads;
}

// Reach-weighted visible-bug load used for the opened/closed reign balance.
export function feltLoad(items: FeltClassification[]): number {
  return enrichIssueSignals(items).reduce((sum, item) => {
    if (!isFeltSignal(item)) return sum;
    return sum
      + (SCOPE_WEIGHT[item.scope] ?? 1)
      * (USERS_WEIGHT[item.affectedUsers] ?? 0.65)
      * workaroundMultiplier(item.workaroundStatus)
      * communityMultiplier(item);
  }, 0);
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
  if (item.confidence != null && item.confidence < 0.65) return false;
  if (isSourceOnlySignal(item)) return false;
  return true;
}

function verifiedDebtPoints(load: number): number {
  return clamp(-Math.log1p(Math.max(0, load)) * 0.35, VERIFIED_DEBT_MAX, 0);
}

function carryoverDebtPoints(load: number): number {
  return clamp(-Math.log1p(Math.max(0, load)) * 0.12, CARRYOVER_DEBT_MAX, 0);
}

function staleDebtPoints(load: number): number {
  return clamp(-Math.log1p(Math.max(0, load)) * 0.05, STALE_DEBT_MAX, 0);
}

function closureRiskPoints(load: number): number {
  return clamp(-Math.log1p(Math.max(0, load)) * 0.08, CLOSURE_RISK_MAX, 0);
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
  if (failures > 0 || ['FAILURE', 'ERROR', 'EXPECTED', 'ACTION_REQUIRED'].includes(state)) {
    return clamp(-0.8 - Math.log1p(failures) * 0.25, RELEASE_CHECK_DOWN, 0);
  }
  if (pending > 0 || ['PENDING'].includes(state)) {
    return clamp(-0.25 - Math.log1p(pending) * 0.08, RELEASE_CHECK_DOWN, 0);
  }
  if (state === 'SUCCESS' && successes > 0) {
    return clamp(Math.log1p(successes) * 0.18, 0, RELEASE_CHECK_UP);
  }
  return 0;
}

function artifactVerificationPoints(input: InstallInput): number {
  if (input.artifactMismatch) return ARTIFACT_DOWN;
  let points = 0;
  if (input.artifactVerified && input.releaseIntegrityPresent && input.releaseShaMatches !== false) {
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
  age: number,
  coverage: number,
  debt: DebtLoads,
): string {
  if (status === 'skip-cve') return 'known medium-or-higher CVE exposure';
  if (status === 'wait') return `only ${(age / 24).toFixed(1)}d old — no settle signal yet`;
  if (status === 'skip-hotfix') {
    return input.hasHotfixSuccessor
      ? 'maintainers shipped a hotfix patch on top of it'
      : `replaced by the next stable within ${Math.round(input.hoursToNextStable ?? 0)}h`;
  }

  const bits: string[] = [];
  if (input.isLatest) {
    bits.push(`latest — stood ${(age / 24).toFixed(1)}d with no hotfix`);
  } else if (input.hoursToNextStable != null) {
    bits.push(`stood ${input.hoursToNextStable >= 24
      ? `${(input.hoursToNextStable / 24).toFixed(1)}d`
      : `${Math.round(input.hoursToNextStable)}h`} as current stable`);
  }
  if (debt.verified > 2) bits.push(`${Math.round(debt.verified)} field-confirmed blocker risk`);
  if (debt.carryover > 8) bits.push(`${Math.round(debt.carryover)} source/carryover risk`);
  if (input.unresolvedClosureRiskWeight > 0) bits.push(`${Math.round(input.unresolvedClosureRiskWeight)} unresolved closed-release risk`);
  if (input.feltClosedWeight > input.feltOpenedWeight && input.feltClosedWeight > 2) {
    bits.push('net-fixing field-visible bugs');
  } else if (input.feltOpenedWeight > input.feltClosedWeight && input.feltOpenedWeight > 2) {
    bits.push('net-opening field-visible bugs');
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
  } else if (input.artifactVerified) {
    bits.push('npm artifact verified');
  }
  if (input.ciReportMismatch) bits.push('release evidence report missing');
  if (input.betaCount > 0) bits.push(`${input.betaCount} betas baked`);
  if (input.breakingCount > 0) bits.push(`${input.breakingCount} breaking`);
  if (coverage < 0.95) bits.push(`${Math.round(coverage * 100)}% evidence coverage`);
  return bits.join(', ') || 'no adverse signal';
}

export function installConfidence(input: InstallInput, now: number = Date.now()): InstallConfidence {
  const age = ageHours(input.publishedAt, now);
  const coverage = coveragePoints(input.rawIssueCount, input.classifiedIssueCount);
  const hotfix =
    !input.isLatest &&
    (input.hasHotfixSuccessor ||
      (input.hoursToNextStable != null && input.hoursToNextStable < HOTFIX_GAP_HOURS));

  if (input.cveAffected) {
    const score = round1(clamp(4.9 * (1 - Math.min(1, input.cveLoad / 30)), 0, 4.9));
    return {
      score,
      status: 'skip-cve',
      band: 'skip',
      hotfix,
      components: null,
      evidenceCoverage: coverage.ratio,
      reason: reasonFor(input, 'skip-cve', age, coverage.ratio, {
        verified: input.verifiedDebtWeight,
        carryover: input.carryoverDebtWeight,
        stale: input.staleDebtWeight,
      }),
    };
  }

  if (!(age >= SETTLE_HOURS)) {
    return {
      score: null,
      status: 'wait',
      band: 'wait',
      hotfix,
      components: null,
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
  let score = clamp(
    BASE + verifiedDebt + carryoverDebt + staleDebt + closureRisk + coverage.points + survival + shakeout + regression + breaking + releaseVerification + artifactVerification,
    0,
    10,
  );
  if (hotfix) score = Math.min(score, HOTFIX_SCORE_CAP);

  const rounded = round1(score);
  return {
    score: rounded,
    status: hotfix ? 'skip-hotfix' : 'eligible',
    band: bandFor(rounded, hotfix ? 'skip-hotfix' : 'eligible'),
    hotfix,
    components: {
      base: BASE,
      verifiedDebt: round1(verifiedDebt),
      carryoverDebt: round1(carryoverDebt),
      staleDebt: round1(staleDebt),
      closureRisk: round1(closureRisk),
      coverage: round1(coverage.points),
      survival: round1(survival),
      shakeout: round1(shakeout),
      regression: round1(regression),
      breaking: round1(breaking),
      releaseVerification: round1(releaseVerification),
      artifactVerification: round1(artifactVerification),
    },
    evidenceCoverage: coverage.ratio,
    reason: reasonFor(input, hotfix ? 'skip-hotfix' : 'eligible', age, coverage.ratio, {
      verified: input.verifiedDebtWeight,
      carryover: input.carryoverDebtWeight,
      stale: input.staleDebtWeight,
    }),
  };
}

export function pickRecommended(
  scored: Array<{ tag: string; status: InstallStatus; score: number | null }>,
): string | null {
  for (const release of scored) {
    if (release.status === 'eligible' && release.score != null && release.score >= REC_THRESHOLD) {
      return release.tag;
    }
  }
  return null;
}
