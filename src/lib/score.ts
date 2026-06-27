// Evidence-based Install Confidence.
//
// This model answers "should I install this stable?" using hard safety gates
// plus explicit evidence tiers. Release-local blockers and regressions matter
// most. Historical unresolved backlog is shown, but capped so the latest release
// is not buried just because old issues remain open.

const HOUR_MS = 60 * 60 * 1000;

export const SCORE_MODEL_VERSION = 'evidence-v5-community-risk';
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
const COVERAGE_MAX = -2.5;
const REGRESSION_DOWN = -0.8;
const REGRESSION_UP = 0.4;
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
  rawIssueCount: number;
  classifiedIssueCount: number;
  cveAffected: boolean;
  cveLoad: number;
}

export interface InstallComponents {
  base: number;
  verifiedDebt: number;
  carryoverDebt: number;
  staleDebt: number;
  coverage: number;
  survival: number;
  shakeout: number;
  regression: number;
  breaking: number;
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
  duplicateCluster?: string | null;
  author?: string | null;
  isBot?: boolean | number;
  comments?: number;
  clusterHumanReporterCount?: number;
  clusterCommentCount?: number;
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

function enrichIssueSignals<T extends IssueSignalFields>(items: T[]): Array<T & Required<Pick<IssueSignalFields, 'clusterHumanReporterCount' | 'clusterCommentCount'>>> {
  const stats = new Map<string, { reporters: Set<string>; comments: number }>();
  items.forEach((item, index) => {
    const key = issueKey(item, index);
    const current = stats.get(key) ?? { reporters: new Set<string>(), comments: 0 };
    if (!isBotIssue(item) && item.author) current.reporters.add(item.author);
    current.comments += Math.max(0, item.comments ?? 0);
    stats.set(key, current);
  });
  return items.map((item, index) => {
    const current = stats.get(issueKey(item, index));
    return {
      ...item,
      clusterHumanReporterCount: current?.reporters.size ?? 0,
      clusterCommentCount: current?.comments ?? 0,
    };
  });
}

function hasCommunityConfirmation(item: IssueSignalFields): boolean {
  return (item.clusterHumanReporterCount ?? 0) >= 2 || (item.clusterCommentCount ?? item.comments ?? 0) >= 6;
}

function communityMultiplier(item: IssueSignalFields): number {
  const reporters = Math.max(0, item.clusterHumanReporterCount ?? (isBotIssue(item) ? 0 : item.author ? 1 : 0));
  const comments = Math.max(0, item.clusterCommentCount ?? item.comments ?? 0);
  const reporterLift = Math.log1p(Math.max(0, reporters - 1)) * 0.25;
  const commentLift = Math.log1p(comments) * 0.08;
  return clamp(1 + reporterLift + commentLift, 0.75, 1.6);
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
  const releaseSpecific = item.releaseLocal === true;
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
  const buckets = {
    verified: new Map<string, number>(),
    carryover: new Map<string, number>(),
    stale: new Map<string, number>(),
  };
  const evidenceByKey = new Map<string, DebtEvidenceItem>();
  for (const [index, item] of enrichedItems.entries()) {
    const weight = issueDebtWeight(item);
    if (weight <= 0) continue;
    const tier = classifyDebtTier(item);
    const bucket = buckets[tier];
    const key = issueKey(item, index);
    const previous = bucket.get(key) ?? 0;
    if (weight > previous) {
      bucket.set(key, weight);
      evidenceByKey.set(`${tier}:${key}`, {
        issueNumber: item.issueNumber,
        duplicateCluster: item.duplicateCluster,
        tier,
        weight,
        humanReporterCount: item.clusterHumanReporterCount,
        commentCount: item.clusterCommentCount,
        fieldConfirmed: hasFieldConfirmation(item),
      });
    }
  }
  const loads = {
    verified: [...buckets.verified.values()].reduce((sum, weight) => sum + weight, 0),
    carryover: [...buckets.carryover.values()].reduce((sum, weight) => sum + weight, 0),
    stale: [...buckets.stale.values()].reduce((sum, weight) => sum + weight, 0),
  };
  return {
    loads,
    evidence: [...evidenceByKey.values()].sort((a, b) => b.weight - a.weight),
  };
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
  if (input.feltClosedWeight > input.feltOpenedWeight && input.feltClosedWeight > 2) {
    bits.push('net-fixing field-visible bugs');
  } else if (input.feltOpenedWeight > input.feltClosedWeight && input.feltOpenedWeight > 2) {
    bits.push('net-opening field-visible bugs');
  }
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
  const survival = survivalPoints(input, age);
  const shakeout = shakeoutPoints(input.betaCount);
  const regression = regressionPoints(input.feltOpenedWeight, input.feltClosedWeight);
  const breaking = breakingPoints(input.breakingCount);
  let score = clamp(
    BASE + verifiedDebt + carryoverDebt + staleDebt + coverage.points + survival + shakeout + regression + breaking,
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
      coverage: round1(coverage.points),
      survival: round1(survival),
      shakeout: round1(shakeout),
      regression: round1(regression),
      breaking: round1(breaking),
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
