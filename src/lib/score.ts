import type { IssueClassification } from './llm';

// Ported from davideuler/agent-watch's release-stability-evaluation methodology.
// Key principles:
// - Baseline for a release with zero attributed issues is NEUTRAL (5), not perfect (10).
//   "No signal" ≠ "good"; we explicitly don't know.
// - Per-issue cap so one nasty bug can't single-handedly crash the score.
// - Core-serious (core + critical/high) issues drive the score; other issues are
//   limited to a small bounded penalty.
// - Hard floor at 1.0 so unstable releases stay distinguishable from "grey".
// - Recency decay floors at 0.55 — old issues still matter but less.

const PER_ISSUE_CAP = 5;
const OTHER_DROP_MAX = 2.0;
const OTHER_DROP_TAU = 3.0;
const MIN_SCORE = 1.0;
const NEUTRAL_SCORE = 5.0;
const POS_OFFSET = 0.7;
const NEW_VERSION_GREY_HOURS = 3;
const HALF_LIFE_DAYS = 45;
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
export const PEER_MEDIAN_FLOOR = 5.5; // bumped by refresh.ts when signal ≤ median
// Bot-generated issues still get counted, but their contribution is dampened. They tend
// to over-report (one human bug → 20 bot reports), so weighting prevents volume bias
// while preserving the underlying signal.
const BOT_WEIGHT_MULTIPLIER = 0.3;

const SEVERITY: Record<IssueClassification['severity'], number> = {
  critical: 2.8,
  high: 1.9,
  medium: 1.0,
  low: 0.35,
};

const SCOPE: Record<IssueClassification['scope'], number> = {
  broad: 1.75,
  moderate: 1.0,
  niche: 0.3,
};

const FUNCTIONALITY: Record<IssueClassification['functionality'], number> = {
  core: 1.65,
  provider: 0.75,
  integration: 0.45,
  docs: 0.15,
};

const USER_SHARE: Record<IssueClassification['affectedUsers'], number> = {
  many: 1.45,
  some: 0.9,
  few: 0.35,
  unknown: 0.75,
};

const WORKAROUND: Record<IssueClassification['workaroundStatus'], number> = {
  none: 1.0,
  unknown: 0.85,
  partial: 0.65,
  confirmed: 0.35,
};

export interface IssueInput {
  number: number;
  updatedAt: string;
  commentCount: number;
  publishedAt: string | null; // release published_at, used for age-based grace + signal age
  isBot: boolean;             // true → contribution multiplied by BOT_WEIGHT_MULTIPLIER
  classification: IssueClassification;
}

export interface ScoredIssue {
  number: number;
  weight: number;
  isCoreSerious: boolean;
  classification: IssueClassification;
}

export interface ScoreBreakdown {
  finalScore: number;
  baseScore: number;
  riskIndex: number;          // effective core risk, post-cancellation
  weightedNegSum: number;     // total negative signal pre-cancellation, used for peer median
  negativeIssues: number;
  positiveIssues: number;
  perIssue: ScoredIssue[];
  state: 'analyzing' | 'rated' | 'insufficient';
}

function recencyFactor(createdAt: string, now: number): number {
  const ageDays = Math.max(0, now - Date.parse(createdAt)) / DAY_MS;
  return 0.55 + 0.45 * Math.exp(-ageDays / HALF_LIFE_DAYS);
}

function discussionBoost(commentCount: number): number {
  return 1 + Math.min(1.4, Math.log10(1 + commentCount) * 0.45);
}

function duplicateBoost(clusterSize: number): number {
  if (clusterSize <= 1) return 1;
  return 1 + Math.log2(clusterSize) * 0.28;
}

function issueRiskWeight(i: IssueInput, now: number, clusterSize: number): number {
  const c = i.classification;
  const conf = Math.max(0.2, c.confidence);
  const botFactor = i.isBot ? BOT_WEIGHT_MULTIPLIER : 1.0;
  return (
    recencyFactor(i.updatedAt, now) *
    discussionBoost(i.commentCount) *
    duplicateBoost(clusterSize) *
    conf *
    SEVERITY[c.severity] *
    SCOPE[c.scope] *
    FUNCTIONALITY[c.functionality] *
    USER_SHARE[c.affectedUsers] *
    WORKAROUND[c.workaroundStatus] *
    botFactor
  );
}

function positiveEvidenceWeight(i: IssueInput, now: number): number {
  const ageDays = Math.max(0, now - Date.parse(i.updatedAt)) / DAY_MS;
  const recency = 0.65 + 0.35 * Math.exp(-ageDays / HALF_LIFE_DAYS);
  const dboost = 1 + Math.min(0.8, Math.log10(1 + i.commentCount) * 0.3);
  return recency * dboost * Math.max(0.2, i.classification.confidence);
}

function scoreFromRiskIndex(riskIndex: number): number {
  return 10 / (1 + Math.pow(Math.max(0, riskIndex) / 4.2, 1.35));
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

export function scoreRelease(
  issues: IssueInput[],
  releasePublishedAt: string | null,
  now = Date.now(),
  peerMedianWeightedNeg?: number,
): ScoreBreakdown {
  // 3-hour grace period for fresh releases — no useful signal yet.
  if (releasePublishedAt) {
    const ageMs = now - Date.parse(releasePublishedAt);
    if (ageMs >= 0 && ageMs < NEW_VERSION_GREY_HOURS * HOUR_MS) {
      return {
        finalScore: NEUTRAL_SCORE,
        baseScore: NEUTRAL_SCORE,
        riskIndex: 0,
        weightedNegSum: 0,
        negativeIssues: 0,
        positiveIssues: 0,
        perIssue: [],
        state: 'analyzing',
      };
    }
  }

  // No attributed issues → neutral baseline. Score reflects absence of signal, not "perfect".
  if (issues.length === 0) {
    return {
      finalScore: NEUTRAL_SCORE,
      baseScore: NEUTRAL_SCORE,
      riskIndex: 0,
      weightedNegSum: 0,
      negativeIssues: 0,
      positiveIssues: 0,
      perIssue: [],
      state: 'insufficient',
    };
  }

  // Cluster sizes for duplicate boost.
  const clusterSizes = new Map<string, number>();
  for (const i of issues) {
    const key = i.classification.duplicateCluster;
    if (!key) continue;
    clusterSizes.set(key, (clusterSizes.get(key) ?? 0) + 1);
  }

  let weightedNegCoreSerious = 0;
  let weightedNegOther = 0;
  let weightedPos = 0;
  let neg = 0;
  let pos = 0;
  const perIssue: ScoredIssue[] = [];

  for (const i of issues) {
    const c = i.classification;
    const clusterSize = c.duplicateCluster ? clusterSizes.get(c.duplicateCluster) ?? 1 : 1;

    if (c.sentiment === 'negative') {
      const raw = issueRiskWeight(i, now, clusterSize);
      const w = Math.min(raw, PER_ISSUE_CAP);
      const isCoreSerious = c.functionality === 'core' && (c.severity === 'critical' || c.severity === 'high');
      if (isCoreSerious) {
        weightedNegCoreSerious += w;
      } else {
        weightedNegOther += w;
      }
      neg++;
      perIssue.push({ number: i.number, weight: -w, isCoreSerious, classification: c });
    } else if (c.sentiment === 'positive') {
      const w = positiveEvidenceWeight(i, now);
      weightedPos += w;
      pos++;
      perIssue.push({ number: i.number, weight: w, isCoreSerious: false, classification: c });
    } else {
      perIssue.push({ number: i.number, weight: 0, isCoreSerious: false, classification: c });
    }
  }

  // Positives cancel non-core-serious negatives first, then residual budget eats core-serious.
  const posBudget = POS_OFFSET * weightedPos;
  const otherCancel = Math.min(weightedNegOther, posBudget);
  const coreCancel = Math.min(weightedNegCoreSerious, Math.max(0, posBudget - otherCancel));
  const effectiveCore = Math.max(0, weightedNegCoreSerious - coreCancel);
  const effectiveOther = Math.max(0, weightedNegOther - otherCancel);

  // Core drives the score; other issues drop it by at most OTHER_DROP_MAX.
  const coreScore = scoreFromRiskIndex(effectiveCore);
  const otherDrop = OTHER_DROP_MAX * (1 - Math.exp(-effectiveOther / OTHER_DROP_TAU));
  let finalScore = clamp(coreScore - otherDrop, MIN_SCORE, 10);
  const baseScore = finalScore;

  // Peer median floor: if this release's total negative signal is at or below the median
  // across all rated releases in this project, and our score fell below 5.5, lift it
  // to 5.5. Prevents an unusually-buggy project from making every average release look
  // catastrophic.
  const weightedNegSum = weightedNegCoreSerious + weightedNegOther;
  if (
    peerMedianWeightedNeg !== undefined &&
    Number.isFinite(peerMedianWeightedNeg) &&
    peerMedianWeightedNeg > 0 &&
    weightedNegSum <= peerMedianWeightedNeg &&
    finalScore < PEER_MEDIAN_FLOOR
  ) {
    finalScore = PEER_MEDIAN_FLOOR;
  }

  return {
    finalScore: round1(finalScore),
    baseScore: round1(baseScore),
    riskIndex: round2(effectiveCore),
    weightedNegSum: round2(weightedNegSum),
    negativeIssues: neg,
    positiveIssues: pos,
    perIssue,
    state: 'rated',
  };
}
