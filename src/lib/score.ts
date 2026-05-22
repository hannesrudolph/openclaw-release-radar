import type { IssueClassification } from './llm';

// ---- multipliers (copy of agent-watch tuning) ----
const SEVERITY: Record<IssueClassification['severity'], number> = {
  critical: 3.0,
  high: 2.0,
  medium: 1.0,
  low: 0.4,
};

const SCOPE: Record<IssueClassification['scope'], number> = {
  broad: 1.6,
  moderate: 1.0,
  niche: 0.5,
};

const FUNCTIONALITY: Record<IssueClassification['functionality'], number> = {
  core: 1.5,
  integration: 1.0,
  provider: 0.8,
  docs: 0.2,
};

const USER_SHARE: Record<IssueClassification['affectedUsers'], number> = {
  many: 1.4,
  some: 1.0,
  few: 0.6,
  unknown: 0.8,
};

const HALF_LIFE_DAYS = 45;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface ScoredIssue {
  number: number;
  weight: number; // signed: negative for problems, positive for praise
  isCore: boolean;
  classification: IssueClassification;
}

export interface IssueInput {
  number: number;
  updatedAt: string; // ISO
  commentCount: number;
  classification: IssueClassification;
}

function recencyFactor(updatedAt: string, now: number): number {
  const age = Math.max(0, now - Date.parse(updatedAt));
  const halfLives = age / (HALF_LIFE_DAYS * DAY_MS);
  return Math.pow(0.5, halfLives);
}

function discussionBoost(commentCount: number): number {
  // log-scaled: 0c → 1.0, 5c → ~1.5, 20c → ~2.1, 50c → ~2.7
  return 1 + Math.log10(1 + commentCount) * 0.7;
}

function duplicateBoost(clusterSize: number): number {
  // 1 issue → 1.0, 2 → 1.4, 3 → 1.65, 5 → 2.0
  if (clusterSize <= 1) return 1;
  return 1 + Math.log2(clusterSize) * 0.4;
}

export interface ScoreBreakdown {
  finalScore: number;          // 0..10, 10 = perfect stability
  baseScore: number;           // same as final without rating blend
  riskIndex: number;           // raw aggregated risk
  negativeIssues: number;
  positiveIssues: number;
  perIssue: ScoredIssue[];
}

export function scoreRelease(issues: IssueInput[], now = Date.now()): ScoreBreakdown {
  // 1. group by duplicate cluster to compute cluster size
  const clusterSizes = new Map<string, number>();
  for (const i of issues) {
    const key = i.classification.duplicateCluster;
    if (!key) continue;
    clusterSizes.set(key, (clusterSizes.get(key) ?? 0) + 1);
  }

  // 2. compute per-issue weights
  const scored: ScoredIssue[] = issues.map((i) => {
    const c = i.classification;
    const sign = c.sentiment === 'negative' ? -1 : c.sentiment === 'positive' ? 1 : 0;
    if (sign === 0) {
      return { number: i.number, weight: 0, isCore: c.functionality === 'core', classification: c };
    }
    const workaround = c.hasWorkaround ? 0.6 : 1.0;
    const clusterSize = c.duplicateCluster ? clusterSizes.get(c.duplicateCluster) ?? 1 : 1;
    const w =
      recencyFactor(i.updatedAt, now) *
      discussionBoost(i.commentCount) *
      duplicateBoost(clusterSize) *
      c.confidence *
      SEVERITY[c.severity] *
      SCOPE[c.scope] *
      FUNCTIONALITY[c.functionality] *
      USER_SHARE[c.affectedUsers] *
      workaround;
    return {
      number: i.number,
      weight: sign * w,
      isCore: c.functionality === 'core',
      classification: c,
    };
  });

  // 3. cancel: positives offset negatives. Non-core first, then core.
  let positiveBudget = scored.filter((s) => s.weight > 0).reduce((a, s) => a + s.weight, 0);
  const negatives = scored.filter((s) => s.weight < 0).map((s) => ({ ...s }));
  // sort negatives: cancel non-core first
  negatives.sort((a, b) => Number(a.isCore) - Number(b.isCore));
  for (const n of negatives) {
    if (positiveBudget <= 0) break;
    const absW = -n.weight;
    const taken = Math.min(absW, positiveBudget);
    n.weight += taken; // moves toward 0
    positiveBudget -= taken;
  }

  const riskIndex = negatives.reduce((a, n) => a + Math.max(0, -n.weight), 0);
  const baseScore = 10 / (1 + Math.pow(riskIndex / 4.2, 1.35));

  const negativeIssues = negatives.filter((n) => n.weight < 0).length;
  const positiveIssues = scored.filter((s) => s.weight > 0).length;

  return {
    finalScore: round1(baseScore),
    baseScore: round1(baseScore),
    riskIndex: round2(riskIndex),
    negativeIssues,
    positiveIssues,
    perIssue: scored,
  };
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}
function round2(x: number): number {
  return Math.round(x * 100) / 100;
}
