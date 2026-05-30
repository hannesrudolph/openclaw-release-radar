// Install Confidence — answers ONE question: "should I install this stable release?"
//
// Design rationale (see git history for the model it replaced):
// The previous 0–10 "stability" score was dominated by reign-confounded terms
// (fix-bonus, peer-median) and ended up POSITIVELY correlated with bug volume —
// the buggiest releases scored highest. This model instead leans on signals that
// are (a) age/cadence-invariant and (b) mostly structural / LLM-free, because the
// install decision is about proven safety, not maintenance activity.
//
// Signal hierarchy (most → least trusted), and why each survives the "is it
// confounded by how long/popular the release was?" test:
//   1. CVE exposure         — objective, version-range matched. Sets a "skip-cve"
//                             STATUS (never recommended), and a DECAYED penalty on
//                             the score. Decay: a vuln counts 100% for the version
//                             right before its patch, then ×0.3 per older release
//                             (capped 10 back). GitHub advisory ranges have no lower
//                             bound (`< X` blames every older version equally), so
//                             without decay the oldest release always looks worst —
//                             an age artifact, not real quality. Decay attributes a
//                             vuln mostly to the versions just before its fix.
//   2. Settle age (<24h)    — below a day there is genuinely no signal yet.
//   3. Hotfix succession    — a `<tag>-N` patch successor (openclaw's hotfix
//                             convention) or a next STABLE within 6h => the
//                             maintainers themselves replaced it. Hard skip.
//   4. Survival gap         — how long it stood before the next STABLE (NOT the
//                             next beta — a beta of the next version is forward
//                             development, not a reaction). Age-invariant.
//   5. Shakeout depth       — betas baked before promotion. Structural, LLM-free.
//   6. Visible-bug balance  — USER-VISIBLE regressions (core + integration + provider,
//                             high/critical, weighted by how many users hit them) closed
//                             vs opened during its reign, as a RATIO (time-invariant).
//                             This is what people actually downgrade over ("Discord stopped
//                             delivering"), unlike a silent CVE. LLM-derived, so it's
//                             shrunk toward neutral on low volume.
//   7. Breaking changes     — adoption cost. Situational; dormant when zero.

const HOUR_MS = 60 * 60 * 1000;

// ---- tunables (calibrated on openclaw's release history; see scripts/) ----
const SETTLE_HOURS = 24;       // younger than this => no settle signal yet ("wait")
const HOTFIX_GAP_HOURS = 6;    // next STABLE faster than this => emergency hotfix
const PIVOT_HOURS = 24;        // a "typical" stable lifetime → neutral survival
const BASE = 6.0;              // neutral eligible baseline
const HOTFIX_SCORE_CAP = 4.9;  // a hotfixed release must read below 5.0
// ---- visible-bug ("felt") regression balance ----
// "felt" = user-facing surfaces (core/integration/provider), high/critical, weighted by
// reach (scope × affected users). A broad bug that hits many weighs ~4× a niche one.
const FELT_SCOPE: Record<string, number> = { broad: 1.5, moderate: 1.0, niche: 0.4 };
const FELT_USERS: Record<string, number> = { many: 1.3, some: 0.85, few: 0.35, unknown: 0.65 };
const FELT_PRIOR = 12;         // pseudo-count (weighted) — shrinks low-volume ratios to neutral
const FELT_REACH = 6;          // ratio→points scale
const FELT_DOWN = -3.0, FELT_UP = 2.0; // max points a net-breaking / net-fixing reign can apply
// ---- CVE (skip-cve releases are scored purely by own-CVE severity; see header) ----
const CVE_DECAY = 0.3;         // weight per stable older than the patch (used by cveDecayLoad)
const CVE_WINDOW = 10;         // releases beyond this far back from a patch => weight 0
const CVE_SEV_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CVE_SKIP_TOP = HOTFIX_SCORE_CAP; // mildest skip-cve score (≈ 1 low CVE); always < 5
const CVE_LOAD_FULL = 30;      // own-CVE severity load at which skip-cve bottoms out (~0)
// Score needed to be the recommended install. Set at the caution-band floor (5.5),
// NOT "ok" (7): `eligible` already means a release cleared the hard safety gates
// (no CVE, not hotfixed, settled), so among those we recommend the NEWEST that
// isn't outright "weak". This matters when a CVE wave gates every older release
// and the only clean option is a freshly-settled one scoring in the caution band —
// returning "nothing recommended" there would be unhelpful. The band still conveys
// the nuance (a recommended release can read "Caution").
export const REC_THRESHOLD = 5.5;

// component caps — these ARE the weights, expressed as max swing each signal can apply
const SURVIVAL_MIN = -3.0, SURVIVAL_MAX = 2.0;
const SHAKEOUT_MAX = 1.2;
const BREAKING_PER_BULLET = -0.3, BREAKING_MAX_BULLETS = 5;

export type InstallStatus = 'wait' | 'skip-cve' | 'skip-hotfix' | 'eligible';
export type InstallBand = 'solid' | 'ok' | 'caution' | 'weak' | 'skip' | 'wait';

export interface InstallInput {
  publishedAt: string | null;
  isLatest: boolean;               // true only for the single newest stable
  hoursToNextStable: number | null; // gap to the next STABLE; null if latest/unknown
  hasHotfixSuccessor: boolean;     // a `<tag>-N` patch release follows it
  betaCount: number;               // prereleases baked before this stable
  breakingCount: number;           // `### Breaking` bullets (aggregate)
  feltOpenedWeight: number;        // reach-weighted visible bugs OPENED during its reign
  feltClosedWeight: number;        // reach-weighted visible bugs CLOSED during its reign
  cveAffected: boolean;            // any known advisory matches this version → skip-cve status
  cveLoad: number;                 // decayed severity-weighted CVE load (see cveDecayLoad)
}

export interface InstallComponents {
  base: number;
  survival: number;
  shakeout: number;
  regression: number;
  breaking: number;
}

export interface InstallConfidence {
  score: number | null;            // 0–10, null when status === 'wait'
  status: InstallStatus;
  band: InstallBand;
  hotfix: boolean;
  components: InstallComponents | null;
  reason: string;                  // short human explanation for the UI/API
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}
function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

// How long it stood before the next STABLE, log-scaled around a typical lifetime.
// Negative for releases superseded faster than typical; positive for ones that
// stood notably longer (more battle-tested as the current version).
function survivalPoints(input: InstallInput, ageHours: number): number {
  if (input.isLatest) {
    // No successor yet: "time as latest with no hotfix" is mild positive evidence,
    // capped low because there's no successor to confirm the team is comfortable.
    return clamp(Math.log2(ageHours / 24) * 0.6, 0, 1.8);
  }
  if (input.hoursToNextStable == null) return 0; // data gap → neutral
  return clamp(Math.log2(input.hoursToNextStable / PIVOT_HOURS) * 0.9, SURVIVAL_MIN, SURVIVAL_MAX);
}

function shakeoutPoints(betaCount: number): number {
  return clamp(Math.log2(1 + Math.max(0, betaCount)) * 0.4, 0, SHAKEOUT_MAX);
}

// A minimal classification shape for the visible-bug ("felt") signal.
export interface FeltClassification {
  sentiment: string;
  severity: string;
  functionality: string;
  scope: string;
  affectedUsers: string;
}

// Reach-weighted "felt" load of a set of issues: user-visible (core/integration/
// provider), high/critical negatives, each weighted by scope × affected users. This
// is the signal a CVE misses — what users actually see and downgrade over.
export function feltLoad(items: FeltClassification[]): number {
  let w = 0;
  for (const c of items) {
    if (c.sentiment !== 'negative') continue;
    if (c.functionality !== 'core' && c.functionality !== 'integration' && c.functionality !== 'provider') continue;
    if (c.severity !== 'critical' && c.severity !== 'high') continue;
    w += (FELT_SCOPE[c.scope] ?? 1.0) * (FELT_USERS[c.affectedUsers] ?? 0.65);
  }
  return w;
}

// Visible-bug close/open balance during the reign, as a ratio so it's invariant to how
// long the release stood. Bayesian-shrunk toward neutral (FELT_PRIOR pseudo-count) so a
// release with only a couple of visible bugs isn't slammed by a noisy 0%-fixed ratio —
// only a release with real volume of unfixed visible regressions takes the full hit.
// Net-breaking is penalised slightly harder than net-fixing is rewarded.
function feltRegressionPoints(openedWeight: number, closedWeight: number): number {
  const o = Math.max(0, openedWeight);
  const c = Math.max(0, closedWeight);
  const ratio = (c + FELT_PRIOR * 0.5) / (o + c + FELT_PRIOR);
  const raw = (ratio - 0.5) * FELT_REACH;
  return clamp(ratio < 0.5 ? raw * 1.3 : raw, FELT_DOWN, FELT_UP);
}

function breakingPoints(breakingCount: number): number {
  return Math.max(BREAKING_PER_BULLET * BREAKING_MAX_BULLETS, BREAKING_PER_BULLET * Math.max(0, breakingCount));
}

// Decayed, severity-weighted CVE load for a version. Each affecting advisory comes
// with a `distance` = how many STABLE releases sit between this version and the
// advisory's patch (0 = this is the newest still-affected version). The version
// right before the patch counts 100%, each older release ×CVE_DECAY, zero beyond
// CVE_WINDOW. This stops GitHub's lower-bound-less ranges (`< X` blames every prior
// version equally) from making the oldest release look worst purely by age: a vuln
// is attributed mostly to the versions just before it was fixed.
// (Distance is computed by lib/versionMatch.stableDistance — kept out of here so
// this stays a pure numeric function with no cross-module imports.)
export function cveDecayLoad(items: Array<{ severity: string; distance: number }>): number {
  let load = 0;
  for (const it of items) {
    const sev = CVE_SEV_WEIGHT[it.severity] ?? 0;
    if (sev === 0) continue;
    const d = Math.max(0, it.distance);
    const weight = d < CVE_WINDOW ? Math.pow(CVE_DECAY, d) : 0;
    load += sev * weight;
  }
  return load;
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
  ageHours: number,
): string {
  if (status === 'skip-cve') return 'vulnerable to a known CVE — upgrade past this version';
  if (status === 'wait') return `only ${(ageHours / 24).toFixed(1)}d old — no settle signal yet`;
  if (status === 'skip-hotfix') {
    return input.hasHotfixSuccessor
      ? 'maintainers shipped a hotfix patch on top of it'
      : `replaced by the next stable within ${Math.round(input.hoursToNextStable ?? 0)}h`;
  }
  const bits: string[] = [];
  if (input.isLatest) {
    bits.push(`latest — stood ${(ageHours / 24).toFixed(1)}d with no hotfix`);
  } else if (input.hoursToNextStable != null) {
    const h = input.hoursToNextStable;
    bits.push(`stood ${h >= 24 ? `${(h / 24).toFixed(1)}d` : `${Math.round(h)}h`} as current stable`);
  }
  if (input.betaCount > 0) bits.push(`${input.betaCount} betas baked`);
  const feltTotal = input.feltOpenedWeight + input.feltClosedWeight;
  if (feltTotal >= 4) {
    bits.push(input.feltClosedWeight >= input.feltOpenedWeight ? 'net-fixing visible bugs' : 'net-breaking visible bugs');
  }
  if (input.breakingCount > 0) bits.push(`${input.breakingCount} breaking`);
  return bits.join(', ') || 'no adverse signal';
}

export function installConfidence(input: InstallInput, now: number = Date.now()): InstallConfidence {
  const ageHours = input.publishedAt ? (now - Date.parse(input.publishedAt)) / HOUR_MS : Infinity;
  const hotfix =
    !input.isLatest &&
    (input.hasHotfixSuccessor ||
      (input.hoursToNextStable != null && input.hoursToNextStable < HOTFIX_GAP_HOURS));

  // skip-cve: scored PURELY by how vulnerable this version is — the severity of its
  // OWN CVEs (cveLoad, same own-CVE set the badge shows) — NOT by maintenance quality.
  // Rationale: a vulnerable release won't be installed regardless, so its number should
  // rank "how bad to be on it" (more/worse CVEs => lower) and track the CVE badge.
  // Letting the maintenance base (survival/betas) leak in here was wrong: it let a
  // well-tended but more-vulnerable release (e.g. one that baked through many betas)
  // outrank a short-lived but less-vulnerable one. Always < 5 → never outranks an install.
  if (input.cveAffected) {
    const score = round1(clamp(CVE_SKIP_TOP * (1 - Math.min(1, input.cveLoad / CVE_LOAD_FULL)), 0, CVE_SKIP_TOP));
    return { score, status: 'skip-cve', band: 'skip', hotfix, components: null, reason: reasonFor(input, 'skip-cve', ageHours) };
  }

  // Too young to judge (and not CVE-flagged) → no signal yet.
  if (!(ageHours >= SETTLE_HOURS)) {
    return { score: null, status: 'wait', band: 'wait', hotfix, components: null, reason: reasonFor(input, 'wait', ageHours) };
  }

  // Eligible / hotfixed: maintenance quality is the right signal here.
  const survival = survivalPoints(input, ageHours);
  const shakeout = shakeoutPoints(input.betaCount);
  const regression = feltRegressionPoints(input.feltOpenedWeight, input.feltClosedWeight);
  const breaking = breakingPoints(input.breakingCount);
  let s = clamp(BASE + survival + shakeout + regression + breaking, 0, 10);
  if (hotfix) s = Math.min(s, HOTFIX_SCORE_CAP); // a hotfixed release must read < 5
  const score = round1(s);
  const status: InstallStatus = hotfix ? 'skip-hotfix' : 'eligible';
  return {
    score,
    status,
    band: bandFor(score, status),
    hotfix,
    components: {
      base: BASE,
      survival: round1(survival),
      shakeout: round1(shakeout),
      regression: round1(regression),
      breaking: round1(breaking),
    },
    reason: reasonFor(input, status, ageHours),
  };
}

// Cross-release pick: the recommended install is the NEWEST release that passed
// all gates (status 'eligible') and scores at or above REC_THRESHOLD. Encodes the
// product choice "newest that's good enough" (recency-first). `scored` must be in
// newest-first order. Returns the chosen tag, or null when nothing qualifies.
export function pickRecommended(
  scored: Array<{ tag: string; status: InstallStatus; score: number | null }>,
): string | null {
  for (const r of scored) {
    if (r.status === 'eligible' && r.score != null && r.score >= REC_THRESHOLD) return r.tag;
  }
  return null;
}
