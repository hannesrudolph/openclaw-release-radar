import {
  closureProofExamples,
  closureProofRiskRows,
  closureProofSummary,
  type ClosureProofRiskRow,
  getReleaseScoreAudit,
  updateReleaseScoreAuditGateEvidence,
} from './db';

export const CLOSURE_RISK_DISPOSITIONS = [
  'credited_release_fix',
  'known_not_in_release',
  'open_canonical_risk',
  'unsupported_closure_claim',
  'neutral_or_non_actionable',
  'missing_evidence',
] as const;

export type ClosureRiskDisposition = (typeof CLOSURE_RISK_DISPOSITIONS)[number];

const CLOSURE_RISK_DISPOSITION_BY_STATUS: Record<string, ClosureRiskDisposition> = {
  fixed_in_release: 'credited_release_fix',
  fixed_after_release: 'known_not_in_release',
  main_only_claim: 'known_not_in_release',
  duplicate_to_open_canonical: 'open_canonical_risk',
  duplicate_to_closed_canonical: 'unsupported_closure_claim',
  canonical_cycle_or_self_reference: 'unsupported_closure_claim',
  duplicate_or_superseded: 'unsupported_closure_claim',
  already_present_claim: 'unsupported_closure_claim',
  no_code_proof: 'unsupported_closure_claim',
  non_bug_neutral: 'neutral_or_non_actionable',
  not_planned: 'neutral_or_non_actionable',
  reporter_replaced: 'neutral_or_non_actionable',
  reporter_withdrawn: 'neutral_or_non_actionable',
  reporter_self_closed: 'neutral_or_non_actionable',
  no_timeline_event: 'missing_evidence',
  unknown: 'missing_evidence',
};

export function closureRiskDisposition(status: string): ClosureRiskDisposition {
  return CLOSURE_RISK_DISPOSITION_BY_STATUS[status] ?? 'missing_evidence';
}

const DISPOSITION_RISK_WEIGHT: Record<ClosureRiskDisposition, number> = {
  credited_release_fix: 0,
  known_not_in_release: 1,
  open_canonical_risk: 1.2,
  unsupported_closure_claim: 0.8,
  neutral_or_non_actionable: 0,
  missing_evidence: 1.5,
};

const SEVERITY_RISK_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 2.5,
  medium: 0.8,
  low: 0,
};

const FUNCTIONALITY_RISK_WEIGHT: Record<string, number> = {
  core: 1.25,
  integration: 1,
  provider: 0.8,
  docs: 0,
};

const SCOPE_RISK_WEIGHT: Record<string, number> = {
  broad: 1.5,
  moderate: 1,
  niche: 0.4,
};

const USERS_RISK_WEIGHT: Record<string, number> = {
  many: 1.3,
  some: 0.85,
  few: 0.35,
  unknown: 0.65,
};

export function closureProofPayload(tag: string) {
  const summaryRows = closureProofSummary(tag);
  if (!summaryRows.length) return null;
  const byStatus = Object.fromEntries(summaryRows.map((row) => [row.status, row.count]));
  const byRiskDisposition = countByRiskDisposition(summaryRows);
  const weightedRisk = weightedRiskForRows(closureProofRiskRows(tag));
  const notCreditedCount = summaryRows
    .filter((row) => row.status !== 'fixed_in_release')
    .reduce((sum, row) => sum + row.count, 0);
  const creditedCount = byStatus.fixed_in_release ?? 0;
  const examples = closureProofExamples(tag, 30).map((row) => ({
    number: row.issue_number,
    title: row.title,
    url: row.html_url,
    closedAt: row.closed_at,
    status: row.status,
    summary: row.summary,
    sentiment: row.sentiment,
    severity: row.severity,
    scope: row.scope,
    functionality: row.functionality,
    affectedUsers: row.affected_users,
    checkedAt: row.checked_at,
    riskDisposition: closureRiskDisposition(row.status),
    evidence: parseJson(row.evidence_json, {}),
  }));
  const riskSummary = {
    creditedReleaseFixCount: byRiskDisposition.credited_release_fix ?? 0,
    knownNotInReleaseCount: byRiskDisposition.known_not_in_release ?? 0,
    openCanonicalRiskCount: byRiskDisposition.open_canonical_risk ?? 0,
    unsupportedClosureClaimCount: byRiskDisposition.unsupported_closure_claim ?? 0,
    neutralOrNonActionableCount: byRiskDisposition.neutral_or_non_actionable ?? 0,
    missingEvidenceCount: byRiskDisposition.missing_evidence ?? 0,
  };
  const unresolvedForReleaseCount = riskSummary.knownNotInReleaseCount +
    riskSummary.openCanonicalRiskCount +
    riskSummary.unsupportedClosureClaimCount +
    riskSummary.missingEvidenceCount;
  return {
    creditedCount,
    notCreditedCount,
    analyzedClosedCount: creditedCount + notCreditedCount,
    byStatus,
    byRiskDisposition,
    riskSummary: {
      ...riskSummary,
      unresolvedForReleaseCount,
      unresolvedWeightedRisk: roundMetric(weightedRisk.unresolvedWeightedRisk),
      weightedRiskByDisposition: roundRiskMap(weightedRisk.byDisposition),
    },
    examples,
  };
}

export function enrichGateEvidenceWithClosureProof(tag: string, gateEvidence: any, closureProof = closureProofPayload(tag)) {
  if (gateEvidence && closureProof) {
    gateEvidence.fixProvenance ??= {};
    gateEvidence.fixProvenance.closureProof = closureProof;
    gateEvidence.fixProvenance.releaseFixCredit = {
      countedClosedCount: closureProof.creditedCount,
      notCountedClosedCount: closureProof.notCreditedCount,
      analyzedClosedCount: closureProof.analyzedClosedCount,
    };
  }
  return gateEvidence;
}

export function persistClosureProofInScoreAudit(tag: string): boolean {
  const audit = getReleaseScoreAudit(tag);
  if (!audit) return false;
  const gateEvidence = parseJson(audit.gate_evidence_json, null);
  if (!gateEvidence) return false;
  const enriched = enrichGateEvidenceWithClosureProof(tag, gateEvidence);
  updateReleaseScoreAuditGateEvidence(tag, JSON.stringify(enriched));
  return true;
}

function parseJson<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function countByRiskDisposition(
  rows: Array<{ status: string; count: number }>,
): Partial<Record<ClosureRiskDisposition, number>> {
  const counts: Partial<Record<ClosureRiskDisposition, number>> = {};
  for (const row of rows) {
    const disposition = closureRiskDisposition(row.status);
    counts[disposition] = (counts[disposition] ?? 0) + row.count;
  }
  return counts;
}

export function closureRiskWeightForRow(row: Pick<ClosureProofRiskRow,
  'status' | 'sentiment' | 'severity' | 'scope' | 'functionality' | 'affected_users'
>): number {
  const disposition = closureRiskDisposition(row.status);
  const dispositionWeight = DISPOSITION_RISK_WEIGHT[disposition] ?? 0;
  if (dispositionWeight <= 0) return 0;
  if (row.sentiment !== 'negative') return 0;
  const severity = SEVERITY_RISK_WEIGHT[row.severity ?? ''] ?? 0;
  const functionality = FUNCTIONALITY_RISK_WEIGHT[row.functionality ?? ''] ?? 0;
  if (severity <= 0 || functionality <= 0) return 0;
  return dispositionWeight *
    severity *
    functionality *
    (SCOPE_RISK_WEIGHT[row.scope ?? ''] ?? 1) *
    (USERS_RISK_WEIGHT[row.affected_users ?? 'unknown'] ?? USERS_RISK_WEIGHT.unknown);
}

function weightedRiskForRows(rows: ClosureProofRiskRow[]): {
  unresolvedWeightedRisk: number;
  byDisposition: Partial<Record<ClosureRiskDisposition, number>>;
} {
  const byDisposition: Partial<Record<ClosureRiskDisposition, number>> = {};
  for (const row of rows) {
    const disposition = closureRiskDisposition(row.status);
    const weight = closureRiskWeightForRow(row) * Number(row.count ?? 0);
    if (weight <= 0) continue;
    byDisposition[disposition] = (byDisposition[disposition] ?? 0) + weight;
  }
  return {
    unresolvedWeightedRisk: Object.values(byDisposition).reduce((sum, value) => sum + Number(value ?? 0), 0),
    byDisposition,
  };
}

function roundRiskMap(map: Partial<Record<ClosureRiskDisposition, number>>): Partial<Record<ClosureRiskDisposition, number>> {
  const rounded: Partial<Record<ClosureRiskDisposition, number>> = {};
  for (const [key, value] of Object.entries(map)) {
    const roundedValue = roundMetric(Number(value ?? 0));
    if (roundedValue > 0) rounded[key as ClosureRiskDisposition] = roundedValue;
  }
  return rounded;
}

function roundMetric(value: number): number {
  return Math.round(value * 1000) / 1000;
}
