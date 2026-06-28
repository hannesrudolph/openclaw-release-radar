import {
  closureProofExamples,
  closureProofSummary,
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

export function closureProofPayload(tag: string) {
  const summaryRows = closureProofSummary(tag);
  if (!summaryRows.length) return null;
  const byStatus = Object.fromEntries(summaryRows.map((row) => [row.status, row.count]));
  const byRiskDisposition = countByRiskDisposition(summaryRows);
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
    functionality: row.functionality,
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
    },
    examples,
  };
}

export function enrichGateEvidenceWithClosureProof(tag: string, gateEvidence: any) {
  const closureProof = closureProofPayload(tag);
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
