import {
  closureProofExamples,
  closureProofRiskRows,
  closureProofSummary,
  getRelease,
  type ClosureProofRiskRow,
  getReleaseScoreAudit,
  labelsForIssueAt,
  updateReleaseScoreAuditGateEvidence,
} from './db';
import { releaseLabelCutoff } from './labelCutoff';
import {
  applyLabelOverrides,
  applyTitleFunctionalityHint,
  applyTitleIssueShapeHint,
} from './labelOverrides';
import type { IssueClassification } from './llm';

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
  duplicate_to_fixed_after_release: 'known_not_in_release',
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
  const release = getRelease(tag);
  const labelCutoff = release ? releaseLabelCutoff(release) : null;
  const byStatus = Object.fromEntries(summaryRows.map((row) => [row.status, row.count]));
  const byRiskDisposition = countByRiskDisposition(summaryRows);
  const weightedRisk = weightedRiskForRows(closureProofRiskRows(tag), labelCutoff);
  const notCreditedCount = summaryRows
    .filter((row) => row.status !== 'fixed_in_release')
    .reduce((sum, row) => sum + row.count, 0);
  const creditedCount = byStatus.fixed_in_release ?? 0;
  const analyzedClosedCount = creditedCount + notCreditedCount;
  const exampleCandidateLimit = Math.max(30, analyzedClosedCount);
  const examples = closureProofExamples(tag, exampleCandidateLimit).map((row) => {
    const classification = effectiveClosureClassification(row, labelCutoff);
    const effectiveRiskRow = classification
      ? {
        status: row.status,
        sentiment: classification.classification.sentiment,
        severity: classification.classification.severity,
        scope: classification.classification.scope,
        functionality: classification.classification.functionality,
        affected_users: classification.classification.affectedUsers,
      }
      : row;
    return {
      number: row.issue_number,
      title: row.title,
      url: row.html_url,
      closedAt: row.closed_at,
      status: row.status,
      summary: row.summary,
      sentiment: classification?.classification.sentiment ?? row.sentiment,
      severity: classification?.classification.severity ?? row.severity,
      scope: classification?.classification.scope ?? row.scope,
      functionality: classification?.classification.functionality ?? row.functionality,
      affectedUsers: classification?.classification.affectedUsers ?? row.affected_users,
      checkedAt: row.checked_at,
      labels: classification?.labels ?? parseJson<string[]>(row.labels, []),
      rawClassification: classification?.rawClassification ?? null,
      classification: classification?.classification ?? null,
      classificationDiff: classification?.classificationDiff ?? {},
      riskWeight: roundMetric(closureRiskWeightForRow(effectiveRiskRow)),
      riskDisposition: closureRiskDisposition(row.status),
      evidence: parseJson(row.evidence_json, {}),
    };
  }).sort(compareClosureProofExamples).slice(0, 30);
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
    analyzedClosedCount,
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

function compareClosureProofExamples(a: any, b: any): number {
  const riskDiff = Number(b.riskWeight ?? 0) - Number(a.riskWeight ?? 0);
  if (riskDiff !== 0) return riskDiff;
  const statusDiff = closureStatusRank(a.status) - closureStatusRank(b.status);
  if (statusDiff !== 0) return statusDiff;
  return String(b.closedAt ?? '').localeCompare(String(a.closedAt ?? ''));
}

function closureStatusRank(status: string): number {
  return ({
    duplicate_to_open_canonical: 0,
    fixed_after_release: 1,
    duplicate_to_fixed_after_release: 2,
    main_only_claim: 3,
    already_present_claim: 4,
    duplicate_to_closed_canonical: 5,
    canonical_cycle_or_self_reference: 6,
    duplicate_or_superseded: 7,
    no_code_proof: 8,
    no_timeline_event: 9,
    reporter_replaced: 10,
    reporter_withdrawn: 11,
    reporter_self_closed: 12,
    not_planned: 13,
    non_bug_neutral: 14,
    fixed_in_release: 15,
  } as Record<string, number>)[status] ?? 99;
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

type ClosureRiskWeightRow = Pick<ClosureProofRiskRow,
  'status' | 'sentiment' | 'severity' | 'scope' | 'functionality' | 'affected_users'
>;

type ClosureRiskSourceRow = ClosureRiskWeightRow & {
  issue_number: number;
  title: string;
  labels: string;
  has_workaround: number | null;
  workaround_status: string | null;
  duplicate_cluster: string | null;
  affects_version: string | null;
  confidence: number | null;
  rationale: string | null;
};

export function closureRiskWeightForRow(row: ClosureRiskWeightRow): number {
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

function weightedRiskForRows(rows: ClosureProofRiskRow[], labelCutoff: string | null): {
  unresolvedWeightedRisk: number;
  byDisposition: Partial<Record<ClosureRiskDisposition, number>>;
} {
  const byDisposition: Partial<Record<ClosureRiskDisposition, number>> = {};
  for (const row of rows) {
    const disposition = closureRiskDisposition(row.status);
    const effective = effectiveClosureRiskRow(row, labelCutoff);
    const weight = closureRiskWeightForRow(effective) * Number(row.count ?? 0);
    if (weight <= 0) continue;
    byDisposition[disposition] = (byDisposition[disposition] ?? 0) + weight;
  }
  return {
    unresolvedWeightedRisk: Object.values(byDisposition).reduce((sum, value) => sum + Number(value ?? 0), 0),
    byDisposition,
  };
}

function effectiveClosureRiskRow(row: ClosureRiskSourceRow, labelCutoff: string | null): ClosureRiskWeightRow {
  const effective = effectiveClosureClassification(row, labelCutoff);
  if (!effective) return row;
  return {
    status: row.status,
    sentiment: effective.classification.sentiment,
    severity: effective.classification.severity,
    scope: effective.classification.scope,
    functionality: effective.classification.functionality,
    affected_users: effective.classification.affectedUsers,
  };
}

function effectiveClosureClassification(row: ClosureRiskSourceRow, labelCutoff: string | null): {
  labels: string[];
  rawClassification: IssueClassification;
  classification: IssueClassification;
  classificationDiff: Record<string, { raw: unknown; effective: unknown }>;
} | null {
  if (!row.sentiment || !row.severity || !row.scope || !row.functionality || !row.affected_users) {
    return null;
  }
  const currentLabels = parseJson<string[]>(row.labels, []);
  const labels = labelsForIssueAt(row.issue_number, currentLabels, labelCutoff, {
    useFallbackWhenNoEvents: labelCutoff == null,
  });
  const rawClassification = rowToClassification(row);
  const classification = applyTitleIssueShapeHint(
    applyLabelOverrides(
      applyTitleFunctionalityHint(rawClassification, row.title ?? ''),
      labels,
    ),
    row.title ?? '',
    labels,
  );
  return {
    labels,
    rawClassification,
    classification,
    classificationDiff: classificationDiff(rawClassification, classification),
  };
}

function rowToClassification(row: ClosureRiskSourceRow): IssueClassification {
  const workaroundStatus = ['none', 'partial', 'confirmed', 'unknown'].includes(row.workaround_status ?? '')
    ? row.workaround_status as IssueClassification['workaroundStatus']
    : row.has_workaround === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment as IssueClassification['sentiment'],
    severity: row.severity as IssueClassification['severity'],
    scope: row.scope as IssueClassification['scope'],
    functionality: row.functionality as IssueClassification['functionality'],
    affectedUsers: row.affected_users as IssueClassification['affectedUsers'],
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster,
    affectsVersion: row.affects_version,
    confidence: typeof row.confidence === 'number' ? row.confidence : 0.5,
    rationale: row.rationale ?? '',
  };
}

function classificationDiff(
  raw: IssueClassification,
  effective: IssueClassification,
): Record<string, { raw: unknown; effective: unknown }> {
  const out: Record<string, { raw: unknown; effective: unknown }> = {};
  for (const key of [
    'sentiment',
    'severity',
    'scope',
    'functionality',
    'affectedUsers',
    'workaroundStatus',
    'confidence',
  ] as const) {
    if (raw[key] !== effective[key]) out[key] = { raw: raw[key], effective: effective[key] };
  }
  return out;
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
