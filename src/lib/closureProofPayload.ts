import {
  closureProofExamples,
  closureProofRiskRows,
  closureProofRows,
  closureProofSummary,
  getRelease,
  type ClosureProofJoinedRow,
  type ClosureProofRiskRow,
  getReleaseScoreAudit,
  issueLabelEventCount,
  issueLabelSnapshotCountAt,
  labelsForIssueAt,
  releaseFixCreditDecision,
  type ReleaseFixCreditDecision,
} from './db';
import { releaseLabelCutoff } from './labelCutoff';
import {
  applyClosureRiskSentimentHint,
  applyLabelOverrides,
  applyTitleFunctionalityHint,
  applyTitleIssueShapeHint,
} from './labelOverrides';
import {
  CLOSURE_PROOF_STATUSES,
  CLOSURE_RISK_DISPOSITIONS,
  CLOSURE_RISK_DISPOSITION_WEIGHT,
  closureRiskDisposition,
  type ClosureProofStatus,
  type ClosureRiskDisposition,
} from './closureProofTaxonomy';
import type { IssueClassification } from './llm';
import { aggregateClosureRisk } from './closureRiskAggregation';
import { scoringLabelInfoAtCutoff } from './scoringLabelAuthority';
export { CLOSURE_RISK_DISPOSITIONS, closureRiskDisposition } from './closureProofTaxonomy';
export const CLOSURE_PROOF_SCHEMA_VERSION = 1;
export const RELEASE_FIX_CREDIT_SCHEMA_VERSION = 1;
export const AFFIRMATIVE_CLOSURE_RISK_DISPOSITIONS = [
  'known_not_in_release',
  'open_canonical_risk',
  'unsupported_closure_claim',
] as const;

export interface ClosureProofPayloadOptions {
  predecessorTag: string | null;
  fixCreditDecisions?: ReleaseFixCreditDecision[];
  riskDispositionOverrides?: ReadonlyMap<number, ClosureRiskDisposition>;
}

export interface MissingClosureEvidenceDiagnostic {
  issueNumber: number;
  status: string;
  title: string;
  sentiment: string;
  severity: string;
  functionality: string;
  scope: string;
  affectedUsers: string;
  potentialRiskWeight: number;
}

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

export function closureProofPayload(
  tag: string,
  labelCutoffOverride?: string | null,
  options?: ClosureProofPayloadOptions,
) {
  const summaryRows = closureProofSummary(tag);
  if (!summaryRows.length) return emptyClosureProofPayload(tag, options);
  const release = getRelease(tag);
  const audit = getReleaseScoreAudit(tag);
  const labelCutoff = labelCutoffOverride !== undefined
    ? labelCutoffOverride
    : release ? releaseLabelCutoff(release, audit?.scored_at ?? null) : null;
  const byStatus = Object.fromEntries(summaryRows.map((row) => [row.status, row.count]));
  const closureRows = closureProofRows(tag);
  const byRiskDisposition = countByRiskDisposition(
    closureRows,
    options?.riskDispositionOverrides,
  );
  const riskRows = closureProofRiskRows(tag);
  const weightedRisk = weightedRiskForRows(
    riskRows,
    labelCutoff,
    options?.riskDispositionOverrides,
  );
  const neutralAuditSignals = neutralAuditSignalsForRows(
    riskRows,
    labelCutoff,
    options?.riskDispositionOverrides,
  );
  const containedFixedCount = byStatus.fixed_in_release ?? 0;
  const fixedRows = closureRows
    .filter((row) => row.status === 'fixed_in_release')
    .sort((left, right) => left.issue_number - right.issue_number);
  const fixCreditDecisions = options?.fixCreditDecisions ??
    fixedRows.map((row) => releaseFixCreditDecision(
      row.issue_number,
      tag,
      options?.predecessorTag,
    ));
  const fixCreditDecisionCounts = countFixCreditDecisions(fixCreditDecisions);
  const creditedCount = fixCreditDecisionCounts.credited;
  const analyzedClosedCount = summaryRows.reduce((sum, row) => sum + row.count, 0);
  const notCreditedCount = analyzedClosedCount - creditedCount;
  const containedNotCreditedCount = containedFixedCount - creditedCount;
  const exampleCandidateLimit = Math.max(30, analyzedClosedCount);
  const allExamples = closureProofExamples(tag, exampleCandidateLimit)
    .map((row) => closureProofAuditItemFromRow(
      row,
      labelCutoff,
      options?.riskDispositionOverrides?.get(row.issue_number),
    ))
    .sort(compareClosureProofExamples);
  const neutralAuditExamples = allExamples
    .filter((example) => isNeutralAuditExample(example))
    .sort(compareNeutralAuditExamples)
    .slice(0, 10);
  const examples = allExamples.slice(0, 30);
  const examplesByStatus = representativeExamplesByStatus(allExamples, summaryRows);
  const riskSummary = {
    creditedReleaseFixCount: creditedCount,
    containedReleaseFixCount: containedFixedCount,
    containedWithoutFirstCreditCount: containedNotCreditedCount,
    resolvedByCanonicalReleaseFixCount: byRiskDisposition.resolved_by_canonical_release_fix ?? 0,
    resolvedByReleaseFixProofCount: byRiskDisposition.resolved_by_release_fix_proof ?? 0,
    knownNotInReleaseCount: byRiskDisposition.known_not_in_release ?? 0,
    openCanonicalRiskCount: byRiskDisposition.open_canonical_risk ?? 0,
    unsupportedClosureClaimCount: byRiskDisposition.unsupported_closure_claim ?? 0,
    neutralOrNonActionableCount: byRiskDisposition.neutral_or_non_actionable ?? 0,
    neutralHighImpactCount: neutralAuditSignals.highImpact,
    neutralBugShapedCount: neutralAuditSignals.bugShaped,
    missingEvidenceCount: byRiskDisposition.missing_evidence ?? 0,
  };
  return {
    schemaVersion: CLOSURE_PROOF_SCHEMA_VERSION,
    creditedCount,
    notCreditedCount,
    analyzedClosedCount,
    containedFixedCount,
    containedNotCreditedCount,
    targetTag: tag,
    predecessorTag: options?.predecessorTag ?? null,
    fixCreditDecisionCounts,
    fixCreditDecisions,
    byStatus,
    byRiskDisposition,
    riskSummary: {
      ...riskSummary,
      unresolvedForReleaseCount: weightedRisk.unresolvedForReleaseCount,
      unresolvedWeightedRisk: roundMetric(weightedRisk.unresolvedWeightedRisk),
      weightedRiskByDisposition: roundRiskMap(weightedRisk.byDisposition),
    },
    neutralAuditExamples,
    examplesByStatus,
    examples,
  };
}

export function emptyClosureProofPayload(
  tag?: string,
  options?: ClosureProofPayloadOptions,
) {
  const payload = {
    schemaVersion: CLOSURE_PROOF_SCHEMA_VERSION,
    creditedCount: 0,
    notCreditedCount: 0,
    analyzedClosedCount: 0,
    byStatus: {},
    byRiskDisposition: {},
    riskSummary: {
      creditedReleaseFixCount: 0,
      resolvedByCanonicalReleaseFixCount: 0,
      resolvedByReleaseFixProofCount: 0,
      knownNotInReleaseCount: 0,
      openCanonicalRiskCount: 0,
      unsupportedClosureClaimCount: 0,
      neutralOrNonActionableCount: 0,
      neutralHighImpactCount: 0,
      neutralBugShapedCount: 0,
      missingEvidenceCount: 0,
      unresolvedForReleaseCount: 0,
      unresolvedWeightedRisk: 0,
      weightedRiskByDisposition: {},
    },
    neutralAuditExamples: [],
    examplesByStatus: {},
    examples: [],
  };
  if (tag === undefined || !options?.predecessorTag) return payload;
  return {
    ...payload,
    containedFixedCount: 0,
    containedNotCreditedCount: 0,
    targetTag: tag ?? null,
    predecessorTag: options?.predecessorTag ?? null,
    fixCreditDecisionCounts: { credited: 0, withheld: 0, invalid: 0 },
    fixCreditDecisions: [],
    riskSummary: {
      ...payload.riskSummary,
      containedReleaseFixCount: 0,
      containedWithoutFirstCreditCount: 0,
    },
  };
}

function countFixCreditDecisions(decisions: ReleaseFixCreditDecision[]): {
  credited: number;
  withheld: number;
  invalid: number;
} {
  return decisions.reduce((counts, decision) => {
    counts[decision.status]++;
    return counts;
  }, { credited: 0, withheld: 0, invalid: 0 });
}

export function closureProofAuditRows(tag: string, labelCutoffOverride?: string | null) {
  const release = getRelease(tag);
  const audit = getReleaseScoreAudit(tag);
  const labelCutoff = labelCutoffOverride !== undefined
    ? labelCutoffOverride
    : release ? releaseLabelCutoff(release, audit?.scored_at ?? null) : null;
  return closureProofRows(tag)
    .map((row) => closureProofAuditItemFromRow(row, labelCutoff))
    .sort(compareClosureProofExamples);
}

function closureProofAuditItemFromRow(
  row: ClosureProofJoinedRow,
  labelCutoff: string | null,
  dispositionOverride?: ClosureRiskDisposition,
) {
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
    riskWeight: roundMetric(
      closureRiskWeightForRow(effectiveRiskRow, dispositionOverride),
    ),
    riskDisposition: dispositionOverride ?? closureRiskDisposition(row.status),
    evidence: parseJson(row.evidence_json, {}),
  };
}

function compareClosureProofExamples(a: any, b: any): number {
  const riskDiff = Number(b.riskWeight ?? 0) - Number(a.riskWeight ?? 0);
  if (riskDiff !== 0) return riskDiff;
  const statusDiff = closureStatusRank(a.status) - closureStatusRank(b.status);
  if (statusDiff !== 0) return statusDiff;
  return String(b.closedAt ?? '').localeCompare(String(a.closedAt ?? ''));
}

function representativeExamplesByStatus(
  allExamples: any[],
  summaryRows: Array<{ status: string; count: number }>,
  limitPerStatus = 1,
): Record<string, any[]> {
  const byStatus: Record<string, any[]> = {};
  for (const row of summaryRows) {
    if (row.status === 'fixed_in_release' || Number(row.count ?? 0) <= 0) continue;
    const examples = allExamples
      .filter((example) => example.status === row.status)
      .slice(0, limitPerStatus);
    if (examples.length) byStatus[row.status] = examples;
  }
  return byStatus;
}

export const CLOSURE_PROOF_STATUS_RANK = {
  duplicate_to_open_canonical: 0,
  superseded_to_open_pr: 1,
  duplicate_with_open_pr_context: 2,
  not_planned_with_open_pr_context: 3,
  linked_closing_pr_open: 4,
  related_open_pr_context: 5,
  duplicate_with_release_fix_proof: 6,
  fixed_not_in_scored_releases: 6,
  fixed_in_later_release: 7,
  fixed_after_latest_release: 8,
  fixed_skipped_by_later_releases: 9,
  fixed_after_release: 10,
  duplicate_to_fixed_after_release: 11,
  not_planned_fixed_after_release: 12,
  not_planned_direct_fix_commit_reachability_unknown: 12.5,
  related_merged_pr_not_reachable_context: 13,
  not_planned_related_merged_pr_not_reachable_context: 14,
  duplicate_related_merged_pr_not_reachable_context: 15,
  main_only_claim: 16,
  already_present_claim: 17,
  admin_not_planned_unverified: 18,
  admin_not_planned_no_context: 19,
  duplicate_to_closed_canonical_missing_proof: 20,
  duplicate_to_unverified_closed_canonical: 21,
  duplicate_to_known_not_in_release_canonical: 22,
  duplicate_to_open_pr_canonical: 23,
  duplicate_to_closed_canonical: 24,
  duplicate_to_non_actionable_canonical: 25,
  canonical_cycle_or_self_reference: 26,
  duplicate_or_superseded: 27,
  repro_requested: 28,
  insufficient_info: 29,
  linked_closing_pr_reachability_unknown: 30,
  related_merged_pr_reachability_unknown: 31,
  not_planned_related_merged_pr_reachability_unknown: 32,
  duplicate_related_merged_pr_reachability_unknown: 33,
  linked_closing_pr_closed_unmerged: 34,
  linked_closing_pr_not_merged: 35,
  not_planned_linked_pr_not_merged: 36,
  related_closed_unmerged_pr_context: 37,
  not_planned_related_closed_unmerged_pr_context: 38,
  duplicate_related_closed_unmerged_pr_context: 39,
  external_repo_closing_pr_unscored: 40,
  related_merged_pr_reachable_context_without_fix_credit: 41,
  not_planned_related_merged_pr_reachable_context_without_fix_credit: 42,
  duplicate_related_merged_pr_reachable_context_without_fix_credit: 43,
  related_pr_without_release_fix: 44,
  not_planned_related_pr_without_release_fix: 45,
  duplicate_related_pr_without_release_fix: 46,
  direct_fix_commit_reachability_unknown: 47,
  closed_without_release_fix_proof: 48,
  no_code_proof: 49,
  no_timeline_event: 50,
  unknown: 51,
  reporter_replaced: 52,
  reporter_withdrawn: 53,
  reporter_self_closed: 54,
  non_bug_direct_fix_commit_reachability_unknown: 55,
  non_bug_fixed_after_release: 56,
  non_bug_fixed_after_latest_release: 57,
  non_bug_fixed_skipped_by_later_releases: 58,
  non_bug_fixed_not_in_scored_releases: 59,
  non_bug_fixed_in_later_release: 60,
  non_bug_linked_without_merge: 61,
  non_bug_linked_pr_open: 62,
  non_bug_linked_pr_closed_unmerged: 63,
  non_bug_duplicate_to_open_canonical: 64,
  non_bug_superseded_to_open_pr: 65,
  non_bug_duplicate_with_open_pr_context: 66,
  non_bug_duplicate_related_merged_pr_not_reachable_context: 67,
  non_bug_duplicate_related_merged_pr_reachability_unknown: 68,
  non_bug_duplicate_related_closed_unmerged_pr_context: 69,
  non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit: 70,
  non_bug_duplicate_related_pr_without_release_fix: 71,
  non_bug_duplicate_to_fixed_after_release: 72,
  non_bug_duplicate_to_closed_canonical_missing_proof: 73,
  non_bug_duplicate_to_closed_canonical: 74,
  non_bug_duplicate_or_superseded: 75,
  non_bug_not_actionable: 76,
  not_planned: 77,
  non_bug_neutral: 78,
  non_bug_duplicate_to_fixed_in_release: 79,
  non_bug_fixed_in_release: 80,
  not_planned_with_release_fix_proof: 81,
  duplicate_to_fixed_in_release: 82,
  fixed_in_release: 83,
} satisfies Record<ClosureProofStatus, number>;

const rankedStatusSet = new Set<ClosureProofStatus>(Object.keys(CLOSURE_PROOF_STATUS_RANK) as ClosureProofStatus[]);
if (rankedStatusSet.size !== CLOSURE_PROOF_STATUSES.length) {
  throw new Error('closure proof status rank table must cover every proof status exactly once');
}

function closureStatusRank(status: string): number {
  return CLOSURE_PROOF_STATUS_RANK[status as ClosureProofStatus] ?? Number.MAX_SAFE_INTEGER;
}

function isNeutralAuditExample(example: any): boolean {
  return example.riskDisposition === 'neutral_or_non_actionable' &&
    example.sentiment === 'neutral' &&
    (
      example.severity === 'high' ||
      example.severity === 'critical' ||
      BUG_SHAPED_TITLE_RE.test(example.title ?? '')
    );
}

function compareNeutralAuditExamples(a: any, b: any): number {
  const severityDiff = neutralAuditSeverityRank(b.severity) - neutralAuditSeverityRank(a.severity);
  if (severityDiff !== 0) return severityDiff;
  const bugDiff = Number(BUG_SHAPED_TITLE_RE.test(b.title ?? '')) - Number(BUG_SHAPED_TITLE_RE.test(a.title ?? ''));
  if (bugDiff !== 0) return bugDiff;
  return String(b.closedAt ?? '').localeCompare(String(a.closedAt ?? ''));
}

function neutralAuditSeverityRank(severity: unknown): number {
  return ({ critical: 3, high: 2, medium: 1, low: 0 } as Record<string, number>)[String(severity ?? '')] ?? 0;
}

export function enrichGateEvidenceWithClosureProof(tag: string, gateEvidence: any, closureProof = closureProofPayload(tag)) {
  if (gateEvidence) {
    const payload: any = closureProof ?? emptyClosureProofPayload();
    gateEvidence.fixProvenance ??= {};
    gateEvidence.fixProvenance.closureProof = payload;
    const releaseFixCredit: Record<string, unknown> = {
      schemaVersion: RELEASE_FIX_CREDIT_SCHEMA_VERSION,
      countedClosedCount: payload.creditedCount,
      notCountedClosedCount: payload.notCreditedCount,
      analyzedClosedCount: payload.analyzedClosedCount,
    };
    if (Array.isArray(payload.fixCreditDecisions)) {
      Object.assign(releaseFixCredit, {
        targetTag: payload.targetTag ?? tag,
        predecessorTag: payload.predecessorTag ?? null,
        containedFixedCount: payload.containedFixedCount ?? 0,
        containedNotCreditedCount: payload.containedNotCreditedCount ?? 0,
        decisionCounts: payload.fixCreditDecisionCounts ?? {
          credited: 0,
          withheld: 0,
          invalid: 0,
        },
        decisions: payload.fixCreditDecisions,
      });
    }
    gateEvidence.fixProvenance.releaseFixCredit = releaseFixCredit;
  }
  return gateEvidence;
}

export function persistClosureProofInScoreAudit(tag: string): never {
  throw new Error(
    `Direct closure-proof patching is disabled for ${tag}; rebuild and seal the full score run instead`,
  );
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
  rows: Array<{ issue_number: number; status: string }>,
  overrides?: ReadonlyMap<number, ClosureRiskDisposition>,
): Partial<Record<ClosureRiskDisposition, number>> {
  const counts: Partial<Record<ClosureRiskDisposition, number>> = {};
  for (const row of rows) {
    const disposition =
      overrides?.get(row.issue_number) ?? closureRiskDisposition(row.status);
    counts[disposition] = (counts[disposition] ?? 0) + 1;
  }
  return counts;
}

type ClosureRiskWeightRow = Pick<ClosureProofRiskRow,
  'status' | 'sentiment' | 'severity' | 'scope' | 'functionality' | 'affected_users'
>;

export type ClosureRiskSourceRow = ClosureRiskWeightRow & {
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

export function closureRiskWeightForRow(
  row: ClosureRiskWeightRow,
  dispositionOverride?: ClosureRiskDisposition,
): number {
  const disposition = dispositionOverride ?? closureRiskDisposition(row.status);
  if (!isAffirmativeClosureRiskDisposition(disposition)) return 0;
  const dispositionWeight = CLOSURE_RISK_DISPOSITION_WEIGHT[disposition] ?? 0;
  if (dispositionWeight <= 0) return 0;
  return dispositionWeight * closureRiskClassificationWeightForRow(row);
}

export function isAffirmativeClosureRiskDisposition(
  disposition: string,
): disposition is typeof AFFIRMATIVE_CLOSURE_RISK_DISPOSITIONS[number] {
  return (AFFIRMATIVE_CLOSURE_RISK_DISPOSITIONS as readonly string[]).includes(disposition);
}

export function closureRiskClassificationWeightForRow(row: ClosureRiskWeightRow): number {
  if (row.sentiment !== 'negative') return 0;
  const severity = SEVERITY_RISK_WEIGHT[row.severity ?? ''] ?? 0;
  const functionality = FUNCTIONALITY_RISK_WEIGHT[row.functionality ?? ''] ?? 0;
  if (severity <= 0 || functionality <= 0) return 0;
  return severity *
    functionality *
    (SCOPE_RISK_WEIGHT[row.scope ?? ''] ?? 1) *
    (USERS_RISK_WEIGHT[row.affected_users ?? 'unknown'] ?? USERS_RISK_WEIGHT.unknown);
}

export function scoreAffectingMissingEvidenceClosureRows(
  tag: string,
  labelCutoffOverride?: string | null,
): MissingClosureEvidenceDiagnostic[] {
  const release = getRelease(tag);
  const audit = getReleaseScoreAudit(tag);
  const labelCutoff = labelCutoffOverride !== undefined
    ? labelCutoffOverride
    : release ? releaseLabelCutoff(release, audit?.scored_at ?? null) : null;
  return closureProofRiskRows(tag)
    .filter((row) => closureRiskDisposition(row.status) === 'missing_evidence')
    .map((row) => {
      const effective = effectiveClosureRiskRow(row, labelCutoff);
      return {
        issueNumber: row.issue_number,
        status: row.status,
        title: row.title,
        sentiment: effective.sentiment ?? '',
        severity: effective.severity ?? '',
        functionality: effective.functionality ?? '',
        scope: effective.scope ?? '',
        affectedUsers: effective.affected_users ?? '',
        potentialRiskWeight:
          closureRiskClassificationWeightForRow(effective) * Number(row.count ?? 0),
      };
    })
    .filter((row) => row.potentialRiskWeight > 0)
    .map((row) => ({
      ...row,
      potentialRiskWeight: roundMetric(row.potentialRiskWeight),
    }))
    .sort((left, right) =>
      left.issueNumber - right.issueNumber ||
      left.status.localeCompare(right.status)
    );
}

function weightedRiskForRows(
  rows: ClosureProofRiskRow[],
  labelCutoff: string | null,
  overrides?: ReadonlyMap<number, ClosureRiskDisposition>,
): {
  unresolvedForReleaseCount: number;
  unresolvedWeightedRisk: number;
  byDisposition: Partial<Record<ClosureRiskDisposition, number>>;
} {
  const aggregated = aggregateClosureRisk(rows.map((row) => {
    const disposition =
      overrides?.get(row.issue_number) ?? closureRiskDisposition(row.status);
    const effective = effectiveClosureRiskRow(row, labelCutoff);
    return {
      issueNumber: row.issue_number,
      disposition,
      weight:
        closureRiskWeightForRow(effective, disposition) *
        Number(row.count ?? 0),
      duplicateCluster: row.duplicate_cluster,
      canonicalIssueNumber: canonicalIssueNumberForRisk(row.evidence_json),
    };
  }));
  return {
    unresolvedForReleaseCount: aggregated.unresolvedForReleaseCount,
    unresolvedWeightedRisk: aggregated.unresolvedWeightedRisk,
    byDisposition: aggregated.weightedRiskByDisposition as Partial<Record<ClosureRiskDisposition, number>>,
  };
}

function canonicalIssueNumberForRisk(evidenceJson: string | null | undefined): number | null {
  const evidence = parseJson<Record<string, any>>(evidenceJson, {});
  const number = Number(evidence?.canonicalResolution?.terminalIssue?.number);
  return Number.isInteger(number) && number > 0 ? number : null;
}

const BUG_SHAPED_TITLE_RE = /\b(bug|fail(?:s|ed|ure)?|error|crash|stuck|regression|broken|lost|timeout|leak|silently|dropped|corrupt|deadlock|stall)\b/i;

function neutralAuditSignalsForRows(
  rows: ClosureProofRiskRow[],
  labelCutoff: string | null,
  overrides?: ReadonlyMap<number, ClosureRiskDisposition>,
): {
  highImpact: number;
  bugShaped: number;
} {
  let highImpact = 0;
  let bugShaped = 0;
  for (const row of rows) {
    const disposition =
      overrides?.get(row.issue_number) ?? closureRiskDisposition(row.status);
    if (disposition !== 'neutral_or_non_actionable') continue;
    const effective = effectiveClosureRiskRow(row, labelCutoff);
    if (effective.sentiment !== 'neutral') continue;
    if (effective.severity === 'high' || effective.severity === 'critical') {
      highImpact += Number(row.count ?? 0);
    }
    if (BUG_SHAPED_TITLE_RE.test(row.title ?? '')) {
      bugShaped += Number(row.count ?? 0);
    }
  }
  return { highImpact, bugShaped };
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

export function effectiveClosureClassification(
  row: ClosureRiskSourceRow,
  labelCutoff: string | null,
  labelsAtCutoffOverride?: string[],
): {
  labels: string[];
  rawClassification: IssueClassification;
  classification: IssueClassification;
  classificationDiff: Record<string, { raw: unknown; effective: unknown }>;
  labelSource: string;
} | null {
  if (!row.sentiment || !row.severity || !row.scope || !row.functionality || !row.affected_users) {
    return null;
  }
  const labelsAtCutoff = labelsAtCutoffOverride ?? labelsForIssueAt(
    row.issue_number,
    parseJson<string[]>(row.labels, []),
    labelCutoff,
    {
      useFallbackWhenNoEvents: labelCutoff == null,
      useSnapshotWhenNoEvents: labelCutoff != null,
    },
  );
  const labelInfo = scoringLabelInfoAtCutoff(
    row.issue_number,
    labelsAtCutoff,
    labelCutoff,
  );
  const labels = labelInfo.labels;
  const timelineEventCount = issueLabelEventCount(row.issue_number);
  const snapshotCount = issueLabelSnapshotCountAt(row.issue_number, labelCutoff);
  const rawClassification = rowToClassification(row);
  const classification = applyClosureRiskSentimentHint(
    applyTitleIssueShapeHint(
      applyLabelOverrides(
        applyTitleFunctionalityHint(rawClassification, row.title ?? ''),
        labels,
        labelInfo,
      ),
      row.title ?? '',
      labels,
      labelInfo,
    ),
    row.title ?? '',
    labels,
    labelInfo,
  );
  return {
    labels,
    rawClassification,
    classification,
    classificationDiff: classificationDiff(rawClassification, classification),
    labelSource: rowLabelSource(labelCutoff, timelineEventCount, snapshotCount),
  };
}

function rowLabelSource(labelCutoff: string | null, timelineEventCount: number, snapshotCount: number): string {
  if (labelCutoff == null) return 'current';
  if (timelineEventCount > 0) return 'timeline';
  if (snapshotCount > 0) return 'snapshot';
  return 'missing_timeline';
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
