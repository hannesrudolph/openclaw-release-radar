import { Router } from 'express';
import { config } from '../config';
import { getCached, setCached } from '../lib/cache';
import {
  getRefreshState,
  issuesForVersion,
  listReleasesDb,
  openedDuringReign,
} from '../lib/refresh';
import {
  comparisonReleases,
  dataFreshnessCacheDigest,
  getLastScoredAt,
  getRelease,
  getReleaseScoreAudit,
  latestScoredStableReleaseTag,
  latestComparisonSnapshot,
  listAdvisories,
  releaseDataFreshness,
  publicIssueSummaryFreshness,
  publicReleaseRowsFreshness,
  releasePrReachabilityRows,
  releaseScoreAuditFreshness,
  type AdvisoryRow,
} from '../lib/db';
import {
  closureProofAuditRows,
  enrichGateEvidenceWithClosureProof,
  CLOSURE_RISK_DISPOSITIONS,
} from '../lib/closureProofPayload';
import { CLOSURE_PROOF_STATUSES, closureRiskDispositionLabel, closureRiskWeightLabel } from '../lib/closureProofTaxonomy';
import { releaseLabelCutoff } from '../lib/labelCutoff';
import { matchesRange, firstPatchedVersion, stableDistance } from '../lib/versionMatch';
import { bandFor, type InstallStatus } from '../lib/score';
import { SCORE_HISTORY_CHART_LIMIT } from '../lib/historyWindow';
import { PUBLIC_ISSUES_PER_RELEASE, publicIssueSummariesForRelease } from '../lib/publicIssueSummary';
import {
  RELEASE_ISSUE_EVIDENCE_IMPACT_CLASSES,
  RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
  RELEASE_ISSUE_EVIDENCE_TIERS,
  releaseIssueEvidenceRows,
  summarizeIssueEvidenceRows,
  type ReleaseIssueEvidenceImpactClass,
  type ReleaseIssueEvidenceTier,
} from '../lib/releaseIssueEvidence';

export const api = Router();

// How many stables after a version we still count its CVEs for the BADGE. 0 =
// only CVEs patched in the very next stable — i.e. "this version's own disclosed
// vulnerabilities". This deliberately differs from the cumulative `< X` match:
// GitHub ranges have no lower bound, so the raw count grows with age (the oldest
// release showed "42 CVE", which looks alarming and falsely flatters the newest).
// The windowed count is age-fair (reflects how leaky THIS version was, not how old
// it is) and matches what the decayed score actually weighs. NOTE: this is display
// only — the skip-cve STATUS still trips on ANY medium+ match (security ≠ decay).
const CVE_BADGE_WINDOW = 0;
const CLOSURE_PROOF_AUDIT_SCHEMA_VERSION = 1;
const CLOSURE_PROOF_AUDIT_DEFAULT_LIMIT = 50;
const CLOSURE_PROOF_AUDIT_MAX_LIMIT = 100;
const ISSUE_EVIDENCE_AUDIT_DEFAULT_LIMIT = 50;
const ISSUE_EVIDENCE_AUDIT_MAX_LIMIT = 250;
const PR_REACHABILITY_AUDIT_SCHEMA_VERSION = 1;
const PR_REACHABILITY_AUDIT_DEFAULT_LIMIT = 100;
const PR_REACHABILITY_AUDIT_MAX_LIMIT = 250;
const ISSUE_EVIDENCE_SENTIMENTS = ['negative', 'positive', 'neutral'] as const;
const ISSUE_EVIDENCE_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const ISSUE_EVIDENCE_FUNCTIONALITIES = ['core', 'integration', 'provider', 'docs'] as const;
const ISSUE_EVIDENCE_SCOPES = ['broad', 'moderate', 'niche'] as const;
const ISSUE_EVIDENCE_AFFECTED_USERS = ['many', 'some', 'few', 'unknown'] as const;
const ISSUE_EVIDENCE_SORTS = ['rank', 'weight', 'updated', 'created', 'closed', 'number'] as const;
type IssueEvidenceSort = (typeof ISSUE_EVIDENCE_SORTS)[number];
type SortDirection = 'asc' | 'desc';

// Cross-reference each release tag against cached advisories. `affected` = CVEs in
// this version's own window (see CVE_BADGE_WINDOW); `patched` = CVEs whose fix first
// shipped in this exact release. A release that's merely "newer than the patch" is
// NOT credited as patching.
function advisoryStatusFor(tag: string, all: AdvisoryRow[], stableTags: string[]) {
  const norm = tag.replace(/^v/i, '');
  const affected: AdvisoryRow[] = [];
  const patched: AdvisoryRow[] = [];
  for (const a of all) {
    if (
      matchesRange(tag, a.vulnerable_version_range) &&
      stableDistance(tag, a.patched_versions, stableTags) <= CVE_BADGE_WINDOW
    ) {
      affected.push(a);
    }
    const first = firstPatchedVersion(a.patched_versions);
    if (first && (first === tag || first.replace(/^v/i, '') === norm)) patched.push(a);
  }
  return { affected, patched };
}

// Parse the stored broken-surfaces JSON (see lib/surfaces.ts) defensively.
function parseBrokenSurfaces(json: string | null): Array<{ label: string; icon: string; count: number }> {
  if (!json) return [];
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function summarizeAdvisories(list: AdvisoryRow[]) {
  const by = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const a of list) by[a.severity] = (by[a.severity] ?? 0) + 1;
  return {
    total: list.length,
    bySeverity: by,
    items: list.map((a) => ({
      ghsaId: a.ghsa_id,
      cveId: a.cve_id,
      severity: a.severity,
      summary: a.summary,
      url: a.html_url,
      patchedVersion: firstPatchedVersion(a.patched_versions),
    })),
  };
}

function parseJson<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function boundedInteger(
  raw: unknown,
  fallback: number,
  min: number,
  max: number,
): number {
  const value = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : fallback;
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

function closureProofAuditResponseRow(row: ReturnType<typeof closureProofAuditRows>[number]) {
  return {
    issueNumber: row.number,
    title: row.title,
    url: row.url,
    closedAt: row.closedAt,
    status: row.status,
    summary: row.summary,
    riskDisposition: row.riskDisposition,
    riskDispositionLabel: closureRiskDispositionLabel(row.riskDisposition),
    riskWeight: row.riskWeight,
    riskWeightLabel: closureRiskWeightLabel(row.riskWeight),
    checkedAt: row.checkedAt,
    labels: row.labels,
    classification: row.classification,
    classificationDiff: row.classificationDiff,
    evidence: compactClosureProofEvidence(row.evidence),
  };
}

function compactClosureProofEvidence(evidence: unknown) {
  const raw = evidence && typeof evidence === 'object' ? evidence as Record<string, unknown> : {};
  return {
    stateReasons: arrayOf(raw.stateReasons, compactScalar),
    closureActors: arrayOf(raw.closureActors, compactScalar),
    closureContextCommentCount: raw.closureContextCommentCount ?? null,
    hasClosingLink: raw.hasClosingLink === true,
    hasMergedClosingPr: raw.hasMergedClosingPr === true,
    hasReachableClosingPr: raw.hasReachableClosingPr === true,
    hasNotReachableClosingPr: raw.hasNotReachableClosingPr === true,
    hasReachableFixCommit: raw.hasReachableFixCommit === true,
    hasNotReachableFixCommit: raw.hasNotReachableFixCommit === true,
    canonicalIssues: arrayOf(raw.canonicalIssues, compactScalar),
    canonicalIssueDetails: arrayOf(raw.canonicalIssueDetails, compactIssueRef),
    canonicalResolution: compactCanonicalResolution(raw.canonicalResolution),
    closingPrs: arrayOf(raw.closingPrs, compactScalar),
    linkedPrs: arrayOf(raw.linkedPrs, compactPrRef),
    relatedPrContext: compactRelatedPrContext(raw.relatedPrContext),
    reachableTrustedFixProofPrs: arrayOf(raw.reachableTrustedFixProofPrs, compactPrRef),
    matchingComments: arrayOf(raw.matchingComments, compactCommentRef, 5),
    nonActionableRationaleComments: arrayOf(raw.nonActionableRationaleComments, compactCommentRef, 5),
    laterFixProof: compactLaterFixProof(raw.laterFixProof),
    unscoredFixProof: compactUnscoredFixProof(raw.unscoredFixProof),
    fixCommitProof: arrayOf(raw.fixCommitProof, compactCommitProof),
    canonicalFixCommitProof: arrayOf(raw.canonicalFixCommitProof, compactCommitProof),
    reachableFixCommits: arrayOf(raw.reachableFixCommits, compactScalar),
    notReachableFixCommits: arrayOf(raw.notReachableFixCommits, compactScalar),
  };
}

function compactRelatedPrContext(value: unknown) {
  const raw = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    externalClosing: arrayOf(raw.externalClosing, compactPrRef),
    open: arrayOf(raw.open, compactPrRef),
    closedUnmerged: arrayOf(raw.closedUnmerged, compactPrRef),
    notReachable: arrayOf(raw.notReachable, compactPrRef),
    reachable: arrayOf(raw.reachable, compactPrRef),
    unknownReachability: arrayOf(raw.unknownReachability, compactPrRef),
  };
}

function compactCanonicalResolution(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    path: arrayOf(raw.path, compactScalar),
    terminalIssue: compactIssueRef(raw.terminalIssue),
    terminalProof: raw.terminalProof && typeof raw.terminalProof === 'object'
      ? {
        status: (raw.terminalProof as Record<string, unknown>).status ?? null,
        summary: (raw.terminalProof as Record<string, unknown>).summary ?? null,
        crossRelease: (raw.terminalProof as Record<string, unknown>).crossRelease === true,
        releaseTag: (raw.terminalProof as Record<string, unknown>).releaseTag ?? null,
        timing: (raw.terminalProof as Record<string, unknown>).timing ?? null,
      }
      : null,
    cycle: raw.cycle === true,
    selfReference: raw.selfReference === true,
  };
}

function arrayOf<T>(value: unknown, mapper: (item: unknown) => T | null, limit = 50): T[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, limit).map(mapper).filter((item): item is T => item != null);
}

function compactScalar(value: unknown): string | number | boolean | null {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  return null;
}

function compactIssueRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const number = Number(raw.number ?? raw.issueNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : typeof raw.html_url === 'string' ? raw.html_url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
  };
}

function compactPrRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const number = Number(raw.number ?? raw.prNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    repositoryNameWithOwner: typeof raw.repositoryNameWithOwner === 'string' ? raw.repositoryNameWithOwner : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
    merged: raw.merged === 1 || raw.merged === true || typeof raw.mergedAt === 'string',
    mergedAt: typeof raw.mergedAt === 'string' ? raw.mergedAt : null,
    reachabilityStatus: typeof raw.reachabilityStatus === 'string' ? raw.reachabilityStatus : null,
    reachabilityMethod: typeof raw.reachabilityMethod === 'string' ? raw.reachabilityMethod : null,
    reachabilityEvidence: typeof raw.reachabilityEvidence === 'string' ? raw.reachabilityEvidence : null,
    mergeCommitOid: typeof raw.mergeCommitOid === 'string' ? raw.mergeCommitOid : null,
  };
}

function compactCommentRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    author: typeof raw.author === 'string' ? raw.author : null,
    createdAt: typeof raw.createdAt === 'string' ? raw.createdAt : null,
    updatedAt: typeof raw.updatedAt === 'string' ? raw.updatedAt : null,
    snippet: typeof raw.snippet === 'string' ? raw.snippet : null,
  };
}

function compactCommitProof(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    commitOid: typeof raw.commitOid === 'string' ? raw.commitOid : null,
    shortOid: typeof raw.shortOid === 'string' ? raw.shortOid : null,
    status: typeof raw.status === 'string' ? raw.status : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    evidence: typeof raw.evidence === 'string' ? raw.evidence : null,
    snippet: typeof raw.snippet === 'string' ? raw.snippet : null,
  };
}

function compactLaterFixProof(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    releaseTag: typeof raw.releaseTag === 'string' ? raw.releaseTag : null,
    publishedAt: typeof raw.publishedAt === 'string' ? raw.publishedAt : null,
    proofType: typeof raw.proofType === 'string' ? raw.proofType : null,
    prNumber: Number.isInteger(Number(raw.prNumber)) ? Number(raw.prNumber) : null,
    prRepositoryNameWithOwner: typeof raw.prRepositoryNameWithOwner === 'string' ? raw.prRepositoryNameWithOwner : null,
    commitOid: typeof raw.commitOid === 'string' ? raw.commitOid : null,
  };
}

function compactUnscoredFixProof(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    timing: typeof raw.timing === 'string' ? raw.timing : null,
    proofTime: typeof raw.proofTime === 'string' ? raw.proofTime : null,
    latestScoredReleaseTag: typeof raw.latestScoredReleaseTag === 'string' ? raw.latestScoredReleaseTag : null,
    latestScoredReleasePublishedAt: typeof raw.latestScoredReleasePublishedAt === 'string' ? raw.latestScoredReleasePublishedAt : null,
    proofType: typeof raw.proofType === 'string' ? raw.proofType : null,
    prNumber: Number.isInteger(Number(raw.prNumber)) ? Number(raw.prNumber) : null,
    prRepositoryNameWithOwner: typeof raw.prRepositoryNameWithOwner === 'string' ? raw.prRepositoryNameWithOwner : null,
    commitOid: typeof raw.commitOid === 'string' ? raw.commitOid : null,
  };
}

function parsePrFilter(raw: unknown): { repo: string | null; number: number } | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const value = raw.trim();
  const match = /^(?:(?<repo>[^#]+)#)?(?<number>\d+)$/.exec(value);
  if (!match?.groups) return null;
  const number = Number(match.groups.number);
  if (!Number.isInteger(number) || number <= 0) return null;
  const repo = match.groups.repo?.trim() || null;
  return { repo, number };
}

function parseIssueEvidenceTierFilter(raw: unknown): ReleaseIssueEvidenceTier[] | null {
  const tiers = parseCommaList(raw);
  if (!tiers.length) return null;
  const aliases: Record<string, ReleaseIssueEvidenceTier> = {
    openUnconfirmedRisk: 'carryoverDebt',
  };
  const normalized = tiers.map((tier) => aliases[tier] ?? tier);
  if (normalized.some((tier) => !(RELEASE_ISSUE_EVIDENCE_TIERS as readonly string[]).includes(tier))) return [];
  return [...new Set(normalized)] as ReleaseIssueEvidenceTier[];
}

function parseIssueEvidenceImpactFilter(raw: unknown): ReleaseIssueEvidenceImpactClass[] | null {
  const impacts = parseCommaList(raw);
  if (!impacts.length) return null;
  if (impacts.some((impact) => !(RELEASE_ISSUE_EVIDENCE_IMPACT_CLASSES as readonly string[]).includes(impact))) return [];
  return impacts as ReleaseIssueEvidenceImpactClass[];
}

function parseIssueEvidenceStateFilter(raw: unknown): Array<'open' | 'closed' | 'other'> | null {
  const states = parseCommaList(raw);
  if (!states.length) return null;
  if (states.some((state) => !['open', 'closed', 'other'].includes(state))) return [];
  return states as Array<'open' | 'closed' | 'other'>;
}

function parseIssueEvidenceEnumFilter<T extends string>(raw: unknown, allowed: readonly T[]): T[] | null {
  const values = parseCommaList(raw);
  if (!values.length) return null;
  if (values.some((value) => !allowed.includes(value as T))) return [];
  return values as T[];
}

function parseBooleanFilter(raw: unknown): boolean | null | undefined {
  if (raw == null) return null;
  const value = Array.isArray(raw) ? raw[0] : raw;
  const text = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes'].includes(text)) return true;
  if (['0', 'false', 'no'].includes(text)) return false;
  return undefined;
}

function parseNumberFilter(raw: unknown): number | null | undefined {
  if (raw == null || raw === '') return null;
  const value = Array.isArray(raw) ? raw[0] : raw;
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}

function parseIssueEvidenceSort(raw: unknown): IssueEvidenceSort | null {
  if (raw == null || raw === '') return 'rank';
  const value = Array.isArray(raw) ? raw[0] : raw;
  const text = String(value).trim();
  return (ISSUE_EVIDENCE_SORTS as readonly string[]).includes(text) ? text as IssueEvidenceSort : null;
}

function parseSortDirection(raw: unknown, sort: IssueEvidenceSort): SortDirection | null {
  if (raw == null || raw === '') return sort === 'rank' ? 'asc' : 'desc';
  const value = Array.isArray(raw) ? raw[0] : raw;
  const text = String(value).trim().toLowerCase();
  return text === 'asc' || text === 'desc' ? text : null;
}

function parseCommaList(raw: unknown): string[] {
  const values = Array.isArray(raw) ? raw : typeof raw === 'string' ? [raw] : [];
  return [...new Set(values
    .flatMap((value) => String(value).split(','))
    .map((value) => value.trim())
    .filter(Boolean))];
}

function issueEvidenceState(row: { issue?: { state?: unknown; missing?: unknown } }): 'open' | 'closed' | 'other' {
  const state = row.issue?.state;
  return state === 'open' || state === 'closed' ? state : 'other';
}

function issueClassificationField(row: { issue?: unknown; debtClassification?: unknown }, field: string): string | null {
  const debtClassification = row.debtClassification && typeof row.debtClassification === 'object'
    ? row.debtClassification as Record<string, unknown>
    : null;
  const issue = row.issue && typeof row.issue === 'object' ? row.issue as Record<string, unknown> : null;
  const classification = issue?.classification && typeof issue.classification === 'object'
    ? issue.classification as Record<string, unknown>
    : null;
  const value = debtClassification?.[field] ?? classification?.[field];
  return typeof value === 'string' ? value : null;
}

function sortedIssueEvidenceRows<T extends { row: any; rank: number }>(
  rows: T[],
  sort: IssueEvidenceSort,
  direction: SortDirection,
): T[] {
  return [...rows].sort((a, b) => {
    const valueDiff = compareIssueEvidenceSortValue(a, b, sort, direction);
    if (valueDiff !== 0) return valueDiff;
    return a.rank - b.rank;
  });
}

function compareIssueEvidenceSortValue(
  a: { row: any; rank: number },
  b: { row: any; rank: number },
  sort: IssueEvidenceSort,
  direction: SortDirection,
): number {
  if (sort === 'rank') return direction === 'asc' ? a.rank - b.rank : b.rank - a.rank;
  const av = issueEvidenceSortValue(a.row, sort);
  const bv = issueEvidenceSortValue(b.row, sort);
  const aMissing = av == null || Number.isNaN(av);
  const bMissing = bv == null || Number.isNaN(bv);
  if (aMissing && bMissing) return 0;
  if (aMissing) return 1;
  if (bMissing) return -1;
  const diff = av === bv ? 0 : av < bv ? -1 : 1;
  return direction === 'asc' ? diff : -diff;
}

function issueEvidenceSortValue(row: any, sort: IssueEvidenceSort): number | null {
  if (sort === 'weight') {
    const weight = Number(row.weight);
    return Number.isFinite(weight) ? weight : null;
  }
  if (sort === 'number') {
    const number = Number(row.issue?.number);
    return Number.isInteger(number) && number > 0 ? number : null;
  }
  if (sort === 'updated') return timestampValue(row.issue?.updatedAt);
  if (sort === 'created') return timestampValue(row.issue?.createdAt);
  if (sort === 'closed') return timestampValue(row.issue?.closedAt);
  return null;
}

function timestampValue(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function issueEvidenceCountsByTier(rows: Array<{ tier: ReleaseIssueEvidenceTier }>): Record<ReleaseIssueEvidenceTier, number> {
  const counts = Object.fromEntries(RELEASE_ISSUE_EVIDENCE_TIERS.map((tier) => [tier, 0])) as Record<ReleaseIssueEvidenceTier, number>;
  for (const row of rows) counts[row.tier] += 1;
  return counts;
}

function issueEvidenceSummaryByTier(rows: any[]): Record<ReleaseIssueEvidenceTier, ReturnType<typeof summarizeIssueEvidenceRows>> {
  return Object.fromEntries(RELEASE_ISSUE_EVIDENCE_TIERS.map((tier) => [
    tier,
    summarizeIssueEvidenceRows(rows.filter((row) => row.tier === tier)),
  ])) as Record<ReleaseIssueEvidenceTier, ReturnType<typeof summarizeIssueEvidenceRows>>;
}

function distinctIssueCount(rows: Array<{ issue?: { number?: unknown }; number?: unknown; issueNumber?: unknown }>): number {
  const numbers = new Set<number>();
  for (const row of rows) {
    const number = Number(row.issue?.number ?? row.number ?? row.issueNumber);
    if (Number.isInteger(number) && number > 0) numbers.add(number);
  }
  return numbers.size;
}

function countByStringField<T>(rows: T[], getter: (row: T) => unknown): Record<string, number> {
  return rows.reduce((acc, row) => {
    const key = getter(row);
    if (typeof key === 'string' && key) acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

function distinctPullRequestCount(rows: Array<{ pr_repository_name_with_owner?: unknown; pr_number?: unknown }>): number {
  const prs = new Set<string>();
  for (const row of rows) {
    const repo = typeof row.pr_repository_name_with_owner === 'string' ? row.pr_repository_name_with_owner : null;
    const number = Number(row.pr_number);
    if (repo && Number.isInteger(number) && number > 0) prs.add(`${repo.toLowerCase()}#${number}`);
  }
  return prs.size;
}

function reachabilityAuditResponseRow(row: ReturnType<typeof releasePrReachabilityRows>[number]) {
  return {
    repositoryNameWithOwner: row.pr_repository_name_with_owner,
    number: row.pr_number,
    title: row.title,
    url: row.url,
    state: row.state,
    merged: row.merged === 1,
    mergedAt: row.merged_at,
    status: row.status,
    method: row.method,
    checkedAt: row.checked_at,
    tagCommitOid: row.tag_commit_oid,
    mergeCommitOid: row.merge_commit_oid,
    prMergeCommitOid: row.pr_merge_commit_oid,
    baseRefName: row.base_ref_name ?? row.pr_base_ref_name,
    evidence: parseJson(row.evidence_json, {}),
  };
}

function normalizeComparison(row: Record<string, unknown> | undefined) {
  if (!row) return null;
  return {
    schemaVersion: COMPARISON_UPSTREAM_SCHEMA_VERSION,
    snapshotId: row.snapshot_id,
    tag: row.tag,
    score: row.score,
    band: row.band,
    status: row.status,
    recommended: row.recommended === 1,
    reason: row.reason,
    negativeIssues: row.negative_issues,
    positiveIssues: row.positive_issues,
    totalAttributedIssues: row.total_attributed_issues,
    visibleIssues: parseJson(String(row.visible_issues_json ?? '[]'), [] as unknown[]),
    rawCardText: row.raw_card_text,
  };
}

function normalizeComparisonSnapshot(row: ReturnType<typeof latestComparisonSnapshot>) {
  if (!row) return null;
  return {
    id: row.id,
    sourceUrl: row.source_url,
    capturedAt: row.captured_at,
    pageTitle: row.page_title,
  };
}

api.get('/health', (_req, res) => {
  res.json({ ok: true, repo: `${config.github.owner}/${config.github.repo}` });
});

// UI config — lets the frontend respect server-side limits without hardcoding.
api.get('/config', (_req, res) => {
  res.json({
    schemaVersion: CONFIG_PAYLOAD_SCHEMA_VERSION,
    releases: config.limits.releases,
    refreshMinutes: config.refresh.intervalMinutes,
  });
});

api.get('/status', (_req, res) => {
  const state = getRefreshState();
  const lastScoredAt = getLastScoredAt();
  const latestScoredTag = latestScoredStableReleaseTag();
  res.json({
    schemaVersion: STATUS_PAYLOAD_SCHEMA_VERSION,
    ...state,
    lastRefreshAt: state.processLastRefreshAt,
    processLastRefreshAt: state.processLastRefreshAt,
    lastScoredAt,
    dataFreshness: latestScoredTag ? releaseDataFreshness(latestScoredTag) : null,
  });
});

// Maintainer-signal counts mined from the release-notes body + neighbouring releases.
// See lib/releaseNotes.ts. These are exposed for the UI to render without further
// computation, but the UI is intentionally NOT consuming them yet — we want to watch
// the numbers settle across a few refresh cycles before deciding how to surface them.
//
// `breakingCount` semantics: for a stable release, this is the AGGREGATE of its
// own `### Breaking` bullets plus those in every beta in the chain back to the
// previous stable. The maintainer typically lists a breaking change in the beta
// that introduced it and does NOT repeat the bullet when the stable promotes —
// so the stable's own body alone undercounts breakage that ships in it. See
// `computeAggregateBreaking` in lib/releaseNotes.ts. `fixesCount` / `changesCount`
// stay own-only because changelog generators DO re-list those at promotion.
function maintainerSignals(r: {
  breaking_count: number;
  fixes_count: number;
  changes_count: number;
  highlights_count: number;
  pr_refs_count: number;
  beta_count: number;
  hours_to_next_release: number | null;
  hours_to_next_stable: number | null;
}) {
  return {
    breakingCount:      r.breaking_count,
    fixesCount:         r.fixes_count,
    changesCount:       r.changes_count,
    highlightsCount:    r.highlights_count,
    prRefsCount:        r.pr_refs_count,
    betaCount:          r.beta_count,
    hoursToNextRelease: r.hours_to_next_release,
    hoursToNextStable:  r.hours_to_next_stable,
  };
}

const SCORE_AUDIT_SUMMARY_SCHEMA_VERSION = 1;
const LOCAL_AUDIT_SCHEMA_VERSION = 1;
const COMPARISON_PAYLOAD_SCHEMA_VERSION = 1;
const COMPARISON_UPSTREAM_SCHEMA_VERSION = 1;
const COMPARISON_DELTA_SCHEMA_VERSION = 1;
const STATUS_PAYLOAD_SCHEMA_VERSION = 1;
const CONFIG_PAYLOAD_SCHEMA_VERSION = 1;
const RELEASE_ROW_SCHEMA_VERSION = 2;
const RELEASE_HISTORY_ROW_SCHEMA_VERSION = 1;

function scoreAuditSummary(audit: ReturnType<typeof getReleaseScoreAudit>) {
  if (!audit) return null;
  const components = parseJson(audit.components_json, null) as any;
  const input = parseJson(audit.input_json, null) as any;
  return {
    schemaVersion: SCORE_AUDIT_SUMMARY_SCHEMA_VERSION,
    modelVersion: audit.score_model_version,
    promptVersion: audit.prompt_version,
    evidenceCoverage: components?.evidenceCoverage ?? null,
    rawIssueCount: input?.rawIssueCount ?? null,
    classifiedIssueCount: input?.classifiedIssueCount ?? null,
  };
}

function scoreExplanation(audit: ReturnType<typeof getReleaseScoreAudit>) {
  if (!audit) return null;
  const components = parseJson(audit.components_json, null) as any;
  return components?.explanation ?? null;
}

function freshnessForRelease(
  release: { tag: string; published_at: string | null; hours_to_next_stable?: number | null },
  audit: ReturnType<typeof getReleaseScoreAudit>,
) {
  const labelRelease = {
    ...release,
    hours_to_next_stable: release.hours_to_next_stable ?? null,
  };
  return {
    ...releaseDataFreshness(release.tag),
    labelCutoffAt: releaseLabelCutoff(labelRelease, audit?.scored_at ?? null),
  };
}

function releaseAuditLinks(tag: string) {
  const encodedTag = encodeURIComponent(tag);
  return {
    review: `/api/releases/${encodedTag}/review`,
    issues: `/api/releases/${encodedTag}/review/issues`,
    closureProofs: `/api/releases/${encodedTag}/review/closure-proofs`,
    reachability: `/api/releases/${encodedTag}/review/reachability`,
  };
}

function releaseAuditRawRows(tag: string) {
  const { issues, closureProofs, reachability } = releaseAuditLinks(tag);
  return { issues, closureProofs, reachability };
}

function reviewSourceProvenance(tag: string, scoredAt: string | null, dataFreshness: ReturnType<typeof freshnessForRelease>) {
  return {
    sourceMode: 'current_db',
    scoreTable: 'release_score_audits',
    scoredAt,
    dataFreshnessScoredAt: dataFreshness.scoredAt,
    scoreTimestampAligned: scoredAt === dataFreshness.scoredAt,
    sources: dataFreshness.sources,
    rawRows: releaseAuditRawRows(tag),
  };
}

api.get('/releases', (_req, res) => {
  const rows = listReleasesDb(config.limits.releases);
  const advisories = listAdvisories();
  const stableTags = rows.map((r) => r.tag); // newest-first; used for CVE recency window
  res.json(
    rows.map((r) => {
      const status = advisoryStatusFor(r.tag, advisories, stableTags);
      const audit = getReleaseScoreAudit(r.tag);
      return {
        schemaVersion: RELEASE_ROW_SCHEMA_VERSION,
        tag: r.tag,
        name: r.name,
        publishedAt: r.published_at,
        htmlUrl: r.html_url,
        finalScore: r.final_score,                 // Install Confidence 0–10 (null when 'wait')
        band: bandFor(r.final_score, (r.state ?? 'eligible') as InstallStatus),
        status: r.state,                           // wait | skip-cve | skip-hotfix | eligible
        recommended: r.recommended === 1,
        reason: r.score_reason,
        brokenSurfaces: parseBrokenSurfaces(r.broken_surfaces),
        negativeIssues: r.negative_issues,
        positiveIssues: r.positive_issues,
        closedSeriousFixed: r.closed_serious_fixed,
        openedSeriousDuringReign: r.opened_serious_during_reign,
        scoredAt: r.scored_at,
        scoreAudit: scoreAuditSummary(audit),
        explanation: scoreExplanation(audit),
        dataFreshness: freshnessForRelease(r, audit),
        auditLinks: releaseAuditLinks(r.tag),
        advisories: {
          affected: summarizeAdvisories(status.affected),
          patched: summarizeAdvisories(status.patched),
        },
        maintainerSignals: maintainerSignals(r),
      };
    }),
  );
});

api.get('/releases/history', (_req, res) => {
  const rows = listReleasesDb(SCORE_HISTORY_CHART_LIMIT);
  res.json(
    rows.map((r) => ({
      schemaVersion: RELEASE_HISTORY_ROW_SCHEMA_VERSION,
      tag: r.tag,
      publishedAt: r.published_at,
      finalScore: r.final_score,
    })),
  );
});

api.get('/comparison', (_req, res) => {
  if (!config.comparison.apiEnabled) {
    res.status(404).json({ error: 'comparison api disabled' });
    return;
  }
  const snapshot = normalizeComparisonSnapshot(latestComparisonSnapshot());
  const upstreamByTag = new Map(comparisonReleases().map((row) => [String(row.tag), row]));
  const releases = listReleasesDb(config.limits.releases).map((release) => {
    const audit = getReleaseScoreAudit(release.tag);
    const upstream = normalizeComparison(upstreamByTag.get(release.tag));
    const localScore = release.final_score;
    const upstreamScore = typeof upstream?.score === 'number' ? upstream.score : null;
    return {
      tag: release.tag,
      local: {
        schemaVersion: LOCAL_AUDIT_SCHEMA_VERSION,
        score: localScore,
        band: bandFor(localScore, (release.state ?? 'eligible') as InstallStatus),
        status: release.state,
        recommended: release.recommended === 1,
        reason: release.score_reason,
        negativeIssues: release.negative_issues,
        positiveIssues: release.positive_issues,
        scoredAt: release.scored_at,
        dataFreshness: freshnessForRelease(release, audit),
        modelVersion: audit?.score_model_version ?? null,
        components: parseJson(audit?.components_json, null),
        input: parseJson(audit?.input_json, null),
        gateEvidence: enrichGateEvidenceWithClosureProof(release.tag, parseJson(audit?.gate_evidence_json, null)),
      },
      upstream,
      delta: {
        schemaVersion: COMPARISON_DELTA_SCHEMA_VERSION,
        score: localScore != null && upstreamScore != null ? Math.round((localScore - upstreamScore) * 10) / 10 : null,
        negativeIssues:
          release.negative_issues != null && typeof upstream?.negativeIssues === 'number'
            ? release.negative_issues - upstream.negativeIssues
            : null,
      },
    };
  });
  res.json({ schemaVersion: COMPARISON_PAYLOAD_SCHEMA_VERSION, snapshot, releases });
});

api.get('/releases/:tag/review', (req, res) => {
  const tag = req.params.tag;
  const release = getRelease(tag);
  if (!release) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  const audit = getReleaseScoreAudit(tag);
  const gateEvidence = enrichGateEvidenceWithClosureProof(tag, parseJson(audit?.gate_evidence_json, null));
  const dataFreshness = freshnessForRelease(release, audit);
  const payload: Record<string, unknown> = {
    tag,
    local: {
      schemaVersion: LOCAL_AUDIT_SCHEMA_VERSION,
      score: release.final_score,
      band: bandFor(release.final_score, (release.state ?? 'eligible') as InstallStatus),
      status: release.state,
      recommended: release.recommended === 1,
      reason: release.score_reason,
      negativeIssues: release.negative_issues,
      positiveIssues: release.positive_issues,
      scoredAt: release.scored_at,
      dataFreshness,
      sourceProvenance: reviewSourceProvenance(tag, release.scored_at, dataFreshness),
      modelVersion: audit?.score_model_version ?? null,
      promptVersion: audit?.prompt_version ?? null,
      input: parseJson(audit?.input_json, null),
      components: parseJson(audit?.components_json, null),
      issueEvidence: parseJson(audit?.issue_evidence_json, null),
      gateEvidence,
    },
  };
  if (req.query.includeComparison === '1') {
    if (!config.comparison.apiEnabled) {
      res.status(404).json({ error: 'comparison api disabled', tag });
      return;
    }
    payload.snapshot = normalizeComparisonSnapshot(latestComparisonSnapshot());
    payload.upstream = normalizeComparison(comparisonReleases().find((row) => row.tag === tag));
  }
  res.json(payload);
});

api.get('/releases/:tag/review/issues', (req, res) => {
  const tag = req.params.tag;
  const release = getRelease(tag);
  if (!release) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  const audit = getReleaseScoreAudit(tag);
  const tierFilter = parseIssueEvidenceTierFilter(req.query.tier);
  if (tierFilter && tierFilter.length === 0) {
    res.status(400).json({ error: 'invalid tier', tier: req.query.tier });
    return;
  }
  const impactFilter = parseIssueEvidenceImpactFilter(req.query.impact);
  if (impactFilter && impactFilter.length === 0) {
    res.status(400).json({ error: 'invalid impact', impact: req.query.impact });
    return;
  }
  const stateFilter = parseIssueEvidenceStateFilter(req.query.state);
  if (stateFilter && stateFilter.length === 0) {
    res.status(400).json({ error: 'invalid state', state: req.query.state });
    return;
  }
  const sentimentFilter = parseIssueEvidenceEnumFilter(req.query.sentiment, ISSUE_EVIDENCE_SENTIMENTS);
  if (sentimentFilter && sentimentFilter.length === 0) {
    res.status(400).json({ error: 'invalid sentiment', sentiment: req.query.sentiment });
    return;
  }
  const severityFilter = parseIssueEvidenceEnumFilter(req.query.severity, ISSUE_EVIDENCE_SEVERITIES);
  if (severityFilter && severityFilter.length === 0) {
    res.status(400).json({ error: 'invalid severity', severity: req.query.severity });
    return;
  }
  const functionalityFilter = parseIssueEvidenceEnumFilter(req.query.functionality, ISSUE_EVIDENCE_FUNCTIONALITIES);
  if (functionalityFilter && functionalityFilter.length === 0) {
    res.status(400).json({ error: 'invalid functionality', functionality: req.query.functionality });
    return;
  }
  const scopeFilter = parseIssueEvidenceEnumFilter(req.query.scope, ISSUE_EVIDENCE_SCOPES);
  if (scopeFilter && scopeFilter.length === 0) {
    res.status(400).json({ error: 'invalid scope', scope: req.query.scope });
    return;
  }
  const affectedUsersFilter = parseIssueEvidenceEnumFilter(req.query.affectedUsers, ISSUE_EVIDENCE_AFFECTED_USERS);
  if (affectedUsersFilter && affectedUsersFilter.length === 0) {
    res.status(400).json({ error: 'invalid affectedUsers', affectedUsers: req.query.affectedUsers });
    return;
  }
  const fieldConfirmedFilter = parseBooleanFilter(req.query.fieldConfirmed);
  if (fieldConfirmedFilter === undefined) {
    res.status(400).json({ error: 'invalid fieldConfirmed', fieldConfirmed: req.query.fieldConfirmed });
    return;
  }
  const minWeight = parseNumberFilter(req.query.minWeight);
  if (minWeight === undefined) {
    res.status(400).json({ error: 'invalid minWeight', minWeight: req.query.minWeight });
    return;
  }
  const maxWeight = parseNumberFilter(req.query.maxWeight);
  if (maxWeight === undefined) {
    res.status(400).json({ error: 'invalid maxWeight', maxWeight: req.query.maxWeight });
    return;
  }
  if (minWeight != null && maxWeight != null && minWeight > maxWeight) {
    res.status(400).json({ error: 'invalid weight range', minWeight, maxWeight });
    return;
  }
  const sort = parseIssueEvidenceSort(req.query.sort);
  if (!sort) {
    res.status(400).json({ error: 'invalid sort', sort: req.query.sort });
    return;
  }
  const direction = parseSortDirection(req.query.direction, sort);
  if (!direction) {
    res.status(400).json({ error: 'invalid direction', direction: req.query.direction });
    return;
  }
  const summaryOnly = parseBooleanFilter(req.query.summaryOnly);
  if (summaryOnly === undefined) {
    res.status(400).json({ error: 'invalid summaryOnly', summaryOnly: req.query.summaryOnly });
    return;
  }
  const limit = boundedInteger(req.query.limit, ISSUE_EVIDENCE_AUDIT_DEFAULT_LIMIT, 1, ISSUE_EVIDENCE_AUDIT_MAX_LIMIT);
  const cursor = boundedInteger(req.query.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
  const evidence = releaseIssueEvidenceRows(tag);
  if (!evidence) {
    res.status(404).json({ error: 'release evidence not found', tag });
    return;
  }
  const tierSet = tierFilter ? new Set(tierFilter) : null;
  const impactSet = impactFilter ? new Set(impactFilter) : null;
  const stateSet = stateFilter ? new Set(stateFilter) : null;
  const sentimentSet = sentimentFilter ? new Set(sentimentFilter) : null;
  const severitySet = severityFilter ? new Set(severityFilter) : null;
  const functionalitySet = functionalityFilter ? new Set(functionalityFilter) : null;
  const scopeSet = scopeFilter ? new Set(scopeFilter) : null;
  const affectedUsersSet = affectedUsersFilter ? new Set(affectedUsersFilter) : null;
  const filteredRows = evidence.rows
    .map((row, rank) => ({ row, rank }))
    .filter(({ row }) => !tierSet || tierSet.has(row.tier))
    .filter(({ row }) => !impactSet || impactSet.has(row.installImpactClass as ReleaseIssueEvidenceImpactClass))
    .filter(({ row }) => !stateSet || stateSet.has(issueEvidenceState(row)))
    .filter(({ row }) => !sentimentSet || sentimentSet.has(issueClassificationField(row, 'sentiment') as any))
    .filter(({ row }) => !severitySet || severitySet.has(issueClassificationField(row, 'severity') as any))
    .filter(({ row }) => !functionalitySet || functionalitySet.has(issueClassificationField(row, 'functionality') as any))
    .filter(({ row }) => !scopeSet || scopeSet.has(issueClassificationField(row, 'scope') as any))
    .filter(({ row }) => !affectedUsersSet || affectedUsersSet.has(issueClassificationField(row, 'affectedUsers') as any))
    .filter(({ row }) => fieldConfirmedFilter == null || row.fieldConfirmed === fieldConfirmedFilter)
    .filter(({ row }) => minWeight == null || Number(row.weight ?? 0) >= minWeight)
    .filter(({ row }) => maxWeight == null || Number(row.weight ?? 0) <= maxWeight);
  const allRows = sortedIssueEvidenceRows(filteredRows, sort, direction).map(({ row }) => row);
  const filteredCountsByTier = issueEvidenceCountsByTier(allRows);
  const filteredSummaryByTier = issueEvidenceSummaryByTier(allRows);
  const pageRows = summaryOnly ? [] : allRows.slice(cursor, cursor + limit);
  const nextCursor = summaryOnly ? null : cursor + pageRows.length < allRows.length ? cursor + pageRows.length : null;
  res.json({
    schemaVersion: RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
    tag,
    sourceMode: 'current_db',
    scoredAt: release.scored_at,
    dataFreshness: freshnessForRelease(release, audit),
    labelCutoffAt: evidence.labelCutoffAt,
    filters: {
      tier: tierFilter?.length === 1 ? tierFilter[0] : null,
      tiers: tierFilter ?? null,
      impact: impactFilter?.length === 1 ? impactFilter[0] : null,
      impacts: impactFilter ?? null,
      state: stateFilter?.length === 1 ? stateFilter[0] : null,
      states: stateFilter ?? null,
      sentiment: sentimentFilter?.length === 1 ? sentimentFilter[0] : null,
      sentiments: sentimentFilter ?? null,
      severity: severityFilter?.length === 1 ? severityFilter[0] : null,
      severities: severityFilter ?? null,
      functionality: functionalityFilter?.length === 1 ? functionalityFilter[0] : null,
      functionalities: functionalityFilter ?? null,
      scope: scopeFilter?.length === 1 ? scopeFilter[0] : null,
      scopes: scopeFilter ?? null,
      affectedUsers: affectedUsersFilter?.length === 1 ? affectedUsersFilter[0] : null,
      affectedUsersList: affectedUsersFilter ?? null,
      fieldConfirmed: fieldConfirmedFilter,
      minWeight,
      maxWeight,
      sort,
      direction,
      summaryOnly: summaryOnly === true,
    },
    countsByTier: evidence.countsByTier,
    summaryByTier: evidence.summaryByTier,
    unfilteredCountsByTier: evidence.countsByTier,
    unfilteredSummaryByTier: evidence.summaryByTier,
    filteredCountsByTier,
    filteredSummaryByTier,
    filteredSummary: summarizeIssueEvidenceRows(allRows),
    tierInfo: evidence.tierInfo,
    totals: {
      unfilteredRows: evidence.rows.length,
      filteredRows: allRows.length,
      unfilteredDistinctIssues: distinctIssueCount(evidence.rows),
      filteredDistinctIssues: distinctIssueCount(allRows),
    },
    total: allRows.length,
    totalRows: allRows.length,
    distinctIssueCount: distinctIssueCount(allRows),
    limit: summaryOnly ? 0 : limit,
    cursor: summaryOnly ? 0 : cursor,
    nextCursor,
    rows: pageRows,
  });
});

api.get('/releases/:tag/review/closure-proofs', (req, res) => {
  const tag = req.params.tag;
  const release = getRelease(tag);
  if (!release) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  const audit = getReleaseScoreAudit(tag);
  const statusFilter = typeof req.query.status === 'string' && req.query.status.trim()
    ? req.query.status.trim()
    : null;
  const riskDispositionFilter = typeof req.query.riskDisposition === 'string' && req.query.riskDisposition.trim()
    ? req.query.riskDisposition.trim()
    : null;
  if (statusFilter && !(CLOSURE_PROOF_STATUSES as readonly string[]).includes(statusFilter)) {
    res.status(400).json({
      error: 'invalid status',
      status: statusFilter,
      allowedStatuses: CLOSURE_PROOF_STATUSES,
    });
    return;
  }
  if (riskDispositionFilter && !(CLOSURE_RISK_DISPOSITIONS as readonly string[]).includes(riskDispositionFilter)) {
    res.status(400).json({
      error: 'invalid riskDisposition',
      riskDisposition: riskDispositionFilter,
      allowedRiskDispositions: CLOSURE_RISK_DISPOSITIONS,
    });
    return;
  }
  const limit = boundedInteger(req.query.limit, CLOSURE_PROOF_AUDIT_DEFAULT_LIMIT, 1, CLOSURE_PROOF_AUDIT_MAX_LIMIT);
  const cursor = boundedInteger(req.query.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
  const sourceRows = closureProofAuditRows(tag);
  const allRows = sourceRows
    .filter((row) => !statusFilter || row.status === statusFilter)
    .filter((row) => !riskDispositionFilter || row.riskDisposition === riskDispositionFilter);
  const pageRows = allRows.slice(cursor, cursor + limit).map(closureProofAuditResponseRow);
  const nextCursor = cursor + pageRows.length < allRows.length ? cursor + pageRows.length : null;
  res.json({
    schemaVersion: CLOSURE_PROOF_AUDIT_SCHEMA_VERSION,
    tag,
    sourceMode: 'current_db',
    scoredAt: release.scored_at,
    dataFreshness: freshnessForRelease(release, audit),
    filters: {
      status: statusFilter,
      riskDisposition: riskDispositionFilter,
    },
    totals: {
      unfilteredRows: sourceRows.length,
      filteredRows: allRows.length,
      unfilteredDistinctIssues: distinctIssueCount(sourceRows),
      filteredDistinctIssues: distinctIssueCount(allRows),
    },
    total: allRows.length,
    totalRows: allRows.length,
    distinctIssueCount: distinctIssueCount(allRows),
    unfilteredCountsByStatus: countByStringField(sourceRows, (row) => row.status),
    filteredCountsByStatus: countByStringField(allRows, (row) => row.status),
    unfilteredCountsByRiskDisposition: countByStringField(sourceRows, (row) => row.riskDisposition),
    filteredCountsByRiskDisposition: countByStringField(allRows, (row) => row.riskDisposition),
    limit,
    cursor,
    nextCursor,
    rows: pageRows,
  });
});

api.get('/releases/:tag/review/reachability', (req, res) => {
  const tag = req.params.tag;
  const release = getRelease(tag);
  if (!release) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  const audit = getReleaseScoreAudit(tag);
  const statusFilter = typeof req.query.status === 'string' && req.query.status.trim()
    ? req.query.status.trim()
    : null;
  if (statusFilter && !['reachable', 'not_reachable', 'unknown'].includes(statusFilter)) {
    res.status(400).json({ error: 'invalid status', status: statusFilter });
    return;
  }
  const prFilter = parsePrFilter(req.query.pr);
  if (typeof req.query.pr === 'string' && req.query.pr.trim() && !prFilter) {
    res.status(400).json({ error: 'invalid pr filter', pr: req.query.pr });
    return;
  }
  const limit = boundedInteger(req.query.limit, PR_REACHABILITY_AUDIT_DEFAULT_LIMIT, 1, PR_REACHABILITY_AUDIT_MAX_LIMIT);
  const cursor = boundedInteger(req.query.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
  const sourceRows = releasePrReachabilityRows(tag);
  const allRows = sourceRows
    .filter((row) => !statusFilter || row.status === statusFilter)
    .filter((row) => !prFilter || (
      row.pr_number === prFilter.number &&
      (!prFilter.repo || row.pr_repository_name_with_owner.toLowerCase() === prFilter.repo.toLowerCase())
    ));
  const filteredCountsByStatus = countByStringField(allRows, (row) => row.status);
  const unfilteredCountsByStatus = countByStringField(sourceRows, (row) => row.status);
  const pageRows = allRows.slice(cursor, cursor + limit).map(reachabilityAuditResponseRow);
  const nextCursor = cursor + pageRows.length < allRows.length ? cursor + pageRows.length : null;
  res.json({
    schemaVersion: PR_REACHABILITY_AUDIT_SCHEMA_VERSION,
    tag,
    sourceMode: 'current_db',
    scoredAt: release.scored_at,
    dataFreshness: freshnessForRelease(release, audit),
    filters: {
      status: statusFilter,
      pr: prFilter ? { repositoryNameWithOwner: prFilter.repo, number: prFilter.number } : null,
    },
    totals: {
      unfilteredRows: sourceRows.length,
      filteredRows: allRows.length,
      unfilteredPullRequests: distinctPullRequestCount(sourceRows),
      filteredPullRequests: distinctPullRequestCount(allRows),
    },
    total: allRows.length,
    totalRows: allRows.length,
    distinctPullRequestCount: distinctPullRequestCount(allRows),
    countsByStatus: filteredCountsByStatus,
    filteredCountsByStatus,
    unfilteredCountsByStatus,
    limit,
    cursor,
    nextCursor,
    rows: pageRows,
  });
});

// ── Public API ────────────────────────────────────────────────────────────────
// Single endpoint answering "which stable should I install right now?".
//
// score:       Install Confidence 0–10 (higher = stronger install confidence under current audit gates). null when 'wait'.
// band:        solid | ok | caution | weak | skip | wait
// status:      eligible | skip-cve | skip-hotfix | wait
// recommended: true for the single newest release that passed all gates and scores
//              at or above the recommendation threshold.
// reason:      short human explanation of the verdict.
// sentiment / severity / scope / hasWorkaround / confidence: per-issue LLM context.
//
// The score is NOT issue-volume based (that is confounded by how long/popular a
// release was). It comes from age/cadence-invariant signals: known CVEs, settle
// age, hotfix succession, stable-to-stable survival, beta shakeout depth, and the
// serious-bug close/open balance during the release's reign. See lib/score.ts.
//
// Data refreshes on a configurable interval (REFRESH_MINUTES). scoredAt = last time
// the score was computed for this specific release.

const PUBLIC_PAYLOAD_SCHEMA_VERSION = 2;
const PUBLIC_RELEASE_SCHEMA_VERSION = 2;

function publicCacheKey(
  freshness = releaseScoreAuditFreshness(),
  sourceFreshness = dataFreshnessCacheDigest(),
  releaseFreshness = publicReleaseRowsFreshness(config.limits.releases),
  issueSummaryFreshness = publicIssueSummaryFreshness(config.limits.releases),
): string {
  return [
    PUBLIC_PAYLOAD_SCHEMA_VERSION,
    releaseFreshness.max_scored_at ?? '',
    releaseFreshness.count,
    releaseFreshness.digest,
    freshness.max_scored_at ?? '',
    freshness.count,
    freshness.digest,
    sourceFreshness.max_ts ?? '',
    sourceFreshness.count,
    sourceFreshness.digest,
    issueSummaryFreshness.max_ts ?? '',
    issueSummaryFreshness.count,
    issueSummaryFreshness.digest,
  ].join(':');
}

function buildPublicPayload() {
  const { processLastRefreshAt } = getRefreshState();
  const lastScoredAt = getLastScoredAt();
  // Only the focused window (config.limits.releases, default 10) carries full
  // evidence + My-install scoring. The chart still plots SCORE_HISTORY_CHART_LIMIT
  // (20) points, but releases 11–20 are frozen rows from past runs: on the client
  // they have no /public detail, so My-install falls back to their stored global
  // score — comparative trend context only, not re-filtered per profile.
  const allReleases = listReleasesDb(config.limits.releases);

  const releases = allReleases.map((r) => {
    const audit = getReleaseScoreAudit(r.tag);
    const auditSummary = scoreAuditSummary(audit);
    const labelCutoff = releaseLabelCutoff(r, audit?.scored_at ?? null);
    const all = issuesForVersion(r.tag);
    const { topIssues, watchIssues } = publicIssueSummariesForRelease({
      issues: all,
      openedIssues: openedDuringReign(r.tag),
      labelCutoff,
    });

    return {
      schemaVersion:     PUBLIC_RELEASE_SCHEMA_VERSION,
      tag:               r.tag,
      publishedAt:       r.published_at,
      url:               r.html_url,
      score:             r.final_score,
      band:              bandFor(r.final_score, (r.state ?? 'eligible') as InstallStatus),
      status:            r.state,
      recommended:       r.recommended === 1,
      reason:            r.score_reason,
      negativeIssues:    r.negative_issues ?? 0,
      positiveIssues:    r.positive_issues ?? 0,
      scoredAt:          r.scored_at,
      scoreAudit:        auditSummary,
      explanation:       scoreExplanation(audit),
      dataFreshness:     freshnessForRelease(r, audit),
      auditLinks:        releaseAuditLinks(r.tag),
      totalAttributedIssues: all.length,
      issues:            topIssues,
      watchIssues,
    };
  });

  return {
    schemaVersion: PUBLIC_PAYLOAD_SCHEMA_VERSION,
    repo:      `${config.github.owner}/${config.github.repo}`,
    updatedAt: lastScoredAt ?? processLastRefreshAt,
    releases,
  };
}

api.get('/public', (_req, res) => {
  const cacheKey = publicCacheKey();
  const hit = getCached(cacheKey);
  if (hit) { res.json(hit); return; }
  const data = buildPublicPayload();
  setCached(data, cacheKey);
  res.json(data);
});
