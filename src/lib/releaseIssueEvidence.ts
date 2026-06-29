import type { IssueClassification } from './llm';
import { releaseLabelCutoff } from './labelCutoff';
import {
  explainOpenDebtLoad,
  feltSignalMask,
  type DebtEvidenceItem,
} from './score';
import {
  classifyIssueRowWithLabels,
  safeParseLabels,
} from './releaseScoring';
import {
  getRelease,
  getReleaseScoreAudit,
  issueLabelEventCount,
  issueLabelSnapshotCountAt,
  issuesForVersion,
  labelsForIssueAt,
  openedDuringReign,
  unclassifiedIssuesForVersion,
  unverifiedClosedForRelease,
  verifiedFixedForRelease,
  type JoinedIssue,
} from './db';

export const RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION = 1;
const UNCLASSIFIED_ISSUE_AUDIT_LIMIT = 1_000_000;

export const RELEASE_ISSUE_EVIDENCE_TIERS = [
  'verifiedDebt',
  'carryoverDebt',
  'staleDebt',
  'openedFeltSerious',
  'verifiedFixed',
  'unverifiedClosed',
  'unclassifiedIssues',
] as const;

export type ReleaseIssueEvidenceTier = (typeof RELEASE_ISSUE_EVIDENCE_TIERS)[number];

export const RELEASE_ISSUE_EVIDENCE_TIER_INFO: Record<ReleaseIssueEvidenceTier, {
  label: string;
  description: string;
}> = {
  verifiedDebt: {
    label: 'Field blocker debt',
    description: 'Release-local field/community-confirmed blocker evidence that counts as hard open debt.',
  },
  carryoverDebt: {
    label: 'Open inherited/source risk',
    description: 'Open negative issues attributed to this release, but not proven release-local field blockers.',
  },
  staleDebt: {
    label: 'Stale or weak evidence',
    description: 'Open negative issues with stale, needs-info, low-confidence, low-severity, docs, or otherwise weak evidence.',
  },
  openedFeltSerious: {
    label: 'Opened field-visible reports',
    description: 'Field-visible high/critical reports opened during this release window.',
  },
  verifiedFixed: {
    label: 'Verified release fixes',
    description: 'Closed issues credited as fixed by code proof reachable from this release tag.',
  },
  unverifiedClosed: {
    label: 'Unverified closed issues',
    description: 'Closed release-window issues that do not receive direct release-fix credit.',
  },
  unclassifiedIssues: {
    label: 'Unclassified attributed issues',
    description: 'Attributed issues missing current classification rows.',
  },
};

type LabelSource = 'current' | 'timeline' | 'snapshot' | 'missing_timeline';

interface LabelInfo {
  labels: string[];
  currentLabels: string[];
  timelineEventCount: number;
  source: LabelSource;
}

interface ClassifiedIssueSummary {
  number: number;
  title: string;
  url: string | null;
  state: string;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  author: string | null;
  authorAssociation: string | null;
  isBot: boolean;
  comments: number;
  uniqueHumanCommenters: number;
  maintainerCommenters: number;
  contributorCommenters: number;
  commenterScanTruncated: boolean;
  reactionTotal: number;
  positiveReactions: number;
  labels: string[];
  currentLabels: string[];
  labelSource: LabelSource;
  labelTimelineEventCount: number;
  labelSnapshotCount: number;
  labelCutoffAt: string | null;
  rawClassification: IssueClassification;
  classification: IssueClassification;
  classificationDiff: Record<string, { raw: unknown; effective: unknown }>;
}

interface MissingIssueSummary {
  number: number | null;
  title: string;
  url: null;
  state: null;
  createdAt: null;
  updatedAt: null;
  closedAt: null;
  author: null;
  comments: null;
  labels: string[];
  missing: true;
}

export interface ReleaseIssueEvidenceRow {
  tier: ReleaseIssueEvidenceTier;
  tierLabel: string;
  tierDescription: string;
  issue: ClassifiedIssueSummary | ReturnType<typeof unclassifiedIssueSummary> | MissingIssueSummary;
  weight?: number | null;
  duplicateCluster?: string | null;
  humanReporterCount?: number | null;
  commentCount?: number | null;
  fieldConfirmed?: boolean | null;
  humanCommenterCount?: number | null;
  maintainerCommenterCount?: number | null;
  contributorCommenterCount?: number | null;
  reactionTotal?: number | null;
  positiveReactionCount?: number | null;
  commenterScanTruncated?: boolean | null;
  installImpactClass?: string | null;
  installImpactMultiplier?: number | null;
  clusterReleaseLocal?: boolean | null;
}

export interface ReleaseIssueEvidenceTierSummary {
  count: number;
  weight: number;
  fieldConfirmedCount: number;
  openCount: number;
  closedCount: number;
  otherStateCount: number;
  missingIssueCount: number;
  byInstallImpactClass: Record<string, number>;
  weightByInstallImpactClass: Record<string, number>;
}

export interface ReleaseIssueEvidenceResult {
  schemaVersion: typeof RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION;
  tag: string;
  labelCutoffAt: string | null;
  countsByTier: Record<ReleaseIssueEvidenceTier, number>;
  summaryByTier: Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary>;
  tierInfo: typeof RELEASE_ISSUE_EVIDENCE_TIER_INFO;
  rows: ReleaseIssueEvidenceRow[];
}

export function releaseIssueEvidenceRows(tag: string): ReleaseIssueEvidenceResult | null {
  const release = getRelease(tag);
  if (!release) return null;
  const audit = getReleaseScoreAudit(tag);
  const labelCutoff = releaseLabelCutoff(release, audit?.scored_at ?? null);
  const labelInfoByIssue = new Map<number, LabelInfo>();
  const labelInfo = (row: JoinedIssue): LabelInfo => {
    const cached = labelInfoByIssue.get(row.number);
    if (cached) return cached;
    const currentLabels = safeParseLabels(row.labels);
    const timelineEventCount = issueLabelEventCount(row.number);
    const labelSnapshotCount = issueLabelSnapshotCountAt(row.number, labelCutoff);
    const labels = labelsForIssueAt(row.number, currentLabels, labelCutoff, {
      useFallbackWhenNoEvents: labelCutoff == null,
      useSnapshotWhenNoEvents: labelCutoff != null,
    });
    const source: LabelSource = labelCutoff == null
      ? 'current'
      : timelineEventCount > 0
        ? 'timeline'
        : labelSnapshotCount > 0
          ? 'snapshot'
          : 'missing_timeline';
    const info = { labels, currentLabels, timelineEventCount, source };
    labelInfoByIssue.set(row.number, info);
    return info;
  };
  const classify = (row: JoinedIssue): IssueClassification =>
    classifyIssueRowWithLabels(row, labelInfo(row).labels);
  const feltInput = (row: JoinedIssue) => ({
    ...classify(row),
    issueNumber: row.number,
    title: row.title,
    duplicateCluster: row.duplicate_cluster,
    author: row.author,
    authorAssociation: row.author_association,
    isBot: row.is_bot,
    comments: row.comments,
    uniqueHumanCommenterCount: row.unique_human_commenters,
    maintainerCommenterCount: row.maintainer_commenters,
    contributorCommenterCount: row.contributor_commenters,
    commenterScanTruncated: row.commenter_scan_truncated,
    reactionTotal: row.reaction_total,
    positiveReactionCount: row.positive_reactions,
    labels: labelInfo(row).labels,
  });

  const attributed = issuesForVersion(tag);
  const issueByNumber = new Map<number, JoinedIssue>();
  const remember = (rows: JoinedIssue[]) => rows.forEach((row) => issueByNumber.set(row.number, row));
  const opened = openedDuringReign(tag);
  const verifiedFixed = verifiedFixedForRelease(tag);
  const unverifiedClosed = unverifiedClosedForRelease(tag);
  remember(attributed);
  remember(opened);
  remember(verifiedFixed);
  remember(unverifiedClosed);

  const verifiedFixedNumbers = new Set(verifiedFixed.map((row) => row.number));
  const scoreStateForIssue = (row: JoinedIssue): string =>
    verifiedFixedNumbers.has(row.number) ? 'closed' : row.state === 'open' ? 'open' : 'closed-unverified';
  const debtInputs = attributed.map((row) => ({
    ...feltInput(row),
    issueNumber: row.number,
    state: scoreStateForIssue(row),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    affectsVersion: row.affects_version,
    releaseLocal: release.published_at ? Date.parse(row.created_at) >= Date.parse(release.published_at) : false,
  }));
  const debt = explainOpenDebtLoad(debtInputs);
  const openedMask = feltSignalMask(opened.map(feltInput));
  const openedFeltRows = opened.filter((_, index) => openedMask[index]);

  const rows: ReleaseIssueEvidenceRow[] = [
    ...debt.evidence.map((item) => debtEvidenceRow(item, issueByNumber, labelInfo, labelCutoff)),
    ...openedFeltRows.map((issue) => withTierInfo({ tier: 'openedFeltSerious' as const, issue: classifiedIssueSummary(issue, labelInfo, labelCutoff) })),
    ...verifiedFixed.map((issue) => withTierInfo({ tier: 'verifiedFixed' as const, issue: classifiedIssueSummary(issue, labelInfo, labelCutoff) })),
    ...unverifiedClosed.map((issue) => withTierInfo({ tier: 'unverifiedClosed' as const, issue: classifiedIssueSummary(issue, labelInfo, labelCutoff) })),
    ...unclassifiedIssuesForVersion(tag, UNCLASSIFIED_ISSUE_AUDIT_LIMIT).map((issue) => withTierInfo({
      tier: 'unclassifiedIssues' as const,
      issue: unclassifiedIssueSummary(issue),
    })),
  ];
  return {
    schemaVersion: RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
    tag,
    labelCutoffAt: labelCutoff,
    countsByTier: countByTier(rows),
    summaryByTier: summarizeByTier(rows),
    tierInfo: RELEASE_ISSUE_EVIDENCE_TIER_INFO,
    rows,
  };
}

function withTierInfo<T extends { tier: ReleaseIssueEvidenceTier }>(row: T): T & {
  tierLabel: string;
  tierDescription: string;
} {
  const info = RELEASE_ISSUE_EVIDENCE_TIER_INFO[row.tier];
  return {
    ...row,
    tierLabel: info.label,
    tierDescription: info.description,
  };
}

function debtEvidenceRow(
  item: DebtEvidenceItem,
  issueByNumber: Map<number, JoinedIssue>,
  labelInfo: (row: JoinedIssue) => LabelInfo,
  labelCutoff: string | null,
): ReleaseIssueEvidenceRow {
  const issue = item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined;
  const tier = ({
    verified: 'verifiedDebt',
    carryover: 'carryoverDebt',
    stale: 'staleDebt',
  } as const)[item.tier];
  return {
    tier,
    tierLabel: RELEASE_ISSUE_EVIDENCE_TIER_INFO[tier].label,
    tierDescription: RELEASE_ISSUE_EVIDENCE_TIER_INFO[tier].description,
    issue: issue ? classifiedIssueSummary(issue, labelInfo, labelCutoff) : missingIssueSummary(item.issueNumber),
    weight: item.weight,
    duplicateCluster: item.duplicateCluster ?? null,
    humanReporterCount: item.humanReporterCount ?? null,
    commentCount: item.commentCount ?? null,
    fieldConfirmed: item.fieldConfirmed ?? null,
    humanCommenterCount: item.humanCommenterCount ?? null,
    maintainerCommenterCount: item.maintainerCommenterCount ?? null,
    contributorCommenterCount: item.contributorCommenterCount ?? null,
    reactionTotal: item.reactionTotal ?? null,
    positiveReactionCount: item.positiveReactionCount ?? null,
    commenterScanTruncated: item.commenterScanTruncated ?? null,
    installImpactClass: item.installImpactClass ?? null,
    installImpactMultiplier: item.installImpactMultiplier ?? null,
    clusterReleaseLocal: item.clusterReleaseLocal ?? null,
  };
}

function classifiedIssueSummary(
  row: JoinedIssue,
  labelInfo: (row: JoinedIssue) => LabelInfo,
  labelCutoff: string | null,
): ClassifiedIssueSummary {
  const rawClassification = rawClassificationFromRow(row);
  const classification = classifyIssueRowWithLabels(row, labelInfo(row).labels);
  return {
    number: row.number,
    title: row.title,
    url: row.html_url ?? null,
    state: row.state,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    closedAt: row.closed_at,
    author: row.author ?? null,
    authorAssociation: row.author_association ?? null,
    isBot: row.is_bot === 1,
    comments: row.comments,
    uniqueHumanCommenters: row.unique_human_commenters ?? 0,
    maintainerCommenters: row.maintainer_commenters ?? 0,
    contributorCommenters: row.contributor_commenters ?? 0,
    commenterScanTruncated: row.commenter_scan_truncated === 1,
    reactionTotal: row.reaction_total ?? 0,
    positiveReactions: row.positive_reactions ?? 0,
    labels: labelInfo(row).labels,
    currentLabels: labelInfo(row).currentLabels,
    labelSource: labelInfo(row).source,
    labelTimelineEventCount: labelInfo(row).timelineEventCount,
    labelSnapshotCount: issueLabelSnapshotCountAt(row.number, labelCutoff),
    labelCutoffAt: labelCutoff,
    rawClassification,
    classification,
    classificationDiff: classificationDiff(rawClassification, classification),
  };
}

function unclassifiedIssueSummary(row: {
  number: number;
  title: string;
  html_url: string | null;
  state: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  author: string | null;
  comments: number;
  labels: string;
}) {
  return {
    number: row.number,
    title: row.title,
    url: row.html_url,
    state: row.state,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    closedAt: row.closed_at,
    author: row.author,
    comments: row.comments,
    labels: safeParseLabels(row.labels),
  };
}

function missingIssueSummary(issueNumber: number | undefined) {
  return {
    number: issueNumber ?? null,
    title: 'missing issue row',
    url: null,
    state: null,
    createdAt: null,
    updatedAt: null,
    closedAt: null,
    author: null,
    comments: null,
    labels: [],
    missing: true as const,
  };
}

function rawClassificationFromRow(row: JoinedIssue): IssueClassification {
  const workaroundStatus = ['none', 'partial', 'confirmed', 'unknown'].includes(row.workaround_status)
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
    confidence: row.confidence,
    rationale: row.rationale ?? '',
  };
}

function classificationDiff(
  raw: IssueClassification,
  effective: IssueClassification,
): Record<string, { raw: unknown; effective: unknown }> {
  const out: Record<string, { raw: unknown; effective: unknown }> = {};
  const keys: Array<keyof IssueClassification> = [
    'sentiment',
    'severity',
    'scope',
    'functionality',
    'affectedUsers',
    'workaroundStatus',
    'duplicateCluster',
    'affectsVersion',
    'confidence',
  ];
  for (const key of keys) {
    if (raw[key] !== effective[key]) out[key] = { raw: raw[key], effective: effective[key] };
  }
  return out;
}

function countByTier(rows: ReleaseIssueEvidenceRow[]): Record<ReleaseIssueEvidenceTier, number> {
  const counts = Object.fromEntries(RELEASE_ISSUE_EVIDENCE_TIERS.map((tier) => [tier, 0])) as Record<ReleaseIssueEvidenceTier, number>;
  for (const row of rows) counts[row.tier] += 1;
  return counts;
}

export function summarizeIssueEvidenceRows(rows: ReleaseIssueEvidenceRow[]): ReleaseIssueEvidenceTierSummary {
  const summary = emptyTierSummary();
  for (const row of rows) {
    summary.count += 1;
    const weight = typeof row.weight === 'number' && Number.isFinite(row.weight) ? row.weight : 0;
    summary.weight += weight;
    if (row.fieldConfirmed === true) summary.fieldConfirmedCount += 1;
    if (isMissingIssue(row.issue)) summary.missingIssueCount += 1;
    const state = row.issue?.state;
    if (state === 'open') summary.openCount += 1;
    else if (state === 'closed') summary.closedCount += 1;
    else summary.otherStateCount += 1;
    const impact = typeof row.installImpactClass === 'string' && row.installImpactClass
      ? row.installImpactClass
      : null;
    if (impact) {
      summary.byInstallImpactClass[impact] = (summary.byInstallImpactClass[impact] ?? 0) + 1;
      summary.weightByInstallImpactClass[impact] = (summary.weightByInstallImpactClass[impact] ?? 0) + weight;
    }
  }
  return roundTierSummary(summary);
}

function isMissingIssue(issue: ReleaseIssueEvidenceRow['issue']): issue is MissingIssueSummary {
  return 'missing' in issue && issue.missing === true;
}

function summarizeByTier(rows: ReleaseIssueEvidenceRow[]): Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary> {
  return Object.fromEntries(RELEASE_ISSUE_EVIDENCE_TIERS.map((tier) => [
    tier,
    summarizeIssueEvidenceRows(rows.filter((row) => row.tier === tier)),
  ])) as Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary>;
}

function emptyTierSummary(): ReleaseIssueEvidenceTierSummary {
  return {
    count: 0,
    weight: 0,
    fieldConfirmedCount: 0,
    openCount: 0,
    closedCount: 0,
    otherStateCount: 0,
    missingIssueCount: 0,
    byInstallImpactClass: {},
    weightByInstallImpactClass: {},
  };
}

function roundTierSummary(summary: ReleaseIssueEvidenceTierSummary): ReleaseIssueEvidenceTierSummary {
  return {
    ...summary,
    weight: roundMetric(summary.weight),
    weightByInstallImpactClass: Object.fromEntries(Object.entries(summary.weightByInstallImpactClass)
      .map(([key, value]) => [key, roundMetric(value)])),
  };
}

function roundMetric(value: number): number {
  return Math.round(value * 1000) / 1000;
}
