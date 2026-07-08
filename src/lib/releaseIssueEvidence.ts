import type {
  IssueClassification,
  IssueClassificationProvenance,
} from './llm';
import {
  labelAuthorizedForScoring,
  type LabelOverrideAuthority,
} from './labelOverrides';
import { releaseLabelCutoff } from './labelCutoff';
import {
  applyExclusiveIssueRiskLedger,
  explainOpenDebtLoad,
  explainFeltLoad,
  semanticHumanConfirmationReasons,
  type ConfirmationReason,
  type DebtEvidenceItem,
  type ReleaseLocalEvidence,
} from './score';
import {
  classifyIssueRowForOpenDebtWithLabels,
  classifyIssueRowWithLabels,
  exactReleaseLocalEvidence,
  issueFieldEvidence,
  releaseLinkedIssueRows,
  releaseScopedDebtState,
  safeParseLabels,
} from './releaseScoring';
import {
  createReleaseClosureAuthorityEvaluation,
  createReleaseClosureAuthorityEvaluationForRun,
  type ReleaseClosureAuthorityEvaluation,
} from './closureClaimAuthorityEvaluation';
import { scoringLabelInfoAtCutoff } from './scoringLabelAuthority';
import {
  closureRiskWeightForRow,
} from './closureProofPayload';
import {
  aggregateClosureRisk,
  buildIssueAliasGroups,
  canonicalIssueNumbersFromEvidence,
  type AggregatedClosureRisk,
} from './closureRiskAggregation';
import {
  closedBeforeReleaseCommentCandidates,
  closureProofRows,
  compactIssueCommentEvidence,
  db,
  getRelease,
  getReleaseScoreAudit,
  issuesForVersion,
  latestIssueLabelEventAt,
  openedDuringReign,
  scoreSourceIdentityCacheKey,
  unclassifiedIssuesForVersion,
  unverifiedClosedForRelease,
  verifiedFixedForRelease,
  type JoinedIssue,
  type ReleaseAttributionCandidateRow,
  type ReleaseFixCreditDecision,
} from './db';

export const RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION = 2;
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

export const RELEASE_ISSUE_EVIDENCE_IMPACT_CLASSES = [
  'security',
  'provider',
  'message_delivery',
  'state_data',
  'general',
] as const;

export type ReleaseIssueEvidenceImpactClass = (typeof RELEASE_ISSUE_EVIDENCE_IMPACT_CLASSES)[number];

export const RELEASE_ISSUE_EVIDENCE_TIER_INFO: Record<ReleaseIssueEvidenceTier, {
  label: string;
  description: string;
}> = {
  verifiedDebt: {
    label: 'Field blocker debt',
    description: 'Release-local field/community-confirmed blocker evidence that counts as hard open debt.',
  },
  carryoverDebt: {
    label: 'Inherited issue context',
    description: 'Inherited issue groups linked to this release for audit context only; they have zero score impact and cannot apply a score ceiling.',
  },
  staleDebt: {
    label: 'Weak or stale evidence',
    description: 'Open negative issues with source/static-only, unconfirmed, stale, needs-info, low-confidence, low-severity, docs, or otherwise weak evidence.',
  },
  openedFeltSerious: {
    label: 'Counted opened high-impact reports',
    description: 'Exclusive deduplicated high/critical opened-report groups that contribute regression penalty.',
  },
  verifiedFixed: {
    label: 'Contained release fixes',
    description: 'Closed issues with fix proof contained in this tag; only first-containing fixes receive regression credit.',
  },
  unverifiedClosed: {
    label: 'Closed issues without release-fix credit',
    description: 'Closed release-window issues that do not receive direct release-fix credit.',
  },
  unclassifiedIssues: {
    label: 'Unclassified attributed issues',
    description: 'Attributed issues missing current classification rows.',
  },
};

type LabelSource = 'current' | 'timeline' | 'snapshot' | 'missing_timeline';

export interface BatchedIssueLabelInfo {
  labels: string[];
  currentLabels: string[];
  timelineEventCount: number;
  labelSnapshotCount: number;
  source: LabelSource;
}

type LabelInfo = BatchedIssueLabelInfo;
type ResolvedLabelInfo = LabelInfo & {
  authority: LabelOverrideAuthority;
};

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
  classificationOrigin: string;
  rawModelOutput: string | null;
  classificationProvenance: IssueClassificationProvenance | null;
  classifierSourceIdentity: Record<string, unknown> | null;
  classifierSourceIdentityDigest: string | null;
  classificationPromptVersion: number;
  classifiedAt: string;
  classifiedUpdatedAt: string;
  classifiedCommentsDigest: string | null;
  storedClassification: IssueClassification;
  rawClassification: IssueClassification | null;
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
  aliasGroup?: string | null;
  adversePoints?: number | null;
  humanReporterCount?: number | null;
  commentCount?: number | null;
  fieldConfirmed?: boolean | null;
  confirmationReasons?: DebtEvidenceItem['confirmationReasons'];
  humanCommenterCount?: number | null;
  maintainerCommenterCount?: number | null;
  contributorCommenterCount?: number | null;
  reactionTotal?: number | null;
  positiveReactionCount?: number | null;
  commenterScanTruncated?: boolean | null;
  installImpactClass?: string | null;
  installImpactMultiplier?: number | null;
  clusterReleaseLocal?: boolean | null;
  releaseLocalEvidence?: ReleaseLocalEvidence | null;
  debtClassification?: IssueClassification | null;
  debtClassificationDiff?: Record<string, { raw: unknown; effective: unknown }> | null;
  fixCreditDecision?: ReleaseFixCreditDecision | null;
  scoreAffecting?: boolean;
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

export interface ReleaseIssueEvidencePageOptions {
  cursor: number;
  limit: number;
  summaryOnly: boolean;
  matches: (row: ReleaseIssueEvidenceRow) => boolean;
  sortValue: (row: ReleaseIssueEvidenceRow, rank: number) => number | null;
  direction: 'asc' | 'desc';
}

export interface ReleaseIssueEvidencePageResult {
  schemaVersion: typeof RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION;
  tag: string;
  labelCutoffAt: string | null;
  countsByTier: Record<ReleaseIssueEvidenceTier, number>;
  summaryByTier: Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary>;
  filteredCountsByTier: Record<ReleaseIssueEvidenceTier, number>;
  filteredSummaryByTier: Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary>;
  filteredSummary: ReleaseIssueEvidenceTierSummary;
  tierInfo: typeof RELEASE_ISSUE_EVIDENCE_TIER_INFO;
  totals: {
    unfilteredRows: number;
    filteredRows: number;
    unfilteredDistinctIssues: number;
    filteredDistinctIssues: number;
  };
  rows: ReleaseIssueEvidenceRow[];
  nextCursor: number | null;
}

const RELEASE_PROFILE_EVIDENCE_TIERS = [
  'verifiedDebt',
  'carryoverDebt',
  'staleDebt',
  'openedFeltSerious',
  'unverifiedClosed',
] as const;

export type ReleaseProfileEvidenceTier = (typeof RELEASE_PROFILE_EVIDENCE_TIERS)[number];

export interface ReleaseProfileEvidenceRow {
  issueNumber: number;
  title: string;
  state: string;
  tier: ReleaseProfileEvidenceTier;
  weight: number;
}

type ReleaseProfileEvidenceCandidate = ReleaseProfileEvidenceRow & {
  aliasGroup: string;
};

export interface ReleaseProfileEvidenceResult {
  schemaVersion: typeof RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION;
  tag: string;
  rows: ReleaseProfileEvidenceRow[];
}

export interface ReleaseProfileEvidenceSourceRows {
  attributed: JoinedIssue[];
  opened: JoinedIssue[];
  commentEvidenceCache?: ReleaseProfileCommentEvidenceCache;
  closureAuthority?: ReleaseClosureAuthorityEvaluation;
}

interface CompactProfileCommentEvidence {
  confirmations: Array<{
    reason: ConfirmationReason;
    updatedAt: string | null;
  }>;
  releaseEvidence: Map<string, Array<{
    evidence: NonNullable<ReturnType<typeof exactReleaseLocalEvidence>>;
    createdAt: string | null;
    updatedAt: string | null;
  }>>;
  complete: boolean;
}

export interface ReleaseProfileCommentEvidenceCache {
  releaseTags: string[];
  releasePublishedAtByTag: Map<string, string | null>;
  byIssue: Map<number, CompactProfileCommentEvidence>;
}

export function createReleaseProfileCommentEvidenceCache(
  releaseTags: string[],
): ReleaseProfileCommentEvidenceCache {
  return {
    releaseTags: [...new Set(releaseTags)],
    releasePublishedAtByTag: new Map(
      [...new Set(releaseTags)].map((tag) => [tag, getRelease(tag)?.published_at ?? null]),
    ),
    byIssue: new Map(),
  };
}

interface ReleaseEvidenceComputation {
  tag: string;
  labelCutoff: string | null;
  labelInfo: (row: JoinedIssue) => ResolvedLabelInfo;
  classify: (row: JoinedIssue) => IssueClassification;
  opened: JoinedIssue[];
  verifiedFixed: JoinedIssue[];
  unverifiedClosed: JoinedIssue[];
  issueByNumber: Map<number, JoinedIssue>;
  debt: ReturnType<typeof explainOpenDebtLoad>;
  openedAnalysis: ReturnType<typeof explainFeltLoad>;
  closureRisk: AggregatedClosureRisk;
  fixCreditDecisionByIssue: Map<number, ReleaseFixCreditDecision>;
}

let pageComputationCache: {
  epoch: string;
  tag: string;
  value: ReleaseEvidenceComputation | null;
} | null = null;

export function releaseIssueEvidenceRows(tag: string): ReleaseIssueEvidenceResult | null {
  const computation = releaseEvidenceComputation(tag);
  if (!computation) return null;
  const rows = [...releaseIssueEvidenceRowIterator(computation)];
  return {
    schemaVersion: RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
    tag,
    labelCutoffAt: computation.labelCutoff,
    countsByTier: countByTier(rows),
    summaryByTier: summarizeByTier(rows),
    tierInfo: RELEASE_ISSUE_EVIDENCE_TIER_INFO,
    rows,
  };
}

export function releaseIssueEvidencePage(
  tag: string,
  options: ReleaseIssueEvidencePageOptions,
): ReleaseIssueEvidencePageResult | null {
  const computation = releaseEvidenceComputationForPage(tag);
  if (!computation) return null;

  const unfilteredCountsByTier = emptyCountsByTier();
  const filteredCountsByTier = emptyCountsByTier();
  const unfilteredSummaryByTier = emptySummaryByTier();
  const filteredSummaryByTier = emptySummaryByTier();
  const filteredSummary = emptyTierSummary();
  const unfilteredIssueNumbers = new Set<number>();
  const filteredIssueNumbers = new Set<number>();
  const sortEntries: Array<{ rank: number; value: number | null }> = [];
  let unfilteredRows = 0;
  let filteredRows = 0;

  for (const row of releaseIssueEvidenceRowIterator(computation, false)) {
    const rank = unfilteredRows++;
    unfilteredCountsByTier[row.tier] += 1;
    addRowToSummary(unfilteredSummaryByTier[row.tier], row);
    rememberIssueNumber(unfilteredIssueNumbers, row);
    if (!options.matches(row)) continue;

    filteredRows++;
    filteredCountsByTier[row.tier] += 1;
    addRowToSummary(filteredSummaryByTier[row.tier], row);
    addRowToSummary(filteredSummary, row);
    rememberIssueNumber(filteredIssueNumbers, row);
    if (!options.summaryOnly) {
      sortEntries.push({ rank, value: options.sortValue(row, rank) });
    }
  }

  let rows: ReleaseIssueEvidenceRow[] = [];
  if (!options.summaryOnly && sortEntries.length) {
    sortEntries.sort((left, right) => compareSortEntries(left, right, options.direction));
    const selectedRanks = new Map(
      sortEntries
        .slice(options.cursor, options.cursor + options.limit)
        .map((entry, pageIndex) => [entry.rank, pageIndex]),
    );
    if (selectedRanks.size) {
      const selectedRows = new Array<ReleaseIssueEvidenceRow>(selectedRanks.size);
      let rank = 0;
      for (const row of releaseIssueEvidenceRowIterator(computation, true)) {
        const pageIndex = selectedRanks.get(rank++);
        if (pageIndex != null) selectedRows[pageIndex] = row;
      }
      rows = selectedRows;
    }
  }

  return {
    schemaVersion: RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
    tag,
    labelCutoffAt: computation.labelCutoff,
    countsByTier: unfilteredCountsByTier,
    summaryByTier: finalizeSummaryByTier(unfilteredSummaryByTier),
    filteredCountsByTier,
    filteredSummaryByTier: finalizeSummaryByTier(filteredSummaryByTier),
    filteredSummary: roundTierSummary(filteredSummary),
    tierInfo: RELEASE_ISSUE_EVIDENCE_TIER_INFO,
    totals: {
      unfilteredRows,
      filteredRows,
      unfilteredDistinctIssues: unfilteredIssueNumbers.size,
      filteredDistinctIssues: filteredIssueNumbers.size,
    },
    rows,
    nextCursor: options.summaryOnly || options.cursor + rows.length >= filteredRows
      ? null
      : options.cursor + rows.length,
  };
}

function releaseEvidenceComputationForPage(
  tag: string,
): ReleaseEvidenceComputation | null {
  const epoch = scoreSourceIdentityCacheKey();
  if (
    pageComputationCache?.epoch === epoch &&
    pageComputationCache.tag === tag
  ) {
    return pageComputationCache.value;
  }
  const value = releaseEvidenceComputation(tag);
  pageComputationCache = { epoch, tag, value };
  return value;
}

export function releaseProfileEvidenceRows(
  tag: string,
  sourceRows?: ReleaseProfileEvidenceSourceRows,
): ReleaseProfileEvidenceResult | null {
  const computation = releaseEvidenceComputation(tag, sourceRows);
  if (!computation) return null;
  const {
    classify,
    opened,
    issueByNumber,
    debt,
    openedAnalysis,
    closureRisk,
  } = computation;
  const candidates: ReleaseProfileEvidenceCandidate[] = [];

  for (const item of debt.evidence) {
    const issue = item.issueNumber ? issueByNumber.get(item.issueNumber) : null;
    const tier = ({
      verified: 'verifiedDebt',
      carryover: 'carryoverDebt',
      stale: 'staleDebt',
    } as const)[item.tier];
    if (!issue || !tier) continue;
    rememberProfileCandidate(candidates, issue, tier, item.weight, classify(issue), item.aliasGroup);
  }

  for (let index = 0; index < opened.length; index++) {
    if (openedAnalysis.evidence[index]?.counted !== true) continue;
    rememberProfileCandidate(
      candidates,
      opened[index],
      'openedFeltSerious',
      openedAnalysis.evidence[index]?.countedWeight ?? 0,
      classify(opened[index]),
      openedAnalysis.evidence[index]?.aliasGroup,
    );
  }

  for (const group of closureRisk.groups) {
    const issue = issueByNumber.get(group.issueNumber);
    if (!issue) continue;
    rememberProfileCandidate(
      candidates,
      issue,
      'unverifiedClosed',
      group.weight,
      classify(issue),
      group.key,
    );
  }

  const byAliasGroup = new Map<string, ReleaseProfileEvidenceCandidate>();
  for (const candidate of candidates) {
    const aliasGroup = candidate.aliasGroup;
    const current = byAliasGroup.get(aliasGroup);
    if (!current || profileCandidatePrecedes(candidate, current)) {
      byAliasGroup.set(aliasGroup, candidate);
    }
  }
  return {
    schemaVersion: RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
    tag,
    rows: [...byAliasGroup.values()]
      .map(({ aliasGroup: _aliasGroup, ...row }) => row)
      .sort((a, b) => a.issueNumber - b.issueNumber),
  };
}

function releaseEvidenceComputation(
  tag: string,
  sourceRows?: ReleaseProfileEvidenceSourceRows,
): ReleaseEvidenceComputation | null {
  const release = getRelease(tag);
  if (!release) return null;
  const audit = getReleaseScoreAudit(tag);
  const labelCutoff = releaseLabelCutoff(release, audit?.scored_at ?? null);
  const persistedEvidence = persistedReleaseIssueEvidence(
    audit?.issue_evidence_json,
    audit?.gate_evidence_json,
    tag,
  );

  const intervalAttributed = sourceRows?.attributed ?? issuesForVersion(tag);
  const attributed = [
    ...intervalAttributed,
    ...persistedTargetAttributionRows(
      tag,
      persistedEvidence.targetEvidenceByIssue,
      intervalAttributed,
    ),
  ];
  const issueByNumber = new Map<number, JoinedIssue>();
  const remember = (rows: JoinedIssue[]) => rows.forEach((row) => issueByNumber.set(row.number, row));
  const openedDuringWindow = sourceRows?.opened ?? openedDuringReign(tag);
  const rawVerifiedFixed = verifiedFixedForRelease(tag);
  const rawUnverifiedClosed = unverifiedClosedForRelease(tag);
  const releaseClosureProofs = closureProofRows(tag);
  const closureAuthority =
    sourceRows?.closureAuthority ??
    (
      audit?.authority_run_id
        ? createReleaseClosureAuthorityEvaluationForRun(
            audit.authority_run_id,
          )
        : createReleaseClosureAuthorityEvaluation()
    );
  remember(attributed);
  remember(openedDuringWindow);
  remember(rawVerifiedFixed);
  remember(rawUnverifiedClosed);
  const rawClosureRiskCandidateRows = releaseClosureProofs;
  const labelInfoByIssue = batchIssueLabelInfo(
    [...issueByNumber.values()],
    labelCutoff,
    releaseClosureProofs.map((row) => ({
      number: row.issue_number,
      labels: row.labels,
    })),
  );
  const resolvedLabelInfoByIssue = new Map<number, ResolvedLabelInfo>();
  const labelInfo = (row: JoinedIssue): ResolvedLabelInfo => {
    const cached = resolvedLabelInfoByIssue.get(row.number);
    if (cached) return cached;
    const info = labelInfoByIssue.get(row.number) ?? fallbackLabelInfo(row, labelCutoff);
    const resolved = scoringLabelInfoAtCutoff(row.number, info.labels, labelCutoff);
    const value = {
      ...info,
      labels: resolved.labels,
      authority: {
        labelActors: resolved.labelActors,
        authorizedScoringLabels: resolved.authorizedScoringLabels,
        authorityReferences: resolved.authorityReferences,
      },
    };
    resolvedLabelInfoByIssue.set(row.number, value);
    return value;
  };
  const classify = (row: JoinedIssue): IssueClassification =>
    classifyIssueRowWithLabels(
      row,
      labelInfo(row).labels,
      labelInfo(row).authority,
    );
  const classifyDebt = (row: JoinedIssue): IssueClassification =>
    classifyIssueRowForOpenDebtWithLabels(
      row,
      labelInfo(row).labels,
      labelInfo(row).authority,
    );
  type CompactFieldEvidence = Omit<
    ReturnType<typeof issueFieldEvidence>,
    'commentsAtCutoff'
  > & {
    releaseLocalEvidence: ReturnType<typeof exactReleaseLocalEvidence>;
    releaseExplicitlyUnaffected: boolean;
  };
  const fieldEvidenceByIssue = new Map<number, CompactFieldEvidence>();
  if (sourceRows?.commentEvidenceCache) {
    primeProfileCommentEvidenceCache(
      [...issueByNumber.values()],
      sourceRows.commentEvidenceCache,
    );
  }
  const fieldEvidence = (row: JoinedIssue) => {
    const cached = fieldEvidenceByIssue.get(row.number);
    if (cached) return cached;
    if (sourceRows?.commentEvidenceCache) {
      const computed = compactProfileFieldEvidence(
        row,
        tag,
        labelInfo(row).labels,
        labelCutoff,
        labelInfo(row).authority,
        sourceRows.commentEvidenceCache,
        closureAuthority,
      );
      const compact = {
        ...computed,
        releaseLocalEvidence: computed.releaseExplicitlyUnaffected
          ? null
          : computed.releaseLocalEvidence ??
            persistedEvidence.targetEvidenceByIssue.get(row.number) ??
            null,
      };
      fieldEvidenceByIssue.set(row.number, compact);
      return compact;
    }
    const evidence = issueFieldEvidence(
      row,
      labelInfo(row).labels,
      labelCutoff,
      {
        requireCompleteComments: false,
        labelAuthority: labelInfo(row).authority,
        authorityReferenceForEvent: (eventId) =>
          Object.values(
            labelInfo(row).authority.authorityReferences ?? {},
          ).find((reference) => reference?.subjectIdentity === eventId) ?? null,
      },
    );
    const { commentsAtCutoff, ...summary } = evidence;
    const explicitlyUnaffected = closureAuthority.releaseExplicitlyUnaffected(
      row.number,
      tag,
    );
    const releaseLocalEvidence = explicitlyUnaffected
      ? null
      : exactReleaseLocalEvidence(
          row,
          tag,
          commentsAtCutoff,
          release.published_at,
          (commentNodeId) =>
            summary.confirmationReasons.find((reason) =>
              reason.source === 'comment' &&
              reason.commentNodeId === commentNodeId
            )?.authorityReference ?? null,
        ) ??
        persistedEvidence.targetEvidenceByIssue.get(row.number) ??
        null;
    const compact = {
      ...summary,
      releaseLocalEvidence,
      releaseExplicitlyUnaffected: explicitlyUnaffected,
    };
    fieldEvidenceByIssue.set(row.number, compact);
    return compact;
  };
  const verifiedFixed = rawVerifiedFixed.filter((row) =>
    !fieldEvidence(row).releaseExplicitlyUnaffected);
  const unverifiedClosed = rawUnverifiedClosed.filter((row) =>
    !fieldEvidence(row).releaseExplicitlyUnaffected);
  const closureRiskCandidateRows = rawClosureRiskCandidateRows.filter((row) => {
    const issue = issueByNumber.get(row.issue_number);
    return !issue || !fieldEvidence(issue).releaseExplicitlyUnaffected;
  });
  const closureRiskCandidateNumbers = new Set(
    closureRiskCandidateRows.map((row) => row.issue_number),
  );

  const issueAliasGroups = buildIssueAliasGroups([
    ...[...attributed, ...openedDuringWindow, ...verifiedFixed, ...unverifiedClosed].map((row) => ({
      issueNumber: row.number,
      duplicateCluster: row.duplicate_cluster,
    })),
    ...releaseClosureProofs.map((row) => ({
      issueNumber: row.issue_number,
      duplicateCluster: row.duplicate_cluster,
      canonicalIssueNumbers: canonicalIssueNumbersFromEvidence(row.evidence_json),
    })),
  ]);
  const aliasGroupForIssue = (row: { number: number; duplicate_cluster?: string | null }): string =>
    issueAliasGroups.keyFor({
      issueNumber: row.number,
      duplicateCluster: row.duplicate_cluster,
    });
  const feltInput = (row: JoinedIssue) => ({
    ...classify(row),
    humanReporterCount: fieldEvidence(row).humanReporterCount,
    confirmationReasons: fieldEvidence(row).confirmationReasons,
    commentEvidenceComplete: fieldEvidence(row).commentEvidenceComplete,
    issueNumber: row.number,
    issueNodeId: row.node_id,
    title: row.title,
    duplicateCluster: row.duplicate_cluster,
    aliasGroup: aliasGroupForIssue(row),
    author: row.author,
    authorNodeId: row.author_node_id,
    authorType: row.author_type,
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
    releaseLocalEvidence: fieldEvidence(row).releaseLocalEvidence ?? undefined,
  });
  const resolvedForRiskNumbers = new Set(verifiedFixed.map((row) => row.number));
  for (const row of releaseClosureProofs) {
    if (
      !isAdverseClosureRiskDisposition(
        closureAuthority.closureDisposition(row),
      ) ||
      !closureRiskCandidateNumbers.has(row.issue_number)
    ) {
      resolvedForRiskNumbers.add(row.issue_number);
    }
  }
  const releaseClosureProofNumbers = new Set(
    releaseClosureProofs.map((row) => row.issue_number),
  );
  const scoreStateForIssue = (row: JoinedIssue): string =>
    releaseScopedDebtState(row, resolvedForRiskNumbers, releaseClosureProofNumbers);
  const debtInputs = attributed
    .filter((row) => !fieldEvidence(row).releaseExplicitlyUnaffected)
    .map((row) => {
      const baseClassification = classify(row);
      const debtClassification = classifyDebt(row);
      const debtClassificationDiff = classificationDiff(baseClassification, debtClassification);
      const releaseLocalEvidence = fieldEvidence(row).releaseLocalEvidence;
      return {
        ...feltInput(row),
        ...debtClassification,
        issueNumber: row.number,
        state: scoreStateForIssue(row),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        affectsVersion: row.affects_version,
        releaseLocal: releaseLocalEvidence != null,
        ...(releaseLocalEvidence ? { releaseLocalEvidence } : {}),
        ...(Object.keys(debtClassificationDiff).length
          ? { debtClassification, debtClassificationDiff }
        : {}),
      };
    });
  const rawDebt = explainOpenDebtLoad(debtInputs);
  const releaseLinkedOpened = releaseLinkedIssueRows(
    openedDuringWindow.map((row) => ({
      ...row,
      releaseLocalEvidence: fieldEvidence(row).releaseLocalEvidence,
      releaseExplicitlyUnaffected: fieldEvidence(row).releaseExplicitlyUnaffected,
    })),
    tag,
  );
  const proofByIssue = new Map(releaseClosureProofs.map((row) => [row.issue_number, row]));
  const opened = releaseLinkedOpened.filter((row) => {
    if (scoreStateForIssue(row) === 'open') return false;
    const proof = proofByIssue.get(row.number);
    return !proof ||
      isAdverseClosureRiskDisposition(
        closureAuthority.closureDisposition(proof),
      );
  });
  const rawRegression = explainFeltLoad(opened.map(feltInput));
  const rawClosureRisk = aggregateClosureRisk(
    closureRiskCandidateRows.map((row) => {
      const issueRow = { ...row, number: row.issue_number } as unknown as JoinedIssue;
      const classification = classifyDebt(issueRow);
      const canonicalIssueNumbers = canonicalIssueNumbersFromEvidence(row.evidence_json);
      const disposition = closureAuthority.closureDisposition(row);
      return {
        issueNumber: row.issue_number,
        disposition,
        weight: closureRiskWeightForRow({
          status: row.status,
          sentiment: classification.sentiment,
          severity: classification.severity,
          scope: classification.scope,
          functionality: classification.functionality,
          affected_users: classification.affectedUsers,
        }, disposition),
        duplicateCluster: row.duplicate_cluster,
        canonicalIssueNumbers,
        aliasGroup: issueAliasGroups.keyFor({
          issueNumber: row.issue_number,
          duplicateCluster: row.duplicate_cluster,
          canonicalIssueNumbers,
        }),
      };
    }),
  );
  const riskAccounting = applyExclusiveIssueRiskLedger({
    debt: rawDebt,
    regression: rawRegression,
    closureRisk: rawClosureRisk,
  });
  return {
    tag,
    labelCutoff,
    labelInfo,
    classify,
    opened,
    verifiedFixed,
    unverifiedClosed,
    issueByNumber,
    debt: riskAccounting.debt,
    openedAnalysis: riskAccounting.regression,
    closureRisk: riskAccounting.closureRisk,
    fixCreditDecisionByIssue: persistedEvidence.fixCreditDecisionByIssue,
  };
}

interface PersistedReleaseIssueEvidence {
  targetEvidenceByIssue: Map<number, ReleaseLocalEvidence>;
  fixCreditDecisionByIssue: Map<number, ReleaseFixCreditDecision>;
}

function persistedReleaseIssueEvidence(
  issueEvidenceJson: string | null | undefined,
  gateEvidenceJson: string | null | undefined,
  tag: string,
): PersistedReleaseIssueEvidence {
  const targetEvidenceByIssue = new Map<number, ReleaseLocalEvidence>();
  const fixCreditDecisionByIssue = new Map<number, ReleaseFixCreditDecision>();
  const payload = parseJsonRecord(issueEvidenceJson);

  if (Array.isArray(payload?.targetEvidenceAttribution)) {
    for (const value of payload.targetEvidenceAttribution) {
      const row = objectRecord(value);
      const issueNumber = positiveIssueNumber(row?.issueNumber);
      const releaseLocalEvidence = persistedTargetReleaseLocalEvidence(
        row?.releaseLocalEvidence,
        tag,
      );
      if (
        !issueNumber ||
        row?.reasonCode !== 'post_publication_exact_version_human_reproduction' ||
        !releaseLocalEvidence
      ) {
        continue;
      }
      targetEvidenceByIssue.set(issueNumber, releaseLocalEvidence);
    }
  }

  if (Array.isArray(payload?.verifiedFixed)) {
    for (const value of payload.verifiedFixed) {
      const row = objectRecord(value);
      const issueNumber = positiveIssueNumber(
        row?.number ?? objectRecord(row?.issue)?.number,
      );
      if (!issueNumber) continue;
      const decision = persistedFixCreditDecision(
        row?.fixCreditDecision,
        issueNumber,
        tag,
      );
      if (decision) fixCreditDecisionByIssue.set(issueNumber, decision);
    }
  }

  const gatePayload = parseJsonRecord(gateEvidenceJson);
  const fixProvenance = objectRecord(gatePayload?.fixProvenance);
  const releaseFixCredit = objectRecord(fixProvenance?.releaseFixCredit);
  if (
    releaseFixCredit?.schemaVersion === 1 &&
    releaseFixCredit.targetTag === tag &&
    Array.isArray(releaseFixCredit.decisions)
  ) {
    for (const value of releaseFixCredit.decisions) {
      const row = objectRecord(value);
      const issueNumber = positiveIssueNumber(row?.issueNumber);
      if (!issueNumber) continue;
      const decision = persistedFixCreditDecision(
        row,
        issueNumber,
        tag,
      );
      if (decision) fixCreditDecisionByIssue.set(issueNumber, decision);
    }
  }

  return { targetEvidenceByIssue, fixCreditDecisionByIssue };
}

function persistedTargetAttributionRows(
  tag: string,
  targetEvidenceByIssue: ReadonlyMap<number, ReleaseLocalEvidence>,
  attributed: JoinedIssue[],
): JoinedIssue[] {
  if (!targetEvidenceByIssue.size) return [];
  const existing = new Set(attributed.map((row) => row.number));
  return closedBeforeReleaseCommentCandidates(tag)
    .filter(isClassifiedAttributionCandidate)
    .filter((row) =>
      targetEvidenceByIssue.has(row.number) &&
      !existing.has(row.number)
    );
}

function isClassifiedAttributionCandidate(
  row: ReleaseAttributionCandidateRow,
): row is JoinedIssue {
  return row.issue_number === row.number &&
    typeof row.sentiment === 'string' &&
    typeof row.severity === 'string' &&
    typeof row.scope === 'string' &&
    typeof row.functionality === 'string' &&
    typeof row.affected_users === 'string';
}

function persistedTargetReleaseLocalEvidence(
  value: unknown,
  tag: string,
): ReleaseLocalEvidence | null {
  const evidence = objectRecord(value);
  if (
    evidence?.kind !== 'exact-version' ||
    evidence.source !== 'comment' ||
    evidence.version !== tag ||
    typeof evidence.snippet !== 'string' ||
    !evidence.snippet.trim()
  ) {
    return null;
  }
  return evidence as unknown as ReleaseLocalEvidence;
}

function persistedFixCreditDecision(
  value: unknown,
  issueNumber: number,
  tag: string,
): ReleaseFixCreditDecision | null {
  const decision = objectRecord(value);
  if (
    decision?.schemaVersion !== 1 ||
    decision.issueNumber !== issueNumber ||
    !['credited', 'withheld', 'invalid'].includes(String(decision.status)) ||
    typeof decision.reasonCode !== 'string' ||
    !decision.reasonCode ||
    decision.targetTag !== tag ||
    !(
      decision.predecessorTag == null ||
      typeof decision.predecessorTag === 'string'
    ) ||
    !Array.isArray(decision.proofIdentities)
  ) {
    return null;
  }
  return decision as unknown as ReleaseFixCreditDecision;
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function positiveIssueNumber(value: unknown): number | null {
  const issueNumber = Number(value);
  return Number.isInteger(issueNumber) && issueNumber > 0 ? issueNumber : null;
}

function compactProfileFieldEvidence(
  row: JoinedIssue,
  releaseTag: string,
  effectiveLabels: string[],
  cutoff: string | null,
  labelAuthority: LabelOverrideAuthority,
  cache: ReleaseProfileCommentEvidenceCache,
  closureAuthority: ReleaseClosureAuthorityEvaluation,
) {
  let cached = cache.byIssue.get(row.number);
  if (!cached) {
    primeProfileCommentEvidenceCache([row], cache);
    cached = cache.byIssue.get(row.number) ?? emptyCompactProfileCommentEvidence();
  }

  const cutoffMs = cutoff ? Date.parse(cutoff) : NaN;
  const confirmationReasons: ConfirmationReason[] = [];
  const seenReasons = new Set<string>();
  for (const candidate of cached.confirmations) {
    const reason = candidate.reason;
    const identity = reason.source === 'comment'
      ? `${reason.source}\0${reason.actorType ?? ''}\0${reason.actorNodeId ?? ''}`
      : `${reason.source}\0${reason.eventId ?? ''}`;
    if (seenReasons.has(identity)) continue;
    if (
      Number.isFinite(cutoffMs) &&
      (
        Date.parse(reason.occurredAt) > cutoffMs ||
        !candidate.updatedAt ||
        !Number.isFinite(Date.parse(candidate.updatedAt)) ||
        Date.parse(candidate.updatedAt) > cutoffMs
      )
    ) {
      continue;
    }
    seenReasons.add(identity);
    confirmationReasons.push(reason);
  }
  confirmationReasons.push(...profileLabelConfirmationReasons(
    row.number,
    effectiveLabels,
    cutoff,
    labelAuthority,
  ));

  let releaseLocalEvidence = exactReleaseLocalEvidence(
    row,
    releaseTag,
    [],
    cache.releasePublishedAtByTag.get(releaseTag) ?? null,
  );
  const explicitlyUnaffected =
    closureAuthority.releaseExplicitlyUnaffected(row.number, releaseTag);
  if (explicitlyUnaffected) {
    releaseLocalEvidence = null;
  } else if (!releaseLocalEvidence) {
    for (const candidate of cached.releaseEvidence.get(releaseTag) ?? []) {
      if (!profileCommentAvailableAtCutoff(candidate, cutoff)) continue;
      releaseLocalEvidence = candidate.evidence;
      break;
    }
  }

  const reporterIdentities = new Set<string>();
  if (row.author_node_id && row.author_type === 'User') {
    reporterIdentities.add(`User\0${row.author_node_id}`);
  }
  for (const reason of confirmationReasons) {
    if (
      reason.source === 'comment' &&
      reason.actorNodeId &&
      reason.actorType === 'User'
    ) {
      reporterIdentities.add(`User\0${reason.actorNodeId}`);
    }
  }
  return {
    humanReporterCount: reporterIdentities.size,
    confirmationReasons,
    commentEvidenceComplete: cached.complete,
    releaseLocalEvidence,
    releaseExplicitlyUnaffected: explicitlyUnaffected,
  };
}

function primeProfileCommentEvidenceCache(
  rows: JoinedIssue[],
  cache: ReleaseProfileCommentEvidenceCache,
): void {
  const missingByIssue = new Map<number, JoinedIssue>();
  for (const row of rows) {
    if (!cache.byIssue.has(row.number)) missingByIssue.set(row.number, row);
  }
  if (!missingByIssue.size) return;
  for (const issueNumber of missingByIssue.keys()) {
    cache.byIssue.set(issueNumber, emptyCompactProfileCommentEvidence());
  }
  for (const commentRow of compactIssueCommentEvidence([...missingByIssue.keys()])) {
    const row = missingByIssue.get(Number(commentRow.issue_number));
    const compact = cache.byIssue.get(Number(commentRow.issue_number));
    if (!row || !compact) continue;
    compact.complete = commentRow.complete === 1;
    if (commentRow.id == null || commentRow.complete !== 1) continue;
    const comment = {
      id: Number(commentRow.id),
      node_id: commentRow.comment_node_id,
      node_type: commentRow.comment_node_type,
      url: commentRow.url,
      user: {
        id: commentRow.actor_node_id,
        login: commentRow.author,
        type: commentRow.actor_type,
      },
      author_association: commentRow.author_association,
      body: commentRow.body,
      created_at: commentRow.created_at,
      updated_at: commentRow.updated_at,
    };
    const reasons = semanticHumanConfirmationReasons({
      issueNumber: row.number,
      issueNodeId: row.node_id,
      issueAuthor: {
        nodeId: row.author_node_id ?? null,
        login: row.author,
        actorType: row.author_type,
      },
      comments: [comment],
    });
    for (const reason of reasons) {
      compact.confirmations.push({
        reason,
        updatedAt: comment.updated_at ?? comment.created_at ?? null,
      });
    }
    for (const releaseTag of cache.releaseTags) {
      const evidence = exactReleaseLocalEvidence(
        { title: '', body: '' },
        releaseTag,
        [comment],
        cache.releasePublishedAtByTag.get(releaseTag) ?? null,
        (commentNodeId) =>
          reasons.find((reason) =>
            reason.source === 'comment' &&
            reason.commentNodeId === commentNodeId
          )?.authorityReference ?? null,
      );
      if (!evidence) continue;
      const evidenceRows = compact.releaseEvidence.get(releaseTag) ?? [];
      evidenceRows.push({
        evidence,
        createdAt: comment.created_at ?? null,
        updatedAt: comment.updated_at ?? comment.created_at ?? null,
      });
      compact.releaseEvidence.set(releaseTag, evidenceRows);
    }
  }
}

function emptyCompactProfileCommentEvidence(): CompactProfileCommentEvidence {
  return {
    confirmations: [],
    releaseEvidence: new Map(),
    complete: false,
  };
}

function profileLabelConfirmationReasons(
  issueNumber: number,
  effectiveLabels: string[],
  cutoff: string | null,
  labelAuthority: LabelOverrideAuthority,
): ConfirmationReason[] {
  const codes = new Map<string, ConfirmationReason['code']>([
    ['P0', 'human_applied_p0'],
    ['P1', 'human_applied_p1'],
    ['regression', 'human_applied_regression'],
  ]);
  const reasons: ConfirmationReason[] = [];
  for (const [label, code] of codes) {
    if (!effectiveLabels.includes(label)) continue;
    const event = latestIssueLabelEventAt(issueNumber, label, cutoff);
    const authorityReference =
      labelAuthority.authorityReferences?.[label] ?? null;
    if (
      !event ||
      event.action !== 'labeled' ||
      !labelAuthorizedForScoring(label, labelAuthority) ||
      !authorityReference
    ) {
      continue;
    }
    reasons.push({
      code,
      source: 'label_event',
      author: event.actor_login ?? 'unavailable',
      occurredAt: event.created_at,
      label: label as 'P0' | 'P1' | 'regression',
      eventId: event.event_id,
      authorityReference,
    });
  }
  return reasons;
}

function profileCommentAvailableAtCutoff(
  comment: { createdAt: string | null; updatedAt: string | null },
  cutoff: string | null,
): boolean {
  if (!cutoff) return true;
  const cutoffMs = Date.parse(cutoff);
  const createdMs = Date.parse(comment.createdAt ?? '');
  const updatedMs = Date.parse(comment.updatedAt ?? comment.createdAt ?? '');
  return Number.isFinite(cutoffMs) &&
    Number.isFinite(createdMs) &&
    Number.isFinite(updatedMs) &&
    createdMs <= cutoffMs &&
    updatedMs <= cutoffMs;
}

const batchLabelEventCountsStmt = db.prepare(`
WITH selected(issue_number) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?)
)
SELECT e.issue_number, COUNT(*) AS count
FROM issue_label_events e
JOIN selected s ON s.issue_number=e.issue_number
GROUP BY e.issue_number
`);

const batchLabelEventsUntilStmt = db.prepare(`
WITH selected(issue_number) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?)
)
SELECT e.issue_number, e.action, e.label_name
FROM issue_label_events e
JOIN selected s ON s.issue_number=e.issue_number
WHERE (? IS NULL OR e.created_at <= ?)
ORDER BY e.issue_number, e.created_at, e.event_id
`);

const batchLabelSnapshotsAtStmt = db.prepare(`
WITH selected(issue_number) AS (
  SELECT CAST(value AS INTEGER) FROM json_each(?)
),
ranked AS (
  SELECT
    s.issue_number,
    s.labels_json,
    COUNT(*) OVER (PARTITION BY s.issue_number) AS count,
    ROW_NUMBER() OVER (
      PARTITION BY s.issue_number
      ORDER BY s.snapshot_at DESC
    ) AS ordinal
  FROM issue_label_snapshots s
  JOIN selected selected_issue ON selected_issue.issue_number=s.issue_number
  WHERE s.snapshot_at <= ?
)
SELECT issue_number, labels_json, count
FROM ranked
WHERE ordinal=1
`);

export function batchIssueLabelInfo(
  issueRows: Array<{ number: number; labels: string }>,
  cutoff: string | null,
  additionalRows: Array<{ number: number; labels: string }> = [],
): Map<number, LabelInfo> {
  const currentLabelsByIssue = new Map<number, string[]>();
  for (const row of [...issueRows, ...additionalRows]) {
    if (!currentLabelsByIssue.has(row.number)) {
      currentLabelsByIssue.set(row.number, safeParseLabels(row.labels));
    }
  }
  const issueNumbers = [...currentLabelsByIssue.keys()];
  if (!issueNumbers.length) return new Map();

  const issueNumbersJson = JSON.stringify(issueNumbers);
  const eventCounts = new Map<number, number>();
  for (const row of batchLabelEventCountsStmt.all(issueNumbersJson) as Array<{
    issue_number: number;
    count: number;
  }>) {
    eventCounts.set(Number(row.issue_number), Number(row.count ?? 0));
  }

  const eventLabels = new Map<number, Set<string>>();
  for (const row of batchLabelEventsUntilStmt.all(
    issueNumbersJson,
    cutoff,
    cutoff,
  ) as Array<{ issue_number: number; action: string; label_name: string }>) {
    const issueNumber = Number(row.issue_number);
    const labels = eventLabels.get(issueNumber) ?? new Set<string>();
    if (row.action === 'labeled') labels.add(row.label_name);
    else if (row.action === 'unlabeled') labels.delete(row.label_name);
    eventLabels.set(issueNumber, labels);
  }

  const snapshots = new Map<number, { count: number; labels: string[] | null }>();
  if (cutoff) {
    for (const row of batchLabelSnapshotsAtStmt.all(issueNumbersJson, cutoff) as Array<{
      issue_number: number;
      labels_json: string;
      count: number;
    }>) {
      snapshots.set(Number(row.issue_number), {
        count: Number(row.count ?? 0),
        labels: safeParseLabelArray(row.labels_json),
      });
    }
  }

  const result = new Map<number, LabelInfo>();
  for (const [issueNumber, currentLabels] of currentLabelsByIssue) {
    const timelineEventCount = eventCounts.get(issueNumber) ?? 0;
    const snapshot = snapshots.get(issueNumber);
    const labelSnapshotCount = snapshot?.count ?? 0;
    const labels = timelineEventCount > 0
      ? [...(eventLabels.get(issueNumber) ?? [])]
      : cutoff != null
        ? snapshot?.labels ?? []
        : currentLabels;
    const source: LabelSource = cutoff == null
      ? 'current'
      : timelineEventCount > 0
        ? 'timeline'
        : labelSnapshotCount > 0
          ? 'snapshot'
          : 'missing_timeline';
    result.set(issueNumber, {
      labels,
      currentLabels,
      timelineEventCount,
      labelSnapshotCount,
      source,
    });
  }
  return result;
}

function fallbackLabelInfo(row: { labels: string }, cutoff: string | null): LabelInfo {
  const currentLabels = safeParseLabels(row.labels);
  return {
    labels: cutoff == null ? currentLabels : [],
    currentLabels,
    timelineEventCount: 0,
    labelSnapshotCount: 0,
    source: cutoff == null ? 'current' : 'missing_timeline',
  };
}

function safeParseLabelArray(value: string): string[] | null {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed)
      ? parsed.filter((label): label is string => typeof label === 'string')
      : null;
  } catch {
    return null;
  }
}

function* releaseIssueEvidenceRowIterator(
  computation: ReleaseEvidenceComputation,
  includeProvenance = true,
): Generator<ReleaseIssueEvidenceRow> {
  const {
    labelCutoff,
    labelInfo,
    opened,
    verifiedFixed,
    unverifiedClosed,
    issueByNumber,
    debt,
    openedAnalysis,
    fixCreditDecisionByIssue,
  } = computation;

  for (const item of debt.evidence) {
    yield debtEvidenceRow(item, issueByNumber, labelInfo, labelCutoff, includeProvenance);
  }
  for (let index = 0; index < opened.length; index++) {
    const evidence = openedAnalysis.evidence[index];
    if (evidence?.counted !== true) continue;
    yield withTierInfo({
      tier: 'openedFeltSerious' as const,
      issue: classifiedIssueSummary(opened[index], labelInfo, labelCutoff, includeProvenance),
      weight: evidence.countedWeight ?? 0,
      duplicateCluster: evidence.duplicateCluster ?? null,
      aliasGroup: evidence.aliasGroup ?? null,
      fieldConfirmed: evidence.fieldConfirmed ?? false,
      confirmationReasons: evidence.confirmationReasons ?? [],
      releaseLocalEvidence: evidence.releaseLocalEvidence ?? null,
    });
  }
  for (const issue of verifiedFixed) {
    yield withTierInfo({
      tier: 'verifiedFixed' as const,
      issue: classifiedIssueSummary(issue, labelInfo, labelCutoff, includeProvenance),
      fixCreditDecision: fixCreditDecisionByIssue.get(issue.number) ?? null,
    });
  }
  for (const issue of unverifiedClosed) {
    yield withTierInfo({
      tier: 'unverifiedClosed' as const,
      issue: classifiedIssueSummary(issue, labelInfo, labelCutoff, includeProvenance),
    });
  }
  for (const issue of unclassifiedIssuesForVersion(computation.tag, UNCLASSIFIED_ISSUE_AUDIT_LIMIT)) {
    yield withTierInfo({
      tier: 'unclassifiedIssues' as const,
      issue: unclassifiedIssueSummary(issue),
    });
  }
}

function compareSortEntries(
  left: { rank: number; value: number | null },
  right: { rank: number; value: number | null },
  direction: 'asc' | 'desc',
): number {
  const leftMissing = left.value == null || Number.isNaN(left.value);
  const rightMissing = right.value == null || Number.isNaN(right.value);
  if (leftMissing && rightMissing) return left.rank - right.rank;
  if (leftMissing) return 1;
  if (rightMissing) return -1;
  const leftValue = left.value as number;
  const rightValue = right.value as number;
  const valueDiff = leftValue === rightValue ? 0 : leftValue < rightValue ? -1 : 1;
  return valueDiff === 0
    ? left.rank - right.rank
    : direction === 'asc'
      ? valueDiff
      : -valueDiff;
}

function rememberIssueNumber(
  numbers: Set<number>,
  row: ReleaseIssueEvidenceRow,
): void {
  const number = Number(row.issue?.number);
  if (Number.isInteger(number) && number > 0) numbers.add(number);
}

function isAdverseClosureRiskDisposition(disposition: string): boolean {
  return [
    'known_not_in_release',
    'open_canonical_risk',
    'unsupported_closure_claim',
    'missing_evidence',
  ].includes(disposition);
}

const PROFILE_TIER_PRIORITY: Record<ReleaseProfileEvidenceTier, number> = {
  verifiedDebt: 5,
  openedFeltSerious: 4,
  carryoverDebt: 3,
  staleDebt: 2,
  unverifiedClosed: 1,
};

function rememberProfileCandidate(
  rows: ReleaseProfileEvidenceCandidate[],
  issue: JoinedIssue,
  tier: ReleaseProfileEvidenceTier,
  explicitWeight: number | null | undefined,
  classification: IssueClassification,
  aliasGroup: string | null | undefined,
): void {
  if (classification.sentiment !== 'negative') return;
  const weight = compactProfileEvidenceWeight(explicitWeight, tier, classification, issue.state);
  if (weight <= 0) return;
  rows.push({
    issueNumber: issue.number,
    title: issue.title,
    state: issue.state,
    tier,
    weight,
    aliasGroup: aliasGroup || `issue:${issue.number}`,
  });
}

function compactProfileEvidenceWeight(
  explicitWeight: number | null | undefined,
  tier: ReleaseProfileEvidenceTier,
  classification: IssueClassification,
  state: string,
): number {
  if (typeof explicitWeight === 'number' && Number.isFinite(explicitWeight)) {
    return Math.max(0, explicitWeight);
  }
  const severity = ({
    critical: 2.2,
    high: 1.5,
    medium: 0.8,
    low: 0.35,
  } as Record<string, number>)[classification.severity] ?? 0.6;
  const confidence = Math.max(0.5, Math.min(1.25, Number(classification.confidence ?? 1)));
  const stateFactor = state.toLowerCase() === 'closed' ? 0.35 : 1;
  const tierFactor = tier === 'unverifiedClosed' ? 0.85 : tier === 'openedFeltSerious' ? 1 : 0.7;
  return severity * confidence * stateFactor * tierFactor;
}

function profileCandidatePrecedes(
  candidate: ReleaseProfileEvidenceCandidate,
  current: ReleaseProfileEvidenceCandidate,
): boolean {
  if (candidate.weight !== current.weight) return candidate.weight > current.weight;
  const priority = PROFILE_TIER_PRIORITY[candidate.tier] - PROFILE_TIER_PRIORITY[current.tier];
  if (priority !== 0) return priority > 0;
  return candidate.issueNumber < current.issueNumber;
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
  labelInfo: (row: JoinedIssue) => ResolvedLabelInfo,
  labelCutoff: string | null,
  includeProvenance: boolean,
): ReleaseIssueEvidenceRow {
  const issue = item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined;
  const tier = ({
    verified: 'verifiedDebt',
    carryover: 'carryoverDebt',
    stale: 'staleDebt',
  } as const)[item.tier];
  const presentationInfo = debtEvidencePresentationInfo(
    tier,
    item,
    issue ? labelInfo(issue).labels : [],
  );
  return {
    tier,
    tierLabel: presentationInfo.label,
    tierDescription: presentationInfo.description,
    issue: issue
      ? classifiedIssueSummary(issue, labelInfo, labelCutoff, includeProvenance)
      : missingIssueSummary(item.issueNumber),
    weight: item.weight,
    duplicateCluster: item.duplicateCluster ?? null,
    aliasGroup: item.aliasGroup,
    adversePoints: item.adversePoints,
    humanReporterCount: item.humanReporterCount ?? null,
    commentCount: item.commentCount ?? null,
    fieldConfirmed: item.fieldConfirmed ?? null,
    confirmationReasons: item.confirmationReasons ?? [],
    humanCommenterCount: item.humanCommenterCount ?? null,
    maintainerCommenterCount: item.maintainerCommenterCount ?? null,
    contributorCommenterCount: item.contributorCommenterCount ?? null,
    reactionTotal: item.reactionTotal ?? null,
    positiveReactionCount: item.positiveReactionCount ?? null,
    commenterScanTruncated: item.commenterScanTruncated ?? null,
    installImpactClass: item.installImpactClass ?? null,
    installImpactMultiplier: item.installImpactMultiplier ?? null,
    clusterReleaseLocal: item.clusterReleaseLocal ?? null,
    releaseLocalEvidence: item.releaseLocalEvidence ?? null,
    debtClassification: item.debtClassification ?? null,
    debtClassificationDiff: item.debtClassificationDiff ?? null,
    ...(tier === 'carryoverDebt' ? { scoreAffecting: false } : {}),
  };
}

function debtEvidencePresentationInfo(
  tier: ReleaseIssueEvidenceTier,
  item: DebtEvidenceItem,
  labels: string[],
): { label: string; description: string } {
  const defaultInfo = RELEASE_ISSUE_EVIDENCE_TIER_INFO[tier];
  if (tier !== 'carryoverDebt') return defaultInfo;
  const sourceOnly = labels.some((label) =>
    label === 'clawsweeper:source-repro' || label === 'clawsweeper:current-main-repro'
  );
  if (!sourceOnly && item.fieldConfirmed === true) return defaultInfo;
  return {
    label: 'Weak or stale evidence',
    description: 'Source/static-only or otherwise unconfirmed evidence. The legacy carryover machine tier is retained for compatibility, but this row is presentation-only context and does not lower the assessment.',
  };
}

function classifiedIssueSummary(
  row: JoinedIssue,
  labelInfo: (row: JoinedIssue) => ResolvedLabelInfo,
  labelCutoff: string | null,
  includeProvenance: boolean,
): ClassifiedIssueSummary {
  const storedClassification = rawClassificationFromRow(row);
  const classification = classifyIssueRowWithLabels(
    row,
    labelInfo(row).labels,
    labelInfo(row).authority,
  );
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
    labelSnapshotCount: labelInfo(row).labelSnapshotCount,
    labelCutoffAt: labelCutoff,
    classificationOrigin: row.classification_origin,
    rawModelOutput: includeProvenance ? row.raw_model_output : null,
    classificationProvenance: includeProvenance
      ? parseJsonRecord<IssueClassificationProvenance>(row.provenance_json)
      : null,
    classifierSourceIdentity: includeProvenance
      ? parseJsonRecord(row.source_identity_json)
      : null,
    classifierSourceIdentityDigest: includeProvenance ? row.source_identity_digest : null,
    classificationPromptVersion: row.prompt_version,
    classifiedAt: row.classified_at,
    classifiedUpdatedAt: row.classified_updated_at,
    classifiedCommentsDigest: row.classified_comments_digest,
    storedClassification,
    rawClassification: row.classification_origin === 'raw_model' ? storedClassification : null,
    classification,
    classificationDiff: classificationDiff(storedClassification, classification),
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
    hasWorkaround: row.has_workaround === 1,
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster,
    affectsVersion: row.affects_version,
    confidence: row.confidence,
    rationale: row.rationale ?? '',
  };
}

function parseJsonRecord<T extends object = Record<string, unknown>>(
  json: string | null | undefined,
): T | null {
  if (!json) return null;
  try {
    const parsed = JSON.parse(json);
    return parsed != null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as T
      : null;
  } catch {
    return null;
  }
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
    'hasWorkaround',
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
  const counts = emptyCountsByTier();
  for (const row of rows) counts[row.tier] += 1;
  return counts;
}

export function summarizeIssueEvidenceRows(rows: ReleaseIssueEvidenceRow[]): ReleaseIssueEvidenceTierSummary {
  const summary = emptyTierSummary();
  for (const row of rows) addRowToSummary(summary, row);
  return roundTierSummary(summary);
}

function isMissingIssue(issue: ReleaseIssueEvidenceRow['issue']): issue is MissingIssueSummary {
  return 'missing' in issue && issue.missing === true;
}

function summarizeByTier(rows: ReleaseIssueEvidenceRow[]): Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary> {
  const summaries = emptySummaryByTier();
  for (const row of rows) addRowToSummary(summaries[row.tier], row);
  return finalizeSummaryByTier(summaries);
}

function emptyCountsByTier(): Record<ReleaseIssueEvidenceTier, number> {
  return Object.fromEntries(
    RELEASE_ISSUE_EVIDENCE_TIERS.map((tier) => [tier, 0]),
  ) as Record<ReleaseIssueEvidenceTier, number>;
}

function emptySummaryByTier(): Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary> {
  return Object.fromEntries(
    RELEASE_ISSUE_EVIDENCE_TIERS.map((tier) => [tier, emptyTierSummary()]),
  ) as Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary>;
}

function finalizeSummaryByTier(
  summaries: Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary>,
): Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary> {
  return Object.fromEntries(
    RELEASE_ISSUE_EVIDENCE_TIERS.map((tier) => [tier, roundTierSummary(summaries[tier])]),
  ) as Record<ReleaseIssueEvidenceTier, ReleaseIssueEvidenceTierSummary>;
}

function addRowToSummary(
  summary: ReleaseIssueEvidenceTierSummary,
  row: ReleaseIssueEvidenceRow,
): void {
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
