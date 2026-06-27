import { PROMPT_VERSION, type IssueClassification } from './llm';
import { applyLabelOverrides, applyTitleFunctionalityHint, applyTitleIssueShapeHint } from './labelOverrides';
import { releaseLabelCutoff } from './labelCutoff';
import {
  cveDecayLoad,
  explainOpenDebtLoad,
  feltLoad,
  feltSignalMask,
  installConfidence,
  isFeltSignal,
  pickRecommended,
  SCORE_MODEL_VERSION,
  type InstallConfidence,
  type InstallInput,
} from './score';
import { hasHotfixSuccessor } from './releaseNotes';
import { stableDistance, matchesRange } from './versionMatch';
import { topBrokenSurfaces } from './surfaces';
import {
  getReleaseCommit,
  issueCountForVersion,
  issuesForVersion,
  labelsForIssueAt,
  listAdvisories,
  listReleasesDb,
  openedDuringReign,
  unverifiedClosedForRelease,
  verifiedFixedForRelease,
  type JoinedIssue,
  type ReleaseRow,
} from './db';

export { PROMPT_VERSION, SCORE_MODEL_VERSION };

export interface ReleaseScoreRunOptions {
  releases?: ReleaseRow[];
  releaseLimit?: number;
  allFetchedTags: string[];
  stableTagsNewestFirst: string[];
  nowForRelease?: (release: ReleaseRow) => number;
}

export interface ReleaseScoreResult {
  rel: ReleaseRow;
  conf: InstallConfidence;
  input: InstallInput;
  debtEvidence: Record<string, unknown>;
  gateEvidence: Record<string, unknown>;
  neg: number;
  pos: number;
  openedSerious: number;
  closedSerious: number;
  brokenSurfaces: string;
}

export interface ReleaseScoreRun {
  scored: ReleaseScoreResult[];
  recommendedTag: string | null;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function buildReleaseScoreRun(options: ReleaseScoreRunOptions): ReleaseScoreRun {
  const releases = options.releases ?? listReleasesDb(options.releaseLimit ?? 20);
  const advisories = listAdvisories();
  const cveFor = (tag: string): { affected: boolean; load: number } => {
    const matching = advisories.filter((a) => matchesRange(tag, a.vulnerable_version_range));
    const affected = matching.some((a) => (SEV_RANK[a.severity] ?? 0) >= 2);
    const load = cveDecayLoad(
      matching
        .map((a) => ({
          severity: a.severity,
          distance: stableDistance(tag, a.patched_versions, options.stableTagsNewestFirst),
        }))
        .filter((x) => x.distance <= 0),
    );
    return { affected, load };
  };

  const scored = releases.map((release, idx) =>
    scoreRelease({
      release,
      idx,
      allFetchedTags: options.allFetchedTags,
      stableTagsNewestFirst: options.stableTagsNewestFirst,
      cveFor,
      now: options.nowForRelease?.(release) ?? Date.now(),
    }),
  );
  const recommendedTag = pickRecommended(
    scored.map((s) => ({ tag: s.rel.tag, status: s.conf.status, score: s.conf.score })),
  );
  return { scored, recommendedTag };
}

function scoreRelease(args: {
  release: ReleaseRow;
  idx: number;
  allFetchedTags: string[];
  stableTagsNewestFirst: string[];
  cveFor: (tag: string) => { affected: boolean; load: number };
  now: number;
}): ReleaseScoreResult {
  const { release: rel } = args;
  const labelCutoff = releaseLabelCutoff(rel);
  const effectiveLabels = (row: JoinedIssue): string[] =>
    labelsForIssueAt(row.number, safeParseLabels(row.labels), labelCutoff);
  const classify = (row: JoinedIssue): IssueClassification =>
    classifyIssueRowWithLabels(row, effectiveLabels(row));
  const countCoreSerious = (rows: JoinedIssue[]): number =>
    rows.reduce((n, r) => (isCoreSerious(classify(r)) ? n + 1 : n), 0);

  let neg = 0;
  let pos = 0;
  const attributed = issuesForVersion(rel.tag);
  for (const row of attributed) {
    const sentiment = classify(row).sentiment;
    if (sentiment === 'negative') neg++;
    else if (sentiment === 'positive') pos++;
  }

  const openedReign = openedDuringReign(rel.tag);
  const verifiedFixed = verifiedFixedForRelease(rel.tag);
  const unverifiedClosed = unverifiedClosedForRelease(rel.tag);
  const verifiedFixedNumbers = new Set(verifiedFixed.map((row) => row.number));
  const scoreStateForIssue = (row: JoinedIssue): string => {
    if (verifiedFixedNumbers.has(row.number)) return 'closed';
    return row.state === 'open' ? 'open' : 'closed-unverified';
  };
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
    labels: effectiveLabels(row),
  });

  const debtInputs = attributed.map((row) => ({
    ...feltInput(row),
    issueNumber: row.number,
    state: scoreStateForIssue(row),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    affectsVersion: row.affects_version,
    releaseLocal: rel.published_at ? Date.parse(row.created_at) >= Date.parse(rel.published_at) : false,
  }));
  const activeDebt = explainOpenDebtLoad(debtInputs);
  const openedSerious = countCoreSerious(openedReign);
  const closedSerious = countCoreSerious(verifiedFixed);
  const openedFeltInputs = openedReign.map(feltInput);
  const openedFeltMask = feltSignalMask(openedFeltInputs);
  const openedFeltRows = openedReign.filter((_, rowIndex) => openedFeltMask[rowIndex]);
  const feltOpenedWeight = feltLoad(openedFeltInputs);
  const feltClosedWeight = feltLoad(verifiedFixed.map(feltInput));
  const brokenSurfaces = JSON.stringify(topBrokenSurfaces(openedFeltRows.map((row) => row.title)));
  const cve = args.cveFor(rel.tag);
  const releaseCommit = getReleaseCommit(rel.tag);
  const input: InstallInput = {
    publishedAt: rel.published_at,
    isLatest: args.idx === 0,
    hoursToNextStable: rel.hours_to_next_stable,
    hasHotfixSuccessor: hasHotfixSuccessor(args.allFetchedTags, rel.tag),
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    feltOpenedWeight,
    feltClosedWeight,
    verifiedDebtWeight: activeDebt.loads.verified,
    carryoverDebtWeight: activeDebt.loads.carryover,
    staleDebtWeight: activeDebt.loads.stale,
    rawIssueCount: issueCountForVersion(rel.tag),
    classifiedIssueCount: attributed.length,
    cveAffected: cve.affected,
    cveLoad: cve.load,
    releaseCheckState: releaseCommit?.check_state ?? null,
    releaseCheckTotal: releaseCommit?.check_total ?? 0,
    releaseCheckSuccess: releaseCommit?.check_success ?? 0,
    releaseCheckFailure: releaseCommit?.check_failure ?? 0,
    releaseCheckPending: releaseCommit?.check_pending ?? 0,
    artifactVerified: rel.artifact_verified === 1,
    artifactMismatch: rel.artifact_mismatch,
    ciReportVerified: rel.ci_report_verified === 1,
    ciReportMismatch: rel.ci_report_mismatch,
    releaseIntegrityPresent: !!rel.release_integrity,
    releaseShaMatches: rel.release_sha && releaseCommit?.tag_commit_oid
      ? rel.release_sha === releaseCommit.tag_commit_oid
      : undefined,
  };
  const conf = installConfidence(input, args.now);
  const issueByNumber = new Map(attributed.map((row) => [row.number, row]));
  const summarizeIssue = (row: JoinedIssue | undefined) => {
    if (!row) return null;
    const classification = classify(row);
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
      uniqueHumanCommenters: row.unique_human_commenters,
      maintainerCommenters: row.maintainer_commenters,
      contributorCommenters: row.contributor_commenters,
      commenterScanTruncated: row.commenter_scan_truncated,
      reactionTotal: row.reaction_total,
      positiveReactions: row.positive_reactions,
      labels: effectiveLabels(row),
      currentLabels: safeParseLabels(row.labels),
      labelCutoffAt: labelCutoff,
      affectsVersion: row.affects_version,
      duplicateCluster: row.duplicate_cluster,
      classification,
    };
  };

  const debtEvidence = {
    verifiedDebt: activeDebt.evidence
      .filter((item) => item.tier === 'verified')
      .slice(0, 25)
      .map((item) => ({ ...item, issue: summarizeIssue(item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined) })),
    carryoverDebt: activeDebt.evidence
      .filter((item) => item.tier === 'carryover')
      .slice(0, 25)
      .map((item) => ({ ...item, issue: summarizeIssue(item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined) })),
    staleDebt: activeDebt.evidence
      .filter((item) => item.tier === 'stale')
      .slice(0, 25)
      .map((item) => ({ ...item, issue: summarizeIssue(item.issueNumber ? issueByNumber.get(item.issueNumber) : undefined) })),
    openedFeltSerious: openedFeltRows
      .slice(0, 25)
      .map((row) => summarizeIssue(row)),
    verifiedFixed: verifiedFixed
      .slice(0, 25)
      .map((row) => summarizeIssue(row)),
    unverifiedClosed: unverifiedClosed
      .slice(0, 25)
      .map((row) => summarizeIssue(row)),
  };
  const gateEvidence = {
    cve,
    stableTagsNewestFirst: args.stableTagsNewestFirst,
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    hoursToNextStable: rel.hours_to_next_stable,
    hasHotfixSuccessor: input.hasHotfixSuccessor,
    releaseChecks: releaseCommit ? {
      state: releaseCommit.check_state,
      total: releaseCommit.check_total,
      success: releaseCommit.check_success,
      failure: releaseCommit.check_failure,
      pending: releaseCommit.check_pending,
      skipped: releaseCommit.check_skipped,
      contexts: parseJsonArray(releaseCommit.check_contexts_json).slice(0, 25),
    } : null,
    artifactVerification: {
      npmPackageUrl: rel.npm_package_url,
      releaseTarballUrl: rel.release_tarball_url,
      releaseIntegrity: rel.release_integrity,
      releaseSha: rel.release_sha,
      releaseShaMatches: rel.release_sha && releaseCommit?.tag_commit_oid
        ? rel.release_sha === releaseCommit.tag_commit_oid
        : null,
      ciReportUrl: rel.full_release_ci_report_url,
      ciReportVerified: rel.ci_report_verified === 1,
      ciReportMismatch: rel.ci_report_mismatch,
      registryVersion: rel.registry_version,
      registryIntegrity: rel.registry_integrity,
      registryTarballUrl: rel.registry_tarball_url,
      verified: rel.artifact_verified === 1,
      mismatch: rel.artifact_mismatch,
    },
    fixProvenance: {
      verifiedFixedCount: verifiedFixed.length,
      unverifiedClosedCount: unverifiedClosed.length,
    },
  };

  return { rel, conf, input, debtEvidence, gateEvidence, neg, pos, openedSerious, closedSerious, brokenSurfaces };
}

function isCoreSerious(classification: IssueClassification): boolean {
  return classification.sentiment === 'negative' &&
    classification.functionality === 'core' &&
    (classification.severity === 'critical' || classification.severity === 'high');
}

export function safeParseLabels(json: string): string[] {
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function parseJsonArray(json: string | null | undefined): unknown[] {
  try {
    const value = json ? JSON.parse(json) : [];
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function rowToClassification(row: {
  sentiment: string;
  severity: string;
  scope: string;
  functionality: string;
  affected_users: string;
  has_workaround: number;
  workaround_status: string;
  duplicate_cluster: string | null;
  affects_version: string | null;
  confidence: number;
  rationale: string | null;
}): IssueClassification {
  const wsAllowed = ['none', 'partial', 'confirmed', 'unknown'] as const;
  const ws = wsAllowed.includes(row.workaround_status as (typeof wsAllowed)[number])
    ? (row.workaround_status as IssueClassification['workaroundStatus'])
    : row.has_workaround === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment as IssueClassification['sentiment'],
    severity: row.severity as IssueClassification['severity'],
    scope: row.scope as IssueClassification['scope'],
    functionality: row.functionality as IssueClassification['functionality'],
    affectedUsers: row.affected_users as IssueClassification['affectedUsers'],
    workaroundStatus: ws,
    duplicateCluster: row.duplicate_cluster,
    affectsVersion: row.affects_version,
    confidence: row.confidence,
    rationale: row.rationale ?? '',
  };
}

export function classifyIssueRow(row: JoinedIssue): IssueClassification {
  return classifyIssueRowWithLabels(row, safeParseLabels(row.labels));
}

export function classifyIssueRowWithLabels(row: JoinedIssue, labels: string[]): IssueClassification {
  return applyTitleIssueShapeHint(
    applyLabelOverrides(
      applyTitleFunctionalityHint(rowToClassification(row), row.title),
      labels,
    ),
    row.title,
    labels,
  );
}

export function isOpenFeltSeriousIssue(row: JoinedIssue): boolean {
  const c = classifyIssueRow(row);
  return row.state === 'open' && isFeltSignal({
    ...c,
    issueNumber: row.number,
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
    labels: safeParseLabels(row.labels),
  });
}
