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
import { closureProofPayload, enrichGateEvidenceWithClosureProof } from './closureProofPayload';
import {
  getReleaseCommit,
  issueLabelEventCount,
  issueCountForVersion,
  issuesForVersion,
  labelsForIssueAt,
  listAdvisories,
  listReleasesDb,
  openedDuringReign,
  updateReleaseScore,
  upsertReleaseScoreAudit,
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
  explanation: ScoreExplanation;
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

export interface ScoreExplanation {
  schemaVersion: number;
  title: string;
  positives: string[];
  positiveDetails: ScoreExplanationDetail[];
  limits: string[];
  limitDetails: ScoreExplanationDetail[];
  verdict: string;
}

export interface ScoreExplanationDetail {
  code: string;
  text: string;
  metrics?: Record<string, number | string | boolean | null>;
  buckets?: Record<string, number>;
  riskBuckets?: Record<string, number>;
  issueRefs?: ScoreExplanationIssueRef[];
}

export interface ScoreExplanationIssueRef {
  number: number;
  title: string;
  url: string | null;
  state?: string | null;
  status?: string | null;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const SHORT_ISSUE_TITLE_LENGTH = 110;
export const SCORE_EXPLANATION_SCHEMA_VERSION = 1;
export const SCORE_EXPLANATION_LIMIT_CODES = [
  'field_visible_reports_opened',
  'source_carryover_risk',
  'stale_low_confidence_evidence',
  'closed_issues_not_counted_as_release_fixes',
  'unverified_closed_fix_reachability',
  'missing_full_release_evidence_report',
  'model_ceiling_and_capped_confidence',
] as const;
export const SCORE_EXPLANATION_POSITIVE_CODES = [
  'no_verified_field_blocker_debt',
  'release_checks_passed',
  'artifact_verified',
  'release_recommended',
  'hard_gates_passed',
] as const;
type ScoreExplanationLimitCode = (typeof SCORE_EXPLANATION_LIMIT_CODES)[number];
type ScoreExplanationPositiveCode = (typeof SCORE_EXPLANATION_POSITIVE_CODES)[number];

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

  const scoredWithoutExplanation = releases.map((release, idx) =>
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
    scoredWithoutExplanation.map((s) => ({ tag: s.rel.tag, status: s.conf.status, score: s.conf.score })),
  );
  const scored = scoredWithoutExplanation.map((result) => ({
    ...result,
    explanation: buildScoreExplanation(result, result.rel.tag === recommendedTag),
  }));
  return { scored, recommendedTag };
}

export function persistReleaseScoreRun(run: ReleaseScoreRun): void {
  for (const result of run.scored) {
    const scoredAt = new Date().toISOString();
    const recommended = result.rel.tag === run.recommendedTag ? 1 : 0;
    updateReleaseScore({
      tag: result.rel.tag,
      final_score: result.conf.score,
      negative_issues: result.neg,
      positive_issues: result.pos,
      state: result.conf.status,
      recommended,
      score_reason: result.conf.reason,
      broken_surfaces: result.brokenSurfaces,
      closed_serious_fixed: result.closedSerious,
      opened_serious_during_reign: result.openedSerious,
      scored_at: scoredAt,
    });
    upsertReleaseScoreAudit({
      release_tag: result.rel.tag,
      scored_at: scoredAt,
      score_model_version: SCORE_MODEL_VERSION,
      prompt_version: PROMPT_VERSION,
      final_score: result.conf.score,
      status: result.conf.status,
      band: result.conf.band,
      recommended,
      input_json: JSON.stringify(result.input),
      components_json: JSON.stringify({
        components: result.conf.components,
        evidenceCoverage: result.conf.evidenceCoverage,
        hotfix: result.conf.hotfix,
        reason: result.conf.reason,
        explanation: result.explanation,
      }),
      issue_evidence_json: JSON.stringify(result.debtEvidence),
      gate_evidence_json: JSON.stringify(result.gateEvidence),
    });
  }
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
  const labelInfoByIssue = new Map<number, {
    labels: string[];
    currentLabels: string[];
    timelineEventCount: number;
    source: 'current' | 'timeline' | 'missing_timeline';
  }>();
  const labelInfo = (row: JoinedIssue) => {
    const cached = labelInfoByIssue.get(row.number);
    if (cached) return cached;
    const currentLabels = safeParseLabels(row.labels);
    const timelineEventCount = issueLabelEventCount(row.number);
    const labels = labelsForIssueAt(row.number, currentLabels, labelCutoff, {
      useFallbackWhenNoEvents: labelCutoff == null,
    });
    const source: 'current' | 'timeline' | 'missing_timeline' = labelCutoff == null
      ? 'current'
      : timelineEventCount > 0
        ? 'timeline'
        : 'missing_timeline';
    const info = { labels, currentLabels, timelineEventCount, source };
    labelInfoByIssue.set(row.number, info);
    return info;
  };
  const effectiveLabels = (row: JoinedIssue): string[] => labelInfo(row).labels;
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
  const closureProof = closureProofPayload(rel.tag);
  const unresolvedClosureRiskWeight = closureRiskWeight(closureProof?.riskSummary);
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
    unresolvedClosureRiskWeight,
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
    const rawClassification = rowToClassification(row);
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
      labels: labelInfo(row).labels,
      currentLabels: labelInfo(row).currentLabels,
      labelCutoffAt: labelCutoff,
      labelTimelineEventCount: labelInfo(row).timelineEventCount,
      labelSource: labelInfo(row).source,
      affectsVersion: row.affects_version,
      duplicateCluster: row.duplicate_cluster,
      rawClassification,
      classification,
      classificationDiff: classificationDiff(rawClassification, classification),
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
  const labelTimeline = labelTimelineCoverage(
    [...attributed, ...openedReign, ...verifiedFixed, ...unverifiedClosed],
    labelInfo,
    labelCutoff,
  );
  const gateEvidence = enrichGateEvidenceWithClosureProof(rel.tag, {
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
    labelTimeline,
    fixProvenance: {
      verifiedFixedCount: verifiedFixed.length,
      unverifiedClosedCount: unverifiedClosed.length,
    },
  }, closureProof);

  return {
    rel,
    conf,
    input,
    explanation: {
      schemaVersion: SCORE_EXPLANATION_SCHEMA_VERSION,
      title: 'Why not 10?',
      positives: [],
      positiveDetails: [],
      limits: [],
      limitDetails: [],
      verdict: '',
    },
    debtEvidence,
    gateEvidence,
    neg,
    pos,
    openedSerious,
    closedSerious,
    brokenSurfaces,
  };
}

function buildScoreExplanation(result: ReleaseScoreResult, recommended: boolean): ScoreExplanation {
  const evidence = result.debtEvidence as any;
  const gate = result.gateEvidence as any;
  const input = result.input;
  const components = (result.conf.components ?? {}) as Partial<Record<string, number>>;
  const opened = Array.isArray(evidence.openedFeltSerious) ? evidence.openedFeltSerious : [];
  const openedStillOpen = opened.filter((issue: any) => issue?.state === 'open');
  const carryover = (Array.isArray(evidence.carryoverDebt) ? evidence.carryoverDebt : [])
    .map((row: any) => row.issue)
    .filter(Boolean);
  const stale = Array.isArray(evidence.staleDebt) ? evidence.staleDebt : [];
  const verified = Array.isArray(evidence.verifiedDebt) ? evidence.verifiedDebt : [];
  const limits: string[] = [];
  const limitDetails: ScoreExplanationDetail[] = [];
  const addLimit = (
    code: ScoreExplanationLimitCode,
    text: string,
    extra: Omit<ScoreExplanationDetail, 'code' | 'text'> = {},
  ) => {
    limits.push(text);
    limitDetails.push({ code, text, ...extra });
  };

  if (opened.length) {
    const examples = openedStillOpen.length ? openedStillOpen : opened;
    const example = issueListText(examples);
    addLimit(
      'field_visible_reports_opened',
      `${opened.length} field-visible bug reports were opened in this release window; ${openedStillOpen.length} are still open.` +
      sentenceSuffix('Examples', example),
      {
        metrics: { openedCount: opened.length, stillOpenCount: openedStillOpen.length },
        issueRefs: issueRefs(examples),
      },
    );
  }

  if ((input.carryoverDebtWeight ?? 0) > 0) {
    const example = issueListText(carryover);
    addLimit(
      'source_carryover_risk',
      `There is unresolved source/carryover risk, weighted by install impact. Provider/security/product-debt issues stay visible but are damped unless they directly affect install/runtime stability. This bucket is capped at ${penaltyText(components.carryoverDebt)}.` +
      sentenceSuffix('Top examples', example),
      {
        metrics: {
          rawWeight: roundMetric(input.carryoverDebtWeight),
          cappedPenalty: Math.abs(numberOrZero(components.carryoverDebt)),
        },
        issueRefs: issueRefs(carryover),
      },
    );
  }

  if ((input.staleDebtWeight ?? 0) > 0) {
    addLimit(
      'stale_low_confidence_evidence',
      `${stale.length} low-confidence/stale evidence items are still tracked, capped at ${penaltyText(components.staleDebt)}.`,
      {
        metrics: {
          count: stale.length,
          rawWeight: roundMetric(input.staleDebtWeight),
          cappedPenalty: Math.abs(numberOrZero(components.staleDebt)),
        },
      },
    );
  }

  const fix = gate.fixProvenance ?? {};
  const closureProof = fix.closureProof;
  if (closureProof?.notCreditedCount > 0) {
    const bucketText = closureProofSummaryText(closureProof);
    const riskText = closureRiskSummaryText(closureProof);
    const buckets = proofBucketsExceptFixed(closureProof.byStatus);
    const riskBuckets = proofBucketsExceptFixed(closureProof.byRiskDisposition, 'credited_release_fix');
    const riskSummary = closureProof.riskSummary ?? {};
    addLimit(
      'closed_issues_not_counted_as_release_fixes',
      `${closureProof.notCreditedCount} closed issues in this release window are not counted as release fixes.` +
      (riskText ? ` Risk split: ${riskText}.` : '') +
      (bucketText ? ` Breakdown: ${bucketText}.` : ''),
      {
        metrics: {
          countedClosedCount: Number(closureProof.creditedCount ?? 0),
          notCountedClosedCount: Number(closureProof.notCreditedCount ?? 0),
          analyzedClosedCount: Number(closureProof.analyzedClosedCount ?? 0),
          unresolvedForReleaseCount: Number(riskSummary.unresolvedForReleaseCount ?? 0),
          unresolvedClosureRiskWeight: roundMetric(input.unresolvedClosureRiskWeight),
          knownNotInReleaseCount: Number(riskSummary.knownNotInReleaseCount ?? 0),
          openCanonicalRiskCount: Number(riskSummary.openCanonicalRiskCount ?? 0),
          unsupportedClosureClaimCount: Number(riskSummary.unsupportedClosureClaimCount ?? 0),
          neutralOrNonActionableCount: Number(riskSummary.neutralOrNonActionableCount ?? 0),
          missingEvidenceCount: Number(riskSummary.missingEvidenceCount ?? 0),
        },
        buckets,
        riskBuckets,
        issueRefs: issueRefs((closureProof.examples ?? []).filter((item: any) => item.status !== 'fixed_in_release')),
      },
    );
  } else if ((fix.unverifiedClosedCount ?? 0) > 0) {
    addLimit(
      'unverified_closed_fix_reachability',
      `${fix.unverifiedClosedCount} closed issues are not counted as fixes yet because release-tag reachability has not been analyzed for them.`,
      { metrics: { unverifiedClosedCount: Number(fix.unverifiedClosedCount ?? 0) } },
    );
  }

  const artifact = gate.artifactVerification;
  if (artifact?.ciReportMismatch) {
    addLimit(
      'missing_full_release_evidence_report',
      `The npm package is verified, but the linked full release evidence report is missing: ${artifact.ciReportMismatch}.`,
      { metrics: { ciReportMismatch: artifact.ciReportMismatch } },
    );
  }

  if (!limits.length && !verified.length) {
    addLimit(
      'model_ceiling_and_capped_confidence',
      'No field-blocker evidence is currently holding this release down; the remaining gap comes from the model ceiling and capped confidence signals.',
    );
  }

  const positives: string[] = [];
  const positiveDetails: ScoreExplanationDetail[] = [];
  const addPositive = (
    code: ScoreExplanationPositiveCode,
    text: string,
    extra: Omit<ScoreExplanationDetail, 'code' | 'text'> = {},
  ) => {
    positives.push(text);
    positiveDetails.push({ code, text, ...extra });
  };
  if (!verified.length) {
    addPositive(
      'no_verified_field_blocker_debt',
      'No verified field-blocker debt is currently scoring against this release.',
      { metrics: { verifiedDebtCount: verified.length } },
    );
  }
  const checks = gate.releaseChecks;
  if (checks?.failure === 0 && checks?.pending === 0 && checks?.success > 0) {
    addPositive(
      'release_checks_passed',
      `${checks.success} release checks passed with no failed or pending checks.`,
      { metrics: { success: Number(checks.success ?? 0), failure: Number(checks.failure ?? 0), pending: Number(checks.pending ?? 0) } },
    );
  }
  if (artifact?.verified) {
    const text = artifact.releaseShaMatches === true
      ? 'The npm package integrity, tarball, and release SHA match.'
      : 'The npm package integrity and tarball metadata are verified.';
    addPositive(
      'artifact_verified',
      text,
      { metrics: { artifactVerified: true, releaseShaMatches: artifact.releaseShaMatches === true } },
    );
  }
  if (recommended) {
    addPositive('release_recommended', 'The release is eligible and recommended.');
  } else if (result.conf.status === 'eligible') {
    addPositive('hard_gates_passed', 'The release passed hard install gates.');
  }

  return {
    schemaVersion: SCORE_EXPLANATION_SCHEMA_VERSION,
    title: 'Why not 10?',
    positives,
    positiveDetails,
    limits,
    limitDetails,
    verdict: installVerdictText(result.conf.status, recommended),
  };
}

function issueRefs(items: any[], limit = 2): ScoreExplanationIssueRef[] {
  return items
    .slice(0, limit)
    .map((item) => ({
      number: Number(item?.number ?? item?.issue?.number),
      title: shortIssueTitle(item?.issue ?? item),
      url: item?.url ?? item?.issue?.url ?? null,
      state: item?.state ?? item?.issue?.state ?? null,
      status: item?.status ?? null,
    }))
    .filter((item) => Number.isInteger(item.number) && item.number > 0 && item.title.length > 0);
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

function labelTimelineCoverage(
  rows: JoinedIssue[],
  labelInfo: (row: JoinedIssue) => {
    labels: string[];
    currentLabels: string[];
    timelineEventCount: number;
    source: 'current' | 'timeline' | 'missing_timeline';
  },
  cutoffAt: string | null,
): Record<string, unknown> {
  const byIssue = new Map<number, JoinedIssue>();
  for (const row of rows) byIssue.set(row.number, row);
  let current = 0;
  let timeline = 0;
  let missingTimeline = 0;
  let missingTimelineWithCurrentLabels = 0;
  for (const row of byIssue.values()) {
    const info = labelInfo(row);
    if (info.source === 'current') current++;
    else if (info.source === 'timeline') timeline++;
    else {
      missingTimeline++;
      if (info.currentLabels.length > 0) missingTimelineWithCurrentLabels++;
    }
  }
  return {
    cutoffAt,
    issueCount: byIssue.size,
    currentLabelCount: current,
    timelineLabelCount: timeline,
    missingTimelineCount: missingTimeline,
    missingTimelineWithCurrentLabelsCount: missingTimelineWithCurrentLabels,
    historicalCurrentLabelFallbackAllowed: cutoffAt == null,
  };
}

function proofBucketsExceptFixed(buckets: unknown, fixedKey = 'fixed_in_release'): Record<string, number> {
  if (!buckets || typeof buckets !== 'object' || Array.isArray(buckets)) return {};
  const entries = Object.entries(buckets as Record<string, unknown>)
    .filter(([status]) => status !== fixedKey)
    .map(([status, count]) => [status, Number(count)] as const)
    .filter(([, count]) => Number.isFinite(count) && count > 0);
  return Object.fromEntries(entries);
}

function closureRiskWeight(riskSummary: any): number {
  if (!riskSummary || typeof riskSummary !== 'object') return 0;
  return numberOrZero(riskSummary.knownNotInReleaseCount) +
    numberOrZero(riskSummary.openCanonicalRiskCount) * 1.2 +
    numberOrZero(riskSummary.unsupportedClosureClaimCount) * 0.8 +
    numberOrZero(riskSummary.missingEvidenceCount) * 1.5;
}

function numberOrZero(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function roundMetric(value: unknown): number {
  return Math.round(numberOrZero(value) * 1000) / 1000;
}

function installVerdictText(status: string, recommended: boolean): string {
  if (recommended) {
    return 'This means the release is the current recommended install candidate under the audit gates, but field reports, source-derived risk, or closed issues not tied to this release tag keep it below a perfect score.';
  }
  if (status === 'eligible') {
    return 'This means the release passed hard install gates, but the audit does not support treating it as the recommended install target.';
  }
  if (status === 'wait') {
    return 'This release is not scored yet because it has not had enough time to settle.';
  }
  return 'This release is not recommended to install because a hard safety gate is active.';
}

function closureProofSummaryText(closureProof: any): string {
  const byStatus = closureProof?.byStatus ?? {};
  return Object.entries(byStatus)
    .filter(([status]) => status !== 'fixed_in_release')
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([status, count]) => `${count} ${closureStatusLabel(status)}`)
    .join(' · ');
}

function closureRiskSummaryText(closureProof: any): string {
  const risk = closureProof?.riskSummary ?? {};
  const parts = [
    [risk.knownNotInReleaseCount, 'known not in this tag'],
    [risk.openCanonicalRiskCount, 'still-open canonical risk'],
    [risk.unsupportedClosureClaimCount, 'unsupported closure claim/admin triage'],
    [risk.missingEvidenceCount, 'missing proof evidence'],
    [risk.neutralOrNonActionableCount, 'neutral/non-actionable closure'],
  ];
  return parts
    .filter(([count]) => Number(count ?? 0) > 0)
    .map(([count, label]) => `${count} ${label}`)
    .join(' · ');
}

function closureStatusLabel(status: string): string {
  return ({
    fixed_in_release: 'fixed in this release',
    fixed_after_release: 'fixed after this release',
    duplicate_to_open_canonical: 'moved to open canonical',
    duplicate_to_closed_canonical: 'moved to closed canonical',
    canonical_cycle_or_self_reference: 'bad canonical reference',
    duplicate_or_superseded: 'duplicate/superseded',
    already_present_claim: 'already-present claim',
    main_only_claim: 'main-only claim',
    reporter_replaced: 'reporter refiled/replaced',
    reporter_withdrawn: 'reporter withdrew',
    reporter_self_closed: 'reporter self-closed',
    no_code_proof: 'no linked release fix',
    no_timeline_event: 'close event not fetched',
    non_bug_neutral: 'not bug evidence',
    not_planned: 'not planned',
    unknown: 'not enough release evidence',
  } as Record<string, string>)[status] ?? String(status ?? 'unknown');
}

function issueListText(issues: any[], limit = 2): string {
  return issues
    .slice(0, limit)
    .map(issueRef)
    .filter(Boolean)
    .join('; ');
}

function sentenceSuffix(label: string, text: string): string {
  if (!text) return '';
  return ` ${label}: ${text}${/[.!?]$/.test(text) ? '' : '.'}`;
}

function issueRef(issue: any): string {
  if (!issue?.number) return '';
  return `#${issue.number} ${shortIssueTitle(issue)}`;
}

function shortIssueTitle(issue: any): string {
  const title = String(issue?.title ?? '').replace(/^\[bug\]:?\s*/i, '').trim();
  return truncateAtWordBoundary(title, SHORT_ISSUE_TITLE_LENGTH);
}

function penaltyText(value: unknown): string {
  if (typeof value !== 'number') return 'a 0 point penalty';
  const abs = Math.abs(value);
  return `a ${abs} point penalty`;
}

function truncateAtWordBoundary(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  const suffix = '...';
  const limit = Math.max(0, maxLength - suffix.length);
  const slice = text.slice(0, limit).trimEnd();
  const boundary = Math.max(slice.lastIndexOf(' '), slice.lastIndexOf('/'), slice.lastIndexOf('-'));
  if (boundary >= Math.floor(limit * 0.65)) return `${slice.slice(0, boundary).trimEnd()}${suffix}`;
  return `${slice}${suffix}`;
}

export const __releaseScoringTest = {
  shortIssueTitle,
  truncateAtWordBoundary,
};

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
