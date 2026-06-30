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
  SCORE_COMPONENT_LIMITS,
  SCORE_MODEL_VERSION,
  type InstallConfidence,
  type InstallInput,
} from './score';
import { hasHotfixSuccessor } from './releaseNotes';
import { stableDistance, matchesRange } from './versionMatch';
import { topBrokenSurfaces } from './surfaces';
import { closureProofPayload, closureRiskDisposition, enrichGateEvidenceWithClosureProof } from './closureProofPayload';
import {
  getReleaseCommit,
  issueLabelEventCount,
  issueLabelSnapshotCountAt,
  issueCountForVersion,
  issuesForVersion,
  labelsForIssueAt,
  listAdvisories,
  listReleasesDb,
  openedDuringReign,
  unclassifiedIssuesForVersion,
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
  scoredAt: string;
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
  scoreLedger: ScoreExplanationLedger | null;
  positives: string[];
  positiveDetails: ScoreExplanationDetail[];
  limits: string[];
  limitDetails: ScoreExplanationDetail[];
  verdict: string;
}

export interface ScoreExplanationLedger {
  schemaVersion: number;
  finalScore: number | null;
  status: string;
  band: string;
  subtotalBeforeCaps: number | null;
  scoreAfterCaps: number | null;
  rows: ScoreExplanationLedgerRow[];
  caps: ScoreExplanationCap[];
}

export interface ScoreExplanationLedgerRow {
  key: string;
  label: string;
  points: number;
  kind: 'base' | 'bonus' | 'penalty' | 'neutral';
  metric?: number | string | null;
  note?: string | null;
}

export interface ScoreExplanationCap {
  key: string;
  label: string;
  ceiling: number;
  applied: boolean;
  before: number | null;
  after: number | null;
  reason: string;
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
  tier?: string | null;
  weight?: number | null;
  installImpactClass?: string | null;
  installImpactMultiplier?: number | null;
  proof?: ScoreExplanationIssueProof | null;
}

export interface ScoreExplanationIssueProof {
  status: string | null;
  statusLabel: string | null;
  riskDisposition: string | null;
  riskDispositionLabel: string | null;
  summary: string | null;
  riskWeight: number | null;
  canonicalIssue?: ScoreExplanationLinkedRef | null;
  canonicalPath?: number[] | null;
  openPrs?: ScoreExplanationLinkedRef[];
  reachablePrs?: ScoreExplanationLinkedRef[];
  notReachablePrs?: ScoreExplanationLinkedRef[];
}

export interface ScoreExplanationLinkedRef {
  number: number;
  title?: string | null;
  url?: string | null;
  state?: string | null;
  status?: string | null;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const SHORT_ISSUE_TITLE_LENGTH = 110;
export const SCORE_INPUT_SCHEMA_VERSION = 1;
export const SCORE_COMPONENTS_SCHEMA_VERSION = 1;
export const SCORE_EXPLANATION_SCHEMA_VERSION = 1;
export const GATE_EVIDENCE_SCHEMA_VERSION = 1;
export const ISSUE_EVIDENCE_SCHEMA_VERSION = 1;
export const LABEL_TIMELINE_SCHEMA_VERSION = 1;
export const RELEASE_CHECKS_SCHEMA_VERSION = 1;
export const ARTIFACT_VERIFICATION_SCHEMA_VERSION = 1;
export const SCORE_EXPLANATION_LIMIT_CODES = [
  'field_visible_reports_opened',
  'verified_field_blocker_debt',
  'source_carryover_risk',
  'stale_low_confidence_evidence',
  'incomplete_classification_coverage',
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

  const scoredWithoutExplanation = releases.map((release, idx) => {
    const now = options.nowForRelease?.(release) ?? Date.now();
    return scoreRelease({
      release,
      idx,
      allFetchedTags: options.allFetchedTags,
      stableTagsNewestFirst: options.stableTagsNewestFirst,
      cveFor,
      now,
    });
  });
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
    const scoredAt = result.scoredAt;
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
        schemaVersion: SCORE_COMPONENTS_SCHEMA_VERSION,
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
  const labelCutoff = releaseLabelCutoff(rel, args.now);
  const labelInfoByIssue = new Map<number, {
    labels: string[];
    currentLabels: string[];
    timelineEventCount: number;
    source: 'current' | 'timeline' | 'snapshot' | 'missing_timeline';
  }>();
  const labelInfo = (row: JoinedIssue) => {
    const cached = labelInfoByIssue.get(row.number);
    if (cached) return cached;
    const currentLabels = safeParseLabels(row.labels);
    const timelineEventCount = issueLabelEventCount(row.number);
    const snapshotCount = issueLabelSnapshotCountAt(row.number, labelCutoff);
    const labels = labelsForIssueAt(row.number, currentLabels, labelCutoff, {
      useFallbackWhenNoEvents: labelCutoff == null,
      useSnapshotWhenNoEvents: labelCutoff != null,
    });
    const source: 'current' | 'timeline' | 'snapshot' | 'missing_timeline' = labelCutoff == null
      ? 'current'
      : timelineEventCount > 0
        ? 'timeline'
        : snapshotCount > 0
          ? 'snapshot'
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
  const unclassifiedIssues = unclassifiedIssuesForVersion(rel.tag, 25);
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
  const openedRegressionRows = releaseRegressionOpenedRows(openedReign);
  const feltOpenedWeight = feltLoad(openedRegressionRows.map(feltInput));
  const feltClosedWeight = feltLoad(verifiedFixed.map(feltInput));
  const brokenSurfaces = JSON.stringify(topBrokenSurfaces(openedFeltRows.map((row) => row.title)));
  const cve = args.cveFor(rel.tag);
  const releaseCommit = getReleaseCommit(rel.tag);
  const closureProof = closureProofPayload(rel.tag, labelCutoff);
  const unresolvedClosureRiskWeight = closureRiskWeight(closureProof?.riskSummary);
  const debtSummary = {
    verified: debtTierSummary(activeDebt.evidence, 'verified'),
    carryover: debtTierSummary(activeDebt.evidence, 'carryover'),
    stale: debtTierSummary(activeDebt.evidence, 'stale'),
  };
  const input: InstallInput = {
    schemaVersion: SCORE_INPUT_SCHEMA_VERSION,
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
    verifiedDebtIssueCount: debtSummary.verified.count,
    carryoverDebtIssueCount: debtSummary.carryover.count,
    staleDebtIssueCount: debtSummary.stale.count,
    unresolvedClosureRiskWeight,
    unresolvedClosureIssueCount: Number(closureProof?.riskSummary?.unresolvedForReleaseCount ?? 0),
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
    schemaVersion: ISSUE_EVIDENCE_SCHEMA_VERSION,
    debtSummary,
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
    unclassifiedIssues: unclassifiedIssues.map((row) => ({
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
    })),
  };
  const labelTimeline = labelTimelineCoverage(
    [...attributed, ...openedReign, ...verifiedFixed, ...unverifiedClosed],
    labelInfo,
    labelCutoff,
  );
  const gateEvidence = enrichGateEvidenceWithClosureProof(rel.tag, {
    schemaVersion: GATE_EVIDENCE_SCHEMA_VERSION,
    cve,
    stableTagsNewestFirst: args.stableTagsNewestFirst,
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    hoursToNextStable: rel.hours_to_next_stable,
    hasHotfixSuccessor: input.hasHotfixSuccessor,
    releaseChecks: releaseCommit ? {
      schemaVersion: RELEASE_CHECKS_SCHEMA_VERSION,
      state: releaseCommit.check_state,
      total: releaseCommit.check_total,
      success: releaseCommit.check_success,
      failure: releaseCommit.check_failure,
      pending: releaseCommit.check_pending,
      skipped: releaseCommit.check_skipped,
      contexts: parseJsonArray(releaseCommit.check_contexts_json).slice(0, 25),
    } : null,
    artifactVerification: {
      schemaVersion: ARTIFACT_VERIFICATION_SCHEMA_VERSION,
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
      fullReleaseValidationUrl: rel.full_release_validation_url,
      releaseValidationVerified: rel.release_validation_verified === 1,
      releaseValidationMismatch: rel.release_validation_mismatch,
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
    scoredAt: new Date(args.now).toISOString(),
    conf,
    input,
    explanation: {
      schemaVersion: SCORE_EXPLANATION_SCHEMA_VERSION,
      title: 'Why not 10?',
      scoreLedger: null,
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
  const carryoverDebt = Array.isArray(evidence.carryoverDebt) ? evidence.carryoverDebt : [];
  const carryover = carryoverDebt
    .map((row: any) => row.issue)
    .filter(Boolean);
  const stale = Array.isArray(evidence.staleDebt) ? evidence.staleDebt : [];
  const verified = Array.isArray(evidence.verifiedDebt) ? evidence.verifiedDebt : [];
  const debtSummary = evidence.debtSummary ?? {};
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
    const example = issueListText(examples, 3);
    addLimit(
      'field_visible_reports_opened',
      `${opened.length} field-visible bug reports were opened in this release window; ${openedStillOpen.length} are still open.` +
      sentenceSuffix('Examples', example),
      {
        metrics: {
          openedCount: opened.length,
          stillOpenCount: openedStillOpen.length,
          closedCount: Math.max(0, opened.length - openedStillOpen.length),
        },
        issueRefs: issueRefs(examples, 5),
      },
    );
  }

  if ((input.verifiedDebtWeight ?? 0) > 0) {
    const verifiedIssues = verified
      .map((row: any) => row.issue)
      .filter(Boolean);
    const example = issueListText(verifiedIssues, 3);
    addLimit(
      'verified_field_blocker_debt',
      `There is verified field-blocker debt: release-local, field/community-confirmed high-impact issue evidence is still open. This contributes ${penaltyText(components.verifiedDebt)}; this bucket can contribute up to a ${SCORE_COMPONENT_LIMITS.verifiedDebtMaxPenalty} point penalty.` +
      sentenceSuffix('Top examples', example),
      {
        metrics: {
          count: Number(debtSummary.verified?.count ?? verified.length),
          storedExampleCount: verified.length,
          rawWeight: roundMetric(input.verifiedDebtWeight),
          storedExampleWeight: roundMetric(debtSummary.verified?.storedWeight ?? verified.reduce((sum: number, item: any) => sum + Number(item.weight ?? 0), 0)),
          cappedPenalty: Math.abs(numberOrZero(components.verifiedDebt)),
          maxPenalty: SCORE_COMPONENT_LIMITS.verifiedDebtMaxPenalty,
          capApplied: Math.abs(numberOrZero(components.verifiedDebt)) >= SCORE_COMPONENT_LIMITS.verifiedDebtMaxPenalty,
          byInstallImpactClass: debtSummary.verified?.byInstallImpactClass ?? {},
        },
        issueRefs: issueRefs(verified, 5),
      },
    );
  }

  if ((input.carryoverDebtWeight ?? 0) > 0) {
    const example = issueListText(carryover, 3);
    addLimit(
      'source_carryover_risk',
      `There is open non-verified risk: open negative issues overlapping this release are inherited, source-derived, or otherwise not proven release-local field blockers. This is context, not confirmed release-local field breakage. Provider/security/product-debt issues stay visible but are damped unless they directly affect install/runtime stability. This contributes ${penaltyText(components.carryoverDebt)}; this bucket can contribute up to a ${SCORE_COMPONENT_LIMITS.carryoverDebtMaxPenalty} point penalty.` +
      sentenceSuffix('Top examples', example),
      {
        metrics: {
          count: Number(debtSummary.carryover?.count ?? carryoverDebt.length),
          storedExampleCount: carryoverDebt.length,
          rawWeight: roundMetric(input.carryoverDebtWeight),
          storedExampleWeight: roundMetric(debtSummary.carryover?.storedWeight ?? carryoverDebt.reduce((sum: number, item: any) => sum + Number(item.weight ?? 0), 0)),
          cappedPenalty: Math.abs(numberOrZero(components.carryoverDebt)),
          maxPenalty: SCORE_COMPONENT_LIMITS.carryoverDebtMaxPenalty,
          capApplied: Math.abs(numberOrZero(components.carryoverDebt)) >= SCORE_COMPONENT_LIMITS.carryoverDebtMaxPenalty,
          byInstallImpactClass: debtSummary.carryover?.byInstallImpactClass ?? {},
        },
        issueRefs: issueRefs(carryoverDebt, 5),
      },
    );
  }

  if ((input.staleDebtWeight ?? 0) > 0) {
    const example = issueListText(stale.map((row: any) => row.issue).filter(Boolean), 3);
    addLimit(
      'stale_low_confidence_evidence',
      `${stale.length} low-confidence/stale evidence items are still tracked. This contributes ${penaltyText(components.staleDebt)}; this bucket can contribute up to a ${SCORE_COMPONENT_LIMITS.staleDebtMaxPenalty} point penalty.` +
      sentenceSuffix('Top examples', example),
      {
        metrics: {
          count: Number(debtSummary.stale?.count ?? stale.length),
          storedExampleCount: stale.length,
          rawWeight: roundMetric(input.staleDebtWeight),
          storedExampleWeight: roundMetric(debtSummary.stale?.storedWeight ?? stale.reduce((sum: number, item: any) => sum + Number(item.weight ?? 0), 0)),
          cappedPenalty: Math.abs(numberOrZero(components.staleDebt)),
          maxPenalty: SCORE_COMPONENT_LIMITS.staleDebtMaxPenalty,
          capApplied: Math.abs(numberOrZero(components.staleDebt)) >= SCORE_COMPONENT_LIMITS.staleDebtMaxPenalty,
          byInstallImpactClass: debtSummary.stale?.byInstallImpactClass ?? {},
        },
        issueRefs: issueRefs(stale, 5),
      },
    );
  }

  const missingClassificationCount = Math.max(0, Number(input.rawIssueCount ?? 0) - Number(input.classifiedIssueCount ?? 0));
  if (missingClassificationCount > 0) {
    const coveragePercent = Math.round((result.conf.evidenceCoverage ?? 0) * 100);
    const unclassified = Array.isArray(evidence.unclassifiedIssues) ? evidence.unclassifiedIssues : [];
    addLimit(
      'incomplete_classification_coverage',
      `Classification coverage is ${coveragePercent}% (${input.classifiedIssueCount}/${input.rawIssueCount}); ${missingClassificationCount} attributed issues lack current classification evidence.` +
      ` This contributes ${penaltyText(components.coverage)} until evidence is complete.`,
      {
        metrics: {
          rawIssueCount: Number(input.rawIssueCount ?? 0),
          classifiedIssueCount: Number(input.classifiedIssueCount ?? 0),
          missingClassificationCount,
          evidenceCoverage: roundMetric(result.conf.evidenceCoverage ?? 0),
          cappedPenalty: Math.abs(numberOrZero(components.coverage)),
        },
        issueRefs: issueRefs(unclassified, 5),
      },
    );
  }

  const fix = gate.fixProvenance ?? {};
  const closureProof = fix.closureProof;
  const closureRiskSummary = closureProof?.riskSummary ?? {};
  const unresolvedClosureCount = Number(closureRiskSummary.unresolvedForReleaseCount ?? 0);
  const unresolvedClosureWeight = Number(closureRiskSummary.unresolvedWeightedRisk ?? 0);
  if (closureProof?.notCreditedCount > 0 && (unresolvedClosureCount > 0 || unresolvedClosureWeight > 0)) {
    const bucketText = closureProofSummaryText(closureProof);
    const riskText = closureRiskSummaryText(closureProof);
    const buckets = proofBucketsExceptFixed(closureProof.byStatus);
    const riskBuckets = proofBucketsExceptFixed(closureProof.byRiskDisposition, [
      'credited_release_fix',
      'resolved_by_canonical_release_fix',
      'resolved_by_release_fix_proof',
    ]);
    const riskSummary = closureProof.riskSummary ?? {};
    const neutralAuditRefs = issueRefs(closureProof.neutralAuditExamples ?? [], 2);
    const primaryIssueRefLimit = Math.max(3, 5 - neutralAuditRefs.length);
    const closureExamples = closureProofExamplesForExplanation(closureProof, primaryIssueRefLimit);
    const closureIssueRefs = mergeIssueRefs(
      issueRefs(closureExamples, primaryIssueRefLimit),
      neutralAuditRefs,
      5,
    );
    addLimit(
      'closed_issues_not_counted_as_release_fixes',
      `${unresolvedClosureCount} closed issues in this release window still carry unresolved release risk after proof checks.` +
      ` ${closureProof.notCreditedCount} total closed issues are not direct release-fix credit, including not-scored or non-actionable closures.` +
      ` This contributes ${penaltyText(components.closureRisk)}; this bucket can contribute up to a ${SCORE_COMPONENT_LIMITS.closureRiskMaxPenalty} point penalty.` +
      ((components.closureRiskCeiling ?? 0) > 0 ? ` Because closure risk weight is at least ${SCORE_COMPONENT_LIMITS.heavyClosureRiskThreshold}, heavy unresolved closure risk caps the final score at ${components.closureRiskCeiling}.` : '') +
      ((Number(riskSummary.neutralHighImpactCount ?? 0) > 0 || Number(riskSummary.neutralBugShapedCount ?? 0) > 0)
        ? ` Audit-only closure flags: ${Number(riskSummary.neutralHighImpactCount ?? 0)} high-impact and ${Number(riskSummary.neutralBugShapedCount ?? 0)} bug-shaped not-scored closures were left out of the scored closure penalty; review them separately.`
        : '') +
      (riskText ? ` Risk split: ${riskText}.` : '') +
      (bucketText ? ` Breakdown: ${bucketText}.` : ''),
      {
        metrics: {
          countedClosedCount: Number(closureProof.creditedCount ?? 0),
          notCountedClosedCount: Number(closureProof.notCreditedCount ?? 0),
          analyzedClosedCount: Number(closureProof.analyzedClosedCount ?? 0),
          unresolvedForReleaseCount: Number(riskSummary.unresolvedForReleaseCount ?? 0),
          unresolvedClosureRiskWeight: roundMetric(input.unresolvedClosureRiskWeight),
          cappedPenalty: Math.abs(numberOrZero(components.closureRisk)),
          maxPenalty: SCORE_COMPONENT_LIMITS.closureRiskMaxPenalty,
          capApplied: Math.abs(numberOrZero(components.closureRisk)) >= SCORE_COMPONENT_LIMITS.closureRiskMaxPenalty,
          scoreCeiling: Number(components.closureRiskCeiling ?? 0) || null,
          heavyClosureRiskThreshold: SCORE_COMPONENT_LIMITS.heavyClosureRiskThreshold,
          resolvedByCanonicalReleaseFixCount: Number(riskSummary.resolvedByCanonicalReleaseFixCount ?? 0),
          resolvedByReleaseFixProofCount: Number(riskSummary.resolvedByReleaseFixProofCount ?? 0),
          knownNotInReleaseCount: Number(riskSummary.knownNotInReleaseCount ?? 0),
          openCanonicalRiskCount: Number(riskSummary.openCanonicalRiskCount ?? 0),
          unsupportedClosureClaimCount: Number(riskSummary.unsupportedClosureClaimCount ?? 0),
          neutralOrNonActionableCount: Number(riskSummary.neutralOrNonActionableCount ?? 0),
          neutralHighImpactCount: Number(riskSummary.neutralHighImpactCount ?? 0),
          neutralBugShapedCount: Number(riskSummary.neutralBugShapedCount ?? 0),
          missingEvidenceCount: Number(riskSummary.missingEvidenceCount ?? 0),
        },
        buckets,
        riskBuckets,
        issueRefs: closureIssueRefs,
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
      {
        metrics: {
          artifactVerified: true,
          releaseShaMatches: artifact.releaseShaMatches === true,
          ciReportVerified: artifact.ciReportVerified === true,
          releaseValidationVerified: artifact.releaseValidationVerified === true,
        },
      },
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
    scoreLedger: buildScoreLedger(result),
    positives,
    positiveDetails,
    limits,
    limitDetails,
    verdict: installVerdictText(result.conf.status, recommended),
  };
}

function buildScoreLedger(result: ReleaseScoreResult): ScoreExplanationLedger | null {
  const components = result.conf.components;
  if (!components) return buildGateScoreLedger(result);
  const input = result.input;
  let rows: ScoreExplanationLedgerRow[] = [
    {
      key: 'base',
      label: 'Base',
      points: roundMetric(components.base),
      kind: 'base',
      note: 'Starting confidence for an eligible stable before evidence adjustments.',
    },
    {
      key: 'verifiedDebt',
      label: 'Field blocker debt',
      points: roundMetric(components.verifiedDebt),
      kind: scoreLedgerKind(components.verifiedDebt),
      metric: roundMetric(input.verifiedDebtWeight),
      note: 'Release-local field/community blocker evidence.',
    },
    {
      key: 'carryoverDebt',
      label: 'Open non-verified risk',
      points: roundMetric(components.carryoverDebt),
      kind: scoreLedgerKind(components.carryoverDebt),
      metric: roundMetric(input.carryoverDebtWeight),
      note: 'Open negative issue debt overlapping this release that is inherited, source-derived, or otherwise not proven release-local field-blocker evidence.',
    },
    {
      key: 'staleDebt',
      label: 'Stale/low-confidence risk',
      points: roundMetric(components.staleDebt),
      kind: scoreLedgerKind(components.staleDebt),
      metric: roundMetric(input.staleDebtWeight),
      note: 'Weak or stale evidence risk, heavily capped.',
    },
    {
      key: 'closureRisk',
      label: 'Closed-release risk',
      points: roundMetric(components.closureRisk),
      kind: scoreLedgerKind(components.closureRisk),
      metric: roundMetric(input.unresolvedClosureRiskWeight),
      note: 'Closed issues not proven fixed in this release tag.',
    },
    {
      key: 'coverage',
      label: 'Classification coverage',
      points: roundMetric(components.coverage),
      kind: scoreLedgerKind(components.coverage),
      metric: `${input.classifiedIssueCount}/${input.rawIssueCount}`,
      note: 'Penalty only when attributed issue classification coverage is incomplete.',
    },
    {
      key: 'survival',
      label: 'Stable survival',
      points: roundMetric(components.survival),
      kind: scoreLedgerKind(components.survival),
      metric: input.hoursToNextStable == null ? null : roundMetric(input.hoursToNextStable),
      note: 'Reward for standing without a quick stable hotfix replacement.',
    },
    {
      key: 'shakeout',
      label: 'Beta shakeout',
      points: roundMetric(components.shakeout),
      kind: scoreLedgerKind(components.shakeout),
      metric: input.betaCount,
      note: 'Small reward for beta/prerelease bake time.',
    },
    {
      key: 'regression',
      label: 'Opened vs fixed balance',
      points: roundMetric(components.regression),
      kind: scoreLedgerKind(components.regression),
      metric: `${roundMetric(input.feltOpenedWeight)} opened / ${roundMetric(input.feltClosedWeight)} fixed`,
      note: 'Field-visible regressions opened versus verified fixes in the release window.',
    },
    {
      key: 'breaking',
      label: 'Breaking changes',
      points: roundMetric(components.breaking),
      kind: scoreLedgerKind(components.breaking),
      metric: input.breakingCount,
      note: 'Penalty for documented breaking changes in the stable/beta chain.',
    },
    {
      key: 'releaseVerification',
      label: 'Release checks',
      points: roundMetric(components.releaseVerification),
      kind: scoreLedgerKind(components.releaseVerification),
      metric: `${input.releaseCheckSuccess ?? 0} passed / ${input.releaseCheckFailure ?? 0} failed / ${input.releaseCheckPending ?? 0} pending`,
      note: 'Release commit check confidence.',
    },
    {
      key: 'artifactVerification',
      label: 'Artifact verification',
      points: roundMetric(components.artifactVerification),
      kind: scoreLedgerKind(components.artifactVerification),
      metric: input.artifactVerified ? 'verified' : input.artifactMismatch ? 'mismatch' : 'not verified',
      note: 'npm package and release artifact integrity evidence.',
    },
  ];
  let subtotalBeforeCaps = scoreLedgerSubtotal(rows);
  let caps = scoreLedgerCaps(result, subtotalBeforeCaps);
  let scoreAfterCaps = caps.length ? caps[caps.length - 1].after ?? subtotalBeforeCaps : subtotalBeforeCaps;
  if (typeof result.conf.score === 'number') {
    const adjustment = roundMetric(result.conf.score - scoreAfterCaps);
    if (Math.abs(adjustment) > 0) {
      rows = [
        ...rows,
        {
          key: 'precisionAdjustment',
          label: 'Unrounded model adjustment',
          points: adjustment,
          kind: scoreLedgerKind(adjustment),
          note: 'Reconciles displayed one-decimal components with the unrounded score calculation.',
        },
      ];
      subtotalBeforeCaps = scoreLedgerSubtotal(rows);
      caps = scoreLedgerCaps(result, subtotalBeforeCaps);
      scoreAfterCaps = caps.length ? caps[caps.length - 1].after ?? subtotalBeforeCaps : subtotalBeforeCaps;
    }
  }
  return {
    schemaVersion: 1,
    finalScore: result.conf.score,
    status: result.conf.status,
    band: result.conf.band,
    subtotalBeforeCaps,
    scoreAfterCaps,
    rows,
    caps,
  };
}

function buildGateScoreLedger(result: ReleaseScoreResult): ScoreExplanationLedger {
  const input = result.input;
  const row: ScoreExplanationLedgerRow = result.conf.status === 'skip-cve'
    ? {
      key: 'cveGate',
      label: 'CVE safety gate',
      points: roundMetric(result.conf.score ?? 0),
      kind: 'penalty',
      metric: roundMetric(input.cveLoad),
      note: 'Known medium-or-higher CVE exposure activates a hard skip gate; score is bounded below normal install confidence.',
    }
    : {
      key: 'settleGate',
      label: 'Settle-time gate',
      points: 0,
      kind: 'neutral',
      metric: input.publishedAt,
      note: 'Release is not scored until it has had enough time to settle.',
    };
  const subtotalBeforeCaps = result.conf.score == null ? null : row.points;
  return {
    schemaVersion: 1,
    finalScore: result.conf.score,
    status: result.conf.status,
    band: result.conf.band,
    subtotalBeforeCaps,
    scoreAfterCaps: subtotalBeforeCaps,
    rows: [row],
    caps: [],
  };
}

function scoreLedgerSubtotal(rows: ScoreExplanationLedgerRow[]): number {
  return roundMetric(rows.reduce((sum, row) => sum + row.points, 0));
}

function scoreLedgerCaps(result: ReleaseScoreResult, subtotalBeforeCaps: number): ScoreExplanationCap[] {
  const components = result.conf.components;
  const caps: ScoreExplanationCap[] = [];
  let scoreAfterCaps = subtotalBeforeCaps;
  if (components && components.closureRiskCeiling > 0) {
    const after = roundMetric(Math.min(scoreAfterCaps, components.closureRiskCeiling));
    caps.push({
      key: 'closureRiskCeiling',
      label: 'Heavy closure-risk ceiling',
      ceiling: roundMetric(components.closureRiskCeiling),
      applied: scoreAfterCaps > components.closureRiskCeiling,
      before: scoreAfterCaps,
      after,
      reason: 'Heavy unresolved closed-release risk prevents a solid score.',
    });
    scoreAfterCaps = after;
  }
  if (result.conf.status === 'skip-hotfix') {
    const hotfixCeiling = 4.9;
    const after = roundMetric(Math.min(scoreAfterCaps, hotfixCeiling));
    caps.push({
      key: 'hotfixCeiling',
      label: 'Hotfix successor ceiling',
      ceiling: hotfixCeiling,
      applied: scoreAfterCaps > hotfixCeiling,
      before: scoreAfterCaps,
      after,
      reason: 'A release replaced quickly by a later stable is not an install target.',
    });
    scoreAfterCaps = after;
  }
  return caps;
}

function scoreLedgerKind(points: number): ScoreExplanationLedgerRow['kind'] {
  if (points > 0) return 'bonus';
  if (points < 0) return 'penalty';
  return 'neutral';
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
      tier: item?.tier ?? null,
      weight: typeof item?.weight === 'number' ? roundMetric(item.weight) : null,
      installImpactClass: item?.installImpactClass ?? null,
      installImpactMultiplier: typeof item?.installImpactMultiplier === 'number' ? roundMetric(item.installImpactMultiplier) : null,
      proof: issueRefProof(item),
    }))
    .filter((item) => Number.isInteger(item.number) && item.number > 0 && item.title.length > 0);
}

function issueRefProof(item: any): ScoreExplanationIssueProof | null {
  const status = typeof item?.status === 'string' && item.status ? item.status : null;
  const summary = typeof item?.summary === 'string' && item.summary ? item.summary : null;
  const riskDisposition = typeof item?.riskDisposition === 'string' && item.riskDisposition
    ? item.riskDisposition
    : status ? closureRiskDisposition(status) : null;
  const evidence = item?.evidence && typeof item.evidence === 'object' ? item.evidence : {};
  const canonicalResolution = evidence.canonicalResolution && typeof evidence.canonicalResolution === 'object'
    ? evidence.canonicalResolution
    : null;
  const canonicalIssue = linkedIssueRef(canonicalResolution?.terminalIssue) ??
    linkedIssueRef(Array.isArray(evidence.canonicalIssueDetails) ? evidence.canonicalIssueDetails[0] : null);
  const canonicalPath = Array.isArray(canonicalResolution?.path)
    ? canonicalResolution.path.filter((number: unknown): number is number => Number.isInteger(number) && Number(number) > 0)
    : null;
  const relatedPrContext = evidence.relatedPrContext && typeof evidence.relatedPrContext === 'object'
    ? evidence.relatedPrContext
    : {};
  const openPrs = linkedRefs([
    ...(Array.isArray(evidence.canonicalOpenPrs) ? evidence.canonicalOpenPrs : []),
    ...(Array.isArray(evidence.relatedOpenPrs) ? evidence.relatedOpenPrs : []),
    ...(Array.isArray(relatedPrContext.open) ? relatedPrContext.open : []),
  ], 3);
  const reachablePrs = linkedRefs(Array.isArray(relatedPrContext.reachable) ? relatedPrContext.reachable : [], 3);
  const notReachablePrs = linkedRefs(Array.isArray(relatedPrContext.notReachable) ? relatedPrContext.notReachable : [], 3);
  const riskWeight = typeof item?.riskWeight === 'number' ? roundMetric(item.riskWeight) : null;
  if (!status && !summary && !riskDisposition && riskWeight == null && !canonicalIssue &&
    !openPrs.length && !reachablePrs.length && !notReachablePrs.length) {
    return null;
  }
  return {
    status,
    statusLabel: status ? closureStatusLabel(status) : null,
    riskDisposition,
    riskDispositionLabel: riskDisposition ? closureRiskDispositionLabel(riskDisposition) : null,
    summary,
    riskWeight,
    canonicalIssue,
    canonicalPath,
    openPrs,
    reachablePrs,
    notReachablePrs,
  };
}

function linkedRefs(values: unknown[], limit: number): ScoreExplanationLinkedRef[] {
  const seen = new Set<number>();
  const refs: ScoreExplanationLinkedRef[] = [];
  for (const value of values) {
    const ref = linkedIssueRef(value);
    if (!ref || seen.has(ref.number)) continue;
    seen.add(ref.number);
    refs.push(ref);
    if (refs.length >= limit) break;
  }
  return refs;
}

function linkedIssueRef(value: unknown): ScoreExplanationLinkedRef | null {
  if (!value || typeof value !== 'object') return null;
  const raw = value as any;
  const number = Number(raw.number ?? raw.issueNumber ?? raw.prNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : typeof raw.html_url === 'string' ? raw.html_url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
    status: typeof raw.reachabilityStatus === 'string' ? raw.reachabilityStatus : typeof raw.status === 'string' ? raw.status : null,
  };
}

function closureProofExamplesWithStatusCoverage(closureProof: any): any[] {
  const seen = new Set<number>();
  const merged: any[] = [];
  const add = (item: any) => {
    const number = Number(item?.number ?? item?.issue?.number);
    if (!Number.isInteger(number) || number <= 0 || seen.has(number)) return;
    seen.add(number);
    merged.push(item);
  };
  for (const item of closureProof?.examples ?? []) add(item);
  const examplesByStatus = closureProof?.examplesByStatus ?? {};
  if (examplesByStatus && typeof examplesByStatus === 'object') {
    for (const examples of Object.values(examplesByStatus)) {
      if (!Array.isArray(examples)) continue;
      for (const item of examples) add(item);
    }
  }
  return merged;
}

const CLOSURE_EXPLANATION_DISPOSITION_ORDER = [
  'open_canonical_risk',
  'known_not_in_release',
  'unsupported_closure_claim',
  'missing_evidence',
  'neutral_or_non_actionable',
  'resolved_by_canonical_release_fix',
  'resolved_by_release_fix_proof',
];

const CLOSURE_EXPLANATION_STATUS_PREFERENCE: Record<string, string[]> = {
  open_canonical_risk: [
    'duplicate_to_open_canonical',
    'superseded_to_open_pr',
    'duplicate_with_open_pr_context',
    'not_planned_with_open_pr_context',
    'related_open_pr_context',
  ],
  known_not_in_release: [
    'fixed_after_latest_release',
    'fixed_in_later_release',
    'fixed_after_release',
    'fixed_not_in_scored_releases',
    'main_only_claim',
    'duplicate_to_known_not_in_release_canonical',
  ],
  unsupported_closure_claim: [
    'admin_not_planned_no_context',
    'admin_not_planned_unverified',
    'already_present_claim',
    'closed_without_release_fix_proof',
    'no_code_proof',
    'duplicate_to_closed_canonical_missing_proof',
    'duplicate_or_superseded',
    'repro_requested',
    'insufficient_info',
  ],
  missing_evidence: [
    'no_timeline_event',
    'unknown',
    'linked_closing_pr_reachability_unknown',
    'duplicate_to_closed_canonical_missing_proof',
  ],
  resolved_by_release_fix_proof: [
    'duplicate_with_release_fix_proof',
    'not_planned_with_release_fix_proof',
  ],
};

function closureProofExamplesForExplanation(closureProof: any, limit: number): any[] {
  const cap = Math.max(0, limit);
  if (cap <= 0) return [];
  const candidates = closureProofExamplesWithStatusCoverage(closureProof)
    .filter((item: any) => item.status !== 'fixed_in_release');
  const selected: any[] = [];
  const seen = new Set<number>();
  const add = (item: any) => {
    const number = Number(item?.number ?? item?.issue?.number);
    if (!Number.isInteger(number) || number <= 0 || seen.has(number) || selected.length >= cap) return;
    seen.add(number);
    selected.push(item);
  };
  const byDisposition = new Map<string, any>();
  for (const item of candidates) {
    const disposition = typeof item?.riskDisposition === 'string' && item.riskDisposition
      ? item.riskDisposition
      : typeof item?.status === 'string' ? closureRiskDisposition(item.status) : null;
    if (disposition && !byDisposition.has(disposition)) byDisposition.set(disposition, item);
  }
  const dispositionCounts = closureProof?.byRiskDisposition && typeof closureProof.byRiskDisposition === 'object'
    ? closureProof.byRiskDisposition
    : {};
  for (const disposition of CLOSURE_EXPLANATION_DISPOSITION_ORDER) {
    if (Number(dispositionCounts[disposition] ?? 0) > 0) {
      add(preferredClosureExampleForDisposition(disposition, candidates) ?? byDisposition.get(disposition));
    }
  }
  for (const [disposition, count] of Object.entries(dispositionCounts)) {
    if (CLOSURE_EXPLANATION_DISPOSITION_ORDER.includes(disposition)) continue;
    if (Number(count ?? 0) > 0) {
      add(preferredClosureExampleForDisposition(disposition, candidates) ?? byDisposition.get(disposition));
    }
  }
  for (const item of candidates) add(item);
  return selected;
}

function preferredClosureExampleForDisposition(disposition: string, candidates: any[]): any | null {
  const preferredStatuses = CLOSURE_EXPLANATION_STATUS_PREFERENCE[disposition] ?? [];
  for (const status of preferredStatuses) {
    const match = candidates.find((item) => item?.status === status && (
      item?.riskDisposition === disposition || closureRiskDisposition(String(item?.status ?? '')) === disposition
    ));
    if (match) return match;
  }
  return null;
}

function debtTierSummary(items: any[], tier: 'verified' | 'carryover' | 'stale'): {
  count: number;
  weight: number;
  storedWeight: number;
  byInstallImpactClass: Record<string, number>;
} {
  const tierItems = items.filter((item) => item.tier === tier);
  const byInstallImpactClass: Record<string, number> = {};
  for (const item of tierItems) {
    const key = String(item.installImpactClass ?? 'unknown');
    byInstallImpactClass[key] = (byInstallImpactClass[key] ?? 0) + 1;
  }
  return {
    count: tierItems.length,
    weight: roundMetric(tierItems.reduce((sum, item) => sum + Number(item.weight ?? 0), 0)),
    storedWeight: roundMetric(tierItems.slice(0, 25).reduce((sum, item) => sum + Number(item.weight ?? 0), 0)),
    byInstallImpactClass,
  };
}

function mergeIssueRefs(
  primary: ScoreExplanationIssueRef[],
  secondary: ScoreExplanationIssueRef[],
  limit: number,
): ScoreExplanationIssueRef[] {
  const seen = new Set<number>();
  const merged: ScoreExplanationIssueRef[] = [];
  for (const issue of [...primary, ...secondary]) {
    if (!Number.isInteger(issue.number) || seen.has(issue.number)) continue;
    seen.add(issue.number);
    merged.push(issue);
    if (merged.length >= limit) break;
  }
  return merged;
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
    source: 'current' | 'timeline' | 'snapshot' | 'missing_timeline';
  },
  cutoffAt: string | null,
): Record<string, unknown> {
  const byIssue = new Map<number, JoinedIssue>();
  for (const row of rows) byIssue.set(row.number, row);
  let current = 0;
  let timeline = 0;
  let snapshot = 0;
  let missingTimeline = 0;
  let missingTimelineWithCurrentLabels = 0;
  for (const row of byIssue.values()) {
    const info = labelInfo(row);
    if (info.source === 'current') current++;
    else if (info.source === 'timeline') timeline++;
    else if (info.source === 'snapshot') snapshot++;
    else {
      missingTimeline++;
      if (info.currentLabels.length > 0) missingTimelineWithCurrentLabels++;
    }
  }
  return {
    schemaVersion: LABEL_TIMELINE_SCHEMA_VERSION,
    cutoffAt,
    issueCount: byIssue.size,
    currentLabelCount: current,
    timelineLabelCount: timeline,
    snapshotLabelCount: snapshot,
    missingTimelineCount: missingTimeline,
    missingTimelineWithCurrentLabelsCount: missingTimelineWithCurrentLabels,
    historicalCurrentLabelFallbackAllowed: cutoffAt == null,
  };
}

function proofBucketsExceptFixed(buckets: unknown, fixedKey: string | string[] = 'fixed_in_release'): Record<string, number> {
  if (!buckets || typeof buckets !== 'object' || Array.isArray(buckets)) return {};
  const fixedKeys = new Set(Array.isArray(fixedKey) ? fixedKey : [fixedKey]);
  const entries = Object.entries(buckets as Record<string, unknown>)
    .filter(([status]) => !fixedKeys.has(status))
    .map(([status, count]) => [status, Number(count)] as const)
    .filter(([, count]) => Number.isFinite(count) && count > 0);
  return Object.fromEntries(entries);
}

function closureRiskWeight(riskSummary: any): number {
  if (!riskSummary || typeof riskSummary !== 'object') return 0;
  return numberOrZero(riskSummary.unresolvedWeightedRisk);
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
    [risk.resolvedByCanonicalReleaseFixCount, 'resolved by canonical release fix'],
    [risk.resolvedByReleaseFixProofCount, 'resolved by release fix proof'],
    [risk.knownNotInReleaseCount, 'known not in this tag'],
    [risk.openCanonicalRiskCount, 'still-open canonical/PR risk'],
    [risk.unsupportedClosureClaimCount, 'unsupported closure claim/admin triage'],
    [risk.missingEvidenceCount, 'missing proof evidence'],
    [risk.neutralOrNonActionableCount, 'not-scored/non-actionable closure'],
    [risk.neutralHighImpactCount, 'high-impact not-scored audit flag'],
    [risk.neutralBugShapedCount, 'bug-shaped not-scored audit flag'],
  ];
  return parts
    .filter(([count]) => Number(count ?? 0) > 0)
    .map(([count, label]) => `${count} ${label}`)
    .join(' · ');
}

function closureRiskDispositionLabel(disposition: string): string {
  return ({
    credited_release_fix: 'credited release fix',
    resolved_by_canonical_release_fix: 'resolved by canonical release fix',
    resolved_by_release_fix_proof: 'resolved by release fix proof',
    known_not_in_release: 'known not in this tag',
    open_canonical_risk: 'still open canonical/PR risk',
    unsupported_closure_claim: 'unsupported closure claim',
    neutral_or_non_actionable: 'not scored/non-actionable',
    missing_evidence: 'missing evidence',
  } as Record<string, string>)[disposition] ?? String(disposition ?? 'unknown').replace(/_/g, ' ');
}

function closureStatusLabel(status: string): string {
  return ({
    fixed_in_release: 'fixed in this release',
    fixed_after_release: 'fixed after this release',
    fixed_in_later_release: 'fixed in later release',
    fixed_not_in_scored_releases: 'fixed outside scored releases',
    fixed_after_latest_release: 'fixed after latest release',
    fixed_skipped_by_later_releases: 'fix skipped by later releases',
    duplicate_to_fixed_in_release: 'canonical fixed in this release',
    duplicate_to_open_canonical: 'moved to open canonical',
    duplicate_to_closed_canonical: 'moved to closed canonical',
    duplicate_to_non_actionable_canonical: 'canonical non-actionable',
    duplicate_to_known_not_in_release_canonical: 'canonical not in this release',
    duplicate_to_open_pr_canonical: 'canonical open PR context',
    duplicate_to_unverified_closed_canonical: 'canonical unresolved closure',
    duplicate_to_closed_canonical_missing_proof: 'closed canonical proof missing',
    duplicate_to_fixed_after_release: 'canonical fixed after this release',
    duplicate_with_release_fix_proof: 'duplicate with release proof',
    superseded_to_open_pr: 'moved to open PR',
    duplicate_with_open_pr_context: 'related open PR context',
    duplicate_related_closed_unmerged_pr_context: 'duplicate related PR closed unmerged',
    duplicate_related_merged_pr_not_reachable_context: 'duplicate related PR not in tag',
    duplicate_related_merged_pr_reachable_context_without_fix_credit: 'duplicate related PR in tag, no fix credit',
    duplicate_related_merged_pr_reachability_unknown: 'duplicate related PR reachability unknown',
    duplicate_related_pr_without_release_fix: 'duplicate related PR without release-fix proof',
    canonical_cycle_or_self_reference: 'bad canonical reference',
    duplicate_or_superseded: 'duplicate/superseded',
    already_present_claim: 'already-present claim',
    admin_not_planned_unverified: 'unverified admin not-planned',
    admin_not_planned_no_context: 'admin not-planned without close context',
    not_planned_with_release_fix_proof: 'not-planned with release proof',
    not_planned_fixed_after_release: 'not-planned fixed after this release',
    not_planned_with_open_pr_context: 'not-planned with open PR context',
    not_planned_linked_pr_not_merged: 'not-planned linked PR not merged',
    not_planned_related_closed_unmerged_pr_context: 'not-planned related PR closed unmerged',
    not_planned_related_merged_pr_not_reachable_context: 'not-planned related PR not in tag',
    not_planned_related_merged_pr_reachable_context_without_fix_credit: 'not-planned related PR in tag, no fix credit',
    not_planned_related_merged_pr_reachability_unknown: 'not-planned related PR reachability unknown',
    not_planned_related_pr_without_release_fix: 'not-planned related PR without release-fix proof',
    main_only_claim: 'main-only claim',
    reporter_replaced: 'reporter refiled/replaced',
    reporter_withdrawn: 'reporter withdrew',
    repro_requested: 'fresh repro requested',
    insufficient_info: 'insufficient repro info',
    reporter_self_closed: 'reporter self-closed',
    no_code_proof: 'no linked release fix',
    linked_closing_pr_reachability_unknown: 'merged closing PR reachability unknown',
    linked_closing_pr_not_merged: 'linked PR not merged',
    linked_closing_pr_open: 'linked PR still open',
    linked_closing_pr_closed_unmerged: 'linked PR closed unmerged',
    external_repo_closing_pr_unscored: 'external repo closing PR unscored',
    related_open_pr_context: 'related PR open',
    related_closed_unmerged_pr_context: 'related PR closed unmerged',
    related_merged_pr_not_reachable_context: 'related merged PR not in tag',
    related_merged_pr_reachable_context_without_fix_credit: 'related PR in tag, no fix credit',
    related_merged_pr_reachability_unknown: 'related merged PR reachability unknown',
    related_pr_without_release_fix: 'related PR without release-fix proof',
    closed_without_release_fix_proof: 'closed without release-fix proof',
    no_timeline_event: 'close event not fetched',
    non_bug_fixed_in_release: 'not bug evidence: fixed in release',
    non_bug_fixed_after_release: 'not bug evidence: fixed after release',
    non_bug_fixed_in_later_release: 'not bug evidence: fixed in later release',
    non_bug_fixed_not_in_scored_releases: 'not bug evidence: fixed outside scored releases',
    non_bug_fixed_after_latest_release: 'not bug evidence: fixed after latest',
    non_bug_fixed_skipped_by_later_releases: 'not bug evidence: skipped by later releases',
    non_bug_linked_without_merge: 'not bug evidence: unmerged link',
    non_bug_linked_pr_open: 'not bug evidence: linked PR open',
    non_bug_linked_pr_closed_unmerged: 'not bug evidence: linked PR closed unmerged',
    non_bug_duplicate_to_fixed_in_release: 'not bug evidence: canonical fixed in release',
    non_bug_duplicate_to_open_canonical: 'not bug evidence: open canonical',
    non_bug_duplicate_to_closed_canonical: 'not bug evidence: closed canonical',
    non_bug_duplicate_to_closed_canonical_missing_proof: 'not bug evidence: canonical proof missing',
    non_bug_duplicate_to_fixed_after_release: 'not bug evidence: canonical fixed after release',
    non_bug_superseded_to_open_pr: 'not bug evidence: open PR context',
    non_bug_duplicate_with_open_pr_context: 'not bug evidence: related open PR context',
    non_bug_duplicate_related_closed_unmerged_pr_context: 'not bug evidence: duplicate related PR closed unmerged',
    non_bug_duplicate_related_merged_pr_not_reachable_context: 'not bug evidence: duplicate related PR not in tag',
    non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit: 'not bug evidence: duplicate related PR in tag, no fix credit',
    non_bug_duplicate_related_merged_pr_reachability_unknown: 'not bug evidence: duplicate related PR reachability unknown',
    non_bug_duplicate_related_pr_without_release_fix: 'not bug evidence: duplicate related PR without release-fix proof',
    non_bug_duplicate_or_superseded: 'not bug evidence: duplicate/superseded',
    non_bug_not_actionable: 'not bug evidence: concrete non-actionable',
    non_bug_neutral: 'not bug evidence',
    not_planned: 'concrete non-actionable',
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
  const rawTitle = String(issue?.title ?? '').trim();
  const title = rawTitle.replace(/^\[bug\]:?\s*/i, '').trim() || rawTitle || 'untitled report';
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
  buildScoreExplanation,
  releaseRegressionOpenedRows,
  shortIssueTitle,
  truncateAtWordBoundary,
};

function releaseRegressionOpenedRows<T extends { state?: string | null }>(rows: T[]): T[] {
  return rows.filter((row) => row.state !== 'open');
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
