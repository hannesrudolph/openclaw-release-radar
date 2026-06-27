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
import { enrichGateEvidenceWithClosureProof } from './closureProofPayload';
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
  title: string;
  positives: string[];
  limits: string[];
  verdict: string;
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
    fixProvenance: {
      verifiedFixedCount: verifiedFixed.length,
      unverifiedClosedCount: unverifiedClosed.length,
    },
  });

  return {
    rel,
    conf,
    input,
    explanation: { title: 'Why not 10?', positives: [], limits: [], verdict: '' },
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

  if (opened.length) {
    const example = issueListText(openedStillOpen.length ? openedStillOpen : opened);
    limits.push(
      `${opened.length} field-visible bug reports were opened in this release window; ${openedStillOpen.length} are still open.` +
      (example ? ` Examples: ${example}.` : ''),
    );
  }

  if ((input.carryoverDebtWeight ?? 0) > 0) {
    const example = issueListText(carryover);
    limits.push(
      `There is unresolved source/carryover risk, weighted by install impact. Provider/security/product-debt issues stay visible but are damped unless they directly affect install/runtime stability. This bucket is capped at ${penaltyText(components.carryoverDebt)}.` +
      (example ? ` Top examples: ${example}.` : ''),
    );
  }

  if ((input.staleDebtWeight ?? 0) > 0) {
    limits.push(`${stale.length} low-confidence/stale evidence items are still tracked, capped at ${penaltyText(components.staleDebt)}.`);
  }

  const fix = gate.fixProvenance ?? {};
  const closureProof = fix.closureProof;
  if (closureProof?.notCreditedCount > 0) {
    const bucketText = closureProofSummaryText(closureProof);
    limits.push(
      `${closureProof.notCreditedCount} closed issues in this release window are not counted as release fixes.` +
      (bucketText ? ` Breakdown: ${bucketText}.` : ''),
    );
  } else if ((fix.unverifiedClosedCount ?? 0) > 0) {
    limits.push(`${fix.unverifiedClosedCount} closed issues are not counted as fixes yet because release-tag reachability has not been analyzed for them.`);
  }

  const artifact = gate.artifactVerification;
  if (artifact?.ciReportMismatch) {
    limits.push(`The npm package is verified, but the linked full release evidence report is missing: ${artifact.ciReportMismatch}.`);
  }

  if (!limits.length && !verified.length) {
    limits.push('No field-blocker evidence is currently holding this release down; the remaining gap comes from the model ceiling and capped confidence signals.');
  }

  const positives: string[] = [];
  if (!verified.length) positives.push('No verified field-blocker debt is currently scoring against this release.');
  const checks = gate.releaseChecks;
  if (checks?.failure === 0 && checks?.success > 0) positives.push(`${checks.success} release checks passed with no failed checks.`);
  if (artifact?.verified) positives.push('The npm package integrity, tarball, and release SHA match.');
  if (recommended) positives.push('The release is eligible and recommended.');
  else if (result.conf.status === 'eligible') positives.push('The release passed hard install gates.');

  return {
    title: 'Why not 10?',
    positives,
    limits,
    verdict: installVerdictText(result.conf.status, recommended),
  };
}

function installVerdictText(status: string, recommended: boolean): string {
  if (recommended) {
    return 'This means the release looks safe to install, but the audit still contains field reports, source-derived risk, or closed issues that are not tied to this release tag, so the model will not score it as flawless.';
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

function issueRef(issue: any): string {
  if (!issue?.number) return '';
  return `#${issue.number} ${shortIssueTitle(issue)}`;
}

function shortIssueTitle(issue: any): string {
  const title = String(issue?.title ?? '').replace(/^\[bug\]:?\s*/i, '').trim();
  return title.length > 88 ? `${title.slice(0, 85)}...` : title;
}

function penaltyText(value: unknown): string {
  if (typeof value !== 'number') return 'a 0 point penalty';
  const abs = Math.abs(value);
  return `a ${abs} point penalty`;
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
