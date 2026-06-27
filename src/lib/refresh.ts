import { config } from '../config';
import { invalidateCache } from './cache';
import {
  GhComment,
  GhIssue,
  getReleaseCommit as fetchReleaseCommit,
  listIssueCommentsBatch,
  listIssueLabelEventsBatch,
  listReleases,
  listSecurityAdvisories,
  paginateIssues,
} from './github';
import { classifyIssue, type IssueClassification, PROMPT_VERSION } from './llm';
import { applyLabelOverrides, applyTitleFunctionalityHint, applyTitleIssueShapeHint } from './labelOverrides';
import {
  computeAggregateBreaking,
  computeBetaCount,
  computeHoursToNextRelease,
  computeHoursToNextStable,
  hasHotfixSuccessor,
  parseReleaseNotes,
} from './releaseNotes';
import { verifyNpmArtifact } from './npmRegistry';
import { verifyEvidenceReportUrl } from './releaseEvidence';
import { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } from './closureProofAnalysis';
import { checkReleasePrReachability } from './releaseReachability';
import { matchesRange, stableDistance } from './versionMatch';
import { topBrokenSurfaces } from './surfaces';

// Limited concurrency for LLM classification. During scoring calibration we may
// intentionally raise this through CLASSIFY_CONCURRENCY to burn tokens for speed.
const CLASSIFY_CONCURRENCY = config.refresh.classifyConcurrency;

async function runWithConcurrency<T>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const pool = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const idx = cursor++;
      if (idx >= items.length) return;
      await worker(items[idx]);
    }
  });
  await Promise.all(pool);
}

import {
  cveDecayLoad,
  explainOpenDebtLoad,
  feltLoad,
  feltSignalMask,
  installConfidence,
  isFeltSignal,
  pickRecommended,
  SCORE_MODEL_VERSION,
  type InstallInput,
} from './score';
import {
  closedDuringReign,
  countStaleClassifications,
  deleteStaleClassifications,
  detectBot,
  getClassification,
  getLastScoredAt,
  getReleaseCommit,
  labelsForIssueAt,
  getMeta,
  getRelease,
  issueCountForVersion,
  issuesForVersion,
  listAdvisories,
  listReleasesDb,
  openedDuringReign,
  setMeta,
  updateReleaseDerivedStats,
  updateReleaseArtifactVerification,
  updateReleaseScore,
  upsertReleaseScoreAudit,
  upsertAdvisory,
  upsertClassification,
  upsertIssue,
  upsertIssueLabelEvent,
  upsertRelease,
  upsertReleaseCommit,
  unverifiedClosedForRelease,
  verifiedFixedForRelease,
} from './db';

function isMaintainerAssociation(association: string | null | undefined): boolean {
  return ['OWNER', 'MEMBER', 'COLLABORATOR'].includes(association ?? '');
}

function isContributorAssociation(association: string | null | undefined): boolean {
  return isMaintainerAssociation(association) || association === 'CONTRIBUTOR';
}

function commentStats(issue: GhIssue, comments: GhComment[]): {
  unique_human_commenters: number;
  maintainer_commenters: number;
  contributor_commenters: number;
  commenter_scan_truncated: number;
} {
  const humans = new Set<string>();
  const maintainers = new Set<string>();
  const contributors = new Set<string>();
  for (const comment of comments) {
    const login = comment.user?.login;
    if (!login || detectBot(login, '[]')) continue;
    humans.add(login);
    if (isMaintainerAssociation(comment.author_association)) maintainers.add(login);
    if (isContributorAssociation(comment.author_association)) contributors.add(login);
  }
  return {
    unique_human_commenters: humans.size,
    maintainer_commenters: maintainers.size,
    contributor_commenters: contributors.size,
    commenter_scan_truncated: comments.length < issue.comments ? 1 : 0,
  };
}

function releaseLabelCutoff(rel: { published_at: string | null; hours_to_next_release: number | null }): string | null {
  if (!rel.published_at || rel.hours_to_next_release == null) return null;
  const publishedAt = Date.parse(rel.published_at);
  if (!Number.isFinite(publishedAt)) return null;
  return new Date(publishedAt + rel.hours_to_next_release * 3_600_000).toISOString();
}

const BACKFILL_FLAG = 'backfill_completed_at';

let refreshing = false;
// Seed from DB so "Not yet refreshed" doesn't show after a restart.
let lastRefreshAt: string | null = getLastScoredAt();
let lastError: string | null = null;

export function getRefreshState() {
  return { refreshing, lastRefreshAt, lastError };
}

export async function refresh(): Promise<{
  classifiedCount: number;
  releaseCount: number;
  durationMs: number;
}> {
  if (refreshing) throw new Error('refresh already running');
  refreshing = true;
  lastError = null;
  const t0 = Date.now();

  try {
    // 1. Pull releases. We over-fetch (×6) because openclaw's prerelease:stable
    // ratio is ~3:1; from this wider window we keep ALL entries for derived-stat
    // computation (betaCount, hoursToNextRelease, aggregate breaking) but only
    // score the latest `releases` stable ones. Prereleases are not scored — they
    // signal shake-out time around the stable that ships next.
    //
    // The ×6 multiplier also bounds how far back `computeAggregateBreaking` can
    // look: a stable's beta chain must be inside this fetched window for its
    // breaking bullets to be counted. At openclaw's 3:1 beta:stable ratio,
    // ×6 → ~10 stables of headroom past the monitored count. If that ratio ever
    // inverts (more betas per stable), bump the multiplier.
    // Monitor only the latest `config.limits.releases` (default 10). This is the
    // expensive window: it drives the issue-classification cutoff (oldestMonitoredMs
    // below) and thus how many LLM calls a back-fill / prompt-sweep costs. The score
    // chart renders up to SCORE_HISTORY_CHART_LIMIT (20) points, but there's no sense
    // running the long classification pass that wide — the focus is the recent 10.
    // Chart points 11–20 are intentionally frozen rows already scored in past runs
    // (served straight from the DB), kept purely as comparative trend context.
    const monitoredReleaseCount = config.limits.releases;
    const fetched = await listReleases(monitoredReleaseCount * 6);
    const releases = fetched.filter((r) => !r.prerelease).slice(0, monitoredReleaseCount);
    for (const r of releases) {
      upsertRelease({
        tag: r.tag_name,
        name: r.name,
        published_at: r.published_at,
        html_url: r.html_url,
        prerelease: r.prerelease,
        body: r.body ?? null,
      });
    }
    const tags = releases.map((r) => r.tag_name);

    // Derived stats per stable: parse maintainer-signal counts from the body,
    // count preceding prereleases and time-to-next-release. No new API calls —
    // all data comes from `fetched`. Failure here is a code bug, not a network
    // issue, so we don't try/catch — let it surface during dev.
    //
    // releasesForCalc carries `breakingCount` from each fetched body (including
    // prereleases) so `computeAggregateBreaking` can roll a stable's preceding
    // beta chain into its stored `breaking_count`. Without this, a `### Breaking`
    // bullet that only appears in a beta body (and is not repeated in the stable
    // body at promotion time) would be invisible — see comment on
    // computeAggregateBreaking in releaseNotes.ts.
    const releasesForCalc = fetched.map((r) => ({
      tag: r.tag_name,
      published_at: r.published_at,
      prerelease: r.prerelease,
      breakingCount: parseReleaseNotes(r.body).breakingCount,
    }));
    for (const r of releases) {
      const stats = parseReleaseNotes(r.body);
      updateReleaseDerivedStats({
        tag: r.tag_name,
        // Aggregated: own + breaking bullets from each preceding beta until the
        // previous stable. Other counts (fixes/changes/highlights) are NOT
        // aggregated — the changelog generator re-lists them in the stable body
        // at promotion time, so they're already counted once.
        breaking_count: computeAggregateBreaking(releasesForCalc, r.tag_name),
        fixes_count: stats.fixesCount,
        changes_count: stats.changesCount,
        highlights_count: stats.highlightsCount,
        pr_refs_count: stats.prRefsCount,
        beta_count: computeBetaCount(releasesForCalc, r.tag_name),
        hours_to_next_release: computeHoursToNextRelease(releasesForCalc, r.tag_name),
        hours_to_next_stable: computeHoursToNextStable(releasesForCalc, r.tag_name),
        npm_package_url: stats.npmPackageUrl,
        release_tarball_url: stats.registryTarballUrl,
        release_integrity: stats.integrity,
        release_sha: stats.releaseSha,
        full_release_ci_report_url: stats.fullReleaseCiReportUrl,
      });
    }

    for (const r of releases) {
      const stats = parseReleaseNotes(r.body);
      try {
        const artifact = await verifyNpmArtifact({
          tag: r.tag_name,
          expectedIntegrity: stats.integrity,
          expectedTarballUrl: stats.registryTarballUrl,
        });
        const evidenceReport = await verifyEvidenceReportUrl(stats.fullReleaseCiReportUrl);
        updateReleaseArtifactVerification({
          tag: r.tag_name,
          registry_version: artifact.version,
          registry_integrity: artifact.integrity,
          registry_tarball_url: artifact.tarballUrl,
          ci_report_verified: evidenceReport.verified ? 1 : 0,
          ci_report_mismatch: evidenceReport.mismatch,
          artifact_verified: artifact.verified ? 1 : 0,
          artifact_mismatch: artifact.mismatch,
        });
      } catch (e) {
        console.warn(`[artifacts] ${r.tag_name} npm verification failed (continuing): ${(e as Error).message}`);
      }
    }

    for (const r of releases) {
      try {
        const commit = await fetchReleaseCommit(r.tag_name);
        upsertReleaseCommit({
          tag: r.tag_name,
          tag_commit_oid: commit.oid,
          committed_at: commit.committedAt,
          check_state: commit.checkState,
          check_total: commit.checkTotal,
          check_success: commit.checkSuccess,
          check_failure: commit.checkFailure,
          check_pending: commit.checkPending,
          check_skipped: commit.checkSkipped,
          check_contexts_json: JSON.stringify(commit.checkContexts),
        });
      } catch (e) {
        console.warn(`[release-checks] ${r.tag_name} fetch failed (continuing): ${(e as Error).message}`);
      }
    }

    // 1b. Pull all security advisories for the repo. One cheap call, backfills
    // historical CVEs automatically. Failure here must not abort the whole
    // refresh — security data is additive; if the endpoint is down or the repo
    // has none, we still want issue/release data to update.
    try {
      const advisories = await listSecurityAdvisories();
      for (const adv of advisories) {
        // Take the first vulnerability entry referring to this repo's package.
        // openclaw advisories all have exactly one; if a future one had multiple,
        // we'd pick the one matching ecosystem === 'npm' (or fallback).
        const v = adv.vulnerabilities[0];
        upsertAdvisory({
          ghsa_id: adv.ghsa_id,
          cve_id: adv.cve_id,
          summary: adv.summary,
          severity: adv.severity,
          html_url: adv.html_url,
          published_at: adv.published_at,
          vulnerable_version_range: v?.vulnerable_version_range ?? null,
          patched_versions: v?.patched_versions ?? null,
        });
      }
    } catch (e) {
      console.warn(`[advisories] fetch failed (continuing): ${(e as Error).message}`);
    }

    // 2. Stream issues sorted by updated_at desc.
    //
    // FULL_ISSUE_BACKFILL=true deliberately walks the entire issue connection so
    // release attribution has all open/closed history. Normal mode keeps the
    // incremental early-stop behavior for later operational refreshes.
    //
    // First run (no backfill flag yet) IGNORES condition (a). Otherwise a fresh deploy
    // on top of an existing DB stops on page 1 the moment every visible issue is "known
    // unchanged" — never reaching the older issues that older releases need. Once we've
    // crossed the oldest release published_at at least once, the flag is set and future
    // runs use the cheap (a)+(b)+(c) stop logic. No tokens are spent re-classifying
    // unchanged issues — only fetched + upserted.
    const publishedAts = releases
      .map((r) => r.published_at)
      .filter((p): p is string => !!p)
      .map((p) => Date.parse(p))
      .filter((ms) => Number.isFinite(ms));
    const oldestMonitoredMs = publishedAts.length > 0 ? Math.min(...publishedAts) : -Infinity;
    const backfillDone = getMeta(BACKFILL_FLAG) !== null;
    const monitoredWindows = releases
      .map((release) => {
        const start = release.published_at ? Date.parse(release.published_at) : NaN;
        const next = releases
          .map((candidate) => candidate.published_at ? Date.parse(candidate.published_at) : NaN)
          .filter((ms) => Number.isFinite(ms) && ms > start)
          .sort((a, b) => a - b)[0];
        return { start, end: next ?? Infinity };
      })
      .filter((window) => Number.isFinite(window.start));
    const issueOverlapsMonitoredWindow = (issue: GhIssue): boolean => {
      const created = Date.parse(issue.created_at);
      const closed = issue.closed_at ? Date.parse(issue.closed_at) : Infinity;
      return monitoredWindows.some((window) => created < window.end && closed > window.start);
    };

    // After a PROMPT_VERSION bump, rows written under the old prompt are stale but
    // sit behind the oldest-monitored cutoff — the normal early-stop would skip
    // them forever. Detect this once and do a full sweep this run so the bump
    // actually propagates. Worst case: ~25 pages (~$1) once per prompt change.
    const staleRows = countStaleClassifications(PROMPT_VERSION);
    const promptSweep = backfillDone && staleRows > 0;
    if (promptSweep) {
      console.log(`[refresh] prompt-sweep: ${staleRows} stale classifications, ignoring early-stop this run`);
    }

    const fullIssueBackfill = config.refresh.fullIssueBackfill;
    const MAX_PAGES = config.refresh.maxIssuePages;
    let pagesFetched = 0;
    let classifiedCount = 0;
    let crossedOldestEver = false;

    paginate: for await (const page of paginateIssues(100)) {
      pagesFetched++;

      // Page can be empty after PR filtering — keep going until we hit a real signal
      // or run out of pages.
      let allUnchanged = page.length > 0;
      let crossedOldest = false;
      const toClassify: GhIssue[] = [];
      const commentsByIssue = await listIssueCommentsBatch(
        page.filter((issue) => issue.comments > 0).map((issue) => issue.number),
      );
      const labelEventsByIssue = await listIssueLabelEventsBatch(
        page
          .filter((issue) => issue.labels.length > 0 && issueOverlapsMonitoredWindow(issue))
          .map((issue) => issue.number),
      );

      // Pass 1: upsert + decide what needs LLM. SQLite writes are cheap and sequential.
      for (const issue of page) {
        const author = issue.user?.login ?? null;
        const labelsJson = JSON.stringify(issue.labels.map((l) => l.name));
        const comments = commentsByIssue.get(issue.number) ?? [];
        const stats = commentStats(issue, comments);
        upsertIssue({
          number: issue.number,
          state: issue.state,
          title: issue.title,
          author,
          author_association: issue.author_association ?? null,
          html_url: issue.html_url,
          created_at: issue.created_at,
          updated_at: issue.updated_at,
          closed_at: issue.closed_at,
          comments: issue.comments,
          unique_human_commenters: stats.unique_human_commenters,
          maintainer_commenters: stats.maintainer_commenters,
          contributor_commenters: stats.contributor_commenters,
          commenter_scan_truncated: stats.commenter_scan_truncated,
          reaction_total: issue.reaction_total ?? 0,
          positive_reactions: issue.positive_reactions ?? 0,
          labels: labelsJson,
          is_bot: detectBot(author, labelsJson) ? 1 : 0,
        });
        for (const event of labelEventsByIssue.get(issue.number) ?? []) {
          upsertIssueLabelEvent({
            issue_number: event.issueNumber,
            event_id: event.eventId,
            action: event.action,
            label_name: event.labelName,
            actor_login: event.actorLogin,
            created_at: event.createdAt,
          });
        }

        if (Date.parse(issue.updated_at) < oldestMonitoredMs) crossedOldest = true;

        // Full history is fetched for accurate open/closed linkage, but spend
        // classification tokens only on issues whose lifetime overlaps a release
        // being scored. Closed-before-release issues cannot affect that score.
        if (!issueOverlapsMonitoredWindow(issue)) continue;

        const existing = getClassification(issue.number);
        const skip = existing && (
          // Back-fill mode: preserve tokens — anything already classified is left as-is,
          // even if updated_at moved on or prompt_version is stale. The next normal run
          // (once the back-fill flag is set) will pick up those rows incrementally.
          !backfillDone ||
          // Normal mode: only skip when the row is fully current.
          (existing.classified_updated_at === issue.updated_at && existing.prompt_version === PROMPT_VERSION)
        );
        if (skip) continue;
        allUnchanged = false;
        toClassify.push(issue);
      }

      // Pass 2: pull recent comments in one GraphQL batch, then classify pending
      // issues in parallel. Per-issue failures are isolated — one issue erroring
      // out doesn't kill the rest of the page or the back-fill.
      await runWithConcurrency(toClassify, CLASSIFY_CONCURRENCY, async (issue) => {
        try {
          const comments = commentsByIssue.get(issue.number) ?? [];
          const cls: IssueClassification = await classifyIssue(issue, comments, tags);
          upsertClassification(issue.number, cls, issue.updated_at, PROMPT_VERSION);
          classifiedCount++;
        } catch (e) {
          console.error(`[classify] issue #${issue.number} failed:`, (e as Error).message);
        }
      });

      if (crossedOldest) crossedOldestEver = true;

      // During a full backfill, do not stop on timestamps or page sameness:
      // older still-open issues are part of the release's current debt.
      const canEarlyStop = !fullIssueBackfill && backfillDone && !promptSweep && allUnchanged;
      const canCrossedOldestStop = !fullIssueBackfill && !promptSweep && crossedOldest;
      if (canEarlyStop || canCrossedOldestStop) break paginate;
      if (pagesFetched >= MAX_PAGES) break paginate;
    }

    // Mark a full backfill complete after walking the connection (or hitting its
    // explicit safety cap). Normal mode marks it after crossing the release cutoff.
    if (!backfillDone && (fullIssueBackfill || crossedOldestEver || pagesFetched >= MAX_PAGES)) {
      setMeta(BACKFILL_FLAG, new Date().toISOString());
    }

    // After a prompt-sweep that walked the full pagination: if any rows are
    // STILL on the old prompt version, they're issues whose updated_at is too
    // old for GitHub pagination to reach within MAX_PAGES — they will keep
    // forcing the (expensive) sweep on every refresh forever. Drop them. If
    // GitHub ever surfaces those issues again (new comment), refresh will
    // re-classify them fresh on the next pass.
    if (promptSweep) {
      const leftover = countStaleClassifications(PROMPT_VERSION);
      if (leftover > 0) {
        const dropped = deleteStaleClassifications(PROMPT_VERSION);
        console.log(`[refresh] dropped ${dropped} unreachable stale rows after sweep`);
      }
    }

    const allReleases = listReleasesDb(monitoredReleaseCount);

    for (const rel of allReleases) {
      try {
        const closure = await refreshClosureEvidenceForRelease(rel.tag);
        console.log(`[closure-evidence] ${rel.tag}: ${closure.issueCount} closed issues inspected`);
      } catch (e) {
        console.warn(`[closure-evidence] ${rel.tag} failed (continuing): ${(e as Error).message}`);
      }
      try {
        const reachability = await checkReleasePrReachability(rel.tag);
        console.log(`[reachability] ${rel.tag}: ${reachability.reachable}/${reachability.candidates} reachable`);
      } catch (e) {
        console.warn(`[reachability] ${rel.tag} failed (continuing): ${(e as Error).message}`);
      }
    }

    // 4. Score every monitored release with the Install Confidence model — a single
    //    pass answering "should I install this stable?" from age/cadence-invariant
    //    signals (CVE, settle age, hotfix succession, stable-to-stable survival, beta
    //    shakeout, serious-regression balance). No peer median, no carry-forward
    //    attribution in the score itself. See lib/score.ts for the full rationale.
    const allFetchedTags = fetched.map((r) => r.tag_name);

    // CVE exposure per tag. `affected` (medium+ advisory matches) drives the
    // skip-cve STATUS (never recommended); `load` is the DECAYED severity-weighted
    // penalty on the score — see cveDecayLoad. Distance is measured over all fetched
    // stables (newest first), so it can see releases between a version and a far patch.
    const advisories = listAdvisories();
    const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    const stableTagsNewestFirst = fetched.filter((r) => !r.prerelease).map((r) => r.tag_name);
    const cveFor = (tag: string): { affected: boolean; load: number } => {
      const matching = advisories.filter((a) => matchesRange(tag, a.vulnerable_version_range));
      const affected = matching.some((a) => (SEV_RANK[a.severity] ?? 0) >= 2); // medium+ gates
      // Score load = severity of this version's OWN CVEs (patched in the next stable,
      // distance ≤ 0) — the same set the badge shows. Distant CVEs still trip the
      // skip-cve STATUS via `affected`, but don't inflate the severity number.
      const load = cveDecayLoad(
        matching
          .map((a) => ({
            severity: a.severity,
            distance: stableDistance(tag, a.patched_versions, stableTagsNewestFirst),
          }))
          .filter((x) => x.distance <= 0),
      );
      return { affected, load };
    };

    // Post-override classification for an attributed/reign issue row.
    const isCoreSerious = (c: IssueClassification): boolean =>
      c.sentiment === 'negative' &&
      c.functionality === 'core' &&
      (c.severity === 'critical' || c.severity === 'high');
    const scored = allReleases.map((rel, idx) => {
      const labelCutoff = releaseLabelCutoff(rel);
      const effectiveLabels = (row: ReturnType<typeof issuesForVersion>[number]): string[] =>
        labelsForIssueAt(row.number, safeParseLabels(row.labels), labelCutoff);
      const classify = (row: ReturnType<typeof issuesForVersion>[number]): IssueClassification =>
        classifyIssueRowWithLabels(row, effectiveLabels(row));
      const countCoreSerious = (rows: ReturnType<typeof issuesForVersion>): number =>
        rows.reduce((n, r) => (isCoreSerious(classify(r)) ? n + 1 : n), 0);
      // negative/positive counts are display-only context (not part of the score).
      let neg = 0;
      let pos = 0;
      const attributed = issuesForVersion(rel.tag);
      for (const r of attributed) {
        const s = classify(r).sentiment;
        if (s === 'negative') neg++;
        else if (s === 'positive') pos++;
      }
      const openedReign = openedDuringReign(rel.tag);
      const closedReign = closedDuringReign(rel.tag);
      const verifiedFixed = verifiedFixedForRelease(rel.tag);
      const unverifiedClosed = unverifiedClosedForRelease(rel.tag);
      const verifiedFixedNumbers = new Set(verifiedFixed.map((row) => row.number));
      const scoreStateForIssue = (row: typeof attributed[number]): string => {
        if (verifiedFixedNumbers.has(row.number)) return 'closed';
        return row.state === 'open' ? 'open' : 'closed-unverified';
      };
      const feltInput = (row: typeof attributed[number]) => ({
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
          // Artifact-scoped scoring: reachable fixes remove debt. Closed issues
          // without reachable-fix proof stay visible in provenance review but do
          // not masquerade as active field-confirmed release debt.
          state: scoreStateForIssue(row),
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          affectsVersion: row.affects_version,
          releaseLocal: rel.published_at ? Date.parse(row.created_at) >= Date.parse(rel.published_at) : false,
        }));
      const activeDebt = explainOpenDebtLoad(debtInputs);
      // core-serious counts: kept for the informational API/DB stats.
      const openedSerious = countCoreSerious(openedReign);
      const closedSerious = countCoreSerious(verifiedFixed);
      // visible-bug ("felt") reach-weighted load drives the score's regression term.
      const openedFeltInputs = openedReign.map(feltInput);
      const openedFeltMask = feltSignalMask(openedFeltInputs);
      const openedFeltRows = openedReign.filter((_, rowIndex) => openedFeltMask[rowIndex]);
      const feltOpenedWeight = feltLoad(openedFeltInputs);
      const feltClosedWeight = feltLoad(verifiedFixed.map(feltInput));
      // WHAT it breaks: still-open visible regressions introduced during the reign,
      // grouped by named surface (Discord, Ollama, …) for the UI.
      const brokenSurfaces = JSON.stringify(
        topBrokenSurfaces(
          openedFeltRows.map((r) => r.title),
        ),
      );
      const cve = cveFor(rel.tag);
      const releaseCommit = getReleaseCommit(rel.tag);
      const input: InstallInput = {
        publishedAt: rel.published_at,
        isLatest: idx === 0, // listReleasesDb returns newest-first
        hoursToNextStable: rel.hours_to_next_stable,
        hasHotfixSuccessor: hasHotfixSuccessor(allFetchedTags, rel.tag),
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
      const conf = installConfidence(input);
      const issueByNumber = new Map(attributed.map((row) => [row.number, row]));
      const summarizeIssue = (row: ReturnType<typeof issuesForVersion>[number] | undefined) => {
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
        stableTagsNewestFirst,
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
    });

    // Recommended install: newest release that passed all gates and scores ≥ threshold.
    const recommendedTag = pickRecommended(
      scored.map((s) => ({ tag: s.rel.tag, status: s.conf.status, score: s.conf.score })),
    );

    for (const s of scored) {
      const scoredAt = new Date().toISOString();
      updateReleaseScore({
        tag: s.rel.tag,
        final_score: s.conf.score,
        negative_issues: s.neg,
        positive_issues: s.pos,
        state: s.conf.status,
        recommended: s.rel.tag === recommendedTag ? 1 : 0,
        score_reason: s.conf.reason,
        broken_surfaces: s.brokenSurfaces,
        closed_serious_fixed: s.closedSerious,
        opened_serious_during_reign: s.openedSerious,
        scored_at: scoredAt,
      });
      upsertReleaseScoreAudit({
        release_tag: s.rel.tag,
        scored_at: scoredAt,
        score_model_version: SCORE_MODEL_VERSION,
        prompt_version: PROMPT_VERSION,
        final_score: s.conf.score,
        status: s.conf.status,
        band: s.conf.band,
        recommended: s.rel.tag === recommendedTag ? 1 : 0,
        input_json: JSON.stringify(s.input),
        components_json: JSON.stringify({
          components: s.conf.components,
          evidenceCoverage: s.conf.evidenceCoverage,
          hotfix: s.conf.hotfix,
          reason: s.conf.reason,
        }),
        issue_evidence_json: JSON.stringify(s.debtEvidence),
        gate_evidence_json: JSON.stringify(s.gateEvidence),
      });
    }

    for (const s of scored) {
      try {
        const proof = await analyzeClosureProofsForRelease(s.rel.tag);
        console.log(`[closure-proof] ${s.rel.tag}: ${proof.analyzed} analyzed`);
      } catch (e) {
        console.warn(`[closure-proof] ${s.rel.tag} failed (continuing): ${(e as Error).message}`);
      }
    }

    lastRefreshAt = new Date().toISOString();
    invalidateCache();
    return {
      classifiedCount,
      releaseCount: allReleases.length,
      durationMs: Date.now() - t0,
    };
  } catch (e) {
    lastError = (e as Error).message;
    throw e;
  } finally {
    refreshing = false;
  }
}

function safeParseLabels(json: string): string[] {
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function parseJsonArray(json: string | null | undefined): unknown[] {
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
  // workaround_status was added later; rows written by old code have the default 'unknown',
  // but be defensive: if it's an unexpected value, fall back to deriving from has_workaround.
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

// re-export for routes

export function classifyIssueRow(row: ReturnType<typeof issuesForVersion>[number]): IssueClassification {
  return classifyIssueRowWithLabels(row, safeParseLabels(row.labels));
}

export function classifyIssueRowWithLabels(
  row: ReturnType<typeof issuesForVersion>[number],
  labels: string[],
): IssueClassification {
  return applyTitleIssueShapeHint(
    applyLabelOverrides(
      applyTitleFunctionalityHint(rowToClassification(row), row.title),
      labels,
    ),
    row.title,
    labels,
  );
}

export function isOpenFeltSeriousIssue(row: ReturnType<typeof issuesForVersion>[number]): boolean {
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

export { getRelease, issuesForVersion, listReleasesDb, openedDuringReign };
