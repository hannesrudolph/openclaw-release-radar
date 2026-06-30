import { config } from '../config';
import { invalidateCache } from './cache';
import {
  GhComment,
  type GhIssueFixEvidence,
  GhIssue,
  getReleaseCommit as fetchReleaseCommit,
  listIssueCommentsBatch,
  listIssueFixEvidenceBatch,
  listIssueLabelEventsBatch,
  listReleases,
  listSecurityAdvisories,
  paginateIssues,
} from './github';
import { classifyIssue, type IssueClassification, PROMPT_VERSION } from './llm';
import {
  computeAggregateBreaking,
  computeBetaCount,
  computeHoursToNextRelease,
  computeHoursToNextStable,
  parseReleaseNotes,
} from './releaseNotes';
import { verifyNpmArtifact } from './npmRegistry';
import { verifyEvidenceReportUrl } from './releaseEvidence';
import { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } from './closureProofAnalysis';
import { checkReleasePrReachability } from './releaseReachability';
import { buildReleaseScoreRun, persistReleaseScoreRun } from './releaseScoring';

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
  countStaleClassifications,
  deleteStaleClassifications,
  detectBot,
  getClassification,
  getMeta,
  getRelease,
  issuesForVersion,
  listReleasesDb,
  openedDuringReign,
  setMeta,
  updateReleaseDerivedStats,
  updateReleaseArtifactVerification,
  upsertAdvisory,
  upsertClassification,
  upsertIssue,
  upsertIssueClosureEvent,
  upsertIssueLabelEvent,
  upsertIssueLabelSnapshot,
  upsertIssuePrLink,
  upsertIssueReopenEvent,
  upsertPullRequestFix,
  upsertRelease,
  upsertReleaseCommit,
} from './db';

function isMaintainerAssociation(association: string | null | undefined): boolean {
  return ['OWNER', 'MEMBER', 'COLLABORATOR'].includes(association ?? '');
}

function isContributorAssociation(association: string | null | undefined): boolean {
  return isMaintainerAssociation(association) || association === 'CONTRIBUTOR';
}

function persistIssueStateEvidence(evidence: GhIssueFixEvidence): void {
  for (const event of evidence.closureEvents) {
    upsertIssueClosureEvent({
      issue_number: event.issueNumber,
      event_id: event.eventId,
      closed_at: event.closedAt,
      actor_login: event.actorLogin,
      state_reason: event.stateReason,
      closer_type: event.closerType,
      closer_number: event.closerNumber,
      closer_oid: event.closerOid,
      raw_json: JSON.stringify(event.raw),
    });
  }
  for (const event of evidence.reopenEvents) {
    upsertIssueReopenEvent({
      issue_number: event.issueNumber,
      event_id: event.eventId,
      reopened_at: event.reopenedAt,
      actor_login: event.actorLogin,
      raw_json: JSON.stringify(event.raw),
    });
  }
    for (const link of evidence.prLinks) {
      upsertIssuePrLink({
        issue_number: link.issueNumber,
        pr_repository_owner: link.prRepositoryOwner,
        pr_repository_name: link.prRepositoryName,
        pr_repository_name_with_owner: link.prRepositoryNameWithOwner,
        pr_number: link.prNumber,
      source: link.source,
      will_close_target: link.willCloseTarget == null ? null : link.willCloseTarget ? 1 : 0,
      referenced_at: link.referencedAt,
    });
  }
    for (const pr of evidence.pullRequests) {
      upsertPullRequestFix({
        pr_repository_owner: pr.repositoryOwner,
        pr_repository_name: pr.repositoryName,
        pr_repository_name_with_owner: pr.repositoryNameWithOwner,
        pr_number: pr.number,
      title: pr.title,
      url: pr.url,
      state: pr.state,
      merged: pr.merged ? 1 : 0,
      merged_at: pr.mergedAt,
      merge_commit_oid: pr.mergeCommitOid,
      base_ref_name: pr.baseRefName,
    });
  }
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

const BACKFILL_FLAG = 'backfill_completed_at';
export const ISSUE_CRAWL_META_KEY = 'issue_crawl_last_run';
type IssuePaginationStopReason = 'exhausted' | 'early_stop' | 'page_cap';

let refreshing = false;
let processLastRefreshAt: string | null = null;
let lastError: string | null = null;

export function getRefreshState() {
  return { refreshing, processLastRefreshAt, lastError };
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
    const refreshStartedAt = new Date(t0).toISOString();
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
        full_release_validation_url: stats.fullReleaseValidationUrl,
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
        const evidenceReport = await verifyEvidenceReportUrl(stats.fullReleaseCiReportUrl, stats.fullReleaseValidationUrl, {
          expectedReleaseTag: r.tag_name,
          expectedReleaseSha: stats.releaseSha,
        });
        updateReleaseArtifactVerification({
          tag: r.tag_name,
          registry_version: artifact.version,
          registry_integrity: artifact.integrity,
          registry_tarball_url: artifact.tarballUrl,
          ci_report_verified: evidenceReport.verified ? 1 : 0,
          ci_report_mismatch: evidenceReport.mismatch,
          release_validation_verified: evidenceReport.fallbackKind === 'github_actions_run' && evidenceReport.verified ? 1 : 0,
          release_validation_mismatch: evidenceReport.fallbackKind === 'github_actions_run' ? evidenceReport.mismatch : null,
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
    let issuesFetched = 0;
    let monitoredIssuesFetched = 0;
    let commenterScanTruncatedCount = 0;
    let classifiedCount = 0;
    let crossedOldestEver = false;
    let issuePaginationStopReason: IssuePaginationStopReason = 'exhausted';

    paginate: for await (const page of paginateIssues(100)) {
      pagesFetched++;
      issuesFetched += page.length;

      // Page can be empty after PR filtering — keep going until we hit a real signal
      // or run out of pages.
      let allUnchanged = page.length > 0;
      let crossedOldest = false;
      const toClassify: GhIssue[] = [];
      const monitoredIssueNumbers = page
        .filter((issue) => issueOverlapsMonitoredWindow(issue))
        .map((issue) => issue.number);
      monitoredIssuesFetched += monitoredIssueNumbers.length;
      const [commentsByIssue, labelEventsByIssue, stateEvidenceByIssue] = await Promise.all([
        listIssueCommentsBatch(page.filter((issue) => issue.comments > 0).map((issue) => issue.number)),
        listIssueLabelEventsBatch(monitoredIssueNumbers),
        listIssueFixEvidenceBatch(monitoredIssueNumbers),
      ]);

      // Pass 1: upsert + decide what needs LLM. SQLite writes are cheap and sequential.
      for (const issue of page) {
        const author = issue.user?.login ?? null;
        const labelsJson = JSON.stringify(issue.labels.map((l) => l.name));
        const comments = commentsByIssue.get(issue.number) ?? [];
        const stats = commentStats(issue, comments);
        if (stats.commenter_scan_truncated) commenterScanTruncatedCount++;
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
        upsertIssueLabelSnapshot({
          issue_number: issue.number,
          snapshot_at: refreshStartedAt,
          labels_json: labelsJson,
        });
        const stateEvidence = stateEvidenceByIssue.get(issue.number);
        if (stateEvidence) persistIssueStateEvidence(stateEvidence);

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
      if (canEarlyStop || canCrossedOldestStop) {
        issuePaginationStopReason = 'early_stop';
        break paginate;
      }
      if (pagesFetched >= MAX_PAGES) {
        issuePaginationStopReason = 'page_cap';
        break paginate;
      }
    }

    // Mark backfill complete only when the monitored history boundary is reached
    // or the GitHub issue connection is exhausted. Hitting MAX_ISSUE_PAGES is a
    // safety stop, not proof that older issue history was fetched.
    if (!backfillDone && shouldMarkBackfillComplete({
      fullIssueBackfill,
      crossedOldestEver,
      issuePaginationStopReason,
    })) {
      setMeta(BACKFILL_FLAG, new Date().toISOString());
    } else if (!backfillDone && issuePaginationStopReason === 'page_cap') {
      console.warn(`[refresh] issue pagination stopped at MAX_ISSUE_PAGES=${MAX_PAGES}; backfill remains incomplete`);
    }

    const issueCrawlMeta = {
      schemaVersion: 1,
      startedAt: refreshStartedAt,
      finishedAt: new Date().toISOString(),
      fullIssueBackfill,
      backfillCompleteAtStart: backfillDone,
      backfillCompleteAfterRun: getMeta(BACKFILL_FLAG) !== null,
      promptSweep,
      staleClassificationsAtStart: staleRows,
      monitoredReleaseCount,
      oldestMonitoredAt: Number.isFinite(oldestMonitoredMs) ? new Date(oldestMonitoredMs).toISOString() : null,
      pagesFetched,
      issuesFetched,
      monitoredIssuesFetched,
      maxIssuePages: MAX_PAGES,
      stopReason: issuePaginationStopReason,
      crossedOldestEver,
      commenterScanTruncatedCount,
      evidenceRefreshFailures: [] as string[],
      scorePersisted: false,
      scorePersistedAt: null,
    };
    persistIssueCrawlMeta(issueCrawlMeta);
    if (shouldRefuseScoreAfterIssuePagination(issuePaginationStopReason)) {
      throw new Error(`Issue pagination stopped at MAX_ISSUE_PAGES=${MAX_PAGES}; refusing to persist scores from incomplete crawl`);
    }

    // After a prompt-sweep that walked the full pagination: if any rows are
    // STILL on the old prompt version, they're issues whose updated_at is too
    // old for GitHub pagination to reach within MAX_PAGES — they will keep
    // forcing the (expensive) sweep on every refresh forever. Drop them. If
    // GitHub ever surfaces those issues again (new comment), refresh will
    // re-classify them fresh on the next pass.
    if (promptSweep && shouldDropStaleClassificationsAfterPromptSweep(issuePaginationStopReason)) {
      const leftover = countStaleClassifications(PROMPT_VERSION);
      if (leftover > 0) {
        const dropped = deleteStaleClassifications(PROMPT_VERSION);
        console.log(`[refresh] dropped ${dropped} unreachable stale rows after sweep`);
      }
    } else if (promptSweep && issuePaginationStopReason === 'page_cap') {
      console.warn('[refresh] prompt-sweep reached page cap; stale classifications were not dropped');
    }

    const allReleases = listReleasesDb(monitoredReleaseCount);
    const evidenceRefreshFailures: string[] = [];

    for (const rel of allReleases) {
      try {
        const closure = await refreshClosureEvidenceForRelease(rel.tag);
        console.log(`[closure-evidence] ${rel.tag}: ${closure.issueCount} closed issues inspected`);
      } catch (e) {
        const message = `[closure-evidence] ${rel.tag} failed: ${(e as Error).message}`;
        evidenceRefreshFailures.push(message);
        console.warn(`${message}; refusing score persistence after evidence refresh failures`);
      }
      try {
        const reachability = await checkReleasePrReachability(rel.tag);
        console.log(`[reachability] ${rel.tag}: ${reachability.reachable}/${reachability.candidates} reachable`);
      } catch (e) {
        const message = `[reachability] ${rel.tag} failed: ${(e as Error).message}`;
        evidenceRefreshFailures.push(message);
        console.warn(`${message}; refusing score persistence after evidence refresh failures`);
      }
      try {
        const proof = await analyzeClosureProofsForRelease(rel.tag);
        console.log(`[closure-proof] ${rel.tag}: ${proof.analyzed} analyzed`);
      } catch (e) {
        const message = `[closure-proof] ${rel.tag} failed: ${(e as Error).message}`;
        evidenceRefreshFailures.push(message);
        console.warn(`${message}; refusing score persistence after evidence refresh failures`);
      }
    }
    if (shouldRefuseScoreAfterEvidenceFailures(evidenceRefreshFailures)) {
      persistIssueCrawlMeta({
        ...issueCrawlMeta,
        evidenceRefreshFailures,
      });
      throw new Error(`Evidence refresh failed for ${evidenceRefreshFailures.length} step(s); refusing to persist scores`);
    }

    // 4. Score every monitored release with the Install Confidence model — a single
    //    pass answering "should I install this stable?" from age/cadence-invariant
    //    signals (CVE, settle age, hotfix succession, stable-to-stable survival, beta
    //    shakeout, serious-regression balance). No peer median, no carry-forward
    //    attribution in the score itself. See lib/score.ts for the full rationale.
    const scoreRun = buildReleaseScoreRun({
      releases: allReleases,
    });
    persistReleaseScoreRun(scoreRun);
    persistIssueCrawlMeta({
      ...issueCrawlMeta,
      scorePersisted: true,
      scorePersistedAt: new Date().toISOString(),
    });

    processLastRefreshAt = new Date().toISOString();
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

function shouldMarkBackfillComplete({
  fullIssueBackfill,
  crossedOldestEver,
  issuePaginationStopReason,
}: {
  fullIssueBackfill: boolean;
  crossedOldestEver: boolean;
  issuePaginationStopReason: IssuePaginationStopReason;
}): boolean {
  if (issuePaginationStopReason === 'page_cap') return false;
  if (fullIssueBackfill) return issuePaginationStopReason === 'exhausted';
  return crossedOldestEver || issuePaginationStopReason === 'exhausted';
}

function shouldDropStaleClassificationsAfterPromptSweep(issuePaginationStopReason: IssuePaginationStopReason): boolean {
  return issuePaginationStopReason === 'exhausted';
}

function shouldRefuseScoreAfterIssuePagination(issuePaginationStopReason: IssuePaginationStopReason): boolean {
  return issuePaginationStopReason === 'page_cap';
}

function shouldRefuseScoreAfterEvidenceFailures(failures: unknown[]): boolean {
  return failures.length > 0;
}

function persistIssueCrawlMeta(meta: Record<string, unknown>): void {
  setMeta(ISSUE_CRAWL_META_KEY, JSON.stringify(meta));
}

export const __refreshTest = {
  shouldDropStaleClassificationsAfterPromptSweep,
  shouldMarkBackfillComplete,
  shouldRefuseScoreAfterEvidenceFailures,
  shouldRefuseScoreAfterIssuePagination,
};

export {
  classifyIssueRow,
  classifyIssueRowWithLabels,
  isOpenFeltSeriousIssue,
} from './releaseScoring';
export { getRelease, issuesForVersion, listReleasesDb, openedDuringReign };
