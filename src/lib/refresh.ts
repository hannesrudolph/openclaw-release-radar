import { config } from '../config';
import { invalidateCache } from './cache';
import {
  GhIssue,
  listIssueComments,
  listReleases,
  listSecurityAdvisories,
  paginateIssues,
} from './github';
import { classifyIssue, type IssueClassification, PROMPT_VERSION } from './llm';
import { applyLabelOverrides, applyTitleFunctionalityHint } from './labelOverrides';
import {
  computeBetaCount,
  computeHoursToNextRelease,
  parseReleaseNotes,
} from './releaseNotes';

// Limited concurrency for LLM classification — keeps wall time tractable on cold-cache
// back-fill (≈1400 issues at ~1s each serially → ~25 min; 5-wide pool → ~5 min) while
// staying well under GitHub's secondary rate limit and OpenAI's per-minute token caps.
const CLASSIFY_CONCURRENCY = 5;

function computeMedian(sorted: number[]): number | undefined {
  if (sorted.length < 3) return undefined;
  const mid = sorted.length >> 1;
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

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
import { scoreRelease, type IssueInput } from './score';
import {
  closedDuringReign,
  countStaleClassifications,
  deleteStaleClassifications,
  detectBot,
  getClassification,
  getLastScoredAt,
  getMeta,
  getRelease,
  issuesForVersion,
  listReleasesDb,
  openedDuringReign,
  setMeta,
  updateReleaseDerivedStats,
  updateReleaseScore,
  upsertAdvisory,
  upsertClassification,
  upsertIssue,
  upsertRelease,
} from './db';

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
    // computation (betaCount, hoursToNextRelease) but only score the latest
    // `releases` stable ones. Prereleases are not scored — they signal shake-out
    // time around the stable that ships next.
    const fetched = await listReleases(config.limits.releases * 6);
    const releases = fetched.filter((r) => !r.prerelease).slice(0, config.limits.releases);
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
    const releasesForCalc = fetched.map((r) => ({
      tag: r.tag_name,
      published_at: r.published_at,
      prerelease: r.prerelease,
    }));
    for (const r of releases) {
      const stats = parseReleaseNotes(r.body);
      updateReleaseDerivedStats({
        tag: r.tag_name,
        breaking_count: stats.breakingCount,
        fixes_count: stats.fixesCount,
        changes_count: stats.changesCount,
        highlights_count: stats.highlightsCount,
        pr_refs_count: stats.prRefsCount,
        beta_count: computeBetaCount(releasesForCalc, r.tag_name),
        hours_to_next_release: computeHoursToNextRelease(releasesForCalc, r.tag_name),
      });
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

    // 2. Stream issues sorted by updated_at desc, paginating until we either:
    //    (a) see a full page where every issue is already classified at its current
    //        updated_at and prompt version — nothing newer below this point;
    //    (b) cross the published_at of the oldest monitored release — anything older
    //        can't affect a release we display on the dashboard;
    //    (c) hit MAX_PAGES as a safety belt against pathological data.
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

    // After a PROMPT_VERSION bump, rows written under the old prompt are stale but
    // sit behind the oldest-monitored cutoff — the normal early-stop would skip
    // them forever. Detect this once and do a full sweep this run so the bump
    // actually propagates. Worst case: ~25 pages (~$1) once per prompt change.
    const staleRows = countStaleClassifications(PROMPT_VERSION);
    const promptSweep = backfillDone && staleRows > 0;
    if (promptSweep) {
      console.log(`[refresh] prompt-sweep: ${staleRows} stale classifications, ignoring early-stop this run`);
    }

    const MAX_PAGES = 50; // 50 × 100 raw items ≈ several months of openclaw history
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

      // Pass 1: upsert + decide what needs LLM. SQLite writes are cheap and sequential.
      for (const issue of page) {
        const author = issue.user?.login ?? null;
        const labelsJson = JSON.stringify(issue.labels.map((l) => l.name));
        upsertIssue({
          number: issue.number,
          state: issue.state,
          title: issue.title,
          author,
          html_url: issue.html_url,
          created_at: issue.created_at,
          updated_at: issue.updated_at,
          closed_at: issue.closed_at,
          comments: issue.comments,
          labels: labelsJson,
          is_bot: detectBot(author, labelsJson) ? 1 : 0,
        });

        if (Date.parse(issue.updated_at) < oldestMonitoredMs) crossedOldest = true;

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

      // Pass 2: classify pending issues in parallel. Per-issue failures are isolated
      // — one issue erroring out doesn't kill the rest of the page or the back-fill.
      await runWithConcurrency(toClassify, CLASSIFY_CONCURRENCY, async (issue) => {
        try {
          const comments = issue.comments > 0 ? await listIssueComments(issue.number) : [];
          const cls: IssueClassification = await classifyIssue(issue, comments, tags);
          upsertClassification(issue.number, cls, issue.updated_at, PROMPT_VERSION);
          classifiedCount++;
        } catch (e) {
          console.error(`[classify] issue #${issue.number} failed:`, (e as Error).message);
        }
      });

      if (crossedOldest) crossedOldestEver = true;

      // During the initial back-fill (or after a PROMPT_VERSION bump that left
      // stale rows behind the oldest-monitored cutoff) we ignore the early-stop
      // shortcuts and walk the full pagination up to MAX_PAGES, so we actually
      // reach older issues that would otherwise stay frozen on the old prompt.
      const canEarlyStop = backfillDone && !promptSweep && allUnchanged;
      const canCrossedOldestStop = !promptSweep && crossedOldest;
      if (canEarlyStop || canCrossedOldestStop) break paginate;
      if (pagesFetched >= MAX_PAGES) break paginate;
    }

    // Mark back-fill complete the first time we actually paginated past the oldest
    // monitored release (or hit MAX_PAGES). After this, the "all unchanged" early
    // stop kicks in on subsequent runs.
    if (!backfillDone && (crossedOldestEver || pagesFetched >= MAX_PAGES)) {
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

    // 4. Recompute scores per release using strict LLM attribution (agent-watch model).
    //
    // Only issues where the LLM extracted an explicit affectsVersion are counted toward
    // that version's score. Unattributed issues are silently dropped — this is by design,
    // see the rationale in db.ts/issuesForVersionStmt.
    //
    // Two passes: pass 1 scores without peer floor to collect each release's
    // weightedNegSum; pass 2 re-scores rated releases with the median injected, so
    // average-or-better releases get lifted to PEER_MEDIAN_FLOOR (5.5) if they fell below.
    const allReleases = listReleasesDb(config.limits.releases);

    const buildInput = (r: ReturnType<typeof issuesForVersion>[number]): IssueInput => {
      const labelNames = safeParseLabels(r.labels);
      let classification = rowToClassification(r);
      classification = applyTitleFunctionalityHint(classification, r.title);
      classification = applyLabelOverrides(classification, labelNames);
      return {
        number: r.number,
        updatedAt: r.updated_at,
        commentCount: r.comments,
        isBot: r.is_bot === 1,
        classification,
      };
    };

    const pass1 = allReleases.map((rel) => {
      const inputs = issuesForVersion(rel.tag).map(buildInput);
      const closedInputs = closedDuringReign(rel.tag).map(buildInput);
      const openedInputs = openedDuringReign(rel.tag).map(buildInput);
      return {
        rel,
        inputs,
        closedInputs,
        openedInputs,
        score: scoreRelease(inputs, rel.published_at, undefined, undefined, closedInputs, openedInputs),
      };
    });

    // Median weightedNegSum across rated releases that actually have negative signal.
    // Need at least 3 such releases — otherwise the median is meaningless noise.
    // For even-sized lists, take the mean of the two central values rather than the
    // upper one — the floor lift is sensitive to this for small N.
    const negSums = pass1
      .filter((p) => p.score.state === 'rated' && p.score.negativeIssues > 0)
      .map((p) => p.score.weightedNegSum)
      .sort((a, b) => a - b);
    const peerMedian = computeMedian(negSums);

    for (const { rel, inputs, closedInputs, openedInputs, score: firstScore } of pass1) {
      const score =
        peerMedian !== undefined && firstScore.state === 'rated'
          ? scoreRelease(inputs, rel.published_at, undefined, peerMedian, closedInputs, openedInputs)
          : firstScore;
      updateReleaseScore({
        tag: rel.tag,
        final_score: score.finalScore,
        risk_index: score.riskIndex,
        negative_issues: score.negativeIssues,
        positive_issues: score.positiveIssues,
        state: score.state,
        closed_serious_fixed: score.closedSeriousFixed,
        fix_bonus: score.fixBonus,
        opened_serious_during_reign: score.openedSeriousDuringReign,
      });
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
export { getRelease, issuesForVersion, listReleasesDb };
