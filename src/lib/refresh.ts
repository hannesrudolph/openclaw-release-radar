import { config } from '../config';
import { invalidateCache } from './cache';
import { GhIssue, listIssueComments, listReleases, paginateIssues } from './github';
import { classifyIssue, type IssueClassification, PROMPT_VERSION } from './llm';

// Limited concurrency for LLM classification — keeps wall time tractable on cold-cache
// back-fill (≈1400 issues at ~1s each serially → ~25 min; 5-wide pool → ~5 min) while
// staying well under GitHub's secondary rate limit and OpenAI's per-minute token caps.
const CLASSIFY_CONCURRENCY = 5;

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
  detectBot,
  getClassification,
  getLastScoredAt,
  getMeta,
  getRelease,
  issuesForVersion,
  listReleasesDb,
  setMeta,
  updateReleaseScore,
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
    // 1. Pull releases. listReleases handles the prerelease filtering and over-fetch buffer.
    const releases = await listReleases(config.limits.releases);
    for (const r of releases) {
      upsertRelease({
        tag: r.tag_name,
        name: r.name,
        published_at: r.published_at,
        html_url: r.html_url,
        prerelease: r.prerelease,
      });
    }
    const tags = releases.map((r) => r.tag_name);

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

      // During the initial back-fill we ignore the "all unchanged" shortcut so we
      // actually reach older releases that pre-existing DB rows wouldn't cover.
      const canEarlyStop = backfillDone && allUnchanged;
      if (canEarlyStop || crossedOldest) break paginate;
      if (pagesFetched >= MAX_PAGES) break paginate;
    }

    // Mark back-fill complete the first time we actually paginated past the oldest
    // monitored release (or hit MAX_PAGES). After this, the "all unchanged" early
    // stop kicks in on subsequent runs.
    if (!backfillDone && (crossedOldestEver || pagesFetched >= MAX_PAGES)) {
      setMeta(BACKFILL_FLAG, new Date().toISOString());
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

    const pass1 = allReleases.map((rel) => {
      const versioned = issuesForVersion(rel.tag);
      const inputs: IssueInput[] = versioned.map((r) => ({
        number: r.number,
        updatedAt: r.updated_at,
        commentCount: r.comments,
        publishedAt: rel.published_at,
        isBot: r.is_bot === 1,
        classification: rowToClassification(r),
      }));
      return { rel, inputs, score: scoreRelease(inputs, rel.published_at) };
    });

    // Median weightedNegSum across rated releases that actually have negative signal.
    // Need at least 3 such releases — otherwise the median is meaningless noise.
    const negSums = pass1
      .filter((p) => p.score.state === 'rated' && p.score.negativeIssues > 0)
      .map((p) => p.score.weightedNegSum)
      .sort((a, b) => a - b);
    const peerMedian = negSums.length >= 3 ? negSums[Math.floor(negSums.length / 2)] : undefined;

    for (const { rel, inputs, score: firstScore } of pass1) {
      const score =
        peerMedian !== undefined && firstScore.state === 'rated'
          ? scoreRelease(inputs, rel.published_at, undefined, peerMedian)
          : firstScore;
      updateReleaseScore({
        tag: rel.tag,
        final_score: score.finalScore,
        risk_index: score.riskIndex,
        negative_issues: score.negativeIssues,
        positive_issues: score.positiveIssues,
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
