import { config } from '../config';
import { invalidateCache } from './cache';
import { listIssueComments, listIssues, listReleases } from './github';
import { classifyIssue, type IssueClassification } from './llm';
import { scoreRelease, type IssueInput } from './score';
import {
  detectBot,
  getClassification,
  getLastScoredAt,
  getRelease,
  issuesForVersion,
  listReleasesDb,
  updateReleaseScore,
  upsertClassification,
  upsertIssue,
  upsertRelease,
} from './db';

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
    // 1. Pull releases.
    // Fetch with a buffer: betas often outnumber stable releases significantly,
    // so we need more than (stable + beta) to guarantee we collect enough of each.
    const fetchLimit = Math.min(100, (config.limits.stableReleases + config.limits.betaReleases) * 6);
    const releases = await listReleases(fetchLimit);
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

    // 2. Pull issues sorted by updated desc.
    const issues = await listIssues(config.limits.issues);

    // 3. Classify only new/changed issues.
    let classifiedCount = 0;
    for (const issue of issues) {
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

      const existing = getClassification(issue.number);
      if (existing && existing.classified_updated_at === issue.updated_at) {
        continue; // unchanged since last classification
      }

      try {
        const comments = issue.comments > 0 ? await listIssueComments(issue.number) : [];
        const cls: IssueClassification = await classifyIssue(issue, comments, tags);
        upsertClassification(issue.number, cls, issue.updated_at);
        classifiedCount++;
      } catch (e) {
        console.error(`[classify] issue #${issue.number} failed:`, (e as Error).message);
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
    const allReleases = listReleasesDb(Math.min(100, (config.limits.stableReleases + config.limits.betaReleases) * 6));

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
