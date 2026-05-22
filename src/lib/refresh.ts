import { config } from '../config';
import { invalidateCache } from './cache';
import { listIssueComments, listIssues, listReleases } from './github';
import { classifyIssue, type IssueClassification } from './llm';
import { scoreRelease, type IssueInput } from './score';
import {
  getClassification,
  getLastScoredAt,
  getRelease,
  issuesOpenDuring,
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

    // 2. Pull issues sorted by updated desc.
    const issues = await listIssues(config.limits.issues);

    // 3. Classify only new/changed issues.
    let classifiedCount = 0;
    for (const issue of issues) {
      upsertIssue({
        number: issue.number,
        state: issue.state,
        title: issue.title,
        author: issue.user?.login ?? null,
        html_url: issue.html_url,
        created_at: issue.created_at,
        updated_at: issue.updated_at,
        closed_at: issue.closed_at,
        comments: issue.comments,
        labels: JSON.stringify(issue.labels.map((l) => l.name)),
      });

      const existing = getClassification(issue.number);
      if (existing && existing.classified_updated_at === issue.updated_at) {
        continue; // unchanged since last classification
      }

      try {
        const comments = issue.comments > 0 ? await listIssueComments(issue.number) : [];
        const cls: IssueClassification = await classifyIssue(issue, comments);
        upsertClassification(issue.number, cls, issue.updated_at);
        classifiedCount++;
      } catch (e) {
        console.error(`[classify] issue #${issue.number} failed:`, (e as Error).message);
      }
    }

    // 4. Recompute scores per release using time-window attribution.
    //
    // For each release, the "lifetime window" is [release.published_at, next_release.published_at).
    // The latest release has no upper bound (end = now). An issue counts against a release if it
    // was open at any point during that window. This is deterministic and replaces the old
    // LLM-based affectsVersion guess (which couldn't reliably attribute issues without explicit
    // version mentions, leading to all unversioned bugs being dumped on the latest release).
    const allReleases = listReleasesDb(Math.min(100, (config.limits.stableReleases + config.limits.betaReleases) * 6));

    // allReleases is sorted by published_at DESC, so index 0 = newest. Build [start, end) windows.
    // Skip releases with null published_at (drafts) — no meaningful window.
    for (let i = 0; i < allReleases.length; i++) {
      const rel = allReleases[i];
      if (!rel.published_at) continue;
      const start = rel.published_at;
      // The "next-newer" release in time terms sits at i-1 in this DESC list.
      // For i === 0 (latest), end is null → issuesOpenDuring treats as "now".
      const end = i === 0 ? null : (allReleases[i - 1].published_at ?? null);

      const pool = issuesOpenDuring(start, end);
      const inputs: IssueInput[] = pool.map((r) => ({
        number: r.number,
        updatedAt: r.updated_at,
        commentCount: r.comments,
        classification: rowToClassification(r),
      }));
      const score = scoreRelease(inputs);
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
  duplicate_cluster: string | null;
  confidence: number;
  rationale: string | null;
}): IssueClassification {
  return {
    sentiment: row.sentiment as IssueClassification['sentiment'],
    severity: row.severity as IssueClassification['severity'],
    scope: row.scope as IssueClassification['scope'],
    functionality: row.functionality as IssueClassification['functionality'],
    affectedUsers: row.affected_users as IssueClassification['affectedUsers'],
    hasWorkaround: row.has_workaround === 1,
    duplicateCluster: row.duplicate_cluster,
    confidence: row.confidence,
    rationale: row.rationale ?? '',
  };
}

// re-export for routes
export { getRelease, issuesOpenDuring, listReleasesDb };
