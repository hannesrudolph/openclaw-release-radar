import { config } from '../config';
import { invalidateCache } from './cache';
import { listIssueComments, listIssues, listReleases } from './github';
import { classifyIssue, type IssueClassification } from './llm';
import { scoreRelease, type IssueInput } from './score';
import {
  getClassification,
  getLastScoredAt,
  getRelease,
  issuesForVersion,
  issuesWithoutVersion,
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
        const cls: IssueClassification = await classifyIssue(issue, comments, tags);
        upsertClassification(issue.number, cls, issue.updated_at);
        classifiedCount++;
      } catch (e) {
        console.error(`[classify] issue #${issue.number} failed:`, (e as Error).message);
      }
    }

    // 4. Recompute scores per release (treat unversioned negative issues as latest-release tax).
    const allReleases = listReleasesDb(Math.min(100, (config.limits.stableReleases + config.limits.betaReleases) * 6));
    const unversioned = issuesWithoutVersion();
    const latestTag = allReleases[0]?.tag;

    for (const rel of allReleases) {
      const versioned = issuesForVersion(rel.tag);
      const pool = rel.tag === latestTag ? [...versioned, ...unversioned] : versioned;
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
  affects_version: string | null;
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
    affectsVersion: row.affects_version,
    confidence: row.confidence,
    rationale: row.rationale ?? '',
  };
}

// re-export for routes
export { getRelease, issuesForVersion, listReleasesDb, issuesWithoutVersion };
