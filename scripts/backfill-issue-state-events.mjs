import {
  db,
  upsertIssueClosureEvent,
  upsertIssueLabelSnapshot,
  upsertIssuePrLink,
  upsertIssueReopenEvent,
  upsertPullRequestFix,
} from '../src/lib/db.ts';
import { listIssueFixEvidenceBatch } from '../src/lib/github.ts';

const args = parseArgs(process.argv.slice(2));
const limit = Number(args.limit ?? process.env.RELEASES_LIMIT ?? 10);
const batchSize = Number(args.batchSize ?? args['batch-size'] ?? 50);
const dryRun = args['dry-run'] === true;

const issueNumbers = roughScoredIssueUniverse(limit);
const snapshotAt = new Date().toISOString();
console.log(JSON.stringify({
  selectedIssues: issueNumbers.length,
  limit,
  batchSize,
  snapshotAt,
  dryRun,
}, null, 2));

let closureEvents = 0;
let reopenEvents = 0;
let prLinks = 0;
let pullRequests = 0;

if (!dryRun) {
  snapshotCurrentLabels(issueNumbers, snapshotAt);
  for (let offset = 0; offset < issueNumbers.length; offset += batchSize) {
    const chunk = issueNumbers.slice(offset, offset + batchSize);
    const evidenceByIssue = await listIssueFixEvidenceBatch(chunk);
    for (const evidence of evidenceByIssue.values()) {
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
        closureEvents++;
      }
      for (const event of evidence.reopenEvents) {
        upsertIssueReopenEvent({
          issue_number: event.issueNumber,
          event_id: event.eventId,
          reopened_at: event.reopenedAt,
          actor_login: event.actorLogin,
          raw_json: JSON.stringify(event.raw),
        });
        reopenEvents++;
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
        prLinks++;
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
        pullRequests++;
      }
    }
    console.log(`[state-events] ${Math.min(offset + chunk.length, issueNumbers.length)}/${issueNumbers.length}`);
  }
}

console.log(JSON.stringify({
  closureEvents,
  reopenEvents,
  prLinks,
  pullRequests,
}, null, 2));

function roughScoredIssueUniverse(releaseLimit) {
  const rows = db.prepare(`
    WITH selected AS (
      SELECT tag, published_at
      FROM releases
      WHERE prerelease=0
        AND final_score IS NOT NULL
        AND published_at IS NOT NULL
      ORDER BY published_at DESC
      LIMIT ?
    ),
    windows AS (
      SELECT
        s.tag,
        s.published_at AS start_at,
        COALESCE(
          (SELECT MIN(next.published_at)
           FROM releases next
           WHERE next.published_at > s.published_at
             AND next.prerelease=0),
          '9999-12-31T23:59:59Z'
        ) AS end_at
      FROM selected s
    )
    SELECT DISTINCT i.number
    FROM issues i
    JOIN windows w
      ON i.created_at < w.end_at
     AND (i.closed_at IS NULL OR i.closed_at > w.start_at)
    ORDER BY i.number DESC
  `).all(releaseLimit);
  return rows.map((row) => Number(row.number)).filter((number) => Number.isInteger(number));
}

function snapshotCurrentLabels(issueNumbers, snapshotAt) {
  if (!issueNumbers.length) return;
  for (let offset = 0; offset < issueNumbers.length; offset += 500) {
    const chunk = issueNumbers.slice(offset, offset + 500);
    const rows = db.prepare(`
      WITH selected(issue_number) AS (
        SELECT value FROM json_each(?)
      )
      SELECT i.number, i.labels
      FROM issues i
      JOIN selected s ON s.issue_number=i.number
    `).all(JSON.stringify(chunk));
    for (const row of rows) {
      upsertIssueLabelSnapshot({
        issue_number: Number(row.number),
        snapshot_at: snapshotAt,
        labels_json: String(row.labels ?? '[]'),
      });
    }
  }
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      out[arg.slice(2, eq)] = arg.slice(eq + 1);
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) out[key] = true;
    else {
      out[key] = next;
      i++;
    }
  }
  return out;
}
