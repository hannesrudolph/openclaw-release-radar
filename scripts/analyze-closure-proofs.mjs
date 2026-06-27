import { DatabaseSync } from 'node:sqlite';
import { listIssueCommentsBatch } from '../src/lib/github.ts';
import { classifyClosureProof } from '../src/lib/closureProof.ts';
import { upsertIssueClosureProof } from '../src/lib/db.ts';

const releaseTag = process.argv[2] ?? 'v2026.6.10';
const db = new DatabaseSync('./data/radar.db');

const rows = db.prepare(`
WITH target AS (
  SELECT * FROM releases WHERE tag=?
),
closed AS (
  SELECT DISTINCT
    i.number,
    i.title,
    i.closed_at,
    c.sentiment
  FROM issues i
  JOIN classifications c ON c.issue_number=i.number
  JOIN target
  WHERE i.closed_at IS NOT NULL
    AND i.closed_at >= target.published_at
    AND i.closed_at < COALESCE(
      (SELECT MIN(next.published_at) FROM releases next
       WHERE next.published_at > target.published_at AND next.prerelease=0),
      '9999-12-31T23:59:59Z'
    )
    AND NOT EXISTS (
      SELECT 1
      FROM issue_closure_events e
      JOIN issue_pr_links l ON l.issue_number=e.issue_number
      JOIN pull_request_fixes p ON p.pr_number=l.pr_number
      JOIN release_pr_reachability rpr ON rpr.tag=target.tag AND rpr.pr_number=p.pr_number
      WHERE e.issue_number=i.number
        AND e.state_reason='COMPLETED'
        AND p.merged=1
        AND rpr.status='reachable'
        AND (l.will_close_target=1 OR l.source IN ('closedByPullRequestsReferences','ClosedEvent.closer'))
    )
),
agg AS (
  SELECT
    closed.number,
    closed.title,
    closed.closed_at,
    closed.sentiment,
    GROUP_CONCAT(DISTINCT e.state_reason) AS state_reasons,
    GROUP_CONCAT(DISTINCT e.actor_login) AS closure_actors,
    COUNT(DISTINCT e.event_id) AS closure_events,
    COUNT(DISTINCT CASE
      WHEN l.will_close_target=1 OR l.source IN ('closedByPullRequestsReferences','ClosedEvent.closer')
      THEN l.pr_number END
    ) AS closing_links,
    COUNT(DISTINCT CASE
      WHEN (l.will_close_target=1 OR l.source IN ('closedByPullRequestsReferences','ClosedEvent.closer'))
       AND p.merged=1
      THEN p.pr_number END
    ) AS merged_closing_prs,
    COUNT(DISTINCT CASE
      WHEN (l.will_close_target=1 OR l.source IN ('closedByPullRequestsReferences','ClosedEvent.closer'))
       AND p.merged=1
       AND rpr.status='reachable'
      THEN p.pr_number END
    ) AS reachable_closing_prs,
    COUNT(DISTINCT CASE
      WHEN (l.will_close_target=1 OR l.source IN ('closedByPullRequestsReferences','ClosedEvent.closer'))
       AND p.merged=1
       AND rpr.status='not_reachable'
      THEN p.pr_number END
    ) AS not_reachable_closing_prs,
    GROUP_CONCAT(DISTINCT CASE
      WHEN l.will_close_target=1 OR l.source IN ('closedByPullRequestsReferences','ClosedEvent.closer')
      THEN p.pr_number || ':' || COALESCE(p.title, '')
      END
    ) AS closing_prs
  FROM closed
  LEFT JOIN issue_closure_events e ON e.issue_number=closed.number
  LEFT JOIN issue_pr_links l ON l.issue_number=closed.number
  LEFT JOIN pull_request_fixes p ON p.pr_number=l.pr_number
  LEFT JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_number=l.pr_number
  GROUP BY closed.number
)
SELECT * FROM agg
ORDER BY closed_at DESC
`).all(releaseTag, releaseTag);

const commentsByIssue = await listIssueCommentsBatch(rows.map((row) => row.number));
const counts = new Map();
for (const row of rows) {
  const comments = (commentsByIssue.get(row.number) ?? []).map((comment) => ({
    author: comment.user?.login ?? null,
    body: comment.body,
    createdAt: comment.created_at,
  }));
  const result = classifyClosureProof({
    issueNumber: row.number,
    sentiment: row.sentiment,
    stateReasons: splitCsv(row.state_reasons),
    closureActors: splitCsv(row.closure_actors),
    hasClosureEvent: Number(row.closure_events ?? 0) > 0,
    hasClosingLink: Number(row.closing_links ?? 0) > 0,
    hasMergedClosingPr: Number(row.merged_closing_prs ?? 0) > 0,
    hasReachableClosingPr: Number(row.reachable_closing_prs ?? 0) > 0,
    hasNotReachableClosingPr: Number(row.not_reachable_closing_prs ?? 0) > 0,
    comments,
  });
  const evidence = {
    ...result.evidence,
    title: row.title,
    closedAt: row.closed_at,
    closingPrs: splitCsv(row.closing_prs),
  };
  upsertIssueClosureProof({
    release_tag: releaseTag,
    issue_number: row.number,
    status: result.status,
    summary: result.summary,
    evidence_json: JSON.stringify(evidence),
  });
  counts.set(result.status, (counts.get(result.status) ?? 0) + 1);
}

console.log(JSON.stringify({
  releaseTag,
  analyzed: rows.length,
  buckets: Object.fromEntries([...counts.entries()].sort((a, b) => b[1] - a[1])),
}, null, 2));

function splitCsv(value) {
  if (!value) return [];
  return String(value).split(',').map((item) => item.trim()).filter(Boolean);
}
