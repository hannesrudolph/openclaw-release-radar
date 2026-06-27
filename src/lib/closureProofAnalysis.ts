import { db, deleteIssueClosureProofsForRelease, upsertIssueClosureEvent, upsertIssueClosureProof, upsertIssuePrLink, upsertPullRequestFix } from './db';
import { classifyClosureProof } from './closureProof';
import { listIssueCommentsBatch, listIssueFixEvidenceBatch } from './github';

export interface ClosureProofAnalysisResult {
  releaseTag: string;
  analyzed: number;
  buckets: Record<string, number>;
  rawEvidence: {
    closureEvents: number;
    prLinks: number;
    pullRequests: number;
  };
}

const closedIssueRowsStmt = db.prepare(`
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
    AND target.published_at IS NOT NULL
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
)
SELECT * FROM closed
ORDER BY closed_at DESC
`);

const aggregateRowsStmt = db.prepare(`
WITH selected(issue_number) AS (
  SELECT value FROM json_each(?)
)
SELECT
  i.number,
  i.title,
  i.closed_at,
  c.sentiment,
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
FROM selected
JOIN issues i ON i.number=selected.issue_number
LEFT JOIN classifications c ON c.issue_number=i.number
LEFT JOIN issue_closure_events e ON e.issue_number=i.number
LEFT JOIN issue_pr_links l ON l.issue_number=i.number
LEFT JOIN pull_request_fixes p ON p.pr_number=l.pr_number
LEFT JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_number=l.pr_number
GROUP BY i.number
ORDER BY i.closed_at DESC
`);

export async function analyzeClosureProofsForRelease(releaseTag: string): Promise<ClosureProofAnalysisResult> {
  const closedRows = closedIssueRowsStmt.all(releaseTag) as Array<{ number: number }>;
  const issueNumbers = closedRows.map((row) => row.number);
  const rawEvidence = await refreshRawClosureEvidence(issueNumbers);
  const aggregateRows = issueNumbers.length
    ? aggregateRowsStmt.all(JSON.stringify(issueNumbers), releaseTag) as Array<any>
    : [];
  const commentsByIssue = await listIssueCommentsBatch(issueNumbers);
  const counts = new Map<string, number>();
  deleteIssueClosureProofsForRelease(releaseTag);

  for (const row of aggregateRows) {
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

  return {
    releaseTag,
    analyzed: aggregateRows.length,
    buckets: Object.fromEntries([...counts.entries()].sort((a, b) => b[1] - a[1])),
    rawEvidence,
  };
}

async function refreshRawClosureEvidence(issueNumbers: number[]): Promise<ClosureProofAnalysisResult['rawEvidence']> {
  let closureEvents = 0;
  let prLinks = 0;
  let pullRequests = 0;
  for (let offset = 0; offset < issueNumbers.length; offset += 20) {
    const chunk = issueNumbers.slice(offset, offset + 20);
    const evidence = await listIssueFixEvidenceBatch(chunk);
    for (const item of evidence.values()) {
      for (const event of item.closureEvents) {
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
      for (const link of item.prLinks) {
        upsertIssuePrLink({
          issue_number: link.issueNumber,
          pr_number: link.prNumber,
          source: link.source,
          will_close_target: link.willCloseTarget == null ? null : link.willCloseTarget ? 1 : 0,
          referenced_at: link.referencedAt,
        });
        prLinks++;
      }
      for (const pr of item.pullRequests) {
        upsertPullRequestFix({
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
  }
  return { closureEvents, prLinks, pullRequests };
}

function splitCsv(value: unknown): string[] {
  if (!value) return [];
  return String(value).split(',').map((item) => item.trim()).filter(Boolean);
}
