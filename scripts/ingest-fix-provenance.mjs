import {
  getReleaseCommit,
  listIssueFixEvidenceBatch,
} from '../src/lib/github.ts';
import {
  db,
  upsertIssueClosureEvent,
  upsertIssuePrLink,
  upsertPullRequestFix,
  upsertReleaseCommit,
} from '../src/lib/db.ts';

const tag = process.argv[2] ?? 'v2026.6.10';

const release = db.prepare(`SELECT tag, published_at FROM releases WHERE tag=?`).get(tag);
if (!release) throw new Error(`release not found in local DB: ${tag}`);

const closedIssues = db.prepare(`
SELECT i.number
FROM issues i
JOIN classifications c ON c.issue_number=i.number
JOIN releases target ON target.tag=?
WHERE i.closed_at IS NOT NULL
  AND i.closed_at >= target.published_at
  AND c.sentiment='negative'
ORDER BY
  CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
  i.closed_at DESC
`).all(tag).map((row) => row.number);

const commit = await getReleaseCommit(tag);
upsertReleaseCommit({
  tag,
  tag_commit_oid: commit.oid,
  committed_at: commit.committedAt,
});

let closureEvents = 0;
let prLinks = 0;
let pullRequests = 0;
for (let offset = 0; offset < closedIssues.length; offset += 20) {
  const chunk = closedIssues.slice(offset, offset + 20);
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

console.log(JSON.stringify({
  tag,
  tagCommit: commit,
  closedIssues: closedIssues.length,
  closureEvents,
  prLinks,
  pullRequests,
  mergedPullRequests: db.prepare(`SELECT COUNT(*) AS n FROM pull_request_fixes WHERE merged=1`).get().n,
}, null, 2));
