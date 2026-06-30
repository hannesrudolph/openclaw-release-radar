import { createHash } from 'node:crypto';

const {
  db,
  issuesForVersion,
  runInWriteTransaction,
  upsertIssueCommentSnapshot,
} = await import('../src/lib/db.ts');
const { listIssueCommentsBatch } = await import('../src/lib/github.ts');

const args = new Set(process.argv.slice(2));
const allScored = args.has('--all-scored');
const releaseTags = process.argv.slice(2).filter((arg) => !arg.startsWith('--'));

const tags = releaseTags.length
  ? releaseTags
  : db.prepare(`
    SELECT tag
    FROM releases
    WHERE prerelease=0
      AND final_score IS NOT NULL
    ORDER BY published_at DESC
    ${allScored ? '' : 'LIMIT 10'}
  `).all().map((row) => row.tag);

if (!tags.length) throw new Error('No release tags selected for issue comment snapshot backfill');

const issuesByNumber = new Map();
for (const tag of tags) {
  for (const issue of issuesForVersion(tag)) {
    issuesByNumber.set(Number(issue.number), {
      number: Number(issue.number),
      comments: Number(issue.comments ?? 0),
    });
  }
}

const issues = [...issuesByNumber.values()].sort((a, b) => b.number - a.number);
const withComments = issues.filter((issue) => issue.comments > 0);
const fetchedComments = new Map();
const startedAt = new Date().toISOString();

for (let offset = 0; offset < withComments.length; offset += 250) {
  const chunk = withComments.slice(offset, offset + 250);
  const comments = await listIssueCommentsBatch(chunk.map((issue) => issue.number));
  for (const [issueNumber, rows] of comments) fetchedComments.set(issueNumber, rows);
  console.error(`[comment-snapshots] fetched ${Math.min(offset + chunk.length, withComments.length)}/${withComments.length}`);
}

runInWriteTransaction(() => {
  for (const issue of issues) {
    const comments = fetchedComments.get(issue.number) ?? [];
    upsertIssueCommentSnapshot({
      issue_number: issue.number,
      comment_count: issue.comments,
      fetched_comment_count: comments.length,
      latest_comment_updated_at: latestCommentUpdatedAt(comments),
      comments_digest: commentDigest(issue.comments, comments),
    });
  }
});

console.log(JSON.stringify({
  schemaVersion: 1,
  startedAt,
  finishedAt: new Date().toISOString(),
  releaseTags: tags,
  issueCount: issues.length,
  issuesWithComments: withComments.length,
  snapshotsWritten: issues.length,
}, null, 2));

function latestCommentUpdatedAt(comments) {
  return comments
    .map((comment) => comment.updated_at ?? comment.created_at ?? null)
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

function commentDigest(totalCommentCount, comments) {
  const hash = createHash('sha256');
  hash.update(JSON.stringify({
    totalCommentCount,
    comments: comments
      .map((comment) => ({
        id: comment.id,
        author: comment.user?.login ?? null,
        association: comment.author_association ?? null,
        body: comment.body,
        createdAt: comment.created_at,
        updatedAt: comment.updated_at,
      }))
      .sort((a, b) => String(a.updatedAt ?? a.createdAt ?? '').localeCompare(String(b.updatedAt ?? b.createdAt ?? '')) ||
        Number(a.id ?? 0) - Number(b.id ?? 0)),
  }));
  return hash.digest('hex');
}
