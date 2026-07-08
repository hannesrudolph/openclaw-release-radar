const {
  allScored,
  releaseTags,
} = parseCommentSnapshotArgs(process.argv.slice(2));
if (allScored && releaseTags.length > 0) {
  throw new Error('Use either --all-scored or explicit release tags, not both');
}
const classificationConcurrency = positiveInteger(
  process.env.CLASSIFY_CONCURRENCY ?? 10,
  'CLASSIFY_CONCURRENCY',
);
const runId = new Date().toISOString();
const failureSource = 'backfill-issue-comment-snapshots';
const {
  acquireRenewableRefreshLease,
  db,
  getRelease,
  insertIngestionEvidenceFailure,
  issueEvidenceRevisions,
  issuesForVersion,
} = await import('../src/lib/db.ts');
if (releaseTags.length > 0) assertActiveStableReleaseTags(releaseTags);

const lease = acquireRenewableRefreshLease('backfill-issue-comment-snapshots');
let tags = [];
let issueNumbers = [];
let failureScope = null;
let snapshotCommitted = false;

try {
  if (releaseTags.length > 0) assertActiveStableReleaseTags(releaseTags);
  tags = releaseTags.length
    ? releaseTags
    : db.prepare(`
    SELECT tag
    FROM releases
    WHERE prerelease=0
      AND catalog_active=1
      AND (
        final_score IS NOT NULL
        OR scored_at IS NOT NULL
        OR EXISTS (
          SELECT 1 FROM release_score_audits audit
          WHERE audit.release_tag=releases.tag
        )
      )
    ORDER BY published_at DESC
    ${allScored ? '' : 'LIMIT 10'}
  `).all().map((row) => row.tag);

  if (!tags.length) throw new Error('No release tags selected for issue comment snapshot backfill');

  issueNumbers = [...new Set(tags.flatMap((tag) =>
    issuesForVersion(tag).map((issue) => Number(issue.number)),
  ))]
    .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0)
    .sort((left, right) => right - left);
  lease.assertHeld('comment snapshot scope derivation');
  const {
    canonicalManualScope,
    supersedeExactIngestionEvidenceFailures,
  } = await import('./lib/manual-command-scope.mjs');
  failureScope = canonicalManualScope({ releaseTags: tags, issueNumbers });
  const [
    { listIssueCommentSnapshotsBatch },
    { reconcileIssueCommentSnapshots },
  ] = await Promise.all([
    import('../src/lib/github.ts'),
    import('../src/lib/refresh.ts'),
  ]);
  const snapshotsByIssue = new Map();
  const startedAt = new Date().toISOString();
  const expectedRevisions = issueEvidenceRevisions(issueNumbers);

  for (let offset = 0; offset < issueNumbers.length; offset += 250) {
    const chunk = issueNumbers.slice(offset, offset + 250);
    const snapshots = await listIssueCommentSnapshotsBatch(chunk);
    for (const [issueNumber, snapshot] of snapshots) snapshotsByIssue.set(issueNumber, snapshot);
    console.error(
      `[comment-snapshots] fetched ${Math.min(offset + chunk.length, issueNumbers.length)}/${issueNumbers.length}`,
    );
  }

  const result = await reconcileIssueCommentSnapshots({
    issueNumbers,
    releaseTags: tags,
    snapshotsByIssue,
    classificationConcurrency,
    snapshotAt: startedAt,
    expectedRevisions,
    assertCanWrite: (stage) => lease.assertHeld(stage),
  });
  snapshotCommitted = true;
  const finalSnapshots = result.snapshotsByIssue;
  lease.assertHeld('comment snapshot backfill recovery');
  supersedeExactIngestionEvidenceFailures(db, {
    successfulRunId: runId,
    source: failureSource,
    scope: failureScope,
  });

  console.log(JSON.stringify({
    schemaVersion: 2,
    startedAt,
    finishedAt: new Date().toISOString(),
    releaseTags: tags,
    issueCount: issueNumbers.length,
    issuesWithComments: issueNumbers.filter((issueNumber) =>
      (finalSnapshots.get(issueNumber)?.totalCount ?? 0) > 0
    ).length,
    zeroCommentSnapshots: issueNumbers.filter((issueNumber) =>
      finalSnapshots.get(issueNumber)?.totalCount === 0
    ).length,
    snapshotsWritten: issueNumbers.length,
    reconciledIssues: result.reconciledIssueNumbers.length,
    classifiedIssues: result.classifiedIssueNumbers.length,
  }, null, 2));
} catch (error) {
  if (!failureScope) throw error;
  const message = `[${failureSource}] failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source: failureSource,
    scope: failureScope,
    message,
    context_json: JSON.stringify({
      releaseTags: tags,
      issueNumbers,
      snapshotCommitted,
    }),
    scoring_blocking: 1,
  });
  const outcome = snapshotCommitted
    ? 'snapshot changes were committed before the post-commit lease or recovery failure'
    : 'no reconciled snapshot transaction was committed';
  throw new Error(`${message}; ${outcome}`, { cause: error });
} finally {
  lease.release();
}

function parseCommentSnapshotArgs(argv) {
  const releaseTags = [];
  let allScored = false;
  for (const arg of argv) {
    if (arg === '--all-scored') {
      if (allScored) throw new Error('Option --all-scored may only be specified once');
      allScored = true;
      continue;
    }
    if (arg.startsWith('--all-scored=')) {
      throw new Error('Boolean option --all-scored does not accept a value');
    }
    if (arg.startsWith('--')) {
      throw new Error(`Unknown option ${arg.split('=', 1)[0]}`);
    }
    if (!validReleaseTag(arg)) {
      throw new Error(`Invalid release tag ${JSON.stringify(arg)}`);
    }
    if (releaseTags.includes(arg)) {
      throw new Error(`Release tag ${JSON.stringify(arg)} may only be specified once`);
    }
    releaseTags.push(arg);
  }
  return { allScored, releaseTags };
}

function validReleaseTag(tag) {
  return Boolean(tag) && !tag.startsWith('-') && !/\s/.test(tag);
}

function positiveInteger(value, name) {
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0) {
    throw new Error(`${name} must be a positive integer, got ${String(value)}`);
  }
  return number;
}

function assertActiveStableReleaseTags(releaseTags) {
  const invalid = releaseTags.filter((tag) => {
    const release = getRelease(tag);
    return !release ||
      release.catalog_active !== 1 ||
      release.prerelease === 1 ||
      release.published_at == null;
  });
  if (invalid.length > 0) {
    throw new Error(
      `Selected release tag(s) are not active published stable releases: ${invalid.join(', ')}`,
    );
  }
}
