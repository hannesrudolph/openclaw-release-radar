const args = parseIssueStateArgs(process.argv.slice(2));
if (args.batchSize != null && args['batch-size'] != null) {
  throw new Error('Use either --batch-size or --batchSize, not both');
}
const limit = positiveInteger(args.limit ?? process.env.RELEASES_LIMIT ?? 10, '--limit');
const batchSize = positiveInteger(args.batchSize ?? args['batch-size'] ?? 50, '--batch-size');
const dryRun = args['dry-run'] === true;
const snapshotAt = new Date().toISOString();
const runId = snapshotAt;

// db.ts snapshots this flag at module evaluation; dry-run must not bootstrap writable.
if (dryRun) process.env.RADAR_DB_READ_ONLY = '1';

const {
  acquireRenewableRefreshLease,
  assertIssueEvidenceRevisions,
  db,
  insertIngestionEvidenceFailure,
  issueEvidenceRevisions,
  runInWriteTransaction,
  upsertIssueLabelSnapshot,
} = await import('../src/lib/db.ts');

let closureEvents = 0;
let reopenEvents = 0;
let prLinks = 0;
let pullRequests = 0;
let commitReferences = 0;
let stateEvidenceCommitted = false;
const lease = dryRun ? null : acquireRenewableRefreshLease('backfill-issue-state-events');

try {
  const issueNumbers = roughScoredIssueUniverse(limit);
  lease?.assertHeld('issue state scope derivation');
  console.log(JSON.stringify({
    selectedIssues: issueNumbers.length,
    limit,
    batchSize,
    snapshotAt,
    dryRun,
  }, null, 2));

  if (!dryRun) {
    const [
      { listIssueFixEvidenceBatch },
      { replaceVerifiedIssueStateEventSnapshot },
      {
        canonicalManualScope,
        supersedeExactIngestionEvidenceFailures,
      },
    ] = await Promise.all([
      import('../src/lib/github.ts'),
      import('../src/lib/closureProofAnalysis.ts'),
      import('./lib/manual-command-scope.mjs'),
    ]);
    const expectedRevisions = issueEvidenceRevisions(issueNumbers);
    const writeScope = canonicalManualScope({ issueNumbers });
    const evidenceByIssue = new Map();
    let missingAliasCount = 0;
    for (let offset = 0; offset < issueNumbers.length; offset += batchSize) {
      const chunk = issueNumbers.slice(offset, offset + batchSize);
      const chunkScope = canonicalManualScope({ issueNumbers: chunk });
      const beforeMissingAliases = missingAliasCount;
      let chunkEvidence;
      try {
        chunkEvidence = await listIssueFixEvidenceBatch(chunk, {
          onMissingIssueAlias: ({ issueNumber, aliasIndex }) => {
            missingAliasCount++;
            recordBackfillEvidenceFailure(
              'backfill-issue-state-events-missing-alias',
              canonicalManualScope({ issueNumbers: [issueNumber] }),
              new Error('GitHub issue alias was missing during fix evidence batch recovery'),
              { issueNumber, aliasIndex, offset, batchSize },
            );
          },
        });
      } catch (error) {
        const message = recordBackfillEvidenceFailure(
          'backfill-issue-state-events',
          chunkScope,
          error,
          {
            offset,
            batchSize,
            issueNumbers: chunk,
          },
        );
        throw new Error(`${message}; refusing to write partial issue state evidence`);
      }
      if (missingAliasCount > beforeMissingAliases) {
        throw new Error(`Refusing to write partial issue state evidence after ${missingAliasCount - beforeMissingAliases} missing issue alias failure(s)`);
      }
      lease.assertHeld(`issue state evidence chunk ${offset} completion`);
      for (const [issueNumber, evidence] of chunkEvidence.entries()) {
        evidenceByIssue.set(issueNumber, evidence);
      }
      console.log(`[state-events:fetch] ${Math.min(offset + chunk.length, issueNumbers.length)}/${issueNumbers.length}`);
    }

    try {
      lease.assertHeld('issue state evidence persistence');
      runInWriteTransaction(() => {
        assertIssueEvidenceRevisions(expectedRevisions);
        snapshotCurrentLabels(issueNumbers, snapshotAt);
        for (let offset = 0; offset < issueNumbers.length; offset += batchSize) {
          const chunk = issueNumbers.slice(offset, offset + batchSize);
          for (const issueNumber of chunk) {
            const evidence = evidenceByIssue.get(issueNumber);
            if (!evidence) continue;
            replaceVerifiedIssueStateEventSnapshot(evidence);
            closureEvents += evidence.closureEvents.length;
            reopenEvents += evidence.reopenEvents.length;
            prLinks += evidence.prLinks.length;
            commitReferences += evidence.commitReferences.length;
            pullRequests += evidence.pullRequests.length;
          }
          console.log(`[state-events] ${Math.min(offset + chunk.length, issueNumbers.length)}/${issueNumbers.length}`);
        }
        for (let offset = 0; offset < issueNumbers.length; offset += batchSize) {
          const chunk = issueNumbers.slice(offset, offset + batchSize);
          supersedeExactIngestionEvidenceFailures(db, {
            successfulRunId: runId,
            source: 'backfill-issue-state-events',
            scope: canonicalManualScope({ issueNumbers: chunk }),
          });
          for (const issueNumber of chunk) {
            supersedeExactIngestionEvidenceFailures(db, {
              successfulRunId: runId,
              source: 'backfill-issue-state-events-missing-alias',
              scope: canonicalManualScope({ issueNumbers: [issueNumber] }),
              issueNumber,
            });
          }
        }
        supersedeExactIngestionEvidenceFailures(db, {
          successfulRunId: runId,
          source: 'backfill-issue-state-events-write',
          scope: writeScope,
        });
      });
      stateEvidenceCommitted = true;
      lease.assertHeld('issue state evidence post-commit recovery');
    } catch (error) {
      const message = recordBackfillEvidenceFailure(
        'backfill-issue-state-events-write',
        writeScope,
        error,
        {
          issueNumbers,
          batchSize,
          snapshotAt,
          stateEvidenceCommitted,
        },
      );
      const outcome = stateEvidenceCommitted
        ? 'issue state evidence was committed before the post-commit lease or recovery failure'
        : 'rolled back issue state evidence writes';
      throw new Error(`${message}; ${outcome}`);
    }
  }
} finally {
  lease?.release();
}

console.log(JSON.stringify({
  closureEvents,
  reopenEvents,
  prLinks,
  pullRequests,
  commitReferences,
}, null, 2));

function recordBackfillEvidenceFailure(source, scope, error, context = {}) {
  const message = `[${source}] ${scope} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source,
    scope,
    release_tag: typeof context.releaseTag === 'string' ? context.releaseTag : null,
    issue_number: typeof context.issueNumber === 'number' ? context.issueNumber : null,
    message,
    context_json: JSON.stringify(context),
    scoring_blocking: 1,
  });
  return message;
}

function roughScoredIssueUniverse(releaseLimit) {
  const rows = db.prepare(`
    WITH selected AS (
      SELECT tag, published_at
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
             AND next.prerelease=0
             AND next.catalog_active=1),
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

function parseIssueStateArgs(argv) {
  const booleanOptions = new Set(['dry-run']);
  const valueOptions = new Set(['limit', 'batch-size', 'batchSize']);
  const out = {};
  const seen = new Set();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      throw new Error(`Unexpected positional argument ${JSON.stringify(arg)}`);
    }
    const eq = arg.indexOf('=');
    const key = arg.slice(2, eq === -1 ? undefined : eq);
    if (!booleanOptions.has(key) && !valueOptions.has(key)) {
      throw new Error(`Unknown option --${key}`);
    }
    if (seen.has(key)) throw new Error(`Option --${key} may only be specified once`);
    seen.add(key);
    if (eq !== -1) {
      if (booleanOptions.has(key)) {
        throw new Error(`Boolean option --${key} does not accept a value`);
      }
      const value = arg.slice(eq + 1);
      if (!value) throw new Error(`Option --${key} requires a value`);
      out[key] = value;
      continue;
    }
    if (booleanOptions.has(key)) {
      out[key] = true;
      continue;
    }
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) throw new Error(`Option --${key} requires a value`);
    out[key] = next;
    i++;
  }
  return out;
}

function positiveInteger(value, name) {
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0) {
    throw new Error(`${name} must be a positive integer, got ${String(value)}`);
  }
  return number;
}
