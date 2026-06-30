import { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } from '../src/lib/closureProofAnalysis.ts';
import {
  db,
  getClassification,
  insertIngestionEvidenceFailure,
  listReleasesDb,
  runInWriteTransaction,
  upsertClassification,
} from '../src/lib/db.ts';
import { listIssueCommentsBatch, listIssuesBatch } from '../src/lib/github.ts';
import { classifyIssue, PROMPT_VERSION } from '../src/lib/llm.ts';
import { checkReleasePrReachability } from '../src/lib/releaseReachability.ts';
import { buildReleaseScoreRun, persistReleaseScoreRun } from '../src/lib/releaseScoring.ts';
import { assertCleanIngestionMetadataBeforeScore } from './lib/score-ingestion-guard.mjs';

const args = parseArgs(process.argv.slice(2));
const limit = Number(args.limit ?? process.env.RELEASES_LIMIT ?? 10);
const classifyConcurrency = Number(args.concurrency ?? process.env.CLASSIFY_CONCURRENCY ?? 10);
const batchSize = Number(args.batchSize ?? args['batch-size'] ?? 25);
const tagsArg = typeof args.tags === 'string' ? new Set(args.tags.split(',').map((tag) => tag.trim()).filter(Boolean)) : null;
const dryRun = args['dry-run'] === true;
const skipProof = args['skip-proof'] === true;
const skipScore = args['skip-score'] === true;
const runId = new Date().toISOString();

const releases = listReleasesDb(Math.max(limit, 1))
  .filter((release) => release.final_score != null)
  .filter((release) => !tagsArg || tagsArg.has(release.tag));
const releaseTags = releases.map((release) => release.tag);
if (!releaseTags.length) {
  console.log(JSON.stringify({ classified: 0, releases: 0, message: 'No scored releases selected.' }, null, 2));
  process.exit(0);
}

const issueNumbers = rawClosedMissingOrStaleClassification(releaseTags, PROMPT_VERSION);
console.log(JSON.stringify({
  selectedReleases: releaseTags,
  missingOrStaleClosedIssueClassifications: issueNumbers.length,
  dryRun,
}, null, 2));

let classified = 0;
if (!dryRun && issueNumbers.length) {
  const stagedClassifications = new Map();
  for (let offset = 0; offset < issueNumbers.length; offset += batchSize) {
    const chunk = issueNumbers.slice(offset, offset + batchSize);
    try {
      const issues = await listIssuesBatch(chunk);
      const commentsByIssue = await listIssueCommentsBatch(chunk);
      await runWithConcurrency(chunk, classifyConcurrency, async (issueNumber) => {
        const issue = issues.get(issueNumber);
        if (!issue) throw new Error(`GitHub issue #${issueNumber} was not returned`);
        const existing = getClassification(issue.number);
        if (existing && Number(existing.prompt_version) === PROMPT_VERSION) return;
        const comments = commentsByIssue.get(issue.number) ?? [];
        const classification = await classifyIssue(issue, comments, releaseTags);
        stagedClassifications.set(issue.number, {
          issueNumber: issue.number,
          classification,
          issueUpdatedAt: issue.updated_at,
          promptVersion: PROMPT_VERSION,
        });
      });
      console.log(`[classify:stage] ${Math.min(offset + chunk.length, issueNumbers.length)}/${issueNumbers.length}`);
    } catch (error) {
      const message = recordBackfillFailure(
        'backfill-closed-windows-classification',
        `offset ${offset}`,
        error,
        {
          offset,
          batchSize,
          issueCount: chunk.length,
          firstIssueNumber: chunk[0] ?? null,
          lastIssueNumber: chunk[chunk.length - 1] ?? null,
        },
      );
      throw new Error(`${message}; refusing to write partial closed-window classifications`);
    }
  }
  try {
    runInWriteTransaction(() => {
      for (const row of stagedClassifications.values()) {
        upsertClassification(row.issueNumber, row.classification, row.issueUpdatedAt, row.promptVersion);
      }
    });
    classified = stagedClassifications.size;
  } catch (error) {
    const message = recordBackfillFailure(
      'backfill-closed-windows-classification-write',
      'write phase',
      error,
      {
        stagedClassificationCount: stagedClassifications.size,
        issueCount: issueNumbers.length,
        batchSize,
      },
    );
    throw new Error(`${message}; rolled back closed-window classification writes`);
  }
}

const proofResults = [];
if (!dryRun && !skipProof) {
  for (const tag of releaseTags) {
    const closureEvidence = await refreshClosureEvidenceForRelease(tag);
    const reachability = await checkReleasePrReachability(tag);
    const proof = await analyzeClosureProofsForRelease(tag);
    proofResults.push({ tag, closureEvidence, reachability, proof });
    console.log(`[proof] ${tag}: ${proof.analyzed} analyzed`);
  }
}

let scored = 0;
let recommendedTag = null;
if (!dryRun && !skipScore) {
  assertCleanIngestionMetadataBeforeScore(releases);
  const scoreRun = buildReleaseScoreRun({
    releaseLimit: Math.max(limit, releases.length),
  });
  persistReleaseScoreRun(scoreRun, {
    source: 'backfill-closed-windows',
    scope: releaseTags.join(','),
  });
  scored = scoreRun.scored.length;
  recommendedTag = scoreRun.recommendedTag;
}

console.log(JSON.stringify({
  classified,
  proofedReleases: proofResults.length,
  scored,
  recommendedTag,
}, null, 2));

function rawClosedMissingOrStaleClassification(tags, promptVersion) {
  if (!tags.length) return [];
  const selected = JSON.stringify(tags);
  const rows = db.prepare(`
    WITH selected(tag) AS (
      SELECT value FROM json_each(?)
    ),
    windows AS (
      SELECT r.tag,
             r.published_at,
             COALESCE(
               (SELECT MIN(next.published_at)
                FROM releases next
                WHERE next.published_at > r.published_at
                  AND next.prerelease=0),
               '9999-12-31T23:59:59Z'
             ) AS end_at
      FROM releases r
      JOIN selected s ON s.tag=r.tag
      WHERE r.prerelease=0
        AND r.final_score IS NOT NULL
        AND r.published_at IS NOT NULL
    )
    SELECT DISTINCT i.number
    FROM windows w
    JOIN issues i
      ON i.closed_at IS NOT NULL
     AND i.closed_at >= w.published_at
     AND i.closed_at < w.end_at
    LEFT JOIN classifications c ON c.issue_number=i.number
    WHERE c.issue_number IS NULL
       OR c.prompt_version < ?
    ORDER BY i.number DESC
  `).all(selected, promptVersion);
  return rows.map((row) => Number(row.number)).filter((number) => Number.isInteger(number));
}

async function runWithConcurrency(items, limit, worker) {
  let cursor = 0;
  const workers = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      await worker(items[index]);
    }
  });
  await Promise.all(workers);
}

function recordBackfillFailure(source, scope, error, context = {}) {
  const message = `[${source}] ${scope} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source,
    scope,
    issue_number: typeof context.issueNumber === 'number' ? context.issueNumber : null,
    message,
    context_json: JSON.stringify(context),
    scoring_blocking: 1,
  });
  return message;
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
