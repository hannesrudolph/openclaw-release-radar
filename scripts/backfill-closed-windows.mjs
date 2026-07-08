import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
} from '../src/lib/commentEvidence.ts';

const args = parseClosedWindowArgs(process.argv.slice(2));
if (args.all === true && args.tags) {
  throw new Error('Use either --all or --tags, not both');
}
const limit = args.all === true
  ? 1_000_000
  : positiveInteger(args.limit ?? process.env.RELEASES_LIMIT ?? 10, '--limit');
const monitoredLimit = positiveInteger(process.env.RELEASES_LIMIT ?? 10, 'RELEASES_LIMIT');
const classifyConcurrency = positiveInteger(
  args.concurrency ?? process.env.CLASSIFY_CONCURRENCY ?? 10,
  '--concurrency',
);
const requestedTags = args.tags == null ? null : parseReleaseTagList(args.tags);
const dryRun = args['dry-run'] === true;
const skipProof = args['skip-proof'] === true;
const skipScore = args['skip-score'] === true;
const runId = new Date().toISOString();

// db.ts snapshots this flag at module evaluation; dry-run must not bootstrap writable.
if (dryRun) process.env.RADAR_DB_READ_ONLY = '1';

const {
  acquireRenewableRefreshLease,
  classifierSourceIdentity,
  db,
  getMeta,
  getRelease,
  getReleaseScoreAudit,
  insertIngestionEvidenceFailure,
  listReleasesDb,
  releaseClosureProofIntegrity,
} = await import('../src/lib/db.ts');
const {
  assertCleanIngestionMetadataBeforeScore,
  assertValidIssueCrawlMetadataBeforeMutation,
} = await import('./lib/score-ingestion-guard.mjs');
if (requestedTags) assertActiveAuditedStableReleaseTags(requestedTags);
assertValidIssueCrawlMetadataBeforeMutation();
const lease = dryRun ? null : acquireRenewableRefreshLease('backfill-closed-windows');
let runtime = null;

backfillRun: try {
  if (lease) {
    assertValidIssueCrawlMetadataBeforeMutation();
    if (requestedTags) assertActiveAuditedStableReleaseTags(requestedTags);
  }
  const activeStableReleases = listReleasesDb(1_000_000);
  const auditedReleases = activeStableReleases.filter((release) =>
    release.final_score != null ||
    release.scored_at != null ||
    getReleaseScoreAudit(release.tag) != null);
  const requestedTagSet = requestedTags ? new Set(requestedTags) : null;
  const releases = requestedTagSet
    ? auditedReleases.filter((release) => requestedTagSet.has(release.tag))
    : auditedReleases.slice(0, Math.max(limit, 1));
  const releaseTags = releases.map((release) => release.tag);
  lease?.assertHeld('closed-window scope derivation');
  if (!releaseTags.length) {
    console.log(JSON.stringify({
      classified: 0,
      releases: 0,
      dryRun,
      message: 'No audited releases selected.',
    }, null, 2));
    process.exitCode = 0;
    break backfillRun;
  }

  const [
    closureProofAnalysis,
    llm,
    refresh,
    reachability,
    scoring,
    manualScope,
    scoreWindow,
  ] = await Promise.all([
    import('../src/lib/closureProofAnalysis.ts'),
    import('../src/lib/llm.ts'),
    import('../src/lib/refresh.ts'),
    import('../src/lib/releaseReachability.ts'),
    import('../src/lib/releaseScoring.ts'),
    import('./lib/manual-command-scope.mjs'),
    import('./lib/score-run-window.mjs'),
  ]);
  runtime = {
    ...closureProofAnalysis,
    ...manualScope,
    releaseClosureProofIntegrity,
  };
  const {
    analyzeClosureProofsForRelease,
    createClosureProofRunContext,
    refreshClosureEvidenceForRelease,
  } = closureProofAnalysis;
  const { PROMPT_VERSION } = llm;
  const { reconcileIssueCommentSnapshots } = refresh;
  const { checkReleasePrReachability } = reachability;
  const { buildReleaseScoreRun, persistReleaseScoreRun } = scoring;
  const {
    canonicalManualScope,
    exactIngestionFailureMatches,
    manualScorePlan,
  } = manualScope;
  const {
    monitoredScoreWindowReleases,
    scoreRunWindowOptions,
  } = scoreWindow;
  const monitoredReleases = monitoredScoreWindowReleases(monitoredLimit);
  const monitoredReleaseTags = monitoredReleases.map((release) => release.tag);
  const selectedReleaseTagSet = new Set(releaseTags);
  const selectedCoversMonitoredWindow = monitoredReleaseTags.every((tag) =>
    selectedReleaseTagSet.has(tag));
  const scorePlan = manualScorePlan({
    selectedReleaseTags: releaseTags,
    monitoredReleaseTags,
    skipProof,
    skipScore,
  });
  const stagedOnlyReason = scorePlan.status === 'staged-only' ? scorePlan.reason : null;
  const closureRunContext = lease
    ? createClosureProofRunContext({ assertCanWrite: (stage) => lease.assertHeld(stage) })
    : null;
  const classifierIdentity = classifierSourceIdentity(releaseTags, PROMPT_VERSION);

const issueNumbers = rawClosedMissingOrStaleClassification(
  releaseTags,
  PROMPT_VERSION,
  classifierIdentity.digest,
);
console.log(JSON.stringify({
  selectedReleases: releaseTags,
  missingOrStaleClosedIssueClassifications: issueNumbers.length,
  dryRun,
  monitoredReleaseTags,
  scorePlan: dryRun
    ? { status: 'dry-run' }
    : scorePlan,
}, null, 2));

let classified = 0;
const classificationScope = canonicalManualScope({ releaseTags, issueNumbers });
if (!dryRun && issueNumbers.length) {
  let classificationCommitted = false;
  try {
    const reconciliation = await reconcileIssueCommentSnapshots({
      issueNumbers,
      classifyIssueNumbers: issueNumbers,
      releaseTags,
      classificationConcurrency: classifyConcurrency,
      assertCanWrite: (stage) => lease?.assertHeld(stage),
    });
    classificationCommitted = true;
    classified = reconciliation.classifiedIssueNumbers.length;
    lease?.assertHeld('closed-window classification recovery');
    recoverBackfillFailure(
      'backfill-closed-windows-classification',
      classificationScope,
    );
    console.log(
      `[classify] ${classified}/${issueNumbers.length} closed issue(s) classified from stable comment snapshots`,
    );
  } catch (error) {
    const message = recordBackfillFailure(
      'backfill-closed-windows-classification',
      classificationScope,
      error,
      {
        releaseTags,
        issueNumbers,
        classificationCommitted,
      },
    );
    const outcome = classificationCommitted
      ? 'reconciled issue evidence was committed before the post-commit lease or recovery failure'
      : 'rolled back reconciled closed-window issue evidence and classifications';
    throw new Error(`${message}; ${outcome}`);
  }
}

const proofResults = [];
if (!dryRun && !skipProof) {
  for (const tag of releaseTags) {
    let closureEvidence;
    let reachability;
    let proof;
    try {
      closureEvidence = await refreshClosureEvidenceForRelease(tag, closureRunContext);
      lease?.assertHeld(`closed-window closure evidence completion for ${tag}`);
      recoverBackfillFailure(
        'backfill-closed-windows-closure-evidence',
        tag,
        tag,
      );
    } catch (error) {
      const message = recordBackfillFailure(
        'backfill-closed-windows-closure-evidence',
        tag,
        error,
        { releaseTag: tag },
      );
      throw new Error(`${message}; refusing to continue closed-window backfill`);
    }
    try {
      reachability = await checkReleasePrReachability(tag);
      lease?.assertHeld(`closed-window reachability completion for ${tag}`);
      recoverBackfillFailure(
        'backfill-closed-windows-reachability',
        tag,
        tag,
      );
    } catch (error) {
      const message = recordBackfillFailure(
        'backfill-closed-windows-reachability',
        tag,
        error,
        { releaseTag: tag },
      );
      throw new Error(`${message}; refusing to continue closed-window backfill`);
    }
    try {
      // Static contract reference: analyzeClosureProofsForRelease(tag, { persistScoreAuditPayload: false })
      proof = await analyzeClosureProofsForRelease(tag, {
        persistScoreAuditPayload: false,
        runContext: closureRunContext,
      });
      lease?.assertHeld(`closed-window closure proof completion for ${tag}`);
      recoverBackfillFailure(
        'backfill-closed-windows-closure-proof',
        tag,
        tag,
      );
    } catch (error) {
      const message = recordBackfillFailure(
        'backfill-closed-windows-closure-proof',
        tag,
        error,
        { releaseTag: tag },
      );
      throw new Error(`${message}; refusing to continue closed-window backfill`);
    }
    proofResults.push({ tag, closureEvidence, reachability, proof });
    console.log(`[proof] ${tag}: ${proof.analyzed} analyzed`);
  }

  const maxStabilizationPasses = 3;
  let unsettledTags = releaseTags.filter((tag) => !closureProofIsCurrent(tag));
  for (
    let pass = 1;
    pass <= maxStabilizationPasses && unsettledTags.length > 0;
    pass++
  ) {
    lease?.renew(`closed-window closure proof stabilization pass ${pass}`);
    for (const tag of releaseTags) {
      try {
        const proof = await analyzeClosureProofsForRelease(tag, {
          persistScoreAuditPayload: false,
          refreshCommentPrMentionEvidence: false,
          refreshPrReachability: false,
          runContext: closureRunContext,
        });
        console.log(`[proof-stabilize] pass ${pass} ${tag}: ${proof.analyzed} analyzed`);
      } catch (error) {
        const message = recordBackfillFailure(
          'backfill-closed-windows-closure-proof-stabilization',
          tag,
          error,
          { releaseTag: tag, stabilizationPass: pass },
        );
        throw new Error(`${message}; refusing to continue closed-window backfill`);
      }
    }
    unsettledTags = releaseTags.filter((tag) => !closureProofIsCurrent(tag));
    if (unsettledTags.length > 0) {
      console.log(
        `[proof-stabilize] pass ${pass} left ${unsettledTags.length} ` +
        `release(s) unsettled: ${unsettledTags.join(', ')}`,
      );
    }
  }
  if (unsettledTags.length > 0) {
    const error = new Error(
      `Closure proof dependencies did not stabilize after ${maxStabilizationPasses} passes: ` +
      unsettledTags.join(', '),
    );
    for (const tag of unsettledTags) {
      recordBackfillFailure(
        'backfill-closed-windows-closure-proof-stabilization',
        tag,
        error,
        { releaseTag: tag, maxStabilizationPasses },
      );
    }
    throw error;
  }
  for (const tag of releaseTags) {
    lease?.assertHeld(`closed-window closure proof stabilization recovery for ${tag}`);
    recoverBackfillFailure(
      'backfill-closed-windows-closure-proof-stabilization',
      tag,
      tag,
    );
  }
}

let scored = 0;
let recommendedTag = null;
let scoreResult = dryRun
  ? { status: 'dry-run', monitoredReleaseTags }
  : stagedOnlyReason
    ? { status: 'staged-only', reason: stagedOnlyReason, monitoredReleaseTags }
    : null;
if (!dryRun && !stagedOnlyReason) {
  const scoreFailureCoordinate = {
    source: 'backfill-closed-windows-score',
    scope: canonicalManualScope({ releaseTags: monitoredReleaseTags }),
    releaseTag: null,
    issueNumber: null,
    prRepositoryNameWithOwner: null,
    prNumber: null,
  };
  assertCleanIngestionMetadataBeforeScore(monitoredReleases, {
    ignoreFailure: (failure) =>
      exactIngestionFailureMatches(failure, scoreFailureCoordinate),
  });
  let scoreCommitted = false;
  try {
    const scoreRun = buildReleaseScoreRun(scoreRunWindowOptions(monitoredReleases));
    lease?.assertHeld('closed-window score persistence');
    persistReleaseScoreRun(scoreRun, {
      source: 'backfill-closed-windows',
      runId,
      scope: scoreFailureCoordinate.scope,
    });
    scoreCommitted = true;
    lease?.assertHeld('closed-window score post-commit recovery');
    recoverBackfillFailure(
      scoreFailureCoordinate.source,
      scoreFailureCoordinate.scope,
    );
    scored = scoreRun.scored.length;
    recommendedTag = scoreRun.recommendedTag;
    scoreResult = {
      status: 'committed',
      releaseCount: scored,
      recommendedTag,
      monitoredReleaseTags,
      sourceIdentityDigest: scoreRun.sourceIdentity.digest,
    };
  } catch (error) {
    scoreCommitted ||= scoreRunCommittedByThisCommand(runId);
    const message = recordBackfillFailure(
      scoreFailureCoordinate.source,
      scoreFailureCoordinate.scope,
      error,
      { releaseTags: monitoredReleaseTags, scoreCommitted },
    );
    const outcome = scoreCommitted
      ? 'the complete monitored score window was committed before the post-commit failure'
      : 'the score transaction did not commit';
    throw new Error(`${message}; ${outcome}`);
  }
}

console.log(JSON.stringify({
  classified,
  proofedReleases: proofResults.length,
  scored,
  recommendedTag,
  score: scoreResult,
}, null, 2));
} finally {
  lease?.release();
}

function rawClosedMissingOrStaleClassification(tags, promptVersion, sourceIdentityDigest) {
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
                  AND next.prerelease=0
                  AND next.catalog_active=1),
               '9999-12-31T23:59:59Z'
             ) AS end_at
      FROM releases r
      JOIN selected s ON s.tag=r.tag
      WHERE r.prerelease=0
        AND r.catalog_active=1
        AND (
          r.final_score IS NOT NULL
          OR r.scored_at IS NOT NULL
          OR EXISTS (
            SELECT 1 FROM release_score_audits audit
            WHERE audit.release_tag=r.tag
          )
        )
        AND r.published_at IS NOT NULL
    )
    SELECT DISTINCT i.number
    FROM windows w
    JOIN issues i
      ON i.closed_at IS NOT NULL
     AND i.closed_at >= w.published_at
     AND i.closed_at < w.end_at
    LEFT JOIN classifications c ON c.issue_number=i.number
    LEFT JOIN issue_comment_snapshots comments ON comments.issue_number=i.number
    WHERE c.issue_number IS NULL
       OR c.prompt_version < ?
       OR comments.issue_number IS NULL
       OR comments.schema_version != ${AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION}
       OR c.classified_updated_at IS NOT comments.issue_updated_at
       OR c.classified_comments_digest IS NOT comments.comments_digest
       OR c.source_identity_digest IS NOT ?
    ORDER BY i.number DESC
  `).all(selected, promptVersion, sourceIdentityDigest);
  return rows.map((row) => Number(row.number)).filter((number) => Number.isInteger(number));
}

function closureProofIsCurrent(tag) {
  const integrity = runtime.releaseClosureProofIntegrity(tag, 1);
  return integrity.missingCount === 0 &&
    integrity.extraCount === 0 &&
    integrity.staleCount === 0 &&
    integrity.analyzerVersionMismatchCount === 0;
}

function recoverBackfillFailure(source, scope, releaseTag = null, issueNumber = null) {
  return runtime.supersedeExactIngestionEvidenceFailures(db, {
    successfulRunId: runId,
    source,
    scope,
    releaseTag,
    issueNumber,
  });
}

function scoreRunCommittedByThisCommand(successfulRunId) {
  const raw = getMeta('score_persistence_last_run');
  if (!raw) return false;
  try {
    const meta = JSON.parse(raw);
    return meta?.source === 'backfill-closed-windows' &&
      meta?.historyRunId === `backfill-closed-windows:${successfulRunId}`;
  } catch {
    return false;
  }
}

function recordBackfillFailure(source, scope, error, context = {}) {
  const message = `[${source}] ${scope} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source,
    scope,
    release_tag: typeof context.releaseTag === 'string' ? context.releaseTag : null,
    issue_number: typeof context.issueNumber === 'number' ? context.issueNumber : null,
    pr_repository_name_with_owner: typeof context.prRepositoryNameWithOwner === 'string' ? context.prRepositoryNameWithOwner : null,
    pr_number: typeof context.prNumber === 'number' ? context.prNumber : null,
    message,
    context_json: JSON.stringify(context),
    scoring_blocking: 1,
  });
  return message;
}

function parseClosedWindowArgs(argv) {
  const booleanOptions = new Set(['all', 'dry-run', 'skip-proof', 'skip-score']);
  const valueOptions = new Set(['limit', 'concurrency', 'tags']);
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

function parseReleaseTagList(value) {
  const tags = String(value).split(',').map((tag) => tag.trim());
  if (tags.length === 0 || tags.some((tag) => !validReleaseTag(tag))) {
    throw new Error('--tags must contain comma-separated non-empty release tags without whitespace');
  }
  if (new Set(tags).size !== tags.length) {
    throw new Error('--tags must not contain duplicate release tags');
  }
  return tags;
}

function validReleaseTag(tag) {
  return Boolean(tag) && !tag.startsWith('-') && !/\s/.test(tag);
}

function assertActiveAuditedStableReleaseTags(tags) {
  const invalid = tags.filter((tag) => {
    const release = getRelease(tag);
    return !release ||
      release.catalog_active !== 1 ||
      release.prerelease === 1 ||
      release.published_at == null ||
      (
        release.final_score == null &&
        release.scored_at == null &&
        getReleaseScoreAudit(tag) == null
      );
  });
  if (invalid.length > 0) {
    throw new Error(
      `Selected release tag(s) are not active audited stable releases: ${invalid.join(', ')}`,
    );
  }
}
