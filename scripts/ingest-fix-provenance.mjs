// Compatibility wrapper for older workflows. The old implementation refreshed
// only raw closure/PR evidence, which could leave proof rows and score-audit
// gate evidence stale. This now runs the full release fix-provenance pipeline.
import { releaseTagArg } from './lib/release-tag-arg.mjs';

const releaseTag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run ingest:fix-provenance --',
  description: 'Compatibility alias for the full closure proof and reachability pipeline.',
});
const runId = new Date().toISOString();
const {
  acquireRenewableRefreshLease,
  currentAuthorizedReleaseCatalog,
  db,
  getRelease,
  insertIngestionEvidenceFailure,
} = await import('../src/lib/db.ts');
const { assertValidIssueCrawlMetadataBeforeMutation } = await import('./lib/score-ingestion-guard.mjs');
const {
  supersedeExactIngestionEvidenceFailures,
} = await import('./lib/manual-command-scope.mjs');
const authorizedCatalog = currentAuthorizedReleaseCatalog();
const release = getRelease(releaseTag);
if (
  !release ||
  release.catalog_active !== 1 ||
  release.prerelease !== 0 ||
  !authorizedCatalog.tags.includes(releaseTag)
) {
  throw new Error(
    `Release ${releaseTag} is not an active stable release in the authorized ` +
      'GitHub catalog; refusing to write fix provenance evidence',
  );
}
const failureSource = 'ingest_fix_provenance';
assertValidIssueCrawlMetadataBeforeMutation();
const {
  analyzeClosureProofsForRelease,
  createClosureProofRunContext,
  refreshClosureEvidenceForRelease,
} = await import('../src/lib/closureProofAnalysis.ts');
const { reconcileClosureSnapshotDrift } = await import('../src/lib/refresh.ts');
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');
const refreshLease = acquireRenewableRefreshLease(`ingest-fix-provenance:${releaseTag}`);
assertValidIssueCrawlMetadataBeforeMutation();
const closureRunContext = createClosureProofRunContext({
  assertCanWrite: (stage) => refreshLease.assertHeld(stage),
});

let closureEvidence;
let reachability;
let proof;
let proofCommitted = false;
try {
  closureEvidence = await refreshClosureEvidenceForRelease(releaseTag, closureRunContext);
  refreshLease.assertHeld('single-release closure evidence completion');
  reachability = await checkReleasePrReachability(releaseTag);
  refreshLease.assertHeld('single-release reachability completion');
  proof = await analyzeWithDriftReconciliation();
  proofCommitted = true;
  refreshLease.assertHeld('single-release proof completion');
  supersedeExactIngestionEvidenceFailures(db, {
    successfulRunId: runId,
    source: failureSource,
    scope: releaseTag,
    releaseTag,
  });
} catch (error) {
  const message = `[ingest_fix_provenance] ${releaseTag} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source: failureSource,
    scope: releaseTag,
    release_tag: releaseTag,
    message,
    context_json: JSON.stringify({ releaseTag, proofCommitted }),
    scoring_blocking: 1,
  });
  throw error;
} finally {
  refreshLease.release();
}

console.log(JSON.stringify({
  releaseTag,
  closureEvidence,
  reachability,
  proof,
  score: {
    status: 'staged-only',
    reason: 'single-release proof repair does not replace the monitored score window',
    nextCommand: 'npm run backfill:closed-windows -- --all',
  },
}, null, 2));

async function analyzeWithDriftReconciliation() {
  const maxAnalysisAttempts = 4;
  let lastError;
  for (let attempt = 1; attempt <= maxAnalysisAttempts; attempt++) {
    refreshLease.renew(`single-release proof attempt ${attempt}`);
    try {
      return await analyzeClosureProofsForRelease(releaseTag, {
        persistScoreAuditPayload: false,
        runContext: closureRunContext,
      });
    } catch (error) {
      lastError = error;
      const reconciliation = await reconcileClosureSnapshotDrift({
        runContext: closureRunContext,
        releaseTags: [releaseTag],
        assertCanWrite: (stage) => refreshLease.assertHeld(stage),
        rerunAffected: async () => {
          closureEvidence = await refreshClosureEvidenceForRelease(releaseTag, closureRunContext);
        },
      });
      if (reconciliation.reconciledIssueNumbers.length === 0) throw error;
    }
  }
  throw lastError;
}
