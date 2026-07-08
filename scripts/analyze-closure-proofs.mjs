import { releaseTagArg } from './lib/release-tag-arg.mjs';

const releaseTag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run analyze:closure-proofs --',
  description: 'Refresh closure evidence, PR reachability, and closure proof for one release tag.',
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
      'GitHub catalog; refusing to write closure proof evidence',
  );
}
const failureSource = 'analyze_closure_proofs';
assertValidIssueCrawlMetadataBeforeMutation();
const {
  analyzeClosureProofsForRelease,
  createClosureProofRunContext,
  refreshClosureEvidenceForRelease,
} = await import('../src/lib/closureProofAnalysis.ts');
const { reconcileClosureSnapshotDrift } = await import('../src/lib/refresh.ts');
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');
const refreshLease = acquireRenewableRefreshLease(`analyze-closure-proofs:${releaseTag}`);
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
  const message = `[analyze_closure_proofs] ${releaseTag} failed: ${error instanceof Error ? error.message : String(error)}`;
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
