// Compatibility wrapper for older workflows. The old implementation refreshed
// only raw closure/PR evidence, which could leave proof rows and score-audit
// gate evidence stale. This now runs the full release fix-provenance pipeline.
import { releaseTagArg } from './lib/release-tag-arg.mjs';

const releaseTag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run ingest:fix-provenance --',
  description: 'Compatibility alias for the full closure proof and reachability pipeline.',
});
const runId = new Date().toISOString();
const { getRelease, insertIngestionEvidenceFailure, listReleasesDb } = await import('../src/lib/db.ts');
const { assertCleanIngestionMetadataBeforeScore } = await import('./lib/score-ingestion-guard.mjs');
if (!getRelease(releaseTag)) {
  throw new Error(`Release ${releaseTag} does not exist in the local DB; refusing to write fix provenance evidence`);
}
assertCleanIngestionMetadataBeforeScore(listReleasesDb(10));
const { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } = await import('../src/lib/closureProofAnalysis.ts');
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');

let closureEvidence;
let reachability;
let proof;
try {
  closureEvidence = await refreshClosureEvidenceForRelease(releaseTag);
  reachability = await checkReleasePrReachability(releaseTag);
  proof = await analyzeClosureProofsForRelease(releaseTag);
} catch (error) {
  const message = `[ingest_fix_provenance] ${releaseTag} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source: 'ingest_fix_provenance',
    scope: releaseTag,
    release_tag: releaseTag,
    message,
    context_json: JSON.stringify({ releaseTag }),
    scoring_blocking: 1,
  });
  throw error;
}

console.log(JSON.stringify({
  releaseTag,
  closureEvidence,
  reachability,
  proof,
}, null, 2));
