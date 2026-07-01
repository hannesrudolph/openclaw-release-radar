import { releaseTagArg } from './lib/release-tag-arg.mjs';

const releaseTag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run analyze:closure-proofs --',
  description: 'Refresh closure evidence, PR reachability, and closure proof for one release tag.',
});
const runId = new Date().toISOString();
const { getRelease, insertIngestionEvidenceFailure, listReleasesDb } = await import('../src/lib/db.ts');
const { assertCleanIngestionMetadataBeforeScore } = await import('./lib/score-ingestion-guard.mjs');
if (!getRelease(releaseTag)) {
  throw new Error(`Release ${releaseTag} does not exist in the local DB; refusing to write closure proof evidence`);
}
assertCleanIngestionMetadataBeforeScore(listReleasesDb(10));
const { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } = await import('../src/lib/closureProofAnalysis.ts');
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');
const { buildReleaseScoreRun, persistReleaseScoreRun } = await import('../src/lib/releaseScoring.ts');
let closureEvidence;
let reachability;
let proof;
let scoreRun;
try {
  closureEvidence = await refreshClosureEvidenceForRelease(releaseTag);
  reachability = await checkReleasePrReachability(releaseTag);
  proof = await analyzeClosureProofsForRelease(releaseTag, { persistScoreAuditPayload: false });
  scoreRun = buildReleaseScoreRun({ releases: listReleasesDb(10) });
  persistReleaseScoreRun(scoreRun, { source: 'analyze-closure-proofs', scope: releaseTag });
} catch (error) {
  const message = `[analyze_closure_proofs] ${releaseTag} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source: 'analyze_closure_proofs',
    scope: releaseTag,
    release_tag: releaseTag,
    message,
    context_json: JSON.stringify({ releaseTag }),
    scoring_blocking: 1,
  });
  throw error;
}
console.log(JSON.stringify({
  closureEvidence,
  reachability,
  proof,
  score: {
    releaseCount: scoreRun.scored.length,
    recommendedTag: scoreRun.recommendedTag,
    sourceIdentityDigest: scoreRun.sourceIdentity.digest,
  },
}, null, 2));
