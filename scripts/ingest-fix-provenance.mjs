// Compatibility wrapper for older workflows. The old implementation refreshed
// only raw closure/PR evidence, which could leave proof rows and score-audit
// gate evidence stale. This now runs the full release fix-provenance pipeline.
import { releaseTagArg } from './lib/release-tag-arg.mjs';

const releaseTag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run ingest:fix-provenance --',
  description: 'Compatibility alias for the full closure proof and reachability pipeline.',
});
const { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } = await import('../src/lib/closureProofAnalysis.ts');
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');

const closureEvidence = await refreshClosureEvidenceForRelease(releaseTag);
const reachability = await checkReleasePrReachability(releaseTag);
const proof = await analyzeClosureProofsForRelease(releaseTag);

console.log(JSON.stringify({
  releaseTag,
  closureEvidence,
  reachability,
  proof,
}, null, 2));
