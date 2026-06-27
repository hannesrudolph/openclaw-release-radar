// Compatibility wrapper for older workflows. The old implementation refreshed
// only raw closure/PR evidence, which could leave proof rows and score-audit
// gate evidence stale. This now runs the full release fix-provenance pipeline.
import { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } from '../src/lib/closureProofAnalysis.ts';
import { checkReleasePrReachability } from '../src/lib/releaseReachability.ts';

const releaseTag = process.argv[2] ?? 'v2026.6.10';

const closureEvidence = await refreshClosureEvidenceForRelease(releaseTag);
const reachability = await checkReleasePrReachability(releaseTag);
const proof = await analyzeClosureProofsForRelease(releaseTag);

console.log(JSON.stringify({
  releaseTag,
  closureEvidence,
  reachability,
  proof,
}, null, 2));
