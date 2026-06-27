import { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } from '../src/lib/closureProofAnalysis.ts';
import { checkReleasePrReachability } from '../src/lib/releaseReachability.ts';

const releaseTag = process.argv[2] ?? 'v2026.6.10';
const closureEvidence = await refreshClosureEvidenceForRelease(releaseTag);
const reachability = await checkReleasePrReachability(releaseTag);
const proof = await analyzeClosureProofsForRelease(releaseTag);
console.log(JSON.stringify({ closureEvidence, reachability, proof }, null, 2));
