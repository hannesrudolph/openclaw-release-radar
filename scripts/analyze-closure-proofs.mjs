import { releaseTagArg } from './lib/release-tag-arg.mjs';

const releaseTag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run analyze:closure-proofs --',
  description: 'Refresh closure evidence, PR reachability, and closure proof for one release tag.',
});
const { analyzeClosureProofsForRelease, refreshClosureEvidenceForRelease } = await import('../src/lib/closureProofAnalysis.ts');
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');
const closureEvidence = await refreshClosureEvidenceForRelease(releaseTag);
const reachability = await checkReleasePrReachability(releaseTag);
const proof = await analyzeClosureProofsForRelease(releaseTag);
console.log(JSON.stringify({ closureEvidence, reachability, proof }, null, 2));
