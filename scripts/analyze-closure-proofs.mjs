import { analyzeClosureProofsForRelease } from '../src/lib/closureProofAnalysis.ts';

const releaseTag = process.argv[2] ?? 'v2026.6.10';
const result = await analyzeClosureProofsForRelease(releaseTag);
console.log(JSON.stringify(result, null, 2));
