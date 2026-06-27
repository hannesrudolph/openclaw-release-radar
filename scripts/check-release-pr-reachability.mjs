import { checkReleasePrReachability } from '../src/lib/releaseReachability.ts';

const tag = process.argv[2] ?? 'v2026.6.10';
const result = await checkReleasePrReachability(tag);
console.log(JSON.stringify(result, null, 2));
