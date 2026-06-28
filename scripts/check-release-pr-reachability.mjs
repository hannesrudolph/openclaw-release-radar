import { releaseTagArg } from './lib/release-tag-arg.mjs';

const tag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run check:release-pr-reachability --',
  description: 'Check PR merge-commit reachability for one release tag.',
});
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');
const result = await checkReleasePrReachability(tag);
console.log(JSON.stringify(result, null, 2));
