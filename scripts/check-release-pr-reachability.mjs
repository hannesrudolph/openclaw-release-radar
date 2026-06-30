import { releaseTagArg } from './lib/release-tag-arg.mjs';

const tag = releaseTagArg(process.argv.slice(2), {
  command: 'npm run check:release-pr-reachability --',
  description: 'Check PR merge-commit reachability for one release tag.',
});
const runId = new Date().toISOString();
const { getRelease, insertIngestionEvidenceFailure } = await import('../src/lib/db.ts');
if (!getRelease(tag)) {
  throw new Error(`Release ${tag} does not exist in the local DB; refusing to write reachability evidence`);
}
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');
let result;
try {
  result = await checkReleasePrReachability(tag);
} catch (error) {
  const message = `[release_pr_reachability] ${tag} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source: 'release_pr_reachability',
    scope: tag,
    release_tag: tag,
    message,
    context_json: JSON.stringify({ releaseTag: tag }),
    scoring_blocking: 1,
  });
  throw error;
}
console.log(JSON.stringify(result, null, 2));
