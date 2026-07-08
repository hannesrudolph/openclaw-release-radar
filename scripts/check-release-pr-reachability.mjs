import {
  parseReleaseReachabilityArgs,
  releaseReachabilityUsage,
} from './lib/release-reachability-args.mjs';

const command = 'npm run check:release-pr-reachability --';
let args;
try {
  args = parseReleaseReachabilityArgs(process.argv.slice(2), { command });
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  console.error(`Run ${command} --help for usage.`);
  process.exit(1);
}
if (args.mode === 'help') {
  console.log(releaseReachabilityUsage(command));
  process.exit(0);
}
if (args.mode === 'direct_commit') {
  const {
    checkDirectCommitFirstContainingReleaseFromRemoteCatalog,
  } = await import('../src/lib/releaseReachability.ts');
  const result = await checkDirectCommitFirstContainingReleaseFromRemoteCatalog({
    repositoryNameWithOwner: args.repositoryNameWithOwner,
    commitOid: args.commitOid,
    targetTag: args.tag,
    predecessorTag: args.predecessorTag,
  });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.creditEligible ? 0 : 2);
}

const tag = args.tag;
const runId = new Date().toISOString();
const {
  acquireRenewableRefreshLease,
  currentAuthorizedReleaseCatalog,
  db,
  getRelease,
  insertIngestionEvidenceFailure,
} = await import('../src/lib/db.ts');
const authorizedCatalog = currentAuthorizedReleaseCatalog();
const release = getRelease(tag);
if (
  !release ||
  release.catalog_active !== 1 ||
  release.prerelease !== 0 ||
  !authorizedCatalog.tags.includes(tag)
) {
  throw new Error(
    `Release ${tag} is not an active stable release in the authorized GitHub ` +
      'catalog; refusing to write reachability evidence',
  );
}
const {
  supersedeExactIngestionEvidenceFailures,
} = await import('./lib/manual-command-scope.mjs');
const { checkReleasePrReachability } = await import('../src/lib/releaseReachability.ts');
const failureSource = 'release_pr_reachability';
const lease = acquireRenewableRefreshLease(`check-release-pr-reachability:${tag}`);
let result;
let reachabilityCommitted = false;
try {
  result = await checkReleasePrReachability(tag);
  reachabilityCommitted = true;
  lease.assertHeld('standalone reachability post-commit recovery');
  supersedeExactIngestionEvidenceFailures(db, {
    successfulRunId: runId,
    source: failureSource,
    scope: tag,
    releaseTag: tag,
  });
} catch (error) {
  const message = `[${failureSource}] ${tag} failed: ${error instanceof Error ? error.message : String(error)}`;
  insertIngestionEvidenceFailure({
    run_id: runId,
    source: failureSource,
    scope: tag,
    release_tag: tag,
    message,
    context_json: JSON.stringify({ releaseTag: tag, reachabilityCommitted }),
    scoring_blocking: 1,
  });
  const outcome = reachabilityCommitted
    ? 'reachability replacement was committed before the post-commit lease or recovery failure'
    : 'previous reachability rows remain intact';
  throw new Error(`${message}; ${outcome}`, { cause: error });
} finally {
  lease.release();
}
console.log(JSON.stringify(result, null, 2));
