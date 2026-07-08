import { assertSupportedNodeVersion } from './node-version.mjs';

assertSanitizedTestEntrypointEnvironment();
assertSupportedNodeVersion();
const args = process.argv.slice(2);
const allowBootstrap = args.includes('--bootstrap');
const unexpected = args.filter((argument) => argument !== '--bootstrap');

if (unexpected.length > 0) {
  console.error(
    `Unsupported baseline acceptance argument(s): ${unexpected.join(', ')}`,
  );
  process.exitCode = 1;
} else {
  const { tsImport } = await import('tsx/esm/api');
  const { acceptTestBaselineCandidate } = await tsImport(
    './test-suite-runner.mjs',
    import.meta.url,
  );
  try {
    const accepted = acceptTestBaselineCandidate({ allowBootstrap });
    console.log(JSON.stringify(accepted, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  }
}

function assertSanitizedTestEntrypointEnvironment() {
  const inheritedNames = [
    'NODE_OPTIONS',
    'NODE_PATH',
    'npm_lifecycle_event',
  ].filter((name) =>
    Object.prototype.hasOwnProperty.call(process.env, name),
  );
  if (
    inheritedNames.length > 0 ||
    !process.execArgv.includes('--no-global-search-paths')
  ) {
    throw new Error(
      'Test entrypoints require NODE_OPTIONS, NODE_PATH, and ' +
      'npm_lifecycle_event to be unset before Node starts and require ' +
      '--no-global-search-paths; use the declared npm script.',
    );
  }
}
