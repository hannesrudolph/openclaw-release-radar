import { assertSupportedNodeVersion } from './node-version.mjs';

assertSanitizedTestEntrypointEnvironment();
assertSupportedNodeVersion();
const args = process.argv.slice(2);
const full = args.includes('--full');
const unexpected = args.filter((argument) => argument !== '--full');
const focusedTestGuidance =
  'For focused validation: npm run test:focus -- [--authoritative] ' +
  '<manifest-test-file> [--name <pattern>]';

if (unexpected.length > 0) {
  console.error(
    `Unsupported full-test argument(s): ${unexpected.join(', ')}\n` +
    focusedTestGuidance,
  );
  process.exitCode = 1;
} else if (!full) {
  console.error(
    'Full test runs require the explicit --full flag.\n' +
    focusedTestGuidance,
  );
  process.exitCode = 1;
} else {
  const { tsImport } = await import('tsx/esm/api');
  const { runTestSuite } = await tsImport(
    './test-suite-runner.mjs',
    import.meta.url,
  );
  try {
    const result = await runTestSuite({
      mode: 'verify',
      forwardedArgs: [],
    });

    if (result.interruptedBy) {
      process.kill(process.pid, result.interruptedBy);
    } else if (!result.ok) {
      process.exitCode = 1;
    }
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
