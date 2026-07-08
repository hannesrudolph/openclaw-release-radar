import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertSupportedNodeVersion } from './node-version.mjs';

assertSanitizedTestEntrypointEnvironment();
assertSupportedNodeVersion();
const { tsImport } = await import('tsx/esm/api');
const {
  acquireRepositoryDatabaseWriterLock,
} = await tsImport('../src/lib/exclusiveProcessLock.ts', import.meta.url);

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const writerLock = acquireRepositoryDatabaseWriterLock({
  repositoryRoot,
  label: 'database guard self-test',
});
try {
  await tsImport('./verify-database-guard.mjs', import.meta.url);
} finally {
  writerLock.release();
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
