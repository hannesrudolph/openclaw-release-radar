import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseQualityRefreshArgs,
  validateQualityRefreshDatabase,
} from './lib/quality-refresh-cli.mjs';
import {
  acquireRepositoryDatabaseWriterLock,
  pathsReferToSameFile,
} from '../src/lib/exclusiveProcessLock.ts';

const repositoryRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const { databasePath, resumeExisting } = parseQualityRefreshArgs(
  process.argv.slice(2),
);
const configuredApplicationEnvironment = {
  databasePath: process.env.DB_PATH,
  dotenvConfigPath: process.env.DOTENV_CONFIG_PATH,
};

process.env.DB_PATH = databasePath;
process.env.RADAR_DB_READ_ONLY = '0';
process.env.RADAR_DB_BOOTSTRAP_MODE = 'fresh';
process.env.REFRESH_ON_STARTUP = 'false';
process.env.REFRESH_MINUTES = '0';

const writerLock = acquireRepositoryDatabaseWriterLock({
  repositoryRoot,
  label: 'quality database refresh',
  databasePath,
});

let databaseModule;
let operationError = null;
const cleanupErrors = [];
try {
  validateQualityRefreshDatabase({
    databasePath,
    repositoryRoot,
    resumeExisting,
    environmentDatabasePath: configuredApplicationEnvironment.databasePath,
    dotenvConfigPath: configuredApplicationEnvironment.dotenvConfigPath,
  });
  if (resumeExisting) {
    process.env.RADAR_DB_BOOTSTRAP_MODE = 'existing';
  }
  databaseModule = await import('../src/lib/db.ts');
  if (
    !databaseModule.openedDatabasePath ||
    !pathsReferToSameFile(databaseModule.openedDatabasePath, databasePath)
  ) {
    throw new Error(
      `Database module opened ${String(databaseModule.openedDatabasePath)} ` +
      `instead of the requested quality database ${databasePath}`,
    );
  }
  const refreshModule = await import('../src/lib/refresh.ts');
  const result = await refreshModule.refresh({
    operation: 'quality-refresh',
    trigger: 'manual-cli',
  });
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  operationError = error;
} finally {
  try {
    databaseModule?.db.close();
  } catch (error) {
    cleanupErrors.push(error);
  } finally {
    try {
      writerLock.release();
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
}

if (operationError && cleanupErrors.length > 0) {
  throw new AggregateError(
    [operationError, ...cleanupErrors],
    'Quality refresh and cleanup both failed',
  );
}
if (operationError) throw operationError;
if (cleanupErrors.length > 0) {
  throw new AggregateError(cleanupErrors, 'Quality refresh cleanup failed');
}
