import {
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { resolveConfiguredLiveDatabase } from './live-database-path.mjs';
import {
  captureSqliteFamilyFingerprint,
} from './sqlite-family-fingerprint.mjs';

const maximumDiagnosticCharacters = 2_048;

try {
  const [repositoryRootArgument, writeProbePath] = process.argv.slice(2);
  if (
    process.argv.length !== 4 ||
    !repositoryRootArgument ||
    !writeProbePath
  ) {
    throw new Error(
      'Live database inspection requires repository-root and write-probe arguments.',
    );
  }
  if (
    process.env.RADAR_TEST_LIVE_DB_INSPECTION_BOUNDARY !==
      'darwin-seatbelt-v1'
  ) {
    throw new Error(
      'Live database inspection requires the kernel deny-write boundary.',
    );
  }

  const repositoryRoot = realpathSync.native(repositoryRootArgument);
  if (
    !isAbsolute(repositoryRootArgument) ||
    repositoryRoot !== repositoryRootArgument ||
    !isAbsolute(writeProbePath) ||
    resolve(writeProbePath) !== writeProbePath
  ) {
    throw new Error('Live database inspection paths must be canonical and absolute.');
  }

  assertWriteDenied(writeProbePath);
  const liveDatabase = resolveConfiguredLiveDatabase({
    root: repositoryRoot,
    environment: {
      DB_PATH: process.env.DB_PATH,
      DOTENV_CONFIG_PATH: process.env.DOTENV_CONFIG_PATH,
    },
  });
  if (liveDatabase === null) {
    throw new Error(
      'Configured live database must be file-backed for test isolation.',
    );
  }
  const fingerprint = captureSqliteFamilyFingerprint(liveDatabase);
  process.stdout.write(JSON.stringify({
    schemaVersion: 1,
    kind: 'live-database-inspection',
    liveDatabase,
    fingerprint,
  }));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(
    `[live-database-inspection] ${
      message.slice(0, maximumDiagnosticCharacters)
    }\n`,
  );
  process.exitCode = 1;
}

function assertWriteDenied(path) {
  try {
    writeFileSync(path, 'deny-write-probe', {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
  } catch (error) {
    if (error?.code === 'EACCES' || error?.code === 'EPERM') return;
    throw new Error(
      `Kernel deny-write probe failed unexpectedly: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  rmSync(path, { force: true });
  throw new Error('Kernel deny-write boundary allowed the inspection probe write.');
}
