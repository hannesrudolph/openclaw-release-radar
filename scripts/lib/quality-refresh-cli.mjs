import { resolve } from 'node:path';
import { lstatSync, realpathSync, statSync } from 'node:fs';

export function parseQualityRefreshArgs(
  argv,
  {
    cwd = process.cwd(),
    repositoryRoot = cwd,
    environment = process.env,
  } = {},
) {
  if (
    argv.length !== 2 ||
    argv[0] !== '--db-path' ||
    !argv[1] ||
    argv[1].startsWith('--')
  ) {
    throw new Error(
      'Usage: refresh:quality -- --db-path <isolated-quality-database>',
    );
  }

  const databasePath = resolve(cwd, argv[1]);
  const liveDatabasePath = resolve(repositoryRoot, 'data', 'radar.db');
  if (pathsReferToSameFile(databasePath, liveDatabasePath)) {
    throw new Error(
      'refresh:quality refuses data/radar.db; use a separate quality database',
    );
  }

  const existingFamilyMember = sqliteFamily(databasePath)
    .find(pathEntryExists);
  if (existingFamilyMember) {
    throw new Error(
      'refresh:quality requires a fresh database; ' +
      `SQLite family member already exists: ${existingFamilyMember}`,
    );
  }

  environment.RADAR_DB_BOOTSTRAP_MODE = 'fresh';
  return { databasePath };
}

function sqliteFamily(databasePath) {
  return [
    databasePath,
    `${databasePath}-wal`,
    `${databasePath}-shm`,
    `${databasePath}-journal`,
  ];
}

function pathEntryExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw new Error(
      `refresh:quality could not verify database path absence: ${path}`,
      { cause: error },
    );
  }
}

function pathsReferToSameFile(left, right) {
  if (left === right) return true;
  try {
    if (realpathSync(left) === realpathSync(right)) return true;
  } catch {
    // One side may not exist yet.
  }
  try {
    const leftStat = statSync(left);
    const rightStat = statSync(right);
    return leftStat.dev === rightStat.dev && leftStat.ino === rightStat.ino;
  } catch {
    return false;
  }
}
