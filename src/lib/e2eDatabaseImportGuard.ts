import {
  closeSync,
  constants as fsConstants,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  type Stats,
} from 'node:fs';
import {
  basename,
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from 'node:path';

type DatabaseGuardAttestation = {
  databasePath: string;
  databaseIdentity: {
    dev: string;
    ino: string;
  } | null;
  dotenvPath: string;
  tempRoot: string;
};

type DatabaseBootstrapMode = 'fresh' | 'existing';

export function createE2eDatabaseImportGuard(input: {
  helperName: string;
  guardAttestation: DatabaseGuardAttestation;
  expectedBootstrapMode: DatabaseBootstrapMode;
}): {
  databasePath: string;
  assertReady(): void;
} {
  const databasePath = requiredEnvironmentPath('DB_PATH', input.helperName);
  const dotenvPath = requiredEnvironmentPath(
    'DOTENV_CONFIG_PATH',
    input.helperName,
  );
  const tempRoot = requiredEnvironmentPath(
    'RADAR_TEST_TEMP_ROOT',
    input.helperName,
  );

  assertAttestedPath(
    input.helperName,
    'DB_PATH',
    databasePath,
    input.guardAttestation.databasePath,
  );
  assertAttestedPath(
    input.helperName,
    'DOTENV_CONFIG_PATH',
    dotenvPath,
    input.guardAttestation.dotenvPath,
  );
  assertAttestedPath(
    input.helperName,
    'RADAR_TEST_TEMP_ROOT',
    tempRoot,
    input.guardAttestation.tempRoot,
  );
  const assertReady = (): void => {
    assertEnvironmentUnchanged(
      input.helperName,
      'DB_PATH',
      databasePath,
    );
    assertEnvironmentUnchanged(
      input.helperName,
      'DOTENV_CONFIG_PATH',
      dotenvPath,
    );
    assertEnvironmentUnchanged(
      input.helperName,
      'RADAR_TEST_TEMP_ROOT',
      tempRoot,
    );
    assertEnvironmentUnchanged(
      input.helperName,
      'RADAR_DB_BOOTSTRAP_MODE',
      input.expectedBootstrapMode,
    );

    assertPrivateDirectory(tempRoot, 'RADAR_TEST_TEMP_ROOT');
    assertPrivateArtifactPath(databasePath, 'DB_PATH', tempRoot);
    assertPrivateArtifactPath(dotenvPath, 'DOTENV_CONFIG_PATH', tempRoot);
    if (databasePath === dotenvPath) {
      throw new Error(
        `${input.helperName} DB_PATH and DOTENV_CONFIG_PATH must differ`,
      );
    }
    if (basename(databasePath) !== 'radar.db') {
      throw new Error(`${input.helperName} DB_PATH must name radar.db`);
    }
    assertPrivateRegularFile(dotenvPath, 'DOTENV_CONFIG_PATH', {
      empty: true,
    });

    if (input.expectedBootstrapMode === 'fresh') {
      assertFreshDatabaseIdentityAttestation(
        input.helperName,
        input.guardAttestation.databaseIdentity,
      );
      assertFreshDatabaseFamily(databasePath, input.helperName);
    } else {
      const databaseIdentity = requireExistingDatabaseIdentityAttestation(
        input.helperName,
        input.guardAttestation.databaseIdentity,
      );
      assertExistingDatabaseFamily(
        databasePath,
        databaseIdentity,
        input.helperName,
      );
    }
  };

  assertReady();
  return Object.freeze({
    databasePath,
    assertReady,
  });
}

function requiredEnvironmentPath(name: string, helperName: string): string {
  const value = process.env[name];
  if (!value || value.trim() !== value) {
    throw new Error(
      `${helperName} requires an explicit ${name} without surrounding whitespace`,
    );
  }
  if (!isAbsolute(value) || resolve(value) !== value) {
    throw new Error(`${helperName} ${name} must be an absolute canonical path`);
  }
  return value;
}

function assertAttestedPath(
  helperName: string,
  name: string,
  path: string,
  attestedPath: string,
): void {
  if (path !== attestedPath) {
    throw new Error(
      `${helperName} ${name} does not match the installed database guard`,
    );
  }
}

function assertEnvironmentUnchanged(
  helperName: string,
  name: string,
  expected: string,
): void {
  if (process.env[name] !== expected) {
    throw new Error(
      `${helperName} ${name} changed before the database import`,
    );
  }
}

function assertFreshDatabaseIdentityAttestation(
  helperName: string,
  identity: DatabaseGuardAttestation['databaseIdentity'],
): void {
  if (identity !== null) {
    throw new Error(
      `${helperName} fresh DB_PATH must not carry a device/inode attestation`,
    );
  }
}

function requireExistingDatabaseIdentityAttestation(
  helperName: string,
  identity: DatabaseGuardAttestation['databaseIdentity'],
): NonNullable<DatabaseGuardAttestation['databaseIdentity']> {
  if (
    identity === null ||
    typeof identity !== 'object' ||
    !/^\d+$/.test(identity.dev) ||
    !/^\d+$/.test(identity.ino)
  ) {
    throw new Error(
      `${helperName} existing DB_PATH requires an exact device/inode attestation`,
    );
  }
  return identity;
}

function assertPrivateArtifactPath(
  path: string,
  label: string,
  tempRoot: string,
): void {
  if (path === tempRoot || !isWithin(tempRoot, path)) {
    throw new Error(`${label} must stay below RADAR_TEST_TEMP_ROOT`);
  }
  assertPrivateDirectoryChain(dirname(path), tempRoot, label);
}

function assertPrivateDirectoryChain(
  path: string,
  tempRoot: string,
  label: string,
): void {
  let cursor = path;
  while (true) {
    assertPrivateDirectory(cursor, `${label} parent`);
    if (cursor === tempRoot) return;
    if (!isWithin(tempRoot, cursor)) {
      throw new Error(`${label} parent escapes RADAR_TEST_TEMP_ROOT`);
    }
    const parent = dirname(cursor);
    if (parent === cursor) {
      throw new Error(`${label} parent never reaches RADAR_TEST_TEMP_ROOT`);
    }
    cursor = parent;
  }
}

function assertPrivateDirectory(path: string, label: string): void {
  const stats = requiredStats(path, label);
  const owner = typeof process.getuid === 'function'
    ? process.getuid()
    : null;
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (owner !== null && stats.uid !== owner) ||
    (stats.mode & 0o077) !== 0 ||
    realpathSync.native(path) !== path
  ) {
    throw new Error(`${label} must be a private owner-controlled directory`);
  }
}

function assertPrivateRegularFile(
  path: string,
  label: string,
  options: { empty?: boolean } = {},
): void {
  const stats = requiredStats(path, label);
  const owner = typeof process.getuid === 'function'
    ? process.getuid()
    : null;
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (owner !== null && stats.uid !== owner) ||
    (stats.mode & 0o022) !== 0 ||
    realpathSync.native(path) !== path
  ) {
    throw new Error(`${label} must be a private owner-controlled regular file`);
  }
  if (options.empty && stats.size !== 0) {
    throw new Error(`${label} must be empty`);
  }
}

function assertFreshDatabaseFamily(
  databasePath: string,
  helperName: string,
): void {
  for (const path of databaseFamily(databasePath)) {
    if (pathEntryExists(path)) {
      throw new Error(
        `${helperName} fresh database artifact already exists: ${path}`,
      );
    }
  }
}

function assertExistingDatabaseFamily(
  databasePath: string,
  expectedIdentity: NonNullable<
    DatabaseGuardAttestation['databaseIdentity']
  >,
  helperName: string,
): void {
  assertDatabaseIdentity(databasePath, expectedIdentity, helperName);
  assertPrivateRegularFile(databasePath, 'DB_PATH');
  assertSqliteDatabaseHeader(databasePath, 'DB_PATH');
  assertDatabaseIdentity(databasePath, expectedIdentity, helperName);
  for (const path of databaseFamily(databasePath).slice(1)) {
    if (pathEntryExists(path)) {
      assertPrivateRegularFile(
        path,
        `DB_PATH family member ${basename(path)}`,
      );
    }
  }
}

function assertDatabaseIdentity(
  databasePath: string,
  expectedIdentity: NonNullable<
    DatabaseGuardAttestation['databaseIdentity']
  >,
  helperName: string,
): void {
  try {
    const stats = lstatSync(databasePath, { bigint: true });
    if (
      !stats.isFile() ||
      stats.isSymbolicLink() ||
      String(stats.dev) !== expectedIdentity.dev ||
      String(stats.ino) !== expectedIdentity.ino
    ) {
      throw new Error('identity mismatch');
    }
  } catch {
    throw new Error(
      `${helperName} DB_PATH device/inode changed before repository import`,
    );
  }
}

function assertSqliteDatabaseHeader(path: string, label: string): void {
  const expected = Buffer.from('SQLite format 3\0', 'binary');
  const observed = Buffer.alloc(expected.length);
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  let bytesRead = 0;
  try {
    bytesRead = readSync(descriptor, observed, 0, observed.length, 0);
  } finally {
    closeSync(descriptor);
  }
  if (bytesRead !== expected.length || !observed.equals(expected)) {
    throw new Error(`${label} must contain an initialized SQLite database`);
  }
}

function databaseFamily(databasePath: string): string[] {
  return [
    databasePath,
    `${databasePath}-wal`,
    `${databasePath}-shm`,
    `${databasePath}-journal`,
  ];
}

function pathEntryExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function isWithin(root: string, path: string): boolean {
  const relation = relative(root, path);
  return relation !== '' &&
    relation !== '..' &&
    !relation.startsWith(`..${sep}`) &&
    !isAbsolute(relation);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function requiredStats(path: string, label: string): Stats {
  try {
    return lstatSync(path);
  } catch (error) {
    throw new Error(`${label} is unavailable: ${errorMessage(error)}`);
  }
}
