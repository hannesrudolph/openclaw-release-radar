import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

interface FilesystemIdentity {
  dev: number;
  ino: number;
}

interface HeldLock {
  owner: ExclusiveProcessLockOwner;
  guardIdentity: FilesystemIdentity;
}

const heldLocks = new Map<string, HeldLock>();

export interface ExclusiveProcessLockOwner {
  pid: number;
  token: string;
  label: string;
  startedAt: string;
  cwd: string;
  entrypoint: string | null;
  databasePath: string | null;
}

export interface ExclusiveProcessLock {
  path: string;
  owner: ExclusiveProcessLockOwner;
  release: () => void;
}

interface AcquireExclusiveProcessLockOptions {
  lockPath: string;
  label: string;
  resourceLabel?: string;
  databasePath?: string | null;
  pid?: number;
  startedAt?: string;
  registerExitHandler?: boolean;
  busyTimeoutMs?: number;
}

export function repositoryDatabaseWriterLockPath(repositoryRoot: string): string {
  const identity = createHash('sha256')
    .update(canonicalExistingPath(repositoryRoot))
    .digest('hex')
    .slice(0, 20);
  return join(processLockRootPath(), `db-writer-${identity}.lock.sqlite`);
}

export function databaseInitializationLockPath(databasePath: string): string {
  const identity = createHash('sha256')
    .update(stableFilesystemPathIdentity(databasePath))
    .digest('hex')
    .slice(0, 20);
  return join(processLockRootPath(), `db-path-init-${identity}.lock.sqlite`);
}

export function databaseFileInitializationLockPath(databasePath: string): string {
  const identity = createHash('sha256')
    .update(existingFilesystemIdentity(databasePath))
    .digest('hex')
    .slice(0, 20);
  return join(processLockRootPath(), `db-file-init-${identity}.lock.sqlite`);
}

export function processLockRootPath(): string {
  const inheritedTestRoot = process.env.RADAR_TEST_PROCESS_LOCK_ROOT;
  if (inheritedTestRoot !== undefined) {
    if (
      inheritedTestRoot.length === 0 ||
      inheritedTestRoot.trim() !== inheritedTestRoot
    ) {
      throw new Error(
        'RADAR_TEST_PROCESS_LOCK_ROOT must be a non-empty path without ' +
        'leading or trailing whitespace',
      );
    }
    const runId = process.env.RADAR_TEST_RUN_ID;
    const tempRoot = process.env.RADAR_TEST_TEMP_ROOT;
    const testMarker = Boolean(
      process.env.NODE_TEST_CONTEXT ||
      process.env.RADAR_TEST_WORKER_DB_PATH ||
      process.env.NODE_ENV === 'test',
    );
    if (
      !testMarker ||
      !runId ||
      runId.trim() !== runId ||
      !tempRoot ||
      tempRoot.trim() !== tempRoot
    ) {
      throw new Error(
        'RADAR_TEST_PROCESS_LOCK_ROOT is allowed only inside a validated ' +
        'test run with RADAR_TEST_RUN_ID and RADAR_TEST_TEMP_ROOT',
      );
    }
    assertPrivateOwnedDirectory(resolve(tempRoot), 'Test temporary root');
    return resolve(inheritedTestRoot);
  }
  const userIdentity = typeof process.getuid === 'function'
    ? String(process.getuid())
    : createHash('sha256')
      .update(process.env.USER ?? process.env.USERNAME ?? 'unknown')
      .digest('hex')
      .slice(0, 12);
  return join(tmpdir(), `openclaw-release-radar-locks-${userIdentity}`);
}

export function pathsReferToSameFile(left: string, right: string): boolean {
  const leftPath = resolve(left);
  const rightPath = resolve(right);
  if (leftPath === rightPath) return true;
  try {
    if (realpathSync(leftPath) === realpathSync(rightPath)) return true;
  } catch {
    // One side may not exist yet.
  }
  try {
    const leftStat = statSync(leftPath);
    const rightStat = statSync(rightPath);
    return leftStat.dev === rightStat.dev && leftStat.ino === rightStat.ino;
  } catch {
    return false;
  }
}

export function acquireRepositoryDatabaseWriterLock(options: {
  repositoryRoot: string;
  label: string;
  databasePath?: string | null;
  pid?: number;
  startedAt?: string;
  registerExitHandler?: boolean;
}): ExclusiveProcessLock {
  return acquireExclusiveProcessLock({
    ...options,
    resourceLabel: 'repository database writer',
    lockPath: repositoryDatabaseWriterLockPath(options.repositoryRoot),
  });
}

/**
 * Returns authority only for a lock held by this module instance. The owner
 * metadata file is diagnostic and is never accepted as proof of ownership.
 */
export function locallyHeldRepositoryDatabaseWriterLockOwner(options: {
  repositoryRoot: string;
}): ExclusiveProcessLockOwner | null {
  const lockPath = resolve(
    repositoryDatabaseWriterLockPath(options.repositoryRoot),
  );
  const held = heldLocks.get(lockPath);
  if (!held) return null;
  assertGuardFileIdentity(
    lockPath,
    held.guardIdentity,
    'local repository writer lock inspection',
  );
  return { ...held.owner };
}

export function assertRepositoryDatabaseWriterLockContended(options: {
  repositoryRoot: string;
}): void {
  assertExclusiveProcessLockContended({
    lockPath: repositoryDatabaseWriterLockPath(options.repositoryRoot),
    resourceLabel: 'repository database writer',
  });
}

export function assertRepositoryDatabaseWriterLockOwnedBy(options: {
  repositoryRoot: string;
  pid: number;
  token: string;
}): ExclusiveProcessLockOwner {
  return assertExclusiveProcessLockContended({
    lockPath: repositoryDatabaseWriterLockPath(options.repositoryRoot),
    resourceLabel: 'repository database writer',
    expectedOwner: {
      pid: options.pid,
      token: options.token,
    },
  });
}

export function assertExclusiveProcessLockContended(options: {
  lockPath: string;
  resourceLabel?: string;
  expectedOwner?: Pick<ExclusiveProcessLockOwner, 'pid' | 'token'>;
}): ExclusiveProcessLockOwner {
  const resolvedLockPath = resolve(options.lockPath);
  const locallyHeld = heldLocks.get(resolvedLockPath);
  if (locallyHeld) {
    assertGuardFileIdentity(
      resolvedLockPath,
      locallyHeld.guardIdentity,
      'local lock verification',
    );
    assertExpectedOwner(
      locallyHeld.owner,
      options.expectedOwner,
      options.resourceLabel ?? 'exclusive process lock',
    );
    return locallyHeld.owner;
  }
  ensurePrivateLockDirectory(dirname(resolvedLockPath));
  const expectedGuardIdentity = ensurePermanentGuardFile(resolvedLockPath);
  const ownerBefore = readLockOwner(resolvedLockPath + '.owner.json');
  assertExpectedOwner(
    ownerBefore,
    options.expectedOwner,
    options.resourceLabel ?? 'exclusive process lock',
  );
  const guard = new DatabaseSync(resolvedLockPath);
  try {
    assertGuardFileIdentity(
      resolvedLockPath,
      expectedGuardIdentity,
      'contention probe open',
    );
    guard.exec('PRAGMA busy_timeout = 0');
    try {
      guard.exec('BEGIN IMMEDIATE');
    } catch (error) {
      if (!isSqliteLockContention(error)) throw error;
      assertGuardFileIdentity(
        resolvedLockPath,
        expectedGuardIdentity,
        'contention probe transaction',
      );
      const ownerAfter = readLockOwner(resolvedLockPath + '.owner.json');
      assertExpectedOwner(
        ownerAfter,
        options.expectedOwner,
        options.resourceLabel ?? 'exclusive process lock',
      );
      if (
        options.expectedOwner &&
        (
          ownerBefore?.pid !== ownerAfter?.pid ||
          ownerBefore?.token !== ownerAfter?.token
        )
      ) {
        throw new Error(
          `The ${options.resourceLabel ?? 'exclusive process lock'} owner ` +
          `changed during verification: ${resolvedLockPath}.`,
        );
      }
      if (options.expectedOwner) assertProcessIsAlive(options.expectedOwner.pid);
      return ownerAfter ?? ownerBefore ?? {
        pid: 0,
        token: '',
        label: 'unverified lock owner',
        startedAt: '',
        cwd: '',
        entrypoint: null,
        databasePath: null,
      };
    }
    guard.exec('ROLLBACK');
    throw new Error(
      `The inherited ${options.resourceLabel ?? 'exclusive process lock'} ` +
      `lease is not currently held: ${resolvedLockPath}.`,
    );
  } finally {
    try {
      guard.close();
    } catch {
      // The handle may already have been closed by an exceptional SQLite path.
    }
  }
}

/**
 * Holds a SQLite write transaction on a permanent guard file.
 *
 * The guard database is the sole authority. Metadata is diagnostic only and is
 * never used to decide whether a lock can be stolen. SQLite delegates exclusion
 * to the operating system, and process death releases the lock automatically.
 */
export function acquireExclusiveProcessLock({
  lockPath,
  label,
  resourceLabel = 'exclusive process lock',
  databasePath = null,
  pid = process.pid,
  startedAt = new Date().toISOString(),
  registerExitHandler = true,
  busyTimeoutMs = 0,
}: AcquireExclusiveProcessLockOptions): ExclusiveProcessLock {
  if (
    !Number.isInteger(busyTimeoutMs) ||
    busyTimeoutMs < 0 ||
    busyTimeoutMs > 60_000
  ) {
    throw new Error(
      `Exclusive process lock busyTimeoutMs must be an integer from 0 to 60000, ` +
      `got ${String(busyTimeoutMs)}.`,
    );
  }
  const resolvedLockPath = resolve(lockPath);
  const ownerPath = `${resolvedLockPath}.owner.json`;
  if (heldLocks.has(resolvedLockPath)) {
    throw new Error(
      `This process already holds the ${resourceLabel}: ${resolvedLockPath}.`,
    );
  }
  ensurePrivateLockDirectory(dirname(resolvedLockPath));
  const guardIdentity = ensurePermanentGuardFile(resolvedLockPath);

  const owner: ExclusiveProcessLockOwner = {
    pid,
    token: randomUUID(),
    label,
    startedAt,
    cwd: process.cwd(),
    entrypoint: process.argv[1] ?? null,
    databasePath: databasePath ? resolve(databasePath) : null,
  };
  const guard = new DatabaseSync(resolvedLockPath);
  let transactionHeld = false;
  try {
    assertGuardFileIdentity(
      resolvedLockPath,
      guardIdentity,
      'lock database open',
    );
    guard.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
    guard.exec('BEGIN IMMEDIATE');
    transactionHeld = true;
    assertGuardFileIdentity(
      resolvedLockPath,
      guardIdentity,
      'lock transaction acquisition',
    );
    unlinkIfExists(ownerPath);
    writeOwnerMetadata(ownerPath, owner);
    assertGuardFileIdentity(
      resolvedLockPath,
      guardIdentity,
      'lock owner publication',
    );
    heldLocks.set(resolvedLockPath, { owner, guardIdentity });
  } catch (error) {
    const cleanupErrors: unknown[] = [];
    try {
      closeGuard(guard, transactionHeld);
    } catch (closeError) {
      cleanupErrors.push(closeError);
    }
    try {
      removeOwnerMetadataIfTokenMatches(ownerPath, owner.token);
    } catch (metadataError) {
      cleanupErrors.push(metadataError);
    }
    if (isSqliteLockContention(error)) {
      const contention = lockContentionError({
        resourceLabel,
        lockPath: resolvedLockPath,
        owner: readLockOwner(ownerPath),
        cause: error,
      });
      throw cleanupErrors.length > 0
        ? new AggregateError(
            [contention, ...cleanupErrors],
            `Lock contention cleanup failed for ${resolvedLockPath}`,
          )
        : contention;
    }
    throw cleanupErrors.length > 0
      ? new AggregateError(
          [error, ...cleanupErrors],
          `Lock acquisition cleanup failed for ${resolvedLockPath}`,
        )
      : error;
  }

  let released = false;
  let releasing = false;
  let guardClosed = false;
  const releaseInternal = (bestEffort: boolean) => {
    if (released || releasing) return;
    releasing = true;
    const errors: Error[] = [];
    if (transactionHeld) {
      try {
        guard.exec('ROLLBACK');
        transactionHeld = false;
        if (heldLocks.get(resolvedLockPath)?.owner.token === owner.token) {
          heldLocks.delete(resolvedLockPath);
        }
      } catch (error) {
        errors.push(normalizeLockCleanupError(
          error,
          'rollback guard transaction',
        ));
      }
    }
    if (!guardClosed) {
      if (!guard.isOpen) {
        guardClosed = true;
        transactionHeld = false;
        if (heldLocks.get(resolvedLockPath)?.owner.token === owner.token) {
          heldLocks.delete(resolvedLockPath);
        }
      } else {
        try {
          guard.close();
          guardClosed = true;
          transactionHeld = false;
          if (heldLocks.get(resolvedLockPath)?.owner.token === owner.token) {
            heldLocks.delete(resolvedLockPath);
          }
        } catch (error) {
          if (!guard.isOpen) {
            guardClosed = true;
            transactionHeld = false;
            if (heldLocks.get(resolvedLockPath)?.owner.token === owner.token) {
              heldLocks.delete(resolvedLockPath);
            }
          } else {
            errors.push(normalizeLockCleanupError(error, 'close guard database'));
          }
        }
      }
    }
    if (!transactionHeld && guardClosed) {
      try {
        removeOwnerMetadataIfTokenMatches(ownerPath, owner.token);
      } catch (error) {
        errors.push(normalizeLockCleanupError(error, 'remove owner metadata'));
      }
    }
    if (errors.length === 0 && !transactionHeld && guardClosed) {
      released = true;
      if (registerExitHandler) process.off('exit', releaseOnExit);
    }
    releasing = false;
    if (!bestEffort && errors.length > 0) {
      throw new AggregateError(
        errors,
        `Failed to release ${resourceLabel} ${resolvedLockPath}`,
      );
    }
  };
  const release = () => releaseInternal(false);
  const releaseOnExit = () => releaseInternal(true);
  if (registerExitHandler) process.once('exit', releaseOnExit);

  return {
    path: resolvedLockPath,
    owner,
    release,
  };
}

function ensurePermanentGuardFile(path: string): FilesystemIdentity {
  try {
    const descriptor = openSync(path, 'wx', 0o600);
    try {
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    fsyncDirectory(dirname(path));
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'EEXIST') throw error;
  }
  return assertSecureGuardFile(path);
}

function ensurePrivateLockDirectory(directory: string): void {
  try {
    mkdirSync(directory, { mode: 0o700 });
    fsyncDirectory(dirname(directory));
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'EEXIST') throw error;
  }
  assertPrivateOwnedDirectory(directory, 'Process lock directory');
}

function assertPrivateOwnedDirectory(directory: string, label: string): void {
  const stats = lstatSync(directory);
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (typeof process.getuid === 'function' && stats.uid !== process.getuid()) ||
    (stats.mode & 0o077) !== 0
  ) {
    throw new Error(
      `${label} must be a private, owner-only directory: ${directory}`,
    );
  }
}

function assertSecureGuardFile(path: string): FilesystemIdentity {
  const stats = lstatSync(path);
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (typeof process.getuid === 'function' && stats.uid !== process.getuid()) ||
    (stats.mode & 0o077) !== 0
  ) {
    throw new Error(
      `Process guard must be an owner-only regular file with one link: ${path}`,
    );
  }
  return { dev: stats.dev, ino: stats.ino };
}

function writeOwnerMetadata(
  ownerPath: string,
  owner: ExclusiveProcessLockOwner,
): void {
  const temporaryPath =
    `${ownerPath}.${owner.pid}.${owner.token}.tmp`;
  const descriptor = openSync(temporaryPath, 'wx', 0o600);
  try {
    writeFileSync(descriptor, `${JSON.stringify(owner)}\n`);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    renameSync(temporaryPath, ownerPath);
    fsyncDirectory(dirname(ownerPath));
  } finally {
    unlinkIfExists(temporaryPath);
  }
}

function readLockOwner(ownerPath: string): ExclusiveProcessLockOwner | null {
  try {
    const stats = lstatSync(ownerPath);
    if (
      !stats.isFile() ||
      stats.isSymbolicLink() ||
      stats.nlink !== 1 ||
      (typeof process.getuid === 'function' && stats.uid !== process.getuid()) ||
      (stats.mode & 0o077) !== 0
    ) {
      return null;
    }
    const contents = readFileSync(ownerPath, 'utf8');
    const after = lstatSync(ownerPath);
    if (
      after.dev !== stats.dev ||
      after.ino !== stats.ino ||
      after.size !== stats.size
    ) {
      return null;
    }
    const owner = JSON.parse(contents) as Partial<ExclusiveProcessLockOwner>;
    if (
      !Number.isInteger(owner.pid) ||
      Number(owner.pid) <= 0 ||
      typeof owner.token !== 'string' ||
      owner.token.length === 0 ||
      typeof owner.label !== 'string' ||
      owner.label.length === 0 ||
      typeof owner.startedAt !== 'string'
    ) {
      return null;
    }
    return owner as ExclusiveProcessLockOwner;
  } catch {
    return null;
  }
}

function assertExpectedOwner(
  owner: ExclusiveProcessLockOwner | null,
  expected: Pick<ExclusiveProcessLockOwner, 'pid' | 'token'> | undefined,
  resourceLabel: string,
): void {
  if (!expected) return;
  if (
    !Number.isInteger(expected.pid) ||
    expected.pid <= 0 ||
    !expected.token
  ) {
    throw new Error(`Expected ${resourceLabel} owner identity is invalid`);
  }
  if (owner?.pid !== expected.pid || owner.token !== expected.token) {
    throw new Error(
      `The active ${resourceLabel} does not match the expected runner ` +
      `pid/token identity`,
    );
  }
}

function assertProcessIsAlive(pid: number): void {
  try {
    process.kill(pid, 0);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'EPERM') return;
    throw new Error(`Expected lock owner pid ${pid} is not alive`, {
      cause: error,
    });
  }
}

function assertGuardFileIdentity(
  path: string,
  expected: FilesystemIdentity,
  stage: string,
): void {
  const observed = assertSecureGuardFile(path);
  if (observed.dev !== expected.dev || observed.ino !== expected.ino) {
    throw new Error(
      `Process guard pathname identity changed during ${stage}: ${path}`,
    );
  }
}

function removeOwnerMetadataIfTokenMatches(
  ownerPath: string,
  token: string,
): void {
  const current = readLockOwner(ownerPath);
  if (current?.token !== token) return;
  unlinkIfExists(ownerPath);
  fsyncDirectory(dirname(ownerPath));
}

function closeGuard(guard: DatabaseSync, transactionHeld: boolean): void {
  const errors: Error[] = [];
  try {
    if (transactionHeld) guard.exec('ROLLBACK');
  } catch (error) {
    errors.push(normalizeLockCleanupError(error, 'rollback guard transaction'));
  }
  try {
    guard.close();
  } catch (error) {
    errors.push(normalizeLockCleanupError(error, 'close guard connection'));
  }
  if (errors.length > 0) {
    throw new AggregateError(errors, 'Guard database cleanup failed');
  }
}

function normalizeLockCleanupError(error: unknown, operation: string): Error {
  return new Error(
    `${operation}: ${error instanceof Error ? error.message : String(error)}`,
    { cause: error },
  );
}

function lockContentionError(options: {
  resourceLabel: string;
  lockPath: string;
  owner: ExclusiveProcessLockOwner | null;
  cause: unknown;
}): Error {
  const ownerDescription = options.owner
    ? ` in pid ${options.owner.pid} since ${options.owner.startedAt} ` +
      `(${options.owner.label})`
    : '';
  return new Error(
    `Another ${options.resourceLabel} is already running${ownerDescription}; ` +
    `guard: ${options.lockPath}.`,
    { cause: options.cause },
  );
}

function isSqliteLockContention(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const sqliteError = error as Error & {
    errcode?: number;
    errstr?: string;
  };
  return sqliteError.errcode === 5 ||
    sqliteError.errcode === 6 ||
    /database is (?:locked|busy)|SQLITE_(?:BUSY|LOCKED)/i.test(
      `${error.message} ${sqliteError.errstr ?? ''}`,
    );
}

function fsyncDirectory(directory: string): void {
  let descriptor: number | null = null;
  try {
    descriptor = openSync(directory, 'r');
    fsyncSync(descriptor);
  } catch {
    // Directory fsync is not supported on every deployment filesystem.
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

function canonicalExistingPath(path: string): string {
  const resolvedPath = resolve(path);
  try {
    return realpathSync(resolvedPath);
  } catch {
    return resolvedPath;
  }
}

function stableFilesystemPathIdentity(path: string): string {
  const resolvedPath = resolve(path);
  const parent = dirname(resolvedPath);
  return `path:${join(canonicalExistingPath(parent), basename(resolvedPath))}`;
}

function existingFilesystemIdentity(path: string): string {
  const stats = statSync(resolve(path));
  return `inode:${stats.dev}:${stats.ino}`;
}

function unlinkIfExists(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }
}
