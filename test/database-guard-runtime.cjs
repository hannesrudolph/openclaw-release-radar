const fs = require('node:fs');
const fsPromises = require('node:fs/promises');
const { createHash } = require('node:crypto');
const {
  closeSync,
  constants: fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeSync,
} = fs;
const { delimiter } = require('node:path');
const { EventEmitter } = require('node:events');
const { syncBuiltinESMExports } = require('node:module');
const {
  basename,
  dirname,
  isAbsolute,
  join,
  parse: parsePath,
  resolve,
  sep,
} = require('node:path');
const { fileURLToPath, pathToFileURL } = require('node:url');

const installKey = Symbol.for('openclaw-release-radar.database-guard');
const guardedProcessIdentityTelemetryKey = Symbol.for(
  'openclaw-release-radar.guarded-process-identity-telemetry',
);
if (Object.getOwnPropertyDescriptor(globalThis, installKey) !== undefined) {
  throw new Error(
    'Database guard installation state existed before the guard runtime loaded',
  );
}
const databaseGuardInstallation = installDatabaseGuard();
Object.defineProperty(globalThis, installKey, {
  configurable: false,
  enumerable: false,
  writable: false,
  value: databaseGuardInstallation,
});
module.exports = databaseGuardInstallation;

function installDatabaseGuard() {
  const runId = requiredEnv('RADAR_TEST_RUN_ID');
  const auditPath = requiredEnv('RADAR_TEST_DB_AUDIT');
  const guardPolicy = loadDatabaseGuardPolicy(runId);
  assertKernelWriteBoundaryActive(guardPolicy);
  const liveDatabaseFamily = guardPolicy.liveDatabaseFamily.map((member) => ({
    ...member,
    identity: databaseIdentity(member.path),
  }));
  if (liveDatabaseFamily.some((member) => member.identity === null)) {
    throw new Error('Database guard policy contains a non-file database member');
  }
  for (const member of liveDatabaseFamily) {
    assertLiveDatabaseMemberCurrent(member);
  }
  const writableRoots = guardPolicy.writableRoots
    .map((path) => canonicalizePath(String(path)));
  const executableRoots = guardPolicy.executableRoots
    .map((path) => canonicalizePath(String(path)));
  const allowedExecutableIdentities = guardPolicy.allowedExecutables;
  const inheritedDatabase = requiredEnv('DB_PATH');
  const inheritedIdentity = databaseIdentity(inheritedDatabase);
  if (inheritedIdentity === null) {
    throw new Error('DB_PATH must reference a file-backed database during tests');
  }
  const assignedWorkerDatabase = databaseIdentity(
    process.env.RADAR_TEST_WORKER_DB_PATH ?? inheritedDatabase,
  );
  if (assignedWorkerDatabase === null) {
    throw new Error('RADAR_TEST_WORKER_DB_PATH must reference a file-backed database');
  }
  const workerDatabaseRoot = dirname(assignedWorkerDatabase.path);
  const enforceWorkerRoot =
    process.env.RADAR_TEST_ENFORCE_WORKER_DB_ROOT === '1';
  const allowedRoots = JSON.parse(requiredEnv('RADAR_TEST_ALLOWED_DB_ROOTS'))
    .map((path) => canonicalizePath(String(path)));
  const processLockRoot = canonicalizePath(
    requiredEnv('RADAR_TEST_PROCESS_LOCK_ROOT'),
  );
  const sqliteMaximumBytes =
    positiveIntegerEnv('RADAR_TEST_SQLITE_MAX_MIB', 256) * 1024 * 1024;
  const protectedEnvironment = new Map(
    Object.entries(process.env)
      .filter(([name, value]) =>
        value !== undefined &&
        (name === 'NODE_OPTIONS' ||
          name === 'DOTENV_CONFIG_PATH' ||
          name === 'PATH' ||
          name === 'TMPDIR' ||
          name === 'TMP' ||
          name === 'TEMP' ||
          name === 'SQLITE_TMPDIR' ||
          name === 'RADAR_CODE_REVISION' ||
          name.startsWith('RADAR_TEST_'))),
  );

  if (!protectedEnvironment.has('NODE_OPTIONS')) {
    throw new Error('Missing required test environment variable: NODE_OPTIONS');
  }
  if (isProtectedDatabaseIdentity(inheritedIdentity)) {
    throw new Error(`Test process inherited the live database path: ${inheritedDatabase}`);
  }
  assertEnvironmentHasNoLiveDatabasePath(process.env, 'test process');
  const directHelperName = directDatabaseHelperName();
  if (directHelperName !== null && guardPolicy.legacy === true) {
    throw new Error(
      `${directHelperName} requires the authoritative kernel write boundary`,
    );
  }
  const helperArtifacts = directHelperName === null
    ? null
    : assertPrivateHelperArtifacts();
  if (
    enforceWorkerRoot &&
    !isWithin(workerDatabaseRoot, inheritedIdentity.path)
  ) {
    throw new Error(
      `Test process inherited a database outside its assigned worker root: ` +
      `${inheritedIdentity.path}`,
    );
  }

  audit({
    type: 'process-start',
    pid: process.pid,
    ppid: process.ppid,
    context: process.env.NODE_TEST_CONTEXT ?? null,
    dbPath: inheritedDatabase,
    workerDbPath: process.env.RADAR_TEST_WORKER_DB_PATH ?? null,
    codeRevision: process.env.RADAR_CODE_REVISION ?? null,
    script: process.argv[1] ?? null,
  });

  const childProcess = require('node:child_process');
  const sqlite = require('node:sqlite');
  const workerThreads = require('node:worker_threads');
  const NativeDatabaseSync = sqlite.DatabaseSync;
  const nativeBackup = sqlite.backup;
  const NativeChildProcess = childProcess.ChildProcess;
  const nativeChildProcessSpawn = NativeChildProcess.prototype.spawn;
  const nativeChildFunctions = Object.freeze({
    exec: childProcess.exec,
    execFile: childProcess.execFile,
    execFileSync: childProcess.execFileSync,
    execSync: childProcess.execSync,
    fork: childProcess.fork,
    spawn: childProcess.spawn,
    spawnSync: childProcess.spawnSync,
  });
  const nativeFsFunctions = Object.freeze({
    appendFile: fs.appendFile,
    appendFileSync: fs.appendFileSync,
    chmod: fs.chmod,
    chmodSync: fs.chmodSync,
    chown: fs.chown,
    chownSync: fs.chownSync,
    copyFile: fs.copyFile,
    copyFileSync: fs.copyFileSync,
    cp: fs.cp,
    cpSync: fs.cpSync,
    createWriteStream: fs.createWriteStream,
    fchmod: fs.fchmod,
    fchmodSync: fs.fchmodSync,
    fchown: fs.fchown,
    fchownSync: fs.fchownSync,
    ftruncate: fs.ftruncate,
    ftruncateSync: fs.ftruncateSync,
    futimes: fs.futimes,
    futimesSync: fs.futimesSync,
    link: fs.link,
    linkSync: fs.linkSync,
    lchmod: fs.lchmod,
    lchmodSync: fs.lchmodSync,
    lchown: fs.lchown,
    lchownSync: fs.lchownSync,
    lutimes: fs.lutimes,
    lutimesSync: fs.lutimesSync,
    mkdir: fs.mkdir,
    mkdirSync: fs.mkdirSync,
    mkdtemp: fs.mkdtemp,
    mkdtempSync: fs.mkdtempSync,
    mkdtempDisposableSync: fs.mkdtempDisposableSync,
    open: fs.open,
    openSync: fs.openSync,
    rename: fs.rename,
    renameSync: fs.renameSync,
    rm: fs.rm,
    rmSync: fs.rmSync,
    rmdir: fs.rmdir,
    rmdirSync: fs.rmdirSync,
    symlink: fs.symlink,
    symlinkSync: fs.symlinkSync,
    truncate: fs.truncate,
    truncateSync: fs.truncateSync,
    unlink: fs.unlink,
    unlinkSync: fs.unlinkSync,
    utimes: fs.utimes,
    utimesSync: fs.utimesSync,
    write: fs.write,
    writeFile: fs.writeFile,
    writeFileSync: fs.writeFileSync,
    writeSync: fs.writeSync,
    writev: fs.writev,
    writevSync: fs.writevSync,
  });
  const nativeFsPromiseFunctions = Object.freeze({
    appendFile: fsPromises.appendFile,
    chmod: fsPromises.chmod,
    chown: fsPromises.chown,
    copyFile: fsPromises.copyFile,
    cp: fsPromises.cp,
    link: fsPromises.link,
    lchmod: fsPromises.lchmod,
    lchown: fsPromises.lchown,
    lutimes: fsPromises.lutimes,
    mkdir: fsPromises.mkdir,
    mkdtemp: fsPromises.mkdtemp,
    mkdtempDisposable: fsPromises.mkdtempDisposable,
    open: fsPromises.open,
    rename: fsPromises.rename,
    rm: fsPromises.rm,
    rmdir: fsPromises.rmdir,
    symlink: fsPromises.symlink,
    truncate: fsPromises.truncate,
    unlink: fsPromises.unlink,
    utimes: fsPromises.utimes,
    writeFile: fsPromises.writeFile,
  });
  const NativeWriteStream = fs.WriteStream;
  const writableFileDescriptors = new Map();
  const guardedFileHandlePrototypes = new WeakSet();
  const databaseTargets = new WeakMap();
  const databasePolicies = new WeakMap();
  const statementTargets = new WeakMap();
  const sessionTargets = new WeakMap();
  const NativeWorker = workerThreads.Worker;
  const workerTargets = new WeakMap();
  const guardRequireArg = `--require=${__filename}`;
  const nodeExecutable = fileIdentity(process.execPath);
  const tsxExecutable = fileIdentity(
    resolve(__dirname, '..', 'node_modules', '.bin', 'tsx'),
  );
  const processStatusExecutable = ['/bin/ps', '/usr/bin/ps']
    .map((path) => trustedSystemExecutableIdentity(path))
    .find((identity) => identity !== null) ?? null;
  const sqliteExecutable = executableIdentity('sqlite3', process.env, process.cwd());
  const databasePolicyProbe =
    process.env.RADAR_TEST_DATABASE_POLICY_PROBE === '1';
  const databasePolicyProbeAuthority =
    process.env.RADAR_TEST_DATABASE_POLICY_PROBE_AUTHORITY === '1';
  if (
    process.env.RADAR_TEST_DATABASE_POLICY_PROBE !== undefined &&
    !databasePolicyProbe
  ) {
    throw new Error(
      'RADAR_TEST_DATABASE_POLICY_PROBE must be exactly 1 when present',
    );
  }
  if (
    process.env.RADAR_TEST_DATABASE_POLICY_PROBE_AUTHORITY !== undefined &&
    !databasePolicyProbeAuthority
  ) {
    throw new Error(
      'RADAR_TEST_DATABASE_POLICY_PROBE_AUTHORITY must be exactly 1 when present',
    );
  }
  if (databasePolicyProbe && !databasePolicyProbeAuthority) {
    throw new Error(
      'Database policy probe capability was not authorized by the test worker',
    );
  }
  const databasePolicyProbeCompiler = databasePolicyProbe
    ? fileIdentity(resolve(__dirname, '..', 'node_modules', 'esbuild', 'bin', 'esbuild'))
    : null;

  function installFilesystemGuards() {
    const guardTarget = (
      method,
      native,
      targetIndex = 0,
      { inspectDescendants = false } = {},
    ) => function guardedFilesystemMutation(...args) {
      args[targetIndex] = assertWritableTarget(
        method,
        args[targetIndex],
        { inspectDescendants },
      );
      return Reflect.apply(native, this, args);
    };
    const guardDescriptor = (method, native) =>
      function guardedDescriptorMutation(descriptor, ...args) {
        assertWritableFileDescriptor(method, descriptor);
        return Reflect.apply(native, this, [descriptor, ...args]);
      };
    const guardCopy = (
      method,
      native,
      { inspectSourceDescendants = false } = {},
    ) => function guardedFilesystemCopy(source, destination, ...args) {
      const sourceSnapshot = assertReadableCopySource(
        method,
        source,
        { inspectDescendants: inspectSourceDescendants },
      );
      const destinationSnapshot = assertWritableTarget(
        method,
        destination,
        { inspectDescendants: true },
      );
      return Reflect.apply(native, this, [
        sourceSnapshot,
        destinationSnapshot,
        ...args,
      ]);
    };

    fs.appendFile = guardTarget('appendFile', nativeFsFunctions.appendFile);
    fs.appendFileSync =
      guardTarget('appendFileSync', nativeFsFunctions.appendFileSync);
    fs.chmod = guardTarget('chmod', nativeFsFunctions.chmod);
    fs.chmodSync = guardTarget('chmodSync', nativeFsFunctions.chmodSync);
    fs.chown = guardTarget('chown', nativeFsFunctions.chown);
    fs.chownSync = guardTarget('chownSync', nativeFsFunctions.chownSync);
    fs.copyFile = guardCopy('copyFile', nativeFsFunctions.copyFile);
    fs.copyFileSync =
      guardCopy('copyFileSync', nativeFsFunctions.copyFileSync);
    fs.cp = guardCopy('cp', nativeFsFunctions.cp, {
      inspectSourceDescendants: true,
    });
    fs.cpSync = guardCopy('cpSync', nativeFsFunctions.cpSync, {
      inspectSourceDescendants: true,
    });
    fs.fchmod = guardDescriptor('fchmod', nativeFsFunctions.fchmod);
    fs.fchmodSync =
      guardDescriptor('fchmodSync', nativeFsFunctions.fchmodSync);
    fs.fchown = guardDescriptor('fchown', nativeFsFunctions.fchown);
    fs.fchownSync =
      guardDescriptor('fchownSync', nativeFsFunctions.fchownSync);
    fs.ftruncate = guardDescriptor('ftruncate', nativeFsFunctions.ftruncate);
    fs.ftruncateSync =
      guardDescriptor('ftruncateSync', nativeFsFunctions.ftruncateSync);
    fs.futimes = guardDescriptor('futimes', nativeFsFunctions.futimes);
    fs.futimesSync =
      guardDescriptor('futimesSync', nativeFsFunctions.futimesSync);
    fs.mkdir = guardTarget('mkdir', nativeFsFunctions.mkdir);
    fs.mkdirSync = guardTarget('mkdirSync', nativeFsFunctions.mkdirSync);
    fs.mkdtemp = guardTarget('mkdtemp', nativeFsFunctions.mkdtemp);
    fs.mkdtempSync =
      guardTarget('mkdtempSync', nativeFsFunctions.mkdtempSync);
    fs.rename = function guardedRename(source, destination, ...args) {
      const sourceSnapshot = assertWritableTarget(
        'rename-source',
        source,
        { inspectDescendants: true },
      );
      const destinationSnapshot =
        assertWritableTarget('rename-destination', destination);
      return Reflect.apply(nativeFsFunctions.rename, this, [
        sourceSnapshot,
        destinationSnapshot,
        ...args,
      ]);
    };
    fs.renameSync = function guardedRenameSync(source, destination) {
      return nativeFsFunctions.renameSync(
        assertWritableTarget('renameSync-source', source, {
          inspectDescendants: true,
        }),
        assertWritableTarget('renameSync-destination', destination),
      );
    };
    fs.link = function guardedLink(source, destination, ...args) {
      return Reflect.apply(nativeFsFunctions.link, this, [
        assertWritableTarget('link-source', source),
        assertWritableTarget('link-destination', destination),
        ...args,
      ]);
    };
    fs.linkSync = function guardedLinkSync(source, destination) {
      return nativeFsFunctions.linkSync(
        assertWritableTarget('linkSync-source', source),
        assertWritableTarget('linkSync-destination', destination),
      );
    };
    fs.symlink = function guardedSymlink(target, path, ...args) {
      assertSymlinkTargetSafe('symlink', target, path);
      return Reflect.apply(nativeFsFunctions.symlink, this, [
        target,
        assertWritableTarget('symlink-destination', path),
        ...args,
      ]);
    };
    fs.symlinkSync = function guardedSymlinkSync(target, path, ...args) {
      assertSymlinkTargetSafe('symlinkSync', target, path);
      return Reflect.apply(nativeFsFunctions.symlinkSync, this, [
        target,
        assertWritableTarget('symlinkSync-destination', path),
        ...args,
      ]);
    };
    fs.rm = guardTarget('rm', nativeFsFunctions.rm, 0, {
      inspectDescendants: true,
    });
    fs.rmSync = guardTarget('rmSync', nativeFsFunctions.rmSync, 0, {
      inspectDescendants: true,
    });
    fs.rmdir = guardTarget('rmdir', nativeFsFunctions.rmdir, 0, {
      inspectDescendants: true,
    });
    fs.rmdirSync = guardTarget('rmdirSync', nativeFsFunctions.rmdirSync, 0, {
      inspectDescendants: true,
    });
    fs.truncate = guardTarget('truncate', nativeFsFunctions.truncate);
    fs.truncateSync =
      guardTarget('truncateSync', nativeFsFunctions.truncateSync);
    fs.unlink = guardTarget('unlink', nativeFsFunctions.unlink);
    fs.unlinkSync = guardTarget('unlinkSync', nativeFsFunctions.unlinkSync);
    fs.utimes = guardTarget('utimes', nativeFsFunctions.utimes);
    fs.utimesSync = guardTarget('utimesSync', nativeFsFunctions.utimesSync);
    fs.write = guardDescriptor('write', nativeFsFunctions.write);
    fs.writeSync = guardDescriptor('writeSync', nativeFsFunctions.writeSync);
    fs.writeFile = guardTarget('writeFile', nativeFsFunctions.writeFile);
    fs.writeFileSync =
      guardTarget('writeFileSync', nativeFsFunctions.writeFileSync);
    fs.writev = guardDescriptor('writev', nativeFsFunctions.writev);
    fs.writevSync = guardDescriptor('writevSync', nativeFsFunctions.writevSync);

    for (const name of ['lchmod', 'lchown', 'lutimes']) {
      if (typeof nativeFsFunctions[name] === 'function') {
        fs[name] = guardTarget(name, nativeFsFunctions[name]);
      }
      const syncName = `${name}Sync`;
      if (typeof nativeFsFunctions[syncName] === 'function') {
        fs[syncName] = guardTarget(syncName, nativeFsFunctions[syncName]);
      }
    }
    if (typeof nativeFsFunctions.mkdtempDisposableSync === 'function') {
      fs.mkdtempDisposableSync = guardTarget(
        'mkdtempDisposableSync',
        nativeFsFunctions.mkdtempDisposableSync,
      );
    }

    fs.open = function guardedOpen(path, flags, mode, callback) {
      const pathSnapshot = snapshotFilesystemPath(path);
      const flagSnapshot = snapshotOpenFlags(flags);
      if (openFlagsPermitWrite(flagSnapshot)) {
        assertWritablePath('open', pathSnapshot);
      }
      const completion = typeof mode === 'function' ? mode : callback;
      const wrapped = typeof completion === 'function'
        ? function guardedOpenCompletion(error, descriptor) {
          if (!error) registerWritableFileDescriptor(descriptor, pathSnapshot);
          return Reflect.apply(completion, this, [error, descriptor]);
        }
        : completion;
      return typeof mode === 'function'
        ? nativeFsFunctions.open(pathSnapshot, flagSnapshot, wrapped)
        : nativeFsFunctions.open(pathSnapshot, flagSnapshot, mode, wrapped);
    };
    fs.openSync = function guardedOpenSync(path, flags, mode) {
      const pathSnapshot = snapshotFilesystemPath(path);
      const flagSnapshot = snapshotOpenFlags(flags);
      if (openFlagsPermitWrite(flagSnapshot)) {
        assertWritablePath('openSync', pathSnapshot);
      }
      const descriptor = nativeFsFunctions.openSync(
        pathSnapshot,
        flagSnapshot,
        mode,
      );
      registerWritableFileDescriptor(descriptor, pathSnapshot);
      return descriptor;
    };

    fs.createWriteStream = function guardedCreateWriteStream(path, options) {
      assertWriteStreamTarget('createWriteStream', path, options);
      return nativeFsFunctions.createWriteStream(
        snapshotFilesystemPathOrNull(path),
        options,
      );
    };
    class GuardedWriteStream extends NativeWriteStream {
      constructor(path, options) {
        assertWriteStreamTarget('WriteStream', path, options);
        super(snapshotFilesystemPathOrNull(path), options);
      }
    }
    Object.defineProperty(GuardedWriteStream, 'name', { value: 'WriteStream' });
    fs.WriteStream = GuardedWriteStream;
    if (fs.FileWriteStream === NativeWriteStream) {
      fs.FileWriteStream = GuardedWriteStream;
    }

    fsPromises.appendFile =
      guardTarget('promises.appendFile', nativeFsPromiseFunctions.appendFile);
    fsPromises.chmod =
      guardTarget('promises.chmod', nativeFsPromiseFunctions.chmod);
    fsPromises.chown =
      guardTarget('promises.chown', nativeFsPromiseFunctions.chown);
    fsPromises.copyFile = guardCopy(
      'promises.copyFile',
      nativeFsPromiseFunctions.copyFile,
    );
    fsPromises.cp = guardCopy(
      'promises.cp',
      nativeFsPromiseFunctions.cp,
      { inspectSourceDescendants: true },
    );
    fsPromises.link = function guardedPromiseLink(source, destination) {
      return nativeFsPromiseFunctions.link(
        assertWritableTarget('promises.link-source', source),
        assertWritableTarget('promises.link-destination', destination),
      );
    };
    fsPromises.mkdir =
      guardTarget('promises.mkdir', nativeFsPromiseFunctions.mkdir);
    fsPromises.mkdtemp =
      guardTarget('promises.mkdtemp', nativeFsPromiseFunctions.mkdtemp);
    fsPromises.rename = function guardedPromiseRename(source, destination) {
      return nativeFsPromiseFunctions.rename(
        assertWritableTarget('promises.rename-source', source, {
          inspectDescendants: true,
        }),
        assertWritableTarget('promises.rename-destination', destination),
      );
    };
    fsPromises.rm = guardTarget(
      'promises.rm',
      nativeFsPromiseFunctions.rm,
      0,
      { inspectDescendants: true },
    );
    fsPromises.rmdir = guardTarget(
      'promises.rmdir',
      nativeFsPromiseFunctions.rmdir,
      0,
      { inspectDescendants: true },
    );
    fsPromises.symlink = function guardedPromiseSymlink(target, path, ...args) {
      assertSymlinkTargetSafe('promises.symlink', target, path);
      return Reflect.apply(nativeFsPromiseFunctions.symlink, this, [
        target,
        assertWritableTarget('promises.symlink-destination', path),
        ...args,
      ]);
    };
    fsPromises.truncate =
      guardTarget('promises.truncate', nativeFsPromiseFunctions.truncate);
    fsPromises.unlink =
      guardTarget('promises.unlink', nativeFsPromiseFunctions.unlink);
    fsPromises.utimes =
      guardTarget('promises.utimes', nativeFsPromiseFunctions.utimes);
    fsPromises.writeFile =
      guardTarget('promises.writeFile', nativeFsPromiseFunctions.writeFile);
    for (const name of ['lchmod', 'lchown', 'lutimes']) {
      if (typeof nativeFsPromiseFunctions[name] === 'function') {
        fsPromises[name] = guardTarget(
          `promises.${name}`,
          nativeFsPromiseFunctions[name],
        );
      }
    }
    if (typeof nativeFsPromiseFunctions.mkdtempDisposable === 'function') {
      fsPromises.mkdtempDisposable = guardTarget(
        'promises.mkdtempDisposable',
        nativeFsPromiseFunctions.mkdtempDisposable,
      );
    }
    fsPromises.open = async function guardedPromiseOpen(path, flags, mode) {
      const pathSnapshot = snapshotFilesystemPath(path);
      const flagSnapshot = snapshotOpenFlags(flags);
      if (openFlagsPermitWrite(flagSnapshot)) {
        assertWritablePath('promises.open', pathSnapshot);
      }
      const handle = await nativeFsPromiseFunctions.open(
        pathSnapshot,
        flagSnapshot,
        mode,
      );
      registerWritableFileDescriptor(handle.fd, pathSnapshot);
      installFileHandleGuards(handle);
      return handle;
    };
  }

  function installFileHandleGuards(handle) {
    const prototype = Object.getPrototypeOf(handle);
    if (guardedFileHandlePrototypes.has(prototype)) return;
    guardedFileHandlePrototypes.add(prototype);
    for (const name of [
      'appendFile',
      'chmod',
      'chown',
      'createWriteStream',
      'truncate',
      'utimes',
      'write',
      'writeFile',
      'writev',
    ]) {
      const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
      if (typeof descriptor?.value !== 'function') continue;
      const native = descriptor.value;
      Object.defineProperty(prototype, name, {
        ...descriptor,
        value: function guardedFileHandleMutation(...args) {
          assertWritableFileDescriptor(`FileHandle.${name}`, this.fd);
          return Reflect.apply(native, this, args);
        },
      });
    }
  }

  function assertWriteStreamTarget(method, path, options) {
    if (Number.isInteger(options?.fd)) {
      assertWritableFileDescriptor(method, options.fd);
      return;
    }
    assertWritableTarget(method, path);
  }

  function assertWritableTarget(method, target, options = {}) {
    if (Number.isInteger(target)) {
      assertWritableFileDescriptor(method, target);
      return target;
    }
    if (
      target !== null &&
      typeof target === 'object' &&
      !(target instanceof URL) &&
      !Buffer.isBuffer(target) &&
      Number.isInteger(target.fd)
    ) {
      assertWritableFileDescriptor(method, target.fd);
      return target;
    }
    const snapshot = snapshotFilesystemPath(target);
    assertWritablePath(method, snapshot, options);
    return snapshot;
  }

  function assertReadableCopySource(method, source, {
    inspectDescendants = false,
  } = {}) {
    const snapshot = snapshotFilesystemPath(source);
    const identity = filesystemIdentity(snapshot);
    const protectedReason = protectedFilesystemReason(identity);
    if (protectedReason) {
      refuseFilesystemRead(method, identity.path, protectedReason);
    }
    if (
      inspectDescendants &&
      pathContainsProtectedDatabaseIdentity(identity.path)
    ) {
      refuseFilesystemRead(
        method,
        identity.path,
        'source contains a live database alias or family member',
      );
    }
    return snapshot;
  }

  function assertWritablePath(method, path, {
    inspectDescendants = false,
  } = {}) {
    const identity = filesystemIdentity(path);
    const protectedReason = protectedFilesystemReason(identity);
    if (protectedReason) refuseFilesystemWrite(method, identity.path, protectedReason);
    if (
      inspectDescendants &&
      pathContainsProtectedDatabaseIdentity(identity.path)
    ) {
      refuseFilesystemWrite(
        method,
        identity.path,
        'target contains a live database alias or family member',
      );
    }
    if (!writableRoots.some((root) => isWithin(root, identity.path))) {
      refuseFilesystemWrite(
        method,
        identity.path,
        'target is outside the sealed writable roots',
      );
    }
    return identity;
  }

  function filesystemIdentity(path) {
    const canonical = canonicalizePath(String(
      path instanceof URL
        ? fileURLToPath(path)
        : Buffer.isBuffer(path)
          ? path.toString()
          : path,
    ));
    let inode = null;
    try {
      const stats = statSync(canonical, { bigint: true });
      inode = `${stats.dev}:${stats.ino}`;
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') throw error;
    }
    return { path: canonical, inode };
  }

  function childOperandFilesystemIdentity(value, cwd) {
    const path = resolveChildOperandPath(value, cwd);
    if (path === null) return null;
    const canonical = canonicalizeChildOperandPath(path);
    let inode = null;
    try {
      const stats = statSync(canonical, { bigint: true });
      inode = `${stats.dev}:${stats.ino}`;
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') throw error;
    }
    return { path: canonical, inode };
  }

  function assertChildPathOperandsSafe(
    method,
    command,
    args,
    cwd,
    commandIdentity = null,
  ) {
    let operandCwd = cwd;
    let nextArgumentChangesDirectory = false;
    const sourceArgumentIndexes =
      childInterpreterSourceArgumentIndexes(commandIdentity, args);

    for (let argumentIndex = 0; argumentIndex < args.length; argumentIndex++) {
      const rawArgument = args[argumentIndex];
      const argument = String(rawArgument);
      if (sourceArgumentIndexes.has(argumentIndex)) continue;
      for (const candidate of childPathOperandCandidates(argument)) {
        let identity;
        try {
          identity = childOperandFilesystemIdentity(candidate, operandCwd);
        } catch (error) {
          refuseChild(
            method,
            command,
            `child path operand cannot be resolved safely: ${error.message}`,
          );
        }
        if (identity === null) continue;
        const protectedReason = protectedFilesystemReason(identity);
        if (protectedReason) {
          refuseChild(
            method,
            command,
            `child path operand targets the live database family: ` +
              `${identity.path} (${protectedReason})`,
          );
        }
        if (pathContainsProtectedDatabaseIdentity(identity.path)) {
          refuseChild(
            method,
            command,
            `child path operand contains a live database alias or family member: ` +
              identity.path,
          );
        }
      }

      if (nextArgumentChangesDirectory) {
        const identity = childOperandFilesystemIdentity(argument, operandCwd);
        if (identity !== null) operandCwd = identity.path;
        nextArgumentChangesDirectory = false;
        continue;
      }
      if (argument === '-C' || argument === '--directory') {
        nextArgumentChangesDirectory = true;
        continue;
      }
      const attachedDirectory = attachedChildOperandDirectory(argument);
      if (attachedDirectory !== null) {
        const identity =
          childOperandFilesystemIdentity(attachedDirectory, operandCwd);
        if (identity !== null) operandCwd = identity.path;
      }
    }
  }

  function childInterpreterSourceArgumentIndexes(commandIdentity, args) {
    const indexes = new Set();
    const name = basename(commandIdentity?.path ?? '').toLowerCase();
    if (
      sameFile(commandIdentity, nodeExecutable) ||
      sameFile(commandIdentity, tsxExecutable)
    ) {
      for (let index = 0; index < args.length; index++) {
        const argument = String(args[index]);
        if (argument === '--') break;
        if (
          argument === '-e' ||
          argument === '--eval' ||
          argument === '-p' ||
          argument === '--print'
        ) {
          if (index + 1 < args.length) indexes.add(++index);
          continue;
        }
        if (
          argument.startsWith('--eval=') ||
          argument.startsWith('--print=') ||
          (argument.startsWith('-e') && argument.length > 2) ||
          (argument.startsWith('-p') && argument.length > 2)
        ) {
          indexes.add(index);
        }
      }
      return indexes;
    }
    if (!['bash', 'dash', 'ksh', 'sh', 'zsh'].includes(name)) return indexes;
    for (let index = 0; index < args.length; index++) {
      if (!/^-[^-]*c/.test(String(args[index]))) continue;
      if (index + 1 < args.length) indexes.add(index + 1);
      break;
    }
    return indexes;
  }

  function childPathOperandCandidates(argument) {
    const candidates = new Set([argument]);
    const assignmentIndex = argument.indexOf('=');
    if (assignmentIndex > 0 && assignmentIndex + 1 < argument.length) {
      candidates.add(argument.slice(assignmentIndex + 1));
    }

    const redirection =
      /^(?:\d*)?(?:>>|>|<<|<>|<)(.+)$/s.exec(argument);
    if (redirection !== null) candidates.add(redirection[1]);

    const fileUrlIndex = argument.indexOf('file:');
    if (fileUrlIndex > 0) candidates.add(argument.slice(fileUrlIndex));

    const slashIndexes = [
      argument.indexOf('/'),
      process.platform === 'win32' ? argument.indexOf('\\') : -1,
    ].filter((index) => index > 0);
    if (
      slashIndexes.length > 0 &&
      (argument.startsWith('-') || /^(?:\d*)?[<>]/.test(argument))
    ) {
      candidates.add(argument.slice(Math.min(...slashIndexes)));
    }

    if (
      argument.startsWith('-') &&
      !argument.startsWith('--') &&
      argument.length > 2 &&
      argument.length <= 256
    ) {
      const maximumPrefixLength = Math.min(argument.length - 1, 16);
      for (let prefixLength = 2; prefixLength <= maximumPrefixLength;
        prefixLength++) {
        candidates.add(argument.slice(prefixLength));
      }
    }

    return [...candidates].filter((candidate) =>
      candidate !== '' && candidate !== '-' && candidate !== '--');
  }

  function attachedChildOperandDirectory(argument) {
    if (argument.startsWith('--directory=')) {
      return argument.slice('--directory='.length);
    }
    if (argument.startsWith('-C') && argument !== '-C') {
      const value = argument.slice(2);
      return value.startsWith('=') ? value.slice(1) : value;
    }
    return null;
  }

  function resolveChildOperandPath(value, cwd) {
    const operand = String(value);
    if (
      operand === '' ||
      operand === '-' ||
      operand === '--' ||
      operand.includes('\0') ||
      operand.length > 4096
    ) {
      return null;
    }
    try {
      if (operand.startsWith('file:')) {
        return resolveDatabaseLocation(operand, cwd);
      }
      return isAbsolute(operand)
        ? resolve(operand)
        : resolve(cwd, operand);
    } catch (error) {
      if (
        error instanceof URIError ||
        error?.code === 'ERR_INVALID_ARG_VALUE' ||
        error?.code === 'ERR_INVALID_FILE_URL_PATH'
      ) {
        return null;
      }
      throw error;
    }
  }

  function canonicalizeChildOperandPath(path) {
    let unresolved = resolve(path);
    const seenPaths = new Set();
    for (let redirects = 0; redirects <= 40; redirects++) {
      if (seenPaths.has(unresolved)) {
        throw new Error(`child path operand contains a symlink cycle: ${unresolved}`);
      }
      seenPaths.add(unresolved);
      const root = parsePath(unresolved).root;
      const components = unresolved
        .slice(root.length)
        .split(sep)
        .filter((component) => component !== '');
      let cursor = root;
      let redirected = false;

      for (let index = 0; index < components.length; index++) {
        const candidate = join(cursor, components[index]);
        let stats;
        try {
          stats = lstatSync(candidate);
        } catch (error) {
          if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') throw error;
          return resolve(
            realpathSync.native(cursor),
            ...components.slice(index),
          );
        }
        if (!stats.isSymbolicLink()) {
          cursor = candidate;
          continue;
        }

        const target = readlinkSync(candidate);
        unresolved = resolve(
          isAbsolute(target) ? target : resolve(dirname(candidate), target),
          ...components.slice(index + 1),
        );
        redirected = true;
        break;
      }

      if (!redirected) return realpathSync.native(cursor);
    }
    throw new Error(`child path operand exceeds the symlink limit: ${path}`);
  }

  function protectedFilesystemReason(identity) {
    for (const member of liveDatabaseFamily) {
      const currentIdentity = filesystemIdentity(member.path);
      if (
        identity.path === member.path ||
        isWithin(identity.path, member.path) ||
        (
          identity.inode !== null &&
          (
            (
              member.identity.inode !== null &&
              identity.inode === member.identity.inode
            ) ||
            (
              currentIdentity.inode !== null &&
              identity.inode === currentIdentity.inode
            )
          )
        )
      ) {
        return `target is the live database family or one of its ancestors/aliases`;
      }
    }
    return null;
  }

  function pathContainsProtectedDatabaseIdentity(path) {
    let stats;
    try {
      stats = lstatSync(path);
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return false;
      throw error;
    }
    const identity = childOperandFilesystemIdentity(path, process.cwd());
    if (identity !== null && protectedFilesystemReason(identity)) return true;
    if (!stats.isDirectory() || stats.isSymbolicLink()) return false;
    for (const entry of readdirSync(path)) {
      if (pathContainsProtectedDatabaseIdentity(join(path, entry))) return true;
    }
    return false;
  }

  function assertSymlinkTargetSafe(method, target, destination) {
    const destinationPath = snapshotFilesystemPath(destination);
    const rawTarget = String(
      target instanceof URL
        ? fileURLToPath(target)
        : Buffer.isBuffer(target)
          ? target.toString()
          : target,
    );
    const resolvedTarget = isAbsolute(rawTarget)
      ? rawTarget
      : resolve(dirname(String(destinationPath)), rawTarget);
    const reason = protectedFilesystemReason(filesystemIdentity(resolvedTarget));
    if (reason) refuseFilesystemWrite(method, resolvedTarget, reason);
  }

  function registerWritableFileDescriptor(descriptor, path) {
    if (!Number.isInteger(descriptor) || descriptor < 0) return;
    const identity = filesystemIdentity(path);
    if (
      protectedFilesystemReason(identity) ||
      !writableRoots.some((root) => isWithin(root, identity.path))
    ) {
      writableFileDescriptors.delete(descriptor);
      return;
    }
    const stats = fstatSync(descriptor, { bigint: true });
    writableFileDescriptors.set(descriptor, {
      inode: `${stats.dev}:${stats.ino}`,
      path: identity.path,
    });
  }

  function assertWritableFileDescriptor(method, descriptor) {
    if (!Number.isInteger(descriptor) || descriptor < 0) {
      refuseFilesystemWrite(method, null, 'file descriptor is invalid');
    }
    if (descriptor === 1 || descriptor === 2) return;
    const stats = fstatSync(descriptor, { bigint: true });
    const inode = `${stats.dev}:${stats.ino}`;
    if (
      liveDatabaseFamily.some((member) =>
        member.identity.inode !== null &&
        member.identity.inode === inode)
    ) {
      refuseFilesystemWrite(
        method,
        `fd:${descriptor}`,
        'file descriptor references the live database family',
      );
    }
    const recorded = writableFileDescriptors.get(descriptor);
    if (recorded?.inode === inode) return;
    for (const descriptorPath of [
      `/dev/fd/${descriptor}`,
      `/proc/self/fd/${descriptor}`,
    ]) {
      try {
        const linked = readlinkSync(descriptorPath);
        const identity = assertWritablePath(method, linked);
        writableFileDescriptors.set(descriptor, {
          inode,
          path: identity.path,
        });
        return;
      } catch {
        // Try the next platform descriptor path before failing closed.
      }
    }
    refuseFilesystemWrite(
      method,
      `fd:${descriptor}`,
      'file descriptor was not opened through a sealed writable path',
    );
  }

  function refuseFilesystemWrite(method, path, reason) {
    audit({
      type: 'filesystem-write',
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      method,
      path,
      blocked: true,
      reason,
    });
    throw new Error(
      `Refusing ${method} filesystem mutation during tests: ${reason}` +
      `${path ? ` (${path})` : ''}`,
    );
  }

  function refuseFilesystemRead(method, path, reason) {
    audit({
      type: 'filesystem-read',
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      method,
      path,
      blocked: true,
      reason,
    });
    throw new Error(
      `Refusing ${method} filesystem read during tests: ${reason}` +
      `${path ? ` (${path})` : ''}`,
    );
  }

  function snapshotFilesystemPath(value) {
    if (value instanceof URL) return new URL(value.href);
    if (Buffer.isBuffer(value)) return Buffer.from(value);
    if (typeof value !== 'string') {
      throw new TypeError('Filesystem path must be a string, Buffer, URL, or fd');
    }
    return String(value);
  }

  function snapshotFilesystemPathOrNull(value) {
    return value == null ? value : snapshotFilesystemPath(value);
  }

  function snapshotOpenFlags(flags) {
    return typeof flags === 'number' ? flags : String(flags);
  }

  function openFlagsPermitWrite(flags) {
    if (typeof flags === 'string') return /[wa+]/.test(flags);
    return (
      flags &
      (
        fsConstants.O_WRONLY |
        fsConstants.O_RDWR |
        fsConstants.O_APPEND |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC
      )
    ) !== 0;
  }

  installGuardedProcessIdentityTelemetry();
  installFilesystemGuards();

  class GuardedDatabaseSync {
    constructor(path, rawOptions) {
      const location = snapshotPathLike(path);
      const options = snapshotPlainRecord(rawOptions, 'DatabaseSync options');
      if (options.allowExtension === true) {
        throw new Error('SQLite extension loading is forbidden during tests');
      }
      options.allowExtension = false;
      const identity = assertDatabaseAllowed('sqlite-open', location);
      const database = new NativeDatabaseSync(location, options);
      databaseTargets.set(this, database);
      databasePolicies.set(this, {
        configured: false,
        identity,
        journalSizeLimit: 8 * 1024 * 1024,
        maximumPages: null,
        writable: options.readOnly !== true,
      });
      try {
        configureDatabaseIfNeeded(this);
      } catch (error) {
        databaseTargets.delete(this);
        databasePolicies.delete(this);
        try {
          database.close();
        } catch {
          // Preserve the configuration failure as the primary error.
        }
        throw error;
      }
    }

    aggregate(...args) {
      return databaseTarget(this).aggregate(...args);
    }

    applyChangeset(...args) {
      return databaseTarget(this).applyChangeset(...args);
    }

    close() {
      const result = databaseTarget(this).close();
      const policy = databasePolicy(this);
      policy.configured = false;
      policy.maximumPages = null;
      return result;
    }

    createSession(options) {
      const snapshot = snapshotPlainRecord(options, 'SQLite session options');
      if (
        snapshot.db !== undefined &&
        String(snapshot.db).toLowerCase() !== 'main'
      ) {
        throw new Error('Refusing a session on an attached SQLite database');
      }
      const session = databaseTarget(this).createSession(snapshot);
      return guardedSession(session);
    }

    enableLoadExtension(allow) {
      if (allow) {
        throw new Error('SQLite extension loading is forbidden during tests');
      }
      return databaseTarget(this).enableLoadExtension(false);
    }

    exec(sql) {
      const source = String(sql);
      validateSqlSafety(source, databasePolicy(this));
      return databaseTarget(this).exec(source);
    }

    function(...args) {
      return databaseTarget(this).function(...args);
    }

    get isOpen() {
      return databaseTarget(this).isOpen;
    }

    get isTransaction() {
      return databaseTarget(this).isTransaction;
    }

    loadExtension(path) {
      throw new Error(
        `SQLite extension loading is forbidden during tests: ${String(path)}`,
      );
    }

    location(dbName) {
      if (dbName !== undefined && String(dbName).toLowerCase() !== 'main') {
        throw new Error('Refusing to inspect a non-main attached SQLite database');
      }
      return databaseTarget(this).location(
        dbName === undefined ? undefined : String(dbName),
      );
    }

    open() {
      const result = databaseTarget(this).open();
      configureDatabaseIfNeeded(this);
      return result;
    }

    prepare(sql) {
      const source = String(sql);
      validateSqlSafety(source, databasePolicy(this));
      return guardedStatement(databaseTarget(this).prepare(source));
    }

    [Symbol.dispose]() {
      const database = databaseTarget(this);
      const policy = databasePolicy(this);
      policy.configured = false;
      policy.maximumPages = null;
      if (typeof database[Symbol.dispose] === 'function') {
        return database[Symbol.dispose]();
      }
      return database.close();
    }
  }
  Object.defineProperty(GuardedDatabaseSync, 'name', { value: 'DatabaseSync' });
  Object.freeze(GuardedDatabaseSync.prototype);
  sqlite.DatabaseSync = GuardedDatabaseSync;

  sqlite.backup = async function guardedBackup(source, destination, rawOptions) {
    assertDatabaseAllowed('sqlite-backup', destination);
    const options = snapshotPlainRecord(rawOptions, 'SQLite backup options');
    for (const name of ['source', 'target']) {
      if (
        options[name] !== undefined &&
        String(options[name]).toLowerCase() !== 'main'
      ) {
        throw new Error(`Refusing SQLite backup from attached ${name} database`);
      }
    }
    return await nativeBackup(
      databaseTargets.get(source) ?? source,
      snapshotPathLike(destination),
      options,
    );
  };

  class GuardedWorker extends EventEmitter {
    constructor(filename, rawOptions) {
      super();
      const options = snapshotWorkerOptions(rawOptions);
      const execArgv = options.execArgv ?? inheritedWorkerExecArgv();
      options.execArgv = execArgv.includes(guardRequireArg)
        ? [...execArgv]
        : [...execArgv, guardRequireArg];
      options.env = assertWorkerEnvironment(options.env);
      const worker = new NativeWorker(snapshotWorkerFilename(filename), options);
      workerTargets.set(this, worker);
      for (const event of ['error', 'exit', 'message', 'messageerror', 'online']) {
        worker.on(event, (...args) => this.emit(event, ...args));
      }
    }

    get stdin() {
      return workerTarget(this).stdin;
    }

    get stdout() {
      return workerTarget(this).stdout;
    }

    get stderr() {
      return workerTarget(this).stderr;
    }

    get threadId() {
      return workerTarget(this).threadId;
    }

    get resourceLimits() {
      return workerTarget(this).resourceLimits;
    }

    get performance() {
      return workerTarget(this).performance;
    }

    postMessage(value, transferList) {
      return workerTarget(this).postMessage(
        value,
        transferList === undefined ? undefined : [...transferList],
      );
    }

    ref() {
      workerTarget(this).ref();
      return this;
    }

    unref() {
      workerTarget(this).unref();
      return this;
    }

    terminate() {
      return workerTarget(this).terminate();
    }

    cpuUsage(previousValue) {
      return workerTarget(this).cpuUsage(previousValue);
    }

    getHeapSnapshot() {
      return workerTarget(this).getHeapSnapshot();
    }

    getHeapStatistics() {
      return workerTarget(this).getHeapStatistics();
    }

    async [Symbol.asyncDispose]() {
      await this.terminate();
    }
  }
  Object.defineProperty(GuardedWorker, 'name', { value: 'Worker' });
  Object.freeze(GuardedWorker.prototype);
  workerThreads.Worker = GuardedWorker;

  childProcess.spawn = function guardedSpawn(command, rawArgs, rawOptions) {
    const call = normalizeSpawnCall([command, rawArgs, rawOptions]);
    const options = snapshotChildOptions('spawn', call.options);
    const commandSnapshot = String(call.command);
    const argsSnapshot = snapshotArguments(call.args);
    assertChildLaunch('spawn', commandSnapshot, argsSnapshot, options);
    return nativeChildFunctions.spawn(commandSnapshot, argsSnapshot, options);
  };
  childProcess.spawnSync = function guardedSpawnSync(command, rawArgs, rawOptions) {
    const call = normalizeSpawnCall([command, rawArgs, rawOptions]);
    const options = snapshotChildOptions('spawnSync', call.options);
    const commandSnapshot = String(call.command);
    const argsSnapshot = snapshotArguments(call.args);
    assertChildLaunch('spawnSync', commandSnapshot, argsSnapshot, options);
    return nativeChildFunctions.spawnSync(commandSnapshot, argsSnapshot, options);
  };
  childProcess.fork = function guardedFork(modulePath, rawArgs, rawOptions) {
    const call = normalizeForkCall([modulePath, rawArgs, rawOptions]);
    const options = snapshotChildOptions('fork', call.options);
    const moduleSnapshot = String(call.modulePath);
    const argsSnapshot = snapshotArguments(call.args);
    assertForkLaunch(moduleSnapshot, argsSnapshot, options);
    return nativeChildFunctions.fork(moduleSnapshot, argsSnapshot, options);
  };
  childProcess.exec = function guardedExec(command, rawOptions, rawCallback) {
    const { options: optionInput, callback } =
      normalizeExecCall([command, rawOptions, rawCallback]);
    const options = snapshotChildOptions('exec', optionInput);
    const commandSnapshot = String(command);
    assertShellLaunch('exec', commandSnapshot, options);
    return nativeChildFunctions.exec(commandSnapshot, options, callback);
  };
  childProcess.execSync = function guardedExecSync(command, rawOptions) {
    const options = snapshotChildOptions(
      'execSync',
      normalizeExecCall([command, rawOptions]).options,
    );
    const commandSnapshot = String(command);
    assertShellLaunch('execSync', commandSnapshot, options);
    return nativeChildFunctions.execSync(commandSnapshot, options);
  };
  childProcess.execFile = function guardedExecFile(
    file,
    rawArgs,
    rawOptions,
    rawCallback,
  ) {
    const call = normalizeExecFileCall(
      [file, rawArgs, rawOptions, rawCallback],
    );
    const options = snapshotChildOptions('execFile', call.options);
    const fileSnapshot = String(call.file);
    const argsSnapshot = snapshotArguments(call.args);
    assertChildLaunch('execFile', fileSnapshot, argsSnapshot, options);
    return nativeChildFunctions.execFile(
      fileSnapshot,
      argsSnapshot,
      options,
      call.callback,
    );
  };
  childProcess.execFileSync = function guardedExecFileSync(
    file,
    rawArgs,
    rawOptions,
  ) {
    const call = normalizeExecFileCall([file, rawArgs, rawOptions]);
    const options = snapshotChildOptions('execFileSync', call.options);
    const fileSnapshot = String(call.file);
    const argsSnapshot = snapshotArguments(call.args);
    assertChildLaunch('execFileSync', fileSnapshot, argsSnapshot, options);
    return nativeChildFunctions.execFileSync(fileSnapshot, argsSnapshot, options);
  };
  NativeChildProcess.prototype.spawn = function guardedPrototypeSpawn(rawOptions) {
    const options = snapshotInternalSpawnOptions(rawOptions);
    const environment = environmentFromPairs(
      options.envPairs,
      'ChildProcess.prototype.spawn',
    );
    const validationOptions = {
      cwd: options.cwd,
      detached: options.detached,
      env: environment,
      shell: false,
    };
    const command = String(options.file ?? '');
    const argv = Array.isArray(options.args)
      ? options.args.map((value) => String(value))
      : [];
    const args = argv.length > 0 && argv[0] === command
      ? argv.slice(1)
      : argv;
    assertChildLaunch(
      'ChildProcess.prototype.spawn',
      command,
      args,
      validationOptions,
    );
    options.envPairs = environmentPairs(validationOptions.env);
    return Reflect.apply(nativeChildProcessSpawn, this, [options]);
  };

  syncBuiltinESMExports();

  function assertForkLaunch(modulePath, args, options) {
    if (options.detached === true) {
      refuseChild('fork', modulePath, 'detached child processes are forbidden');
    }
    const environment = assertChildEnvironment('fork', options);
    const cwd = childCwd(options);
    assertChildDatabasePath('fork', environment, cwd);
    const execPath = options.execPath ?? process.execPath;
    if (!sameFile(executableIdentity(execPath, environment, cwd), nodeExecutable)) {
      refuseChild(
        'fork',
        execPath,
        'custom fork execPath cannot be verified as the guarded Node runtime',
      );
    }
    assertDirectCommand('fork', execPath, [modulePath, ...args], options, environment, cwd);
  }

  function assertShellLaunch(method, command, options) {
    const environment = assertChildEnvironment(method, options);
    const cwd = childCwd(options);
    assertChildDatabasePath(method, environment, cwd);
    authorizeShellExecutable(method, options, environment, cwd);
    assertShellCommand(method, command, options, environment, cwd);
  }

  function assertChildLaunch(method, command, args, options) {
    restoreDatabasePolicyProbeCompilerEnvironment(
      method,
      command,
      args,
      options,
    );
    const environment = assertChildEnvironment(method, options);
    const cwd = childCwd(options);
    assertChildDatabasePath(method, environment, cwd);
    if (options.detached === true) {
      assertDetachedChildAllowed(
        method,
        command,
        args,
        environment,
        cwd,
      );
    }
    if (options.shell) {
      assertChildPathOperandsSafe(method, command, args, cwd);
      authorizeShellExecutable(method, options, environment, cwd);
      assertShellCommand(
        method,
        [command, ...args].map((value) => String(value)).join(' '),
        options,
        environment,
        cwd,
      );
      return;
    }
    assertDirectCommand(method, command, args, options, environment, cwd);
  }

  function authorizeShellExecutable(method, options, environment, cwd) {
    const shell = typeof options.shell === 'string'
      ? options.shell
      : process.platform === 'win32'
        ? process.env.ComSpec
        : '/bin/sh';
    const authorization = authorizeExecutable(
      `${method}:shell`,
      String(shell ?? ''),
      environment,
      cwd,
    );
    audit({
      type: 'child-process',
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      method: `${method}:shell`,
      command: authorization.identity.path,
      blocked: false,
      detached: options.detached === true,
      allowedBy: authorization.allowedBy,
    });
  }

  function restoreDatabasePolicyProbeCompilerEnvironment(
    method,
    command,
    args,
    options,
  ) {
    if (!databasePolicyProbeCompiler) return;
    const environment = options.env ?? process.env;
    const cwd = childCwd(options);
    if (
      !sameFile(
        executableIdentity(command, environment, cwd),
        databasePolicyProbeCompiler,
      )
    ) {
      return;
    }
    if (
      options.detached === true ||
      options.shell ||
      (
        args.length !== 1 &&
        args.length !== 2
      ) ||
      !/^--service=\d+\.\d+\.\d+$/.test(String(args[0])) ||
      (args.length === 2 && args[1] !== '--ping')
    ) {
      refuseChild(
        method,
        command,
        'database policy probe compiler arguments are not authorized',
      );
    }
    const restored = snapshotEnvironment(
      environment,
      `${method} database policy probe compiler`,
    );
    for (const [name, expected] of protectedEnvironment) {
      restored[name] = expected;
    }
    restored.DB_PATH = inheritedDatabase;
    options.env = restored;
  }

  function assertDetachedChildAllowed(
    method,
    command,
    args,
    environment,
    cwd,
  ) {
    const scope = environment.RADAR_TEST_DETACHED_SCOPE;
    const stack = String(new Error().stack ?? '').replaceAll('\\', '/');
    const isNode = sameFile(
      executableIdentity(command, environment, cwd),
      nodeExecutable,
    );
    const commandIdentity = executableIdentity(command, environment, cwd);
    const commandName = basename(commandIdentity?.path ?? '').toLowerCase();
    const resourceWatchdogPath = resolve(__dirname, 'resource-watchdog.mjs');
    const allowed =
      (scope === 'resource-watchdog' &&
        isNode &&
        args.length === 2 &&
        sameFile(fileIdentity(args[0], cwd), fileIdentity(resourceWatchdogPath)) &&
        stack.includes('/test/test-suite-runner.mjs')) ||
      (scope === 'resource-watchdog-victim' &&
        isNode &&
        args[0] === '-e' &&
        stack.includes('/src/lib/testRunnerSafety.test.ts')) ||
      (scope === 'release-reachability' &&
        commandIdentity !== null &&
        (
          isNode ||
          (
            (commandName === 'git' || commandName === 'git.exe') &&
            allowedExecutableIdentities.some((identity) =>
              executableIdentityMatches(commandIdentity, identity))
          )
        ) &&
        stack.includes('/src/lib/releaseReachability.ts'));

    if (!allowed) {
      refuseChild(method, command, 'detached child processes are forbidden');
    }
    audit({
      type: 'child-process',
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      method,
      command: String(command),
      blocked: false,
      detached: true,
      scope,
    });
  }

  function installGuardedProcessIdentityTelemetry() {
    if (
      Object.getOwnPropertyDescriptor(
        globalThis,
        guardedProcessIdentityTelemetryKey,
      ) !== undefined
    ) {
      throw new Error(
        'Guarded process identity telemetry was installed before the database guard',
      );
    }
    Object.defineProperty(globalThis, guardedProcessIdentityTelemetryKey, {
      configurable: false,
      enumerable: false,
      writable: false,
      value(pid) {
        if (!Number.isInteger(pid) || pid <= 0) {
          refuseChild(
            'processIdentityTelemetry',
            processStatusExecutable?.path ?? null,
            'process identity telemetry requires a positive integer PID',
          );
        }
        const currentIdentity = processStatusExecutable === null
          ? null
          : trustedSystemExecutableIdentity(processStatusExecutable.path);
        if (
          processStatusExecutable === null ||
          !exactFileIdentityMatches(
            processStatusExecutable,
            currentIdentity,
          )
        ) {
          refuseChild(
            'processIdentityTelemetry',
            processStatusExecutable?.path ?? null,
            'trusted system ps identity is unavailable or changed',
          );
        }
        const args = [
          '-p',
          String(pid),
          '-o',
          'pid=,ppid=,pgid=,lstart=,comm=',
        ];
        audit({
          type: 'child-process',
          pid: process.pid,
          context: process.env.NODE_TEST_CONTEXT ?? null,
          method: 'processIdentityTelemetry',
          command: processStatusExecutable.path,
          args,
          targetPid: pid,
          blocked: false,
          detached: false,
          scope: 'guard-owned-process-identity-telemetry',
        });
        return nativeChildFunctions.spawnSync(
          processStatusExecutable.path,
          args,
          {
            encoding: 'utf8',
            env: {
              LANG: 'C',
              LC_ALL: 'C',
            },
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 2_000,
          },
        );
      },
    });
  }

  function assertChildEnvironment(
    method,
    options,
    environment = null,
    subject = 'child',
  ) {
    const candidate = environment ?? options.env ?? process.env;
    if (
      candidate === null ||
      typeof candidate !== 'object' ||
      Array.isArray(candidate)
    ) {
      refuseChild(method, null, `${subject} environment is not an object`);
    }

    for (const [name, expected] of protectedEnvironment) {
      if (!Object.prototype.hasOwnProperty.call(candidate, name) ||
          String(candidate[name]) !== expected) {
        refuseChild(
          method,
          null,
          `${subject} environment removed or replaced protected ${name}`,
        );
      }
    }
    assertDatabasePolicyProbeChildEnvironment(method, candidate, subject);
    assertEnvironmentHasNoLiveDatabasePath(candidate, subject);

    return candidate;
  }

  function assertDatabasePolicyProbeChildEnvironment(
    method,
    candidate,
    subject,
  ) {
    const probe = candidate.RADAR_TEST_DATABASE_POLICY_PROBE;
    const context = candidate.RADAR_TEST_DATABASE_POLICY_PROBE_CONTEXT;
    const authority =
      candidate.RADAR_TEST_DATABASE_POLICY_PROBE_AUTHORITY;
    if (!databasePolicyProbeAuthority && authority !== undefined) {
      refuseChild(
        method,
        null,
        `${subject} cannot mint database policy probe authority`,
      );
    }
    if (probe === undefined && context === undefined) return;
    if (!databasePolicyProbeAuthority) {
      refuseChild(
        method,
        null,
        `${subject} cannot mint database policy probe capability`,
      );
    }
    if (
      probe !== '1' ||
      (context !== 'test' && context !== 'evaluation')
    ) {
      refuseChild(
        method,
        null,
        `${subject} database policy probe environment is invalid`,
      );
    }
  }

  function assertWorkerEnvironment(rawEnvironment) {
    const environment = snapshotEnvironment(
      rawEnvironment ?? process.env,
      'Worker',
    );
    assertChildEnvironment('Worker', { env: environment }, null, 'worker');
    if (environment.RADAR_TEST_WORKER_DB_PATH === undefined) {
      environment.RADAR_TEST_WORKER_DB_PATH = assignedWorkerDatabase.path;
    }
    const workerIdentity = databaseIdentity(environment.DB_PATH);
    if (
      workerIdentity === null ||
      !sameDatabase(workerIdentity, inheritedIdentity)
    ) {
      refuseChild(
        'Worker',
        null,
        'worker environment must use the current guarded database path',
      );
    }
    const declaredWorkerIdentity = databaseIdentity(
      environment.RADAR_TEST_WORKER_DB_PATH,
    );
    if (
      declaredWorkerIdentity === null ||
      !sameDatabase(declaredWorkerIdentity, assignedWorkerDatabase)
    ) {
      refuseChild(
        'Worker',
        null,
        'worker environment replaced its assigned worker database identity',
      );
    }
    environment.DB_PATH = inheritedIdentity.path;
    environment.RADAR_TEST_WORKER_DB_PATH = assignedWorkerDatabase.path;
    environment.RADAR_TEST_ENFORCE_WORKER_DB_ROOT = '1';
    return environment;
  }

  function assertChildDatabasePath(method, environment, cwd) {
    if (!Object.prototype.hasOwnProperty.call(environment, 'DB_PATH') ||
        environment.DB_PATH === undefined ||
        String(environment.DB_PATH) === '') {
      refuseChild(method, null, 'child environment removed required DB_PATH');
    }
    assertDatabaseAllowed('child-db-path', environment.DB_PATH, cwd);
  }

  function auditAllowedChildProcess(
    method,
    authorization,
    args,
    options,
  ) {
    audit({
      type: 'child-process',
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      method,
      command: authorization.identity.path,
      args: args.slice(0, 64),
      blocked: false,
      detached: options.detached === true,
      allowedBy: authorization.allowedBy,
    });
  }

  function assertDirectCommand(method, command, args, options, environment, cwd, depth = 0) {
    if (depth > 4) {
      refuseChild(method, command, 'child command wrapper depth exceeded');
    }
    const authorization = authorizeExecutable(method, command, environment, cwd);
    if (isSqliteExecutable(command, environment, cwd)) {
      refuseChild(
        method,
        command,
        'external sqlite3 execution is forbidden during tests',
      );
    }

    if (isEnvExecutable(authorization.identity)) {
      assertEnvCommand(method, args, options, environment, cwd, depth + 1);
      auditAllowedChildProcess(method, authorization, args, options);
      return;
    }

    if (isTaskpolicyExecutable(authorization.identity)) {
      assertTaskpolicyCommand(
        method,
        args,
        options,
        environment,
        cwd,
        depth + 1,
      );
      auditAllowedChildProcess(method, authorization, args, options);
      return;
    }

    if (isNiceExecutable(authorization.identity)) {
      assertNiceCommand(
        method,
        args,
        options,
        environment,
        cwd,
        depth + 1,
      );
      auditAllowedChildProcess(method, authorization, args, options);
      return;
    }

    const shellSource = shellCommandSource(authorization.identity, args);
    if (shellSource !== null) {
      assertChildPathOperandsSafe(
        method,
        command,
        args,
        cwd,
        authorization.identity,
      );
      assertShellCommand(method, shellSource, options, environment, cwd);
      auditAllowedChildProcess(method, authorization, args, options);
      return;
    }

    assertChildPathOperandsSafe(
      method,
      command,
      args,
      cwd,
      authorization.identity,
    );
    auditAllowedChildProcess(method, authorization, args, options);
  }

  function authorizeExecutable(method, command, environment, cwd) {
    const identity = executableIdentity(command, environment, cwd);
    if (identity === null) {
      refuseChild(method, command, 'child executable identity is unavailable');
    }
    const exact = allowedExecutableIdentities.find((allowed) =>
      executableIdentityMatches(identity, allowed));
    if (exact) return { identity, allowedBy: 'exact-identity' };
    const root = executableRoots.find((candidate) =>
      isWithin(candidate, identity.path));
    if (root) return { identity, allowedBy: `isolated-root:${root}` };
    refuseChild(
      method,
      command,
      `child executable is not allowlisted: ${identity.path}`,
    );
  }

  function assertEnvCommand(method, args, options, environment, cwd, depth) {
    const nestedEnvironment = { ...environment };
    let index = 0;

    while (index < args.length) {
      const argument = String(args[index]);
      if (argument === '--') {
        index++;
        break;
      }
      if (argument === '-i' || argument === '--ignore-environment') {
        refuseChild(
          method,
          'env',
          'env cannot clear the protected test environment',
        );
      }
      if (argument === '-u' || argument === '--unset') {
        const name = args[index + 1];
        if (name === undefined) {
          refuseChild(method, 'env', 'env --unset is missing a variable name');
        }
        assertShellEnvironmentMutationAllowed(method, 'env', String(name));
        delete nestedEnvironment[String(name)];
        index += 2;
        continue;
      }
      if (argument.startsWith('--unset=')) {
        const name = argument.slice('--unset='.length);
        assertShellEnvironmentMutationAllowed(method, 'env', name);
        delete nestedEnvironment[name];
        index++;
        continue;
      }
      if (argument === '-S' || argument === '--split-string' ||
          argument.startsWith('--split-string=')) {
        refuseChild(method, 'env', 'env split-string child commands cannot be audited');
      }
      if (argument.startsWith('-')) {
        refuseChild(method, 'env', `unsupported env option ${argument}`);
      }
      const assignment = parseEnvironmentAssignment(argument);
      if (assignment === null) break;
      assertShellEnvironmentMutationAllowed(method, 'env', assignment.name);
      assertChildPathOperandsSafe(method, 'env', [argument], cwd);
      nestedEnvironment[assignment.name] = assignment.value;
      index++;
    }

    if (index >= args.length) return;
    assertChildEnvironment(method, options, nestedEnvironment);
    assertChildDatabasePath(method, nestedEnvironment, cwd);
    assertDirectCommand(
      method,
      args[index],
      args.slice(index + 1),
      options,
      nestedEnvironment,
      cwd,
      depth,
    );
  }

  function assertTaskpolicyCommand(
    method,
    args,
    options,
    environment,
    cwd,
    depth,
  ) {
    if (args.length < 2 || args[0] !== '-b') {
      refuseChild(
        method,
        'taskpolicy',
        'taskpolicy only supports the audited -b <command> form',
      );
    }
    assertDirectCommand(
      method,
      args[1],
      args.slice(2),
      options,
      environment,
      cwd,
      depth,
    );
  }

  function assertNiceCommand(
    method,
    args,
    options,
    environment,
    cwd,
    depth,
  ) {
    if (args.length < 3 || args[0] !== '-n' || args[1] !== '15') {
      refuseChild(
        method,
        'nice',
        'nice only supports the audited -n 15 <command> form',
      );
    }
    assertDirectCommand(
      method,
      args[2],
      args.slice(3),
      options,
      environment,
      cwd,
      depth,
    );
  }

  function assertShellCommand(method, source, options, environment, cwd) {
    const parsed = tokenizeShell(String(source), environment);
    const hasSqlite = parsed.tokens.some((token) =>
      token !== null && isSqliteExecutable(token, environment, cwd));

    if (parsed.unsafe) {
      refuseChild(
        method,
        null,
        'shell command uses unauditable expansion or globbing',
      );
    }

    if (hasSqlite) {
      refuseChild(
        method,
        'sqlite3',
        'external sqlite3 execution is forbidden during tests',
      );
    }

    let segment = [];
    for (const token of [...parsed.tokens, null]) {
      if (token !== null) {
        segment.push(token);
        continue;
      }
      if (segment.length > 0) assertShellSegment(method, segment, options, environment, cwd);
      segment = [];
    }
  }

  function assertShellSegment(method, words, options, environment, cwd) {
    let index = 0;
    const segmentEnvironment = { ...environment };
    while (index < words.length) {
      const assignment = parseEnvironmentAssignment(words[index]);
      if (assignment === null) break;
      assertShellEnvironmentMutationAllowed(
        method,
        'assignment',
        assignment.name,
      );
      segmentEnvironment[assignment.name] = assignment.value;
      index++;
    }
    if (index >= words.length) {
      assertChildPathOperandsSafe(method, 'assignment', words, cwd);
      return;
    }

    const command = words[index];
    const args = words.slice(index + 1);
    if (command === 'unset') {
      for (const name of args) {
        if (protectedEnvironment.has(name) || name === 'DB_PATH') {
          refuseChild(method, command, `shell command unsets protected ${name}`);
        }
      }
      return;
    }
    if (command === 'export') {
      for (const argument of args) {
        const assignment = parseEnvironmentAssignment(argument);
        const name = assignment?.name ?? String(argument);
        assertShellEnvironmentMutationAllowed(method, command, name);
      }
      assertChildPathOperandsSafe(method, command, args, cwd);
      return;
    }
    if (['declare', 'local', 'readonly', 'typeset'].includes(command)) {
      for (const argument of args) {
        if (String(argument).startsWith('-')) continue;
        const assignment = parseEnvironmentAssignment(argument);
        const name = assignment?.name ?? String(argument);
        assertShellEnvironmentMutationAllowed(method, command, name);
      }
      assertChildPathOperandsSafe(method, command, args, cwd);
      return;
    }

    assertChildEnvironment(method, options, segmentEnvironment);
    assertChildDatabasePath(method, segmentEnvironment, cwd);

    if (['eval', 'source', '.'].includes(command)) {
      refuseChild(
        method,
        command,
        'dynamic shell evaluation is forbidden during tests',
      );
    }
    if (['command', 'exec', 'builtin', 'nohup'].includes(command) && args.length > 0) {
      if (
        ['declare', 'export', 'local', 'readonly', 'typeset', 'unset']
          .includes(args[0])
      ) {
        assertShellSegment(method, args, options, segmentEnvironment, cwd);
        return;
      }
      assertDirectCommand(
        method,
        args[0],
        args.slice(1),
        options,
        segmentEnvironment,
        cwd,
      );
      return;
    }
    assertDirectCommand(method, command, args, options, segmentEnvironment, cwd);
  }

  function assertShellEnvironmentMutationAllowed(method, command, name) {
    if (name === 'DB_PATH' || protectedEnvironment.has(name)) {
      refuseChild(
        method,
        command,
        `shell command mutates protected ${name}`,
      );
    }
  }

  function assertDatabaseAllowed(type, location, cwd = process.cwd()) {
    const identity = databaseIdentity(location, cwd);
    const blocked = identity !== null && isProtectedDatabaseIdentity(identity);
    const permittedRoots = enforceWorkerRoot
      ? [workerDatabaseRoot, processLockRoot]
      : allowedRoots;
    const outsideAllowedRoots = identity !== null &&
      !permittedRoots.some((root) => isWithin(root, identity.path));

    auditDatabase(
      type,
      location,
      identity,
      blocked,
      outsideAllowedRoots,
      enforceWorkerRoot,
    );

    if (blocked) {
      throw new Error(`Refusing to open the live database during tests: ${identity.path}`);
    }
    if (outsideAllowedRoots) {
      throw new Error(
        `Refusing to open a database outside the test roots: ${identity.path}`,
      );
    }
    return identity;
  }

  function isProtectedDatabaseIdentity(identity) {
    return identity !== null &&
      liveDatabaseFamily.some((member) =>
        sameDatabase(identity, member.identity));
  }

  function assertEnvironmentHasNoLiveDatabasePath(environment, subject) {
    if (guardPolicy.legacy === true) return;
    for (const [name, rawValue] of Object.entries(environment)) {
      if (rawValue === undefined) continue;
      const value = String(rawValue);
      if (
        liveDatabaseFamily.some((member) =>
          value.includes(member.path) ||
          value.includes(pathToFileURL(member.path).href))
      ) {
        refuseChild(
          'environment',
          null,
          `${subject} environment exposes live database family member via ${name}`,
        );
      }
    }
  }

  function configureDatabaseIfNeeded(facade) {
    const database = databaseTarget(facade);
    const policy = databasePolicy(facade);
    if (
      policy.configured ||
      !policy.writable ||
      !database.isOpen ||
      policy.identity === null ||
      isWithin(processLockRoot, policy.identity.path)
    ) {
      return;
    }
    policy.maximumPages = configureWritableDatabase(database);
    policy.configured = true;
  }

  function configureWritableDatabase(database) {
    const pageSizeRow = database.prepare('PRAGMA page_size').get();
    const pageSize = Number(
      pageSizeRow?.page_size ?? Object.values(pageSizeRow ?? {})[0],
    );
    if (!Number.isInteger(pageSize) || pageSize <= 0) {
      throw new Error(`Unable to determine SQLite page size: ${String(pageSize)}`);
    }
    const maximumPages = Math.max(1, Math.floor(sqliteMaximumBytes / pageSize));
    database.exec(`
      PRAGMA max_page_count = ${maximumPages};
      PRAGMA journal_size_limit = 8388608;
      PRAGMA wal_autocheckpoint = 256;
    `);
    const configuredRow = database.prepare('PRAGMA max_page_count').get();
    const configuredPages = Number(
      configuredRow?.max_page_count ?? Object.values(configuredRow ?? {})[0],
    );
    if (
      !Number.isInteger(configuredPages) ||
      configuredPages <= 0 ||
      configuredPages * pageSize > sqliteMaximumBytes
    ) {
      throw new Error(
        `SQLite max_page_count exceeds the test ceiling: ` +
        `${configuredPages} pages * ${pageSize} bytes`,
      );
    }
    return configuredPages;
  }

  function databaseTarget(facade) {
    const database = databaseTargets.get(facade);
    if (database === undefined) {
      throw new TypeError('Illegal invocation of guarded DatabaseSync method');
    }
    return database;
  }

  function databasePolicy(facade) {
    const policy = databasePolicies.get(facade);
    if (policy === undefined) {
      throw new TypeError('Illegal invocation of guarded DatabaseSync method');
    }
    return policy;
  }

  class GuardedStatementSync {
    constructor(token, statement) {
      if (token !== statementFacadeToken) {
        throw new TypeError('StatementSync cannot be constructed directly');
      }
      statementTargets.set(this, statement);
    }

    all(...args) {
      return statementTarget(this).all(...args);
    }

    columns() {
      return statementTarget(this).columns();
    }

    get expandedSQL() {
      return statementTarget(this).expandedSQL;
    }

    get(...args) {
      return statementTarget(this).get(...args);
    }

    iterate(...args) {
      return statementTarget(this).iterate(...args);
    }

    run(...args) {
      return statementTarget(this).run(...args);
    }

    setAllowBareNamedParameters(enabled) {
      return statementTarget(this).setAllowBareNamedParameters(Boolean(enabled));
    }

    setAllowUnknownNamedParameters(enabled) {
      return statementTarget(this).setAllowUnknownNamedParameters(Boolean(enabled));
    }

    setReadBigInts(enabled) {
      return statementTarget(this).setReadBigInts(Boolean(enabled));
    }

    setReturnArrays(enabled) {
      return statementTarget(this).setReturnArrays(Boolean(enabled));
    }

    get sourceSQL() {
      return statementTarget(this).sourceSQL;
    }
  }
  const statementFacadeToken = Object.freeze({});
  Object.defineProperty(GuardedStatementSync, 'name', { value: 'StatementSync' });
  Object.freeze(GuardedStatementSync.prototype);

  function guardedStatement(statement) {
    return new GuardedStatementSync(statementFacadeToken, statement);
  }

  function statementTarget(facade) {
    const statement = statementTargets.get(facade);
    if (statement === undefined) {
      throw new TypeError('Illegal invocation of guarded StatementSync method');
    }
    return statement;
  }

  function guardedSession(session) {
    const facade = Object.create(null);
    sessionTargets.set(facade, session);
    Object.defineProperties(facade, {
      changeset: {
        enumerable: true,
        value: () => sessionTarget(facade).changeset(),
      },
      close: {
        enumerable: true,
        value: () => sessionTarget(facade).close(),
      },
      patchset: {
        enumerable: true,
        value: () => sessionTarget(facade).patchset(),
      },
    });
    return Object.freeze(facade);
  }

  function sessionTarget(facade) {
    const session = sessionTargets.get(facade);
    if (session === undefined) {
      throw new TypeError('Illegal invocation of guarded SQLite session method');
    }
    return session;
  }

  function validateSqlSafety(source, policy) {
    for (const statement of tokenizeSqlStatements(source)) {
      const words = statement
        .filter((token) => token.type === 'word')
        .map((token) => token.value);
      if (words.includes('ATTACH')) {
        refuseSql('Refusing ATTACH SQL during isolated tests', source);
      }
      if (words.includes('VACUUM')) {
        refuseSql('Refusing VACUUM SQL during isolated tests', source);
      }
      validatePragmaSafety(statement, policy, source);
    }
  }

  function validatePragmaSafety(tokens, policy, source) {
    const pragmaIndex = tokens.findIndex((token) =>
      token.type === 'word' && token.value === 'PRAGMA');
    if (pragmaIndex === -1) return;

    let index = pragmaIndex + 1;
    let nameToken = tokens[index];
    if (nameToken === undefined) return;
    if (
      tokens[index + 1]?.value === '.' &&
      ['word', 'identifier'].includes(tokens[index + 2]?.type)
    ) {
      const schema = nameToken.value;
      if (!['MAIN', 'TEMP'].includes(schema)) {
        refuseSql(`Refusing PRAGMA against attached schema ${schema}`, source);
      }
      index += 2;
      nameToken = tokens[index];
    }
    if (!['word', 'identifier'].includes(nameToken?.type)) return;

    const name = nameToken.value;
    const operator = tokens[index + 1]?.value;
    if (operator !== '=' && operator !== '(') return;
    if (name === 'MAX_PAGE_COUNT') {
      const value = pragmaIntegerValue(tokens, index + 2, operator, source);
      if (
        policy.maximumPages === null ||
        value <= 0 ||
        value > policy.maximumPages
      ) {
        refuseSql(
          'Refusing PRAGMA max_page_count that weakens the test database ceiling',
          source,
        );
      }
    }
    if (name === 'JOURNAL_SIZE_LIMIT') {
      const value = pragmaIntegerValue(tokens, index + 2, operator, source);
      if (value < 0 || value > policy.journalSizeLimit) {
        refuseSql(
          'Refusing PRAGMA journal_size_limit that weakens the test journal ceiling',
          source,
        );
      }
    }
    if (name === 'PAGE_SIZE') {
      refuseSql(
        'Refusing PRAGMA page_size changes after the byte ceiling is configured',
        source,
      );
    }
  }

  function pragmaIntegerValue(tokens, start, operator, source) {
    const endSymbol = operator === '(' ? ')' : ';';
    const valueTokens = [];
    for (let index = start; index < tokens.length; index++) {
      if (tokens[index].value === endSymbol) break;
      valueTokens.push(tokens[index].value);
    }
    const value = valueTokens.join('');
    if (!/^-?\d+$/.test(value)) {
      refuseSql(
        'Refusing a dynamic or non-integer protected SQLite PRAGMA value',
        source,
      );
    }
    return Number(value);
  }

  function refuseSql(reason, source) {
    audit({
      type: 'sqlite-sql-policy',
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      dbPath: process.env.DB_PATH ?? null,
      workerDbPath: process.env.RADAR_TEST_WORKER_DB_PATH ?? null,
      blocked: true,
      reason,
      sql: String(source).slice(0, 512),
    });
    throw new Error(reason);
  }

  function workerTarget(facade) {
    const worker = workerTargets.get(facade);
    if (worker === undefined) {
      throw new TypeError('Illegal invocation of guarded Worker method');
    }
    return worker;
  }

  function snapshotWorkerOptions(rawOptions) {
    const options = snapshotPlainRecord(rawOptions, 'Worker options');
    if (options.argv !== undefined) {
      if (!Array.isArray(options.argv)) {
        refuseChild('Worker', null, 'worker argv must be an array');
      }
      options.argv = snapshotArguments(options.argv);
    }
    if (options.execArgv !== undefined) {
      if (!Array.isArray(options.execArgv)) {
        refuseChild('Worker', null, 'worker execArgv must be an array');
      }
      options.execArgv = snapshotArguments(options.execArgv);
    }
    if (options.resourceLimits !== undefined) {
      options.resourceLimits = snapshotPlainRecord(
        options.resourceLimits,
        'Worker resource limits',
      );
    }
    if (options.transferList !== undefined) {
      if (!Array.isArray(options.transferList)) {
        refuseChild('Worker', null, 'worker transferList must be an array');
      }
      options.transferList = [...options.transferList];
    }
    return options;
  }

  function snapshotChildOptions(method, rawOptions) {
    const options = snapshotPlainRecord(rawOptions, `${method} options`);
    options.env = snapshotEnvironment(options.env ?? process.env, method);
    options.cwd = childCwd(options);
    if (
      options.detached !== undefined &&
      typeof options.detached !== 'boolean'
    ) {
      refuseChild(method, null, 'detached option must be a boolean');
    }
    if (
      options.shell !== undefined &&
      typeof options.shell !== 'boolean' &&
      typeof options.shell !== 'string'
    ) {
      refuseChild(method, null, 'shell option must be a boolean or string');
    }
    if (Array.isArray(options.stdio)) options.stdio = [...options.stdio];
    if (Buffer.isBuffer(options.input)) options.input = Buffer.from(options.input);
    return options;
  }

  function snapshotInternalSpawnOptions(rawOptions) {
    const options = snapshotPlainRecord(
      rawOptions,
      'ChildProcess.prototype.spawn options',
    );
    if (Array.isArray(options.args)) options.args = snapshotArguments(options.args);
    if (Array.isArray(options.envPairs)) {
      options.envPairs = snapshotArguments(options.envPairs);
    }
    if (Array.isArray(options.stdio)) options.stdio = [...options.stdio];
    if (options.cwd !== undefined && options.cwd !== null) {
      options.cwd = childCwd(options);
    }
    return options;
  }

  function snapshotEnvironment(rawEnvironment, method) {
    if (
      rawEnvironment === null ||
      typeof rawEnvironment !== 'object' ||
      Array.isArray(rawEnvironment)
    ) {
      refuseChild(method, null, 'child environment is not an object');
    }
    const environment = Object.create(null);
    let names;
    try {
      names = Object.keys(rawEnvironment);
    } catch {
      refuseChild(method, null, 'child environment keys cannot be inspected');
    }
    for (const name of names) {
      let value;
      try {
        value = rawEnvironment[name];
      } catch {
        refuseChild(
          method,
          null,
          `child environment value ${name} cannot be inspected`,
        );
      }
      if (value !== undefined) environment[name] = String(value);
    }
    return environment;
  }

  function environmentFromPairs(rawPairs, method) {
    if (!Array.isArray(rawPairs)) {
      refuseChild(method, null, 'internal child environment pairs are missing');
    }
    const environment = Object.create(null);
    for (const rawPair of rawPairs) {
      const pair = String(rawPair);
      const separator = pair.indexOf('=');
      if (separator <= 0) {
        refuseChild(method, null, 'internal child environment pair is malformed');
      }
      const name = pair.slice(0, separator);
      if (
        Object.prototype.hasOwnProperty.call(environment, name) &&
        (protectedEnvironment.has(name) || name === 'DB_PATH')
      ) {
        refuseChild(
          method,
          null,
          `internal child environment duplicates protected ${name}`,
        );
      }
      environment[name] = pair.slice(separator + 1);
    }
    return environment;
  }

  function environmentPairs(environment) {
    return Object.entries(environment)
      .map(([name, value]) => `${name}=${value}`);
  }

  function snapshotPlainRecord(rawValue, label) {
    if (rawValue === undefined || rawValue === null) return Object.create(null);
    if (typeof rawValue !== 'object' || Array.isArray(rawValue)) {
      throw new TypeError(`${label} must be an object`);
    }
    const snapshot = Object.create(null);
    let keys;
    try {
      keys = Reflect.ownKeys(rawValue);
    } catch {
      throw new TypeError(`${label} keys cannot be inspected`);
    }
    for (const key of keys) {
      if (typeof key !== 'string' && typeof key !== 'symbol') continue;
      let value;
      try {
        value = rawValue[key];
      } catch {
        throw new TypeError(`${label} property ${String(key)} cannot be inspected`);
      }
      snapshot[key] = value;
    }
    return snapshot;
  }

  function auditDatabase(
    type,
    location,
    identity,
    blocked,
    outsideAllowedRoots,
    workerRootEnforced,
  ) {
    audit({
      type,
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      dbPath: process.env.DB_PATH ?? null,
      workerDbPath: process.env.RADAR_TEST_WORKER_DB_PATH ?? null,
      location: displayLocation(location),
      resolvedPath: identity?.path ?? null,
      inode: identity?.inode ?? null,
      blocked,
      outsideAllowedRoots,
      workerRootEnforced,
    });
  }

  function refuseChild(method, command, reason) {
    audit({
      type: 'child-process',
      pid: process.pid,
      context: process.env.NODE_TEST_CONTEXT ?? null,
      method,
      command: command == null ? null : String(command),
      blocked: true,
      reason,
    });
    throw new Error(`Refusing ${method} child process during tests: ${reason}`);
  }

  function positiveIntegerEnv(name, maximum) {
    const raw = requiredEnv(name);
    if (!/^[1-9]\d*$/.test(raw) || Number(raw) > maximum) {
      throw new Error(`${name} must be an integer from 1 to ${maximum}, got ${raw}`);
    }
    return Number(raw);
  }

  function isSqliteExecutable(command, environment, cwd) {
    const identity = executableIdentity(command, environment, cwd);
    return basename(String(command)).toLowerCase() === 'sqlite3' ||
      sameFile(identity, sqliteExecutable);
  }

  function isEnvExecutable(identity) {
    return identity?.path === '/usr/bin/env';
  }

  function isNiceExecutable(identity) {
    return identity?.path === '/usr/bin/nice';
  }

  function isTaskpolicyExecutable(identity) {
    return identity?.path === '/usr/sbin/taskpolicy';
  }

  function shellCommandSource(identity, args) {
    const name = basename(identity?.path ?? '').toLowerCase();
    if (!['bash', 'dash', 'ksh', 'sh', 'zsh'].includes(name)) return null;
    for (let index = 0; index < args.length; index++) {
      const argument = String(args[index]);
      if (/^-[^-]*c/.test(argument)) {
        return args[index + 1] === undefined ? '' : String(args[index + 1]);
      }
    }
    return null;
  }

  function audit(event) {
    const line = `${JSON.stringify({ runId, ...event })}\n`;
    const descriptor = openSync(
      auditPath,
      fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_WRONLY,
      0o600,
    );
    try {
      writeSync(descriptor, line);
    } finally {
      closeSync(descriptor);
    }
  }

  const installedHooks = Object.freeze({
    fs: captureInstalledHookSet(fs, nativeFsFunctions),
    fsPromises: captureInstalledHookSet(
      fsPromises,
      nativeFsPromiseFunctions,
    ),
    childProcess: captureInstalledHookSet(
      childProcess,
      nativeChildFunctions,
    ),
    sqliteBackup: sqlite.backup,
    sqliteDatabaseSync: sqlite.DatabaseSync,
    worker: workerThreads.Worker,
    writeStream: fs.WriteStream,
    childPrototypeSpawn: NativeChildProcess.prototype.spawn,
  });
  let installation;
  installation = Object.freeze({
    schemaVersion: 1,
    assertActive({ requirePrivateArtifacts = false } = {}) {
      assertGuardRuntimeActive();
      if (
        process.env.RADAR_TEST_RUN_ID !== runId ||
        process.env.DB_PATH !== inheritedDatabase ||
        process.env.DOTENV_CONFIG_PATH !==
          protectedEnvironment.get('DOTENV_CONFIG_PATH')
      ) {
        throw new Error('Database guard protected process identity changed');
      }
      const artifacts =
        requirePrivateArtifacts || helperArtifacts !== null
          ? assertPrivateHelperArtifacts()
          : null;
      return guardAttestation(artifacts);
    },
    assertBootstrapPolicyProbe() {
      assertGuardRuntimeActive();
      if (!databasePolicyProbe || !databasePolicyProbeAuthority) {
        throw new Error(
          'Database bootstrap policy probe capability was not authorized at launch',
        );
      }
      const mutableProbeEnvironment = new Set([
        'DOTENV_CONFIG_PATH',
        'RADAR_TEST_WRITER_LOCK_PID',
        'RADAR_TEST_WRITER_LEASE_PATH',
        'RADAR_TEST_WRITER_LOCK_TOKEN',
      ]);
      for (const [name, expected] of protectedEnvironment) {
        if (
          !mutableProbeEnvironment.has(name) &&
          process.env[name] !== expected
        ) {
          throw new Error(
            `Database bootstrap policy probe changed protected ${name}`,
          );
        }
      }
      return guardAttestation(null);
    },
  });

  function assertGuardRuntimeActive() {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, installKey);
    if (
      descriptor === undefined ||
      descriptor.configurable ||
      descriptor.enumerable ||
      descriptor.writable ||
      descriptor.value !== installation
    ) {
      throw new Error('Database guard installation capability is not sealed');
    }
    if (
      !installedHookSetMatches(fs, installedHooks.fs) ||
      !installedHookSetMatches(fsPromises, installedHooks.fsPromises) ||
      !installedHookSetMatches(
        childProcess,
        installedHooks.childProcess,
      ) ||
      sqlite.backup !== installedHooks.sqliteBackup ||
      sqlite.DatabaseSync !== installedHooks.sqliteDatabaseSync ||
      workerThreads.Worker !== installedHooks.worker ||
      fs.WriteStream !== installedHooks.writeStream ||
      NativeChildProcess.prototype.spawn !== installedHooks.childPrototypeSpawn
    ) {
      throw new Error('Database guard runtime hooks are not fully installed');
    }
  }

  function guardAttestation(artifacts) {
    const databaseFileIdentity = attestedDatabaseFileIdentity();
    return Object.freeze({
      schemaVersion: 1,
      runId,
      policyKind: guardPolicy.kind,
      policyPath: guardPolicy.policyPath,
      databasePath: inheritedIdentity.path,
      databaseIdentity: databaseFileIdentity,
      dotenvPath: canonicalizePath(
        protectedEnvironment.get('DOTENV_CONFIG_PATH'),
      ),
      tempRoot: canonicalizePath(
        protectedEnvironment.get('RADAR_TEST_TEMP_ROOT'),
      ),
      privateArtifacts: artifacts,
    });
  }

  function attestedDatabaseFileIdentity() {
    if (inheritedIdentity.inode === null) return null;
    const currentIdentity = databaseIdentity(inheritedIdentity.path);
    if (
      currentIdentity === null ||
      currentIdentity.path !== inheritedIdentity.path ||
      currentIdentity.dev !== inheritedIdentity.dev ||
      currentIdentity.ino !== inheritedIdentity.ino
    ) {
      throw new Error(
        'Database guard DB_PATH device/inode changed before repository import',
      );
    }
    return Object.freeze({
      dev: inheritedIdentity.dev,
      ino: inheritedIdentity.ino,
    });
  }

  function captureInstalledHookSet(target, nativeFunctions) {
    return Object.freeze(Object.fromEntries(
      Object.keys(nativeFunctions)
        .filter((name) => typeof nativeFunctions[name] === 'function')
        .map((name) => [name, target[name]]),
    ));
  }

  function installedHookSetMatches(target, expected) {
    return Object.entries(expected)
      .every(([name, hook]) => target[name] === hook);
  }

  audit({
    type: 'guard-ready',
    pid: process.pid,
    ppid: process.ppid,
    context: process.env.NODE_TEST_CONTEXT ?? null,
    dbPath: inheritedDatabase,
    policyKind: guardPolicy.kind,
    helperArtifacts,
    script: process.argv[1] ?? null,
  });
  return installation;
}

function directDatabaseHelperName() {
  const name = basename(String(process.argv[1] ?? ''));
  return new Set([
    'composedPublication.e2e.helper.js',
    'composedPublication.e2e.helper.ts',
    'releaseValidationProofEvaluationCli.helper.js',
    'releaseValidationProofEvaluationCli.helper.ts',
    'scorerVerifierContract.e2e.helper.js',
    'scorerVerifierContract.e2e.helper.ts',
  ]).has(name)
    ? name
    : null;
}

function assertPrivateHelperArtifacts() {
  const helperName = directDatabaseHelperName() ?? 'guarded helper';
  if (process.env.NODE_TEST_CONTEXT !== undefined) {
    throw new Error(`${helperName} must not inherit NODE_TEST_CONTEXT`);
  }
  const runId = requiredEnv('RADAR_TEST_RUN_ID');
  const codeRevision = requiredEnv('RADAR_CODE_REVISION');
  if (requiredEnv('RADAR_TEST_CODE_REVISION') !== codeRevision) {
    throw new Error(`${helperName} code revision is not bound to the test run`);
  }

  const tempRoot = assertPrivateDirectory(
    requiredEnv('RADAR_TEST_TEMP_ROOT'),
    'RADAR_TEST_TEMP_ROOT',
  );
  for (const name of ['TMPDIR', 'TMP', 'TEMP', 'SQLITE_TMPDIR']) {
    const path = assertPrivateDirectory(requiredEnv(name), name);
    if (!isWithin(tempRoot, path)) {
      throw new Error(`${helperName} ${name} escapes RADAR_TEST_TEMP_ROOT`);
    }
  }

  const dotenvPath = privateArtifactPath(
    requiredEnv('DOTENV_CONFIG_PATH'),
    'DOTENV_CONFIG_PATH',
    tempRoot,
  );
  if (dotenvPath !== join(tempRoot, 'empty.env')) {
    throw new Error(
      `${helperName} DOTENV_CONFIG_PATH must be RADAR_TEST_TEMP_ROOT/empty.env`,
    );
  }
  assertPrivateRegularFile(dotenvPath, 'DOTENV_CONFIG_PATH', {
    empty: true,
  });

  const databasePath = privateArtifactPath(
    requiredEnv('DB_PATH'),
    'DB_PATH',
    tempRoot,
  );
  if (basename(databasePath) !== 'radar.db') {
    throw new Error(`${helperName} DB_PATH must name radar.db`);
  }
  if (databasePath === dotenvPath) {
    throw new Error(`${helperName} DB_PATH and DOTENV_CONFIG_PATH must differ`);
  }

  const bootstrapMode = requiredEnv('RADAR_DB_BOOTSTRAP_MODE');
  if (bootstrapMode !== 'fresh' && bootstrapMode !== 'existing') {
    throw new Error(
      `${helperName} RADAR_DB_BOOTSTRAP_MODE must be fresh or existing`,
    );
  }
  const databaseFamily = [
    databasePath,
    `${databasePath}-wal`,
    `${databasePath}-shm`,
    `${databasePath}-journal`,
  ];
  if (bootstrapMode === 'fresh') {
    for (const path of databaseFamily) {
      if (pathEntryExists(path)) {
        throw new Error(
          `${helperName} fresh database artifact already exists: ${path}`,
        );
      }
    }
  } else {
    assertPrivateRegularFile(databasePath, 'DB_PATH');
    assertSqliteDatabaseHeader(databasePath, 'DB_PATH');
    for (const path of databaseFamily.slice(1)) {
      if (pathEntryExists(path)) {
        assertPrivateRegularFile(path, `DB_PATH family member ${basename(path)}`);
      }
    }
  }

  return Object.freeze({
    runId,
    helperName,
    bootstrapMode,
    tempRoot,
    databasePath,
    dotenvPath,
  });
}

function privateArtifactPath(rawPath, label, tempRoot) {
  if (typeof rawPath !== 'string' || !isAbsolute(rawPath)) {
    throw new Error(`${label} must be an absolute path`);
  }
  const absolute = resolve(rawPath);
  const canonical = canonicalizePath(absolute);
  if (rawPath !== absolute || canonical !== absolute) {
    throw new Error(`${label} must be canonical and must not traverse symlinks`);
  }
  if (absolute === tempRoot || !isWithin(tempRoot, absolute)) {
    throw new Error(`${label} must stay below RADAR_TEST_TEMP_ROOT`);
  }
  assertPrivateDirectoryChain(dirname(absolute), tempRoot, label);
  return absolute;
}

function assertPrivateDirectory(path, label) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw new Error(`${label} must be an absolute directory path`);
  }
  const absolute = resolve(path);
  let stats;
  try {
    stats = lstatSync(absolute);
  } catch (error) {
    throw new Error(`${label} is unavailable: ${error.message}`);
  }
  const owner = typeof process.getuid === 'function' ? process.getuid() : null;
  if (
    path !== absolute ||
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (owner !== null && stats.uid !== owner) ||
    (stats.mode & 0o077) !== 0 ||
    realpathSync.native(absolute) !== absolute
  ) {
    throw new Error(`${label} must be a private owner-controlled directory`);
  }
  return absolute;
}

function assertPrivateDirectoryChain(path, tempRoot, label) {
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

function assertPrivateRegularFile(path, label, { empty = false } = {}) {
  let stats;
  try {
    stats = lstatSync(path);
  } catch (error) {
    throw new Error(`${label} is unavailable: ${error.message}`);
  }
  const owner = typeof process.getuid === 'function' ? process.getuid() : null;
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
  if (empty && stats.size !== 0) {
    throw new Error(`${label} must be empty`);
  }
}

function assertSqliteDatabaseHeader(path, label) {
  const expected = Buffer.from('SQLite format 3\0', 'binary');
  const observed = Buffer.alloc(expected.length);
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  let bytesRead;
  try {
    bytesRead = readSync(descriptor, observed, 0, observed.length, 0);
  } finally {
    closeSync(descriptor);
  }
  if (bytesRead !== expected.length || !observed.equals(expected)) {
    throw new Error(`${label} must contain an initialized SQLite database`);
  }
}

function pathEntryExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function loadDatabaseGuardPolicy(runId) {
  const policyPath = process.env.RADAR_TEST_DATABASE_GUARD_POLICY;
  const policyDigest = process.env.RADAR_TEST_DATABASE_GUARD_POLICY_DIGEST;
  if (!policyPath) {
    if (
      policyDigest ||
      process.env.RADAR_TEST_SANDBOX_BACKEND ||
      process.env.RADAR_TEST_SANDBOX_PROFILE_DIGEST
    ) {
      throw new Error('Database guard policy environment is incomplete');
    }
    return legacyDatabaseGuardPolicy(runId);
  }
  if (process.env.RADAR_TEST_LIVE_DB !== undefined) {
    throw new Error(
      'Authoritative test children must not receive RADAR_TEST_LIVE_DB',
    );
  }
  if (!policyDigest) {
    throw new Error('Missing sealed database guard policy digest');
  }
  assertPrivateControlFile(policyPath, 'database guard policy');
  let policy;
  try {
    policy = JSON.parse(readFileSync(policyPath, 'utf8'));
  } catch (error) {
    throw new Error(`Database guard policy is not valid JSON: ${error.message}`);
  }
  assertExactRecordKeys(policy, [
    'allowedExecutables',
    'contentHash',
    'executableRoots',
    'kind',
    'liveDatabaseFamily',
    'repositoryRoot',
    'runId',
    'sandbox',
    'schemaVersion',
    'writableRoots',
  ], 'database guard policy');
  if (
    policy.schemaVersion !== 1 ||
    policy.kind !== 'authoritative-test-database-guard-policy' ||
    policy.runId !== runId
  ) {
    throw new Error('Database guard policy identity is invalid');
  }
  const { contentHash, ...content } = policy;
  const expectedHash = sha256Text(
    `authoritative-test-database-guard-policy-v1\0${canonicalJson(content)}`,
  );
  if (
    typeof contentHash !== 'string' ||
    contentHash !== expectedHash ||
    contentHash !== policyDigest
  ) {
    throw new Error('Database guard policy content seal is invalid');
  }
  policy.repositoryRoot = assertCanonicalPolicyPath(
    policy.repositoryRoot,
    'repository root',
  );
  policy.writableRoots = validatePolicyPaths(
    policy.writableRoots,
    'writable root',
  );
  policy.executableRoots = validatePolicyPaths(
    policy.executableRoots,
    'executable root',
  );
  if (
    policy.writableRoots.some((root) =>
      isWithin(root, canonicalizePath(policyPath)))
  ) {
    throw new Error('Database guard policy must be outside writable roots');
  }
  policy.liveDatabaseFamily = validateLiveDatabaseFamily(
    policy.liveDatabaseFamily,
  );
  policy.allowedExecutables = validateAllowedExecutables(
    policy.allowedExecutables,
  );
  policy.sandbox = validateSandboxPolicy(policy.sandbox);
  if (
    process.env.RADAR_TEST_SANDBOX_BACKEND !== policy.sandbox.backend ||
    process.env.RADAR_TEST_SANDBOX_PROFILE_DIGEST !==
      policy.sandbox.profileDigest
  ) {
    throw new Error('Database guard sandbox identity is not sealed to the run');
  }
  const allowedDatabaseRoots = parseStringArrayEnvironment(
    'RADAR_TEST_ALLOWED_DB_ROOTS',
  ).map((path) => canonicalizePath(path));
  if (
    allowedDatabaseRoots.some((allowedRoot) =>
      !policy.writableRoots.some((writableRoot) =>
        isWithin(writableRoot, allowedRoot)))
  ) {
    throw new Error(
      'Database guard database roots escape the sealed writable roots',
    );
  }
  return { ...policy, legacy: false, policyPath: canonicalizePath(policyPath) };
}

function legacyDatabaseGuardPolicy(runId) {
  const liveDatabase = canonicalizePath(requiredEnv('RADAR_TEST_LIVE_DB'));
  const writableRoots = parseStringArrayEnvironment(
    'RADAR_TEST_ALLOWED_DB_ROOTS',
  ).map((path) => canonicalizePath(path));
  const repositoryRoot = canonicalizePath(resolve(__dirname, '..'));
  const executableCandidates = [
    process.execPath,
    '/bin/bash',
    '/bin/chmod',
    '/bin/cp',
    '/bin/ls',
    '/bin/ps',
    '/bin/sh',
    '/bin/zsh',
    '/usr/bin/cc',
    '/usr/bin/env',
    '/usr/bin/git',
    '/usr/bin/id',
    '/usr/bin/nice',
    '/usr/bin/ps',
    '/usr/bin/tar',
    '/usr/bin/xattr',
    '/usr/sbin/iostat',
    '/usr/sbin/lsof',
    '/usr/sbin/taskpolicy',
  ];
  return {
    schemaVersion: 1,
    kind: 'legacy-test-database-guard-policy',
    runId,
    repositoryRoot,
    writableRoots,
    executableRoots: [
      ...writableRoots,
      canonicalizePath(join(repositoryRoot, 'node_modules')),
    ],
    allowedExecutables: executableCandidates
      .map((path) => fileIdentity(path))
      .filter((identity) => identity !== null),
    liveDatabaseFamily: [
      liveDatabase,
      `${liveDatabase}-wal`,
      `${liveDatabase}-shm`,
      `${liveDatabase}-journal`,
    ].map((path) => {
      const identity = databaseIdentity(path);
      return {
        path,
        exists: identity?.inode !== null,
        dev: identity?.inode?.split(':', 1)[0] ?? null,
        ino: identity?.inode?.split(':', 2)[1] ?? null,
      };
    }),
    sandbox: null,
    legacy: true,
    policyPath: null,
  };
}

function validateLiveDatabaseFamily(value) {
  if (!Array.isArray(value) || value.length !== 4) {
    throw new Error('Database guard policy must seal four SQLite family paths');
  }
  const members = value.map((member, index) => {
    assertExactRecordKeys(member, ['dev', 'exists', 'ino', 'path'],
      `live database family member ${index}`);
    const path = assertCanonicalPolicyPath(
      member.path,
      `live database family member ${index}`,
    );
    if (typeof member.exists !== 'boolean') {
      throw new Error('Live database family existence state is invalid');
    }
    const dev = normalizePolicyInodePart(member.dev, member.exists, 'dev');
    const ino = normalizePolicyInodePart(member.ino, member.exists, 'ino');
    return { path, exists: member.exists, dev, ino };
  });
  const expectedPaths = [
    members[0].path,
    `${members[0].path}-wal`,
    `${members[0].path}-shm`,
    `${members[0].path}-journal`,
  ];
  if (members.some((member, index) => member.path !== expectedPaths[index])) {
    throw new Error('Database guard policy SQLite family paths are malformed');
  }
  return members;
}

function validateAllowedExecutables(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('Database guard policy has no executable allowlist');
  }
  const identities = value.map((identity, index) => {
    assertExactRecordKeys(identity, ['dev', 'ino', 'mode', 'path', 'uid'],
      `allowed executable ${index}`);
    const path = assertCanonicalPolicyPath(
      identity.path,
      `allowed executable ${index}`,
    );
    const normalized = {
      path,
      dev: normalizePolicyInodePart(identity.dev, true, 'dev'),
      ino: normalizePolicyInodePart(identity.ino, true, 'ino'),
      mode: Number(identity.mode),
      uid: Number(identity.uid),
    };
    const observed = fileIdentity(path);
    if (
      observed === null ||
      !executableIdentityMatches(observed, normalized) ||
      observed.mode !== normalized.mode ||
      observed.uid !== normalized.uid ||
      (observed.mode & 0o111) === 0
    ) {
      throw new Error(`Allowed executable identity changed: ${path}`);
    }
    return normalized;
  });
  return identities;
}

function validateSandboxPolicy(value) {
  assertExactRecordKeys(value, ['backend', 'executable', 'profileDigest'],
    'sandbox policy');
  if (
    value.backend !== 'darwin-seatbelt-v1' ||
    !/^[0-9a-f]{64}$/.test(String(value.profileDigest))
  ) {
    throw new Error('Database guard sandbox policy is invalid');
  }
  assertExactRecordKeys(
    value.executable,
    ['dev', 'ino', 'mode', 'path', 'uid'],
    'sandbox executable identity',
  );
  const executable = {
    path: assertCanonicalPolicyPath(
      value.executable.path,
      'sandbox executable',
    ),
    dev: normalizePolicyInodePart(value.executable.dev, true, 'dev'),
    ino: normalizePolicyInodePart(value.executable.ino, true, 'ino'),
    mode: Number(value.executable.mode),
    uid: Number(value.executable.uid),
  };
  const observed = fileIdentity(executable.path);
  if (
    observed === null ||
    !executableIdentityMatches(observed, executable) ||
    observed.mode !== executable.mode ||
    observed.uid !== executable.uid
  ) {
    throw new Error('Database guard sandbox executable identity changed');
  }
  return {
    backend: value.backend,
    executable,
    profileDigest: String(value.profileDigest),
  };
}

function validatePolicyPaths(value, label) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`Database guard policy has no ${label}s`);
  }
  const paths = value.map((path, index) =>
    assertCanonicalPolicyPath(path, `${label} ${index}`));
  if (new Set(paths).size !== paths.length) {
    throw new Error(`Database guard policy contains duplicate ${label}s`);
  }
  return paths;
}

function assertCanonicalPolicyPath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value)) {
    throw new Error(`Database guard ${label} must be an absolute path`);
  }
  const canonical = canonicalizePath(value);
  if (canonical !== value) {
    throw new Error(`Database guard ${label} is not canonical: ${value}`);
  }
  return canonical;
}

function normalizePolicyInodePart(value, required, label) {
  if (!required && value === null) return null;
  const normalized = String(value);
  if (!/^[0-9]+$/.test(normalized)) {
    throw new Error(`Database guard policy ${label} is invalid`);
  }
  return normalized;
}

function assertPrivateControlFile(path, label) {
  const absolute = resolve(path);
  const stats = lstatSync(absolute);
  const parentStats = lstatSync(dirname(absolute));
  const owner = typeof process.getuid === 'function' ? process.getuid() : null;
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    !parentStats.isDirectory() ||
    parentStats.isSymbolicLink() ||
    (owner !== null && (stats.uid !== owner || parentStats.uid !== owner)) ||
    (stats.mode & 0o077) !== 0 ||
    (parentStats.mode & 0o077) !== 0 ||
    realpathSync.native(absolute) !== absolute
  ) {
    throw new Error(`${label} must be a private owner-controlled regular file`);
  }
}

function assertExactRecordKeys(value, expected, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(required)) {
    throw new Error(`${label} fields are not exactly sealed`);
  }
}

function parseStringArrayEnvironment(name) {
  let value;
  try {
    value = JSON.parse(requiredEnv(name));
  } catch (error) {
    throw new Error(`${name} must be a JSON string array: ${error.message}`);
  }
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((entry) => typeof entry !== 'string' || entry.length === 0)
  ) {
    throw new Error(`${name} must be a non-empty JSON string array`);
  }
  return value;
}

function assertKernelWriteBoundaryActive(policy) {
  if (policy.legacy === true) return;
  if (process.platform !== 'darwin' || policy.sandbox?.backend !== 'darwin-seatbelt-v1') {
    throw new Error('Authoritative database guard requires the macOS Seatbelt boundary');
  }
  const controlRoot = dirname(policy.policyPath);
  if (policy.writableRoots.some((root) => isWithin(root, controlRoot))) {
    throw new Error('Seatbelt control root overlaps a writable root');
  }
  const probePath = join(
    controlRoot,
    `.seatbelt-write-denial-${process.pid}-${Date.now()}`,
  );
  let descriptor = null;
  try {
    descriptor = openSync(
      probePath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
      0o600,
    );
  } catch (error) {
    if (error?.code === 'EACCES' || error?.code === 'EPERM') return;
    throw new Error(
      `Unable to prove the macOS deny-write boundary: ${error.message}`,
    );
  }
  try {
    throw new Error(
      'The authoritative child is not inside the sealed macOS deny-write boundary',
    );
  } finally {
    if (descriptor !== null) closeSync(descriptor);
    try {
      unlinkSync(probePath);
    } catch {
      // The boundary is already considered absent; preserve the primary error.
    }
  }
}

function assertLiveDatabaseMemberCurrent(member) {
  let stats = null;
  try {
    const pathStats = lstatSync(member.path);
    if (pathStats.isSymbolicLink() || !pathStats.isFile()) {
      throw new Error(
        `Live database family member is not a no-follow regular file: ${member.path}`,
      );
    }
    stats = statSync(member.path, { bigint: true });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  if (!member.exists) {
    if (stats !== null) {
      throw new Error(`Live database family member appeared before tests: ${member.path}`);
    }
    return;
  }
  if (
    stats === null ||
    String(stats.dev) !== String(member.dev) ||
    String(stats.ino) !== String(member.ino)
  ) {
    throw new Error(`Live database family identity changed before tests: ${member.path}`);
  }
}

function canonicalJson(value) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Canonical JSON cannot encode a non-finite number');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new Error(`Canonical JSON cannot encode ${typeof value}`);
}

function sha256Text(value) {
  return createHash('sha256').update(value).digest('hex');
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required test environment variable: ${name}`);
  return value;
}

function normalizeSpawnCall(args) {
  const [command, rawArgs, rawOptions] = args;
  if (Array.isArray(rawArgs)) {
    return {
      command,
      args: rawArgs,
      options: isOptions(rawOptions) ? rawOptions : {},
    };
  }
  return {
    command,
    args: [],
    options: isOptions(rawArgs) ? rawArgs : {},
  };
}

function normalizeForkCall(args) {
  const [modulePath, rawArgs, rawOptions] = args;
  if (Array.isArray(rawArgs)) {
    return {
      modulePath,
      args: rawArgs,
      options: isOptions(rawOptions) ? rawOptions : {},
    };
  }
  return {
    modulePath,
    args: [],
    options: isOptions(rawArgs) ? rawArgs : {},
  };
}

function normalizeExecCall(args) {
  const [, rawOptions, rawCallback] = args;
  if (typeof rawOptions === 'function') {
    return {
      command: args[0],
      options: {},
      callback: rawOptions,
    };
  }
  return {
    command: args[0],
    options: isOptions(rawOptions) ? rawOptions : {},
    callback: typeof rawCallback === 'function' ? rawCallback : undefined,
  };
}

function normalizeExecFileCall(args) {
  const [file, rawArgs, rawOptions, rawCallback] = args;
  if (Array.isArray(rawArgs)) {
    return {
      file,
      args: rawArgs,
      options: isOptions(rawOptions) ? rawOptions : {},
      callback: typeof rawOptions === 'function'
        ? rawOptions
        : typeof rawCallback === 'function'
          ? rawCallback
          : undefined,
    };
  }
  return {
    file,
    args: [],
    options: isOptions(rawArgs) ? rawArgs : {},
    callback: typeof rawArgs === 'function'
      ? rawArgs
      : typeof rawOptions === 'function'
        ? rawOptions
        : undefined,
  };
}

function isOptions(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function childCwd(options) {
  const value = options.cwd;
  if (value instanceof URL) return resolve(fileURLToPath(value));
  if (Buffer.isBuffer(value)) return resolve(value.toString());
  return value == null ? process.cwd() : resolve(String(value));
}

function parseEnvironmentAssignment(value) {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(String(value));
  return match === null ? null : { name: match[1], value: match[2] };
}

function snapshotArguments(values) {
  return values.map((value) => String(value));
}

function snapshotPathLike(value) {
  if (value instanceof URL) return new URL(value.href);
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  return String(value);
}

function snapshotWorkerFilename(value) {
  return value instanceof URL ? new URL(value.href) : String(value);
}

function tokenizeSqlStatements(source) {
  const statements = [];
  let statement = [];
  const pushStatement = () => {
    if (statement.length > 0) statements.push(statement);
    statement = [];
  };

  for (let index = 0; index < source.length;) {
    const character = source[index];
    if (/\s/.test(character)) {
      index++;
      continue;
    }
    if (character === '-' && source[index + 1] === '-') {
      index += 2;
      while (index < source.length && source[index] !== '\n') index++;
      continue;
    }
    if (character === '/' && source[index + 1] === '*') {
      const end = source.indexOf('*/', index + 2);
      if (end === -1) {
        throw new Error('Refusing unterminated SQLite block comment');
      }
      index = end + 2;
      continue;
    }
    if (character === "'") {
      index = skipSqlQuoted(source, index, "'", true);
      statement.push({ type: 'literal', value: 'LITERAL' });
      continue;
    }
    if (character === '"' || character === '`') {
      const end = skipSqlQuoted(source, index, character, true);
      statement.push({
        type: 'identifier',
        value: source.slice(index + 1, end - 1).toUpperCase(),
      });
      index = end;
      continue;
    }
    if (character === '[') {
      const end = source.indexOf(']', index + 1);
      if (end === -1) {
        throw new Error('Refusing unterminated SQLite bracket identifier');
      }
      statement.push({
        type: 'identifier',
        value: source.slice(index + 1, end).toUpperCase(),
      });
      index = end + 1;
      continue;
    }
    if (character === ';') {
      statement.push({ type: 'symbol', value: ';' });
      pushStatement();
      index++;
      continue;
    }
    const word = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(source.slice(index));
    if (word !== null) {
      statement.push({ type: 'word', value: word[0].toUpperCase() });
      index += word[0].length;
      continue;
    }
    const number = /^\d+/.exec(source.slice(index));
    if (number !== null) {
      statement.push({ type: 'number', value: number[0] });
      index += number[0].length;
      continue;
    }
    statement.push({ type: 'symbol', value: character });
    index++;
  }
  pushStatement();
  return statements;
}

function skipSqlQuoted(source, start, quote, doubledEscape) {
  for (let index = start + 1; index < source.length; index++) {
    if (source[index] !== quote) continue;
    if (doubledEscape && source[index + 1] === quote) {
      index++;
      continue;
    }
    return index + 1;
  }
  throw new Error(`Refusing unterminated SQLite ${quote} quote`);
}

function tokenizeShell(source, environment) {
  const tokens = [];
  let current = '';
  let active = false;
  let quote = null;
  let unsafe = false;

  function finishWord() {
    if (!active) return;
    tokens.push(current);
    current = '';
    active = false;
  }

  function appendEnvironment(name) {
    current += environment[name] === undefined ? '' : String(environment[name]);
    active = true;
  }

  for (let index = 0; index < source.length; index++) {
    const character = source[index];
    if (quote === "'") {
      if (character === "'") quote = null;
      else current += character;
      active = true;
      continue;
    }
    if (quote === '"') {
      if (character === '"') {
        quote = null;
        continue;
      }
      if (character === '\\') {
        const next = source[index + 1];
        if (next !== undefined && ['$', '`', '"', '\\', '\n'].includes(next)) {
          current += next === '\n' ? '' : next;
          index++;
          active = true;
          continue;
        }
      }
      if (character === '$') {
        const expansion = readEnvironmentExpansion(source, index);
        if (expansion === null) {
          unsafe = true;
          current += character;
        } else {
          appendEnvironment(expansion.name);
          index = expansion.end;
        }
        continue;
      }
      if (character === '`') unsafe = true;
      current += character;
      active = true;
      continue;
    }

    if (character === "'" || character === '"') {
      quote = character;
      active = true;
      continue;
    }
    if (/\s/.test(character)) {
      finishWord();
      if (character === '\n') tokens.push(null);
      continue;
    }
    if (';&|()'.includes(character)) {
      finishWord();
      tokens.push(null);
      if (source[index + 1] === character && ['&', '|'].includes(character)) index++;
      continue;
    }
    if (character === '\\') {
      const next = source[index + 1];
      if (next === undefined) {
        unsafe = true;
      } else {
        current += next === '\n' ? '' : next;
        index++;
        active = true;
      }
      continue;
    }
    if (character === '$') {
      const expansion = readEnvironmentExpansion(source, index);
      if (expansion === null) {
        unsafe = true;
        current += character;
        active = true;
      } else {
        appendEnvironment(expansion.name);
        index = expansion.end;
      }
      continue;
    }
    if (character === '`' || ['*', '?', '[', ']', '{', '}'].includes(character)) {
      unsafe = true;
    }
    current += character;
    active = true;
  }

  if (quote !== null) unsafe = true;
  finishWord();
  return { tokens, unsafe };
}

function readEnvironmentExpansion(source, start) {
  const next = source[start + 1];
  if (next === '{') {
    const end = source.indexOf('}', start + 2);
    if (end === -1) return null;
    const name = source.slice(start + 2, end);
    return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)
      ? { name, end }
      : null;
  }
  const match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(source.slice(start + 1));
  if (match === null) return null;
  return { name: match[0], end: start + match[0].length };
}

function executableIdentity(command, environment, cwd) {
  if (typeof command !== 'string' || command === '') return null;
  if (command.includes('/') || (process.platform === 'win32' && command.includes('\\'))) {
    const identity =
      fileIdentity(isAbsolute(command) ? command : resolve(cwd, command));
    return identity !== null && (identity.mode & 0o111) !== 0
      ? identity
      : null;
  }

  const path = String(environment.PATH ?? process.env.PATH ?? '');
  for (const directory of path.split(delimiter)) {
    const candidate = resolve(directory || cwd, command);
    if (existsSync(candidate)) {
      const identity = fileIdentity(candidate);
      if (identity !== null && (identity.mode & 0o111) !== 0) return identity;
    }
  }
  return null;
}

function fileIdentity(path) {
  if (path == null) return null;
  try {
    const canonicalPath = realpathSync.native(String(path));
    const stat = statSync(canonicalPath, { bigint: true });
    const mode = Number(stat.mode & 0o7777n);
    if (!stat.isFile()) return null;
    return {
      path: canonicalPath,
      inode: `${stat.dev}:${stat.ino}`,
      mode,
      uid: Number(stat.uid),
    };
  } catch {
    return null;
  }
}

function trustedSystemExecutableIdentity(path) {
  const identity = fileIdentity(path);
  if (identity === null) return null;
  try {
    const stat = statSync(identity.path, { bigint: true });
    const mode = Number(stat.mode & 0o777n);
    const uid = Number(stat.uid);
    if (
      !stat.isFile() ||
      (
        process.platform !== 'win32' &&
        (uid !== 0 || (mode & 0o022) !== 0)
      )
    ) {
      return null;
    }
    return {
      ...identity,
      mode,
      uid,
    };
  } catch {
    return null;
  }
}

function exactFileIdentityMatches(left, right) {
  return left !== null &&
    right !== null &&
    left.path === right.path &&
    left.inode === right.inode &&
    left.mode === right.mode &&
    left.uid === right.uid;
}

function executableIdentityMatches(observed, allowed) {
  if (observed === null || allowed === null || allowed === undefined) {
    return false;
  }
  const allowedInode = allowed.inode ??
    (
      allowed.dev !== undefined && allowed.ino !== undefined
        ? `${allowed.dev}:${allowed.ino}`
        : null
    );
  return observed.path === allowed.path &&
    allowedInode !== null &&
    observed.inode === String(allowedInode);
}

function sameFile(left, right) {
  if (left === null || right === null) return false;
  return left.path === right.path || left.inode === right.inode;
}

function databaseIdentity(location, cwd = process.cwd()) {
  const path = resolveDatabaseLocation(location, cwd);
  if (path === null) return null;

  const canonicalPath = canonicalizePath(path);
  let inode = null;
  let dev = null;
  let ino = null;
  try {
    const stat = statSync(canonicalPath, { bigint: true });
    dev = String(stat.dev);
    ino = String(stat.ino);
    inode = `${dev}:${ino}`;
  } catch {
    // A new temporary database has no inode until SQLite creates it.
  }

  return { path: canonicalPath, inode, dev, ino };
}

function resolveDatabaseLocation(location, cwd = process.cwd()) {
  if (location instanceof URL) {
    if (location.protocol !== 'file:') return null;
    if (location.searchParams.get('mode') === 'memory') return null;
    return resolve(fileURLToPath(location));
  }

  let value = Buffer.isBuffer(location)
    ? location.toString()
    : typeof location === 'string'
      ? location
      : null;
  if (value === null || value === '' || value === ':memory:') return null;

  if (value.startsWith('file:')) {
    const sqliteLocation = value.slice('file:'.length);
    const queryIndex = sqliteLocation.search(/[?#]/);
    const sqlitePath = queryIndex === -1
      ? sqliteLocation
      : sqliteLocation.slice(0, queryIndex);
    const query = queryIndex === -1
      ? ''
      : sqliteLocation.slice(queryIndex + 1).split('#', 1)[0];
    const parameters = new URLSearchParams(query);
    if (sqlitePath === ':memory:' || parameters.get('mode') === 'memory') return null;
    if (sqlitePath.startsWith('//')) return resolve(fileURLToPath(new URL(value)));
    value = decodeURIComponent(sqlitePath);
  }

  return isAbsolute(value) ? resolve(value) : resolve(cwd, value);
}

function canonicalizePath(path) {
  const absolute = resolve(path);
  const suffix = [];
  let cursor = absolute;
  const root = parsePath(absolute).root;
  while (cursor !== root && !existsSync(cursor)) {
    suffix.unshift(basename(cursor));
    cursor = dirname(cursor);
  }
  const canonicalParent = realpathSync.native(cursor);
  return resolve(canonicalParent, ...suffix);
}

function inheritedWorkerExecArgv() {
  const result = [];
  for (let index = 0; index < process.execArgv.length; index++) {
    const argument = process.execArgv[index];
    if (['-e', '--eval', '-p', '--print'].includes(argument)) {
      index++;
      continue;
    }
    if (/^(?:--eval|--print)=/.test(argument)) continue;
    result.push(argument);
  }
  return result;
}

function isWithin(root, path) {
  return path === root || path.startsWith(`${root}${sep}`);
}

function sameDatabase(left, right) {
  return left.path === right.path ||
    (left.inode !== null && right.inode !== null && left.inode === right.inode);
}

function displayLocation(location) {
  if (location instanceof URL) return location.href;
  if (Buffer.isBuffer(location)) return location.toString();
  return String(location);
}
