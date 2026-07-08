import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
} from 'node:fs';
import {
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path';
import { fileURLToPath } from 'node:url';

const sourcePath = fileURLToPath(
  new URL('./process-io-darwin.c', import.meta.url),
);
const maximumPid = 0x7fffffff;
const maximumHelperBytes = 16 * 1024 * 1024;
const maximumCompileOutputBytes = 64 * 1024;
const maximumSampleOutputBytes = 4 * 1024 * 1024;
const compileTimeoutMs = 15_000;
const sampleTimeoutMs = 5_000;
const decimalPattern = /^(?:0|[1-9]\d*)$/;
const positiveDecimalPattern = /^[1-9]\d*$/;

export function initializeProcessGroupWriteAccounting({
  tempRoot,
  platform = process.platform,
  compilerPath = '/usr/bin/cc',
  run = spawnSync,
} = {}) {
  if (typeof platform !== 'string' || platform.length === 0) {
    throw new Error('Process write accounting platform must be a string.');
  }
  if (platform !== 'darwin') {
    return createUnsupportedAccounting(platform);
  }
  if (typeof run !== 'function') {
    throw new Error('Process write accounting run option must be a function.');
  }

  const privateTempRoot = assertPrivateDirectory(tempRoot, 'temporary root');
  const compiler = assertCompilerPath(compilerPath);
  const sealedSource = captureRepositorySourceIdentity(sourcePath);
  const helperDirectory = mkdtempSync(
    join(privateTempRoot, '.process-io-darwin-'),
  );

  try {
    chmodSync(helperDirectory, 0o700);
    const sealedDirectory = capturePrivateDirectoryIdentity(
      helperDirectory,
      'helper directory',
    );
    const temporaryHelperPath = join(
      helperDirectory,
      `.process-io-darwin.${process.pid}.${randomUUID()}.tmp`,
    );
    const helperPath = join(helperDirectory, 'process-io-darwin');

    const compileResult = invokeBounded(run, compiler, [
      '-std=c11',
      '-O2',
      '-Wall',
      '-Wextra',
      '-Werror',
      sealedSource.canonicalPath,
      '-o',
      temporaryHelperPath,
    ], {
      label: 'compile Darwin process write accounting helper',
      cwd: helperDirectory,
      timeout: compileTimeoutMs,
      maximumOutputBytes: maximumCompileOutputBytes,
    });
    assertSuccessfulInvocation(
      compileResult,
      'compile Darwin process write accounting helper',
    );
    assertRepositorySourceIdentity(sourcePath, sealedSource);

    assertPrivateDirectoryIdentity(
      helperDirectory,
      sealedDirectory,
      'helper directory',
    );
    assertAtomicCompilerOutput(temporaryHelperPath, helperDirectory);
    chmodSync(temporaryHelperPath, 0o700);
    fsyncFile(temporaryHelperPath);
    renameSync(temporaryHelperPath, helperPath);
    fsyncDirectory(helperDirectory);

    const sealedHelper = captureExecutableIdentity(helperPath);
    assertHelperWithinDirectory(
      sealedHelper.canonicalPath,
      sealedDirectory.canonicalPath,
    );
    assertPrivateDirectoryIdentity(
      helperDirectory,
      sealedDirectory,
      'helper directory',
    );

    const smokeResult = runSealedHelper({
      run,
      helperPath,
      sealedHelper,
      helperDirectory,
      sealedDirectory,
      args: ['--self-check'],
      label: 'smoke-sample Darwin process write accounting helper',
    });
    const smokeRows = parseHelperSnapshot(smokeResult.stdout, null);
    if (smokeRows.length === 0) {
      throw new Error(
        'Darwin process write accounting helper self-check returned no process.',
      );
    }

    return createDarwinAccounting({
      platform,
      helperPath,
      sealedHelper,
      helperDirectory,
      sealedDirectory,
      sourceDigest: sealedSource.digest,
      run,
    });
  } catch (error) {
    rmSync(helperDirectory, { recursive: true, force: true });
    throw error;
  }
}

function createUnsupportedAccounting(platform) {
  let activeProcessGroupPid = null;
  return {
    supported: false,
    platform,
    helperPath: null,
    sample(processGroupPid) {
      activeProcessGroupPid = validateProcessGroupPid(processGroupPid);
      return snapshot();
    },
    snapshot,
  };

  function snapshot() {
    return {
      schemaVersion: 1,
      platform,
      supported: false,
      currentBytes: 0,
      peakBytes: 0,
      observedProcessCount: 0,
      sampledProcessCount: 0,
      activeProcessGroupPid,
      topWriters: [],
    };
  }
}

function createDarwinAccounting({
  platform,
  helperPath,
  sealedHelper,
  helperDirectory,
  sealedDirectory,
  sourceDigest,
  run,
}) {
  const writers = new Map();
  let currentBytes = 0n;
  let peakBytes = 0n;
  let sampledProcessCount = 0n;
  let activeProcessGroupPid = null;

  return {
    supported: true,
    platform,
    helperPath,
    sample(processGroupPid) {
      const validatedPid = validateProcessGroupPid(processGroupPid);
      assertPrivateDirectoryIdentity(
        helperDirectory,
        sealedDirectory,
        'helper directory',
      );
      assertExecutableIdentity(helperPath, sealedHelper);
      if (validatedPid === null) {
        activeProcessGroupPid = null;
        return snapshot();
      }

      const result = runSealedHelper({
        run,
        helperPath,
        sealedHelper,
        helperDirectory,
        sealedDirectory,
        args: [String(validatedPid)],
        label: `sample process group ${validatedPid}`,
      });
      const rows = parseHelperSnapshot(result.stdout, validatedPid);
      const updates = prepareWriterUpdates(writers, rows);
      let chargedBytes = 0n;
      for (const update of updates) {
        chargedBytes += update.delta;
      }
      const nextCurrentBytes = currentBytes + chargedBytes;
      const nextSampledProcessCount =
        sampledProcessCount + BigInt(rows.length);

      for (const update of updates) {
        writers.set(update.identity, update.writer);
      }
      currentBytes = nextCurrentBytes;
      if (currentBytes > peakBytes) peakBytes = currentBytes;
      sampledProcessCount = nextSampledProcessCount;
      activeProcessGroupPid = validatedPid;
      return snapshot();
    },
    snapshot,
  };

  function snapshot() {
    const topWriters = [...writers.values()]
      .sort(compareWriters)
      .slice(0, 10)
      .map((writer) => ({
        pid: writer.pid,
        processStartAbstime: writer.processStartAbstime,
        processName: writer.processName,
        bytesWritten: safeInteger(
          writer.bytesWritten,
          `bytes written by process ${writer.pid}`,
        ),
      }));
    return {
      schemaVersion: 1,
      platform,
      supported: true,
      helperDigest: sealedHelper.digest,
      sourceDigest,
      currentBytes: safeInteger(currentBytes, 'current bytes written'),
      peakBytes: safeInteger(peakBytes, 'peak bytes written'),
      observedProcessCount: safeInteger(
        BigInt(writers.size),
        'observed process count',
      ),
      sampledProcessCount: safeInteger(
        sampledProcessCount,
        'sampled process count',
      ),
      activeProcessGroupPid,
      topWriters,
    };
  }
}

function prepareWriterUpdates(writers, rows) {
  const identities = new Set();
  return rows.map((row) => {
    const identity = `${row.pid}:${row.processStartAbstime}`;
    if (identities.has(identity)) {
      throw new Error(`Duplicate process identity in helper output: ${identity}`);
    }
    identities.add(identity);

    const previous = writers.get(identity);
    if (previous && row.rawBytesWritten < previous.rawBytesWritten) {
      throw new Error(
        `Process write counter regressed for ${identity}: ` +
        `${row.rawBytesWritten} < ${previous.rawBytesWritten}.`,
      );
    }
    const delta = previous
      ? row.rawBytesWritten - previous.rawBytesWritten
      : row.rawBytesWritten;
    return {
      identity,
      delta,
      writer: {
        pid: row.pid,
        processStartAbstime: row.processStartAbstime,
        processName: row.processName,
        rawBytesWritten: row.rawBytesWritten,
        bytesWritten: (previous?.bytesWritten ?? 0n) + delta,
      },
    };
  });
}

function compareWriters(left, right) {
  if (left.bytesWritten !== right.bytesWritten) {
    return left.bytesWritten > right.bytesWritten ? -1 : 1;
  }
  if (left.pid !== right.pid) return left.pid - right.pid;
  return left.processStartAbstime.localeCompare(right.processStartAbstime);
}

function parseHelperSnapshot(output, expectedProcessGroupPid) {
  let parsed;
  try {
    parsed = JSON.parse(String(output));
  } catch (error) {
    throw new Error(
      `Darwin process write accounting helper emitted malformed JSON: ` +
      `${normalizeError(error).message}`,
    );
  }
  if (
    !isPlainObject(parsed) ||
    !hasExactKeys(parsed, [
      'processGroupPid',
      'processes',
      'schemaVersion',
    ]) ||
    parsed.schemaVersion !== 1 ||
    !Number.isInteger(parsed.processGroupPid) ||
    parsed.processGroupPid <= 0 ||
    parsed.processGroupPid > maximumPid ||
    !Array.isArray(parsed.processes) ||
    parsed.processes.length > 131072
  ) {
    throw new Error(
      'Darwin process write accounting helper snapshot is malformed.',
    );
  }
  if (
    expectedProcessGroupPid !== null &&
    parsed.processGroupPid !== expectedProcessGroupPid
  ) {
    throw new Error(
      `Darwin process write accounting helper returned process group ` +
      `${parsed.processGroupPid}; expected ${expectedProcessGroupPid}.`,
    );
  }
  return parsed.processes.map((row, index) => parseHelperRow(row, index));
}

function parseHelperRow(row, index) {
  if (
    !isPlainObject(row) ||
    !hasExactKeys(row, [
      'pid',
      'processName',
      'ri_diskio_byteswritten',
      'ri_proc_start_abstime',
    ]) ||
    !Number.isInteger(row.pid) ||
    row.pid <= 0 ||
    row.pid > maximumPid ||
    typeof row.ri_proc_start_abstime !== 'string' ||
    !positiveDecimalPattern.test(row.ri_proc_start_abstime) ||
    typeof row.ri_diskio_byteswritten !== 'string' ||
    !decimalPattern.test(row.ri_diskio_byteswritten) ||
    typeof row.processName !== 'string' ||
    Buffer.byteLength(row.processName, 'utf8') > 192
  ) {
    throw new Error(
      `Darwin process write accounting helper row ${index} is malformed.`,
    );
  }
  return {
    pid: row.pid,
    processStartAbstime: row.ri_proc_start_abstime,
    processName: row.processName,
    rawBytesWritten: BigInt(row.ri_diskio_byteswritten),
  };
}

function runSealedHelper({
  run,
  helperPath,
  sealedHelper,
  helperDirectory,
  sealedDirectory,
  args,
  label,
}) {
  assertPrivateDirectoryIdentity(
    helperDirectory,
    sealedDirectory,
    'helper directory',
  );
  assertExecutableIdentity(helperPath, sealedHelper);
  const result = invokeBounded(run, helperPath, args, {
    label,
    cwd: helperDirectory,
    timeout: sampleTimeoutMs,
    maximumOutputBytes: maximumSampleOutputBytes,
  });
  assertSuccessfulInvocation(result, label);
  assertPrivateDirectoryIdentity(
    helperDirectory,
    sealedDirectory,
    'helper directory',
  );
  assertExecutableIdentity(helperPath, sealedHelper);
  return result;
}

function invokeBounded(run, command, args, {
  label,
  cwd,
  timeout,
  maximumOutputBytes,
}) {
  let result;
  try {
    result = run(command, args, {
      cwd,
      encoding: 'utf8',
      env: {
        ...process.env,
        LC_ALL: 'C',
        LANG: 'C',
      },
      maxBuffer: maximumOutputBytes,
      timeout,
      windowsHide: true,
    });
  } catch (error) {
    throw new Error(`${label} failed: ${normalizeError(error).message}`);
  }
  if (!result || typeof result !== 'object') {
    throw new Error(`${label} returned no process result.`);
  }
  const stdout = normalizeOutput(result.stdout);
  const stderr = normalizeOutput(result.stderr);
  if (
    Buffer.byteLength(stdout) > maximumOutputBytes ||
    Buffer.byteLength(stderr) > maximumOutputBytes
  ) {
    throw new Error(`${label} exceeded the ${maximumOutputBytes}-byte limit.`);
  }
  return {
    ...result,
    stdout,
    stderr,
  };
}

function assertSuccessfulInvocation(result, label) {
  if (result.error) {
    throw new Error(`${label} failed: ${normalizeError(result.error).message}`);
  }
  if (result.signal !== null && result.signal !== undefined) {
    throw new Error(`${label} was terminated by signal ${result.signal}.`);
  }
  if (result.status !== 0) {
    const detail = result.stderr.trim();
    throw new Error(
      `${label} exited with status ${String(result.status)}` +
      `${detail ? `: ${detail}` : '.'}`,
    );
  }
}

function assertAtomicCompilerOutput(path, helperDirectory) {
  assertPathWithin(path, helperDirectory, 'temporary helper');
  const stats = lstatSync(path, { bigint: true });
  if (
    stats.isSymbolicLink() ||
    !stats.isFile() ||
    stats.nlink !== 1n ||
    stats.size <= 0n ||
    stats.size > BigInt(maximumHelperBytes) ||
    stats.uid !== currentUid()
  ) {
    throw new Error('Compiler output is not a private regular helper file.');
  }
  if (realpathSync(path) !== resolve(path)) {
    throw new Error('Compiler output path is not canonical.');
  }
}

function captureRepositorySourceIdentity(path) {
  const before = lstatSync(path, { bigint: true });
  const canonicalPath = realpathSync(path);
  if (
    canonicalPath !== resolve(path) ||
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.nlink < 1n ||
    before.size <= 0n ||
    before.size > BigInt(maximumHelperBytes) ||
    before.uid !== currentUid()
  ) {
    throw new Error(
      'Darwin process write accounting source is not a repository-owned file.',
    );
  }
  const descriptor = openNoFollow(path);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (!sameFileStats(opened, before)) {
      throw new Error(
        'Darwin process write accounting source changed while opening.',
      );
    }
    const digest = digestDescriptor(descriptor, opened.size);
    const after = lstatSync(path, { bigint: true });
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      !sameFileStats(after, opened) ||
      realpathSync(path) !== canonicalPath
    ) {
      throw new Error(
        'Darwin process write accounting source changed while hashing.',
      );
    }
    return {
      canonicalPath,
      device: String(opened.dev),
      inode: String(opened.ino),
      uid: String(opened.uid),
      mode: Number(opened.mode & 0o777n),
      size: String(opened.size),
      modificationTime: String(opened.mtimeNs),
      changeTime: String(opened.ctimeNs),
      digest,
    };
  } finally {
    closeSync(descriptor);
  }
}

function assertRepositorySourceIdentity(path, expected) {
  const actual = captureRepositorySourceIdentity(path);
  if (
    actual.canonicalPath !== expected.canonicalPath ||
    actual.device !== expected.device ||
    actual.inode !== expected.inode ||
    actual.uid !== expected.uid ||
    actual.mode !== expected.mode ||
    actual.size !== expected.size ||
    actual.modificationTime !== expected.modificationTime ||
    actual.changeTime !== expected.changeTime ||
    actual.digest !== expected.digest
  ) {
    throw new Error(
      'Darwin process write accounting source changed during compilation.',
    );
  }
}

function assertCompilerPath(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw new Error('Darwin process write accounting compiler path is invalid.');
  }
  const canonicalPath = realpathSync(path);
  const stats = lstatSync(path, { bigint: true });
  const mode = Number(stats.mode & 0o777n);
  if (
    canonicalPath !== resolve(path) ||
    stats.isSymbolicLink() ||
    !stats.isFile() ||
    (mode & 0o111) === 0
  ) {
    throw new Error('Darwin process write accounting compiler is not executable.');
  }
  return canonicalPath;
}

function assertPrivateDirectory(path, label) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw new Error(`Process write accounting ${label} must be absolute.`);
  }
  const stats = lstatSync(path);
  if (stats.isSymbolicLink()) {
    throw new Error(
      `Process write accounting ${label} must not be a symbolic link.`,
    );
  }
  return capturePrivateDirectoryIdentity(realpathSync(path), label)
    .canonicalPath;
}

function capturePrivateDirectoryIdentity(path, label) {
  const stats = lstatSync(path, { bigint: true });
  const canonicalPath = realpathSync(path);
  const mode = Number(stats.mode & 0o777n);
  if (
    canonicalPath !== resolve(path) ||
    stats.isSymbolicLink() ||
    !stats.isDirectory() ||
    stats.uid !== currentUid() ||
    (mode & 0o077) !== 0
  ) {
    throw new Error(
      `Process write accounting ${label} must be canonical, owner-private, ` +
      `and owned by the current user.`,
    );
  }
  return {
    canonicalPath,
    device: String(stats.dev),
    inode: String(stats.ino),
    uid: String(stats.uid),
    mode,
  };
}

function assertPrivateDirectoryIdentity(path, expected, label) {
  const actual = capturePrivateDirectoryIdentity(path, label);
  if (
    actual.canonicalPath !== expected.canonicalPath ||
    actual.device !== expected.device ||
    actual.inode !== expected.inode ||
    actual.uid !== expected.uid ||
    actual.mode !== expected.mode
  ) {
    throw new Error(`Process write accounting ${label} identity changed.`);
  }
}

function captureExecutableIdentity(path) {
  const before = lstatSync(path, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile()) {
    throw new Error('Process write accounting helper is not a regular file.');
  }
  const canonicalPath = realpathSync(path);
  if (canonicalPath !== resolve(path)) {
    throw new Error('Process write accounting helper path is not canonical.');
  }
  const descriptor = openNoFollow(path);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    assertPrivateExecutableStats(opened);
    if (!sameFileStats(opened, before)) {
      throw new Error('Process write accounting helper changed while opening.');
    }
    const digest = digestDescriptor(descriptor, opened.size);
    const after = lstatSync(path, { bigint: true });
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      !sameFileStats(after, opened) ||
      realpathSync(path) !== canonicalPath
    ) {
      throw new Error('Process write accounting helper changed while hashing.');
    }
    return {
      canonicalPath,
      device: String(opened.dev),
      inode: String(opened.ino),
      uid: String(opened.uid),
      mode: Number(opened.mode & 0o777n),
      size: String(opened.size),
      modificationTime: String(opened.mtimeNs),
      changeTime: String(opened.ctimeNs),
      digest,
    };
  } finally {
    closeSync(descriptor);
  }
}

function assertExecutableIdentity(path, expected) {
  let actual;
  try {
    actual = captureExecutableIdentity(path);
  } catch (error) {
    throw new Error(
      `Process write accounting helper integrity check failed: ` +
      `${normalizeError(error).message}`,
    );
  }
  if (
    actual.canonicalPath !== expected.canonicalPath ||
    actual.device !== expected.device ||
    actual.inode !== expected.inode ||
    actual.uid !== expected.uid ||
    actual.mode !== expected.mode ||
    actual.size !== expected.size ||
    actual.modificationTime !== expected.modificationTime ||
    actual.changeTime !== expected.changeTime ||
    actual.digest !== expected.digest
  ) {
    throw new Error(
      'Process write accounting helper was deleted, replaced, or modified.',
    );
  }
}

function assertPrivateExecutableStats(stats) {
  const mode = Number(stats.mode & 0o777n);
  if (
    !stats.isFile() ||
    stats.nlink !== 1n ||
    stats.uid !== currentUid() ||
    mode !== 0o700 ||
    stats.size <= 0n ||
    stats.size > BigInt(maximumHelperBytes)
  ) {
    throw new Error(
      'Process write accounting helper must be a private owner executable.',
    );
  }
}

function sameFileStats(left, right) {
  return left.dev === right.dev &&
    left.ino === right.ino &&
    left.uid === right.uid &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

function digestDescriptor(descriptor, expectedSize) {
  if (expectedSize > BigInt(maximumHelperBytes)) {
    throw new Error('Process write accounting helper exceeds its size limit.');
  }
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let bytesReadTotal = 0n;
  while (true) {
    const bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    bytesReadTotal += BigInt(bytesRead);
    if (bytesReadTotal > BigInt(maximumHelperBytes)) {
      throw new Error('Process write accounting helper grew while hashing.');
    }
    hash.update(buffer.subarray(0, bytesRead));
  }
  if (bytesReadTotal !== expectedSize) {
    throw new Error('Process write accounting helper size changed while hashing.');
  }
  return hash.digest('hex');
}

function openNoFollow(path) {
  if (!Number.isInteger(fsConstants.O_NOFOLLOW)) {
    throw new Error('O_NOFOLLOW is unavailable for helper integrity checks.');
  }
  return openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
}

function fsyncFile(path) {
  const descriptor = openNoFollow(path);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function assertHelperWithinDirectory(helperPath, helperDirectory) {
  assertPathWithin(helperPath, helperDirectory, 'installed helper');
}

function assertPathWithin(path, directory, label) {
  const pathRelativeToDirectory = relative(resolve(directory), resolve(path));
  if (
    pathRelativeToDirectory === '' ||
    pathRelativeToDirectory === '..' ||
    pathRelativeToDirectory.startsWith('../') ||
    pathRelativeToDirectory.startsWith('..\\') ||
    isAbsolute(pathRelativeToDirectory)
  ) {
    throw new Error(`Process write accounting ${label} escaped its directory.`);
  }
}

function validateProcessGroupPid(processGroupPid) {
  if (processGroupPid === null) return null;
  if (
    !Number.isSafeInteger(processGroupPid) ||
    processGroupPid <= 0 ||
    processGroupPid > maximumPid
  ) {
    throw new Error('Process group PID must be a positive pid_t or null.');
  }
  return processGroupPid;
}

function safeInteger(value, label) {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label} cannot be represented as a safe JSON integer.`);
  }
  return Number(value);
}

function currentUid() {
  if (typeof process.getuid !== 'function') {
    throw new Error('Current user identity is unavailable.');
  }
  return BigInt(process.getuid());
}

function normalizeOutput(value) {
  if (value === null || value === undefined) return '';
  return Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
}

function normalizeError(error) {
  return error instanceof Error ? error : new Error(String(error));
}

function isPlainObject(value) {
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null);
}

function hasExactKeys(value, expectedKeys) {
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  return actualKeys.length === sortedExpectedKeys.length &&
    actualKeys.every((key, index) => key === sortedExpectedKeys[index]);
}
