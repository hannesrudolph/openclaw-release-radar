import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const repositoryRoot = resolve(import.meta.dirname, '..');
const guardRuntimePath = join(repositoryRoot, 'test', 'database-guard-runtime.cjs');
const childProbePath = join(repositoryRoot, 'test', 'database-guard-child-probe.cjs');
const root = mkdtempSync(join(tmpdir(), 'openclaw-database-guard-self-test-'));
const outsideRoot = mkdtempSync(join(tmpdir(), 'openclaw-database-guard-outside-'));
const workerRoot = join(root, 'worker');
const processLockRoot = join(root, 'locks');
const liveDatabase = join(root, 'live.db');
const safeDatabase = join(workerRoot, 'safe.db');
const childDatabase = join(workerRoot, 'child.db');
const safeBackup = join(workerRoot, 'safe-backup.db');
const safeCopy = join(workerRoot, 'safe-copy.db');
const copiedLiveDatabase = join(workerRoot, 'copied-live.db');
const copiedLiveTree = join(workerRoot, 'copied-live-tree');
const siblingDatabase = join(root, 'sibling.db');
const sqlDestination = join(workerRoot, 'sql-destination.db');
const outsideDatabase = join(outsideRoot, 'outside.db');
const symlinkAlias = join(root, 'live-symlink.db');
const hardlinkAlias = join(root, 'live-hardlink.db');
const danglingWalAlias = join(root, 'live-wal-symlink.db');
const memoryAlias = join(root, ':memory:alias');
const sqliteAlias = join(root, 'sqlite3');
const childOperandMarker = join(workerRoot, 'child-operand-launched');
const childOperandShellScript = join(workerRoot, 'child-operand-probe.sh');
const auditPath = join(root, 'audit.jsonl');
const emptyDotenvPath = join(root, 'empty.env');
const runId = `database-guard-self-test-${process.pid}`;

try {
  mkdirSync(workerRoot, { recursive: true });
  mkdirSync(processLockRoot, { recursive: true });
  initializeDatabase(liveDatabase);
  initializeDatabase(safeDatabase);
  initializeDatabase(childDatabase);
  initializeDatabase(siblingDatabase);
  symlinkSync(liveDatabase, symlinkAlias);
  linkSync(liveDatabase, hardlinkAlias);
  symlinkSync(`${liveDatabase}-wal`, danglingWalAlias);
  symlinkSync(liveDatabase, memoryAlias);
  symlinkSync(process.execPath, sqliteAlias);
  appendFileSync(
    childOperandShellScript,
    '#!/bin/sh\nprintf launched > "$CHILD_OPERAND_MARKER"\n',
  );
  chmodSync(childOperandShellScript, 0o700);
  appendFileSync(auditPath, '');
  appendFileSync(emptyDotenvPath, '');

  const baseEnv = {
    ...process.env,
    DB_PATH: safeDatabase,
    DOTENV_CONFIG_PATH: emptyDotenvPath,
    NODE_OPTIONS: `--require=${guardRuntimePath}`,
    RADAR_CODE_REVISION: 'database-guard-self-test',
    RADAR_TEST_ALLOWED_DB_ROOTS: JSON.stringify([root, processLockRoot]),
    RADAR_TEST_CODE_REVISION: 'database-guard-self-test',
    RADAR_TEST_DB_AUDIT: auditPath,
    RADAR_TEST_LIVE_DB: liveDatabase,
    RADAR_TEST_PROCESS_LOCK_ROOT: processLockRoot,
    RADAR_TEST_RUN_ID: runId,
    RADAR_TEST_SQLITE_MAX_MIB: '128',
    RADAR_TEST_TEMP_ROOT: workerRoot,
    RADAR_TEST_WORKER_DB_PATH: safeDatabase,
    SQLITE_TMPDIR: workerRoot,
    TEMP: workerRoot,
    TMP: workerRoot,
    TMPDIR: workerRoot,
  };

  assertSuccess(
    'private temporary database',
    runNode(sqliteOpenSource(), {
      ...baseEnv,
      TARGET_DATABASE: safeDatabase,
    }),
  );
  assertProbe('direct live path', liveDatabase, false, baseEnv);
  assertProbe(
    'file URI live path',
    `${pathToFileURL(liveDatabase).href}?mode=rw`,
    false,
    baseEnv,
  );
  assertProbe('symlink alias', symlinkAlias, false, baseEnv);
  assertProbe('hardlink alias', hardlinkAlias, false, baseEnv);
  assertProbe('file::memory disk alias', 'file::memory:alias', false, baseEnv);
  for (const [label, source] of [
    ['copy direct live database source', liveDatabase],
    ['copy live database symlink source', symlinkAlias],
    ['copy live database hardlink source', hardlinkAlias],
  ]) {
    assertCopySourceFailure(
      label,
      source,
      copiedLiveDatabase,
      false,
      baseEnv,
    );
  }
  assertCopySourceFailure(
    'recursive copy source containing live database',
    root,
    copiedLiveTree,
    true,
    baseEnv,
  );
  assertCopySourceSuccess(
    'copy private temporary database source',
    safeDatabase,
    safeCopy,
    baseEnv,
  );
  assertFailure(
    'database outside isolated root',
    runNode(sqliteOpenSource(), {
      ...baseEnv,
      TARGET_DATABASE: outsideDatabase,
    }),
    /Refusing to open a database outside the test roots/,
  );

  assertSuccess(
    'backup inside isolated root',
    runNode(sqliteBackupSource(), {
      ...baseEnv,
      TARGET_DATABASE: safeBackup,
    }),
  );
  assertBackupFailure('backup direct live path', liveDatabase, baseEnv);
  assertBackupFailure('backup symlink live path', symlinkAlias, baseEnv);
  assertFailure(
    'backup outside isolated root',
    runNode(sqliteBackupSource(), {
      ...baseEnv,
      TARGET_DATABASE: outsideDatabase,
    }),
    /Refusing to open a database outside the test roots/,
  );

  assertWorkerFailure('worker direct live path', liveDatabase, baseEnv);
  assertWorkerFailure('worker symlink live path', symlinkAlias, baseEnv);
  assertFailure(
    'worker cannot leave its assigned database root',
    runNode(workerSqliteOpenSource(), {
      ...baseEnv,
      TARGET_DATABASE: siblingDatabase,
    }),
    /Refusing to open a database outside the test roots/,
  );
  assertFailure(
    'worker environment cannot replace its assigned database',
    runNode(workerEnvironmentOverrideSource(), {
      ...baseEnv,
      TARGET_DATABASE: liveDatabase,
    }),
    /worker environment must use the current guarded database path/,
  );
  assertSuccess(
    'nested worker follows the current child database inside its assigned root',
    runNode(workerSqliteOpenSource(), {
      ...baseEnv,
      DB_PATH: childDatabase,
      TARGET_DATABASE: childDatabase,
    }),
  );
  assertFailure(
    'recovered Worker constructor remains guarded',
    runNode(recoveredWorkerConstructorSource(), {
      ...baseEnv,
      TARGET_DATABASE: liveDatabase,
    }),
    /worker environment removed or replaced protected/,
  );
  assertSuccess(
    'worker receives a validated environment snapshot',
    runNode(hostileWorkerEnvironmentSource(), {
      ...baseEnv,
      TARGET_DATABASE: liveDatabase,
    }),
  );
  assertFailure(
    'nested Node child live path',
    runNode(nestedChildSource(false), {
      ...baseEnv,
      CHILD_PROBE: childProbePath,
      TARGET_DATABASE: liveDatabase,
    }),
    /Refusing to open the live database/,
  );
  assertFailure(
    'nested child cannot remove guard environment',
    runNode(nestedChildSource(true), {
      ...baseEnv,
      CHILD_PROBE: childProbePath,
      TARGET_DATABASE: liveDatabase,
    }),
    /Refusing spawnSync child process during tests/,
  );
  assertFailure(
    'ordinary guarded child cannot mint database policy probe capability',
    runNode(databasePolicyProbeMintSource(), baseEnv),
    /cannot mint database policy probe capability/,
  );
  assertFailure(
    'ordinary guarded child cannot mint database policy probe authority',
    runNode(databasePolicyProbeAuthorityMintSource(), baseEnv),
    /cannot mint database policy probe authority/,
  );
  assertSuccess(
    'child receives a validated environment snapshot',
    runNode(hostileChildEnvironmentSource(), {
      ...baseEnv,
      CHILD_PROBE: childProbePath,
      TARGET_DATABASE: liveDatabase,
    }),
  );
  assertSuccess(
    'child receives a validated options snapshot',
    runNode(hostileChildOptionsSource(), {
      ...baseEnv,
      CHILD_PROBE: childProbePath,
      TARGET_DATABASE: liveDatabase,
    }),
  );
  assertFailure(
    'recovered child-process function remains guarded',
    runNode(recoveredChildFunctionSource(), {
      ...baseEnv,
      CHILD_PROBE: childProbePath,
      TARGET_DATABASE: liveDatabase,
    }),
    /child environment removed or replaced protected/,
  );
  for (const [label, operands, cwd = root] of [
    ['direct live database operand', [liveDatabase]],
    ['direct WAL operand', [`${liveDatabase}-wal`]],
    ['direct SHM operand', [`${liveDatabase}-shm`]],
    ['direct journal operand', [`${liveDatabase}-journal`]],
    ['relative live database operand', ['live.db']],
    ['file URL live database operand', [pathToFileURL(liveDatabase).href]],
    ['symlink live database operand', [symlinkAlias]],
    ['hardlink live database operand', [hardlinkAlias]],
    ['dangling WAL symlink operand', [danglingWalAlias]],
    ['assignment live database operand', [`of=${liveDatabase}`]],
    ['long option live database operand', [`--output=${liveDatabase}`]],
    ['attached archive live database operand', [`-f${liveDatabase}`]],
    ['redirection live database operand', [`2>${liveDatabase}-journal`]],
    ['archive directory containing live database', ['-C', root, '.']],
  ]) {
    assertChildOperandFailure(label, operands, cwd, baseEnv);
  }
  assertChildOperandSuccess(
    'private temporary database operand',
    [safeDatabase],
    root,
    baseEnv,
  );
  assertChildOperandSuccess(
    'private archive-style operands',
    ['-C', workerRoot, '.', `of=${safeBackup}`],
    root,
    baseEnv,
  );
  assertInterpreterInlineSourceSuccess(
    'Node inline source is not treated as a path operand',
    process.execPath,
    baseEnv,
  );
  assertShellChildOperandFailure(
    'shell script live database operand',
    liveDatabase,
    baseEnv,
  );
  assertShellChildOperandSuccess(
    'shell script private database operand',
    safeDatabase,
    baseEnv,
  );
  assertFailure(
    'direct ChildProcess.prototype.spawn cannot bypass the guard',
    runNode(directChildProcessSpawnSource(), {
      ...baseEnv,
      SQLITE_ALIAS: sqliteAlias,
    }),
    /external sqlite3 execution is forbidden/,
  );
  assertFailure(
    'detached fork is forbidden',
    runNode(detachedForkSource(), {
      ...baseEnv,
      CHILD_PROBE: childProbePath,
    }),
    /detached child processes are forbidden/,
  );
  if (process.platform !== 'win32') {
    assertSuccess(
      'detached process identity telemetry is narrowly authorized',
      runNode(processIdentityTelemetrySource(), baseEnv),
    );
    assertSuccess(
      'detached process identity telemetry preserves an inherited scope',
      runNode(processIdentityTelemetrySource(), {
        ...baseEnv,
        RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog',
      }),
    );
    assertSuccess(
      'guarded process identity telemetry capability is immutable',
      runNode(processIdentityTelemetryCapabilitySource(), baseEnv),
    );
    assertSuccess(
      'injected process identity telemetry launch is rejected',
      runNode(processIdentityTelemetryInjectedRunSource(), baseEnv),
    );
    assertFailure(
      'detached process identity telemetry scope cannot bypass the guard',
      runNode(processIdentityTelemetryScopeBypassSource(), baseEnv),
      /detached child processes are forbidden/,
    );
  }
  assertFailure(
    'external sqlite client is always forbidden',
    runNode(externalSqliteSource(), {
      ...baseEnv,
      SQLITE_ALIAS: sqliteAlias,
      TARGET_DATABASE: safeDatabase,
    }),
    /external sqlite3 execution is forbidden/,
  );
  assertFailure(
    'external sqlite client through a shell is forbidden',
    runNode(shellExternalSqliteSource(), {
      ...baseEnv,
      SQLITE_ALIAS: sqliteAlias,
      TARGET_DATABASE: safeDatabase,
    }),
    /external sqlite3 execution is forbidden/,
  );
  assertFailure(
    'external sqlite client through env is forbidden',
    runNode(envExternalSqliteSource(), {
      ...baseEnv,
      SQLITE_ALIAS: sqliteAlias,
      TARGET_DATABASE: safeDatabase,
    }),
    /external sqlite3 execution is forbidden/,
  );
  if (process.platform === 'darwin' && existsSync('/usr/bin/nice')) {
    assertSuccess(
      'nice wrapper recursively authorizes Node',
      runNode(niceNodeSource(), baseEnv),
    );
    assertFailure(
      'nice wrapper cannot conceal an external sqlite client',
      runNode(niceWrappedCommandSource('sqlite'), {
        ...baseEnv,
        SQLITE_ALIAS: sqliteAlias,
      }),
      /external sqlite3 execution is forbidden/,
    );
    assertFailure(
      'nice wrapper cannot conceal an unallowlisted executable',
      runNode(niceWrappedCommandSource('unallowlisted'), baseEnv),
      /child executable is not allowlisted/,
    );
    assertFailure(
      'nice wrapper rejects unsupported scheduling arguments',
      runNode(niceMalformedSource(), baseEnv),
      /nice only supports the audited -n 15 <command> form/,
    );
  }
  if (
    process.platform === 'darwin' &&
    existsSync('/usr/sbin/taskpolicy') &&
    existsSync('/usr/bin/nice')
  ) {
    assertSuccess(
      'taskpolicy and nice recursively authorize Node',
      runNode(taskpolicyNodeSource(), baseEnv),
    );
    assertFailure(
      'taskpolicy and nice cannot conceal an external sqlite client',
      runNode(taskpolicyWrappedSqliteSource(), {
        ...baseEnv,
        SQLITE_ALIAS: sqliteAlias,
      }),
      /external sqlite3 execution is forbidden/,
    );
    assertFailure(
      'taskpolicy wrapper rejects unsupported policy arguments',
      runNode(taskpolicyMalformedSource(), baseEnv),
      /taskpolicy only supports the audited -b <command> form/,
    );
  }
  for (const [label, command] of [
    ['shell DB_PATH assignment', `DB_PATH=${liveDatabase} true`],
    ['shell DB_PATH export', `export DB_PATH=${liveDatabase}; true`],
    [
      'shell protected guard export',
      `export RADAR_TEST_LIVE_DB=${safeDatabase}; true`,
    ],
    [
      'wrapped shell DB_PATH export',
      `command export DB_PATH=${liveDatabase}; true`,
    ],
  ]) {
    assertFailure(
      label,
      runNode(shellCommandSource(command), baseEnv),
      /shell command mutates protected/,
    );
  }
  assertFailure(
    'env cannot assign DB_PATH',
    runNode(envMutationSource(), {
      ...baseEnv,
      TARGET_DATABASE: liveDatabase,
    }),
    /shell command mutates protected DB_PATH/,
  );
  assertFailure(
    'dynamic shell evaluation is forbidden',
    runNode(
      shellCommandSource(`eval 'export DB_PATH=${liveDatabase}'`),
      baseEnv,
    ),
    /dynamic shell evaluation is forbidden/,
  );
  assertFailure(
    'DatabaseSync constructor recovery remains guarded',
    runChildProbe('constructor-open', liveDatabase, baseEnv),
    /Refusing to open the live database/,
  );
  for (const [label, mode, expected] of [
    ['ATTACH through exec', 'attach-exec', /Refusing ATTACH SQL/],
    ['ATTACH through prepare', 'attach-prepare', /Refusing ATTACH SQL/],
    ['VACUUM INTO through exec', 'vacuum-exec', /Refusing VACUUM SQL/],
    ['VACUUM INTO through prepare', 'vacuum-prepare', /Refusing VACUUM SQL/],
    ['VACUUM main through exec', 'vacuum-main-exec', /Refusing VACUUM SQL/],
    ['VACUUM main through prepare', 'vacuum-main-prepare', /Refusing VACUUM SQL/],
    [
      'max_page_count weakening',
      'weaken-max-page-count',
      /Refusing PRAGMA max_page_count/,
    ],
    [
      'journal_size_limit weakening',
      'weaken-journal-size-limit',
      /Refusing PRAGMA journal_size_limit/,
    ],
  ]) {
    assertFailure(
      label,
      runChildProbe(mode, sqlDestination, baseEnv),
      expected,
    );
  }
  assertFailure(
    'SQLite extension loading cannot be enabled at construction',
    runNode(extensionLoadingSource(), baseEnv),
    /SQLite extension loading is forbidden/,
  );
  assertSuccess(
    'failed guard installation can be retried',
    runUnpreloadedNode(installRetrySource(), {
      ...baseEnv,
      NODE_OPTIONS: '--no-warnings',
      RADAR_TEST_DB_AUDIT: '',
      RETRY_AUDIT_PATH: auditPath,
      RUNTIME_PATH: guardRuntimePath,
      TARGET_DATABASE: liveDatabase,
    }),
  );
  assertFailure(
    'inherited live database path',
    runNode('process.exit(0)', {
      ...baseEnv,
      DB_PATH: liveDatabase,
    }),
    /inherited the live database path/,
  );

  verifyAudit();
  console.log(
    '[test-runner] database guard self-test passed: direct, URI, symlink, ' +
    'hardlink, backup, worker isolation, constructor facades, child snapshots, ' +
    'audited scheduling wrappers, external clients, SQL destinations, resource ' +
    'ceilings, shell state, retryable installation, inherited paths, and ' +
    'outside-root access enforced.',
  );
} finally {
  rmSync(root, { recursive: true, force: true });
  rmSync(outsideRoot, { recursive: true, force: true });
}

function initializeDatabase(path) {
  const database = new DatabaseSync(path);
  database.exec('CREATE TABLE self_test (id INTEGER PRIMARY KEY)');
  database.close();
}

function assertProbe(label, target, succeeds, env) {
  const result = runNode(sqliteOpenSource(), {
    ...env,
    TARGET_DATABASE: target,
  });
  if (succeeds) {
    assertSuccess(label, result);
  } else {
    assertFailure(label, result, /Refusing to open the live database/);
  }
}

function assertBackupFailure(label, target, env) {
  assertFailure(
    label,
    runNode(sqliteBackupSource(), {
      ...env,
      TARGET_DATABASE: target,
    }),
    /Refusing to open the live database/,
  );
}

function assertWorkerFailure(label, target, env) {
  assertFailure(
    label,
    runNode(workerSqliteOpenSource(), {
      ...env,
      TARGET_DATABASE: target,
    }),
    /Refusing to open the live database/,
  );
}

function assertCopySourceFailure(
  label,
  source,
  destination,
  recursive,
  env,
) {
  rmSync(destination, { recursive: true, force: true });
  try {
    assertFailure(
      label,
      runNode(copySource(source, destination, recursive), env),
      /Refusing (?:copyFileSync|cpSync) filesystem read during tests: .*live database/,
    );
    if (existsSync(destination)) {
      throw new Error(`${label} created a destination before being blocked`);
    }
  } finally {
    rmSync(destination, { recursive: true, force: true });
  }
}

function assertCopySourceSuccess(label, source, destination, env) {
  rmSync(destination, { force: true });
  try {
    assertSuccess(
      label,
      runNode(copySource(source, destination, false), env),
    );
    if (!existsSync(destination)) {
      throw new Error(`${label} did not create its destination`);
    }
  } finally {
    rmSync(destination, { force: true });
  }
}

function runChildProbe(mode, target, env) {
  return runNode(childProbeSource(mode), {
    ...env,
    CHILD_PROBE: childProbePath,
    TARGET_DATABASE: target,
  });
}

function assertChildOperandFailure(label, operands, cwd, env) {
  rmSync(childOperandMarker, { force: true });
  try {
    assertFailure(
      label,
      runNode(
        childOperandLaunchSource(operands, childOperandMarker, cwd),
        env,
      ),
      /child path operand (?:targets the|contains a) live database/,
    );
    if (existsSync(childOperandMarker)) {
      throw new Error(`${label} reached native child execution`);
    }
  } finally {
    rmSync(childOperandMarker, { force: true });
  }
}

function assertChildOperandSuccess(label, operands, cwd, env) {
  rmSync(childOperandMarker, { force: true });
  try {
    assertSuccess(
      label,
      runNode(
        childOperandLaunchSource(operands, childOperandMarker, cwd),
        env,
      ),
    );
    if (!existsSync(childOperandMarker)) {
      throw new Error(`${label} did not reach native child execution`);
    }
  } finally {
    rmSync(childOperandMarker, { force: true });
  }
}

function assertShellChildOperandFailure(label, operand, env) {
  rmSync(childOperandMarker, { force: true });
  try {
    assertFailure(
      label,
      runNode(
        shellChildOperandLaunchSource(operand, childOperandMarker),
        env,
      ),
      /child path operand (?:targets the|contains a) live database/,
    );
    if (existsSync(childOperandMarker)) {
      throw new Error(`${label} reached native shell execution`);
    }
  } finally {
    rmSync(childOperandMarker, { force: true });
  }
}

function assertShellChildOperandSuccess(label, operand, env) {
  rmSync(childOperandMarker, { force: true });
  try {
    assertSuccess(
      label,
      runNode(
        shellChildOperandLaunchSource(operand, childOperandMarker),
        env,
      ),
    );
    if (!existsSync(childOperandMarker)) {
      throw new Error(`${label} did not reach native shell execution`);
    }
  } finally {
    rmSync(childOperandMarker, { force: true });
  }
}

function assertInterpreterInlineSourceSuccess(label, executable, env) {
  rmSync(childOperandMarker, { force: true });
  try {
    assertSuccess(
      label,
      runNode(
        interpreterInlineSourceLaunchSource(executable, childOperandMarker),
        env,
      ),
    );
    if (!existsSync(childOperandMarker)) {
      throw new Error(`${label} did not reach native child execution`);
    }
  } finally {
    rmSync(childOperandMarker, { force: true });
  }
}

function assertSuccess(label, result) {
  if (result.status !== 0 || result.signal !== null) {
    throw new Error(`${label} unexpectedly failed:\n${diagnostics(result)}`);
  }
}

function assertFailure(label, result, expected) {
  if (result.status === 0 && result.signal === null) {
    throw new Error(`${label} unexpectedly succeeded`);
  }
  if (!expected.test(diagnostics(result))) {
    throw new Error(
      `${label} failed for the wrong reason; expected ${expected}:\n` +
      diagnostics(result),
    );
  }
}

function runNode(source, env) {
  return spawnSync(process.execPath, ['-e', source], {
    cwd: root,
    encoding: 'utf8',
    env,
    timeout: 15_000,
  });
}

function runUnpreloadedNode(source, env) {
  return spawnSync(process.execPath, ['-e', source], {
    cwd: root,
    encoding: 'utf8',
    env,
    timeout: 15_000,
  });
}

function childOperandLaunchSource(operands, marker, cwd) {
  const markerSource =
    `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'launched')`;
  return `
    const { spawnSync } = require('node:child_process');
    const result = spawnSync(
      process.execPath,
      [
        '-e',
        ${JSON.stringify(markerSource)},
        '--',
        ...${JSON.stringify(operands)},
      ],
      {
        cwd: ${JSON.stringify(cwd)},
        encoding: 'utf8',
        env: process.env,
      },
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw result.error;
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function shellChildOperandLaunchSource(operand, marker) {
  return `
    const { spawnSync } = require('node:child_process');
    const result = spawnSync(
      '/bin/sh',
      [
        ${JSON.stringify(childOperandShellScript)},
        ${JSON.stringify(operand)},
      ],
      {
        cwd: ${JSON.stringify(root)},
        encoding: 'utf8',
        env: {
          ...process.env,
          CHILD_OPERAND_MARKER: ${JSON.stringify(marker)},
        },
      },
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw result.error;
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function interpreterInlineSourceLaunchSource(executable, marker) {
  const inlineSource =
    `/*${'x'.repeat(512)}*/` +
    `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'launched')`;
  return `
    const { spawnSync } = require('node:child_process');
    const result = spawnSync(
      ${JSON.stringify(executable)},
      ['-e', ${JSON.stringify(inlineSource)}],
      {
        cwd: ${JSON.stringify(root)},
        encoding: 'utf8',
        env: process.env,
      },
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw result.error;
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function sqliteOpenSource() {
  return `
    const { DatabaseSync } = require('node:sqlite');
    const database = new DatabaseSync(process.env.TARGET_DATABASE);
    database.exec('CREATE TABLE IF NOT EXISTS probe (id INTEGER PRIMARY KEY)');
    database.close();
  `;
}

function copySource(source, destination, recursive) {
  return recursive
    ? `
      require('node:fs').cpSync(
        ${JSON.stringify(source)},
        ${JSON.stringify(destination)},
        { recursive: true },
      );
    `
    : `
      require('node:fs').copyFileSync(
        ${JSON.stringify(source)},
        ${JSON.stringify(destination)},
      );
    `;
}

function sqliteBackupSource() {
  return `
    const { DatabaseSync, backup } = require('node:sqlite');
    const source = new DatabaseSync(process.env.DB_PATH);
    backup(source, process.env.TARGET_DATABASE, {})
      .then(() => {
        source.close();
        process.exit(0);
      })
      .catch((error) => {
        source.close();
        console.error(error.stack || error.message);
        process.exit(1);
      });
  `;
}

function workerSqliteOpenSource() {
  return `
    const { Worker } = require('node:worker_threads');
    const worker = new Worker(
      \`
        const { parentPort, workerData } = require('node:worker_threads');
        const { DatabaseSync } = require('node:sqlite');
        try {
          const database = new DatabaseSync(workerData.target);
          database.close();
          parentPort.postMessage({ opened: true });
        } catch (error) {
          parentPort.postMessage({ error: error.stack || error.message });
        }
      \`,
      {
        eval: true,
        execArgv: [],
        workerData: { target: process.env.TARGET_DATABASE },
      },
    );
    worker.once('message', (message) => {
      if (message.error) {
        console.error(message.error);
        process.exit(1);
      }
      process.exit(message.opened ? 0 : 1);
    });
    worker.once('error', (error) => {
      console.error(error.stack || error.message);
      process.exit(1);
    });
  `;
}

function workerEnvironmentOverrideSource() {
  return `
    const { Worker } = require('node:worker_threads');
    new Worker('process.exit(0)', {
      eval: true,
      env: {
        ...process.env,
        DB_PATH: process.env.TARGET_DATABASE,
      },
    });
  `;
}

function recoveredWorkerConstructorSource() {
  return `
    const { Worker } = require('node:worker_threads');
    const RecoveredWorker = Worker.prototype.constructor;
    const worker = new RecoveredWorker(
      \`
        const { DatabaseSync } = require('node:sqlite');
        const database = new DatabaseSync(process.env.TARGET_DATABASE);
        database.close();
      \`,
      {
        eval: true,
        env: {
          DB_PATH: process.env.DB_PATH,
          PATH: process.env.PATH,
          TARGET_DATABASE: process.env.TARGET_DATABASE,
        },
      },
    );
    worker.once('error', (error) => {
      console.error(error.stack || error.message);
      process.exit(1);
    });
    worker.once('exit', (code) => process.exit(code));
  `;
}

function hostileWorkerEnvironmentSource() {
  return `
    const { Worker } = require('node:worker_threads');
    let dbPathReads = 0;
    const environment = new Proxy({ ...process.env }, {
      get(target, property, receiver) {
        if (property === 'DB_PATH') {
          dbPathReads++;
          return dbPathReads === 1
            ? target.DB_PATH
            : target.TARGET_DATABASE;
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const worker = new Worker(
      \`
        const { parentPort } = require('node:worker_threads');
        const { DatabaseSync } = require('node:sqlite');
        const database = new DatabaseSync(process.env.DB_PATH);
        database.close();
        parentPort.postMessage('ok');
      \`,
      { eval: true, env: environment },
    );
    worker.once('message', () => process.exit(0));
    worker.once('error', (error) => {
      console.error(error.stack || error.message);
      process.exit(1);
    });
  `;
}

function nestedChildSource(dropGuardEnvironment) {
  return `
    const { spawnSync } = require('node:child_process');
    const childEnvironment = ${dropGuardEnvironment
      ? `{
          DB_PATH: process.env.DB_PATH,
          PATH: process.env.PATH,
          TARGET_DATABASE: process.env.TARGET_DATABASE,
        }`
      : `{
          ...process.env,
          TARGET_DATABASE: process.env.TARGET_DATABASE,
        }`};
    const result = spawnSync(
      process.execPath,
      [process.env.CHILD_PROBE, 'open'],
      { encoding: 'utf8', env: childEnvironment },
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function hostileChildEnvironmentSource() {
  return `
    const { spawnSync } = require('node:child_process');
    let dbPathReads = 0;
    const environment = new Proxy({ ...process.env }, {
      get(target, property, receiver) {
        if (property === 'DB_PATH') {
          dbPathReads++;
          return dbPathReads === 1
            ? target.DB_PATH
            : target.TARGET_DATABASE;
        }
        return Reflect.get(target, property, receiver);
      },
    });
    const result = spawnSync(
      process.execPath,
      [process.env.CHILD_PROBE, 'open-db-path'],
      { encoding: 'utf8', env: environment },
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function hostileChildOptionsSource() {
  return `
    const { spawnSync } = require('node:child_process');
    let environmentReads = 0;
    const safeEnvironment = { ...process.env };
    const hostileEnvironment = {
      DB_PATH: process.env.TARGET_DATABASE,
      PATH: process.env.PATH,
      TARGET_DATABASE: process.env.TARGET_DATABASE,
    };
    const options = new Proxy(
      { encoding: 'utf8', env: safeEnvironment },
      {
        get(target, property, receiver) {
          if (property === 'env') {
            environmentReads++;
            return environmentReads === 1
              ? safeEnvironment
              : hostileEnvironment;
          }
          return Reflect.get(target, property, receiver);
        },
      },
    );
    const result = spawnSync(
      process.execPath,
      [process.env.CHILD_PROBE, 'open-db-path'],
      options,
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function recoveredChildFunctionSource() {
  return `
    const { spawnSync } = require('node:child_process');
    const RecoveredSpawnSync = spawnSync.prototype.constructor;
    const result = RecoveredSpawnSync(
      process.execPath,
      [process.env.CHILD_PROBE, 'open'],
      {
        encoding: 'utf8',
        env: {
          DB_PATH: process.env.DB_PATH,
          PATH: process.env.PATH,
          TARGET_DATABASE: process.env.TARGET_DATABASE,
        },
      },
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function directChildProcessSpawnSource() {
  return `
    const { ChildProcess } = require('node:child_process');
    const child = new ChildProcess();
    child.spawn({
      file: process.env.SQLITE_ALIAS,
      args: [process.env.SQLITE_ALIAS, process.env.DB_PATH],
      cwd: process.cwd(),
      detached: false,
      envPairs: Object.entries(process.env).map(
        ([name, value]) => \`\${name}=\${value}\`,
      ),
      stdio: [],
    });
  `;
}

function detachedForkSource() {
  return `
    const { fork } = require('node:child_process');
    fork(process.env.CHILD_PROBE, ['noop'], {
      detached: true,
      env: process.env,
      stdio: 'ignore',
    });
  `;
}

function processIdentityTelemetrySource() {
  const contractUrl = pathToFileURL(
    join(repositoryRoot, 'test', 'watchdog-contract.mjs'),
  ).href;
  return `
    import(${JSON.stringify(contractUrl)})
      .then(({ captureProcessIdentity }) => {
        const identity = captureProcessIdentity(process.pid);
        if (!identity || identity.pid !== process.pid) {
          throw new Error('Authorized process identity telemetry returned no identity');
        }
      })
      .catch((error) => {
        console.error(error.stack || error.message);
        process.exit(1);
      });
  `;
}

function processIdentityTelemetryCapabilitySource() {
  return `
    const key = Symbol.for(
      'openclaw-release-radar.guarded-process-identity-telemetry',
    );
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
    if (
      descriptor === undefined ||
      descriptor.configurable !== false ||
      descriptor.writable !== false ||
      typeof descriptor.value !== 'function'
    ) {
      throw new Error('Guarded process identity telemetry is not immutable');
    }
    if (Reflect.set(globalThis, key, () => null)) {
      throw new Error('Guarded process identity telemetry was replaceable');
    }
    if (Reflect.deleteProperty(globalThis, key)) {
      throw new Error('Guarded process identity telemetry was deletable');
    }
    let rejected = false;
    try {
      descriptor.value(0);
    } catch (error) {
      rejected = /positive integer PID/.test(error.message);
    }
    if (!rejected) {
      throw new Error('Guarded process identity telemetry accepted an invalid PID');
    }
  `;
}

function processIdentityTelemetryInjectedRunSource() {
  const contractUrl = pathToFileURL(
    join(repositoryRoot, 'test', 'watchdog-contract.mjs'),
  ).href;
  return `
    import(${JSON.stringify(contractUrl)})
      .then(({ captureProcessIdentity }) => {
        const { spawnSync } = require('node:child_process');
        let refusal = null;
        const identity = captureProcessIdentity(process.pid, {
          run(command, args, options) {
            try {
              return spawnSync(command, args, {
                ...options,
                env: {
                  ...process.env,
                  DYLD_INSERT_LIBRARIES: '/tmp/forbidden-test-library.dylib',
                  RADAR_TEST_DETACHED_SCOPE:
                    'process-identity-telemetry',
                },
              });
            } catch (error) {
              refusal = error;
              throw error;
            }
          },
        });
        if (identity !== null) {
          throw new Error('Injected process identity telemetry was authorized');
        }
        if (
          !(refusal instanceof Error) ||
          !/detached child processes are forbidden/.test(refusal.message)
        ) {
          throw new Error('Injected process identity telemetry was not guard-refused');
        }
      })
      .catch((error) => {
        console.error(error.stack || error.message);
        process.exit(1);
      });
  `;
}

function processIdentityTelemetryScopeBypassSource() {
  return `
    const { existsSync } = require('node:fs');
    const { spawnSync } = require('node:child_process');
    const command = existsSync('/bin/ps') ? '/bin/ps' : '/usr/bin/ps';
    spawnSync(
      command,
      [
        '-p',
        String(process.pid),
        '-o',
        'pid=,ppid=,pgid=,lstart=,comm=',
      ],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 2_000,
        detached: true,
        env: {
          ...process.env,
          RADAR_TEST_DETACHED_SCOPE: 'process-identity-telemetry',
        },
      },
    );
  `;
}

function externalSqliteSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      process.env.SQLITE_ALIAS,
      [process.env.TARGET_DATABASE, 'PRAGMA user_version'],
      { encoding: 'utf8', env: process.env },
    );
  `;
}

function shellExternalSqliteSource() {
  return `
    const { execSync } = require('node:child_process');
    execSync(
      JSON.stringify(process.env.SQLITE_ALIAS) + ' ' +
        JSON.stringify(process.env.TARGET_DATABASE),
      { env: process.env },
    );
  `;
}

function envExternalSqliteSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      '/usr/bin/env',
      [process.env.SQLITE_ALIAS, process.env.TARGET_DATABASE],
      { encoding: 'utf8', env: process.env },
    );
  `;
}

function niceNodeSource() {
  return `
    const { spawn } = require('node:child_process');
    const child = spawn(
      '/usr/bin/nice',
      ['-n', '15', process.execPath, '-e', 'process.exit(0)'],
      { env: process.env, stdio: 'ignore' },
    );
    child.once('error', (error) => {
      console.error(error.stack || error.message);
      process.exit(1);
    });
    child.once('exit', (code, signal) => {
      if (signal) console.error(signal);
      process.exit(code === 0 ? 0 : 1);
    });
  `;
}

function niceWrappedCommandSource(kind) {
  const command = kind === 'sqlite'
    ? 'process.env.SQLITE_ALIAS'
    : "'/usr/bin/false'";
  const args = kind === 'sqlite'
    ? '[process.env.DB_PATH]'
    : '[]';
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      '/usr/bin/nice',
      ['-n', '15', ${command}, ...${args}],
      { encoding: 'utf8', env: process.env },
    );
  `;
}

function niceMalformedSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      '/usr/bin/nice',
      ['-n', '10', process.execPath, '-e', 'process.exit(0)'],
      { encoding: 'utf8', env: process.env },
    );
  `;
}

function taskpolicyNodeSource() {
  return `
    const { spawn } = require('node:child_process');
    const child = spawn(
      '/usr/sbin/taskpolicy',
      [
        '-b',
        '/usr/bin/nice',
        '-n',
        '15',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      { env: process.env, stdio: 'ignore' },
    );
    child.once('error', (error) => {
      console.error(error.stack || error.message);
      process.exit(1);
    });
    child.once('exit', (code, signal) => {
      if (signal) console.error(signal);
      process.exit(code === 0 ? 0 : 1);
    });
  `;
}

function taskpolicyWrappedSqliteSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      '/usr/sbin/taskpolicy',
      [
        '-b',
        '/usr/bin/nice',
        '-n',
        '15',
        process.env.SQLITE_ALIAS,
        process.env.DB_PATH,
      ],
      { encoding: 'utf8', env: process.env },
    );
  `;
}

function taskpolicyMalformedSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      '/usr/sbin/taskpolicy',
      ['-p', process.execPath, '-e', 'process.exit(0)'],
      { encoding: 'utf8', env: process.env },
    );
  `;
}

function envMutationSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      '/usr/bin/env',
      [\`DB_PATH=\${process.env.TARGET_DATABASE}\`, 'true'],
      { encoding: 'utf8', env: process.env },
    );
  `;
}

function shellCommandSource(command) {
  return `
    const { execSync } = require('node:child_process');
    execSync(${JSON.stringify(command)}, { env: process.env });
  `;
}

function childProbeSource(mode) {
  return `
    const { spawnSync } = require('node:child_process');
    const result = spawnSync(
      process.execPath,
      [process.env.CHILD_PROBE, ${JSON.stringify(mode)}],
      { encoding: 'utf8', env: process.env },
    );
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status === null ? 1 : result.status);
  `;
}

function databasePolicyProbeMintSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      process.execPath,
      ['-e', 'process.exit(0)'],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          RADAR_TEST_DATABASE_POLICY_PROBE: '1',
          RADAR_TEST_DATABASE_POLICY_PROBE_CONTEXT: 'evaluation',
        },
      },
    );
  `;
}

function databasePolicyProbeAuthorityMintSource() {
  return `
    const { spawnSync } = require('node:child_process');
    spawnSync(
      process.execPath,
      ['-e', 'process.exit(0)'],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          RADAR_TEST_DATABASE_POLICY_PROBE_AUTHORITY: '1',
        },
      },
    );
  `;
}

function extensionLoadingSource() {
  return `
    const { DatabaseSync } = require('node:sqlite');
    new DatabaseSync(process.env.DB_PATH, { allowExtension: true });
  `;
}

function installRetrySource() {
  return `
    let failed = false;
    try {
      require(process.env.RUNTIME_PATH);
    } catch (error) {
      failed = /RADAR_TEST_DB_AUDIT/.test(error.message);
    }
    if (!failed) throw new Error('Initial guard installation did not fail as expected');
    process.env.RADAR_TEST_DB_AUDIT = process.env.RETRY_AUDIT_PATH;
    require(process.env.RUNTIME_PATH);
    const { DatabaseSync } = require('node:sqlite');
    try {
      new DatabaseSync(process.env.TARGET_DATABASE);
      throw new Error('Retried guard did not block the live database');
    } catch (error) {
      if (!/Refusing to open the live database/.test(error.message)) throw error;
    }
  `;
}

function diagnostics(result) {
  return [
    `status=${String(result.status)}`,
    `signal=${String(result.signal)}`,
    result.error?.stack ?? result.error?.message ?? '',
    result.stdout ?? '',
    result.stderr ?? '',
  ].filter(Boolean).join('\n');
}

function verifyAudit() {
  const events = readFileSync(auditPath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  if (events.length === 0) throw new Error('Database guard self-test audit is empty');
  if (events.some((event) => event.runId !== runId)) {
    throw new Error('Database guard self-test audit contains an unexpected run ID');
  }

  const blockedDatabaseOperations = events.filter((event) =>
    event.blocked === true &&
    ['sqlite-open', 'sqlite-backup'].includes(event.type));
  if (blockedDatabaseOperations.length < 10) {
    throw new Error(
      `Expected at least 10 blocked database operations, observed ` +
      `${blockedDatabaseOperations.length}: ${JSON.stringify(events)}`,
    );
  }

  const outsideRootOperations = events.filter((event) =>
    event.outsideAllowedRoots === true && event.blocked !== true);
  if (outsideRootOperations.length < 3) {
    throw new Error(
      `Expected at least 3 outside-root database operations, observed ` +
      `${outsideRootOperations.length}: ${JSON.stringify(events)}`,
    );
  }

  const blockedChildProcesses = events.filter((event) =>
    event.type === 'child-process' && event.blocked === true);
  if (blockedChildProcesses.length < 10) {
    throw new Error(
      `Expected at least 10 blocked child-process bypasses, observed ` +
      `${blockedChildProcesses.length}`,
    );
  }

  const blockedSqlPolicies = events.filter((event) =>
    event.type === 'sqlite-sql-policy' && event.blocked === true);
  if (blockedSqlPolicies.length < 6) {
    throw new Error(
      `Expected at least 6 blocked SQLite SQL-policy bypasses, observed ` +
      `${blockedSqlPolicies.length}`,
    );
  }

  const unexpectedLiveAccess = events.filter((event) =>
    event.inode &&
    blockedDatabaseOperations.some((blocked) =>
      blocked.inode === event.inode) &&
    event.blocked !== true);
  if (unexpectedLiveAccess.length > 0) {
    throw new Error(
      `Live database identity was opened without blocking: ` +
      JSON.stringify(unexpectedLiveAccess),
    );
  }
}
