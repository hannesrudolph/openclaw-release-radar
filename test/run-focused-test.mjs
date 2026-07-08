import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import {
  dirname,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assertSupportedNodeVersion } from './node-version.mjs';

assertSanitizedTestEntrypointEnvironment();
assertSupportedNodeVersion();

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const {
  authoritative,
  file,
  testNamePattern,
} = parseArguments(process.argv.slice(2));
const normalizedFile = normalizeManifestPath(file);
const manifest = JSON.parse(
  readFileSync(join(root, 'test', 'test-manifest.json'), 'utf8'),
);
const phase = manifestPhaseForFile(manifest, normalizedFile);
if (!phase) {
  throw new Error(
    `Focused test file is not listed in test/test-manifest.json: ${normalizedFile}`,
  );
}

const { tsImport } = await import('tsx/esm/api');
const runner = await tsImport('./test-suite-runner.mjs', import.meta.url);
const {
  acquireExclusiveProcessLock,
  acquireRepositoryDatabaseWriterLock,
} = await tsImport('../src/lib/exclusiveProcessLock.ts', import.meta.url);

const suiteLock = runner.acquireTestSuiteLock();
let writerLock = null;
let delegatedWriterLock = null;
let tempRoot = null;
let controlRoot = null;
let preserveDiagnostics = false;
let interruptedBy = null;
let exitCode = 1;
let bodyFailure = null;
let liveDatabase = null;
let liveFingerprint = null;

try {
  writerLock = acquireRepositoryDatabaseWriterLock({
    repositoryRoot: root,
    label: 'focused test run',
  });
  tempRoot = mkdtempSync(join(tmpdir(), 'openclaw-radar-focused-'));
  tempRoot = realpathSync.native(tempRoot);
  chmodSync(tempRoot, 0o700);
  controlRoot = mkdtempSync(
    join(tmpdir(), 'openclaw-radar-focused-controls-'),
  );
  controlRoot = realpathSync.native(controlRoot);
  chmodSync(controlRoot, 0o700);

  const processLockLayout = runner.resolveTestProcessLockLayout({
    repositoryRoot: root,
    tempRoot,
    globalWriterLockPath: writerLock.path,
  });
  const processLockRoot = processLockLayout.delegatedProcessLockRoot;
  mkdirSync(processLockRoot, { mode: 0o700 });
  delegatedWriterLock = acquireExclusiveProcessLock({
    lockPath: processLockLayout.delegatedWriterLockPath,
    label: 'authoritative focused test delegated writer',
    resourceLabel: 'delegated repository database writer',
    pid: process.pid,
  });
  const writerLeasePath = join(tempRoot, 'writer-lease.json');
  const writerAuthority = runner.buildDelegatedWriterAuthority({
    owner: delegatedWriterLock.owner,
    processLockRoot,
    repositoryRoot: root,
    tempRoot,
    writerLeasePath,
  });
  writeFileSync(
    writerLeasePath,
    `${JSON.stringify(writerAuthority.lease)}\n`,
    { flag: 'wx', mode: 0o600 },
  );

  const emptyDotenvPath = join(tempRoot, 'empty.env');
  const databasePath = join(tempRoot, 'radar.db');
  const auditPath = join(tempRoot, 'database-audit.jsonl');
  writeFileSync(emptyDotenvPath, '', { flag: 'wx', mode: 0o600 });
  writeFileSync(auditPath, '', { flag: 'wx', mode: 0o600 });

  const liveInspection = runner.inspectConfiguredLiveDatabaseUnderWriteBoundary({
    repositoryRoot: root,
  });
  liveDatabase = liveInspection.liveDatabase;
  liveFingerprint = liveInspection.fingerprint;
  const runId = randomUUID();
  const codeRevision = `focused-test-${runId}`;
  const writeBoundary = runner.createTestWriteBoundary({
    controlRoot,
    initialLiveFingerprint: liveFingerprint,
    repositoryRoot: root,
    runId,
    tempRoot,
    writableRoots: [tempRoot],
  });
  const guardNodeOptions = [
    `--import=${pathToFileURL(
      join(root, 'test', 'worker-environment.mjs'),
    ).href}`,
    `--import=${pathToFileURL(
      join(root, 'test', 'database-guard.mjs'),
    ).href}`,
  ].join(' ');
  const resourceLimits = runner.resolveTestResourceLimits();
  const environment = {
    ...runner.sanitizeTestChildEnvironment({
      environment: process.env,
      liveDatabase,
    }),
    ...writerAuthority.environment,
    DB_PATH: databasePath,
    DOTENV_CONFIG_PATH: emptyDotenvPath,
    NODE_ENV: 'test',
    NODE_OPTIONS: guardNodeOptions,
    RADAR_CODE_REVISION: codeRevision,
    RADAR_DB_BOOTSTRAP_MODE: 'fresh',
    RADAR_DB_READ_ONLY: '0',
    RADAR_TEST_CODE_REVISION: codeRevision,
    RADAR_TEST_DB_AUDIT: auditPath,
    RADAR_TEST_RUN_ID: runId,
    RADAR_TEST_SQLITE_MAX_MIB: String(
      resourceLimits.maximumSqliteBytes / (1024 * 1024),
    ),
    RADAR_TEST_TEMP_ROOT: tempRoot,
    REFRESH_MINUTES: '0',
    REFRESH_ON_STARTUP: 'false',
    SQLITE_TMPDIR: tempRoot,
    TEMP: tempRoot,
    TMP: tempRoot,
    TMPDIR: tempRoot,
    RADAR_TEST_DATABASE_GUARD_POLICY: writeBoundary.policyPath,
    RADAR_TEST_DATABASE_GUARD_POLICY_DIGEST: writeBoundary.policyDigest,
    RADAR_TEST_PROCESS_IDENTITY_HELPER:
      writeBoundary.processIdentityHelper.path,
    RADAR_TEST_PROCESS_IDENTITY_HELPER_IDENTITY: JSON.stringify(
      writeBoundary.processIdentityHelper,
    ),
    RADAR_TEST_SANDBOX_BACKEND: writeBoundary.backend,
    RADAR_TEST_SANDBOX_PROFILE_DIGEST: writeBoundary.profileDigest,
  };

  let installerFixtureIdentity = null;
  if (normalizedFile === 'src/lib/installRelease.test.ts') {
    const installerFixture = runner.materializePrivateInstallerHeredocs({
      sourcePath: join(
        root,
        'ops',
        'viralo',
        'openclaw-release-radar-install-release.sh',
      ),
      fixtureRoot: join(
        authoritative ? controlRoot : tempRoot,
        'installer-heredocs',
      ),
      expectedHeredocCount:
        runner.PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT,
      forbidShellHereStrings: true,
    });
    environment.RADAR_TEST_INSTALLER_FIXTURE_PATH =
      installerFixture.installerPath;
    installerFixtureIdentity = installerFixture.fixtureIdentity;
  }

  const isolationFlag = process.allowedNodeEnvironmentFlags.has(
    '--test-isolation',
  )
    ? '--test-isolation=process'
    : '--experimental-test-isolation=process';
  const timeoutMs = phase === 'installer'
    ? 25 * 60 * 1000
    : phase === 'e2e'
      ? 5 * 60 * 1000
      : 2 * 60 * 1000;
  const command = [
    '--no-warnings',
    '--import=tsx',
    '--test',
    isolationFlag,
    '--test-concurrency=1',
    `--test-timeout=${timeoutMs}`,
    ...(testNamePattern
      ? [`--test-name-pattern=${testNamePattern}`]
      : []),
    normalizedFile,
  ];
  console.log(
    `[test-focus${authoritative ? ':authoritative' : ''}] ${normalizedFile}` +
    `${testNamePattern ? ` matching ${JSON.stringify(testNamePattern)}` : ''}`,
  );
  if (installerFixtureIdentity && authoritative) {
    runner.assertPrivateInstallerFixtureUnchanged(installerFixtureIdentity);
  }
  const launch = writeBoundary.wrapCommand(process.execPath, command);
  const result = spawnSync(launch.command, launch.args, {
    cwd: root,
    env: environment,
    stdio: 'inherit',
  });
  if (installerFixtureIdentity && authoritative) {
    runner.assertPrivateInstallerFixtureUnchanged(
      installerFixtureIdentity,
      'after authoritative focused test',
    );
  }
  runner.assertSqliteFamilyUnchanged(
    liveDatabase,
    liveFingerprint,
    'focused test run',
  );
  if (authoritative) {
    runner.cleanupExitedWorkerDirectories({
      tempRoot,
      auditPath,
      runId,
    });
  }
  if (result.error) throw result.error;
  interruptedBy = result.signal;
  exitCode = result.status ?? 1;
  if (authoritative && interruptedBy === null && exitCode === 0) {
    runner.assertDatabaseAudit({
      auditPath,
      expectedFiles: [normalizedFile],
      tempRoot,
      liveDatabase,
      runId,
      requireCompleteCoverage: true,
    });
  }
  preserveDiagnostics =
    authoritative && (interruptedBy !== null || exitCode !== 0);
  if (preserveDiagnostics) {
    console.error(`[test-focus] preserved diagnostics at ${tempRoot}`);
    console.error(`[test-focus] preserved controls at ${controlRoot}`);
  }
} catch (error) {
  if (authoritative && !preserveDiagnostics) {
    preserveDiagnostics = true;
    if (tempRoot) {
      console.error(`[test-focus] preserved diagnostics at ${tempRoot}`);
    }
    if (controlRoot) {
      console.error(`[test-focus] preserved controls at ${controlRoot}`);
    }
  }
  bodyFailure = error;
} finally {
  const cleanupErrors = [];
  const cleanup = (label, operation) => {
    try {
      operation();
    } catch (error) {
      cleanupErrors.push(new Error(
        `${label}: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      ));
    }
  };
  cleanup('delegated writer-lock release', () => {
    delegatedWriterLock?.release();
  });
  if (tempRoot && !preserveDiagnostics) {
    cleanup('focused test temporary-root removal', () => {
      rmSync(tempRoot, { recursive: true, force: true });
    });
  }
  if (controlRoot && !preserveDiagnostics) {
    cleanup('focused test control-root removal', () => {
      rmSync(controlRoot, { recursive: true, force: true });
    });
  }
  if (liveDatabase && liveFingerprint) {
    cleanup('terminal focused live database verification', () => {
      runner.assertNoOpenLiveDatabaseDescriptors(liveFingerprint);
      runner.assertSqliteFamilyUnchanged(
        liveDatabase,
        liveFingerprint,
        'terminal focused test cleanup',
      );
    });
  }
  cleanup('repository writer-lock release', () => {
    writerLock?.release();
  });
  cleanup('test suite-lock release', () => {
    suiteLock.release();
  });
  const combinedFailure = runner.combineErrors(
    bodyFailure,
    cleanupErrors,
    'Focused test failed and safety verification or cleanup was incomplete',
  );
  if (combinedFailure) throw combinedFailure;
}

if (interruptedBy) {
  process.kill(process.pid, interruptedBy);
} else {
  process.exitCode = exitCode;
}

function parseArguments(args) {
  let authoritative = false;
  let file = null;
  let testNamePattern = null;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--authoritative') {
      if (authoritative) {
        throw new Error('--authoritative was provided more than once.');
      }
      authoritative = true;
      continue;
    }
    if (argument === '--name' || argument === '--test-name-pattern') {
      if (testNamePattern !== null || index + 1 >= args.length) {
        throw new Error(`Invalid ${argument} option.`);
      }
      testNamePattern = args[index + 1];
      index += 1;
      continue;
    }
    if (argument.startsWith('--name=')) {
      if (testNamePattern !== null) {
        throw new Error('Test-name pattern was provided more than once.');
      }
      testNamePattern = argument.slice('--name='.length);
      continue;
    }
    if (argument.startsWith('--test-name-pattern=')) {
      if (testNamePattern !== null) {
        throw new Error('Test-name pattern was provided more than once.');
      }
      testNamePattern = argument.slice('--test-name-pattern='.length);
      continue;
    }
    if (argument.startsWith('-')) {
      throw new Error(`Unsupported focused-test option: ${argument}`);
    }
    if (file !== null) {
      throw new Error('Focused validation accepts exactly one test file.');
    }
    file = argument;
  }
  if (!file) {
    throw new Error(
      'Usage: npm run test:focus -- [--authoritative] ' +
        '<manifest-test-file> [--name <pattern>]',
    );
  }
  if (testNamePattern !== null && testNamePattern.length === 0) {
    throw new Error('Focused test-name pattern must not be empty.');
  }
  return { authoritative, file, testNamePattern };
}

function normalizeManifestPath(file) {
  const absolute = resolve(root, file);
  const normalized = relative(root, absolute).split(sep).join('/');
  if (
    normalized === '' ||
    normalized === '..' ||
    normalized.startsWith('../')
  ) {
    throw new Error(`Focused test path escapes the repository: ${file}`);
  }
  return normalized;
}

function manifestPhaseForFile(manifest, file) {
  for (const [phase, files] of Object.entries(manifest?.phases ?? {})) {
    if (Array.isArray(files) && files.includes(file)) return phase;
  }
  return null;
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
