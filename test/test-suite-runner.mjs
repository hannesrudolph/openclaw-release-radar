import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  appendFileSync,
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readlinkSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statfsSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  assertFileSnapshotUnchanged,
  captureFileSnapshot,
  generatePhaseBaseline,
  readJsonFileSnapshot,
  readTestEventLog,
  TEST_INTEGRITY_SKIP_ALLOWLIST,
  validatePhaseBaseline,
  verifyPhaseIntegrity,
} from './test-integrity.mjs';
import { resolveConfiguredLiveDatabase } from './live-database-path.mjs';
import { assertSupportedNodeVersion } from './node-version.mjs';
import {
  captureSqliteFamilyFingerprint,
  sqliteFamilyPaths,
} from './sqlite-family-fingerprint.mjs';
import {
  acquireExclusiveProcessLock,
  acquireRepositoryDatabaseWriterLock,
  repositoryDatabaseWriterLockPath,
} from '../src/lib/exclusiveProcessLock.ts';
import {
  captureSystemDiskTransferBytes,
  parseDarwinIostatDiskTransferBytes,
  systemDiskTransferDeltaBytes,
} from './system-io.mjs';
import {
  canonicalJson as watchdogCanonicalJson,
  capturePathIdentity,
  captureProcessIdentity,
  sealWatchdogState,
  verifyWatchdogReceiptSeal,
} from './watchdog-contract.mjs';

export { assertSupportedNodeVersion } from './node-version.mjs';
export {
  parseDarwinIostatDiskTransferBytes,
  systemDiskTransferDeltaBytes,
} from './system-io.mjs';
export {
  captureSqliteFamilyFingerprint,
};

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const canonicalRoot = canonicalPath(root);
const repositoryIdentity = canonicalRepositoryIdentity(canonicalRoot);
const manifestPath = join(root, 'test', 'test-manifest.json');
const baselinePath = join(root, 'test', 'test-baseline.json');
const baselineCandidatePath = join(root, 'test', 'test-baseline.candidate.json');
const reporterPath = join(root, 'test', 'test-json-reporter.mjs');
const workerEnvironmentPath = join(root, 'test', 'worker-environment.mjs');
const databaseGuardPath = join(root, 'test', 'database-guard.mjs');
const liveDatabaseInspectionChildPath =
  join(root, 'test', 'live-database-inspection-child.mjs');
const resourceWatchdogPath = join(root, 'test', 'resource-watchdog.mjs');
const processIdentitySourcePath =
  join(root, 'test', 'process-io-darwin.c');
const sandboxExecutablePath = '/usr/bin/sandbox-exec';
const productionInstallerPath = join(
  root,
  'ops',
  'viralo',
  'openclaw-release-radar-install-release.sh',
);
export const PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT = 53;
const executionInputDirectories = Object.freeze([
  '.github',
  'config',
  'dist',
  'docs',
  'fixtures',
  'helpers',
  'src',
  'scripts',
  'test',
  'public',
  'ops',
  'node_modules',
]);
const executionInputRootFiles = Object.freeze([
  '.env.example',
  '.npmrc',
  'AGENTS.md',
  'npm-shrinkwrap.json',
  'package-lock.json',
  'package.json',
  'pnpm-lock.yaml',
  'README.md',
  'tsconfig.json',
  'yarn.lock',
]);
const excludedExecutionInputs = new Set([
  'test/test-baseline.candidate.json',
  'test/test-baseline.json',
]);
const ignoredExecutionInputNames = new Set([
  '.DS_Store',
]);
export const SAFETY_HARNESS_FILES = Object.freeze([
  'package-lock.json',
  'package.json',
  'src/lib/exclusiveProcessLock.ts',
  'test/database-guard-child-probe.cjs',
  'test/accept-test-baseline.mjs',
  'test/database-guard-runtime.cjs',
  'test/database-guard.mjs',
  'test/generate-test-baseline.mjs',
  'test/live-database-inspection-child.mjs',
  'test/live-database-path.mjs',
  'test/node-version.mjs',
  'test/process-io-darwin.c',
  'test/process-io.mjs',
  'test/run-database-guard.mjs',
  'test/run-focused-test.mjs',
  'test/run-installer-preflight.mjs',
  'test/run-tests.mjs',
  'test/resource-watchdog.mjs',
  'test/sqlite-family-fingerprint.mjs',
  'test/system-io.mjs',
  'test/test-integrity.mjs',
  'test/test-json-reporter.mjs',
  'test/test-suite-runner.mjs',
  'test/verify-database-guard.mjs',
  'test/watchdog-contract.mjs',
  'test/worker-environment.mjs',
  'tsconfig.json',
]);
const phaseOrder = ['parallel', 'e2e', 'installer', 'lifecycle', 'scripts'];
const lifecycleTest = 'src/lib/processLifecycle.test.ts';
const defaultPhaseTimeoutMs = 30 * 60 * 1000;
const maximumPhaseTimeoutMs = 2 * 60 * 60 * 1000;
const defaultTestTimeoutMs = 2 * 60 * 1000;
const maximumTestTimeoutMs = 5 * 60 * 1000;
const e2eTestTimeoutMs = 5 * 60 * 1000;
const installerTestTimeoutMs = 25 * 60 * 1000;
const phaseTerminationGraceMs = 5_000;
const watchdogReadinessTimeoutMs = 10_000;
const footprintPollIntervalMs = 250;
const orphanHeartbeatStaleMs = 60_000;
const tempRootOwnerFile = '.runner-owner.json';
const mebibyte = 1024 * 1024;
const gibibyte = 1024 * mebibyte;
const defaultMaximumWorkerBytes = 256 * mebibyte;
const hardMaximumWorkerBytes = 512 * mebibyte;
const defaultMaximumSuiteBytes = 512 * mebibyte;
const hardMaximumSuiteBytes = 1024 * mebibyte;
const defaultMaximumSqliteBytes = 128 * mebibyte;
const hardMaximumSqliteBytes = 256 * mebibyte;
const defaultMaximumProcessWriteBytes = 4096 * mebibyte;
const hardMaximumProcessWriteBytes = 4096 * mebibyte;
const defaultMaximumSystemDiskTransferBytes = 2048 * mebibyte;
const hardMaximumSystemDiskTransferBytes = 4096 * mebibyte;
const minimumStartingFreeBytes = 10 * gibibyte;
const minimumRuntimeFreeBytes = 2 * gibibyte;
const maximumFailureDiagnostics = 20;
const maximumFailureMessageCharacters = 1_000;
const maximumCapturedOutputTailBytes = 16 * 1024;
const maximumLiveDatabaseInspectionOutputBytes = 64 * 1024;
const maximumLiveDatabaseInspectionDiagnosticCharacters = 2_048;
const liveDatabaseInspectionTimeoutMs = 15_000;
const defaultSuiteLockPath = join(
  tmpdir(),
  `openclaw-radar-test-suite-${repositoryIdentity.slice(0, 16)}.lock.sqlite`,
);
const forbiddenForwardedOptions = [
  '--experimental-test-isolation',
  '--test',
  '--test-concurrency',
  '--test-force-exit',
  '--test-name-pattern',
  '--test-only',
  '--test-reporter',
  '--test-reporter-destination',
  '--test-rerun-failures',
  '--test-shard',
  '--test-skip-pattern',
  '--watch',
];

export async function runTestSuite(options = {}) {
  assertSupportedNodeVersion();
  const suiteLock = acquireTestSuiteLock();
  let writerLock = null;
  try {
    writerLock = acquireRepositoryDatabaseWriterLock({
      repositoryRoot: canonicalRoot,
      label: 'authoritative test suite',
    });
    return await runTestSuiteUnlocked({
      ...options,
      globalWriterLockPath: writerLock.path,
    });
  } finally {
    writerLock?.release();
    suiteLock.release();
  }
}

export function acceptTestBaselineCandidate({
  allowBootstrap = false,
} = {}) {
  assertSupportedNodeVersion();
  const suiteLock = acquireTestSuiteLock();
  let writerLock = null;
  try {
    writerLock = acquireRepositoryDatabaseWriterLock({
      repositoryRoot: canonicalRoot,
      label: 'test baseline acceptance',
    });
    const manifest = readTestManifest();
    const tree = captureTestTree(manifest);
    return acceptTestBaselineCandidateFiles({
      allowBootstrap,
      baselineFilePath: baselinePath,
      candidateFilePath: baselineCandidatePath,
      candidateDisplayPath: relative(root, baselineCandidatePath),
      manifest,
      tree,
      captureTree: (excludedPath) => captureTestTree(manifest, {
        excludedPath,
      }),
    });
  } finally {
    writerLock?.release();
    suiteLock.release();
  }
}

export function inspectTestBaselineCandidate({
  baselineFilePath = baselinePath,
  candidateFilePath = baselineCandidatePath,
  candidateDisplayPath = relative(root, baselineCandidatePath),
  manifest: providedManifest,
  tree: providedTree,
  captureTree: providedCaptureTree,
} = {}) {
  try {
    const {
      snapshot: candidateBefore,
      value: candidate,
    } = readJsonFileSnapshot(candidateFilePath);
    if (!candidateBefore.exists || !candidate) {
      return {
        current: false,
        status: 'missing',
        reason: `No generated baseline candidate exists at ${candidateDisplayPath}.`,
        candidate: null,
      };
    }
    const {
      snapshot: baselineBefore,
      value: previousBaseline,
    } = readJsonFileSnapshot(baselineFilePath);
    const manifest = providedManifest ?? readTestManifest();
    const tree = providedTree ?? captureTestTree(manifest);
    const captureTree = providedCaptureTree ??
      (
        providedTree === undefined
          ? (excludedPath) => captureTestTree(manifest, {
            excludedPath,
          })
          : () => tree
      );
    return inspectLoadedTestBaselineCandidate({
      baselineFilePath,
      baselineBefore,
      candidate,
      candidateBefore,
      candidateDisplayPath,
      candidateFilePath,
      captureTree,
      manifest,
      previousBaseline,
      tree,
    });
  } catch (error) {
    return {
      current: false,
      status: 'stale',
      reason: normalizeError(error).message,
      candidate: null,
    };
  }
}

export function acceptTestBaselineCandidateFiles({
  allowBootstrap = false,
  baselineFilePath,
  candidateFilePath,
  candidateDisplayPath = candidateFilePath,
  manifest,
  tree,
  captureTree = () => tree,
  acceptedAt = new Date().toISOString(),
} = {}) {
  const {
    snapshot: baselineBefore,
    value: previousBaseline,
  } = readJsonFileSnapshot(baselineFilePath);
  const {
    snapshot: candidateBefore,
    value: candidate,
  } = readJsonFileSnapshot(candidateFilePath);
  if (!candidateBefore.exists || !candidate) {
    throw new Error(
      `No generated baseline candidate exists at ${candidateDisplayPath}.`,
    );
  }
  assertBaselineCandidateCurrent(candidate, tree, manifest);
  if (baselineCandidateFileDigest(candidate) !== candidateBefore.digest) {
    throw new Error(
      'Generated test baseline candidate file serialization is invalid; ' +
      'regenerate it.',
    );
  }

  if (
    isAcceptedBaseline(previousBaseline) &&
    acceptedBaselineMatchesCandidate(
      previousBaseline,
      candidate,
      candidateBefore.digest,
    )
  ) {
    assertFileSnapshotUnchanged(
      baselineFilePath,
      baselineBefore,
      'accepted test baseline',
      'candidate acceptance recovery',
    );
    assertFileSnapshotUnchanged(
      candidateFilePath,
      candidateBefore,
      'test baseline candidate',
      'candidate acceptance recovery',
    );
    assertTreeUnchanged(tree, captureTree(), 'candidate acceptance recovery');
    removeAcceptedCandidate(candidateFilePath, candidateBefore);
    return previousBaseline;
  }

  if (
    candidate.previousBaselineExists !== baselineBefore.exists ||
    candidate.previousBaselineDigest !== baselineBefore.digest
  ) {
    throw new Error(
      'Accepted baseline changed after candidate generation; regenerate the candidate.',
    );
  }
  const bootstrapRequired = baselineRequiresBootstrap(previousBaseline);
  if (candidate.bootstrap !== bootstrapRequired) {
    throw new Error(
      'Generated test baseline candidate bootstrap state is stale; regenerate it.',
    );
  }
  if (bootstrapRequired && !allowBootstrap) {
    throw new Error(
      'Initial baseline acceptance requires the explicit --bootstrap flag.',
    );
  }
  assertNoBaselineRegression(candidate, previousBaseline);
  const accepted = acceptedBaselineFromCandidate(
    candidate,
    candidateBefore.digest,
    acceptedAt,
  );
  if (!isAcceptedBaseline(accepted)) {
    throw new Error(
      'Generated accepted test baseline provenance is invalid; refusing acceptance.',
    );
  }
  writeJsonAtomically(baselineFilePath, accepted, {
    targetBefore: baselineBefore,
    invariants: [
      {
        path: candidateFilePath,
        snapshot: candidateBefore,
        label: 'test baseline candidate',
      },
    ],
    expectedTree: tree,
    captureTree,
  });
  removeAcceptedCandidate(candidateFilePath, candidateBefore);
  return accepted;
}

async function runTestSuiteUnlocked({
  mode,
  dryRun = false,
  rerun = false,
  forwardedArgs = [],
  globalWriterLockPath,
} = {}) {
  if (mode !== 'verify' && mode !== 'generate') {
    throw new Error(`Unsupported test-suite mode: ${String(mode)}`);
  }
  if (mode === 'verify' && dryRun) {
    throw new Error('Dry-run is available only for explicit baseline generation.');
  }
  assertAuthoritativeArguments(forwardedArgs);

  const {
    snapshot: baselineBefore,
    value: baselineValue,
  } = readJsonFileSnapshot(baselinePath);
  if (!baselineBefore.exists || !baselineValue) {
    throw new Error(
      'The explicit test baseline trust-root file is missing.',
    );
  }
  const integrityBaseline = {
    ...baselineValue,
    skipAllowlist: TEST_INTEGRITY_SKIP_ALLOWLIST,
  };
  const manifest = readTestManifest();
  const initialTree = captureTestTree(manifest);
  assertExactManifest(manifest, initialTree.files);

  if (mode === 'verify') {
    assertGeneratedBaseline(
      manifest,
      initialTree,
      baselineValue,
      integrityBaseline,
    );
  } else {
    baselineRequiresBootstrap(baselineValue);
  }

  if (mode === 'generate' && !rerun) {
    const inspection = inspectTestBaselineCandidate({
      manifest,
      tree: initialTree,
      captureTree: (excludedPath) => captureTestTree(manifest, {
        excludedPath,
      }),
    });
    if (inspection.current) {
      console.log(
        '[test-runner] reusing current test/test-baseline.candidate.json; ' +
        'pass --rerun to regenerate it.',
      );
      return {
        ok: true,
        interruptedBy: null,
        phaseResults: [],
        generationCandidate: inspection.candidate,
        dryRun,
        reusedCandidate: true,
      };
    }
  }
  const baselineCandidateBefore = captureFileSnapshot(baselineCandidatePath);
  const {
    liveDatabase: configuredLiveDatabase,
    fingerprint: initialLiveFingerprint,
  } = inspectConfiguredLiveDatabaseUnderWriteBoundary({
    repositoryRoot: root,
  });
  const initialLiveMetadata =
    sqliteFamilyMetadataFromFingerprint(initialLiveFingerprint);
  const runId = randomUUID();
  const codeRevision = `test-suite-${initialTree.harnessDigest.slice(0, 24)}`;
  const phaseTimeoutMs = resolvePhaseTimeout();
  const testTimeoutMs = resolveTestTimeout();
  const resourceLimits = resolveTestResourceLimits();
  const inheritedEnvironment = sanitizeTestChildEnvironment({
    environment: process.env,
    liveDatabase: configuredLiveDatabase,
  });
  const {
    auditPath,
    controlRoot,
    databaseGuardPolicyPath,
    delegatedWriterLock,
    emptyDotenvPath,
    installerFixtureIdentity,
    installerFixturePath,
    runnerDatabasePath,
    tempRoot,
    watchdog,
    writeBoundary,
    writerEnvironment,
  } = await initializeRunResources({
    runId,
    limits: resourceLimits,
    globalWriterLockPath,
    configuredLiveDatabase,
    initialLiveFingerprint,
    watchdogEnvironment: inheritedEnvironment,
  });
  const guardNodeOptions = [
    `--import=${pathToFileURL(workerEnvironmentPath).href}`,
    `--import=${pathToFileURL(databaseGuardPath).href}`,
  ].join(' ');
  const nodeOptions = [
    guardNodeOptions,
    '--import=tsx',
  ].join(' ');
  const environment = {
    ...inheritedEnvironment,
    ...writerEnvironment,
    DB_PATH: runnerDatabasePath,
    DOTENV_CONFIG_PATH: emptyDotenvPath,
    NODE_ENV: 'test',
    NODE_OPTIONS: nodeOptions,
    RADAR_CODE_REVISION: codeRevision,
    RADAR_DB_READ_ONLY: '0',
    RADAR_TEST_CODE_REVISION: codeRevision,
    RADAR_TEST_DATABASE_GUARD_POLICY: databaseGuardPolicyPath,
    RADAR_TEST_DATABASE_GUARD_POLICY_DIGEST: writeBoundary.policyDigest,
    RADAR_TEST_DB_AUDIT: auditPath,
    RADAR_TEST_PROCESS_IDENTITY_HELPER:
      writeBoundary.processIdentityHelper.path,
    RADAR_TEST_PROCESS_IDENTITY_HELPER_IDENTITY: JSON.stringify(
      writeBoundary.processIdentityHelper,
    ),
    RADAR_TEST_RUN_ID: runId,
    RADAR_TEST_SANDBOX_BACKEND: writeBoundary.backend,
    RADAR_TEST_SANDBOX_PROFILE_DIGEST: writeBoundary.profileDigest,
    RADAR_TEST_SQLITE_MAX_MIB: String(
      resourceLimits.maximumSqliteBytes / mebibyte,
    ),
    RADAR_DB_BOOTSTRAP_MODE: 'fresh',
    RADAR_TEST_TEMP_ROOT: tempRoot,
  };

  let activeChild = null;
  let activeProcessGroupPid = null;
  let activeFootprintMonitor = null;
  let preserveTempRoot = false;
  let interruptedBy = null;
  let signalCount = 0;
  let forcedTermination = null;
  const asynchronousFailures = createFailureChannel();
  const clearForcedTermination = () => {
    if (forcedTermination) clearTimeout(forcedTermination);
    forcedTermination = null;
  };
  const terminateActiveChild = (signal, forceAfterGrace = false) => {
    if (!activeChild && !activeProcessGroupPid) return;
    if (activeChild) killProcessTree(activeChild, signal);
    if (activeProcessGroupPid) {
      try {
        signalProcessGroup(activeProcessGroupPid, signal);
      } catch (error) {
        asynchronousFailures.report(error);
      }
    }
    if (signal === 'SIGKILL' || !forceAfterGrace || forcedTermination) return;
    forcedTermination = setTimeout(() => {
      try {
        if (activeChild) killProcessTree(activeChild, 'SIGKILL');
        if (activeProcessGroupPid) {
          signalProcessGroup(activeProcessGroupPid, 'SIGKILL');
        }
      } catch (error) {
        asynchronousFailures.report(error);
      }
    }, phaseTerminationGraceMs);
    forcedTermination.unref();
  };
  const forwardSignal = (signal) => {
    try {
      signalCount += 1;
      interruptedBy ??= signal;
      terminateActiveChild(
        signalCount > 1 ? 'SIGKILL' : signal,
        signalCount === 1,
      );
    } catch (error) {
      asynchronousFailures.report(error);
    }
  };
  const signalHandlers = new Map(
    ['SIGINT', 'SIGTERM'].map((signal) => [
      signal,
      () => forwardSignal(signal),
    ]),
  );
  for (const [signal, handler] of signalHandlers) process.on(signal, handler);

  const phaseResults = [];
  const attemptedFiles = new Set();
  let generationCandidate = null;
  let completedTree = null;
  let successfulResult = null;
  let bodyFailure = null;
  let watchdogReceipt = null;
  try {
    try {
      for (const phase of phaseOrder) {
      if (interruptedBy) break;
      assertTreeUnchanged(
        initialTree,
        captureTestTree(manifest),
        `${phase} phase start`,
      );
      assertNoOpenLiveDatabaseDescriptors(initialLiveFingerprint);
      const files = manifest.phases[phase];
      const phaseStartedAt = performance.now();
      for (const file of files) attemptedFiles.add(file);
      const eventLogPath = join(tempRoot, `${phase}-events.jsonl`);
      const phaseOutputPath = join(tempRoot, `${phase}-output.log`);
      console.log(
        `[test-runner] ${phase}: ${files.length} file${files.length === 1 ? '' : 's'}`,
      );
      const command = testCommand({
        phase,
        files,
        eventLogPath,
        testTimeoutMs: phase === 'e2e'
          ? e2eTestTimeoutMs
          : phase === 'installer'
            ? installerTestTimeoutMs
            : testTimeoutMs,
      });
      const phaseLaunch = writeBoundary.wrapCommand(
        process.execPath,
        command,
      );
      const phaseEnvironment = phaseChildEnvironment({
        phase,
        environment,
        guardNodeOptions,
        installerFixturePath,
      });
      const phaseOutputDescriptor = openSync(
        phaseOutputPath,
        fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          fsConstants.O_WRONLY,
        0o600,
      );
      try {
        if (phase === 'installer') {
          assertPrivateInstallerFixtureUnchanged(
            installerFixtureIdentity,
          );
        }
        activeChild = spawn(phaseLaunch.command, phaseLaunch.args, {
          cwd: root,
          detached: process.platform !== 'win32',
          env: phaseEnvironment,
          stdio: [
            'ignore',
            phaseOutputDescriptor,
            phaseOutputDescriptor,
          ],
        });
        activeChild.once('exit', (code, signal) => {
          if (code !== 0 || signal !== null) preserveTempRoot = true;
        });
      } finally {
        closeSync(phaseOutputDescriptor);
      }
      const phaseChild = activeChild;
      activeProcessGroupPid = phaseChild.pid;
      watchdog.setActiveProcessGroup(phaseChild.pid, {
        allowedCommandDigests: [
          sha256(canonicalPath(process.execPath)),
        ],
      });
      const footprintMonitor = startFootprintMonitor({
        tempRoot,
        auditPath,
        runId,
        limits: resourceLimits,
      });
      activeFootprintMonitor = footprintMonitor;
      let exit;
      let phaseFailure = null;
      const childOutcome = waitForChild(phaseChild, {
        label: `${phase} test phase`,
        timeoutMs: phaseTimeoutMs,
      }).then(
        (value) => ({ kind: 'exit', value }),
        (error) => ({ kind: 'failure', error: normalizeError(error) }),
      );
      const outcome = await Promise.race([
        childOutcome,
        footprintMonitor.failure.then((error) => ({
          kind: 'failure',
          error,
        })),
        watchdog.failure.then((error) => ({
          kind: 'failure',
          error,
        })),
        asynchronousFailures.promise.then((error) => ({
          kind: 'failure',
          error,
        })),
      ]);
      if (outcome.kind === 'exit') {
        exit = outcome.value;
      } else {
        phaseFailure = outcome.error;
        preserveTempRoot = true;
        terminateActiveChild('SIGTERM', true);
      }
      const resourceBreach =
        latestWatchdogResourceBreach(auditPath, runId);
      if (resourceBreach) {
        preserveTempRoot = true;
        phaseFailure = combineErrors(
          phaseFailure,
          [watchdogResourceBreachError(resourceBreach, phase)],
          `${phase} phase failed after a validation resource breach`,
        );
      }

      const phaseCleanupErrors = [];
      await runCleanupStep(
        phaseCleanupErrors,
        `${phase} footprint monitor`,
        () => footprintMonitor.stop(),
      );
      activeFootprintMonitor = null;
      let processGroupStopped = false;
      await runCleanupStep(
        phaseCleanupErrors,
        `${phase} process group`,
        async () => {
          processGroupStopped =
            await terminateProcessTreeAndWait(phaseChild);
          if (!processGroupStopped) {
            throw new Error(
              `${phase} test process left an unkillable process group ` +
              `${String(phaseChild.pid)}; temporary diagnostics are preserved.`,
            );
          }
        },
      );
      if (processGroupStopped) {
        clearForcedTermination();
        activeChild = null;
        activeProcessGroupPid = null;
        await runCleanupStep(
          phaseCleanupErrors,
          `${phase} watchdog process-group release`,
          () => watchdog.setActiveProcessGroup(null),
        );
        if (phase === 'installer') {
          await runCleanupStep(
            phaseCleanupErrors,
            'installer fixture post-phase integrity',
            () => assertPrivateInstallerFixtureUnchanged(
              installerFixtureIdentity,
              'after installer phase',
            ),
          );
        }
      } else {
        preserveTempRoot = true;
      }
      await runCleanupStep(
        phaseCleanupErrors,
        `${phase} exited worker cleanup`,
        () => cleanupExitedWorkerDirectories({
          tempRoot,
          auditPath,
          runId,
        }),
      );
      phaseFailure = combineErrors(
        phaseFailure,
        phaseCleanupErrors,
        `${phase} phase failed and cleanup was incomplete`,
      );
      if (phaseFailure) {
        printPhaseFailureDiagnostics({
          phase,
          eventLogPath,
          phaseOutputPath,
        });
        throw phaseFailure;
      }

      if (interruptedBy) break;
      if (exit.code !== 0 || exit.signal !== null) {
        preserveTempRoot = true;
        printPhaseFailureDiagnostics({
          phase,
          eventLogPath,
          phaseOutputPath,
        });
        throw new Error(
          `${phase} test process failed with ` +
          `${exit.signal ? `signal ${exit.signal}` : `exit code ${exit.code}`}.`,
        );
      }
      const events = readTestEventLog(eventLogPath);
      const integrity = mode === 'generate'
        ? generatePhaseBaseline({
          phase,
          label: `${phase} tests`,
          root,
          expectedFiles: files,
          events,
          baseline: integrityBaseline,
        })
        : verifyPhaseIntegrity({
          phase,
          label: `${phase} tests`,
          root,
          expectedFiles: files,
          events,
          baseline: integrityBaseline,
        });
      const durationMs = performance.now() - phaseStartedAt;
      console.log(
        mode === 'generate'
          ? `[test-runner] ${phase} passed with ` +
            `${integrity.minimumPassed} baseline pass credit in ` +
            `${(durationMs / 1000).toFixed(1)}s`
          : `[test-runner] ${phase} passed: ` +
            `${integrity.counts.passed}/${integrity.counts.tests} tests in ` +
            `${(durationMs / 1000).toFixed(1)}s`,
      );
      assertSqliteFamilyMetadataUnchanged(
        configuredLiveDatabase,
        initialLiveMetadata,
        `${phase} phase`,
      );
      assertTreeUnchanged(
        initialTree,
        captureTestTree(manifest),
        `${phase} phase completion`,
      );
      phaseResults.push({
        phase,
        files,
        integrity,
        exit,
        durationMs,
        executionInputDigest: initialTree.harnessDigest,
      });
    }

    if (interruptedBy) {
      return {
        ok: false,
        interruptedBy,
        phaseResults,
      };
    }

    assertDatabaseAudit({
      auditPath,
      expectedFiles: phaseOrder.flatMap((phase) => manifest.phases[phase]),
      tempRoot,
      liveDatabase: configuredLiveDatabase,
      runId,
      requireCompleteCoverage: true,
    });
    assertFileSnapshotUnchanged(
      baselinePath,
      baselineBefore,
      'accepted test baseline',
      'test run',
    );
    const finalTree = captureTestTree(manifest);
    assertTreeUnchanged(initialTree, finalTree, 'test run');
    completedTree = finalTree;
    assertSqliteFamilyUnchanged(
      configuredLiveDatabase,
      initialLiveFingerprint,
      'complete test suite',
    );

    if (mode === 'generate') {
      generationCandidate = sealBaselineCandidate({
        schemaVersion: 2,
        kind: 'test-baseline-candidate',
        manifestDigest: finalTree.manifestDigest,
        testTreeDigest: finalTree.testTreeDigest,
        harnessDigest: finalTree.harnessDigest,
        generatedAt: new Date().toISOString(),
        runId,
        bootstrap: baselineRequiresBootstrap(baselineValue),
        previousBaselineExists: baselineBefore.exists,
        previousBaselineDigest: baselineBefore.digest,
        phases: Object.fromEntries(
          phaseResults.map(({ phase, integrity }) => [phase, integrity]),
        ),
      });
      assertNoBaselineRegression(generationCandidate, baselineValue);
    }

      successfulResult = {
        ok: true,
        interruptedBy: null,
        phaseResults,
        generationCandidate,
        dryRun,
      };
    } catch (error) {
      bodyFailure = normalizeError(error);
      throw bodyFailure;
    }
  } finally {
    const cleanupErrors = [];
    let delegatedWriterLockReleased = false;
    if (activeFootprintMonitor) {
      await runCleanupStep(
        cleanupErrors,
        'active footprint monitor',
        () => activeFootprintMonitor.stop(),
      );
      activeFootprintMonitor = null;
    }
    if (activeChild) {
      let stopped = false;
      await runCleanupStep(
        cleanupErrors,
        'active test process group',
        async () => {
          stopped = await terminateProcessTreeAndWait(activeChild);
          if (!stopped) {
            throw new Error(
              `Unable to terminate test process group ` +
              `${String(activeChild.pid)}.`,
            );
          }
        },
      );
      if (stopped) {
        activeChild = null;
        activeProcessGroupPid = null;
        await runCleanupStep(
          cleanupErrors,
          'watchdog process-group release',
          () => watchdog.setActiveProcessGroup(null),
        );
      } else {
        preserveTempRoot = true;
      }
    }
    clearForcedTermination();
    for (const [signal, handler] of signalHandlers) {
      process.off(signal, handler);
    }
    await runCleanupStep(
      cleanupErrors,
      'exited worker cleanup',
      () => cleanupExitedWorkerDirectories({
        tempRoot,
        auditPath,
        runId,
      }),
    );
    if (activeProcessGroupPid === null) {
      await runCleanupStep(
        cleanupErrors,
        'delegated repository writer lock release',
        () => {
          delegatedWriterLock.release();
          delegatedWriterLockReleased = true;
        },
      );
      if (!delegatedWriterLockReleased) preserveTempRoot = true;
    }
    await runCleanupStep(
      cleanupErrors,
      'runner finish audit event',
      () => appendAuditEvent(auditPath, {
        type: 'runner-finish',
        runId,
        pid: process.pid,
        interruptedBy,
        primaryFailure: bodyFailure?.message ?? null,
        cleanupFailures: cleanupErrors.map((error) => error.message),
        preservedTempRoot: preserveTempRoot,
        finishedAt: new Date().toISOString(),
      }),
    );
    await runCleanupStep(
      cleanupErrors,
      'live database family verification',
      () => assertSqliteFamilyUnchanged(
        configuredLiveDatabase,
        initialLiveFingerprint,
        bodyFailure || interruptedBy
          ? 'failed or interrupted test suite'
          : 'test suite cleanup',
      ),
    );
    await runCleanupStep(
      cleanupErrors,
      'database audit verification',
      () => assertDatabaseAudit({
        auditPath,
        expectedFiles: [...attemptedFiles],
        tempRoot,
        liveDatabase: configuredLiveDatabase,
        runId,
        requireCompleteCoverage: false,
      }),
    );
    await runCleanupStep(
      cleanupErrors,
      'accepted test baseline verification',
      () => assertFileSnapshotUnchanged(
        baselinePath,
        baselineBefore,
        'accepted test baseline',
        'test suite cleanup',
      ),
    );
    if (cleanupErrors.length > 0) {
      preserveTempRoot = true;
    }
    if (activeProcessGroupPid === null) {
      await runCleanupStep(
        cleanupErrors,
        'resource watchdog completion',
        async () => {
          watchdogReceipt = await watchdog.complete({ preserveTempRoot });
        },
      );
    } else {
      await runCleanupStep(
        cleanupErrors,
        'resource watchdog handoff',
        () => watchdog.abandon(),
      );
    }
    await runCleanupStep(
      cleanupErrors,
      'resource watchdog terminal audit rescan',
      () => assertWatchdogTerminalAudit({
        auditPath,
        receipt: watchdogReceipt,
        receiptPath: watchdog.receiptPath,
        runId,
      }),
    );
    await runCleanupStep(
      cleanupErrors,
      'terminal database audit rescan',
      () => assertDatabaseAudit({
        auditPath,
        expectedFiles: [...attemptedFiles],
        tempRoot,
        liveDatabase: configuredLiveDatabase,
        runId,
        requireCompleteCoverage: false,
      }),
    );
    await runCleanupStep(
      cleanupErrors,
      'terminal live database family verification',
      () => {
        assertNoOpenLiveDatabaseDescriptors(initialLiveFingerprint);
        assertSqliteFamilyUnchanged(
          configuredLiveDatabase,
          initialLiveFingerprint,
          'terminal test suite verification',
        );
      },
    );
    if (cleanupErrors.length > 0) preserveTempRoot = true;
    if (!preserveTempRoot && activeProcessGroupPid === null) {
      await runCleanupStep(
        cleanupErrors,
        'test temporary root removal',
        () => rmSync(tempRoot, { recursive: true, force: true }),
      );
      await runCleanupStep(
        cleanupErrors,
        'test control root removal',
        () => rmSync(controlRoot, { recursive: true, force: true }),
      );
    } else {
      console.error(`[test-runner] preserved temporary diagnostics at ${tempRoot}`);
      console.error(`[test-runner] preserved safety controls at ${controlRoot}`);
    }
    const combinedFailure = combineErrors(
      bodyFailure,
      cleanupErrors,
      'Test suite failed and safety verification or cleanup was incomplete',
    );
    if (combinedFailure) throw combinedFailure;
  }
  if (!successfulResult || !completedTree) {
    throw new Error('Test suite completed without a verified result.');
  }
  if (mode === 'generate' && generationCandidate) {
    if (dryRun) {
      console.log('[test-runner] baseline dry-run complete; no file was written.');
      console.log(JSON.stringify(generationCandidate, null, 2));
    } else {
      writeJsonAtomically(baselineCandidatePath, generationCandidate, {
        targetBefore: baselineCandidateBefore,
        invariants: [
          {
            path: baselinePath,
            snapshot: baselineBefore,
            label: 'accepted test baseline',
          },
        ],
        expectedTree: completedTree,
        captureTree: (excludedPath) => captureTestTree(manifest, {
          excludedPath,
        }),
      });
      console.log(
        `[test-runner] wrote ${relative(root, baselineCandidatePath)} ` +
        `for explicit review and acceptance.`,
      );
    }
  }
  assertNoOpenLiveDatabaseDescriptors(initialLiveFingerprint);
  assertSqliteFamilyUnchanged(
    configuredLiveDatabase,
    initialLiveFingerprint,
    'test suite return',
  );
  return successfulResult;
}

export function resolvePhaseTimeout({
  environment = process.env,
} = {}) {
  const raw = environment.RADAR_TEST_PHASE_TIMEOUT_MS;
  if (raw == null || raw === '') return defaultPhaseTimeoutMs;
  if (!/^[1-9]\d*$/.test(raw)) {
    throw new Error(
      'RADAR_TEST_PHASE_TIMEOUT_MS must be an integer from 1000 to ' +
      `${maximumPhaseTimeoutMs}, got ${raw}.`,
    );
  }
  const requested = Number(raw);
  if (requested < 1_000 || requested > maximumPhaseTimeoutMs) {
    throw new Error(
      'RADAR_TEST_PHASE_TIMEOUT_MS must be an integer from 1000 to ' +
      `${maximumPhaseTimeoutMs}, got ${raw}.`,
    );
  }
  return requested;
}

export function resolveTestTimeout({
  environment = process.env,
} = {}) {
  const raw = environment.RADAR_TEST_TIMEOUT_MS;
  if (raw == null || raw === '') return defaultTestTimeoutMs;
  if (!/^[1-9]\d*$/.test(raw)) {
    throw new Error(
      'RADAR_TEST_TIMEOUT_MS must be an integer from 1000 to ' +
      `${maximumTestTimeoutMs}, got ${raw}.`,
    );
  }
  const requested = Number(raw);
  if (requested < 1_000 || requested > maximumTestTimeoutMs) {
    throw new Error(
      'RADAR_TEST_TIMEOUT_MS must be an integer from 1000 to ' +
      `${maximumTestTimeoutMs}, got ${raw}.`,
    );
  }
  return requested;
}

export function resolveTestResourceLimits({
  environment = process.env,
} = {}) {
  return {
    maximumWorkerBytes: resolveMebibyteLimit({
      environment,
      name: 'RADAR_TEST_MAX_WORKER_MIB',
      fallbackBytes: defaultMaximumWorkerBytes,
      hardMaximumBytes: hardMaximumWorkerBytes,
    }),
    maximumSuiteBytes: resolveMebibyteLimit({
      environment,
      name: 'RADAR_TEST_MAX_SUITE_MIB',
      fallbackBytes: defaultMaximumSuiteBytes,
      hardMaximumBytes: hardMaximumSuiteBytes,
    }),
    maximumSqliteBytes: resolveMebibyteLimit({
      environment,
      name: 'RADAR_TEST_SQLITE_MAX_MIB',
      fallbackBytes: defaultMaximumSqliteBytes,
      hardMaximumBytes: hardMaximumSqliteBytes,
    }),
    maximumProcessWriteBytes: resolveMebibyteLimit({
      environment,
      name: 'RADAR_TEST_MAX_PROCESS_WRITE_MIB',
      fallbackBytes: defaultMaximumProcessWriteBytes,
      hardMaximumBytes: hardMaximumProcessWriteBytes,
    }),
    maximumSystemDiskTransferBytes: resolveMebibyteLimit({
      environment,
      name: 'RADAR_TEST_MAX_SYSTEM_IO_MIB',
      fallbackBytes: defaultMaximumSystemDiskTransferBytes,
      hardMaximumBytes: hardMaximumSystemDiskTransferBytes,
    }),
    minimumStartingFreeBytes,
    minimumRuntimeFreeBytes,
  };
}

function resolveMebibyteLimit({
  environment,
  name,
  fallbackBytes,
  hardMaximumBytes,
}) {
  const raw = environment[name];
  if (raw == null || raw === '') return fallbackBytes;
  const hardMaximumMiB = hardMaximumBytes / mebibyte;
  if (!/^[1-9]\d*$/.test(raw)) {
    throw new Error(
      `${name} must be an integer from 1 to ${hardMaximumMiB}, got ${raw}.`,
    );
  }
  const requestedBytes = Number(raw) * mebibyte;
  if (requestedBytes > hardMaximumBytes) {
    throw new Error(
      `${name}=${raw} exceeds the non-disableable safety maximum ` +
      `${hardMaximumMiB}.`,
    );
  }
  return requestedBytes;
}

export function acquireTestSuiteLock({
  lockPath = defaultSuiteLockPath,
  pid = process.pid,
  startedAt = new Date().toISOString(),
  registerExitHandler = true,
} = {}) {
  return acquireExclusiveProcessLock({
    lockPath,
    label: 'authoritative test suite',
    resourceLabel: 'authoritative test suite',
    pid,
    startedAt,
    registerExitHandler,
  });
}

export function assertAuthoritativeArguments(args) {
  if (!Array.isArray(args)) {
    throw new Error('Forwarded test arguments must be an array.');
  }
  const rejected = [];
  for (const rawArgument of args) {
    const argument = String(rawArgument);
    const option = argument.split('=', 1)[0];
    if (!argument.startsWith('-') ||
        forbiddenForwardedOptions.includes(option)) {
      rejected.push(argument);
      continue;
    }
    rejected.push(argument);
  }
  if (rejected.length > 0) {
    throw new Error(
      'The authoritative suite does not accept forwarded arguments because they can ' +
      `change test coverage or runner safety: ${rejected.join(', ')}`,
    );
  }
}

export function readTestManifest({
  path = manifestPath,
} = {}) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to read test manifest ${path}: ${error.message}`);
  }
  if (value?.schemaVersion !== 1 ||
      !value.phases ||
      typeof value.phases !== 'object' ||
      Array.isArray(value.phases)) {
    throw new Error('Test manifest must use schemaVersion 1 with a phases object.');
  }
  const keys = Object.keys(value.phases);
  if (keys.length !== phaseOrder.length ||
      phaseOrder.some((phase) => !keys.includes(phase))) {
    throw new Error(
      `Test manifest phases must be exactly: ${phaseOrder.join(', ')}.`,
    );
  }

  const seen = new Set();
  for (const phase of phaseOrder) {
    const files = value.phases[phase];
    if (!Array.isArray(files) || files.length === 0) {
      throw new Error(`Test manifest phase ${phase} must be a non-empty array.`);
    }
    const sorted = [...files].sort((left, right) => left.localeCompare(right));
    if (files.some((file, index) => file !== sorted[index])) {
      throw new Error(`Test manifest phase ${phase} must be sorted.`);
    }
    for (const file of files) {
      assertManifestPath(file, phase);
      if (seen.has(file)) {
        throw new Error(`Test manifest contains duplicate file ${file}.`);
      }
      seen.add(file);
    }
  }
  if (!value.phases.lifecycle.includes(lifecycleTest)) {
    throw new Error(`${lifecycleTest} must run in the serialized lifecycle phase.`);
  }
  return value;
}

export function discoverTestFiles({
  repositoryRoot = root,
} = {}) {
  const sourceRoot = join(repositoryRoot, 'src');
  const scriptRoot = join(repositoryRoot, 'scripts');
  const sourceCandidates = walkFiles(sourceRoot)
    .filter((path) => /\.(?:[cm]?[jt]s|tsx)$/.test(path))
    .filter((path) =>
      /\.(?:test|spec)\.(?:[cm]?[jt]s|tsx)$/.test(path) ||
      /\bnode:test\b/.test(readFileSync(path, 'utf8')));
  const unsupportedSourceTests = sourceCandidates
    .map((path) => normalizePath(relative(repositoryRoot, path)))
    .filter((path) => !/^src\/lib\/[^/]+\.test\.ts$/.test(path));
  if (unsupportedSourceTests.length > 0) {
    throw new Error(
      `Unsupported source test location or naming: ` +
      unsupportedSourceTests.sort().join(', '),
    );
  }
  const libraryTests = sourceCandidates
    .map((path) => normalizePath(relative(repositoryRoot, path)));
  const scriptTests = walkFiles(scriptRoot)
    .filter((path) =>
      /\.(?:test|spec)\.(?:[cm]?[jt]s|tsx)$/.test(path) ||
      (
        /\.(?:[cm]?[jt]s|tsx)$/.test(path) &&
        /\bnode:test\b/.test(readFileSync(path, 'utf8'))
      ))
    .map((path) => normalizePath(relative(repositoryRoot, path)));
  return [...libraryTests, ...scriptTests]
    .sort((left, right) => left.localeCompare(right));
}

export function assertExactManifest(manifest, discoveredFiles) {
  const manifestFiles = phaseOrder.flatMap((phase) => manifest.phases[phase]);
  const manifestSet = new Set(manifestFiles);
  const discoveredSet = new Set(discoveredFiles);
  const missing = [...discoveredSet].filter((file) => !manifestSet.has(file));
  const extra = [...manifestSet].filter((file) => !discoveredSet.has(file));
  if (missing.length > 0 || extra.length > 0) {
    const details = [
      missing.length > 0 ? `missing: ${missing.join(', ')}` : null,
      extra.length > 0 ? `extra: ${extra.join(', ')}` : null,
    ].filter(Boolean);
    throw new Error(`Test manifest does not match discovery (${details.join('; ')}).`);
  }
}

function captureTestTree(manifest, {
  excludedPath,
} = {}) {
  const files = discoverTestFiles();
  assertExactManifest(manifest, files);
  const manifestDigest = sha256(
    JSON.stringify({
      schemaVersion: manifest.schemaVersion,
      phases: Object.fromEntries(
        phaseOrder.map((phase) => [phase, manifest.phases[phase]]),
      ),
    }),
  );
  const testTreeDigest = sha256(
    files
      .map((file) => `${file}\0${sha256(readFileSync(join(root, file)))}\n`)
      .join(''),
  );
  const executionIdentity = captureExecutionInputIdentity({
    excludedPath,
    repositoryRoot: root,
  });
  return {
    files,
    executionInputs: executionIdentity.files,
    manifestDigest,
    testTreeDigest,
    harnessDigest: executionIdentity.digest,
  };
}

export function captureExecutionInputIdentity({
  excludedPath,
  repositoryRoot = root,
} = {}) {
  const files = discoverExecutionInputFiles({
    excludedPath,
    repositoryRoot,
  });
  return {
    files,
    digest: executionInputDigest({
      repositoryRoot,
      files,
    }),
  };
}

export function discoverExecutionInputFiles({
  excludedPath,
  repositoryRoot = root,
} = {}) {
  const excludedAbsolutePath =
    typeof excludedPath === 'string' ? resolve(excludedPath) : null;
  const files = new Set();
  for (const file of executionInputRootFiles) {
    const absolute = join(repositoryRoot, file);
    if (excludedAbsolutePath === resolve(absolute)) continue;
    if (existsSync(absolute) && lstatSync(absolute).isFile()) files.add(file);
  }
  for (const directory of executionInputDirectories) {
    const absolute = join(repositoryRoot, directory);
    if (!existsSync(absolute) || !lstatSync(absolute).isDirectory()) continue;
    for (const path of walkInputEntries(absolute)) {
      if (excludedAbsolutePath === resolve(path)) continue;
      const file = normalizePath(relative(repositoryRoot, path));
      if (
        excludedExecutionInputs.has(file) ||
        ignoredExecutionInputNames.has(basename(file))
      ) {
        continue;
      }
      files.add(file);
    }
  }
  return [...files].sort((left, right) => left.localeCompare(right));
}

function executionInputDigest({
  repositoryRoot,
  files,
}) {
  const digest = createHash('sha256');
  digest.update(canonicalJson({
    node: {
      arch: process.arch,
      executable: captureExecutableIdentity(process.execPath),
      platform: process.platform,
      version: process.version,
    },
    systemExecutables: allowedExecutableIdentities(),
    writeBoundary: process.platform === 'darwin'
      ? captureExecutableIdentity(sandboxExecutablePath)
      : null,
  }));
  digest.update('\n');
  for (const file of files) {
    const path = join(repositoryRoot, file);
    const stats = lstatSync(path);
    const mode = stats.mode & 0o7777;
    if (stats.isSymbolicLink()) {
      digest.update(`${file}\0symlink\0${mode.toString(8)}\0`);
      digest.update(readlinkSync(path));
      digest.update('\n');
      continue;
    }
    if (!stats.isFile()) {
      throw new Error(`Execution input is not a regular file or symlink: ${file}`);
    }
    digest.update(`${file}\0file\0${mode.toString(8)}\0`);
    digest.update(readFileSync(path));
    digest.update('\n');
  }
  return digest.digest('hex');
}

export function assertGeneratedBaseline(
  manifest,
  tree,
  baseline,
  validationBaseline = baseline,
) {
  if (!isAcceptedBaseline(baseline)) {
    throw new Error(
      'Test baseline is not an accepted schemaVersion 2 trust root; ' +
      'explicit candidate generation and acceptance are required.',
    );
  }
  for (const phase of phaseOrder) {
    validatePhaseBaseline({
      phase,
      label: `${phase} tests`,
      expectedFiles: manifest.phases[phase],
      baseline: validationBaseline,
    });
  }
  if (baseline.manifestDigest !== tree.manifestDigest) {
    throw new Error(
      'Test baseline manifest digest does not match the authoritative manifest; ' +
      'explicit regeneration is required.',
    );
  }
  if (baseline.testTreeDigest !== tree.testTreeDigest) {
    throw new Error(
      'Test baseline tree digest does not match the current test files; ' +
      'explicit regeneration is required.',
    );
  }
  if (baseline.harnessDigest !== tree.harnessDigest) {
    throw new Error(
      'Test baseline harness digest does not match the current integrity runner; ' +
      'explicit regeneration is required.',
    );
  }
}

export function testCommand({
  phase,
  files,
  eventLogPath,
  testTimeoutMs = phase === 'e2e'
    ? e2eTestTimeoutMs
    : phase === 'installer'
      ? installerTestTimeoutMs
      : defaultTestTimeoutMs,
}) {
  const isolationFlag = process.allowedNodeEnvironmentFlags.has(
    '--test-isolation',
  )
    ? '--test-isolation=process'
    : '--experimental-test-isolation=process';
  return [
    ...(phase === 'installer' ? ['--import=tsx'] : []),
    '--test',
    isolationFlag,
    '--test-concurrency=1',
    `--test-timeout=${testTimeoutMs}`,
    `--test-reporter=${reporterPath}`,
    `--test-reporter-destination=${eventLogPath}`,
    ...files,
  ];
}

export function summarizeFailedTestEvents(
  events,
  limit = maximumFailureDiagnostics,
) {
  if (!Number.isInteger(limit) || limit <= 0) {
    throw new Error('Failure diagnostic limit must be a positive integer');
  }
  const failures = [];
  const seen = new Set();
  for (const event of events) {
    if (
      event?.type !== 'test:fail' ||
      event?.data?.details?.type !== 'test'
    ) {
      continue;
    }
    const error = event.data.details.error?.cause ??
      event.data.details.error ??
      {};
    if (error.failureType === 'subtestsFailed') continue;
    const file = event.data.file
      ? relative(root, resolve(event.data.file))
      : '<unknown>';
    const line = Number.isInteger(event.data.line)
      ? event.data.line
      : null;
    const name = boundedDiagnosticText(event.data.name ?? '<unnamed>');
    const message = boundedDiagnosticText(
      error.message ??
        event.data.details.error?.message ??
        'test failed without an error message',
    );
    const key = JSON.stringify([file, line, name, message]);
    if (seen.has(key)) continue;
    seen.add(key);
    failures.push({ file, line, name, message });
    if (failures.length >= limit) break;
  }
  return failures;
}

function printPhaseFailureDiagnostics({
  phase,
  eventLogPath,
  phaseOutputPath,
}) {
  let events = [];
  try {
    events = readTestEventLog(eventLogPath);
  } catch {
    // A process-level crash can leave no complete event stream.
  }
  const failures = summarizeFailedTestEvents(events);
  if (failures.length > 0) {
    console.error(
      `[test-runner] ${phase} failed; showing ` +
      `${failures.length} bounded test diagnostic` +
      `${failures.length === 1 ? '' : 's'}:`,
    );
    for (const failure of failures) {
      console.error(
        `- ${failure.file}${failure.line == null ? '' : `:${failure.line}`} ` +
        `${failure.name}: ${failure.message}`,
      );
    }
    return;
  }
  const outputTail = readCapturedOutputTail(phaseOutputPath);
  console.error(
    `[test-runner] ${phase} failed before a structured test diagnostic ` +
    'was available.',
  );
  if (outputTail) console.error(outputTail);
}

function boundedDiagnosticText(value) {
  const normalized = String(value)
    .replace(/\s+/g, ' ')
    .trim();
  if (normalized.length <= maximumFailureMessageCharacters) return normalized;
  return `${normalized.slice(0, maximumFailureMessageCharacters - 15)}...[truncated]`;
}

function readCapturedOutputTail(path) {
  if (!existsSync(path)) return '';
  const size = lstatSync(path).size;
  const length = Math.min(size, maximumCapturedOutputTailBytes);
  if (length <= 0) return '';
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  try {
    const buffer = Buffer.allocUnsafe(length);
    const bytesRead = readSync(
      descriptor,
      buffer,
      0,
      length,
      Math.max(0, size - length),
    );
    return buffer.subarray(0, bytesRead).toString('utf8').trim();
  } finally {
    closeSync(descriptor);
  }
}

export function waitForChild(child, {
  label = 'child process',
  timeoutMs = null,
} = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolvePromise({
        code: child.exitCode,
        signal: child.signalCode,
      });
      return;
    }

    let settled = false;
    let timeout = null;
    const cleanup = () => {
      if (timeout) clearTimeout(timeout);
      child.off('error', onError);
      child.off('exit', onExit);
    };
    const reject = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      rejectPromise(normalizeError(error));
    };
    const resolveExit = (code, signal) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolvePromise({ code, signal });
    };
    const onError = (error) => {
      try {
        reject(error);
      } catch (callbackError) {
        reject(callbackError);
      }
    };
    const onExit = (code, signal) => {
      try {
        resolveExit(code, signal);
      } catch (callbackError) {
        reject(callbackError);
      }
    };
    child.once('error', onError);
    child.once('exit', onExit);
    if (timeoutMs !== null) {
      timeout = setTimeout(() => {
        try {
          killProcessTree(child, 'SIGTERM');
          reject(
            new Error(`${label} exceeded the ${timeoutMs}ms safety timeout.`),
          );
        } catch (error) {
          reject(error);
        }
      }, timeoutMs);
    }
  });
}

export function startFootprintMonitor({
  tempRoot,
  auditPath,
  runId,
  limits,
}) {
  let stopped = false;
  let breached = false;
  let peakSuiteBytes = 0;
  let peakWorkerBytes = 0;
  let minimumObservedFreeBytes = Number.POSITIVE_INFINITY;
  let breachFailure = null;
  const failure = createFailureChannel();
  const reportBreach = (error, event) => {
    breached = true;
    const errors = [normalizeError(error)];
    try {
      appendAuditEvent(auditPath, event);
    } catch (auditError) {
      errors.push(normalizeError(auditError));
    }
    breachFailure = failure.report(
      errors.length === 1
        ? errors[0]
        : new AggregateError(errors, 'Resource breach audit failed'),
    );
  };
  const inspect = () => {
    if (stopped || breached) return;
    try {
      const freeBytes = availableFilesystemBytes(tempRoot);
      minimumObservedFreeBytes = Math.min(minimumObservedFreeBytes, freeBytes);
      if (freeBytes < limits.minimumRuntimeFreeBytes) {
        throw new Error(
          `Test runtime free space fell below ` +
          `${formatBytes(limits.minimumRuntimeFreeBytes)}: ` +
          `${formatBytes(freeBytes)} available.`,
        );
      }
      const suiteBytes = directoryFootprint(tempRoot);
      peakSuiteBytes = Math.max(peakSuiteBytes, suiteBytes);
      if (suiteBytes > limits.maximumSuiteBytes) {
        const error = new Error(
          `Test suite temporary footprint exceeded ` +
          `${formatBytes(limits.maximumSuiteBytes)}: ${formatBytes(suiteBytes)}.`,
        );
        reportBreach(error, {
          type: 'resource-breach',
          runId,
          pid: process.pid,
          scope: 'suite',
          observedBytes: suiteBytes,
          limitBytes: limits.maximumSuiteBytes,
          recordedAt: new Date().toISOString(),
        });
        return;
      }
      for (const entry of readdirSync(tempRoot, { withFileTypes: true })) {
        if (!entry.isDirectory() || !entry.name.startsWith('worker-')) continue;
        const workerPath = join(tempRoot, entry.name);
        const workerBytes = directoryFootprint(workerPath);
        peakWorkerBytes = Math.max(peakWorkerBytes, workerBytes);
        if (workerBytes > limits.maximumWorkerBytes) {
          const error = new Error(
            `Test worker ${entry.name} temporary footprint exceeded ` +
            `${formatBytes(limits.maximumWorkerBytes)}: ` +
            `${formatBytes(workerBytes)}.`,
          );
          reportBreach(error, {
            type: 'resource-breach',
            runId,
            pid: process.pid,
            scope: entry.name,
            observedBytes: workerBytes,
            limitBytes: limits.maximumWorkerBytes,
            recordedAt: new Date().toISOString(),
          });
          return;
        }
      }
    } catch (error) {
      const normalized =
        error instanceof Error ? error : new Error(String(error));
      reportBreach(normalized, {
        type: 'resource-breach',
        runId,
        pid: process.pid,
        scope: 'monitor',
        message: normalized.message,
        recordedAt: new Date().toISOString(),
      });
    }
  };
  inspect();
  const interval = setInterval(() => {
    try {
      inspect();
    } catch (error) {
      failure.report(error);
    }
  }, footprintPollIntervalMs);
  interval.unref();
  return {
    failure: failure.promise,
    stop() {
      if (stopped) return;
      clearInterval(interval);
      inspect();
      stopped = true;
      appendAuditEvent(auditPath, {
        type: 'resource-summary',
        runId,
        pid: process.pid,
        peakSuiteBytes,
        peakWorkerBytes,
        minimumObservedFreeBytes: Number.isFinite(minimumObservedFreeBytes)
          ? minimumObservedFreeBytes
          : null,
        breached,
        recordedAt: new Date().toISOString(),
      });
      if (breachFailure) throw breachFailure;
    },
  };
}

function directoryFootprint(path) {
  let total = 0;
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return 0;
    throw error;
  }
  for (const entry of entries) {
    const entryPath = join(path, entry.name);
    if (entry.isDirectory()) {
      total += directoryFootprint(entryPath);
      continue;
    }
    if (!entry.isFile()) continue;
    try {
      total += lstatSync(entryPath).size;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  return total;
}

function assertFreeSpace(path, requiredBytes) {
  const availableBytes = availableFilesystemBytes(path);
  if (!Number.isFinite(availableBytes) || availableBytes < requiredBytes) {
    throw new Error(
      `Test runner requires at least ${formatBytes(requiredBytes)} free on the ` +
      `temporary filesystem; observed ${formatBytes(availableBytes)}.`,
    );
  }
}

function availableFilesystemBytes(path) {
  const stats = statfsSync(path);
  return Number(stats.bavail) * Number(stats.bsize);
}

export function cleanupExitedWorkerDirectories({
  tempRoot,
  auditPath,
  runId,
}) {
  const events = readJsonLines(auditPath, 'database audit');
  const cleaned = new Set(
    events
      .filter((event) => event.type === 'worker-cleanup')
      .map((event) => event.workerDir),
  );
  const workers = new Map();
  for (const event of events) {
    if (
      event.type === 'worker-env' &&
      Number.isInteger(event.pid) &&
      typeof event.workerDir === 'string' &&
      isWithin(tempRoot, event.workerDir)
    ) {
      workers.set(event.workerDir, event);
    }
  }
  for (const [workerDir, event] of workers) {
    if (cleaned.has(workerDir) || processAlive(event.pid)) continue;
    rmSync(workerDir, { recursive: true, force: true });
    appendAuditEvent(auditPath, {
      type: 'worker-cleanup',
      runId,
      pid: event.pid,
      dbPath: event.dbPath,
      workerDir,
      removed: !existsSync(workerDir),
      cleanedByPid: process.pid,
      recordedAt: new Date().toISOString(),
    });
  }
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

function appendAuditEvent(path, event) {
  appendFileSync(path, `${JSON.stringify(event)}\n`);
}

function prepareAuditRoot(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stats = lstatSync(path);
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (typeof process.getuid === 'function' && stats.uid !== process.getuid()) ||
    (stats.mode & 0o077) !== 0
  ) {
    throw new Error(`Test audit root must be private and owner-only: ${path}`);
  }
  const retentionCutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const maximumAuditBytes = 50 * mebibyte;
  let retainedBytes = 0;
  const entries = readdirSync(path, { withFileTypes: true })
    .filter((entry) =>
      entry.isFile() &&
      (
        entry.name.endsWith('.jsonl') ||
        entry.name.endsWith('.watchdog-receipt.json') ||
        entry.name.endsWith('.watchdog.json')
      ))
    .map((entry) => {
      const entryPath = join(path, entry.name);
      const stats = statSync(entryPath);
      return {
        path: entryPath,
        mtimeMs: stats.mtimeMs,
        size: stats.size,
      };
    })
    .sort((left, right) => right.mtimeMs - left.mtimeMs);
  entries.forEach((entry, index) => {
    retainedBytes += entry.size;
    if (
      index >= 20 ||
      entry.mtimeMs < retentionCutoff ||
      retainedBytes > maximumAuditBytes
    ) {
      rmSync(entry.path, { force: true });
    }
  });
}

export function sanitizeTestChildEnvironment({
  environment = process.env,
  liveDatabase,
} = {}) {
  if (typeof liveDatabase !== 'string' || liveDatabase.length === 0) {
    throw new Error('A live database path is required to sanitize child state.');
  }
  const forbiddenValues = sqliteFamilyPaths(resolve(liveDatabase))
    .flatMap((path) => [path, pathToFileURL(path).href]);
  const sanitized = Object.create(null);
  for (const [name, rawValue] of Object.entries(environment ?? {})) {
    if (rawValue === undefined) continue;
    if (
      name === 'DB_PATH' ||
      name === 'DOTENV_CONFIG_PATH' ||
      name === 'NODE_OPTIONS' ||
      name === 'RADAR_CODE_REVISION' ||
      name === 'RADAR_DB_BOOTSTRAP_MODE' ||
      name === 'RADAR_DB_READ_ONLY' ||
      name.startsWith('RADAR_TEST_')
    ) {
      continue;
    }
    const value = String(rawValue);
    if (forbiddenValues.some((forbidden) => value.includes(forbidden))) {
      continue;
    }
    sanitized[name] = value;
  }
  return sanitized;
}

export function materializePrivateInstallerHeredocs({
  sourcePath,
  fixtureRoot,
  expectedHeredocCount,
  forbidShellHereStrings = false,
} = {}) {
  if (typeof sourcePath !== 'string' || !isAbsolute(sourcePath)) {
    throw new Error('The installer heredoc source path must be absolute.');
  }
  if (typeof fixtureRoot !== 'string' || !isAbsolute(fixtureRoot)) {
    throw new Error('The installer heredoc fixture root must be absolute.');
  }
  if (
    !Number.isSafeInteger(expectedHeredocCount) ||
    expectedHeredocCount < 0
  ) {
    throw new Error(
      'The expected installer quoted-heredoc count must be a nonnegative integer.',
    );
  }
  if (typeof forbidShellHereStrings !== 'boolean') {
    throw new Error(
      'The installer shell here-string policy must be a boolean.',
    );
  }

  const canonicalSourcePath = canonicalPath(sourcePath);
  const sourceBefore = captureFileSnapshot(canonicalSourcePath);
  if (!sourceBefore.exists) {
    throw new Error(
      `The installer heredoc source does not exist: ${canonicalSourcePath}`,
    );
  }
  const source = readFileSync(canonicalSourcePath);
  const sourceDigest = sha256(source);
  if (sourceDigest !== sourceBefore.digest) {
    throw new Error(
      `The installer heredoc source changed while it was read: ${canonicalSourcePath}`,
    );
  }
  const plan = planQuotedInstallerHeredocs(source, canonicalSourcePath);
  if (plan.heredocs.length !== expectedHeredocCount) {
    throw new Error(
      `Expected ${expectedHeredocCount} quoted installer heredocs, ` +
      `found ${plan.heredocs.length}: ${canonicalSourcePath}`,
    );
  }
  if (forbidShellHereStrings && plan.shellHereStrings.length > 0) {
    const first = plan.shellHereStrings[0];
    throw new Error(
      `${canonicalSourcePath}:${first.line} uses an unsupported shell ` +
      'here-string form; rewrite it without <<< because Bash materializes ' +
      'it as a temporary file.',
    );
  }

  const privateRoot = realpathOrResolve(fixtureRoot);
  let createdRoot = false;
  try {
    mkdirSync(privateRoot, { mode: 0o700 });
    createdRoot = true;
    chmodSync(privateRoot, 0o700);
    assertPrivateFixtureDirectory(privateRoot);
    fsyncDirectory(dirname(privateRoot));

    const materializedHeredocs = plan.heredocs.map((heredoc, index) => {
      const bodyPath = join(
        privateRoot,
        `heredoc-${String(index + 1).padStart(3, '0')}-` +
        `${heredoc.delimiter}.input`,
      );
      const bodyIdentity = writeExclusivePrivateFixtureFile(
        bodyPath,
        heredoc.body,
        0o400,
      );
      return {
        ...heredoc,
        bodyPath,
        bodyIdentity,
      };
    });

    const installerPath = join(privateRoot, 'installer-under-test.sh');
    const transformed = renderInstallerHeredocPlan(
      plan,
      materializedHeredocs,
    );
    const transformedIdentity = writeExclusivePrivateFixtureFile(
      installerPath,
      transformed,
      0o500,
    );
    const manifest = {
      schemaVersion: 1,
      kind: 'private-test-installer-heredoc-fixture',
      source: {
        path: canonicalSourcePath,
        bytes: source.length,
        sha256: sourceDigest,
      },
      transformed: {
        path: basename(installerPath),
        bytes: transformed.length,
        sha256: transformedIdentity.digest,
      },
      heredocs: materializedHeredocs.map((heredoc, index) => ({
        index: index + 1,
        delimiter: heredoc.delimiter,
        openerLine: heredoc.openerLine,
        bodyStartLine: heredoc.bodyStartLine,
        bodyEndLine: heredoc.bodyEndLine,
        delimiterLine: heredoc.delimiterLine,
        path: basename(heredoc.bodyPath),
        bytes: heredoc.body.length,
        sha256: heredoc.bodyIdentity.digest,
      })),
    };
    const manifestPath = join(privateRoot, 'heredoc-manifest.json');
    const manifestIdentity = writeExclusivePrivateFixtureFile(
      manifestPath,
      `${JSON.stringify(manifest, null, 2)}\n`,
      0o400,
    );
    const fixtureIdentity = sealPrivateInstallerFixtureIdentity({
      fixtureRoot: privateRoot,
      installerPath,
      transformedIdentity,
      manifestIdentity,
      materializedHeredocs,
    });
    assertFileSnapshotUnchanged(
      canonicalSourcePath,
      sourceBefore,
      'production release installer',
      'private test heredoc materialization',
    );
    return {
      fixtureRoot: privateRoot,
      installerPath,
      manifestPath,
      sourcePath: canonicalSourcePath,
      sourceSha256: sourceDigest,
      transformedSha256: transformedIdentity.digest,
      fixtureIdentity,
      heredocs: materializedHeredocs.map((heredoc, index) => ({
        index: index + 1,
        delimiter: heredoc.delimiter,
        openerLine: heredoc.openerLine,
        bodyStartLine: heredoc.bodyStartLine,
        bodyEndLine: heredoc.bodyEndLine,
        delimiterLine: heredoc.delimiterLine,
        bodyPath: heredoc.bodyPath,
        bytes: heredoc.body.length,
        sha256: heredoc.bodyIdentity.digest,
      })),
    };
  } catch (error) {
    if (createdRoot) {
      rmSync(privateRoot, { recursive: true, force: true });
    }
    throw error;
  }
}

export function assertPrivateInstallerFixtureUnchanged(
  fixtureIdentity,
  context = 'before installer phase',
) {
  try {
    if (
      !fixtureIdentity ||
      typeof fixtureIdentity !== 'object' ||
      !fixtureIdentity.root ||
      !Array.isArray(fixtureIdentity.files) ||
      fixtureIdentity.files[0]?.role !== 'transformed installer' ||
      fixtureIdentity.files[0]?.path !== fixtureIdentity.installerPath
    ) {
      throw new Error('Expected sealed installer fixture identity metadata.');
    }
    const rootBefore = capturePrivateFixtureDirectoryIdentity(
      fixtureIdentity.root.path,
    );
    assertPrivateFixtureIdentityMatches(
      fixtureIdentity.root,
      rootBefore,
      'fixture root',
    );
    for (const expected of fixtureIdentity.files) {
      const observed = capturePrivateFixtureFileIdentity(
        expected.path,
        expected.mode,
      );
      assertPrivateFixtureIdentityMatches(
        expected,
        observed,
        expected.role,
      );
    }
    const rootAfter = capturePrivateFixtureDirectoryIdentity(
      fixtureIdentity.root.path,
    );
    assertPrivateFixtureIdentityMatches(
      fixtureIdentity.root,
      rootAfter,
      'fixture root',
    );
  } catch (error) {
    const normalized = normalizeError(error);
    throw new Error(
      `Private installer fixture changed ${context}: ` +
      `${normalized.message}`,
      { cause: normalized },
    );
  }
}

export function phaseChildEnvironment({
  phase,
  environment,
  guardNodeOptions,
  installerFixturePath,
} = {}) {
  if (phase !== 'installer') return environment;
  if (
    typeof installerFixturePath !== 'string' ||
    !isAbsolute(installerFixturePath)
  ) {
    throw new Error(
      'The installer phase requires an absolute private installer fixture path.',
    );
  }
  if (
    typeof guardNodeOptions !== 'string' ||
    guardNodeOptions.length === 0 ||
    guardNodeOptions.trim() !== guardNodeOptions
  ) {
    throw new Error(
      'The installer phase requires guarded child NODE_OPTIONS.',
    );
  }
  return {
    ...environment,
    NODE_OPTIONS: guardNodeOptions,
    RADAR_TEST_INSTALLER_FIXTURE_PATH: installerFixturePath,
  };
}

function planQuotedInstallerHeredocs(source, sourcePath) {
  const lines = installerSourceLines(source);
  const heredocs = [];
  const shellHereStrings = [];
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    const lineBytes = source.subarray(line.start, line.contentEnd);
    const lineText = lineBytes.toString('utf8');
    for (const offset of shellHereStringOperatorOffsets(lineText)) {
      shellHereStrings.push({ line: line.number, offset });
    }
    const operators = trueHeredocOperatorOffsets(lineText);
    if (operators.length === 0) continue;
    if (operators.length !== 1) {
      throw new Error(
        `${sourcePath}:${line.number} must contain exactly one heredoc opener.`,
      );
    }
    const operatorIndex = operators[0];
    const opener = /^<<'([A-Za-z_][A-Za-z0-9_]*)'/.exec(
      lineText.slice(operatorIndex),
    );
    if (
      opener === null ||
      !Buffer.from(lineText, 'utf8').equals(lineBytes)
    ) {
      throw new Error(
        `${sourcePath}:${line.number} uses an unsupported heredoc form; ` +
        `only exact <<'DELIM' openers are allowed.`,
      );
    }
    const characterAfterOpener =
      lineText[operatorIndex + opener[0].length];
    if (
      characterAfterOpener !== undefined &&
      characterAfterOpener !== ' ' &&
      characterAfterOpener !== '\t'
    ) {
      throw new Error(
        `${sourcePath}:${line.number} must separate the quoted heredoc ` +
        `opener from trailing shell syntax.`,
      );
    }

    const bodyLineIndex = installerHeredocBodyLineIndex({
      lineIndex,
      lines,
      lineText,
      openerEnd: operatorIndex + opener[0].length,
      source,
      sourcePath,
    });
    const delimiter = opener[1];
    let delimiterIndex = bodyLineIndex;
    while (
      delimiterIndex < lines.length &&
      source
        .subarray(
          lines[delimiterIndex].start,
          lines[delimiterIndex].contentEnd,
        )
        .toString('utf8') !== delimiter
    ) {
      delimiterIndex += 1;
    }
    if (delimiterIndex >= lines.length) {
      throw new Error(
        `${sourcePath}:${line.number} has an unterminated ` +
        `<<'${delimiter}' heredoc.`,
      );
    }

    const delimiterLine = lines[delimiterIndex];
    const openerByteOffset = Buffer.byteLength(
      lineText.slice(0, operatorIndex),
      'utf8',
    );
    const openerStart = line.start + openerByteOffset;
    const openerEnd = openerStart + Buffer.byteLength(opener[0], 'utf8');
    const bodyStart = lines[bodyLineIndex - 1].end;
    const bodyEnd = delimiterLine.start;
    // Retain each removed line ending so shell diagnostics keep source lines.
    const removedLineEndings = Buffer.concat(
      lines
        .slice(bodyLineIndex, delimiterIndex + 1)
        .map((removedLine) =>
          source.subarray(removedLine.contentEnd, removedLine.end)),
    );
    const hasBodyLines = delimiterIndex > bodyLineIndex;
    heredocs.push({
      delimiter,
      openerStart,
      openerEnd,
      bodyStart,
      delimiterEnd: delimiterLine.end,
      removedLineEndings,
      body: Buffer.from(source.subarray(bodyStart, bodyEnd)),
      openerLine: line.number,
      bodyStartLine: hasBodyLines ? lines[bodyLineIndex].number : null,
      bodyEndLine: hasBodyLines ? delimiterLine.number - 1 : null,
      delimiterLine: delimiterLine.number,
    });
    lineIndex = delimiterIndex;
  }
  return { source, heredocs, shellHereStrings };
}

function installerHeredocBodyLineIndex({
  lineIndex,
  lines,
  lineText,
  openerEnd,
  source,
  sourcePath,
}) {
  const suffix = lineText.slice(openerEnd);
  if (!/^[ \t]+\|\|[ \t]*$/.test(suffix)) {
    return lineIndex + 1;
  }
  const continuationLine = lines[lineIndex + 1];
  if (!continuationLine) {
    throw new Error(
      `${sourcePath}:${lines[lineIndex].number} has an incomplete ` +
      `heredoc shell continuation.`,
    );
  }
  const continuation = source
    .subarray(continuationLine.start, continuationLine.contentEnd)
    .toString('utf8');
  if (!/^[ \t]+(?:return|exit)[ \t]+[0-9]+[ \t]*$/.test(continuation)) {
    throw new Error(
      `${sourcePath}:${continuationLine.number} uses an unsupported ` +
      `heredoc shell continuation.`,
    );
  }
  return lineIndex + 2;
}

function trueHeredocOperatorOffsets(lineText) {
  const offsets = [];
  for (let index = 0; index < lineText.length;) {
    if (
      lineText.startsWith('<<<', index) &&
      lineText[index + 3] !== '<'
    ) {
      index += 3;
      continue;
    }
    if (lineText.startsWith('<<', index)) {
      offsets.push(index);
      index += 2;
      continue;
    }
    index += 1;
  }
  return offsets;
}

function shellHereStringOperatorOffsets(lineText) {
  const offsets = [];
  for (let index = 0; index < lineText.length;) {
    if (
      lineText.startsWith('<<<', index) &&
      lineText[index + 3] !== '<'
    ) {
      offsets.push(index);
      index += 3;
      continue;
    }
    index += 1;
  }
  return offsets;
}

function installerSourceLines(source) {
  const lines = [];
  let start = 0;
  let number = 1;
  while (start < source.length) {
    const lineFeed = source.indexOf(0x0a, start);
    const end = lineFeed === -1 ? source.length : lineFeed + 1;
    let contentEnd = lineFeed === -1 ? end : lineFeed;
    if (contentEnd > start && source[contentEnd - 1] === 0x0d) {
      contentEnd -= 1;
    }
    lines.push({ start, contentEnd, end, number });
    start = end;
    number += 1;
  }
  return lines;
}

function renderInstallerHeredocPlan(plan, materializedHeredocs) {
  const chunks = [];
  let cursor = 0;
  for (let index = 0; index < plan.heredocs.length; index += 1) {
    const heredoc = plan.heredocs[index];
    const materialized = materializedHeredocs[index];
    chunks.push(plan.source.subarray(cursor, heredoc.openerStart));
    chunks.push(Buffer.from(`< ${shellSingleQuote(materialized.bodyPath)}`));
    chunks.push(plan.source.subarray(heredoc.openerEnd, heredoc.bodyStart));
    chunks.push(heredoc.removedLineEndings);
    cursor = heredoc.delimiterEnd;
  }
  chunks.push(plan.source.subarray(cursor));
  return Buffer.concat(chunks);
}

function shellSingleQuote(value) {
  return `'${String(value).split("'").join(`'"'"'`)}'`;
}

function sealPrivateInstallerFixtureIdentity({
  fixtureRoot,
  installerPath,
  transformedIdentity,
  manifestIdentity,
  materializedHeredocs,
}) {
  const files = Object.freeze([
    Object.freeze({
      role: 'transformed installer',
      ...transformedIdentity,
    }),
    ...materializedHeredocs.map((heredoc, index) => Object.freeze({
      role: `heredoc body ${index + 1}`,
      ...heredoc.bodyIdentity,
    })),
    Object.freeze({
      role: 'fixture manifest',
      ...manifestIdentity,
    }),
  ]);
  const root = capturePrivateFixtureDirectoryIdentity(fixtureRoot);
  const expectedEntries = files
    .map((identity) => basename(identity.path))
    .sort((left, right) => left.localeCompare(right));
  if (
    root.entries.length !== expectedEntries.length ||
    root.entries.some((entry, index) => entry !== expectedEntries[index])
  ) {
    throw new Error('Private installer fixture contains unexpected entries.');
  }
  return Object.freeze({
    installerPath,
    root,
    files,
  });
}

function assertPrivateFixtureDirectory(path) {
  capturePrivateFixtureDirectoryIdentity(path);
}

function capturePrivateFixtureDirectoryIdentity(path) {
  const before = lstatSync(path, { bigint: true });
  assertPrivateFixtureDirectoryStat(path, before);
  const entries = readdirSync(path).sort((left, right) =>
    left.localeCompare(right));
  const after = lstatSync(path, { bigint: true });
  assertPrivateFixtureDirectoryStat(path, after);
  if (!samePrivateFixtureStat(before, after)) {
    throw new Error(
      `Private installer fixture root changed while inspected: ${path}`,
    );
  }
  return Object.freeze({
    ...privateFixtureStatIdentity(path, after),
    digest: sha256(entries.join('\0')),
    entries: Object.freeze(entries),
  });
}

function assertPrivateFixtureDirectoryStat(path, stats) {
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error(`Private installer fixture root is not a directory: ${path}`);
  }
  if (Number(stats.mode & 0o777n) !== 0o700) {
    throw new Error(`Private installer fixture root has unsafe mode: ${path}`);
  }
}

function capturePrivateFixtureFileIdentity(path, expectedMode) {
  let descriptor = null;
  try {
    const pathBefore = lstatSync(path, { bigint: true });
    assertPrivateFixtureFileStat(path, pathBefore, expectedMode);
    descriptor = openSync(
      path,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const descriptorBefore = fstatSync(descriptor, { bigint: true });
    assertPrivateFixtureFileStat(path, descriptorBefore, expectedMode);
    if (!samePrivateFixtureStat(pathBefore, descriptorBefore)) {
      throw new Error(
        `Private installer fixture path identity changed before read: ${path}`,
      );
    }

    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (true) {
      const bytesRead = readSync(
        descriptor,
        buffer,
        0,
        buffer.length,
        position,
      );
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }

    const descriptorAfter = fstatSync(descriptor, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    assertPrivateFixtureFileStat(path, descriptorAfter, expectedMode);
    assertPrivateFixtureFileStat(path, pathAfter, expectedMode);
    if (
      !samePrivateFixtureStat(descriptorBefore, descriptorAfter) ||
      !samePrivateFixtureStat(descriptorAfter, pathAfter) ||
      BigInt(position) !== descriptorAfter.size
    ) {
      throw new Error(
        `Private installer fixture changed while inspected: ${path}`,
      );
    }
    return Object.freeze({
      ...privateFixtureStatIdentity(path, descriptorAfter),
      digest: digest.digest('hex'),
    });
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

function assertPrivateFixtureFileStat(path, stats, expectedMode) {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1n ||
    Number(stats.mode & 0o777n) !== expectedMode
  ) {
    throw new Error(`Private installer fixture file is unsafe: ${path}`);
  }
}

function privateFixtureStatIdentity(path, stats) {
  return {
    path,
    dev: String(stats.dev),
    ino: String(stats.ino),
    mode: Number(stats.mode & 0o777n),
    nlink: Number(stats.nlink),
    size: String(stats.size),
    mtimeNs: String(stats.mtimeNs),
    ctimeNs: String(stats.ctimeNs),
  };
}

function samePrivateFixtureStat(left, right) {
  return left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

function assertPrivateFixtureIdentityMatches(expected, observed, label) {
  for (const field of [
    'path',
    'dev',
    'ino',
    'mode',
    'nlink',
    'size',
    'mtimeNs',
    'ctimeNs',
    'digest',
  ]) {
    if (expected[field] !== observed[field]) {
      throw new Error(`${label} ${field} metadata changed.`);
    }
  }
  if (
    expected.entries &&
    (
      expected.entries.length !== observed.entries?.length ||
      expected.entries.some(
        (entry, index) => entry !== observed.entries[index],
      )
    )
  ) {
    throw new Error(`${label} directory entries changed.`);
  }
}

function writeExclusivePrivateFixtureFile(path, contents, mode) {
  const bytes = Buffer.isBuffer(contents)
    ? contents
    : Buffer.from(String(contents));
  const descriptor = openSync(
    path,
    fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_WRONLY |
      (fsConstants.O_NOFOLLOW ?? 0),
    mode,
  );
  let descriptorStats;
  try {
    writeFileSync(descriptor, bytes);
    fchmodSync(descriptor, mode);
    fsyncSync(descriptor);
    descriptorStats = fstatSync(descriptor);
    if (
      !descriptorStats.isFile() ||
      descriptorStats.nlink !== 1 ||
      (descriptorStats.mode & 0o777) !== mode
    ) {
      throw new Error(`Private installer fixture file is unsafe: ${path}`);
    }
  } finally {
    closeSync(descriptor);
  }
  const pathStats = lstatSync(path);
  if (
    !pathStats.isFile() ||
    pathStats.isSymbolicLink() ||
    pathStats.nlink !== 1 ||
    pathStats.dev !== descriptorStats.dev ||
    pathStats.ino !== descriptorStats.ino ||
    (pathStats.mode & 0o777) !== mode
  ) {
    throw new Error(`Private installer fixture path identity changed: ${path}`);
  }
  fsyncDirectory(dirname(path));
  const identity = capturePrivateFixtureFileIdentity(path, mode);
  if (identity.digest !== sha256(bytes)) {
    throw new Error(`Private installer fixture digest changed: ${path}`);
  }
  return identity;
}

export function resolveTestWriteBoundaryBackend({
  platform = process.platform,
  executablePath = sandboxExecutablePath,
} = {}) {
  if (platform !== 'darwin') {
    throw new Error(
      'The authoritative test suite requires a kernel-enforced deny-write ' +
      'boundary. Only the macOS sandbox-exec backend is implemented; ' +
      'non-Darwin runs must provide an equivalent external sandbox with the ' +
      'live database unmounted.',
    );
  }
  const executable = captureExecutableIdentity(executablePath);
  if (
    executable === null ||
    executable.uid !== 0 ||
    (executable.mode & 0o022) !== 0
  ) {
    throw new Error(
      `The macOS deny-write backend is unavailable or untrusted: ${executablePath}`,
    );
  }
  return {
    backend: 'darwin-seatbelt-v1',
    executable,
  };
}

export function inspectConfiguredLiveDatabaseUnderWriteBoundary({
  repositoryRoot = root,
  environment = process.env,
  platform = process.platform,
  executablePath = sandboxExecutablePath,
  childPath = liveDatabaseInspectionChildPath,
  run = spawnSync,
} = {}) {
  if (typeof run !== 'function') {
    throw new Error('Live database inspection requires a child-process runner.');
  }
  const backend = resolveTestWriteBoundaryBackend({
    platform,
    executablePath,
  });
  const canonicalRepositoryRoot = canonicalPath(repositoryRoot);
  if (
    typeof childPath !== 'string' ||
    !isAbsolute(childPath) ||
    resolve(childPath) !== childPath
  ) {
    throw new Error(
      'Live database inspection child path must be absolute and normalized.',
    );
  }
  const childStats = lstatSync(childPath);
  if (childStats.isSymbolicLink() || !childStats.isFile()) {
    throw new Error(
      `Live database inspection child is not a direct regular file: ${childPath}`,
    );
  }
  const canonicalChildPath = realpathSync.native(childPath);
  const profile = buildDarwinDenyWriteProfile();
  let probeRoot = null;
  try {
    probeRoot = realpathSync.native(mkdtempSync(
      join(tmpdir(), 'openclaw-radar-live-db-inspection-'),
    ));
    chmodSync(probeRoot, 0o700);
    const writeProbePath = join(probeRoot, 'write-probe');
    const result = run(
      backend.executable.path,
      [
        '-p',
        profile,
        process.execPath,
        '--no-global-search-paths',
        canonicalChildPath,
        canonicalRepositoryRoot,
        writeProbePath,
      ],
      {
        cwd: canonicalRepositoryRoot,
        encoding: 'utf8',
        env: liveDatabaseInspectionEnvironment({
          environment,
          backend: backend.backend,
        }),
        maxBuffer: maximumLiveDatabaseInspectionOutputBytes,
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: liveDatabaseInspectionTimeoutMs,
      },
    );
    if (existsSync(writeProbePath)) {
      throw new Error(
        'The kernel deny-write boundary left an inspection probe artifact.',
      );
    }
    if (result?.error) {
      throw new Error(
        `Unable to run the write-denied live database inspection child: ` +
        normalizeError(result.error).message,
      );
    }
    if (result?.signal != null) {
      throw new Error(
        `Write-denied live database inspection ended with signal ` +
        `${String(result.signal)}.`,
      );
    }
    if (result?.status !== 0) {
      const diagnostic = boundedLiveDatabaseInspectionDiagnostic(
        result?.stderr,
      );
      throw new Error(
        `Write-denied live database inspection failed with exit code ` +
        `${String(result?.status)}${
          diagnostic ? `: ${diagnostic}` : '.'
        }`,
      );
    }
    return Object.freeze({
      ...parseLiveDatabaseInspectionResult(result.stdout),
      boundary: backend.backend,
    });
  } finally {
    if (probeRoot !== null) {
      rmSync(probeRoot, { recursive: true, force: true });
    }
  }
}

export function parseLiveDatabaseInspectionResult(output) {
  const text = Buffer.isBuffer(output)
    ? output.toString('utf8')
    : typeof output === 'string'
      ? output
      : '';
  if (
    text.length === 0 ||
    Buffer.byteLength(text, 'utf8') >
      maximumLiveDatabaseInspectionOutputBytes
  ) {
    throw new Error('Live database inspection output is missing or oversized.');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('Live database inspection output is not valid JSON.');
  }
  if (
    !isPlainRecord(value) ||
    !hasExactKeys(value, [
      'schemaVersion',
      'kind',
      'liveDatabase',
      'fingerprint',
    ]) ||
    value.schemaVersion !== 1 ||
    value.kind !== 'live-database-inspection' ||
    typeof value.liveDatabase !== 'string' ||
    !isAbsolute(value.liveDatabase) ||
    resolve(value.liveDatabase) !== value.liveDatabase ||
    !Array.isArray(value.fingerprint) ||
    value.fingerprint.length !== 4
  ) {
    throw new Error('Live database inspection result has an invalid envelope.');
  }
  const expectedPaths = sqliteFamilyPaths(value.liveDatabase);
  const fingerprint = value.fingerprint.map((member, index) => {
    if (
      !isPlainRecord(member) ||
      !hasExactKeys(member, [
        'path',
        'exists',
        'dev',
        'ino',
        'size',
        'mtimeMs',
        'ctimeMs',
        'digest',
      ]) ||
      member.path !== expectedPaths[index] ||
      typeof member.exists !== 'boolean'
    ) {
      throw new Error(
        `Live database inspection fingerprint member ${index} is invalid.`,
      );
    }
    if (member.exists) {
      if (
        !isNonnegativeInteger(member.dev) ||
        !isNonnegativeInteger(member.ino) ||
        !isNonnegativeInteger(member.size) ||
        !Number.isFinite(member.mtimeMs) ||
        !Number.isFinite(member.ctimeMs) ||
        !isSha256(member.digest)
      ) {
        throw new Error(
          `Live database inspection fingerprint member ${index} ` +
          `has invalid file metadata.`,
        );
      }
    } else if (
      member.dev !== null ||
      member.ino !== null ||
      member.size !== null ||
      member.mtimeMs !== null ||
      member.ctimeMs !== null ||
      member.digest !== null
    ) {
      throw new Error(
        `Missing live database fingerprint member ${index} has metadata.`,
      );
    }
    return Object.freeze({ ...member });
  });
  return Object.freeze({
    schemaVersion: 1,
    kind: 'live-database-inspection',
    liveDatabase: value.liveDatabase,
    fingerprint: Object.freeze(fingerprint),
  });
}

function liveDatabaseInspectionEnvironment({
  environment,
  backend,
}) {
  if (environment === null || typeof environment !== 'object') {
    throw new Error('Live database inspection environment must be an object.');
  }
  const childEnvironment = Object.create(null);
  for (const name of [
    'DB_PATH',
    'DOTENV_CONFIG_PATH',
    'HOME',
    'LANG',
    'LC_ALL',
    'TZ',
  ]) {
    const value = environment[name];
    if (value === undefined) continue;
    if (typeof value !== 'string' || value.includes('\0')) {
      throw new Error(
        `Live database inspection environment variable ${name} is invalid.`,
      );
    }
    childEnvironment[name] = value;
  }
  childEnvironment.RADAR_TEST_LIVE_DB_INSPECTION_BOUNDARY = backend;
  return childEnvironment;
}

function boundedLiveDatabaseInspectionDiagnostic(value) {
  const text = Buffer.isBuffer(value)
    ? value.toString('utf8')
    : typeof value === 'string'
      ? value
      : '';
  return text
    .trim()
    .replace(/\s+/g, ' ')
    .slice(-maximumLiveDatabaseInspectionDiagnosticCharacters);
}

function isNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

export function buildDarwinDenyWriteProfile({
  unreadablePaths = [],
  writableRoots = [],
} = {}) {
  if (!Array.isArray(writableRoots)) {
    throw new Error('The macOS sandbox writable roots must be an array.');
  }
  if (!Array.isArray(unreadablePaths)) {
    throw new Error('The macOS sandbox unreadable paths must be an array.');
  }
  const roots = [...new Set(writableRoots.map((path) => canonicalPath(path)))];
  const deniedReads = [
    ...new Set(unreadablePaths.map((path) => canonicalPath(path))),
  ];
  return [
    '(version 1)',
    '(allow default)',
    ...(deniedReads.length === 0
      ? []
      : [
          '(deny file-read-data',
          ...deniedReads.map(
            (path) => `  (literal ${JSON.stringify(path)})`,
          ),
          ')',
        ]),
    '(deny file-write*)',
    '(allow file-write*',
    ...roots.map((path) => `  (subpath ${JSON.stringify(path)})`),
    '  (literal "/dev/null")',
    '  (literal "/dev/tty"))',
    ...(roots.length === 0
      ? ['(deny file-write-setugid)']
      : [
          '(allow file-write-setugid',
          ...roots.map((path) => `  (subpath ${JSON.stringify(path)})`),
          ')',
        ]),
    '(deny process-exec',
    '  (literal "/bin/launchctl")',
    '  (literal "/usr/bin/open")',
    '  (literal "/usr/bin/osascript")',
    '  (literal "/usr/bin/ssh")',
    '  (literal "/usr/bin/sudo"))',
    '',
  ].join('\n');
}

export function buildDarwinSandboxProfile({
  unreadablePaths = [],
  writableRoots,
} = {}) {
  if (!Array.isArray(writableRoots) || writableRoots.length === 0) {
    throw new Error('The macOS sandbox requires at least one writable root.');
  }
  return buildDarwinDenyWriteProfile({
    unreadablePaths,
    writableRoots,
  });
}

export function resolveTestProcessLockLayout({
  repositoryRoot = root,
  tempRoot,
  globalWriterLockPath =
    repositoryDatabaseWriterLockPath(repositoryRoot),
} = {}) {
  if (typeof tempRoot !== 'string' || !isAbsolute(tempRoot)) {
    throw new Error('The test process-lock layout requires an absolute temp root.');
  }
  if (
    typeof globalWriterLockPath !== 'string' ||
    !isAbsolute(globalWriterLockPath)
  ) {
    throw new Error(
      'The test process-lock layout requires an absolute global writer-lock path.',
    );
  }
  const writerLockBasename = basename(
    repositoryDatabaseWriterLockPath(repositoryRoot),
  );
  const canonicalTempRoot = realpathOrResolve(tempRoot);
  const canonicalGlobalWriterLockPath =
    realpathOrResolve(globalWriterLockPath);
  if (basename(canonicalGlobalWriterLockPath) !== writerLockBasename) {
    throw new Error(
      'The global writer-lock path does not match the repository lock identity.',
    );
  }
  const globalProcessLockRoot =
    realpathOrResolve(dirname(canonicalGlobalWriterLockPath));
  const auditRoot =
    realpathOrResolve(join(globalProcessLockRoot, 'test-audits'));
  const delegatedProcessLockRoot =
    realpathOrResolve(join(canonicalTempRoot, 'process-locks'));
  const delegatedWriterLockPath =
    realpathOrResolve(join(delegatedProcessLockRoot, writerLockBasename));
  const workerDatabaseRoots = Object.freeze([canonicalTempRoot]);
  const sandboxWritableRoots = Object.freeze([
    canonicalTempRoot,
    auditRoot,
  ]);
  const workerWritable = (candidate) =>
    sandboxWritableRoots.some((writableRoot) =>
      isWithin(writableRoot, candidate));
  if (
    workerWritable(globalProcessLockRoot) ||
    workerWritable(canonicalGlobalWriterLockPath)
  ) {
    throw new Error(
      'The global process-lock root must remain outside worker-writable roots.',
    );
  }
  if (
    !isWithin(canonicalTempRoot, delegatedProcessLockRoot) ||
    !isWithin(delegatedProcessLockRoot, delegatedWriterLockPath)
  ) {
    throw new Error(
      'The delegated repository writer lock must stay inside the test temp root.',
    );
  }
  return Object.freeze({
    auditRoot,
    delegatedProcessLockRoot,
    delegatedWriterLockPath,
    globalProcessLockRoot,
    globalWriterLockPath: canonicalGlobalWriterLockPath,
    sandboxWritableRoots,
    workerDatabaseRoots,
  });
}

export function buildDelegatedWriterAuthority({
  owner,
  processLockRoot,
  repositoryRoot = root,
  tempRoot,
  writerLeasePath,
} = {}) {
  if (
    !owner ||
    owner.pid !== process.pid ||
    typeof owner.token !== 'string' ||
    owner.token.length === 0 ||
    owner.token.trim() !== owner.token
  ) {
    throw new Error(
      'The delegated writer lock must use the real runner PID and a private token.',
    );
  }
  for (const [label, path] of [
    ['process-lock root', processLockRoot],
    ['temp root', tempRoot],
    ['writer lease path', writerLeasePath],
  ]) {
    if (typeof path !== 'string' || !isAbsolute(path)) {
      throw new Error(
        `The delegated writer ${label} must be an absolute path.`,
      );
    }
  }
  const canonicalTempRoot = realpathOrResolve(tempRoot);
  const canonicalProcessLockRoot = realpathOrResolve(processLockRoot);
  const canonicalWriterLeasePath = realpathOrResolve(writerLeasePath);
  if (
    !samePath(
      canonicalProcessLockRoot,
      join(canonicalTempRoot, 'process-locks'),
    )
  ) {
    throw new Error(
      'The delegated process-lock root must be tempRoot/process-locks.',
    );
  }
  if (!samePath(dirname(canonicalWriterLeasePath), canonicalTempRoot)) {
    throw new Error(
      'The delegated writer lease must be a direct child of the test temp root.',
    );
  }
  const lease = Object.freeze({
    token: owner.token,
    pid: owner.pid,
    repositoryRoot: canonicalPath(repositoryRoot),
  });
  const environment = Object.freeze({
    RADAR_TEST_ALLOWED_DB_ROOTS: JSON.stringify([canonicalTempRoot]),
    RADAR_TEST_PROCESS_LOCK_ROOT: canonicalProcessLockRoot,
    RADAR_TEST_WRITER_LOCK_PID: String(owner.pid),
    RADAR_TEST_WRITER_LEASE_PATH: canonicalWriterLeasePath,
    RADAR_TEST_WRITER_LOCK_TOKEN: owner.token,
  });
  return Object.freeze({ environment, lease });
}

export function createTestWriteBoundary({
  controlRoot,
  initialLiveFingerprint,
  repositoryRoot,
  runId,
  tempRoot,
  writableRoots,
}) {
  const backend = resolveTestWriteBoundaryBackend();
  if (!Array.isArray(writableRoots) || writableRoots.length === 0) {
    throw new Error('The test write boundary requires writable roots.');
  }
  const canonicalWritableRoots = [
    ...new Set(writableRoots.map((path) => canonicalPath(path))),
  ];
  for (const member of initialLiveFingerprint) {
    if (canonicalWritableRoots.some((path) => isWithin(path, member.path))) {
      throw new Error(
        `The live database family overlaps a sandbox-writable root: ${member.path}`,
      );
    }
  }
  const processIdentityHelper =
    prepareDarwinProcessIdentityHelper(controlRoot);
  const readDenialProbePath = join(controlRoot, '.sandbox-read-denial-probe');
  writePrivateControlFile(readDenialProbePath, 'sealed-read-probe');
  const unreadablePaths = [
    ...initialLiveFingerprint.map((member) => canonicalPath(member.path)),
    readDenialProbePath,
  ];
  const profile = buildDarwinSandboxProfile({
    unreadablePaths,
    writableRoots: canonicalWritableRoots,
  });
  const profileDigest = sha256(profile);
  const profilePath = join(controlRoot, 'darwin-seatbelt.sb');
  writePrivateControlFile(profilePath, profile);
  const policy = sealDatabaseGuardPolicy({
    schemaVersion: 1,
    kind: 'authoritative-test-database-guard-policy',
    runId,
    repositoryRoot,
    writableRoots: canonicalWritableRoots,
    executableRoots: [
      canonicalPath(join(repositoryRoot, 'node_modules')),
      canonicalPath(tempRoot),
    ],
    allowedExecutables: allowedExecutableIdentities([
      processIdentityHelper.path,
    ]),
    liveDatabaseFamily: initialLiveFingerprint.map((member) => ({
      path: canonicalPath(member.path),
      exists: member.exists,
      dev: member.dev,
      ino: member.ino,
    })),
    sandbox: {
      backend: backend.backend,
      executable: backend.executable,
      profileDigest,
    },
  });
  const policyPath = join(controlRoot, 'database-guard-policy.json');
  writePrivateControlFile(
    policyPath,
    `${JSON.stringify(policy, null, 2)}\n`,
  );
  verifyDarwinWriteBoundary({
    executablePath: backend.executable.path,
    profilePath,
    controlRoot,
    deniedReadPath: readDenialProbePath,
    tempRoot,
  });
  return {
    backend: backend.backend,
    policyDigest: policy.contentHash,
    policyPath,
    processIdentityHelper,
    profileDigest,
    profilePath,
    wrapCommand(command, args) {
      return {
        command: backend.executable.path,
        args: ['-f', profilePath, command, ...args],
      };
    },
  };
}

function prepareDarwinProcessIdentityHelper(controlRoot) {
  const helperPath = join(controlRoot, 'process-identity-darwin');
  const temporaryPath =
    `${helperPath}.${process.pid}.${randomUUID()}.tmp`;
  try {
    const result = spawnSync(
      '/usr/bin/cc',
      [
        '-std=c11',
        '-O2',
        '-Wall',
        '-Wextra',
        '-Werror',
        processIdentitySourcePath,
        '-o',
        temporaryPath,
      ],
      {
        cwd: controlRoot,
        encoding: 'utf8',
        maxBuffer: 64 * 1024,
        timeout: 15_000,
      },
    );
    if (result.error || result.signal || result.status !== 0) {
      throw new Error(
        `Unable to compile the Darwin process identity helper: ` +
        `${normalizeError(
          result.error ?? result.stderr ?? result.signal ?? result.status,
        ).message}`,
      );
    }
    chmodSync(temporaryPath, 0o500);
    const descriptor = openSync(temporaryPath, 'r');
    try {
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporaryPath, helperPath);
    fsyncDirectory(controlRoot);
    const identity = captureExecutableIdentity(helperPath);
    if (identity === null) {
      throw new Error(
        'The compiled Darwin process identity helper is not executable.',
      );
    }
    return {
      ...identity,
      digest: sha256(readFileSync(helperPath)),
    };
  } catch (error) {
    rmSync(temporaryPath, { force: true });
    rmSync(helperPath, { force: true });
    throw error;
  }
}

function sealDatabaseGuardPolicy(policy) {
  const content = { ...policy };
  delete content.contentHash;
  return {
    ...content,
    contentHash: sha256(
      `authoritative-test-database-guard-policy-v1\0${canonicalJson(content)}`,
    ),
  };
}

function writePrivateControlFile(path, contents) {
  const descriptor = openSync(
    path,
    fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_WRONLY,
    0o400,
  );
  try {
    writeFileSync(descriptor, contents);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(path, 0o400);
  fsyncDirectory(dirname(path));
}

function allowedExecutableIdentities(additionalPaths = []) {
  const candidates = [
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
    ...additionalPaths,
  ];
  const identities = new Map();
  for (const candidate of candidates) {
    const identity = captureExecutableIdentity(candidate);
    if (identity) {
      identities.set(
        `${identity.path}:${identity.dev}:${identity.ino}`,
        identity,
      );
    }
  }
  return [...identities.values()]
    .sort((left, right) => left.path.localeCompare(right.path));
}

function captureExecutableIdentity(path) {
  try {
    const canonical = realpathSync.native(path);
    const stats = statSync(canonical, { bigint: true });
    const mode = Number(stats.mode & 0o7777n);
    if (!stats.isFile() || (mode & 0o111) === 0) return null;
    return {
      path: canonical,
      dev: String(stats.dev),
      ino: String(stats.ino),
      mode,
      uid: Number(stats.uid),
    };
  } catch {
    return null;
  }
}

function verifyDarwinWriteBoundary({
  executablePath,
  profilePath,
  controlRoot,
  deniedReadPath,
  tempRoot,
}) {
  const allowedPath = join(tempRoot, '.sandbox-write-probe');
  const deniedPath = join(controlRoot, '.sandbox-denied-probe');
  writeFileSync(deniedPath, 'unsandboxed-write-proof', { mode: 0o600 });
  writeFileSync(deniedPath, 'sealed');
  const probeEnvironment = {
    HOME: process.env.HOME ?? tempRoot,
    LANG: 'C',
    LC_ALL: 'C',
    PATH: process.env.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin',
    TEMP: tempRoot,
    TMP: tempRoot,
    TMPDIR: tempRoot,
  };
  try {
    const allowed = spawnSync(
      executablePath,
      [
        '-f',
        profilePath,
        process.execPath,
        '-e',
        'require("node:fs").writeFileSync(process.argv[1], "allowed")',
        allowedPath,
      ],
      {
        cwd: root,
        encoding: 'utf8',
        env: probeEnvironment,
        maxBuffer: 64 * 1024,
        timeout: 5_000,
      },
    );
    if (
      allowed.error ||
      allowed.status !== 0 ||
      readFileSync(allowedPath, 'utf8') !== 'allowed'
    ) {
      throw new Error(
        `The macOS deny-write boundary rejected its writable-root probe: ` +
        `${normalizeError(allowed.error ?? allowed.stderr ?? allowed.status).message}`,
      );
    }
    const denied = spawnSync(
      executablePath,
      [
        '-f',
        profilePath,
        process.execPath,
        '-e',
        'require("node:fs").writeFileSync(process.argv[1], "escaped")',
        deniedPath,
      ],
      {
        cwd: root,
        encoding: 'utf8',
        env: probeEnvironment,
        maxBuffer: 64 * 1024,
        timeout: 5_000,
      },
    );
    if (
      denied.error ||
      denied.status === 0 ||
      readFileSync(deniedPath, 'utf8') !== 'sealed'
    ) {
      throw new Error(
        'The macOS deny-write boundary did not reject an out-of-root write.',
      );
    }
    const deniedRead = spawnSync(
      executablePath,
      [
        '-f',
        profilePath,
        process.execPath,
        '-e',
        'require("node:fs").readFileSync(process.argv[1])',
        deniedReadPath,
      ],
      {
        cwd: root,
        encoding: 'utf8',
        env: probeEnvironment,
        maxBuffer: 64 * 1024,
        timeout: 5_000,
      },
    );
    if (deniedRead.error || deniedRead.status === 0) {
      throw new Error(
        'The macOS read boundary did not reject a protected database read.',
      );
    }
  } finally {
    rmSync(allowedPath, { force: true });
    rmSync(deniedPath, { force: true });
  }
}

async function initializeRunResources({
  runId,
  limits,
  globalWriterLockPath,
  configuredLiveDatabase,
  initialLiveFingerprint,
  watchdogEnvironment,
}) {
  let tempRoot = null;
  let controlRoot = null;
  let delegatedWriterLock = null;
  let processLockLayout = null;
  let watchdog = null;
  let auditPath = null;
  try {
    scavengeOrphanedTestRoots();
    tempRoot = canonicalPath(mkdtempSync(join(
      tmpdir(),
      testRootPrefixForRepository(canonicalRoot),
    )));
    processLockLayout = resolveTestProcessLockLayout({
      repositoryRoot: canonicalRoot,
      tempRoot,
      globalWriterLockPath,
    });
    delegatedWriterLock = acquireExclusiveProcessLock({
      lockPath: processLockLayout.delegatedWriterLockPath,
      label: 'authoritative test suite delegated writer',
      resourceLabel: 'delegated repository database writer',
      pid: process.pid,
    });
    controlRoot = canonicalPath(mkdtempSync(join(
      tmpdir(),
      `${testRootPrefixForRepository(canonicalRoot)}controls-`,
    )));
    const tempRootOwnerPath = join(tempRoot, tempRootOwnerFile);
    const controlRootOwnerPath = join(controlRoot, tempRootOwnerFile);
    const runnerOwnerPaths = resolveResourceWatchdogOwnerPaths({
      tempRoot,
      tempRootOwnerPath,
      additionalOwnerPaths: [controlRootOwnerPath],
    });
    const initialOwnerState = {
      schemaVersion: 1,
      repositoryIdentity,
      repositoryRoot: canonicalRoot,
      runId,
      parentPid: process.pid,
      heartbeatAt: new Date().toISOString(),
      completed: false,
    };
    for (const ownerPath of runnerOwnerPaths) {
      writeTempRootOwnerState(ownerPath, initialOwnerState);
    }
    const installerFixture = materializePrivateInstallerHeredocs({
      sourcePath: productionInstallerPath,
      fixtureRoot: join(controlRoot, 'installer-heredocs'),
      expectedHeredocCount:
        PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT,
      forbidShellHereStrings: true,
    });
    const auditRoot = processLockLayout.auditRoot;
    prepareAuditRoot(auditRoot);
    auditPath = join(auditRoot, `${runId}.jsonl`);
    const emptyDotenvPath = join(tempRoot, 'empty.env');
    const runnerDatabasePath = join(tempRoot, 'runner.db');
    const writerLeasePath = join(tempRoot, 'writer-lease.json');
    const writerAuthority = buildDelegatedWriterAuthority({
      owner: delegatedWriterLock.owner,
      processLockRoot: processLockLayout.delegatedProcessLockRoot,
      repositoryRoot: canonicalRoot,
      tempRoot,
      writerLeasePath,
    });
    const systemDiskTransferBaselineBytes =
      captureSystemDiskTransferBytes();
    writeFileSync(auditPath, '', { flag: 'wx', mode: 0o600 });
    writeFileSync(emptyDotenvPath, '', { flag: 'wx', mode: 0o600 });
    writeFileSync(
      writerLeasePath,
      `${JSON.stringify(writerAuthority.lease)}\n`,
      { flag: 'wx', mode: 0o600 },
    );
    const writeBoundary = createTestWriteBoundary({
      controlRoot,
      initialLiveFingerprint,
      repositoryRoot: canonicalRoot,
      runId,
      tempRoot,
      writableRoots: processLockLayout.sandboxWritableRoots,
    });
    assertFreeSpace(tempRoot, limits.minimumStartingFreeBytes);
    appendAuditEvent(auditPath, {
      type: 'runner-start',
      runId,
      pid: process.pid,
      repositoryIdentity,
      repositoryRoot: canonicalRoot,
      tempRoot,
      delegatedWriterLock: {
        path: delegatedWriterLock.path,
        pid: delegatedWriterLock.owner.pid,
      },
      writeBoundary: {
        backend: writeBoundary.backend,
        policyDigest: writeBoundary.policyDigest,
        profileDigest: writeBoundary.profileDigest,
      },
      resourceLimits: limits,
      systemDiskTransferBaselineBytes,
      startedAt: new Date().toISOString(),
    });
    watchdog = await startResourceWatchdog({
      runId,
      tempRoot,
      tempRootOwnerPath,
      additionalOwnerPaths: [controlRootOwnerPath],
      auditPath,
      auditRoot,
      limits,
      systemDiskTransferBaselineBytes,
      repositoryIdentity,
      repositoryRoot: canonicalRoot,
      childEnvironment: watchdogEnvironment,
      liveDatabase: configuredLiveDatabase,
    });
    return {
      auditPath,
      controlRoot,
      databaseGuardPolicyPath: writeBoundary.policyPath,
      delegatedWriterLock,
      emptyDotenvPath,
      installerFixtureIdentity: installerFixture.fixtureIdentity,
      installerFixturePath: installerFixture.installerPath,
      runnerDatabasePath,
      tempRoot,
      watchdog,
      writeBoundary,
      writerEnvironment: writerAuthority.environment,
    };
  } catch (error) {
    const cleanupErrors = [];
    let preserveTempRoot = false;
    let delegatedWriterLockReleased = false;
    let watchdogReceipt = null;
    if (tempRoot) {
      if (auditPath) {
        await runCleanupStep(
          cleanupErrors,
          'resource initialization failure audit event',
          () => appendAuditEvent(auditPath, {
            type: 'runner-initialization-failure',
            runId,
            pid: process.pid,
            message: normalizeError(error).message,
            recordedAt: new Date().toISOString(),
          }),
        );
      }
    }
    if (cleanupErrors.length > 0) preserveTempRoot = true;
    if (delegatedWriterLock) {
      await runCleanupStep(
        cleanupErrors,
        'partially initialized delegated writer lock release',
        () => {
          delegatedWriterLock.release();
          delegatedWriterLockReleased = true;
        },
      );
      if (!delegatedWriterLockReleased) preserveTempRoot = true;
    }
    if (watchdog) {
      await runCleanupStep(
        cleanupErrors,
        'partially initialized resource watchdog completion',
        async () => {
          watchdogReceipt = await watchdog.complete({ preserveTempRoot });
        },
      );
      await runCleanupStep(
        cleanupErrors,
        'partially initialized resource watchdog terminal audit rescan',
        () => assertWatchdogTerminalAudit({
          auditPath,
          receipt: watchdogReceipt,
          receiptPath: watchdog.receiptPath,
          runId,
        }),
      );
    }
    if (tempRoot) {
      await runCleanupStep(
        cleanupErrors,
        'resource initialization live database verification',
        () => assertSqliteFamilyUnchanged(
          configuredLiveDatabase,
          initialLiveFingerprint,
          'test-run resource initialization failure',
        ),
      );
      if (auditPath) {
        await runCleanupStep(
          cleanupErrors,
          'resource initialization database audit verification',
          () => assertDatabaseAudit({
            auditPath,
            expectedFiles: [],
            tempRoot,
            liveDatabase: configuredLiveDatabase,
            runId,
            requireCompleteCoverage: false,
          }),
        );
      }
    }
    if (cleanupErrors.length > 0) preserveTempRoot = true;
    if (tempRoot && !preserveTempRoot) {
      await runCleanupStep(
        cleanupErrors,
        'partially initialized temporary root removal',
        () => rmSync(tempRoot, { recursive: true, force: true }),
      );
    }
    if (controlRoot && !preserveTempRoot) {
      await runCleanupStep(
        cleanupErrors,
        'partially initialized control root removal',
        () => rmSync(controlRoot, { recursive: true, force: true }),
      );
    }
    if (preserveTempRoot && tempRoot) {
      console.error(
        `[test-runner] preserved partially initialized diagnostics at ${tempRoot}`,
      );
      if (controlRoot) {
        console.error(
          `[test-runner] preserved partial safety controls at ${controlRoot}`,
        );
      }
    }
    throw combineErrors(
      normalizeError(error),
      cleanupErrors,
      'Test-run resource initialization failed and cleanup was incomplete',
    );
  }
}

export function canonicalRepositoryIdentity(repositoryRoot = root) {
  return sha256(canonicalPath(repositoryRoot));
}

export function testRootPrefixForRepository(repositoryRoot = root) {
  return `openclaw-radar-tests-${
    canonicalRepositoryIdentity(repositoryRoot).slice(0, 16)
  }-`;
}

export function scavengeOrphanedTestRoots({
  repositoryRoot = root,
  tempDirectory = tmpdir(),
  now = Date.now(),
  staleHeartbeatMs = orphanHeartbeatStaleMs,
} = {}) {
  const expectedIdentity = canonicalRepositoryIdentity(repositoryRoot);
  const prefix = testRootPrefixForRepository(repositoryRoot);
  const removed = [];
  for (const entry of readdirSync(tempDirectory, { withFileTypes: true })) {
    if (!entry.isDirectory() || !entry.name.startsWith(prefix)) continue;
    const path = join(tempDirectory, entry.name);
    const stats = lstatSync(path);
    if (
      stats.isSymbolicLink() ||
      (typeof process.getuid === 'function' && stats.uid !== process.getuid()) ||
      (stats.mode & 0o077) !== 0
    ) {
      continue;
    }
    let owner;
    try {
      owner = readJsonFileOrNull(join(path, tempRootOwnerFile));
    } catch {
      continue;
    }
    if (
      owner?.schemaVersion !== 1 ||
      owner.repositoryIdentity !== expectedIdentity ||
      !Number.isInteger(owner.parentPid) ||
      owner.parentPid <= 0 ||
      typeof owner.heartbeatAt !== 'string'
    ) {
      continue;
    }
    const heartbeatAge = now - Date.parse(owner.heartbeatAt);
    if (
      processAlive(owner.parentPid) ||
      !Number.isFinite(heartbeatAge) ||
      heartbeatAge < staleHeartbeatMs
    ) {
      continue;
    }
    rmSync(path, { recursive: true, force: true });
    removed.push(path);
  }
  return removed;
}

function resolveResourceWatchdogOwnerPaths({
  tempRoot,
  tempRootOwnerPath,
  additionalOwnerPaths = [],
}) {
  if (!Array.isArray(additionalOwnerPaths)) {
    throw new Error(
      'Resource watchdog additional owner paths must be an array.',
    );
  }
  const ownerPaths = [
    tempRootOwnerPath,
    ...additionalOwnerPaths,
  ].map((ownerPath) => {
    if (
      typeof ownerPath !== 'string' ||
      !isAbsolute(ownerPath) ||
      basename(ownerPath) !== tempRootOwnerFile
    ) {
      throw new Error(
        `Resource watchdog owner paths must be absolute ` +
        `${tempRootOwnerFile} paths.`,
      );
    }
    const absoluteOwnerPath = resolve(ownerPath);
    const ownerRoot = dirname(absoluteOwnerPath);
    const rootStats = lstatSync(ownerRoot);
    if (
      !rootStats.isDirectory() ||
      rootStats.isSymbolicLink() ||
      (
        typeof process.getuid === 'function' &&
        rootStats.uid !== process.getuid()
      ) ||
      (rootStats.mode & 0o077) !== 0
    ) {
      throw new Error(
        `Resource watchdog owner root must be private and owner-only: ` +
        `${ownerRoot}`,
      );
    }
    if (existsSync(absoluteOwnerPath)) {
      const ownerStats = lstatSync(absoluteOwnerPath);
      if (
        !ownerStats.isFile() ||
        ownerStats.isSymbolicLink() ||
        (
          typeof process.getuid === 'function' &&
          ownerStats.uid !== process.getuid()
        ) ||
        (ownerStats.mode & 0o077) !== 0
      ) {
        throw new Error(
          `Resource watchdog owner state must be a private regular file: ` +
          `${absoluteOwnerPath}`,
        );
      }
    }
    return absoluteOwnerPath;
  });
  if (!samePath(dirname(ownerPaths[0]), tempRoot)) {
    throw new Error(
      'The primary resource watchdog owner path must belong to tempRoot.',
    );
  }
  const canonicalOwnerPaths = ownerPaths.map((ownerPath) =>
    realpathOrResolve(ownerPath));
  if (new Set(canonicalOwnerPaths).size !== ownerPaths.length) {
    throw new Error('Resource watchdog owner paths must be distinct.');
  }
  return Object.freeze(ownerPaths);
}

export async function startResourceWatchdog({
  runId,
  tempRoot,
  tempRootOwnerPath = join(tempRoot, tempRootOwnerFile),
  additionalOwnerPaths = [],
  auditPath,
  auditRoot,
  limits,
  systemDiskTransferBaselineBytes =
    captureSystemDiskTransferBytes(),
  repositoryIdentity: expectedRepositoryIdentity =
    canonicalRepositoryIdentity(root),
  repositoryRoot = canonicalRoot,
  childEnvironment = process.env,
  liveDatabase =
    resolveConfiguredLiveDatabase({ root }) ?? join(root, 'data', 'radar.db'),
}) {
  const ownerPaths = resolveResourceWatchdogOwnerPaths({
    tempRoot,
    tempRootOwnerPath,
    additionalOwnerPaths,
  });
  const primaryOwnerPath = ownerPaths[0];
  const statePath = join(auditRoot, `${runId}.watchdog.json`);
  const receiptPath = join(auditRoot, `${runId}.watchdog-receipt.json`);
  const watchdogToken = `${randomUUID()}${randomUUID()}`;
  const parentIdentity = captureProcessIdentity(process.pid);
  if (!parentIdentity) {
    throw new Error('Unable to capture the test runner process identity.');
  }
  const auditRootIdentity = capturePathIdentity(auditRoot);
  const auditPathIdentity = capturePathIdentity(auditPath);
  const tempRootIdentity = capturePathIdentity(tempRoot);
  let completed = false;
  let activeProcessGroupPid = null;
  let activeProcessGroupIdentity = null;
  let activeProcessGroupAllowedCommandDigests = null;
  let heartbeat = null;
  const failure = createFailureChannel();
  const writeState = (extra = {}) => {
    if (completed) return;
    const heartbeatAt = new Date().toISOString();
    const state = sealWatchdogState({
      schemaVersion: 2,
      runId,
      parentPid: process.pid,
      parentIdentity,
      repositoryIdentity: expectedRepositoryIdentity,
      repositoryRoot,
      auditRoot,
      auditRootIdentity,
      tempRoot,
      tempRootIdentity,
      tempRootOwnerPath: primaryOwnerPath,
      auditPath,
      auditPathIdentity,
      receiptPath,
      heartbeatAt,
      activeProcessGroupPid,
      activeProcessGroupIdentity,
      activeProcessGroupAllowedCommandDigests,
      completed: false,
      limits,
      systemDiskTransferBaselineBytes,
      ...extra,
    }, watchdogToken);
    writeWatchdogState(statePath, state);
    const ownerState = {
      schemaVersion: 1,
      repositoryIdentity: expectedRepositoryIdentity,
      repositoryRoot,
      runId,
      parentPid: process.pid,
      heartbeatAt,
      completed: state.completed === true,
    };
    for (const ownerPath of ownerPaths) {
      writeTempRootOwnerState(ownerPath, ownerState);
    }
  };
  writeState();
  const sanitizedChildEnvironment = sanitizeTestChildEnvironment({
    environment: childEnvironment,
    liveDatabase,
  });
  const child = spawn(process.execPath, [resourceWatchdogPath, statePath], {
    cwd: root,
    detached: true,
    env: {
      ...sanitizedChildEnvironment,
      ...(process.env.RADAR_TEST_RUN_ID
        ? childEnvironment
        : {}),
      RADAR_TEST_WATCHDOG_REPOSITORY_IDENTITY: expectedRepositoryIdentity,
      RADAR_TEST_WATCHDOG_RUN_ID: runId,
      RADAR_TEST_WATCHDOG_STATE_PATH: statePath,
      RADAR_TEST_WATCHDOG_TOKEN: watchdogToken,
      ...(process.env.RADAR_TEST_RUN_ID
        ? {
          RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog',
        }
        : {}),
    },
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  let watchdogErrorTail = '';
  child.stderr?.on('data', (chunk) => {
    watchdogErrorTail = `${watchdogErrorTail}${String(chunk)}`
      .slice(-maximumCapturedOutputTailBytes);
  });
  try {
    await waitForWatchdogReady(child, {
      runId,
      statePath,
      timeoutMs: watchdogReadinessTimeoutMs,
    });
  } catch (error) {
    try {
      child.kill('SIGKILL');
    } catch {
      // Readiness failure still rejects even if the watchdog already exited.
    }
    await waitForExitWithin(child, phaseTerminationGraceMs);
    throw new Error(
      `${normalizeError(error).message}` +
      `${watchdogErrorTail
        ? `\nResource watchdog stderr:\n${watchdogErrorTail.trim()}`
        : ''}`,
    );
  }
  child.once('error', (error) => {
    try {
      failure.report(error);
    } catch {
      // The failure channel itself is nonthrowing.
    }
  });
  child.once('exit', (code, signal) => {
    try {
      if (!completed) {
        failure.report(
          new Error(
            `Resource watchdog exited before completion with ` +
            `${signal ? `signal ${signal}` : `code ${String(code)}`}.` +
            `${watchdogErrorTail
              ? `\nResource watchdog stderr:\n${watchdogErrorTail.trim()}`
              : ''}`,
          ),
        );
      }
    } catch {
      // Event callbacks must never throw into Node's event machinery.
    }
  });
  if (child.exitCode !== null || child.signalCode !== null) {
    failure.report(
      new Error('Resource watchdog exited immediately after readiness.'),
    );
  }
  try {
    child.disconnect();
  } catch {
    // The watchdog may already have disconnected after acknowledging readiness.
  }
  child.unref();
  heartbeat = setInterval(() => {
    try {
      writeState();
    } catch (error) {
      failure.report(error);
    }
  }, 1_000);
  heartbeat.unref();
  return {
    ready: true,
    receiptPath,
    failure: failure.promise,
    setActiveProcessGroup(pid, {
      allowedCommandDigests = [],
    } = {}) {
      if (completed) {
        throw new Error('Cannot change a completed resource watchdog.');
      }
      if (Number.isInteger(pid) && pid > 0) {
        if (
          !Array.isArray(allowedCommandDigests) ||
          allowedCommandDigests.length > 7 ||
          allowedCommandDigests.some((digest) =>
            typeof digest !== 'string' ||
            !/^[0-9a-f]{64}$/.test(digest))
        ) {
          throw new Error(
            'Allowed process-group command digests are malformed.',
          );
        }
        const identity = captureProcessIdentity(pid);
        if (!identity) {
          throw new Error(
            `Unable to capture test process-group identity for ${pid}.`,
          );
        }
        if (
          process.platform !== 'win32' &&
          identity.processGroupPid !== pid
        ) {
          throw new Error(
            `Test process ${pid} is not the leader of process group ` +
            `${String(identity.processGroupPid)}.`,
          );
        }
        activeProcessGroupPid = pid;
        activeProcessGroupIdentity = identity;
        activeProcessGroupAllowedCommandDigests = [
          ...new Set([
            identity.commandDigest,
            ...allowedCommandDigests,
          ]),
        ].sort();
      } else {
        activeProcessGroupPid = null;
        activeProcessGroupIdentity = null;
        activeProcessGroupAllowedCommandDigests = null;
      }
      writeState();
    },
    async complete({ preserveTempRoot }) {
      if (completed) return;
      if (activeProcessGroupPid !== null) {
        throw new Error(
          `Cannot complete watchdog while process group ` +
          `${activeProcessGroupPid} is still owned.`,
        );
      }
      try {
        writeState({
          completed: true,
          preserveTempRoot,
        });
        completed = true;
        if (heartbeat) clearInterval(heartbeat);
      } catch (error) {
        completed = true;
        if (heartbeat) clearInterval(heartbeat);
        try {
          child.kill('SIGKILL');
        } catch {
          // The watchdog may already have exited.
        }
        await waitForExitWithin(child, phaseTerminationGraceMs);
        throw error;
      }
      if (!await waitForExitWithin(child, phaseTerminationGraceMs)) {
        try {
          child.kill('SIGKILL');
        } catch {
          // The watchdog may exit between the wait and the signal.
        }
        if (!await waitForExitWithin(child, phaseTerminationGraceMs)) {
          throw new Error('Resource watchdog did not exit after completion.');
        }
      }
      const receipt = readWatchdogTerminalReceipt(receiptPath, {
        auditPath,
        parentIdentity,
        parentPid: process.pid,
        requireSuccess: false,
        receiptPath,
        runId,
        statePath,
        tempRoot,
        watchdogPid: child.pid,
      });
      assertWatchdogTerminalAudit({
        auditPath,
        receipt,
        receiptPath,
        runId,
      });
      if (child.signalCode !== null || child.exitCode !== 0) {
        throw new Error(
          `Resource watchdog completion failed with ` +
          `${child.signalCode
            ? `signal ${child.signalCode}`
            : `exit code ${String(child.exitCode)}`}.`,
        );
      }
      return receipt;
    },
    abandon() {
      if (completed) return;
      completed = true;
      if (heartbeat) clearInterval(heartbeat);
    },
  };
}

function writeTempRootOwnerState(path, value) {
  writeWatchdogState(path, value);
}

function waitForWatchdogReady(child, {
  runId,
  statePath,
  timeoutMs,
}) {
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let timeout = null;
    const cleanup = () => {
      if (timeout) clearTimeout(timeout);
      child.off('message', onMessage);
      child.off('error', onError);
      child.off('exit', onExit);
    };
    const resolveReady = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolvePromise();
    };
    const rejectReady = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      rejectPromise(normalizeError(error));
    };
    const onMessage = (message) => {
      try {
        if (
          message?.type === 'watchdog-ready' &&
          message.runId === runId &&
          message.statePath === statePath
        ) {
          resolveReady();
        }
      } catch (error) {
        rejectReady(error);
      }
    };
    const onError = (error) => {
      try {
        rejectReady(error);
      } catch {
        // Readiness callbacks must never throw into the event emitter.
      }
    };
    const onExit = (code, signal) => {
      try {
        rejectReady(
          new Error(
            `Resource watchdog exited before readiness with ` +
            `${signal ? `signal ${signal}` : `code ${String(code)}`}.`,
          ),
        );
      } catch {
        // Readiness callbacks must never throw into the event emitter.
      }
    };
    child.on('message', onMessage);
    child.once('error', onError);
    child.once('exit', onExit);
    timeout = setTimeout(() => {
      try {
        rejectReady(
          new Error(
            `Resource watchdog did not acknowledge readiness within ` +
            `${timeoutMs}ms.`,
          ),
        );
      } catch {
        // The timeout must settle the promise without throwing.
      }
    }, timeoutMs);
  });
}

function writeWatchdogState(path, value) {
  const temporaryPath =
    `${path}.${process.pid}.${randomUUID()}.tmp`;
  const descriptor = openSync(temporaryPath, 'wx', 0o600);
  try {
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    renameSync(temporaryPath, path);
    fsyncDirectory(dirname(path));
  } finally {
    rmSync(temporaryPath, { force: true });
  }
}

export function readWatchdogTerminalReceipt(receiptPath, expected = {}) {
  let receipt;
  try {
    receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
  } catch (error) {
    throw new Error(
      `Resource watchdog terminal receipt is missing or malformed: ` +
      `${normalizeError(error).message}`,
    );
  }
  if (!verifyWatchdogReceiptSeal(receipt)) {
    throw new Error('Resource watchdog terminal receipt seal is invalid.');
  }
  const exactFields = [
    'auditPath',
    'parentPid',
    'receiptPath',
    'runId',
    'statePath',
    'tempRoot',
    'watchdogPid',
  ];
  for (const field of exactFields) {
    if (
      Object.hasOwn(expected, field) &&
      receipt[field] !== expected[field]
    ) {
      throw new Error(
        `Resource watchdog terminal receipt ${field} does not match.`,
      );
    }
  }
  if (
    expected.parentIdentity &&
    watchdogCanonicalJson(receipt.parentIdentity) !==
      watchdogCanonicalJson(expected.parentIdentity)
  ) {
    throw new Error(
      'Resource watchdog terminal receipt parent identity does not match.',
    );
  }
  if (
    expected.requireSuccess !== false &&
    (receipt.outcome !== 'completed' || receipt.success !== true)
  ) {
    throw new Error(
      `Resource watchdog terminal receipt reports ` +
      `${String(receipt.outcome)} instead of successful completion.`,
    );
  }
  return receipt;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return String(bytes);
  if (bytes >= gibibyte) return `${(bytes / gibibyte).toFixed(2)} GiB`;
  return `${(bytes / mebibyte).toFixed(2)} MiB`;
}

function killProcessTree(child, signal) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform !== 'win32' && child.pid) {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // Fall through to the direct child if the process group already exited.
    }
  }
  try {
    child.kill(signal);
  } catch {
    // The process exited between the state check and the signal.
  }
}

async function terminateProcessTreeAndWait(child) {
  if (!child) return true;
  if (child.exitCode === null && child.signalCode === null) {
    killProcessTree(child, 'SIGTERM');
    if (!await waitForExitWithin(child, phaseTerminationGraceMs)) {
      killProcessTree(child, 'SIGKILL');
      await waitForExitWithin(child, phaseTerminationGraceMs);
    }
  }
  return await terminateResidualProcessGroup(child.pid);
}

function waitForExitWithin(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve(true);
  }
  return new Promise((resolvePromise) => {
    let timer = null;
    const onExit = () => {
      if (timer) clearTimeout(timer);
      resolvePromise(true);
    };
    child.once('exit', onExit);
    timer = setTimeout(() => {
      child.off('exit', onExit);
      resolvePromise(false);
    }, timeoutMs);
  });
}

async function terminateResidualProcessGroup(pid) {
  if (
    process.platform === 'win32' ||
    !Number.isInteger(pid) ||
    pid <= 0 ||
    !processGroupAlive(pid)
  ) {
    return true;
  }
  signalProcessGroup(pid, 'SIGTERM');
  if (await waitForProcessGroupExit(pid, phaseTerminationGraceMs)) return true;
  signalProcessGroup(pid, 'SIGKILL');
  return await waitForProcessGroupExit(pid, phaseTerminationGraceMs);
}

function processGroupAlive(pid) {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

function signalProcessGroup(pid, signal) {
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error;
  }
}

function waitForProcessGroupExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolvePromise) => {
    const inspect = () => {
      if (!processGroupAlive(pid)) {
        resolvePromise(true);
        return;
      }
      if (Date.now() >= deadline) {
        resolvePromise(false);
        return;
      }
      setTimeout(inspect, 50);
    };
    inspect();
  });
}

export function assertDatabaseAudit({
  auditPath,
  expectedFiles,
  tempRoot,
  liveDatabase,
  runId,
  requireCompleteCoverage = true,
}) {
  const events = readJsonLines(auditPath, 'database audit');
  if (events.length === 0) {
    throw new Error('Database audit is empty.');
  }
  const problems = [];
  for (const event of events) {
    if (event.runId !== runId) {
      problems.push(`audit event has unexpected run ID ${String(event.runId)}`);
    }
    if (event.blocked === true) {
      problems.push(
        `database guard blocked ${event.type ?? 'unknown'} in pid ${event.pid ?? 'unknown'}`,
      );
    }
    if (event.outsideAllowedRoots === true) {
      problems.push(
        `database access escaped allowed roots: ${event.resolvedPath ?? event.location}`,
      );
    }
    if (event.resolvedPath &&
        samePath(event.resolvedPath, liveDatabase)) {
      problems.push(`database audit referenced the live database: ${event.resolvedPath}`);
    }
  }

  const expected = new Set(expectedFiles);
  const workerEvents = events.filter((event) => event.type === 'worker-env');
  const processStartsByPid = new Map();
  for (const event of events.filter((candidate) =>
    candidate.type === 'process-start')) {
    const starts = processStartsByPid.get(event.pid) ?? [];
    starts.push(event);
    processStartsByPid.set(event.pid, starts);
  }
  const workersByFile = new Map();
  const workerDatabases = new Set();
  for (const event of workerEvents) {
    const file = normalizeAuditScript(event.script);
    const entries = workersByFile.get(file) ?? [];
    entries.push(event);
    workersByFile.set(file, entries);
    if (typeof event.dbPath !== 'string' || !isWithin(tempRoot, event.dbPath)) {
      problems.push(`worker ${file} did not receive a private suite database.`);
    } else if (workerDatabases.has(realpathOrResolve(event.dbPath))) {
      problems.push(`worker database was reused: ${event.dbPath}`);
    } else {
      workerDatabases.add(realpathOrResolve(event.dbPath));
    }
    const processStarts = processStartsByPid.get(event.pid) ?? [];
    if (processStarts.length === 0) {
      problems.push(`worker ${file} has no guarded process-start audit event.`);
    } else if (processStarts.some((start) =>
      typeof start.dbPath !== 'string' ||
      typeof start.workerDbPath !== 'string' ||
      !samePath(start.dbPath, event.dbPath) ||
      !samePath(start.workerDbPath, event.dbPath))) {
      problems.push(
        `worker ${file} did not start on its assigned private suite database.`,
      );
    }
  }
  for (const file of expected) {
    const workers = workersByFile.get(file) ?? [];
    if (
      (requireCompleteCoverage && workers.length !== 1) ||
      (!requireCompleteCoverage && workers.length > 1)
    ) {
      problems.push(
        requireCompleteCoverage
          ? `expected exactly one isolated worker for ${file}, observed ${workers.length}`
          : `expected at most one isolated worker for ${file}, observed ${workers.length}`,
      );
    }
  }
  for (const file of workersByFile.keys()) {
    if (!expected.has(file)) problems.push(`unexpected isolated worker for ${file}`);
  }

  const cleanedDatabases = new Set(
    events
      .filter((event) => event.type === 'worker-cleanup')
      .map((event) => realpathOrResolve(String(event.dbPath))),
  );
  for (const database of workerDatabases) {
    if (!cleanedDatabases.has(database)) {
      problems.push(`worker database was not audited as cleaned: ${database}`);
    }
  }
  for (const event of events.filter((candidate) =>
    candidate.type === 'worker-cleanup')) {
    if (event.removed !== true || typeof event.workerDir !== 'string') {
      problems.push(`worker cleanup event is incomplete for ${event.dbPath}`);
      continue;
    }
    if (existsSync(event.workerDir)) {
      problems.push(`worker directory still exists after cleanup: ${event.workerDir}`);
    }
  }
  if (problems.length > 0) {
    throw new Error(
      `[test-database-audit] failed:\n` +
      problems.map((problem) => `- ${problem}`).join('\n'),
    );
  }
}

function readJsonLines(path, label) {
  const text = readFileSync(path, 'utf8');
  return text
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(
          `Invalid ${label} JSON at ${path}:${index + 1}: ${error.message}`,
        );
      }
    });
}

export function latestWatchdogResourceBreach(auditPath, runId) {
  const events = readJsonLines(auditPath, 'resource watchdog audit');
  for (let index = events.length - 1; index >= 0; index--) {
    const event = events[index];
    if (
      event?.type === 'watchdog-resource-breach' &&
      event.runId === runId
    ) {
      return event;
    }
  }
  return null;
}

export function assertWatchdogTerminalAudit({
  auditPath,
  receipt = null,
  receiptPath,
  runId,
}) {
  const terminalReceipt = receipt ?? readWatchdogTerminalReceipt(
    receiptPath,
    {
      requireSuccess: false,
      runId,
    },
  );
  const events = readJsonLines(auditPath, 'resource watchdog terminal audit');
  const runEvents = events.filter((event) => event?.runId === runId);
  const breaches = runEvents.filter((event) =>
    event?.type === 'resource-breach' ||
    event?.type === 'watchdog-resource-breach');
  const summaries = runEvents.filter((event) =>
    event?.type === 'watchdog-process-write-summary');
  const terminals = runEvents.filter((event) =>
    event?.type === 'watchdog-terminal-receipt');
  if (summaries.length !== 1 || terminals.length !== 1) {
    throw new Error(
      `Resource watchdog terminal audit is incomplete: ` +
      `${summaries.length} summaries and ${terminals.length} receipts.`,
    );
  }
  const summaryIndex = runEvents.indexOf(summaries[0]);
  const terminalIndex = runEvents.indexOf(terminals[0]);
  if (
    summaryIndex < 0 ||
    terminalIndex <= summaryIndex ||
    terminalIndex !== runEvents.length - 1
  ) {
    throw new Error(
      'Resource watchdog terminal receipt was not the final durable run event after its summary.',
    );
  }
  for (const event of [summaries[0], terminals[0]]) {
    if (
      event.outcome !== terminalReceipt.outcome ||
      event.success !== terminalReceipt.success ||
      event.stateRemoved !== terminalReceipt.stateRemoved
    ) {
      throw new Error(
        'Resource watchdog terminal audit disagrees with its sealed receipt.',
      );
    }
  }
  if (
    terminals[0].contentHash !== terminalReceipt.contentHash ||
    watchdogCanonicalJson(summaries[0].processWriteAccounting) !==
      watchdogCanonicalJson(terminalReceipt.processWriteAccounting) ||
    watchdogCanonicalJson(terminals[0].processWriteAccounting) !==
      watchdogCanonicalJson(terminalReceipt.processWriteAccounting)
  ) {
    throw new Error(
      'Resource watchdog terminal accounting or receipt hash does not agree.',
    );
  }
  if (
    breaches.length > 0 ||
    terminalReceipt.detail?.resourceBreach != null ||
    terminalReceipt.outcome !== 'completed' ||
    terminalReceipt.success !== true ||
    terminalReceipt.stateRemoved !== true
  ) {
    const breach =
      breaches.at(-1)?.detail?.resourceProblem ??
      terminalReceipt.detail?.resourceBreach?.resourceProblem ??
      null;
    throw new Error(
      `Resource watchdog terminal state is unsafe: ` +
      `${
        breach?.kind ??
        (
          terminalReceipt.stateRemoved === true
            ? terminalReceipt.outcome
            : 'watchdog-state-removal-failure'
        ) ??
        'unknown failure'
      }.`,
    );
  }
  return terminalReceipt;
}

function watchdogResourceBreachError(event, phase) {
  const problem = event?.detail?.resourceProblem;
  const kind =
    typeof problem?.kind === 'string' ? problem.kind : 'unknown-resource';
  const observed = formatBytes(problem?.observedBytes);
  const limit = formatBytes(problem?.limitBytes);
  return new Error(
    `Validation resource watchdog stopped the ${phase} phase: ` +
    `${kind} reached ${observed} with a limit of ${limit}.`,
  );
}

function normalizeAuditScript(value) {
  if (typeof value !== 'string' || value.length === 0) return '<unknown>';
  let path = value;
  if (path.startsWith('file:')) path = fileURLToPath(path);
  const absolute = isAbsolute(path) ? resolve(path) : resolve(root, path);
  return normalizePath(relative(root, absolute));
}

function writeJsonAtomically(targetPath, value, {
  targetBefore,
  invariants = [],
  expectedTree,
  captureTree,
}) {
  const temporaryPath = join(
    dirname(targetPath),
    `.${basename(targetPath)}.${process.pid}.${randomUUID()}.tmp`,
  );
  const mode = targetBefore.mode ?? 0o644;
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  const fileDescriptor = openSync(temporaryPath, 'wx', mode);
  try {
    writeFileSync(fileDescriptor, serialized);
    fsyncSync(fileDescriptor);
  } finally {
    closeSync(fileDescriptor);
  }
  const temporarySnapshot = captureFileSnapshot(temporaryPath);

  try {
    assertFileSnapshotUnchanged(
      targetPath,
      targetBefore,
      'target JSON file',
      'atomic JSON write',
    );
    for (const invariant of invariants) {
      assertFileSnapshotUnchanged(
        invariant.path,
        invariant.snapshot,
        invariant.label,
        'atomic JSON write',
      );
    }
    const currentTree = captureTree(temporaryPath);
    assertTreeUnchanged(expectedTree, currentTree, 'atomic JSON write');
    renameSync(temporaryPath, targetPath);
    const directoryDescriptor = openSync(dirname(targetPath), 'r');
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
    assertInstalledFileSnapshot(
      targetPath,
      temporarySnapshot,
      sha256(serialized),
    );
  } finally {
    rmSync(temporaryPath, { force: true });
  }
}

function assertInstalledFileSnapshot(path, sourceSnapshot, expectedDigest) {
  const installed = captureFileSnapshot(path);
  if (
    !installed.exists ||
    installed.dev !== sourceSnapshot.dev ||
    installed.ino !== sourceSnapshot.ino ||
    installed.size !== sourceSnapshot.size ||
    installed.mtimeNs !== sourceSnapshot.mtimeNs ||
    installed.mode !== sourceSnapshot.mode ||
    installed.digest !== sourceSnapshot.digest ||
    installed.digest !== expectedDigest
  ) {
    throw new Error(
      `Atomically installed file does not match the prepared file: ${path}`,
    );
  }
}

function removeAcceptedCandidate(path, expectedSnapshot) {
  assertFileSnapshotUnchanged(
    path,
    expectedSnapshot,
    'test baseline candidate',
    'accepted candidate cleanup',
  );
  const tombstonePath = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomUUID()}.accepted`,
  );
  renameSync(path, tombstonePath);
  fsyncDirectory(dirname(path));
  let restored = false;
  try {
    assertInstalledFileSnapshot(
      tombstonePath,
      expectedSnapshot,
      expectedSnapshot.digest,
    );
    if (captureFileSnapshot(path).exists) {
      throw new Error(
        'Test baseline candidate pathname was recreated during cleanup.',
      );
    }
    rmSync(tombstonePath);
    fsyncDirectory(dirname(path));
    if (captureFileSnapshot(path).exists ||
        captureFileSnapshot(tombstonePath).exists) {
      throw new Error('Accepted test baseline candidate cleanup was incomplete.');
    }
  } catch (error) {
    try {
      if (
        !captureFileSnapshot(path).exists &&
        captureFileSnapshot(tombstonePath).exists
      ) {
        renameSync(tombstonePath, path);
        fsyncDirectory(dirname(path));
        restored = true;
      }
    } catch (restoreError) {
      throw new AggregateError(
        [normalizeError(error), normalizeError(restoreError)],
        'Accepted test baseline candidate cleanup failed and could not be restored.',
      );
    }
    if (restored) {
      assertFileSnapshotUnchanged(
        path,
        expectedSnapshot,
        'test baseline candidate',
        'accepted candidate cleanup recovery',
      );
    }
    throw error;
  }
}

function readJsonFileOrNull(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new Error(`Unable to read JSON file ${path}: ${error.message}`);
  }
}

function inspectLoadedTestBaselineCandidate({
  baselineFilePath,
  baselineBefore,
  candidate,
  candidateBefore,
  candidateDisplayPath,
  candidateFilePath,
  captureTree,
  manifest,
  previousBaseline,
  tree,
}) {
  try {
    assertBaselineCandidateCurrent(candidate, tree, manifest);
    if (baselineCandidateFileDigest(candidate) !== candidateBefore.digest) {
      throw new Error(
        'Generated test baseline candidate file serialization is invalid; ' +
        'regenerate it.',
      );
    }

    let binding = 'previous-baseline';
    if (
      isAcceptedBaseline(previousBaseline) &&
      acceptedBaselineMatchesCandidate(
        previousBaseline,
        candidate,
        candidateBefore.digest,
      )
    ) {
      binding = 'already-accepted';
    } else {
      if (
        candidate.previousBaselineExists !== baselineBefore.exists ||
        candidate.previousBaselineDigest !== baselineBefore.digest
      ) {
        throw new Error(
          'Accepted baseline changed after candidate generation; regenerate the candidate.',
        );
      }
      const bootstrapRequired = baselineRequiresBootstrap(previousBaseline);
      if (candidate.bootstrap !== bootstrapRequired) {
        throw new Error(
          'Generated test baseline candidate bootstrap state is stale; regenerate it.',
        );
      }
    }

    assertNoBaselineRegression(candidate, previousBaseline);
    const accepted = acceptedBaselineFromCandidate(
      candidate,
      candidateBefore.digest,
      candidate.generatedAt,
    );
    if (!isAcceptedBaseline(accepted)) {
      throw new Error(
        'Generated test baseline candidate cannot produce a valid accepted baseline.',
      );
    }
    assertFileSnapshotUnchanged(
      baselineFilePath,
      baselineBefore,
      'accepted test baseline',
      'candidate inspection',
    );
    assertFileSnapshotUnchanged(
      candidateFilePath,
      candidateBefore,
      'test baseline candidate',
      'candidate inspection',
    );
    assertTreeUnchanged(tree, captureTree(), 'candidate inspection');
    return {
      current: true,
      status: binding === 'already-accepted'
        ? 'accepted-recovery'
        : 'reusable',
      reason: null,
      candidate,
    };
  } catch (error) {
    return {
      current: false,
      status: 'stale',
      reason:
        `${candidateDisplayPath} is not reusable: ${normalizeError(error).message}`,
      candidate: null,
    };
  }
}

export function isAcceptedBaseline(value) {
  try {
    if (
      !isPlainRecord(value) ||
      !hasExactKeys(value, [
        'schemaVersion',
        'kind',
        'manifestDigest',
        'testTreeDigest',
        'harnessDigest',
        'generatedAt',
        'acceptedAt',
        'runId',
        'bootstrap',
        'previousBaselineExists',
        'previousBaselineDigest',
        'candidateDigest',
        'candidateFileDigest',
        'phases',
      ]) ||
      value.schemaVersion !== 2 ||
      value.kind !== 'accepted-test-baseline' ||
      !isSha256(value.manifestDigest) ||
      !isSha256(value.testTreeDigest) ||
      !isSha256(value.harnessDigest) ||
      !isCanonicalTimestamp(value.generatedAt) ||
      !isCanonicalTimestamp(value.acceptedAt) ||
      Date.parse(value.acceptedAt) < Date.parse(value.generatedAt) ||
      !isRunId(value.runId) ||
      typeof value.bootstrap !== 'boolean' ||
      typeof value.previousBaselineExists !== 'boolean' ||
      !hasValidPreviousBaselineBinding(value) ||
      !isSha256(value.candidateDigest) ||
      !isSha256(value.candidateFileDigest) ||
      !hasValidAcceptedPhases(value.phases)
    ) {
      return false;
    }
    const candidate = candidateFromAcceptedBaseline(value);
    return candidate.contentDigest === value.candidateDigest &&
      baselineCandidateFileDigest(candidate) === value.candidateFileDigest;
  } catch {
    return false;
  }
}

function acceptedBaselineFromCandidate(
  candidate,
  candidateFileDigest,
  acceptedAt,
) {
  return {
    schemaVersion: 2,
    kind: 'accepted-test-baseline',
    manifestDigest: candidate.manifestDigest,
    testTreeDigest: candidate.testTreeDigest,
    harnessDigest: candidate.harnessDigest,
    generatedAt: candidate.generatedAt,
    acceptedAt,
    runId: candidate.runId,
    bootstrap: candidate.bootstrap,
    previousBaselineExists: candidate.previousBaselineExists,
    previousBaselineDigest: candidate.previousBaselineDigest,
    candidateDigest: candidate.contentDigest,
    candidateFileDigest,
    phases: candidate.phases,
  };
}

function candidateFromAcceptedBaseline(value) {
  return {
    schemaVersion: 2,
    kind: 'test-baseline-candidate',
    manifestDigest: value.manifestDigest,
    testTreeDigest: value.testTreeDigest,
    harnessDigest: value.harnessDigest,
    generatedAt: value.generatedAt,
    runId: value.runId,
    bootstrap: value.bootstrap,
    previousBaselineExists: value.previousBaselineExists,
    previousBaselineDigest: value.previousBaselineDigest,
    phases: value.phases,
    contentDigest: value.candidateDigest,
  };
}

function acceptedBaselineMatchesCandidate(
  accepted,
  candidate,
  candidateFileDigest,
) {
  if (!isAcceptedBaseline(accepted)) return false;
  return accepted.candidateFileDigest === candidateFileDigest &&
    canonicalJson(candidateFromAcceptedBaseline(accepted)) ===
      canonicalJson(candidate);
}

export function baselineRequiresBootstrap(previousBaseline) {
  if (isAcceptedBaseline(previousBaseline)) return false;
  if (isExplicitBootstrapBaseline(previousBaseline)) return true;
  throw new Error(
    'Test baseline is neither an accepted trust root nor the explicit ' +
    'fail-closed bootstrap state.',
  );
}

export function baselineCandidateContentDigest(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error('Generated test baseline candidate must be an object.');
  }
  const { contentDigest: _contentDigest, ...content } = candidate;
  return sha256(canonicalJson(content));
}

export function sealBaselineCandidate(candidate) {
  const content = { ...candidate };
  delete content.contentDigest;
  return {
    ...content,
    contentDigest: baselineCandidateContentDigest(content),
  };
}

export function assertBaselineCandidateSeal(candidate) {
  if (typeof candidate?.contentDigest !== 'string') {
    throw new Error('Generated test baseline candidate has no content seal.');
  }
  const observed = baselineCandidateContentDigest(candidate);
  if (candidate.contentDigest !== observed) {
    throw new Error(
      'Generated test baseline candidate content seal is invalid; regenerate it.',
    );
  }
}

function baselineCandidateFileDigest(candidate) {
  return sha256(`${JSON.stringify(candidate, null, 2)}\n`);
}

function isExplicitBootstrapBaseline(value) {
  if (
    !isPlainRecord(value) ||
    !hasExactKeys(value, [
      'schemaVersion',
      'manifestDigest',
      'testTreeDigest',
      'harnessDigest',
      'generatedAt',
      'acceptedAt',
      'runId',
      'previousBaselineDigest',
      'candidateDigest',
      'phases',
    ]) ||
    value.schemaVersion !== 2
  ) {
    return false;
  }
  for (const field of [
    'manifestDigest',
    'testTreeDigest',
    'harnessDigest',
    'generatedAt',
    'acceptedAt',
    'runId',
    'previousBaselineDigest',
    'candidateDigest',
  ]) {
    if (value[field] !== null) return false;
  }
  if (!isPlainRecord(value.phases) ||
      !hasExactKeys(value.phases, phaseOrder)) {
    return false;
  }
  return phaseOrder.every((phase) => {
    const entry = value.phases[phase];
    return isPlainRecord(entry) &&
      hasExactKeys(entry, [
        'minimumPassed',
        'minimumPassedByFile',
        'testIdentityCounts',
      ]) &&
      entry.minimumPassed === null &&
      entry.minimumPassedByFile === null &&
      entry.testIdentityCounts === null;
  });
}

function hasValidPreviousBaselineBinding(value) {
  return value.previousBaselineExists
    ? isSha256(value.previousBaselineDigest)
    : value.previousBaselineDigest === null;
}

function hasValidAcceptedPhases(phases) {
  if (!isPlainRecord(phases) || !hasExactKeys(phases, phaseOrder)) {
    return false;
  }
  return phaseOrder.every((phase) => {
    const entry = phases[phase];
    if (
      !isPlainRecord(entry) ||
      !hasExactKeys(entry, [
        'minimumPassed',
        'minimumPassedByFile',
        'testIdentityCounts',
      ]) ||
      !Number.isInteger(entry.minimumPassed) ||
      entry.minimumPassed < 0 ||
      !isCountRecord(entry.minimumPassedByFile) ||
      !isTestIdentityCountRecord(entry.testIdentityCounts)
    ) {
      return false;
    }
    const perFileTotal = Object.values(entry.minimumPassedByFile)
      .reduce((total, count) => total + count, 0);
    return perFileTotal >= entry.minimumPassed;
  });
}

function isCountRecord(value) {
  return isPlainRecord(value) &&
    Object.keys(value).length > 0 &&
    Object.entries(value).every(([key, count]) =>
      key.length > 0 &&
      Number.isInteger(count) &&
      count >= 0);
}

function isTestIdentityCountRecord(value) {
  if (!isCountRecord(value)) return false;
  return Object.entries(value).every(([identity, count]) => {
    if (count <= 0) return false;
    try {
      const parsed = JSON.parse(identity);
      return Array.isArray(parsed) &&
        parsed.length === 2 &&
        parsed.every((part) =>
          typeof part === 'string' && part.length > 0);
    } catch {
      return false;
    }
  });
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, expectedKeys) {
  const observed = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return observed.length === expected.length &&
    observed.every((key, index) => key === expected[index]);
}

function isSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function isRunId(value) {
  return typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      .test(value);
}

function assertBaselineCandidateCurrent(candidate, tree, manifest) {
  if (
    !isPlainRecord(candidate) ||
    !hasExactKeys(candidate, [
      'schemaVersion',
      'kind',
      'manifestDigest',
      'testTreeDigest',
      'harnessDigest',
      'generatedAt',
      'runId',
      'bootstrap',
      'previousBaselineExists',
      'previousBaselineDigest',
      'phases',
      'contentDigest',
    ]) ||
    candidate?.schemaVersion !== 2 ||
    candidate?.kind !== 'test-baseline-candidate' ||
    !isSha256(candidate.manifestDigest) ||
    !isSha256(candidate.testTreeDigest) ||
    !isSha256(candidate.harnessDigest) ||
    !isCanonicalTimestamp(candidate.generatedAt) ||
    !isRunId(candidate.runId) ||
    typeof candidate.bootstrap !== 'boolean' ||
    typeof candidate.previousBaselineExists !== 'boolean' ||
    !hasValidPreviousBaselineBinding(candidate) ||
    !isPlainRecord(candidate.phases) ||
    !isSha256(candidate.contentDigest)
  ) {
    throw new Error('Generated test baseline candidate is malformed.');
  }
  assertBaselineCandidateSeal(candidate);
  for (const [field, observed] of [
    ['manifestDigest', tree.manifestDigest],
    ['testTreeDigest', tree.testTreeDigest],
    ['harnessDigest', tree.harnessDigest],
  ]) {
    if (candidate[field] !== observed) {
      throw new Error(
        `Generated test baseline candidate ${field} is stale; regenerate it.`,
      );
    }
  }
  for (const phase of phaseOrder) {
    validatePhaseBaseline({
      phase,
      label: `${phase} candidate`,
      expectedFiles: manifest.phases[phase],
      baseline: {
        ...candidate,
        skipAllowlist: TEST_INTEGRITY_SKIP_ALLOWLIST,
      },
    });
  }
}

function assertNoBaselineRegression(candidate, previousBaseline) {
  if (!isAcceptedBaseline(previousBaseline)) return;
  const problems = [];
  for (const phase of phaseOrder) {
    const previous = previousBaseline.phases?.[phase];
    const next = candidate.phases?.[phase];
    if (!previous || !next) {
      problems.push(`phase ${phase} is missing`);
      continue;
    }
    if (next.minimumPassed < previous.minimumPassed) {
      problems.push(
        `${phase} pass credit decreased from ${previous.minimumPassed} ` +
        `to ${next.minimumPassed}`,
      );
    }
    compareCountRecords({
      previous: previous.minimumPassedByFile,
      next: next.minimumPassedByFile,
      label: `${phase} per-file pass minimum`,
      problems,
    });
    compareCountRecords({
      previous: previous.testIdentityCounts,
      next: next.testIdentityCounts,
      label: `${phase} runtime test identity`,
      problems,
    });
  }
  if (problems.length > 0) {
    throw new Error(
      `Generated baseline would reduce existing coverage:\n` +
      problems.map((problem) => `- ${problem}`).join('\n'),
    );
  }
}

function compareCountRecords({
  previous,
  next,
  label,
  problems,
}) {
  for (const [key, priorCount] of Object.entries(previous ?? {})) {
    const nextCount = Number(next?.[key] ?? 0);
    if (nextCount < priorCount) {
      problems.push(
        `${label} ${key} decreased from ${priorCount} to ${nextCount}`,
      );
    }
  }
}

function assertTreeUnchanged(expected, observed, context) {
  if (expected.manifestDigest !== observed.manifestDigest ||
      expected.testTreeDigest !== observed.testTreeDigest ||
      expected.harnessDigest !== observed.harnessDigest) {
    throw new Error(
      `Test tree changed during ${context}; refusing to accept the run.`,
    );
  }
}

export function assertNoOpenLiveDatabaseDescriptors(fingerprint, {
  descriptorRoot = '/dev/fd',
  platform = process.platform,
} = {}) {
  if (platform !== 'darwin') {
    throw new Error(
      'Open-descriptor inspection is implemented only for the macOS ' +
      'authoritative test boundary.',
    );
  }
  const protectedIdentities = new Set(
    fingerprint
      .filter((member) => member.exists)
      .map((member) => `${member.dev}:${member.ino}`),
  );
  for (const entry of readdirSync(descriptorRoot)) {
    if (!/^\d+$/.test(entry)) continue;
    const descriptor = Number(entry);
    if (descriptor <= 2) continue;
    try {
      const stats = fstatSync(descriptor);
      if (protectedIdentities.has(`${stats.dev}:${stats.ino}`)) {
        throw new Error(
          `Refusing to launch tests with an inherited live database ` +
          `descriptor: fd ${descriptor}.`,
        );
      }
    } catch (error) {
      if (error?.code === 'EBADF' || error?.code === 'ENOENT') continue;
      throw error;
    }
  }
}

export function assertSqliteFamilyUnchanged(path, expected, context) {
  const observed = captureSqliteFamilyFingerprint(path);
  for (let index = 0; index < observed.length; index += 1) {
    if (JSON.stringify(observed[index]) !== JSON.stringify(expected[index])) {
      throw new Error(
        `Live database family member changed during ${context}: ` +
        observed[index].path,
      );
    }
  }
}

function sqliteFamilyMetadataFromFingerprint(fingerprint) {
  return fingerprint.map((member) => ({
    path: member.path,
    exists: member.exists,
    dev: member.dev,
    ino: member.ino,
    size: member.size,
    mtimeMs: member.mtimeMs,
    ctimeMs: member.ctimeMs,
  }));
}

function captureSqliteFamilyMetadata(path) {
  return sqliteFamilyPaths(path).map((memberPath) => {
    try {
      const stats = statSync(memberPath);
      return {
        path: memberPath,
        exists: true,
        dev: stats.dev,
        ino: stats.ino,
        size: stats.size,
        mtimeMs: stats.mtimeMs,
        ctimeMs: stats.ctimeMs,
      };
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      return {
        path: memberPath,
        exists: false,
        dev: null,
        ino: null,
        size: null,
        mtimeMs: null,
        ctimeMs: null,
      };
    }
  });
}

function assertSqliteFamilyMetadataUnchanged(path, expected, context) {
  const observed = captureSqliteFamilyMetadata(path);
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    throw new Error(
      `Live database family metadata changed during ${context}: ${path}`,
    );
  }
}

function assertManifestPath(file, phase) {
  if (typeof file !== 'string' ||
      file === '' ||
      isAbsolute(file) ||
      normalizePath(file) !== file ||
      file.split('/').includes('..')) {
    throw new Error(`Invalid test manifest path in ${phase}: ${String(file)}`);
  }
  if (phase === 'scripts') {
    if (!file.startsWith('scripts/') ||
        !/\.(?:test|spec)\.(?:[cm]?[jt]s|tsx)$/.test(file)) {
      throw new Error(`Invalid script test in manifest: ${file}`);
    }
  } else if (!file.startsWith('src/lib/') || !file.endsWith('.test.ts')) {
    throw new Error(`Invalid library test in manifest phase ${phase}: ${file}`);
  }
  const absolute = join(root, file);
  if (!existsSync(absolute) || !lstatSync(absolute).isFile()) {
    throw new Error(`Manifest test file does not exist as a regular file: ${file}`);
  }
}

function walkFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

function walkInputEntries(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walkInputEntries(path));
    else if (entry.isFile() || entry.isSymbolicLink()) files.push(path);
  }
  return files;
}

function isWithin(parent, candidate) {
  const parentPath = realpathOrResolve(parent);
  const candidatePath = realpathOrResolve(candidate);
  return candidatePath === parentPath ||
    candidatePath.startsWith(`${parentPath}${sep}`);
}

function realpathOrResolve(path) {
  const absolutePath = resolve(path);
  const missingSegments = [];
  let existingAncestor = absolutePath;
  try {
    return realpathSync.native(absolutePath);
  } catch (error) {
    if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') {
      return absolutePath;
    }
  }
  while (true) {
    const parent = dirname(existingAncestor);
    if (parent === existingAncestor) return absolutePath;
    missingSegments.push(basename(existingAncestor));
    existingAncestor = parent;
    try {
      return resolve(
        realpathSync.native(existingAncestor),
        ...missingSegments.reverse(),
      );
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') {
        return absolutePath;
      }
    }
  }
}

function samePath(left, right) {
  return realpathOrResolve(left) === realpathOrResolve(right);
}

function canonicalPath(path) {
  try {
    return realpathSync.native(resolve(path));
  } catch {
    return resolve(path);
  }
}

function normalizePath(path) {
  return String(path).split('\\').join('/');
}

function canonicalJson(value) {
  if (value === null || typeof value === 'string' ||
      typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Canonical JSON cannot encode a non-finite number.');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort((left, right) => left < right ? -1 : left > right ? 1 : 0)
      .map((key) => {
        if (value[key] === undefined) {
          throw new Error(`Canonical JSON cannot encode undefined at ${key}.`);
        }
        return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
      })
      .join(',')}}`;
  }
  throw new Error(`Canonical JSON cannot encode ${typeof value}.`);
}

function createFailureChannel() {
  let reported = null;
  let resolveFailure;
  const promise = new Promise((resolvePromise) => {
    resolveFailure = resolvePromise;
  });
  return {
    promise,
    report(error) {
      if (reported) return reported;
      reported = normalizeError(error);
      resolveFailure(reported);
      return reported;
    },
  };
}

export async function runCleanupStep(errors, label, operation) {
  try {
    await operation();
  } catch (error) {
    const normalized = normalizeError(error);
    errors.push(new Error(`${label}: ${normalized.message}`, {
      cause: normalized,
    }));
  }
}

export function combineErrors(primary, additional, message) {
  const errors = [
    ...(primary ? [normalizeError(primary)] : []),
    ...(additional ?? []).map((error) => normalizeError(error)),
  ];
  if (errors.length === 0) return null;
  if (errors.length === 1) return errors[0];
  return new AggregateError(errors, message);
}

function normalizeError(error) {
  return error instanceof Error ? error : new Error(String(error));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fsyncDirectory(directory) {
  let descriptor = null;
  try {
    descriptor = openSync(directory, 'r');
    fsyncSync(descriptor);
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}
