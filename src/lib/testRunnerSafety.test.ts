import { strict as assert } from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter, once } from 'node:events';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve, sep } from 'node:path';
import { before, describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import {
  acquireExclusiveProcessLock,
  assertExclusiveProcessLockContended,
  databaseFileInitializationLockPath,
  databaseInitializationLockPath,
  pathsReferToSameFile,
  repositoryDatabaseWriterLockPath,
} from './exclusiveProcessLock.ts';

const mebibyte = 1024 * 1024;

type ResolveConfiguredLiveDatabase = (options: {
  root: string;
  environment?: Record<string, string | undefined>;
  envFilePath?: string;
  envFileText?: string;
}) => string | null;
type VerifyPhaseIntegrity = (options: {
  phase: string;
  label?: string;
  root: string;
  expectedFiles: string[];
  events: unknown[];
  baseline: {
    phases: Record<string, {
      minimumPassed: number;
      minimumPassedByFile: Record<string, number> | null;
      testIdentityCounts: Record<string, number> | null;
    }>;
    skipAllowlist: Array<{
      file: string;
      name: string;
      reportedReason: true | string;
      reason: string;
      platforms: string[];
    }>;
  };
  platform?: string;
}) => unknown;
type GeneratePhaseBaseline = (options: {
  phase: string;
  label?: string;
  root: string;
  expectedFiles: string[];
  events: unknown[];
  baseline: {
    phases: Record<string, {
      minimumPassed: number | null;
      minimumPassedByFile: Record<string, number> | null;
      testIdentityCounts: Record<string, number> | null;
    }>;
    skipAllowlist: Array<{
      file: string;
      name: string;
      reportedReason: true | string;
      reason: string;
      platforms: string[];
    }>;
  };
  platform?: string;
}) => {
  minimumPassed: number;
  minimumPassedByFile: Record<string, number>;
  testIdentityCounts: Record<string, number>;
};
type AssertAuthoritativeArguments = (args: string[]) => void;
type AssertExactManifest = (
  manifest: { phases: Record<string, string[]> },
  discoveredFiles: string[],
) => void;
type AssertGeneratedBaseline = (
  manifest: { phases: Record<string, string[]> },
  tree: {
    manifestDigest: string;
    testTreeDigest: string;
    harnessDigest: string;
  },
  baseline: Record<string, unknown>,
  validationBaseline?: Record<string, unknown>,
) => void;
type AssertSupportedNodeVersion = (version?: string) => void;
type ResolvePhaseTimeout = (options?: {
  environment?: Record<string, string | undefined>;
}) => number;
type ResolveTestTimeout = (options?: {
  environment?: Record<string, string | undefined>;
}) => number;
type ResolveTestResourceLimits = (options?: {
  environment?: Record<string, string | undefined>;
}) => {
  maximumWorkerBytes: number;
  maximumSuiteBytes: number;
  maximumSqliteBytes: number;
  maximumProcessWriteBytes: number;
  maximumSystemDiskTransferBytes: number;
  minimumStartingFreeBytes: number;
  minimumRuntimeFreeBytes: number;
};
type CaptureExecutionInputIdentity = (options?: {
  excludedPath?: string;
  repositoryRoot?: string;
}) => {
  files: string[];
  digest: string;
};
type DiscoverExecutionInputFiles = (options?: {
  excludedPath?: string;
  repositoryRoot?: string;
}) => string[];
type SanitizeTestChildEnvironment = (options?: {
  environment?: Record<string, string | undefined>;
  liveDatabase?: string;
}) => Record<string, string>;
type ResolveTestWriteBoundaryBackend = (options?: {
  platform?: string;
  executablePath?: string;
}) => {
  backend: string;
  executable: Record<string, unknown>;
};
type BuildDarwinSandboxProfile = (options?: {
  unreadablePaths?: string[];
  writableRoots?: string[];
}) => string;
type LiveDatabaseInspectionResult = {
  schemaVersion: 1;
  kind: 'live-database-inspection';
  liveDatabase: string;
  fingerprint: SqliteFamilyFingerprint;
};
type InspectConfiguredLiveDatabaseUnderWriteBoundary = (options?: {
  repositoryRoot?: string;
  environment?: Record<string, string | undefined>;
  platform?: string;
  executablePath?: string;
  childPath?: string;
  run?: (
    command: string,
    args: string[],
    options: {
      cwd: string;
      encoding: string;
      env: Record<string, string>;
      maxBuffer: number;
      stdio: string[];
      timeout: number;
    },
  ) => {
    error?: Error | null;
    signal?: NodeJS.Signals | null;
    status?: number | null;
    stdout?: string | Buffer | null;
    stderr?: string | Buffer | null;
  };
}) => LiveDatabaseInspectionResult & {
  boundary: string;
};
type ParseLiveDatabaseInspectionResult = (
  output: string | Buffer,
) => LiveDatabaseInspectionResult;
type TestProcessLockLayout = {
  auditRoot: string;
  delegatedProcessLockRoot: string;
  delegatedWriterLockPath: string;
  globalProcessLockRoot: string;
  globalWriterLockPath: string;
  sandboxWritableRoots: readonly string[];
  workerDatabaseRoots: readonly string[];
};
type ResolveTestProcessLockLayout = (options: {
  repositoryRoot?: string;
  tempRoot: string;
  globalWriterLockPath?: string;
}) => TestProcessLockLayout;
type BuildDelegatedWriterAuthority = (options: {
  owner: {
    pid: number;
    token: string;
  };
  processLockRoot: string;
  repositoryRoot?: string;
  tempRoot: string;
  writerLeasePath: string;
}) => {
  environment: Readonly<Record<string, string>>;
  lease: Readonly<{
    token: string;
    pid: number;
    repositoryRoot: string;
  }>;
};
type PrivateFixtureIdentity = {
  path: string;
  dev: string;
  ino: string;
  mode: number;
  nlink: number;
  size: string;
  mtimeNs: string;
  ctimeNs: string;
  digest: string;
};
type PrivateInstallerFixtureIdentity = {
  installerPath: string;
  root: PrivateFixtureIdentity & {
    entries: readonly string[];
  };
  files: ReadonlyArray<PrivateFixtureIdentity & {
    role: string;
  }>;
};
type MaterializePrivateInstallerHeredocs = (options: {
  sourcePath: string;
  fixtureRoot: string;
  expectedHeredocCount: number;
  forbidShellHereStrings?: boolean;
}) => {
  fixtureRoot: string;
  installerPath: string;
  manifestPath: string;
  sourcePath: string;
  sourceSha256: string;
  transformedSha256: string;
  fixtureIdentity: PrivateInstallerFixtureIdentity;
  heredocs: Array<{
    index: number;
    delimiter: string;
    openerLine: number;
    bodyStartLine: number | null;
    bodyEndLine: number | null;
    delimiterLine: number;
    bodyPath: string;
    bytes: number;
    sha256: string;
  }>;
};
type AssertPrivateInstallerFixtureUnchanged = (
  fixtureIdentity: PrivateInstallerFixtureIdentity,
  context?: string,
) => void;
type PhaseChildEnvironment = (options: {
  phase: 'parallel' | 'e2e' | 'installer' | 'lifecycle' | 'scripts';
  environment: Record<string, string>;
  guardNodeOptions: string;
  installerFixturePath: string;
}) => Record<string, string>;
type TestCommand = (options: {
  phase: 'parallel' | 'e2e' | 'installer' | 'lifecycle' | 'scripts';
  files: string[];
  eventLogPath: string;
  testTimeoutMs?: number;
}) => string[];
type SummarizeFailedTestEvents = (
  events: unknown[],
  limit?: number,
) => Array<{
  file: string;
  line: number | null;
  name: string;
  message: string;
}>;
type AcquireTestSuiteLock = (options?: {
  lockPath?: string;
  pid?: number;
  startedAt?: string;
  registerExitHandler?: boolean;
}) => {
  path: string;
  owner: {
    pid: number;
    token: string;
    label: string;
    startedAt: string;
  };
  release: () => void;
};
type SqliteFamilyFingerprint = Array<{
  path: string;
  exists: boolean;
  dev: number | null;
  ino: number | null;
  size: number | null;
  mtimeMs: number | null;
  ctimeMs: number | null;
  digest: string | null;
}>;
type CaptureSqliteFamilyFingerprint = (
  path: string,
) => SqliteFamilyFingerprint;
type AssertSqliteFamilyUnchanged = (
  path: string,
  expected: SqliteFamilyFingerprint,
  context: string,
) => void;
type AssertDatabaseAudit = (options: {
  auditPath: string;
  expectedFiles: string[];
  tempRoot: string;
  liveDatabase: string;
  runId: string;
  requireCompleteCoverage?: boolean;
}) => void;
type WaitForChild = (
  child: EventEmitter & {
    exitCode: number | null;
    signalCode: NodeJS.Signals | null;
    pid?: number;
    kill: (signal?: NodeJS.Signals) => boolean;
  },
  options?: { label?: string; timeoutMs?: number | null },
) => Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
type StartResourceWatchdog = (options: {
  runId: string;
  tempRoot: string;
  tempRootOwnerPath?: string;
  additionalOwnerPaths?: string[];
  auditPath: string;
  auditRoot: string;
  systemDiskTransferBaselineBytes?: number | null;
  limits: {
    maximumWorkerBytes: number;
    maximumSuiteBytes: number;
    maximumSqliteBytes: number;
    maximumProcessWriteBytes: number;
    maximumSystemDiskTransferBytes: number;
    minimumStartingFreeBytes: number;
    minimumRuntimeFreeBytes: number;
  };
  repositoryIdentity?: string;
  repositoryRoot?: string;
  childEnvironment?: Record<string, string | undefined>;
  liveDatabase?: string;
}) => Promise<{
  ready: true;
  receiptPath: string;
  failure: Promise<Error>;
  setActiveProcessGroup: (
    pid: number | null,
    options?: { allowedCommandDigests?: string[] },
  ) => void;
  complete: (options: {
    preserveTempRoot: boolean;
  }) => Promise<Record<string, unknown>>;
  abandon: () => void;
}>;
type StartFootprintMonitor = (options: {
  tempRoot: string;
  auditPath: string;
  runId: string;
  limits: {
    maximumWorkerBytes: number;
    maximumSuiteBytes: number;
    minimumRuntimeFreeBytes: number;
  };
}) => {
  failure: Promise<Error>;
  stop: () => void;
};
type AssertWatchdogTerminalAudit = (options: {
  auditPath: string;
  receipt?: Record<string, unknown> | null;
  receiptPath: string;
  runId: string;
}) => Record<string, unknown>;
type RunCleanupStep = (
  errors: Error[],
  label: string,
  operation: () => unknown | Promise<unknown>,
) => Promise<void>;
type CaptureProcessIdentity = (
  pid: number,
  options?: {
    platform?: string;
    run?: (
      command: string,
      args: string[],
      options: Record<string, unknown>,
    ) => {
      error?: Error | null;
      signal?: string | null;
      status?: number | null;
      stdout?: string | Buffer | null;
    };
  },
) => Record<string, unknown> | null;
type CapturePathIdentity = (
  path: string,
) => Record<string, unknown>;
type SealWatchdogState = (
  payload: Record<string, unknown>,
  token: string,
) => Record<string, unknown>;
type VerifyWatchdogReceiptSeal = (receipt: unknown) => boolean;
type SealWatchdogReceipt = (
  payload: Record<string, unknown>,
) => Record<string, unknown>;
type ProcessIdentityMatches = (
  expected: Record<string, unknown>,
  actual: Record<string, unknown>,
  options?: {
    requireProcessGroupLeader?: boolean;
    allowedCommandDigests?: string[] | null;
  },
) => boolean;
type ProcessIdentityMatchesAfterDarwinReparent = (
  expected: Record<string, unknown>,
  actual: Record<string, unknown>,
  options: {
    parentIdentity: Record<string, unknown>;
    parentAlive: boolean;
    requireProcessGroupLeader?: boolean;
    allowedCommandDigests?: string[] | null;
  },
) => boolean;

const helperUrl = pathToFileURL(
  join(process.cwd(), 'test', 'live-database-path.mjs'),
).href;
const integrityHelperUrl = pathToFileURL(
  join(process.cwd(), 'test', 'test-integrity.mjs'),
).href;
const watchdogContractUrl = pathToFileURL(
  join(process.cwd(), 'test', 'watchdog-contract.mjs'),
).href;
let resolveConfiguredLiveDatabase: ResolveConfiguredLiveDatabase;
let verifyPhaseIntegrity: VerifyPhaseIntegrity;
let generatePhaseBaseline: GeneratePhaseBaseline;
let assertAuthoritativeArguments: AssertAuthoritativeArguments;
let assertExactManifest: AssertExactManifest;
let assertGeneratedBaseline: AssertGeneratedBaseline;
let assertSupportedNodeVersion: AssertSupportedNodeVersion;
let resolvePhaseTimeout: ResolvePhaseTimeout;
let resolveTestTimeout: ResolveTestTimeout;
let resolveTestResourceLimits: ResolveTestResourceLimits;
let captureExecutionInputIdentity: CaptureExecutionInputIdentity;
let discoverExecutionInputFiles: DiscoverExecutionInputFiles;
let sanitizeTestChildEnvironment: SanitizeTestChildEnvironment;
let resolveTestWriteBoundaryBackend: ResolveTestWriteBoundaryBackend;
let buildDarwinSandboxProfile: BuildDarwinSandboxProfile;
let inspectConfiguredLiveDatabaseUnderWriteBoundary:
  InspectConfiguredLiveDatabaseUnderWriteBoundary;
let parseLiveDatabaseInspectionResult:
  ParseLiveDatabaseInspectionResult;
let resolveTestProcessLockLayout: ResolveTestProcessLockLayout;
let buildDelegatedWriterAuthority: BuildDelegatedWriterAuthority;
let materializePrivateInstallerHeredocs:
  MaterializePrivateInstallerHeredocs;
let assertPrivateInstallerFixtureUnchanged:
  AssertPrivateInstallerFixtureUnchanged;
let phaseChildEnvironment: PhaseChildEnvironment;
let testCommand: TestCommand;
let summarizeFailedTestEvents: SummarizeFailedTestEvents;
let acquireTestSuiteLock: AcquireTestSuiteLock;
let captureSqliteFamilyFingerprint: CaptureSqliteFamilyFingerprint;
let assertSqliteFamilyUnchanged: AssertSqliteFamilyUnchanged;
let assertDatabaseAudit: AssertDatabaseAudit;
let waitForChild: WaitForChild;
let startResourceWatchdog: StartResourceWatchdog;
let startFootprintMonitor: StartFootprintMonitor;
let assertWatchdogTerminalAudit: AssertWatchdogTerminalAudit;
let runCleanupStep: RunCleanupStep;
let combineErrors: (
  primary: unknown,
  additional: unknown[],
  message: string,
) => Error | AggregateError | null;
let canonicalRepositoryIdentity: (repositoryRoot?: string) => string;
let testRootPrefixForRepository: (repositoryRoot?: string) => string;
let scavengeOrphanedTestRoots: (options?: {
  repositoryRoot?: string;
  tempDirectory?: string;
  now?: number;
  staleHeartbeatMs?: number;
}) => string[];
let sealBaselineCandidate: <T extends Record<string, unknown>>(
  candidate: T,
) => T & { contentDigest: string };
let assertBaselineCandidateSeal: (candidate: unknown) => void;
let baselineRequiresBootstrap: (baseline: unknown) => boolean;
let acceptTestBaselineCandidateFiles: (options: {
  allowBootstrap?: boolean;
  baselineFilePath: string;
  candidateFilePath: string;
  candidateDisplayPath?: string;
  manifest: { phases: Record<string, string[]> };
  tree: {
    manifestDigest: string;
    testTreeDigest: string;
    harnessDigest: string;
  };
  captureTree?: (excludedPath?: string) => {
    manifestDigest: string;
    testTreeDigest: string;
    harnessDigest: string;
  };
  acceptedAt?: string;
}) => unknown;
let isAcceptedBaseline: (baseline: unknown) => boolean;
let parseDarwinIostatDiskTransferBytes: (output: string) => number;
let systemDiskTransferDeltaBytes: (
  baselineBytes: number,
  currentBytes: number,
) => number;
let latestWatchdogResourceBreach: (
  auditPath: string,
  runId: string,
) => Record<string, unknown> | null;
let captureProcessIdentity: CaptureProcessIdentity;
let capturePathIdentity: CapturePathIdentity;
let sealWatchdogState: SealWatchdogState;
let verifyWatchdogReceiptSeal: VerifyWatchdogReceiptSeal;
let sealWatchdogReceipt: SealWatchdogReceipt;
let processIdentityMatches: ProcessIdentityMatches;
let processIdentityMatchesAfterDarwinReparent:
  ProcessIdentityMatchesAfterDarwinReparent;
let safetyHarnessFiles: readonly string[];
let productionInstallerQuotedHeredocCount: number;

before(async () => {
  const runnerHelperUrl = pathToFileURL(
    join(process.cwd(), 'test', 'test-suite-runner.mjs'),
  ).href;
  const [
    databaseHelper,
    integrityHelper,
    runnerHelper,
    watchdogContract,
  ] = await Promise.all([
    import(helperUrl) as Promise<{
      resolveConfiguredLiveDatabase: ResolveConfiguredLiveDatabase;
    }>,
    import(integrityHelperUrl) as Promise<{
      verifyPhaseIntegrity: VerifyPhaseIntegrity;
      generatePhaseBaseline: GeneratePhaseBaseline;
    }>,
    import(runnerHelperUrl) as Promise<{
      assertAuthoritativeArguments: AssertAuthoritativeArguments;
      assertExactManifest: AssertExactManifest;
      assertGeneratedBaseline: AssertGeneratedBaseline;
      assertSupportedNodeVersion: AssertSupportedNodeVersion;
      resolvePhaseTimeout: ResolvePhaseTimeout;
      resolveTestTimeout: ResolveTestTimeout;
      resolveTestResourceLimits: ResolveTestResourceLimits;
      captureExecutionInputIdentity: CaptureExecutionInputIdentity;
      discoverExecutionInputFiles: DiscoverExecutionInputFiles;
      sanitizeTestChildEnvironment: SanitizeTestChildEnvironment;
      resolveTestWriteBoundaryBackend: ResolveTestWriteBoundaryBackend;
      buildDarwinSandboxProfile: BuildDarwinSandboxProfile;
      inspectConfiguredLiveDatabaseUnderWriteBoundary:
        InspectConfiguredLiveDatabaseUnderWriteBoundary;
      parseLiveDatabaseInspectionResult:
        ParseLiveDatabaseInspectionResult;
      resolveTestProcessLockLayout: ResolveTestProcessLockLayout;
      buildDelegatedWriterAuthority: BuildDelegatedWriterAuthority;
      materializePrivateInstallerHeredocs:
        MaterializePrivateInstallerHeredocs;
      assertPrivateInstallerFixtureUnchanged:
        AssertPrivateInstallerFixtureUnchanged;
      phaseChildEnvironment: PhaseChildEnvironment;
      testCommand: TestCommand;
      summarizeFailedTestEvents: SummarizeFailedTestEvents;
      acquireTestSuiteLock: AcquireTestSuiteLock;
      captureSqliteFamilyFingerprint: CaptureSqliteFamilyFingerprint;
      assertSqliteFamilyUnchanged: AssertSqliteFamilyUnchanged;
      assertDatabaseAudit: AssertDatabaseAudit;
      waitForChild: WaitForChild;
      startResourceWatchdog: StartResourceWatchdog;
      startFootprintMonitor: StartFootprintMonitor;
      assertWatchdogTerminalAudit: AssertWatchdogTerminalAudit;
      runCleanupStep: RunCleanupStep;
      combineErrors: typeof combineErrors;
      canonicalRepositoryIdentity: typeof canonicalRepositoryIdentity;
      testRootPrefixForRepository: typeof testRootPrefixForRepository;
      scavengeOrphanedTestRoots: typeof scavengeOrphanedTestRoots;
      sealBaselineCandidate: typeof sealBaselineCandidate;
      assertBaselineCandidateSeal: typeof assertBaselineCandidateSeal;
      baselineRequiresBootstrap: typeof baselineRequiresBootstrap;
      acceptTestBaselineCandidateFiles:
        typeof acceptTestBaselineCandidateFiles;
      isAcceptedBaseline: typeof isAcceptedBaseline;
      parseDarwinIostatDiskTransferBytes:
        typeof parseDarwinIostatDiskTransferBytes;
      systemDiskTransferDeltaBytes: typeof systemDiskTransferDeltaBytes;
      latestWatchdogResourceBreach: typeof latestWatchdogResourceBreach;
      SAFETY_HARNESS_FILES: readonly string[];
      PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT: number;
    }>,
    import(watchdogContractUrl) as Promise<{
      captureProcessIdentity: CaptureProcessIdentity;
      capturePathIdentity: CapturePathIdentity;
      sealWatchdogState: SealWatchdogState;
      verifyWatchdogReceiptSeal: VerifyWatchdogReceiptSeal;
      sealWatchdogReceipt: SealWatchdogReceipt;
      processIdentityMatches: ProcessIdentityMatches;
      processIdentityMatchesAfterDarwinReparent:
        ProcessIdentityMatchesAfterDarwinReparent;
    }>,
  ]);
  resolveConfiguredLiveDatabase = databaseHelper.resolveConfiguredLiveDatabase;
  verifyPhaseIntegrity = integrityHelper.verifyPhaseIntegrity;
  generatePhaseBaseline = integrityHelper.generatePhaseBaseline;
  assertAuthoritativeArguments = runnerHelper.assertAuthoritativeArguments;
  assertExactManifest = runnerHelper.assertExactManifest;
  assertGeneratedBaseline = runnerHelper.assertGeneratedBaseline;
  assertSupportedNodeVersion = runnerHelper.assertSupportedNodeVersion;
  resolvePhaseTimeout = runnerHelper.resolvePhaseTimeout;
  resolveTestTimeout = runnerHelper.resolveTestTimeout;
  resolveTestResourceLimits = runnerHelper.resolveTestResourceLimits;
  captureExecutionInputIdentity =
    runnerHelper.captureExecutionInputIdentity;
  discoverExecutionInputFiles = runnerHelper.discoverExecutionInputFiles;
  sanitizeTestChildEnvironment = runnerHelper.sanitizeTestChildEnvironment;
  resolveTestWriteBoundaryBackend =
    runnerHelper.resolveTestWriteBoundaryBackend;
  buildDarwinSandboxProfile = runnerHelper.buildDarwinSandboxProfile;
  inspectConfiguredLiveDatabaseUnderWriteBoundary =
    runnerHelper.inspectConfiguredLiveDatabaseUnderWriteBoundary;
  parseLiveDatabaseInspectionResult =
    runnerHelper.parseLiveDatabaseInspectionResult;
  resolveTestProcessLockLayout =
    runnerHelper.resolveTestProcessLockLayout;
  buildDelegatedWriterAuthority =
    runnerHelper.buildDelegatedWriterAuthority;
  materializePrivateInstallerHeredocs =
    runnerHelper.materializePrivateInstallerHeredocs;
  assertPrivateInstallerFixtureUnchanged =
    runnerHelper.assertPrivateInstallerFixtureUnchanged;
  phaseChildEnvironment = runnerHelper.phaseChildEnvironment;
  testCommand = runnerHelper.testCommand;
  summarizeFailedTestEvents = runnerHelper.summarizeFailedTestEvents;
  acquireTestSuiteLock = runnerHelper.acquireTestSuiteLock;
  captureSqliteFamilyFingerprint =
    runnerHelper.captureSqliteFamilyFingerprint;
  assertSqliteFamilyUnchanged = runnerHelper.assertSqliteFamilyUnchanged;
  assertDatabaseAudit = runnerHelper.assertDatabaseAudit;
  waitForChild = runnerHelper.waitForChild;
  startResourceWatchdog = runnerHelper.startResourceWatchdog;
  startFootprintMonitor = runnerHelper.startFootprintMonitor;
  assertWatchdogTerminalAudit = runnerHelper.assertWatchdogTerminalAudit;
  runCleanupStep = runnerHelper.runCleanupStep;
  combineErrors = runnerHelper.combineErrors;
  canonicalRepositoryIdentity = runnerHelper.canonicalRepositoryIdentity;
  testRootPrefixForRepository = runnerHelper.testRootPrefixForRepository;
  scavengeOrphanedTestRoots = runnerHelper.scavengeOrphanedTestRoots;
  sealBaselineCandidate = runnerHelper.sealBaselineCandidate;
  assertBaselineCandidateSeal = runnerHelper.assertBaselineCandidateSeal;
  baselineRequiresBootstrap = runnerHelper.baselineRequiresBootstrap;
  acceptTestBaselineCandidateFiles =
    runnerHelper.acceptTestBaselineCandidateFiles;
  isAcceptedBaseline = runnerHelper.isAcceptedBaseline;
  parseDarwinIostatDiskTransferBytes =
    runnerHelper.parseDarwinIostatDiskTransferBytes;
  systemDiskTransferDeltaBytes =
    runnerHelper.systemDiskTransferDeltaBytes;
  latestWatchdogResourceBreach =
    runnerHelper.latestWatchdogResourceBreach;
  productionInstallerQuotedHeredocCount =
    runnerHelper.PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT;
  captureProcessIdentity = watchdogContract.captureProcessIdentity;
  capturePathIdentity = watchdogContract.capturePathIdentity;
  sealWatchdogState = watchdogContract.sealWatchdogState;
  verifyWatchdogReceiptSeal =
    watchdogContract.verifyWatchdogReceiptSeal;
  sealWatchdogReceipt = watchdogContract.sealWatchdogReceipt;
  processIdentityMatches = watchdogContract.processIdentityMatches;
  processIdentityMatchesAfterDarwinReparent =
    watchdogContract.processIdentityMatchesAfterDarwinReparent;
  safetyHarnessFiles = runnerHelper.SAFETY_HARNESS_FILES;
});

describe('test runner live database resolution', () => {
  const root = resolve('/tmp/openclaw-release-radar-test-root');

  it('uses an explicit process DB_PATH before the .env value', () => {
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: { DB_PATH: './runtime/live.db' },
        envFileText: 'DB_PATH=./file/live.db\n',
      }),
      join(root, 'runtime', 'live.db'),
    );
  });

  it('uses the .env DB_PATH when the process environment does not set one', () => {
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: {},
        envFileText: 'DB_PATH="./configured/radar.db"\n',
      }),
      join(root, 'configured', 'radar.db'),
    );
  });

  it('protects the database selected by a custom DOTENV_CONFIG_PATH', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-custom-dotenv-test-'));
    const customEnvDirectory = join(directory, 'config');
    const defaultDatabase = join(directory, 'default.db');
    const liveDatabase = join(directory, 'configured-live.db');
    try {
      mkdirSync(customEnvDirectory);
      writeFileSync(join(directory, '.env'), 'DB_PATH=./default.db\n');
      writeFileSync(
        join(customEnvDirectory, 'runtime.env'),
        'DB_PATH="./configured-live.db"\n',
      );
      writeFileSync(defaultDatabase, 'decoy');
      writeFileSync(liveDatabase, 'live');

      const configuredDatabase = resolveConfiguredLiveDatabase({
        root: directory,
        environment: {
          DOTENV_CONFIG_PATH: './config/runtime.env',
        },
      });

      assert.equal(configuredDatabase, liveDatabase);
      assert.ok(configuredDatabase);
      const fingerprint = captureSqliteFamilyFingerprint(configuredDatabase);
      assert.equal(fingerprint[0].path, liveDatabase);
      assert.equal(fingerprint[0].exists, true);
      assert.deepEqual(
        {
          ...sanitizeTestChildEnvironment({
            environment: {
              DOTENV_CONFIG_PATH: './config/runtime.env',
              LIVE_DATABASE_REFERENCE: liveDatabase,
              SAFE_DATABASE_REFERENCE: defaultDatabase,
            },
            liveDatabase: configuredDatabase,
          }),
        },
        {
          SAFE_DATABASE_REFERENCE: defaultDatabase,
        },
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('preserves an absolute configured database path', () => {
    const absolutePath = resolve('/tmp/openclaw-live/radar.db');
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: { DB_PATH: absolutePath },
        envFileText: '',
      }),
      absolutePath,
    );
  });

  it('normalizes absolute and relative SQLite file URIs', () => {
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: { DB_PATH: 'file:///tmp/openclaw%20live/radar.db?mode=rw' },
        envFileText: '',
      }),
      resolve('/tmp/openclaw live/radar.db'),
    );
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: { DB_PATH: 'file:configured/radar.db?mode=rw' },
        envFileText: '',
      }),
      join(root, 'configured', 'radar.db'),
    );
  });

  it('distinguishes real SQLite memory URIs from disk paths with memory-like names', () => {
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: { DB_PATH: 'file::memory:?cache=shared' },
        envFileText: '',
      }),
      null,
    );
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: { DB_PATH: 'file:shared-memory?mode=memory&cache=shared' },
        envFileText: '',
      }),
      null,
    );
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: { DB_PATH: 'file::memory:alias' },
        envFileText: '',
      }),
      join(root, ':memory:alias'),
    );
  });

  it('falls back to the repository data database', () => {
    assert.equal(
      resolveConfiguredLiveDatabase({
        root,
        environment: {},
        envFileText: '',
      }),
      join(root, 'data', 'radar.db'),
    );
  });
});

describe('test runner live database inspection boundary', () => {
  it('fails unsupported platforms before reading configuration or child paths', () => {
    let environmentReads = 0;
    const environment = new Proxy<Record<string, string | undefined>>(
      {},
      {
        get() {
          environmentReads += 1;
          throw new Error('configuration must not be read');
        },
      },
    );

    assert.throws(
      () => inspectConfiguredLiveDatabaseUnderWriteBoundary({
        repositoryRoot: process.cwd(),
        environment,
        platform: 'linux',
        childPath: join(process.cwd(), 'does-not-exist.mjs'),
      }),
      /Only the macOS sandbox-exec backend is implemented/,
    );
    assert.equal(environmentReads, 0);
  });

  it('accepts only bounded, exact, ordered inspection output', () => {
    const databasePath = resolve('/tmp/radar-inspection/radar.db');
    const fingerprint = [
      databasePath,
      `${databasePath}-wal`,
      `${databasePath}-shm`,
      `${databasePath}-journal`,
    ].map((path) => ({
      path,
      exists: false,
      dev: null,
      ino: null,
      size: null,
      mtimeMs: null,
      ctimeMs: null,
      digest: null,
    }));
    const valid = {
      schemaVersion: 1,
      kind: 'live-database-inspection',
      liveDatabase: databasePath,
      fingerprint,
    };

    assert.deepEqual(
      parseLiveDatabaseInspectionResult(JSON.stringify(valid)),
      valid,
    );
    assert.throws(
      () => parseLiveDatabaseInspectionResult('not-json'),
      /not valid JSON/,
    );
    assert.throws(
      () => parseLiveDatabaseInspectionResult('x'.repeat(64 * 1024 + 1)),
      /missing or oversized/,
    );
    assert.throws(
      () => parseLiveDatabaseInspectionResult(JSON.stringify({
        ...valid,
        fingerprint: [
          fingerprint[1],
          fingerprint[0],
          ...fingerprint.slice(2),
        ],
      })),
      /fingerprint member 0 is invalid/,
    );
    assert.throws(
      () => parseLiveDatabaseInspectionResult(JSON.stringify({
        ...valid,
        fingerprint: [
          {
            ...fingerprint[0],
            exists: true,
            dev: Number.MAX_SAFE_INTEGER + 1,
            ino: 1,
            size: 1,
            mtimeMs: 1,
            ctimeMs: 1,
            digest: 'a'.repeat(64),
          },
          ...fingerprint.slice(1),
        ],
      })),
      /invalid file metadata/,
    );
  });

  it('constructs a deny-write Seatbelt child with an allowlisted environment', () => {
    const databasePath = resolve('/tmp/radar-inspection-contract/radar.db');
    const fingerprint = [
      databasePath,
      `${databasePath}-wal`,
      `${databasePath}-shm`,
      `${databasePath}-journal`,
    ].map((path) => ({
      path,
      exists: false,
      dev: null,
      ino: null,
      size: null,
      mtimeMs: null,
      ctimeMs: null,
      digest: null,
    }));
    let invocation: {
      command: string;
      args: string[];
      options: {
        cwd: string;
        encoding: string;
        env: Record<string, string>;
        maxBuffer: number;
        stdio: string[];
        timeout: number;
      };
    } | null = null;
    const result = inspectConfiguredLiveDatabaseUnderWriteBoundary({
      repositoryRoot: process.cwd(),
      environment: {
        DB_PATH: databasePath,
        HOME: '/Users/test',
        PATH: '/must-not-reach-child',
        RADAR_TEST_UNTRUSTED: 'must-not-reach-child',
      },
      run(command, args, options) {
        invocation = { command, args, options };
        return {
          status: 0,
          signal: null,
          stdout: JSON.stringify({
            schemaVersion: 1,
            kind: 'live-database-inspection',
            liveDatabase: databasePath,
            fingerprint,
          }),
          stderr: '',
        };
      },
    });

    assert.ok(invocation);
    assert.equal(invocation.command, '/usr/bin/sandbox-exec');
    assert.equal(invocation.args[0], '-p');
    assert.match(invocation.args[1], /\(deny file-write\*\)/);
    assert.equal(invocation.args[2], process.execPath);
    assert.equal(invocation.options.cwd, realpathSync.native(process.cwd()));
    assert.deepEqual(
      { ...invocation.options.env },
      {
        DB_PATH: databasePath,
        HOME: '/Users/test',
        RADAR_TEST_LIVE_DB_INSPECTION_BOUNDARY: 'darwin-seatbelt-v1',
      },
    );
    assert.equal(result.boundary, 'darwin-seatbelt-v1');
    assert.deepEqual(result.fingerprint, fingerprint);

    const child = readFileSync(
      join(process.cwd(), 'test', 'live-database-inspection-child.mjs'),
      'utf8',
    );
    assert.ok(
      child.indexOf('assertWriteDenied(writeProbePath);') <
        child.indexOf('resolveConfiguredLiveDatabase({'),
      'the child must prove kernel write denial before reading configuration',
    );
  });

  it('rejects a symlinked inspection child before spawning it', () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'radar-inspection-child-symlink-'),
    );
    const target = join(directory, 'child.mjs');
    const alias = join(directory, 'child-alias.mjs');
    try {
      writeFileSync(target, 'process.exit(0);\n');
      symlinkSync(target, alias);
      assert.throws(
        () => inspectConfiguredLiveDatabaseUnderWriteBoundary({
          repositoryRoot: process.cwd(),
          childPath: alias,
          run() {
            throw new Error('symlinked inspection child reached spawn');
          },
        }),
        /not a direct regular file/,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('fails closed instead of substituting a disk path for a memory database', () => {
    const child = readFileSync(
      join(process.cwd(), 'test', 'live-database-inspection-child.mjs'),
      'utf8',
    );
    assert.match(
      child,
      /Configured live database must be file-backed for test isolation/,
    );
    assert.doesNotMatch(
      child,
      /resolveConfiguredLiveDatabase\([\s\S]*\)\s*\?\?/,
    );
  });

  it('acquires suite and writer locks before inspecting the configured database', () => {
    const runner = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    const wrapperStart = runner.indexOf(
      'export async function runTestSuite(options = {}) {',
    );
    const wrapperEnd = runner.indexOf(
      'export function acceptTestBaselineCandidate',
      wrapperStart,
    );
    const wrapper = runner.slice(wrapperStart, wrapperEnd);
    assert.ok(wrapperStart >= 0);
    assert.ok(wrapper.indexOf('acquireTestSuiteLock()') >= 0);
    assert.ok(
      wrapper.indexOf('acquireRepositoryDatabaseWriterLock({') >
        wrapper.indexOf('acquireTestSuiteLock()'),
    );
    assert.ok(
      wrapper.indexOf('runTestSuiteUnlocked({') >
        wrapper.indexOf('acquireRepositoryDatabaseWriterLock({'),
    );

    const unlockedStart = runner.indexOf(
      'async function runTestSuiteUnlocked({',
    );
    const unlockedEnd = runner.indexOf(
      'export function resolvePhaseTimeout',
      unlockedStart,
    );
    const unlocked = runner.slice(unlockedStart, unlockedEnd);
    assert.ok(
      unlocked.indexOf('inspectConfiguredLiveDatabaseUnderWriteBoundary({') >= 0,
    );

    const focused = readFileSync(
      join(process.cwd(), 'test', 'run-focused-test.mjs'),
      'utf8',
    );
    const focusedSuiteLock = focused.indexOf(
      'const suiteLock = runner.acquireTestSuiteLock();',
    );
    const focusedWriterLock = focused.indexOf(
      'writerLock = acquireRepositoryDatabaseWriterLock({',
    );
    const focusedInspection = focused.indexOf(
      'runner.inspectConfiguredLiveDatabaseUnderWriteBoundary({',
    );
    assert.ok(focusedSuiteLock >= 0);
    assert.ok(focusedWriterLock > focusedSuiteLock);
    assert.ok(focusedInspection > focusedWriterLock);
  });

  it('keeps baseline candidate inspection inside the locked suite runner', () => {
    const wrapper = readFileSync(
      join(process.cwd(), 'test', 'generate-test-baseline.mjs'),
      'utf8',
    );
    assert.match(wrapper, /await runTestSuite\(\{/);
    assert.doesNotMatch(wrapper, /inspectTestBaselineCandidate/);
    assert.doesNotMatch(wrapper, /test-baseline\.candidate\.json/);
    assert.doesNotMatch(wrapper, /readJsonFileSnapshot/);
  });
});

describe('test runner integrity enforcement', () => {
  const root = resolve('/tmp/openclaw-release-radar-integrity-root');
  const file = 'src/lib/example.test.ts';

  it('rejects a phase pass-count regression', () => {
    assert.throws(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events: phaseEvents(root, file, testCounts({ tests: 2, passed: 2 })),
        baseline: integrityBaseline(3),
        platform: 'linux',
      }),
      /parallel tests pass minimum regressed: 2 passed .* required at least 3/,
    );
  });

  it('rejects a single-file regression masked by aggregate test growth', () => {
    const growthFile = 'src/lib/growth.test.ts';
    assert.throws(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file, growthFile],
        events: phaseEventsForFiles(root, [
          {
            file,
            counts: testCounts({ tests: 4, passed: 4 }),
          },
          {
            file: growthFile,
            counts: testCounts({ tests: 3, passed: 3 }),
          },
        ]),
        baseline: integrityBaseline(6, [], {
          [file]: 5,
          [growthFile]: 1,
        }),
        platform: 'linux',
      }),
      /src\/lib\/example\.test\.ts per-file pass minimum regressed: 4 passed .* required at least 5/,
    );
  });

  it('rejects missing and extra per-file baseline identities', () => {
    const extraFile = 'src/lib/extra.test.ts';
    assert.throws(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events: phaseEvents(root, file, testCounts({ tests: 2, passed: 2 })),
        baseline: integrityBaseline(2, [], {
          [extraFile]: 2,
        }),
        platform: 'linux',
      }),
      /per-file baseline is missing manifest file\(s\): src\/lib\/example\.test\.ts[\s\S]*per-file baseline has extra file\(s\): src\/lib\/extra\.test\.ts/,
    );
  });

  it('rejects an unknown skip with its stable identity', () => {
    const skipName = 'requires an optional command';
    assert.throws(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events: phaseEvents(
          root,
          file,
          testCounts({ tests: 2, passed: 1, skipped: 1 }),
          {
            statusEvents: [statusEvent(root, file, skipName, {
              skip: 'optional command unavailable',
            })],
          },
        ),
        baseline: integrityBaseline(1),
        platform: 'linux',
      }),
      new RegExp(`Unallowlisted skip in ${escapeRegExp(file)}.*${skipName}.*linux`),
    );
  });

  it('accepts an exactly allowlisted skip and credits the pass minimum', () => {
    const skipName = 'requires an optional command';
    assert.doesNotThrow(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events: phaseEvents(
          root,
          file,
          testCounts({ tests: 2, passed: 1, skipped: 1 }),
          {
            statusEvents: [statusEvent(root, file, skipName, {
              skip: 'optional command unavailable',
            })],
          },
        ),
        baseline: integrityBaseline(2, [{
          file,
          name: skipName,
          reportedReason: 'optional command unavailable',
          reason: 'requires an optional command',
          platforms: ['linux'],
        }], {
          [file]: 2,
        }),
        platform: 'linux',
      }),
    );
  });

  it('rejects cancelled and todo tests', () => {
    const events = phaseEvents(
      root,
      file,
      testCounts({ tests: 3, passed: 1, cancelled: 1, todo: 1 }),
      {
        statusEvents: [
          statusEvent(root, file, 'cancelled case', {
            error: { failureType: 'cancelledByParent' },
          }, 'test:fail'),
          statusEvent(root, file, 'unfinished case', {
            todo: 'not implemented',
          }),
        ],
      },
    );
    assert.throws(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events,
        baseline: integrityBaseline(1),
        platform: 'linux',
      }),
      /Todo tests are forbidden[\s\S]*Cancelled tests are forbidden/,
    );
  });

  it('rejects a manifest file without a top-level completion event', () => {
    assert.throws(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events: phaseEvents(
          root,
          file,
          testCounts({ tests: 2, passed: 2 }),
          { includeCompletion: false },
        ),
        baseline: integrityBaseline(2),
        platform: 'linux',
      }),
      /Manifest file src\/lib\/example\.test\.ts did not finish exactly once/,
    );
  });

  it('accepts increased pass counts without exact-count brittleness', () => {
    assert.doesNotThrow(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events: phaseEvents(root, file, testCounts({ tests: 5, passed: 5 })),
        baseline: integrityBaseline(2),
        platform: 'linux',
      }),
    );
  });

  it('rejects failed tests even when pass minima would otherwise be met', () => {
    assert.throws(
      () => verifyPhaseIntegrity({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file],
        events: phaseEvents(
          root,
          file,
          testCounts({ tests: 2, passed: 1, failed: 1 }),
        ),
        baseline: integrityBaseline(1),
        platform: 'linux',
      }),
      /Failed tests are forbidden: 1 reported/,
    );
  });

  it('derives per-file minima only from a fully auditable successful phase', () => {
    const growthFile = 'src/lib/growth.test.ts';
    assert.deepEqual(
      generatePhaseBaseline({
        phase: 'parallel',
        label: 'parallel tests',
        root,
        expectedFiles: [file, growthFile],
        events: phaseEventsForFiles(root, [
          { file, counts: testCounts({ tests: 2, passed: 2 }) },
          { file: growthFile, counts: testCounts({ tests: 3, passed: 3 }) },
        ]),
        baseline: integrityBaseline(0, [], null),
        platform: 'linux',
      }),
      {
        minimumPassed: 5,
        minimumPassedByFile: {
          [file]: 2,
          [growthFile]: 3,
        },
        testIdentityCounts: {
          [JSON.stringify([file, 'synthetic pass 1'])]: 1,
          [JSON.stringify([file, 'synthetic pass 2'])]: 1,
          [JSON.stringify([growthFile, 'synthetic pass 1'])]: 1,
          [JSON.stringify([growthFile, 'synthetic pass 2'])]: 1,
          [JSON.stringify([growthFile, 'synthetic pass 3'])]: 1,
        },
      },
    );
  });
});

describe('test runner resource bounds', () => {
  const gibibyte = 1024 * mebibyte;

  it('rejects unsupported Node versions at the plain-JavaScript preflight', () => {
    for (const version of ['22.16.0', '22.16.1', '23.0.0']) {
      assert.doesNotThrow(() => assertSupportedNodeVersion(version));
    }
    for (const version of ['22.15.9', '21.99.99']) {
      assert.throws(
        () => assertSupportedNodeVersion(version),
        new RegExp(`Node\\.js >=22\\.16\\.0.*observed ${escapeRegExp(version)}`),
      );
    }
    assert.throws(
      () => assertSupportedNodeVersion('not-a-version'),
      /Unable to parse Node\.js version/,
    );
  });

  it('runs Node preflight before loading TypeScript in every validation entrypoint', () => {
    const sanitizedEntrypoints = new Set([
      'run-tests.mjs',
      'generate-test-baseline.mjs',
      'accept-test-baseline.mjs',
      'run-database-guard.mjs',
      'run-focused-test.mjs',
    ]);
    for (const entrypoint of [
      'run-tests.mjs',
      'generate-test-baseline.mjs',
      'accept-test-baseline.mjs',
      'run-database-guard.mjs',
      'run-focused-test.mjs',
      'run-installer-preflight.mjs',
    ]) {
      const source = readFileSync(
        join(process.cwd(), 'test', entrypoint),
        'utf8',
      );
      const preflightIndex = source.indexOf('assertSupportedNodeVersion();');
      const typescriptLoadIndex = source.indexOf(
        "await import('tsx/esm/api')",
      );
      assert.notEqual(preflightIndex, -1, `${entrypoint} must run preflight`);
      assert.notEqual(
        typescriptLoadIndex,
        -1,
        `${entrypoint} must dynamically load tsx`,
      );
      assert.ok(
        preflightIndex < typescriptLoadIndex,
        `${entrypoint} must preflight Node before loading tsx`,
      );
      if (sanitizedEntrypoints.has(entrypoint)) {
        const environmentGuardIndex = source.indexOf(
          'assertSanitizedTestEntrypointEnvironment();',
        );
        assert.notEqual(
          environmentGuardIndex,
          -1,
          `${entrypoint} must assert its sanitized launch environment`,
        );
        assert.ok(
          environmentGuardIndex < preflightIndex,
          `${entrypoint} must assert its environment before Node preflight`,
        );
        assert.match(source, /'NODE_OPTIONS'/);
        assert.match(source, /'NODE_PATH'/);
        assert.match(source, /'npm_lifecycle_event'/);
        assert.match(source, /--no-global-search-paths/);
      }
    }

    const sanitizedNodePrefix =
      '/usr/bin/env -u NODE_OPTIONS -u NODE_PATH -u npm_lifecycle_event ' +
      'node --no-global-search-paths';
    const packageScripts = (
      JSON.parse(
        readFileSync(join(process.cwd(), 'package.json'), 'utf8'),
      ) as { scripts: Record<string, string> }
    ).scripts;
    const expectedTestScripts: Record<string, string> = {
      'test:safety': `${sanitizedNodePrefix} test/run-database-guard.mjs`,
      'test:preflight':
        `${sanitizedNodePrefix} --no-warnings test/run-installer-preflight.mjs`,
      'test:focus':
        `${sanitizedNodePrefix} --no-warnings test/run-focused-test.mjs`,
      test: `${sanitizedNodePrefix} test/run-tests.mjs`,
      'test:baseline':
        `${sanitizedNodePrefix} test/generate-test-baseline.mjs`,
      'test:baseline:accept':
        `${sanitizedNodePrefix} test/accept-test-baseline.mjs`,
    };
    for (const [name, expected] of Object.entries(expectedTestScripts)) {
      assert.equal(packageScripts[name], expected);
    }
    const sanitizedNpmPrefix =
      '/usr/bin/env -u NODE_OPTIONS -u NODE_PATH -u npm_lifecycle_event npm';
    assert.equal(
      packageScripts['verify:authoritative-ci'],
      `${sanitizedNpmPrefix} run test:safety && ` +
        `${sanitizedNpmPrefix} run test:baseline -- --full --rerun`,
    );
  });

  it('requires explicit full-suite intent at both complete-suite entrypoints', () => {
    for (const entrypoint of [
      'run-tests.mjs',
      'generate-test-baseline.mjs',
    ]) {
      const source = readFileSync(
        join(process.cwd(), 'test', entrypoint),
        'utf8',
      );
      const fullOption = source.indexOf("'--full'");
      const missingFullGuard = source.search(
        /if\s*\(\s*!full\s*\)\s*\{/,
      );
      const suiteRun = source.indexOf('await runTestSuite({');
      assert.ok(fullOption >= 0, `${entrypoint} must recognize --full`);
      assert.ok(
        missingFullGuard >= 0,
        `${entrypoint} must reject runs without --full`,
      );
      assert.ok(
        suiteRun > missingFullGuard,
        `${entrypoint} must enforce --full before starting the suite`,
      );
      assert.match(
        source.slice(missingFullGuard, suiteRun),
        /--full[\s\S]*(?:process\.exitCode\s*=\s*1|throw new Error\()/,
      );
      assert.match(source, /forwardedArgs:\s*\[\]/);
    }
  });

  it('keeps focused validation one-file and one-worker with opt-in authority', () => {
    const source = readFileSync(
      join(process.cwd(), 'test', 'run-focused-test.mjs'),
      'utf8',
    );
    assert.match(source, /if \(argument === '--authoritative'\)/);
    assert.match(
      source,
      /Usage: npm run test:focus -- \[--authoritative\]/,
    );
    assert.match(
      source,
      /Focused validation accepts exactly one test file/,
    );
    assert.match(source, /test-manifest\.json/);
    assert.match(source, /runner\.acquireTestSuiteLock\(\)/);
    assert.match(source, /acquireRepositoryDatabaseWriterLock\(\{/);
    assert.match(source, /runner\.resolveTestProcessLockLayout\(\{/);
    assert.match(source, /acquireExclusiveProcessLock\(\{/);
    assert.match(source, /owner: delegatedWriterLock\.owner/);
    assert.match(source, /runner\.buildDelegatedWriterAuthority\(\{/);
    assert.match(source, /DB_PATH: databasePath/);
    assert.match(source, /DOTENV_CONFIG_PATH: emptyDotenvPath/);
    assert.match(
      source,
      /writeFileSync\(emptyDotenvPath, '', \{ flag: 'wx', mode: 0o600 \}\)/,
    );
    assert.match(source, /NODE_OPTIONS: guardNodeOptions/);
    assert.match(source, /RADAR_TEST_DB_AUDIT: auditPath/);
    assert.doesNotMatch(source, /RADAR_TEST_LIVE_DB\s*:/);
    assert.match(source, /const writeBoundary = runner\.createTestWriteBoundary\(\{/);
    assert.match(
      source,
      /RADAR_TEST_DATABASE_GUARD_POLICY: writeBoundary\.policyPath/,
    );
    assert.match(
      source,
      /const launch = writeBoundary\.wrapCommand\(process\.execPath, command\)/,
    );
    assert.match(
      source,
      /const resourceLimits = runner\.resolveTestResourceLimits\(\)/,
    );
    assert.match(source, /'--test-concurrency=1'/);
    assert.match(source, /forbidShellHereStrings: true/);
    assert.match(source, /runner\.assertSqliteFamilyUnchanged\(/);
    const workerCleanup = source.indexOf(
      'runner.cleanupExitedWorkerDirectories({',
    );
    const auditVerification = source.indexOf('runner.assertDatabaseAudit({');
    assert.ok(workerCleanup >= 0);
    assert.ok(auditVerification > workerCleanup);
    assert.match(
      source,
      /catch \(error\) \{\s+if \(authoritative && !preserveDiagnostics\)/,
    );
    assert.ok(
      source.indexOf('delegatedWriterLock?.release()') <
        source.indexOf('rmSync(tempRoot, { recursive: true, force: true })'),
    );
    assert.doesNotMatch(source, /test-baseline\.candidate\.json/);
  });

  it('preflights direct E2E helpers with installed guard hooks and private artifacts', () => {
    const guard = readFileSync(
      join(process.cwd(), 'test', 'database-guard-runtime.cjs'),
      'utf8',
    );
    const databaseSource = readFileSync(
      join(process.cwd(), 'src', 'lib', 'db.ts'),
      'utf8',
    );
    const importGuardSource = readFileSync(
      join(process.cwd(), 'src', 'lib', 'e2eDatabaseImportGuard.ts'),
      'utf8',
    );
    assert.match(
      guard,
      /Object\.getOwnPropertyDescriptor\(globalThis, installKey\) !== undefined/,
    );
    assert.match(
      guard,
      /Object\.defineProperty\(globalThis, installKey,[\s\S]*configurable: false,[\s\S]*writable: false/,
    );
    assert.match(guard, /module\.exports = databaseGuardInstallation/);
    assert.match(
      guard,
      /Database guard runtime hooks are not fully installed/,
    );
    assert.match(guard, /captureInstalledHookSet\(fs, nativeFsFunctions\)/);
    assert.match(
      guard,
      /installedHookSetMatches\(\s*childProcess,\s*installedHooks\.childProcess/,
    );
    assert.match(
      guard,
      /DOTENV_CONFIG_PATH must be RADAR_TEST_TEMP_ROOT\/empty\.env/,
    );
    assert.match(guard, /DB_PATH must name radar\.db/);
    assert.match(guard, /fresh database artifact already exists/);
    assert.match(guard, /must contain an initialized SQLite database/);
    assert.match(guard, /stats\.nlink !== 1/);
    assert.match(
      guard,
      /const databaseFileIdentity = attestedDatabaseFileIdentity\(\)/,
    );
    assert.match(guard, /databaseIdentity: databaseFileIdentity/);
    assert.match(
      guard,
      /if \(inheritedIdentity\.inode === null\) return null/,
    );
    assert.match(
      guard,
      /Database guard DB_PATH device\/inode changed before repository import/,
    );
    assert.match(
      importGuardSource,
      /fresh DB_PATH must not carry a device\/inode attestation/,
    );
    assert.match(
      importGuardSource,
      /existing DB_PATH requires an exact device\/inode attestation/,
    );
    assert.match(
      importGuardSource,
      /assertDatabaseIdentity\(databasePath, expectedIdentity, helperName\);\s*assertPrivateRegularFile\(databasePath, 'DB_PATH'\);\s*assertSqliteDatabaseHeader\(databasePath, 'DB_PATH'\);\s*assertDatabaseIdentity\(databasePath, expectedIdentity, helperName\)/,
    );
    assert.match(guard, /composedPublication\.e2e\.helper\.ts/);
    assert.match(
      guard,
      /releaseValidationProofEvaluationCli\.helper\.ts/,
    );
    assert.match(guard, /scorerVerifierContract\.e2e\.helper\.ts/);
    assert.match(
      guard,
      /directHelperName !== null && guardPolicy\.legacy === true/,
    );
    assert.match(
      guard,
      /requires the authoritative kernel write boundary/,
    );
    assert.match(
      databaseSource,
      /Symbol\.for\('openclaw-release-radar\.database-guard'\)/,
    );
    assert.match(
      databaseSource,
      /if \(databasePolicyProbeContext \|\| testContext\) \{\s*assertAuthoritativeTestDatabaseGuard\(\);\s*\}/,
    );
    assert.match(
      databaseSource,
      /Test database access requires the authoritative kernel write boundary/,
    );
    assert.ok(
      guard.indexOf("type: 'guard-ready'") >
        guard.indexOf('sqlite.DatabaseSync = GuardedDatabaseSync'),
    );

    for (const helperName of [
      'composedPublication.e2e.helper.ts',
      'scorerVerifierContract.e2e.helper.ts',
    ]) {
      const source = readFileSync(
        join(process.cwd(), 'src', 'lib', helperName),
        'utf8',
      );
      const guardLoad = source.indexOf(
        "require(\n  '../../test/database-guard-runtime.cjs'",
      );
      const guardAssertion = source.indexOf('databaseGuard.assertActive({');
      const scenarioAssertion = source.indexOf(
        helperName.startsWith('composedPublication')
          ? 'composedScenarioBootstrapMode(scenario)'
          : 'assertScorerVerifierScenario(scenario)',
      );
      const importReadinessAssertion = source.indexOf(
        'databaseImportGuard.assertReady();',
      );
      const repositoryLoads = [
        source.indexOf("require('../config')"),
        source.indexOf("require('./advisoryCatalogDigest')"),
        source.indexOf("await import('./db')"),
      ].filter((index) => index >= 0);
      const databaseImports = [
        source.indexOf("await import('./db')"),
      ].filter((index) => index >= 0);
      assert.ok(guardLoad >= 0, `${helperName} must load the guard runtime`);
      assert.ok(
        guardAssertion > guardLoad,
        `${helperName} must verify the loaded guard capability`,
      );
      assert.ok(
        scenarioAssertion > guardAssertion,
        `${helperName} must validate its scenario after the guard`,
      );
      assert.ok(
        repositoryLoads.every((index) => index > scenarioAssertion),
        `${helperName} must validate the guard and scenario before repository imports`,
      );
      assert.ok(
        importReadinessAssertion > scenarioAssertion,
        `${helperName} must recheck its database attestation before import`,
      );
      assert.ok(
        databaseImports.every((index) => index > importReadinessAssertion),
        `${helperName} must recheck its database identity immediately before database imports`,
      );
      assert.match(source, /requirePrivateArtifacts: true/);
      assert.match(
        source,
        /databaseIdentity:\s*\{\s*dev: string;\s*ino: string;\s*\} \| null;/,
      );
      assert.match(
        source,
        /'authoritative-test-database-guard-policy'/,
      );
      assert.match(source, /RADAR_DB_BOOTSTRAP_MODE/);
      assert.doesNotMatch(
        source,
        /Symbol\.for\('openclaw-release-radar\.database-guard'\)[\s\S]*installed/,
      );
    }

    const evaluationHelper = readFileSync(
      join(
        process.cwd(),
        'src',
        'lib',
        'releaseValidationProofEvaluationCli.helper.ts',
      ),
      'utf8',
    );
    const evaluationGuardLoad = evaluationHelper.indexOf(
      "require(\n  '../../test/database-guard-runtime.cjs'",
    );
    const evaluationGuardAssertion = evaluationHelper.indexOf(
      'databaseGuard.assertActive({',
    );
    const evaluationDatabaseImport = evaluationHelper.indexOf(
      "await import('./db')",
    );
    const evaluationLifecycleImport = evaluationHelper.indexOf(
      "await import('./releaseValidationProofLifecycle')",
    );
    assert.ok(evaluationGuardLoad >= 0);
    assert.ok(evaluationGuardAssertion > evaluationGuardLoad);
    assert.ok(evaluationLifecycleImport > evaluationGuardAssertion);
    assert.ok(evaluationDatabaseImport > evaluationGuardAssertion);
    assert.equal(
      evaluationHelper.indexOf(
        "from './releaseValidationProofLifecycle'",
      ),
      -1,
    );
    assert.match(evaluationHelper, /requirePrivateArtifacts: true/);
    assert.match(
      evaluationHelper,
      /databaseIdentity:\s*\{\s*dev: string;\s*ino: string;\s*\} \| null;/,
    );
    assert.match(
      evaluationHelper,
      /'authoritative-test-database-guard-policy'/,
    );

    for (const testName of [
      'composedPublication.e2e.test.ts',
      'scorerVerifierContract.e2e.test.ts',
    ]) {
      const source = readFileSync(
        join(process.cwd(), 'src', 'lib', testName),
        'utf8',
      );
      assert.match(source, /const privateArtifactRoot = realpathSync\.native/);
      assert.match(source, /DOTENV_CONFIG_PATH: requiredEnv\(/);
      assert.doesNotMatch(source, /mkdtempSync\(join\(tmpdir\(\)/);
    }
    const composedTest = readFileSync(
      join(process.cwd(), 'src', 'lib', 'composedPublication.e2e.test.ts'),
      'utf8',
    );
    assert.match(composedTest, /bootstrapModeForScenario\(scenario\)/);
    assert.doesNotMatch(composedTest, /RADAR_TEST_LIVE_DB/);
  });

  it('rejects a direct scorer/verifier helper launch before creating its forged database', () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'radar-direct-scorer-helper-'),
    );
    const databasePath = join(directory, 'radar.db');
    const initialFingerprint =
      captureSqliteFamilyFingerprint(databasePath);
    const helperPath = join(
      process.cwd(),
      'src',
      'lib',
      'scorerVerifierContract.e2e.helper.ts',
    );
    const helperArguments = [
      '--no-warnings',
      '--import=tsx',
      helperPath,
      'score',
      'refresh:forged-direct-launch',
      '0'.repeat(64),
    ];
    const childEnvironment = {
      ...process.env,
      DB_PATH: databasePath,
      RADAR_DB_BOOTSTRAP_MODE: 'fresh',
    };
    delete childEnvironment.NODE_TEST_CONTEXT;

    try {
      const result = spawnSync(process.execPath, helperArguments, {
        cwd: process.cwd(),
        env: childEnvironment,
        encoding: 'utf8',
        timeout: 30_000,
      });
      const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
      assert.equal(result.error, undefined, output);
      assert.equal(result.signal, null, output);
      assert.notEqual(result.status, 0, output);
      assert.match(
        output,
        /scorer\/verifier helper requires an existing private database/,
      );
      assert.doesNotMatch(output, /CONTRACT_E2E_RESULT=/);
    } finally {
      try {
        assertSqliteFamilyUnchanged(
          databasePath,
          initialFingerprint,
          'guarded direct scorer/verifier helper rejection',
        );
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    }
  });

  it('rejects a direct scorer/verifier helper launch against an existing database without the authoritative guard', () => {
    const directory = mkdtempSync(
      join(tmpdir(), 'radar-direct-existing-scorer-helper-'),
    );
    const databasePath = join(directory, 'radar.db');
    const legacyLiveDatabase = join(directory, 'configured-live-decoy.db');
    const fixture = new DatabaseSync(databasePath);
    try {
      fixture.exec('CREATE TABLE incident_probe (id INTEGER PRIMARY KEY)');
    } finally {
      fixture.close();
    }
    const initialFingerprint =
      captureSqliteFamilyFingerprint(databasePath);
    const helperPath = join(
      process.cwd(),
      'src',
      'lib',
      'scorerVerifierContract.e2e.helper.ts',
    );
    const publicationRunId = 'forged-direct-existing-launch';
    const helperArguments = [
      '--no-warnings',
      '--import=tsx',
      helperPath,
      'score',
      publicationRunId,
      `refresh:${publicationRunId}`,
      '0'.repeat(64),
    ];
    const execEnvironmentDeletes = [
      'NODE_TEST_CONTEXT',
      'RADAR_TEST_DATABASE_GUARD_POLICY',
      'RADAR_TEST_DATABASE_GUARD_POLICY_DIGEST',
      'RADAR_TEST_SANDBOX_BACKEND',
      'RADAR_TEST_SANDBOX_PROFILE_DIGEST',
    ];
    const launcherSource = `
      const environment = {
        ...process.env,
        NODE_OPTIONS: '--no-warnings',
        RADAR_TEST_LIVE_DB: ${JSON.stringify(legacyLiveDatabase)},
      };
      for (const name of ${JSON.stringify(execEnvironmentDeletes)}) {
        delete environment[name];
      }
      process.execve(
        process.execPath,
        ${JSON.stringify([process.execPath, ...helperArguments])},
        environment,
      );
      throw new Error('process.execve unexpectedly returned');
    `;
    const childEnvironment = {
      ...process.env,
      DB_PATH: databasePath,
      RADAR_DB_BOOTSTRAP_MODE: 'existing',
    };
    delete childEnvironment.NODE_TEST_CONTEXT;

    try {
      // execve drops the JavaScript preload but keeps the suite's Seatbelt profile.
      const result = spawnSync(
        process.execPath,
        ['--no-warnings', '-e', launcherSource],
        {
          cwd: process.cwd(),
          env: childEnvironment,
          encoding: 'utf8',
          timeout: 30_000,
        },
      );
      const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
      assert.equal(result.error, undefined, output);
      assert.equal(result.signal, null, output);
      assert.notEqual(result.status, 0, output);
      assert.match(
        output,
        /scorerVerifierContract\.e2e\.helper\.ts requires the authoritative kernel write boundary/,
      );
      assert.doesNotMatch(output, /CONTRACT_E2E_RESULT=/);
    } finally {
      try {
        assertSqliteFamilyUnchanged(
          databasePath,
          initialFingerprint,
          'unguarded direct scorer/verifier helper rejection',
        );
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    }
  });

  it('preserves diagnostics before throwing on a nonzero phase exit', () => {
    const runner = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    const failureStart = runner.indexOf(
      'if (exit.code !== 0 || exit.signal !== null) {',
    );
    const failureEnd = runner.indexOf(
      'const events = readTestEventLog(eventLogPath);',
      failureStart,
    );
    const failureSource = runner.slice(failureStart, failureEnd);
    const preserve = failureSource.indexOf('preserveTempRoot = true;');
    const diagnostics = failureSource.indexOf(
      'printPhaseFailureDiagnostics({',
    );
    const failureThrow = failureSource.indexOf('throw new Error(');
    assert.ok(failureStart >= 0);
    assert.ok(failureEnd > failureStart);
    assert.ok(preserve >= 0);
    assert.ok(diagnostics >= 0);
    assert.ok(failureThrow > preserve);
    assert.ok(failureThrow > diagnostics);
  });

  it('runs installer preflight without the dynamic state-machine suite', () => {
    const source = readFileSync(
      join(process.cwd(), 'test', 'run-installer-preflight.mjs'),
      'utf8',
    );
    assert.match(source, /materializePrivateInstallerHeredocs\(\{/);
    assert.match(source, /forbidShellHereStrings: true/);
    assert.match(source, /\['-n', materialized\.installerPath\]/);
    assert.match(
      source,
      /\[materialized\.installerPath, 'protocol', '5'\]/,
    );
    assert.doesNotMatch(source, /installRelease\.test\.ts/);
  });

  it('hardcodes one test worker for every phase', () => {
    for (const phase of [
      'parallel',
      'e2e',
      'installer',
      'lifecycle',
      'scripts',
    ] as const) {
      const file = `${phase}.test.ts`;
      const command = testCommand({
        phase,
        files: [file],
        eventLogPath: `/tmp/${phase}-events.jsonl`,
      });
      assert.deepEqual(
        command.filter((argument) =>
          argument.startsWith('--test-concurrency')),
        ['--test-concurrency=1'],
        `${phase} must be serialized`,
      );
      assert.deepEqual(
        command.filter((argument) =>
          argument.startsWith('--test-timeout=')),
        [
          `--test-timeout=${
            phase === 'e2e'
              ? 300000
              : phase === 'installer'
                ? 1500000
                : 120000
          }`,
        ],
        `${phase} must have a bounded per-test timeout`,
      );
      assert.equal(command.at(-1), file);
      assert.equal(
        command.includes('--import=tsx'),
        phase === 'installer',
        `${phase} must use the intended TypeScript loader placement`,
      );
      assert.equal(
        command.some((argument) => argument === '--test-reporter=spec'),
        false,
        `${phase} must not stream the verbose spec reporter`,
      );
      assert.equal(
        command.some((argument) =>
          argument === '--test-reporter-destination=stdout'),
        false,
        `${phase} must keep reporter output out of the session ledger`,
      );
    }
  });

  it('bounds structured failure diagnostics without losing leaf-test identity', () => {
    const huge = 'x'.repeat(10_000);
    const events = Array.from({ length: 30 }, (_, index) => ({
      type: 'test:fail',
      data: {
        name: `failure ${index}`,
        file: join(process.cwd(), 'src', 'lib', 'example.test.ts'),
        line: index + 1,
        details: {
          type: 'test',
          error: {
            cause: {
              message: huge,
              failureType: 'testCodeFailure',
            },
          },
        },
      },
    }));
    const failures = summarizeFailedTestEvents(events);
    assert.equal(failures.length, 20);
    assert.equal(failures[0].file, 'src/lib/example.test.ts');
    assert.equal(failures[0].line, 1);
    assert.equal(failures[0].name, 'failure 0');
    assert.ok(failures[0].message.length <= 1_000);
    assert.match(failures[0].message, /\.\.\.\[truncated\]$/);
  });

  it('preserves the protected test environment for API payload workers', () => {
    const source = readFileSync(
      join(process.cwd(), 'src', 'lib', 'apiRoutes.test.ts'),
      'utf8',
    );
    assert.doesNotMatch(source, /process\.env\.NODE_OPTIONS\s*=/);
  });

  it('removes live SQLite identities and protected controls from child environments', () => {
    const liveDatabase = resolve(
      '/tmp/openclaw-release-radar-live-environment/radar.db',
    );
    const environment = {
      DB_PATH: liveDatabase,
      DOTENV_CONFIG_PATH: '/tmp/live.env',
      NODE_OPTIONS: '--require=unsafe.cjs',
      RADAR_CODE_REVISION: 'unsafe',
      RADAR_DB_BOOTSTRAP_MODE: 'unsafe',
      RADAR_DB_READ_ONLY: '1',
      RADAR_TEST_ESCAPE: 'unsafe',
      SAFE_VALUE: 'preserved',
      LIVE_FAMILY_PATH: `${liveDatabase}-wal`,
      LIVE_FAMILY_URL: `prefix:${
        pathToFileURL(`${liveDatabase}-shm`).href
      }:suffix`,
      OMITTED: undefined,
    };
    const sanitized = sanitizeTestChildEnvironment({
      environment,
      liveDatabase,
    });

    assert.equal(Object.getPrototypeOf(sanitized), null);
    assert.deepEqual({ ...sanitized }, { SAFE_VALUE: 'preserved' });
  });

  it('fails closed without a supported kernel write boundary', () => {
    for (const platform of ['linux', 'win32']) {
      assert.throws(
        () => resolveTestWriteBoundaryBackend({
          platform,
          executablePath: '/missing/sandbox-exec',
        }),
        /requires a kernel-enforced deny-write boundary/,
      );
    }
  });

  it('canonicalizes and deduplicates macOS sandbox writable roots', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-sandbox-profile-'));
    const writableRoot = join(directory, 'writable');
    const aliasRoot = join(directory, 'alias');
    const unreadablePath = join(directory, 'protected-radar.db');
    try {
      mkdirSync(writableRoot);
      symlinkSync(writableRoot, aliasRoot, 'dir');
      const profile = buildDarwinSandboxProfile({
        unreadablePaths: [unreadablePath, unreadablePath],
        writableRoots: [writableRoot, aliasRoot, writableRoot],
      });
      const canonicalRoot = realpathSync.native(writableRoot);
      const canonicalUnreadablePath = resolve(unreadablePath);
      assert.equal(
        profile.split(JSON.stringify(canonicalRoot)).length - 1,
        2,
      );
      assert.match(profile, /\(deny file-write\*\)/);
      assert.match(profile, /\(deny file-read-data/);
      assert.equal(
        profile.split(JSON.stringify(canonicalUnreadablePath)).length - 1,
        1,
      );
      assert.match(profile, /\(allow file-write-setugid/);
      assert.match(profile, /\(literal "\/dev\/null"\)/);
      assert.match(profile, /\(literal "\/dev\/tty"\)/);
      assert.doesNotMatch(profile, /process-path "\/bin\/bash"/);
      assert.doesNotMatch(profile, /\/private\/var\/tmp/);
      assert.doesNotMatch(profile, /sh-thd/);
      assert.doesNotMatch(profile, /allow file-write-data/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('isolates global writer controls from delegated worker lock paths', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-dual-lock-layout-'));
    const repositoryRoot = process.cwd();
    const tempRoot = join(directory, 'suite-temp');
    const controlRoot = join(directory, 'suite-controls');
    const globalProcessLockRoot = join(directory, 'global-process-locks');
    try {
      mkdirSync(tempRoot, { mode: 0o700 });
      mkdirSync(controlRoot, { mode: 0o700 });
      mkdirSync(globalProcessLockRoot, { mode: 0o700 });
      const writerLockBasename = basename(
        repositoryDatabaseWriterLockPath(repositoryRoot),
      );
      const layout = resolveTestProcessLockLayout({
        repositoryRoot,
        tempRoot,
        globalWriterLockPath: join(
          globalProcessLockRoot,
          writerLockBasename,
        ),
      });
      const canonicalDirectory = realpathSync.native(directory);
      const canonicalTempRoot = join(canonicalDirectory, 'suite-temp');
      const canonicalControlRoot = join(
        canonicalDirectory,
        'suite-controls',
      );
      const canonicalGlobalRoot =
        join(canonicalDirectory, 'global-process-locks');
      const installerFixtureRoot = join(
        canonicalControlRoot,
        'installer-heredocs',
      );
      const workerWritable = (candidate: string) =>
        layout.sandboxWritableRoots.some((writableRoot) =>
          candidate === writableRoot ||
          candidate.startsWith(`${writableRoot}${sep}`));

      assert.equal(layout.globalProcessLockRoot, canonicalGlobalRoot);
      assert.equal(
        layout.globalWriterLockPath,
        join(canonicalGlobalRoot, writerLockBasename),
      );
      assert.equal(
        layout.delegatedProcessLockRoot,
        join(canonicalTempRoot, 'process-locks'),
      );
      assert.equal(
        layout.delegatedWriterLockPath,
        join(canonicalTempRoot, 'process-locks', writerLockBasename),
      );
      assert.equal(
        basename(layout.delegatedWriterLockPath),
        basename(layout.globalWriterLockPath),
      );
      assert.deepEqual(layout.workerDatabaseRoots, [canonicalTempRoot]);
      assert.deepEqual(layout.sandboxWritableRoots, [
        canonicalTempRoot,
        join(canonicalGlobalRoot, 'test-audits'),
      ]);
      assert.equal(workerWritable(layout.globalProcessLockRoot), false);
      assert.equal(workerWritable(layout.globalWriterLockPath), false);
      assert.equal(workerWritable(layout.delegatedProcessLockRoot), true);
      assert.equal(workerWritable(layout.delegatedWriterLockPath), true);
      assert.equal(workerWritable(layout.auditRoot), true);
      assert.equal(workerWritable(canonicalControlRoot), false);
      assert.equal(workerWritable(installerFixtureRoot), false);

      const profile = buildDarwinSandboxProfile({
        writableRoots: [...layout.sandboxWritableRoots],
      });
      assert.match(
        profile,
        new RegExp(escapeRegExp(
          `(subpath ${JSON.stringify(canonicalTempRoot)})`,
        )),
      );
      assert.match(
        profile,
        new RegExp(escapeRegExp(
          `(subpath ${JSON.stringify(layout.auditRoot)})`,
        )),
      );
      assert.equal(
        profile.includes(
          `(subpath ${JSON.stringify(layout.globalProcessLockRoot)})`,
        ),
        false,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('delegates writer authority with the real parent PID and a distinct token', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-dual-lock-owner-'));
    const tempRoot = join(directory, 'suite-temp');
    const globalProcessLockRoot = join(directory, 'global-process-locks');
    let globalLock: ReturnType<typeof acquireExclusiveProcessLock> | null = null;
    let delegatedLock:
      ReturnType<typeof acquireExclusiveProcessLock> | null = null;
    try {
      mkdirSync(tempRoot, { mode: 0o700 });
      mkdirSync(globalProcessLockRoot, { mode: 0o700 });
      const writerLockBasename = basename(
        repositoryDatabaseWriterLockPath(process.cwd()),
      );
      const layout = resolveTestProcessLockLayout({
        repositoryRoot: process.cwd(),
        tempRoot,
        globalWriterLockPath: join(
          globalProcessLockRoot,
          writerLockBasename,
        ),
      });
      globalLock = acquireExclusiveProcessLock({
        lockPath: layout.globalWriterLockPath,
        label: 'synthetic global writer',
        resourceLabel: 'synthetic global repository writer',
        pid: process.pid,
        registerExitHandler: false,
      });
      delegatedLock = acquireExclusiveProcessLock({
        lockPath: layout.delegatedWriterLockPath,
        label: 'synthetic delegated writer',
        resourceLabel: 'synthetic delegated repository writer',
        pid: process.pid,
        registerExitHandler: false,
      });
      const writerLeasePath = join(tempRoot, 'writer-lease.json');
      const authority = buildDelegatedWriterAuthority({
        owner: delegatedLock.owner,
        processLockRoot: layout.delegatedProcessLockRoot,
        repositoryRoot: process.cwd(),
        tempRoot,
        writerLeasePath,
      });

      assert.equal(delegatedLock.owner.pid, process.pid);
      assert.notEqual(delegatedLock.owner.token, globalLock.owner.token);
      assert.deepEqual(authority.lease, {
        token: delegatedLock.owner.token,
        pid: process.pid,
        repositoryRoot: realpathSync.native(process.cwd()),
      });
      assert.deepEqual(authority.environment, {
        RADAR_TEST_ALLOWED_DB_ROOTS: JSON.stringify(
          layout.workerDatabaseRoots,
        ),
        RADAR_TEST_PROCESS_LOCK_ROOT: layout.delegatedProcessLockRoot,
        RADAR_TEST_WRITER_LOCK_PID: String(process.pid),
        RADAR_TEST_WRITER_LEASE_PATH:
          join(realpathSync.native(tempRoot), 'writer-lease.json'),
        RADAR_TEST_WRITER_LOCK_TOKEN: delegatedLock.owner.token,
      });
      assert.equal(
        JSON.stringify(authority).includes(globalLock.owner.token),
        false,
      );
      assert.equal(
        JSON.stringify(authority).includes(layout.globalProcessLockRoot),
        false,
      );
      assert.throws(
        () => buildDelegatedWriterAuthority({
          owner: {
            ...delegatedLock!.owner,
            pid: process.pid + 1,
          },
          processLockRoot: layout.delegatedProcessLockRoot,
          repositoryRoot: process.cwd(),
          tempRoot,
          writerLeasePath,
        }),
        /real runner PID/,
      );
    } finally {
      delegatedLock?.release();
      globalLock?.release();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('orders delegated lock release before watchdog and temp cleanup', () => {
    const runner = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    const outerStart = runner.indexOf(
      'export async function runTestSuite(options = {})',
    );
    const outerEnd = runner.indexOf(
      'export function acceptTestBaselineCandidate',
      outerStart,
    );
    const outerSource = runner.slice(outerStart, outerEnd);
    const unlockedCall = outerSource.indexOf(
      'return await runTestSuiteUnlocked({',
    );
    const globalRelease = outerSource.indexOf('writerLock?.release()');
    assert.ok(unlockedCall >= 0);
    assert.ok(globalRelease > unlockedCall);
    assert.match(
      outerSource,
      /globalWriterLockPath: writerLock\.path/,
    );
    assert.doesNotMatch(outerSource, /writerLockOwner/);

    const mainStart = runner.indexOf(
      'async function runTestSuiteUnlocked({',
    );
    const mainEnd = runner.indexOf(
      'export function resolvePhaseTimeout',
      mainStart,
    );
    const initializationStart = runner.indexOf(
      'async function initializeRunResources({',
    );
    const mainSource = runner.slice(mainStart, mainEnd);
    const workerCleanup = mainSource.indexOf("'exited worker cleanup'");
    const delegatedRelease = mainSource.indexOf(
      "'delegated repository writer lock release'",
    );
    const delegatedReleaseFailure = mainSource.indexOf(
      'if (!delegatedWriterLockReleased) preserveTempRoot = true;',
      delegatedRelease,
    );
    const watchdogCompletion = mainSource.indexOf(
      "'resource watchdog completion'",
    );
    const watchdogVerification = mainSource.indexOf(
      "'resource watchdog terminal audit rescan'",
    );
    const tempRemoval = mainSource.indexOf(
      "'test temporary root removal'",
    );
    const controlRemoval = mainSource.indexOf(
      "'test control root removal'",
    );
    assert.ok(workerCleanup >= 0);
    assert.ok(delegatedRelease > workerCleanup);
    assert.ok(delegatedReleaseFailure > delegatedRelease);
    assert.ok(watchdogCompletion > delegatedReleaseFailure);
    assert.ok(watchdogVerification > watchdogCompletion);
    assert.ok(tempRemoval > watchdogVerification);
    assert.ok(controlRemoval > tempRemoval);
    assert.match(mainSource, /\.\.\.writerEnvironment/);
    assert.doesNotMatch(mainSource, /RADAR_TEST_PROCESS_LOCK_ROOT\s*:/);
    assert.doesNotMatch(mainSource, /canonicalProcessLockRoot|writerLockOwner/);

    const initializationEnd = runner.indexOf(
      'export function canonicalRepositoryIdentity',
      initializationStart,
    );
    const initializationSource =
      runner.slice(initializationStart, initializationEnd);
    const tempCreation = initializationSource.indexOf(
      'tempRoot = canonicalPath(mkdtempSync',
    );
    const controlCreation = initializationSource.indexOf(
      'controlRoot = canonicalPath(mkdtempSync',
    );
    const controlOwnerPathCreation = initializationSource.indexOf(
      'const controlRootOwnerPath = join(controlRoot, tempRootOwnerFile);',
    );
    const ownerPathValidation = initializationSource.indexOf(
      'const runnerOwnerPaths = resolveResourceWatchdogOwnerPaths({',
    );
    const initialOwnerWrite = initializationSource.indexOf(
      'for (const ownerPath of runnerOwnerPaths)',
    );
    const installerFixtureCreation = initializationSource.indexOf(
      'const installerFixture = materializePrivateInstallerHeredocs({',
    );
    const delegatedAcquisition = initializationSource.indexOf(
      'delegatedWriterLock = acquireExclusiveProcessLock({',
    );
    const partialRelease = initializationSource.indexOf(
      "'partially initialized delegated writer lock release'",
    );
    const partialReleaseFailure = initializationSource.indexOf(
      'if (!delegatedWriterLockReleased) preserveTempRoot = true;',
      partialRelease,
    );
    const partialWatchdogCompletion = initializationSource.indexOf(
      "'partially initialized resource watchdog completion'",
    );
    const partialWatchdogVerification = initializationSource.indexOf(
      "'partially initialized resource watchdog terminal audit rescan'",
    );
    const partialTempGuard = initializationSource.indexOf(
      'if (tempRoot && !preserveTempRoot)',
    );
    const partialTempRemoval = initializationSource.indexOf(
      "'partially initialized temporary root removal'",
    );
    const partialControlRemoval = initializationSource.indexOf(
      "'partially initialized control root removal'",
    );
    assert.ok(tempCreation >= 0);
    assert.ok(delegatedAcquisition > tempCreation);
    assert.ok(controlCreation > delegatedAcquisition);
    assert.ok(controlOwnerPathCreation > controlCreation);
    assert.ok(ownerPathValidation > controlOwnerPathCreation);
    assert.ok(initialOwnerWrite > ownerPathValidation);
    assert.ok(installerFixtureCreation > initialOwnerWrite);
    assert.match(
      initializationSource.slice(
        delegatedAcquisition,
        initializationSource.indexOf('});', delegatedAcquisition) + 3,
      ),
      /pid: process\.pid/,
    );
    assert.match(
      initializationSource,
      /owner: delegatedWriterLock\.owner/,
    );
    assert.match(
      initializationSource,
      /processLockRoot: processLockLayout\.delegatedProcessLockRoot/,
    );
    assert.match(
      initializationSource,
      /const auditRoot = processLockLayout\.auditRoot/,
    );
    assert.match(
      initializationSource,
      /writeFileSync\(emptyDotenvPath, '', \{ flag: 'wx', mode: 0o600 \}\)/,
    );
    assert.match(
      initializationSource,
      /writableRoots: processLockLayout\.sandboxWritableRoots/,
    );
    assert.match(
      initializationSource,
      /fixtureRoot: join\(controlRoot, 'installer-heredocs'\)/,
    );
    assert.match(
      initializationSource,
      /forbidShellHereStrings: true/,
    );
    assert.doesNotMatch(
      initializationSource,
      /fixtureRoot: join\(tempRoot, 'installer-heredocs'\)/,
    );
    assert.match(
      initializationSource,
      /const controlRootOwnerPath = join\(controlRoot, tempRootOwnerFile\)/,
    );
    assert.match(
      initializationSource,
      /\$\{testRootPrefixForRepository\(canonicalRoot\)\}controls-/,
    );
    assert.match(
      initializationSource,
      /for \(const ownerPath of runnerOwnerPaths\) \{\s+writeTempRootOwnerState\(ownerPath, initialOwnerState\);\s+\}/,
    );
    assert.equal(
      (
        initializationSource.match(
          /additionalOwnerPaths: \[controlRootOwnerPath\]/g,
        ) ?? []
      ).length,
      2,
    );
    assert.match(
      initializationSource,
      /JSON\.stringify\(writerAuthority\.lease\)/,
    );
    assert.ok(partialRelease > delegatedAcquisition);
    assert.ok(partialReleaseFailure > partialRelease);
    assert.ok(partialWatchdogCompletion > partialReleaseFailure);
    assert.ok(partialWatchdogVerification > partialWatchdogCompletion);
    assert.ok(partialTempGuard > partialWatchdogVerification);
    assert.ok(partialTempRemoval > partialTempGuard);
    assert.ok(partialControlRemoval > partialTempRemoval);

    const ownerPathHelperStart = runner.indexOf(
      'function resolveResourceWatchdogOwnerPaths({',
    );
    const watchdogStart = runner.indexOf(
      'export async function startResourceWatchdog({',
      ownerPathHelperStart,
    );
    const watchdogEnd = runner.indexOf(
      'function writeTempRootOwnerState',
      watchdogStart,
    );
    const ownerPathHelperSource =
      runner.slice(ownerPathHelperStart, watchdogStart);
    const watchdogSource = runner.slice(watchdogStart, watchdogEnd);
    assert.ok(ownerPathHelperStart >= 0);
    assert.ok(watchdogStart > ownerPathHelperStart);
    assert.ok(watchdogEnd > watchdogStart);
    assert.match(ownerPathHelperSource, /!isAbsolute\(ownerPath\)/);
    assert.match(
      ownerPathHelperSource,
      /basename\(ownerPath\) !== tempRootOwnerFile/,
    );
    assert.match(ownerPathHelperSource, /!rootStats\.isDirectory\(\)/);
    assert.match(ownerPathHelperSource, /rootStats\.isSymbolicLink\(\)/);
    assert.match(
      ownerPathHelperSource,
      /rootStats\.uid !== process\.getuid\(\)/,
    );
    assert.match(ownerPathHelperSource, /rootStats\.mode & 0o077/);
    assert.match(ownerPathHelperSource, /!ownerStats\.isFile\(\)/);
    assert.match(ownerPathHelperSource, /ownerStats\.isSymbolicLink\(\)/);
    assert.match(
      ownerPathHelperSource,
      /ownerStats\.uid !== process\.getuid\(\)/,
    );
    assert.match(ownerPathHelperSource, /ownerStats\.mode & 0o077/);
    assert.match(
      ownerPathHelperSource,
      /samePath\(dirname\(ownerPaths\[0\]\), tempRoot\)/,
    );
    assert.match(
      watchdogSource,
      /additionalOwnerPaths = \[\]/,
    );
    assert.match(
      watchdogSource,
      /for \(const ownerPath of ownerPaths\) \{\s+writeTempRootOwnerState\(ownerPath, ownerState\);\s+\}/,
    );
    assert.match(
      watchdogSource,
      /heartbeat = setInterval\(\(\) => \{\s+try \{\s+writeState\(\);/,
    );
  });

  it('scopes the transformed installer path to the installer phase', () => {
    const environment = {
      NODE_OPTIONS: '--import=tsx',
      SAFE_VALUE: 'preserved',
    };
    const guardNodeOptions =
      '--import=file:///private/worker.mjs --import=file:///private/guard.mjs';
    const installerFixturePath = resolve(
      '/tmp/openclaw-release-radar-private-installer.sh',
    );
    const installerEnvironment = phaseChildEnvironment({
      phase: 'installer',
      environment,
      guardNodeOptions,
      installerFixturePath,
    });
    assert.notStrictEqual(installerEnvironment, environment);
    assert.deepEqual(installerEnvironment, {
      NODE_OPTIONS: guardNodeOptions,
      SAFE_VALUE: 'preserved',
      RADAR_TEST_INSTALLER_FIXTURE_PATH: installerFixturePath,
    });
    assert.doesNotMatch(
      installerEnvironment.NODE_OPTIONS,
      /(?:^|\s)--import=tsx(?:\s|$)/,
    );
    for (const phase of [
      'parallel',
      'e2e',
      'lifecycle',
      'scripts',
    ] as const) {
      assert.strictEqual(
        phaseChildEnvironment({
          phase,
          environment,
          guardNodeOptions,
          installerFixturePath,
        }),
        environment,
      );
    }
    assert.deepEqual(environment, {
      NODE_OPTIONS: '--import=tsx',
      SAFE_VALUE: 'preserved',
    });
    assert.throws(
      () => phaseChildEnvironment({
        phase: 'installer',
        environment,
        guardNodeOptions,
        installerFixturePath: 'relative-installer.sh',
      }),
      /requires an absolute private installer fixture path/,
    );
    assert.throws(
      () => phaseChildEnvironment({
        phase: 'installer',
        environment,
        guardNodeOptions: '',
        installerFixturePath,
      }),
      /requires guarded child NODE_OPTIONS/,
    );
    const runnerSource = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    assert.match(
      runnerSource,
      /try \{\s+if \(phase === 'installer'\) \{\s+assertPrivateInstallerFixtureUnchanged\(\s+installerFixtureIdentity,\s+\);\s+\}\s+activeChild = spawn/,
    );
    const mainStart = runnerSource.indexOf(
      'async function runTestSuiteUnlocked({',
    );
    const mainEnd = runnerSource.indexOf(
      'export function resolvePhaseTimeout',
      mainStart,
    );
    const mainSource = runnerSource.slice(mainStart, mainEnd);
    const installerSpawn = mainSource.indexOf('activeChild = spawn');
    const processGroupCompletion = mainSource.indexOf(
      'await terminateProcessTreeAndWait(phaseChild)',
      installerSpawn,
    );
    const confirmedStopBranch = mainSource.indexOf(
      'if (processGroupStopped) {',
      processGroupCompletion,
    );
    const postInstallerCheck = mainSource.indexOf(
      "'installer fixture post-phase integrity'",
      confirmedStopBranch,
    );
    const unconfirmedStopBranch = mainSource.indexOf(
      '} else {\n        preserveTempRoot = true;\n      }',
      postInstallerCheck,
    );
    const phaseFailureAggregation = mainSource.indexOf(
      'phaseFailure = combineErrors(',
      postInstallerCheck,
    );
    assert.ok(installerSpawn >= 0);
    assert.ok(processGroupCompletion > installerSpawn);
    assert.ok(confirmedStopBranch > processGroupCompletion);
    assert.ok(postInstallerCheck > confirmedStopBranch);
    assert.ok(unconfirmedStopBranch > postInstallerCheck);
    assert.ok(phaseFailureAggregation > postInstallerCheck);
    assert.equal(
      (
        mainSource.match(/installer fixture post-phase integrity/g) ?? []
      ).length,
      1,
    );
    assert.match(
      mainSource,
      /if \(processGroupStopped\) \{[\s\S]*?if \(phase === 'installer'\) \{\s+await runCleanupStep\(\s+phaseCleanupErrors,\s+'installer fixture post-phase integrity',\s+\(\) => assertPrivateInstallerFixtureUnchanged\(\s+installerFixtureIdentity,\s+'after installer phase',\s+\),\s+\);\s+\}[\s\S]*?\} else \{\s+preserveTempRoot = true;\s+\}/,
    );
  });

  it('materializes quoted heredocs privately without changing shell suffixes', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-heredoc-fixture-'));
    const sourcePath = join(directory, 'installer-source.sh');
    const fixtureRoot = join(directory, 'private-fixture');
    const sourceText = [
      '#!/usr/bin/env bash',
      'value="$("$node_bin" - <<\'NODE\'',
      "  process.stdout.write('$HOME `tick` \"quoted\"\\n');",
      'NODE',
      ')"',
      'cat >&2 <<\'EOF\'',
      "  indented '$PATH' `literal` \"quotes\"",
      'EOF',
      'run_node <<\'NODE\' || return 1',
      "process.stdout.write('return-body\\n');",
      'NODE',
      'run_node <<\'NODE\' || exit 1',
      "process.stdout.write('exit-body\\n');",
      'NODE',
      'run_node <<\'NODE\' ||',
      '  return 1',
      "process.stdout.write('continued-body\\n');",
      'NODE',
      'read -r upload_sha upload_size <<<"$upload_identity" || exit 1',
      'done <<< "$tar_entries"',
      '',
    ].join('\r\n');
    const source = Buffer.from(sourceText);
    writeFileSync(sourcePath, source);
    try {
      const materialized = materializePrivateInstallerHeredocs({
        sourcePath,
        fixtureRoot,
        expectedHeredocCount: 5,
      });
      assert.equal(materialized.heredocs.length, 5);
      assert.deepEqual(
        materialized.heredocs.map((entry) => entry.delimiter),
        ['NODE', 'EOF', 'NODE', 'NODE', 'NODE'],
      );
      assert.deepEqual(
        readFileSync(materialized.heredocs[0].bodyPath),
        Buffer.from(
          "  process.stdout.write('$HOME `tick` \"quoted\"\\n');\r\n",
        ),
      );
      assert.deepEqual(
        readFileSync(materialized.heredocs[1].bodyPath),
        Buffer.from("  indented '$PATH' `literal` \"quotes\"\r\n"),
      );
      assert.deepEqual(
        readFileSync(materialized.heredocs[2].bodyPath),
        Buffer.from("process.stdout.write('return-body\\n');\r\n"),
      );
      assert.deepEqual(
        readFileSync(materialized.heredocs[3].bodyPath),
        Buffer.from("process.stdout.write('exit-body\\n');\r\n"),
      );
      assert.deepEqual(
        readFileSync(materialized.heredocs[4].bodyPath),
        Buffer.from("process.stdout.write('continued-body\\n');\r\n"),
      );

      const transformed = readFileSync(
        materialized.installerPath,
        'utf8',
      );
      assert.ok(transformed.includes(
        `value="$("$node_bin" - < '${materialized.heredocs[0].bodyPath}'`,
      ));
      assert.ok(transformed.includes(
        `cat >&2 < '${materialized.heredocs[1].bodyPath}'`,
      ));
      assert.ok(transformed.includes(
        `run_node < '${materialized.heredocs[2].bodyPath}' || return 1`,
      ));
      assert.ok(transformed.includes(
        `run_node < '${materialized.heredocs[3].bodyPath}' || exit 1`,
      ));
      assert.ok(transformed.includes(
        `run_node < '${materialized.heredocs[4].bodyPath}' ||\r\n` +
        '  return 1',
      ));
      assert.ok(transformed.includes(
        'read -r upload_sha upload_size <<<"$upload_identity" || exit 1',
      ));
      assert.ok(transformed.includes('done <<< "$tar_entries"'));
      assert.doesNotMatch(transformed, /<<'[A-Za-z_][A-Za-z0-9_]*'/);
      assert.equal(
        transformed.match(/\r\n/g)?.length,
        sourceText.match(/\r\n/g)?.length,
      );
      assert.ok(transformed.endsWith('\r\n'));

      const manifest = JSON.parse(
        readFileSync(materialized.manifestPath, 'utf8'),
      );
      assert.equal(manifest.source.sha256, materialized.sourceSha256);
      assert.equal(
        manifest.transformed.sha256,
        materialized.transformedSha256,
      );
      assert.equal(
        materialized.sourceSha256,
        createHash('sha256').update(source).digest('hex'),
      );
      assert.equal(
        materialized.transformedSha256,
        createHash('sha256')
          .update(readFileSync(materialized.installerPath))
          .digest('hex'),
      );
      assert.doesNotThrow(() =>
        assertPrivateInstallerFixtureUnchanged(
          materialized.fixtureIdentity,
        ));
      assert.equal(Object.isFrozen(materialized.fixtureIdentity), true);
      assert.equal(Object.isFrozen(materialized.fixtureIdentity.root), true);
      assert.equal(Object.isFrozen(materialized.fixtureIdentity.files), true);
      assert.equal(
        materialized.fixtureIdentity.files.length,
        materialized.heredocs.length + 2,
      );
      assert.deepEqual(
        manifest.heredocs.map((entry: {
          openerLine: number;
          bodyStartLine: number | null;
          bodyEndLine: number | null;
          delimiterLine: number;
        }) => ({
          openerLine: entry.openerLine,
          bodyStartLine: entry.bodyStartLine,
          bodyEndLine: entry.bodyEndLine,
          delimiterLine: entry.delimiterLine,
        })),
        [
          {
            openerLine: 2,
            bodyStartLine: 3,
            bodyEndLine: 3,
            delimiterLine: 4,
          },
          {
            openerLine: 6,
            bodyStartLine: 7,
            bodyEndLine: 7,
            delimiterLine: 8,
          },
          {
            openerLine: 9,
            bodyStartLine: 10,
            bodyEndLine: 10,
            delimiterLine: 11,
          },
          {
            openerLine: 12,
            bodyStartLine: 13,
            bodyEndLine: 13,
            delimiterLine: 14,
          },
          {
            openerLine: 15,
            bodyStartLine: 17,
            bodyEndLine: 17,
            delimiterLine: 18,
          },
        ],
      );
      assert.equal(statSync(materialized.fixtureRoot).mode & 0o777, 0o700);
      const installerStats = statSync(
        materialized.installerPath,
        { bigint: true },
      );
      const manifestStats = statSync(
        materialized.manifestPath,
        { bigint: true },
      );
      const expectedInstaller = materialized.fixtureIdentity.files.find(
        (identity) => identity.role === 'transformed installer',
      );
      assert.ok(expectedInstaller);
      assert.equal(expectedInstaller.path, materialized.installerPath);
      assert.equal(expectedInstaller.dev, String(installerStats.dev));
      assert.equal(expectedInstaller.ino, String(installerStats.ino));
      assert.equal(
        expectedInstaller.mode,
        Number(installerStats.mode & 0o777n),
      );
      assert.equal(expectedInstaller.nlink, Number(installerStats.nlink));
      assert.equal(
        expectedInstaller.digest,
        materialized.transformedSha256,
      );
      assert.equal(Number(installerStats.mode & 0o777n), 0o500);
      assert.equal(installerStats.nlink, 1n);
      assert.equal(Number(manifestStats.mode & 0o777n), 0o400);
      assert.equal(manifestStats.nlink, 1n);
      for (const heredoc of materialized.heredocs) {
        const stats = statSync(heredoc.bodyPath);
        assert.equal(stats.mode & 0o777, 0o400);
        assert.equal(stats.nlink, 1);
        assert.equal(
          createHash('sha256')
            .update(readFileSync(heredoc.bodyPath))
            .digest('hex'),
          heredoc.sha256,
        );
      }
      assert.deepEqual(readFileSync(sourcePath), source);
      const transformedBefore = readFileSync(materialized.installerPath);
      assert.throws(
        () => materializePrivateInstallerHeredocs({
          sourcePath,
          fixtureRoot,
          expectedHeredocCount: 5,
        }),
        /EEXIST|exist/i,
      );
      assert.deepEqual(
        readFileSync(materialized.installerPath),
        transformedBefore,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects materialized installer fixture mutation or replacement', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-heredoc-identity-'));
    const sourcePath = join(directory, 'installer-source.sh');
    writeFileSync(
      sourcePath,
      '#!/usr/bin/env bash\ncat <<\'EOF\'\nbody\nEOF\n',
    );
    const materialize = (name: string) =>
      materializePrivateInstallerHeredocs({
        sourcePath,
        fixtureRoot: join(directory, name),
        expectedHeredocCount: 1,
      });
    try {
      const contentMutation = materialize('content-mutation');
      const original = readFileSync(contentMutation.installerPath);
      chmodSync(contentMutation.installerPath, 0o700);
      writeFileSync(
        contentMutation.installerPath,
        Buffer.concat([original, Buffer.from('# changed\n')]),
      );
      chmodSync(contentMutation.installerPath, 0o500);
      assert.throws(
        () => assertPrivateInstallerFixtureUnchanged(
          contentMutation.fixtureIdentity,
        ),
        /fixture changed before installer phase/i,
      );

      const replacement = materialize('replacement');
      const replacementBytes = readFileSync(replacement.installerPath);
      rmSync(replacement.installerPath);
      writeFileSync(replacement.installerPath, replacementBytes, {
        flag: 'wx',
        mode: 0o500,
      });
      chmodSync(replacement.installerPath, 0o500);
      assert.throws(
        () => assertPrivateInstallerFixtureUnchanged(
          replacement.fixtureIdentity,
        ),
        /fixture changed before installer phase/i,
      );

      const linkedBody = materialize('linked-body');
      linkSync(
        linkedBody.heredocs[0].bodyPath,
        join(linkedBody.fixtureRoot, 'body-alias'),
      );
      assert.throws(
        () => assertPrivateInstallerFixtureUnchanged(
          linkedBody.fixtureIdentity,
        ),
        /fixture changed before installer phase/i,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('fails closed on unsupported or unterminated heredoc forms', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-heredoc-reject-'));
    const cases: Array<{
      name: string;
      source: string;
      message: RegExp;
      expectedHeredocCount?: number;
      forbidShellHereStrings?: boolean;
    }> = [
      {
        name: 'unquoted',
        source: 'cat <<EOF\nbody\nEOF\n',
        message: /unsupported heredoc form/,
      },
      {
        name: 'here-string-then-unquoted',
        source: 'read -r value <<<"$input"; cat <<EOF\nbody\nEOF\n',
        message: /unsupported heredoc form/,
      },
      {
        name: 'here-string-only',
        source: 'read -r value <<<"$input"\n',
        message: /unsupported shell here-string form/,
        expectedHeredocCount: 0,
        forbidShellHereStrings: true,
      },
      {
        name: 'indented',
        source: 'cat <<-\'EOF\'\n\tbody\nEOF\n',
        message: /unsupported heredoc form/,
      },
      {
        name: 'four-angle',
        source: 'cat <<<<EOF\nbody\nEOF\n',
        message: /exactly one heredoc opener|unsupported heredoc form/,
      },
      {
        name: 'spaced',
        source: 'cat << \'EOF\'\nbody\nEOF\n',
        message: /unsupported heredoc form/,
      },
      {
        name: 'multiple',
        source: 'cat <<\'ONE\' <<\'TWO\'\nONE\nTWO\n',
        message: /exactly one heredoc opener/,
      },
      {
        name: 'unsupported-continuation',
        source: 'cat <<\'EOF\' ||\n  cleanup\nbody\nEOF\n',
        message: /unsupported heredoc shell continuation/,
      },
      {
        name: 'unterminated',
        source: 'cat <<\'EOF\'\nbody\n',
        message: /unterminated <<'EOF' heredoc/,
      },
    ];
    try {
      for (const [index, fixture] of cases.entries()) {
        const sourcePath = join(directory, `${fixture.name}.sh`);
        const fixtureRoot = join(directory, `fixture-${index}`);
        writeFileSync(sourcePath, fixture.source);
        assert.throws(
          () => materializePrivateInstallerHeredocs({
            sourcePath,
            fixtureRoot,
            expectedHeredocCount:
              fixture.expectedHeredocCount ?? 1,
            forbidShellHereStrings:
              fixture.forbidShellHereStrings ?? false,
          }),
          fixture.message,
        );
        assert.equal(existsSync(fixtureRoot), false);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('materializes every quoted heredoc in the production installer', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-heredoc-production-'));
    const sourcePath = join(
      process.cwd(),
      'ops',
      'viralo',
      'openclaw-release-radar-install-release.sh',
    );
    const fixtureRoot = join(directory, 'private-fixture');
    const sourceBefore = readFileSync(sourcePath);
    const sourceText = sourceBefore.toString('utf8');
    try {
      assert.equal(productionInstallerQuotedHeredocCount, 53);
      assert.equal(
        sourceText.match(/<<'[A-Za-z_][A-Za-z0-9_]*'/g)?.length ?? 0,
        productionInstallerQuotedHeredocCount,
      );
      const productionHereStrings = sourceText
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.includes('<<<'));
      assert.deepEqual(productionHereStrings, []);
      const materialized = materializePrivateInstallerHeredocs({
        sourcePath,
        fixtureRoot,
        expectedHeredocCount: productionInstallerQuotedHeredocCount,
        forbidShellHereStrings: true,
      });
      assert.equal(
        materialized.heredocs.length,
        productionInstallerQuotedHeredocCount,
      );
      const transformed = readFileSync(
        materialized.installerPath,
        'utf8',
      );
      assert.doesNotMatch(
        transformed,
        /<<'[A-Za-z_][A-Za-z0-9_]*'/,
      );
      assert.equal(
        transformed.match(/<<</g)?.length ?? 0,
        productionHereStrings.length,
      );
      assert.deepEqual(
        transformed
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line.includes('<<<')),
        productionHereStrings,
      );
      assert.equal(
        JSON.parse(
          readFileSync(materialized.manifestPath, 'utf8'),
        ).heredocs.length,
        productionInstallerQuotedHeredocCount,
      );
      assert.deepEqual(readFileSync(sourcePath), sourceBefore);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('verifies cleaned worker databases through a canonical temp-root alias', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-audit-alias-test-'));
    const realRoot = join(directory, 'real-root');
    const aliasRoot = join(directory, 'alias-root');
    const auditPath = join(directory, 'audit.jsonl');
    const runId = 'audit-alias-run';
    const file = 'src/lib/a.test.ts';
    try {
      mkdirSync(realRoot);
      symlinkSync(realRoot, aliasRoot, 'dir');
      const workerDir = mkdtempSync(join(aliasRoot, 'worker-'));
      const dbPath = join(workerDir, 'radar.db');
      writeFileSync(
        auditPath,
        [
          {
            runId,
            type: 'worker-env',
            pid: 101,
            context: 'child-v8',
            dbPath,
            workerDir,
            script: join(process.cwd(), file),
          },
          {
            runId,
            type: 'process-start',
            pid: 101,
            dbPath,
            workerDbPath: dbPath,
          },
          {
            runId,
            type: 'worker-cleanup',
            pid: 101,
            dbPath,
            workerDir,
            removed: true,
          },
        ].map((event) => JSON.stringify(event)).join('\n') + '\n',
      );
      rmSync(workerDir, { recursive: true, force: true });

      assert.doesNotThrow(() => assertDatabaseAudit({
        auditPath,
        expectedFiles: [file],
        tempRoot: aliasRoot,
        liveDatabase: join(directory, 'live.db'),
        runId,
      }));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects workers that start on the shared suite database', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-audit-shared-test-'));
    const auditPath = join(directory, 'audit.jsonl');
    const runId = 'audit-shared-run';
    const sharedDatabase = join(directory, 'runner.db');
    const files = ['src/lib/a.test.ts', 'src/lib/b.test.ts'];
    const workers = files.map((file, index) => {
      const workerDir = mkdtempSync(join(directory, 'worker-'));
      return {
        dbPath: join(workerDir, 'radar.db'),
        file,
        pid: 201 + index,
        workerDir,
      };
    });
    try {
      const events = workers.flatMap((worker) => [
        {
          runId,
          type: 'worker-env',
          pid: worker.pid,
          context: 'child-v8',
          dbPath: worker.dbPath,
          workerDir: worker.workerDir,
          script: join(process.cwd(), worker.file),
        },
        {
          runId,
          type: 'process-start',
          pid: worker.pid,
          dbPath: sharedDatabase,
          workerDbPath: worker.dbPath,
        },
        {
          runId,
          type: 'worker-cleanup',
          pid: worker.pid,
          dbPath: worker.dbPath,
          workerDir: worker.workerDir,
          removed: true,
        },
      ]);
      writeFileSync(
        auditPath,
        events.map((event) => JSON.stringify(event)).join('\n') + '\n',
      );
      for (const worker of workers) {
        rmSync(worker.workerDir, { recursive: true, force: true });
      }

      assert.throws(
        () => assertDatabaseAudit({
          auditPath,
          expectedFiles: files,
          tempRoot: directory,
          liveDatabase: join(directory, 'live.db'),
          runId,
        }),
        /did not start on its assigned private suite database/,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('enforces bounded disk footprints and cumulative process writes', () => {
    assert.deepEqual(resolveTestResourceLimits({ environment: {} }), {
      maximumWorkerBytes: 256 * mebibyte,
      maximumSuiteBytes: 512 * mebibyte,
      maximumSqliteBytes: 128 * mebibyte,
      maximumProcessWriteBytes: 4096 * mebibyte,
      maximumSystemDiskTransferBytes: 2048 * mebibyte,
      minimumStartingFreeBytes: 10 * gibibyte,
      minimumRuntimeFreeBytes: 2 * gibibyte,
    });
    assert.deepEqual(resolveTestResourceLimits({
      environment: {
        RADAR_TEST_MAX_WORKER_MIB: '512',
        RADAR_TEST_MAX_SUITE_MIB: '1024',
        RADAR_TEST_SQLITE_MAX_MIB: '256',
        RADAR_TEST_MAX_PROCESS_WRITE_MIB: '4096',
        RADAR_TEST_MAX_SYSTEM_IO_MIB: '4096',
      },
    }), {
      maximumWorkerBytes: 512 * mebibyte,
      maximumSuiteBytes: 1024 * mebibyte,
      maximumSqliteBytes: 256 * mebibyte,
      maximumProcessWriteBytes: 4096 * mebibyte,
      maximumSystemDiskTransferBytes: 4096 * mebibyte,
      minimumStartingFreeBytes: 10 * gibibyte,
      minimumRuntimeFreeBytes: 2 * gibibyte,
    });

    for (const [name, value, expected] of [
      ['RADAR_TEST_MAX_WORKER_MIB', '513', /safety maximum 512/],
      ['RADAR_TEST_MAX_SUITE_MIB', '1025', /safety maximum 1024/],
      ['RADAR_TEST_SQLITE_MAX_MIB', '257', /safety maximum 256/],
      ['RADAR_TEST_MAX_PROCESS_WRITE_MIB', '4097', /safety maximum 4096/],
      ['RADAR_TEST_MAX_SYSTEM_IO_MIB', '4097', /safety maximum 4096/],
      ['RADAR_TEST_MAX_WORKER_MIB', '0', /integer from 1 to 512/],
      ['RADAR_TEST_MAX_SUITE_MIB', '1.5', /integer from 1 to 1024/],
      ['RADAR_TEST_MAX_WORKER_MIB', 'none', /integer from 1 to 512/],
    ] as const) {
      assert.throws(
        () => resolveTestResourceLimits({
          environment: { [name]: value },
        }),
        expected,
      );
    }
  });

  it('detects a footprint breach introduced immediately before monitor shutdown', () => {
    const tempRoot = mkdtempSync(join(tmpdir(), 'radar-final-footprint-'));
    const auditPath = join(tempRoot, 'audit.jsonl');
    const runId = 'final-footprint-breach';
    writeFileSync(auditPath, '');
    const monitor = startFootprintMonitor({
      tempRoot,
      auditPath,
      runId,
      limits: {
        maximumWorkerBytes: 1024,
        maximumSuiteBytes: 1024,
        minimumRuntimeFreeBytes: 0,
      },
    });
    try {
      writeFileSync(join(tempRoot, 'late-breach.bin'), Buffer.alloc(2048));
      assert.throws(
        () => monitor.stop(),
        /temporary footprint exceeded/,
      );
      const events = readFileSync(auditPath, 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      assert.deepEqual(
        events.map((event) => event.type),
        ['resource-breach', 'resource-summary'],
      );
      assert.equal(events[0].runId, runId);
      assert.equal(events[1].breached, true);
    } finally {
      rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  it('parses monotonic macOS disk-transfer counters and rejects regressions', () => {
    const output = `
                  disk0           disk1
        KB/t xfrs      MB    KB/t xfrs      MB
       16.00  100 1024.50    8.00   10    4.25
    `;
    const baseline = parseDarwinIostatDiskTransferBytes(output);
    assert.equal(baseline, 1028.75 * mebibyte);
    assert.equal(
      systemDiskTransferDeltaBytes(baseline, baseline + 64 * mebibyte),
      64 * mebibyte,
    );
    assert.throws(
      () => systemDiskTransferDeltaBytes(baseline, baseline - 1),
      /counter regressed/,
    );
    assert.throws(
      () => parseDarwinIostatDiskTransferBytes('no numeric device rows'),
      /Unable to parse/,
    );
  });

  it('enforces a bounded non-disableable phase timeout', () => {
    assert.equal(resolvePhaseTimeout({ environment: {} }), 30 * 60 * 1000);
    assert.equal(resolvePhaseTimeout({
      environment: { RADAR_TEST_PHASE_TIMEOUT_MS: '60000' },
    }), 60_000);
    for (const value of ['0', '999', '7200001', 'none', '1.5']) {
      assert.throws(
        () => resolvePhaseTimeout({
          environment: { RADAR_TEST_PHASE_TIMEOUT_MS: value },
        }),
        /must be an integer from 1000 to 7200000/,
      );
    }
  });

  it('enforces a bounded non-disableable per-test timeout', () => {
    assert.equal(resolveTestTimeout({ environment: {} }), 2 * 60 * 1000);
    assert.equal(resolveTestTimeout({
      environment: { RADAR_TEST_TIMEOUT_MS: '60000' },
    }), 60_000);
    assert.deepEqual(
      testCommand({
        phase: 'parallel',
        files: ['bounded.test.ts'],
        eventLogPath: '/tmp/bounded-events.jsonl',
        testTimeoutMs: 45_000,
      }).filter((argument) => argument.startsWith('--test-timeout=')),
      ['--test-timeout=45000'],
    );
    for (const value of ['0', '999', '300001', 'none', '1.5']) {
      assert.throws(
        () => resolveTestTimeout({
          environment: { RADAR_TEST_TIMEOUT_MS: value },
        }),
        /must be an integer from 1000 to 300000/,
      );
    }
  });

  it('bounds watchdog SIGKILL confirmation instead of polling forever', () => {
    const watchdog = readFileSync(
      join(process.cwd(), 'test', 'resource-watchdog.mjs'),
      'utf8',
    );
    assert.match(watchdog, /const terminationKillMs = 5_000/);
    assert.match(
      watchdog,
      /const killDeadline = Date\.now\(\) \+ terminationKillMs/,
    );
    assert.match(watchdog, /Date\.now\(\) < killDeadline/);
    assert.match(watchdog, /watchdog-termination-unconfirmed/);
    assert.match(
      watchdog,
      /watchdog-process-group-termination-unconfirmed/,
    );
  });

  it('bounds transient process-group identity ambiguity before failing closed', () => {
    const watchdog = readFileSync(
      join(process.cwd(), 'test', 'resource-watchdog.mjs'),
      'utf8',
    );
    assert.match(watchdog, /const processGroupIdentityGraceMs = 1_000/);
    assert.match(
      watchdog,
      /now - pendingSince < processGroupIdentityGraceMs/,
    );
    assert.match(
      watchdog,
      /status === 'gone' \|\| status === 'pending'/,
    );
    assert.match(
      watchdog,
      /watchdog-process-group-identity-pending/,
    );
  });

  it('keys resource-breach interruption by the complete process-group assignment', () => {
    const watchdog = readFileSync(
      join(process.cwd(), 'test', 'resource-watchdog.mjs'),
      'utf8',
    );
    assert.doesNotMatch(watchdog, /interruptedProcessGroupPid/);
    assert.match(watchdog, /const interruptedProcessGroupAssignments = new Set\(\)/);
    assert.match(
      watchdog,
      /return canonicalJson\(\{\s*processGroupPid: state\.activeProcessGroupPid,\s*processGroupIdentity: state\.activeProcessGroupIdentity,\s*allowedCommandDigests: processGroupAllowedCommandDigests\(state\),\s*\}\)/,
    );
  });

  it('accepts only sealed command transitions for the same process instance', () => {
    const launcherDigest = 'a'.repeat(64);
    const targetDigest = 'b'.repeat(64);
    const expected = {
      schemaVersion: 1,
      platform: 'darwin',
      pid: 4242,
      parentPid: 4000,
      processGroupPid: 4242,
      startedAt: 'Mon Jul  6 14:56:28 2026',
      commandDigest: launcherDigest,
    };
    const transitioned = {
      ...expected,
      commandDigest: targetDigest,
    };
    assert.equal(
      processIdentityMatches(expected, transitioned, {
        requireProcessGroupLeader: true,
        allowedCommandDigests: [launcherDigest, targetDigest],
      }),
      true,
    );
    assert.equal(
      processIdentityMatches(expected, transitioned, {
        requireProcessGroupLeader: true,
        allowedCommandDigests: [launcherDigest],
      }),
      false,
    );
    assert.equal(
      processIdentityMatches(expected, {
        ...transitioned,
        startedAt: 'Mon Jul  6 14:56:29 2026',
      }, {
        requireProcessGroupLeader: true,
        allowedCommandDigests: [launcherDigest, targetDigest],
      }),
      false,
    );
    const parentIdentity = {
      schemaVersion: 1,
      platform: 'darwin',
      pid: expected.parentPid,
      parentPid: 3000,
      processGroupPid: 3000,
      startedAt: 'Mon Jul  6 14:55:00 2026',
      commandDigest: 'c'.repeat(64),
    };
    const reparented = {
      ...transitioned,
      parentPid: 1,
    };
    assert.equal(
      processIdentityMatchesAfterDarwinReparent(expected, reparented, {
        parentIdentity,
        parentAlive: false,
        requireProcessGroupLeader: true,
        allowedCommandDigests: [launcherDigest, targetDigest],
      }),
      true,
    );
    for (const invalid of [
      {
        actual: reparented,
        parentIdentity,
        parentAlive: true,
      },
      {
        actual: { ...reparented, parentPid: 2 },
        parentIdentity,
        parentAlive: false,
      },
      {
        actual: { ...reparented, startedAt: 'Mon Jul  6 14:56:29 2026' },
        parentIdentity,
        parentAlive: false,
      },
      {
        actual: { ...reparented, platform: 'linux' },
        parentIdentity,
        parentAlive: false,
      },
      {
        actual: reparented,
        parentIdentity: { ...parentIdentity, pid: 4001 },
        parentAlive: false,
      },
    ]) {
      assert.equal(
        processIdentityMatchesAfterDarwinReparent(
          expected,
          invalid.actual,
          {
            parentIdentity: invalid.parentIdentity,
            parentAlive: invalid.parentAlive,
            requireProcessGroupLeader: true,
            allowedCommandDigests: [launcherDigest, targetDigest],
          },
        ),
        false,
      );
    }
  });

  it('fails closed when live process-group identity cannot be recaptured', () => {
    const watchdog = readFileSync(
      join(process.cwd(), 'test', 'resource-watchdog.mjs'),
      'utf8',
    );
    assert.doesNotMatch(watchdog, /verifiedProcessGroupAssignments/);
    assert.match(
      watchdog,
      /pendingProcessGroupIdentities\.set\(assignmentKey, now\)[\s\S]*return 'pending';[\s\S]*now - pendingSince < processGroupIdentityGraceMs[\s\S]*return 'pending';[\s\S]*return 'unverified';/,
    );
    assert.match(
      watchdog,
      /status !== 'leader-exited'[\s\S]*throw new Error\(failureMessage\)/,
    );
  });

  it('removes watchdog state before making the receipt the final run event', () => {
    const watchdog = readFileSync(
      join(process.cwd(), 'test', 'resource-watchdog.mjs'),
      'utf8',
    );
    const finalizeStart = watchdog.indexOf(
      'function finalizeTerminalReceipt(state, options)',
    );
    const receiptStart = watchdog.indexOf(
      'function writeTerminalReceipt(state, {',
    );
    const finalizeSource = watchdog.slice(finalizeStart, receiptStart);
    assert.ok(finalizeStart >= 0);
    assert.ok(receiptStart > finalizeStart);
    assert.ok(
      finalizeSource.indexOf('removeStateFile(state)') <
        finalizeSource.indexOf('writeTerminalReceipt(state, {'),
    );
    assert.match(finalizeSource, /watchdog-state-removal-failure/);
    assert.match(finalizeSource, /success: stateRemoved && options\.success === true/);
  });

  it('rejects terminal audit records followed by another run event', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-terminal-audit-'));
    const auditPath = join(directory, 'audit.jsonl');
    const runId = 'terminal-audit-run';
    const accounting = {
      schemaVersion: 1,
      platform: process.platform,
      supported: false,
      available: true,
      currentBytes: 0,
      peakBytes: 0,
      observedProcessCount: 0,
      sampledProcessCount: 0,
      activeProcessGroupPid: null,
      topWriters: [],
    };
    const receipt = sealWatchdogReceipt({
      schemaVersion: 1,
      kind: 'resource-watchdog-terminal',
      runId,
      processWriteAccounting: accounting,
      outcome: 'completed',
      success: true,
      stateRemoved: true,
      detail: { resourceBreach: null },
    });
    const events = [
      {
        type: 'watchdog-process-write-summary',
        runId,
        outcome: 'completed',
        success: true,
        stateRemoved: true,
        processWriteAccounting: accounting,
      },
      {
        type: 'watchdog-terminal-receipt',
        runId,
        outcome: 'completed',
        success: true,
        stateRemoved: true,
        processWriteAccounting: accounting,
        contentHash: receipt.contentHash,
      },
    ];
    try {
      writeFileSync(
        auditPath,
        `${events.map((event) => JSON.stringify(event)).join('\n')}\n`,
      );
      assert.doesNotThrow(() => assertWatchdogTerminalAudit({
        auditPath,
        receipt,
        receiptPath: join(directory, 'unused-receipt.json'),
        runId,
      }));
      writeFileSync(
        auditPath,
        `${[
          ...events,
          { type: 'late-run-event', runId },
        ].map((event) => JSON.stringify(event)).join('\n')}\n`,
      );
      assert.throws(
        () => assertWatchdogTerminalAudit({
          auditPath,
          receipt,
          receiptPath: join(directory, 'unused-receipt.json'),
          runId,
        }),
        /was not the final durable run event/,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('reads the durable resource-breach record for runner diagnostics', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-watchdog-audit-read-'));
    const auditPath = join(directory, 'audit.jsonl');
    try {
      writeFileSync(
        auditPath,
        [
          JSON.stringify({ type: 'runner-start', runId: 'run-a' }),
          JSON.stringify({
            type: 'watchdog-resource-breach',
            runId: 'run-a',
            detail: {
              resourceProblem: {
                kind: 'system-disk-transfer',
                observedBytes: 3,
                limitBytes: 2,
              },
            },
          }),
          JSON.stringify({
            type: 'watchdog-resource-breach',
            runId: 'run-b',
          }),
          '',
        ].join('\n'),
      );
      assert.equal(
        latestWatchdogResourceBreach(auditPath, 'run-a')?.type,
        'watchdog-resource-breach',
      );
      assert.equal(
        latestWatchdogResourceBreach(auditPath, 'missing'),
        null,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects a timed-out child even when no exit event is emitted', async () => {
    const child = Object.assign(new EventEmitter(), {
      exitCode: null as number | null,
      signalCode: null as NodeJS.Signals | null,
      pid: undefined,
      signals: [] as NodeJS.Signals[],
      kill(signal: NodeJS.Signals = 'SIGTERM') {
        this.signals.push(signal);
        return true;
      },
    });
    const startedAt = Date.now();
    await assert.rejects(
      waitForChild(child, {
        label: 'silent child',
        timeoutMs: 25,
      }),
      /silent child exceeded the 25ms safety timeout/,
    );
    assert.ok(Date.now() - startedAt < 1_000);
    assert.deepEqual(child.signals, ['SIGTERM']);
  });

  it('runs cleanup steps independently and aggregates every failure', async () => {
    const errors: Error[] = [];
    const visited: string[] = [];
    await runCleanupStep(errors, 'first cleanup', () => {
      visited.push('first');
      throw new Error('first failed');
    });
    await runCleanupStep(errors, 'second cleanup', async () => {
      visited.push('second');
      throw new Error('second failed');
    });
    await runCleanupStep(errors, 'third cleanup', () => {
      visited.push('third');
    });

    assert.deepEqual(visited, ['first', 'second', 'third']);
    const combined = combineErrors(
      new Error('primary failed'),
      errors,
      'combined cleanup failure',
    );
    assert.ok(combined instanceof AggregateError);
    assert.equal(combined.errors.length, 3);
    assert.match(combined.errors[1].message, /first cleanup: first failed/);
    assert.match(combined.errors[2].message, /second cleanup: second failed/);
  });

  it('digests every safety-critical harness dependency', () => {
    for (const file of [
      'package-lock.json',
      'package.json',
      'src/lib/exclusiveProcessLock.ts',
      'test/database-guard-child-probe.cjs',
      'test/database-guard-runtime.cjs',
      'test/process-io-darwin.c',
      'test/process-io.mjs',
      'test/resource-watchdog.mjs',
      'test/test-suite-runner.mjs',
      'test/verify-database-guard.mjs',
      'tsconfig.json',
    ]) {
      assert.ok(safetyHarnessFiles.includes(file), `${file} must be digested`);
    }
  });

  it('binds production, helper, fixture, config, test, and dependency inputs', () => {
    const repositoryRoot =
      mkdtempSync(join(tmpdir(), 'radar-execution-identity-'));
    const inputs = [
      ['src/index.ts', 'export const production = true;\n'],
      ['helpers/runner-helper.mjs', 'export const helper = true;\n'],
      ['fixtures/release.json', '{"fixture":true}\n'],
      ['config/runtime.json', '{"mode":"test"}\n'],
      ['scripts/task.mjs', 'export const task = true;\n'],
      ['test/example.test.ts', 'export const testInput = true;\n'],
      ['node_modules/example/index.js', 'module.exports = true;\n'],
      ['package.json', '{"name":"identity-fixture"}\n'],
      ['package-lock.json', '{"lockfileVersion":3}\n'],
      ['tsconfig.json', '{"compilerOptions":{}}\n'],
    ] as const;
    try {
      for (const [file, contents] of inputs) {
        const path = join(repositoryRoot, file);
        mkdirSync(resolve(path, '..'), { recursive: true });
        writeFileSync(path, contents);
      }
      mkdirSync(join(repositoryRoot, 'test'), { recursive: true });
      writeFileSync(
        join(repositoryRoot, 'test', 'test-baseline.json'),
        '{"accepted":true}\n',
      );
      writeFileSync(
        join(repositoryRoot, 'test', 'test-baseline.candidate.json'),
        '{"candidate":true}\n',
      );

      const discovered = discoverExecutionInputFiles({ repositoryRoot });
      assert.deepEqual(discovered, inputs.map(([file]) => file).sort());
      const initial = captureExecutionInputIdentity({ repositoryRoot });
      assert.deepEqual(initial.files, discovered);

      for (const [file, contents] of inputs) {
        const path = join(repositoryRoot, file);
        writeFileSync(path, `${contents}changed\n`);
        assert.notEqual(
          captureExecutionInputIdentity({ repositoryRoot }).digest,
          initial.digest,
          `${file} must affect execution identity`,
        );
        writeFileSync(path, contents);
      }
      assert.equal(
        captureExecutionInputIdentity({ repositoryRoot }).digest,
        initial.digest,
      );
    } finally {
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  it('excludes only the exact atomic-write transient from execution identity', () => {
    const repositoryRoot =
      mkdtempSync(join(tmpdir(), 'radar-execution-transient-'));
    const testDirectory = join(repositoryRoot, 'test');
    const stableInput = join(testDirectory, 'example.test.ts');
    const transient = join(
      testDirectory,
      '.test-baseline.candidate.json.123.exact.tmp',
    );
    const similarlyNamedSibling = join(
      testDirectory,
      '.test-baseline.candidate.json.123.sibling.tmp',
    );
    try {
      mkdirSync(testDirectory, { recursive: true });
      writeFileSync(stableInput, 'export const stable = true;\n');
      const initial = captureExecutionInputIdentity({ repositoryRoot });

      writeFileSync(transient, '{"candidate":true}\n');
      const withoutExactTransient = captureExecutionInputIdentity({
        excludedPath: transient,
        repositoryRoot,
      });
      assert.equal(withoutExactTransient.digest, initial.digest);
      assert.doesNotMatch(
        withoutExactTransient.files.join('\n'),
        /exact\.tmp/,
      );

      writeFileSync(similarlyNamedSibling, '{"candidate":false}\n');
      const withSibling = captureExecutionInputIdentity({
        excludedPath: transient,
        repositoryRoot,
      });
      assert.notEqual(withSibling.digest, initial.digest);
      assert.ok(
        withSibling.files.includes(
          'test/.test-baseline.candidate.json.123.sibling.tmp',
        ),
      );
    } finally {
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  it('guards direct filesystem writes and defaults child executables to deny', () => {
    const guard = readFileSync(
      join(process.cwd(), 'test', 'database-guard-runtime.cjs'),
      'utf8',
    );
    for (const mutation of [
      'fs.writeFile =',
      'fs.writeFileSync =',
      'fs.write =',
      'fs.writeSync =',
      'fs.writev =',
      'fs.writevSync =',
      'fsPromises.writeFile =',
      'fsPromises.open = async function guardedPromiseOpen',
      'installFileHandleGuards(handle)',
    ]) {
      assert.ok(guard.includes(mutation), `${mutation} must be guarded`);
    }
    assert.match(
      guard,
      /const exact = allowedExecutableIdentities\.find[\s\S]*const root = executableRoots\.find[\s\S]*child executable is not allowlisted/,
    );
    assert.match(
      guard,
      /isTaskpolicyExecutable[\s\S]*assertTaskpolicyCommand[\s\S]*taskpolicy only supports the audited -b <command> form/,
    );
    assert.match(
      guard,
      /isNiceExecutable[\s\S]*assertNiceCommand[\s\S]*nice only supports the audited -n 15 <command> form/,
    );
    const runner = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    assert.match(runner, /'\/usr\/bin\/nice'/);
    assert.match(runner, /'\/usr\/sbin\/taskpolicy'/);
    assert.match(guard, /installFilesystemGuards\(\);/);
  });

  it('blocks a second suite while held and permits acquisition after release', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-suite-lock-test-'));
    const lockPath = join(directory, 'suite.lock.sqlite');
    let first: ReturnType<AcquireTestSuiteLock> | null = null;
    let second: ReturnType<AcquireTestSuiteLock> | null = null;
    try {
      first = acquireTestSuiteLock({
        lockPath,
        pid: 101,
        startedAt: '2026-07-04T16:00:00.000Z',
        registerExitHandler: false,
      });
      assert.doesNotThrow(() => assertExclusiveProcessLockContended({
        lockPath,
        resourceLabel: 'authoritative test suite',
      }));
      assert.throws(
        () => acquireTestSuiteLock({
          lockPath,
          pid: 202,
          registerExitHandler: false,
        }),
        /already holds the authoritative test suite/i,
      );
      first.release();
      first = null;
      assert.throws(
        () => assertExclusiveProcessLockContended({
          lockPath,
          resourceLabel: 'authoritative test suite',
        }),
        /not currently (?:contended|held|locked)/i,
      );

      second = acquireTestSuiteLock({
        lockPath,
        pid: 202,
        registerExitHandler: false,
      });
      assert.equal(second.path, lockPath);
    } finally {
      second?.release();
      first?.release();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('does not let malformed owner metadata bypass transaction authority', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-writer-lock-test-'));
    const lockPath = join(directory, 'writer.lock.sqlite');
    let first: ReturnType<typeof acquireExclusiveProcessLock> | null = null;
    let successor: ReturnType<typeof acquireExclusiveProcessLock> | null = null;
    try {
      first = acquireExclusiveProcessLock({
        lockPath,
        label: 'first writer',
        resourceLabel: 'database writer',
        pid: 101,
        startedAt: '2026-07-04T16:00:00.000Z',
        registerExitHandler: false,
      });
      assert.throws(
        () => acquireExclusiveProcessLock({
          lockPath,
          label: 'competing writer',
          resourceLabel: 'database writer',
          pid: 202,
          registerExitHandler: false,
        }),
        /already holds the database writer/,
      );

      writeFileSync(`${lockPath}.owner.json`, '{ malformed metadata\n');
      assert.throws(
        () => acquireExclusiveProcessLock({
          lockPath,
          label: 'metadata bypass attempt',
          resourceLabel: 'database writer',
          pid: 202,
          registerExitHandler: false,
        }),
        /already holds the database writer/,
      );

      first.release();
      first = null;
      successor = acquireExclusiveProcessLock({
        lockPath,
        label: 'successor writer',
        resourceLabel: 'database writer',
        pid: 202,
        registerExitHandler: false,
      });
      assert.throws(
        () => acquireExclusiveProcessLock({
          lockPath,
          label: 'third writer',
          resourceLabel: 'database writer',
          pid: 303,
          registerExitHandler: false,
        }),
        /already holds the database writer/,
      );
    } finally {
      successor?.release();
      first?.release();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('keeps the permanent guard inode stable across lock lifetimes', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-guard-inode-test-'));
    const lockPath = join(directory, 'guard.lock.sqlite');
    let first: ReturnType<typeof acquireExclusiveProcessLock> | null = null;
    let second: ReturnType<typeof acquireExclusiveProcessLock> | null = null;
    try {
      first = acquireExclusiveProcessLock({
        lockPath,
        label: 'first owner',
        registerExitHandler: false,
      });
      const initial = statSync(lockPath);
      first.release();
      first = null;

      const released = statSync(lockPath);
      second = acquireExclusiveProcessLock({
        lockPath,
        label: 'second owner',
        registerExitHandler: false,
      });
      const reacquired = statSync(lockPath);
      assert.deepEqual(
        [released.dev, released.ino],
        [initial.dev, initial.ino],
      );
      assert.deepEqual(
        [reacquired.dev, reacquired.ino],
        [initial.dev, initial.ino],
      );
    } finally {
      second?.release();
      first?.release();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('derives a stable repository-scoped database writer lock path', () => {
    const first = repositoryDatabaseWriterLockPath('/tmp/radar-one');
    assert.equal(first, repositoryDatabaseWriterLockPath('/tmp/radar-one'));
    assert.notEqual(first, repositoryDatabaseWriterLockPath('/tmp/radar-two'));
  });

  it('canonicalizes repository identity across symlink aliases', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-repo-identity-test-'));
    const repository = join(directory, 'repository');
    const alias = join(directory, 'alias');
    try {
      writeFileSync(join(directory, 'placeholder'), '');
      symlinkSync(directory, repository);
      symlinkSync(repository, alias);
      assert.equal(
        canonicalRepositoryIdentity(repository),
        canonicalRepositoryIdentity(alias),
      );
      assert.equal(
        testRootPrefixForRepository(repository),
        testRootPrefixForRepository(alias),
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('scavenges only stale roots whose recorded owner is dead', () => {
    const tempDirectory =
      mkdtempSync(join(tmpdir(), 'radar-orphan-scavenge-test-'));
    const repository =
      mkdtempSync(join(tmpdir(), 'radar-orphan-repository-test-'));
    const now = Date.parse('2026-07-05T12:00:00.000Z');
    const prefix = testRootPrefixForRepository(repository);
    const deadPid = 2_147_483_647;
    const makeRoot = (
      label: string,
      parentPid: number,
      heartbeatAt: string,
      runId = label,
    ) => {
      const path = mkdtempSync(join(tempDirectory, `${prefix}${label}-`));
      writeFileSync(
        join(path, '.runner-owner.json'),
        `${JSON.stringify({
          schemaVersion: 1,
          repositoryIdentity: canonicalRepositoryIdentity(repository),
          repositoryRoot: resolve(repository),
          runId,
          parentPid,
          heartbeatAt,
          completed: false,
        })}\n`,
      );
      return path;
    };
    try {
      const staleRunId = 'stale-run';
      const staleDead = makeRoot(
        'stale-dead',
        deadPid,
        '2026-07-05T11:00:00.000Z',
        staleRunId,
      );
      const staleControl = makeRoot(
        'controls-stale-dead',
        deadPid,
        '2026-07-05T11:00:00.000Z',
        staleRunId,
      );
      const staleLive = makeRoot(
        'stale-live',
        process.pid,
        '2026-07-05T11:00:00.000Z',
      );
      const freshDead = makeRoot(
        'fresh-dead',
        deadPid,
        '2026-07-05T11:59:59.500Z',
      );

      const removed = scavengeOrphanedTestRoots({
        repositoryRoot: repository,
        tempDirectory,
        now,
        staleHeartbeatMs: 1_000,
      });
      assert.deepEqual(
        new Set(removed),
        new Set([staleDead, staleControl]),
      );
      assert.equal(existsSync(staleDead), false);
      assert.equal(existsSync(staleControl), false);
      assert.equal(existsSync(staleLive), true);
      assert.equal(existsSync(freshDead), true);
    } finally {
      rmSync(tempDirectory, { recursive: true, force: true });
      rmSync(repository, { recursive: true, force: true });
    }
  });

  it('separates stable pathname locks from shared inode locks', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-file-identity-test-'));
    const original = join(directory, 'original.db');
    const symlink = join(directory, 'symlink.db');
    const hardlink = join(directory, 'hardlink.db');
    try {
      const pathLockBeforeCreation =
        databaseInitializationLockPath(original);
      writeFileSync(original, 'database');
      symlinkSync(original, symlink);
      linkSync(original, hardlink);

      assert.equal(pathsReferToSameFile(original, symlink), true);
      assert.equal(pathsReferToSameFile(original, hardlink), true);
      assert.equal(
        pathLockBeforeCreation,
        databaseInitializationLockPath(original),
      );
      assert.notEqual(
        databaseInitializationLockPath(original),
        databaseInitializationLockPath(symlink),
      );
      assert.notEqual(
        databaseInitializationLockPath(original),
        databaseInitializationLockPath(hardlink),
      );
      assert.equal(
        databaseFileInitializationLockPath(original),
        databaseFileInitializationLockPath(symlink),
      );
      assert.equal(
        databaseFileInitializationLockPath(original),
        databaseFileInitializationLockPath(hardlink),
      );
      assert.equal(
        pathsReferToSameFile(original, join(directory, 'missing.db')),
        false,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe('test runner live database family immutability', () => {
  const members = [
    { label: 'main', suffix: '' },
    { label: 'WAL', suffix: '-wal' },
    { label: 'SHM', suffix: '-shm' },
    { label: 'rollback journal', suffix: '-journal' },
  ];

  for (const member of members) {
    it(`detects ${member.label} content and size mutations`, () => {
      const directory = mkdtempSync(join(tmpdir(), 'radar-family-test-'));
      const databasePath = join(directory, 'radar.db');
      const memberPath = `${databasePath}${member.suffix}`;
      try {
        for (const candidate of members) {
          writeFileSync(`${databasePath}${candidate.suffix}`, 'alpha');
        }

        const beforeContentMutation =
          captureSqliteFamilyFingerprint(databasePath);
        writeFileSync(memberPath, 'bravo');
        assertFamilyMutationReported(
          databasePath,
          beforeContentMutation,
          memberPath,
        );

        const beforeSizeMutation =
          captureSqliteFamilyFingerprint(databasePath);
        writeFileSync(memberPath, 'charlie');
        assertFamilyMutationReported(
          databasePath,
          beforeSizeMutation,
          memberPath,
        );
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    });

    it(`detects ${member.label} creation and removal`, () => {
      const directory = mkdtempSync(join(tmpdir(), 'radar-family-test-'));
      const databasePath = join(directory, 'radar.db');
      const memberPath = `${databasePath}${member.suffix}`;
      try {
        const beforeCreation = captureSqliteFamilyFingerprint(databasePath);
        writeFileSync(memberPath, 'created');
        assertFamilyMutationReported(
          databasePath,
          beforeCreation,
          memberPath,
        );

        const beforeRemoval = captureSqliteFamilyFingerprint(databasePath);
        rmSync(memberPath);
        assertFamilyMutationReported(
          databasePath,
          beforeRemoval,
          memberPath,
        );
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    });
  }

  it('detects same-content inode replacement', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-family-inode-test-'));
    const databasePath = join(directory, 'radar.db');
    try {
      writeFileSync(databasePath, 'same content');
      const before = captureSqliteFamilyFingerprint(databasePath);
      rmSync(databasePath);
      writeFileSync(databasePath, 'same content');
      assertFamilyMutationReported(databasePath, before, databasePath);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects symlink members instead of following them', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-family-symlink-test-'));
    const target = join(directory, 'target.db');
    const databasePath = join(directory, 'radar.db');
    try {
      writeFileSync(target, 'live data');
      symlinkSync(target, databasePath);
      assert.throws(
        () => captureSqliteFamilyFingerprint(databasePath),
        /not one no-follow regular file/,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects hard-linked members instead of trusting path-only isolation', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-family-hardlink-test-'));
    const target = join(directory, 'target.db');
    const databasePath = join(directory, 'radar.db');
    try {
      writeFileSync(target, 'live data');
      linkSync(target, databasePath);
      assert.throws(
        () => captureSqliteFamilyFingerprint(databasePath),
        /not one no-follow regular file/,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe('resource watchdog ownership', () => {
  it('runs ps identity telemetry in a detached process group', () => {
    let invocation: {
      command: string;
      args: string[];
      options: Record<string, unknown>;
    } | null = null;
    const identity = captureProcessIdentity(4242, {
      platform: 'darwin',
      run(command, args, options) {
        invocation = { command, args, options };
        return {
          status: 0,
          signal: null,
          stdout:
            '4242 1 4242 Sun Jul  5 17:01:45 2026 /usr/bin/node\n',
        };
      },
    });

    assert.ok(identity);
    assert.ok(invocation);
    assert.equal(invocation.command, '/bin/ps');
    assert.deepEqual(invocation.args, [
      '-p',
      '4242',
      '-o',
      'pid=,ppid=,pgid=,lstart=,comm=',
    ]);
    assert.equal(invocation.options.encoding, 'utf8');
    assert.equal(invocation.options.timeout, 2_000);
    assert.equal(invocation.options.detached, true);
    assert.deepEqual(invocation.options.stdio, ['ignore', 'pipe', 'ignore']);
    assert.equal(invocation.options.env, undefined);
  });

  it('acknowledges readiness before returning control to the runner', async () => {
    const tempRoot = mkdtempSync(join(tmpdir(), 'radar-watchdog-ready-test-'));
    const controlRoot =
      mkdtempSync(join(tmpdir(), 'radar-watchdog-control-test-'));
    const auditRoot = mkdtempSync(join(tmpdir(), 'radar-watchdog-audit-test-'));
    const runId = `watchdog-ready-${process.pid}-${Date.now()}`;
    const auditPath = join(auditRoot, `${runId}.jsonl`);
    const tempRootOwnerPath = join(tempRoot, '.runner-owner.json');
    const controlRootOwnerPath = join(controlRoot, '.runner-owner.json');
    writeFileSync(auditPath, '', { mode: 0o600 });
    let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
    try {
      watchdog = await startResourceWatchdog({
        runId,
        tempRoot,
        tempRootOwnerPath,
        additionalOwnerPaths: [controlRootOwnerPath],
        auditPath,
        auditRoot,
        systemDiskTransferBaselineBytes: null,
        limits: {
          maximumWorkerBytes: 1024 * 1024,
          maximumSuiteBytes: 1024 * 1024,
          maximumSqliteBytes: 1024 * 1024,
          maximumProcessWriteBytes: 4096 * 1024 * 1024,
          maximumSystemDiskTransferBytes: 4096 * 1024 * 1024,
          minimumStartingFreeBytes: 0,
          minimumRuntimeFreeBytes: 0,
        },
        repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
        repositoryRoot: process.cwd(),
      });
      assert.equal(watchdog.ready, true);
      const activeTempOwner =
        JSON.parse(readFileSync(tempRootOwnerPath, 'utf8'));
      const activeControlOwner =
        JSON.parse(readFileSync(controlRootOwnerPath, 'utf8'));
      assert.deepEqual(activeControlOwner, activeTempOwner);
      assert.equal(activeTempOwner.runId, runId);
      assert.equal(activeTempOwner.parentPid, process.pid);
      assert.equal(activeTempOwner.completed, false);
      const receipt = await watchdog.complete({ preserveTempRoot: false });
      const completedTempOwner =
        JSON.parse(readFileSync(tempRootOwnerPath, 'utf8'));
      const completedControlOwner =
        JSON.parse(readFileSync(controlRootOwnerPath, 'utf8'));
      assert.deepEqual(completedControlOwner, completedTempOwner);
      assert.equal(completedTempOwner.runId, runId);
      assert.equal(completedTempOwner.parentPid, process.pid);
      assert.equal(completedTempOwner.completed, true);
      assert.equal(receipt.outcome, 'completed');
      assert.equal(receipt.success, true);
      assert.equal(receipt.stateRemoved, true);
      assert.equal(receipt.receiptPath, watchdog.receiptPath);
      assert.equal(existsSync(watchdog.receiptPath), true);
      const terminalEvents = readFileSync(auditPath, 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      assert.equal(terminalEvents.at(-1)?.type, 'watchdog-terminal-receipt');
      watchdog = null;
      assert.equal(
        existsSync(join(auditRoot, `${runId}.watchdog.json`)),
        false,
      );
    } finally {
      watchdog?.abandon();
      rmSync(tempRoot, { recursive: true, force: true });
      rmSync(controlRoot, { recursive: true, force: true });
      rmSync(auditRoot, { recursive: true, force: true });
    }
  });

  it(
    'rejects tampered watchdog state without signaling the owned process group',
    {
      skip: process.platform === 'win32',
      timeout: 10_000,
    },
    async () => {
      const tempRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-tamper-test-'));
      const auditRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-tamper-audit-test-'));
      const runId = `watchdog-tamper-${process.pid}-${Date.now()}`;
      const auditPath = join(auditRoot, `${runId}.jsonl`);
      const statePath = join(auditRoot, `${runId}.watchdog.json`);
      writeFileSync(auditPath, '', { mode: 0o600 });
      const victim = spawn(
        process.execPath,
        ['-e', "process.send?.('ready');setInterval(()=>{},1000);"],
        {
          detached: true,
          env: {
            ...process.env,
            RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-victim',
          },
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        },
      );
      let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
      try {
        await waitForMessage(victim, 'ready', 2_000);
        victim.disconnect();
        watchdog = await startResourceWatchdog({
          runId,
          tempRoot,
          auditPath,
          auditRoot,
          systemDiskTransferBaselineBytes: null,
          limits: {
            maximumWorkerBytes: 1024 * 1024,
            maximumSuiteBytes: 1024 * 1024,
            maximumSqliteBytes: 1024 * 1024,
            maximumProcessWriteBytes: 4096 * 1024 * 1024,
            maximumSystemDiskTransferBytes: 4096 * 1024 * 1024,
            minimumStartingFreeBytes: 0,
            minimumRuntimeFreeBytes: 0,
          },
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
        });
        watchdog.setActiveProcessGroup(victim.pid!);
        const state = JSON.parse(readFileSync(statePath, 'utf8'));
        state.parentPid = 1;
        writeFileSync(statePath, `${JSON.stringify(state)}\n`, {
          mode: 0o600,
        });
        const watchdogFailure = await withTimeout(
          watchdog.failure,
          2_000,
          'tampered watchdog did not fail closed',
        );
        assert.match(watchdogFailure.message, /exited before completion/);
        assert.doesNotThrow(() => process.kill(process.pid, 0));
        assert.doesNotThrow(() => process.kill(victim.pid!, 0));
        assert.equal(existsSync(watchdog.receiptPath), false);
        watchdog.abandon();
        watchdog = null;
      } finally {
        watchdog?.abandon();
        if (victim.pid) {
          try {
            process.kill(-victim.pid, 'SIGKILL');
          } catch {
            // The victim remains alive when the watchdog fails closed.
          }
        }
        rmSync(tempRoot, { recursive: true, force: true });
        rmSync(auditRoot, { recursive: true, force: true });
      }
    },
  );

  it(
    'terminates only the verified group when completion finds live children',
    {
      skip: process.platform === 'win32',
      timeout: 15_000,
    },
    async () => {
      const tempRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-live-group-test-'));
      const auditRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-live-group-audit-test-'));
      const runId = `watchdog-live-group-${process.pid}-${Date.now()}`;
      const statePath = join(auditRoot, `${runId}.watchdog.json`);
      const auditPath = join(auditRoot, `${runId}.jsonl`);
      const receiptPath =
        join(auditRoot, `${runId}.watchdog-receipt.json`);
      const ownerPath = join(tempRoot, '.runner-owner.json');
      const token = 'a'.repeat(64);
      writeFileSync(auditPath, '', { mode: 0o600 });
      const parent = spawn(
        process.execPath,
        ['-e', "process.send?.('ready');setInterval(()=>{},1000);"],
        {
          env: {
            ...process.env,
            RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-parent',
          },
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        },
      );
      const victim = spawn(
        process.execPath,
        [
          '-e',
          "process.on('SIGTERM',()=>{});" +
          "process.send?.('ready');setInterval(()=>{},1000);",
        ],
        {
          detached: true,
          env: {
            ...process.env,
            RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-victim',
          },
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        },
      );
      let watchdogProcess: ReturnType<typeof spawn> | null = null;
      try {
        await waitForMessage(parent, 'ready', 2_000);
        await waitForMessage(victim, 'ready', 2_000);
        const victimExit = once(victim, 'exit');
        parent.disconnect();
        victim.disconnect();
        const parentIdentity = captureProcessIdentity(parent.pid!);
        const processGroupIdentity = captureProcessIdentity(victim.pid!);
        assert.ok(parentIdentity);
        assert.ok(processGroupIdentity);
        writeFileSync(ownerPath, `${JSON.stringify({
          schemaVersion: 1,
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
          runId,
          parentPid: parent.pid,
          heartbeatAt: new Date().toISOString(),
          completed: true,
        })}\n`, { mode: 0o600 });
        const state = sealWatchdogState({
          schemaVersion: 2,
          runId,
          parentPid: parent.pid,
          parentIdentity,
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
          auditRoot,
          auditRootIdentity: capturePathIdentity(auditRoot),
          tempRoot,
          tempRootIdentity: capturePathIdentity(tempRoot),
          tempRootOwnerPath: ownerPath,
          auditPath,
          auditPathIdentity: capturePathIdentity(auditPath),
          receiptPath,
          heartbeatAt: new Date().toISOString(),
          activeProcessGroupPid: victim.pid,
          activeProcessGroupIdentity: processGroupIdentity,
          completed: true,
          preserveTempRoot: true,
          limits: {
            maximumWorkerBytes: 1024 * 1024,
            maximumSuiteBytes: 1024 * 1024,
            maximumSqliteBytes: 1024 * 1024,
            maximumProcessWriteBytes: 4096 * 1024 * 1024,
            maximumSystemDiskTransferBytes: 4096 * 1024 * 1024,
            minimumStartingFreeBytes: 0,
            minimumRuntimeFreeBytes: 0,
          },
          systemDiskTransferBaselineBytes: null,
        }, token);
        writeFileSync(statePath, `${JSON.stringify(state)}\n`, {
          mode: 0o600,
        });
        watchdogProcess = spawn(
          process.execPath,
          [join(process.cwd(), 'test', 'resource-watchdog.mjs'), statePath],
          {
            env: {
              ...process.env,
              RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog',
              RADAR_TEST_WATCHDOG_REPOSITORY_IDENTITY:
                canonicalRepositoryIdentity(process.cwd()),
              RADAR_TEST_WATCHDOG_RUN_ID: runId,
              RADAR_TEST_WATCHDOG_STATE_PATH: statePath,
              RADAR_TEST_WATCHDOG_TOKEN: token,
            },
            stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
          },
        );
        const watchdogExit = once(watchdogProcess, 'exit');
        await waitForWatchdogMessage(
          watchdogProcess,
          runId,
          statePath,
          2_000,
        );
        const [victimCode, victimSignal] = await withTimeout(
          victimExit,
          8_000,
          'completed watchdog did not terminate its live process group',
        );
        assert.equal(victimCode, null);
        assert.equal(victimSignal, 'SIGKILL');
        const [watchdogCode, watchdogSignal] = await withTimeout(
          watchdogExit,
          2_000,
          'completed watchdog did not persist its terminal receipt',
        );
        watchdogProcess = null;
        assert.equal(watchdogCode, 1);
        assert.equal(watchdogSignal, null);
        assert.doesNotThrow(() => process.kill(parent.pid!, 0));
        const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
        assert.equal(verifyWatchdogReceiptSeal(receipt), true);
        assert.equal(receipt.outcome, 'completed-with-live-process-group');
        assert.equal(receipt.success, false);
        assert.equal(
          receipt.detail?.termination?.processWriteAccounting?.supported,
          process.platform === 'darwin',
        );
        assert.ok(
          Number.isFinite(
            receipt.detail?.termination?.processWriteAccounting?.currentBytes,
          ),
        );
      } finally {
        parent.kill('SIGKILL');
        if (victim.pid) {
          try {
            process.kill(-victim.pid, 'SIGKILL');
          } catch {
            // The watchdog should already have terminated the victim.
          }
        }
        watchdogProcess?.kill('SIGKILL');
        rmSync(tempRoot, { recursive: true, force: true });
        rmSync(auditRoot, { recursive: true, force: true });
      }
    },
  );

  it(
    'continues through an authenticated same-process command transition',
    {
      skip: process.platform === 'win32',
      timeout: 15_000,
    },
    async () => {
      const tempRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-exec-test-'));
      const auditRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-exec-audit-test-'));
      const runId = `watchdog-exec-${process.pid}-${Date.now()}`;
      const auditPath = join(auditRoot, `${runId}.jsonl`);
      const transitionedTitle = 'radar-phase';
      writeFileSync(auditPath, '', { mode: 0o600 });
      const victim = spawn(
        process.execPath,
        [
          '-e',
          `
            process.send?.('ready');
            process.on('message', (message) => {
              if (message !== 'transition') return;
              process.title = ${JSON.stringify(transitionedTitle)};
              process.send?.('transitioned');
            });
            setInterval(() => {}, 1000);
          `,
        ],
        {
          detached: true,
          env: {
            ...process.env,
            RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-victim',
          },
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        },
      );
      let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
      try {
        await waitForMessage(victim, 'ready', 2_000);
        watchdog = await startResourceWatchdog({
          runId,
          tempRoot,
          auditPath,
          auditRoot,
          systemDiskTransferBaselineBytes: null,
          limits: {
            maximumWorkerBytes: mebibyte,
            maximumSuiteBytes: mebibyte,
            maximumSqliteBytes: mebibyte,
            maximumProcessWriteBytes: 4096 * mebibyte,
            maximumSystemDiskTransferBytes: 4096 * mebibyte,
            minimumStartingFreeBytes: 0,
            minimumRuntimeFreeBytes: 0,
          },
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
        });
        watchdog.setActiveProcessGroup(victim.pid!, {
          allowedCommandDigests: [sha256Text(transitionedTitle)],
        });
        victim.send('transition');
        await waitForMessage(victim, 'transitioned', 2_000);
        await waitForCondition(
          () => readFileSync(auditPath, 'utf8').includes(
            '"type":"watchdog-process-group-command-transition"',
          ),
          2_000,
          'watchdog did not authenticate the process command transition',
        );
        assert.doesNotMatch(
          readFileSync(auditPath, 'utf8'),
          /"type":"watchdog-failure"/,
        );

        const victimExit = once(victim, 'exit');
        process.kill(-victim.pid!, 'SIGTERM');
        const [victimCode, victimSignal] = await withTimeout(
          victimExit,
          2_000,
          'transitioned process group did not exit',
        );
        assert.equal(victimCode, null);
        assert.equal(victimSignal, 'SIGTERM');
        await new Promise((resolvePromise) => {
          setTimeout(resolvePromise, 750);
        });
        assert.doesNotMatch(
          readFileSync(auditPath, 'utf8'),
          /"type":"watchdog-failure"/,
        );
        watchdog.setActiveProcessGroup(null);
        const receipt = await watchdog.complete({
          preserveTempRoot: false,
        });
        assert.equal(receipt.outcome, 'completed');
        assert.equal(receipt.success, true);
        watchdog = null;
      } finally {
        if (victim.pid) {
          try {
            process.kill(-victim.pid, 'SIGKILL');
          } catch {
            // The process group should already be gone.
          }
        }
        watchdog?.abandon();
        rmSync(tempRoot, { recursive: true, force: true });
        rmSync(auditRoot, { recursive: true, force: true });
      }
    },
  );

  it(
    'continues accounting and safely terminates an authenticated group after its leader exits',
    {
      skip: process.platform === 'win32',
      timeout: 15_000,
    },
    async () => {
      const tempRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-leader-exit-test-'));
      const auditRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-leader-exit-audit-test-'));
      const runId = `watchdog-leader-exit-${process.pid}-${Date.now()}`;
      const auditPath = join(auditRoot, `${runId}.jsonl`);
      writeFileSync(auditPath, '', { mode: 0o600 });
      const leader = spawn(
        process.execPath,
        [
          '-e',
          `
            const { spawn } = require('node:child_process');
            const child = spawn(
              process.execPath,
              ['-e', 'setInterval(() => {}, 1000)'],
              { stdio: 'ignore' },
            );
            child.once('spawn', () => {
              process.send?.({ type: 'child-ready', pid: child.pid });
            });
            process.on('message', (message) => {
              if (message === 'exit-leader') process.exit(0);
            });
            setInterval(() => {}, 1000);
          `,
        ],
        {
          detached: true,
          env: {
            ...process.env,
            RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-victim',
          },
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        },
      );
      let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
      try {
        const [message] = await withTimeout(
          once(leader, 'message'),
          2_000,
          'process-group child was not started',
        );
        assert.equal(
          typeof message === 'object' && message !== null
            ? (message as { type?: string }).type
            : null,
          'child-ready',
        );
        const childPid = (message as { pid?: number }).pid;
        assert.ok(Number.isInteger(childPid) && childPid! > 0);
        const leaderExit = once(leader, 'exit');
        watchdog = await startResourceWatchdog({
          runId,
          tempRoot,
          auditPath,
          auditRoot,
          systemDiskTransferBaselineBytes: null,
          limits: {
            maximumWorkerBytes: mebibyte,
            maximumSuiteBytes: mebibyte,
            maximumSqliteBytes: 1024 * 1024,
            maximumProcessWriteBytes: 4096 * mebibyte,
            maximumSystemDiskTransferBytes: 4096 * mebibyte,
            minimumStartingFreeBytes: 0,
            minimumRuntimeFreeBytes: 0,
          },
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
        });
        watchdog.setActiveProcessGroup(leader.pid!);
        leader.send('exit-leader');
        const [leaderCode, leaderSignal] = await withTimeout(
          leaderExit,
          2_000,
          'process-group leader did not exit',
        );
        assert.equal(leaderCode, 0);
        assert.equal(leaderSignal, null);
        assert.doesNotThrow(() => process.kill(childPid!, 0));
        await waitForCondition(
          () => readFileSync(auditPath, 'utf8').includes(
            '"type":"watchdog-process-group-leader-exited"',
          ),
          2_000,
          'watchdog did not recognize the leaderless process group',
        );
        assert.doesNotMatch(
          readFileSync(auditPath, 'utf8'),
          /"type":"watchdog-failure"/,
        );

        writeFileSync(
          join(tempRoot, 'leaderless-breach.bin'),
          Buffer.alloc(2 * mebibyte),
        );
        await waitForCondition(
          () => {
            try {
              process.kill(-leader.pid!, 0);
              return false;
            } catch (error) {
              return (error as NodeJS.ErrnoException).code === 'ESRCH';
            }
          },
          8_000,
          'watchdog did not terminate the leaderless process group',
        );
        await waitForCondition(
          () => readFileSync(auditPath, 'utf8').includes(
            '"type":"watchdog-process-group-termination-confirmed"',
          ),
          2_000,
          'watchdog did not confirm leaderless process-group termination',
        );
        const audit = readFileSync(auditPath, 'utf8');
        assert.match(
          audit,
          /"type":"watchdog-process-group-termination-confirmed"/,
        );
        assert.match(audit, /"cause":"resource-breach"/);
        assert.doesNotMatch(audit, /"type":"watchdog-signal-failure"/);
        watchdog.setActiveProcessGroup(null);
        await assert.rejects(
          watchdog.complete({ preserveTempRoot: true }),
          /terminal state is unsafe: suite-footprint/,
        );
        const receipt = JSON.parse(
          readFileSync(watchdog.receiptPath, 'utf8'),
        );
        assert.equal(verifyWatchdogReceiptSeal(receipt), true);
        assert.equal(receipt.outcome, 'resource-breach');
        assert.equal(receipt.success, false);
        assert.equal(receipt.stateRemoved, true);
        assert.equal(
          (receipt.detail as {
            resourceBreach?: {
              resourceProblem?: { kind?: string };
            };
          }).resourceBreach?.resourceProblem?.kind,
          'suite-footprint',
        );
        watchdog = null;
      } finally {
        if (leader.pid) {
          try {
            process.kill(-leader.pid, 'SIGKILL');
          } catch {
            // The test drains the process group before watchdog completion.
          }
        }
        watchdog?.abandon();
        rmSync(tempRoot, { recursive: true, force: true });
        rmSync(auditRoot, { recursive: true, force: true });
      }
    },
  );

  it(
    'tolerates worker directories removed during resource inspection',
    {
      skip: process.platform === 'win32',
      timeout: 15_000,
    },
    async () => {
      const tempRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-churn-test-'));
      const auditRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-churn-audit-test-'));
      const runId = `watchdog-churn-${process.pid}-${Date.now()}`;
      const auditPath = join(auditRoot, `${runId}.jsonl`);
      const externalTarget = join(auditRoot, 'external-target.bin');
      writeFileSync(auditPath, '', { mode: 0o600 });
      writeFileSync(externalTarget, Buffer.alloc(2 * 1024 * 1024));
      symlinkSync(externalTarget, join(tempRoot, 'external-target-link'));
      let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
      try {
        watchdog = await startResourceWatchdog({
          runId,
          tempRoot,
          auditPath,
          auditRoot,
          systemDiskTransferBaselineBytes: null,
          limits: {
            maximumWorkerBytes: 1024 * 1024,
            maximumSuiteBytes: 1024 * 1024,
            maximumSqliteBytes: 1024 * 1024,
            maximumProcessWriteBytes: 4096 * 1024 * 1024,
            maximumSystemDiskTransferBytes: 4096 * 1024 * 1024,
            minimumStartingFreeBytes: 0,
            minimumRuntimeFreeBytes: 0,
          },
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
        });
        for (let index = 0; index < 2_000; index++) {
          const workerRoot = join(tempRoot, `worker-churn-${index % 8}`);
          const directory = join(workerRoot, `nested-${index}`);
          mkdirSync(directory, { recursive: true });
          writeFileSync(join(directory, 'payload.bin'), 'temporary');
          rmSync(workerRoot, { recursive: true, force: true });
          if (index % 25 === 0) {
            await new Promise((resolvePromise) => setImmediate(resolvePromise));
          }
        }
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
        assert.equal(
          readFileSync(auditPath, 'utf8').includes(
            '"type":"watchdog-termination"',
          ),
          false,
        );
        const receipt = await watchdog.complete({ preserveTempRoot: false });
        assert.equal(receipt.outcome, 'completed');
        watchdog = null;
      } finally {
        watchdog?.abandon();
        rmSync(tempRoot, { recursive: true, force: true });
        rmSync(auditRoot, { recursive: true, force: true });
      }
    },
  );

  it(
    'kills the active process group but preserves a responsive parent on resource breach',
    {
      skip: process.platform === 'win32',
      timeout: 15_000,
    },
    async () => {
      const tempRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-breach-test-'));
      const auditRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-breach-audit-test-'));
      const victim = spawn(
        process.execPath,
        [
          '-e',
          "process.on('SIGTERM',()=>{});" +
          "process.send?.('ready');setInterval(()=>{},1000);",
        ],
        {
          detached: true,
          env: {
            ...process.env,
            RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-victim',
          },
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        },
      );
      let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
      try {
        await waitForMessage(victim, 'ready', 2_000);
        const victimExit = once(victim, 'exit');
        try {
          victim.disconnect();
        } catch {
          // The child can disconnect after acknowledging readiness.
        }
        const runId = `watchdog-breach-${victim.pid}`;
        const auditPath = join(auditRoot, `${runId}.jsonl`);
        writeFileSync(auditPath, '', { mode: 0o600 });
        watchdog = await startResourceWatchdog({
          runId,
          tempRoot,
          auditPath,
          auditRoot,
          systemDiskTransferBaselineBytes: null,
          limits: {
            maximumWorkerBytes: 1024 * 1024,
            maximumSuiteBytes: 1,
            maximumSqliteBytes: 1024 * 1024,
            maximumProcessWriteBytes: 4096 * 1024 * 1024,
            maximumSystemDiskTransferBytes: 4096 * 1024 * 1024,
            minimumStartingFreeBytes: 0,
            minimumRuntimeFreeBytes: 0,
          },
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
        });
        watchdog.setActiveProcessGroup(victim.pid!);
        writeFileSync(join(tempRoot, 'breach.bin'), 'exceeds one byte');
        const [code, signal] = await withTimeout(
          victimExit,
          8_000,
          'watchdog did not terminate the resistant process group',
        );
        assert.equal(code, null);
        assert.equal(signal, 'SIGKILL');
        assert.doesNotThrow(
          () => process.kill(process.pid, 0),
          'resource breach killed the responsive runner parent',
        );
        await waitForCondition(
          () => readFileSync(auditPath, 'utf8').includes(
            '"type":"watchdog-process-group-termination-confirmed"',
          ),
          2_000,
          'watchdog did not persist process-group termination confirmation',
        );
        const audit = readFileSync(auditPath, 'utf8');
        assert.match(audit, /"type":"watchdog-resource-breach"/);
        assert.match(
          audit,
          /"type":"watchdog-process-group-termination-confirmed"/,
        );
        assert.match(audit, /"cause":"resource-breach"/);
        assert.match(audit, /"kind":"suite-footprint"/);
        watchdog.setActiveProcessGroup(null);
        await assert.rejects(
          watchdog.complete({ preserveTempRoot: true }),
          /terminal state is unsafe: suite-footprint/,
        );
        const receipt = JSON.parse(
          readFileSync(watchdog.receiptPath, 'utf8'),
        );
        assert.equal(verifyWatchdogReceiptSeal(receipt), true);
        assert.equal(receipt.outcome, 'resource-breach');
        assert.equal(receipt.success, false);
        assert.equal(receipt.stateRemoved, true);
        assert.equal(
          (receipt.detail as {
            resourceBreach?: {
              resourceProblem?: { kind?: string };
            };
          }).resourceBreach?.resourceProblem?.kind,
          'suite-footprint',
        );
        watchdog = null;
      } finally {
        if (victim.pid) {
          try {
            process.kill(-victim.pid, 'SIGKILL');
          } catch {
            // The watchdog should already have removed the process group.
          }
        }
        watchdog?.abandon();
        rmSync(tempRoot, { recursive: true, force: true });
        rmSync(auditRoot, { recursive: true, force: true });
      }
    },
  );

  it(
    'terminates a macOS process group after cumulative overwrite churn',
    {
      skip: process.platform !== 'darwin',
      timeout: 20_000,
    },
    async () => {
      await assertDarwinProcessWriteBreach('overwrite');
    },
  );

  it(
    'terminates a macOS process group after cumulative create-delete churn',
    {
      skip: process.platform !== 'darwin',
      timeout: 20_000,
    },
    async () => {
      await assertDarwinProcessWriteBreach('create-delete');
    },
  );

  it(
    'records whole-system I/O pressure without killing repository processes',
    {
      skip: process.platform !== 'darwin',
      timeout: 10_000,
    },
    async () => {
      const tempRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-system-io-test-'));
      const auditRoot =
        mkdtempSync(join(tmpdir(), 'radar-watchdog-system-io-audit-test-'));
      const victim = spawn(
        process.execPath,
        ['-e', "process.send?.('ready');setInterval(()=>{},1000);"],
        {
          detached: true,
          env: {
            ...process.env,
            RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-victim',
          },
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        },
      );
      let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
      try {
        await waitForMessage(victim, 'ready', 2_000);
        victim.disconnect();
        const runId = `watchdog-system-io-${victim.pid}`;
        const auditPath = join(auditRoot, `${runId}.jsonl`);
        writeFileSync(auditPath, '', { mode: 0o600 });
        watchdog = await startResourceWatchdog({
          runId,
          tempRoot,
          auditPath,
          auditRoot,
          systemDiskTransferBaselineBytes: 0,
          limits: {
            maximumWorkerBytes: 1024 * 1024,
            maximumSuiteBytes: 1024 * 1024,
            maximumSqliteBytes: 1024 * 1024,
            maximumProcessWriteBytes: 4096 * 1024 * 1024,
            maximumSystemDiskTransferBytes: 1,
            minimumStartingFreeBytes: 0,
            minimumRuntimeFreeBytes: 0,
          },
          repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
          repositoryRoot: process.cwd(),
        });
        watchdog.setActiveProcessGroup(victim.pid!);
        await waitForCondition(
          () => readFileSync(auditPath, 'utf8').includes(
            '"type":"watchdog-system-io-pressure"',
          ),
          2_000,
          'watchdog did not record whole-system I/O pressure',
        );
        assert.doesNotThrow(() => process.kill(process.pid, 0));
        assert.doesNotThrow(() => process.kill(victim.pid!, 0));
        assert.doesNotMatch(
          readFileSync(auditPath, 'utf8'),
          /watchdog-resource-breach/,
        );
        watchdog.setActiveProcessGroup(null);
        const receipt = await watchdog.complete({ preserveTempRoot: false });
        assert.equal(receipt.outcome, 'completed');
        assert.equal(receipt.success, true);
        watchdog = null;
      } finally {
        if (victim.pid) {
          try {
            process.kill(-victim.pid, 'SIGKILL');
          } catch {
            // The victim may already have exited.
          }
        }
        watchdog?.abandon();
        rmSync(tempRoot, { recursive: true, force: true });
        rmSync(auditRoot, { recursive: true, force: true });
      }
    },
  );
});

describe('test baseline candidate lifecycle', () => {
  it('reuses a current candidate unless generation is explicitly rerun', () => {
    const generator = readFileSync(
      join(process.cwd(), 'test', 'generate-test-baseline.mjs'),
      'utf8',
    );
    assert.match(
      generator,
      /(?:args\.includes\('--rerun'\)|argument === '--rerun')/,
    );
    const suiteCallStart = generator.indexOf('await runTestSuite({');
    const suiteCallEnd = generator.indexOf('});', suiteCallStart);
    const suiteCall = generator.slice(suiteCallStart, suiteCallEnd);
    assert.ok(suiteCallStart >= 0);
    assert.ok(suiteCallEnd > suiteCallStart);
    assert.match(suiteCall, /\brerun\b/);
    assert.match(suiteCall, /forwardedArgs:\s*\[\]/);

    const runner = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    const mainStart = runner.indexOf(
      'async function runTestSuiteUnlocked({',
    );
    const mainEnd = runner.indexOf(
      'export function resolvePhaseTimeout',
      mainStart,
    );
    const mainSource = runner.slice(mainStart, mainEnd);
    const candidateInspection = mainSource.indexOf(
      'const inspection = inspectTestBaselineCandidate({',
    );
    const reuseGuard = mainSource.indexOf(
      "if (mode === 'generate' && !rerun) {",
    );
    const resourceInitialization = mainSource.indexOf(
      'await initializeRunResources({',
    );
    assert.match(mainSource, /rerun = false/);
    assert.ok(reuseGuard >= 0);
    assert.ok(candidateInspection > reuseGuard);
    assert.ok(candidateInspection >= 0);
    assert.ok(resourceInitialization > candidateInspection);
    const reuseSource = mainSource.slice(
      candidateInspection,
      resourceInitialization,
    );
    assert.match(reuseSource, /inspection\.current/);
    assert.match(reuseSource, /return\s*\{/);

    const inspectorStart = runner.indexOf(
      'function inspectLoadedTestBaselineCandidate({',
    );
    const inspectorEnd = runner.indexOf(
      'export function isAcceptedBaseline',
      inspectorStart,
    );
    const inspectorSource = runner.slice(inspectorStart, inspectorEnd);
    assert.ok(inspectorStart >= 0);
    assert.ok(inspectorEnd > inspectorStart);
    assert.match(inspectorSource, /assertBaselineCandidateCurrent\(/);
    assert.match(inspectorSource, /assertNoBaselineRegression\(/);
  });

  it('keeps an existing candidate until a verified replacement is written', () => {
    const runner = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    const mainStart = runner.indexOf(
      'async function runTestSuiteUnlocked({',
    );
    const mainEnd = runner.indexOf(
      'export function resolvePhaseTimeout',
      mainStart,
    );
    const mainSource = runner.slice(mainStart, mainEnd);
    const candidateSnapshot = mainSource.indexOf(
      'captureFileSnapshot(baselineCandidatePath)',
    );
    const candidateWrite = mainSource.indexOf(
      'writeJsonAtomically(baselineCandidatePath',
    );
    assert.ok(candidateSnapshot >= 0);
    assert.ok(candidateWrite > candidateSnapshot);
    assert.doesNotMatch(mainSource, /removeAcceptedCandidate\(/);
    assert.match(
      mainSource.slice(candidateWrite),
      /targetBefore:\s*baselineCandidateBefore/,
    );
  });

  it('does not persist a candidate before watchdog completion succeeds', () => {
    const runner = readFileSync(
      join(process.cwd(), 'test', 'test-suite-runner.mjs'),
      'utf8',
    );
    const watchdogCompletion = runner.indexOf(
      "'resource watchdog completion'",
    );
    const terminalAuditRescan = runner.indexOf(
      "'resource watchdog terminal audit rescan'",
    );
    const databaseAuditRescan = runner.indexOf(
      "'terminal database audit rescan'",
    );
    const liveDatabaseRescan = runner.indexOf(
      "'terminal live database family verification'",
    );
    const combinedFailure = runner.indexOf(
      'const combinedFailure = combineErrors(',
    );
    const candidateWrite = runner.indexOf(
      'writeJsonAtomically(baselineCandidatePath',
    );
    assert.ok(watchdogCompletion >= 0);
    assert.ok(terminalAuditRescan > watchdogCompletion);
    assert.ok(databaseAuditRescan > terminalAuditRescan);
    assert.ok(liveDatabaseRescan > databaseAuditRescan);
    assert.ok(combinedFailure > liveDatabaseRescan);
    assert.ok(candidateWrite > combinedFailure);
  });

  it('seals canonical candidate content and rejects reviewed-content tampering', () => {
    const candidate = sealBaselineCandidate({
      schemaVersion: 2,
      kind: 'test-baseline-candidate',
      manifestDigest: 'manifest',
      testTreeDigest: 'tree',
      harnessDigest: 'harness',
      generatedAt: '2026-07-05T12:00:00.000Z',
      runId: 'run',
      bootstrap: true,
      previousBaselineExists: false,
      previousBaselineDigest: null,
      phases: {
        parallel: {
          minimumPassed: 10,
          minimumPassedByFile: { 'src/lib/a.test.ts': 10 },
          testIdentityCounts: { a: 10 },
        },
      },
    });
    assert.doesNotThrow(() => assertBaselineCandidateSeal(candidate));

    const tampered = structuredClone(candidate);
    tampered.phases.parallel.minimumPassed = 1;
    assert.throws(
      () => assertBaselineCandidateSeal(tampered),
      /content seal is invalid/,
    );
  });

  it('derives bootstrap authority from the accepted baseline', () => {
    assert.equal(baselineRequiresBootstrap(bootstrapBaselineFixture()), true);
    assert.equal(
      baselineRequiresBootstrap(acceptedBaselineFixture()),
      false,
    );
    assert.throws(
      () => baselineRequiresBootstrap(null),
      /neither an accepted trust root nor the explicit fail-closed bootstrap state/,
    );
    assert.throws(
      () => baselineRequiresBootstrap({
        ...bootstrapBaselineFixture(),
        acceptedAt: '2026-07-05T12:01:00.000Z',
      }),
      /neither an accepted trust root nor the explicit fail-closed bootstrap state/,
    );
  });

  it('rejects noncanonical accepted timestamps and malformed provenance', () => {
    const baseline = acceptedBaselineFixture();
    assert.equal(isAcceptedBaseline(baseline), true);
    assert.equal(isAcceptedBaseline({
      ...baseline,
      acceptedAt: '2026-07-05T12:01:00+00:00',
    }), false);
    assert.equal(isAcceptedBaseline({
      ...baseline,
      previousBaselineExists: false,
    }), false);
    assert.equal(isAcceptedBaseline({
      ...baseline,
      phases: {
        ...baseline.phases,
        scripts: {
          ...baseline.phases.scripts,
          minimumPassed: baseline.phases.scripts.minimumPassed + 1,
        },
      },
    }), false);
  });

  it('validates the accepted trust root before adding runtime skip policy', () => {
    const baseline = acceptedBaselineFixture();
    assert.doesNotThrow(() => assertGeneratedBaseline(
      baselineManifestFixture(),
      baselineTreeFixture(),
      baseline,
      {
        ...baseline,
        skipAllowlist: [],
      },
    ));
  });

  it('atomically accepts a reviewed candidate and supports cleanup recovery', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-baseline-accept-'));
    const baselinePath = join(directory, 'test-baseline.json');
    const candidatePath = join(directory, 'test-baseline.candidate.json');
    const manifest = baselineManifestFixture();
    const tree = baselineTreeFixture();
    let transientPath: string | undefined;
    try {
      const bootstrap = bootstrapBaselineFixture();
      const bootstrapText = `${JSON.stringify(bootstrap, null, 2)}\n`;
      writeFileSync(baselinePath, bootstrapText);
      const candidate = baselineCandidateFixture({
        previousBaselineDigest: sha256Text(bootstrapText),
      });
      const candidateText = `${JSON.stringify(candidate, null, 2)}\n`;
      writeFileSync(candidatePath, candidateText);

      const accepted = acceptTestBaselineCandidateFiles({
        allowBootstrap: true,
        baselineFilePath: baselinePath,
        candidateFilePath: candidatePath,
        manifest,
        tree,
        captureTree: (excludedPath) => {
          assert.equal(typeof excludedPath, 'string');
          assert.equal(existsSync(excludedPath!), true);
          assert.equal(resolve(excludedPath!, '..'), directory);
          assert.match(
            basename(excludedPath!),
            /^\.test-baseline\.json\.\d+\.[^.]+\.tmp$/,
          );
          transientPath = excludedPath;
          return tree;
        },
        acceptedAt: '2026-07-05T12:01:00.000Z',
      });
      assert.equal(isAcceptedBaseline(accepted), true);
      assert.equal(existsSync(candidatePath), false);
      assert.equal(
        isAcceptedBaseline(JSON.parse(readFileSync(baselinePath, 'utf8'))),
        true,
      );
      assert.equal(existsSync(transientPath!), false);

      writeFileSync(candidatePath, candidateText);
      const recovered = acceptTestBaselineCandidateFiles({
        allowBootstrap: true,
        baselineFilePath: baselinePath,
        candidateFilePath: candidatePath,
        manifest,
        tree,
        captureTree: () => tree,
        acceptedAt: '2026-07-05T12:02:00.000Z',
      });
      assert.deepEqual(recovered, accepted);
      assert.equal(existsSync(candidatePath), false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects stale baseline binding and candidate serialization changes', () => {
    const directory = mkdtempSync(join(tmpdir(), 'radar-baseline-stale-'));
    const baselinePath = join(directory, 'test-baseline.json');
    const candidatePath = join(directory, 'test-baseline.candidate.json');
    const manifest = baselineManifestFixture();
    const tree = baselineTreeFixture();
    try {
      const bootstrap = bootstrapBaselineFixture();
      const bootstrapText = `${JSON.stringify(bootstrap, null, 2)}\n`;
      writeFileSync(baselinePath, bootstrapText);
      const candidate = baselineCandidateFixture({
        previousBaselineDigest: sha256Text(bootstrapText),
      });
      writeFileSync(candidatePath, JSON.stringify(candidate));
      assert.throws(
        () => acceptTestBaselineCandidateFiles({
          allowBootstrap: true,
          baselineFilePath: baselinePath,
          candidateFilePath: candidatePath,
          manifest,
          tree,
          captureTree: () => tree,
        }),
        /candidate file serialization is invalid/,
      );

      writeFileSync(
        candidatePath,
        `${JSON.stringify(candidate, null, 2)}\n`,
      );
      writeFileSync(baselinePath, `${bootstrapText}\n`);
      assert.throws(
        () => acceptTestBaselineCandidateFiles({
          allowBootstrap: true,
          baselineFilePath: baselinePath,
          candidateFilePath: candidatePath,
          manifest,
          tree,
          captureTree: () => tree,
        }),
        /Accepted baseline changed after candidate generation/,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

function bootstrapBaselineFixture() {
  return {
    schemaVersion: 2,
    manifestDigest: null,
    testTreeDigest: null,
    harnessDigest: null,
    generatedAt: null,
    acceptedAt: null,
    runId: null,
    previousBaselineDigest: null,
    candidateDigest: null,
    phases: {
      parallel: {
        minimumPassed: null,
        minimumPassedByFile: null,
        testIdentityCounts: null,
      },
      e2e: {
        minimumPassed: null,
        minimumPassedByFile: null,
        testIdentityCounts: null,
      },
      installer: {
        minimumPassed: null,
        minimumPassedByFile: null,
        testIdentityCounts: null,
      },
      lifecycle: {
        minimumPassed: null,
        minimumPassedByFile: null,
        testIdentityCounts: null,
      },
      scripts: {
        minimumPassed: null,
        minimumPassedByFile: null,
        testIdentityCounts: null,
      },
    },
  };
}

function baselineManifestFixture() {
  return {
    phases: {
      parallel: ['src/lib/a.test.ts'],
      e2e: ['src/lib/composedPublication.e2e.test.ts'],
      installer: ['src/lib/installRelease.test.ts'],
      lifecycle: ['src/lib/processLifecycle.test.ts'],
      scripts: ['scripts/validation/a.test.mjs'],
    },
  };
}

function baselineTreeFixture() {
  return {
    manifestDigest: '1'.repeat(64),
    testTreeDigest: '2'.repeat(64),
    harnessDigest: '3'.repeat(64),
  };
}

function baselineCandidateFixture({
  previousBaselineDigest = '4'.repeat(64),
}: {
  previousBaselineDigest?: string;
} = {}) {
  const tree = baselineTreeFixture();
  return sealBaselineCandidate({
    schemaVersion: 2,
    kind: 'test-baseline-candidate',
    ...tree,
    generatedAt: '2026-07-05T12:00:00.000Z',
    runId: '019f3135-b594-4cf0-b431-b8f231671ebb',
    bootstrap: true,
    previousBaselineExists: true,
    previousBaselineDigest,
    phases: {
      parallel: {
        minimumPassed: 1,
        minimumPassedByFile: { 'src/lib/a.test.ts': 1 },
        testIdentityCounts: {
          '["src/lib/a.test.ts","passes"]': 1,
        },
      },
      e2e: {
        minimumPassed: 1,
        minimumPassedByFile: {
          'src/lib/composedPublication.e2e.test.ts': 1,
        },
        testIdentityCounts: {
          '["src/lib/composedPublication.e2e.test.ts","passes"]': 1,
        },
      },
      installer: {
        minimumPassed: 1,
        minimumPassedByFile: {
          'src/lib/installRelease.test.ts': 1,
        },
        testIdentityCounts: {
          '["src/lib/installRelease.test.ts","passes"]': 1,
        },
      },
      lifecycle: {
        minimumPassed: 1,
        minimumPassedByFile: {
          'src/lib/processLifecycle.test.ts': 1,
        },
        testIdentityCounts: {
          '["src/lib/processLifecycle.test.ts","passes"]': 1,
        },
      },
      scripts: {
        minimumPassed: 1,
        minimumPassedByFile: { 'scripts/validation/a.test.mjs': 1 },
        testIdentityCounts: {
          '["scripts/validation/a.test.mjs","passes"]': 1,
        },
      },
    },
  });
}

function acceptedBaselineFixture() {
  const candidate = baselineCandidateFixture();
  return {
    schemaVersion: 2,
    kind: 'accepted-test-baseline',
    manifestDigest: candidate.manifestDigest,
    testTreeDigest: candidate.testTreeDigest,
    harnessDigest: candidate.harnessDigest,
    generatedAt: candidate.generatedAt,
    acceptedAt: '2026-07-05T12:01:00.000Z',
    runId: candidate.runId,
    bootstrap: candidate.bootstrap,
    previousBaselineExists: candidate.previousBaselineExists,
    previousBaselineDigest: candidate.previousBaselineDigest,
    candidateDigest: candidate.contentDigest,
    candidateFileDigest: sha256Text(
      `${JSON.stringify(candidate, null, 2)}\n`,
    ),
    phases: candidate.phases,
  };
}

function sha256Text(value: string) {
  return createHash('sha256').update(value).digest('hex');
}

describe('authoritative test manifest enforcement', () => {
  it('rejects coverage-changing forwarded arguments and file operands', () => {
    assert.throws(
      () => assertAuthoritativeArguments(['--test-name-pattern=focused']),
      /change test coverage or runner safety/,
    );
    assert.throws(
      () => assertAuthoritativeArguments(['src/lib/cache.test.ts']),
      /change test coverage or runner safety/,
    );
    assert.doesNotThrow(() => assertAuthoritativeArguments([]));
  });

  it('rejects missing and extra discovered tests', () => {
    const manifest = {
      phases: {
        parallel: ['src/lib/a.test.ts'],
        e2e: ['src/lib/composedPublication.e2e.test.ts'],
        installer: ['src/lib/installRelease.test.ts'],
        lifecycle: ['src/lib/processLifecycle.test.ts'],
        scripts: ['scripts/validation/a.test.mjs'],
      },
    };
    assert.throws(
      () => assertExactManifest(manifest, [
        'src/lib/a.test.ts',
        'src/lib/composedPublication.e2e.test.ts',
        'src/lib/installRelease.test.ts',
        'src/lib/processLifecycle.test.ts',
        'scripts/validation/b.test.mjs',
      ]),
      /missing: scripts\/validation\/b\.test\.mjs; extra: scripts\/validation\/a\.test\.mjs/,
    );
  });
});

function testCounts(overrides: Partial<{
  tests: number;
  failed: number;
  passed: number;
  cancelled: number;
  skipped: number;
  todo: number;
}> = {}) {
  return {
    tests: 1,
    failed: 0,
    passed: 1,
    cancelled: 0,
    skipped: 0,
    todo: 0,
    ...overrides,
  };
}

function phaseEvents(
  root: string,
  file: string,
  counts: ReturnType<typeof testCounts>,
  options: {
    includeCompletion?: boolean;
    statusEvents?: unknown[];
  } = {},
) {
  return phaseEventsForFiles(root, [{
    file,
    counts,
    ...options,
  }]);
}

function phaseEventsForFiles(
  root: string,
  files: Array<{
    file: string;
    counts: ReturnType<typeof testCounts>;
    includeCompletion?: boolean;
    statusEvents?: unknown[];
  }>,
) {
  const globalCounts = files.reduce(
    (total, entry) => addCounts(total, entry.counts),
    testCounts({ tests: 0, passed: 0 }),
  );
  return [
    ...files.flatMap((entry) => completeStatusEvents(root, entry)),
    ...files.flatMap((entry) => {
      const absoluteFile = join(root, entry.file);
      return [
        {
          type: 'test:summary',
          data: { success: true, counts: entry.counts, file: absoluteFile },
        },
        ...(entry.includeCompletion === false ? [] : [{
          type: 'test:complete',
          data: {
            name: entry.file,
            nesting: 0,
            details: { type: 'test', passed: true },
            file: absoluteFile,
          },
        }]),
      ];
    }),
    {
      type: 'test:summary',
      data: { success: true, counts: globalCounts },
    },
  ];
}

function completeStatusEvents(
  root: string,
  entry: {
    file: string;
    counts: ReturnType<typeof testCounts>;
    statusEvents?: unknown[];
  },
) {
  const events = [...(entry.statusEvents ?? [])] as Array<any>;
  const observed = {
    passed: 0,
    failed: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
  };
  for (const event of events) {
    if (event?.type === 'test:fail') {
      if (event?.data?.details?.error?.failureType === 'cancelledByParent') {
        observed.cancelled++;
      } else {
        observed.failed++;
      }
    } else if (event?.data?.details?.skip) {
      observed.skipped++;
    } else if (event?.data?.details?.todo) {
      observed.todo++;
    } else {
      observed.passed++;
    }
  }
  const add = (
    outcome: keyof typeof observed,
    create: (index: number) => unknown,
  ) => {
    for (
      let index = observed[outcome] + 1;
      index <= entry.counts[outcome];
      index++
    ) {
      events.push(create(index));
    }
  };
  add('passed', (index) =>
    statusEvent(root, entry.file, `synthetic pass ${index}`, {}));
  add('failed', (index) =>
    statusEvent(
      root,
      entry.file,
      `synthetic failure ${index}`,
      { error: { failureType: 'testCodeFailure' } },
      'test:fail',
    ));
  add('cancelled', (index) =>
    statusEvent(
      root,
      entry.file,
      `synthetic cancellation ${index}`,
      { error: { failureType: 'cancelledByParent' } },
      'test:fail',
    ));
  add('skipped', (index) =>
    statusEvent(
      root,
      entry.file,
      `synthetic skip ${index}`,
      { skip: 'synthetic skip' },
    ));
  add('todo', (index) =>
    statusEvent(
      root,
      entry.file,
      `synthetic todo ${index}`,
      { todo: 'synthetic todo' },
    ));
  return events;
}

function addCounts(
  left: ReturnType<typeof testCounts>,
  right: ReturnType<typeof testCounts>,
) {
  return {
    tests: left.tests + right.tests,
    failed: left.failed + right.failed,
    passed: left.passed + right.passed,
    cancelled: left.cancelled + right.cancelled,
    skipped: left.skipped + right.skipped,
    todo: left.todo + right.todo,
  };
}

function statusEvent(
  root: string,
  file: string,
  name: string,
  details: Record<string, unknown>,
  type = 'test:pass',
) {
  return {
    type,
    data: {
      name,
      nesting: 0,
      details: { type: 'test', ...details },
      file: join(root, file),
    },
  };
}

function integrityBaseline(
  minimumPassed: number,
  skipAllowlist: Array<{
    file: string;
    name: string;
    reportedReason: true | string;
    reason: string;
    platforms: string[];
  }> = [],
  minimumPassedByFile?: Record<string, number> | null,
) {
  const perFile = minimumPassedByFile === undefined ? {
    'src/lib/example.test.ts': minimumPassed,
  } : minimumPassedByFile;
  const testIdentityCounts: Record<string, number> = {};
  for (const [file, minimum] of Object.entries(perFile ?? {})) {
    const skips = skipAllowlist.filter((entry) => entry.file === file);
    for (const skip of skips) {
      testIdentityCounts[JSON.stringify([file, skip.name])] =
        (testIdentityCounts[JSON.stringify([file, skip.name])] ?? 0) + 1;
    }
    for (let index = 1; index <= minimum - skips.length; index++) {
      testIdentityCounts[JSON.stringify([file, `synthetic pass ${index}`])] = 1;
    }
  }
  return {
    phases: {
      parallel: {
        minimumPassed,
        minimumPassedByFile: perFile,
        testIdentityCounts:
          minimumPassedByFile === null ? null : testIdentityCounts,
      },
    },
    skipAllowlist,
  };
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function assertFamilyMutationReported(
  databasePath: string,
  expected: SqliteFamilyFingerprint,
  changedPath: string,
) {
  assert.throws(
    () => assertSqliteFamilyUnchanged(
      databasePath,
      expected,
      'focused unit test',
    ),
    (error: unknown) =>
      error instanceof Error &&
      error.message.includes('focused unit test') &&
      error.message.endsWith(changedPath),
  );
}

async function assertDarwinProcessWriteBreach(
  mode: 'overwrite' | 'create-delete',
) {
  const tempRoot =
    mkdtempSync(join(tmpdir(), `radar-watchdog-${mode}-test-`));
  const auditRoot =
    mkdtempSync(join(tmpdir(), `radar-watchdog-${mode}-audit-test-`));
  const targetPath = join(tempRoot, mode);
  const victim = spawn(
    process.execPath,
    [
      '-e',
      `
        const fs = require('node:fs');
        const mode = process.argv[1];
        const targetPath = process.argv[2];
        const payload = Buffer.alloc(512 * 1024, 0x5a);
        process.on('SIGTERM', () => {});
        process.once('disconnect', () => process.exit(125));
        setTimeout(() => process.exit(124), 30_000).unref();
        process.on('message', (message) => {
          if (message !== 'write') return;
          try {
            if (mode === 'overwrite') {
              const descriptor = fs.openSync(targetPath, 'w');
              try {
                for (let index = 0; index < 16; index++) {
                  fs.writeSync(
                    descriptor,
                    payload,
                    0,
                    payload.length,
                    0,
                  );
                  fs.fsyncSync(descriptor);
                }
              } finally {
                fs.closeSync(descriptor);
              }
            } else {
              fs.mkdirSync(targetPath, { recursive: true });
              for (let index = 0; index < 16; index++) {
                const path = targetPath + '/entry-' + index + '.bin';
                const descriptor = fs.openSync(path, 'w');
                try {
                  fs.writeSync(descriptor, payload);
                  fs.fsyncSync(descriptor);
                } finally {
                  fs.closeSync(descriptor);
                }
                fs.unlinkSync(path);
              }
            }
            process.send?.('written');
          } catch (error) {
            process.send?.('write-failed');
            process.exit(1);
          }
        });
        process.send?.('ready');
        setInterval(() => {}, 1000);
      `,
      mode,
      targetPath,
    ],
    {
      detached: true,
      env: {
        ...process.env,
        RADAR_TEST_DETACHED_SCOPE: 'resource-watchdog-victim',
      },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    },
  );
  let watchdog: Awaited<ReturnType<StartResourceWatchdog>> | null = null;
  try {
    await waitForMessage(victim, 'ready', 2_000);
    const victimExit = once(victim, 'exit');
    const runId = `watchdog-process-write-${mode}-${victim.pid}`;
    const auditPath = join(auditRoot, `${runId}.jsonl`);
    writeFileSync(auditPath, '', { mode: 0o600 });
    watchdog = await startResourceWatchdog({
      runId,
      tempRoot,
      auditPath,
      auditRoot,
      systemDiskTransferBaselineBytes: null,
      limits: {
        maximumWorkerBytes: 8 * mebibyte,
        maximumSuiteBytes: 8 * mebibyte,
        maximumSqliteBytes: 1024 * 1024,
        maximumProcessWriteBytes: 2 * mebibyte,
        maximumSystemDiskTransferBytes: 4096 * mebibyte,
        minimumStartingFreeBytes: 0,
        minimumRuntimeFreeBytes: 0,
      },
      repositoryIdentity: canonicalRepositoryIdentity(process.cwd()),
      repositoryRoot: process.cwd(),
    });
    watchdog.setActiveProcessGroup(victim.pid!);
    victim.send('write');
    const [code, signal] = await withTimeout(
      victimExit,
      12_000,
      `watchdog did not terminate ${mode} churn process group`,
    );
    assert.equal(code, null);
    assert.equal(signal, 'SIGKILL');
    assert.doesNotThrow(() => process.kill(process.pid, 0));
    await waitForCondition(
      () => readFileSync(auditPath, 'utf8').includes(
        '"type":"watchdog-process-group-termination-confirmed"',
      ),
      2_000,
      'watchdog did not confirm cumulative-write process-group termination',
    );
    const audit = readFileSync(auditPath, 'utf8');
    assert.match(audit, /"kind":"process-group-cumulative-write"/);
    assert.match(audit, /"currentBytes":\d+/);
    assert.match(audit, /"peakBytes":\d+/);
    assert.match(audit, /"topWriters":\[/);
    const terminationEvent = audit
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line))
      .find((event) =>
        event.type === 'watchdog-process-group-termination-confirmed');
    assert.ok(terminationEvent);
    assert.ok(
      terminationEvent.processWriteAccounting.currentBytes > 2 * mebibyte,
    );
    assert.ok(
      terminationEvent.processWriteAccounting.topWriters.some(
        (writer: { pid?: number; bytesWritten?: number }) =>
          writer.pid === victim.pid &&
          (writer.bytesWritten ?? 0) > 2 * mebibyte,
      ),
    );

    let retainedBytes = 0;
    if (mode === 'overwrite' && existsSync(targetPath)) {
      retainedBytes = statSync(targetPath).size;
    } else if (mode === 'create-delete' && existsSync(targetPath)) {
      retainedBytes = readdirSync(targetPath)
        .map((name) => statSync(join(targetPath, name)).size)
        .reduce((total, size) => total + size, 0);
    }
    assert.ok(
      retainedBytes <= 512 * 1024,
      `${mode} retained ${retainedBytes} bytes after cumulative churn`,
    );

    watchdog.setActiveProcessGroup(null);
    await assert.rejects(
      watchdog.complete({ preserveTempRoot: true }),
      /terminal state is unsafe: process-group-cumulative-write/,
    );
    const receipt = JSON.parse(
      readFileSync(watchdog.receiptPath, 'utf8'),
    );
    assert.equal(verifyWatchdogReceiptSeal(receipt), true);
    assert.equal(receipt.outcome, 'resource-breach');
    assert.equal(receipt.success, false);
    assert.equal(receipt.stateRemoved, true);
    const accounting = (receipt as {
      processWriteAccounting?: {
        currentBytes?: number;
        peakBytes?: number;
        topWriters?: Array<{ pid?: number; bytesWritten?: number }>;
      };
      detail?: {
        resourceBreach?: {
          resourceProblem?: { kind?: string };
        };
      };
    }).processWriteAccounting;
    assert.ok(accounting);
    assert.ok((accounting.currentBytes ?? 0) > 2 * mebibyte);
    assert.ok(
      (accounting.peakBytes ?? 0) >= (accounting.currentBytes ?? 0),
    );
    assert.ok(
      accounting.topWriters?.some((writer) =>
        writer.pid === victim.pid &&
        (writer.bytesWritten ?? 0) > 2 * mebibyte),
    );
    assert.equal(
      (receipt as {
        detail?: {
          resourceBreach?: {
            resourceProblem?: { kind?: string };
          };
        };
      }).detail?.resourceBreach?.resourceProblem?.kind,
      'process-group-cumulative-write',
    );
    watchdog = null;
  } finally {
    if (victim.pid) {
      try {
        process.kill(-victim.pid, 'SIGKILL');
      } catch {
        // The watchdog should already have terminated the victim.
      }
    }
    watchdog?.abandon();
    rmSync(tempRoot, { recursive: true, force: true });
    rmSync(auditRoot, { recursive: true, force: true });
  }
}

function waitForMessage(
  child: ReturnType<typeof spawn>,
  expected: unknown,
  timeoutMs: number,
) {
  return new Promise<void>((resolvePromise, rejectPromise) => {
    let timer: NodeJS.Timeout | null = null;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      child.off('message', onMessage);
      child.off('error', onError);
      child.off('exit', onExit);
    };
    const onMessage = (message: unknown) => {
      if (message !== expected) return;
      cleanup();
      resolvePromise();
    };
    const onError = (error: Error) => {
      cleanup();
      rejectPromise(error);
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      rejectPromise(
        new Error(
          `process exited before message with ` +
          `${signal ? `signal ${signal}` : `code ${String(code)}`}`,
        ),
      );
    };
    child.on('message', onMessage);
    child.once('error', onError);
    child.once('exit', onExit);
    timer = setTimeout(() => {
      cleanup();
      rejectPromise(new Error(`message was not received within ${timeoutMs}ms`));
    }, timeoutMs);
  });
}

async function waitForCondition(
  condition: () => boolean,
  timeoutMs: number,
  message: string,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) return;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
  }
  throw new Error(message);
}

function waitForWatchdogMessage(
  child: ReturnType<typeof spawn>,
  runId: string,
  statePath: string,
  timeoutMs: number,
) {
  return new Promise<void>((resolvePromise, rejectPromise) => {
    let timer: NodeJS.Timeout | null = null;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      child.off('message', onMessage);
      child.off('error', onError);
      child.off('exit', onExit);
    };
    const onMessage = (message: unknown) => {
      if (
        typeof message !== 'object' ||
        message === null ||
        !('type' in message) ||
        !('runId' in message) ||
        !('statePath' in message) ||
        message.type !== 'watchdog-ready' ||
        message.runId !== runId ||
        message.statePath !== statePath
      ) {
        return;
      }
      cleanup();
      resolvePromise();
    };
    const onError = (error: Error) => {
      cleanup();
      rejectPromise(error);
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      rejectPromise(
        new Error(
          `watchdog exited before readiness with ` +
          `${signal ? `signal ${signal}` : `code ${String(code)}`}`,
        ),
      );
    };
    child.on('message', onMessage);
    child.once('error', onError);
    child.once('exit', onExit);
    timer = setTimeout(() => {
      cleanup();
      rejectPromise(
        new Error(`watchdog readiness was not received within ${timeoutMs}ms`),
      );
    }, timeoutMs);
  });
}

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
) {
  return new Promise<T>((resolvePromise, rejectPromise) => {
    const timer = setTimeout(
      () => rejectPromise(new Error(message)),
      timeoutMs,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolvePromise(value);
      },
      (error) => {
        clearTimeout(timer);
        rejectPromise(error);
      },
    );
  });
}
