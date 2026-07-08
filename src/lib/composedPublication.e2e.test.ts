import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  readdirSync,
  rmSync,
  statSync,
  type Dirent,
} from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const helper = join(root, 'src', 'lib', 'composedPublication.e2e.helper.ts');
const fixtureCodeRevision =
  process.env.RADAR_CODE_REVISION ?? 'composed-publication-e2e-v1';
const testTempRoot = realpathSync.native(requiredEnv('RADAR_TEST_TEMP_ROOT'));
const privateArtifactRoot = realpathSync.native(
  dirname(requiredEnv('DB_PATH')),
);
assert.ok(
  isWithin(testTempRoot, privateArtifactRoot),
  'composed publication E2E artifacts must stay under RADAR_TEST_TEMP_ROOT',
);
const MAX_PRIVATE_FILE_BYTES = 512 * 1024 * 1024;
const MAX_HELPER_OUTPUT_BYTES = 4 * 1024 * 1024;
const HELPER_TIMEOUT_MS = 120_000;

type ReleaseCatalogTuple = [
  tag: string,
  releaseNodeId: string,
  tagCommitOid: string,
  prerelease: boolean,
];

type ReleaseArtifactIdentityTuple = [
  tag: string,
  releaseNodeId: string,
  tagCommitOid: string,
];

const exactCatalogOracle: ReleaseCatalogTuple[] = [
  [
    'v2099.7.5',
    'RE_composed_publication',
    'cccccccccccccccccccccccccccccccccccccccc',
    false,
  ],
  [
    'v2099.7.4',
    'RE_composed_publication_predecessor',
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    false,
  ],
];
const exactRefreshReceiptArtifactIdentityOracle:
  ReleaseArtifactIdentityTuple[] = [
    [
      'v2099.7.4',
      'RE_composed_publication_predecessor',
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    ],
    [
      'v2099.7.5',
      'RE_composed_publication',
      'cccccccccccccccccccccccccccccccccccccccc',
    ],
  ];
const phantomCatalogTags = ['v2026.7.1', 'v2026.6.30'] as const;

type ScenarioResult = {
  scenario: string;
  [key: string]: any;
};

type PrivateDatabase = {
  dir: string;
  dbPath: string;
};

describe('composed ingestion-to-publication and crash recovery E2E', {
  concurrency: false,
}, () => {
  it('publishes one coherent atomic score, receipt, semantic link set, and API view', {
    timeout: 120_000,
  }, async () => {
    const database = privateDatabase('clean');
    try {
      const result = await runScenario(database, 'clean');
      assert.equal(result.apiOutcome, 'success');
      assert.deepEqual(result.probeRows, ['forecast', 'ingestion', 'score']);
      assert.deepEqual(result.ledgerProblems, []);
      assert.deepEqual(result.linkProblems, []);
      assert.deepEqual(result.scoreContractFailures, []);
      assert.deepEqual(result.apiVerificationProblems, []);
      assert.equal(typeof result.finalScore, 'number');
      assert.equal(result.apiReceiptVerified, true);
      assert.equal(result.apiSemanticLinksVerified, true);
      assert.equal(result.publicStatus, 200);
      assert.equal(result.publicScore, result.finalScore);
      assert.deepEqual(
        result.publicReleaseTags,
        [exactCatalogOracle[0][0]],
      );
      assert.deepEqual(
        result.releaseIndexTags,
        [exactCatalogOracle[0][0]],
      );
      assert.deepEqual(result.phantomReviewStatuses, {
        'v2026.6.30': 404,
        'v2026.7.1': 404,
      });
      assert.match(result.publicSnapshotId, /^[0-9a-f]{64}$/);
      assert.match(result.publicAuditDigest, /^[0-9a-f]{64}$/);
      assert.equal(result.reviewStatus, 200);
      assert.equal(result.issuesReviewStatus, 200);
      assert.equal(result.closureProofsReviewStatus, 200);
      assert.equal(result.reachabilityReviewStatus, 200);
      assert.deepEqual(result.releaseAuditFailures, []);
      assert.notEqual(result.forecastEligibilityOutcome, 'not_eligible');
      assert.ok(result.forecastCount > 0);
      assert.ok(result.canonicalForecastCount > 0);
      assert.deepEqual(result.artifactLedgerProblems, []);
      assert.equal(result.artifactReceiptCount, 2);
      assert.equal(result.artifactObservationCount, 2);
      assert.equal(result.authorizedAdvisoryV2SnapshotCount, 1);
      assert.ok(
        Number.isInteger(result.authorizedAdvisoryV2SnapshotId) &&
        result.authorizedAdvisoryV2SnapshotId > 0,
      );
      assert.equal(
        result.authorizedAdvisoryV2RunId,
        result.runId,
      );
      assert.equal(
        result.authorizedAdvisoryV2ReceiptId,
        result.receiptId,
      );
      assert.equal(result.artifactPublicationLinkCount, 2);
      assert.match(result.artifactPublicationDigest, /^[0-9a-f]{64}$/);
      assert.equal(result.artifactScopeReleaseCount, 2);
      assert.deepEqual(result.artifactScopeScoredReleaseTags, ['v2099.7.5']);
      assert.deepEqual(
        result.artifactScopeDependencyReleaseTags,
        ['v2099.7.4'],
      );
      assertExactCatalogEvidence(result);
      assert.match(result.artifactScopeDigest, /^[0-9a-f]{64}$/);
      assert.match(
        result.artifactReceiptId,
        /^artifact-receipt-v2:[0-9a-f]{64}$/,
      );
      assert.match(
        result.artifactObservationId,
        /^artifact-observation-v1:[0-9a-f]{64}$/,
      );
      assert.equal(
        result.publishedSourceIdentityDigest,
        result.stagedSourceIdentityDigest,
      );
      assert.equal(
        result.historySourceIdentityDigest,
        result.stagedSourceIdentityDigest,
      );
      assert.equal(
        result.mutableArtifactSourceIdentityDigest,
        result.stagedSourceIdentityDigest,
      );
      assert.match(result.historyRunContentHash, /^[0-9a-f]{64}$/);
    } finally {
      removePrivateDatabase(database);
    }
  });

  for (const phase of [
    'score.persist',
    'forecast.capture',
    'success.receipt',
    'commit.fence',
    'lease-loss-before-commit',
  ] as const) {
    it(`rolls back atomic publication at ${phase}`, {
      timeout: 120_000,
    }, async () => {
      await assertAtomicFailureScenario(phase);
    });
  }

  for (const terminalStatus of [
    'receiptless',
    'failure',
    'abandoned',
  ] as const) {
    it(`restores the prior schema-3 publication after a tip ending as ${terminalStatus}`, {
      timeout: 120_000,
    }, async () => {
      await assertRecoveryScenario(terminalStatus);
    });
  }

  it('restores across two consecutive failed immutable publications', {
    timeout: 120_000,
  }, async () => {
    const database = privateDatabase('recovery-multiple');
    try {
      const result = await runScenario(database, 'recovery:multiple');
      assert.equal(result.restoredScore, 8.5);
      assert.equal(
        result.scoreRecovery.restoredHistoryRunId,
        'refresh:prior-multiple',
      );
      assert.equal(result.displacedPublicationCount, 2);
      assert.equal(result.restoredReceiptSchemaVersion, 3);
      assert.equal(result.restoredArtifactRunId, 'prior-multiple');
      assert.deepEqual(result.artifactLedgerProblems, []);
      assert.deepEqual(result.displacedOperationRunIds, [
        'failed-multiple-a',
        'failed-multiple-b',
      ]);
    } finally {
      removePrivateDatabase(database);
    }
  });

  it('keeps classifier attempts durable across restart without accepted classifications', {
    timeout: 120_000,
  }, async () => {
    const database = privateDatabase('classifier-ledger');
    try {
      const seeded = await runScenario(database, 'classifier-seed');
      assert.equal(seeded.runCount, 3);
      assert.equal(seeded.attemptCount, 3);
      assert.equal(seeded.classificationCount, 0);
      const reopened = await runScenario(database, 'classifier-verify');
      assert.deepEqual(
        { ...reopened, scenario: seeded.scenario },
        seeded,
      );
      assert.deepEqual(reopened.terminalStatuses, [
        'abandoned',
        'terminal_failure',
      ]);
      assert.equal(reopened.publicationCount, 0);
    } finally {
      removePrivateDatabase(database);
    }
  });

  it('retries concurrent public score reads across a real database epoch change', {
    timeout: 180_000,
  }, async () => {
    const database = privateDatabase('api-epoch');
    try {
      const result = await runScenario(database, 'api-epoch');
      assert.equal(result.reviewStatus, 200);
      assert.equal(result.comparisonStatus, 200);
      assert.equal(result.reviewLocalStatus, 'stale');
      assert.equal(result.comparisonLocalStatus, 'stale');
      assert.ok(result.lifecycle.spawned >= 3);
      assert.ok(result.lifecycle.canceled >= 1);
      assert.equal(result.lifecycle.active, 0);
      assert.equal(result.lifecycle.terminated, result.lifecycle.spawned);
    } finally {
      removePrivateDatabase(database);
    }
  });

  for (const phase of [
    'after-attempt',
    'score.persist',
    'forecast.capture',
    'success.receipt',
    'after-commit',
  ] as const) {
    it(`survives SIGKILL at ${phase}`, {
      timeout: 120_000,
    }, async () => {
      await assertSigkillScenario(phase);
    });
  }
});

async function assertAtomicFailureScenario(
  phase:
    | 'score.persist'
    | 'forecast.capture'
    | 'success.receipt'
    | 'commit.fence'
    | 'lease-loss-before-commit',
): Promise<void> {
  const database = privateDatabase(`failure-${phase}`);
  try {
    const result = await runScenario(database, `failure:${phase}`);
    assert.equal(result.failurePhase, phase);
    assert.equal(result.receiptStatus, 'failure');
    assert.deepEqual(result.probeRows, ['ingestion']);
    assert.deepEqual(result.ledgerProblems, []);
    assert.ok(
      result.stageStatuses.some((value: string) =>
        value.startsWith('score.persist:failed:')),
    );
  } finally {
    removePrivateDatabase(database);
  }
}

async function assertSigkillScenario(
  phase:
    | 'after-attempt'
    | 'score.persist'
    | 'forecast.capture'
    | 'success.receipt'
    | 'after-commit',
): Promise<void> {
  const database = privateDatabase(`sigkill-${phase}`);
  try {
    const exit = await killAtPublicationPhase(database, phase);
    assert.equal(exit.code, null);
    assert.equal(exit.signal, 'SIGKILL');
    await delay(700);
    const recovered = await runScenario(
      database,
      `crash-recover:${phase}`,
    );
    const committed = phase === 'after-commit';
    assert.equal(
      recovered.crashReceiptStatus,
      committed ? 'success' : 'abandoned',
    );
    if (committed) {
      assert.equal(typeof recovered.committedScore, 'number');
    } else {
      assert.equal(recovered.committedScore, null);
    }
    assert.deepEqual(
      recovered.probeRows,
      committed
        ? ['forecast', 'ingestion', 'score']
        : ['ingestion'],
    );
  } finally {
    removePrivateDatabase(database);
  }
}

async function assertRecoveryScenario(
  terminalStatus: 'receiptless' | 'failure' | 'abandoned',
): Promise<void> {
  const database = privateDatabase(`recovery-${terminalStatus}`);
  try {
    const result = await runScenario(
      database,
      `recovery:${terminalStatus}`,
    );
    assert.equal(result.restoredScore, 8.5);
    assert.equal(
      result.scoreRecovery.restoredHistoryRunId,
      `refresh:prior-${terminalStatus}`,
    );
    assert.equal(
      result.abandonedReceiptCount,
      terminalStatus === 'receiptless' ? 1 : 0,
    );
    assert.equal(result.restoredReceiptSchemaVersion, 3);
    assert.equal(
      result.restoredArtifactRunId,
      `prior-${terminalStatus}`,
    );
    assert.deepEqual(result.artifactLedgerProblems, []);
  } finally {
    removePrivateDatabase(database);
  }
}

function privateDatabase(label: string): PrivateDatabase {
  const dir = mkdtempSync(
    join(privateArtifactRoot, `radar-composed-${label}-`),
  );
  const dbPath = join(dir, 'radar.db');
  return { dir, dbPath };
}

function assertExactCatalogEvidence(result: ScenarioResult): void {
  assert.equal(result.catalogCaptureReceiptCount, 1);
  assert.equal(result.catalogCaptureReceiptSource, 'test_fixture');
  assert.deepEqual(result.persistedCatalogTuples, exactCatalogOracle);
  assert.deepEqual(
    result.allPersistedReleaseTags,
    exactCatalogOracle.map(([tag]) => tag),
  );
  assert.deepEqual(result.inactivePersistedReleaseTags, []);
  assert.deepEqual(
    result.catalogCaptureReceiptTags,
    exactCatalogOracle.map(([tag]) => tag),
  );
  assert.equal(
    result.catalogCaptureReceiptStableCount,
    exactCatalogOracle.filter(([, , , prerelease]) => !prerelease).length,
  );
  assert.equal(
    result.catalogCaptureReceiptPrereleaseCount,
    exactCatalogOracle.filter(([, , , prerelease]) => prerelease).length,
  );
  assert.deepEqual(
    result.catalogCaptureReceiptLatestStableTuple,
    exactCatalogOracle.find(([, , , prerelease]) => !prerelease) ?? null,
  );
  assert.deepEqual(
    result.refreshReceiptArtifactIdentityTuples,
    exactRefreshReceiptArtifactIdentityOracle,
  );
  for (const phantomTag of phantomCatalogTags) {
    assert.equal(
      result.persistedCatalogTuples.some(
        (tuple: ReleaseCatalogTuple) => tuple[0] === phantomTag,
      ),
      false,
      `persisted catalog must not contain phantom tag ${phantomTag}`,
    );
    assert.equal(
      result.catalogCaptureReceiptTags.includes(phantomTag),
      false,
      `catalog capture receipt must not contain phantom tag ${phantomTag}`,
    );
    assert.equal(
      result.refreshReceiptArtifactIdentityTuples.some(
        (tuple: ReleaseArtifactIdentityTuple) => tuple[0] === phantomTag,
      ),
      false,
      `refresh receipt must not contain phantom tag ${phantomTag}`,
    );
  }
}

function removePrivateDatabase(database: PrivateDatabase): void {
  rmSync(database.dir, { recursive: true, force: true });
}

async function runScenario(
  database: PrivateDatabase,
  scenario: string,
): Promise<ScenarioResult> {
  const command = helperCommand(scenario);
  const child = spawn(
    command.executable,
    command.args,
    {
      cwd: root,
      env: helperEnvironment(database, scenario),
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  const exitPromise = childExit(child);
  void exitPromise.catch(() => {});
  let stdout = '';
  let stderr = '';
  let outputBytes = 0;
  let safetyFailure: Error | null = null;
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  const appendOutput = (target: 'stdout' | 'stderr', chunk: string) => {
    outputBytes += Buffer.byteLength(chunk);
    if (outputBytes > MAX_HELPER_OUTPUT_BYTES) {
      safetyFailure ??= new Error(
        `${scenario} helper exceeded ${MAX_HELPER_OUTPUT_BYTES} output bytes`,
      );
      child.kill('SIGKILL');
      return;
    }
    if (target === 'stdout') stdout += chunk;
    else stderr += chunk;
  };
  child.stdout.on('data', (chunk: string) => appendOutput('stdout', chunk));
  child.stderr.on('data', (chunk: string) => appendOutput('stderr', chunk));

  const timeout = setTimeout(() => {
    safetyFailure ??= new Error(
      `${scenario} helper exceeded ${HELPER_TIMEOUT_MS}ms`,
    );
    child.kill('SIGKILL');
  }, HELPER_TIMEOUT_MS);
  const sizeMonitor = setInterval(() => {
    const problem = privateDatabaseSizeProblem(database);
    if (!problem) return;
    safetyFailure ??= new Error(`${scenario} helper ${problem}`);
    child.kill('SIGKILL');
  }, 50);

  let exit: { code: number | null; signal: NodeJS.Signals | null };
  try {
    exit = await exitPromise;
  } finally {
    clearTimeout(timeout);
    clearInterval(sizeMonitor);
  }
  const finalSizeProblem = privateDatabaseSizeProblem(database);
  if (finalSizeProblem) {
    safetyFailure ??= new Error(`${scenario} helper ${finalSizeProblem}`);
  }
  if (safetyFailure) throw safetyFailure;
  assert.equal(
    exit.code,
    0,
    `${scenario} helper failed with ${String(exit.signal)}:\n${stdout}\n${stderr}`,
  );
  const line = stdout
    .split(/\r?\n/)
    .find((candidate) => candidate.startsWith('COMPOSED_E2E_RESULT='));
  assert.ok(line, `${scenario} helper emitted no result:\n${stdout}`);
  return JSON.parse(line.slice('COMPOSED_E2E_RESULT='.length));
}

async function killAtPublicationPhase(
  database: PrivateDatabase,
  phase: string,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  const command = helperCommand(`crash-worker:${phase}`);
  const child = spawn(
    command.executable,
    command.args,
    {
      cwd: root,
      env: helperEnvironment(database, `crash-worker:${phase}`),
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  const exitPromise = childExit(child);
  void exitPromise.catch(() => {});
  let stdout = '';
  let stderr = '';
  let outputBytes = 0;
  let outputProblem: string | null = null;
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    outputBytes += Buffer.byteLength(chunk);
    if (outputBytes > MAX_HELPER_OUTPUT_BYTES) {
      outputProblem =
        `child output exceeded ${MAX_HELPER_OUTPUT_BYTES} bytes`;
      child.kill('SIGKILL');
      return;
    }
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    outputBytes += Buffer.byteLength(chunk);
    if (outputBytes > MAX_HELPER_OUTPUT_BYTES) {
      outputProblem =
        `child output exceeded ${MAX_HELPER_OUTPUT_BYTES} bytes`;
      child.kill('SIGKILL');
      return;
    }
    stderr += chunk;
  });
  try {
    await waitForOutput(
      () => stdout.includes(`CRASH_READY=${phase}`),
      () => child.exitCode != null || child.signalCode != null,
      () => `phase=${phase}\nstdout=${stdout}\nstderr=${stderr}`,
      () => outputProblem ?? privateDatabaseSizeProblem(database),
    );
    assert.equal(child.kill('SIGKILL'), true);
    const exit = await exitPromise;
    const finalSizeProblem = privateDatabaseSizeProblem(database);
    if (finalSizeProblem) {
      throw new Error(`Child violated safety limit: ${finalSizeProblem}`);
    }
    return exit;
  } finally {
    if (child.exitCode == null && child.signalCode == null) {
      child.kill('SIGKILL');
      await exitPromise;
    }
  }
}

function helperCommand(scenario: string): {
  executable: string;
  args: string[];
} {
  const nodeArgs = ['--import', 'tsx', helper, scenario];
  if (
    process.platform === 'darwin' &&
    scenario === 'api-epoch' &&
    existsSync('/usr/bin/nice')
  ) {
    return {
      executable: '/usr/bin/nice',
      args: ['-n', '15', process.execPath, ...nodeArgs],
    };
  }
  if (
    process.platform === 'darwin' &&
    existsSync('/usr/sbin/taskpolicy') &&
    existsSync('/usr/bin/nice')
  ) {
    return {
      executable: '/usr/sbin/taskpolicy',
      args: [
        '-b',
        '/usr/bin/nice',
        '-n',
        '15',
        process.execPath,
        ...nodeArgs,
      ],
    };
  }
  return {
    executable: process.execPath,
    args: nodeArgs,
  };
}

function privateDatabaseSizeProblem(
  database: PrivateDatabase,
): string | null {
  const pending = [database.dir];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        pending.push(path);
        continue;
      }
      if (!entry.isFile()) continue;
      let size: number;
      try {
        size = statSync(path).size;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
        throw error;
      }
      if (size > MAX_PRIVATE_FILE_BYTES) {
        return (
          `created ${path} at ${size} bytes, exceeding the ` +
          `${MAX_PRIVATE_FILE_BYTES}-byte private-file limit`
        );
      }
    }
  }
  return null;
}

function helperEnvironment(
  database: PrivateDatabase,
  scenario: string,
): NodeJS.ProcessEnv {
  const bootstrapMode = bootstrapModeForScenario(scenario);
  assert.equal(
    existsSync(database.dbPath),
    bootstrapMode === 'existing',
    `${scenario} database existence must match ${bootstrapMode} bootstrap mode`,
  );
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return {
    ...env,
    DB_PATH: database.dbPath,
    DOTENV_CONFIG_PATH: requiredEnv('DOTENV_CONFIG_PATH'),
    GITHUB_TOKEN: '',
    GITHUB_PERSONAL_ACCESS_TOKEN: '',
    OPENAI_API_KEY: '',
    OC_OPENAI_API_KEY: '',
    REFRESH_ON_STARTUP: 'false',
    REFRESH_MINUTES: '0',
    RELEASES_LIMIT: '1',
    COMPARISON_API_ENABLED: scenario === 'api-epoch' ? 'true' : 'false',
    RADAR_DB_READ_ONLY: '0',
    RADAR_DB_BOOTSTRAP_MODE: bootstrapMode,
  };
}

function bootstrapModeForScenario(
  scenario: string,
): 'fresh' | 'existing' {
  if (
    scenario === 'classifier-verify' ||
    scenario.startsWith('crash-recover:')
  ) {
    return 'existing';
  }
  if (
    scenario === 'clean' ||
    scenario === 'api-epoch' ||
    scenario === 'classifier-seed' ||
    scenario.startsWith('failure:') ||
    scenario.startsWith('recovery:') ||
    scenario.startsWith('crash-worker:')
  ) {
    return 'fresh';
  }
  throw new Error(`Unknown composed publication scenario: ${scenario}`);
}

async function waitForOutput(
  ready: () => boolean,
  exited: () => boolean,
  diagnostics: () => string,
  unsafe: () => string | null = () => null,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (ready()) return;
    const safetyProblem = unsafe();
    if (safetyProblem) {
      throw new Error(`Child violated safety limit: ${safetyProblem}`);
    }
    if (exited()) {
      throw new Error(`Child exited before crash marker.\n${diagnostics()}`);
    }
    await delay(10);
  }
  throw new Error(`Timed out waiting for crash marker.\n${diagnostics()}`);
}

async function childExit(
  child: ReturnType<typeof spawn>,
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  const outputClosed =
    (child.stdout == null || child.stdout.readableEnded) &&
    (child.stderr == null || child.stderr.readableEnded);
  if ((child.exitCode != null || child.signalCode != null) && outputClosed) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  return await new Promise((resolveExit, rejectExit) => {
    child.once('error', rejectExit);
    child.once('close', (code, signal) => resolveExit({ code, signal }));
  });
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise<void>((resolveDelay) =>
    setTimeout(resolveDelay, milliseconds));
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  assert.ok(value, `Missing required test environment variable: ${name}`);
  return value;
}

function isWithin(root: string, path: string): boolean {
  const normalizedRoot = resolve(root);
  const normalizedPath = resolve(path);
  return normalizedPath === normalizedRoot ||
    normalizedPath.startsWith(`${normalizedRoot}${sep}`);
}
