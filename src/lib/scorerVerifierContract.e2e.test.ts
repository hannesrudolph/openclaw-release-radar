import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const tsx = join(root, 'node_modules', '.bin', 'tsx');
const helper = join(root, 'src', 'lib', 'scorerVerifierContract.e2e.helper.ts');
const composedHelper = join(
  root,
  'src',
  'lib',
  'composedPublication.e2e.helper.ts',
);
const testTempRoot = realpathSync.native(requiredEnv('RADAR_TEST_TEMP_ROOT'));
const privateArtifactRoot = realpathSync.native(
  dirname(requiredEnv('DB_PATH')),
);
assert.ok(
  isWithin(testTempRoot, privateArtifactRoot),
  'scorer/verifier E2E artifacts must stay under RADAR_TEST_TEMP_ROOT',
);

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
  score: number | null;
  historyRunId: string;
  historyRunContentHash: string;
  apiAuditDigest: string | null;
  apiDiagnosticStatus: string | null;
  contractFailures: string[];
  verifierFailures: string[];
  persistedCatalogTuples: ReleaseCatalogTuple[];
  catalogCaptureReceiptTags: string[];
  catalogCaptureReceiptStableCount: number;
  catalogCaptureReceiptPrereleaseCount: number;
  catalogCaptureReceiptLatestStableTuple: ReleaseCatalogTuple | null;
  refreshReceiptArtifactIdentityTuples: ReleaseArtifactIdentityTuple[];
  catalogCaptureReceiptCount: number;
  catalogCaptureReceiptSource: string | null;
};

function helperEnvironment(dir: string): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return {
    ...env,
    DB_PATH: join(dir, 'radar.db'),
    DOTENV_CONFIG_PATH: requiredEnv('DOTENV_CONFIG_PATH'),
    GITHUB_TOKEN: '',
    GITHUB_PERSONAL_ACCESS_TOKEN: '',
    OPENAI_API_KEY: '',
    OC_OPENAI_API_KEY: '',
    REFRESH_ON_STARTUP: 'false',
    REFRESH_MINUTES: '0',
    RELEASES_LIMIT: '1',
    COMPARISON_API_ENABLED: 'false',
    RADAR_DB_READ_ONLY: '0',
  };
}

function runScenario(scenario: string): ScenarioResult {
  const dir = mkdtempSync(
    join(privateArtifactRoot, `radar-scorer-verifier-${scenario}-`),
  );
  try {
    const clean = runHelper({
      dir,
      executable: composedHelper,
      args: ['clean'],
      prefix: 'COMPOSED_E2E_RESULT=',
      bootstrapMode: 'fresh',
    });
    assert.deepEqual(clean.scoreContractFailures, []);
    assert.deepEqual(clean.ledgerProblems, []);
    assert.deepEqual(clean.linkProblems, []);
    assert.deepEqual(clean.apiVerificationProblems, []);
    assert.deepEqual(clean.releaseAuditFailures, []);
    assert.equal(clean.apiReceiptVerified, true);
    assert.equal(clean.apiSemanticLinksVerified, true);
    assertExactCatalogEvidence(clean);
    return runHelper({
      dir,
      executable: helper,
      args: [
        scenario,
        String(clean.runId),
        String(clean.historyRunId),
        String(clean.historyRunContentHash),
      ],
      prefix: 'CONTRACT_E2E_RESULT=',
      bootstrapMode: 'existing',
    }) as ScenarioResult;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function assertExactCatalogEvidence(
  result: Pick<
    ScenarioResult,
    | 'persistedCatalogTuples'
    | 'catalogCaptureReceiptTags'
    | 'catalogCaptureReceiptStableCount'
    | 'catalogCaptureReceiptPrereleaseCount'
    | 'catalogCaptureReceiptLatestStableTuple'
    | 'refreshReceiptArtifactIdentityTuples'
    | 'catalogCaptureReceiptCount'
    | 'catalogCaptureReceiptSource'
  >,
): void {
  assert.equal(result.catalogCaptureReceiptCount, 1);
  assert.equal(result.catalogCaptureReceiptSource, 'test_fixture');
  assert.deepEqual(result.persistedCatalogTuples, exactCatalogOracle);
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
      result.persistedCatalogTuples.some((tuple) => tuple[0] === phantomTag),
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
        (tuple) => tuple[0] === phantomTag,
      ),
      false,
      `refresh receipt must not contain phantom tag ${phantomTag}`,
    );
  }
}

function runHelper(input: {
  dir: string;
  executable: string;
  args: string[];
  prefix: string;
  bootstrapMode: 'fresh' | 'existing';
}): any {
  const result = spawnSync(tsx, [input.executable, ...input.args], {
    cwd: root,
    env: {
      ...helperEnvironment(input.dir),
      RADAR_DB_BOOTSTRAP_MODE: input.bootstrapMode,
    },
    encoding: 'utf8',
    timeout: 120_000,
  });
  assert.equal(
    result.status,
    0,
    `${input.args.join(':')} helper failed:\n${result.stdout}\n${result.stderr}`,
  );
  const line = result.stdout
    .split(/\r?\n/)
    .find((candidate) => candidate.startsWith(input.prefix));
  assert.ok(
    line,
    `${input.args.join(':')} helper did not emit its result:\n${result.stdout}`,
  );
  return JSON.parse(line.slice(input.prefix.length));
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

describe('scorer-to-verifier contract E2E', () => {
  it('publishes a real scored and sealed SQLite audit through the API and verifier', () => {
    const result = runScenario('baseline');
    assertExactCatalogEvidence(result);
    assert.match(result.historyRunId, /^refresh:/);
    assert.match(result.historyRunContentHash, /^[0-9a-f]{64}$/);
    assert.match(result.apiAuditDigest ?? '', /^[0-9a-f]{64}$/);
    assert.equal(result.apiDiagnosticStatus, null);
    assert.deepEqual(result.contractFailures, []);
    assert.deepEqual(result.verifierFailures, []);
  });

  const tamperCases = [
    {
      scenario: 'score',
      verifierPattern: /final_score|score record mismatch|sealed history tip/i,
    },
    {
      scenario: 'source-identity',
      verifierPattern: /source (?:identity|provenance)|sealed history tip/i,
    },
    {
      scenario: 'ledger',
      verifierPattern: /scoreLedger|sealed history tip/i,
    },
    {
      scenario: 'recommendation',
      verifierPattern: /recommendationDecision|recommendation decision|sealed history tip/i,
    },
    {
      scenario: 'missing-proof',
      verifierPattern: /closure proofs .* must cover|closure proof.*missing|closure dependency/i,
    },
  ];

  for (const testCase of tamperCases) {
    it(`rejects ${testCase.scenario} tampering`, () => {
      const result = runScenario(testCase.scenario);
      assertExactCatalogEvidence(result);
      assert.equal(result.apiAuditDigest, null);
      assert.equal(result.apiDiagnosticStatus, 'eligible');
      assert.match(result.verifierFailures.join('\n'), testCase.verifierPattern);
    });
  }
});
