import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { canonicalJson } from './operationReceipts.ts';
import {
  projectReleaseCatalogActiveRows,
  releaseCatalogCaptureReceiptContentHash,
  releaseCatalogCaptureReceiptId,
  releaseCatalogCaptureReceiptPayloadProblems,
  verifyReleaseCatalogCaptureReceiptLedger,
  type ReleaseCatalogActiveProjectionRow,
  type ReleaseCatalogCaptureActiveCatalog,
  type ReleaseCatalogCaptureLedgerVerification,
  type ReleaseCatalogCaptureOperationAttemptRow,
  type ReleaseCatalogCaptureReceiptPayload,
  type ReleaseCatalogCaptureReceiptStorageRow,
  type ReleaseCatalogCaptureTerminalReceiptRow,
} from './releaseCatalogReceipt.ts';

const REPOSITORY = 'openclaw/openclaw';
const FOREIGN_REPOSITORY = 'attacker/openclaw';
const OPERATION = 'refresh';

type CatalogRow = Omit<
  ReleaseCatalogActiveProjectionRow,
  'catalog_rank'
>;

type GithubFixture = {
  payload: ReleaseCatalogCaptureReceiptPayload;
  row: ReleaseCatalogCaptureReceiptStorageRow;
  attempt: ReleaseCatalogCaptureOperationAttemptRow;
  terminal: ReleaseCatalogCaptureTerminalReceiptRow;
};

const RELEASE_V1: CatalogRow = releaseRow({
  tag: 'v1.0.0',
  nodeId: 'RE_release_v1',
  oid: '1'.repeat(40),
  publishedAt: '2026-07-01T12:00:00.000Z',
  prerelease: false,
});
const RELEASE_V2_BETA: CatalogRow = releaseRow({
  tag: 'v2.0.0-beta.1',
  nodeId: 'RE_release_v2_beta_1',
  oid: '2'.repeat(40),
  publishedAt: '2026-07-02T12:00:00.000Z',
  prerelease: true,
});
const RELEASE_V2: CatalogRow = releaseRow({
  tag: 'v2.0.0',
  nodeId: 'RE_release_v2',
  oid: '3'.repeat(40),
  publishedAt: '2026-07-03T12:00:00Z',
  prerelease: false,
});
const PHANTOM_RELEASE: CatalogRow = releaseRow({
  tag: 'v9.9.9',
  nodeId: 'RE_phantom_release',
  oid: '9'.repeat(40),
  publishedAt: '2026-07-04T12:00:00.000Z',
  prerelease: false,
});

const INITIAL_CATALOG = activeCatalog([RELEASE_V1]);
const BETA_CATALOG = activeCatalog([RELEASE_V2_BETA, RELEASE_V1]);
const CURRENT_CATALOG = activeCatalog([
  RELEASE_V2,
  RELEASE_V2_BETA,
  RELEASE_V1,
]);

describe('release catalog capture receipt ledger', () => {
  it('accepts an immutable GitHub capture bound to its exact successful run', () => {
    const fixture = githubFixture({
      activeCatalog: CURRENT_CATALOG,
    });

    const verification = verify({
      receipts: [fixture.row],
      attempts: [fixture.attempt],
      terminalReceipts: [fixture.terminal],
      activeCatalog: CURRENT_CATALOG,
    });

    assert.deepEqual(verification.ledgerProblems, []);
    assert.deepEqual(verification.currentProblems, []);
    assert.deepEqual(verification.problems, []);
    assert.equal(verification.receiptCount, 1);
    assert.equal(verification.latestReceiptId, fixture.row.receipt_id);
    assert.equal(
      verification.latestOperationRunId,
      fixture.payload.operationRunId,
    );
    assert.equal(verification.latestSource, 'github_graphql');
    assert.deepEqual(verification.latestPayload, fixture.payload);
  });

  it('accepts GitHub whole-second UTC timestamps but rejects offset aliases', () => {
    const fixture = githubFixture({
      activeCatalog: CURRENT_CATALOG,
    });
    assert.deepEqual(
      releaseCatalogCaptureReceiptPayloadProblems(fixture.payload),
      [],
    );

    const offsetAlias = structuredClone(fixture.payload);
    offsetAlias.activeCatalog.latestStable!.publishedAt =
      '2026-07-03T08:00:00-04:00';
    assert.match(
      releaseCatalogCaptureReceiptPayloadProblems(offsetAlias).join('; '),
      /latestStable publishedAt must be a canonical ISO timestamp/,
    );
  });

  it('fails closed when the latest run has no catalog capture receipt', () => {
    const receiptlessRun = githubFixture({
      activeCatalog: CURRENT_CATALOG,
    });

    const verification = verify({
      receipts: [],
      attempts: [receiptlessRun.attempt],
      terminalReceipts: [receiptlessRun.terminal],
      activeCatalog: CURRENT_CATALOG,
    });

    assert.deepEqual(verification.ledgerProblems, [
      'successful refresh operation "refresh-run-1" has no release catalog capture receipt',
    ]);
    assert.deepEqual(verification.currentProblems, [
      'active release catalog has no valid immutable capture receipt',
    ]);
    assert.equal(verification.latestReceiptId, null);
    assert.equal(verification.latestOperationRunId, null);
  });

  it('rejects failed and abandoned latest capture runs as read authority', () => {
    for (const status of ['failure', 'abandoned']) {
      const fixture = githubFixture({
        activeCatalog: CURRENT_CATALOG,
        terminalStatus: status,
      });

      const verification = verify({
        receipts: [fixture.row],
        attempts: [fixture.attempt],
        terminalReceipts: [fixture.terminal],
        activeCatalog: CURRENT_CATALOG,
      });

      assert.deepEqual(
        verification.ledgerProblems,
        [],
        `${status}: ${problemText(verification)}`,
      );
      assert.deepEqual(verification.currentProblems, [
        `latest GitHub catalog capture run terminated with ${status}`,
      ]);
    }
  });

  it('detects payload, storage-column, content-hash, and receipt-ID tampering', () => {
    const fixture = githubFixture({
      activeCatalog: CURRENT_CATALOG,
    });
    const payloadTampered = structuredClone(fixture.row);
    const changedPayload = structuredClone(fixture.payload);
    changedPayload.observedAt =
      '2026-07-07T12:01:01.000Z';
    payloadTampered.payload_json = canonicalJson(changedPayload);

    const cases: Array<{
      name: string;
      row: ReleaseCatalogCaptureReceiptStorageRow;
      patterns: RegExp[];
    }> = [
      {
        name: 'payload',
        row: payloadTampered,
        patterns: [
          /storage columns do not match its canonical payload/,
          /content hash mismatch/,
        ],
      },
      {
        name: 'storage column',
        row: {
          ...fixture.row,
          active_release_count: fixture.row.active_release_count + 1,
        },
        patterns: [/storage columns do not match its canonical payload/],
      },
      {
        name: 'content hash',
        row: {
          ...fixture.row,
          content_hash: hash('tampered-content-hash'),
        },
        patterns: [/content hash mismatch/],
      },
      {
        name: 'receipt ID',
        row: {
          ...fixture.row,
          receipt_id: hash('tampered-receipt-id'),
        },
        patterns: [/receipt ID mismatch/],
      },
    ];

    for (const testCase of cases) {
      const verification = verify({
        receipts: [testCase.row],
        attempts: [fixture.attempt],
        terminalReceipts: [fixture.terminal],
        activeCatalog: CURRENT_CATALOG,
      });
      assert.notEqual(
        verification.problems.length,
        0,
        `${testCase.name} tampering was accepted`,
      );
      for (const pattern of testCase.patterns) {
        assert.match(
          problemText(verification),
          pattern,
          testCase.name,
        );
      }
    }
  });

  it('rejects test_fixture authority by default and allows it only explicitly', () => {
    const fixture = testFixtureReceipt(CURRENT_CATALOG);

    const rejected = verify({
      receipts: [fixture],
      attempts: [],
      terminalReceipts: [],
      activeCatalog: CURRENT_CATALOG,
    });
    assert.match(
      problemText(rejected),
      /uses forbidden test_fixture authority/,
    );
    assert.match(
      problemText(rejected),
      /test_fixture catalog receipt cannot authorize product reads or promotion/,
    );

    const allowed = verify({
      receipts: [fixture],
      attempts: [],
      terminalReceipts: [],
      activeCatalog: CURRENT_CATALOG,
      allowTestFixture: true,
    });
    assert.deepEqual(allowed.problems, []);
  });

  it('rejects a foreign configured repository and a foreign effective config', () => {
    const foreignCapture = githubFixture({
      repository: FOREIGN_REPOSITORY,
      attemptRepository: FOREIGN_REPOSITORY,
      activeCatalog: CURRENT_CATALOG,
    });
    const foreignVerification = verify({
      receipts: [foreignCapture.row],
      attempts: [foreignCapture.attempt],
      terminalReceipts: [foreignCapture.terminal],
      activeCatalog: CURRENT_CATALOG,
    });
    assert.deepEqual(foreignVerification.ledgerProblems, []);
    assert.deepEqual(foreignVerification.currentProblems, [
      'latest catalog capture receipt repository does not match configuration',
    ]);

    const wrongEffectiveConfig = githubFixture({
      repository: REPOSITORY,
      attemptRepository: FOREIGN_REPOSITORY,
      activeCatalog: CURRENT_CATALOG,
    });
    const effectiveConfigVerification = verify({
      receipts: [wrongEffectiveConfig.row],
      attempts: [wrongEffectiveConfig.attempt],
      terminalReceipts: [wrongEffectiveConfig.terminal],
      activeCatalog: CURRENT_CATALOG,
    });
    assert.match(
      problemText(effectiveConfigVerification),
      /repository does not match the operation effective config/,
    );
    assert.deepEqual(effectiveConfigVerification.currentProblems, []);
  });

  it('rejects the wrong operation, attempt hash, and operation run', () => {
    const wrongOperation = githubFixture({
      activeCatalog: CURRENT_CATALOG,
      operation: 'refresh-catalog',
      attemptOperation: OPERATION,
    });
    const wrongHash = githubFixture({
      activeCatalog: CURRENT_CATALOG,
      payloadAttemptContentHash: hash('wrong-attempt-hash'),
    });
    const wrongRunBase = githubFixture({
      activeCatalog: CURRENT_CATALOG,
    });
    const wrongRunPayload = structuredClone(wrongRunBase.payload);
    wrongRunPayload.operationRunId = 'missing-refresh-run';
    const wrongRun = {
      row: sealReceipt(
        wrongRunPayload,
        wrongRunBase.row.id,
        wrongRunBase.row.previous_content_hash,
      ),
      terminal: terminalReceipt(wrongRunPayload),
    };

    const cases = [
      {
        name: 'operation',
        receipts: [wrongOperation.row],
        attempts: [wrongOperation.attempt],
        terminalReceipts: [wrongOperation.terminal],
        pattern: /does not bind the exact refresh operation attempt/,
      },
      {
        name: 'attempt hash',
        receipts: [wrongHash.row],
        attempts: [wrongHash.attempt],
        terminalReceipts: [wrongHash.terminal],
        pattern: /does not bind the exact refresh operation attempt/,
      },
      {
        name: 'run',
        receipts: [wrongRun.row],
        attempts: [wrongRunBase.attempt],
        terminalReceipts: [wrongRun.terminal],
        pattern: /references a missing refresh operation attempt/,
      },
    ];

    for (const testCase of cases) {
      const verification = verify({
        receipts: testCase.receipts,
        attempts: testCase.attempts,
        terminalReceipts: testCase.terminalReceipts,
        activeCatalog: CURRENT_CATALOG,
      });
      assert.match(
        problemText(verification),
        testCase.pattern,
        testCase.name,
      );
      assert.deepEqual(
        verification.currentProblems,
        [],
        `${testCase.name}: ${problemText(verification)}`,
      );
    }
  });

  it('rejects the wrong active projection digest and tag order', () => {
    const fixture = githubFixture({
      activeCatalog: CURRENT_CATALOG,
    });
    const wrongDigest = structuredClone(CURRENT_CATALOG);
    wrongDigest.digest = hash('wrong-active-projection');
    const wrongOrder = structuredClone(CURRENT_CATALOG);
    wrongOrder.tags.reverse();

    for (const activeCatalog of [wrongDigest, wrongOrder]) {
      const verification = verify({
        receipts: [fixture.row],
        attempts: [fixture.attempt],
        terminalReceipts: [fixture.terminal],
        activeCatalog,
      });
      assert.deepEqual(verification.ledgerProblems, []);
      assert.deepEqual(verification.currentProblems, [
        'latest catalog capture receipt does not match the exact active catalog projection',
      ]);
    }
  });

  it('rejects prerelease flag drift against the captured catalog', () => {
    const betaAsStable = structuredClone(BETA_CATALOG);
    betaAsStable.stableCount = 2;
    betaAsStable.prereleaseCount = 0;
    betaAsStable.latestStable = latestStable(RELEASE_V2_BETA);
    const fixture = githubFixture({
      activeCatalog: betaAsStable,
    });

    const verification = verify({
      receipts: [fixture.row],
      attempts: [fixture.attempt],
      terminalReceipts: [fixture.terminal],
      activeCatalog: BETA_CATALOG,
    });

    assert.deepEqual(verification.ledgerProblems, []);
    assert.deepEqual(verification.currentProblems, [
      'latest catalog capture receipt does not match the exact active catalog projection',
    ]);
    const driftedProjection = projectReleaseCatalogActiveRows([
      {
        ...RELEASE_V2_BETA,
        catalog_rank: 0,
        prerelease: false,
      },
      {
        ...RELEASE_V1,
        catalog_rank: 1,
      },
    ]);
    assert.equal(driftedProjection.stableCount, 2);
    assert.equal(driftedProjection.prereleaseCount, 0);
  });

  it('treats captured GitHub prerelease metadata as authoritative over tag spelling', () => {
    for (const tag of [
      'v2.0.0-beta5',
      'v2026.5.3-1',
      'v2099.1.1-preview.1',
      'v2099.1.1-canary',
    ]) {
      const projection = projectReleaseCatalogActiveRows([{
        ...RELEASE_V1,
        tag,
        catalog_rank: 0,
        prerelease: false,
      }]);
      assert.equal(projection.stableCount, 1, tag);
      assert.equal(projection.latestStable?.tag, tag);
    }
  });

  it('accepts canonical boolean or SQLite prerelease states only', () => {
    for (const [prerelease, expected] of [
      [false, 0],
      [true, 1],
      [0, 0],
      [1, 1],
    ] as const) {
      const projection = projectReleaseCatalogActiveRows([{
        ...RELEASE_V2_BETA,
        catalog_rank: 0,
        prerelease,
      }]);
      assert.equal(projection.prereleaseCount, expected);
      assert.equal(projection.stableCount, expected === 0 ? 1 : 0);
    }

    for (const prerelease of ['false', '', null, {}, -1, 2]) {
      assert.throws(
        () => projectReleaseCatalogActiveRows([{
          ...RELEASE_V2_BETA,
          catalog_rank: 0,
          prerelease,
        }]),
        /invalid prerelease state/,
        String(prerelease),
      );
    }
  });

  it('does not derive a base stable tag from a prerelease name', () => {
    const projection = projectReleaseCatalogActiveRows([
      {
        ...RELEASE_V2_BETA,
        catalog_rank: 0,
        name: 'OpenClaw v2.0.0',
      },
      {
        ...RELEASE_V1,
        catalog_rank: 1,
      },
    ]);

    assert.deepEqual(projection.tags, [
      'v2.0.0-beta.1',
      'v1.0.0',
    ]);
    assert.equal(projection.prereleaseCount, 1);
    assert.equal(projection.stableCount, 1);
    assert.equal(projection.latestStable?.tag, 'v1.0.0');
  });

  it('rejects beta tag and name normalization as a stable active projection', () => {
    const fixture = githubFixture({
      activeCatalog: BETA_CATALOG,
    });
    const normalizedBeta: CatalogRow = {
      ...RELEASE_V2_BETA,
      tag: 'v2.0.0',
      name: 'OpenClaw v2.0.0',
      html_url:
        'https://github.com/openclaw/openclaw/releases/tag/v2.0.0',
      prerelease: false,
    };
    const normalizedCatalog = activeCatalog([
      normalizedBeta,
      RELEASE_V1,
    ]);

    assert.equal(
      normalizedCatalog.latestStable?.nodeId,
      RELEASE_V2_BETA.node_id,
    );
    assert.notEqual(normalizedCatalog.digest, BETA_CATALOG.digest);

    const verification = verify({
      receipts: [fixture.row],
      attempts: [fixture.attempt],
      terminalReceipts: [fixture.terminal],
      activeCatalog: normalizedCatalog,
    });

    assert.deepEqual(verification.ledgerProblems, []);
    assert.deepEqual(verification.currentProblems, [
      'latest catalog capture receipt does not match the exact active catalog projection',
    ]);
  });

  it('rejects a phantom extra tag absent from the active projection', () => {
    const phantomCatalog = activeCatalog([
      PHANTOM_RELEASE,
      RELEASE_V2,
      RELEASE_V2_BETA,
      RELEASE_V1,
    ]);
    const fixture = githubFixture({
      activeCatalog: phantomCatalog,
    });

    const verification = verify({
      receipts: [fixture.row],
      attempts: [fixture.attempt],
      terminalReceipts: [fixture.terminal],
      activeCatalog: CURRENT_CATALOG,
    });

    assert.deepEqual(verification.ledgerProblems, []);
    assert.deepEqual(verification.currentProblems, [
      'latest catalog capture receipt does not match the exact active catalog projection',
    ]);
  });

  it('fails closed on a deleted tip and an appended catalog rollback', () => {
    const chain = githubLedger([
      INITIAL_CATALOG,
      BETA_CATALOG,
      CURRENT_CATALOG,
    ]);

    const deletedTip = verify({
      receipts: chain.receipts.slice(0, -1),
      attempts: chain.attempts,
      terminalReceipts: chain.terminalReceipts,
      activeCatalog: CURRENT_CATALOG,
    });
    assert.deepEqual(deletedTip.ledgerProblems, [
      'successful refresh operation "refresh-run-3" has no release catalog capture receipt',
    ]);
    assert.deepEqual(deletedTip.currentProblems, [
      'latest catalog capture receipt does not match the exact active catalog projection',
    ]);

    const rollback = githubFixture({
      id: 4,
      runId: 'refresh-run-4',
      observedAt: '2026-07-07T12:20:00.000Z',
      activeCatalog: INITIAL_CATALOG,
      previousContentHash: chain.receipts.at(-1)!.content_hash,
    });
    const rollbackVerification = verify({
      receipts: [...chain.receipts, rollback.row],
      attempts: [...chain.attempts, rollback.attempt],
      terminalReceipts: [...chain.terminalReceipts, rollback.terminal],
      activeCatalog: CURRENT_CATALOG,
    });
    assert.deepEqual(rollbackVerification.ledgerProblems, []);
    assert.deepEqual(rollbackVerification.currentProblems, [
      'latest catalog capture receipt does not match the exact active catalog projection',
    ]);
  });

  it('rejects a later successful refresh run without a catalog capture receipt', () => {
    const authorized = githubFixture({
      activeCatalog: CURRENT_CATALOG,
    });
    const receiptless = githubFixture({
      id: 2,
      runId: 'refresh-run-without-catalog-receipt',
      observedAt: '2026-07-07T12:20:00.000Z',
      activeCatalog: CURRENT_CATALOG,
      previousContentHash: authorized.row.content_hash,
    });

    const verification = verify({
      receipts: [authorized.row],
      attempts: [authorized.attempt, receiptless.attempt],
      terminalReceipts: [
        authorized.terminal,
        receiptless.terminal,
      ],
      activeCatalog: CURRENT_CATALOG,
    });

    assert.match(
      problemText(verification),
      /successful refresh operation "refresh-run-without-catalog-receipt" has no release catalog capture receipt/,
    );
    assert.deepEqual(verification.currentProblems, []);
  });

  it('detects reordered and re-rooted stored chains before authorization', () => {
    const chain = githubLedger([
      INITIAL_CATALOG,
      BETA_CATALOG,
      CURRENT_CATALOG,
    ]);
    const reordered = structuredClone(chain.receipts);
    [reordered[0].id, reordered[1].id] = [
      reordered[1].id,
      reordered[0].id,
    ];

    const reorderedVerification = verify({
      receipts: reordered,
      attempts: chain.attempts,
      terminalReceipts: chain.terminalReceipts,
      activeCatalog: CURRENT_CATALOG,
    });
    assert.match(
      problemText(reorderedVerification),
      /previous content hash mismatch/,
    );
    assert.match(
      problemText(reorderedVerification),
      /content hash mismatch/,
    );
    assert.deepEqual(reorderedVerification.currentProblems, []);

    const rerootedVerification = verify({
      receipts: chain.receipts.slice(1),
      attempts: chain.attempts,
      terminalReceipts: chain.terminalReceipts,
      activeCatalog: CURRENT_CATALOG,
    });
    assert.match(
      problemText(rerootedVerification),
      /previous content hash mismatch/,
    );
    assert.match(
      problemText(rerootedVerification),
      /content hash mismatch/,
    );
    assert.deepEqual(rerootedVerification.currentProblems, []);
  });

  it('rejects a fully recomputed chain that rewrites repository authority', () => {
    const chain = githubLedger([
      INITIAL_CATALOG,
      BETA_CATALOG,
      CURRENT_CATALOG,
    ]);
    const rewrittenPayload = structuredClone(chain.fixtures[1].payload);
    rewrittenPayload.repository = FOREIGN_REPOSITORY;
    rewrittenPayload.remoteCatalog!.repositoryNameWithOwner =
      FOREIGN_REPOSITORY;
    const rewrittenSecond = sealReceipt(
      rewrittenPayload,
      chain.receipts[1].id,
      chain.receipts[0].content_hash,
    );
    const recomputedThird = sealReceipt(
      chain.fixtures[2].payload,
      chain.receipts[2].id,
      rewrittenSecond.content_hash,
    );

    const verification = verify({
      receipts: [
        chain.receipts[0],
        rewrittenSecond,
        recomputedThird,
      ],
      attempts: chain.attempts,
      terminalReceipts: chain.terminalReceipts,
      activeCatalog: CURRENT_CATALOG,
    });
    const problems = problemText(verification);

    assert.match(
      problems,
      /repository does not match the operation effective config/,
    );
    assert.doesNotMatch(problems, /previous content hash mismatch/);
    assert.doesNotMatch(problems, /content hash mismatch/);
    assert.doesNotMatch(problems, /receipt ID mismatch/);
    assert.deepEqual(verification.currentProblems, []);
  });
});

function releaseRow(input: {
  tag: string;
  nodeId: string;
  oid: string;
  publishedAt: string;
  prerelease: boolean;
}): CatalogRow {
  return {
    node_id: input.nodeId,
    catalog_tag_commit_oid: input.oid,
    tag: input.tag,
    name: input.tag,
    published_at: input.publishedAt,
    created_at: input.publishedAt,
    updated_at: input.publishedAt,
    html_url: `https://github.com/openclaw/openclaw/releases/tag/${input.tag}`,
    prerelease: input.prerelease,
    body: `${input.tag} release notes`,
  };
}

function activeCatalog(
  rows: readonly CatalogRow[],
): ReleaseCatalogCaptureActiveCatalog {
  const projection = projectReleaseCatalogActiveRows(
    rows.map((row, catalogRank) => ({
      ...row,
      catalog_rank: catalogRank,
    })),
  );
  return {
    digest: projection.digest,
    releaseCount: projection.releaseCount,
    stableCount: projection.stableCount,
    prereleaseCount: projection.prereleaseCount,
    tags: [...projection.tags],
    latestStable: projection.latestStable
      ? { ...projection.latestStable }
      : null,
  };
}

function githubFixture(options: {
  id?: number;
  runId?: string;
  observedAt?: string;
  activeCatalog?: ReleaseCatalogCaptureActiveCatalog;
  previousContentHash?: string | null;
  repository?: string;
  attemptRepository?: string;
  operation?: string;
  attemptOperation?: string;
  attemptContentHash?: string;
  payloadAttemptContentHash?: string;
  terminalStatus?: string;
} = {}): GithubFixture {
  const id = options.id ?? 1;
  const runId = options.runId ?? `refresh-run-${id}`;
  const observedAt =
    options.observedAt ?? `2026-07-07T12:${String(id).padStart(2, '0')}:00.000Z`;
  const repository = options.repository ?? REPOSITORY;
  const attemptRepository = options.attemptRepository ?? repository;
  const active = structuredClone(options.activeCatalog ?? CURRENT_CATALOG);
  const operation = options.operation ?? OPERATION;
  const attemptOperation = options.attemptOperation ?? operation;
  const attemptContentHash =
    options.attemptContentHash ?? hash(`attempt:${runId}`);
  const [owner, repo] = attemptRepository.split('/');
  const attempt: ReleaseCatalogCaptureOperationAttemptRow = {
    run_id: runId,
    operation: attemptOperation,
    started_at: offsetTimestamp(observedAt, -30_000),
    effective_config_json: canonicalJson({
      github: { owner, repo },
      schemaVersion: 1,
    }),
    content_hash: attemptContentHash,
  };
  const payload: ReleaseCatalogCaptureReceiptPayload = {
    schemaVersion: 1,
    source: 'github_graphql',
    repository,
    observedAt,
    operationRunId: runId,
    operation,
    operationAttemptContentHash:
      options.payloadAttemptContentHash ?? attemptContentHash,
    remoteCatalog: {
      repositoryNodeId: `R_${repository.replace('/', '_')}`,
      repositoryNameWithOwner: repository,
      digest: hash(`remote:${runId}:${active.digest}`),
      totalCount: active.releaseCount + 1,
      nodeCount: active.releaseCount + 1,
      publishedCount: active.releaseCount,
      draftCount: 1,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      sweepPageCounts: [1, 1],
      exhausted: true,
      stabilized: true,
      sourceOrder: 'CREATED_AT_DESC',
    },
    activeCatalog: active,
  };
  return {
    payload,
    row: sealReceipt(
      payload,
      id,
      options.previousContentHash ?? null,
    ),
    attempt,
    terminal: terminalReceipt(
      payload,
      options.terminalStatus ?? 'success',
    ),
  };
}

function terminalReceipt(
  payload: ReleaseCatalogCaptureReceiptPayload,
  status = 'success',
): ReleaseCatalogCaptureTerminalReceiptRow {
  return {
    run_id: payload.operationRunId!,
    status,
    finished_at: offsetTimestamp(payload.observedAt, 30_000),
    payload_json: canonicalJson({
      schemaVersion: 3,
      operation: payload.operation,
      releaseCatalog: {
        digest: payload.remoteCatalog!.digest,
        nodeCount: payload.remoteCatalog!.nodeCount,
        totalCount: payload.remoteCatalog!.totalCount,
        attestation: {
          localActiveCatalog: {
            digest: payload.activeCatalog.digest,
            releaseCount: payload.activeCatalog.releaseCount,
          },
          latestStable: payload.activeCatalog.latestStable,
        },
      },
    }),
  };
}

function testFixtureReceipt(
  active: ReleaseCatalogCaptureActiveCatalog,
): ReleaseCatalogCaptureReceiptStorageRow {
  const payload: ReleaseCatalogCaptureReceiptPayload = {
    schemaVersion: 1,
    source: 'test_fixture',
    repository: REPOSITORY,
    observedAt: '2026-07-07T12:00:00.000Z',
    operationRunId: null,
    operation: null,
    operationAttemptContentHash: null,
    remoteCatalog: null,
    activeCatalog: structuredClone(active),
  };
  return sealReceipt(payload, 1, null);
}

function sealReceipt(
  payload: ReleaseCatalogCaptureReceiptPayload,
  id: number,
  previousContentHash: string | null,
): ReleaseCatalogCaptureReceiptStorageRow {
  const contentHash = releaseCatalogCaptureReceiptContentHash({
    payload,
    previousContentHash,
  });
  return {
    id,
    receipt_id: releaseCatalogCaptureReceiptId(contentHash),
    operation_run_id: payload.operationRunId,
    source_kind: payload.source,
    repository: payload.repository,
    observed_at: payload.observedAt,
    active_catalog_digest: payload.activeCatalog.digest,
    active_release_count: payload.activeCatalog.releaseCount,
    payload_json: canonicalJson(payload),
    previous_content_hash: previousContentHash,
    content_hash: contentHash,
  };
}

function githubLedger(
  catalogs: readonly ReleaseCatalogCaptureActiveCatalog[],
): {
  fixtures: GithubFixture[];
  receipts: ReleaseCatalogCaptureReceiptStorageRow[];
  attempts: ReleaseCatalogCaptureOperationAttemptRow[];
  terminalReceipts: ReleaseCatalogCaptureTerminalReceiptRow[];
} {
  const fixtures: GithubFixture[] = [];
  let previousContentHash: string | null = null;
  for (const [index, catalog] of catalogs.entries()) {
    const id = index + 1;
    const fixture = githubFixture({
      id,
      runId: `refresh-run-${id}`,
      observedAt:
        `2026-07-07T12:${String(index * 5).padStart(2, '0')}:00.000Z`,
      activeCatalog: catalog,
      previousContentHash,
    });
    fixtures.push(fixture);
    previousContentHash = fixture.row.content_hash;
  }
  return {
    fixtures,
    receipts: fixtures.map((fixture) => fixture.row),
    attempts: fixtures.map((fixture) => fixture.attempt),
    terminalReceipts: fixtures.map((fixture) => fixture.terminal),
  };
}

function verify(input: {
  receipts: readonly ReleaseCatalogCaptureReceiptStorageRow[];
  attempts: readonly ReleaseCatalogCaptureOperationAttemptRow[];
  terminalReceipts: readonly ReleaseCatalogCaptureTerminalReceiptRow[];
  activeCatalog: ReleaseCatalogCaptureActiveCatalog;
  allowTestFixture?: boolean;
}): ReleaseCatalogCaptureLedgerVerification {
  return verifyReleaseCatalogCaptureReceiptLedger({
    ...input,
    expectedRepository: REPOSITORY,
  });
}

function latestStable(row: CatalogRow): NonNullable<
  ReleaseCatalogCaptureActiveCatalog['latestStable']
> {
  return {
    nodeId: row.node_id!,
    tag: row.tag,
    tagCommitOid: row.catalog_tag_commit_oid!,
    publishedAt: row.published_at!,
  };
}

function offsetTimestamp(value: string, offsetMs: number): string {
  return new Date(Date.parse(value) + offsetMs).toISOString();
}

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function problemText(
  verification: ReleaseCatalogCaptureLedgerVerification,
): string {
  return verification.problems.join('\n');
}
