import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { CLOSURE_PROOF_STATUSES, CLOSURE_RISK_DISPOSITIONS } from './closureProofTaxonomy.ts';
import {
  scoreSourceIdentityManifestDigest,
  scoreSourceIdentityManifestProblems,
} from './scoreSourceIdentity.ts';
import {
  bindScoreExplanationAudit,
  buildScoreLedgerV2,
  installConfidence,
  SCORE_MODEL_VERSION,
} from './score.ts';
import {
  canonicalJson,
  operationAttemptConfigHash,
  operationAttemptContentHash,
  operationCaptureReceiptContentHash,
  operationCaptureReceiptId,
} from './operationReceipts.ts';
import {
  projectReleaseCatalogActiveRows,
  releaseCatalogCaptureReceiptContentHash,
  releaseCatalogCaptureReceiptId,
} from './releaseCatalogReceipt.ts';
import { resolveReleaseAuditInvocation } from '../../scripts/lib/release-audit-cli.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownsTestDir = assignedWorkerDatabasePath === null;
const testDir = assignedWorkerDatabasePath
  ? dirname(assignedWorkerDatabasePath)
  : mkdtempSync(join(tmpdir(), 'radar-release-audit-test-'));
const cliReadOnlyDir = mkdtempSync(
  join(testDir, 'radar-release-audit-read-only-'),
);
const cliReadOnlyPath = join(cliReadOnlyDir, 'radar.db');
const cliEmptyDotenvPath = join(cliReadOnlyDir, 'empty.env');
writeFileSync(cliEmptyDotenvPath, '', { flag: 'wx', mode: 0o600 });
const testDatabasePath =
  assignedWorkerDatabasePath ?? join(testDir, 'radar.db');
if (assignedWorkerDatabasePath) {
  assert.equal(
    process.env.DB_PATH,
    assignedWorkerDatabasePath,
    'release audit tests must use their assigned worker database',
  );
} else {
  process.env.DB_PATH = testDatabasePath;
}
let verifyReleaseAudit: typeof import('../../scripts/lib/release-audit-invariants.mjs').verifyReleaseAudit;
let releaseAuditInvariantTest:
  typeof import('../../scripts/lib/release-audit-invariants.mjs').__releaseAuditInvariantTest;
let openReleaseAuditReader:
  typeof import('../../scripts/lib/release-audit-reader.mjs').openReleaseAuditReader;
let releaseClosureDependencyMembership:
  typeof import('../../scripts/lib/release-audit-reader.mjs').releaseClosureDependencyMembership;
let RELEASE_ISSUE_EVIDENCE_TIERS: typeof import('./releaseIssueEvidence.ts').RELEASE_ISSUE_EVIDENCE_TIERS;
let RELEASE_ISSUE_EVIDENCE_TIER_INFO:
  typeof import('./releaseIssueEvidence.ts').RELEASE_ISSUE_EVIDENCE_TIER_INFO;
let CLASSIFICATION_PROMPT_TEMPLATE_HASH:
  typeof import('./llm.ts').CLASSIFICATION_PROMPT_TEMPLATE_HASH;
let testDb: typeof import('./db.ts').db;

before(async () => {
  initializeProductionSchema(cliReadOnlyPath);
  seedReceiptBackedTestCatalog(cliReadOnlyPath);
  ({
    verifyReleaseAudit,
    __releaseAuditInvariantTest: releaseAuditInvariantTest,
  } = await import('../../scripts/lib/release-audit-invariants.mjs'));
  ({ openReleaseAuditReader, releaseClosureDependencyMembership } =
    await import('../../scripts/lib/release-audit-reader.mjs'));
  ({
    RELEASE_ISSUE_EVIDENCE_TIERS,
    RELEASE_ISSUE_EVIDENCE_TIER_INFO,
  } = await import('./releaseIssueEvidence.ts'));
  ({ CLASSIFICATION_PROMPT_TEMPLATE_HASH } = await import('./llm.ts'));
  ({ db: testDb } = await import('./db.ts'));
});

after(() => {
  try { testDb.close(); } catch { /* already closed or setup failed */ }
  if (ownsTestDir) rmSync(testDir, { recursive: true, force: true });
  rmSync(cliReadOnlyDir, { recursive: true, force: true });
});

function initializeProductionSchema(path: string): void {
  const result = spawnSync(process.execPath, [
    '--import=tsx',
    '--input-type=module',
    '-e',
    `const { db } = (await import('./src/lib/db.ts')).default; db.close();`,
  ], {
    cwd: root,
    env: {
      ...process.env,
      DB_PATH: path,
      DOTENV_CONFIG_PATH:
        process.env.DOTENV_CONFIG_PATH ?? cliEmptyDotenvPath,
      RADAR_DB_BOOTSTRAP_MODE: 'fresh',
      RADAR_DB_READ_ONLY: '0',
    },
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
}

function seedReceiptBackedTestCatalog(path: string): void {
  const database = new DatabaseSync(path);
  const repository = 'openclaw/openclaw';
  const runId = 'release-audit-catalog-fixture';
  const trigger = 'release-audit-fixture';
  const codeRevision = `git:${'a'.repeat(40)}`;
  const startedAt = '2026-07-07T00:00:00.000Z';
  const observedAt = '2026-07-07T00:00:01.000Z';
  const finishedAt = '2026-07-07T00:00:02.000Z';
  const tag = 'v-release-audit-fixture';
  const release = {
    catalog_rank: 0,
    node_id: 'R_release_audit_fixture',
    catalog_tag_commit_oid: createHash('sha1').update(tag).digest('hex'),
    tag,
    name: 'Release audit fixture',
    published_at: startedAt,
    created_at: startedAt,
    updated_at: startedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease: 0,
    body: '',
  };
  const activeCatalog = projectReleaseCatalogActiveRows([release]);
  const remoteCatalog = {
    repositoryNodeId: 'REPO_release_audit_fixture',
    repositoryNameWithOwner: repository,
    digest: createHash('sha256')
      .update(`release-catalog:${repository}:${runId}`)
      .digest('hex'),
    totalCount: 1,
    nodeCount: 1,
    publishedCount: 1,
    draftCount: 0,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    sweepPageCounts: [1, 1],
    exhausted: true as const,
    stabilized: true as const,
    sourceOrder: 'CREATED_AT_DESC' as const,
  };
  const effectiveConfigJson = canonicalJson({
    github: { owner: 'openclaw', repo: 'openclaw' },
    schemaVersion: 1,
  });
  const attempt = {
    run_id: runId,
    operation: 'refresh',
    trigger,
    started_at: startedAt,
    lease_name: 'github-refresh',
    lease_holder_id: `holder-${runId}`,
    lease_expires_at: '2026-07-07T00:05:00.000Z',
    code_revision: codeRevision,
    effective_config_json: effectiveConfigJson,
    effective_config_hash: operationAttemptConfigHash(effectiveConfigJson),
    content_hash: '',
  };
  attempt.content_hash = operationAttemptContentHash({
    runId: attempt.run_id,
    operation: attempt.operation,
    trigger: attempt.trigger,
    startedAt: attempt.started_at,
    leaseName: attempt.lease_name,
    leaseHolderId: attempt.lease_holder_id,
    leaseExpiresAt: attempt.lease_expires_at,
    codeRevision: attempt.code_revision,
    effectiveConfigJson: attempt.effective_config_json,
  });
  const receiptCatalog = {
    digest: remoteCatalog.digest,
    nodeCount: remoteCatalog.nodeCount,
    totalCount: remoteCatalog.totalCount,
    attestation: {
      localActiveCatalog: {
        digest: activeCatalog.digest,
        releaseCount: activeCatalog.releaseCount,
      },
      latestStable: activeCatalog.latestStable,
    },
  };
  const terminalPayloadJson = canonicalJson({
    schemaVersion: 1,
    operation: attempt.operation,
    trigger,
    codeRevision,
    releaseCatalog: receiptCatalog,
  });
  const terminalReceipt = {
    receipt_id: operationCaptureReceiptId(runId),
    run_id: runId,
    status: 'success' as const,
    finished_at: finishedAt,
    duration_ms: 2_000,
    stage_event_count: 0,
    stage_chain_hash: null,
    payload_json: terminalPayloadJson,
    previous_content_hash: null,
    content_hash: '',
  };
  terminalReceipt.content_hash = operationCaptureReceiptContentHash({
    receiptId: terminalReceipt.receipt_id,
    runId: terminalReceipt.run_id,
    status: terminalReceipt.status,
    finishedAt: terminalReceipt.finished_at,
    durationMs: terminalReceipt.duration_ms,
    stageEventCount: terminalReceipt.stage_event_count,
    stageChainHash: terminalReceipt.stage_chain_hash,
    payloadJson: terminalReceipt.payload_json,
    previousContentHash: terminalReceipt.previous_content_hash,
  });
  const catalogPayload = {
    schemaVersion: 1 as const,
    source: 'github_graphql' as const,
    repository,
    observedAt,
    operationRunId: attempt.run_id,
    operation: attempt.operation,
    operationAttemptContentHash: attempt.content_hash,
    remoteCatalog,
    activeCatalog: {
      digest: activeCatalog.digest,
      releaseCount: activeCatalog.releaseCount,
      stableCount: activeCatalog.stableCount,
      prereleaseCount: activeCatalog.prereleaseCount,
      tags: activeCatalog.tags,
      latestStable: activeCatalog.latestStable,
    },
  };
  const catalogContentHash = releaseCatalogCaptureReceiptContentHash({
    payload: catalogPayload,
    previousContentHash: null,
  });

  database.exec('BEGIN IMMEDIATE');
  try {
    database.prepare(`
      INSERT INTO releases (
        tag, node_id, catalog_tag_commit_oid, name, published_at, created_at,
        updated_at, html_url, prerelease, body, catalog_rank, catalog_digest,
        catalog_active
      )
      VALUES (
        :tag, :node_id, :catalog_tag_commit_oid, :name, :published_at, :created_at,
        :updated_at, :html_url, :prerelease, :body, :catalog_rank, :catalog_digest,
        1
      )
    `).run({
      ...release,
      catalog_digest: activeCatalog.digest,
    });
    database.prepare(`
      INSERT INTO refresh_operation_attempts (
        run_id, operation, trigger, started_at, lease_name, lease_holder_id,
        lease_expires_at, code_revision, effective_config_json,
        effective_config_hash, content_hash
      )
      VALUES (
        :run_id, :operation, :trigger, :started_at, :lease_name, :lease_holder_id,
        :lease_expires_at, :code_revision, :effective_config_json,
        :effective_config_hash, :content_hash
      )
    `).run(attempt);
    database.prepare(`
      INSERT INTO refresh_capture_receipts (
        receipt_id, run_id, status, finished_at, duration_ms, stage_event_count,
        stage_chain_hash, payload_json, previous_content_hash, content_hash
      )
      VALUES (
        :receipt_id, :run_id, :status, :finished_at, :duration_ms,
        :stage_event_count, :stage_chain_hash, :payload_json,
        :previous_content_hash, :content_hash
      )
    `).run(terminalReceipt);
    database.prepare(`
      INSERT INTO release_catalog_capture_receipts (
        receipt_id, operation_run_id, source_kind, repository, observed_at,
        active_catalog_digest, active_release_count, payload_json,
        previous_content_hash, content_hash
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      releaseCatalogCaptureReceiptId(catalogContentHash),
      catalogPayload.operationRunId,
      catalogPayload.source,
      catalogPayload.repository,
      catalogPayload.observedAt,
      catalogPayload.activeCatalog.digest,
      catalogPayload.activeCatalog.releaseCount,
      canonicalJson(catalogPayload),
      null,
      catalogContentHash,
    );
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  } finally {
    database.close();
  }
}

function isolatedCliFixtureEnvironment(
  overrides: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ...overrides,
    DOTENV_CONFIG_PATH:
      process.env.DOTENV_CONFIG_PATH ?? cliEmptyDotenvPath,
  };
}

function fileSnapshot(path: string) {
  const stat = statSync(path, { bigint: true });
  return {
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    content: readFileSync(path),
  };
}

describe('release audit verifier CLI', () => {
  it('uses --db-path=B instead of DB_PATH=A for transitive audit imports', () => {
    const unrelatedPath = join(cliReadOnlyDir, 'unrelated-global.db');
    const unrelated = new DatabaseSync(unrelatedPath);
    unrelated.exec(`
      CREATE TABLE unrelated_probe(value TEXT NOT NULL);
      INSERT INTO unrelated_probe(value) VALUES('database-a');
    `);
    unrelated.close();

    const cliArgs = [
      '--db-path',
      cliReadOnlyPath,
      '--all',
    ];
    assert.equal(
      resolveReleaseAuditInvocation(cliArgs, {
        DB_PATH: unrelatedPath,
      }).dbPath,
      cliReadOnlyPath,
    );

    const result = spawnSync(process.execPath, [
      '--import=tsx',
      '--input-type=module',
      '--eval',
      [
        `process.env.DB_PATH = ${JSON.stringify(unrelatedPath)};`,
        `process.argv.splice(`,
        `  1,`,
        `  process.argv.length - 1,`,
        `  'scripts/verify-release-audit-invariants.mjs',`,
        `  ...${JSON.stringify(cliArgs)},`,
        `);`,
        `await import('./scripts/verify-release-audit-invariants.mjs');`,
      ].join('\n'),
    ], {
      cwd: root,
      env: isolatedCliFixtureEnvironment({
        DB_PATH: cliReadOnlyPath,
        RADAR_DB_BOOTSTRAP_MODE: 'existing',
        RADAR_DB_READ_ONLY: '0',
      }),
      encoding: 'utf8',
    });
    const output = `${result.stdout}\n${result.stderr}`;

    assert.equal(result.signal, null, output);
    assert.match(
      output,
      /Release audit invariants passed|release audit invariant failure/,
    );
    const unrelatedObserver = new DatabaseSync(unrelatedPath, { readOnly: true });
    try {
      assert.equal(
        (
          unrelatedObserver.prepare(
            'SELECT value FROM unrelated_probe',
          ).get() as { value: string }
        ).value,
        'database-a',
      );
    } finally {
      unrelatedObserver.close();
    }
  });

  it('does not mutate a WAL database or its visible state', () => {
    const path = cliReadOnlyPath;
    const walPath = `${path}-wal`;
    const shmPath = `${path}-shm`;
    let writer: DatabaseSync | null = null;
    let observer: DatabaseSync | null = null;
    try {
      writer = new DatabaseSync(path);
      writer.exec('PRAGMA journal_mode=WAL');
      writer.exec('PRAGMA wal_autocheckpoint=0');
      writer.exec('DROP INDEX IF EXISTS idx_issues_created_at');
      writer.prepare(`
        INSERT INTO meta(key, value) VALUES('read_only_verifier_probe', 'before')
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
      `).run();
      const visibleStateBefore = writer.prepare(`
        SELECT
          (SELECT value FROM meta WHERE key='read_only_verifier_probe') AS probe,
          EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type='index' AND name='idx_issues_created_at'
          ) AS migration_index_present
      `).get();

      observer = new DatabaseSync(path, { readOnly: true });
      observer.exec('PRAGMA query_only=ON');
      observer.exec('BEGIN');
      observer.prepare(`
        SELECT value FROM meta WHERE key='read_only_verifier_probe'
      `).get();
      assert.equal(existsSync(walPath), true);
      assert.equal(existsSync(shmPath), true);
      assert.ok(statSync(walPath).size > 0);
      const warmup = spawnSync(process.execPath, [
        '--import=tsx',
        'scripts/verify-release-audit-invariants.mjs',
        '--all',
      ], {
        cwd: root,
        env: {
          ...process.env,
          DB_PATH: path,
          RADAR_DB_BOOTSTRAP_MODE: 'existing',
          RADAR_DB_READ_ONLY: '1',
        },
        encoding: 'utf8',
      });
      assert.equal(warmup.signal, null, `${warmup.stdout}\n${warmup.stderr}`);
      chmodSync(path, 0o444);
      chmodSync(walPath, 0o444);
      chmodSync(shmPath, 0o444);
      const dataVersionBefore = Number(
        (observer.prepare('PRAGMA data_version').get() as { data_version: number }).data_version,
      );
      const filesBefore = {
        database: fileSnapshot(path),
        wal: fileSnapshot(walPath),
        shm: fileSnapshot(shmPath),
      };

      const result = spawnSync(process.execPath, [
        '--import=tsx',
        'scripts/verify-release-audit-invariants.mjs',
        '--all',
      ], {
        cwd: root,
        env: {
          ...process.env,
          DB_PATH: path,
          RADAR_DB_BOOTSTRAP_MODE: 'existing',
          RADAR_DB_READ_ONLY: '0',
        },
        encoding: 'utf8',
      });
      const output = `${result.stdout}\n${result.stderr}`;
      assert.equal(result.signal, null, output);
      assert.match(output, /Release audit invariants passed|release audit invariant failure/);

      const dataVersionAfter = Number(
        (observer.prepare('PRAGMA data_version').get() as { data_version: number }).data_version,
      );
      const filesAfter = {
        database: fileSnapshot(path),
        wal: fileSnapshot(walPath),
        shm: fileSnapshot(shmPath),
      };
      const visibleStateAfter = writer.prepare(`
        SELECT
          (SELECT value FROM meta WHERE key='read_only_verifier_probe') AS probe,
          EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type='index' AND name='idx_issues_created_at'
          ) AS migration_index_present
      `).get();

      assert.equal(dataVersionAfter, dataVersionBefore);
      assert.deepEqual(visibleStateAfter, visibleStateBefore);
      assert.deepEqual(filesAfter, filesBefore);
    } finally {
      try {
        observer?.exec('ROLLBACK');
      } catch {
        // The observer may not have reached the pinned transaction.
      }
      observer?.close();
      writer?.close();
    }
  });
});

describe('release audit reader snapshot', () => {
  it('pins one WAL snapshot and limits history lookups to active stable rows', () => {
    const dir = mkdtempSync(join(tmpdir(), 'radar-release-audit-snapshot-'));
    const path = join(dir, 'radar.db');
    let writer: DatabaseSync | null = null;
    let auditDatabase: DatabaseSync | null = null;
    let auditReader: ReturnType<typeof openReleaseAuditReader> | null = null;
    try {
      writer = new DatabaseSync(path);
      writer.exec('PRAGMA journal_mode=WAL');
      writer.exec('PRAGMA wal_autocheckpoint=0');
      writer.exec(`
        CREATE TABLE releases (
          tag TEXT PRIMARY KEY,
          prerelease INTEGER NOT NULL,
          catalog_active INTEGER NOT NULL,
          final_score REAL
        );
        CREATE TABLE release_score_audits (
          release_tag TEXT PRIMARY KEY
        );
        INSERT INTO releases(tag, prerelease, catalog_active, final_score)
        VALUES
          ('v1', 0, 1, 7.5),
          ('v2026.7.1-beta.2', 1, 1, 8.0),
          ('v2026.7.1', 0, 0, NULL),
          ('v2026.6.30', 0, 0, NULL);
      `);

      auditDatabase = new DatabaseSync(path, { readOnly: true });
      auditReader = openReleaseAuditReader(path, {
        database: auditDatabase,
        closeDatabase: false,
        verifyReleaseCatalog: false,
      });
      assert.equal(auditDatabase.isTransaction, true);
      assert.equal(auditReader.scoredStableReleaseCount(), 1);
      const expectedStableHistoryTags = new Set(['v1']);
      for (const tag of [
        'v1',
        'v2026.7.1-beta.2',
        'v2026.7.1',
        'v2026.6.30',
      ]) {
        assert.equal(
          auditReader.getRelease(tag)?.tag ?? null,
          expectedStableHistoryTags.has(tag) ? tag : null,
          tag,
        );
      }

      writer.prepare(`
        INSERT INTO releases(tag, prerelease, catalog_active, final_score)
        VALUES('v2', 0, 1, 8.0)
      `).run();
      assert.equal(
        Number(
          (
            writer.prepare('SELECT COUNT(*) AS count FROM releases').get() as {
              count: number;
            }
          ).count,
        ),
        5,
      );
      assert.equal(auditReader.scoredStableReleaseCount(), 1);

      auditReader.close();
      auditReader = null;
      assert.equal(auditDatabase.isTransaction, false);
      assert.equal(
        Number(
          (
            auditDatabase.prepare(
              'SELECT COUNT(*) AS count FROM releases',
            ).get() as { count: number }
          ).count,
        ),
        5,
      );
    } finally {
      auditReader?.close();
      auditDatabase?.close();
      writer?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const labelTimelineFixture = {
  schemaVersion: 1,
  cutoffAt: null,
  issueCount: 1,
  currentLabelCount: 1,
  timelineLabelCount: 0,
  snapshotLabelCount: 0,
  missingTimelineCount: 0,
  missingTimelineWithCurrentLabelsCount: 0,
  historicalCurrentLabelFallbackAllowed: true,
};
const releaseChecksFixture = {
  schemaVersion: 2,
  state: null,
  total: 0,
  success: 0,
  failure: 0,
  pending: 0,
  skipped: 0,
  contextCount: 0,
  shownContextCount: 0,
  contextsTruncated: false,
  contexts: [],
};
const artifactVerificationFixture = {
  schemaVersion: 2,
  observationId: null,
  receiptId: null,
  evidenceIdentity: null,
  evidenceReportIdentity: null,
  runId: null,
  observedAt: null,
  observationContentHash: null,
  observationPreviousContentHash: null,
  receiptContentHash: null,
  receiptPreviousContentHash: null,
  release: null,
  releaseMetadata: null,
  artifact: null,
  evidenceReport: null,
  npmPackageUrl: null,
  releaseTarballUrl: null,
  releaseIntegrity: null,
  releaseSha: null,
  verified: false,
  releaseShaMatches: null,
  ciReportUrl: null,
  ciReportVerified: false,
  ciReportMismatch: null,
  fullReleaseValidationUrl: null,
  releaseValidationVerified: false,
  releaseValidationMismatch: null,
  registryVersion: null,
  registryIntegrity: null,
  registryTarballUrl: null,
  mismatch: null,
};
const proofCheckedAt = '2026-01-02T00:00:00Z';
const auditScoredAt = '2026-01-02T00:00:01.000Z';
const tagOid = 'a'.repeat(40);
const mergeOid = 'b'.repeat(40);
const predecessorTag = 'v0';
const predecessorOid = 'e'.repeat(40);
const directCommitOid = 'd'.repeat(40);
const classificationSourceIdentityDigest = '9'.repeat(64);

function advisorySnapshotAuditProjectionFixture() {
  const activeMetadata = {
    schemaVersion: 2,
    snapshotId: 1,
    capturedAt: '2026-01-01T23:59:30Z',
    repository: {
      owner: 'openclaw',
      name: 'openclaw',
      url: 'https://github.com/openclaw/openclaw',
    },
    target: {
      ecosystem: 'npm',
      packageName: 'openclaw',
    },
    sourceHash: '1'.repeat(64),
    catalogHash: '2'.repeat(64),
    scoreHash: '3'.repeat(64),
    contentHash: '4'.repeat(64),
    previousContentHash: null,
    rowCount: 1,
    scoreRowCount: 1,
    scoreReady: true,
    scoreContentDigest: '5'.repeat(64),
  };
  const metadataDigest = createHash('sha256')
    .update(canonicalJson(activeMetadata))
    .digest('hex');
  return {
    schemaVersion: 1,
    sourceMode: 'receipt_authorized_compound_advisory_v2',
    verified: true,
    snapshotCount: 1,
    latestSnapshotId: 1,
    activeSnapshotId: 1,
    activeMetadata,
    activeMetadataDigest: metadataDigest,
    activeContentHash: activeMetadata.contentHash,
    activeScoreContentDigest: activeMetadata.scoreContentDigest,
    activeRowCount: 1,
    activeScoreRowCount: 1,
    activeProjectionVerified: true,
    authorizingReceipt: {
      schemaVersion: 1,
      snapshotId: 1,
      metadataDigest,
      receiptId: 'receipt-advisory-v2',
      runId: 'run-advisory-v2',
      receiptSemanticIdentity: '6'.repeat(64),
      operationStartedAt: '2026-01-01T23:59:00Z',
      finishedAt: '2026-01-02T00:00:00Z',
    },
    authorizedSnapshotIds: [1],
    authorizedSnapshotCount: 1,
    stagedSnapshotIds: [],
    stagedSnapshotCount: 0,
    integrityProblems: [],
    activeProjectionProblems: [],
    operationLedgerProblems: [],
    authorizationProblems: [],
    problems: [],
    failedCount: 0,
  };
}

const sourceIdentitySources = [
  { source: 'releases', count: 0, digest: 'd'.repeat(64) },
  { source: 'release_commits', count: 0, digest: 'd'.repeat(64) },
  { source: 'advisories', count: 0, digest: 'd'.repeat(64) },
  { source: 'advisory_snapshot', count: 0, digest: 'd'.repeat(64) },
  { source: 'issues', count: 1, digest: 'd'.repeat(64) },
  { source: 'classifications', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_comment_snapshots', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_label_events', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_label_snapshots', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_closure_proofs', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_closure_events', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_reopen_events', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_state_event_snapshots', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_pr_links', count: 0, digest: 'd'.repeat(64) },
  { source: 'issue_commit_references', count: 0, digest: 'd'.repeat(64) },
  { source: 'pull_request_fixes', count: 0, digest: 'd'.repeat(64) },
  { source: 'release_pr_reachability', count: 0, digest: 'd'.repeat(64) },
  { source: 'release_closure_dependency_snapshots', count: 0, digest: 'd'.repeat(64) },
] as const;
const sourceIdentityFixture = {
  schemaVersion: 7,
  sourceMode: 'current_db',
  scope: 'score_input_database',
  algorithm: 'sha256',
  rowCount: 1,
  sourceCount: sourceIdentitySources.length,
  digest: scoreSourceIdentityManifestDigest(sourceIdentitySources, 7),
  sources: sourceIdentitySources,
};

function directReachabilityProofFixture(
  tag: string,
  status: 'reachable' | 'not_reachable',
  tagCommitOid: string,
  checkedCommitOid: string,
  evidence:
    | 'fix_commit_in_release_history'
    | 'predecessor_release_in_target_history'
    | 'not_reachable_from_release_tag',
) {
  return {
    tag,
    status,
    tagCommitOid,
    checkedCommitOid,
    method: 'git-merge-base',
    evidence: {
      schemaVersion: 1,
      evidence,
      method: 'git-merge-base',
      repositoryNameWithOwner: 'openclaw/openclaw',
      tagCommitOid,
      checkedCommitOid,
      baseRefName: null,
      commandStatus: status === 'reachable' ? 0 : 1,
      stdout: null,
      stderr: null,
      signal: null,
      timedOut: false,
      outputLimitExceeded: false,
      aborted: false,
    },
    strictValid: true,
    validationReasonCode: null,
  };
}

function directCommitProofFixture() {
  return {
    schemaVersion: 1,
    kind: 'direct_commit',
    repositoryNameWithOwner: 'openclaw/openclaw',
    commitOid: directCommitOid,
    targetTag: 'v1',
    predecessorTag,
    status: 'credited',
    reasonCode: 'first_containing_direct_commit',
    creditEligible: true,
    target: directReachabilityProofFixture(
      'v1',
      'reachable',
      tagOid,
      directCommitOid,
      'fix_commit_in_release_history',
    ),
    predecessor: directReachabilityProofFixture(
      predecessorTag,
      'not_reachable',
      predecessorOid,
      directCommitOid,
      'not_reachable_from_release_tag',
    ),
    releaseAncestry: directReachabilityProofFixture(
      'v1',
      'reachable',
      tagOid,
      predecessorOid,
      'predecessor_release_in_target_history',
    ),
    failure: null,
  };
}

function directCommitReachabilitySummaryFixture(
  overrides: Record<string, unknown> = {},
) {
  return {
    missingProofCount: 0,
    invalidProofCount: 0,
    declaredCreditedCommitOids: [],
    creditedCommitOids: [],
    predecessorContainedCommitOids: [],
    unprovenCommitOids: [],
    candidateCommitOids: [directCommitOid],
    ...overrides,
  };
}

function issueCrawlAuditFixture({
  totalCount = 2,
  fetchedCount = totalCount,
}: {
  totalCount?: number;
  fetchedCount?: number;
} = {}) {
  const digest = 'a'.repeat(64);
  const contentDigest = 'b'.repeat(64);
  const repository = 'openclaw/openclaw';
  const sourceOrder = 'CREATED_AT_ASC';
  const asOfBoundary = {
    totalCount,
    terminalIssue: totalCount > 0
      ? {
          nodeId: `ISSUE-node-${totalCount}`,
          issueNumber: totalCount,
          createdAt: '2026-01-01T00:00:00Z',
        }
      : null,
    membershipDigest: digest,
  };
  const baseline = {
    schemaVersion: 2,
    source: 'github.repository.issues',
    repository,
    sourceOrder,
    establishedAt: '2026-01-02T00:00:00Z',
    crawlStartedAt: '2026-01-01T23:00:00Z',
    boundaryTotalCount: totalCount,
    observedTotalCount: totalCount,
    postBoundaryGrowthCount: 0,
    asOfBoundary,
    fetchedCount: totalCount,
    uniqueCount: totalCount,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    digest,
    membershipDigest: digest,
    contentDigest,
    identity: createHash('sha256')
      .update(JSON.stringify([
        repository,
        sourceOrder,
        totalCount,
        asOfBoundary.terminalIssue?.nodeId ?? null,
        asOfBoundary.terminalIssue?.issueNumber ?? null,
        asOfBoundary.terminalIssue?.createdAt ?? null,
        digest,
      ]))
      .digest('hex'),
  };
  const snapshotId = 'c'.repeat(64);
  const consumedAt = '2026-01-01T23:59:30Z';
  return {
    baseline,
    issueCrawl: {
      schemaVersion: 4,
      repository,
      startedAt: '2026-01-01T23:00:00Z',
      finishedAt: '2026-01-02T00:00:00Z',
      fullIssueBackfill: true,
      crawlMode: 'exhaustive',
      backfillCompleteAtStart: false,
      backfillCompleteAfterRun: true,
      baseline,
      pagination: {
        schemaVersion: 2,
        source: 'github.repository.issues',
        repository,
        sourceOrder,
        completeness: 'exhaustive_stable',
        boundaryTotalCount: totalCount,
        observedTotalCount: totalCount,
        postBoundaryGrowthCount: 0,
        asOfBoundary,
        fetchedCount,
        uniqueCount: fetchedCount,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        exhausted: true,
        stabilized: true,
        digest,
        membershipDigest: digest,
        contentDigest,
        lastRequestCursor: null,
        nextCursor: null,
        hasNextPage: false,
      },
      catalogSnapshot: {
        schemaVersion: 1,
        snapshotId,
        contentHash: snapshotId,
        capturedAt: '2026-01-01T22:59:00Z',
        resumed: false,
        priorStatus: 'missing',
        maxAgeHours: 24,
        consumedAt,
        consumedByRunId: 'release-audit-run',
        consumptionContentHash: 'd'.repeat(64),
      },
      catalogAttestation: {
        schemaVersion: 1,
        snapshotId,
        snapshotContentHash: snapshotId,
        observedAt: '2026-01-01T23:59:45Z',
        totalCount,
        membershipDigest: digest,
        contentDigest,
        finalSweepCount: 2,
        finalPagesFetched: 2,
      },
      stopReason: 'exhausted',
      evidenceRefreshFailures: [],
      classificationFailures: [],
      scorePersisted: true,
      scorePersistedAt: auditScoredAt,
    },
  };
}

function driftedSourceIdentity() {
  const sources = sourceIdentityFixture.sources.map((source) =>
    source.source === 'issues'
      ? { ...source, digest: 'f'.repeat(64) }
      : source);
  return {
    ...sourceIdentityFixture,
    digest: scoreSourceIdentityManifestDigest(sources, sourceIdentityFixture.schemaVersion),
    sources,
  };
}

function obsoleteSourceIdentity(schemaVersion = 4) {
  const sources = sourceIdentityFixture.sources.map((source) => ({ ...source }));
  return {
    ...sourceIdentityFixture,
    schemaVersion,
    digest: scoreSourceIdentityManifestDigest(sources, schemaVersion),
    sources,
  };
}

function publicationDbFixture({
  forecast,
  historyRows,
}: {
  forecast: Record<string, unknown>;
  historyRows: Array<Record<string, unknown>>;
}) {
  return {
    prepare(sql: string) {
      if (sql.includes('FROM release_validation_forecasts')) {
        return { all: () => [forecast] };
      }
      if (sql.includes('FROM release_score_audit_history')) {
        return { all: () => historyRows };
      }
      throw new Error(`Unexpected publication fixture query: ${sql}`);
    },
  };
}
const defaultScoreInput = {
  schemaVersion: 2,
  publishedAt: '2026-01-01T00:00:00Z',
  isLatest: true,
  hoursToNextStable: null,
  hasHotfixSuccessor: false,
  betaCount: 1,
  breakingCount: 0,
  feltOpenedWeight: 0,
  feltClosedWeight: 0,
  verifiedDebtWeight: 0,
  carryoverDebtWeight: 0,
  staleDebtWeight: 0,
  verifiedDebtIssueCount: 0,
  carryoverDebtIssueCount: 0,
  staleDebtIssueCount: 0,
  rawIssueCount: 1,
  classifiedIssueCount: 1,
  unresolvedClosureIssueCount: 0,
  unresolvedClosureRiskWeight: 0,
  affirmativeClosureRiskCeilingWeight: 0,
  cveAffected: false,
  cveLoad: 0,
  releaseCheckState: null,
  releaseCheckTotal: 0,
  releaseCheckSuccess: 0,
  releaseCheckFailure: 0,
  releaseCheckPending: 0,
  artifactVerified: false,
  artifactMismatch: null,
  ciReportVerified: false,
  ciReportMismatch: null,
  releaseIntegrityPresent: false,
};
const defaultScoreConfidence = installConfidence(
  defaultScoreInput,
  Date.parse(auditScoredAt),
);
if (defaultScoreConfidence.score == null) {
  throw new Error('default audit fixture must produce a numeric score');
}
const defaultScore = defaultScoreConfidence.score;
const defaultBand = defaultScoreConfidence.band;
const defaultRecommended = defaultScore >= 7;
if (!defaultRecommended) {
  throw new Error('default audit fixture must qualify for recommendation');
}
const defaultScoreReason = defaultScoreConfidence.reason;

function debtTierSummaryFixture() {
  return {
    count: 0,
    weight: 0,
    storedWeight: 0,
    byInstallImpactClass: {},
  };
}

function issueEvidenceFixture() {
  return {
    schemaVersion: 3,
    evidenceCounts: {
      verifiedDebt: 0,
      carryoverDebt: 0,
      staleDebt: 0,
      openedFeltSerious: 0,
      verifiedFixed: 0,
      unverifiedClosed: 0,
      unclassifiedIssues: 0,
      targetEvidenceAttribution: 0,
    },
    targetEvidenceAttribution: [],
    debtSummary: {
      verified: debtTierSummaryFixture(),
      carryover: debtTierSummaryFixture(),
      stale: debtTierSummaryFixture(),
    },
    verifiedDebt: [],
    carryoverDebt: [],
    staleDebt: [],
    openedFeltSerious: [],
    verifiedFixed: [],
    unverifiedClosed: [],
    unclassifiedIssues: [],
  };
}
const scoreAffectingFreshnessSourceNames = [
  'classification_rows',
  'closure_events',
  'closure_proofs',
  'issue_comments',
  'issue_commit_references',
  'issue_fetches',
  'issue_pr_links',
  'issue_rows',
  'issue_state_event_snapshots',
  'label_events',
  'label_snapshots',
  'pull_request_fixes',
  'release_closure_dependency_snapshots',
  'release_metadata',
  'release_pr_reachability',
  'reopen_events',
] as const;

function scoredSourceFreshnessFixture() {
  return scoreAffectingFreshnessSourceNames.map((source) => ({
    source,
    max_ts: source === 'issue_rows'
      ? '2026-01-01T23:00:00Z'
      : source === 'classification_rows'
        ? '2026-01-01T23:10:00Z'
        : proofCheckedAt,
  }));
}

function unscoredSourceFreshnessFixture() {
  return scoreAffectingFreshnessSourceNames.map((source) => ({
    source,
    max_ts: null,
  }));
}

function scoredDataFreshnessSourcesFixture() {
  return scoredSourceFreshnessFixture().map((row) => ({
    source: row.source,
    count: 1,
    nullCount: 0,
    maxAt: row.max_ts,
    ageHoursAtScore: row.source === 'issue_rows'
      ? 1
      : row.source === 'classification_rows'
        ? 0.83
        : 0,
  }));
}

function unscoredDataFreshnessSourcesFixture() {
  return unscoredSourceFreshnessFixture().map((row) => ({
    source: row.source,
    count: 0,
    nullCount: 0,
    maxAt: row.max_ts,
    ageHoursAtScore: null,
  }));
}

const proofDependencyFreshnessFixture = [
  'issue_rows',
  'issue_fetches',
  'issue_comments',
  'classification_rows',
  'label_events',
  'label_snapshots',
  'issue_state_event_snapshots',
  'closure_events',
  'reopen_events',
  'issue_pr_links',
  'issue_commit_references',
  'pull_request_fixes',
  'release_pr_reachability',
  'release_closure_dependency_snapshots',
].map((source) => ({ source, max_ts: proofCheckedAt }));

function fixCreditDecisionFixture(overrides: any = {}) {
  return {
    schemaVersion: 1,
    issueNumber: 1,
    status: 'credited',
    reasonCode: 'first_containing_trusted_pr',
    targetTag: 'v1',
    predecessorTag,
    proofIdentities: [{
      kind: 'trusted_pull_request',
      repositoryNameWithOwner: 'openclaw/openclaw',
      prNumber: 1,
      sources: ['closedByPullRequestsReferences'],
      merged: true,
      mergeCommitOid: mergeOid,
      baseRefName: 'main',
      target: {
        tag: 'v1',
        status: 'reachable',
        tagCommitOid: tagOid,
        checkedCommitOid: mergeOid,
        baseRefName: 'main',
        method: 'git-merge-base',
        checkedAt: proofCheckedAt,
        evidenceReason: 'merge_commit_in_release_history',
        strictValid: true,
        validationReasonCode: null,
      },
      predecessor: {
        tag: predecessorTag,
        status: 'not_reachable',
        tagCommitOid: predecessorOid,
        checkedCommitOid: mergeOid,
        baseRefName: 'main',
        method: 'git-merge-base',
        checkedAt: proofCheckedAt,
        evidenceReason: 'not_reachable_from_release_tag',
        strictValid: true,
        validationReasonCode: null,
      },
    }],
    ...overrides,
  };
}

function closureProofFixture(overrides: any = {}) {
  const byStatus = overrides.byStatus ?? { fixed_in_release: 1 };
  const analyzedClosedCount = overrides.analyzedClosedCount ??
    Object.values(byStatus).reduce((sum: number, count) => sum + Number(count ?? 0), 0);
  const containedFixedCount = overrides.containedFixedCount ?? Number(byStatus.fixed_in_release ?? 0);
  const creditedCount = overrides.creditedCount ?? containedFixedCount;
  const notCreditedCount = overrides.notCreditedCount ?? analyzedClosedCount - creditedCount;
  const fixCreditDecisions = overrides.fixCreditDecisions ??
    (containedFixedCount === 1 && creditedCount === 1 ? [fixCreditDecisionFixture()] : []);
  const fixCreditDecisionCounts = overrides.fixCreditDecisionCounts ?? {
    credited: fixCreditDecisions.filter((decision: any) => decision.status === 'credited').length,
    withheld: fixCreditDecisions.filter((decision: any) => decision.status === 'withheld').length,
    invalid: fixCreditDecisions.filter((decision: any) => decision.status === 'invalid').length,
  };
  const proof = {
    schemaVersion: 2,
    creditedCount,
    notCreditedCount,
    analyzedClosedCount,
    containedFixedCount,
    containedNotCreditedCount: containedFixedCount - creditedCount,
    targetTag: 'v1',
    predecessorTag,
    fixCreditDecisionCounts,
    fixCreditDecisions,
    byStatus,
    byRiskDisposition: { credited_release_fix: 1 },
    riskSummary: {
      creditedReleaseFixCount: creditedCount,
      containedReleaseFixCount: containedFixedCount,
      containedWithoutFirstCreditCount: containedFixedCount - creditedCount,
      resolvedByCanonicalReleaseFixCount: 0,
      resolvedByReleaseFixProofCount: 0,
      knownNotInReleaseCount: 0,
      openCanonicalRiskCount: 0,
      unsupportedClosureClaimCount: 0,
      neutralOrNonActionableCount: 0,
      neutralHighImpactCount: 0,
      neutralBugShapedCount: 0,
      missingEvidenceCount: 0,
      unresolvedForReleaseCount: 0,
      unresolvedWeightedRisk: 0,
      weightedRiskByDisposition: {},
    },
    neutralAuditExamples: [],
    examples: [],
    ...overrides,
  };
  proof.examplesByStatus ??= Object.fromEntries(
    Object.keys(proof.byStatus ?? {})
      .filter((status) => status !== 'fixed_in_release')
      .map((status) => [status, [{ number: 1, status }]]),
  );
  return proof;
}

function releaseFixCreditFixture(closureProof = closureProofFixture(), overrides: any = {}) {
  return {
    schemaVersion: 1,
    targetTag: closureProof.targetTag,
    predecessorTag: closureProof.predecessorTag,
    countedClosedCount: closureProof.creditedCount,
    notCountedClosedCount: closureProof.notCreditedCount,
    analyzedClosedCount: closureProof.analyzedClosedCount,
    containedFixedCount: closureProof.containedFixedCount,
    containedNotCreditedCount: closureProof.containedNotCreditedCount,
    decisionCounts: closureProof.fixCreditDecisionCounts,
    decisions: closureProof.fixCreditDecisions,
    ...overrides,
  };
}

function fixProvenanceFixture(overrides: any = {}) {
  const closureProof = overrides.closureProof ?? closureProofFixture();
  return {
    verifiedFixedCount: closureProof.containedFixedCount,
    creditedFixedCount: closureProof.creditedCount,
    unverifiedClosedCount: 0,
    predecessorBoundary: {
      schemaVersion: 1,
      oldestScoredStableTag: 'v1',
      oldestScoredStablePredecessorTag: predecessorTag,
      targetTag: 'v1',
      predecessorTag,
    },
    closureProof,
    releaseFixCredit: overrides.releaseFixCredit ?? releaseFixCreditFixture(closureProof),
    ...overrides,
  };
}

function rawClassificationFixture(issueNumber: number, promptVersion: number) {
  const rawModelOutput = JSON.stringify({
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affected_users: 'some',
    affected_users_evidence: 'The fixture issue affects some users.',
    hasWorkaround: false,
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.9,
    rationale: 'Fixture classification.',
  });
  return {
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affected_users: 'some',
    has_workaround: 0,
    workaround_status: 'unknown',
    duplicate_cluster: null,
    affects_version: null,
    confidence: 0.9,
    rationale: 'Fixture classification.',
    prompt_version: promptVersion,
    classification_origin: 'raw_model',
    raw_model_output: rawModelOutput,
    provenance_json: JSON.stringify({
      schemaVersion: 1,
      responseId: `chatcmpl-fixture-${issueNumber}`,
      requestedModel: 'fixture-model',
      responseModel: 'fixture-model',
      requestedServiceTier: 'default',
      responseServiceTier: 'default',
      reasoningEffort: 'medium',
      promptVersion,
      promptTemplateHash: CLASSIFICATION_PROMPT_TEMPLATE_HASH,
      promptHash: 'a'.repeat(64),
      rawModelOutputHash: createHash('sha256').update(rawModelOutput).digest('hex'),
      rawModelOutput,
    }),
  };
}

function reader(overrides: Partial<{
  releases: any[];
  rawClosed: any[];
  closed: any[];
  opened: any[];
  verified: any[];
  unverified: any[];
  proofRows: any[];
  prEvidence: any[];
  proofDependencyFreshness: any[];
  issueNumbers: number[];
  activeReleaseRows: any[] | null;
  audit: any;
  closureDependencySnapshotReport: any;
  publicationFailures: string[];
  publicationDigests: Record<string, unknown>;
  publicationAuthorityBindings: Record<string, unknown>;
  issueCrawlMetadata: any;
  advisorySnapshotProjection: any;
}> = {}) {
  const data = {
    releases: [{
      tag: 'v1',
      published_at: defaultScoreInput.publishedAt,
      hours_to_next_stable: defaultScoreInput.hoursToNextStable,
      beta_count: defaultScoreInput.betaCount,
      breaking_count: defaultScoreInput.breakingCount,
      final_score: defaultScore,
      state: 'eligible',
      recommended: Number(defaultRecommended),
      scored_at: auditScoredAt,
      score_reason: defaultScoreReason,
      negative_issues: 1,
      positive_issues: 0,
    }],
    rawClosed: [{ number: 1 }],
    opened: [],
    closed: [{ number: 1, prompt_version: 6 }],
    verified: [{ number: 1, sentiment: 'negative', prompt_version: 6 }],
    unverified: [],
    proofRows: [{
      release_tag: 'v1',
      issue_number: 1,
      status: 'fixed_in_release',
      checked_at: proofCheckedAt,
      evidence_json: JSON.stringify({
        hasReachableClosingPr: true,
        hasReachableFixCommit: false,
        hasNotReachableFixCommit: false,
        reachableFixCommits: [],
        notReachableFixCommits: [],
        fixCommitProof: [],
        linkedPrs: [{
          number: 1,
          repositoryNameWithOwner: 'openclaw/openclaw',
          source: 'closedByPullRequestsReferences',
          willCloseTarget: 1,
          state: 'MERGED',
          merged: 1,
          mergedAt: '2026-01-01T12:00:00Z',
          reachabilityStatus: 'reachable',
          reachabilityMethod: 'git-merge-base',
          reachabilityEvidence: 'merge_commit_in_release_history',
          mergeCommitOid: mergeOid,
        }],
        stateReasons: ['COMPLETED'],
      }),
    }],
    prEvidence: [{
      issue_number: 1,
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 1,
      merged: 1,
      status: 'reachable',
      tag_commit_oid: tagOid,
      release_tag_commit_oid: tagOid,
      merge_commit_oid: mergeOid,
      evidence_json: JSON.stringify({
        schemaVersion: 1,
        evidence: 'merge_commit_in_release_history',
        method: 'git-merge-base',
        tagCommitOid: tagOid,
        checkedCommitOid: mergeOid,
        baseRefName: 'main',
        commandStatus: 0,
      }),
    }],
    proofDependencyFreshness: proofDependencyFreshnessFixture,
    closureDependencySnapshotReport: {
      tag: 'v1',
      missingCount: 0,
      schemaMismatchCount: 0,
      membershipMismatchCount: 0,
      referencedIssueMissingCount: 0,
      evidenceInvalidCount: 0,
      identityMismatchCount: 0,
      failedCount: 0,
      snapshot: {
        release_tag: 'v1',
        captured_at: proofCheckedAt,
        dependency_digest: 'c'.repeat(64),
      },
      currentIdentity: null,
    },
    issueNumbers: [1],
    activeReleaseRows: null,
    publicationFailures: [],
    publicationDigests: {
      v1: 'd'.repeat(64),
    },
    publicationAuthorityBindings: {
      v1: {
        authorityRunId: 'score-authority:test-run',
        authorityRunContentHash: 'a'.repeat(64),
        historyV2SealContentHash: 'b'.repeat(64),
      },
    },
    issueCrawlMetadata: null,
    advisorySnapshotProjection: advisorySnapshotAuditProjectionFixture(),
    audit: {
      score_model_version: SCORE_MODEL_VERSION,
      prompt_version: 6,
      scored_at: auditScoredAt,
      input_json: JSON.stringify(defaultScoreInput),
      components_json: JSON.stringify({
        schemaVersion: 1,
        components: defaultScoreConfidence.components,
        evidenceCoverage: defaultScoreConfidence.evidenceCoverage,
        hotfix: defaultScoreConfidence.hotfix,
        reason: defaultScoreReason,
        recommendationDecision: scoreExplanationFixture().recommendationDecision,
        explanation: scoreExplanationFixture(),
      }),
      issue_evidence_json: JSON.stringify(issueEvidenceFixture()),
      source_identity_json: JSON.stringify(sourceIdentityFixture),
      gate_evidence_json: JSON.stringify({
        schemaVersion: 1,
        cve: { affected: false, load: 0 },
        stableTagsNewestFirst: ['v1', predecessorTag],
        betaCount: 0,
        breakingCount: 0,
        hoursToNextStable: null,
        hasHotfixSuccessor: false,
        labelTimeline: labelTimelineFixture,
        releaseChecks: releaseChecksFixture,
        artifactVerification: artifactVerificationFixture,
        fixProvenance: fixProvenanceFixture(),
      }),
    },
    ...overrides,
  };
  if (data.audit && data.audit.issue_evidence_json === undefined) {
    data.audit = { ...data.audit, issue_evidence_json: JSON.stringify(issueEvidenceFixture()) };
  }
  if (data.audit && data.audit.score_model_version === undefined) {
    data.audit = { ...data.audit, score_model_version: SCORE_MODEL_VERSION };
  }
  if (data.audit && data.audit.input_json === undefined) {
    data.audit = { ...data.audit, input_json: JSON.stringify(defaultScoreInput) };
  }
  if (data.audit && data.audit.components_json === undefined) {
    data.audit = {
      ...data.audit,
      components_json: JSON.stringify({
        schemaVersion: 1,
        components: defaultScoreConfidence.components,
        evidenceCoverage: defaultScoreConfidence.evidenceCoverage,
        hotfix: defaultScoreConfidence.hotfix,
        reason: defaultScoreReason,
        recommendationDecision: scoreExplanationFixture().recommendationDecision,
        explanation: scoreExplanationFixture(),
      }),
    };
  }
  if (data.audit && data.audit.source_identity_json === undefined) {
    data.audit = { ...data.audit, source_identity_json: JSON.stringify(sourceIdentityFixture) };
  }
  if (data.audit?.gate_evidence_json) {
    const gate = JSON.parse(data.audit.gate_evidence_json);
    gate.schemaVersion ??= 1;
    gate.cve ??= { affected: false, load: 0 };
    gate.stableTagsNewestFirst ??= ['v1', predecessorTag];
    gate.betaCount ??= 0;
    gate.breakingCount ??= 0;
    gate.hoursToNextStable ??= null;
    gate.hasHotfixSuccessor ??= false;
    gate.releaseChecks ??= releaseChecksFixture;
    gate.artifactVerification ??= artifactVerificationFixture;
    if (gate.fixProvenance && typeof gate.fixProvenance === 'object') {
      const fix = gate.fixProvenance;
      const proof = fix.closureProof;
      if (proof && typeof proof === 'object') {
        fix.creditedFixedCount ??= proof.creditedCount ?? 0;
        fix.predecessorBoundary ??= {
          schemaVersion: 1,
          oldestScoredStableTag: 'v1',
          oldestScoredStablePredecessorTag: predecessorTag,
          targetTag: 'v1',
          predecessorTag,
        };
        if (proof.riskSummary && typeof proof.riskSummary === 'object') {
          proof.riskSummary.containedReleaseFixCount ??= proof.containedFixedCount ?? 0;
          proof.riskSummary.containedWithoutFirstCreditCount ??=
            proof.containedNotCreditedCount ?? 0;
        }
        if (fix.releaseFixCredit && typeof fix.releaseFixCredit === 'object') {
          const credit = fix.releaseFixCredit;
          credit.targetTag ??= proof.targetTag ?? 'v1';
          credit.predecessorTag ??= proof.predecessorTag ?? predecessorTag;
          credit.containedFixedCount ??= proof.containedFixedCount ?? 0;
          credit.containedNotCreditedCount ??= proof.containedNotCreditedCount ?? 0;
          credit.decisionCounts ??= proof.fixCreditDecisionCounts ?? {
            credited: 0,
            withheld: 0,
            invalid: 0,
          };
          credit.decisions ??= proof.fixCreditDecisions ?? [];
        }
      }
    }
    data.audit = { ...data.audit, gate_evidence_json: JSON.stringify(gate) };
  }
  return {
    listReleases: () => data.releases,
    stableReleaseBoundaryRows: () => [{
      tag: 'v1',
      published_at: defaultScoreInput.publishedAt,
      catalog_rank: 0,
      catalog_tag_commit_oid: tagOid,
      resolved_tag_commit_oid: tagOid,
    }, {
      tag: predecessorTag,
      published_at: '2025-12-01T00:00:00Z',
      catalog_rank: 1,
      catalog_tag_commit_oid: predecessorOid,
      resolved_tag_commit_oid: predecessorOid,
    }],
    activeReleaseBoundaryRows: () => data.activeReleaseRows ?? [{
      tag: 'v1',
      published_at: defaultScoreInput.publishedAt,
      catalog_rank: 0,
      prerelease: 0,
    }, {
      tag: predecessorTag,
      published_at: '2025-12-01T00:00:00Z',
      catalog_rank: 1,
      prerelease: 0,
    }],
    releaseCommitForAudit: () => ({
      check_state: null,
      check_total: 0,
      check_success: 0,
      check_failure: 0,
      check_pending: 0,
      check_contexts_json: '[]',
    }),
    rawClosedDuringReign: () => data.rawClosed,
    issueNumbersForVersion: () => data.issueNumbers,
    issuesForVersion: () => data.issueNumbers.map((number: number) => ({
      number,
      state: number === 1 ? 'closed' : 'open',
      title: `issue ${number}`,
      html_url: `https://github.com/x/y/issues/${number}`,
      updated_at: '2026-01-01T23:00:00Z',
      closed_at: number === 1 ? '2026-01-01T12:00:00Z' : null,
      labels: '[]',
      comments: 0,
      has_workaround: 0,
      reaction_total: 0,
      positive_reactions: 0,
      is_bot: 0,
      author: 'tester',
      author_association: 'MEMBER',
      unique_human_commenters: 0,
      maintainer_commenters: 0,
      contributor_commenters: 0,
      commenter_scan_truncated: 0,
      source_identity_digest: classificationSourceIdentityDigest,
      ...rawClassificationFixture(number, Number(data.audit?.prompt_version ?? 6)),
    })),
    labelsForIssueAt: (_issueNumber: number, fallbackLabels: string[]) => fallbackLabels,
    openedDuringReign: () => data.opened,
    closedDuringReign: () => data.closed,
    verifiedFixedForRelease: () => data.verified,
    unverifiedClosedForRelease: () => data.unverified,
    proofRowsFor: () => data.proofRows.map((row: any) => {
      const number = Number(row.issue_number);
      return {
        release_tag: 'v1',
        issue_number: number,
        title: `issue ${number}`,
        html_url: `https://github.com/x/y/issues/${number}`,
        closed_at: '2026-01-01T12:00:00Z',
        summary: 'Fixed in release.',
        labels: '[]',
        effective_labels: [],
        checked_at: proofCheckedAt,
        ...rawClassificationFixture(number, Number(data.audit?.prompt_version ?? 6)),
        ...row,
        evidence_json: normalizedProofEvidenceJson(row.evidence_json),
      };
    }),
    prReachabilityEvidenceForIssue: () => data.prEvidence,
    proofDependencyFreshnessForIssue: () => data.proofDependencyFreshness,
    closureDependencySnapshotIntegrityForRelease: () =>
      data.closureDependencySnapshotReport,
    prReachabilityRowsForRelease: () => data.prEvidence.map((row: any) => ({
      tag: 'v1',
      pr_repository_name_with_owner: row.pr_repository_name_with_owner,
      pr_number: row.pr_number,
      title: `PR ${row.pr_number}`,
      url: `https://github.com/${row.pr_repository_name_with_owner}/pull/${row.pr_number}`,
      state: 'MERGED',
      merged: row.merged,
      merged_at: '2026-01-01T12:00:00Z',
      tag_commit_oid: row.tag_commit_oid ?? null,
      merge_commit_oid: row.merge_commit_oid ?? null,
      pr_merge_commit_oid: row.merge_commit_oid ?? null,
      base_ref_name: row.base_ref_name ?? 'main',
      status: row.status,
      method: row.method ?? 'git-merge-base',
      evidence_json: row.evidence_json ?? JSON.stringify({
        schemaVersion: 1,
        evidence: 'merge_commit_in_release_history',
        method: 'git-merge-base',
        tagCommitOid: row.tag_commit_oid ?? tagOid,
        checkedCommitOid: row.merge_commit_oid ?? mergeOid,
        baseRefName: row.base_ref_name ?? 'main',
        commandStatus: 0,
      }),
      checked_at: proofCheckedAt,
    })),
    getReleaseScoreAudit: () => data.audit,
    scorePublicationIntegrity: () => ({
      failures: data.publicationFailures,
      failedCount: data.publicationFailures.length,
      publicationDigests: data.publicationDigests,
      publicationAuthorityBindings: data.publicationAuthorityBindings,
    }),
    issueCrawlMetadata: () => data.issueCrawlMetadata,
    advisorySnapshotAuditProjection: () =>
      structuredClone(data.advisorySnapshotProjection),
    scoreSourceIdentity: () => sourceIdentityFixture,
    sourceFreshnessFor: () =>
      data.releases.some((release: any) => release.scored_at != null)
        ? scoredSourceFreshnessFixture()
        : unscoredSourceFreshnessFixture(),
  };
}

function normalizedProofEvidenceJson(value: string): string {
  const evidence = JSON.parse(value);
  return JSON.stringify({
    targetReachableFixCommits: [],
    targetNotReachableFixCommits: [],
    targetUnknownFixCommits: [],
    predecessorContainedFixCommits: [],
    firstContainingUnknownFixCommits: [],
    directCommitFirstContainingProofs: [],
    ...evidence,
  });
}

describe('release closure dependency membership', () => {
  it('derives branching, transitive, cycle, terminal, and cross-release references', () => {
    const membership = releaseClosureDependencyMembership([1], [{
      issue_number: 1,
      evidence_json: JSON.stringify({
        canonicalIssues: [20, 30],
        canonicalIssueDetails: [{ number: 40 }],
        canonicalFixCommitProof: [{ sourceIssueNumber: 50 }],
        canonicalResolution: {
          path: [1, 20, 40, 20],
          blockingBranch: [1, 30],
          terminalIssue: { number: 20 },
          terminalIssues: [{ number: 20 }, { number: 30 }],
          cycleTerminalIssue: { number: 20 },
          terminalProof: {
            crossRelease: true,
            issueNumber: 30,
            releaseTag: 'v0',
          },
          branches: [
            {
              path: [1, 20, 40, 20],
              terminalIssue: { number: 20 },
              terminalProof: {
                crossRelease: true,
                sourceIssueNumber: 40,
                releaseTag: 'v0',
              },
            },
            { path: [1, 30], terminalIssue: { number: 30 } },
          ],
        },
      }),
    }]);

    assert.deepEqual(membership.issueNumbers, [1, 20, 30, 40, 50]);
    assert.deepEqual(membership.referencedIssueNumbers, [1, 20, 30, 40, 50]);
    assert.equal(membership.invalidEvidenceCount, 0);
  });

  it('requires exact membership and existing referenced issues in the audit gate', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closureDependencySnapshotReport: {
          tag: 'v1',
          missingCount: 0,
          schemaMismatchCount: 0,
          membershipMismatchCount: 1,
          referencedIssueMissingCount: 1,
          evidenceInvalidCount: 0,
          identityMismatchCount: 1,
          failedCount: 3,
          snapshot: {
            release_tag: 'v1',
            captured_at: proofCheckedAt,
            dependency_digest: 'c'.repeat(64),
          },
          currentIdentity: null,
        },
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /membership=1, missingIssues=1, invalidEvidence=0, identity=1/.test(failure)));
  });
});

function scoreLedgerClassificationFixture() {
  return {
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affectedUsers: 'some',
    hasWorkaround: false,
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.9,
    rationale: 'Fixture classification.',
  };
}

function scoreLedgerEvidenceSourcesFixture(overrides: any = {}) {
  const releasePayload = {
    tag: 'v1',
    publishedAt: defaultScoreInput.publishedAt,
    isLatest: defaultScoreInput.isLatest,
    hoursToNextStable: defaultScoreInput.hoursToNextStable,
    hasHotfixSuccessor: defaultScoreInput.hasHotfixSuccessor,
    betaCount: defaultScoreInput.betaCount,
    breakingCount: defaultScoreInput.breakingCount,
    ...overrides.release,
  };
  const coveragePayload = {
    issueNumber: 1,
    updatedAt: '2026-01-01T23:00:00Z',
    classification: scoreLedgerClassificationFixture(),
    classificationOrigin: 'raw_model',
    classifierSourceIdentityDigest: classificationSourceIdentityDigest,
    ...overrides.coverage,
  };
  return [{
    key: 'release',
    refs: [{
      kind: 'release',
      identity: 'release:v1',
      payload: releasePayload,
    }],
  }, {
    key: 'coverage',
    refs: [{
      kind: 'classification',
      identity: 'issue:1:classification',
      payload: coveragePayload,
    }],
  }];
}

function scoreExplanationFixture(overrides: any = {}) {
  const confidence = defaultScoreConfidence;
  const baseScoreLedger = buildScoreLedgerV2({
    input: defaultScoreInput,
    confidence,
    now: Date.parse(auditScoredAt),
    evidenceSources: scoreLedgerEvidenceSourcesFixture(overrides.evidence),
  });
  const recommendationSummary =
    `Decision highest_confidence: release v1 (score ${defaultScore.toFixed(1)}); ` +
    `selected v1 (score ${defaultScore.toFixed(1)}); highest-scoring qualifying release v1 ` +
    `(score ${defaultScore.toFixed(1)}); threshold 7.0; recency tolerance 0.5. ` +
    'This release is recommended as the highest-confidence qualifying release.';
  const humanRecommendationSummary =
    'Recommended at the highest audited score; the newest release wins when scores are equal.';
  const modelLimit =
    'No field-blocker evidence is currently holding this release down; the remaining gap comes from the model ceiling and capped confidence signals.';
  const explanation = {
    schemaVersion: 5,
    title: 'Why not 10?',
    positives: [humanRecommendationSummary],
    positiveDetails: [{
      code: 'release_recommended',
      label: 'Release recommended',
      text: humanRecommendationSummary,
    }],
    limits: [modelLimit],
    limitDetails: [{
      code: 'model_ceiling_and_capped_confidence',
      label: 'Model ceiling and capped confidence',
      text: modelLimit,
    }],
    recommendationDecision: {
      schemaVersion: 1,
      policyCode: 'highest_confidence_with_recency_tolerance',
      threshold: 7,
      recencyTolerance: 0.5,
      selectedTag: 'v1',
      selectedScore: defaultScore,
      highestScoringTag: 'v1',
      highestScore: defaultScore,
      releaseTag: 'v1',
      releaseScore: defaultScore,
      qualifies: defaultRecommended,
      selected: defaultRecommended,
      recencyRank: 1,
      scoreRank: 1,
      scoreDeltaToHighest: 0,
      decisionCode: 'highest_confidence',
      summary: recommendationSummary,
    },
    verdict: 'This means the release is the current recommended install target under the audit and recommendation gates, but the audit still contains evidence.',
    authorityReferences: [],
  };
  return {
    ...explanation,
    scoreLedger: structuredClone(bindScoreExplanationAudit(
      baseScoreLedger,
      explanation,
    )),
  };
}

function readerWithMutatedPersistedComponents(
  mutator: (components: any) => void,
) {
  const auditReader = reader();
  const audit = auditReader.getReleaseScoreAudit('v1');
  const components = JSON.parse(audit.components_json);
  mutator(components);
  audit.components_json = JSON.stringify(components);
  return auditReader;
}

function scoreExplanationIssueRefFixture(number = 101): any {
  return {
    number,
    title: `issue ${number}`,
    url: `https://github.com/x/y/issues/${number}`,
    confirmationReasons: [{
      code: 'independent_human_reproduction',
      source: 'comment',
      author: 'community-reporter',
      association: 'CONTRIBUTOR',
      occurredAt: '2026-01-01T01:00:00Z',
      updatedAt: '2026-01-01T01:00:00Z',
      commentId: 7001,
      commentUrl: `https://github.com/x/y/issues/${number}#issuecomment-7001`,
      issueNodeId: `ISSUE_${number}`,
      issueAuthorNodeId: `ISSUE_AUTHOR_${number}`,
      issueAuthorType: 'User',
      commentNodeId: `COMMENT_${number}`,
      commentNodeType: 'IssueComment',
      actorNodeId: `COMMENT_AUTHOR_${number}`,
      actorType: 'User',
      commentBodyDigest: 'a'.repeat(64),
      snippet: 'Can confirm this issue after upgrading.',
    }, {
      code: 'human_applied_p0',
      source: 'label_event',
      author: 'maintainer',
      occurredAt: '2026-01-01T01:30:00Z',
      label: 'P0',
      eventId: `LABEL_EVENT_${number}`,
    }],
    releaseLocalEvidence: {
      kind: 'exact-version',
      source: 'comment',
      version: 'v1',
      snippet: 'Can confirm this issue affects v1.',
      commentId: 7001,
      commentUrl: `https://github.com/x/y/issues/${number}#issuecomment-7001`,
      commentNodeId: `COMMENT_${number}`,
      author: 'community-reporter',
      actorNodeId: `COMMENT_AUTHOR_${number}`,
      actorType: 'User',
      association: 'CONTRIBUTOR',
      occurredAt: '2026-01-01T01:00:00Z',
      updatedAt: '2026-01-01T01:00:00Z',
      commentBodyDigest: 'a'.repeat(64),
    },
  };
}

function closureAuditClassificationFixture() {
  const classification = structuredClone(scoreLedgerClassificationFixture());
  Reflect.deleteProperty(classification, 'hasWorkaround');
  return classification;
}

function closureAuditEvidenceFixture() {
  return {
    stateReasons: ['COMPLETED'],
    closureActors: [],
    closureContextCommentCount: null,
    hasClosingLink: false,
    hasMergedClosingPr: false,
    hasReachableClosingPr: true,
    hasNotReachableClosingPr: false,
    hasReachableFixCommit: false,
    hasNotReachableFixCommit: false,
    hasUnknownFixCommit: false,
    canonicalIssues: [],
    canonicalIssueDetails: [],
    canonicalResolution: null,
    closingPrs: [],
    linkedPrs: [{
      number: 1,
      repositoryNameWithOwner: 'openclaw/openclaw',
      source: 'closedByPullRequestsReferences',
      willCloseTarget: true,
      referencedAt: null,
      sourceCommentDatabaseId: null,
      sourceCommentUrl: null,
      metadataMissing: false,
      title: null,
      url: null,
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-01-01T12:00:00Z',
      reachabilityStatus: 'reachable',
      reachabilityMethod: 'git-merge-base',
      reachabilityEvidence: 'merge_commit_in_release_history',
      mergeCommitOid: mergeOid,
    }],
    relatedPrContext: {
      externalClosing: [],
      open: [],
      closedUnmerged: [],
      notReachable: [],
      reachable: [],
      unknownReachability: [],
    },
    reachableTrustedFixProofPrs: [],
    matchingComments: [],
    nonActionableRationaleComments: [],
    laterFixProof: null,
    unscoredFixProof: null,
    fixCommitProof: [],
    canonicalFixCommitProof: [],
    referencedCommitContext: [],
    reachableFixCommits: [],
    notReachableFixCommits: [],
    unknownFixCommits: [],
  };
}

function apiFixtureFetchJson(mutator?: (dataFreshness: any, publicRelease: any) => void) {
  const snapshotId = 'f'.repeat(64);
  const releasePublishedAt = '2026-01-01T00:00:00Z';
  const validationCodeRevision = 'test-revision';
  const validationSeriesKey = `test-model/prompt-6/revision-${validationCodeRevision}`;
  const validationCounts = {
    captured: 0,
    upcoming: 0,
    open: 1,
    missed: 1,
    failed: 0,
    invalidLegacyForecasts: 0,
  };
  const validationDenominatorRows = [
    {
      opportunityId: '1'.repeat(64),
      enrollmentContentHash: '3'.repeat(64),
      stateContentHash: '5'.repeat(64),
      enrolledAt: '2026-01-01T00:00:01Z',
      cohortInceptionAt: '2026-01-01T00:00:01Z',
      enrollmentKind: 'prospective',
      releaseNodeId: 'release-node-v1',
      releaseTag: 'v1',
      releaseTagCommitOid: tagOid,
      releasePublishedAt,
      opportunityCode: 'first_verified_after_3h',
      modelVersion: 'test-model',
      promptVersion: 6,
      codeRevision: validationCodeRevision,
      opensAt: '2026-01-01T03:00:00Z',
      closesAtExclusive: '2026-01-01T06:00:00Z',
      enrollmentRunId: 'test-enrollment-run',
      operationAttemptContentHash: '7'.repeat(64),
      catalogDigest: '8'.repeat(64),
      catalogReleaseCount: 1,
      disposition: 'missed',
      terminal: true,
      capturedDecisionId: null,
      capturedContentHash: null,
      successEvidence: [],
      failureCount: 0,
      failures: [],
    },
    {
      opportunityId: '2'.repeat(64),
      enrollmentContentHash: '4'.repeat(64),
      stateContentHash: '6'.repeat(64),
      enrolledAt: '2026-01-01T00:00:01Z',
      cohortInceptionAt: '2026-01-01T00:00:01Z',
      enrollmentKind: 'prospective',
      releaseNodeId: 'release-node-v1',
      releaseTag: 'v1',
      releaseTagCommitOid: tagOid,
      releasePublishedAt,
      opportunityCode: 'first_verified_after_24h',
      modelVersion: 'test-model',
      promptVersion: 6,
      codeRevision: validationCodeRevision,
      opensAt: '2026-01-02T00:00:00Z',
      closesAtExclusive: '2026-01-02T06:00:00Z',
      enrollmentRunId: 'test-enrollment-run',
      operationAttemptContentHash: '7'.repeat(64),
      catalogDigest: '8'.repeat(64),
      catalogReleaseCount: 1,
      disposition: 'eligible',
      terminal: false,
      capturedDecisionId: null,
      capturedContentHash: null,
      successEvidence: [],
      failureCount: 0,
      failures: [],
    },
  ];
  const validationOpportunities = validationDenominatorRows.map((row) => ({
    opportunityId: row.opportunityId,
    releaseTag: row.releaseTag,
    releasePublishedAt: row.releasePublishedAt,
    code: row.opportunityCode,
    state: row.disposition === 'eligible' ? 'open' : row.disposition,
    opensAt: row.opensAt,
    closesAtExclusive: row.closesAtExclusive,
    enrolledAt: row.enrolledAt,
    enrollmentContentHash: row.enrollmentContentHash,
    stateContentHash: row.stateContentHash,
    timeUntilOpenMs: null,
    timeUntilCloseMs: row.disposition === 'eligible' ? 21_599_000 : null,
    capturedDecisionId: row.capturedDecisionId,
    capturedContentHash: row.capturedContentHash,
    failureCount: row.failureCount,
    failures: row.failures,
    invalidCurrentSeriesForecastCount: 0,
    otherSeriesForecastCount: 0,
  }));
  const scoreAudit = {
    schemaVersion: 2,
    reviewSchemaVersion: 1,
    auditDigest: 'd'.repeat(64),
    authorityRunId: 'score-authority:test-run',
    authorityRunContentHash: 'a'.repeat(64),
    historyV2SealContentHash: 'b'.repeat(64),
    modelVersion: SCORE_MODEL_VERSION,
    promptVersion: 6,
    evidenceCoverage: 1,
    rawIssueCount: 1,
    classifiedIssueCount: 1,
  };
  const profileRowsDigest = 'e'.repeat(64);
  const profileBindingContent = {
    schemaVersion: 1,
    auditDigest: scoreAudit.auditDigest,
    authorityRunId: scoreAudit.authorityRunId,
    authorityRunContentHash: scoreAudit.authorityRunContentHash,
    historyV2SealContentHash: scoreAudit.historyV2SealContentHash,
    sourceIdentityDigest: 'c'.repeat(64),
    scoreModelVersion: scoreAudit.modelVersion,
    promptVersion: scoreAudit.promptVersion,
    profileRowsDigest,
  };
  const profilePublicationBinding = {
    ...profileBindingContent,
    contentHash: createHash('sha256')
      .update('release-profile-evidence-binding-v1\0')
      .update(canonicalJson(profileBindingContent))
      .digest('hex'),
  };
  const explanation = scoreExplanationFixture();
  const auditLinks = releaseAuditInvariantTest.expectedAuditLinks(
    'v1',
    snapshotId,
    scoreAudit.auditDigest,
  );
  const dataFreshness = {
    schemaVersion: 1,
    tag: 'v1',
    scoredAt: auditScoredAt,
    issueUpdatedAtMax: '2026-01-01T23:00:00Z',
    issueUpdatedAgeHoursAtScore: 1,
    closureProofCheckedAtMax: proofCheckedAt,
    sourceFetchedAtMax: proofCheckedAt,
    sourceFetchedAgeHoursAtScore: 0,
    sources: scoredDataFreshnessSourcesFixture(),
  };
  const publicRelease = {
    schemaVersion: 4,
    snapshotId,
    tag: 'v1',
    score: defaultScore,
    band: defaultBand,
    status: 'eligible',
    recommended: defaultRecommended,
    reason: defaultScoreReason,
    negativeIssues: 1,
    positiveIssues: 0,
    scoredAt: auditScoredAt,
    scoreAudit,
    explanation,
    dataFreshness,
    auditLinks,
    totalAttributedIssues: 1,
    profileEvidence: {
      schemaVersion: 2,
      sourceMode: 'sealed_score_replay',
      issueEvidenceSchemaVersion: 3,
      profileRowCount: 1,
      profileRowsDigest,
      publicationBinding: profilePublicationBinding,
      issueCount: 1,
      weightedIssueCount: 1,
      surfaceIssueCount: 1,
      surfaceWeight: 2.5,
      surfaces: [{
        label: 'Discord',
        icon: 'discord',
        count: 1,
        weight: 2.5,
        tiers: { verifiedDebt: 1 },
        weightByTier: { verifiedDebt: 2.5 },
      }],
    },
    issues: [{
      number: 1,
      title: 'issue 1',
      url: 'https://github.com/x/y/issues/1',
      affectedUsers: 'some',
    }],
  };
  const sourceProvenance = {
    sourceMode: 'current_db',
    scoreTable: 'release_score_audits',
    auditDigest: scoreAudit.auditDigest,
    scoreAuthority: {
      runId: scoreAudit.authorityRunId,
      contentHash: scoreAudit.authorityRunContentHash,
      historyV2SealContentHash: scoreAudit.historyV2SealContentHash,
    },
    scoredAt: auditScoredAt,
    dataFreshnessScoredAt: dataFreshness.scoredAt,
    scoreTimestampAligned: true,
    scoreSourceIdentity: sourceIdentityFixture,
    advisorySnapshot: advisorySnapshotAuditProjectionFixture(),
    sources: dataFreshness.sources,
    rawRows: {
      issues: auditLinks.issues,
      closureProofs: auditLinks.closureProofs,
      reachability: auditLinks.reachability,
    },
  };
  const assertReviewPublicationBinding = (parsed: URL, url: string) => {
    const snapshots = parsed.searchParams.getAll('publicationSnapshot');
    const digests = parsed.searchParams.getAll('auditDigest');
    if (
      snapshots.length !== 1 ||
      snapshots[0] !== snapshotId ||
      digests.length !== 1 ||
      digests[0] !== scoreAudit.auditDigest
    ) {
      throwHttpError(url, 409, {
        error: 'publication snapshot or audit identity changed; reload parent review',
        tag: 'v1',
      });
    }
  };
  const pageLinks = (
    parsed: URL,
    cursor: number,
    limit: number,
    nextCursor: number | null,
  ) => {
    const build = (pageCursor: number) => {
      const params = new URLSearchParams();
      for (const [name, value] of parsed.searchParams) {
        if (name === 'cursor' || name === 'limit') continue;
        params.append(name, value);
      }
      params.set('limit', String(limit));
      params.set('cursor', String(pageCursor));
      return `${parsed.pathname}?${params.toString()}`;
    };
    return {
      self: build(cursor),
      next: nextCursor == null ? null : build(nextCursor),
    };
  };
  mutator?.(dataFreshness, publicRelease);
  const closurePage = (url: string) => {
    const parsed = new URL(url);
    assertReviewPublicationBinding(parsed, url);
    const statusFilter = scalarSearchParam(parsed, 'status', url, 'invalid status', {
      allowedStatuses: CLOSURE_PROOF_STATUSES,
    });
    const riskDispositionFilter = scalarSearchParam(parsed, 'riskDisposition', url, 'invalid riskDisposition', {
      allowedRiskDispositions: CLOSURE_RISK_DISPOSITIONS,
    });
    const issueFilter = issueNumberSearchParam(parsed, url);
    if (statusFilter && !CLOSURE_PROOF_STATUSES.includes(statusFilter as any)) {
      throwHttpError(url, 400, {
        error: 'invalid status',
        status: statusFilter,
        allowedStatuses: CLOSURE_PROOF_STATUSES,
      });
    }
    if (riskDispositionFilter && !CLOSURE_RISK_DISPOSITIONS.includes(riskDispositionFilter as any)) {
      throwHttpError(url, 400, {
        error: 'invalid riskDisposition',
        riskDisposition: riskDispositionFilter,
        allowedRiskDispositions: CLOSURE_RISK_DISPOSITIONS,
      });
    }
    const row = {
      issueNumber: 1,
      title: 'issue 1',
      url: 'https://github.com/x/y/issues/1',
      closedAt: '2026-01-01T12:00:00Z',
      status: 'fixed_in_release',
      summary: 'Fixed in release.',
      riskDisposition: 'credited_release_fix',
      riskDispositionLabel: 'credited release fix',
      riskWeight: 0,
      riskWeightLabel: 'risk 0',
      checkedAt: proofCheckedAt,
      labels: [],
      classification: closureAuditClassificationFixture(),
      classificationDiff: {},
      evidence: closureAuditEvidenceFixture(),
    };
    const rows = (issueFilter == null || issueFilter === row.issueNumber) &&
      (!statusFilter || statusFilter === row.status) &&
      (!riskDispositionFilter || riskDispositionFilter === row.riskDisposition)
      ? [row]
      : [];
    const cursor = integerSearchParam(parsed, 'cursor', url, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = integerSearchParam(parsed, 'limit', url, 50, 1, 100);
    const pageRows = rows.slice(cursor, cursor + limit);
    const sourceRows = [row];
    const filteredCountsByStatus = rows.reduce((acc: any, item) => {
      acc[item.status] = (acc[item.status] ?? 0) + 1;
      return acc;
    }, {});
    const filteredCountsByRiskDisposition = rows.reduce((acc: any, item) => {
      acc[item.riskDisposition] = (acc[item.riskDisposition] ?? 0) + 1;
      return acc;
    }, {});
    const nextCursor = cursor + pageRows.length < rows.length
      ? cursor + pageRows.length
      : null;
    return {
      schemaVersion: 2,
      snapshotId,
      auditDigest: scoreAudit.auditDigest,
      auditIdentity: scoreAudit.auditDigest,
      tag: 'v1',
      sourceMode: 'current_db',
      scoredAt: auditScoredAt,
      dataFreshness,
      filters: {
        issue: issueFilter,
        issueNumber: issueFilter,
        status: statusFilter,
        riskDisposition: riskDispositionFilter,
      },
      totals: {
        unfilteredRows: sourceRows.length,
        filteredRows: rows.length,
        unfilteredDistinctIssues: sourceRows.length,
        filteredDistinctIssues: rows.length,
      },
      total: rows.length,
      totalRows: rows.length,
      distinctIssueCount: rows.length,
      unfilteredCountsByStatus: { fixed_in_release: 1 },
      filteredCountsByStatus,
      unfilteredCountsByRiskDisposition: { credited_release_fix: 1 },
      filteredCountsByRiskDisposition,
      limit,
      cursor,
      nextCursor,
      links: pageLinks(parsed, cursor, limit, nextCursor),
      rows: pageRows,
    };
  };
  const reachabilityPage = (url: string) => {
    const parsed = new URL(url);
    assertReviewPublicationBinding(parsed, url);
    const row = {
      repositoryNameWithOwner: 'openclaw/openclaw',
      number: 1,
      title: 'PR 1',
      url: 'https://github.com/openclaw/openclaw/pull/1',
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-01-01T12:00:00Z',
      status: 'reachable',
      method: 'git-merge-base',
      checkedAt: proofCheckedAt,
      tagCommitOid: tagOid,
      mergeCommitOid: mergeOid,
      prMergeCommitOid: mergeOid,
      baseRefName: 'main',
      evidence: {
        schemaVersion: 1,
        evidence: 'merge_commit_in_release_history',
        method: 'git-merge-base',
        tagCommitOid: tagOid,
        checkedCommitOid: mergeOid,
        baseRefName: 'main',
        commandStatus: 0,
      },
    };
    const statusFilter = scalarSearchParam(parsed, 'status', url, 'invalid status');
    if (statusFilter && !['reachable', 'not_reachable', 'unknown'].includes(statusFilter)) {
      throwHttpError(url, 400, { error: 'invalid status', status: statusFilter });
    }
    const prFilter = scalarSearchParam(parsed, 'pr', url, 'invalid pr filter');
    if (prFilter && !/^(?:[\w.-]+\/[\w.-]+#)?\d+$/.test(prFilter)) {
      throwHttpError(url, 400, { error: 'invalid pr filter', pr: prFilter });
    }
    const rows = (!statusFilter || statusFilter === row.status) &&
      (!prFilter || prFilter === '1' || prFilter === 'openclaw/openclaw#1')
      ? [row]
      : [];
    const cursor = integerSearchParam(parsed, 'cursor', url, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = integerSearchParam(parsed, 'limit', url, 100, 1, 250);
    const pageRows = rows.slice(cursor, cursor + limit);
    const sourceRows = [row];
    const filteredCountsByStatus = rows.reduce((acc: any, item) => {
      acc[item.status] = (acc[item.status] ?? 0) + 1;
      return acc;
    }, {});
    const nextCursor = cursor + pageRows.length < rows.length
      ? cursor + pageRows.length
      : null;
    return {
      schemaVersion: 1,
      snapshotId,
      auditDigest: scoreAudit.auditDigest,
      auditIdentity: scoreAudit.auditDigest,
      tag: 'v1',
      sourceMode: 'current_db',
      scoredAt: auditScoredAt,
      dataFreshness,
      filters: {
        status: statusFilter,
        pr: prFilter ? { repositoryNameWithOwner: prFilter.includes('#') ? prFilter.split('#')[0] : null, number: Number(prFilter.split('#').pop()) } : null,
      },
      totals: {
        unfilteredRows: sourceRows.length,
        filteredRows: rows.length,
        unfilteredPullRequests: sourceRows.length,
        filteredPullRequests: rows.length,
      },
      total: rows.length,
      totalRows: rows.length,
      distinctPullRequestCount: rows.length,
      countsByStatus: filteredCountsByStatus,
      filteredCountsByStatus,
      unfilteredCountsByStatus: { reachable: 1 },
      limit,
      cursor,
      nextCursor,
      links: pageLinks(parsed, cursor, limit, nextCursor),
      rows: pageRows,
    };
  };
  const issueEvidencePage = (url: string) => {
    const parsed = new URL(url);
    assertReviewPublicationBinding(parsed, url);
    const row = {
      tier: 'verifiedFixed',
      tierLabel: 'Contained release fixes',
      tierDescription: 'Closed issues with fix proof contained in this tag; only first-containing fixes receive regression credit.',
      installImpactClass: 'state_data',
      weight: 1,
      fieldConfirmed: true,
      issue: {
        number: 1,
        title: 'issue 1',
        url: 'https://github.com/x/y/issues/1',
        state: 'closed',
        labels: [],
        rawClassification: {
          sentiment: 'negative',
          severity: 'high',
          functionality: 'core',
          scope: 'moderate',
          affectedUsers: 'some',
        },
        classification: {
          sentiment: 'negative',
          severity: 'high',
          functionality: 'core',
          scope: 'moderate',
          affectedUsers: 'some',
        },
        classificationDiff: {},
      },
    };
    const tierFilter = parsed.searchParams.get('tier');
    const tiers = tierFilter ? tierFilter.split(',').map((tier) => tier.trim()).filter(Boolean) : [];
    if (tiers.some((tier) => !(RELEASE_ISSUE_EVIDENCE_TIERS as readonly string[]).includes(tier))) {
      throwHttpError(url, 400, { error: 'invalid tier', tier: tierFilter });
    }
    const impactFilter = parsed.searchParams.get('impact');
    const impacts = impactFilter ? impactFilter.split(',').map((impact) => impact.trim()).filter(Boolean) : [];
    const stateFilter = parsed.searchParams.get('state');
    const states = stateFilter ? stateFilter.split(',').map((state) => state.trim()).filter(Boolean) : [];
    const enumFilter = (key: string) => {
      const raw = parsed.searchParams.get(key);
      return raw ? raw.split(',').map((value) => value.trim()).filter(Boolean) : [];
    };
    const sentiments = enumFilter('sentiment');
    const severities = enumFilter('severity');
    const functionalities = enumFilter('functionality');
    const scopes = enumFilter('scope');
    const affectedUsers = enumFilter('affectedUsers');
    const issueFilter = issueNumberSearchParam(parsed, url);
    const fieldConfirmedFilter = scalarSearchParam(parsed, 'fieldConfirmed', url, 'invalid fieldConfirmed');
    if (fieldConfirmedFilter != null && !['1', 'true', 'yes', '0', 'false', 'no'].includes(fieldConfirmedFilter.toLowerCase())) {
      throwHttpError(url, 400, { error: 'invalid fieldConfirmed', fieldConfirmed: fieldConfirmedFilter });
    }
    const fieldConfirmed = fieldConfirmedFilter == null ? null : ['1', 'true', 'yes'].includes(fieldConfirmedFilter.toLowerCase());
    const minWeightRaw = scalarSearchParam(parsed, 'minWeight', url, 'invalid minWeight');
    const maxWeightRaw = scalarSearchParam(parsed, 'maxWeight', url, 'invalid maxWeight');
    const minWeight = minWeightRaw == null ? null : Number(minWeightRaw);
    const maxWeight = maxWeightRaw == null ? null : Number(maxWeightRaw);
    if (minWeightRaw != null && !Number.isFinite(minWeight)) {
      throwHttpError(url, 400, { error: 'invalid minWeight', minWeight: minWeightRaw });
    }
    if (maxWeightRaw != null && !Number.isFinite(maxWeight)) {
      throwHttpError(url, 400, { error: 'invalid maxWeight', maxWeight: maxWeightRaw });
    }
    if (minWeight != null && maxWeight != null && minWeight > maxWeight) {
      throwHttpError(url, 400, { error: 'invalid weight range', minWeight, maxWeight });
    }
    const sort = scalarSearchParam(parsed, 'sort', url, 'invalid sort') ?? 'rank';
    if (!['rank', 'weight', 'updated', 'created', 'closed', 'number'].includes(sort)) {
      throwHttpError(url, 400, { error: 'invalid sort', sort });
    }
    const direction = scalarSearchParam(parsed, 'direction', url, 'invalid direction') ?? (sort === 'rank' ? 'asc' : 'desc');
    if (!['asc', 'desc'].includes(direction)) {
      throwHttpError(url, 400, { error: 'invalid direction', direction });
    }
    const summaryOnlyRaw = scalarSearchParam(parsed, 'summaryOnly', url, 'invalid summaryOnly');
    if (summaryOnlyRaw != null && !['1', 'true', 'yes', '0', 'false', 'no'].includes(summaryOnlyRaw.toLowerCase())) {
      throwHttpError(url, 400, { error: 'invalid summaryOnly', summaryOnly: summaryOnlyRaw });
    }
    const summaryOnly = ['1', 'true', 'yes'].includes(String(summaryOnlyRaw ?? '').toLowerCase());
    const rows = (!tiers.length || tiers.includes(row.tier)) &&
      (!impacts.length || impacts.includes(row.installImpactClass)) &&
      (!states.length || states.includes(row.issue.state)) &&
      (!sentiments.length || sentiments.includes(row.issue.classification.sentiment)) &&
      (!severities.length || severities.includes(row.issue.classification.severity)) &&
      (!functionalities.length || functionalities.includes(row.issue.classification.functionality)) &&
      (!scopes.length || scopes.includes(row.issue.classification.scope)) &&
      (!affectedUsers.length || affectedUsers.includes(row.issue.classification.affectedUsers)) &&
      (issueFilter == null || row.issue.number === issueFilter) &&
      (fieldConfirmed == null || row.fieldConfirmed === fieldConfirmed) &&
      (minWeight == null || row.weight >= minWeight) &&
      (maxWeight == null || row.weight <= maxWeight)
      ? [row]
      : [];
    const cursor = integerSearchParam(parsed, 'cursor', url, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = integerSearchParam(parsed, 'limit', url, 50, 1, 250);
    const pageRows = summaryOnly ? [] : rows.slice(cursor, cursor + limit);
    const summaryFor = (count: number) => ({
      count,
      weight: count ? 1 : 0,
      fieldConfirmedCount: count ? 1 : 0,
      openCount: 0,
      closedCount: count,
      otherStateCount: 0,
      missingIssueCount: 0,
      byInstallImpactClass: count ? { state_data: 1 } : {},
      weightByInstallImpactClass: count ? { state_data: 1 } : {},
    });
    const countsByTier = {
      verifiedDebt: 0,
      carryoverDebt: 0,
      staleDebt: 0,
      openedFeltSerious: 0,
      verifiedFixed: 1,
      unverifiedClosed: 0,
      unclassifiedIssues: 0,
    };
    const filteredCountsByTier = { ...countsByTier, verifiedFixed: rows.length };
    const summaryByTier = {
      verifiedDebt: summaryFor(0),
      carryoverDebt: summaryFor(0),
      staleDebt: summaryFor(0),
      openedFeltSerious: summaryFor(0),
      verifiedFixed: summaryFor(1),
      unverifiedClosed: summaryFor(0),
      unclassifiedIssues: summaryFor(0),
    };
    const filteredSummaryByTier = { ...summaryByTier, verifiedFixed: summaryFor(rows.length) };
    const responseCursor = summaryOnly ? 0 : cursor;
    const responseLimit = summaryOnly ? 0 : limit;
    const nextCursor = summaryOnly
      ? null
      : cursor + pageRows.length < rows.length
        ? cursor + pageRows.length
        : null;
    return {
      schemaVersion: 2,
      snapshotId,
      auditDigest: scoreAudit.auditDigest,
      auditIdentity: scoreAudit.auditDigest,
      tag: 'v1',
      sourceMode: 'current_db',
      scoredAt: auditScoredAt,
      dataFreshness,
      labelCutoffAt: null,
      filters: {
        tier: tiers.length === 1 ? tiers[0] : null,
        tiers: tiers.length ? tiers : null,
        impact: impacts.length === 1 ? impacts[0] : null,
        impacts: impacts.length ? impacts : null,
        state: states.length === 1 ? states[0] : null,
        states: states.length ? states : null,
        sentiment: sentiments.length === 1 ? sentiments[0] : null,
        sentiments: sentiments.length ? sentiments : null,
        severity: severities.length === 1 ? severities[0] : null,
        severities: severities.length ? severities : null,
        functionality: functionalities.length === 1 ? functionalities[0] : null,
        functionalities: functionalities.length ? functionalities : null,
        scope: scopes.length === 1 ? scopes[0] : null,
        scopes: scopes.length ? scopes : null,
        affectedUsers: affectedUsers.length === 1 ? affectedUsers[0] : null,
        affectedUsersList: affectedUsers.length ? affectedUsers : null,
        issue: issueFilter,
        issueNumber: issueFilter,
        fieldConfirmed,
        minWeight,
        maxWeight,
        sort,
        direction,
        summaryOnly,
      },
      countsByTier,
      summaryByTier,
      unfilteredCountsByTier: countsByTier,
      unfilteredSummaryByTier: summaryByTier,
      filteredCountsByTier,
      filteredSummaryByTier,
      tierInfo: RELEASE_ISSUE_EVIDENCE_TIER_INFO,
      totals: {
        unfilteredRows: 1,
        filteredRows: rows.length,
        unfilteredDistinctIssues: 1,
        filteredDistinctIssues: rows.length,
      },
      total: rows.length,
      totalRows: rows.length,
      distinctIssueCount: rows.length,
      limit: responseLimit,
      cursor: responseCursor,
      nextCursor,
      links: pageLinks(parsed, responseCursor, responseLimit, nextCursor),
      filteredSummary: { count: rows.length, weight: rows.length ? 1 : 0, fieldConfirmedCount: rows.length ? 1 : 0, openCount: 0, closedCount: rows.length, otherStateCount: 0, missingIssueCount: 0, byInstallImpactClass: rows.length ? { state_data: 1 } : {}, weightByInstallImpactClass: rows.length ? { state_data: 1 } : {} },
      rows: pageRows,
    };
  };
  return async (url: string) => {
    if (url.endsWith('/api/status')) {
      return { schemaVersion: 1, refreshing: false, lastError: null, lastRefreshAt: null, processLastRefreshAt: null, lastScoredAt: auditScoredAt, dataFreshness };
    }
    if (url.endsWith('/api/validation/opportunities')) {
      return {
        schemaVersion: 2,
        asOf: auditScoredAt,
        latestRelease: {
          tag: 'v1',
          publishedAt: releasePublishedAt,
          ageMs: 86_401_000,
          ageHours: 86_401_000 / 3_600_000,
        },
        currentSeries: {
          key: validationSeriesKey,
          modelVersion: 'test-model',
          promptVersion: 6,
          codeRevision: validationCodeRevision,
          ledgerForecastCount: 0,
          enrolledOpportunityCount: validationDenominatorRows.length,
        },
        currentAudit: {
          present: true,
          current: true,
          scoreModelVersion: 'test-model',
          promptVersion: 6,
          scoredAt: auditScoredAt,
        },
        counts: validationCounts,
        denominatorLedger: {
          schemaVersion: 3,
          sourcePolicy: 'prospective_append_only_release_catalog_enrollment_v2',
          contentHash: '9'.repeat(64),
          rowCount: validationDenominatorRows.length,
          counts: {
            upcoming: 0,
            eligible: 1,
            captured: 0,
            missed: 1,
            failed: 0,
          },
          integrity: {
            valid: true,
            enrollmentLedgerValid: true,
            operationReceiptLedgerVerified: true,
            errorCount: 0,
            errors: [],
          },
          rows: validationDenominatorRows,
        },
        overallStatus: 'open',
        currentStratum: {
          key: validationSeriesKey,
          status: 'open',
          denominatorReady: true,
          counts: validationCounts,
        },
        nextDeadlineAt: '2026-01-02T06:00:00Z',
        recommendedAction: 'run_verified_refresh_before_deadline',
        opportunities: validationOpportunities,
      };
    }
    if (url.endsWith('/api/config')) return { schemaVersion: 1, releases: 10, refreshMinutes: 0 };
    if (url.endsWith('/api/public')) {
      return {
        schemaVersion: 4,
        snapshotId,
        snapshot: {
          schemaVersion: 1,
          id: snapshotId,
          generatedAt: auditScoredAt,
          source: 'current',
          retained: false,
          stale: false,
          actionable: true,
          ageMs: 0,
          maxAgeMs: null,
        },
        repo: 'x/y',
        updatedAt: auditScoredAt,
        releases: [publicRelease],
      };
    }
    if (url.endsWith('/api/releases')) {
      return [{
        schemaVersion: 2,
        snapshotId,
        tag: 'v1',
        finalScore: defaultScore,
        band: defaultBand,
        status: 'eligible',
        recommended: defaultRecommended,
        reason: defaultScoreReason,
        negativeIssues: 1,
        positiveIssues: 0,
        scoredAt: auditScoredAt,
        scoreAudit,
        explanation,
        dataFreshness,
        auditLinks,
      }];
    }
    if (url.endsWith('/api/releases/history')) {
      return [{
        schemaVersion: 2,
        snapshotId,
        tag: 'v1',
        publishedAt: releasePublishedAt,
        finalScore: defaultScore,
        status: 'eligible',
        band: defaultBand,
        recommended: defaultRecommended,
        scoredAt: auditScoredAt,
        scoreAudit,
        dataFreshness,
        auditLinks,
      }];
    }
    if (url.endsWith('/api/comparison')) {
      return {
        schemaVersion: 1,
        snapshot: { id: 1, sourceUrl: 'http://source.test', capturedAt: 't', pageTitle: 'Snapshot' },
        releases: [{
          tag: 'v1',
          local: {
            schemaVersion: 1,
            score: defaultScore,
            band: defaultBand,
            status: 'eligible',
            recommended: defaultRecommended,
            reason: defaultScoreReason,
            negativeIssues: 1,
            positiveIssues: 0,
            scoredAt: auditScoredAt,
            dataFreshness,
            components: {
              schemaVersion: 1,
              components: defaultScoreConfidence.components,
              evidenceCoverage: defaultScoreConfidence.evidenceCoverage,
              hotfix: defaultScoreConfidence.hotfix,
              reason: defaultScoreReason,
              explanation,
              recommendationDecision: explanation.recommendationDecision,
            },
            gateEvidence: {
              schemaVersion: 1,
              releaseChecks: releaseChecksFixture,
              artifactVerification: artifactVerificationFixture,
              fixProvenance: fixProvenanceFixture(),
            },
          },
          upstream: null,
          delta: { schemaVersion: 1, score: null, negativeIssues: null },
        }],
      };
    }
    if (url.includes('/api/releases/v1/review/closure-proofs')) return closurePage(url);
    if (url.includes('/api/releases/v1/review/reachability')) return reachabilityPage(url);
    if (url.includes('/api/releases/v1/review/issues')) return issueEvidencePage(url);
    if (new URL(url).pathname === '/api/releases/v1/review') {
      assertReviewPublicationBinding(new URL(url), url);
      return {
        snapshotId,
        tag: 'v1',
        auditLinks,
        local: {
          schemaVersion: 1,
          score: defaultScore,
          band: defaultBand,
          status: 'eligible',
          recommended: defaultRecommended,
          reason: defaultScoreReason,
          negativeIssues: 1,
          positiveIssues: 0,
          scoredAt: auditScoredAt,
          dataFreshness,
          sourceProvenance,
          auditDigest: sourceProvenance.auditDigest,
          input: defaultScoreInput,
          issueEvidence: issueEvidenceFixture(),
          gateEvidence: {
            schemaVersion: 1,
            cve: { affected: false, load: 0 },
            stableTagsNewestFirst: ['v1', predecessorTag],
            betaCount: 0,
            breakingCount: 0,
            hoursToNextStable: null,
            hasHotfixSuccessor: false,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: fixProvenanceFixture(),
          },
          components: {
            schemaVersion: 1,
            components: defaultScoreConfidence.components,
            evidenceCoverage: defaultScoreConfidence.evidenceCoverage,
            hotfix: defaultScoreConfidence.hotfix,
            reason: defaultScoreReason,
            recommendationDecision: explanation.recommendationDecision,
            explanation,
          },
        },
      };
    }
    throw new Error(`unexpected URL ${url}`);
  };
}

function unscoredApiFixtureFetchJson() {
  const baseFetchJson = apiFixtureFetchJson();
  const snapshotId = 'f'.repeat(64);
  const reason =
    'Analysis is stale. Previous audited status: eligible. Refresh before installing.';
  const staleAudit = {
    schemaVersion: 1,
    state: 'stale',
    message: reason,
    previousStatus: null,
    auditedAt: null,
    causes: ['audit_missing'],
  };
  const dataFreshness = {
    schemaVersion: 1,
    tag: 'v1',
    scoredAt: null,
    issueUpdatedAtMax: null,
    issueUpdatedAgeHoursAtScore: null,
    closureProofCheckedAtMax: null,
    sourceFetchedAtMax: null,
    sourceFetchedAgeHoursAtScore: null,
    sources: unscoredDataFreshnessSourcesFixture(),
  };
  const auditLinks = releaseAuditInvariantTest.expectedAuditLinks(
    'v1',
    snapshotId,
    null,
  );
  const common = {
    band: 'wait',
    status: 'stale',
    diagnosticStatus: 'eligible',
    staleAudit,
    recommended: false,
    reason,
    negativeIssues: null,
    positiveIssues: null,
    scoredAt: null,
    dataFreshness,
  };
  return async (url: string) => {
    const parsed = new URL(url);
    if (parsed.pathname === '/api/status') {
      return {
        schemaVersion: 1,
        refreshing: false,
        lastError: null,
        lastRefreshAt: null,
        processLastRefreshAt: null,
        lastScoredAt: null,
      };
    }
    if (
      parsed.pathname === '/api/validation/opportunities' ||
      parsed.pathname === '/api/config'
    ) {
      return baseFetchJson(url);
    }
    if (parsed.pathname === '/api/releases') {
      return [{
        schemaVersion: 2,
        snapshotId,
        tag: 'v1',
        finalScore: null,
        ...common,
        scoreAudit: null,
        explanation: null,
        brokenSurfaces: [],
        closedSeriousFixed: null,
        openedSeriousDuringReign: null,
        auditLinks,
      }];
    }
    if (parsed.pathname === '/api/releases/history') return [];
    if (parsed.pathname === '/api/public') {
      return {
        schemaVersion: 4,
        snapshotId,
        snapshot: {
          schemaVersion: 1,
          id: snapshotId,
          generatedAt: auditScoredAt,
          source: 'current',
          retained: false,
          stale: false,
          actionable: true,
          ageMs: 0,
          maxAgeMs: null,
        },
        repo: 'x/y',
        updatedAt: null,
        releases: [{
          schemaVersion: 4,
          snapshotId,
          tag: 'v1',
          score: null,
          ...common,
          scoreAudit: null,
          explanation: null,
          auditLinks,
          totalAttributedIssues: 0,
          profileEvidence: {
            schemaVersion: 2,
            sourceMode: 'current_diagnostic_evidence',
            issueEvidenceSchemaVersion: 3,
            profileRowCount: 0,
            profileRowsDigest: '0'.repeat(64),
            publicationBinding: null,
            issueCount: 0,
            weightedIssueCount: 0,
            surfaceIssueCount: 0,
            surfaceWeight: 0,
            surfaces: [],
          },
          issues: [],
          watchIssues: [],
        }],
      };
    }
    if (parsed.pathname === '/api/comparison') {
      return {
        schemaVersion: 1,
        snapshot: {
          id: 1,
          sourceUrl: 'http://source.test',
          capturedAt: 't',
          pageTitle: 'Snapshot',
        },
        releases: [{
          tag: 'v1',
          local: {
            schemaVersion: 1,
            score: null,
            ...common,
            modelVersion: null,
            components: null,
            input: null,
            gateEvidence: null,
          },
          upstream: null,
          delta: { schemaVersion: 1, score: null, negativeIssues: null },
        }],
      };
    }
    if (parsed.pathname === '/api/releases/v1/review') {
      assert.equal(parsed.searchParams.get('publicationSnapshot'), snapshotId);
      assert.equal(parsed.searchParams.get('auditDigest'), 'unavailable');
      return {
        snapshotId,
        tag: 'v1',
        auditLinks,
        local: {
          schemaVersion: 1,
          score: null,
          ...common,
          sourceProvenance: null,
          auditDigest: null,
          modelVersion: null,
          promptVersion: null,
          input: null,
          components: null,
          issueEvidence: null,
          gateEvidence: null,
        },
      };
    }
    throw new Error(`unexpected unscored URL ${url}`);
  };
}

function apiFixtureFetchJsonWithMutatedExplanation(mutator: (explanation: any) => void) {
  const fetchJson = apiFixtureFetchJson();
  return async (url: string) => {
    const payload = JSON.parse(JSON.stringify(await fetchJson(url)));
    if (url.endsWith('/api/public')) {
      mutator(payload.releases[0].explanation);
    } else if (url.endsWith('/api/releases')) {
      mutator(payload[0].explanation);
    } else if (url.endsWith('/api/comparison')) {
      mutator(payload.releases[0].local.components.explanation);
    } else if (new URL(url).pathname === '/api/releases/v1/review') {
      mutator(payload.local.components.explanation);
    }
    return payload;
  };
}

function throwHttpError(url: string, status: number, payload: unknown): never {
  const error: any = new Error(`${url} returned ${status}: ${JSON.stringify(payload)}`);
  error.status = status;
  error.body = JSON.stringify(payload);
  error.payload = payload;
  throw error;
}

function scalarSearchParam(parsed: URL, key: string, url: string, error: string, extra: Record<string, unknown> = {}): string | null {
  const values = parsed.searchParams.getAll(key);
  if (values.length === 0) return null;
  if (values.length > 1) throwHttpError(url, 400, { error, [key]: values, ...extra });
  const value = values[0].trim();
  return value ? value : null;
}

function integerSearchParam(parsed: URL, key: string, url: string, fallback: number, min: number, max: number): number {
  const value = scalarSearchParam(parsed, key, url, `invalid ${key}`);
  if (value == null) return fallback;
  if (!/^-?\d+$/.test(value)) throwHttpError(url, 400, { error: `invalid ${key}`, [key]: value });
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throwHttpError(url, 400, { error: `invalid ${key}`, [key]: value });
  return Math.max(min, Math.min(max, number));
}

function issueNumberSearchParam(parsed: URL, url: string): number | null {
  const issue = scalarSearchParam(parsed, 'issue', url, 'invalid issue');
  const number = scalarSearchParam(parsed, 'number', url, 'invalid issue');
  if (issue == null && number == null) return null;
  const values = [issue, number].filter((value): value is string => value != null);
  const parsedValues = values.map((value) => Number(value));
  if (parsedValues.some((value) => !Number.isInteger(value) || value <= 0)) {
    throwHttpError(url, 400, { error: 'invalid issue', issue, number });
  }
  if (parsedValues.some((value) => value !== parsedValues[0])) {
    throwHttpError(url, 400, { error: 'invalid issue', issue, number });
  }
  return parsedValues[0];
}

describe('release audit invariant policy mirrors', () => {
  it('requires exact publication binding on every published audit link', () => {
    const publicationSnapshot = 'a'.repeat(64);
    const auditDigest = 'b'.repeat(64);
    const canonical = releaseAuditInvariantTest.expectedAuditLinks(
      'v1',
      publicationSnapshot,
      auditDigest,
    );
    const cases = [
      {
        label: 'missing snapshot',
        mutate: (links: Record<string, string>) => {
          const url = new URL(links.review, 'https://radar.invalid');
          url.searchParams.delete('publicationSnapshot');
          links.review = `${url.pathname}${url.search}`;
        },
      },
      {
        label: 'duplicate digest',
        mutate: (links: Record<string, string>) => {
          const url = new URL(links.issues, 'https://radar.invalid');
          url.searchParams.append('auditDigest', auditDigest);
          links.issues = `${url.pathname}${url.search}`;
        },
      },
      {
        label: 'snapshot mismatch',
        mutate: (links: Record<string, string>) => {
          const url = new URL(links.closureProofs, 'https://radar.invalid');
          url.searchParams.set('publicationSnapshot', 'c'.repeat(64));
          links.closureProofs = `${url.pathname}${url.search}`;
        },
      },
      {
        label: 'digest mismatch',
        mutate: (links: Record<string, string>) => {
          const url = new URL(links.reachability, 'https://radar.invalid');
          url.searchParams.set('auditDigest', 'd'.repeat(64));
          links.reachability = `${url.pathname}${url.search}`;
        },
      },
      {
        label: 'cross release path',
        mutate: (links: Record<string, string>) => {
          links.review = links.review.replace('/v1/', '/v2/');
        },
      },
      {
        label: 'unexpected query',
        mutate: (links: Record<string, string>) => {
          const url = new URL(links.review, 'https://radar.invalid');
          url.searchParams.append('debug', '1');
          links.review = `${url.pathname}${url.search}`;
        },
      },
    ];

    for (const testCase of cases) {
      const links = structuredClone(canonical);
      testCase.mutate(links);
      const failures: string[] = [];
      const result = releaseAuditInvariantTest.verifyAuditLinks({
        failures,
        tag: 'v1',
        label: testCase.label,
        auditLinks: links,
        publicationSnapshot,
        auditDigest,
      });
      assert.equal(result, null, testCase.label);
      assert.ok(failures.length > 0, testCase.label);
    }
  });

  it('appends duplicate filter probes without permitting publication overrides', () => {
    const bound = new URL(
      releaseAuditInvariantTest.expectedAuditLinks(
        'v1',
        'a'.repeat(64),
        'b'.repeat(64),
      ).issues,
      'https://radar.invalid',
    ).toString();
    const probed = new URL(releaseAuditInvariantTest.reviewUrlWithQuery(bound, [
      ['issue', 1],
      ['issue', 2],
    ]));

    assert.deepEqual(probed.searchParams.getAll('issue'), ['1', '2']);
    assert.deepEqual(probed.searchParams.getAll('publicationSnapshot'), ['a'.repeat(64)]);
    assert.deepEqual(probed.searchParams.getAll('auditDigest'), ['b'.repeat(64)]);
    assert.throws(
      () => releaseAuditInvariantTest.reviewUrlWithQuery(bound, [
        ['publicationSnapshot', 'c'.repeat(64)],
      ]),
      /cannot override publicationSnapshot/,
    );
    assert.throws(
      () => releaseAuditInvariantTest.reviewUrlWithQuery(bound, [
        ['auditDigest', 'd'.repeat(64)],
      ]),
      /cannot override auditDigest/,
    );
  });

  it('withholds mixed-sibling credit for target absence before predecessor containment', () => {
    const outcome = releaseAuditInvariantTest.expectedFixCreditDecisionOutcome([
      {
        kind: 'trusted_pull_request',
        merged: true,
        target: { status: 'reachable', strictValid: true },
        predecessor: { status: 'not_reachable', strictValid: true },
      },
      {
        kind: 'trusted_pull_request',
        merged: true,
        target: { status: 'not_reachable', strictValid: true },
        predecessor: { status: 'reachable', strictValid: true },
      },
    ], directCommitReachabilitySummaryFixture());

    assert.deepEqual(outcome, {
      status: 'withheld',
      reasonCode: 'target_reachability_not_reachable',
    });
  });

  it('independently replays strict direct-commit proof identities and fails closed on mutations', () => {
    const boundary = {
      valid: true,
      targetCommitOid: tagOid,
      predecessorCommitOid: predecessorOid,
    };
    const replay = (proof: any) =>
      releaseAuditInvariantTest.expectedDirectCommitProofIdentity(
        proof,
        'v1',
        predecessorTag,
        boundary,
      );

    const valid = replay(directCommitProofFixture());
    assert.equal(valid.strictValid, true);
    assert.equal(valid.validationReasonCode, null);
    assert.equal(valid.target?.strictValid, true);
    assert.equal(valid.predecessor?.strictValid, true);
    assert.equal(valid.releaseAncestry?.strictValid, true);

    const cases = [
      {
        name: 'repository',
        mutate(proof: any) {
          proof.repositoryNameWithOwner = 'fork/openclaw';
        },
        expected: 'repository_identity_mismatch',
      },
      {
        name: 'evidence',
        mutate(proof: any) {
          delete proof.target.evidence.commandStatus;
        },
        expected: 'reachability_evidence_invalid',
      },
      {
        name: 'commit',
        mutate(proof: any) {
          proof.target.checkedCommitOid = 'f'.repeat(40);
          proof.target.evidence.checkedCommitOid = 'f'.repeat(40);
        },
        expected: 'reachability_evidence_invalid',
      },
      {
        name: 'boundary',
        mutate(proof: any) {
          proof.targetTag = 'v-other';
        },
        expected: 'release_boundary_mismatch',
      },
      {
        name: 'derived-fields',
        mutate(proof: any) {
          proof.strictValid = true;
        },
        expected: 'unexpected_derived_validation_fields',
      },
    ] as const;

    for (const testCase of cases) {
      const proof: any = directCommitProofFixture();
      testCase.mutate(proof);
      const result = replay(proof);
      assert.equal(result.strictValid, false, testCase.name);
      assert.equal(result.validationReasonCode, testCase.expected, testCase.name);
    }
  });

  it('derives direct-commit decision outcomes from complete proof coverage', () => {
    assert.deepEqual(
      releaseAuditInvariantTest.expectedFixCreditDecisionOutcome(
        [],
        directCommitReachabilitySummaryFixture({ missingProofCount: 1 }),
      ),
      {
        status: 'withheld',
        reasonCode: 'direct_commit_first_containing_proof_missing',
      },
    );
    assert.deepEqual(
      releaseAuditInvariantTest.expectedFixCreditDecisionOutcome(
        [],
        directCommitReachabilitySummaryFixture({ invalidProofCount: 1 }),
      ),
      {
        status: 'withheld',
        reasonCode: 'direct_commit_first_containing_proof_invalid',
      },
    );
    assert.deepEqual(
      releaseAuditInvariantTest.expectedFixCreditDecisionOutcome(
        [],
        directCommitReachabilitySummaryFixture({
          declaredCreditedCommitOids: [directCommitOid],
          creditedCommitOids: [directCommitOid],
        }),
      ),
      {
        status: 'credited',
        reasonCode: 'first_containing_direct_commit',
      },
    );
    assert.deepEqual(
      releaseAuditInvariantTest.expectedFixCreditDecisionOutcome(
        [],
        directCommitReachabilitySummaryFixture({
          predecessorContainedCommitOids: [directCommitOid],
        }),
      ),
      {
        status: 'withheld',
        reasonCode: 'direct_commit_not_first_containing',
      },
    );
  });

  it('derives score-model capabilities from minimum evidence versions', () => {
    const supports = releaseAuditInvariantTest.scoreModelSupportsCapability;

    assert.equal(supports('evidence-v19-legacy', 'exclusiveRiskLedger'), false);
    assert.equal(supports('evidence-v20-exclusive-risk-ledger', 'exclusiveRiskLedger'), true);
    assert.equal(supports('evidence-v20-exclusive-risk-ledger', 'rawClassificationProvenance'), false);
    assert.equal(supports('evidence-v21-human-confirmed-field', 'rawClassificationProvenance'), true);
    assert.equal(supports('evidence-v25-closure-context', 'missingEvidenceFailClosed'), false);
    assert.equal(supports('evidence-v26-calibrated-evidence', 'missingEvidenceFailClosed'), true);
    assert.equal(supports(SCORE_MODEL_VERSION, 'affirmativeClosureRiskCeiling'), true);
    assert.equal(supports('evidence-v28-future-compatible', 'missingEvidenceFailClosed'), true);
    assert.equal(supports('evidence-v28-future-compatible', 'rawClassificationProvenance'), true);
    assert.equal(supports('custom-model-v99', 'rawClassificationProvenance'), false);
  });

  it('ignores only obsolete manifest failures for excluded legacy forecasts', () => {
    const manifest = obsoleteSourceIdentity();
    const manifestProblems = scoreSourceIdentityManifestProblems(manifest);
    const forecast = {
      decision_id: 'legacy-late',
      audit_history_run_id: 'run-legacy',
      opportunity_code: 'first_verified_after_3h',
      recorded_at: '2026-01-02T01:00:00Z',
      latest_release_published_at: '2026-01-01T00:00:00Z',
      decision_json: JSON.stringify({ schemaVersion: 2 }),
      source_identity_json: JSON.stringify(manifest),
    };
    const historyRows = [{
      run_id: 'run-legacy',
      release_tag: 'v-legacy',
      source_identity_json: JSON.stringify(manifest),
    }];
    const sourceFailure =
      `forecast legacy-late has invalid source provenance: ${manifestProblems.join(', ')}`;
    const historyFailure =
      `forecast legacy-late references invalid history provenance run-legacy/v-legacy: ` +
      manifestProblems.join(', ');
    const structuralFailures = [
      'forecast legacy-late previous hash does not match the prior forecast',
      'forecast legacy-late content hash is invalid',
      'forecast legacy-late decision ID is invalid',
    ];

    assert.deepEqual(
      releaseAuditInvariantTest.scorePublicationFailuresForAudit(
        { db: publicationDbFixture({ forecast, historyRows }) },
        { failures: [sourceFailure, historyFailure, ...structuralFailures] },
      ),
      structuralFailures,
    );
  });

  it('keeps active and structurally invalid legacy forecast provenance strict', () => {
    const manifest = obsoleteSourceIdentity();
    const activeForecast = {
      decision_id: 'legacy-active',
      audit_history_run_id: 'run-active',
      opportunity_code: 'first_verified_after_3h',
      recorded_at: '2026-01-01T04:00:00Z',
      latest_release_published_at: '2026-01-01T00:00:00Z',
      decision_json: JSON.stringify({ schemaVersion: 2 }),
      source_identity_json: JSON.stringify(manifest),
    };
    const activeProblems = scoreSourceIdentityManifestProblems(manifest);
    const activeFailure =
      `forecast legacy-active has invalid source provenance: ${activeProblems.join(', ')}`;
    const activeHistoryRows = [{
      run_id: 'run-active',
      release_tag: 'v-active',
      source_identity_json: JSON.stringify(manifest),
    }];
    const activeHistoryFailure =
      `forecast legacy-active references invalid history provenance run-active/v-active: ` +
      activeProblems.join(', ');
    assert.deepEqual(
      releaseAuditInvariantTest.scorePublicationFailuresForAudit(
        { db: publicationDbFixture({ forecast: activeForecast, historyRows: activeHistoryRows }) },
        { failures: [activeFailure, activeHistoryFailure] },
      ),
      [activeFailure, activeHistoryFailure],
    );

    const invalidManifest = { ...manifest, digest: '0'.repeat(64) };
    const invalidForecast = {
      ...activeForecast,
      decision_id: 'legacy-late-invalid',
      recorded_at: '2026-01-02T01:00:00Z',
      source_identity_json: JSON.stringify(invalidManifest),
    };
    const invalidProblems = scoreSourceIdentityManifestProblems(invalidManifest);
    const invalidFailure =
      `forecast legacy-late-invalid has invalid source provenance: ${invalidProblems.join(', ')}`;
    assert.deepEqual(
      releaseAuditInvariantTest.scorePublicationFailuresForAudit(
        { db: publicationDbFixture({ forecast: invalidForecast, historyRows: [] }) },
        { failures: [invalidFailure] },
      ),
      [invalidFailure],
    );
  });
});

describe('release audit exhaustive pagination', () => {
  function pageFixture(
    rows: Array<{ id: string }>,
    cursor: number,
    {
      total = rows.length,
      nextCursor,
      pageRows,
    }: {
      total?: number;
      nextCursor?: number | null;
      pageRows?: Array<{ id: string }>;
    } = {},
  ) {
    const selected = pageRows ?? rows.slice(cursor, cursor + 2);
    const resolvedNextCursor = nextCursor === undefined
      ? cursor + selected.length < total
        ? cursor + selected.length
        : null
      : nextCursor;
    return {
      total,
      totalRows: total,
      totals: { filteredRows: total },
      limit: 2,
      cursor,
      nextCursor: resolvedNextCursor,
      links: {
        next: resolvedNextCursor == null
          ? null
          : `/audit?limit=2&cursor=${resolvedNextCursor}`,
      },
      rows: selected,
    };
  }

  async function collectPaginationCase(
    mutate: (page: any, cursor: number, rows: Array<{ id: string }>) => any =
      (page) => page,
  ) {
    const rows = ['a', 'b', 'c', 'd', 'e'].map((id) => ({ id }));
    const pageAt = (cursor: number) =>
      mutate(pageFixture(rows, cursor), cursor, rows);
    const failures: string[] = [];
    let validatedPages = 0;
    const collected = await releaseAuditInvariantTest.collectExhaustiveAuditPages({
      base: 'http://example.test/audit',
      firstPage: pageAt(0),
      fetchJson: async (url: string) => {
        const cursor = Number(new URL(url).searchParams.get('cursor') ?? 0);
        return pageAt(cursor);
      },
      failures,
      tag: 'v1',
      label: 'test audit',
      limit: 2,
      identity: (row: { id: string }) => row.id,
      expectedIdentities: rows.map((row) => row.id),
      validatePage: () => {
        validatedPages++;
      },
    });
    return { collected, failures, validatedPages };
  }

  it('exhausts and validates every page', async () => {
    const result = await collectPaginationCase();
    assert.deepEqual(result.failures, []);
    assert.deepEqual(result.collected.map((row: any) => row.id), ['a', 'b', 'c', 'd', 'e']);
    assert.equal(result.validatedPages, 3);
  });

  it('rejects a duplicate identity first introduced on page three', async () => {
    const result = await collectPaginationCase((page, cursor, rows) =>
      cursor === 4
        ? pageFixture(rows, cursor, { pageRows: [rows[1]], nextCursor: null })
        : page);
    assert.ok(result.failures.some((failure) =>
      /must not repeat identity b/.test(failure)));
  });

  it('rejects total drift after page two', async () => {
    const result = await collectPaginationCase((page, cursor) =>
      cursor === 4
        ? { ...page, total: 4, totalRows: 4, totals: { filteredRows: 4 } }
        : page);
    assert.ok(result.failures.some((failure) =>
      /total must remain stable at 5/.test(failure)));
  });

  it('rejects cursor cycles and lack of progress', async () => {
    const result = await collectPaginationCase((page, cursor) =>
      cursor === 2 ? { ...page, nextCursor: 2 } : page);
    assert.ok(result.failures.some((failure) =>
      /nextCursor \(2\) must advance/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /cursor cycle detected at 2/.test(failure)));
  });

  it('rejects an exhausted identity union with a missing expected row', async () => {
    const result = await collectPaginationCase((page, cursor, rows) =>
      cursor === 4
        ? pageFixture(rows, cursor, { pageRows: [{ id: 'x' }], nextCursor: null })
        : page);
    assert.ok(result.failures.some((failure) =>
      /missing=e, extra=x/.test(failure)));
  });

  it('rejects valid-looking content drift on row 26 beyond preview caps', async () => {
    const expectedRows = Array.from({ length: 26 }, (_, index) => ({
      id: `row-${index + 1}`,
      commitOid: 'a'.repeat(40),
      evidence: {
        status: 'reachable',
        checkedCommitOid: 'a'.repeat(40),
      },
    }));
    const apiRows = structuredClone(expectedRows);
    apiRows[25] = {
      ...apiRows[25],
      commitOid: 'b'.repeat(40),
      evidence: {
        status: 'reachable',
        checkedCommitOid: 'b'.repeat(40),
      },
    };
    const limit = 5;
    const pageAt = (cursor: number) => {
      const rows = apiRows.slice(cursor, cursor + limit);
      const nextCursor = cursor + rows.length < apiRows.length
        ? cursor + rows.length
        : null;
      return {
        total: apiRows.length,
        totalRows: apiRows.length,
        totals: { filteredRows: apiRows.length },
        limit,
        cursor,
        nextCursor,
        links: {
          next: nextCursor == null
            ? null
            : `/audit?limit=${limit}&cursor=${nextCursor}`,
        },
        rows,
      };
    };
    const failures: string[] = [];

    await releaseAuditInvariantTest.collectExhaustiveAuditPages({
      base: 'http://example.test/audit',
      firstPage: pageAt(0),
      fetchJson: async (url: string) =>
        pageAt(Number(new URL(url).searchParams.get('cursor') ?? 0)),
      failures,
      tag: 'v1',
      label: 'exact-content audit',
      limit,
      identity: (row: { id: string }) => row.id,
      expectedIdentities: expectedRows.map((row) => row.id),
      expectedRows,
    });

    assert.ok(failures.some((failure) =>
      /row row-26 must exactly match independently reconstructed DB content/.test(failure)));
  });
});

describe('verifyReleaseAudit', () => {
  it('passes coherent DB and API invariants', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({ reader: reader(), apiBase: 'http://example.test', fetchJson });
    assert.deepEqual(result.failures, []);
    assert.deepEqual(result.rows, [{ tag: 'v1', closed: 1, verified: 1, unverified: 0, proof: 1, counted: 1, notCounted: 0 }]);
  });

  it('keeps bounded audit selection separate from API publication scope', async () => {
    const auditReader: any = reader();
    const listReleases = auditReader.listReleases;
    const calls: Array<{ limit: number; scoredOnly: boolean }> = [];
    auditReader.listReleases = (
      limit: number,
      options: { scoredOnly?: boolean } = {},
    ) => {
      calls.push({
        limit,
        scoredOnly: options.scoredOnly === true,
      });
      return listReleases(limit, options);
    };
    const baseFetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: auditReader,
      apiBase: 'http://example.test',
      limit: 1,
      scoredOnly: true,
      fetchJson: async (url: string) =>
        url.endsWith('/api/config')
          ? { schemaVersion: 1, releases: 2, refreshMinutes: 0 }
          : baseFetchJson(url),
    });

    assert.deepEqual(calls, [{
      limit: 1,
      scoredOnly: true,
    }, {
      limit: 2,
      scoredOnly: false,
    }]);
    assert.deepEqual(result.releases.map((release: any) => release.tag), ['v1']);
    assert.deepEqual(result.failures, []);
  });

  it('rejects self-consistent rehashed release evidence that contradicts DB operands', async () => {
    const explanation = scoreExplanationFixture({
      evidence: {
        release: { betaCount: defaultScoreInput.betaCount + 1 },
      },
    });
    const result = await verifyReleaseAudit({
      reader: readerWithMutatedPersistedComponents((components) => {
        components.explanation = explanation;
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /scoreLedger release manifest must match independently reconstructed evidence/.test(failure)));
  });

  it('keeps release tag in evidence without treating it as a score-input field', async () => {
    const explanation = scoreExplanationFixture({
      evidence: {
        release: { tag: 'v-other' },
      },
    });
    const result = await verifyReleaseAudit({
      reader: readerWithMutatedPersistedComponents((components) => {
        components.explanation = explanation;
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /scoreLedger release manifest must match independently reconstructed evidence/.test(failure)));
    assert.ok(result.failures.every((failure) => !/score input tag/.test(failure)));
  });

  it('reconstructs hotfix successors from the full active catalog', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        activeReleaseRows: [{
          tag: 'v1-1',
          published_at: '2026-01-01T01:00:00Z',
          catalog_rank: 0,
          prerelease: 0,
        }, {
          tag: 'v1',
          published_at: defaultScoreInput.publishedAt,
          catalog_rank: 1,
          prerelease: 0,
        }, {
          tag: predecessorTag,
          published_at: '2025-12-01T00:00:00Z',
          catalog_rank: 2,
          prerelease: 0,
        }],
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /score input hasHotfixSuccessor \(false\) must match bound evidence \(true\)/.test(
        failure,
      )));
  });

  it('does not reconstruct prerelease or older hotfix-shaped tags as successors', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        activeReleaseRows: [{
          tag: 'v1-2',
          published_at: '2026-01-01T01:00:00Z',
          catalog_rank: 0,
          prerelease: 1,
        }, {
          tag: 'v1',
          published_at: defaultScoreInput.publishedAt,
          catalog_rank: 1,
          prerelease: 0,
        }, {
          tag: 'v1-1',
          published_at: '2025-12-31T23:00:00Z',
          catalog_rank: 2,
          prerelease: 0,
        }, {
          tag: predecessorTag,
          published_at: '2025-12-01T00:00:00Z',
          catalog_rank: 3,
          prerelease: 0,
        }],
      }),
    });

    assert.ok(result.failures.every((failure) =>
      !/score input hasHotfixSuccessor/.test(failure)));
  });

  it('rejects self-consistent rehashed coverage evidence that contradicts DB rows', async () => {
    const explanation = scoreExplanationFixture({
      evidence: {
        coverage: {
          classifierSourceIdentityDigest: 'f'.repeat(64),
        },
      },
    });
    const result = await verifyReleaseAudit({
      reader: readerWithMutatedPersistedComponents((components) => {
        components.explanation = explanation;
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /scoreLedger coverage manifest must match independently reconstructed evidence/.test(failure)));
  });

  it('reads classification source identity independently when the row projection omits it', async () => {
    const auditReader = reader();
    const projectedRows = auditReader.issuesForVersion('v1').map((row) => {
      const projected = structuredClone(row);
      Reflect.deleteProperty(projected, 'source_identity_digest');
      return projected;
    });
    auditReader.issuesForVersion = () => projectedRows;
    (auditReader as any).db = {
      prepare(sql: string) {
        assert.match(sql, /FROM classifications/);
        return {
          get: () => ({
            source_identity_digest: classificationSourceIdentityDigest,
          }),
        };
      },
    };

    const result = await verifyReleaseAudit({ reader: auditReader });

    assert.ok(!result.failures.some((failure) =>
      /scoreLedger coverage source cannot be independently reconstructed/.test(failure)));
  });

  it('rejects rehashed canonical explanation prose tampering', async () => {
    const explanation = scoreExplanationFixture();
    const tamperedText =
      'No field blocker is recorded, but this submitted explanation changes the model claim.';
    explanation.limits[0] = tamperedText;
    explanation.limitDetails[0].text = tamperedText;
    explanation.scoreLedger = structuredClone(
      bindScoreExplanationAudit(explanation.scoreLedger, explanation),
    );
    const result = await verifyReleaseAudit({
      reader: readerWithMutatedPersistedComponents((components) => {
        components.explanation = explanation;
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /model-ceiling prose must equal the independently known canonical claim/.test(failure)));
  });

  it('replays score reasons even when persisted reason fields agree on forged prose', async () => {
    const forgedReason = 'Self-consistent persisted prose that does not follow from the score input.';
    const auditReader = readerWithMutatedPersistedComponents((components) => {
      components.reason = forgedReason;
    });
    auditReader.listReleases()[0].score_reason = forgedReason;

    const result = await verifyReleaseAudit({ reader: auditReader });

    assert.ok(result.failures.some((failure) =>
      /persisted components\.reason must equal independently replayed reason/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /release score_reason must equal independently replayed reason/.test(failure)));
  });

  it('accepts a genuinely unscored release without audit or authority bindings', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{
          tag: 'v1',
          final_score: null,
          state: null,
          recommended: 0,
          scored_at: null,
          score_reason: null,
          negative_issues: null,
          positive_issues: null,
          broken_surfaces: null,
          closed_serious_fixed: 0,
          opened_serious_during_reign: 0,
        }],
        rawClosed: [],
        closed: [],
        opened: [],
        verified: [],
        unverified: [],
        proofRows: [],
        prEvidence: [],
        proofDependencyFreshness: [],
        issueNumbers: [],
        audit: null,
        publicationDigests: {},
        publicationAuthorityBindings: {},
      }),
      apiBase: 'http://example.test',
      fetchJson: unscoredApiFixtureFetchJson(),
    });

    assert.deepEqual(result.failures, []);
    assert.deepEqual(result.rows, [{
      tag: 'v1',
      closed: 0,
      verified: 0,
      unverified: 0,
      proof: 0,
      counted: 0,
      notCounted: 0,
    }]);
  });

  it('rejects every stale score-derived column on an unscored release', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{
          tag: 'v1',
          final_score: null,
          state: 'eligible',
          recommended: 1,
          scored_at: null,
          score_reason: 'stale reason',
          negative_issues: 1,
          positive_issues: 2,
          broken_surfaces: '["cli"]',
          closed_serious_fixed: 3,
          opened_serious_during_reign: 4,
        }],
        rawClosed: [],
        closed: [],
        opened: [],
        verified: [],
        unverified: [],
        proofRows: [],
        prEvidence: [],
        proofDependencyFreshness: [],
        issueNumbers: [],
        audit: null,
        publicationDigests: {},
        publicationAuthorityBindings: {},
      }),
    });

    for (const field of [
      'negative_issues',
      'positive_issues',
      'state',
      'score_reason',
      'broken_surfaces',
      'recommended',
      'closed_serious_fixed',
      'opened_serious_during_reign',
    ]) {
      assert.ok(
        result.failures.some((failure) =>
          failure.includes(`unscored release ${field} must`)),
        field,
      );
    }
  });

  it('rejects a persisted score audit attached to an otherwise unscored release', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{
          tag: 'v1',
          final_score: null,
          state: null,
          recommended: 0,
          scored_at: null,
          score_reason: null,
          negative_issues: null,
          positive_issues: null,
          broken_surfaces: null,
          closed_serious_fixed: 0,
          opened_serious_during_reign: 0,
        }],
        publicationDigests: {},
        publicationAuthorityBindings: {},
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /unscored release must not have a release score audit row/.test(failure)));
  });

  it('rejects a fabricated API score summary for an unscored release', async () => {
    const fetchJson = unscoredApiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{
          tag: 'v1',
          final_score: null,
          state: null,
          recommended: 0,
          scored_at: null,
          score_reason: null,
          negative_issues: null,
          positive_issues: null,
          broken_surfaces: null,
          closed_serious_fixed: 0,
          opened_serious_during_reign: 0,
        }],
        rawClosed: [],
        closed: [],
        opened: [],
        verified: [],
        unverified: [],
        proofRows: [],
        prEvidence: [],
        proofDependencyFreshness: [],
        issueNumbers: [],
        audit: null,
        publicationDigests: {},
        publicationAuthorityBindings: {},
      }),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname !== '/api/releases') return payload;
        return payload.map((release: any) => ({
          ...release,
          scoreAudit: {
            schemaVersion: 2,
            reviewSchemaVersion: 1,
            auditDigest: 'd'.repeat(64),
            authorityRunId: 'fabricated',
            authorityRunContentHash: 'a'.repeat(64),
            historyV2SealContentHash: 'b'.repeat(64),
            modelVersion: 'fabricated',
            promptVersion: 1,
            evidenceCoverage: 1,
            rawIssueCount: 0,
            classifiedIssueCount: 0,
          },
        }));
      },
    });

    assert.ok(result.failures.some((failure) =>
      /releases row scoreAudit must be null while the release is unscored/.test(failure)));
  });

  it('allows the internal comparison endpoint to be disabled', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        if (url.endsWith('/api/comparison')) throw new Error(`${url} returned 404`);
        return fetchJson(url);
      },
    });
    assert.deepEqual(result.failures, []);
  });

  it('fails when the recommended flag does not match the scoring threshold policy', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{
          tag: 'v1',
          final_score: defaultScore,
          state: 'eligible',
          recommended: 0,
          scored_at: auditScoredAt,
          score_reason: 'test reason',
          negative_issues: 1,
          positive_issues: 0,
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /recommended release tags/.test(failure)));
  });

  it('fails when releases API rows expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases')) {
          return [{ ...payload[0], unexpectedDebugField: true }];
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /releases row must not expose unknown keys: unexpectedDebugField/.test(failure)));
  });

  it('rejects duplicate and extra release API tags before map construction', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname !== '/api/releases') return payload;
        return [
          payload[0],
          structuredClone(payload[0]),
          { ...structuredClone(payload[0]), tag: 'v-extra' },
        ];
      },
    });

    assert.ok(result.failures.some((failure) =>
      /releases API must not contain duplicate tags before map construction: v1/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /releases API contains unexpected tag v-extra/.test(failure)));
  });

  it('fails when persisted score audit payloads expose unexpected top-level keys', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ ...defaultScoreInput, debugInput: true }),
          components_json: JSON.stringify({
            schemaVersion: 1,
            components: {},
            evidenceCoverage: 1,
            hotfix: false,
            reason: 'test reason',
            explanation: scoreExplanationFixture(),
          }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 2, debugIssueEvidence: true }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
            debugGate: true,
          }),
        },
      }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson(),
    });

    assert.ok(result.failures.some((failure) => /score input payload has unexpected top-level key debugInput/.test(failure)));
    assert.ok(result.failures.some((failure) => /issue evidence payload has unexpected top-level key debugIssueEvidence/.test(failure)));
    assert.ok(result.failures.some((failure) => /gate evidence payload has unexpected top-level key debugGate/.test(failure)));
  });

  it('fails when review payloads expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname === '/api/releases/v1/review') {
          return {
            ...payload,
            debugReview: true,
            local: {
              ...payload.local,
              debugLocal: true,
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /review payload must not expose unknown keys: debugReview/.test(failure)));
    assert.ok(result.failures.some((failure) => /review local must not expose unknown keys: debugLocal/.test(failure)));
  });

  it('fails when comparison payloads expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/comparison')) {
          return {
            ...payload,
            debugComparison: true,
            snapshot: { ...payload.snapshot, debugSnapshot: true },
            releases: [{
              ...payload.releases[0],
              debugComparisonRow: true,
              local: { ...payload.releases[0].local, debugLocal: true },
              upstream: {
                schemaVersion: 1,
                snapshotId: 1,
                tag: 'v1',
                score: 7.5,
                band: 'ok',
                status: 'eligible',
                recommended: true,
                reason: 'upstream',
                negativeIssues: 1,
                positiveIssues: 0,
                totalAttributedIssues: 1,
                visibleIssues: [],
                rawCardText: 'card',
                debugUpstream: true,
              },
              delta: { ...payload.releases[0].delta, debugDelta: true },
            }],
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /comparison payload must not expose unknown keys: debugComparison/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison snapshot must not expose unknown keys: debugSnapshot/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison release row must not expose unknown keys: debugComparisonRow/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison local must not expose unknown keys: debugLocal/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison upstream must not expose unknown keys: debugUpstream/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison delta must not expose unknown keys: debugDelta/.test(failure)));
  });

  it('fails when score ledger row identity drifts', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        const rows = explanation.scoreLedger.rows;
        rows.splice(rows.findIndex((row: any) => row.key === 'closureRisk'), 1);
        rows.find((row: any) => row.key === 'releaseVerification').label = 'Checks';
        rows.push({ ...rows.find((row: any) => row.key === 'coverage') });
      }),
    });

    assert.ok(result.failures.some((failure) => /scoreLedger component row order/.test(failure)));
    assert.ok(result.failures.some((failure) => /releaseVerification.*label/.test(failure)));
    assert.ok(result.failures.some((failure) => /duplicate keys: coverage/.test(failure)));
  });

  it('fails when score ledger caps use unknown or misordered identities', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        explanation.scoreLedger.caps = [
          { key: 'hotfixCeiling', label: 'Hotfix successor ceiling', ceiling: 8, applied: false, before: 7.5, after: 7.5, reason: 'test' },
          { key: 'closureRiskCeiling', label: 'Wrong closure label', ceiling: 7.9, applied: false, before: 7.5, after: 7.5, reason: 'test' },
          { key: 'mysteryCeiling', label: 'Mystery', ceiling: 7, applied: true, before: 7.5, after: 7, reason: 'test' },
        ];
      }),
    });

    assert.ok(result.failures.some((failure) => /scoreLedger cap order/.test(failure)));
    assert.ok(result.failures.some((failure) => /closureRiskCeiling.*label/.test(failure)));
    assert.ok(result.failures.some((failure) => /unknown cap key/.test(failure)));
  });

  it('fails when score explanation details lack canonical labels or use the wrong code category', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        delete explanation.positiveDetails[0].label;
        explanation.limitDetails[0].code = 'release_recommended';
        explanation.limitDetails[0].label = 'Release recommended';
        explanation.limitDetails[0].debugPayload = true;
      }),
    });

    assert.ok(result.failures.some((failure) => /positiveDetails\[0\] label must be present/.test(failure)));
    assert.ok(result.failures.some((failure) => /limitDetails\[0\] code .* must be known for limitDetails/.test(failure)));
    assert.ok(result.failures.some((failure) => /limitDetails\[0\] must not expose unknown keys: debugPayload/.test(failure)));
  });

  it('fails when confirmation reasons expose cross-source fields even when those fields are null', async () => {
    const forbiddenLabelEventFields = [
      'association',
      'updatedAt',
      'commentId',
      'commentUrl',
      'issueNodeId',
      'issueAuthorNodeId',
      'issueAuthorType',
      'commentNodeId',
      'commentNodeType',
      'actorNodeId',
      'actorType',
      'commentBodyDigest',
      'snippet',
    ];
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        const issueRef = scoreExplanationIssueRefFixture();
        issueRef.confirmationReasons[0].label = null;
        issueRef.confirmationReasons[0].eventId = null;
        issueRef.confirmationReasons[1].code = 'human_applied_p1';
        for (const key of forbiddenLabelEventFields) {
          issueRef.confirmationReasons[1][key] = null;
        }
        explanation.positiveDetails[0].issueRefs = [issueRef];
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /confirmationReasons\[0\] label is not allowed for comment evidence/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /confirmationReasons\[0\] eventId is not allowed for comment evidence/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /confirmationReasons\[1\] code must match label P0/.test(failure)));
    for (const key of forbiddenLabelEventFields) {
      assert.ok(result.failures.some((failure) =>
        failure.includes(`confirmationReasons[1] ${key} is not allowed for label_event evidence`)));
    }
  });

  it('fails when title or body locality exposes comment fields even when those fields are null', async () => {
    const forbiddenFields = [
      'commentId',
      'commentUrl',
      'commentNodeId',
      'author',
      'actorNodeId',
      'actorType',
      'association',
      'occurredAt',
      'updatedAt',
      'commentBodyDigest',
    ];
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        explanation.positiveDetails[0].issueRefs = ['title', 'body'].map((source, index) => ({
          number: 201 + index,
          title: `${source} locality`,
          url: `https://github.com/x/y/issues/${201 + index}`,
          releaseLocalEvidence: {
            kind: 'exact-version',
            source,
            version: 'v1',
            snippet: `Exact v1 evidence in the ${source}.`,
            ...Object.fromEntries(forbiddenFields.map((key) => [key, null])),
          },
        }));
      }),
    });

    for (const source of ['title', 'body']) {
      for (const key of forbiddenFields) {
        assert.ok(result.failures.some((failure) =>
          failure.includes(`releaseLocalEvidence ${key} is not allowed for ${source} evidence`)));
      }
    }
  });

  it('fails when comment evidence omits source-required own fields', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        const issueRef = scoreExplanationIssueRefFixture();
        delete issueRef.confirmationReasons[0].commentUrl;
        delete issueRef.confirmationReasons[0].issueAuthorType;
        issueRef.confirmationReasons[0].association = 42;
        delete issueRef.releaseLocalEvidence.association;
        delete issueRef.releaseLocalEvidence.actorNodeId;
        explanation.positiveDetails[0].issueRefs = [issueRef];
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /confirmationReasons\[0\] is missing required field commentUrl/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /confirmationReasons\[0\] is missing required field issueAuthorType/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /confirmationReasons\[0\] association must be a non-empty string or null/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /releaseLocalEvidence is missing required field association/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /releaseLocalEvidence is missing required field actorNodeId/.test(failure)));
  });

  it('fails when recommendation decision fields or canonical summary drift', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        delete explanation.recommendationDecision.recencyRank;
        explanation.recommendationDecision.threshold = 6;
        explanation.recommendationDecision.selectedScore = 7.4;
        explanation.recommendationDecision.scoreDeltaToHighest = 0.2;
        explanation.recommendationDecision.decisionCode = 'newest_within_confidence_tolerance';
        explanation.recommendationDecision.summary = 'drifted summary';
      }),
    });

    assert.ok(result.failures.some((failure) => /missing required field recencyRank/.test(failure)));
    assert.ok(result.failures.some((failure) => /threshold must be 7/.test(failure)));
    assert.ok(result.failures.some((failure) => /selectedScore must match releaseScore/.test(failure)));
    assert.ok(result.failures.some((failure) => /scoreDeltaToHighest .* must equal 0/.test(failure)));
    assert.ok(result.failures.some((failure) => /decisionCode .* must equal highest_confidence/.test(failure)));
    assert.ok(result.failures.some((failure) => /summary must match its canonical decision fields/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /release_recommended positive detail must match human recommendation copy/.test(failure)));
  });

  it('fails when score ledger band drifts from the release band', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        explanation.scoreLedger.band = 'solid';
      }),
    });

    assert.ok(result.failures.some((failure) => /scoreLedger band .* must match release band/.test(failure)));
  });

  it('fails when summary release audit links drift from canonical endpoints', async () => {
    const fetchJson = apiFixtureFetchJson((_, publicRelease) => {
      publicRelease.auditLinks = {
        ...publicRelease.auditLinks,
        review: '/wrong/review',
      };
    });
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases')) {
          return [{
            ...payload[0],
            auditLinks: {
              ...payload[0].auditLinks,
              issues: '/wrong/issues',
            },
          }];
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /public release auditLinks must point at release audit endpoints/.test(failure)));
    assert.ok(result.failures.some((failure) => /releases row auditLinks must point at release audit endpoints/.test(failure)));
  });

  it('fails when dynamic audit endpoint payloads expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/issues') && !url.includes('not-a-tier')) {
          return { ...payload, debugPayload: true };
        }
        if (url.includes('/api/releases/v1/review/closure-proofs') && payload.rows?.[0]) {
          return { ...payload, rows: [{ ...payload.rows[0], debugRow: true }] };
        }
        if (url.includes('/api/releases/v1/review/reachability') && payload.rows?.[0]) {
          return { ...payload, rows: [{ ...payload.rows[0], debugRow: true }] };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /issue evidence audit payload must not expose unknown keys: debugPayload/.test(failure)));
    assert.ok(result.failures.some((failure) => /closure proof audit row must not expose unknown keys: debugRow/.test(failure)));
    assert.ok(result.failures.some((failure) => /PR reachability audit row must not expose unknown keys: debugRow/.test(failure)));
  });

  it('fails when child audit payloads drift from their publication binding', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        const parsed = new URL(url);
        if (
          parsed.pathname === '/api/releases/v1/review/issues' &&
          parsed.searchParams.get('limit') === '11'
        ) {
          return { ...payload, snapshotId: 'c'.repeat(64) };
        }
        if (
          parsed.pathname === '/api/releases/v1/review/closure-proofs' &&
          parsed.searchParams.get('limit') === '5'
        ) {
          return { ...payload, auditDigest: 'e'.repeat(64) };
        }
        if (
          parsed.pathname === '/api/releases/v1/review/reachability' &&
          parsed.searchParams.get('limit') === '7'
        ) {
          const self = new URL(payload.links.self, 'https://radar.invalid');
          self.pathname = '/api/releases/v2/review/reachability';
          return {
            ...payload,
            links: {
              ...payload.links,
              self: `${self.pathname}${self.search}`,
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) =>
      /issue evidence audit snapshotId .* must match public snapshotId/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /closure proof audit auditDigest .* must match/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /PR reachability audit links\.self must point at the exact v1 reachability endpoint/.test(failure)));
  });

  it('fails when review payload exposes comparison data', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname === '/api/releases/v1/review') {
          return {
            ...payload,
            upstream: { score: 8.7 },
            snapshot: { id: 1 },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /review payload must not expose internal\/comparison key upstream/.test(failure)));
    assert.ok(result.failures.some((failure) => /review payload must not expose internal\/comparison key snapshot/.test(failure)));
  });

  it('fails when data freshness sourceFetchedAtMax is not the max source timestamp', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        freshness.sourceFetchedAtMax = '2026-01-01T23:10:00Z';
      }),
    });

    assert.ok(result.failures.some((failure) => /sourceFetchedAtMax/.test(failure)));
  });

  it('fails when API freshness omits either score-affecting snapshot source', async () => {
    for (const source of [
      'issue_state_event_snapshots',
      'release_closure_dependency_snapshots',
    ]) {
      const result = await verifyReleaseAudit({
        reader: reader(),
        apiBase: 'http://example.test',
        fetchJson: apiFixtureFetchJson((freshness) => {
          freshness.sources = freshness.sources.filter(
            (row: any) => row.source !== source,
          );
        }),
      });

      assert.ok(
        result.failures.some((failure) =>
          /dataFreshness sources must equal the complete score-affecting source set/.test(failure)),
        source,
      );
    }
  });

  it('fails duplicate API freshness rows before source map construction', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        freshness.sources.push(structuredClone(freshness.sources[0]));
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /dataFreshness sources must not contain duplicate names/.test(failure)));
  });

  it('fails valid but stale API freshness timestamps that disagree with DB rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        const source = freshness.sources.find(
          (row: any) => row.source === 'issue_state_event_snapshots',
        );
        source.maxAt = '2026-01-01T22:00:00Z';
        source.ageHoursAtScore = 2;
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /API dataFreshness source\/maxAt rows must equal independently reconstructed DB freshness rows/.test(failure)));
  });

  it('fails when data freshness age arithmetic drifts', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        const issueRows = freshness.sources.find(
          (source: any) => source.source === 'issue_rows',
        );
        assert.ok(issueRows);
        issueRows.ageHoursAtScore = 99;
      }),
    });

    assert.ok(result.failures.some((failure) => /issue_rows ageHoursAtScore/.test(failure)));
  });

  it('fails when API data freshness reports source evidence newer than the score', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        const closureProofs = freshness.sources.find((source: any) => source.source === 'closure_proofs');
        closureProofs.maxAt = '2026-01-02T00:01:01Z';
        closureProofs.ageHoursAtScore = -0.02;
        freshness.closureProofCheckedAtMax = closureProofs.maxAt;
        freshness.sourceFetchedAtMax = closureProofs.maxAt;
        freshness.sourceFetchedAgeHoursAtScore = -0.02;
      }),
    });

    assert.ok(result.failures.some((failure) => /closure_proofs changed .* newer than scoredAt/.test(failure)));
  });

  it('fails when proof audit endpoints use stale score timestamps', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/closure-proofs')) {
          return { ...payload, scoredAt: '2025-12-31T00:00:00Z' };
        }
        if (url.includes('/api/releases/v1/review/reachability')) {
          return { ...payload, scoredAt: '2025-12-31T00:00:00Z' };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /closure proof audit scoredAt/.test(failure)));
    assert.ok(result.failures.some((failure) => /PR reachability audit scoredAt/.test(failure)));
  });

  it('fails when reachable PR reachability rows lack auditable commit identity', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/reachability') && payload.rows?.[0]) {
          return {
            ...payload,
            rows: [{
              ...payload.rows[0],
              tagCommitOid: null,
              mergeCommitOid: null,
            }],
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /must include full tagCommitOid/.test(failure)));
    assert.ok(result.failures.some((failure) => /must include full mergeCommitOid/.test(failure)));
  });

  it('fails when PR reachability evidence reason is not known', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/reachability') && payload.rows?.[0]) {
          return {
            ...payload,
            rows: [{
              ...payload.rows[0],
              evidence: { ...payload.rows[0].evidence, evidence: 'mystery_reachability_reason' },
            }],
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /evidence reason must be known/.test(failure)));
  });

  it('fails valid-looking closure and reachability OID drift against DB rows', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = structuredClone(await fetchJson(url));
        const path = new URL(url).pathname;
        if (
          path === '/api/releases/v1/review/closure-proofs' &&
          payload.rows?.[0]?.evidence?.linkedPrs?.[0]
        ) {
          payload.rows[0].evidence.linkedPrs[0].mergeCommitOid = 'c'.repeat(40);
        }
        if (
          path === '/api/releases/v1/review/reachability' &&
          payload.rows?.[0]
        ) {
          payload.rows[0].tagCommitOid = 'b'.repeat(40);
          payload.rows[0].mergeCommitOid = 'c'.repeat(40);
          payload.rows[0].prMergeCommitOid = 'c'.repeat(40);
          payload.rows[0].evidence = {
            ...payload.rows[0].evidence,
            tagCommitOid: 'b'.repeat(40),
            checkedCommitOid: 'c'.repeat(40),
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) =>
      /closure proof audit row 1:fixed_in_release must exactly match independently reconstructed DB content/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /PR reachability audit row openclaw\/openclaw#1 must exactly match independently reconstructed DB content/.test(failure)));
  });

  it('fails when review source provenance drifts from score freshness', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname === '/api/releases/v1/review') {
          return {
            ...payload,
            local: {
              ...payload.local,
              sourceProvenance: {
                ...payload.local.sourceProvenance,
                scoreTimestampAligned: false,
                rawRows: {
                  ...payload.local.sourceProvenance.rawRows,
                  issues: '/wrong/issues',
                },
              },
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /scoreTimestampAligned/.test(failure)));
    assert.ok(result.failures.some((failure) => /rawRows must point at review row endpoints/.test(failure)));
  });

  it('fails when API advisory provenance drifts from the independently reconstructed v2 publication', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname === '/api/releases/v1/review') {
          return {
            ...payload,
            local: {
              ...payload.local,
              sourceProvenance: {
                ...payload.local.sourceProvenance,
                advisorySnapshot: {
                  ...payload.local.sourceProvenance.advisorySnapshot,
                  activeContentHash: '0'.repeat(64),
                },
              },
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) =>
      /advisorySnapshot must match the independently reconstructed/.test(failure)));
  });

  it('fails when API authority bindings drift from the independently sealed publication', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname === '/api/releases') {
          return payload.map((release: any) => ({
            ...release,
            scoreAudit: {
              ...release.scoreAudit,
              authorityRunContentHash: 'c'.repeat(64),
            },
          }));
        }
        if (new URL(url).pathname === '/api/releases/v1/review') {
          return {
            ...payload,
            local: {
              ...payload.local,
              sourceProvenance: {
                ...payload.local.sourceProvenance,
                scoreAuthority: {
                  ...payload.local.sourceProvenance.scoreAuthority,
                  historyV2SealContentHash: 'e'.repeat(64),
                },
              },
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) =>
      /scoreAudit authority binding must match the independently sealed/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /review sourceProvenance scoreAuthority must match the independently sealed/.test(failure)));
  });

  it('still requires an independent authority binding for a scored release', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({ publicationAuthorityBindings: {} }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson(),
    });

    assert.ok(result.failures.some((failure) =>
      /independently sealed score authority binding must be present/.test(failure)));
  });

  it('fails when API authority binding fields are missing', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname === '/api/public') {
          return {
            ...payload,
            releases: payload.releases.map((release: any) => ({
              ...release,
              scoreAudit: {
                ...release.scoreAudit,
                authorityRunId: null,
              },
            })),
          };
        }
        if (new URL(url).pathname === '/api/releases/v1/review') {
          return {
            ...payload,
            local: {
              ...payload.local,
              sourceProvenance: {
                ...payload.local.sourceProvenance,
                scoreAuthority: null,
              },
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) =>
      /scoreAudit authority binding runId must be present/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /review sourceProvenance scoreAuthority must be present/.test(failure)));
  });

  it('fails when audit scalar columns drift from the release row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          final_score: 4.2,
          status: 'wait',
          band: 'wait',
          recommended: 0,
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify(defaultScoreInput),
          components_json: JSON.stringify({
            schemaVersion: 1,
            components: {},
            evidenceCoverage: 1,
            hotfix: false,
            reason: 'stale reason',
            explanation: scoreExplanationFixture(),
          }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });

    assert.ok(result.failures.some((failure) => /audit final_score/.test(failure)));
    assert.ok(result.failures.some((failure) => /audit status/.test(failure)));
    assert.ok(result.failures.some((failure) => /audit recommended/.test(failure)));
    assert.ok(result.failures.some((failure) => /score components reason/.test(failure)));
  });

  it('fails when a scored release has partial classification coverage', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          input_json: JSON.stringify({
            ...defaultScoreInput,
            rawIssueCount: 2,
            classifiedIssueCount: 1,
          }),
        },
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /classifiedIssueCount \(1\) must equal rawIssueCount \(2\)/.test(failure)));
  });

  it('fails when review input masks stale persisted audit input', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (new URL(url).pathname === '/api/releases/v1/review') {
          return {
            ...payload,
            local: {
              ...payload.local,
              input: {
                ...payload.local.input,
                rawIssueCount: 999,
              },
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /review input must match persisted audit input/.test(failure)));
  });

  it('fails when review closure proof masks stale persisted audit proof payload', async () => {
    const staleProof = closureProofFixture({
      examples: [{ number: 999, status: 'fixed_in_release', riskWeight: 0 }],
    });
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ schemaVersion: 1, rawIssueCount: 1, classifiedIssueCount: 1 }),
          components_json: JSON.stringify({ schemaVersion: 1, components: {}, explanation: { schemaVersion: 1 } }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: staleProof,
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson(),
    });

    assert.ok(result.failures.some((failure) => /review closureProof must match persisted audit closureProof/.test(failure)));
  });

  it('fails when public issue summaries omit capped release-universe rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({ issueNumbers: [1, 2] }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((_, publicRelease) => {
        publicRelease.totalAttributedIssues = 2;
        publicRelease.scoreAudit.rawIssueCount = 2;
      }),
    });

    assert.ok(result.failures.some((failure) => /public issues length/.test(failure)));
  });

  it('fails when public issue summaries include issues outside the release universe', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({ issueNumbers: [1] }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((_, publicRelease) => {
        publicRelease.issues = [{
          number: 999,
          title: 'outside issue',
          url: 'https://github.com/x/y/issues/999',
          affectedUsers: 'some',
        }];
      }),
    });

    assert.ok(result.failures.some((failure) => /public issue #999 must belong/.test(failure)));
  });

  it('fails when audit fix counts drift from verified queries', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: fixProvenanceFixture({ verifiedFixedCount: 2 }),
          }),
        },
      }),
    });
    assert.equal(result.failures.length, 1);
    assert.match(result.failures[0], /verifiedFixedCount/);
  });

  it('fails when raw closed issues are missing classifications', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        rawClosed: [{ number: 1 }, { number: 2 }],
        closed: [{ number: 1, prompt_version: 6 }],
      }),
    });
    assert.ok(result.failures.some((failure) => /raw closed release-window issues/.test(failure)));
  });

  it('fails when non-recommended scored releases hide raw closed issues without proof rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{ tag: 'v1', final_score: 5.8, state: 'eligible', recommended: 0, scored_at: auditScoredAt }],
        rawClosed: [{ number: 1 }],
        closed: [],
        verified: [],
        unverified: [],
        proofRows: [],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: {
              ...labelTimelineFixture,
              issueCount: 0,
              currentLabelCount: 0,
            },
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 0,
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /raw closed release-window issues/.test(failure)));
    assert.ok(result.failures.some((failure) => /closure proofs .* raw closed release-window issues/.test(failure)));
  });

  it('fails when closed-window classifications are stale', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 5 }],
        verified: [{ number: 1, sentiment: 'negative', prompt_version: 5 }],
      }),
    });
    assert.ok(result.failures.some((failure) => /classification prompt_version/.test(failure)));
  });

  it('fails when proof rows are newer than their score audit', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: '2026-01-02T00:00:02Z',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /must not be newer than audit scored_at/.test(failure)));
  });

  it('fails when proof dependency source evidence is newer than the proof row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofDependencyFreshness: [
          ...proofDependencyFreshnessFixture.filter((source) => source.source !== 'issue_pr_links'),
          {
            source: 'issue_pr_links',
            max_ts: '2026-01-02T00:00:00.500Z',
          },
        ],
      }),
    });
    assert.ok(result.failures.some((failure) => /newer than issue_pr_links dependency/.test(failure)));
  });

  it('fails when linked PR metadata is newer than the proof row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofDependencyFreshness: [
          ...proofDependencyFreshnessFixture.filter((source) => source.source !== 'pull_request_fixes'),
          {
            source: 'pull_request_fixes',
            max_ts: '2026-01-02T00:00:00.500Z',
          },
        ],
      }),
    });
    assert.ok(result.failures.some((failure) => /newer than pull_request_fixes dependency/.test(failure)));
  });

  it('fails when proof dependency freshness omits a required source', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofDependencyFreshness: proofDependencyFreshnessFixture
          .filter((source) => source.source !== 'pull_request_fixes'),
      }),
    });
    assert.ok(result.failures.some((failure) => /dependency freshness must include pull_request_fixes/.test(failure)));
  });

  it('fails when source evidence changed after the score audit', async () => {
    const staleReader = reader();
    staleReader.sourceFreshnessFor = () => [{
      source: 'issue_rows',
      max_ts: '2026-01-02T00:00:02Z',
    }];
    const result = await verifyReleaseAudit({ reader: staleReader });
    assert.ok(result.failures.some((failure) => /issue_rows changed/.test(failure)));
  });

  it('fails when persisted score source identity is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          source_identity_json: null,
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /source identity must be present/.test(failure)));
  });

  it('surfaces sealed publication, history manifest, and forecast provenance failures', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        publicationFailures: [
          'current audit v1 does not match the recorded sealed history tip',
          'forecast decision-1 references invalid history provenance run-1/v1',
        ],
      }),
    });
    assert.ok(result.failures.some((failure) =>
      /score-publication: current audit v1 does not match/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /score-publication: forecast decision-1 references invalid history provenance/.test(failure)));
  });

  it('fails when advisory snapshot completeness metadata or digest is invalid', async () => {
    const result = await verifyReleaseAudit({
      reader: {
        ...reader({}),
        advisorySnapshotAuditProjection: () => ({
          schemaVersion: 1,
          sourceMode: 'receipt_authorized_compound_advisory_v2',
          verified: false,
          failedCount: 2,
          problems: [
            'incomplete_sweep:advisory sweep was not stable',
            'digest_mismatch:current rows changed',
          ],
        }),
      },
    });
    assert.ok(
      result.failures.some((failure) =>
        /receipt-authorized advisory snapshot v2 publication must verify/.test(failure)),
    );
  });

  it('fails when a scored audit is backed by a partial issue universe mislabeled complete', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        issueCrawlMetadata: issueCrawlAuditFixture({
          totalCount: 2,
          fetchedCount: 1,
        }),
      }),
    });

    assert.ok(result.failures.some((failure) =>
      /issue-crawl: .*fetchedCount must equal boundaryTotalCount/.test(failure)));
  });

  it('fails when current source rows drift without timestamp or count changes', async () => {
    const driftedReader = reader();
    driftedReader.scoreSourceIdentity = () => driftedSourceIdentity();
    const result = await verifyReleaseAudit({ reader: driftedReader });
    assert.ok(result.failures.some((failure) => /must match current score-input rows/.test(failure)));
  });

  it('reports source identity schema errors instead of crashing', async () => {
    const invalidReader = reader();
    invalidReader.scoreSourceIdentity = () => {
      throw new Error('no such column: issue_pr_links.source_comment_url');
    };
    const result = await verifyReleaseAudit({ reader: invalidReader });
    assert.ok(result.failures.some((failure) => /could not be computed.*source_comment_url/.test(failure)));
  });

  it('fails when score source rows change during audit verification', async () => {
    const unstableReader = reader();
    let calls = 0;
    unstableReader.scoreSourceIdentity = () => {
      calls++;
      return calls === 1
        ? sourceIdentityFixture
        : driftedSourceIdentity();
    };
    const result = await verifyReleaseAudit({ reader: unstableReader });
    assert.ok(result.failures.some((failure) => /must remain stable during audit verification/.test(failure)));
  });

  it('reruns complete publication integrity during final stabilization', async () => {
    const unstableReader = reader();
    const baseline = structuredClone(unstableReader.scorePublicationIntegrity());
    let calls = 0;
    unstableReader.scorePublicationIntegrity = () => {
      calls++;
      if (calls === 1) return structuredClone(baseline);
      return {
        ...structuredClone(baseline),
        failures: ['publication changed after API verification'],
        failedCount: 1,
      };
    };

    const result = await verifyReleaseAudit({ reader: unstableReader });

    assert.equal(calls, 2);
    assert.ok(result.failures.some((failure) =>
      /complete score publication integrity report must remain stable during audit verification/.test(failure)));
    assert.ok(result.failures.some((failure) =>
      /score-publication-final: publication changed after API verification/.test(failure)));
  });

  it('fails duplicate and reordered score source manifests even with recomputed digests', async () => {
    for (const mutation of ['duplicate', 'reordered'] as const) {
      const identity = structuredClone(sourceIdentityFixture);
      if (mutation === 'duplicate') {
        identity.sources[1] = structuredClone(identity.sources[0]);
        identity.rowCount = identity.sources.reduce((sum, source) => sum + source.count, 0);
      } else {
        [identity.sources[0], identity.sources[1]] = [
          identity.sources[1],
          identity.sources[0],
        ];
      }
      identity.digest = scoreSourceIdentityManifestDigest(
        identity.sources,
        identity.schemaVersion,
      );
      const result = await verifyReleaseAudit({
        reader: reader({
          audit: {
            prompt_version: 6,
            scored_at: auditScoredAt,
            source_identity_json: JSON.stringify(identity),
          },
        }),
      });
      assert.ok(
        result.failures.some((failure) => /source identity manifest sources/.test(failure)),
        mutation,
      );
    }
  });

  it('allows one-second GitHub closure event timestamp skew', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            closedAt: '2026-01-01T00:00:00Z',
            closureEventClosedAt: ['2026-01-01T00:00:01Z'],
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });
    assert.ok(!result.failures.some((failure) => /closure event timestamp/.test(failure)));
  });

  it('fails when proof closure event timestamp does not match issue closedAt within tolerance', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            closedAt: '2026-01-01T00:00:00Z',
            closureEventClosedAt: ['2026-01-03T00:00:00Z'],
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /closure event timestamp/.test(failure)));
  });

  it('fails when reachable PR proof lacks backing reachability rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        prEvidence: [],
      }),
    });
    assert.ok(result.failures.some((failure) => /merged reachable PR row/.test(failure)));
  });

  it('fails when embedded linked PR proof is missing identity fields', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            linkedPrs: [{
              number: 1,
              merged: 1,
              reachabilityStatus: 'reachable',
              reachabilityEvidence: 'merge_commit_in_release_history',
            }],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /linkedPrs\[0\].*repositoryNameWithOwner/.test(failure)));
    assert.ok(result.failures.some((failure) => /linkedPrs\[0\].*must include source/.test(failure)));
    assert.ok(result.failures.some((failure) => /linkedPrs\[0\].*must include known state/.test(failure)));
  });

  it('accepts explicit missing PR metadata when the source comment is linked', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            linkedPrs: [{
              number: 1,
              repositoryNameWithOwner: 'openclaw/openclaw',
              source: 'closedByPullRequestsReferences',
              willCloseTarget: 1,
              state: 'MERGED',
              merged: 1,
              mergedAt: '2026-01-01T12:00:00Z',
              reachabilityStatus: 'reachable',
              reachabilityMethod: 'git-merge-base',
              reachabilityEvidence: 'merge_commit_in_release_history',
              mergeCommitOid: mergeOid,
            }, {
              number: 88894,
              repositoryNameWithOwner: 'openclaw/openclaw',
              source: 'ClosureComment.fixProof',
              metadataMissing: 1,
              sourceCommentDatabaseId: 123456,
              sourceCommentUrl: 'https://github.com/openclaw/openclaw/issues/1#issuecomment-123456',
            }],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });
    assert.deepEqual(result.failures, []);
  });

  it('fails when related PR context proof is missing identity fields', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'related_open_pr_context',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            relatedPrContext: {
              open: [{ number: 44 }],
            },
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /relatedPrContext\.open\[0\].*repositoryNameWithOwner/.test(failure)));
    assert.ok(result.failures.some((failure) => /relatedPrContext\.open\[0\].*must include source/.test(failure)));
  });

  it('fails when canonical open PR evidence is missing identity fields', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'superseded_to_open_pr',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalOpenPrs: [{ number: 45, repositoryNameWithOwner: 'openclaw/openclaw' }],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /canonicalOpenPrs\[0\].*must include source/.test(failure)));
    assert.ok(result.failures.some((failure) => /canonicalOpenPrs\[0\].*must include known state/.test(failure)));
  });

  it('fails when reachable linked PR proof is backed by a different PR row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        prEvidence: [{
          issue_number: 1,
          pr_repository_name_with_owner: 'openclaw/openclaw',
          pr_number: 2,
          merged: 1,
          status: 'reachable',
          tag_commit_oid: tagOid,
          release_tag_commit_oid: tagOid,
          merge_commit_oid: 'c'.repeat(40),
          evidence_json: JSON.stringify({
            schemaVersion: 1,
            evidence: 'merge_commit_in_release_history',
            method: 'git-merge-base',
            tagCommitOid: tagOid,
            checkedCommitOid: 'c'.repeat(40),
            baseRefName: 'main',
            commandStatus: 0,
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /hasReachableClosingPr must have a merged reachable PR row/.test(failure)));
  });

  it('fails when embedded linked PR reachability disagrees with persisted reachability rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        prEvidence: [{
          issue_number: 1,
          pr_repository_name_with_owner: 'openclaw/openclaw',
          pr_number: 1,
          merged: 1,
          status: 'not_reachable',
          tag_commit_oid: tagOid,
          release_tag_commit_oid: tagOid,
          merge_commit_oid: mergeOid,
          evidence_json: JSON.stringify({
            schemaVersion: 1,
            evidence: 'not_reachable_from_release_tag',
            method: 'git-merge-base',
            tagCommitOid: tagOid,
            checkedCommitOid: mergeOid,
            baseRefName: 'main',
            commandStatus: 1,
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /reachabilityStatus .* must match persisted reachability/.test(failure)));
  });

  it('fails when unknown PR reachability lacks an evidence reason', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'no_code_proof',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        prEvidence: [{
          issue_number: 1,
          pr_repository_name_with_owner: 'openclaw/openclaw',
          pr_number: 1,
          merged: 1,
          status: 'unknown',
          tag_commit_oid: null,
          release_tag_commit_oid: null,
          evidence_json: '{}',
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { no_code_proof: 1 },
                byRiskDisposition: { unsupported_closure_claim: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 1,
                  neutralOrNonActionableCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 2.125,
                  weightedRiskByDisposition: { unsupported_closure_claim: 2.125 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /unknown reachability must include evidence reason/.test(failure)));
  });

  it('fails when persisted closure proof lacks representative examples for non-fixed statuses', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'repro_requested',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        prEvidence: [],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { repro_requested: 1 },
                byRiskDisposition: { unsupported_closure_claim: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 1,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 2.125,
                  weightedRiskByDisposition: { unsupported_closure_claim: 2.125 },
                },
                examplesByStatus: {},
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) =>
      /persisted closureProof examplesByStatus must include at least one repro_requested example/.test(failure)));
  });

  it('requires the affirmative closure ceiling weight while allowing exclusive penalty subsets', async () => {
    const hasIssueSubsetFailure = (failure: string) =>
      /score input unresolvedClosureIssueCount .* must be an exclusive subset of raw closure risk/.test(
        failure,
      );
    const hasWeightSubsetFailure = (failure: string) =>
      /score input unresolvedClosureRiskWeight .* must be an exclusive subset of raw closure risk/.test(
        failure,
      );
    const hasCeilingFailure = (failure: string) =>
      /score input affirmativeClosureRiskCeilingWeight .* must match deduplicated affirmative closure risk/.test(
        failure,
      );
    const fixture = {
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_open_canonical',
          risk_disposition: 'open_canonical_risk',
          risk_weight: 3.188,
          evidence_json: JSON.stringify({
            canonicalIssue: 999,
            canonicalResolution: { terminalIssue: { number: 999, state: 'open' } },
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        audit: {
          score_model_version: SCORE_MODEL_VERSION,
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({
            ...defaultScoreInput,
            unresolvedClosureIssueCount: 0,
            unresolvedClosureRiskWeight: 0,
          }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_open_canonical: 1 },
                byRiskDisposition: { open_canonical_risk: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 1,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 3.188,
                  weightedRiskByDisposition: { open_canonical_risk: 3.188 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      };
    const result = await verifyReleaseAudit({
      reader: reader(fixture),
    });

    assert.ok(!result.failures.some(hasIssueSubsetFailure));
    assert.ok(!result.failures.some(hasWeightSubsetFailure));
    assert.ok(result.failures.some(hasCeilingFailure), result.failures.join('\n'));

    const validExclusiveSubset = structuredClone(fixture);
    const validExclusiveInput = JSON.parse(validExclusiveSubset.audit.input_json);
    validExclusiveInput.affirmativeClosureRiskCeilingWeight = 3.188;
    validExclusiveSubset.audit.input_json = JSON.stringify(validExclusiveInput);
    const validExclusive = await verifyReleaseAudit({
      reader: reader(validExclusiveSubset),
    });
    assert.ok(!validExclusive.failures.some((failure) =>
      hasIssueSubsetFailure(failure) ||
      hasWeightSubsetFailure(failure) ||
      hasCeilingFailure(failure)));

    const v20Fixture = structuredClone(fixture);
    v20Fixture.audit.score_model_version = 'evidence-v20-exclusive-risk-ledger';
    const v20 = await verifyReleaseAudit({ reader: reader(v20Fixture) });
    assert.ok(!v20.failures.some(hasIssueSubsetFailure));
    assert.ok(!v20.failures.some(hasWeightSubsetFailure));
    const v21Fixture = structuredClone(fixture);
    v21Fixture.audit.score_model_version = 'evidence-v21-human-confirmed-field';
    const v21Reader = reader(v21Fixture);
    const validIssuesForVersion = v21Reader.issuesForVersion;
    v21Reader.issuesForVersion = (tag: string) =>
      validIssuesForVersion(tag).map((row: any) => ({
        ...row,
        classification_origin: 'legacy_or_manual',
      }));
    const v21 = await verifyReleaseAudit({ reader: v21Reader });
    assert.ok(!v21.failures.some(hasIssueSubsetFailure));
    assert.ok(!v21.failures.some(hasWeightSubsetFailure));
    assert.ok(v21.failures.some((failure) => /raw classification provenance is invalid/.test(failure)));
  });

  it('fails when persisted closure proof schema version is missing', async () => {
    const closureProof = closureProofFixture();
    delete closureProof.schemaVersion;
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof,
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted closureProof schemaVersion/.test(failure)));
  });

  it('fails when persisted release fix credit schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted releaseFixCredit schemaVersion/.test(failure)));
  });

  it('fails when persisted issue evidence schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: '{}',
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted issueEvidence schemaVersion/.test(failure)));
  });

  it('fails when label timeline schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: { ...labelTimelineFixture, schemaVersion: undefined },
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /labelTimeline schemaVersion/.test(failure)));
  });

  it('fails when gate evidence schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 0,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted gateEvidence schemaVersion/.test(failure)));
  });

  it('fails when score input schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ rawIssueCount: 1, classifiedIssueCount: 1 }),
          components_json: JSON.stringify({ schemaVersion: 1, components: {}, explanation: { schemaVersion: 1 } }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted score input schemaVersion/.test(failure)));
  });

  it('fails when score components schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ schemaVersion: 1, rawIssueCount: 1, classifiedIssueCount: 1 }),
          components_json: JSON.stringify({ components: {}, explanation: { schemaVersion: 1 } }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted score components schemaVersion/.test(failure)));
  });

  it('fails when release checks schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            releaseChecks: { ...releaseChecksFixture, schemaVersion: undefined },
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /releaseChecks schemaVersion/.test(failure)));
  });

  it('fails when artifact verification schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: { ...artifactVerificationFixture, schemaVersion: undefined },
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /artifactVerification schemaVersion/.test(failure)));
  });

  it('fails when artifact verification proof identities are malformed', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 2 }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: {
              ...artifactVerificationFixture,
              receiptId: 'artifact-receipt-v2:not-a-hash',
            },
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: {
                schemaVersion: 1,
                countedClosedCount: 1,
                notCountedClosedCount: 0,
                analyzedClosedCount: 1,
              },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) =>
      /receiptId must be a canonical artifact receipt ID or null/.test(
        failure,
      )));
  });

  it('fails when canonical-open proof does not resolve to open terminal', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_open_canonical',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalResolution: { terminalIssue: { state: 'closed' } },
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_open_canonical: 1 },
                byRiskDisposition: { open_canonical_risk: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 1,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 3.188,
                  weightedRiskByDisposition: { open_canonical_risk: 3.188 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /open terminal/.test(failure)));
  });

  it('fails when closed canonical proof should use a more specific status', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_closed_canonical',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalResolution: {
              terminalIssue: { state: 'closed' },
              terminalProof: { status: 'fixed_in_release', summary: 'canonical was fixed in this release' },
            },
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_closed_canonical: 1 },
                byRiskDisposition: { unsupported_closure_claim: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 1,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 1,
                  weightedRiskByDisposition: { unsupported_closure_claim: 1 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /more specific canonical status/.test(failure)));
  });

  it('fails when weak not-planned canonical terminal proof is treated as non-actionable', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_non_actionable_canonical',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalResolution: {
              terminalIssue: { state: 'closed' },
              terminalProof: { status: 'not_planned', summary: 'canonical was closed not planned' },
            },
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_non_actionable_canonical: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /not_planned terminal proof must include concrete non-actionable rationale/.test(failure)));
  });

  it('fails when negative NOT_PLANNED is neutral without concrete rationale', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'not_planned',
          evidence_json: JSON.stringify({
            stateReasons: ['NOT_PLANNED'],
            matchingComments: [],
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { not_planned: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) =>
      /negative NOT_PLANNED issue #1 cannot be neutral\/non-actionable without concrete close-time rationale/.test(failure)));
  });

  it('allows negative NOT_PLANNED neutralization with concrete outside-repo rationale', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'not_planned',
          evidence_json: JSON.stringify({
            stateReasons: ['NOT_PLANNED'],
            nonActionableRationaleComments: [{
              snippet: 'Close: this lives outside the OpenClaw source repository and is plugin-owned.',
            }],
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { not_planned: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(!result.failures.some((failure) =>
      /negative NOT_PLANNED issue #1 cannot be neutral\/non-actionable without concrete close-time rationale/.test(
        failure,
      )));
    assert.ok(result.failures.some((failure) =>
      /closure-risk operands for issue #1 require authority-bound closure or label evidence unavailable to the current audit reader/.test(
        failure,
      )));
  });

  it('replays benign labels while failing closed for score-authority labels', async () => {
    const benign = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          effective_labels: ['question'],
          evidence_json: JSON.stringify(closureAuditEvidenceFixture()),
        }],
      }),
    });
    assert.ok(!benign.failures.some((failure) =>
      /closure-risk operands for issue #1 require authority-bound closure or label evidence/.test(
        failure,
      )));

    for (const label of ['P0', 'impact:data-loss']) {
      const authorityBound = await verifyReleaseAudit({
        reader: reader({
          proofRows: [{
            issue_number: 1,
            status: 'fixed_in_release',
            effective_labels: [label],
            evidence_json: JSON.stringify(closureAuditEvidenceFixture()),
          }],
        }),
      });
      assert.ok(authorityBound.failures.some((failure) =>
        /closure-risk operands for issue #1 require authority-bound closure or label evidence/.test(
          failure,
        )));
    }
  });

  it('fails when commit proof uses short hashes or mismatched flags', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: ['cfeaf6897fd8'],
            notReachableFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: 'cfeaf6897fd8',
              status: 'reachable',
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'Fix evidence commit cfeaf6897fd8',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /40-hex SHA/.test(failure)));
    assert.ok(result.failures.some((failure) => /hasReachableFixCommit/.test(failure)));
  });

  it('fails when unknown direct fix commit proof omits unknown commit evidence', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'direct_fix_commit_reachability_unknown',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            hasUnknownFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [],
            notReachableFixCommits: [],
            unknownFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              source: 'ClosureComment.fixProof',
              status: 'unknown',
              tagCommitOid: null,
              evidence: 'commit_unavailable',
              snippet: 'Fix evidence commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /must set hasUnknownFixCommit/.test(failure)));
    assert.ok(result.failures.some((failure) => /must include unknownFixCommits/.test(failure)));
    assert.ok(result.failures.some((failure) => /unknownFixCommits must equal/.test(failure)));
  });

  it('fails when admin not-planned proof hides unknown direct fix commit evidence', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'admin_not_planned_unverified',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            hasUnknownFixCommit: true,
            stateReasons: ['NOT_PLANNED'],
            closureContextCommentCount: 1,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            unknownFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              source: 'ClosureComment.fixProof',
              status: 'unknown',
              tagCommitOid: null,
              evidence: 'commit_unavailable',
              snippet: 'Fix evidence commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /admin_not_planned_unverified issue #1 must not have direct fix proof/.test(failure)));
  });

  it('enforces missing-evidence fail-closed semantics from v26 onward', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    for (const [scoreModelVersion, shouldFailClosed] of [
      ['evidence-v25-closure-context', false],
      ['evidence-v26-calibrated-evidence', true],
      [SCORE_MODEL_VERSION, true],
      ['evidence-v28-future-compatible', true],
    ] as const) {
      const result = await verifyReleaseAudit({
        reader: reader({
          verified: [],
          unverified: [{ number: 1, sentiment: 'negative', prompt_version: 6 }],
          proofRows: [{
            issue_number: 1,
            status: 'direct_fix_commit_reachability_unknown',
            evidence_json: JSON.stringify({
              hasReachableClosingPr: false,
              hasReachableFixCommit: false,
              hasNotReachableFixCommit: false,
              hasUnknownFixCommit: true,
              stateReasons: ['COMPLETED'],
              reachableFixCommits: [],
              notReachableFixCommits: [],
              unknownFixCommits: [commit],
              fixCommitProof: [{
                issueNumber: 1,
                sourceIssueNumber: 1,
                commitOid: commit,
                source: 'ClosureComment.fixProof',
                status: 'unknown',
                tagCommitOid: null,
                evidence: 'commit_unavailable',
                snippet: `Fix evidence commit ${commit}`,
                trustedSource: true,
                author: 'maintainer',
              }],
            }),
          }],
          audit: {
            score_model_version: scoreModelVersion,
            prompt_version: 6,
            scored_at: auditScoredAt,
            input_json: JSON.stringify({
              ...defaultScoreInput,
              unresolvedClosureIssueCount: 0,
              unresolvedClosureRiskWeight: 0,
            }),
            gate_evidence_json: JSON.stringify({
              labelTimeline: labelTimelineFixture,
              fixProvenance: {
                verifiedFixedCount: 0,
                unverifiedClosedCount: 1,
                closureProof: closureProofFixture({
                  creditedCount: 0,
                  notCreditedCount: 1,
                  byStatus: { direct_fix_commit_reachability_unknown: 1 },
                  byRiskDisposition: { missing_evidence: 1 },
                  riskSummary: {
                    creditedReleaseFixCount: 0,
                    resolvedByCanonicalReleaseFixCount: 0,
                    resolvedByReleaseFixProofCount: 0,
                    knownNotInReleaseCount: 0,
                    openCanonicalRiskCount: 0,
                    unsupportedClosureClaimCount: 0,
                    neutralOrNonActionableCount: 0,
                    neutralHighImpactCount: 0,
                    neutralBugShapedCount: 0,
                    missingEvidenceCount: 1,
                    unresolvedForReleaseCount: 0,
                    unresolvedWeightedRisk: 0,
                    weightedRiskByDisposition: {},
                  },
                }),
                releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
              },
            }),
          },
        }),
      });
      assert.equal(
        result.failures.some((failure) =>
          /score-affecting negative missing_evidence issue #1/.test(failure)),
        shouldFailClosed,
        scoreModelVersion,
      );
    }
  });

  it('rejects tampered raw classification provenance for v27 scores', async () => {
    const tamperedReader = reader();
    tamperedReader.getReleaseScoreAudit('v1').score_model_version = SCORE_MODEL_VERSION;
    const validIssuesForVersion = tamperedReader.issuesForVersion;
    tamperedReader.issuesForVersion = (tag: string) =>
      validIssuesForVersion(tag).map((row: any) => ({
        ...row,
        provenance_json: JSON.stringify({
          ...JSON.parse(row.provenance_json),
          rawModelOutputHash: '0'.repeat(64),
        }),
      }));

    const result = await verifyReleaseAudit({ reader: tamperedReader });

    assert.ok(result.failures.some((failure) =>
      /raw classification provenance is invalid/.test(failure)));
  });

  it('accepts a valid v27 score audit control', async () => {
    const validReader = reader();
    validReader.getReleaseScoreAudit('v1').score_model_version = SCORE_MODEL_VERSION;

    const result = await verifyReleaseAudit({ reader: validReader });

    assert.deepEqual(result.failures, []);
  });

  it('accepts neutral unknown direct fix commit proof as non-actionable audit evidence', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        verified: [],
        unverified: [{ number: 1, sentiment: 'neutral', prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'non_bug_direct_fix_commit_reachability_unknown',
          title: 'neutral source proof note',
          sentiment: 'neutral',
          severity: 'low',
          functionality: 'docs',
          scope: 'niche',
          affected_users: 'few',
          evidence_json: JSON.stringify({
            closureClassification: {
              classification: {
                sentiment: 'neutral',
                severity: 'low',
                functionality: 'docs',
                scope: 'niche',
                affectedUsers: 'few',
              },
            },
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            hasUnknownFixCommit: true,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [],
            notReachableFixCommits: [],
            unknownFixCommits: [commit],
            targetReachableFixCommits: [],
            targetNotReachableFixCommits: [],
            targetUnknownFixCommits: [commit],
            predecessorContainedFixCommits: [],
            firstContainingUnknownFixCommits: [],
            directCommitFirstContainingProofs: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'ClosureComment.fixProof',
              status: 'unknown',
              creditEligible: false,
              tagCommitOid: null,
              evidence: 'commit_unavailable',
              snippet: `Fix evidence commit ${commit}`,
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { non_bug_direct_fix_commit_reachability_unknown: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.deepEqual(result.failures, []);
  });

  it('fails when target-reachable commit arrays do not match proof entry statuses', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: true,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [],
            notReachableFixCommits: [],
            targetReachableFixCommits: [],
            targetNotReachableFixCommits: [],
            targetUnknownFixCommits: [],
            predecessorContainedFixCommits: [],
            firstContainingUnknownFixCommits: [],
            directCommitFirstContainingProofs: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'ClosureComment.fixProof',
              status: 'reachable',
              creditEligible: false,
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'Fix evidence commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) =>
      /targetReachableFixCommits must equal/.test(failure)));
  });

  it('accepts referenced event commit proof as a known source', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: true,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [commit],
            notReachableFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'ReferencedEvent.commit',
              status: 'reachable',
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'GitHub ReferencedEvent same-repo commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a: fix(test): prove path',
            }],
          }),
        }],
      }),
    });
    assert.ok(!result.failures.some((failure) => /unknown source|closure-comment commit proof/.test(failure)));
  });

  it('fails when commit proof source is unknown', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: true,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [commit],
            notReachableFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'AdHocCommit',
              status: 'reachable',
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'Ad hoc commit proof',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /unknown source AdHocCommit/.test(failure)));
  });
});
