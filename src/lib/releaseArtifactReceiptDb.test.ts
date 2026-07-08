import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { join } from 'node:path';
import { buildArtifactVerificationEvidence } from './artifactVerification.ts';
import {
  buildReleaseArtifactPublication,
  type ReleaseArtifactPublication,
} from './releaseArtifactPublication.ts';
import type {
  ReleaseArtifactIdentity,
  ReleaseArtifactMetadata,
} from './releaseArtifactReceipt.ts';
import type { EvidenceReportVerification } from './releaseEvidence.ts';

const VERSION = '2026.6.10';
const TAG = `v${VERSION}`;
const RELEASE_SHA = 'a'.repeat(40);
const TARBALL_URL =
  `https://registry.npmjs.org/openclaw/-/openclaw-${VERSION}.tgz`;
const REPORT_URL =
  `https://github.com/openclaw/openclaw/blob/${RELEASE_SHA}/` +
  'release-evidence.json';
const RAW_REPORT_URL =
  `https://raw.githubusercontent.com/openclaw/openclaw/${RELEASE_SHA}/` +
  'release-evidence.json';
const VALIDATION_URL =
  'https://github.com/openclaw/openclaw/actions/runs/123456789';

const databasePath = requiredEnvironmentPath('DB_PATH');
const emptyDotenvPath = requiredEnvironmentPath('DOTENV_CONFIG_PATH');

let db: typeof import('./db.ts');

before(async () => {
  db = await import(`./db.ts?release-artifact-db-${Date.now()}-${Math.random()}`);
});

after(() => {
  db?.db.close();
});

function requiredEnvironmentPath(name: string): string {
  const value = process.env[name];
  assert.ok(value, `${name} must be assigned by the guarded test runner`);
  return value;
}

describe('release artifact verification database ledger', () => {
  it('is append-only, restart-safe, idempotent, transactional, and fail-closed', () => {
    const release = releaseIdentity();
    db.replaceActiveReleaseCatalog([{
      node_id: release.releaseNodeId,
      catalog_tag_commit_oid: release.catalogTagCommitOid,
      tag: release.tag,
      name: release.tag,
      published_at: release.publishedAt,
      created_at: release.publishedAt,
      updated_at: release.publishedAt,
      html_url: `https://github.com/openclaw/openclaw/releases/tag/${release.tag}`,
      prerelease: false,
      body: null,
    }]);

    const successfulRun = beginRun('artifact-success');
    const successfulInput = verificationInput(
      successfulRun,
      offsetTime(successfulRun.startedAt, 2_000),
    );
    const first = db.persistReleaseArtifactVerification(successfulInput);
    const retry = db.persistReleaseArtifactVerification(successfulInput);
    assert.equal(first.receipt.inserted, true);
    assert.equal(first.observation.inserted, true);
    assert.equal(retry.receipt.equivalent, true);
    assert.equal(retry.observation.equivalent, true);
    assert.equal(
      retry.observation.row.observationId,
      first.observation.row.observationId,
    );
    assert.equal(
      db.getReleaseArtifactVerificationReceipt(first.receipt.row.receiptId)
        ?.contentHash,
      first.receipt.row.contentHash,
    );
    assert.equal(
      db.getReleaseArtifactVerificationObservation(
        first.observation.row.observationId,
      )?.contentHash,
      first.observation.row.contentHash,
    );
    assert.equal(
      db.getCurrentReleaseArtifactVerificationObservation(release),
      null,
      'unterminated observations must not become current',
    );
    assert.equal(
      db.getReleaseArtifactVerificationForScoring(release, {
        runId: successfulRun.runId,
      })?.observation.runId,
      successfulRun.runId,
      'the fenced active run may select its own staged observation',
    );
    const stagedIdentity = db.scoreSourceIdentity({
      artifactObservationRunId: successfulRun.runId,
    });

    finalizeSuccess(successfulRun);
    db.setMeta('score_persistence_last_run', JSON.stringify({
      schemaVersion: 2,
      source: 'refresh',
      operationReceiptRequired: true,
      operationRunId: successfulRun.runId,
    }));
    assert.equal(
      db.getCurrentReleaseArtifactVerificationObservation(release)?.runId,
      successfulRun.runId,
    );
    assert.deepEqual(
      db.scoreSourceIdentity(),
      stagedIdentity,
      'published selection must reproduce the staged semantic receipt identity',
    );
    const beforeMutableArtifactFields = db.scoreSourceIdentity();
    db.updateReleaseDerivedStats({
      tag: TAG,
      breaking_count: 0,
      fixes_count: 0,
      changes_count: 0,
      highlights_count: 0,
      pr_refs_count: 0,
      beta_count: 0,
      hours_to_next_release: null,
      hours_to_next_stable: null,
      npm_package_url: 'https://mutable.invalid/package',
      release_tarball_url: 'https://mutable.invalid/tarball.tgz',
      release_integrity: 'sha512-mutable',
      release_sha: 'f'.repeat(40),
      full_release_ci_report_url: 'https://mutable.invalid/report',
      full_release_validation_url: 'https://mutable.invalid/validation',
    });
    db.updateReleaseArtifactVerification({
      tag: TAG,
      registry_version: 'mutable',
      registry_integrity: 'sha512-mutable',
      registry_tarball_url: 'https://mutable.invalid/registry.tgz',
      ci_report_verified: 0,
      ci_report_mismatch: 'mutable',
      release_validation_verified: 0,
      release_validation_mismatch: 'mutable',
      artifact_verified: 0,
      artifact_mismatch: 'mutable',
    });
    assert.deepEqual(
      db.scoreSourceIdentity(),
      beforeMutableArtifactFields,
      'mutable release artifact fields and timestamps must not affect schema-17 identity',
    );

    const failedRun = beginRun('artifact-failure');
    const failedInput = verificationInput(
      failedRun,
      offsetTime(failedRun.startedAt, 2_000),
    );
    const reused = db.persistReleaseArtifactVerification(failedInput);
    assert.equal(reused.receipt.inserted, false);
    assert.equal(reused.receipt.equivalent, true);
    assert.equal(reused.receipt.row.receiptId, first.receipt.row.receiptId);
    assert.equal(reused.receipt.row.contentHash, first.receipt.row.contentHash);
    assert.equal(reused.observation.inserted, true);
    assert.notEqual(
      reused.observation.row.observationId,
      first.observation.row.observationId,
    );
    assert.deepEqual(
      db.scoreSourceIdentity({
        artifactObservationRunId: failedRun.runId,
      }),
      stagedIdentity,
      'observing identical semantic evidence in a later run must not change identity',
    );

    const countsBeforeConflict = ledgerCounts();
    assert.throws(
      () => db.persistReleaseArtifactVerification({
        ...failedInput,
        evidenceReport: evidenceReport('7'.repeat(64)),
      }),
      /observation conflict/,
    );
    assert.deepEqual(
      ledgerCounts(),
      countsBeforeConflict,
      'a conflicting observation must roll back its newly staged receipt',
    );
    finalizeFailure(failedRun);
    assert.throws(
      () => db.getReleaseArtifactVerificationForScoring(release, {
        runId: failedRun.runId,
      }),
      /terminated as "failure"/,
    );
    assert.equal(
      db.getCurrentReleaseArtifactVerificationObservation(release)?.runId,
      successfulRun.runId,
      'a later failed run must not displace the last successful observation',
    );

    const activeRun = beginRun('artifact-active');
    const active = db.persistReleaseArtifactVerification(
      verificationInput(
        activeRun,
        offsetTime(activeRun.startedAt, 2_000),
        evidenceReport('8'.repeat(64)),
      ),
    );
    assert.notEqual(active.receipt.row.receiptId, first.receipt.row.receiptId);
    assert.notEqual(
      db.scoreSourceIdentity({
        artifactObservationRunId: activeRun.runId,
      }).digest,
      stagedIdentity.digest,
      'semantic artifact evidence changes must change schema-17 identity',
    );
    assert.equal(
      db.getCurrentReleaseArtifactVerificationObservation(release)?.runId,
      successfulRun.runId,
      'a later active run must not displace the last successful observation',
    );

    const countsBeforeUnknown = ledgerCounts();
    assert.throws(
      () => db.persistReleaseArtifactVerification({
        ...successfulInput,
        runId: 'artifact-unknown',
      }),
      /unknown refresh run/,
    );
    assert.deepEqual(ledgerCounts(), countsBeforeUnknown);

    const terminalRun = beginRun('artifact-terminal');
    finalizeFailure(terminalRun, false);
    const countsBeforeTerminal = ledgerCounts();
    assert.throws(
      () => db.persistReleaseArtifactVerification(
        verificationInput(
          terminalRun,
          offsetTime(terminalRun.startedAt, 2_000),
          evidenceReport('9'.repeat(64)),
        ),
      ),
      /after terminal receipt/,
    );
    assert.deepEqual(
      ledgerCounts(),
      countsBeforeTerminal,
      'terminal-run rejection must roll back its staged receipt',
    );
    releaseRunLease(terminalRun);

    const integrity = db.releaseArtifactVerificationLedgerIntegrity();
    assert.deepEqual(integrity.problems, []);
    assert.equal(integrity.receiptCount, 2);
    assert.equal(integrity.observationCount, 3);

    db.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const restart = spawnSync(process.execPath, [
      '--import',
      'tsx',
      '--input-type=module',
      '--eval',
      `
        const imported = await import('./src/lib/db.ts?artifact-reload=' + Date.now());
        const database = imported.default ?? imported;
        const integrity = database.releaseArtifactVerificationLedgerIntegrity();
        if (integrity.problems.length > 0) {
          console.error(integrity.problems.join('\\n'));
          process.exit(11);
        }
        if (integrity.receiptCount !== 2 || integrity.observationCount !== 3) {
          process.exit(12);
        }
        const receipts = database.listReleaseArtifactVerificationReceipts();
        const observations = database.listReleaseArtifactVerificationObservations();
        if (receipts.some((row) => !row.contentHash || !row.receiptId)) process.exit(13);
        if (observations.some((row) => !row.contentHash || !row.observationId)) {
          process.exit(14);
        }
        database.db.close();
      `,
    ], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DB_PATH: databasePath,
        DOTENV_CONFIG_PATH: emptyDotenvPath,
        RADAR_DB_READ_ONLY: '1',
        RADAR_DB_BOOTSTRAP_MODE: 'existing',
        NODE_ENV: 'test',
      },
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
    assert.equal(restart.status, 0, `${restart.stdout}\n${restart.stderr}`);

    assert.throws(
      () => db.db.prepare(`
        UPDATE release_artifact_verification_receipts
        SET release_tag=release_tag
      `).run(),
      /release_artifact_verification_receipts is append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        DELETE FROM release_artifact_verification_receipts
      `).run(),
      /release_artifact_verification_receipts is append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        UPDATE release_artifact_verification_observations
        SET release_tag=release_tag
      `).run(),
      /release_artifact_verification_observations is append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        DELETE FROM release_artifact_verification_observations
      `).run(),
      /release_artifact_verification_observations is append-only/,
    );

    const unfencedStartedAt = recentTime(-10_000);
    db.insertRefreshOperationAttempt({
      run_id: 'artifact-unfenced',
      operation: 'quality-refresh',
      trigger: 'test',
      started_at: unfencedStartedAt,
      lease_name: 'artifact-unfenced-lease',
      lease_holder_id: 'artifact-unfenced-holder',
      lease_expires_at: offsetTime(recentTime(), 300_000),
      code_revision: 'git:0123456789abcdef0123456789abcdef01234567',
      effective_config: { schemaVersion: 1 },
    });
    const countsBeforeUnfenced = ledgerCounts();
    assert.throws(
      () => db.persistReleaseArtifactVerification({
        ...successfulInput,
        runId: 'artifact-unfenced',
        observedAt: offsetTime(unfencedStartedAt, 1_000),
      }),
      /current unexpired lease holder\/fencing identity is not active/,
    );
    assert.deepEqual(ledgerCounts(), countsBeforeUnfenced);

    const secondReceipt = db.db.prepare(`
      SELECT id, previous_content_hash
      FROM release_artifact_verification_receipts
      ORDER BY id
      LIMIT 1 OFFSET 1
    `).get() as { id: number; previous_content_hash: string | null };
    db.db.exec('DROP TRIGGER release_artifact_verification_receipts_no_update');
    db.db.prepare(`
      UPDATE release_artifact_verification_receipts
      SET previous_content_hash=?
      WHERE id=?
    `).run('f'.repeat(64), secondReceipt.id);
    const receiptTamper = db.releaseArtifactVerificationLedgerIntegrity();
    assert.match(
      receiptTamper.problems.join('\n'),
      /previous content hash mismatch|failed verification/,
    );
    db.db.prepare(`
      UPDATE release_artifact_verification_receipts
      SET previous_content_hash=?
      WHERE id=?
    `).run(secondReceipt.previous_content_hash, secondReceipt.id);
    recreateReceiptUpdateTrigger();
    assert.deepEqual(db.releaseArtifactVerificationLedgerIntegrity().problems, []);

    const secondObservation = db.db.prepare(`
      SELECT id, previous_content_hash
      FROM release_artifact_verification_observations
      ORDER BY id
      LIMIT 1 OFFSET 1
    `).get() as { id: number; previous_content_hash: string | null };
    db.db.exec(
      'DROP TRIGGER release_artifact_verification_observations_no_update',
    );
    db.db.prepare(`
      UPDATE release_artifact_verification_observations
      SET previous_content_hash=?
      WHERE id=?
    `).run('e'.repeat(64), secondObservation.id);
    const observationTamper = db.releaseArtifactVerificationLedgerIntegrity();
    assert.match(
      observationTamper.problems.join('\n'),
      /previous content hash mismatch|failed verification/,
    );
    db.db.prepare(`
      UPDATE release_artifact_verification_observations
      SET previous_content_hash=?
      WHERE id=?
    `).run(secondObservation.previous_content_hash, secondObservation.id);
    recreateObservationUpdateTrigger();
    assert.deepEqual(db.releaseArtifactVerificationLedgerIntegrity().problems, []);

    finalizeFailure(activeRun);
  });

  it('rejects non-exact artifact publications before terminal receipt insertion', () => {
    const sourceRun = beginRun('artifact-publication-source');
    db.persistReleaseArtifactVerification(
      verificationInput(
        sourceRun,
        offsetTime(sourceRun.startedAt, 2_000),
        evidenceReport('9'.repeat(64)),
      ),
    );
    const wrongRunPublication =
      db.releaseArtifactPublicationForRun(sourceRun.runId);
    finalizeSuccess(sourceRun, wrongRunPublication);

    const targetRun = beginRun('artifact-publication-target');
    db.persistReleaseArtifactVerification(
      verificationInput(
        targetRun,
        offsetTime(targetRun.startedAt, 2_000),
        evidenceReport('9'.repeat(64)),
      ),
    );
    const exactPublication =
      db.releaseArtifactPublicationForRun(targetRun.runId);
    const [exactLink] = exactPublication.links;
    assert.ok(exactLink);
    assert.notEqual(
      wrongRunPublication.links[0]?.observationId,
      exactLink.observationId,
    );
    assert.equal(
      wrongRunPublication.links[0]?.receiptId,
      exactLink.receiptId,
    );

    const missingPublication = buildReleaseArtifactPublication([]);
    const extraPublication = buildReleaseArtifactPublication([
      ...exactPublication.links,
      extraArtifactPublicationLink(),
    ]);
    const substitutedSameTagPublication = buildReleaseArtifactPublication(
      exactPublication.links.map((link, index) =>
        index === 0
          ? {
              ...link,
              observationContentHash:
                `${link.observationContentHash[0] === '0' ? '1' : '0'}` +
                link.observationContentHash.slice(1),
              release: {
                ...link.release,
                releaseNodeId: `${link.release.releaseNodeId}-substituted`,
              },
            }
          : link),
    );
    assert.equal(
      substitutedSameTagPublication.links[0]?.release.tag,
      exactLink.release.tag,
    );

    const receiptInput = stageSuccessfulReceiptInput(
      targetRun,
      exactPublication,
    );
    const receiptChainBefore = refreshCaptureReceiptChain();
    const cases = [
      {
        name: 'missing publication member',
        releaseArtifacts: missingPublication,
        expected: /missing immutable observation membership/,
      },
      {
        name: 'extra publication member',
        releaseArtifacts: extraPublication,
        expected: /extra immutable observation membership/,
      },
      {
        name: 'substituted same-tag release identity',
        releaseArtifacts: substitutedSameTagPublication,
        expected:
          /is substituted: release identity, observation content hash/,
      },
      {
        name: 'wrong-run publication',
        releaseArtifacts: wrongRunPublication,
        expected: /missing immutable observation membership/,
      },
    ];
    for (const testCase of cases) {
      assert.throws(
        () => db.appendRefreshCaptureReceipt({
          ...receiptInput,
          payload: {
            ...receiptInput.payload,
            releaseArtifacts: testCase.releaseArtifacts,
          },
        }),
        testCase.expected,
        testCase.name,
      );
      assert.equal(
        db.getRefreshCaptureReceipt(targetRun.runId),
        null,
        testCase.name,
      );
      assert.deepEqual(
        refreshCaptureReceiptChain(),
        receiptChainBefore,
        testCase.name,
      );
    }

    const rollbackMetaKey =
      'release_artifact_publication_semantic_transaction_rollback';
    assert.equal(db.getMeta(rollbackMetaKey), null);
    assert.throws(
      () => db.runInWriteTransaction(() => {
        db.setMeta(rollbackMetaKey, 'pending');
        db.appendRefreshCaptureReceipt({
          ...receiptInput,
          payload: {
            ...receiptInput.payload,
            releaseArtifacts: substitutedSameTagPublication,
          },
        });
      }),
      /is substituted: release identity, observation content hash/,
    );
    assert.equal(db.getMeta(rollbackMetaKey), null);
    assert.equal(db.getRefreshCaptureReceipt(targetRun.runId), null);
    assert.deepEqual(refreshCaptureReceiptChain(), receiptChainBefore);

    db.appendRefreshCaptureReceipt({
      run_id: targetRun.runId,
      lease_name: targetRun.leaseName,
      lease_holder_id: targetRun.leaseHolderId,
      status: 'failure',
      finished_at: offsetTime(targetRun.startedAt, 9_000),
      duration_ms: 9_000,
      payload: {
        schemaVersion: 1,
        operation: targetRun.operation,
        trigger: targetRun.trigger,
        error: { message: 'artifact publication rejected' },
      },
    });
    releaseRunLease(targetRun);
  });
});

interface RunFixture {
  runId: string;
  operation: string;
  trigger: string;
  startedAt: string;
  leaseName: string;
  leaseHolderId: string;
}

function beginRun(suffix: string): RunFixture {
  const startedAt = recentTime(-20_000);
  const acquiredAt = recentTime();
  const run: RunFixture = {
    runId: `run-${suffix}`,
    operation: 'quality-refresh',
    trigger: 'test',
    startedAt,
    leaseName: `lease-${suffix}`,
    leaseHolderId: `holder-${suffix}`,
  };
  assert.equal(
    db.acquireRefreshLease(
      run.leaseName,
      run.leaseHolderId,
      acquiredAt,
      300_000,
    ),
    true,
  );
  db.beginRefreshOperationAttempt({
    run_id: run.runId,
    operation: run.operation,
    trigger: run.trigger,
    started_at: run.startedAt,
    lease_name: run.leaseName,
    lease_holder_id: run.leaseHolderId,
    lease_expires_at: offsetTime(acquiredAt, 300_000),
    code_revision: 'git:0123456789abcdef0123456789abcdef01234567',
    effective_config: { schemaVersion: 1 },
  });
  return run;
}

function finalizeSuccess(
  run: RunFixture,
  releaseArtifacts: ReleaseArtifactPublication =
    db.releaseArtifactPublicationForRun(run.runId),
): void {
  db.appendRefreshCaptureReceipt(
    stageSuccessfulReceiptInput(run, releaseArtifacts),
  );
  releaseRunLease(run);
}

function stageSuccessfulReceiptInput(
  run: RunFixture,
  releaseArtifacts: ReleaseArtifactPublication,
) {
  const historyRunId = `history-${run.runId}`;
  const historyRunContentHash = '1'.repeat(64);
  const authorityRunId = `authority-${run.runId}`;
  const authorityRunContentHash = '2'.repeat(64);
  const historyV2SealContentHash = '3'.repeat(64);
  const commitNotBefore = offsetTime(run.startedAt, 5_500);
  const commitNotAfter = offsetTime(run.startedAt, 6_000);
  const scoreDetails = {
    historyRunId,
    historyRunContentHash,
    authorityRunId,
    authorityRunContentHash,
    historyV2SealContentHash,
    commitNotBefore,
    commitNotAfter,
  };
  appendStage(run, 'score.persist', 'started', 5_000);
  appendStage(
    run,
    'score.persist',
    'completed',
    6_000,
    1_000,
    { scoredReleases: 1 },
    scoreDetails,
  );
  appendStage(run, 'forecast.capture', 'started', 7_000);
  appendStage(
    run,
    'forecast.capture',
    'completed',
    8_000,
    1_000,
    { validationForecasts: 0 },
    { eligibilityOutcome: 'not_eligible' },
  );
  return {
    run_id: run.runId,
    lease_name: run.leaseName,
    lease_holder_id: run.leaseHolderId,
    status: 'success' as const,
    finished_at: offsetTime(run.startedAt, 8_000),
    duration_ms: 8_000,
    payload: {
      schemaVersion: 2,
      operation: run.operation,
      trigger: run.trigger,
      scoreHistory: {
        runId: historyRunId,
        contentHash: historyRunContentHash,
      },
      scoreAuthority: {
        runId: authorityRunId,
        contentHash: authorityRunContentHash,
        historyV2SealContentHash,
      },
      scoreCommit: {
        historyRunId,
        historyRunContentHash,
        authorityRunId,
        authorityRunContentHash,
        historyV2SealContentHash,
        commitNotBefore,
        commitNotAfter,
      },
      releaseTags: [TAG],
      releaseArtifacts,
      forecast: {
        eligibilityOutcome: 'not_eligible',
        decisionIds: [],
        newDecisionIds: [],
        existingDecisionIds: [],
        captures: [],
      },
    },
  };
}

function finalizeFailure(run: RunFixture, releaseLease = true): void {
  db.appendRefreshCaptureReceipt({
    run_id: run.runId,
    lease_name: run.leaseName,
    lease_holder_id: run.leaseHolderId,
    status: 'failure',
    finished_at: offsetTime(run.startedAt, 4_000),
    duration_ms: 4_000,
    payload: {
      schemaVersion: 1,
      operation: run.operation,
      trigger: run.trigger,
      error: { message: 'test failure' },
    },
  });
  if (releaseLease) releaseRunLease(run);
}

function releaseRunLease(run: RunFixture): void {
  assert.equal(db.releaseRefreshLease(run.leaseName, run.leaseHolderId), true);
}

function appendStage(
  run: RunFixture,
  stage: string,
  status: 'started' | 'completed',
  offsetMs: number,
  durationMs: number | null = null,
  counts: Record<string, unknown> | null = null,
  details: Record<string, unknown> | null = null,
): void {
  db.appendRefreshOperationStageEvent({
    run_id: run.runId,
    lease_name: run.leaseName,
    lease_holder_id: run.leaseHolderId,
    stage,
    status,
    occurred_at: offsetTime(run.startedAt, offsetMs),
    duration_ms: durationMs,
    counts,
    details,
  });
}

function verificationInput(
  run: RunFixture,
  observedAt: string,
  report: EvidenceReportVerification = evidenceReport('6'.repeat(64)),
) {
  return {
    runId: run.runId,
    observedAt,
    release: releaseIdentity(),
    releaseMetadata: releaseMetadata(),
    artifact: artifactEvidence(),
    evidenceReport: report,
  };
}

function releaseIdentity(): ReleaseArtifactIdentity {
  return {
    repository: 'openclaw/openclaw',
    tag: TAG,
    releaseNodeId: 'RE_kwDOReleaseArtifactReceiptDb',
    catalogTagCommitOid: RELEASE_SHA,
    publishedAt: '2026-06-10T12:00:00.000Z',
  };
}

function releaseMetadata(): ReleaseArtifactMetadata {
  return {
    npmPackageUrl: `https://www.npmjs.com/package/openclaw/v/${VERSION}`,
    releaseTarballUrl: TARBALL_URL,
    releaseIntegrity: integrity(),
    releaseSha: RELEASE_SHA,
    ciReportUrl: REPORT_URL,
    fullReleaseValidationUrl: VALIDATION_URL,
  };
}

function artifactEvidence() {
  const bytes = Buffer.from('release artifact receipt database tarball bytes');
  const digest = createHash('sha512').update(bytes).digest('base64');
  return buildArtifactVerificationEvidence({
    packageName: 'openclaw',
    requestedVersion: VERSION,
    metadataUrl: `https://registry.npmjs.org/openclaw/${VERSION}`,
    metadataContentDigest: '5'.repeat(64),
    registryAvailability: 'available',
    registryPackageName: 'openclaw',
    registryVersion: VERSION,
    registryIntegrity: `sha512-${digest}`,
    registryTarballUrl: TARBALL_URL,
    registryGitHead: RELEASE_SHA,
    actualDigests: { sha512: digest },
    tarballByteCount: bytes.length,
    expectedIntegrity: `sha512-${digest}`,
    expectedTarballUrl: TARBALL_URL,
    expectedReleaseSha: RELEASE_SHA,
  });
}

function evidenceReport(contentDigest: string): EvidenceReportVerification {
  return {
    url: REPORT_URL,
    rawUrl: RAW_REPORT_URL,
    fallbackUrl: null,
    fallbackKind: null,
    fallbackArtifactCount: 0,
    contentDigest,
    fallbackArtifactDigest: null,
    expectedReleaseTag: TAG,
    expectedReleaseSha: RELEASE_SHA,
    verified: true,
    mismatch: null,
  };
}

function integrity(): string {
  const bytes = Buffer.from('release artifact receipt database tarball bytes');
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}

function ledgerCounts(): { receipts: number; observations: number } {
  return {
    receipts: db.listReleaseArtifactVerificationReceipts().length,
    observations: db.listReleaseArtifactVerificationObservations().length,
  };
}

function refreshCaptureReceiptChain() {
  return db.listRefreshCaptureReceipts().map((receipt) => ({
    receiptId: receipt.receipt_id,
    runId: receipt.run_id,
    previousContentHash: receipt.previous_content_hash,
    contentHash: receipt.content_hash,
  }));
}

function extraArtifactPublicationLink():
  ReleaseArtifactPublication['links'][number] {
  const evidenceIdentity = 'd'.repeat(64);
  return {
    release: {
      repository: 'openclaw/openclaw',
      tag: 'v2099.1.1',
      releaseNodeId: 'RE_extraArtifactPublication',
      catalogTagCommitOid: 'c'.repeat(40),
      publishedAt: '2099-01-01T00:00:00.000Z',
    },
    observationId: `artifact-observation-v1:${'e'.repeat(64)}`,
    observationContentHash: 'f'.repeat(64),
    receiptId: `artifact-receipt-v2:${evidenceIdentity}`,
    receiptContentHash: '0'.repeat(64),
    evidenceIdentity,
    evidenceReportIdentity:
      `release-evidence-v1:sha256:${'1'.repeat(64)}`,
  };
}

function recreateReceiptUpdateTrigger(): void {
  db.db.exec(`
    CREATE TRIGGER release_artifact_verification_receipts_no_update
    BEFORE UPDATE ON release_artifact_verification_receipts
    BEGIN
      SELECT RAISE(
        ABORT,
        'release_artifact_verification_receipts is append-only'
      );
    END
  `);
}

function recreateObservationUpdateTrigger(): void {
  db.db.exec(`
    CREATE TRIGGER release_artifact_verification_observations_no_update
    BEFORE UPDATE ON release_artifact_verification_observations
    BEGIN
      SELECT RAISE(
        ABORT,
        'release_artifact_verification_observations is append-only'
      );
    END
  `);
}

function recentTime(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function offsetTime(value: string, offsetMs: number): string {
  return new Date(Date.parse(value) + offsetMs).toISOString();
}
