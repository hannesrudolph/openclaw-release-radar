import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertOperationReceiptStagePrefix,
  operationCaptureReceiptContentHash,
  operationCaptureReceiptSemanticIdentity,
  operationEffectiveConfig,
  operationErrorDetails,
  operationReceiptArtifactPublicationSemanticProblems,
  operationReceiptSemanticProblems,
  operationReceiptStagePrefixSemanticProblems,
  verifyOperationReceiptLedger,
  verifyOperationReceiptSemanticLinks,
} from './operationReceipts.ts';
import {
  releaseValidationDecisionId,
  releaseValidationForecastContentHash,
} from './releaseValidation.ts';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from './scoreHistoryLedger.ts';
import {
  buildReleaseScoreAuditHistoryV2Seal,
  buildScoreAuthorityResolutionRun,
} from './scoreAuthorityResolution.ts';
import {
  sealReleaseValidationForecastV2,
  verifyReleaseValidationProofBundle,
} from './releaseValidationProof.ts';
import {
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle.ts';
import {
  buildReleaseArtifactPublicationScope,
} from './releaseArtifactPublicationScope.ts';
import {
  buildReleaseArtifactPublication,
} from './releaseArtifactPublication.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownedTestDir = assignedWorkerDatabasePath === null
  ? mkdtempSync(join(tmpdir(), 'radar-operation-receipts-'))
  : null;
if (ownedTestDir !== null) {
  const emptyDotenvPath = join(ownedTestDir, '.env.empty');
  process.env.DB_PATH = join(ownedTestDir, 'radar.db');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
  writeFileSync(emptyDotenvPath, '');
}

let db: typeof import('./db.ts');

before(async () => {
  db = await import(`./db.ts?operation-receipts-${Date.now()}-${Math.random()}`);
});

after(() => {
  db?.db.close();
  if (ownedTestDir !== null) {
    rmSync(ownedTestDir, { recursive: true, force: true });
  }
});

describe('durable refresh operation receipts', () => {
  it('keeps receipt semantic identity stable across chain re-hashing', () => {
    const semantic = {
      receiptId: 'receipt-semantic-identity',
      runId: 'run-semantic-identity',
      status: 'success' as const,
      finishedAt: '2026-07-04T12:00:04.000Z',
      durationMs: 4_000,
      stageEventCount: 4,
      stageChainHash: 'a'.repeat(64),
      payloadJson: JSON.stringify({
        schemaVersion: 1,
        operation: 'refresh',
      }),
    };
    const originalContentHash = operationCaptureReceiptContentHash({
      ...semantic,
      previousContentHash: null,
    });
    const rechainedContentHash = operationCaptureReceiptContentHash({
      ...semantic,
      previousContentHash: 'b'.repeat(64),
    });
    const semanticIdentity = operationCaptureReceiptSemanticIdentity(semantic);

    assert.notEqual(rechainedContentHash, originalContentHash);
    assert.equal(
      operationCaptureReceiptSemanticIdentity({ ...semantic }),
      semanticIdentity,
    );

    const mutations = [
      { receiptId: `${semantic.receiptId}-changed` },
      { runId: `${semantic.runId}-changed` },
      { status: 'failure' as const },
      { finishedAt: '2026-07-04T12:00:05.000Z' },
      { durationMs: semantic.durationMs + 1 },
      { stageEventCount: semantic.stageEventCount + 1 },
      { stageChainHash: 'c'.repeat(64) },
      { payloadJson: '{"schemaVersion":2}' },
    ];
    for (const mutation of mutations) {
      assert.notEqual(
        operationCaptureReceiptSemanticIdentity({
          ...semantic,
          ...mutation,
        }),
        semanticIdentity,
        JSON.stringify(mutation),
      );
    }
  });

  it('builds an effective config that cannot retain API secrets', () => {
    const githubSecret = 'github_pat_receipt_test_secret_1234567890';
    const openaiSecret = 'sk-receipt-test-secret-1234567890';
    const effective = operationEffectiveConfig({
      github: {
        owner: 'openclaw',
        repo: 'openclaw',
        token: githubSecret,
        graphql: {
          concurrency: 2,
          minStartSpacingMs: 250,
          token: githubSecret,
        },
      },
      openai: {
        apiKey: openaiSecret,
        model: 'gpt-test',
        reasoningEffort: 'medium',
        serviceTier: 'priority',
        requestTimeoutMs: 300_000,
        maxAttempts: 5,
        retryBaseMs: 1_000,
        retryMaxMs: 30_000,
      },
      refresh: {
        fullIssueBackfill: false,
        maxIssuePages: 4_096,
        issuePageSize: 100,
        issueCatalogSnapshotMaxAgeHours: 24,
        secret: openaiSecret,
      },
      limits: {
        releases: 10,
      },
    } as any);
    const serialized = JSON.stringify(effective);

    assert.equal(serialized.includes(githubSecret), false);
    assert.equal(serialized.includes(openaiSecret), false);
    assert.equal(serialized.includes('"token"'), false);
    assert.equal(serialized.includes('"apiKey"'), false);
    assert.equal((effective.openai as any).model, 'gpt-test');
    assert.equal((effective.refresh as any).issuePageSize, 100);
    assert.equal((effective.refresh as any).issueCatalogSnapshotMaxAgeHours, 24);
  });

  it('supports idempotent retries, rejects conflicts, verifies hashes, and enforces immutability', () => {
    const startedAt = recentTime(-10_000);
    const attemptInput = operationAttempt('run-receipt-1', {
      trigger: 'manual',
      startedAt,
    });
    const inserted = db.insertRefreshOperationAttempt(attemptInput);
    const equivalent = db.insertRefreshOperationAttempt(attemptInput);
    acquireAttemptLease(attemptInput);

    assert.equal(inserted.inserted, true);
    assert.equal(equivalent.equivalent, true);
    assert.equal(equivalent.row.content_hash, inserted.row.content_hash);
    assert.throws(
      () => db.insertRefreshOperationAttempt({
        ...attemptInput,
        trigger: 'scheduler',
      }),
      /attempt conflict/,
    );

    const started = db.appendRefreshOperationStageEvent({
      event_id: 'event-receipt-1-start',
      run_id: attemptInput.run_id,
      lease_name: attemptInput.lease_name,
      lease_holder_id: attemptInput.lease_holder_id,
      stage: 'release.fetch',
      status: 'started',
      occurred_at: offsetTime(startedAt, 1_000),
    });
    const completed = db.appendRefreshOperationStageEvent({
      event_id: 'event-receipt-1-complete',
      run_id: attemptInput.run_id,
      lease_name: attemptInput.lease_name,
      lease_holder_id: attemptInput.lease_holder_id,
      stage: 'release.fetch',
      status: 'completed',
      occurred_at: offsetTime(startedAt, 3_000),
      duration_ms: 2_000,
      counts: { releases: 10 },
      details: { digest: 'a'.repeat(64) },
    });
    const completedRetry = db.appendRefreshOperationStageEvent({
      event_id: 'event-receipt-1-complete',
      run_id: attemptInput.run_id,
      lease_name: attemptInput.lease_name,
      lease_holder_id: attemptInput.lease_holder_id,
      stage: 'release.fetch',
      status: 'completed',
      occurred_at: offsetTime(startedAt, 3_000),
      duration_ms: 2_000,
      counts: { releases: 10 },
      details: { digest: 'a'.repeat(64) },
    });

    assert.equal(started.row.sequence, 1);
    assert.equal(completed.row.sequence, 2);
    assert.equal(completed.row.previous_content_hash, started.row.content_hash);
    assert.equal(completedRetry.equivalent, true);
    assert.throws(
      () => db.appendRefreshOperationStageEvent({
        event_id: 'event-receipt-1-complete',
        run_id: attemptInput.run_id,
        lease_name: attemptInput.lease_name,
        lease_holder_id: attemptInput.lease_holder_id,
        stage: 'release.fetch',
        status: 'completed',
        occurred_at: offsetTime(startedAt, 3_000),
        duration_ms: 2_001,
      }),
      /stage event conflict/,
    );

    const receiptInput = {
      receipt_id: 'receipt-receipt-1',
      run_id: attemptInput.run_id,
      lease_name: attemptInput.lease_name,
      lease_holder_id: attemptInput.lease_holder_id,
      status: 'failure' as const,
      finished_at: offsetTime(startedAt, 4_000),
      duration_ms: 4_000,
      payload: {
        schemaVersion: 1,
        output: 'test',
      },
    };
    const receipt = db.appendRefreshCaptureReceipt(receiptInput);
    const receiptRetry = db.appendRefreshCaptureReceipt(receiptInput);

    assert.equal(receipt.inserted, true);
    assert.equal(receipt.row.stage_event_count, 2);
    assert.equal(receipt.row.stage_chain_hash, completed.row.content_hash);
    assert.equal(receiptRetry.equivalent, true);
    assert.throws(
      () => db.appendRefreshCaptureReceipt({
        ...receiptInput,
        duration_ms: receiptInput.duration_ms + 1,
      }),
      /receipt conflict/,
    );
    assert.throws(
      () => db.appendRefreshOperationStageEvent({
        run_id: attemptInput.run_id,
        lease_name: attemptInput.lease_name,
        lease_holder_id: attemptInput.lease_holder_id,
        stage: 'post-terminal',
        status: 'started',
        occurred_at: offsetTime(startedAt, 5_000),
      }),
      /cannot be appended after terminal receipt/,
    );

    const verification = verifyOperationReceiptLedger({
      attempts: db.listRefreshOperationAttempts(),
      stageEvents: db.listRefreshOperationStageEvents(),
      receipts: db.listRefreshCaptureReceipts(),
    });
    assert.deepEqual(verification.problems, []);
    assert.deepEqual(verification.unterminatedRunIds, []);

    assert.throws(
      () => db.db.prepare(`
        UPDATE refresh_operation_attempts SET trigger='changed' WHERE run_id=?
      `).run(attemptInput.run_id),
      /append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        UPDATE refresh_operation_stage_events SET stage='changed' WHERE event_id=?
      `).run(started.row.event_id),
      /append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        DELETE FROM refresh_capture_receipts WHERE run_id=?
      `).run(attemptInput.run_id),
      /append-only/,
    );
  });

  it('redacts bearer, JWT, URL, quoted JSON, and full secret values', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue';
    const details = operationErrorDetails(new Error(
      `Bearer ${jwt} ` +
      `https://alice:super-secret@example.test/path ` +
      `{"token":"quoted secret value","password":"another secret"} ` +
      `api_key=full-secret-value token=${jwt}`,
    ));
    const serialized = JSON.stringify(details);
    for (const secret of [
      jwt,
      'alice',
      'super-secret',
      'quoted secret value',
      'another secret',
      'full-secret-value',
    ]) {
      assert.equal(serialized.includes(secret), false, secret);
    }
    assert.match(serialized, /\[redacted\]/);
  });

  it('rejects terminal receipts whose stage chain is still active', () => {
    const startedAt = recentTime(-10_000);
    const attempt = operationAttempt('run-active-stage', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);
    db.appendRefreshOperationStageEvent({
      run_id: attempt.run_id,
      lease_name: attempt.lease_name,
      lease_holder_id: attempt.lease_holder_id,
      stage: 'forecast.capture',
      status: 'started',
      occurred_at: offsetTime(startedAt, 1_000),
    });
    assert.throws(
      () => db.appendRefreshCaptureReceipt({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: attempt.lease_holder_id,
        status: 'failure',
        finished_at: offsetTime(startedAt, 2_000),
        duration_ms: 2_000,
        payload: { schemaVersion: 1 },
      }),
      /with active stages/,
    );
    assert.equal(db.getRefreshCaptureReceipt(attempt.run_id), null);
  });

  it('rolls back output and terminal receipt together', () => {
    const startedAt = recentTime(-10_000);
    const attempt = operationAttempt('run-rollback', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);

    assert.throws(
      () => db.runInWriteTransaction(() => {
        db.setMeta('receipt_rollback_output', 'committed');
        db.appendRefreshCaptureReceipt({
          run_id: attempt.run_id,
          lease_name: attempt.lease_name,
          lease_holder_id: attempt.lease_holder_id,
          status: 'failure',
          finished_at: offsetTime(startedAt, 1_000),
          duration_ms: 1_000,
          payload: { schemaVersion: 1 },
        });
        throw new Error('force final transaction rollback');
      }),
      /force final transaction rollback/,
    );

    assert.equal(db.getMeta('receipt_rollback_output'), null);
    assert.equal(db.getRefreshCaptureReceipt(attempt.run_id), null);
    db.appendRefreshCaptureReceipt({
      run_id: attempt.run_id,
      lease_name: attempt.lease_name,
      lease_holder_id: attempt.lease_holder_id,
      status: 'failure',
      finished_at: offsetTime(startedAt, 2_000),
      duration_ms: 2_000,
      payload: { schemaVersion: 1, error: 'rolled back' },
    });
  });

  it('appends abandonment receipts for expired unterminated attempts without mutating them', () => {
    const successorStartedAt = recentTime(-1_000);
    const leaseName = 'github-refresh-abandonment';
    const oldAttempt = operationAttempt('run-expired', {
      trigger: 'scheduler',
      startedAt: offsetTime(successorStartedAt, -600_000),
      leaseName,
      leaseHolderId: 'holder-old',
      leaseExpiresAt: offsetTime(successorStartedAt, -300_000),
    });
    db.insertRefreshOperationAttempt(oldAttempt);
    const original = db.getRefreshOperationAttempt(oldAttempt.run_id);
    assert.equal(
      db.acquireRefreshLease(
        leaseName,
        'holder-new',
        successorStartedAt,
        db.REFRESH_WRITE_LEASE_TTL_MS,
      ),
      true,
    );

    const next = db.beginRefreshOperationAttempt(operationAttempt('run-successor', {
      trigger: 'manual',
      startedAt: successorStartedAt,
      leaseName,
      leaseHolderId: 'holder-new',
      leaseExpiresAt: offsetTime(successorStartedAt, 300_000),
    }));

    assert.equal(next.abandonedReceipts.length, 1);
    assert.equal(next.abandonedReceipts[0].run_id, oldAttempt.run_id);
    assert.equal(next.abandonedReceipts[0].status, 'abandoned');
    assert.deepEqual(db.getRefreshOperationAttempt(oldAttempt.run_id), original);
    assert.equal(
      JSON.parse(next.abandonedReceipts[0].payload_json).successorRunId,
      'run-successor',
    );
  });

  it('rejects inactive stage completion before inserting a ledger row', () => {
    const startedAt = recentTime(-5_000);
    const attempt = operationAttempt('run-inactive-completion', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);

    assert.throws(
      () => db.appendRefreshOperationStageEvent({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: attempt.lease_holder_id,
        stage: 'score.persist',
        status: 'completed',
        occurred_at: offsetTime(startedAt, 1_000),
        duration_ms: 1_000,
      }),
      /without an active started stage/,
    );
    assert.deepEqual(db.listRefreshOperationStageEvents(attempt.run_id), []);
  });

  it('rejects invalid intermediate prefixes before an append caller inserts them', () => {
    const startedAt = recentTime(-10_000);
    const attempt = operationAttempt('run-invalid-intermediate-prefix', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);
    db.appendRefreshOperationStageEvent({
      run_id: attempt.run_id,
      lease_name: attempt.lease_name,
      lease_holder_id: attempt.lease_holder_id,
      stage: 'release.fetch',
      status: 'started',
      occurred_at: offsetTime(startedAt, 2_000),
    });
    db.appendRefreshOperationStageEvent({
      run_id: attempt.run_id,
      lease_name: attempt.lease_name,
      lease_holder_id: attempt.lease_holder_id,
      stage: 'release.fetch',
      status: 'completed',
      occurred_at: offsetTime(startedAt, 4_000),
      duration_ms: 2_000,
    });

    const candidate = semanticStage(
      attempt.run_id,
      3,
      'score.persist',
      'started',
      offsetTime(startedAt, 3_000),
      null,
    );
    assert.throws(
      () => assertOperationReceiptStagePrefix({
        attempt: db.getRefreshOperationAttempt(attempt.run_id)!,
        stageEvents: [
          ...db.listRefreshOperationStageEvents(attempt.run_id),
          candidate,
        ],
      }),
      /stage prefix semantic validation failed.*timestamps are not nondecreasing/,
    );
    assert.equal(db.listRefreshOperationStageEvents(attempt.run_id).length, 2);
  });

  it('rejects stage prefixes continued after a failed terminal stage', () => {
    const startedAt = recentTime(-10_000);
    const attempt = operationAttempt('run-stage-after-failure', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);
    db.appendRefreshOperationStageEvent({
      run_id: attempt.run_id,
      lease_name: attempt.lease_name,
      lease_holder_id: attempt.lease_holder_id,
      stage: 'release.fetch',
      status: 'started',
      occurred_at: offsetTime(startedAt, 1_000),
    });
    db.appendRefreshOperationStageEvent({
      run_id: attempt.run_id,
      lease_name: attempt.lease_name,
      lease_holder_id: attempt.lease_holder_id,
      stage: 'release.fetch',
      status: 'failed',
      occurred_at: offsetTime(startedAt, 2_000),
      duration_ms: 1_000,
    });

    const candidate = semanticStage(
      attempt.run_id,
      3,
      'forecast.capture',
      'started',
      offsetTime(startedAt, 3_000),
      null,
    );
    assert.throws(
      () => assertOperationReceiptStagePrefix({
        attempt: db.getRefreshOperationAttempt(attempt.run_id)!,
        stageEvents: [
          ...db.listRefreshOperationStageEvents(attempt.run_id),
          candidate,
        ],
      }),
      /stage prefix semantic validation failed.*after a failed terminal stage/,
    );
    assert.equal(db.listRefreshOperationStageEvents(attempt.run_id).length, 2);
  });

  it('rejects stale holders for both stage and receipt appends', () => {
    const startedAt = recentTime(-5_000);
    const attempt = operationAttempt('run-stale-holder', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);
    db.appendRefreshOperationStageEvent({
      run_id: attempt.run_id,
      lease_name: attempt.lease_name,
      lease_holder_id: attempt.lease_holder_id,
      stage: 'release.fetch',
      status: 'started',
      occurred_at: offsetTime(startedAt, 1_000),
    });
    assert.equal(db.releaseRefreshLease(attempt.lease_name, attempt.lease_holder_id), true);
    assert.equal(
      db.acquireRefreshLease(
        attempt.lease_name,
        'replacement-holder',
        new Date().toISOString(),
        300_000,
      ),
      true,
    );

    assert.throws(
      () => db.appendRefreshOperationStageEvent({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: attempt.lease_holder_id,
        stage: 'release.fetch',
        status: 'completed',
        occurred_at: offsetTime(startedAt, 2_000),
        duration_ms: 1_000,
      }),
      /current unexpired lease holder\/fencing identity is not active/,
    );
    assert.throws(
      () => db.appendRefreshCaptureReceipt({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: 'replacement-holder',
        status: 'failure',
        finished_at: offsetTime(startedAt, 3_000),
        duration_ms: 3_000,
        payload: { schemaVersion: 1 },
      }),
      /does not match the operation fencing identity/,
    );
    assert.equal(db.listRefreshOperationStageEvents(attempt.run_id).length, 1);
    assert.equal(db.getRefreshCaptureReceipt(attempt.run_id), null);
  });

  it('rejects zero-stage successful score-publishing refresh receipts', () => {
    for (const operation of ['refresh', 'quality-refresh']) {
      const startedAt = recentTime(-5_000);
      const attempt = {
        ...operationAttempt(`run-zero-stage-success-${operation}`, {
          trigger: 'test',
          startedAt,
        }),
        operation,
      };
      db.insertRefreshOperationAttempt(attempt);
      acquireAttemptLease(attempt);

      assert.throws(
        () => db.appendRefreshCaptureReceipt({
          run_id: attempt.run_id,
          lease_name: attempt.lease_name,
          lease_holder_id: attempt.lease_holder_id,
          status: 'success',
          finished_at: offsetTime(startedAt, 1_000),
          duration_ms: 1_000,
          payload: {
            schemaVersion: 1,
            operation,
            trigger: 'test',
          },
        }),
        /requires score\.persist then forecast\.capture/,
      );
      assert.equal(db.getRefreshCaptureReceipt(attempt.run_id), null);
    }
  });

  it('rejects success publication stages that do not bind a durable score commit', () => {
    const startedAt = recentTime(-10_000);
    const attempt = operationAttempt('run-unbound-score-commit', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);
    const historyRunId = 'history-unbound-score-commit';
    const historyRunContentHash = 'a'.repeat(64);
    for (const event of [
      {
        stage: 'score.persist',
        status: 'started' as const,
        occurred_at: offsetTime(startedAt, 1_000),
      },
      {
        stage: 'score.persist',
        status: 'completed' as const,
        occurred_at: offsetTime(startedAt, 2_000),
        duration_ms: 1_000,
        counts: { scoredReleases: 1 },
        details: { historyRunId, historyRunContentHash },
      },
      {
        stage: 'forecast.capture',
        status: 'started' as const,
        occurred_at: offsetTime(startedAt, 3_000),
      },
      {
        stage: 'forecast.capture',
        status: 'completed' as const,
        occurred_at: offsetTime(startedAt, 4_000),
        duration_ms: 1_000,
        counts: { validationForecasts: 0 },
        details: { eligibilityOutcome: 'not_eligible' },
      },
    ]) {
      db.appendRefreshOperationStageEvent({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: attempt.lease_holder_id,
        ...event,
      });
    }

    assert.throws(
      () => db.appendRefreshCaptureReceipt({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: attempt.lease_holder_id,
        status: 'success',
        finished_at: offsetTime(startedAt, 4_000),
        duration_ms: 4_000,
        payload: {
          schemaVersion: 1,
          operation: 'refresh',
          trigger: 'test',
          scoreHistory: {
            runId: historyRunId,
            contentHash: historyRunContentHash,
          },
          scoreCommit: {},
          releaseTags: ['v-test'],
          forecast: {
            eligibilityOutcome: 'not_eligible',
            decisionIds: [],
            captures: [],
          },
        },
      }),
      /does not bind the durable score commit/,
    );
    assert.equal(db.getRefreshCaptureReceipt(attempt.run_id), null);
  });

  it('accepts a complete strictly chronological success receipt', () => {
    const fixture = semanticReceiptFixture();

    assert.deepEqual(operationReceiptSemanticProblems(fixture), []);
  });

  it('requires the exact scored and predecessor artifact union in schema 3', () => {
    const valid = schema3SemanticReceiptFixture();
    assert.deepEqual(operationReceiptSemanticProblems(valid), []);

    const cases: Array<{
      name: string;
      tags: string[];
      scope?: ReturnType<typeof buildReleaseArtifactPublicationScope>;
      expected: RegExp;
    }> = [
      {
        name: 'missing scored release',
        tags: ['v-predecessor'],
        expected: /does not match its scored\/dependency scope/,
      },
      {
        name: 'missing predecessor dependency',
        tags: ['v-test'],
        expected: /does not match its scored\/dependency scope/,
      },
      {
        name: 'unrelated extra release',
        tags: ['v-test', 'v-predecessor', 'v-unrelated'],
        expected: /does not match its scored\/dependency scope/,
      },
      {
        name: 'duplicate release tag',
        tags: ['v-test', 'v-predecessor', 'v-predecessor'],
        expected: /duplicate release tags/,
      },
      {
        name: 'scored and dependency roles swapped',
        tags: ['v-test', 'v-predecessor'],
        scope: buildReleaseArtifactPublicationScope({
          scoredReleaseTags: ['v-predecessor'],
          predecessorByReleaseTag: {
            'v-predecessor': 'v-test',
          },
        }),
        expected: /does not match the durable score dependency set/,
      },
    ];
    for (const testCase of cases) {
      const fixture = schema3SemanticReceiptFixture();
      const payload = JSON.parse(fixture.receipt.payload_json);
      payload.releaseArtifacts.links = artifactLinks(testCase.tags);
      payload.releaseArtifacts.linkCount = testCase.tags.length;
      if (testCase.scope) payload.releaseArtifactScope = testCase.scope;
      fixture.receipt.payload_json = JSON.stringify(payload);
      assert.match(
        operationReceiptSemanticProblems(fixture).join('\n'),
        testCase.expected,
        testCase.name,
      );
    }
  });

  it('binds canonical artifact publications to supplied immutable ledger rows', () => {
    const valid = canonicalArtifactPublicationReceiptFixture();
    assert.deepEqual(
      operationReceiptArtifactPublicationSemanticProblems(valid),
      [],
    );
    assert.deepEqual(
      operationReceiptSemanticProblems({
        attempt: valid.attempt,
        stageEvents: valid.stageEvents,
        receipt: valid.receipt,
        artifactReceipts: valid.artifactReceipts,
        artifactObservations: valid.artifactObservations,
      }),
      [],
    );

    const fabricated = schema3SemanticReceiptFixture();
    assert.match(
      operationReceiptSemanticProblems({
        ...fabricated,
        artifactReceipts: valid.artifactReceipts,
        artifactObservations: valid.artifactObservations,
      }).join('\n'),
      /publication link 0 is invalid|missing immutable observation membership/,
    );

    const reordered = canonicalArtifactPublicationReceiptFixture();
    const reorderedPayload = JSON.parse(reordered.receipt.payload_json);
    reorderedPayload.releaseArtifacts.links.reverse();
    reordered.receipt.payload_json = JSON.stringify(reorderedPayload);
    assert.match(
      operationReceiptArtifactPublicationSemanticProblems(reordered).join('\n'),
      /links are not in canonical order/,
    );
  });

  it('makes artifact membership policy explicit and fails closed in strict mode', () => {
    const optional = verifyOperationReceiptLedger({
      attempts: [],
      stageEvents: [],
      receipts: [],
    });
    assert.equal(optional.artifactMembershipPolicy, 'if-present');
    assert.equal(optional.artifactReceiptCount, null);
    assert.equal(optional.artifactObservationCount, null);
    assert.deepEqual(optional.problems, []);

    const omitted = verifyOperationReceiptLedger({
      attempts: [],
      stageEvents: [],
      receipts: [],
      artifactMembershipPolicy: 'strict',
    });
    assert.equal(omitted.artifactMembershipPolicy, 'strict');
    assert.match(
      omitted.problems.join('\n'),
      /strict artifact membership verification requires both complete receipt and observation ledgers/,
    );

    const empty = verifyOperationReceiptLedger({
      attempts: [],
      stageEvents: [],
      receipts: [],
      artifactReceipts: [],
      artifactObservations: [],
      artifactMembershipPolicy: 'strict',
    });
    assert.equal(empty.artifactReceiptCount, 0);
    assert.equal(empty.artifactObservationCount, 0);
    assert.deepEqual(empty.problems, []);

    const valid = canonicalArtifactPublicationReceiptFixture();
    assert.match(
      operationReceiptSemanticProblems({
        attempt: valid.attempt,
        stageEvents: valid.stageEvents,
        receipt: valid.receipt,
        artifactMembershipPolicy: 'strict',
      }).join('\n'),
      /strict artifact membership verification requires both complete receipt and observation ledgers/,
    );
    assert.match(
      operationReceiptSemanticProblems({
        attempt: valid.attempt,
        stageEvents: valid.stageEvents,
        receipt: valid.receipt,
        artifactReceipts: valid.artifactReceipts,
        artifactMembershipPolicy: 'strict',
      }).join('\n'),
      /strict artifact membership verification requires both complete receipt and observation ledgers/,
    );
    assert.deepEqual(
      operationReceiptSemanticProblems({
        attempt: valid.attempt,
        stageEvents: valid.stageEvents,
        receipt: valid.receipt,
        artifactReceipts: valid.artifactReceipts,
        artifactObservations: valid.artifactObservations,
        artifactMembershipPolicy: 'strict',
      }),
      [],
    );

    const missing = canonicalArtifactPublicationReceiptFixture();
    missing.artifactObservations.shift();
    assert.match(
      operationReceiptSemanticProblems({
        attempt: missing.attempt,
        stageEvents: missing.stageEvents,
        receipt: missing.receipt,
        artifactReceipts: missing.artifactReceipts,
        artifactObservations: missing.artifactObservations,
        artifactMembershipPolicy: 'strict',
      }).join('\n'),
      /extra immutable observation membership|has no supplied immutable observation/,
    );

    const substituted = canonicalArtifactPublicationReceiptFixture();
    const substitutedPayload = JSON.parse(substituted.receipt.payload_json);
    substitutedPayload.releaseArtifacts.links[0].receiptContentHash =
      'f'.repeat(64);
    substitutedPayload.releaseArtifacts = buildReleaseArtifactPublication(
      substitutedPayload.releaseArtifacts.links,
    );
    substituted.receipt.payload_json = JSON.stringify(substitutedPayload);
    assert.match(
      operationReceiptSemanticProblems({
        attempt: substituted.attempt,
        stageEvents: substituted.stageEvents,
        receipt: substituted.receipt,
        artifactReceipts: substituted.artifactReceipts,
        artifactObservations: substituted.artifactObservations,
        artifactMembershipPolicy: 'strict',
      }).join('\n'),
      /is substituted: receipt content hash/,
    );
  });

  it('rejects malformed artifact IDs, stored hash drift, digest drift, and duplicates', () => {
    const cases: Array<{
      name: string;
      mutate: (
        fixture: ReturnType<typeof canonicalArtifactPublicationReceiptFixture>,
      ) => void;
      expected: RegExp;
    }> = [
      {
        name: 'malformed observation ID',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts.links[0].observationId =
            'artifact-observation-v1:not-a-digest';
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /observation ID is malformed/,
      },
      {
        name: 'wrong stored observation hash',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts.links[0].observationContentHash =
            'f'.repeat(64);
          payload.releaseArtifacts = buildReleaseArtifactPublication(
            payload.releaseArtifacts.links,
          );
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /observation content hash.*do not match immutable ledger rows/,
      },
      {
        name: 'wrong stored receipt hash',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts.links[0].receiptContentHash =
            'e'.repeat(64);
          payload.releaseArtifacts = buildReleaseArtifactPublication(
            payload.releaseArtifacts.links,
          );
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /receipt content hash.*do not match immutable ledger rows/,
      },
      {
        name: 'receipt ID detached from evidence identity',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts.links[0].evidenceIdentity = 'd'.repeat(64);
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /receipt ID does not match evidence identity/,
      },
      {
        name: 'wrong publication digest',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts.contentDigest = 'f'.repeat(64);
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /digest does not match canonical links/,
      },
    ];
    for (const testCase of cases) {
      const fixture = canonicalArtifactPublicationReceiptFixture();
      testCase.mutate(fixture);
      assert.match(
        operationReceiptArtifactPublicationSemanticProblems(fixture).join('\n'),
        testCase.expected,
        testCase.name,
      );
    }

    const duplicate = canonicalArtifactPublicationReceiptFixture();
    const duplicatePayload = JSON.parse(duplicate.receipt.payload_json);
    duplicatePayload.releaseArtifacts.links = [
      duplicatePayload.releaseArtifacts.links[0],
      duplicatePayload.releaseArtifacts.links[0],
    ];
    duplicatePayload.releaseArtifacts.linkCount = 2;
    duplicate.receipt.payload_json = JSON.stringify(duplicatePayload);
    const duplicateProblems =
      operationReceiptArtifactPublicationSemanticProblems(duplicate).join('\n');
    assert.match(duplicateProblems, /duplicate observation IDs/);
    assert.match(duplicateProblems, /duplicate receipt IDs/);
    assert.match(duplicateProblems, /duplicate release tags/);

    const duplicateLedger = canonicalArtifactPublicationReceiptFixture();
    duplicateLedger.artifactReceipts.push({
      ...duplicateLedger.artifactReceipts[0],
    });
    duplicateLedger.artifactObservations.push({
      ...duplicateLedger.artifactObservations[0],
    });
    const duplicateLedgerProblems =
      operationReceiptArtifactPublicationSemanticProblems(duplicateLedger)
        .join('\n');
    assert.match(
      duplicateLedgerProblems,
      /supplied artifact receipt ledger has duplicate receipt ID/,
    );
    assert.match(
      duplicateLedgerProblems,
      /supplied artifact observation ledger has duplicate observation ID/,
    );
  });

  it('rejects cross-run, substituted, missing, and extra artifact membership', () => {
    const cases: Array<{
      name: string;
      mutate: (
        fixture: ReturnType<typeof canonicalArtifactPublicationReceiptFixture>,
      ) => void;
      expected: RegExp;
    }> = [
      {
        name: 'cross-run observation',
        mutate: (fixture) => {
          fixture.artifactObservations[0].runId = 'run-other-artifact-publication';
        },
        expected: /belongs to run "run-other-artifact-publication", not/,
      },
      {
        name: 'substituted release identity',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts.links[0].release.releaseNodeId += '-substituted';
          payload.releaseArtifacts = buildReleaseArtifactPublication(
            payload.releaseArtifacts.links,
          );
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /is substituted: release identity/,
      },
      {
        name: 'missing observation membership',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts = buildReleaseArtifactPublication(
            payload.releaseArtifacts.links.slice(1),
          );
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /missing immutable observation membership/,
      },
      {
        name: 'extra observation membership',
        mutate: (fixture) => {
          const payload = JSON.parse(fixture.receipt.payload_json);
          payload.releaseArtifacts = buildReleaseArtifactPublication([
            ...payload.releaseArtifacts.links,
            extraArtifactPublicationLink(),
          ]);
          fixture.receipt.payload_json = JSON.stringify(payload);
        },
        expected: /extra immutable observation membership/,
      },
    ];
    for (const testCase of cases) {
      const fixture = canonicalArtifactPublicationReceiptFixture();
      testCase.mutate(fixture);
      assert.match(
        operationReceiptArtifactPublicationSemanticProblems(fixture).join('\n'),
        testCase.expected,
        testCase.name,
      );
    }
  });

  it('applies complete success semantics to quality refreshes', () => {
    const complete = semanticReceiptFixture();
    complete.attempt.operation = 'quality-refresh';
    const completePayload = JSON.parse(complete.receipt.payload_json);
    completePayload.operation = 'quality-refresh';
    complete.receipt.payload_json = JSON.stringify(completePayload);
    assert.deepEqual(operationReceiptSemanticProblems(complete), []);

    const malformed = semanticReceiptFixture();
    malformed.attempt.operation = 'quality-refresh';
    malformed.stageEvents.length = 0;
    malformed.receipt.stage_event_count = 0;
    const malformedPayload = JSON.parse(malformed.receipt.payload_json);
    malformedPayload.operation = 'quality-refresh';
    malformed.receipt.payload_json = JSON.stringify(malformedPayload);
    assert.match(
      operationReceiptSemanticProblems(malformed).join('\n'),
      /requires score\.persist then forecast\.capture/,
    );
  });

  it('rejects adversarial stage chronology and terminal inconsistencies', () => {
    const cases: Array<{
      name: string;
      mutate: (fixture: ReturnType<typeof semanticReceiptFixture>) => void;
      expected: RegExp;
    }> = [
      {
        name: 'sequence gap',
        mutate: (fixture) => {
          fixture.stageEvents[2].sequence = 5;
        },
        expected: /chronology is incomplete/,
      },
      {
        name: 'timestamp regression',
        mutate: (fixture) => {
          fixture.stageEvents[2].occurred_at = offsetTime(
            fixture.attempt.started_at,
            1_500,
          );
        },
        expected: /timestamps are not nondecreasing/,
      },
      {
        name: 'duration mismatch',
        mutate: (fixture) => {
          fixture.stageEvents[1].duration_ms = 999;
        },
        expected: /duration does not match its started\/completed timestamps/,
      },
      {
        name: 'inactive completion',
        mutate: (fixture) => {
          fixture.stageEvents[1].stage = 'score.other';
        },
        expected: /closes inactive stage/,
      },
      {
        name: 'failed stage before success',
        mutate: (fixture) => {
          prependClosedStage(fixture, 'release.fetch', 'failed');
        },
        expected: /cannot succeed after a failed terminal stage/,
      },
      {
        name: 'interleaved required publication stages',
        mutate: (fixture) => {
          const startedAt = fixture.attempt.started_at;
          fixture.stageEvents.splice(
            2,
            0,
            semanticStage(fixture.attempt.run_id, 3, 'publication.audit', 'started',
              offsetTime(startedAt, 2_250), null),
            semanticStage(fixture.attempt.run_id, 4, 'publication.audit', 'completed',
              offsetTime(startedAt, 2_500), 250),
          );
          resequenceSemanticStages(fixture.stageEvents);
        },
        expected: /requires score\.persist then forecast\.capture/,
      },
      {
        name: 'receipt duration mismatch',
        mutate: (fixture) => {
          fixture.receipt.duration_ms++;
        },
        expected: /duration does not match its attempt timestamps/,
      },
    ];

    for (const testCase of cases) {
      const fixture = semanticReceiptFixture();
      testCase.mutate(fixture);
      assert.match(
        operationReceiptSemanticProblems(fixture).join('\n'),
        testCase.expected,
        testCase.name,
      );
    }
  });

  it('rejects duplicate, out-of-order, and post-failure stage prefixes', () => {
    const cases: Array<{
      name: string;
      stages: ReturnType<typeof semanticStage>[];
      expected: RegExp;
    }> = [
      {
        name: 'duplicate sequence',
        stages: [
          semanticStage('run-prefix', 1, 'release.fetch', 'started',
            '2026-07-04T12:00:01.000Z', null),
          semanticStage('run-prefix', 1, 'release.fetch', 'completed',
            '2026-07-04T12:00:02.000Z', 1_000),
        ],
        expected: /chronology is incomplete/,
      },
      {
        name: 'out-of-order rows',
        stages: [
          semanticStage('run-prefix', 2, 'release.fetch', 'completed',
            '2026-07-04T12:00:02.000Z', 1_000),
          semanticStage('run-prefix', 1, 'release.fetch', 'started',
            '2026-07-04T12:00:01.000Z', null),
        ],
        expected: /chronology is incomplete|closes inactive stage/,
      },
      {
        name: 'stage after failure',
        stages: [
          semanticStage('run-prefix', 1, 'release.fetch', 'started',
            '2026-07-04T12:00:01.000Z', null),
          semanticStage('run-prefix', 2, 'release.fetch', 'failed',
            '2026-07-04T12:00:02.000Z', 1_000),
          semanticStage('run-prefix', 3, 'forecast.capture', 'started',
            '2026-07-04T12:00:03.000Z', null),
        ],
        expected: /after a failed terminal stage/,
      },
    ];
    const attempt = semanticReceiptFixture().attempt;
    attempt.run_id = 'run-prefix';
    for (const testCase of cases) {
      assert.match(
        operationReceiptStagePrefixSemanticProblems({
          attempt,
          stageEvents: testCase.stages,
        }).join('\n'),
        testCase.expected,
        testCase.name,
      );
    }
  });

  it('rejects globally regressing stage time before inserting the stage', () => {
    const startedAt = recentTime(-10_000);
    const attempt = operationAttempt('run-regressing-stage-time', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);
    for (const event of [
      {
        stage: 'release.fetch',
        status: 'started' as const,
        occurred_at: offsetTime(startedAt, 500),
      },
      {
        stage: 'release.fetch',
        status: 'completed' as const,
        occurred_at: offsetTime(startedAt, 2_500),
        duration_ms: 2_000,
      },
    ]) {
      db.appendRefreshOperationStageEvent({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: attempt.lease_holder_id,
        ...event,
      });
    }
    const durablePrefix = db.listRefreshOperationStageEvents(attempt.run_id);

    assert.throws(
      () => db.appendRefreshOperationStageEvent({
        run_id: attempt.run_id,
        lease_name: attempt.lease_name,
        lease_holder_id: attempt.lease_holder_id,
        stage: 'score.persist',
        status: 'started' as const,
        occurred_at: offsetTime(startedAt, 2_000),
      }),
      /stage prefix semantic validation failed.*stage timestamps are not nondecreasing/,
    );
    assert.deepEqual(
      db.listRefreshOperationStageEvents(attempt.run_id),
      durablePrefix,
    );
    assert.equal(db.getRefreshCaptureReceipt(attempt.run_id), null);
  });

  it('accepts unterminated attempts only while their matching lease is active', () => {
    const startedAt = recentTime(-5_000);
    const attempt = operationAttempt('run-active-unterminated', {
      trigger: 'test',
      startedAt,
    });
    db.insertRefreshOperationAttempt(attempt);
    acquireAttemptLease(attempt);
    const observedAt = new Date().toISOString();

    const active = verifyOperationReceiptLedger({
      attempts: [db.getRefreshOperationAttempt(attempt.run_id)!],
      stageEvents: [],
      receipts: [],
      leases: db.listRefreshLeases().filter((lease) => lease.name === attempt.lease_name),
      observedAt,
    });
    assert.deepEqual(active.activeUnterminatedRunIds, [attempt.run_id]);
    assert.deepEqual(active.invalidUnterminatedRunIds, []);
    assert.deepEqual(active.problems, []);

    assert.equal(db.releaseRefreshLease(attempt.lease_name, attempt.lease_holder_id), true);
    const expired = verifyOperationReceiptLedger({
      attempts: [db.getRefreshOperationAttempt(attempt.run_id)!],
      stageEvents: [],
      receipts: [],
      leases: [],
      observedAt: new Date().toISOString(),
    });
    assert.deepEqual(expired.activeUnterminatedRunIds, []);
    assert.deepEqual(expired.invalidUnterminatedRunIds, [attempt.run_id]);
    assert.ok(expired.semanticProblems.some((problem) =>
      /not backed by its active matching lease/.test(problem)));
  });

  it('separates hash-chain verification from dangling semantic links', () => {
    const verification = verifyOperationReceiptSemanticLinks({
      attempts: [{
        ...operationAttempt('run-dangling-links', {
          trigger: 'test',
          startedAt: recentTime(-5_000),
        }),
        effective_config_json: '{}',
        effective_config_hash: 'a'.repeat(64),
        content_hash: 'b'.repeat(64),
      } as any],
      receipts: [{
        receipt_id: 'receipt-dangling-links',
        run_id: 'run-dangling-links',
        status: 'success',
        finished_at: recentTime(-1_000),
        duration_ms: 4_000,
        stage_event_count: 4,
        stage_chain_hash: 'c'.repeat(64),
        payload_json: JSON.stringify({
          scoreHistory: {
            runId: 'missing-history-run',
            contentHash: 'd'.repeat(64),
          },
          forecast: {
            eligibilityOutcome: 'eligible_and_captured',
            decisionIds: ['missing-forecast'],
            captures: [{ decisionId: 'missing-forecast' }],
          },
        }),
        previous_content_hash: null,
        content_hash: 'e'.repeat(64),
      }],
      historyRows: [],
      historyRuns: [],
      forecasts: [],
      authorityRuns: [],
      historyV2Seals: [],
    });

    assert.ok(verification.problems.some((problem) => /dangling score history link/.test(problem)));
    assert.ok(verification.problems.some((problem) => /dangling forecast link/.test(problem)));
    assert.ok(verification.problems.some((problem) =>
      /score authority link does not match durable authority evidence/.test(problem)));
  });

  it('accepts semantically equivalent already-captured forecasts linked to original seals', () => {
    const fixture = semanticLinkFixture();

    assert.deepEqual(verifyOperationReceiptSemanticLinks(fixture).problems, []);
  });

  it('verifies canonical forecast IDs, hashes, and immutable proof links', () => {
    const fixture = canonicalSemanticLinkFixture();
    const verification = verifyReleaseValidationProofBundle(
      fixture.validationProof,
    );
    assert.equal(verification.valid, true, verification.problems.join('; '));

    const payload = JSON.parse(fixture.receipts[0].payload_json);
    assert.deepEqual(payload.forecast.canonicalForecastIds, [
      fixture.canonicalForecast.forecastId,
    ]);
    assert.deepEqual(payload.forecast.canonicalForecastContentHashes, [
      fixture.canonicalForecast.contentHash,
    ]);
    assert.deepEqual(
      verifyOperationReceiptSemanticLinks(fixture).problems,
      [],
    );
  });

  it('rejects omitted and tampered schema-v2 canonical forecast proof links', () => {
    const omitted = canonicalSemanticLinkFixture();
    const omittedPayload = JSON.parse(omitted.receipts[0].payload_json);
    for (const field of [
      'canonicalForecastIds',
      'canonicalForecastContentHashes',
      'newCanonicalForecastIds',
      'existingCanonicalForecastIds',
      'canonicalCaptures',
    ]) {
      delete omittedPayload.forecast[field];
    }
    omitted.receipts[0].payload_json = JSON.stringify(omittedPayload);
    assert.match(
      verifyOperationReceiptSemanticLinks(omitted).problems.join('\n'),
      /schema-v2 forecast output omits canonical forecast proof links/,
    );

    const tamperedHash = canonicalSemanticLinkFixture();
    const tamperedHashPayload = JSON.parse(
      tamperedHash.receipts[0].payload_json,
    );
    tamperedHashPayload.forecast.canonicalForecastContentHashes[0] =
      'f'.repeat(64);
    tamperedHash.receipts[0].payload_json =
      JSON.stringify(tamperedHashPayload);
    assert.match(
      verifyOperationReceiptSemanticLinks(tamperedHash).problems.join('\n'),
      /canonical forecast links do not match canonical captures/,
    );

    const tamperedObligation = canonicalSemanticLinkFixture();
    const tamperedObligationPayload = JSON.parse(
      tamperedObligation.receipts[0].payload_json,
    );
    tamperedObligationPayload.forecast.canonicalCaptures[0].obligationId =
      'e'.repeat(64);
    tamperedObligation.receipts[0].payload_json =
      JSON.stringify(tamperedObligationPayload);
    assert.match(
      verifyOperationReceiptSemanticLinks(tamperedObligation).problems.join('\n'),
      /mismatched immutable proof link/,
    );
  });

  it('keeps schema-v1 receipts valid after their forecast gains canonical proof rows', () => {
    const fixture = canonicalSemanticLinkFixture();
    const payload = JSON.parse(fixture.receipts[0].payload_json);
    payload.schemaVersion = 1;
    for (const field of [
      'canonicalForecastIds',
      'canonicalForecastContentHashes',
      'newCanonicalForecastIds',
      'existingCanonicalForecastIds',
      'canonicalCaptures',
    ]) {
      delete payload.forecast[field];
    }
    fixture.receipts[0].payload_json = JSON.stringify(payload);

    assert.deepEqual(verifyOperationReceiptSemanticLinks(fixture).problems, []);
  });

  it('verifies quality-refresh semantic links instead of skipping them', () => {
    const fixture = semanticLinkFixture();
    fixture.attempts[0].operation = 'quality-refresh';
    const payload = JSON.parse(fixture.receipts[0].payload_json);
    payload.operation = 'quality-refresh';
    fixture.receipts[0].payload_json = JSON.stringify(payload);
    fixture.historyRuns = [];

    assert.match(
      verifyOperationReceiptSemanticLinks(fixture).problems.join('\n'),
      /dangling score history link/,
    );
  });

  it('accepts an already-captured forecast from the retry history run itself', () => {
    const fixture = semanticLinkFixture();
    const currentHistory = fixture.historyRows.find(
      (row) => row.run_id === 'history-current',
    )!;
    const forecast = semanticForecast(currentHistory);
    fixture.forecasts = [forecast];
    const payload = JSON.parse(fixture.receipts[0].payload_json);
    payload.forecast.decisionIds = [forecast.decision_id];
    payload.forecast.newDecisionIds = [];
    payload.forecast.existingDecisionIds = [forecast.decision_id];
    payload.forecast.captures = [{
      decisionId: forecast.decision_id,
      status: 'already_captured',
    }];
    fixture.receipts[0].payload_json = JSON.stringify(payload);

    assert.deepEqual(verifyOperationReceiptSemanticLinks(fixture).problems, []);
  });

  it('rejects reused forecasts without their original seal or explicit reuse status', () => {
    const missingSeal = semanticLinkFixture();
    missingSeal.historyRuns = missingSeal.historyRuns.filter(
      (run) => run.run_id !== 'history-original',
    );
    assert.match(
      verifyOperationReceiptSemanticLinks(missingSeal).problems.join('\n'),
      /original sealed score run/,
    );

    const falseReuse = semanticLinkFixture();
    const payload = JSON.parse(falseReuse.receipts[0].payload_json);
    payload.forecast.eligibilityOutcome = 'eligible_and_captured';
    payload.forecast.newDecisionIds = ['decision-reused'];
    payload.forecast.existingDecisionIds = [];
    payload.forecast.captures[0].status = 'inserted';
    falseReuse.receipts[0].payload_json = JSON.stringify(payload);
    assert.match(
      verifyOperationReceiptSemanticLinks(falseReuse).problems.join('\n'),
      /targets a different score run/,
    );
  });

  it('rejects conflicting seals, malformed forecasts, tampered history, cross-run aliases, and invalid chronology', () => {
    const conflictingSeals = semanticLinkFixture();
    conflictingSeals.historyRuns.push({
      ...conflictingSeals.historyRuns.find(
        (run) => run.run_id === 'history-original',
      )!,
      id: 3,
    });
    assert.match(
      verifyOperationReceiptSemanticLinks(conflictingSeals).problems.join('\n'),
      /conflicting .*seals/,
    );

    const malformedForecast = semanticLinkFixture();
    malformedForecast.forecasts[0].candidate_scores_json = '{';
    rekeySemanticForecast(malformedForecast);
    assert.match(
      verifyOperationReceiptSemanticLinks(malformedForecast).problems.join('\n'),
      /malformed decision or candidate snapshots/,
    );

    const tamperedHistory = semanticLinkFixture();
    tamperedHistory.historyRows
      .find((row) => row.run_id === 'history-original')!.final_score = 1;
    assert.match(
      verifyOperationReceiptSemanticLinks(tamperedHistory).problems.join('\n'),
      /row-set hash does not match|candidate .* does not match score audit history/,
    );

    const crossRunAlias = semanticLinkFixture();
    const forecast = crossRunAlias.forecasts[0];
    const candidates = JSON.parse(forecast.candidate_scores_json);
    candidates[0].auditSnapshot.run_id = 'history-current';
    forecast.candidate_scores_json = JSON.stringify(candidates);
    rekeySemanticForecast(crossRunAlias);
    assert.match(
      verifyOperationReceiptSemanticLinks(crossRunAlias).problems.join('\n'),
      /candidate .* does not match score audit history/,
    );

    const invalidChronology = semanticLinkFixture();
    const originalSeal = invalidChronology.historyRuns.find(
      (run) => run.run_id === 'history-original',
    )!;
    originalSeal.recorded_at = '2026-07-04T12:00:03.000Z';
    originalSeal.content_hash = releaseScoreAuditHistoryRunContentHash({
      runId: originalSeal.run_id,
      recordedAt: originalSeal.recorded_at,
      rowCount: originalSeal.row_count,
      rowsContentHash: originalSeal.rows_content_hash,
      previousContentHash: originalSeal.previous_content_hash,
    });
    assert.match(
      verifyOperationReceiptSemanticLinks(invalidChronology).problems.join('\n'),
      /chronologically invalid|not an earlier capture/,
    );
  });
});

function operationAttempt(
  runId: string,
  overrides: {
    trigger: string;
    startedAt: string;
    leaseName?: string;
    leaseHolderId?: string;
    leaseExpiresAt?: string;
  },
) {
  return {
    run_id: runId,
    operation: 'refresh',
    trigger: overrides.trigger,
    started_at: overrides.startedAt,
    lease_name: overrides.leaseName ?? `github-refresh-${runId}`,
    lease_holder_id: overrides.leaseHolderId ?? `holder-${runId}`,
    lease_expires_at: overrides.leaseExpiresAt ??
      new Date(Date.parse(overrides.startedAt) + 300_000).toISOString(),
    code_revision: 'git:0123456789abcdef0123456789abcdef01234567',
    effective_config: {
      schemaVersion: 1,
      github: {
        owner: 'openclaw',
        repo: 'openclaw',
      },
      openai: {
        model: 'gpt-test',
      },
    },
  };
}

function recentTime(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function offsetTime(value: string, offsetMs: number): string {
  return new Date(Date.parse(value) + offsetMs).toISOString();
}

function acquireAttemptLease(attempt: ReturnType<typeof operationAttempt>): void {
  assert.equal(
    db.acquireRefreshLease(
      attempt.lease_name,
      attempt.lease_holder_id,
      new Date().toISOString(),
      300_000,
    ),
    true,
  );
}

function semanticReceiptFixture() {
  const startedAt = '2026-07-04T12:00:00.000Z';
  const runId = 'run-semantic-fixture';
  const historyRunId = 'history-semantic-fixture';
  const historyRunContentHash = 'a'.repeat(64);
  const authorityRunId = 'authority-semantic-fixture';
  const authorityRunContentHash = 'e'.repeat(64);
  const historyV2SealContentHash = 'f'.repeat(64);
  const commitNotBefore = offsetTime(startedAt, 1_500);
  const commitNotAfter = offsetTime(startedAt, 2_000);
  const attempt = {
    run_id: runId,
    operation: 'refresh',
    trigger: 'test',
    started_at: startedAt,
    lease_name: 'semantic-fixture-lease',
    lease_holder_id: 'semantic-fixture-holder',
    lease_expires_at: offsetTime(startedAt, 300_000),
    code_revision: 'git:0123456789abcdef0123456789abcdef01234567',
    effective_config_json: '{}',
    effective_config_hash: 'b'.repeat(64),
    content_hash: 'c'.repeat(64),
  };
  const stageEvents = [
    semanticStage(runId, 1, 'score.persist', 'started', offsetTime(startedAt, 1_000), null),
    semanticStage(
      runId,
      2,
      'score.persist',
      'completed',
      offsetTime(startedAt, 2_000),
      1_000,
      { scoredReleases: 1 },
      {
        historyRunId,
        historyRunContentHash,
        authorityRunId,
        authorityRunContentHash,
        historyV2SealContentHash,
        commitNotBefore,
        commitNotAfter,
      },
    ),
    semanticStage(
      runId,
      3,
      'forecast.capture',
      'started',
      offsetTime(startedAt, 3_000),
      null,
    ),
    semanticStage(
      runId,
      4,
      'forecast.capture',
      'completed',
      offsetTime(startedAt, 4_000),
      1_000,
      { validationForecasts: 0 },
      { eligibilityOutcome: 'not_eligible' },
    ),
  ];
  const receipt = {
    receipt_id: 'receipt-semantic-fixture',
    run_id: runId,
    status: 'success' as const,
    finished_at: offsetTime(startedAt, 4_000),
    duration_ms: 4_000,
    stage_event_count: stageEvents.length,
    stage_chain_hash: stageEvents.at(-1)!.content_hash,
    payload_json: JSON.stringify(successReceiptPayload({
      trigger: 'test',
      historyRunId,
      historyRunContentHash,
      authorityRunId,
      authorityRunContentHash,
      historyV2SealContentHash,
      commitNotBefore,
      commitNotAfter,
    })),
    previous_content_hash: null,
    content_hash: 'd'.repeat(64),
  };
  return { attempt, stageEvents, receipt };
}

function schema3SemanticReceiptFixture() {
  const fixture = semanticReceiptFixture();
  const payload = JSON.parse(fixture.receipt.payload_json);
  payload.schemaVersion = 3;
  payload.scoreMetadata = {
    releaseTags: ['v-test'],
    predecessorByReleaseTag: {
      'v-test': 'v-predecessor',
    },
  };
  payload.releaseArtifactScope = buildReleaseArtifactPublicationScope({
    scoredReleaseTags: ['v-test'],
    predecessorByReleaseTag: {
      'v-test': 'v-predecessor',
    },
  });
  payload.releaseArtifacts = {
    schemaVersion: 1,
    linkCount: 2,
    links: artifactLinks(['v-test', 'v-predecessor']),
    contentDigest: 'a'.repeat(64),
  };
  fixture.receipt.payload_json = JSON.stringify(payload);
  return fixture;
}

function artifactLinks(tags: string[]) {
  return tags.map((tag, index) => ({
    release: {
      repository: 'openclaw/openclaw',
      tag,
      releaseNodeId: `RE_${index}`,
      catalogTagCommitOid: `${index + 1}`.repeat(40),
      publishedAt: `2026-07-0${index + 1}T00:00:00.000Z`,
    },
  }));
}

function canonicalArtifactPublicationReceiptFixture() {
  const fixture = schema3SemanticReceiptFixture();
  const releases = artifactLinks(['v-test', 'v-predecessor'])
    .map((link) => link.release);
  const artifactReceipts = releases.map((release, index) => {
    const evidenceIdentity = `${index + 1}`.repeat(64);
    return {
      receiptId: `artifact-receipt-v2:${evidenceIdentity}`,
      release,
      evidenceIdentity,
      evidenceReportIdentity:
        `release-evidence-v1:sha256:${`${index + 5}`.repeat(64)}`,
      contentHash: `${index + 3}`.repeat(64),
    };
  });
  const artifactObservations = artifactReceipts.map((receipt, index) => ({
    observationId:
      `artifact-observation-v1:${`${index + 7}`.repeat(64)}`,
    runId: fixture.receipt.run_id,
    release: receipt.release,
    receiptId: receipt.receiptId,
    receiptContentHash: receipt.contentHash,
    contentHash: (index === 0 ? '9' : 'a').repeat(64),
  }));
  const publication = buildReleaseArtifactPublication(
    artifactObservations.map((observation, index) => ({
      release: observation.release,
      observationId: observation.observationId,
      observationContentHash: observation.contentHash,
      receiptId: artifactReceipts[index].receiptId,
      receiptContentHash: artifactReceipts[index].contentHash,
      evidenceIdentity: artifactReceipts[index].evidenceIdentity,
      evidenceReportIdentity: artifactReceipts[index].evidenceReportIdentity,
    })),
  );
  const payload = JSON.parse(fixture.receipt.payload_json);
  payload.releaseArtifacts = publication;
  fixture.receipt.payload_json = JSON.stringify(payload);
  return {
    ...fixture,
    artifactReceipts,
    artifactObservations,
  };
}

function extraArtifactPublicationLink() {
  const evidenceIdentity = 'b'.repeat(64);
  return {
    release: {
      repository: 'openclaw/openclaw',
      tag: 'v-extra',
      releaseNodeId: 'RE_extra',
      catalogTagCommitOid: 'f'.repeat(40),
      publishedAt: '2026-07-03T00:00:00.000Z',
    },
    observationId: `artifact-observation-v1:${'c'.repeat(64)}`,
    observationContentHash: 'd'.repeat(64),
    receiptId: `artifact-receipt-v2:${evidenceIdentity}`,
    receiptContentHash: 'e'.repeat(64),
    evidenceIdentity,
    evidenceReportIdentity:
      `release-evidence-v1:sha256:${'f'.repeat(64)}`,
  };
}

function semanticStage(
  runId: string,
  sequence: number,
  stage: string,
  status: 'started' | 'completed' | 'failed',
  occurredAt: string,
  durationMs: number | null,
  counts: Record<string, unknown> | null = null,
  details: Record<string, unknown> | null = null,
) {
  return {
    event_id: `event-${sequence}-${stage}-${status}`,
    run_id: runId,
    sequence,
    stage,
    status,
    occurred_at: occurredAt,
    duration_ms: durationMs,
    counts_json: counts == null ? null : JSON.stringify(counts),
    details_json: details == null ? null : JSON.stringify(details),
    previous_content_hash: sequence === 1 ? null : `hash-${sequence - 1}`,
    content_hash: `hash-${sequence}`,
  };
}

function prependClosedStage(
  fixture: ReturnType<typeof semanticReceiptFixture>,
  stage: string,
  terminalStatus: 'completed' | 'failed',
): void {
  const startedAt = fixture.attempt.started_at;
  fixture.stageEvents.unshift(
    semanticStage(
      fixture.attempt.run_id,
      1,
      stage,
      'started',
      offsetTime(startedAt, 100),
      null,
    ),
    semanticStage(
      fixture.attempt.run_id,
      2,
      stage,
      terminalStatus,
      offsetTime(startedAt, 200),
      100,
    ),
  );
  resequenceSemanticStages(fixture.stageEvents);
  fixture.receipt.stage_event_count = fixture.stageEvents.length;
}

function resequenceSemanticStages(
  stages: ReturnType<typeof semanticStage>[],
): void {
  for (const [index, stage] of stages.entries()) stage.sequence = index + 1;
}

function successReceiptPayload(input: {
  trigger: string;
  historyRunId: string;
  historyRunContentHash: string;
  authorityRunId: string;
  authorityRunContentHash: string;
  historyV2SealContentHash: string;
  commitNotBefore: string;
  commitNotAfter: string;
}) {
  return {
    schemaVersion: 1,
    operation: 'refresh',
    trigger: input.trigger,
    scoreHistory: {
      runId: input.historyRunId,
      contentHash: input.historyRunContentHash,
    },
    scoreAuthority: {
      runId: input.authorityRunId,
      contentHash: input.authorityRunContentHash,
      historyV2SealContentHash: input.historyV2SealContentHash,
    },
    scoreCommit: {
      historyRunId: input.historyRunId,
      historyRunContentHash: input.historyRunContentHash,
      authorityRunId: input.authorityRunId,
      authorityRunContentHash: input.authorityRunContentHash,
      historyV2SealContentHash: input.historyV2SealContentHash,
      commitNotBefore: input.commitNotBefore,
      commitNotAfter: input.commitNotAfter,
    },
    releaseTags: ['v-test'],
    forecast: {
      eligibilityOutcome: 'not_eligible',
      decisionIds: [],
      newDecisionIds: [],
      existingDecisionIds: [],
      captures: [],
    },
  };
}

function semanticLinkFixture() {
  const originalRecordedAt = '2026-07-04T11:00:00.000Z';
  const currentRecordedAt = '2026-07-04T12:00:02.000Z';
  const sourceIdentityDigest = '1'.repeat(64);
  const originalAuthority = buildScoreAuthorityResolutionRun({
    authorityRunId: 'authority-original',
    sourceIdentitySchemaVersion: 1,
    sourceIdentityDigest,
    recordedAt: originalRecordedAt,
    previousContentHash: null,
    rows: [],
  });
  const currentAuthority = buildScoreAuthorityResolutionRun({
    authorityRunId: 'authority-current',
    sourceIdentitySchemaVersion: 1,
    sourceIdentityDigest,
    recordedAt: currentRecordedAt,
    previousContentHash: originalAuthority.contentHash,
    rows: [],
  });
  const originalHistory = semanticHistoryRow(
    'history-original',
    originalRecordedAt,
    originalAuthority.authorityRunId,
    sourceIdentityDigest,
  );
  const currentHistory = semanticHistoryRow(
    'history-current',
    currentRecordedAt,
    currentAuthority.authorityRunId,
    sourceIdentityDigest,
  );
  const originalSeal = semanticHistorySeal(1, [originalHistory], null);
  const currentSeal = semanticHistorySeal(2, [currentHistory], originalSeal.content_hash);
  const originalHistoryV2Seal = {
    id: 1,
    ...buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: originalSeal.run_id,
      authorityRunId: originalAuthority.authorityRunId,
      sealedAt: originalRecordedAt,
      historyRowCount: originalSeal.row_count,
      historyRowsContentHash: originalSeal.rows_content_hash,
      authorityRowCount: originalAuthority.rowCount,
      authorityRowsContentHash: originalAuthority.rowsContentHash,
      previousContentHash: null,
    }),
  };
  const currentHistoryV2Seal = {
    id: 2,
    ...buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: currentSeal.run_id,
      authorityRunId: currentAuthority.authorityRunId,
      sealedAt: currentRecordedAt,
      historyRowCount: currentSeal.row_count,
      historyRowsContentHash: currentSeal.rows_content_hash,
      authorityRowCount: currentAuthority.rowCount,
      authorityRowsContentHash: currentAuthority.rowsContentHash,
      previousContentHash: originalHistoryV2Seal.contentHash,
    }),
  };
  const base = semanticReceiptFixture();
  const attempt = base.attempt;
  const forecast = semanticForecast(originalHistory);
  const receipt = {
    ...base.receipt,
    payload_json: JSON.stringify({
      schemaVersion: 1,
      operation: 'refresh',
      trigger: 'test',
      scoreHistory: {
        runId: 'history-current',
        contentHash: currentSeal.content_hash,
      },
      scoreAuthority: {
        runId: currentAuthority.authorityRunId,
        contentHash: currentAuthority.contentHash,
        historyV2SealContentHash: currentHistoryV2Seal.contentHash,
      },
      scoreCommit: {
        historyRunId: 'history-current',
        historyRunContentHash: currentSeal.content_hash,
        authorityRunId: currentAuthority.authorityRunId,
        authorityRunContentHash: currentAuthority.contentHash,
        historyV2SealContentHash: currentHistoryV2Seal.contentHash,
        commitNotBefore: '2026-07-04T12:00:01.500Z',
        commitNotAfter: currentRecordedAt,
      },
      releaseTags: ['v-test'],
      forecast: {
        eligibilityOutcome: 'already_captured',
        decisionIds: [forecast.decision_id],
        newDecisionIds: [],
        existingDecisionIds: [forecast.decision_id],
        captures: [{
          decisionId: forecast.decision_id,
          status: 'already_captured',
        }],
      },
    }),
  };
  return {
    attempts: [attempt],
    receipts: [receipt],
    historyRows: [originalHistory, currentHistory],
    historyRuns: [originalSeal, currentSeal],
    forecasts: [forecast],
    authorityRuns: [originalAuthority, currentAuthority],
    historyV2Seals: [originalHistoryV2Seal, currentHistoryV2Seal],
  };
}

function canonicalSemanticLinkFixture() {
  const fixture = semanticLinkFixture();
  const legacyForecast = fixture.forecasts[0];
  const receiptPayload = JSON.parse(fixture.receipts[0].payload_json);
  const release = {
    repository: 'openclaw/openclaw',
    nodeId: 'R_release_v_test',
    tagCommitOid: 'a'.repeat(40),
    publishedAt: legacyForecast.latest_release_published_at,
    aliases: [legacyForecast.latest_release_tag],
  };
  const lifecycle = planReleaseValidationProofLifecycle({
    existing: emptyReleaseValidationProofFixture(),
    repository: release.repository,
    observedAt: release.publishedAt,
    source: 'operation-receipt-test-catalog',
    releases: [release],
    modelVersion: legacyForecast.score_model_version,
    promptVersion: legacyForecast.prompt_version,
    codeRevision: legacyForecast.code_revision,
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
  });
  const obligation = lifecycle.bundle.obligations.find((row) =>
    row.opportunityCode === legacyForecast.opportunity_code &&
    row.horizonCode === 'field_regression_72h');
  assert.ok(obligation);
  const assignment = lifecycle.bundle.splitAssignments.find((row) =>
    row.obligationId === obligation.obligationId);
  assert.ok(assignment);
  const cohortRows = [
    ...lifecycle.bundle.obligations,
    ...lifecycle.bundle.splitAssignments,
    ...lifecycle.bundle.forecasts,
    ...lifecycle.bundle.outcomes,
    ...lifecycle.bundle.observationBatches,
  ].filter((row) => row.cohortId === lifecycle.cohort.cohortId);
  const canonicalForecast = sealReleaseValidationForecastV2({
    proofEpochId: lifecycle.cohort.proofEpochId,
    cohortId: lifecycle.cohort.cohortId,
    cohortSequence: Math.max(
      0,
      ...cohortRows.map((row) => row.cohortSequence),
    ) + 1,
    previousCohortContentHash:
      lifecycle.verification.cohortChainTips[lifecycle.cohort.cohortId] ?? null,
    obligationId: obligation.obligationId,
    splitAssignmentId: assignment.assignmentId,
    policyId: lifecycle.cohort.policyId,
    policyContentHash: lifecycle.cohort.policyContentHash,
    recordedAt: legacyForecast.recorded_at,
    latestRelease: obligation.release,
    candidates: [obligation.release],
    selectedReleaseId: obligation.release.releaseId,
    forecast: {
      schemaVersion: 1,
      legacyForecast: {
        decisionId: legacyForecast.decision_id,
        contentHash: legacyForecast.content_hash,
      },
      originalScorePublication: {
        historyRunId: legacyForecast.audit_history_run_id,
      },
      canonicalCapturePublication: {
        historyRunId: receiptPayload.scoreHistory.runId,
        historyRunContentHash: receiptPayload.scoreHistory.contentHash,
        authorityRunId: receiptPayload.scoreAuthority.runId,
        authorityRunContentHash: receiptPayload.scoreAuthority.contentHash,
        historyV2SealContentHash:
          receiptPayload.scoreAuthority.historyV2SealContentHash,
      },
    },
  });
  const validationProof = {
    ...lifecycle.bundle,
    forecasts: [...lifecycle.bundle.forecasts, canonicalForecast],
  };
  receiptPayload.schemaVersion = 2;
  receiptPayload.forecast.canonicalForecastIds = [
    canonicalForecast.forecastId,
  ];
  receiptPayload.forecast.canonicalForecastContentHashes = [
    canonicalForecast.contentHash,
  ];
  receiptPayload.forecast.newCanonicalForecastIds = [
    canonicalForecast.forecastId,
  ];
  receiptPayload.forecast.existingCanonicalForecastIds = [];
  receiptPayload.forecast.canonicalCaptures = [{
    opportunityCode: obligation.opportunityCode,
    horizonCode: obligation.horizonCode,
    status: 'inserted',
    forecastId: canonicalForecast.forecastId,
    contentHash: canonicalForecast.contentHash,
    obligationId: canonicalForecast.obligationId,
    splitAssignmentId: canonicalForecast.splitAssignmentId,
    cohortId: canonicalForecast.cohortId,
    legacyDecisionId: legacyForecast.decision_id,
    legacyContentHash: legacyForecast.content_hash,
  }];
  fixture.receipts[0].payload_json = JSON.stringify(receiptPayload);
  return {
    ...fixture,
    validationProof,
    canonicalForecast,
  };
}

function emptyReleaseValidationProofFixture() {
  return {
    epochs: [],
    retirements: [],
    policies: [],
    cohorts: [],
    catalogObservations: [],
    catalogMembers: [],
    catalogReconciliations: [],
    catalogReconciliationRows: [],
    obligations: [],
    splitAssignments: [],
    forecasts: [],
    outcomes: [],
    observationBatches: [],
    evaluationReceipts: [],
    promotionReceipts: [],
  };
}

function semanticHistoryRow(
  runId: string,
  recordedAt: string,
  authorityRunId: string,
  sourceIdentityDigest: string,
) {
  return {
    id: runId === 'history-original' ? 1 : 2,
    run_id: runId,
    recorded_at: recordedAt,
    release_tag: 'v-test',
    scored_at: '2026-07-04T10:30:00.000Z',
    score_model_version: 'model-test',
    prompt_version: 1,
    final_score: 8,
    status: 'eligible',
    band: 'good',
    recommended: 1,
    input_json: '{}',
    components_json: '{}',
    issue_evidence_json: '{}',
    gate_evidence_json: '{}',
    source_identity_json: JSON.stringify({
      schemaVersion: 1,
      digest: sourceIdentityDigest,
    }),
    authority_run_id: authorityRunId,
  };
}

function semanticHistorySeal(
  id: number,
  rows: ReturnType<typeof semanticHistoryRow>[],
  previousContentHash: string | null,
) {
  const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(rows);
  const input = {
    id,
    run_id: rows[0].run_id,
    recorded_at: rows[0].recorded_at,
    row_count: rows.length,
    rows_content_hash: rowsContentHash,
    previous_content_hash: previousContentHash,
    content_hash: '',
  };
  input.content_hash = releaseScoreAuditHistoryRunContentHash({
    runId: input.run_id,
    recordedAt: input.recorded_at,
    rowCount: input.row_count,
    rowsContentHash,
    previousContentHash,
  });
  return input;
}

function semanticForecast(history: ReturnType<typeof semanticHistoryRow>) {
  const recommendationDecision = {
    selectedTag: history.release_tag,
    policyCode: 'highest_confidence_with_recency_tolerance',
  };
  const row = {
    id: 1,
    decision_id: '',
    opportunity_code: 'first_verified_after_3h',
    recorded_at: history.recorded_at,
    latest_release_tag: history.release_tag,
    latest_release_published_at: '2026-07-04T08:00:00.000Z',
    selected_tag: history.release_tag,
    audit_history_run_id: history.run_id,
    score_model_version: history.score_model_version,
    prompt_version: history.prompt_version,
    policy_code: recommendationDecision.policyCode,
    candidate_scores_json: JSON.stringify([{
      releaseTag: history.release_tag,
      auditSnapshot: { ...history },
      scoreSnapshot: {
        scoredAt: history.scored_at,
        finalScore: history.final_score,
        status: history.status,
        band: history.band,
        recommended: true,
      },
    }]),
    decision_json: JSON.stringify({
      schemaVersion: 2,
      opportunityCode: 'first_verified_after_3h',
      recordedAt: history.recorded_at,
      latestReleaseTag: history.release_tag,
      latestReleasePublishedAt: '2026-07-04T08:00:00.000Z',
      selectedTag: history.release_tag,
      recommendationDecision,
    }),
    source_identity_json: history.source_identity_json,
    code_revision: 'revision-test',
    previous_content_hash: null,
    content_hash: '',
  };
  row.content_hash = releaseValidationForecastContentHash(row);
  row.decision_id = releaseValidationDecisionId(row, row.content_hash);
  return row;
}

function rekeySemanticForecast(
  fixture: ReturnType<typeof semanticLinkFixture>,
): void {
  const forecast = fixture.forecasts[0];
  const previousDecisionId = forecast.decision_id;
  forecast.content_hash = releaseValidationForecastContentHash(forecast);
  forecast.decision_id = releaseValidationDecisionId(forecast, forecast.content_hash);
  const payload = JSON.parse(fixture.receipts[0].payload_json);
  payload.forecast.decisionIds = payload.forecast.decisionIds.map(
    (decisionId: string) =>
      decisionId === previousDecisionId ? forecast.decision_id : decisionId,
  );
  payload.forecast.existingDecisionIds = payload.forecast.existingDecisionIds.map(
    (decisionId: string) =>
      decisionId === previousDecisionId ? forecast.decision_id : decisionId,
  );
  payload.forecast.captures = payload.forecast.captures.map(
    (capture: Record<string, unknown>) => ({
      ...capture,
      decisionId: capture.decisionId === previousDecisionId
        ? forecast.decision_id
        : capture.decisionId,
    }),
  );
  fixture.receipts[0].payload_json = JSON.stringify(payload);
}
