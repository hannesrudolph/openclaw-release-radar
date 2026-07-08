import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
} from './commentEvidence.ts';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
} from './stateEventSnapshot.ts';
import {
  abortableDelay,
  runCooperativeGroup,
} from './cooperativeCancellation.ts';
import type {
  GhComment,
  GhIssue,
  GhIssueCommentSnapshot,
  GhIssueFixEvidence,
  GhIssueFixEvidenceConnectionSnapshot,
  GhIssueLabelEvidenceSnapshot,
  GhIssueLabelEvent,
  GhReleaseCatalog,
} from './github.ts';
import {
  ClassifierAttemptLedgerTerminalError,
  PROMPT_VERSION,
  type IssueClassification,
} from './llm.ts';
import {
  captureClassifierError,
  createClassifierAttemptRun,
  createClassifierAttemptTerminalReceipt,
} from './classifierAttemptLedger.ts';
import {
  buildClosureClaimCandidateLedgerEntry,
  buildClosureClaimSourceSnapshotLedgerEntry,
} from './closureClaimCandidates.ts';
import { buildScoreAuthorityResolutionRun } from './scoreAuthorityResolution.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownsTestDir = assignedWorkerDatabasePath === null;
const testDir = assignedWorkerDatabasePath
  ? dirname(assignedWorkerDatabasePath)
  : mkdtempSync(join(tmpdir(), 'radar-refresh-test-'));
const testDatabasePath =
  assignedWorkerDatabasePath ?? join(testDir, 'radar.db');
if (assignedWorkerDatabasePath) {
  assert.equal(
    process.env.DB_PATH,
    assignedWorkerDatabasePath,
    'refresh tests must use their assigned worker database',
  );
  assert.ok(
    process.env.DOTENV_CONFIG_PATH,
    'refresh tests require the runner-assigned empty dotenv path',
  );
} else {
  process.env.DB_PATH = testDatabasePath;
  const emptyDotenvPath = join(testDir, '.env.empty');
  writeFileSync(emptyDotenvPath, '');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
}
let __refreshTest: typeof import('./refresh.ts').__refreshTest;
let reconcileIssueCommentSnapshots: typeof import('./refresh.ts').reconcileIssueCommentSnapshots;
let db: typeof import('./db.ts').db;
let dbModule: typeof import('./db.ts');
let createGracefulShutdown: typeof import('../index.ts').createGracefulShutdown;

before(async () => {
  ({ __refreshTest, reconcileIssueCommentSnapshots } = await import('./refresh.ts'));
  dbModule = await import('./db.ts');
  ({ db } = dbModule);
  ({ createGracefulShutdown } = await import('../index.ts'));
});

after(() => {
  try { db.close(); } catch { /* already closed or setup failed */ }
  if (ownsTestDir) rmSync(testDir, { recursive: true, force: true });
});

describe('refresh backfill completion', () => {
  it('bounds concurrent work while preserving input order', async () => {
    let active = 0;
    let maxActive = 0;
    const completed: number[] = [];
    const results = await __refreshTest.mapWithConcurrency(
      [0, 1, 2, 3, 4, 5],
      3,
      async (value: number) => {
        active++;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolve) => setTimeout(resolve, (5 - value) * 2));
        completed.push(value);
        active--;
        return `result-${value}`;
      },
    );

    assert.equal(maxActive, 3);
    assert.notDeepEqual(completed, [0, 1, 2, 3, 4, 5]);
    assert.deepEqual(results, [
      'result-0',
      'result-1',
      'result-2',
      'result-3',
      'result-4',
      'result-5',
    ]);
  });

  it('tracks active, accumulated, and failed stage timings', async () => {
    let clock = 100;
    const timer = __refreshTest.createStageTimer(() => clock);

    const finishCrawl = timer.start('issue.crawl');
    clock = 125;
    assert.deepEqual(timer.snapshot(), { 'issue.crawl': 25 });
    finishCrawl();

    clock = 130;
    await timer.timed('issue.classification', () => {
      clock = 137;
    }, { accumulate: true });
    clock = 140;
    await timer.timed('issue.classification', () => {
      clock = 151;
    }, { accumulate: true });

    clock = 160;
    await assert.rejects(
      timer.timed('score.build', () => {
        clock = 169;
        throw new Error('score build failed');
      }),
      /score build failed/,
    );
    clock = 170;
    await timer.timed('score.persist', () => {
      clock = 176;
    });

    assert.deepEqual(timer.snapshot(), {
      'issue.crawl': 25,
      'issue.classification': 18,
      'score.build': 9,
      'score.persist': 6,
    });
  });

  it('emits append-only started/completed/failed stage lifecycle events', async () => {
    let clock = Date.parse('2026-07-04T12:00:00.000Z');
    const events: Array<Record<string, unknown>> = [];
    const timer = __refreshTest.createStageTimer(
      () => clock,
      undefined,
      (event: Record<string, unknown>) => events.push(event),
    );

    await timer.timed('release.fetch', () => {
      clock += 25;
      return [1, 2, 3];
    });
    const finishCrawl = timer.start('issue.crawl');
    clock += 10;
    finishCrawl();
    timer.start('closure.proof');
    clock += 15;
    timer.failActive(new Error('proof failed'));

    assert.deepEqual(
      events.map((event) => ({
        stage: event.stage,
        status: event.status,
        durationMs: event.durationMs,
        counts: event.counts,
      })),
      [
        { stage: 'release.fetch', status: 'started', durationMs: null, counts: null },
        { stage: 'release.fetch', status: 'completed', durationMs: 25, counts: { items: 3 } },
        { stage: 'issue.crawl', status: 'started', durationMs: null, counts: null },
        { stage: 'issue.crawl', status: 'completed', durationMs: 10, counts: null },
        { stage: 'closure.proof', status: 'started', durationMs: null, counts: null },
        { stage: 'closure.proof', status: 'failed', durationMs: 15, counts: null },
      ],
    );
    assert.match(
      String((events.at(-1)?.details as any)?.error?.message),
      /proof failed/,
    );
  });

  it('records recoverable stage failures as degraded completions', async () => {
    let clock = Date.parse('2026-07-04T13:00:00.000Z');
    const events: Array<Record<string, unknown>> = [];
    const timer = __refreshTest.createStageTimer(
      () => clock,
      undefined,
      (event: Record<string, unknown>) => events.push(event),
    );

    await assert.rejects(
      timer.timed('release.evidence', () => {
        clock += 25;
        throw new Error('advisory source failed');
      }, { recoverable: true }),
      /advisory source failed/,
    );
    await timer.timed('issue.crawl', () => {
      clock += 10;
    });

    assert.deepEqual(
      events.map((event) => [event.stage, event.status]),
      [
        ['release.evidence', 'started'],
        ['release.evidence', 'completed'],
        ['issue.crawl', 'started'],
        ['issue.crawl', 'completed'],
      ],
    );
    assert.equal(
      (events[1]?.details as Record<string, unknown>)?.outcome,
      'degraded',
    );
    assert.match(
      String(
        ((events[1]?.details as Record<string, any>)?.error as Record<string, unknown>)
          ?.message,
      ),
      /advisory source failed/,
    );
  });

  it('keeps a stage recoverable when its first completion event append fails', () => {
    let clock = Date.parse('2026-07-04T15:00:00.000Z');
    let failCompletionOnce = true;
    const events: Array<{ stage: string; status: string }> = [];
    const timer = __refreshTest.createStageTimer(
      () => {
        clock += 1_000;
        return clock;
      },
      undefined,
      (event) => {
        if (event.status === 'completed' && failCompletionOnce) {
          failCompletionOnce = false;
          throw new Error('injected completion append failure');
        }
        events.push({ stage: event.stage, status: event.status });
      },
    );
    const finish = timer.start('release.fetch');

    assert.throws(
      () => finish('completed'),
      /injected completion append failure/,
    );
    timer.failActive(new Error('refresh failed after telemetry error'));

    assert.deepEqual(events, [
      { stage: 'release.fetch', status: 'started' },
      { stage: 'release.fetch', status: 'failed' },
    ]);
  });

  it('orchestrates attempt, injected evidence stages, score, not-eligible forecast, and success receipt', async () => {
    let clock = Date.now() - 10_000;
    let eventSequence = 0;
    assert.equal(dbModule.acquireRefreshLease(
      'refresh-orchestration-test',
      'holder-refresh-orchestration-success',
      new Date(clock).toISOString(),
      300_000,
    ), true);
    const operation = __refreshTest.createRefreshOrchestration({
      operation: 'refresh',
      trigger: 'integration-success',
      codeRevision: 'git:0123456789abcdef0123456789abcdef01234567',
      effectiveConfig: {
        schemaVersion: 1,
        github: { owner: 'openclaw', repo: 'openclaw' },
      },
      leaseName: 'refresh-orchestration-test',
      leaseHolderId: 'holder-refresh-orchestration-success',
      leaseTtlMs: 300_000,
      startedAt: new Date(clock).toISOString(),
      dependencies: {
        beginAttempt: dbModule.beginRefreshOperationAttempt,
        appendStageEvent: dbModule.appendRefreshOperationStageEvent,
        appendReceipt: dbModule.appendRefreshCaptureReceipt,
        transaction: dbModule.runInWriteTransaction,
        nowMs: () => {
          clock += 1_000;
          return clock;
        },
        randomId: () => `refresh-orchestration-success-${++eventSequence}`,
      },
    });
    const callOrder: string[] = [];

    const result = await operation.run(async ({ timed }) => {
      const evidence = await timed('release.fetch', async () => {
        callOrder.push('evidence');
        return [{ tag: 'v-test' }];
      });
      const scoreRun = await timed('score.build', async () => {
        callOrder.push('score');
        return {
          releases: evidence,
          scored: [{ rel: { tag: 'v-test' } }],
          recommendedTag: 'v-test',
        };
      });
      return operation.publishScore({
        scoreRun,
        scoredReleaseCount: scoreRun.scored.length,
        activatePublication: () => {
          callOrder.push('activate');
          dbModule.setMeta('refresh_orchestration_advisory', 'active');
        },
        persistScore: () => {
          callOrder.push('persist');
          dbModule.setMeta('refresh_orchestration_score', 'persisted');
          const committedAt = new Date(clock).toISOString();
          return {
            historyRunId: 'refresh:integration-success',
            historyRunContentHash: 'a'.repeat(64),
            authorityRunId: 'authority:integration-success',
            authorityRunContentHash: 'b'.repeat(64),
            historyV2SealContentHash: 'c'.repeat(64),
            commitTiming: {
              historyRunId: 'refresh:integration-success',
              historyRunContentHash: 'a'.repeat(64),
              authorityRunId: 'authority:integration-success',
              authorityRunContentHash: 'b'.repeat(64),
              historyV2SealContentHash: 'c'.repeat(64),
              commitNotBefore: committedAt,
              commitNotAfter: committedAt,
            },
          };
        },
        finalizeScore: () => {
          callOrder.push('finalize');
          dbModule.setMeta('refresh_orchestration_score', 'finalized');
        },
        captureForecast: () => {
          callOrder.push('forecast');
          return {
            eligibilityOutcome: 'not_eligible',
            forecasts: [],
          };
        },
        forecastCount: (forecast) => forecast.forecasts.length,
        scorePersistDetails: (scorePersistence) => ({
          historyRunId: scorePersistence.historyRunId,
          historyRunContentHash: scorePersistence.historyRunContentHash,
          authorityRunId: scorePersistence.authorityRunId,
          authorityRunContentHash: scorePersistence.authorityRunContentHash,
          historyV2SealContentHash: scorePersistence.historyV2SealContentHash,
          commitNotBefore: scorePersistence.commitTiming.commitNotBefore,
          commitNotAfter: scorePersistence.commitTiming.commitNotAfter,
        }),
        forecastDetails: (forecast) => ({
          eligibilityOutcome: forecast.eligibilityOutcome,
        }),
        successPayload: (scorePersistence, forecast) => ({
          schemaVersion: 1,
          operation: 'refresh',
          trigger: 'integration-success',
          scoreHistory: {
            runId: scorePersistence.historyRunId,
            contentHash: scorePersistence.historyRunContentHash,
          },
          scoreAuthority: {
            runId: scorePersistence.authorityRunId,
            contentHash: scorePersistence.authorityRunContentHash,
            historyV2SealContentHash: scorePersistence.historyV2SealContentHash,
          },
          scoreCommit: scorePersistence.commitTiming,
          releaseTags: ['v-test'],
          forecast: {
            eligibilityOutcome: forecast.eligibilityOutcome,
            decisionIds: [],
            captures: forecast.forecasts,
          },
        }),
      });
    });

    const attempt = dbModule.getRefreshOperationAttempt(operation.runId);
    const stages = dbModule.listRefreshOperationStageEvents(operation.runId);
    const receipt = dbModule.getRefreshCaptureReceipt(operation.runId);
    assert.equal(attempt?.trigger, 'integration-success');
    assert.deepEqual(
      callOrder,
      ['evidence', 'score', 'activate', 'persist', 'finalize', 'forecast'],
    );
    assert.equal(dbModule.getMeta('refresh_orchestration_advisory'), 'active');
    assert.equal(dbModule.getMeta('refresh_orchestration_score'), 'finalized');
    assert.deepEqual(
      stages.map((event) => [event.stage, event.status]),
      [
        ['release.fetch', 'started'],
        ['release.fetch', 'completed'],
        ['score.build', 'started'],
        ['score.build', 'completed'],
        ['score.persist', 'started'],
        ['score.persist', 'completed'],
        ['forecast.capture', 'started'],
        ['forecast.capture', 'completed'],
      ],
    );
    assert.equal(receipt?.status, 'success');
    assert.equal(JSON.parse(receipt?.payload_json ?? '{}').forecast.eligibilityOutcome, 'not_eligible');
    assert.equal(result.receiptId, receipt?.receipt_id);
    assert.equal(operation.terminalReceiptId(), receipt?.receipt_id);
    assert.equal(dbModule.releaseRefreshLease(
      'refresh-orchestration-test',
      'holder-refresh-orchestration-success',
    ), true);
  });

  it('records failed score orchestration with a terminal failure receipt and no forecast stage', async () => {
    let clock = Date.now() - 10_000;
    let eventSequence = 0;
    assert.equal(dbModule.acquireRefreshLease(
      'refresh-orchestration-test',
      'holder-refresh-orchestration-failure',
      new Date(clock).toISOString(),
      300_000,
    ), true);
    const operation = __refreshTest.createRefreshOrchestration({
      operation: 'refresh',
      trigger: 'integration-failure',
      codeRevision: 'git:fedcba9876543210fedcba9876543210fedcba98',
      effectiveConfig: { schemaVersion: 1 },
      leaseName: 'refresh-orchestration-test',
      leaseHolderId: 'holder-refresh-orchestration-failure',
      leaseTtlMs: 300_000,
      startedAt: new Date(clock).toISOString(),
      dependencies: {
        beginAttempt: dbModule.beginRefreshOperationAttempt,
        appendStageEvent: dbModule.appendRefreshOperationStageEvent,
        appendReceipt: dbModule.appendRefreshCaptureReceipt,
        transaction: dbModule.runInWriteTransaction,
        nowMs: () => {
          clock += 1_000;
          return clock;
        },
        randomId: () => `refresh-orchestration-failure-${++eventSequence}`,
      },
    });

    await assert.rejects(
      operation.run(async ({ timed }) => {
        await timed('release.fetch', async () => [{ tag: 'v-test' }]);
        await timed('score.build', async () => {
          throw new Error('injected score failure');
        });
        throw new Error('unreachable');
      }),
      /injected score failure/,
    );

    const stages = dbModule.listRefreshOperationStageEvents(operation.runId);
    const receipt = dbModule.getRefreshCaptureReceipt(operation.runId);
    assert.deepEqual(
      stages.map((event) => [event.stage, event.status]),
      [
        ['release.fetch', 'started'],
        ['release.fetch', 'completed'],
        ['score.build', 'started'],
        ['score.build', 'failed'],
      ],
    );
    assert.equal(receipt?.status, 'failure');
    assert.match(receipt?.payload_json ?? '', /injected score failure/);
    assert.equal(operation.terminalReceiptId(), receipt?.receipt_id);
    assert.equal(dbModule.releaseRefreshLease(
      'refresh-orchestration-test',
      'holder-refresh-orchestration-failure',
    ), true);
  });

  it('drains concurrent final attestations before appending one terminal failure receipt', async () => {
    let clock = Date.now() - 10_000;
    let eventSequence = 0;
    const leaseName = 'refresh-orchestration-final-attestation-failure';
    const leaseHolderId = 'holder-refresh-orchestration-final-attestation-failure';
    assert.equal(dbModule.acquireRefreshLease(
      leaseName,
      leaseHolderId,
      new Date(clock).toISOString(),
      300_000,
    ), true);
    const operation = __refreshTest.createRefreshOrchestration({
      operation: 'refresh',
      trigger: 'integration-final-attestation-failure',
      codeRevision: 'git:cccccccccccccccccccccccccccccccccccccccc',
      effectiveConfig: { schemaVersion: 1 },
      leaseName,
      leaseHolderId,
      leaseTtlMs: 300_000,
      startedAt: new Date(clock).toISOString(),
      dependencies: {
        beginAttempt: dbModule.beginRefreshOperationAttempt,
        appendStageEvent: dbModule.appendRefreshOperationStageEvent,
        appendReceipt: dbModule.appendRefreshCaptureReceipt,
        transaction: dbModule.runInWriteTransaction,
        nowMs: () => {
          clock += 1_000;
          return clock;
        },
        randomId: () => `final-attestation-failure-${++eventSequence}`,
      },
    });
    const primaryError = new Error('injected issue final attestation failure');
    let markReleaseStarted!: () => void;
    const releaseStarted = new Promise<void>((resolve) => {
      markReleaseStarted = resolve;
    });

    await assert.rejects(
      operation.run(async () => {
        const stages = operation.stageTimer.startCooperative([
          'issue.final-attest',
          'release.final-attest',
        ] as const);
        try {
          await runCooperativeGroup([
            () => stages.timed('issue.final-attest', async () => {
              await releaseStarted;
              throw primaryError;
            }),
            (signal) => stages.timed('release.final-attest', async () => {
              markReleaseStarted();
              await abortableDelay(30_000, signal);
              return { unreachable: true };
            }),
          ] as const);
        } catch (error) {
          try {
            stages.fail(error);
          } catch {
            // The orchestration failure path retries any stage left active.
          }
          throw error;
        }
      }),
      (error: unknown) => {
        assert.equal(error, primaryError);
        return true;
      },
    );

    const stageEvents = dbModule.listRefreshOperationStageEvents(operation.runId);
    assert.deepEqual(
      stageEvents.map((event) => [event.stage, event.status]),
      [
        ['issue.final-attest', 'started'],
        ['release.final-attest', 'started'],
        ['release.final-attest', 'completed'],
        ['issue.final-attest', 'failed'],
      ],
    );
    assert.equal(
      JSON.parse(stageEvents[2].details_json ?? '{}').outcome,
      'aborted',
    );
    const receipt = dbModule.getRefreshCaptureReceipt(operation.runId);
    assert.equal(receipt?.status, 'failure');
    assert.equal(
      JSON.parse(receipt?.payload_json ?? '{}').error.message,
      primaryError.message,
    );
    assert.equal(
      dbModule.listRefreshCaptureReceipts().filter((candidate) =>
        candidate.run_id === operation.runId).length,
      1,
    );
    assert.equal(operation.terminalReceiptId(), receipt?.receipt_id);
    assert.equal(dbModule.releaseRefreshLease(leaseName, leaseHolderId), true);
  });

  it('builds explicit durable success output links including empty forecast eligibility', () => {
    dbModule.setMeta('score_persistence_last_run', JSON.stringify({
      schemaVersion: 2,
      source: 'refresh',
      historyRunId: 'refresh:run-1',
      historyRunContentHash: 'a'.repeat(64),
      authorityRunId: 'score-authority:refresh:run-1',
      authorityRunContentHash: 'f'.repeat(64),
      historyV2SealContentHash: '0'.repeat(64),
    }));
    const payload = __refreshTest.successReceiptPayload({
      operation: 'refresh',
      trigger: 'manual',
      codeRevision: 'git:0123456789abcdef0123456789abcdef01234567',
      scoreRun: {
        scored: [{
          rel: { tag: 'v1' },
          conf: {
            score: 8,
            status: 'eligible',
            reason: 'fixture score',
          },
          neg: 1,
          pos: 2,
          brokenSurfaces: '[]',
          closedSerious: 3,
          openedSerious: 4,
          scoredAt: '2026-07-04T12:00:05.000Z',
          recommendationDecision: {
            releaseTag: 'v1',
            selectedTag: 'v1',
          },
          explanation: {},
        }],
        recommendedTag: 'v1',
        predecessorByReleaseTag: {
          v1: null,
        },
      },
      scorePersistence: {
        source: 'refresh',
        persistedAt: '2026-07-04T12:00:05.000Z',
        historyRunId: 'refresh:run-1',
        historyRunContentHash: 'a'.repeat(64),
        authorityRunId: 'score-authority:refresh:run-1',
        authorityRunContentHash: 'f'.repeat(64),
        historyV2SealContentHash: '0'.repeat(64),
        commitTiming: {
          schemaVersion: 4,
          historyRunId: 'refresh:run-1',
          historyRunContentHash: 'a'.repeat(64),
          authorityRunId: 'score-authority:refresh:run-1',
          authorityRunContentHash: 'f'.repeat(64),
          historyV2SealContentHash: '0'.repeat(64),
          historyRecordedAt: '2026-07-04T12:00:05.000Z',
          commitNotBefore: '2026-07-04T12:00:05.000Z',
          commitNotAfter: '2026-07-04T12:00:05.010Z',
          commitNotBeforeMs: Date.parse('2026-07-04T12:00:05.000Z'),
          commitNotAfterMs: Date.parse('2026-07-04T12:00:05.010Z'),
        },
        catalogAttestation: {
          schemaVersion: 4,
          initialRemoteCatalog: {
            digest: 'b'.repeat(64),
            totalCount: 10,
            nodeCount: 10,
            pageCount: 1,
            pagesFetched: 2,
            sweepCount: 2,
            exhausted: true,
            stabilized: true,
            sourceOrder: 'CREATED_AT_DESC',
          },
          finalRemoteCatalog: {
            digest: 'b'.repeat(64),
            totalCount: 10,
            nodeCount: 10,
            pageCount: 1,
            pagesFetched: 2,
            sweepCount: 2,
            exhausted: true,
            stabilized: true,
            sourceOrder: 'CREATED_AT_DESC',
          },
          finalObservedAt: '2026-07-04T12:00:04.000Z',
          projectedActiveCatalog: {
            digest: 'e'.repeat(64),
            releaseCount: 10,
          },
          localActiveCatalog: {
            digest: 'e'.repeat(64),
            releaseCount: 10,
          },
          latestStable: {
            nodeId: 'R_v1',
            tag: 'v1',
            tagCommitOid: '1'.repeat(40),
            publishedAt: '2026-07-04T08:00:00.000Z',
          },
          scoreBuiltAt: '2026-07-04T12:00:03.000Z',
        },
        issueCrawlMetadata: {
          schemaVersion: 2,
          startedAt: '2026-07-04T12:00:00.000Z',
          finishedAt: '2026-07-04T12:00:04.000Z',
          scorePersisted: true,
          scorePersistedAt: '2026-07-04T12:00:05.000Z',
        },
      },
      forecastCapture: {
        eligibilityOutcome: 'not_eligible',
        forecasts: [],
        canonicalForecasts: [],
      },
      advisoryProvenance: {
        schemaVersion: 2,
        snapshotId: 42,
        capturedAt: '2026-07-04T12:00:02.000Z',
        repository: {
          owner: 'openclaw',
          name: 'openclaw',
          url: 'https://github.com/openclaw/openclaw',
        },
        target: {
          ecosystem: 'npm',
          packageName: 'openclaw',
        },
        sourceHash: 'c'.repeat(64),
        catalogHash: 'd'.repeat(64),
        scoreHash: 'e'.repeat(64),
        contentHash: 'f'.repeat(64),
        previousContentHash: null,
        rowCount: 3,
        scoreRowCount: 2,
        scoreReady: true,
        scoreContentDigest: 'd'.repeat(64),
      },
      releaseArtifacts: {
        schemaVersion: 1,
        linkCount: 1,
        links: [{
          release: {
            repository: 'openclaw/openclaw',
            tag: 'v1',
            releaseNodeId: 'R_v1',
            catalogTagCommitOid: '1'.repeat(40),
            publishedAt: '2026-07-04T08:00:00.000Z',
          },
          observationId: `artifact-observation-v1:${'2'.repeat(64)}`,
          observationContentHash: '3'.repeat(64),
          receiptId: `artifact-receipt-v2:${'4'.repeat(64)}`,
          receiptContentHash: '5'.repeat(64),
          evidenceIdentity: '6'.repeat(64),
          evidenceReportIdentity:
            `release-evidence-v1:sha256:${'7'.repeat(64)}`,
        }],
        contentDigest: '8'.repeat(64),
      },
    } as any);

    assert.equal(payload.schemaVersion, 3);
    assert.equal((payload.scoreHistory as any).runId, 'refresh:run-1');
    assert.equal(
      (payload.scoreAuthority as any).runId,
      'score-authority:refresh:run-1',
    );
    assert.equal((payload.scoreCommit as any).historyRunId, 'refresh:run-1');
    assert.equal((payload.scoreMetadata as any).historyRunId, 'refresh:run-1');
    assert.deepEqual(payload.scoreRows, [{
      tag: 'v1',
      finalScore: 8,
      negativeIssues: 1,
      positiveIssues: 2,
      state: 'eligible',
      recommended: true,
      scoreReason: 'fixture score',
      brokenSurfaces: '[]',
      closedSeriousFixed: 3,
      openedSeriousDuringReign: 4,
      scoredAt: '2026-07-04T12:00:05.000Z',
    }]);
    assert.deepEqual(payload.releaseTags, ['v1']);
    assert.equal((payload.releaseArtifacts as any).linkCount, 1);
    assert.deepEqual((payload.releaseArtifactScope as any).scoredReleaseTags, ['v1']);
    assert.deepEqual((payload.releaseArtifactScope as any).dependencyReleaseTags, []);
    assert.deepEqual(
      (payload.releaseArtifactScope as any).predecessorByReleaseTag,
      { v1: null },
    );
    assert.equal((payload.recommendation as any).selectedTag, 'v1');
    assert.equal((payload.issueCrawl as any).metaKey, 'issue_crawl_last_run');
    assert.equal((payload.releaseCatalog as any).digest, 'b'.repeat(64));
    assert.equal((payload.releaseCatalog as any).attestation.schemaVersion, 4);
    assert.equal((payload.advisoryCatalog as any).contentDigest, 'd'.repeat(64));
    assert.equal((payload.advisoryCatalog as any).metaKey, 'advisory_snapshot_v2_last_run');
    assert.equal((payload.advisoryCatalog as any).snapshotId, 42);
    assert.equal((payload.advisoryCatalog as any).catalogRowCount, 3);
    assert.equal((payload.advisoryCatalog as any).scoreRowCount, 2);
    assert.deepEqual(payload.forecast, {
      eligibilityOutcome: 'not_eligible',
      decisionIds: [],
      newDecisionIds: [],
      existingDecisionIds: [],
      captures: [],
      canonicalForecastIds: [],
      canonicalForecastContentHashes: [],
      newCanonicalForecastIds: [],
      existingCanonicalForecastIds: [],
      canonicalCaptures: [],
    });
  });

  it('publishes scores, forecasts, completion events, and success receipt in one transaction', () => {
    const source = readFileSync(new URL('./refresh.ts', import.meta.url), 'utf8');
    const orchestrationFactory = source.indexOf('function createRefreshOrchestration');
    const finalTransaction = source.indexOf(
      'const finalized = dependencies.transaction(() => {',
      orchestrationFactory,
    );
    const finalizeMetadata = source.indexOf(
      'options.finalizeScore(scorePersistence);',
      finalTransaction,
    );
    const forecastCapture = source.indexOf(
      'const forecast = options.captureForecast(scorePersistence);',
      finalTransaction,
    );
    const successReceipt = source.indexOf(
      'const receipt = dependencies.appendReceipt({',
      forecastCapture,
    );
    const scorePersistence = source.indexOf(
      'scorePersistence = options.persistScore();',
      finalTransaction,
    );
    const publicationActivation = source.indexOf(
      'options.activatePublication?.();',
      finalTransaction,
    );
    const scoreCompletion = source.indexOf(
      "'score.persist',\n            'completed'",
      scorePersistence,
    );
    const finalFence = source.indexOf(
      'options.assertCommitAllowed?.();',
      successReceipt,
    );
    const productionPublish = source.indexOf('const publication = orchestration.publishScore({');
    assert.ok(orchestrationFactory >= 0);
    assert.ok(finalTransaction > orchestrationFactory);
    assert.ok(publicationActivation > finalTransaction);
    assert.ok(scorePersistence > publicationActivation);
    assert.ok(scoreCompletion > scorePersistence);
    assert.ok(finalizeMetadata > finalTransaction);
    assert.ok(forecastCapture > finalizeMetadata);
    assert.ok(successReceipt > forecastCapture);
    assert.ok(finalFence > successReceipt);
    assert.ok(productionPublish > successReceipt);
    assert.match(
      source.slice(productionPublish),
      /activatePublication: \(\) => \{\s*activateCompoundAdvisorySnapshot\(advisoryProvenance\.snapshotId/,
    );
    assert.match(
      source.slice(productionPublish),
      /forecastDetails: \(forecastCapture\) => \(\{\s*eligibilityOutcome: forecastCapture\.eligibilityOutcome/,
    );
    assert.match(
      source.slice(productionPublish),
      /atomic score\/forecast\/success receipt publication rolled back/,
    );
  });

  it('binds artifact verification to the catalog OID and persists canonical observations', () => {
    const source = readFileSync(new URL('./refresh.ts', import.meta.url), 'utf8');
    assert.equal(
      (source.match(/expectedReleaseSha: r\.tag_commit_oid/g) ?? []).length,
      1,
    );
    assert.equal(
      (source.match(/expectedReleaseSha: stats\.releaseSha/g) ?? []).length,
      1,
    );
    assert.match(source, /expectedNpmPackageUrl: stats\.npmPackageUrl/);
    assert.match(source, /expectedCatalogReleaseSha: r\.tag_commit_oid/);
    assert.match(source, /const observedAt = new Date\(\)\.toISOString\(\);/);
    assert.match(source, /persistReleaseArtifactVerification\(\{/);
    assert.match(source, /releaseSha: stats\.releaseSha/);
    assert.match(source, /artifactObservationRunId: runId/);
    assert.match(
      source,
      /releaseArtifacts: releaseArtifactPublicationForRun\(runId\)/,
    );
  });

  it('rolls back every score publication phase and lease loss without partial actionable state', async () => {
    const phases = [
      'advisory.activate',
      'score.write',
      'authority.write',
      'audit.write',
      'history.seal',
      'history.v2.seal',
      'after.persist',
      'metadata.finalize',
      'forecast.insert',
      'payload.construct',
      'receipt.append',
      'commit.fence',
      'lease.loss',
    ] as const;

    for (const [index, failurePhase] of phases.entries()) {
      const suffix = `${index}-${failurePhase.replaceAll('.', '-')}`;
      const tag = `v-atomic-${suffix}`;
      const leaseName = `refresh-atomic-${suffix}`;
      const holderId = `holder-atomic-${suffix}`;
      const historyRunId = `refresh:atomic-${suffix}`;
      let clock = Date.now() - 20_000;
      let eventSequence = 0;
      const publishedAt = new Date(clock - 60_000).toISOString();
      dbModule.replaceActiveReleaseCatalog([{
        tag,
        node_id: `R_${tag}`,
        catalog_tag_commit_oid: createHash('sha256')
          .update(tag)
          .digest('hex')
          .slice(0, 40),
        name: tag,
        published_at: publishedAt,
        created_at: publishedAt,
        updated_at: publishedAt,
        html_url: `https://example.test/${tag}`,
        prerelease: false,
        body: '',
      }], {
        capture: { source: 'test_fixture' },
      });
      assert.equal(dbModule.acquireRefreshLease(
        leaseName,
        holderId,
        new Date(clock).toISOString(),
        300_000,
      ), true);
      const operation = __refreshTest.createRefreshOrchestration({
        operation: 'refresh',
        trigger: `atomic-${failurePhase}`,
        codeRevision: 'git:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        effectiveConfig: { schemaVersion: 1 },
        leaseName,
        leaseHolderId: holderId,
        leaseTtlMs: 300_000,
        startedAt: new Date(clock).toISOString(),
        dependencies: {
          beginAttempt: dbModule.beginRefreshOperationAttempt,
          appendStageEvent: dbModule.appendRefreshOperationStageEvent,
          appendReceipt: (input) => {
            if (input.status === 'success' && failurePhase === 'receipt.append') {
              throw new Error(`injected ${failurePhase}`);
            }
            return dbModule.appendRefreshCaptureReceipt(input);
          },
          transaction: dbModule.runInWriteTransaction,
          nowMs: () => {
            clock += 1_000;
            return clock;
          },
          randomId: () => `atomic-${suffix}-${++eventSequence}`,
        },
      });
      const scoredAt = new Date(clock + 1_000).toISOString();
      const sourceIdentity = dbModule.scoreSourceIdentity();
      const authorityRunId = `score-authority:${historyRunId}`;
      const audit = {
        release_tag: tag,
        scored_at: scoredAt,
        score_model_version: 'atomic-test-model',
        prompt_version: 1,
        final_score: 8,
        status: 'eligible',
        band: 'solid',
        recommended: 1,
        input_json: '{"schemaVersion":1}',
        components_json: '{"schemaVersion":1,"reason":"atomic fixture"}',
        issue_evidence_json: '{"schemaVersion":1}',
        gate_evidence_json: '{"schemaVersion":1}',
        source_identity_json: JSON.stringify(sourceIdentity),
      };

      await assert.rejects(
        operation.run(async () => operation.publishScore({
          scoreRun: { tag },
          scoredReleaseCount: 1,
          assertScorePersistAllowed: () => undefined,
          activatePublication: () => {
            dbModule.setMeta(`atomic_advisory_${suffix}`, 'active');
            if (failurePhase === 'advisory.activate') {
              throw new Error(`injected ${failurePhase}`);
            }
          },
          persistScore: () => {
            dbModule.updateReleaseScore({
              tag,
              final_score: 8,
              negative_issues: 1,
              positive_issues: 2,
              state: 'eligible',
              recommended: 1,
              score_reason: 'atomic fixture',
              broken_surfaces: '[]',
              closed_serious_fixed: 3,
              opened_serious_during_reign: 4,
              scored_at: scoredAt,
            });
            if (failurePhase === 'score.write') throw new Error(`injected ${failurePhase}`);
            const authorityRun = buildScoreAuthorityResolutionRun({
              authorityRunId,
              sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
              sourceIdentityDigest: sourceIdentity.digest,
              recordedAt: scoredAt,
              previousContentHash:
                dbModule.listScoreAuthorityResolutionRuns().at(-1)?.contentHash ??
                null,
              rows: [],
            });
            const storedAuthorityRun =
              dbModule.insertScoreAuthorityResolutionRun(authorityRun).row;
            if (failurePhase === 'authority.write') {
              throw new Error(`injected ${failurePhase}`);
            }
            const boundAudit = {
              ...audit,
              authority_run_id: storedAuthorityRun.authorityRunId,
            };
            dbModule.upsertReleaseScoreAudit(boundAudit);
            if (failurePhase === 'audit.write') throw new Error(`injected ${failurePhase}`);
            dbModule.insertReleaseScoreAuditHistory(
              historyRunId,
              scoredAt,
              boundAudit,
            );
            const seal = dbModule.sealReleaseScoreAuditHistoryRun(historyRunId, scoredAt);
            if (failurePhase === 'history.seal') throw new Error(`injected ${failurePhase}`);
            const historyV2Seal = dbModule.sealReleaseScoreAuditHistoryV2({
              historyRunId,
              authorityRunId: storedAuthorityRun.authorityRunId,
              sealedAt: scoredAt,
            });
            if (failurePhase === 'history.v2.seal') {
              throw new Error(`injected ${failurePhase}`);
            }
            dbModule.setMeta('score_persistence_last_run', JSON.stringify({
              schemaVersion: 2,
              source: 'refresh',
              operationReceiptRequired: true,
              operationRunId: operation.runId,
              historyRunId,
              historyRunContentHash: seal.row.content_hash,
              authorityRunId: storedAuthorityRun.authorityRunId,
              authorityRunContentHash: storedAuthorityRun.contentHash,
              historyV2SealContentHash: historyV2Seal.row.contentHash,
            }));
            const commitTiming = {
              schemaVersion: 4,
              historyRunId,
              historyRunContentHash: seal.row.content_hash,
              authorityRunId: storedAuthorityRun.authorityRunId,
              authorityRunContentHash: storedAuthorityRun.contentHash,
              historyV2SealContentHash: historyV2Seal.row.contentHash,
              historyRecordedAt: scoredAt,
              commitNotBefore: scoredAt,
              commitNotAfter: scoredAt,
              commitNotBeforeMs: Date.parse(scoredAt),
              commitNotAfterMs: Date.parse(scoredAt),
            };
            return {
              historyRunId,
              historyRunContentHash: seal.row.content_hash,
              authorityRunId: storedAuthorityRun.authorityRunId,
              authorityRunContentHash: storedAuthorityRun.contentHash,
              historyV2SealContentHash: historyV2Seal.row.contentHash,
              persistedAt: scoredAt,
              commitTiming,
            };
          },
          afterPersist: () => {
            dbModule.setMeta(`atomic_after_${suffix}`, 'written');
            if (failurePhase === 'after.persist') throw new Error(`injected ${failurePhase}`);
          },
          finalizeScore: () => {
            dbModule.setMeta(`atomic_finalize_${suffix}`, 'written');
            if (failurePhase === 'metadata.finalize') throw new Error(`injected ${failurePhase}`);
          },
          captureForecast: () => {
            dbModule.setMeta(`atomic_forecast_${suffix}`, 'written');
            if (failurePhase === 'forecast.insert') throw new Error(`injected ${failurePhase}`);
            return { eligibilityOutcome: 'not_eligible', forecasts: [] };
          },
          forecastCount: (forecast) => forecast.forecasts.length,
          scorePersistDetails: (scorePersistence) => ({
            historyRunId: scorePersistence.historyRunId,
            historyRunContentHash: scorePersistence.historyRunContentHash,
            authorityRunId: scorePersistence.authorityRunId,
            authorityRunContentHash: scorePersistence.authorityRunContentHash,
            historyV2SealContentHash:
              scorePersistence.historyV2SealContentHash,
            commitNotBefore: scorePersistence.commitTiming.commitNotBefore,
            commitNotAfter: scorePersistence.commitTiming.commitNotAfter,
          }),
          forecastDetails: (forecast) => ({
            eligibilityOutcome: forecast.eligibilityOutcome,
          }),
          successPayload: (scorePersistence) => {
            dbModule.setMeta(`atomic_payload_${suffix}`, 'written');
            if (failurePhase === 'payload.construct') throw new Error(`injected ${failurePhase}`);
            return {
              schemaVersion: 1,
              operation: 'refresh',
              trigger: `atomic-${failurePhase}`,
              codeRevision: 'git:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              scoreHistory: {
                runId: scorePersistence.historyRunId,
                contentHash: scorePersistence.historyRunContentHash,
                persistedAt: scorePersistence.persistedAt,
              },
              scoreAuthority: {
                runId: scorePersistence.authorityRunId,
                contentHash: scorePersistence.authorityRunContentHash,
                historyV2SealContentHash:
                  scorePersistence.historyV2SealContentHash,
              },
              scoreCommit: scorePersistence.commitTiming,
              releaseTags: [tag],
              forecast: {
                eligibilityOutcome: 'not_eligible',
                decisionIds: [],
                newDecisionIds: [],
                existingDecisionIds: [],
                captures: [],
              },
            };
          },
          assertCommitAllowed: () => {
            if (failurePhase === 'lease.loss') {
              assert.equal(dbModule.releaseRefreshLease(leaseName, holderId), true);
              assert.equal(
                dbModule.isRefreshLeaseHeld(leaseName, holderId, new Date(clock).toISOString()),
                false,
              );
              throw new Error('injected lease loss within publication transaction');
            }
            if (failurePhase === 'commit.fence') throw new Error(`injected ${failurePhase}`);
          },
        })),
        /injected/,
        failurePhase,
      );

      assert.equal(dbModule.getRelease(tag)?.final_score, null, failurePhase);
      assert.equal(dbModule.getRelease(tag)?.recommended, 0, failurePhase);
      assert.equal(dbModule.getReleaseScoreAudit(tag), undefined, failurePhase);
      assert.equal(dbModule.getReleaseScoreAuditHistoryRunSeal(historyRunId), null, failurePhase);
      assert.equal(
        dbModule.getScoreAuthorityResolutionRun(authorityRunId),
        null,
        failurePhase,
      );
      assert.equal(
        dbModule.getReleaseScoreAuditHistoryV2Seal(historyRunId),
        null,
        failurePhase,
      );
      assert.equal(dbModule.getMeta(`atomic_advisory_${suffix}`), null, failurePhase);
      assert.equal(dbModule.getMeta(`atomic_after_${suffix}`), null, failurePhase);
      assert.equal(dbModule.getMeta(`atomic_finalize_${suffix}`), null, failurePhase);
      assert.equal(dbModule.getMeta(`atomic_forecast_${suffix}`), null, failurePhase);
      assert.equal(dbModule.getMeta(`atomic_payload_${suffix}`), null, failurePhase);
      assert.equal(dbModule.getSealedReleaseScoreAuditPublication(tag).valid, false, failurePhase);
      assert.equal(dbModule.getRefreshCaptureReceipt(operation.runId)?.status, 'failure', failurePhase);
      assert.deepEqual(
        dbModule.listRefreshOperationStageEvents(operation.runId)
          .filter((event) => event.stage === 'score.persist')
          .map((event) => event.status),
        ['started', 'failed'],
        failurePhase,
      );
      assert.equal(dbModule.releaseRefreshLease(leaseName, holderId), true, failurePhase);
    }
  });

  it('rejects publication after a competing SQLite connection replaces the lease fence', async () => {
    const tag = 'v-atomic-competing-lease';
    const leaseName = 'refresh-atomic-competing-lease';
    const holderId = 'holder-atomic-competing-lease';
    const replacementHolderId = 'holder-atomic-competing-replacement';
    let clock = Date.now() - 20_000;
    let eventSequence = 0;
    dbModule.upsertRelease({
      tag,
      name: tag,
      published_at: new Date(clock - 60_000).toISOString(),
      html_url: `https://example.test/${tag}`,
      prerelease: false,
      body: '',
    });
    assert.equal(dbModule.acquireRefreshLease(
      leaseName,
      holderId,
      new Date(clock).toISOString(),
      300_000,
    ), true);
    const operation = __refreshTest.createRefreshOrchestration({
      operation: 'refresh',
      trigger: 'atomic-competing-lease',
      codeRevision: 'git:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      effectiveConfig: { schemaVersion: 1 },
      leaseName,
      leaseHolderId: holderId,
      leaseTtlMs: 300_000,
      startedAt: new Date(clock).toISOString(),
      dependencies: {
        beginAttempt: dbModule.beginRefreshOperationAttempt,
        appendStageEvent: dbModule.appendRefreshOperationStageEvent,
        appendReceipt: dbModule.appendRefreshCaptureReceipt,
        transaction: (publish) => {
          const competing = new DatabaseSync(process.env.DB_PATH!);
          try {
            competing.prepare(`
              UPDATE refresh_leases
              SET holder_id=?, acquired_at=?, expires_at=?
              WHERE name=?
            `).run(
              replacementHolderId,
              new Date(clock + 1_000).toISOString(),
              new Date(clock + 301_000).toISOString(),
              leaseName,
            );
          } finally {
            competing.close();
          }
          return dbModule.runInWriteTransaction(publish);
        },
        nowMs: () => {
          clock += 1_000;
          return clock;
        },
        randomId: () => `atomic-competing-${++eventSequence}`,
      },
    });

    await assert.rejects(
      operation.run(async () => operation.publishScore({
        scoreRun: { tag },
        scoredReleaseCount: 1,
        assertScorePersistAllowed: () => {
          if (!dbModule.isRefreshLeaseHeld(
            leaseName,
            holderId,
            new Date(clock).toISOString(),
          )) {
            throw new Error('competing connection replaced the publication lease');
          }
        },
        persistScore: () => {
          dbModule.updateReleaseScore({
            tag,
            final_score: 9,
            negative_issues: 0,
            positive_issues: 1,
            state: 'eligible',
            recommended: 1,
            score_reason: 'must not publish',
            broken_surfaces: '[]',
            closed_serious_fixed: 1,
            opened_serious_during_reign: 0,
            scored_at: new Date(clock).toISOString(),
          });
          return {};
        },
        finalizeScore: () => undefined,
        captureForecast: () => ({ eligibilityOutcome: 'not_eligible', forecasts: [] }),
        forecastCount: (forecast) => forecast.forecasts.length,
        forecastDetails: (forecast) => ({
          eligibilityOutcome: forecast.eligibilityOutcome,
        }),
        successPayload: () => ({
          schemaVersion: 1,
          operation: 'refresh',
          trigger: 'atomic-competing-lease',
          codeRevision: 'git:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          releaseTags: [tag],
          forecast: {
            eligibilityOutcome: 'not_eligible',
            decisionIds: [],
            newDecisionIds: [],
            existingDecisionIds: [],
            captures: [],
          },
        }),
      })),
      /competing connection replaced the publication lease/,
    );

    assert.equal(dbModule.getRelease(tag)?.final_score, null);
    assert.equal(dbModule.getRelease(tag)?.recommended, 0);
    assert.equal(dbModule.getReleaseScoreAudit(tag), undefined);
    assert.equal(dbModule.getRefreshCaptureReceipt(operation.runId), null);
    assert.equal(
      dbModule.listRefreshOperationStageEvents(operation.runId)
        .filter((event) => event.stage === 'score.persist')
        .map((event) => event.status)
        .join(','),
      'started',
    );
    const attempt = dbModule.getRefreshOperationAttempt(operation.runId);
    assert.ok(attempt);
    const abandonedAt = new Date(clock + 1_000).toISOString();
    dbModule.appendRefreshCaptureReceipt({
      run_id: operation.runId,
      lease_name: leaseName,
      lease_holder_id: replacementHolderId,
      status: 'abandoned',
      finished_at: abandonedAt,
      duration_ms: Date.parse(abandonedAt) - Date.parse(attempt.started_at),
      payload: {
        schemaVersion: 1,
        reason: 'competing_lease_replaced_test_run',
      },
    });
    assert.equal(
      dbModule.getRefreshCaptureReceipt(operation.runId)?.status,
      'abandoned',
    );
    assert.equal(dbModule.releaseRefreshLease(leaseName, replacementHolderId), true);
  });

  it('prospectively enrolls immutable validation slots immediately after catalog activation', () => {
    const source = readFileSync(new URL('./refresh.ts', import.meta.url), 'utf8');
    const refreshStart = source.indexOf('export async function refresh(');
    const catalogActivation = source.indexOf(
      'const activeCatalogIdentity = replaceActiveReleaseCatalog(',
      refreshStart,
    );
    const proofStage = source.indexOf(
      "'validation.proof.catalog'",
      catalogActivation,
    );
    const proofPlan = source.indexOf(
      'planReleaseValidationProofLifecycle({',
      proofStage,
    );
    const proofAppend = source.indexOf(
      'appendReleaseValidationProof(plan.append)',
      proofPlan,
    );
    const enrollmentStage = source.indexOf(
      "'validation.enroll'",
      catalogActivation,
    );
    const enrollmentWrite = source.indexOf(
      'insertReleaseValidationOpportunityEnrollments({',
      enrollmentStage,
    );
    const releaseEvidence = source.indexOf(
      "refreshLease.renew('release evidence')",
      enrollmentWrite,
    );
    const scorePublication = source.indexOf(
      'const publication = orchestration.publishScore({',
      releaseEvidence,
    );
    assert.ok(catalogActivation > refreshStart);
    assert.ok(proofStage > catalogActivation);
    assert.ok(proofPlan > proofStage);
    assert.ok(proofAppend > proofPlan);
    assert.ok(enrollmentStage > catalogActivation);
    assert.ok(enrollmentStage > proofAppend);
    assert.ok(enrollmentWrite > enrollmentStage);
    assert.ok(releaseEvidence > enrollmentWrite);
    assert.ok(scorePublication > releaseEvidence);
    assert.match(
      source.slice(proofStage, enrollmentStage),
      /runRefreshWrite\('validation proof catalog'/,
    );
    assert.match(
      source.slice(proofStage, enrollmentStage),
      /existing: readReleaseValidationProofBundle\(\)/,
    );
    assert.match(
      source.slice(proofStage, enrollmentStage),
      /\.filter\(\(release\) => !release\.prerelease\)/,
    );
    assert.match(
      source.slice(enrollmentStage, enrollmentWrite),
      /refreshLease\.assertHeld\('validation opportunity enrollment'\)/,
    );
    assert.match(
      source.slice(enrollmentStage, releaseEvidence),
      /operationAttemptContentHash: attempt\.content_hash/,
    );
    assert.match(
      source.slice(scorePublication),
      /forecastFailureDetails: .*forecastPlan/s,
    );
  });

  it('commits the operation attempt before network work and returns durable IDs', () => {
    const source = readFileSync(new URL('./refresh.ts', import.meta.url), 'utf8');
    const orchestrationFactory = source.indexOf('function createRefreshOrchestration');
    const attemptCommit = source.indexOf('dependencies.beginAttempt({', orchestrationFactory);
    const refreshStart = source.indexOf('export async function refresh(');
    const orchestrationStart = source.indexOf(
      'orchestration = createRefreshOrchestration({',
      refreshStart,
    );
    const refreshBody = source.slice(refreshStart);
    const firstNetworkFetch = refreshBody.indexOf('fetchReleaseCatalog({');

    assert.ok(orchestrationFactory >= 0);
    assert.ok(attemptCommit > orchestrationFactory);
    assert.ok(refreshStart >= 0);
    assert.ok(orchestrationStart > refreshStart);
    assert.ok(firstNetworkFetch > 0);
    assert.match(source.slice(refreshStart, orchestrationStart), /refreshLease\.acquire\(\)/);
    assert.match(source.slice(refreshStart, refreshStart + 500), /runId: string;\s+receiptId: string;/);
    assert.match(source.slice(orchestrationStart), /return \{\s+runId,\s+receiptId: terminalReceiptId,/);
  });

  it('uses a unique holder with a five-minute renewable refresh lease', () => {
    const calls: Array<Record<string, unknown>> = [];
    let now = '2026-07-03T12:00:00.000Z';
    const lease = __refreshTest.createRefreshLeaseGuard({
      name: __refreshTest.REFRESH_LEASE_NAME,
      holderId: '1234:test-holder',
      ttlMs: __refreshTest.REFRESH_LEASE_TTL_MS,
      now: () => now,
      acquire(name, holderId, acquiredAt, ttlMs) {
        calls.push({ operation: 'acquire', name, holderId, acquiredAt, ttlMs });
        return true;
      },
      renew(name, holderId, renewedAt, ttlMs) {
        calls.push({ operation: 'renew', name, holderId, renewedAt, ttlMs });
        return true;
      },
      release(name, holderId) {
        calls.push({ operation: 'release', name, holderId });
        return true;
      },
    });

    lease.acquire();
    now = '2026-07-03T12:01:00.000Z';
    lease.renew('issue crawl');
    assert.equal(lease.release(), true);
    assert.equal(lease.release(), false);

    assert.equal(__refreshTest.REFRESH_LEASE_TTL_MS, 300_000);
    assert.deepEqual(calls, [
      {
        operation: 'acquire',
        name: 'github-refresh',
        holderId: '1234:test-holder',
        acquiredAt: '2026-07-03T12:00:00.000Z',
        ttlMs: 300_000,
      },
      {
        operation: 'renew',
        name: 'github-refresh',
        holderId: '1234:test-holder',
        renewedAt: '2026-07-03T12:01:00.000Z',
        ttlMs: 300_000,
      },
      {
        operation: 'release',
        name: 'github-refresh',
        holderId: '1234:test-holder',
      },
    ]);
  });

  it('fails fast when another process holds the refresh lease', () => {
    let releaseCalls = 0;
    const lease = __refreshTest.createRefreshLeaseGuard({
      name: 'github-refresh',
      holderId: 'blocked-holder',
      ttlMs: 300_000,
      now: () => '2026-07-03T12:00:00.000Z',
      acquire: () => false,
      renew: () => true,
      release: () => {
        releaseCalls++;
        return true;
      },
    });

    assert.throws(() => lease.acquire(), /refresh already running in another process/);
    assert.equal(lease.release(), false);
    assert.equal(releaseCalls, 0);
  });

  it('renews the process lease periodically, latches heartbeat failure, blocks writes, and cleans up', () => {
    let heartbeat: (() => void) | null = null;
    let scheduledInterval: number | null = null;
    let cancelCalls = 0;
    let renewCalls = 0;
    let releaseCalls = 0;
    let reportedFailure: Error | null = null;
    const refreshController = new AbortController();
    const abortRefresh = __refreshTest.abortRefreshOnLeaseFailure(refreshController);
    const handle = { kind: 'test-heartbeat' };
    const lease = __refreshTest.createRefreshLeaseGuard({
      name: 'github-refresh',
      holderId: 'heartbeat-holder',
      ttlMs: 300_000,
      now: () => '2026-07-03T12:00:00.000Z',
      acquire: () => true,
      renew: () => {
        renewCalls++;
        return false;
      },
      release: () => {
        releaseCalls++;
        return true;
      },
      scheduleHeartbeat(callback, intervalMs) {
        heartbeat = callback;
        scheduledInterval = intervalMs;
        return handle;
      },
      cancelHeartbeat(received) {
        assert.equal(received, handle);
        cancelCalls++;
      },
      onFailure(error) {
        reportedFailure = error;
        abortRefresh(error);
      },
    });

    lease.acquire();
    lease.startHeartbeat(__refreshTest.REFRESH_LEASE_HEARTBEAT_MS);
    assert.equal(scheduledInterval, 60_000);
    assert.ok(heartbeat);
    heartbeat();

    assert.equal(renewCalls, 1);
    assert.equal(lease.heartbeatFailed(), true);
    assert.match(reportedFailure?.message ?? '', /was lost before periodic heartbeat/);
    assert.equal(refreshController.signal.aborted, true);
    assert.equal(refreshController.signal.reason, reportedFailure);
    let writeAttempted = false;
    assert.throws(() => {
      lease.assertHeld('test evidence write');
      writeAttempted = true;
    }, /was lost before periodic heartbeat/);
    assert.equal(writeAttempted, false);
    assert.equal(cancelCalls, 1);
    assert.equal(lease.release(), true);
    assert.equal(releaseCalls, 1);
    assert.equal(cancelCalls, 1);
  });

  it('preserves an earlier refresh cancellation when a later lease heartbeat fails', () => {
    const controller = new AbortController();
    const shutdownReason = new Error('shutdown already requested');
    const leaseFailure = new Error('lease heartbeat failed later');
    controller.abort(shutdownReason);

    __refreshTest.abortRefreshOnLeaseFailure(controller)(leaseFailure);

    assert.equal(controller.signal.reason, shutdownReason);
  });

  it('cancels and drains all issue-page evidence siblings after one fetch fails', async () => {
    const primary = new Error('issue comment evidence failed');
    const started: string[] = [];
    const finalized: string[] = [];
    const slow = (name: string) => async (signal: AbortSignal) => {
      started.push(name);
      try {
        await abortableDelay(30_000, signal);
        return name;
      } finally {
        finalized.push(name);
      }
    };

    await assert.rejects(
      __refreshTest.runIssuePageEvidenceFetchGroup([
        slow('metadata'),
        async () => {
          started.push('comments');
          throw primary;
        },
        slow('labels'),
        slow('state'),
      ] as const, new AbortController().signal),
      (error) => error === primary,
    );

    assert.deepEqual(started.sort(), ['comments', 'labels', 'metadata', 'state']);
    assert.deepEqual(finalized.sort(), ['labels', 'metadata', 'state']);
  });

  it('rolls back a refresh write when the lease fails at the commit fence', () => {
    const key = 'refresh_test_commit_fence';
    const stages: string[] = [];

    assert.throws(
      () => __refreshTest.runLeaseFencedWrite(
        'test metadata',
        (stage) => {
          stages.push(stage);
          if (stage === 'test metadata commit') {
            throw new Error('lease lost before commit');
          }
        },
        () => dbModule.setMeta(key, 'must-roll-back'),
      ),
      /lease lost before commit/,
    );

    assert.deepEqual(stages, [
      'test metadata persistence',
      'test metadata transaction',
      'test metadata commit',
    ]);
    assert.equal(dbModule.getMeta(key), null);
  });

  it('cleans up a healthy heartbeat when the lease is released', () => {
    let cancelCalls = 0;
    const lease = __refreshTest.createRefreshLeaseGuard({
      name: 'github-refresh',
      holderId: 'healthy-holder',
      ttlMs: 300_000,
      now: () => '2026-07-03T12:00:00.000Z',
      acquire: () => true,
      renew: () => true,
      release: () => true,
      scheduleHeartbeat: () => 'heartbeat-handle',
      cancelHeartbeat(handle) {
        assert.equal(handle, 'heartbeat-handle');
        cancelCalls++;
      },
    });

    lease.acquire();
    lease.startHeartbeat(1_000);
    assert.equal(lease.release(), true);
    assert.equal(cancelCalls, 1);
  });

  it('releases the registered active lease exactly once during shutdown cleanup', () => {
    let releaseCalls = 0;
    const registry = __refreshTest.createRefreshLeaseRegistry();
    const lease = {
      release() {
        releaseCalls++;
        return true;
      },
    };

    registry.set(lease);
    assert.equal(registry.release(), true);
    assert.equal(registry.release(), false);
    registry.clear(lease);
    assert.equal(releaseCalls, 1);
  });

  it('keeps the lease until an active refresh settles during graceful shutdown', async () => {
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      const events: string[] = [];
      let closeServer: ((error?: Error) => void) | null = null;
      let resolveRefresh!: () => void;
      const refreshSettled = new Promise<void>((resolve) => {
        resolveRefresh = resolve;
      });
      const shutdown = createGracefulShutdown({
        clearRefreshTimer: () => events.push('timer'),
        cancelRefresh: () => {
          events.push('abort');
          return true;
        },
        waitForRefresh: () => refreshSettled,
        releaseRefreshResources: () => {
          events.push('lease');
          return true;
        },
        closeServer(callback) {
          events.push('server');
          closeServer = callback;
        },
        closeDatabase: () => events.push('database'),
        exit: (code) => events.push(`exit:${code}`),
        scheduleForceExit: () => 'force-exit',
        cancelForceExit: (handle) => events.push(`cancel:${String(handle)}`),
        log: () => undefined,
        logError: () => undefined,
      });

      shutdown(signal);
      assert.deepEqual(events, ['timer', 'abort', 'server']);
      assert.ok(closeServer);
      closeServer();
      await Promise.resolve();
      assert.deepEqual(events, ['timer', 'abort', 'server']);
      resolveRefresh();
      await new Promise((resolve) => setImmediate(resolve));
      assert.deepEqual(events, [
        'timer',
        'abort',
        'server',
        'lease',
        'cancel:force-exit',
        'database',
        'exit:0',
      ]);
    }
  });

  it('still drains an active refresh before closing SQLite when server close fails', async () => {
    const events: string[] = [];
    let closeServer: ((error?: Error) => void) | null = null;
    let resolveRefresh!: () => void;
    const refreshSettled = new Promise<void>((resolve) => {
      resolveRefresh = resolve;
    });
    const shutdown = createGracefulShutdown({
      clearRefreshTimer: () => events.push('timer'),
      cancelRefresh: () => {
        events.push('abort');
        return true;
      },
      waitForRefresh: () => refreshSettled,
      releaseRefreshResources: () => {
        events.push('lease');
        return true;
      },
      closeServer(callback) {
        events.push('server');
        closeServer = callback;
      },
      closeDatabase: () => events.push('database'),
      exit: (code) => events.push(`exit:${code}`),
      scheduleForceExit: () => 'force-exit',
      cancelForceExit: (handle) => events.push(`cancel:${String(handle)}`),
      log: () => undefined,
      logError: (message) => events.push(`error:${message}`),
    });

    shutdown('SIGTERM');
    assert.deepEqual(events, ['timer', 'abort', 'server']);
    assert.ok(closeServer);
    closeServer(new Error('listener teardown failed'));
    await Promise.resolve();
    assert.deepEqual(events, [
      'timer',
      'abort',
      'server',
      'error:[shutdown] server close failed: listener teardown failed',
    ]);

    resolveRefresh();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(events, [
      'timer',
      'abort',
      'server',
      'error:[shutdown] server close failed: listener teardown failed',
      'lease',
      'cancel:force-exit',
      'database',
      'exit:1',
    ]);
  });

  it('treats an already-closed server as an idempotent shutdown success', async () => {
    const events: string[] = [];
    let closeServer: ((error?: Error) => void) | null = null;
    const shutdown = createGracefulShutdown({
      clearRefreshTimer: () => events.push('timer'),
      cancelRefresh: () => {
        events.push('abort');
        return false;
      },
      waitForRefresh: async () => undefined,
      releaseRefreshResources: () => {
        events.push('lease');
        return false;
      },
      closeServer(callback) {
        events.push('server');
        closeServer = callback;
      },
      closeDatabase: () => events.push('database'),
      exit: (code) => events.push(`exit:${code}`),
      scheduleForceExit: () => 'force-exit',
      cancelForceExit: (handle) => events.push(`cancel:${String(handle)}`),
      log: () => undefined,
      logError: (message) => events.push(`error:${message}`),
    });

    shutdown('SIGTERM');
    assert.ok(closeServer);
    const error = Object.assign(new Error('Server is not running.'), {
      code: 'ERR_SERVER_NOT_RUNNING',
    });
    closeServer(error);
    await new Promise((resolve) => setImmediate(resolve));

    assert.deepEqual(events, [
      'timer',
      'abort',
      'server',
      'lease',
      'cancel:force-exit',
      'database',
      'exit:0',
    ]);
  });

  it('fetches comments only for issue rows that can overlap monitored releases', () => {
    const relevant = issue(2, {
      number: 1001,
      created_at: '2026-07-02T00:00:00.000Z',
      closed_at: null,
    });
    const irrelevant = issue(4, {
      number: 1002,
      created_at: '2026-01-01T00:00:00.000Z',
      closed_at: '2026-01-02T00:00:00.000Z',
    });
    const targets = __refreshTest.issuePageEvidenceTargets(
      [relevant, irrelevant],
      (candidate) => candidate.number === relevant.number,
    );

    assert.deepEqual(targets, {
      commentIssueNumbers: [1001],
      metadataOnlyIssueNumbers: [1002],
    });
    assert.equal(__refreshTest.issueRowFromRemoteMetadata(irrelevant).comments, 4);
  });

  it('treats metadata-only row mutations as changed for incremental early-stop decisions', () => {
    const remote = issue(4, {
      number: 1003,
      title: 'Original title',
      created_at: '2026-01-01T00:00:00.000Z',
      closed_at: '2026-01-02T00:00:00.000Z',
    });
    const row = __refreshTest.issueRowFromRemoteMetadata(remote);

    assert.equal(__refreshTest.issueRemoteMetadataMatchesPersisted(row, row), true);
    assert.equal(__refreshTest.issueRemoteMetadataMatchesPersisted({
      ...row,
      title: 'Older stored title',
    }, row), false);
    assert.equal(__refreshTest.issueRemoteMetadataMatchesPersisted(undefined, row), false);
  });

  it('reconciles complete staged metadata drift even when comment and state tokens match', () => {
    const staged = issue(0, {
      number: 1004,
      title: 'Staged title',
      labels: [{ name: 'bug' }],
    });
    const remote = {
      ...staged,
      title: 'Current title',
      body: 'Current body',
      reaction_total: 3,
      labels: [{ name: 'confirmed' }],
    };
    const stableSnapshot = snapshot(0, [], {
      issueNumber: staged.number,
      issueUpdatedAt: staged.updated_at,
    });
    const stableState = fixEvidence(staged.number);

    assert.equal(
      __refreshTest.stagedIssueRequiresMetadataReconciliation(
        staged,
        staged,
        stableSnapshot,
        stableState,
      ),
      false,
    );
    assert.equal(
      __refreshTest.stagedIssueRequiresMetadataReconciliation(
        staged,
        remote,
        stableSnapshot,
        stableState,
      ),
      true,
    );
  });

  it('requires exact comment counts and unique comment IDs', () => {
    assert.deepEqual(
      __refreshTest.commentCompleteness(2, [comment(101), comment(102)]),
      {
        complete: true,
        expectedCount: 2,
        fetchedCount: 2,
        uniqueCount: 2,
        invalidIdIndexes: [],
        duplicateIds: [],
      },
    );
    assert.equal(__refreshTest.commentCompleteness(2, [comment(101)]).complete, false);
    assert.equal(__refreshTest.commentCompleteness(1, [comment(101), comment(102)]).complete, false);
    assert.deepEqual(
      __refreshTest.commentCompleteness(2, [comment(101), comment(101)]),
      {
        complete: false,
        expectedCount: 2,
        fetchedCount: 2,
        uniqueCount: 1,
        invalidIdIndexes: [],
        duplicateIds: [101],
      },
    );
    assert.deepEqual(
      __refreshTest.commentCompleteness(1, [{ ...comment(101), id: 0 }]),
      {
        complete: false,
        expectedCount: 1,
        fetchedCount: 1,
        uniqueCount: 0,
        invalidIdIndexes: [0],
        duplicateIds: [],
      },
    );
  });

  it('records monitored-window comment completeness failures with requirement provenance', () => {
    const captured: Array<Record<string, unknown>> = [];
    const incomplete = snapshot(2, [comment(101)], { issueNumber: 1101 });
    const message = __refreshTest.recordCommentCompletenessFailure({
      snapshot: incomplete,
      pageContext: {
        page: 7,
        commentRequirement: 'monitored_release_overlap',
        requiredCommentIssueNumbers: [1101],
        metadataOnlyIssueCount: 99,
      },
      recordFailure(source, scope, error, context) {
        captured.push({ source, scope, error, context });
        return `${source}:${scope}`;
      },
    });

    assert.equal(message, 'issue-comments-count-mismatch:issue #1101');
    assert.equal(captured.length, 1);
    assert.equal(captured[0].source, 'issue-comments-count-mismatch');
    assert.deepEqual(captured[0].context, {
      page: 7,
      commentRequirement: 'monitored_release_overlap',
      requiredCommentIssueNumbers: [1101],
      metadataOnlyIssueCount: 99,
      issueNumber: 1101,
      issueUpdatedAt: incomplete.issueUpdatedAt,
      expectedCommentCount: 2,
      fetchedCommentCount: 1,
      uniqueCommentCount: 1,
      invalidCommentIdIndexes: [],
      duplicateCommentIds: [],
      expectedCountSource: 'snapshot.totalCount',
      fetchedCountSource: 'snapshot.comments',
      digestSource: 'snapshot.commentsDigest',
    });
  });

  it('records comment count and duplicate-ID mismatches as durable score blockers', () => {
    const records: Array<Record<string, unknown>> = [];
    const failures: string[] = [];
    const recordFailure = (
      source: string,
      scope: string | null,
      error: unknown,
      context: Record<string, unknown>,
    ) => {
      const message = `[${source}] ${scope} failed: ${(error as Error).message}`;
      records.push({ source, scope, context, message, scoringBlocking: true });
      failures.push(message);
      return message;
    };

    assert.equal(__refreshTest.recordCommentCompletenessFailure({
      snapshot: snapshot(2, [comment(101), comment(102)]),
      pageContext: { page: 1 },
      recordFailure,
    }), null);
    __refreshTest.recordCommentCompletenessFailure({
      snapshot: snapshot(2, [comment(101)]),
      pageContext: { page: 1 },
      recordFailure,
    });
    __refreshTest.recordCommentCompletenessFailure({
      snapshot: snapshot(2, [comment(101), comment(101)]),
      pageContext: { page: 1 },
      recordFailure,
    });
    __refreshTest.recordCommentCompletenessFailure({
      snapshot: snapshot(1, [{ ...comment(101), id: 0 }]),
      pageContext: { page: 1 },
      recordFailure,
    });

    assert.equal(records.length, 3);
    assert.equal(records[0].source, 'issue-comments-count-mismatch');
    assert.equal(records[1].source, 'issue-comments-duplicate-ids');
    assert.equal(records[2].source, 'issue-comments-invalid-ids');
    assert.deepEqual(records[1].context, {
      page: 1,
      issueNumber: 42,
      issueUpdatedAt: '2026-07-02T00:00:00.000Z',
      expectedCommentCount: 2,
      fetchedCommentCount: 2,
      uniqueCommentCount: 1,
      invalidCommentIdIndexes: [],
      duplicateCommentIds: [101],
      expectedCountSource: 'snapshot.totalCount',
      fetchedCountSource: 'snapshot.comments',
      digestSource: 'snapshot.commentsDigest',
    });
    assert.equal(__refreshTest.shouldRefuseScoreAfterEvidenceFailures(failures), true);
  });

  it('never replaces the independently sourced expected comment count with a partial fetch', () => {
    const complete = __refreshTest.issueCommentSnapshot(
      snapshot(2, [comment(101), comment(102)]),
    );
    assert.equal(complete.comment_count, 2);
    assert.equal(complete.fetched_comment_count, 2);
    assert.equal(
      complete.schema_version,
      AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    );

    assert.throws(
      () => __refreshTest.issueCommentSnapshot(snapshot(2, [comment(101)])),
      /expected 2, fetched 1/,
    );
    assert.throws(
      () => __refreshTest.issueCommentSnapshot(snapshot(2, [comment(101), comment(101)])),
      /duplicate IDs 101/,
    );
    assert.throws(
      () => __refreshTest.issueCommentSnapshot(snapshot(1, [{ ...comment(101), id: 0 }])),
      /invalid ID indexes 0/,
    );
  });

  it('retries full issue, label, fix, and snapshot fetches until issue metadata matches', async () => {
    let issueFetches = 0;
    const sleeps: number[] = [];
    const stableSnapshot = snapshot(1, [comment(101)]);
    const evidence = await __refreshTest.fetchReconciledIssueEvidence([42], {
      maxAttempts: 3,
      dependencies: {
        async listIssues() {
          issueFetches++;
          return new Map([[
            42,
            issueFetches === 1
              ? issue(0, { updated_at: '2026-07-01T00:00:00.000Z' })
              : issue(1),
          ]]);
        },
        async listSnapshots() {
          return new Map([[42, stableSnapshot]]);
        },
        async listLabelEvidence() {
          return new Map([[42, labelEvidenceSnapshot(issue(1), [])]]);
        },
        async listFixEvidence() {
          return new Map([[42, fixEvidence(42)]]);
        },
        async sleep(ms) {
          sleeps.push(ms);
        },
      },
    });

    assert.equal(issueFetches, 2);
    assert.deepEqual(sleeps, [100]);
    assert.equal(evidence.get(42)?.issue.comments, 1);
    assert.equal(evidence.get(42)?.snapshot.commentsDigest, stableSnapshot.commentsDigest);
  });

  it('retries reconciliation until state snapshot metadata matches the issue and comment snapshot', async () => {
    let stateFetches = 0;
    const sleeps: number[] = [];
    const stableSnapshot = snapshot(1, [comment(101)]);
    const evidence = await __refreshTest.fetchReconciledIssueEvidence([42], {
      maxAttempts: 3,
      dependencies: {
        async listIssues() {
          return new Map([[42, issue(1)]]);
        },
        async listSnapshots() {
          return new Map([[42, stableSnapshot]]);
        },
        async listLabelEvidence() {
          return new Map([[42, labelEvidenceSnapshot(issue(1), [])]]);
        },
        async listFixEvidence() {
          stateFetches++;
          const stateEvidence = fixEvidence(42);
          if (stateFetches === 1) {
            stateEvidence.stateSnapshot = {
              ...stateEvidence.stateSnapshot,
              issueUpdatedAt: '2026-07-01T23:59:59.000Z',
            };
          }
          return new Map([[42, stateEvidence]]);
        },
        async sleep(ms) {
          sleeps.push(ms);
        },
      },
    });

    assert.equal(stateFetches, 2);
    assert.deepEqual(sleeps, [100]);
    assert.equal(
      evidence.get(42)?.fixEvidence.stateSnapshot.issueUpdatedAt,
      stableSnapshot.issueUpdatedAt,
    );
  });

  it('retries cross-repository label evidence and fails closed when it never converges', async () => {
    let labelFetches = 0;
    const sleeps: number[] = [];
    const stableIssue = issue(1);
    const stableSnapshot = snapshot(1, [comment(101)]);
    const evidence = await __refreshTest.fetchReconciledIssueEvidence([42], {
      maxAttempts: 3,
      dependencies: {
        async listIssues() {
          return new Map([[42, stableIssue]]);
        },
        async listSnapshots() {
          return new Map([[42, stableSnapshot]]);
        },
        async listLabelEvidence() {
          labelFetches++;
          const labels = labelEvidenceSnapshot(stableIssue, []);
          return new Map([[
            42,
            labelFetches === 1
              ? { ...labels, repositoryNodeId: 'REPO-node-other' }
              : labels,
          ]]);
        },
        async listFixEvidence() {
          return new Map([[42, fixEvidence(42)]]);
        },
        async sleep(ms) {
          sleeps.push(ms);
        },
      },
    });

    assert.equal(labelFetches, 2);
    assert.deepEqual(sleeps, [100]);
    assert.equal(
      evidence.get(42)?.labelEvidenceSnapshot.repositoryNodeId,
      'REPO-node-openclaw',
    );

    await assert.rejects(
      __refreshTest.fetchReconciledIssueEvidence([42], {
        maxAttempts: 2,
        dependencies: {
          async listIssues() {
            return new Map([[42, stableIssue]]);
          },
          async listSnapshots() {
            return new Map([[42, stableSnapshot]]);
          },
          async listLabelEvidence() {
            return new Map([[
              42,
              {
                ...labelEvidenceSnapshot(stableIssue, []),
                repositoryNodeId: 'REPO-node-other',
              },
            ]]);
          },
          async listFixEvidence() {
            return new Map([[42, fixEvidence(42)]]);
          },
          async sleep() {},
        },
      }),
      (error: unknown) => {
        assert.match(String(error), /repositoryNodeId=REPO-node-other/);
        assert.match(String(error), /commentSnapshot=\(repositoryNodeId=REPO-node-openclaw/);
        assert.match(String(error), /fixEvidence=\(repositoryNodeId=REPO-node-openclaw/);
        assert.match(String(error), /stateSnapshot=\(repositoryNodeId=REPO-node-openclaw/);
        return true;
      },
    );
  });

  it('builds the complete deduplicated pre-closure target union across monitored releases', () => {
    const targets = __refreshTest.closureTargetsForReleases(
      [{ tag: 'v3' }, { tag: 'v2' }, { tag: 'v1' }],
      (tag: string) => ({
        v3: [{ number: 3 }, { number: 2 }, { number: 0 }],
        v2: [{ number: 2 }, { number: 1 }],
        v1: [{ number: 1 }, { number: Number.NaN }],
      })[tag] ?? [],
    );

    assert.deepEqual(targets.issueNumbers, [3, 2, 1]);
    assert.deepEqual([...targets.issueNumbersByTag.get('v3') ?? []], [3, 2]);
    assert.deepEqual([...targets.issueNumbersByTag.get('v2') ?? []], [2, 1]);
    assert.deepEqual([...targets.issueNumbersByTag.get('v1') ?? []], [1]);
  });

  it('persists target reconciliation in bounded chunks and aggregates progress', async () => {
    const calls: number[][] = [];
    const progress: Array<{ completed: number; total: number; classified: number }> = [];
    const result = await __refreshTest.reconcileIssueCommentSnapshotChunks({
      issueNumbers: [1, 2, 3],
      releaseTags: ['v2099.7.1'],
      chunkSize: 2,
      reconcile: (async ({ issueNumbers }: { issueNumbers: number[] }) => {
        calls.push(issueNumbers);
        return {
          snapshotsByIssue: new Map(issueNumbers.map((issueNumber) => [
            issueNumber,
            snapshot(0, [], { issueNumber }),
          ])),
          issuesByNumber: new Map(),
          labelEventsByIssue: new Map(),
          labelEvidenceSnapshotsByIssue: new Map(),
          stateEvidenceByIssue: new Map(),
          reconciledIssueNumbers: issueNumbers,
          classifiedIssueNumbers: issueNumbers,
        };
      }) as any,
      onChunk: (value) => progress.push(value),
    });
    assert.deepEqual(calls, [[1, 2], [3]]);
    assert.deepEqual(result.classifiedIssueNumbers, [1, 2, 3]);
    assert.deepEqual(progress, [
      { completed: 2, total: 3, classified: 2 },
      { completed: 3, total: 3, classified: 1 },
    ]);
  });

  it('reconciles closure snapshot drift repeatedly until reruns converge', async () => {
    const firstSnapshot = snapshot(0, [], { issueNumber: 4301 });
    const secondSnapshot = snapshot(0, [], { issueNumber: 4302 });
    const context = closureRunContext([
      [4301, firstSnapshot],
      [4302, secondSnapshot],
    ]);
    const unresolved = [[4301], [4302], []];
    const reruns: Array<{ issueNumbers: number[]; attempt: number }> = [];

    const result = await __refreshTest.reconcileClosureSnapshotDrift({
      runContext: context,
      releaseTags: ['v2099.7.1'],
      unresolved: () => unresolved.shift() ?? [],
      reconcile: (async ({ issueNumbers }: { issueNumbers: number[] }) => ({
        snapshotsByIssue: new Map(issueNumbers.map((issueNumber) => [
          issueNumber,
          context.commentSnapshotsByIssue.get(issueNumber)!,
        ])),
        issuesByNumber: new Map(),
        labelEventsByIssue: new Map(),
        labelEvidenceSnapshotsByIssue: new Map(),
        stateEvidenceByIssue: new Map(issueNumbers.map((issueNumber) => [
          issueNumber,
          fixEvidence(issueNumber),
        ])),
        reconciledIssueNumbers: issueNumbers,
        classifiedIssueNumbers: issueNumbers,
      })) as any,
      async rerunAffected(issueNumbers, attempt) {
        reruns.push({ issueNumbers, attempt });
      },
    });

    assert.equal(result.attempts, 2);
    assert.deepEqual(result.reconciledIssueNumbers, [4301, 4302]);
    assert.deepEqual(result.classifiedIssueNumbers, [4301, 4302]);
    assert.deepEqual(reruns, [
      { issueNumbers: [4301], attempt: 1 },
      { issueNumbers: [4302], attempt: 2 },
    ]);
    assert.equal(context.commentsByIssue.get(4301), firstSnapshot.comments);
    assert.equal(context.fixEvidenceByIssue.get(4302)?.issueNumber, 4302);
  });

  it('fails closed when closure snapshot drift does not converge within the bound', async () => {
    const issueNumber = 4303;
    const stableSnapshot = snapshot(0, [], { issueNumber });
    const context = closureRunContext([[issueNumber, stableSnapshot]]);
    let reruns = 0;

    await assert.rejects(
      __refreshTest.reconcileClosureSnapshotDrift({
        runContext: context,
        releaseTags: ['v2099.7.1'],
        maxAttempts: 2,
        unresolved: () => [issueNumber],
        reconcile: (async () => ({
          snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
          issuesByNumber: new Map(),
          labelEventsByIssue: new Map(),
          labelEvidenceSnapshotsByIssue: new Map(),
          stateEvidenceByIssue: new Map(),
          reconciledIssueNumbers: [issueNumber],
          classifiedIssueNumbers: [],
        })) as any,
        async rerunAffected() {
          reruns++;
        },
      }),
      /did not converge after 2 attempts for #4303/,
    );
    assert.equal(reruns, 2);
  });

  it('fetches and persists comment and state snapshots for zero-count issues', async () => {
    const issueNumber = 4200;
    dbModule.upsertIssue(issueRow(issueNumber, 0, '2026-07-02T00:00:00.000Z'));
    const fetchedIssueNumbers: number[][] = [];
    const zeroSnapshot = snapshot(0, [], { issueNumber });
    dbModule.upsertClassification(
      issueNumber,
      classification(),
      zeroSnapshot.issueUpdatedAt,
      PROMPT_VERSION,
      zeroSnapshot.commentsDigest,
      dbModule.classifierSourceIdentity(['v2099.7.1'], PROMPT_VERSION),
    );

    const result = await reconcileIssueCommentSnapshots({
      issueNumbers: [issueNumber],
      releaseTags: ['v2099.7.1'],
      dependencies: {
        async listSnapshots(issueNumbers) {
          fetchedIssueNumbers.push(issueNumbers);
          return new Map([[issueNumber, zeroSnapshot]]);
        },
        async listIssues() {
          return new Map([[issueNumber, issue(0, { number: issueNumber })]]);
        },
        async listLabelEvidence() {
          return new Map([[
            issueNumber,
            labelEvidenceSnapshot(issue(0, { number: issueNumber }), []),
          ]]);
        },
        async listFixEvidence() {
          return new Map([[issueNumber, fixEvidence(issueNumber)]]);
        },
        async classify() {
          throw new Error('current classification must not be recomputed for a state-only reconciliation');
        },
      },
    });

    assert.deepEqual(fetchedIssueNumbers, [[issueNumber], [issueNumber]]);
    assert.deepEqual(result.reconciledIssueNumbers, [issueNumber]);
    assert.deepEqual(result.classifiedIssueNumbers, []);
    const stored = db.prepare(`
      SELECT comment_count, fetched_comment_count, comments_digest, issue_updated_at, schema_version, verified_at
      FROM issue_comment_snapshots
      WHERE issue_number=?
    `).get(issueNumber) as any;
    assert.equal(stored.comment_count, 0);
    assert.equal(stored.fetched_comment_count, 0);
    assert.equal(stored.comments_digest, zeroSnapshot.commentsDigest);
    assert.equal(stored.issue_updated_at, zeroSnapshot.issueUpdatedAt);
    assert.equal(
      stored.schema_version,
      AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    );
    assert.ok(Number.isFinite(Date.parse(stored.verified_at)));
    assert.equal(dbModule.getIssueStateEventSnapshot(issueNumber)?.total_count, 0);
  });

  it('atomically reconciles issue rows, evidence, snapshots, and digest-bound classification', async () => {
    const issueNumber = 4201;
    dbModule.upsertIssue(issueRow(issueNumber, 0, '2026-07-01T00:00:00.000Z'));
    const stableSnapshot = snapshot(1, [comment(201)], { issueNumber });
    const fullIssue = issue(1, {
      number: issueNumber,
      body: 'Observed on v2099.7.1 with complete reproduction steps.',
      labels: [{ name: 'bug' }],
    });
    const stableFixEvidence = fixEvidence(issueNumber, true);
    let classifiedComments: number[] = [];

    const result = await reconcileIssueCommentSnapshots({
      issueNumbers: [issueNumber],
      releaseTags: ['v2099.7.1'],
      snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
      dependencies: reconciliationDependencies({
        issueNumber,
        issue: fullIssue,
        snapshot: stableSnapshot,
        labelEvents: [
          labelEvent(issueNumber, `label-${issueNumber}`),
        ],
        fixEvidence: stableFixEvidence,
        async classify(_issue, comments) {
          classifiedComments = comments.map((row) => row.id);
          return classification();
        },
      }),
    });

    assert.deepEqual(classifiedComments, [201]);
    assert.deepEqual(result.reconciledIssueNumbers, [issueNumber]);
    assert.deepEqual(result.classifiedIssueNumbers, [issueNumber]);
    const storedIssue = dbModule.getIssue(issueNumber);
    assert.equal(storedIssue?.comments, stableSnapshot.totalCount);
    assert.equal(storedIssue?.updated_at, stableSnapshot.issueUpdatedAt);
    assert.equal(storedIssue?.body, 'Observed on v2099.7.1 with complete reproduction steps.');
    assert.equal(storedIssue?.labels, '["bug"]');
    const storedSnapshot = db.prepare(`
      SELECT comment_count, comments_digest, issue_updated_at, schema_version, verified_at
      FROM issue_comment_snapshots
      WHERE issue_number=?
    `).get(issueNumber) as any;
    assert.equal(storedSnapshot.comment_count, stableSnapshot.totalCount);
    assert.equal(storedSnapshot.comments_digest, stableSnapshot.commentsDigest);
    assert.equal(storedSnapshot.issue_updated_at, stableSnapshot.issueUpdatedAt);
    assert.equal(
      storedSnapshot.schema_version,
      AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    );
    assert.ok(Number.isFinite(Date.parse(storedSnapshot.verified_at)));
    const storedClassification = db.prepare(`
      SELECT classified_updated_at, classified_comments_digest, classification_origin
      FROM classifications
      WHERE issue_number=?
    `).get(issueNumber) as any;
    assert.equal(storedClassification.classified_updated_at, stableSnapshot.issueUpdatedAt);
    assert.equal(storedClassification.classified_comments_digest, stableSnapshot.commentsDigest);
    assert.equal(storedClassification.classification_origin, 'legacy_or_manual');
    assert.equal(
      (db.prepare(`SELECT COUNT(*) AS count FROM issue_label_events WHERE issue_number=?`).get(issueNumber) as any).count,
      1,
    );
    assert.equal(
      (db.prepare(`SELECT COUNT(*) AS count FROM issue_closure_events WHERE issue_number=?`).get(issueNumber) as any).count,
      1,
    );
    const expectedClaims = __refreshTest.closureClaimExtractionForIssue({
      issue: fullIssue,
      snapshot: stableSnapshot,
      fixEvidence: stableFixEvidence,
    });
    assert.ok(expectedClaims.candidates.length > 0);
    const expectedCandidateRows = expectedClaims.candidates
      .map((candidate) => {
        const entry = buildClosureClaimCandidateLedgerEntry(candidate);
        return {
          candidate_id: entry.candidateId,
          content_hash: entry.contentHash,
        };
      })
      .sort((left, right) =>
        compareCodePointStrings(left.candidate_id, right.candidate_id));
    const storedCandidateRows = db.prepare(`
      SELECT candidate_id, content_hash
      FROM closure_claim_candidates
      WHERE issue_number=?
      ORDER BY candidate_id
    `).all(issueNumber)
      .map((row) => ({ ...(row as Record<string, unknown>) })) as Array<{
        candidate_id: string;
        content_hash: string;
      }>;
    assert.deepEqual(storedCandidateRows, expectedCandidateRows);

    const expectedSources = new Map(
      expectedClaims.candidates.map((candidate) => {
        const entry = buildClosureClaimSourceSnapshotLedgerEntry(candidate);
        return [entry.sourceIdentity, {
          source_identity: entry.sourceIdentity,
          content_hash: entry.contentHash,
        }] as const;
      }),
    );
    const storedSourceRows = db.prepare(`
      SELECT source_identity, content_hash
      FROM closure_claim_source_snapshots
      WHERE issue_number=?
      ORDER BY source_identity
    `).all(issueNumber)
      .map((row) => ({ ...(row as Record<string, unknown>) })) as Array<{
        source_identity: string;
        content_hash: string;
      }>;
    assert.deepEqual(
      storedSourceRows,
      [...expectedSources.values()].sort((left, right) =>
        compareCodePointStrings(left.source_identity, right.source_identity)),
    );
  });

  it('replays the exact closure candidate and source set idempotently', () => {
    const issueNumber = 4240;
    const sourceIssue = issue(0, {
      number: issueNumber,
      body: 'This was fixed in v2099.7.1.',
    });
    const stableSnapshot = snapshot(0, [], { issueNumber });
    const stableFixEvidence = fixEvidence(issueNumber);
    dbModule.upsertIssue({
      ...issueRow(issueNumber, 0, stableSnapshot.issueUpdatedAt),
      body: sourceIssue.body,
    });
    dbModule.upsertIssueCommentSnapshot(
      __refreshTest.issueCommentSnapshot(stableSnapshot),
    );
    __refreshTest.persistIssueStateEvidence(stableFixEvidence);

    const first = dbModule.runInWriteTransaction(() =>
      __refreshTest.persistClosureClaimEvidenceForIssue({
        issue: sourceIssue,
        snapshot: stableSnapshot,
        fixEvidence: stableFixEvidence,
        capturedAt: '2026-07-04T12:00:00.000Z',
      }));
    assert.ok(first.extraction.candidates.length > 0);
    assert.equal(first.persistence.candidatePersistence.insertedSourceCount, 1);
    assert.equal(
      first.persistence.candidatePersistence.insertedCandidateCount,
      first.extraction.candidates.length,
    );
    assert.equal(first.persistence.insertedReceiptCount, 1);

    const replay = dbModule.runInWriteTransaction(() =>
      __refreshTest.persistClosureClaimEvidenceForIssue({
        issue: sourceIssue,
        snapshot: stableSnapshot,
        fixEvidence: stableFixEvidence,
        capturedAt: '2026-07-04T13:00:00.000Z',
      }));
    assert.equal(replay.persistence.candidatePersistence.insertedSourceCount, 0);
    assert.equal(replay.persistence.candidatePersistence.replayedSourceCount, 1);
    assert.equal(replay.persistence.candidatePersistence.insertedCandidateCount, 0);
    assert.equal(
      replay.persistence.candidatePersistence.replayedCandidateCount,
      first.extraction.candidates.length,
    );
    assert.deepEqual(
      replay.persistence.candidatePersistence.candidateIds,
      first.persistence.candidatePersistence.candidateIds,
    );
    assert.equal(replay.persistence.insertedReceiptCount, 0);
    assert.equal(replay.persistence.replayedReceiptCount, 1);
    assert.equal(
      (db.prepare(`
        SELECT COUNT(*) AS count
        FROM closure_claim_source_snapshots
        WHERE issue_number=?
      `).get(issueNumber) as { count: number }).count,
      1,
    );
    assert.equal(
      (db.prepare(`
        SELECT COUNT(*) AS count
        FROM closure_claim_candidates
        WHERE issue_number=?
      `).get(issueNumber) as { count: number }).count,
      first.extraction.candidates.length,
    );
    assert.equal(
      (db.prepare(`
        SELECT COUNT(*) AS count
        FROM closure_claim_extraction_receipts
        WHERE issue_number=?
      `).get(issueNumber) as { count: number }).count,
      1,
    );
  });

  it('rolls back all reconciled issue evidence when closure source extraction rejects', async () => {
    const issueNumber = 4241;
    const sourceIssue = issue(0, {
      number: issueNumber,
      body: 'This was fixed in v2099.7.1.',
      created_at: 'not-a-timestamp',
      labels: [{ name: 'bug' }],
    });
    const stableSnapshot = snapshot(0, [], { issueNumber });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers: [issueNumber],
        releaseTags: ['v2099.7.1'],
        snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
        dependencies: reconciliationDependencies({
          issueNumber,
          issue: sourceIssue,
          snapshot: stableSnapshot,
          labelEvents: [labelEvent(issueNumber, `label-${issueNumber}`)],
          fixEvidence: fixEvidence(issueNumber),
          async classify() {
            return classification();
          },
        }),
      }),
      /closure claim extraction rejected 1 source.*invalid_source/,
    );

    assertNoPersistedIssueEvidence(issueNumber);
  });

  it('fails closed if extraction ever returns a display-only closure candidate', () => {
    const issueNumber = 4242;
    const sourceIssue = issue(0, {
      number: issueNumber,
      body: 'This was fixed in v2099.7.1.',
    });
    const stableSnapshot = snapshot(0, [], { issueNumber });
    const extraction = __refreshTest.closureClaimExtractionForIssue({
      issue: sourceIssue,
      snapshot: stableSnapshot,
      fixEvidence: fixEvidence(issueNumber),
    });
    assert.ok(extraction.candidates.length > 0);
    const displayOnlyCandidate = {
      ...extraction.candidates[0],
      candidateId: null,
      sourceIdentity: null,
      canonicalSourceIdentityJson: null,
      eligibility: 'display_only' as const,
      identityProblems: ['missing_actor_node_id'] as const,
    };

    assert.throws(
      () => __refreshTest.acceptedClosureClaimExtraction(issueNumber, {
        ...extraction,
        candidates: [displayOnlyCandidate],
      }),
      /identity-incomplete candidate.*missing_actor_node_id/,
    );
  });

  it('fails closed before writes when stabilized issue state evidence is missing', async () => {
    const issueNumber = 4243;
    const sourceIssue = issue(0, { number: issueNumber });
    const stableSnapshot = snapshot(0, [], { issueNumber });
    const dependencies = reconciliationDependencies({
      issueNumber,
      issue: sourceIssue,
      snapshot: stableSnapshot,
      labelEvents: [],
      fixEvidence: fixEvidence(issueNumber),
      async classify() {
        return classification();
      },
    });
    dependencies.listFixEvidence = async () => new Map();

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers: [issueNumber],
        releaseTags: ['v2099.7.1'],
        snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
        maxAttempts: 1,
        dependencies,
      }),
      /missing fix evidence/,
    );

    assertNoPersistedIssueEvidence(issueNumber);
  });

  it('rolls back repaired issue evidence when a closure source revision conflicts', async () => {
    const issueNumber = 4244;
    const originalComment = {
      ...comment(244),
      body: 'This was fixed in v2099.7.1.',
    };
    const originalIssue = issue(1, { number: issueNumber });
    const originalSnapshot = snapshot(1, [originalComment], { issueNumber });
    const stableFixEvidence = fixEvidence(issueNumber);
    dbModule.upsertIssue(
      issueRow(issueNumber, 1, originalSnapshot.issueUpdatedAt),
    );
    dbModule.upsertIssueCommentSnapshot(
      __refreshTest.issueCommentSnapshot(originalSnapshot),
    );
    __refreshTest.persistIssueStateEvidence(stableFixEvidence);
    const originalClaims = __refreshTest.persistClosureClaimEvidenceForIssue({
      issue: originalIssue,
      snapshot: originalSnapshot,
      fixEvidence: stableFixEvidence,
      capturedAt: '2026-07-04T12:00:00.000Z',
    });
    assert.ok(originalClaims.extraction.candidates.length > 0);
    const rollbackProtectedTables = [
      'issue_comment_snapshots',
      'issue_label_events',
      'issue_label_evidence_snapshots',
      'issue_label_snapshots',
      'issue_state_event_snapshots',
      'issue_closure_events',
      'classifications',
      'closure_claim_source_snapshots',
      'closure_claim_candidates',
      'closure_claim_extraction_receipts',
    ];
    const originalIssueRow = dbModule.getIssue(issueNumber);
    const originalEvidenceRows = new Map(
      rollbackProtectedTables.map((table) => [
        table,
        issueTableRows(table, issueNumber),
      ]),
    );

    const changedComment = {
      ...originalComment,
      body: 'This was fixed in v2099.7.2.',
    };
    const changedSnapshot = snapshot(1, [changedComment], { issueNumber });
    const changedIssue = issue(1, {
      number: issueNumber,
      body: 'Changed issue body that must roll back.',
      labels: [{ name: 'bug' }],
    });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers: [issueNumber],
        releaseTags: ['v2099.7.1'],
        snapshotsByIssue: new Map([[issueNumber, changedSnapshot]]),
        dependencies: reconciliationDependencies({
          issueNumber,
          issue: changedIssue,
          snapshot: changedSnapshot,
          labelEvents: [labelEvent(issueNumber, `label-${issueNumber}`)],
          fixEvidence: stableFixEvidence,
          async classify() {
            return classification();
          },
        }),
      }),
      /Closure claim source revision .* conflicts with stored source/,
    );

    assert.deepEqual(dbModule.getIssue(issueNumber), originalIssueRow);
    for (const table of rollbackProtectedTables) {
      assert.deepEqual(
        issueTableRows(table, issueNumber),
        originalEvidenceRows.get(table),
        table,
      );
    }
    assert.equal(
      issueTableCount('closure_claim_source_snapshots', issueNumber),
      originalClaims.persistence.candidatePersistence.insertedSourceCount,
    );
    assert.equal(
      issueTableCount('closure_claim_candidates', issueNumber),
      originalClaims.persistence.candidatePersistence.insertedCandidateCount,
    );
    assert.deepEqual(
      db.prepare(`
        SELECT receipt_id, content_hash
        FROM closure_claim_extraction_receipts
        WHERE issue_number=?
        ORDER BY receipt_id
      `).all(issueNumber).map((row) => ({ ...(row as Record<string, unknown>) })),
      [{
        receipt_id: originalClaims.persistence.receipt.receiptId,
        content_hash: originalClaims.persistence.receipt.contentHash,
      }],
    );
    assert.deepEqual(
      db.prepare(`
        SELECT
          members.member_ordinal,
          members.candidate_id,
          members.candidate_content_hash,
          members.source_identity
        FROM closure_claim_extraction_receipt_members members
        JOIN closure_claim_extraction_receipts receipts
          ON receipts.receipt_id=members.receipt_id
        WHERE receipts.issue_number=?
        ORDER BY members.member_ordinal
      `).all(issueNumber).map((row) => ({ ...(row as Record<string, unknown>) })),
      originalClaims.persistence.receipt.members.map((member) => ({
        member_ordinal: member.ordinal,
        candidate_id: member.candidateId,
        candidate_content_hash: member.candidateContentHash,
        source_identity: member.sourceIdentity,
      })),
    );
  });

  it('rejects author, repository, and issue identity mismatches before extraction', () => {
    const issueNumber = 4245;
    const sourceIssue = issue(0, { number: issueNumber });
    const stableFixEvidence = fixEvidence(issueNumber);

    assert.throws(
      () => __refreshTest.closureClaimExtractionForIssue({
        issue: sourceIssue,
        snapshot: snapshot(0, [], {
          issueNumber,
          issueAuthor: {
            nodeId: sourceIssue.user!.id,
            actorType: sourceIssue.user!.type,
            login: 'renamed-reporter',
          },
        }),
        fixEvidence: stableFixEvidence,
      }),
      /author identity does not match/,
    );
    assert.throws(
      () => __refreshTest.closureClaimExtractionForIssue({
        issue: sourceIssue,
        snapshot: snapshot(0, [], {
          issueNumber,
          repositoryNodeId: 'REPO-node-other',
        }),
        fixEvidence: stableFixEvidence,
      }),
      /conflicting repository identities/,
    );
    assert.throws(
      () => __refreshTest.closureClaimExtractionForIssue({
        issue: sourceIssue,
        snapshot: snapshot(0, [], {
          issueNumber: issueNumber + 1,
          issueNodeId: sourceIssue.node_id,
          issueAuthor: {
            nodeId: sourceIssue.user!.id,
            actorType: sourceIssue.user!.type,
            login: sourceIssue.user!.login,
          },
        }),
        fixEvidence: stableFixEvidence,
      }),
      /identity does not match the accepted issue revision/,
    );
  });

  it('rolls back reconciled evidence when a label event ID conflicts with persisted provenance', async () => {
    const issueNumber = 4208;
    const eventId = 'label-event-immutable-conflict';
    dbModule.upsertIssueLabelEvent({
      issue_number: 999,
      event_id: eventId,
      action: 'labeled',
      label_name: 'existing-label',
      actor_login: 'maintainer',
      created_at: '2026-07-01T00:00:00.000Z',
    });
    const stableSnapshot = snapshot(1, [comment(208)], { issueNumber });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers: [issueNumber],
        releaseTags: ['v2099.7.1'],
        snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
        dependencies: reconciliationDependencies({
          issueNumber,
          issue: issue(1, {
            number: issueNumber,
            labels: [{ name: 'bug' }],
          }),
          snapshot: stableSnapshot,
          labelEvents: [
            labelEvent(issueNumber, eventId, {
              action: 'unlabeled',
              actorLogin: 'other-maintainer',
            }),
          ],
          fixEvidence: fixEvidence(issueNumber, true),
          async classify() {
            return classification();
          },
        }),
      }),
      /label-event-immutable-conflict conflicts with immutable persisted provenance/,
    );

    assert.equal(dbModule.getIssue(issueNumber), undefined);
    assert.equal(
      (db.prepare(`SELECT COUNT(*) AS count FROM issue_comment_snapshots WHERE issue_number=?`).get(issueNumber) as any).count,
      0,
    );
    assert.equal(
      (db.prepare(`SELECT COUNT(*) AS count FROM classifications WHERE issue_number=?`).get(issueNumber) as any).count,
      0,
    );
    assert.deepEqual(
      { ...(db.prepare(`
        SELECT issue_number, action, label_name, actor_login, created_at
        FROM issue_label_events
        WHERE event_id=?
      `).get(eventId) as Record<string, unknown>) },
      {
        issue_number: 999,
        action: 'labeled',
        label_name: 'existing-label',
        actor_login: 'maintainer',
        created_at: '2026-07-01T00:00:00.000Z',
      },
    );
  });

  it('fetches and persists complete comments when a metadata-only issue becomes a closure dependency', async () => {
    const issueNumber = 4209;
    const metadataOnly = issue(1, {
      number: issueNumber,
      created_at: '2025-01-01T00:00:00.000Z',
      closed_at: '2025-01-02T00:00:00.000Z',
    });
    dbModule.upsertIssueMetadata(__refreshTest.issueRowFromRemoteMetadata(metadataOnly));
    const stableSnapshot = snapshot(1, [comment(209)], {
      issueNumber,
      issueUpdatedAt: metadataOnly.updated_at,
    });

    const result = await reconcileIssueCommentSnapshots({
      issueNumbers: [issueNumber],
      releaseTags: ['v2099.7.1'],
      dependencies: reconciliationDependencies({
        issueNumber,
        issue: metadataOnly,
        snapshot: stableSnapshot,
        labelEvents: [],
        fixEvidence: fixEvidence(issueNumber),
        async classify() {
          return classification();
        },
      }),
    });

    assert.deepEqual(result.reconciledIssueNumbers, [issueNumber]);
    assert.equal(
      (db.prepare(`
        SELECT fetched_comment_count
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(issueNumber) as { fetched_comment_count: number }).fetched_comment_count,
      1,
    );
  });

  it('feeds comments to the classifier in the same deterministic order used by the digest', async () => {
    const issueNumber = 4210;
    dbModule.upsertIssue(issueRow(issueNumber, 0, '2026-07-01T00:00:00.000Z'));
    const stableSnapshot = snapshot(
      3,
      [comment(303), comment(301), comment(302)],
      { issueNumber },
    );
    const classifiedOrder: number[] = [];

    await reconcileIssueCommentSnapshots({
      issueNumbers: [issueNumber],
      releaseTags: ['v2099.7.1'],
      snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
      dependencies: reconciliationDependencies({
        issueNumber,
        issue: issue(3, { number: issueNumber }),
        snapshot: stableSnapshot,
        labelEvents: [],
        fixEvidence: fixEvidence(issueNumber),
        async classify(_issue, comments) {
          classifiedOrder.push(...comments.map((row) => row.id));
          return classification();
        },
      }),
    });

    assert.deepEqual(classifiedOrder, [301, 302, 303]);
    const stored = db.prepare(`
      SELECT comments_json
      FROM issue_comment_snapshots
      WHERE issue_number=?
    `).get(issueNumber) as { comments_json: string };
    assert.deepEqual(
      JSON.parse(stored.comments_json).map((row: GhComment) => row.id),
      classifiedOrder,
    );
  });

  it('refuses a staged reconciliation when a newer issue revision commits before its transaction', async () => {
    const issueNumber = 4211;
    dbModule.upsertIssue(issueRow(issueNumber, 0, '2026-07-01T00:00:00.000Z'));
    const stagedSnapshot = snapshot(1, [comment(311)], { issueNumber });
    const newerSnapshot = snapshot(1, [comment(399)], {
      issueNumber,
      issueUpdatedAt: '2026-07-03T00:00:00.000Z',
    });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers: [issueNumber],
        releaseTags: ['v2099.7.1'],
        snapshotsByIssue: new Map([[issueNumber, stagedSnapshot]]),
        dependencies: reconciliationDependencies({
          issueNumber,
          issue: issue(1, { number: issueNumber }),
          snapshot: stagedSnapshot,
          labelEvents: [],
          fixEvidence: fixEvidence(issueNumber),
          async classify() {
            dbModule.upsertIssue(issueRow(
              issueNumber,
              newerSnapshot.totalCount,
              newerSnapshot.issueUpdatedAt,
            ));
            dbModule.upsertIssueCommentSnapshot(
              __refreshTest.issueCommentSnapshot(newerSnapshot),
            );
            dbModule.upsertClassification(
              issueNumber,
              classification(),
              newerSnapshot.issueUpdatedAt,
              PROMPT_VERSION,
              newerSnapshot.commentsDigest,
              dbModule.classifierSourceIdentity(['v2099.7.1'], PROMPT_VERSION),
            );
            return classification();
          },
        }),
      }),
      /evidence revision changed while work was staged/,
    );

    assert.equal(dbModule.getIssue(issueNumber)?.updated_at, newerSnapshot.issueUpdatedAt);
    assert.equal(
      (db.prepare(`
        SELECT comments_digest
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(issueNumber) as { comments_digest: string }).comments_digest,
      newerSnapshot.commentsDigest,
    );
  });

  it('reclassifies when the known-tag classifier source identity changes', async () => {
    const issueNumber = 4212;
    const stableSnapshot = snapshot(1, [comment(312)], { issueNumber });
    dbModule.upsertIssue(issueRow(issueNumber, 1, stableSnapshot.issueUpdatedAt));
    dbModule.upsertIssueCommentSnapshot(__refreshTest.issueCommentSnapshot(stableSnapshot));
    dbModule.upsertClassification(
      issueNumber,
      classification(),
      stableSnapshot.issueUpdatedAt,
      PROMPT_VERSION,
      stableSnapshot.commentsDigest,
      dbModule.classifierSourceIdentity(['v2026.6.1'], PROMPT_VERSION),
    );
    let classifyCalls = 0;

    await reconcileIssueCommentSnapshots({
      issueNumbers: [issueNumber],
      releaseTags: ['v2099.7.1'],
      snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
      dependencies: reconciliationDependencies({
        issueNumber,
        issue: issue(1, { number: issueNumber }),
        snapshot: stableSnapshot,
        labelEvents: [],
        fixEvidence: fixEvidence(issueNumber),
        async classify() {
          classifyCalls++;
          return classification();
        },
      }),
    });

    assert.equal(classifyCalls, 1);
    assert.equal(
      dbModule.getClassification(issueNumber)?.source_identity_digest,
      dbModule.classifierSourceIdentity(['v2099.7.1'], PROMPT_VERSION).digest,
    );
  });

  it('treats a classification as current only when update time, prompt, and comment digest match', () => {
    const stableSnapshot = snapshot(1, [comment(203)]);
    const sourceIdentity = dbModule.classifierSourceIdentity(['v2099.7.1'], PROMPT_VERSION);
    const current = {
      classified_updated_at: stableSnapshot.issueUpdatedAt,
      classified_comments_digest: stableSnapshot.commentsDigest,
      prompt_version: PROMPT_VERSION,
      source_identity_digest: sourceIdentity.digest,
    };

    assert.equal(__refreshTest.classificationMatchesSnapshot(current, stableSnapshot, sourceIdentity.digest), true);
    assert.equal(__refreshTest.classificationMatchesSnapshot({
      ...current,
      classified_comments_digest: null,
    }, stableSnapshot, sourceIdentity.digest), false);
    assert.equal(__refreshTest.classificationCanDeferLegacyCommentBinding({
      ...current,
      classified_comments_digest: null,
    }, stableSnapshot, sourceIdentity.digest), true);
    assert.equal(__refreshTest.classificationCanDeferLegacyCommentBinding({
      ...current,
      classified_comments_digest: null,
      source_identity_digest: null,
    }, stableSnapshot, sourceIdentity.digest), false);
    assert.equal(__refreshTest.classificationCanDeferLegacyCommentBinding(current, stableSnapshot, sourceIdentity.digest), false);
    assert.equal(__refreshTest.classificationMatchesSnapshot({
      ...current,
      classified_comments_digest: 'stale-digest',
    }, stableSnapshot, sourceIdentity.digest), false);
    assert.equal(__refreshTest.classificationMatchesSnapshot({
      ...current,
      source_identity_digest: 'different-runtime',
    }, stableSnapshot, sourceIdentity.digest), false);
  });

  it('automatically upgrades legacy null-digest classifications once and reuses bound rows later', async () => {
    const issueNumber = 4203;
    const stableSnapshot = snapshot(1, [comment(204)], { issueNumber });
    dbModule.upsertIssue(issueRow(issueNumber, 1, stableSnapshot.issueUpdatedAt));
    dbModule.upsertClassification(
      issueNumber,
      classification(),
      stableSnapshot.issueUpdatedAt,
      PROMPT_VERSION,
    );
    let classifyCalls = 0;

    const first = await reconcileIssueCommentSnapshots({
      issueNumbers: [issueNumber],
      releaseTags: ['v2099.7.1'],
      snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
      dependencies: reconciliationDependencies({
        issueNumber,
        issue: issue(1, { number: issueNumber }),
        snapshot: stableSnapshot,
        labelEvents: [],
        fixEvidence: fixEvidence(issueNumber),
        async classify() {
          classifyCalls++;
          return classification();
        },
      }),
    });
    assert.deepEqual(first.classifiedIssueNumbers, [issueNumber]);
    assert.equal(classifyCalls, 1);
    assert.equal(
      (dbModule.getClassification(issueNumber) as any)?.classified_comments_digest,
      stableSnapshot.commentsDigest,
    );

    const second = await reconcileIssueCommentSnapshots({
      issueNumbers: [issueNumber],
      releaseTags: ['v2099.7.1'],
      snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
      dependencies: {
        async listIssues() {
          throw new Error('bound classification must not refetch the full issue');
        },
        async listLabelEvidence() {
          throw new Error('bound classification must not refetch labels');
        },
        async listFixEvidence() {
          throw new Error('bound classification must not refetch fix evidence');
        },
        async classify() {
          throw new Error('bound classification must not reclassify');
        },
      },
    });
    assert.deepEqual(second.classifiedIssueNumbers, []);
    assert.equal(classifyCalls, 1);
  });

  it('rolls back the entire reconciliation set when classification fails', async () => {
    const issueNumber = 4202;
    dbModule.upsertIssue(issueRow(issueNumber, 0, '2026-07-01T00:00:00.000Z'));
    const stableSnapshot = snapshot(1, [comment(202)], { issueNumber });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers: [issueNumber],
        releaseTags: ['v2099.7.1'],
        snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
        dependencies: reconciliationDependencies({
          issueNumber,
          issue: issue(1, { number: issueNumber, labels: [{ name: 'bug' }] }),
          snapshot: stableSnapshot,
          labelEvents: [
            labelEvent(issueNumber, `label-${issueNumber}`),
          ],
          fixEvidence: fixEvidence(issueNumber, true),
          async classify() {
            throw new Error('classification unavailable');
          },
        }),
      }),
      /Failed to classify reconciled issue #4202: classification unavailable/,
    );

    const storedIssue = dbModule.getIssue(issueNumber);
    assert.equal(storedIssue?.comments, 0);
    assert.equal(storedIssue?.updated_at, '2026-07-01T00:00:00.000Z');
    assert.equal(
      (db.prepare(`SELECT COUNT(*) AS count FROM issue_comment_snapshots WHERE issue_number=?`).get(issueNumber) as any).count,
      0,
    );
    assert.equal(
      (db.prepare(`SELECT COUNT(*) AS count FROM issue_label_events WHERE issue_number=?`).get(issueNumber) as any).count,
      0,
    );
    assert.equal(dbModule.getClassification(issueNumber), undefined);
  });

  it('rejects a raw classifier result that omits its accepted terminal receipt', async () => {
    const issueNumber = 4220;
    dbModule.upsertIssue(issueRow(issueNumber, 0, '2026-07-01T00:00:00.000Z'));
    const stableSnapshot = snapshot(1, [comment(220)], { issueNumber });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers: [issueNumber],
        releaseTags: ['v2099.7.1'],
        snapshotsByIssue: new Map([[issueNumber, stableSnapshot]]),
        dependencies: reconciliationDependencies({
          issueNumber,
          issue: issue(1, { number: issueNumber }),
          snapshot: stableSnapshot,
          labelEvents: [],
          fixEvidence: fixEvidence(issueNumber),
          async classify() {
            return {
              ...classification(),
              provenance: {} as any,
            };
          },
        }),
      }),
      /missing its accepted classifier attempt receipt/,
    );

    assert.equal(dbModule.getClassification(issueNumber), undefined);
    assert.equal(dbModule.listClassifierClassificationPublications().length, 0);
    assert.equal(
      (db.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(issueNumber) as { count: number }).count,
      0,
    );
  });

  it('keeps a sibling terminal classifier failure durable and publishes completed sibling work', async () => {
    const issueNumbers = [4221, 4222];
    const snapshots = new Map(issueNumbers.map((issueNumber, index) => [
      issueNumber,
      snapshot(1, [comment(221 + index)], { issueNumber }),
    ]));
    for (const issueNumber of issueNumbers) {
      dbModule.upsertIssue(issueRow(
        issueNumber,
        0,
        '2026-07-01T00:00:00.000Z',
      ));
    }
    const failedRun = createClassifierAttemptRun({
      runId: 'classifier-run-sibling-failure',
      issueNumber: 4222,
      startedAt: '2026-07-04T00:00:00.000Z',
      maxAttempts: 1,
      classifierIdentityHash: dbModule.classifierSourceIdentity(
        ['v2099.7.1'],
        PROMPT_VERSION,
      ).promptTemplateHash,
      requestHash: 'e'.repeat(64),
    });
    const failedReceipt = createClassifierAttemptTerminalReceipt(failedRun, [], {
      receiptId: 'classifier-receipt-sibling-failure',
      status: 'terminal_failure',
      finishedAt: '2026-07-04T00:00:01.000Z',
      error: captureClassifierError(new Error('sibling model failure')),
    });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers,
        releaseTags: ['v2099.7.1'],
        classificationConcurrency: 2,
        snapshotsByIssue: snapshots,
        dependencies: {
          async listIssues() {
            return new Map(issueNumbers.map((issueNumber) => [
              issueNumber,
              issue(1, { number: issueNumber }),
            ]));
          },
          async listSnapshots() {
            return snapshots;
          },
          async listLabelEvidence() {
            return new Map(issueNumbers.map((issueNumber) => [
              issueNumber,
              labelEvidenceSnapshot(issue(1, { number: issueNumber }), []),
            ]));
          },
          async listFixEvidence() {
            return new Map(issueNumbers.map((issueNumber) => [
              issueNumber,
              fixEvidence(issueNumber),
            ]));
          },
          async classify(candidate) {
            if (candidate.number === 4222) {
              dbModule.recordClassifierAttemptRun(failedRun);
              dbModule.recordClassifierAttemptTerminalReceipt(failedReceipt);
              throw new Error('sibling model failure');
            }
            return classification();
          },
        },
      }),
      /sibling model failure/,
    );

    assert.equal(
      dbModule.getClassifierAttemptLedger(failedRun.runId)?.receipt.status,
      'terminal_failure',
    );
    assert.ok(dbModule.getClassification(4221));
    assert.equal(dbModule.getClassification(4222), undefined);
    assert.equal(
      (db.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(4221) as { count: number }).count,
      1,
    );
    assert.equal(
      (db.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(4222) as { count: number }).count,
      0,
    );
  });

  it('keeps an abandoned sibling ledger durable without replacing the primary classifier failure', async () => {
    const issueNumbers = [4223, 4224];
    const snapshots = new Map(issueNumbers.map((issueNumber, index) => [
      issueNumber,
      snapshot(1, [comment(223 + index)], { issueNumber }),
    ]));
    for (const issueNumber of issueNumbers) {
      dbModule.upsertIssue(issueRow(
        issueNumber,
        0,
        '2026-07-01T00:00:00.000Z',
      ));
    }
    const classifierIdentityHash = dbModule.classifierSourceIdentity(
      ['v2099.7.1'],
      PROMPT_VERSION,
    ).promptTemplateHash;
    const abandonedRun = createClassifierAttemptRun({
      runId: 'classifier-run-abandoned-sibling',
      issueNumber: 4223,
      startedAt: '2026-07-04T00:00:00.000Z',
      maxAttempts: 1,
      classifierIdentityHash,
      requestHash: 'a'.repeat(64),
    });
    const failedRun = createClassifierAttemptRun({
      runId: 'classifier-run-primary-failure',
      issueNumber: 4224,
      startedAt: '2026-07-04T00:00:00.000Z',
      maxAttempts: 1,
      classifierIdentityHash,
      requestHash: 'b'.repeat(64),
    });
    let siblingStartedResolve!: () => void;
    const siblingStarted = new Promise<void>((resolve) => {
      siblingStartedResolve = resolve;
    });

    await assert.rejects(
      reconcileIssueCommentSnapshots({
        issueNumbers,
        releaseTags: ['v2099.7.1'],
        classificationConcurrency: 2,
        snapshotsByIssue: snapshots,
        dependencies: {
          async listIssues() {
            return new Map(issueNumbers.map((issueNumber) => [
              issueNumber,
              issue(1, { number: issueNumber }),
            ]));
          },
          async listSnapshots() {
            return snapshots;
          },
          async listLabelEvidence() {
            return new Map(issueNumbers.map((issueNumber) => [
              issueNumber,
              labelEvidenceSnapshot(issue(1, { number: issueNumber }), []),
            ]));
          },
          async listFixEvidence() {
            return new Map(issueNumbers.map((issueNumber) => [
              issueNumber,
              fixEvidence(issueNumber),
            ]));
          },
          async classify(candidate, _comments, _tags, signal) {
            if (candidate.number === 4223) {
              dbModule.recordClassifierAttemptRun(abandonedRun);
              siblingStartedResolve();
              await new Promise<never>((_resolve, reject) => {
                let settled = false;
                const abandon = () => {
                  if (settled) return;
                  settled = true;
                  const cause = new Error('sibling cancelled after primary failure');
                  const receipt = createClassifierAttemptTerminalReceipt(
                    abandonedRun,
                    [],
                    {
                      receiptId: 'classifier-receipt-abandoned-sibling',
                      status: 'abandoned',
                      finishedAt: '2026-07-04T00:00:02.000Z',
                      error: captureClassifierError(cause),
                    },
                  );
                  dbModule.recordClassifierAttemptTerminalReceipt(receipt);
                  const ledger = dbModule.getClassifierAttemptLedger(abandonedRun.runId);
                  assert.ok(ledger);
                  reject(new ClassifierAttemptLedgerTerminalError(
                    cause.message,
                    'abandoned',
                    ledger,
                    cause,
                  ));
                };
                signal?.addEventListener('abort', abandon, { once: true });
                if (signal?.aborted) abandon();
              });
            }

            await siblingStarted;
            const cause = new Error('primary sibling model failure');
            dbModule.recordClassifierAttemptRun(failedRun);
            const receipt = createClassifierAttemptTerminalReceipt(failedRun, [], {
              receiptId: 'classifier-receipt-primary-failure',
              status: 'terminal_failure',
              finishedAt: '2026-07-04T00:00:01.000Z',
              error: captureClassifierError(cause),
            });
            dbModule.recordClassifierAttemptTerminalReceipt(receipt);
            const ledger = dbModule.getClassifierAttemptLedger(failedRun.runId);
            assert.ok(ledger);
            throw new ClassifierAttemptLedgerTerminalError(
              cause.message,
              'terminal_failure',
              ledger,
              cause,
            );
          },
        },
      }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /primary sibling model failure/);
        assert.doesNotMatch(error.message, /sibling cancelled after primary failure/);
        return true;
      },
    );

    assert.equal(
      dbModule.getClassifierAttemptLedger(failedRun.runId)?.receipt.status,
      'terminal_failure',
    );
    assert.equal(
      dbModule.getClassifierAttemptLedger(abandonedRun.runId)?.receipt.status,
      'abandoned',
    );
    assert.equal(
      dbModule.listRecentIngestionEvidenceFailures(100).some((failure) =>
        failure.source === 'issue-classification' &&
        failure.scope === 'issue #4223'),
      false,
    );
  });

  it('distinguishes paginator failure after yielding partial pages', async () => {
    const cause = new Error('GitHub page 3 failed');
    async function* partialPages() {
      yield [1, 2];
      yield [3];
      throw cause;
    }

    const seen: number[] = [];
    let caught: unknown;
    try {
      for await (const page of __refreshTest.withIssuePaginationFailureBoundary(partialPages())) {
        seen.push(...page);
      }
    } catch (error) {
      caught = error;
    }

    assert.deepEqual(seen, [1, 2, 3]);
    assert.ok(caught instanceof __refreshTest.IssuePaginationFailure);
    assert.equal(caught.paginationCause, cause);
  });

  it('records, persists, and throws for score-blocking issue pagination failure', () => {
    const cause = new Error('cursor request failed');
    const crawlMeta = {
      stopReason: 'evidence_failure',
      pagesFetched: 2,
      issuesFetched: 150,
      scorePersisted: false,
      timings: {
        'release.fetch': 25,
        'issue.crawl': 80,
        'issue.classification': 40,
      },
    };
    let recorded: Record<string, unknown> | null = null;
    let persisted: Record<string, unknown> | null = null;
    let scoreAttempted = false;

    assert.throws(() => {
      __refreshTest.failIssuePagination({
        cause,
        scope: 'after page 2',
        context: {
          pagesFetched: 2,
          issuesFetched: 150,
          monitoredIssuesFetched: 120,
          maxIssuePages: 25,
        },
        recordFailure(source, scope, error, context) {
          recorded = { source, scope, error, context, scoringBlocking: true };
          return '[issue-pagination] after page 2 failed: cursor request failed';
        },
        buildCrawlMeta: () => crawlMeta,
        persistCrawlMeta(meta) {
          persisted = meta;
        },
      });
      scoreAttempted = true;
    }, /refusing to persist scores from incomplete issue pagination/);

    assert.equal(scoreAttempted, false);
    assert.deepEqual(recorded, {
      source: 'issue-pagination',
      scope: 'after page 2',
      error: cause,
      context: {
        pagesFetched: 2,
        issuesFetched: 150,
        monitoredIssuesFetched: 120,
        maxIssuePages: 25,
      },
      scoringBlocking: true,
    });
    assert.deepEqual(persisted, crawlMeta);
  });

  it('does not mark issue backfill complete when pagination stops at the page cap', () => {
    for (const paginationExhaustiveStable of [false, true]) {
      assert.equal(__refreshTest.shouldMarkBackfillComplete({
        issuePaginationStopReason: 'page_cap',
        paginationExhaustiveStable,
      }), false);
    }
  });

  it('does not mark issue backfill complete when page evidence fetching fails', () => {
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      issuePaginationStopReason: 'evidence_failure',
      paginationExhaustiveStable: true,
    }), false);
  });

  it('marks issue backfill complete only after a stabilized exhaustive connection', () => {
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      issuePaginationStopReason: 'exhausted',
      paginationExhaustiveStable: true,
    }), true);
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      issuePaginationStopReason: 'exhausted',
      paginationExhaustiveStable: false,
    }), false);
  });

  it('never promotes an incremental early stop into an exhaustive baseline', () => {
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      issuePaginationStopReason: 'early_stop',
      paginationExhaustiveStable: true,
    }), false);
  });

  it('builds a self-validating exhaustive issue baseline identity', () => {
    const membershipDigest = 'a'.repeat(64);
    const contentDigest = 'b'.repeat(64);
    const baseline = __refreshTest.issueCrawlBaselineFromCatalog({
      exhausted: true,
      stabilized: true,
      totalCount: 2,
      observedTotalCount: 3,
      postBoundaryGrowthCount: 1,
      nodeCount: 2,
      uniqueCount: 2,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      digest: membershipDigest,
      membershipDigest,
      contentDigest,
      snapshotBoundary: {
        totalCount: 2,
        terminalIssue: {
          nodeId: 'ISSUE-node-2',
          issueNumber: 2,
          createdAt: '2026-07-03T00:00:00.000Z',
        },
        membershipDigest,
      },
      lastRequestCursor: null,
      nextCursor: null,
      hasNextPage: false,
      sourceOrder: 'CREATED_AT_ASC',
    }, '2026-07-04T02:00:00.000Z', '2026-07-04T01:00:00.000Z');

    assert.equal(baseline.boundaryTotalCount, 2);
    assert.equal(baseline.observedTotalCount, 3);
    assert.equal(baseline.postBoundaryGrowthCount, 1);
    assert.equal(baseline.membershipDigest, membershipDigest);
    assert.equal(baseline.contentDigest, contentDigest);
    assert.match(baseline.identity, /^[0-9a-f]{64}$/);
    assert.deepEqual(__refreshTest.issueCrawlBaselineProblems(baseline), []);
    assert.ok(__refreshTest.issueCrawlBaselineProblems({
      ...baseline,
      fetchedCount: 1,
    }).some((problem: string) => /must equal boundaryTotalCount/.test(problem)));
    assert.ok(__refreshTest.issueCrawlBaselineProblems({
      ...baseline,
      identity: 'b'.repeat(64),
    }).some((problem: string) => /identity does not match/.test(problem)));
  });

  it('records counted cursor state for partial and exhaustive issue crawls', () => {
    const membershipDigest = 'c'.repeat(64);
    const contentDigest = 'd'.repeat(64);
    const baseline = __refreshTest.issueCrawlBaselineFromCatalog({
      exhausted: true,
      stabilized: true,
      totalCount: 400,
      observedTotalCount: 400,
      postBoundaryGrowthCount: 0,
      nodeCount: 400,
      uniqueCount: 400,
      pageCount: 4,
      pagesFetched: 8,
      sweepCount: 2,
      digest: membershipDigest,
      membershipDigest,
      contentDigest,
      snapshotBoundary: {
        totalCount: 400,
        terminalIssue: {
          nodeId: 'ISSUE-node-400',
          issueNumber: 400,
          createdAt: '2026-07-03T00:00:00.000Z',
        },
        membershipDigest,
      },
      lastRequestCursor: 'cursor-300',
      nextCursor: null,
      hasNextPage: false,
      sourceOrder: 'CREATED_AT_ASC',
    }, '2026-07-04T02:00:00.000Z', '2026-07-04T01:00:00.000Z');
    const partial = __refreshTest.issuePaginationFromPage({
      totalCount: 500,
      fetchedCount: 100,
      uniqueCount: 100,
      pageCount: 1,
      requestCursor: null,
      nextCursor: 'cursor-100',
      hasNextPage: true,
      exhausted: false,
      digest: null,
      membershipDigest: null,
      contentDigest: null,
      sourceOrder: 'UPDATED_AT_DESC',
    }, baseline);
    assert.deepEqual({
      completeness: partial.completeness,
      boundaryTotalCount: partial.boundaryTotalCount,
      observedTotalCount: partial.observedTotalCount,
      postBoundaryGrowthCount: partial.postBoundaryGrowthCount,
      fetchedCount: partial.fetchedCount,
      nextCursor: partial.nextCursor,
      hasNextPage: partial.hasNextPage,
      exhausted: partial.exhausted,
      stabilized: partial.stabilized,
    }, {
      completeness: 'incremental_partial',
      boundaryTotalCount: 400,
      observedTotalCount: 500,
      postBoundaryGrowthCount: 100,
      fetchedCount: 100,
      nextCursor: 'cursor-100',
      hasNextPage: true,
      exhausted: false,
      stabilized: false,
    });

    const complete = __refreshTest.issuePaginationFromCatalog({
      exhausted: true,
      stabilized: true,
      totalCount: 500,
      observedTotalCount: 501,
      postBoundaryGrowthCount: 1,
      nodeCount: 500,
      uniqueCount: 500,
      pageCount: 5,
      pagesFetched: 10,
      sweepCount: 2,
      digest: membershipDigest,
      membershipDigest,
      contentDigest,
      snapshotBoundary: {
        totalCount: 500,
        terminalIssue: {
          nodeId: 'ISSUE-node-500',
          issueNumber: 500,
          createdAt: '2026-07-03T00:00:00.000Z',
        },
        membershipDigest,
      },
      lastRequestCursor: 'cursor-400',
      nextCursor: null,
      hasNextPage: false,
      sourceOrder: 'CREATED_AT_ASC',
    });
    assert.equal(complete.completeness, 'exhaustive_stable');
    assert.equal(complete.fetchedCount, complete.boundaryTotalCount);
    assert.equal(complete.observedTotalCount, 501);
    assert.equal(complete.postBoundaryGrowthCount, 1);
    assert.equal(complete.digest, membershipDigest);

    const natural = __refreshTest.issuePaginationFromIncrementalSweep({
      exhausted: true,
      stabilized: false,
      totalCount: 501,
      nodeCount: 501,
      uniqueCount: 501,
      pageCount: 6,
      pagesFetched: 6,
      sweepCount: 1,
      digest: 'e'.repeat(64),
      membershipDigest: 'e'.repeat(64),
      contentDigest: 'f'.repeat(64),
      lastRequestCursor: 'cursor-500',
      nextCursor: null,
      hasNextPage: false,
      sourceOrder: 'UPDATED_AT_DESC',
    }, baseline);
    assert.equal(natural.completeness, 'incremental_exhaustive');
    assert.equal(natural.exhausted, true);
    assert.equal(natural.stabilized, false);
    assert.equal(natural.postBoundaryGrowthCount, 101);
  });

  it('validates repository-bound crawl metadata before score persistence', () => {
    const membershipDigest = 'a'.repeat(64);
    const contentDigest = 'b'.repeat(64);
    const baseline = __refreshTest.issueCrawlBaselineFromCatalog({
      exhausted: true,
      stabilized: true,
      totalCount: 2,
      observedTotalCount: 3,
      postBoundaryGrowthCount: 1,
      nodeCount: 2,
      uniqueCount: 2,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      digest: membershipDigest,
      membershipDigest,
      contentDigest,
      snapshotBoundary: {
        totalCount: 2,
        terminalIssue: {
          nodeId: 'ISSUE-node-2',
          issueNumber: 2,
          createdAt: '2026-07-03T00:00:00.000Z',
        },
        membershipDigest,
      },
      lastRequestCursor: null,
      nextCursor: null,
      hasNextPage: false,
      sourceOrder: 'CREATED_AT_ASC',
    }, '2026-07-04T02:00:00.000Z', '2026-07-04T01:00:00.000Z');
    const pagination = __refreshTest.issuePaginationFromCatalog({
      exhausted: true,
      stabilized: true,
      totalCount: 2,
      observedTotalCount: 3,
      postBoundaryGrowthCount: 1,
      nodeCount: 2,
      uniqueCount: 2,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      digest: membershipDigest,
      membershipDigest,
      contentDigest,
      snapshotBoundary: baseline.asOfBoundary,
      lastRequestCursor: null,
      nextCursor: null,
      hasNextPage: false,
      sourceOrder: 'CREATED_AT_ASC',
    });
    const snapshotId = 'e'.repeat(64);
    const crawl = {
      schemaVersion: 4,
      repository: baseline.repository,
      fullIssueBackfill: true,
      crawlMode: 'exhaustive',
      backfillCompleteAfterRun: true,
      baseline,
      pagination,
      catalogSnapshot: {
        schemaVersion: 1,
        snapshotId,
        contentHash: snapshotId,
        capturedAt: '2026-07-04T01:30:00.000Z',
        resumed: false,
        priorStatus: 'missing',
        maxAgeHours: 24,
        consumedAt: '2026-07-04T02:01:00.000Z',
        consumedByRunId: 'refresh-run',
        consumptionContentHash: 'f'.repeat(64),
      },
      catalogAttestation: {
        schemaVersion: 1,
        snapshotId,
        snapshotContentHash: snapshotId,
        observedAt: '2026-07-04T02:30:00.000Z',
        totalCount: 2,
        membershipDigest,
        contentDigest,
        finalSweepCount: 1,
        finalPagesFetched: 1,
      },
      stopReason: 'exhausted',
      evidenceRefreshFailures: [],
      classificationFailures: [],
    };

    assert.deepEqual(__refreshTest.issueCrawlMetadataProblems(
      crawl,
      baseline,
      { forScorePersistence: true },
    ), []);
    assert.ok(__refreshTest.issueCrawlMetadataProblems(
      {
        ...crawl,
        repository: 'other/repository',
        pagination: { ...pagination, repository: 'other/repository' },
      },
      baseline,
      { forScorePersistence: true },
    ).some((problem: string) => /repository must equal/.test(problem)));
  });

  it('drops stale prompt-sweep classifications only after exhausting pagination', () => {
    assert.equal(__refreshTest.shouldDropStaleClassificationsAfterPromptSweep('exhausted'), true);
    assert.equal(__refreshTest.shouldDropStaleClassificationsAfterPromptSweep('page_cap'), false);
    assert.equal(__refreshTest.shouldDropStaleClassificationsAfterPromptSweep('early_stop'), false);
  });

  it('refuses to score after page-capped issue pagination', () => {
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('page_cap'), true);
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('evidence_failure'), true);
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('exhausted'), false);
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('early_stop'), true);
  });

  it('refuses to score after any monitored-release evidence refresh failure', () => {
    assert.equal(__refreshTest.shouldRefuseScoreAfterEvidenceFailures([]), false);
    assert.equal(__refreshTest.shouldRefuseScoreAfterEvidenceFailures(['closure proof failed']), true);
  });

  it('refuses to score after truncated comment scans', () => {
    assert.equal(__refreshTest.shouldRefuseScoreAfterTruncatedCommentScans(0), false);
    assert.equal(__refreshTest.shouldRefuseScoreAfterTruncatedCommentScans(1), true);
  });

  it('formats score-blocking evidence refresh failures with source and scope', () => {
    assert.equal(
      __refreshTest.evidenceRefreshFailureMessage('release-checks', 'v2026.6.10', new Error('GraphQL missing contexts')),
      '[release-checks] v2026.6.10 failed: GraphQL missing contexts',
    );
    assert.equal(
      __refreshTest.evidenceRefreshFailureMessage('release-metadata', 'listReleases', new Error('GraphQL unavailable')),
      '[release-metadata] listReleases failed: GraphQL unavailable',
    );
    assert.equal(
      __refreshTest.evidenceRefreshFailureMessage('artifact-verification', 'v2026.6.10', new Error('npm registry timeout')),
      '[artifact-verification] v2026.6.10 failed: npm registry timeout',
    );
    assert.equal(
      __refreshTest.evidenceRefreshFailureMessage('advisories', null, new Error('GraphQL unavailable')),
      '[advisories] failed: GraphQL unavailable',
    );
    assert.equal(
      __refreshTest.evidenceRefreshFailureMessage('issue-comments-truncated', null, new Error('2 issue(s) had incomplete comment scans')),
      '[issue-comments-truncated] failed: 2 issue(s) had incomplete comment scans',
    );
  });

  it('stores only active advisories for the configured npm package and preserves withdrawals in provenance', () => {
    const active = advisory({
      ghsaId: 'GHSA-active',
      ecosystem: 'NPM',
      packageName: 'OpenClaw',
      vulnerableVersionRange: '< 2026.6.2',
    });
    const withdrawn = advisory({
      ghsaId: 'GHSA-withdrawn',
      state: 'withdrawn',
      withdrawnAt: '2026-07-02T00:00:00Z',
      vulnerableVersionRange: '< 2026.5.1',
    });

    const rows = __refreshTest.flattenAdvisoryVulnerabilityRows(
      [active, withdrawn],
      { ecosystem: 'npm', packageName: 'openclaw' },
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0].ghsa_id, 'GHSA-active');
    assert.equal(rows[0].package_ecosystem, 'npm');
    assert.equal(rows[0].package_name, 'openclaw');

    const provenance = __refreshTest.advisoryIngestionProvenance(
      advisoryCatalog([active, withdrawn]),
      rows,
      '2026-07-04T00:00:00Z',
    );
    assert.deepEqual(provenance.activeAdvisoryIds, ['GHSA-active']);
    assert.equal(provenance.withdrawnAdvisories.length, 1);
    assert.equal(provenance.withdrawnAdvisories[0].ghsaId, 'GHSA-withdrawn');
    assert.equal(provenance.withdrawnAdvisories[0].withdrawnAt, '2026-07-02T00:00:00Z');
    assert.equal(
      provenance.withdrawnAdvisories[0].vulnerabilities[0].vulnerableVersionRange,
      '< 2026.5.1',
    );
    assert.equal(provenance.exhausted, true);
    assert.equal(provenance.stabilized, true);
    assert.equal(provenance.totalCount, 2);
    assert.equal(provenance.nodeCount, 2);
    assert.equal(provenance.sweepCount, 2);
    assert.equal(provenance.rowCount, 1);
    assert.match(provenance.sourceDigest, /^[0-9a-f]{64}$/);
    assert.match(provenance.contentDigest, /^[0-9a-f]{64}$/);
  });

  it('rejects foreign, missing, and malformed advisory rows before scoring storage', () => {
    assert.throws(
      () => __refreshTest.flattenAdvisoryVulnerabilityRows(
        [advisory({ ecosystem: 'PIP' })],
        { ecosystem: 'npm', packageName: 'openclaw' },
      ),
      /package pip:openclaw does not match expected npm:openclaw/,
    );
    assert.throws(
      () => __refreshTest.flattenAdvisoryVulnerabilityRows(
        [advisory({ packageName: 'other-package' })],
        { ecosystem: 'npm', packageName: 'openclaw' },
      ),
      /package npm:other-package does not match expected npm:openclaw/,
    );
    assert.throws(
      () => __refreshTest.flattenAdvisoryVulnerabilityRows(
        [advisory({ packageName: null })],
        { ecosystem: 'npm', packageName: 'openclaw' },
      ),
      /missing package identity/,
    );
    assert.throws(
      () => __refreshTest.flattenAdvisoryVulnerabilityRows(
        [advisory({ vulnerableVersionRange: '>= 2026.6.1foo' })],
        { ecosystem: 'npm', packageName: 'openclaw' },
      ),
      /malformed_vulnerable_range/,
    );
    for (const vulnerableVersionRange of [
      '>= 2026.6.2, < 2026.6.2',
      '2026.6.1 2026.6.2',
      '>= 2026.6.1,',
    ]) {
      assert.throws(
        () => __refreshTest.flattenAdvisoryVulnerabilityRows(
          [advisory({ vulnerableVersionRange })],
          { ecosystem: 'npm', packageName: 'openclaw' },
        ),
        /malformed_vulnerable_range/,
      );
    }
    assert.throws(
      () => __refreshTest.flattenAdvisoryVulnerabilityRows(
        [advisory({
          vulnerableVersionRange: '<= 2026.6.2',
          patchedVersions: '2026.6.2',
        })],
        { ecosystem: 'npm', packageName: 'openclaw' },
      ),
      /patched_version_still_vulnerable/,
    );
    assert.equal(
      __refreshTest.flattenAdvisoryVulnerabilityRows(
        [advisory({ patchedVersions: null })],
        { ecosystem: 'npm', packageName: 'openclaw' },
      )[0].patched_versions,
      null,
    );
  });

  it('records flattening and snapshot replacement errors as durable advisory failures', () => {
    const records: Array<{
      source: string;
      scope: string | null;
      message: string;
      context: Record<string, unknown>;
    }> = [];
    const recordFailure = (
      source: string,
      scope: string | null,
      error: unknown,
      context: Record<string, unknown>,
    ) => {
      const message = `[${source}] ${scope} failed: ${(error as Error).message}`;
      records.push({ source, scope, message, context });
      return message;
    };

    let flattenError: unknown;
    try {
      __refreshTest.flattenAdvisoryVulnerabilityRows(
        [advisory({ ecosystem: 'PIP' })],
        { ecosystem: 'npm', packageName: 'openclaw' },
      );
    } catch (error) {
      flattenError = error;
    }
    __refreshTest.recordAdvisoryIngestionFailure({
      error: flattenError,
      scope: 'npm:openclaw',
      packageName: 'openclaw',
      advisoryCount: 1,
      withdrawnAdvisoryCount: 0,
      recordFailure,
    });
    __refreshTest.recordAdvisoryIngestionFailure({
      error: new Error('snapshot transaction rolled back'),
      scope: 'npm:openclaw',
      packageName: 'openclaw',
      advisoryCount: 2,
      withdrawnAdvisoryCount: 1,
      recordFailure,
    });

    assert.equal(records.length, 2);
    assert.equal(records[0].source, 'advisories');
    assert.equal(records[0].context.phase, 'flatten');
    assert.equal(records[1].source, 'advisories');
    assert.equal(records[1].context.phase, 'snapshot-replace');
    assert.equal(records[1].context.withdrawnAdvisoryCount, 1);
  });

  it('refuses to score after any issue classification failure', () => {
    assert.equal(__refreshTest.shouldRefuseScoreAfterClassificationFailures([]), false);
    assert.equal(__refreshTest.shouldRefuseScoreAfterClassificationFailures(['[classify] issue #1 failed: timeout']), true);
  });

  it('records each classification failure with issue-specific run context', () => {
    const records: Array<{
      source: string;
      scope: string | null;
      error: unknown;
      context: Record<string, unknown>;
    }> = [];
    const message = __refreshTest.recordIssueClassificationFailure({
      issue: issue(0),
      error: new Error('model timeout'),
      pageContext: {
        page: 3,
        refreshRunId: '2026-07-03T12:00:00.000Z:1234:test',
      },
      recordFailure(source, scope, error, context) {
        records.push({ source, scope, error, context });
        return `[${source}] ${scope} failed: ${(error as Error).message}`;
      },
    });

    assert.equal(message, '[issue-classification] issue #42 failed: model timeout');
    assert.equal(records.length, 1);
    assert.equal(records[0].source, 'issue-classification');
    assert.equal(records[0].scope, 'issue #42');
    assert.deepEqual(records[0].context, {
      page: 3,
      refreshRunId: '2026-07-03T12:00:00.000Z:1234:test',
      phase: 'classify',
      issueNumber: 42,
      issueUpdatedAt: '2026-07-02T00:00:00.000Z',
      issueState: 'open',
      issueUrl: 'https://example.test/issues/42',
    });
  });

  it('summarizes long failure lists before storing crawl metadata', () => {
    const failures = Array.from({ length: 27 }, (_, index) => `failure ${index + 1}`);
    const summarized = __refreshTest.summarizeFailures(failures);

    assert.equal(summarized.length, 26);
    assert.equal(summarized[0], 'failure 1');
    assert.equal(summarized[24], 'failure 25');
    assert.equal(summarized[25], '[summary] 2 additional failure(s) omitted');
  });

  it('selects monitored releases by publication order, including a late-published final-page stable', () => {
    const catalog = releaseCatalog([
      release('v2099.7.2-beta.1', true, {
        published_at: '2026-07-02T12:00:00Z',
        created_at: '2026-07-03T10:00:00Z',
      }),
      release('v2099.7.2', false, {
        published_at: '2026-07-02T00:00:00Z',
        created_at: '2026-07-02T00:00:00Z',
      }),
      release('v2099.7.1-beta.1', true, {
        published_at: '2026-07-01T12:00:00Z',
        created_at: '2026-07-01T12:00:00Z',
      }),
      release('v2099.7.1', false, {
        published_at: '2026-07-01T00:00:00Z',
        created_at: '2026-07-01T00:00:00Z',
      }),
      release('v2099.6.30', false, {
        published_at: '2026-06-30T00:00:00Z',
        created_at: '2026-06-30T00:00:00Z',
      }),
      release('v2099.7.3', false, {
        published_at: '2026-07-03T12:00:00Z',
        created_at: '2026-05-01T00:00:00Z',
      }),
    ]);

    const result = __refreshTest.releaseWindowCompleteness(catalog, 3);
    const selection = __refreshTest.selectReleaseWindow(catalog, 3);

    assert.equal(result.complete, true);
    assert.equal(result.oldestMonitoredTag, 'v2099.7.1');
    assert.deepEqual(
      selection.monitored.map((item: any) => item.tag_name),
      ['v2099.7.3', 'v2099.7.2', 'v2099.7.1'],
    );
    assert.equal(selection.predecessorBoundary?.tag_name, 'v2099.6.30');
    assert.deepEqual(
      selection.derivedContext.map((item: any) => item.tag_name),
      [
        'v2099.7.3',
        'v2099.7.2-beta.1',
        'v2099.7.2',
        'v2099.7.1-beta.1',
        'v2099.7.1',
        'v2099.6.30',
      ],
    );
  });

  it('attests the final catalog and rejects digest drift or a newly published stable before score publication', () => {
    const initial = releaseCatalog([
      release('v3', false, { published_at: '2026-07-03T00:00:00.000Z' }),
      release('v2', false, { published_at: '2026-07-02T00:00:00.000Z' }),
      release('v1', false, { published_at: '2026-07-01T00:00:00.000Z' }),
    ], {
      digest: 'a'.repeat(64),
    });
    const selection = __refreshTest.selectReleaseWindow(initial, 2);
    dbModule.replaceActiveReleaseCatalog(selection.ordered.map((item: any) => ({
      node_id: item.node_id,
      catalog_tag_commit_oid: item.tag_commit_oid,
      tag: item.tag_name,
      name: item.name,
      published_at: item.published_at,
      created_at: item.created_at,
      updated_at: item.updated_at,
      html_url: item.html_url,
      prerelease: item.prerelease,
      body: item.body,
    })));
    const scoreRun = {
      scored: selection.monitored.map((item: any) => ({
        rel: {
          tag: item.tag_name,
          node_id: item.node_id,
          catalog_tag_commit_oid: item.tag_commit_oid,
          published_at: item.published_at,
        },
      })),
    };
    const attestation = __refreshTest.finalReleaseCatalogAttestation({
      initialCatalog: initial,
      finalCatalog: releaseCatalog(initial.releases, {
        digest: 'a'.repeat(64),
        sweepCount: 3,
        pagesFetched: 3,
      }),
      monitoredReleaseCount: 2,
      scoreRun,
      scoreBuiltAt: '2026-07-04T00:00:00.000Z',
      finalObservedAt: '2026-07-04T00:00:01.000Z',
    } as any);
    assert.equal(attestation.schemaVersion, 4);
    assert.equal(attestation.initialRemoteCatalog.sweepCount, 2);
    assert.equal(attestation.finalRemoteCatalog.sweepCount, 3);
    assert.equal(attestation.latestStable.tag, 'v3');

    assert.throws(
      () => __refreshTest.finalReleaseCatalogAttestation({
        initialCatalog: initial,
        finalCatalog: releaseCatalog(initial.releases, {
          digest: 'b'.repeat(64),
        }),
        monitoredReleaseCount: 2,
        scoreRun,
        scoreBuiltAt: '2026-07-04T00:00:00.000Z',
        finalObservedAt: '2026-07-04T00:00:01.000Z',
      } as any),
      /catalog drifted after score construction/,
    );

    const withNewStable = releaseCatalog([
      release('v4', false, { published_at: '2026-07-04T00:00:00.000Z' }),
      ...initial.releases,
    ], {
      digest: 'c'.repeat(64),
    });
    assert.throws(
      () => __refreshTest.finalReleaseCatalogAttestation({
        initialCatalog: initial,
        finalCatalog: withNewStable,
        monitoredReleaseCount: 2,
        scoreRun,
        scoreBuiltAt: '2026-07-04T00:00:00.000Z',
        finalObservedAt: '2026-07-04T00:00:01.000Z',
      } as any),
      /catalog drifted after score construction/,
    );
  });

  it('accepts fewer stable releases only from explicitly exhausted stable metadata', () => {
    const catalog = releaseCatalog([
      release('v2'),
      release('v2-beta.1', true, { published_at: '2026-07-01T12:00:00Z' }),
      release('v1', false, { published_at: '2026-06-30T00:00:00Z' }),
    ]);
    const result = __refreshTest.releaseWindowCompleteness(catalog, 10);
    const selection = __refreshTest.selectReleaseWindow(catalog, 10);

    assert.equal(result.complete, true);
    assert.equal(result.exhausted, true);
    assert.equal(selection.predecessorBoundary, null);
    assert.deepEqual(selection.reachability, selection.monitored);

    const notExhausted = releaseCatalog(catalog.releases, { exhausted: false });
    const incomplete = __refreshTest.releaseWindowCompleteness(notExhausted, 10);
    assert.equal(incomplete.complete, false);
    assert.match(incomplete.reason ?? '', /did not explicitly exhaust/);
    assert.throws(
      () => __refreshTest.selectReleaseWindow(notExhausted, 10),
      /requires explicit repository\.releases exhaustion metadata/,
    );
  });

  it('uses explicit stabilization and count metadata for release completeness', () => {
    const releases = [release('v2'), release('v1', false, { published_at: '2026-06-30T00:00:00Z' })];

    const unstable = __refreshTest.releaseWindowCompleteness(
      releaseCatalog(releases, { stabilized: false }),
      1,
    );
    assert.equal(unstable.complete, false);
    assert.match(unstable.reason ?? '', /did not stabilize/);

    const countMismatch = __refreshTest.releaseWindowCompleteness(
      releaseCatalog(releases, { totalCount: 3 }),
      1,
    );
    assert.equal(countMismatch.complete, false);
    assert.match(countMismatch.reason ?? '', /metadata count mismatch/);
  });

  it('keeps prerelease ties deterministic but rejects ambiguous stable publication boundaries', () => {
    const tied = [
      release('vA', false, {
        node_id: 'R_2',
        published_at: '2026-07-02T00:00:00Z',
      }),
      release('vA', false, {
        node_id: 'R_1',
        published_at: '2026-07-02T00:00:00Z',
      }),
      release('vB', false, {
        node_id: 'R_3',
        published_at: '2026-07-02T00:00:00Z',
      }),
    ];

    assert.deepEqual(
      __refreshTest.orderReleaseCatalogByPublication(tied).map((item: any) => item.node_id),
      ['R_1', 'R_2', 'R_3'],
    );
    assert.throws(
      () => __refreshTest.selectReleaseWindow(releaseCatalog(tied), 1),
      /publication timestamp ambiguity/,
    );

    const prereleaseTie = [
      release('v2', false, { published_at: '2026-07-03T00:00:00Z' }),
      release('v2-beta.2', true, {
        node_id: 'R_beta_2',
        published_at: '2026-07-02T00:00:00Z',
      }),
      release('v2-beta.1', true, {
        node_id: 'R_beta_1',
        published_at: '2026-07-02T00:00:00Z',
      }),
      release('v1', false, { published_at: '2026-07-01T00:00:00Z' }),
    ];
    const selection = __refreshTest.selectReleaseWindow(releaseCatalog(prereleaseTie), 1);
    assert.deepEqual(
      selection.ordered.map((item: any) => item.tag_name),
      ['v2', 'v2-beta.1', 'v2-beta.2', 'v1'],
    );
    assert.equal(selection.predecessorBoundary?.tag_name, 'v1');
  });

  it('fails release selection on missing or malformed publication timestamps', () => {
    assert.throws(
      () => __refreshTest.selectReleaseWindow(releaseCatalog([
        release('v-missing', false, { published_at: null }),
      ]), 1),
      /missing published_at/,
    );
    assert.throws(
      () => __refreshTest.selectReleaseWindow(releaseCatalog([
        release('v-malformed', false, { published_at: 'not-a-timestamp' }),
      ]), 1),
      /malformed published_at/,
    );
  });
});

function release(
  tag_name: string,
  prerelease = false,
  overrides: Partial<GhReleaseCatalog['releases'][number]> = {},
): GhReleaseCatalog['releases'][number] {
  return {
    node_id: `R_${tag_name}`,
    tag_name,
    tag_commit_oid: '1'.repeat(40),
    name: tag_name,
    published_at: '2026-07-02T00:00:00Z',
    created_at: '2026-07-02T00:00:00Z',
    updated_at: '2026-07-02T00:00:00Z',
    html_url: `https://example.test/releases/${tag_name}`,
    prerelease,
    draft: false,
    body: null,
    ...overrides,
  };
}

function releaseCatalog(
  releases: GhReleaseCatalog['releases'],
  metadata: Partial<GhReleaseCatalog['metadata']> = {},
): GhReleaseCatalog {
  return {
    releases,
    metadata: {
      exhausted: true,
      stabilized: true,
      totalCount: releases.length,
      nodeCount: releases.length,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      digest: 'test-digest',
      sourceOrder: 'CREATED_AT_DESC',
      ...metadata,
    },
  };
}

function issueTableCount(table: string, issueNumber: number): number {
  return (db.prepare(`
    SELECT COUNT(*) AS count
    FROM ${table}
    WHERE issue_number=?
  `).get(issueNumber) as { count: number }).count;
}

function issueTableRows(
  table: string,
  issueNumber: number,
): Array<Record<string, unknown>> {
  return db.prepare(`
    SELECT *
    FROM ${table}
    WHERE issue_number=?
    ORDER BY rowid
  `).all(issueNumber).map((row) => ({ ...(row as Record<string, unknown>) }));
}

function assertNoPersistedIssueEvidence(issueNumber: number): void {
  assert.equal(
    (db.prepare(`
      SELECT COUNT(*) AS count
      FROM issues
      WHERE number=?
    `).get(issueNumber) as { count: number }).count,
    0,
    'issues',
  );
  for (const table of [
    'issue_comment_snapshots',
    'issue_label_events',
    'issue_label_evidence_snapshots',
    'issue_label_snapshots',
    'issue_state_event_snapshots',
    'issue_closure_events',
    'classifications',
    'closure_claim_source_snapshots',
    'closure_claim_candidates',
    'closure_claim_extraction_receipts',
  ]) {
    assert.equal(issueTableCount(table, issueNumber), 0, table);
  }
  assert.equal(
    (db.prepare(`
      SELECT COUNT(*) AS count
      FROM closure_claim_extraction_receipt_members members
      JOIN closure_claim_extraction_receipts receipts
        ON receipts.receipt_id=members.receipt_id
      WHERE receipts.issue_number=?
    `).get(issueNumber) as { count: number }).count,
    0,
    'closure_claim_extraction_receipt_members',
  );
}

function issue(comments: number, overrides: Partial<GhIssue> = {}): GhIssue {
  const number = overrides.number ?? 42;
  return {
    node_id: `ISSUE-node-${number}`,
    node_type: 'Issue',
    number,
    title: 'Issue',
    body: null,
    state: 'open' as const,
    user: {
      id: `ACTOR-reporter-${number}`,
      type: 'User',
      login: 'reporter',
    },
    author_association: 'CONTRIBUTOR',
    created_at: '2026-07-01T00:00:00.000Z',
    updated_at: '2026-07-02T00:00:00.000Z',
    closed_at: null,
    html_url: `https://example.test/issues/${number}`,
    comments,
    labels: [],
    ...overrides,
  };
}

function comment(id: number): GhComment {
  return {
    id,
    node_id: `COMMENT-node-${id}`,
    node_type: 'IssueComment',
    url: `https://example.test/comments/${id}`,
    user: {
      id: `ACTOR-user-${id}`,
      type: 'User',
      login: `user-${id}`,
    },
    author_association: 'CONTRIBUTOR',
    body: `comment ${id}`,
    created_at: '2026-07-01T01:00:00.000Z',
    updated_at: '2026-07-01T01:00:00.000Z',
  };
}

function snapshot(
  totalCount: number,
  comments: GhComment[],
  overrides: Partial<GhIssueCommentSnapshot> = {},
): GhIssueCommentSnapshot {
  const repositoryNodeId =
    overrides.repositoryNodeId ?? 'REPO-node-openclaw';
  const issueNumber = overrides.issueNumber ?? 42;
  const issueNodeId = overrides.issueNodeId ?? `ISSUE-node-${issueNumber}`;
  const issueNodeType = overrides.issueNodeType ?? 'Issue';
  const issueAuthor = overrides.issueAuthor ?? {
    nodeId: `ACTOR-reporter-${issueNumber}`,
    actorType: 'User',
    login: 'reporter',
  };
  const issueUpdatedAt =
    overrides.issueUpdatedAt ?? '2026-07-02T00:00:00.000Z';
  const finalTotalCount = overrides.totalCount ?? totalCount;
  const finalComments = overrides.comments ?? comments;
  let commentsDigest = overrides.commentsDigest;
  if (!commentsDigest) {
    try {
      commentsDigest = commentEvidenceDigest(finalTotalCount, finalComments);
    } catch {
      commentsDigest = 'invalid-test-digest';
    }
  }
  let authorityDigest = overrides.authorityDigest;
  let stabilization = overrides.stabilization;
  try {
    const snapshotIdentity = {
      repositoryNodeId,
      issueNodeId,
      issueNodeType,
      issueAuthor,
    };
    const firstSweep = commentEvidenceSweepIdentity({
      sweepOrdinal: 1,
      issueUpdatedAt,
      totalCount: finalTotalCount,
      comments: finalComments,
      snapshotIdentity,
    });
    const secondSweep = commentEvidenceSweepIdentity({
      sweepOrdinal: 2,
      issueUpdatedAt,
      totalCount: finalTotalCount,
      comments: finalComments,
      snapshotIdentity,
    });
    authorityDigest ??= secondSweep.authorityDigest;
    stabilization ??= commentEvidenceStabilizationIdentity(
      firstSweep,
      secondSweep,
      2,
    );
  } catch {
    authorityDigest ??= '0'.repeat(64);
    stabilization ??= {
      schemaVersion: 1,
      sweepCount: 2,
      firstSweep: {
        schemaVersion: 1,
        sweepOrdinal: 1,
        issueUpdatedAt,
        totalCount: finalTotalCount,
        authorityDigest,
        identityDigest: '1'.repeat(64),
      },
      secondSweep: {
        schemaVersion: 1,
        sweepOrdinal: 2,
        issueUpdatedAt,
        totalCount: finalTotalCount,
        authorityDigest,
        identityDigest: '2'.repeat(64),
      },
      identityDigest: '3'.repeat(64),
    };
  }
  if (!authorityDigest || !stabilization) {
    throw new Error('Test comment snapshot failed to build evidence identity');
  }
  return {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType,
    issueAuthor,
    issueUpdatedAt,
    totalCount: finalTotalCount,
    comments: finalComments,
    commentsDigest,
    authorityDigest,
    stabilization,
    ...overrides,
  };
}

function issueRow(issueNumber: number, comments: number, updatedAt: string) {
  return {
    number: issueNumber,
    node_id: `ISSUE-node-${issueNumber}`,
    state: 'open',
    title: `Issue ${issueNumber}`,
    author: 'reporter',
    author_node_id: `ACTOR-reporter-${issueNumber}`,
    author_type: 'User',
    author_association: 'CONTRIBUTOR',
    html_url: `https://example.test/issues/${issueNumber}`,
    created_at: '2026-07-01T00:00:00.000Z',
    updated_at: updatedAt,
    closed_at: null,
    comments,
    labels: '[]',
    is_bot: 0,
  };
}

function classification(): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'medium',
    scope: 'moderate',
    functionality: 'core',
    affectedUsers: 'some',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: 'v2099.7.1',
    confidence: 0.9,
    rationale: 'test classification',
  };
}

function fixEvidence(issueNumber: number, withClosure = false): GhIssueFixEvidence {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = `ISSUE-node-${issueNumber}`;
  const closureEvents = withClosure ? [{
    issueNumber,
    eventId: `closed-${issueNumber}`,
    eventType: 'ClosedEvent' as const,
    closedAt: '2026-07-02T00:00:00.000Z',
    connectionOrdinal: 0,
    actorNodeId: 'ACTOR-maintainer',
    actorLogin: 'maintainer',
    actorType: 'User',
    stateReason: 'COMPLETED',
    closerType: 'Commit',
    closerNumber: null,
    closerNodeId: `COMMIT-node-${issueNumber}`,
    closerOid: 'c'.repeat(40),
    raw: {
      __typename: 'ClosedEvent',
      id: `closed-${issueNumber}`,
      createdAt: '2026-07-02T00:00:00.000Z',
      actor: {
        id: 'ACTOR-maintainer',
        __typename: 'User',
        login: 'maintainer',
      },
      closer: {
        id: `COMMIT-node-${issueNumber}`,
        __typename: 'Commit',
        oid: 'c'.repeat(40),
      },
      stateReason: 'COMPLETED',
    },
  }] : [];
  const reopenEvents = withClosure ? [{
    issueNumber,
    eventId: `reopened-${issueNumber}`,
    eventType: 'ReopenedEvent' as const,
    reopenedAt: '2026-07-02T00:00:00.000Z',
    connectionOrdinal: 1,
    actorNodeId: 'ACTOR-maintainer',
    actorLogin: 'maintainer',
    actorType: 'User',
    raw: {
      __typename: 'ReopenedEvent',
      id: `reopened-${issueNumber}`,
      createdAt: '2026-07-02T00:00:00.000Z',
      actor: {
        id: 'ACTOR-maintainer',
        __typename: 'User',
        login: 'maintainer',
      },
    },
  }] : [];
  const normalizedEvents = normalizeIssueStateEvents([
    ...closureEvents.map((event) => ({
      eventId: event.eventId,
      eventNodeType: event.eventType,
      type: 'closed' as const,
      occurredAt: event.closedAt,
      connectionOrdinal: event.connectionOrdinal,
      actorNodeId: event.actorNodeId,
      actorLogin: event.actorLogin,
      actorType: event.actorType,
      stateReason: event.stateReason,
      closerNodeId: event.closerNodeId,
      closerType: event.closerType,
      closerNumber: event.closerNumber,
      closerOid: event.closerOid,
    })),
    ...reopenEvents.map((event) => ({
      eventId: event.eventId,
      eventNodeType: event.eventType,
      type: 'reopened' as const,
      occurredAt: event.reopenedAt,
      connectionOrdinal: event.connectionOrdinal,
      actorNodeId: event.actorNodeId,
      actorLogin: event.actorLogin,
      actorType: event.actorType,
      stateReason: null,
      closerNodeId: null,
      closerType: null,
      closerNumber: null,
      closerOid: null,
    })),
  ]);
  const stateSweep = {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue' as const,
    issueState: 'open' as const,
    issueUpdatedAt: '2026-07-02T00:00:00.000Z',
    totalCount: normalizedEvents.length,
    events: normalizedEvents,
  };
  const firstStateSweep = issueStateEventSweepIdentity({
    ...stateSweep,
    sweepOrdinal: 1,
  });
  const secondStateSweep = issueStateEventSweepIdentity({
    ...stateSweep,
    sweepOrdinal: 2,
  });
  return {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    stateSnapshot: {
      schemaVersion: ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
      repositoryNodeId,
      issueNumber,
      issueState: 'open',
      issueUpdatedAt: '2026-07-02T00:00:00.000Z',
      totalCount: normalizedEvents.length,
      fetchedCount: normalizedEvents.length,
      eventsDigest: issueStateEventsDigest(normalizedEvents, {
        repositoryNodeId,
        issueNodeId,
        issueNodeType: 'Issue',
      }),
      authorityDigest: secondStateSweep.sweepDigest,
      sweepIdentity: secondStateSweep,
      sweepCount: 2,
      stabilized: true,
      stabilization: issueStateEventStabilizationIdentity(
        firstStateSweep,
        secondStateSweep,
        2,
      ),
    },
    connectionSnapshots: {
      closedByPullRequestsReferences: connectionSnapshot([], []),
      stateEvents: connectionSnapshot(
        normalizedEvents.map((event) => event.eventId),
        normalizedEvents,
      ),
      referenceEvents: connectionSnapshot([], []),
    },
    closureEvents,
    reopenEvents,
    prLinks: [],
    pullRequests: [],
    commitReferences: [],
  };
}

function connectionSnapshot(
  identities: string[],
  contents: unknown[],
): GhIssueFixEvidenceConnectionSnapshot {
  assert.equal(identities.length, contents.length);
  const totalCount = identities.length;
  return {
    totalCount,
    observedTotalCount: totalCount,
    postBoundaryGrowthCount: 0,
    fetchedCount: totalCount,
    terminalFirstNIdentity: identities.at(-1) ?? null,
    identityDigest: createHash('sha256')
      .update(JSON.stringify([totalCount, identities]))
      .digest('hex'),
    contentDigest: createHash('sha256')
      .update(JSON.stringify([totalCount, contents]))
      .digest('hex'),
    sourceOrder: 'CONNECTION_ASC',
  };
}

function labelEvent(
  issueNumber: number,
  eventId: string,
  overrides: {
    action?: 'labeled' | 'unlabeled';
    labelName?: string;
    labelNodeId?: string;
    actorLogin?: string | null;
    actorNodeId?: string | null;
    actorType?: string | null;
    createdAt?: string;
  } = {},
): GhIssueLabelEvent {
  const action = overrides.action ?? 'labeled';
  const labelName = overrides.labelName ?? 'bug';
  const labelNodeId =
    overrides.labelNodeId ?? `LABEL-node-${labelName.replaceAll(':', '-')}`;
  const actorLogin =
    overrides.actorLogin === undefined ? 'maintainer' : overrides.actorLogin;
  const actorNodeId = actorLogin == null
    ? null
    : overrides.actorNodeId ?? `ACTOR-${actorLogin}`;
  const actorType = actorLogin == null
    ? null
    : overrides.actorType ?? 'User';
  const createdAt =
    overrides.createdAt ?? '2026-07-02T00:00:00.000Z';
  const actor = actorLogin == null
    ? null
    : {
        id: actorNodeId,
        __typename: actorType,
        login: actorLogin,
      };
  return {
    issueNumber,
    issueNodeId: `ISSUE-node-${issueNumber}`,
    issueNodeType: 'Issue',
    eventId,
    action,
    labelNodeId,
    labelName,
    actorNodeId,
    actorLogin,
    actorType,
    createdAt,
    raw: {
      __typename: action === 'labeled' ? 'LabeledEvent' : 'UnlabeledEvent',
      id: eventId,
      createdAt,
      actor,
      label: {
        id: labelNodeId,
        name: labelName,
      },
    },
  };
}

function labelEvidenceSnapshot(
  sourceIssue: GhIssue,
  events: GhIssueLabelEvent[],
): GhIssueLabelEvidenceSnapshot {
  return {
    schemaVersion: 2,
    repository: 'openclaw/openclaw',
    repositoryNodeId: 'REPO-node-openclaw',
    issueNumber: sourceIssue.number,
    issueNodeId: sourceIssue.node_id,
    issueNodeType: sourceIssue.node_type,
    capturedAt: '2026-07-04T00:00:00.000Z',
    issueUpdatedAt: sourceIssue.updated_at,
    totalCount: events.length,
    fetchedCount: events.length,
    pageCount: 1,
    sweepCount: 2,
    stabilized: true,
    events,
  };
}

function reconciliationDependencies(input: {
  issueNumber: number;
  issue: GhIssue;
  snapshot: GhIssueCommentSnapshot;
  labelEvents: GhIssueLabelEvent[];
  fixEvidence: GhIssueFixEvidence;
  classify: (issue: GhIssue, comments: GhComment[], releaseTags: string[]) => Promise<any>;
}) {
  return {
    async listIssues() {
      return new Map([[input.issueNumber, input.issue]]);
    },
    async listSnapshots() {
      return new Map([[input.issueNumber, input.snapshot]]);
    },
    async listLabelEvidence() {
      return new Map([[
        input.issueNumber,
        labelEvidenceSnapshot(input.issue, input.labelEvents),
      ]]);
    },
    async listFixEvidence() {
      return new Map([[input.issueNumber, input.fixEvidence]]);
    },
    classify: input.classify,
  };
}

function closureRunContext(
  snapshots: Array<[number, GhIssueCommentSnapshot]>,
) {
  return {
    commentSnapshotsByIssue: new Map(snapshots),
    commentSnapshotRequests: new Map(),
    commentsByIssue: new Map<number, GhComment[]>(),
    commentSnapshotMetadataDriftIssueNumbers: new Set(snapshots.map(([issueNumber]) => issueNumber)),
    stateSnapshotMetadataDriftIssueNumbers: new Set(),
    fixEvidenceByIssue: new Map<number, GhIssueFixEvidence>(),
    fixEvidenceRequests: new Map(),
    pullRequestsByKey: new Map(),
    pullRequestRequests: new Map(),
    permissiveMissingPullRequestKeys: new Set(),
    issueEvidenceRevisionsByIssue: new Map(),
  };
}

function compareCodePointStrings(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function advisory(input: {
  ghsaId?: string;
  state?: 'published' | 'withdrawn';
  withdrawnAt?: string | null;
  ecosystem?: string;
  packageName?: string | null;
  vulnerableVersionRange?: string | null;
  patchedVersions?: string | null;
} = {}) {
  const ghsaId = input.ghsaId ?? 'GHSA-test';
  const state = input.state ?? 'published';
  return {
    ghsa_id: ghsaId,
    cve_id: 'CVE-2026-0001',
    summary: `Summary for ${ghsaId}`,
    severity: 'high' as const,
    state,
    published_at: '2026-07-01T00:00:00Z',
    withdrawn_at: input.withdrawnAt ?? (state === 'withdrawn' ? '2026-07-02T00:00:00Z' : null),
    html_url: `https://github.com/advisories/${ghsaId}`,
    vulnerabilities: [{
      package: {
        ecosystem: input.ecosystem ?? 'npm',
        name: input.packageName === undefined ? 'openclaw' : input.packageName,
      },
      vulnerable_version_range: input.vulnerableVersionRange === undefined
        ? '< 2026.6.2'
        : input.vulnerableVersionRange,
      patched_versions: input.patchedVersions === undefined ? '2026.6.2' : input.patchedVersions,
    }],
  };
}

function advisoryCatalog(advisories: ReturnType<typeof advisory>[]) {
  const nodeCount = advisories.reduce(
    (sum, advisoryRow) => sum + advisoryRow.vulnerabilities.length,
    0,
  );
  return {
    advisories,
    metadata: {
      exhausted: true,
      stabilized: true,
      totalCount: nodeCount,
      nodeCount,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      digest: 'a'.repeat(64),
      sourceOrder: 'UPDATED_AT_DESC' as const,
    },
  };
}
