import { after, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SCORE_MODEL_VERSION, selectRecommendation } from './score.ts';
import { PROMPT_VERSION } from './llm.ts';
import { releaseValidationForecastContentHash } from './releaseValidation.ts';
import { buildScoreAuthorityResolutionRun } from './scoreAuthorityResolution.ts';
import { config } from '../config.ts';
import { planReleaseValidationProofLifecycle } from './releaseValidationProofLifecycle.ts';
import { stageReleaseValidationOutcomeRows } from './releaseValidationBatch.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownedTestDir = assignedWorkerDatabasePath === null
  ? mkdtempSync(join(tmpdir(), 'radar-release-forecast-shared-'))
  : null;
const testDatabasePath =
  assignedWorkerDatabasePath ?? join(ownedTestDir!, 'radar.db');
const inheritedDotenvPath =
  process.env.DOTENV_CONFIG_PATH?.trim() || null;
const ownedDotenvDir = inheritedDotenvPath === null
  ? ownedTestDir ?? mkdtempSync(join(tmpdir(), 'radar-release-forecast-env-'))
  : null;

if (assignedWorkerDatabasePath) {
  assert.equal(
    process.env.DB_PATH,
    assignedWorkerDatabasePath,
    'guarded tests must use their assigned private database',
  );
} else {
  process.env.DB_PATH = testDatabasePath;
}
if (inheritedDotenvPath === null) {
  const emptyDotenvPath = join(ownedDotenvDir!, 'empty.env');
  writeFileSync(emptyDotenvPath, '');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
}

let sharedModules: {
  db: typeof import('./db.ts');
  scoring: typeof import('./releaseScoring.ts');
} | null = null;
let savepointSequence = 0;

async function freshModules(name: string) {
  if (!sharedModules) {
    const scoring = await import(
      `./releaseScoring.ts?release-forecast-shared-${Date.now()}-${Math.random()}`
    );
    const db = await import('./db.ts');
    sharedModules = { db, scoring };
  }
  const savepoint = `release_forecast_test_${++savepointSequence}`;
  sharedModules.db.db.exec(`SAVEPOINT ${savepoint}`);
  let active = true;
  return {
    db: sharedModules.db,
    scoring: sharedModules.scoring,
    cleanup() {
      if (!active) return;
      sharedModules!.db.db.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
      sharedModules!.db.db.exec(`RELEASE SAVEPOINT ${savepoint}`);
      active = false;
    },
    name,
  };
}

after(() => {
  if (sharedModules) {
    sharedModules.db.db.close();
    sharedModules = null;
  }
  if (ownedTestDir) {
    rmSync(ownedTestDir, { recursive: true, force: true });
  }
  if (ownedDotenvDir && ownedDotenvDir !== ownedTestDir) {
    rmSync(ownedDotenvDir, { recursive: true, force: true });
  }
});

function seedRelease(db: any, tag: string, publishedAt: string) {
  db.upsertRelease({
    tag,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease: false,
    body: '',
  });
  db.upsertReleaseCommit({
    tag,
    tag_commit_oid: 'a'.repeat(40),
    committed_at: publishedAt,
  });
}

function buildRun(db: any, scoring: any, options: {
  tags: string[];
  stableTagsNewestFirst: string[];
  oldestScoredStablePredecessorTag: string;
  scoredAt: number;
}) {
  for (const tag of options.tags) {
    db.replaceReleaseClosureDependencySnapshot(
      db.releaseClosureDependencyIdentity(tag, []),
    );
  }
  return scoring.buildReleaseScoreRun({
    releases: options.tags.map((tag) => db.getRelease(tag)),
    allFetchedTags: options.tags,
    stableTagsNewestFirst: options.stableTagsNewestFirst,
    oldestScoredStablePredecessorTag: options.oldestScoredStablePredecessorTag,
    nowForRelease: () => options.scoredAt,
  });
}

function rebuildRecommendation(scoring: any, run: any) {
  const selection = selectRecommendation(run.scored.map((result: any) => ({
    tag: result.rel.tag,
    status: result.conf.status,
    score: result.conf.score,
    publishedAt: result.rel.published_at,
  })));
  const decisions = scoring.__releaseScoringTest.recommendationDecisionsForRun(
    run.scored,
    selection,
  );
  run.recommendedTag = selection.selectedTag;
  for (const result of run.scored) {
    const decision = decisions.get(result.rel.tag);
    result.recommendationDecision = decision;
    result.explanation = scoring.__releaseScoringTest.buildScoreExplanation(result, decision);
    result.scoreLedger = result.explanation.scoreLedger;
  }
}

function activateCatalog(db: any, tagsNewestFirst: string[]) {
  return db.replaceActiveReleaseCatalog(tagsNewestFirst.map((tag) => {
    const release = db.getRelease(tag);
    const commit = db.getReleaseCommit(tag);
    return {
      node_id: release.node_id,
      catalog_tag_commit_oid: commit.tag_commit_oid,
      tag: release.tag,
      name: release.name,
      published_at: release.published_at,
      created_at: release.created_at,
      updated_at: release.updated_at,
      html_url: release.html_url,
      prerelease: release.prerelease === 1,
      body: release.body,
    };
  }), {
    capture: { source: 'test_fixture' },
  });
}

function seedCanonicalForecastLifecycle(db: any, input: {
  tagsNewestFirst: string[];
  codeRevision: string;
  observedAt: string;
}) {
  const plan = planReleaseValidationProofLifecycle({
    existing: db.readReleaseValidationProofBundle(),
    repository: `${config.github.owner}/${config.github.repo}`,
    observedAt: input.observedAt,
    source: 'forecast-test-catalog',
    releases: input.tagsNewestFirst.map((tag) => {
      const release = db.getRelease(tag);
      const commit = db.getReleaseCommit(tag);
      return {
        repository: `${config.github.owner}/${config.github.repo}`,
        nodeId: release.node_id,
        tagCommitOid: commit.tag_commit_oid,
        publishedAt: release.published_at,
        aliases: [release.tag],
      };
    }),
    modelVersion: SCORE_MODEL_VERSION,
    promptVersion: PROMPT_VERSION,
    codeRevision: input.codeRevision,
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
  });
  db.appendReleaseValidationProof(plan.append);
  return plan;
}

function catalogAttestation(
  db: any,
  scoreBuiltAt: string,
  finalObservedAt: string,
) {
  const local = db.currentActiveReleaseCatalog();
  const remote = {
    digest: 'a'.repeat(64),
    totalCount: local.releaseCount,
    nodeCount: local.releaseCount,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    exhausted: true,
    stabilized: true,
    sourceOrder: 'CREATED_AT_DESC',
  };
  return {
    schemaVersion: 4,
    initialRemoteCatalog: remote,
    finalRemoteCatalog: { ...remote },
    finalObservedAt,
    projectedActiveCatalog: {
      digest: local.digest,
      releaseCount: local.releaseCount,
    },
    localActiveCatalog: {
      digest: local.digest,
      releaseCount: local.releaseCount,
    },
    latestStable: local.latestStable,
    scoreBuiltAt,
  };
}

function commitClock(
  beforeWallMs: number,
  afterWallMs: number,
  beforeMonotonicMs = 1_000,
  afterMonotonicMs = 1_001,
) {
  const walls = [beforeWallMs, afterWallMs];
  const monotonic = [beforeMonotonicMs, afterMonotonicMs];
  return {
    wallTimeMs: () => walls.shift()!,
    monotonicTimeMs: () => monotonic.shift()!,
  };
}

function sealTestRefreshPublication(
  db: any,
  runId: string,
  persistence: any,
) {
  if (db.getRefreshCaptureReceipt(runId)) return;
  const metadata = JSON.parse(
    db.getMeta('score_persistence_last_run') ?? 'null',
  );
  assert.equal(metadata.operationRunId, runId);
  assert.deepEqual(metadata.releaseTags, metadata.releaseTags?.filter(
    (tag: unknown) => typeof tag === 'string',
  ));
  const leaseName = `forecast-test-lease:${runId}`;
  const leaseHolderId = `forecast-test-holder:${runId}`;
  const leaseAcquiredAtMs = Date.now();
  const leaseTtlMs = 300_000;
  const scoreStartedAt = persistence.commitTiming.commitNotBefore;
  const scoreCompletedAt = persistence.commitTiming.commitNotAfter;
  const scoreStartedAtMs = Date.parse(scoreStartedAt);
  const scoreCompletedAtMs = Date.parse(scoreCompletedAt);
  const startedAt = new Date(scoreStartedAtMs - 1).toISOString();
  const leaseAcquiredAt = new Date(leaseAcquiredAtMs).toISOString();
  assert.equal(
    db.acquireRefreshLease(
      leaseName,
      leaseHolderId,
      leaseAcquiredAt,
      leaseTtlMs,
    ),
    true,
  );
  try {
    db.beginRefreshOperationAttempt({
      run_id: runId,
      operation: 'refresh',
      trigger: 'forecast-test',
      started_at: startedAt,
      lease_name: leaseName,
      lease_holder_id: leaseHolderId,
      lease_expires_at: new Date(
        leaseAcquiredAtMs + leaseTtlMs,
      ).toISOString(),
      code_revision: persistence.codeRevision,
      effective_config: { schemaVersion: 1 },
    });
    db.appendRefreshOperationStageEvent({
      run_id: runId,
      lease_name: leaseName,
      lease_holder_id: leaseHolderId,
      stage: 'score.persist',
      status: 'started',
      occurred_at: scoreStartedAt,
    });
    db.appendRefreshOperationStageEvent({
      run_id: runId,
      lease_name: leaseName,
      lease_holder_id: leaseHolderId,
      stage: 'score.persist',
      status: 'completed',
      occurred_at: scoreCompletedAt,
      duration_ms: scoreCompletedAtMs - scoreStartedAtMs,
      counts: { scoredReleases: metadata.releaseTags.length },
      details: {
        historyRunId: persistence.historyRunId,
        historyRunContentHash: persistence.historyRunContentHash,
        authorityRunId: persistence.authorityRunId,
        authorityRunContentHash: persistence.authorityRunContentHash,
        historyV2SealContentHash: persistence.historyV2SealContentHash,
        commitNotBefore: scoreStartedAt,
        commitNotAfter: scoreCompletedAt,
      },
    });
    db.appendRefreshOperationStageEvent({
      run_id: runId,
      lease_name: leaseName,
      lease_holder_id: leaseHolderId,
      stage: 'forecast.capture',
      status: 'started',
      occurred_at: scoreCompletedAt,
    });
    db.appendRefreshOperationStageEvent({
      run_id: runId,
      lease_name: leaseName,
      lease_holder_id: leaseHolderId,
      stage: 'forecast.capture',
      status: 'completed',
      occurred_at: scoreCompletedAt,
      duration_ms: 0,
      counts: { validationForecasts: 0 },
      details: { eligibilityOutcome: 'not_eligible' },
    });
    db.appendRefreshCaptureReceipt({
      run_id: runId,
      lease_name: leaseName,
      lease_holder_id: leaseHolderId,
      status: 'success',
      finished_at: scoreCompletedAt,
      duration_ms: scoreCompletedAtMs - Date.parse(startedAt),
      payload: {
        schemaVersion: 1,
        operation: 'refresh',
        trigger: 'forecast-test',
        codeRevision: persistence.codeRevision,
        scoreHistory: {
          runId: persistence.historyRunId,
          contentHash: persistence.historyRunContentHash,
          persistedAt: persistence.persistedAt,
        },
        scoreAuthority: {
          runId: persistence.authorityRunId,
          contentHash: persistence.authorityRunContentHash,
          historyV2SealContentHash: persistence.historyV2SealContentHash,
        },
        scoreCommit: persistence.commitTiming,
        releaseTags: metadata.releaseTags,
        forecast: {
          eligibilityOutcome: 'not_eligible',
          decisionIds: [],
          captures: [],
        },
      },
    });
  } finally {
    assert.equal(db.releaseRefreshLease(leaseName, leaseHolderId), true);
  }
}

function seedSingleReleaseForecastSeries(db: any, input: {
  runId: string;
  modelVersion: string;
  promptVersion: number;
  releaseTag: string;
  sourceIdentityJson: string;
  codeRevision?: string | null;
}) {
  const release = db.getRelease(input.releaseTag);
  const recommendationDecision = {
    releaseTag: input.releaseTag,
    selectedTag: input.releaseTag,
    policyCode: 'highest_confidence_with_recency_tolerance',
  };
  return [
    {
      opportunityCode: 'first_verified_after_3h',
      ageHours: 4,
      minAgeHours: 3,
      maxAgeHours: 6,
    },
    {
      opportunityCode: 'first_verified_after_24h',
      ageHours: 25,
      minAgeHours: 24,
      maxAgeHours: 30,
    },
  ].map(({ opportunityCode, ageHours, minAgeHours, maxAgeHours }) => {
    const recordedAt = new Date(
      Date.parse(release.published_at) + ageHours * 3_600_000,
    ).toISOString();
    const runId = `${input.runId}:${opportunityCode}`;
    const sourceIdentity = JSON.parse(input.sourceIdentityJson);
    const authorityRunId = `score-authority:${runId}`;
    const existingAuthorityRun =
      db.getScoreAuthorityResolutionRun(authorityRunId);
    const authorityRun = existingAuthorityRun ?? (() => {
      const previousAuthorityRun =
        db.listScoreAuthorityResolutionRuns().at(-1) ?? null;
      const created = buildScoreAuthorityResolutionRun({
        authorityRunId,
        sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
        sourceIdentityDigest: sourceIdentity.digest,
        recordedAt,
        previousContentHash: previousAuthorityRun?.contentHash ?? null,
        rows: [],
      });
      db.insertScoreAuthorityResolutionRun(created);
      return created;
    })();
    const audit = {
      release_tag: input.releaseTag,
      scored_at: recordedAt,
      score_model_version: input.modelVersion,
      prompt_version: input.promptVersion,
      final_score: 8,
      status: 'eligible',
      band: 'solid',
      recommended: 1,
      input_json: '{}',
      components_json: '{}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
      source_identity_json: input.sourceIdentityJson,
      authority_run_id: authorityRunId,
    };
    db.insertReleaseScoreAuditHistory(runId, recordedAt, audit);
    const seal = db.sealReleaseScoreAuditHistoryRun(runId, recordedAt);
    const historyV2Seal = db.sealReleaseScoreAuditHistoryV2({
      historyRunId: runId,
      authorityRunId,
      sealedAt: recordedAt,
    });
    const catalog = db.currentActiveReleaseCatalog();
    const catalogAttestation = {
      schemaVersion: 4,
      initialRemoteCatalog: {
        digest: 'a'.repeat(64),
        totalCount: catalog.releaseCount,
        nodeCount: catalog.releaseCount,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        exhausted: true,
        stabilized: true,
        sourceOrder: 'CREATED_AT_DESC',
      },
      finalRemoteCatalog: {
        digest: 'a'.repeat(64),
        totalCount: catalog.releaseCount,
        nodeCount: catalog.releaseCount,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        exhausted: true,
        stabilized: true,
        sourceOrder: 'CREATED_AT_DESC',
      },
      finalObservedAt: recordedAt,
      projectedActiveCatalog: {
        digest: catalog.digest,
        releaseCount: catalog.releaseCount,
      },
      localActiveCatalog: {
        digest: catalog.digest,
        releaseCount: catalog.releaseCount,
      },
      latestStable: catalog.latestStable,
      scoreBuiltAt: recordedAt,
    };
    const candidates = [{
      releaseTag: input.releaseTag,
      releasePublishedAt: release.published_at,
      scoreSnapshot: {
        scoredAt: audit.scored_at,
        finalScore: audit.final_score,
        status: audit.status,
        band: audit.band,
        recommended: audit.recommended === 1,
      },
      recommendationDecision,
      auditSnapshot: {
        run_id: runId,
        recorded_at: recordedAt,
        ...audit,
      },
    }];
    return db.insertReleaseValidationForecast({
      opportunity_code: opportunityCode,
      recorded_at: recordedAt,
      latest_release_tag: input.releaseTag,
      latest_release_published_at: release.published_at,
      selected_tag: input.releaseTag,
      audit_history_run_id: runId,
      score_model_version: input.modelVersion,
      prompt_version: input.promptVersion,
      policy_code: recommendationDecision.policyCode,
      candidate_scores_json: JSON.stringify(candidates),
      decision_json: JSON.stringify({
        schemaVersion: 4,
        opportunityCode,
        recordedAt,
        latestReleaseTag: input.releaseTag,
        latestReleasePublishedAt: release.published_at,
        latestReleaseAgeHours: ageHours,
        opportunityWindow: {
          minAgeHours,
          maxAgeHours,
          windowStartAt: new Date(
            Date.parse(release.published_at) + minAgeHours * 3_600_000,
          ).toISOString(),
          windowEndAt: new Date(
            Date.parse(release.published_at) + maxAgeHours * 3_600_000,
          ).toISOString(),
          windowStartMs:
            Date.parse(release.published_at) + minAgeHours * 3_600_000,
          windowEndMs:
            Date.parse(release.published_at) + maxAgeHours * 3_600_000,
          observedAtMs: Date.parse(recordedAt),
          observedAgeHours: ageHours,
          valid: true,
        },
        selectedTag: input.releaseTag,
        recommendationDecision,
        scoreCommit: {
          schemaVersion: 4,
          historyRunId: runId,
          historyRunContentHash: seal.row.content_hash,
          authorityRunId,
          authorityRunContentHash: authorityRun.contentHash,
          historyV2SealContentHash: historyV2Seal.row.contentHash,
          historyRecordedAt: recordedAt,
          commitNotBefore: recordedAt,
          commitNotAfter: recordedAt,
          commitNotBeforeMs: Date.parse(recordedAt),
          commitNotAfterMs: Date.parse(recordedAt),
        },
        catalogAttestation,
      }),
      source_identity_json: input.sourceIdentityJson,
      code_revision: input.codeRevision ?? input.modelVersion,
    });
  });
}

describe('release scoring forecast persistence', () => {
  it('rolls back real score history and forecasts when publication crashes before its receipt', async () => {
    const { db, scoring, cleanup } = await freshModules('atomic-publication-rollback');
    try {
      const codeRevision = 'atomic-publication-revision';
      const publishedAtMs = Date.parse('2026-07-04T00:00:00.000Z');
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(db, 'v-boundary', new Date(
        publishedAtMs - 24 * 3_600_000,
      ).toISOString());
      activateCatalog(db, ['v-latest', 'v-boundary']);
      seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest', 'v-boundary'],
        codeRevision,
        observedAt: new Date(publishedAtMs).toISOString(),
      });
      const run = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, run);
      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 1).toISOString(),
      );
      const issueCrawl = {
        schemaVersion: 2,
        startedAt: new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        finishedAt: new Date(publishedAtMs + 2 * 3_600_000 + 1_000).toISOString(),
        stopReason: 'exhausted',
      };
      const historyRunId = 'refresh:atomic-publication-crash';

      assert.throws(
        () => db.runInWriteTransaction(() => {
          const persistence = scoring.persistReleaseScoreRun(run, {
            source: 'refresh',
            runId: 'atomic-publication-crash',
            codeRevision,
            catalogAttestation: attestation,
            issueCrawl,
            clock: commitClock(
              publishedAtMs + 4 * 3_600_000,
              publishedAtMs + 4 * 3_600_000 + 1,
            ),
          });
          scoring.finalizeReleaseScorePublicationMetadata(persistence);
          const capture = scoring.captureReleaseValidationForecasts({
            run,
            scorePersistence: persistence,
          });
          assert.equal(capture.forecasts.length, 1);
          assert.equal(capture.canonicalForecasts.length, 2);
          assert.equal(db.listReleaseValidationForecasts().length, 1);
          assert.equal(db.readReleaseValidationProofBundle().forecasts.length, 2);
          throw new Error('injected crash after score and forecast construction before receipt');
        }),
        /injected crash after score and forecast construction before receipt/,
      );

      assert.equal(db.getRelease('v-latest')?.final_score, null);
      assert.equal(db.getRelease('v-latest')?.recommended, 0);
      assert.equal(db.getReleaseScoreAudit('v-latest'), undefined);
      assert.equal(db.getReleaseScoreAuditHistoryRunSeal(historyRunId), null);
      assert.equal(db.listReleaseScoreAuditHistoryForRun(historyRunId).length, 0);
      assert.equal(db.listReleaseValidationForecasts().length, 0);
      assert.equal(db.readReleaseValidationProofBundle().forecasts.length, 0);
      assert.equal(db.getMeta('score_persistence_last_run'), null);
      assert.equal(db.getMeta('last_scored_at'), null);
      assert.equal(db.getMeta('issue_crawl_last_run'), null);
    } finally {
      cleanup();
    }
  });

  it('commits score history before capture and uses retry time instead of the old history timestamp', async () => {
    const { db, scoring, cleanup } = await freshModules('commit-gap-retry');
    const priorRevision = process.env.RADAR_CODE_REVISION;
    try {
      process.env.RADAR_CODE_REVISION = 'forecast-test-revision';
      const publishedAtMs = Date.parse('2026-07-04T00:00:00.000Z');
      seedRelease(db, 'v-old', new Date(publishedAtMs - 60 * 3_600_000).toISOString());
      seedRelease(db, 'v-mid', new Date(publishedAtMs - 30 * 3_600_000).toISOString());
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(db, 'v-boundary', new Date(publishedAtMs - 90 * 3_600_000).toISOString());
      activateCatalog(db, ['v-latest', 'v-mid', 'v-old', 'v-boundary']);
      seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest', 'v-mid', 'v-old', 'v-boundary'],
        codeRevision: 'forecast-test-revision',
        observedAt: new Date(publishedAtMs).toISOString(),
      });
      const run = buildRun(db, scoring, {
        tags: ['v-old', 'v-latest', 'v-mid'],
        stableTagsNewestFirst: ['v-latest', 'v-mid', 'v-old', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, run);
      const issueCrawl = {
        schemaVersion: 1,
        startedAt: new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        finishedAt: new Date(publishedAtMs + 2 * 3_600_000 + 1_000).toISOString(),
        stopReason: 'complete',
      };
      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000 + 2_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 3_000).toISOString(),
      );
      const firstCommitMs = publishedAtMs + 3 * 3_600_000;
      const firstPersistence = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        scope: 'all',
        issueCrawl,
        runId: 'ingestion-run-1',
        codeRevision: 'forecast-test-revision',
        catalogAttestation: attestation,
        clock: commitClock(firstCommitMs, firstCommitMs + 5),
      });
      assert.equal(db.listReleaseValidationForecasts().length, 0);
      assert.ok(db.getReleaseScoreAuditHistoryRunSeal(firstPersistence.historyRunId));
      sealTestRefreshPublication(
        db,
        'ingestion-run-1',
        firstPersistence,
      );

      const retryCommitMs = publishedAtMs + 4 * 3_600_000;
      const retryPersistence = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        scope: 'all',
        issueCrawl,
        runId: 'ingestion-run-1',
        codeRevision: 'forecast-test-revision',
        catalogAttestation: attestation,
        clock: commitClock(retryCommitMs, retryCommitMs + 7),
      });
      const capture = scoring.captureReleaseValidationForecasts({
        run,
        scorePersistence: retryPersistence,
      });
      assert.equal(capture.eligibilityOutcome, 'eligible_and_captured');
      assert.deepEqual(capture.forecasts.map((item: any) => item.opportunityCode), [
        'first_verified_after_3h',
      ]);
      assert.deepEqual(
        capture.canonicalForecasts.map((item: any) => [
          item.opportunityCode,
          item.horizonCode,
          item.status,
        ]),
        [
          ['first_verified_after_3h', 'field_regression_72h', 'inserted'],
          ['first_verified_after_3h', 'security_30d', 'inserted'],
        ],
      );
      assert.equal(db.readReleaseValidationProofBundle().forecasts.length, 2);
      const forecast = db.listReleaseValidationForecasts()[0];
      const decision = JSON.parse(forecast.decision_json);
      const candidates = JSON.parse(forecast.candidate_scores_json);
      assert.equal(forecast.recorded_at, retryPersistence.commitTiming.commitNotAfter);
      assert.notEqual(forecast.recorded_at, firstPersistence.persistedAt);
      assert.equal(candidates[0].auditSnapshot.recorded_at, firstPersistence.persistedAt);
      assert.equal(decision.schemaVersion, 4);
      assert.deepEqual(decision.catalogAttestation, attestation);
      assert.equal(decision.scoreCommit.historyRecordedAt, firstPersistence.persistedAt);
      assert.equal(
        decision.scoreCommit.historyRunContentHash,
        retryPersistence.historyRunContentHash,
      );
      assert.equal(decision.opportunityWindow.observedAtMs, retryCommitMs + 7);
      const tamperedDecision = structuredClone(decision);
      tamperedDecision.catalogAttestation.finalObservedAt =
        '2026-07-04T02:59:59.000Z';
      assert.notEqual(
        releaseValidationForecastContentHash({
          ...forecast,
          decision_json: JSON.stringify(tamperedDecision),
        }),
        forecast.content_hash,
      );
      assert.deepEqual(JSON.parse(db.getMeta('issue_crawl_last_run') ?? 'null'), {
        ...issueCrawl,
        scorePersisted: true,
        scorePersistedAt: retryPersistence.commitTiming.commitNotBefore,
      });
      assert.deepEqual(
        retryPersistence.issueCrawlMetadata,
        JSON.parse(db.getMeta('issue_crawl_last_run') ?? 'null'),
      );
    } finally {
      if (priorRevision === undefined) delete process.env.RADAR_CODE_REVISION;
      else process.env.RADAR_CODE_REVISION = priorRevision;
      cleanup();
    }
  });

  it('preflights same-window retries and publishes already_captured without a new forecast', async () => {
    const { db, scoring, cleanup } = await freshModules('same-window-retry');
    try {
      const codeRevision = 'same-window-revision';
      const publishedAtMs = Date.parse('2026-07-04T00:00:00.000Z');
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(db, 'v-boundary', new Date(publishedAtMs - 24 * 3_600_000).toISOString());
      activateCatalog(db, ['v-latest', 'v-boundary']);
      seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest', 'v-boundary'],
        codeRevision,
        observedAt: new Date(publishedAtMs).toISOString(),
      });
      const makeRun = (scoredAt: number) => {
        const run = buildRun(db, scoring, {
          tags: ['v-latest'],
          stableTagsNewestFirst: ['v-latest', 'v-boundary'],
          oldestScoredStablePredecessorTag: 'v-boundary',
          scoredAt,
        });
        rebuildRecommendation(scoring, run);
        return run;
      };
      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 1).toISOString(),
      );
      const firstRun = makeRun(publishedAtMs + 2 * 3_600_000);
      const firstPersistence = scoring.persistReleaseScoreRun(firstRun, {
        source: 'refresh',
        runId: 'same-window-first',
        codeRevision,
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 4 * 3_600_000,
          publishedAtMs + 4 * 3_600_000 + 1,
        ),
      });
      const firstCapture = scoring.captureReleaseValidationForecasts({
        run: firstRun,
        scorePersistence: firstPersistence,
      });
      assert.equal(firstCapture.eligibilityOutcome, 'eligible_and_captured');
      assert.equal(firstCapture.forecasts[0].status, 'inserted');
      const firstDecisionId = firstCapture.forecasts[0].decisionId;
      const firstCanonicalIds = firstCapture.canonicalForecasts.map(
        (forecast: any) => forecast.forecastId,
      );
      assert.equal(firstCanonicalIds.length, 2);
      assert.ok(firstCapture.canonicalForecasts.every((forecast: any) =>
        forecast.status === 'inserted' &&
        forecast.legacyDecisionId === firstDecisionId));
      sealTestRefreshPublication(
        db,
        'same-window-first',
        firstPersistence,
      );

      const retryRun = makeRun(publishedAtMs + 2 * 3_600_000);
      const retryPersistence = scoring.persistReleaseScoreRun(retryRun, {
        source: 'refresh',
        runId: 'same-window-retry',
        codeRevision,
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 5 * 3_600_000,
          publishedAtMs + 5 * 3_600_000 + 1,
        ),
      });
      const priorRevision = process.env.RADAR_CODE_REVISION;
      process.env.RADAR_CODE_REVISION = 'mutated-mid-attempt-revision';
      const retryCapture = scoring.captureReleaseValidationForecasts({
        run: retryRun,
        scorePersistence: retryPersistence,
      });
      if (priorRevision === undefined) delete process.env.RADAR_CODE_REVISION;
      else process.env.RADAR_CODE_REVISION = priorRevision;
      assert.equal(retryCapture.eligibilityOutcome, 'already_captured');
      assert.deepEqual(retryCapture.forecasts, [{
        opportunityCode: 'first_verified_after_3h',
        status: 'already_captured',
        decisionId: firstDecisionId,
        codeRevision,
      }]);
      assert.deepEqual(
        retryCapture.canonicalForecasts.map((forecast: any) => forecast.forecastId),
        firstCanonicalIds,
      );
      assert.ok(retryCapture.canonicalForecasts.every((forecast: any) =>
        forecast.status === 'already_captured'));
      assert.equal(
        db.listReleaseValidationForecasts().filter((row: any) =>
          row.latest_release_tag === 'v-latest' &&
          row.code_revision === codeRevision).length,
        1,
      );
      assert.equal(
        db.getReleaseScoreAuditHistoryRunSeal(retryPersistence.historyRunId)?.content_hash,
        retryPersistence.historyRunContentHash,
      );
      sealTestRefreshPublication(
        db,
        'same-window-retry',
        retryPersistence,
      );

      const conflictingRun = structuredClone(retryRun);
      conflictingRun.sourceIdentity.digest = 'f'.repeat(64);
      assert.throws(
        () => scoring.persistReleaseScoreRun(conflictingRun, {
          source: 'refresh',
          runId: 'same-window-conflict',
          codeRevision,
          catalogAttestation: attestation,
          clock: commitClock(
            publishedAtMs + 5 * 3_600_000 + 2,
            publishedAtMs + 5 * 3_600_000 + 3,
          ),
        }),
        /preflight rejected occupied slot/,
      );
      assert.equal(
        db.getReleaseScoreAuditHistoryRunSeal('refresh:same-window-conflict'),
        null,
      );

      const laterRun = makeRun(publishedAtMs + 24 * 3_600_000);
      const laterAttestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 24 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 24 * 3_600_000 + 1).toISOString(),
      );
      const laterPersistence = scoring.persistReleaseScoreRun(laterRun, {
        source: 'refresh',
        runId: 'later-opportunity',
        codeRevision,
        catalogAttestation: laterAttestation,
        clock: commitClock(
          publishedAtMs + 25 * 3_600_000,
          publishedAtMs + 25 * 3_600_000 + 1,
        ),
      });
      const laterCapture = scoring.captureReleaseValidationForecasts({
        run: laterRun,
        scorePersistence: laterPersistence,
      });
      assert.deepEqual(
        laterCapture.forecasts.map((forecast: any) => [
          forecast.opportunityCode,
          forecast.status,
        ]),
        [['first_verified_after_24h', 'inserted']],
      );
      assert.deepEqual(
        laterCapture.canonicalForecasts.map((forecast: any) => [
          forecast.opportunityCode,
          forecast.horizonCode,
          forecast.status,
        ]),
        [
          ['first_verified_after_24h', 'field_regression_72h', 'inserted'],
          ['first_verified_after_24h', 'security_30d', 'inserted'],
        ],
      );
      assert.equal(db.readReleaseValidationProofBundle().forecasts.length, 4);
    } finally {
      cleanup();
    }
  });

  it('adds prospective canonical rows to an exact legacy forecast that predates canonical capture', async () => {
    const { db, scoring, cleanup } = await freshModules(
      'existing-legacy-canonical-upgrade',
    );
    try {
      const codeRevision = 'existing-legacy-canonical-revision';
      const publishedAtMs = Date.parse('2026-07-04T00:00:00.000Z');
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(
        db,
        'v-boundary',
        new Date(publishedAtMs - 24 * 3_600_000).toISOString(),
      );
      activateCatalog(db, ['v-latest', 'v-boundary']);
      seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest', 'v-boundary'],
        codeRevision,
        observedAt: new Date(publishedAtMs).toISOString(),
      });
      const run = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, run);
      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 1).toISOString(),
      );
      const persistence = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        runId: 'existing-legacy-canonical-upgrade',
        codeRevision,
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 4 * 3_600_000,
          publishedAtMs + 4 * 3_600_000 + 1,
        ),
      });

      let legacyInput: any = null;
      let legacyDecisionId = '';
      let legacyContentHash = '';
      assert.throws(
        () => db.runInWriteTransaction(() => {
          const staged = scoring.captureReleaseValidationForecasts({
            run,
            scorePersistence: persistence,
          });
          assert.equal(staged.forecasts.length, 1);
          assert.equal(staged.canonicalForecasts.length, 2);
          const [row] = db.listReleaseValidationForecasts();
          assert.ok(row);
          legacyDecisionId = row.decision_id;
          legacyContentHash = row.content_hash;
          legacyInput = {
            opportunity_code: row.opportunity_code,
            recorded_at: row.recorded_at,
            latest_release_tag: row.latest_release_tag,
            latest_release_published_at: row.latest_release_published_at,
            selected_tag: row.selected_tag,
            audit_history_run_id: row.audit_history_run_id,
            score_model_version: row.score_model_version,
            prompt_version: row.prompt_version,
            policy_code: row.policy_code,
            candidate_scores_json: row.candidate_scores_json,
            decision_json: row.decision_json,
            source_identity_json: row.source_identity_json,
            code_revision: row.code_revision,
          };
          throw new Error('roll back canonical capture to construct upgrade state');
        }),
        /roll back canonical capture to construct upgrade state/,
      );
      assert.ok(legacyInput);
      assert.equal(db.listReleaseValidationForecasts().length, 0);
      assert.equal(db.readReleaseValidationProofBundle().forecasts.length, 0);

      const seededLegacy = db.insertReleaseValidationForecast(legacyInput);
      assert.equal(seededLegacy.inserted, true);
      assert.equal(seededLegacy.row.decision_id, legacyDecisionId);
      assert.equal(seededLegacy.row.content_hash, legacyContentHash);
      sealTestRefreshPublication(
        db,
        'existing-legacy-canonical-upgrade',
        persistence,
      );

      const retryRun = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, retryRun);
      const retryPersistence = scoring.persistReleaseScoreRun(retryRun, {
        source: 'refresh',
        runId: 'existing-legacy-canonical-retry',
        codeRevision,
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 5 * 3_600_000,
          publishedAtMs + 5 * 3_600_000 + 1,
        ),
      });
      const upgraded = scoring.captureReleaseValidationForecasts({
        run: retryRun,
        scorePersistence: retryPersistence,
      });
      assert.equal(upgraded.eligibilityOutcome, 'already_captured');
      assert.deepEqual(upgraded.forecasts, [{
        opportunityCode: 'first_verified_after_3h',
        status: 'already_captured',
        decisionId: legacyDecisionId,
        codeRevision,
      }]);
      assert.deepEqual(
        upgraded.canonicalForecasts.map((forecast: any) => [
          forecast.opportunityCode,
          forecast.horizonCode,
          forecast.status,
          forecast.legacyDecisionId,
          forecast.legacyContentHash,
        ]),
        [
          [
            'first_verified_after_3h',
            'field_regression_72h',
            'inserted',
            legacyDecisionId,
            legacyContentHash,
          ],
          [
            'first_verified_after_3h',
            'security_30d',
            'inserted',
            legacyDecisionId,
            legacyContentHash,
          ],
        ],
      );
      assert.equal(db.listReleaseValidationForecasts().length, 1);
      assert.equal(db.readReleaseValidationProofBundle().forecasts.length, 2);
    } finally {
      cleanup();
    }
  });

  it('uses inclusive starts, exclusive ends, and commit completion after lock wait', async () => {
    const { db, scoring, cleanup } = await freshModules('commit-boundaries');
    const priorRevision = process.env.RADAR_CODE_REVISION;
    try {
      process.env.RADAR_CODE_REVISION = 'boundary-revision';
      const publishedAtMs = Date.parse('2026-07-05T00:00:00.000Z');
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(db, 'v-boundary', new Date(publishedAtMs - 24 * 3_600_000).toISOString());
      activateCatalog(db, ['v-latest', 'v-boundary']);
      seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest', 'v-boundary'],
        codeRevision: 'boundary-revision',
        observedAt: new Date(publishedAtMs).toISOString(),
      });
      const run = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, run);
      const forecastCountAtStart = db.listReleaseValidationForecasts().length;
      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 1).toISOString(),
      );
      const atStart = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        runId: 'at-start',
        codeRevision: 'boundary-revision',
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 3 * 3_600_000,
          publishedAtMs + 3 * 3_600_000,
        ),
      });
      const capturedAtStart = scoring.captureReleaseValidationForecasts({
        run,
        scorePersistence: atStart,
      });
      assert.equal(capturedAtStart.forecasts.length, 1);
      assert.equal(capturedAtStart.canonicalForecasts.length, 2);
      sealTestRefreshPublication(
        db,
        'at-start',
        atStart,
      );

      const crossing = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        runId: 'crossing-end',
        codeRevision: 'boundary-revision',
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 6 * 3_600_000 - 1,
          publishedAtMs + 5 * 3_600_000,
          10_000,
          10_001,
        ),
      });
      assert.equal(crossing.commitTiming.commitNotAfterMs, publishedAtMs + 6 * 3_600_000);
      const excluded = scoring.captureReleaseValidationForecasts({
        run,
        scorePersistence: crossing,
      });
      assert.equal(excluded.eligibilityOutcome, 'not_eligible');
      assert.deepEqual(excluded.canonicalForecasts, []);
      assert.equal(
        db.listReleaseValidationForecasts().length,
        forecastCountAtStart + 1,
      );
    } finally {
      if (priorRevision === undefined) delete process.env.RADAR_CODE_REVISION;
      else process.env.RADAR_CODE_REVISION = priorRevision;
      cleanup();
    }
  });

  it('normalizes a backward wall clock and fails closed if monotonic time regresses', async () => {
    const { db, scoring, cleanup } = await freshModules('clock-normalization');
    const priorRevision = process.env.RADAR_CODE_REVISION;
    try {
      process.env.RADAR_CODE_REVISION = 'clock-revision';
      const publishedAtMs = Date.parse('2026-07-06T00:00:00.000Z');
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(db, 'v-boundary', new Date(publishedAtMs - 24 * 3_600_000).toISOString());
      activateCatalog(db, ['v-latest', 'v-boundary']);
      seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest', 'v-boundary'],
        codeRevision: 'clock-revision',
        observedAt: new Date(publishedAtMs).toISOString(),
      });
      const run = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, run);
      const forecastCountAtStart = db.listReleaseValidationForecasts().length;
      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 1).toISOString(),
      );
      const beforeMs = publishedAtMs + 4 * 3_600_000;
      const normalized = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        runId: 'backward-wall',
        codeRevision: 'clock-revision',
        catalogAttestation: attestation,
        clock: commitClock(beforeMs, beforeMs - 60_000, 5_000, 5_025),
      });
      assert.equal(normalized.commitTiming.commitNotAfterMs, beforeMs + 25);
      const normalizedCapture = scoring.captureReleaseValidationForecasts({
        run,
        scorePersistence: normalized,
      });
      assert.equal(normalizedCapture.forecasts.length, 1);
      assert.equal(normalizedCapture.canonicalForecasts.length, 2);
      sealTestRefreshPublication(
        db,
        'backward-wall',
        normalized,
      );

      assert.throws(
        () => scoring.persistReleaseScoreRun(structuredClone(run), {
          source: 'refresh',
          runId: 'backward-monotonic',
          codeRevision: 'clock-revision',
          catalogAttestation: attestation,
          clock: commitClock(beforeMs + 100_000, beforeMs + 100_001, 10_000, 9_999),
        }),
        /monotonic clock moved backward/,
      );
      assert.ok(db.getReleaseScoreAuditHistoryRunSeal('refresh:backward-monotonic'));
      assert.equal(
        db.listReleaseValidationForecasts().some((row: any) =>
          row.audit_history_run_id === 'refresh:backward-monotonic'),
        false,
      );
    } finally {
      if (priorRevision === undefined) delete process.env.RADAR_CODE_REVISION;
      else process.env.RADAR_CODE_REVISION = priorRevision;
      cleanup();
    }
  });

  it('blocks missing/invalid attestation, local catalog CAS drift, and non-refresh capture', async () => {
    const { db, scoring, cleanup } = await freshModules('attestation-guards');
    const priorRevision = process.env.RADAR_CODE_REVISION;
    try {
      process.env.RADAR_CODE_REVISION = 'attestation-revision';
      const publishedAtMs = Date.parse('2026-07-07T00:00:00.000Z');
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(db, 'v-boundary', new Date(publishedAtMs - 24 * 3_600_000).toISOString());
      activateCatalog(db, ['v-latest', 'v-boundary']);
      const run = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, run);
      const forecastCountAtStart = db.listReleaseValidationForecasts().length;
      assert.throws(
        () => scoring.persistReleaseScoreRun(run, {
          source: 'refresh',
          runId: 'missing-attestation',
          codeRevision: 'attestation-revision',
        }),
        /valid final catalog attestation/,
      );
      assert.equal(db.getReleaseScoreAuditHistoryRunSeal('refresh:missing-attestation'), null);

      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 1).toISOString(),
      );
      const manual = scoring.persistReleaseScoreRun(run, {
        source: 'manual',
        runId: 'manual',
        clock: commitClock(
          publishedAtMs + 4 * 3_600_000,
          publishedAtMs + 4 * 3_600_000 + 1,
        ),
      });
      assert.equal(db.listReleaseValidationForecasts().length, forecastCountAtStart);
      assert.throws(
        () => scoring.captureReleaseValidationForecasts({
          run,
          scorePersistence: manual,
        }),
        /only be captured by refresh/,
      );

      const refreshPersistence = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        runId: 'invalid-capture-attestation',
        codeRevision: 'attestation-revision',
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 4 * 3_600_000,
          publishedAtMs + 4 * 3_600_000 + 1,
        ),
      });
      const invalidPersistence = structuredClone(refreshPersistence);
      invalidPersistence.catalogAttestation.finalRemoteCatalog.digest = 'b'.repeat(64);
      assert.throws(
        () => scoring.captureReleaseValidationForecasts({
          run,
          scorePersistence: invalidPersistence,
        }),
        /valid catalog attestation/,
      );
      sealTestRefreshPublication(
        db,
        'invalid-capture-attestation',
        refreshPersistence,
      );

      const staleRun = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, staleRun);
      db.db.prepare(`
        UPDATE releases
        SET name='changed after attestation'
        WHERE tag='v-latest'
      `).run();
      assert.throws(
        () => scoring.persistReleaseScoreRun(staleRun, {
          source: 'refresh',
          runId: 'local-cas-drift',
          codeRevision: 'attestation-revision',
          catalogAttestation: attestation,
          clock: commitClock(
            publishedAtMs + 4 * 3_600_000,
            publishedAtMs + 4 * 3_600_000 + 1,
          ),
        }),
        /Active release catalog rows do not match|changed after final attestation/,
      );
      assert.equal(db.getReleaseScoreAuditHistoryRunSeal('refresh:local-cas-drift'), null);
    } finally {
      if (priorRevision === undefined) delete process.env.RADAR_CODE_REVISION;
      else process.env.RADAR_CODE_REVISION = priorRevision;
      cleanup();
    }
  });

  it('fails closed on missing, duplicate, or mismatched canonical obligation slots', async () => {
    const { db, scoring, cleanup } = await freshModules(
      'canonical-obligation-slot-guards',
    );
    try {
      const codeRevision = 'canonical-obligation-slot-revision';
      const publishedAt = '2026-07-08T00:00:00.000Z';
      seedRelease(db, 'v-latest', publishedAt);
      activateCatalog(db, ['v-latest']);
      const lifecycle = seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest'],
        codeRevision,
        observedAt: publishedAt,
      });
      const bundle = db.readReleaseValidationProofBundle();
      const releaseId = lifecycle.bundle.obligations[0].release.releaseId;
      const input = {
        bundle,
        cohort: lifecycle.cohort,
        releaseId,
        opportunityCode: 'first_verified_after_3h',
        legacyDecisionId: 'legacy-decision-slot-test',
      };
      const slots = scoring.__releaseScoringTest.canonicalForecastProofSlots(
        input,
      );
      assert.deepEqual([...slots.keys()], [
        'field_regression_72h',
        'security_30d',
      ]);

      const target = bundle.obligations.find((row: any) =>
        row.opportunityCode === input.opportunityCode &&
        row.horizonCode === 'field_regression_72h');
      assert.ok(target);
      const assignment = bundle.splitAssignments.find((row: any) =>
        row.obligationId === target.obligationId);
      assert.ok(assignment);

      assert.throws(
        () => scoring.__releaseScoringTest.canonicalForecastProofSlots({
          ...input,
          bundle: {
            ...bundle,
            obligations: bundle.obligations.filter((row: any) =>
              row.obligationId !== target.obligationId),
            splitAssignments: bundle.splitAssignments.filter((row: any) =>
              row.obligationId !== target.obligationId),
          },
        }),
        /exactly one obligation for each horizon/,
      );
      assert.throws(
        () => scoring.__releaseScoringTest.canonicalForecastProofSlots({
          ...input,
          bundle: {
            ...bundle,
            obligations: [...bundle.obligations, target],
          },
        }),
        /exactly one obligation for each horizon/,
      );
      assert.throws(
        () => scoring.__releaseScoringTest.canonicalForecastProofSlots({
          ...input,
          bundle: {
            ...bundle,
            splitAssignments: [...bundle.splitAssignments, assignment],
          },
        }),
        /has 2 split assignments/,
      );
      assert.throws(
        () => scoring.__releaseScoringTest.canonicalForecastProofSlots({
          ...input,
          bundle: {
            ...bundle,
            splitAssignments: bundle.splitAssignments.map((row: any) =>
              row.assignmentId === assignment.assignmentId
                ? { ...row, cohortId: 'f'.repeat(64) }
                : row),
          },
        }),
        /does not match obligation/,
      );
      assert.throws(
        () => scoring.__releaseScoringTest.canonicalForecastProofSlots({
          ...input,
          bundle: {
            ...bundle,
            obligations: bundle.obligations.map((row: any) =>
              row.obligationId === target.obligationId
                ? { ...row, proofEpochId: 'e'.repeat(64) }
                : row),
          },
        }),
        /does not match its cohort and horizon slot/,
      );
    } finally {
      cleanup();
    }
  });

  it('does not backfill canonical forecasts for a release predating proof inception', async () => {
    const { db, scoring, cleanup } = await freshModules('pre-inception-canonical');
    try {
      const codeRevision = 'pre-inception-revision';
      const publishedAtMs = Date.parse('2026-07-08T00:00:00.000Z');
      seedRelease(db, 'v-latest', new Date(publishedAtMs).toISOString());
      seedRelease(
        db,
        'v-boundary',
        new Date(publishedAtMs - 24 * 3_600_000).toISOString(),
      );
      activateCatalog(db, ['v-latest', 'v-boundary']);
      const lifecycle = seedCanonicalForecastLifecycle(db, {
        tagsNewestFirst: ['v-latest', 'v-boundary'],
        codeRevision,
        observedAt: new Date(publishedAtMs + 60_000).toISOString(),
      });
      assert.equal(lifecycle.excludedPreInceptionReleaseCount, 2);
      assert.equal(lifecycle.bundle.obligations.length, 0);

      const run = buildRun(db, scoring, {
        tags: ['v-latest'],
        stableTagsNewestFirst: ['v-latest', 'v-boundary'],
        oldestScoredStablePredecessorTag: 'v-boundary',
        scoredAt: publishedAtMs + 2 * 3_600_000,
      });
      rebuildRecommendation(scoring, run);
      const attestation = catalogAttestation(
        db,
        new Date(publishedAtMs + 2 * 3_600_000).toISOString(),
        new Date(publishedAtMs + 2 * 3_600_000 + 1).toISOString(),
      );
      const persistence = scoring.persistReleaseScoreRun(run, {
        source: 'refresh',
        runId: 'pre-inception-canonical',
        codeRevision,
        catalogAttestation: attestation,
        clock: commitClock(
          publishedAtMs + 4 * 3_600_000,
          publishedAtMs + 4 * 3_600_000 + 1,
        ),
      });
      const capture = scoring.captureReleaseValidationForecasts({
        run,
        scorePersistence: persistence,
      });

      assert.equal(capture.forecasts.length, 1);
      assert.deepEqual(capture.canonicalForecasts, []);
      assert.equal(db.readReleaseValidationProofBundle().forecasts.length, 0);
    } finally {
      cleanup();
    }
  });

  it('appends the current model forecast series once beside an existing v16 series', async () => {
    const { db, cleanup } = await freshModules('model-series');
    try {
      const now = Date.now();
      seedRelease(
        db,
        'v-latest',
        new Date(now - 30 * 3_600_000).toISOString(),
      );
      activateCatalog(db, ['v-latest']);
      const sourceIdentityJson = JSON.stringify(db.scoreSourceIdentity());
      const legacyForecasts = seedSingleReleaseForecastSeries(db, {
        runId: 'legacy-v16-run',
        modelVersion: 'evidence-v16',
        promptVersion: 5,
        releaseTag: 'v-latest',
        sourceIdentityJson,
      });
      assert.deepEqual(
        legacyForecasts.map((item) => item.inserted),
        [true, true],
      );
      const legacyDecisionId = legacyForecasts[0].row.decision_id;
      const [legacyOutcome] = stageReleaseValidationOutcomeRows([], [{
        decision_id: legacyDecisionId,
        horizon_code: 'field_regression_72h',
        observed_at: new Date(now).toISOString(),
        status: 'indeterminate',
        outcome_json: '{"schemaVersion":1,"reason":"legacy-series-fixture"}',
        source_identity_json: sourceIdentityJson,
      }]);
      db.db.prepare(`
        INSERT INTO release_validation_outcome_observations (
          id, observation_id, decision_id, horizon_code, observed_at, status,
          outcome_json, source_identity_json, previous_content_hash, content_hash
        )
        VALUES (
          :id, :observation_id, :decision_id, :horizon_code, :observed_at, :status,
          :outcome_json, :source_identity_json, :previous_content_hash, :content_hash
        )
      `).run(legacyOutcome);
      const currentInput = {
        runId: 'current-v19-run',
        modelVersion: SCORE_MODEL_VERSION,
        promptVersion: PROMPT_VERSION,
        releaseTag: 'v-latest',
        sourceIdentityJson,
      };
      assert.deepEqual(
        seedSingleReleaseForecastSeries(db, currentInput)
          .map((item) => item.inserted),
        [true, true],
      );
      assert.deepEqual(
        seedSingleReleaseForecastSeries(db, currentInput)
          .map((item) => item.inserted),
        [false, false],
      );
      const forecasts = db.listReleaseValidationForecasts();
      assert.equal(forecasts.length, 4);
      assert.deepEqual(
        forecasts.map((row) => [
          row.opportunity_code,
          row.score_model_version,
          row.prompt_version,
        ]),
        [
          ['first_verified_after_3h', 'evidence-v16', 5],
          ['first_verified_after_3h', SCORE_MODEL_VERSION, PROMPT_VERSION],
          ['first_verified_after_24h', 'evidence-v16', 5],
          ['first_verified_after_24h', SCORE_MODEL_VERSION, PROMPT_VERSION],
        ],
      );
      assert.equal(
        new Set(forecasts.map((row) => JSON.stringify([
          row.opportunity_code,
          row.latest_release_tag,
          row.score_model_version,
          row.prompt_version,
        ]))).size,
        4,
      );
      const outcomes = db.listReleaseValidationOutcomeObservations();
      assert.equal(outcomes.length, 1);
      assert.equal(outcomes[0].decision_id, legacyDecisionId);
      assert.ok(forecasts.some((row) =>
        row.decision_id === legacyDecisionId));
    } finally {
      cleanup();
    }
  });
});
