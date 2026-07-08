import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import {
  releaseValidationDecisionId,
  releaseValidationForecastContentHash,
  releaseValidationObservationBatchResults,
} from './releaseValidation';
import {
  assertReleaseValidationObservationBatchRetryEquivalent,
  canonicalReleaseValidationBatchJson,
  releaseValidationObservationBatchContentHash,
  releaseValidationObservationBatchForecastInputs,
  releaseValidationObservationBatchReport,
  stageReleaseValidationObservationBatchReceipt,
  stageReleaseValidationOutcomeRows,
  verifyReleaseValidationObservationBatchLedger,
  type ReleaseValidationObservationBatchResult,
} from './releaseValidationBatch';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;

describe('release validation observation batches', () => {
  it('rolls back partial writes, is exactly idempotent, and detects tamper and chain drift', async () => {
    const ownedDir = assignedWorkerDatabasePath === null
      ? mkdtempSync(join(tmpdir(), 'release-validation-batch-'))
      : null;
    const path = assignedWorkerDatabasePath ??
      join(ownedDir!, 'radar.db');
    const previousDbPath = process.env.DB_PATH;
    if (assignedWorkerDatabasePath) {
      assert.equal(
        process.env.DB_PATH,
        assignedWorkerDatabasePath,
        'release validation batch tests must use their assigned worker database',
      );
    } else {
      process.env.DB_PATH = path;
    }
    const database = await import(`./db.ts?validation-batch=${Date.now()}`);
    try {
      const release = {
        node_id: 'R_release_validation_batch',
        catalog_tag_commit_oid: '1'.repeat(40),
        tag: 'v-batch',
        name: 'v-batch',
        published_at: '2026-06-01T00:00:00.000Z',
        created_at: '2026-06-01T00:00:00.000Z',
        updated_at: '2026-06-01T00:00:00.000Z',
        html_url: 'https://example.test/releases/v-batch',
        prerelease: false,
        body: '',
      };
      database.replaceActiveReleaseCatalog([release], {
        capture: { source: 'test_fixture' },
      });
      const sourceIdentityJson = JSON.stringify({
        schemaVersion: 2,
        digest: 'a'.repeat(64),
      });
      const forecast = {
        id: 1,
        decision_id: '',
        opportunity_code: 'first_verified_after_24h',
        recorded_at: '2026-06-02T00:00:00.000Z',
        latest_release_tag: release.tag,
        latest_release_published_at: release.published_at,
        selected_tag: release.tag,
        audit_history_run_id: 'run-batch',
        score_model_version: 'model-batch',
        prompt_version: 1,
        policy_code: 'batch-test',
        candidate_scores_json: '[]',
        decision_json: '{"schemaVersion":4}',
        source_identity_json: sourceIdentityJson,
        code_revision: 'batch-test-revision',
        previous_content_hash: null,
        content_hash: '',
      };
      forecast.content_hash = releaseValidationForecastContentHash(forecast);
      forecast.decision_id = releaseValidationDecisionId(
        forecast,
        forecast.content_hash,
      );
      const forecastInputs = releaseValidationObservationBatchForecastInputs([forecast]);
      database.db.prepare(`
        INSERT INTO release_validation_forecasts (
          id, decision_id, opportunity_code, recorded_at, latest_release_tag,
          latest_release_published_at, selected_tag, audit_history_run_id,
          score_model_version, prompt_version, policy_code, candidate_scores_json,
          decision_json, source_identity_json, code_revision, previous_content_hash,
          content_hash
        )
        VALUES (
          :id, :decision_id, :opportunity_code, :recorded_at, :latest_release_tag,
          :latest_release_published_at, :selected_tag, :audit_history_run_id,
          :score_model_version, :prompt_version, :policy_code, :candidate_scores_json,
          :decision_json, :source_identity_json, :code_revision, :previous_content_hash,
          :content_hash
        )
      `).run(forecast);

      const currentSourceIdentity = database.scoreSourceIdentity();
      const stagedOutcomes = stageReleaseValidationOutcomeRows([], [
        {
          decision_id: forecast.decision_id,
          horizon_code: 'field_regression_72h',
          observed_at: '2026-06-05T00:00:00.000Z',
          status: 'indeterminate',
          outcome_json: '{"schemaVersion":1,"reason":"field-test","fatal":false}',
          source_identity_json: JSON.stringify(currentSourceIdentity),
        },
        {
          decision_id: forecast.decision_id,
          horizon_code: 'security_30d',
          observed_at: '2026-07-02T00:00:00.000Z',
          status: 'indeterminate',
          outcome_json: '{"schemaVersion":1,"reason":"security-test","fatal":false}',
          source_identity_json: JSON.stringify(currentSourceIdentity),
        },
      ]);
      const results: ReleaseValidationObservationBatchResult[] = stagedOutcomes.map(
        (outcome) => ({
          decisionId: forecast.decision_id,
          opportunityCode: forecast.opportunity_code,
          targetReleaseTag: forecast.latest_release_tag,
          horizonCode: outcome.horizon_code,
          status: 'indeterminate',
          persistence: 'inserted',
          fatal: false,
          reason: JSON.parse(outcome.outcome_json).reason,
          observationId: outcome.observation_id,
          observationContentHash: outcome.content_hash,
        }),
      );
      const receipt = stageReleaseValidationObservationBatchReceipt(
        [],
        [],
        stagedOutcomes,
        {
          batchId: 'batch-atomic',
          observedAt: '2026-07-02T00:00:00.000Z',
          codeRevision: 'batch-test-revision',
          sourceIdentityDigest: currentSourceIdentity.digest,
          forecastCount: 1,
          forecastInputs,
          results,
        },
      );
      const receiptReport = releaseValidationObservationBatchReport(receipt);
      assert.equal(receiptReport.schemaVersion, 2);
      assert.deepEqual(receiptReport.forecastInputs, forecastInputs);
      assert.match(String(receiptReport.forecastInputSetHash), /^[0-9a-f]{64}$/);
      assert.match(String(receiptReport.resultSetHash), /^[0-9a-f]{64}$/);
      assert.match(String(receiptReport.outcomeRefSetHash), /^[0-9a-f]{64}$/);
      assert.match(String(receiptReport.batchKey), /^[0-9a-f]{64}$/);
      assert.equal((receiptReport.outcomeRefs as unknown[]).length, 2);

      assert.throws(
        () => stageReleaseValidationObservationBatchReceipt(
          [],
          [],
          stagedOutcomes,
          {
            batchId: 'batch-duplicate-result',
            observedAt: '2026-07-02T00:00:00.000Z',
            codeRevision: 'batch-test-revision',
            sourceIdentityDigest: currentSourceIdentity.digest,
            forecastCount: 1,
            forecastInputs,
            results: [...results, structuredClone(results[0])],
          },
        ),
        /repeats .*field_regression_72h/,
      );

      const conflictingIdentity = structuredClone(results);
      conflictingIdentity[1].opportunityCode = 'first_verified_after_3h';
      assert.throws(
        () => stageReleaseValidationObservationBatchReceipt(
          [],
          [],
          stagedOutcomes,
          {
            batchId: 'batch-conflicting-identity',
            observedAt: '2026-07-02T00:00:00.000Z',
            codeRevision: 'batch-test-revision',
            sourceIdentityDigest: currentSourceIdentity.digest,
            forecastCount: 1,
            forecastInputs,
            results: conflictingIdentity,
          },
        ),
        /inconsistent forecast identity/,
      );

      const missingFatality = structuredClone(results);
      delete missingFatality[0].fatal;
      assert.throws(
        () => stageReleaseValidationObservationBatchReceipt(
          [],
          [],
          stagedOutcomes,
          {
            batchId: 'batch-missing-fatality',
            observedAt: '2026-07-02T00:00:00.000Z',
            codeRevision: 'batch-test-revision',
            sourceIdentityDigest: currentSourceIdentity.digest,
            forecastCount: 1,
            forecastInputs,
            results: missingFatality,
          },
        ),
        /missing reason or fatality/,
      );

      const conflictingOutcomeSummary = structuredClone(results);
      conflictingOutcomeSummary[0].reason = 'different-reason';
      assert.throws(
        () => stageReleaseValidationObservationBatchReceipt(
          [],
          [],
          stagedOutcomes,
          {
            batchId: 'batch-conflicting-outcome',
            observedAt: '2026-07-02T00:00:00.000Z',
            codeRevision: 'batch-test-revision',
            sourceIdentityDigest: currentSourceIdentity.digest,
            forecastCount: 1,
            forecastInputs,
            results: conflictingOutcomeSummary,
          },
        ),
        /result does not match outcome/,
      );

      assert.throws(
        () => database.commitReleaseValidationObservationBatch(
          { outcomes: stagedOutcomes, receipt },
          { failAfterOutcomeInsertCount: 1 },
        ),
        /Injected validation observation batch failure after 1 outcome insert/,
      );
      assert.equal(
        database.db.prepare(`
          SELECT COUNT(*) AS count
          FROM release_validation_outcome_observations
        `).get().count,
        0,
      );
      assert.equal(
        database.db.prepare(`
          SELECT COUNT(*) AS count
          FROM release_validation_observation_batches
        `).get().count,
        0,
      );

      const changedForecastReceipt = stageReleaseValidationObservationBatchReceipt(
        [],
        [],
        stagedOutcomes,
        {
          batchId: 'batch-changed-forecast-input',
          observedAt: '2026-07-02T00:00:00.000Z',
          codeRevision: 'batch-test-revision',
          sourceIdentityDigest: currentSourceIdentity.digest,
          forecastCount: 1,
          forecastInputs: [{
            decisionId: forecast.decision_id,
            contentHash: 'b'.repeat(64),
          }],
          results,
        },
      );
      assert.throws(
        () => database.commitReleaseValidationObservationBatch({
          outcomes: stagedOutcomes,
          receipt: changedForecastReceipt,
        }),
        /forecast decision IDs or content hashes changed after staging/,
      );

      const wrongIdentityOutcomes = stageReleaseValidationOutcomeRows([], [
        {
          decision_id: forecast.decision_id,
          horizon_code: 'field_regression_72h',
          observed_at: '2026-06-05T00:00:00.000Z',
          status: 'indeterminate',
          outcome_json: '{"schemaVersion":1,"reason":"field-test","fatal":false}',
          source_identity_json: JSON.stringify({ digest: 'b'.repeat(64) }),
        },
      ]);
      const wrongIdentityResults: ReleaseValidationObservationBatchResult[] = [
        {
          decisionId: forecast.decision_id,
          opportunityCode: forecast.opportunity_code,
          targetReleaseTag: forecast.latest_release_tag,
          horizonCode: 'field_regression_72h',
          status: 'indeterminate',
          persistence: 'inserted',
          fatal: false,
          reason: 'field-test',
          observationId: wrongIdentityOutcomes[0].observation_id,
          observationContentHash: wrongIdentityOutcomes[0].content_hash,
        },
        {
          decisionId: forecast.decision_id,
          opportunityCode: forecast.opportunity_code,
          targetReleaseTag: forecast.latest_release_tag,
          horizonCode: 'security_30d',
          status: 'pending',
          persistence: 'not_applicable',
        },
      ];
      const wrongIdentityReceipt = stageReleaseValidationObservationBatchReceipt(
        [],
        [],
        wrongIdentityOutcomes,
        {
          batchId: 'batch-wrong-outcome-source',
          observedAt: '2026-07-02T00:00:00.000Z',
          codeRevision: 'batch-test-revision',
          sourceIdentityDigest: currentSourceIdentity.digest,
          forecastCount: 1,
          forecastInputs,
          results: wrongIdentityResults,
        },
      );
      assert.throws(
        () => database.commitReleaseValidationObservationBatch({
          outcomes: wrongIdentityOutcomes,
          receipt: wrongIdentityReceipt,
        }),
        /outcome .* source identity does not match the receipt/,
      );

      const inserted = database.commitReleaseValidationObservationBatch({
        outcomes: stagedOutcomes,
        receipt,
      });
      assert.equal(inserted.inserted, true);
      assert.equal(inserted.equivalent, false);
      assert.equal(inserted.row.intended_count, 2);
      assert.equal(inserted.row.inserted_count, 2);
      assert.equal(inserted.row.indeterminate_count, 2);

      const equivalent = database.commitReleaseValidationObservationBatch({
        outcomes: stagedOutcomes,
        receipt,
      });
      assert.equal(equivalent.inserted, false);
      assert.equal(equivalent.equivalent, true);
      assert.equal(equivalent.row.content_hash, inserted.row.content_hash);

      const conflictingReceipt = stageReleaseValidationObservationBatchReceipt(
        [],
        [],
        stagedOutcomes,
        {
          batchId: 'batch-atomic',
          observedAt: '2026-07-02T00:00:01.000Z',
          codeRevision: 'batch-test-revision',
          sourceIdentityDigest: currentSourceIdentity.digest,
          forecastCount: 1,
          forecastInputs,
          results,
        },
      );
      assert.throws(
        () => database.commitReleaseValidationObservationBatch({
          outcomes: stagedOutcomes,
          receipt: conflictingReceipt,
        }),
        /Validation observation batch conflict.*persisted receipt or inserted outcome set differs/,
      );

      assert.throws(
        () => database.db.prepare(`
          UPDATE release_validation_observation_batches
          SET pending_count=1
          WHERE batch_id='batch-atomic'
        `).run(),
        /append-only/,
      );
      assert.throws(
        () => database.db.prepare(`
          DELETE FROM release_validation_observation_batches
          WHERE batch_id='batch-atomic'
        `).run(),
        /append-only/,
      );

      const pendingResults: ReleaseValidationObservationBatchResult[] = [
        'field_regression_72h',
        'security_30d',
      ].map((horizonCode) => ({
        decisionId: forecast.decision_id,
        opportunityCode: forecast.opportunity_code,
        targetReleaseTag: forecast.latest_release_tag,
        horizonCode,
        status: 'pending',
        persistence: 'not_applicable',
      }));
      const secondReceipt = stageReleaseValidationObservationBatchReceipt(
        [inserted.row],
        stagedOutcomes,
        [],
        {
          batchId: 'batch-second',
          observedAt: '2026-07-02T00:00:02.000Z',
          codeRevision: 'batch-test-revision',
          sourceIdentityDigest: currentSourceIdentity.digest,
          forecastCount: 1,
          forecastInputs,
          results: pendingResults,
        },
      );
      database.commitReleaseValidationObservationBatch({
        outcomes: [],
        receipt: secondReceipt,
      });

      const outcomes = database.listReleaseValidationOutcomeObservations();
      const batches = database.listReleaseValidationObservationBatches();
      assert.equal(
        verifyReleaseValidationObservationBatchLedger({ outcomes, batches }).failedCount,
        0,
      );

      const payloadTampered = structuredClone(batches);
      payloadTampered[0].results_json = payloadTampered[0].results_json.replace(
        'field-test',
        'tampered',
      );
      assert.ok(
        verifyReleaseValidationObservationBatchLedger({
          outcomes,
          batches: payloadTampered,
        }).batchContentHashFailureCount > 0,
      );

      const chainTampered = structuredClone(batches);
      chainTampered[1].previous_content_hash = 'f'.repeat(64);
      chainTampered[1].content_hash = releaseValidationObservationBatchContentHash(
        chainTampered[1],
      );
      const chainReport = verifyReleaseValidationObservationBatchLedger({
        outcomes,
        batches: chainTampered,
      });
      assert.equal(chainReport.batchChainFailureCount, 1);
      assert.equal(chainReport.batchContentHashFailureCount, 0);

      const outcomeBindingTampered = structuredClone(batches);
      outcomeBindingTampered[1].outcome_chain_previous_hash = null;
      outcomeBindingTampered[1].content_hash =
        releaseValidationObservationBatchContentHash(outcomeBindingTampered[1]);
      assert.ok(
        verifyReleaseValidationObservationBatchLedger({
          outcomes,
          batches: outcomeBindingTampered,
        }).batchOutcomeBindingFailureCount > 0,
      );
    } finally {
      database.db.close();
      if (assignedWorkerDatabasePath === null) {
        if (previousDbPath == null) delete process.env.DB_PATH;
        else process.env.DB_PATH = previousDbPath;
      }
      if (ownedDir !== null) {
        rmSync(ownedDir, { recursive: true, force: true });
      }
    }
  });

  it('binds exact canonical sets and rejects same-count drift and reordered inputs', () => {
    const forecastInputs = [
      { decisionId: 'decision-a', contentHash: '1'.repeat(64) },
      { decisionId: 'decision-b', contentHash: '2'.repeat(64) },
    ];
    const outcomes = stageReleaseValidationOutcomeRows([], [
      {
        decision_id: 'decision-a',
        horizon_code: 'field_regression_72h',
        observed_at: '2026-07-04T00:00:00.000Z',
        status: 'indeterminate',
        outcome_json: JSON.stringify({
          schemaVersion: 1,
          reason: 'evidence_missing',
          fatal: false,
        }),
        source_identity_json: JSON.stringify({ digest: '3'.repeat(64) }),
      },
      {
        decision_id: 'decision-b',
        horizon_code: 'security_30d',
        observed_at: '2026-07-04T00:00:01.000Z',
        status: 'matured',
        outcome_json: JSON.stringify({ schemaVersion: 3, adverse: false }),
        source_identity_json: JSON.stringify({ digest: '3'.repeat(64) }),
      },
    ]);
    const results: ReleaseValidationObservationBatchResult[] = [
      {
        decisionId: 'decision-b',
        opportunityCode: 'first_verified_after_24h',
        targetReleaseTag: 'v-b',
        horizonCode: 'field_regression_72h',
        status: 'pending',
        persistence: 'not_applicable',
      },
      {
        decisionId: 'decision-a',
        opportunityCode: 'first_verified_after_24h',
        targetReleaseTag: 'v-a',
        horizonCode: 'security_30d',
        status: 'excluded',
        persistence: 'not_applicable',
        reason: 'forecast_not_evaluable',
      },
      {
        decisionId: 'decision-b',
        opportunityCode: 'first_verified_after_24h',
        targetReleaseTag: 'v-b',
        horizonCode: 'security_30d',
        status: 'matured',
        persistence: 'inserted',
        adverse: false,
        observationId: outcomes[1].observation_id,
        observationContentHash: outcomes[1].content_hash,
      },
      {
        decisionId: 'decision-a',
        opportunityCode: 'first_verified_after_24h',
        targetReleaseTag: 'v-a',
        horizonCode: 'field_regression_72h',
        status: 'indeterminate',
        persistence: 'inserted',
        fatal: false,
        reason: 'evidence_missing',
        observationId: outcomes[0].observation_id,
        observationContentHash: outcomes[0].content_hash,
      },
    ];
    const receipt = stageReleaseValidationObservationBatchReceipt(
      [],
      [],
      outcomes,
      {
        batchId: 'batch-exact-sets',
        observedAt: '2026-07-04T00:00:02.000Z',
        codeRevision: 'batch-exact-sets-revision',
        sourceIdentityDigest: '3'.repeat(64),
        forecastCount: 2,
        forecastInputs,
        results,
      },
    );
    const report = releaseValidationObservationBatchReport(receipt);
    assert.equal(report.schemaVersion, 2);
    assert.deepEqual(
      releaseValidationObservationBatchResults(receipt.results_json),
      report.results,
    );
    assert.deepEqual(report.forecastInputs, forecastInputs);
    assert.deepEqual(
      (report.results as ReleaseValidationObservationBatchResult[]).map((result) =>
        `${result.decisionId}/${result.horizonCode}`),
      [
        'decision-a/field_regression_72h',
        'decision-a/security_30d',
        'decision-b/field_regression_72h',
        'decision-b/security_30d',
      ],
    );
    assert.deepEqual(report.counts, {
      forecastCount: 2,
      resultCount: 4,
      intendedCount: 2,
      insertedCount: 2,
      alreadyExistingCount: 0,
      maturedCount: 1,
      pendingCount: 1,
      excludedCount: 1,
      indeterminateCount: 1,
    });
    assert.equal(
      verifyReleaseValidationObservationBatchLedger({
        outcomes,
        batches: [receipt],
      }).failedCount,
      0,
    );
    assert.doesNotThrow(() =>
      assertReleaseValidationObservationBatchRetryEquivalent(receipt, {
        codeRevision: receipt.code_revision,
        sourceIdentityDigest: receipt.source_identity_digest,
        forecastInputs,
      }));
    assert.throws(
      () => assertReleaseValidationObservationBatchRetryEquivalent(receipt, {
        codeRevision: receipt.code_revision,
        sourceIdentityDigest: receipt.source_identity_digest,
        forecastInputs: [
          forecastInputs[0],
          { ...forecastInputs[1], contentHash: '4'.repeat(64) },
        ],
      }),
      /forecastInputSet/,
    );
    assert.throws(
      () => assertReleaseValidationObservationBatchRetryEquivalent(receipt, {
        codeRevision: receipt.code_revision,
        sourceIdentityDigest: receipt.source_identity_digest,
        forecastInputs: [...forecastInputs].reverse(),
      }),
      /forecastInputSet/,
    );

    const forecastOrderTampered = tamperV2Receipt(receipt, (payload) => {
      payload.forecastInputs.reverse();
    });
    const forecastOrderReport = verifyReleaseValidationObservationBatchLedger({
      outcomes,
      batches: [forecastOrderTampered],
    });
    assert.equal(forecastOrderReport.batchContentHashFailureCount, 0);
    assert.ok(forecastOrderReport.batchForecastBindingFailureCount > 0);

    const resultTampered = tamperV2Receipt(receipt, (payload) => {
      const excluded = payload.results.find((result) => result.status === 'excluded');
      if (excluded) excluded.reason = 'different_exclusion';
    });
    const resultReport = verifyReleaseValidationObservationBatchLedger({
      outcomes,
      batches: [resultTampered],
    });
    assert.equal(resultReport.batchContentHashFailureCount, 0);
    assert.ok(resultReport.batchResultSetFailureCount > 0);

    const outcomeRefsTampered = tamperV2Receipt(receipt, (payload) => {
      payload.outcomeRefs.pop();
    });
    const outcomeRefsReport = verifyReleaseValidationObservationBatchLedger({
      outcomes,
      batches: [outcomeRefsTampered],
    });
    assert.equal(outcomeRefsReport.batchContentHashFailureCount, 0);
    assert.ok(outcomeRefsReport.batchOutcomeReferenceSetFailureCount > 0);
  });

  it('leaves legacy outcomes in v1 history and owns each new v2 outcome once', () => {
    const legacyOutcomes = stageReleaseValidationOutcomeRows([], [{
      decision_id: 'legacy-decision',
      horizon_code: 'field_regression_72h',
      observed_at: '2026-07-01T00:00:00.000Z',
      status: 'indeterminate',
      outcome_json: JSON.stringify({
        schemaVersion: 1,
        reason: 'legacy_reason',
        fatal: false,
      }),
      source_identity_json: JSON.stringify({ digest: '5'.repeat(64) }),
    }]);
    const legacyReceipt = stageReleaseValidationObservationBatchReceipt(
      [],
      [],
      legacyOutcomes,
      {
        batchId: 'legacy-batch',
        observedAt: '2026-07-01T00:00:01.000Z',
        codeRevision: 'legacy-batch-revision',
        sourceIdentityDigest: '5'.repeat(64),
        forecastCount: 1,
        results: [
          {
            decisionId: 'legacy-decision',
            opportunityCode: 'first_verified_after_24h',
            targetReleaseTag: 'v-legacy',
            horizonCode: 'field_regression_72h',
            status: 'indeterminate',
            persistence: 'inserted',
            fatal: false,
            reason: 'legacy_reason',
            observationId: legacyOutcomes[0].observation_id,
            observationContentHash: legacyOutcomes[0].content_hash,
          },
          {
            decisionId: 'legacy-decision',
            opportunityCode: 'first_verified_after_24h',
            targetReleaseTag: 'v-legacy',
            horizonCode: 'security_30d',
            status: 'pending',
            persistence: 'not_applicable',
          },
        ],
      },
    );
    const v2Outcomes = stageReleaseValidationOutcomeRows(legacyOutcomes, [{
      decision_id: 'v2-decision',
      horizon_code: 'security_30d',
      observed_at: '2026-07-02T00:00:00.000Z',
      status: 'matured',
      outcome_json: JSON.stringify({ schemaVersion: 3, adverse: false }),
      source_identity_json: JSON.stringify({ digest: '6'.repeat(64) }),
    }]);
    const v2Receipt = stageReleaseValidationObservationBatchReceipt(
      [legacyReceipt],
      legacyOutcomes,
      v2Outcomes,
      {
        batchId: 'v2-batch',
        observedAt: '2026-07-02T00:00:01.000Z',
        codeRevision: 'v2-batch-revision',
        sourceIdentityDigest: '6'.repeat(64),
        forecastCount: 1,
        forecastInputs: [
          { decisionId: 'v2-decision', contentHash: '7'.repeat(64) },
        ],
        results: [
          {
            decisionId: 'v2-decision',
            opportunityCode: 'first_verified_after_24h',
            targetReleaseTag: 'v2',
            horizonCode: 'field_regression_72h',
            status: 'pending',
            persistence: 'not_applicable',
          },
          {
            decisionId: 'v2-decision',
            opportunityCode: 'first_verified_after_24h',
            targetReleaseTag: 'v2',
            horizonCode: 'security_30d',
            status: 'matured',
            persistence: 'inserted',
            adverse: false,
            observationId: v2Outcomes[0].observation_id,
            observationContentHash: v2Outcomes[0].content_hash,
          },
        ],
      },
    );
    const v2AlreadyExistingReceipt = stageReleaseValidationObservationBatchReceipt(
      [legacyReceipt, v2Receipt],
      [...legacyOutcomes, ...v2Outcomes],
      [],
      {
        batchId: 'v2-already-existing-batch',
        observedAt: '2026-07-02T00:00:02.000Z',
        codeRevision: 'v2-batch-revision',
        sourceIdentityDigest: '6'.repeat(64),
        forecastCount: 1,
        forecastInputs: [
          { decisionId: 'v2-decision', contentHash: '7'.repeat(64) },
        ],
        results: [
          {
            decisionId: 'v2-decision',
            opportunityCode: 'first_verified_after_24h',
            targetReleaseTag: 'v2',
            horizonCode: 'field_regression_72h',
            status: 'pending',
            persistence: 'not_applicable',
          },
          {
            decisionId: 'v2-decision',
            opportunityCode: 'first_verified_after_24h',
            targetReleaseTag: 'v2',
            horizonCode: 'security_30d',
            status: 'matured',
            persistence: 'already_existing',
            adverse: false,
            observationId: v2Outcomes[0].observation_id,
            observationContentHash: v2Outcomes[0].content_hash,
          },
        ],
      },
    );
    const verification = verifyReleaseValidationObservationBatchLedger({
      outcomes: [...legacyOutcomes, ...v2Outcomes],
      batches: [legacyReceipt, v2Receipt, v2AlreadyExistingReceipt],
    });
    assert.equal(verification.failedCount, 0);
    assert.equal(releaseValidationObservationBatchReport(legacyReceipt).schemaVersion, 1);
    assert.deepEqual(
      releaseValidationObservationBatchResults(legacyReceipt.results_json),
      releaseValidationObservationBatchReport(legacyReceipt).results,
    );
    const v2Report = releaseValidationObservationBatchReport(v2Receipt);
    assert.equal(v2Report.schemaVersion, 2);
    assert.deepEqual(
      (v2Report.outcomeRefs as Array<{ observationId: string }>).map((reference) =>
        reference.observationId),
      [v2Outcomes[0].observation_id],
    );
    assert.notEqual(
      (v2Report.outcomeRefs as Array<{ observationId: string }>)[0].observationId,
      legacyOutcomes[0].observation_id,
    );
    assert.deepEqual(
      releaseValidationObservationBatchReport(v2AlreadyExistingReceipt).outcomeRefs,
      [],
    );

    const pendingV1Results: ReleaseValidationObservationBatchResult[] = [
      {
        decisionId: 'v2-decision',
        opportunityCode: 'first_verified_after_24h',
        targetReleaseTag: 'v2',
        horizonCode: 'field_regression_72h',
        status: 'pending',
        persistence: 'not_applicable',
      },
      {
        decisionId: 'v2-decision',
        opportunityCode: 'first_verified_after_24h',
        targetReleaseTag: 'v2',
        horizonCode: 'security_30d',
        status: 'pending',
        persistence: 'not_applicable',
      },
    ];
    assert.throws(
      () => stageReleaseValidationObservationBatchReceipt(
        [legacyReceipt, v2Receipt, v2AlreadyExistingReceipt],
        [...legacyOutcomes, ...v2Outcomes],
        [],
        {
          batchId: 'regressed-v1-batch',
          observedAt: '2026-07-02T00:00:03.000Z',
          codeRevision: 'v2-batch-revision',
          sourceIdentityDigest: '6'.repeat(64),
          forecastCount: 1,
          results: pendingV1Results,
        },
      ),
      /cannot append legacy v1 history after v2 history begins/,
    );

    const regressedV1Receipt = stageReleaseValidationObservationBatchReceipt(
      [],
      [...legacyOutcomes, ...v2Outcomes],
      [],
      {
        batchId: 'regressed-v1-batch',
        observedAt: '2026-07-02T00:00:03.000Z',
        codeRevision: 'v2-batch-revision',
        sourceIdentityDigest: '6'.repeat(64),
        forecastCount: 1,
        results: pendingV1Results,
      },
    );
    regressedV1Receipt.id = Number(v2AlreadyExistingReceipt.id) + 1;
    regressedV1Receipt.previous_content_hash = v2AlreadyExistingReceipt.content_hash;
    regressedV1Receipt.outcome_chain_previous_hash =
      v2AlreadyExistingReceipt.outcome_chain_content_hash;
    regressedV1Receipt.outcome_chain_content_hash =
      v2AlreadyExistingReceipt.outcome_chain_content_hash;
    regressedV1Receipt.content_hash =
      releaseValidationObservationBatchContentHash(regressedV1Receipt);
    const regressionReport = verifyReleaseValidationObservationBatchLedger({
      outcomes: [...legacyOutcomes, ...v2Outcomes],
      batches: [
        legacyReceipt,
        v2Receipt,
        v2AlreadyExistingReceipt,
        regressedV1Receipt,
      ],
    });
    assert.equal(regressionReport.batchSchemaRegressionCount, 1);
    assert.match(regressionReport.problems.join('\n'), /regresses from v2 to v1/);
  });
});

function tamperV2Receipt(
  receipt: ReturnType<typeof stageReleaseValidationObservationBatchReceipt>,
  mutate: (payload: {
    forecastInputs: Array<{ decisionId: string; contentHash: string }>;
    results: ReleaseValidationObservationBatchResult[];
    outcomeRefs: Array<Record<string, unknown>>;
  }) => void,
): ReturnType<typeof stageReleaseValidationObservationBatchReceipt> {
  const tampered = structuredClone(receipt);
  const wrapper = JSON.parse(tampered.results_json);
  mutate(wrapper[0]);
  tampered.results_json = canonicalReleaseValidationBatchJson(wrapper);
  tampered.content_hash = releaseValidationObservationBatchContentHash(tampered);
  return tampered;
}
