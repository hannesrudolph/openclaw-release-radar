import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  releaseValidationCohortCellKey,
  releaseValidationSplitSeedHash,
  sealReleaseValidationCatalogObservation,
  sealReleaseValidationCatalogReconciliation,
  sealReleaseValidationCohort,
  sealReleaseValidationEvaluationReceipt,
  sealReleaseValidationForecastV2,
  sealReleaseValidationObservationBatch,
  sealReleaseValidationObligation,
  sealReleaseValidationOutcomeV2,
  sealReleaseValidationPolicy,
  sealReleaseValidationPromotionReceipt,
  sealReleaseValidationProofEpoch,
  sealReleaseValidationProofEpochRetirement,
  sealReleaseValidationSplitAssignment,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';

const databasePath = requiredEnvironmentPath('DB_PATH');
const emptyDotenvPath = requiredEnvironmentPath('DOTENV_CONFIG_PATH');

let databaseModule: typeof import('./db.ts');

before(async () => {
  databaseModule = await import(
    `./db.ts?validation-proof-db-${Date.now()}-${Math.random()}`
  );
});

after(() => {
  databaseModule?.db.close();
});

function requiredEnvironmentPath(name: string): string {
  const value = process.env[name];
  assert.ok(value, `${name} must be assigned by the guarded test runner`);
  return value;
}

describe('release validation proof database ledger', () => {
  it('is atomic, immutable, idempotent, restart-safe, and projection-audited', async () => {
    const fixture = proofFixture();
    assert.equal(databaseModule.releaseValidationProofStorageAvailable(), true);
    assert.deepEqual(
      databaseModule.verifyStoredReleaseValidationProofBundle().problems,
      [],
    );

    assert.throws(
      () => databaseModule.appendReleaseValidationProof({
        obligations: [fixture.obligation],
      }),
      /missing proof epoch|outside its cohort|one immutable split assignment/,
    );
    assert.equal(totalProofRows(), 0);

    const inserted = databaseModule.appendReleaseValidationProof(
      fixture.bundle,
    );
    assert.equal(inserted.insertedCount, 15);
    assert.equal(inserted.equivalentCount, 0);
    assert.equal(inserted.verification.valid, true);
    assert.deepEqual(inserted.bundle, fixture.bundle);

    const retry = databaseModule.appendReleaseValidationProof(fixture.bundle);
    assert.equal(retry.insertedCount, 0);
    assert.equal(retry.equivalentCount, 15);
    assert.deepEqual(retry.bundle, fixture.bundle);

    assert.throws(
      () => databaseModule.appendReleaseValidationProof({
        forecasts: [fixture.forecast, fixture.forecast],
      }),
      /repeats the same immutable record ID/,
    );
    assert.throws(
      () => databaseModule.appendReleaseValidationProof({
        forecasts: [{
          ...fixture.forecast,
          forecast: { recommendation: 'wait', score: 0 },
        }],
      }),
      /stored immutable record differs/,
    );
    assert.equal(totalProofRows(), 15);

    assert.throws(
      () => databaseModule.db.prepare(`
        UPDATE release_validation_policies
        SET policy_code='tampered'
        WHERE policy_id=?
      `).run(fixture.policy.policyId),
      /append-only/,
    );
    assert.throws(
      () => databaseModule.db.prepare(`
        DELETE FROM release_validation_catalog_members
        WHERE member_id=?
      `).run(fixture.catalog.members[0].memberId),
      /append-only/,
    );

    databaseModule.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const restartProbe = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        '--input-type=module',
        '--eval',
        `
          const imported = await import('./src/lib/db.ts');
          const database = imported.default ?? imported;
          const bundle = database.readReleaseValidationProofBundle();
          const verification =
            database.verifyStoredReleaseValidationProofBundle();
          console.log(JSON.stringify({
            valid: verification.valid,
            epochCount: bundle.epochs.length,
            promotionCount: bundle.promotionReceipts.length,
          }));
          database.db.close();
        `,
      ],
      {
        cwd: join(import.meta.dirname, '..', '..'),
        encoding: 'utf8',
        env: {
          ...process.env,
          DB_PATH: databasePath,
          DOTENV_CONFIG_PATH: emptyDotenvPath,
          RADAR_DB_BOOTSTRAP_MODE: 'existing',
          RADAR_DB_READ_ONLY: '1',
        },
      },
    );
    assert.equal(
      restartProbe.status,
      0,
      `${restartProbe.stdout}\n${restartProbe.stderr}`,
    );
    assert.deepEqual(
      JSON.parse(restartProbe.stdout.trim().split('\n').at(-1) ?? '{}'),
      { valid: true, epochCount: 1, promotionCount: 1 },
    );

    databaseModule.db.exec(`
      DROP TRIGGER release_validation_policies_no_update;
      UPDATE release_validation_policies
      SET policy_code='projection-tamper'
      WHERE policy_id='${fixture.policy.policyId}';
    `);
    assert.throws(
      () => databaseModule.readReleaseValidationProofBundle(),
      /divergent policy_code projection/,
    );
  });
});

function totalProofRows(): number {
  return [
    'release_validation_proof_epochs',
    'release_validation_proof_epoch_retirements',
    'release_validation_policies',
    'release_validation_cohorts',
    'release_validation_catalog_observations',
    'release_validation_catalog_members',
    'release_validation_catalog_reconciliations',
    'release_validation_catalog_reconciliation_rows',
    'release_validation_obligations',
    'release_validation_split_assignments',
    'release_validation_forecasts_v2',
    'release_validation_outcomes_v2',
    'release_validation_proof_observation_batches',
    'release_validation_evaluation_receipts',
    'release_validation_promotion_receipts',
  ].reduce((sum, table) => {
    const row = databaseModule.db.prepare(
      `SELECT COUNT(*) AS count FROM ${table}`,
    ).get() as { count: number };
    return sum + Number(row.count);
  }, 0);
}

function proofFixture() {
  const repository = 'openclaw/openclaw';
  const epoch = sealReleaseValidationProofEpoch({
    repository,
    recordedAt: '2026-01-01T00:00:00Z',
    startsAt: '2026-01-01T00:00:00Z',
  });
  const policy = sealReleaseValidationPolicy({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 1,
    previousEpochContentHash: null,
    policyCode: 'prospective-v1',
    policyVersion: 1,
    recordedAt: '2026-01-01T00:00:00Z',
    effectiveAt: '2026-01-01T00:00:00Z',
    requiredCells: [{
      opportunityCode: 'first_verified_after_3h',
      horizonCode: 'field_regression_72h',
    }],
  });
  const cell = policy.requiredCells[0];
  const cohort = sealReleaseValidationCohort({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 2,
    previousEpochContentHash: policy.contentHash,
    policyId: policy.policyId,
    policyContentHash: policy.contentHash,
    modelVersion: 'model-v1',
    promptVersion: 1,
    codeRevision: 'revision-v1',
    recordedAt: '2026-01-01T00:01:00Z',
    startsAt: '2026-01-01T00:01:00Z',
    requiredCellIds: [cell.cellId],
  });
  const release = {
    repository,
    nodeId: 'release-node-1',
    tagCommitOid: '1'.repeat(40),
    publishedAt: '2026-01-01T00:01:00Z',
    aliases: ['v1.0.0'],
  };
  const catalog = sealReleaseValidationCatalogObservation({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 3,
    previousEpochContentHash: cohort.contentHash,
    source: 'github',
    observedAt: '2026-01-01T00:02:00Z',
    exhaustive: true,
    stabilized: true,
    releases: [release],
  });
  const reconciliation = sealReleaseValidationCatalogReconciliation({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 4,
    previousEpochContentHash: catalog.observation.contentHash,
    reconciledAt: '2026-01-01T00:03:00Z',
    previousObservation: null,
    currentObservation: catalog.observation,
    currentMembers: catalog.members,
  });
  const obligation = sealReleaseValidationObligation({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 1,
    previousCohortContentHash: null,
    cellId: cell.cellId,
    opportunityCode: cell.opportunityCode,
    horizonCode: cell.horizonCode,
    release,
    recordedAt: '2026-01-01T00:04:00Z',
    opensAt: '2026-01-01T01:00:00Z',
    closesAtExclusive: '2026-01-01T02:00:00Z',
    outcomeDueAt: '2026-01-01T03:00:00Z',
    catalogObservationId: catalog.observation.observationId,
    catalogObservationContentHash: catalog.observation.contentHash,
    reconciliationId: reconciliation.reconciliation.reconciliationId,
    reconciliationContentHash: reconciliation.reconciliation.contentHash,
  });
  const assignment = sealReleaseValidationSplitAssignment({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 2,
    previousCohortContentHash: obligation.contentHash,
    obligationId: obligation.obligationId,
    assignedAt: '2026-01-01T00:05:00Z',
    arm: 'production',
    splitPolicyHash: policy.splitPolicyHash,
    seedHash: releaseValidationSplitSeedHash({
      proofEpochId: epoch.proofEpochId,
      cohortId: cohort.cohortId,
      releaseId: catalog.members[0].release.releaseId,
      admissionOrdinal: 1,
      splitPolicyHash: policy.splitPolicyHash,
    }),
  });
  const forecast = sealReleaseValidationForecastV2({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 3,
    previousCohortContentHash: assignment.contentHash,
    obligationId: obligation.obligationId,
    splitAssignmentId: assignment.assignmentId,
    policyId: policy.policyId,
    policyContentHash: policy.contentHash,
    recordedAt: '2026-01-01T01:30:00Z',
    latestRelease: release,
    candidates: [release],
    selectedReleaseId: catalog.members[0].release.releaseId,
    forecast: { recommendation: 'install', score: 8.5 },
  });
  const outcome = sealReleaseValidationOutcomeV2({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 4,
    previousCohortContentHash: forecast.contentHash,
    forecastId: forecast.forecastId,
    obligationId: obligation.obligationId,
    cellId: cell.cellId,
    releaseId: catalog.members[0].release.releaseId,
    observedAt: '2026-01-01T03:00:00Z',
    status: 'safe',
    evidenceContentHashes: ['c'.repeat(64)],
    outcome: { adverseCount: 0 },
  });
  const batch = sealReleaseValidationObservationBatch({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 5,
    previousCohortContentHash: outcome.contentHash,
    observedAt: '2026-01-01T03:01:00Z',
    sourceIdentityHash: 'd'.repeat(64),
    expectedObligationIds: [obligation.obligationId],
    cells: [{
      obligationId: obligation.obligationId,
      forecastId: forecast.forecastId,
      outcomeId: outcome.outcomeId,
      disposition: 'observed',
    }],
  });
  const evaluation = sealReleaseValidationEvaluationReceipt({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 5,
    previousEpochContentHash: reconciliation.reconciliation.contentHash,
    evaluatedAt: '2026-01-01T03:02:00Z',
    status: 'validated',
    cohortIds: [cohort.cohortId],
    requiredCellKeys: [
      releaseValidationCohortCellKey(cohort.cohortId, cell.cellId),
    ],
    observationBatchIds: [batch.batchId],
    outcomeIds: [outcome.outcomeId],
    metrics: { accuracy: 1, sampleCount: 1 },
  });
  const promotion = sealReleaseValidationPromotionReceipt({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 6,
    previousEpochContentHash: evaluation.contentHash,
    environment: 'production',
    promotedAt: '2026-01-01T03:03:00Z',
    evaluationId: evaluation.evaluationId,
    evaluationContentHash: evaluation.contentHash,
    cohortIds: [cohort.cohortId],
    forecastIds: [forecast.forecastId],
    outcomeIds: [outcome.outcomeId],
    sourceProofHash: 'e'.repeat(64),
    destinationProofHash: 'f'.repeat(64),
  });
  const retirement = sealReleaseValidationProofEpochRetirement({
    proofEpochId: epoch.proofEpochId,
    epochContentHash: epoch.contentHash,
    epochSequence: 7,
    previousEpochContentHash: promotion.contentHash,
    recordedAt: '2026-01-01T04:00:00Z',
    retiredAt: '2026-01-01T04:00:00Z',
    reason: 'fixture complete',
  });
  const bundle: ReleaseValidationProofBundle = {
    epochs: [epoch],
    retirements: [retirement],
    policies: [policy],
    cohorts: [cohort],
    catalogObservations: [catalog.observation],
    catalogMembers: catalog.members,
    catalogReconciliations: [reconciliation.reconciliation],
    catalogReconciliationRows: reconciliation.rows,
    obligations: [obligation],
    splitAssignments: [assignment],
    forecasts: [forecast],
    outcomes: [outcome],
    observationBatches: [batch],
    evaluationReceipts: [evaluation],
    promotionReceipts: [promotion],
  };
  return {
    bundle,
    epoch,
    policy,
    cohort,
    catalog,
    reconciliation,
    obligation,
    assignment,
    forecast,
    outcome,
    batch,
    evaluation,
    promotion,
    retirement,
  };
}
