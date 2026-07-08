import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { it } from 'node:test';

it('records one CLI evaluation receipt and reuses its exact retry', () => {
  const root = join(import.meta.dirname, '..', '..');
  const databasePath = process.env.DB_PATH;
  assert.ok(databasePath, 'DB_PATH must be provided by the test runner');
  const environment = {
    ...process.env,
    DB_PATH: databasePath,
  };
  delete environment.NODE_TEST_CONTEXT;
  const cliEnvironment = {
    ...environment,
    npm_lifecycle_event: 'validation:evaluate',
    RADAR_DB_BOOTSTRAP_MODE: 'existing',
  };
  const evaluatedAt = '2026-02-15T00:00:00.000Z';

  const seed = spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      'src/lib/releaseValidationProofEvaluationCli.helper.ts',
    ],
    {
      cwd: root,
      env: environment,
      encoding: 'utf8',
    },
  );
  assert.equal(seed.status, 0, `${seed.stdout}\n${seed.stderr}`);

  const runEvaluation = () => spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      'scripts/validation/evaluate-score-quality.mjs',
      '--record',
      '--evaluated-at',
      evaluatedAt,
    ],
    {
      cwd: root,
      env: cliEnvironment,
      encoding: 'utf8',
    },
  );
  const first = runEvaluation();
  assert.equal(first.status, 2, `${first.stdout}\n${first.stderr}`);
  const firstReport = JSON.parse(first.stdout);
  assert.equal(
    firstReport.canonicalEvaluationReceipt.persistence,
    'inserted',
  );
  assert.equal(firstReport.canonicalEvaluationReceipt.insertedCount, 1);
  assert.equal(firstReport.canonicalEvaluationReceipt.equivalentCount, 0);
  assert.ok(
    firstReport.canonicalEvaluationReceipt.opportunityCoverage
      .authoritativeOpportunityCount > 0,
  );
  assert.equal(
    firstReport.canonicalEvaluationReceipt.opportunityCoverage
      .missingOpportunityCount,
    firstReport.canonicalEvaluationReceipt.opportunityCoverage
      .authoritativeOpportunityCount,
  );
  assert.equal(
    firstReport.canonicalEvaluationReceipt.opportunityCoverage
      .partitionValid,
    true,
  );

  const second = runEvaluation();
  assert.equal(second.status, 2, `${second.stdout}\n${second.stderr}`);
  const secondReport = JSON.parse(second.stdout);
  assert.equal(
    secondReport.canonicalEvaluationReceipt.persistence,
    'already_captured',
  );
  assert.equal(secondReport.canonicalEvaluationReceipt.insertedCount, 0);
  assert.equal(secondReport.canonicalEvaluationReceipt.equivalentCount, 0);
  assert.equal(
    secondReport.canonicalEvaluationReceipt.evaluationId,
    firstReport.canonicalEvaluationReceipt.evaluationId,
  );
  assert.equal(
    secondReport.canonicalEvaluationReceipt.contentHash,
    firstReport.canonicalEvaluationReceipt.contentHash,
  );

  const promotedAt = '2026-02-15T00:00:01.000Z';
  const runPromotion = () => spawnSync(
    process.execPath,
    [
      '--import',
      'tsx',
      'scripts/validation/record-promotion.mjs',
      '--environment',
      'calibration',
      '--promoted-at',
      promotedAt,
      '--evaluation-id',
      firstReport.canonicalEvaluationReceipt.evaluationId,
      '--evaluation-content-hash',
      firstReport.canonicalEvaluationReceipt.contentHash,
      '--source-proof-hash',
      'e'.repeat(64),
      '--destination-proof-hash',
      'f'.repeat(64),
    ],
    {
      cwd: root,
      env: promotionChildEnvironment(cliEnvironment),
      encoding: 'utf8',
    },
  );
  const firstPromotion = runPromotion();
  assert.equal(
    firstPromotion.status,
    0,
    `${firstPromotion.stdout}\n${firstPromotion.stderr}`,
  );
  const firstPromotionReport = JSON.parse(firstPromotion.stdout);
  assert.equal(firstPromotionReport.environment, 'calibration');
  assert.equal(firstPromotionReport.persistence, 'inserted');
  assert.equal(firstPromotionReport.insertedCount, 1);
  assert.equal(firstPromotionReport.equivalentCount, 0);

  const secondPromotion = runPromotion();
  assert.equal(
    secondPromotion.status,
    0,
    `${secondPromotion.stdout}\n${secondPromotion.stderr}`,
  );
  const secondPromotionReport = JSON.parse(secondPromotion.stdout);
  assert.equal(secondPromotionReport.persistence, 'already_captured');
  assert.equal(secondPromotionReport.insertedCount, 0);
  assert.equal(secondPromotionReport.equivalentCount, 0);
  assert.equal(
    secondPromotionReport.promotionId,
    firstPromotionReport.promotionId,
  );
  assert.equal(
    secondPromotionReport.contentHash,
    firstPromotionReport.contentHash,
  );

  const database = new DatabaseSync(databasePath, { readOnly: true });
  try {
    const rows = database.prepare(`
      SELECT evaluation_id, evaluated_at, content_hash
      FROM release_validation_evaluation_receipts
      WHERE evaluated_at=?
    `).all(evaluatedAt);
    assert.equal(rows.length, 1);
    assert.deepEqual({ ...rows[0] }, {
      evaluation_id:
        firstReport.canonicalEvaluationReceipt.evaluationId,
      evaluated_at: evaluatedAt,
      content_hash:
        firstReport.canonicalEvaluationReceipt.contentHash,
    });
    const promotions = database.prepare(`
      SELECT promotion_id, evaluation_id, environment, content_hash
      FROM release_validation_promotion_receipts
    `).all();
    assert.equal(promotions.length, 1);
    assert.deepEqual({ ...promotions[0] }, {
      promotion_id: firstPromotionReport.promotionId,
      evaluation_id:
        firstReport.canonicalEvaluationReceipt.evaluationId,
      environment: 'calibration',
      content_hash: firstPromotionReport.contentHash,
    });
  } finally {
    database.close();
  }
});

function promotionChildEnvironment(
  base: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const environment = {
    ...base,
    npm_lifecycle_event: 'promote:quality-db',
  };
  return environment;
}
