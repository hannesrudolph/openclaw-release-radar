import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  assertValidReleaseValidationForecastV2,
  assertValidReleaseValidationOutcomeV2,
  canonicalReleaseValidationProofJson,
  createReleaseValidationStableReleaseIdentity,
  normalizeReleaseValidationProofOid,
  normalizeReleaseValidationProofTimestamp,
  releaseValidationCohortCellKey,
  releaseValidationProofExactSetHash,
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
  verifyReleaseValidationProofBundle,
  type ReleaseValidationEvaluationStatus,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';
import {
  planReleaseValidationProofPromotion,
} from './releaseValidationProofPromotion.ts';
import {
  summarizeReleaseValidationProof,
} from './releaseValidationProofSummary.ts';

const repository = 'OpenClaw/OpenClaw';
const sourceIdentityHash = 'c'.repeat(64);
const evidenceHash = 'd'.repeat(64);
const sourceProofHash = 'e'.repeat(64);
const destinationProofHash = 'f'.repeat(64);

describe('release validation proof canonical domains', () => {
  it('sorts object keys, preserves array order, and rejects lossy JSON values', () => {
    assert.equal(
      canonicalReleaseValidationProofJson({
        z: 1,
        a: { y: 2, x: 3 },
        list: ['second', 'first'],
      }),
      '{"a":{"x":3,"y":2},"list":["second","first"],"z":1}',
    );
    assert.notEqual(
      canonicalReleaseValidationProofJson({ values: ['a', 'b'] }),
      canonicalReleaseValidationProofJson({ values: ['b', 'a'] }),
    );
    assert.throws(
      () => canonicalReleaseValidationProofJson({ omitted: undefined }),
      /undefined/,
    );
    assert.throws(
      () => canonicalReleaseValidationProofJson([Number.NaN]),
      /non-finite/,
    );
    assert.throws(
      () => canonicalReleaseValidationProofJson({ value: Infinity }),
      /non-finite/,
    );
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    assert.throws(
      () => canonicalReleaseValidationProofJson(cycle),
      /cycle/,
    );
  });

  it('normalizes timestamps and OIDs without making aliases release identity', () => {
    assert.equal(
      normalizeReleaseValidationProofTimestamp('2026-01-01T00:00:00Z'),
      '2026-01-01T00:00:00.000Z',
    );
    assert.equal(
      normalizeReleaseValidationProofOid('A'.repeat(40)),
      'a'.repeat(40),
    );
    const first = releaseIdentity({
      aliases: ['v1.0.0', 'latest'],
    });
    const renamed = releaseIdentity({
      aliases: ['stable', 'v1'],
    });
    const reusedTag = releaseIdentity({
      nodeId: 'release-node-2',
      tagCommitOid: '2'.repeat(40),
      aliases: ['v1.0.0'],
    });

    assert.equal(first.releaseId, renamed.releaseId);
    assert.notEqual(first.releaseId, reusedTag.releaseId);
    assert.equal(first.repository, 'openclaw/openclaw');
    assert.equal(first.tagCommitOid, '1'.repeat(40));
  });

  it('uses exact-set hashes while retaining ordered policy cells', () => {
    const epoch = sealReleaseValidationProofEpoch({
      repository,
      recordedAt: '2026-01-01T00:00:00Z',
      startsAt: '2026-01-01T00:00:00Z',
    });
    const forward = sealReleaseValidationPolicy({
      proofEpochId: epoch.proofEpochId,
      epochSequence: 1,
      previousEpochContentHash: null,
      policyCode: 'validation-policy',
      policyVersion: 1,
      recordedAt: '2026-01-01T00:00:00Z',
      effectiveAt: '2026-01-01T00:00:00Z',
      requiredCells: [
        { opportunityCode: 'after_3h', horizonCode: 'field_72h' },
        { opportunityCode: 'after_24h', horizonCode: 'security_30d' },
      ],
    });
    const reversed = sealReleaseValidationPolicy({
      proofEpochId: epoch.proofEpochId,
      epochSequence: 1,
      previousEpochContentHash: null,
      policyCode: 'validation-policy',
      policyVersion: 1,
      recordedAt: '2026-01-01T00:00:00Z',
      effectiveAt: '2026-01-01T00:00:00Z',
      requiredCells: [
        { opportunityCode: 'after_24h', horizonCode: 'security_30d' },
        { opportunityCode: 'after_3h', horizonCode: 'field_72h' },
      ],
    });

    assert.equal(forward.requiredCellSetHash, reversed.requiredCellSetHash);
    assert.notEqual(
      forward.requiredCellOrderedHash,
      reversed.requiredCellOrderedHash,
    );
    assert.notEqual(forward.contentHash, reversed.contentHash);
    assert.equal(
      releaseValidationProofExactSetHash('test', ['a', 'b']),
      releaseValidationProofExactSetHash('test', ['b', 'a']),
    );
    assert.notEqual(
      releaseValidationProofExactSetHash('test', ['a', 'b']),
      releaseValidationProofExactSetHash('test', ['a', 'c']),
    );
  });
});

describe('release validation proof graph', () => {
  it('validates a complete graph and replays it deterministically', () => {
    const first = fixture();
    const second = fixture();
    assert.deepEqual(first.bundle, second.bundle);

    const report = verifyReleaseValidationProofBundle(first.bundle);
    assert.equal(report.valid, true, report.problems.join('\n'));
    assert.equal(
      report.epochChainTips[first.epoch.proofEpochId],
      first.promotion.contentHash,
    );
    assert.equal(
      report.cohortChainTips[first.cohort.cohortId],
      first.batch.contentHash,
    );
  });

  it('rejects omitted catalog members and observation cells', () => {
    const first = fixture();
    const missingMember = structuredClone(first.bundle);
    missingMember.catalogMembers = [];
    const memberReport = verifyReleaseValidationProofBundle(missingMember);
    assert.equal(memberReport.valid, false);
    assert.match(memberReport.problems.join('\n'), /memberCount mismatch/);

    const missingCell = structuredClone(first.bundle);
    missingCell.observationBatches[0].cells = [];
    const cellReport = verifyReleaseValidationProofBundle(missingCell);
    assert.equal(cellReport.valid, false);
    assert.match(
      cellReport.problems.join('\n'),
      /canonical deterministic replay|omits expected cells/,
    );
  });

  it('rejects same-count different cohort and cell sets', () => {
    const first = fixture();
    const wrongCellKey = `${first.cohort.cohortId}:${'9'.repeat(64)}`;
    const wrongEvaluation = sealReleaseValidationEvaluationReceipt({
      proofEpochId: first.epoch.proofEpochId,
      epochSequence: first.evaluation.epochSequence,
      previousEpochContentHash:
        first.evaluation.previousEpochContentHash,
      evaluatedAt: first.evaluation.evaluatedAt,
      status: first.evaluation.status,
      cohortIds: first.evaluation.cohortIds,
      requiredCellKeys: [wrongCellKey],
      observationBatchIds: first.evaluation.observationBatchIds,
      outcomeIds: first.evaluation.outcomeIds,
      metrics: first.evaluation.metrics,
    });
    const wrongPromotion = sealReleaseValidationPromotionReceipt({
      proofEpochId: first.epoch.proofEpochId,
      epochSequence: 6,
      previousEpochContentHash: wrongEvaluation.contentHash,
      environment: 'production',
      promotedAt: first.promotion.promotedAt,
      evaluationId: wrongEvaluation.evaluationId,
      evaluationContentHash: wrongEvaluation.contentHash,
      cohortIds: wrongEvaluation.cohortIds,
      forecastIds: [first.forecast.forecastId],
      outcomeIds: [first.outcome.outcomeId],
      sourceProofHash,
      destinationProofHash,
    });
    const wrongCellBundle = {
      ...first.bundle,
      evaluationReceipts: [wrongEvaluation],
      promotionReceipts: [wrongPromotion],
    };
    const wrongCellReport =
      verifyReleaseValidationProofBundle(wrongCellBundle);
    assert.equal(wrongCellReport.valid, false);
    assert.match(
      wrongCellReport.problems.join('\n'),
      /required cell set mismatch.*exact set/,
    );

    const alienCohortId = '8'.repeat(64);
    const wrongCohortEvaluation = sealReleaseValidationEvaluationReceipt({
      proofEpochId: first.epoch.proofEpochId,
      epochSequence: 5,
      previousEpochContentHash: first.reconciliation.contentHash,
      evaluatedAt: first.evaluation.evaluatedAt,
      status: 'validated',
      cohortIds: [alienCohortId],
      requiredCellKeys: [
        releaseValidationCohortCellKey(alienCohortId, first.cell.cellId),
      ],
      observationBatchIds: [first.batch.batchId],
      outcomeIds: [first.outcome.outcomeId],
      metrics: {},
    });
    const wrongCohortReport = verifyReleaseValidationProofBundle({
      ...first.bundle,
      evaluationReceipts: [wrongCohortEvaluation],
      promotionReceipts: [],
    });
    assert.equal(wrongCohortReport.valid, false);
    assert.match(
      wrongCohortReport.problems.join('\n'),
      /cohort set mismatch.*exact set/,
    );
  });

  it('treats tag reuse as retirement plus addition, never as identity reuse', () => {
    const epoch = sealReleaseValidationProofEpoch({
      repository,
      recordedAt: '2026-01-01T00:00:00Z',
      startsAt: '2026-01-01T00:00:00Z',
    });
    const oldCatalog = sealReleaseValidationCatalogObservation({
      proofEpochId: epoch.proofEpochId,
      epochSequence: 1,
      previousEpochContentHash: null,
      source: 'github',
      observedAt: '2026-01-01T00:01:00Z',
      exhaustive: true,
      stabilized: true,
      releases: [{
        repository,
        nodeId: 'old-node',
        tagCommitOid: '1'.repeat(40),
        publishedAt: '2026-01-01T00:00:00Z',
        aliases: ['v-reused'],
      }],
    });
    const newCatalog = sealReleaseValidationCatalogObservation({
      proofEpochId: epoch.proofEpochId,
      epochSequence: 2,
      previousEpochContentHash: oldCatalog.observation.contentHash,
      source: 'github',
      observedAt: '2026-01-02T00:01:00Z',
      exhaustive: true,
      stabilized: true,
      releases: [{
        repository,
        nodeId: 'new-node',
        tagCommitOid: '2'.repeat(40),
        publishedAt: '2026-01-02T00:00:00Z',
        aliases: ['v-reused'],
      }],
    });
    const reconciled = sealReleaseValidationCatalogReconciliation({
      proofEpochId: epoch.proofEpochId,
      epochSequence: 3,
      previousEpochContentHash: newCatalog.observation.contentHash,
      reconciledAt: '2026-01-02T00:02:00Z',
      previousObservation: oldCatalog.observation,
      previousMembers: oldCatalog.members,
      currentObservation: newCatalog.observation,
      currentMembers: newCatalog.members,
    });

    assert.notEqual(
      oldCatalog.members[0].release.releaseId,
      newCatalog.members[0].release.releaseId,
    );
    assert.deepEqual(
      reconciled.rows.map((row) => row.status),
      ['added', 'retired'],
    );
    assert.equal(
      reconciled.rows.find((row) => row.status === 'retired')?.retiredAt,
      '2026-01-02T00:02:00.000Z',
    );

    assert.throws(
      () => sealReleaseValidationCatalogObservation({
        proofEpochId: epoch.proofEpochId,
        epochSequence: 4,
        previousEpochContentHash: reconciled.reconciliation.contentHash,
        source: 'github',
        observedAt: '2026-01-03T00:00:00Z',
        exhaustive: true,
        stabilized: true,
        releases: [
          {
            repository,
            nodeId: 'one',
            tagCommitOid: '3'.repeat(40),
            publishedAt: '2026-01-03T00:00:00Z',
            aliases: ['duplicate-alias'],
          },
          {
            repository,
            nodeId: 'two',
            tagCommitOid: '4'.repeat(40),
            publishedAt: '2026-01-03T00:00:00Z',
            aliases: ['duplicate-alias'],
          },
        ],
      }),
      /maps to multiple release identities/,
    );
  });

  it('rejects missing release identity and legacy upgrade attempts', () => {
    assert.throws(
      () => createReleaseValidationStableReleaseIdentity({
        repository,
        nodeId: '',
        tagCommitOid: '1'.repeat(40),
        publishedAt: '2026-01-01T00:00:00Z',
        aliases: ['v1'],
      }),
      /nodeId/,
    );

    const legacyForecast = {
      schemaVersion: 2,
      kind: 'forecast_v2',
      decision_id: 'legacy-decision',
      latest_release_tag: 'v1',
      recorded_at: '2026-01-01T00:00:00Z',
      contentHash: '0'.repeat(64),
    };
    assert.throws(
      () => assertValidReleaseValidationForecastV2(legacyForecast),
      /keys mismatch|Legacy forecasts/,
    );

    const legacyOutcome = {
      schemaVersion: 2,
      kind: 'outcome_v2',
      observation_id: 'legacy-observation',
      decision_id: 'legacy-decision',
      contentHash: '0'.repeat(64),
    };
    assert.throws(
      () => assertValidReleaseValidationOutcomeV2(legacyOutcome),
      /keys mismatch|Legacy outcomes/,
    );
  });

  it('detects independently valid chain divergence', () => {
    const first = fixture();
    const divergentAssignment = sealReleaseValidationSplitAssignment({
      proofEpochId: first.epoch.proofEpochId,
      cohortId: first.cohort.cohortId,
      cohortSequence: 2,
      previousCohortContentHash: '9'.repeat(64),
      obligationId: first.obligation.obligationId,
      assignedAt: first.assignment.assignedAt,
      arm: first.assignment.arm,
      splitPolicyHash: first.assignment.splitPolicyHash,
      seedHash: first.assignment.seedHash,
    });
    const report = verifyReleaseValidationProofBundle({
      ...first.bundle,
      splitAssignments: [divergentAssignment],
    });

    assert.equal(report.valid, false);
    assert.match(
      report.problems.join('\n'),
      /Cohort chain .*previous hash mismatch/,
    );
  });

  it('rejects backdated policy, cohort, and retirement records', () => {
    const epoch = sealReleaseValidationProofEpoch({
      repository,
      recordedAt: '2026-01-01T00:00:00Z',
      startsAt: '2026-01-01T00:00:00Z',
    });
    assert.throws(
      () => sealReleaseValidationPolicy({
        proofEpochId: epoch.proofEpochId,
        epochSequence: 1,
        previousEpochContentHash: null,
        policyCode: 'backdated',
        policyVersion: 1,
        recordedAt: '2026-01-02T00:00:00Z',
        effectiveAt: '2026-01-01T00:00:00Z',
        requiredCells: [{
          opportunityCode: 'after_3h',
          horizonCode: 'field_72h',
        }],
      }),
      /effective before it is recorded/,
    );
    assert.throws(
      () => sealReleaseValidationCohort({
        proofEpochId: epoch.proofEpochId,
        epochSequence: 1,
        previousEpochContentHash: null,
        policyId: '1'.repeat(64),
        policyContentHash: '2'.repeat(64),
        modelVersion: 'model',
        promptVersion: 1,
        codeRevision: 'revision',
        recordedAt: '2026-01-02T00:00:00Z',
        startsAt: '2026-01-01T00:00:00Z',
        requiredCellIds: ['3'.repeat(64)],
      }),
      /start before it is recorded/,
    );
    assert.throws(
      () => sealReleaseValidationProofEpochRetirement({
        proofEpochId: epoch.proofEpochId,
        epochContentHash: epoch.contentHash,
        epochSequence: 1,
        previousEpochContentHash: null,
        recordedAt: '2026-01-02T00:00:00Z',
        retiredAt: '2026-01-01T00:00:00Z',
        reason: 'backdated',
      }),
      /cannot be backdated/,
    );
  });

  it('detects payload tamper and does not hash contentHash into itself', () => {
    const first = fixture();
    const tampered = structuredClone(first.bundle);
    tampered.outcomes[0].outcome = { adverseCount: 99 };
    const report = verifyReleaseValidationProofBundle(tampered);

    assert.equal(report.valid, false);
    assert.match(
      report.problems.join('\n'),
      /outcome v2 is not a canonical deterministic replay|content hash mismatch/,
    );

    const hashOnlyTamper = structuredClone(first.bundle);
    hashOnlyTamper.forecasts[0].contentHash = '0'.repeat(64);
    const hashOnlyReport =
      verifyReleaseValidationProofBundle(hashOnlyTamper);
    assert.equal(hashOnlyReport.valid, false);
    assert.match(
      hashOnlyReport.problems.join('\n'),
      /forecast v2 is not a canonical deterministic replay|content hash mismatch/,
    );
  });

  it('keeps calibration and production promotion gates separate', () => {
    const insufficient = fixture('insufficient');
    const productionReport =
      verifyReleaseValidationProofBundle(insufficient.bundle);
    assert.equal(productionReport.valid, false);
    assert.match(
      productionReport.problems.join('\n'),
      /Production promotion .* requires validated evidence/,
    );

    const calibrationPromotion = sealReleaseValidationPromotionReceipt({
      proofEpochId: insufficient.epoch.proofEpochId,
      epochSequence: 6,
      previousEpochContentHash: insufficient.evaluation.contentHash,
      environment: 'calibration',
      promotedAt: insufficient.promotion.promotedAt,
      evaluationId: insufficient.evaluation.evaluationId,
      evaluationContentHash: insufficient.evaluation.contentHash,
      cohortIds: [insufficient.cohort.cohortId],
      forecastIds: [insufficient.forecast.forecastId],
      outcomeIds: [insufficient.outcome.outcomeId],
      sourceProofHash,
      destinationProofHash,
    });
    const calibrationReport = verifyReleaseValidationProofBundle({
      ...insufficient.bundle,
      promotionReceipts: [calibrationPromotion],
    });
    assert.equal(
      calibrationReport.valid,
      true,
      calibrationReport.problems.join('\n'),
    );
  });

  it('plans promotion against the exact latest evaluation ID and hash', () => {
    const complete = fixture();
    const bundle = {
      ...complete.bundle,
      promotionReceipts: [],
    };
    const plan = planReleaseValidationProofPromotion({
      bundle,
      environment: 'production',
      promotedAt: complete.promotion.promotedAt,
      evaluationId: complete.evaluation.evaluationId,
      evaluationContentHash: complete.evaluation.contentHash,
      sourceProofHash,
      destinationProofHash,
    });

    assert.equal(plan.status, 'inserted');
    assert.equal(
      plan.receipt.evaluationId,
      complete.evaluation.evaluationId,
    );
    assert.equal(
      plan.receipt.evaluationContentHash,
      complete.evaluation.contentHash,
    );
    assert.equal(
      verifyReleaseValidationProofBundle(plan.candidate).valid,
      true,
    );

    const retry = planReleaseValidationProofPromotion({
      bundle: plan.candidate,
      environment: 'production',
      promotedAt: complete.promotion.promotedAt,
      evaluationId: complete.evaluation.evaluationId,
      evaluationContentHash: complete.evaluation.contentHash,
      sourceProofHash,
      destinationProofHash,
    });
    assert.equal(retry.status, 'already_captured');
    assert.deepEqual(retry.append.promotionReceipts, []);
    assert.equal(retry.receipt.promotionId, plan.receipt.promotionId);

    assert.throws(
      () => planReleaseValidationProofPromotion({
        bundle,
        environment: 'production',
        promotedAt: complete.promotion.promotedAt,
        evaluationId: complete.evaluation.evaluationId,
        evaluationContentHash: '0'.repeat(64),
        sourceProofHash,
        destinationProofHash,
      }),
      /exact evaluation ID and content hash/,
    );
  });

  it('never lets calibration or an older validation authorize production', () => {
    const complete = fixture();
    const base = {
      ...complete.bundle,
      promotionReceipts: [],
    };
    const evaluatedAt = '2026-01-01T03:03:00Z';
    const laterInsufficient = sealReleaseValidationEvaluationReceipt({
      proofEpochId: complete.epoch.proofEpochId,
      epochSequence: complete.evaluation.epochSequence + 1,
      previousEpochContentHash: complete.evaluation.contentHash,
      evaluatedAt,
      status: 'insufficient',
      cohortIds: complete.evaluation.cohortIds,
      requiredCellKeys: complete.evaluation.requiredCellKeys,
      observationBatchIds: complete.evaluation.observationBatchIds,
      outcomeIds: complete.evaluation.outcomeIds,
      metrics: {
        schemaVersion: 4,
        generatedAt: evaluatedAt,
        status: 'insufficient',
      },
    });
    const bundle = {
      ...base,
      evaluationReceipts: [
        complete.evaluation,
        laterInsufficient,
      ],
    };
    const verification = verifyReleaseValidationProofBundle(bundle);
    assert.equal(
      verification.valid,
      true,
      verification.problems.join('\n'),
    );
    const promotedAt = '2026-01-01T03:04:00Z';

    assert.throws(
      () => planReleaseValidationProofPromotion({
        bundle,
        environment: 'production',
        promotedAt,
        evaluationId: complete.evaluation.evaluationId,
        evaluationContentHash: complete.evaluation.contentHash,
        sourceProofHash,
        destinationProofHash,
      }),
      /latest evaluation receipt/,
    );
    assert.throws(
      () => planReleaseValidationProofPromotion({
        bundle,
        environment: 'production',
        promotedAt,
        evaluationId: laterInsufficient.evaluationId,
        evaluationContentHash: laterInsufficient.contentHash,
        sourceProofHash,
        destinationProofHash,
      }),
      /production promotion requires validated evidence/,
    );

    const calibration = planReleaseValidationProofPromotion({
      bundle,
      environment: 'calibration',
      promotedAt,
      evaluationId: laterInsufficient.evaluationId,
      evaluationContentHash: laterInsufficient.contentHash,
      sourceProofHash,
      destinationProofHash,
    });
    assert.equal(calibration.status, 'inserted');
    assert.equal(calibration.receipt.environment, 'calibration');
    assert.equal(
      verifyReleaseValidationProofBundle(calibration.candidate).valid,
      true,
    );
  });

  it('summarizes current validation and promotion authority without ambiguity', () => {
    const complete = fixture();
    const observedAt = '2026-01-01T03:05:00Z';
    const promoted = summarizeReleaseValidationProof(
      complete.bundle,
      observedAt,
    );
    assert.equal(promoted.status, 'production_promoted');
    assert.equal(promoted.valid, true);
    assert.equal(promoted.productionAuthorized, true);
    assert.equal(
      promoted.currentEvaluation?.evaluationId,
      complete.evaluation.evaluationId,
    );
    assert.equal(
      promoted.currentProductionPromotion?.promotionId,
      complete.promotion.promotionId,
    );

    const unpromoted = summarizeReleaseValidationProof({
      ...complete.bundle,
      promotionReceipts: [],
    }, observedAt);
    assert.equal(unpromoted.status, 'validated_not_promoted');
    assert.equal(unpromoted.productionAuthorized, false);

    const insufficient = fixture('insufficient');
    const calibrationPromotion = sealReleaseValidationPromotionReceipt({
      proofEpochId: insufficient.epoch.proofEpochId,
      epochSequence: 6,
      previousEpochContentHash: insufficient.evaluation.contentHash,
      environment: 'calibration',
      promotedAt: insufficient.promotion.promotedAt,
      evaluationId: insufficient.evaluation.evaluationId,
      evaluationContentHash: insufficient.evaluation.contentHash,
      cohortIds: insufficient.evaluation.cohortIds,
      forecastIds: [insufficient.forecast.forecastId],
      outcomeIds: [insufficient.outcome.outcomeId],
      sourceProofHash,
      destinationProofHash,
    });
    const calibration = summarizeReleaseValidationProof({
      ...insufficient.bundle,
      promotionReceipts: [calibrationPromotion],
    }, observedAt);
    assert.equal(calibration.status, 'insufficient');
    assert.equal(calibration.productionAuthorized, false);
    assert.equal(
      calibration.latestCalibrationPromotion?.promotionId,
      calibrationPromotion.promotionId,
    );
  });

  it('revokes production authority when the active cohort set advances', () => {
    const complete = fixture();
    const policy = sealReleaseValidationPolicy({
      proofEpochId: complete.epoch.proofEpochId,
      epochSequence: 7,
      previousEpochContentHash: complete.promotion.contentHash,
      policyCode: 'calibration-v2',
      policyVersion: 1,
      recordedAt: '2026-01-01T03:04:00Z',
      effectiveAt: '2026-01-01T03:04:00Z',
      developmentArm: 'calibration',
      requiredCells: [{
        opportunityCode: complete.cell.opportunityCode,
        horizonCode: complete.cell.horizonCode,
      }],
    });
    const cohort = sealReleaseValidationCohort({
      proofEpochId: complete.epoch.proofEpochId,
      epochSequence: 8,
      previousEpochContentHash: policy.contentHash,
      policyId: policy.policyId,
      policyContentHash: policy.contentHash,
      modelVersion: 'model-v2',
      promptVersion: 2,
      codeRevision: 'revision-v2',
      recordedAt: '2026-01-01T03:04:00Z',
      startsAt: '2026-01-01T03:04:00Z',
      requiredCellIds: policy.requiredCells.map((cell) => cell.cellId),
    });
    const bundle = {
      ...complete.bundle,
      policies: [...complete.bundle.policies, policy],
      cohorts: [...complete.bundle.cohorts, cohort],
    };
    const verification = verifyReleaseValidationProofBundle(bundle);
    assert.equal(verification.valid, true, verification.problems.join('\n'));

    const summary = summarizeReleaseValidationProof(
      bundle,
      '2026-01-01T03:05:00Z',
    );
    assert.equal(summary.status, 'validated_not_promoted');
    assert.equal(summary.productionAuthorized, false);
    assert.ok(summary.productionAuthorizationProblems.some((problem) =>
      /cohort set does not match/.test(problem)));
    assert.throws(
      () => planReleaseValidationProofPromotion({
        bundle,
        environment: 'production',
        promotedAt: '2026-01-01T03:05:00Z',
        evaluationId: complete.evaluation.evaluationId,
        evaluationContentHash: complete.evaluation.contentHash,
        sourceProofHash,
        destinationProofHash,
      }),
      /active cohort.*set does not match exactly/i,
    );
  });

  it('revokes production authority when cohort evidence advances', () => {
    const complete = fixture();
    const bundle = appendProspectiveAdmissionAfterPromotion(complete);
    const verification = verifyReleaseValidationProofBundle(bundle);
    assert.equal(verification.valid, true, verification.problems.join('\n'));

    const summary = summarizeReleaseValidationProof(
      bundle,
      '2026-01-01T03:13:00Z',
    );
    assert.equal(summary.status, 'validated_not_promoted');
    assert.equal(summary.productionAuthorized, false);
    assert.ok(summary.productionAuthorizationProblems.some((problem) =>
      /stale relative to cohort evidence/.test(problem)));
    assert.throws(
      () => planReleaseValidationProofPromotion({
        bundle,
        environment: 'production',
        promotedAt: '2026-01-01T03:13:00Z',
        evaluationId: complete.evaluation.evaluationId,
        evaluationContentHash: complete.evaluation.contentHash,
        sourceProofHash,
        destinationProofHash,
      }),
      /stale relative to cohort evidence/,
    );
  });
});

function fixture(
  evaluationStatus: ReleaseValidationEvaluationStatus = 'validated',
) {
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
  const release = releaseIdentity();
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
  const catalogReconciliation =
    sealReleaseValidationCatalogReconciliation({
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
    reconciliationId:
      catalogReconciliation.reconciliation.reconciliationId,
    reconciliationContentHash:
      catalogReconciliation.reconciliation.contentHash,
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
      releaseId: release.releaseId,
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
    selectedReleaseId: release.releaseId,
    forecast: {
      recommendation: 'install',
      score: 8.5,
    },
  });
  const outcome = sealReleaseValidationOutcomeV2({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 4,
    previousCohortContentHash: forecast.contentHash,
    forecastId: forecast.forecastId,
    obligationId: obligation.obligationId,
    cellId: cell.cellId,
    releaseId: release.releaseId,
    observedAt: '2026-01-01T03:00:00Z',
    status: 'safe',
    evidenceContentHashes: [evidenceHash],
    outcome: { adverseCount: 0 },
  });
  const batch = sealReleaseValidationObservationBatch({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 5,
    previousCohortContentHash: outcome.contentHash,
    observedAt: '2026-01-01T03:01:00Z',
    sourceIdentityHash,
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
    previousEpochContentHash:
      catalogReconciliation.reconciliation.contentHash,
    evaluatedAt: '2026-01-01T03:02:00Z',
    status: evaluationStatus,
    cohortIds: [cohort.cohortId],
    requiredCellKeys: [
      releaseValidationCohortCellKey(cohort.cohortId, cell.cellId),
    ],
    observationBatchIds: [batch.batchId],
    outcomeIds: [outcome.outcomeId],
    metrics: {
      accuracy: 1,
      sampleCount: 1,
    },
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
    sourceProofHash,
    destinationProofHash,
  });
  const reconciliation = catalogReconciliation.reconciliation;
  const bundle: ReleaseValidationProofBundle = {
    epochs: [epoch],
    retirements: [],
    policies: [policy],
    cohorts: [cohort],
    catalogObservations: [catalog.observation],
    catalogMembers: catalog.members,
    catalogReconciliations: [reconciliation],
    catalogReconciliationRows: catalogReconciliation.rows,
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
    cell,
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
  };
}

function appendProspectiveAdmissionAfterPromotion(
  complete: ReturnType<typeof fixture>,
): ReleaseValidationProofBundle {
  const nextRelease = releaseIdentity({
    nodeId: 'release-node-2',
    tagCommitOid: '2'.repeat(40),
    publishedAt: '2026-01-01T03:10:00Z',
    aliases: ['v2.0.0'],
  });
  const catalog = sealReleaseValidationCatalogObservation({
    proofEpochId: complete.epoch.proofEpochId,
    epochSequence: 7,
    previousEpochContentHash: complete.promotion.contentHash,
    source: 'github',
    observedAt: '2026-01-01T03:11:00Z',
    exhaustive: true,
    stabilized: true,
    releases: [complete.obligation.release, nextRelease],
  });
  const reconciliation = sealReleaseValidationCatalogReconciliation({
    proofEpochId: complete.epoch.proofEpochId,
    epochSequence: 8,
    previousEpochContentHash: catalog.observation.contentHash,
    reconciledAt: '2026-01-01T03:12:00Z',
    previousObservation: complete.catalog.observation,
    previousMembers: complete.catalog.members,
    currentObservation: catalog.observation,
    currentMembers: catalog.members,
  });
  const obligation = sealReleaseValidationObligation({
    proofEpochId: complete.epoch.proofEpochId,
    cohortId: complete.cohort.cohortId,
    cohortSequence: 6,
    previousCohortContentHash: complete.batch.contentHash,
    cellId: complete.cell.cellId,
    opportunityCode: complete.cell.opportunityCode,
    horizonCode: complete.cell.horizonCode,
    release: nextRelease,
    recordedAt: '2026-01-01T03:12:00Z',
    opensAt: '2026-01-01T06:10:00Z',
    closesAtExclusive: '2026-01-01T09:10:00Z',
    outcomeDueAt: '2026-01-04T09:10:00Z',
    catalogObservationId: catalog.observation.observationId,
    catalogObservationContentHash: catalog.observation.contentHash,
    reconciliationId: reconciliation.reconciliation.reconciliationId,
    reconciliationContentHash: reconciliation.reconciliation.contentHash,
  });
  const assignment = sealReleaseValidationSplitAssignment({
    proofEpochId: complete.epoch.proofEpochId,
    cohortId: complete.cohort.cohortId,
    cohortSequence: 7,
    previousCohortContentHash: obligation.contentHash,
    obligationId: obligation.obligationId,
    assignedAt: '2026-01-01T03:12:00Z',
    arm: 'production',
    splitPolicyHash: complete.policy.splitPolicyHash,
    seedHash: releaseValidationSplitSeedHash({
      proofEpochId: complete.epoch.proofEpochId,
      cohortId: complete.cohort.cohortId,
      releaseId: nextRelease.releaseId,
      admissionOrdinal: 2,
      splitPolicyHash: complete.policy.splitPolicyHash,
    }),
  });
  return {
    ...complete.bundle,
    catalogObservations: [
      ...complete.bundle.catalogObservations,
      catalog.observation,
    ],
    catalogMembers: [...complete.bundle.catalogMembers, ...catalog.members],
    catalogReconciliations: [
      ...complete.bundle.catalogReconciliations,
      reconciliation.reconciliation,
    ],
    catalogReconciliationRows: [
      ...complete.bundle.catalogReconciliationRows,
      ...reconciliation.rows,
    ],
    obligations: [...complete.bundle.obligations, obligation],
    splitAssignments: [...complete.bundle.splitAssignments, assignment],
  };
}

function releaseIdentity(overrides: {
  nodeId?: string;
  tagCommitOid?: string;
  publishedAt?: string;
  aliases?: readonly string[];
} = {}) {
  return createReleaseValidationStableReleaseIdentity({
    repository,
    nodeId: overrides.nodeId ?? 'release-node-1',
    tagCommitOid: overrides.tagCommitOid ?? '1'.repeat(40),
    publishedAt: overrides.publishedAt ?? '2026-01-01T00:01:00Z',
    aliases: overrides.aliases ?? ['v1.0.0'],
  });
}
