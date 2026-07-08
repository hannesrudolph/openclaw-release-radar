import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  releaseValidationCohortCellKey,
  sealReleaseValidationForecastV2,
  sealReleaseValidationObservationBatch,
  sealReleaseValidationOutcomeV2,
  sealReleaseValidationProofEpochRetirement,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';
import {
  DEFAULT_VALIDATION_QUALITY_CRITERIA,
  DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
} from './releaseValidation.ts';
import {
  buildReleaseArtifactPublication,
} from './releaseArtifactPublication.ts';
import {
  scoreSourceIdentityManifestDigest,
} from './scoreSourceIdentity.ts';
import {
  planReleaseValidationProofEvaluation,
} from './releaseValidationProofEvaluation.ts';
import {
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownedTestDir = assignedWorkerDatabasePath === null
  ? mkdtempSync(join(tmpdir(), 'radar-validation-proof-evaluation-'))
  : null;
const databasePath = assignedWorkerDatabasePath ??
  join(ownedTestDir!, 'radar.db');
if (assignedWorkerDatabasePath) {
  assert.equal(
    process.env.DB_PATH,
    assignedWorkerDatabasePath,
    'release validation proof evaluation tests must use their assigned worker database',
  );
  assert.ok(
    process.env.DOTENV_CONFIG_PATH,
    'release validation proof evaluation tests require the runner-assigned empty dotenv path',
  );
} else {
  const emptyDotenvPath = join(ownedTestDir!, '.env.empty');
  process.env.DB_PATH = databasePath;
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
  writeFileSync(emptyDotenvPath, '');
}

let databaseModule: typeof import('./db.ts');

before(async () => {
  databaseModule = await import(
    `./db.ts?validation-proof-evaluation-${Date.now()}-${Math.random()}`
  );
});

after(() => {
  databaseModule?.db.close();
  if (ownedTestDir !== null) {
    rmSync(ownedTestDir, { recursive: true, force: true });
  }
});

describe('canonical release validation evaluation receipts', () => {
  it('binds every active cohort, required cell, batch, and outcome exactly', () => {
    const fixture = evaluationFixture();
    const plan = planReleaseValidationProofEvaluation({
      bundle: fixture.bundle,
      evaluatedAt: fixture.evaluatedAt,
      status: 'insufficient',
      metrics: fixture.metrics,
    });

    assert.equal(plan.status, 'inserted');
    assert.deepEqual(plan.receipt.cohortIds, [fixture.cohortId]);
    assert.equal(
      plan.receipt.requiredCellCount,
      fixture.requiredCellCount,
    );
    assert.deepEqual(plan.receipt.observationBatchIds, [fixture.batchId]);
    assert.deepEqual(plan.receipt.outcomeIds, fixture.outcomeIds);
    assert.equal(
      plan.coverage.authoritativeOpportunityCount,
      fixture.bundle.obligations.length,
    );
    assert.equal(
      plan.coverage.evaluatedOpportunityCount,
      fixture.bundle.obligations.length,
    );
    assert.equal(plan.coverage.observedOpportunityCount,
      fixture.bundle.obligations.length);
    assert.equal(plan.coverage.excludedOpportunityCount, 0);
    assert.equal(plan.coverage.pendingOpportunityCount, 0);
    assert.equal(plan.coverage.missingOpportunityCount, 0);
    assert.equal(
      verifyReleaseValidationProofBundle(plan.candidate).valid,
      true,
    );

    const retry = planReleaseValidationProofEvaluation({
      bundle: plan.candidate,
      evaluatedAt: fixture.evaluatedAt,
      status: 'insufficient',
      metrics: fixture.metrics,
    });
    assert.equal(retry.status, 'already_captured');
    assert.deepEqual(retry.append.evaluationReceipts, []);
    assert.equal(retry.receipt.evaluationId, plan.receipt.evaluationId);

    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: plan.candidate,
        evaluatedAt: fixture.evaluatedAt,
        status: 'insufficient',
        metrics: {
          ...fixture.metrics,
          failureClass: 'different_retry',
        },
      }),
      /differs from its exact retry/,
    );
  });

  it('rolls canonical evaluation persistence back with its outer transaction', () => {
    const fixture = evaluationFixture();
    databaseModule.appendReleaseValidationProof(fixture.bundle);
    const plan = planReleaseValidationProofEvaluation({
      bundle: databaseModule.readReleaseValidationProofBundle(),
      evaluatedAt: fixture.evaluatedAt,
      status: 'insufficient',
      metrics: fixture.metrics,
    });

    assert.throws(
      () => databaseModule.runInWriteTransaction(() => {
        databaseModule.appendReleaseValidationProof(plan.append);
        throw new Error('rollback canonical evaluation');
      }),
      /rollback canonical evaluation/,
    );
    assert.equal(
      databaseModule.readReleaseValidationProofBundle()
        .evaluationReceipts.length,
      0,
    );

    const persisted = databaseModule.appendReleaseValidationProof(plan.append);
    assert.equal(persisted.insertedByType.evaluationReceipts, 1);
    assert.equal(persisted.verification.valid, true);
    const stored = persisted.bundle.evaluationReceipts[0];
    assert.equal(stored.evaluationId, plan.receipt.evaluationId);

    const retry = planReleaseValidationProofEvaluation({
      bundle: persisted.bundle,
      evaluatedAt: fixture.evaluatedAt,
      status: 'insufficient',
      metrics: fixture.metrics,
    });
    const equivalent = databaseModule.appendReleaseValidationProof(
      retry.append,
    );
    assert.equal(retry.status, 'already_captured');
    assert.equal(equivalent.insertedCount, 0);
  });

  it('keeps historical retries active until the epoch retirement time', () => {
    const fixture = evaluationFixture();
    const initial = planReleaseValidationProofEvaluation({
      bundle: fixture.bundle,
      evaluatedAt: fixture.evaluatedAt,
      status: 'insufficient',
      metrics: fixture.metrics,
    });
    const epoch = initial.candidate.epochs[0];
    assert.ok(epoch);
    const verification = verifyReleaseValidationProofBundle(
      initial.candidate,
    );
    assert.equal(verification.valid, true, verification.problems.join('; '));
    const recordedAt = new Date(
      Date.parse(fixture.evaluatedAt) + 1_000,
    ).toISOString();
    const retiredAt = new Date(
      Date.parse(recordedAt) + 1_000,
    ).toISOString();
    const retirement = sealReleaseValidationProofEpochRetirement({
      proofEpochId: epoch.proofEpochId,
      epochContentHash: epoch.contentHash,
      epochSequence: initial.receipt.epochSequence + 1,
      previousEpochContentHash:
        verification.epochChainTips[epoch.proofEpochId] ?? null,
      recordedAt,
      retiredAt,
      reason: 'test future-effective retirement',
    });
    const retiredBundle = {
      ...initial.candidate,
      retirements: [retirement],
    };
    const retiredVerification =
      verifyReleaseValidationProofBundle(retiredBundle);
    assert.equal(
      retiredVerification.valid,
      true,
      retiredVerification.problems.join('; '),
    );

    const retry = planReleaseValidationProofEvaluation({
      bundle: retiredBundle,
      evaluatedAt: fixture.evaluatedAt,
      status: 'insufficient',
      metrics: fixture.metrics,
    });
    assert.equal(retry.status, 'already_captured');
    assert.equal(retry.receipt.evaluationId, initial.receipt.evaluationId);

    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: retiredBundle,
        evaluatedAt: retiredAt,
        status: 'insufficient',
        metrics: {
          ...fixture.metrics,
          generatedAt: retiredAt,
        },
      }),
      /exactly one active proof epoch with active cohorts; found 0/,
    );
  });

  it('rejects validated status when prospective authorization is insufficient or false', () => {
    const fixture = evaluationFixture();
    const metrics = validatedMetrics(fixture);

    for (const mutation of [
      {
        prospectiveEvaluation: {
          ...metrics.prospectiveEvaluation,
          proofComplete: false,
          promotionDecision: {
            ...metrics.prospectiveEvaluation.promotionDecision,
            decision: 'deny_production',
            productionAuthorized: false,
            status: 'insufficient',
            failureClass: 'production_cohort_incomplete',
          },
        },
      },
      {
        prospectiveEvaluation: {
          ...metrics.prospectiveEvaluation,
          proofVerification: {
            valid: false,
            problems: ['fabricated prospective failure'],
          },
          promotionDecision: {
            ...metrics.prospectiveEvaluation.promotionDecision,
            decision: 'deny_production',
            productionAuthorized: false,
            status: 'failed',
            failureClass: 'canonical_proof_integrity',
          },
        },
      },
      {
        prospectiveEvaluation: {
          ...metrics.prospectiveEvaluation,
          promotionDecision: {
            ...metrics.prospectiveEvaluation.promotionDecision,
            productionAuthorized: false,
          },
        },
      },
      {
        promotionDecision: {
          ...metrics.promotionDecision,
          productionAuthorized: false,
        },
      },
    ]) {
      assert.throws(
        () => planReleaseValidationProofEvaluation({
          bundle: fixture.bundle,
          evaluatedAt: fixture.evaluatedAt,
          status: 'validated',
          metrics: { ...metrics, ...mutation },
        }),
        /not production-authorized/,
      );
    }

    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: fixture.bundle,
        evaluatedAt: fixture.evaluatedAt,
        status: 'validated',
        metrics: {
          ...metrics,
          forecastLedgerRowCount: metrics.forecastLedgerRowCount + 1,
        },
      }),
      /forecast population accounting/,
    );
  });

  it('rejects receiptless non-refresh score publication authorization', () => {
    const fixture = evaluationFixture({
      mutateAuthorization: (authorization) => ({
        ...authorization,
        source: 'api-test',
        operationReceiptRequired: false,
        terminalReceipt: null,
      }),
    });

    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: fixture.bundle,
        evaluatedAt: fixture.evaluatedAt,
        status: 'validated',
        metrics: validatedMetrics(fixture),
      }),
      /authorization source must equal refresh/,
    );
  });

  it('rejects artifact publication fallback drift absent from source identity', () => {
    const fixture = evaluationFixture({
      mutateAuthorization: (authorization) => {
        const publication = authorization.releaseArtifacts as ReturnType<
          typeof buildReleaseArtifactPublication
        >;
        const original = publication.links[0];
        assert.ok(original);
        const fallback = {
          ...original,
          release: {
            ...original.release,
            tag: 'v-fallback-drift',
            releaseNodeId: 'R_fallback_drift',
            catalogTagCommitOid: 'f'.repeat(40),
          },
          observationId: `artifact-observation-v1:${'8'.repeat(64)}`,
          observationContentHash: '9'.repeat(64),
          receiptId: `artifact-receipt-v2:${'c'.repeat(64)}`,
          receiptContentHash: 'b'.repeat(64),
          evidenceIdentity: 'c'.repeat(64),
          evidenceReportIdentity:
            `release-evidence-v1:sha256:${'d'.repeat(64)}`,
        };
        return {
          ...authorization,
          releaseArtifacts: buildReleaseArtifactPublication([
            original,
            fallback,
          ]),
        };
      },
    });

    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: fixture.bundle,
        evaluatedAt: fixture.evaluatedAt,
        status: 'validated',
        metrics: validatedMetrics(fixture),
      }),
      /artifact publication is not exactly represented in source identity/,
    );
  });

  it('rejects incomplete required-cell evidence and under-threshold evidence', () => {
    const incomplete = evaluationFixture({
      limitEvidenceToFirstObligation: true,
    });
    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: incomplete.bundle,
        evaluatedAt: incomplete.evaluatedAt,
        status: 'validated',
        metrics: validatedMetrics(incomplete),
      }),
      /forecast for obligation .* must exist exactly once; found 0/,
    );

    const underThreshold = evaluationFixture();
    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: underThreshold.bundle,
        evaluatedAt: underThreshold.evaluatedAt,
        status: 'validated',
        metrics: validatedMetrics(underThreshold),
      }),
      /has 1 independent evidence; .* required/,
    );
  });

});

function evaluationFixture(options: {
  mutateAuthorization?: (
    authorization: Record<string, unknown>,
  ) => Record<string, unknown>;
  limitEvidenceToFirstObligation?: boolean;
} = {}) {
  const repository = 'openclaw/openclaw';
  const publishedAt = '2026-01-01T00:00:00.000Z';
  const lifecycle = planReleaseValidationProofLifecycle({
    existing: emptyProofBundle(),
    repository,
    observedAt: publishedAt,
    source: 'evaluation-fixture-catalog',
    releases: [{
      repository,
      nodeId: 'R_evaluation_fixture',
      tagCommitOid: 'a'.repeat(40),
      publishedAt,
      aliases: ['v-evaluation'],
    }],
    modelVersion: 'model-evaluation',
    promptVersion: 9,
    codeRevision: 'evaluation-revision',
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
  });
  const obligation = lifecycle.bundle.obligations[0];
  const cohort = lifecycle.bundle.cohorts.find((row) =>
    row.cohortId === obligation.cohortId);
  assert.ok(cohort);
  let sequence = Math.max(
    0,
    ...[
      ...lifecycle.bundle.obligations,
      ...lifecycle.bundle.splitAssignments,
    ].map((row) => row.cohortSequence),
  );
  let tip =
    lifecycle.verification.cohortChainTips[cohort.cohortId] ?? null;
  const observedAt = new Date(
    Math.max(...lifecycle.bundle.obligations.map((row) =>
      Date.parse(row.outcomeDueAt))) + 1,
  ).toISOString();
  const forecasts: ReleaseValidationProofBundle['forecasts'][number][] = [];
  const outcomes: ReleaseValidationProofBundle['outcomes'][number][] = [];
  const authorizationReports: Array<Record<string, unknown>> = [];
  const evidenceObligations = options.limitEvidenceToFirstObligation
    ? lifecycle.bundle.obligations.slice(0, 1)
    : lifecycle.bundle.obligations;
  for (const [index, currentObligation] of
    evidenceObligations.entries()) {
    const currentAssignment = lifecycle.bundle.splitAssignments.find((row) =>
      row.obligationId === currentObligation.obligationId);
    assert.ok(currentAssignment);
    const scorePublication = scorePublicationFixture(
      currentObligation.release,
    );
    const authorization = options.mutateAuthorization
      ? options.mutateAuthorization(scorePublication.authorization)
      : scorePublication.authorization;
    const decisionId = `legacy-evaluation-decision-${index}`;
    const legacyContentHash = createHash('sha256')
      .update(decisionId)
      .digest('hex');
    const forecast = sealReleaseValidationForecastV2({
      proofEpochId: cohort.proofEpochId,
      cohortId: cohort.cohortId,
      cohortSequence: ++sequence,
      previousCohortContentHash: tip,
      obligationId: currentObligation.obligationId,
      splitAssignmentId: currentAssignment.assignmentId,
      policyId: cohort.policyId,
      policyContentHash: cohort.policyContentHash,
      recordedAt: currentObligation.opensAt,
      latestRelease: currentObligation.release,
      candidates: [currentObligation.release],
      selectedReleaseId: currentObligation.release.releaseId,
      forecast: {
        schemaVersion: 1,
        legacyForecast: {
          decisionId,
          contentHash: legacyContentHash,
        },
        originalScorePublication: {
          scoreCommit: scorePublication.scoreCommit,
          sourceIdentity: scorePublication.sourceIdentity,
          authorization,
        },
        canonicalCapturePublication: scorePublication.capturePublication,
      },
    });
    forecasts.push(forecast);
    authorizationReports.push(scorePublicationAuthorizationReport(
      forecast,
      authorization,
      scorePublication.sourceIdentity,
    ));
    tip = forecast.contentHash;
  }
  for (const [index, currentObligation] of
    evidenceObligations.entries()) {
    const forecast = forecasts[index]!;
    const decisionId = `legacy-evaluation-decision-${index}`;
    const legacyContentHash = createHash('sha256')
      .update(decisionId)
      .digest('hex');
    const evidenceContentHash = createHash('sha256')
      .update(`evidence:${decisionId}`)
      .digest('hex');
    const outcome = sealReleaseValidationOutcomeV2({
      proofEpochId: cohort.proofEpochId,
      cohortId: cohort.cohortId,
      cohortSequence: ++sequence,
      previousCohortContentHash: tip,
      forecastId: forecast.forecastId,
      obligationId: currentObligation.obligationId,
      cellId: currentObligation.cellId,
      releaseId: currentObligation.release.releaseId,
      observedAt,
      status: 'safe',
      evidenceContentHashes: [evidenceContentHash],
      outcome: {
        schemaVersion: 1,
        legacyForecast: {
          decisionId,
          contentHash: legacyContentHash,
        },
        legacyObservation: {
          observationId: `legacy-evaluation-observation-${index}`,
          contentHash: evidenceContentHash,
          status: 'matured',
          observedAt,
          adverse: false,
        },
      },
    });
    outcomes.push(outcome);
    tip = outcome.contentHash;
  }
  const batch = sealReleaseValidationObservationBatch({
    proofEpochId: cohort.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: ++sequence,
    previousCohortContentHash: tip,
    observedAt,
    sourceIdentityHash: 'd'.repeat(64),
    expectedObligationIds: forecasts.map((forecast) =>
      forecast.obligationId),
    cells: forecasts.map((forecast, index) => ({
      obligationId: forecast.obligationId,
      forecastId: forecast.forecastId,
      outcomeId: outcomes[index]!.outcomeId,
      disposition: 'observed',
    })),
  });
  const bundle = {
    ...lifecycle.bundle,
    forecasts,
    outcomes,
    observationBatches: [batch],
  };
  const verification = verifyReleaseValidationProofBundle(bundle);
  assert.equal(verification.valid, true, verification.problems.join('; '));
  const evaluatedAt = new Date(Date.parse(observedAt) + 1).toISOString();
  return {
    bundle,
    evaluatedAt,
    cohortId: cohort.cohortId,
    requiredCellCount: cohort.requiredCellCount,
    batchId: batch.batchId,
    outcomeIds: outcomes.map((outcome) => outcome.outcomeId),
    authorizationReports,
    metrics: {
      schemaVersion: 4,
      generatedAt: evaluatedAt,
      status: 'insufficient' as const,
      failureClass: 'sample_or_power',
      errors: [],
    },
  };
}

function validatedMetrics(fixture: ReturnType<typeof evaluationFixture>) {
  const proofEpochIds = [...new Set(
    fixture.bundle.cohorts.map((cohort) => cohort.proofEpochId),
  )];
  const cohortIds = fixture.bundle.cohorts.map((cohort) => cohort.cohortId);
  const requiredCellKeys = fixture.bundle.cohorts.flatMap((cohort) =>
    cohort.requiredCellIds.map((cellId) =>
      releaseValidationCohortCellKey(cohort.cohortId, cellId)));
  const promotionDecision = {
    decision: 'authorize_production',
    productionAuthorized: true,
    insufficientAuthorizesProduction: false,
    calibrationAuthorizesProduction: false,
    status: 'passed',
    failureClass: null,
  };
  return {
    schemaVersion: 4,
    generatedAt: fixture.evaluatedAt,
    status: 'validated' as const,
    failureClass: null,
    errors: [],
    thresholds: DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
    qualityCriteria: DEFAULT_VALIDATION_QUALITY_CRITERIA,
    forecastLedgerRowCount: fixture.bundle.forecasts.length,
    eligibleForecastCount: fixture.bundle.forecasts.length,
    excludedForecastCount: 0,
    excludedForecasts: [],
    decisionLevelForecastCount: fixture.bundle.forecasts.length,
    outcomeLedgerRowCount: fixture.bundle.outcomes.length,
    opportunityDenominator: {
      present: true,
      valid: true,
      ready: true,
      currentStratumKey: 'model-evaluation/prompt-9/revision-evaluation-revision',
      sourcePolicy:
        'prospective_append_only_release_catalog_enrollment_v2',
      contentHash: 'a'.repeat(64),
      rowCount: fixture.bundle.forecasts.length,
      capturedCount: fixture.bundle.forecasts.length,
      upcomingCount: 0,
      eligibleCount: 0,
      failedCount: 0,
      missedCount: 0,
      terminalCount: fixture.bundle.forecasts.length,
      unmatchedForecastCount: 0,
      integrityErrorCount: 0,
      errors: [],
      rows: fixture.bundle.forecasts.map((forecast, index) => ({
        opportunityId: createHash('sha256')
          .update(`denominator:${forecast.forecastId}`)
          .digest('hex'),
        stateContentHash: createHash('sha256')
          .update(`denominator-state:${forecast.forecastId}`)
          .digest('hex'),
        disposition: 'captured',
        terminal: true,
        capturedDecisionId: `legacy-evaluation-decision-${index}`,
        capturedContentHash: createHash('sha256')
          .update(`legacy-evaluation-decision-${index}`)
          .digest('hex'),
      })),
    },
    currentStratum: {
      status: 'validated',
      failureClass: null,
      sampleSufficient: true,
      qualityPassed: true,
      policyGateStatus: 'passed',
      candidateScoreGateStatus: 'passed',
    },
    prospectiveEvaluation: {
      schemaVersion: 2,
      authority: 'canonical_release_validation_proof',
      evaluationPurpose: 'production',
      evaluatedAt: fixture.evaluatedAt,
      proofComplete: true,
      proofVerification: {
        valid: true,
        problems: [],
      },
      activeProofEpochIds: proofEpochIds,
      activeCohortIds: cohortIds,
      requiredCellKeys,
      observationBatchIds:
        fixture.bundle.observationBatches.map((batch) => batch.batchId),
      outcomeIds: fixture.bundle.outcomes.map((outcome) => outcome.outcomeId),
      scorePublicationAuthorizations: fixture.authorizationReports,
      splitAssignments: {
        source: 'canonical_obligation_assignments',
        persisted: true,
        expectedAssignmentCount: 1,
        persistedAssignmentCount: 1,
        missingAssignmentKeys: [],
        extraAssignmentKeys: [],
        errors: [],
      },
      productionSummary: {
        activeCohortCount: cohortIds.length,
        productionCohortCount: cohortIds.length,
        calibrationCohortCount: 0,
        currentStratumCohortCount: cohortIds.length,
        everyActiveCohortPassed: true,
        calibrationExcludedFromAuthorization: true,
      },
      cohorts: [],
      promotionDecision,
    },
    promotionDecision,
  };
}

function scorePublicationFixture(
  release: ReleaseValidationProofBundle['obligations'][number]['release'],
) {
  const operationRunId = 'evaluation-refresh-run';
  const historyRunId = 'refresh:evaluation-refresh-run';
  const historyRunContentHash = '1'.repeat(64);
  const authorityRunId = 'score-authority:refresh:evaluation-refresh-run';
  const authorityRunContentHash = '2'.repeat(64);
  const historyV2SealContentHash = '3'.repeat(64);
  const releaseArtifact = {
    repository: release.repository,
    tag: release.aliases[0] ?? 'v-evaluation',
    releaseNodeId: release.nodeId,
    catalogTagCommitOid: release.tagCommitOid,
    publishedAt: release.publishedAt,
  };
  const publicationLink = {
    release: releaseArtifact,
    observationId: `artifact-observation-v1:${'4'.repeat(64)}`,
    observationContentHash: '5'.repeat(64),
    receiptId: `artifact-receipt-v2:${'8'.repeat(64)}`,
    receiptContentHash: '7'.repeat(64),
    evidenceIdentity: '8'.repeat(64),
    evidenceReportIdentity:
      `release-evidence-v1:sha256:${'9'.repeat(64)}`,
  };
  const releaseArtifacts = buildReleaseArtifactPublication([publicationLink]);
  const releaseArtifactReceipts = [{
    release: releaseArtifact,
    receiptId: publicationLink.receiptId,
    evidenceIdentity: publicationLink.evidenceIdentity,
    evidenceReportIdentity: publicationLink.evidenceReportIdentity,
    canonicalReceiptJson: JSON.stringify({ schemaVersion: 2 }),
  }];
  const artifactSource = {
    source: 'release_artifact_receipts' as const,
    count: 1,
    digest: releaseArtifactSemanticSourceDigest(releaseArtifactReceipts),
  };
  const effectiveScoringConfig = {
    schemaVersion: 1 as const,
    repository: { owner: 'openclaw', repo: 'openclaw' },
    monitoredReleaseLimit: 20,
    recommendation: {
      policyCode: 'highest_confidence_with_recency_tolerance' as const,
      threshold: 0.5,
      recencyTolerance: 0.05,
    },
  };
  const effectiveScoringConfigDigest = createHash('sha256')
    .update(JSON.stringify(effectiveScoringConfig))
    .digest('hex');
  const sourceIdentity = {
    schemaVersion: 17 as const,
    sourceMode: 'current_db' as const,
    scope: 'score_input_database' as const,
    algorithm: 'sha256' as const,
    codeRevision: 'evaluation-revision',
    effectiveScoringConfig,
    effectiveScoringConfigDigest,
    rowCount: 1,
    sourceCount: 1,
    digest: '',
    sources: [artifactSource],
  };
  sourceIdentity.digest = scoreSourceIdentityManifestDigest(
    sourceIdentity.sources,
    17,
    {
      codeRevision: sourceIdentity.codeRevision,
      effectiveScoringConfig,
      effectiveScoringConfigDigest,
    },
  );
  const scoreCommit = {
    schemaVersion: 4,
    historyRunId,
    historyRunContentHash,
    authorityRunId,
    authorityRunContentHash,
    historyV2SealContentHash,
  };
  const capturePublication = {
    historyRunId,
    historyRunContentHash,
    authorityRunId,
    authorityRunContentHash,
    historyV2SealContentHash,
  };
  const authorization = {
    schemaVersion: 1,
    source: 'refresh',
    operationReceiptRequired: true,
    operationRunId,
    artifactPublicationRunId: operationRunId,
    terminalReceipt: {
      receiptId: 'evaluation-refresh-receipt',
      runId: operationRunId,
      status: 'success',
      contentHash: 'a'.repeat(64),
    },
    scoreHistory: {
      runId: historyRunId,
      contentHash: historyRunContentHash,
    },
    scoreAuthority: {
      runId: authorityRunId,
      contentHash: authorityRunContentHash,
      historyV2SealContentHash,
    },
    releaseArtifacts,
    releaseArtifactReceipts,
  };
  return {
    scoreCommit,
    capturePublication,
    sourceIdentity,
    authorization,
  };
}

function scorePublicationAuthorizationReport(
  forecast: ReleaseValidationProofBundle['forecasts'][number],
  authorization: Record<string, unknown>,
  sourceIdentity: Record<string, unknown>,
) {
  const payload = forecast.forecast as unknown as Record<string, unknown>;
  const legacy = payload.legacyForecast as Record<string, unknown>;
  return {
    forecastId: forecast.forecastId,
    forecastContentHash: forecast.contentHash,
    decisionId: legacy.decisionId,
    legacyForecastContentHash: legacy.contentHash,
    sourceIdentity,
    ...authorization,
  };
}

function releaseArtifactSemanticSourceDigest(
  receipts: Array<Record<string, unknown>>,
): string {
  const columns = [
    'release',
    'receiptId',
    'evidenceIdentity',
    'evidenceReportIdentity',
    'canonicalReceiptJson',
  ] as const;
  const hash = createHash('sha256');
  const update = (value: readonly unknown[]) => {
    hash.update(JSON.stringify(value));
    hash.update('\n');
  };
  update([
    'source_columns',
    'release_artifact_receipts',
    'semantic_release_artifact_receipts',
    columns,
  ]);
  update([
    'source_order',
    'release_artifact_receipts',
    'semantic_release_artifact_receipts',
    ['release.repository', 'release.tag', 'release.releaseNodeId'],
  ]);
  for (const receipt of receipts) {
    const release = receipt.release as Record<string, unknown>;
    update([
      'row',
      'release_artifact_receipts',
      'semantic_release_artifact_receipts',
      columns.map((column) =>
        column === 'release'
          ? {
              repository: release.repository,
              tag: release.tag,
              releaseNodeId: release.releaseNodeId,
              catalogTagCommitOid: release.catalogTagCommitOid,
              publishedAt: release.publishedAt,
            }
          : receipt[column]),
    ]);
  }
  return hash.digest('hex');
}

function emptyProofBundle(): ReleaseValidationProofBundle {
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
