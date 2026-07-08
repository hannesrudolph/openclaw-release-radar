import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  sealReleaseValidationForecastV2,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';
import {
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle.ts';
import {
  planReleaseValidationProofObservation,
} from './releaseValidationProofObservation.ts';

describe('canonical release validation observations', () => {
  it('seals exact safe/censored outcomes and one complete cohort batch', () => {
    const fixture = observationFixture();
    const plan = planReleaseValidationProofObservation({
      bundle: fixture.bundle,
      observedAt: fixture.observedAt,
      sourceIdentityHash: fixture.sourceIdentityHash,
      legacyForecasts: [fixture.legacyForecast],
      legacyOutcomes: fixture.legacyOutcomes,
    });

    assert.deepEqual(
      plan.append.outcomes.map((row) => row.status),
      ['safe', 'censored'],
    );
    assert.equal(plan.append.observationBatches.length, 1);
    assert.ok(plan.append.observationBatches[0].cells.every((cell) =>
      cell.disposition === 'observed' && cell.outcomeId));
    assert.equal(plan.captures[0].insertedOutcomeIds.length, 2);
    assert.equal(plan.captures[0].pendingForecastIds.length, 0);
    assert.equal(plan.coverage.authoritativeOpportunityCount, 4);
    assert.equal(plan.coverage.observedOpportunityCount, 2);
    assert.equal(plan.coverage.evaluatedOpportunityCount, 1);
    assert.equal(plan.coverage.excludedOpportunityCount, 1);
    assert.equal(plan.coverage.pendingOpportunityCount, 0);
    assert.equal(plan.coverage.missingOpportunityCount, 2);
    assert.equal(
      verifyReleaseValidationProofBundle(plan.candidate).valid,
      true,
    );

    const retry = planReleaseValidationProofObservation({
      bundle: plan.candidate,
      observedAt: fixture.observedAt,
      sourceIdentityHash: fixture.sourceIdentityHash,
      legacyForecasts: [fixture.legacyForecast],
      legacyOutcomes: fixture.legacyOutcomes,
    });
    assert.deepEqual(retry.append.outcomes, []);
    assert.deepEqual(retry.append.observationBatches, []);
    assert.equal(retry.captures[0].status, 'already_captured');
    assert.deepEqual(
      retry.captures[0].observedOutcomeIds,
      plan.captures[0].observedOutcomeIds,
    );
  });

  it('records a complete pending batch before canonical outcomes are due', () => {
    const fixture = observationFixture();
    const earliestDueAt = Math.min(...fixture.obligations.map((row) =>
      Date.parse(row.outcomeDueAt)));
    const plan = planReleaseValidationProofObservation({
      bundle: fixture.bundle,
      observedAt: new Date(earliestDueAt - 1).toISOString(),
      sourceIdentityHash: fixture.sourceIdentityHash,
      legacyForecasts: [fixture.legacyForecast],
      legacyOutcomes: fixture.legacyOutcomes,
    });

    assert.deepEqual(plan.append.outcomes, []);
    assert.equal(plan.append.observationBatches.length, 1);
    assert.ok(plan.append.observationBatches[0].cells.every((cell) =>
      cell.disposition === 'pending' && cell.outcomeId == null));
    assert.equal(plan.captures[0].pendingForecastIds.length, 2);
    assert.equal(plan.coverage.authoritativeOpportunityCount, 4);
    assert.equal(plan.coverage.observedOpportunityCount, 0);
    assert.equal(plan.coverage.pendingOpportunityCount, 2);
    assert.equal(plan.coverage.missingOpportunityCount, 2);
    assert.equal(
      verifyReleaseValidationProofBundle(plan.candidate).valid,
      true,
    );
  });

  it('keeps nonterminal indeterminate evidence pending until maturation', () => {
    const fixture = observationFixture();
    const nonterminal = {
      ...fixture.legacyOutcomes[1],
      outcome_json:
        '{"schemaVersion":1,"reason":"insufficient_evidence","terminal":false}',
    };
    const pendingPlan = planReleaseValidationProofObservation({
      bundle: fixture.bundle,
      observedAt: fixture.observedAt,
      sourceIdentityHash: fixture.sourceIdentityHash,
      legacyForecasts: [fixture.legacyForecast],
      legacyOutcomes: [fixture.legacyOutcomes[0], nonterminal],
    });

    const pendingForecast = fixture.bundle.forecasts.find((row) =>
      row.obligationId === fixture.obligations[1].obligationId);
    assert.ok(pendingForecast);
    assert.deepEqual(
      pendingPlan.append.outcomes.map((row) => row.status),
      ['safe'],
    );
    assert.deepEqual(
      pendingPlan.captures[0].pendingForecastIds,
      [pendingForecast.forecastId],
    );

    const maturedAt = new Date(
      Date.parse(fixture.observedAt) + 1_000,
    ).toISOString();
    const matured = {
      ...nonterminal,
      observation_id: 'legacy-observation-1-matured',
      observed_at: maturedAt,
      status: 'matured',
      outcome_json: '{"schemaVersion":1,"adverse":true}',
      content_hash: 'f'.repeat(64),
    };
    const maturedPlan = planReleaseValidationProofObservation({
      bundle: pendingPlan.candidate,
      observedAt: maturedAt,
      sourceIdentityHash: fixture.sourceIdentityHash,
      legacyForecasts: [fixture.legacyForecast],
      legacyOutcomes: [
        fixture.legacyOutcomes[0],
        nonterminal,
        matured,
      ],
    });

    assert.equal(maturedPlan.append.outcomes.length, 1);
    assert.equal(
      maturedPlan.append.outcomes[0].forecastId,
      pendingForecast.forecastId,
    );
    assert.equal(maturedPlan.append.outcomes[0].status, 'adverse');
    assert.deepEqual(
      maturedPlan.append.outcomes[0].evidenceContentHashes,
      [matured.content_hash],
    );
    assert.deepEqual(maturedPlan.captures[0].pendingForecastIds, []);
    assert.equal(
      verifyReleaseValidationProofBundle(maturedPlan.candidate).valid,
      true,
    );

    const historicalRetry = planReleaseValidationProofObservation({
      bundle: maturedPlan.candidate,
      observedAt: fixture.observedAt,
      sourceIdentityHash: fixture.sourceIdentityHash,
      legacyForecasts: [fixture.legacyForecast],
      legacyOutcomes: [
        fixture.legacyOutcomes[0],
        nonterminal,
        matured,
      ],
    });
    assert.equal(historicalRetry.captures[0].status, 'already_captured');
    assert.deepEqual(
      historicalRetry.captures[0].pendingForecastIds,
      [pendingForecast.forecastId],
    );
  });

  it('rejects canonical outcomes that cannot bind the exact legacy forecast', () => {
    const fixture = observationFixture();
    assert.throws(
      () => planReleaseValidationProofObservation({
        bundle: fixture.bundle,
        observedAt: fixture.observedAt,
        sourceIdentityHash: fixture.sourceIdentityHash,
        legacyForecasts: [{
          ...fixture.legacyForecast,
          content_hash: 'f'.repeat(64),
        }],
        legacyOutcomes: fixture.legacyOutcomes,
      }),
      /does not have its exact legacy forecast evidence/,
    );
  });
});

function observationFixture() {
  const publishedAt = '2026-01-01T00:00:00.000Z';
  const repository = 'openclaw/openclaw';
  const release = {
    repository,
    nodeId: 'R_observation_fixture',
    tagCommitOid: 'a'.repeat(40),
    publishedAt,
    aliases: ['v-observation'],
  };
  const lifecycle = planReleaseValidationProofLifecycle({
    existing: emptyProofBundle(),
    repository,
    observedAt: publishedAt,
    source: 'observation-fixture-catalog',
    releases: [release],
    modelVersion: 'model-observation',
    promptVersion: 7,
    codeRevision: 'observation-revision',
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
  });
  const obligations = lifecycle.bundle.obligations
    .filter((row) => row.opportunityCode === 'first_verified_after_3h')
    .sort((left, right) => left.horizonCode.localeCompare(right.horizonCode));
  assert.equal(obligations.length, 2);
  let sequence = Math.max(
    0,
    ...[
      ...lifecycle.bundle.obligations,
      ...lifecycle.bundle.splitAssignments,
    ].map((row) => row.cohortSequence),
  );
  let tip =
    lifecycle.verification.cohortChainTips[lifecycle.cohort.cohortId] ?? null;
  const legacyForecast = {
    decision_id: 'legacy-observation-decision',
    content_hash: 'b'.repeat(64),
    opportunity_code: 'first_verified_after_3h',
    recorded_at: obligations[0].opensAt,
  } as any;
  const forecasts = obligations.map((obligation) => {
    const assignment = lifecycle.bundle.splitAssignments.find((row) =>
      row.obligationId === obligation.obligationId);
    assert.ok(assignment);
    const forecast = sealReleaseValidationForecastV2({
      proofEpochId: lifecycle.cohort.proofEpochId,
      cohortId: lifecycle.cohort.cohortId,
      cohortSequence: ++sequence,
      previousCohortContentHash: tip,
      obligationId: obligation.obligationId,
      splitAssignmentId: assignment.assignmentId,
      policyId: lifecycle.cohort.policyId,
      policyContentHash: lifecycle.cohort.policyContentHash,
      recordedAt: obligation.opensAt,
      latestRelease: obligation.release,
      candidates: [obligation.release],
      selectedReleaseId: obligation.release.releaseId,
      forecast: {
        schemaVersion: 1,
        legacyForecast: {
          decisionId: legacyForecast.decision_id,
          contentHash: legacyForecast.content_hash,
        },
      },
    });
    tip = forecast.contentHash;
    return forecast;
  });
  const bundle = {
    ...lifecycle.bundle,
    forecasts,
  };
  const verification = verifyReleaseValidationProofBundle(bundle);
  assert.equal(verification.valid, true, verification.problems.join('; '));
  const observedAt = new Date(
    Math.max(...obligations.map((row) => Date.parse(row.outcomeDueAt))) + 1,
  ).toISOString();
  const legacyOutcomes = obligations.map((obligation, index) => ({
    observation_id: `legacy-observation-${index}`,
    decision_id: legacyForecast.decision_id,
    horizon_code: obligation.horizonCode,
    observed_at: observedAt,
    status: index === 0 ? 'matured' : 'indeterminate',
    outcome_json: index === 0
      ? '{"schemaVersion":1,"adverse":false}'
      : '{"schemaVersion":1,"reason":"insufficient_evidence","terminal":true}',
    source_identity_json: JSON.stringify({
      schemaVersion: 1,
      digest: 'c'.repeat(64),
    }),
    content_hash: index === 0 ? 'd'.repeat(64) : 'e'.repeat(64),
  })) as any[];
  return {
    bundle,
    obligations,
    legacyForecast,
    legacyOutcomes,
    observedAt,
    sourceIdentityHash: 'c'.repeat(64),
  };
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
