import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  sealReleaseValidationProofEpochRetirement,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';
import {
  RELEASE_VALIDATION_REQUIRED_POLICY_CELLS,
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle.ts';

const repository = 'openclaw/openclaw';
const codeRevision = `git:${'a'.repeat(40)}`;
const nextCodeRevision = `git:${'b'.repeat(40)}`;

describe('release validation proof lifecycle planner', () => {
  it('bootstraps from the real observation time without enrolling history', () => {
    const plan = planReleaseValidationProofLifecycle({
      existing: emptyBundle(),
      repository,
      observedAt: '2026-07-01T00:00:00Z',
      source: 'github_graphql_stable_releases',
      releases: [
        release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
      ],
      modelVersion: 'score-v1',
      promptVersion: 5,
      codeRevision,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    });

    assert.equal(plan.verification.valid, true);
    assert.equal(plan.policy.requiredCellCount, 4);
    assert.deepEqual(
      plan.policy.requiredCells.map((cell) => [
        cell.opportunityCode,
        cell.horizonCode,
      ]),
      RELEASE_VALIDATION_REQUIRED_POLICY_CELLS.map((cell) => [
        cell.opportunityCode,
        cell.horizonCode,
      ]),
    );
    assert.equal(plan.bundle.catalogMembers.length, 1);
    assert.equal(plan.bundle.obligations.length, 0);
    assert.equal(plan.bundle.splitAssignments.length, 0);
    assert.equal(plan.excludedPreInceptionReleaseCount, 1);

    const retry = planReleaseValidationProofLifecycle({
      existing: plan.bundle,
      repository,
      observedAt: '2026-07-01T00:00:00Z',
      source: 'github_graphql_stable_releases',
      releases: [
        release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
      ],
      modelVersion: 'score-v1',
      promptVersion: 5,
      codeRevision,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    });

    assert.deepEqual(retry.append, emptyAppend());
    assert.deepEqual(retry.bundle, plan.bundle);
  });

  it('does not append through a future-effective epoch retirement', () => {
    const bootstrap = bootstrapPlan();
    const verification = verifyReleaseValidationProofBundle(bootstrap.bundle);
    const retirement = sealReleaseValidationProofEpochRetirement({
      proofEpochId: bootstrap.epoch.proofEpochId,
      epochContentHash: bootstrap.epoch.contentHash,
      epochSequence: bootstrap.catalogReconciliation.epochSequence + 1,
      previousEpochContentHash:
        verification.epochChainTips[bootstrap.epoch.proofEpochId] ?? null,
      recordedAt: '2026-07-01T00:30:00Z',
      retiredAt: '2026-07-01T01:00:00Z',
      reason: 'scheduled validation epoch transition',
    });
    const pendingRetirement: ReleaseValidationProofBundle = {
      ...bootstrap.bundle,
      retirements: [retirement],
    };
    assert.equal(
      verifyReleaseValidationProofBundle(pendingRetirement).valid,
      true,
    );

    assert.throws(
      () => planReleaseValidationProofLifecycle({
        existing: pendingRetirement,
        repository,
        observedAt: '2026-07-01T00:45:00Z',
        source: 'github_graphql_stable_releases',
        releases: [
          release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
        ],
        modelVersion: 'score-v1',
        promptVersion: 5,
        codeRevision,
        developmentArm: 'production',
        developmentReleaseCount: 1,
      }),
      /sealed pending retirement/,
    );
  });

  it('creates every opportunity-by-horizon obligation from first admission', () => {
    const bootstrap = bootstrapPlan();
    const firstRelease = release(
      'prospective-1',
      '2',
      '2026-07-01T01:00:00Z',
      'v2',
    );
    const plan = planReleaseValidationProofLifecycle({
      existing: bootstrap.bundle,
      repository,
      observedAt: '2026-07-01T01:05:00Z',
      source: 'github_graphql_stable_releases',
      releases: [
        firstRelease,
        release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
      ],
      modelVersion: 'score-v1',
      promptVersion: 5,
      codeRevision,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    });

    assert.equal(plan.append.obligations.length, 4);
    assert.equal(plan.append.splitAssignments.length, 4);
    assert.deepEqual(
      new Set(plan.append.splitAssignments.map((row) => row.arm)),
      new Set(['production']),
    );
    const field3h = plan.append.obligations.find((row) =>
      row.opportunityCode === 'first_verified_after_3h' &&
      row.horizonCode === 'field_regression_72h');
    assert.ok(field3h);
    assert.equal(field3h.opensAt, '2026-07-01T04:00:00.000Z');
    assert.equal(
      field3h.closesAtExclusive,
      '2026-07-01T07:00:00.000Z',
    );
    assert.equal(field3h.outcomeDueAt, '2026-07-04T07:00:00.000Z');
    assert.equal(plan.verification.valid, true);
  });

  it('records late misses and assigns later admissions to immutable holdout', () => {
    const first = firstProspectivePlan();
    const lateRelease = release(
      'prospective-2',
      '3',
      '2026-07-01T02:00:00Z',
      'v3',
    );
    const late = planReleaseValidationProofLifecycle({
      existing: first.bundle,
      repository,
      observedAt: '2026-07-04T12:00:00Z',
      source: 'github_graphql_stable_releases',
      releases: [
        lateRelease,
        release('prospective-1', '2', '2026-07-01T01:00:00Z', 'v2'),
        release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
      ],
      modelVersion: 'score-v1',
      promptVersion: 5,
      codeRevision,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    });

    assert.equal(late.append.obligations.length, 4);
    assert.deepEqual(
      new Set(late.append.splitAssignments.map((row) => row.arm)),
      new Set(['holdout']),
    );
    assert.ok(late.append.obligations.every((row) =>
      Date.parse(row.recordedAt) >= Date.parse(row.closesAtExclusive)));

    const retired = planReleaseValidationProofLifecycle({
      existing: late.bundle,
      repository,
      observedAt: '2026-07-05T00:00:00Z',
      source: 'github_graphql_stable_releases',
      releases: [
        lateRelease,
        release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
      ],
      modelVersion: 'score-v1',
      promptVersion: 5,
      codeRevision,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    });

    assert.equal(retired.append.obligations.length, 0);
    assert.equal(retired.bundle.obligations.length, 8);
    assert.ok(retired.append.catalogReconciliationRows.some((row) =>
      row.status === 'retired'));
    assert.equal(retired.verification.valid, true);
  });

  it('retires superseded production strata before future release admission', () => {
    const first = firstProspectivePlan();
    const priorCohort = first.cohort;
    const priorObligations = cohortObligationIdentity(
      first.bundle,
      priorCohort.cohortId,
    );

    const revisedInput = {
      repository,
      observedAt: '2026-07-01T02:00:00Z',
      source: 'github_graphql_stable_releases',
      releases: [
        release('prospective-1', '2', '2026-07-01T01:00:00Z', 'v2'),
        release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
      ],
      modelVersion: 'score-v2',
      promptVersion: 6,
      codeRevision: nextCodeRevision,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    } as const;
    const revised = planReleaseValidationProofLifecycle({
      existing: first.bundle,
      ...revisedInput,
    });

    assert.equal(revised.append.retirements.length, 1);
    assert.equal(
      revised.append.retirements[0].proofEpochId,
      priorCohort.proofEpochId,
    );
    assert.equal(
      revised.append.retirements[0].retiredAt,
      '2026-07-01T02:00:00.000Z',
    );
    assert.notEqual(revised.epoch.proofEpochId, priorCohort.proofEpochId);
    assert.equal(revised.append.epochs.length, 1);
    assert.equal(revised.append.cohorts.length, 1);
    assert.equal(revised.append.obligations.length, 0);
    assert.equal(revised.admittedReleaseCount, 0);
    assert.equal(revised.verification.valid, true);
    const revisedRetry = planReleaseValidationProofLifecycle({
      existing: revised.bundle,
      ...revisedInput,
    });
    assert.deepEqual(revisedRetry.append, emptyAppend());
    assert.deepEqual(revisedRetry.bundle, revised.bundle);

    const currentCohort = revised.cohort;
    const laterRelease = release(
      'prospective-2',
      '3',
      '2026-07-01T03:00:00Z',
      'v3',
    );
    const admitted = planReleaseValidationProofLifecycle({
      existing: revised.bundle,
      repository,
      observedAt: '2026-07-01T03:05:00Z',
      source: 'github_graphql_stable_releases',
      releases: [
        laterRelease,
        release('prospective-1', '2', '2026-07-01T01:00:00Z', 'v2'),
        release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
      ],
      modelVersion: 'score-v2',
      promptVersion: 6,
      codeRevision: nextCodeRevision,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    });

    assert.equal(admitted.append.retirements.length, 0);
    assert.equal(admitted.append.epochs.length, 0);
    assert.equal(admitted.append.cohorts.length, 0);
    assert.equal(admitted.append.obligations.length, 4);
    assert.equal(admitted.append.splitAssignments.length, 4);
    assert.equal(admitted.admittedReleaseCount, 1);
    assert.ok(admitted.append.obligations.every((row) =>
      row.cohortId === currentCohort.cohortId &&
      row.release.nodeId === laterRelease.nodeId));
    assert.ok(admitted.append.obligations.every((row) =>
      row.cohortId !== priorCohort.cohortId));
    assert.ok(admitted.append.splitAssignments.every((row) =>
      row.cohortId === currentCohort.cohortId &&
      row.arm === 'production'));
    assert.deepEqual(
      cohortObligationIdentity(admitted.bundle, priorCohort.cohortId),
      priorObligations,
    );
    assert.equal(
      admitted.bundle.obligations.filter((row) =>
        row.cohortId === priorCohort.cohortId).length,
      4,
    );
    assert.equal(
      admitted.bundle.obligations.filter((row) =>
        row.cohortId === currentCohort.cohortId).length,
      4,
    );
    assert.equal(admitted.bundle.obligations.length, 8);
    assert.equal(admitted.verification.valid, true);
  });

  it('rejects same-observation mutation and detects missing policy cells', () => {
    const first = firstProspectivePlan();
    assert.throws(
      () => planReleaseValidationProofLifecycle({
        existing: first.bundle,
        repository,
        observedAt: '2026-07-01T01:05:00Z',
        source: 'github_graphql_stable_releases',
        releases: [
          release('prospective-1', '2', '2026-07-01T01:00:00Z', 'renamed'),
          release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
        ],
        modelVersion: 'score-v1',
        promptVersion: 5,
        codeRevision,
        developmentArm: 'production',
        developmentReleaseCount: 1,
      }),
      /differs from retry input/,
    );

    const removed = first.bundle.obligations.at(-1);
    assert.ok(removed);
    const tampered: ReleaseValidationProofBundle = {
      ...first.bundle,
      obligations: first.bundle.obligations.slice(0, -1),
      splitAssignments: first.bundle.splitAssignments.filter(
        (row) => row.obligationId !== removed.obligationId,
      ),
    };
    const verification = verifyReleaseValidationProofBundle(tampered);
    assert.equal(verification.valid, false);
    assert.match(
      verification.problems.join('\n'),
      /must have one obligation for cell/,
    );
  });
});

function bootstrapPlan() {
  return planReleaseValidationProofLifecycle({
    existing: emptyBundle(),
    repository,
    observedAt: '2026-07-01T00:00:00Z',
    source: 'github_graphql_stable_releases',
    releases: [
      release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
    ],
    modelVersion: 'score-v1',
    promptVersion: 5,
    codeRevision,
    developmentArm: 'production',
    developmentReleaseCount: 1,
  });
}

function firstProspectivePlan() {
  const bootstrap = bootstrapPlan();
  return planReleaseValidationProofLifecycle({
    existing: bootstrap.bundle,
    repository,
    observedAt: '2026-07-01T01:05:00Z',
    source: 'github_graphql_stable_releases',
    releases: [
      release('prospective-1', '2', '2026-07-01T01:00:00Z', 'v2'),
      release('historical', '1', '2026-06-30T00:00:00Z', 'v1'),
    ],
    modelVersion: 'score-v1',
    promptVersion: 5,
    codeRevision,
    developmentArm: 'production',
    developmentReleaseCount: 1,
  });
}

function release(
  nodeId: string,
  oidDigit: string,
  publishedAt: string,
  alias: string,
) {
  return {
    repository,
    nodeId,
    tagCommitOid: oidDigit.repeat(40),
    publishedAt,
    aliases: [alias],
  };
}

function cohortObligationIdentity(
  bundle: ReleaseValidationProofBundle,
  cohortId: string,
) {
  return bundle.obligations
    .filter((row) => row.cohortId === cohortId)
    .map((row) => [row.obligationId, row.contentHash])
    .sort((left, right) => left[0].localeCompare(right[0]));
}

function emptyBundle(): ReleaseValidationProofBundle {
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

function emptyAppend() {
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
  };
}
