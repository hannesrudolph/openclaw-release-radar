import {
  canonicalReleaseValidationProofJson,
  releaseValidationActiveCohortsAt,
  releaseValidationUnevaluatedCohortEvidence,
  sealReleaseValidationPromotionReceipt,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationEvaluationReceipt,
  type ReleaseValidationPromotionEnvironment,
  type ReleaseValidationPromotionReceipt,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof';

export interface ReleaseValidationProofPromotionPlan {
  readonly receipt: ReleaseValidationPromotionReceipt;
  readonly append: {
    readonly promotionReceipts:
      readonly ReleaseValidationPromotionReceipt[];
  };
  readonly status: 'inserted' | 'already_captured';
  readonly candidate: ReleaseValidationProofBundle;
}

export function planReleaseValidationProofPromotion(input: {
  bundle: ReleaseValidationProofBundle;
  environment: ReleaseValidationPromotionEnvironment;
  promotedAt: string;
  evaluationId: string;
  evaluationContentHash: string;
  sourceProofHash: string;
  destinationProofHash: string;
}): ReleaseValidationProofPromotionPlan {
  const verification = verifyReleaseValidationProofBundle(input.bundle);
  if (!verification.valid) {
    throw new Error(
      `Cannot promote an invalid canonical validation proof ledger: ` +
      verification.problems.join('; '),
    );
  }
  const promotedAt = normalizedTimestamp(input.promotedAt);
  const evaluation = exactEvaluation(input.bundle, {
    evaluationId: input.evaluationId,
    evaluationContentHash: input.evaluationContentHash,
  });
  if (Date.parse(evaluation.evaluatedAt) > Date.parse(promotedAt)) {
    throw new Error('Canonical promotion cannot predate its evaluation');
  }
  const matching = input.bundle.promotionReceipts.filter((receipt) =>
    receipt.environment === input.environment &&
    receipt.promotedAt === promotedAt &&
    receipt.evaluationId === evaluation.evaluationId);
  if (matching.length > 1) {
    throw new Error('Canonical promotion has duplicate exact retries');
  }
  const existingPromotion = matching[0] ?? null;
  const retirement = input.bundle.retirements.find((row) =>
    row.proofEpochId === evaluation.proofEpochId);
  if (
    retirement &&
    (
      existingPromotion == null ||
      retirement.epochSequence < existingPromotion.epochSequence
    ) &&
    Date.parse(retirement.retiredAt) <= Date.parse(promotedAt)
  ) {
    throw new Error('Canonical promotion cannot use a retired proof epoch');
  }

  if (
    input.environment === 'production' &&
    evaluation.status !== 'validated'
  ) {
    throw new Error(
      'Canonical production promotion requires validated evidence',
    );
  }

  const currentEvaluation = latestEvaluationAt(
    input.bundle,
    evaluation.proofEpochId,
    promotedAt,
    existingPromotion?.epochSequence ?? null,
  );
  if (
    !currentEvaluation ||
    currentEvaluation.evaluationId !== evaluation.evaluationId ||
    currentEvaluation.contentHash !== evaluation.contentHash
  ) {
    throw new Error(
      'Canonical promotion requires the latest evaluation receipt',
    );
  }

  const activeCohortIds = releaseValidationActiveCohortsAt(
    input.bundle,
    evaluation.proofEpochId,
    promotedAt,
  )
    .filter((cohort) =>
      existingPromotion == null ||
      cohort.epochSequence < existingPromotion.epochSequence)
    .map((cohort) => cohort.cohortId);
  assertExactSet(
    evaluation.cohortIds,
    activeCohortIds,
    'Canonical promotion active cohort',
  );
  assertNoPostEvaluationCohortEvidence(
    input.bundle,
    evaluation,
    promotedAt,
  );

  const cohortIdSet = new Set(evaluation.cohortIds);
  const forecastIds = input.bundle.forecasts
    .filter((forecast) =>
      cohortIdSet.has(forecast.cohortId) &&
      Date.parse(forecast.recordedAt) <= Date.parse(evaluation.evaluatedAt))
    .slice()
    .sort((left, right) =>
      left.cohortId.localeCompare(right.cohortId) ||
      left.cohortSequence - right.cohortSequence ||
      left.forecastId.localeCompare(right.forecastId))
    .map((forecast) => forecast.forecastId);
  const outcomeIds = input.bundle.outcomes
    .filter((outcome) =>
      cohortIdSet.has(outcome.cohortId) &&
      Date.parse(outcome.observedAt) <= Date.parse(evaluation.evaluatedAt))
    .slice()
    .sort((left, right) =>
      left.cohortId.localeCompare(right.cohortId) ||
      left.cohortSequence - right.cohortSequence ||
      left.outcomeId.localeCompare(right.outcomeId))
    .map((outcome) => outcome.outcomeId);
  assertExactSet(
    outcomeIds,
    evaluation.outcomeIds,
    'Canonical promotion evaluation outcome',
  );

  if (existingPromotion) {
    const receipt = sealReleaseValidationPromotionReceipt({
      proofEpochId: evaluation.proofEpochId,
      epochSequence: existingPromotion.epochSequence,
      previousEpochContentHash:
        existingPromotion.previousEpochContentHash,
      environment: input.environment,
      promotedAt,
      evaluationId: evaluation.evaluationId,
      evaluationContentHash: evaluation.contentHash,
      cohortIds: evaluation.cohortIds,
      forecastIds,
      outcomeIds,
      sourceProofHash: input.sourceProofHash,
      destinationProofHash: input.destinationProofHash,
    });
    if (
      canonicalReleaseValidationProofJson(receipt) !==
        canonicalReleaseValidationProofJson(existingPromotion)
    ) {
      throw new Error(
        `Canonical promotion ${existingPromotion.promotionId} differs from its ` +
        `exact retry`,
      );
    }
    return {
      receipt: existingPromotion,
      append: { promotionReceipts: [] },
      status: 'already_captured',
      candidate: input.bundle,
    };
  }

  const receipt = sealReleaseValidationPromotionReceipt({
    proofEpochId: evaluation.proofEpochId,
    epochSequence:
      maximumEpochSequence(input.bundle, evaluation.proofEpochId) + 1,
    previousEpochContentHash:
      verification.epochChainTips[evaluation.proofEpochId] ?? null,
    environment: input.environment,
    promotedAt,
    evaluationId: evaluation.evaluationId,
    evaluationContentHash: evaluation.contentHash,
    cohortIds: evaluation.cohortIds,
    forecastIds,
    outcomeIds,
    sourceProofHash: input.sourceProofHash,
    destinationProofHash: input.destinationProofHash,
  });
  const candidate = {
    ...input.bundle,
    promotionReceipts: [...input.bundle.promotionReceipts, receipt],
  };
  const candidateVerification = verifyReleaseValidationProofBundle(candidate);
  if (!candidateVerification.valid) {
    throw new Error(
      `Canonical validation promotion plan is invalid: ` +
      candidateVerification.problems.join('; '),
    );
  }
  return {
    receipt,
    append: { promotionReceipts: [receipt] },
    status: 'inserted',
    candidate,
  };
}

function exactEvaluation(
  bundle: ReleaseValidationProofBundle,
  input: {
    evaluationId: string;
    evaluationContentHash: string;
  },
): ReleaseValidationEvaluationReceipt {
  const evaluation = bundle.evaluationReceipts.find((receipt) =>
    receipt.evaluationId === input.evaluationId);
  if (
    !evaluation ||
    evaluation.contentHash !== input.evaluationContentHash
  ) {
    throw new Error(
      'Canonical promotion requires the exact evaluation ID and content hash',
    );
  }
  return evaluation;
}

function latestEvaluationAt(
  bundle: ReleaseValidationProofBundle,
  proofEpochId: string,
  promotedAt: string,
  beforeEpochSequence: number | null,
): ReleaseValidationEvaluationReceipt | null {
  return bundle.evaluationReceipts
    .filter((receipt) =>
      receipt.proofEpochId === proofEpochId &&
      (
        beforeEpochSequence == null ||
        receipt.epochSequence < beforeEpochSequence
      ) &&
      Date.parse(receipt.evaluatedAt) <= Date.parse(promotedAt))
    .slice()
    .sort((left, right) =>
      Date.parse(right.evaluatedAt) - Date.parse(left.evaluatedAt) ||
      right.epochSequence - left.epochSequence ||
      right.evaluationId.localeCompare(left.evaluationId))[0] ?? null;
}

function assertNoPostEvaluationCohortEvidence(
  bundle: ReleaseValidationProofBundle,
  evaluation: ReleaseValidationEvaluationReceipt,
  promotedAt: string,
): void {
  const laterEvidence = releaseValidationUnevaluatedCohortEvidence(
    bundle,
    {
      cohortIds: evaluation.cohortIds,
      evaluatedAt: evaluation.evaluatedAt,
      observedAt: promotedAt,
    },
  );
  if (laterEvidence.length > 0) {
    throw new Error(
      `Canonical promotion evaluation is stale relative to cohort evidence: ` +
      laterEvidence.slice(0, 10).join(', '),
    );
  }
}

function maximumEpochSequence(
  bundle: ReleaseValidationProofBundle,
  proofEpochId: string,
): number {
  return Math.max(0, ...[
    ...bundle.retirements,
    ...bundle.policies,
    ...bundle.cohorts,
    ...bundle.catalogObservations,
    ...bundle.catalogReconciliations,
    ...bundle.evaluationReceipts,
    ...bundle.promotionReceipts,
  ].filter((row) => row.proofEpochId === proofEpochId)
    .map((row) => row.epochSequence));
}

function assertExactSet(
  actual: readonly string[],
  expected: readonly string[],
  label: string,
): void {
  const normalizedActual = [...actual].sort();
  const normalizedExpected = [...expected].sort();
  if (
    normalizedActual.length !== new Set(normalizedActual).size ||
    normalizedExpected.length !== new Set(normalizedExpected).size ||
    canonicalReleaseValidationProofJson(normalizedActual) !==
      canonicalReleaseValidationProofJson(normalizedExpected)
  ) {
    throw new Error(`${label} set does not match exactly`);
  }
}

function normalizedTimestamp(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error('Canonical promotion time is invalid');
  }
  return new Date(timestamp).toISOString();
}
