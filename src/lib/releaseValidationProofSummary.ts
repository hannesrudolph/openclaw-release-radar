import {
  releaseValidationActiveCohortsAt,
  releaseValidationUnevaluatedCohortEvidence,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationEvaluationReceipt,
  type ReleaseValidationPromotionReceipt,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof';

export type ReleaseValidationProofSummaryStatus =
  | 'invalid'
  | 'uninitialized'
  | 'no_active_epoch'
  | 'ambiguous_active_epochs'
  | 'unevaluated'
  | 'insufficient'
  | 'measurable_but_failed'
  | 'validated_not_promoted'
  | 'production_promoted';

export function summarizeReleaseValidationProof(
  bundle: ReleaseValidationProofBundle,
  observedAt: string,
) {
  const normalizedObservedAt = normalizedTimestamp(observedAt);
  const observedAtMs = Date.parse(normalizedObservedAt);
  const verification = verifyReleaseValidationProofBundle(bundle);
  const activeEpochs = bundle.epochs
    .filter((epoch) =>
      Date.parse(epoch.startsAt) <= observedAtMs &&
      bundle.retirements.every((retirement) =>
        retirement.proofEpochId !== epoch.proofEpochId ||
        Date.parse(retirement.retiredAt) > observedAtMs) &&
      releaseValidationActiveCohortsAt(
        bundle,
        epoch.proofEpochId,
        normalizedObservedAt,
      ).length > 0)
    .slice()
    .sort((left, right) =>
      Date.parse(left.startsAt) - Date.parse(right.startsAt) ||
      left.proofEpochId.localeCompare(right.proofEpochId));
  const activeEpochIds = activeEpochs.map((epoch) => epoch.proofEpochId);
  const activeEpochIdSet = new Set(activeEpochIds);
  const activeCohorts = activeEpochs.flatMap((epoch) =>
    releaseValidationActiveCohortsAt(
      bundle,
      epoch.proofEpochId,
      normalizedObservedAt,
    ));
  const activeCohortIds = activeCohorts.map((cohort) => cohort.cohortId);
  const currentEvaluation = latestEvaluation(
    bundle.evaluationReceipts.filter((receipt) =>
      activeEpochIdSet.has(receipt.proofEpochId) &&
      Date.parse(receipt.evaluatedAt) <= observedAtMs),
  );
  const currentProductionPromotion = currentEvaluation
    ? latestPromotion(bundle.promotionReceipts.filter((receipt) =>
        receipt.proofEpochId === currentEvaluation.proofEpochId &&
        receipt.environment === 'production' &&
        Date.parse(receipt.promotedAt) <= observedAtMs))
    : null;
  const latestCalibrationPromotion = currentEvaluation
    ? latestPromotion(bundle.promotionReceipts.filter((receipt) =>
        receipt.proofEpochId === currentEvaluation.proofEpochId &&
        receipt.environment === 'calibration' &&
        Date.parse(receipt.promotedAt) <= observedAtMs))
    : null;
  const unevaluatedEvidence = currentEvaluation
    ? releaseValidationUnevaluatedCohortEvidence(bundle, {
        cohortIds: currentEvaluation.cohortIds,
        evaluatedAt: currentEvaluation.evaluatedAt,
        observedAt: normalizedObservedAt,
      })
    : [];
  const productionAuthorizationProblems = authorizationProblems({
    valid: verification.valid,
    activeEpochIds,
    activeCohortIds,
    currentEvaluation,
    currentProductionPromotion,
    unevaluatedEvidence,
  });
  const productionAuthorized =
    productionAuthorizationProblems.length === 0;
  const status = summaryStatus({
    valid: verification.valid,
    epochCount: bundle.epochs.length,
    activeEpochCount: activeEpochs.length,
    currentEvaluation,
    productionAuthorized,
  });

  return {
    schemaVersion: 1 as const,
    observedAt: normalizedObservedAt,
    status,
    valid: verification.valid,
    productionAuthorized,
    productionAuthorizationProblems,
    counts: {
      epochs: bundle.epochs.length,
      retirements: bundle.retirements.length,
      policies: bundle.policies.length,
      cohorts: bundle.cohorts.length,
      obligations: bundle.obligations.length,
      splitAssignments: bundle.splitAssignments.length,
      forecasts: bundle.forecasts.length,
      outcomes: bundle.outcomes.length,
      observationBatches: bundle.observationBatches.length,
      evaluationReceipts: bundle.evaluationReceipts.length,
      promotionReceipts: bundle.promotionReceipts.length,
    },
    activeEpochCount: activeEpochs.length,
    activeEpochIds,
    activeCohortCount: activeCohorts.length,
    activeCohortIds,
    currentEvaluation: currentEvaluation
      ? evaluationSummary(currentEvaluation)
      : null,
    currentProductionPromotion: currentProductionPromotion
      ? promotionSummary(currentProductionPromotion)
      : null,
    latestCalibrationPromotion: latestCalibrationPromotion
      ? promotionSummary(latestCalibrationPromotion)
      : null,
    problems: verification.problems,
  };
}

function authorizationProblems(input: {
  valid: boolean;
  activeEpochIds: readonly string[];
  activeCohortIds: readonly string[];
  currentEvaluation: ReleaseValidationEvaluationReceipt | null;
  currentProductionPromotion: ReleaseValidationPromotionReceipt | null;
  unevaluatedEvidence: readonly string[];
}): string[] {
  if (!input.valid) {
    return ['canonical validation proof ledger is invalid'];
  }
  if (input.activeEpochIds.length !== 1) {
    return [
      `production authorization requires exactly one active proof epoch; ` +
      `found ${input.activeEpochIds.length}`,
    ];
  }
  if (!input.currentEvaluation) {
    return ['production authorization requires a current evaluation'];
  }
  const problems: string[] = [];
  if (input.currentEvaluation.status !== 'validated') {
    problems.push(
      `current evaluation status ${input.currentEvaluation.status} is not validated`,
    );
  }
  if (!sameExactSet(
    input.currentEvaluation.cohortIds,
    input.activeCohortIds,
  )) {
    problems.push(
      'current evaluation cohort set does not match the active cohort set',
    );
  }
  if (input.unevaluatedEvidence.length > 0) {
    problems.push(
      `current evaluation is stale relative to cohort evidence: ` +
      input.unevaluatedEvidence.slice(0, 10).join(', '),
    );
  }
  if (!input.currentProductionPromotion) {
    problems.push(
      'production authorization requires a production promotion receipt',
    );
  } else if (
    input.currentProductionPromotion.evaluationId !==
      input.currentEvaluation.evaluationId ||
    input.currentProductionPromotion.evaluationContentHash !==
      input.currentEvaluation.contentHash
  ) {
    problems.push(
      'current production promotion does not bind the current evaluation',
    );
  }
  return problems;
}

function sameExactSet(
  left: readonly string[],
  right: readonly string[],
): boolean {
  if (
    left.length !== right.length ||
    new Set(left).size !== left.length ||
    new Set(right).size !== right.length
  ) {
    return false;
  }
  const expected = new Set(right);
  return left.every((value) => expected.has(value));
}

function summaryStatus(input: {
  valid: boolean;
  epochCount: number;
  activeEpochCount: number;
  currentEvaluation: ReleaseValidationEvaluationReceipt | null;
  productionAuthorized: boolean;
}): ReleaseValidationProofSummaryStatus {
  if (!input.valid) return 'invalid';
  if (input.epochCount === 0) return 'uninitialized';
  if (input.activeEpochCount === 0) return 'no_active_epoch';
  if (input.activeEpochCount > 1) return 'ambiguous_active_epochs';
  if (!input.currentEvaluation) return 'unevaluated';
  if (input.currentEvaluation.status === 'insufficient') {
    return 'insufficient';
  }
  if (input.currentEvaluation.status === 'measurable_but_failed') {
    return 'measurable_but_failed';
  }
  return input.productionAuthorized
    ? 'production_promoted'
    : 'validated_not_promoted';
}

function latestEvaluation(
  receipts: readonly ReleaseValidationEvaluationReceipt[],
): ReleaseValidationEvaluationReceipt | null {
  return receipts.slice().sort((left, right) =>
    Date.parse(right.evaluatedAt) - Date.parse(left.evaluatedAt) ||
    right.epochSequence - left.epochSequence ||
    right.evaluationId.localeCompare(left.evaluationId))[0] ?? null;
}

function latestPromotion(
  receipts: readonly ReleaseValidationPromotionReceipt[],
): ReleaseValidationPromotionReceipt | null {
  return receipts.slice().sort((left, right) =>
    Date.parse(right.promotedAt) - Date.parse(left.promotedAt) ||
    right.epochSequence - left.epochSequence ||
    right.promotionId.localeCompare(left.promotionId))[0] ?? null;
}

function evaluationSummary(receipt: ReleaseValidationEvaluationReceipt) {
  return {
    evaluationId: receipt.evaluationId,
    contentHash: receipt.contentHash,
    proofEpochId: receipt.proofEpochId,
    evaluatedAt: receipt.evaluatedAt,
    status: receipt.status,
    cohortCount: receipt.cohortCount,
    requiredCellCount: receipt.requiredCellCount,
    observationBatchCount: receipt.observationBatchCount,
    outcomeCount: receipt.outcomeCount,
  };
}

function promotionSummary(receipt: ReleaseValidationPromotionReceipt) {
  return {
    promotionId: receipt.promotionId,
    contentHash: receipt.contentHash,
    proofEpochId: receipt.proofEpochId,
    environment: receipt.environment,
    promotedAt: receipt.promotedAt,
    evaluationId: receipt.evaluationId,
    evaluationContentHash: receipt.evaluationContentHash,
    cohortCount: receipt.cohortCount,
    forecastCount: receipt.forecastCount,
    outcomeCount: receipt.outcomeCount,
    sourceProofHash: receipt.sourceProofHash,
    destinationProofHash: receipt.destinationProofHash,
  };
}

function normalizedTimestamp(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error('Release validation proof summary time is invalid');
  }
  return new Date(timestamp).toISOString();
}
