import { createHash } from 'node:crypto';
import {
  canonicalReleaseValidationProofJson,
  releaseValidationActiveCohortsAt,
  releaseValidationCohortCellKey,
  sealReleaseValidationEvaluationReceipt,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationEvaluationReceipt,
  type ReleaseValidationEvaluationStatus,
  type ReleaseValidationProofBundle,
  type ReleaseValidationProofJsonValue,
} from './releaseValidationProof';
import {
  DEFAULT_VALIDATION_QUALITY_CRITERIA,
  DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
} from './releaseValidation';
import {
  parseReleaseArtifactPublication,
} from './releaseArtifactPublication';
import {
  scoreSourceIdentityManifestDigest,
} from './scoreSourceIdentity';
import {
  buildReleaseValidationOpportunityProofCoverage,
  type ReleaseValidationOpportunityProofCoverage,
} from './releaseValidationOpportunityProofCoverage';

type JsonRecord = Record<string, ReleaseValidationProofJsonValue>;

interface ValidatedEvidenceCase {
  readonly obligation:
    ReleaseValidationProofBundle['obligations'][number];
  readonly assignment:
    ReleaseValidationProofBundle['splitAssignments'][number];
  readonly forecast:
    ReleaseValidationProofBundle['forecasts'][number];
  readonly outcome:
    ReleaseValidationProofBundle['outcomes'][number];
  readonly observationBatchIds: readonly string[];
  readonly legacyDecisionId: string;
}

interface ValidatedCellEvidence {
  readonly cellId: string;
  readonly opportunityCode: string;
  readonly horizonCode: string;
  readonly cases: readonly ValidatedEvidenceCase[];
}

interface ValidatedCohortEvidence {
  readonly cohort: ReleaseValidationProofBundle['cohorts'][number];
  readonly policy: ReleaseValidationProofBundle['policies'][number];
  readonly purpose: 'production' | 'calibration';
  readonly cohortKey: string;
  readonly canonicalForecastCount: number;
  readonly linkedDecisionCount: number;
  readonly cells: readonly ValidatedCellEvidence[];
}

interface ValidatedProofEvidence {
  readonly cohorts: readonly ValidatedCohortEvidence[];
  readonly productionCohortCount: number;
  readonly calibrationCohortCount: number;
  readonly splitAssignmentCount: number;
}

export interface ReleaseValidationProofEvaluationPlan {
  readonly receipt: ReleaseValidationEvaluationReceipt;
  readonly append: {
    readonly evaluationReceipts: readonly ReleaseValidationEvaluationReceipt[];
  };
  readonly status: 'inserted' | 'already_captured';
  readonly coverage: ReleaseValidationOpportunityProofCoverage;
  readonly candidate: ReleaseValidationProofBundle;
}

export function planReleaseValidationProofEvaluation(input: {
  bundle: ReleaseValidationProofBundle;
  evaluatedAt: string;
  status: ReleaseValidationEvaluationStatus;
  metrics: ReleaseValidationProofJsonValue;
}): ReleaseValidationProofEvaluationPlan {
  const verification = verifyReleaseValidationProofBundle(input.bundle);
  if (!verification.valid) {
    throw new Error(
      `Cannot evaluate an invalid canonical validation proof ledger: ` +
      verification.problems.join('; '),
    );
  }
  const evaluatedAt = normalizedTimestamp(input.evaluatedAt);
  const metrics = canonicalMetrics(input.metrics);
  const metricsRecord = jsonRecord(metrics, 'evaluation metrics');
  if (metricsRecord.status !== input.status) {
    throw new Error(
      'Canonical evaluation metrics status must match the receipt status',
    );
  }
  if (metricsRecord.generatedAt !== evaluatedAt) {
    throw new Error(
      'Canonical evaluation metrics generatedAt must equal evaluatedAt',
    );
  }

  const activeEpochs = input.bundle.epochs.filter((epoch) =>
    input.bundle.retirements.every((retirement) =>
      retirement.proofEpochId !== epoch.proofEpochId ||
      Date.parse(retirement.retiredAt) > Date.parse(evaluatedAt)) &&
    releaseValidationActiveCohortsAt(
      input.bundle,
      epoch.proofEpochId,
      evaluatedAt,
    ).length > 0);
  if (activeEpochs.length !== 1) {
    throw new Error(
      `Canonical evaluation requires exactly one active proof epoch with ` +
      `active cohorts; found ${activeEpochs.length}`,
    );
  }
  const proofEpochId = activeEpochs[0].proofEpochId;
  const cohorts = releaseValidationActiveCohortsAt(
    input.bundle,
    proofEpochId,
    evaluatedAt,
  );
  const cohortIds = cohorts.map((cohort) => cohort.cohortId);
  const coverage = buildReleaseValidationOpportunityProofCoverage({
    bundle: input.bundle,
    asOf: evaluatedAt,
    cohortIds,
  });
  const requiredCellKeys = cohorts.flatMap((cohort) =>
    cohort.requiredCellIds.map((cellId) =>
      releaseValidationCohortCellKey(cohort.cohortId, cellId)));
  const cohortIdSet = new Set(cohortIds);
  const observationBatchIds = input.bundle.observationBatches
    .filter((batch) =>
      cohortIdSet.has(batch.cohortId) &&
      Date.parse(batch.observedAt) <= Date.parse(evaluatedAt))
    .slice()
    .sort((left, right) =>
      left.cohortId.localeCompare(right.cohortId) ||
      left.cohortSequence - right.cohortSequence ||
      left.batchId.localeCompare(right.batchId))
    .map((batch) => batch.batchId);
  const outcomeIds = input.bundle.outcomes
    .filter((outcome) =>
      cohortIdSet.has(outcome.cohortId) &&
      Date.parse(outcome.observedAt) <= Date.parse(evaluatedAt))
    .slice()
    .sort((left, right) =>
      left.cohortId.localeCompare(right.cohortId) ||
      left.cohortSequence - right.cohortSequence ||
      left.outcomeId.localeCompare(right.outcomeId))
    .map((outcome) => outcome.outcomeId);

  if (input.status === 'validated') {
    const prospectiveReport = validatedAuthorizationReport(
      metricsRecord,
      evaluatedAt,
    );
    assertValidatedScorePublicationAuthorizations({
      prospectiveReport,
      bundle: input.bundle,
      cohortIds,
    });
    const evidence = validatedProofEvidence({
      bundle: input.bundle,
      cohorts,
      evaluatedAt,
    });
    assertValidatedOpportunityCoverage(coverage);
    assertValidatedReportProofBinding({
      prospectiveReport,
      evidence,
      proofEpochId,
      evaluatedAt,
      cohortIds,
      requiredCellKeys,
      observationBatchIds,
      outcomeIds,
    });
  }

  const existing = input.bundle.evaluationReceipts.filter((receipt) =>
    receipt.proofEpochId === proofEpochId &&
    receipt.evaluatedAt === evaluatedAt);
  if (existing.length > 1) {
    throw new Error(
      'Canonical validation proof contains duplicate evaluation timestamps',
    );
  }
  if (existing.length === 1) {
    const receipt = sealReleaseValidationEvaluationReceipt({
      proofEpochId,
      epochSequence: existing[0].epochSequence,
      previousEpochContentHash: existing[0].previousEpochContentHash,
      evaluatedAt,
      status: input.status,
      cohortIds,
      requiredCellKeys,
      observationBatchIds,
      outcomeIds,
      metrics,
    });
    if (
      canonicalReleaseValidationProofJson(receipt) !==
      canonicalReleaseValidationProofJson(existing[0])
    ) {
      throw new Error(
        `Canonical evaluation ${existing[0].evaluationId} differs from its ` +
        `exact retry`,
      );
    }
    return {
      receipt: existing[0],
      append: { evaluationReceipts: [] },
      status: 'already_captured',
      coverage,
      candidate: input.bundle,
    };
  }

  const receipt = sealReleaseValidationEvaluationReceipt({
    proofEpochId,
    epochSequence: maximumEpochSequence(input.bundle, proofEpochId) + 1,
    previousEpochContentHash:
      verification.epochChainTips[proofEpochId] ?? null,
    evaluatedAt,
    status: input.status,
    cohortIds,
    requiredCellKeys,
    observationBatchIds,
    outcomeIds,
    metrics,
  });
  const candidate = {
    ...input.bundle,
    evaluationReceipts: [...input.bundle.evaluationReceipts, receipt],
  };
  const candidateVerification = verifyReleaseValidationProofBundle(candidate);
  if (!candidateVerification.valid) {
    throw new Error(
      `Canonical validation evaluation plan is invalid: ` +
      candidateVerification.problems.join('; '),
    );
  }
  return {
    receipt,
    append: { evaluationReceipts: [receipt] },
    status: 'inserted',
    coverage,
    candidate,
  };
}

function validatedAuthorizationReport(
  metrics: JsonRecord,
  evaluatedAt: string,
): JsonRecord {
  expectValidatedValue(metrics.schemaVersion, 4, 'metrics schemaVersion');
  expectValidatedValue(metrics.failureClass, null, 'metrics failureClass');
  expectValidatedEmptyArray(metrics.errors, 'metrics errors');
  expectValidatedCanonicalValue(
    metrics.thresholds,
    DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
    'production sample thresholds',
  );
  expectValidatedCanonicalValue(
    metrics.qualityCriteria,
    DEFAULT_VALIDATION_QUALITY_CRITERIA,
    'production quality criteria',
  );
  for (const key of [
    'forecastLedgerRowCount',
    'eligibleForecastCount',
    'decisionLevelForecastCount',
    'outcomeLedgerRowCount',
  ]) {
    expectValidatedPositiveInteger(metrics[key], `metrics ${key}`);
  }
  expectValidatedNonNegativeInteger(
    metrics.excludedForecastCount,
    'metrics excludedForecastCount',
  );
  expectValidatedValue(
    metrics.forecastLedgerRowCount,
    Number(metrics.eligibleForecastCount) +
      Number(metrics.excludedForecastCount),
    'metrics forecast population accounting',
  );
  expectValidatedValue(
    metrics.decisionLevelForecastCount,
    Number(metrics.eligibleForecastCount),
    'metrics decision-level eligible forecast count',
  );
  const excludedForecasts = validatedArray(
    metrics.excludedForecasts,
    'metrics excludedForecasts',
  ).map((value, index) =>
    validatedRecord(value, `metrics excludedForecasts[${index}]`));
  expectValidatedValue(
    excludedForecasts.length,
    Number(metrics.excludedForecastCount),
    'metrics excludedForecasts count',
  );
  const excludedDecisionIds = new Set<string>();
  for (const [index, forecast] of excludedForecasts.entries()) {
    const decisionId = validatedNonEmptyString(
      forecast.decisionId,
      `metrics excludedForecasts[${index}].decisionId`,
    );
    validatedNonEmptyString(
      forecast.reason,
      `metrics excludedForecasts[${index}].reason`,
    );
    if (excludedDecisionIds.has(decisionId)) {
      rejectValidated(
        `metrics excludedForecasts repeats decision ${decisionId}`,
      );
    }
    excludedDecisionIds.add(decisionId);
  }

  const denominator = validatedRecord(
    metrics.opportunityDenominator,
    'opportunityDenominator',
  );
  assertValidatedDenominatorCoverage(denominator);

  const currentStratum = validatedRecord(
    metrics.currentStratum,
    'currentStratum',
  );
  expectValidatedValue(
    currentStratum.status,
    'validated',
    'currentStratum.status',
  );
  expectValidatedValue(
    currentStratum.failureClass,
    null,
    'currentStratum.failureClass',
  );
  expectValidatedValue(
    currentStratum.sampleSufficient,
    true,
    'currentStratum.sampleSufficient',
  );
  expectValidatedValue(
    currentStratum.qualityPassed,
    true,
    'currentStratum.qualityPassed',
  );
  expectValidatedValue(
    currentStratum.policyGateStatus,
    'passed',
    'currentStratum.policyGateStatus',
  );
  expectValidatedValue(
    currentStratum.candidateScoreGateStatus,
    'passed',
    'currentStratum.candidateScoreGateStatus',
  );

  const prospectiveReport = validatedRecord(
    metrics.prospectiveEvaluation,
    'prospectiveEvaluation',
  );
  expectValidatedValue(
    prospectiveReport.schemaVersion,
    2,
    'prospectiveEvaluation.schemaVersion',
  );
  expectValidatedValue(
    prospectiveReport.authority,
    'canonical_release_validation_proof',
    'prospectiveEvaluation.authority',
  );
  expectValidatedValue(
    prospectiveReport.evaluationPurpose,
    'production',
    'prospectiveEvaluation.evaluationPurpose',
  );
  expectValidatedValue(
    prospectiveReport.evaluatedAt,
    evaluatedAt,
    'prospectiveEvaluation.evaluatedAt',
  );
  expectValidatedValue(
    prospectiveReport.proofComplete,
    true,
    'prospectiveEvaluation.proofComplete',
  );
  const proofVerification = validatedRecord(
    prospectiveReport.proofVerification,
    'prospectiveEvaluation.proofVerification',
  );
  expectValidatedValue(
    proofVerification.valid,
    true,
    'prospectiveEvaluation.proofVerification.valid',
  );
  expectValidatedEmptyArray(
    proofVerification.problems,
    'prospectiveEvaluation.proofVerification.problems',
  );

  const prospectiveDecision = validatedRecord(
    prospectiveReport.promotionDecision,
    'prospectiveEvaluation.promotionDecision',
  );
  assertProductionAuthorizationDecision(
    prospectiveDecision,
    'prospectiveEvaluation.promotionDecision',
  );
  const topLevelDecision = validatedRecord(
    metrics.promotionDecision,
    'promotionDecision',
  );
  assertProductionAuthorizationDecision(
    topLevelDecision,
    'promotionDecision',
  );
  expectValidatedCanonicalValue(
    topLevelDecision,
    prospectiveDecision,
    'top-level and prospective promotion decisions',
  );
  return prospectiveReport;
}

function assertValidatedDenominatorCoverage(
  denominator: JsonRecord,
): void {
  expectValidatedValue(
    denominator.present,
    true,
    'opportunityDenominator.present',
  );
  expectValidatedValue(
    denominator.valid,
    true,
    'opportunityDenominator.valid',
  );
  expectValidatedValue(
    denominator.ready,
    true,
    'opportunityDenominator.ready',
  );
  validatedNonEmptyString(
    denominator.currentStratumKey,
    'opportunityDenominator.currentStratumKey',
  );
  validatedNonEmptyString(
    denominator.sourcePolicy,
    'opportunityDenominator.sourcePolicy',
  );
  validatedSha256(
    denominator.contentHash,
    'opportunityDenominator.contentHash',
  );
  const countKeys = [
    'rowCount',
    'capturedCount',
    'upcomingCount',
    'eligibleCount',
    'missedCount',
    'failedCount',
    'terminalCount',
    'unmatchedForecastCount',
    'integrityErrorCount',
  ] as const;
  for (const key of countKeys) {
    expectValidatedNonNegativeInteger(
      denominator[key],
      `opportunityDenominator.${key}`,
    );
  }
  expectValidatedValue(
    denominator.unmatchedForecastCount,
    0,
    'opportunityDenominator.unmatchedForecastCount',
  );
  expectValidatedValue(
    denominator.integrityErrorCount,
    0,
    'opportunityDenominator.integrityErrorCount',
  );
  expectValidatedValue(
    denominator.failedCount,
    0,
    'opportunityDenominator.failedCount',
  );
  expectValidatedValue(
    denominator.missedCount,
    0,
    'opportunityDenominator.missedCount',
  );
  expectValidatedEmptyArray(
    denominator.errors,
    'opportunityDenominator.errors',
  );
  const rows = validatedArray(
    denominator.rows,
    'opportunityDenominator.rows',
  ).map((value, index) =>
    validatedRecord(value, `opportunityDenominator.rows[${index}]`));
  expectValidatedValue(
    rows.length,
    Number(denominator.rowCount),
    'opportunityDenominator row count',
  );
  if (rows.length === 0) {
    rejectValidated('opportunityDenominator has zero authoritative rows');
  }
  const dispositions = [
    'upcoming',
    'eligible',
    'captured',
    'missed',
    'failed',
  ] as const;
  const seenOpportunityIds = new Set<string>();
  const counts = Object.fromEntries(
    dispositions.map((disposition) => [disposition, 0]),
  ) as Record<(typeof dispositions)[number], number>;
  let terminalCount = 0;
  for (const [index, row] of rows.entries()) {
    const label = `opportunityDenominator.rows[${index}]`;
    const opportunityId = validatedSha256(
      row.opportunityId,
      `${label}.opportunityId`,
    );
    validatedSha256(row.stateContentHash, `${label}.stateContentHash`);
    if (seenOpportunityIds.has(opportunityId)) {
      rejectValidated(
        `opportunityDenominator repeats opportunity ${opportunityId}`,
      );
    }
    seenOpportunityIds.add(opportunityId);
    if (
      typeof row.disposition !== 'string' ||
      !dispositions.includes(
        row.disposition as (typeof dispositions)[number],
      )
    ) {
      rejectValidated(`${label}.disposition is invalid`);
    }
    counts[row.disposition as (typeof dispositions)[number]]++;
    if (typeof row.terminal !== 'boolean') {
      rejectValidated(`${label}.terminal must be boolean`);
    }
    if (row.terminal) terminalCount++;
    if (row.disposition === 'captured') {
      validatedNonEmptyString(
        row.capturedDecisionId,
        `${label}.capturedDecisionId`,
      );
      validatedSha256(
        row.capturedContentHash,
        `${label}.capturedContentHash`,
      );
    } else {
      expectValidatedValue(
        row.capturedDecisionId,
        null,
        `${label}.capturedDecisionId`,
      );
      expectValidatedValue(
        row.capturedContentHash,
        null,
        `${label}.capturedContentHash`,
      );
    }
  }
  for (const disposition of dispositions) {
    expectValidatedValue(
      denominator[`${disposition}Count`],
      Number(counts[disposition]),
      `opportunityDenominator.${disposition}Count`,
    );
  }
  expectValidatedValue(
    denominator.terminalCount,
    Number(terminalCount),
    'opportunityDenominator.terminalCount',
  );
  expectValidatedValue(
    rows.length,
    dispositions.reduce(
      (total, disposition) => total + counts[disposition],
      0,
    ),
    'opportunityDenominator disposition partition',
  );
}

function assertValidatedOpportunityCoverage(
  coverage: ReleaseValidationOpportunityProofCoverage,
): void {
  if (
    !coverage.partitionValid ||
    coverage.authoritativeOpportunityCount <= 0 ||
    coverage.evaluatedOpportunityCount !==
      coverage.authoritativeOpportunityCount ||
    coverage.observedOpportunityCount !==
      coverage.authoritativeOpportunityCount ||
    coverage.authoritativeObservedOpportunityCount !==
      coverage.authoritativeOpportunityCount ||
    coverage.excludedOpportunityCount !== 0 ||
    coverage.pendingOpportunityCount !== 0 ||
    coverage.missingOpportunityCount !== 0 ||
    coverage.unauthoritativeObservedOpportunityCount !== 0
  ) {
    rejectValidated(
      'canonical opportunity coverage is not fully authoritative and evaluated',
    );
  }
}

function assertProductionAuthorizationDecision(
  decision: JsonRecord,
  label: string,
): void {
  expectValidatedValue(
    decision.decision,
    'authorize_production',
    `${label}.decision`,
  );
  expectValidatedValue(
    decision.productionAuthorized,
    true,
    `${label}.productionAuthorized`,
  );
  expectValidatedValue(
    decision.insufficientAuthorizesProduction,
    false,
    `${label}.insufficientAuthorizesProduction`,
  );
  expectValidatedValue(
    decision.calibrationAuthorizesProduction,
    false,
    `${label}.calibrationAuthorizesProduction`,
  );
  expectValidatedValue(decision.status, 'passed', `${label}.status`);
  expectValidatedValue(
    decision.failureClass,
    null,
    `${label}.failureClass`,
  );
}

function assertValidatedScorePublicationAuthorizations(input: {
  prospectiveReport: JsonRecord;
  bundle: ReleaseValidationProofBundle;
  cohortIds: readonly string[];
}): void {
  const cohortIdSet = new Set(input.cohortIds);
  const forecasts = input.bundle.forecasts.filter((forecast) =>
    cohortIdSet.has(forecast.cohortId));
  if (forecasts.length === 0) {
    rejectValidated('active canonical proof has zero score publications');
  }
  const reported = validatedArray(
    input.prospectiveReport.scorePublicationAuthorizations,
    'prospectiveEvaluation.scorePublicationAuthorizations',
  ).map((value, index) =>
    validatedRecord(
      value,
      `prospectiveEvaluation.scorePublicationAuthorizations[${index}]`,
    ));
  if (reported.length !== forecasts.length) {
    rejectValidated(
      'score publication authorizations do not exactly cover active forecasts',
    );
  }

  for (const forecast of forecasts) {
    const payload = validatedRecord(
      forecast.forecast,
      `canonical forecast ${forecast.forecastId} payload`,
    );
    const legacy = validatedRecord(
      payload.legacyForecast,
      `canonical forecast ${forecast.forecastId} legacy link`,
    );
    const original = validatedRecord(
      payload.originalScorePublication,
      `canonical forecast ${forecast.forecastId} original score publication`,
    );
    const capture = validatedRecord(
      payload.canonicalCapturePublication,
      `canonical forecast ${forecast.forecastId} capture publication`,
    );
    const authorization = validatedRecord(
      original.authorization,
      `canonical forecast ${forecast.forecastId} authorization`,
    );
    const sourceIdentity = validatedRecord(
      original.sourceIdentity,
      `canonical forecast ${forecast.forecastId} source identity`,
    );
    assertAuthorizedScorePublication({
      forecast,
      original,
      capture,
      authorization,
      sourceIdentity,
    });

    const expected = {
      forecastId: forecast.forecastId,
      forecastContentHash: forecast.contentHash,
      decisionId: legacy.decisionId,
      legacyForecastContentHash: legacy.contentHash,
      sourceIdentity,
      ...authorization,
    } satisfies JsonRecord;
    const report = exactValidatedRow(
      reported.filter((row) => row.forecastId === forecast.forecastId),
      `score publication authorization ${forecast.forecastId}`,
    );
    expectValidatedCanonicalValue(
      report,
      expected,
      `score publication authorization ${forecast.forecastId}`,
    );
  }
}

function assertAuthorizedScorePublication(input: {
  forecast: ReleaseValidationProofBundle['forecasts'][number];
  original: JsonRecord;
  capture: JsonRecord;
  authorization: JsonRecord;
  sourceIdentity: JsonRecord;
}): void {
  const label = `canonical forecast ${input.forecast.forecastId}`;
  expectValidatedValue(
    input.authorization.schemaVersion,
    1,
    `${label} authorization schemaVersion`,
  );
  expectValidatedValue(
    input.authorization.source,
    'refresh',
    `${label} authorization source`,
  );
  expectValidatedValue(
    input.authorization.operationReceiptRequired,
    true,
    `${label} operationReceiptRequired`,
  );
  const operationRunId = validatedNonEmptyString(
    input.authorization.operationRunId,
    `${label} operationRunId`,
  );
  expectValidatedValue(
    input.authorization.artifactPublicationRunId,
    operationRunId,
    `${label} artifactPublicationRunId`,
  );

  const terminalReceipt = validatedRecord(
    input.authorization.terminalReceipt,
    `${label} terminalReceipt`,
  );
  expectValidatedValue(
    terminalReceipt.runId,
    operationRunId,
    `${label} terminalReceipt.runId`,
  );
  expectValidatedValue(
    terminalReceipt.status,
    'success',
    `${label} terminalReceipt.status`,
  );
  validatedNonEmptyString(
    terminalReceipt.receiptId,
    `${label} terminalReceipt.receiptId`,
  );
  validatedSha256(
    terminalReceipt.contentHash,
    `${label} terminalReceipt.contentHash`,
  );

  const scoreHistory = validatedRecord(
    input.authorization.scoreHistory,
    `${label} scoreHistory`,
  );
  const scoreAuthority = validatedRecord(
    input.authorization.scoreAuthority,
    `${label} scoreAuthority`,
  );
  for (const [key, value] of [
    ['historyRunId', scoreHistory.runId],
    ['historyRunContentHash', scoreHistory.contentHash],
    ['authorityRunId', scoreAuthority.runId],
    ['authorityRunContentHash', scoreAuthority.contentHash],
    [
      'historyV2SealContentHash',
      scoreAuthority.historyV2SealContentHash,
    ],
  ] as const) {
    const expected = key.endsWith('Id')
      ? validatedNonEmptyString(value, `${label} ${key}`)
      : validatedSha256(value, `${label} ${key}`);
    expectValidatedValue(
      input.capture[key],
      expected,
      `${label} capture ${key}`,
    );
  }

  const scoreCommit = validatedRecord(
    input.original.scoreCommit,
    `${label} scoreCommit`,
  );
  for (const key of [
    'historyRunId',
    'historyRunContentHash',
    'authorityRunId',
    'authorityRunContentHash',
    'historyV2SealContentHash',
  ]) {
    expectValidatedValue(
      scoreCommit[key],
      input.capture[key],
      `${label} scoreCommit.${key}`,
    );
  }

  const artifactSource = assertValidatedSourceIdentity(
    input.sourceIdentity,
    label,
  );
  const publication = parseValidatedArtifactPublication(
    input.authorization.releaseArtifacts,
    label,
  );
  const semanticReceipts = validatedArtifactSemanticReceipts(
    input.authorization.releaseArtifactReceipts,
    label,
  );
  if (
    publication.linkCount === 0 ||
    artifactSource.count !== publication.linkCount ||
    semanticReceipts.length !== publication.linkCount
  ) {
    rejectValidated(
      `${label} artifact publication is not exactly represented in source identity`,
    );
  }
  expectValidatedValue(
    artifactSource.digest,
    releaseArtifactSemanticSourceDigest(semanticReceipts),
    `${label} artifact source digest`,
  );
  assertArtifactPublicationSemanticBinding(
    publication.links as unknown as readonly JsonRecord[],
    semanticReceipts,
    label,
  );
  assertArtifactPublicationCandidateCoverage(
    publication.links as unknown as readonly JsonRecord[],
    input.forecast.candidates,
    label,
  );
}

function assertValidatedSourceIdentity(
  sourceIdentity: JsonRecord,
  label: string,
): JsonRecord {
  expectValidatedValue(
    sourceIdentity.schemaVersion,
    17,
    `${label} source identity schemaVersion`,
  );
  expectValidatedValue(
    sourceIdentity.sourceMode,
    'current_db',
    `${label} source identity sourceMode`,
  );
  expectValidatedValue(
    sourceIdentity.scope,
    'score_input_database',
    `${label} source identity scope`,
  );
  expectValidatedValue(
    sourceIdentity.algorithm,
    'sha256',
    `${label} source identity algorithm`,
  );
  const codeRevision = validatedNonEmptyString(
    sourceIdentity.codeRevision,
    `${label} source identity codeRevision`,
  );
  const effectiveScoringConfig = validatedRecord(
    sourceIdentity.effectiveScoringConfig,
    `${label} source identity effectiveScoringConfig`,
  );
  const effectiveScoringConfigDigest = validatedSha256(
    sourceIdentity.effectiveScoringConfigDigest,
    `${label} source identity effectiveScoringConfigDigest`,
  );
  const sources = validatedArray(
    sourceIdentity.sources,
    `${label} source identity sources`,
  ).map((value, index) =>
    validatedRecord(value, `${label} source identity sources[${index}]`));
  if (
    sources.length === 0 ||
    new Set(sources.map((source) => source.source)).size !== sources.length
  ) {
    rejectValidated(`${label} source identity sources are incomplete`);
  }
  let rowCount = 0;
  for (const source of sources) {
    validatedNonEmptyString(source.source, `${label} source name`);
    if (
      typeof source.count !== 'number' ||
      !Number.isInteger(source.count) ||
      source.count < 0
    ) {
      rejectValidated(`${label} source count is invalid`);
    }
    rowCount += source.count;
    validatedSha256(source.digest, `${label} source digest`);
  }
  expectValidatedValue(
    sourceIdentity.sourceCount,
    sources.length,
    `${label} source identity sourceCount`,
  );
  expectValidatedValue(
    sourceIdentity.rowCount,
    rowCount,
    `${label} source identity rowCount`,
  );
  expectValidatedValue(
    sourceIdentity.digest,
    scoreSourceIdentityManifestDigest(
      sources as unknown as Parameters<
        typeof scoreSourceIdentityManifestDigest
      >[0],
      17,
      {
        codeRevision,
        effectiveScoringConfig:
          effectiveScoringConfig as unknown as NonNullable<
            Parameters<typeof scoreSourceIdentityManifestDigest>[2]
          >['effectiveScoringConfig'],
        effectiveScoringConfigDigest,
      },
    ),
    `${label} source identity digest`,
  );
  return exactValidatedRow(
    sources.filter((source) => source.source === 'release_artifact_receipts'),
    `${label} release_artifact_receipts source`,
  );
}

function parseValidatedArtifactPublication(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
) {
  try {
    return parseReleaseArtifactPublication(value);
  } catch (error) {
    rejectValidated(
      `${label} artifact publication is invalid: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function validatedArtifactSemanticReceipts(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): JsonRecord[] {
  return validatedArray(value, `${label} releaseArtifactReceipts`)
    .map((row, index) => {
      const receipt = validatedRecord(
        row,
        `${label} releaseArtifactReceipts[${index}]`,
      );
      const release = validatedRecord(
        receipt.release,
        `${label} releaseArtifactReceipts[${index}].release`,
      );
      for (const key of [
        'repository',
        'tag',
        'releaseNodeId',
        'catalogTagCommitOid',
        'publishedAt',
      ]) {
        validatedNonEmptyString(
          release[key],
          `${label} artifact receipt release.${key}`,
        );
      }
      validatedNonEmptyString(
        receipt.receiptId,
        `${label} artifact receipt receiptId`,
      );
      validatedSha256(
        receipt.evidenceIdentity,
        `${label} artifact receipt evidenceIdentity`,
      );
      validatedNonEmptyString(
        receipt.evidenceReportIdentity,
        `${label} artifact receipt evidenceReportIdentity`,
      );
      validatedNonEmptyString(
        receipt.canonicalReceiptJson,
        `${label} artifact receipt canonicalReceiptJson`,
      );
      return receipt;
    });
}

function releaseArtifactSemanticSourceDigest(
  receipts: readonly JsonRecord[],
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
  const sorted = receipts.slice().sort((left, right) =>
    artifactReleaseKey(validatedRecord(left.release, 'artifact release'))
      .localeCompare(
        artifactReleaseKey(validatedRecord(right.release, 'artifact release')),
      ));
  for (const receipt of sorted) {
    update([
      'row',
      'release_artifact_receipts',
      'semantic_release_artifact_receipts',
      columns.map((column) =>
        column === 'release'
          ? canonicalArtifactRelease(
              validatedRecord(receipt.release, 'artifact release'),
            )
          : receipt[column]),
    ]);
  }
  return hash.digest('hex');
}

function assertArtifactPublicationSemanticBinding(
  links: readonly JsonRecord[],
  receipts: readonly JsonRecord[],
  label: string,
): void {
  for (const link of links) {
    const receipt = exactValidatedRow(
      receipts.filter((candidate) =>
        candidate.receiptId === link.receiptId),
      `${label} artifact publication receipt ${String(link.receiptId)}`,
    );
    for (const key of [
      'release',
      'receiptId',
      'evidenceIdentity',
      'evidenceReportIdentity',
    ]) {
      expectValidatedCanonicalValue(
        receipt[key],
        link[key],
        `${label} artifact publication ${key}`,
      );
    }
  }
}

function assertArtifactPublicationCandidateCoverage(
  links: readonly JsonRecord[],
  candidates: ReleaseValidationProofBundle['forecasts'][number]['candidates'],
  label: string,
): void {
  if (links.length !== candidates.length) {
    rejectValidated(
      `${label} artifact publication does not exactly cover scored candidates`,
    );
  }
  for (const candidate of candidates) {
    exactValidatedRow(
      links.filter((link) => {
        const release = validatedRecord(
          link.release,
          `${label} artifact publication release`,
        );
        return release.repository === candidate.repository &&
          release.releaseNodeId === candidate.nodeId &&
          release.catalogTagCommitOid === candidate.tagCommitOid &&
          release.publishedAt === candidate.publishedAt &&
          candidate.aliases.includes(String(release.tag ?? ''));
      }),
      `${label} artifact publication candidate ${candidate.releaseId}`,
    );
  }
}

function artifactReleaseKey(release: JsonRecord): string {
  const canonical = canonicalArtifactRelease(release);
  return [
    canonical.repository,
    canonical.tag,
    canonical.releaseNodeId,
    canonical.catalogTagCommitOid,
    canonical.publishedAt,
  ].join('\0');
}

function canonicalArtifactRelease(release: JsonRecord): JsonRecord {
  return {
    repository: release.repository,
    tag: release.tag,
    releaseNodeId: release.releaseNodeId,
    catalogTagCommitOid: release.catalogTagCommitOid,
    publishedAt: release.publishedAt,
  };
}

function validatedProofEvidence(input: {
  bundle: ReleaseValidationProofBundle;
  cohorts: readonly ReleaseValidationProofBundle['cohorts'][number][];
  evaluatedAt: string;
}): ValidatedProofEvidence {
  const evaluatedAtMs = Date.parse(input.evaluatedAt);
  const policiesById = new Map(
    input.bundle.policies.map((policy) => [policy.policyId, policy]),
  );
  const batches = input.bundle.observationBatches.filter((batch) =>
    Date.parse(batch.observedAt) <= evaluatedAtMs);
  const cohortEvidence = input.cohorts.map((cohort) => {
    const policy = policiesById.get(cohort.policyId);
    if (!policy) {
      rejectValidated(
        `active cohort ${cohort.cohortId} has no canonical policy`,
      );
    }
    const cohortForecasts = input.bundle.forecasts.filter((forecast) =>
      forecast.cohortId === cohort.cohortId);
    if (cohortForecasts.length === 0) {
      rejectValidated(
        `active cohort ${cohort.cohortId} has zero canonical forecasts`,
      );
    }
    const cells = cohort.requiredCellIds.map((cellId) => {
      const cell = policy.requiredCells.find((row) => row.cellId === cellId);
      if (!cell) {
        rejectValidated(
          `active cohort ${cohort.cohortId} is missing required cell ${cellId}`,
        );
      }
      const obligations = input.bundle.obligations.filter((obligation) =>
        obligation.cohortId === cohort.cohortId &&
        obligation.cellId === cellId);
      if (obligations.length === 0) {
        rejectValidated(
          `required cell ${cohort.cohortId}:${cellId} has zero obligations`,
        );
      }
      const cases = obligations.map((obligation) => {
        if (Date.parse(obligation.recordedAt) > evaluatedAtMs) {
          rejectValidated(
            `required cell ${cohort.cohortId}:${cellId} has future evidence`,
          );
        }
        const assignment = exactValidatedRow(
          input.bundle.splitAssignments.filter((row) =>
            row.obligationId === obligation.obligationId),
          `split assignment for obligation ${obligation.obligationId}`,
        );
        const forecast = exactValidatedRow(
          input.bundle.forecasts.filter((row) =>
            row.obligationId === obligation.obligationId),
          `forecast for obligation ${obligation.obligationId}`,
        );
        if (Date.parse(forecast.recordedAt) > evaluatedAtMs) {
          rejectValidated(
            `forecast ${forecast.forecastId} postdates the evaluation`,
          );
        }
        const outcome = exactValidatedRow(
          input.bundle.outcomes.filter((row) =>
            row.forecastId === forecast.forecastId),
          `outcome for forecast ${forecast.forecastId}`,
        );
        if (
          Date.parse(outcome.observedAt) > evaluatedAtMs ||
          !['safe', 'adverse'].includes(outcome.status)
        ) {
          rejectValidated(
            `forecast ${forecast.forecastId} lacks a terminal outcome by ` +
            input.evaluatedAt,
          );
        }
        const coveringBatchIds = batches
          .filter((batch) =>
            batch.cohortId === cohort.cohortId &&
            batch.cells.some((batchCell) =>
              batchCell.obligationId === obligation.obligationId &&
              batchCell.forecastId === forecast.forecastId &&
              batchCell.outcomeId === outcome.outcomeId &&
              batchCell.disposition === 'observed'))
          .map((batch) => batch.batchId);
        if (coveringBatchIds.length === 0) {
          rejectValidated(
            `outcome ${outcome.outcomeId} is absent from canonical ` +
            `observation batches`,
          );
        }
        return {
          obligation,
          assignment,
          forecast,
          outcome,
          observationBatchIds: coveringBatchIds,
          legacyDecisionId: validatedLegacyDecisionId(forecast.forecast),
        };
      });
      const decisionIds = cases.map((row) => row.legacyDecisionId);
      if (new Set(decisionIds).size !== decisionIds.length) {
        rejectValidated(
          `required cell ${cohort.cohortId}:${cellId} reuses a legacy ` +
          `decision`,
        );
      }
      return {
        cellId,
        opportunityCode: cell.opportunityCode,
        horizonCode: cell.horizonCode,
        cases,
      };
    });
    for (const cell of cells) {
      assertProofMinimums(
        cell.cases,
        DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
        `required cell ${cohort.cohortId}:${cell.cellId}`,
      );
      const developmentCases = cell.cases.filter((row) =>
        row.assignment.arm !== 'holdout');
      const holdoutCases = cell.cases.filter((row) =>
        row.assignment.arm === 'holdout');
      if (developmentCases.length === 0 || holdoutCases.length === 0) {
        rejectValidated(
          `required cell ${cohort.cohortId}:${cell.cellId} lacks the ` +
          `canonical development/holdout split`,
        );
      }
      assertProofMinimums(
        holdoutCases,
        scaledHoldoutMinimums(),
        `required cell ${cohort.cohortId}:${cell.cellId} holdout`,
      );
    }
    const linkedDecisionIds = new Set(
      cohortForecasts.map((forecast) =>
        validatedLegacyDecisionId(forecast.forecast)),
    );
    return {
      cohort,
      policy,
      purpose: policy.developmentArm,
      cohortKey:
        `${cohort.modelVersion}/prompt-${cohort.promptVersion}/` +
        `revision-${cohort.codeRevision}`,
      canonicalForecastCount: cohortForecasts.length,
      linkedDecisionCount: linkedDecisionIds.size,
      cells,
    };
  });
  const productionCohortCount = cohortEvidence.filter((row) =>
    row.purpose === 'production').length;
  if (productionCohortCount === 0) {
    rejectValidated('canonical proof has no active production cohort');
  }
  const obligationsById = new Map(
    input.bundle.obligations.map((row) => [row.obligationId, row]),
  );
  const splitAssignmentKeys = input.bundle.splitAssignments.map((assignment) => {
    const obligation = obligationsById.get(assignment.obligationId);
    if (!obligation) {
      rejectValidated(
        `split assignment ${assignment.assignmentId} has no obligation`,
      );
    }
    return `${assignment.cohortId}\0${obligation.release.releaseId}`;
  });
  return {
    cohorts: cohortEvidence,
    productionCohortCount,
    calibrationCohortCount:
      cohortEvidence.length - productionCohortCount,
    splitAssignmentCount: new Set(splitAssignmentKeys).size,
  };
}

function assertProofMinimums(
  cases: readonly ValidatedEvidenceCase[],
  minimums: typeof DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
  label: string,
): void {
  const counts = {
    independent: cases.length,
    uniqueReleases: new Set(
      cases.map((row) => row.obligation.release.releaseId),
    ).size,
    recommended: cases.filter((row) =>
      row.forecast.selectedReleaseId !== null).length,
    withheld: cases.filter((row) =>
      row.forecast.selectedReleaseId === null).length,
    adverse: cases.filter((row) => row.outcome.status === 'adverse').length,
    safe: cases.filter((row) => row.outcome.status === 'safe').length,
  };
  for (const key of Object.keys(minimums) as Array<keyof typeof minimums>) {
    if (counts[key] < minimums[key]) {
      rejectValidated(
        `${label} has ${counts[key]} ${key} evidence; ` +
        `${minimums[key]} required`,
      );
    }
  }
}

function scaledHoldoutMinimums(): typeof DEFAULT_VALIDATION_SAMPLE_THRESHOLDS {
  return Object.fromEntries(
    Object.entries(DEFAULT_VALIDATION_SAMPLE_THRESHOLDS).map(
      ([key, value]) => [key, value === 0 ? 0 : Math.ceil(value / 2)],
    ),
  ) as unknown as typeof DEFAULT_VALIDATION_SAMPLE_THRESHOLDS;
}

function assertValidatedReportProofBinding(input: {
  prospectiveReport: JsonRecord;
  evidence: ValidatedProofEvidence;
  proofEpochId: string;
  evaluatedAt: string;
  cohortIds: readonly string[];
  requiredCellKeys: readonly string[];
  observationBatchIds: readonly string[];
  outcomeIds: readonly string[];
}): void {
  expectValidatedExactStringSet(
    input.prospectiveReport.activeProofEpochIds,
    [input.proofEpochId],
    'prospectiveEvaluation.activeProofEpochIds',
  );
  expectValidatedExactStringSet(
    input.prospectiveReport.activeCohortIds,
    input.cohortIds,
    'prospectiveEvaluation.activeCohortIds',
  );
  expectValidatedExactStringSet(
    input.prospectiveReport.requiredCellKeys,
    input.requiredCellKeys,
    'prospectiveEvaluation.requiredCellKeys',
  );
  expectValidatedExactStringSet(
    input.prospectiveReport.observationBatchIds,
    input.observationBatchIds,
    'prospectiveEvaluation.observationBatchIds',
  );
  expectValidatedExactStringSet(
    input.prospectiveReport.outcomeIds,
    input.outcomeIds,
    'prospectiveEvaluation.outcomeIds',
  );

  const splitAssignments = validatedRecord(
    input.prospectiveReport.splitAssignments,
    'prospectiveEvaluation.splitAssignments',
  );
  expectValidatedValue(
    splitAssignments.source,
    'canonical_obligation_assignments',
    'prospectiveEvaluation.splitAssignments.source',
  );
  expectValidatedValue(
    splitAssignments.persisted,
    true,
    'prospectiveEvaluation.splitAssignments.persisted',
  );
  expectValidatedValue(
    splitAssignments.expectedAssignmentCount,
    input.evidence.splitAssignmentCount,
    'prospectiveEvaluation.splitAssignments.expectedAssignmentCount',
  );
  expectValidatedValue(
    splitAssignments.persistedAssignmentCount,
    input.evidence.splitAssignmentCount,
    'prospectiveEvaluation.splitAssignments.persistedAssignmentCount',
  );
  expectValidatedEmptyArray(
    splitAssignments.missingAssignmentKeys,
    'prospectiveEvaluation.splitAssignments.missingAssignmentKeys',
  );
  expectValidatedEmptyArray(
    splitAssignments.extraAssignmentKeys,
    'prospectiveEvaluation.splitAssignments.extraAssignmentKeys',
  );
  expectValidatedEmptyArray(
    splitAssignments.errors,
    'prospectiveEvaluation.splitAssignments.errors',
  );

  const summary = validatedRecord(
    input.prospectiveReport.productionSummary,
    'prospectiveEvaluation.productionSummary',
  );
  expectValidatedValue(
    summary.activeCohortCount,
    input.evidence.cohorts.length,
    'prospectiveEvaluation.productionSummary.activeCohortCount',
  );
  expectValidatedValue(
    summary.productionCohortCount,
    input.evidence.productionCohortCount,
    'prospectiveEvaluation.productionSummary.productionCohortCount',
  );
  expectValidatedValue(
    summary.calibrationCohortCount,
    input.evidence.calibrationCohortCount,
    'prospectiveEvaluation.productionSummary.calibrationCohortCount',
  );
  expectValidatedPositiveInteger(
    summary.currentStratumCohortCount,
    'prospectiveEvaluation.productionSummary.currentStratumCohortCount',
  );
  expectValidatedValue(
    summary.everyActiveCohortPassed,
    true,
    'prospectiveEvaluation.productionSummary.everyActiveCohortPassed',
  );
  expectValidatedValue(
    summary.calibrationExcludedFromAuthorization,
    true,
    'prospectiveEvaluation.productionSummary.' +
      'calibrationExcludedFromAuthorization',
  );

  const cohortReports = validatedArray(
    input.prospectiveReport.cohorts,
    'prospectiveEvaluation.cohorts',
  ).map((value, index) =>
    validatedRecord(value, `prospectiveEvaluation.cohorts[${index}]`));
  if (cohortReports.length !== input.evidence.cohorts.length) {
    rejectValidated(
      'prospectiveEvaluation.cohorts does not exactly cover active cohorts',
    );
  }
  for (const evidence of input.evidence.cohorts) {
    const matches = cohortReports.filter((report) =>
      report.cohortId === evidence.cohort.cohortId);
    const report = exactValidatedRow(
      matches,
      `prospective cohort report ${evidence.cohort.cohortId}`,
    );
    assertValidatedCohortReport(report, evidence, input.evaluatedAt);
  }
}

function assertValidatedCohortReport(
  report: JsonRecord,
  evidence: ValidatedCohortEvidence,
  evaluatedAt: string,
): void {
  const expected = {
    cohortKey: evidence.cohortKey,
    proofEpochId: evidence.cohort.proofEpochId,
    policyId: evidence.cohort.policyId,
    purpose: evidence.purpose,
    startsAt: evidence.cohort.startsAt,
    retiredAt: evidence.cohort.retiredAt,
    requiredCellCount: evidence.cohort.requiredCellCount,
    canonicalForecastCount: evidence.canonicalForecastCount,
    linkedDecisionCount: evidence.linkedDecisionCount,
    status: 'passed',
  } satisfies JsonRecord;
  for (const [key, value] of Object.entries(expected)) {
    expectValidatedValue(report[key], value, `cohort report ${key}`);
  }
  expectValidatedEmptyArray(report.errors, 'cohort report errors');
  const cellReports = validatedArray(
    report.cells,
    `cohort ${evidence.cohort.cohortId} cells`,
  ).map((value, index) =>
    validatedRecord(
      value,
      `cohort ${evidence.cohort.cohortId} cells[${index}]`,
    ));
  if (cellReports.length !== evidence.cells.length) {
    rejectValidated(
      `cohort ${evidence.cohort.cohortId} does not report every required cell`,
    );
  }
  for (const cellEvidence of evidence.cells) {
    const cellReport = exactValidatedRow(
      cellReports.filter((row) => row.cellId === cellEvidence.cellId),
      `required cell report ${evidence.cohort.cohortId}:${cellEvidence.cellId}`,
    );
    expectValidatedValue(
      cellReport.opportunityCode,
      cellEvidence.opportunityCode,
      'required cell opportunityCode',
    );
    expectValidatedValue(
      cellReport.horizonCode,
      cellEvidence.horizonCode,
      'required cell horizonCode',
    );
    expectValidatedValue(cellReport.status, 'passed', 'required cell status');
    expectValidatedValue(
      cellReport.qualityStatus,
      'passed',
      'required cell qualityStatus',
    );
    const coverage = validatedRecord(
      cellReport.coverage,
      'required cell coverage',
    );
    assertValidatedCoverage(
      coverage,
      cellEvidence,
      evidence.cohort,
      evaluatedAt,
    );
    const policy = validatedRecord(
      cellReport.policy,
      'required cell policy evaluation',
    );
    const candidate = validatedRecord(
      cellReport.candidate,
      'required cell candidate evaluation',
    );
    assertPassedQualitySection(policy, 'policy');
    assertPassedQualitySection(candidate, 'candidate');
    assertPolicyCasesBindProof(policy, cellEvidence, evidence.cohort);
    assertCandidateCasesBindProof(candidate, cellEvidence);
  }
}

function assertValidatedCoverage(
  coverage: JsonRecord,
  evidence: ValidatedCellEvidence,
  cohort: ReleaseValidationProofBundle['cohorts'][number],
  evaluatedAt: string,
): void {
  expectValidatedValue(coverage.status, 'passed', 'cell coverage status');
  expectValidatedValue(
    coverage.obligationCount,
    evidence.cases.length,
    'cell coverage obligationCount',
  );
  expectValidatedValue(
    coverage.forecastCount,
    evidence.cases.length,
    'cell coverage forecastCount',
  );
  expectValidatedValue(
    coverage.terminalOutcomeCount,
    evidence.cases.length,
    'cell coverage terminalOutcomeCount',
  );
  for (const key of [
    'censoredCount',
    'captureAttritionCount',
    'overdueCount',
    'pendingCount',
  ]) {
    expectValidatedValue(coverage[key], 0, `cell coverage ${key}`);
  }
  expectValidatedEmptyArray(coverage.errors, 'cell coverage errors');
  const cases = validatedArray(
    coverage.cases,
    'cell coverage cases',
  ).map((value, index) =>
    validatedRecord(value, `cell coverage cases[${index}]`));
  if (cases.length !== evidence.cases.length) {
    rejectValidated('cell coverage case count differs from canonical proof');
  }
  for (const expected of evidence.cases) {
    const actual = exactValidatedRow(
      cases.filter((row) =>
        row.obligationId === expected.obligation.obligationId),
      `coverage case ${expected.obligation.obligationId}`,
    );
    expectValidatedValue(
      actual.releaseId,
      expected.obligation.release.releaseId,
      'coverage case releaseId',
    );
    expectValidatedValue(
      actual.arm,
      expected.assignment.arm,
      'coverage case arm',
    );
    expectValidatedValue(
      actual.forecastId,
      expected.forecast.forecastId,
      'coverage case forecastId',
    );
    expectValidatedValue(
      actual.outcomeId,
      expected.outcome.outcomeId,
      'coverage case outcomeId',
    );
    expectValidatedValue(
      actual.status,
      expected.outcome.status,
      'coverage case status',
    );
    expectValidatedValue(actual.terminal, true, 'coverage case terminal');
    expectValidatedExactStringSet(
      actual.observationBatchIds,
      expected.observationBatchIds,
      'coverage case observationBatchIds',
    );
    if (Date.parse(expected.outcome.observedAt) > Date.parse(evaluatedAt)) {
      rejectValidated(
        `cohort ${cohort.cohortId} coverage includes future outcomes`,
      );
    }
  }
}

function assertPassedQualitySection(
  section: JsonRecord,
  kind: 'policy' | 'candidate',
): void {
  expectValidatedValue(section.present, true, `${kind} evaluation present`);
  const cases = validatedArray(section.cases, `${kind} evaluation cases`);
  if (cases.length === 0) {
    rejectValidated(`${kind} evaluation has zero cases`);
  }
  const nonOverlapping = validatedRecord(
    section.nonOverlappingSensitivity,
    `${kind} non-overlapping sensitivity`,
  );
  assertSufficientSample(
    nonOverlapping.sampleSufficiency,
    DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
    kind,
    `${kind} non-overlapping sample`,
  );
  assertPassedQualityAssessment(
    nonOverlapping.qualityAssessment,
    kind,
    `${kind} non-overlapping quality`,
  );
  const temporal = validatedRecord(
    section.temporalBlocks,
    `${kind} temporal holdout`,
  );
  expectValidatedValue(
    temporal.status,
    'sufficient',
    `${kind} temporal holdout status`,
  );
  expectValidatedValue(
    temporal.qualityStatus,
    'passed',
    `${kind} temporal holdout qualityStatus`,
  );
  expectValidatedValue(
    temporal.splitAssignmentSource,
    'canonical_obligation_assignments',
    `${kind} temporal splitAssignmentSource`,
  );
  expectValidatedValue(
    temporal.splitAssignmentsPersisted,
    true,
    `${kind} temporal splitAssignmentsPersisted`,
  );
  expectValidatedEmptyArray(
    temporal.missingAssignmentKeys,
    `${kind} temporal missingAssignmentKeys`,
  );
  validatedRecord(temporal.development, `${kind} temporal development`);
  const holdout = validatedRecord(
    temporal.holdout,
    `${kind} temporal holdout partition`,
  );
  assertSufficientSample(
    holdout.sampleSufficiency,
    scaledHoldoutMinimums(),
    kind,
    `${kind} temporal holdout sample`,
  );
  assertPassedQualityAssessment(
    holdout.qualityAssessment,
    kind,
    `${kind} temporal holdout quality`,
  );

  const gate = validatedRecord(
    section.gateAnalysis,
    `${kind} gateAnalysis`,
  );
  expectValidatedValue(gate.status, 'passed', `${kind} gate status`);
  for (const key of [
    'nonOverlappingSufficient',
    'nonOverlappingQualityPassed',
    'temporalSufficient',
    'temporalQualityPassed',
  ]) {
    expectValidatedValue(gate[key], true, `${kind} gate ${key}`);
  }
}

function assertSufficientSample(
  value: ReleaseValidationProofJsonValue,
  expectedMinimums: typeof DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
  kind: 'policy' | 'candidate',
  label: string,
): void {
  const sample = validatedRecord(value, label);
  expectValidatedValue(sample.status, 'sufficient', `${label}.status`);
  const counts = validatedRecord(sample.counts, `${label}.counts`);
  const minimums = validatedRecord(sample.minimums, `${label}.minimums`);
  const keys = kind === 'policy'
    ? [
        'independent',
        'uniqueReleases',
        'recommended',
        'withheld',
        'adverse',
        'safe',
      ]
    : ['independent', 'uniqueReleases', 'adverse', 'safe'];
  for (const key of keys) {
    expectValidatedValue(
      minimums[key],
      expectedMinimums[key as keyof typeof expectedMinimums],
      `${label}.minimums.${key}`,
    );
    const count = counts[key];
    if (
      typeof count !== 'number' ||
      !Number.isInteger(count) ||
      count < Number(minimums[key])
    ) {
      rejectValidated(`${label}.counts.${key} is under threshold`);
    }
  }
  if (sample.met !== undefined) {
    const met = validatedRecord(sample.met, `${label}.met`);
    for (const key of keys) {
      expectValidatedValue(met[key], true, `${label}.met.${key}`);
    }
  }
}

function assertPassedQualityAssessment(
  value: ReleaseValidationProofJsonValue,
  kind: 'policy' | 'candidate',
  label: string,
): void {
  const quality = validatedRecord(value, label);
  expectValidatedValue(quality.status, 'passed', `${label}.status`);
  const checks = validatedRecord(quality.checks, `${label}.checks`);
  const expected = kind === 'policy'
    ? {
        recommendationPrecisionLowerBound: {
          boundary: 'minimum',
          value:
            DEFAULT_VALIDATION_QUALITY_CRITERIA
              .recommendationPrecisionLowerBound,
          direction: 'minimum',
        },
        falseSafeUpperBound: {
          boundary: 'maximum',
          value: DEFAULT_VALIDATION_QUALITY_CRITERIA.falseSafeUpperBound,
          direction: 'maximum',
        },
        accuracyLowerBound: {
          boundary: 'minimum',
          value: DEFAULT_VALIDATION_QUALITY_CRITERIA.accuracyLowerBound,
          direction: 'minimum',
        },
        safeVsAdverseAucLowerBound: {
          boundary: 'minimum',
          value: DEFAULT_VALIDATION_QUALITY_CRITERIA.safeVsAdverseAucMinimum,
          direction: 'minimum',
        },
      } as const
    : {
        safeVsAdverseAucLowerBound: {
          boundary: 'minimum',
          value: DEFAULT_VALIDATION_QUALITY_CRITERIA.safeVsAdverseAucMinimum,
          direction: 'minimum',
        },
      } as const;
  for (const [key, contract] of Object.entries(expected)) {
    const check = validatedRecord(checks[key], `${label}.checks.${key}`);
    expectValidatedValue(check.passed, true, `${label}.checks.${key}.passed`);
    expectValidatedValue(
      check[contract.boundary],
      contract.value,
      `${label}.checks.${key}.${contract.boundary}`,
    );
    if (check.applicable !== undefined) {
      expectValidatedValue(
        check.applicable,
        true,
        `${label}.checks.${key}.applicable`,
      );
    }
    const observed = check.observed;
    if (
      typeof observed !== 'number' ||
      !Number.isFinite(observed) ||
      (
        contract.direction === 'minimum'
          ? observed < contract.value
          : observed > contract.value
      )
    ) {
      rejectValidated(`${label}.checks.${key}.observed fails its boundary`);
    }
  }
}

function assertPolicyCasesBindProof(
  section: JsonRecord,
  evidence: ValidatedCellEvidence,
  cohort: ReleaseValidationProofBundle['cohorts'][number],
): void {
  const cases = validatedArray(
    section.cases,
    'policy evaluation cases',
  ).map((value, index) =>
    validatedRecord(value, `policy evaluation cases[${index}]`));
  if (cases.length !== evidence.cases.length) {
    rejectValidated('policy evaluation cases do not cover canonical evidence');
  }
  for (const proofCase of evidence.cases) {
    const reportCase = exactValidatedRow(
      cases.filter((row) => row.decisionId === proofCase.legacyDecisionId),
      `policy case ${proofCase.legacyDecisionId}`,
    );
    expectValidatedValue(
      reportCase.opportunityCode,
      evidence.opportunityCode,
      'policy case opportunityCode',
    );
    expectValidatedValue(
      reportCase.horizonCode,
      evidence.horizonCode,
      'policy case horizonCode',
    );
    expectValidatedValue(
      reportCase.modelVersion,
      cohort.modelVersion,
      'policy case modelVersion',
    );
    expectValidatedValue(
      reportCase.promptVersion,
      cohort.promptVersion,
      'policy case promptVersion',
    );
    expectValidatedValue(
      reportCase.codeRevision,
      cohort.codeRevision,
      'policy case codeRevision',
    );
    expectValidatedValue(
      reportCase.recommended,
      proofCase.forecast.selectedReleaseId !== null,
      'policy case recommended',
    );
    expectValidatedValue(
      reportCase.adverse,
      proofCase.outcome.status === 'adverse',
      'policy case adverse',
    );
    expectValidatedValue(
      reportCase.observedAt,
      proofCase.outcome.observedAt,
      'policy case observedAt',
    );
    expectValidatedValue(
      reportCase.windowStartAt,
      proofCase.forecast.recordedAt,
      'policy case windowStartAt',
    );
    const identity = validatedRecord(
      reportCase.latestReleaseIdentity,
      'policy case latestReleaseIdentity',
    );
    expectValidatedValue(
      identity.nodeId,
      proofCase.obligation.release.nodeId,
      'policy case latestReleaseIdentity.nodeId',
    );
    expectValidatedValue(
      identity.tagCommitOid,
      proofCase.obligation.release.tagCommitOid,
      'policy case latestReleaseIdentity.tagCommitOid',
    );
    expectValidatedValue(
      identity.publishedAt,
      proofCase.obligation.release.publishedAt,
      'policy case latestReleaseIdentity.publishedAt',
    );
    if (
      !proofCase.obligation.release.aliases.includes(
        String(reportCase.releaseTag ?? ''),
      )
    ) {
      rejectValidated('policy case releaseTag is absent from canonical aliases');
    }
    if (
      typeof reportCase.score !== 'number' ||
      !Number.isFinite(reportCase.score)
    ) {
      rejectValidated('policy case score is not finite');
    }
  }
}

function assertCandidateCasesBindProof(
  section: JsonRecord,
  evidence: ValidatedCellEvidence,
): void {
  const expectedDecisionIds = new Set(
    evidence.cases.map((row) => row.legacyDecisionId),
  );
  const cases = validatedArray(
    section.cases,
    'candidate evaluation cases',
  ).map((value, index) =>
    validatedRecord(value, `candidate evaluation cases[${index}]`));
  const observedDecisionIds = new Set<string>();
  for (const reportCase of cases) {
    const decisionId = reportCase.decisionId;
    if (
      typeof decisionId !== 'string' ||
      !expectedDecisionIds.has(decisionId)
    ) {
      rejectValidated('candidate evaluation includes an unknown decision');
    }
    observedDecisionIds.add(decisionId);
    expectValidatedValue(
      reportCase.opportunityCode,
      evidence.opportunityCode,
      'candidate case opportunityCode',
    );
    expectValidatedValue(
      reportCase.horizonCode,
      evidence.horizonCode,
      'candidate case horizonCode',
    );
    if (
      typeof reportCase.score !== 'number' ||
      !Number.isFinite(reportCase.score)
    ) {
      rejectValidated('candidate case score is not finite');
    }
  }
  if (
    observedDecisionIds.size !== expectedDecisionIds.size ||
    [...expectedDecisionIds].some((value) =>
      !observedDecisionIds.has(value))
  ) {
    rejectValidated(
      'candidate evaluation does not cover every canonical decision',
    );
  }
}

function validatedLegacyDecisionId(
  value: ReleaseValidationProofJsonValue,
): string {
  const payload = validatedRecord(value, 'canonical forecast payload');
  const legacy = validatedRecord(
    payload.legacyForecast,
    'canonical forecast legacy link',
  );
  if (
    typeof legacy.decisionId !== 'string' ||
    !legacy.decisionId.trim() ||
    typeof legacy.contentHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(legacy.contentHash)
  ) {
    rejectValidated('canonical forecast legacy link is incomplete');
  }
  return legacy.decisionId;
}

function exactValidatedRow<T>(
  rows: readonly T[],
  label: string,
): T {
  if (rows.length !== 1) {
    rejectValidated(`${label} must exist exactly once; found ${rows.length}`);
  }
  return rows[0];
}

function validatedRecord(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): JsonRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    rejectValidated(`${label} must be a JSON object`);
  }
  return value as JsonRecord;
}

function validatedArray(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): readonly ReleaseValidationProofJsonValue[] {
  if (!Array.isArray(value)) {
    rejectValidated(`${label} must be a JSON array`);
  }
  return value;
}

function expectValidatedEmptyArray(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): void {
  const array = validatedArray(value, label);
  if (array.length !== 0) {
    rejectValidated(`${label} must be empty`);
  }
}

function expectValidatedExactStringSet(
  value: ReleaseValidationProofJsonValue | undefined,
  expected: readonly string[],
  label: string,
): void {
  const actual = validatedArray(value, label);
  if (
    actual.some((item) => typeof item !== 'string') ||
    actual.length !== expected.length ||
    new Set(actual).size !== actual.length ||
    expected.some((item) => !actual.includes(item))
  ) {
    rejectValidated(`${label} does not match the canonical proof`);
  }
}

function expectValidatedPositiveInteger(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): void {
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    rejectValidated(`${label} must be a positive integer`);
  }
}

function expectValidatedNonNegativeInteger(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): void {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    rejectValidated(`${label} must be a non-negative integer`);
  }
}

function validatedNonEmptyString(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): string {
  if (typeof value !== 'string' || !value.trim()) {
    rejectValidated(`${label} must be a non-empty string`);
  }
  return value;
}

function validatedSha256(
  value: ReleaseValidationProofJsonValue | undefined,
  label: string,
): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    rejectValidated(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function expectValidatedCanonicalValue(
  actual: unknown,
  expected: unknown,
  label: string,
): void {
  if (
    canonicalReleaseValidationProofJson(actual) !==
    canonicalReleaseValidationProofJson(expected)
  ) {
    rejectValidated(`${label} does not match the canonical contract`);
  }
}

function expectValidatedValue(
  actual: ReleaseValidationProofJsonValue | undefined,
  expected: ReleaseValidationProofJsonValue,
  label: string,
): void {
  if (actual !== expected) {
    rejectValidated(`${label} must equal ${String(expected)}`);
  }
}

function rejectValidated(problem: string): never {
  throw new Error(
    `Canonical validated evaluation is not production-authorized: ${problem}`,
  );
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

function canonicalMetrics(
  value: ReleaseValidationProofJsonValue,
): ReleaseValidationProofJsonValue {
  return JSON.parse(
    canonicalReleaseValidationProofJson(value),
  ) as ReleaseValidationProofJsonValue;
}

function normalizedTimestamp(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error('Canonical evaluation time is invalid');
  }
  return new Date(timestamp).toISOString();
}

function jsonRecord(
  value: ReleaseValidationProofJsonValue,
  label: string,
): Record<string, ReleaseValidationProofJsonValue> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, ReleaseValidationProofJsonValue>;
}
