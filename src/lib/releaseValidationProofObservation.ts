import {
  canonicalReleaseValidationProofJson,
  sealReleaseValidationObservationBatch,
  sealReleaseValidationOutcomeV2,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationForecastV2,
  type ReleaseValidationObservationBatch,
  type ReleaseValidationOutcomeV2,
  type ReleaseValidationProofBundle,
  type ReleaseValidationProofJsonValue,
} from './releaseValidationProof';
import type {
  ReleaseValidationForecastLedgerRow,
  ReleaseValidationOutcomeLedgerRow,
} from './releaseValidation';
import {
  buildReleaseValidationOpportunityProofCoverage,
  type ReleaseValidationOpportunityProofCoverage,
} from './releaseValidationOpportunityProofCoverage';

export interface ReleaseValidationProofObservationCapture {
  cohortId: string;
  batchId: string;
  batchContentHash: string;
  status: 'inserted' | 'already_captured';
  insertedOutcomeIds: string[];
  observedOutcomeIds: string[];
  pendingForecastIds: string[];
}

export interface ReleaseValidationProofObservationPlan {
  append: {
    outcomes: ReleaseValidationOutcomeV2[];
    observationBatches: ReleaseValidationObservationBatch[];
  };
  captures: ReleaseValidationProofObservationCapture[];
  coverage: ReleaseValidationOpportunityProofCoverage;
  candidate: ReleaseValidationProofBundle;
}

export function planReleaseValidationProofObservation(input: {
  bundle: ReleaseValidationProofBundle;
  observedAt: string;
  sourceIdentityHash: string;
  legacyForecasts: readonly ReleaseValidationForecastLedgerRow[];
  legacyOutcomes: readonly ReleaseValidationOutcomeLedgerRow[];
}): ReleaseValidationProofObservationPlan {
  const verification = verifyReleaseValidationProofBundle(input.bundle);
  if (!verification.valid) {
    throw new Error(
      `Cannot observe canonical validation outcomes with an invalid proof ` +
      `ledger: ${verification.problems.join('; ')}`,
    );
  }
  const observedAtMs = Date.parse(input.observedAt);
  if (!Number.isFinite(observedAtMs)) {
    throw new Error('Canonical validation observation time is invalid');
  }
  const observedAt = new Date(observedAtMs).toISOString();
  if (!/^[0-9a-f]{64}$/.test(input.sourceIdentityHash)) {
    throw new Error(
      'Canonical validation observation requires a source identity hash',
    );
  }

  const legacyForecastsByDecision = uniqueBy(
    input.legacyForecasts,
    (row) => row.decision_id,
    'legacy validation forecast decision',
  );
  const obligationsById = new Map(
    input.bundle.obligations.map((row) => [row.obligationId, row]),
  );
  const existingOutcomesByForecast = groupBy(
    input.bundle.outcomes.filter((row) =>
      requiredTimestamp(
        row.observedAt,
        `canonical outcome ${row.outcomeId}`,
      ) <= observedAtMs),
    (row) => row.forecastId,
  );
  const allExistingOutcomesByForecast = groupBy(
    input.bundle.outcomes,
    (row) => row.forecastId,
  );
  const legacyOutcomesByCell = groupBy(
    input.legacyOutcomes,
    (row) => `${row.decision_id}\0${row.horizon_code}`,
  );
  const newOutcomes: ReleaseValidationOutcomeV2[] = [];
  const newBatches: ReleaseValidationObservationBatch[] = [];
  const captures: ReleaseValidationProofObservationCapture[] = [];
  const workingOutcomes = [...input.bundle.outcomes];
  const workingBatches = [...input.bundle.observationBatches];

  for (const cohort of [...input.bundle.cohorts].sort((left, right) =>
    left.epochSequence - right.epochSequence ||
    left.cohortId.localeCompare(right.cohortId))) {
    const forecasts = input.bundle.forecasts
      .filter((row) =>
        row.cohortId === cohort.cohortId &&
        requiredTimestamp(
          row.recordedAt,
          `canonical forecast ${row.forecastId}`,
        ) <= observedAtMs)
      .sort((left, right) =>
        left.cohortSequence - right.cohortSequence ||
        left.forecastId.localeCompare(right.forecastId));
    if (forecasts.length === 0) continue;

    const existingBatches = workingBatches.filter((row) =>
      row.cohortId === cohort.cohortId &&
      row.observedAt === observedAt &&
      row.sourceIdentityHash === input.sourceIdentityHash);
    if (existingBatches.length > 1) {
      throw new Error(
        `Canonical validation cohort ${cohort.cohortId} has duplicate ` +
        `observation batches for the same immutable capture`,
      );
    }
    if (existingBatches.length === 1) {
      const existing = existingBatches[0];
      const cells = canonicalObservationCells({
        forecasts,
        obligationsById,
        outcomes: workingOutcomes,
        observedAt: existing.observedAt,
      });
      const replay = sealReleaseValidationObservationBatch({
        proofEpochId: existing.proofEpochId,
        cohortId: existing.cohortId,
        cohortSequence: existing.cohortSequence,
        previousCohortContentHash: existing.previousCohortContentHash,
        observedAt: existing.observedAt,
        sourceIdentityHash: existing.sourceIdentityHash,
        expectedObligationIds: forecasts.map((row) => row.obligationId),
        cells,
      });
      if (
        canonicalReleaseValidationProofJson(replay) !==
        canonicalReleaseValidationProofJson(existing)
      ) {
        throw new Error(
          `Canonical validation observation batch ${existing.batchId} ` +
          `differs from its exact retry`,
        );
      }
      captures.push(observationCapture(
        existing,
        [],
        cells,
        'already_captured',
      ));
      continue;
    }

    let nextSequence = maximumCohortSequence(
      {
        ...input.bundle,
        outcomes: workingOutcomes,
        observationBatches: workingBatches,
      },
      cohort.cohortId,
    );
    let cohortTip = currentCohortTip(
      {
        ...input.bundle,
        outcomes: workingOutcomes,
        observationBatches: workingBatches,
      },
      cohort.cohortId,
    );
    const insertedOutcomes: ReleaseValidationOutcomeV2[] = [];
    const cells: Array<{
      obligationId: string;
      forecastId: string;
      outcomeId: string | null;
      disposition: 'observed' | 'pending';
    }> = [];

    for (const forecast of forecasts) {
      const obligation = obligationsById.get(forecast.obligationId);
      if (!obligation || obligation.cohortId !== cohort.cohortId) {
        throw new Error(
          `Canonical forecast ${forecast.forecastId} has no exact obligation`,
        );
      }
      const existing = existingOutcomesByForecast.get(forecast.forecastId) ?? [];
      if (existing.length > 1) {
        throw new Error(
          `Canonical forecast ${forecast.forecastId} has multiple outcomes`,
        );
      }
      if (existing.length === 1) {
        cells.push(observedCell(forecast, existing[0]));
        continue;
      }

      const legacyLink = canonicalLegacyForecastLink(forecast);
      const legacyForecast = legacyForecastsByDecision.get(
        legacyLink.decisionId,
      );
      if (
        !legacyForecast ||
        legacyForecast.content_hash !== legacyLink.contentHash ||
        requiredTimestamp(
          legacyForecast.recorded_at,
          `legacy forecast ${legacyLink.decisionId}`,
        ) > observedAtMs
      ) {
        throw new Error(
          `Canonical forecast ${forecast.forecastId} does not have its exact ` +
          `legacy forecast evidence as of ${observedAt}`,
        );
      }
      const evidence = terminalLegacyObservation(
        legacyOutcomesByCell.get(
          `${legacyLink.decisionId}\0${obligation.horizonCode}`,
        ) ?? [],
        observedAtMs,
      );
      if (
        observedAtMs < Date.parse(obligation.outcomeDueAt) ||
        !evidence
      ) {
        cells.push(pendingCell(forecast));
        continue;
      }
      const futureCanonicalOutcomes =
        allExistingOutcomesByForecast.get(forecast.forecastId) ?? [];
      if (futureCanonicalOutcomes.length > 0) {
        throw new Error(
          `Cannot backfill canonical forecast ${forecast.forecastId} at ` +
          `${observedAt}; a later canonical outcome already exists`,
        );
      }

      const parsed = parseLegacyOutcome(evidence);
      const status = evidence.status === 'matured'
        ? parsed.adverse === true
          ? 'adverse'
          : 'safe'
        : 'censored';
      const outcome = sealReleaseValidationOutcomeV2({
        proofEpochId: cohort.proofEpochId,
        cohortId: cohort.cohortId,
        cohortSequence: ++nextSequence,
        previousCohortContentHash: cohortTip,
        forecastId: forecast.forecastId,
        obligationId: obligation.obligationId,
        cellId: obligation.cellId,
        releaseId: obligation.release.releaseId,
        observedAt,
        status,
        evidenceContentHashes: [requiredHash(
          evidence.content_hash,
          `legacy observation ${evidence.observation_id}`,
        )],
        outcome: canonicalOutcomePayload({
          forecast,
          legacyLink,
          evidence,
          parsed,
          sourceIdentityHash: input.sourceIdentityHash,
        }),
      });
      cohortTip = outcome.contentHash;
      insertedOutcomes.push(outcome);
      newOutcomes.push(outcome);
      workingOutcomes.push(outcome);
      existingOutcomesByForecast.set(forecast.forecastId, [outcome]);
      cells.push(observedCell(forecast, outcome));
    }

    const batch = sealReleaseValidationObservationBatch({
      proofEpochId: cohort.proofEpochId,
      cohortId: cohort.cohortId,
      cohortSequence: ++nextSequence,
      previousCohortContentHash: cohortTip,
      observedAt,
      sourceIdentityHash: input.sourceIdentityHash,
      expectedObligationIds: forecasts.map((row) => row.obligationId),
      cells,
    });
    newBatches.push(batch);
    workingBatches.push(batch);
    captures.push(observationCapture(
      batch,
      insertedOutcomes,
      cells,
      'inserted',
    ));
  }

  const candidate = {
    ...input.bundle,
    outcomes: workingOutcomes,
    observationBatches: workingBatches,
  };
  const candidateVerification = verifyReleaseValidationProofBundle(candidate);
  if (!candidateVerification.valid) {
    throw new Error(
      `Canonical validation observation plan is invalid: ` +
      candidateVerification.problems.join('; '),
    );
  }
  return {
    append: {
      outcomes: newOutcomes,
      observationBatches: newBatches,
    },
    captures,
    coverage: buildReleaseValidationOpportunityProofCoverage({
      bundle: candidate,
      asOf: observedAt,
    }),
    candidate,
  };
}

function canonicalObservationCells(input: {
  forecasts: ReleaseValidationForecastV2[];
  obligationsById: Map<string, { obligationId: string }>;
  outcomes: ReleaseValidationOutcomeV2[];
  observedAt: string;
}) {
  const observedAtMs = requiredTimestamp(
    input.observedAt,
    'canonical observation batch',
  );
  const outcomesByForecast = groupBy(
    input.outcomes.filter((row) =>
      requiredTimestamp(
        row.observedAt,
        `canonical outcome ${row.outcomeId}`,
      ) <= observedAtMs),
    (row) => row.forecastId,
  );
  return input.forecasts.map((forecast) => {
    if (!input.obligationsById.has(forecast.obligationId)) {
      throw new Error(
        `Canonical forecast ${forecast.forecastId} has no exact obligation`,
      );
    }
    const outcomes = outcomesByForecast.get(forecast.forecastId) ?? [];
    if (outcomes.length > 1) {
      throw new Error(
        `Canonical forecast ${forecast.forecastId} has multiple outcomes`,
      );
    }
    return outcomes.length === 1
      ? observedCell(forecast, outcomes[0])
      : pendingCell(forecast);
  });
}

function canonicalLegacyForecastLink(forecast: ReleaseValidationForecastV2): {
  decisionId: string;
  contentHash: string;
} {
  const payload = jsonRecord(
    forecast.forecast,
    `canonical forecast ${forecast.forecastId} payload`,
  );
  const legacy = jsonRecord(
    payload.legacyForecast,
    `canonical forecast ${forecast.forecastId} legacy link`,
  );
  const decisionId = requiredString(legacy.decisionId, 'legacy decision ID');
  const contentHash = requiredHash(
    legacy.contentHash,
    `legacy forecast ${decisionId}`,
  );
  return { decisionId, contentHash };
}

function terminalLegacyObservation(
  rows: ReleaseValidationOutcomeLedgerRow[],
  observedAtMs: number,
): ReleaseValidationOutcomeLedgerRow | null {
  const ordered = rows
    .filter((row) =>
      requiredTimestamp(
        row.observed_at,
        `legacy observation ${row.observation_id}`,
      ) <= observedAtMs &&
      (row.status === 'matured' || row.status === 'indeterminate'))
    .slice()
    .sort((left, right) =>
      Number(left.status === 'matured') - Number(right.status === 'matured') ||
      Date.parse(left.observed_at) - Date.parse(right.observed_at) ||
      String(left.content_hash).localeCompare(String(right.content_hash)));
  for (let index = ordered.length - 1; index >= 0; index--) {
    const row = ordered[index];
    if (
      row.status === 'matured' ||
      parseLegacyOutcome(row).terminal === true
    ) {
      return row;
    }
  }
  return null;
}

function parseLegacyOutcome(
  row: ReleaseValidationOutcomeLedgerRow,
): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(row.outcome_json);
  } catch (error) {
    throw new Error(
      `Legacy observation ${row.observation_id} has invalid outcome JSON`,
      { cause: error },
    );
  }
  return jsonRecord(value, `legacy observation ${row.observation_id}`);
}

function canonicalOutcomePayload(input: {
  forecast: ReleaseValidationForecastV2;
  legacyLink: { decisionId: string; contentHash: string };
  evidence: ReleaseValidationOutcomeLedgerRow;
  parsed: Record<string, unknown>;
  sourceIdentityHash: string;
}): ReleaseValidationProofJsonValue {
  const payload = {
    schemaVersion: 1,
    canonicalForecastId: input.forecast.forecastId,
    sourceIdentityHash: input.sourceIdentityHash,
    legacyForecast: input.legacyLink,
    legacyObservation: {
      observationId: input.evidence.observation_id,
      contentHash: input.evidence.content_hash,
      status: input.evidence.status,
      observedAt: input.evidence.observed_at,
      ...(typeof input.parsed.adverse === 'boolean'
        ? { adverse: input.parsed.adverse }
        : {}),
      ...(typeof input.parsed.reason === 'string'
        ? { reason: input.parsed.reason }
        : {}),
      ...(input.parsed.terminal === true ? { terminal: true } : {}),
      ...(input.parsed.fatal === true ? { fatal: true } : {}),
    },
  };
  return JSON.parse(
    canonicalReleaseValidationProofJson(payload),
  ) as ReleaseValidationProofJsonValue;
}

function observedCell(
  forecast: ReleaseValidationForecastV2,
  outcome: ReleaseValidationOutcomeV2,
) {
  return {
    obligationId: forecast.obligationId,
    forecastId: forecast.forecastId,
    outcomeId: outcome.outcomeId,
    disposition: 'observed' as const,
  };
}

function pendingCell(forecast: ReleaseValidationForecastV2) {
  return {
    obligationId: forecast.obligationId,
    forecastId: forecast.forecastId,
    outcomeId: null,
    disposition: 'pending' as const,
  };
}

function observationCapture(
  batch: ReleaseValidationObservationBatch,
  insertedOutcomes: ReleaseValidationOutcomeV2[],
  cells: Array<{
    forecastId: string;
    outcomeId: string | null;
    disposition: 'observed' | 'pending';
  }>,
  status: 'inserted' | 'already_captured',
): ReleaseValidationProofObservationCapture {
  return {
    cohortId: batch.cohortId,
    batchId: batch.batchId,
    batchContentHash: batch.contentHash,
    status,
    insertedOutcomeIds: insertedOutcomes.map((row) => row.outcomeId),
    observedOutcomeIds: cells.flatMap((cell) =>
      cell.outcomeId ? [cell.outcomeId] : []),
    pendingForecastIds: cells
      .filter((cell) => cell.disposition === 'pending')
      .map((cell) => cell.forecastId),
  };
}

function currentCohortTip(
  bundle: ReleaseValidationProofBundle,
  cohortId: string,
): string | null {
  const verification = verifyReleaseValidationProofBundle(bundle);
  if (!verification.valid) {
    throw new Error(
      `Cannot derive canonical validation cohort tip: ` +
      verification.problems.join('; '),
    );
  }
  return verification.cohortChainTips[cohortId] ?? null;
}

function maximumCohortSequence(
  bundle: ReleaseValidationProofBundle,
  cohortId: string,
): number {
  return Math.max(0, ...[
    ...bundle.obligations,
    ...bundle.splitAssignments,
    ...bundle.forecasts,
    ...bundle.outcomes,
    ...bundle.observationBatches,
  ].filter((row) => row.cohortId === cohortId)
    .map((row) => row.cohortSequence));
}

function uniqueBy<T>(
  rows: readonly T[],
  keyOf: (row: T) => string,
  label: string,
): Map<string, T> {
  const result = new Map<string, T>();
  for (const row of rows) {
    const key = keyOf(row);
    if (result.has(key)) {
      throw new Error(`Duplicate ${label} ${JSON.stringify(key)}`);
    }
    result.set(key, row);
  }
  return result;
}

function groupBy<T>(
  rows: readonly T[],
  keyOf: (row: T) => string,
): Map<string, T[]> {
  const result = new Map<string, T[]>();
  for (const row of rows) {
    const key = keyOf(row);
    const matches = result.get(key) ?? [];
    matches.push(row);
    result.set(key, matches);
  }
  return result;
}

function jsonRecord(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requiredHash(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 string`);
  }
  return value;
}

function requiredTimestamp(value: string, label: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${label} timestamp is invalid`);
  }
  return timestamp;
}
