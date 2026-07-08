import { createHash } from 'node:crypto';
import {
  canonicalReleaseValidationProofJson,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof';

export const RELEASE_VALIDATION_OPPORTUNITY_PROOF_COVERAGE_SCHEMA_VERSION =
  1 as const;

export type ReleaseValidationOpportunityEvidenceDisposition =
  | 'evaluated'
  | 'excluded'
  | 'pending'
  | 'missing';

export interface ReleaseValidationOpportunityProofCoverageRow {
  cohortId: string;
  cohortPurpose: 'production' | 'calibration';
  obligationId: string;
  cellId: string;
  opportunityCode: string;
  horizonCode: string;
  forecastId: string | null;
  outcomeId: string | null;
  outcomeStatus: 'safe' | 'adverse' | 'censored' | null;
  observationBatchIds: string[];
  observed: boolean;
  authoritativeObservation: boolean;
  disposition: ReleaseValidationOpportunityEvidenceDisposition;
  reason:
    | 'terminal_outcome'
    | 'censored_outcome'
    | 'capture_window_open'
    | 'forecast_missing_after_close'
    | 'outcome_pending'
    | 'outcome_missing_after_due'
    | 'observation_batch_missing';
}

export interface ReleaseValidationOpportunityProofCoverage {
  schemaVersion:
    typeof RELEASE_VALIDATION_OPPORTUNITY_PROOF_COVERAGE_SCHEMA_VERSION;
  asOf: string;
  denominatorSource: 'canonical_release_validation_obligations';
  cohortIds: string[];
  authoritativeOpportunityCount: number;
  forecastedOpportunityCount: number;
  observedOpportunityCount: number;
  authoritativeObservedOpportunityCount: number;
  evaluatedOpportunityCount: number;
  excludedOpportunityCount: number;
  pendingOpportunityCount: number;
  missingOpportunityCount: number;
  unauthoritativeObservedOpportunityCount: number;
  productionOpportunityCount: number;
  calibrationOpportunityCount: number;
  cutoffExcludedEvidence: {
    obligationCount: number;
    forecastCount: number;
    outcomeCount: number;
    observationBatchCount: number;
  };
  partitionValid: boolean;
  rows: ReleaseValidationOpportunityProofCoverageRow[];
  contentHash: string;
}

export function buildReleaseValidationOpportunityProofCoverage(input: {
  bundle: ReleaseValidationProofBundle;
  asOf: string;
  cohortIds?: readonly string[];
}): ReleaseValidationOpportunityProofCoverage {
  const asOfMs = Date.parse(input.asOf);
  if (!Number.isFinite(asOfMs)) {
    throw new Error('Validation opportunity proof coverage time is invalid');
  }
  const asOf = new Date(asOfMs).toISOString();
  const allCohortIds = new Set(input.bundle.cohorts.map((row) => row.cohortId));
  const cohortIds = input.cohortIds == null
    ? [...allCohortIds]
    : [...new Set(input.cohortIds)];
  for (const cohortId of cohortIds) {
    if (!allCohortIds.has(cohortId)) {
      throw new Error(
        `Validation opportunity proof coverage references unknown cohort ` +
        cohortId,
      );
    }
  }
  cohortIds.sort();
  const cohortIdSet = new Set(cohortIds);
  const policiesById = new Map(
    input.bundle.policies.map((row) => [row.policyId, row]),
  );
  const cohortsById = new Map(
    input.bundle.cohorts.map((row) => [row.cohortId, row]),
  );
  const scopedObligations = input.bundle.obligations.filter((row) =>
    cohortIdSet.has(row.cohortId));
  const scopedForecasts = input.bundle.forecasts.filter((row) =>
    cohortIdSet.has(row.cohortId));
  const scopedOutcomes = input.bundle.outcomes.filter((row) =>
    cohortIdSet.has(row.cohortId));
  const scopedBatches = input.bundle.observationBatches.filter((row) =>
    cohortIdSet.has(row.cohortId));
  const obligations = scopedObligations.filter((row) =>
    requiredTimestamp(row.recordedAt, `obligation ${row.obligationId}`) <=
      asOfMs);
  const forecasts = scopedForecasts.filter((row) =>
    requiredTimestamp(row.recordedAt, `forecast ${row.forecastId}`) <= asOfMs);
  const outcomes = scopedOutcomes.filter((row) =>
    requiredTimestamp(row.observedAt, `outcome ${row.outcomeId}`) <= asOfMs);
  const batches = scopedBatches.filter((row) =>
    requiredTimestamp(row.observedAt, `observation batch ${row.batchId}`) <=
      asOfMs);
  const forecastsByObligation = groupBy(
    forecasts,
    (row) => row.obligationId,
  );
  const outcomesByForecast = groupBy(outcomes, (row) => row.forecastId);
  const rows = obligations
    .slice()
    .sort((left, right) =>
      left.cohortId.localeCompare(right.cohortId) ||
      left.cellId.localeCompare(right.cellId) ||
      Date.parse(left.release.publishedAt) -
        Date.parse(right.release.publishedAt) ||
      left.obligationId.localeCompare(right.obligationId))
    .map((obligation): ReleaseValidationOpportunityProofCoverageRow => {
      const cohort = cohortsById.get(obligation.cohortId);
      const policy = cohort ? policiesById.get(cohort.policyId) : null;
      if (!cohort || !policy) {
        throw new Error(
          `Validation opportunity ${obligation.obligationId} has no exact ` +
          `cohort policy`,
        );
      }
      const matchingForecasts =
        forecastsByObligation.get(obligation.obligationId) ?? [];
      if (matchingForecasts.length > 1) {
        throw new Error(
          `Validation opportunity ${obligation.obligationId} has multiple ` +
          `canonical forecasts as of ${asOf}`,
        );
      }
      const forecast = matchingForecasts[0] ?? null;
      if (!forecast) {
        const pending =
          asOfMs < requiredTimestamp(
            obligation.closesAtExclusive,
            `obligation ${obligation.obligationId} close`,
          );
        return coverageRow({
          obligation,
          cohortPurpose: policy.developmentArm,
          forecastId: null,
          outcomeId: null,
          outcomeStatus: null,
          observationBatchIds: [],
          observed: false,
          authoritativeObservation: false,
          disposition: pending ? 'pending' : 'missing',
          reason: pending
            ? 'capture_window_open'
            : 'forecast_missing_after_close',
        });
      }

      const matchingOutcomes = outcomesByForecast.get(forecast.forecastId) ?? [];
      if (matchingOutcomes.length > 1) {
        throw new Error(
          `Validation forecast ${forecast.forecastId} has multiple canonical ` +
          `outcomes as of ${asOf}`,
        );
      }
      const outcome = matchingOutcomes[0] ?? null;
      if (!outcome) {
        const pending =
          asOfMs < requiredTimestamp(
            obligation.outcomeDueAt,
            `obligation ${obligation.obligationId} outcome due`,
          );
        return coverageRow({
          obligation,
          cohortPurpose: policy.developmentArm,
          forecastId: forecast.forecastId,
          outcomeId: null,
          outcomeStatus: null,
          observationBatchIds: [],
          observed: false,
          authoritativeObservation: false,
          disposition: pending ? 'pending' : 'missing',
          reason: pending ? 'outcome_pending' : 'outcome_missing_after_due',
        });
      }

      const coveringBatchIds = batches
        .filter((batch) =>
          batch.cohortId === obligation.cohortId &&
          batch.cells.some((cell) =>
            cell.obligationId === obligation.obligationId &&
            cell.forecastId === forecast.forecastId &&
            cell.outcomeId === outcome.outcomeId &&
            cell.disposition === 'observed'))
        .map((batch) => batch.batchId)
        .sort();
      if (coveringBatchIds.length === 0) {
        return coverageRow({
          obligation,
          cohortPurpose: policy.developmentArm,
          forecastId: forecast.forecastId,
          outcomeId: outcome.outcomeId,
          outcomeStatus: outcome.status,
          observationBatchIds: [],
          observed: true,
          authoritativeObservation: false,
          disposition: 'missing',
          reason: 'observation_batch_missing',
        });
      }
      return coverageRow({
        obligation,
        cohortPurpose: policy.developmentArm,
        forecastId: forecast.forecastId,
        outcomeId: outcome.outcomeId,
        outcomeStatus: outcome.status,
        observationBatchIds: coveringBatchIds,
        observed: true,
        authoritativeObservation: true,
        disposition: outcome.status === 'censored'
          ? 'excluded'
          : 'evaluated',
        reason: outcome.status === 'censored'
          ? 'censored_outcome'
          : 'terminal_outcome',
      });
    });
  const counts = dispositionCounts(rows);
  const withoutHash = {
    schemaVersion:
      RELEASE_VALIDATION_OPPORTUNITY_PROOF_COVERAGE_SCHEMA_VERSION,
    asOf,
    denominatorSource:
      'canonical_release_validation_obligations' as const,
    cohortIds,
    authoritativeOpportunityCount: rows.length,
    forecastedOpportunityCount:
      rows.filter((row) => row.forecastId != null).length,
    observedOpportunityCount: rows.filter((row) => row.observed).length,
    authoritativeObservedOpportunityCount:
      rows.filter((row) => row.authoritativeObservation).length,
    evaluatedOpportunityCount: counts.evaluated,
    excludedOpportunityCount: counts.excluded,
    pendingOpportunityCount: counts.pending,
    missingOpportunityCount: counts.missing,
    unauthoritativeObservedOpportunityCount:
      rows.filter((row) => row.observed && !row.authoritativeObservation)
        .length,
    productionOpportunityCount:
      rows.filter((row) => row.cohortPurpose === 'production').length,
    calibrationOpportunityCount:
      rows.filter((row) => row.cohortPurpose === 'calibration').length,
    cutoffExcludedEvidence: {
      obligationCount: scopedObligations.length - obligations.length,
      forecastCount: scopedForecasts.length - forecasts.length,
      outcomeCount: scopedOutcomes.length - outcomes.length,
      observationBatchCount: scopedBatches.length - batches.length,
    },
    partitionValid:
      counts.evaluated + counts.excluded + counts.pending + counts.missing ===
        rows.length,
    rows,
  };
  return {
    ...withoutHash,
    contentHash: coverageContentHash(withoutHash),
  };
}

function coverageRow(input: {
  obligation: ReleaseValidationProofBundle['obligations'][number];
  cohortPurpose: 'production' | 'calibration';
  forecastId: string | null;
  outcomeId: string | null;
  outcomeStatus: 'safe' | 'adverse' | 'censored' | null;
  observationBatchIds: string[];
  observed: boolean;
  authoritativeObservation: boolean;
  disposition: ReleaseValidationOpportunityEvidenceDisposition;
  reason: ReleaseValidationOpportunityProofCoverageRow['reason'];
}): ReleaseValidationOpportunityProofCoverageRow {
  return {
    cohortId: input.obligation.cohortId,
    cohortPurpose: input.cohortPurpose,
    obligationId: input.obligation.obligationId,
    cellId: input.obligation.cellId,
    opportunityCode: input.obligation.opportunityCode,
    horizonCode: input.obligation.horizonCode,
    forecastId: input.forecastId,
    outcomeId: input.outcomeId,
    outcomeStatus: input.outcomeStatus,
    observationBatchIds: input.observationBatchIds,
    observed: input.observed,
    authoritativeObservation: input.authoritativeObservation,
    disposition: input.disposition,
    reason: input.reason,
  };
}

function dispositionCounts(
  rows: ReleaseValidationOpportunityProofCoverageRow[],
): Record<ReleaseValidationOpportunityEvidenceDisposition, number> {
  return Object.fromEntries(
    (['evaluated', 'excluded', 'pending', 'missing'] as const).map(
      (disposition) => [
        disposition,
        rows.filter((row) => row.disposition === disposition).length,
      ],
    ),
  ) as Record<ReleaseValidationOpportunityEvidenceDisposition, number>;
}

function groupBy<T>(
  rows: readonly T[],
  keyFor: (row: T) => string,
): Map<string, T[]> {
  const result = new Map<string, T[]>();
  for (const row of rows) {
    const key = keyFor(row);
    const matches = result.get(key) ?? [];
    matches.push(row);
    result.set(key, matches);
  }
  return result;
}

function coverageContentHash(value: unknown): string {
  return createHash('sha256')
    .update('release-validation-opportunity-proof-coverage-v1\0')
    .update(canonicalReleaseValidationProofJson(value))
    .digest('hex');
}

function requiredTimestamp(value: string, label: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${label} timestamp is invalid`);
  }
  return timestamp;
}
