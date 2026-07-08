import { normalizeCodeRevision } from './codeRevision';
import {
  releaseValidationForecastTiming,
  type ReleaseValidationForecastLedgerRow,
} from './releaseValidation';
import {
  releaseValidationOpportunityDenominatorCoverage,
  validationCohortKey,
  type ReleaseValidationOpportunityDenominatorLedger,
  type ReleaseValidationOpportunityDisposition,
} from './releaseValidationOpportunityDenominator';

const HOUR_MS = 3_600_000;

export const RELEASE_VALIDATION_OPPORTUNITY_STATUS_SCHEMA_VERSION = 2;

export type ReleaseValidationOpportunityState =
  | 'not_enrolled'
  | 'upcoming'
  | 'open'
  | 'captured'
  | 'missed'
  | 'failed';

export interface ReleaseValidationOpportunityStatusInput {
  now: string;
  denominatorLedger: ReleaseValidationOpportunityDenominatorLedger;
  forecasts: ReleaseValidationForecastLedgerRow[];
  currentSeries: {
    modelVersion: string;
    promptVersion: number;
    codeRevision?: string | null;
  };
  currentAudit?: {
    scoreModelVersion: string;
    promptVersion: number;
    scoredAt: string;
  } | null;
}

export interface ReleaseValidationOpportunityStatus {
  schemaVersion: typeof RELEASE_VALIDATION_OPPORTUNITY_STATUS_SCHEMA_VERSION;
  asOf: string;
  latestRelease: {
    tag: string;
    publishedAt: string;
    ageMs: number;
    ageHours: number;
  } | null;
  currentSeries: {
    key: string;
    modelVersion: string;
    promptVersion: number;
    codeRevision: string;
    ledgerForecastCount: number;
    enrolledOpportunityCount: number;
  };
  currentAudit: {
    present: boolean;
    current: boolean;
    scoreModelVersion: string | null;
    promptVersion: number | null;
    scoredAt: string | null;
  };
  counts: {
    captured: number;
    upcoming: number;
    open: number;
    missed: number;
    failed: number;
    invalidLegacyForecasts: number;
  };
  denominatorLedger: {
    schemaVersion: number;
    sourcePolicy: string;
    contentHash: string;
    rowCount: number;
    counts: Record<ReleaseValidationOpportunityDisposition, number>;
    integrity: ReleaseValidationOpportunityDenominatorLedger['integrity'];
    rows: ReleaseValidationOpportunityDenominatorLedger['rows'];
  };
  overallStatus: ReleaseValidationOpportunityState;
  currentStratum: {
    key: string;
    status: ReleaseValidationOpportunityState;
    denominatorReady: boolean;
    counts: ReleaseValidationOpportunityStatus['counts'];
  };
  nextDeadlineAt: string | null;
  recommendedAction:
    | 'observe_captured_forecasts'
    | 'schedule_verified_refresh_in_window'
    | 'run_verified_refresh_before_deadline'
    | 'refresh_current_model_before_deadline'
    | 'wait_for_next_release'
    | 'repair_denominator_integrity'
    | 'wait_for_prospective_enrollment';
  opportunities: Array<{
    opportunityId: string;
    releaseTag: string;
    releasePublishedAt: string;
    code: string;
    state: ReleaseValidationOpportunityState;
    opensAt: string;
    closesAtExclusive: string;
    enrolledAt: string;
    enrollmentContentHash: string;
    stateContentHash: string;
    timeUntilOpenMs: number | null;
    timeUntilCloseMs: number | null;
    capturedDecisionId: string | null;
    capturedContentHash: string | null;
    failureCount: number;
    failures: ReleaseValidationOpportunityDenominatorLedger['rows'][number]['failures'];
    invalidCurrentSeriesForecastCount: number;
    otherSeriesForecastCount: number;
  }>;
}

export function buildReleaseValidationOpportunityStatus(
  input: ReleaseValidationOpportunityStatusInput,
): ReleaseValidationOpportunityStatus {
  const nowMs = requiredTimestamp(input.now, 'now');
  if (!input.currentSeries.modelVersion.trim() ||
    !Number.isInteger(input.currentSeries.promptVersion)) {
    throw new Error('Current validation model/prompt series is invalid');
  }
  const codeRevision = normalizeCodeRevision(input.currentSeries.codeRevision);
  if (!codeRevision) {
    throw new Error('Current validation code revision is required');
  }
  const currentSeriesKey = validationCohortKey({
    modelVersion: input.currentSeries.modelVersion,
    promptVersion: input.currentSeries.promptVersion,
    codeRevision,
  });
  const isCurrentSeriesForecast = (
    forecast: ReleaseValidationForecastLedgerRow,
  ): boolean =>
    forecast.score_model_version === input.currentSeries.modelVersion &&
    forecast.prompt_version === input.currentSeries.promptVersion &&
    normalizeCodeRevision(forecast.code_revision) === codeRevision;
  const currentSeriesForecasts = input.forecasts.filter(isCurrentSeriesForecast);
  const coverage = releaseValidationOpportunityDenominatorCoverage({
    ledger: input.denominatorLedger,
    forecasts: currentSeriesForecasts,
    currentModelVersion: input.currentSeries.modelVersion,
    currentPromptVersion: input.currentSeries.promptVersion,
    currentCodeRevision: codeRevision,
  });
  const rows = coverage.rows;
  const opportunities = rows.map((row) => {
    const matchingCurrent = currentSeriesForecasts.filter((forecast) =>
      forecast.latest_release_tag === row.releaseTag &&
      forecast.opportunity_code === row.opportunityCode);
    const invalidCurrentSeriesForecastCount = matchingCurrent.filter((forecast) =>
      forecast.latest_release_published_at !== row.releasePublishedAt ||
      !releaseValidationForecastTiming(forecast).valid).length;
    const otherSeriesForecastCount = input.forecasts.filter((forecast) =>
      forecast.latest_release_tag === row.releaseTag &&
      forecast.opportunity_code === row.opportunityCode &&
      !isCurrentSeriesForecast(forecast)).length;
    const state = dispositionState(row.disposition);
    return {
      opportunityId: row.opportunityId,
      releaseTag: row.releaseTag,
      releasePublishedAt: row.releasePublishedAt,
      code: row.opportunityCode,
      state,
      opensAt: row.opensAt,
      closesAtExclusive: row.closesAtExclusive,
      enrolledAt: row.enrolledAt,
      enrollmentContentHash: row.enrollmentContentHash,
      stateContentHash: row.stateContentHash,
      timeUntilOpenMs: state === 'upcoming'
        ? Date.parse(row.opensAt) - nowMs
        : null,
      timeUntilCloseMs: state === 'open'
        ? Date.parse(row.closesAtExclusive) - nowMs
        : null,
      capturedDecisionId: row.capturedDecisionId,
      capturedContentHash: row.capturedContentHash,
      failureCount: row.failureCount,
      failures: row.failures,
      invalidCurrentSeriesForecastCount,
      otherSeriesForecastCount,
    };
  });
  const counts = {
    captured: opportunities.filter((row) => row.state === 'captured').length,
    upcoming: opportunities.filter((row) => row.state === 'upcoming').length,
    open: opportunities.filter((row) => row.state === 'open').length,
    missed: opportunities.filter((row) => row.state === 'missed').length,
    failed: opportunities.filter((row) => row.state === 'failed').length,
    invalidLegacyForecasts: input.forecasts.filter((forecast) =>
      !releaseValidationForecastTiming(forecast).valid).length,
  };
  const overallStatus: ReleaseValidationOpportunityState =
    !coverage.valid || counts.failed > 0
      ? 'failed'
      : counts.open > 0
        ? 'open'
        : counts.missed > 0
          ? 'missed'
          : counts.upcoming > 0
            ? 'upcoming'
            : counts.captured > 0
              ? 'captured'
              : 'not_enrolled';
  const latestRow = rows.slice().sort((left, right) =>
    Date.parse(right.releasePublishedAt) - Date.parse(left.releasePublishedAt) ||
    right.releaseTag.localeCompare(left.releaseTag))[0] ?? null;
  if (latestRow && Date.parse(latestRow.releasePublishedAt) > nowMs) {
    throw new Error('Latest enrolled release publication time is in the future');
  }
  const currentAudit = input.currentAudit ?? null;
  const auditCurrent = currentAudit != null &&
    currentAudit.scoreModelVersion === input.currentSeries.modelVersion &&
    currentAudit.promptVersion === input.currentSeries.promptVersion &&
    Number.isFinite(Date.parse(currentAudit.scoredAt));
  const open = opportunities.find((row) => row.state === 'open');
  const upcoming = opportunities
    .filter((row) => row.state === 'upcoming')
    .sort((left, right) =>
      Date.parse(left.opensAt) - Date.parse(right.opensAt))[0];
  const recommendedAction =
    overallStatus === 'failed'
      ? 'repair_denominator_integrity'
      : open
        ? auditCurrent
          ? 'run_verified_refresh_before_deadline'
          : 'refresh_current_model_before_deadline'
        : upcoming
          ? 'schedule_verified_refresh_in_window'
          : counts.missed > 0
            ? 'wait_for_next_release'
            : counts.captured > 0
              ? 'observe_captured_forecasts'
              : 'wait_for_prospective_enrollment';

  return {
    schemaVersion: RELEASE_VALIDATION_OPPORTUNITY_STATUS_SCHEMA_VERSION,
    asOf: new Date(nowMs).toISOString(),
    latestRelease: latestRow ? {
      tag: latestRow.releaseTag,
      publishedAt: latestRow.releasePublishedAt,
      ageMs: nowMs - Date.parse(latestRow.releasePublishedAt),
      ageHours: (nowMs - Date.parse(latestRow.releasePublishedAt)) / HOUR_MS,
    } : null,
    currentSeries: {
      key: currentSeriesKey,
      modelVersion: input.currentSeries.modelVersion,
      promptVersion: input.currentSeries.promptVersion,
      codeRevision,
      ledgerForecastCount: currentSeriesForecasts.length,
      enrolledOpportunityCount: rows.length,
    },
    currentAudit: {
      present: currentAudit != null,
      current: auditCurrent,
      scoreModelVersion: currentAudit?.scoreModelVersion ?? null,
      promptVersion: currentAudit?.promptVersion ?? null,
      scoredAt: currentAudit?.scoredAt ?? null,
    },
    counts,
    denominatorLedger: {
      schemaVersion: input.denominatorLedger.schemaVersion,
      sourcePolicy: input.denominatorLedger.sourcePolicy,
      contentHash: input.denominatorLedger.contentHash,
      rowCount: rows.length,
      counts: {
        upcoming: coverage.upcomingCount,
        eligible: coverage.eligibleCount,
        captured: coverage.capturedCount,
        missed: coverage.missedCount,
        failed: coverage.failedCount,
      },
      integrity: input.denominatorLedger.integrity,
      rows,
    },
    overallStatus,
    currentStratum: {
      key: currentSeriesKey,
      status: overallStatus,
      denominatorReady: coverage.ready,
      counts,
    },
    nextDeadlineAt: open?.closesAtExclusive ?? upcoming?.opensAt ?? null,
    recommendedAction,
    opportunities,
  };
}

export function releaseValidationOpportunityStatusExitCode(
  report: ReleaseValidationOpportunityStatus,
): number {
  if (report.overallStatus === 'failed') return 1;
  if (report.overallStatus === 'open') return 3;
  if (report.overallStatus === 'missed') return 4;
  if (
    report.overallStatus === 'upcoming' ||
    report.overallStatus === 'not_enrolled'
  ) return 2;
  return 0;
}

function dispositionState(
  disposition: ReleaseValidationOpportunityDisposition,
): ReleaseValidationOpportunityState {
  return disposition === 'eligible' ? 'open' : disposition;
}

function requiredTimestamp(value: string, label: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${label} must be a valid timestamp`);
  }
  return timestamp;
}
