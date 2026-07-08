import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  assertReleaseValidationObservationBatchRetryEquivalent,
  releaseValidationObservationBatchForecastInputs,
  releaseValidationObservationBatchReport,
  stageReleaseValidationObservationBatchReceipt,
  stageReleaseValidationOutcomeRows,
  verifyReleaseValidationObservationBatchLedger,
} from '../../src/lib/releaseValidationBatch.ts';
import {
  validateReleaseValidationLedgerIntegrity,
} from '../../src/lib/releaseValidation.ts';
import {
  planReleaseValidationProofObservation,
} from '../../src/lib/releaseValidationProofObservation.ts';

export function assertObservationBatchRetryEquivalent(row, input) {
  assertReleaseValidationObservationBatchRetryEquivalent(row, input);
}

export function summarizeObservationForecastCoverage(results, forecastCount) {
  const byDecision = new Map();
  for (const result of results) {
    const rows = byDecision.get(result.decisionId) ?? [];
    rows.push(result);
    byDecision.set(result.decisionId, rows);
  }
  let eligibleForecastCount = 0;
  let excludedForecastCount = 0;
  let partiallyExcludedForecastCount = 0;
  let observedForecastCount = 0;
  let pendingForecastCount = 0;
  for (const rows of byDecision.values()) {
    const excludedCount = rows.filter((row) =>
      row.status === 'excluded').length;
    if (excludedCount === rows.length) excludedForecastCount++;
    else if (excludedCount === 0) eligibleForecastCount++;
    else partiallyExcludedForecastCount++;
    if (rows.some((row) =>
      row.status === 'matured' || row.status === 'indeterminate')) {
      observedForecastCount++;
    }
    if (rows.some((row) => row.status === 'pending')) {
      pendingForecastCount++;
    }
  }
  const missingForecastCount = Math.max(0, forecastCount - byDecision.size);
  const extraForecastCount = Math.max(0, byDecision.size - forecastCount);
  return {
    schemaVersion: 1,
    authoritativeForecastCount: forecastCount,
    evaluatedForecastCount: byDecision.size,
    observedForecastCount,
    eligibleForecastCount,
    excludedForecastCount,
    partiallyExcludedForecastCount,
    pendingForecastCount,
    missingForecastCount,
    extraForecastCount,
    partitionValid:
      eligibleForecastCount +
        excludedForecastCount +
        partiallyExcludedForecastCount +
        missingForecastCount === forecastCount &&
      extraForecastCount === 0,
  };
}

export async function runObserveOutcomes(args = process.argv.slice(2)) {
const options = parseArgs(args);

const {
  commitReleaseValidationObservationBatch,
  appendReleaseValidationProof,
  db,
  getMeta,
  getReleaseValidationObservationBatch,
  listAuthorizedReleaseValidationAdvisorySnapshots,
  listReleaseValidationForecasts,
  listReleaseValidationObservationBatches,
  listReleaseValidationOutcomeObservations,
  listReleaseScoreAuditHistoryV2Seals,
  listScoreAuthorityResolutionRuns,
  readReleaseValidationProofBundle,
  runInWriteTransaction,
  scoreSourceIdentity,
} = await import('../../src/lib/db.ts');
const {
  RELEASE_VALIDATION_HORIZONS,
  assessReleaseValidationObservation,
  buildIndependentFieldEvidenceSnapshot,
  buildReleaseValidationIndeterminatePayload,
  releaseValidationDecisionSchemaVersion,
  releaseValidationForecastTiming,
  releaseValidationObservationTargets,
} = await import('../../src/lib/releaseValidation.ts');
const { codeRevisionFromEnv } = await import('../../src/lib/codeRevision.ts');
const { config } = await import('../../src/config.ts');

const batchId = options.batchId ?? `validation-observe:${randomUUID()}`;
const codeRevision = codeRevisionFromEnv();
if (!codeRevision) {
  throw new Error('validation:observe requires a deterministic code revision');
}

const forecasts = listReleaseValidationForecasts();
const forecastInputs = releaseValidationObservationBatchForecastInputs(forecasts);
const existing = listReleaseValidationOutcomeObservations();
const existingBatches = listReleaseValidationObservationBatches();
const existingProof = readReleaseValidationProofBundle();
const auditHistory = db.prepare(`
  SELECT *
  FROM release_score_audit_history
  ORDER BY recorded_at, id
`).all();
const auditHistoryRuns = db.prepare(`
  SELECT *
  FROM release_score_audit_history_runs
  ORDER BY id
`).all();
const authorityRuns = listScoreAuthorityResolutionRuns();
const historyV2Seals = listReleaseScoreAuditHistoryV2Seals();
const currentSourceIdentity = scoreSourceIdentity();
const sourceIdentityDigest = validSourceIdentity(currentSourceIdentity)?.digest;
if (!sourceIdentityDigest) {
  throw new Error('validation:observe requires the current score source identity digest');
}
const issueCrawl = parseJson(getMeta('issue_crawl_last_run'));
const scorePersistence = parseJson(getMeta('score_persistence_last_run'));
const advisorySnapshots = listAuthorizedReleaseValidationAdvisorySnapshots();
const independentFieldSource = {
  issues: db.prepare(`
    SELECT number, state, title, body, author, html_url, created_at, updated_at,
           comments, is_bot, fetched_at
    FROM issues
    ORDER BY created_at, number
  `).all(),
  commentSnapshots: db.prepare(`
    SELECT issue_number, schema_version, fetched_at, verified_at, comment_count,
           fetched_comment_count, latest_comment_updated_at, comments_digest,
           issue_updated_at, comments_json
    FROM issue_comment_snapshots
    ORDER BY issue_number
  `).all(),
  labelEvents: db.prepare(`
    SELECT issue_number, event_id, action, label_name, actor_login, created_at, fetched_at
    FROM issue_label_events
    ORDER BY issue_number, created_at, event_id
  `).all(),
  closureProofs: db.prepare(`
    SELECT proof.issue_number, proof.release_tag, proof.status, proof.summary,
           proof.evidence_json, proof.checked_at,
           release.published_at AS release_published_at,
           release.html_url AS release_url
    FROM issue_closure_proofs proof
    JOIN releases release ON release.tag=proof.release_tag
    ORDER BY proof.issue_number, release.published_at, proof.release_tag
  `).all(),
};
const expectedAdvisoryPackage = {
  ecosystem: 'npm',
  packageName: config.github.repo,
};

assertValidationLedgers({
  forecasts,
  observations: existing,
  batches: existingBatches,
  auditHistory,
  auditHistoryRuns,
  authorityRuns,
  historyV2Seals,
  advisorySnapshots,
  expectedAdvisoryPackage,
  phase: 'existing',
});

const existingBatch = getReleaseValidationObservationBatch(batchId);
if (existingBatch) {
  assertObservationBatchRetryEquivalent(existingBatch, {
    observedAt: options.observedAt,
    codeRevision,
    sourceIdentityDigest,
    forecastInputs,
  });
  const proofPlan = planReleaseValidationProofObservation({
    bundle: existingProof,
    observedAt: existingBatch.observed_at,
    sourceIdentityHash: sourceIdentityDigest,
    legacyForecasts: forecasts,
    legacyOutcomes: existing,
  });
  const proofPersistence = appendReleaseValidationProof(proofPlan.append);
  finish(existingBatch, 'already_existing', {
    plan: proofPlan,
    persistence: proofPersistence,
  });
} else {
  const observedAt = options.observedAt ?? new Date().toISOString();
  const results = [];
  const intended = [];
  const existingMatured = new Map(
    existing
      .filter((row) => row.status === 'matured')
      .map((row) => [`${row.decision_id}\0${row.horizon_code}`, row]),
  );

  for (const forecast of forecasts) {
    const decisionSchemaVersion = releaseValidationDecisionSchemaVersion(forecast);
    const timing = releaseValidationForecastTiming(forecast);
    const observationTargets = releaseValidationObservationTargets(forecast);
    for (const horizonCode of Object.keys(RELEASE_VALIDATION_HORIZONS)) {
      const resultIdentity = {
        decisionId: forecast.decision_id,
        opportunityCode: forecast.opportunity_code,
        targetReleaseTag: forecast.selected_tag ?? forecast.latest_release_tag,
        targetReleaseTags: observationTargets.map((target) => target.targetReleaseTag),
        horizonCode,
      };
      if (decisionSchemaVersion !== 4) {
        results.push({
          ...resultIdentity,
          status: 'excluded',
          persistence: 'not_applicable',
          reason: 'forecast_decision_schema_not_evaluable',
          decisionSchemaVersion,
        });
        continue;
      }
      if (!timing.valid) {
        results.push({
          ...resultIdentity,
          status: 'excluded',
          persistence: 'not_applicable',
          reason: 'forecast_timing_invalid',
          timing,
        });
        continue;
      }

      const key = `${forecast.decision_id}\0${horizonCode}`;
      const existingForHorizon = existing.filter((row) =>
        row.decision_id === forecast.decision_id && row.horizon_code === horizonCode);
      const matured = existingMatured.get(key);
      if (matured) {
        const payload = parseJson(matured.outcome_json);
        results.push({
          ...resultIdentity,
          status: 'matured',
          persistence: 'already_existing',
          observationId: matured.observation_id,
          observationContentHash: matured.content_hash,
          ...(typeof payload?.adverse === 'boolean' ? { adverse: payload.adverse } : {}),
        });
        continue;
      }
      const terminalIndeterminate = existingForHorizon
        .filter((row) => row.status === 'indeterminate')
        .map((row) => ({ row, payload: parseJson(row.outcome_json) }))
        .find((item) =>
          item.payload?.reason === 'observation_grace_window_missed' &&
          item.payload?.terminal === true);
      if (terminalIndeterminate) {
        results.push({
          ...resultIdentity,
          status: 'indeterminate',
          persistence: 'already_existing',
          fatal: terminalIndeterminate.payload.fatal === true,
          reason: terminalIndeterminate.payload.reason,
          observationId: terminalIndeterminate.row.observation_id,
          observationContentHash: terminalIndeterminate.row.content_hash,
        });
        continue;
      }

      const horizonEndAt = new Date(
        Date.parse(forecast.recorded_at) +
        RELEASE_VALIDATION_HORIZONS[horizonCode].durationMs,
      ).toISOString();
      const fieldEvidenceCapturedAt =
        typeof scorePersistence?.persistedAt === 'string'
          ? scorePersistence.persistedAt
          : null;
      const fieldEvidenceCapturedAtMs = Date.parse(fieldEvidenceCapturedAt ?? '');
      const independentFieldEvidence =
        horizonCode === 'field_regression_72h' &&
        Number.isFinite(fieldEvidenceCapturedAtMs) &&
        fieldEvidenceCapturedAtMs >= Date.parse(horizonEndAt) &&
        fieldEvidenceCapturedAtMs <= Date.parse(observedAt)
          ? observationTargets.map((target) =>
              buildIndependentFieldEvidenceSnapshot({
                forecast,
                targetReleaseTag: target.targetReleaseTag,
                horizonEndAt,
                capturedAt: fieldEvidenceCapturedAt,
                ...independentFieldSource,
              }))
          : null;
      const assessment = assessReleaseValidationObservation({
        forecast,
        horizonCode,
        now: observedAt,
        auditHistory,
        currentSourceIdentity,
        issueCrawl,
        scorePersistence,
        advisorySnapshots,
        independentFieldEvidence,
        expectedAdvisoryPackage,
      });
      if (assessment.status === 'pending') {
        results.push({
          ...resultIdentity,
          ...assessment,
          persistence: 'not_applicable',
        });
        continue;
      }
      if (assessment.status === 'indeterminate') {
        const duplicate = existingForHorizon
          .filter((row) => row.status === 'indeterminate')
          .map((row) => ({ row, payload: parseJson(row.outcome_json) }))
          .find((item) => item.payload?.reason === assessment.reason);
        if (duplicate) {
          results.push({
            ...resultIdentity,
            ...assessment,
            persistence: 'already_existing',
            observationId: duplicate.row.observation_id,
            observationContentHash: duplicate.row.content_hash,
          });
          continue;
        }
        const currentIdentity = validSourceIdentity(currentSourceIdentity);
        const forecastIdentity = validSourceIdentity(parseJson(forecast.source_identity_json));
        const sourceIdentity = currentIdentity ?? forecastIdentity;
        if (!sourceIdentity) {
          throw new Error(
            `Cannot persist indeterminate validation outcome without a source identity for ` +
            `${forecast.decision_id}`,
          );
        }
        const payload = buildReleaseValidationIndeterminatePayload({
          forecast,
          assessment,
          observedAt,
          sourceIdentityFallback: currentIdentity == null,
        });
        const resultIndex = results.length;
        results.push({
          ...resultIdentity,
          ...assessment,
          persistence: 'inserted',
        });
        intended.push({
          resultIndex,
          input: {
            decision_id: forecast.decision_id,
            horizon_code: horizonCode,
            observed_at: observedAt,
            status: 'indeterminate',
            outcome_json: JSON.stringify(payload),
            source_identity_json: JSON.stringify(sourceIdentity),
          },
        });
        continue;
      }

      const resultIndex = results.length;
      results.push({
        ...resultIdentity,
        status: 'matured',
        persistence: 'inserted',
        adverse: assessment.outcome.adverse,
      });
      intended.push({
        resultIndex,
        input: {
          decision_id: forecast.decision_id,
          horizon_code: horizonCode,
          observed_at: assessment.observedAt,
          status: 'matured',
          outcome_json: JSON.stringify(assessment.outcome),
          source_identity_json: JSON.stringify(assessment.sourceIdentity),
        },
      });
    }
  }

  const stagedOutcomes = stageReleaseValidationOutcomeRows(
    existing,
    intended.map((item) => item.input),
  );
  for (const [index, staged] of stagedOutcomes.entries()) {
    const result = results[intended[index].resultIndex];
    result.observationId = staged.observation_id;
    result.observationContentHash = staged.content_hash;
  }
  const stagedReceipt = stageReleaseValidationObservationBatchReceipt(
    existingBatches,
    existing,
    stagedOutcomes,
    {
      batchId,
      observedAt,
      codeRevision,
      sourceIdentityDigest,
      forecastCount: forecasts.length,
      forecastInputs,
      results,
    },
  );

  assertValidationLedgers({
    forecasts,
    observations: [...existing, ...stagedOutcomes],
    batches: [...existingBatches, stagedReceipt],
    auditHistory,
    auditHistoryRuns,
    authorityRuns,
    historyV2Seals,
    advisorySnapshots,
    expectedAdvisoryPackage,
    phase: 'proposed',
  });
  if (codeRevisionFromEnv() !== codeRevision) {
    throw new Error('Validation observation code revision changed after staging');
  }

  const proofPlan = planReleaseValidationProofObservation({
    bundle: existingProof,
    observedAt,
    sourceIdentityHash: sourceIdentityDigest,
    legacyForecasts: forecasts,
    legacyOutcomes: [...existing, ...stagedOutcomes],
  });
  const committed = runInWriteTransaction(() => {
    const legacy = commitReleaseValidationObservationBatch({
      outcomes: stagedOutcomes,
      receipt: stagedReceipt,
    });
    const proof = appendReleaseValidationProof(proofPlan.append);
    return { legacy, proof };
  });
  finish(
    committed.legacy.row,
    committed.legacy.inserted ? 'inserted' : 'already_existing',
    {
      plan: proofPlan,
      persistence: committed.proof,
    },
  );
}
}

function finish(receipt, receiptPersistence, canonicalProof = null) {
  const report = {
    ...releaseValidationObservationBatchReport(receipt),
    receiptPersistence,
    canonicalProof: canonicalProof
      ? {
          insertedCount: canonicalProof.persistence.insertedCount,
          equivalentCount: canonicalProof.persistence.equivalentCount,
          insertedOutcomeCount:
            canonicalProof.persistence.insertedByType.outcomes,
          insertedBatchCount:
            canonicalProof.persistence.insertedByType.observationBatches,
          captures: canonicalProof.plan.captures,
          opportunityCoverage: canonicalProof.plan.coverage,
        }
      : null,
  };
  const results = report.results;
  report.forecastCoverage = summarizeObservationForecastCoverage(
    results,
    report.forecastCount,
  );
  report.eligibleForecastCount =
    report.forecastCoverage.eligibleForecastCount;
  report.excludedForecastCount =
    report.forecastCoverage.excludedForecastCount;
  report.partiallyExcludedForecastCount =
    report.forecastCoverage.partiallyExcludedForecastCount;
  report.observedForecastCount =
    report.forecastCoverage.observedForecastCount;
  report.missingForecastCount =
    report.forecastCoverage.missingForecastCount;
  report.insertedMaturedCount = results.filter((row) =>
    row.status === 'matured' && row.persistence === 'inserted').length;
  report.insertedIndeterminateCount = results.filter((row) =>
    row.status === 'indeterminate' && row.persistence === 'inserted').length;
  report.graceMissedCount = results.filter((row) =>
    row.status === 'indeterminate' &&
    row.reason === 'observation_grace_window_missed').length;
  report.fatalIndeterminateCount = results.filter((row) =>
    row.status === 'indeterminate' && row.fatal === true).length;
  console.log(JSON.stringify(report, null, 2));
  if (report.fatalIndeterminateCount > 0) process.exitCode = 1;
  else if (report.indeterminateCount > 0) process.exitCode = 2;
}

function assertValidationLedgers(input) {
  const integrity = validateReleaseValidationLedgerIntegrity({
    forecasts: input.forecasts,
    observations: input.observations,
    auditHistory: input.auditHistory,
    auditHistoryRuns: input.auditHistoryRuns,
    authorityRuns: input.authorityRuns,
    historyV2Seals: input.historyV2Seals,
    advisorySnapshots: input.advisorySnapshots,
    expectedAdvisoryPackage: input.expectedAdvisoryPackage,
  });
  const batchIntegrity = verifyReleaseValidationObservationBatchLedger({
    outcomes: input.observations,
    batches: input.batches,
  });
  if (!integrity.ok || batchIntegrity.failedCount > 0) {
    throw new Error(
      `Refusing to append validation outcomes because the ${input.phase} immutable ledger is corrupt: ` +
      [...integrity.errors, ...batchIntegrity.problems].join('; '),
    );
  }
}

function parseArgs(args) {
  const parsed = {
    batchId: null,
    observedAt: null,
  };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--batch-id') {
      parsed.batchId = requiredValue(args, ++index, arg).trim();
      if (!parsed.batchId || /[\u0000-\u0020\u007f]/.test(parsed.batchId)) {
        throw new Error('--batch-id must be a non-empty printable token');
      }
    } else if (arg === '--observed-at') {
      parsed.observedAt = requiredValue(args, ++index, arg);
      if (!Number.isFinite(Date.parse(parsed.observedAt))) {
        throw new Error('--observed-at must be a valid ISO timestamp');
      }
    } else {
      throw new Error(
        'Usage: validation:observe [--batch-id <id>] [--observed-at <ISO timestamp>]',
      );
    }
  }
  return parsed;
}

function requiredValue(args, index, flag) {
  const value = args[index];
  if (!value || value.startsWith('--')) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parseJson(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function validSourceIdentity(value) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    typeof value.digest === 'string' && value.digest
    ? value
    : null;
}

const entryUrl = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : null;
if (entryUrl === import.meta.url) {
  await runObserveOutcomes();
}
