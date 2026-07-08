import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

async function main(args = process.argv.slice(2)) {
  const options = parseArgs(args);
  if (options.record) {
    if (process.env.RADAR_DB_READ_ONLY === '1') {
      throw new Error(
        'validation:evaluate --record requires a writable database',
      );
    }
  } else {
    process.env.RADAR_DB_READ_ONLY = '1';
  }

  const {
    appendReleaseValidationProof,
    db,
    listAuthorizedReleaseValidationAdvisorySnapshots,
    listRefreshCaptureReceipts,
    listRefreshLeases,
    listRefreshOperationAttempts,
    listRefreshOperationStageEvents,
    listReleaseValidationForecasts,
    listReleaseValidationObservationBatches,
    listReleaseValidationOpportunityEnrollments,
    listReleaseValidationOutcomeObservations,
    listReleaseScoreAuditHistoryV2Seals,
    listScoreAuthorityResolutionRuns,
    readReleaseValidationProofBundle,
    runInReadTransaction,
  } = await import('../../src/lib/db.ts');
  const {
    evaluateReleaseValidationLedger,
    releaseValidationEvaluationExitCode,
    validateReleaseValidationLedgerIntegrity,
  } = await import('../../src/lib/releaseValidation.ts');
  const {
    verifyReleaseValidationObservationBatchLedger,
  } = await import('../../src/lib/releaseValidationBatch.ts');
  const {
    planReleaseValidationProofEvaluation,
  } = await import('../../src/lib/releaseValidationProofEvaluation.ts');
  const { SCORE_MODEL_VERSION } = await import('../../src/lib/score.ts');
  const { PROMPT_VERSION } = await import('../../src/lib/llm.ts');
  const { config } = await import('../../src/config.ts');
  const { codeRevisionFromEnv } = await import('../../src/lib/codeRevision.ts');
  const { buildPersistedOpportunityDenominator } =
    await import('./opportunity-denominator.mjs');

  const generatedAt = options.evaluatedAt ?? new Date().toISOString();
  const source = runInReadTransaction(() =>
    filterScoreQualityEvidenceAsOf({
      advisorySnapshots: listAuthorizedReleaseValidationAdvisorySnapshots(),
      forecasts: listReleaseValidationForecasts(),
      observations: listReleaseValidationOutcomeObservations(),
      observationBatches: listReleaseValidationObservationBatches(),
      enrollments: listReleaseValidationOpportunityEnrollments(),
      attempts: listRefreshOperationAttempts(),
      stageEvents: listRefreshOperationStageEvents(),
      receipts: listRefreshCaptureReceipts(),
      leases: listRefreshLeases(),
      auditHistory: db.prepare(`
        SELECT *
        FROM release_score_audit_history
        ORDER BY recorded_at, id
      `).all(),
      auditHistoryRuns: db.prepare(`
        SELECT *
        FROM release_score_audit_history_runs
        ORDER BY id
      `).all(),
      authorityRuns: listScoreAuthorityResolutionRuns(),
      historyV2Seals: listReleaseScoreAuditHistoryV2Seals(),
      canonicalProof: readReleaseValidationProofBundle(),
    }, generatedAt, {
      includeCurrentLeaseSnapshot: options.evaluatedAt == null,
    }));
  const opportunityDenominatorLedger = buildPersistedOpportunityDenominator({
    asOf: generatedAt,
    enrollments: source.enrollments,
    forecasts: source.forecasts,
    attempts: source.attempts,
    stageEvents: source.stageEvents,
    receipts: source.receipts,
    leases: source.leases,
    auditHistory: source.auditHistory,
  });
  const expectedAdvisoryPackage = {
    ecosystem: 'npm',
    packageName: config.github.repo,
  };
  const integrity = validateReleaseValidationLedgerIntegrity({
    forecasts: source.forecasts,
    observations: source.observations,
    auditHistory: source.auditHistory,
    auditHistoryRuns: source.auditHistoryRuns,
    authorityRuns: source.authorityRuns,
    historyV2Seals: source.historyV2Seals,
    advisorySnapshots: source.advisorySnapshots,
    expectedAdvisoryPackage,
  });
  const observationBatchVerification =
    verifyReleaseValidationObservationBatchLedger({
      outcomes: source.observations,
      batches: source.observationBatches,
    });

  const report = integrity.ok && observationBatchVerification.failedCount === 0
    ? evaluateReleaseValidationLedger({
        forecasts: source.forecasts,
        observations: source.observations,
        auditHistory: source.auditHistory,
        auditHistoryRuns: source.auditHistoryRuns,
        authorityRuns: source.authorityRuns,
        historyV2Seals: source.historyV2Seals,
        advisorySnapshots: source.advisorySnapshots,
        currentModelVersion: SCORE_MODEL_VERSION,
        currentPromptVersion: PROMPT_VERSION,
        currentCodeRevision: codeRevisionFromEnv(),
        expectedAdvisoryPackage,
        generatedAt,
        opportunityDenominatorLedger,
        prospectiveProof: {
          canonicalProof: source.canonicalProof,
          evaluationPurpose: 'production',
        },
      })
    : {
        schemaVersion: 4,
        generatedAt,
        status: 'measurable_but_failed',
        failureClass: 'ledger_integrity',
        phase: 'ledger_integrity',
        errors: [
          ...integrity.errors,
          ...observationBatchVerification.problems,
        ],
        integrity,
        observationBatchVerification,
        promotionDecision: {
          decision: 'deny_production',
          productionAuthorized: false,
          insufficientAuthorizesProduction: false,
          calibrationAuthorizesProduction: false,
          status: 'failed',
          failureClass: 'ledger_integrity',
        },
      };
  let canonicalEvaluationReceipt = null;
  if (options.record || options.requireRecorded) {
    const plan = planReleaseValidationProofEvaluation({
      bundle: source.canonicalProof,
      evaluatedAt: generatedAt,
      status: report.status,
      metrics: report,
    });
    if (options.requireRecorded && plan.status !== 'already_captured') {
      throw new Error(
        'validation:evaluate --require-recorded did not find an exact ' +
        'canonical evaluation receipt',
      );
    }
    const persistence = options.record
      ? appendReleaseValidationProof(plan.append)
      : {
          insertedByType: { evaluationReceipts: 0 },
          equivalentByType: { evaluationReceipts: 0 },
        };
    canonicalEvaluationReceipt = {
      evaluationId: plan.receipt.evaluationId,
      contentHash: plan.receipt.contentHash,
      evaluatedAt: plan.receipt.evaluatedAt,
      status: plan.receipt.status,
      persistence: plan.status,
      insertedCount: persistence.insertedByType.evaluationReceipts,
      equivalentCount: persistence.equivalentByType.evaluationReceipts,
      cohortCount: plan.receipt.cohortCount,
      requiredCellCount: plan.receipt.requiredCellCount,
      observationBatchCount: plan.receipt.observationBatchCount,
      outcomeCount: plan.receipt.outcomeCount,
      opportunityCoverage: plan.coverage,
    };
  }
  console.log(JSON.stringify({
    ...report,
    canonicalEvaluationReceipt,
  }, null, 2));
  process.exitCode = releaseValidationEvaluationExitCode(report.status);
}

function parseArgs(args) {
  const parsed = {
    record: false,
    requireRecorded: false,
    evaluatedAt: null,
  };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--record') {
      parsed.record = true;
    } else if (arg === '--require-recorded') {
      parsed.requireRecorded = true;
    } else if (arg === '--evaluated-at') {
      const value = args[++index];
      if (!value || !Number.isFinite(Date.parse(value))) {
        throw new Error('--evaluated-at requires a valid ISO timestamp');
      }
      parsed.evaluatedAt = new Date(Date.parse(value)).toISOString();
    } else {
      throw new Error(
        'Usage: validation:evaluate [--record | --require-recorded] ' +
        '[--evaluated-at <ISO timestamp>]',
      );
    }
  }
  if (parsed.record && parsed.requireRecorded) {
    throw new Error('--record and --require-recorded are mutually exclusive');
  }
  if (parsed.requireRecorded && parsed.evaluatedAt == null) {
    throw new Error('--require-recorded requires --evaluated-at');
  }
  return parsed;
}

export function filterScoreQualityEvidenceAsOf(
  source,
  evaluatedAt,
  {
    includeCurrentLeaseSnapshot = false,
  } = {},
) {
  const cutoffMs = authoritativeTimestampMs(
    evaluatedAt,
    'evaluation cutoff',
  );
  return {
    ...source,
    advisorySnapshots: pointInTimeRows(
      source.advisorySnapshots,
      cutoffMs,
      'advisory snapshot',
      advisorySnapshotAvailableAt,
    ),
    forecasts: pointInTimeRows(
      source.forecasts,
      cutoffMs,
      'validation forecast',
      (row, label) => rowTimestamp(row, 'recorded_at', label),
    ),
    observations: pointInTimeRows(
      source.observations,
      cutoffMs,
      'validation outcome',
      (row, label) => rowTimestamp(row, 'observed_at', label),
    ),
    observationBatches: pointInTimeRows(
      source.observationBatches,
      cutoffMs,
      'validation observation batch',
      (row, label) => rowTimestamp(row, 'observed_at', label),
    ),
    enrollments: pointInTimeRows(
      source.enrollments,
      cutoffMs,
      'validation opportunity enrollment',
      (row, label) => rowTimestamp(row, 'enrolled_at', label),
    ),
    attempts: pointInTimeRows(
      source.attempts,
      cutoffMs,
      'refresh operation attempt',
      (row, label) => rowTimestamp(row, 'started_at', label),
    ),
    stageEvents: pointInTimeRows(
      source.stageEvents,
      cutoffMs,
      'refresh operation stage event',
      (row, label) => rowTimestamp(row, 'occurred_at', label),
    ),
    receipts: pointInTimeRows(
      source.receipts,
      cutoffMs,
      'refresh capture receipt',
      (row, label) => rowTimestamp(row, 'finished_at', label),
    ),
    leases: includeCurrentLeaseSnapshot
      ? pointInTimeRows(
          source.leases,
          cutoffMs,
          'refresh lease',
          (row, label) => rowTimestamp(row, 'acquired_at', label),
        )
      : [],
    auditHistory: pointInTimeRows(
      source.auditHistory,
      cutoffMs,
      'score audit history row',
      (row, label) => rowTimestamp(row, 'recorded_at', label),
    ),
    auditHistoryRuns: pointInTimeRows(
      source.auditHistoryRuns,
      cutoffMs,
      'score audit history run',
      (row, label) => rowTimestamp(row, 'recorded_at', label),
    ),
    authorityRuns: pointInTimeRows(
      source.authorityRuns,
      cutoffMs,
      'score authority run',
      (row, label) => rowTimestamp(row, 'recordedAt', label),
    ),
    historyV2Seals: pointInTimeRows(
      source.historyV2Seals,
      cutoffMs,
      'score audit history v2 seal',
      (row, label) => rowTimestamp(row, 'sealedAt', label),
    ),
    canonicalProof: filterCanonicalReleaseValidationProofAsOf(
      source.canonicalProof,
      evaluatedAt,
    ),
  };
}

export function filterCanonicalReleaseValidationProofAsOf(
  bundle,
  evaluatedAt,
) {
  const cutoffMs = authoritativeTimestampMs(
    evaluatedAt,
    'canonical proof cutoff',
  );
  const catalogObservationTimes = uniqueParentTimes(
    bundle.catalogObservations,
    'catalog observation',
    'observationId',
    'observedAt',
  );
  const catalogReconciliationTimes = uniqueParentTimes(
    bundle.catalogReconciliations,
    'catalog reconciliation',
    'reconciliationId',
    'reconciledAt',
  );
  return {
    epochs: pointInTimeRows(
      bundle.epochs,
      cutoffMs,
      'proof epoch',
      (row, label) => rowTimestamp(row, 'recordedAt', label),
    ),
    retirements: pointInTimeRows(
      bundle.retirements,
      cutoffMs,
      'proof epoch retirement',
      (row, label) => rowTimestamp(row, 'recordedAt', label),
    ),
    policies: pointInTimeRows(
      bundle.policies,
      cutoffMs,
      'validation policy',
      (row, label) => rowTimestamp(row, 'recordedAt', label),
    ),
    cohorts: pointInTimeRows(
      bundle.cohorts,
      cutoffMs,
      'validation cohort',
      (row, label) => rowTimestamp(row, 'recordedAt', label),
    ),
    catalogObservations: pointInTimeRows(
      bundle.catalogObservations,
      cutoffMs,
      'catalog observation',
      (row, label) => rowTimestamp(row, 'observedAt', label),
    ),
    catalogMembers: pointInTimeChildRows(
      bundle.catalogMembers,
      cutoffMs,
      'catalog member',
      'observationId',
      catalogObservationTimes,
    ),
    catalogReconciliations: pointInTimeRows(
      bundle.catalogReconciliations,
      cutoffMs,
      'catalog reconciliation',
      (row, label) => rowTimestamp(row, 'reconciledAt', label),
    ),
    catalogReconciliationRows: pointInTimeChildRows(
      bundle.catalogReconciliationRows,
      cutoffMs,
      'catalog reconciliation row',
      'reconciliationId',
      catalogReconciliationTimes,
    ),
    obligations: pointInTimeRows(
      bundle.obligations,
      cutoffMs,
      'validation obligation',
      (row, label) => rowTimestamp(row, 'recordedAt', label),
    ),
    splitAssignments: pointInTimeRows(
      bundle.splitAssignments,
      cutoffMs,
      'validation split assignment',
      (row, label) => rowTimestamp(row, 'assignedAt', label),
    ),
    forecasts: pointInTimeRows(
      bundle.forecasts,
      cutoffMs,
      'canonical validation forecast',
      (row, label) => rowTimestamp(row, 'recordedAt', label),
    ),
    outcomes: pointInTimeRows(
      bundle.outcomes,
      cutoffMs,
      'canonical validation outcome',
      (row, label) => rowTimestamp(row, 'observedAt', label),
    ),
    observationBatches: pointInTimeRows(
      bundle.observationBatches,
      cutoffMs,
      'canonical validation observation batch',
      (row, label) => rowTimestamp(row, 'observedAt', label),
    ),
    evaluationReceipts: pointInTimeRows(
      bundle.evaluationReceipts,
      cutoffMs,
      'canonical validation evaluation receipt',
      (row, label) => rowTimestamp(row, 'evaluatedAt', label),
    ),
    promotionReceipts: pointInTimeRows(
      bundle.promotionReceipts,
      cutoffMs,
      'canonical validation promotion receipt',
      (row, label) => rowTimestamp(row, 'promotedAt', label),
    ),
  };
}

function pointInTimeRows(rows, cutoffMs, label, timestampFor) {
  if (!Array.isArray(rows)) {
    throw new Error(
      `Point-in-time evaluation cannot place ${label} evidence: ` +
      'expected an array',
    );
  }
  return rows.filter((row, index) =>
    timestampFor(row, `${label} ${index + 1}`) <= cutoffMs);
}

function pointInTimeChildRows(
  rows,
  cutoffMs,
  label,
  parentIdField,
  parentTimes,
) {
  return pointInTimeRows(
    rows,
    cutoffMs,
    label,
    (row, rowLabel) => {
      const record = evidenceRecord(row, rowLabel);
      const parentId = record[parentIdField];
      if (typeof parentId !== 'string' || !parentId || !parentTimes.has(parentId)) {
        throw new Error(
          `Point-in-time evaluation cannot place ${rowLabel}: ` +
          'no unique authoritative timestamp parent exists',
        );
      }
      return parentTimes.get(parentId);
    },
  );
}

function uniqueParentTimes(rows, label, idField, timestampField) {
  if (!Array.isArray(rows)) {
    throw new Error(
      `Point-in-time evaluation cannot place ${label} evidence: ` +
      'expected an array',
    );
  }
  const times = new Map();
  for (const [index, row] of rows.entries()) {
    const rowLabel = `${label} ${index + 1}`;
    const record = evidenceRecord(row, rowLabel);
    const id = record[idField];
    if (typeof id !== 'string' || !id || times.has(id)) {
      throw new Error(
        `Point-in-time evaluation cannot place ${rowLabel}: ` +
        'authoritative timestamp parent identity is ambiguous',
      );
    }
    times.set(id, rowTimestamp(record, timestampField, rowLabel));
  }
  return times;
}

function advisorySnapshotAvailableAt(row, label) {
  const record = evidenceRecord(row, label);
  const capturedAtMs = rowTimestamp(record, 'capturedAt', label);
  const provenance = record.provenance;
  if (record.schemaVersion === 2) {
    const provenanceRecord = evidenceRecord(
      provenance,
      `${label} provenance`,
    );
    const publication = evidenceRecord(
      provenanceRecord.publication,
      `${label} publication`,
    );
    const finishedAtMs = rowTimestamp(
      publication,
      'finishedAt',
      `${label} publication`,
    );
    if (finishedAtMs < capturedAtMs) {
      throw new Error(
        `Point-in-time evaluation cannot place ${label}: ` +
        'authoritative publication timestamp predates capture',
      );
    }
    return finishedAtMs;
  }
  if (provenance != null) {
    throw new Error(
      `Point-in-time evaluation cannot place ${label}: ` +
      'authoritative timestamp is ambiguous for legacy provenance',
    );
  }
  return capturedAtMs;
}

function rowTimestamp(row, field, label) {
  const record = evidenceRecord(row, label);
  return authoritativeTimestampMs(record[field], `${label}.${field}`);
}

function authoritativeTimestampMs(value, label) {
  const timestamp = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(timestamp)) {
    throw new Error(
      `Point-in-time evaluation cannot place ${label}: ` +
      'authoritative timestamp is missing or invalid',
    );
  }
  return timestamp;
}

function evidenceRecord(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(
      `Point-in-time evaluation cannot place ${label}: evidence is not an object`,
    );
  }
  return value;
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  void main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
