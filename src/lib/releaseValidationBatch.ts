import { createHash } from 'node:crypto';
import { normalizeCodeRevision } from './codeRevision';
import {
  RELEASE_VALIDATION_HORIZONS,
  releaseValidationObservationId,
  releaseValidationOutcomeContentHash,
  type ReleaseValidationForecastLedgerRow,
  type ReleaseValidationOutcomeLedgerRow,
} from './releaseValidation';

export const RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION = 2;
const RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION = 1;
const RELEASE_VALIDATION_OBSERVATION_BATCH_PAYLOAD_KIND =
  'release_validation_observation_batch';

export type ReleaseValidationObservationBatchPersistence =
  | 'inserted'
  | 'already_existing'
  | 'not_applicable';

export interface ReleaseValidationObservationBatchResult {
  decisionId: string;
  opportunityCode: string;
  targetReleaseTag: string;
  horizonCode: string;
  status: 'excluded' | 'pending' | 'matured' | 'indeterminate';
  persistence: ReleaseValidationObservationBatchPersistence;
  observationId?: string;
  observationContentHash?: string;
  adverse?: boolean;
  fatal?: boolean;
  reason?: string;
  [key: string]: unknown;
}

export interface ReleaseValidationObservationBatchForecastInput {
  decisionId: string;
  contentHash: string;
}

export interface ReleaseValidationObservationBatchOutcomeReference {
  observationId: string;
  observationContentHash: string;
  decisionId: string;
  horizonCode: string;
  status: 'matured' | 'indeterminate';
}

export interface ReleaseValidationObservationBatchCounts {
  forecastCount: number;
  resultCount: number;
  intendedCount: number;
  insertedCount: number;
  alreadyExistingCount: number;
  maturedCount: number;
  pendingCount: number;
  excludedCount: number;
  indeterminateCount: number;
}

export interface ReleaseValidationObservationBatchPayloadV2 {
  kind: typeof RELEASE_VALIDATION_OBSERVATION_BATCH_PAYLOAD_KIND;
  schemaVersion: typeof RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION;
  batchId: string;
  batchKey: string;
  observedAt: string;
  codeRevision: string;
  sourceIdentityDigest: string;
  forecastInputs: ReleaseValidationObservationBatchForecastInput[];
  forecastInputSetHash: string;
  results: ReleaseValidationObservationBatchResult[];
  resultSetHash: string;
  outcomeRefs: ReleaseValidationObservationBatchOutcomeReference[];
  outcomeRefSetHash: string;
  counts: ReleaseValidationObservationBatchCounts;
  outcomeChainPreviousHash: string | null;
  outcomeChainContentHash: string | null;
  previousBatchContentHash: string | null;
}

export interface ReleaseValidationObservationBatchReceiptInput {
  batchId: string;
  observedAt: string;
  codeRevision: string;
  sourceIdentityDigest: string;
  forecastCount: number;
  forecastInputs?: ReleaseValidationObservationBatchForecastInput[];
  results: ReleaseValidationObservationBatchResult[];
}

export interface ReleaseValidationObservationBatchReceiptRow {
  id: number;
  batch_id: string;
  observed_at: string;
  code_revision: string;
  source_identity_digest: string;
  forecast_count: number;
  intended_count: number;
  inserted_count: number;
  already_existing_count: number;
  pending_count: number;
  excluded_count: number;
  indeterminate_count: number;
  results_json: string;
  outcome_chain_previous_hash: string | null;
  outcome_chain_content_hash: string | null;
  previous_content_hash: string | null;
  content_hash: string;
}

export interface ReleaseValidationObservationBatchVerification {
  outcomeRowCount: number;
  batchCount: number;
  outcomeChainFailureCount: number;
  outcomeContentHashFailureCount: number;
  observationIdFailureCount: number;
  invalidBatchRowIdCount: number;
  duplicateBatchIdCount: number;
  batchChainFailureCount: number;
  batchContentHashFailureCount: number;
  batchPayloadFailureCount: number;
  batchCountMismatchCount: number;
  batchOutcomeBindingFailureCount: number;
  batchForecastBindingFailureCount: number;
  batchResultSetFailureCount: number;
  batchOutcomeReferenceSetFailureCount: number;
  batchSchemaRegressionCount: number;
  duplicateV2OutcomeReferenceCount: number;
  failedCount: number;
  problems: string[];
}

export interface ReleaseValidationObservationBatchRetryInput {
  observedAt?: string | null;
  codeRevision: string;
  sourceIdentityDigest: string;
  forecastInputs: ReleaseValidationObservationBatchForecastInput[];
}

export function canonicalReleaseValidationBatchJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export function stageReleaseValidationOutcomeRows(
  existing: ReleaseValidationOutcomeLedgerRow[],
  inputs: Array<Omit<
    ReleaseValidationOutcomeLedgerRow,
    'id' | 'observation_id' | 'previous_content_hash' | 'content_hash'
  >>,
): ReleaseValidationOutcomeLedgerRow[] {
  const orderedExisting = orderRows(existing);
  const seenObservationIds = new Set(orderedExisting.map((row) => row.observation_id));
  const maturedKeys = new Set(
    orderedExisting
      .filter((row) => row.status === 'matured')
      .map((row) => outcomeBusinessKey(row)),
  );
  let nextId = orderedExisting.reduce(
    (maximum, row) => Math.max(maximum, Number(row.id) || 0),
    0,
  ) + 1;
  let previousContentHash = orderedExisting.at(-1)?.content_hash ?? null;
  const staged: ReleaseValidationOutcomeLedgerRow[] = [];

  for (const input of inputs) {
    validateOutcomeInput(input);
    const row: ReleaseValidationOutcomeLedgerRow = {
      ...input,
      id: nextId++,
      observation_id: '',
      previous_content_hash: previousContentHash,
      content_hash: '',
    };
    row.observation_id = releaseValidationObservationId(row);
    if (seenObservationIds.has(row.observation_id)) {
      throw new Error(
        `Validation outcome ${row.decision_id}/${row.horizon_code} already exists exactly`,
      );
    }
    const businessKey = outcomeBusinessKey(row);
    if (row.status === 'matured' && maturedKeys.has(businessKey)) {
      throw new Error(
        `Matured validation outcome already exists for ${row.decision_id}/${row.horizon_code}`,
      );
    }
    row.content_hash = releaseValidationOutcomeContentHash(
      row,
      row.previous_content_hash ?? null,
    );
    staged.push(row);
    seenObservationIds.add(row.observation_id);
    if (row.status === 'matured') maturedKeys.add(businessKey);
    previousContentHash = row.content_hash;
  }
  return staged;
}

export function stageReleaseValidationObservationBatchReceipt(
  existingBatches: ReleaseValidationObservationBatchReceiptRow[],
  existingOutcomes: ReleaseValidationOutcomeLedgerRow[],
  stagedOutcomes: ReleaseValidationOutcomeLedgerRow[],
  input: ReleaseValidationObservationBatchReceiptInput,
): ReleaseValidationObservationBatchReceiptRow {
  const normalized = normalizeBatchReceiptInput(input);
  const orderedBatches = orderRows(existingBatches);
  if (orderedBatches.some((row) => row.batch_id === normalized.batchId)) {
    throw new Error(
      `Validation observation batch ${JSON.stringify(normalized.batchId)} already exists`,
    );
  }
  if (
    normalized.schemaVersion === RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION &&
    orderedBatches.some((row) =>
      storedBatchSchemaVersion(row.results_json) ===
        RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION)
  ) {
    throw new Error(
      'Validation observation batch cannot append legacy v1 history after v2 history begins',
    );
  }
  const orderedExistingOutcomes = orderRows(existingOutcomes);
  const counts = validateResultsAndOutcomes(
    normalized.results,
    normalized.forecastCount,
    orderedExistingOutcomes,
    stagedOutcomes,
    normalized.forecastInputs,
  );
  const previousOutcomeHash = orderedExistingOutcomes.at(-1)?.content_hash ?? null;
  const outcomeContentHash = stagedOutcomes.at(-1)?.content_hash ?? previousOutcomeHash;
  const previousBatchHash = orderedBatches.at(-1)?.content_hash ?? null;
  const row: ReleaseValidationObservationBatchReceiptRow = {
    id: orderedBatches.reduce(
      (maximum, batch) => Math.max(maximum, Number(batch.id) || 0),
      0,
    ) + 1,
    batch_id: normalized.batchId,
    observed_at: normalized.observedAt,
    code_revision: normalized.codeRevision,
    source_identity_digest: normalized.sourceIdentityDigest,
    forecast_count: normalized.forecastCount,
    intended_count: stagedOutcomes.length,
    inserted_count: counts.insertedCount,
    already_existing_count: counts.alreadyExistingCount,
    pending_count: counts.pendingCount,
    excluded_count: counts.excludedCount,
    indeterminate_count: counts.indeterminateCount,
    results_json: '',
    outcome_chain_previous_hash: previousOutcomeHash,
    outcome_chain_content_hash: outcomeContentHash,
    previous_content_hash: previousBatchHash,
    content_hash: '',
  };
  if (row.intended_count !== row.inserted_count) {
    throw new Error(
      `Validation observation batch intended ${row.intended_count} outcomes but results mark ` +
      `${row.inserted_count} inserted`,
    );
  }
  if (normalized.schemaVersion === RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION) {
    const payload = buildV2Payload({
      row,
      forecastInputs: normalized.forecastInputs ?? [],
      results: normalized.results,
      stagedOutcomes,
      counts,
    });
    row.results_json = canonicalReleaseValidationBatchJson([payload]);
  } else {
    row.results_json = canonicalReleaseValidationBatchJson(normalized.results);
  }
  row.content_hash = releaseValidationObservationBatchContentHash(row);
  return row;
}

export function releaseValidationObservationBatchContentHash(
  row: Omit<ReleaseValidationObservationBatchReceiptRow, 'id' | 'content_hash'>,
): string {
  const schemaVersion = storedBatchSchemaVersion(row.results_json);
  return createHash('sha256')
    .update(
      `release-validation-observation-batch-v${schemaVersion}\0` +
      `${row.previous_content_hash ?? ''}\0` +
      canonicalReleaseValidationBatchJson([
        row.batch_id,
        row.observed_at,
        row.code_revision,
        row.source_identity_digest,
        row.forecast_count,
        row.intended_count,
        row.inserted_count,
        row.already_existing_count,
        row.pending_count,
        row.excluded_count,
        row.indeterminate_count,
        row.results_json,
        row.outcome_chain_previous_hash,
        row.outcome_chain_content_hash,
      ]),
    )
    .digest('hex');
}

export function verifyReleaseValidationObservationBatchLedger(input: {
  outcomes: ReleaseValidationOutcomeLedgerRow[];
  batches: ReleaseValidationObservationBatchReceiptRow[];
}): ReleaseValidationObservationBatchVerification {
  const problems: string[] = [];
  const outcomes = orderRows(input.outcomes);
  const batches = orderRows(input.batches);
  const outcomeIndexByHash = new Map<string, number>();
  const outcomeById = new Map<string, ReleaseValidationOutcomeLedgerRow>();
  let outcomeChainFailureCount = 0;
  let outcomeContentHashFailureCount = 0;
  let observationIdFailureCount = 0;
  let previousOutcomeHash: string | null = null;

  for (const [index, row] of outcomes.entries()) {
    if ((row.previous_content_hash ?? null) !== previousOutcomeHash) {
      outcomeChainFailureCount++;
      problems.push(
        `Validation outcome ${JSON.stringify(row.observation_id)} previous hash mismatch`,
      );
    }
    if (
      releaseValidationOutcomeContentHash(row, row.previous_content_hash ?? null) !==
      row.content_hash
    ) {
      outcomeContentHashFailureCount++;
      problems.push(
        `Validation outcome ${JSON.stringify(row.observation_id)} content hash mismatch`,
      );
    }
    if (releaseValidationObservationId(row) !== row.observation_id) {
      observationIdFailureCount++;
      problems.push(
        `Validation outcome ${JSON.stringify(row.observation_id)} observation ID mismatch`,
      );
    }
    if (outcomeIndexByHash.has(String(row.content_hash ?? ''))) {
      outcomeContentHashFailureCount++;
      problems.push(
        `Duplicate validation outcome content hash ${JSON.stringify(row.content_hash)}`,
      );
    }
    if (outcomeById.has(row.observation_id)) {
      observationIdFailureCount++;
      problems.push(
        `Duplicate validation outcome observation ID ${JSON.stringify(row.observation_id)}`,
      );
    }
    outcomeIndexByHash.set(String(row.content_hash ?? ''), index);
    outcomeById.set(row.observation_id, row);
    previousOutcomeHash = row.content_hash ?? null;
  }

  let invalidBatchRowIdCount = 0;
  let duplicateBatchIdCount = 0;
  let batchChainFailureCount = 0;
  let batchContentHashFailureCount = 0;
  let batchPayloadFailureCount = 0;
  let batchCountMismatchCount = 0;
  let batchOutcomeBindingFailureCount = 0;
  let batchForecastBindingFailureCount = 0;
  let batchResultSetFailureCount = 0;
  let batchOutcomeReferenceSetFailureCount = 0;
  let batchSchemaRegressionCount = 0;
  let duplicateV2OutcomeReferenceCount = 0;
  const seenBatchIds = new Set<string>();
  const seenBatchRowIds = new Set<number>();
  const v2OutcomeReferenceCounts = new Map<string, number>();
  let previousBatchHash: string | null = null;
  let previousBatchOutcomeHash: string | null | undefined;
  let sawV2Batch = false;

  for (const [batchIndex, batch] of batches.entries()) {
    const rowId = Number(batch.id);
    if (!Number.isInteger(rowId) || rowId <= 0 || seenBatchRowIds.has(rowId)) {
      invalidBatchRowIdCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} has invalid row ID`,
      );
    }
    seenBatchRowIds.add(rowId);
    if (seenBatchIds.has(batch.batch_id)) {
      duplicateBatchIdCount++;
      problems.push(
        `Duplicate validation observation batch ID ${JSON.stringify(batch.batch_id)}`,
      );
    }
    seenBatchIds.add(batch.batch_id);
    if ((batch.previous_content_hash ?? null) !== previousBatchHash) {
      batchChainFailureCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} previous hash mismatch`,
      );
    }
    if (releaseValidationObservationBatchContentHash(batch) !== batch.content_hash) {
      batchContentHashFailureCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} content hash mismatch`,
      );
    }
    if (
      !batch.batch_id ||
      batch.batch_id.length > 512 ||
      /[\u0000-\u0020\u007f]/.test(batch.batch_id) ||
      !Number.isFinite(Date.parse(batch.observed_at)) ||
      normalizeCodeRevision(batch.code_revision) !== batch.code_revision ||
      !/^[0-9a-f]{64}$/.test(batch.source_identity_digest) ||
      [
        batch.forecast_count,
        batch.intended_count,
        batch.inserted_count,
        batch.already_existing_count,
        batch.pending_count,
        batch.excluded_count,
        batch.indeterminate_count,
      ].some((count) => !Number.isInteger(count) || count < 0)
    ) {
      batchPayloadFailureCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} metadata is invalid`,
      );
    }
    if (
      batchIndex > 0 &&
      batch.outcome_chain_previous_hash !== previousBatchOutcomeHash
    ) {
      batchOutcomeBindingFailureCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} outcome chain is not contiguous`,
      );
    }

    let results: ReleaseValidationObservationBatchResult[] | null = null;
    let payloadV2: ReleaseValidationObservationBatchPayloadV2 | null = null;
    let parsedSchemaVersion: 1 | 2 | null = null;
    try {
      const stored = parseStoredBatchResults(batch.results_json);
      if (canonicalReleaseValidationBatchJson(stored.raw) !== batch.results_json) {
        throw new Error('results JSON is not canonical');
      }
      results = stored.results;
      payloadV2 = stored.payloadV2;
      parsedSchemaVersion = payloadV2
        ? RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION
        : RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION;
      if (payloadV2) {
        const payloadProblems = v2PayloadProblems(payloadV2, batch);
        if (payloadProblems.metadata.length > 0) {
          batchPayloadFailureCount++;
          problems.push(
            `Validation observation batch ${JSON.stringify(batch.batch_id)} v2 metadata is invalid: ` +
            payloadProblems.metadata.join(', '),
          );
        }
        if (payloadProblems.forecasts.length > 0) {
          batchForecastBindingFailureCount++;
          problems.push(
            `Validation observation batch ${JSON.stringify(batch.batch_id)} forecast input set is invalid: ` +
            payloadProblems.forecasts.join(', '),
          );
        }
        if (payloadProblems.results.length > 0) {
          batchResultSetFailureCount++;
          problems.push(
            `Validation observation batch ${JSON.stringify(batch.batch_id)} result set is invalid: ` +
            payloadProblems.results.join(', '),
          );
        }
        if (payloadProblems.outcomeRefs.length > 0) {
          batchOutcomeReferenceSetFailureCount++;
          problems.push(
            `Validation observation batch ${JSON.stringify(batch.batch_id)} outcome reference set is invalid: ` +
            payloadProblems.outcomeRefs.join(', '),
          );
        }
      }
      const counts = validateResultShapes(
        results,
        batch.forecast_count,
        payloadV2?.forecastInputs,
      );
      const expectedCounts = batchCounts(
        batch.forecast_count,
        results,
        batch.intended_count,
        counts,
      );
      if (
        batch.intended_count !== batch.inserted_count ||
        batch.inserted_count !== counts.insertedCount ||
        batch.already_existing_count !== counts.alreadyExistingCount ||
        batch.pending_count !== counts.pendingCount ||
        batch.excluded_count !== counts.excludedCount ||
        batch.indeterminate_count !== counts.indeterminateCount ||
        (
          payloadV2 != null &&
          canonicalReleaseValidationBatchJson(payloadV2.counts) !==
            canonicalReleaseValidationBatchJson(expectedCounts)
        )
      ) {
        batchCountMismatchCount++;
        problems.push(
          `Validation observation batch ${JSON.stringify(batch.batch_id)} count mismatch`,
        );
      }
    } catch (error) {
      batchPayloadFailureCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} results are invalid: ` +
        `${(error as Error).message}`,
      );
    }
    if (
      parsedSchemaVersion === RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION &&
      sawV2Batch
    ) {
      batchSchemaRegressionCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} regresses from v2 to v1`,
      );
    }
    if (parsedSchemaVersion === RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION) {
      sawV2Batch = true;
    }

    const startIndex = outcomeChainIndex(
      batch.outcome_chain_previous_hash,
      outcomeIndexByHash,
    );
    const endIndex = outcomeChainIndex(
      batch.outcome_chain_content_hash,
      outcomeIndexByHash,
    );
    if (startIndex == null || endIndex == null) {
      batchOutcomeBindingFailureCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} references an unknown outcome hash`,
      );
    } else if (batch.inserted_count === 0) {
      if (endIndex !== startIndex) {
        batchOutcomeBindingFailureCount++;
        problems.push(
          `Validation observation batch ${JSON.stringify(batch.batch_id)} advanced the outcome chain without inserts`,
        );
      }
    } else if (endIndex !== startIndex + batch.inserted_count) {
      batchOutcomeBindingFailureCount++;
      problems.push(
        `Validation observation batch ${JSON.stringify(batch.batch_id)} outcome span does not match inserted count`,
      );
    }

    if (results && startIndex != null && endIndex != null) {
      const insertedResults = results.filter((result) => result.persistence === 'inserted');
      const insertedRows = outcomes.slice(startIndex + 1, endIndex + 1);
      const insertedResultRefs = outcomeReferencesFromResults(insertedResults);
      const insertedRowRefs = outcomeReferencesFromRows(insertedRows);
      const insertedResultSetMatches = payloadV2
        ? canonicalReleaseValidationBatchJson(insertedResultRefs) ===
          canonicalReleaseValidationBatchJson(insertedRowRefs)
        : insertedResults.length === insertedRows.length &&
          insertedResults.every((result, index) =>
            result.observationId === insertedRows[index]?.observation_id &&
            result.observationContentHash === insertedRows[index]?.content_hash);
      if (!insertedResultSetMatches) {
        batchOutcomeBindingFailureCount++;
        problems.push(
          `Validation observation batch ${JSON.stringify(batch.batch_id)} inserted result set does not match its outcome segment`,
        );
      }
      if (payloadV2) {
        if (
          canonicalReleaseValidationBatchJson(payloadV2.outcomeRefs) !==
          canonicalReleaseValidationBatchJson(insertedRowRefs)
        ) {
          batchOutcomeReferenceSetFailureCount++;
          problems.push(
            `Validation observation batch ${JSON.stringify(batch.batch_id)} exact outcome reference set does not match its outcome segment`,
          );
        }
        for (const reference of payloadV2.outcomeRefs) {
          const key = outcomeReferenceKey(reference);
          v2OutcomeReferenceCounts.set(
            key,
            (v2OutcomeReferenceCounts.get(key) ?? 0) + 1,
          );
        }
      }
      for (const result of results.filter((item) =>
        item.persistence === 'inserted' || item.persistence === 'already_existing')) {
        const observation = outcomeById.get(String(result.observationId ?? ''));
        const observationIndex = observation
          ? outcomeIndexByHash.get(String(observation.content_hash ?? ''))
          : undefined;
        if (
          !observation ||
          observation.content_hash !== result.observationContentHash ||
          observation.decision_id !== result.decisionId ||
          observation.horizon_code !== result.horizonCode ||
          observation.status !== result.status ||
          resultOutcomePayloadProblem(result, observation) != null ||
          Date.parse(observation.observed_at) > Date.parse(batch.observed_at) ||
          (
            result.persistence === 'already_existing' &&
            (observationIndex == null || observationIndex > startIndex)
          )
        ) {
          batchOutcomeBindingFailureCount++;
          problems.push(
            `Validation observation batch ${JSON.stringify(batch.batch_id)} has an invalid ` +
            `${result.persistence} result for ${result.decisionId}/${result.horizonCode}`,
          );
        }
      }
    }

    previousBatchHash = batch.content_hash;
    previousBatchOutcomeHash = batch.outcome_chain_content_hash;
  }

  for (const [reference, count] of v2OutcomeReferenceCounts) {
    if (count <= 1) continue;
    duplicateV2OutcomeReferenceCount += count - 1;
    problems.push(
      `Validation v2 outcome reference ${JSON.stringify(reference)} appears in ${count} batches`,
    );
  }

  if (
    batches.length > 0 &&
    batches.at(-1)?.outcome_chain_content_hash !== (outcomes.at(-1)?.content_hash ?? null)
  ) {
    batchOutcomeBindingFailureCount++;
    problems.push('Validation observation batch ledger does not cover the outcome ledger tip');
  }

  const failedCount = outcomeChainFailureCount +
    outcomeContentHashFailureCount +
    observationIdFailureCount +
    invalidBatchRowIdCount +
    duplicateBatchIdCount +
    batchChainFailureCount +
    batchContentHashFailureCount +
    batchPayloadFailureCount +
    batchCountMismatchCount +
    batchOutcomeBindingFailureCount +
    batchForecastBindingFailureCount +
    batchResultSetFailureCount +
    batchOutcomeReferenceSetFailureCount +
    batchSchemaRegressionCount +
    duplicateV2OutcomeReferenceCount;
  return {
    outcomeRowCount: outcomes.length,
    batchCount: batches.length,
    outcomeChainFailureCount,
    outcomeContentHashFailureCount,
    observationIdFailureCount,
    invalidBatchRowIdCount,
    duplicateBatchIdCount,
    batchChainFailureCount,
    batchContentHashFailureCount,
    batchPayloadFailureCount,
    batchCountMismatchCount,
    batchOutcomeBindingFailureCount,
    batchForecastBindingFailureCount,
    batchResultSetFailureCount,
    batchOutcomeReferenceSetFailureCount,
    batchSchemaRegressionCount,
    duplicateV2OutcomeReferenceCount,
    failedCount,
    problems,
  };
}

export function releaseValidationObservationBatchRowsEqual(
  left: ReleaseValidationObservationBatchReceiptRow,
  right: ReleaseValidationObservationBatchReceiptRow,
): boolean {
  return canonicalReleaseValidationBatchJson(left) ===
    canonicalReleaseValidationBatchJson(right);
}

export function releaseValidationOutcomeRowsEqual(
  left: ReleaseValidationOutcomeLedgerRow,
  right: ReleaseValidationOutcomeLedgerRow,
): boolean {
  return canonicalReleaseValidationBatchJson(left) ===
    canonicalReleaseValidationBatchJson(right);
}

export function releaseValidationObservationBatchForecastInputs(
  forecasts: Array<Pick<ReleaseValidationForecastLedgerRow, 'decision_id' | 'content_hash'>>,
): ReleaseValidationObservationBatchForecastInput[] {
  const inputs = forecasts.map((forecast) => ({
    decisionId: String(forecast.decision_id ?? '').trim(),
    contentHash: String(forecast.content_hash ?? '').trim().toLowerCase(),
  }));
  const sorted = sortForecastInputs(inputs);
  validateForecastInputs(sorted, sorted.length);
  return sorted;
}

export function assertReleaseValidationObservationBatchRetryEquivalent(
  row: ReleaseValidationObservationBatchReceiptRow,
  input: ReleaseValidationObservationBatchRetryInput,
): void {
  const differingFields: string[] = [];
  let stored: ReturnType<typeof parseStoredBatchResults> | null = null;
  try {
    stored = parseStoredBatchResults(row.results_json);
  } catch {
    differingFields.push('receiptPayload');
  }
  if (!stored?.payloadV2) {
    differingFields.push('schemaVersion');
  } else {
    const payloadProblems = v2PayloadProblems(stored.payloadV2, row);
    if (
      canonicalReleaseValidationBatchJson(stored.raw) !== row.results_json ||
      releaseValidationObservationBatchContentHash(row) !== row.content_hash ||
      Object.values(payloadProblems).some((items) => items.length > 0)
    ) {
      differingFields.push('receiptPayload');
    }
    try {
      validateForecastInputs(input.forecastInputs, row.forecast_count);
      if (
        canonicalReleaseValidationBatchJson(input.forecastInputs) !==
        canonicalReleaseValidationBatchJson(stored.payloadV2.forecastInputs) ||
        releaseValidationObservationBatchSetHash(
          'forecast-inputs',
          input.forecastInputs,
        ) !== stored.payloadV2.forecastInputSetHash
      ) {
        differingFields.push('forecastInputSet');
      }
    } catch {
      differingFields.push('forecastInputSet');
    }
  }
  if (input.observedAt != null && input.observedAt !== row.observed_at) {
    differingFields.push('observedAt');
  }
  if (normalizeCodeRevision(input.codeRevision) !== row.code_revision) {
    differingFields.push('codeRevision');
  }
  if (input.sourceIdentityDigest.trim().toLowerCase() !== row.source_identity_digest) {
    differingFields.push('sourceIdentityDigest');
  }
  if (differingFields.length > 0) {
    throw new Error(
      `Validation observation batch conflict for ${JSON.stringify(row.batch_id)}; ` +
      `differing fields: ${[...new Set(differingFields)].join(', ')}`,
    );
  }
}

export function releaseValidationObservationBatchReport(
  row: ReleaseValidationObservationBatchReceiptRow,
): Record<string, unknown> {
  const stored = parseStoredBatchResults(row.results_json);
  const payload = stored.payloadV2;
  return {
    schemaVersion: payload?.schemaVersion ??
      RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION,
    batchId: row.batch_id,
    ...(payload ? {
      batchKey: payload.batchKey,
      forecastInputs: payload.forecastInputs,
      forecastInputSetHash: payload.forecastInputSetHash,
      resultSetHash: payload.resultSetHash,
      outcomeRefs: payload.outcomeRefs,
      outcomeRefSetHash: payload.outcomeRefSetHash,
      counts: payload.counts,
    } : {}),
    observedAt: row.observed_at,
    codeRevision: row.code_revision,
    sourceIdentityDigest: row.source_identity_digest,
    forecastCount: row.forecast_count,
    intendedCount: row.intended_count,
    insertedCount: row.inserted_count,
    alreadyExistingCount: row.already_existing_count,
    pendingCount: row.pending_count,
    excludedCount: row.excluded_count,
    indeterminateCount: row.indeterminate_count,
    previousBatchHash: row.previous_content_hash,
    contentHash: row.content_hash,
    outcomeChainPreviousHash: row.outcome_chain_previous_hash,
    outcomeChainContentHash: row.outcome_chain_content_hash,
    results: stored.results,
  };
}

interface NormalizedBatchReceiptInput {
  schemaVersion: 1 | 2;
  batchId: string;
  observedAt: string;
  codeRevision: string;
  sourceIdentityDigest: string;
  forecastCount: number;
  forecastInputs?: ReleaseValidationObservationBatchForecastInput[];
  results: ReleaseValidationObservationBatchResult[];
}

function normalizeBatchReceiptInput(
  input: ReleaseValidationObservationBatchReceiptInput,
): NormalizedBatchReceiptInput {
  const batchId = input.batchId.trim();
  const codeRevision = normalizeCodeRevision(input.codeRevision);
  const sourceIdentityDigest = input.sourceIdentityDigest.trim().toLowerCase();
  if (!batchId || batchId.length > 512 || /[\u0000-\u0020\u007f]/.test(batchId)) {
    throw new Error('Validation observation batch ID must be a non-empty printable token');
  }
  if (!Number.isFinite(Date.parse(input.observedAt))) {
    throw new Error('Validation observation batch observedAt must be a valid timestamp');
  }
  if (!codeRevision) {
    throw new Error('Validation observation batch requires a deterministic code revision');
  }
  if (!/^[0-9a-f]{64}$/.test(sourceIdentityDigest)) {
    throw new Error('Validation observation batch source identity digest must be SHA-256');
  }
  if (!Number.isInteger(input.forecastCount) || input.forecastCount < 0) {
    throw new Error('Validation observation batch forecast count must be non-negative');
  }
  const stored = parseStoredBatchResultsValue(input.results);
  const schemaVersion = stored.payloadV2 || input.forecastInputs
    ? RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION
    : RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION;
  if (
    stored.payloadV2 &&
    input.forecastInputs &&
    canonicalReleaseValidationBatchJson(stored.payloadV2.forecastInputs) !==
      canonicalReleaseValidationBatchJson(input.forecastInputs)
  ) {
    throw new Error(
      'Validation observation batch stored and supplied forecast inputs differ',
    );
  }
  const forecastInputs = stored.payloadV2?.forecastInputs ??
    structuredClone(input.forecastInputs);
  if (schemaVersion === RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION) {
    if (!forecastInputs) {
      throw new Error('Validation observation batch v2 requires exact forecast inputs');
    }
    validateForecastInputs(forecastInputs, input.forecastCount);
  }
  const results = schemaVersion === RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION
    ? sortBatchResults(stored.results)
    : structuredClone(stored.results);
  return {
    schemaVersion,
    batchId,
    observedAt: input.observedAt,
    codeRevision,
    sourceIdentityDigest,
    forecastCount: input.forecastCount,
    ...(forecastInputs ? { forecastInputs: structuredClone(forecastInputs) } : {}),
    results,
  };
}

function validateResultsAndOutcomes(
  results: ReleaseValidationObservationBatchResult[],
  forecastCount: number,
  existingOutcomes: ReleaseValidationOutcomeLedgerRow[],
  stagedOutcomes: ReleaseValidationOutcomeLedgerRow[],
  forecastInputs?: ReleaseValidationObservationBatchForecastInput[],
): ReturnType<typeof validateResultShapes> {
  const counts = validateResultShapes(results, forecastCount, forecastInputs);
  const outcomesById = new Map(
    [...existingOutcomes, ...stagedOutcomes].map((row) => [row.observation_id, row]),
  );
  const stagedIds = new Set(stagedOutcomes.map((row) => row.observation_id));
  for (const result of results) {
    if (result.persistence === 'not_applicable') continue;
    const outcome = outcomesById.get(String(result.observationId ?? ''));
    if (
      !outcome ||
      outcome.content_hash !== result.observationContentHash ||
      outcome.decision_id !== result.decisionId ||
      outcome.horizon_code !== result.horizonCode ||
      outcome.status !== result.status ||
      resultOutcomePayloadProblem(result, outcome) != null
    ) {
      throw new Error(
        `Validation observation batch result does not match outcome ` +
        `${result.decisionId}/${result.horizonCode}`,
      );
    }
    if (
      (result.persistence === 'inserted') !== stagedIds.has(outcome.observation_id)
    ) {
      throw new Error(
        `Validation observation batch persistence is wrong for ` +
        `${result.decisionId}/${result.horizonCode}`,
      );
    }
  }
  if (
    stagedOutcomes.some((outcome) =>
      !results.some((result) =>
        result.persistence === 'inserted' &&
        result.observationId === outcome.observation_id))
  ) {
    throw new Error('Validation observation batch omits a staged outcome');
  }
  return counts;
}

function validateResultShapes(
  results: ReleaseValidationObservationBatchResult[],
  forecastCount: number,
  forecastInputs?: ReleaseValidationObservationBatchForecastInput[],
): {
  insertedCount: number;
  alreadyExistingCount: number;
  maturedCount: number;
  pendingCount: number;
  excludedCount: number;
  indeterminateCount: number;
} {
  const horizons = Object.keys(RELEASE_VALIDATION_HORIZONS).sort();
  const pairs = new Set<string>();
  const horizonsByDecision = new Map<string, Set<string>>();
  const identityByDecision = new Map<string, string>();
  for (const result of results) {
    if (
      !result ||
      typeof result !== 'object' ||
      !String(result.decisionId ?? '').trim() ||
      !String(result.opportunityCode ?? '').trim() ||
      !String(result.targetReleaseTag ?? '').trim() ||
      !horizons.includes(String(result.horizonCode ?? ''))
    ) {
      throw new Error('Validation observation batch result identity is invalid');
    }
    if (!['excluded', 'pending', 'matured', 'indeterminate'].includes(result.status)) {
      throw new Error(
        `Validation observation batch result status ${JSON.stringify(result.status)} is invalid`,
      );
    }
    if (!['inserted', 'already_existing', 'not_applicable'].includes(result.persistence)) {
      throw new Error(
        `Validation observation batch persistence ${JSON.stringify(result.persistence)} is invalid`,
      );
    }
    const pair = `${result.decisionId}\0${result.horizonCode}`;
    if (pairs.has(pair)) {
      throw new Error(
        `Validation observation batch repeats ${result.decisionId}/${result.horizonCode}`,
      );
    }
    pairs.add(pair);
    const decisionHorizons = horizonsByDecision.get(result.decisionId) ?? new Set<string>();
    decisionHorizons.add(result.horizonCode);
    horizonsByDecision.set(result.decisionId, decisionHorizons);
    const decisionIdentity = canonicalReleaseValidationBatchJson([
      result.opportunityCode,
      result.targetReleaseTag,
    ]);
    const priorIdentity = identityByDecision.get(result.decisionId);
    if (priorIdentity != null && priorIdentity !== decisionIdentity) {
      throw new Error(
        `Validation observation batch has inconsistent forecast identity for ${result.decisionId}`,
      );
    }
    identityByDecision.set(result.decisionId, decisionIdentity);
    const outcomeStatus = result.status === 'matured' || result.status === 'indeterminate';
    if (
      outcomeStatus !== (result.persistence !== 'not_applicable') ||
      outcomeStatus !== (
        typeof result.observationId === 'string' &&
        result.observationId.length > 0 &&
        typeof result.observationContentHash === 'string' &&
        /^[0-9a-f]{64}$/.test(result.observationContentHash)
      )
    ) {
      throw new Error(
        `Validation observation batch persistence fields are invalid for ` +
        `${result.decisionId}/${result.horizonCode}`,
      );
    }
    if (result.status === 'matured' && typeof result.adverse !== 'boolean') {
      throw new Error(
        `Validation observation batch matured result is missing adverse outcome for ` +
        `${result.decisionId}/${result.horizonCode}`,
      );
    }
    if (
      result.status === 'indeterminate' &&
      (typeof result.fatal !== 'boolean' || !String(result.reason ?? '').trim())
    ) {
      throw new Error(
        `Validation observation batch indeterminate result is missing reason or fatality for ` +
        `${result.decisionId}/${result.horizonCode}`,
      );
    }
  }
  if (horizonsByDecision.size !== forecastCount) {
    throw new Error(
      `Validation observation batch has ${horizonsByDecision.size} decisions for ` +
      `${forecastCount} forecasts`,
    );
  }
  if (forecastInputs) {
    validateForecastInputs(forecastInputs, forecastCount);
    const resultDecisionIds = [...horizonsByDecision.keys()].sort();
    const forecastDecisionIds = forecastInputs.map((forecast) => forecast.decisionId);
    if (
      canonicalReleaseValidationBatchJson(resultDecisionIds) !==
      canonicalReleaseValidationBatchJson(forecastDecisionIds)
    ) {
      throw new Error(
        'Validation observation batch result decisions do not exactly match forecast inputs',
      );
    }
  }
  for (const [decisionId, decisionHorizons] of horizonsByDecision) {
    if (
      decisionHorizons.size !== horizons.length ||
      horizons.some((horizon) => !decisionHorizons.has(horizon))
    ) {
      throw new Error(
        `Validation observation batch does not cover every horizon for ${decisionId}`,
      );
    }
  }
  return {
    insertedCount: results.filter((result) => result.persistence === 'inserted').length,
    alreadyExistingCount: results.filter((result) =>
      result.persistence === 'already_existing').length,
    maturedCount: results.filter((result) => result.status === 'matured').length,
    pendingCount: results.filter((result) => result.status === 'pending').length,
    excludedCount: results.filter((result) => result.status === 'excluded').length,
    indeterminateCount: results.filter((result) => result.status === 'indeterminate').length,
  };
}

function buildV2Payload(input: {
  row: ReleaseValidationObservationBatchReceiptRow;
  forecastInputs: ReleaseValidationObservationBatchForecastInput[];
  results: ReleaseValidationObservationBatchResult[];
  stagedOutcomes: ReleaseValidationOutcomeLedgerRow[];
  counts: ReturnType<typeof validateResultShapes>;
}): ReleaseValidationObservationBatchPayloadV2 {
  validateForecastInputs(input.forecastInputs, input.row.forecast_count);
  const forecastInputs = structuredClone(input.forecastInputs);
  const results = sortBatchResults(input.results);
  const outcomeRefs = outcomeReferencesFromRows(input.stagedOutcomes);
  const counts = batchCounts(
    input.row.forecast_count,
    results,
    input.row.intended_count,
    input.counts,
  );
  const payloadWithoutKey = {
    kind: RELEASE_VALIDATION_OBSERVATION_BATCH_PAYLOAD_KIND as
      typeof RELEASE_VALIDATION_OBSERVATION_BATCH_PAYLOAD_KIND,
    schemaVersion: RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION as
      typeof RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION,
    batchId: input.row.batch_id,
    observedAt: input.row.observed_at,
    codeRevision: input.row.code_revision,
    sourceIdentityDigest: input.row.source_identity_digest,
    forecastInputs,
    forecastInputSetHash: releaseValidationObservationBatchSetHash(
      'forecast-inputs',
      forecastInputs,
    ),
    results,
    resultSetHash: releaseValidationObservationBatchSetHash('results', results),
    outcomeRefs,
    outcomeRefSetHash: releaseValidationObservationBatchSetHash(
      'outcome-refs',
      outcomeRefs,
    ),
    counts,
    outcomeChainPreviousHash: input.row.outcome_chain_previous_hash,
    outcomeChainContentHash: input.row.outcome_chain_content_hash,
    previousBatchContentHash: input.row.previous_content_hash,
  };
  return {
    ...payloadWithoutKey,
    batchKey: releaseValidationObservationBatchKey(payloadWithoutKey),
  };
}

function batchCounts(
  forecastCount: number,
  results: ReleaseValidationObservationBatchResult[],
  intendedCount: number,
  counts: ReturnType<typeof validateResultShapes>,
): ReleaseValidationObservationBatchCounts {
  return {
    forecastCount,
    resultCount: results.length,
    intendedCount,
    insertedCount: counts.insertedCount,
    alreadyExistingCount: counts.alreadyExistingCount,
    maturedCount: counts.maturedCount,
    pendingCount: counts.pendingCount,
    excludedCount: counts.excludedCount,
    indeterminateCount: counts.indeterminateCount,
  };
}

function releaseValidationObservationBatchSetHash(
  setName: 'forecast-inputs' | 'results' | 'outcome-refs',
  values: unknown[],
): string {
  return createHash('sha256')
    .update(
      `release-validation-observation-batch-v2-${setName}\0` +
      canonicalReleaseValidationBatchJson(values),
    )
    .digest('hex');
}

function releaseValidationObservationBatchKey(
  payload: Omit<ReleaseValidationObservationBatchPayloadV2, 'batchKey'>,
): string {
  return createHash('sha256')
    .update(
      'release-validation-observation-batch-key-v2\0' +
      canonicalReleaseValidationBatchJson([
        payload.batchId,
        payload.observedAt,
        payload.codeRevision,
        payload.sourceIdentityDigest,
        payload.forecastInputSetHash,
        payload.resultSetHash,
        payload.outcomeRefSetHash,
        payload.counts,
        payload.outcomeChainPreviousHash,
        payload.outcomeChainContentHash,
        payload.previousBatchContentHash,
      ]),
    )
    .digest('hex');
}

function parseStoredBatchResults(resultsJson: string): {
  raw: unknown[];
  results: ReleaseValidationObservationBatchResult[];
  payloadV2: ReleaseValidationObservationBatchPayloadV2 | null;
} {
  return parseStoredBatchResultsValue(JSON.parse(resultsJson));
}

function parseStoredBatchResultsValue(value: unknown): {
  raw: unknown[];
  results: ReleaseValidationObservationBatchResult[];
  payloadV2: ReleaseValidationObservationBatchPayloadV2 | null;
} {
  if (!Array.isArray(value)) {
    throw new Error('results are not an array');
  }
  const candidate = value.length === 1 ? value[0] : null;
  if (
    candidate &&
    typeof candidate === 'object' &&
    !Array.isArray(candidate) &&
    (candidate as Record<string, unknown>).kind ===
      RELEASE_VALIDATION_OBSERVATION_BATCH_PAYLOAD_KIND &&
    (candidate as Record<string, unknown>).schemaVersion ===
      RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION
  ) {
    const payload = candidate as ReleaseValidationObservationBatchPayloadV2;
    if (!Array.isArray(payload.results)) {
      throw new Error('v2 results are not an array');
    }
    return {
      raw: structuredClone(value),
      results: structuredClone(payload.results),
      payloadV2: structuredClone(payload),
    };
  }
  return {
    raw: structuredClone(value),
    results: structuredClone(value) as ReleaseValidationObservationBatchResult[],
    payloadV2: null,
  };
}

function storedBatchSchemaVersion(resultsJson: string): 1 | 2 {
  try {
    return parseStoredBatchResults(resultsJson).payloadV2
      ? RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION
      : RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION;
  } catch {
    return RELEASE_VALIDATION_OBSERVATION_BATCH_LEGACY_SCHEMA_VERSION;
  }
}

function v2PayloadProblems(
  payload: ReleaseValidationObservationBatchPayloadV2,
  row: ReleaseValidationObservationBatchReceiptRow,
): {
  metadata: string[];
  forecasts: string[];
  results: string[];
  outcomeRefs: string[];
} {
  const problems = {
    metadata: [] as string[],
    forecasts: [] as string[],
    results: [] as string[],
    outcomeRefs: [] as string[],
  };
  if (
    payload.kind !== RELEASE_VALIDATION_OBSERVATION_BATCH_PAYLOAD_KIND ||
    payload.schemaVersion !== RELEASE_VALIDATION_OBSERVATION_BATCH_SCHEMA_VERSION ||
    payload.batchId !== row.batch_id ||
    payload.observedAt !== row.observed_at ||
    payload.codeRevision !== row.code_revision ||
    payload.sourceIdentityDigest !== row.source_identity_digest ||
    payload.outcomeChainPreviousHash !== row.outcome_chain_previous_hash ||
    payload.outcomeChainContentHash !== row.outcome_chain_content_hash ||
    payload.previousBatchContentHash !== row.previous_content_hash
  ) {
    problems.metadata.push('receipt projection mismatch');
  }
  try {
    validateForecastInputs(payload.forecastInputs, row.forecast_count);
    if (
      payload.forecastInputSetHash !==
      releaseValidationObservationBatchSetHash(
        'forecast-inputs',
        payload.forecastInputs,
      )
    ) {
      problems.forecasts.push('set hash mismatch');
    }
  } catch (error) {
    problems.forecasts.push((error as Error).message);
  }
  try {
    if (
      canonicalReleaseValidationBatchJson(payload.results) !==
      canonicalReleaseValidationBatchJson(sortBatchResults(payload.results))
    ) {
      problems.results.push('results are not in canonical set order');
    }
    if (
      payload.resultSetHash !==
      releaseValidationObservationBatchSetHash('results', payload.results)
    ) {
      problems.results.push('set hash mismatch');
    }
    const counts = validateResultShapes(
      payload.results,
      row.forecast_count,
      payload.forecastInputs,
    );
    const expectedCounts = batchCounts(
      row.forecast_count,
      payload.results,
      row.intended_count,
      counts,
    );
    if (
      canonicalReleaseValidationBatchJson(payload.counts) !==
      canonicalReleaseValidationBatchJson(expectedCounts)
    ) {
      problems.results.push('counts mismatch');
    }
  } catch (error) {
    problems.results.push((error as Error).message);
  }
  try {
    validateOutcomeReferences(payload.outcomeRefs);
    if (
      payload.outcomeRefSetHash !==
      releaseValidationObservationBatchSetHash('outcome-refs', payload.outcomeRefs)
    ) {
      problems.outcomeRefs.push('set hash mismatch');
    }
    if (payload.outcomeRefs.length !== row.inserted_count) {
      problems.outcomeRefs.push('reference count mismatch');
    }
  } catch (error) {
    problems.outcomeRefs.push((error as Error).message);
  }
  const payloadWithoutKey = { ...payload };
  delete (payloadWithoutKey as Partial<ReleaseValidationObservationBatchPayloadV2>).batchKey;
  if (
    !/^[0-9a-f]{64}$/.test(payload.batchKey) ||
    payload.batchKey !== releaseValidationObservationBatchKey(
      payloadWithoutKey as Omit<ReleaseValidationObservationBatchPayloadV2, 'batchKey'>,
    )
  ) {
    problems.metadata.push('batch key mismatch');
  }
  return problems;
}

function validateForecastInputs(
  inputs: ReleaseValidationObservationBatchForecastInput[],
  forecastCount: number,
): void {
  if (!Array.isArray(inputs) || inputs.length !== forecastCount) {
    throw new Error('forecast inputs do not match forecast count');
  }
  const seen = new Set<string>();
  for (const input of inputs) {
    if (
      !input ||
      typeof input !== 'object' ||
      !String(input.decisionId ?? '').trim() ||
      !/^[0-9a-f]{64}$/.test(String(input.contentHash ?? ''))
    ) {
      throw new Error('forecast input identity or content hash is invalid');
    }
    if (seen.has(input.decisionId)) {
      throw new Error(`forecast input ${JSON.stringify(input.decisionId)} is duplicated`);
    }
    seen.add(input.decisionId);
  }
  if (
    canonicalReleaseValidationBatchJson(inputs) !==
    canonicalReleaseValidationBatchJson(sortForecastInputs(inputs))
  ) {
    throw new Error('forecast inputs are not in canonical sorted order');
  }
}

function sortForecastInputs(
  inputs: ReleaseValidationObservationBatchForecastInput[],
): ReleaseValidationObservationBatchForecastInput[] {
  return structuredClone(inputs).sort((left, right) =>
    left.decisionId.localeCompare(right.decisionId) ||
    left.contentHash.localeCompare(right.contentHash));
}

function sortBatchResults(
  results: ReleaseValidationObservationBatchResult[],
): ReleaseValidationObservationBatchResult[] {
  return structuredClone(results).sort((left, right) =>
    String(left.decisionId ?? '').localeCompare(String(right.decisionId ?? '')) ||
    String(left.horizonCode ?? '').localeCompare(String(right.horizonCode ?? '')) ||
    canonicalReleaseValidationBatchJson(left).localeCompare(
      canonicalReleaseValidationBatchJson(right),
    ));
}

function outcomeReferencesFromRows(
  rows: ReleaseValidationOutcomeLedgerRow[],
): ReleaseValidationObservationBatchOutcomeReference[] {
  return sortOutcomeReferences(rows.map((row) => ({
    observationId: row.observation_id,
    observationContentHash: String(row.content_hash ?? ''),
    decisionId: row.decision_id,
    horizonCode: row.horizon_code,
    status: row.status as 'matured' | 'indeterminate',
  })));
}

function outcomeReferencesFromResults(
  results: ReleaseValidationObservationBatchResult[],
): ReleaseValidationObservationBatchOutcomeReference[] {
  return sortOutcomeReferences(results.map((result) => ({
    observationId: String(result.observationId ?? ''),
    observationContentHash: String(result.observationContentHash ?? ''),
    decisionId: result.decisionId,
    horizonCode: result.horizonCode,
    status: result.status as 'matured' | 'indeterminate',
  })));
}

function sortOutcomeReferences(
  references: ReleaseValidationObservationBatchOutcomeReference[],
): ReleaseValidationObservationBatchOutcomeReference[] {
  return structuredClone(references).sort((left, right) =>
    left.observationId.localeCompare(right.observationId) ||
    left.observationContentHash.localeCompare(right.observationContentHash));
}

function validateOutcomeReferences(
  references: ReleaseValidationObservationBatchOutcomeReference[],
): void {
  if (!Array.isArray(references)) {
    throw new Error('outcome references are not an array');
  }
  const seen = new Set<string>();
  for (const reference of references) {
    if (
      !reference ||
      typeof reference !== 'object' ||
      !reference.observationId ||
      !/^[0-9a-f]{64}$/.test(reference.observationContentHash) ||
      !reference.decisionId ||
      !(reference.horizonCode in RELEASE_VALIDATION_HORIZONS) ||
      !['matured', 'indeterminate'].includes(reference.status)
    ) {
      throw new Error('outcome reference identity is invalid');
    }
    const key = outcomeReferenceKey(reference);
    if (seen.has(key)) {
      throw new Error(`outcome reference ${JSON.stringify(key)} is duplicated`);
    }
    seen.add(key);
  }
  if (
    canonicalReleaseValidationBatchJson(references) !==
    canonicalReleaseValidationBatchJson(sortOutcomeReferences(references))
  ) {
    throw new Error('outcome references are not in canonical sorted order');
  }
}

function outcomeReferenceKey(
  reference: Pick<
    ReleaseValidationObservationBatchOutcomeReference,
    'observationId' | 'observationContentHash'
  >,
): string {
  return `${reference.observationId}\0${reference.observationContentHash}`;
}

function resultOutcomePayloadProblem(
  result: ReleaseValidationObservationBatchResult,
  outcome: ReleaseValidationOutcomeLedgerRow,
): string | null {
  let payload: unknown;
  try {
    payload = JSON.parse(outcome.outcome_json);
  } catch {
    return 'outcome JSON is malformed';
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return 'outcome payload is not an object';
  }
  const record = payload as Record<string, unknown>;
  if (result.status === 'matured') {
    if (
      typeof record.adverse !== 'boolean' ||
      typeof result.adverse !== 'boolean' ||
      result.adverse !== record.adverse
    ) {
      return 'matured adverse summary does not match outcome payload';
    }
    return null;
  }
  if (result.status === 'indeterminate') {
    if (
      typeof record.reason !== 'string' ||
      !record.reason.trim() ||
      typeof record.fatal !== 'boolean' ||
      result.reason !== record.reason ||
      result.fatal !== record.fatal
    ) {
      return 'indeterminate summary does not match outcome payload';
    }
  }
  return null;
}

function validateOutcomeInput(
  input: Omit<
    ReleaseValidationOutcomeLedgerRow,
    'id' | 'observation_id' | 'previous_content_hash' | 'content_hash'
  >,
): void {
  if (
    !input.decision_id.trim() ||
    !(input.horizon_code in RELEASE_VALIDATION_HORIZONS) ||
    !['matured', 'indeterminate'].includes(input.status) ||
    !Number.isFinite(Date.parse(input.observed_at))
  ) {
    throw new Error('Validation outcome input identity, status, horizon, or timestamp is invalid');
  }
  JSON.parse(input.outcome_json);
  const sourceIdentity = JSON.parse(input.source_identity_json);
  if (
    !sourceIdentity ||
    typeof sourceIdentity !== 'object' ||
    Array.isArray(sourceIdentity) ||
    typeof sourceIdentity.digest !== 'string' ||
    !sourceIdentity.digest
  ) {
    throw new Error('Validation outcome source identity is missing its digest');
  }
}

function outcomeBusinessKey(
  row: Pick<ReleaseValidationOutcomeLedgerRow, 'decision_id' | 'horizon_code'>,
): string {
  return `${row.decision_id}\0${row.horizon_code}`;
}

function outcomeChainIndex(
  hash: string | null,
  indexByHash: Map<string, number>,
): number | null {
  if (hash == null) return -1;
  return indexByHash.get(hash) ?? null;
}

function orderRows<T extends { id?: number }>(rows: T[]): T[] {
  return rows
    .map((row, index) => ({ row, index }))
    .sort((left, right) => {
      const leftId = Number(left.row.id);
      const rightId = Number(right.row.id);
      const leftValid = Number.isInteger(leftId) && leftId > 0;
      const rightValid = Number.isInteger(rightId) && rightId > 0;
      if (leftValid && rightValid && leftId !== rightId) return leftId - rightId;
      if (leftValid !== rightValid) return leftValid ? -1 : 1;
      return left.index - right.index;
    })
    .map((item) => item.row);
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, nested]) => nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalValue(nested)]),
    );
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('Canonical validation batch JSON does not support non-finite numbers');
  }
  return value;
}
