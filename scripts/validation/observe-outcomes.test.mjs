import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assertObservationBatchRetryEquivalent,
  summarizeObservationForecastCoverage,
} from './observe-outcomes.mjs';
import {
  canonicalReleaseValidationBatchJson,
  releaseValidationObservationBatchContentHash,
  stageReleaseValidationObservationBatchReceipt,
} from '../../src/lib/releaseValidationBatch.ts';

test('observe retry requires the exact canonical v2 forecast set', () => {
  const forecastInputs = [
    { decisionId: 'forecast-a', contentHash: 'a'.repeat(64) },
    { decisionId: 'forecast-b', contentHash: 'b'.repeat(64) },
  ];
  const results = forecastInputs.flatMap((forecast, index) => [
    {
      decisionId: forecast.decisionId,
      opportunityCode: 'first_verified_after_24h',
      targetReleaseTag: `v${index + 1}`,
      horizonCode: 'field_regression_72h',
      status: 'pending',
      persistence: 'not_applicable',
    },
    {
      decisionId: forecast.decisionId,
      opportunityCode: 'first_verified_after_24h',
      targetReleaseTag: `v${index + 1}`,
      horizonCode: 'security_30d',
      status: 'excluded',
      persistence: 'not_applicable',
      reason: 'forecast_not_evaluable',
    },
  ]);
  const receipt = stageReleaseValidationObservationBatchReceipt(
    [],
    [],
    [],
    {
      batchId: 'observe-retry-v2',
      observedAt: '2026-07-04T12:00:00.000Z',
      codeRevision: 'observe-retry-revision',
      sourceIdentityDigest: 'c'.repeat(64),
      forecastCount: forecastInputs.length,
      forecastInputs,
      results,
    },
  );
  const retry = {
    codeRevision: receipt.code_revision,
    sourceIdentityDigest: receipt.source_identity_digest,
    forecastInputs,
  };
  assert.deepEqual(summarizeObservationForecastCoverage(
    results,
    forecastInputs.length,
  ), {
    schemaVersion: 1,
    authoritativeForecastCount: 2,
    evaluatedForecastCount: 2,
    observedForecastCount: 0,
    eligibleForecastCount: 0,
    excludedForecastCount: 0,
    partiallyExcludedForecastCount: 2,
    pendingForecastCount: 2,
    missingForecastCount: 0,
    extraForecastCount: 0,
    partitionValid: true,
  });

  assert.doesNotThrow(() =>
    assertObservationBatchRetryEquivalent(receipt, retry));
  assert.throws(
    () => assertObservationBatchRetryEquivalent(receipt, {
      ...retry,
      forecastInputs: [
        forecastInputs[0],
        { ...forecastInputs[1], contentHash: 'd'.repeat(64) },
      ],
    }),
    /forecastInputSet/,
  );
  assert.throws(
    () => assertObservationBatchRetryEquivalent(receipt, {
      ...retry,
      forecastInputs: [...forecastInputs].reverse(),
    }),
    /forecastInputSet/,
  );

  const reorderedReceipt = structuredClone(receipt);
  const wrapper = JSON.parse(reorderedReceipt.results_json);
  wrapper[0].forecastInputs.reverse();
  reorderedReceipt.results_json = canonicalReleaseValidationBatchJson(wrapper);
  reorderedReceipt.content_hash =
    releaseValidationObservationBatchContentHash(reorderedReceipt);
  assert.throws(
    () => assertObservationBatchRetryEquivalent(reorderedReceipt, retry),
    /receiptPayload/,
  );
});

test('observe retry refuses to treat a legacy receipt as v2-equivalent', () => {
  const legacyReceipt = stageReleaseValidationObservationBatchReceipt(
    [],
    [],
    [],
    {
      batchId: 'observe-retry-legacy',
      observedAt: '2026-07-04T12:00:00.000Z',
      codeRevision: 'observe-retry-revision',
      sourceIdentityDigest: 'e'.repeat(64),
      forecastCount: 1,
      results: [
        {
          decisionId: 'legacy-forecast',
          opportunityCode: 'first_verified_after_24h',
          targetReleaseTag: 'v-legacy',
          horizonCode: 'field_regression_72h',
          status: 'pending',
          persistence: 'not_applicable',
        },
        {
          decisionId: 'legacy-forecast',
          opportunityCode: 'first_verified_after_24h',
          targetReleaseTag: 'v-legacy',
          horizonCode: 'security_30d',
          status: 'excluded',
          persistence: 'not_applicable',
          reason: 'legacy_forecast',
        },
      ],
    },
  );

  assert.throws(
    () => assertObservationBatchRetryEquivalent(legacyReceipt, {
      codeRevision: legacyReceipt.code_revision,
      sourceIdentityDigest: legacyReceipt.source_identity_digest,
      forecastInputs: [
        { decisionId: 'legacy-forecast', contentHash: 'f'.repeat(64) },
      ],
    }),
    /schemaVersion/,
  );
});
