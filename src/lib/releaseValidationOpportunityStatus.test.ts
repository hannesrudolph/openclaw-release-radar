import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import {
  buildReleaseValidationOpportunityStatus,
  releaseValidationOpportunityStatusExitCode,
} from './releaseValidationOpportunityStatus';
import {
  buildReleaseValidationOpportunityDenominatorLedger,
  planReleaseValidationOpportunityEnrollments,
  releaseValidationOpportunityEnrollmentContentHash,
  releaseValidationOpportunityId,
  type ReleaseValidationOpportunityEnrollmentRow,
} from './releaseValidationOpportunityDenominator';
import {
  type ReleaseValidationForecastLedgerRow,
} from './releaseValidation';

const publishedAt = '2026-07-01T00:00:00.000Z';
const modelVersion = 'evidence-v26-calibrated-evidence';
const promptVersion = 8;
const currentRevision = 'test-revision';

describe('release validation opportunity status', () => {
  it('uses persisted inclusive-start and exclusive-end enrollment windows', () => {
    assert.equal(statusAt('2026-07-01T02:59:59.999Z').opportunities[0].state, 'upcoming');
    assert.equal(statusAt('2026-07-01T03:00:00.000Z').opportunities[0].state, 'open');
    assert.equal(statusAt('2026-07-01T05:59:59.999Z').opportunities[0].state, 'open');
    assert.equal(statusAt('2026-07-01T06:00:00.000Z').opportunities[0].state, 'missed');
    assert.equal(statusAt('2026-07-02T00:00:00.000Z').opportunities[1].state, 'open');
    assert.equal(statusAt('2026-07-02T06:00:00.000Z').opportunities[1].state, 'missed');
  });

  it('counts only exact current model, prompt, and code revision captures', () => {
    const current = forecast({
      decisionId: 'current',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-07-01T03:30:00.000Z',
    });
    const oldModel = forecast({
      decisionId: 'old-model',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-07-01T03:45:00.000Z',
      scoreModelVersion: 'evidence-v22-advisory-consistency',
    });
    const oldPrompt = forecast({
      decisionId: 'old-prompt',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-07-01T03:50:00.000Z',
      forecastPromptVersion: promptVersion - 1,
    });
    const oldRevision = forecast({
      decisionId: 'old-revision',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-07-01T03:55:00.000Z',
      codeRevision: 'previous-revision',
    });
    const late = forecast({
      decisionId: 'late',
      opportunityCode: 'first_verified_after_24h',
      recordedAt: '2026-07-02T08:00:00.000Z',
    });
    const report = statusAt(
      '2026-07-02T08:30:00.000Z',
      [current, oldModel, oldPrompt, oldRevision, late],
    );
    assert.equal(report.opportunities[0].state, 'captured');
    assert.equal(report.opportunities[0].capturedDecisionId, 'current');
    assert.equal(report.opportunities[0].otherSeriesForecastCount, 3);
    assert.equal(report.opportunities[1].state, 'missed');
    assert.equal(report.opportunities[1].invalidCurrentSeriesForecastCount, 1);
    assert.equal(report.counts.invalidLegacyForecasts, 1);
    assert.equal(report.denominatorLedger.rowCount, 2);
    assert.match(report.denominatorLedger.rows[0].opportunityId, /^[0-9a-f]{64}$/);
    assert.match(
      report.denominatorLedger.rows[0].stateContentHash,
      /^[0-9a-f]{64}$/,
    );
  });

  it('does not invent retrospective misses before prospective enrollment', () => {
    const now = '2026-07-03T00:00:00.000Z';
    const report = statusAt(now, [], currentRevision, now);
    assert.equal(report.denominatorLedger.rowCount, 0);
    assert.equal(report.counts.missed, 0);
    assert.equal(report.overallStatus, 'not_enrolled');
    assert.equal(report.currentStratum.status, report.overallStatus);
    assert.equal(releaseValidationOpportunityStatusExitCode(report), 2);
  });

  it('keeps enrolled slots after their release is no longer in the active catalog', () => {
    const captured = forecast({
      decisionId: 'captured-old-release',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-07-01T04:00:00.000Z',
    });
    const report = statusAt('2026-07-03T00:00:00.000Z', [captured]);
    assert.equal(report.denominatorLedger.rowCount, 2);
    assert.equal(report.counts.captured, 1);
    assert.equal(report.counts.missed, 1);
    assert.equal(report.latestRelease?.tag, 'v2099.7.1');
    assert.equal(report.currentStratum.status, report.overallStatus);
  });

  it('reports open, missed, captured, and integrity-failed exit states', () => {
    assert.equal(
      releaseValidationOpportunityStatusExitCode(
        statusAt('2026-07-01T04:00:00.000Z'),
      ),
      3,
    );
    assert.equal(
      releaseValidationOpportunityStatusExitCode(
        statusAt('2026-07-03T00:00:00.000Z'),
      ),
      4,
    );
    const captured = [
      forecast({
        decisionId: '3h',
        opportunityCode: 'first_verified_after_3h',
        recordedAt: '2026-07-01T03:30:00.000Z',
      }),
      forecast({
        decisionId: '24h',
        opportunityCode: 'first_verified_after_24h',
        recordedAt: '2026-07-02T00:30:00.000Z',
      }),
    ];
    assert.equal(
      releaseValidationOpportunityStatusExitCode(
        statusAt('2026-07-03T00:00:00.000Z', captured),
      ),
      0,
    );

    const failed = statusAt('2026-07-01T04:00:00.000Z');
    failed.denominatorLedger.integrity.errors.push('tampered');
    failed.denominatorLedger.integrity.valid = false;
    const rebuilt = buildReleaseValidationOpportunityStatus({
      now: failed.asOf,
      denominatorLedger: {
        ...denominatorAt(failed.asOf, []),
        integrity: failed.denominatorLedger.integrity,
      },
      forecasts: [],
      currentSeries: {
        modelVersion,
        promptVersion,
        codeRevision: currentRevision,
      },
    });
    assert.equal(rebuilt.overallStatus, 'failed');
    assert.equal(rebuilt.currentStratum.status, 'failed');
    assert.equal(releaseValidationOpportunityStatusExitCode(rebuilt), 1);
  });

  it('requires a concrete current code revision', () => {
    assert.throws(
      () => statusAt('2026-07-01T04:00:00.000Z', [], '   '),
      /code revision is required/,
    );
  });
});

function statusAt(
  now: string,
  forecasts: ReleaseValidationForecastLedgerRow[] = [],
  codeRevision: string = currentRevision,
  enrolledAt: string = '2026-07-01T01:00:00.000Z',
) {
  const denominatorLedger = denominatorAt(now, forecasts, enrolledAt);
  return buildReleaseValidationOpportunityStatus({
    now,
    denominatorLedger,
    forecasts,
    currentSeries: {
      modelVersion,
      promptVersion,
      codeRevision,
    },
    currentAudit: {
      scoreModelVersion: modelVersion,
      promptVersion,
      scoredAt: now,
    },
  });
}

function denominatorAt(
  now: string,
  forecasts: ReleaseValidationForecastLedgerRow[],
  enrolledAt: string = '2026-07-01T01:00:00.000Z',
) {
  return buildReleaseValidationOpportunityDenominatorLedger({
    asOf: now,
    enrollments: enrollmentRows(enrolledAt),
    forecasts,
  });
}

function enrollmentRows(enrolledAt: string):
ReleaseValidationOpportunityEnrollmentRow[] {
  const inputs = planReleaseValidationOpportunityEnrollments({
    enrolledAt,
    release: {
      nodeId: 'release-node-v2099.7.1',
      tag: 'v2099.7.1',
      tagCommitOid: 'c'.repeat(40),
      publishedAt,
    },
    cohort: {
      modelVersion,
      promptVersion,
      codeRevision: currentRevision,
    },
    evidence: {
      enrollmentRunId: 'refresh-enrollment-run',
      operationAttemptContentHash: 'a'.repeat(64),
      catalogDigest: 'b'.repeat(64),
      catalogReleaseCount: 10,
    },
  });
  let previousContentHash: string | null = null;
  return inputs.map((input, index) => {
    const opportunityId = releaseValidationOpportunityId(input);
    const contentHash = releaseValidationOpportunityEnrollmentContentHash({
      ...input,
      opportunity_id: opportunityId,
      previous_content_hash: previousContentHash,
    });
    const row = {
      id: index + 1,
      ...input,
      opportunity_id: opportunityId,
      previous_content_hash: previousContentHash,
      content_hash: contentHash,
    };
    previousContentHash = contentHash;
    return row;
  });
}

function forecast(input: {
  decisionId: string;
  opportunityCode: 'first_verified_after_3h' | 'first_verified_after_24h';
  recordedAt: string;
  scoreModelVersion?: string;
  forecastPromptVersion?: number;
  codeRevision?: string | null;
}): ReleaseValidationForecastLedgerRow {
  return {
    id: 1,
    decision_id: input.decisionId,
    opportunity_code: input.opportunityCode,
    recorded_at: input.recordedAt,
    latest_release_tag: 'v2099.7.1',
    latest_release_published_at: publishedAt,
    selected_tag: 'v2099.7.1',
    audit_history_run_id: 'run',
    score_model_version: input.scoreModelVersion ?? modelVersion,
    prompt_version: input.forecastPromptVersion ?? promptVersion,
    policy_code: 'highest_confidence_with_recency_tolerance',
    candidate_scores_json: '[]',
    decision_json: JSON.stringify({ schemaVersion: 4 }),
    source_identity_json: JSON.stringify({ digest: 'source' }),
    code_revision: input.codeRevision === undefined
      ? currentRevision
      : input.codeRevision,
    previous_content_hash: null,
    content_hash: createHash('sha256').update(input.decisionId).digest('hex'),
  };
}
