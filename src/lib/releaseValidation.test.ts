import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { describe, it } from 'node:test';
import {
  advisorySnapshotContentHash,
  assessReleaseValidationObservation,
  buildAdvisorySnapshotValidationEvidence,
  buildIndependentFieldEvidenceSnapshot,
  buildReleaseValidationIndeterminatePayload,
  DEFAULT_VALIDATION_SAMPLE_THRESHOLDS,
  evaluateReleaseValidationLedger,
  independentFieldAdverseEvidenceIdentity,
  independentFieldEvidenceContentHash,
  independentFieldIssueUniverseEntryIdentity,
  releaseValidationDecisionId,
  releaseValidationForecastContentHash,
  releaseValidationObservationId,
  releaseValidationObservationTargets,
  releaseValidationOutcomeContentHash,
  releaseValidationForecastTiming,
  releaseCatalogAttestationProblems,
  releaseValidationScoreCommitTimingProblems,
  releaseValidationEvaluationExitCode,
  validateReleaseValidationLedgerIntegrity,
  validateReleaseValidationForecastProvenance,
  wilsonInterval,
  type AdvisorySnapshotValidationEvidence,
  type AdvisorySnapshotValidationRow,
  type ObservationAssessmentInput,
  type IndependentFieldAdverseEvidence,
  type IndependentFieldEvidenceSnapshot,
  type ReleaseScoreAuditHistoryEvidenceRow,
  type ReleaseScoreAuditHistoryRunSealEvidenceRow,
  type ReleaseScoreAuditHistoryV2SealEvidence,
  type ReleaseScoreAuthorityRunEvidence,
  type ReleaseValidationForecastLedgerRow,
  type ReleaseValidationHorizonCode,
  type ReleaseValidationOutcomeLedgerRow,
  type ReleaseValidationProspectiveProofInput,
} from './releaseValidation.ts';

const TSX_BIN = join(
  import.meta.dirname,
  '..',
  '..',
  'node_modules',
  '.bin',
  'tsx',
);
import {
  COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
  advisoryVulnerabilityKey,
  compoundAdvisorySnapshotMetadataDigest,
} from './advisorySnapshot.ts';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from './scoreHistoryLedger.ts';
import {
  buildReleaseScoreAuditHistoryV2Seal,
  buildScoreAuthorityResolutionRun,
} from './scoreAuthorityResolution.ts';
import {
  sealReleaseValidationForecastV2,
  sealReleaseValidationObservationBatch,
  sealReleaseValidationOutcomeV2,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';
import {
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle.ts';
import { commentEvidenceDigest } from './commentEvidence.ts';
import { normalizeCodeRevision } from './codeRevision.ts';
import {
  buildReleaseValidationOpportunityDenominatorLedger,
  releaseValidationOpportunityEnrollmentContentHash,
  releaseValidationOpportunityId,
  type ReleaseValidationOpportunityDenominatorLedger,
  type ReleaseValidationOpportunityEnrollmentRow,
} from './releaseValidationOpportunityDenominator.ts';
import {
  buildScoreLedgerV2,
  installConfidence,
  type InstallInput,
} from './score.ts';
import {
  filterCanonicalReleaseValidationProofAsOf,
  filterScoreQualityEvidenceAsOf,
} from '../../scripts/validation/evaluate-score-quality.mjs';

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const FORECAST_AT = '2026-01-01T00:00:00.000Z';
const SOURCE_OLD = { schemaVersion: 2, digest: 'source-old' };
const SOURCE_NEW = { schemaVersion: 2, digest: 'source-new' };
const TEST_CODE_REVISION = 'test-revision';

function forecast(overrides: Partial<ReleaseValidationForecastLedgerRow> = {}): ReleaseValidationForecastLedgerRow {
  return {
    id: 1,
    decision_id: 'decision-1',
    opportunity_code: 'first_verified_after_24h',
    recorded_at: FORECAST_AT,
    latest_release_tag: 'v2026.1.1',
    latest_release_published_at: '2025-12-31T00:00:00.000Z',
    selected_tag: 'v2026.1.1',
    audit_history_run_id: 'run-forecast',
    score_model_version: 'model-v1',
    prompt_version: 6,
    policy_code: 'highest_confidence_with_recency_tolerance',
    candidate_scores_json: '[{"tag":"v2026.1.1","score":8.5}]',
    decision_json: '{"schemaVersion":4,"selectedTag":"v2026.1.1"}',
    source_identity_json: JSON.stringify(SOURCE_OLD),
    content_hash: 'forecast-hash',
    ...overrides,
  };
}

function audit(overrides: Partial<ReleaseScoreAuditHistoryEvidenceRow> = {}): ReleaseScoreAuditHistoryEvidenceRow {
  return {
    id: 2,
    run_id: 'run-observe',
    recorded_at: '2026-02-02T00:00:00.000Z',
    release_tag: 'v2026.1.1',
    scored_at: '2026-02-02T00:00:00.000Z',
    score_model_version: 'model-v1',
    prompt_version: 6,
    final_score: 8.5,
    status: 'eligible',
    band: 'good',
    recommended: 1,
    input_json: JSON.stringify({
      rawIssueCount: 10,
      classifiedIssueCount: 10,
      hoursToNextStable: null,
    }),
    components_json: '{"schemaVersion":1}',
    issue_evidence_json: JSON.stringify({
      schemaVersion: 2,
      evidenceCounts: {
        verifiedDebt: 0,
        carryoverDebt: 0,
        staleDebt: 0,
        openedFeltSerious: 0,
        verifiedFixed: 0,
        unverifiedClosed: 0,
        unclassifiedIssues: 0,
      },
      debtSummary: { verified: { count: 0 } },
      verifiedDebt: [],
      openedFeltSerious: [],
      unclassifiedIssues: [],
    }),
    gate_evidence_json: '{"schemaVersion":1}',
    source_identity_json: JSON.stringify(SOURCE_NEW),
    ...overrides,
  };
}

function advisoryRow(
  overrides: Partial<AdvisorySnapshotValidationRow> = {},
): AdvisorySnapshotValidationRow {
  const row = {
    ghsa_id: 'GHSA-default',
    cve_id: null,
    summary: 'test advisory',
    severity: 'high',
    html_url: 'https://example.test/GHSA-default',
    published_at: '2026-01-20T00:00:00.000Z',
    package_ecosystem: 'npm',
    package_name: 'openclaw',
    vulnerable_version_range: '<= 2026.1.1',
    patched_versions: '>= 2026.1.2',
    ...overrides,
  };
  return {
    ...row,
    advisory_key: overrides.advisory_key ?? advisoryVulnerabilityKey(
      row.ghsa_id,
      row.package_ecosystem,
      row.package_name,
      row.vulnerable_version_range,
    ),
  };
}

function advisorySnapshot(
  rows: AdvisorySnapshotValidationRow[] = [],
  overrides: Partial<AdvisorySnapshotValidationEvidence> = {},
): AdvisorySnapshotValidationEvidence {
  return {
    snapshotId: 1,
    capturedAt: '2026-02-01T00:00:00.000Z',
    rowCount: rows.length,
    contentHash: advisorySnapshotContentHash(rows),
    rows,
    ...overrides,
  };
}

function authorizedAdvisorySnapshot(
  rows: AdvisorySnapshotValidationRow[] = [],
  overrides: Partial<AdvisorySnapshotValidationEvidence> = {},
): AdvisorySnapshotValidationEvidence {
  const snapshot = advisorySnapshot(rows, {
    schemaVersion: 2,
    ...overrides,
  });
  const metadata = {
    schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    snapshotId: snapshot.snapshotId,
    capturedAt: snapshot.capturedAt,
    repository: {
      owner: 'openclaw',
      name: 'openclaw',
      url: 'https://github.com/openclaw/openclaw',
    },
    target: {
      ecosystem: 'npm',
      packageName: 'openclaw',
    },
    sourceHash: '1'.repeat(64),
    catalogHash: '2'.repeat(64),
    scoreHash: '3'.repeat(64),
    contentHash: '4'.repeat(64),
    previousContentHash: null,
    rowCount: rows.length,
    scoreRowCount: rows.length,
    scoreReady: true as const,
    scoreContentDigest: snapshot.contentHash,
  };
  return {
    ...snapshot,
    provenance: {
      schemaVersion: 2,
      metadata,
      ledgerContentHash: metadata.contentHash,
      previousLedgerContentHash: metadata.previousContentHash,
      sourceHash: metadata.sourceHash,
      catalogHash: metadata.catalogHash,
      scoreHash: metadata.scoreHash,
      scoreContentDigest: metadata.scoreContentDigest,
      metadataDigest: compoundAdvisorySnapshotMetadataDigest(metadata),
      publication: {
        receiptId: `receipt-${snapshot.snapshotId}`,
        runId: `run-${snapshot.snapshotId}`,
        receiptSemanticIdentity: '5'.repeat(64),
        operationStartedAt: new Date(
          Date.parse(snapshot.capturedAt) - HOUR_MS,
        ).toISOString(),
        finishedAt: new Date(
          Date.parse(snapshot.capturedAt) + HOUR_MS,
        ).toISOString(),
      },
    },
  };
}

function cleanEvidence(
  horizonCode: ReleaseValidationHorizonCode,
  overrides: Partial<ObservationAssessmentInput> = {},
): ObservationAssessmentInput {
  const row = overrides.forecast ?? forecast();
  const targets = releaseValidationObservationTargets(row);
  const postHorizonAt = horizonCode === 'field_regression_72h'
    ? '2026-01-05T00:00:00.000Z'
    : '2026-02-02T00:00:00.000Z';
  return {
    forecast: row,
    horizonCode,
    now: postHorizonAt,
    auditHistory: targets.map((target, index) => audit({
      id: index + 2,
      run_id: `run-observe-${horizonCode}`,
      release_tag: target.targetReleaseTag,
      recorded_at: postHorizonAt,
      scored_at: postHorizonAt,
    })),
    currentSourceIdentity: SOURCE_NEW,
    issueCrawl: {
      finishedAt: postHorizonAt,
      scorePersistedAt: postHorizonAt,
      scorePersisted: true,
      stopReason: 'early_stop',
      backfillCompleteAfterRun: true,
      commenterScanTruncatedCount: 0,
      classificationFailures: [],
      evidenceRefreshFailures: [],
    },
    scorePersistence: {
      persistedAt: postHorizonAt,
      scoreModelVersion: 'model-v1',
      promptVersion: 6,
      sourceIdentityDigest: SOURCE_NEW.digest,
      releaseTags: targets.map((target) => target.targetReleaseTag),
      issueCrawlFinishedAt: postHorizonAt,
      issueCrawlScorePersistedAt: postHorizonAt,
    },
    advisorySnapshots: [],
    independentFieldEvidence: horizonCode === 'field_regression_72h'
      ? targets.map((target) => independentFieldSnapshot(row, [], {
          targetReleaseTag: target.targetReleaseTag,
        }))
      : null,
    ...overrides,
  };
}

function independentFieldSnapshot(
  row: ReleaseValidationForecastLedgerRow,
  evidenceRefs: IndependentFieldAdverseEvidence[] = [],
  overrides: Partial<IndependentFieldEvidenceSnapshot> = {},
): IndependentFieldEvidenceSnapshot {
  const windowEndAt = new Date(Date.parse(row.recorded_at) + 72 * HOUR_MS).toISOString();
  const issueUniverse = evidenceRefs.map((evidence) => {
    const entry = {
      issueNumber: evidence.issueNumber,
      issueUrl: evidence.issueUrl,
      createdAt: evidence.createdAt,
      state: evidence.state,
      issueUpdatedAt: evidence.createdAt,
      issueContentFrozenAtHorizon: true,
      issueEvidenceIdentity: '1'.repeat(64),
      commentSnapshotEvidenceIdentity: '2'.repeat(64),
      commentEvidenceIdentities: [],
      labelEventEvidenceIdentities: [],
      closureProofEvidenceIdentities: [],
      adverseEvidenceIdentity: evidence.evidenceIdentity,
    };
    return {
      ...entry,
      evidenceIdentity: independentFieldIssueUniverseEntryIdentity(entry),
    };
  });
  const snapshot = {
    schemaVersion: 3 as const,
    capturedAt: new Date(Date.parse(windowEndAt) + DAY_MS).toISOString(),
    targetReleaseTag: row.selected_tag ?? row.latest_release_tag,
    windowStartAt: row.recorded_at,
    windowEndAt,
    complete: true,
    issueUniverseCount: evidenceRefs.length,
    completeCommentSnapshotCount: evidenceRefs.length,
    incompleteIssueNumbers: [],
    mutableIssueContentNumbers: [],
    issueUniverse,
    evidenceRefs,
    ...overrides,
  };
  const {
    contentHash: _contentHash,
    ...snapshotWithoutHash
  } = snapshot;
  return {
    ...snapshotWithoutHash,
    contentHash: independentFieldEvidenceContentHash(snapshotWithoutHash),
  };
}

function independentAdverseEvidence(
  row: ReleaseValidationForecastLedgerRow,
  issueNumber = 101,
  overrides: Partial<IndependentFieldAdverseEvidence> = {},
): IndependentFieldAdverseEvidence {
  const targetTag = row.selected_tag ?? row.latest_release_tag;
  const evidence = {
    sourceClass: 'exact_version_human_confirmation',
    issueNumber,
    issueUrl: `https://example.test/issues/${issueNumber}`,
    createdAt: new Date(Date.parse(row.recorded_at) + HOUR_MS).toISOString(),
    state: 'open',
    versionLink: {
      source: 'title',
      version: targetTag,
      referenceUrl: `https://example.test/issues/${issueNumber}`,
      commentId: null,
      author: 'reporter',
      snippet: `Regression on ${targetTag}`,
    },
    confirmations: [{
      source: 'comment',
      sourceClass: 'independent_human_reproduction',
      actor: 'second-user',
      occurredAt: new Date(Date.parse(row.recorded_at) + 2 * HOUR_MS).toISOString(),
      referenceUrl: `https://example.test/issues/${issueNumber}#comment-1`,
      commentId: issueNumber * 10,
      eventId: null,
      label: null,
      snippet: 'I can confirm the same issue.',
    }],
    laterFixes: [],
    ...overrides,
  };
  return {
    ...evidence,
    evidenceIdentity: independentFieldAdverseEvidenceIdentity(evidence),
  };
}

describe('release validation observation assessment', () => {
  it('enforces inclusive starts and exclusive ends for forecast opportunities', () => {
    const timing = (
      opportunityCode: string,
      ageHours: number,
    ) => releaseValidationForecastTiming(forecast({
      opportunity_code: opportunityCode,
      recorded_at: new Date(Date.parse('2026-01-01T00:00:00.000Z') +
        ageHours * HOUR_MS).toISOString(),
      latest_release_published_at: '2026-01-01T00:00:00.000Z',
    }));
    assert.equal(timing('first_verified_after_3h', 3).valid, true);
    assert.equal(timing('first_verified_after_3h', 6).valid, false);
    assert.equal(timing('first_verified_after_24h', 24).valid, true);
    assert.equal(timing('first_verified_after_24h', 30).valid, false);
    const publishedAtMs = Date.parse('2026-01-01T00:00:00.000Z');
    assert.equal(releaseValidationForecastTiming(forecast({
      opportunity_code: 'first_verified_after_3h',
      recorded_at: new Date(publishedAtMs + 6 * HOUR_MS - 1).toISOString(),
      latest_release_published_at: new Date(publishedAtMs).toISOString(),
    })).valid, true);
    assert.equal(releaseValidationForecastTiming(forecast({
      opportunity_code: 'first_verified_after_3h',
      recorded_at: new Date(publishedAtMs + 6 * HOUR_MS).toISOString(),
      latest_release_published_at: new Date(publishedAtMs).toISOString(),
    })).valid, false);
  });

  it('validates schema-v4 catalog and score-commit attestation with distinct history/forecast times', () => {
    const historyRunId = 'run-schema-v4';
    const historyRecordedAt = '2026-01-01T03:00:00.000Z';
    const recordedAt = '2026-01-01T04:00:00.010Z';
    const historyRunContentHash = 'a'.repeat(64);
    const authorityRunId = 'score-authority:run-schema-v4';
    const authorityRunContentHash = 'd'.repeat(64);
    const historyV2SealContentHash = 'e'.repeat(64);
    const catalogAttestation = {
      schemaVersion: 4,
      initialRemoteCatalog: {
        digest: 'b'.repeat(64),
        totalCount: 2,
        nodeCount: 2,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        exhausted: true,
        stabilized: true,
        sourceOrder: 'CREATED_AT_DESC',
      },
      finalRemoteCatalog: {
        digest: 'b'.repeat(64),
        totalCount: 2,
        nodeCount: 2,
        pageCount: 1,
        pagesFetched: 3,
        sweepCount: 3,
        exhausted: true,
        stabilized: true,
        sourceOrder: 'CREATED_AT_DESC',
      },
      finalObservedAt: '2026-01-01T03:59:59.000Z',
      projectedActiveCatalog: {
        digest: 'c'.repeat(64),
        releaseCount: 2,
      },
      localActiveCatalog: {
        digest: 'c'.repeat(64),
        releaseCount: 2,
      },
      latestStable: {
        nodeId: 'R_latest',
        tag: 'v2026.1.1',
        tagCommitOid: '1'.repeat(40),
        publishedAt: '2026-01-01T00:00:00.000Z',
      },
      scoreBuiltAt: '2026-01-01T03:59:58.000Z',
    };
    const scoreCommit = {
      schemaVersion: 4,
      historyRunId,
      historyRunContentHash,
      authorityRunId,
      authorityRunContentHash,
      historyV2SealContentHash,
      historyRecordedAt,
      commitNotBefore: '2026-01-01T04:00:00.000Z',
      commitNotAfter: recordedAt,
      commitNotBeforeMs: Date.parse('2026-01-01T04:00:00.000Z'),
      commitNotAfterMs: Date.parse(recordedAt),
    };
    assert.deepEqual(releaseCatalogAttestationProblems(catalogAttestation), []);
    assert.deepEqual(releaseValidationScoreCommitTimingProblems(scoreCommit, {
      recordedAt,
      historyRunId,
      historyRunContentHash,
      historyRecordedAt,
      authorityRunId,
      authorityRunContentHash,
      historyV2SealContentHash,
    }), []);
    assert.match(
      releaseCatalogAttestationProblems({
        ...catalogAttestation,
        finalRemoteCatalog: {
          ...catalogAttestation.finalRemoteCatalog,
          digest: 'd'.repeat(64),
        },
      }).join('\n'),
      /do not agree/,
    );
    assert.match(
      releaseValidationScoreCommitTimingProblems({
        ...scoreCommit,
        commitNotAfterMs: scoreCommit.commitNotAfterMs - 1,
      }, {
        recordedAt,
        historyRunId,
        historyRunContentHash,
        historyRecordedAt,
      }).join('\n'),
      /not exact integer-millisecond/,
    );
  });

  it('reports pending before a horizon and never creates a backdated outcome', () => {
    const result = assessReleaseValidationObservation({
      ...cleanEvidence('field_regression_72h'),
      now: '2026-01-02T00:00:00.000Z',
    });
    assert.equal(result.status, 'pending');
    assert.equal(result.reason, 'horizon_not_reached');
  });

  it('uses independent raw evidence even when the classifier proxy under-detects', () => {
    const row = forecast();
    const evidence = independentAdverseEvidence(row);
    const result = assessReleaseValidationObservation(cleanEvidence('field_regression_72h', {
      forecast: row,
      independentFieldEvidence: independentFieldSnapshot(row, [evidence]),
      auditHistory: [fieldAudit([])],
    }));

    assert.equal(result.status, 'matured');
    if (result.status !== 'matured') return;
    assert.equal(result.outcome.adverse, true);
    assert.equal(result.outcome.fieldRegression?.issueCount, 1);
    assert.equal(result.outcome.fieldRegression?.clusterCount, 1);
    assert.equal(result.outcome.fieldRegression?.classifierProxy.adverse, false);
    assert.equal(
      result.outcome.fieldRegression?.evidenceRefs[0].sourceClass,
      'exact_version_human_confirmation',
    );
  });

  it('binds a later observation to the preceding post-horizon audit and evidence', () => {
    const row = forecast();
    const auditAt = '2026-01-04T01:00:00.000Z';
    const observedAt = '2026-01-04T02:00:00.000Z';
    const result = assessReleaseValidationObservation(cleanEvidence('field_regression_72h', {
      forecast: row,
      now: observedAt,
      auditHistory: [audit({ recorded_at: auditAt, scored_at: auditAt })],
      issueCrawl: {
        finishedAt: auditAt,
        scorePersistedAt: auditAt,
        scorePersisted: true,
        stopReason: 'early_stop',
        backfillCompleteAfterRun: true,
        commenterScanTruncatedCount: 0,
        classificationFailures: [],
        evidenceRefreshFailures: [],
      },
      scorePersistence: {
        persistedAt: auditAt,
        scoreModelVersion: 'model-v1',
        promptVersion: 6,
        sourceIdentityDigest: SOURCE_NEW.digest,
        releaseTags: ['v2026.1.1'],
        issueCrawlFinishedAt: auditAt,
        issueCrawlScorePersistedAt: auditAt,
      },
      independentFieldEvidence: independentFieldSnapshot(row, [], {
        capturedAt: auditAt,
      }),
    }));

    assert.equal(result.status, 'matured');
    if (result.status !== 'matured') return;
    assert.equal(result.observedAt, observedAt);
    assert.equal(result.outcome.observedAt, observedAt);
    assert.equal(result.outcome.auditEvidence.recordedAt, auditAt);
    assert.equal(result.outcome.fieldRegression?.evidenceCompleteness.capturedAt, auditAt);
  });

  it('fails closed when independent field evidence does not match the audit time', () => {
    const row = forecast();
    const auditAt = '2026-01-04T01:00:00.000Z';
    const observedAt = '2026-01-04T02:00:00.000Z';
    const base = cleanEvidence('field_regression_72h', {
      forecast: row,
      now: observedAt,
      auditHistory: [audit({ recorded_at: auditAt, scored_at: auditAt })],
      issueCrawl: {
        finishedAt: auditAt,
        scorePersistedAt: auditAt,
        scorePersisted: true,
        stopReason: 'early_stop',
        backfillCompleteAfterRun: true,
        commenterScanTruncatedCount: 0,
        classificationFailures: [],
        evidenceRefreshFailures: [],
      },
      scorePersistence: {
        persistedAt: auditAt,
        scoreModelVersion: 'model-v1',
        promptVersion: 6,
        sourceIdentityDigest: SOURCE_NEW.digest,
        releaseTags: ['v2026.1.1'],
        issueCrawlFinishedAt: auditAt,
        issueCrawlScorePersistedAt: auditAt,
      },
    });

    for (const capturedAt of [
      '2026-01-04T00:30:00.000Z',
      '2026-01-04T01:30:00.000Z',
    ]) {
      const result = assessReleaseValidationObservation({
        ...base,
        independentFieldEvidence: independentFieldSnapshot(row, [], { capturedAt }),
      });
      assert.equal(result.status, 'indeterminate');
      assert.equal(result.reason, 'independent_field_evidence_provenance_mismatch');
      assert.equal(result.fatal, true);
    }
  });

  it('builds exact-version evidence from complete raw comments and trusted later fixes', () => {
    const row = forecast();
    const issueUrl = 'https://example.test/issues/301';
    const comments = [
      {
        id: 3010,
        url: `${issueUrl}#comment-3010`,
        user: { login: 'build-bot[bot]' },
        body: 'I can confirm the same issue.',
        created_at: '2026-01-01T01:00:00.000Z',
        updated_at: '2026-01-01T01:00:00.000Z',
      },
      {
        id: 3011,
        url: `${issueUrl}#comment-3011`,
        user: { login: 'human-confirmation' },
        body: 'I can confirm the same issue.',
        created_at: '2026-01-01T02:00:00.000Z',
        updated_at: '2026-01-01T02:00:00.000Z',
      },
    ];
    const commentsJson = JSON.stringify(comments);
    const snapshot = buildIndependentFieldEvidenceSnapshot({
      forecast: row,
      horizonEndAt: '2026-01-04T00:00:00.000Z',
      capturedAt: '2026-01-04T01:00:00.000Z',
      issues: [{
        number: 301,
        state: 'closed',
        title: 'Crash on v2026.1.1',
        body: '',
        author: 'reporter',
        html_url: issueUrl,
        created_at: '2026-01-01T00:30:00.000Z',
        updated_at: '2026-01-03T00:00:00.000Z',
        comments: comments.length,
      }],
      commentSnapshots: [{
        issue_number: 301,
        schema_version: 2,
        verified_at: '2026-01-04T00:30:00.000Z',
        comment_count: comments.length,
        fetched_comment_count: comments.length,
        comments_digest: commentEvidenceDigest(comments.length, comments),
        issue_updated_at: '2026-01-03T00:00:00.000Z',
        comments_json: commentsJson,
      }],
      labelEvents: [],
      closureProofs: [{
        issue_number: 301,
        release_tag: 'v2026.1.2',
        release_published_at: '2026-01-03T00:00:00.000Z',
        status: 'fixed_in_release',
        evidence_json: JSON.stringify({
          linkedPrs: [{
            number: 55,
            trustedFixProof: 1,
            merged: 1,
            url: 'https://example.test/pull/55',
          }],
        }),
      }],
    });
    assert.equal(snapshot.complete, true);
    assert.equal(snapshot.evidenceRefs.length, 1);
    assert.equal(snapshot.schemaVersion, 3);
    assert.match(snapshot.contentHash ?? '', /^[0-9a-f]{64}$/);
    assert.equal(snapshot.issueUniverse?.length, 1);
    assert.match(snapshot.issueUniverse?.[0].evidenceIdentity ?? '', /^[0-9a-f]{64}$/);
    assert.equal(
      snapshot.issueUniverse?.[0].adverseEvidenceIdentity,
      snapshot.evidenceRefs[0].evidenceIdentity,
    );
    assert.equal(snapshot.evidenceRefs[0].confirmations.length, 1);
    assert.equal(snapshot.evidenceRefs[0].laterFixes.length, 1);
    assert.equal(
      snapshot.evidenceRefs[0].sourceClass,
      'exact_version_human_confirmation_and_trusted_later_fix',
    );
  });

  it('censors mutable issue text and post-horizon fixes instead of leaking them', () => {
    const row = forecast();
    const issueUrl = 'https://example.test/issues/302';
    const comments: object[] = [];
    const snapshot = buildIndependentFieldEvidenceSnapshot({
      forecast: row,
      horizonEndAt: '2026-01-04T00:00:00.000Z',
      capturedAt: '2026-01-05T00:00:00.000Z',
      issues: [{
        number: 302,
        state: 'closed',
        title: 'Crash on v2026.1.1',
        body: 'Version detail added after the validation horizon.',
        author: 'reporter',
        html_url: issueUrl,
        created_at: '2026-01-01T00:30:00.000Z',
        updated_at: '2026-01-04T00:30:00.000Z',
        comments: 0,
      }],
      commentSnapshots: [{
        issue_number: 302,
        schema_version: 2,
        verified_at: '2026-01-04T00:45:00.000Z',
        comment_count: 0,
        fetched_comment_count: 0,
        comments_digest: commentEvidenceDigest(0, comments),
        issue_updated_at: '2026-01-04T00:30:00.000Z',
        comments_json: JSON.stringify(comments),
      }],
      labelEvents: [],
      closureProofs: [{
        issue_number: 302,
        release_tag: 'v2026.1.2',
        release_published_at: '2026-01-04T00:30:00.000Z',
        status: 'fixed_in_release',
        evidence_json: JSON.stringify({
          linkedPrs: [{
            number: 56,
            trustedFixProof: 1,
            merged: 1,
            url: 'https://example.test/pull/56',
          }],
        }),
      }],
    });
    assert.equal(snapshot.complete, false);
    assert.deepEqual(snapshot.mutableIssueContentNumbers, [302]);
    assert.deepEqual(snapshot.incompleteIssueNumbers, [302]);
    assert.equal(snapshot.evidenceRefs.length, 0);
    assert.equal(snapshot.issueUniverse?.[0].issueContentFrozenAtHorizon, false);
    assert.equal(snapshot.issueUniverse?.[0].closureProofEvidenceIdentities.length, 0);

    const assessment = assessReleaseValidationObservation(
      cleanEvidence('field_regression_72h', {
        forecast: row,
        independentFieldEvidence: snapshot,
      }),
    );
    assert.equal(assessment.status, 'indeterminate');
    assert.equal(assessment.reason, 'independent_field_evidence_incomplete');
  });

  it('refuses incomplete independent evidence instead of declaring the release safe', () => {
    const row = forecast();
    const result = assessReleaseValidationObservation(cleanEvidence('field_regression_72h', {
      forecast: row,
      independentFieldEvidence: independentFieldSnapshot(row, [], {
        complete: false,
        issueUniverseCount: 1,
        completeCommentSnapshotCount: 0,
        incompleteIssueNumbers: [101],
      }),
    }));
    assert.equal(result.status, 'indeterminate');
    assert.equal(result.reason, 'independent_field_evidence_incomplete');
  });

  it('declares an older selected release observed-safe after a complete exact-version crawl', () => {
    const olderTag = 'v2025.12.31';
    const row = forecast({
        selected_tag: olderTag,
        candidate_scores_json: JSON.stringify([
          { tag: 'v2026.1.1', score: 7.2 },
          { tag: olderTag, score: 8.6 },
        ]),
      });
    const result = assessReleaseValidationObservation(cleanEvidence('field_regression_72h', {
      forecast: row,
      independentFieldEvidence: [
        independentFieldSnapshot(row, [], {
          targetReleaseTag: row.latest_release_tag,
        }),
        independentFieldSnapshot(row, [], { targetReleaseTag: olderTag }),
      ],
      auditHistory: [
        audit({
          release_tag: row.latest_release_tag,
          recorded_at: '2026-01-05T00:00:00.000Z',
          scored_at: '2026-01-05T00:00:00.000Z',
        }),
        audit({
          id: 3,
          release_tag: olderTag,
          recorded_at: '2026-01-05T00:00:00.000Z',
          scored_at: '2026-01-05T00:00:00.000Z',
        }),
      ],
      scorePersistence: {
        ...(cleanEvidence('field_regression_72h').scorePersistence as object),
        releaseTags: ['v2026.1.1', olderTag],
      },
    }));
    assert.equal(result.status, 'matured');
    if (result.status !== 'matured') return;
    assert.equal(result.outcome.adverse, false);
    assert.equal(result.outcome.fieldRegression?.observedClass, 'observed-safe');
  });

  it('can record an adverse older selected release from explicit exact-version evidence', () => {
    const olderTag = 'v2025.12.31';
    const row = forecast({
        selected_tag: olderTag,
        candidate_scores_json: JSON.stringify([
          { tag: 'v2026.1.1', score: 7.2 },
          { tag: olderTag, score: 8.6 },
        ]),
      });
    const result = assessReleaseValidationObservation(cleanEvidence('field_regression_72h', {
      forecast: row,
      independentFieldEvidence: [
        independentFieldSnapshot(row, [], {
          targetReleaseTag: row.latest_release_tag,
        }),
        independentFieldSnapshot(row, [
          independentAdverseEvidence(row, 201),
        ], { targetReleaseTag: olderTag }),
      ],
      auditHistory: [
        fieldAudit([], { release_tag: row.latest_release_tag }),
        fieldAudit([], { id: 3, release_tag: olderTag }),
      ],
      scorePersistence: {
        ...(cleanEvidence('field_regression_72h').scorePersistence as object),
        releaseTags: ['v2026.1.1', olderTag],
      },
    }));
    assert.equal(result.status, 'matured');
    if (result.status !== 'matured') return;
    assert.equal(result.outcome.adverse, true);
    assert.equal(
      result.outcome.fieldRegression?.evidenceScope,
      'complete_exact_version_post_forecast_crawl',
    );
  });

  it('requires an immutable advisory snapshot captured after the 30d horizon', () => {
    const result = assessReleaseValidationObservation(cleanEvidence('security_30d'));
    assert.equal(result.status, 'indeterminate');
    assert.equal(result.reason, 'post_horizon_advisory_snapshot_missing');
  });

  it('does not use legacy advisory snapshots for new security observations', () => {
    const result = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [advisorySnapshot()],
    }));
    assert.equal(result.status, 'indeterminate');
    assert.equal(result.reason, 'post_horizon_advisory_snapshot_missing');
  });

  it('accepts a complete empty post-horizon advisory snapshot as non-adverse evidence', () => {
    const result = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [
        advisorySnapshot([advisoryRow({ ghsa_id: 'GHSA-legacy-collision' })]),
        authorizedAdvisorySnapshot(),
      ],
    }));
    assert.equal(result.status, 'matured');
    if (result.status !== 'matured') return;
    assert.equal(result.outcome.adverse, false);
    assert.equal(result.outcome.security?.snapshotSchemaVersion, 2);
    assert.equal(result.outcome.security?.snapshotId, 1);
    assert.equal(
      result.outcome.security?.snapshotProvenance?.publication.receiptId,
      'receipt-1',
    );
    assert.equal(result.outcome.security?.advisoryCount, 0);
  });

  it('treats malformed advisory ranges as fatal indeterminate evidence', () => {
    const rows = [advisoryRow({ vulnerable_version_range: '^2026.1.0' })];
    const result = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [authorizedAdvisorySnapshot(rows)],
    }));
    assert.equal(result.status, 'indeterminate');
    assert.equal(result.reason, 'malformed_advisory_vulnerable_version_range');
    assert.equal(result.fatal, true);
  });

  it('rejects hash-valid foreign-package and noncanonical advisory snapshot rows', () => {
    const foreign = advisoryRow({
      ghsa_id: 'GHSA-foreign',
      package_name: 'other-package',
    });
    const foreignResult = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [authorizedAdvisorySnapshot([foreign])],
    }));
    assert.equal(foreignResult.status, 'indeterminate');
    assert.equal(foreignResult.fatal, true);
    assert.equal(foreignResult.reason, 'post_horizon_advisory_snapshot_row_malformed');

    const mismatchedKey = advisoryRow({
      ghsa_id: 'GHSA-key',
      advisory_key: 'not-the-canonical-key',
    });
    const keyResult = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [authorizedAdvisorySnapshot([mismatchedKey])],
    }));
    assert.equal(keyResult.status, 'indeterminate');
    assert.equal(keyResult.fatal, true);
    assert.equal(keyResult.reason, 'post_horizon_advisory_snapshot_row_malformed');
  });

  it('surfaces duplicate identities and orphan advisory snapshot rows', () => {
    const duplicate = advisoryRow({ ghsa_id: 'GHSA-duplicate' });
    const duplicateResult = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [authorizedAdvisorySnapshot([duplicate, duplicate])],
    }));
    assert.equal(duplicateResult.status, 'indeterminate');
    assert.equal(duplicateResult.fatal, true);
    assert.equal(duplicateResult.reason, 'post_horizon_advisory_snapshot_row_malformed');

    const orphanSnapshots = buildAdvisorySnapshotValidationEvidence([], [{
      snapshot_id: 999,
      ...advisoryRow({ ghsa_id: 'GHSA-orphan' }),
    }]);
    assert.equal(orphanSnapshots.length, 1);
    assert.equal(orphanSnapshots[0].snapshotId, 999);
    assert.equal(orphanSnapshots[0].capturedAt, '');
    const report = evaluateReleaseValidationLedger({
      forecasts: [],
      observations: [],
      auditHistory: [],
      advisorySnapshots: orphanSnapshots,
      currentModelVersion: 'model-v1',
      currentPromptVersion: 6,
      currentCodeRevision: TEST_CODE_REVISION,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(
      String((report.errors as string[])[0]),
      /Invalid advisory snapshot v1:999/,
    );
  });

  it('records an adverse security outcome from the immutable snapshot', () => {
    const rows = [advisoryRow({ ghsa_id: 'GHSA-hit' })];
    const result = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [authorizedAdvisorySnapshot(rows)],
    }));
    assert.equal(result.status, 'matured');
    if (result.status !== 'matured') return;
    assert.equal(result.outcome.adverse, true);
    assert.equal(result.outcome.security?.advisories[0].ghsaId, 'GHSA-hit');
  });

  it('freezes advisory state at the earliest post-horizon observation', () => {
    const affected = advisoryRow({ ghsa_id: 'GHSA-temporal-state' });
    const modified = advisoryRow({
      ghsa_id: 'GHSA-temporal-state',
      severity: 'low',
    });
    const result = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [
        authorizedAdvisorySnapshot([affected], {
          snapshotId: 1,
          capturedAt: '2026-01-31T01:00:00.000Z',
        }),
        authorizedAdvisorySnapshot([modified], {
          snapshotId: 2,
          capturedAt: '2026-02-01T00:00:00.000Z',
        }),
        authorizedAdvisorySnapshot([], {
          snapshotId: 3,
          capturedAt: '2026-02-02T00:00:00.000Z',
        }),
      ],
    }));
    assert.equal(result.status, 'matured');
    if (result.status !== 'matured') return;
    assert.equal(result.outcome.adverse, true);
    assert.equal(result.outcome.security?.snapshotId, 1);
    assert.equal(result.outcome.security?.advisories[0].ghsaId, 'GHSA-temporal-state');
  });

  it('fails closed when the first post-horizon advisory snapshot is ambiguous', () => {
    const capturedAt = '2026-01-31T01:00:00.000Z';
    const result = assessReleaseValidationObservation(cleanEvidence('security_30d', {
      advisorySnapshots: [
        authorizedAdvisorySnapshot([], { snapshotId: 1, capturedAt }),
        authorizedAdvisorySnapshot([advisoryRow({ ghsa_id: 'GHSA-ambiguous' })], {
          snapshotId: 2,
          capturedAt,
        }),
      ],
    }));
    assert.equal(result.status, 'indeterminate');
    assert.equal(result.reason, 'post_horizon_advisory_snapshot_ambiguous');
    assert.equal(result.fatal, true);
  });

  it('refuses to backfill either horizon after its observation grace window', () => {
    for (const [horizonCode, now] of [
      ['field_regression_72h', '2026-01-05T00:00:00.001Z'],
      ['security_30d', '2026-02-07T00:00:00.001Z'],
    ] as const) {
      const result = assessReleaseValidationObservation({
        ...cleanEvidence(horizonCode),
        now,
      });
      assert.equal(result.status, 'indeterminate');
      assert.equal(result.reason, 'observation_grace_window_missed');
      assert.equal(result.fatal, false);
    }
  });

  it('binds observation evidence to the exact persisted score run', () => {
    const result = assessReleaseValidationObservation(cleanEvidence('field_regression_72h', {
      auditHistory: [audit({
        recorded_at: '2026-01-05T00:00:00.001Z',
        scored_at: '2026-01-05T00:00:00.000Z',
      })],
    }));
    assert.equal(result.status, 'indeterminate');
    assert.equal(result.reason, 'matching_post_horizon_audit_history_missing');
  });

  it('refuses crawl metadata that is dated after the observation', () => {
    const base = cleanEvidence('field_regression_72h');
    const result = assessReleaseValidationObservation({
      ...base,
      issueCrawl: {
        ...(base.issueCrawl as Record<string, unknown>),
        finishedAt: '2026-01-05T00:00:00.001Z',
      },
    });
    assert.equal(result.status, 'indeterminate');
    assert.equal(result.reason, 'post_horizon_issue_crawl_missing');
  });

  it('fails closed on malformed completeness arrays and issue counts', () => {
    const base = cleanEvidence('field_regression_72h');
    for (const field of ['classificationFailures', 'evidenceRefreshFailures'] as const) {
      const result = assessReleaseValidationObservation({
        ...base,
        issueCrawl: {
          ...(base.issueCrawl as Record<string, unknown>),
          [field]: null,
        },
      });
      assert.equal(result.status, 'indeterminate');
      assert.equal(result.reason, 'post_horizon_issue_evidence_incomplete');
    }

    for (const count of [null, Number.NaN, -1, 1.5, '10']) {
      const result = assessReleaseValidationObservation({
        ...base,
        auditHistory: [audit({
          recorded_at: '2026-01-05T00:00:00.000Z',
          scored_at: '2026-01-05T00:00:00.000Z',
          input_json: JSON.stringify({
            rawIssueCount: count,
            classifiedIssueCount: count,
            hoursToNextStable: null,
          }),
        })],
      });
      assert.equal(result.status, 'indeterminate');
      assert.equal(result.reason, 'post_horizon_classification_coverage_incomplete');
    }

    const malformedUnclassified = assessReleaseValidationObservation({
      ...base,
      auditHistory: [audit({
        recorded_at: '2026-01-05T00:00:00.000Z',
        scored_at: '2026-01-05T00:00:00.000Z',
        issue_evidence_json: JSON.stringify({
          evidenceCounts: { verifiedDebt: 0, openedFeltSerious: 0 },
          verifiedDebt: [],
          openedFeltSerious: [],
          unclassifiedIssues: null,
        }),
      })],
    });
    assert.equal(malformedUnclassified.status, 'indeterminate');
    assert.equal(malformedUnclassified.reason, 'post_horizon_audit_payload_malformed');
    assert.equal(malformedUnclassified.fatal, true);

    const malformedEvidenceCounts = assessReleaseValidationObservation({
      ...base,
      auditHistory: [audit({
        recorded_at: '2026-01-05T00:00:00.000Z',
        scored_at: '2026-01-05T00:00:00.000Z',
        issue_evidence_json: JSON.stringify({
          evidenceCounts: { verifiedDebt: null, openedFeltSerious: null },
          verifiedDebt: [],
          openedFeltSerious: [],
          unclassifiedIssues: [],
        }),
      })],
    });
    assert.equal(malformedEvidenceCounts.status, 'matured');
    if (malformedEvidenceCounts.status !== 'matured') return;
    assert.equal(
      malformedEvidenceCounts.outcome.fieldRegression?.classifierProxy.validationEligible,
      false,
    );
    assert.equal(
      malformedEvidenceCounts.outcome.fieldRegression?.classifierProxy.adverse,
      null,
    );
  });
});

interface ForecastFixture {
  forecast: ReleaseValidationForecastLedgerRow;
  history: ReleaseScoreAuditHistoryEvidenceRow[];
  historyRunSeal?: ReleaseScoreAuditHistoryRunSealEvidenceRow;
  authorityRun?: ReleaseScoreAuthorityRunEvidence;
  historyV2Seal?: ReleaseScoreAuditHistoryV2SealEvidence;
}

interface OutcomeFixture {
  observations: ReleaseValidationOutcomeLedgerRow[];
  history: ReleaseScoreAuditHistoryEvidenceRow[];
  snapshots: AdvisorySnapshotValidationEvidence[];
}

describe('release validation ledger integrity', () => {
  it('accepts valid forecast/outcome chains, score-history seals, and advisory snapshots', () => {
    const fixture = integrityFixture();
    const report = validateReleaseValidationLedgerIntegrity(fixture);

    assert.equal(report.ok, true);
    assert.equal(report.failedCount, 0);
    assert.deepEqual(report.errors, []);
  });

  it('keeps legacy and compound snapshots with the same numeric id distinct', () => {
    const capturedAt = '2026-02-01T00:00:00.000Z';
    const report = validateReleaseValidationLedgerIntegrity({
      forecasts: [],
      observations: [],
      auditHistory: [],
      auditHistoryRuns: [],
      advisorySnapshots: [
        advisorySnapshot([], { snapshotId: 1, capturedAt }),
        authorizedAdvisorySnapshot([], { snapshotId: 1, capturedAt }),
      ],
    });
    assert.equal(report.ok, true);
    assert.equal(report.advisorySnapshots.snapshotCount, 2);
    assert.equal(report.advisorySnapshots.duplicateSnapshotIdCount, 0);
    assert.equal(report.advisorySnapshots.latestSnapshotId, 1);
    assert.equal(report.advisorySnapshots.latestSnapshotSchemaVersion, 2);
  });

  it('reports unreferenced historical semantic incompatibilities without failing the ledger', () => {
    const historical = advisorySnapshot([
      advisoryRow({
        ghsa_id: 'GHSA-legacy-patch',
        vulnerable_version_range: '<= 2026.1.1',
        patched_versions: '>= 2026.1.1',
      }),
    ], {
      snapshotId: 1,
      capturedAt: '2026-01-01T00:00:00.000Z',
    });
    const current = advisorySnapshot([], {
      snapshotId: 2,
      capturedAt: '2026-02-01T00:00:00.000Z',
    });
    const integrity = validateReleaseValidationLedgerIntegrity({
      forecasts: [],
      observations: [],
      auditHistory: [],
      auditHistoryRuns: [],
      advisorySnapshots: [historical, current],
    });
    assert.equal(integrity.ok, true);
    assert.equal(integrity.advisorySnapshots.latestSnapshotId, 2);
    assert.equal(integrity.advisorySnapshots.semanticProblemCount, 0);
    assert.equal(integrity.advisorySnapshots.legacySemanticProblemCount, 1);
    assert.equal(integrity.advisorySnapshots.legacySemanticSnapshotCount, 1);
    assert.deepEqual(integrity.advisorySnapshots.legacySemanticSnapshotIds, [1]);

    const evaluation = evaluateReleaseValidationLedger({
      forecasts: [],
      observations: [],
      auditHistory: [],
      advisorySnapshots: [historical, current],
      currentModelVersion: 'model-current',
      currentPromptVersion: 1,
      currentCodeRevision: TEST_CODE_REVISION,
      opportunityDenominatorLedger: emptyOpportunityDenominator(
        '2026-12-31T00:00:00.000Z',
      ),
    }) as any;
    assert.deepEqual(evaluation.errors, []);
    assert.equal(evaluation.status, 'insufficient');
    assert.equal(evaluation.advisorySnapshotSemantics.legacySemanticProblemCount, 1);
    assert.deepEqual(evaluation.advisorySnapshotSemantics.legacySemanticSnapshotIds, [1]);
  });

  it('keeps structural failures global and current semantic failures fatal', () => {
    const historicalStructural = advisorySnapshot([
      advisoryRow({
        ghsa_id: 'GHSA-foreign-history',
        package_name: 'other-package',
      }),
    ], {
      snapshotId: 1,
      capturedAt: '2026-01-01T00:00:00.000Z',
    });
    const currentSemantic = advisorySnapshot([
      advisoryRow({
        ghsa_id: 'GHSA-current-patch',
        vulnerable_version_range: '<= 2026.1.1',
        patched_versions: '>= 2026.1.1',
      }),
    ], {
      snapshotId: 2,
      capturedAt: '2026-02-01T00:00:00.000Z',
    });
    const report = validateReleaseValidationLedgerIntegrity({
      forecasts: [],
      observations: [],
      auditHistory: [],
      auditHistoryRuns: [],
      advisorySnapshots: [historicalStructural, currentSemantic],
    });
    assert.equal(report.ok, false);
    assert.equal(report.advisorySnapshots.packageMismatchCount, 1);
    assert.equal(report.advisorySnapshots.semanticProblemCount, 1);
    assert.equal(report.advisorySnapshots.legacySemanticProblemCount, 0);
    assert.match(report.errors.join('\n'), /package_mismatch/);
    assert.match(report.errors.join('\n'), /semantic incompatibility/);
  });

  it('rejects duplicate release opportunity identities only within the same scoring series', () => {
    const duplicate = integrityFixture();
    const prior = duplicate.forecasts.at(-1)!;
    const row = structuredClone(prior);
    row.id = Number(prior.id) + 1;
    row.previous_content_hash = prior.content_hash;
    row.content_hash = releaseValidationForecastContentHash(row);
    row.decision_id = releaseValidationDecisionId(row, row.content_hash);
    duplicate.forecasts.push(row);

    const report = validateReleaseValidationLedgerIntegrity({
      ...duplicate,
      observations: [],
    });
    assert.equal(report.forecasts.duplicateSeriesIdentityCount, 1);
    assert.match(report.errors.join('\n'), /Duplicate validation forecast series identity/);
  });

  it('detects tampered hashes and deterministic forecast/outcome IDs', () => {
    const forecastTampered = integrityFixture();
    forecastTampered.forecasts[0].candidate_scores_json += ' ';
    let report = validateReleaseValidationLedgerIntegrity({
      ...forecastTampered,
      observations: [],
    });
    assert.ok(report.forecasts.contentHashFailureCount > 0);

    const decisionTampered = integrityFixture();
    decisionTampered.forecasts[0].decision_id = 'tampered-decision-id';
    report = validateReleaseValidationLedgerIntegrity({
      ...decisionTampered,
      observations: [],
    });
    assert.equal(report.forecasts.decisionIdFailureCount, 1);

    const outcomeTampered = integrityFixture();
    outcomeTampered.observations[0].outcome_json = '{"tampered":true}';
    report = validateReleaseValidationLedgerIntegrity(outcomeTampered);
    assert.ok(report.outcomes.contentHashFailureCount > 0);
    assert.ok(report.outcomes.observationIdFailureCount > 0);
  });

  it('detects broken previous links independently from row hashes', () => {
    const forecastBroken = integrityFixture();
    const forecastRow = forecastBroken.forecasts[1];
    forecastRow.previous_content_hash = 'f'.repeat(64);
    forecastRow.content_hash = releaseValidationForecastContentHash(forecastRow);
    forecastRow.decision_id = releaseValidationDecisionId(
      forecastRow,
      forecastRow.content_hash,
    );
    let report = validateReleaseValidationLedgerIntegrity({
      ...forecastBroken,
      observations: [],
    });
    assert.equal(report.forecasts.chainFailureCount, 1);
    assert.equal(report.forecasts.contentHashFailureCount, 0);
    assert.equal(report.forecasts.decisionIdFailureCount, 0);

    const outcomeBroken = integrityFixture();
    const outcomeRow = outcomeBroken.observations[1];
    outcomeRow.previous_content_hash = 'e'.repeat(64);
    outcomeRow.content_hash = releaseValidationOutcomeContentHash(outcomeRow);
    report = validateReleaseValidationLedgerIntegrity(outcomeBroken);
    assert.equal(report.outcomes.chainFailureCount, 1);
    assert.equal(report.outcomes.contentHashFailureCount, 0);

    const scoreRunBroken = integrityFixture();
    const scoreRun = scoreRunBroken.auditHistoryRuns[1];
    scoreRun.previous_content_hash = 'd'.repeat(64);
    scoreRun.content_hash = releaseScoreAuditHistoryRunContentHash({
      runId: scoreRun.run_id,
      recordedAt: scoreRun.recorded_at,
      rowCount: scoreRun.row_count,
      rowsContentHash: scoreRun.rows_content_hash,
      previousContentHash: scoreRun.previous_content_hash,
    });
    report = validateReleaseValidationLedgerIntegrity(scoreRunBroken);
    assert.equal(report.scoreHistory.chainFailureCount, 1);
    assert.equal(report.scoreHistory.contentHashMismatchCount, 0);
  });

  it('counts fully rehashed authority and history-v2 chain corruption as fatal', () => {
    const valid = authorityLedgerFixture();
    let report = validateReleaseValidationLedgerIntegrity(valid);
    assert.equal(report.ok, true);
    assert.equal(report.scoreAuthority.failedCount, 0);

    const authorityBroken = authorityLedgerFixture();
    authorityBroken.authorityRuns[1] = buildScoreAuthorityResolutionRun({
      authorityRunId: authorityBroken.authorityRuns[1].authorityRunId,
      sourceIdentitySchemaVersion:
        authorityBroken.authorityRuns[1].sourceIdentitySchemaVersion,
      sourceIdentityDigest:
        authorityBroken.authorityRuns[1].sourceIdentityDigest,
      recordedAt: authorityBroken.authorityRuns[1].recordedAt,
      previousContentHash: 'f'.repeat(64),
      rows: [],
    });
    report = validateReleaseValidationLedgerIntegrity(authorityBroken);
    assert.equal(report.ok, false);
    assert.equal(report.scoreAuthority.authorityRunIntegrityFailureCount, 0);
    assert.equal(report.scoreAuthority.authorityChainFailureCount, 1);
    assert.ok(report.failedCount > 0);
    assert.match(report.errors.join('\n'), /does not match authority chain/);

    const historyV2Broken = authorityLedgerFixture();
    const priorSeal = historyV2Broken.historyV2Seals[1];
    historyV2Broken.historyV2Seals[1] = buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: priorSeal.historyRunId,
      authorityRunId: priorSeal.authorityRunId,
      sealedAt: priorSeal.sealedAt,
      historyRowCount: priorSeal.historyRowCount,
      historyRowsContentHash: priorSeal.historyRowsContentHash,
      authorityRowCount: priorSeal.authorityRowCount,
      authorityRowsContentHash: priorSeal.authorityRowsContentHash,
      previousContentHash: 'e'.repeat(64),
    });
    report = validateReleaseValidationLedgerIntegrity(historyV2Broken);
    assert.equal(report.ok, false);
    assert.equal(report.scoreAuthority.historyV2SealIntegrityFailureCount, 0);
    assert.equal(report.scoreAuthority.historyV2ChainFailureCount, 1);
    assert.ok(report.failedCount > 0);
    assert.match(report.errors.join('\n'), /does not match history v2 chain/);
  });

  it('validates authority chains by cryptographic topology instead of caller order', () => {
    const fixture = authorityLedgerFixture();
    fixture.authorityRuns.reverse();
    fixture.historyV2Seals.reverse();

    const report = validateReleaseValidationLedgerIntegrity(fixture);
    assert.equal(report.scoreAuthority.authorityChainFailureCount, 0);
    assert.equal(report.scoreAuthority.historyV2ChainFailureCount, 0);
    assert.equal(report.scoreAuthority.failedCount, 0);
    assert.equal(report.ok, true);
  });

  it('counts canonical history-v2 projection mismatches as fatal', () => {
    const fixture = authorityLedgerFixture();
    const priorSeal = fixture.historyV2Seals[1];
    fixture.historyV2Seals[1] = buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: priorSeal.historyRunId,
      authorityRunId: priorSeal.authorityRunId,
      sealedAt: priorSeal.sealedAt,
      historyRowCount: priorSeal.historyRowCount + 1,
      historyRowsContentHash: priorSeal.historyRowsContentHash,
      authorityRowCount: priorSeal.authorityRowCount,
      authorityRowsContentHash: priorSeal.authorityRowsContentHash,
      previousContentHash: fixture.historyV2Seals[0].contentHash,
    });
    const report = validateReleaseValidationLedgerIntegrity(fixture);
    assert.equal(report.ok, false);
    assert.equal(report.scoreAuthority.historyV2SealIntegrityFailureCount, 0);
    assert.equal(report.scoreAuthority.bindingMismatchCount, 1);
    assert.ok(report.failedCount > 0);
    assert.match(
      report.errors.join('\n'),
      /does not exactly bind its history and authority runs/,
    );
  });

  it('detects deleted history-row suffixes and missing run seals', () => {
    const deletedRow = integrityFixture();
    const firstRunId = deletedRow.forecasts[0].audit_history_run_id;
    deletedRow.auditHistory = deletedRow.auditHistory.filter((row) =>
      row.run_id !== firstRunId || row.release_tag !== 'v-integrity-previous');
    let report = validateReleaseValidationLedgerIntegrity(deletedRow);
    assert.equal(report.scoreHistory.rowCountMismatchCount, 1);
    assert.equal(report.scoreHistory.rowsContentHashMismatchCount, 1);
    assert.equal(report.forecasts.invalidRunSealCount, 1);

    const missingSeal = integrityFixture();
    missingSeal.auditHistoryRuns = missingSeal.auditHistoryRuns.filter(
      (row) => row.run_id !== firstRunId,
    );
    report = validateReleaseValidationLedgerIntegrity(missingSeal);
    assert.equal(report.scoreHistory.missingSealCount, 1);
    assert.equal(report.forecasts.missingRunSealCount, 1);

    const tamperedSeal = integrityFixture();
    tamperedSeal.auditHistoryRuns[1].content_hash = 'c'.repeat(64);
    report = validateReleaseValidationLedgerIntegrity(tamperedSeal);
    assert.equal(report.scoreHistory.contentHashMismatchCount, 1);
    assert.equal(report.forecasts.invalidRunSealCount, 1);
  });

  it('detects broken decision references and advisory snapshot hashes', () => {
    const brokenDecision = integrityFixture();
    const outcome = brokenDecision.observations[0];
    outcome.decision_id = 'missing-decision';
    outcome.observation_id = releaseValidationObservationId(outcome);
    outcome.content_hash = releaseValidationOutcomeContentHash(outcome);
    let report = validateReleaseValidationLedgerIntegrity(brokenDecision);
    assert.equal(report.outcomes.missingDecisionCount, 1);
    assert.equal(report.outcomes.contentHashFailureCount, 0);
    assert.equal(report.outcomes.observationIdFailureCount, 0);

    const advisoryTampered = integrityFixture();
    advisoryTampered.advisorySnapshots[0].contentHash = '0'.repeat(64);
    report = validateReleaseValidationLedgerIntegrity(advisoryTampered);
    assert.equal(report.advisorySnapshots.contentHashMismatchCount, 1);
  });

  it('makes evaluation fail before metrics on hash, chain, and seal corruption', () => {
    const root = join(import.meta.dirname, '..', '..');
    const cases = [
      ['forecast_hash', 'forecasts', 'contentHashFailureCount'],
      ['forecast_chain', 'forecasts', 'chainFailureCount'],
      ['run_seal', 'scoreHistory', 'contentHashMismatchCount'],
    ] as const;
    for (const [corruption, section, count] of cases) {
      const fixture = corruptValidationLedgerDb(`validation-evaluate-${corruption}`, corruption);
      try {
        const evaluate = spawnSync(
          TSX_BIN,
          [
            'scripts/validation/evaluate-score-quality.mjs',
            '--evaluated-at',
            '2099-01-03T00:00:00.000Z',
          ],
          {
            cwd: root,
            env: {
              ...process.env,
              DB_PATH: fixture.dbPath,
              NODE_TEST_CONTEXT: undefined,
              RADAR_DB_BOOTSTRAP_MODE: 'existing',
              RADAR_DB_READ_ONLY: '1',
            },
            encoding: 'utf8',
          },
        );
        assert.equal(evaluate.status, 1, `${evaluate.stdout}\n${evaluate.stderr}`);
        const report = JSON.parse(evaluate.stdout);
        assert.equal(report.status, 'measurable_but_failed');
        assert.equal(report.phase, 'ledger_integrity');
        assert.ok(report.integrity[section][count] > 0);
        assert.equal('combined' in report, false);
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('makes observe refuse to extend a corrupt chain', () => {
    const fixture = corruptValidationLedgerDb('validation-observe-refusal', 'forecast_hash');
    const root = join(import.meta.dirname, '..', '..');
    try {
      const observe = spawnSync(
        TSX_BIN,
        ['scripts/validation/observe-outcomes.mjs'],
        {
          cwd: root,
          env: {
            ...process.env,
            DB_PATH: fixture.dbPath,
            NODE_TEST_CONTEXT: undefined,
            RADAR_DB_BOOTSTRAP_MODE: 'existing',
            RADAR_DB_READ_ONLY: '0',
          },
          encoding: 'utf8',
        },
      );
      assert.equal(observe.status, 1, `${observe.stdout}\n${observe.stderr}`);
      assert.match(
        `${observe.stdout}\n${observe.stderr}`,
        /Refusing to append validation outcomes because the existing immutable ledger is corrupt/,
      );
      const db = new DatabaseSync(fixture.dbPath, { readOnly: true });
      try {
        const row = db.prepare(`
          SELECT COUNT(*) AS count
          FROM release_validation_outcome_observations
        `).get() as { count: number };
        assert.equal(row.count, 0);
      } finally {
        db.close();
      }
    } finally {
      fixture.cleanup();
    }
  });

  it('makes observe exclude a timing-invalid forecast without appending outcomes', () => {
    const fixture = legacyLateValidationForecastDb('validation-observe-late-exclusion');
    const root = join(import.meta.dirname, '..', '..');
    try {
      const observe = spawnSync(
        TSX_BIN,
        [
          'scripts/validation/observe-outcomes.mjs',
          '--batch-id',
          'validation-observe-late-exclusion',
        ],
        {
          cwd: root,
          env: {
            ...process.env,
            DB_PATH: fixture.dbPath,
            NODE_TEST_CONTEXT: undefined,
            RADAR_DB_BOOTSTRAP_MODE: 'existing',
            RADAR_DB_READ_ONLY: '0',
          },
          encoding: 'utf8',
        },
      );
      assert.equal(observe.status, 0, `${observe.stdout}\n${observe.stderr}`);
      const report = JSON.parse(observe.stdout);
      assert.equal(report.forecastCount, 1);
      assert.equal(report.eligibleForecastCount, 0);
      assert.equal(report.excludedForecastCount, 1);
      assert.equal(report.excludedCount, 2);
      assert.equal(report.results.length, 2);
      assert.deepEqual(
        report.results.map((row: any) => row.horizonCode).sort(),
        ['field_regression_72h', 'security_30d'],
      );
      assert.ok(report.results.every((row: any) => row.status === 'excluded'));
      assert.ok(report.results.every((row: any) =>
        row.reason === 'forecast_decision_schema_not_evaluable'));
      assert.ok(report.results.every((row: any) => row.decisionSchemaVersion === 2));
      assert.equal(report.receiptPersistence, 'inserted');

      const rerun = spawnSync(
        TSX_BIN,
        [
          'scripts/validation/observe-outcomes.mjs',
          '--batch-id',
          'validation-observe-late-exclusion',
        ],
        {
          cwd: root,
          env: {
            ...process.env,
            DB_PATH: fixture.dbPath,
            NODE_TEST_CONTEXT: undefined,
            RADAR_DB_BOOTSTRAP_MODE: 'existing',
            RADAR_DB_READ_ONLY: '0',
          },
          encoding: 'utf8',
        },
      );
      assert.equal(rerun.status, 0, `${rerun.stdout}\n${rerun.stderr}`);
      const rerunReport = JSON.parse(rerun.stdout);
      assert.equal(rerunReport.receiptPersistence, 'already_existing');
      assert.equal(rerunReport.contentHash, report.contentHash);
      assert.deepEqual(rerunReport.results, report.results);

      const conflict = spawnSync(
        TSX_BIN,
        [
          'scripts/validation/observe-outcomes.mjs',
          '--batch-id',
          'validation-observe-late-exclusion',
          '--observed-at',
          '2026-01-03T00:00:00.000Z',
        ],
        {
          cwd: root,
          env: {
            ...process.env,
            DB_PATH: fixture.dbPath,
            NODE_TEST_CONTEXT: undefined,
            RADAR_DB_BOOTSTRAP_MODE: 'existing',
            RADAR_DB_READ_ONLY: '0',
          },
          encoding: 'utf8',
        },
      );
      assert.equal(conflict.status, 1, `${conflict.stdout}\n${conflict.stderr}`);
      assert.match(
        `${conflict.stdout}\n${conflict.stderr}`,
        /Validation observation batch conflict.*observedAt/,
      );

      const db = new DatabaseSync(fixture.dbPath, { readOnly: true });
      try {
        const row = db.prepare(`
          SELECT COUNT(*) AS count
          FROM release_validation_outcome_observations
        `).get() as { count: number };
        assert.equal(row.count, 0);
        const receipt = db.prepare(`
          SELECT forecast_count, intended_count, inserted_count, excluded_count
          FROM release_validation_observation_batches
        `).get() as {
          forecast_count: number;
          intended_count: number;
          inserted_count: number;
          excluded_count: number;
        };
        assert.deepEqual({ ...receipt }, {
          forecast_count: 1,
          intended_count: 0,
          inserted_count: 0,
          excluded_count: 2,
        });
      } finally {
        db.close();
      }
    } finally {
      fixture.cleanup();
    }
  });
});

function forecastFixture(input: {
  decisionId: string;
  latestTag: string;
  opportunityCode?: string;
  selectedTag?: string | null;
  candidates?: Array<{ tag: string; score: number }>;
  modelVersion?: string;
  promptVersion?: number;
  recordedAt?: string;
  codeRevision?: string | null;
  releaseNodeId?: string;
  releaseTagCommitOid?: string;
  releasePublishedAt?: string;
}): ForecastFixture {
  const recordedAt = input.recordedAt ?? FORECAST_AT;
  const selectedTag = input.selectedTag === undefined ? input.latestTag : input.selectedTag;
  const candidates = input.candidates ?? [{ tag: input.latestTag, score: 8 }];
  const modelVersion = input.modelVersion ?? 'model-current';
  const promptVersion = input.promptVersion ?? 6;
  const runId = `${input.decisionId}-forecast-run`;
  const authorityRunId = `score-authority:${runId}`;
  const sourceIdentity = {
    schemaVersion: 2,
    digest: '1'.repeat(64),
  };
  const sourceIdentityJson = JSON.stringify(sourceIdentity);
  const authorityRun = buildScoreAuthorityResolutionRun({
    authorityRunId,
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    recordedAt,
    previousContentHash: null,
    rows: [],
  });
  const history = candidates.map((candidate, index) => audit({
    id: index + 1,
    run_id: runId,
    recorded_at: recordedAt,
    release_tag: candidate.tag,
    scored_at: recordedAt,
    score_model_version: modelVersion,
    prompt_version: promptVersion,
    final_score: candidate.score,
    recommended: candidate.tag === selectedTag ? 1 : 0,
    source_identity_json: sourceIdentityJson,
    authority_run_id: authorityRunId,
  }));
  const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(
    history
      .slice()
      .sort((left, right) =>
        left.release_tag.localeCompare(right.release_tag)) as unknown as
        Array<Record<string, unknown>>,
  );
  const historyRunSeal = {
    run_id: runId,
    recorded_at: recordedAt,
    row_count: history.length,
    rows_content_hash: rowsContentHash,
    previous_content_hash: null,
    content_hash: releaseScoreAuditHistoryRunContentHash({
      runId,
      recordedAt,
      rowCount: history.length,
      rowsContentHash,
      previousContentHash: null,
    }),
  };
  const historyV2Seal = buildReleaseScoreAuditHistoryV2Seal({
    historyRunId: runId,
    authorityRunId,
    sealedAt: recordedAt,
    historyRowCount: historyRunSeal.row_count,
    historyRowsContentHash: historyRunSeal.rows_content_hash,
    authorityRowCount: authorityRun.rowCount,
    authorityRowsContentHash: authorityRun.rowsContentHash,
    previousContentHash: null,
  });
  const candidateSnapshots = candidates.map((candidate) => {
    const row = history.find((item) => item.release_tag === candidate.tag)!;
    return {
      releaseTag: candidate.tag,
      scoreSnapshot: {
        scoredAt: row.scored_at,
        finalScore: row.final_score,
        status: row.status,
        band: row.band,
        recommended: row.recommended === 1,
      },
      auditSnapshot: row,
    };
  });
  const opportunityCode = input.opportunityCode ?? 'first_verified_after_24h';
  const minAgeHours = opportunityCode === 'first_verified_after_3h' ? 3 : 24;
  const maxAgeHours = opportunityCode === 'first_verified_after_3h' ? 6 : 30;
  const defaultOpportunityAgeHours =
    opportunityCode === 'first_verified_after_3h' ? 4 : 25;
  const latestReleasePublishedAt = input.releasePublishedAt ?? new Date(
    Date.parse(recordedAt) - defaultOpportunityAgeHours * HOUR_MS,
  ).toISOString();
  const opportunityAgeHours =
    (Date.parse(recordedAt) - Date.parse(latestReleasePublishedAt)) / HOUR_MS;
  const forecastRow = forecast({
    id: stableNumber(input.decisionId),
    decision_id: input.decisionId,
    opportunity_code: opportunityCode,
    recorded_at: recordedAt,
    latest_release_tag: input.latestTag,
    latest_release_published_at: latestReleasePublishedAt,
    selected_tag: selectedTag,
    audit_history_run_id: runId,
    score_model_version: modelVersion,
    prompt_version: promptVersion,
    code_revision: input.codeRevision === undefined
      ? TEST_CODE_REVISION
      : input.codeRevision,
    candidate_scores_json: JSON.stringify(candidateSnapshots),
    decision_json: JSON.stringify({
      schemaVersion: 4,
      opportunityCode,
      recordedAt,
      latestReleaseTag: input.latestTag,
      latestReleasePublishedAt,
      latestReleaseAgeHours: opportunityAgeHours,
      opportunityWindow: {
        minAgeHours,
        maxAgeHours,
        windowStartAt: new Date(
          Date.parse(latestReleasePublishedAt) + minAgeHours * HOUR_MS,
        ).toISOString(),
        windowEndAt: new Date(
          Date.parse(latestReleasePublishedAt) + maxAgeHours * HOUR_MS,
        ).toISOString(),
        windowStartMs:
          Date.parse(latestReleasePublishedAt) + minAgeHours * HOUR_MS,
        windowEndMs:
          Date.parse(latestReleasePublishedAt) + maxAgeHours * HOUR_MS,
        observedAtMs: Date.parse(recordedAt),
        observedAgeHours: opportunityAgeHours,
        valid: true,
      },
      selectedTag,
      recommendationDecision: {
        policyCode: 'highest_confidence_with_recency_tolerance',
        selectedTag,
      },
      scoreCommit: {
        schemaVersion: 4,
        historyRunId: runId,
        historyRunContentHash: historyRunSeal.content_hash,
        authorityRunId,
        authorityRunContentHash: authorityRun.contentHash,
        historyV2SealContentHash: historyV2Seal.contentHash,
        historyRecordedAt: recordedAt,
        commitNotBefore: recordedAt,
        commitNotAfter: recordedAt,
        commitNotBeforeMs: Date.parse(recordedAt),
        commitNotAfterMs: Date.parse(recordedAt),
      },
      catalogAttestation: {
        schemaVersion: 4,
        initialRemoteCatalog: {
          digest: 'b'.repeat(64),
          totalCount: candidates.length,
          nodeCount: candidates.length,
          pageCount: 1,
          pagesFetched: 2,
          sweepCount: 2,
          exhausted: true,
          stabilized: true,
          sourceOrder: 'CREATED_AT_DESC',
        },
        finalRemoteCatalog: {
          digest: 'b'.repeat(64),
          totalCount: candidates.length,
          nodeCount: candidates.length,
          pageCount: 1,
          pagesFetched: 2,
          sweepCount: 2,
          exhausted: true,
          stabilized: true,
          sourceOrder: 'CREATED_AT_DESC',
        },
        finalObservedAt: recordedAt,
        projectedActiveCatalog: {
          digest: 'c'.repeat(64),
          releaseCount: candidates.length,
        },
        localActiveCatalog: {
          digest: 'c'.repeat(64),
          releaseCount: candidates.length,
        },
        latestStable: {
          nodeId: input.releaseNodeId ?? `node-${input.latestTag}`,
          tag: input.latestTag,
          tagCommitOid: input.releaseTagCommitOid ?? '1'.repeat(40),
          publishedAt: latestReleasePublishedAt,
        },
        scoreBuiltAt: recordedAt,
      },
    }),
    source_identity_json: sourceIdentityJson,
  });
  forecastRow.content_hash = releaseValidationForecastContentHash(forecastRow);
  return {
    forecast: forecastRow,
    history,
    historyRunSeal,
    authorityRun,
    historyV2Seal,
  };
}

function strictAuthorityForecastFixture(
  input: Parameters<typeof forecastFixture>[0],
) {
  const fixture = forecastFixture(input);
  assert.ok(fixture.historyRunSeal);
  assert.ok(fixture.authorityRun);
  assert.ok(fixture.historyV2Seal);
  return {
    ...fixture,
    historyRunSeal: fixture.historyRunSeal,
    authorityRun: fixture.authorityRun,
    historyV2Seal: fixture.historyV2Seal,
  };
}

function outcomeFixture(
  fixture: ForecastFixture,
  adverse: Partial<Record<ReleaseValidationHorizonCode, boolean>> = {},
): OutcomeFixture {
  const observations: ReleaseValidationOutcomeLedgerRow[] = [];
  const history: ReleaseScoreAuditHistoryEvidenceRow[] = [];
  const snapshots: AdvisorySnapshotValidationEvidence[] = [];
  const policyTargetTag =
    fixture.forecast.selected_tag ?? fixture.forecast.latest_release_tag;
  const targets = releaseValidationObservationTargets(fixture.forecast);
  for (const [index, horizonCode] of (
    ['field_regression_72h', 'security_30d'] as ReleaseValidationHorizonCode[]
  ).entries()) {
    const durationMs = horizonCode === 'field_regression_72h' ? 72 * HOUR_MS : 30 * DAY_MS;
    const windowEndAt = new Date(Date.parse(fixture.forecast.recorded_at) + durationMs).toISOString();
    const observedAt = new Date(Date.parse(windowEndAt) + HOUR_MS).toISOString();
    const policyAdverse = adverse[horizonCode] === true;
    const fieldCreatedAt = new Date(
      Date.parse(fixture.forecast.recorded_at) + HOUR_MS,
    ).toISOString();
    const securityRows = horizonCode === 'security_30d' && policyAdverse
      ? [advisoryRow({
          ghsa_id: `${fixture.forecast.decision_id}-GHSA`,
          published_at: new Date(
            Date.parse(fixture.forecast.recorded_at) + DAY_MS,
          ).toISOString(),
          vulnerable_version_range: `<= ${policyTargetTag}`,
          patched_versions: null,
        })]
      : [];
    const securitySnapshot = horizonCode === 'security_30d'
      ? advisorySnapshot(securityRows, {
          snapshotId: stableNumber(`${fixture.forecast.decision_id}-snapshot`),
          capturedAt: new Date(Date.parse(windowEndAt) + 30 * 60_000).toISOString(),
        })
      : null;
    if (securitySnapshot) snapshots.push(securitySnapshot);

    const candidateOutcomes = targets.map((target, targetIndex) => {
      const targetAdverse =
        target.targetReleaseTag === policyTargetTag && policyAdverse;
      const runId =
        `${fixture.forecast.decision_id}-${horizonCode}-${targetIndex}-observe`;
      const observationAudit = audit({
        id: stableNumber(runId),
        run_id: runId,
        recorded_at: observedAt,
        release_tag: target.targetReleaseTag,
        scored_at: observedAt,
        score_model_version: 'observation-model',
        prompt_version: 9,
        source_identity_json: JSON.stringify(SOURCE_NEW),
        ...(horizonCode === 'field_regression_72h' && targetAdverse
          ? {
              issue_evidence_json: JSON.stringify({
                evidenceCounts: {
                  verifiedDebt: 0,
                  openedFeltSerious: 1,
                },
                verifiedDebt: [],
                openedFeltSerious: [{
                  duplicateCluster: 'regression',
                  fieldConfirmed: true,
                  issue: {
                    number: 1,
                    createdAt: fieldCreatedAt,
                    state: 'closed',
                    affectsVersion: target.targetReleaseTag,
                    classification: {
                      severity: 'high',
                      functionality: 'core',
                    },
                  },
                }],
                unclassifiedIssues: [],
              }),
            }
          : {}),
      });
      history.push(observationAudit);
      const auditEvidence = {
        runId,
        recordedAt: observedAt,
        scoredAt: observedAt,
        sourceIdentityDigest: SOURCE_NEW.digest,
        scoreModelVersion: observationAudit.score_model_version,
        promptVersion: observationAudit.prompt_version,
      };
      if (horizonCode === 'field_regression_72h') {
        const evidenceRefs = targetAdverse
          ? [independentAdverseEvidence(fixture.forecast, 1, {
              createdAt: fieldCreatedAt,
              versionLink: {
                source: 'title',
                version: target.targetReleaseTag,
                referenceUrl: 'https://example.test/issues/1',
                commentId: null,
                author: 'reporter',
                snippet: `Regression on ${target.targetReleaseTag}`,
              },
            })]
          : [];
        const evidenceSnapshot = independentFieldSnapshot(
          fixture.forecast,
          evidenceRefs,
          {
            targetReleaseTag: target.targetReleaseTag,
            capturedAt: observedAt,
          },
        );
        return {
          targetReleaseTag: target.targetReleaseTag,
          roles: target.roles,
          candidateScore: candidateScore(
            fixture.forecast,
            target.targetReleaseTag,
          ),
          adverse: targetAdverse,
          auditEvidence,
          fieldRegression: {
            outcomeSourceClass: 'independent_raw_evidence',
            observedClass: targetAdverse ? 'observed-adverse' : 'observed-safe',
            evidenceScope: 'complete_exact_version_post_forecast_crawl',
            evidenceCompleteness: {
              capturedAt: observedAt,
              issueUniverseCount: evidenceSnapshot.issueUniverseCount,
              completeCommentSnapshotCount:
                evidenceSnapshot.completeCommentSnapshotCount,
              incompleteIssueNumbers: [],
            },
            issueCount: evidenceRefs.length,
            clusterCount: evidenceRefs.length,
            evidenceRefs,
            evidenceSnapshot,
            classifierProxy: {
              sourceClass: 'classifier_score_bucket_proxy',
              validationEligible: false,
              adverse: targetAdverse,
              issueCount: evidenceRefs.length,
              reason: null,
            },
          },
        };
      }
      const affected = targetAdverse ? securityRows : [];
      return {
        targetReleaseTag: target.targetReleaseTag,
        roles: target.roles,
        candidateScore: candidateScore(
          fixture.forecast,
          target.targetReleaseTag,
        ),
        adverse: targetAdverse,
        auditEvidence,
        security: {
          snapshotId: securitySnapshot!.snapshotId,
          snapshotCapturedAt: securitySnapshot!.capturedAt,
          snapshotContentHash: securitySnapshot!.contentHash,
          advisoryCount: affected.length,
          advisories: affected.map((row) => ({
            advisoryKey: row.advisory_key,
            ghsaId: row.ghsa_id,
            cveId: row.cve_id,
            severity: row.severity,
            publishedAt: row.published_at,
            vulnerableVersionRange: row.vulnerable_version_range,
          })),
        },
      };
    });
    const policyOutcome = candidateOutcomes.find((item) =>
      item.targetReleaseTag === policyTargetTag)!;
    observations.push({
      id: index + 1,
      observation_id: `${fixture.forecast.decision_id}-${horizonCode}`,
      decision_id: fixture.forecast.decision_id,
      horizon_code: horizonCode,
      observed_at: observedAt,
      status: 'matured',
      outcome_json: JSON.stringify({
        schemaVersion: 3,
        decisionId: fixture.forecast.decision_id,
        opportunityCode: fixture.forecast.opportunity_code,
        horizonCode,
        targetReleaseTag: policyTargetTag,
        windowStartAt: fixture.forecast.recorded_at,
        windowEndAt,
        observedAt,
        adverse: policyOutcome.adverse,
        prediction: {
          recommended: fixture.forecast.selected_tag != null,
          recommendedLatest: fixture.forecast.selected_tag === fixture.forecast.latest_release_tag,
          selectedTag: fixture.forecast.selected_tag,
          targetReleaseScore: candidateScore(fixture.forecast, policyTargetTag),
        },
        auditEvidence: policyOutcome.auditEvidence,
        policyAction: {
          action: fixture.forecast.selected_tag == null
            ? 'withhold_latest'
            : 'install_selected',
          targetReleaseTag: policyTargetTag,
          adverse: policyOutcome.adverse,
        },
        candidateOutcomes,
        ...(policyOutcome.fieldRegression
          ? { fieldRegression: policyOutcome.fieldRegression }
          : {}),
        ...(policyOutcome.security ? { security: policyOutcome.security } : {}),
      }),
      source_identity_json: JSON.stringify(SOURCE_NEW),
      content_hash: `${fixture.forecast.decision_id}-${horizonCode}-hash`,
    });
  }
  return { observations, history, snapshots };
}

function evaluateFixtures(input: {
  fixtures: ForecastFixture[];
  outcomes: OutcomeFixture[];
  generatedAt?: string;
  thresholds?: {
    independent: number;
    uniqueReleases?: number;
    recommended: number;
    withheld: number;
    adverse: number;
    safe: number;
  };
  currentModelVersion?: string;
  currentPromptVersion?: number;
  currentCodeRevision?: string | null;
  qualityCriteria?: {
    recommendationPrecisionLowerBound?: number;
    falseSafeUpperBound?: number;
    accuracyLowerBound?: number;
    safeVsAdverseAucMinimum?: number;
  };
  observations?: ReleaseValidationOutcomeLedgerRow[];
  auditHistory?: ReleaseScoreAuditHistoryEvidenceRow[];
  auditHistoryRuns?: ReleaseScoreAuditHistoryRunSealEvidenceRow[];
  authorityRuns?: ReleaseScoreAuthorityRunEvidence[];
  historyV2Seals?: ReleaseScoreAuditHistoryV2SealEvidence[];
  advisorySnapshots?: AdvisorySnapshotValidationEvidence[];
  opportunityDenominatorLedger?: ReleaseValidationOpportunityDenominatorLedger;
  prospectiveProof?: ReleaseValidationProspectiveProofInput;
}) {
  const currentModelVersion = input.currentModelVersion ??
    input.fixtures[0]?.forecast.score_model_version ??
    'model-current';
  const currentPromptVersion = input.currentPromptVersion ??
    input.fixtures[0]?.forecast.prompt_version ??
    6;
  const currentCodeRevision = input.currentCodeRevision === undefined
    ? TEST_CODE_REVISION
    : input.currentCodeRevision as string;
  const generatedAt = input.generatedAt ?? '2026-12-31T00:00:00.000Z';
  return evaluateReleaseValidationLedger({
    forecasts: input.fixtures.map((item) => item.forecast),
    observations: input.observations ?? input.outcomes.flatMap((item) => item.observations),
    auditHistory: input.auditHistory ?? [
      ...input.fixtures.flatMap((item) => item.history),
      ...input.outcomes.flatMap((item) => item.history),
    ],
    auditHistoryRuns: input.auditHistoryRuns ??
      input.fixtures.flatMap((item) =>
        item.historyRunSeal ? [item.historyRunSeal] : []),
    authorityRuns: input.authorityRuns ??
      input.fixtures.flatMap((item) =>
        item.authorityRun ? [item.authorityRun] : []),
    historyV2Seals: input.historyV2Seals ??
      input.fixtures.flatMap((item) =>
        item.historyV2Seal ? [item.historyV2Seal] : []),
    advisorySnapshots: input.advisorySnapshots ??
      input.outcomes.flatMap((item) => item.snapshots),
    currentModelVersion,
    currentPromptVersion,
    currentCodeRevision,
    generatedAt,
    thresholds: input.thresholds
      ? {
          ...input.thresholds,
          uniqueReleases: input.thresholds.uniqueReleases ??
            input.thresholds.independent,
        }
      : undefined,
    qualityCriteria: input.qualityCriteria,
    opportunityDenominatorLedger: input.opportunityDenominatorLedger ??
      opportunityDenominatorForForecasts({
        forecasts: input.fixtures.map((item) => item.forecast),
        currentModelVersion,
        currentPromptVersion,
        currentCodeRevision,
        asOf: generatedAt,
      }),
    prospectiveProof: input.prospectiveProof,
  }) as any;
}

function emptyOpportunityDenominator(
  asOf: string,
): ReleaseValidationOpportunityDenominatorLedger {
  return buildReleaseValidationOpportunityDenominatorLedger({
    asOf,
    enrollments: [],
    forecasts: [],
  });
}

function opportunityDenominatorForForecasts(input: {
  forecasts: ReleaseValidationForecastLedgerRow[];
  currentModelVersion: string;
  currentPromptVersion: number;
  currentCodeRevision: string;
  asOf: string;
}): ReleaseValidationOpportunityDenominatorLedger {
  const codeRevision = normalizeCodeRevision(input.currentCodeRevision);
  if (!codeRevision) return emptyOpportunityDenominator(input.asOf);
  const currentForecasts = input.forecasts.filter((forecast) =>
    forecast.score_model_version === input.currentModelVersion &&
    forecast.prompt_version === input.currentPromptVersion &&
    normalizeCodeRevision(forecast.code_revision) === codeRevision &&
    releaseValidationForecastTiming(forecast).valid &&
    (() => {
      try {
        const decision = JSON.parse(forecast.decision_json);
        return decision.schemaVersion === 4 &&
          typeof decision.opportunityWindow?.windowStartAt === 'string' &&
          typeof decision.opportunityWindow?.windowEndAt === 'string';
      } catch {
        return false;
      }
    })());
  let previousContentHash: string | null = null;
  const enrollments: ReleaseValidationOpportunityEnrollmentRow[] =
    currentForecasts.map((forecast, index) => {
      const decision = JSON.parse(forecast.decision_json);
      const opportunityWindow = decision.opportunityWindow;
      const inputRow = {
        enrolled_at: new Date(
          Date.parse(forecast.recorded_at) - 1,
        ).toISOString(),
        cohort_inception_at: new Date(
          Date.parse(forecast.recorded_at) - 1,
        ).toISOString(),
        enrollment_kind: 'prospective' as const,
        release_node_id:
          decision.catalogAttestation?.latestStable?.nodeId ??
          `node-${forecast.latest_release_tag}`,
        release_tag: forecast.latest_release_tag,
        release_tag_commit_oid:
          decision.catalogAttestation?.latestStable?.tagCommitOid ??
          '1'.repeat(40),
        release_published_at: forecast.latest_release_published_at,
        opportunity_code: forecast.opportunity_code as
          ReleaseValidationOpportunityEnrollmentRow['opportunity_code'],
        opens_at: opportunityWindow.windowStartAt,
        closes_at_exclusive: opportunityWindow.windowEndAt,
        score_model_version: forecast.score_model_version,
        prompt_version: forecast.prompt_version,
        code_revision: codeRevision,
        enrollment_run_id: `test-enrollment-${forecast.decision_id}`,
        operation_attempt_content_hash: stableSha256(
          `attempt-${forecast.decision_id}`,
        ),
        catalog_digest: stableSha256(`catalog-${forecast.decision_id}`),
        catalog_release_count: 1,
      };
      const opportunityId = releaseValidationOpportunityId(inputRow);
      const contentHash = releaseValidationOpportunityEnrollmentContentHash({
        ...inputRow,
        opportunity_id: opportunityId,
        previous_content_hash: previousContentHash,
      });
      const row = {
        id: index + 1,
        ...inputRow,
        opportunity_id: opportunityId,
        previous_content_hash: previousContentHash,
        content_hash: contentHash,
      };
      previousContentHash = contentHash;
      return row;
    });
  return buildReleaseValidationOpportunityDenominatorLedger({
    asOf: input.asOf,
    enrollments,
    forecasts: input.forecasts,
  });
}

function stableSha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function emptyCanonicalValidationProof(): ReleaseValidationProofBundle {
  return {
    epochs: [],
    retirements: [],
    policies: [],
    cohorts: [],
    catalogObservations: [],
    catalogMembers: [],
    catalogReconciliations: [],
    catalogReconciliationRows: [],
    obligations: [],
    splitAssignments: [],
    forecasts: [],
    outcomes: [],
    observationBatches: [],
    evaluationReceipts: [],
    promotionReceipts: [],
  };
}

function canonicalEvaluationFixture(input: {
  complete?: boolean;
} = {}) {
  const complete = input.complete ?? true;
  const repository = 'openclaw/openclaw';
  const releaseCount = 7;
  const releaseSpacingMs = 40 * DAY_MS;
  const releases = Array.from({ length: releaseCount }, (_, index) => {
    const publishedAt = new Date(
      Date.parse('2026-01-01T00:00:00.000Z') +
        index * releaseSpacingMs,
    ).toISOString();
    return {
      repository,
      nodeId: `R_canonical_${index + 1}`,
      tagCommitOid: `${index + 1}`.repeat(40),
      publishedAt,
      aliases: [`2026.${index + 1}.0`],
      adverse: index >= 4,
      score: index >= 4 ? 3 : 9,
    };
  });

  let proof = emptyCanonicalValidationProof();
  const strictFixtures: Array<
    ReturnType<typeof strictAuthorityForecastFixture>
  > = [];
  const outcomeFixtures: OutcomeFixture[] = [];
  const observations: ReleaseValidationOutcomeLedgerRow[] = [];
  const canonicalForecasts: Array<
    ReturnType<typeof sealReleaseValidationForecastV2>
  > = [];
  const canonicalOutcomes: Array<
    ReturnType<typeof sealReleaseValidationOutcomeV2>
  > = [];
  let previousForecastHash: string | null = null;
  let previousOutcomeHash: string | null = null;
  let nextForecastId = 1;
  let nextOutcomeId = 1;
  let cohort: ReleaseValidationProofBundle['cohorts'][number] | null = null;

  for (const [index, release] of releases.entries()) {
    const lifecycle = planReleaseValidationProofLifecycle({
      existing: proof,
      repository,
      observedAt: release.publishedAt,
      source: `canonical-catalog-${index + 1}`,
      releases: releases.slice(0, index + 1),
      modelVersion: 'model-current',
      promptVersion: 6,
      codeRevision: TEST_CODE_REVISION,
      policyCode: 'prospective-release-validation',
      policyVersion: 1,
      developmentArm: 'production',
      developmentReleaseCount: 1,
    });
    proof = lifecycle.bundle;
    if (cohort == null) {
      cohort = lifecycle.cohort;
    } else {
      assert.equal(lifecycle.cohort.cohortId, cohort.cohortId);
    }

    const releaseFixtures = [
      strictAuthorityForecastFixture({
        decisionId: `canonical-${index + 1}-3h`,
        latestTag: release.aliases[0],
        opportunityCode: 'first_verified_after_3h',
        recordedAt: new Date(
          Date.parse(release.publishedAt) + 5 * HOUR_MS,
        ).toISOString(),
        releaseNodeId: release.nodeId,
        releaseTagCommitOid: release.tagCommitOid,
        releasePublishedAt: release.publishedAt,
        candidates: [{ tag: release.aliases[0], score: release.score }],
      }),
      strictAuthorityForecastFixture({
        decisionId: `canonical-${index + 1}-24h`,
        latestTag: release.aliases[0],
        opportunityCode: 'first_verified_after_24h',
        recordedAt: new Date(
          Date.parse(release.publishedAt) + 29 * HOUR_MS,
        ).toISOString(),
        releaseNodeId: release.nodeId,
        releaseTagCommitOid: release.tagCommitOid,
        releasePublishedAt: release.publishedAt,
        candidates: [{ tag: release.aliases[0], score: release.score }],
      }),
    ];
    for (const fixture of releaseFixtures) {
      const forecastRow = {
        ...fixture.forecast,
        id: nextForecastId++,
        previous_content_hash: previousForecastHash,
        content_hash: '',
      };
      forecastRow.content_hash = releaseValidationForecastContentHash(
        forecastRow,
        previousForecastHash,
      );
      forecastRow.decision_id = releaseValidationDecisionId(
        forecastRow,
        forecastRow.content_hash,
      );
      fixture.forecast = forecastRow;
      previousForecastHash = forecastRow.content_hash;
    }
    strictFixtures.push(...releaseFixtures);

    const releaseOutcomeFixtures = releaseFixtures.map((fixture) =>
      outcomeFixture(fixture, {
        field_regression_72h: release.adverse,
        security_30d: release.adverse,
      }));
    outcomeFixtures.push(...releaseOutcomeFixtures);
    const releaseObservations = releaseOutcomeFixtures
      .flatMap((fixture) => fixture.observations)
      .sort((left, right) =>
        Date.parse(left.observed_at) - Date.parse(right.observed_at) ||
        left.decision_id.localeCompare(right.decision_id) ||
        left.horizon_code.localeCompare(right.horizon_code));
    for (const observation of releaseObservations) {
      observation.id = nextOutcomeId++;
      observation.previous_content_hash = previousOutcomeHash;
      observation.content_hash = releaseValidationOutcomeContentHash(
        observation,
        previousOutcomeHash,
      );
      observation.observation_id =
        releaseValidationObservationId(observation);
      previousOutcomeHash = observation.content_hash;
    }
    observations.push(...releaseObservations);

    const verification = verifyReleaseValidationProofBundle(proof);
    assert.equal(
      verification.valid,
      true,
      verification.problems.join('; '),
    );
    let cohortSequence = Math.max(
      0,
      ...[
        ...proof.obligations,
        ...proof.splitAssignments,
        ...proof.forecasts,
        ...proof.outcomes,
        ...proof.observationBatches,
      ].map((row) => row.cohortSequence),
    );
    let cohortTip =
      verification.cohortChainTips[cohort.cohortId] ?? null;
    const releaseObligations = proof.obligations
      .filter((obligation) =>
        obligation.release.nodeId === release.nodeId)
      .sort((left, right) => {
        const leftFixture = releaseFixtures.find((fixture) =>
          fixture.forecast.opportunity_code === left.opportunityCode);
        const rightFixture = releaseFixtures.find((fixture) =>
          fixture.forecast.opportunity_code === right.opportunityCode);
        assert.ok(leftFixture);
        assert.ok(rightFixture);
        return Date.parse(leftFixture.forecast.recorded_at) -
          Date.parse(rightFixture.forecast.recorded_at) ||
          left.cellId.localeCompare(right.cellId);
      });
    const omittedObligationId =
      !complete && index === releases.length - 1
        ? releaseObligations.at(-1)?.obligationId ?? null
        : null;
    const releaseCanonicalForecasts: Array<
      ReturnType<typeof sealReleaseValidationForecastV2>
    > = [];

    for (const obligation of releaseObligations) {
      if (obligation.obligationId === omittedObligationId) continue;
      const legacyFixture = releaseFixtures.find((fixture) =>
        fixture.forecast.opportunity_code === obligation.opportunityCode);
      assert.ok(legacyFixture);
      const assignment = proof.splitAssignments.find((row) =>
        row.obligationId === obligation.obligationId);
      assert.ok(assignment);
      const canonicalForecast = sealReleaseValidationForecastV2({
        proofEpochId: cohort.proofEpochId,
        cohortId: cohort.cohortId,
        cohortSequence: ++cohortSequence,
        previousCohortContentHash: cohortTip,
        obligationId: obligation.obligationId,
        splitAssignmentId: assignment.assignmentId,
        policyId: cohort.policyId,
        policyContentHash: cohort.policyContentHash,
        recordedAt: legacyFixture.forecast.recorded_at,
        latestRelease: obligation.release,
        candidates: [obligation.release],
        selectedReleaseId: obligation.release.releaseId,
        forecast: {
          schemaVersion: 1,
          legacyForecast: {
            decisionId: legacyFixture.forecast.decision_id,
            contentHash: legacyFixture.forecast.content_hash,
          },
        },
      });
      releaseCanonicalForecasts.push(canonicalForecast);
      canonicalForecasts.push(canonicalForecast);
      cohortTip = canonicalForecast.contentHash;
    }

    const releaseOutcomeInputs = releaseCanonicalForecasts
      .map((canonicalForecast) => {
        const obligation = releaseObligations.find((row) =>
          row.obligationId === canonicalForecast.obligationId);
        assert.ok(obligation);
        const legacyFixture = releaseFixtures.find((fixture) =>
          fixture.forecast.opportunity_code === obligation.opportunityCode);
        assert.ok(legacyFixture);
        const legacyObservation = releaseObservations.find((row) =>
          row.decision_id === legacyFixture.forecast.decision_id &&
          row.horizon_code === obligation.horizonCode);
        assert.ok(legacyObservation);
        return {
          canonicalForecast,
          obligation,
          legacyFixture,
          legacyObservation,
        };
      })
      .sort((left, right) =>
        Date.parse(left.legacyObservation.observed_at) -
          Date.parse(right.legacyObservation.observed_at) ||
        left.obligation.cellId.localeCompare(right.obligation.cellId));
    const releaseCanonicalOutcomes: Array<
      ReturnType<typeof sealReleaseValidationOutcomeV2>
    > = [];
    for (const outcomeInput of releaseOutcomeInputs) {
      const parsedOutcome = JSON.parse(
        outcomeInput.legacyObservation.outcome_json,
      );
      const canonicalOutcome = sealReleaseValidationOutcomeV2({
        proofEpochId: cohort.proofEpochId,
        cohortId: cohort.cohortId,
        cohortSequence: ++cohortSequence,
        previousCohortContentHash: cohortTip,
        forecastId: outcomeInput.canonicalForecast.forecastId,
        obligationId: outcomeInput.obligation.obligationId,
        cellId: outcomeInput.obligation.cellId,
        releaseId: outcomeInput.obligation.release.releaseId,
        observedAt: outcomeInput.legacyObservation.observed_at,
        status: parsedOutcome.adverse === true ? 'adverse' : 'safe',
        evidenceContentHashes: [
          outcomeInput.legacyObservation.content_hash,
        ],
        outcome: {
          schemaVersion: 1,
          legacyForecast: {
            decisionId: outcomeInput.legacyFixture.forecast.decision_id,
            contentHash: outcomeInput.legacyFixture.forecast.content_hash,
          },
          legacyObservation: {
            observationId:
              outcomeInput.legacyObservation.observation_id,
            contentHash: outcomeInput.legacyObservation.content_hash,
            status: outcomeInput.legacyObservation.status,
            observedAt: outcomeInput.legacyObservation.observed_at,
          },
        },
      });
      releaseCanonicalOutcomes.push(canonicalOutcome);
      canonicalOutcomes.push(canonicalOutcome);
      cohortTip = canonicalOutcome.contentHash;
    }
    proof = {
      ...proof,
      forecasts: [...proof.forecasts, ...releaseCanonicalForecasts],
      outcomes: [...proof.outcomes, ...releaseCanonicalOutcomes],
    };
    const releaseVerification = verifyReleaseValidationProofBundle(proof);
    assert.equal(
      releaseVerification.valid,
      true,
      releaseVerification.problems.join('; '),
    );
  }

  assert.ok(cohort);
  const verification = verifyReleaseValidationProofBundle(proof);
  assert.equal(verification.valid, true, verification.problems.join('; '));
  let cohortSequence = Math.max(
    0,
    ...[
      ...proof.obligations,
      ...proof.splitAssignments,
      ...proof.forecasts,
      ...proof.outcomes,
      ...proof.observationBatches,
    ].map((row) => row.cohortSequence),
  );
  const cohortTip =
    verification.cohortChainTips[cohort.cohortId] ?? null;
  const batchObservedAt = new Date(
    Math.max(...canonicalOutcomes.map((row) => Date.parse(row.observedAt))) +
      1_000,
  ).toISOString();
  const observationBatch = sealReleaseValidationObservationBatch({
    proofEpochId: cohort.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: ++cohortSequence,
    previousCohortContentHash: cohortTip,
    observedAt: batchObservedAt,
    sourceIdentityHash: stableSha256('canonical-evaluation-batch-source'),
    expectedObligationIds: canonicalForecasts.map((row) => row.obligationId),
    cells: canonicalForecasts.map((forecastRow) => {
      const outcome = canonicalOutcomes.find((row) =>
        row.forecastId === forecastRow.forecastId);
      assert.ok(outcome);
      return {
        obligationId: forecastRow.obligationId,
        forecastId: forecastRow.forecastId,
        outcomeId: outcome.outcomeId,
        disposition: 'observed' as const,
      };
    }),
  });
  proof = {
    ...proof,
    observationBatches: [observationBatch],
  };
  const finalVerification = verifyReleaseValidationProofBundle(proof);
  assert.equal(
    finalVerification.valid,
    true,
    finalVerification.problems.join('; '),
  );

  return {
    proof,
    fixtures: strictFixtures,
    outcomes: outcomeFixtures,
    observations,
    auditHistory: [
      ...strictFixtures.flatMap((fixture) => fixture.history),
      ...outcomeFixtures.flatMap((fixture) => fixture.history),
    ],
    auditHistoryRuns: strictFixtures.map((fixture) =>
      fixture.historyRunSeal),
    authorityRuns: strictFixtures.map((fixture) => fixture.authorityRun),
    historyV2Seals: strictFixtures.map((fixture) => fixture.historyV2Seal),
    advisorySnapshots: outcomeFixtures.flatMap((fixture) =>
      fixture.snapshots),
    generatedAt: new Date(Date.parse(batchObservedAt) + 1_000).toISOString(),
  };
}

function evaluateCanonicalFixture(
  fixture: ReturnType<typeof canonicalEvaluationFixture>,
  prospectiveProof: ReleaseValidationProspectiveProofInput = {
    canonicalProof: fixture.proof,
    evaluationPurpose: 'production',
  },
) {
  return evaluateFixtures({
    fixtures: fixture.fixtures,
    outcomes: fixture.outcomes,
    observations: fixture.observations,
    auditHistory: fixture.auditHistory,
    auditHistoryRuns: fixture.auditHistoryRuns,
    authorityRuns: fixture.authorityRuns,
    historyV2Seals: fixture.historyV2Seals,
    advisorySnapshots: fixture.advisorySnapshots,
    generatedAt: fixture.generatedAt,
    thresholds: {
      independent: 2,
      uniqueReleases: 2,
      recommended: 1,
      withheld: 0,
      adverse: 1,
      safe: 1,
    },
    qualityCriteria: {
      recommendationPrecisionLowerBound: 0,
      falseSafeUpperBound: 1,
      accuracyLowerBound: 0,
      safeVsAdverseAucMinimum: 0.5,
    },
    prospectiveProof,
  });
}

describe('release validation ledger evaluation', () => {
  it('uses the documented production minimum of 20 for every sample category', () => {
    assert.deepEqual(DEFAULT_VALIDATION_SAMPLE_THRESHOLDS, {
      independent: 20,
      uniqueReleases: 20,
      recommended: 20,
      adverse: 20,
      withheld: 20,
      safe: 20,
    });
  });

  it('projects every validation evidence class to the evaluation cutoff', () => {
    const fixture = pointInTimeFilterFixture();
    const projected = filterScoreQualityEvidenceAsOf(
      fixture.source,
      fixture.cutoff,
      { includeCurrentLeaseSnapshot: true },
    );
    for (const key of [
      'advisorySnapshots',
      'forecasts',
      'observations',
      'observationBatches',
      'enrollments',
      'attempts',
      'stageEvents',
      'receipts',
      'leases',
      'auditHistory',
      'auditHistoryRuns',
      'authorityRuns',
      'historyV2Seals',
    ] as const) {
      assert.deepEqual(
        projected[key].map((row: any) => row.marker),
        ['before'],
        key,
      );
    }
    for (const [key, rows] of Object.entries(projected.canonicalProof)) {
      assert.deepEqual(
        (rows as any[]).map((row) => row.marker),
        ['before'],
        key,
      );
    }
    assert.deepEqual(
      filterScoreQualityEvidenceAsOf(fixture.source, fixture.cutoff).leases,
      [],
      'historical replay must not trust the mutable current lease snapshot',
    );

    const invalid = structuredClone(fixture.source);
    invalid.forecasts[0].recorded_at = 'not-a-timestamp';
    assert.throws(
      () => filterScoreQualityEvidenceAsOf(invalid, fixture.cutoff),
      /authoritative timestamp is missing or invalid/,
    );

    const ambiguous = structuredClone(fixture.source.canonicalProof);
    ambiguous.catalogObservations[1].observationId =
      ambiguous.catalogObservations[0].observationId;
    assert.throws(
      () => filterCanonicalReleaseValidationProofAsOf(
        ambiguous,
        fixture.cutoff,
      ),
      /authoritative timestamp parent identity is ambiguous/,
    );
  });

  it('excludes outcomes observed after generatedAt and rejects invalid outcome time', () => {
    const fixture = forecastFixture({
      decisionId: 'future-outcome',
      latestTag: 'v-future-outcome',
    });
    const future = outcomeFixture(fixture).observations[0];
    const generatedAt = new Date(
      Date.parse(future.observed_at) - 1,
    ).toISOString();
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [],
      observations: [future],
      auditHistory: fixture.history,
      advisorySnapshots: [],
      generatedAt,
      thresholds: {
        independent: 0,
        recommended: 0,
        withheld: 0,
        adverse: 0,
        safe: 0,
      },
    });
    assert.equal(report.outcomeLedgerRowCount, 0);
    assert.equal(report.combined.cases.length, 0);

    const invalid = {
      ...future,
      observed_at: 'not-a-timestamp',
    };
    const invalidReport = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [],
      observations: [invalid],
      auditHistory: fixture.history,
      advisorySnapshots: [],
      generatedAt,
      thresholds: {
        independent: 0,
        recommended: 0,
        withheld: 0,
        adverse: 0,
        safe: 0,
      },
    });
    assert.equal(invalidReport.status, 'measurable_but_failed');
    assert.match(
      invalidReport.errors.join('\n'),
      /has an invalid observed_at/,
    );
  });

  it('canonical prospective evaluation refuses incomplete required cells', () => {
    const fixture = canonicalEvaluationFixture({ complete: false });
    const report = evaluateCanonicalFixture(fixture);

    assert.equal(report.status, 'insufficient');
    assert.equal(report.promotionDecision.productionAuthorized, false);
    assert.equal(
      report.prospectiveEvaluation.productionSummary
        .everyActiveCohortPassed,
      false,
    );
    assert.ok(
      report.prospectiveEvaluation.cohorts[0].cells.some(
        (cell: any) => cell.status === 'insufficient',
      ),
    );
  });

  it('canonical prospective evaluation validates only when every cell passes', () => {
    const fixture = canonicalEvaluationFixture();
    const report = evaluateCanonicalFixture(fixture, {
      canonicalProof: fixture.proof,
      evaluationPurpose: 'production',
      cohorts: [],
      splitAssignments: [],
      reconciliationRows: [],
      observationBatches: [],
      observationBatchVerification: {
        failedCount: 99,
        problems: ['obsolete prospective proof must be ignored'],
      },
    });

    assert.deepEqual(report.errors, []);
    assert.equal(report.status, 'validated');
    assert.equal(report.promotionDecision.productionAuthorized, true);
    assert.equal(
      report.prospectiveEvaluation.splitAssignments.source,
      'canonical_obligation_assignments',
    );
    assert.equal(
      report.prospectiveEvaluation.productionSummary
        .everyActiveCohortPassed,
      true,
    );
    assert.ok(
      report.prospectiveEvaluation.cohorts[0].cells.every(
        (cell: any) => cell.status === 'passed',
      ),
    );
  });

  it('canonical prospective evaluation fails closed on proof corruption', () => {
    const fixture = canonicalEvaluationFixture();
    const corrupted = structuredClone(fixture.proof);
    corrupted.forecasts[0].contentHash = '0'.repeat(64);
    const report = evaluateCanonicalFixture(fixture, {
      canonicalProof: corrupted,
      evaluationPurpose: 'production',
    });

    assert.equal(report.status, 'measurable_but_failed');
    assert.equal(report.promotionDecision.productionAuthorized, false);
    assert.equal(
      report.prospectiveEvaluation.proofVerification.valid,
      false,
    );
    assert.match(
      report.errors.join('\n'),
      /Canonical validation proof:/,
    );
  });

  it('runs forecast, dual-target observation, and separate candidate/policy evaluation', () => {
    const fixture = forecastFixture({
      decisionId: 'dual-target-lifecycle',
      latestTag: 'v2026.2.1',
      selectedTag: 'v2026.1.1',
      candidates: [
        { tag: 'v2026.2.1', score: 2 },
        { tag: 'v2026.1.1', score: 9 },
        { tag: 'v2025.12.1', score: 5 },
      ],
    });
    const latestEvidence = independentAdverseEvidence(fixture.forecast, 301, {
      versionLink: {
        source: 'title',
        version: fixture.forecast.latest_release_tag,
        referenceUrl: 'https://example.test/issues/301',
        commentId: null,
        author: 'reporter',
        snippet: `Regression on ${fixture.forecast.latest_release_tag}`,
      },
    });
    const fieldInput = cleanEvidence('field_regression_72h', {
      forecast: fixture.forecast,
      independentFieldEvidence: [
        independentFieldSnapshot(fixture.forecast, [latestEvidence], {
          targetReleaseTag: fixture.forecast.latest_release_tag,
        }),
        independentFieldSnapshot(fixture.forecast, [], {
          targetReleaseTag: fixture.forecast.selected_tag!,
        }),
        independentFieldSnapshot(fixture.forecast, [], {
          targetReleaseTag: 'v2025.12.1',
        }),
      ],
    });
    const fieldAssessment = assessReleaseValidationObservation(fieldInput);
    assert.equal(fieldAssessment.status, 'matured');
    if (fieldAssessment.status !== 'matured') return;
    assert.equal(fieldAssessment.outcome.schemaVersion, 3);
    assert.equal(fieldAssessment.outcome.candidateOutcomes?.length, 3);
    assert.deepEqual(
      fieldAssessment.outcome.candidateOutcomes?.find((item) =>
        item.targetReleaseTag === 'v2025.12.1')?.roles,
      ['candidate'],
    );
    assert.equal(fieldAssessment.outcome.adverse, false);

    const securityRows = [advisoryRow({
      ghsa_id: 'GHSA-dual-target',
      vulnerable_version_range: fixture.forecast.latest_release_tag,
      patched_versions: null,
      published_at: '2026-01-20T00:00:00.000Z',
    })];
    const securityEvidence = authorizedAdvisorySnapshot(securityRows, {
      snapshotId: 301,
      capturedAt: '2026-02-01T00:00:00.000Z',
    });
    const securityInput = cleanEvidence('security_30d', {
      forecast: fixture.forecast,
      advisorySnapshots: [securityEvidence],
    });
    const securityAssessment = assessReleaseValidationObservation(securityInput);
    assert.equal(securityAssessment.status, 'matured');
    if (securityAssessment.status !== 'matured') return;
    assert.equal(securityAssessment.outcome.candidateOutcomes?.length, 3);
    assert.equal(securityAssessment.outcome.adverse, false);

    const observations: ReleaseValidationOutcomeLedgerRow[] = [];
    for (const [id, assessment] of [
      [1, fieldAssessment],
      [2, securityAssessment],
    ] as const) {
      const row: ReleaseValidationOutcomeLedgerRow = {
        id,
        observation_id: '',
        decision_id: fixture.forecast.decision_id,
        horizon_code: assessment.horizonCode,
        observed_at: assessment.observedAt,
        status: 'matured',
        outcome_json: JSON.stringify(assessment.outcome),
        source_identity_json: JSON.stringify(assessment.sourceIdentity),
        previous_content_hash: observations.at(-1)?.content_hash ?? null,
        content_hash: '',
      };
      row.content_hash = releaseValidationOutcomeContentHash(
        row,
        row.previous_content_hash,
      );
      row.observation_id = releaseValidationObservationId(row);
      observations.push(row);
    }
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [],
      observations,
      auditHistory: [
        ...fixture.history,
        ...fieldInput.auditHistory,
        ...securityInput.auditHistory,
      ],
      advisorySnapshots: [securityEvidence],
      thresholds: {
        independent: 1,
        recommended: 1,
        withheld: 0,
        adverse: 0,
        safe: 1,
      },
    });
    assert.deepEqual(report.errors, []);
    assert.equal(report.policyActionSafety.combined.cases.length, 1);
    assert.equal(report.policyActionSafety.combined.cases[0].releaseTag, 'v2026.1.1');
    assert.equal(report.policyActionSafety.combined.cases[0].adverse, false);
    assert.equal(report.candidateScoreQuality.combined.cases.length, 3);
    assert.equal(
      report.candidateScoreQuality.combined.nonOverlappingSensitivity.candidateCount,
      3,
    );
    assert.equal(
      report.candidateScoreQuality.combined.nonOverlappingSensitivity
        .independentSampleCount,
      1,
    );
    assert.equal(
      report.candidateScoreQuality.combined.cases.find((item: any) =>
        item.releaseTag === 'v2026.2.1').adverse,
      true,
    );
    assert.equal(
      report.candidateScoreQuality.combined.cases.find((item: any) =>
        item.releaseTag === 'v2026.1.1').adverse,
      false,
    );
  });

  it('requires the selected tag and candidate set to exactly match the history run', () => {
    const fixture = forecastFixture({
      decisionId: 'bound',
      latestTag: 'v2',
      selectedTag: 'v1',
      candidates: [
        { tag: 'v2', score: 7 },
        { tag: 'v1', score: 9 },
      ],
    });
    assert.deepEqual(
      validateReleaseValidationForecastProvenance(
        [fixture.forecast],
        fixture.history,
        [fixture.historyRunSeal!],
        [fixture.authorityRun!],
        [fixture.historyV2Seal!],
      ),
      [],
    );

    const wrongRecommended = fixture.history.map((row) => ({
      ...row,
      recommended: row.release_tag === 'v2' ? 1 : 0,
    }));
    assert.match(
      validateReleaseValidationForecastProvenance(
        [fixture.forecast],
        wrongRecommended,
      ).join('\n'),
      /does not equal the recommended history candidate/,
    );

    const omitted = {
      ...fixture.forecast,
      candidate_scores_json: JSON.stringify(
        JSON.parse(fixture.forecast.candidate_scores_json).slice(0, 1),
      ),
    };
    assert.match(
      validateReleaseValidationForecastProvenance([omitted], fixture.history).join('\n'),
      /candidate tags do not exactly match history run/,
    );
  });

  it('rejects tampered authority runs, v2 seals, and score-commit authority links', () => {
    const fixture = strictAuthorityForecastFixture({
      decisionId: 'strict-authority',
      latestTag: 'v-strict-authority',
    });
    const validate = (
      authorityRuns = [fixture.authorityRun],
      historyV2Seals = [fixture.historyV2Seal],
      forecasts = [fixture.forecast],
    ) => validateReleaseValidationForecastProvenance(
      forecasts,
      fixture.history,
      [fixture.historyRunSeal],
      authorityRuns,
      historyV2Seals,
    );

    assert.deepEqual(validate(), []);
    assert.match(
      validate([], []).join('\n'),
      /score authority run .* is missing/,
    );
    assert.match(
      validate([], []).join('\n'),
      /score audit history v2 seal is missing/,
    );

    const tamperedAuthorityRun = {
      ...fixture.authorityRun,
      contentHash: 'f'.repeat(64),
    };
    assert.match(
      validate([tamperedAuthorityRun]).join('\n'),
      /authority run contentHash does not match canonical run/,
    );

    const mismatchedV2Seal = buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: fixture.historyV2Seal.historyRunId,
      authorityRunId: fixture.historyV2Seal.authorityRunId,
      sealedAt: fixture.historyV2Seal.sealedAt,
      historyRowCount: fixture.historyV2Seal.historyRowCount,
      historyRowsContentHash: fixture.historyV2Seal.historyRowsContentHash,
      authorityRowCount: fixture.historyV2Seal.authorityRowCount,
      authorityRowsContentHash: 'e'.repeat(64),
      previousContentHash: fixture.historyV2Seal.previousContentHash,
    });
    assert.match(
      validate([fixture.authorityRun], [mismatchedV2Seal]).join('\n'),
      /history v2 seal does not exactly bind the history and authority runs/,
    );

    const decision = JSON.parse(fixture.forecast.decision_json);
    decision.scoreCommit.authorityRunContentHash = 'd'.repeat(64);
    assert.match(
      validate(
        [fixture.authorityRun],
        [fixture.historyV2Seal],
        [{
          ...fixture.forecast,
          decision_json: JSON.stringify(decision),
        }],
      ).join('\n'),
      /authorityRunContentHash does not match the authority run/,
    );
  });

  it('uses only history-bound score snapshots and rejects conflicting aliases', () => {
    const fixture = forecastFixture({
      decisionId: 'score-aliases',
      latestTag: 'v1',
      candidates: [{ tag: 'v1', score: 8 }],
    });
    const candidates = JSON.parse(fixture.forecast.candidate_scores_json);
    candidates[0].score = 1;
    const injected = {
      ...fixture.forecast,
      candidate_scores_json: JSON.stringify(candidates),
    };
    assert.match(
      validateReleaseValidationForecastProvenance([injected], fixture.history).join('\n'),
      /conflicting score aliases/,
    );

    const injectedFixture = { forecast: injected, history: fixture.history };
    const injectedOutcomes = outcomeFixture(injectedFixture);
    const report = evaluateFixtures({
      fixtures: [injectedFixture],
      outcomes: [injectedOutcomes],
      thresholds: { independent: 1, recommended: 1, withheld: 0, adverse: 0, safe: 1 },
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.equal(report.combined.cases[0].score, 8);

    const conflictingTagCandidates = JSON.parse(fixture.forecast.candidate_scores_json);
    conflictingTagCandidates[0].tag = 'v-other';
    const conflictingTag = {
      ...fixture.forecast,
      candidate_scores_json: JSON.stringify(conflictingTagCandidates),
    };
    assert.match(
      validateReleaseValidationForecastProvenance([conflictingTag], fixture.history).join('\n'),
      /conflicting candidate aliases/,
    );

    const conflictingSnapshotCandidates = JSON.parse(fixture.forecast.candidate_scores_json);
    conflictingSnapshotCandidates[0].scoreSnapshot.final_score = 2;
    const conflictingSnapshot = {
      ...fixture.forecast,
      candidate_scores_json: JSON.stringify(conflictingSnapshotCandidates),
    };
    assert.match(
      validateReleaseValidationForecastProvenance(
        [conflictingSnapshot],
        fixture.history,
      ).join('\n'),
      /conflicting score aliases/,
    );
  });

  it('binds forecast time and candidate audit identity to the exact history run', () => {
    const fixture = forecastFixture({
      decisionId: 'forecast-run-time',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const laterRecordedAt = '2026-01-02T00:00:00.000Z';
    const laterHistory = fixture.history.map((row) => ({
      ...row,
      recorded_at: laterRecordedAt,
      scored_at: laterRecordedAt,
    }));
    const laterCandidates = JSON.parse(fixture.forecast.candidate_scores_json);
    laterCandidates[0].auditSnapshot = laterHistory[0];
    laterCandidates[0].scoreSnapshot.scoredAt = laterRecordedAt;
    const laterRunForecast = {
      ...fixture.forecast,
      candidate_scores_json: JSON.stringify(laterCandidates),
    };
    assert.deepEqual(
      validateReleaseValidationForecastProvenance(
        [fixture.forecast],
        fixture.history,
        [fixture.historyRunSeal!],
        [fixture.authorityRun!],
        [fixture.historyV2Seal!],
      ),
      [],
    );
    assert.match(
      validateReleaseValidationForecastProvenance(
        [laterRunForecast],
        laterHistory,
        [fixture.historyRunSeal!],
        [fixture.authorityRun!],
        [fixture.historyV2Seal!],
      ).join('\n'),
      /sealed history row projection is invalid|historyRecordedAt does not match/,
    );

    const missingRunIdCandidates = JSON.parse(fixture.forecast.candidate_scores_json);
    delete missingRunIdCandidates[0].auditSnapshot.run_id;
    const missingRunIdForecast = {
      ...fixture.forecast,
      candidate_scores_json: JSON.stringify(missingRunIdCandidates),
    };
    assert.match(
      validateReleaseValidationForecastProvenance(
        [missingRunIdForecast],
        fixture.history,
        [fixture.historyRunSeal!],
        [fixture.authorityRun!],
        [fixture.historyV2Seal!],
      ).join('\n'),
      /does not match score audit history/,
    );
  });

  it('exact-binds forecast score replay to persisted scored_at at 24h', () => {
    const boundary = '2026-06-02T00:00:00.000Z';
    const exact = scoreReplayForecastFixture(boundary, boundary);
    assert.deepEqual(
      validateReleaseValidationForecastProvenance(
        [exact.forecast],
        exact.history,
      ),
      [],
    );

    for (const ledgerTime of [
      '2026-06-01T23:59:59.999Z',
      '2026-06-02T00:00:00.001Z',
    ]) {
      const mismatched = scoreReplayForecastFixture(ledgerTime, boundary);
      const problems = validateReleaseValidationForecastProvenance(
        [mismatched.forecast],
        mismatched.history,
      ).join('\n');
      assert.match(
        problems,
        /scoreLedger evaluatedAt must exactly match persisted scoredAt/,
      );
      assert.match(
        problems,
        /scoreLedger semantic replay does not match the persisted derivation/,
      );
    }
  });

  it('accepts schema-v1 forecasts whose ledger row supplies the run identity', () => {
    const fixture = forecastFixture({
      decisionId: 'legacy-forecast-run-identity',
      latestTag: 'v1',
    });
    const decision = JSON.parse(fixture.forecast.decision_json);
    decision.schemaVersion = 1;
    const candidates = JSON.parse(fixture.forecast.candidate_scores_json);
    delete candidates[0].auditSnapshot.run_id;
    delete candidates[0].auditSnapshot.recorded_at;
    const legacy = {
      ...fixture.forecast,
      decision_json: JSON.stringify(decision),
      candidate_scores_json: JSON.stringify(candidates),
    };
    assert.deepEqual(
      validateReleaseValidationForecastProvenance([legacy], fixture.history),
      [],
    );
  });

  it('reports independent metrics and requires the current model stratum', () => {
    const fixtures = [
      forecastFixture({
        decisionId: 'd1',
        latestTag: 'v1',
        selectedTag: 'v1',
        modelVersion: 'model-a',
        recordedAt: '2026-01-01T00:00:00.000Z',
        candidates: [{ tag: 'v1', score: 9 }],
      }),
      forecastFixture({
        decisionId: 'd2',
        latestTag: 'v2',
        selectedTag: null,
        modelVersion: 'model-a',
        recordedAt: '2026-02-02T00:00:00.000Z',
        candidates: [{ tag: 'v2', score: 4 }],
      }),
      forecastFixture({
        decisionId: 'd3',
        latestTag: 'v3',
        selectedTag: 'v3',
        modelVersion: 'model-b',
        recordedAt: '2026-03-06T00:00:00.000Z',
        candidates: [{ tag: 'v3', score: 6 }],
      }),
      forecastFixture({
        decisionId: 'd4',
        latestTag: 'v4',
        selectedTag: null,
        modelVersion: 'model-b',
        recordedAt: '2026-04-08T00:00:00.000Z',
        candidates: [{ tag: 'v4', score: 7 }],
      }),
    ];
    const outcomes = [
      outcomeFixture(fixtures[0]),
      outcomeFixture(fixtures[1], {
        field_regression_72h: true,
        security_30d: true,
      }),
      outcomeFixture(fixtures[2], { security_30d: true }),
      outcomeFixture(fixtures[3]),
    ];
    const report = evaluateFixtures({
      fixtures,
      outcomes,
      generatedAt: '2026-06-01T00:00:00.000Z',
      currentModelVersion: 'model-a',
      thresholds: { independent: 2, recommended: 1, withheld: 1, adverse: 1, safe: 1 },
    });

    assert.equal(report.status, 'insufficient');
    assert.equal(report.decisionLevelForecastCount, 4);
    assert.deepEqual(report.combined.confusionMatrix, {
      definition: {
        positivePrediction: 'selected a release for installation',
        positiveOutcome: 'safe through horizon',
      },
      truePositiveRecommendedSafe: 1,
      falsePositiveRecommendedAdverse: 1,
      trueNegativeWithheldAdverse: 1,
      falseNegativeWithheldSafe: 1,
    });
    assert.equal(report.currentStratum.status, 'insufficient');
    assert.equal(report.currentStratum.policyGateStatus, 'insufficient');
    assert.equal(report.currentStratum.candidateScoreGateStatus, 'insufficient');
    assert.equal(report.combined.scoreAnalysis.discrimination.safeVsAdverseAuc, 1);
    assert.equal(
      report.currentStratum.combined.clusterAwareUncertainty.metrics
        .safeVsAdverseAuc,
      null,
    );
  });

  it('does not become measurable when only older model strata are sufficient', () => {
    const fixtures = [
      forecastFixture({
        decisionId: 'old-1',
        latestTag: 'v1',
        selectedTag: 'v1',
        modelVersion: 'old-model',
        recordedAt: '2026-01-01T00:00:00.000Z',
      }),
      forecastFixture({
        decisionId: 'old-2',
        latestTag: 'v2',
        selectedTag: null,
        modelVersion: 'old-model',
        recordedAt: '2026-02-02T00:00:00.000Z',
      }),
      forecastFixture({
        decisionId: 'current-1',
        latestTag: 'v3',
        selectedTag: 'v3',
        modelVersion: 'current-model',
        recordedAt: '2026-03-06T00:00:00.000Z',
      }),
    ];
    const outcomes = [
      outcomeFixture(fixtures[0]),
      outcomeFixture(fixtures[1], { field_regression_72h: true }),
      outcomeFixture(fixtures[2]),
    ];
    const report = evaluateFixtures({
      fixtures,
      outcomes,
      currentModelVersion: 'current-model',
      thresholds: { independent: 2, recommended: 1, withheld: 1, adverse: 1, safe: 1 },
    });
    assert.equal(report.status, 'insufficient');
    assert.equal(report.combined.sampleSufficiency.status, 'sufficient');
    assert.equal(report.currentStratum.status, 'insufficient');
  });

  it('keeps the same release opportunity in separate model/prompt forecast series', () => {
    const older = forecastFixture({
      decisionId: 'same-release-older-series',
      latestTag: 'v-series',
      opportunityCode: 'first_verified_after_24h',
      modelVersion: 'evidence-v16',
      promptVersion: 5,
      recordedAt: '2026-01-02T00:00:00.000Z',
    });
    const current = forecastFixture({
      decisionId: 'same-release-current-series',
      latestTag: 'v-series',
      opportunityCode: 'first_verified_after_24h',
      modelVersion: 'evidence-v19-stable-comment-snapshots',
      promptVersion: 6,
      recordedAt: '2026-01-02T02:00:00.000Z',
      releasePublishedAt: older.forecast.latest_release_published_at,
    });
    const report = evaluateFixtures({
      fixtures: [older, current],
      outcomes: [outcomeFixture(older), outcomeFixture(current)],
      currentModelVersion: 'evidence-v19-stable-comment-snapshots',
      currentPromptVersion: 6,
      thresholds: { independent: 1, recommended: 1, withheld: 0, adverse: 0, safe: 1 },
    });

    assert.equal(report.eligibleForecastCount, 2);
    assert.equal(report.decisionLevelForecastCount, 2);
    assert.equal(report.combined.independentSampleCount, 2);
    assert.equal(report.currentStratum.combined.present, true);
    assert.equal(report.currentStratum.combined.cases[0].decisionId, current.forecast.decision_id);
    assert.equal(
      report.primaryOpportunityPolicy,
      'retain_every_valid_forecast_decision_without_native_or_later-decision_collapse',
    );
    assert.equal(report.pairedModelComparisons.combined[0].matchedCaseCount, 1);
  });

  it('uses code revision in series identity and current-stratum selection', () => {
    const legacyRevision = forecastFixture({
      decisionId: 'revision-legacy-null',
      latestTag: 'v-revision',
      codeRevision: null,
    });
    const oldRevision = forecastFixture({
      decisionId: 'revision-old',
      latestTag: 'v-revision',
      codeRevision: 'old-revision',
    });
    const currentRevision = forecastFixture({
      decisionId: 'revision-current',
      latestTag: 'v-revision',
      codeRevision: 'current-revision',
    });
    const legacyOutcomes = outcomeFixture(legacyRevision);
    const oldOutcomes = outcomeFixture(oldRevision);
    const currentOutcomes = outcomeFixture(currentRevision);
    const report = evaluateFixtures({
      fixtures: [legacyRevision, oldRevision, currentRevision],
      outcomes: [legacyOutcomes, oldOutcomes, currentOutcomes],
      observations: [oldOutcomes.observations[0], currentOutcomes.observations[0]],
      advisorySnapshots: [],
      generatedAt: '2026-01-04T01:00:00.000Z',
      currentCodeRevision: ' current-revision ',
      thresholds: { independent: 1, recommended: 1, withheld: 0, adverse: 0, safe: 1 },
    });
    assert.equal(report.eligibleForecastCount, 3);
    assert.equal(report.currentStratum.codeRevision, 'current-revision');
    assert.deepEqual(report.currentStratum.availableCodeRevisions, [
      'old-revision',
      'current-revision',
    ]);
    assert.deepEqual(
      report.currentStratum.horizons.field_regression_72h.cases
        .map((item: any) => item.decisionId),
      ['revision-current'],
    );
    assert.equal(
      report.pairedModelComparisons.horizons.field_regression_72h[0].matchedCaseCount,
      1,
    );
  });

  it('refuses to infer the current revision from forecast rows', () => {
    const fixture = forecastFixture({
      decisionId: 'revision-not-inferred',
      latestTag: 'v-revision',
      codeRevision: 'only-ledger-revision',
    });
    const outcomes = outcomeFixture(fixture);
    assert.throws(
      () => evaluateFixtures({
        fixtures: [fixture],
        outcomes: [outcomes],
        currentCodeRevision: null,
      }),
      /code revision is required/,
    );
  });

  it('fails closed when the persisted denominator is missing and keeps status consistent', () => {
    const fixture = forecastFixture({
      decisionId: 'missing-denominator',
      latestTag: 'v-missing-denominator',
    });
    const outcomes = outcomeFixture(fixture);
    const report = evaluateReleaseValidationLedger({
      forecasts: [fixture.forecast],
      observations: outcomes.observations,
      auditHistory: [...fixture.history, ...outcomes.history],
      advisorySnapshots: outcomes.snapshots,
      currentModelVersion: fixture.forecast.score_model_version,
      currentPromptVersion: fixture.forecast.prompt_version,
      currentCodeRevision: TEST_CODE_REVISION,
      generatedAt: '2026-12-31T00:00:00.000Z',
      thresholds: {
        independent: 0,
        uniqueReleases: 0,
        recommended: 0,
        withheld: 0,
        adverse: 0,
        safe: 0,
      },
    }) as any;
    assert.equal(report.status, 'measurable_but_failed');
    assert.equal(report.currentStratum.status, report.status);
    assert.equal(report.currentStratum.failureClass, report.failureClass);
    assert.equal(report.opportunityDenominator.present, false);
    assert.match(
      report.errors.join('\n'),
      /opportunity denominator ledger is missing/,
    );
  });

  it('excludes a legacy 25-hour first 3-hour forecast from evaluation', () => {
    const fixture = forecastFixture({
      decisionId: 'legacy-late-3h',
      latestTag: 'v-late',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-01-02T01:00:00.000Z',
    });
    const decision = JSON.parse(fixture.forecast.decision_json);
    decision.schemaVersion = 2;
    decision.latestReleasePublishedAt = '2026-01-01T00:00:00.000Z';
    delete decision.latestReleaseAgeHours;
    delete decision.opportunityWindow;
    fixture.forecast.latest_release_published_at = '2026-01-01T00:00:00.000Z';
    fixture.forecast.decision_json = JSON.stringify(decision);
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [],
      generatedAt: '2026-01-02T02:00:00.000Z',
      thresholds: { independent: 0, recommended: 0, withheld: 0, adverse: 0, safe: 0 },
    });
    assert.equal(report.eligibleForecastCount, 0);
    assert.equal(report.excludedForecastCount, 1);
    assert.equal(report.excludedForecasts[0].reason, 'legacy_decision_schema');
    assert.equal(report.status, 'insufficient');
  });

  it('does not treat legacy classifier-only field outcomes as validation evidence', () => {
    const fixture = forecastFixture({
      decisionId: 'legacy-proxy-only',
      latestTag: 'v-proxy',
    });
    const outcomes = outcomeFixture(fixture);
    const legacyField = structuredClone(outcomes.observations[0]);
    const payload = JSON.parse(legacyField.outcome_json);
    payload.schemaVersion = 1;
    payload.fieldRegression = {
      evidenceScope: 'full_release_window',
      issueCount: 0,
      clusterCount: 0,
      issues: [],
    };
    legacyField.outcome_json = JSON.stringify(payload);
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: [legacyField, outcomes.observations[1]],
      generatedAt: '2026-03-01T00:00:00.000Z',
      thresholds: { independent: 0, recommended: 0, withheld: 0, adverse: 0, safe: 0 },
    });
    assert.equal(
      report.outcomeCoverage.horizons.field_regression_72h.proxyOnlyCount,
      1,
    );
    assert.equal(report.combined.independentSampleCount, 0);
    assert.equal(report.status, 'insufficient');
  });

  it('fails measurable inverted and useless models against minimum quality criteria', () => {
    const modelReport = (
      prefix: string,
      scores: number[],
    ) => {
      const tags = ['v2026.1.1', 'v2026.2.1', 'v2026.3.1', 'v2026.4.1'];
      const fixtures = (
        ['first_verified_after_3h', 'first_verified_after_24h'] as const
      ).flatMap((opportunityCode, opportunityIndex) => [
        forecastFixture({
          decisionId: `${prefix}-${opportunityCode}-recommended-safe`,
          latestTag: `${tags[0]}-${opportunityIndex}`,
          selectedTag: `${tags[0]}-${opportunityIndex}`,
          opportunityCode,
          recordedAt: new Date(
            Date.parse('2026-01-01T00:00:00.000Z') +
            opportunityIndex * 200 * DAY_MS,
          ).toISOString(),
          candidates: [{ tag: `${tags[0]}-${opportunityIndex}`, score: scores[0] }],
        }),
        forecastFixture({
          decisionId: `${prefix}-${opportunityCode}-recommended-adverse`,
          latestTag: `${tags[1]}-${opportunityIndex}`,
          selectedTag: `${tags[1]}-${opportunityIndex}`,
          opportunityCode,
          recordedAt: new Date(
            Date.parse('2026-02-02T00:00:00.000Z') +
            opportunityIndex * 200 * DAY_MS,
          ).toISOString(),
          candidates: [{ tag: `${tags[1]}-${opportunityIndex}`, score: scores[1] }],
        }),
        forecastFixture({
          decisionId: `${prefix}-${opportunityCode}-withheld-safe`,
          latestTag: `${tags[2]}-${opportunityIndex}`,
          selectedTag: null,
          opportunityCode,
          recordedAt: new Date(
            Date.parse('2026-03-06T00:00:00.000Z') +
            opportunityIndex * 200 * DAY_MS,
          ).toISOString(),
          candidates: [{ tag: `${tags[2]}-${opportunityIndex}`, score: scores[2] }],
        }),
        forecastFixture({
          decisionId: `${prefix}-${opportunityCode}-withheld-adverse`,
          latestTag: `${tags[3]}-${opportunityIndex}`,
          selectedTag: null,
          opportunityCode,
          recordedAt: new Date(
            Date.parse('2026-04-08T00:00:00.000Z') +
            opportunityIndex * 200 * DAY_MS,
          ).toISOString(),
          candidates: [{ tag: `${tags[3]}-${opportunityIndex}`, score: scores[3] }],
        }),
      ]);
      return evaluateFixtures({
        fixtures,
        outcomes: fixtures.map((fixture, index) =>
          outcomeFixture(
            fixture,
            index % 4 === 1 || index % 4 === 3
              ? { field_regression_72h: true, security_30d: true }
              : {},
          )),
        currentModelVersion: 'model-current',
        thresholds: {
          independent: 4,
          uniqueReleases: 4,
          recommended: 2,
          withheld: 2,
          adverse: 2,
          safe: 2,
        },
      });
    };
    const inverted = modelReport('inverted', [1, 9, 9, 1]);
    const useless = modelReport('useless', [5, 5, 5, 5]);
    assert.equal(inverted.errors.length, 0, JSON.stringify(inverted.errors, null, 2));
    assert.equal(useless.errors.length, 0, JSON.stringify(useless.errors, null, 2));
    assert.notEqual(inverted.status, 'validated');
    assert.notEqual(useless.status, 'validated');
    assert.equal(
      inverted.currentStratum.combined.sampleSufficiency.status,
      'sufficient',
      JSON.stringify(inverted.currentStratum.combined.sampleSufficiency, null, 2),
    );
    assert.equal(useless.currentStratum.combined.sampleSufficiency.status, 'sufficient');
    assert.equal(inverted.currentStratum.combined.qualityAssessment.status, 'failed');
    assert.equal(useless.currentStratum.combined.qualityAssessment.status, 'failed');
  });

  it('gates 3h and 24h independently on the later temporal holdout', () => {
    const fixtures: ForecastFixture[] = [];
    const outcomes: OutcomeFixture[] = [];
    for (let index = 0; index < 12; index++) {
      const publishedAt = new Date(
        Date.parse('2024-01-01T00:00:00.000Z') + index * 40 * DAY_MS,
      ).toISOString();
      for (const opportunityCode of (
        ['first_verified_after_3h', 'first_verified_after_24h'] as const
      )) {
        const holdout = index >= 6;
        const shouldFail = opportunityCode === 'first_verified_after_24h' && holdout;
        const adverse = index % 2 === 1;
        const recommend = shouldFail ? adverse : !adverse;
        const score = shouldFail
          ? adverse ? 9 : 1
          : adverse ? 1 : 9;
        const tag = `v2025.${index + 1}.1`;
        const opportunityAgeHours =
          opportunityCode === 'first_verified_after_3h' ? 4 : 25;
        const fixture = forecastFixture({
          decisionId: `${opportunityCode}-${index}`,
          latestTag: tag,
          selectedTag: recommend ? tag : null,
          opportunityCode,
          recordedAt: new Date(
            Date.parse(publishedAt) + opportunityAgeHours * HOUR_MS,
          ).toISOString(),
          releasePublishedAt: publishedAt,
          candidates: [{ tag, score }],
        });
        fixtures.push(fixture);
        outcomes.push(outcomeFixture(
          fixture,
          adverse
            ? { field_regression_72h: true, security_30d: true }
            : {},
        ));
      }
    }
    const report = evaluateFixtures({
      fixtures,
      outcomes,
      thresholds: {
        independent: 12,
        uniqueReleases: 12,
        recommended: 6,
        withheld: 6,
        adverse: 6,
        safe: 6,
      },
      qualityCriteria: {
        recommendationPrecisionLowerBound: 0.4,
        falseSafeUpperBound: 0.6,
        accuracyLowerBound: 0.6,
        safeVsAdverseAucMinimum: 0.6,
      },
    });

    assert.equal(
      report.currentStratum.opportunities.first_verified_after_3h.gateStatus,
      'passed',
    );
    assert.equal(
      report.currentStratum.opportunities.first_verified_after_24h.gateStatus,
      'failed',
    );
    assert.equal(
      report.currentStratum.opportunities.first_verified_after_3h
        .horizons.field_regression_72h.gateAnalysis.status,
      'passed',
    );
    assert.equal(
      report.currentStratum.opportunities.first_verified_after_24h
        .horizons.security_30d.gateAnalysis.status,
      'failed',
    );
    assert.equal(report.currentStratum.policyGateStatus, 'failed');
    assert.equal(report.status, 'measurable_but_failed');
    const temporal = report.currentStratum.opportunities
      .first_verified_after_24h.combined.temporalBlocks;
    assert.equal(temporal.method, 'chronological_development_holdout');
    assert.equal(temporal.development.qualityAssessment.status, 'passed');
    assert.equal(temporal.holdout.qualityAssessment.status, 'failed');
  });

  it('reports cell-specific insufficiency and differential censoring by opportunity', () => {
    const complete = forecastFixture({
      decisionId: 'coverage-complete-3h',
      latestTag: 'v-coverage-complete',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-01-01T04:00:00.000Z',
    });
    const censored = forecastFixture({
      decisionId: 'coverage-censored-24h',
      latestTag: 'v-coverage-censored',
      opportunityCode: 'first_verified_after_24h',
      recordedAt: '2026-03-02T01:00:00.000Z',
    });
    const completeOutcomes = outcomeFixture(complete);
    const censoredOutcomes = outcomeFixture(censored);
    const censoredSecurity = indeterminateRow(
      censored.forecast,
      'security_30d',
      99,
      {
        reason: 'post_horizon_advisory_snapshot_missing',
        fatal: false,
        afterGrace: false,
      },
    );
    const report = evaluateFixtures({
      fixtures: [complete, censored],
      outcomes: [completeOutcomes, censoredOutcomes],
      observations: [
        ...completeOutcomes.observations,
        censoredOutcomes.observations[0],
        censoredSecurity,
      ],
      generatedAt: new Date(
        Date.parse(censoredSecurity.observed_at) + 1,
      ).toISOString(),
      thresholds: {
        independent: 1,
        uniqueReleases: 1,
        recommended: 1,
        withheld: 0,
        adverse: 0,
        safe: 1,
      },
    });

    assert.equal(report.status, 'insufficient');
    assert.equal(report.failureClass, 'outcome_censoring');
    assert.equal(
      report.outcomeCoverage.horizons.security_30d.byOpportunity
        .first_verified_after_3h.maturedCount,
      1,
    );
    assert.equal(
      report.outcomeCoverage.horizons.security_30d.byOpportunity
        .first_verified_after_24h.indeterminateCount,
      1,
    );
    assert.equal(
      report.outcomeCoverage.combined.byOpportunity
        .first_verified_after_24h.indeterminateCount,
      1,
    );
    assert.equal(
      report.currentStratum.opportunities.first_verified_after_24h
        .horizons.field_regression_72h.sampleSufficiency.status,
      'sufficient',
    );
    assert.equal(
      report.currentStratum.opportunities.first_verified_after_24h
        .horizons.security_30d.sampleSufficiency.status,
      'insufficient',
    );
  });

  it('keeps repeated decisions for one release in a single dependence cluster', () => {
    const first = forecastFixture({
      decisionId: 'cluster-repeat-3h',
      latestTag: 'v-cluster-repeat',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-01-01T04:00:00.000Z',
    });
    const second = forecastFixture({
      decisionId: 'cluster-repeat-24h',
      latestTag: 'v-cluster-repeat',
      opportunityCode: 'first_verified_after_24h',
      recordedAt: '2026-01-02T01:00:00.000Z',
    });
    const report = evaluateFixtures({
      fixtures: [first, second],
      outcomes: [outcomeFixture(first), outcomeFixture(second)],
      thresholds: {
        independent: 2,
        uniqueReleases: 2,
        recommended: 2,
        withheld: 0,
        adverse: 0,
        safe: 2,
      },
    });

    assert.equal(report.combined.independentSampleCount, 2);
    assert.equal(
      report.combined.clusterAwareUncertainty.uniqueReleaseClusterCount,
      1,
    );
    assert.equal(
      report.currentStratum.combined.temporalBlocks.developmentClusterCount,
      1,
    );
    assert.equal(
      report.currentStratum.combined.temporalBlocks.holdoutClusterCount,
      0,
    );
  });

  it('keeps the chronological holdout immutable when later release clusters append', () => {
    const build = (count: number) => {
      const fixtures: ForecastFixture[] = [];
      const outcomes: OutcomeFixture[] = [];
      for (let index = 0; index < count; index++) {
        const adverse = index % 2 === 1;
        const tag = `v-holdout-${index + 1}`;
        const fixture = forecastFixture({
          decisionId: `holdout-${index + 1}`,
          latestTag: tag,
          selectedTag: adverse ? null : tag,
          opportunityCode: 'first_verified_after_3h',
          recordedAt: new Date(
            Date.parse('2024-01-01T00:00:00.000Z') + index * 40 * DAY_MS,
          ).toISOString(),
          candidates: [{ tag, score: adverse ? 1 : 9 }],
        });
        fixtures.push(fixture);
        outcomes.push(outcomeFixture(
          fixture,
          adverse
            ? { field_regression_72h: true, security_30d: true }
            : {},
        ));
      }
      return evaluateFixtures({
        fixtures,
        outcomes,
        thresholds: {
          independent: 8,
          uniqueReleases: 8,
          recommended: 4,
          withheld: 4,
          adverse: 4,
          safe: 4,
        },
      });
    };
    const initial = build(8).currentStratum.opportunities
      .first_verified_after_3h.horizons.field_regression_72h
      .temporalBlocks;
    const appended = build(12).currentStratum.opportunities
      .first_verified_after_3h.horizons.field_regression_72h
      .temporalBlocks;

    assert.equal(initial.developmentClusterTarget, 4);
    assert.deepEqual(
      appended.development.clusterKeys,
      initial.development.clusterKeys,
    );
    assert.deepEqual(
      appended.holdout.clusterKeys.slice(0, initial.holdout.clusterKeys.length),
      initial.holdout.clusterKeys,
    );
  });

  it('keeps scores ordinal and does not claim arbitrary probability calibration', () => {
    const scores = [9, 8, 7, 3, 2, 1];
    const adverse = [false, true, false, true, false, true];
    const fixtures = scores.map((score, index) => forecastFixture({
      decisionId: `calibration-${index}`,
      latestTag: `v2026.${index + 1}.1`,
      recordedAt: new Date(
        Date.parse('2026-01-01T00:00:00.000Z') + index * 45 * DAY_MS,
      ).toISOString(),
      candidates: [{ tag: `v2026.${index + 1}.1`, score }],
    }));
    const outcomes = fixtures.map((fixture, index) => outcomeFixture(
      fixture,
      adverse[index]
        ? { field_regression_72h: true, security_30d: true }
        : {},
    ));
    const report = evaluateFixtures({
      fixtures,
      outcomes,
      thresholds: {
        independent: 6,
        recommended: 6,
        withheld: 0,
        adverse: 3,
        safe: 3,
      },
    });
    const scoreAnalysis =
      report.candidateScoreQuality.combined.scoreAnalysis;
    assert.match(scoreAnalysis.interpretation, /Scores are ordinal/);
    assert.equal(scoreAnalysis.calibration, undefined);
    assert.equal(
      typeof report.candidateScoreQuality.combined.clusterAwareUncertainty
        .metrics.safeVsAdverseAuc.lower,
      'number',
    );

    const edgeFixture = forecastFixture({
      decisionId: 'calibration-edge',
      latestTag: 'v2026.10.1',
      candidates: [{ tag: 'v2026.10.1', score: 0 }],
    });
    const edgeReport = evaluateFixtures({
      fixtures: [edgeFixture],
      outcomes: [outcomeFixture(edgeFixture)],
      thresholds: {
        independent: 0,
        recommended: 0,
        withheld: 0,
        adverse: 0,
        safe: 0,
      },
    });
    assert.equal(
      edgeReport.candidateScoreQuality.combined.scoreAnalysis.calibration,
      undefined,
    );
  });

  it('retains a later adverse older-release selection beside its native forecast', () => {
    const native = forecastFixture({
      decisionId: 'native-v1',
      latestTag: 'v1',
      selectedTag: 'v1',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-01-01T03:00:00.000Z',
    });
    const selectedOlder = forecastFixture({
      decisionId: 'selected-v1-later',
      latestTag: 'v2',
      selectedTag: 'v1',
      opportunityCode: 'first_verified_after_24h',
      recordedAt: '2026-01-02T00:00:00.000Z',
      candidates: [
        { tag: 'v2', score: 7 },
        { tag: 'v1', score: 9 },
      ],
    });
    const outcomes = [
      outcomeFixture(native),
      outcomeFixture(selectedOlder, { field_regression_72h: true }),
    ];
    const report = evaluateFixtures({
      fixtures: [native, selectedOlder],
      outcomes,
      currentModelVersion: 'model-current',
      thresholds: { independent: 1, recommended: 1, withheld: 0, adverse: 0, safe: 1 },
    });
    assert.equal(report.eligibleForecastCount, 2);
    assert.equal(report.decisionLevelForecastCount, 2);
    assert.deepEqual(
      report.combined.cases.map((item: any) => item.decisionId).sort(),
      ['native-v1', 'selected-v1-later'],
    );
    assert.equal(
      report.combined.cases.find((item: any) =>
        item.decisionId === 'selected-v1-later').adverse,
      true,
    );
  });

  it('retains overlapping decisions and reports a non-overlapping sensitivity', () => {
    const first = forecastFixture({
      decisionId: 'overlap-1',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const second = forecastFixture({
      decisionId: 'overlap-2',
      latestTag: 'v2',
      recordedAt: '2026-01-02T00:00:00.000Z',
    });
    const report = evaluateFixtures({
      fixtures: [first, second],
      outcomes: [outcomeFixture(first), outcomeFixture(second)],
      thresholds: { independent: 2, recommended: 2, withheld: 0, adverse: 0, safe: 2 },
    });
    assert.equal(report.combined.candidateCaseCount, 2);
    assert.equal(report.combined.independentSampleCount, 2);
    assert.equal(report.combined.overlapExcludedCount, 1);
    assert.equal(report.combined.nonOverlappingSensitivity.independentSampleCount, 1);
    assert.equal(report.status, 'insufficient');
    assert.equal(report.currentStratum.combined.sampleSufficiency.status, 'sufficient');
    assert.equal(report.currentStratum.combined.gateAnalysis.status, 'insufficient');
    assert.equal(
      report.currentStratum.combined.qualityAssessment.checks
        .safeVsAdverseAucLowerBound.observed,
      null,
    );
    assert.equal(
      report.currentStratum.combined.qualityAssessment.checks
        .safeVsAdverseAucLowerBound.passed,
      false,
    );
  });

  it('fails the AUC criterion when sufficient samples contain only one outcome class', () => {
    const first = forecastFixture({
      decisionId: 'auc-unavailable-1',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const second = forecastFixture({
      decisionId: 'auc-unavailable-2',
      latestTag: 'v2',
      recordedAt: '2026-02-15T00:00:00.000Z',
    });
    const report = evaluateFixtures({
      fixtures: [first, second],
      outcomes: [outcomeFixture(first), outcomeFixture(second)],
      thresholds: {
        independent: 2,
        recommended: 2,
        withheld: 0,
        adverse: 0,
        safe: 2,
      },
    });
    const combined = report.currentStratum.combined;
    assert.equal(combined.sampleSufficiency.status, 'sufficient');
    assert.equal(combined.scoreAnalysis.discrimination.safeVsAdverseAuc, null);
    assert.equal(
      combined.clusterAwareUncertainty.metrics.safeVsAdverseAuc,
      null,
    );
    assert.equal(
      combined.qualityAssessment.checks.safeVsAdverseAucLowerBound.applicable,
      true,
    );
    assert.equal(
      combined.qualityAssessment.checks.safeVsAdverseAucLowerBound.passed,
      false,
    );
    assert.equal(combined.qualityAssessment.status, 'failed');
    assert.equal(report.status, 'measurable_but_failed');
  });

  it('computes current-stratum independence before older-model overlap exclusion', () => {
    const older = forecastFixture({
      decisionId: 'older-overlap',
      latestTag: 'v1',
      modelVersion: 'older-model',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const current = forecastFixture({
      decisionId: 'current-overlap',
      latestTag: 'v2',
      modelVersion: 'current-model',
      recordedAt: '2026-01-02T00:00:00.000Z',
    });
    const report = evaluateFixtures({
      fixtures: [older, current],
      outcomes: [outcomeFixture(older), outcomeFixture(current)],
      currentModelVersion: 'current-model',
      thresholds: { independent: 1, recommended: 1, withheld: 0, adverse: 0, safe: 1 },
    });

    assert.equal(report.status, 'insufficient');
    assert.equal(report.combined.independentSampleCount, 2);
    assert.equal(report.combined.cases[0].decisionId, 'older-overlap');
    assert.equal(report.currentStratum.status, 'insufficient');
    assert.equal(report.currentStratum.combined.independentSampleCount, 1);
    assert.equal(report.currentStratum.combined.cases[0].decisionId, 'current-overlap');
  });

  it('rejects tampered prediction and exact audit fields in matured outcomes', () => {
    const fixture = forecastFixture({ decisionId: 'tamper', latestTag: 'v1' });
    const outcomes = outcomeFixture(fixture, { field_regression_72h: true });
    const predictionTampered = structuredClone(outcomes.observations);
    const predictionPayload = JSON.parse(predictionTampered[0].outcome_json);
    predictionPayload.prediction.targetReleaseScore = 1;
    predictionTampered[0].outcome_json = JSON.stringify(predictionPayload);
    let report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: predictionTampered,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(report.errors.join('\n'), /prediction_mismatch/);

    const auditTampered = structuredClone(outcomes.observations);
    const auditPayload = JSON.parse(auditTampered[0].outcome_json);
    auditPayload.auditEvidence.promptVersion += 1;
    auditPayload.candidateOutcomes[0].auditEvidence.promptVersion += 1;
    auditTampered[0].outcome_json = JSON.stringify(auditPayload);
    report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: auditTampered,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(
      report.errors.join('\n'),
      /candidate_audit_history_evidence_mismatch|audit_history_evidence_mismatch/,
    );

    const fieldTampered = structuredClone(outcomes.observations);
    const fieldPayload = JSON.parse(fieldTampered[0].outcome_json);
    fieldPayload.fieldRegression.evidenceRefs[0].versionLink.version = 'v-other';
    fieldPayload.candidateOutcomes[0].fieldRegression.evidenceRefs[0]
      .versionLink.version = 'v-other';
    fieldTampered[0].outcome_json = JSON.stringify(fieldPayload);
    report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: fieldTampered,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(
      report.errors.join('\n'),
      /field_evidence_snapshot_provenance_mismatch|independent_field_evidence_content_mismatch/,
    );

    const fieldTimingTampered = structuredClone(outcomes.observations);
    const fieldTimingPayload = JSON.parse(fieldTimingTampered[0].outcome_json);
    fieldTimingPayload.fieldRegression.evidenceCompleteness.capturedAt =
      new Date(Date.parse(fieldTimingPayload.auditEvidence.recordedAt) - 1).toISOString();
    fieldTimingPayload.candidateOutcomes[0].fieldRegression
      .evidenceCompleteness.capturedAt =
        fieldTimingPayload.fieldRegression.evidenceCompleteness.capturedAt;
    fieldTimingTampered[0].outcome_json = JSON.stringify(fieldTimingPayload);
    report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: fieldTimingTampered,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(
      report.errors.join('\n'),
      /invalid_field_regression_payload|field_evidence_snapshot_provenance_mismatch/,
    );

    const universeTampered = structuredClone(outcomes.observations);
    const universePayload = JSON.parse(universeTampered[0].outcome_json);
    universePayload.fieldRegression.evidenceSnapshot.issueUniverse[0]
      .issueEvidenceIdentity = 'f'.repeat(64);
    universePayload.candidateOutcomes[0].fieldRegression.evidenceSnapshot
      .issueUniverse[0].issueEvidenceIdentity = 'f'.repeat(64);
    universeTampered[0].outcome_json = JSON.stringify(universePayload);
    report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: universeTampered,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(
      report.errors.join('\n'),
      /field_evidence_snapshot_provenance_mismatch/,
    );
  });

  it('rejects security outcomes whose immutable snapshot content is missing or tampered', () => {
    const fixture = forecastFixture({ decisionId: 'snapshot-tamper', latestTag: 'v1' });
    const outcomes = outcomeFixture(fixture, { security_30d: true });
    const missingAdvisory = structuredClone(outcomes.observations);
    const payload = JSON.parse(missingAdvisory[1].outcome_json);
    payload.adverse = false;
    payload.policyAction.adverse = false;
    payload.candidateOutcomes[0].adverse = false;
    payload.security.advisoryCount = 0;
    payload.security.advisories = [];
    payload.candidateOutcomes[0].security.advisoryCount = 0;
    payload.candidateOutcomes[0].security.advisories = [];
    missingAdvisory[1].outcome_json = JSON.stringify(payload);
    let report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: missingAdvisory,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(report.errors.join('\n'), /security_snapshot_content_mismatch/);

    const tamperedSnapshots = structuredClone(outcomes.snapshots);
    tamperedSnapshots[0].contentHash = 'tampered';
    report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      advisorySnapshots: tamperedSnapshots,
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(report.errors.join('\n'), /hash_mismatch|content_mismatch/);
  });

  it('rejects a persisted security outcome that skipped an earlier post-horizon snapshot', () => {
    const fixture = forecastFixture({
      decisionId: 'snapshot-prospective-order',
      latestTag: 'v1',
    });
    const outcomes = outcomeFixture(fixture, { security_30d: true });
    const referenced = outcomes.snapshots[0];
    const earlier = advisorySnapshot([], {
      snapshotId: referenced.snapshotId + 1,
      capturedAt: new Date(
        Date.parse(referenced.capturedAt) - 60_000,
      ).toISOString(),
    });
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      advisorySnapshots: [earlier, referenced],
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(report.errors.join('\n'), /security_snapshot_provenance_mismatch/);
  });

  it('fails a historical semantic incompatibility when a security outcome references it', () => {
    const fixture = forecastFixture({
      decisionId: 'referenced-legacy-semantic',
      latestTag: 'v2026.1.1',
    });
    const outcomes = outcomeFixture(fixture, { security_30d: true });
    const referenced = structuredClone(outcomes.snapshots[0]);
    referenced.rows[0].patched_versions = '>= 2026.1.1';
    referenced.contentHash = advisorySnapshotContentHash(referenced.rows);
    const securityAudit = outcomes.history.find((row) =>
      row.run_id.includes('security_30d'))!;
    const current = advisorySnapshot([], {
      snapshotId: referenced.snapshotId + 1,
      capturedAt: new Date(
        Date.parse(securityAudit.recorded_at) + DAY_MS,
      ).toISOString(),
    });
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      advisorySnapshots: [referenced, current],
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.deepEqual(
      report.advisorySnapshotSemantics.outcomeReferencedSnapshotIds,
      [referenced.snapshotId],
    );
    assert.equal(report.advisorySnapshotSemantics.semanticProblemCount, 1);
    assert.equal(report.advisorySnapshotSemantics.legacySemanticProblemCount, 0);
    assert.match(
      report.errors.join('\n'),
      /post_horizon_advisory_snapshot_row_malformed/,
    );
  });

  it('rejects multiple matured rows for one decision and horizon', () => {
    const fixture = forecastFixture({ decisionId: 'duplicate-matured', latestTag: 'v1' });
    const outcomes = outcomeFixture(fixture);
    const duplicate = structuredClone(outcomes.observations[0]);
    duplicate.observation_id = `${duplicate.observation_id}-duplicate`;
    duplicate.observed_at = new Date(Date.parse(duplicate.observed_at) + 60_000).toISOString();
    const payload = JSON.parse(duplicate.outcome_json);
    payload.observedAt = duplicate.observed_at;
    duplicate.outcome_json = JSON.stringify(payload);
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [outcomes],
      observations: [...outcomes.observations, duplicate],
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.match(report.errors.join('\n'), /Multiple matured outcomes/);
  });

  it('blocks validation when any retained decision misses grace', () => {
    const native = forecastFixture({
      decisionId: 'coverage-native',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const secondary = forecastFixture({
      decisionId: 'coverage-secondary',
      latestTag: 'v2',
      selectedTag: 'v1',
      opportunityCode: 'first_verified_after_3h',
      recordedAt: '2026-01-02T00:00:00.000Z',
      candidates: [
        { tag: 'v2', score: 7 },
        { tag: 'v1', score: 9 },
      ],
    });
    const nativeOutcomes = outcomeFixture(native);
    const report = evaluateFixtures({
      fixtures: [native, secondary],
      outcomes: [nativeOutcomes],
      observations: nativeOutcomes.observations,
      generatedAt: '2026-03-01T00:00:00.000Z',
      thresholds: { independent: 1, recommended: 1, withheld: 0, adverse: 0, safe: 1 },
    });
    assert.equal(report.outcomeCoverage.combined.terminalAttritionCount, 1);
    assert.equal(report.status, 'insufficient');
  });

  it('surfaces unresolved fatal indeterminate evidence as a fatal evaluation', () => {
    const fixture = forecastFixture({
      decisionId: 'fatal-indeterminate',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const fatalRow = indeterminateRow(
      fixture.forecast,
      'field_regression_72h',
      1,
      {
        reason: 'post_horizon_audit_payload_malformed',
        fatal: true,
        afterGrace: false,
      },
    );
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [],
      observations: [fatalRow],
      generatedAt: '2026-01-04T02:00:00.000Z',
      thresholds: { independent: 0, recommended: 0, withheld: 0, adverse: 0, safe: 0 },
    });
    assert.equal(report.status, 'measurable_but_failed');
    assert.equal(report.outcomeCoverage.combined.fatalIndeterminateCount, 1);
  });

  it('keeps nonfatal censored evidence in coverage instead of complete-case metrics', () => {
    const fixture = forecastFixture({
      decisionId: 'censored-coverage',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const censored = indeterminateRow(
      fixture.forecast,
      'field_regression_72h',
      1,
      {
        reason: 'independent_field_evidence_incomplete',
        fatal: false,
        afterGrace: false,
      },
    );
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [],
      observations: [censored],
      generatedAt: '2026-01-04T02:00:00.000Z',
      thresholds: {
        independent: 0,
        uniqueReleases: 0,
        recommended: 0,
        withheld: 0,
        adverse: 0,
        safe: 0,
      },
    });
    assert.equal(
      report.outcomeCoverage.horizons.field_regression_72h.indeterminateCount,
      1,
    );
    assert.equal(report.outcomeCoverage.combined.completeCaseCount, 0);
    assert.equal(report.outcomeCoverage.combined.indeterminateCount, 1);
    assert.equal(report.combined.independentSampleCount, 0);
    assert.equal(report.status, 'insufficient');
    assert.equal(report.failureClass, 'outcome_censoring');
  });

  it('persists and reports grace-missed attrition instead of hiding complete-case loss', () => {
    const complete = forecastFixture({
      decisionId: 'complete',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const missed = forecastFixture({
      decisionId: 'missed',
      latestTag: 'v2',
      recordedAt: '2026-02-02T00:00:00.000Z',
    });
    const completeOutcomes = outcomeFixture(complete);
    const indeterminateRows = (
      ['field_regression_72h', 'security_30d'] as ReleaseValidationHorizonCode[]
    ).map((horizonCode, index) => indeterminateRow(missed.forecast, horizonCode, index + 1));
    const report = evaluateFixtures({
      fixtures: [complete, missed],
      outcomes: [completeOutcomes],
      observations: [...completeOutcomes.observations, ...indeterminateRows],
      generatedAt: '2026-04-01T00:00:00.000Z',
      thresholds: { independent: 1, recommended: 1, withheld: 0, adverse: 0, safe: 1 },
    });

    assert.equal(report.status, 'insufficient');
    assert.equal(report.outcomeCoverage.combined.completeCaseCount, 1);
    assert.equal(report.outcomeCoverage.combined.terminalAttritionCount, 1);
    assert.equal(report.outcomeCoverage.horizons.field_regression_72h.persistedGraceMissedCount, 1);
    assert.equal(report.outcomeCoverage.horizons.security_30d.persistedGraceMissedCount, 1);
  });

  it('reports unrecorded grace expiry as terminal attrition', () => {
    const fixture = forecastFixture({
      decisionId: 'unrecorded-miss',
      latestTag: 'v1',
      recordedAt: '2026-01-01T00:00:00.000Z',
    });
    const report = evaluateFixtures({
      fixtures: [fixture],
      outcomes: [],
      generatedAt: '2026-03-01T00:00:00.000Z',
      thresholds: { independent: 0, recommended: 0, withheld: 0, adverse: 0, safe: 0 },
    });
    assert.equal(report.status, 'insufficient');
    assert.equal(report.outcomeCoverage.combined.terminalAttritionCount, 1);
    assert.equal(
      report.outcomeCoverage.horizons.field_regression_72h.indeterminateByReason[0].reason,
      'grace_expired_without_matured_outcome',
    );
  });

  it('keeps validation scripts bound to immutable snapshots and current versions', () => {
    const root = join(import.meta.dirname, '..', '..');
    const observeScript = readFileSync(
      join(root, 'scripts/validation/observe-outcomes.mjs'),
      'utf8',
    );
    const evaluateScript = readFileSync(
      join(root, 'scripts/validation/evaluate-score-quality.mjs'),
      'utf8',
    );
    assert.match(observeScript, /buildReleaseValidationIndeterminatePayload/);
    assert.match(observeScript, /status: 'indeterminate'/);
    assert.match(observeScript, /releaseValidationForecastTiming/);
    assert.match(observeScript, /status: 'excluded'/);
    assert.match(observeScript, /excludedForecastCount/);
    assert.ok(
      observeScript.indexOf('if (!timing.valid)') <
      observeScript.indexOf('const horizonEndAt'),
      'timing-invalid forecasts must be excluded before observation assessment',
    );
    assert.match(observeScript, /stageReleaseValidationOutcomeRows/);
    assert.match(observeScript, /stageReleaseValidationObservationBatchReceipt/);
    assert.match(observeScript, /commitReleaseValidationObservationBatch/);
    assert.match(evaluateScript, /listAuthorizedReleaseValidationAdvisorySnapshots/);
    assert.doesNotMatch(evaluateScript, /listAdvisorySnapshotRows/);
    assert.match(evaluateScript, /currentModelVersion: SCORE_MODEL_VERSION/);
    assert.match(evaluateScript, /currentPromptVersion: PROMPT_VERSION/);
    assert.match(evaluateScript, /measurable_but_failed/);
    assert.match(observeScript, /validateReleaseValidationLedgerIntegrity/);
    assert.match(evaluateScript, /validateReleaseValidationLedgerIntegrity/);
    assert.match(observeScript, /release_score_audit_history_runs/);
    assert.match(evaluateScript, /release_score_audit_history_runs/);
    assert.match(observeScript, /scorePersistence\?\.persistedAt/);
    assert.match(observeScript, /releaseValidationObservationTargets\(forecast\)/);
    assert.match(
      observeScript,
      /observationTargets\.map\(\(target\) =>\s+buildIndependentFieldEvidenceSnapshot\(\{/,
    );
    assert.match(
      observeScript,
      /fieldEvidenceCapturedAtMs >= Date\.parse\(horizonEndAt\)/,
    );
    assert.match(
      observeScript,
      /fieldEvidenceCapturedAtMs <= Date\.parse\(observedAt\)/,
    );
    assert.match(observeScript, /capturedAt: fieldEvidenceCapturedAt/);
    assert.doesNotMatch(observeScript, /capturedAt: observedAt/);
  });

  it('computes Wilson intervals without normal approximations at the boundaries', () => {
    assert.deepEqual(wilsonInterval(0, 10), {
      estimate: 0,
      lower: 0,
      upper: 0.2775,
      confidence: 0.95,
      method: 'wilson',
    });
    assert.equal(wilsonInterval(0, 0), null);
    assert.equal(releaseValidationEvaluationExitCode('validated'), 0);
    assert.equal(releaseValidationEvaluationExitCode('insufficient'), 2);
    assert.equal(releaseValidationEvaluationExitCode('measurable_but_failed'), 1);
  });
});

function pointInTimeFilterFixture() {
  const cutoff = '2026-07-01T00:00:00.000Z';
  const before = '2026-06-30T23:59:59.999Z';
  const after = '2026-07-01T00:00:00.001Z';
  const pair = (field: string) => [
    { marker: 'before', [field]: before },
    { marker: 'after', [field]: after },
  ];
  const canonicalProof = {
    epochs: [
      {
        marker: 'before',
        proofEpochId: 'epoch-before',
        recordedAt: before,
        startsAt: after,
      },
      {
        marker: 'after',
        proofEpochId: 'epoch-after',
        recordedAt: after,
        startsAt: before,
      },
    ],
    retirements: [
      {
        marker: 'before',
        retirementId: 'retirement-before',
        recordedAt: before,
        retiredAt: after,
      },
      {
        marker: 'after',
        retirementId: 'retirement-after',
        recordedAt: after,
        retiredAt: before,
      },
    ],
    policies: [
      {
        marker: 'before',
        policyId: 'policy-before',
        recordedAt: before,
        effectiveAt: after,
      },
      {
        marker: 'after',
        policyId: 'policy-after',
        recordedAt: after,
        effectiveAt: before,
      },
    ],
    cohorts: [
      {
        marker: 'before',
        cohortId: 'cohort-before',
        recordedAt: before,
        startsAt: after,
      },
      {
        marker: 'after',
        cohortId: 'cohort-after',
        recordedAt: after,
        startsAt: before,
      },
    ],
    catalogObservations: [
      {
        marker: 'before',
        observationId: 'catalog-before',
        observedAt: before,
      },
      {
        marker: 'after',
        observationId: 'catalog-after',
        observedAt: after,
      },
    ],
    catalogMembers: [
      {
        marker: 'before',
        memberId: 'member-before',
        observationId: 'catalog-before',
      },
      {
        marker: 'after',
        memberId: 'member-after',
        observationId: 'catalog-after',
      },
    ],
    catalogReconciliations: [
      {
        marker: 'before',
        reconciliationId: 'reconciliation-before',
        reconciledAt: before,
      },
      {
        marker: 'after',
        reconciliationId: 'reconciliation-after',
        reconciledAt: after,
      },
    ],
    catalogReconciliationRows: [
      {
        marker: 'before',
        reconciliationRowId: 'row-before',
        reconciliationId: 'reconciliation-before',
      },
      {
        marker: 'after',
        reconciliationRowId: 'row-after',
        reconciliationId: 'reconciliation-after',
      },
    ],
    obligations: pair('recordedAt'),
    splitAssignments: pair('assignedAt'),
    forecasts: pair('recordedAt'),
    outcomes: pair('observedAt'),
    observationBatches: pair('observedAt'),
    evaluationReceipts: pair('evaluatedAt'),
    promotionReceipts: pair('promotedAt'),
  };
  return {
    cutoff,
    source: {
      advisorySnapshots: [
        {
          marker: 'before',
          schemaVersion: 2,
          capturedAt: before,
          provenance: { publication: { finishedAt: before } },
        },
        {
          marker: 'after',
          schemaVersion: 2,
          capturedAt: before,
          provenance: { publication: { finishedAt: after } },
        },
      ],
      forecasts: pair('recorded_at'),
      observations: pair('observed_at'),
      observationBatches: pair('observed_at'),
      enrollments: pair('enrolled_at'),
      attempts: pair('started_at'),
      stageEvents: pair('occurred_at'),
      receipts: pair('finished_at'),
      leases: pair('acquired_at'),
      auditHistory: pair('recorded_at'),
      auditHistoryRuns: pair('recorded_at'),
      authorityRuns: pair('recordedAt'),
      historyV2Seals: pair('sealedAt'),
      canonicalProof,
    },
  };
}

function scoreReplayForecastFixture(
  ledgerTime: string,
  scoredAt: string,
): {
  forecast: ReleaseValidationForecastLedgerRow;
  history: ReleaseScoreAuditHistoryEvidenceRow[];
} {
  const fixture = forecastFixture({
    decisionId: 'score-replay-time',
    latestTag: 'v-score-replay-time',
    recordedAt: '2026-06-02T00:00:00.000Z',
  });
  const input: InstallInput = {
    schemaVersion: 2,
    publishedAt: '2026-06-01T00:00:00.000Z',
    isLatest: true,
    hoursToNextStable: null,
    hasHotfixSuccessor: false,
    betaCount: 0,
    breakingCount: 0,
    feltOpenedWeight: 0,
    feltClosedWeight: 0,
    verifiedDebtWeight: 0,
    carryoverDebtWeight: 0,
    staleDebtWeight: 0,
    unresolvedClosureRiskWeight: 0,
    affirmativeClosureRiskCeilingWeight: 0,
    rawIssueCount: 0,
    classifiedIssueCount: 0,
    cveAffected: false,
    cveLoad: 0,
  };
  const confidence = installConfidence(input, Date.parse(ledgerTime));
  const ledger = buildScoreLedgerV2({
    input,
    confidence,
    now: Date.parse(ledgerTime),
  });
  const history = structuredClone(fixture.history);
  Object.assign(history[0], {
    scored_at: scoredAt,
    final_score: confidence.score,
    status: confidence.status,
    band: confidence.band,
    recommended: 1,
    input_json: JSON.stringify(input),
    components_json: JSON.stringify({
      schemaVersion: 1,
      explanation: { scoreLedger: ledger },
    }),
  });
  const decision = JSON.parse(fixture.forecast.decision_json);
  decision.schemaVersion = 1;
  const candidates = JSON.parse(fixture.forecast.candidate_scores_json);
  candidates[0].scoreSnapshot = {
    scoredAt,
    finalScore: confidence.score,
    status: confidence.status,
    band: confidence.band,
    recommended: true,
  };
  candidates[0].auditSnapshot = history[0];
  return {
    forecast: {
      ...fixture.forecast,
      decision_json: JSON.stringify(decision),
      candidate_scores_json: JSON.stringify(candidates),
    },
    history,
  };
}

function integrityFixture(): {
  forecasts: ReleaseValidationForecastLedgerRow[];
  observations: ReleaseValidationOutcomeLedgerRow[];
  auditHistory: ReleaseScoreAuditHistoryEvidenceRow[];
  auditHistoryRuns: ReleaseScoreAuditHistoryRunSealEvidenceRow[];
  authorityRuns: ReleaseScoreAuthorityRunEvidence[];
  historyV2Seals: ReleaseScoreAuditHistoryV2SealEvidence[];
  advisorySnapshots: AdvisorySnapshotValidationEvidence[];
} {
  const fixtures = [
    forecastFixture({
      decisionId: 'integrity-first',
      latestTag: 'v-integrity-first',
      selectedTag: 'v-integrity-first',
      recordedAt: '2026-01-01T00:00:00.000Z',
      candidates: [
        { tag: 'v-integrity-first', score: 8 },
        { tag: 'v-integrity-previous', score: 7 },
      ],
    }),
    forecastFixture({
      decisionId: 'integrity-second',
      latestTag: 'v-integrity-second',
      selectedTag: 'v-integrity-second',
      recordedAt: '2026-02-01T00:00:00.000Z',
    }),
  ];
  const auditHistory = fixtures.flatMap((fixture) => fixture.history);
  const authorityRuns: ReleaseScoreAuthorityRunEvidence[] = [];
  let previousAuthorityHash: string | null = null;
  for (const fixture of fixtures) {
    const sourceIdentity = JSON.parse(
      fixture.forecast.source_identity_json,
    ) as { schemaVersion: number; digest: string };
    const authorityRunId = fixture.history[0].authority_run_id!;
    const authorityRun = buildScoreAuthorityResolutionRun({
      authorityRunId,
      sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
      sourceIdentityDigest: sourceIdentity.digest,
      recordedAt: fixture.forecast.recorded_at,
      previousContentHash: previousAuthorityHash,
      rows: [],
    });
    authorityRuns.push(authorityRun);
    previousAuthorityHash = authorityRun.contentHash;
  }
  const auditHistoryRuns: ReleaseScoreAuditHistoryRunSealEvidenceRow[] = [];
  let previousRunHash: string | null = null;
  for (const [index, fixture] of fixtures.entries()) {
    const rows = fixture.history.slice().sort((left, right) =>
      left.release_tag.localeCompare(right.release_tag));
    const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(
      rows as unknown as Array<Record<string, unknown>>,
    );
    const run = {
      id: index + 1,
      run_id: fixture.forecast.audit_history_run_id,
      recorded_at: fixture.forecast.recorded_at,
      row_count: rows.length,
      rows_content_hash: rowsContentHash,
      previous_content_hash: previousRunHash,
      content_hash: '',
    };
    run.content_hash = releaseScoreAuditHistoryRunContentHash({
      runId: run.run_id,
      recordedAt: run.recorded_at,
      rowCount: run.row_count,
      rowsContentHash: run.rows_content_hash,
      previousContentHash: run.previous_content_hash,
    });
    auditHistoryRuns.push(run);
    previousRunHash = run.content_hash;
  }
  const historyV2Seals: ReleaseScoreAuditHistoryV2SealEvidence[] = [];
  let previousHistoryV2Hash: string | null = null;
  for (const [index, historyRun] of auditHistoryRuns.entries()) {
    const authorityRun = authorityRuns[index];
    const seal = buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: historyRun.run_id,
      authorityRunId: authorityRun.authorityRunId,
      sealedAt: historyRun.recorded_at,
      historyRowCount: historyRun.row_count,
      historyRowsContentHash: historyRun.rows_content_hash,
      authorityRowCount: authorityRun.rowCount,
      authorityRowsContentHash: authorityRun.rowsContentHash,
      previousContentHash: previousHistoryV2Hash,
    });
    historyV2Seals.push(seal);
    previousHistoryV2Hash = seal.contentHash;
  }

  let previousForecastHash: string | null = null;
  const forecasts = fixtures.map((fixture, index) => {
    const row = structuredClone(fixture.forecast);
    const decision = JSON.parse(row.decision_json);
    decision.scoreCommit = {
      ...decision.scoreCommit,
      historyRunContentHash: auditHistoryRuns[index].content_hash,
      authorityRunId: authorityRuns[index].authorityRunId,
      authorityRunContentHash: authorityRuns[index].contentHash,
      historyV2SealContentHash: historyV2Seals[index].contentHash,
    };
    const candidates = JSON.parse(row.candidate_scores_json);
    for (const candidate of candidates) {
      candidate.auditSnapshot = fixture.history.find(
        (historyRow) => historyRow.release_tag === candidate.releaseTag,
      );
    }
    row.candidate_scores_json = JSON.stringify(candidates);
    row.decision_json = JSON.stringify(decision);
    row.id = index + 1;
    row.previous_content_hash = previousForecastHash;
    row.content_hash = releaseValidationForecastContentHash(row);
    row.decision_id = releaseValidationDecisionId(row, row.content_hash);
    previousForecastHash = row.content_hash;
    return row;
  });

  let previousOutcomeHash: string | null = null;
  const observations = forecasts.map((row, index) => {
    const outcome: ReleaseValidationOutcomeLedgerRow = {
      id: index + 1,
      observation_id: '',
      decision_id: row.decision_id,
      horizon_code: 'field_regression_72h',
      observed_at: new Date(Date.parse(row.recorded_at) + 72 * HOUR_MS).toISOString(),
      status: 'indeterminate',
      outcome_json: JSON.stringify({ schemaVersion: 1, reason: 'fixture' }),
      source_identity_json: JSON.stringify(SOURCE_NEW),
      previous_content_hash: previousOutcomeHash,
      content_hash: '',
    };
    outcome.observation_id = releaseValidationObservationId(outcome);
    outcome.content_hash = releaseValidationOutcomeContentHash(outcome);
    previousOutcomeHash = outcome.content_hash;
    return outcome;
  });

  return {
    forecasts,
    observations,
    auditHistory,
    auditHistoryRuns,
    authorityRuns,
    historyV2Seals,
    advisorySnapshots: [advisorySnapshot()],
  };
}

function authorityLedgerFixture() {
  const sourceIdentity = {
    schemaVersion: 2,
    digest: '1'.repeat(64),
  };
  const recordedAts = [
    '2026-01-01T00:00:00.000Z',
    '2026-02-01T00:00:00.000Z',
  ];
  const authorityRuns: ReturnType<
    typeof buildScoreAuthorityResolutionRun
  >[] = [];
  let previousAuthorityContentHash: string | null = null;
  for (const [index, recordedAt] of recordedAts.entries()) {
    const run = buildScoreAuthorityResolutionRun({
      authorityRunId: `score-authority:ledger-${index + 1}`,
      sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
      sourceIdentityDigest: sourceIdentity.digest,
      recordedAt,
      previousContentHash: previousAuthorityContentHash,
      rows: [],
    });
    authorityRuns.push(run);
    previousAuthorityContentHash = run.contentHash;
  }

  const auditHistory = recordedAts.map((recordedAt, index) => audit({
    id: index + 1,
    run_id: `history:ledger-${index + 1}`,
    recorded_at: recordedAt,
    release_tag: `v-ledger-${index + 1}`,
    scored_at: recordedAt,
    source_identity_json: JSON.stringify(sourceIdentity),
    authority_run_id: authorityRuns[index].authorityRunId,
  }));
  const auditHistoryRuns: ReleaseScoreAuditHistoryRunSealEvidenceRow[] = [];
  let previousHistoryContentHash: string | null = null;
  for (const [index, row] of auditHistory.entries()) {
    const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(
      [row] as unknown as Array<Record<string, unknown>>,
    );
    const run = {
      id: index + 1,
      run_id: row.run_id,
      recorded_at: row.recorded_at,
      row_count: 1,
      rows_content_hash: rowsContentHash,
      previous_content_hash: previousHistoryContentHash,
      content_hash: '',
    };
    run.content_hash = releaseScoreAuditHistoryRunContentHash({
      runId: run.run_id,
      recordedAt: run.recorded_at,
      rowCount: run.row_count,
      rowsContentHash: run.rows_content_hash,
      previousContentHash: run.previous_content_hash,
    });
    auditHistoryRuns.push(run);
    previousHistoryContentHash = run.content_hash;
  }

  const historyV2Seals: ReturnType<
    typeof buildReleaseScoreAuditHistoryV2Seal
  >[] = [];
  let previousHistoryV2ContentHash: string | null = null;
  for (const [index, historyRun] of auditHistoryRuns.entries()) {
    const authorityRun = authorityRuns[index];
    const seal = buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: historyRun.run_id,
      authorityRunId: authorityRun.authorityRunId,
      sealedAt: historyRun.recorded_at,
      historyRowCount: historyRun.row_count,
      historyRowsContentHash: historyRun.rows_content_hash,
      authorityRowCount: authorityRun.rowCount,
      authorityRowsContentHash: authorityRun.rowsContentHash,
      previousContentHash: previousHistoryV2ContentHash,
    });
    historyV2Seals.push(seal);
    previousHistoryV2ContentHash = seal.contentHash;
  }

  return {
    forecasts: [],
    observations: [],
    auditHistory,
    auditHistoryRuns,
    authorityRuns,
    historyV2Seals,
    advisorySnapshots: [advisorySnapshot()],
  };
}

function corruptValidationLedgerDb(
  name: string,
  corruption: 'forecast_hash' | 'forecast_chain' | 'run_seal',
): {
  dbPath: string;
  cleanup: () => void;
} {
  const dir = mkdtempSync(join(tmpdir(), `${name}-`));
  const dbPath = join(dir, 'radar.db');
  const root = join(import.meta.dirname, '..', '..');
  const setup = spawnSync(process.execPath, [
    '--import',
    'tsx',
    '--input-type=module',
    '--eval',
    `
    void (async () => {
      process.env.DB_PATH = ${JSON.stringify(dbPath)};
      const databaseModule = await import('./src/lib/db.ts');
      const database = databaseModule.default ?? databaseModule;
      const authorityModule = await import('./src/lib/scoreAuthorityResolution.ts');
      const authority = authorityModule.default ?? authorityModule;
      const recordedAt = '2099-01-02T00:00:00.000Z';
      const authorityRunId = 'score-authority:run-observe-refusal';
      database.upsertRelease({
        tag: 'v-observe-refusal',
        name: 'v-observe-refusal',
        published_at: '2099-01-01T00:00:00.000Z',
        html_url: 'https://example.test/v-observe-refusal',
        prerelease: false,
        body: '',
      });
      database.replaceActiveReleaseCatalog([{
        node_id: 'R_v-observe-refusal',
        catalog_tag_commit_oid: '${'1'.repeat(40)}',
        tag: 'v-observe-refusal',
        name: 'v-observe-refusal',
        published_at: '2099-01-01T00:00:00.000Z',
        created_at: '2099-01-01T00:00:00.000Z',
        updated_at: '2099-01-01T00:00:00.000Z',
        html_url: 'https://example.test/v-observe-refusal',
        prerelease: false,
        body: '',
      }], {
        capture: { source: 'test_fixture' },
      });
      const sourceIdentityValue = database.scoreSourceIdentity();
      const sourceIdentity = JSON.stringify(sourceIdentityValue);
      const authorityRun = authority.buildScoreAuthorityResolutionRun({
        authorityRunId,
        sourceIdentitySchemaVersion: sourceIdentityValue.schemaVersion,
        sourceIdentityDigest: sourceIdentityValue.digest,
        recordedAt,
        previousContentHash: null,
        rows: [],
      });
      database.insertScoreAuthorityResolutionRun(authorityRun);
      const audit = {
        release_tag: 'v-observe-refusal',
        scored_at: recordedAt,
        score_model_version: 'model-v1',
        prompt_version: 6,
        final_score: 8,
        status: 'eligible',
        band: 'good',
        recommended: 1,
        input_json: '{}',
        components_json: '{}',
        issue_evidence_json: '{}',
        gate_evidence_json: '{}',
        source_identity_json: sourceIdentity,
        authority_run_id: authorityRunId,
      };
      database.insertReleaseScoreAuditHistory('run-observe-refusal', recordedAt, audit);
      const seal = database.sealReleaseScoreAuditHistoryRun('run-observe-refusal', recordedAt);
      const historyV2Seal = database.sealReleaseScoreAuditHistoryV2({
        historyRunId: 'run-observe-refusal',
        authorityRunId,
        sealedAt: recordedAt,
      });
      const catalog = database.currentActiveReleaseCatalog();
      const recommendationDecision = {
        policyCode: 'highest_confidence_with_recency_tolerance',
        selectedTag: audit.release_tag,
      };
      database.insertReleaseValidationForecast({
        opportunity_code: 'first_verified_after_24h',
        recorded_at: recordedAt,
        latest_release_tag: audit.release_tag,
        latest_release_published_at: '2099-01-01T00:00:00.000Z',
        selected_tag: audit.release_tag,
        audit_history_run_id: 'run-observe-refusal',
        score_model_version: audit.score_model_version,
        prompt_version: audit.prompt_version,
        policy_code: recommendationDecision.policyCode,
        candidate_scores_json: JSON.stringify([{
          releaseTag: audit.release_tag,
          scoreSnapshot: {
            scoredAt: audit.scored_at,
            finalScore: audit.final_score,
            status: audit.status,
            band: audit.band,
            recommended: true,
          },
          auditSnapshot: {
            run_id: 'run-observe-refusal',
            recorded_at: recordedAt,
            ...audit,
          },
        }]),
        decision_json: JSON.stringify({
          schemaVersion: 4,
          opportunityCode: 'first_verified_after_24h',
          recordedAt,
          latestReleaseTag: audit.release_tag,
          latestReleasePublishedAt: '2099-01-01T00:00:00.000Z',
          latestReleaseAgeHours: 24,
          opportunityWindow: {
            minAgeHours: 24,
            maxAgeHours: 30,
            windowStartAt: '2099-01-02T00:00:00.000Z',
            windowEndAt: '2099-01-02T06:00:00.000Z',
            windowStartMs: Date.parse('2099-01-02T00:00:00.000Z'),
            windowEndMs: Date.parse('2099-01-02T06:00:00.000Z'),
            observedAtMs: Date.parse(recordedAt),
            observedAgeHours: 24,
            valid: true,
          },
          selectedTag: audit.release_tag,
          recommendationDecision,
          scoreCommit: {
            schemaVersion: 4,
            historyRunId: 'run-observe-refusal',
            historyRunContentHash: seal.row.content_hash,
            authorityRunId,
            authorityRunContentHash: authorityRun.contentHash,
            historyV2SealContentHash: historyV2Seal.row.contentHash,
            historyRecordedAt: recordedAt,
            commitNotBefore: recordedAt,
            commitNotAfter: recordedAt,
            commitNotBeforeMs: Date.parse(recordedAt),
            commitNotAfterMs: Date.parse(recordedAt),
          },
          catalogAttestation: {
            schemaVersion: 4,
            initialRemoteCatalog: {
              digest: '${'b'.repeat(64)}',
              totalCount: 1,
              nodeCount: 1,
              pageCount: 1,
              pagesFetched: 2,
              sweepCount: 2,
              exhausted: true,
              stabilized: true,
              sourceOrder: 'CREATED_AT_DESC',
            },
            finalRemoteCatalog: {
              digest: '${'b'.repeat(64)}',
              totalCount: 1,
              nodeCount: 1,
              pageCount: 1,
              pagesFetched: 2,
              sweepCount: 2,
              exhausted: true,
              stabilized: true,
              sourceOrder: 'CREATED_AT_DESC',
            },
            finalObservedAt: recordedAt,
            projectedActiveCatalog: {
              digest: catalog.digest,
              releaseCount: catalog.releaseCount,
            },
            localActiveCatalog: {
              digest: catalog.digest,
              releaseCount: catalog.releaseCount,
            },
            latestStable: catalog.latestStable,
            scoreBuiltAt: recordedAt,
          },
        }),
        source_identity_json: sourceIdentity,
        code_revision: 'observe-refusal-revision',
      });
      database.db.exec(${JSON.stringify({
        forecast_hash: `
          DROP TRIGGER release_validation_forecasts_no_update;
          UPDATE release_validation_forecasts
          SET candidate_scores_json=candidate_scores_json || ' ';
        `,
        forecast_chain: `
          DROP TRIGGER release_validation_forecasts_no_update;
          UPDATE release_validation_forecasts
          SET previous_content_hash='broken-chain';
        `,
        run_seal: `
          DROP TRIGGER release_score_audit_history_runs_no_update;
          UPDATE release_score_audit_history_runs
          SET content_hash='broken-seal';
        `,
      }[corruption])});
      database.db.close();
    })().catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
    `,
  ], {
    cwd: root,
    env: {
      ...process.env,
      DB_PATH: dbPath,
      RADAR_DB_BOOTSTRAP_MODE: 'fresh',
    },
    encoding: 'utf8',
  });
  assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);
  return {
    dbPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function legacyLateValidationForecastDb(name: string): {
  dbPath: string;
  cleanup: () => void;
} {
  const dir = mkdtempSync(join(tmpdir(), `${name}-`));
  const dbPath = join(dir, 'radar.db');
  const root = join(import.meta.dirname, '..', '..');
  const setup = spawnSync(process.execPath, [
    '--import',
    'tsx',
    '--input-type=module',
    '--eval',
    `
    void (async () => {
      process.env.DB_PATH = ${JSON.stringify(dbPath)};
      const databaseModule = await import('./src/lib/db.ts');
      const database = databaseModule.default ?? databaseModule;
      const validationModule = await import('./src/lib/releaseValidation.ts');
      const validation = validationModule.default ?? validationModule;
      const recordedAt = '2026-01-02T01:00:00.000Z';
      const publishedAt = '2026-01-01T00:00:00.000Z';
      database.replaceActiveReleaseCatalog([{
        node_id: 'R_v2026_1_1',
        catalog_tag_commit_oid: '${'1'.repeat(40)}',
        tag: 'v2026.1.1',
        name: 'v2026.1.1',
        published_at: publishedAt,
        created_at: publishedAt,
        updated_at: publishedAt,
        html_url: 'https://example.test/v2026.1.1',
        prerelease: false,
        body: '',
      }], {
        capture: { source: 'test_fixture' },
      });
      const sourceIdentityJson = JSON.stringify({
        schemaVersion: 2,
        digest: '${'b'.repeat(64)}',
      });
      const runId = 'run-legacy-late-observe';
      const audit = {
        release_tag: 'v2026.1.1',
        scored_at: recordedAt,
        score_model_version: 'model-v1',
        prompt_version: 6,
        final_score: 8,
        status: 'eligible',
        band: 'good',
        recommended: 1,
        input_json: '{}',
        components_json: '{}',
        issue_evidence_json: '{}',
        gate_evidence_json: '{}',
        source_identity_json: sourceIdentityJson,
        authority_run_id: null,
      };
      database.insertReleaseScoreAuditHistory(runId, recordedAt, audit);
      database.sealReleaseScoreAuditHistoryRun(runId, recordedAt);
      const recommendationDecision = {
        policyCode: 'highest_confidence_with_recency_tolerance',
        selectedTag: audit.release_tag,
      };
      const candidateScoresJson = JSON.stringify([{
        releaseTag: audit.release_tag,
        releasePublishedAt: publishedAt,
        scoreSnapshot: {
          scoredAt: audit.scored_at,
          finalScore: audit.final_score,
          status: audit.status,
          band: audit.band,
          recommended: true,
        },
        recommendationDecision,
        auditSnapshot: {
          run_id: runId,
          recorded_at: recordedAt,
          ...audit,
        },
      }]);
      const decisionJson = JSON.stringify({
        schemaVersion: 2,
        opportunityCode: 'first_verified_after_3h',
        recordedAt,
        latestReleaseTag: audit.release_tag,
        latestReleasePublishedAt: publishedAt,
        selectedTag: audit.release_tag,
        recommendationDecision,
      });
      const forecast = {
        id: 1,
        decision_id: '',
        opportunity_code: 'first_verified_after_3h',
        recorded_at: recordedAt,
        latest_release_tag: audit.release_tag,
        latest_release_published_at: publishedAt,
        selected_tag: audit.release_tag,
        audit_history_run_id: runId,
        score_model_version: audit.score_model_version,
        prompt_version: audit.prompt_version,
        policy_code: recommendationDecision.policyCode,
        candidate_scores_json: candidateScoresJson,
        decision_json: decisionJson,
        source_identity_json: sourceIdentityJson,
        code_revision: null,
        previous_content_hash: null,
        content_hash: '',
      };
      forecast.content_hash = validation.releaseValidationForecastContentHash(forecast);
      forecast.decision_id = validation.releaseValidationDecisionId(
        forecast,
        forecast.content_hash,
      );
      database.db.prepare(\`
        INSERT INTO release_validation_forecasts (
          id, decision_id, opportunity_code, recorded_at, latest_release_tag,
          latest_release_published_at, selected_tag, audit_history_run_id,
          score_model_version, prompt_version, policy_code, candidate_scores_json,
          decision_json, source_identity_json, code_revision, previous_content_hash,
          content_hash
        )
        VALUES (
          :id, :decision_id, :opportunity_code, :recorded_at, :latest_release_tag,
          :latest_release_published_at, :selected_tag, :audit_history_run_id,
          :score_model_version, :prompt_version, :policy_code, :candidate_scores_json,
          :decision_json, :source_identity_json, :code_revision, :previous_content_hash,
          :content_hash
        )
      \`).run(forecast);
      database.db.close();
    })().catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
    `,
  ], {
    cwd: root,
    env: {
      ...process.env,
      DB_PATH: dbPath,
      RADAR_DB_BOOTSTRAP_MODE: 'fresh',
    },
    encoding: 'utf8',
  });
  assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);
  return {
    dbPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function fieldIssue(
  number: number,
  createdAt: string,
  duplicateCluster: string,
  severity = 'high',
  affectsVersion?: string,
) {
  return {
    duplicateCluster,
    fieldConfirmed: true,
    issue: {
      number,
      createdAt,
      state: 'closed',
      affectsVersion,
      classification: { severity, functionality: 'core' },
    },
  };
}

function fieldAudit(
  opened: object[],
  overrides: Partial<ReleaseScoreAuditHistoryEvidenceRow> = {},
) {
  return audit({
    recorded_at: '2026-01-05T00:00:00.000Z',
    scored_at: '2026-01-05T00:00:00.000Z',
    issue_evidence_json: JSON.stringify({
      evidenceCounts: {
        verifiedDebt: 0,
        openedFeltSerious: opened.length,
      },
      verifiedDebt: [],
      openedFeltSerious: opened,
      unclassifiedIssues: [],
    }),
    ...overrides,
  });
}

function candidateScore(row: ReleaseValidationForecastLedgerRow, tag: string): number | null {
  const candidate = JSON.parse(row.candidate_scores_json)
    .find((item: any) => item.releaseTag === tag || item.tag === tag);
  return candidate?.scoreSnapshot?.finalScore ?? null;
}

function stableNumber(value: string): number {
  let hash = 0;
  for (const character of value) hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  return hash || 1;
}

function indeterminateRow(
  row: ReleaseValidationForecastLedgerRow,
  horizonCode: ReleaseValidationHorizonCode,
  id: number,
  options: {
    reason?: string;
    fatal?: boolean;
    afterGrace?: boolean;
  } = {},
): ReleaseValidationOutcomeLedgerRow {
  const durationMs = horizonCode === 'field_regression_72h' ? 72 * HOUR_MS : 30 * DAY_MS;
  const graceMs = horizonCode === 'field_regression_72h' ? DAY_MS : 7 * DAY_MS;
  const windowEndAt = new Date(Date.parse(row.recorded_at) + durationMs).toISOString();
  const afterGrace = options.afterGrace ?? true;
  const observedAt = new Date(
    Date.parse(windowEndAt) + (afterGrace ? graceMs + 1 : HOUR_MS),
  ).toISOString();
  const reason = options.reason ?? 'observation_grace_window_missed';
  const assessment = {
    status: 'indeterminate' as const,
    fatal: options.fatal ?? false,
    horizonCode,
    targetReleaseTag: row.selected_tag ?? row.latest_release_tag,
    windowStartAt: row.recorded_at,
    windowEndAt,
    reason,
    details: {
      latestObservationAt: new Date(Date.parse(windowEndAt) + graceMs).toISOString(),
      observedAt,
    },
  };
  return {
    id,
    observation_id: `${row.decision_id}-${horizonCode}-indeterminate`,
    decision_id: row.decision_id,
    horizon_code: horizonCode,
    observed_at: observedAt,
    status: 'indeterminate',
    outcome_json: JSON.stringify(buildReleaseValidationIndeterminatePayload({
      forecast: row,
      assessment,
      observedAt,
    })),
    source_identity_json: JSON.stringify(SOURCE_NEW),
    content_hash: `${row.decision_id}-${horizonCode}-indeterminate-hash`,
  };
}
