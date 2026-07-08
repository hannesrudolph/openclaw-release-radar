import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  buildDoctorReport,
  compoundAdvisorySnapshotSummary,
  currentActiveReleaseCatalogForDoctor,
  doctorHasStrictCreditedProof,
  verifyApiAgainstDb,
} from '../../scripts/doctor.mjs';
import { config } from '../config.ts';
import {
  ADVISORY_SNAPSHOT_META_KEY,
  ADVISORY_SNAPSHOT_V2_META_KEY,
  COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
  advisorySnapshotContentHash,
  advisoryRangeIdentityV2,
  advisoryVulnerabilityKey,
  buildCompoundAdvisorySnapshot,
  canonicalCompoundAdvisoryRangeRowJson,
  canonicalCompoundAdvisorySnapshotJson,
  compoundAdvisoryScoreRows,
  compoundAdvisorySnapshotLedgerContentHash,
  compoundAdvisorySnapshotRowContentHash,
} from './advisorySnapshot.ts';
import { repositoryAdvisoryCatalogContentDigest } from './advisoryCatalogDigest.ts';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from './scoreHistoryLedger.ts';
import {
  buildReleaseScoreAuditHistoryV2Seal,
  buildScoreAuthorityResolutionRun,
} from './scoreAuthorityResolution.ts';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
  type NormalizedIssueStateEvent,
} from './stateEventSnapshot.ts';
import {
  SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  scoreEffectiveScoringConfigDigest,
  scoreSourceIdentityManifestDigest,
} from './scoreSourceIdentity.ts';
import {
  releaseValidationDecisionId,
  releaseValidationForecastContentHash,
} from './releaseValidation.ts';
import {
  canonicalReleaseValidationProofJson,
  createReleaseValidationStableReleaseIdentity,
  releaseValidationCohortCellKey,
  releaseValidationSplitSeedHash,
  sealReleaseValidationCatalogObservation,
  sealReleaseValidationCatalogReconciliation,
  sealReleaseValidationCohort,
  sealReleaseValidationEvaluationReceipt,
  sealReleaseValidationForecastV2,
  sealReleaseValidationObservationBatch,
  sealReleaseValidationObligation,
  sealReleaseValidationOutcomeV2,
  sealReleaseValidationPolicy,
  sealReleaseValidationPromotionReceipt,
  sealReleaseValidationProofEpoch,
  sealReleaseValidationSplitAssignment,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';
import { CLOSURE_PROOF_ANALYZER_VERSION } from './analysisVersions.ts';
import {
  canonicalJson as canonicalOperationJson,
  operationAttemptConfigHash,
  operationAttemptContentHash,
  operationCaptureReceiptContentHash,
  operationStageEventContentHash,
} from './operationReceipts.ts';
import {
  canonicalIssueContentDigest,
  canonicalIssueMembershipDigest,
  stageIssueCatalogSnapshot,
} from './issueCatalogSnapshot.ts';
import {
  releaseCatalogCaptureReceiptContentHash,
  releaseCatalogCaptureReceiptId,
} from './releaseCatalogReceipt.ts';
import {
  assessDataFreshnessHealth,
  assessDurableIngestionEvidenceFailureHealth,
  assessIssueCrawlHealth,
} from '../../scripts/lib/doctor-health.mjs';
import {
  APPEND_ONLY_TRIGGER_SPECS,
  IMMUTABLE_LEDGER_TABLES,
} from '../../scripts/lib/database-schema-manifest.mjs';

function issueBaselineIdentity(baseline: {
  repository: string;
  sourceOrder: string;
  asOfBoundary: {
    totalCount: number;
    terminalIssue: {
      nodeId: string;
      issueNumber: number;
      createdAt: string;
    } | null;
    membershipDigest: string;
  };
}): string {
  return createHash('sha256')
    .update(JSON.stringify([
      baseline.repository,
      baseline.sourceOrder,
      baseline.asOfBoundary.totalCount,
      baseline.asOfBoundary.terminalIssue?.nodeId ?? null,
      baseline.asOfBoundary.terminalIssue?.issueNumber ?? null,
      baseline.asOfBoundary.terminalIssue?.createdAt ?? null,
      baseline.asOfBoundary.membershipDigest,
    ]))
    .digest('hex');
}

describe('doctor strict fix-credit proof validation', () => {
  it('accepts strict direct proof and rejects legacy or identity-mismatched variants', () => {
    const targetTag = 'v-target';
    const predecessorTag = 'v-predecessor';
    const valid = {
      proofIdentities: [{
        kind: 'direct_commit',
        strictValid: true,
        validationReasonCode: null,
        targetTag,
        predecessorTag,
        status: 'credited',
        reasonCode: 'first_containing_direct_commit',
        creditEligible: true,
        target: {
          tag: targetTag,
          strictValid: true,
          status: 'reachable',
        },
        predecessor: {
          tag: predecessorTag,
          strictValid: true,
          status: 'not_reachable',
        },
        releaseAncestry: {
          tag: targetTag,
          strictValid: true,
          status: 'reachable',
        },
      }],
    };

    assert.equal(
      doctorHasStrictCreditedProof(valid, targetTag, predecessorTag),
      true,
    );
    assert.equal(
      doctorHasStrictCreditedProof({
        proofIdentities: [{
          kind: 'direct_commit',
          commitOid: 'a'.repeat(40),
          targetTag,
          predecessorTag,
        }],
      }, targetTag, predecessorTag),
      false,
    );

    for (const mutate of [
      (proof: any) => { proof.target.strictValid = false; },
      (proof: any) => { proof.predecessor.status = 'reachable'; },
      (proof: any) => { proof.releaseAncestry.tag = 'v-other'; },
      (proof: any) => { proof.validationReasonCode = 'reachability_evidence_invalid'; },
    ]) {
      const candidate = structuredClone(valid);
      mutate(candidate.proofIdentities[0]);
      assert.equal(
        doctorHasStrictCreditedProof(candidate, targetTag, predecessorTag),
        false,
      );
    }
  });
});

function doctorStateSnapshotIdentity(input: {
  repositoryNodeId?: string;
  issueNumber: number;
  issueNodeId: string;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  events: readonly NormalizedIssueStateEvent[];
}) {
  const repositoryNodeId =
    input.repositoryNodeId ?? 'REPO-node-openclaw';
  const issueNodeType = 'Issue' as const;
  const events = normalizeIssueStateEvents(input.events);
  const sweep = {
    repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId: input.issueNodeId,
    issueNodeType,
    issueState: input.issueState,
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: events.length,
    events,
  };
  const firstSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 1,
  });
  const secondSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 2,
  });
  const stabilization = issueStateEventStabilizationIdentity(
    firstSweep,
    secondSweep,
    2,
  );
  return {
    repositoryNodeId,
    issueNodeType,
    events,
    eventsDigest: issueStateEventsDigest(events, {
      repositoryNodeId,
      issueNodeId: input.issueNodeId,
      issueNodeType,
    }),
    authorityDigest: secondSweep.sweepDigest,
    stabilization,
  };
}

function issueCrawlBaselineFixture(overrides: Record<string, unknown> = {}) {
  const membershipDigest = 'a'.repeat(64);
  const baseline = {
    schemaVersion: 2,
    source: 'github.repository.issues',
    repository: 'openclaw/openclaw',
    sourceOrder: 'CREATED_AT_ASC',
    establishedAt: '2026-06-02T01:04:00Z',
    crawlStartedAt: '2026-06-02T00:55:00Z',
    boundaryTotalCount: 1,
    observedTotalCount: 1,
    postBoundaryGrowthCount: 0,
    asOfBoundary: {
      totalCount: 1,
      terminalIssue: {
        nodeId: 'ISSUE-node-1',
        issueNumber: 1,
        createdAt: '2026-06-01T00:00:00Z',
      },
      membershipDigest,
    },
    fetchedCount: 1,
    uniqueCount: 1,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    digest: membershipDigest,
    membershipDigest,
    contentDigest: 'b'.repeat(64),
    identity: '',
    ...overrides,
  };
  baseline.identity = typeof overrides.identity === 'string'
    ? overrides.identity
    : issueBaselineIdentity(baseline);
  return baseline;
}

function issueCrawlFixture(overrides: Record<string, unknown> = {}) {
  const baseline = (
    overrides.baseline &&
    typeof overrides.baseline === 'object' &&
    !Array.isArray(overrides.baseline)
  )
    ? overrides.baseline as ReturnType<typeof issueCrawlBaselineFixture>
    : issueCrawlBaselineFixture();
  const snapshotId = 'c'.repeat(64);
  const consumedAt = '2026-06-02T01:04:30Z';
  return {
    schemaVersion: 4,
    repository: baseline.repository,
    startedAt: '2026-06-02T00:55:00Z',
    finishedAt: '2026-06-02T01:05:00.000Z',
    fullIssueBackfill: true,
    crawlMode: 'exhaustive',
    backfillCompleteAtStart: false,
    backfillCompleteAfterRun: true,
    baseline,
    pagination: {
      schemaVersion: 2,
      source: 'github.repository.issues',
      repository: 'openclaw/openclaw',
      sourceOrder: 'CREATED_AT_ASC',
      completeness: 'exhaustive_stable',
      boundaryTotalCount: 1,
      observedTotalCount: 1,
      postBoundaryGrowthCount: 0,
      asOfBoundary: baseline.asOfBoundary,
      fetchedCount: 1,
      uniqueCount: 1,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      exhausted: true,
      stabilized: true,
      digest: baseline.digest,
      membershipDigest: baseline.membershipDigest,
      contentDigest: baseline.contentDigest,
      lastRequestCursor: null,
      nextCursor: null,
      hasNextPage: false,
    },
    catalogSnapshot: {
      schemaVersion: 1,
      snapshotId,
      contentHash: snapshotId,
      capturedAt: '2026-06-02T00:54:00Z',
      resumed: false,
      priorStatus: 'missing',
      maxAgeHours: 24,
      consumedAt,
      consumedByRunId: 'doctor-refresh-run',
      consumptionContentHash: 'd'.repeat(64),
    },
    catalogAttestation: {
      schemaVersion: 1,
      snapshotId,
      snapshotContentHash: snapshotId,
      observedAt: '2026-06-02T01:04:45Z',
      totalCount: baseline.boundaryTotalCount,
      membershipDigest: baseline.membershipDigest,
      contentDigest: baseline.contentDigest,
      finalSweepCount: 2,
      finalPagesFetched: 2,
    },
    stopReason: 'exhausted',
    evidenceRefreshFailures: [],
    classificationFailures: [],
    scorePersisted: true,
    scorePersistedAt: '2026-06-02T01:05:00.000Z',
    ...overrides,
  };
}

describe('doctor data freshness health', () => {
  const latest = { tag: 'v1', scoredAt: '2026-06-30T01:00:00.000Z' };

  it('warns when issue evidence is stale at scoring time or now', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-27T01:00:00.000Z',
      issueUpdatedAgeHoursAtScore: 72,
      issueUpdatedAgeHoursNow: 73,
      sourceFetchedAtMax: '2026-06-30T00:59:00.000Z',
      sources: [],
    }, latest, { maxIssueLagHours: 48 });

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /old at scoring time/.test(warning)));
    assert.ok(result.warnings.some((warning) => /old now/.test(warning)));
  });

  it('fails when source evidence changed after the latest score', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-30T00:59:00.000Z',
      issueUpdatedAgeHoursAtScore: 0.02,
      issueUpdatedAgeHoursNow: 0.03,
      sourceFetchedAtMax: '2026-06-30T01:05:00.000Z',
      sources: [
        { source: 'issues', maxAt: '2026-06-30T00:59:00.000Z' },
        { source: 'issue_pr_links', maxAt: '2026-06-30T01:05:00.000Z' },
      ],
    }, latest);

    assert.ok(result.failures.some((failure) => /source evidence changed after latest score/.test(failure)));
    assert.ok(result.failures.some((failure) => /issue_pr_links/.test(failure)));
  });

  it('fails when populated freshness sources have no timestamps', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-30T00:59:00.000Z',
      issueUpdatedAgeHoursAtScore: 0.02,
      issueUpdatedAgeHoursNow: 0.03,
      sourceFetchedAtMax: '2026-06-30T00:59:00.000Z',
      sources: [
        { source: 'issue_fetches', count: 10, maxAt: null },
        { source: 'release_rows', count: 3, maxAt: null },
      ],
    }, latest);

    assert.ok(result.failures.some((failure) => /issue_fetches freshness/.test(failure)));
    assert.ok(result.failures.some((failure) => /release_rows freshness/.test(failure)));
  });

  it('fails when a populated freshness source has partial null timestamps', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-30T00:59:00.000Z',
      issueUpdatedAgeHoursAtScore: 0.02,
      issueUpdatedAgeHoursNow: 0.03,
      sourceFetchedAtMax: '2026-06-30T00:59:00.000Z',
      sources: [
        { source: 'issue_pr_links', count: 10, nullCount: 2, maxAt: '2026-06-30T00:59:00.000Z' },
      ],
    }, latest);

    assert.ok(result.failures.some((failure) => /issue_pr_links freshness has 2 row/.test(failure)));
  });

  it('fails when freshness timestamps are malformed', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: 'not-a-score-date',
      issueUpdatedAtMax: 'not-an-issue-date',
      issueUpdatedAgeHoursAtScore: 0.02,
      issueUpdatedAgeHoursNow: 0.03,
      sourceFetchedAtMax: 'not-a-source-date',
      sources: [
        { source: 'closure_proofs', count: 1, nullCount: 0, maxAt: 'not-a-date' },
        { source: 'empty_source', count: 0, nullCount: 0, maxAt: 'also-not-a-date' },
      ],
    }, latest);

    assert.ok(result.failures.some((failure) => /scoredAt is not a valid timestamp/.test(failure)));
    assert.ok(result.failures.some((failure) => /sourceFetchedAtMax is not a valid timestamp/.test(failure)));
    assert.ok(result.failures.some((failure) => /issueUpdatedAtMax is not a valid timestamp/.test(failure)));
    assert.ok(result.failures.some((failure) => /closure_proofs freshness maxAt is not a valid timestamp/.test(failure)));
    assert.ok(!result.failures.some((failure) => /empty_source/.test(failure)));
  });

  it('fails when issue rows include updates after the latest score', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-30T01:05:00.000Z',
      issueUpdatedAgeHoursAtScore: -0.08,
      issueUpdatedAgeHoursNow: 0,
      sourceFetchedAtMax: '2026-06-30T00:59:00.000Z',
      sources: [],
    }, latest);

    assert.ok(result.failures.some((failure) => /issue data includes updates after latest score/.test(failure)));
  });
});

describe('doctor issue crawl health', () => {
  const latest = { tag: 'v1', scoredAt: '2026-06-30T01:00:00.000Z' };
  const baseline = issueCrawlBaselineFixture();

  it('does not warn when issue crawl metadata is absent before any score exists', () => {
    assert.deepEqual(assessIssueCrawlHealth(null, null), { warnings: [], failures: [] });
  });

  it('warns when a scored release has no issue crawl metadata', () => {
    const result = assessIssueCrawlHealth(null, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /no issue crawl metadata/.test(warning)));
  });

  it('warns when a newer issue crawl hit the page cap without persisting a score', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'page_cap',
      pagesFetched: 500,
      backfillCompleteAfterRun: false,
      scorePersisted: false,
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /hit page cap/.test(warning)));
    assert.ok(result.warnings.some((warning) => /did not mark issue backfill complete/.test(warning)));
  });

  it('fails when a page-capped crawl persisted or could have produced the latest score', () => {
    const persisted = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'page_cap',
      pagesFetched: 500,
      backfillCompleteAfterRun: false,
      scorePersisted: true,
    }, latest);
    assert.ok(persisted.failures.some((failure) => /hit page cap/.test(failure)));

    const possibleLatest = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'page_cap',
      pagesFetched: 500,
      backfillCompleteAfterRun: false,
      scorePersisted: false,
    }, latest);
    assert.ok(possibleLatest.failures.some((failure) => /hit page cap/.test(failure)));
  });

  it('warns when a failed evidence refresh happened after the latest score', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: ['[closure-proof] v1 failed: timeout'],
      scorePersisted: false,
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /evidence refresh failure/.test(warning)));
    assert.ok(result.warnings.some((warning) => /current score predates/.test(warning)));
  });

  it('fails when evidence refresh failures persisted or could have produced the latest score', () => {
    const persisted = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: ['[reachability] v1 failed: git object missing'],
      scorePersisted: true,
    }, latest);
    assert.ok(persisted.failures.some((failure) => /evidence refresh failure/.test(failure)));

    const possibleLatest = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: ['[closure-evidence] v1 failed: API error'],
      scorePersisted: false,
    }, latest);
    assert.ok(possibleLatest.failures.some((failure) => /evidence refresh failure/.test(failure)));
  });

  it('fails when evidence refresh failures metadata is malformed', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: 'closure proof failed',
      scorePersisted: false,
    }, latest);

    assert.ok(result.failures.some((failure) => /must be an array/.test(failure)));
  });

  it('warns on evidence-failure stop reason even when failure examples are absent', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'evidence_failure',
      scorePersisted: false,
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /stopped during score-affecting evidence refresh/.test(warning)));
  });

  it('warns when failed classifications happened after the latest score', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: ['[classify] issue #1 failed: timeout'],
      scorePersisted: false,
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /classification failure/.test(warning)));
    assert.ok(result.warnings.some((warning) => /current score predates/.test(warning)));
  });

  it('fails when classification failures persisted or could have produced the latest score', () => {
    const persisted = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: ['[classify] issue #10 failed: rate limited'],
      scorePersisted: true,
    }, latest);
    assert.ok(persisted.failures.some((failure) => /classification failure/.test(failure)));

    const possibleLatest = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: ['[classify] issue #11 failed: bad response'],
      scorePersisted: false,
    }, latest);
    assert.ok(possibleLatest.failures.some((failure) => /classification failure/.test(failure)));
  });

  it('fails when classification failure metadata is malformed', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: 'classification failed',
      scorePersisted: false,
    }, latest);

    assert.ok(result.failures.some((failure) => /classificationFailures must be an array/.test(failure)));
  });

  it('accepts an incremental partial crawl only when it matches the stored exhaustive baseline', () => {
    const result = assessIssueCrawlHealth(issueCrawlFixture({
      crawlMode: 'incremental',
      fullIssueBackfill: false,
      stopReason: 'early_stop',
      scorePersisted: false,
      baseline,
      pagination: {
        schemaVersion: 2,
        source: 'github.repository.issues',
        repository: 'openclaw/openclaw',
        sourceOrder: 'UPDATED_AT_DESC',
        completeness: 'incremental_partial',
        boundaryTotalCount: baseline.boundaryTotalCount,
        observedTotalCount: 120,
        postBoundaryGrowthCount: 119,
        asOfBoundary: baseline.asOfBoundary,
        fetchedCount: 20,
        uniqueCount: 20,
        pageCount: 1,
        pagesFetched: 1,
        sweepCount: 1,
        exhausted: false,
        stabilized: false,
        digest: null,
        membershipDigest: null,
        contentDigest: null,
        lastRequestCursor: null,
        nextCursor: 'cursor-20',
        hasNextPage: true,
      },
    }), latest, { baseline });

    assert.deepEqual(result, { warnings: [], failures: [] });
  });

  it('accepts a naturally exhausted incremental crawl anchored to the stored baseline', () => {
    const result = assessIssueCrawlHealth(issueCrawlFixture({
      crawlMode: 'incremental',
      fullIssueBackfill: false,
      stopReason: 'exhausted',
      scorePersisted: false,
      baseline,
      pagination: {
        schemaVersion: 2,
        source: 'github.repository.issues',
        repository: 'openclaw/openclaw',
        sourceOrder: 'UPDATED_AT_DESC',
        completeness: 'incremental_exhaustive',
        boundaryTotalCount: baseline.boundaryTotalCount,
        observedTotalCount: 3,
        postBoundaryGrowthCount: 2,
        asOfBoundary: baseline.asOfBoundary,
        fetchedCount: 3,
        uniqueCount: 3,
        pageCount: 1,
        pagesFetched: 1,
        sweepCount: 1,
        exhausted: true,
        stabilized: false,
        digest: 'c'.repeat(64),
        membershipDigest: 'c'.repeat(64),
        contentDigest: 'd'.repeat(64),
        lastRequestCursor: null,
        nextCursor: null,
        hasNextPage: false,
      },
    }), latest, {
      baseline,
      repository: 'openclaw/openclaw',
    });

    assert.deepEqual(result, { warnings: [], failures: [] });
  });

  it('rejects crawl and pagination repository identity drift from the baseline', () => {
    const result = assessIssueCrawlHealth(issueCrawlFixture({
      repository: 'other/repository',
      pagination: {
        ...issueCrawlFixture().pagination,
        repository: 'other/repository',
      },
    }), latest, {
      baseline,
      repository: 'openclaw/openclaw',
    });

    assert.ok(result.failures.some((failure) =>
      /repository must equal openclaw\/openclaw/.test(failure)));
  });

  it('fails a partial universe mislabeled as a complete issue crawl', () => {
    const result = assessIssueCrawlHealth(issueCrawlFixture({
      baseline,
      pagination: {
        schemaVersion: 2,
        source: 'github.repository.issues',
        repository: 'openclaw/openclaw',
        sourceOrder: 'CREATED_AT_ASC',
        completeness: 'exhaustive_stable',
        boundaryTotalCount: baseline.boundaryTotalCount,
        observedTotalCount: 120,
        postBoundaryGrowthCount: 119,
        asOfBoundary: baseline.asOfBoundary,
        fetchedCount: 100,
        uniqueCount: 100,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        exhausted: true,
        stabilized: true,
        digest: 'b'.repeat(64),
        membershipDigest: 'b'.repeat(64),
        contentDigest: 'c'.repeat(64),
        lastRequestCursor: null,
        nextCursor: null,
        hasNextPage: false,
      },
    }), latest, { baseline });

    assert.ok(result.failures.some((failure) =>
      /fetchedCount must equal boundaryTotalCount/.test(failure)));
  });

  it('fails an incremental early stop whose embedded baseline differs from storage', () => {
    const result = assessIssueCrawlHealth(issueCrawlFixture({
      crawlMode: 'incremental',
      fullIssueBackfill: false,
      stopReason: 'early_stop',
      scorePersisted: false,
      baseline: {
        ...baseline,
        digest: 'c'.repeat(64),
        membershipDigest: 'c'.repeat(64),
        asOfBoundary: {
          ...baseline.asOfBoundary,
          membershipDigest: 'c'.repeat(64),
        },
        identity: issueBaselineIdentity({
          ...baseline,
          asOfBoundary: {
            ...baseline.asOfBoundary,
            membershipDigest: 'c'.repeat(64),
          },
        }),
      },
      pagination: {
        schemaVersion: 2,
        source: 'github.repository.issues',
        repository: 'openclaw/openclaw',
        sourceOrder: 'UPDATED_AT_DESC',
        completeness: 'incremental_partial',
        boundaryTotalCount: baseline.boundaryTotalCount,
        observedTotalCount: 120,
        postBoundaryGrowthCount: 119,
        asOfBoundary: baseline.asOfBoundary,
        fetchedCount: 20,
        uniqueCount: 20,
        pageCount: 1,
        pagesFetched: 1,
        sweepCount: 1,
        exhausted: false,
        stabilized: false,
        digest: null,
        membershipDigest: null,
        contentDigest: null,
        lastRequestCursor: null,
        nextCursor: 'cursor-20',
        hasNextPage: true,
      },
    }), latest, { baseline });

    assert.ok(result.failures.some((failure) =>
      /embedded baseline does not match stored exhaustive baseline/.test(failure)));
  });
});

describe('doctor live API readiness contract', () => {
  it('requires semantic health readiness and the exact check set', () => {
    const report: any = {
      api: {
        status: {
          refreshing: false,
          lastError: null,
          lastScoredAt: '2026-06-02T01:00:00Z',
        },
        public: {
          recommendedCount: 1,
          recommendedTag: 'v2',
        },
        health: {
          schemaVersion: 1,
          ok: true,
          status: 'ready',
          repo: 'openclaw/openclaw',
          currentRelease: { tag: 'v2' },
          checks: {
            database: { ok: true },
            releaseWindow: { ok: true },
            scoreAudit: { ok: true },
            sourceIdentity: { ok: true },
            closureProof: { ok: true },
            recommendation: { ok: true },
            ingestion: { ok: false },
            unexpected: { ok: true },
          },
          failures: [{ code: 'score_blocking_ingestion_failure' }],
        },
      },
      recommendation: { recommended: [{ tag: 'v2' }] },
      latestScoredStable: { tag: 'v2' },
      tables: { releases: { maxAt: '2026-06-02T01:00:00Z' } },
      failures: [],
    };

    verifyApiAgainstDb(report);

    assert.ok(report.failures.some((failure: string) =>
      /failures must be an empty array/.test(failure)));
    assert.ok(report.failures.some((failure: string) =>
      /readiness checks .* must equal/.test(failure)));
    assert.ok(report.failures.some((failure: string) =>
      /readiness check ingestion must report ok=true/.test(failure)));
  });

  it('accepts a coherent zero-recommendation API and database view', () => {
    const readyChecks = {
      closureProof: { ok: true },
      database: { ok: true },
      ingestion: { ok: true },
      recommendation: { ok: true },
      releaseWindow: { ok: true },
      scoreAudit: { ok: true },
      sourceIdentity: { ok: true },
    };
    const report: any = {
      api: {
        status: {
          refreshing: false,
          lastError: null,
          lastScoredAt: '2026-06-02T01:00:00Z',
        },
        public: {
          recommendedCount: 0,
          recommendedTag: null,
        },
        health: {
          schemaVersion: 1,
          ok: true,
          status: 'ready',
          repo: 'openclaw/openclaw',
          currentRelease: { tag: 'v2' },
          checks: readyChecks,
          failures: [],
        },
      },
      recommendation: {
        recommendedCount: 0,
        recommended: [],
      },
      latestScoredStable: { tag: 'v2' },
      tables: { releases: { maxAt: '2026-06-02T01:00:00Z' } },
      failures: [],
    };

    verifyApiAgainstDb(report);

    assert.deepEqual(report.failures, []);
  });
});

describe('doctor durable ingestion evidence failure health', () => {
  const latest = { tag: 'v1', scoredAt: '2026-06-30T01:00:00.000Z' };

  it('ignores absent durable ingestion failure table summaries', () => {
    assert.deepEqual(assessDurableIngestionEvidenceFailureHealth({ present: false }, latest), {
      warnings: [],
      failures: [],
    });
  });

  it('warns when durable score-affecting ingestion failures exist after the latest score', () => {
    const result = assessDurableIngestionEvidenceFailureHealth({
      present: true,
      blockingAfterLatestScoreCount: 3,
      bySource: {
        'issue-comments': { count: 2, maxAt: '2026-06-30T02:00:00Z' },
        advisories: { count: 1, maxAt: '2026-06-30T02:01:00Z' },
      },
      recentAfterLatestScore: [],
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /3 durable score-affecting ingestion evidence failure/.test(warning)));
    assert.ok(result.warnings.some((warning) => /issue-comments:2/.test(warning)));
    assert.ok(result.warnings.some((warning) => /advisories:1/.test(warning)));
  });
});

describe('doctor issue release-window performance', () => {
  it('reports the required issue indexes and measured query plans', () => {
    const { dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.performance.failedCount, 0);
      assert.equal(report.performance.missingIndexCount, 0);
      assert.equal(report.performance.unusedPlanCount, 0);
      assert.ok(report.performance.plans.every((plan: any) => plan.usesExpectedIndex));
    } finally {
      cleanup();
    }
  });

  it('fails when a release-window index is missing', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`DROP INDEX idx_issues_closed_at`);
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.performance.missingIndexCount, 1);
      assert.ok(
        report.failures.some((failure: string) =>
          /issue release-window index verification failed/.test(failure)),
      );
    } finally {
      cleanup();
    }
  });
});

describe('doctor advisory snapshot integrity', () => {
  it('passes a complete hash-valid advisory snapshot fixture', () => {
    const { dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.equal(report.advisorySnapshots.snapshotCount, 1);
      assert.equal(report.advisorySnapshots.rowCount, 1);
      assert.equal(report.advisorySnapshots.failedCount, 0);
      assert.equal(report.advisorySnapshots.latestSemanticFailureCount, 0);
      assert.equal(report.advisorySnapshots.currentSemanticFailureCount, 0);
      assert.equal(report.advisorySnapshots.legacySemanticWarningCount, 0);
      assert.deepEqual(report.advisorySnapshots.schema.history.missingColumns, []);
      assert.deepEqual(report.advisorySnapshots.schema.rows.missingColumns, []);
      assert.equal(report.advisorySnapshots.v2.snapshotCount, 1);
      assert.equal(report.advisorySnapshots.v2.rowCount, 1);
      assert.equal(report.advisorySnapshots.v2.failedCount, 0);
      assert.equal(report.advisorySnapshots.v2.chainFailureCount, 0);
      assert.equal(report.advisorySnapshots.v2.headerFailureCount, 0);
      assert.equal(report.advisorySnapshots.v2.rowFailureCount, 0);
      assert.equal(report.advisorySnapshots.v2.currentMetadataFailureCount, 0);
      assert.equal(report.advisorySnapshots.v2.activeProjectionFailureCount, 0);
    } finally {
      cleanup();
    }
  });

  it('accepts an intact staged ledger tip while preserving the selected active snapshot', () => {
    const { db, cleanup } = freshDoctorDb();
    try {
      const stagedSnapshotId = insertDoctorCompoundAdvisorySnapshot(
        db,
        '2026-06-02T01:00:20Z',
        { activate: false },
      );
      const summary = compoundAdvisorySnapshotSummary(db);

      assert.equal(summary.snapshotCount, 2);
      assert.equal(summary.latestSnapshotId, stagedSnapshotId);
      assert.equal(summary.activeSnapshotId, 1);
      assert.equal(summary.stagedSnapshotCount, 1);
      assert.equal(summary.currentMetadataFailureCount, 0);
      assert.equal(summary.activeProjectionFailureCount, 0);
      assert.equal(summary.failedCount, 0, JSON.stringify(summary.problems));
    } finally {
      cleanup();
    }
  });

  it('fails when advisory completeness metadata is missing or not stabilized', () => {
    const missing = freshDoctorDb();
    try {
      missing.db.prepare(`DELETE FROM meta WHERE key=?`).run(ADVISORY_SNAPSHOT_META_KEY);
      const report = buildDoctorReport({
        dbPath: missing.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.ok(report.advisorySnapshots.completenessProblemCount > 0);
      assert.ok(
        report.advisorySnapshots.examples.completenessProblems
          .some((problem: any) => problem.code === 'missing_metadata'),
      );
    } finally {
      missing.cleanup();
    }

    const unstable = freshDoctorDb();
    try {
      const metadata = JSON.parse(
        (unstable.db.prepare(`SELECT value FROM meta WHERE key=?`)
          .get(ADVISORY_SNAPSHOT_META_KEY) as any).value,
      );
      metadata.stabilized = false;
      metadata.sweepCount = 1;
      unstable.db.prepare(`UPDATE meta SET value=? WHERE key=?`).run(
        JSON.stringify(metadata),
        ADVISORY_SNAPSHOT_META_KEY,
      );
      const report = buildDoctorReport({
        dbPath: unstable.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.ok(
        report.advisorySnapshots.examples.completenessProblems
          .some((problem: any) => problem.code === 'incomplete_sweep'),
      );
    } finally {
      unstable.cleanup();
    }
  });

  it('fails when current advisory rows drift from completeness metadata or latest snapshot', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`UPDATE advisories SET summary='changed after snapshot'`).run();
      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });
      assert.ok(report.advisorySnapshots.completenessProblemCount > 0);
      assert.equal(report.advisorySnapshots.latestSnapshotMismatchCount, 1);
      assert.equal(report.advisorySnapshots.v2.activeProjectionFailureCount, 1);
    } finally {
      cleanup();
    }
  });

  it('fails when a stored advisory v2 row is tampered independently of snapshot_json', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, ['advisory_snapshot_v2_rows']);
      db.prepare(`
        UPDATE advisory_snapshot_v2_rows
        SET row_hash=?
        WHERE snapshot_id=1
      `).run('f'.repeat(64));

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.v2.rowFailureCount, 1);
      assert.equal(report.advisorySnapshots.v2.headerFailureCount, 1);
      assert.ok(report.advisorySnapshots.v2.problems.some((problem: string) =>
        /stored row .* does not match snapshot_json/.test(problem)));
      assert.ok(report.failures.some((failure: string) =>
        /advisory snapshot integrity failed.*v2=1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when an advisory snapshot authority policy is forged', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, ['advisory_snapshot_v2_history']);
      const header = db.prepare(`
        SELECT *
        FROM advisory_snapshot_v2_history
        WHERE id=1
      `).get() as any;
      const snapshot = JSON.parse(header.snapshot_json);
      snapshot.authorityPolicy = {
        schemaVersion: 1,
        name: 'rest_overrides_graphql',
      };
      const snapshotJson = canonicalCompoundAdvisorySnapshotJson(snapshot);
      const contentHash = compoundAdvisorySnapshotLedgerContentHash({
        capturedAt: header.captured_at,
        repository: {
          owner: header.repository_owner,
          name: header.repository_name,
          url: header.repository_url,
        },
        target: {
          ecosystem: header.target_ecosystem,
          packageName: header.target_package_name,
        },
        sourceHash: header.source_hash,
        catalogHash: header.catalog_hash,
        scoreHash: header.score_hash,
        rowCount: Number(header.row_count),
        scoreRowCount: Number(header.score_row_count),
        scoreContentDigest: header.score_content_digest,
        snapshotJson,
        previousContentHash: header.previous_content_hash,
      });
      db.prepare(`
        UPDATE advisory_snapshot_v2_history
        SET snapshot_json=?, content_hash=?
        WHERE id=1
      `).run(snapshotJson, contentHash);
      const activeMetadata = JSON.parse(
        (db.prepare(`SELECT value FROM meta WHERE key=?`)
          .get(ADVISORY_SNAPSHOT_V2_META_KEY) as any).value,
      );
      activeMetadata.contentHash = contentHash;
      db.prepare(`UPDATE meta SET value=? WHERE key=?`).run(
        canonicalOperationJson(activeMetadata),
        ADVISORY_SNAPSHOT_V2_META_KEY,
      );

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.v2.headerFailureCount, 1);
      assert.ok(report.advisorySnapshots.v2.problems.some((problem: string) =>
        /Unsupported compound advisory authority policy/.test(problem)));
      assert.ok(report.failures.some((failure: string) =>
        /advisory snapshot integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when the first advisory v2 ledger entry claims a prior content hash', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, ['advisory_snapshot_v2_history']);
      db.prepare(`
        UPDATE advisory_snapshot_v2_history
        SET previous_content_hash=?
        WHERE id=1
      `).run('f'.repeat(64));

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.v2.chainFailureCount, 1);
      assert.ok(report.advisorySnapshots.v2.problems.some((problem: string) =>
        /previous_content_hash does not match the prior ledger entry/.test(problem)));
      assert.ok(report.failures.some((failure: string) =>
        /advisory snapshot integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('warns on semantic incompatibility confined to an older immutable snapshot', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'advisory_snapshot_history',
        'advisory_snapshot_rows',
      ]);
      appendDoctorCurrentAdvisorySnapshot(db, 2);
      const vulnerableVersionRange = '^2.0.0';
      db.prepare(`
        UPDATE advisory_snapshot_rows
        SET vulnerable_version_range=?, advisory_key=?
        WHERE snapshot_id=1
      `).run(
        vulnerableVersionRange,
        advisoryVulnerabilityKey(
          doctorAdvisorySnapshotRow.ghsa_id,
          doctorAdvisorySnapshotRow.package_ecosystem,
          doctorAdvisorySnapshotRow.package_name,
          vulnerableVersionRange,
        ),
      );
      rewriteDoctorAdvisorySnapshotHash(db, 1);
      reinstallDoctorAppendOnlyTriggers(db);
      seedDoctorCleanIssueCrawl(db);

      const report = buildDoctorReport({
        dbPath,
        failOnWarnings: true,
        now: new Date('2026-06-02T02:00:00Z'),
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.latestSemanticFailureCount, 0);
      assert.equal(report.advisorySnapshots.currentSemanticFailureCount, 0);
      assert.equal(report.advisorySnapshots.legacySemanticWarningCount, 1);
      assert.equal(report.advisorySnapshots.legacySemanticSnapshotCount, 1);
      assert.equal(report.advisorySnapshots.failedCount, 0);
      assert.deepEqual(report.warnings, []);
      assert.ok(report.legacyFindings.some((finding: string) =>
        /snapshot 1.*malformed_vulnerable_range/.test(finding)));
      assert.equal(report.ok, true, JSON.stringify({
        warnings: report.warnings,
        failures: report.failures,
        operationReceiptProblems: report.operationReceipts.problems,
        legacyFindings: report.legacyFindings,
      }, null, 2));
      assert.ok(!report.failures.some((failure: string) =>
        /advisory snapshot integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails semantic invalidity at the current rows and latest immutable snapshot', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'advisory_snapshot_history',
        'advisory_snapshot_rows',
      ]);
      const vulnerableVersionRange = '<=2.0.0';
      const advisoryKey = advisoryVulnerabilityKey(
        doctorAdvisorySnapshotRow.ghsa_id,
        doctorAdvisorySnapshotRow.package_ecosystem,
        doctorAdvisorySnapshotRow.package_name,
        vulnerableVersionRange,
      );
      db.prepare(`
        UPDATE advisory_snapshot_rows
        SET vulnerable_version_range=?, advisory_key=?
        WHERE snapshot_id=1
      `).run(vulnerableVersionRange, advisoryKey);
      db.prepare(`
        UPDATE advisories
        SET vulnerable_version_range=?, advisory_key=?
      `).run(vulnerableVersionRange, advisoryKey);
      rewriteDoctorAdvisorySnapshotHash(db, 1);
      rewriteDoctorAdvisoryCompletenessMetadata(db);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.latestSemanticFailureCount, 1);
      assert.equal(report.advisorySnapshots.currentSemanticFailureCount, 1);
      assert.equal(report.advisorySnapshots.currentStructuralFailureCount, 0);
      assert.equal(report.advisorySnapshots.legacySemanticWarningCount, 0);
      assert.equal(report.advisorySnapshots.latestSnapshotMismatchCount, 0);
      assert.ok(report.failures.some((failure: string) =>
        /latestSemantic=1.*currentSemantic=1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('keeps package identity failures fatal in older immutable snapshots', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'advisory_snapshot_history',
        'advisory_snapshot_rows',
      ]);
      appendDoctorCurrentAdvisorySnapshot(db, 2);
      const packageName = 'legacy-other-package';
      db.prepare(`
        UPDATE advisory_snapshot_rows
        SET package_name=?, advisory_key=?
        WHERE snapshot_id=1
      `).run(
        packageName,
        advisoryVulnerabilityKey(
          doctorAdvisorySnapshotRow.ghsa_id,
          doctorAdvisorySnapshotRow.package_ecosystem,
          packageName,
          doctorAdvisorySnapshotRow.vulnerable_version_range,
        ),
      );
      rewriteDoctorAdvisorySnapshotHash(db, 1);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.packageMismatchCount, 1);
      assert.equal(report.advisorySnapshots.legacySemanticWarningCount, 0);
      assert.ok(report.failures.some((failure: string) =>
        /advisory snapshot integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails on an advisory snapshot content hash mismatch', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, ['advisory_snapshot_history']);
      db.prepare(`
        UPDATE advisory_snapshot_history
        SET content_hash=?
        WHERE id=1
      `).run('f'.repeat(64));

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.equal(report.advisorySnapshots.contentHashMismatchCount, 1);
      assert.ok(report.failures.some((failure) => /advisory snapshot integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when a snapshot header row_count does not match its attached rows', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, ['advisory_snapshot_history']);
      db.prepare(`UPDATE advisory_snapshot_history SET row_count=2 WHERE id=1`).run();

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.equal(report.advisorySnapshots.rowCountMismatchCount, 1);
      assert.equal(report.advisorySnapshots.contentHashMismatchCount, 0);
    } finally {
      cleanup();
    }
  });

  it('fails on orphan advisory snapshot rows', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec('PRAGMA foreign_keys=OFF');
      insertDoctorAdvisorySnapshotRow(db, {
        snapshotId: 999,
        ghsaId: 'GHSA-doctor-orphan',
        vulnerableVersionRange: '<3.0.0',
      });

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.equal(report.advisorySnapshots.orphanRowCount, 1);
      assert.equal(report.advisorySnapshots.packageMismatchCount, 0);
      assert.equal(report.advisorySnapshots.advisoryKeyMismatchCount, 0);
    } finally {
      cleanup();
    }
  });

  it('fails on wrong npm package identity without conflating it with a key mismatch', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'advisory_snapshot_history',
        'advisory_snapshot_rows',
      ]);
      const packageName = 'other-package';
      db.prepare(`
        UPDATE advisory_snapshot_rows
        SET package_name=?, advisory_key=?
        WHERE snapshot_id=1
      `).run(
        packageName,
        advisoryVulnerabilityKey(
          doctorAdvisorySnapshotRow.ghsa_id,
          doctorAdvisorySnapshotRow.package_ecosystem,
          packageName,
          doctorAdvisorySnapshotRow.vulnerable_version_range,
        ),
      );
      rewriteDoctorAdvisorySnapshotHash(db, 1);

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.equal(report.advisorySnapshots.packageMismatchCount, 1);
      assert.equal(report.advisorySnapshots.advisoryKeyMismatchCount, 0);
      assert.equal(report.advisorySnapshots.contentHashMismatchCount, 0);
    } finally {
      cleanup();
    }
  });

  it('fails on noncanonical advisory keys', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'advisory_snapshot_history',
        'advisory_snapshot_rows',
      ]);
      db.prepare(`
        UPDATE advisory_snapshot_rows
        SET advisory_key='not-canonical'
        WHERE snapshot_id=1
      `).run();
      rewriteDoctorAdvisorySnapshotHash(db, 1);

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.equal(report.advisorySnapshots.advisoryKeyMismatchCount, 1);
      assert.equal(report.advisorySnapshots.contentHashMismatchCount, 0);
    } finally {
      cleanup();
    }
  });

  it('fails on malformed rows and duplicate canonical identities', () => {
    const malformed = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(malformed.db, [
        'advisory_snapshot_history',
        'advisory_snapshot_rows',
      ]);
      malformed.db.prepare(`
        UPDATE advisory_snapshot_rows
        SET summary=''
        WHERE snapshot_id=1
      `).run();
      rewriteDoctorAdvisorySnapshotHash(malformed.db, 1);

      const report = buildDoctorReport({
        dbPath: malformed.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.malformedRowCount, 1);
      assert.equal(report.advisorySnapshots.latestSemanticFailureCount, 1);
      assert.equal(report.advisorySnapshots.legacySemanticWarningCount, 0);
      assert.equal(report.advisorySnapshots.contentHashMismatchCount, 0);
    } finally {
      malformed.cleanup();
    }

    const duplicate = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(duplicate.db, ['advisory_snapshot_history']);
      insertDoctorAdvisorySnapshotRow(duplicate.db, {
        snapshotId: 1,
        advisoryKey: 'duplicate-key',
      });
      duplicate.db.prepare(`UPDATE advisory_snapshot_history SET row_count=2 WHERE id=1`).run();
      rewriteDoctorAdvisorySnapshotHash(duplicate.db, 1);

      const report = buildDoctorReport({
        dbPath: duplicate.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.duplicateCanonicalIdentityCount, 1);
      assert.equal(report.advisorySnapshots.contentHashMismatchCount, 0);
      assert.equal(report.advisorySnapshots.rowCountMismatchCount, 0);
    } finally {
      duplicate.cleanup();
    }
  });

  it('reports malformed legacy snapshot schemas without crashing', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        ALTER TABLE advisory_snapshot_rows RENAME TO advisory_snapshot_rows_full;
        CREATE TABLE advisory_snapshot_rows (snapshot_id INTEGER);
        INSERT INTO advisory_snapshot_rows(snapshot_id)
        SELECT snapshot_id FROM advisory_snapshot_rows_full;
      `);

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.ok(report.advisorySnapshots.schemaFailureCount > 0);
      assert.ok(report.advisorySnapshots.schema.rows.missingColumns.includes('advisory_key'));
      assert.ok(report.failures.some((failure) => /advisory snapshot integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });
});

describe('doctor score persistence release/audit parity', () => {
  it('still fails strict mode for genuine operational warnings', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`UPDATE issues SET commenter_scan_truncated=1 WHERE number=1`).run();
      const report = buildDoctorReport({
        dbPath,
        failOnWarnings: true,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.deepEqual(report.failures, []);
      assert.deepEqual(report.legacyFindings, []);
      assert.ok(report.warnings.some((warning: string) =>
        /truncated comment scans/.test(warning)));
      assert.equal(report.ok, false);
    } finally {
      cleanup();
    }
  });

  it('passes a coherent scored release/audit fixture', () => {
    const { dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.deepEqual(report.failures, []);
      assert.deepEqual(report.scorePersistence.scoredStableTags, ['v2', 'v1']);
      assert.deepEqual(report.scorePersistence.auditedStableTags, ['v2', 'v1']);
      assert.deepEqual(report.scorePersistence.missingAuditTags, []);
      assert.deepEqual(report.scorePersistence.orphanAuditTags, []);
      assert.deepEqual(report.scorePersistence.releaseAuditMismatches, []);
    } finally {
      cleanup();
    }
  });

  it('ignores inactive historical release rows in current health checks', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`
        INSERT INTO releases (
          tag, published_at, prerelease, catalog_active, final_score, state,
          recommended, score_reason, scored_at
        ) VALUES (
          'v-stale', '2026-06-03T00:00:00Z', 0, 0, 10, 'eligible',
          1, 'stale historical row', '2026-06-03T01:00:00Z'
        )
      `).run();

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.deepEqual(report.failures, []);
      assert.equal(report.latestScoredStable.tag, 'v2');
      assert.deepEqual(report.scorePersistence.scoredStableTags, ['v2', 'v1']);
      assert.equal(report.recommendation.recommendedCount, 1);
    } finally {
      cleanup();
    }
  });

  it('fails when an older scored stable release is missing an audit row even if meta matches audits', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`DELETE FROM release_score_audits WHERE release_tag='v1'`).run();
      writeScorePersistenceMeta(db, ['v2']);

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.ok(report.failures.some((failure) => /scored stable row count \(2\) does not match audited stable rows \(1\)/.test(failure)));
      assert.ok(report.failures.some((failure) => /releaseTags do not match scored stable release rows/.test(failure)));
      assert.ok(report.failures.some((failure) => /missing release_score_audits rows.*v1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when an older release row and audit row disagree', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`UPDATE release_score_audits SET final_score=6.6, scored_at='2026-06-01T02:00:00Z', status='wait', recommended=1 WHERE release_tag='v1'`).run();

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.ok(report.failures.some((failure) => /release\/audit field mismatch/.test(failure)));
      assert.deepEqual(
        report.scorePersistence.releaseAuditMismatches.filter((row: any) => row.tag === 'v1').map((row: any) => row.field).sort(),
        ['final_score', 'recommended', 'scored_at', 'status'],
      );
    } finally {
      cleanup();
    }
  });

  it('fails when an older scored stable audit has partial classification coverage', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`
        UPDATE release_score_audits
        SET input_json=?
        WHERE release_tag='v1'
      `).run(JSON.stringify({ rawIssueCount: 1, classifiedIssueCount: 0 }));

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.deepEqual(
        report.scorePersistence.classificationCoverageMismatches,
        [{ tag: 'v1', rawIssueCount: 1, classifiedIssueCount: 0 }],
      );
      assert.ok(report.failures.some((failure) =>
        /classification coverage must be exact for every audited stable release/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when an audit row exists for a stable release that is no longer scored', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`UPDATE releases SET final_score=NULL, scored_at=NULL, recommended=0 WHERE tag='v1'`).run();

      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });

      assert.ok(report.failures.some((failure) => /scored stable row count \(1\) does not match audited stable rows \(2\)/.test(failure)));
      assert.ok(report.failures.some((failure) => /orphan audit rows.*v1|audit rows without scored stable release rows.*v1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when an audit source identity is missing', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`UPDATE release_score_audits SET source_identity_json=NULL WHERE release_tag='v1'`).run();
      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });
      assert.ok(report.failures.some((failure) => /source identity missing.*v1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('reports a missing source identity column instead of crashing on a pre-migration DB', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        ALTER TABLE release_score_audits RENAME TO release_score_audits_with_identity;
        CREATE TABLE release_score_audits (
          release_tag TEXT PRIMARY KEY,
          scored_at TEXT NOT NULL,
          score_model_version TEXT NOT NULL,
          prompt_version INTEGER NOT NULL,
          final_score REAL,
          status TEXT NOT NULL,
          band TEXT NOT NULL,
          recommended INTEGER NOT NULL DEFAULT 0,
          input_json TEXT NOT NULL,
          components_json TEXT,
          issue_evidence_json TEXT NOT NULL,
          gate_evidence_json TEXT NOT NULL
        );
        INSERT INTO release_score_audits (
          release_tag, scored_at, score_model_version, prompt_version, final_score, status, band,
          recommended, input_json, components_json, issue_evidence_json, gate_evidence_json
        )
        SELECT
          release_tag, scored_at, score_model_version, prompt_version, final_score, status, band,
          recommended, input_json, components_json, issue_evidence_json, gate_evidence_json
        FROM release_score_audits_with_identity;
        DROP TABLE release_score_audits_with_identity;
      `);
      const report = buildDoctorReport({ dbPath, sourceIdentityForDb: () => doctorSourceIdentityFixture });
      assert.ok(report.failures.some((failure) => /source_identity_json is missing/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when current source identity differs from persisted audits', () => {
    const { dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => {
          const sources = doctorSourceIdentityFixture.sources.map((source) =>
            source.source === 'issues'
              ? { ...source, digest: 'd'.repeat(64) }
              : source);
          return {
            ...doctorSourceIdentityFixture,
            digest: doctorSourceIdentityDigest(sources),
            sources,
          };
        },
      });
      assert.ok(report.failures.some((failure) => /score source identity drift/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('rejects duplicate and reordered score source manifests', () => {
    for (const mutation of ['duplicate', 'reordered'] as const) {
      const { db, dbPath, cleanup } = freshDoctorDb();
      try {
        const identity = structuredClone(doctorSourceIdentityFixture);
        if (mutation === 'duplicate') {
          identity.sources[1] = structuredClone(identity.sources[0]);
          identity.rowCount = identity.sources.reduce((sum, source) => sum + source.count, 0);
        } else {
          [identity.sources[0], identity.sources[1]] = [
            identity.sources[1],
            identity.sources[0],
          ];
        }
        identity.digest = doctorSourceIdentityDigest(identity.sources);
        db.prepare(`UPDATE release_score_audits SET source_identity_json=?`).run(
          JSON.stringify(identity),
        );
        const report = buildDoctorReport({
          dbPath,
          sourceIdentityForDb: () => doctorSourceIdentityFixture,
        });
        assert.ok(
          report.failures.some((failure) => /source identity malformed/.test(failure)),
          mutation,
        );
      } finally {
        cleanup();
      }
    }
  });

  it('reports source identity schema errors instead of crashing', () => {
    const { dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => {
          throw new Error('no such column: issue_pr_links.source_comment_url');
        },
      });
      assert.ok(report.failures.some((failure) => /source identity could not be computed.*source_comment_url/.test(failure)));
    } finally {
      cleanup();
    }
  });
});

describe('doctor closure dependency membership', () => {
  it('rejects omitted, extra, and nonexistent proof dependency issues', () => {
    const fixture = freshDoctorDb();
    try {
      const { db, dbPath } = fixture;
      db.prepare(`
        UPDATE issues
        SET state='closed', closed_at='2026-06-02T00:30:00Z'
        WHERE number=1
      `).run();
      const insertIssue = db.prepare(`
        INSERT INTO issues (
          number, state, title, created_at, updated_at, closed_at,
          comments, labels, revision, fetched_at, commenter_scan_truncated
        )
        VALUES (?, 'open', ?, '2026-06-02T00:10:00Z', '2026-06-02T00:20:00Z', NULL,
          0, '[]', 1, '2026-06-02T00:20:00Z', 0)
      `);
      for (const issueNumber of [2, 3, 4]) {
        insertIssue.run(issueNumber, `canonical issue ${issueNumber}`);
      }
      const upsertProof = (canonicalIssues: number[]) => {
        db.prepare(`DELETE FROM issue_closure_proofs WHERE release_tag='v2'`).run();
        db.prepare(`
          INSERT INTO issue_closure_proofs (
            release_tag, issue_number, status, summary, evidence_json, checked_at
          )
          VALUES ('v2', 1, 'canonical_cycle_or_self_reference', 'proof', ?, '2026-06-03T00:00:00Z')
        `).run(JSON.stringify({
          proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
          canonicalIssues,
          canonicalResolution: {
            path: [1, ...canonicalIssues],
            branches: [{
              path: [1, ...canonicalIssues],
              terminalIssue: { number: canonicalIssues.at(-1) },
            }],
            terminalIssues: canonicalIssues.map((number) => ({ number })),
          },
        }));
      };
      const sealSnapshot = (issueNumbers: number[]) => {
        const report = buildDoctorReport({
          dbPath,
          sourceIdentityForDb: () => doctorSourceIdentityFixture,
        });
        const current = report.closureProof.integrity.dependencySnapshot.current;
        assert.ok(current?.digest);
        db.prepare(`
          UPDATE release_closure_dependency_snapshots
          SET issue_numbers_json=?, dependency_digest=?, dependency_row_count=?
          WHERE release_tag='v2'
        `).run(JSON.stringify(issueNumbers), current.digest, current.rowCount);
      };

      upsertProof([2, 3]);
      sealSnapshot([1, 2, 3]);
      upsertProof([2, 3, 4]);
      let report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(
        report.closureProof.integrity.dependencySnapshot.issueNumbersMismatchCount,
        1,
      );
      assert.deepEqual(
        report.closureProof.integrity.dependencySnapshot.persisted.omittedExpectedIssueNumbers,
        [4],
      );

      sealSnapshot([1, 2, 3, 4]);
      upsertProof([2, 3]);
      report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(
        report.closureProof.integrity.dependencySnapshot.issueNumbersMismatchCount,
        1,
      );
      assert.deepEqual(
        report.closureProof.integrity.dependencySnapshot.persisted.extraIssueNumbers,
        [4],
      );

      const missingIssueNumber = 999_999;
      upsertProof([2, 3, missingIssueNumber]);
      sealSnapshot([1, 2, 3, missingIssueNumber]);
      report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(
        report.closureProof.integrity.dependencySnapshot.referencedIssueMissingCount,
        1,
      );
      assert.equal(
        report.closureProof.integrity.dependencySnapshot.issueNumbersMismatchCount,
        0,
      );
    } finally {
      fixture.cleanup();
    }
  });
});

describe('doctor score history ledger integrity', () => {
  it('accepts a complete sealed history run', () => {
    const { dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.scoreHistory.historyRowCount, 2);
      assert.equal(report.scoreHistory.runCount, 1);
      assert.deepEqual(report.scoreHistory.schema.history.missingColumns, []);
      assert.equal(report.scoreHistory.failedCount, 0);
    } finally {
      cleanup();
    }
  });

  it('detects deleted or mutated history rows and missing seals', () => {
    const deleted = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(deleted.db, ['release_score_audit_history']);
      deleted.db.prepare(`
        DELETE FROM release_score_audit_history
        WHERE run_id='run-doctor' AND release_tag='v1'
      `).run();
      const report = buildDoctorReport({
        dbPath: deleted.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.ok(report.scoreHistory.rowCountMismatchCount > 0);
      assert.ok(report.scoreHistory.rowsContentHashMismatchCount > 0);
    } finally {
      deleted.cleanup();
    }

    const missingSeal = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(missingSeal.db, ['release_score_audit_history_runs']);
      missingSeal.db.prepare(`
        DELETE FROM release_score_audit_history_runs
        WHERE run_id='run-doctor'
      `).run();
      const report = buildDoctorReport({
        dbPath: missingSeal.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.scoreHistory.missingSealCount, 1);
    } finally {
      missingSeal.cleanup();
    }
  });

  it('detects run-chain and seal-content tampering', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, ['release_score_audit_history_runs']);
      db.prepare(`
        UPDATE release_score_audit_history_runs
        SET previous_content_hash='tampered', content_hash='tampered'
        WHERE run_id='run-doctor'
      `).run();
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.scoreHistory.chainFailureCount, 1);
      assert.equal(report.scoreHistory.contentHashMismatchCount, 1);
    } finally {
      cleanup();
    }
  });

  it('requires authority_run_id on score history rows', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        ALTER TABLE release_score_audit_history
        RENAME COLUMN authority_run_id TO missing_authority_run_id
      `);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.deepEqual(
        report.scoreHistory.schema.history.missingColumns,
        ['authority_run_id'],
      );
      assert.equal(report.scoreHistory.schemaFailureCount, 1);
      assert.ok(report.failures.some((failure: string) =>
        /score history ledger integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('requires one exact non-null authority run binding across the current score tip', () => {
    const mutations = [
      {
        name: 'current audit',
        apply(db: DatabaseSync) {
          db.prepare(`
            UPDATE release_score_audits
            SET authority_run_id=NULL
            WHERE release_tag='v1'
          `).run();
        },
      },
      {
        name: 'history row',
        apply(db: DatabaseSync) {
          disableDoctorAppendOnlyTriggers(db, ['release_score_audit_history']);
          db.prepare(`
            UPDATE release_score_audit_history
            SET authority_run_id=NULL
            WHERE run_id='run-doctor' AND release_tag='v1'
          `).run();
        },
      },
      {
        name: 'authority run',
        apply(db: DatabaseSync) {
          disableDoctorAppendOnlyTriggers(db, ['score_authority_resolution_runs']);
          db.prepare(`
            UPDATE score_authority_resolution_runs
            SET authority_run_id=NULL
            WHERE authority_run_id='score-authority:run-doctor'
          `).run();
        },
      },
      {
        name: 'history v2 seal',
        apply(db: DatabaseSync) {
          disableDoctorAppendOnlyTriggers(db, ['release_score_audit_history_v2_seals']);
          db.prepare(`
            UPDATE release_score_audit_history_v2_seals
            SET authority_run_id='score-authority:other'
            WHERE history_run_id='run-doctor'
          `).run();
        },
      },
      {
        name: 'score metadata',
        apply(db: DatabaseSync) {
          const meta = JSON.parse(String(db.prepare(`
            SELECT value FROM meta WHERE key='score_persistence_last_run'
          `).get()?.value));
          db.prepare(`
            UPDATE meta SET value=? WHERE key='score_persistence_last_run'
          `).run(JSON.stringify({ ...meta, authorityRunId: null }));
        },
      },
    ];

    for (const mutation of mutations) {
      const { db, dbPath, cleanup } = freshDoctorDb();
      try {
        mutation.apply(db);
        const report = buildDoctorReport({
          dbPath,
          sourceIdentityForDb: () => doctorSourceIdentityFixture,
        });

        assert.ok(
          report.scoreHistory.authorityRunBindingFailureCount > 0,
          mutation.name,
        );
        assert.ok(
          report.scoreHistory.authorityBindingProblems.some((problem: string) =>
            /authority/i.test(problem)),
          mutation.name,
        );
      } finally {
        cleanup();
      }
    }
  });

  it('rejects equal instants that are not canonical UTC millisecond timestamps', () => {
    for (const noncanonical of [
      '2026-06-02T01:05:00Z',
      '2026-06-02T01:05:00.000+00:00',
      '2026-06-01T19:05:00.000-06:00',
    ]) {
      assert.equal(
        Date.parse(noncanonical),
        Date.parse('2026-06-02T01:05:00.000Z'),
        noncanonical,
      );
      const { db, dbPath, cleanup } = freshDoctorDb();
      try {
        disableDoctorAppendOnlyTriggers(db, [
          'release_score_audit_history',
          'release_score_audit_history_runs',
          'score_authority_resolution_runs',
          'release_score_audit_history_v2_seals',
        ]);
        db.prepare(`
          UPDATE release_score_audit_history
          SET recorded_at=?
          WHERE run_id='run-doctor'
        `).run(noncanonical);
        const run = db.prepare(`
          SELECT *
          FROM release_score_audit_history_runs
          WHERE run_id='run-doctor'
        `).get() as any;
        const historyRunContentHash = releaseScoreAuditHistoryRunContentHash({
          runId: run.run_id,
          recordedAt: noncanonical,
          rowCount: Number(run.row_count),
          rowsContentHash: run.rows_content_hash,
          previousContentHash: run.previous_content_hash ?? null,
        });
        db.prepare(`
          UPDATE release_score_audit_history_runs
          SET recorded_at=?, content_hash=?
          WHERE run_id='run-doctor'
        `).run(noncanonical, historyRunContentHash);
        db.prepare(`
          UPDATE score_authority_resolution_runs
          SET recorded_at=?
          WHERE authority_run_id='score-authority:run-doctor'
        `).run(noncanonical);
        db.prepare(`
          UPDATE release_score_audit_history_v2_seals
          SET sealed_at=?
          WHERE history_run_id='run-doctor'
        `).run(noncanonical);
        const meta = JSON.parse(String(db.prepare(`
          SELECT value FROM meta WHERE key='score_persistence_last_run'
        `).get()?.value));
        db.prepare(`
          UPDATE meta SET value=? WHERE key='score_persistence_last_run'
        `).run(JSON.stringify({
          ...meta,
          persistedAt: noncanonical,
          historyRunContentHash,
          commitTiming: {
            ...meta.commitTiming,
            historyRunContentHash,
            historyRecordedAt: noncanonical,
            commitNotBefore: noncanonical,
            commitNotAfter: noncanonical,
          },
        }));

        const report = buildDoctorReport({
          dbPath,
          sourceIdentityForDb: () => doctorSourceIdentityFixture,
        });

        assert.equal(report.scoreHistory.recordedAtMismatchCount, 0, noncanonical);
        assert.equal(report.scoreHistory.contentHashMismatchCount, 0, noncanonical);
        assert.equal(
          report.scoreHistory.authorityRunBindingFailureCount,
          0,
          noncanonical,
        );
        assert.ok(report.scoreHistory.canonicalTimestampFailureCount > 0, noncanonical);
        assert.ok(report.scoreHistory.canonicalTimestampProblems.some(
          (problem: string) => problem.includes(noncanonical),
        ));
      } finally {
        cleanup();
      }
    }
  });

  it('accounts for history timestamp mismatches separately from row counts', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, ['release_score_audit_history']);
      db.prepare(`
        UPDATE release_score_audit_history
        SET recorded_at='2026-06-02T01:05:00.001Z'
        WHERE run_id='run-doctor' AND release_tag='v1'
      `).run();

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.scoreHistory.rowCountMismatchCount, 0);
      assert.equal(report.scoreHistory.recordedAtMismatchCount, 1);
      assert.equal(report.scoreHistory.rowsContentHashMismatchCount, 0);
      assert.equal(report.scoreHistory.failedCount, 1);
      assert.ok(report.failures.some((failure: string) =>
        /recordedAt=1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('rejects semantically invalid source provenance on the current sealed tip', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'release_score_audit_history',
        'release_score_audit_history_runs',
        'release_score_audit_history_v2_seals',
      ]);
      const invalid = structuredClone(doctorSourceIdentityFixture);
      invalid.sources[1] = structuredClone(invalid.sources[0]);
      invalid.digest = scoreSourceIdentityManifestDigest(
        invalid.sources,
        invalid.schemaVersion,
        invalid,
      );
      db.prepare(`
        UPDATE release_score_audit_history
        SET source_identity_json=?
        WHERE run_id='run-doctor' AND release_tag='v1'
      `).run(JSON.stringify(invalid));
      rewriteDoctorHistorySeal(db, 'run-doctor');
      db.prepare(`
        INSERT INTO release_validation_forecasts (
          id, decision_id, opportunity_code, recorded_at, latest_release_tag,
          latest_release_published_at, selected_tag, audit_history_run_id,
          score_model_version, prompt_version, policy_code, candidate_scores_json,
          decision_json, source_identity_json, code_revision, previous_content_hash,
          content_hash
        )
        VALUES (
          1, 'invalid-history-reference', 'first_verified_after_3h',
          '2026-06-02T01:05:00Z', 'v2', '2026-06-02T00:00:00Z', 'v2',
          'run-doctor', 'test-model', 6, 'policy', '[]', '{}', ?, NULL, NULL, 'hash'
        )
      `).run(JSON.stringify(doctorSourceIdentityFixture));

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.scoreHistory.sourceManifestFailureCount, 1);
      assert.equal(report.scoreHistory.currentTipSourceManifestFailureCount, 1);
      assert.equal(report.validation.referencedHistorySourceManifestFailureCount, 1);
      assert.ok(report.failures.some((failure) => /currentManifest=1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('rejects mutable current audits that do not match the recorded sealed history tip', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`
        UPDATE release_score_audits
        SET components_json='{"changed":true}'
        WHERE release_tag='v1'
      `).run();
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.scoreHistory.currentAuditHistoryMismatchCount, 1);
      assert.ok(report.failures.some((failure) => /currentMismatch=1/.test(failure)));
    } finally {
      cleanup();
    }
  });
});

describe('doctor refresh operation receipt integrity', () => {
  it('projects catalog tag commit OIDs exactly and fails closed when they are absent', () => {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec(`
        CREATE TABLE releases (
          tag TEXT PRIMARY KEY,
          node_id TEXT,
          catalog_tag_commit_oid TEXT,
          name TEXT,
          published_at TEXT,
          created_at TEXT,
          updated_at TEXT,
          html_url TEXT,
          prerelease INTEGER NOT NULL,
          body TEXT,
          catalog_rank INTEGER,
          catalog_digest TEXT,
          catalog_active INTEGER NOT NULL
        )
      `);
      const rows = [
        {
          catalog_rank: 0,
          node_id: 'R_v2',
          catalog_tag_commit_oid: 'A'.repeat(40),
          tag: 'v2',
          name: 'v2',
          published_at: '2026-06-02T00:00:00Z',
          created_at: '2026-06-02T00:00:00Z',
          updated_at: '2026-06-02T00:00:00Z',
          html_url: 'https://example.test/v2',
          prerelease: 0,
          body: '',
        },
        {
          catalog_rank: 1,
          node_id: 'R_v1',
          catalog_tag_commit_oid: 'b'.repeat(40),
          tag: 'v1',
          name: 'v1',
          published_at: '2026-06-01T00:00:00Z',
          created_at: '2026-06-01T00:00:00Z',
          updated_at: '2026-06-01T00:00:00Z',
          html_url: 'https://example.test/v1',
          prerelease: 0,
          body: '',
        },
      ];
      const insert = db.prepare(`
        INSERT INTO releases (
          catalog_rank, node_id, catalog_tag_commit_oid, tag, name, published_at,
          created_at, updated_at, html_url, prerelease, body, catalog_digest,
          catalog_active
        )
        VALUES (
          :catalog_rank, :node_id, :catalog_tag_commit_oid, :tag, :name, :published_at,
          :created_at, :updated_at, :html_url, :prerelease, :body, NULL, 1
        )
      `);
      rows.forEach((row) => insert.run(row));

      const expectedDigest = createHash('sha256')
        .update(JSON.stringify([
          'active_release_catalog',
          1,
          rows.map((row) => [
            row.catalog_rank,
            row.node_id,
            row.catalog_tag_commit_oid.toLowerCase(),
            row.tag,
            row.name,
            row.published_at,
            row.created_at,
            row.updated_at,
            row.html_url,
            row.prerelease,
            row.body,
          ]),
        ]))
        .digest('hex');
      db.prepare(`
        UPDATE releases
        SET catalog_digest=?
        WHERE catalog_active=1
      `).run(expectedDigest);
      const projected = currentActiveReleaseCatalogForDoctor(db);

      assert.equal(projected.digest, expectedDigest);
      assert.deepEqual(projected.latestStable, {
        nodeId: 'R_v2',
        tag: 'v2',
        tagCommitOid: 'a'.repeat(40),
        publishedAt: '2026-06-02T00:00:00Z',
      });
      assert.deepEqual(projected.problems, []);

      db.prepare(`
        UPDATE releases
        SET catalog_tag_commit_oid=?
        WHERE tag='v1'
      `).run('c'.repeat(40));
      assert.notEqual(currentActiveReleaseCatalogForDoctor(db).digest, projected.digest);

      db.prepare(`
        UPDATE releases
        SET catalog_tag_commit_oid=NULL
        WHERE tag='v2'
      `).run();
      assert.match(
        currentActiveReleaseCatalogForDoctor(db).problems.join('\n'),
        /v2 has invalid catalog tag commit OID/,
      );
    } finally {
      db.close();
    }
  });

  it('accepts a complete hash-valid receipt linked to the score output', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.operationReceipts.attemptCount, 1);
      assert.equal(report.operationReceipts.stageEventCount, 4);
      assert.equal(report.operationReceipts.successCount, 1);
      assert.equal(report.operationReceipts.failedCount, 0);
    } finally {
      cleanup();
    }
  });

  it('keeps the active score receipt authoritative when a newer advisory snapshot is only staged', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const stagedSnapshotId = insertDoctorCompoundAdvisorySnapshot(
        db,
        '2026-06-02T01:00:20Z',
        { activate: false },
      );
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.advisorySnapshots.v2.latestSnapshotId, stagedSnapshotId);
      assert.equal(report.advisorySnapshots.v2.activeSnapshotId, 1);
      assert.equal(report.advisorySnapshots.v2.stagedSnapshotCount, 1);
      assert.equal(report.advisorySnapshots.v2.failedCount, 0);
      assert.equal(
        report.validation.advisoryV2AuthorizationFailureCount,
        0,
        JSON.stringify(report.validation.errors),
      );
      assert.equal(report.validation.authorizedAdvisoryV2SnapshotCount, 1);
      assert.equal(report.validation.stagedAdvisoryV2SnapshotCount, 1);
      assert.equal(
        report.operationReceipts.currentScoreTipFailureCount,
        0,
        JSON.stringify(report.operationReceipts.problems),
      );
      assert.equal(
        report.operationReceipts.failedCount,
        0,
        JSON.stringify(report.operationReceipts.problems),
      );
    } finally {
      cleanup();
    }
  });

  it('loads canonical proof record_json for receipt semantics and fails closed on divergence', () => {
    const { db, dbPath, cleanup } = freshDoctorDb({
      validationProof: 'uninitialized',
    });
    try {
      createDoctorProofRecordTables(db);
      const baseline = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(baseline.operationReceipts.semanticLinkFailureCount, 0);
      assert.equal(baseline.validationProof.status, 'uninitialized');
      assert.equal(baseline.validationProof.valid, true);
      assert.equal(baseline.validationProof.productionAuthorized, false);

      db.prepare(`
        INSERT INTO release_validation_proof_epochs (
          proof_epoch_id, content_hash, record_json
        )
        VALUES (?, ?, ?)
      `).run('a'.repeat(64), 'b'.repeat(64), '{}');
      const divergent = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.ok(divergent.operationReceipts.semanticLinkFailureCount > 0);
      assert.equal(divergent.validationProof.status, 'invalid');
      assert.equal(divergent.validationProof.valid, false);
      assert.match(
        divergent.operationReceipts.problems.join('\n'),
        /proof storage could not be reconstructed: .*diverges from its immutable ID or content-hash projection/,
      );
    } finally {
      cleanup();
    }
  });

  it('rejects a hash-valid receipt with mismatched advisory v2 counts', () => {
    const { db, dbPath, cleanup } = freshDoctorDb({
      operationReceipt: {
        advisoryCatalog: { catalogRowCount: 999 },
      },
    });
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.ok(report.operationReceipts.linkFailureCount > 0);
      assert.ok(report.operationReceipts.problems.some((problem: string) =>
        /advisory v2 ledger is not authoritative/.test(problem)));
    } finally {
      cleanup();
    }
  });

  it('rejects current score receipt authorization when advisory v2 metadata drifts', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const receipt = db.prepare(`
        SELECT payload_json FROM refresh_capture_receipts WHERE run_id='refresh-doctor'
      `).get() as { payload_json: string };
      const payload = JSON.parse(receipt.payload_json);
      const scoreMeta = JSON.parse(String(db.prepare(`
        SELECT value FROM meta WHERE key='score_persistence_last_run'
      `).get()?.value));
      db.prepare(`
        UPDATE meta SET value=? WHERE key='score_persistence_last_run'
      `).run(JSON.stringify({
        ...scoreMeta,
        source: 'refresh',
        operationReceiptRequired: true,
        operationRunId: 'refresh-doctor',
        codeRevision: payload.codeRevision,
        issueCrawlMetadataDigest: payload.issueCrawl.metadataDigest,
      }));
      const advisoryMetadata = JSON.parse(String(db.prepare(`
        SELECT value FROM meta WHERE key=?
      `).get(ADVISORY_SNAPSHOT_V2_META_KEY)?.value));
      db.prepare(`UPDATE meta SET value=? WHERE key=?`).run(
        canonicalOperationJson({
          ...advisoryMetadata,
          scoreRowCount: advisoryMetadata.scoreRowCount + 1,
        }),
        ADVISORY_SNAPSHOT_V2_META_KEY,
      );

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.ok(report.operationReceipts.currentScoreTipFailureCount > 0);
      assert.ok(report.operationReceipts.problems.some((problem: string) =>
        /current refresh score advisory v2 ledger is not authoritative/.test(problem)));
    } finally {
      cleanup();
    }
  });

  it('detects receipt hash tampering and broken score-history linkage', () => {
    const badLink = freshDoctorDb({
      operationReceipt: {
        historyContentHash: 'f'.repeat(64),
      },
    });
    try {
      const report = buildDoctorReport({
        dbPath: badLink.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.ok(report.operationReceipts.linkFailureCount > 0);
      assert.ok(report.failures.some((failure) =>
        /refresh operation receipt integrity failed/.test(failure)));
    } finally {
      badLink.cleanup();
    }

    const tampered = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(tampered.db, ['refresh_capture_receipts']);
      tampered.db.prepare(`
        UPDATE refresh_capture_receipts
        SET content_hash='tampered'
        WHERE run_id='refresh-doctor'
      `).run();
      const report = buildDoctorReport({
        dbPath: tampered.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.ok(report.operationReceipts.ledgerFailureCount > 0);
    } finally {
      tampered.cleanup();
    }
  });

  it('requires the current refresh score tip to have a non-bypassable success receipt', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const meta = JSON.parse((db.prepare(`
        SELECT value FROM meta WHERE key='score_persistence_last_run'
      `).get() as { value: string }).value);
      db.prepare(`
        UPDATE meta
        SET value=?
        WHERE key='score_persistence_last_run'
      `).run(JSON.stringify({
        ...meta,
        source: 'refresh',
        operationReceiptRequired: false,
        operationRunId: 'missing-current-receipt',
        codeRevision: 'doctor-current-revision',
      }));
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.ok(report.operationReceipts.currentScoreTipFailureCount > 0);
      assert.ok(report.failures.some((failure: string) =>
        /current score tip receipt authorization failed/.test(failure)));
      assert.ok(report.operationReceipts.problems.some((problem: string) =>
        /cannot disable operation receipt authorization/.test(problem)));
    } finally {
      cleanup();
    }
  });

  it('cannot bypass immutable receipt authorization by changing mutable score source', () => {
    const { db, dbPath, cleanup } = freshDoctorDb({
      operationReceipt: { includeScoreMetadata: true },
    });
    try {
      const receipt = db.prepare(`
        SELECT payload_json
        FROM refresh_capture_receipts
        WHERE run_id='refresh-doctor'
      `).get() as { payload_json: string };
      const immutableMeta = JSON.parse(receipt.payload_json).scoreMetadata;
      assert.equal(immutableMeta.source, 'refresh');
      db.prepare(`
        UPDATE meta SET value=? WHERE key='score_persistence_last_run'
      `).run(JSON.stringify(immutableMeta));
      const baseline = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(baseline.operationReceipts.problems.some((problem: string) =>
        /source does not match immutable refresh receipt\/history semantics/.test(problem)), false);
      assert.equal(baseline.operationReceipts.problems.some((problem: string) =>
        /metadata snapshot does not match current score metadata/.test(problem)), false);

      db.prepare(`
        UPDATE meta SET value=? WHERE key='score_persistence_last_run'
      `).run(JSON.stringify({
        ...immutableMeta,
        source: 'test',
        operationReceiptRequired: false,
      }));

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.ok(report.operationReceipts.currentScoreTipFailureCount > 0);
      assert.ok(report.operationReceipts.problems.some((problem: string) =>
        /source does not match immutable refresh receipt\/history semantics/.test(problem)));
      assert.ok(report.operationReceipts.problems.some((problem: string) =>
        /cannot disable operation receipt authorization/.test(problem)));
      assert.ok(report.operationReceipts.problems.some((problem: string) =>
        /metadata snapshot does not match current score metadata/.test(problem)));
    } finally {
      cleanup();
    }
  });

  it('treats an unterminated attempt without its matching active lease as a ledger failure', () => {
    const { db, dbPath, cleanup } = freshDoctorDb({
      operationReceipt: { unterminated: true },
    });
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.deepEqual(report.operationReceipts.invalidUnterminatedRunIds, ['refresh-doctor']);
      assert.equal(report.operationReceipts.activeUnterminatedRunIds.length, 0);
      assert.ok(report.operationReceipts.semanticFailureCount > 0);
      assert.ok(report.operationReceipts.problems.some((problem: string) =>
        /not backed by its active matching lease/.test(problem)));
    } finally {
      cleanup();
    }
  });
});

describe('doctor release catalog provenance', () => {
  it('accepts the immutable GitHub capture bound to the active projection and success receipt', () => {
    const { dbPath, cleanup } = freshDoctorDb();
    try {
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.releaseCatalogProvenance.status, 'verified');
      assert.equal(report.releaseCatalogProvenance.verifierInvoked, true);
      assert.equal(report.releaseCatalogProvenance.receiptCount, 1);
      assert.equal(report.releaseCatalogProvenance.attemptCount, 1);
      assert.equal(report.releaseCatalogProvenance.terminalReceiptCount, 1);
      assert.equal(report.releaseCatalogProvenance.latestReceipt.source, 'github_graphql');
      assert.equal(report.releaseCatalogProvenance.latestReceipt.terminalStatus, 'success');
      assert.deepEqual(report.releaseCatalogProvenance.problems, []);
      assert.ok(!report.failures.some((failure: string) =>
        /release catalog provenance verification failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails closed when the catalog receipt is missing or uses fixture authority', () => {
    const missing = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(
        missing.db,
        ['release_catalog_capture_receipts'],
      );
      missing.db.prepare(`DELETE FROM release_catalog_capture_receipts`).run();
      reinstallDoctorAppendOnlyTriggers(missing.db);
      const report = buildDoctorReport({
        dbPath: missing.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.releaseCatalogProvenance.status, 'invalid');
      assert.match(
        report.releaseCatalogProvenance.problems.join('\n'),
        /active release catalog has no valid immutable capture receipt/,
      );
      assert.ok(report.failures.some((failure: string) =>
        /release catalog provenance verification failed/.test(failure)));
    } finally {
      missing.cleanup();
    }

    const fixture = freshDoctorDb();
    try {
      rewriteDoctorReleaseCatalogReceipt(fixture.db, (payload) => ({
        ...payload,
        source: 'test_fixture',
        operationRunId: null,
        operation: null,
        operationAttemptContentHash: null,
        remoteCatalog: null,
      }));
      const report = buildDoctorReport({
        dbPath: fixture.dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.match(
        report.releaseCatalogProvenance.problems.join('\n'),
        /forbidden test_fixture authority/,
      );
      assert.match(
        report.releaseCatalogProvenance.problems.join('\n'),
        /test_fixture catalog receipt cannot authorize product reads or promotion/,
      );
      assert.ok(report.failures.some((failure: string) =>
        /release catalog provenance verification failed/.test(failure)));
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects failed and abandoned terminal refresh receipts', () => {
    for (const status of ['failure', 'abandoned'] as const) {
      const fixture = freshDoctorDb();
      try {
        rewriteDoctorTerminalReceiptStatus(fixture.db, status);
        const report = buildDoctorReport({
          dbPath: fixture.dbPath,
          sourceIdentityForDb: () => doctorSourceIdentityFixture,
        });

        assert.match(
          report.releaseCatalogProvenance.problems.join('\n'),
          new RegExp(`latest GitHub catalog capture run terminated with ${status}`),
        );
        assert.equal(
          report.releaseCatalogProvenance.latestReceipt.terminalStatus,
          status,
        );
        assert.ok(report.failures.some((failure: string) =>
          /release catalog provenance verification failed/.test(failure)));
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects tamper and wrong repository, run, or attempt-hash bindings', () => {
    const cases = [
      {
        name: 'tampered content hash',
        mutate(db: DatabaseSync) {
          disableDoctorAppendOnlyTriggers(
            db,
            ['release_catalog_capture_receipts'],
          );
          db.prepare(`
            UPDATE release_catalog_capture_receipts
            SET content_hash=?
          `).run('f'.repeat(64));
          reinstallDoctorAppendOnlyTriggers(db);
        },
        expected: /content hash mismatch/,
      },
      {
        name: 'wrong repository',
        mutate(db: DatabaseSync) {
          rewriteDoctorReleaseCatalogReceipt(db, (payload) => ({
            ...payload,
            repository: 'other/repository',
            remoteCatalog: {
              ...payload.remoteCatalog,
              repositoryNameWithOwner: 'other/repository',
            },
          }));
        },
        expected: /repository does not match/,
      },
      {
        name: 'wrong run',
        mutate(db: DatabaseSync) {
          rewriteDoctorReleaseCatalogReceipt(db, (payload) => ({
            ...payload,
            operationRunId: 'missing-release-catalog-run',
          }));
        },
        expected: /missing refresh operation attempt/,
      },
      {
        name: 'wrong attempt hash',
        mutate(db: DatabaseSync) {
          rewriteDoctorReleaseCatalogReceipt(db, (payload) => ({
            ...payload,
            operationAttemptContentHash: 'e'.repeat(64),
          }));
        },
        expected: /does not bind the exact refresh operation attempt/,
      },
    ];

    for (const testCase of cases) {
      const fixture = freshDoctorDb();
      try {
        testCase.mutate(fixture.db);
        const report = buildDoctorReport({
          dbPath: fixture.dbPath,
          sourceIdentityForDb: () => doctorSourceIdentityFixture,
        });

        assert.match(
          report.releaseCatalogProvenance.problems.join('\n'),
          testCase.expected,
          testCase.name,
        );
        assert.ok(report.releaseCatalogProvenance.problems.length <= 12);
        assert.ok(report.failures.some((failure: string) =>
          /release catalog provenance verification failed/.test(failure)));
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects an active projection that no longer matches the receipt', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`
        UPDATE releases
        SET body='projection drift'
        WHERE tag='v1'
      `).run();
      const changed = currentActiveReleaseCatalogForDoctor(db);
      assert.ok(changed.digest);
      db.prepare(`
        UPDATE releases
        SET catalog_digest=?
        WHERE catalog_active=1
      `).run(changed.digest);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.releaseCatalogProvenance.projectionProblemCount, 0);
      assert.match(
        report.releaseCatalogProvenance.problems.join('\n'),
        /latest catalog capture receipt does not match the exact active catalog projection/,
      );
      assert.ok(report.failures.some((failure: string) =>
        /release catalog provenance verification failed/.test(failure)));
    } finally {
      cleanup();
    }
  });
});

describe('doctor state-event projection parity', () => {
  it('detects ordinal, actor, and closer tampering against the verified snapshot', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const issueNodeId = 'I_doctor_1';
      const events = normalizeIssueStateEvents([{
        eventId: 'doctor-close-1',
        eventNodeType: 'ClosedEvent',
        type: 'closed',
        occurredAt: '2026-06-02T00:55:00Z',
        connectionOrdinal: 0,
        actorNodeId: 'U_doctor_maintainer',
        actorLogin: 'maintainer',
        actorType: 'User',
        stateReason: 'COMPLETED',
        closerNodeId: 'PR_doctor_42',
        closerType: 'PullRequest',
        closerNumber: 42,
        closerOid: 'a'.repeat(40),
      }]);
      const closedStateSnapshot = doctorStateSnapshotIdentity({
        issueNumber: 1,
        issueNodeId,
        issueState: 'closed',
        issueUpdatedAt: events[0].occurredAt,
        events,
      });
      db.prepare(`
        UPDATE issues
        SET state='closed', updated_at=?, closed_at=?
        WHERE number=1
      `).run(events[0].occurredAt, events[0].occurredAt);
      db.prepare(`
        UPDATE issue_state_event_snapshots
        SET repository_node_id=?, issue_node_id=?, issue_node_type=?, schema_version=?,
            issue_state='closed', issue_updated_at=?, total_count=1, fetched_count=1,
            events_digest=?, authority_digest=?, events_json=?,
            stabilization_json=?, stabilization_identity_digest=?
        WHERE issue_number=1
      `).run(
        closedStateSnapshot.repositoryNodeId,
        issueNodeId,
        closedStateSnapshot.issueNodeType,
        ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
        events[0].occurredAt,
        closedStateSnapshot.eventsDigest,
        closedStateSnapshot.authorityDigest,
        JSON.stringify(closedStateSnapshot.events),
        JSON.stringify(closedStateSnapshot.stabilization),
        closedStateSnapshot.stabilization.identityDigest,
      );
      db.prepare(`
        INSERT INTO issue_closure_events (
          issue_number, issue_node_id, event_id, closed_at, connection_ordinal,
          actor_node_id, actor_login, actor_type, state_reason,
          closer_type, closer_number, closer_node_id, closer_oid, raw_json, fetched_at
        )
        VALUES (
          1, ?, ?, ?, 0, ?, 'maintainer', 'User', 'COMPLETED',
          'PullRequest', 42, ?, ?, '{}', ?
        )
      `).run(
        issueNodeId,
        events[0].eventId,
        events[0].occurredAt,
        events[0].actorNodeId,
        events[0].closerNodeId,
        events[0].closerOid,
        events[0].occurredAt,
      );

      const baseline = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(baseline.stateSnapshots.projectionMismatchCount, 0);

      const mutations = [
        `connection_ordinal=1`,
        `actor_login='attacker'`,
        `actor_type='Bot'`,
        `closer_number=99`,
        `closer_node_id='PR_doctor_attacker'`,
      ];
      for (const mutation of mutations) {
        db.prepare(`
          UPDATE issue_closure_events
          SET ${mutation}
          WHERE event_id='doctor-close-1'
        `).run();
        const report = buildDoctorReport({
          dbPath,
          sourceIdentityForDb: () => doctorSourceIdentityFixture,
        });
        assert.equal(report.stateSnapshots.projectionMismatchCount, 1, mutation);
        db.prepare(`
          UPDATE issue_closure_events
          SET connection_ordinal=0, actor_login='maintainer', actor_type='User',
              closer_number=42, closer_node_id='PR_doctor_42'
          WHERE event_id='doctor-close-1'
        `).run();
      }
    } finally {
      cleanup();
    }
  });
});

describe('doctor issue catalog snapshot integrity', () => {
  it('reports a valid consumed snapshot as consumed rather than resumable', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      seedDoctorCleanIssueCrawl(db);
      const report = buildDoctorReport({
        dbPath,
        now: new Date('2026-06-02T02:00:00.000Z'),
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.issueCatalogSnapshots.failedCount, 0);
      assert.equal(report.issueCatalogSnapshots.consumptionCount, 1);
      assert.equal(report.issueCatalogSnapshots.latest.status, 'consumed');
      assert.equal(
        report.issueCatalogSnapshots.latest.consumption.runId,
        'doctor-refresh-run',
      );
    } finally {
      cleanup();
    }
  });

  it('reports a valid but expired snapshot as stale without failing health', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      insertDoctorIssueCatalogSnapshot(db, '2026-07-02T00:00:00.000Z');
      const report = buildDoctorReport({
        dbPath,
        now: new Date('2026-07-04T12:00:00.000Z'),
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.issueCatalogSnapshots.failedCount, 0);
      assert.equal(report.issueCatalogSnapshots.latest.status, 'stale');
      assert.equal(
        report.failures.some((failure) => /issue catalog snapshot integrity failed/.test(failure)),
        false,
      );
    } finally {
      cleanup();
    }
  });

  it('fails health when immutable issue catalog row content is corrupted', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const snapshotId = insertDoctorIssueCatalogSnapshot(
        db,
        '2026-07-04T11:00:00.000Z',
      );
      disableDoctorAppendOnlyTriggers(db, ['issue_catalog_snapshot_rows']);
      db.prepare(`
        UPDATE issue_catalog_snapshot_rows
        SET issue_json=replace(issue_json, 'Doctor issue', 'Corrupted issue')
        WHERE snapshot_id=?
      `).run(snapshotId);

      const report = buildDoctorReport({
        dbPath,
        now: new Date('2026-07-04T12:00:00.000Z'),
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.ok(report.issueCatalogSnapshots.ledgerFailureCount > 0);
      assert.ok(report.failures.some((failure) =>
        /issue catalog snapshot integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when the consumption chain or canonical hash is corrupted', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const first = insertDoctorIssueCatalogSnapshot(db, '2026-07-04T08:00:00.000Z');
      insertDoctorIssueCatalogConsumption(db, first, {
        runId: 'doctor-consumption-1',
        consumedAt: '2026-07-04T08:05:00.000Z',
      });
      const second = insertDoctorIssueCatalogSnapshot(db, '2026-07-04T09:00:00.000Z');
      insertDoctorIssueCatalogConsumption(db, second, {
        runId: 'doctor-consumption-2',
        consumedAt: '2026-07-04T09:05:00.000Z',
      });
      disableDoctorAppendOnlyTriggers(db, ['issue_catalog_snapshot_consumptions']);
      db.prepare(`
        UPDATE issue_catalog_snapshot_consumptions
        SET previous_content_hash=?, content_hash=?
        WHERE snapshot_id=?
      `).run('f'.repeat(64), 'e'.repeat(64), second);

      const report = buildDoctorReport({
        dbPath,
        now: new Date('2026-07-04T10:00:00.000Z'),
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.ok(report.issueCatalogSnapshots.consumptionFailureCount >= 2);
      assert.ok(report.issueCatalogSnapshots.examples.some((problem: any) =>
        /preceding consumption|canonical consumption payload/.test(problem.detail)));
    } finally {
      cleanup();
    }
  });

  it('fails when crawl consumption or publication attestation links drift', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      seedDoctorCleanIssueCrawl(db);
      const row = db.prepare(`
        SELECT value FROM meta WHERE key='issue_crawl_last_run'
      `).get() as { value: string };
      const crawl = JSON.parse(row.value);
      crawl.catalogSnapshot.consumptionContentHash = 'f'.repeat(64);
      crawl.catalogAttestation.membershipDigest = 'e'.repeat(64);
      db.prepare(`
        UPDATE meta SET value=? WHERE key='issue_crawl_last_run'
      `).run(JSON.stringify(crawl));

      const report = buildDoctorReport({
        dbPath,
        now: new Date('2026-06-02T02:00:00.000Z'),
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.ok(report.issueCatalogSnapshots.crawlLinkFailureCount >= 2);
      assert.ok(report.failures.some((failure) =>
        /issue catalog snapshot integrity failed/.test(failure)));
      assert.ok(report.failures.some((failure) =>
        /catalogAttestation membershipDigest must match exhaustive pagination/.test(failure)));
    } finally {
      cleanup();
    }
  });
});

describe('doctor append-only trigger integrity', () => {
  it('verifies every required trigger and isolated update/delete/replace behavior', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      const historyBefore = db.prepare(`
        SELECT *
        FROM release_score_audit_history
        ORDER BY id
      `).all();
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      const historyAfter = db.prepare(`
        SELECT *
        FROM release_score_audit_history
        ORDER BY id
      `).all();

      assert.equal(
        report.appendOnlyTriggers.requiredCount,
        APPEND_ONLY_TRIGGER_SPECS.length,
      );
      assert.equal(
        report.appendOnlyTriggers.requiredTableCount,
        IMMUTABLE_LEDGER_TABLES.length,
      );
      assert.equal(
        report.appendOnlyTriggers.presentCount,
        APPEND_ONLY_TRIGGER_SPECS.length,
      );
      assert.equal(report.appendOnlyTriggers.shapeFailureCount, 0);
      assert.equal(report.appendOnlyTriggers.behaviorFailureCount, 0);
      assert.equal(report.appendOnlyTriggers.unexpectedCount, 0);
      assert.equal(report.appendOnlyTriggers.failedCount, 0);
      assert.ok(IMMUTABLE_LEDGER_TABLES.every(
        (table) => report.tables[table]?.present === true,
      ));
      assert.deepEqual(
        report.appendOnlyTriggers.tableChecks.map((check: any) => check.table),
        IMMUTABLE_LEDGER_TABLES,
      );
      assert.ok(report.appendOnlyTriggers.tableChecks.every((check: any) =>
        check.recursiveTriggersEnabled &&
        check.update.valid &&
        check.delete.valid &&
        check.replace.valid));
      assert.deepEqual(historyAfter, historyBefore);
    } finally {
      cleanup();
    }
  });

  it('fails when a canonical immutable ledger table is missing', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`DROP TABLE classifier_attempt_runs`);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.tables.classifier_attempt_runs.present, false);
      assert.equal(report.appendOnlyTriggers.missingCount, 2);
      assert.ok(report.failures.includes(
        'missing core table classifier_attempt_runs',
      ));
    } finally {
      cleanup();
    }
  });

  it('rejects undeclared unconditional append-only guards', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        CREATE TABLE undeclared_immutable_ledger (
          ledger_id TEXT PRIMARY KEY
        );
        CREATE TRIGGER undeclared_immutable_ledger_block_update
        BEFORE UPDATE ON undeclared_immutable_ledger
        BEGIN
          SELECT RAISE(ABORT, 'immutable ledger rows cannot be updated');
        END;
        CREATE TRIGGER undeclared_immutable_ledger_block_delete
        BEFORE DELETE ON undeclared_immutable_ledger
        BEGIN
          SELECT RAISE(ABORT, 'immutable ledger rows cannot be deleted');
        END;
      `);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.appendOnlyTriggers.unexpectedCount, 2);
      assert.deepEqual(
        report.appendOnlyTriggers.unexpected
          .map((item: any) => item.name)
          .sort(),
        [
          'undeclared_immutable_ledger_block_delete',
          'undeclared_immutable_ledger_block_update',
        ],
      );
      assert.ok(report.failures.some((failure) =>
        /append-only trigger verification failed .*unexpected=2/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('ignores conditional field guards and singleton delete guards', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        CREATE TABLE mutable_singleton (
          id INTEGER PRIMARY KEY,
          revision INTEGER NOT NULL
        );
        CREATE TRIGGER mutable_singleton_no_delete
        BEFORE DELETE ON mutable_singleton
        BEGIN
          SELECT RAISE(ABORT, 'mutable singleton cannot be deleted');
        END;
        CREATE TRIGGER releases_score_update_guard
        BEFORE UPDATE OF final_score ON releases
        WHEN NEW.final_score < 0
        BEGIN
          SELECT RAISE(ABORT, 'final score cannot be negative');
        END;
      `);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.appendOnlyTriggers.unexpectedCount, 0);
    } finally {
      cleanup();
    }
  });

  it('fails when a required trigger is removed', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`DROP TRIGGER release_validation_forecasts_no_delete`);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.appendOnlyTriggers.missingCount, 1);
      assert.ok(report.failures.some((failure) =>
        /append-only trigger verification failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails on a correctly named but bypassable trigger', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        DROP TRIGGER release_validation_forecasts_no_update;
        CREATE TRIGGER release_validation_forecasts_no_update
        BEFORE UPDATE OF never_written ON release_validation_forecasts
        BEGIN
          SELECT RAISE(ABORT, 'release_validation_forecasts is append-only');
        END;
      `);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      const check = report.appendOnlyTriggers.checks.find(
        (item: any) => item.name === 'release_validation_forecasts_no_update',
      );

      assert.equal(check.shapeValid, false);
      assert.equal(check.behaviorValid, false);
      assert.equal(report.appendOnlyTriggers.shapeFailureCount, 1);
      assert.equal(report.appendOnlyTriggers.behaviorFailureCount, 1);
    } finally {
      cleanup();
    }
  });

  it('rejects a delete guard that permits DELETE and INSERT OR REPLACE', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        DROP TRIGGER release_validation_observation_batches_no_delete;
        CREATE TRIGGER release_validation_observation_batches_no_delete
        BEFORE DELETE ON release_validation_observation_batches
        WHEN 0
        BEGIN
          SELECT RAISE(ABORT, 'release_validation_observation_batches is append-only');
        END;
      `);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      const tableCheck = report.appendOnlyTriggers.tableChecks.find(
        (item: any) => item.table === 'release_validation_observation_batches',
      );
      const triggerCheck = report.appendOnlyTriggers.checks.find(
        (item: any) =>
          item.name === 'release_validation_observation_batches_no_delete',
      );

      assert.equal(tableCheck.delete.valid, false);
      assert.equal(tableCheck.replace.valid, false);
      assert.equal(triggerCheck.shapeValid, false);
      assert.equal(triggerCheck.behaviorValid, false);
    } finally {
      cleanup();
    }
  });
});

describe('doctor validation outcome uniqueness', () => {
  it('fails on a fully rehashed authority-chain break', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'score_authority_resolution_runs',
      ]);
      const stored = db.prepare(`
        SELECT *
        FROM score_authority_resolution_runs
        WHERE authority_run_id='score-authority:run-doctor'
      `).get() as any;
      const rebuilt = buildScoreAuthorityResolutionRun({
        authorityRunId: stored.authority_run_id,
        sourceIdentitySchemaVersion: stored.source_identity_schema_version,
        sourceIdentityDigest: stored.source_identity_digest,
        recordedAt: stored.recorded_at,
        previousContentHash: 'f'.repeat(64),
        rows: [],
      });
      db.prepare(`
        UPDATE score_authority_resolution_runs
        SET previous_content_hash=?, content_hash=?
        WHERE authority_run_id=?
      `).run(
        rebuilt.previousContentHash,
        rebuilt.contentHash,
        rebuilt.authorityRunId,
      );

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.validation.authorityRunIntegrityFailureCount, 0);
      assert.ok(report.validation.authorityChainFailureCount > 0);
      assert.ok(report.validation.failedCount > 0);
      assert.ok(report.failures.some((failure: string) =>
        /validation ledger integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails on a fully rehashed history-v2 chain break', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      disableDoctorAppendOnlyTriggers(db, [
        'release_score_audit_history_v2_seals',
      ]);
      const stored = db.prepare(`
        SELECT *
        FROM release_score_audit_history_v2_seals
        WHERE history_run_id='run-doctor'
      `).get() as any;
      const rebuilt = buildReleaseScoreAuditHistoryV2Seal({
        historyRunId: stored.history_run_id,
        authorityRunId: stored.authority_run_id,
        sealedAt: stored.sealed_at,
        historyRowCount: stored.history_row_count,
        historyRowsContentHash: stored.history_rows_content_hash,
        authorityRowCount: stored.authority_row_count,
        authorityRowsContentHash: stored.authority_rows_content_hash,
        previousContentHash: 'e'.repeat(64),
      });
      db.prepare(`
        UPDATE release_score_audit_history_v2_seals
        SET previous_content_hash=?, content_hash=?
        WHERE history_run_id=?
      `).run(
        rebuilt.previousContentHash,
        rebuilt.contentHash,
        rebuilt.historyRunId,
      );

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.validation.historyV2SealIntegrityFailureCount, 0);
      assert.ok(report.validation.historyV2ChainFailureCount > 0);
      assert.ok(report.validation.failedCount > 0);
      assert.ok(report.failures.some((failure: string) =>
        /validation ledger integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('reports legacy forecasts that fall outside their bounded opportunity window', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.prepare(`
        INSERT INTO release_validation_forecasts (
          id, decision_id, opportunity_code, recorded_at, latest_release_tag,
          latest_release_published_at, selected_tag, audit_history_run_id,
          score_model_version, prompt_version, policy_code, candidate_scores_json,
          decision_json, source_identity_json, code_revision, previous_content_hash,
          content_hash
        )
        VALUES (
          1, 'legacy-late-decision', 'first_verified_after_3h',
          '2026-06-02T01:00:00Z', 'v2', '2026-06-01T00:00:00Z', 'v2',
          'run-doctor', 'test-model', 6, 'policy', '[]',
          '{"schemaVersion":2,"opportunityCode":"first_verified_after_3h","recordedAt":"2026-06-02T01:00:00Z","latestReleaseTag":"v2","latestReleasePublishedAt":"2026-06-01T00:00:00Z","selectedTag":"v2","recommendationDecision":{"selectedTag":"v2","policyCode":"policy"}}',
          '{"digest":"test"}', NULL, NULL, 'legacy-late-hash'
        )
      `).run();
      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.validation.legacyLateForecastCount, 1);
      assert.ok(report.legacyFindings.some((finding: string) =>
        /outside their bounded opportunity window/.test(finding)));
    } finally {
      cleanup();
    }
  });

  it('warns instead of failing for obsolete manifests on a structurally valid excluded legacy forecast', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      seedDoctorLegacyManifestForecast(db, { outOfWindow: true });
      seedDoctorCleanIssueCrawl(db);

      const report = buildDoctorReport({
        dbPath,
        failOnWarnings: true,
        now: new Date('2026-06-02T02:00:00Z'),
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.validation.legacyLateForecastCount, 1);
      assert.equal(report.validation.forecastSourceManifestFailureCount, 0);
      assert.equal(report.validation.referencedHistorySourceManifestFailureCount, 0);
      assert.equal(report.validation.legacyForecastSourceManifestWarningCount, 1);
      assert.equal(report.validation.legacyReferencedHistorySourceManifestWarningCount, 1);
      assert.equal(report.validation.legacyManifestCompatibilityWarningCount, 2);
      assert.equal(
        report.validation.failedCount,
        0,
        JSON.stringify(report.validation, null, 2),
      );
      assert.equal(report.scoreHistory.currentTipSourceManifestFailureCount, 0);
      assert.equal(report.scoreHistory.sourceManifestFailureCount, 1);
      assert.deepEqual(report.warnings, []);
      assert.ok(report.legacyFindings.some((finding: string) =>
        /obsolete source schema 4/.test(finding)));
      assert.equal(report.ok, true, JSON.stringify({
        warnings: report.warnings,
        failures: report.failures,
        operationReceiptProblems: report.operationReceipts.problems,
        legacyFindings: report.legacyFindings,
      }, null, 2));
      assert.ok(!report.failures.some((failure: string) =>
        /validation ledger integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('keeps in-window v1-v3 forecasts readable but non-evaluable', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      seedDoctorLegacyManifestForecast(db, { outOfWindow: false });

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.validation.legacyLateForecastCount, 0);
      assert.equal(report.validation.legacyDecisionSchemaCount, 1);
      assert.equal(report.validation.forecastSourceManifestFailureCount, 0);
      assert.equal(report.validation.referencedHistorySourceManifestFailureCount, 0);
      assert.equal(report.validation.legacyManifestCompatibilityWarningCount, 2);
      assert.equal(report.validation.failedCount, 0);
      assert.ok(report.legacyFindings.some((finding: string) =>
        /decision schema v1-v3/.test(finding)));
    } finally {
      cleanup();
    }
  });

  it('keeps structurally corrupt obsolete manifests fatal even when the forecast is excluded', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      seedDoctorLegacyManifestForecast(db, {
        outOfWindow: true,
        corruptManifest: true,
      });

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });

      assert.equal(report.validation.legacyLateForecastCount, 1);
      assert.equal(report.validation.legacyManifestCompatibilityWarningCount, 0);
      assert.equal(report.validation.forecastSourceManifestFailureCount, 1);
      assert.equal(report.validation.referencedHistorySourceManifestFailureCount, 1);
      assert.ok(report.validation.errors.some((error: string) =>
        /digest does not match the ordered source manifest/.test(error)));
      assert.ok(report.failures.some((failure: string) =>
        /validation ledger integrity failed/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when legacy forecast uniqueness can suppress a new scoring series', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`
        CREATE UNIQUE INDEX legacy_release_validation_forecast_identity
        ON release_validation_forecasts(opportunity_code, latest_release_tag)
      `);

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.validation.forecastSeriesUniqueIndexFailureCount, 1);
      assert.ok(report.failures.some((failure) =>
        /forecastSeriesUniqueIndex=1/.test(failure)));
    } finally {
      cleanup();
    }
  });

  it('fails when the matured partial unique index is missing or duplicate keys exist', () => {
    const { db, dbPath, cleanup } = freshDoctorDb();
    try {
      db.exec(`DROP INDEX idx_release_validation_outcomes_one_matured`);
      db.prepare(`
        INSERT INTO release_validation_forecasts (
          id, decision_id, opportunity_code, recorded_at, latest_release_tag,
          latest_release_published_at, selected_tag, audit_history_run_id,
          score_model_version, prompt_version, policy_code, candidate_scores_json,
          decision_json, source_identity_json, previous_content_hash, content_hash
        )
        VALUES (
          1, 'decision-duplicate', 'first_verified_after_24h',
          '2026-06-02T01:05:00Z', 'v2', '2026-06-02T00:00:00Z', 'v2',
          'run-doctor', 'test-model', 6, 'policy', '[]', '{}',
          '{"digest":"test"}', NULL, 'forecast-hash'
        )
      `).run();
      const insertOutcome = db.prepare(`
        INSERT INTO release_validation_outcome_observations (
          id, observation_id, decision_id, horizon_code, observed_at, status,
          outcome_json, source_identity_json, previous_content_hash, content_hash
        )
        VALUES (?, ?, 'decision-duplicate', 'field_regression_72h', ?, 'matured',
          '{}', '{"digest":"test"}', ?, ?)
      `);
      insertOutcome.run(1, 'observation-1', '2026-06-05T01:05:00Z', null, 'outcome-1');
      insertOutcome.run(2, 'observation-2', '2026-06-05T01:05:01Z', 'outcome-1', 'outcome-2');

      const report = buildDoctorReport({
        dbPath,
        sourceIdentityForDb: () => doctorSourceIdentityFixture,
      });
      assert.equal(report.validation.duplicateMaturedOutcomeCount, 1);
      assert.equal(report.validation.maturedUniqueIndexFailureCount, 1);
      assert.ok(report.validation.forecastHashFailureCount > 0);
      assert.ok(report.validation.outcomeHashFailureCount > 0);
      assert.ok(report.failures.some((failure) => /duplicateMatured=1/.test(failure)));
    } finally {
      cleanup();
    }
  });
});

function installDoctorAppendOnlyTriggers(db: DatabaseSync) {
  db.exec(`
    CREATE TRIGGER advisory_snapshot_history_no_update
    BEFORE UPDATE ON advisory_snapshot_history
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_history_no_delete
    BEFORE DELETE ON advisory_snapshot_history
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_rows_no_update
    BEFORE UPDATE ON advisory_snapshot_rows
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_rows is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_rows_no_delete
    BEFORE DELETE ON advisory_snapshot_rows
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_rows is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_history_no_update
    BEFORE UPDATE ON advisory_snapshot_v2_history
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_history_no_delete
    BEFORE DELETE ON advisory_snapshot_v2_history
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_rows_no_update
    BEFORE UPDATE ON advisory_snapshot_v2_rows
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_rows is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_rows_no_delete
    BEFORE DELETE ON advisory_snapshot_v2_rows
    BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_rows is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshots_no_update
    BEFORE UPDATE ON issue_catalog_snapshots
    BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshots is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshots_no_delete
    BEFORE DELETE ON issue_catalog_snapshots
    BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshots is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_rows_no_update
    BEFORE UPDATE ON issue_catalog_snapshot_rows
    BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_rows is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_rows_no_delete
    BEFORE DELETE ON issue_catalog_snapshot_rows
    BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_rows is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_consumptions_no_update
    BEFORE UPDATE ON issue_catalog_snapshot_consumptions
    BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_consumptions is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_consumptions_no_delete
    BEFORE DELETE ON issue_catalog_snapshot_consumptions
    BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_consumptions is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_no_update
    BEFORE UPDATE ON release_score_audit_history
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_no_delete
    BEFORE DELETE ON release_score_audit_history
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_runs_no_update
    BEFORE UPDATE ON release_score_audit_history_runs
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history_runs is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_runs_no_delete
    BEFORE DELETE ON release_score_audit_history_runs
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history_runs is append-only');
    END;
    CREATE TRIGGER score_authority_resolution_runs_no_update
    BEFORE UPDATE ON score_authority_resolution_runs
    BEGIN
      SELECT RAISE(ABORT, 'score_authority_resolution_runs is append-only');
    END;
    CREATE TRIGGER score_authority_resolution_runs_no_delete
    BEFORE DELETE ON score_authority_resolution_runs
    BEGIN
      SELECT RAISE(ABORT, 'score_authority_resolution_runs is append-only');
    END;
    CREATE TRIGGER score_authority_resolution_rows_no_update
    BEFORE UPDATE ON score_authority_resolution_rows
    BEGIN
      SELECT RAISE(ABORT, 'score_authority_resolution_rows is append-only');
    END;
    CREATE TRIGGER score_authority_resolution_rows_no_delete
    BEFORE DELETE ON score_authority_resolution_rows
    BEGIN
      SELECT RAISE(ABORT, 'score_authority_resolution_rows is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_v2_seals_no_update
    BEFORE UPDATE ON release_score_audit_history_v2_seals
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history_v2_seals is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_v2_seals_no_delete
    BEFORE DELETE ON release_score_audit_history_v2_seals
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history_v2_seals is append-only');
    END;
    CREATE TRIGGER release_validation_forecasts_no_update
    BEFORE UPDATE ON release_validation_forecasts
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_forecasts is append-only');
    END;
    CREATE TRIGGER release_validation_forecasts_no_delete
    BEFORE DELETE ON release_validation_forecasts
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_forecasts is append-only');
    END;
    CREATE TRIGGER release_validation_opportunity_enrollments_no_update
    BEFORE UPDATE ON release_validation_opportunity_enrollments
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_opportunity_enrollments is append-only');
    END;
    CREATE TRIGGER release_validation_opportunity_enrollments_no_delete
    BEFORE DELETE ON release_validation_opportunity_enrollments
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_opportunity_enrollments is append-only');
    END;
    CREATE TRIGGER release_validation_outcomes_no_update
    BEFORE UPDATE ON release_validation_outcome_observations
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_outcome_observations is append-only');
    END;
    CREATE TRIGGER release_validation_outcomes_no_delete
    BEFORE DELETE ON release_validation_outcome_observations
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_outcome_observations is append-only');
    END;
    CREATE TRIGGER release_validation_observation_batches_no_update
    BEFORE UPDATE ON release_validation_observation_batches
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_observation_batches is append-only');
    END;
    CREATE TRIGGER release_validation_observation_batches_no_delete
    BEFORE DELETE ON release_validation_observation_batches
    BEGIN
      SELECT RAISE(ABORT, 'release_validation_observation_batches is append-only');
    END;
    CREATE TRIGGER refresh_operation_attempts_no_update
    BEFORE UPDATE ON refresh_operation_attempts
    BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_attempts is append-only');
    END;
    CREATE TRIGGER refresh_operation_attempts_no_delete
    BEFORE DELETE ON refresh_operation_attempts
    BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_attempts is append-only');
    END;
    CREATE TRIGGER refresh_operation_stage_events_no_update
    BEFORE UPDATE ON refresh_operation_stage_events
    BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_stage_events is append-only');
    END;
    CREATE TRIGGER refresh_operation_stage_events_no_delete
    BEFORE DELETE ON refresh_operation_stage_events
    BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_stage_events is append-only');
    END;
    CREATE TRIGGER refresh_capture_receipts_no_update
    BEFORE UPDATE ON refresh_capture_receipts
    BEGIN
      SELECT RAISE(ABORT, 'refresh_capture_receipts is append-only');
    END;
    CREATE TRIGGER refresh_capture_receipts_no_delete
    BEFORE DELETE ON refresh_capture_receipts
    BEGIN
      SELECT RAISE(ABORT, 'refresh_capture_receipts is append-only');
    END;
  `);

  const existingTables = new Set(
    (db.prepare(`
      SELECT name
      FROM sqlite_schema
      WHERE type='table'
    `).all() as Array<{ name: string }>).map(({ name }) => name),
  );
  for (const table of IMMUTABLE_LEDGER_TABLES) {
    if (existingTables.has(table)) continue;
    const quotedTable = `"${table.replaceAll('"', '""')}"`;
    db.exec(`
      CREATE TABLE ${quotedTable} (
        ledger_id TEXT PRIMARY KEY,
        content_hash TEXT NOT NULL UNIQUE
      )
    `);
  }

  const existingTriggers = new Set(
    (db.prepare(`
      SELECT name
      FROM sqlite_schema
      WHERE type='trigger'
    `).all() as Array<{ name: string }>).map(({ name }) => name),
  );
  for (const spec of APPEND_ONLY_TRIGGER_SPECS) {
    if (existingTriggers.has(spec.name)) continue;
    db.exec(`
      CREATE TRIGGER ${spec.name}
      BEFORE ${spec.event} ON ${spec.table}
      BEGIN
        SELECT RAISE(ABORT, '${spec.message}');
      END
    `);
  }
}

function disableDoctorAppendOnlyTriggers(db: DatabaseSync, tables: string[]) {
  const tableSet = new Set(tables);
  const rows = db.prepare(`
    SELECT name, tbl_name
    FROM sqlite_schema
    WHERE type='trigger'
  `).all() as Array<{ name: string; tbl_name: string }>;
  for (const row of rows) {
    if (!tableSet.has(row.tbl_name)) continue;
    db.exec(`DROP TRIGGER "${row.name.replaceAll('"', '""')}"`);
  }
}

function createDoctorProofRecordTables(db: DatabaseSync) {
  for (const [table, idColumn] of [
    ['release_validation_proof_epochs', 'proof_epoch_id'],
    ['release_validation_proof_epoch_retirements', 'retirement_id'],
    ['release_validation_policies', 'policy_id'],
    ['release_validation_cohorts', 'cohort_id'],
    ['release_validation_catalog_observations', 'observation_id'],
    ['release_validation_catalog_members', 'member_id'],
    ['release_validation_catalog_reconciliations', 'reconciliation_id'],
    [
      'release_validation_catalog_reconciliation_rows',
      'reconciliation_row_id',
    ],
    ['release_validation_obligations', 'obligation_id'],
    ['release_validation_split_assignments', 'assignment_id'],
    ['release_validation_forecasts_v2', 'forecast_id'],
    ['release_validation_outcomes_v2', 'outcome_id'],
    ['release_validation_proof_observation_batches', 'batch_id'],
    ['release_validation_evaluation_receipts', 'evaluation_id'],
    ['release_validation_promotion_receipts', 'promotion_id'],
  ]) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS ${table} (
        ${idColumn} TEXT PRIMARY KEY,
        content_hash TEXT NOT NULL,
        record_json TEXT NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS ${table}_no_update
      BEFORE UPDATE ON ${table}
      BEGIN
        SELECT RAISE(ABORT, '${table} is append-only');
      END;
      CREATE TRIGGER IF NOT EXISTS ${table}_no_delete
      BEFORE DELETE ON ${table}
      BEGIN
        SELECT RAISE(ABORT, '${table} is append-only');
      END;
    `);
  }
}

function insertDoctorProductionValidationProof(db: DatabaseSync) {
  const repository = 'openclaw/openclaw';
  const epoch = sealReleaseValidationProofEpoch({
    repository,
    recordedAt: '2026-01-01T00:00:00Z',
    startsAt: '2026-01-01T00:00:00Z',
  });
  const policy = sealReleaseValidationPolicy({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 1,
    previousEpochContentHash: null,
    policyCode: 'doctor-fixture-v1',
    policyVersion: 1,
    recordedAt: '2026-01-01T00:00:00Z',
    effectiveAt: '2026-01-01T00:00:00Z',
    requiredCells: [{
      opportunityCode: 'first_verified_after_3h',
      horizonCode: 'field_regression_72h',
    }],
  });
  const cell = policy.requiredCells[0];
  const cohort = sealReleaseValidationCohort({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 2,
    previousEpochContentHash: policy.contentHash,
    policyId: policy.policyId,
    policyContentHash: policy.contentHash,
    modelVersion: 'doctor-model-v1',
    promptVersion: 1,
    codeRevision: 'doctor-test-revision',
    recordedAt: '2026-01-01T00:01:00Z',
    startsAt: '2026-01-01T00:01:00Z',
    requiredCellIds: [cell.cellId],
  });
  const release = createReleaseValidationStableReleaseIdentity({
    repository,
    nodeId: 'doctor-release-node',
    tagCommitOid: '1'.repeat(40),
    publishedAt: '2026-01-01T00:01:00Z',
    aliases: ['v-doctor'],
  });
  const catalog = sealReleaseValidationCatalogObservation({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 3,
    previousEpochContentHash: cohort.contentHash,
    source: 'github',
    observedAt: '2026-01-01T00:02:00Z',
    exhaustive: true,
    stabilized: true,
    releases: [release],
  });
  const reconciliation = sealReleaseValidationCatalogReconciliation({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 4,
    previousEpochContentHash: catalog.observation.contentHash,
    reconciledAt: '2026-01-01T00:03:00Z',
    previousObservation: null,
    currentObservation: catalog.observation,
    currentMembers: catalog.members,
  });
  const obligation = sealReleaseValidationObligation({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 1,
    previousCohortContentHash: null,
    cellId: cell.cellId,
    opportunityCode: cell.opportunityCode,
    horizonCode: cell.horizonCode,
    release,
    recordedAt: '2026-01-01T00:04:00Z',
    opensAt: '2026-01-01T01:00:00Z',
    closesAtExclusive: '2026-01-01T02:00:00Z',
    outcomeDueAt: '2026-01-01T03:00:00Z',
    catalogObservationId: catalog.observation.observationId,
    catalogObservationContentHash: catalog.observation.contentHash,
    reconciliationId: reconciliation.reconciliation.reconciliationId,
    reconciliationContentHash: reconciliation.reconciliation.contentHash,
  });
  const assignment = sealReleaseValidationSplitAssignment({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 2,
    previousCohortContentHash: obligation.contentHash,
    obligationId: obligation.obligationId,
    assignedAt: '2026-01-01T00:05:00Z',
    arm: 'production',
    splitPolicyHash: policy.splitPolicyHash,
    seedHash: releaseValidationSplitSeedHash({
      proofEpochId: epoch.proofEpochId,
      cohortId: cohort.cohortId,
      releaseId: release.releaseId,
      admissionOrdinal: 1,
      splitPolicyHash: policy.splitPolicyHash,
    }),
  });
  const forecast = sealReleaseValidationForecastV2({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 3,
    previousCohortContentHash: assignment.contentHash,
    obligationId: obligation.obligationId,
    splitAssignmentId: assignment.assignmentId,
    policyId: policy.policyId,
    policyContentHash: policy.contentHash,
    recordedAt: '2026-01-01T01:30:00Z',
    latestRelease: release,
    candidates: [release],
    selectedReleaseId: release.releaseId,
    forecast: { recommendation: 'install', score: 8.5 },
  });
  const outcome = sealReleaseValidationOutcomeV2({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 4,
    previousCohortContentHash: forecast.contentHash,
    forecastId: forecast.forecastId,
    obligationId: obligation.obligationId,
    cellId: cell.cellId,
    releaseId: release.releaseId,
    observedAt: '2026-01-01T03:00:00Z',
    status: 'safe',
    evidenceContentHashes: ['c'.repeat(64)],
    outcome: { adverseCount: 0 },
  });
  const batch = sealReleaseValidationObservationBatch({
    proofEpochId: epoch.proofEpochId,
    cohortId: cohort.cohortId,
    cohortSequence: 5,
    previousCohortContentHash: outcome.contentHash,
    observedAt: '2026-01-01T03:01:00Z',
    sourceIdentityHash: 'd'.repeat(64),
    expectedObligationIds: [obligation.obligationId],
    cells: [{
      obligationId: obligation.obligationId,
      forecastId: forecast.forecastId,
      outcomeId: outcome.outcomeId,
      disposition: 'observed',
    }],
  });
  const evaluation = sealReleaseValidationEvaluationReceipt({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 5,
    previousEpochContentHash: reconciliation.reconciliation.contentHash,
    evaluatedAt: '2026-01-01T03:02:00Z',
    status: 'validated',
    cohortIds: [cohort.cohortId],
    requiredCellKeys: [
      releaseValidationCohortCellKey(cohort.cohortId, cell.cellId),
    ],
    observationBatchIds: [batch.batchId],
    outcomeIds: [outcome.outcomeId],
    metrics: { accuracy: 1, sampleCount: 1 },
  });
  const promotion = sealReleaseValidationPromotionReceipt({
    proofEpochId: epoch.proofEpochId,
    epochSequence: 6,
    previousEpochContentHash: evaluation.contentHash,
    environment: 'production',
    promotedAt: '2026-01-01T03:03:00Z',
    evaluationId: evaluation.evaluationId,
    evaluationContentHash: evaluation.contentHash,
    cohortIds: [cohort.cohortId],
    forecastIds: [forecast.forecastId],
    outcomeIds: [outcome.outcomeId],
    sourceProofHash: 'e'.repeat(64),
    destinationProofHash: 'f'.repeat(64),
  });
  const bundle: ReleaseValidationProofBundle = {
    epochs: [epoch],
    retirements: [],
    policies: [policy],
    cohorts: [cohort],
    catalogObservations: [catalog.observation],
    catalogMembers: catalog.members,
    catalogReconciliations: [reconciliation.reconciliation],
    catalogReconciliationRows: reconciliation.rows,
    obligations: [obligation],
    splitAssignments: [assignment],
    forecasts: [forecast],
    outcomes: [outcome],
    observationBatches: [batch],
    evaluationReceipts: [evaluation],
    promotionReceipts: [promotion],
  };
  const storage = [
    ['epochs', 'release_validation_proof_epochs', 'proof_epoch_id', 'proofEpochId'],
    [
      'retirements',
      'release_validation_proof_epoch_retirements',
      'retirement_id',
      'retirementId',
    ],
    ['policies', 'release_validation_policies', 'policy_id', 'policyId'],
    ['cohorts', 'release_validation_cohorts', 'cohort_id', 'cohortId'],
    [
      'catalogObservations',
      'release_validation_catalog_observations',
      'observation_id',
      'observationId',
    ],
    [
      'catalogMembers',
      'release_validation_catalog_members',
      'member_id',
      'memberId',
    ],
    [
      'catalogReconciliations',
      'release_validation_catalog_reconciliations',
      'reconciliation_id',
      'reconciliationId',
    ],
    [
      'catalogReconciliationRows',
      'release_validation_catalog_reconciliation_rows',
      'reconciliation_row_id',
      'reconciliationRowId',
    ],
    [
      'obligations',
      'release_validation_obligations',
      'obligation_id',
      'obligationId',
    ],
    [
      'splitAssignments',
      'release_validation_split_assignments',
      'assignment_id',
      'assignmentId',
    ],
    ['forecasts', 'release_validation_forecasts_v2', 'forecast_id', 'forecastId'],
    ['outcomes', 'release_validation_outcomes_v2', 'outcome_id', 'outcomeId'],
    [
      'observationBatches',
      'release_validation_proof_observation_batches',
      'batch_id',
      'batchId',
    ],
    [
      'evaluationReceipts',
      'release_validation_evaluation_receipts',
      'evaluation_id',
      'evaluationId',
    ],
    [
      'promotionReceipts',
      'release_validation_promotion_receipts',
      'promotion_id',
      'promotionId',
    ],
  ] as const;
  for (const [key, table, idColumn, idField] of storage) {
    const insert = db.prepare(`
      INSERT INTO ${table} (${idColumn}, content_hash, record_json)
      VALUES (?, ?, ?)
    `);
    for (const record of bundle[key]) {
      insert.run(
        record[idField],
        record.contentHash,
        canonicalReleaseValidationProofJson(record),
      );
    }
  }
}

type DoctorOperationReceiptOverrides = {
  historyContentHash?: string;
  forecastDecisionId?: string;
  unterminated?: boolean;
  advisoryCatalog?: Record<string, unknown>;
  includeScoreMetadata?: boolean;
};

function freshDoctorDb({
  validationProof = 'production',
  operationReceipt = {},
}: {
  validationProof?: 'production' | 'uninitialized';
  operationReceipt?: DoctorOperationReceiptOverrides | false;
} = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'radar-doctor-'));
  const dbPath = join(dir, 'radar.db');
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE releases (
      tag TEXT PRIMARY KEY,
      node_id TEXT,
      catalog_tag_commit_oid TEXT,
      name TEXT,
      published_at TEXT,
      created_at TEXT,
      updated_at TEXT,
      html_url TEXT,
      prerelease INTEGER NOT NULL DEFAULT 0,
      body TEXT,
      catalog_rank INTEGER,
      catalog_digest TEXT,
      catalog_active INTEGER NOT NULL DEFAULT 1,
      final_score REAL,
      state TEXT,
      recommended INTEGER NOT NULL DEFAULT 0,
      score_reason TEXT,
      scored_at TEXT,
      release_metadata_fetched_at TEXT,
      release_derived_fetched_at TEXT,
      release_artifact_checked_at TEXT
    );
    CREATE TABLE issues (
      number INTEGER PRIMARY KEY,
      node_id TEXT,
      state TEXT NOT NULL DEFAULT 'open',
      title TEXT NOT NULL DEFAULT '',
      body TEXT,
      author_node_id TEXT,
      author_type TEXT,
      created_at TEXT,
      updated_at TEXT,
      closed_at TEXT,
      comments INTEGER NOT NULL DEFAULT 0,
      labels TEXT NOT NULL DEFAULT '[]',
      revision INTEGER NOT NULL DEFAULT 1,
      fetched_at TEXT,
      commenter_scan_truncated INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_issues_created_at ON issues(created_at);
    CREATE INDEX idx_issues_closed_at ON issues(closed_at);
    CREATE TABLE classifications (
      issue_number INTEGER PRIMARY KEY,
      sentiment TEXT,
      severity TEXT,
      scope TEXT,
      functionality TEXT,
      affected_users TEXT,
      has_workaround INTEGER,
      workaround_status TEXT,
      duplicate_cluster TEXT,
      affects_version TEXT,
      confidence REAL,
      rationale TEXT,
      classified_at TEXT,
      classified_updated_at TEXT,
      classified_comments_digest TEXT,
      prompt_version INTEGER,
      source_identity_json TEXT,
      source_identity_digest TEXT,
      classification_origin TEXT NOT NULL DEFAULT 'legacy_or_manual',
      raw_model_output TEXT,
      provenance_json TEXT,
      revision INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE release_score_audits (
      release_tag TEXT PRIMARY KEY,
      scored_at TEXT NOT NULL,
      score_model_version TEXT NOT NULL,
      prompt_version INTEGER NOT NULL,
      final_score REAL,
      status TEXT NOT NULL,
      band TEXT NOT NULL,
      recommended INTEGER NOT NULL DEFAULT 0,
      input_json TEXT NOT NULL,
      components_json TEXT,
      issue_evidence_json TEXT NOT NULL,
      gate_evidence_json TEXT NOT NULL,
      source_identity_json TEXT,
      authority_run_id TEXT
    );
    CREATE TABLE release_score_audit_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      scored_at TEXT NOT NULL,
      score_model_version TEXT NOT NULL,
      prompt_version INTEGER NOT NULL,
      final_score REAL,
      status TEXT NOT NULL,
      band TEXT NOT NULL,
      recommended INTEGER NOT NULL,
      input_json TEXT NOT NULL,
      components_json TEXT,
      issue_evidence_json TEXT NOT NULL,
      gate_evidence_json TEXT NOT NULL,
      source_identity_json TEXT NOT NULL,
      authority_run_id TEXT
    );
    CREATE TABLE release_score_audit_history_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL UNIQUE,
      recorded_at TEXT NOT NULL,
      row_count INTEGER NOT NULL,
      rows_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE score_authority_resolution_runs (
      authority_run_id TEXT PRIMARY KEY,
      schema_version INTEGER NOT NULL,
      policy_version INTEGER NOT NULL,
      source_identity_schema_version INTEGER NOT NULL,
      source_identity_digest TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      row_count INTEGER NOT NULL,
      rows_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE score_authority_resolution_rows (
      authority_run_id TEXT NOT NULL,
      row_ordinal INTEGER NOT NULL,
      release_tag TEXT,
      issue_number INTEGER NOT NULL,
      subject_kind TEXT NOT NULL,
      subject_identity TEXT NOT NULL,
      candidate_id TEXT,
      authority TEXT NOT NULL,
      reason TEXT NOT NULL,
      authorized_for_scoring INTEGER NOT NULL,
      evidence_digest TEXT NOT NULL,
      resolution_json TEXT NOT NULL,
      content_hash TEXT NOT NULL UNIQUE,
      PRIMARY KEY(authority_run_id, row_ordinal)
    );
    CREATE TABLE release_score_audit_history_v2_seals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      schema_version INTEGER NOT NULL,
      history_run_id TEXT NOT NULL UNIQUE,
      authority_run_id TEXT NOT NULL UNIQUE,
      sealed_at TEXT NOT NULL,
      history_row_count INTEGER NOT NULL,
      history_rows_content_hash TEXT NOT NULL,
      authority_row_count INTEGER NOT NULL,
      authority_rows_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE release_validation_forecasts (
      id INTEGER PRIMARY KEY,
      decision_id TEXT UNIQUE,
      opportunity_code TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      latest_release_tag TEXT NOT NULL,
      latest_release_published_at TEXT NOT NULL,
      selected_tag TEXT,
      audit_history_run_id TEXT NOT NULL,
      score_model_version TEXT NOT NULL,
      prompt_version INTEGER NOT NULL,
      policy_code TEXT NOT NULL,
      candidate_scores_json TEXT NOT NULL,
      decision_json TEXT NOT NULL,
      source_identity_json TEXT NOT NULL,
      code_revision TEXT,
      previous_content_hash TEXT,
      content_hash TEXT UNIQUE
    );
    CREATE TABLE release_validation_opportunity_enrollments (
      id INTEGER PRIMARY KEY,
      opportunity_id TEXT
    );
    CREATE UNIQUE INDEX idx_release_validation_forecasts_series_without_revision
      ON release_validation_forecasts(
        opportunity_code, latest_release_tag, score_model_version, prompt_version
      )
      WHERE code_revision IS NULL;
    CREATE UNIQUE INDEX idx_release_validation_forecasts_series_with_revision
      ON release_validation_forecasts(
        opportunity_code, latest_release_tag, score_model_version, prompt_version, code_revision
      )
      WHERE code_revision IS NOT NULL;
    CREATE TABLE release_validation_outcome_observations (
      id INTEGER PRIMARY KEY,
      observation_id TEXT,
      decision_id TEXT,
      horizon_code TEXT,
      observed_at TEXT,
      status TEXT,
      outcome_json TEXT,
      source_identity_json TEXT,
      previous_content_hash TEXT,
      content_hash TEXT
    );
    CREATE TABLE release_validation_observation_batches (
      id INTEGER PRIMARY KEY,
      batch_id TEXT
    );
    CREATE UNIQUE INDEX idx_release_validation_outcomes_one_matured
      ON release_validation_outcome_observations(decision_id, horizon_code)
      WHERE status='matured';
    CREATE TABLE release_commits (
      tag TEXT PRIMARY KEY,
      tag_commit_oid TEXT,
      committed_at TEXT,
      fetched_at TEXT
    );
    CREATE TABLE issue_comment_snapshots (
      issue_number INTEGER PRIMARY KEY,
      repository_node_id TEXT,
      issue_node_id TEXT,
      issue_author_node_id TEXT,
      issue_author_login TEXT,
      issue_author_type TEXT,
      schema_version INTEGER NOT NULL,
      fetched_at TEXT NOT NULL,
      verified_at TEXT,
      comment_count INTEGER NOT NULL,
      fetched_comment_count INTEGER NOT NULL,
      latest_comment_updated_at TEXT,
      comments_digest TEXT NOT NULL,
      authority_digest TEXT,
      issue_updated_at TEXT,
      comments_json TEXT,
      stabilization_json TEXT,
      stabilization_identity_digest TEXT,
      revision INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE issue_state_event_snapshots (
      issue_number INTEGER PRIMARY KEY,
      repository_node_id TEXT,
      issue_node_id TEXT,
      issue_node_type TEXT,
      schema_version INTEGER NOT NULL,
      issue_state TEXT NOT NULL,
      issue_updated_at TEXT NOT NULL,
      total_count INTEGER NOT NULL,
      fetched_count INTEGER NOT NULL,
      events_digest TEXT NOT NULL,
      authority_digest TEXT,
      events_json TEXT NOT NULL,
      sweep_count INTEGER NOT NULL DEFAULT 0,
      stabilized INTEGER NOT NULL DEFAULT 0,
      stabilization_json TEXT,
      stabilization_identity_digest TEXT,
      revision INTEGER NOT NULL DEFAULT 1,
      fetched_at TEXT NOT NULL,
      verified_at TEXT NOT NULL
    );
    CREATE TABLE issue_closure_evidence_state (
      issue_number INTEGER PRIMARY KEY,
      schema_version INTEGER,
      issue_updated_at TEXT,
      comments_digest TEXT,
      checked_at TEXT
    );
    CREATE TABLE issue_closure_proofs (
      release_tag TEXT,
      issue_number INTEGER,
      status TEXT,
      summary TEXT,
      evidence_json TEXT,
      checked_at TEXT
    );
    CREATE TABLE release_closure_dependency_snapshots (
      release_tag TEXT PRIMARY KEY,
      schema_version INTEGER NOT NULL,
      analyzer_version INTEGER NOT NULL,
      issue_numbers_json TEXT NOT NULL,
      dependency_digest TEXT NOT NULL,
      dependency_row_count INTEGER NOT NULL,
      captured_at TEXT NOT NULL
    );
    CREATE TABLE issue_closure_events (
      issue_number INTEGER,
      issue_node_id TEXT,
      event_id TEXT,
      closed_at TEXT,
      connection_ordinal INTEGER,
      actor_node_id TEXT,
      actor_login TEXT,
      actor_type TEXT,
      state_reason TEXT,
      closer_type TEXT,
      closer_number INTEGER,
      closer_node_id TEXT,
      closer_oid TEXT,
      raw_json TEXT,
      fetched_at TEXT
    );
    CREATE TABLE issue_reopen_events (
      issue_number INTEGER,
      issue_node_id TEXT,
      event_id TEXT,
      reopened_at TEXT,
      connection_ordinal INTEGER,
      actor_node_id TEXT,
      actor_login TEXT,
      actor_type TEXT,
      raw_json TEXT,
      fetched_at TEXT
    );
    CREATE TABLE issue_pr_links (
      issue_number INTEGER,
      issue_node_id TEXT,
      pr_repository_name_with_owner TEXT,
      pr_number INTEGER,
      pr_node_id TEXT,
      source TEXT,
      source_node_id TEXT,
      will_close_target INTEGER,
      referenced_at TEXT,
      source_comment_database_id INTEGER,
      source_comment_url TEXT,
      raw_json TEXT,
      fetched_at TEXT
    );
    CREATE TABLE issue_commit_references (
      issue_number INTEGER,
      issue_node_id TEXT,
      event_id TEXT,
      commit_oid TEXT,
      commit_message_headline TEXT,
      commit_repository_name_with_owner TEXT,
      is_cross_repository INTEGER,
      is_direct_reference INTEGER,
      referenced_at TEXT,
      actor_node_id TEXT,
      actor_login TEXT,
      raw_json TEXT,
      fetched_at TEXT
    );
    CREATE TABLE pull_request_fixes (
      pr_repository_owner TEXT,
      pr_repository_name TEXT,
      pr_repository_name_with_owner TEXT,
      pr_number INTEGER,
      node_id TEXT,
      repository_node_id TEXT,
      title TEXT,
      url TEXT,
      state TEXT,
      merged INTEGER,
      merged_at TEXT,
      merge_commit_oid TEXT,
      base_ref_name TEXT,
      raw_json TEXT,
      fetched_at TEXT
    );
    CREATE TABLE release_pr_reachability (
      tag TEXT,
      pr_repository_owner TEXT,
      pr_repository_name TEXT,
      pr_repository_name_with_owner TEXT,
      pr_number INTEGER,
      tag_commit_oid TEXT,
      status TEXT,
      merge_commit_oid TEXT,
      base_ref_name TEXT,
      method TEXT,
      evidence_json TEXT,
      checked_at TEXT
    );
    CREATE TABLE issue_label_events (
      issue_number INTEGER,
      issue_node_id TEXT,
      event_id TEXT,
      action TEXT,
      label_name TEXT,
      actor_node_id TEXT,
      actor_login TEXT,
      actor_type TEXT,
      created_at TEXT,
      raw_json TEXT,
      fetched_at TEXT
    );
    CREATE TABLE issue_label_snapshots (
      issue_number INTEGER,
      issue_node_id TEXT,
      snapshot_at TEXT,
      labels_json TEXT,
      fetched_at TEXT
    );
    CREATE TABLE advisories (
      advisory_key TEXT PRIMARY KEY,
      ghsa_id TEXT NOT NULL,
      cve_id TEXT,
      summary TEXT NOT NULL,
      severity TEXT NOT NULL,
      html_url TEXT NOT NULL,
      published_at TEXT,
      package_ecosystem TEXT,
      package_name TEXT,
      vulnerable_version_range TEXT,
      patched_versions TEXT,
      fetched_at TEXT NOT NULL
    );
    CREATE TABLE advisory_snapshot_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      captured_at TEXT NOT NULL,
      row_count INTEGER NOT NULL,
      content_hash TEXT NOT NULL
    );
    CREATE TABLE advisory_snapshot_rows (
      snapshot_id INTEGER NOT NULL,
      advisory_key TEXT NOT NULL,
      ghsa_id TEXT NOT NULL,
      cve_id TEXT,
      summary TEXT NOT NULL,
      severity TEXT NOT NULL,
      html_url TEXT NOT NULL,
      published_at TEXT,
      package_ecosystem TEXT,
      package_name TEXT,
      vulnerable_version_range TEXT,
      patched_versions TEXT,
      PRIMARY KEY(snapshot_id, advisory_key),
      FOREIGN KEY(snapshot_id) REFERENCES advisory_snapshot_history(id) ON DELETE RESTRICT
    );
    CREATE TABLE advisory_snapshot_v2_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      schema_version INTEGER NOT NULL,
      captured_at TEXT NOT NULL,
      repository_owner TEXT NOT NULL,
      repository_name TEXT NOT NULL,
      repository_url TEXT NOT NULL,
      target_ecosystem TEXT NOT NULL,
      target_package_name TEXT NOT NULL,
      source_hash TEXT NOT NULL,
      catalog_hash TEXT NOT NULL,
      score_hash TEXT NOT NULL,
      score_ready INTEGER NOT NULL,
      row_count INTEGER NOT NULL,
      score_row_count INTEGER NOT NULL,
      score_content_digest TEXT NOT NULL,
      snapshot_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE advisory_snapshot_v2_rows (
      snapshot_id INTEGER NOT NULL,
      range_identity TEXT NOT NULL,
      ghsa_id TEXT NOT NULL,
      package_ecosystem TEXT NOT NULL,
      package_name TEXT NOT NULL,
      vulnerable_version_range TEXT NOT NULL,
      state TEXT NOT NULL,
      target_package INTEGER NOT NULL,
      score_eligible INTEGER NOT NULL,
      audit_only INTEGER NOT NULL,
      row_json TEXT NOT NULL,
      row_hash TEXT NOT NULL,
      PRIMARY KEY(snapshot_id, range_identity),
      FOREIGN KEY(snapshot_id) REFERENCES advisory_snapshot_v2_history(id) ON DELETE RESTRICT
    );
    CREATE TABLE issue_catalog_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      snapshot_id TEXT NOT NULL UNIQUE,
      schema_version INTEGER NOT NULL,
      row_schema_version INTEGER NOT NULL,
      repository TEXT NOT NULL,
      source TEXT NOT NULL,
      source_order TEXT NOT NULL,
      captured_at TEXT NOT NULL,
      boundary_total_count INTEGER NOT NULL,
      observed_total_count INTEGER NOT NULL,
      post_boundary_growth_count INTEGER NOT NULL,
      terminal_node_id TEXT,
      terminal_issue_number INTEGER,
      terminal_created_at TEXT,
      fetched_count INTEGER NOT NULL,
      unique_count INTEGER NOT NULL,
      page_count INTEGER NOT NULL,
      pages_fetched INTEGER NOT NULL,
      sweep_count INTEGER NOT NULL,
      membership_digest TEXT NOT NULL,
      content_digest TEXT NOT NULL,
      last_request_cursor TEXT,
      row_count INTEGER NOT NULL,
      row_schema_digest TEXT NOT NULL,
      rows_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE issue_catalog_snapshot_rows (
      snapshot_id TEXT NOT NULL,
      source_ordinal INTEGER NOT NULL,
      issue_number INTEGER NOT NULL,
      node_id TEXT NOT NULL,
      issue_json TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      PRIMARY KEY(snapshot_id, source_ordinal),
      UNIQUE(snapshot_id, issue_number),
      UNIQUE(snapshot_id, node_id),
      FOREIGN KEY(snapshot_id) REFERENCES issue_catalog_snapshots(snapshot_id) ON DELETE RESTRICT
    );
    CREATE TABLE issue_catalog_snapshot_consumptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      schema_version INTEGER NOT NULL,
      snapshot_id TEXT NOT NULL UNIQUE,
      repository TEXT NOT NULL,
      run_id TEXT NOT NULL UNIQUE,
      consumed_at TEXT NOT NULL,
      processed_row_count INTEGER NOT NULL,
      processed_page_count INTEGER NOT NULL,
      snapshot_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE,
      FOREIGN KEY(snapshot_id) REFERENCES issue_catalog_snapshots(snapshot_id) ON DELETE RESTRICT
    );
    CREATE TABLE refresh_leases (
      name TEXT PRIMARY KEY,
      holder_id TEXT NOT NULL,
      acquired_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    CREATE TABLE refresh_operation_attempts (
      run_id TEXT PRIMARY KEY,
      operation TEXT NOT NULL,
      trigger TEXT NOT NULL,
      started_at TEXT NOT NULL,
      lease_name TEXT NOT NULL,
      lease_holder_id TEXT NOT NULL,
      lease_expires_at TEXT NOT NULL,
      code_revision TEXT NOT NULL,
      effective_config_json TEXT NOT NULL,
      effective_config_hash TEXT NOT NULL,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE refresh_operation_stage_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT NOT NULL UNIQUE,
      run_id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      stage TEXT NOT NULL,
      status TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      duration_ms INTEGER,
      counts_json TEXT,
      details_json TEXT,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE refresh_capture_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT NOT NULL UNIQUE,
      run_id TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL,
      finished_at TEXT NOT NULL,
      duration_ms INTEGER NOT NULL,
      stage_event_count INTEGER NOT NULL,
      stage_chain_hash TEXT,
      payload_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE release_catalog_capture_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT NOT NULL UNIQUE,
      operation_run_id TEXT,
      source_kind TEXT NOT NULL,
      repository TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      active_catalog_digest TEXT NOT NULL,
      active_release_count INTEGER NOT NULL,
      payload_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE release_artifact_verification_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT NOT NULL UNIQUE,
      schema_version INTEGER NOT NULL,
      release_repository TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      release_node_id TEXT NOT NULL,
      release_tag_commit_oid TEXT NOT NULL,
      release_published_at TEXT NOT NULL,
      evidence_identity TEXT NOT NULL UNIQUE,
      canonical_receipt_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE release_artifact_verification_observations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observation_id TEXT NOT NULL UNIQUE,
      schema_version INTEGER NOT NULL,
      run_id TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      release_repository TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      release_node_id TEXT NOT NULL,
      release_tag_commit_oid TEXT NOT NULL,
      release_published_at TEXT NOT NULL,
      receipt_id TEXT NOT NULL,
      receipt_content_hash TEXT NOT NULL,
      canonical_observation_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE ingestion_evidence_failures (
      id INTEGER PRIMARY KEY,
      run_id TEXT,
      occurred_at TEXT,
      source TEXT,
      scope TEXT,
      release_tag TEXT,
      issue_number INTEGER,
      pr_repository_name_with_owner TEXT,
      pr_number INTEGER,
      message TEXT,
      context_json TEXT,
      scoring_blocking INTEGER
    );
    CREATE TABLE comparison_snapshots (id INTEGER PRIMARY KEY, source_url TEXT, captured_at TEXT, page_title TEXT);
    CREATE TABLE comparison_releases (snapshot_id INTEGER);
  `);
  createDoctorProofRecordTables(db);
  if (validationProof === 'production') {
    insertDoctorProductionValidationProof(db);
  }
  installDoctorAppendOnlyTriggers(db);
  seedDoctorFixture(db);
  if (operationReceipt !== false) {
    insertDoctorOperationReceipt(db, operationReceipt);
  }
  const bootstrapReport = buildDoctorReport({
    dbPath,
    sourceIdentityForDb: () => doctorSourceIdentityFixture,
  });
  const dependency = bootstrapReport.closureProof?.integrity?.dependencySnapshot?.current;
  if (!dependency?.digest || !Number.isInteger(dependency.rowCount)) {
    throw new Error('Doctor fixture could not derive closure dependency snapshot identity');
  }
  db.prepare(`
    UPDATE release_closure_dependency_snapshots
    SET dependency_digest=?, dependency_row_count=?
    WHERE release_tag='v2'
  `).run(dependency.digest, dependency.rowCount);
  return {
    db,
    dbPath,
    cleanup: () => {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function seedDoctorFixture(db: DatabaseSync) {
  const issueNodeId = 'I_doctor_1';
  const historyRecordedAt = '2026-06-02T01:05:00.000Z';
  const authorityRun = buildScoreAuthorityResolutionRun({
    authorityRunId: 'score-authority:run-doctor',
    sourceIdentitySchemaVersion: doctorSourceIdentityFixture.schemaVersion,
    sourceIdentityDigest: doctorSourceIdentityFixture.digest,
    recordedAt: historyRecordedAt,
    previousContentHash: null,
    rows: [],
  });
  db.prepare(`
    INSERT INTO score_authority_resolution_runs (
      authority_run_id, schema_version, policy_version,
      source_identity_schema_version, source_identity_digest, recorded_at,
      row_count, rows_content_hash, previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    authorityRun.authorityRunId,
    authorityRun.schemaVersion,
    authorityRun.policyVersion,
    authorityRun.sourceIdentitySchemaVersion,
    authorityRun.sourceIdentityDigest,
    authorityRun.recordedAt,
    authorityRun.rowCount,
    authorityRun.rowsContentHash,
    authorityRun.previousContentHash,
    authorityRun.contentHash,
  );
  const openStateSnapshot = doctorStateSnapshotIdentity({
    issueNumber: 1,
    issueNodeId,
    issueState: 'open',
    issueUpdatedAt: '2026-06-02T00:30:00Z',
    events: [],
  });
  db.prepare(`
    INSERT INTO releases (
      tag, node_id, catalog_tag_commit_oid, name, published_at, created_at,
      updated_at, html_url, prerelease, body, catalog_rank, catalog_active,
      final_score, state, recommended, score_reason, scored_at,
      release_metadata_fetched_at, release_derived_fetched_at, release_artifact_checked_at
    ) VALUES (
      'v0', 'R_v0', ?, 'v0', '2026-05-31T00:00:00.000Z',
      '2026-05-31T00:00:00.000Z', '2026-05-31T00:00:00.000Z',
      'https://example.test/releases/v0', 0, '', 2, 1,
      NULL, NULL, 0, NULL, NULL,
      '2026-05-31T00:00:00Z', '2026-05-31T00:00:00Z', '2026-05-31T00:00:00Z'
    )
  `).run('0'.repeat(40));
  const releaseRows = [
    ['v2', '2026-06-02T00:00:00.000Z', 0, '2'.repeat(40), 7.8, 'eligible', 1, '2026-06-02T01:00:00.000Z'],
    ['v1', '2026-06-01T00:00:00.000Z', 1, '1'.repeat(40), 7.5, 'eligible', 0, '2026-06-01T01:00:00.000Z'],
  ] as const;
  const insertRelease = db.prepare(`
    INSERT INTO releases (
      tag, node_id, catalog_tag_commit_oid, name, published_at, created_at,
      updated_at, html_url, prerelease, body, catalog_rank, catalog_active,
      final_score, state, recommended, score_reason, scored_at,
      release_metadata_fetched_at, release_derived_fetched_at, release_artifact_checked_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, 1,
      ?, ?, ?, 'test reason', ?,
      '2026-05-31T00:00:00Z', '2026-05-31T00:00:00Z', '2026-05-31T00:00:00Z'
    )
  `);
  const insertAudit = db.prepare(`
    INSERT INTO release_score_audits (
      release_tag, scored_at, score_model_version, prompt_version, final_score, status, band, recommended,
      input_json, components_json, issue_evidence_json, gate_evidence_json,
      source_identity_json, authority_run_id
    ) VALUES (?, ?, 'test-model', 6, ?, ?, 'ok', ?, ?, '{}', ?, ?, ?, ?)
  `);
  for (
    const [
      tag,
      publishedAt,
      catalogRank,
      tagCommitOid,
      score,
      status,
      recommended,
      scoredAt,
    ] of releaseRows
  ) {
    const predecessorTag = tag === 'v2' ? 'v1' : 'v0';
    const closureProof = {
      schemaVersion: 1,
      creditedCount: 0,
      notCreditedCount: 0,
      analyzedClosedCount: 0,
      containedFixedCount: 0,
      containedNotCreditedCount: 0,
      targetTag: tag,
      predecessorTag,
      fixCreditDecisionCounts: { credited: 0, withheld: 0, invalid: 0 },
      fixCreditDecisions: [],
      byStatus: {},
      byRiskDisposition: {},
      riskSummary: {},
    };
    const releaseFixCredit = {
      schemaVersion: 1,
      targetTag: tag,
      predecessorTag,
      countedClosedCount: 0,
      notCountedClosedCount: 0,
      analyzedClosedCount: 0,
      containedFixedCount: 0,
      containedNotCreditedCount: 0,
      decisionCounts: { credited: 0, withheld: 0, invalid: 0 },
      decisions: [],
    };
    insertRelease.run(
      tag,
      `R_${tag}`,
      tagCommitOid,
      tag,
      publishedAt,
      publishedAt,
      publishedAt,
      `https://example.test/releases/${tag}`,
      catalogRank,
      score,
      status,
      recommended,
      scoredAt,
    );
    insertAudit.run(
      tag,
      scoredAt,
      score,
      status,
      recommended,
      JSON.stringify({ rawIssueCount: 1, classifiedIssueCount: 1 }),
      JSON.stringify({ debtSummary: {}, verifiedDebt: [], carryoverDebt: [], staleDebt: [], openedFeltSerious: [], verifiedFixed: [], unverifiedClosed: [], unclassifiedIssues: [] }),
      JSON.stringify({ fixProvenance: { closureProof, releaseFixCredit } }),
      JSON.stringify(doctorSourceIdentityFixture),
      authorityRun.authorityRunId,
    );
    db.prepare(`
      INSERT INTO release_commits (tag, tag_commit_oid, committed_at, fetched_at)
      VALUES (?, ?, ?, '2026-05-31T00:00:00Z')
    `).run(tag, tagCommitOid, publishedAt);
  }
  db.prepare(`
    INSERT INTO release_commits (tag, tag_commit_oid, committed_at, fetched_at)
    VALUES ('v0', ?, '2026-05-31T00:00:00.000Z', '2026-05-31T00:00:00Z')
  `).run('0'.repeat(40));
  const activeCatalog = currentActiveReleaseCatalogForDoctor(db);
  if (!activeCatalog.digest) {
    throw new Error(
      `Doctor fixture active catalog could not be projected: ` +
      activeCatalog.problems.join('; '),
    );
  }
  db.prepare(`
    UPDATE releases
    SET catalog_digest=?
    WHERE catalog_active=1
  `).run(activeCatalog.digest);
  db.prepare(`
    INSERT INTO issues (
      number, node_id, state, title, author_node_id, author_type,
      created_at, updated_at, closed_at,
      comments, labels, revision, fetched_at, commenter_scan_truncated
    )
    VALUES (
      1, ?, 'open', 'doctor issue', 'U_doctor_reporter', 'User',
      '2026-06-02T00:30:00Z', '2026-06-02T00:30:00Z', NULL,
      0, '[]', 1, '2026-06-02T00:30:00Z', 0
    )
  `).run(issueNodeId);
  db.prepare(`INSERT INTO classifications (issue_number, classified_at) VALUES (1, '2026-06-02T00:40:00Z')`).run();
  db.prepare(`
    INSERT INTO issue_state_event_snapshots (
      issue_number, repository_node_id, issue_node_id, issue_node_type,
      schema_version,
      issue_state, issue_updated_at, total_count, fetched_count,
      events_digest, authority_digest, events_json,
      sweep_count, stabilized, stabilization_json,
      stabilization_identity_digest, revision, fetched_at, verified_at
    )
    VALUES (
      1, ?, ?, ?, ?, 'open', '2026-06-02T00:30:00Z',
      0, 0, ?, ?, ?, 2, 1, ?, ?, 1,
      '2026-06-02T00:45:00Z', '2026-06-02T00:45:00Z'
    )
  `).run(
    openStateSnapshot.repositoryNodeId,
    issueNodeId,
    openStateSnapshot.issueNodeType,
    ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
    openStateSnapshot.eventsDigest,
    openStateSnapshot.authorityDigest,
    JSON.stringify(openStateSnapshot.events),
    JSON.stringify(openStateSnapshot.stabilization),
    openStateSnapshot.stabilization.identityDigest,
  );
  db.prepare(`
    INSERT INTO release_closure_dependency_snapshots (
      release_tag, schema_version, analyzer_version, issue_numbers_json,
      dependency_digest, dependency_row_count, captured_at
    )
    VALUES ('v2', 2, ${CLOSURE_PROOF_ANALYZER_VERSION}, '[]', ?, 0, '2026-06-02T00:50:00Z')
  `).run('0'.repeat(64));
  db.prepare(`
    INSERT INTO advisory_snapshot_history(id, captured_at, row_count, content_hash)
    VALUES (1, '2026-06-02T00:50:00Z', 1, ?)
  `).run(advisorySnapshotContentHash([doctorAdvisorySnapshotRow]));
  insertDoctorAdvisorySnapshotRow(db, { snapshotId: 1 });
  db.prepare(`
    INSERT INTO advisories (
      advisory_key, ghsa_id, cve_id, summary, severity, html_url, published_at,
      package_ecosystem, package_name, vulnerable_version_range, patched_versions, fetched_at
    )
    VALUES (
      :advisory_key, :ghsa_id, :cve_id, :summary, :severity, :html_url, :published_at,
      :package_ecosystem, :package_name, :vulnerable_version_range, :patched_versions,
      '2026-06-02T00:50:00Z'
    )
  `).run(doctorAdvisorySnapshotRow);
  db.prepare(`INSERT INTO meta(key, value) VALUES(?, ?)`).run(
    ADVISORY_SNAPSHOT_META_KEY,
    JSON.stringify({
      schemaVersion: 1,
      source: 'github-security-vulnerabilities',
      sourceOrder: 'UPDATED_AT_DESC',
      ecosystem: 'npm',
      packageName: config.github.repo,
      capturedAt: '2026-06-02T00:50:00Z',
      exhausted: true,
      stabilized: true,
      totalCount: 1,
      nodeCount: 1,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      sourceDigest: 'a'.repeat(64),
      advisoryCount: 1,
      activeAdvisoryCount: 1,
      withdrawnAdvisoryCount: 0,
      rowCount: 1,
      contentDigest: advisorySnapshotContentHash([doctorAdvisorySnapshotRow]),
    }),
  );
  insertDoctorCompoundAdvisorySnapshot(db, '2026-06-02T01:00:10Z');
  db.prepare(`
    INSERT INTO release_score_audit_history (
      run_id, recorded_at, release_tag, scored_at, score_model_version, prompt_version,
      final_score, status, band, recommended, input_json, components_json,
      issue_evidence_json, gate_evidence_json, source_identity_json, authority_run_id
    )
    SELECT
      'run-doctor', ?, release_tag, scored_at, score_model_version, prompt_version,
      final_score, status, band, recommended, input_json, components_json,
      issue_evidence_json, gate_evidence_json, source_identity_json, authority_run_id
    FROM release_score_audits
  `).run(historyRecordedAt);
  const historyRows = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    WHERE run_id='run-doctor'
    ORDER BY release_tag
  `).all() as Array<Record<string, unknown>>;
  const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(historyRows);
  const historyRunContentHash = releaseScoreAuditHistoryRunContentHash({
    runId: 'run-doctor',
    recordedAt: historyRecordedAt,
    rowCount: historyRows.length,
    rowsContentHash,
    previousContentHash: null,
  });
  db.prepare(`
    INSERT INTO release_score_audit_history_runs (
      run_id, recorded_at, row_count, rows_content_hash,
      previous_content_hash, content_hash
    )
    VALUES ('run-doctor', ?, ?, ?, NULL, ?)
  `).run(
    historyRecordedAt,
    historyRows.length,
    rowsContentHash,
    historyRunContentHash,
  );
  const historyV2Seal = buildReleaseScoreAuditHistoryV2Seal({
    historyRunId: 'run-doctor',
    authorityRunId: authorityRun.authorityRunId,
    sealedAt: historyRecordedAt,
    historyRowCount: historyRows.length,
    historyRowsContentHash: rowsContentHash,
    authorityRowCount: authorityRun.rowCount,
    authorityRowsContentHash: authorityRun.rowsContentHash,
    previousContentHash: null,
  });
  db.prepare(`
    INSERT INTO release_score_audit_history_v2_seals (
      schema_version, history_run_id, authority_run_id, sealed_at,
      history_row_count, history_rows_content_hash, authority_row_count,
      authority_rows_content_hash, previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    historyV2Seal.schemaVersion,
    historyV2Seal.historyRunId,
    historyV2Seal.authorityRunId,
    historyV2Seal.sealedAt,
    historyV2Seal.historyRowCount,
    historyV2Seal.historyRowsContentHash,
    historyV2Seal.authorityRowCount,
    historyV2Seal.authorityRowsContentHash,
    historyV2Seal.previousContentHash,
    historyV2Seal.contentHash,
  );
  writeScorePersistenceMeta(db, ['v2', 'v1']);
}

function insertDoctorOperationReceipt(
  db: DatabaseSync,
  overrides: DoctorOperationReceiptOverrides = {},
) {
  const runId = 'refresh-doctor';
  const startedAt = '2026-06-02T01:00:00.000Z';
  const effectiveConfigJson = canonicalOperationJson({
    schemaVersion: 1,
    github: {
      owner: 'openclaw',
      repo: 'openclaw',
    },
    openai: {
      model: 'gpt-test',
    },
  });
  const attempt = {
    run_id: runId,
    operation: 'refresh',
    trigger: 'doctor-test',
    started_at: startedAt,
    lease_name: 'github-refresh',
    lease_holder_id: 'doctor-holder',
    lease_expires_at: '2026-06-02T01:05:00.000Z',
    code_revision: 'git:0123456789abcdef0123456789abcdef01234567',
    effective_config_json: effectiveConfigJson,
    effective_config_hash: operationAttemptConfigHash(effectiveConfigJson),
    content_hash: '',
  };
  attempt.content_hash = operationAttemptContentHash({
    runId: attempt.run_id,
    operation: attempt.operation,
    trigger: attempt.trigger,
    startedAt: attempt.started_at,
    leaseName: attempt.lease_name,
    leaseHolderId: attempt.lease_holder_id,
    leaseExpiresAt: attempt.lease_expires_at,
    codeRevision: attempt.code_revision,
    effectiveConfigJson: attempt.effective_config_json,
  });
  db.prepare(`
    INSERT INTO refresh_operation_attempts (
      run_id, operation, trigger, started_at, lease_name, lease_holder_id,
      lease_expires_at, code_revision, effective_config_json,
      effective_config_hash, content_hash
    )
    VALUES (
      :run_id, :operation, :trigger, :started_at, :lease_name, :lease_holder_id,
      :lease_expires_at, :code_revision, :effective_config_json,
      :effective_config_hash, :content_hash
    )
  `).run(attempt);
  if (overrides.unterminated) return;

  const historyContentHash = overrides.historyContentHash ??
    (db.prepare(`
      SELECT content_hash
      FROM release_score_audit_history_runs
      WHERE run_id='run-doctor'
    `).get() as any).content_hash;
  const authorityRun = db.prepare(`
    SELECT authority_run_id, content_hash
    FROM score_authority_resolution_runs
    WHERE authority_run_id='score-authority:run-doctor'
  `).get() as { authority_run_id: string; content_hash: string };
  const historyV2Seal = db.prepare(`
    SELECT content_hash
    FROM release_score_audit_history_v2_seals
    WHERE history_run_id='run-doctor'
  `).get() as { content_hash: string };
  const scoreCommit = {
    schemaVersion: 4,
    historyRunId: 'run-doctor',
    historyRunContentHash: historyContentHash,
    authorityRunId: authorityRun.authority_run_id,
    authorityRunContentHash: authorityRun.content_hash,
    historyV2SealContentHash: historyV2Seal.content_hash,
    historyRecordedAt: '2026-06-02T01:05:00.000Z',
    commitNotBefore: '2026-06-02T01:05:00.000Z',
    commitNotAfter: '2026-06-02T01:05:00.000Z',
    commitNotBeforeMs: Date.parse('2026-06-02T01:05:00.000Z'),
    commitNotAfterMs: Date.parse('2026-06-02T01:05:00.000Z'),
  };
  const startedEvent = {
    event_id: 'refresh-doctor-stage-start',
    run_id: runId,
    sequence: 1,
    stage: 'score.persist',
    status: 'started' as const,
    occurred_at: '2026-06-02T01:04:59.000Z',
    duration_ms: null,
    counts_json: null,
    details_json: null,
    previous_content_hash: null,
    content_hash: '',
  };
  startedEvent.content_hash = operationStageEventContentHash({
    eventId: startedEvent.event_id,
    runId: startedEvent.run_id,
    sequence: startedEvent.sequence,
    stage: startedEvent.stage,
    status: startedEvent.status,
    occurredAt: startedEvent.occurred_at,
    durationMs: startedEvent.duration_ms,
    countsJson: startedEvent.counts_json,
    detailsJson: startedEvent.details_json,
    previousContentHash: startedEvent.previous_content_hash,
  });
  const completedEvent = {
    event_id: 'refresh-doctor-stage-completed',
    run_id: runId,
    sequence: 2,
    stage: 'score.persist',
    status: 'completed' as const,
    occurred_at: '2026-06-02T01:04:59.500Z',
    duration_ms: 500,
    counts_json: canonicalOperationJson({ scoredReleases: 2 }),
    details_json: canonicalOperationJson({
      historyRunId: 'run-doctor',
      historyRunContentHash: historyContentHash,
      authorityRunId: authorityRun.authority_run_id,
      authorityRunContentHash: authorityRun.content_hash,
      historyV2SealContentHash: historyV2Seal.content_hash,
      commitNotBefore: scoreCommit.commitNotBefore,
      commitNotAfter: scoreCommit.commitNotAfter,
    }),
    previous_content_hash: startedEvent.content_hash,
    content_hash: '',
  };
  completedEvent.content_hash = operationStageEventContentHash({
    eventId: completedEvent.event_id,
    runId: completedEvent.run_id,
    sequence: completedEvent.sequence,
    stage: completedEvent.stage,
    status: completedEvent.status,
    occurredAt: completedEvent.occurred_at,
    durationMs: completedEvent.duration_ms,
    countsJson: completedEvent.counts_json,
    detailsJson: completedEvent.details_json,
    previousContentHash: completedEvent.previous_content_hash,
  });
  const forecastStartedEvent = {
    event_id: 'refresh-doctor-forecast-start',
    run_id: runId,
    sequence: 3,
    stage: 'forecast.capture',
    status: 'started' as const,
    occurred_at: '2026-06-02T01:04:59.750Z',
    duration_ms: null,
    counts_json: null,
    details_json: null,
    previous_content_hash: completedEvent.content_hash,
    content_hash: '',
  };
  forecastStartedEvent.content_hash = operationStageEventContentHash({
    eventId: forecastStartedEvent.event_id,
    runId: forecastStartedEvent.run_id,
    sequence: forecastStartedEvent.sequence,
    stage: forecastStartedEvent.stage,
    status: forecastStartedEvent.status,
    occurredAt: forecastStartedEvent.occurred_at,
    durationMs: forecastStartedEvent.duration_ms,
    countsJson: forecastStartedEvent.counts_json,
    detailsJson: forecastStartedEvent.details_json,
    previousContentHash: forecastStartedEvent.previous_content_hash,
  });
  const forecastDecisionIds = overrides.forecastDecisionId
    ? [overrides.forecastDecisionId]
    : [];
  const forecastCompletedEvent = {
    event_id: 'refresh-doctor-forecast-completed',
    run_id: runId,
    sequence: 4,
    stage: 'forecast.capture',
    status: 'completed' as const,
    occurred_at: '2026-06-02T01:05:00.000Z',
    duration_ms: 250,
    counts_json: canonicalOperationJson({
      validationForecasts: forecastDecisionIds.length,
    }),
    details_json: canonicalOperationJson({
      eligibilityOutcome: forecastDecisionIds.length > 0
        ? 'eligible_and_captured'
        : 'not_eligible',
    }),
    previous_content_hash: forecastStartedEvent.content_hash,
    content_hash: '',
  };
  forecastCompletedEvent.content_hash = operationStageEventContentHash({
    eventId: forecastCompletedEvent.event_id,
    runId: forecastCompletedEvent.run_id,
    sequence: forecastCompletedEvent.sequence,
    stage: forecastCompletedEvent.stage,
    status: forecastCompletedEvent.status,
    occurredAt: forecastCompletedEvent.occurred_at,
    durationMs: forecastCompletedEvent.duration_ms,
    countsJson: forecastCompletedEvent.counts_json,
    detailsJson: forecastCompletedEvent.details_json,
    previousContentHash: forecastCompletedEvent.previous_content_hash,
  });
  const insertStage = db.prepare(`
    INSERT INTO refresh_operation_stage_events (
      event_id, run_id, sequence, stage, status, occurred_at, duration_ms,
      counts_json, details_json, previous_content_hash, content_hash
    )
    VALUES (
      :event_id, :run_id, :sequence, :stage, :status, :occurred_at, :duration_ms,
      :counts_json, :details_json, :previous_content_hash, :content_hash
    )
  `);
  insertStage.run(startedEvent);
  insertStage.run(completedEvent);
  insertStage.run(forecastStartedEvent);
  insertStage.run(forecastCompletedEvent);
  const issueCrawlMetadata = {
    schemaVersion: 2,
    startedAt,
    finishedAt: '2026-06-02T01:04:58.000Z',
    scorePersisted: true,
    scorePersistedAt: '2026-06-02T01:05:00.000Z',
  };
  const advisoryMetadata = JSON.parse(String(db.prepare(`
    SELECT value FROM meta WHERE key=?
  `).get(ADVISORY_SNAPSHOT_V2_META_KEY)?.value));
  const projectedCatalog = currentActiveReleaseCatalogForDoctor(db);
  if (projectedCatalog.problems.length > 0 || !projectedCatalog.digest) {
    throw new Error(
      `Doctor operation receipt active catalog is invalid: ` +
      projectedCatalog.problems.join('; '),
    );
  }
  const activeCatalog = {
    digest: projectedCatalog.digest,
    releaseCount: projectedCatalog.releaseCount,
    stableCount: projectedCatalog.stableCount,
    prereleaseCount: projectedCatalog.prereleaseCount,
    tags: [...projectedCatalog.tags],
    latestStable: projectedCatalog.latestStable,
  };
  const catalogObservedAt = '2026-06-02T01:04:58.500Z';
  const remoteCatalog = {
    repositoryNodeId: 'REPO-node-openclaw',
    repositoryNameWithOwner: 'openclaw/openclaw',
    digest: 'a'.repeat(64),
    totalCount: activeCatalog.releaseCount,
    nodeCount: activeCatalog.releaseCount,
    publishedCount: activeCatalog.releaseCount,
    draftCount: 0,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    sweepPageCounts: [1, 1],
    exhausted: true as const,
    stabilized: true as const,
    sourceOrder: 'CREATED_AT_DESC' as const,
  };
  const catalogSweepAttestation = {
    digest: remoteCatalog.digest,
    totalCount: remoteCatalog.totalCount,
    nodeCount: remoteCatalog.nodeCount,
    pageCount: remoteCatalog.pageCount,
    pagesFetched: remoteCatalog.pagesFetched,
    sweepCount: remoteCatalog.sweepCount,
    exhausted: true as const,
    stabilized: true as const,
    sourceOrder: remoteCatalog.sourceOrder,
  };
  const catalogAttestation = {
    schemaVersion: 4,
    initialRemoteCatalog: catalogSweepAttestation,
    finalRemoteCatalog: catalogSweepAttestation,
    finalObservedAt: catalogObservedAt,
    projectedActiveCatalog: {
      digest: activeCatalog.digest,
      releaseCount: activeCatalog.releaseCount,
    },
    localActiveCatalog: {
      digest: activeCatalog.digest,
      releaseCount: activeCatalog.releaseCount,
    },
    latestStable: activeCatalog.latestStable,
    scoreBuiltAt: '2026-06-02T01:04:58.250Z',
  };
  const issueCrawlMetadataDigest = createHash('sha256')
    .update(canonicalOperationJson(issueCrawlMetadata))
    .digest('hex');
  const immutableScoreMetadata = overrides.includeScoreMetadata
    ? {
        ...JSON.parse(String(db.prepare(`
          SELECT value FROM meta WHERE key='score_persistence_last_run'
        `).get()?.value)),
        source: 'refresh',
        operationRunId: runId,
        operationReceiptRequired: true,
        codeRevision: attempt.code_revision,
        issueCrawlMetadataDigest,
        historyRunId: 'run-doctor',
        historyRunContentHash: historyContentHash,
        authorityRunId: authorityRun.authority_run_id,
        authorityRunContentHash: authorityRun.content_hash,
        historyV2SealContentHash: historyV2Seal.content_hash,
        commitTiming: scoreCommit,
        catalogAttestation,
      }
    : null;
  const payloadJson = canonicalOperationJson({
    schemaVersion: 1,
    operation: 'refresh',
    trigger: 'doctor-test',
    codeRevision: attempt.code_revision,
    scoreHistory: {
      runId: 'run-doctor',
      contentHash: historyContentHash,
      persistedAt: '2026-06-02T01:05:00.000Z',
    },
    scoreAuthority: {
      runId: authorityRun.authority_run_id,
      contentHash: authorityRun.content_hash,
      historyV2SealContentHash: historyV2Seal.content_hash,
    },
    scoreCommit,
    ...(immutableScoreMetadata ? { scoreMetadata: immutableScoreMetadata } : {}),
    releaseTags: ['v2', 'v1'],
    recommendation: {
      selectedTag: 'v2',
      decisions: [],
    },
    issueCrawl: {
      metaKey: 'issue_crawl_last_run',
      metadataDigest: issueCrawlMetadataDigest,
      metadata: issueCrawlMetadata,
    },
    releaseCatalog: {
      digest: remoteCatalog.digest,
      nodeCount: remoteCatalog.nodeCount,
      totalCount: remoteCatalog.totalCount,
      attestation: catalogAttestation,
    },
    advisoryCatalog: {
      metaKey: ADVISORY_SNAPSHOT_V2_META_KEY,
      metadataDigest: createHash('sha256')
        .update(canonicalOperationJson(advisoryMetadata))
        .digest('hex'),
      metadata: advisoryMetadata,
      snapshotId: advisoryMetadata.snapshotId,
      sourceHash: advisoryMetadata.sourceHash,
      catalogHash: advisoryMetadata.catalogHash,
      scoreHash: advisoryMetadata.scoreHash,
      contentHash: advisoryMetadata.contentHash,
      contentDigest: advisoryMetadata.scoreContentDigest,
      advisoryCount: advisoryMetadata.scoreRowCount,
      rowCount: advisoryMetadata.scoreRowCount,
      catalogRowCount: advisoryMetadata.rowCount,
      scoreRowCount: advisoryMetadata.scoreRowCount,
      ...overrides.advisoryCatalog,
    },
    forecast: {
      eligibilityOutcome: forecastDecisionIds.length > 0
        ? 'eligible_and_captured'
        : 'not_eligible',
      decisionIds: forecastDecisionIds,
      captures: forecastDecisionIds.map((decisionId) => ({ decisionId })),
    },
  });
  insertDoctorReleaseCatalogReceipt(db, {
    attempt,
    activeCatalog,
    remoteCatalog,
    observedAt: catalogObservedAt,
  });
  const receipt = {
    receipt_id: 'receipt-refresh-doctor',
    run_id: runId,
    status: 'success' as const,
    finished_at: '2026-06-02T01:05:00.000Z',
    duration_ms: 300_000,
    stage_event_count: 4,
    stage_chain_hash: forecastCompletedEvent.content_hash,
    payload_json: payloadJson,
    previous_content_hash: null,
    content_hash: '',
  };
  receipt.content_hash = operationCaptureReceiptContentHash({
    receiptId: receipt.receipt_id,
    runId: receipt.run_id,
    status: receipt.status,
    finishedAt: receipt.finished_at,
    durationMs: receipt.duration_ms,
    stageEventCount: receipt.stage_event_count,
    stageChainHash: receipt.stage_chain_hash,
    payloadJson: receipt.payload_json,
    previousContentHash: receipt.previous_content_hash,
  });
  db.prepare(`
    INSERT INTO refresh_capture_receipts (
      receipt_id, run_id, status, finished_at, duration_ms, stage_event_count,
      stage_chain_hash, payload_json, previous_content_hash, content_hash
    )
    VALUES (
      :receipt_id, :run_id, :status, :finished_at, :duration_ms, :stage_event_count,
      :stage_chain_hash, :payload_json, :previous_content_hash, :content_hash
    )
  `).run(receipt);
}

function insertDoctorReleaseCatalogReceipt(
  db: DatabaseSync,
  input: {
    attempt: {
      run_id: string;
      operation: string;
      content_hash: string;
    };
    activeCatalog: {
      digest: string;
      releaseCount: number;
      stableCount: number;
      prereleaseCount: number;
      tags: string[];
      latestStable: {
        nodeId: string;
        tag: string;
        tagCommitOid: string;
        publishedAt: string;
      } | null;
    };
    remoteCatalog: {
      repositoryNodeId: string;
      repositoryNameWithOwner: string;
      digest: string;
      totalCount: number;
      nodeCount: number;
      publishedCount: number;
      draftCount: number;
      pageCount: number;
      pagesFetched: number;
      sweepCount: number;
      sweepPageCounts: number[];
      exhausted: true;
      stabilized: true;
      sourceOrder: 'CREATED_AT_DESC';
    };
    observedAt: string;
  },
) {
  const previousContentHash = (
    db.prepare(`
      SELECT content_hash
      FROM release_catalog_capture_receipts
      ORDER BY id DESC
      LIMIT 1
    `).get() as { content_hash?: string } | undefined
  )?.content_hash ?? null;
  const payload = {
    schemaVersion: 1 as const,
    source: 'github_graphql' as const,
    repository: 'openclaw/openclaw',
    observedAt: input.observedAt,
    operationRunId: input.attempt.run_id,
    operation: input.attempt.operation,
    operationAttemptContentHash: input.attempt.content_hash,
    remoteCatalog: input.remoteCatalog,
    activeCatalog: input.activeCatalog,
  };
  const contentHash = releaseCatalogCaptureReceiptContentHash({
    payload,
    previousContentHash,
  });
  const receiptId = releaseCatalogCaptureReceiptId(contentHash);
  db.prepare(`
    INSERT INTO release_catalog_capture_receipts (
      receipt_id, operation_run_id, source_kind, repository, observed_at,
      active_catalog_digest, active_release_count, payload_json,
      previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    receiptId,
    payload.operationRunId,
    payload.source,
    payload.repository,
    payload.observedAt,
    payload.activeCatalog.digest,
    payload.activeCatalog.releaseCount,
    canonicalOperationJson(payload),
    previousContentHash,
    contentHash,
  );
}

function rewriteDoctorReleaseCatalogReceipt(
  db: DatabaseSync,
  mutate: (payload: any) => any,
) {
  const row = db.prepare(`
    SELECT *
    FROM release_catalog_capture_receipts
    ORDER BY id DESC
    LIMIT 1
  `).get() as any;
  const payload = mutate(JSON.parse(row.payload_json));
  const contentHash = releaseCatalogCaptureReceiptContentHash({
    payload,
    previousContentHash: row.previous_content_hash ?? null,
  });
  const receiptId = releaseCatalogCaptureReceiptId(contentHash);
  disableDoctorAppendOnlyTriggers(db, ['release_catalog_capture_receipts']);
  db.prepare(`
    UPDATE release_catalog_capture_receipts
    SET
      receipt_id=?,
      operation_run_id=?,
      source_kind=?,
      repository=?,
      observed_at=?,
      active_catalog_digest=?,
      active_release_count=?,
      payload_json=?,
      content_hash=?
    WHERE id=?
  `).run(
    receiptId,
    payload.operationRunId,
    payload.source,
    payload.repository,
    payload.observedAt,
    payload.activeCatalog.digest,
    payload.activeCatalog.releaseCount,
    canonicalOperationJson(payload),
    contentHash,
    row.id,
  );
  reinstallDoctorAppendOnlyTriggers(db);
}

function rewriteDoctorTerminalReceiptStatus(
  db: DatabaseSync,
  status: 'failure' | 'abandoned',
) {
  const row = db.prepare(`
    SELECT *
    FROM refresh_capture_receipts
    WHERE run_id='refresh-doctor'
  `).get() as any;
  const contentHash = operationCaptureReceiptContentHash({
    receiptId: row.receipt_id,
    runId: row.run_id,
    status,
    finishedAt: row.finished_at,
    durationMs: Number(row.duration_ms),
    stageEventCount: Number(row.stage_event_count),
    stageChainHash: row.stage_chain_hash ?? null,
    payloadJson: row.payload_json,
    previousContentHash: row.previous_content_hash ?? null,
  });
  disableDoctorAppendOnlyTriggers(db, ['refresh_capture_receipts']);
  db.prepare(`
    UPDATE refresh_capture_receipts
    SET status=?, content_hash=?
    WHERE run_id=?
  `).run(status, contentHash, row.run_id);
  reinstallDoctorAppendOnlyTriggers(db);
}

function insertDoctorAdvisorySnapshotRow(
  db: DatabaseSync,
  overrides: {
    snapshotId: number;
    advisoryKey?: string;
    ghsaId?: string;
    vulnerableVersionRange?: string;
  },
) {
  const ghsaId = overrides.ghsaId ?? doctorAdvisorySnapshotRow.ghsa_id;
  const vulnerableVersionRange = overrides.vulnerableVersionRange ??
    doctorAdvisorySnapshotRow.vulnerable_version_range;
  db.prepare(`
    INSERT INTO advisory_snapshot_rows (
      snapshot_id, advisory_key, ghsa_id, cve_id, summary, severity, html_url,
      published_at, package_ecosystem, package_name, vulnerable_version_range,
      patched_versions
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    overrides.snapshotId,
    overrides.advisoryKey ?? advisoryVulnerabilityKey(
      ghsaId,
      doctorAdvisorySnapshotRow.package_ecosystem,
      doctorAdvisorySnapshotRow.package_name,
      vulnerableVersionRange,
    ),
    ghsaId,
    doctorAdvisorySnapshotRow.cve_id,
    doctorAdvisorySnapshotRow.summary,
    doctorAdvisorySnapshotRow.severity,
    doctorAdvisorySnapshotRow.html_url,
    doctorAdvisorySnapshotRow.published_at,
    doctorAdvisorySnapshotRow.package_ecosystem,
    doctorAdvisorySnapshotRow.package_name,
    vulnerableVersionRange,
    doctorAdvisorySnapshotRow.patched_versions,
  );
}

function doctorNativeJsonHash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function doctorCompoundAdvisorySnapshot(capturedAt: string) {
  const identity = advisoryRangeIdentityV2(
    doctorAdvisorySnapshotRow.ghsa_id,
    doctorAdvisorySnapshotRow.package_ecosystem,
    doctorAdvisorySnapshotRow.package_name,
    doctorAdvisorySnapshotRow.vulnerable_version_range,
  );
  const graphqlRange = {
    ghsaId: doctorAdvisorySnapshotRow.ghsa_id,
    cveId: doctorAdvisorySnapshotRow.cve_id,
    summary: doctorAdvisorySnapshotRow.summary,
    severity: doctorAdvisorySnapshotRow.severity,
    htmlUrl: doctorAdvisorySnapshotRow.html_url,
    publishedAt: doctorAdvisorySnapshotRow.published_at,
    withdrawnAt: null,
    ecosystem: doctorAdvisorySnapshotRow.package_ecosystem,
    packageName: doctorAdvisorySnapshotRow.package_name,
    vulnerableVersionRange: doctorAdvisorySnapshotRow.vulnerable_version_range,
    firstPatchedVersion: doctorAdvisorySnapshotRow.patched_versions,
    updatedAt: capturedAt,
    identity,
  } as const;
  const graphqlIdentities = [identity];
  const graphql = {
    source: 'graphql-security-vulnerabilities' as const,
    retrieval: {
      startedAt: capturedAt,
      completedAt: capturedAt,
    },
    ecosystem: doctorAdvisorySnapshotRow.package_ecosystem,
    packageName: doctorAdvisorySnapshotRow.package_name,
    exhausted: true,
    stabilized: true,
    totalCount: 1,
    nodeCount: 1,
    uniqueRangeCount: 1,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    digest: doctorNativeJsonHash([
      1,
      [[
        identity,
        graphqlRange.cveId,
        graphqlRange.summary,
        graphqlRange.severity,
        graphqlRange.htmlUrl,
        graphqlRange.publishedAt,
        graphqlRange.withdrawnAt,
        graphqlRange.firstPatchedVersion,
        graphqlRange.updatedAt,
      ]],
    ]),
    identityDigest: doctorNativeJsonHash(graphqlIdentities),
    ranges: [graphqlRange],
    rangeIdentities: graphqlIdentities,
  };
  const repositoryAdvisory = {
    ghsa_id: doctorAdvisorySnapshotRow.ghsa_id,
    cve_id: doctorAdvisorySnapshotRow.cve_id,
    summary: doctorAdvisorySnapshotRow.summary,
    severity: doctorAdvisorySnapshotRow.severity,
    state: 'published' as const,
    published_at: doctorAdvisorySnapshotRow.published_at,
    updated_at: capturedAt,
    withdrawn_at: null,
    html_url:
      `https://github.com/${config.github.owner}/${config.github.repo}/security/advisories/` +
      doctorAdvisorySnapshotRow.ghsa_id,
    vulnerabilities: [{
      package: {
        ecosystem: doctorAdvisorySnapshotRow.package_ecosystem,
        name: doctorAdvisorySnapshotRow.package_name,
      },
      vulnerable_version_range: doctorAdvisorySnapshotRow.vulnerable_version_range,
      patched_versions: doctorAdvisorySnapshotRow.patched_versions,
    }],
  };
  const repositoryRest = {
    source: 'repository-security-advisories-rest' as const,
    retrieval: {
      startedAt: capturedAt,
      completedAt: capturedAt,
    },
    stabilized: true,
    exhausted: false,
    totalCount: null,
    observedAdvisoryCount: 1,
    observedRangeCount: 1,
    targetRangeCount: 1,
    pageCount: 1,
    pagesFetched: 4,
    sweepCount: 4,
    digest: repositoryAdvisoryCatalogContentDigest([repositoryAdvisory]),
    identityDigest: doctorNativeJsonHash([
      1,
      [[doctorAdvisorySnapshotRow.ghsa_id, [identity]]],
    ]),
    targetIdentityDigest: doctorNativeJsonHash([identity]),
    allRangeIdentities: [identity],
    targetRangeIdentities: [identity],
    advisories: [repositoryAdvisory],
    completeness: {
      terminalPageProven: false,
      terminalPageEvidence: 'unproven-no-link' as const,
      terminalPageLinkHeaderPresent: false,
      remoteTotalCount: null,
      enumeratedCount: 1,
      crossOrderVerified: true,
      boundaryEvidence: {
        updatedAtDesc: {
          mode: 'single-page-no-link' as const,
          linkHeaderPresent: false,
          pageCount: 1,
          sweepCount: 2,
        },
        updatedAtAsc: {
          mode: 'single-page-no-link' as const,
          linkHeaderPresent: false,
          pageCount: 1,
          sweepCount: 2,
        },
      },
    },
  };
  return buildCompoundAdvisorySnapshot({
    capturedAt,
    repository: {
      owner: config.github.owner,
      name: config.github.repo,
      url: `https://github.com/${config.github.owner}/${config.github.repo}`,
    },
    target: {
      ecosystem: doctorAdvisorySnapshotRow.package_ecosystem,
      packageName: doctorAdvisorySnapshotRow.package_name,
    },
    sources: {
      graphql,
      repositoryRest,
    },
  });
}

function insertDoctorCompoundAdvisorySnapshot(
  db: DatabaseSync,
  capturedAt: string,
  options: { activate?: boolean } = {},
): number {
  const snapshot = doctorCompoundAdvisorySnapshot(capturedAt);
  const scoreRows = compoundAdvisoryScoreRows(snapshot);
  const scoreContentDigest = advisorySnapshotContentHash(scoreRows);
  const snapshotJson = canonicalCompoundAdvisorySnapshotJson(snapshot);
  const previousContentHash = (
    db.prepare(`
      SELECT content_hash
      FROM advisory_snapshot_v2_history
      ORDER BY id DESC
      LIMIT 1
    `).get() as { content_hash?: string } | undefined
  )?.content_hash ?? null;
  const contentHash = compoundAdvisorySnapshotLedgerContentHash({
    capturedAt,
    repository: snapshot.repository,
    target: snapshot.target,
    sourceHash: snapshot.sourceHash,
    catalogHash: snapshot.catalogHash,
    scoreHash: snapshot.scoreHash,
    rowCount: snapshot.rows.length,
    scoreRowCount: scoreRows.length,
    scoreContentDigest,
    snapshotJson,
    previousContentHash,
  });
  const inserted = db.prepare(`
    INSERT INTO advisory_snapshot_v2_history (
      schema_version, captured_at,
      repository_owner, repository_name, repository_url,
      target_ecosystem, target_package_name,
      source_hash, catalog_hash, score_hash, score_ready,
      row_count, score_row_count, score_content_digest,
      snapshot_json, previous_content_hash, content_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
  `).run(
    COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    capturedAt,
    snapshot.repository.owner,
    snapshot.repository.name,
    snapshot.repository.url,
    snapshot.target.ecosystem,
    snapshot.target.packageName,
    snapshot.sourceHash,
    snapshot.catalogHash,
    snapshot.scoreHash,
    snapshot.rows.length,
    scoreRows.length,
    scoreContentDigest,
    snapshotJson,
    previousContentHash,
    contentHash,
  );
  const snapshotId = Number(inserted.lastInsertRowid);
  for (const row of snapshot.rows) {
    db.prepare(`
      INSERT INTO advisory_snapshot_v2_rows (
        snapshot_id, range_identity, ghsa_id,
        package_ecosystem, package_name, vulnerable_version_range,
        state, target_package, score_eligible, audit_only,
        row_json, row_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      snapshotId,
      row.identity,
      row.ghsaId,
      row.ecosystem,
      row.packageName,
      row.vulnerableVersionRange,
      row.state,
      Number(row.targetPackage),
      Number(row.scoreEligible),
      Number(row.auditOnly),
      canonicalCompoundAdvisoryRangeRowJson(row),
      compoundAdvisorySnapshotRowContentHash(row),
    );
  }
  if (options.activate !== false) {
    db.prepare(`
      INSERT INTO meta(key, value) VALUES(?, ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `).run(
      ADVISORY_SNAPSHOT_V2_META_KEY,
      canonicalOperationJson({
        schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
        snapshotId,
        capturedAt,
        repository: snapshot.repository,
        target: snapshot.target,
        sourceHash: snapshot.sourceHash,
        catalogHash: snapshot.catalogHash,
        scoreHash: snapshot.scoreHash,
        contentHash,
        previousContentHash,
        rowCount: snapshot.rows.length,
        scoreRowCount: scoreRows.length,
        scoreReady: true,
        scoreContentDigest,
      }),
    );
  }
  return snapshotId;
}

function appendDoctorCurrentAdvisorySnapshot(db: DatabaseSync, snapshotId: number) {
  db.prepare(`
    INSERT INTO advisory_snapshot_history(id, captured_at, row_count, content_hash)
    VALUES (?, '2026-06-02T00:55:00Z', 1, ?)
  `).run(snapshotId, advisorySnapshotContentHash([doctorAdvisorySnapshotRow]));
  insertDoctorAdvisorySnapshotRow(db, { snapshotId });
}

function rewriteDoctorAdvisorySnapshotHash(db: DatabaseSync, snapshotId: number) {
  const rows = db.prepare(`
    SELECT advisory_key, ghsa_id, cve_id, summary, severity, html_url, published_at,
           package_ecosystem, package_name, vulnerable_version_range, patched_versions
    FROM advisory_snapshot_rows
    WHERE snapshot_id=?
  `).all(snapshotId) as any[];
  db.prepare(`
    UPDATE advisory_snapshot_history
    SET content_hash=?
    WHERE id=?
  `).run(advisorySnapshotContentHash(rows), snapshotId);
}

function rewriteDoctorAdvisoryCompletenessMetadata(db: DatabaseSync) {
  const rows = db.prepare(`
    SELECT advisory_key, ghsa_id, cve_id, summary, severity, html_url, published_at,
           package_ecosystem, package_name, vulnerable_version_range, patched_versions
    FROM advisories
    ORDER BY advisory_key
  `).all() as any[];
  const metadata = JSON.parse(String(db.prepare(`
    SELECT value FROM meta WHERE key=?
  `).get(ADVISORY_SNAPSHOT_META_KEY)?.value));
  db.prepare(`UPDATE meta SET value=? WHERE key=?`).run(
    JSON.stringify({
      ...metadata,
      rowCount: rows.length,
      contentDigest: advisorySnapshotContentHash(rows),
    }),
    ADVISORY_SNAPSHOT_META_KEY,
  );
}

function seedDoctorLegacyManifestForecast(
  db: DatabaseSync,
  options: { outOfWindow: boolean; corruptManifest?: boolean },
) {
  disableDoctorAppendOnlyTriggers(db, [
    'release_score_audit_history',
    'release_score_audit_history_runs',
    'release_score_audit_history_v2_seals',
  ]);
  db.prepare(`UPDATE release_score_audit_history SET id=id+10`).run();
  db.prepare(`UPDATE release_score_audit_history_runs SET id=id+10`).run();
  db.prepare(`UPDATE release_score_audit_history_v2_seals SET id=id+10`).run();
  const sources = [{
    source: 'legacy_score_inputs',
    count: 1,
    digest: 'c'.repeat(64),
  }];
  const schemaVersion = 4;
  const legacyManifest = {
    schemaVersion,
    sourceMode: 'current_db',
    scope: 'score_input_database',
    algorithm: 'sha256',
    rowCount: 1,
    sourceCount: sources.length,
    digest: scoreSourceIdentityManifestDigest(sources as any, schemaVersion),
    sources,
  };
  if (options.corruptManifest) legacyManifest.digest = '0'.repeat(64);
  const sourceIdentityJson = JSON.stringify(legacyManifest);
  const runId = 'run-legacy-manifest';
  const recordedAt = '2026-06-02T01:05:00.000Z';
  const currentAuthorityRun = db.prepare(`
    SELECT *
    FROM score_authority_resolution_runs
    WHERE authority_run_id='score-authority:run-doctor'
  `).get() as any;
  const legacyAuthorityRun = buildScoreAuthorityResolutionRun({
    authorityRunId: 'score-authority:run-legacy-manifest',
    sourceIdentitySchemaVersion: schemaVersion,
    sourceIdentityDigest: legacyManifest.digest,
    recordedAt,
    previousContentHash: currentAuthorityRun.content_hash,
    rows: [],
  });
  db.prepare(`
    INSERT INTO score_authority_resolution_runs (
      authority_run_id, schema_version, policy_version,
      source_identity_schema_version, source_identity_digest, recorded_at,
      row_count, rows_content_hash, previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    legacyAuthorityRun.authorityRunId,
    legacyAuthorityRun.schemaVersion,
    legacyAuthorityRun.policyVersion,
    legacyAuthorityRun.sourceIdentitySchemaVersion,
    legacyAuthorityRun.sourceIdentityDigest,
    legacyAuthorityRun.recordedAt,
    legacyAuthorityRun.rowCount,
    legacyAuthorityRun.rowsContentHash,
    legacyAuthorityRun.previousContentHash,
    legacyAuthorityRun.contentHash,
  );
  const base = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    WHERE run_id='run-doctor' AND release_tag='v2'
  `).get() as any;
  const { id: _baseId, ...baseValues } = base;
  db.prepare(`
    INSERT INTO release_score_audit_history (
      id, run_id, recorded_at, release_tag, scored_at, score_model_version,
      prompt_version, final_score, status, band, recommended, input_json,
      components_json, issue_evidence_json, gate_evidence_json, source_identity_json,
      authority_run_id
    )
    VALUES (
      1, :run_id, :recorded_at, :release_tag, :scored_at, :score_model_version,
      :prompt_version, :final_score, :status, :band, :recommended, :input_json,
      :components_json, :issue_evidence_json, :gate_evidence_json, :source_identity_json,
      :authority_run_id
    )
  `).run({
    ...baseValues,
    run_id: runId,
    recorded_at: recordedAt,
    source_identity_json: sourceIdentityJson,
    authority_run_id: legacyAuthorityRun.authorityRunId,
  });
  const historyRow = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    WHERE run_id=?
  `).get(runId) as any;
  const rowsContentHash = releaseScoreAuditHistoryRowsContentHash([historyRow]);
  const runContentHash = releaseScoreAuditHistoryRunContentHash({
    runId,
    recordedAt,
    rowCount: 1,
    rowsContentHash,
    previousContentHash: null,
  });
  db.prepare(`
    INSERT INTO release_score_audit_history_runs (
      id, run_id, recorded_at, row_count, rows_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (1, ?, ?, 1, ?, NULL, ?)
  `).run(runId, recordedAt, rowsContentHash, runContentHash);
  db.prepare(`
    UPDATE release_score_audit_history_runs
    SET previous_content_hash=?
    WHERE run_id='run-doctor'
  `).run(runContentHash);
  const authorityRun = db.prepare(`
    SELECT *
    FROM score_authority_resolution_runs
    WHERE authority_run_id=?
  `).get(historyRow.authority_run_id) as any;
  const legacyHistoryV2Seal = buildReleaseScoreAuditHistoryV2Seal({
    historyRunId: runId,
    authorityRunId: authorityRun.authority_run_id,
    sealedAt: recordedAt,
    historyRowCount: 1,
    historyRowsContentHash: rowsContentHash,
    authorityRowCount: Number(authorityRun.row_count),
    authorityRowsContentHash: authorityRun.rows_content_hash,
    previousContentHash: null,
  });
  db.prepare(`
    INSERT INTO release_score_audit_history_v2_seals (
      id, schema_version, history_run_id, authority_run_id, sealed_at,
      history_row_count, history_rows_content_hash, authority_row_count,
      authority_rows_content_hash, previous_content_hash, content_hash
    )
    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    legacyHistoryV2Seal.schemaVersion,
    legacyHistoryV2Seal.historyRunId,
    legacyHistoryV2Seal.authorityRunId,
    legacyHistoryV2Seal.sealedAt,
    legacyHistoryV2Seal.historyRowCount,
    legacyHistoryV2Seal.historyRowsContentHash,
    legacyHistoryV2Seal.authorityRowCount,
    legacyHistoryV2Seal.authorityRowsContentHash,
    legacyHistoryV2Seal.previousContentHash,
    legacyHistoryV2Seal.contentHash,
  );
  db.prepare(`
    UPDATE release_score_audit_history_v2_seals
    SET previous_content_hash=?
    WHERE history_run_id='run-doctor'
  `).run(legacyHistoryV2Seal.contentHash);
  rewriteDoctorHistorySeal(db, 'run-doctor');
  rebindDoctorRefreshReceiptToCurrentScoreTip(db);

  const opportunityCode = options.outOfWindow
    ? 'first_verified_after_3h'
    : 'first_verified_after_24h';
  const latestReleasePublishedAt = '2026-06-01T00:05:00Z';
  const candidateScores = [{
    releaseTag: historyRow.release_tag,
    scoreSnapshot: {
      scoredAt: historyRow.scored_at,
      finalScore: historyRow.final_score,
      status: historyRow.status,
      band: historyRow.band,
      recommended: historyRow.recommended === 1,
    },
    auditSnapshot: historyRow,
  }];
  const decision = {
    schemaVersion: 2,
    opportunityCode,
    recordedAt,
    latestReleaseTag: historyRow.release_tag,
    latestReleasePublishedAt,
    selectedTag: historyRow.release_tag,
    recommendationDecision: {
      selectedTag: historyRow.release_tag,
      policyCode: 'policy',
    },
  };
  const forecast = {
    id: 1,
    decision_id: 'pending',
    opportunity_code: opportunityCode,
    recorded_at: recordedAt,
    latest_release_tag: historyRow.release_tag,
    latest_release_published_at: latestReleasePublishedAt,
    selected_tag: historyRow.release_tag,
    audit_history_run_id: runId,
    score_model_version: historyRow.score_model_version,
    prompt_version: historyRow.prompt_version,
    policy_code: 'policy',
    candidate_scores_json: JSON.stringify(candidateScores),
    decision_json: JSON.stringify(decision),
    source_identity_json: sourceIdentityJson,
    code_revision: null,
    previous_content_hash: null,
    content_hash: '',
  };
  forecast.content_hash = releaseValidationForecastContentHash(forecast as any);
  forecast.decision_id = releaseValidationDecisionId(
    forecast as any,
    forecast.content_hash,
  );
  db.prepare(`
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
  `).run(forecast);
  reinstallDoctorAppendOnlyTriggers(db);
}

function seedDoctorCleanIssueCrawl(db: DatabaseSync) {
  const snapshotId = insertDoctorIssueCatalogSnapshot(
    db,
    '2026-06-02T00:54:00Z',
  );
  const consumption = insertDoctorIssueCatalogConsumption(db, snapshotId);
  const snapshot = db.prepare(`
    SELECT
      snapshot_id AS snapshotId,
      captured_at AS capturedAt,
      boundary_total_count AS boundaryTotalCount,
      observed_total_count AS observedTotalCount,
      post_boundary_growth_count AS postBoundaryGrowthCount,
      terminal_node_id AS terminalNodeId,
      terminal_issue_number AS terminalIssueNumber,
      terminal_created_at AS terminalCreatedAt,
      fetched_count AS fetchedCount,
      unique_count AS uniqueCount,
      page_count AS pageCount,
      pages_fetched AS pagesFetched,
      sweep_count AS sweepCount,
      membership_digest AS membershipDigest,
      content_digest AS contentDigest,
      content_hash AS contentHash
    FROM issue_catalog_snapshots
    WHERE snapshot_id=?
  `).get(snapshotId) as Record<string, any>;
  const baseline = issueCrawlBaselineFixture({
    establishedAt: '2026-06-02T01:04:00Z',
    crawlStartedAt: '2026-06-02T00:55:00Z',
    boundaryTotalCount: Number(snapshot.boundaryTotalCount),
    observedTotalCount: Number(snapshot.observedTotalCount),
    postBoundaryGrowthCount: Number(snapshot.postBoundaryGrowthCount),
    asOfBoundary: {
      totalCount: Number(snapshot.boundaryTotalCount),
      terminalIssue: {
        nodeId: snapshot.terminalNodeId,
        issueNumber: Number(snapshot.terminalIssueNumber),
        createdAt: snapshot.terminalCreatedAt,
      },
      membershipDigest: snapshot.membershipDigest,
    },
    fetchedCount: Number(snapshot.fetchedCount),
    uniqueCount: Number(snapshot.uniqueCount),
    pageCount: Number(snapshot.pageCount),
    pagesFetched: Number(snapshot.pagesFetched),
    sweepCount: Number(snapshot.sweepCount),
    digest: snapshot.membershipDigest,
    membershipDigest: snapshot.membershipDigest,
    contentDigest: snapshot.contentDigest,
  });
  const issueCrawl = issueCrawlFixture({
    baseline,
    pagination: {
      schemaVersion: 2,
      source: 'github.repository.issues',
      repository: 'openclaw/openclaw',
      sourceOrder: 'CREATED_AT_ASC',
      completeness: 'exhaustive_stable',
      boundaryTotalCount: Number(snapshot.boundaryTotalCount),
      observedTotalCount: Number(snapshot.observedTotalCount),
      postBoundaryGrowthCount: Number(snapshot.postBoundaryGrowthCount),
      asOfBoundary: baseline.asOfBoundary,
      fetchedCount: Number(snapshot.fetchedCount),
      uniqueCount: Number(snapshot.uniqueCount),
      pageCount: Number(snapshot.pageCount),
      pagesFetched: Number(snapshot.pagesFetched),
      sweepCount: Number(snapshot.sweepCount),
      exhausted: true,
      stabilized: true,
      digest: snapshot.membershipDigest,
      membershipDigest: snapshot.membershipDigest,
      contentDigest: snapshot.contentDigest,
      lastRequestCursor: null,
      nextCursor: null,
      hasNextPage: false,
    },
    catalogSnapshot: {
      schemaVersion: 1,
      snapshotId,
      contentHash: snapshot.contentHash,
      capturedAt: snapshot.capturedAt,
      resumed: false,
      priorStatus: 'missing',
      maxAgeHours: 24,
      consumedAt: consumption.consumedAt,
      consumedByRunId: consumption.runId,
      consumptionContentHash: consumption.contentHash,
    },
    catalogAttestation: {
      schemaVersion: 1,
      snapshotId,
      snapshotContentHash: snapshot.contentHash,
      observedAt: '2026-06-02T01:04:45Z',
      totalCount: Number(snapshot.boundaryTotalCount),
      membershipDigest: snapshot.membershipDigest,
      contentDigest: snapshot.contentDigest,
      finalSweepCount: 2,
      finalPagesFetched: 2,
    },
  });
  db.prepare(`
    INSERT INTO meta(key, value)
    VALUES('issue_crawl_last_run', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `).run(JSON.stringify(issueCrawl));
  db.prepare(`
    INSERT INTO meta(key, value)
    VALUES('issue_crawl_exhaustive_baseline', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `).run(JSON.stringify(baseline));
}

function insertDoctorIssueCatalogSnapshot(db: DatabaseSync, capturedAt: string): string {
  const issue = {
    node_id: 'ISSUE-doctor-catalog-1',
    node_type: 'Issue' as const,
    number: 1,
    title: 'Doctor issue',
    body: 'Doctor body',
    state: 'open' as const,
    user: {
      id: 'USER-doctor-reporter',
      type: 'User',
      login: 'doctor-reporter',
    },
    author_association: 'CONTRIBUTOR',
    created_at: '2026-06-01T00:00:00.000Z',
    updated_at: '2026-06-01T00:00:00.000Z',
    closed_at: null,
    html_url: 'https://example.test/issues/1',
    comments: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: [{ name: 'bug' }],
  };
  const records = [{ nodeId: issue.node_id, issue }];
  const membershipDigest = canonicalIssueMembershipDigest(1, records);
  const contentDigest = canonicalIssueContentDigest(1, records);
  const staged = stageIssueCatalogSnapshot({
    repository: 'openclaw/openclaw',
    capturedAt,
    previousContentHash: (
      db.prepare(`
        SELECT content_hash AS contentHash
        FROM issue_catalog_snapshots
        ORDER BY id DESC
        LIMIT 1
      `).get() as { contentHash?: string } | undefined
    )?.contentHash ?? null,
    catalog: {
      issues: [issue],
      metadata: {
        exhausted: true,
        stabilized: true,
        totalCount: 1,
        observedTotalCount: 1,
        postBoundaryGrowthCount: 0,
        nodeCount: 1,
        uniqueCount: 1,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        digest: membershipDigest,
        membershipDigest,
        contentDigest,
        snapshotBoundary: {
          totalCount: 1,
          terminalIssue: {
            nodeId: issue.node_id,
            issueNumber: issue.number,
            createdAt: issue.created_at,
          },
          membershipDigest,
        },
        lastRequestCursor: null,
        nextCursor: null,
        hasNextPage: false,
        sourceOrder: 'CREATED_AT_ASC',
      },
    },
  });
  const header = staged.header;
  db.prepare(`
    INSERT INTO issue_catalog_snapshots (
      snapshot_id, schema_version, row_schema_version, repository, source,
      source_order, captured_at, boundary_total_count, observed_total_count,
      post_boundary_growth_count, terminal_node_id, terminal_issue_number,
      terminal_created_at, fetched_count, unique_count, page_count,
      pages_fetched, sweep_count, membership_digest, content_digest,
      last_request_cursor, row_count, row_schema_digest, rows_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (
      :snapshot_id, :schema_version, :row_schema_version, :repository, :source,
      :source_order, :captured_at, :boundary_total_count, :observed_total_count,
      :post_boundary_growth_count, :terminal_node_id, :terminal_issue_number,
      :terminal_created_at, :fetched_count, :unique_count, :page_count,
      :pages_fetched, :sweep_count, :membership_digest, :content_digest,
      :last_request_cursor, :row_count, :row_schema_digest, :rows_content_hash,
      :previous_content_hash, :content_hash
    )
  `).run({
    snapshot_id: header.snapshotId,
    schema_version: header.schemaVersion,
    row_schema_version: header.rowSchemaVersion,
    repository: header.repository,
    source: header.source,
    source_order: header.sourceOrder,
    captured_at: header.capturedAt,
    boundary_total_count: header.boundaryTotalCount,
    observed_total_count: header.observedTotalCount,
    post_boundary_growth_count: header.postBoundaryGrowthCount,
    terminal_node_id: header.terminalNodeId,
    terminal_issue_number: header.terminalIssueNumber,
    terminal_created_at: header.terminalCreatedAt,
    fetched_count: header.fetchedCount,
    unique_count: header.uniqueCount,
    page_count: header.pageCount,
    pages_fetched: header.pagesFetched,
    sweep_count: header.sweepCount,
    membership_digest: header.membershipDigest,
    content_digest: header.contentDigest,
    last_request_cursor: header.lastRequestCursor,
    row_count: header.rowCount,
    row_schema_digest: header.rowSchemaDigest,
    rows_content_hash: header.rowsContentHash,
    previous_content_hash: header.previousContentHash,
    content_hash: header.contentHash,
  });
  const row = staged.rows[0];
  db.prepare(`
    INSERT INTO issue_catalog_snapshot_rows (
      snapshot_id, source_ordinal, issue_number, node_id, issue_json, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    row.snapshotId,
    row.sourceOrdinal,
    row.issueNumber,
    row.nodeId,
    row.issueJson,
    row.contentHash,
  );
  return header.snapshotId;
}

function insertDoctorIssueCatalogConsumption(
  db: DatabaseSync,
  snapshotId: string,
  {
    runId = 'doctor-refresh-run',
    consumedAt = '2026-06-02T01:04:30Z',
  }: {
    runId?: string;
    consumedAt?: string;
  } = {},
) {
  const snapshot = db.prepare(`
    SELECT
      snapshot_id AS snapshotId,
      repository,
      row_count AS rowCount,
      page_count AS pageCount,
      content_hash AS contentHash
    FROM issue_catalog_snapshots
    WHERE snapshot_id=?
  `).get(snapshotId) as {
    snapshotId: string;
    repository: string;
    rowCount: number;
    pageCount: number;
    contentHash: string;
  };
  const previousContentHash = (
    db.prepare(`
      SELECT content_hash AS contentHash
      FROM issue_catalog_snapshot_consumptions
      ORDER BY id DESC
      LIMIT 1
    `).get() as { contentHash?: string } | undefined
  )?.contentHash ?? null;
  const contentHash = createHash('sha256')
    .update(canonicalOperationJson([
      'issue-catalog-snapshot-consumption-v1',
      1,
      snapshot.snapshotId,
      snapshot.repository,
      runId,
      consumedAt,
      Number(snapshot.rowCount),
      Number(snapshot.pageCount),
      snapshot.contentHash,
      previousContentHash,
    ]))
    .digest('hex');
  db.prepare(`
    INSERT INTO issue_catalog_snapshot_consumptions (
      schema_version, snapshot_id, repository, run_id, consumed_at,
      processed_row_count, processed_page_count, snapshot_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    snapshot.snapshotId,
    snapshot.repository,
    runId,
    consumedAt,
    snapshot.rowCount,
    snapshot.pageCount,
    snapshot.contentHash,
    previousContentHash,
    contentHash,
  );
  return {
    ...snapshot,
    runId,
    consumedAt,
    previousContentHash,
    contentHash,
  };
}

function reinstallDoctorAppendOnlyTriggers(db: DatabaseSync) {
  disableDoctorAppendOnlyTriggers(db, [...IMMUTABLE_LEDGER_TABLES]);
  installDoctorAppendOnlyTriggers(db);
}

function writeScorePersistenceMeta(db: DatabaseSync, releaseTags: string[]) {
  const historyRun = db.prepare(`
    SELECT recorded_at, content_hash
    FROM release_score_audit_history_runs
    WHERE run_id='run-doctor'
  `).get() as { recorded_at: string; content_hash: string };
  const authorityRun = db.prepare(`
    SELECT authority_run_id, content_hash
    FROM score_authority_resolution_runs
    WHERE authority_run_id='score-authority:run-doctor'
  `).get() as { authority_run_id: string; content_hash: string };
  const historyV2Seal = db.prepare(`
    SELECT content_hash
    FROM release_score_audit_history_v2_seals
    WHERE history_run_id='run-doctor'
  `).get() as { content_hash: string };
  const scoreCommit = {
    schemaVersion: 4,
    historyRunId: 'run-doctor',
    historyRunContentHash: historyRun.content_hash,
    authorityRunId: authorityRun.authority_run_id,
    authorityRunContentHash: authorityRun.content_hash,
    historyV2SealContentHash: historyV2Seal.content_hash,
    historyRecordedAt: historyRun.recorded_at,
    commitNotBefore: historyRun.recorded_at,
    commitNotAfter: historyRun.recorded_at,
    commitNotBeforeMs: Date.parse(historyRun.recorded_at),
    commitNotAfterMs: Date.parse(historyRun.recorded_at),
  };
  db.prepare(`
    INSERT INTO meta (key, value)
    VALUES ('score_persistence_last_run', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `).run(JSON.stringify({
    schemaVersion: 2,
    source: 'test',
    scope: null,
    persistedAt: historyRun.recorded_at,
    scoreModelVersion: 'test-model',
    promptVersion: 6,
    scoredReleaseCount: releaseTags.length,
    recommendedTag: 'v2',
    releaseTags,
    minScoredAt: '2026-06-01T01:00:00.000Z',
    maxScoredAt: '2026-06-02T01:00:00.000Z',
    sourceIdentitySchemaVersion: doctorSourceIdentityFixture.schemaVersion,
    sourceIdentityDigest: doctorSourceIdentityFixture.digest,
    sourceIdentityRowCount: doctorSourceIdentityFixture.rowCount,
    sourceIdentitySourceCount: doctorSourceIdentityFixture.sourceCount,
    historyRunId: 'run-doctor',
    historyRunContentHash: historyRun.content_hash,
    authorityRunId: authorityRun.authority_run_id,
    authorityRunContentHash: authorityRun.content_hash,
    historyV2SealContentHash: historyV2Seal.content_hash,
    commitTiming: scoreCommit,
  }));
}

function rewriteDoctorHistorySeal(db: DatabaseSync, runId: string) {
  const rows = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    WHERE run_id=?
    ORDER BY release_tag
  `).all(runId) as Array<Record<string, unknown>>;
  const seal = db.prepare(`
    SELECT *
    FROM release_score_audit_history_runs
    WHERE run_id=?
  `).get(runId) as any;
  const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(rows);
  const contentHash = releaseScoreAuditHistoryRunContentHash({
    runId,
    recordedAt: seal.recorded_at,
    rowCount: rows.length,
    rowsContentHash,
    previousContentHash: seal.previous_content_hash ?? null,
  });
  db.prepare(`
    UPDATE release_score_audit_history_runs
    SET row_count=?, rows_content_hash=?, content_hash=?
    WHERE run_id=?
  `).run(rows.length, rowsContentHash, contentHash, runId);
  const authorityRun = db.prepare(`
    SELECT *
    FROM score_authority_resolution_runs
    WHERE authority_run_id=(
      SELECT authority_run_id
      FROM release_score_audit_history_v2_seals
      WHERE history_run_id=?
    )
  `).get(runId) as any;
  const storedV2Seal = db.prepare(`
    SELECT *
    FROM release_score_audit_history_v2_seals
    WHERE history_run_id=?
  `).get(runId) as any;
  let rewrittenHistoryV2SealContentHash: string | null = null;
  if (authorityRun && storedV2Seal) {
    const v2Seal = buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: runId,
      authorityRunId: authorityRun.authority_run_id,
      sealedAt: seal.recorded_at,
      historyRowCount: rows.length,
      historyRowsContentHash: rowsContentHash,
      authorityRowCount: Number(authorityRun.row_count),
      authorityRowsContentHash: authorityRun.rows_content_hash,
      previousContentHash: storedV2Seal.previous_content_hash ?? null,
    });
    db.prepare(`
      UPDATE release_score_audit_history_v2_seals
      SET sealed_at=?, history_row_count=?, history_rows_content_hash=?,
          authority_row_count=?, authority_rows_content_hash=?,
          previous_content_hash=?, content_hash=?
      WHERE history_run_id=?
    `).run(
      v2Seal.sealedAt,
      v2Seal.historyRowCount,
      v2Seal.historyRowsContentHash,
      v2Seal.authorityRowCount,
      v2Seal.authorityRowsContentHash,
      v2Seal.previousContentHash,
      v2Seal.contentHash,
      runId,
    );
    rewrittenHistoryV2SealContentHash = v2Seal.contentHash;
  }
  const meta = JSON.parse(String(db.prepare(`
    SELECT value FROM meta WHERE key='score_persistence_last_run'
  `).get()?.value));
  db.prepare(`
    UPDATE meta SET value=? WHERE key='score_persistence_last_run'
  `).run(JSON.stringify({
    ...meta,
    historyRunContentHash: contentHash,
    historyV2SealContentHash:
      rewrittenHistoryV2SealContentHash ?? meta.historyV2SealContentHash,
    commitTiming: meta.commitTiming
      ? {
          ...meta.commitTiming,
          historyRunContentHash: contentHash,
          historyV2SealContentHash:
            rewrittenHistoryV2SealContentHash ??
            meta.commitTiming.historyV2SealContentHash,
        }
      : meta.commitTiming,
  }));
}

function rebindDoctorRefreshReceiptToCurrentScoreTip(db: DatabaseSync) {
  const runId = 'refresh-doctor';
  const historyRun = db.prepare(`
    SELECT run_id, content_hash
    FROM release_score_audit_history_runs
    WHERE run_id='run-doctor'
  `).get() as { run_id: string; content_hash: string };
  const authorityRun = db.prepare(`
    SELECT authority_run_id, content_hash
    FROM score_authority_resolution_runs
    WHERE authority_run_id='score-authority:run-doctor'
  `).get() as { authority_run_id: string; content_hash: string };
  const historyV2Seal = db.prepare(`
    SELECT content_hash
    FROM release_score_audit_history_v2_seals
    WHERE history_run_id='run-doctor'
  `).get() as { content_hash: string };
  const stages = db.prepare(`
    SELECT *
    FROM refresh_operation_stage_events
    WHERE run_id=?
    ORDER BY sequence
  `).all(runId) as any[];
  const receipt = db.prepare(`
    SELECT *
    FROM refresh_capture_receipts
    WHERE run_id=?
  `).get(runId) as any;
  if (stages.length !== 4 || !receipt) {
    throw new Error('Doctor refresh receipt fixture is incomplete');
  }

  const scoreCompleted = stages[1];
  const scoreDetails = JSON.parse(scoreCompleted.details_json);
  scoreCompleted.details_json = canonicalOperationJson({
    ...scoreDetails,
    historyRunId: historyRun.run_id,
    historyRunContentHash: historyRun.content_hash,
    authorityRunId: authorityRun.authority_run_id,
    authorityRunContentHash: authorityRun.content_hash,
    historyV2SealContentHash: historyV2Seal.content_hash,
  });
  scoreCompleted.previous_content_hash = stages[0].content_hash;
  scoreCompleted.content_hash = operationStageEventContentHash({
    eventId: scoreCompleted.event_id,
    runId: scoreCompleted.run_id,
    sequence: Number(scoreCompleted.sequence),
    stage: scoreCompleted.stage,
    status: scoreCompleted.status,
    occurredAt: scoreCompleted.occurred_at,
    durationMs: scoreCompleted.duration_ms,
    countsJson: scoreCompleted.counts_json,
    detailsJson: scoreCompleted.details_json,
    previousContentHash: scoreCompleted.previous_content_hash,
  });

  for (let index = 2; index < stages.length; index += 1) {
    const stage = stages[index];
    stage.previous_content_hash = stages[index - 1].content_hash;
    stage.content_hash = operationStageEventContentHash({
      eventId: stage.event_id,
      runId: stage.run_id,
      sequence: Number(stage.sequence),
      stage: stage.stage,
      status: stage.status,
      occurredAt: stage.occurred_at,
      durationMs: stage.duration_ms,
      countsJson: stage.counts_json,
      detailsJson: stage.details_json,
      previousContentHash: stage.previous_content_hash,
    });
  }

  const payload = JSON.parse(receipt.payload_json);
  payload.scoreHistory = {
    ...payload.scoreHistory,
    runId: historyRun.run_id,
    contentHash: historyRun.content_hash,
  };
  payload.scoreAuthority = {
    ...payload.scoreAuthority,
    runId: authorityRun.authority_run_id,
    contentHash: authorityRun.content_hash,
    historyV2SealContentHash: historyV2Seal.content_hash,
  };
  payload.scoreCommit = {
    ...payload.scoreCommit,
    historyRunId: historyRun.run_id,
    historyRunContentHash: historyRun.content_hash,
    authorityRunId: authorityRun.authority_run_id,
    authorityRunContentHash: authorityRun.content_hash,
    historyV2SealContentHash: historyV2Seal.content_hash,
  };
  if (payload.scoreMetadata) {
    payload.scoreMetadata = {
      ...payload.scoreMetadata,
      historyRunId: historyRun.run_id,
      historyRunContentHash: historyRun.content_hash,
      authorityRunId: authorityRun.authority_run_id,
      authorityRunContentHash: authorityRun.content_hash,
      historyV2SealContentHash: historyV2Seal.content_hash,
      commitTiming: {
        ...payload.scoreMetadata.commitTiming,
        historyRunId: historyRun.run_id,
        historyRunContentHash: historyRun.content_hash,
        authorityRunId: authorityRun.authority_run_id,
        authorityRunContentHash: authorityRun.content_hash,
        historyV2SealContentHash: historyV2Seal.content_hash,
      },
    };
  }
  receipt.stage_chain_hash = stages.at(-1).content_hash;
  receipt.payload_json = canonicalOperationJson(payload);
  receipt.content_hash = operationCaptureReceiptContentHash({
    receiptId: receipt.receipt_id,
    runId: receipt.run_id,
    status: receipt.status,
    finishedAt: receipt.finished_at,
    durationMs: Number(receipt.duration_ms),
    stageEventCount: Number(receipt.stage_event_count),
    stageChainHash: receipt.stage_chain_hash,
    payloadJson: receipt.payload_json,
    previousContentHash: receipt.previous_content_hash ?? null,
  });

  disableDoctorAppendOnlyTriggers(db, [
    'refresh_operation_stage_events',
    'refresh_capture_receipts',
  ]);
  try {
    const updateStage = db.prepare(`
      UPDATE refresh_operation_stage_events
      SET previous_content_hash=?, details_json=?, content_hash=?
      WHERE event_id=?
    `);
    for (const stage of stages.slice(1)) {
      updateStage.run(
        stage.previous_content_hash,
        stage.details_json,
        stage.content_hash,
        stage.event_id,
      );
    }
    db.prepare(`
      UPDATE refresh_capture_receipts
      SET stage_chain_hash=?, payload_json=?, content_hash=?
      WHERE run_id=?
    `).run(
      receipt.stage_chain_hash,
      receipt.payload_json,
      receipt.content_hash,
      runId,
    );
  } finally {
    reinstallDoctorAppendOnlyTriggers(db);
  }
}

const doctorSourceIdentitySources = [
  { source: 'releases', count: 3, digest: 'b'.repeat(64) },
  { source: 'release_commits', count: 3, digest: 'b'.repeat(64) },
  { source: 'advisories', count: 1, digest: 'b'.repeat(64) },
  { source: 'advisory_snapshot', count: 1, digest: 'b'.repeat(64) },
  { source: 'advisory_snapshot_v2', count: 1, digest: 'b'.repeat(64) },
  { source: 'advisory_snapshot_v2_history', count: 1, digest: 'b'.repeat(64) },
  { source: 'advisory_snapshot_v2_rows', count: 1, digest: 'b'.repeat(64) },
  { source: 'issues', count: 1, digest: 'b'.repeat(64) },
  { source: 'classifications', count: 1, digest: 'b'.repeat(64) },
  { source: 'issue_comment_snapshots', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_label_events', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_label_evidence_snapshots', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_label_evidence_rows', count: 0, digest: 'b'.repeat(64) },
  { source: 'repository_collaborator_permission_snapshots_v2', count: 0, digest: 'b'.repeat(64) },
  { source: 'repository_collaborator_permission_rows_v2', count: 0, digest: 'b'.repeat(64) },
  { source: 'signed_maintainer_roster_snapshots', count: 0, digest: 'b'.repeat(64) },
  { source: 'signed_maintainer_roster_entries', count: 0, digest: 'b'.repeat(64) },
  { source: 'closure_claim_source_snapshots', count: 0, digest: 'b'.repeat(64) },
  { source: 'closure_claim_candidates', count: 0, digest: 'b'.repeat(64) },
  { source: 'closure_claim_extraction_receipts', count: 0, digest: 'b'.repeat(64) },
  { source: 'closure_claim_extraction_receipt_members', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_label_snapshots', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_closure_proofs', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_closure_events', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_reopen_events', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_state_event_snapshots', count: 1, digest: 'b'.repeat(64) },
  { source: 'issue_pr_links', count: 0, digest: 'b'.repeat(64) },
  { source: 'issue_commit_references', count: 0, digest: 'b'.repeat(64) },
  { source: 'pull_request_fixes', count: 0, digest: 'b'.repeat(64) },
  { source: 'release_pr_reachability', count: 0, digest: 'b'.repeat(64) },
  { source: 'release_closure_dependency_snapshots', count: 1, digest: 'b'.repeat(64) },
  { source: 'release_artifact_receipts', count: 0, digest: 'b'.repeat(64) },
] as const;

const doctorEffectiveScoringConfig = {
  schemaVersion: 1,
  repository: {
    owner: config.github.owner,
    repo: config.github.repo,
  },
  monitoredReleaseLimit: config.limits.releases,
  recommendation: {
    policyCode: 'highest_confidence_with_recency_tolerance' as const,
    threshold: 7.5,
    recencyTolerance: 0.25,
  },
};
const doctorSourceRuntimeIdentity = {
  codeRevision: 'doctor-test-revision',
  effectiveScoringConfig: doctorEffectiveScoringConfig,
  effectiveScoringConfigDigest:
    scoreEffectiveScoringConfigDigest(doctorEffectiveScoringConfig),
};

function doctorSourceIdentityDigest(
  sources: ReadonlyArray<{
    source: (typeof doctorSourceIdentitySources)[number]['source'];
    count: number;
    digest: string;
  }>,
) {
  return scoreSourceIdentityManifestDigest(
    sources,
    SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
    doctorSourceRuntimeIdentity,
  );
}

const doctorSourceIdentityFixture = {
  schemaVersion: SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  sourceMode: 'current_db',
  scope: 'score_input_database',
  algorithm: 'sha256',
  ...doctorSourceRuntimeIdentity,
  rowCount: 15,
  sourceCount: 32,
  digest: doctorSourceIdentityDigest(doctorSourceIdentitySources),
  sources: doctorSourceIdentitySources,
};

const doctorAdvisorySnapshotRow = {
  advisory_key: advisoryVulnerabilityKey(
    'GHSA-doctor-valid',
    'npm',
    config.github.repo,
    '<2.0.0',
  ),
  ghsa_id: 'GHSA-doctor-valid',
  cve_id: 'CVE-2026-0001',
  summary: 'Doctor advisory fixture',
  severity: 'high',
  html_url: 'https://github.com/advisories/GHSA-doctor-valid',
  published_at: '2026-06-01T12:00:00Z',
  package_ecosystem: 'npm',
  package_name: config.github.repo,
  vulnerable_version_range: '<2.0.0',
  patched_versions: '2.0.0',
};
