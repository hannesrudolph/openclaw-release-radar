import { after, afterEach, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import express from 'express';
import {
  recommendationDecisionSummary,
  type RecommendationDecisionContract,
} from './recommendationDecision.ts';
import {
  bandFor,
  bindScoreExplanationAudit,
  buildScoreLedgerV2,
  installConfidence,
  REC_THRESHOLD,
  RECOMMENDATION_RECENCY_TOLERANCE,
} from './score.ts';
import type { ScoreSourceIdentityOptions } from './scoreSourceIdentity.ts';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
  serializeCommentEvidence,
} from './commentEvidence.ts';
import { canonicalJson as canonicalOperationJson } from './operationReceipts.ts';
import { CLOSURE_PROOF_ANALYZER_VERSION } from './analysisVersions.ts';
import {
  releaseValidationDecisionId,
  releaseValidationForecastContentHash,
} from './releaseValidation.ts';
import {
  appendClassifierAttempt,
  captureClassifierRawModelOutput,
  captureClassifierRawResponse,
  createClassifierAttemptLedger,
  createClassifierAttemptRun,
  createClassifierAttemptTerminalReceipt,
} from './classifierAttemptLedger.ts';
import { verifyScoreAuditPayloadContracts } from './scoreAuditContracts.ts';
import { buildScoreAuthorityResolutionRun } from './scoreAuthorityResolution.ts';
import {
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle.ts';

const assignedWorkerDatabase =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownsTempDir = assignedWorkerDatabase === null;
const tempDir = assignedWorkerDatabase
  ? dirname(assignedWorkerDatabase)
  : mkdtempSync(join(tmpdir(), 'radar-api-routes-'));
const testDatabasePath = assignedWorkerDatabase ?? join(tempDir, 'radar.db');
process.env.DB_PATH = testDatabasePath;
assert.equal(
  process.env.DB_PATH,
  testDatabasePath,
  'API route tests must use their assigned worker/private database',
);
process.env.REFRESH_MINUTES = '0';
process.env.COMPARISON_API_ENABLED = 'true';
process.env.RADAR_CODE_REVISION ??= 'api-routes-test-revision';

const PRIMARY_RELEASE_TAG = 'v2026.6.1';
const PRIMARY_RELEASE_PUBLISHED_AT = '2026-06-01T00:00:00Z';
const BETA_RELEASE_TAG = 'v2026.7.1-beta.2';
const BETA_RELEASE_PUBLISHED_AT = '2026-07-01T00:00:00Z';
const PHANTOM_RELEASE_FIXTURES = [
  {
    tag: 'v2026.7.1',
    publishedAt: '2026-07-01T00:00:00Z',
  },
  {
    tag: 'v2026.6.30',
    publishedAt: '2026-06-30T00:00:00Z',
  },
] as const;
const PHANTOM_RELEASE_TAGS =
  PHANTOM_RELEASE_FIXTURES.map((release) => release.tag);

let server: Server | null = null;
let baseUrl: string;
let dbModule: typeof import('./db.ts');
let apiModule: typeof import('../routes/api.ts');
let configModule: typeof import('../config.ts');
let scoreSourceIdentityManifestDigest:
  (typeof import('./scoreSourceIdentity.ts'))['scoreSourceIdentityManifestDigest'];
let planReleaseValidationProofEvaluation:
  (typeof import('./releaseValidationProofEvaluation.ts'))['planReleaseValidationProofEvaluation'];
let scoreAuditRunSequence = 0;
let scoringVersions: {
  model: string;
  prompt: number;
  input: number;
  components: number;
  explanation: number;
  issueEvidence: number;
  gateEvidence: number;
};

async function getJsonExact(path: string): Promise<{
  status: number;
  body: any;
  headers: Headers;
}> {
  const response = await fetch(`${baseUrl}${path}`);
  return {
    status: response.status,
    body: await response.json(),
    headers: response.headers,
  };
}

async function getJson(path: string): Promise<{
  status: number;
  body: any;
  headers: Headers;
}> {
  const parsed = new URL(path, 'http://radar.test');
  const match = parsed.pathname.match(
    /^\/api\/releases\/([^/]+)\/review\/(issues|closure-proofs|reachability)$/,
  );
  if (
    match &&
    !parsed.searchParams.has('publicationSnapshot') &&
    !parsed.searchParams.has('auditDigest')
  ) {
    const releases = await getJsonExact('/api/releases');
    const tag = decodeURIComponent(match[1]);
    const release = Array.isArray(releases.body)
      ? releases.body.find((row: any) => row.tag === tag)
      : undefined;
    const key = ({
      issues: 'issues',
      'closure-proofs': 'closureProofs',
      reachability: 'reachability',
    } as const)[match[2] as 'issues' | 'closure-proofs' | 'reachability'];
    const bound = release?.auditLinks?.[key];
    if (typeof bound === 'string') {
      const url = new URL(bound, 'http://radar.test');
      parsed.searchParams.forEach((value, name) => url.searchParams.append(name, value));
      return getJsonExact(`${url.pathname}${url.search}`);
    }
  }
  return getJsonExact(path);
}

before(async () => {
  configModule = await import('../config.ts');
  assert.equal(
    configModule.config.db.path,
    testDatabasePath,
    'API route config must use the assigned worker/private database',
  );
  const scoreSourceIdentityModule =
    await import('./scoreSourceIdentity.ts');
  scoreSourceIdentityManifestDigest =
    scoreSourceIdentityModule.scoreSourceIdentityManifestDigest;
  const releaseValidationProofEvaluationModule =
    await import('./releaseValidationProofEvaluation.ts');
  planReleaseValidationProofEvaluation =
    releaseValidationProofEvaluationModule.planReleaseValidationProofEvaluation;
  (configModule.config.comparison as { apiEnabled: boolean }).apiEnabled = true;
  dbModule = await import(`./db.ts?api-routes-${Date.now()}`);
  const mainDatabase = (
    dbModule.db.prepare('PRAGMA database_list').all() as Array<{
      name: string;
      file: string;
    }>
  ).find((database) => database.name === 'main');
  const mainDatabasePath = mainDatabase?.file;
  assert.ok(mainDatabasePath);
  assert.equal(
    realpathSync.native(mainDatabasePath),
    realpathSync.native(testDatabasePath),
    'API route SQLite connection must use the assigned worker/private database',
  );
  const scoring = await import('./releaseScoring.ts');
  scoringVersions = {
    model: scoring.SCORE_MODEL_VERSION,
    prompt: scoring.PROMPT_VERSION,
    input: scoring.SCORE_INPUT_SCHEMA_VERSION,
    components: scoring.SCORE_COMPONENTS_SCHEMA_VERSION,
    explanation: scoring.SCORE_EXPLANATION_SCHEMA_VERSION,
    issueEvidence: scoring.ISSUE_EVIDENCE_SCHEMA_VERSION,
    gateEvidence: scoring.GATE_EVIDENCE_SCHEMA_VERSION,
  };
  restorePrimaryTestCatalog();
  seedIssue({
    number: 101,
    state: 'open',
    title: 'v2026.6.1 release local broad regression still open',
    createdAt: '2026-06-01T12:00:00Z',
    updatedAt: '2026-06-02T12:00:00Z',
    labels: ['P1', 'bug', 'regression'],
    classification: {
      sentiment: 'negative',
      severity: 'high',
      functionality: 'core',
      scope: 'broad',
      affectedUsers: 'many',
    },
  });
  seedIssue({
    number: 102,
    state: 'open',
    title: 'provider issue needs info',
    createdAt: '2026-06-01T13:00:00Z',
    updatedAt: '2026-06-02T13:00:00Z',
    labels: ['bug', 'stale'],
    classification: {
      sentiment: 'negative',
      severity: 'medium',
      functionality: 'provider',
      scope: 'moderate',
      affectedUsers: 'some',
    },
  });
  seedIssue({
    number: 108,
    state: 'open',
    title: 'Request: preserve session data during cleanup',
    createdAt: '2026-06-01T13:30:00Z',
    updatedAt: '2026-06-02T13:30:00Z',
    labels: ['impact:data-loss', 'clawsweeper:source-repro'],
    classification: {
      sentiment: 'neutral',
      severity: 'high',
      functionality: 'core',
      scope: 'moderate',
      affectedUsers: 'some',
    },
  });
  seedIssue({
    number: 103,
    state: 'closed',
    title: 'fixed release bug',
    createdAt: '2026-06-01T14:00:00Z',
    updatedAt: '2026-06-03T00:00:00Z',
    closedAt: '2026-06-03T00:00:00Z',
    labels: ['bug'],
  });
  seedClosure(103, '2026-06-03T00:00:00Z');
  seedClosureProof(103, 'fixed_in_release');
  seedIssue({
    number: 104,
    state: 'closed',
    title: 'fixed after release bug',
    createdAt: '2026-06-01T15:00:00Z',
    updatedAt: '2026-06-04T00:00:00Z',
    closedAt: '2026-06-04T00:00:00Z',
    labels: ['bug'],
  });
  seedClosure(104, '2026-06-04T00:00:00Z');
  seedClosureProof(104, 'fixed_after_release');
  seedIssue({
    number: 105,
    state: 'closed',
    title: 'neutral issue with unknown source commit proof',
    createdAt: '2026-06-01T16:00:00Z',
    updatedAt: '2026-06-05T00:00:00Z',
    closedAt: '2026-06-05T00:00:00Z',
    labels: ['question'],
    classification: {
      sentiment: 'neutral',
      severity: 'low',
      functionality: 'docs',
      scope: 'niche',
      affectedUsers: 'few',
    },
  });
  seedClosure(105, '2026-06-05T00:00:00Z');
  seedClosureProof(105, 'non_bug_direct_fix_commit_reachability_unknown', {
    hasReachableClosingPr: false,
    hasReachableFixCommit: false,
    hasNotReachableFixCommit: false,
    hasUnknownFixCommit: true,
    stateReasons: ['COMPLETED'],
    reachableFixCommits: [],
    notReachableFixCommits: [],
    unknownFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
    matchingComments: [{
      databaseId: 123456,
      issueNumber: 105,
      url: 'https://github.com/openclaw/openclaw/issues/105#issuecomment-123456',
      author: 'maintainer',
      createdAt: '2026-06-05T00:00:00Z',
      updatedAt: '2026-06-05T00:00:00Z',
      snippet: 'Fixed by commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a.',
    }],
    fixCommitProof: [{
      issueNumber: 105,
      sourceIssueNumber: 105,
      commitOid: 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
      source: 'ClosureComment.fixProof',
      referencedAt: '2026-06-05T00:00:00Z',
      sourceCommentDatabaseId: 123456,
      sourceCommentUrl: 'https://github.com/openclaw/openclaw/issues/105#issuecomment-123456',
      status: 'unknown',
      tagCommitOid: null,
      evidence: 'commit_unavailable',
      snippet: 'Fix evidence commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
      trustedSource: true,
      author: 'maintainer',
    }],
  });
  seedIssue({
    number: 199,
    state: 'closed',
    title: 'closed negative issue with an unsupported not-planned claim',
    createdAt: '2026-06-01T17:00:00Z',
    updatedAt: '2026-06-06T00:00:00Z',
    closedAt: '2026-06-06T00:00:00Z',
    labels: ['bug'],
    classification: {
      sentiment: 'negative',
      severity: 'high',
      functionality: 'core',
      scope: 'broad',
      affectedUsers: 'many',
    },
  });
  seedClosure(199, '2026-06-06T00:00:00Z');
  seedClosureProof(199, 'not_planned');
  seedReachability({
    prNumber: 123,
    status: 'reachable',
  });
  seedReachability({
    prNumber: 124,
    status: 'not_reachable',
  });
  const proofCheckedAt = new Date().toISOString();
  dbModule.db.prepare(`
    UPDATE issue_closure_proofs
    SET checked_at=?
    WHERE release_tag='v2026.6.1'
  `).run(proofCheckedAt);
  refreshClosureDependencySnapshot();

  apiModule = await import(`../routes/api.ts?api-routes-${Date.now()}`);
  const app = express();
  app.use('/api', apiModule.api);
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', () => resolve());
  });
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(() => {
  for (const runId of [
    'receipt-api-success',
    'receipt-api-failure',
    'receipt-api-abandoned',
  ]) {
    removeOperationReceiptFixture(runId);
  }
  removeReceiptHistoryRunFixture('history-receipt-api-success');
});

after(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) => {
      server!.close((error) => error ? reject(error) : resolve());
    });
  }
  dbModule.db.close();
  if (ownsTempDir) rmSync(tempDir, { recursive: true, force: true });
});

describe('audit API routes', () => {
  it('keeps liveness independent from semantic readiness', async () => {
    const live = await getJson('/api/live');
    assert.equal(live.status, 200);
    assert.equal(live.body.ok, true);
    assert.equal(live.body.status, 'live');

    const health = await getJson('/api/health');
    assert.equal(health.status, 503);
    assert.equal(health.body.ok, false);
    assert.equal(health.body.status, 'not_ready');
    assert.ok(health.body.failures.some((failure: any) =>
      failure.code === 'current_score_missing'));
  });

  it('publishes only the authorized stable from a catalog contaminated with inactive phantom rows', async () => {
    const nonPrimaryFixtureTags = [
      BETA_RELEASE_TAG,
      ...PHANTOM_RELEASE_TAGS,
    ];
    try {
      replaceTestActiveCatalog([
        testCatalogRelease(
          BETA_RELEASE_TAG,
          BETA_RELEASE_PUBLISHED_AT,
          true,
        ),
        primaryTestCatalogRelease(),
      ]);
      for (const phantom of PHANTOM_RELEASE_FIXTURES) {
        dbModule.upsertRelease(
          testCatalogRelease(phantom.tag, phantom.publishedAt),
        );
      }

      const catalog = dbModule.currentActiveReleaseCatalog();
      assert.equal(catalog.releaseCount, 2);
      assert.equal(catalog.stableCount, 1);
      assert.equal(catalog.prereleaseCount, 1);
      assert.deepEqual(
        catalog.tags,
        [BETA_RELEASE_TAG, PRIMARY_RELEASE_TAG],
      );
      assert.equal(catalog.latestStable?.tag, PRIMARY_RELEASE_TAG);
      const catalogAuthorization =
        dbModule.releaseCatalogCaptureReceiptLedgerIntegrity(catalog);
      assert.deepEqual(catalogAuthorization.problems, []);
      assert.ok(catalogAuthorization.latestPayload);
      assert.deepEqual(
        catalogAuthorization.latestPayload.activeCatalog.tags,
        [BETA_RELEASE_TAG, PRIMARY_RELEASE_TAG],
      );
      assert.deepEqual(
        dbModule.listActiveReleaseCatalogDb().map((release) => ({
          rank: release.catalog_rank,
          tag: release.tag,
          prerelease: release.prerelease,
        })),
        [
          { rank: 0, tag: BETA_RELEASE_TAG, prerelease: 1 },
          { rank: 1, tag: PRIMARY_RELEASE_TAG, prerelease: 0 },
        ],
      );
      for (const tag of PHANTOM_RELEASE_TAGS) {
        const phantom = dbModule.getRelease(tag);
        assert.ok(phantom, `${tag} fixture row must exist`);
        assert.equal(phantom.catalog_active, 0, tag);
        assert.equal(phantom.catalog_rank, null, tag);
        assert.equal(phantom.catalog_digest, null, tag);
        assert.equal(phantom.prerelease, 0, tag);
      }

      const releases = await getJsonExact('/api/releases');
      assert.equal(releases.status, 200, JSON.stringify({
        body: releases.body,
        lifecycle: apiModule.releaseApiWorkerLifecycleSnapshot(),
      }));
      assert.equal(releases.body.length, 1);
      const releaseTags = releases.body.map((release: any) => release.tag);
      assert.deepEqual(releaseTags, [PRIMARY_RELEASE_TAG]);
      assert.equal(releaseTags.includes(BETA_RELEASE_TAG), false);
      const primaryRelease = releases.body[0];
      for (const path of [
        primaryRelease.auditLinks.review,
        primaryRelease.auditLinks.issues,
        primaryRelease.auditLinks.closureProofs,
        primaryRelease.auditLinks.reachability,
      ]) {
        const response = await getJsonExact(path);
        assert.equal(response.status, 200, path);
      }

      const history = await getJsonExact('/api/releases/history');
      assert.equal(history.status, 200);
      assert.ok(history.body.every(
        (release: any) => release.tag === PRIMARY_RELEASE_TAG,
      ));
      const publicPayload = await getJsonExact('/api/public');
      assert.equal(publicPayload.status, 200);
      assert.deepEqual(
        publicPayload.body.releases.map((release: any) => release.tag),
        [PRIMARY_RELEASE_TAG],
      );
      const comparison = await getJsonExact('/api/comparison');
      assert.equal(comparison.status, 200);
      assert.deepEqual(
        comparison.body.releases.map((release: any) => release.tag),
        [PRIMARY_RELEASE_TAG],
      );
      for (const response of [
        releases,
        history,
        publicPayload,
        comparison,
      ]) {
        const serialized = JSON.stringify(response.body);
        for (const tag of nonPrimaryFixtureTags) {
          assert.equal(serialized.includes(tag), false, tag);
        }
      }

      for (const tag of nonPrimaryFixtureTags) {
        for (const suffix of [
          '/review',
          '/review/issues',
          '/review/closure-proofs',
          '/review/reachability',
        ]) {
          const path = `/api/releases/${encodeURIComponent(tag)}${suffix}`;
          const response = await getJsonExact(path);
          assert.equal(response.status, 404, path);
          assert.deepEqual(
            response.body,
            { error: 'release not found', tag },
            path,
          );
        }
      }
    } finally {
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`
        DELETE FROM releases
        WHERE tag IN (?, ?, ?)
      `).run(...nonPrimaryFixtureTags);
    }
  });

  it('fails closed if an authorized beta is relabeled stable after catalog capture', async () => {
    replaceTestActiveCatalog([
      testCatalogRelease(
        BETA_RELEASE_TAG,
        BETA_RELEASE_PUBLISHED_AT,
        true,
      ),
      primaryTestCatalogRelease(),
    ]);
    const releaseIndex = await getJsonExact('/api/releases');
    assert.equal(releaseIndex.status, 200);
    const primaryRelease = releaseIndex.body.find(
      (release: any) => release.tag === PRIMARY_RELEASE_TAG,
    );
    assert.ok(primaryRelease);
    const productSurfaces = [
      { path: '/api/releases', error: 'release payload unavailable' },
      { path: '/api/releases/history', error: 'release history unavailable' },
      { path: '/api/public', error: 'public payload unavailable' },
      { path: '/api/comparison', error: 'comparison payload unavailable' },
      {
        path: '/api/validation/opportunities',
        error: 'validation opportunity status unavailable',
      },
      { path: '/api/status', error: 'status unavailable' },
      { path: primaryRelease.auditLinks.review, error: 'release review unavailable' },
      {
        path: primaryRelease.auditLinks.issues,
        error: 'release issue evidence unavailable',
      },
      {
        path: primaryRelease.auditLinks.closureProofs,
        error: 'release closure proof evidence unavailable',
      },
      {
        path: primaryRelease.auditLinks.reachability,
        error: 'release reachability evidence unavailable',
      },
    ];
    const relabeledCatalog = [
      testCatalogRelease(
        BETA_RELEASE_TAG,
        BETA_RELEASE_PUBLISHED_AT,
        false,
      ),
      primaryTestCatalogRelease(),
    ];
    const relabeledIdentity =
      dbModule.projectActiveReleaseCatalog(relabeledCatalog);
    dbModule.db.prepare(`
      UPDATE releases
      SET prerelease=CASE WHEN tag=? THEN 0 ELSE prerelease END,
          catalog_digest=?
      WHERE catalog_active=1
    `).run(BETA_RELEASE_TAG, relabeledIdentity.digest);
    assert.ok(
      dbModule.releaseCatalogCaptureReceiptLedgerIntegrity(
        relabeledIdentity,
      ).problems.length > 0,
    );

    try {
      for (const surface of productSurfaces) {
        const response = await getJsonExact(surface.path);
        assert.equal(response.status, 503, surface.path);
        assert.equal(response.body.error, surface.error, surface.path);
      }
    } finally {
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`DELETE FROM releases WHERE tag=?`).run(
        BETA_RELEASE_TAG,
      );
    }
  });

  it('withholds actionability when the latest authorized stable has no sealed score', async () => {
    const latestStableTag = 'v2026.6.2';
    replaceTestActiveCatalog([
      testCatalogRelease(latestStableTag, '2026-06-02T00:00:00Z'),
      primaryTestCatalogRelease(),
    ]);
    seedScoreAuditState();

    try {
      const releases = await getJsonExact('/api/releases');
      assert.equal(releases.status, 200);
      assert.deepEqual(
        releases.body.map((release: any) => release.tag),
        [latestStableTag, PRIMARY_RELEASE_TAG],
      );
      const latest = releases.body[0];
      assert.equal(latest.finalScore, null);
      assert.equal(latest.status, 'stale');
      assert.equal(latest.recommended, false);
      assert.ok(latest.staleAudit.causes.includes('audit_missing'));
      const previous = releases.body[1];
      assert.equal(previous.finalScore, null);
      assert.equal(previous.recommended, false);
      assert.equal(previous.status, 'stale');

      const publicPayload = await getJsonExact('/api/public');
      assert.equal(publicPayload.status, 200);
      assert.equal(publicPayload.body.snapshot.actionable, false);
      assert.ok(publicPayload.body.releases.every(
        (release: any) =>
          release.score === null &&
          release.recommended === false &&
          release.status === 'stale',
      ));

      const health = await getJsonExact('/api/health');
      assert.equal(health.status, 503);
      assert.ok(health.body.failures.some(
        (failure: any) => failure.code === 'current_score_missing',
      ));

      const status = await getJsonExact('/api/status');
      assert.equal(status.status, 200);
      assert.equal(status.body.latestStableTag, latestStableTag);
      assert.equal(status.body.latestScoredTag, PRIMARY_RELEASE_TAG);
      assert.equal(status.body.lastScoredAt, null);
      assert.equal(status.body.dataFreshness, null);
      assert.equal(
        status.body.currentScoreAuthorizationStatus,
        'unavailable',
      );
      assert.equal(status.body.currentScoreAuthorizationSnapshotId, null);
    } finally {
      clearScoreAuditState();
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`DELETE FROM releases WHERE tag=?`).run(
        latestStableTag,
      );
    }
  });

  it('makes the public snapshot non-actionable when any surfaced stable lacks a sealed score', async () => {
    const scorelessTag = 'v2026.5.30';
    replaceTestActiveCatalog([
      primaryTestCatalogRelease(),
      testCatalogRelease(scorelessTag, '2026-05-30T00:00:00Z'),
    ]);
    seedScoreAuditState();

    try {
      const releases = await getJsonExact('/api/releases');
      assert.equal(releases.status, 200);
      const scored = releases.body.find(
        (release: any) => release.tag === PRIMARY_RELEASE_TAG,
      );
      assert.equal(scored.finalScore, 7.5);
      assert.equal(scored.recommended, true);
      const scoreless = releases.body.find(
        (release: any) => release.tag === scorelessTag,
      );
      assert.equal(scoreless.finalScore, null);
      assert.equal(scoreless.status, 'stale');
      assert.equal(scoreless.recommended, false);
      assert.ok(scoreless.staleAudit.causes.includes('audit_missing'));

      const publicPayload = await getJsonExact('/api/public');
      assert.equal(publicPayload.status, 200);
      assert.equal(publicPayload.body.snapshot.actionable, false);
      assert.ok(publicPayload.body.releases.every(
        (release: any) =>
          release.score === null &&
          release.recommended === false &&
          release.status === 'stale',
      ));
    } finally {
      clearScoreAuditState();
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`DELETE FROM releases WHERE tag=?`).run(
        scorelessTag,
      );
    }
  });

  it('marks every score-bearing, review, comparison, and status response no-store', async () => {
    const paths = [
      '/api/health',
      '/api/status',
      '/api/config',
      '/api/receipts?limit=1',
      '/api/receipts/missing-receipt',
      '/api/validation/opportunities',
      '/api/releases',
      '/api/releases/history',
      '/api/public',
      '/api/comparison',
      '/api/releases/v2026.6.1/review',
      '/api/releases/v2026.6.1/review/issues?limit=1',
      '/api/releases/v2026.6.1/review/closure-proofs?limit=1',
      '/api/releases/v2026.6.1/review/reachability?limit=1',
    ];
    for (const path of paths) {
      const response = await getJson(path);
      assert.equal(response.headers.get('cache-control'), 'no-store', path);
    }
  });

  it('shares one explicit snapshot identity across release, history, and public responses', async () => {
    const releases = await getJson('/api/releases');
    const history = await getJson('/api/releases/history');
    const publicPayload = await getJson('/api/public');
    const review = await getJson('/api/releases/v2026.6.1/review');
    const snapshotId = releases.headers.get('x-radar-snapshot-id');

    assert.match(snapshotId ?? '', /^[0-9a-f]{64}$/);
    assert.equal(history.headers.get('x-radar-snapshot-id'), snapshotId);
    assert.equal(publicPayload.headers.get('x-radar-snapshot-id'), snapshotId);
    assert.equal(review.headers.get('x-radar-snapshot-id'), snapshotId);
    assert.equal(review.body.snapshotId, snapshotId);
    assert.equal(publicPayload.body.snapshotId, snapshotId);
    assert.equal(publicPayload.body.snapshot.id, snapshotId);
    assert.equal(publicPayload.body.snapshot.stale, false);
    assert.equal(publicPayload.body.snapshot.actionable, false);
    assert.ok(releases.body.every((row: any) => row.snapshotId === snapshotId));
    assert.ok(history.body.every((row: any) => row.snapshotId === snapshotId));
    assert.ok(publicPayload.body.releases.every((row: any) => row.snapshotId === snapshotId));
  });

  it('returns 404 for inactive release tags and never retains them publicly', async () => {
    const replacementTag = 'v2026.6.2';
    const warmPublic = await getJsonExact('/api/public');
    assert.equal(warmPublic.status, 200);
    assert.ok(warmPublic.body.releases.some(
      (release: any) => release.tag === PRIMARY_RELEASE_TAG,
    ));

    replaceTestActiveCatalog([
      testCatalogRelease(replacementTag, '2026-06-02T00:00:00Z'),
    ]);
    try {
      assert.equal(
        dbModule.getRelease(PRIMARY_RELEASE_TAG)?.catalog_active,
        0,
      );
      for (const path of [
        `/api/releases/${PRIMARY_RELEASE_TAG}/review`,
        `/api/releases/${PRIMARY_RELEASE_TAG}/review/issues`,
        `/api/releases/${PRIMARY_RELEASE_TAG}/review/closure-proofs`,
        `/api/releases/${PRIMARY_RELEASE_TAG}/review/reachability`,
      ]) {
        const response = await getJsonExact(path);
        assert.equal(response.status, 404, path);
        assert.deepEqual(
          response.body,
          { error: 'release not found', tag: PRIMARY_RELEASE_TAG },
          path,
        );
        assert.equal(response.headers.get('cache-control'), 'no-store', path);
      }

      for (const path of [
        '/api/releases',
        '/api/releases/history',
        '/api/comparison',
      ]) {
        const response = await getJsonExact(path);
        assert.equal(response.status, 200, path);
        assert.doesNotMatch(JSON.stringify(response.body), /v2026\.6\.1/, path);
      }

      apiModule.setApiLocalRefreshingForTests(true);
      const publicPayload = await getJsonExact('/api/public');
      assert.equal(publicPayload.status, 503);
      assert.deepEqual(
        publicPayload.body,
        { error: 'public payload unavailable' },
      );
      assert.equal(publicPayload.headers.get('cache-control'), 'no-store');
      assert.doesNotMatch(
        JSON.stringify(publicPayload.body),
        /v2026\.6\.1/,
      );
    } finally {
      apiModule.setApiLocalRefreshingForTests(null);
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`DELETE FROM releases WHERE tag=?`).run(replacementTag);
    }
  });

  it('fails every release product surface closed for an unauthorized active catalog', async () => {
    const releaseIndex = await getJsonExact('/api/releases');
    assert.equal(releaseIndex.status, 200);
    const release = releaseIndex.body.find(
      (row: any) => row.tag === PRIMARY_RELEASE_TAG,
    );
    assert.ok(release);
    const cases = [
      { path: '/api/releases', error: 'release payload unavailable' },
      { path: '/api/releases/history', error: 'release history unavailable' },
      { path: '/api/public', error: 'public payload unavailable' },
      { path: '/api/comparison', error: 'comparison payload unavailable' },
      {
        path: '/api/validation/opportunities',
        error: 'validation opportunity status unavailable',
      },
      { path: release.auditLinks.review, error: 'release review unavailable' },
      {
        path: release.auditLinks.issues,
        error: 'release issue evidence unavailable',
      },
      {
        path: release.auditLinks.closureProofs,
        error: 'release closure proof evidence unavailable',
      },
      {
        path: release.auditLinks.reachability,
        error: 'release reachability evidence unavailable',
      },
    ];
    for (const testCase of cases) {
      const response = await getJsonExact(testCase.path);
      assert.equal(response.status, 200, testCase.path);
    }

    const unauthorizedRelease = {
      ...primaryTestCatalogRelease(),
      name: 'unauthorized active catalog mutation',
    };
    const unauthorizedIdentity = dbModule.projectActiveReleaseCatalog([
      unauthorizedRelease,
    ]);
    dbModule.db.prepare(`
      UPDATE releases
      SET name=?, catalog_digest=?
      WHERE tag=?
    `).run(
      unauthorizedRelease.name,
      unauthorizedIdentity.digest,
      PRIMARY_RELEASE_TAG,
    );
    assert.ok(
      dbModule.releaseCatalogCaptureReceiptLedgerIntegrity(
        unauthorizedIdentity,
      ).problems.length > 0,
    );

    try {
      for (const testCase of cases) {
        const response = await getJsonExact(testCase.path);
        assert.equal(response.status, 503, testCase.path);
        assert.equal(response.body.error, testCase.error, testCase.path);
        assert.equal(
          response.headers.get('cache-control'),
          'no-store',
          testCase.path,
        );
      }
    } finally {
      restorePrimaryTestCatalog();
      assert.deepEqual(
        dbModule.releaseCatalogCaptureReceiptLedgerIntegrity(
          dbModule.projectActiveReleaseCatalog([
            primaryTestCatalogRelease(),
          ]),
        ).problems,
        [],
      );
    }
  });

  it('exposes bounded, redacted, verified operation receipt history and status pointers', async () => {
    const bearer = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyZWNlaXB0LXRlc3QifQ.signaturevalue';
    const historyRunId = 'history-receipt-api-success';
    const historyPublication = seedReceiptHistoryRun(
      historyRunId,
      '2026-07-04T10:00:03.400Z',
      'v-api-test',
    );
    const scoreCommit = {
      schemaVersion: 4,
      historyRunId,
      historyRunContentHash: historyPublication.historyRunContentHash,
      authorityRunId: historyPublication.authorityRunId,
      authorityRunContentHash: historyPublication.authorityRunContentHash,
      historyV2SealContentHash: historyPublication.historyV2SealContentHash,
      historyRecordedAt: '2026-07-04T10:00:03.400Z',
      commitNotBefore: '2026-07-04T10:00:03.400Z',
      commitNotAfter: '2026-07-04T10:00:03.400Z',
      commitNotBeforeMs: Date.parse('2026-07-04T10:00:03.400Z'),
      commitNotAfterMs: Date.parse('2026-07-04T10:00:03.400Z'),
    };
    const success = seedOperationReceipt({
      runId: 'receipt-api-success',
      status: 'success',
      startedAt: '2026-07-04T10:00:00.000Z',
      finishedAt: '2026-07-04T10:00:04.000Z',
      stages: [
        {
          stage: 'release.fetch',
          status: 'started',
          occurredAt: '2026-07-04T10:00:01.000Z',
        },
        {
          stage: 'release.fetch',
          status: 'completed',
          occurredAt: '2026-07-04T10:00:03.000Z',
          durationMs: 2_000,
          counts: { releases: 10 },
          details: {
            authorization: `Bearer ${bearer}`,
            note: 'release catalog captured',
          },
        },
        {
          stage: 'score.persist',
          status: 'started',
          occurredAt: '2026-07-04T10:00:03.100Z',
        },
        {
          stage: 'score.persist',
          status: 'completed',
          occurredAt: '2026-07-04T10:00:03.400Z',
          durationMs: 300,
          counts: { scoredReleases: 1 },
          details: {
            historyRunId,
            historyRunContentHash: historyPublication.historyRunContentHash,
            ...scoreCommit,
          },
        },
        {
          stage: 'forecast.capture',
          status: 'started',
          occurredAt: '2026-07-04T10:00:03.500Z',
        },
        {
          stage: 'forecast.capture',
          status: 'completed',
          occurredAt: '2026-07-04T10:00:04.000Z',
          durationMs: 500,
          counts: { validationForecasts: 0 },
          details: { eligibilityOutcome: 'not_eligible' },
        },
      ],
      payload: {
        schemaVersion: 1,
        operation: 'refresh',
        trigger: 'api-test',
        codeRevision: 'revision-receipt-api-success',
        apiKey: 'receipt-api-secret-value',
        message: `Bearer ${bearer}`,
        oversized: 'x'.repeat(5_000),
        scoreHistory: {
          runId: historyRunId,
          contentHash: historyPublication.historyRunContentHash,
          persistedAt: '2026-07-04T10:00:03.400Z',
        },
        scoreAuthority: {
          runId: historyPublication.authorityRunId,
          contentHash: historyPublication.authorityRunContentHash,
          historyV2SealContentHash:
            historyPublication.historyV2SealContentHash,
        },
        scoreCommit,
        releaseTags: ['v-api-test'],
        forecast: {
          eligibilityOutcome: 'not_eligible',
          decisionIds: [],
          captures: [],
        },
      },
    });
    const failure = seedOperationReceipt({
      runId: 'receipt-api-failure',
      status: 'failure',
      startedAt: '2026-07-04T11:00:00.000Z',
      finishedAt: '2026-07-04T11:00:03.000Z',
      stages: [
        {
          stage: 'issue.fetch',
          status: 'started',
          occurredAt: '2026-07-04T11:00:01.000Z',
        },
        {
          stage: 'issue.fetch',
          status: 'failed',
          occurredAt: '2026-07-04T11:00:02.000Z',
          durationMs: 1_000,
          details: { password: 'receipt-stage-secret' },
        },
      ],
      payload: {
        schemaVersion: 1,
        error: { message: 'synthetic receipt API failure' },
      },
    });
    const abandoned = seedOperationReceipt({
      runId: 'receipt-api-abandoned',
      status: 'abandoned',
      startedAt: '2026-07-04T12:00:00.000Z',
      finishedAt: '2026-07-04T12:05:00.000Z',
      payload: {
        schemaVersion: 1,
        reason: 'lease_expired',
        successorRunId: 'receipt-api-successor',
      },
    });

    const list = await getJson('/api/receipts?limit=2');
    assert.equal(list.status, 200);
    assert.equal(list.headers.get('cache-control'), 'no-store');
    assert.equal(list.body.schemaVersion, 1);
    assert.equal(list.body.limit, 2);
    assert.equal(list.body.count, 2);
    assert.equal(list.body.hasMore, true);
    assert.equal(list.body.verification.status, 'verified');
    assert.deepEqual(
      list.body.receipts.map((receipt: any) => [receipt.runId, receipt.outcome]),
      [
        ['receipt-api-abandoned', 'abandoned'],
        ['receipt-api-failure', 'failure'],
      ],
    );

    const byReceipt = await getJson(`/api/receipts/${success.receipt_id}`);
    assert.equal(byReceipt.status, 200);
    assert.equal(byReceipt.body.matchedBy, 'receipt_id');
    assert.equal(byReceipt.body.receipt.outcome, 'success');
    assert.deepEqual(
      byReceipt.body.receipt.stages.map((stage: any) => stage.sequence),
      [1, 2, 3, 4, 5, 6],
    );
    assert.equal(byReceipt.body.receipt.verification.status, 'verified');
    assert.match(byReceipt.body.receipt.attempt.hashes.effectiveConfig, /^[0-9a-f]{64}$/);
    assert.match(byReceipt.body.receipt.attempt.hashes.content, /^[0-9a-f]{64}$/);
    assert.match(byReceipt.body.receipt.terminal.hashes.content, /^[0-9a-f]{64}$/);
    assert.equal(byReceipt.body.receipt.terminal.payload.apiKey, '[redacted]');
    assert.equal(byReceipt.body.receipt.terminal.payloadTruncated, true);
    assert.deepEqual(byReceipt.body.receipt.links, {
      historyRunId: 'history-receipt-api-success',
      historyRunContentHash: historyPublication.historyRunContentHash,
      forecastDecisionIds: [],
    });
    const serialized = JSON.stringify(byReceipt.body);
    for (const secret of [
      bearer,
      'receipt-api-secret-value',
      'receipt-stage-secret',
      'config-receipt-api-success-secret',
    ]) {
      assert.equal(serialized.includes(secret), false, secret);
    }
    assert.equal(serialized.includes('effective_config_json'), false);

    const byRun = await getJson('/api/receipts/receipt-api-success');
    assert.equal(byRun.status, 200);
    assert.equal(byRun.body.matchedBy, 'run_id');
    assert.equal(byRun.body.receipt.receiptId, success.receipt_id);

    for (const path of [
      '/api/receipts?limit=0',
      '/api/receipts?limit=26',
      '/api/receipts?limit=1&limit=2',
      '/api/receipts/bad%20id',
    ]) {
      const response = await getJson(path);
      assert.equal(response.status, 400, path);
      assert.equal(response.headers.get('cache-control'), 'no-store', path);
    }
    const missing = await getJson('/api/receipts/receipt-api-missing');
    assert.equal(missing.status, 404);

    const status = await getJson('/api/status');
    assert.equal(status.body.activeRunId, null);
    assert.equal(status.body.latestAttemptRunId, abandoned.run_id);
    assert.equal(status.body.latestTerminalReceiptId, abandoned.receipt_id);
    assert.equal(status.body.latestTerminalReceiptStatus, 'abandoned');
    assert.equal(status.body.latestSuccessReceiptId, success.receipt_id);
    assert.equal(status.body.latestSuccessRunId, success.run_id);
    assert.equal(status.body.latestFailureReceiptId, failure.receipt_id);
    assert.equal(status.body.latestFailureRunId, failure.run_id);
    assert.equal(status.body.currentScoreReceiptId, null);
    assert.equal(status.body.currentScoreAuthorizationStatus, 'unavailable');
  });

  it('reports exact current canonical validation and promotion authority', async () => {
    const repository = 'openclaw/openclaw';
    const publishedAt = '2026-07-01T00:00:00.000Z';
    const lifecycle = planReleaseValidationProofLifecycle({
      existing: dbModule.readReleaseValidationProofBundle(),
      repository,
      observedAt: publishedAt,
      source: 'api-validation-proof-catalog',
      releases: [{
        repository,
        nodeId: 'R_api_validation_proof',
        tagCommitOid: 'a'.repeat(40),
        publishedAt,
        aliases: ['2099.7.1'],
      }],
      modelVersion: 'api-validation-model',
      promptVersion: 9,
      codeRevision: 'api-validation-revision',
      policyCode: 'prospective-release-validation',
      policyVersion: 1,
      developmentArm: 'production',
    });
    dbModule.appendReleaseValidationProof(lifecycle.append);
    const evaluatedAt = '2026-07-04T10:00:00.000Z';
    const evaluationCount =
      dbModule.readReleaseValidationProofBundle().evaluationReceipts.length;
    assert.throws(
      () => planReleaseValidationProofEvaluation({
        bundle: dbModule.readReleaseValidationProofBundle(),
        evaluatedAt,
        status: 'validated',
        metrics: {
          schemaVersion: 4,
          generatedAt: evaluatedAt,
          status: 'validated',
        },
      }),
      /not production-authorized/,
    );
    assert.equal(
      dbModule.readReleaseValidationProofBundle().evaluationReceipts.length,
      evaluationCount,
    );
  });

  it('keeps hash-chain verification separate while rejecting dangling receipt links', async () => {
    const historyRunId = `missing-history-${Date.now()}`;
    const historyRunContentHash = createHash('sha256').update(historyRunId).digest('hex');
    const authorityRunId = `missing-authority-${Date.now()}`;
    const authorityRunContentHash = createHash('sha256')
      .update(authorityRunId)
      .digest('hex');
    const historyV2SealContentHash = createHash('sha256')
      .update(`history-v2:${historyRunId}`)
      .digest('hex');
    const decisionId = `missing-forecast-${Date.now()}`;
    const scoreCommit = {
      schemaVersion: 4,
      historyRunId,
      historyRunContentHash,
      authorityRunId,
      authorityRunContentHash,
      historyV2SealContentHash,
      historyRecordedAt: '2026-07-04T13:00:02.000Z',
      commitNotBefore: '2026-07-04T13:00:02.000Z',
      commitNotAfter: '2026-07-04T13:00:02.000Z',
      commitNotBeforeMs: Date.parse('2026-07-04T13:00:02.000Z'),
      commitNotAfterMs: Date.parse('2026-07-04T13:00:02.000Z'),
    };
    const receipt = seedOperationReceipt({
      runId: `receipt-api-dangling-${Date.now()}`,
      status: 'success',
      startedAt: '2026-07-04T13:00:00.000Z',
      finishedAt: '2026-07-04T13:00:04.000Z',
      stages: [
        {
          stage: 'score.persist',
          status: 'started',
          occurredAt: '2026-07-04T13:00:01.000Z',
        },
        {
          stage: 'score.persist',
          status: 'completed',
          occurredAt: '2026-07-04T13:00:02.000Z',
          durationMs: 1_000,
          counts: { scoredReleases: 1 },
          details: {
            historyRunId,
            historyRunContentHash,
            ...scoreCommit,
          },
        },
        {
          stage: 'forecast.capture',
          status: 'started',
          occurredAt: '2026-07-04T13:00:03.000Z',
        },
        {
          stage: 'forecast.capture',
          status: 'completed',
          occurredAt: '2026-07-04T13:00:04.000Z',
          durationMs: 1_000,
          counts: { validationForecasts: 1 },
          details: { eligibilityOutcome: 'eligible_and_captured' },
        },
      ],
      payload: {
        schemaVersion: 1,
        operation: 'refresh',
        trigger: 'api-test',
        scoreHistory: {
          runId: historyRunId,
          contentHash: historyRunContentHash,
        },
        scoreAuthority: {
          runId: authorityRunId,
          contentHash: authorityRunContentHash,
          historyV2SealContentHash,
        },
        scoreCommit,
        releaseTags: ['v-dangling'],
        forecast: {
          eligibilityOutcome: 'eligible_and_captured',
          decisionIds: [decisionId],
          newDecisionIds: [decisionId],
          existingDecisionIds: [],
          captures: [{ decisionId, status: 'inserted' }],
        },
      },
    });

    try {
      const response = await getJson(`/api/receipts/${receipt.receipt_id}`);
      assert.equal(response.status, 200);
      assert.equal(response.body.receipt.verification.hashChain.verified, true);
      assert.equal(response.body.receipt.verification.semanticLinks.verified, false);
      assert.equal(response.body.receipt.verification.status, 'failed');
      assert.ok(response.body.receipt.verification.semanticLinks.problems.some(
        (problem: string) => /dangling score history link|dangling forecast link/.test(problem),
      ));
    } finally {
      removeOperationReceiptFixture(receipt.run_id);
    }
  });

  it('verifies valid existing-capture linkage through original history rows and seals', async () => {
    const fixture = seedExistingCaptureReceiptFixture(`valid-${Date.now()}`);
    try {
      const detail = await getJson(`/api/receipts/${fixture.receipt.receipt_id}`);
      assert.equal(detail.status, 200);
      assert.equal(detail.body.receipt.verification.semanticLinks.verified, true);
      assert.equal(detail.body.receipt.verification.status, 'verified');

      const list = await getJson('/api/receipts?limit=25');
      const listed = list.body.receipts.find(
        (receipt: any) => receipt.receiptId === fixture.receipt.receipt_id,
      );
      assert.equal(listed?.verification.semanticLinks.verified, true);
      assert.equal(listed?.verification.status, 'verified');
    } finally {
      removeExistingCaptureReceiptFixture(fixture);
    }
  });

  it('fails receipt APIs closed when an existing capture loses its original seal', async () => {
    const fixture = seedExistingCaptureReceiptFixture(`missing-seal-${Date.now()}`);
    try {
      deleteReceiptHistorySealFixture(fixture.originalHistoryRunId);
      const detail = await getJson(`/api/receipts/${fixture.receipt.receipt_id}`);
      assert.equal(detail.status, 200);
      assert.equal(detail.body.receipt.verification.hashChain.verified, true);
      assert.equal(detail.body.receipt.verification.semanticLinks.verified, false);
      assert.ok(detail.body.receipt.verification.semanticLinks.problems.some(
        (problem: string) => /original sealed score run|missing its seal/.test(problem),
      ));
    } finally {
      removeExistingCaptureReceiptFixture(fixture);
    }
  });

  it('fails receipt APIs closed on tampered original history rows', async () => {
    const fixture = seedExistingCaptureReceiptFixture(`tampered-history-${Date.now()}`);
    try {
      mutateReceiptHistoryRowFixture(fixture.originalHistoryRunId, () => {
        dbModule.db.prepare(`
          UPDATE release_score_audit_history
          SET final_score=1
          WHERE run_id=?
        `).run(fixture.originalHistoryRunId);
      });
      const detail = await getJson(`/api/receipts/${fixture.receipt.receipt_id}`);
      assert.equal(detail.status, 200);
      assert.equal(detail.body.receipt.verification.semanticLinks.verified, false);
      assert.ok(detail.body.receipt.verification.semanticLinks.problems.some(
        (problem: string) =>
          /row-set hash does not match|does not match score audit history/.test(problem),
      ));
    } finally {
      removeExistingCaptureReceiptFixture(fixture);
    }
  });

  it('fails receipt APIs closed on cross-run forecast aliases', async () => {
    const fixture = seedExistingCaptureReceiptFixture(
      `cross-run-${Date.now()}`,
      { crossRunAlias: true },
    );
    try {
      const detail = await getJson(`/api/receipts/${fixture.receipt.receipt_id}`);
      assert.equal(detail.status, 200);
      assert.equal(detail.body.receipt.verification.semanticLinks.verified, false);
      assert.ok(detail.body.receipt.verification.semanticLinks.problems.some(
        (problem: string) => /does not match score audit history/.test(problem),
      ));
    } finally {
      removeExistingCaptureReceiptFixture(fixture);
    }
  });

  it('reports a refresh running in another process from its durable lease and attempt', async () => {
    const runId = `cross-process-active-${Date.now()}`;
    const holderId = `holder-${runId}`;
    const startedAt = new Date().toISOString();
    const ttlMs = 300_000;
    try {
      assert.equal(
        dbModule.acquireRefreshLease('github-refresh', holderId, startedAt, ttlMs),
        true,
      );
      dbModule.insertRefreshOperationAttempt({
        run_id: runId,
        operation: 'refresh',
        trigger: 'manual-test',
        started_at: startedAt,
        lease_name: 'github-refresh',
        lease_holder_id: holderId,
        lease_expires_at: new Date(Date.parse(startedAt) + ttlMs).toISOString(),
        code_revision: `revision-${runId}`,
        effective_config: { schemaVersion: 1 },
      });
      dbModule.appendRefreshOperationStageEvent({
        run_id: runId,
        lease_name: 'github-refresh',
        lease_holder_id: holderId,
        stage: 'issue.catalog',
        status: 'started',
        occurred_at: new Date(Date.parse(startedAt) + 1).toISOString(),
      });

      const active = await getJson('/api/status');
      assert.equal(active.status, 200);
      assert.equal(active.body.refreshing, true);
      assert.equal(active.body.activeRunId, runId);
      assert.equal(active.body.activeOperation, 'refresh');
      assert.equal(active.body.activeTrigger, 'manual-test');
      assert.equal(active.body.activeStartedAt, startedAt);
      assert.equal(
        active.body.activeLeaseExpiresAt,
        new Date(Date.parse(startedAt) + ttlMs).toISOString(),
      );
      assert.equal(active.body.activeStage, 'issue.catalog');
      assert.equal(active.body.lastError, null);
    } finally {
      dbModule.releaseRefreshLease('github-refresh', holderId);
      removeOperationReceiptFixture(runId);
    }

    const inactive = await getJson('/api/status');
    assert.equal(inactive.status, 200);
    assert.equal(inactive.body.refreshing, false);
    assert.equal(inactive.body.activeRunId, null);
    assert.equal(inactive.body.activeStage, null);
  });

  it('withholds every score surface for a cross-process lease-only refresh', async () => {
    seedScoreAuditState();
    const warmPublic = await getJson('/api/public');
    assert.equal(warmPublic.status, 200);
    assert.equal(warmPublic.body.snapshot.source, 'current');
    assert.equal(warmPublic.body.snapshot.actionable, true);
    const holderId = `lease-only-${Date.now()}`;
    const acquiredAt = new Date().toISOString();
    const ttlMs = 300_000;
    const expiresAt = new Date(Date.parse(acquiredAt) + ttlMs).toISOString();
    try {
      assert.equal(
        dbModule.acquireRefreshLease('github-refresh', holderId, acquiredAt, ttlMs),
        true,
      );
      const status = await getJson('/api/status');
      assert.equal(status.status, 200);
      assert.equal(status.body.refreshing, true);
      assert.equal(status.body.activeRunId, null);
      assert.equal(status.body.activeStartedAt, null);
      assert.equal(status.body.activeLeaseExpiresAt, expiresAt);
      await assertScoreSurfacesFailClosed(
        'cross-process lease-only refresh',
        'refresh_in_progress',
        {
          snapshotId: warmPublic.body.snapshot.id,
          release: warmPublic.body.releases.find(
            (row: any) => row.tag === 'v2026.6.1',
          ),
        },
      );
    } finally {
      dbModule.releaseRefreshLease('github-refresh', holderId);
      clearScoreAuditState();
    }

    const inactive = await getJson('/api/status');
    assert.equal(inactive.status, 200);
    assert.equal(inactive.body.refreshing, false);
    assert.equal(inactive.body.activeRunId, null);
    assert.equal(inactive.body.activeLeaseExpiresAt, null);
  });

  it('keeps worker-built score surfaces guarded when local refresh outlives its lease', async () => {
    seedScoreAuditState();
    const holderId = `local-refresh-${Date.now()}`;
    const acquiredAt = new Date().toISOString();
    let leaseHeld = false;
    await waitForReleaseWorkerIdle();
    await waitForScoreReadWorkerIdle();
    apiModule.resetReleaseApiWorkerLifecycleForTests();
    apiModule.resetScoreReadWorkerLifecycleForTests();
    process.env.RADAR_TEST_RELEASE_WORKER_DELAY_MS = '200';
    try {
      assert.equal(
        dbModule.acquireRefreshLease('github-refresh', holderId, acquiredAt, 300_000),
        true,
      );
      leaseHeld = true;
      apiModule.setApiLocalRefreshingForTests(true);

      const releasesPromise = getJson('/api/releases');
      await waitForCondition(
        () => apiModule.releaseApiWorkerLifecycleSnapshot().active === 1,
        'locally guarded release API worker',
      );
      assert.equal(dbModule.releaseRefreshLease('github-refresh', holderId), true);
      leaseHeld = false;

      const releases = await within(
        releasesPromise,
        5_000,
        'release API retry after local lease loss',
      );
      assert.equal(releases.status, 200);
      const release = releases.body.find((row: any) => row.tag === 'v2026.6.1');
      assert.equal(release.finalScore, null);
      assert.equal(release.recommended, false);
      assert.equal(release.status, 'stale');
      assert.ok(release.staleAudit.causes.includes('refresh_in_progress'));
      assert.ok(apiModule.releaseApiWorkerLifecycleSnapshot().spawned >= 2);

      const status = await getJson('/api/status');
      assert.equal(status.body.refreshing, true);
      assert.equal(status.body.activeLeaseExpiresAt, null);

      const history = await getJson('/api/releases/history');
      assert.equal(history.status, 200);
      const historyRelease = history.body.find(
        (row: any) => row.tag === 'v2026.6.1',
      );
      assert.equal(historyRelease.finalScore, null);
      assert.equal(historyRelease.recommended, false);
      assert.ok(historyRelease.staleAudit.causes.includes('refresh_in_progress'));

      const review = await getJson('/api/releases/v2026.6.1/review');
      assert.equal(review.status, 200);
      assert.equal(review.body.local.score, null);
      assert.equal(review.body.local.recommended, false);
      assert.ok(review.body.local.staleAudit.causes.includes('refresh_in_progress'));

      const comparison = await getJson('/api/comparison');
      assert.equal(comparison.status, 200);
      const comparisonRelease = comparison.body.releases.find(
        (row: any) => row.tag === 'v2026.6.1',
      );
      assert.equal(comparisonRelease.local.score, null);
      assert.equal(comparisonRelease.local.recommended, false);
      assert.ok(
        comparisonRelease.local.staleAudit.causes.includes('refresh_in_progress'),
      );
    } finally {
      if (leaseHeld) {
        dbModule.releaseRefreshLease('github-refresh', holderId);
      }
      apiModule.setApiLocalRefreshingForTests(null);
      delete process.env.RADAR_TEST_RELEASE_WORKER_DELAY_MS;
      await waitForReleaseWorkerIdle();
      await waitForScoreReadWorkerIdle();
      clearScoreAuditState();
    }
  });

  it('selects refresh blockers and status by state and newest timestamps', () => {
    assert.deepEqual(apiModule.scorePublicationBlockerCauses({
      closureProofFailureCount: 0,
      activeScoreBlockingIngestionFailureCount: 0,
      localRefreshing: true,
      durableRefreshing: false,
    }), ['refresh_in_progress']);
    assert.deepEqual(apiModule.scorePublicationBlockerCauses({
      closureProofFailureCount: 1,
      activeScoreBlockingIngestionFailureCount: 2,
      localRefreshing: false,
      durableRefreshing: true,
    }), [
      'closure_proof_integrity_stale',
      'score_blocking_ingestion_failure',
      'refresh_in_progress',
    ]);

    assert.deepEqual(apiModule.resolveRefreshStatus({
      processLastRefreshAt: '2026-07-04T10:00:00.000Z',
      processLastError: 'older local failure',
      processLastErrorAt: '2026-07-04T09:00:00.000Z',
      durableLastRefreshAt: '2026-07-04T11:00:00.000Z',
      durableErrors: [],
    }), {
      lastRefreshAt: '2026-07-04T11:00:00.000Z',
      lastError: null,
    });
    assert.deepEqual(apiModule.resolveRefreshStatus({
      processLastRefreshAt: '2026-07-04T10:00:00.000Z',
      processLastError: null,
      processLastErrorAt: null,
      durableLastRefreshAt: '2026-07-04T09:00:00.000Z',
      durableErrors: [{
        at: '2026-07-04T12:00:00.000Z',
        message: 'newer durable failure',
      }],
    }), {
      lastRefreshAt: '2026-07-04T10:00:00.000Z',
      lastError: 'newer durable failure',
    });
  });

  it('exposes compact audit links on release summary rows', async () => {
    const releases = await getJson('/api/releases');
    assert.equal(releases.status, 200);
    const release = releases.body.find(
      (row: any) => row.tag === 'v2026.6.1',
    );
    assert.ok(release);
    const binding = new URLSearchParams({
      publicationSnapshot: release.snapshotId,
      auditDigest: release.scoreAudit?.auditDigest ?? 'unavailable',
    }).toString();
    const expected = {
      review: `/api/releases/v2026.6.1/review?${binding}`,
      issues: `/api/releases/v2026.6.1/review/issues?${binding}`,
      closureProofs:
        `/api/releases/v2026.6.1/review/closure-proofs?${binding}`,
      reachability:
        `/api/releases/v2026.6.1/review/reachability?${binding}`,
    };
    assert.deepEqual(release.auditLinks, expected);

    const publicPayload = await getJson('/api/public');
    assert.equal(publicPayload.status, 200);
    assert.deepEqual(publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1')?.auditLinks, expected);
  });

  it('exposes parent review source provenance and raw row links', async () => {
    seedScoreAuditState();
    try {
      const response = await getJson('/api/releases/v2026.6.1/review');

      assert.equal(response.status, 200);
      assert.match(response.body.snapshotId, /^[0-9a-f]{64}$/);
      assert.equal(
        response.headers.get('x-radar-snapshot-id'),
        response.body.snapshotId,
      );
      assert.ok(
        response.body.local.sourceProvenance,
        JSON.stringify(response.body.local.staleAudit ?? response.body.local, null, 2),
      );
      assert.equal(response.body.local.sourceProvenance.sourceMode, 'current_db');
      assert.equal(response.body.local.sourceProvenance.scoreTable, 'release_score_audits');
      assert.equal(response.body.local.sourceProvenance.scoredAt, response.body.local.scoredAt);
      assert.equal(response.body.local.sourceProvenance.dataFreshnessScoredAt, response.body.local.dataFreshness.scoredAt);
      assert.equal(
        response.body.local.sourceProvenance.scoreTimestampAligned,
        response.body.local.scoredAt === response.body.local.dataFreshness.scoredAt,
      );
      assert.deepEqual(response.body.local.sourceProvenance.sources, response.body.local.dataFreshness.sources);
      assert.equal(
        response.body.local.sourceProvenance.advisorySnapshot.schemaVersion,
        1,
      );
      assert.equal(
        response.body.local.sourceProvenance.advisorySnapshot.sourceMode,
        'receipt_authorized_compound_advisory_v2',
      );
      assert.equal(
        typeof response.body.local.sourceProvenance.advisorySnapshot.verified,
        'boolean',
      );
      assert.equal(
        response.body.local.sourceProvenance.advisorySnapshot.failedCount,
        response.body.local.sourceProvenance.advisorySnapshot.problems.length,
      );
      assert.deepEqual(response.body.local.sourceProvenance.rawRows, {
        issues: response.body.auditLinks.issues,
        closureProofs: response.body.auditLinks.closureProofs,
        reachability: response.body.auditLinks.reachability,
      });
    } finally {
      clearScoreAuditState();
    }
  });

  it('preserves raw classifier origin, output, and provenance in review issue evidence', async () => {
    const issueNumber = 110;
    const issueUpdatedAt = '2026-06-02T14:00:00Z';
    const llmModule = await import('./llm.ts');
    const sourceIdentity = dbModule.classifierSourceIdentity(
      ['v2026.6.1'],
      scoringVersions.prompt,
    );
    const issueBody =
      'The core gateway fails during startup for many default installs on v2026.6.1. ' +
      'No workaround exists.';
    const promptInput = llmModule.__llmTest.buildClassifierPromptInput({
      number: issueNumber,
      state: 'open',
      title: 'v2026.6.1 raw classifier provenance route fixture',
      body: issueBody,
      user: { login: 'reporter' },
      created_at: '2026-06-01T14:00:00Z',
      updated_at: issueUpdatedAt,
      closed_at: null,
      html_url: `https://example.test/issues/${issueNumber}`,
      comments: 0,
      labels: [{ name: 'bug' }],
    }, [], ['v2026.6.1']);
    const rawModelOutput = JSON.stringify({
      sentiment: 'negative',
      severity: 'high',
      functionality: 'core',
      scope: 'moderate',
      affected_users: 'many',
      workaroundStatus: 'unknown',
      duplicateCluster: null,
      affectsVersion: 'v2026.6.1',
      evidence: {
        sentiment: [{ source_id: 'issue:body', excerpt: 'fails' }],
        severity: [{ source_id: 'issue:body', excerpt: 'fails during startup' }],
        functionality: [{ source_id: 'issue:body', excerpt: 'core gateway' }],
        scope: [{ source_id: 'issue:body', excerpt: 'default installs' }],
        affected_users: [{ source_id: 'issue:body', excerpt: 'many default installs' }],
        workaroundStatus: [],
        duplicateCluster: [],
        affectsVersion: [{ source_id: 'issue:body', excerpt: 'v2026.6.1' }],
      },
      rationale: 'The cited issue body supports the persisted classification.',
    });
    const classification = llmModule.__llmTest.parseRawClassification(
      rawModelOutput,
      ['v2026.6.1'],
      promptInput.groundingSources,
      promptInput.inputTruncation,
    );
    const provenance = {
      schemaVersion: 2 as const,
      responseId: 'chatcmpl-api-route-provenance',
      requestedModel: sourceIdentity.model,
      responseModel: sourceIdentity.model,
      requestedServiceTier: sourceIdentity.serviceTier,
      responseServiceTier: sourceIdentity.serviceTier,
      reasoningEffort: sourceIdentity.reasoningEffort,
      promptVersion: scoringVersions.prompt,
      promptTemplateHash: sourceIdentity.promptTemplateHash,
      promptHash: 'c'.repeat(64),
      rawModelOutputHash: createHash('sha256').update(rawModelOutput).digest('hex'),
      rawModelOutput,
      groundingSources: promptInput.groundingSources,
      groundingSourcesHash: createHash('sha256')
        .update(canonicalOperationJson(promptInput.groundingSources))
        .digest('hex'),
      inputTruncation: promptInput.inputTruncation,
    };
    dbModule.upsertIssue({
      number: issueNumber,
      state: 'open',
      title: 'v2026.6.1 raw classifier provenance route fixture',
      author: 'reporter',
      author_association: 'NONE',
      html_url: `https://example.test/issues/${issueNumber}`,
      created_at: '2026-06-01T14:00:00Z',
      updated_at: issueUpdatedAt,
      closed_at: null,
      comments: 0,
      unique_human_commenters: 0,
      maintainer_commenters: 0,
      contributor_commenters: 0,
      commenter_scan_truncated: 0,
      reaction_total: 0,
      positive_reactions: 0,
      labels: '["bug"]',
      is_bot: 0,
    });
    const acceptedClassifier = recordAcceptedClassifierLedger({
      issueNumber,
      rawModelOutput,
      sourceIdentity,
      responseId: provenance.responseId,
    });
    dbModule.upsertClassification(
      issueNumber,
      {
        ...classification,
        provenance,
      },
      issueUpdatedAt,
      scoringVersions.prompt,
      'route-provenance-comments-digest',
      sourceIdentity,
      acceptedClassifier,
    );

    try {
      const response = await getJson(
        `/api/releases/v2026.6.1/review/issues?issue=${issueNumber}&limit=250`,
      );
      assert.equal(response.status, 200);
      assert.equal(response.body.rows.length, 1);
      const issue = response.body.rows[0].issue;
      assert.equal(issue.classificationOrigin, 'raw_model');
      assert.equal(issue.rawModelOutput, rawModelOutput);
      assert.deepEqual(issue.classificationProvenance, provenance);
      assert.deepEqual(issue.classifierSourceIdentity, sourceIdentity);
      assert.equal(issue.classifierSourceIdentityDigest, sourceIdentity.digest);
      assert.equal(issue.classificationPromptVersion, scoringVersions.prompt);
      assert.equal(issue.classifiedUpdatedAt, issueUpdatedAt);
      assert.equal(issue.classifiedCommentsDigest, 'route-provenance-comments-digest');
      assert.deepEqual(issue.rawClassification, issue.storedClassification);
    } finally {
      dbModule.db.prepare(`DELETE FROM classifications WHERE issue_number=?`).run(issueNumber);
      dbModule.db.prepare(`DELETE FROM issues WHERE number=?`).run(issueNumber);
    }
  });

  it('does not report durable refresh success without a current score success receipt', async () => {
    clearRefreshMeta();
    try {
      dbModule.setMeta('issue_crawl_last_run', JSON.stringify({
        schemaVersion: 1,
        finishedAt: '2026-06-02T12:34:56Z',
        stopReason: 'exhausted',
        scorePersisted: true,
        scorePersistedAt: '2026-06-02T12:35:00Z',
        evidenceRefreshFailures: [],
        classificationFailures: [],
      }));
      dbModule.setMeta('score_persistence_last_run', JSON.stringify({
        schemaVersion: 2,
        source: 'refresh',
        persistedAt: '2026-06-02T12:35:00Z',
        issueCrawlFinishedAt: '2026-06-02T12:34:56Z',
        issueCrawlStopReason: 'exhausted',
        issueCrawlScorePersistedAt: '2026-06-02T12:35:00Z',
      }));
      const status = await getJson('/api/status');
      assert.equal(status.status, 200);
      assert.equal(status.body.lastRefreshAt, null);
      assert.equal(status.body.processLastRefreshAt, null);
      assert.match(status.body.lastError, /missing its operation run ID/);
    } finally {
      clearRefreshMeta();
    }
  });

  it('exposes persisted validation opportunity status without latest-release synthesis', async () => {
    const response = await getJson('/api/validation/opportunities');
    assert.equal(response.status, 200);
    assert.equal(response.body.schemaVersion, 2);
    assert.equal(response.body.latestRelease, null);
    assert.equal(response.body.currentSeries?.modelVersion, scoringVersions.model);
    assert.equal(response.body.currentSeries?.promptVersion, scoringVersions.prompt);
    assert.equal(response.body.denominatorLedger?.rowCount, 0);
    assert.equal(response.body.opportunities?.length, 0);
    assert.equal(response.body.overallStatus, 'not_enrolled');
    assert.equal(response.body.currentStratum?.status, response.body.overallStatus);
    assert.equal(response.body.currentStratum?.denominatorReady, false);
  });

  it('does not preserve a receiptless score as the last durable success', async () => {
    clearRefreshMeta();
    try {
      dbModule.setMeta('score_persistence_last_run', JSON.stringify({
        schemaVersion: 2,
        source: 'refresh',
        persistedAt: '2026-06-02T10:00:00Z',
        issueCrawlFinishedAt: '2026-06-02T09:59:00Z',
        issueCrawlStopReason: 'exhausted',
        issueCrawlScorePersistedAt: '2026-06-02T10:00:00Z',
      }));
      dbModule.setMeta('issue_crawl_last_run', JSON.stringify({
        schemaVersion: 1,
        finishedAt: '2026-06-02T12:34:56Z',
        stopReason: 'evidence_failure',
        scorePersisted: false,
        scorePersistedAt: null,
        evidenceRefreshFailures: ['[advisories] refresh failed: synthetic failure'],
        classificationFailures: [],
      }));
      const status = await getJson('/api/status');
      assert.equal(status.status, 200);
      assert.equal(status.body.lastRefreshAt, null);
      assert.equal(status.body.processLastRefreshAt, null);
      assert.match(status.body.lastError, /synthetic failure/);
    } finally {
      clearRefreshMeta();
    }
  });

  it('keeps a post-score forecast failure failed after process state is lost', async () => {
    const seeded = seedScoreAuditState();
    const runId = `status-post-score-failure-${Date.now()}`;
    const codeRevision = 'status-post-score-revision';
    const leaseName = `github-refresh-${runId}`;
    const leaseHolderId = `holder-${runId}`;
    try {
      assert.equal(
        dbModule.acquireRefreshLease(
          leaseName,
          leaseHolderId,
          new Date().toISOString(),
          300_000,
        ),
        true,
      );
      dbModule.insertRefreshOperationAttempt({
        run_id: runId,
        operation: 'refresh',
        trigger: 'test',
        started_at: '2026-06-02T12:34:00.000Z',
        lease_name: leaseName,
        lease_holder_id: leaseHolderId,
        lease_expires_at: '2026-06-02T12:39:00.000Z',
        code_revision: codeRevision,
        effective_config: { schemaVersion: 1 },
      });
      dbModule.appendRefreshCaptureReceipt({
        run_id: runId,
        lease_name: leaseName,
        lease_holder_id: leaseHolderId,
        status: 'failure',
        finished_at: '2026-06-02T12:34:56.000Z',
        duration_ms: 56_000,
        payload: {
          schemaVersion: 1,
          operation: 'refresh',
          trigger: 'test',
          codeRevision,
          error: { message: 'forecast publication failed after score commit' },
        },
      });
      assert.equal(dbModule.releaseRefreshLease(leaseName, leaseHolderId), true);
      const meta = JSON.parse(dbModule.getMeta('score_persistence_last_run') ?? 'null');
      dbModule.setMeta('score_persistence_last_run', JSON.stringify({
        ...meta,
        source: 'refresh',
        operationReceiptRequired: true,
        operationRunId: runId,
        codeRevision,
        historyRunId: seeded.historyRunId,
        historyRunContentHash: seeded.historyRunContentHash,
      }));

      const status = await getJson('/api/status');
      assert.equal(status.status, 200);
      assert.equal(status.body.lastRefreshAt, null);
      assert.match(status.body.lastError, /terminal receipt is failure/);
      assert.equal(status.body.currentScoreRunId, runId);
      assert.equal(
        status.body.currentScoreReceiptId,
        dbModule.getRefreshCaptureReceipt(runId)?.receipt_id,
      );
      assert.equal(status.body.currentScoreReceiptStatus, 'failure');
      assert.equal(status.body.currentScoreAuthorizationStatus, 'unauthorized');
      const health = await getJson('/api/health');
      assert.equal(health.status, 503);
      assert.ok(health.body.checks.scoreAudit.publicationProblems.some(
        (problem: string) => /terminal receipt is failure/.test(problem),
      ));
    } finally {
      dbModule.releaseRefreshLease(leaseName, leaseHolderId);
      clearScoreAuditState();
    }
  });

  it('does not treat a finished but unpersisted crawl as a durable refresh', async () => {
    clearRefreshMeta();
    try {
      dbModule.setMeta('issue_crawl_last_run', JSON.stringify({
        schemaVersion: 1,
        finishedAt: '2026-06-02T12:34:56Z',
        stopReason: 'early_stop',
        scorePersisted: false,
        scorePersistedAt: null,
        evidenceRefreshFailures: [],
        classificationFailures: [],
      }));
      const status = await getJson('/api/status');
      assert.equal(status.status, 200);
      assert.equal(status.body.lastRefreshAt, null);
      assert.equal(status.body.processLastRefreshAt, null);
      assert.match(status.body.lastError, /before score persistence/);
    } finally {
      clearRefreshMeta();
    }
  });

  it('keeps a current compatible audit actionable across API surfaces', async () => {
    const seeded = seedScoreAuditState();
    try {
      const releases = await getJson('/api/releases');
      const release = releases.body.find((row: any) => row.tag === 'v2026.6.1');
      assert.equal(release.finalScore, 7.5);
      assert.equal(release.band, 'ok');
      assert.equal(release.recommended, true);
      assert.equal(release.reason, 'test score');
      assert.equal(release.staleAudit, null);
      assert.equal(release.explanation.schemaVersion, scoringVersions.explanation);
      assert.equal(release.scoreAudit.reviewSchemaVersion, 1);
      assert.match(release.scoreAudit.auditDigest, /^[0-9a-f]{64}$/);
      assert.equal(release.scoreAudit.authorityRunId, seeded.authorityRunId);
      assert.equal(
        release.scoreAudit.authorityRunContentHash,
        seeded.authorityRunContentHash,
      );
      assert.equal(
        release.scoreAudit.historyV2SealContentHash,
        seeded.historyV2SealContentHash,
      );

      const publicPayload = await getJson('/api/public');
      assert.equal(publicPayload.body.snapshot.actionable, true);
      const publicRelease = publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1');
      assert.equal(publicRelease.score, 7.5);
      assert.equal(publicRelease.recommended, true);
      assert.equal(publicRelease.reason, 'test score');
      assert.equal(publicRelease.staleAudit, null);
      assert.equal(publicRelease.scoreAudit.authorityRunId, seeded.authorityRunId);
      assert.equal(
        publicRelease.scoreAudit.authorityRunContentHash,
        seeded.authorityRunContentHash,
      );
      assert.equal(
        publicRelease.scoreAudit.historyV2SealContentHash,
        seeded.historyV2SealContentHash,
      );
      assert.equal(publicRelease.profileEvidence.schemaVersion, 2);
      assert.equal(
        publicRelease.profileEvidence.sourceMode,
        'sealed_score_replay',
      );
      assert.match(
        publicRelease.profileEvidence.profileRowsDigest,
        /^[0-9a-f]{64}$/,
      );
      assert.equal(
        publicRelease.profileEvidence.profileRowCount >=
          publicRelease.profileEvidence.surfaceIssueCount,
        true,
      );
      assert.deepEqual(
        {
          auditDigest:
            publicRelease.profileEvidence.publicationBinding.auditDigest,
          authorityRunId:
            publicRelease.profileEvidence.publicationBinding.authorityRunId,
          authorityRunContentHash:
            publicRelease.profileEvidence.publicationBinding
              .authorityRunContentHash,
          historyV2SealContentHash:
            publicRelease.profileEvidence.publicationBinding
              .historyV2SealContentHash,
          profileRowsDigest:
            publicRelease.profileEvidence.publicationBinding
              .profileRowsDigest,
        },
        {
          auditDigest: publicRelease.scoreAudit.auditDigest,
          authorityRunId: seeded.authorityRunId,
          authorityRunContentHash: seeded.authorityRunContentHash,
          historyV2SealContentHash: seeded.historyV2SealContentHash,
          profileRowsDigest:
            publicRelease.profileEvidence.profileRowsDigest,
        },
      );
      assert.match(
        publicRelease.profileEvidence.publicationBinding
          .sourceIdentityDigest,
        /^[0-9a-f]{64}$/,
      );
      assert.match(
        publicRelease.profileEvidence.publicationBinding.contentHash,
        /^[0-9a-f]{64}$/,
      );

      const review = await getJson('/api/releases/v2026.6.1/review');
      assert.equal(review.body.local.score, 7.5);
      assert.equal(review.body.local.recommended, true);
      assert.equal(review.body.local.reason, 'test score');
      assert.equal(review.body.local.staleAudit, null);
      assert.equal(review.body.local.schemaVersion, release.scoreAudit.reviewSchemaVersion);
      assert.equal(review.body.local.auditDigest, release.scoreAudit.auditDigest);
      assert.equal(review.body.local.sourceProvenance.auditDigest, release.scoreAudit.auditDigest);
      assert.deepEqual(review.body.local.sourceProvenance.scoreAuthority, {
        runId: seeded.authorityRunId,
        contentHash: seeded.authorityRunContentHash,
        historyV2SealContentHash: seeded.historyV2SealContentHash,
      });
    } finally {
      clearScoreAuditState();
    }
  });

  it('redacts actionable rows when the current public snapshot is non-actionable', async () => {
    const diagnosticTag = 'v2026.5.30';
    replaceTestActiveCatalog([
      primaryTestCatalogRelease(),
      testCatalogRelease(diagnosticTag, '2026-05-30T00:00:00Z'),
    ]);
    dbModule.replaceReleaseClosureDependencySnapshot(
      dbModule.releaseClosureDependencyIdentity(diagnosticTag, []),
    );
    seedScoreAuditState();
    dbModule.updateReleaseScore({
      tag: diagnosticTag,
      final_score: 6.5,
      negative_issues: 0,
      positive_issues: 0,
      state: 'eligible',
      recommended: 0,
      score_reason: 'diagnostic older score',
      broken_surfaces: '[]',
      closed_serious_fixed: 0,
      opened_serious_during_reign: 0,
      scored_at: '2026-06-02T00:00:00.000Z',
    });

    try {
      const releases = await getJson('/api/releases');
      assert.equal(releases.status, 200);
      const actionableRelease = releases.body.find(
        (row: any) => row.tag === 'v2026.6.1',
      );
      assert.equal(actionableRelease.finalScore, 7.5);
      assert.equal(actionableRelease.recommended, true);
      assert.equal(actionableRelease.staleAudit, null);
      assert.match(actionableRelease.scoreAudit.auditDigest, /^[0-9a-f]{64}$/);
      const diagnosticRelease = releases.body.find(
        (row: any) => row.tag === diagnosticTag,
      );
      assert.ok(diagnosticRelease);
      assert.equal(diagnosticRelease.finalScore, null);
      assert.equal(diagnosticRelease.recommended, false);
      assert.ok(diagnosticRelease.staleAudit.causes.includes('audit_missing'));

      const publicPayload = await getJson('/api/public');
      assert.equal(publicPayload.status, 200);
      const publicRelease = publicPayload.body.releases.find(
        (row: any) => row.tag === 'v2026.6.1',
      );
      assert.equal(publicPayload.body.snapshot.source, 'current');
      assert.equal(publicPayload.body.snapshot.actionable, false);
      assert.equal(publicRelease.score, null);
      assert.equal(publicRelease.recommended, false);
      assert.equal(publicRelease.scoreAudit, null);
      assert.equal(publicRelease.explanation, null);
      assert.equal(publicRelease.scoredAt, null);
      assert.equal(
        publicRelease.profileEvidence.sourceMode,
        'current_diagnostic_evidence',
      );
      assert.equal(publicRelease.profileEvidence.publicationBinding, null);
      assert.ok(publicRelease.staleAudit.causes.includes(
        'public_snapshot_non_actionable',
      ));
      const publicDiagnosticRelease = publicPayload.body.releases.find(
        (row: any) => row.tag === diagnosticTag,
      );
      assert.ok(publicDiagnosticRelease);
      assert.equal(publicDiagnosticRelease.score, null);
      assert.equal(publicDiagnosticRelease.recommended, false);
      assert.equal(
        publicDiagnosticRelease.profileEvidence.publicationBinding,
        null,
      );
    } finally {
      clearScoreAuditState();
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`
        DELETE FROM release_closure_dependency_snapshots
        WHERE release_tag=?
      `).run(diagnosticTag);
      dbModule.db.prepare(`DELETE FROM releases WHERE tag=?`).run(diagnosticTag);
    }
  });

  it('invalidates actionable audits when persisted and running code revisions differ', async () => {
    const persistedRevision = 'api-routes-code-revision-a';
    seedScoreAuditState({
      sourceIdentityOptions: { codeRevision: persistedRevision },
    });
    try {
      await assertScoreSurfacesFailClosed(
        'code revision drift',
        'evidence_source_changed',
      );
    } finally {
      clearScoreAuditState();
    }
  });

  it('invalidates actionable audits when effective scoring configuration changes', async () => {
    const originalLimit = configModule.config.limits.releases;
    const originalEnvLimit = process.env.RELEASES_LIMIT;
    seedScoreAuditState();
    try {
      const before = await getJson('/api/releases');
      assert.equal(
        before.body.find((row: any) => row.tag === 'v2026.6.1')?.recommended,
        true,
      );
      const changedLimit = originalLimit + 1;
      (configModule.config.limits as { releases: number }).releases = changedLimit;
      process.env.RELEASES_LIMIT = String(changedLimit);
      await assertScoreSurfacesFailClosed(
        'effective scoring configuration drift',
        'evidence_source_changed',
      );
    } finally {
      (configModule.config.limits as { releases: number }).releases = originalLimit;
      if (originalEnvLimit == null) delete process.env.RELEASES_LIMIT;
      else process.env.RELEASES_LIMIT = originalEnvLimit;
      clearScoreAuditState();
    }
  });

  it('reports semantic readiness only for a current auditable score run', async () => {
    const seeded = seedScoreAuditState();
    try {
      const response = await getJson('/api/health');
      assert.equal(response.status, 200);
      assert.equal(response.body.ok, true);
      assert.equal(response.body.status, 'ready');
      assert.equal(response.body.currentRelease.tag, 'v2026.6.1');
      assert.deepEqual(response.body.failures, []);
      assert.ok(Object.values(response.body.checks).every((check: any) => check.ok === true));
      assert.match(response.body.checks.scoreAudit.auditDigest, /^[0-9a-f]{64}$/);
      assert.equal(
        response.body.checks.scoreAudit.authorityRunId,
        seeded.authorityRunId,
      );
      assert.equal(
        response.body.checks.scoreAudit.authorityRunContentHash,
        seeded.authorityRunContentHash,
      );
      assert.equal(
        response.body.checks.scoreAudit.historyV2SealContentHash,
        seeded.historyV2SealContentHash,
      );
      assert.deepEqual(
        response.body.checks.scoreAudit.releases.map((release: any) => ({
          tag: release.tag,
          authorityRunId: release.authorityRunId,
          authorityRunContentHash: release.authorityRunContentHash,
          historyV2SealContentHash: release.historyV2SealContentHash,
        })),
        [{
          tag: 'v2026.6.1',
          authorityRunId: seeded.authorityRunId,
          authorityRunContentHash: seeded.authorityRunContentHash,
          historyV2SealContentHash: seeded.historyV2SealContentHash,
        }],
      );
      assert.equal(
        response.body.checks.sourceIdentity.persistedDigest,
        response.body.checks.sourceIdentity.currentDigest,
      );
      assert.equal(response.body.checks.closureProof.missingCount, 0);
      assert.equal(response.body.checks.closureProof.staleCount, 0);
      assert.equal(response.body.checks.ingestion.activeScoreBlockingFailureCount, 0);
    } finally {
      clearScoreAuditState();
    }
  });

  it('fails readiness when the selected older candidate has stale closure proof', async () => {
    const olderTag = 'v2026.6.0';
    const olderScore = 8.1;
    replaceTestActiveCatalog([
      primaryTestCatalogRelease(),
      testCatalogRelease(olderTag, '2026-05-31T00:00:00Z'),
    ]);
    const configureCurrentDecision = (decision: Record<string, unknown>) => {
      Object.assign(decision, {
        selectedTag: olderTag,
        selectedScore: olderScore,
        highestScoringTag: olderTag,
        highestScore: olderScore,
        scoreRank: 2,
        scoreDeltaToHighest: 0.6,
        decisionCode: 'higher_confidence_release_selected',
      });
      decision.summary = recommendationDecisionSummary(
        decision as unknown as RecommendationDecisionContract,
      );
    };
    const seeded = seedScoreAuditState({
      recommended: false,
      rebindExplanationAuditAfterDecisionMutation: true,
      mutateDecision: (components, explanation) => {
        configureCurrentDecision(components);
        configureCurrentDecision(explanation);
      },
    });
    const scoredAt = dbModule.getReleaseScoreAudit('v2026.6.1')!.scored_at;
    const olderBand = bandFor(olderScore, 'eligible');
    const olderInput = structuredClone(seeded.input);
    Object.assign(olderInput, {
      publishedAt: '2026-05-31T00:00:00Z',
      isLatest: false,
      hoursToNextStable: 24,
      betaCount: 4,
      rawIssueCount: 0,
      classifiedIssueCount: 0,
    });
    const olderConfidence = installConfidence(olderInput, Date.parse(scoredAt));
    assert.deepEqual(
      {
        score: olderConfidence.score,
        status: olderConfidence.status,
        band: olderConfidence.band,
      },
      {
        score: olderScore,
        status: 'eligible',
        band: olderBand,
      },
    );
    const olderScoreLedger = buildScoreLedgerV2({
      input: olderInput,
      confidence: olderConfidence,
      now: Date.parse(scoredAt),
    });
    const olderComponents = structuredClone(seeded.components);
    olderComponents.components = olderConfidence.components;
    olderComponents.evidenceCoverage = olderConfidence.evidenceCoverage;
    olderComponents.hotfix = olderConfidence.hotfix;
    olderComponents.reason = olderConfidence.reason;
    const configureOlderDecision = (decision: Record<string, unknown>) => {
      Object.assign(decision, {
        selectedTag: olderTag,
        selectedScore: olderScore,
        highestScoringTag: olderTag,
        highestScore: olderScore,
        releaseTag: olderTag,
        releaseScore: olderScore,
        qualifies: true,
        selected: true,
        recencyRank: 2,
        scoreRank: 1,
        scoreDeltaToHighest: 0,
        decisionCode: 'highest_confidence',
      });
      decision.summary = recommendationDecisionSummary(
        decision as unknown as RecommendationDecisionContract,
      );
    };
    configureOlderDecision(olderComponents.recommendationDecision);
    configureOlderDecision(olderComponents.explanation.recommendationDecision);
    olderComponents.explanation.verdict =
      olderComponents.explanation.recommendationDecision.summary;
    olderComponents.explanation.scoreLedger = structuredClone(
      bindScoreExplanationAudit(
        olderScoreLedger,
        olderComponents.explanation,
      ),
    );
    const olderGateEvidence = structuredClone(seeded.gateEvidence);
    olderGateEvidence.stableTagsNewestFirst = ['v2026.6.1', olderTag, 'v2026.5.31'];
    olderGateEvidence.betaCount = olderInput.betaCount;
    const emptyRiskSummary = closureRiskSummary();
    for (const key of Object.keys(emptyRiskSummary)) {
      if (key !== 'weightedRiskByDisposition') {
        (emptyRiskSummary as Record<string, unknown>)[key] = 0;
      }
    }
    olderGateEvidence.fixProvenance = {
      verifiedFixedCount: 0,
      creditedFixedCount: 0,
      unverifiedClosedCount: 0,
      predecessorBoundary: {
        schemaVersion: 1,
        oldestScoredStableTag: olderTag,
        oldestScoredStablePredecessorTag: 'v2026.5.31',
        targetTag: olderTag,
        predecessorTag: 'v2026.5.31',
      },
      closureProof: {
        schemaVersion: 1,
        creditedCount: 0,
        notCreditedCount: 0,
        analyzedClosedCount: 0,
        containedFixedCount: 0,
        containedNotCreditedCount: 0,
        targetTag: olderTag,
        predecessorTag: 'v2026.5.31',
        fixCreditDecisionCounts: { credited: 0, withheld: 0, invalid: 0 },
        fixCreditDecisions: [],
        byStatus: {},
        byRiskDisposition: {},
        riskSummary: emptyRiskSummary,
        neutralAuditExamples: [],
        examplesByStatus: {},
        examples: [],
      },
      releaseFixCredit: {
        schemaVersion: 1,
        targetTag: olderTag,
        predecessorTag: 'v2026.5.31',
        countedClosedCount: 0,
        notCountedClosedCount: 0,
        analyzedClosedCount: 0,
        containedFixedCount: 0,
        containedNotCreditedCount: 0,
        decisionCounts: { credited: 0, withheld: 0, invalid: 0 },
        decisions: [],
      },
    };
    const currentAudit = dbModule.getReleaseScoreAudit('v2026.6.1')!;
    dbModule.updateReleaseScore({
      tag: olderTag,
      final_score: olderScore,
      negative_issues: 0,
      positive_issues: 0,
      state: 'eligible',
      recommended: 1,
      score_reason: olderConfidence.reason,
      broken_surfaces: '[]',
      closed_serious_fixed: 0,
      opened_serious_during_reign: 0,
      scored_at: scoredAt,
    });
    dbModule.upsertReleaseScoreAudit({
      release_tag: olderTag,
      scored_at: scoredAt,
      score_model_version: scoringVersions.model,
      prompt_version: scoringVersions.prompt,
      final_score: olderScore,
      status: 'eligible',
      band: olderBand,
      recommended: 1,
      input_json: JSON.stringify(olderInput),
      components_json: JSON.stringify(olderComponents),
      issue_evidence_json: JSON.stringify(seeded.issueEvidence),
      gate_evidence_json: JSON.stringify(olderGateEvidence),
      source_identity_json: currentAudit.source_identity_json,
    });
    sealCurrentAuditRun(['v2026.6.1', olderTag], olderTag, scoredAt);

    try {
      const response = await getJson('/api/health');
      assert.equal(response.status, 503);
      assert.equal(response.body.currentRelease.tag, 'v2026.6.1');
      assert.equal(response.body.checks.recommendation.ok, true);
      assert.equal(response.body.checks.scoreAudit.ok, false);
      assert.deepEqual(response.body.checks.closureProof.staleReleaseTags, [olderTag]);
      const olderClosure = response.body.checks.closureProof.releases.find(
        (release: any) => release.tag === olderTag,
      );
      assert.equal(olderClosure.diagnosticPreviouslyRecommended, true);
      assert.equal('recommended' in olderClosure, false);
      assert.equal(olderClosure.ok, false);
      assert.equal(olderClosure.dependencySnapshotMissingCount, 1);
      assert.deepEqual(forbiddenHealthActionFields(response.body), []);
      assert.ok(response.body.failures.some((failure: any) =>
        failure.code === 'closure_proof_integrity_stale'));
    } finally {
      clearScoreAuditState();
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`DELETE FROM releases WHERE tag=?`).run(olderTag);
    }
  });

  it('fails readiness for stale model, prompt, and source-identity contracts', async () => {
    const cases: Array<{
      label: string;
      overrides: ScoreAuditSeedOverrides;
      cause: string;
      sourceIdentityOk: boolean;
      mutateCurrentSource?: boolean;
    }> = [
      {
        label: 'model',
        overrides: { model: 'retired-score-model' },
        cause: 'score_model_changed',
        sourceIdentityOk: true,
      },
      {
        label: 'prompt',
        overrides: { prompt: scoringVersions.prompt - 1 },
        cause: 'prompt_changed',
        sourceIdentityOk: true,
      },
      {
        label: 'source identity',
        overrides: {},
        cause: 'evidence_source_changed',
        sourceIdentityOk: false,
        mutateCurrentSource: true,
      },
    ];

    for (const testCase of cases) {
      const seeded = seedScoreAuditState(testCase.overrides);
      if (testCase.mutateCurrentSource) {
        dbModule.db.prepare(`
          UPDATE issues
          SET title='v2026.6.1 release local broad regression changed after scoring'
          WHERE number=101
        `).run();
      }
      try {
        const response = await getJson('/api/health');
        assert.equal(response.status, 503, testCase.label);
        assert.equal(response.body.ok, false, testCase.label);
        assert.equal(response.body.checks.scoreAudit.ok, false, testCase.label);
        assert.equal(
          response.body.checks.sourceIdentity.ok,
          testCase.sourceIdentityOk,
          testCase.label,
        );
        assert.ok(
          response.body.checks.scoreAudit.causes.includes(testCase.cause),
          testCase.label,
        );
        assert.ok(response.body.failures.some((failure: any) =>
          failure.code === 'score_audit_incompatible'), testCase.label);
      } finally {
        if (testCase.mutateCurrentSource) {
          dbModule.db.prepare(`
            UPDATE issues
            SET title='v2026.6.1 release local broad regression still open'
            WHERE number=101
          `).run();
        }
        clearScoreAuditState();
        if (seeded.historyRunId) removeReceiptHistoryRunFixture(seeded.historyRunId);
      }
    }
  });

  it('fails readiness for an invalid recommendation run', async () => {
    const seeded = seedScoreAuditState({
      expectAuditContractFailure: true,
      mutateDecision: (components, explanation) => {
        components.selectedTag = 'v2026.6.999';
        explanation.selectedTag = 'v2026.6.999';
      },
    });
    try {
      const response = await getJson('/api/health');
      assert.equal(response.status, 503);
      assert.equal(response.body.ok, false);
      assert.equal(response.body.checks.recommendation.ok, false);
      assert.ok(response.body.failures.some((failure: any) =>
        failure.code === 'recommendation_run_invalid'));
    } finally {
      clearScoreAuditState();
      if (seeded.historyRunId) removeReceiptHistoryRunFixture(seeded.historyRunId);
    }
  });

  it('fails readiness for stale closure-proof integrity even when the audit matches the DB', async () => {
    const original = dbModule.db.prepare(`
      SELECT evidence_json
      FROM issue_closure_proofs
      WHERE release_tag='v2026.6.1' AND issue_number=103
    `).get() as { evidence_json: string };
    const staleEvidence = JSON.parse(original.evidence_json);
    staleEvidence.proofAnalyzerVersion = CLOSURE_PROOF_ANALYZER_VERSION - 1;
    dbModule.db.prepare(`
      UPDATE issue_closure_proofs
      SET evidence_json=?
      WHERE release_tag='v2026.6.1' AND issue_number=103
    `).run(JSON.stringify(staleEvidence));
    seedScoreAuditState();
    try {
      const response = await getJson('/api/health');
      assert.equal(response.status, 503);
      assert.equal(response.body.checks.scoreAudit.ok, false);
      assert.equal(response.body.checks.sourceIdentity.ok, true);
      assert.equal(response.body.checks.closureProof.ok, false);
      assert.ok(response.body.checks.closureProof.analyzerVersionMismatchCount > 0);
      assert.ok(response.body.failures.some((failure: any) =>
        failure.code === 'closure_proof_integrity_stale'));
      await assertScoreSurfacesFailClosed(
        'closure-proof integrity failure',
        'closure_proof_integrity_stale',
      );
    } finally {
      clearScoreAuditState();
      dbModule.db.prepare(`
        UPDATE issue_closure_proofs
        SET evidence_json=?
        WHERE release_tag='v2026.6.1' AND issue_number=103
      `).run(original.evidence_json);
    }
  });

  it('fails current publication for score-affecting negative missing_evidence proof rows', async () => {
    const original = dbModule.db.prepare(`
      SELECT status, summary, evidence_json
      FROM issue_closure_proofs
      WHERE release_tag='v2026.6.1' AND issue_number=103
    `).get() as { status: string; summary: string; evidence_json: string };
    seedClosureProof(103, 'missing_evidence', { status: 'missing_evidence' });
    refreshClosureDependencySnapshot();
    seedScoreAuditState();
    try {
      const health = await getJson('/api/health');
      assert.equal(health.status, 503);
      assert.equal(health.body.checks.scoreAudit.ok, false);
      assert.ok(health.body.checks.scoreAudit.publicationProblems.some(
        (problem: string) => /score-affecting negative missing_evidence/.test(problem),
      ));
      assert.ok(health.body.failures.some((failure: any) =>
        failure.code === 'score_audit_incompatible'));
      await assertScoreSurfacesFailClosed('score-affecting missing evidence');
    } finally {
      clearScoreAuditState();
      dbModule.db.prepare(`
        UPDATE issue_closure_proofs
        SET status=?, summary=?, evidence_json=?
        WHERE release_tag='v2026.6.1' AND issue_number=103
      `).run(original.status, original.summary, original.evidence_json);
      refreshClosureDependencySnapshot();
    }
  });

  it('fails readiness while an active score-blocking ingestion failure exists', async () => {
    seedScoreAuditState();
    const runId = `api-health-ingestion-${Date.now()}`;
    dbModule.insertIngestionEvidenceFailure({
      run_id: runId,
      source: 'advisories',
      scope: 'global',
      message: 'synthetic readiness blocker',
      scoring_blocking: true,
    });
    try {
      const response = await getJson('/api/health');
      assert.equal(response.status, 503);
      assert.equal(response.body.checks.ingestion.ok, false);
      assert.equal(response.body.checks.ingestion.activeScoreBlockingFailureCount, 1);
      assert.equal(response.body.checks.ingestion.failures[0].runId, runId);
      assert.ok(response.body.failures.some((failure: any) =>
        failure.code === 'score_blocking_ingestion_failure'));
      await assertScoreSurfacesFailClosed(
        'active score-blocking ingestion failure',
        'score_blocking_ingestion_failure',
      );
    } finally {
      dbModule.db.prepare(`DELETE FROM ingestion_evidence_failures WHERE run_id=?`).run(runId);
      clearScoreAuditState();
    }
  });

  it('treats mutable current audits without sealed history as stale and non-actionable', async () => {
    seedScoreAuditState({ sealHistory: false });
    try {
      await assertScoreSurfacesFailClosed('mutable current without sealed history');
      const review = await getJson('/api/releases/v2026.6.1/review');
      assert.equal(review.body.local.auditDigest, null);
      assert.equal(review.body.local.sourceProvenance, null);
      const health = await getJson('/api/health');
      assert.equal(health.status, 503);
      assert.equal(health.body.checks.scoreAudit.ok, false);
      assert.ok(health.body.checks.scoreAudit.causes.includes('audit_publication_invalid'));
    } finally {
      clearScoreAuditState();
    }
  });

  it('fails closed for wrong persistence runs, tips, and seal hashes', async () => {
    const first = seedScoreAuditState();
    try {
      const originalMeta = JSON.parse(
        dbModule.getMeta('score_persistence_last_run') ?? 'null',
      );
      const cases = [
        {
          label: 'wrong run',
          meta: { ...originalMeta, historyRunId: 'missing-run' },
        },
        {
          label: 'wrong hash',
          meta: { ...originalMeta, historyRunContentHash: '0'.repeat(64) },
        },
      ];
      for (const testCase of cases) {
        dbModule.setMeta('score_persistence_last_run', JSON.stringify(testCase.meta));
        await assertScoreSurfacesFailClosed(testCase.label);
      }

      dbModule.setMeta('score_persistence_last_run', JSON.stringify(originalMeta));
      const second = seedScoreAuditState();
      dbModule.setMeta('score_persistence_last_run', JSON.stringify({
        ...originalMeta,
        historyRunId: first.historyRunId,
        historyRunContentHash: first.historyRunContentHash,
      }));
      await assertScoreSurfacesFailClosed('recorded run is not the sealed tip');
      assert.notEqual(second.historyRunId, first.historyRunId);
    } finally {
      clearScoreAuditState();
    }
  });

  it('fails closed when the sealed history source manifest is semantically invalid', async () => {
    const seeded = seedScoreAuditState({
      mutateHistorySourceIdentity: (identity: any) => {
        identity.sources[1] = structuredClone(identity.sources[0]);
      },
    });
    try {
      await assertScoreSurfacesFailClosed('invalid sealed history manifest');
      const review = await getJson('/api/releases/v2026.6.1/review');
      assert.equal(review.body.local.auditDigest, null);
    } finally {
      clearScoreAuditState();
      if (seeded.historyRunId) removeReceiptHistoryRunFixture(seeded.historyRunId);
    }
  });

  it('binds auditDigest to the sealed run identity', async () => {
    seedScoreAuditState();
    try {
      const first = await getJson('/api/releases/v2026.6.1/review');
      const firstDigest = first.body.local.auditDigest;
      assert.match(firstDigest, /^[0-9a-f]{64}$/);
      clearScoreAuditState();
      seedScoreAuditState();
      const second = await getJson('/api/releases/v2026.6.1/review');
      assert.match(second.body.local.auditDigest, /^[0-9a-f]{64}$/);
      assert.notEqual(second.body.local.auditDigest, firstDigest);
    } finally {
      clearScoreAuditState();
    }
  });

  it('invalidates cached public payloads after score-source rows change', async () => {
    seedScoreAuditState();
    try {
      const before = await getJson('/api/public');
      assert.equal(before.status, 200);
      assert.match(JSON.stringify(before.body), /release local broad regression still open/);

      dbModule.db.prepare(`
        UPDATE issues
        SET title='v2026.6.1 release local broad regression changed externally'
        WHERE number=101
      `).run();
      const after = await getJson('/api/public');
      assert.equal(after.status, 200);
      assert.match(JSON.stringify(after.body), /release local broad regression changed externally/);
      assert.doesNotMatch(JSON.stringify(after.body), /release local broad regression still open/);
    } finally {
      dbModule.db.prepare(`
        UPDATE issues
        SET title='v2026.6.1 release local broad regression still open'
        WHERE number=101
      `).run();
      clearScoreAuditState();
    }
  });

  it('fails closed for stale or incompatible persisted score audits', async () => {
    const cases = [
      ['score model', { model: 'retired-score-model' }],
      ['prompt', { prompt: scoringVersions.prompt - 1 }],
      ['explanation schema', { explanationSchema: scoringVersions.explanation - 1 }],
      ['schema-only audit payloads', { schemaOnlyPayloads: true }],
      ['missing nested fix-credit field', {
        mutateAuditPayloads: (payloads: ScoreAuditPayloads) => {
          delete payloads.gateEvidence.fixProvenance.releaseFixCredit.decisionCounts.invalid;
        },
      }],
      ['missing recency rank', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          delete components.recencyRank;
          delete explanation.recencyRank;
        },
      }],
      ['missing score rank', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          delete components.scoreRank;
          delete explanation.scoreRank;
        },
      }],
      ['threshold drift', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          components.threshold = REC_THRESHOLD - 1;
          explanation.threshold = REC_THRESHOLD - 1;
        },
      }],
      ['release score drift', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          components.releaseScore = 7.4;
          explanation.releaseScore = 7.4;
        },
      }],
      ['selected tag drift', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          components.selectedTag = 'v2026.6.0';
          explanation.selectedTag = 'v2026.6.0';
        },
      }],
      ['highest tag drift', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          components.highestScoringTag = null;
          explanation.highestScoringTag = null;
        },
      }],
      ['decision code drift', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          components.decisionCode = 'install_gate_active';
          explanation.decisionCode = 'install_gate_active';
        },
      }],
      ['summary drift', {
        mutateDecision: (components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          components.summary = 'drifted summary';
          explanation.summary = 'drifted summary';
        },
      }],
      ['decision copy divergence', {
        mutateDecision: (_components: Record<string, unknown>, explanation: Record<string, unknown>) => {
          explanation.selectedScore = 7.4;
        },
      }],
    ] as const;
    const contractFailureCases = new Set([
      'explanation schema',
      'schema-only audit payloads',
      'missing nested fix-credit field',
      'missing recency rank',
      'missing score rank',
      'threshold drift',
      'release score drift',
      'selected tag drift',
      'highest tag drift',
      'decision code drift',
      'summary drift',
      'decision copy divergence',
    ]);

    for (const [label, overrides] of cases) {
      const seeded = seedScoreAuditState({
        ...overrides,
        expectAuditContractFailure: contractFailureCases.has(label),
      });
      try {
        await assertScoreSurfacesFailClosed(label);
      } finally {
        clearScoreAuditState();
        if (seeded.historyRunId) removeReceiptHistoryRunFixture(seeded.historyRunId);
      }
    }

    const sourceManifestCases = [
      ['duplicate source manifest', (identity: any) => {
        identity.sources[1] = structuredClone(identity.sources[0]);
        identity.rowCount = identity.sources.reduce(
          (sum: number, source: any) => sum + source.count,
          0,
        );
        identity.digest = scoreSourceIdentityManifestDigest(identity.sources);
      }],
      ['reordered source manifest', (identity: any) => {
        [identity.sources[0], identity.sources[1]] = [
          identity.sources[1],
          identity.sources[0],
        ];
        identity.digest = scoreSourceIdentityManifestDigest(identity.sources);
      }],
    ] as const;
    for (const [label, mutate] of sourceManifestCases) {
      const seeded = seedScoreAuditState();
      const audit = dbModule.db.prepare(`
        SELECT source_identity_json
        FROM release_score_audits
        WHERE release_tag='v2026.6.1'
      `).get() as { source_identity_json: string };
      const identity = JSON.parse(audit.source_identity_json);
      mutate(identity);
      dbModule.db.prepare(`
        UPDATE release_score_audits
        SET source_identity_json=?
        WHERE release_tag='v2026.6.1'
      `).run(JSON.stringify(identity));
      try {
        await assertScoreSurfacesFailClosed(label);
      } finally {
        clearScoreAuditState();
        if (seeded.historyRunId) removeReceiptHistoryRunFixture(seeded.historyRunId);
      }
    }

    const seeded = seedScoreAuditState();
    dbModule.db.prepare(`
      UPDATE issues
      SET title='v2026.6.1 release local broad regression changed after scoring'
      WHERE number=101
    `).run();
    try {
      await assertScoreSurfacesFailClosed('source identity');
    } finally {
      dbModule.db.prepare(`
        UPDATE issues
        SET title='v2026.6.1 release local broad regression still open'
        WHERE number=101
      `).run();
      clearScoreAuditState();
      if (seeded.historyRunId) removeReceiptHistoryRunFixture(seeded.historyRunId);
    }
  });

  it('preserves persisted closure proof and fix-credit decisions byte-for-byte in review and comparison', async () => {
    const seeded = seedScoreAuditState();
    try {
      const review = await getJson('/api/releases/v2026.6.1/review');
      const comparison = await getJson('/api/comparison');
      const comparisonRelease = comparison.body.releases.find(
        (row: any) => row.tag === 'v2026.6.1',
      );
      const reviewFix = review.body.local.gateEvidence.fixProvenance;
      const comparisonFix = comparisonRelease.local.gateEvidence.fixProvenance;

      assert.equal(
        JSON.stringify(reviewFix.closureProof),
        JSON.stringify(seeded.gateEvidence.fixProvenance.closureProof),
      );
      assert.equal(
        JSON.stringify(reviewFix.releaseFixCredit),
        JSON.stringify(seeded.gateEvidence.fixProvenance.releaseFixCredit),
      );
      assert.equal(
        JSON.stringify(comparisonFix.closureProof),
        JSON.stringify(seeded.gateEvidence.fixProvenance.closureProof),
      );
      assert.equal(
        JSON.stringify(comparisonFix.releaseFixCredit),
        JSON.stringify(seeded.gateEvidence.fixProvenance.releaseFixCredit),
      );
      assert.equal(
        JSON.stringify(reviewFix.releaseFixCredit.decisions[0]),
        JSON.stringify(seeded.persistedFixCreditDecision),
      );
      assert.equal(
        JSON.stringify(comparisonFix.releaseFixCredit.decisions[0]),
        JSON.stringify(seeded.persistedFixCreditDecision),
      );
    } finally {
      clearScoreAuditState();
    }
  });

  it('reports previous gate states without exposing stale score audit evidence', async () => {
    const cases = [
      ['skip-cve', 4.7],
      ['skip-hotfix', 4.9],
      ['wait', null],
    ] as const;

    for (const [status, score] of cases) {
      const seeded = seedScoreAuditState({
        model: 'retired-score-model',
        status,
        score,
        recommended: false,
      });
      try {
        const releases = await getJson('/api/releases');
        const release = releases.body.find((row: any) => row.tag === 'v2026.6.1');
        assert.equal(release.status, 'stale');
        assert.equal(release.diagnosticStatus, status);
        assert.equal(release.finalScore, null);
        assert.equal(release.recommended, false);
        assert.match(release.reason, new RegExp(`Previous audited status: ${status}`));
        assert.equal(release.scoreAudit, null);
        assert.equal(release.staleAudit.previousStatus, status);

        const review = await getJson('/api/releases/v2026.6.1/review');
        assert.equal(review.body.local.status, 'stale');
        assert.equal(review.body.local.diagnosticStatus, status);
        assert.equal(review.body.local.score, null);
        assert.equal(review.body.local.staleAudit.previousStatus, status);
        assert.equal(review.body.local.input, null);
        assert.equal(review.body.local.components, null);
        assert.equal(review.body.local.issueEvidence, null);
        assert.equal(review.body.local.gateEvidence, null);
      } finally {
        clearScoreAuditState();
        if (seeded.historyRunId) removeReceiptHistoryRunFixture(seeded.historyRunId);
      }
    }
  });

  it('marks advice stale when advisory source rows change after scoring while preserving diagnostics', async () => {
    seedScoreAuditState();
    const advisoryKey = 'GHSA-post-score:npm:openclaw:<2026.6.2';
    try {
      dbModule.upsertAdvisory({
        advisory_key: advisoryKey,
        ghsa_id: 'GHSA-post-score',
        cve_id: 'CVE-2026-4242',
        summary: 'Advisory discovered after the score was written',
        severity: 'high',
        html_url: 'https://github.com/advisories/GHSA-post-score',
        published_at: '2026-07-04T00:00:00Z',
        package_ecosystem: 'npm',
        package_name: 'openclaw',
        vulnerable_version_range: '< 2026.6.2',
        patched_versions: null,
      });

      const releases = await getJson('/api/releases');
      const release = releases.body.find((row: any) => row.tag === 'v2026.6.1');
      assert.equal(release.status, 'stale');
      assert.equal(release.diagnosticStatus, 'eligible');
      assert.equal(release.finalScore, null);
      assert.equal(release.recommended, false);
      assert.equal(release.advisories.affected.total, 1);
      assert.equal(release.advisories.affected.items[0].ghsaId, 'GHSA-post-score');
      assert.equal(release.advisories.affected.items[0].patchedVersion, null);

      const publicPayload = await getJson('/api/public');
      const publicRelease = publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1');
      assert.equal(publicRelease.status, 'stale');
      assert.equal(publicRelease.diagnosticStatus, 'eligible');
      assert.equal(publicRelease.score, null);
    } finally {
      dbModule.db.prepare(`DELETE FROM advisories WHERE advisory_key=?`).run(advisoryKey);
      clearScoreAuditState();
    }
  });

  it('returns every matching advisory even when the release is several stables behind the patch', async () => {
    const tags = ['v1.3.0', 'v1.2.0', 'v1.1.0', 'v1.0.0'];
    replaceTestActiveCatalog([
      primaryTestCatalogRelease(),
      ...tags.map((tag, index) => testCatalogRelease(
        tag,
        `2026-05-${String(20 - index).padStart(2, '0')}T00:00:00Z`,
      )),
    ]);
    dbModule.upsertAdvisory({
      advisory_key: 'GHSA-age-window|npm|openclaw|<1.3.0|1.3.0',
      ghsa_id: 'GHSA-age-window',
      cve_id: 'CVE-2026-9999',
      summary: 'Older affected releases must remain visible',
      severity: 'high',
      html_url: 'https://github.com/advisories/GHSA-age-window',
      published_at: '2026-05-21T00:00:00Z',
      package_ecosystem: 'npm',
      package_name: 'openclaw',
      vulnerable_version_range: '<1.3.0',
      patched_versions: '1.3.0',
    });
    try {
      const releases = await getJson('/api/releases');
      const oldest = releases.body.find((row: any) => row.tag === 'v1.0.0');
      assert.equal(oldest.advisories.affected.total, 1);
      assert.equal(oldest.advisories.affected.items[0].ghsaId, 'GHSA-age-window');
      assert.equal(oldest.advisories.affected.items[0].cveId, 'CVE-2026-9999');
    } finally {
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`DELETE FROM advisories WHERE advisory_key=?`).run(
        'GHSA-age-window|npm|openclaw|<1.3.0|1.3.0',
      );
      dbModule.db.prepare(`DELETE FROM releases WHERE tag IN (?, ?, ?, ?)`).run(...tags);
    }
  });

  it('deduplicates overlapping advisory ranges in presentation totals while retaining range detail', async () => {
    const tag = 'v1.5.0';
    const keys = [
      'GHSA-overlap:npm:openclaw:<2.0.0',
      'GHSA-overlap:npm:openclaw:>=1.0.0<2.0.0',
    ];
    replaceTestActiveCatalog([
      primaryTestCatalogRelease(),
      testCatalogRelease(tag, '2026-05-20T00:00:00Z'),
    ]);
    for (const [index, range] of ['< 2.0.0', '>= 1.0.0, < 2.0.0'].entries()) {
      dbModule.upsertAdvisory({
        advisory_key: keys[index],
        ghsa_id: 'GHSA-overlap',
        cve_id: 'CVE-2026-5252',
        summary: 'Overlapping vulnerable ranges',
        severity: 'high',
        html_url: 'https://github.com/advisories/GHSA-overlap',
        published_at: '2026-05-21T00:00:00Z',
        package_ecosystem: 'npm',
        package_name: 'openclaw',
        vulnerable_version_range: range,
        patched_versions: '2.0.0',
      });
    }
    try {
      const releases = await getJson('/api/releases');
      const release = releases.body.find((row: any) => row.tag === tag);
      assert.equal(release.advisories.affected.total, 1);
      assert.equal(release.advisories.affected.rangeTotal, 2);
      assert.equal(release.advisories.affected.bySeverity.high, 1);
      assert.equal(release.advisories.affected.items[0].rangeCount, 2);
      assert.equal(release.advisories.affected.items[0].matchingRanges.length, 2);
    } finally {
      restorePrimaryTestCatalog();
      dbModule.db.prepare(`DELETE FROM advisories WHERE advisory_key IN (?, ?)`).run(...keys);
      dbModule.db.prepare(`DELETE FROM releases WHERE tag=?`).run(tag);
    }
  });

  it('does not restore fallback profile weight for a deduplicated same-cluster opened report', async () => {
    for (const number of [106, 107]) {
      seedIssue({
        number,
        state: 'open',
        title: `Discord crash from duplicate cluster report ${number}`,
        createdAt: `2026-06-02T${number === 106 ? '10' : '11'}:00:00Z`,
        updatedAt: `2026-06-03T${number === 106 ? '10' : '11'}:00:00Z`,
        labels: ['bug', 'regression'],
        classification: {
          sentiment: 'negative',
          severity: 'high',
          functionality: 'core',
          scope: 'broad',
          affectedUsers: 'many',
          duplicateCluster: 'discord-crash-cluster',
        },
      });
    }
    seedClosureProof(106, 'unknown', {
      canonicalIssues: [107],
    });
    refreshClosureDependencySnapshot();
    try {
      const evidence = await getJson('/api/releases/v2026.6.1/review/issues?limit=250');
      const clusterRows = evidence.body.rows.filter(
        (row: any) => row.duplicateCluster === 'discord-crash-cluster',
      );
      assert.equal(clusterRows.length, 1);
      assert.ok(clusterRows[0].weight > 0);
      assert.notEqual(clusterRows[0].tier, 'openedFeltSerious');
      const opened = await getJson('/api/releases/v2026.6.1/review/issues?tier=openedFeltSerious&limit=250');
      assert.equal(
        opened.body.rows.filter((row: any) => row.duplicateCluster === 'discord-crash-cluster').length,
        0,
      );

      const publicPayload = await getJson('/api/public');
      const release = publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1');
      assert.equal(release.profileEvidence.issueEvidenceSchemaVersion, scoringVersions.issueEvidence);
      const discord = release.profileEvidence.surfaces.find((surface: any) => surface.label === 'Discord');
      assert.equal(discord.count, 1);
      assert.equal(Object.values(discord.tiers).reduce((sum: number, count) => sum + Number(count), 0), 1);
      assert.equal(
        discord.weight,
        Math.round(clusterRows[0].weight * 1000) / 1000,
      );
    } finally {
      dbModule.db.prepare(`
        DELETE FROM issue_closure_proofs
        WHERE release_tag='v2026.6.1' AND issue_number=106
      `).run();
      refreshClosureDependencySnapshot();
      dbModule.db.prepare(`DELETE FROM classifications WHERE issue_number IN (106, 107)`).run();
      dbModule.db.prepare(`DELETE FROM issues WHERE number IN (106, 107)`).run();
    }
  });

  it('counts one issue once when it appears in multiple profile evidence tiers', async () => {
    seedIssue({
      number: 109,
      state: 'open',
      title: 'Slack release regression appears in debt and opened evidence',
      createdAt: '2026-06-02T12:00:00Z',
      updatedAt: '2026-06-03T12:00:00Z',
      labels: ['P1', 'bug', 'regression'],
      classification: {
        sentiment: 'negative',
        severity: 'high',
        functionality: 'core',
        scope: 'broad',
        affectedUsers: 'many',
      },
    });
    try {
      const evidence = await getJson('/api/releases/v2026.6.1/review/issues?issue=109&limit=250');
      const positiveRows = evidence.body.rows.filter((row: any) => Number(row.weight ?? 0) > 0);
      assert.equal(positiveRows.length, 1);
      assert.equal(new Set(positiveRows.map((row: any) => row.aliasGroup)).size, 1);

      const publicPayload = await getJson('/api/public');
      assert.equal(publicPayload.status, 200);
      const release = publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1');
      const slack = release.profileEvidence.surfaces.find((surface: any) => surface.label === 'Slack');
      assert.equal(slack.count, 1);
      assert.equal(Object.values(slack.tiers).reduce((sum: number, count) => sum + Number(count), 0), 1);
      assert.equal(release.profileEvidence.issueCount, 1);
    } finally {
      dbModule.db.prepare(`DELETE FROM classifications WHERE issue_number=109`).run();
      dbModule.db.prepare(`DELETE FROM issues WHERE number=109`).run();
    }
  });

  it('keeps streamed public comment evidence equivalent to full review evidence', async () => {
    const issueNumber = 111;
    const updatedAt = '2026-06-03T14:00:00Z';
    const comments = [{
      id: 900_111,
      node_id: 'IC_900111',
      node_type: 'IssueComment',
      url: 'https://example.test/issues/111#issuecomment-900111',
      user: {
        id: 'U_independent-reporter',
        login: 'independent-reporter',
        type: 'User',
      },
      author_association: 'NONE',
      body: 'I can reproduce the same issue on my install.',
      created_at: '2026-06-03T13:00:00Z',
      updated_at: '2026-06-03T13:00:00Z',
    }];
    seedIssue({
      number: issueNumber,
      state: 'open',
      title: 'WhatsApp v2026.6.1 regression with independent reproduction',
      createdAt: '2026-06-02T12:00:00Z',
      updatedAt,
      labels: ['P1', 'bug', 'regression'],
      classification: {
        sentiment: 'negative',
        severity: 'high',
        functionality: 'core',
        scope: 'broad',
        affectedUsers: 'many',
      },
    });
    upsertAuthoritativeCommentSnapshot({
      issueNumber,
      issueUpdatedAt: updatedAt,
      comments,
    });
    try {
      const evidence = await getJson(
        `/api/releases/v2026.6.1/review/issues?issue=${issueNumber}&limit=250`,
      );
      assert.equal(evidence.status, 200);
      assert.equal(evidence.body.rows.length, 1);
      const evidenceRow = evidence.body.rows[0];
      assert.equal(evidenceRow.tier, 'verifiedDebt');
      assert.equal(evidenceRow.fieldConfirmed, true);

      const publicPayload = await getJson('/api/public');
      assert.equal(publicPayload.status, 200);
      const release = publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1');
      const whatsapp = release.profileEvidence.surfaces.find((surface: any) => surface.label === 'WhatsApp');
      assert.equal(whatsapp.count, 1);
      assert.equal(whatsapp.tiers.verifiedDebt, 1);
      assert.equal(whatsapp.weight, Math.round(evidenceRow.weight * 1000) / 1000);
    } finally {
      dbModule.db.prepare(`DELETE FROM issue_comment_snapshots WHERE issue_number=?`).run(issueNumber);
      dbModule.db.prepare(`DELETE FROM classifications WHERE issue_number=?`).run(issueNumber);
      dbModule.db.prepare(`DELETE FROM issues WHERE number=?`).run(issueNumber);
    }
  });

  it('applies the comment publication gate equally to review and compact public evidence', async () => {
    const cases = [
      {
        number: 88058,
        surface: 'Discord',
        body: 'Corroborating repro on v2026.6.1 from a second Control UI installation.',
        createdAt: '2026-05-31T12:00:00Z',
        expectedTier: 'carryoverDebt',
      },
      {
        number: 90781,
        surface: 'WhatsApp',
        body: 'Live repro on v2026.6.1: the response is generated, then dropped on read-back.',
        createdAt: '2026-06-02T12:00:00Z',
        expectedTier: 'verifiedDebt',
      },
    ] as const;

    for (const item of cases) {
      const issueUpdatedAt = '2026-06-03T16:00:00Z';
      const comments = [{
        id: item.number * 10,
        node_id: `IC_${item.number * 10}`,
        node_type: 'IssueComment',
        url: `https://example.test/issues/${item.number}#issuecomment-${item.number * 10}`,
        user: {
          id: `U_independent-${item.number}`,
          login: `independent-${item.number}`,
          type: 'User',
        },
        author_association: 'NONE',
        body: item.body,
        created_at: item.createdAt,
        updated_at: item.createdAt,
      }];
      seedIssue({
        number: item.number,
        state: 'open',
        title: `${item.surface} comment-only release locality case ${item.number}`,
        createdAt: '2026-05-30T12:00:00Z',
        updatedAt: issueUpdatedAt,
        labels: ['clawsweeper:source-repro'],
        classification: {
          sentiment: 'negative',
          severity: 'high',
          functionality: 'core',
          scope: 'broad',
          affectedUsers: 'many',
        },
      });
      upsertAuthoritativeCommentSnapshot({
        issueNumber: item.number,
        issueUpdatedAt,
        comments,
      });
    }

    try {
      for (const item of cases) {
        const evidence = await getJson(
          `/api/releases/v2026.6.1/review/issues?issue=${item.number}&limit=250`,
        );
        assert.equal(evidence.status, 200);
        assert.equal(evidence.body.rows.length, 1);
        assert.equal(evidence.body.rows[0].tier, item.expectedTier, String(item.number));
        assert.equal(evidence.body.rows[0].fieldConfirmed, true, String(item.number));
      }

      const publicPayload = await getJson('/api/public');
      assert.equal(publicPayload.status, 200);
      const release = publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1');
      for (const item of cases) {
        const surface = release.profileEvidence.surfaces.find(
          (candidate: any) => candidate.label === item.surface,
        );
        assert.equal(surface.tiers[item.expectedTier], 1, String(item.number));
      }
    } finally {
      const issueNumbers = cases.map((item) => item.number);
      dbModule.db.prepare(`DELETE FROM issue_comment_snapshots WHERE issue_number IN (?, ?)`)
        .run(...issueNumbers);
      dbModule.db.prepare(`DELETE FROM classifications WHERE issue_number IN (?, ?)`)
        .run(...issueNumbers);
      dbModule.db.prepare(`DELETE FROM issues WHERE number IN (?, ?)`)
        .run(...issueNumbers);
    }
  });

  it('keeps liveness p95 under 100ms during a cold coalesced release-index build', async () => {
    await waitForReleaseWorkerIdle();
    apiModule.resetReleaseApiWorkerLifecycleForTests();
    process.env.RADAR_TEST_RELEASE_WORKER_DELAY_MS = '300';
    try {
      const releasesPromise = getJson('/api/releases');
      const historyPromise = getJson('/api/releases/history');
      await waitForCondition(
        () => apiModule.releaseApiWorkerLifecycleSnapshot().active === 1,
        'release API worker',
      );
      const liveLatencies: number[] = [];
      for (let index = 0; index < 24; index++) {
        const startedAt = performance.now();
        const live = await within(getJson('/api/live'), 500, '/api/live');
        liveLatencies.push(performance.now() - startedAt);
        assert.equal(live.status, 200);
        assert.equal(live.body.ok, true);
      }
      const [releases, history] = await within(
        Promise.all([releasesPromise, historyPromise]),
        3_000,
        'cold release index requests',
      );
      assert.equal(releases.status, 200);
      assert.equal(history.status, 200);
      assert.ok(Array.isArray(releases.body));
      assert.ok(Array.isArray(history.body));
      const sorted = liveLatencies.slice().sort((left, right) => left - right);
      const p95 = sorted[Math.ceil(sorted.length * 0.95) - 1];
      assert.ok(p95 < 100, `liveness p95 was ${p95.toFixed(1)}ms`);
      await waitForReleaseWorkerIdle();
      const lifecycle = apiModule.releaseApiWorkerLifecycleSnapshot();
      assert.equal(lifecycle.spawned, 1);
      assert.equal(lifecycle.terminated, 1);
      assert.equal(lifecycle.active, 0);
      assert.equal(lifecycle.maxActive, 1);
    } finally {
      delete process.env.RADAR_TEST_RELEASE_WORKER_DELAY_MS;
    }
  });

  it('retries and cancels parent review and comparison workers across DB epochs', async () => {
    seedScoreAuditState();
    await waitForScoreReadWorkerIdle();
    apiModule.resetScoreReadWorkerLifecycleForTests();
    process.env.RADAR_TEST_SCORE_READ_WORKER_DELAY_MS = '250';
    const originalTitle = 'v2026.6.1 release local broad regression still open';
    try {
      const reviewPromise = getJson('/api/releases/v2026.6.1/review');
      await waitForCondition(
        () => apiModule.scoreReadWorkerLifecycleSnapshot().active === 1,
        'parent review worker',
      );

      dbModule.db.prepare(`UPDATE issues SET title=? WHERE number=101`)
        .run(`${originalTitle} new epoch`);
      const comparisonPromise = getJson('/api/comparison');
      await waitForCondition(
        () => apiModule.scoreReadWorkerLifecycleSnapshot().canceled >= 1,
        'stale score read worker cancellation',
      );

      const [review, comparison] = await within(
        Promise.all([reviewPromise, comparisonPromise]),
        8_000,
        'parent review and comparison epoch retry',
      );
      assert.equal(review.status, 200);
      assert.equal(review.body.local.score, null);
      assert.equal(review.body.local.status, 'stale');
      assert.ok(review.body.local.staleAudit.causes.includes('evidence_source_changed'));
      assert.equal(comparison.status, 200);
      const local = comparison.body.releases.find(
        (release: any) => release.tag === 'v2026.6.1',
      )?.local;
      assert.equal(local.score, null);
      assert.equal(local.status, 'stale');
      assert.ok(local.staleAudit.causes.includes('evidence_source_changed'));

      await waitForScoreReadWorkerIdle();
      const lifecycle = apiModule.scoreReadWorkerLifecycleSnapshot();
      assert.ok(lifecycle.spawned >= 3);
      assert.ok(lifecycle.canceled >= 1);
      assert.equal(lifecycle.terminated, lifecycle.spawned);
      assert.equal(lifecycle.active, 0);
    } finally {
      delete process.env.RADAR_TEST_SCORE_READ_WORKER_DELAY_MS;
      dbModule.db.prepare(`UPDATE issues SET title=? WHERE number=101`).run(originalTitle);
      clearScoreAuditState();
    }
  });

  it('keeps liveness responsive during a cold bounded public payload build', async () => {
    const firstIssueNumber = 2_000;
    const issueCount = 480;
    const issueNumbers = Array.from({ length: issueCount }, (_, index) => firstIssueNumber + index);
    const rationale = `HEAVY_RATIONALE_MARKER:${'x'.repeat(12 * 1024)}`;
    dbModule.runInWriteTransaction(() => {
      for (const number of issueNumbers) {
        seedIssue({
          number,
          state: 'open',
          title: `Slack synthetic public performance issue ${number}`,
          createdAt: '2026-06-02T12:00:00Z',
          updatedAt: '2026-06-03T12:00:00Z',
          labels: ['P1', 'bug', 'regression'],
          classification: {
            sentiment: 'negative',
            severity: 'high',
            functionality: 'core',
            scope: 'broad',
            affectedUsers: 'many',
            rationale,
          },
        });
      }
    });

    try {
      const lifecycleBefore = apiModule.publicPayloadWorkerLifecycleSnapshot();
      const memoryBefore = process.memoryUsage();
      const coldStartedAt = performance.now();
      let publicSettled = false;
      const firstPublic = getJson('/api/public').finally(() => {
        publicSettled = true;
      });
      await delay(25);
      const secondPublic = getJson('/api/public');
      const live = await within(getJson('/api/live'), 1_000, '/api/live');
      assert.equal(live.status, 200);
      assert.equal(live.body.ok, true);
      assert.equal(publicSettled, false, '/api/public completed before the concurrent liveness probe');

      const [first, second] = await within(
        Promise.all([firstPublic, secondPublic]),
        15_000,
        'cold concurrent /api/public requests',
      );
      assert.equal(first.status, 200);
      assert.deepEqual(second.body, first.body);
      const coldElapsedMs = performance.now() - coldStartedAt;
      assert.ok(coldElapsedMs < 8_000, `cold /api/public took ${coldElapsedMs.toFixed(1)}ms`);
      const serialized = JSON.stringify(first.body);
      const payloadBytes = Buffer.byteLength(serialized);
      assert.ok(payloadBytes < 128 * 1024, `public payload was ${payloadBytes} bytes`);
      assert.doesNotMatch(serialized, /HEAVY_RATIONALE_MARKER/);

      const release = first.body.releases.find((row: any) => row.tag === 'v2026.6.1');
      const slack = release.profileEvidence.surfaces.find((surface: any) => surface.label === 'Slack');
      assert.equal(slack.count, issueCount);
      assert.equal(release.profileEvidence.issueCount, issueCount);
      assert.equal(
        Object.values(slack.tiers).reduce((sum: number, count) => sum + Number(count), 0),
        issueCount,
      );

      const warmStartedAt = performance.now();
      const warm = await within(getJson('/api/public'), 1_000, 'warm /api/public');
      const warmElapsedMs = performance.now() - warmStartedAt;
      assert.equal(warm.status, 200);
      assert.deepEqual(warm.body, first.body);
      assert.ok(warmElapsedMs < 1_000, `warm /api/public took ${warmElapsedMs.toFixed(1)}ms`);

      const lifecycleAfter = apiModule.publicPayloadWorkerLifecycleSnapshot();
      assert.equal(lifecycleAfter.spawned - lifecycleBefore.spawned, 1);
      assert.equal(lifecycleAfter.terminated - lifecycleBefore.terminated, 1);
      assert.equal(lifecycleAfter.active, 0);
      assert.ok(lifecycleAfter.maxActive <= 1);
      assert.ok(lifecycleAfter.lastWorkerHeapUsed < 96 * 1024 * 1024);
      assert.ok(
        lifecycleAfter.lastWorkerRss < 400 * 1024 * 1024,
        `public worker RSS was ${lifecycleAfter.lastWorkerRss} bytes`,
      );
      const memoryAfter = process.memoryUsage();
      assert.ok(
        memoryAfter.heapUsed - memoryBefore.heapUsed < 96 * 1024 * 1024,
        `heap grew by ${memoryAfter.heapUsed - memoryBefore.heapUsed} bytes`,
      );
      assert.ok(
        memoryAfter.rss - memoryBefore.rss < 160 * 1024 * 1024,
        `RSS grew by ${memoryAfter.rss - memoryBefore.rss} bytes`,
      );
    } finally {
      const placeholders = issueNumbers.map(() => '?').join(',');
      dbModule.db.prepare(`DELETE FROM classifications WHERE issue_number IN (${placeholders})`).run(...issueNumbers);
      dbModule.db.prepare(`DELETE FROM issues WHERE number IN (${placeholders})`).run(...issueNumbers);
    }
  });

  it('serves only bounded stale non-actionable retained public data while a rebuild runs', async () => {
    seedScoreAuditState();
    try {
      const warm = await getJson('/api/public');
      assert.equal(warm.status, 200);
      assert.equal(warm.body.snapshot.actionable, true);
      const warmRelease = warm.body.releases.find(
        (release: any) => release.tag === 'v2026.6.1',
      );
      assert.notEqual(warmRelease.profileEvidence.publicationBinding, null);
      const { invalidateCache } = await import('./cache.ts');
      await waitForWorkerIdle();
      apiModule.resetPublicPayloadWorkerLifecycleForTests();
      invalidateCache();
      process.env.RADAR_TEST_PUBLIC_WORKER_DELAY_MS = '350';
      const startedAt = performance.now();
      const retained = await within(getJson('/api/public'), 1_000, 'retained /api/public');
      const elapsedMs = performance.now() - startedAt;
      assert.equal(retained.status, 200);
      assert.equal(retained.headers.get('x-radar-snapshot-id'), warm.body.snapshot.id);
      assert.equal(retained.body.snapshot.id, warm.body.snapshot.id);
      assert.equal(retained.body.snapshot.source, 'retained');
      assert.equal(retained.body.snapshot.retained, true);
      assert.equal(retained.body.snapshot.stale, true);
      assert.equal(retained.body.snapshot.actionable, false);
      assert.equal(retained.body.snapshot.maxAgeMs, 30_000);
      assert.ok(retained.body.snapshot.ageMs <= retained.body.snapshot.maxAgeMs);
      assert.ok(retained.body.releases.length > 0);
      for (const release of retained.body.releases) {
        assert.equal(release.score, null);
        assert.equal(release.status, 'stale');
        assert.equal(release.recommended, false);
        assert.equal(release.scoreAudit, null);
        assert.equal(release.explanation, null);
        assert.equal(
          release.profileEvidence.sourceMode,
          'current_diagnostic_evidence',
        );
        assert.equal(release.profileEvidence.publicationBinding, null);
        assert.ok(release.staleAudit.causes.includes('public_payload_retained'));
      }
      assert.ok(elapsedMs < 250, `retained /api/public took ${elapsedMs.toFixed(1)}ms`);
      assert.equal(apiModule.publicPayloadWorkerLifecycleSnapshot().active, 1);
      await waitForWorkerIdle();
      const rebuilt = await getJson('/api/public');
      assert.equal(rebuilt.body.snapshot.source, 'current');
      assert.equal(rebuilt.body.snapshot.stale, false);
      assert.equal(rebuilt.body.snapshot.actionable, true);
      const lifecycle = apiModule.publicPayloadWorkerLifecycleSnapshot();
      assert.equal(lifecycle.spawned, 1);
      assert.equal(lifecycle.terminated, 1);
      assert.equal(lifecycle.canceled, 0);
      assert.equal(lifecycle.maxActive, 1);
    } finally {
      delete process.env.RADAR_TEST_PUBLIC_WORKER_DELAY_MS;
      await waitForWorkerIdle();
      clearScoreAuditState();
    }
  });

  it('never exposes live partial issue enrichment as actionable during refresh', async () => {
    const warm = await getJson('/api/public');
    assert.equal(warm.status, 200);
    const acquiredAt = new Date().toISOString();
    assert.equal(
      dbModule.acquireRefreshLease(
        'api-public-partial-refresh',
        'api-public-partial-holder',
        acquiredAt,
        300_000,
      ),
      true,
    );
    try {
      const response = await getJson('/api/public');
      assert.equal(response.status, 200);
      assert.equal(response.body.snapshot.source, 'retained');
      assert.equal(response.body.snapshot.actionable, false);
      assert.equal(response.body.snapshot.id, warm.body.snapshot.id);
      assert.ok(response.body.releases.every((release: any) =>
        release.score == null &&
        release.recommended === false &&
        release.status === 'stale'));
    } finally {
      assert.equal(
        dbModule.releaseRefreshLease(
          'api-public-partial-refresh',
          'api-public-partial-holder',
        ),
        true,
      );
    }
  });

  it('waits for a fresh public rebuild after the retained fallback age bound expires', async () => {
    seedScoreAuditState();
    try {
      const warm = await getJson('/api/public');
      assert.equal(warm.status, 200);
      assert.equal(warm.body.snapshot.actionable, true);
      const { invalidateCache } = await import('./cache.ts');
      await waitForWorkerIdle();
      apiModule.resetPublicPayloadWorkerLifecycleForTests();
      invalidateCache();
      apiModule.expireRetainedPublicPayloadForTests();
      process.env.RADAR_TEST_PUBLIC_WORKER_DELAY_MS = '350';
      const startedAt = performance.now();
      const response = await within(getJson('/api/public'), 2_000, 'expired retained /api/public');
      const elapsedMs = performance.now() - startedAt;
      assert.equal(response.status, 200);
      assert.equal(response.body.snapshot.source, 'current');
      assert.equal(response.body.snapshot.retained, false);
      assert.equal(response.body.snapshot.stale, false);
      assert.equal(response.body.snapshot.actionable, true);
      assert.ok(elapsedMs >= 250, `expired retained payload returned in ${elapsedMs.toFixed(1)}ms`);
      await waitForWorkerIdle();
    } finally {
      delete process.env.RADAR_TEST_PUBLIC_WORKER_DELAY_MS;
      await waitForWorkerIdle();
      clearScoreAuditState();
    }
  });

  it('cancels superseded public workers across refresh-epoch churn without RSS growth', async () => {
    await getJson('/api/public');
    await waitForWorkerIdle();
    apiModule.resetPublicPayloadWorkerLifecycleForTests();
    const memoryBefore = process.memoryUsage();
    process.env.RADAR_TEST_PUBLIC_WORKER_DELAY_MS = '250';
    const originalTitle = 'v2026.6.1 release local broad regression still open';
    try {
      dbModule.db.prepare(`UPDATE issues SET title=? WHERE number=101`).run(`${originalTitle} epoch 1`);
      const first = getJson('/api/public');
      await waitForCondition(
        () => apiModule.publicPayloadWorkerLifecycleSnapshot().active === 1,
        'first public worker',
      );

      dbModule.db.prepare(`UPDATE issues SET title=? WHERE number=101`).run(`${originalTitle} epoch 2`);
      const second = getJson('/api/public');
      await waitForCondition(
        () => apiModule.publicPayloadWorkerLifecycleSnapshot().canceled >= 1,
        'first public worker cancellation',
      );

      dbModule.db.prepare(`UPDATE issues SET title=? WHERE number=101`).run(`${originalTitle} epoch 3`);
      const third = getJson('/api/public');
      const responses = await within(
        Promise.all([first, second, third]),
        8_000,
        'refresh-epoch churn public requests',
      );
      for (const response of responses) {
        assert.equal(response.status, 200);
        assert.match(JSON.stringify(response.body), /epoch 3/);
        assert.doesNotMatch(JSON.stringify(response.body), /epoch [12]/);
      }
      await waitForWorkerIdle();
      const lifecycle = apiModule.publicPayloadWorkerLifecycleSnapshot();
      assert.ok(lifecycle.spawned >= 3);
      assert.ok(lifecycle.canceled >= 2);
      assert.equal(lifecycle.terminated, lifecycle.spawned);
      assert.equal(lifecycle.active, 0);
      assert.equal(lifecycle.maxActive, 1);
      const memoryAfter = process.memoryUsage();
      assert.ok(
        memoryAfter.heapUsed - memoryBefore.heapUsed < 64 * 1024 * 1024,
        `heap grew by ${memoryAfter.heapUsed - memoryBefore.heapUsed} bytes`,
      );
      assert.ok(
        memoryAfter.rss - memoryBefore.rss < 160 * 1024 * 1024,
        `RSS grew by ${memoryAfter.rss - memoryBefore.rss} bytes`,
      );
    } finally {
      delete process.env.RADAR_TEST_PUBLIC_WORKER_DELAY_MS;
      dbModule.db.prepare(`UPDATE issues SET title=? WHERE number=101`).run(originalTitle);
    }
  });

  it('withholds incompatible audit provenance on score history rows', async () => {
    dbModule.updateReleaseScore({
      tag: 'v2026.6.1',
      final_score: 7.5,
      negative_issues: 2,
      positive_issues: 1,
      state: 'eligible',
      recommended: 1,
      score_reason: 'test score',
      broken_surfaces: '[]',
      closed_serious_fixed: 1,
      opened_serious_during_reign: 1,
      scored_at: '2026-06-06T00:00:00Z',
    });
    dbModule.upsertReleaseScoreAudit({
      release_tag: 'v2026.6.1',
      scored_at: '2026-06-06T00:00:00Z',
      score_model_version: 'test-model',
      prompt_version: 1,
      final_score: 7.5,
      status: 'eligible',
      band: 'ok',
      recommended: 1,
      input_json: '{}',
      components_json: '{}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
    });
    try {
      const response = await getJson('/api/releases/history');

      assert.equal(response.status, 200);
      const row = response.body.find((item: any) => item.tag === 'v2026.6.1');
      assert.equal(row.schemaVersion, 2);
      assert.equal(row.tag, 'v2026.6.1');
      assert.equal(row.publishedAt, '2026-06-01T00:00:00Z');
      assert.equal(row.scoreAudit, null);
      assert.equal(row.staleAudit.state, 'stale');
      assert.ok(row.staleAudit.causes.includes('audit_publication_invalid'));
      assert.equal(row.scoredAt, null);
      assert.equal(row.dataFreshness.tag, 'v2026.6.1');
      const auditBinding = `publicationSnapshot=${row.snapshotId}&auditDigest=unavailable`;
      assert.deepEqual(row.auditLinks, {
        review: `/api/releases/v2026.6.1/review?${auditBinding}`,
        issues: `/api/releases/v2026.6.1/review/issues?${auditBinding}`,
        closureProofs: `/api/releases/v2026.6.1/review/closure-proofs?${auditBinding}`,
        reachability: `/api/releases/v2026.6.1/review/reachability?${auditBinding}`,
      });
    } finally {
      dbModule.db.prepare(`DELETE FROM release_score_audits WHERE release_tag='v2026.6.1'`).run();
      dbModule.db.prepare(`
        UPDATE releases
        SET final_score=NULL,
            negative_issues=NULL,
            positive_issues=NULL,
            scored_at=NULL,
            state=NULL,
            recommended=0,
            score_reason=NULL,
            broken_surfaces=NULL,
            closed_serious_fixed=0,
            opened_serious_during_reign=0
        WHERE tag='v2026.6.1'
      `).run();
    }
  });

  it('rejects invalid issue evidence filters at the route boundary', async () => {
    const cases = [
      ['/api/releases/v2026.6.1/review/issues?tier=not-a-tier', 'invalid tier'],
      ['/api/releases/v2026.6.1/review/issues?impact=not-impact', 'invalid impact'],
      ['/api/releases/v2026.6.1/review/issues?state=invalid', 'invalid state'],
      ['/api/releases/v2026.6.1/review/issues?sentiment=bad', 'invalid sentiment'],
      ['/api/releases/v2026.6.1/review/issues?severity=bad', 'invalid severity'],
      ['/api/releases/v2026.6.1/review/issues?functionality=bad', 'invalid functionality'],
      ['/api/releases/v2026.6.1/review/issues?scope=bad', 'invalid scope'],
      ['/api/releases/v2026.6.1/review/issues?affectedUsers=bad', 'invalid affectedUsers'],
      ['/api/releases/v2026.6.1/review/issues?issue=bad', 'invalid issue'],
      ['/api/releases/v2026.6.1/review/issues?issue=101&issue=102', 'invalid issue'],
      ['/api/releases/v2026.6.1/review/issues?issue=101&number=102', 'invalid issue'],
      ['/api/releases/v2026.6.1/review/issues?fieldConfirmed=maybe', 'invalid fieldConfirmed'],
      ['/api/releases/v2026.6.1/review/issues?fieldConfirmed=true&fieldConfirmed=maybe', 'invalid fieldConfirmed'],
      ['/api/releases/v2026.6.1/review/issues?minWeight=abc', 'invalid minWeight'],
      ['/api/releases/v2026.6.1/review/issues?minWeight=1&minWeight=abc', 'invalid minWeight'],
      ['/api/releases/v2026.6.1/review/issues?maxWeight=abc', 'invalid maxWeight'],
      ['/api/releases/v2026.6.1/review/issues?maxWeight=1&maxWeight=abc', 'invalid maxWeight'],
      ['/api/releases/v2026.6.1/review/issues?minWeight=10&maxWeight=1', 'invalid weight range'],
      ['/api/releases/v2026.6.1/review/issues?sort=bad', 'invalid sort'],
      ['/api/releases/v2026.6.1/review/issues?sort=rank&sort=bad', 'invalid sort'],
      ['/api/releases/v2026.6.1/review/issues?direction=sideways', 'invalid direction'],
      ['/api/releases/v2026.6.1/review/issues?direction=asc&direction=sideways', 'invalid direction'],
      ['/api/releases/v2026.6.1/review/issues?summaryOnly=wat', 'invalid summaryOnly'],
      ['/api/releases/v2026.6.1/review/issues?summaryOnly=true&summaryOnly=wat', 'invalid summaryOnly'],
      ['/api/releases/v2026.6.1/review/issues?limit=abc', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/issues?limit=1.9', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/issues?limit=1&limit=2', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/issues?cursor=abc', 'invalid cursor'],
      ['/api/releases/v2026.6.1/review/issues?cursor=1.9', 'invalid cursor'],
      ['/api/releases/v2026.6.1/review/issues?cursor=0&cursor=1', 'invalid cursor'],
    ] as const;

    for (const [path, error] of cases) {
      const response = await getJson(path);
      assert.equal(response.status, 400, path);
      assert.equal(response.body.error, error, path);
    }
  });

  it('rejects invalid closure proof filters at the route boundary', async () => {
    const invalidStatus = await getJson('/api/releases/v2026.6.1/review/closure-proofs?status=bad');
    assert.equal(invalidStatus.status, 400);
    assert.equal(invalidStatus.body.error, 'invalid status');
    assert.ok(invalidStatus.body.allowedStatuses.includes('fixed_in_release'));

    const repeatedStatus = await getJson('/api/releases/v2026.6.1/review/closure-proofs?status=fixed_in_release&status=bad');
    assert.equal(repeatedStatus.status, 400);
    assert.equal(repeatedStatus.body.error, 'invalid status');

    const invalidDisposition = await getJson('/api/releases/v2026.6.1/review/closure-proofs?riskDisposition=bad');
    assert.equal(invalidDisposition.status, 400);
    assert.equal(invalidDisposition.body.error, 'invalid riskDisposition');
    assert.ok(invalidDisposition.body.allowedRiskDispositions.includes('credited_release_fix'));

    const repeatedDisposition = await getJson('/api/releases/v2026.6.1/review/closure-proofs?riskDisposition=credited_release_fix&riskDisposition=bad');
    assert.equal(repeatedDisposition.status, 400);
    assert.equal(repeatedDisposition.body.error, 'invalid riskDisposition');

    for (const [path, error] of [
      ['/api/releases/v2026.6.1/review/closure-proofs?issue=bad', 'invalid issue'],
      ['/api/releases/v2026.6.1/review/closure-proofs?issue=103&issue=104', 'invalid issue'],
      ['/api/releases/v2026.6.1/review/closure-proofs?issue=103&number=104', 'invalid issue'],
      ['/api/releases/v2026.6.1/review/closure-proofs?limit=abc', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/closure-proofs?limit=1.9', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/closure-proofs?limit=1&limit=2', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/closure-proofs?cursor=abc', 'invalid cursor'],
      ['/api/releases/v2026.6.1/review/closure-proofs?cursor=1.9', 'invalid cursor'],
      ['/api/releases/v2026.6.1/review/closure-proofs?cursor=0&cursor=1', 'invalid cursor'],
    ] as const) {
      const response = await getJson(path);
      assert.equal(response.status, 400, path);
      assert.equal(response.body.error, error, path);
    }
  });

  it('rejects invalid reachability filters at the route boundary', async () => {
    const invalidStatus = await getJson('/api/releases/v2026.6.1/review/reachability?status=bad');
    assert.equal(invalidStatus.status, 400);
    assert.equal(invalidStatus.body.error, 'invalid status');

    const repeatedStatus = await getJson('/api/releases/v2026.6.1/review/reachability?status=reachable&status=bad');
    assert.equal(repeatedStatus.status, 400);
    assert.equal(repeatedStatus.body.error, 'invalid status');

    const invalidPr = await getJson('/api/releases/v2026.6.1/review/reachability?pr=not-a-pr');
    assert.equal(invalidPr.status, 400);
    assert.equal(invalidPr.body.error, 'invalid pr filter');

    const repeatedPr = await getJson('/api/releases/v2026.6.1/review/reachability?pr=123&pr=not-a-pr');
    assert.equal(repeatedPr.status, 400);
    assert.equal(repeatedPr.body.error, 'invalid pr filter');

    for (const [path, error] of [
      ['/api/releases/v2026.6.1/review/reachability?limit=abc', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/reachability?limit=1.9', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/reachability?limit=1&limit=2', 'invalid limit'],
      ['/api/releases/v2026.6.1/review/reachability?cursor=abc', 'invalid cursor'],
      ['/api/releases/v2026.6.1/review/reachability?cursor=1.9', 'invalid cursor'],
      ['/api/releases/v2026.6.1/review/reachability?cursor=0&cursor=1', 'invalid cursor'],
    ] as const) {
      const response = await getJson(path);
      assert.equal(response.status, 400, path);
      assert.equal(response.body.error, error, path);
    }
  });

  it('applies issue evidence filters, sorting, summary-only mode, and limit clamps', async () => {
    const clamped = await getJson('/api/releases/v2026.6.1/review/issues?limit=999&cursor=-5');
    assert.equal(clamped.status, 200);
    assert.equal(clamped.body.limit, 250);
    assert.equal(clamped.body.cursor, 0);
    assert.ok(clamped.body.total >= 4);

    const summaryOnly = await getJson('/api/releases/v2026.6.1/review/issues?tier=verifiedDebt&summaryOnly=true');
    assert.equal(summaryOnly.status, 200);
    assert.equal(summaryOnly.body.filters.tier, 'verifiedDebt');
    assert.deepEqual(summaryOnly.body.filters.tiers, ['verifiedDebt']);
    assert.equal(summaryOnly.body.filters.summaryOnly, true);
    assert.equal(summaryOnly.body.limit, 0);
    assert.equal(summaryOnly.body.cursor, 0);
    assert.deepEqual(summaryOnly.body.rows, []);
    assert.equal(summaryOnly.body.total, 0);

    const openUnconfirmedAlias = await getJson('/api/releases/v2026.6.1/review/issues?tier=openUnconfirmedRisk&summaryOnly=true');
    assert.equal(openUnconfirmedAlias.status, 200);
    assert.equal(openUnconfirmedAlias.body.filters.tier, 'carryoverDebt');
    assert.deepEqual(openUnconfirmedAlias.body.filters.tiers, ['carryoverDebt']);

    const weakStaleAlias = await getJson('/api/releases/v2026.6.1/review/issues?tier=weakOrStaleEvidence&summaryOnly=true');
    assert.equal(weakStaleAlias.status, 200);
    assert.equal(weakStaleAlias.body.filters.tier, 'staleDebt');
    assert.deepEqual(weakStaleAlias.body.filters.tiers, ['staleDebt']);

    const fieldConfirmed = await getJson('/api/releases/v2026.6.1/review/issues?tier=verifiedDebt&fieldConfirmed=true');
    assert.equal(fieldConfirmed.status, 200);
    assert.equal(fieldConfirmed.body.filters.fieldConfirmed, true);
    assert.ok(fieldConfirmed.body.rows.every((row: any) => row.tier === 'verifiedDebt' && row.fieldConfirmed === true));

    const updatedDesc = await getJson('/api/releases/v2026.6.1/review/issues?limit=10&sort=updated&direction=desc');
    assert.equal(updatedDesc.status, 200);
    assert.equal(updatedDesc.body.filters.sort, 'updated');
    assert.equal(updatedDesc.body.filters.direction, 'desc');
    assert.ok(isNonIncreasingTimestamps(updatedDesc.body.rows.map((row: any) => row.issue.updatedAt)));

    const stateOpen = await getJson('/api/releases/v2026.6.1/review/issues?state=open');
    assert.equal(stateOpen.status, 200);
    assert.equal(stateOpen.body.filters.state, 'open');
    assert.deepEqual(stateOpen.body.filters.states, ['open']);
    assert.ok(stateOpen.body.rows.every((row: any) => row.issue.state === 'open'));

    const negative = await getJson('/api/releases/v2026.6.1/review/issues?sentiment=negative&limit=250');
    assert.equal(negative.status, 200);
    assert.ok(negative.body.rows.every((row: any) => row.issue.classification.sentiment === 'negative'));
    assert.ok(negative.body.rows.every((row: any) => row.issue.number !== 108));

    const byIssue = await getJson('/api/releases/v2026.6.1/review/issues?issue=101');
    assert.equal(byIssue.status, 200);
    assert.equal(byIssue.body.filters.issue, 101);
    assert.equal(byIssue.body.filters.issueNumber, 101);
    assert.ok(byIssue.body.total >= 1);
    assert.ok(byIssue.body.rows.every((row: any) => row.issue.number === 101));

    const byNumberAlias = await getJson('/api/releases/v2026.6.1/review/issues?number=104');
    assert.equal(byNumberAlias.status, 200);
    assert.equal(byNumberAlias.body.filters.issue, 104);
    assert.ok(byNumberAlias.body.total >= 1);
    assert.ok(byNumberAlias.body.rows.every((row: any) => row.issue.number === 104));
  });

  it('preserves repeated enum filters in review pagination links', async () => {
    const response = await getJson(
      '/api/releases/v2026.6.1/review/issues?' +
        'state=open&state=closed&sentiment=negative&sentiment=neutral&limit=1',
    );
    assert.equal(response.status, 200);
    assert.notEqual(response.body.links.next, null);

    for (const link of [response.body.links.self, response.body.links.next]) {
      const url = new URL(link, 'http://radar.test');
      assert.deepEqual(url.searchParams.getAll('state'), ['open', 'closed']);
      assert.deepEqual(
        url.searchParams.getAll('sentiment'),
        ['negative', 'neutral'],
      );
      assert.equal(url.searchParams.get('limit'), '1');
      assert.match(
        url.searchParams.get('publicationSnapshot') ?? '',
        /^[0-9a-f]{64}$/,
      );
      assert.ok(url.searchParams.has('auditDigest'));
    }
  });

  it('applies closure proof filter intersections and limit clamps', async () => {
    const filtered = await getJson('/api/releases/v2026.6.1/review/closure-proofs?status=fixed_after_release&riskDisposition=known_not_in_release');
    assert.equal(filtered.status, 200);
    assert.equal(filtered.body.filters.status, 'fixed_after_release');
    assert.equal(filtered.body.filters.riskDisposition, 'known_not_in_release');
    assert.equal(filtered.body.total, 1);
    assert.equal(filtered.body.rows[0].issueNumber, 104);
    assert.equal(filtered.body.rows[0].status, 'fixed_after_release');
    assert.equal(filtered.body.rows[0].riskDisposition, 'known_not_in_release');
    assert.equal(filtered.body.rows[0].riskDispositionLabel, 'known not in this tag');
    assert.equal(typeof filtered.body.rows[0].riskWeightLabel, 'string');

    const unknownCommit = await getJson('/api/releases/v2026.6.1/review/closure-proofs?status=non_bug_direct_fix_commit_reachability_unknown');
    assert.equal(unknownCommit.status, 200);
    assert.equal(unknownCommit.body.filters.status, 'non_bug_direct_fix_commit_reachability_unknown');
    assert.equal(unknownCommit.body.total, 1);
    assert.equal(unknownCommit.body.rows[0].issueNumber, 105);
    assert.equal(unknownCommit.body.rows[0].riskDisposition, 'neutral_or_non_actionable');
    assert.equal(unknownCommit.body.rows[0].evidence.hasUnknownFixCommit, true);
    assert.deepEqual(unknownCommit.body.rows[0].evidence.unknownFixCommits, ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a']);
    assert.equal(unknownCommit.body.rows[0].evidence.fixCommitProof[0].status, 'unknown');
    assert.equal(unknownCommit.body.rows[0].evidence.fixCommitProof[0].commitUrl, 'https://github.com/openclaw/openclaw/commit/cfeaf6897fd89201b71ff7d5285e48c5a382ac9a');
    assert.equal(unknownCommit.body.rows[0].evidence.fixCommitProof[0].sourceIssueUrl, 'https://github.com/openclaw/openclaw/issues/105');
    assert.equal(unknownCommit.body.rows[0].evidence.fixCommitProof[0].sourceCommentUrl, 'https://github.com/openclaw/openclaw/issues/105#issuecomment-123456');
    assert.equal(unknownCommit.body.rows[0].evidence.matchingComments[0].databaseId, 123456);
    assert.equal(unknownCommit.body.rows[0].evidence.matchingComments[0].url, 'https://github.com/openclaw/openclaw/issues/105#issuecomment-123456');

    const unsupportedNeutralClaim = await getJson(
      '/api/releases/v2026.6.1/review/closure-proofs?status=not_planned',
    );
    assert.equal(unsupportedNeutralClaim.status, 200);
    assert.equal(unsupportedNeutralClaim.body.total, 1);
    assert.equal(unsupportedNeutralClaim.body.rows[0].issueNumber, 199);
    assert.equal(
      unsupportedNeutralClaim.body.rows[0].riskDisposition,
      'unsupported_closure_claim',
    );
    assert.ok(unsupportedNeutralClaim.body.rows[0].riskWeight > 0);

    const unsupportedDisposition = await getJson(
      '/api/releases/v2026.6.1/review/closure-proofs?' +
        'riskDisposition=unsupported_closure_claim',
    );
    assert.equal(unsupportedDisposition.status, 200);
    assert.equal(unsupportedDisposition.body.total, 1);
    assert.equal(unsupportedDisposition.body.rows[0].issueNumber, 199);
    assert.equal(
      unsupportedDisposition.body.filteredCountsByRiskDisposition
        .unsupported_closure_claim,
      1,
    );

    const issueFiltered = await getJson('/api/releases/v2026.6.1/review/closure-proofs?issue=103');
    assert.equal(issueFiltered.status, 200);
    assert.equal(issueFiltered.body.filters.issue, 103);
    assert.equal(issueFiltered.body.filters.issueNumber, 103);
    assert.equal(issueFiltered.body.total, 1);
    assert.equal(issueFiltered.body.rows[0].issueNumber, 103);

    const numberAlias = await getJson('/api/releases/v2026.6.1/review/closure-proofs?number=104');
    assert.equal(numberAlias.status, 200);
    assert.equal(numberAlias.body.filters.issue, 104);
    assert.equal(numberAlias.body.total, 1);
    assert.equal(numberAlias.body.rows[0].issueNumber, 104);

    const clamped = await getJson('/api/releases/v2026.6.1/review/closure-proofs?limit=999&cursor=-2');
    assert.equal(clamped.status, 200);
    assert.equal(clamped.body.limit, 100);
    assert.equal(clamped.body.cursor, 0);
  });

  it('applies reachability PR filter variants and limit clamps', async () => {
    const byNumber = await getJson('/api/releases/v2026.6.1/review/reachability?pr=123');
    assert.equal(byNumber.status, 200);
    assert.deepEqual(byNumber.body.filters.pr, { repositoryNameWithOwner: null, number: 123 });
    assert.equal(byNumber.body.total, 1);
    assert.equal(byNumber.body.rows[0].number, 123);

    const byRepo = await getJson('/api/releases/v2026.6.1/review/reachability?pr=OpenClaw/OpenClaw%23123');
    assert.equal(byRepo.status, 200);
    assert.deepEqual(byRepo.body.filters.pr, { repositoryNameWithOwner: 'OpenClaw/OpenClaw', number: 123 });
    assert.equal(byRepo.body.total, 1);
    assert.equal(byRepo.body.rows[0].repositoryNameWithOwner, 'openclaw/openclaw');

    const clamped = await getJson('/api/releases/v2026.6.1/review/reachability?limit=999&cursor=-2');
    assert.equal(clamped.status, 200);
    assert.equal(clamped.body.limit, 250);
    assert.equal(clamped.body.cursor, 0);
  });

  it('keeps bounded pagination equivalent to one-shot issue, closure, and reachability reads', async () => {
    for (const path of [
      '/api/releases/v2026.6.1/review/issues?sort=updated&direction=desc',
      '/api/releases/v2026.6.1/review/closure-proofs',
      '/api/releases/v2026.6.1/review/reachability',
    ]) {
      const oneShot = await getJson(appendQuery(path, 'limit=250'));
      assert.equal(oneShot.status, 200, path);
      const paged = await collectPagedRows(path, 1);
      assert.deepEqual(paged.rows, oneShot.body.rows, path);
      assert.equal(paged.total, oneShot.body.total, path);
      assert.deepEqual(paged.totals, oneShot.body.totals, path);
    }
  });
});

function isNonIncreasingTimestamps(values: string[]): boolean {
  for (let index = 1; index < values.length; index++) {
    if (Date.parse(values[index - 1]) < Date.parse(values[index])) return false;
  }
  return true;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForCondition(
  check: () => boolean,
  label: string,
  timeoutMs = 2_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await delay(10);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function waitForWorkerIdle(): Promise<void> {
  await waitForCondition(
    () => apiModule.publicPayloadWorkerLifecycleSnapshot().active === 0,
    'public worker termination',
    5_000,
  );
}

async function waitForReleaseWorkerIdle(): Promise<void> {
  await waitForCondition(
    () => apiModule.releaseApiWorkerLifecycleSnapshot().active === 0,
    'release API worker termination',
    5_000,
  );
}

async function waitForScoreReadWorkerIdle(): Promise<void> {
  await waitForCondition(
    () => apiModule.scoreReadWorkerLifecycleSnapshot().active === 0,
    'score read worker termination',
    5_000,
  );
}

function appendQuery(path: string, query: string): string {
  return `${path}${path.includes('?') ? '&' : '?'}${query}`;
}

async function collectPagedRows(
  path: string,
  limit: number,
): Promise<{ rows: any[]; total: number; totals: Record<string, unknown> }> {
  const rows: any[] = [];
  let cursor = 0;
  let expectedTotal: number | null = null;
  let expectedTotals: Record<string, unknown> | null = null;
  for (let page = 0; page < 10_000; page++) {
    const response = await getJson(appendQuery(path, `limit=${limit}&cursor=${cursor}`));
    assert.equal(response.status, 200, path);
    expectedTotal ??= response.body.total;
    expectedTotals ??= response.body.totals;
    assert.equal(response.body.total, expectedTotal, path);
    assert.deepEqual(response.body.totals, expectedTotals, path);
    rows.push(...response.body.rows);
    if (response.body.nextCursor == null) {
      return {
        rows,
        total: expectedTotal ?? 0,
        totals: expectedTotals ?? {},
      };
    }
    assert.ok(response.body.nextCursor > cursor, path);
    cursor = response.body.nextCursor;
  }
  throw new Error(`Pagination did not terminate for ${path}`);
}

function within<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`${label} exceeded ${timeoutMs}ms`)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function forbiddenHealthActionFields(value: unknown, path = 'health'): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      forbiddenHealthActionFields(item, `${path}[${index}]`));
  }
  if (!value || typeof value !== 'object') return [];
  const failures: string[] = [];
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    if (key === 'recommended' || key === 'score' || key === 'finalScore') {
      failures.push(childPath);
    }
    failures.push(...forbiddenHealthActionFields(child, childPath));
  }
  return failures;
}

type ScoreAuditPayloads = {
  input: Record<string, any>;
  components: Record<string, any>;
  issueEvidence: Record<string, any>;
  gateEvidence: Record<string, any>;
};

function debtTierSummary() {
  return {
    count: 0,
    weight: 0,
    storedWeight: 0,
    byInstallImpactClass: {},
  };
}

function closureRiskSummary() {
  return {
    creditedReleaseFixCount: 1,
    containedReleaseFixCount: 1,
    containedWithoutFirstCreditCount: 0,
    resolvedByCanonicalReleaseFixCount: 0,
    resolvedByReleaseFixProofCount: 0,
    knownNotInReleaseCount: 0,
    openCanonicalRiskCount: 0,
    unsupportedClosureClaimCount: 0,
    neutralOrNonActionableCount: 0,
    neutralHighImpactCount: 0,
    neutralBugShapedCount: 0,
    missingEvidenceCount: 0,
    unresolvedForReleaseCount: 0,
    unresolvedWeightedRisk: 0,
    weightedRiskByDisposition: {},
  };
}

type ScoreAuditSeedOverrides = {
  model?: string;
  prompt?: number;
  explanationSchema?: number;
  schemaOnlyPayloads?: boolean;
  status?: 'eligible' | 'skip-cve' | 'skip-hotfix' | 'wait';
  score?: number | null;
  recommended?: boolean;
  expectAuditContractFailure?: boolean;
  mutateDecision?: (
    components: Record<string, unknown>,
    explanation: Record<string, unknown>,
  ) => void;
  rebindExplanationAuditAfterDecisionMutation?: boolean;
  mutateAuditPayloads?: (payloads: ScoreAuditPayloads) => void;
  mutateHistorySourceIdentity?: (identity: any) => void;
  sourceIdentityOptions?: ScoreSourceIdentityOptions;
  sealHistory?: boolean;
};

function seedScoreAuditState(overrides: ScoreAuditSeedOverrides = {}) {
  const status = overrides.status ?? 'eligible';
  const score = overrides.score === undefined ? 7.5 : overrides.score;
  const recommended = overrides.recommended ?? status === 'eligible';
  const band = status === 'wait' ? 'wait' : status.startsWith('skip-') ? 'skip' : 'ok';
  const scoredAt = '2026-06-02T00:00:00.000Z';
  const scoreReason = 'test score';
  const selectedTag = recommended
    ? 'v2026.6.1'
    : status === 'eligible'
      ? 'v2026.6.0'
      : null;
  const selectedScore = recommended
    ? score
    : status === 'eligible' && score != null
      ? score + RECOMMENDATION_RECENCY_TOLERANCE
      : null;
  const highestScoringTag = selectedTag;
  const highestScore = selectedScore;
  const qualifies = status === 'eligible' && score != null && score >= REC_THRESHOLD;
  const recommendationDecision: RecommendationDecisionContract = {
    schemaVersion: 1,
    policyCode: 'highest_confidence_with_recency_tolerance',
    threshold: REC_THRESHOLD,
    recencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
    selectedTag,
    selectedScore,
    highestScoringTag,
    highestScore,
    releaseTag: 'v2026.6.1',
    releaseScore: score,
    qualifies,
    selected: recommended,
    recencyRank: 1,
    scoreRank: status === 'eligible' ? 1 : null,
    scoreDeltaToHighest: score != null && highestScore != null
      ? Math.round((highestScore - score) * 1000) / 1000
      : null,
    decisionCode: status !== 'eligible'
      ? 'install_gate_active'
      : !qualifies
        ? 'below_recommendation_threshold'
        : recommended
          ? 'highest_confidence'
          : 'higher_confidence_release_selected',
    summary: '',
  };
  recommendationDecision.summary = recommendationDecisionSummary(recommendationDecision);
  const componentsRecommendationDecision = structuredClone(recommendationDecision) as unknown as Record<string, unknown>;
  const explanationRecommendationDecision = structuredClone(recommendationDecision) as unknown as Record<string, unknown>;
  const explanation = {
    schemaVersion: overrides.explanationSchema ?? scoringVersions.explanation,
    title: 'Why not 10?',
    scoreLedger: {
      schemaVersion: 1,
      finalScore: score,
      status,
      band,
      subtotalBeforeCaps: score,
      scoreAfterCaps: score,
      rows: [],
      caps: [],
    },
    positives: [],
    positiveDetails: [],
    limits: [],
    limitDetails: [],
    authorityReferences: [],
    verdict: explanationRecommendationDecision.summary,
    recommendationDecision: explanationRecommendationDecision,
  };
  const predecessorTag = 'v2026.5.31';
  const targetReachability = {
    tag: 'v2026.6.1',
    status: 'reachable',
    tagCommitOid: 'a'.repeat(40),
    checkedCommitOid: 'b'.repeat(40),
    baseRefName: 'main',
    method: 'git-merge-base',
    checkedAt: '2026-06-06T00:00:00Z',
    evidenceReason: 'merge_commit_in_release_history',
    strictValid: true,
    validationReasonCode: null,
  };
  const predecessorReachability = {
    tag: predecessorTag,
    status: 'not_reachable',
    tagCommitOid: 'c'.repeat(40),
    checkedCommitOid: 'b'.repeat(40),
    baseRefName: 'main',
    method: 'git-merge-base',
    checkedAt: '2026-06-06T00:00:00Z',
    evidenceReason: 'not_reachable_from_release_tag',
    strictValid: true,
    validationReasonCode: null,
  };
  const persistedFixCreditDecision = {
    schemaVersion: 1,
    issueNumber: 103,
    status: 'credited',
    reasonCode: 'first_containing_trusted_pr',
    targetTag: 'v2026.6.1',
    predecessorTag,
    proofIdentities: [{
      kind: 'trusted_pull_request',
      repositoryNameWithOwner: 'openclaw/openclaw',
      prNumber: 501,
      sources: ['closedByPullRequestsReferences'],
      merged: true,
      mergeCommitOid: 'b'.repeat(40),
      baseRefName: 'main',
      target: targetReachability,
      predecessor: predecessorReachability,
    }],
  };
  const payloads: ScoreAuditPayloads = {
    input: {
      schemaVersion: scoringVersions.input,
      publishedAt: status === 'wait'
        ? '2026-06-01T12:00:00Z'
        : '2026-06-01T00:00:00Z',
      isLatest: status !== 'skip-hotfix',
      hoursToNextStable: null,
      hasHotfixSuccessor: status === 'skip-hotfix',
      betaCount: 0,
      breakingCount: 0,
      feltOpenedWeight: 0,
      feltClosedWeight: 0,
      verifiedDebtWeight: 0,
      carryoverDebtWeight: 0,
      staleDebtWeight: 0,
      verifiedDebtIssueCount: 0,
      carryoverDebtIssueCount: 0,
      staleDebtIssueCount: 0,
      unresolvedClosureRiskWeight: 0,
      affirmativeClosureRiskCeilingWeight: 0,
      unresolvedClosureIssueCount: 0,
      rawIssueCount: 5,
      classifiedIssueCount: 5,
      cveAffected: status === 'skip-cve',
      cveLoad: status === 'skip-cve' ? 1 : 0,
      releaseCheckState: null,
      releaseCheckTotal: 0,
      releaseCheckSuccess: 0,
      releaseCheckFailure: 0,
      releaseCheckPending: 0,
      artifactVerified: false,
      artifactMismatch: null,
      ciReportVerified: false,
      ciReportMismatch: null,
      releaseIntegrityPresent: false,
    },
    components: {
      schemaVersion: scoringVersions.components,
      components: null,
      evidenceCoverage: 1,
      hotfix: status === 'skip-hotfix',
      reason: scoreReason,
      explanation,
      recommendationDecision: componentsRecommendationDecision,
    },
    issueEvidence: {
      schemaVersion: scoringVersions.issueEvidence,
      evidenceCounts: {
        verifiedDebt: 0,
        carryoverDebt: 0,
        staleDebt: 0,
        openedFeltSerious: 0,
        verifiedFixed: 0,
        unverifiedClosed: 0,
        unclassifiedIssues: 0,
        targetEvidenceAttribution: 0,
      },
      targetEvidenceAttribution: [],
      debtSummary: {
        verified: debtTierSummary(),
        carryover: debtTierSummary(),
        stale: debtTierSummary(),
      },
      verifiedDebt: [],
      carryoverDebt: [],
      staleDebt: [],
      openedFeltSerious: [],
      verifiedFixed: [],
      unverifiedClosed: [],
      unclassifiedIssues: [],
    },
    gateEvidence: {
      schemaVersion: scoringVersions.gateEvidence,
      cve: {
        affected: status === 'skip-cve',
        load: status === 'skip-cve' ? 1 : 0,
      },
      stableTagsNewestFirst: ['v2026.6.1', predecessorTag],
      betaCount: 0,
      breakingCount: 0,
      hoursToNextStable: null,
      hasHotfixSuccessor: status === 'skip-hotfix',
      releaseChecks: {
        schemaVersion: 2,
        state: null,
        total: 0,
        success: 0,
        failure: 0,
        pending: 0,
        skipped: 0,
        contextCount: 0,
        shownContextCount: 0,
        contextsTruncated: false,
        contexts: [],
      },
      artifactVerification: {
        schemaVersion: 2,
        observationId: null,
        receiptId: null,
        evidenceIdentity: null,
        evidenceReportIdentity: null,
        runId: null,
        observedAt: null,
        observationContentHash: null,
        observationPreviousContentHash: null,
        receiptContentHash: null,
        receiptPreviousContentHash: null,
        release: null,
        releaseMetadata: null,
        artifact: null,
        evidenceReport: null,
        npmPackageUrl: null,
        releaseTarballUrl: null,
        releaseIntegrity: null,
        releaseSha: null,
        releaseShaMatches: null,
        ciReportUrl: null,
        ciReportVerified: false,
        ciReportMismatch: null,
        fullReleaseValidationUrl: null,
        releaseValidationVerified: false,
        releaseValidationMismatch: null,
        registryVersion: null,
        registryIntegrity: null,
        registryTarballUrl: null,
        verified: false,
        mismatch: null,
      },
      labelTimeline: {
        schemaVersion: 1,
        cutoffAt: null,
        issueCount: 0,
        currentLabelCount: 0,
        timelineLabelCount: 0,
        snapshotLabelCount: 0,
        missingTimelineCount: 0,
        missingTimelineWithCurrentLabelsCount: 0,
        historicalCurrentLabelFallbackAllowed: true,
      },
      fixProvenance: {
        verifiedFixedCount: 1,
        creditedFixedCount: 1,
        unverifiedClosedCount: 0,
        predecessorBoundary: {
          schemaVersion: 1,
          oldestScoredStableTag: 'v2026.6.1',
          oldestScoredStablePredecessorTag: predecessorTag,
          targetTag: 'v2026.6.1',
          predecessorTag,
        },
        closureProof: {
          schemaVersion: 1,
          creditedCount: 1,
          notCreditedCount: 0,
          analyzedClosedCount: 1,
          containedFixedCount: 1,
          containedNotCreditedCount: 0,
          targetTag: 'v2026.6.1',
          predecessorTag,
          fixCreditDecisionCounts: { credited: 1, withheld: 0, invalid: 0 },
          fixCreditDecisions: [structuredClone(persistedFixCreditDecision)],
          byStatus: { fixed_in_release: 1 },
          byRiskDisposition: { credited_release_fix: 1 },
          riskSummary: closureRiskSummary(),
          neutralAuditExamples: [],
          examplesByStatus: {},
          examples: [],
        },
        releaseFixCredit: {
          schemaVersion: 1,
          targetTag: 'v2026.6.1',
          predecessorTag,
          countedClosedCount: 1,
          notCountedClosedCount: 0,
          analyzedClosedCount: 1,
          containedFixedCount: 1,
          containedNotCreditedCount: 0,
          decisionCounts: { credited: 1, withheld: 0, invalid: 0 },
          decisions: [structuredClone(persistedFixCreditDecision)],
        },
      },
    },
  };
  const confidence = installConfidence(payloads.input, Date.parse(scoredAt));
  assert.deepEqual(
    {
      score: confidence.score,
      status: confidence.status,
      band: confidence.band,
    },
    { score, status, band },
  );
  payloads.components.components = confidence.components;
  payloads.components.evidenceCoverage = confidence.evidenceCoverage;
  payloads.components.hotfix = confidence.hotfix;
  const scoreLedger = buildScoreLedgerV2({
    input: payloads.input,
    confidence,
    now: Date.parse(scoredAt),
    evidenceSources: status === 'skip-cve'
      ? [{
          key: 'advisories',
          refs: [{
            kind: 'github_advisory',
            identity: 'GHSA-api-route-fixture',
            payload: {
              ghsaId: 'GHSA-api-route-fixture',
              severity: 'high',
              vulnerableRange: '<=2026.6.1',
            },
          }],
        }]
      : undefined,
  });
  payloads.components.explanation.scoreLedger = structuredClone(
    payloads.components.explanation.schemaVersion === scoringVersions.explanation
      ? bindScoreExplanationAudit(scoreLedger, payloads.components.explanation)
      : scoreLedger,
  );
  overrides.mutateDecision?.(
    payloads.components.recommendationDecision,
    payloads.components.explanation.recommendationDecision,
  );
  if (overrides.rebindExplanationAuditAfterDecisionMutation) {
    payloads.components.explanation.scoreLedger = structuredClone(
      bindScoreExplanationAudit(
        payloads.components.explanation.scoreLedger,
        payloads.components.explanation,
      ),
    );
  }
  if (overrides.schemaOnlyPayloads) {
    payloads.input = { schemaVersion: scoringVersions.input };
    payloads.components = { schemaVersion: scoringVersions.components };
    payloads.issueEvidence = { schemaVersion: scoringVersions.issueEvidence };
    payloads.gateEvidence = { schemaVersion: scoringVersions.gateEvidence };
  }
  overrides.mutateAuditPayloads?.(payloads);
  const contractFailures = verifyScoreAuditPayloadContracts({
    tag: 'v2026.6.1',
    scoredAt,
    input: payloads.input,
    components: payloads.components,
    issueEvidence: payloads.issueEvidence,
    gateEvidence: payloads.gateEvidence,
    versions: {
      scoreInput: scoringVersions.input,
      scoreComponents: scoringVersions.components,
      issueEvidence: scoringVersions.issueEvidence,
      gateEvidence: scoringVersions.gateEvidence,
    },
  });
  if (overrides.expectAuditContractFailure) {
    assert.ok(contractFailures.length > 0, 'expected an intentionally invalid audit fixture');
  } else {
    assert.deepEqual(contractFailures, [], contractFailures.join('\n'));
  }
  const sourceIdentity = dbModule.scoreSourceIdentity(
    overrides.sourceIdentityOptions,
  );

  dbModule.updateReleaseScore({
    tag: 'v2026.6.1',
    final_score: score,
    negative_issues: 2,
    positive_issues: 1,
    state: status,
    recommended: recommended ? 1 : 0,
    score_reason: scoreReason,
    broken_surfaces: '[]',
    closed_serious_fixed: 1,
    opened_serious_during_reign: 1,
    scored_at: scoredAt,
  });
  const auditInput = {
    release_tag: 'v2026.6.1',
    scored_at: scoredAt,
    score_model_version: overrides.model ?? scoringVersions.model,
    prompt_version: overrides.prompt ?? scoringVersions.prompt,
    final_score: score,
    status,
    band,
    recommended: recommended ? 1 : 0,
    input_json: JSON.stringify(payloads.input),
    components_json: JSON.stringify(payloads.components),
    issue_evidence_json: JSON.stringify(payloads.issueEvidence),
    gate_evidence_json: JSON.stringify(payloads.gateEvidence),
    source_identity_json: JSON.stringify(sourceIdentity),
  };
  let historyRunId: string | null = null;
  let historyRunContentHash: string | null = null;
  let authorityRunId: string | null = null;
  let authorityRunContentHash: string | null = null;
  let historyV2SealContentHash: string | null = null;
  if (overrides.sealHistory !== false) {
    historyRunId = `api-test:${++scoreAuditRunSequence}`;
    const historySourceIdentity = structuredClone(sourceIdentity);
    overrides.mutateHistorySourceIdentity?.(historySourceIdentity);
    const authorityRun = insertEmptyScoreAuthorityRun(
      historyRunId,
      scoredAt,
      historySourceIdentity,
      overrides.sourceIdentityOptions,
    );
    authorityRunId = authorityRun.authorityRunId;
    authorityRunContentHash = authorityRun.contentHash;
    const authorityBoundAudit = {
      ...auditInput,
      authority_run_id: authorityRunId,
    };
    dbModule.upsertReleaseScoreAudit(authorityBoundAudit);
    dbModule.db.prepare(`
      INSERT INTO release_score_audit_history (
        run_id, recorded_at, release_tag, scored_at, score_model_version,
        prompt_version, final_score, status, band, recommended, input_json,
        components_json, issue_evidence_json, gate_evidence_json,
        source_identity_json, authority_run_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      historyRunId,
      scoredAt,
      auditInput.release_tag,
      auditInput.scored_at,
      auditInput.score_model_version,
      auditInput.prompt_version,
      auditInput.final_score,
      auditInput.status,
      auditInput.band,
      auditInput.recommended,
      auditInput.input_json,
      auditInput.components_json,
      auditInput.issue_evidence_json,
      auditInput.gate_evidence_json,
      JSON.stringify(historySourceIdentity),
      authorityRunId,
    );
    const seal = dbModule.sealReleaseScoreAuditHistoryRun(historyRunId, scoredAt);
    historyRunContentHash = seal.row.content_hash;
    const historyV2Seal = dbModule.sealReleaseScoreAuditHistoryV2({
      historyRunId,
      authorityRunId,
      sealedAt: scoredAt,
    });
    historyV2SealContentHash = historyV2Seal.row.contentHash;
    dbModule.setMeta('score_persistence_last_run', JSON.stringify({
      schemaVersion: 2,
      source: 'api-test',
      persistedAt: scoredAt,
      scoreModelVersion: auditInput.score_model_version,
      promptVersion: auditInput.prompt_version,
      scoredReleaseCount: 1,
      recommendedTag: recommended ? auditInput.release_tag : null,
      releaseTags: [auditInput.release_tag],
      minScoredAt: scoredAt,
      maxScoredAt: scoredAt,
      sourceIdentitySchemaVersion: historySourceIdentity.schemaVersion,
      sourceIdentityDigest: historySourceIdentity.digest,
      sourceIdentityRowCount: historySourceIdentity.rowCount,
      sourceIdentitySourceCount: historySourceIdentity.sourceCount,
      historyRunId,
      historyRunContentHash,
      authorityRunId,
      authorityRunContentHash,
      historyV2SealContentHash,
      commitTiming: {
        schemaVersion: 4,
        historyRunId,
        historyRunContentHash,
        authorityRunId,
        authorityRunContentHash,
        historyV2SealContentHash,
        historyRecordedAt: scoredAt,
        commitNotBefore: scoredAt,
        commitNotAfter: scoredAt,
        commitNotBeforeMs: Date.parse(scoredAt),
        commitNotAfterMs: Date.parse(scoredAt),
      },
    }));
  } else {
    dbModule.upsertReleaseScoreAudit(auditInput);
  }
  return {
    ...payloads,
    persistedFixCreditDecision,
    historyRunId,
    historyRunContentHash,
    authorityRunId,
    authorityRunContentHash,
    historyV2SealContentHash,
  };
}

function sealCurrentAuditRun(tags: string[], recommendedTag: string | null, persistedAt: string) {
  const audits = tags.map((tag) => {
    const audit = dbModule.getReleaseScoreAudit(tag);
    if (!audit) throw new Error(`missing test score audit for ${tag}`);
    return audit;
  });
  const runId = `api-test:${++scoreAuditRunSequence}`;
  const recordedAt = new Date(Date.now() + 1).toISOString();
  const sourceIdentity = JSON.parse(audits[0].source_identity_json ?? 'null');
  const authorityRun = insertEmptyScoreAuthorityRun(
    runId,
    recordedAt,
    sourceIdentity,
  );
  const insertHistory = dbModule.db.prepare(`
    INSERT INTO release_score_audit_history (
      run_id, recorded_at, release_tag, scored_at, score_model_version,
      prompt_version, final_score, status, band, recommended, input_json,
      components_json, issue_evidence_json, gate_evidence_json,
      source_identity_json, authority_run_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const audit of audits) {
    dbModule.upsertReleaseScoreAudit({
      ...audit,
      authority_run_id: authorityRun.authorityRunId,
    });
    insertHistory.run(
      runId,
      recordedAt,
      audit.release_tag,
      audit.scored_at,
      audit.score_model_version,
      audit.prompt_version,
      audit.final_score,
      audit.status,
      audit.band,
      audit.recommended,
      audit.input_json,
      audit.components_json,
      audit.issue_evidence_json,
      audit.gate_evidence_json,
      audit.source_identity_json,
      authorityRun.authorityRunId,
    );
  }
  const seal = dbModule.sealReleaseScoreAuditHistoryRun(runId, recordedAt);
  const historyV2Seal = dbModule.sealReleaseScoreAuditHistoryV2({
    historyRunId: runId,
    authorityRunId: authorityRun.authorityRunId,
    sealedAt: recordedAt,
  });
  dbModule.setMeta('score_persistence_last_run', JSON.stringify({
    schemaVersion: 2,
    source: 'api-test',
    persistedAt,
    scoreModelVersion: audits[0].score_model_version,
    promptVersion: audits[0].prompt_version,
    scoredReleaseCount: tags.length,
    recommendedTag,
    releaseTags: tags,
    minScoredAt: audits.reduce(
      (minimum, audit) => audit.scored_at < minimum ? audit.scored_at : minimum,
      audits[0].scored_at,
    ),
    maxScoredAt: audits.reduce(
      (maximum, audit) => audit.scored_at > maximum ? audit.scored_at : maximum,
      audits[0].scored_at,
    ),
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    sourceIdentityRowCount: sourceIdentity.rowCount,
    sourceIdentitySourceCount: sourceIdentity.sourceCount,
    historyRunId: runId,
    historyRunContentHash: seal.row.content_hash,
    authorityRunId: authorityRun.authorityRunId,
    authorityRunContentHash: authorityRun.contentHash,
    historyV2SealContentHash: historyV2Seal.row.contentHash,
    commitTiming: {
      schemaVersion: 4,
      historyRunId: runId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
      historyRecordedAt: recordedAt,
      commitNotBefore: recordedAt,
      commitNotAfter: recordedAt,
      commitNotBeforeMs: Date.parse(recordedAt),
      commitNotAfterMs: Date.parse(recordedAt),
    },
  }));
}

function clearRefreshMeta() {
  dbModule.db.prepare(`
    DELETE FROM meta
    WHERE key IN ('issue_crawl_last_run', 'score_persistence_last_run')
  `).run();
}

function seedOperationReceipt(input: {
  runId: string;
  status: 'success' | 'failure' | 'abandoned';
  startedAt: string;
  finishedAt: string;
  stages?: Array<{
    stage: string;
    status: 'started' | 'completed' | 'failed';
    occurredAt: string;
    durationMs?: number;
    counts?: Record<string, unknown>;
    details?: Record<string, unknown>;
  }>;
  payload: Record<string, unknown>;
}) {
  const leaseName = `github-refresh-${input.runId}`;
  const attemptHolderId = `holder-${input.runId}`;
  const receiptHolderId = input.status === 'abandoned'
    ? `successor-${input.runId}`
    : attemptHolderId;
  const attemptLeaseExpiresAt = input.status === 'abandoned'
    ? new Date(Date.now() - 1_000).toISOString()
    : new Date(Date.parse(input.startedAt) + 300_000).toISOString();
  dbModule.insertRefreshOperationAttempt({
    run_id: input.runId,
    operation: 'refresh',
    trigger: 'api-test',
    started_at: input.startedAt,
    lease_name: leaseName,
    lease_holder_id: attemptHolderId,
    lease_expires_at: attemptLeaseExpiresAt,
    code_revision: `revision-${input.runId}`,
    effective_config: {
      schemaVersion: 1,
      apiKey: `config-${input.runId}-secret`,
    },
  });
  assert.equal(
    dbModule.acquireRefreshLease(
      leaseName,
      receiptHolderId,
      new Date().toISOString(),
      300_000,
    ),
    true,
  );
  for (const [index, stage] of (input.stages ?? []).entries()) {
    dbModule.appendRefreshOperationStageEvent({
      event_id: `event-${input.runId}-${index + 1}`,
      run_id: input.runId,
      lease_name: leaseName,
      lease_holder_id: attemptHolderId,
      stage: stage.stage,
      status: stage.status,
      occurred_at: stage.occurredAt,
      duration_ms: stage.durationMs,
      counts: stage.counts,
      details: stage.details,
    });
  }
  try {
    return dbModule.appendRefreshCaptureReceipt({
      run_id: input.runId,
      lease_name: leaseName,
      lease_holder_id: receiptHolderId,
      status: input.status,
      finished_at: input.finishedAt,
      duration_ms: Date.parse(input.finishedAt) - Date.parse(input.startedAt),
      payload: input.payload,
    }).row;
  } finally {
    dbModule.releaseRefreshLease(leaseName, receiptHolderId);
  }
}

function seedReceiptHistoryRun(
  runId: string,
  recordedAt: string,
  releaseTag: string,
  scoredAt = recordedAt,
) {
  const sourceIdentity = dbModule.scoreSourceIdentity();
  const authorityRun = insertEmptyScoreAuthorityRun(
    runId,
    recordedAt,
    sourceIdentity,
  );
  dbModule.db.prepare(`
    INSERT INTO release_score_audit_history (
      run_id, recorded_at, release_tag, scored_at, score_model_version,
      prompt_version, final_score, status, band, recommended, input_json,
      components_json, issue_evidence_json, gate_evidence_json,
      source_identity_json, authority_run_id
    )
    VALUES (?, ?, ?, ?, 'receipt-model', 1, 8, 'eligible', 'good', 1,
      '{}', '{}', '{}', '{}', ?, ?)
  `).run(
    runId,
    recordedAt,
    releaseTag,
    scoredAt,
    JSON.stringify(sourceIdentity),
    authorityRun.authorityRunId,
  );
  const historySeal =
    dbModule.sealReleaseScoreAuditHistoryRun(runId, recordedAt).row;
  const historyV2Seal = dbModule.sealReleaseScoreAuditHistoryV2({
    historyRunId: runId,
    authorityRunId: authorityRun.authorityRunId,
    sealedAt: recordedAt,
  }).row;
  return {
    historyRunContentHash: historySeal.content_hash,
    authorityRunId: authorityRun.authorityRunId,
    authorityRunContentHash: authorityRun.contentHash,
    historyV2SealContentHash: historyV2Seal.contentHash,
  };
}

function seedExistingCaptureReceiptFixture(
  suffix: string,
  options: { crossRunAlias?: boolean } = {},
) {
  const originalHistoryRunId = `receipt-original-${suffix}`;
  const currentHistoryRunId = `receipt-current-${suffix}`;
  const scoredAt = '2026-07-04T07:30:00.000Z';
  const originalRecordedAt = '2026-07-04T08:00:00.000Z';
  const currentRecordedAt = '2026-07-04T10:00:02.000Z';
  const originalPublication = seedReceiptHistoryRun(
    originalHistoryRunId,
    originalRecordedAt,
    'v-existing-capture',
    scoredAt,
  );
  const currentPublication = seedReceiptHistoryRun(
    currentHistoryRunId,
    currentRecordedAt,
    'v-existing-capture',
    scoredAt,
  );
  const originalHistory = dbModule.listReleaseScoreAuditHistoryForRun(
    originalHistoryRunId,
  )[0] as any;
  const recommendationDecision = {
    selectedTag: originalHistory.release_tag,
    policyCode: 'highest_confidence_with_recency_tolerance',
  };
  const forecast: any = {
    opportunity_code: 'first_verified_after_3h',
    recorded_at: originalRecordedAt,
    latest_release_tag: originalHistory.release_tag,
    latest_release_published_at: '2026-07-04T04:00:00.000Z',
    selected_tag: originalHistory.release_tag,
    audit_history_run_id: originalHistoryRunId,
    score_model_version: originalHistory.score_model_version,
    prompt_version: originalHistory.prompt_version,
    policy_code: recommendationDecision.policyCode,
    candidate_scores_json: JSON.stringify([{
      releaseTag: originalHistory.release_tag,
      auditSnapshot: {
        ...originalHistory,
        run_id: options.crossRunAlias
          ? currentHistoryRunId
          : originalHistoryRunId,
      },
      scoreSnapshot: {
        scoredAt: originalHistory.scored_at,
        finalScore: originalHistory.final_score,
        status: originalHistory.status,
        band: originalHistory.band,
        recommended: true,
      },
    }]),
    decision_json: JSON.stringify({
      schemaVersion: 2,
      opportunityCode: 'first_verified_after_3h',
      recordedAt: originalRecordedAt,
      latestReleaseTag: originalHistory.release_tag,
      latestReleasePublishedAt: '2026-07-04T04:00:00.000Z',
      selectedTag: originalHistory.release_tag,
      recommendationDecision,
    }),
    source_identity_json: originalHistory.source_identity_json,
    code_revision: 'receipt-api-test-revision',
    previous_content_hash: null,
    content_hash: '',
    decision_id: '',
  };
  forecast.content_hash = releaseValidationForecastContentHash(forecast);
  forecast.decision_id = releaseValidationDecisionId(
    forecast,
    forecast.content_hash,
  );
  dbModule.db.prepare(`
    INSERT INTO release_validation_forecasts (
      decision_id, opportunity_code, recorded_at, latest_release_tag,
      latest_release_published_at, selected_tag, audit_history_run_id,
      score_model_version, prompt_version, policy_code,
      candidate_scores_json, decision_json, source_identity_json,
      code_revision, previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    forecast.decision_id,
    forecast.opportunity_code,
    forecast.recorded_at,
    forecast.latest_release_tag,
    forecast.latest_release_published_at,
    forecast.selected_tag,
    forecast.audit_history_run_id,
    forecast.score_model_version,
    forecast.prompt_version,
    forecast.policy_code,
    forecast.candidate_scores_json,
    forecast.decision_json,
    forecast.source_identity_json,
    forecast.code_revision,
    forecast.previous_content_hash,
    forecast.content_hash,
  );
  const scoreCommit = {
    schemaVersion: 4,
    historyRunId: currentHistoryRunId,
    historyRunContentHash: currentPublication.historyRunContentHash,
    authorityRunId: currentPublication.authorityRunId,
    authorityRunContentHash: currentPublication.authorityRunContentHash,
    historyV2SealContentHash: currentPublication.historyV2SealContentHash,
    historyRecordedAt: currentRecordedAt,
    commitNotBefore: '2026-07-04T10:00:01.500Z',
    commitNotAfter: currentRecordedAt,
    commitNotBeforeMs: Date.parse('2026-07-04T10:00:01.500Z'),
    commitNotAfterMs: Date.parse(currentRecordedAt),
  };
  const receipt = seedOperationReceipt({
    runId: `receipt-existing-${suffix}`,
    status: 'success',
    startedAt: '2026-07-04T10:00:00.000Z',
    finishedAt: '2026-07-04T10:00:04.000Z',
    stages: [
      {
        stage: 'score.persist',
        status: 'started',
        occurredAt: '2026-07-04T10:00:01.000Z',
      },
      {
        stage: 'score.persist',
        status: 'completed',
        occurredAt: currentRecordedAt,
        durationMs: 1_000,
        counts: { scoredReleases: 1 },
        details: {
          historyRunId: currentHistoryRunId,
          historyRunContentHash: currentPublication.historyRunContentHash,
          ...scoreCommit,
        },
      },
      {
        stage: 'forecast.capture',
        status: 'started',
        occurredAt: '2026-07-04T10:00:03.000Z',
      },
      {
        stage: 'forecast.capture',
        status: 'completed',
        occurredAt: '2026-07-04T10:00:04.000Z',
        durationMs: 1_000,
        counts: { validationForecasts: 1 },
        details: { eligibilityOutcome: 'already_captured' },
      },
    ],
    payload: {
      schemaVersion: 1,
      operation: 'refresh',
      trigger: 'api-test',
      scoreHistory: {
        runId: currentHistoryRunId,
        contentHash: currentPublication.historyRunContentHash,
      },
      scoreAuthority: {
        runId: currentPublication.authorityRunId,
        contentHash: currentPublication.authorityRunContentHash,
        historyV2SealContentHash: currentPublication.historyV2SealContentHash,
      },
      scoreCommit,
      releaseTags: ['v-existing-capture'],
      forecast: {
        eligibilityOutcome: 'already_captured',
        decisionIds: [forecast.decision_id],
        newDecisionIds: [],
        existingDecisionIds: [forecast.decision_id],
        captures: [{
          decisionId: forecast.decision_id,
          status: 'already_captured',
        }],
      },
    },
  });
  return {
    receipt,
    decisionId: forecast.decision_id as string,
    originalHistoryRunId,
    currentHistoryRunId,
    originalAuthorityRunId: originalPublication.authorityRunId,
    currentAuthorityRunId: currentPublication.authorityRunId,
  };
}

function removeExistingCaptureReceiptFixture(
  fixture: ReturnType<typeof seedExistingCaptureReceiptFixture>,
): void {
  removeOperationReceiptFixture(fixture.receipt.run_id);
  removeReceiptForecastFixture(fixture.decisionId);
  removeReceiptHistoryRunFixture(fixture.currentHistoryRunId);
  removeReceiptHistoryRunFixture(fixture.originalHistoryRunId);
}

function removeReceiptForecastFixture(decisionId: string): void {
  mutateAppendOnlyTables(['release_validation_forecasts'], () => {
    dbModule.db.prepare(`
      DELETE FROM release_validation_forecasts WHERE decision_id=?
    `).run(decisionId);
  });
}

function deleteReceiptHistorySealFixture(runId: string): void {
  mutateAppendOnlyTables([
    'release_score_audit_history_v2_seals',
    'release_score_audit_history_runs',
  ], () => {
    dbModule.db.prepare(`
      DELETE FROM release_score_audit_history_v2_seals WHERE history_run_id=?
    `).run(runId);
    dbModule.db.prepare(`
      DELETE FROM release_score_audit_history_runs WHERE run_id=?
    `).run(runId);
  });
}

function mutateReceiptHistoryRowFixture(runId: string, action: () => void): void {
  void runId;
  mutateAppendOnlyTables(['release_score_audit_history'], action);
}

function mutateAppendOnlyTables(tableNames: string[], action: () => void): void {
  const triggers = dbModule.db.prepare(`
    SELECT name, sql
    FROM sqlite_master
    WHERE type='trigger'
      AND tbl_name IN (${tableNames.map(() => '?').join(', ')})
    ORDER BY name
  `).all(...tableNames) as Array<{ name: string; sql: string }>;
  dbModule.db.exec('BEGIN');
  try {
    for (const trigger of triggers) {
      dbModule.db.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
    }
    action();
    for (const trigger of triggers) dbModule.db.exec(trigger.sql);
    dbModule.db.exec('COMMIT');
  } catch (error) {
    dbModule.db.exec('ROLLBACK');
    throw error;
  }
}

function removeOperationReceiptFixture(runId: string): void {
  const tables = [
    'refresh_capture_receipts',
    'refresh_operation_stage_events',
    'refresh_operation_attempts',
  ];
  const triggers = dbModule.db.prepare(`
    SELECT name, sql
    FROM sqlite_master
    WHERE type='trigger'
      AND tbl_name IN (${tables.map(() => '?').join(', ')})
    ORDER BY name
  `).all(...tables) as Array<{ name: string; sql: string }>;
  dbModule.db.exec('BEGIN');
  try {
    for (const trigger of triggers) {
      dbModule.db.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
    }
    dbModule.db.prepare(`DELETE FROM refresh_capture_receipts WHERE run_id=?`).run(runId);
    dbModule.db.prepare(`DELETE FROM refresh_operation_stage_events WHERE run_id=?`).run(runId);
    dbModule.db.prepare(`DELETE FROM refresh_operation_attempts WHERE run_id=?`).run(runId);
    for (const trigger of triggers) dbModule.db.exec(trigger.sql);
    dbModule.db.exec('COMMIT');
  } catch (error) {
    dbModule.db.exec('ROLLBACK');
    throw error;
  }
}

function removeReceiptHistoryRunFixture(runId: string): void {
  const link = dbModule.db.prepare(`
    SELECT authority_run_id
    FROM release_score_audit_history_v2_seals
    WHERE history_run_id=?
  `).get(runId) as { authority_run_id?: string } | undefined;
  const tables = [
    'release_score_audit_history_v2_seals',
    'release_score_audit_history',
    'release_score_audit_history_runs',
    'score_authority_resolution_rows',
    'score_authority_resolution_runs',
  ];
  const triggers = dbModule.db.prepare(`
    SELECT name, sql
    FROM sqlite_master
    WHERE type='trigger'
      AND tbl_name IN (${tables.map(() => '?').join(', ')})
    ORDER BY name
  `).all(...tables) as Array<{ name: string; sql: string }>;
  dbModule.db.exec('BEGIN');
  try {
    for (const trigger of triggers) {
      dbModule.db.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
    }
    dbModule.db.prepare(`
      DELETE FROM release_score_audit_history_v2_seals WHERE history_run_id=?
    `).run(runId);
    dbModule.db.prepare(`
      DELETE FROM release_score_audit_history WHERE run_id=?
    `).run(runId);
    dbModule.db.prepare(`
      DELETE FROM release_score_audit_history_runs WHERE run_id=?
    `).run(runId);
    if (link?.authority_run_id) {
      dbModule.db.prepare(`
        DELETE FROM score_authority_resolution_rows WHERE authority_run_id=?
      `).run(link.authority_run_id);
      dbModule.db.prepare(`
        DELETE FROM score_authority_resolution_runs WHERE authority_run_id=?
      `).run(link.authority_run_id);
    }
    for (const trigger of triggers) dbModule.db.exec(trigger.sql);
    dbModule.db.exec('COMMIT');
  } catch (error) {
    dbModule.db.exec('ROLLBACK');
    throw error;
  }
}

function insertEmptyScoreAuthorityRun(
  historyRunId: string,
  recordedAt: string,
  sourceIdentity: { schemaVersion: number; digest: string },
  sourceIdentityOptions?: ScoreSourceIdentityOptions,
) {
  const previousAuthorityRun =
    dbModule.listScoreAuthorityResolutionRuns().at(-1) ?? null;
  const authorityRun = buildScoreAuthorityResolutionRun({
    authorityRunId: `score-authority:${historyRunId}`,
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    recordedAt,
    previousContentHash: previousAuthorityRun?.contentHash ?? null,
    rows: [],
  });
  return dbModule.insertScoreAuthorityResolutionRun(
    authorityRun,
    sourceIdentityOptions ? { sourceIdentityOptions } : {},
  ).row;
}

function clearScoreAuditState() {
  dbModule.db.prepare(`DELETE FROM release_score_audits WHERE release_tag='v2026.6.1'`).run();
  dbModule.db.prepare(`DELETE FROM meta WHERE key='score_persistence_last_run'`).run();
  dbModule.db.prepare(`
    UPDATE releases
    SET final_score=NULL,
        negative_issues=NULL,
        positive_issues=NULL,
        scored_at=NULL,
        state=NULL,
        recommended=0,
        score_reason=NULL,
        broken_surfaces=NULL,
        closed_serious_fixed=0,
        opened_serious_during_reign=0
    WHERE tag='v2026.6.1'
  `).run();
}

async function assertScoreSurfacesFailClosed(
  label: string,
  expectedCause?: string,
  expectedRetainedPublic?: {
    snapshotId: string;
    release: any;
  },
) {
  const releases = await getJson('/api/releases');
  const release = releases.body.find((row: any) => row.tag === 'v2026.6.1');
  assert.equal(release.finalScore, null, label);
  assert.equal(release.band, 'wait', label);
  assert.equal(release.status, 'stale', label);
  assert.equal(release.diagnosticStatus, 'eligible', label);
  assert.equal(release.recommended, false, label);
  assert.equal(release.explanation, null, label);
  assert.equal(release.scoreAudit, null, label);
  assert.equal(release.scoredAt, null, label);
  assert.equal(release.negativeIssues, null, label);
  assert.equal(release.positiveIssues, null, label);
  assert.equal(release.closedSeriousFixed, null, label);
  assert.equal(release.openedSeriousDuringReign, null, label);
  assert.deepEqual(release.brokenSurfaces, [], label);
  assert.equal(release.staleAudit.state, 'stale', label);
  assert.equal(release.staleAudit.previousStatus, 'eligible', label);
  assert.ok(release.staleAudit.causes.length > 0, label);
  if (expectedCause) {
    assert.ok(release.staleAudit.causes.includes(expectedCause), label);
  }
  assert.match(release.reason, /^Analysis is stale\./, label);

  const publicPayload = await getJson('/api/public');
  const publicRelease = publicPayload.body.releases.find((row: any) => row.tag === 'v2026.6.1');
  assert.equal(publicRelease.score, null, label);
  assert.equal(publicRelease.status, 'stale', label);
  assert.equal(publicRelease.diagnosticStatus, 'eligible', label);
  assert.equal(publicRelease.recommended, false, label);
  assert.equal(publicRelease.explanation, null, label);
  assert.equal(publicRelease.scoreAudit, null, label);
  assert.equal(publicRelease.scoredAt, null, label);
  if (expectedRetainedPublic) {
    assert.equal(publicRelease.negativeIssues, expectedRetainedPublic.release.negativeIssues, label);
    assert.equal(publicRelease.positiveIssues, expectedRetainedPublic.release.positiveIssues, label);
    assert.equal(publicPayload.body.snapshot.id, expectedRetainedPublic.snapshotId, label);
    assert.equal(publicPayload.body.snapshot.source, 'retained', label);
    assert.equal(publicPayload.body.snapshot.retained, true, label);
    assert.equal(publicPayload.body.snapshot.stale, true, label);
    assert.equal(publicPayload.body.snapshot.actionable, false, label);
    assert.deepEqual(publicRelease.staleAudit.causes, ['public_payload_retained'], label);
  } else {
    assert.equal(publicPayload.body.snapshot.actionable, false, label);
    assert.equal(publicRelease.negativeIssues, null, label);
    assert.equal(publicRelease.positiveIssues, null, label);
    assert.deepEqual(publicRelease.staleAudit, release.staleAudit, label);
  }
  assert.match(publicRelease.reason, /^Analysis is stale\./, label);

  const review = await getJson('/api/releases/v2026.6.1/review');
  assert.equal(review.body.local.score, null, label);
  assert.equal(review.body.local.status, 'stale', label);
  assert.equal(review.body.local.diagnosticStatus, 'eligible', label);
  assert.equal(review.body.local.recommended, false, label);
  assert.match(review.body.local.reason, /^Analysis is stale\./, label);
  assert.deepEqual(review.body.local.staleAudit, release.staleAudit, label);
  assert.equal(review.body.local.scoredAt, null, label);
  assert.equal(review.body.local.negativeIssues, null, label);
  assert.equal(review.body.local.positiveIssues, null, label);
  assert.equal(review.body.local.sourceProvenance, null, label);
  assert.equal(review.body.local.auditDigest, null, label);
  assert.equal(review.body.local.modelVersion, null, label);
  assert.equal(review.body.local.promptVersion, null, label);
  assert.equal(review.body.local.input, null, label);
  assert.equal(review.body.local.components, null, label);
  assert.equal(review.body.local.issueEvidence, null, label);
  assert.equal(review.body.local.gateEvidence, null, label);

  const comparison = await getJson('/api/comparison');
  assert.equal(comparison.status, 200, `${label}: ${JSON.stringify(comparison.body)}`);
  const comparisonRelease = comparison.body.releases.find((row: any) => row.tag === 'v2026.6.1');
  assert.equal(comparisonRelease.local.score, null, label);
  assert.deepEqual(comparisonRelease.local.staleAudit, release.staleAudit, label);
  assert.equal(comparisonRelease.local.scoredAt, null, label);
  assert.equal(comparisonRelease.local.negativeIssues, null, label);
  assert.equal(comparisonRelease.local.positiveIssues, null, label);
  assert.equal(comparisonRelease.local.modelVersion, null, label);
  assert.equal(comparisonRelease.local.input, null, label);
  assert.equal(comparisonRelease.local.components, null, label);
  assert.equal(comparisonRelease.local.gateEvidence, null, label);

  const history = await getJson('/api/releases/history');
  const historyRelease = history.body.find((row: any) => row.tag === 'v2026.6.1');
  assert.equal(historyRelease.finalScore, null, label);
  assert.equal(historyRelease.status, 'stale', label);
  assert.equal(historyRelease.diagnosticStatus, 'eligible', label);
  assert.equal(historyRelease.recommended, false, label);
  assert.equal(historyRelease.scoreAudit, null, label);
  assert.equal(historyRelease.scoredAt, null, label);
  assert.deepEqual(historyRelease.staleAudit, release.staleAudit, label);
}

type TestCatalogRelease =
  Parameters<typeof dbModule.replaceActiveReleaseCatalog>[0][number];

function testCatalogRelease(
  tag: string,
  publishedAt: string,
  prerelease = false,
): TestCatalogRelease {
  return {
    node_id: `R_${tag.replace(/[^A-Za-z0-9]/g, '_')}`,
    catalog_tag_commit_oid: createHash('sha1').update(tag).digest('hex'),
    tag,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease,
    body: '',
  };
}

function primaryTestCatalogRelease(): TestCatalogRelease {
  return testCatalogRelease(
    PRIMARY_RELEASE_TAG,
    PRIMARY_RELEASE_PUBLISHED_AT,
  );
}

function replaceTestActiveCatalog(releases: TestCatalogRelease[]): void {
  dbModule.replaceActiveReleaseCatalog(releases, {
    capture: { source: 'test_fixture' },
  });
}

function restorePrimaryTestCatalog(): void {
  replaceTestActiveCatalog([primaryTestCatalogRelease()]);
}

function seedIssue(input: {
  number: number;
  state: 'open' | 'closed';
  title: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string | null;
  labels?: string[];
  classification?: {
    sentiment?: string;
    severity?: string;
    functionality?: string;
    scope?: string;
    affectedUsers?: string;
    duplicateCluster?: string | null;
    rationale?: string;
  };
}) {
  dbModule.upsertIssue({
    number: input.number,
    state: input.state,
    title: input.title,
    author: 'reporter',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${input.number}`,
    created_at: input.createdAt,
    updated_at: input.updatedAt,
    closed_at: input.closedAt ?? null,
    comments: 1,
    unique_human_commenters: 1,
    maintainer_commenters: 0,
    contributor_commenters: 0,
    commenter_scan_truncated: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: JSON.stringify(input.labels ?? ['bug']),
    is_bot: 0,
  });
  const c = input.classification ?? {};
  dbModule.upsertClassification(input.number, {
    sentiment: c.sentiment ?? 'negative',
    severity: c.severity ?? 'high',
    functionality: c.functionality ?? 'core',
    scope: c.scope ?? 'broad',
    affectedUsers: c.affectedUsers ?? 'many',
    workaroundStatus: 'unknown',
    duplicateCluster: c.duplicateCluster ?? null,
    affectsVersion: null,
    confidence: 0.95,
    rationale: c.rationale ?? 'route test classification',
  }, input.updatedAt, 1);
}

function upsertAuthoritativeCommentSnapshot(input: {
  issueNumber: number;
  issueUpdatedAt: string;
  comments: Parameters<typeof commentEvidenceDigest>[1];
}) {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = `I_${input.issueNumber}`;
  const issueAuthorNodeId = `U_reporter-${input.issueNumber}`;
  dbModule.db.prepare(`
    UPDATE issues
    SET node_id=?, author_node_id=?, author_type='User'
    WHERE number=?
  `).run(issueNodeId, issueAuthorNodeId, input.issueNumber);
  const snapshotIdentity = {
    repositoryNodeId,
    issueNodeId,
    issueNodeType: 'Issue',
    issueAuthor: {
      nodeId: issueAuthorNodeId,
      login: 'reporter',
      actorType: 'User',
    },
  };
  const sweep = {
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: input.comments.length,
    comments: input.comments,
    snapshotIdentity,
  };
  const firstSweep = commentEvidenceSweepIdentity({
    ...sweep,
    sweepOrdinal: 1,
  });
  const secondSweep = commentEvidenceSweepIdentity({
    ...sweep,
    sweepOrdinal: 2,
  });
  const stabilization = commentEvidenceStabilizationIdentity(
    firstSweep,
    secondSweep,
    2,
  );
  dbModule.upsertIssueCommentSnapshot({
    issue_number: input.issueNumber,
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_author_node_id: issueAuthorNodeId,
    issue_author_login: 'reporter',
    issue_author_type: 'User',
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    verified_at: input.issueUpdatedAt,
    comment_count: input.comments.length,
    fetched_comment_count: input.comments.length,
    latest_comment_updated_at: input.comments.at(-1)?.updated_at ?? null,
    comments_digest: commentEvidenceDigest(input.comments.length, input.comments),
    authority_digest: secondSweep.authorityDigest,
    issue_updated_at: input.issueUpdatedAt,
    comments_json: serializeCommentEvidence(input.comments),
    stabilization_json: JSON.stringify(stabilization),
    stabilization_identity_digest: stabilization.identityDigest,
  });
}

function recordAcceptedClassifierLedger(input: {
  issueNumber: number;
  rawModelOutput: string;
  sourceIdentity: {
    model: string;
    serviceTier: string;
    promptTemplateHash: string;
    digest: string;
  };
  responseId: string;
}) {
  const requestHash = createHash('sha256')
    .update(`request:${input.issueNumber}:${input.responseId}`)
    .digest('hex');
  const run = createClassifierAttemptRun({
    runId: `classifier-run-${input.issueNumber}-${input.responseId}`,
    issueNumber: input.issueNumber,
    startedAt: '2040-01-01T00:00:00.000Z',
    maxAttempts: 1,
    classifierIdentityHash: input.sourceIdentity.promptTemplateHash,
    requestHash,
  });
  const rawResponse = JSON.stringify({
    id: input.responseId,
    model: input.sourceIdentity.model,
    service_tier: input.sourceIdentity.serviceTier,
    choices: [{ message: { content: input.rawModelOutput } }],
  });
  const attempt = appendClassifierAttempt(run, [], {
    attemptId: `classifier-attempt-${input.issueNumber}-${input.responseId}`,
    status: 'accepted_success',
    startedAt: '2040-01-01T00:00:00.000Z',
    finishedAt: '2040-01-01T00:00:01.000Z',
    rawResponse: captureClassifierRawResponse(rawResponse),
    rawModelOutput: captureClassifierRawModelOutput(input.rawModelOutput),
    error: null,
    retry: {
      decision: 'stop',
      retryable: false,
      delayMs: null,
      reason: 'accepted_success',
    },
    semanticDiagnostics: [],
    provenance: {
      requestHash,
      responseId: input.responseId,
      responseModel: input.sourceIdentity.model,
      responseServiceTier: input.sourceIdentity.serviceTier,
    },
  });
  const receipt = createClassifierAttemptTerminalReceipt(run, [attempt], {
    receiptId: `classifier-receipt-${input.issueNumber}-${input.responseId}`,
    status: 'accepted_success',
    finishedAt: '2040-01-01T00:00:02.000Z',
    error: null,
  });
  const ledger = createClassifierAttemptLedger(run, [attempt], receipt);
  dbModule.recordClassifierAttemptRun(run);
  dbModule.recordClassifierAttempt(attempt);
  dbModule.recordClassifierAttemptTerminalReceipt(receipt);
  const revisions = dbModule.issueEvidenceRevisions([input.issueNumber]).get(input.issueNumber);
  assert.ok(revisions);
  assert.ok(receipt.selectedAttempt);
  return {
    ledger,
    selectedAttemptBinding: receipt.selectedAttempt,
    evidenceRevisions: {
      issueRevision: revisions.issueRevision,
      snapshotRevision: revisions.snapshotRevision,
      stateSnapshotRevision: revisions.stateSnapshotRevision,
    },
  };
}

function seedClosure(issueNumber: number, closedAt: string) {
  dbModule.upsertIssueClosureEvent({
    issue_number: issueNumber,
    event_id: `closed-${issueNumber}`,
    closed_at: closedAt,
    actor_login: 'maintainer',
    state_reason: 'COMPLETED',
    closer_type: null,
    closer_number: null,
    closer_oid: null,
    raw_json: '{}',
  });
}

function seedClosureProof(issueNumber: number, status: string, evidence: Record<string, unknown> = { status }) {
  dbModule.upsertIssueClosureProof({
    release_tag: 'v2026.6.1',
    issue_number: issueNumber,
    status,
    summary: status,
    evidence_json: JSON.stringify({
      ...evidence,
      proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
    }),
  });
}

function refreshClosureDependencySnapshot() {
  const issueNumbers = (dbModule.db.prepare(`
    SELECT issue_number
    FROM issue_closure_proofs
    WHERE release_tag='v2026.6.1'
    ORDER BY issue_number
  `).all() as Array<{ issue_number: number }>).map((row) => row.issue_number);
  dbModule.replaceReleaseClosureDependencySnapshot(
    dbModule.releaseClosureDependencyIdentity('v2026.6.1', issueNumbers),
  );
}

function seedReachability({
  prNumber,
  status,
}: {
  prNumber: number;
  status: 'reachable' | 'not_reachable' | 'unknown';
}) {
  dbModule.upsertReleasePrReachability({
    tag: 'v2026.6.1',
    pr_repository_owner: 'openclaw',
    pr_repository_name: 'openclaw',
    pr_repository_name_with_owner: 'openclaw/openclaw',
    pr_number: prNumber,
    tag_commit_oid: 'tag-commit',
    merge_commit_oid: `merge-${prNumber}`,
    base_ref_name: 'main',
    status,
    evidence_json: '{}',
  });
}
