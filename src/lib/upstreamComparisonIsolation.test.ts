import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { isDeepStrictEqual } from 'node:util';
import express from 'express';
import { invalidateCache } from './cache.ts';

const assignedWorkerDatabase =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownsTempDir = assignedWorkerDatabase === null;
const tempDir = assignedWorkerDatabase
  ? dirname(assignedWorkerDatabase)
  : mkdtempSync(join(tmpdir(), 'radar-comparison-isolation-'));
process.env.DB_PATH = assignedWorkerDatabase ?? join(tempDir, 'radar.db');
process.env.REFRESH_MINUTES = '0';
process.env.COMPARISON_API_ENABLED = 'true';
process.env.RADAR_CODE_REVISION ??=
  process.env.RADAR_TEST_CODE_REVISION ?? 'comparison-isolation-test-revision';

const LOCAL_TAG = 'v2099.12.2+comparison.test';
const PREDECESSOR_TAG = 'v2099.12.1+comparison.test';
const LOCAL_PUBLISHED_AT = '2026-06-30T00:00:00Z';
const PREDECESSOR_PUBLISHED_AT = '2026-06-29T00:00:00Z';
const SCORE_AT = '2026-07-03T00:00:00Z';

let server: Server;
let baseUrl: string;
let dbModule: typeof import('./db.ts');
let apiModule: typeof import('../routes/api.ts');
let scoringModule: typeof import('./releaseScoring.ts');

before(async () => {
  dbModule = await import(`./db.ts?comparison-isolation-${Date.now()}`);
  scoringModule = await import(`./releaseScoring.ts?comparison-isolation-${Date.now()}`);

  seedAuthorizedReleaseCatalog([
    [LOCAL_TAG, LOCAL_PUBLISHED_AT],
    [PREDECESSOR_TAG, PREDECESSOR_PUBLISHED_AT],
  ]);
  seedReleaseCommit(LOCAL_TAG, LOCAL_PUBLISHED_AT);
  seedReleaseCommit(PREDECESSOR_TAG, PREDECESSOR_PUBLISHED_AT);
  dbModule.replaceReleaseClosureDependencySnapshot(
    dbModule.releaseClosureDependencyIdentity(LOCAL_TAG, []),
  );

  const run = scoringModule.buildReleaseScoreRun({
    releases: [dbModule.getRelease(LOCAL_TAG)!],
    oldestScoredStablePredecessorTag: PREDECESSOR_TAG,
    nowForRelease: () => Date.parse(SCORE_AT),
  });
  assert.equal(run.recommendedTag, LOCAL_TAG);
  scoringModule.persistReleaseScoreRun(run, {
    source: 'comparison-isolation-test',
    scope: LOCAL_TAG,
  });
  assert.equal(
    dbModule.getSealedReleaseScoreAuditPublication(LOCAL_TAG).valid,
    true,
  );

  apiModule = await import(`../routes/api.ts?comparison-isolation-${Date.now()}`);
  const app = express();
  app.use('/api', apiModule.api);
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', resolve);
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
  dbModule?.db.close();
  if (ownsTempDir) rmSync(tempDir, { recursive: true, force: true });
});

describe('upstream comparison isolation', () => {
  it('cannot change local scoring, provenance, recommendations, review identity, or readiness', async () => {
    const localBaseline = localInvariantSnapshot();
    const apiBaseline = await apiInvariantSnapshot();
    assert.equal(apiBaseline.review.status, 200);
    assert.equal(apiBaseline.review.body.tag, LOCAL_TAG);
    assert.equal(
      apiBaseline.health.body.status,
      'ready',
      JSON.stringify(apiBaseline.health.body, null, 2),
    );

    for (let sequence = 1; sequence <= 3; sequence++) {
      dbModule.saveComparisonSnapshot(comparisonSnapshot(sequence));
      await assertComparisonSequence(sequence);
      assertLocalIsolation(`repeated import ${sequence}`, localBaseline);
    }

    for (const malformed of [
      {
        label: 'non-finite score',
        input: comparisonSnapshot(10, {
          releases: [
            comparisonRelease(10, LOCAL_TAG),
            comparisonRelease(10, 'v-malformed-score', { score: Number.NaN }),
          ],
        }),
        error: /score must be null or finite number/,
      },
      {
        label: 'duplicate release tag',
        input: comparisonSnapshot(11, {
          releases: [
            comparisonRelease(11, LOCAL_TAG),
            comparisonRelease(11, LOCAL_TAG),
          ],
        }),
        error: /appears more than once/,
      },
      {
        label: 'invalid release URL',
        input: comparisonSnapshot(12, {
          releases: [
            comparisonRelease(12, LOCAL_TAG),
            comparisonRelease(12, 'v-malformed-url', { html_url: 'not-a-url' }),
          ],
        }),
        error: /html_url must be an http\(s\) URL/,
      },
    ]) {
      const comparisonBefore = comparisonState();
      assert.throws(
        () => dbModule.saveComparisonSnapshot(malformed.input),
        malformed.error,
        malformed.label,
      );
      assert.deepEqual(comparisonState(), comparisonBefore, malformed.label);
      assertLocalIsolation(malformed.label, localBaseline);
    }

    dbModule.runInWriteTransaction(() => {
      dbModule.db.prepare('DELETE FROM comparison_snapshots').run();
      dbModule.saveComparisonSnapshot(comparisonSnapshot(20));
    });
    assert.equal(comparisonState().snapshots.length, 1);
    assert.equal(comparisonState().releases.length, 2);
    await assertComparisonSequence(20);
    assertLocalIsolation('successful comparison replacement', localBaseline);

    const external = new DatabaseSync(process.env.DB_PATH!);
    try {
      external.prepare(`
        UPDATE comparison_releases
        SET reason='externally updated comparison reason'
        WHERE tag=?
      `).run(LOCAL_TAG);
    } finally {
      external.close();
    }
    const externallyUpdated = await getJson('/api/comparison');
    assert.equal(externallyUpdated.status, 200);
    assert.equal(
      externallyUpdated.body.releases.find(
        (release: any) => release.tag === LOCAL_TAG,
      )?.upstream?.reason,
      'externally updated comparison reason',
    );
    assertLocalIsolation('external comparison update', localBaseline);

    const beforeImportRollback = comparisonState();
    dbModule.db.exec(`
      CREATE TEMP TRIGGER abort_comparison_release_insert
      BEFORE INSERT ON comparison_releases
      WHEN NEW.tag='v-rollback'
      BEGIN
        SELECT RAISE(ABORT, 'forced comparison release rollback');
      END
    `);
    try {
      assert.throws(
        () => dbModule.saveComparisonSnapshot(comparisonSnapshot(30, {
          releases: [
            comparisonRelease(30, LOCAL_TAG),
            comparisonRelease(30, 'v-rollback'),
          ],
        })),
        /forced comparison release rollback/,
      );
    } finally {
      dbModule.db.exec('DROP TRIGGER abort_comparison_release_insert');
    }
    assert.deepEqual(comparisonState(), beforeImportRollback);
    assertLocalIsolation('mid-import transaction rollback', localBaseline);

    const beforeReplacementRollback = comparisonState();
    assert.throws(
      () => dbModule.runInWriteTransaction(() => {
        dbModule.db.prepare('DELETE FROM comparison_snapshots').run();
        dbModule.saveComparisonSnapshot(comparisonSnapshot(40));
        throw new Error('forced comparison replacement rollback');
      }),
      /forced comparison replacement rollback/,
    );
    assert.deepEqual(comparisonState(), beforeReplacementRollback);
    assertLocalIsolation('replacement transaction rollback', localBaseline);

    for (let repeated = 1; repeated <= 2; repeated++) {
      dbModule.saveComparisonSnapshot(comparisonSnapshot(20));
      await assertComparisonSequence(20);
      assertLocalIsolation(`post-replacement repeated import ${repeated}`, localBaseline);
    }

    apiModule.resetReleaseApiWorkerLifecycleForTests();
    apiModule.resetScoreReadWorkerLifecycleForTests();
    apiModule.resetPublicPayloadWorkerLifecycleForTests();
    invalidateCache();
    apiModule.expireRetainedPublicPayloadForTests();
    assertBoundedInvariantEqual(
      await apiInvariantSnapshot(),
      apiBaseline,
      'fresh API rebuild after comparison mutations',
    );
  });
});

function seedAuthorizedReleaseCatalog(
  releases: Array<readonly [tag: string, publishedAt: string]>,
): void {
  dbModule.replaceActiveReleaseCatalog(
    releases.map(([tag, publishedAt]) => ({
      node_id: `R_${createHash('sha256').update(tag).digest('hex')}`,
      catalog_tag_commit_oid: createHash('sha1').update(tag).digest('hex'),
      tag,
      name: tag,
      published_at: publishedAt,
      created_at: publishedAt,
      updated_at: publishedAt,
      html_url: `https://example.test/releases/${encodeURIComponent(tag)}`,
      prerelease: false,
      body: '',
    })),
    { capture: { source: 'test_fixture' } },
  );
}

function seedReleaseCommit(tag: string, publishedAt: string): void {
  dbModule.upsertReleaseCommit({
    tag,
    tag_commit_oid: createHash('sha1').update(tag).digest('hex'),
    committed_at: publishedAt,
    check_state: 'SUCCESS',
    check_total: 1,
    check_success: 1,
    check_failure: 0,
    check_pending: 0,
    check_skipped: 0,
    check_contexts_json: '[{"name":"build","conclusion":"SUCCESS"}]',
  });
}

function comparisonRelease(
  sequence: number,
  tag: string,
  overrides: Partial<import('./db.ts').ComparisonReleaseInput> = {},
): import('./db.ts').ComparisonReleaseInput {
  return {
    tag,
    name: `Upstream ${tag}`,
    published_at: `2026-07-${String(Math.min(sequence, 28)).padStart(2, '0')}T00:00:00Z`,
    html_url: `https://upstream.example.test/releases/${tag}`,
    displayed_date: `Jul ${Math.min(sequence, 28)}`,
    score: 9.9 - sequence / 100,
    band: 'solid',
    status: 'eligible',
    recommended: tag === LOCAL_TAG,
    reason: `upstream comparison ${sequence}`,
    negative_issues: sequence,
    positive_issues: sequence + 1,
    total_attributed_issues: sequence + 2,
    visible_issues: [{ number: sequence, title: `upstream issue ${sequence}` }],
    raw_card_text: `upstream card ${sequence}`,
    ...overrides,
  };
}

function comparisonSnapshot(
  sequence: number,
  overrides: Partial<import('./db.ts').ComparisonSnapshotInput> = {},
): import('./db.ts').ComparisonSnapshotInput {
  return {
    source_url: `https://upstream.example.test/snapshots/${sequence}`,
    captured_at: `2026-07-${String(Math.min(sequence, 28)).padStart(2, '0')}T12:00:00Z`,
    page_title: `Upstream comparison ${sequence}`,
    page_text: `comparison page ${sequence}`,
    raw_html: `<html>comparison ${sequence}</html>`,
    releases: [
      comparisonRelease(sequence, LOCAL_TAG),
      comparisonRelease(sequence, `v-upstream-${sequence}`),
    ],
    ...overrides,
  };
}

function localInvariantSnapshot() {
  return {
    releases: rows('SELECT * FROM releases ORDER BY tag'),
    scoreAudits: rows('SELECT * FROM release_score_audits ORDER BY release_tag'),
    scoreHistory: rows('SELECT * FROM release_score_audit_history ORDER BY id'),
    scoreHistoryRuns: rows('SELECT * FROM release_score_audit_history_runs ORDER BY id'),
    scorePersistenceMeta: rows(`
      SELECT key, value
      FROM meta
      WHERE key IN ('last_scored_at', 'score_persistence_last_run')
      ORDER BY key
    `),
    scoreApiSourceRevision: dbModule.scoreApiSourceRevision(),
    sourceIdentity: dbModule.scoreSourceIdentity(),
    recommendations: rows(`
      SELECT tag, final_score, state, recommended, score_reason, scored_at
      FROM releases
      ORDER BY tag
    `),
  };
}

function comparisonState() {
  return {
    snapshots: rows('SELECT * FROM comparison_snapshots ORDER BY id'),
    releases: rows('SELECT * FROM comparison_releases ORDER BY snapshot_id, tag'),
  };
}

function rows(sql: string): Array<Record<string, unknown>> {
  return dbModule.db.prepare(sql).all() as Array<Record<string, unknown>>;
}

async function assertComparisonSequence(sequence: number): Promise<void> {
  const comparison = await getJson('/api/comparison');
  assert.equal(comparison.status, 200);
  assert.equal(
    comparison.body.snapshot?.sourceUrl,
    `https://upstream.example.test/snapshots/${sequence}`,
  );
  assert.equal(
    comparison.body.releases.find(
      (release: any) => release.tag === LOCAL_TAG,
    )?.upstream?.reason,
    `upstream comparison ${sequence}`,
  );
}

async function apiInvariantSnapshot() {
  const [releases, publicPayload, review, health] = await Promise.all([
    getJson('/api/releases'),
    getJson('/api/public'),
    getJson(`/api/releases/${LOCAL_TAG}/review`),
    getJson('/api/health'),
  ]);
  const statuses = {
    releases: releases.status,
    publicPayload: publicPayload.status,
    review: review.status,
    health: health.status,
  };
  assert.deepEqual(
    statuses,
    {
      releases: 200,
      publicPayload: 200,
      review: 200,
      health: 200,
    },
    JSON.stringify({
      statuses,
      errors: {
        releases: releases.body?.error ?? null,
        publicPayload: publicPayload.body?.error ?? null,
        review: review.body?.error ?? null,
        health: health.body?.failures ?? null,
      },
    }),
  );
  const normalizedHealth = {
    ...health,
    body: omitCheckedAt(health.body),
  };
  const normalizedSnapshot = normalizeApiSnapshotIdentity(releases, publicPayload);
  return {
    releases: normalizedSnapshot.releases,
    publicPayload: normalizedSnapshot.publicPayload,
    review: {
      ...review,
      digest: createHash('sha256').update(JSON.stringify(review.body)).digest('hex'),
    },
    health: normalizedHealth,
  };
}

function normalizeApiSnapshotIdentity(
  releases: { status: number; body: any },
  publicPayload: { status: number; body: any },
) {
  const snapshotId = publicPayload.body?.snapshotId;
  assert.match(snapshotId, /^[0-9a-f]{64}$/);
  assert.equal(publicPayload.body?.snapshot?.id, snapshotId);
  assert.ok(Number.isFinite(Date.parse(publicPayload.body?.snapshot?.generatedAt)));

  const normalizeRows = (value: any, label: string) => {
    assert.ok(Array.isArray(value), `${label} must be an array`);
    return value.map((row, index) => {
      assert.equal(row.snapshotId, snapshotId, `${label}[${index}] snapshot identity`);
      return { ...row, snapshotId: '<snapshot-id>' };
    });
  };

  return {
    releases: {
      ...releases,
      body: normalizeRows(releases.body, 'release API rows'),
    },
    publicPayload: {
      ...publicPayload,
      body: {
        ...publicPayload.body,
        snapshotId: '<snapshot-id>',
        snapshot: {
          ...publicPayload.body.snapshot,
          id: '<snapshot-id>',
          generatedAt: '<generated-at>',
        },
        releases: normalizeRows(publicPayload.body.releases, 'public API rows'),
      },
    },
  };
}

function assertLocalIsolation(
  label: string,
  localBaseline: ReturnType<typeof localInvariantSnapshot>,
): void {
  assertBoundedInvariantEqual(
    localInvariantSnapshot(),
    localBaseline,
    `${label}: local invariants`,
  );
}

function assertBoundedInvariantEqual(
  actual: Record<string, unknown>,
  expected: Record<string, unknown>,
  label: string,
): void {
  if (isDeepStrictEqual(actual, expected)) return;
  const actualDigests = invariantComponentDigests(actual);
  const expectedDigests = invariantComponentDigests(expected);
  if (isDeepStrictEqual(actualDigests, expectedDigests)) {
    throw new Error(`${label}: deep inequality with identical component digests`);
  }
  assert.deepEqual(actualDigests, expectedDigests, label);
}

function invariantComponentDigests(
  value: Record<string, unknown>,
): Record<string, string> {
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [
        key,
        createHash('sha256')
          .update(JSON.stringify(value[key]) ?? 'undefined')
          .digest('hex'),
      ]),
  );
}

async function getJson(path: string): Promise<{ status: number; body: any }> {
  const response = await fetch(`${baseUrl}${path}`);
  return {
    status: response.status,
    body: await response.json(),
  };
}

function omitCheckedAt(body: any): any {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return body;
  const { checkedAt: _checkedAt, ...rest } = body;
  return rest;
}
