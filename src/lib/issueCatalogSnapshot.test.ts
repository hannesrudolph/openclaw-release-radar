import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  canonicalIssueCatalogIssueJson,
  canonicalIssueContentDigest,
  canonicalIssueMembershipDigest,
  issueCatalogSnapshotCatalog,
} from './issueCatalogSnapshot.ts';
import type {
  GhIssueCatalog,
  GhIssueCatalogIssue,
} from './github.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownedTestDir = assignedWorkerDatabasePath === null
  ? mkdtempSync(join(tmpdir(), 'radar-issue-catalog-snapshot-'))
  : null;
if (ownedTestDir !== null) {
  const emptyDotenvPath = join(ownedTestDir, 'empty.env');
  process.env.DB_PATH = join(ownedTestDir, 'radar.db');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
  writeFileSync(emptyDotenvPath, '');
}

let dbModule: typeof import('./db.ts');
let refreshTest: typeof import('./refresh.ts').__refreshTest;

before(async () => {
  dbModule = await import('./db.ts');
  ({ __refreshTest: refreshTest } = await import('./refresh.ts'));
});

after(() => {
  dbModule.db.close();
  if (ownedTestDir !== null) {
    rmSync(ownedTestDir, { recursive: true, force: true });
  }
});

describe('durable exhaustive issue catalog snapshots', { concurrency: false }, () => {
  it('atomically persists immutable header and issue rows with verified hashes', () => {
    const header = dbModule.insertIssueCatalogSnapshot({
      repository: 'openclaw/openclaw',
      capturedAt: '2026-07-04T10:00:00.000Z',
      catalog: catalogFixture(),
    });
    const snapshot = dbModule.getIssueCatalogSnapshot(header.snapshotId);
    assert.ok(snapshot);

    assert.equal(snapshot.header.rowCount, 2);
    assert.deepEqual(snapshot.rows.map((row) => row.sourceOrdinal), [0, 1]);
    assert.deepEqual(snapshot.rows.map((row) => row.nodeId), ['ISSUE-node-1', 'ISSUE-node-2']);
    assert.deepEqual(
      issueCatalogSnapshotCatalog(snapshot).issues.map((issue) => issue.number),
      [1, 2],
    );
    assert.deepEqual(
      JSON.parse(snapshot.rows[0].issueJson),
      {
        node_id: 'ISSUE-node-1',
        node_type: 'Issue',
        number: 1,
        title: 'Issue 1',
        body: 'Body 1',
        state: 'open',
        user: {
          id: 'ACTOR-reporter-1',
          type: 'User',
          login: 'reporter-1',
        },
        author_association: 'CONTRIBUTOR',
        created_at: '2026-07-01T00:00:00.000Z',
        updated_at: '2026-07-01T00:00:00.000Z',
        closed_at: null,
        html_url: 'https://example.test/issues/1',
        comments: 1,
        reaction_total: 1,
        positive_reactions: 1,
        labels: [{ name: 'bug' }],
      },
    );
    assert.deepEqual(dbModule.issueCatalogSnapshotLedgerIntegrity().problems, []);
    assert.throws(
      () => dbModule.db.prepare(`
        UPDATE issue_catalog_snapshots
        SET captured_at='2026-07-04T11:00:00.000Z'
        WHERE snapshot_id=?
      `).run(snapshot.header.snapshotId),
      /append-only/,
    );
    assert.throws(
      () => dbModule.db.prepare(`
        DELETE FROM issue_catalog_snapshot_rows
        WHERE snapshot_id=? AND source_ordinal=0
      `).run(snapshot.header.snapshotId),
      /append-only/,
    );
  });

  it('rolls back the whole snapshot when catalog validation fails', () => {
    const beforeHeaders = Number((dbModule.db.prepare(`
      SELECT COUNT(*) AS count FROM issue_catalog_snapshots
    `).get() as { count: number }).count);
    const beforeRows = Number((dbModule.db.prepare(`
      SELECT COUNT(*) AS count FROM issue_catalog_snapshot_rows
    `).get() as { count: number }).count);
    const invalid = catalogFixture();
    invalid.metadata.contentDigest = '0'.repeat(64);

    assert.throws(
      () => dbModule.insertIssueCatalogSnapshot({
        repository: 'openclaw/openclaw',
        capturedAt: '2026-07-04T10:30:00.000Z',
        catalog: invalid,
      }),
      /digests do not match/,
    );
    assert.equal(
      Number((dbModule.db.prepare(`
        SELECT COUNT(*) AS count FROM issue_catalog_snapshots
      `).get() as { count: number }).count),
      beforeHeaders,
    );
    assert.equal(
      Number((dbModule.db.prepare(`
        SELECT COUNT(*) AS count FROM issue_catalog_snapshot_rows
      `).get() as { count: number }).count),
      beforeRows,
    );
  });

  it('binds issue node type and immutable author identity into canonical content', () => {
    const issue = issueFixture(1, '2026-07-01T00:00:00.000Z');
    const baseline = canonicalIssueContentDigest(1, [{
      nodeId: issue.node_id,
      issue,
    }]);
    const changedAuthorNodeId = {
      ...issue,
      user: {
        ...issue.user!,
        id: 'ACTOR-other-reporter',
      },
    };
    const changedAuthorType = {
      ...issue,
      user: {
        ...issue.user!,
        type: 'Bot',
      },
    };

    assert.notEqual(
      canonicalIssueContentDigest(1, [{
        nodeId: changedAuthorNodeId.node_id,
        issue: changedAuthorNodeId,
      }]),
      baseline,
    );
    assert.notEqual(
      canonicalIssueContentDigest(1, [{
        nodeId: changedAuthorType.node_id,
        issue: changedAuthorType,
      }]),
      baseline,
    );
    assert.match(canonicalIssueCatalogIssueJson(issue), /"node_type":"Issue"/);
    assert.match(
      canonicalIssueCatalogIssueJson(issue),
      /"user":\{"id":"ACTOR-reporter-1","type":"User","login":"reporter-1"\}/,
    );
  });

  it('refuses a catalog that observed issues beyond its frozen boundary', () => {
    const growing = catalogFixture();
    growing.metadata.observedTotalCount++;
    growing.metadata.postBoundaryGrowthCount++;

    assert.throws(
      () => dbModule.insertIssueCatalogSnapshot({
        repository: 'openclaw/openclaw',
        capturedAt: '2026-07-04T10:45:00.000Z',
        catalog: growing,
      }),
      /no post-boundary growth/,
    );
  });

  it('refuses a staged snapshot outside the documented 24-hour resume window', () => {
    const header = dbModule.insertIssueCatalogSnapshot({
      repository: 'openclaw/openclaw',
      capturedAt: '2026-07-02T10:00:00.000Z',
      catalog: catalogFixture(),
    });
    const result = dbModule.findResumableIssueCatalogSnapshot({
      repository: 'openclaw/openclaw',
      now: new Date('2026-07-04T10:00:00.000Z'),
      maxAgeMs: 24 * 60 * 60 * 1000,
    });

    assert.equal(result.status, 'stale');
    assert.equal(result.snapshot?.header.snapshotId, header.snapshotId);
    assert.ok(result.problems.some((problem) => /resume age policy/.test(problem)));
  });

  it('resumes the latest verified catalog after page failure without rescanning GitHub', async () => {
    let fetchCount = 0;
    const first = await refreshTest.resolveIssueCatalogSnapshotForRefresh({
      repository: 'openclaw/openclaw',
      observedAt: '2026-07-04T12:00:00.000Z',
      maxAgeMs: 24 * 60 * 60 * 1000,
      captureNow: () => '2026-07-04T12:00:00.000Z',
      fetchCatalog: async () => {
        fetchCount++;
        return catalogFixture();
      },
    });
    assert.equal(first.resumed, false);
    assert.equal(fetchCount, 1);

    const pages = [
      first.snapshot.rows.slice(0, 1),
      first.snapshot.rows.slice(1),
    ];
    assert.equal(pages[0][0].issue.number, 1);
    assert.throws(() => {
      throw new Error('simulated page evidence failure');
    }, /simulated page evidence failure/);
    assert.equal(dbModule.getMeta('issue_crawl_exhaustive_baseline'), null);
    assert.equal(dbModule.getMeta('backfill_completed_at'), null);

    const resumed = await refreshTest.resolveIssueCatalogSnapshotForRefresh({
      repository: 'openclaw/openclaw',
      observedAt: '2026-07-04T13:00:00.000Z',
      maxAgeMs: 24 * 60 * 60 * 1000,
      fetchCatalog: async () => {
        fetchCount++;
        throw new Error('network catalog scan should not run');
      },
    });
    assert.equal(resumed.resumed, true);
    assert.equal(resumed.snapshot.header.snapshotId, first.snapshot.header.snapshotId);
    assert.equal(fetchCount, 1);
    assert.deepEqual(
      issueCatalogSnapshotCatalog(resumed.snapshot).issues.map((issue) => issue.number),
      [1, 2],
    );
    assert.equal(dbModule.getMeta('issue_crawl_exhaustive_baseline'), null);
    assert.equal(dbModule.getMeta('backfill_completed_at'), null);
  });

  it('consumes a completed snapshot exactly once and forces the next run to fetch fresh', async () => {
    const header = dbModule.insertIssueCatalogSnapshot({
      repository: 'openclaw/openclaw',
      capturedAt: '2026-07-04T14:00:00.000Z',
      catalog: catalogFixture(),
    });
    const consumption = dbModule.consumeIssueCatalogSnapshot({
      snapshotId: header.snapshotId,
      repository: 'openclaw/openclaw',
      runId: 'refresh-run-consumed',
      consumedAt: '2026-07-04T14:05:00.000Z',
      processedRowCount: header.rowCount,
      processedPageCount: header.pageCount,
    });

    assert.equal(consumption.snapshotId, header.snapshotId);
    assert.equal(consumption.snapshotContentHash, header.contentHash);
    assert.equal(dbModule.findResumableIssueCatalogSnapshot({
      repository: 'openclaw/openclaw',
      now: new Date('2026-07-04T14:10:00.000Z'),
    }).status, 'consumed');
    assert.throws(
      () => dbModule.consumeIssueCatalogSnapshot({
        snapshotId: header.snapshotId,
        repository: 'openclaw/openclaw',
        runId: 'different-refresh-run',
        consumedAt: '2026-07-04T14:06:00.000Z',
        processedRowCount: header.rowCount,
        processedPageCount: header.pageCount,
      }),
      /already consumed/,
    );
    assert.throws(
      () => dbModule.db.prepare(`
        UPDATE issue_catalog_snapshot_consumptions
        SET consumed_at='2026-07-04T15:00:00.000Z'
        WHERE snapshot_id=?
      `).run(header.snapshotId),
      /append-only/,
    );

    let fetchCount = 0;
    const fresh = await refreshTest.resolveIssueCatalogSnapshotForRefresh({
      repository: 'openclaw/openclaw',
      observedAt: '2026-07-04T14:15:00.000Z',
      maxAgeMs: 24 * 60 * 60 * 1000,
      captureNow: () => '2026-07-04T14:15:00.000Z',
      fetchCatalog: async () => {
        fetchCount++;
        return catalogFixture();
      },
    });
    assert.equal(fetchCount, 1);
    assert.equal(fresh.resumed, false);
    assert.equal(fresh.priorStatus, 'consumed');
    assert.notEqual(fresh.snapshot.header.snapshotId, header.snapshotId);
    assert.equal(dbModule.issueCatalogSnapshotLedgerIntegrity().problems.length, 0);
  });

  it('requires a matching exhaustive catalog immediately before publication', () => {
    const header = dbModule.insertIssueCatalogSnapshot({
      repository: 'openclaw/openclaw',
      capturedAt: '2026-07-04T15:00:00.000Z',
      catalog: catalogFixture(),
    });
    const snapshot = dbModule.getIssueCatalogSnapshot(header.snapshotId);
    assert.ok(snapshot);
    const matching = catalogFixture();
    const attestation = refreshTest.finalIssueCatalogAttestation({
      snapshot,
      finalCatalog: matching,
      observedAt: '2026-07-04T15:30:00.000Z',
    });
    assert.equal(attestation.snapshotId, header.snapshotId);
    assert.equal(attestation.contentDigest, header.contentDigest);

    const changed = catalogFixture();
    changed.issues[0] = { ...changed.issues[0], state: 'closed' };
    const changedRecords = changed.issues.map((issue) => ({
      nodeId: issue.node_id,
      issue,
    }));
    changed.metadata.contentDigest = canonicalIssueContentDigest(
      changed.issues.length,
      changedRecords,
    );
    assert.throws(
      () => refreshTest.finalIssueCatalogAttestation({
        snapshot,
        finalCatalog: changed,
        observedAt: '2026-07-04T15:31:00.000Z',
      }),
      /contentDigest changed/,
    );
  });

  it('detects row corruption and will not resume the corrupted snapshot', () => {
    const latest = dbModule.latestIssueCatalogSnapshot('openclaw/openclaw');
    assert.ok(latest);
    dbModule.db.exec(`DROP TRIGGER issue_catalog_snapshot_rows_no_update`);
    dbModule.db.prepare(`
      UPDATE issue_catalog_snapshot_rows
      SET issue_json=replace(issue_json, '"Issue 1"', '"Corrupted issue"')
      WHERE snapshot_id=? AND source_ordinal=0
    `).run(latest.header.snapshotId);

    const result = dbModule.findResumableIssueCatalogSnapshot({
      repository: 'openclaw/openclaw',
      now: new Date('2026-07-04T13:00:00.000Z'),
    });
    assert.equal(result.status, 'invalid');
    assert.ok(result.problems.some((problem) =>
      /contentHash|issueJson|rowsContentHash|contentDigest/.test(problem)));
    assert.ok(dbModule.issueCatalogSnapshotLedgerIntegrity().problems.length > 0);
  });
});

function catalogFixture(): GhIssueCatalog {
  const issues = [
    issueFixture(1, '2026-07-01T00:00:00.000Z'),
    issueFixture(2, '2026-07-02T00:00:00.000Z'),
  ];
  const records = issues.map((issue) => ({ nodeId: issue.node_id, issue }));
  const membershipDigest = canonicalIssueMembershipDigest(issues.length, records);
  const contentDigest = canonicalIssueContentDigest(issues.length, records);
  return {
    issues,
    metadata: {
      exhausted: true,
      stabilized: true,
      totalCount: issues.length,
      observedTotalCount: issues.length,
      postBoundaryGrowthCount: 0,
      nodeCount: issues.length,
      uniqueCount: issues.length,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      digest: membershipDigest,
      membershipDigest,
      contentDigest,
      snapshotBoundary: {
        totalCount: issues.length,
        terminalIssue: {
          nodeId: issues[1].node_id,
          issueNumber: issues[1].number,
          createdAt: issues[1].created_at,
        },
        membershipDigest,
      },
      lastRequestCursor: null,
      nextCursor: null,
      hasNextPage: false,
      sourceOrder: 'CREATED_AT_ASC',
    },
  };
}

function issueFixture(number: number, createdAt: string): GhIssueCatalogIssue {
  return {
    node_id: `ISSUE-node-${number}`,
    node_type: 'Issue',
    number,
    title: `Issue ${number}`,
    body: `Body ${number}`,
    state: 'open',
    user: {
      id: `ACTOR-reporter-${number}`,
      type: 'User',
      login: `reporter-${number}`,
    },
    author_association: 'CONTRIBUTOR',
    created_at: createdAt,
    updated_at: createdAt,
    closed_at: null,
    html_url: `https://example.test/issues/${number}`,
    comments: number,
    reaction_total: number,
    positive_reactions: number,
    labels: [{ name: 'bug' }],
  };
}
