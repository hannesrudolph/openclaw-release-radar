import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { buildDoctorReport } from '../../scripts/doctor.mjs';
import {
  assessDataFreshnessHealth,
  assessDurableIngestionEvidenceFailureHealth,
  assessIssueCrawlHealth,
} from '../../scripts/lib/doctor-health.mjs';

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

describe('doctor score persistence release/audit parity', () => {
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
        sourceIdentityForDb: () => ({
          ...doctorSourceIdentityFixture,
          digest: 'c'.repeat(64),
          sources: [{ source: 'issues', count: 1, digest: 'd'.repeat(64) }],
        }),
      });
      assert.ok(report.failures.some((failure) => /score source identity drift/.test(failure)));
    } finally {
      cleanup();
    }
  });
});

function freshDoctorDb() {
  const dir = mkdtempSync(join(tmpdir(), 'radar-doctor-'));
  const dbPath = join(dir, 'radar.db');
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE releases (
      tag TEXT PRIMARY KEY,
      published_at TEXT,
      prerelease INTEGER NOT NULL DEFAULT 0,
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
      created_at TEXT,
      updated_at TEXT,
      closed_at TEXT,
      fetched_at TEXT,
      commenter_scan_truncated INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE classifications (issue_number INTEGER PRIMARY KEY, classified_at TEXT);
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
      source_identity_json TEXT
    );
    CREATE TABLE release_commits (tag TEXT PRIMARY KEY, fetched_at TEXT);
    CREATE TABLE issue_comment_snapshots (
      issue_number INTEGER PRIMARY KEY,
      fetched_at TEXT NOT NULL,
      comment_count INTEGER NOT NULL,
      fetched_comment_count INTEGER NOT NULL,
      latest_comment_updated_at TEXT,
      comments_digest TEXT NOT NULL
    );
    CREATE TABLE issue_closure_proofs (release_tag TEXT, issue_number INTEGER, status TEXT, checked_at TEXT);
    CREATE TABLE issue_closure_events (issue_number INTEGER, closed_at TEXT, fetched_at TEXT);
    CREATE TABLE issue_reopen_events (issue_number INTEGER, reopened_at TEXT, fetched_at TEXT);
    CREATE TABLE issue_pr_links (issue_number INTEGER, pr_repository_name_with_owner TEXT, pr_number INTEGER, fetched_at TEXT);
    CREATE TABLE issue_commit_references (issue_number INTEGER, fetched_at TEXT);
    CREATE TABLE pull_request_fixes (
      pr_repository_name_with_owner TEXT,
      pr_number INTEGER,
      merged INTEGER,
      merge_commit_oid TEXT,
      base_ref_name TEXT,
      fetched_at TEXT
    );
    CREATE TABLE release_pr_reachability (
      tag TEXT,
      pr_repository_name_with_owner TEXT,
      pr_number INTEGER,
      status TEXT,
      merge_commit_oid TEXT,
      base_ref_name TEXT,
      checked_at TEXT
    );
    CREATE TABLE issue_label_events (issue_number INTEGER, fetched_at TEXT);
    CREATE TABLE issue_label_snapshots (issue_number INTEGER, fetched_at TEXT);
    CREATE TABLE advisories (fetched_at TEXT);
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
  seedDoctorFixture(db);
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
  const releaseRows = [
    ['v2', '2026-06-02T00:00:00Z', 7.8, 'eligible', 1, '2026-06-02T01:00:00Z'],
    ['v1', '2026-06-01T00:00:00Z', 7.5, 'eligible', 0, '2026-06-01T01:00:00Z'],
  ] as const;
  const insertRelease = db.prepare(`
    INSERT INTO releases (
      tag, published_at, prerelease, final_score, state, recommended, score_reason, scored_at,
      release_metadata_fetched_at, release_derived_fetched_at, release_artifact_checked_at
    ) VALUES (?, ?, 0, ?, ?, ?, 'test reason', ?, '2026-05-31T00:00:00Z', '2026-05-31T00:00:00Z', '2026-05-31T00:00:00Z')
  `);
  const insertAudit = db.prepare(`
    INSERT INTO release_score_audits (
      release_tag, scored_at, score_model_version, prompt_version, final_score, status, band, recommended,
      input_json, components_json, issue_evidence_json, gate_evidence_json, source_identity_json
    ) VALUES (?, ?, 'test-model', 6, ?, ?, 'ok', ?, ?, '{}', ?, ?, ?)
  `);
  for (const [tag, publishedAt, score, status, recommended, scoredAt] of releaseRows) {
    insertRelease.run(tag, publishedAt, score, status, recommended, scoredAt);
    insertAudit.run(
      tag,
      scoredAt,
      score,
      status,
      recommended,
      JSON.stringify({ rawIssueCount: 1, classifiedIssueCount: 1 }),
      JSON.stringify({ debtSummary: {}, verifiedDebt: [], carryoverDebt: [], staleDebt: [], openedFeltSerious: [], verifiedFixed: [], unverifiedClosed: [], unclassifiedIssues: [] }),
      JSON.stringify({ fixProvenance: { closureProof: { analyzedClosedCount: 0, riskSummary: {} }, releaseFixCredit: { analyzedClosedCount: 0 } } }),
      JSON.stringify(doctorSourceIdentityFixture),
    );
    db.prepare(`INSERT INTO release_commits (tag, fetched_at) VALUES (?, '2026-05-31T00:00:00Z')`).run(tag);
  }
  db.prepare(`
    INSERT INTO issues (number, created_at, updated_at, closed_at, fetched_at, commenter_scan_truncated)
    VALUES (1, '2026-06-02T00:30:00Z', '2026-06-02T00:30:00Z', NULL, '2026-06-02T00:30:00Z', 0)
  `).run();
  db.prepare(`INSERT INTO classifications (issue_number, classified_at) VALUES (1, '2026-06-02T00:40:00Z')`).run();
  writeScorePersistenceMeta(db, ['v2', 'v1']);
}

function writeScorePersistenceMeta(db: DatabaseSync, releaseTags: string[]) {
  db.prepare(`
    INSERT INTO meta (key, value)
    VALUES ('score_persistence_last_run', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `).run(JSON.stringify({
    schemaVersion: 2,
    source: 'test',
    scope: null,
    persistedAt: '2026-06-02T01:05:00Z',
    scoreModelVersion: 'test-model',
    promptVersion: 6,
    scoredReleaseCount: releaseTags.length,
    recommendedTag: 'v2',
    releaseTags,
    minScoredAt: '2026-06-01T01:00:00Z',
    maxScoredAt: '2026-06-02T01:00:00Z',
    sourceIdentitySchemaVersion: doctorSourceIdentityFixture.schemaVersion,
    sourceIdentityDigest: doctorSourceIdentityFixture.digest,
    sourceIdentityRowCount: doctorSourceIdentityFixture.rowCount,
    sourceIdentitySourceCount: doctorSourceIdentityFixture.sourceCount,
  }));
}

const doctorSourceIdentityFixture = {
  schemaVersion: 1,
  sourceMode: 'current_db',
  scope: 'score_input_database',
  algorithm: 'sha256',
  rowCount: 1,
  sourceCount: 1,
  digest: 'a'.repeat(64),
  sources: [{ source: 'issues', count: 1, digest: 'b'.repeat(64) }],
};
