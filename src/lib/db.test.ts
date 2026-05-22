import { describe, it, before } from 'node:test';
import { strict as assert } from 'node:assert';
import { DatabaseSync } from 'node:sqlite';

// We can't import ./db directly because it opens the production DB at module load.
// Instead we recreate the schema + the issuesOpenDuring SQL verbatim against an
// in-memory DB. If the production SQL drifts, update this test to match.
//
// Test timeline (releases, DESC):
//   v3: 2024-06-01 (latest)
//   v2: 2024-04-01
//   v1: 2024-02-01
//
// For each release, the lifetime window is [published_at, next_newer.published_at).
// Latest has no upper bound — treated as "now" by passing endTs = current ISO.

const NOW = '2024-07-01T00:00:00Z';

const releases = [
  { tag: 'v3', publishedAt: '2024-06-01T00:00:00Z' },
  { tag: 'v2', publishedAt: '2024-04-01T00:00:00Z' },
  { tag: 'v1', publishedAt: '2024-02-01T00:00:00Z' },
];

interface Fixture {
  number: number;
  createdAt: string;
  closedAt: string | null;
  label: string;
}

const fixtures: Fixture[] = [
  // Opened and closed before any release in DB — should not affect any release.
  { number: 1, createdAt: '2024-01-01T00:00:00Z', closedAt: '2024-01-15T00:00:00Z', label: 'closed-before-v1' },
  // Ancient still-open — was open during all three release windows.
  { number: 2, createdAt: '2024-01-01T00:00:00Z', closedAt: null, label: 'ancient-still-open' },
  // Opened during v1's lifetime, closed during v2's — affects v1 and v2, not v3.
  { number: 3, createdAt: '2024-02-15T00:00:00Z', closedAt: '2024-04-15T00:00:00Z', label: 'v1-into-v2' },
  // Opened during v2, still open — affects v2 and v3.
  { number: 4, createdAt: '2024-05-01T00:00:00Z', closedAt: null, label: 'v2-still-open' },
  // Born after v3 published — affects only v3.
  { number: 5, createdAt: '2024-06-15T00:00:00Z', closedAt: null, label: 'born-in-v3' },
  // Opened and closed entirely within v2's window — v2 only.
  { number: 6, createdAt: '2024-04-15T00:00:00Z', closedAt: '2024-05-15T00:00:00Z', label: 'v2-only' },
];

let db: DatabaseSync;
let queryStmt: ReturnType<DatabaseSync['prepare']>;

before(() => {
  db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE issues (
      number INTEGER PRIMARY KEY,
      state TEXT NOT NULL,
      title TEXT NOT NULL,
      author TEXT,
      html_url TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      closed_at TEXT,
      comments INTEGER NOT NULL,
      labels TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE classifications (
      issue_number INTEGER PRIMARY KEY,
      sentiment TEXT NOT NULL,
      severity TEXT NOT NULL,
      scope TEXT NOT NULL,
      functionality TEXT NOT NULL,
      affected_users TEXT NOT NULL,
      has_workaround INTEGER NOT NULL,
      duplicate_cluster TEXT,
      affects_version TEXT,
      confidence REAL NOT NULL,
      rationale TEXT,
      classified_at TEXT NOT NULL,
      classified_updated_at TEXT NOT NULL
    );
  `);

  const insIssue = db.prepare(`
    INSERT INTO issues (number, state, title, html_url, created_at, updated_at, closed_at, comments)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0)`);
  const insCls = db.prepare(`
    INSERT INTO classifications (issue_number, sentiment, severity, scope, functionality,
      affected_users, has_workaround, duplicate_cluster, affects_version, confidence,
      rationale, classified_at, classified_updated_at)
    VALUES (?, 'negative', 'medium', 'moderate', 'core', 'some', 0, NULL, NULL, 0.8, '', ?, ?)`);

  for (const f of fixtures) {
    insIssue.run(
      f.number,
      f.closedAt ? 'closed' : 'open',
      f.label,
      `https://example/${f.number}`,
      f.createdAt,
      f.createdAt,
      f.closedAt,
    );
    insCls.run(f.number, NOW, f.createdAt);
  }

  // Same SQL as src/lib/db.ts issuesOpenDuringStmt.
  queryStmt = db.prepare(`
    SELECT i.number
    FROM issues i
    JOIN classifications c ON c.issue_number = i.number
    WHERE i.created_at < :end_ts
      AND (i.closed_at IS NULL OR i.closed_at > :start_ts)
    ORDER BY i.updated_at DESC
  `);
});

function issuesOpenDuring(startTs: string, endTs: string | null): number[] {
  const end = endTs ?? NOW;
  const rows = queryStmt.all({ start_ts: startTs, end_ts: end }) as { number: number }[];
  return rows.map((r) => r.number).sort((a, b) => a - b);
}

function windowFor(idx: number): { start: string; end: string | null } {
  // releases is sorted DESC — index 0 is latest. The next-newer release sits at idx-1.
  return {
    start: releases[idx].publishedAt,
    end: idx === 0 ? null : releases[idx - 1].publishedAt,
  };
}

describe('issuesOpenDuring (time-window release attribution)', () => {
  it('latest release (v3) — covers issues open at any point since v3 published', () => {
    const { start, end } = windowFor(0);
    assert.deepEqual(issuesOpenDuring(start, end), [2, 4, 5]);
  });

  it('middle release (v2) — bounded above by v3, below by v2 publish', () => {
    const { start, end } = windowFor(1);
    assert.deepEqual(issuesOpenDuring(start, end), [2, 3, 4, 6]);
  });

  it('earliest release (v1) — covers only its short window', () => {
    const { start, end } = windowFor(2);
    assert.deepEqual(issuesOpenDuring(start, end), [2, 3]);
  });

  it('excludes issues closed before window start', () => {
    // The "closed-before-v1" issue (#1) was closed on 2024-01-15, before v1 publish.
    // It must not appear in any release.
    for (let i = 0; i < releases.length; i++) {
      const { start, end } = windowFor(i);
      assert.ok(!issuesOpenDuring(start, end).includes(1), `#1 leaked into ${releases[i].tag}`);
    }
  });

  it('ancient still-open issue counts for every release', () => {
    // #2 has been open since before v1 — must show in v1, v2, v3.
    for (let i = 0; i < releases.length; i++) {
      const { start, end } = windowFor(i);
      assert.ok(issuesOpenDuring(start, end).includes(2), `#2 missing from ${releases[i].tag}`);
    }
  });

  it('issue spanning two releases counts for both', () => {
    // #3 opened during v1, closed during v2 — must show in v1 AND v2, not v3.
    const inV1 = issuesOpenDuring(...Object.values(windowFor(2)) as [string, string | null]).includes(3);
    const inV2 = issuesOpenDuring(...Object.values(windowFor(1)) as [string, string | null]).includes(3);
    const inV3 = issuesOpenDuring(...Object.values(windowFor(0)) as [string, string | null]).includes(3);
    assert.ok(inV1, '#3 missing from v1');
    assert.ok(inV2, '#3 missing from v2');
    assert.ok(!inV3, '#3 leaked into v3');
  });

  it('issue born after latest release publish counts only for latest', () => {
    // #5 created after v3 published — must be in v3 only.
    const inV1 = issuesOpenDuring(...Object.values(windowFor(2)) as [string, string | null]).includes(5);
    const inV2 = issuesOpenDuring(...Object.values(windowFor(1)) as [string, string | null]).includes(5);
    const inV3 = issuesOpenDuring(...Object.values(windowFor(0)) as [string, string | null]).includes(5);
    assert.ok(!inV1 && !inV2, '#5 leaked into older releases');
    assert.ok(inV3, '#5 missing from v3');
  });
});
