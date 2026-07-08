import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import {
  canonicalManualScope,
  exactIngestionFailureMatches,
  manualScorePlan,
  supersedeExactIngestionEvidenceFailures,
} from '../../scripts/lib/manual-command-scope.mjs';
import { parseQualityRefreshArgs } from '../../scripts/lib/quality-refresh-cli.mjs';

async function freshDb(name: string) {
  const assignedPath =
    process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
  const path = assignedPath ??
    join(
      mkdtempSync(join(tmpdir(), `radar-manual-scope-${name}-`)),
      'radar.db',
    );
  if (assignedPath) {
    assert.equal(
      process.env.DB_PATH,
      assignedPath,
      'guarded tests must use their assigned private database',
    );
  } else {
    process.env.DB_PATH = path;
  }
  const db = await import(`./db.ts?manual-scope-${name}-${Date.now()}-${Math.random()}`);
  return { db, dir: dirname(path), ownsDir: assignedPath === null };
}

describe('manual command failure scopes', () => {
  it('requires an explicit isolated quality database for refresh', () => {
    const repositoryRoot =
      mkdtempSync(join(tmpdir(), 'radar-quality-refresh-cli-'));
    const dataDir = join(repositoryRoot, 'data');
    const liveDatabase = join(dataDir, 'radar.db');
    const qualityDatabase = join(dataDir, 'radar-quality.db');
    const symlinkAlias = join(repositoryRoot, 'live-symlink.db');
    const hardlinkAlias = join(repositoryRoot, 'live-hardlink.db');
    const environment: NodeJS.ProcessEnv = {
      RADAR_DB_BOOTSTRAP_MODE: 'existing',
    };
    try {
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(liveDatabase, 'live', { flag: 'wx' });
      symlinkSync(liveDatabase, symlinkAlias);
      linkSync(liveDatabase, hardlinkAlias);
      assert.deepEqual(
        parseQualityRefreshArgs(
          ['--db-path', './data/radar-quality.db'],
          { cwd: repositoryRoot, repositoryRoot, environment },
        ),
        {
          databasePath: qualityDatabase,
        },
      );
      assert.equal(environment.RADAR_DB_BOOTSTRAP_MODE, 'fresh');

      for (const familyMember of [
        qualityDatabase,
        `${qualityDatabase}-wal`,
        `${qualityDatabase}-shm`,
        `${qualityDatabase}-journal`,
      ]) {
        writeFileSync(familyMember, 'stale', { flag: 'wx' });
        try {
          assert.throws(
            () => parseQualityRefreshArgs(
              ['--db-path', './data/radar-quality.db'],
              { cwd: repositoryRoot, repositoryRoot, environment },
            ),
            /SQLite family member already exists/,
          );
        } finally {
          rmSync(familyMember, { force: true });
        }
      }

      for (const path of [
        './data/radar.db',
        './live-symlink.db',
        './live-hardlink.db',
      ]) {
        assert.throws(
          () => parseQualityRefreshArgs(
            ['--db-path', path],
            { cwd: repositoryRoot, repositoryRoot },
          ),
          /refuses data\/radar\.db/,
        );
      }
      for (const args of [
        [],
        ['--db-path'],
        ['--db-path', '--other'],
        ['--db-path', './quality.db', '--extra'],
      ]) {
        assert.throws(
          () => parseQualityRefreshArgs(args, {
            cwd: repositoryRoot,
            repositoryRoot,
          }),
          /Usage: refresh:quality/,
        );
      }
    } finally {
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  it('canonicalizes release and issue sets independently of input order', () => {
    const left = canonicalManualScope({
      releaseTags: ['v2', 'v1', 'v2'],
      issueNumbers: [3, 1, 3, 2],
    });
    const right = canonicalManualScope({
      releaseTags: ['v1', 'v2'],
      issueNumbers: [1, 2, 3],
    });
    assert.equal(left, right);
    assert.notEqual(left, canonicalManualScope({
      releaseTags: ['v1', 'v2'],
      issueNumbers: [1, 2],
    }));
  });

  it('permits scoring only when proof work covers the full monitored window', () => {
    assert.deepEqual(manualScorePlan({
      selectedReleaseTags: ['v3', 'v2'],
      monitoredReleaseTags: ['v3', 'v2', 'v1'],
    }), {
      status: 'staged-only',
      reason: 'selected releases do not cover the complete monitored score window',
    });
    assert.deepEqual(manualScorePlan({
      selectedReleaseTags: ['v4', 'v3', 'v2', 'v1'],
      monitoredReleaseTags: ['v3', 'v2', 'v1'],
    }), {
      status: 'full-window-commit',
      reason: null,
    });
    assert.equal(manualScorePlan({
      selectedReleaseTags: ['v3', 'v2', 'v1'],
      monitoredReleaseTags: ['v3', 'v2', 'v1'],
      skipProof: true,
    }).status, 'staged-only');
    assert.equal(manualScorePlan({
      selectedReleaseTags: ['v3', 'v2', 'v1'],
      monitoredReleaseTags: ['v3', 'v2', 'v1'],
      skipScore: true,
    }).status, 'staged-only');
  });

  it('supersedes only the exact source, scope, release, issue, and PR tuple', async () => {
    const { db, dir, ownsDir } = await freshDb('exact-supersession');
    try {
      const exact = {
        source: 'manual-proof',
        scope: canonicalManualScope({ releaseTags: ['v1'], issueNumbers: [101] }),
        releaseTag: 'v1',
        issueNumber: 101,
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        prNumber: 55,
      };
      const rows = [
        ['exact', exact],
        ['other-scope', { ...exact, scope: canonicalManualScope({ releaseTags: ['v2'], issueNumbers: [101] }) }],
        ['other-release', { ...exact, releaseTag: 'v2' }],
        ['other-issue', { ...exact, issueNumber: 102 }],
        ['other-pr', { ...exact, prNumber: 56 }],
      ] as const;
      rows.forEach(([runId, coordinate], index) => {
        db.insertIngestionEvidenceFailure({
          run_id: runId,
          occurred_at: `2026-07-04T00:0${index}:00Z`,
          source: coordinate.source,
          scope: coordinate.scope,
          release_tag: coordinate.releaseTag,
          issue_number: coordinate.issueNumber,
          pr_repository_name_with_owner: coordinate.prRepositoryNameWithOwner,
          pr_number: coordinate.prNumber,
          message: `${runId} failed`,
        });
      });

      assert.equal(supersedeExactIngestionEvidenceFailures(db.db, {
        successfulRunId: 'repair',
        supersededAt: '2026-07-04T01:00:00Z',
        ...exact,
      }), 1);

      const active = db.listActiveIngestionEvidenceFailures(10);
      assert.deepEqual(
        active.map((row: any) => row.run_id).sort(),
        ['other-issue', 'other-pr', 'other-release', 'other-scope'],
      );
      assert.equal(exactIngestionFailureMatches(
        db.listRecentIngestionEvidenceFailures(10).find((row: any) => row.run_id === 'exact'),
        exact,
      ), true);
    } finally {
      try { db.db.close(); } catch { /* already closed */ }
      if (ownsDir) rmSync(dir, { recursive: true, force: true });
    }
  });
});
