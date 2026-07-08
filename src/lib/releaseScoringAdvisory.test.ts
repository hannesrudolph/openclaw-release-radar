import { after, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownsSharedModulesDir = assignedWorkerDatabasePath === null;

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-release-scoring-advisory-${name}-`)), 'radar.db');
}

async function freshModules(name: string) {
  if (!sharedModules) {
    const path = assignedWorkerDatabasePath ?? dbPath(name);
    sharedModulesDir = dirname(path);
    if (assignedWorkerDatabasePath) {
      assert.equal(
        process.env.DB_PATH,
        assignedWorkerDatabasePath,
        'guarded advisory scoring tests must use their assigned private database',
      );
      assert.ok(
        process.env.DOTENV_CONFIG_PATH,
        'guarded advisory scoring tests require the runner-assigned empty dotenv path',
      );
    } else {
      process.env.DB_PATH = path;
      const emptyDotenvPath = join(sharedModulesDir, 'empty.env');
      writeFileSync(emptyDotenvPath, '', { flag: 'wx', mode: 0o600 });
      process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
    }
    sharedModules = (async () => {
      const db = await import(
        `./db.ts?release-scoring-advisory-${name}-${Date.now()}-${Math.random()}`
      );
      const scoring = await import(
        `./releaseScoring.ts?release-scoring-advisory-${name}-${Date.now()}-${Math.random()}`
      );
      return { db, scoring, dir: dirname(path) };
    })();
  }
  const modules = await sharedModules;
  resetDatabase(modules.db.db);
  return modules;
}

let sharedModules: Promise<{
  db: any;
  scoring: any;
  dir: string;
}> | null = null;
let sharedModulesDir: string | null = null;

function resetDatabase(database: any): void {
  const tables = (database.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type='table'
      AND name NOT LIKE 'sqlite_%'
      AND name <> 'score_api_source_epoch'
    ORDER BY name
  `).all() as Array<{ name: string }>).map((row) => row.name);
  const appendOnlyTriggers = database.prepare(`
    SELECT name, sql
    FROM sqlite_master
    WHERE type='trigger'
      AND sql LIKE '% is append-only%'
    ORDER BY name
  `).all() as Array<{ name: string; sql: string }>;
  database.exec('PRAGMA foreign_keys=OFF');
  try {
    database.exec('BEGIN');
    for (const trigger of appendOnlyTriggers) {
      database.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
    }
    for (const table of tables) {
      database.exec(`DELETE FROM "${table.replaceAll('"', '""')}"`);
    }
    database.exec('DELETE FROM sqlite_sequence');
    for (const trigger of appendOnlyTriggers) database.exec(trigger.sql);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  } finally {
    database.exec('PRAGMA foreign_keys=ON');
  }
}

function releaseFreshModules(dir: string): void {
  if (ownsSharedModulesDir && dir !== sharedModulesDir) {
    rmSync(dir, { recursive: true, force: true });
  }
}

after(async () => {
  if (sharedModules) await sharedModules.catch(() => null);
  if (ownsSharedModulesDir && sharedModulesDir) {
    rmSync(sharedModulesDir, { recursive: true, force: true });
  }
});

function seedRelease(db: any, tag: string, publishedAt: string) {
  const tagCommitOid = createHash('sha1')
    .update(`release-scoring-advisory:${tag}`)
    .digest('hex');
  db.upsertRelease({
    tag,
    node_id: `R_${tag}`,
    catalog_tag_commit_oid: tagCommitOid,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease: false,
    body: '',
  });
  db.upsertReleaseCommit({
    tag,
    tag_commit_oid: tagCommitOid,
    committed_at: publishedAt,
  });
}

function activateCatalog(db: any, tagsNewestFirst: string[]): void {
  db.replaceActiveReleaseCatalog(
    tagsNewestFirst.map((tag) => {
      const release = db.getRelease(tag);
      return {
        node_id: release.node_id,
        catalog_tag_commit_oid: release.catalog_tag_commit_oid,
        tag: release.tag,
        name: release.name,
        published_at: release.published_at,
        created_at: release.created_at,
        updated_at: release.updated_at,
        html_url: release.html_url,
        prerelease: release.prerelease === 1,
        body: release.body,
      };
    }),
    { capture: { source: 'test_fixture' } },
  );
}

function seedAdvisory(db: any, input: {
  key: string;
  range: string;
  patched: string;
}) {
  db.upsertAdvisory({
    advisory_key: input.key,
    ghsa_id: 'GHSA-multi-range',
    cve_id: 'CVE-2026-1111',
    summary: 'Multi-range advisory',
    severity: 'medium',
    html_url: 'https://example.test/advisory/GHSA-multi-range',
    published_at: '2026-06-01T00:00:00Z',
    package_ecosystem: 'npm',
    package_name: 'openclaw',
    vulnerable_version_range: input.range,
    patched_versions: input.patched,
  });
}

describe('release scoring advisory ranges', () => {
  it('scores every vulnerability range for a multi-range GHSA', async () => {
    const { db, scoring, dir } = await freshModules('multi-range-ghsa');
    try {
      seedRelease(db, 'v2026.6.10', '2026-06-10T00:00:00Z');
      seedRelease(db, 'v2026.6.1', '2026-06-01T00:00:00Z');
      activateCatalog(db, ['v2026.6.10', 'v2026.6.1']);
      seedAdvisory(db, {
        key: 'GHSA-multi-range:npm:openclaw:<2026.6.2',
        range: '< 2026.6.2',
        patched: '2026.6.2',
      });
      seedAdvisory(db, {
        key: 'GHSA-multi-range:npm:openclaw:>=2026.6.10<2026.6.11',
        range: '>= 2026.6.10 < 2026.6.11',
        patched: '2026.6.11',
      });

      const keys = new Set([
        'GHSA-multi-range:npm:openclaw:<2026.6.2',
        'GHSA-multi-range:npm:openclaw:>=2026.6.10<2026.6.11',
      ]);
      const rows = db.listAdvisories().filter((row: any) => keys.has(row.advisory_key));
      assert.equal(rows.length, 2);

      const run = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v2026.6.10'), db.getRelease('v2026.6.1')],
        nowForRelease: () => Date.parse('2026-06-12T00:00:00Z'),
      });
      const byTag = new Map(run.scored.map((result: any) => [result.rel.tag, result]));

      assert.equal(byTag.get('v2026.6.10')?.conf.status, 'skip-cve');
      assert.equal(byTag.get('v2026.6.1')?.conf.status, 'skip-cve');
    } finally {
      releaseFreshModules(dir);
    }
  });

  it('refuses advisory rows for a different package identity', async () => {
    const { db, scoring, dir } = await freshModules('foreign-package');
    try {
      seedRelease(db, 'v2026.6.10', '2026-06-10T00:00:00Z');
      activateCatalog(db, ['v2026.6.10']);
      db.upsertAdvisory({
        advisory_key: 'GHSA-foreign:npm:other:<2026.6.11',
        ghsa_id: 'GHSA-foreign',
        cve_id: null,
        summary: 'Foreign package advisory',
        severity: 'high',
        html_url: 'https://example.test/advisory/GHSA-foreign',
        published_at: '2026-06-01T00:00:00Z',
        package_ecosystem: 'npm',
        package_name: 'other-package',
        vulnerable_version_range: '< 2026.6.11',
        patched_versions: '2026.6.11',
      });

      assert.throws(
        () => scoring.buildReleaseScoreRun({
          releases: [db.getRelease('v2026.6.10')],
          nowForRelease: () => Date.parse('2026-06-12T00:00:00Z'),
        }),
        /outside npm\/openclaw/,
      );
    } finally {
      releaseFreshModules(dir);
    }
  });

  it('deduplicates overlapping ranges for one GHSA/package without deleting audit rows', async () => {
    const { db, scoring, dir } = await freshModules('overlapping-range-dedup');
    try {
      seedRelease(db, 'v1.5.0', '2026-06-10T00:00:00Z');
      seedAdvisory(db, {
        key: 'GHSA-multi-range:npm:openclaw:<2.0.0',
        range: '< 2.0.0',
        patched: '2.0.0',
      });
      seedAdvisory(db, {
        key: 'GHSA-multi-range:npm:openclaw:>=1.0.0<2.0.0',
        range: '>= 1.0.0, < 2.0.0',
        patched: '2.0.0',
      });

      const keys = new Set([
        'GHSA-multi-range:npm:openclaw:<2.0.0',
        'GHSA-multi-range:npm:openclaw:>=1.0.0<2.0.0',
      ]);
      const rows = db.listAdvisories().filter((row: any) => keys.has(row.advisory_key));
      assert.equal(rows.length, 2);
      const signal = scoring.__releaseScoringTest.advisoryCveSignal(
        'v1.5.0',
        rows,
        ['v1.5.0'],
      );
      assert.equal(signal.affected, true);
      assert.equal(signal.load, 2);
    } finally {
      releaseFreshModules(dir);
    }
  });
});
