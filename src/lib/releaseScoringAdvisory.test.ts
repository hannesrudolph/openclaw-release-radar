import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-release-scoring-advisory-${name}-`)), 'radar.db');
}

async function freshModules(name: string) {
  const path = dbPath(name);
  process.env.DB_PATH = path;
  const db = await import(`./db.ts?release-scoring-advisory-${name}-${Date.now()}-${Math.random()}`);
  const scoring = await import(`./releaseScoring.ts?release-scoring-advisory-${name}-${Date.now()}-${Math.random()}`);
  return { db, scoring, dir: dirname(path) };
}

function seedRelease(db: any, tag: string, publishedAt: string) {
  db.upsertRelease({
    tag,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease: false,
    body: '',
  });
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

      const rows = db.listAdvisories().filter((row: any) => row.ghsa_id === 'GHSA-multi-range');
      assert.equal(rows.length, 2);

      const run = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v2026.6.10'), db.getRelease('v2026.6.1')],
        allFetchedTags: ['v2026.6.10', 'v2026.6.1'],
        stableTagsNewestFirst: ['v2026.6.10', 'v2026.6.1'],
        nowForRelease: () => Date.parse('2026-06-12T00:00:00Z'),
      });
      const byTag = new Map(run.scored.map((result: any) => [result.rel.tag, result]));

      assert.equal(byTag.get('v2026.6.10')?.conf.status, 'skip-cve');
      assert.equal(byTag.get('v2026.6.1')?.conf.status, 'skip-cve');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
