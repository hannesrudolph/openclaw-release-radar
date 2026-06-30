import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-score-verifier-${name}-`)), 'radar.db');
}

async function freshDb(name: string) {
  const path = dbPath(name);
  process.env.DB_PATH = path;
  const db = await import(`./db.ts?score-verifier-${name}-${Date.now()}-${Math.random()}`);
  return { db, path, dir: dirname(path) };
}

function seedRelease(db: any, tag = 'v-wait') {
  db.upsertRelease({
    tag,
    name: tag,
    published_at: '2026-06-30T00:00:00Z',
    html_url: `https://example.test/${tag}`,
    prerelease: false,
    body: '',
  });
}

describe('score verifier script', () => {
  it('includes audited null-score stable rows when --all is used', async () => {
    const { db, path, dir } = await freshDb('null-score-stable');
    try {
      seedRelease(db);
      db.updateReleaseScore({
        tag: 'v-wait',
        final_score: null,
        negative_issues: 0,
        positive_issues: 0,
        state: 'wait',
        recommended: 0,
        score_reason: 'only 1.0d old - no settle signal yet',
        broken_surfaces: '[]',
        closed_serious_fixed: 0,
        opened_serious_during_reign: 0,
        scored_at: '2026-06-30T01:00:00Z',
      });
      db.db.close();

      const result = spawnSync('npx', ['tsx', 'scripts/verify-new-scoring.mjs', '--all'], {
        cwd: root,
        env: { ...process.env, DB_PATH: path },
        encoding: 'utf8',
      });

      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /v-wait: audited stable release is missing release_score_audits row/);
    } finally {
      try { db.db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
