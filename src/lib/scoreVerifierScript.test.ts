import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const tsx = join(root, 'node_modules', '.bin', 'tsx');

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-score-verifier-${name}-`)), 'radar.db');
}

function emptyDotenvPath(path: string): string {
  const inheritedPath = process.env.DOTENV_CONFIG_PATH;
  if (inheritedPath) return inheritedPath;

  const fixturePath = join(dirname(path), 'empty.env');
  if (!existsSync(fixturePath)) {
    writeFileSync(fixturePath, '', { mode: 0o600 });
  }
  return fixturePath;
}

function catalogRelease(
  tag = 'v-wait',
  publishedAt = '2026-06-30T00:00:00Z',
  prerelease = false,
) {
  return {
    node_id: `R_${tag.replace(/[^A-Za-z0-9]/g, '_')}`,
    catalog_tag_commit_oid: createHash('sha1')
      .update(`score-verifier:${tag}`)
      .digest('hex'),
    tag,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/${tag}`,
    prerelease,
    body: '',
  };
}

async function freshDb(
  name: string,
  catalog: Array<ReturnType<typeof catalogRelease>> = [],
) {
  const path = dbPath(name);
  const initialized = spawnSync(tsx, [
    '-e',
    `
      import {
        db,
        replaceActiveReleaseCatalog,
        upsertReleaseCommit,
      } from './src/lib/db.ts';
      try {
        const catalog = JSON.parse(
          process.env.RADAR_SCORE_VERIFIER_FIXTURE_CATALOG ?? '[]',
        );
        if (catalog.length > 0) {
          replaceActiveReleaseCatalog(catalog, {
            capture: { source: 'test_fixture' },
          });
          for (const release of catalog) {
            upsertReleaseCommit({
              tag: release.tag,
              tag_commit_oid: release.catalog_tag_commit_oid,
              committed_at: release.published_at,
            });
          }
        }
      } finally {
        db.close();
      }
    `,
  ], {
    cwd: root,
    env: {
      ...process.env,
      DB_PATH: path,
      DOTENV_CONFIG_PATH: emptyDotenvPath(path),
      RADAR_DB_BOOTSTRAP_MODE: 'fresh',
      RADAR_DB_READ_ONLY: '0',
      RADAR_SCORE_VERIFIER_FIXTURE_CATALOG: JSON.stringify(catalog),
    },
    encoding: 'utf8',
  });
  assert.equal(initialized.status, 0, `${initialized.stdout}\n${initialized.stderr}`);
  const db = new DatabaseSync(path);
  return { db, path, dir: dirname(path) };
}

function runVerifier(path: string, args = ['--all']) {
  return spawnSync(tsx, ['scripts/verify-new-scoring.mjs', ...args], {
    cwd: root,
    env: {
      ...process.env,
      DB_PATH: path,
      DOTENV_CONFIG_PATH: emptyDotenvPath(path),
      RADAR_DB_BOOTSTRAP_MODE: 'existing',
    },
    encoding: 'utf8',
  });
}

function seedWaitScore(db: DatabaseSync, tag: string, reason: string) {
  db.prepare(`
    UPDATE releases
    SET final_score=NULL,
        negative_issues=0,
        positive_issues=0,
        state='wait',
        recommended=0,
        score_reason=?,
        broken_surfaces='[]',
        closed_serious_fixed=0,
        opened_serious_during_reign=0,
        scored_at='2026-06-30T01:00:00Z'
    WHERE tag=?
  `).run(reason, tag);
}

function seedWaitAudit(db: DatabaseSync, tag: string) {
  db.prepare(`
    INSERT INTO release_score_audits (
      release_tag, scored_at, score_model_version, prompt_version, final_score,
      status, band, recommended, input_json, components_json,
      issue_evidence_json, gate_evidence_json, source_identity_json
    )
    VALUES (?, ?, ?, ?, NULL, 'wait', 'wait', 0, ?, '{}', '{}', '{}', '{}')
  `).run(
    tag,
    '2026-06-30T01:00:00Z',
    'test-model',
    0,
    JSON.stringify({ rawIssueCount: 0, classifiedIssueCount: 0 }),
  );
}

function setScorePersistence(db: DatabaseSync, value: Record<string, unknown>) {
  db.prepare(`
    INSERT INTO meta(key, value)
    VALUES('score_persistence_last_run', ?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `).run(JSON.stringify(value));
}

describe('score verifier script', () => {
  it('does not create a nonexistent database while entering read-only mode', () => {
    const dir = mkdtempSync(join(tmpdir(), 'radar-score-verifier-missing-'));
    const path = join(dir, 'does-not-exist.db');
    try {
      const result = runVerifier(path);

      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /Database not found/);
      assert.equal(existsSync(path), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('includes audited null-score stable rows when --all is used', async () => {
    const { db, path, dir } = await freshDb(
      'null-score-stable',
      [catalogRelease()],
    );
    try {
      seedWaitScore(db, 'v-wait', 'only 1.0d old - no settle signal yet');
      db.close();

      const result = runVerifier(path);

      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /v-wait: audited stable release is missing release_score_audits row/);
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects an empty active monitored release catalog', async () => {
    const { db, path, dir } = await freshDb(
      'zero-coverage',
      [catalogRelease('v-zero-coverage-beta', '2026-06-30T00:00:00Z', true)],
    );
    try {
      db.close();
      const result = runVerifier(path);

      assert.notEqual(result.status, 0);
      assert.match(
        `${result.stdout}\n${result.stderr}`,
        /requires at least one active monitored stable release/,
      );
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects an active monitored stable release with no scored audit disposition', async () => {
    const { db, path, dir } = await freshDb(
      'missing-disposition',
      [catalogRelease('v-unscored')],
    );
    try {
      db.close();
      const result = runVerifier(path);

      assert.notEqual(result.status, 0);
      assert.match(
        `${result.stdout}\n${result.stderr}`,
        /v-unscored: audited stable release is missing release_score_audits row/,
      );
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('treats an audited null-score wait row as a valid monitored disposition', async () => {
    const { db, path, dir } = await freshDb(
      'audited-wait-disposition',
      [catalogRelease('v-wait-audited')],
    );
    try {
      seedWaitScore(db, 'v-wait-audited', 'only 1.0h old - no settle signal yet');
      seedWaitAudit(db, 'v-wait-audited');
      db.close();

      const result = runVerifier(path);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.match(output, /v-wait-audited/);
      assert.doesNotMatch(output, /null final_score is only valid/);
      assert.doesNotMatch(output, /missing release_score_audits row/);
      assert.doesNotMatch(output, /missing valid scored_at/);
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects an unsealed current score audit', async () => {
    const { db, path, dir } = await freshDb(
      'unsealed-audit',
      [catalogRelease('v-unsealed')],
    );
    try {
      seedWaitScore(db, 'v-unsealed', 'only 1.0h old - no settle signal yet');
      seedWaitAudit(db, 'v-unsealed');
      setScorePersistence(db, {
        schemaVersion: 2,
        releaseTags: ['v-unsealed'],
        recommendedTag: null,
      });
      db.close();

      const result = runVerifier(path);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.notEqual(result.status, 0);
      assert.match(
        output,
        /score publication: current audit v-unsealed does not match the recorded sealed history tip/,
      );
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('does not let score persistence releaseTags omit active stable releases from --all', async () => {
    const { db, path, dir } = await freshDb(
      'omitted-active-tag',
      [
        catalogRelease('v-included', '2026-06-30T00:00:00Z'),
        catalogRelease('v-omitted', '2026-06-29T00:00:00Z'),
      ],
    );
    try {
      setScorePersistence(db, {
        schemaVersion: 2,
        releaseTags: ['v-included'],
        recommendedTag: null,
      });
      db.close();

      const result = runVerifier(path);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.notEqual(result.status, 0);
      assert.match(
        output,
        /score persistence releaseTags must exactly match the active stable catalog .*missing: v-omitted/,
      );
      assert.match(
        output,
        /v-omitted: audited stable release is missing release_score_audits row/,
      );
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects non-positive and non-integer limits', async () => {
    const { db, path, dir } = await freshDb('invalid-limits');
    try {
      db.close();
      for (const args of [
        ['--limit', '0'],
        ['--limit', '-1'],
        ['--limit', '1.5'],
        ['--limit', 'not-a-number'],
        ['--limit'],
      ]) {
        const result = runVerifier(path, args);
        assert.notEqual(result.status, 0, args.join(' '));
        assert.match(
          `${result.stdout}\n${result.stderr}`,
          /--limit must be (?:a positive integer|followed by a positive integer)/,
          args.join(' '),
        );
      }
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('computes the recommendation from the full active catalog before applying --limit', async () => {
    const { db, path, dir } = await freshDb(
      'global-recommendation',
      [
        catalogRelease('v2026.6.2', '2026-06-29T00:00:00Z'),
        catalogRelease('v2026.6.1', '2026-06-20T00:00:00Z'),
      ],
    );
    try {
      db.prepare(`
        UPDATE releases
        SET scored_at='2026-06-30T00:00:00Z',
            hours_to_next_stable=CASE
              WHEN tag='v2026.6.1' THEN 240
              ELSE NULL
            END
        WHERE tag IN ('v2026.6.2', 'v2026.6.1')
      `).run();
      db.close();

      const result = runVerifier(path, ['--limit', '1']);
      const output = `${result.stdout}\n${result.stderr}`;

      assert.match(output, /Recommended: v2026\.6\.1/);
    } finally {
      try { db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
