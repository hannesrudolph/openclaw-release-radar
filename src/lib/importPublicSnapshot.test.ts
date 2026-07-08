import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { describe, it } from 'node:test';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const importer = join(root, 'scripts', 'import-public-snapshot.mjs');

describe('public snapshot import tombstone', () => {
  it('preserves a score created while the snapshot response is delayed', () => {
    const packageJson = JSON.parse(
      readFileSync(join(root, 'package.json'), 'utf8'),
    ) as { scripts?: Record<string, string> };
    assert.equal(packageJson.scripts?.['import:public-snapshot'], undefined);

    const guardedWorkerDatabasePath =
      process.env.RADAR_TEST_WORKER_DB_PATH;
    assert.ok(
      guardedWorkerDatabasePath,
      'public snapshot tombstone test requires an assigned worker database',
    );
    const guardedTempRoot = dirname(guardedWorkerDatabasePath);
    const dir = mkdtempSync(
      join(guardedTempRoot, 'radar-public-snapshot-tombstone-'),
    );
    try {
      const protectedDotenvPath = process.env.DOTENV_CONFIG_PATH;
      assert.ok(
        protectedDotenvPath,
        'public snapshot tombstone test requires the guarded empty dotenv artifact',
      );
      assert.equal(
        readFileSync(protectedDotenvPath).length,
        0,
        'guarded test dotenv artifact must be empty',
      );
      const fetchGuardPath = join(dir, 'fetch-guard.mjs');
      const defaultMissingDbPath = join(dir, 'default-missing-private.db');
      const legacyMissingDbPath = join(dir, 'legacy-missing-private.db');
      const existingDbPath = join(dir, 'existing-private.db');
      writeFileSync(fetchGuardPath, `
        import { writeFileSync } from 'node:fs';

        globalThis.fetch = (...args) => {
          writeFileSync(process.env.PUBLIC_SNAPSHOT_FETCH_MARKER, String(args[0]));
          throw new Error('public snapshot fetch guard called');
        };
      `);

      const database = new DatabaseSync(existingDbPath);
      database.exec(`
        CREATE TABLE sentinel (
          id INTEGER PRIMARY KEY,
          value TEXT NOT NULL
        );
        INSERT INTO sentinel (id, value) VALUES (1, 'preserve-local-data');
      `);
      database.close();
      const existingArtifactsBefore = databaseArtifacts(existingDbPath);
      const existingFingerprintBefore =
        captureSqliteFamilyFingerprint(existingDbPath);
      const legacyArgs = [
        '--allow-overwrite-local-releases',
        '--allow-overwrite-scored-local-releases',
        'https://argument.example/api/public',
      ];
      const legacyEnv = {
        ALLOW_PUBLIC_SNAPSHOT_IMPORT: 'true',
        ALLOW_SCORED_PUBLIC_SNAPSHOT_IMPORT: 'true',
        PUBLIC_SNAPSHOT_URL: 'https://environment.example/api/public',
      };
      const scenarios = [
        {
          name: 'default invocation',
          dbPath: defaultMissingDbPath,
          markerPath: join(dir, 'default-fetch-called'),
          args: [],
          env: {},
        },
        {
          name: 'legacy overrides with a missing database',
          dbPath: legacyMissingDbPath,
          markerPath: join(dir, 'legacy-missing-fetch-called'),
          args: legacyArgs,
          env: legacyEnv,
        },
        {
          name: 'legacy overrides with an existing database',
          dbPath: existingDbPath,
          markerPath: join(dir, 'legacy-existing-fetch-called'),
          args: legacyArgs,
          env: legacyEnv,
        },
      ];

      for (const scenario of scenarios) {
        const env = cleanLegacyEnvironment();
        Object.assign(env, scenario.env, {
          DB_PATH: scenario.dbPath,
          DOTENV_CONFIG_PATH: protectedDotenvPath,
          PUBLIC_SNAPSHOT_FETCH_MARKER: scenario.markerPath,
          RADAR_DB_BOOTSTRAP_MODE:
            scenario.dbPath === existingDbPath ? 'existing' : 'fresh',
        });
        const result = spawnSync(process.execPath, [
          `--import=${pathToFileURL(fetchGuardPath).href}`,
          importer,
          ...scenario.args,
        ], {
          cwd: root,
          encoding: 'utf8',
          env,
          timeout: 5_000,
        });

        assert.equal(result.error, undefined, scenario.name);
        assert.ok(
          typeof result.status === 'number' && result.status > 0,
          `${scenario.name}: expected a positive exit status`,
        );
        assert.equal(result.signal, null, scenario.name);
        assert.equal(result.stdout, '', scenario.name);
        assert.match(
          result.stderr,
          /Public snapshot import is permanently disabled/,
          scenario.name,
        );
        assert.match(
          result.stderr,
          /may never write or replace the authoritative GitHub release catalog/,
          scenario.name,
        );
        assert.match(
          result.stderr,
          /in any configured or live database/,
          scenario.name,
        );
        assert.match(result.stderr, /npm run scrape:upstream/, scenario.name);
        assert.equal(existsSync(scenario.markerPath), false, scenario.name);
      }

      assert.deepEqual(databaseArtifacts(defaultMissingDbPath), []);
      assert.deepEqual(databaseArtifacts(legacyMissingDbPath), []);
      assert.deepEqual(databaseArtifacts(existingDbPath), existingArtifactsBefore);
      assert.deepEqual(
        captureSqliteFamilyFingerprint(existingDbPath),
        existingFingerprintBefore,
      );

      const preserved = new DatabaseSync(existingDbPath, { readOnly: true });
      try {
        const row = preserved.prepare(`
          SELECT value
          FROM sentinel
          WHERE id=1
        `).get() as { value: string } | undefined;
        assert.equal(row?.value, 'preserve-local-data');
      } finally {
        preserved.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function cleanLegacyEnvironment(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env.ALLOW_PUBLIC_SNAPSHOT_IMPORT;
  delete env.ALLOW_SCORED_PUBLIC_SNAPSHOT_IMPORT;
  delete env.PUBLIC_SNAPSHOT_URL;
  return env;
}

function databaseArtifacts(dbPath: string): string[] {
  const dbName = basename(dbPath);
  return readdirSync(dirname(dbPath))
    .filter((name) => name.startsWith(dbName))
    .sort();
}

function captureSqliteFamilyFingerprint(dbPath: string): Array<Record<string, unknown>> {
  return [
    dbPath,
    `${dbPath}-wal`,
    `${dbPath}-shm`,
    `${dbPath}-journal`,
  ].map((path) => {
    try {
      const stats = lstatSync(path);
      assert.equal(stats.isSymbolicLink(), false, path);
      assert.equal(stats.isFile(), true, path);
      return {
        path,
        exists: true,
        dev: stats.dev,
        ino: stats.ino,
        mode: stats.mode,
        size: stats.size,
        mtimeMs: stats.mtimeMs,
        ctimeMs: stats.ctimeMs,
        digest: createHash('sha256').update(readFileSync(path)).digest('hex'),
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      return {
        path,
        exists: false,
      };
    }
  });
}
