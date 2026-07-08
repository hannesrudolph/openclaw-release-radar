import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import {
  canonicalManualScope,
  exactIngestionFailureMatches,
  manualScorePlan,
  supersedeExactIngestionEvidenceFailures,
} from '../../scripts/lib/manual-command-scope.mjs';
import {
  configuredApplicationDatabasePaths,
  parseQualityRefreshArgs,
  validateQualityRefreshDatabase,
} from '../../scripts/lib/quality-refresh-cli.mjs';

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
    const qualityDatabase = join(repositoryRoot, 'quality.db');
    const originalBootstrapMode = process.env.RADAR_DB_BOOTSTRAP_MODE;
    try {
      process.env.RADAR_DB_BOOTSTRAP_MODE = 'existing';
      writeFileSync(qualityDatabase, 'existing', { flag: 'wx' });
      assert.deepEqual(
        parseQualityRefreshArgs(
          ['--db-path', './quality.db'],
          { cwd: repositoryRoot },
        ),
        {
          databasePath: qualityDatabase,
          resumeExisting: false,
        },
      );
      assert.deepEqual(
        parseQualityRefreshArgs(
          ['--db-path', './quality.db', '--resume-existing'],
          { cwd: repositoryRoot },
        ),
        {
          databasePath: qualityDatabase,
          resumeExisting: true,
        },
      );
      assert.equal(process.env.RADAR_DB_BOOTSTRAP_MODE, 'existing');

      for (const args of [
        [],
        ['--db-path'],
        ['--db-path', ''],
        ['--db-path', '--other'],
        ['--db-path=./quality.db'],
        ['--resume-existing'],
        ['--db-path', './quality.db', '--extra'],
        ['--db-path', './quality.db', '--resume-existing=true'],
        ['--db-path', './quality.db', '--resume-existing', '--extra'],
        ['--db-path', './quality.db', '--resume-existing', '--resume-existing'],
        ['--db-path', './quality.db', '--db-path', './other.db'],
        ['--resume-existing', '--db-path', './quality.db'],
      ]) {
        assert.throws(
          () => parseQualityRefreshArgs(args, {
            cwd: repositoryRoot,
          }),
          /Usage: refresh:quality/,
        );
      }
    } finally {
      if (originalBootstrapMode === undefined) {
        delete process.env.RADAR_DB_BOOTSTRAP_MODE;
      } else {
        process.env.RADAR_DB_BOOTSTRAP_MODE = originalBootstrapMode;
      }
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  it('validates complete fresh and resume SQLite families without mutation', () => {
    const repositoryRoot =
      mkdtempSync(join(tmpdir(), 'radar-quality-refresh-family-'));
    const qualityDatabase = join(repositoryRoot, 'quality.db');
    const family = [
      qualityDatabase,
      `${qualityDatabase}-wal`,
      `${qualityDatabase}-shm`,
      `${qualityDatabase}-journal`,
    ];
    try {
      validateQualityRefreshDatabase({
        databasePath: qualityDatabase,
        repositoryRoot,
      });

      for (const familyMember of family) {
        writeFileSync(familyMember, 'stale', { flag: 'wx' });
        try {
          assert.throws(
            () => validateQualityRefreshDatabase({
              databasePath: qualityDatabase,
              repositoryRoot,
            }),
            /SQLite family member already exists/,
          );
        } finally {
          rmSync(familyMember, { force: true });
        }
      }

      assert.throws(
        () => validateQualityRefreshDatabase({
          databasePath: qualityDatabase,
          repositoryRoot,
          resumeExisting: true,
        }),
        /requires an existing main database/,
      );

      writeFileSync(qualityDatabase, 'main', { flag: 'wx' });
      for (const [index, sidecar] of family.slice(1).entries()) {
        writeFileSync(sidecar, `sidecar-${index}`, { flag: 'wx' });
      }
      validateQualityRefreshDatabase({
        databasePath: qualityDatabase,
        repositoryRoot,
        resumeExisting: true,
      });
      assert.equal(readFileSync(qualityDatabase, 'utf8'), 'main');
      for (const [index, sidecar] of family.slice(1).entries()) {
        assert.equal(readFileSync(sidecar, 'utf8'), `sidecar-${index}`);
        rmSync(sidecar);
      }

      const symlinkMain = join(repositoryRoot, 'symlink-main.db');
      symlinkSync(qualityDatabase, symlinkMain);
      assert.throws(
        () => validateQualityRefreshDatabase({
          databasePath: symlinkMain,
          repositoryRoot,
          resumeExisting: true,
        }),
        /main database must be a regular non-symlink file/,
      );

      const directoryMain = join(repositoryRoot, 'directory-main.db');
      mkdirSync(directoryMain);
      assert.throws(
        () => validateQualityRefreshDatabase({
          databasePath: directoryMain,
          repositoryRoot,
          resumeExisting: true,
        }),
        /main database must be a regular non-symlink file/,
      );

      symlinkSync(qualityDatabase, `${qualityDatabase}-wal`);
      assert.throws(
        () => validateQualityRefreshDatabase({
          databasePath: qualityDatabase,
          repositoryRoot,
          resumeExisting: true,
        }),
        /SQLite sidecar must be a regular non-symlink file/,
      );
      rmSync(`${qualityDatabase}-wal`);

      mkdirSync(`${qualityDatabase}-shm`);
      assert.throws(
        () => validateQualityRefreshDatabase({
          databasePath: qualityDatabase,
          repositoryRoot,
          resumeExisting: true,
        }),
        /SQLite sidecar must be a regular non-symlink file/,
      );
    } finally {
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  it('rejects resolved-path and inode aliases of the live SQLite family', () => {
    const repositoryRoot =
      mkdtempSync(join(tmpdir(), 'radar-quality-refresh-alias-'));
    const dataDir = join(repositoryRoot, 'data');
    const configuredDir = join(repositoryRoot, 'configured');
    const customEnvDir = join(repositoryRoot, 'config');
    const defaultDatabase = join(dataDir, 'radar.db');
    const inheritedDatabase = join(configuredDir, 'inherited.db');
    const repositoryEnvDatabase = join(configuredDir, 'repository-env.db');
    const customEnvDatabase = join(configuredDir, 'custom-env.db');
    const customEnvPath = join(customEnvDir, 'runtime.env');
    const suffixes = ['', '-wal', '-shm', '-journal'];
    try {
      mkdirSync(dataDir, { recursive: true });
      mkdirSync(configuredDir, { recursive: true });
      mkdirSync(customEnvDir, { recursive: true });
      writeFileSync(
        join(repositoryRoot, '.env'),
        'DB_PATH=./configured/repository-env.db\n',
      );
      writeFileSync(
        customEnvPath,
        'DB_PATH=file:configured/custom-env.db?mode=rw\n',
      );

      const configuredDatabases = configuredApplicationDatabasePaths({
        repositoryRoot,
        environmentDatabasePath: inheritedDatabase,
        dotenvConfigPath: customEnvPath,
      });
      assert.deepEqual(
        new Set(configuredDatabases),
        new Set([
          defaultDatabase,
          inheritedDatabase,
          repositoryEnvDatabase,
          customEnvDatabase,
        ]),
      );

      for (const configuredDatabase of configuredDatabases) {
        for (const suffix of suffixes) {
          const familyMember = `${configuredDatabase}${suffix}`;
          writeFileSync(
            familyMember,
            `configured:${familyMember}`,
            { flag: 'wx' },
          );
        }
      }

      for (const databasePath of configuredDatabases) {
        assert.throws(
          () => validateQualityRefreshDatabase({
            databasePath,
            repositoryRoot,
            resumeExisting: true,
            environmentDatabasePath: inheritedDatabase,
            dotenvConfigPath: customEnvPath,
          }),
          /refuses configured application database SQLite family aliases/,
        );
      }
      assert.throws(
        () => validateQualityRefreshDatabase({
          databasePath: inheritedDatabase,
          repositoryRoot,
          environmentDatabasePath: inheritedDatabase,
          dotenvConfigPath: customEnvPath,
        }),
        /refuses configured application database SQLite family aliases/,
      );

      const symlinkAlias = join(repositoryRoot, 'configured-symlink.db');
      const hardlinkAlias = join(repositoryRoot, 'configured-hardlink.db');
      const inheritedAlias = join(repositoryRoot, 'inherited-symlink.db');
      symlinkSync(repositoryEnvDatabase, symlinkAlias);
      linkSync(customEnvDatabase, hardlinkAlias);
      symlinkSync(inheritedDatabase, inheritedAlias);
      for (const databasePath of [
        symlinkAlias,
        hardlinkAlias,
        inheritedAlias,
      ]) {
        assert.throws(
          () => validateQualityRefreshDatabase({
            databasePath,
            repositoryRoot,
            resumeExisting: true,
            environmentDatabasePath: inheritedDatabase,
            dotenvConfigPath: customEnvPath,
          }),
          /refuses configured application database SQLite family aliases/,
        );
      }

      for (const [requestedIndex, requestedSuffix] of suffixes.entries()) {
        for (const [configuredIndex, configuredSuffix] of suffixes.entries()) {
          const aliasDatabase = join(
            repositoryRoot,
            `cross-alias-${requestedIndex}-${configuredIndex}.db`,
          );
          if (requestedSuffix !== '') {
            writeFileSync(aliasDatabase, 'quality-main', { flag: 'wx' });
          }
          linkSync(
            `${customEnvDatabase}${configuredSuffix}`,
            `${aliasDatabase}${requestedSuffix}`,
          );
          assert.throws(
            () => validateQualityRefreshDatabase({
              databasePath: aliasDatabase,
              repositoryRoot,
              resumeExisting: true,
              environmentDatabasePath: inheritedDatabase,
              dotenvConfigPath: customEnvPath,
            }),
            /refuses configured application database SQLite family aliases/,
          );
        }
      }
    } finally {
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  it('fails closed for missing configured paths through equivalent macOS parents', () => {
    const repositoryRoot =
      mkdtempSync(join(tmpdir(), 'radar-quality-refresh-missing-alias-'));
    const canonicalParent = join(repositoryRoot, 'canonical-parent');
    const symlinkParent = join(repositoryRoot, 'symlink-parent');
    try {
      mkdirSync(canonicalParent);
      symlinkSync(canonicalParent, symlinkParent, 'dir');
      writeFileSync(
        join(repositoryRoot, '.env'),
        `DB_PATH=${join(canonicalParent, 'missing.db')}\n`,
      );
      for (const requestedName of ['missing.db', 'missing.db-shm']) {
        assert.throws(
          () => validateQualityRefreshDatabase({
            databasePath: join(symlinkParent, requestedName),
            repositoryRoot,
          }),
          /refuses configured application database SQLite family aliases/,
        );
      }

      writeFileSync(
        join(repositoryRoot, '.env'),
        `DB_PATH=${join(repositoryRoot, 'Missing-Parent', 'Radar.db')}\n`,
      );
      assert.throws(
        () => validateQualityRefreshDatabase({
          databasePath: join(
            repositoryRoot,
            'missing-parent',
            'radar.db-journal',
          ),
          repositoryRoot,
          platform: 'darwin',
        }),
        /refuses configured application database SQLite family aliases/,
      );

      const home = homedir();
      if (process.platform === 'darwin' && home.startsWith('/Users/')) {
        const logicalPath = join(
          home,
          `.radar-missing-${basename(repositoryRoot)}.db`,
        );
        const firmlinkPath = `/System/Volumes/Data${logicalPath}`;
        writeFileSync(
          join(repositoryRoot, '.env'),
          `DB_PATH=${logicalPath}\n`,
        );
        assert.throws(
          () => validateQualityRefreshDatabase({
            databasePath: `${firmlinkPath}-wal`,
            repositoryRoot,
          }),
          /refuses configured application database SQLite family aliases/,
        );
      }
    } finally {
      rmSync(repositoryRoot, { recursive: true, force: true });
    }
  });

  it('keeps configured-path capture and admission inside the writer-lock flow', () => {
    const source = readFileSync(
      resolve(process.cwd(), 'scripts/refresh-quality-db.mjs'),
      'utf8',
    );
    const configuredCaptureIndex = source.indexOf(
      'const configuredApplicationEnvironment',
    );
    const databaseOverrideIndex = source.indexOf(
      'process.env.DB_PATH = databasePath',
    );
    const forceFreshIndex = source.indexOf(
      "process.env.RADAR_DB_BOOTSTRAP_MODE = 'fresh'",
    );
    const writerLockIndex = source.indexOf(
      'const writerLock = acquireRepositoryDatabaseWriterLock',
    );
    const admissionIndex = source.indexOf(
      'validateQualityRefreshDatabase({',
    );
    const resumeModeIndex = source.indexOf(
      "process.env.RADAR_DB_BOOTSTRAP_MODE = 'existing'",
    );
    const databaseImportIndex = source.indexOf(
      "await import('../src/lib/db.ts')",
    );

    assert.ok(
      configuredCaptureIndex >= 0 &&
        configuredCaptureIndex < databaseOverrideIndex &&
        databaseOverrideIndex < forceFreshIndex &&
        forceFreshIndex < writerLockIndex &&
        writerLockIndex < admissionIndex &&
        admissionIndex < resumeModeIndex &&
        resumeModeIndex < databaseImportIndex,
      'refresh must capture configuration, force fresh intent, lock, admit, ' +
      'select explicit resume intent, then import db.ts',
    );
    assert.match(
      source,
      /environmentDatabasePath: configuredApplicationEnvironment\.databasePath/,
    );
    assert.match(
      source,
      /dotenvConfigPath: configuredApplicationEnvironment\.dotenvConfigPath/,
    );
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
