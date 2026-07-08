import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { describe, it } from 'node:test';

const root = fileURLToPath(new URL('../..', import.meta.url));
const childTimeoutMs = 30_000;
const childOutputLimitBytes = 1024 * 1024;

type ChildResult = {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  error: Error | undefined;
};

function captureChildOutput(
  target: Buffer,
  capturedBytes: number,
  chunk: Buffer,
): number {
  const writableBytes = Math.min(
    chunk.length,
    target.length - capturedBytes,
  );
  if (writableBytes > 0) {
    chunk.copy(target, capturedBytes, 0, writableBytes);
  }
  return capturedBytes + writableBytes;
}

function childError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

async function spawnChild(
  command: string,
  args: string[],
  options: {
    cwd: string;
    env: NodeJS.ProcessEnv;
  },
): Promise<ChildResult> {
  return await new Promise((resolve) => {
    const stdoutBuffer = Buffer.alloc(childOutputLimitBytes);
    const stderrBuffer = Buffer.alloc(childOutputLimitBytes);
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let processError: Error | undefined;
    let timeoutError: Error | undefined;
    const launch = () => spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ['ignore', 'pipe', 'pipe'] as const,
    });
    let child: ReturnType<typeof launch>;

    try {
      child = launch();
    } catch (error) {
      resolve({
        status: null,
        signal: null,
        stdout: '',
        stderr: '',
        error: childError(error),
      });
      return;
    }

    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBytes = captureChildOutput(stdoutBuffer, stdoutBytes, chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrBytes = captureChildOutput(stderrBuffer, stderrBytes, chunk);
    });
    child.once('error', (error) => {
      processError = error;
    });

    const timeout = setTimeout(() => {
      timeoutError = new Error(
        `Child process timed out after ${childTimeoutMs}ms`,
      );
      (timeoutError as NodeJS.ErrnoException).code = 'ETIMEDOUT';
      try {
        child.kill('SIGKILL');
      } catch (error) {
        processError = childError(error);
      }
    }, childTimeoutMs);

    child.once('close', (status, signal) => {
      clearTimeout(timeout);
      resolve({
        status,
        signal,
        stdout: stdoutBuffer.subarray(0, stdoutBytes).toString('utf8'),
        stderr: stderrBuffer.subarray(0, stderrBytes).toString('utf8'),
        error: timeoutError ?? processError,
      });
    });
  });
}

function assertChildCompleted(
  label: string,
  result: {
    error?: Error;
    signal: NodeJS.Signals | null;
  },
): void {
  if (!result.error) return;
  const code = (result.error as NodeJS.ErrnoException).code;
  if (code === 'ETIMEDOUT') {
    throw new Error(
      `${label} timed out after ${childTimeoutMs}ms and was terminated with SIGKILL`,
      { cause: result.error },
    );
  }
  throw new Error(`${label} failed to launch: ${result.error.message}`, {
    cause: result.error,
  });
}

function emptyDotenvPath(dbPath: string): string {
  const inheritedPath = process.env.DOTENV_CONFIG_PATH;
  if (inheritedPath) return inheritedPath;

  const path = join(dirname(dbPath), 'empty.env');
  if (!existsSync(path)) {
    writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
  }
  return path;
}

async function runScript(
  script: string,
  args: string[],
  options: {
    dbPath?: string;
    env?: Record<string, string>;
  } = {},
) {
  const dir = options.dbPath
    ? null
    : mkdtempSync(join(tmpdir(), 'radar-manual-backfill-cli-'));
  const dbPath = options.dbPath ?? join(dir!, 'radar.db');
  const result = await spawnChild(
    process.execPath,
    ['--import=tsx', join(root, 'scripts', script), ...args],
    {
      cwd: root,
      env: {
        ...process.env,
        DB_PATH: dbPath,
        DOTENV_CONFIG_PATH: emptyDotenvPath(dbPath),
        RADAR_DB_BOOTSTRAP_MODE: options.dbPath ? 'existing' : 'fresh',
        GITHUB_TOKEN: '',
        OPENAI_API_KEY: '',
        RELEASES_LIMIT: '10',
        CLASSIFY_CONCURRENCY: '10',
        ...options.env,
      },
    },
  );
  assertChildCompleted(`scripts/${script}`, result);
  return { dbPath, dir, result };
}

function testCatalogRelease(tag: string, prerelease = false) {
  const publishedAt = '2026-07-01T00:00:00Z';
  return {
    node_id: `release-node:${tag}`,
    catalog_tag_commit_oid: createHash('sha1')
      .update(`manual-backfill-cli:${tag}`)
      .digest('hex'),
    tag,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/releases/${encodeURIComponent(tag)}`,
    prerelease,
    body: null,
  };
}

async function seededReleaseDb(
  name: string,
  tag: string,
  active: boolean,
  prerelease = false,
) {
  const dir = mkdtempSync(join(tmpdir(), `radar-manual-backfill-${name}-`));
  const path = join(dir, 'radar.db');
  const release = testCatalogRelease(tag, prerelease);
  const replacement = testCatalogRelease(`fixture-active-${name}`);
  const catalogs = active ? [[release]] : [[release], [replacement]];
  const source = [
    `const namespace = await import(${JSON.stringify(
      pathToFileURL(join(root, 'src', 'lib', 'db.ts')).href,
    )});`,
    'const database = namespace.default ?? namespace;',
    'try {',
    `  for (const catalog of ${JSON.stringify(catalogs)}) {`,
    '    database.replaceActiveReleaseCatalog(catalog, {',
    "      capture: { source: 'test_fixture' },",
    '    });',
    '  }',
    `  database.setMeta('issue_crawl_last_run', JSON.stringify(${JSON.stringify({
      schemaVersion: 4,
      repository: 'openclaw/openclaw',
      stopReason: 'page_cap',
    })}));`,
    '} finally {',
    '  database.db.close();',
    '}',
  ].join('\n');
  const result = await spawnChild(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '--eval', source],
    {
      cwd: root,
      env: {
        ...process.env,
        DB_PATH: path,
        DOTENV_CONFIG_PATH: emptyDotenvPath(path),
        RADAR_DB_BOOTSTRAP_MODE: 'fresh',
      },
    },
  );
  assertChildCompleted(`manual backfill fixture ${name}`, result);
  assert.equal(result.status, 0, result.stderr);
  return { dir, path };
}

function databaseCount(path: string, table: string): number {
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    return Number(
      (database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count,
    );
  } finally {
    database.close();
  }
}

function fileSnapshot(path: string): {
  size: number;
  digest: string;
} | null {
  if (!existsSync(path)) return null;
  const descriptor = openSync(path, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const hash = createHash('sha256');
  let position = 0;
  try {
    while (true) {
      const bytesRead = readSync(
        descriptor,
        buffer,
        0,
        buffer.length,
        position,
      );
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
  } finally {
    closeSync(descriptor);
  }
  return {
    size: statSync(path).size,
    digest: hash.digest('hex'),
  };
}

function sqliteFamilySnapshot(path: string): Array<{
  size: number;
  digest: string;
} | null> {
  return [
    path,
    `${path}-wal`,
    `${path}-shm`,
    `${path}-journal`,
  ].map(fileSnapshot);
}

describe('manual backfill CLI guards', () => {
  it('rejects malformed options and nonpositive sizes before opening the database', async () => {
    const cases: Array<{
      script: string;
      args: string[];
      pattern: RegExp;
      env?: Record<string, string>;
    }> = [
      {
        script: 'backfill-closed-windows.mjs',
        args: ['--unknown'],
        pattern: /Unknown option --unknown/,
      },
      {
        script: 'backfill-closed-windows.mjs',
        args: ['--all=true'],
        pattern: /Boolean option --all does not accept a value/,
      },
      {
        script: 'backfill-closed-windows.mjs',
        args: ['--skip-score=false'],
        pattern: /Boolean option --skip-score does not accept a value/,
      },
      {
        script: 'backfill-closed-windows.mjs',
        args: ['--limit', '0'],
        pattern: /--limit must be a positive integer/,
      },
      {
        script: 'backfill-closed-windows.mjs',
        args: ['--concurrency=-2'],
        pattern: /--concurrency must be a positive integer/,
      },
      {
        script: 'backfill-closed-windows.mjs',
        args: ['v2099.7.1'],
        pattern: /Unexpected positional argument/,
      },
      {
        script: 'backfill-closed-windows.mjs',
        args: ['--tags', 'v2099.7.1,,v2099.7.2'],
        pattern: /--tags must contain comma-separated non-empty release tags/,
      },
      {
        script: 'backfill-issue-state-events.mjs',
        args: ['--unknown=value'],
        pattern: /Unknown option --unknown/,
      },
      {
        script: 'backfill-issue-state-events.mjs',
        args: ['--dry-run=true'],
        pattern: /Boolean option --dry-run does not accept a value/,
      },
      {
        script: 'backfill-issue-state-events.mjs',
        args: ['--limit=-1'],
        pattern: /--limit must be a positive integer/,
      },
      {
        script: 'backfill-issue-state-events.mjs',
        args: ['--batch-size', '0'],
        pattern: /--batch-size must be a positive integer/,
      },
      {
        script: 'backfill-issue-state-events.mjs',
        args: ['unexpected'],
        pattern: /Unexpected positional argument/,
      },
      {
        script: 'backfill-issue-comment-snapshots.mjs',
        args: ['--unknown'],
        pattern: /Unknown option --unknown/,
      },
      {
        script: 'backfill-issue-comment-snapshots.mjs',
        args: ['--all-scored=true'],
        pattern: /Boolean option --all-scored does not accept a value/,
      },
      {
        script: 'backfill-issue-comment-snapshots.mjs',
        args: ['--all-scored', 'v2099.7.1'],
        pattern: /Use either --all-scored or explicit release tags/,
      },
      {
        script: 'backfill-issue-comment-snapshots.mjs',
        args: ['invalid tag'],
        pattern: /Invalid release tag/,
      },
      {
        script: 'backfill-issue-comment-snapshots.mjs',
        args: [],
        env: { CLASSIFY_CONCURRENCY: '0' },
        pattern: /CLASSIFY_CONCURRENCY must be a positive integer/,
      },
    ];

    for (const testCase of cases) {
      const { dbPath, dir, result } = await runScript(
        testCase.script,
        testCase.args,
        { env: testCase.env },
      );
      try {
        assert.notEqual(result.status, 0, `${testCase.script} unexpectedly accepted ${testCase.args.join(' ')}`);
        assert.match(result.stderr, testCase.pattern);
        assert.equal(existsSync(dbPath), false, `${testCase.script} opened the DB before rejecting its CLI`);
      } finally {
        if (dir) rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it('rejects missing or inactive explicit tags before acquiring a lease or loading network stages', async () => {
    for (const testCase of [
      {
        name: 'closed-window-inactive',
        script: 'backfill-closed-windows.mjs',
        seedTag: 'v2099.7.1',
        args: ['--tags', 'v2099.7.1'],
        pattern: /not active audited stable releases: v2099\.7\.1/,
      },
      {
        name: 'closed-window-missing',
        script: 'backfill-closed-windows.mjs',
        seedTag: 'v2099.7.2',
        args: ['--tags', 'v2099.7.1'],
        pattern: /not active audited stable releases: v2099\.7\.1/,
      },
      {
        name: 'comment-snapshot-inactive',
        script: 'backfill-issue-comment-snapshots.mjs',
        seedTag: 'v2099.7.1',
        args: ['v2099.7.1'],
        pattern: /not active published stable releases: v2099\.7\.1/,
      },
      {
        name: 'comment-snapshot-missing',
        script: 'backfill-issue-comment-snapshots.mjs',
        seedTag: 'v2099.7.2',
        args: ['v2099.7.1'],
        pattern: /not active published stable releases: v2099\.7\.1/,
      },
      ...[
        'analyze-closure-proofs.mjs',
        'check-release-pr-reachability.mjs',
        'ingest-fix-provenance.mjs',
      ].flatMap((script) => [
        {
          name: `${script}-inactive`,
          script,
          seedTag: 'v2099.7.1',
          args: ['v2099.7.1'],
          pattern:
            /not an active stable release in the authorized GitHub catalog/,
        },
        {
          name: `${script}-prerelease`,
          script,
          seedTag: 'v2099.7.1-beta.2',
          args: ['v2099.7.1-beta.2'],
          pattern:
            /not an active stable release in the authorized GitHub catalog/,
          prerelease: true,
        },
      ]),
    ]) {
      const fixture = await seededReleaseDb(
        testCase.name,
        testCase.seedTag,
        testCase.name.endsWith('-missing') ||
          testCase.name.endsWith('-prerelease'),
        testCase.prerelease ?? false,
      );
      try {
        const { result } = await runScript(
          testCase.script,
          testCase.args,
          { dbPath: fixture.path },
        );
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, testCase.pattern);
        assert.doesNotMatch(result.stderr, /OPENAI|network|fetch/i);
        assert.equal(databaseCount(fixture.path, 'refresh_leases'), 0);
        assert.equal(databaseCount(fixture.path, 'ingestion_evidence_failures'), 0);
      } finally {
        rmSync(fixture.dir, { recursive: true, force: true });
      }
    }
  });

  it('opens configured databases read-only for dry-run execution', async () => {
    for (const testCase of [
      {
        name: 'closed-window-dry-run',
        script: 'backfill-closed-windows.mjs',
      },
      {
        name: 'issue-state-dry-run',
        script: 'backfill-issue-state-events.mjs',
      },
    ]) {
      const fixture = await seededReleaseDb(
        testCase.name,
        'v2099.7.1',
        false,
      );
      const before = sqliteFamilySnapshot(fixture.path);
      chmodSync(fixture.path, 0o400);
      try {
        const { result } = await runScript(testCase.script, ['--dry-run'], {
          dbPath: fixture.path,
          env: { RADAR_DB_READ_ONLY: '0' },
        });
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /"dryRun": true/);
        assert.deepEqual(sqliteFamilySnapshot(fixture.path), before);
      } finally {
        chmodSync(fixture.path, 0o600);
        rmSync(fixture.dir, { recursive: true, force: true });
      }
    }
  });

  it('orders parsing, leased scope derivation, revalidation, and failure recovery fail-closed', () => {
    const closed = readFileSync(join(root, 'scripts/backfill-closed-windows.mjs'), 'utf8');
    const state = readFileSync(join(root, 'scripts/backfill-issue-state-events.mjs'), 'utf8');
    const comments = readFileSync(
      join(root, 'scripts/backfill-issue-comment-snapshots.mjs'),
      'utf8',
    );

    const closedDbImport = closed.indexOf("await import('../src/lib/db.ts')");
    const stateDbImport = state.indexOf("await import('../src/lib/db.ts')");
    const closedReadOnly = closed.indexOf(
      "if (dryRun) process.env.RADAR_DB_READ_ONLY = '1';",
    );
    const stateReadOnly = state.indexOf(
      "if (dryRun) process.env.RADAR_DB_READ_ONLY = '1';",
    );
    assert.ok(closed.indexOf('parseClosedWindowArgs(process.argv.slice(2))') <
      closedReadOnly);
    assert.ok(closedReadOnly < closedDbImport);
    assert.ok(state.indexOf('parseIssueStateArgs(process.argv.slice(2))') <
      stateReadOnly);
    assert.ok(stateReadOnly < stateDbImport);
    assert.ok(comments.indexOf('parseCommentSnapshotArgs(process.argv.slice(2))') <
      comments.indexOf("await import('../src/lib/db.ts')"));

    const closedLease = closed.indexOf("acquireRenewableRefreshLease('backfill-closed-windows')");
    assert.ok(closedLease < closed.indexOf('const activeStableReleases = listReleasesDb'));
    const closedValidation = closed.indexOf('assertActiveAuditedStableReleaseTags(requestedTags)');
    assert.ok(closedValidation < closedLease);
    assert.ok(
      closed.indexOf('assertActiveAuditedStableReleaseTags(requestedTags)', closedValidation + 1) >
        closedLease,
    );

    const stateLease = state.indexOf(
      "acquireRenewableRefreshLease('backfill-issue-state-events')",
    );
    assert.ok(stateLease < state.indexOf('const issueNumbers = roughScoredIssueUniverse(limit)'));
    assert.ok(state.indexOf('const expectedRevisions = issueEvidenceRevisions(issueNumbers)') <
      state.indexOf('assertIssueEvidenceRevisions(expectedRevisions)'));

    const commentLease = comments.indexOf(
      "acquireRenewableRefreshLease('backfill-issue-comment-snapshots')",
    );
    assert.ok(commentLease < comments.indexOf('tags = releaseTags.length'));
    assert.ok(commentLease < comments.indexOf('issueNumbers = [...new Set'));
    const commentValidation = comments.indexOf('assertActiveStableReleaseTags(releaseTags)');
    assert.ok(commentValidation < commentLease);
    assert.ok(
      comments.indexOf('assertActiveStableReleaseTags(releaseTags)', commentValidation + 1) >
        commentLease,
    );

    const transaction = state.indexOf('runInWriteTransaction(() => {');
    const replacement = state.indexOf('replaceVerifiedIssueStateEventSnapshot(evidence)', transaction);
    const supersession = state.indexOf(
      'supersedeExactIngestionEvidenceFailures(db, {',
      replacement,
    );
    const commitBoundary = state.indexOf(
      '      });\n      stateEvidenceCommitted = true',
      transaction,
    );
    assert.ok(transaction < replacement);
    assert.ok(replacement < supersession);
    assert.ok(supersession < commitBoundary);
  });
});
