import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  codeRevisionFromEnv,
  localGitCodeRevision,
  normalizeCodeRevision,
} from './codeRevision';

describe('code revision identity', () => {
  it('normalizes optional revisions', () => {
    assert.equal(normalizeCodeRevision(null), null);
    assert.equal(normalizeCodeRevision('   '), null);
    assert.equal(normalizeCodeRevision(' abc123 '), 'abc123');
    assert.equal(normalizeCodeRevision('contains spaces'), null);
    assert.equal(
      normalizeCodeRevision('A'.repeat(40)),
      'a'.repeat(40),
    );
  });

  it('uses stable validated environment precedence', () => {
    const githubSha = 'A'.repeat(40);
    const renderSha = 'b'.repeat(40);
    assert.equal(codeRevisionFromEnv({
      RADAR_CODE_REVISION: 'radar',
      CODE_REVISION: 'code',
      GITHUB_SHA: githubSha,
      RENDER_GIT_COMMIT: renderSha,
    }), 'radar');
    assert.equal(codeRevisionFromEnv({
      CODE_REVISION: 'code',
      GITHUB_SHA: githubSha,
    }), 'code');
    assert.equal(codeRevisionFromEnv({
      GITHUB_SHA: githubSha,
      RENDER_GIT_COMMIT: renderSha,
    }), githubSha.toLowerCase());
    assert.equal(codeRevisionFromEnv({
      GITHUB_SHA: 'not-a-provider-sha',
      RENDER_GIT_COMMIT: renderSha,
    }), renderSha);
  });

  it('derives a deterministic dirty-aware local git identity', () => {
    const dir = mkdtempSync(join(tmpdir(), 'radar-code-revision-'));
    try {
      git(dir, 'init', '-q');
      git(dir, 'config', 'user.email', 'test@example.test');
      git(dir, 'config', 'user.name', 'Test');
      writeFileSync(join(dir, 'tracked.txt'), 'clean\n');
      git(dir, 'add', 'tracked.txt');
      git(dir, 'commit', '-qm', 'initial');

      const clean = localGitCodeRevision(dir);
      assert.match(clean ?? '', /^git:[0-9a-f]{40}$/);
      assert.equal(codeRevisionFromEnv({}, dir), clean);

      writeFileSync(join(dir, 'tracked.txt'), 'dirty\n');
      const dirty = localGitCodeRevision(dir);
      assert.match(
        dirty ?? '',
        /^git:[0-9a-f]{40}:dirty:[0-9a-f]{64}$/,
      );
      assert.notEqual(dirty, clean);
      assert.equal(localGitCodeRevision(dir), dirty);

      writeFileSync(join(dir, 'untracked.txt'), 'one\n');
      const withUntracked = localGitCodeRevision(dir);
      writeFileSync(join(dir, 'untracked.txt'), 'two\n');
      assert.notEqual(localGitCodeRevision(dir), withUntracked);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}
