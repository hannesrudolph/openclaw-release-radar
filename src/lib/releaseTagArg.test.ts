import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, it } from 'node:test';

const helperPath = fileURLToPath(
  new URL('../../scripts/lib/release-tag-arg.mjs', import.meta.url),
);

function runReleaseTagArg(args: string[]) {
  const source = [
    `import { releaseTagArg } from ${JSON.stringify(pathToFileURL(helperPath).href)};`,
    `const tag = releaseTagArg(${JSON.stringify(args)}, {`,
    `  command: 'test-command',`,
    `  description: 'test description',`,
    `});`,
    `console.log(tag);`,
  ].join('\n');
  return spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
    encoding: 'utf8',
  });
}

describe('releaseTagArg', () => {
  it('requires one explicit tag', () => {
    const missing = runReleaseTagArg([]);
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /Expected exactly one release tag, got 0/);

    const explicit = runReleaseTagArg(['v-test']);
    assert.equal(explicit.status, 0);
    assert.equal(explicit.stdout.trim(), 'v-test');
  });

  it('documents the required argument without a stale default', () => {
    const help = runReleaseTagArg(['--help']);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /Usage: test-command <release-tag>/);
    assert.match(help.stdout, /never infers the latest release/);
    assert.doesNotMatch(help.stdout, /Default release tag|v2026\.6\.10/);
  });
});
