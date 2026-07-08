import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdtempSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertSupportedNodeVersion } from './node-version.mjs';

assertSupportedNodeVersion();

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sourcePath = join(
  root,
  'ops',
  'viralo',
  'openclaw-release-radar-install-release.sh',
);
const tempRoot = mkdtempSync(join(tmpdir(), 'radar-installer-preflight-'));
chmodSync(tempRoot, 0o700);

try {
  const { tsImport } = await import('tsx/esm/api');
  const {
    materializePrivateInstallerHeredocs,
    PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT,
  } = await tsImport('./test-suite-runner.mjs', import.meta.url);
  const materialized = materializePrivateInstallerHeredocs({
    sourcePath,
    fixtureRoot: join(tempRoot, 'installer-heredocs'),
    expectedHeredocCount: PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT,
    forbidShellHereStrings: true,
  });
  const environment = {
    HOME: tempRoot,
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    TEMP: tempRoot,
    TMP: tempRoot,
    TMPDIR: tempRoot,
  };
  const syntax = spawnSync(
    '/bin/bash',
    ['-n', materialized.installerPath],
    {
      cwd: root,
      encoding: 'utf8',
      env: environment,
    },
  );
  assertCommandSucceeded(syntax, 'installer shell syntax preflight');

  const protocol = spawnSync(
    '/bin/bash',
    [materialized.installerPath, 'protocol', '5'],
    {
      cwd: root,
      encoding: 'utf8',
      env: environment,
    },
  );
  assertCommandSucceeded(protocol, 'installer protocol preflight');
  if (protocol.stdout.trim() !== '5') {
    throw new Error(
      `Installer protocol preflight returned ${JSON.stringify(protocol.stdout.trim())}.`,
    );
  }

  console.log(
    `[installer-preflight] passed: ${PRODUCTION_INSTALLER_QUOTED_HEREDOC_COUNT} ` +
      'heredocs materialized, shell syntax valid, protocol 5',
  );
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

function assertCommandSucceeded(result, label) {
  if (result.error) {
    throw new Error(`${label} could not start`, { cause: result.error });
  }
  if (result.status === 0 && result.signal === null) return;
  const output = `${result.stderr ?? ''}${result.stdout ?? ''}`.trim();
  throw new Error(
    `${label} failed with ${
      result.signal ? `signal ${result.signal}` : `exit code ${result.status}`
    }${output ? `: ${output}` : ''}`,
  );
}
