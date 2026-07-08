import {
  closeSync,
  constants as fsConstants,
  mkdtempSync,
  openSync,
  writeSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const nativeCloseSync = closeSync;
const nativeOpenSync = openSync;
const nativeWriteSync = writeSync;

const context = process.env.NODE_TEST_CONTEXT;
const runId = process.env.RADAR_TEST_RUN_ID;

if (context && runId && process.env.RADAR_TEST_WORKER_DB_ASSIGNED !== runId) {
  const tempRoot = requiredEnv('RADAR_TEST_TEMP_ROOT');
  const auditPath = requiredEnv('RADAR_TEST_DB_AUDIT');
  const codeRevision = requiredEnv('RADAR_TEST_CODE_REVISION');
  const processLockRoot = requiredEnv('RADAR_TEST_PROCESS_LOCK_ROOT');
  const workerDir = mkdtempSync(join(tempRoot, 'worker-'));
  const dbPath = join(workerDir, 'radar.db');
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const policyProbeAuthorityFile = join(
    repositoryRoot,
    'src',
    'lib',
    'db.provenance.test.ts',
  );
  const workerScript = process.argv[1]
    ? resolve(process.argv[1])
    : null;

  process.env.DB_PATH = dbPath;
  process.env.TMPDIR = workerDir;
  process.env.TMP = workerDir;
  process.env.TEMP = workerDir;
  process.env.SQLITE_TMPDIR = workerDir;
  process.env.RADAR_TEST_ALLOWED_DB_ROOTS = JSON.stringify([
    workerDir,
    processLockRoot,
  ]);
  process.env.RADAR_CODE_REVISION = codeRevision;
  process.env.RADAR_DB_READ_ONLY = '0';
  process.env.RADAR_TEST_WORKER_DB_ASSIGNED = runId;
  process.env.RADAR_TEST_WORKER_DB_PATH = dbPath;
  if (workerScript === policyProbeAuthorityFile) {
    process.env.RADAR_TEST_DATABASE_POLICY_PROBE_AUTHORITY = '1';
  } else {
    delete process.env.RADAR_TEST_DATABASE_POLICY_PROBE_AUTHORITY;
  }

  audit({
    type: 'worker-env',
    pid: process.pid,
    context,
    dbPath,
    workerDir,
    codeRevision,
    script: process.argv[1] ?? null,
  });

  let exitAudited = false;
  const auditExit = (signal = null) => {
    if (exitAudited) return;
    exitAudited = true;
    audit({
      type: 'worker-exit',
      pid: process.pid,
      dbPath,
      workerDir,
      signal,
    });
  };
  process.once('exit', () => auditExit());
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      try {
        auditExit(signal);
      } finally {
        process.kill(process.pid, signal);
      }
    });
  }

  function audit(event) {
    const descriptor = nativeOpenSync(
      auditPath,
      fsConstants.O_APPEND | fsConstants.O_WRONLY,
    );
    try {
      nativeWriteSync(
        descriptor,
        `${JSON.stringify({ runId, ...event })}\n`,
      );
    } finally {
      nativeCloseSync(descriptor);
    }
  }
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required test environment variable: ${name}`);
  return value;
}
