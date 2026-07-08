import { execFileSync, spawnSync } from 'node:child_process';
import {
  createHash,
  createHmac,
  timingSafeEqual,
} from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
} from 'node:fs';

const watchdogStateDomain = 'openclaw-radar-watchdog-state-v2';
const watchdogReceiptDomain = 'openclaw-radar-watchdog-receipt-v1';
const guardedProcessIdentityTelemetryKey = Symbol.for(
  'openclaw-release-radar.guarded-process-identity-telemetry',
);

export function captureProcessIdentity(pid, {
    platform = process.platform,
    run = spawnSync,
  } = {}) {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  try {
    if (platform === 'win32') {
      return captureWindowsProcessIdentity(pid);
    }
    const processIdentityHelper = run === spawnSync
      ? configuredProcessIdentityHelper()
      : null;
    if (processIdentityHelper !== null) {
      const result = run(
        processIdentityHelper.path,
        ['--identity', String(pid)],
        {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 2_000,
        },
      );
      return processIdentityFromHelperResult(result, pid, platform);
    }
    const psPath = existsSync('/bin/ps') ? '/bin/ps' : '/usr/bin/ps';
    const guardedTelemetry = run === spawnSync
      ? guardedProcessIdentityTelemetry()
      : null;
    const result = guardedTelemetry !== null
      ? guardedTelemetry(pid)
      : run(
        psPath,
        ['-p', String(pid), '-o', 'pid=,ppid=,pgid=,lstart=,comm='],
        {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
          timeout: 2_000,
          detached: true,
        },
      );
    if (
      result?.error ||
      result?.signal ||
      result?.status !== 0
    ) {
      return null;
    }
    const output = String(result.stdout ?? '').trim();
    const match = output.match(
      /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.{24})\s+(.+?)\s*$/,
    );
    if (!match || Number(match[1]) !== pid) return null;
    return {
      schemaVersion: 1,
      platform,
      pid,
      parentPid: Number(match[2]),
      processGroupPid: Number(match[3]),
      startedAt: match[4].trim(),
      commandDigest: sha256(match[5]),
    };
  } catch {
    return null;
  }
}

function guardedProcessIdentityTelemetry() {
  const descriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    guardedProcessIdentityTelemetryKey,
  );
  if (
    descriptor === undefined ||
    descriptor.configurable !== false ||
    descriptor.writable !== false ||
    typeof descriptor.value !== 'function'
  ) {
    return null;
  }
  return descriptor.value;
}

function configuredProcessIdentityHelper() {
  const helperPath = process.env.RADAR_TEST_PROCESS_IDENTITY_HELPER;
  const rawIdentity =
    process.env.RADAR_TEST_PROCESS_IDENTITY_HELPER_IDENTITY;
  if (helperPath === undefined && rawIdentity === undefined) return null;
  if (!helperPath || !rawIdentity) {
    throw new Error('Darwin process identity helper binding is incomplete.');
  }
  const expected = JSON.parse(rawIdentity);
  const stats = lstatSync(helperPath, { bigint: true });
  if (
    stats.isSymbolicLink() ||
    !stats.isFile() ||
    realpathSync.native(helperPath) !== helperPath ||
    expected?.path !== helperPath ||
    expected.dev !== String(stats.dev) ||
    expected.ino !== String(stats.ino) ||
    expected.mode !== Number(stats.mode & 0o7777n) ||
    expected.uid !== Number(stats.uid) ||
    typeof expected.digest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(expected.digest) ||
    sha256(readFileSync(helperPath)) !== expected.digest
  ) {
    throw new Error('Darwin process identity helper binding changed.');
  }
  return expected;
}

function processIdentityFromHelperResult(result, pid, platform) {
  if (
    result?.error ||
    result?.signal ||
    result?.status !== 0
  ) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(String(result.stdout ?? ''));
  } catch {
    return null;
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    parsed.schemaVersion !== 1 ||
    parsed.pid !== pid ||
    !Number.isInteger(parsed.parentPid) ||
    parsed.parentPid < 0 ||
    !Number.isInteger(parsed.processGroupPid) ||
    parsed.processGroupPid <= 0 ||
    typeof parsed.startedAt !== 'string' ||
    parsed.startedAt.length === 0 ||
    typeof parsed.command !== 'string' ||
    parsed.command.length === 0
  ) {
    return null;
  }
  return {
    schemaVersion: 1,
    platform,
    pid,
    parentPid: parsed.parentPid,
    processGroupPid: parsed.processGroupPid,
    startedAt: parsed.startedAt,
    commandDigest: sha256(parsed.command),
  };
}

export function processIdentityMatches(expected, actual, {
  requireProcessGroupLeader = false,
  allowedCommandDigests = null,
} = {}) {
  if (!validProcessIdentity(expected) || !validProcessIdentity(actual)) {
    return false;
  }
  const commandDigests = allowedCommandDigests === null
    ? [expected.commandDigest]
    : allowedCommandDigests;
  if (
    !validProcessCommandDigests(commandDigests) ||
    !commandDigests.includes(expected.commandDigest)
  ) {
    return false;
  }
  if (
    expected.schemaVersion !== actual.schemaVersion ||
    expected.platform !== actual.platform ||
    expected.pid !== actual.pid ||
    expected.parentPid !== actual.parentPid ||
    expected.processGroupPid !== actual.processGroupPid ||
    expected.startedAt !== actual.startedAt ||
    !commandDigests.includes(actual.commandDigest)
  ) {
    return false;
  }
  return !requireProcessGroupLeader ||
    expected.platform === 'win32' ||
    expected.processGroupPid === expected.pid;
}

export function processIdentityMatchesAfterDarwinReparent(
  expected,
  actual,
  {
    parentIdentity = null,
    parentAlive = true,
    requireProcessGroupLeader = false,
    allowedCommandDigests = null,
  } = {},
) {
  if (
    parentAlive !== false ||
    !validProcessIdentity(expected) ||
    !validProcessIdentity(actual) ||
    !validProcessIdentity(parentIdentity) ||
    expected.platform !== 'darwin' ||
    actual.platform !== 'darwin' ||
    parentIdentity.platform !== 'darwin' ||
    expected.parentPid !== parentIdentity.pid ||
    actual.parentPid !== 1
  ) {
    return false;
  }
  return processIdentityMatches(
    { ...expected, parentPid: 1 },
    actual,
    {
      requireProcessGroupLeader,
      allowedCommandDigests,
    },
  );
}

export function capturePathIdentity(path) {
  const stats = lstatSync(path);
  if (stats.isSymbolicLink()) {
    throw new Error(`Watchdog-owned path must not be a symbolic link: ${path}`);
  }
  return {
    schemaVersion: 1,
    realPath: realpathSync(path),
    device: String(stats.dev),
    inode: String(stats.ino),
    uid: typeof stats.uid === 'number' ? stats.uid : null,
    mode: stats.mode & 0o777,
    kind: stats.isDirectory()
      ? 'directory'
      : stats.isFile()
        ? 'file'
        : 'other',
  };
}

export function pathIdentityMatches(path, expected, {
  kind,
  privateToOwner = true,
} = {}) {
  try {
    const actual = capturePathIdentity(path);
    if (!validPathIdentity(expected)) return false;
    if (
      actual.schemaVersion !== expected.schemaVersion ||
      actual.realPath !== expected.realPath ||
      actual.device !== expected.device ||
      actual.inode !== expected.inode ||
      actual.uid !== expected.uid ||
      actual.kind !== expected.kind
    ) {
      return false;
    }
    if (kind && actual.kind !== kind) return false;
    if (
      typeof process.getuid === 'function' &&
      actual.uid !== process.getuid()
    ) {
      return false;
    }
    if (privateToOwner && (actual.mode & 0o077) !== 0) return false;
    return true;
  } catch {
    return false;
  }
}

export function sealWatchdogState(payload, token) {
  assertWatchdogToken(token);
  const contentHash = createHmac('sha256', token)
    .update(`${watchdogStateDomain}\0${canonicalJson(payload)}`)
    .digest('hex');
  return {
    ...payload,
    contentHash,
  };
}

export function verifyWatchdogStateSeal(state, token) {
  assertWatchdogToken(token);
  if (!state || typeof state !== 'object' || Array.isArray(state)) return false;
  const {
    contentHash,
    ...payload
  } = state;
  if (typeof contentHash !== 'string' || !/^[0-9a-f]{64}$/.test(contentHash)) {
    return false;
  }
  const expected = createHmac('sha256', token)
    .update(`${watchdogStateDomain}\0${canonicalJson(payload)}`)
    .digest('hex');
  return safeDigestEqual(contentHash, expected);
}

export function sealWatchdogReceipt(payload) {
  const contentHash = sha256(
    `${watchdogReceiptDomain}\0${canonicalJson(payload)}`,
  );
  return {
    ...payload,
    contentHash,
  };
}

export function verifyWatchdogReceiptSeal(receipt) {
  if (
    !receipt ||
    typeof receipt !== 'object' ||
    Array.isArray(receipt) ||
    typeof receipt.contentHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(receipt.contentHash)
  ) {
    return false;
  }
  const {
    contentHash,
    ...payload
  } = receipt;
  return safeDigestEqual(
    contentHash,
    sha256(`${watchdogReceiptDomain}\0${canonicalJson(payload)}`),
  );
}

export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function captureWindowsProcessIdentity(pid) {
  const script = [
    `$p = Get-CimInstance Win32_Process -Filter "ProcessId = ${pid}"`,
    'if ($null -eq $p) { exit 3 }',
    '$path = if ($null -eq $p.ExecutablePath) { "" } else { $p.ExecutablePath }',
    'Write-Output "$($p.ProcessId)|$($p.ParentProcessId)|$($p.CreationDate)|$path"',
  ].join('; ');
  const output = execFileSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3_000,
    },
  ).trim();
  const [rawPid, rawParentPid, startedAt, ...pathParts] = output.split('|');
  if (Number(rawPid) !== pid || !startedAt) return null;
  return {
    schemaVersion: 1,
    platform: process.platform,
    pid,
    parentPid: Number(rawParentPid),
    processGroupPid: null,
    startedAt,
    commandDigest: sha256(pathParts.join('|')),
  };
}

function validProcessIdentity(value) {
  return value != null &&
    typeof value === 'object' &&
    value.schemaVersion === 1 &&
    typeof value.platform === 'string' &&
    Number.isInteger(value.pid) &&
    value.pid > 0 &&
    (value.parentPid === null ||
      (Number.isInteger(value.parentPid) && value.parentPid >= 0)) &&
    (value.processGroupPid === null ||
      (Number.isInteger(value.processGroupPid) &&
        value.processGroupPid > 0)) &&
    typeof value.startedAt === 'string' &&
    value.startedAt.length > 0 &&
    typeof value.commandDigest === 'string' &&
    /^[0-9a-f]{64}$/.test(value.commandDigest);
}

function validProcessCommandDigests(value) {
  return Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 8 &&
    new Set(value).size === value.length &&
    value.every((digest) =>
      typeof digest === 'string' &&
      /^[0-9a-f]{64}$/.test(digest));
}

function validPathIdentity(value) {
  return value != null &&
    typeof value === 'object' &&
    value.schemaVersion === 1 &&
    typeof value.realPath === 'string' &&
    value.realPath.length > 0 &&
    typeof value.device === 'string' &&
    typeof value.inode === 'string' &&
    (value.uid === null || Number.isInteger(value.uid)) &&
    Number.isInteger(value.mode) &&
    ['directory', 'file', 'other'].includes(value.kind);
}

function assertWatchdogToken(token) {
  if (typeof token !== 'string' || token.length < 32) {
    throw new Error('Resource watchdog token is missing or invalid.');
  }
}

function safeDigestEqual(left, right) {
  try {
    return timingSafeEqual(
      Buffer.from(left, 'hex'),
      Buffer.from(right, 'hex'),
    );
  } catch {
    return false;
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
