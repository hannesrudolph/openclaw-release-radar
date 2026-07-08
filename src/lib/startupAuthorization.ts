import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from 'node:fs';
import type { BigIntStats } from 'node:fs';
import { basename, dirname, join } from 'node:path';

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const RELEASE_REVISION_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const ARTIFACT_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const TRANSACTION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const STARTUP_AUTHORIZATION_HASH_DOMAIN =
  'installer-startup-authorization-v1';
const FINALIZATION_HASH_DOMAIN = 'installer-finalization-v1';
const MAX_AUTHORIZATION_BYTES = 64 * 1024;

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type StartupAuthorizationPayload = {
  schemaVersion: 1;
  lifecycle: 'pending-activation' | 'committed-completion';
  release: {
    name: string;
    sha: string;
    artifactDigest: string;
    realPath: string;
  };
  database: {
    realPath: string;
    device: string;
    inode: string;
    logicalContentDigest: string;
    schemaDigest: string;
    physicalSha256: string;
  };
  scoreReceipt: {
    receiptId: string;
  };
  promotionReceipt: {
    promotionId: string;
    contentHash: string;
  };
  promotionBinding: {
    contentHash: string;
    promotionAuthorizationContentHash: string;
    reportSha256: string;
  };
  transaction: {
    transactionId: string;
    pendingStateHash: string;
  };
  state:
    | {
      kind: 'pending-activation';
      path: string;
      phase: 'activated';
      phaseTransitionHash: string;
    }
    | {
      kind: 'committed-completion';
      path: string;
      outcome: 'committed';
      finalizationContentHash: string;
    };
  recordedAt: string;
};

export type StartupAuthorizationRecord = StartupAuthorizationPayload & {
  contentHash: string;
};

export type StartupAuthorizationAttestation = {
  schemaVersion: 1;
  lifecycle: StartupAuthorizationRecord['lifecycle'];
  releaseSha: string;
  databasePath: string;
  databasePhysicalSha256: string;
  scoreReceiptId: string;
  promotionId: string;
  transactionId: string;
  authorizationContentHash: string;
};

export function canonicalStartupAuthorizationJson(value: unknown): string {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalStartupAuthorizationJson).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalStartupAuthorizationJson(
            (value as Record<string, unknown>)[key],
          )}`,
      )
      .join(',')}}`;
  }
  throw new Error('startup authorization contains unsupported JSON');
}

export function startupAuthorizationContentHash(
  payload: StartupAuthorizationPayload,
): string {
  return createHash('sha256')
    .update(
      `${STARTUP_AUTHORIZATION_HASH_DOMAIN}\0` +
        canonicalStartupAuthorizationJson(payload),
    )
    .digest('hex');
}

export function verifyProductionStartupAuthorization(input: {
  releaseRoot: string;
  releaseRevision: string;
  databasePath: string;
  expectedOwnerUid?: number;
}): StartupAuthorizationAttestation {
  const expectedOwnerUid = input.expectedOwnerUid ?? 0;
  const releaseRoot = realpathSync(input.releaseRoot);
  const releasesRoot = dirname(releaseRoot);
  if (basename(releasesRoot) !== 'releases') {
    throw new Error(
      `[startup-authorization] production release is not installed under a releases directory: ${releaseRoot}`,
    );
  }
  const base = dirname(releasesRoot);
  const currentPath = join(base, 'current');
  if (realpathSync(currentPath) !== releaseRoot) {
    throw new Error(
      '[startup-authorization] current release symlink does not select this runtime',
    );
  }
  const databasePath = realpathSync(input.databasePath);
  const authorizationDirectory = join(
    base,
    'shared',
    'startup-authorization',
  );
  const authorizationPath = join(authorizationDirectory, 'active.json');
  assertProtectedDirectory(authorizationDirectory, expectedOwnerUid);
  const record = readAuthorizationRecord(authorizationPath, expectedOwnerUid);
  validateAuthorizationRecord(record);

  if (
    record.release.sha !== input.releaseRevision ||
    record.release.realPath !== releaseRoot ||
    record.release.name !== basename(releaseRoot)
  ) {
    throw new Error(
      '[startup-authorization] authorization release identity does not match the current runtime',
    );
  }
  if (record.database.realPath !== databasePath) {
    throw new Error(
      '[startup-authorization] authorization database path does not match production DB_PATH',
    );
  }

  const databaseIdentity = hashStableRegularFile(databasePath);
  if (
    record.database.device !== databaseIdentity.device ||
    record.database.inode !== databaseIdentity.inode
  ) {
    throw new Error(
      '[startup-authorization] installed database inode does not match authorization',
    );
  }
  if (record.database.physicalSha256 !== databaseIdentity.physicalSha256) {
    throw new Error(
      '[startup-authorization] installed database physical digest does not match authorization',
    );
  }

  if (record.lifecycle === 'pending-activation') {
    const expectedPendingPath = join(base, '.pending-deploy');
    if (
      record.state.kind !== 'pending-activation' ||
      record.state.path !== expectedPendingPath ||
      record.state.phase !== 'activated'
    ) {
      throw new Error(
        '[startup-authorization] pending activation state does not match authorization',
      );
    }
    assertRegularDirectory(record.state.path, 'pending activation');
  } else {
    const expectedCompletionPath = join(
      base,
      'shared',
      'deploy-completions',
      `committed-${record.release.name}-${record.transaction.transactionId}`,
    );
    if (
      record.state.kind !== 'committed-completion' ||
      record.state.path !== expectedCompletionPath ||
      record.state.outcome !== 'committed'
    ) {
      throw new Error(
        '[startup-authorization] committed completion state does not match authorization',
      );
    }
    assertRegularDirectory(record.state.path, 'committed completion');
    validateCommittedFinalization(record, expectedOwnerUid);
  }

  return {
    schemaVersion: 1,
    lifecycle: record.lifecycle,
    releaseSha: record.release.sha,
    databasePath: record.database.realPath,
    databasePhysicalSha256: record.database.physicalSha256,
    scoreReceiptId: record.scoreReceipt.receiptId,
    promotionId: record.promotionReceipt.promotionId,
    transactionId: record.transaction.transactionId,
    authorizationContentHash: record.contentHash,
  };
}

function validateAuthorizationRecord(
  record: StartupAuthorizationRecord,
): void {
  assertExactKeys(record, [
    'contentHash',
    'database',
    'lifecycle',
    'promotionBinding',
    'promotionReceipt',
    'recordedAt',
    'release',
    'schemaVersion',
    'scoreReceipt',
    'state',
    'transaction',
  ], 'startup authorization');
  assertExactKeys(record.release, [
    'artifactDigest',
    'name',
    'realPath',
    'sha',
  ], 'startup authorization release');
  assertExactKeys(record.database, [
    'device',
    'inode',
    'logicalContentDigest',
    'physicalSha256',
    'realPath',
    'schemaDigest',
  ], 'startup authorization database');
  assertExactKeys(record.scoreReceipt, ['receiptId'], 'startup authorization score receipt');
  assertExactKeys(record.promotionReceipt, [
    'contentHash',
    'promotionId',
  ], 'startup authorization promotion receipt');
  assertExactKeys(record.promotionBinding, [
    'contentHash',
    'promotionAuthorizationContentHash',
    'reportSha256',
  ], 'startup authorization promotion binding');
  assertExactKeys(record.transaction, [
    'pendingStateHash',
    'transactionId',
  ], 'startup authorization transaction');

  if (record.state?.kind === 'pending-activation') {
    assertExactKeys(record.state, [
      'kind',
      'path',
      'phase',
      'phaseTransitionHash',
    ], 'startup authorization pending state');
  } else if (record.state?.kind === 'committed-completion') {
    assertExactKeys(record.state, [
      'finalizationContentHash',
      'kind',
      'outcome',
      'path',
    ], 'startup authorization committed state');
  } else {
    throw new Error(
      '[startup-authorization] authorization has an unsupported lifecycle state',
    );
  }

  const { contentHash, ...payload } = record;
  if (
    record.schemaVersion !== 1 ||
    !['pending-activation', 'committed-completion'].includes(record.lifecycle) ||
    record.lifecycle !== record.state.kind ||
    !RELEASE_REVISION_PATTERN.test(record.release.sha) ||
    !ARTIFACT_DIGEST_PATTERN.test(record.release.artifactDigest) ||
    !record.release.name ||
    basename(record.release.realPath) !== record.release.name ||
    !record.database.realPath ||
    !/^[0-9]+$/.test(record.database.device) ||
    !/^[0-9]+$/.test(record.database.inode) ||
    !SHA256_PATTERN.test(record.database.logicalContentDigest) ||
    !SHA256_PATTERN.test(record.database.schemaDigest) ||
    !SHA256_PATTERN.test(record.database.physicalSha256) ||
    !SHA256_PATTERN.test(record.scoreReceipt.receiptId) ||
    !SHA256_PATTERN.test(record.promotionReceipt.promotionId) ||
    !SHA256_PATTERN.test(record.promotionReceipt.contentHash) ||
    !SHA256_PATTERN.test(record.promotionBinding.contentHash) ||
    !SHA256_PATTERN.test(
      record.promotionBinding.promotionAuthorizationContentHash,
    ) ||
    !SHA256_PATTERN.test(record.promotionBinding.reportSha256) ||
    !TRANSACTION_ID_PATTERN.test(record.transaction.transactionId) ||
    !SHA256_PATTERN.test(record.transaction.pendingStateHash) ||
    !Number.isFinite(Date.parse(record.recordedAt)) ||
    !SHA256_PATTERN.test(contentHash) ||
    contentHash !==
      startupAuthorizationContentHash(
        payload as StartupAuthorizationPayload,
      )
  ) {
    throw new Error(
      '[startup-authorization] authorization content is invalid or tampered',
    );
  }
  if (
    record.state.kind === 'pending-activation' &&
    !SHA256_PATTERN.test(record.state.phaseTransitionHash)
  ) {
    throw new Error(
      '[startup-authorization] pending activation proof is invalid',
    );
  }
  if (
    record.state.kind === 'committed-completion' &&
    !SHA256_PATTERN.test(record.state.finalizationContentHash)
  ) {
    throw new Error(
      '[startup-authorization] committed completion proof is invalid',
    );
  }
}

function validateCommittedFinalization(
  record: StartupAuthorizationRecord,
  expectedOwnerUid: number,
): void {
  if (record.state.kind !== 'committed-completion') {
    throw new Error(
      '[startup-authorization] committed finalization requires committed state',
    );
  }
  const finalizationPath = join(record.state.path, 'finalization.json');
  const finalization = readProtectedJson(
    finalizationPath,
    expectedOwnerUid,
  ) as Record<string, unknown>;
  assertExactKeys(finalization, [
    'artifactDigest',
    'contentHash',
    'outcome',
    'pendingStateHash',
    'releaseName',
    'releaseSha',
    'schemaVersion',
    'transactionId',
  ], 'startup authorization finalization');
  const payload = {
    schemaVersion: finalization.schemaVersion,
    outcome: finalization.outcome,
    pendingStateHash: finalization.pendingStateHash,
    transactionId: finalization.transactionId,
    releaseName: finalization.releaseName,
    releaseSha: finalization.releaseSha,
    artifactDigest: finalization.artifactDigest,
  };
  const computed = createHash('sha256')
    .update(`${FINALIZATION_HASH_DOMAIN}\0${JSON.stringify(payload)}`)
    .digest('hex');
  if (
    finalization.schemaVersion !== 1 ||
    finalization.outcome !== 'committed' ||
    finalization.pendingStateHash !== record.transaction.pendingStateHash ||
    finalization.transactionId !== record.transaction.transactionId ||
    finalization.releaseName !== record.release.name ||
    finalization.releaseSha !== record.release.sha ||
    finalization.artifactDigest !== record.release.artifactDigest ||
    finalization.contentHash !== record.state.finalizationContentHash ||
    finalization.contentHash !== computed
  ) {
    throw new Error(
      '[startup-authorization] committed finalization does not match authorization',
    );
  }
}

function readAuthorizationRecord(
  path: string,
  expectedOwnerUid: number,
): StartupAuthorizationRecord {
  return readProtectedJson(path, expectedOwnerUid) as StartupAuthorizationRecord;
}

function readProtectedJson(path: string, expectedOwnerUid: number): unknown {
  let info;
  try {
    info = lstatSync(path, { bigint: true });
  } catch (error) {
    throw new Error(
      `[startup-authorization] required installer authorization is missing: ${path}`,
      { cause: error },
    );
  }
  const mode = Number(info.mode & 0o777n);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.nlink !== 1n ||
    Number(info.uid) !== expectedOwnerUid ||
    (mode & 0o022) !== 0
  ) {
    throw new Error(
      `[startup-authorization] installer authorization is not a protected regular file: ${path}`,
    );
  }
  const contents = readStableFile(path, info);
  try {
    return JSON.parse(contents.toString('utf8')) as JsonValue;
  } catch (error) {
    throw new Error(
      '[startup-authorization] installer authorization is not valid JSON',
      { cause: error },
    );
  }
}

function readStableFile(
  path: string,
  expected: BigIntStats,
): Buffer {
  if (
    expected.size <= 0n ||
    expected.size > BigInt(MAX_AUTHORIZATION_BYTES)
  ) {
    throw new Error(
      `[startup-authorization] protected JSON size is invalid: ${path}`,
    );
  }
  const fd = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (
      opened.dev !== expected.dev ||
      opened.ino !== expected.ino ||
      opened.nlink !== 1n ||
      opened.size !== expected.size
    ) {
      throw new Error(
        `[startup-authorization] protected JSON changed while opening: ${path}`,
      );
    }
    const contents = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < contents.length) {
      const bytes = readSync(
        fd,
        contents,
        offset,
        contents.length - offset,
        offset,
      );
      if (bytes === 0) break;
      offset += bytes;
    }
    const after = fstatSync(fd, { bigint: true });
    const finalPath = lstatSync(path, { bigint: true });
    if (
      offset !== contents.length ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      !finalPath.isFile() ||
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.nlink !== 1n ||
      finalPath.size !== opened.size
    ) {
      throw new Error(
        `[startup-authorization] protected JSON changed while reading: ${path}`,
      );
    }
    return contents;
  } finally {
    closeSync(fd);
  }
}

function hashStableRegularFile(path: string): {
  device: string;
  inode: string;
  physicalSha256: string;
} {
  const pathInfo = lstatSync(path, { bigint: true });
  if (
    !pathInfo.isFile() ||
    pathInfo.isSymbolicLink() ||
    pathInfo.nlink !== 1n
  ) {
    throw new Error(
      `[startup-authorization] installed database is not one regular non-symlink file: ${path}`,
    );
  }
  const fd = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (
      opened.dev !== pathInfo.dev ||
      opened.ino !== pathInfo.ino ||
      opened.nlink !== 1n ||
      opened.size !== pathInfo.size
    ) {
      throw new Error(
        '[startup-authorization] installed database changed while opening',
      );
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    for (;;) {
      const bytes = readSync(fd, buffer, 0, buffer.length, offset);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
      offset += bytes;
    }
    const after = fstatSync(fd, { bigint: true });
    const finalPath = lstatSync(path, { bigint: true });
    if (
      BigInt(offset) !== opened.size ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs ||
      !finalPath.isFile() ||
      finalPath.isSymbolicLink() ||
      finalPath.dev !== opened.dev ||
      finalPath.ino !== opened.ino ||
      finalPath.nlink !== 1n ||
      finalPath.size !== opened.size
    ) {
      throw new Error(
        '[startup-authorization] installed database changed while hashing',
      );
    }
    return {
      device: String(opened.dev),
      inode: String(opened.ino),
      physicalSha256: hash.digest('hex'),
    };
  } finally {
    closeSync(fd);
  }
}

function assertProtectedDirectory(path: string, expectedOwnerUid: number): void {
  let info;
  try {
    info = lstatSync(path, { bigint: true });
  } catch (error) {
    throw new Error(
      `[startup-authorization] installer authorization directory is missing: ${path}`,
      { cause: error },
    );
  }
  const mode = Number(info.mode & 0o777n);
  if (
    !info.isDirectory() ||
    info.isSymbolicLink() ||
    Number(info.uid) !== expectedOwnerUid ||
    (mode & 0o022) !== 0
  ) {
    throw new Error(
      `[startup-authorization] installer authorization directory is not protected: ${path}`,
    );
  }
}

function assertRegularDirectory(path: string, label: string): void {
  let info;
  try {
    info = lstatSync(path);
  } catch (error) {
    throw new Error(
      `[startup-authorization] authorized ${label} state is missing: ${path}`,
      { cause: error },
    );
  }
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(
      `[startup-authorization] authorized ${label} state is not a regular directory: ${path}`,
    );
  }
}

function assertExactKeys(
  value: unknown,
  expected: string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!value || Array.isArray(value) || typeof value !== 'object') {
    throw new Error(`[startup-authorization] ${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
    throw new Error(
      `[startup-authorization] ${label} has unexpected fields`,
    );
  }
}
