import { createHash } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from 'node:fs';

export function sqliteFamilyPaths(path) {
  return [path, `${path}-wal`, `${path}-shm`, `${path}-journal`];
}

export function captureSqliteFamilyFingerprint(path) {
  return sqliteFamilyPaths(path).map((memberPath) => ({
    path: memberPath,
    ...fingerprintFile(memberPath),
  }));
}

function fingerprintFile(path) {
  let descriptor = null;
  let observedExistingPath = false;
  try {
    const pathBefore = lstatSync(path);
    observedExistingPath = true;
    if (
      pathBefore.isSymbolicLink() ||
      !pathBefore.isFile() ||
      pathBefore.nlink !== 1
    ) {
      throw new Error(
        `Live database family member is not one no-follow regular file: ${path}`,
      );
    }
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    descriptor = openSync(path, fsConstants.O_RDONLY | noFollow);
    const descriptorBefore = fstatSync(descriptor);
    assertSameFileIdentity(path, pathBefore, descriptorBefore, 'before read');
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (true) {
      const bytesRead = readSync(
        descriptor,
        buffer,
        0,
        buffer.length,
        position,
      );
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const descriptorAfter = fstatSync(descriptor);
    const pathAfter = lstatSync(path);
    assertSameFileIdentity(path, descriptorBefore, descriptorAfter, 'during read');
    assertSameFileIdentity(path, descriptorAfter, pathAfter, 'after read');
    if (
      descriptorBefore.size !== descriptorAfter.size ||
      descriptorBefore.mtimeMs !== descriptorAfter.mtimeMs ||
      descriptorBefore.ctimeMs !== descriptorAfter.ctimeMs ||
      descriptorAfter.size !== pathAfter.size ||
      descriptorAfter.mtimeMs !== pathAfter.mtimeMs ||
      descriptorAfter.ctimeMs !== pathAfter.ctimeMs
    ) {
      throw new Error(
        `Live database family member changed while it was fingerprinted: ${path}`,
      );
    }
    return {
      exists: true,
      dev: descriptorAfter.dev,
      ino: descriptorAfter.ino,
      size: descriptorAfter.size,
      mtimeMs: descriptorAfter.mtimeMs,
      ctimeMs: descriptorAfter.ctimeMs,
      digest: digest.digest('hex'),
    };
  } catch (error) {
    if (error?.code !== 'ENOENT' || observedExistingPath) throw error;
    return {
      exists: false,
      dev: null,
      ino: null,
      size: null,
      mtimeMs: null,
      ctimeMs: null,
      digest: null,
    };
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

function assertSameFileIdentity(path, left, right, context) {
  if (
    left.dev !== right.dev ||
    left.ino !== right.ino ||
    right.nlink !== 1 ||
    !right.isFile() ||
    right.isSymbolicLink()
  ) {
    throw new Error(
      `Live database family member identity changed ${context}: ${path}`,
    );
  }
}
