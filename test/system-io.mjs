import { spawnSync } from 'node:child_process';

const mebibyte = 1024 * 1024;
const darwinIostatPath = '/usr/sbin/iostat';

export function parseDarwinIostatDiskTransferBytes(output) {
  let totalMebibytes = 0;
  let rowCount = 0;
  for (const line of String(output).split('\n')) {
    const columns = line.trim().split(/\s+/);
    if (
      columns.length < 3 ||
      columns.length % 3 !== 0 ||
      !columns.every((column) => /^\d+(?:\.\d+)?$/.test(column))
    ) {
      continue;
    }
    for (let index = 2; index < columns.length; index += 3) {
      totalMebibytes += Number(columns[index]);
      rowCount++;
    }
  }
  if (rowCount === 0 || !Number.isFinite(totalMebibytes)) {
    throw new Error('Unable to parse cumulative disk transfers from iostat');
  }
  return Math.round(totalMebibytes * mebibyte);
}

export function captureSystemDiskTransferBytes({
  platform = process.platform,
  run = spawnSync,
} = {}) {
  if (platform !== 'darwin') return null;
  const result = run(darwinIostatPath, ['-Id'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      LC_ALL: 'C',
      LANG: 'C',
    },
    timeout: 2_000,
    maxBuffer: 64 * 1024,
  });
  if (result.error) {
    throw new Error(
      `Unable to sample cumulative system disk transfers: ${result.error.message}`,
    );
  }
  if (result.status !== 0) {
    throw new Error(
      `Unable to sample cumulative system disk transfers: iostat exited ` +
      `${String(result.status)}: ${String(result.stderr ?? '').trim()}`,
    );
  }
  return parseDarwinIostatDiskTransferBytes(result.stdout);
}

export function systemDiskTransferDeltaBytes(baselineBytes, currentBytes) {
  if (
    !Number.isFinite(baselineBytes) ||
    baselineBytes < 0 ||
    !Number.isFinite(currentBytes) ||
    currentBytes < 0
  ) {
    throw new Error('System disk transfer counters must be finite non-negative bytes');
  }
  if (currentBytes < baselineBytes) {
    throw new Error('System disk transfer counter regressed during validation');
  }
  return currentBytes - baselineBytes;
}
