import { createHash } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
} from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const countFields = [
  'tests',
  'failed',
  'passed',
  'cancelled',
  'skipped',
  'todo',
];
const allPlatforms = [
  'aix',
  'android',
  'darwin',
  'freebsd',
  'linux',
  'openbsd',
  'sunos',
  'win32',
];
const nonDarwinPlatforms = allPlatforms.filter((platform) => platform !== 'darwin');

export const TEST_INTEGRITY_SKIP_ALLOWLIST = Object.freeze([
    {
      file: 'src/lib/promoteQualityDb.test.ts',
      name: 'finds a real writable holder after its database inode is replaced',
      reportedReason: true,
      reason: 'requires an available lsof executable',
      platforms: allPlatforms,
    },
    {
      file: 'src/lib/promoteQualityDb.test.ts',
      name: 'preserves destination owner, group, mode, ACLs, and xattrs',
      reportedReason: true,
      reason: 'requires macOS ACL and xattr behavior',
      platforms: nonDarwinPlatforms,
    },
    {
      file: 'src/lib/promoteQualityDb.test.ts',
      name: 'fails before swap when ACL or xattr metadata cannot be preserved',
      reportedReason: true,
      reason: 'requires macOS ACL and xattr behavior',
      platforms: nonDarwinPlatforms,
    },
    {
      file: 'src/lib/releaseReachability.test.ts',
      name: 'terminates child-spawning process trees after timeout and abort',
      reportedReason: true,
      reason: 'requires POSIX process-group signaling',
      platforms: ['win32'],
    },
    {
      file: 'src/lib/testRunnerSafety.test.ts',
      name: 'terminates a macOS process group after cumulative overwrite churn',
      reportedReason: true,
      reason: 'requires macOS libproc cumulative process-write accounting',
      platforms: nonDarwinPlatforms,
    },
    {
      file: 'src/lib/testRunnerSafety.test.ts',
      name: 'terminates a macOS process group after cumulative create-delete churn',
      reportedReason: true,
      reason: 'requires macOS libproc cumulative process-write accounting',
      platforms: nonDarwinPlatforms,
    },
    {
      file: 'src/lib/testRunnerSafety.test.ts',
      name: 'records whole-system I/O pressure without killing repository processes',
      reportedReason: true,
      reason: 'requires macOS iostat cumulative system I/O telemetry',
      platforms: nonDarwinPlatforms,
    },
]);
const defaultIntegrityPolicy = Object.freeze({
  phases: Object.freeze({}),
  skipAllowlist: TEST_INTEGRITY_SKIP_ALLOWLIST,
});

export function readTestEventLog(path) {
  const text = readFileSync(path, 'utf8');
  if (text.trim() === '') return [];
  return text
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(
          `Invalid test reporter event at ${path}:${index + 1}: ${error.message}`,
        );
      }
    });
}

export function validatePhaseBaseline({
  phase,
  label = phase,
  expectedFiles,
  baseline = defaultIntegrityPolicy,
}) {
  const problems = [];
  const phaseBaseline = baseline?.phases?.[phase];
  if (!phaseBaseline || !Number.isInteger(phaseBaseline.minimumPassed) ||
      phaseBaseline.minimumPassed < 0) {
    problems.push(`No valid pass minimum is configured for phase ${phase}.`);
  }
  const expected = new Set(expectedFiles.map(normalizeSlashes));
  const minimumPassedByFile = validatePerFileBaseline(
    phaseBaseline?.minimumPassedByFile,
    expected,
    label,
    problems,
  );
  const testIdentityCounts = validateTestIdentityCounts(
    phaseBaseline?.testIdentityCounts,
    label,
    problems,
  );
  if (minimumPassedByFile &&
      minimumPassedByFile.size === expected.size &&
      [...expected].every((file) => minimumPassedByFile.has(file))) {
    const perFileTotal = [...minimumPassedByFile.values()]
      .reduce((total, minimum) => total + minimum, 0);
    if (phaseBaseline && Number.isInteger(phaseBaseline.minimumPassed) &&
        perFileTotal < phaseBaseline.minimumPassed) {
      problems.push(
        `${label} per-file minima total ${perFileTotal} is below ` +
        `the phase minimum ${phaseBaseline.minimumPassed}.`,
      );
    }
  }
  throwIntegrityProblems(label, problems);
  return {
    phaseBaseline,
    minimumPassedByFile,
    testIdentityCounts,
  };
}

export function generatePhaseBaseline({
  phase,
  label = phase,
  root,
  expectedFiles,
  events,
  baseline = defaultIntegrityPolicy,
  platform = process.platform,
}) {
  const audit = auditPhaseIntegrity({
    phase,
    label,
    root,
    expectedFiles,
    events,
    baseline,
    platform,
  });
  return {
    minimumPassed: audit.counts.passed + audit.allowedSkips.length,
    minimumPassedByFile: Object.fromEntries(
      [...audit.fileCounts.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([file, counts]) => [
          file,
          counts.passed + (audit.allowedSkipsByFile.get(file) ?? 0),
        ]),
    ),
    testIdentityCounts: Object.fromEntries(
      [...audit.testIdentityCounts.entries()]
        .sort(([left], [right]) => left.localeCompare(right)),
    ),
  };
}

export function verifyPhaseIntegrity({
  phase,
  label = phase,
  root,
  expectedFiles,
  events,
  baseline = defaultIntegrityPolicy,
  platform = process.platform,
}) {
  const audit = auditPhaseIntegrity({
    phase,
    label,
    root,
    expectedFiles,
    events,
    baseline,
    platform,
  });
  const {
    phaseBaseline,
    minimumPassedByFile,
    testIdentityCounts,
  } = validatePhaseBaseline({
    phase,
    label,
    expectedFiles,
    baseline,
  });
  const problems = [];
  const passCredit = audit.counts.passed + audit.allowedSkips.length;
  if (passCredit < phaseBaseline.minimumPassed) {
    problems.push(
      `${label} pass minimum regressed: ${audit.counts.passed} passed + ` +
      `${audit.allowedSkips.length} allowlisted skip(s) = ${passCredit}, ` +
      `required at least ${phaseBaseline.minimumPassed}.`,
    );
  }

  for (const [file, minimumPassed] of minimumPassedByFile) {
    const counts = audit.fileCounts.get(file);
    if (!counts) continue;
    const allowedSkipCount = audit.allowedSkipsByFile.get(file) ?? 0;
    const filePassCredit = counts.passed + allowedSkipCount;
    if (filePassCredit < minimumPassed) {
      problems.push(
        `${file} per-file pass minimum regressed: ${counts.passed} passed + ` +
        `${allowedSkipCount} allowlisted skip(s) = ${filePassCredit}, ` +
        `required at least ${minimumPassed}.`,
      );
    }
  }
  for (const [identity, expected] of testIdentityCounts) {
    const observed = audit.testIdentityCounts.get(identity) ?? 0;
    if (observed < expected) {
      problems.push(
        `${label} test identity multiplicity regressed for ${identity}: ` +
        `required at least ${expected}, observed ${observed}.`,
      );
    }
  }

  throwIntegrityProblems(label, problems);
  return {
    phase,
    label,
    expectedFileCount: audit.expected.size,
    completedFileCount: audit.fileCounts.size,
    counts: audit.counts,
    minimumPassed: phaseBaseline.minimumPassed,
    passCredit,
    perFileMinimumCount: minimumPassedByFile.size,
    testIdentityCount: [...audit.testIdentityCounts.values()]
      .reduce((total, count) => total + count, 0),
    allowedSkips: audit.allowedSkips,
  };
}

export function readJsonFileSnapshot(path) {
  const { bytes, snapshot } = readStableFile(path);
  if (!snapshot.exists) {
    return {
      snapshot,
      value: null,
    };
  }
  try {
    return {
      snapshot,
      value: JSON.parse(bytes.toString('utf8')),
    };
  } catch (error) {
    throw new Error(`Unable to read JSON file ${path}: ${error.message}`);
  }
}

export function captureFileSnapshot(path) {
  return readStableFile(path).snapshot;
}

export function assertFileSnapshotUnchanged(
  path,
  expected,
  label,
  context,
) {
  const observed = captureFileSnapshot(path);
  if (!sameFileSnapshot(expected, observed)) {
    throw new Error(
      `${label} changed during ${context}; refusing to trust the operation.`,
    );
  }
}

function auditPhaseIntegrity({
  phase,
  label,
  root,
  expectedFiles,
  events,
  baseline,
  platform,
}) {
  const problems = [];
  const expected = new Set(expectedFiles.map(normalizeSlashes));
  const summaryEvents = events.filter((event) => event?.type === 'test:summary');
  const globalSummaries = summaryEvents.filter((event) => event?.data?.file == null);
  const fileSummaries = new Map();

  for (const event of summaryEvents.filter((candidate) => candidate?.data?.file != null)) {
    const file = normalizeEventFile(event.data.file, root);
    const summaries = fileSummaries.get(file) ?? [];
    summaries.push(event);
    fileSummaries.set(file, summaries);
  }

  if (globalSummaries.length !== 1) {
    problems.push(
      `Expected exactly one ${label} phase summary, observed ${globalSummaries.length}.`,
    );
  }

  for (const file of expected) {
    const summaries = fileSummaries.get(file) ?? [];
    if (summaries.length !== 1) {
      problems.push(
        `Manifest file ${file} did not emit exactly one summary (observed ${summaries.length}).`,
      );
    }
    const completions = events.filter((event) =>
      isManifestFileCompletion(event, file, root));
    if (completions.length !== 1) {
      problems.push(
        `Manifest file ${file} did not finish exactly once (observed ${completions.length} completions).`,
      );
    }
  }

  for (const [file, summaries] of fileSummaries) {
    if (!expected.has(file)) {
      problems.push(
        `Unexpected test file summary for ${file} (${summaries.length} event${summaries.length === 1 ? '' : 's'}).`,
      );
    }
  }

  const fileCounts = new Map();
  for (const [file, summaries] of fileSummaries) {
    if (summaries.length !== 1) continue;
    const counts = validateCounts(
      summaries[0]?.data?.counts,
      `${file} summary`,
      problems,
    );
    if (!counts) continue;
    fileCounts.set(file, counts);
    if (counts.tests === 0) {
      problems.push(`Manifest file ${file} completed without running any tests.`);
    }
    if (summaries[0]?.data?.success !== true) {
      problems.push(`Manifest file ${file} did not report a successful summary.`);
    }
  }

  const globalCounts = globalSummaries.length === 1
    ? validateCounts(globalSummaries[0]?.data?.counts, `${label} phase summary`, problems)
    : null;
  if (globalSummaries.length === 1 && globalSummaries[0]?.data?.success !== true) {
    problems.push(`${label} did not report a successful phase summary.`);
  }

  if (globalCounts && fileCounts.size === expected.size) {
    for (const field of countFields) {
      const observed = [...fileCounts.values()]
        .reduce((total, counts) => total + counts[field], 0);
      if (observed !== globalCounts[field]) {
        problems.push(
          `${label} ${field} total does not match completed files: ` +
          `phase=${globalCounts[field]}, files=${observed}.`,
        );
      }
    }
  }

  const skipEvents = events.filter((event) =>
    event?.type === 'test:pass' && isStatusReason(event?.data?.details?.skip));
  const allowedSkips = [];
  const allowedSkipsByFile = new Map();
  for (const event of skipEvents) {
    const file = normalizeEventFile(event?.data?.file, root);
    const name = String(event?.data?.name ?? '');
    const reportedReason = event?.data?.details?.skip;
    const allowlistEntry = baseline.skipAllowlist?.find((entry) =>
      entry.file === file &&
      entry.name === name &&
      Object.is(entry.reportedReason, reportedReason) &&
      entry.platforms?.includes(platform));
    if (!allowlistEntry) {
      problems.push(
        `Unallowlisted skip in ${file} for "${name}" on ${platform}; ` +
        `reported reason ${formatReason(reportedReason)}.`,
      );
      continue;
    }
    allowedSkips.push({
      file,
      name,
      reason: allowlistEntry.reason,
      reportedReason,
      platform,
    });
    allowedSkipsByFile.set(file, (allowedSkipsByFile.get(file) ?? 0) + 1);
  }

  if (globalCounts && globalCounts.failed > 0) {
    problems.push(`Failed tests are forbidden: ${globalCounts.failed} reported.`);
  }
  if (globalCounts && globalCounts.skipped !== skipEvents.length) {
    problems.push(
      `${label} reported ${globalCounts.skipped} skipped test(s), but ` +
      `${skipEvents.length} skip event(s) were auditable.`,
    );
  }

  const todoEvents = events.filter((event) =>
    event?.type === 'test:pass' && isStatusReason(event?.data?.details?.todo));
  if (globalCounts?.todo > 0) {
    problems.push(
      `Todo tests are forbidden: ${globalCounts.todo} reported` +
      formatStatusIdentities(todoEvents, root) +
      '.',
    );
  }
  if (globalCounts && globalCounts.todo !== todoEvents.length) {
    problems.push(
      `${label} reported ${globalCounts.todo} todo test(s), but ` +
      `${todoEvents.length} todo event(s) were auditable.`,
    );
  }

  const cancelledEvents = events.filter((event) =>
    event?.type === 'test:fail' &&
    event?.data?.details?.error?.failureType === 'cancelledByParent');
  if (globalCounts?.cancelled > 0) {
    problems.push(
      `Cancelled tests are forbidden: ${globalCounts.cancelled} reported` +
      formatStatusIdentities(cancelledEvents, root) +
      '.',
    );
  }
  if (globalCounts && globalCounts.cancelled !== cancelledEvents.length) {
    problems.push(
      `${label} reported ${globalCounts.cancelled} cancelled test(s), but ` +
      `${cancelledEvents.length} cancellation event(s) were auditable.`,
    );
  }

  const testIdentityCounts = new Map();
  for (const event of events.filter((candidate) =>
    (candidate?.type === 'test:pass' || candidate?.type === 'test:fail') &&
    candidate?.data?.details?.type === 'test' &&
    candidate?.data?.file != null)) {
    const file = normalizeEventFile(event.data.file, root);
    const name = String(event.data.name ?? '');
    if (!expected.has(file) || name.length === 0) continue;
    const identity = JSON.stringify([file, name]);
    testIdentityCounts.set(
      identity,
      (testIdentityCounts.get(identity) ?? 0) + 1,
    );
  }
  if (globalCounts) {
    const identityTotal = [...testIdentityCounts.values()]
      .reduce((total, count) => total + count, 0);
    if (identityTotal !== globalCounts.tests) {
      problems.push(
        `${label} emitted ${identityTotal} auditable runtime test identities ` +
        `for ${globalCounts.tests} reported tests.`,
      );
    }
  }

  throwIntegrityProblems(label, problems);
  return {
    phase,
    label,
    expected,
    counts: globalCounts,
    fileCounts,
    allowedSkips,
    allowedSkipsByFile,
    testIdentityCounts,
  };
}

function validatePerFileBaseline(value, expected, label, problems) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    problems.push(
      `${label} has no generated per-file pass baseline; authoritative generation is required.`,
    );
    return null;
  }

  const minimums = new Map();
  for (const [rawFile, minimumPassed] of Object.entries(value)) {
    const file = normalizeSlashes(rawFile);
    if (!Number.isInteger(minimumPassed) || minimumPassed < 0) {
      problems.push(
        `${label} per-file baseline for ${file} is invalid: ${String(minimumPassed)}.`,
      );
      continue;
    }
    minimums.set(file, minimumPassed);
  }

  const missing = [...expected].filter((file) => !minimums.has(file));
  const extra = [...minimums.keys()].filter((file) => !expected.has(file));
  if (missing.length > 0) {
    problems.push(
      `${label} per-file baseline is missing manifest file(s): ${missing.join(', ')}.`,
    );
  }
  if (extra.length > 0) {
    problems.push(
      `${label} per-file baseline has extra file(s): ${extra.join(', ')}.`,
    );
  }
  return minimums;
}

function validateTestIdentityCounts(value, label, problems) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    problems.push(
      `${label} has no generated runtime test-identity baseline; ` +
      `authoritative generation is required.`,
    );
    return new Map();
  }
  const counts = new Map();
  for (const [identity, count] of Object.entries(value)) {
    if (!Number.isInteger(count) || count <= 0) {
      problems.push(
        `${label} test identity ${identity} has invalid multiplicity ` +
        `${String(count)}.`,
      );
      continue;
    }
    try {
      const parsed = JSON.parse(identity);
      if (
        !Array.isArray(parsed) ||
        parsed.length !== 2 ||
        parsed.some((part) => typeof part !== 'string' || part.length === 0)
      ) {
        throw new Error('identity must be [file, name]');
      }
    } catch {
      problems.push(`${label} has invalid test identity key ${identity}.`);
      continue;
    }
    counts.set(identity, count);
  }
  if (counts.size === 0) {
    problems.push(`${label} runtime test-identity baseline is empty.`);
  }
  return counts;
}

function throwIntegrityProblems(label, problems) {
  if (problems.length === 0) return;
  throw new Error(
    `[test-integrity] ${label} failed:\n` +
    problems.map((problem) => `- ${problem}`).join('\n'),
  );
}

function validateCounts(value, context, problems) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    problems.push(`${context} has no structured counts.`);
    return null;
  }
  const counts = {};
  for (const field of countFields) {
    if (!Number.isInteger(value[field]) || value[field] < 0) {
      problems.push(`${context} has invalid ${field} count ${String(value[field])}.`);
      return null;
    }
    counts[field] = value[field];
  }
  const accounted =
    counts.passed +
    counts.failed +
    counts.cancelled +
    counts.skipped +
    counts.todo;
  if (accounted !== counts.tests) {
    problems.push(
      `${context} test accounting is inconsistent: tests=${counts.tests}, ` +
      `outcomes=${accounted}.`,
    );
  }
  return counts;
}

function isManifestFileCompletion(event, expectedFile, root) {
  if (event?.type !== 'test:complete' ||
      event?.data?.nesting !== 0 ||
      event?.data?.details?.type !== 'test' ||
      normalizeEventFile(event?.data?.file, root) !== expectedFile) {
    return false;
  }
  const name = normalizeSlashes(String(event?.data?.name ?? ''));
  if (name === expectedFile) return true;
  return normalizeEventFile(name, root) === expectedFile;
}

function normalizeEventFile(value, root) {
  if (typeof value !== 'string' || value.length === 0) return '<unknown>';
  let path = value;
  if (path.startsWith('file:')) {
    try {
      path = fileURLToPath(path);
    } catch {
      return normalizeSlashes(path);
    }
  }
  const absolute = isAbsolute(path) ? resolve(path) : resolve(root, path);
  return normalizeSlashes(relative(root, absolute));
}

function normalizeSlashes(value) {
  return String(value).split('\\').join('/');
}

function isStatusReason(value) {
  return value === true || (typeof value === 'string' && value.length > 0);
}

function formatReason(value) {
  return value === true ? 'true' : JSON.stringify(value);
}

function formatStatusIdentities(events, root) {
  if (events.length === 0) return '';
  const identities = events.map((event) =>
    `${normalizeEventFile(event?.data?.file, root)} :: ` +
    `"${String(event?.data?.name ?? '')}"`);
  return ` (${identities.join(', ')})`;
}

function readStableFile(path) {
  let descriptor = null;
  let observedExistingPath = false;
  try {
    const pathBefore = lstatSync(path, { bigint: true });
    observedExistingPath = true;
    assertRegularFileIdentity(path, pathBefore, pathBefore, 'before open');
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    descriptor = openSync(path, fsConstants.O_RDONLY | noFollow);
    const descriptorBefore = fstatSync(descriptor, { bigint: true });
    assertRegularFileIdentity(
      path,
      pathBefore,
      descriptorBefore,
      'before read',
    );

    const digest = createHash('sha256');
    const chunks = [];
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
      const chunk = Buffer.from(buffer.subarray(0, bytesRead));
      chunks.push(chunk);
      digest.update(chunk);
      position += bytesRead;
    }

    const descriptorAfter = fstatSync(descriptor, { bigint: true });
    const pathAfter = lstatSync(path, { bigint: true });
    assertRegularFileIdentity(
      path,
      descriptorBefore,
      descriptorAfter,
      'during read',
    );
    assertRegularFileIdentity(path, descriptorAfter, pathAfter, 'after read');
    if (
      descriptorBefore.size !== descriptorAfter.size ||
      descriptorBefore.mtimeNs !== descriptorAfter.mtimeNs ||
      descriptorBefore.ctimeNs !== descriptorAfter.ctimeNs
    ) {
      throw new Error(`File changed while it was fingerprinted: ${path}`);
    }
    const bytes = Buffer.concat(chunks);
    if (BigInt(bytes.length) !== descriptorAfter.size) {
      throw new Error(`File size changed while it was fingerprinted: ${path}`);
    }
    return {
      bytes,
      snapshot: fileSnapshot(descriptorAfter, digest.digest('hex')),
    };
  } catch (error) {
    if (error?.code !== 'ENOENT' || observedExistingPath) throw error;
    return {
      bytes: null,
      snapshot: missingFileSnapshot(),
    };
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

function fileSnapshot(stat, digest) {
  return Object.freeze({
    exists: true,
    dev: String(stat.dev),
    ino: String(stat.ino),
    size: String(stat.size),
    mtimeNs: String(stat.mtimeNs),
    ctimeNs: String(stat.ctimeNs),
    digest,
    mode: Number(stat.mode & 0o777n),
  });
}

function missingFileSnapshot() {
  return Object.freeze({
    exists: false,
    dev: null,
    ino: null,
    size: null,
    mtimeNs: null,
    ctimeNs: null,
    digest: null,
    mode: null,
  });
}

function sameFileSnapshot(left, right) {
  return left?.exists === right.exists &&
    left?.dev === right.dev &&
    left?.ino === right.ino &&
    left?.size === right.size &&
    left?.mtimeNs === right.mtimeNs &&
    left?.ctimeNs === right.ctimeNs &&
    left?.digest === right.digest &&
    left?.mode === right.mode;
}

function assertRegularFileIdentity(path, left, right, context) {
  if (
    left.dev !== right.dev ||
    left.ino !== right.ino ||
    !right.isFile() ||
    right.isSymbolicLink()
  ) {
    throw new Error(`File identity changed ${context}: ${path}`);
  }
}
