import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statfsSync,
  writeFileSync,
} from 'node:fs';
import {
  dirname,
  join,
  resolve,
} from 'node:path';
import {
  captureSystemDiskTransferBytes,
  systemDiskTransferDeltaBytes,
} from './system-io.mjs';
import {
  initializeProcessGroupWriteAccounting,
} from './process-io.mjs';
import {
  canonicalJson,
  captureProcessIdentity,
  pathIdentityMatches,
  processIdentityMatches,
  processIdentityMatchesAfterDarwinReparent,
  sealWatchdogReceipt,
  verifyWatchdogReceiptSeal,
  verifyWatchdogStateSeal,
} from './watchdog-contract.mjs';

const statePath = process.argv[2];
const expectedStatePath = process.env.RADAR_TEST_WATCHDOG_STATE_PATH;
const expectedRunId = process.env.RADAR_TEST_WATCHDOG_RUN_ID;
const expectedRepositoryIdentity =
  process.env.RADAR_TEST_WATCHDOG_REPOSITORY_IDENTITY;
const watchdogToken = process.env.RADAR_TEST_WATCHDOG_TOKEN;
if (
  !statePath ||
  !expectedStatePath ||
  !expectedRunId ||
  !expectedRepositoryIdentity ||
  !watchdogToken
) {
  process.exit(64);
}

const pollMs = 250;
const staleHeartbeatMs = 10_000;
const terminationGraceMs = 5_000;
const terminationKillMs = 5_000;
const processGroupIdentityGraceMs = 1_000;
const systemIoPollMs = 1_000;
const processWriteAuditMs = 1_000;
const hardMaximumProcessWriteBytes = 4096 * 1024 * 1024;
let nextSystemIoInspectionAt = 0;
let nextProcessWriteAuditAt = 0;
let processWriteAccounting = null;
let latestProcessWriteSnapshot = null;
let processWriteAccountingFailure = null;
const retiredProcessGroupAssignments = new Set();
const leaderlessProcessGroupAssignments = new Set();
const reparentedProcessGroupAssignments = new Set();
const observedProcessGroupCommandTransitions = new Set();
const pendingProcessGroupIdentities = new Map();
let activeProcessGroupAssignmentKey = null;

try {
  await runWatchdog();
} catch (error) {
  try {
    process.stderr.write(
      `[resource-watchdog] ${normalizeError(error).stack ?? normalizeError(error).message}\n`,
    );
  } catch {
    // Durable audit and receipt handling below remain authoritative.
  }
  let state = null;
  try {
    state = readState();
  } catch {
    // Malformed state may be the failure being reported.
  }
  appendAudit(state?.auditPath, {
    type: 'watchdog-failure',
    runId: state?.runId ?? null,
    watchdogPid: process.pid,
    message: normalizeError(error).message,
    processWriteAccounting: currentProcessWriteSnapshot(),
    recordedAt: new Date().toISOString(),
  });
  if (state) {
    let termination = null;
    try {
      termination = await terminateOwnedProcesses(state, {
        cause: 'watchdog-failure',
        detail: { message: normalizeError(error).message },
      });
    } catch (terminationError) {
      appendAudit(state.auditPath, {
        type: 'watchdog-failure-cleanup-error',
        runId: state.runId,
        watchdogPid: process.pid,
        message: normalizeError(terminationError).message,
        recordedAt: new Date().toISOString(),
      });
    }
    try {
      finalizeTerminalReceipt(state, {
        outcome: 'watchdog-failure',
        success: false,
        detail: {
          message: normalizeError(error).message,
          termination,
        },
        preserveTempRoot: true,
        tempRootRemoved: false,
      });
    } catch (receiptError) {
      appendAudit(state.auditPath, {
        type: 'watchdog-terminal-receipt-failure',
        runId: state.runId,
        watchdogPid: process.pid,
        message: normalizeError(receiptError).message,
        recordedAt: new Date().toISOString(),
      });
    }
  }
  process.exitCode = 1;
}

async function runWatchdog() {
  let ready = false;
  let resourceBreach = null;
  const interruptedProcessGroupAssignments = new Set();
  let systemIoPressureRecorded = false;
  while (true) {
    const state = readState();
    if (!state) return;
    if (!ready) {
      try {
        processWriteAccounting = initializeProcessGroupWriteAccounting({
          tempRoot: state.tempRoot,
        });
      } catch (error) {
        processWriteAccountingFailure = normalizeError(error).message;
        throw error;
      }
      if (
        process.platform === 'darwin' &&
        processWriteAccounting.supported !== true
      ) {
        const error = new Error(
          'Darwin process write accounting initialized as unsupported.',
        );
        processWriteAccountingFailure = error.message;
        throw error;
      }
      processWriteAccountingFailure = null;
      latestProcessWriteSnapshot = processWriteAccounting.snapshot();
      appendAuditRequired(state.auditPath, {
        type: 'watchdog-process-write-accounting-ready',
        runId: state.runId,
        watchdogPid: process.pid,
        detail: currentProcessWriteSnapshot(),
        recordedAt: new Date().toISOString(),
      });
      await acknowledgeReadiness(state);
      ready = true;
    }
    const parentAlive = processIdentityAlive(state.parentIdentity);
    const heartbeatAgeMs = Date.now() - Date.parse(state.heartbeatAt);
    const processWriteProblem = inspectProcessWrites(state, {
      forceAudit: state.completed === true,
    });
    const finalResourceProblem =
      processWriteProblem ?? inspectResources(state);
    if (resourceBreach === null && finalResourceProblem) {
      resourceBreach = recordResourceBreach(state, {
        parentAlive,
        heartbeatAgeMs,
        resourceProblem: finalResourceProblem,
      });
    }
    if (state.completed === true) {
      if (processGroupAlive(state)) {
        const termination = await terminateProcessGroup(state, {
          cause: 'completed-with-live-process-group',
          detail: null,
        });
        finalizeTerminalReceipt(state, {
          outcome: 'completed-with-live-process-group',
          success: false,
          detail: { termination },
          preserveTempRoot: true,
          tempRootRemoved: false,
        });
        process.exitCode = 1;
        return;
      }
      appendAuditRequired(state.auditPath, {
        type: 'watchdog-final-resource-inspection',
        runId: state.runId,
        watchdogPid: process.pid,
        resourceBreach,
        processWriteAccounting: currentProcessWriteSnapshot(),
        recordedAt: new Date().toISOString(),
      });
      if (resourceBreach !== null) {
        finalizeTerminalReceipt(state, {
          outcome: 'resource-breach',
          success: false,
          detail: {
            resourceBreach,
          },
          preserveTempRoot: true,
          tempRootRemoved: false,
        });
        process.exitCode = 1;
        return;
      }
      const receipt = finalizeTerminalReceipt(state, {
        outcome: 'completed',
        success: true,
        detail: { resourceBreach: null },
        preserveTempRoot: state.preserveTempRoot === true,
        tempRootRemoved: false,
      });
      if (receipt.success !== true) process.exitCode = 1;
      return;
    }

    if (
      !parentAlive ||
      !Number.isFinite(heartbeatAgeMs) ||
      heartbeatAgeMs > staleHeartbeatMs
    ) {
      const cause = !parentAlive ? 'parent-death' : 'stale-heartbeat';
      const termination = await terminateOwnedProcesses(state, {
        cause,
        detail: {
          parentAlive,
          heartbeatAgeMs,
        },
      });
      const tempRootRemoved = termination.success
        ? removeTempRoot(state)
        : false;
      finalizeTerminalReceipt(state, {
        outcome: cause,
        success: termination.success && tempRootRemoved,
        detail: {
          heartbeatAgeMs,
          parentAlive,
          termination,
        },
        preserveTempRoot: !tempRootRemoved,
        tempRootRemoved,
      });
      process.exitCode = 1;
      return;
    }

    if (!systemIoPressureRecorded) {
      const systemIoPressure = inspectSystemIoPressure(state);
      if (systemIoPressure) {
        systemIoPressureRecorded = true;
        appendAudit(state.auditPath, {
          type: 'watchdog-system-io-pressure',
          runId: state.runId,
          watchdogPid: process.pid,
          parentPid: state.parentPid,
          activeProcessGroupPid: state.activeProcessGroupPid,
          detail: systemIoPressure,
          recordedAt: new Date().toISOString(),
        });
      }
    }

    if (
      resourceBreach !== null &&
      Number.isInteger(state.activeProcessGroupPid) &&
      state.activeProcessGroupPid > 0
    ) {
      const assignmentKey = processGroupAssignmentKey(state);
      if (!interruptedProcessGroupAssignments.has(assignmentKey)) {
        interruptedProcessGroupAssignments.add(assignmentKey);
        await terminateProcessGroup(state, {
          cause: 'resource-breach',
          detail: resourceBreach,
        });
      }
    }
    await sleep(pollMs);
  }
}

function recordResourceBreach(state, detail) {
  appendAuditRequired(state.auditPath, {
    type: 'watchdog-resource-breach',
    runId: state.runId,
    watchdogPid: process.pid,
    parentPid: state.parentPid,
    activeProcessGroupPid: state.activeProcessGroupPid,
    detail,
    recordedAt: new Date().toISOString(),
  });
  return detail;
}

function readState() {
  try {
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    if (
      state?.schemaVersion !== 2 ||
      !verifyWatchdogStateSeal(state, watchdogToken) ||
      typeof state.runId !== 'string' ||
      state.runId !== expectedRunId ||
      !Number.isInteger(state.parentPid) ||
      state.parentPid <= 0 ||
      state.parentIdentity?.pid !== state.parentPid ||
      !processIdentityMatches(
        state.parentIdentity,
        state.parentIdentity,
      ) ||
      state.repositoryIdentity !== expectedRepositoryIdentity ||
      typeof state.tempRoot !== 'string' ||
      typeof state.tempRootOwnerPath !== 'string' ||
      typeof state.auditPath !== 'string' ||
      typeof state.auditRoot !== 'string' ||
      typeof state.receiptPath !== 'string' ||
      typeof state.heartbeatAt !== 'string' ||
      !state.limits ||
      typeof state.limits !== 'object' ||
      !Number.isFinite(state.limits.minimumRuntimeFreeBytes) ||
      !Number.isFinite(state.limits.maximumSuiteBytes) ||
      !Number.isFinite(state.limits.maximumWorkerBytes) ||
      !Number.isFinite(state.limits.maximumProcessWriteBytes) ||
      state.limits.maximumProcessWriteBytes <= 0 ||
      state.limits.maximumProcessWriteBytes >
        hardMaximumProcessWriteBytes ||
      !Number.isFinite(state.limits.maximumSystemDiskTransferBytes) ||
      (
        state.systemDiskTransferBaselineBytes !== null &&
        !Number.isFinite(state.systemDiskTransferBaselineBytes)
      )
    ) {
      throw new Error('Resource watchdog state is malformed.');
    }
    assertStatePaths(state);
    if (
      state.activeProcessGroupPid === null &&
      (
        state.activeProcessGroupIdentity !== null ||
        (
          state.activeProcessGroupAllowedCommandDigests !== null &&
          state.activeProcessGroupAllowedCommandDigests !== undefined
        )
      )
    ) {
      throw new Error(
        'Resource watchdog process-group authority exists without a PID.',
      );
    }
    if (
      state.activeProcessGroupPid !== null &&
      (
        !Number.isInteger(state.activeProcessGroupPid) ||
        state.activeProcessGroupPid <= 0 ||
        state.activeProcessGroupIdentity?.pid !==
          state.activeProcessGroupPid ||
        !processIdentityMatches(
          state.activeProcessGroupIdentity,
          state.activeProcessGroupIdentity,
          {
            requireProcessGroupLeader: process.platform !== 'win32',
            allowedCommandDigests:
              processGroupAllowedCommandDigests(state),
          },
        )
      )
    ) {
      throw new Error(
        'Resource watchdog process-group identity is malformed.',
      );
    }
    if (state.activeProcessGroupPid !== null) {
      const assignmentKey = processGroupAssignmentKey(state);
      if (
        activeProcessGroupAssignmentKey !== null &&
        activeProcessGroupAssignmentKey !== assignmentKey
      ) {
        retiredProcessGroupAssignments.add(
          activeProcessGroupAssignmentKey,
        );
        pendingProcessGroupIdentities.delete(
          activeProcessGroupAssignmentKey,
        );
      }
      activeProcessGroupAssignmentKey = assignmentKey;
    } else if (activeProcessGroupAssignmentKey !== null) {
      retiredProcessGroupAssignments.add(
        activeProcessGroupAssignmentKey,
      );
      pendingProcessGroupIdentities.delete(
        activeProcessGroupAssignmentKey,
      );
      activeProcessGroupAssignmentKey = null;
    }
    return state;
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function acknowledgeReadiness(state) {
  if (typeof process.send !== 'function') return;
  await new Promise((resolvePromise, rejectPromise) => {
    try {
      process.send({
        type: 'watchdog-ready',
        runId: state.runId,
        statePath,
        watchdogPid: process.pid,
      }, (error) => {
        try {
          if (error) rejectPromise(error);
          else resolvePromise();
        } catch (callbackError) {
          rejectPromise(callbackError);
        }
      });
    } catch (error) {
      rejectPromise(error);
    }
  });
  try {
    process.disconnect();
  } catch {
    // The parent may close the IPC channel immediately after the acknowledgement.
  }
}

function inspectResources(state) {
  try {
    const availableBytes = filesystemAvailableBytes(state.tempRoot);
    if (availableBytes < state.limits.minimumRuntimeFreeBytes) {
      return {
        kind: 'free-space',
        observedBytes: availableBytes,
        limitBytes: state.limits.minimumRuntimeFreeBytes,
      };
    }
    const suiteBytes = directoryFootprint(state.tempRoot);
    if (suiteBytes > state.limits.maximumSuiteBytes) {
      return {
        kind: 'suite-footprint',
        observedBytes: suiteBytes,
        limitBytes: state.limits.maximumSuiteBytes,
      };
    }
    for (const entry of readdirSync(state.tempRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || !entry.name.startsWith('worker-')) continue;
      const workerBytes = directoryFootprint(join(state.tempRoot, entry.name));
      if (workerBytes > state.limits.maximumWorkerBytes) {
        return {
          kind: 'worker-footprint',
          worker: entry.name,
          observedBytes: workerBytes,
          limitBytes: state.limits.maximumWorkerBytes,
        };
      }
    }
    return null;
  } catch (error) {
    return {
      kind: 'watchdog-inspection',
      message: normalizeError(error).message,
    };
  }
}

function inspectProcessWrites(state, {
  forceAudit = false,
} = {}) {
  if (!processWriteAccounting) {
    throw new Error('Process write accounting was not initialized.');
  }
  try {
    if (
      Number.isInteger(state.activeProcessGroupPid) &&
      state.activeProcessGroupPid > 0
    ) {
      const assignmentUsable = assertProcessGroupAssignmentUsable(state, {
        operation: 'process-write-accounting',
        failureMessage:
          'Process write accounting refused an unverified process group.',
      });
      if (!assignmentUsable) {
        latestProcessWriteSnapshot = processWriteAccounting.snapshot();
      } else {
        latestProcessWriteSnapshot = processWriteAccounting.sample(
          state.activeProcessGroupPid,
        );
      }
    } else {
      latestProcessWriteSnapshot = processWriteAccounting.sample(null);
    }
  } catch (error) {
    processWriteAccountingFailure = normalizeError(error).message;
    throw error;
  }
  const snapshot = currentProcessWriteSnapshot();
  if (forceAudit || Date.now() >= nextProcessWriteAuditAt) {
    nextProcessWriteAuditAt = Date.now() + processWriteAuditMs;
    appendAuditRequired(state.auditPath, {
      type: 'watchdog-process-write-accounting',
      runId: state.runId,
      watchdogPid: process.pid,
      activeProcessGroupPid: state.activeProcessGroupPid,
      detail: snapshot,
      recordedAt: new Date().toISOString(),
    });
  }
  if (
    snapshot.supported === true &&
    snapshot.currentBytes > state.limits.maximumProcessWriteBytes
  ) {
    return {
      kind: 'process-group-cumulative-write',
      observedBytes: snapshot.currentBytes,
      limitBytes: state.limits.maximumProcessWriteBytes,
      accounting: snapshot,
    };
  }
  return null;
}

function inspectSystemIoPressure(state) {
  if (
    state.systemDiskTransferBaselineBytes === null ||
    Date.now() < nextSystemIoInspectionAt
  ) {
    return null;
  }
  nextSystemIoInspectionAt = Date.now() + systemIoPollMs;
  try {
    const currentBytes = captureSystemDiskTransferBytes();
    if (currentBytes === null) return null;
    const transferredBytes = systemDiskTransferDeltaBytes(
      state.systemDiskTransferBaselineBytes,
      currentBytes,
    );
    if (transferredBytes <= state.limits.maximumSystemDiskTransferBytes) {
      return null;
    }
    return {
      kind: 'whole-system-disk-transfer',
      observedBytes: transferredBytes,
      limitBytes: state.limits.maximumSystemDiskTransferBytes,
      enforcement: 'telemetry-only',
    };
  } catch (error) {
    return {
      kind: 'whole-system-disk-transfer-monitoring',
      message: normalizeError(error).message,
      enforcement: 'telemetry-only',
    };
  }
}

function directoryFootprint(path) {
  let total = 0;
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch (error) {
    if (isMissingPathError(error)) return 0;
    throw error;
  }
  for (const entry of entries) {
    const entryPath = join(path, entry.name);
    let stats;
    try {
      stats = lstatSync(entryPath);
    } catch (error) {
      if (isMissingPathError(error)) continue;
      throw error;
    }
    if (stats.isSymbolicLink()) {
      total += stats.size;
      continue;
    }
    if (stats.isDirectory()) total += directoryFootprint(entryPath);
    else if (stats.isFile()) total += stats.size;
  }
  return total;
}

function isMissingPathError(error) {
  return error != null &&
    typeof error === 'object' &&
    'code' in error &&
    error.code === 'ENOENT';
}

function filesystemAvailableBytes(path) {
  const stats = statfsSync(path);
  return Number(stats.bavail) * Number(stats.bsize);
}

async function terminateProcessGroup(state, {
  cause,
  detail,
}) {
  const signalFailures = [];
  let nextAccountingSampleAt = 0;
  appendAudit(state.auditPath, {
    type: 'watchdog-process-group-termination',
    runId: state.runId,
    watchdogPid: process.pid,
    parentPid: state.parentPid,
    activeProcessGroupPid: state.activeProcessGroupPid,
    cause,
    detail,
    recordedAt: new Date().toISOString(),
  });

  nextAccountingSampleAt = sampleProcessWritesForTermination(
    state,
    nextAccountingSampleAt,
  );
  signalGroup(state, 'SIGTERM', signalFailures);
  const graceDeadline = Date.now() + terminationGraceMs;
  while (
    Date.now() < graceDeadline &&
    processGroupAlive(state)
  ) {
    nextAccountingSampleAt = sampleProcessWritesForTermination(
      state,
      nextAccountingSampleAt,
    );
    await sleep(50);
  }

  const killDeadline = Date.now() + terminationKillMs;
  while (
    Date.now() < killDeadline &&
    processGroupAlive(state)
  ) {
    nextAccountingSampleAt = sampleProcessWritesForTermination(
      state,
      nextAccountingSampleAt,
    );
    signalGroup(state, 'SIGKILL', signalFailures);
    await sleep(pollMs);
  }

  const processGroupStillAlive =
    processGroupAlive(state);
  const processWriteAccounting = currentProcessWriteSnapshot();
  appendAudit(state.auditPath, {
    type: processGroupStillAlive
      ? 'watchdog-process-group-termination-unconfirmed'
      : 'watchdog-process-group-termination-confirmed',
    runId: state.runId,
    watchdogPid: process.pid,
    parentPid: state.parentPid,
    activeProcessGroupPid: state.activeProcessGroupPid,
    cause,
    signalFailures,
    processWriteAccounting,
    recordedAt: new Date().toISOString(),
  });
  return {
    success: !processGroupStillAlive && signalFailures.length === 0,
    processGroupStillAlive,
    signalFailures,
    processWriteAccounting,
  };
}

async function terminateOwnedProcesses(state, {
  cause,
  detail,
}) {
  const signalFailures = [];
  let nextAccountingSampleAt = 0;
  appendAudit(state.auditPath, {
    type: 'watchdog-termination',
    runId: state.runId,
    watchdogPid: process.pid,
    parentPid: state.parentPid,
    activeProcessGroupPid: state.activeProcessGroupPid,
    cause,
    detail,
    recordedAt: new Date().toISOString(),
  });

  nextAccountingSampleAt = sampleProcessWritesForTermination(
    state,
    nextAccountingSampleAt,
  );
  signalGroup(state, 'SIGTERM', signalFailures);
  signalProcess(state, 'SIGTERM', signalFailures);
  const graceDeadline = Date.now() + terminationGraceMs;
  while (
    Date.now() < graceDeadline &&
    (
      processGroupAlive(state) ||
      processIdentityAlive(state.parentIdentity)
    )
  ) {
    nextAccountingSampleAt = sampleProcessWritesForTermination(
      state,
      nextAccountingSampleAt,
    );
    await sleep(50);
  }

  const killDeadline = Date.now() + terminationKillMs;
  while (
    Date.now() < killDeadline &&
    (
      processGroupAlive(state) ||
      processIdentityAlive(state.parentIdentity)
    )
  ) {
    nextAccountingSampleAt = sampleProcessWritesForTermination(
      state,
      nextAccountingSampleAt,
    );
    signalGroup(state, 'SIGKILL', signalFailures);
    signalProcess(state, 'SIGKILL', signalFailures);
    await sleep(pollMs);
  }

  const processGroupStillAlive =
    processGroupAlive(state);
  const parentStillAlive = processIdentityAlive(state.parentIdentity);
  const processWriteAccounting = currentProcessWriteSnapshot();
  if (processGroupStillAlive || parentStillAlive) {
    appendAudit(state.auditPath, {
      type: 'watchdog-termination-unconfirmed',
      runId: state.runId,
      watchdogPid: process.pid,
      parentPid: state.parentPid,
      activeProcessGroupPid: state.activeProcessGroupPid,
      processGroupStillAlive,
      parentStillAlive,
      cause,
      signalFailures,
      processWriteAccounting,
      recordedAt: new Date().toISOString(),
    });
    return {
      success: false,
      processGroupStillAlive,
      parentStillAlive,
      signalFailures,
      processWriteAccounting,
    };
  }

  appendAudit(state.auditPath, {
    type: 'watchdog-termination-confirmed',
    runId: state.runId,
    watchdogPid: process.pid,
    parentPid: state.parentPid,
    activeProcessGroupPid: state.activeProcessGroupPid,
    cause,
    signalFailures,
    processWriteAccounting,
    recordedAt: new Date().toISOString(),
  });
  return {
    success: signalFailures.length === 0,
    processGroupStillAlive,
    parentStillAlive,
    signalFailures,
    processWriteAccounting,
  };
}

function sampleProcessWritesForTermination(state, nextSampleAt) {
  const now = Date.now();
  if (
    now < nextSampleAt ||
    !processWriteAccounting ||
    !Number.isInteger(state.activeProcessGroupPid) ||
    state.activeProcessGroupPid <= 0 ||
    !processGroupAlive(state)
  ) {
    return nextSampleAt;
  }
  try {
    const assignmentUsable = assertProcessGroupAssignmentUsable(state, {
      operation: 'termination-accounting',
      failureMessage:
        'Termination accounting refused an unverified process group.',
    });
    latestProcessWriteSnapshot = assignmentUsable
      ? processWriteAccounting.sample(state.activeProcessGroupPid)
      : processWriteAccounting.snapshot();
  } catch (error) {
    processWriteAccountingFailure = normalizeError(error).message;
    appendAudit(state.auditPath, {
      type: 'watchdog-process-write-accounting-failure',
      runId: state.runId,
      watchdogPid: process.pid,
      activeProcessGroupPid: state.activeProcessGroupPid,
      message: processWriteAccountingFailure,
      recordedAt: new Date().toISOString(),
    });
  }
  return now + pollMs;
}

function signalGroup(state, signal, failures) {
  const pid = state.activeProcessGroupPid;
  if (
    process.platform === 'win32' ||
    !Number.isInteger(pid) ||
    pid <= 0
  ) {
    return true;
  }
  if (!processGroupAlive(state)) return true;
  try {
    const assignmentUsable = assertProcessGroupAssignmentUsable(state, {
      operation: `signal-${signal}`,
      failureMessage: 'Process-group identity changed before signaling.',
    });
    if (!assignmentUsable) return true;
  } catch (error) {
    return recordSignalFailure(state, failures, {
      target: 'process-group',
      pid,
      signal,
      code: 'IDENTITY_MISMATCH',
      message: normalizeError(error).message,
    });
  }
  try {
    process.kill(-pid, signal);
    return true;
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      return recordSignalFailure(state, failures, {
        target: 'process-group',
        pid,
        signal,
        code: error?.code ?? null,
        message: normalizeError(error).message,
      });
    }
    return true;
  }
}

function processGroupAlive(state) {
  const pid = state?.activeProcessGroupPid;
  if (
    process.platform === 'win32' ||
    !Number.isInteger(pid) ||
    pid <= 0
  ) {
    return false;
  }
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

function processAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

function signalProcess(state, signal, failures) {
  const pid = state.parentPid;
  if (!Number.isInteger(pid) || pid <= 0) return;
  const actualIdentity = captureProcessIdentity(pid);
  if (!actualIdentity) return true;
  if (!processIdentityMatches(state.parentIdentity, actualIdentity)) {
    return recordSignalFailure(state, failures, {
      target: 'parent',
      pid,
      signal,
      code: 'IDENTITY_MISMATCH',
      message: 'Parent process identity changed before signaling.',
    });
  }
  try {
    process.kill(pid, signal);
    return true;
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      return recordSignalFailure(state, failures, {
        target: 'parent',
        pid,
        signal,
        code: error?.code ?? null,
        message: normalizeError(error).message,
      });
    }
    return true;
  }
}

function assertStatePaths(state) {
  const auditRoot = resolve(state.auditRoot);
  const expectedState = join(auditRoot, `${state.runId}.watchdog.json`);
  const expectedAudit = join(auditRoot, `${state.runId}.jsonl`);
  const expectedReceipt =
    join(auditRoot, `${state.runId}.watchdog-receipt.json`);
  if (
    resolve(statePath) !== resolve(expectedStatePath) ||
    resolve(statePath) !== expectedState ||
    resolve(state.auditPath) !== expectedAudit ||
    resolve(state.receiptPath) !== expectedReceipt ||
    resolve(state.tempRootOwnerPath) !==
      join(resolve(state.tempRoot), '.runner-owner.json')
  ) {
    throw new Error('Resource watchdog paths are not bound to the run identity.');
  }
  if (
    !pathIdentityMatches(state.auditRoot, state.auditRootIdentity, {
      kind: 'directory',
    }) ||
    !pathIdentityMatches(state.auditPath, state.auditPathIdentity, {
      kind: 'file',
    }) ||
    !pathIdentityMatches(state.tempRoot, state.tempRootIdentity, {
      kind: 'directory',
    })
  ) {
    throw new Error('Resource watchdog owned-path identity changed.');
  }
  const stateStats = lstatSync(statePath);
  if (
    !stateStats.isFile() ||
    stateStats.isSymbolicLink() ||
    (
      typeof process.getuid === 'function' &&
      stateStats.uid !== process.getuid()
    ) ||
    (stateStats.mode & 0o077) !== 0
  ) {
    throw new Error('Resource watchdog state path is not a private regular file.');
  }
  const ownerStats = lstatSync(state.tempRootOwnerPath);
  const owner = JSON.parse(readFileSync(state.tempRootOwnerPath, 'utf8'));
  if (
    !ownerStats.isFile() ||
    ownerStats.isSymbolicLink() ||
    (
      typeof process.getuid === 'function' &&
      ownerStats.uid !== process.getuid()
    ) ||
    (ownerStats.mode & 0o077) !== 0 ||
    owner?.schemaVersion !== 1 ||
    owner.repositoryIdentity !== state.repositoryIdentity ||
    owner.runId !== state.runId ||
    owner.parentPid !== state.parentPid
  ) {
    throw new Error('Resource watchdog temporary-root ownership is invalid.');
  }
  if (realpathSync(state.repositoryRoot) !== state.repositoryRoot) {
    throw new Error('Resource watchdog repository root is not canonical.');
  }
}

function processIdentityAlive(expectedIdentity) {
  const actualIdentity = captureProcessIdentity(expectedIdentity?.pid);
  return processIdentityMatches(expectedIdentity, actualIdentity);
}

function processGroupIdentityStatus(state) {
  const actualIdentity =
    captureProcessIdentity(state.activeProcessGroupPid);
  const assignmentKey = processGroupAssignmentKey(state);
  if (retiredProcessGroupAssignments.has(assignmentKey)) {
    return 'retired';
  }
  const identityOptions = {
    requireProcessGroupLeader: process.platform !== 'win32',
    allowedCommandDigests: processGroupAllowedCommandDigests(state),
  };
  const strictIdentityMatch = processIdentityMatches(
    state.activeProcessGroupIdentity,
    actualIdentity,
    identityOptions,
  );
  const reparentedIdentityMatch =
    !strictIdentityMatch &&
    processIdentityMatchesAfterDarwinReparent(
      state.activeProcessGroupIdentity,
      actualIdentity,
      {
        ...identityOptions,
        parentIdentity: state.parentIdentity,
        parentAlive: processIdentityAlive(state.parentIdentity),
      },
    );
  if (strictIdentityMatch || reparentedIdentityMatch) {
    pendingProcessGroupIdentities.delete(assignmentKey);
    if (
      reparentedIdentityMatch &&
      !reparentedProcessGroupAssignments.has(assignmentKey)
    ) {
      reparentedProcessGroupAssignments.add(assignmentKey);
      appendAuditRequired(state.auditPath, {
        type: 'watchdog-process-group-reparented-after-owner-exit',
        runId: state.runId,
        watchdogPid: process.pid,
        activeProcessGroupPid: state.activeProcessGroupPid,
        previousParentPid: state.activeProcessGroupIdentity.parentPid,
        observedParentPid: actualIdentity.parentPid,
        recordedAt: new Date().toISOString(),
      });
    }
    if (
      actualIdentity.commandDigest !==
        state.activeProcessGroupIdentity.commandDigest
    ) {
      const transitionKey = canonicalJson({
        assignmentKey,
        commandDigest: actualIdentity.commandDigest,
      });
      if (!observedProcessGroupCommandTransitions.has(transitionKey)) {
        observedProcessGroupCommandTransitions.add(transitionKey);
        appendAuditRequired(state.auditPath, {
          type: 'watchdog-process-group-command-transition',
          runId: state.runId,
          watchdogPid: process.pid,
          activeProcessGroupPid: state.activeProcessGroupPid,
          fromCommandDigest:
            state.activeProcessGroupIdentity.commandDigest,
          toCommandDigest: actualIdentity.commandDigest,
          recordedAt: new Date().toISOString(),
        });
      }
    }
    return 'verified';
  }
  if (!processGroupAlive(state)) {
    pendingProcessGroupIdentities.delete(assignmentKey);
    return 'gone';
  }
  if (
    actualIdentity === null &&
    !processAlive(state.activeProcessGroupPid)
  ) {
    pendingProcessGroupIdentities.delete(assignmentKey);
    return 'leader-exited';
  }
  const now = Date.now();
  const pendingSince =
    pendingProcessGroupIdentities.get(assignmentKey);
  if (pendingSince === undefined) {
    pendingProcessGroupIdentities.set(assignmentKey, now);
    appendAuditRequired(state.auditPath, {
      type: 'watchdog-process-group-identity-pending',
      runId: state.runId,
      watchdogPid: process.pid,
      activeProcessGroupPid: state.activeProcessGroupPid,
      activeProcessGroupIdentity: state.activeProcessGroupIdentity,
      observedProcessIdentity: actualIdentity,
      graceMs: processGroupIdentityGraceMs,
      recordedAt: new Date().toISOString(),
    });
    return 'pending';
  }
  if (now - pendingSince < processGroupIdentityGraceMs) {
    return 'pending';
  }
  return 'unverified';
}

function assertProcessGroupAssignmentUsable(state, {
  operation,
  failureMessage,
}) {
  const status = processGroupIdentityStatus(state);
  if (status === 'verified') return true;
  if (status === 'gone' || status === 'pending') return false;
  if (status !== 'leader-exited') {
    throw new Error(failureMessage);
  }
  const assignmentKey = processGroupAssignmentKey(state);
  if (!leaderlessProcessGroupAssignments.has(assignmentKey)) {
    leaderlessProcessGroupAssignments.add(assignmentKey);
    appendAuditRequired(state.auditPath, {
      type: 'watchdog-process-group-leader-exited',
      runId: state.runId,
      watchdogPid: process.pid,
      activeProcessGroupPid: state.activeProcessGroupPid,
      activeProcessGroupIdentity: state.activeProcessGroupIdentity,
      operation,
      recordedAt: new Date().toISOString(),
    });
  }
  return true;
}

function processGroupAssignmentKey(state) {
  return canonicalJson({
    processGroupPid: state.activeProcessGroupPid,
    processGroupIdentity: state.activeProcessGroupIdentity,
    allowedCommandDigests: processGroupAllowedCommandDigests(state),
  });
}

function processGroupAllowedCommandDigests(state) {
  const configured = state.activeProcessGroupAllowedCommandDigests;
  if (configured === undefined) {
    return [state.activeProcessGroupIdentity.commandDigest];
  }
  return configured;
}

function recordSignalFailure(state, failures, failure) {
  const event = {
    type: 'watchdog-signal-failure',
    runId: state.runId,
    watchdogPid: process.pid,
    parentPid: state.parentPid,
    activeProcessGroupPid: state.activeProcessGroupPid,
    ...failure,
    recordedAt: new Date().toISOString(),
  };
  const key = JSON.stringify([
    event.target,
    event.pid,
    event.signal,
    event.code,
    event.message,
  ]);
  if (!failures.some((candidate) => candidate.key === key)) {
    failures.push({
      key,
      target: event.target,
      pid: event.pid,
      signal: event.signal,
      code: event.code,
      message: event.message,
    });
    appendAudit(state.auditPath, event);
  }
  return false;
}

function removeTempRoot(state) {
  if (!existsSync(state.tempRoot)) return true;
  if (
    !pathIdentityMatches(state.tempRoot, state.tempRootIdentity, {
      kind: 'directory',
    })
  ) {
    appendAudit(state.auditPath, {
      type: 'watchdog-path-removal-refused',
      runId: state.runId,
      watchdogPid: process.pid,
      path: state.tempRoot,
      reason: 'temporary-root-identity-mismatch',
      recordedAt: new Date().toISOString(),
    });
    return false;
  }
  rmSync(state.tempRoot, { recursive: true, force: true });
  return !existsSync(state.tempRoot);
}

function removeStateFile(state) {
  if (!existsSync(statePath)) return true;
  if (
    resolve(statePath) !==
      join(resolve(state.auditRoot), `${state.runId}.watchdog.json`) ||
    !pathIdentityMatches(state.auditRoot, state.auditRootIdentity, {
      kind: 'directory',
    })
  ) {
    appendAudit(state.auditPath, {
      type: 'watchdog-path-removal-refused',
      runId: state.runId,
      watchdogPid: process.pid,
      path: statePath,
      reason: 'state-path-identity-mismatch',
      recordedAt: new Date().toISOString(),
    });
    return false;
  }
  const stats = lstatSync(statePath);
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    (
      typeof process.getuid === 'function' &&
      stats.uid !== process.getuid()
    ) ||
    (stats.mode & 0o077) !== 0
  ) {
    return false;
  }
  rmSync(statePath, { force: true });
  fsyncDirectory(state.auditRoot);
  return !existsSync(statePath);
}

function currentProcessWriteSnapshot() {
  try {
    const snapshot =
      latestProcessWriteSnapshot ?? processWriteAccounting?.snapshot();
    if (snapshot) {
      return {
        ...snapshot,
        available: processWriteAccountingFailure === null,
        ...(processWriteAccountingFailure === null
          ? {}
          : { unavailableReason: processWriteAccountingFailure }),
      };
    }
  } catch {
    // The failure receipt below must survive an accounting read failure.
  }
  return {
    schemaVersion: 1,
    platform: process.platform,
    supported: process.platform === 'darwin',
    available: false,
    ...(processWriteAccountingFailure === null
      ? {}
      : { unavailableReason: processWriteAccountingFailure }),
    currentBytes: 0,
    peakBytes: 0,
    observedProcessCount: 0,
    sampledProcessCount: 0,
    activeProcessGroupPid: null,
    topWriters: [],
  };
}

function finalizeTerminalReceipt(state, options) {
  let stateRemoved = false;
  let stateRemovalError = null;
  try {
    stateRemoved = removeStateFile(state);
  } catch (error) {
    stateRemovalError = normalizeError(error);
  }
  if (!stateRemoved) {
    appendAuditRequired(state.auditPath, {
      type: 'watchdog-state-removal-failure',
      runId: state.runId,
      watchdogPid: process.pid,
      statePath,
      message: stateRemovalError?.message ?? 'state file remains present',
      intendedOutcome: options.outcome,
      recordedAt: new Date().toISOString(),
    });
  }
  const detail = stateRemoved
    ? options.detail
    : {
      intendedOutcome: options.outcome,
      intendedSuccess: options.success,
      stateRemoval: {
        success: false,
        message: stateRemovalError?.message ?? 'state file remains present',
      },
      terminalDetail: options.detail,
    };
  return writeTerminalReceipt(state, {
    ...options,
    outcome: stateRemoved || options.success !== true
      ? options.outcome
      : 'state-removal-failure',
    success: stateRemoved && options.success === true,
    preserveTempRoot: stateRemoved
      ? options.preserveTempRoot
      : true,
    detail,
    stateRemoved,
  });
}

function writeTerminalReceipt(state, {
  outcome,
  success,
  detail,
  preserveTempRoot,
  tempRootRemoved,
  stateRemoved,
}) {
  if (
    !pathIdentityMatches(state.auditRoot, state.auditRootIdentity, {
      kind: 'directory',
    }) ||
    !pathIdentityMatches(state.auditPath, state.auditPathIdentity, {
      kind: 'file',
    }) ||
    resolve(state.receiptPath) !==
      join(
        resolve(state.auditRoot),
        `${state.runId}.watchdog-receipt.json`,
      )
  ) {
    throw new Error(
      'Resource watchdog refused to write a receipt outside its audit root.',
    );
  }
  if (existsSync(state.receiptPath)) {
    throw new Error('Resource watchdog terminal receipt already exists.');
  }
  if (stateRemoved === true && existsSync(statePath)) {
    throw new Error(
      'Resource watchdog state reappeared before terminal receipt persistence.',
    );
  }
  const processWriteSnapshot = currentProcessWriteSnapshot();
  appendAuditRequired(state.auditPath, {
    type: 'watchdog-process-write-summary',
    runId: state.runId,
    watchdogPid: process.pid,
    outcome,
    success,
    stateRemoved,
    processWriteAccounting: processWriteSnapshot,
    recordedAt: new Date().toISOString(),
  });
  const receipt = sealWatchdogReceipt({
    schemaVersion: 1,
    kind: 'resource-watchdog-terminal',
    runId: state.runId,
    watchdogPid: process.pid,
    parentPid: state.parentPid,
    parentIdentity: state.parentIdentity,
    activeProcessGroupPid: state.activeProcessGroupPid,
    activeProcessGroupIdentity: state.activeProcessGroupIdentity,
    statePath,
    auditPath: state.auditPath,
    receiptPath: state.receiptPath,
    tempRoot: state.tempRoot,
    processWriteAccounting: processWriteSnapshot,
    outcome,
    success,
    preserveTempRoot,
    tempRootRemoved,
    stateRemoved,
    detail,
    recordedAt: new Date().toISOString(),
  });
  const temporaryPath =
    `${state.receiptPath}.${process.pid}.${Date.now()}.tmp`;
  const descriptor = openSync(
    temporaryPath,
    fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_WRONLY,
    0o600,
  );
  try {
    writeFileSync(descriptor, `${JSON.stringify(receipt, null, 2)}\n`);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    renameSync(temporaryPath, state.receiptPath);
    fsyncDirectory(state.auditRoot);
  } finally {
    rmSync(temporaryPath, { force: true });
  }
  const persisted = JSON.parse(readFileSync(state.receiptPath, 'utf8'));
  if (
    !verifyWatchdogReceiptSeal(persisted) ||
    persisted.contentHash !== receipt.contentHash
  ) {
    throw new Error(
      'Resource watchdog terminal receipt failed durable readback.',
    );
  }
  appendAuditRequired(state.auditPath, {
    type: 'watchdog-terminal-receipt',
    runId: state.runId,
    watchdogPid: process.pid,
    receiptPath: state.receiptPath,
    outcome,
    success,
    stateRemoved,
    processWriteAccounting: processWriteSnapshot,
    contentHash: receipt.contentHash,
    recordedAt: new Date().toISOString(),
  });
  return persisted;
}

function fsyncDirectory(path) {
  let descriptor = null;
  try {
    descriptor = openSync(path, 'r');
    fsyncSync(descriptor);
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

function appendAudit(path, event) {
  if (!path) return;
  let descriptor = null;
  try {
    descriptor = openSync(
      path,
      fsConstants.O_APPEND | fsConstants.O_WRONLY,
    );
    writeFileSync(descriptor, `${JSON.stringify(event)}\n`);
    fsyncSync(descriptor);
  } catch {
    // Supervision must continue even when diagnostics cannot be persisted.
  } finally {
    if (descriptor !== null) closeSync(descriptor);
  }
}

function appendAuditRequired(path, event) {
  const descriptor = openSync(
    path,
    fsConstants.O_APPEND | fsConstants.O_WRONLY,
  );
  try {
    writeFileSync(descriptor, `${JSON.stringify(event)}\n`);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function normalizeError(error) {
  return error instanceof Error ? error : new Error(String(error));
}

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}
