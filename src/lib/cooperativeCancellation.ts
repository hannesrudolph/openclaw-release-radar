const DEFAULT_ABORT_MESSAGE = 'The operation was aborted';

export class AbortError extends Error {
  readonly reason: unknown;

  constructor(reason?: unknown) {
    super(abortMessage(reason), reason === undefined ? undefined : { cause: reason });
    this.name = 'AbortError';
    this.reason = reason;
  }
}

export function isAbortError(error: unknown): error is Error {
  return error instanceof Error && error.name === 'AbortError';
}

export function createAbortError(reason?: unknown): AbortError {
  return reason instanceof AbortError ? reason : new AbortError(reason);
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw createAbortError(signal.reason);
}

export interface ComposedAbortSignal {
  signal: AbortSignal;
  cleanup(): void;
}

export function composeAbortSignals(
  signals: readonly (AbortSignal | null | undefined)[],
): ComposedAbortSignal {
  const controller = new AbortController();
  const uniqueSignals = [...new Set(signals.filter(
    (signal): signal is AbortSignal => signal != null,
  ))];
  const listeners: Array<{
    signal: AbortSignal;
    listener: () => void;
  }> = [];
  let cleaned = false;

  const cleanup = (): void => {
    if (cleaned) return;
    cleaned = true;
    for (const { signal, listener } of listeners) {
      signal.removeEventListener('abort', listener);
    }
    listeners.length = 0;
  };

  const abortFrom = (source: AbortSignal): void => {
    if (!controller.signal.aborted) {
      controller.abort(preservedSignalReason(source));
    }
    cleanup();
  };

  const alreadyAborted = uniqueSignals.find((signal) => signal.aborted);
  if (alreadyAborted) {
    abortFrom(alreadyAborted);
    return { signal: controller.signal, cleanup };
  }

  for (const signal of uniqueSignals) {
    const listener = (): void => abortFrom(signal);
    listeners.push({ signal, listener });
    signal.addEventListener('abort', listener, { once: true });
    if (signal.aborted) {
      abortFrom(signal);
      break;
    }
  }

  return { signal: controller.signal, cleanup };
}

export interface DelayScheduler {
  set(callback: () => void, delayMs: number): unknown;
  clear(handle: unknown): void;
}

const defaultDelayScheduler: DelayScheduler = {
  set: (callback, delayMs) => setTimeout(callback, delayMs),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export async function abortableDelay(
  delayMs: number,
  signal?: AbortSignal,
  scheduler: DelayScheduler = defaultDelayScheduler,
): Promise<void> {
  if (!Number.isFinite(delayMs) || delayMs < 0) {
    throw new RangeError(`delayMs must be a finite non-negative number, got ${String(delayMs)}`);
  }
  throwIfAborted(signal);

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let handle: unknown;
    let handleAssigned = false;
    let clearAfterAssignment = false;

    const cleanup = (): void => {
      if (handleAssigned) {
        scheduler.clear(handle);
      } else {
        clearAfterAssignment = true;
      }
      signal?.removeEventListener('abort', onAbort);
    };
    const settle = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      cleanup();
      callback();
    };
    const onAbort = (): void => {
      settle(() => reject(createAbortError(signal?.reason)));
    };

    handle = scheduler.set(() => settle(resolve), delayMs);
    handleAssigned = true;
    if (clearAfterAssignment) scheduler.clear(handle);
    if (settled) return;
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

export interface CooperativeDiagnostics {
  /** Total tasks supplied to the operation. */
  total: number;
  /** Task factories or workers that were invoked. */
  started: number;
  /** Started tasks that fulfilled, including tasks that ignored a later abort. */
  completed: number;
  /** Started tasks that rejected for a reason other than cooperative cancellation. */
  failed: number;
  /** Started tasks that rejected with an AbortError or the shared abort reason. */
  aborted: number;
  /** Started task settlements observed before the operation returned or threw. */
  drained: number;
  /** Tasks left queued and never invoked. */
  skipped: number;
}

export function createCooperativeDiagnostics(): CooperativeDiagnostics {
  return {
    total: 0,
    started: 0,
    completed: 0,
    failed: 0,
    aborted: 0,
    drained: 0,
    skipped: 0,
  };
}

export interface CooperativeExecutionOptions {
  signal?: AbortSignal;
  diagnostics?: CooperativeDiagnostics;
}

export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (
    item: T,
    index: number,
    signal: AbortSignal,
  ) => R | PromiseLike<R>,
  options: CooperativeExecutionOptions = {},
): Promise<R[]> {
  if (!Number.isInteger(concurrency) || concurrency <= 0) {
    throw new RangeError(
      `concurrency must be a positive integer, got ${String(concurrency)}`,
    );
  }

  const operation = createOperation(items.length, options);
  const results = new Array<R>(items.length);
  const startedTasks: StartedTask<R>[] = [];
  let cursor = 0;

  const runWorker = async (): Promise<void> => {
    while (!operation.stopped()) {
      const index = cursor;
      if (index >= items.length) return;
      cursor++;

      operation.diagnostics.started++;
      const promise = Promise.resolve().then(() => {
        throwIfAborted(operation.signal);
        return worker(items[index], index, operation.signal);
      });
      startedTasks.push({ index, promise });

      try {
        results[index] = await promise;
      } catch (error) {
        operation.stop(error, index);
      }
    }
  };

  try {
    const workerCount = Math.min(concurrency, items.length);
    await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
    const settlements = await Promise.allSettled(
      startedTasks.map(({ promise }) => promise),
    );
    finalizeDiagnostics(operation, startedTasks, settlements);
    operation.throwPrimary();
    return results;
  } finally {
    operation.cleanup();
  }
}

export type CooperativeTask<T> =
  | PromiseLike<T>
  | ((signal: AbortSignal) => T | PromiseLike<T>);

export type CooperativeTaskResult<TTask> =
  TTask extends (signal: AbortSignal) => infer TResult
    ? Awaited<TResult>
    : TTask extends PromiseLike<infer TResult>
      ? Awaited<TResult>
      : never;

export async function runCooperativeGroup<
  const TTasks extends readonly CooperativeTask<unknown>[],
>(
  tasks: TTasks,
  options: CooperativeExecutionOptions = {},
): Promise<{ -readonly [K in keyof TTasks]: CooperativeTaskResult<TTasks[K]> }> {
  const operation = createOperation(tasks.length, options);
  const startedTasks: StartedTask<unknown>[] = [];

  try {
    for (let index = 0; index < tasks.length; index++) {
      const task = tasks[index];
      if (typeof task === 'function' && operation.stopped()) continue;
      operation.diagnostics.started++;

      const promise = typeof task === 'function'
        ? Promise.resolve().then(() => {
            throwIfAborted(operation.signal);
            return task(operation.signal);
          })
        : Promise.resolve(task);
      startedTasks.push({ index, promise });
      void promise.then(undefined, (error) => operation.stop(error, index));
    }

    const settlements = await Promise.allSettled(
      startedTasks.map(({ promise }) => promise),
    );
    finalizeDiagnostics(operation, startedTasks, settlements);
    operation.throwPrimary();

    const results = new Array<unknown>(tasks.length);
    for (let position = 0; position < settlements.length; position++) {
      const settlement = settlements[position];
      if (settlement.status === 'fulfilled') {
        results[startedTasks[position].index] = settlement.value;
      }
    }
    return results as {
      -readonly [K in keyof TTasks]: CooperativeTaskResult<TTasks[K]>;
    };
  } finally {
    operation.cleanup();
  }
}

interface StartedTask<T> {
  index: number;
  promise: Promise<T>;
}

interface Operation {
  readonly signal: AbortSignal;
  readonly diagnostics: CooperativeDiagnostics;
  readonly primaryTaskIndex: () => number | null;
  stopped(): boolean;
  stop(error: unknown, taskIndex: number | null): void;
  throwPrimary(): void;
  cleanup(): void;
}

function createOperation(
  total: number,
  options: CooperativeExecutionOptions,
): Operation {
  const controller = new AbortController();
  const diagnostics = options.diagnostics ?? createCooperativeDiagnostics();
  resetDiagnostics(diagnostics, total);

  let hasPrimary = false;
  let primaryError: unknown;
  let primaryTaskIndex: number | null = null;
  let cleaned = false;

  const stop = (error: unknown, taskIndex: number | null): void => {
    if (hasPrimary) return;
    hasPrimary = true;
    primaryError = error;
    primaryTaskIndex = taskIndex;
    if (!controller.signal.aborted) {
      controller.abort(error === undefined ? createAbortError() : error);
    }
  };
  const onExternalAbort = (): void => {
    stop(createAbortError(options.signal?.reason), null);
  };
  const cleanup = (): void => {
    if (cleaned) return;
    cleaned = true;
    options.signal?.removeEventListener('abort', onExternalAbort);
  };

  if (options.signal?.aborted) {
    onExternalAbort();
  } else {
    options.signal?.addEventListener('abort', onExternalAbort, { once: true });
    if (options.signal?.aborted) onExternalAbort();
  }

  return {
    signal: controller.signal,
    diagnostics,
    primaryTaskIndex: () => primaryTaskIndex,
    stopped: () => hasPrimary,
    stop,
    throwPrimary: () => {
      if (hasPrimary) throw primaryError;
    },
    cleanup,
  };
}

function finalizeDiagnostics<T>(
  operation: Operation,
  startedTasks: readonly StartedTask<T>[],
  settlements: readonly PromiseSettledResult<T>[],
): void {
  const primaryTaskIndex = operation.primaryTaskIndex();
  for (let position = 0; position < settlements.length; position++) {
    const settlement = settlements[position];
    operation.diagnostics.drained++;
    if (settlement.status === 'fulfilled') {
      operation.diagnostics.completed++;
      continue;
    }

    const taskIndex = startedTasks[position].index;
    if (
      isAbortError(settlement.reason) ||
      (
        taskIndex !== primaryTaskIndex &&
        operation.signal.aborted &&
        settlement.reason === operation.signal.reason
      )
    ) {
      operation.diagnostics.aborted++;
    } else {
      operation.diagnostics.failed++;
    }
  }
  operation.diagnostics.skipped =
    operation.diagnostics.total - operation.diagnostics.started;
}

function resetDiagnostics(
  diagnostics: CooperativeDiagnostics,
  total: number,
): void {
  diagnostics.total = total;
  diagnostics.started = 0;
  diagnostics.completed = 0;
  diagnostics.failed = 0;
  diagnostics.aborted = 0;
  diagnostics.drained = 0;
  diagnostics.skipped = 0;
}

function preservedSignalReason(signal: AbortSignal): unknown {
  return signal.reason === undefined ? createAbortError() : signal.reason;
}

function abortMessage(reason: unknown): string {
  if (reason instanceof Error && reason.message) return reason.message;
  if (typeof reason === 'string' && reason) return reason;
  return DEFAULT_ABORT_MESSAGE;
}
