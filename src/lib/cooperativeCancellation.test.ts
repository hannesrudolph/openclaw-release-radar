import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  AbortError,
  abortableDelay,
  composeAbortSignals,
  createAbortError,
  createCooperativeDiagnostics,
  mapWithConcurrency,
  runCooperativeGroup,
  throwIfAborted,
  type DelayScheduler,
} from './cooperativeCancellation.ts';

describe('cooperative cancellation', { concurrency: false }, () => {
  it('creates deterministic AbortErrors while preserving the original reason', () => {
    const reason = new Error('lease lost');
    const error = createAbortError(reason);

    assert.equal(error.name, 'AbortError');
    assert.equal(error.message, 'lease lost');
    assert.equal(error.cause, reason);
    assert.equal((error as AbortError).reason, reason);

    const existing = new AbortError('shutdown');
    assert.equal(createAbortError(existing), existing);

    const runtimeAbort = new Error('runtime abort');
    runtimeAbort.name = 'AbortError';
    const normalized = createAbortError(runtimeAbort);
    assert.ok(normalized instanceof AbortError);
    assert.notEqual(normalized, runtimeAbort);
    assert.equal(normalized.reason, runtimeAbort);

    const controller = new AbortController();
    controller.abort(reason);
    assert.throws(
      () => throwIfAborted(controller.signal),
      (thrown) =>
        thrown instanceof AbortError &&
        thrown.reason === reason &&
        thrown.cause === reason,
    );
  });

  it('composes signals, preserves the first reason, and removes every listener', () => {
    const first = new AbortController();
    const second = new AbortController();
    const firstListeners = trackAbortListeners(first.signal);
    const secondListeners = trackAbortListeners(second.signal);

    try {
      const composed = composeAbortSignals([
        first.signal,
        second.signal,
        first.signal,
      ]);
      assert.equal(firstListeners.active(), 1);
      assert.equal(secondListeners.active(), 1);

      const reason = { source: 'shutdown' };
      second.abort(reason);

      assert.equal(composed.signal.aborted, true);
      assert.equal(composed.signal.reason, reason);
      assert.equal(firstListeners.active(), 0);
      assert.equal(secondListeners.active(), 0);

      first.abort(new Error('later abort'));
      assert.equal(composed.signal.reason, reason);
      composed.cleanup();
      composed.cleanup();
    } finally {
      firstListeners.restore();
      secondListeners.restore();
    }
  });

  it('aborts retry delays and cleans up both the timer and abort listener', async () => {
    const controller = new AbortController();
    const listeners = trackAbortListeners(controller.signal);
    const timer = createTrackedScheduler();
    const reason = new Error('refresh cancelled');

    try {
      const pending = abortableDelay(30_000, controller.signal, timer.scheduler);
      assert.equal(timer.active(), 1);
      assert.equal(listeners.active(), 1);

      controller.abort(reason);
      await assert.rejects(
        pending,
        (error) =>
          error instanceof AbortError &&
          error.reason === reason &&
          error.cause === reason,
      );

      assert.equal(timer.active(), 0);
      assert.equal(timer.cleared(), 1);
      assert.equal(listeners.active(), 0);
    } finally {
      listeners.restore();
    }

    const completed = new AbortController();
    const completionListeners = trackAbortListeners(completed.signal);
    let clearedOnCompletion = 0;
    const handle = {};
    try {
      await abortableDelay(0, completed.signal, {
        set: (callback) => {
          callback();
          return handle;
        },
        clear: (clearedHandle) => {
          assert.equal(clearedHandle, handle);
          clearedOnCompletion++;
        },
      });
      assert.equal(clearedOnCompletion, 1);
      assert.equal(completionListeners.active(), 0);
    } finally {
      completionListeners.restore();
    }
  });

  it('bounds concurrency and returns successful map results in input order', async () => {
    const diagnostics = createCooperativeDiagnostics();
    let active = 0;
    let maxActive = 0;
    const completionOrder: number[] = [];

    const results = await mapWithConcurrency(
      [0, 1, 2, 3, 4],
      2,
      async (value) => {
        active++;
        maxActive = Math.max(maxActive, active);
        await yieldTurns(5 - value);
        completionOrder.push(value);
        active--;
        return `result-${value}`;
      },
      { diagnostics },
    );

    assert.equal(maxActive, 2);
    assert.notDeepEqual(completionOrder, [0, 1, 2, 3, 4]);
    assert.deepEqual(results, [
      'result-0',
      'result-1',
      'result-2',
      'result-3',
      'result-4',
    ]);
    assert.deepEqual(diagnostics, {
      total: 5,
      started: 5,
      completed: 5,
      failed: 0,
      aborted: 0,
      drained: 5,
      skipped: 0,
    });
  });

  it('aborts a slow sibling, suppresses queued work, drains, and throws the primary error', async () => {
    const primary = new Error('primary failure');
    const diagnostics = createCooperativeDiagnostics();
    const started: number[] = [];
    let slowSiblingFinished = false;

    const pending = mapWithConcurrency(
      [0, 1, 2, 3],
      2,
      async (value, _index, signal) => {
        started.push(value);
        if (value === 1) throw primary;
        try {
          await abortableDelay(30_000, signal);
          return value;
        } finally {
          slowSiblingFinished = true;
        }
      },
      { diagnostics },
    );

    await assertRejectsWithIdentity(pending, primary);
    assert.equal(slowSiblingFinished, true);
    assert.deepEqual(started, [0, 1]);
    assert.deepEqual(diagnostics, {
      total: 4,
      started: 2,
      completed: 0,
      failed: 1,
      aborted: 1,
      drained: 2,
      skipped: 2,
    });
  });

  it('handles external abort by stopping dequeue and draining every started task', async () => {
    const external = new AbortController();
    const externalListeners = trackAbortListeners(external.signal);
    const diagnostics = createCooperativeDiagnostics();
    const reason = new Error('lease expired');
    let finalized = 0;

    try {
      const pending = mapWithConcurrency(
        [0, 1, 2],
        2,
        async (_value, _index, signal) => {
          try {
            await abortableDelay(30_000, signal);
            return 'unreachable';
          } finally {
            finalized++;
          }
        },
        { signal: external.signal, diagnostics },
      );

      await waitFor(() => diagnostics.started === 2);
      external.abort(reason);

      await assert.rejects(
        pending,
        (error) =>
          error instanceof AbortError &&
          error.reason === reason &&
          error.cause === reason,
      );
      assert.equal(finalized, 2);
      assert.equal(externalListeners.active(), 0);
      assert.deepEqual(diagnostics, {
        total: 3,
        started: 2,
        completed: 0,
        failed: 0,
        aborted: 2,
        drained: 2,
        skipped: 1,
      });
    } finally {
      externalListeners.restore();
    }
  });

  it('does not invoke dequeued workers when cancellation wins before deferred invocation', async () => {
    const external = new AbortController();
    const diagnostics = createCooperativeDiagnostics();
    const reason = new Error('cancel before invocation');
    let invocations = 0;

    const pending = mapWithConcurrency(
      [0, 1, 2],
      2,
      async () => {
        invocations++;
        return 'unreachable';
      },
      { signal: external.signal, diagnostics },
    );
    external.abort(reason);

    await assert.rejects(
      pending,
      (error) =>
        error instanceof AbortError &&
        error.reason === reason &&
        error.cause === reason,
    );
    assert.equal(invocations, 0);
    assert.deepEqual(diagnostics, {
      total: 3,
      started: 2,
      completed: 0,
      failed: 0,
      aborted: 2,
      drained: 2,
      skipped: 1,
    });
  });

  it('preserves heterogeneous group result ordering on success', async () => {
    const diagnostics = createCooperativeDiagnostics();
    const results = await runCooperativeGroup([
      Promise.resolve(1),
      async () => {
        await yieldTurns(2);
        return 'two' as const;
      },
      async () => true,
    ] as const, { diagnostics });

    assert.deepEqual(results, [1, 'two', true]);
    assert.deepEqual(diagnostics, {
      total: 3,
      started: 3,
      completed: 3,
      failed: 0,
      aborted: 0,
      drained: 3,
      skipped: 0,
    });
  });

  it('drains accepted promises when the group is already aborted', async () => {
    const external = new AbortController();
    const abortReason = new Error('already cancelled');
    const rejectedReason = new Error('accepted promise failed');
    const diagnostics = createCooperativeDiagnostics();
    const unhandled: unknown[] = [];
    let factoryInvocations = 0;
    const onUnhandled = (error: unknown): void => {
      unhandled.push(error);
    };
    process.on('unhandledRejection', onUnhandled);
    external.abort(abortReason);

    try {
      const pending = runCooperativeGroup([
        Promise.reject(rejectedReason),
        async () => {
          factoryInvocations++;
          return 'unreachable';
        },
      ] as const, { signal: external.signal, diagnostics });

      await assert.rejects(
        pending,
        (error) =>
          error instanceof AbortError &&
          error.reason === abortReason &&
          error.cause === abortReason,
      );
      await yieldTurns(2);

      assert.equal(factoryInvocations, 0);
      assert.deepEqual(unhandled, []);
      assert.deepEqual(diagnostics, {
        total: 2,
        started: 1,
        completed: 0,
        failed: 1,
        aborted: 0,
        drained: 1,
        skipped: 1,
      });
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  it('does not invoke grouped factories when cancellation wins after queuing', async () => {
    const external = new AbortController();
    const reason = new Error('cancel queued group');
    const diagnostics = createCooperativeDiagnostics();
    let invocations = 0;

    const pending = runCooperativeGroup([
      async () => {
        invocations++;
        return 1;
      },
      async () => {
        invocations++;
        return 2;
      },
    ] as const, { signal: external.signal, diagnostics });
    external.abort(reason);

    await assert.rejects(
      pending,
      (error) =>
        error instanceof AbortError &&
        error.reason === reason &&
        error.cause === reason,
    );
    assert.equal(invocations, 0);
    assert.deepEqual(diagnostics, {
      total: 2,
      started: 2,
      completed: 0,
      failed: 0,
      aborted: 2,
      drained: 2,
      skipped: 0,
    });
  });

  it('aborts and drains grouped siblings without producing unhandled rejections', async () => {
    const primary = new Error('group primary failure');
    const secondary = new Error('late secondary failure');
    const diagnostics = createCooperativeDiagnostics();
    const unhandled: unknown[] = [];
    let slowSiblingFinished = false;
    const onUnhandled = (error: unknown): void => {
      unhandled.push(error);
    };
    process.on('unhandledRejection', onUnhandled);

    try {
      const pending = runCooperativeGroup([
        async (signal) => {
          try {
            await abortableDelay(30_000, signal);
          } finally {
            slowSiblingFinished = true;
          }
        },
        async () => {
          throw primary;
        },
        async () => {
          await yieldTurns(2);
          throw secondary;
        },
      ] as const, { diagnostics });

      await assertRejectsWithIdentity(pending, primary);
      await yieldTurns(2);

      assert.equal(slowSiblingFinished, true);
      assert.deepEqual(unhandled, []);
      assert.deepEqual(diagnostics, {
        total: 3,
        started: 3,
        completed: 0,
        failed: 2,
        aborted: 1,
        drained: 3,
        skipped: 0,
      });
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });
});

async function assertRejectsWithIdentity(
  promise: Promise<unknown>,
  expected: unknown,
): Promise<void> {
  try {
    await promise;
    assert.fail('Expected promise to reject');
  } catch (error) {
    assert.equal(error, expected);
  }
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await yieldTurns(1);
  }
  throw new Error('Timed out waiting for condition');
}

async function yieldTurns(count: number): Promise<void> {
  for (let turn = 0; turn < count; turn++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

function createTrackedScheduler(): {
  scheduler: DelayScheduler;
  active(): number;
  cleared(): number;
} {
  const handles = new Set<object>();
  let cleared = 0;
  return {
    scheduler: {
      set: () => {
        const handle = {};
        handles.add(handle);
        return handle;
      },
      clear: (handle) => {
        if (handles.delete(handle as object)) cleared++;
      },
    },
    active: () => handles.size,
    cleared: () => cleared,
  };
}

function trackAbortListeners(signal: AbortSignal): {
  active(): number;
  restore(): void;
} {
  const target = signal as any;
  const originalAdd = target.addEventListener;
  const originalRemove = target.removeEventListener;
  const listeners = new Set<unknown>();

  target.addEventListener = function (
    type: string,
    listener: unknown,
    options?: unknown,
  ): void {
    if (type === 'abort') listeners.add(listener);
    originalAdd.call(this, type, listener, options);
  };
  target.removeEventListener = function (
    type: string,
    listener: unknown,
    options?: unknown,
  ): void {
    if (type === 'abort') listeners.delete(listener);
    originalRemove.call(this, type, listener, options);
  };

  return {
    active: () => listeners.size,
    restore: () => {
      target.addEventListener = originalAdd;
      target.removeEventListener = originalRemove;
    },
  };
}
