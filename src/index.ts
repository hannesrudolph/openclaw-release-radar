import express from 'express';
import { join } from 'node:path';
import {
  config,
  serializeEffectiveConfigAttestation,
} from './config';
import {
  type StartupAuthorizationAttestation,
  verifyProductionStartupAuthorization,
} from './lib/startupAuthorization';

interface ShutdownDependencies {
  clearRefreshTimer: () => void;
  cancelRefresh: (reason: Error) => boolean;
  waitForRefresh: () => Promise<void>;
  releaseRefreshResources: () => boolean;
  closeServer: (callback: (error?: Error) => void) => void;
  closeDatabase: () => void;
  exit: (code: number) => void;
  scheduleForceExit?: (callback: () => void, delayMs: number) => unknown;
  cancelForceExit?: (handle: unknown) => void;
  log?: (message: string) => void;
  logError?: (message: string) => void;
}

export function createGracefulShutdown(dependencies: ShutdownDependencies) {
  let shuttingDown = false;
  let finished = false;
  let forceExitHandle: unknown = null;
  const scheduleForceExit = dependencies.scheduleForceExit ?? ((callback, delayMs) => {
    const handle = setTimeout(callback, delayMs);
    handle.unref();
    return handle;
  });
  const cancelForceExit = dependencies.cancelForceExit ?? ((handle) => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  });
  const log = dependencies.log ?? console.log;
  const logError = dependencies.logError ?? console.error;

  const finish = (code: number): void => {
    if (finished) return;
    finished = true;
    if (forceExitHandle != null) cancelForceExit(forceExitHandle);
    try {
      dependencies.closeDatabase();
    } catch (error) {
      logError(`[shutdown] database close failed: ${(error as Error).message}`);
      code = 1;
    }
    dependencies.exit(code);
  };

  return (signal: 'SIGINT' | 'SIGTERM'): void => {
    if (shuttingDown) {
      finished = true;
      dependencies.exit(1);
      return;
    }
    shuttingDown = true;
    log(`[shutdown] ${signal} received`);
    dependencies.clearRefreshTimer();
    try {
      dependencies.cancelRefresh(
        new Error(`Refresh cancelled because ${signal} initiated shutdown`),
      );
    } catch (error) {
      logError(`[shutdown] active refresh cancellation failed: ${(error as Error).message}`);
    }
    forceExitHandle = scheduleForceExit(() => {
      if (finished) return;
      finished = true;
      dependencies.exit(1);
    }, 10_000);
    dependencies.closeServer((error) => {
      let exitCode = 0;
      const closeErrorCode = error && 'code' in error
        ? String(error.code)
        : null;
      if (error && closeErrorCode !== 'ERR_SERVER_NOT_RUNNING') {
        logError(`[shutdown] server close failed: ${error.message}`);
        exitCode = 1;
      }
      void dependencies.waitForRefresh()
        .then(() => {
          try {
            dependencies.releaseRefreshResources();
          } catch (releaseError) {
            logError(
              `[shutdown] refresh lease release failed: ${(releaseError as Error).message}`,
            );
            finish(1);
            return;
          }
          finish(exitCode);
        })
        .catch((refreshError) => {
          logError(
            `[shutdown] active refresh wait failed: ${(refreshError as Error).message}`,
          );
          finish(1);
        });
    });
  };
}

export function requireProductionStartupAuthorization():
  StartupAuthorizationAttestation | null {
  if (config.runtime.mode !== 'production') return null;
  return verifyProductionStartupAuthorization({
    releaseRoot: config.runtime.applicationRootPath,
    releaseRevision: config.runtime.releaseRevision!,
    databasePath: config.db.path,
  });
}

export function startRadarServer() {
  const startupAuthorization = requireProductionStartupAuthorization();
  if (startupAuthorization) {
    console.log(
      `[startup-authorization] accepted=${JSON.stringify(startupAuthorization)}`,
    );
  }
  console.log(`[config] effective=${serializeEffectiveConfigAttestation()}`);
  const { api } = require('./routes/api') as typeof import('./routes/api');
  const { db } = require('./lib/db') as typeof import('./lib/db');
  const {
    cancelActiveRefresh,
    refresh,
    releaseActiveRefreshLease,
    waitForActiveRefresh,
  } = require('./lib/refresh') as typeof import('./lib/refresh');

  const app = express();
  app.use(express.json());
  app.use('/api', api);
  app.use(express.static(join(__dirname, '..', 'public')));

  if (startupAuthorization) {
    const revalidated = requireProductionStartupAuthorization();
    if (
      !revalidated ||
      revalidated.authorizationContentHash !==
        startupAuthorization.authorizationContentHash ||
      revalidated.databasePhysicalSha256 !==
        startupAuthorization.databasePhysicalSha256
    ) {
      throw new Error(
        '[startup-authorization] authorization changed while the database opened',
      );
    }
  }
  const server = app.listen(config.server.port, '127.0.0.1', () => {
    console.log(`[radar] listening on http://127.0.0.1:${config.server.port}`);
    console.log(`[radar] watching ${config.github.owner}/${config.github.repo}`);
  });

  let refreshTimer: ReturnType<typeof setInterval> | null = null;
  let databaseClosed = false;

  // Periodic refresh is deliberately optional while the scoring model is being
  // calibrated. A slow full backfill must not overlap with another refresh.
  if (config.refresh.intervalMinutes > 0) {
    const intervalMs = config.refresh.intervalMinutes * 60_000;
    refreshTimer = setInterval(() => {
      refresh()
        .then((result) =>
          console.log(
            `[refresh] ${result.classifiedCount} classified, ` +
            `${result.releaseCount} releases, ${result.durationMs}ms`,
          ),
        )
        .catch((error) => console.error('[refresh] failed:', (error as Error).message));
    }, intervalMs);
    console.log(`[refresh] every ${config.refresh.intervalMinutes} min`);
  } else {
    console.log('[refresh] automatic refresh disabled');
  }

  if (config.refresh.onStartup) {
    refresh()
      .then((result) =>
        console.log(
          `[startup] refreshed: ${result.classifiedCount} classified, ` +
          `${result.releaseCount} releases, ${result.durationMs}ms`,
        ),
      )
      .catch((error) => console.error('[startup] refresh failed:', (error as Error).message));
  } else {
    console.log('[startup] refresh disabled');
  }

  const shutdown = createGracefulShutdown({
    clearRefreshTimer() {
      if (refreshTimer) clearInterval(refreshTimer);
      refreshTimer = null;
    },
    cancelRefresh: cancelActiveRefresh,
    waitForRefresh: waitForActiveRefresh,
    releaseRefreshResources: releaseActiveRefreshLease,
    closeServer(callback) {
      server.close(callback);
      server.closeIdleConnections?.();
    },
    closeDatabase() {
      if (databaseClosed) return;
      databaseClosed = true;
      db.close();
    },
    exit: (code) => process.exit(code),
  });
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));

  return { app, server, shutdown };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--print-effective-config') {
    console.log(serializeEffectiveConfigAttestation());
  } else if (
    args.length === 1 &&
    args[0] === '--verify-startup-authorization'
  ) {
    const authorization = requireProductionStartupAuthorization();
    console.log(JSON.stringify({
      schemaVersion: 1,
      required: config.runtime.mode === 'production',
      authorization,
    }));
  } else if (args.length > 0) {
    console.error(`Unknown option: ${args.join(' ')}`);
    process.exitCode = 2;
  } else {
    startRadarServer();
  }
}
