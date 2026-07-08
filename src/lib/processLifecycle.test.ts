import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

type ChildMessage = {
  type: string;
  [key: string]: unknown;
};

type ChildExit = {
  code: number | null;
  signal: NodeJS.Signals | null;
};

type RunningChild = ReturnType<typeof startChild>;

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const require = createRequire(import.meta.url);
const tsxCjs = require.resolve('tsx/cjs');
const indexPath = join(root, 'src', 'index.ts');
const dbModulePath = join(root, 'src', 'lib', 'db.ts');
const tempDirs = new Set<string>();

after(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe('radar process lifecycle', { concurrency: false }, () => {
  it('serves liveness, stops cleanly, and restarts the shell on the same port', async () => {
    const dir = createTempDir('radar-process-restart-');
    const firstDbPath = join(dir, 'radar-first.db');
    const secondDbPath = join(dir, 'radar-second.db');
    let first: RunningChild | null = null;
    let second: RunningChild | null = null;

    try {
      const port = await availableLoopbackPort();
      first = startRadarChild({ dbPath: firstDbPath, port });
      const firstListening = await first.waitForMessage(
        (message) => message.type === 'listening',
      );
      assert.equal(requiredPort(firstListening), port);
      const baseUrl = `http://127.0.0.1:${port}`;

      const liveResponse = await fetchWithTimeout(`${baseUrl}/api/live`);
      assert.equal(liveResponse.status, 200);
      assert.deepEqual(await liveResponse.json(), {
        ok: true,
        status: 'live',
        repo: 'openclaw/openclaw',
      });

      assert.equal(first.child.kill('SIGTERM'), true);
      assertGracefulExit(await first.waitForExit(), first);
      assert.match(first.stdout(), /\[shutdown\] SIGTERM received/);

      second = startRadarChild({ dbPath: secondDbPath, port });
      const secondListening = await second.waitForMessage(
        (message) => message.type === 'listening',
      );
      assert.equal(requiredPort(secondListening), port);

      const shellUrl = `${baseUrl}/#/openclaw`;
      const firstShellResponse = await fetchWithTimeout(shellUrl);
      assert.equal(firstShellResponse.status, 200);
      assert.match(firstShellResponse.headers.get('content-type') ?? '', /^text\/html/);
      const firstShell = await firstShellResponse.text();
      assert.match(firstShell, /<title>Release Radar/);
      assert.match(firstShell, /location\.hash === '#\/openclaw'/);
      assert.match(firstShell, /id="viewPackage"/);

      const reloadedShellResponse = await fetchWithTimeout(shellUrl);
      assert.equal(reloadedShellResponse.status, 200);
      assert.equal(await reloadedShellResponse.text(), firstShell);

      assert.equal(second.child.kill('SIGTERM'), true);
      assertGracefulExit(await second.waitForExit(), second);
      assert.match(second.stdout(), /\[shutdown\] SIGTERM received/);
    } finally {
      await stopChild(first);
      await stopChild(second);
    }
  });

  it('waits for an active refresh before releasing the lease and database on SIGTERM', async () => {
    const dir = createTempDir('radar-process-sigterm-');
    const port = await availableLoopbackPort();
    const child = startShutdownHarness(join(dir, 'radar.db'), port);

    try {
      const listening = await child.waitForMessage(
        (message) => message.type === 'listening',
      );
      assert.equal(requiredPort(listening), port);
      const response = await fetchWithTimeout(`http://127.0.0.1:${port}/api/live`);
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { ok: true, status: 'live' });

      assert.equal(child.child.kill('SIGTERM'), true);
      await child.waitForMessage((message) => message.type === 'server-closed');
      await child.waitForMessage((message) => message.type === 'refresh-wait-started');

      const portProbe = await listenOnPort(port);
      await closeServer(portProbe);

      assert.equal(child.messages.some((message) => message.type === 'lease-released'), false);
      assert.equal(child.messages.some((message) => message.type === 'database-closed'), false);
      assert.equal(child.messages.some((message) => message.type === 'exit-requested'), false);

      child.child.send?.({ type: 'resolve-refresh' });
      assertGracefulExit(await child.waitForExit(), child);

      const eventTypes = child.messages.map((message) => message.type);
      assertOrdered(eventTypes, [
        'refresh-cancel-requested',
        'server-close-started',
        'server-closed',
        'refresh-wait-started',
        'refresh-resolved',
        'lease-released',
        'force-exit-cancelled',
        'database-closed',
        'exit-requested',
      ]);
      assert.ok(child.messages.some((message) =>
        message.type === 'log' && message.message === '[shutdown] SIGTERM received'));
    } finally {
      await stopChild(child);
    }
  });
});

function startRadarChild(args: { dbPath: string; port: number }) {
  const source = `
    const { startRadarServer } = require(${JSON.stringify(indexPath)});
    const { server } = startRadarServer();
    server.once('error', (error) => {
      process.send?.({ type: 'server-error', message: error.message });
    });
    server.once('listening', () => {
      const address = server.address();
      process.send?.({
        type: 'listening',
        port: address && typeof address === 'object' ? address.port : null,
      });
    });
  `;
  return startChild(source, processEnv(args.dbPath, args.port));
}

function startShutdownHarness(dbPath: string, port: number) {
  const source = `
    const http = require('node:http');
    const { createGracefulShutdown } = require(${JSON.stringify(indexPath)});
    const { db } = require(${JSON.stringify(dbModulePath)});
    const send = (type, details = {}) => process.send?.({ type, ...details });
    let resolveRefresh;
    const activeRefresh = new Promise((resolve) => {
      resolveRefresh = resolve;
    });
    const server = http.createServer((request, response) => {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ ok: true, status: 'live' }));
    });
    const shutdown = createGracefulShutdown({
      clearRefreshTimer() {
        send('refresh-timer-cleared');
      },
      cancelRefresh(reason) {
        send('refresh-cancel-requested', { reason: reason.message });
        return true;
      },
      waitForRefresh() {
        send('refresh-wait-started');
        return activeRefresh;
      },
      releaseRefreshResources() {
        send('lease-released');
        return true;
      },
      closeServer(callback) {
        send('server-close-started');
        server.close((error) => {
          send('server-closed');
          callback(error);
        });
        server.closeIdleConnections?.();
      },
      closeDatabase() {
        db.close();
        send('database-closed');
      },
      exit(code) {
        send('exit-requested', { code });
        setImmediate(() => process.exit(code));
      },
      scheduleForceExit(callback, delayMs) {
        const handle = setTimeout(callback, delayMs);
        handle.unref();
        return handle;
      },
      cancelForceExit(handle) {
        clearTimeout(handle);
        send('force-exit-cancelled');
      },
      log(message) {
        send('log', { message });
      },
      logError(message) {
        send('error', { message });
      },
    });
    process.once('SIGTERM', () => shutdown('SIGTERM'));
    process.on('message', (message) => {
      if (message?.type !== 'resolve-refresh') return;
      send('refresh-resolved');
      resolveRefresh();
    });
    server.listen(${JSON.stringify(port)}, '127.0.0.1', () => {
      const address = server.address();
      send('listening', {
        port: address && typeof address === 'object' ? address.port : null,
      });
    });
  `;
  return startChild(source, processEnv(dbPath, port));
}

function startChild(source: string, env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, ['--require', tsxCjs, '--eval', source], {
    cwd: root,
    env,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  const messages: ChildMessage[] = [];
  let stdout = '';
  let stderr = '';

  child.stdout?.setEncoding('utf8');
  child.stdout?.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (chunk) => {
    stderr += chunk;
  });
  child.on('message', (message) => {
    if (isChildMessage(message)) messages.push(message);
  });

  return {
    child,
    messages,
    stdout: () => stdout,
    stderr: () => stderr,
    async waitForMessage(
      predicate: (message: ChildMessage) => boolean,
      timeoutMs = 30_000,
    ): Promise<ChildMessage> {
      const existing = messages.find(predicate);
      if (existing) return existing;
      return await new Promise<ChildMessage>((resolve, reject) => {
        const timeout = setTimeout(() => {
          cleanup();
          reject(new Error(`Timed out waiting for child message.\n${childDiagnostics({
            child,
            messages,
            stdout,
            stderr,
          })}`));
        }, timeoutMs);
        const onMessage = (message: unknown) => {
          if (!isChildMessage(message) || !predicate(message)) return;
          cleanup();
          resolve(message);
        };
        const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
          cleanup();
          reject(new Error(
            `Child exited before the expected message (code=${code}, signal=${signal}).\n` +
            childDiagnostics({ child, messages, stdout, stderr }),
          ));
        };
        const onError = (error: Error) => {
          cleanup();
          reject(error);
        };
        const cleanup = () => {
          clearTimeout(timeout);
          child.off('message', onMessage);
          child.off('exit', onExit);
          child.off('error', onError);
        };
        child.on('message', onMessage);
        child.once('exit', onExit);
        child.once('error', onError);
      });
    },
    async waitForExit(timeoutMs = 30_000): Promise<ChildExit> {
      if (child.exitCode != null || child.signalCode != null) {
        return { code: child.exitCode, signal: child.signalCode };
      }
      return await new Promise<ChildExit>((resolve, reject) => {
        const timeout = setTimeout(() => {
          cleanup();
          reject(new Error(`Timed out waiting for child exit.\n${childDiagnostics({
            child,
            messages,
            stdout,
            stderr,
          })}`));
        }, timeoutMs);
        const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
          cleanup();
          resolve({ code, signal });
        };
        const onError = (error: Error) => {
          cleanup();
          reject(error);
        };
        const cleanup = () => {
          clearTimeout(timeout);
          child.off('exit', onExit);
          child.off('error', onError);
        };
        child.once('exit', onExit);
        child.once('error', onError);
      });
    },
  };
}

function processEnv(dbPath: string, port: number): NodeJS.ProcessEnv {
  const dotenvPath = process.env.DOTENV_CONFIG_PATH;
  assert.ok(
    dotenvPath,
    'process lifecycle tests require the inherited protected DOTENV_CONFIG_PATH',
  );
  return {
    ...process.env,
    PORT: String(port),
    DB_PATH: dbPath,
    DOTENV_CONFIG_PATH: dotenvPath,
    RADAR_DB_READ_ONLY: '0',
    REFRESH_ON_STARTUP: 'false',
    REFRESH_MINUTES: '0',
    COMPARISON_API_ENABLED: 'false',
    GITHUB_TOKEN: '',
    GITHUB_PERSONAL_ACCESS_TOKEN: '',
    OPENAI_API_KEY: '',
    OC_OPENAI_API_KEY: '',
  };
}

function createTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.add(dir);
  return dir;
}

function requiredPort(message: ChildMessage): number {
  const port = message.port;
  if (typeof port !== 'number' || port <= 0) {
    throw new Error(`Child reported an invalid port: ${String(port)}`);
  }
  return port;
}

async function fetchWithTimeout(url: string): Promise<Response> {
  return await fetch(url, {
    cache: 'no-store',
    signal: AbortSignal.timeout(5_000),
  });
}

function assertGracefulExit(exit: ChildExit, child: RunningChild): void {
  assert.deepEqual(
    exit,
    { code: 0, signal: null },
    childDiagnostics({
      child: child.child,
      messages: child.messages,
      stdout: child.stdout(),
      stderr: child.stderr(),
    }),
  );
}

function assertOrdered(actual: string[], expected: string[]): void {
  let cursor = -1;
  for (const event of expected) {
    const next = actual.indexOf(event, cursor + 1);
    assert.notEqual(next, -1, `Missing ordered event ${event}: ${actual.join(', ')}`);
    cursor = next;
  }
}

function isChildMessage(message: unknown): message is ChildMessage {
  return Boolean(message) &&
    typeof message === 'object' &&
    typeof (message as { type?: unknown }).type === 'string';
}

function childDiagnostics(args: {
  child: ReturnType<typeof spawn>;
  messages: ChildMessage[];
  stdout: string;
  stderr: string;
}): string {
  return [
    `pid=${args.child.pid ?? 'unknown'}`,
    `messages=${JSON.stringify(args.messages)}`,
    `stdout=${args.stdout}`,
    `stderr=${args.stderr}`,
  ].join('\n');
}

async function listenOnPort(port: number): Promise<Server> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve());
  });
  return server;
}

async function availableLoopbackPort(): Promise<number> {
  const server = await listenOnPort(0);
  try {
    const address = server.address();
    if (!address || typeof address === 'string' || address.port <= 0) {
      throw new Error(`Port probe returned an invalid address: ${String(address)}`);
    }
    return address.port;
  } finally {
    await closeServer(server);
  }
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function stopChild(child: RunningChild | null): Promise<void> {
  if (!child || child.child.exitCode != null || child.child.signalCode != null) return;
  child.child.kill('SIGKILL');
  await child.waitForExit();
}
