import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import express from 'express';

const tempDir = mkdtempSync(join(tmpdir(), 'radar-api-routes-'));
process.env.DB_PATH = join(tempDir, 'radar.db');
process.env.REFRESH_MINUTES = '0';

let server: Server;
let baseUrl: string;
let dbModule: typeof import('./db.ts');

async function getJson(path: string): Promise<{ status: number; body: any }> {
  const response = await fetch(`${baseUrl}${path}`);
  return {
    status: response.status,
    body: await response.json(),
  };
}

before(async () => {
  dbModule = await import(`./db.ts?api-routes-${Date.now()}`);
  dbModule.upsertRelease({
    tag: 'v-test',
    name: 'v-test',
    published_at: '2026-06-01T00:00:00Z',
    html_url: 'https://example.test/releases/v-test',
    prerelease: false,
    body: '',
  });

  const { api } = await import(`../routes/api.ts?api-routes-${Date.now()}`);
  const app = express();
  app.use('/api', api);
  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', () => resolve());
  });
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  dbModule.db.close();
  rmSync(tempDir, { recursive: true, force: true });
});

describe('audit API routes', () => {
  it('rejects invalid issue evidence filters at the route boundary', async () => {
    const cases = [
      ['/api/releases/v-test/review/issues?tier=not-a-tier', 'invalid tier'],
      ['/api/releases/v-test/review/issues?impact=not-impact', 'invalid impact'],
      ['/api/releases/v-test/review/issues?state=invalid', 'invalid state'],
      ['/api/releases/v-test/review/issues?sentiment=bad', 'invalid sentiment'],
      ['/api/releases/v-test/review/issues?severity=bad', 'invalid severity'],
      ['/api/releases/v-test/review/issues?functionality=bad', 'invalid functionality'],
      ['/api/releases/v-test/review/issues?scope=bad', 'invalid scope'],
      ['/api/releases/v-test/review/issues?affectedUsers=bad', 'invalid affectedUsers'],
      ['/api/releases/v-test/review/issues?fieldConfirmed=maybe', 'invalid fieldConfirmed'],
      ['/api/releases/v-test/review/issues?minWeight=abc', 'invalid minWeight'],
      ['/api/releases/v-test/review/issues?maxWeight=abc', 'invalid maxWeight'],
      ['/api/releases/v-test/review/issues?minWeight=10&maxWeight=1', 'invalid weight range'],
      ['/api/releases/v-test/review/issues?sort=bad', 'invalid sort'],
      ['/api/releases/v-test/review/issues?direction=sideways', 'invalid direction'],
      ['/api/releases/v-test/review/issues?summaryOnly=wat', 'invalid summaryOnly'],
    ] as const;

    for (const [path, error] of cases) {
      const response = await getJson(path);
      assert.equal(response.status, 400, path);
      assert.equal(response.body.error, error, path);
    }
  });

  it('rejects invalid closure proof filters at the route boundary', async () => {
    const invalidStatus = await getJson('/api/releases/v-test/review/closure-proofs?status=bad');
    assert.equal(invalidStatus.status, 400);
    assert.equal(invalidStatus.body.error, 'invalid status');
    assert.ok(invalidStatus.body.allowedStatuses.includes('fixed_in_release'));

    const invalidDisposition = await getJson('/api/releases/v-test/review/closure-proofs?riskDisposition=bad');
    assert.equal(invalidDisposition.status, 400);
    assert.equal(invalidDisposition.body.error, 'invalid riskDisposition');
    assert.ok(invalidDisposition.body.allowedRiskDispositions.includes('credited_release_fix'));
  });

  it('rejects invalid reachability filters at the route boundary', async () => {
    const invalidStatus = await getJson('/api/releases/v-test/review/reachability?status=bad');
    assert.equal(invalidStatus.status, 400);
    assert.equal(invalidStatus.body.error, 'invalid status');

    const invalidPr = await getJson('/api/releases/v-test/review/reachability?pr=not-a-pr');
    assert.equal(invalidPr.status, 400);
    assert.equal(invalidPr.body.error, 'invalid pr filter');
  });
});
