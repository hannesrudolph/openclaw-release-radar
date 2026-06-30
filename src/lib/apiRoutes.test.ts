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
  seedIssue({
    number: 101,
    state: 'open',
    title: 'release local broad regression still open',
    createdAt: '2026-06-01T12:00:00Z',
    updatedAt: '2026-06-02T12:00:00Z',
    labels: ['P1', 'bug', 'regression'],
    classification: {
      sentiment: 'negative',
      severity: 'high',
      functionality: 'core',
      scope: 'broad',
      affectedUsers: 'many',
    },
  });
  seedIssue({
    number: 102,
    state: 'open',
    title: 'provider issue needs info',
    createdAt: '2026-06-01T13:00:00Z',
    updatedAt: '2026-06-02T13:00:00Z',
    labels: ['bug', 'stale'],
    classification: {
      sentiment: 'negative',
      severity: 'medium',
      functionality: 'provider',
      scope: 'moderate',
      affectedUsers: 'some',
    },
  });
  seedIssue({
    number: 103,
    state: 'closed',
    title: 'fixed release bug',
    createdAt: '2026-06-01T14:00:00Z',
    updatedAt: '2026-06-03T00:00:00Z',
    closedAt: '2026-06-03T00:00:00Z',
    labels: ['bug'],
  });
  seedClosure(103, '2026-06-03T00:00:00Z');
  seedClosureProof(103, 'fixed_in_release');
  seedIssue({
    number: 104,
    state: 'closed',
    title: 'fixed after release bug',
    createdAt: '2026-06-01T15:00:00Z',
    updatedAt: '2026-06-04T00:00:00Z',
    closedAt: '2026-06-04T00:00:00Z',
    labels: ['bug'],
  });
  seedClosure(104, '2026-06-04T00:00:00Z');
  seedClosureProof(104, 'fixed_after_release');
  seedReachability({
    prNumber: 123,
    status: 'reachable',
  });
  seedReachability({
    prNumber: 124,
    status: 'not_reachable',
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
  it('exposes compact audit links on release summary rows', async () => {
    const expected = {
      review: '/api/releases/v-test/review',
      issues: '/api/releases/v-test/review/issues',
      closureProofs: '/api/releases/v-test/review/closure-proofs',
      reachability: '/api/releases/v-test/review/reachability',
    };

    const releases = await getJson('/api/releases');
    assert.equal(releases.status, 200);
    assert.deepEqual(releases.body.find((row: any) => row.tag === 'v-test')?.auditLinks, expected);

    const publicPayload = await getJson('/api/public');
    assert.equal(publicPayload.status, 200);
    assert.deepEqual(publicPayload.body.releases.find((row: any) => row.tag === 'v-test')?.auditLinks, expected);
  });

  it('exposes parent review source provenance and raw row links', async () => {
    const response = await getJson('/api/releases/v-test/review');

    assert.equal(response.status, 200);
    assert.equal(response.body.local.sourceProvenance.sourceMode, 'current_db');
    assert.equal(response.body.local.sourceProvenance.scoreTable, 'release_score_audits');
    assert.equal(response.body.local.sourceProvenance.scoredAt, response.body.local.scoredAt);
    assert.equal(response.body.local.sourceProvenance.dataFreshnessScoredAt, response.body.local.dataFreshness.scoredAt);
    assert.equal(
      response.body.local.sourceProvenance.scoreTimestampAligned,
      response.body.local.scoredAt === response.body.local.dataFreshness.scoredAt,
    );
    assert.deepEqual(response.body.local.sourceProvenance.sources, response.body.local.dataFreshness.sources);
    assert.deepEqual(response.body.local.sourceProvenance.rawRows, {
      issues: '/api/releases/v-test/review/issues',
      closureProofs: '/api/releases/v-test/review/closure-proofs',
      reachability: '/api/releases/v-test/review/reachability',
    });
  });

  it('exposes audit provenance on score history rows', async () => {
    const response = await getJson('/api/releases/history');

    assert.equal(response.status, 200);
    const row = response.body.find((item: any) => item.tag === 'v-test');
    assert.equal(row.schemaVersion, 2);
    assert.equal(row.tag, 'v-test');
    assert.equal(row.publishedAt, '2026-06-01T00:00:00Z');
    assert.equal(row.scoreAudit, null);
    assert.equal(row.dataFreshness.tag, 'v-test');
    assert.deepEqual(row.auditLinks, {
      review: '/api/releases/v-test/review',
      issues: '/api/releases/v-test/review/issues',
      closureProofs: '/api/releases/v-test/review/closure-proofs',
      reachability: '/api/releases/v-test/review/reachability',
    });
  });

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

  it('applies issue evidence filters, sorting, summary-only mode, and limit clamps', async () => {
    const clamped = await getJson('/api/releases/v-test/review/issues?limit=999&cursor=-5');
    assert.equal(clamped.status, 200);
    assert.equal(clamped.body.limit, 250);
    assert.equal(clamped.body.cursor, 0);
    assert.ok(clamped.body.total >= 4);

    const summaryOnly = await getJson('/api/releases/v-test/review/issues?tier=verifiedDebt&summaryOnly=true');
    assert.equal(summaryOnly.status, 200);
    assert.equal(summaryOnly.body.filters.tier, 'verifiedDebt');
    assert.deepEqual(summaryOnly.body.filters.tiers, ['verifiedDebt']);
    assert.equal(summaryOnly.body.filters.summaryOnly, true);
    assert.equal(summaryOnly.body.limit, 0);
    assert.equal(summaryOnly.body.cursor, 0);
    assert.deepEqual(summaryOnly.body.rows, []);
    assert.equal(summaryOnly.body.total, 1);

    const openUnconfirmedAlias = await getJson('/api/releases/v-test/review/issues?tier=openUnconfirmedRisk&summaryOnly=true');
    assert.equal(openUnconfirmedAlias.status, 200);
    assert.equal(openUnconfirmedAlias.body.filters.tier, 'carryoverDebt');
    assert.deepEqual(openUnconfirmedAlias.body.filters.tiers, ['carryoverDebt']);

    const weakStaleAlias = await getJson('/api/releases/v-test/review/issues?tier=weakOrStaleEvidence&summaryOnly=true');
    assert.equal(weakStaleAlias.status, 200);
    assert.equal(weakStaleAlias.body.filters.tier, 'staleDebt');
    assert.deepEqual(weakStaleAlias.body.filters.tiers, ['staleDebt']);

    const fieldConfirmed = await getJson('/api/releases/v-test/review/issues?tier=verifiedDebt&fieldConfirmed=true');
    assert.equal(fieldConfirmed.status, 200);
    assert.equal(fieldConfirmed.body.filters.fieldConfirmed, true);
    assert.ok(fieldConfirmed.body.rows.every((row: any) => row.tier === 'verifiedDebt' && row.fieldConfirmed === true));

    const updatedDesc = await getJson('/api/releases/v-test/review/issues?limit=10&sort=updated&direction=desc');
    assert.equal(updatedDesc.status, 200);
    assert.equal(updatedDesc.body.filters.sort, 'updated');
    assert.equal(updatedDesc.body.filters.direction, 'desc');
    assert.ok(isNonIncreasingTimestamps(updatedDesc.body.rows.map((row: any) => row.issue.updatedAt)));

    const stateOpen = await getJson('/api/releases/v-test/review/issues?state=open');
    assert.equal(stateOpen.status, 200);
    assert.equal(stateOpen.body.filters.state, 'open');
    assert.deepEqual(stateOpen.body.filters.states, ['open']);
    assert.ok(stateOpen.body.rows.every((row: any) => row.issue.state === 'open'));
  });

  it('applies closure proof filter intersections and limit clamps', async () => {
    const filtered = await getJson('/api/releases/v-test/review/closure-proofs?status=fixed_after_release&riskDisposition=known_not_in_release');
    assert.equal(filtered.status, 200);
    assert.equal(filtered.body.filters.status, 'fixed_after_release');
    assert.equal(filtered.body.filters.riskDisposition, 'known_not_in_release');
    assert.equal(filtered.body.total, 1);
    assert.equal(filtered.body.rows[0].issueNumber, 104);
    assert.equal(filtered.body.rows[0].status, 'fixed_after_release');
    assert.equal(filtered.body.rows[0].riskDisposition, 'known_not_in_release');
    assert.equal(filtered.body.rows[0].riskDispositionLabel, 'known not in this tag');
    assert.equal(typeof filtered.body.rows[0].riskWeightLabel, 'string');

    const clamped = await getJson('/api/releases/v-test/review/closure-proofs?limit=999&cursor=-2');
    assert.equal(clamped.status, 200);
    assert.equal(clamped.body.limit, 100);
    assert.equal(clamped.body.cursor, 0);
  });

  it('applies reachability PR filter variants and limit clamps', async () => {
    const byNumber = await getJson('/api/releases/v-test/review/reachability?pr=123');
    assert.equal(byNumber.status, 200);
    assert.deepEqual(byNumber.body.filters.pr, { repositoryNameWithOwner: null, number: 123 });
    assert.equal(byNumber.body.total, 1);
    assert.equal(byNumber.body.rows[0].number, 123);

    const byRepo = await getJson('/api/releases/v-test/review/reachability?pr=OpenClaw/OpenClaw%23123');
    assert.equal(byRepo.status, 200);
    assert.deepEqual(byRepo.body.filters.pr, { repositoryNameWithOwner: 'OpenClaw/OpenClaw', number: 123 });
    assert.equal(byRepo.body.total, 1);
    assert.equal(byRepo.body.rows[0].repositoryNameWithOwner, 'openclaw/openclaw');

    const clamped = await getJson('/api/releases/v-test/review/reachability?limit=999&cursor=-2');
    assert.equal(clamped.status, 200);
    assert.equal(clamped.body.limit, 250);
    assert.equal(clamped.body.cursor, 0);
  });
});

function isNonIncreasingTimestamps(values: string[]): boolean {
  for (let index = 1; index < values.length; index++) {
    if (Date.parse(values[index - 1]) < Date.parse(values[index])) return false;
  }
  return true;
}

function seedIssue(input: {
  number: number;
  state: 'open' | 'closed';
  title: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string | null;
  labels?: string[];
  classification?: {
    sentiment?: string;
    severity?: string;
    functionality?: string;
    scope?: string;
    affectedUsers?: string;
  };
}) {
  dbModule.upsertIssue({
    number: input.number,
    state: input.state,
    title: input.title,
    author: 'reporter',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${input.number}`,
    created_at: input.createdAt,
    updated_at: input.updatedAt,
    closed_at: input.closedAt ?? null,
    comments: 1,
    unique_human_commenters: 1,
    maintainer_commenters: 0,
    contributor_commenters: 0,
    commenter_scan_truncated: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: JSON.stringify(input.labels ?? ['bug']),
    is_bot: 0,
  });
  const c = input.classification ?? {};
  dbModule.upsertClassification(input.number, {
    sentiment: c.sentiment ?? 'negative',
    severity: c.severity ?? 'high',
    functionality: c.functionality ?? 'core',
    scope: c.scope ?? 'broad',
    affectedUsers: c.affectedUsers ?? 'many',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.95,
    rationale: 'route test classification',
  }, input.updatedAt, 1);
}

function seedClosure(issueNumber: number, closedAt: string) {
  dbModule.upsertIssueClosureEvent({
    issue_number: issueNumber,
    event_id: `closed-${issueNumber}`,
    closed_at: closedAt,
    actor_login: 'maintainer',
    state_reason: 'COMPLETED',
    closer_type: null,
    closer_number: null,
    closer_oid: null,
    raw_json: '{}',
  });
}

function seedClosureProof(issueNumber: number, status: string) {
  dbModule.upsertIssueClosureProof({
    release_tag: 'v-test',
    issue_number: issueNumber,
    status,
    summary: status,
    evidence_json: JSON.stringify({ status }),
  });
}

function seedReachability({
  prNumber,
  status,
}: {
  prNumber: number;
  status: 'reachable' | 'not_reachable' | 'unknown';
}) {
  dbModule.upsertReleasePrReachability({
    tag: 'v-test',
    pr_repository_owner: 'openclaw',
    pr_repository_name: 'openclaw',
    pr_repository_name_with_owner: 'openclaw/openclaw',
    pr_number: prNumber,
    tag_commit_oid: 'tag-commit',
    merge_commit_oid: `merge-${prNumber}`,
    base_ref_name: 'main',
    status,
    evidence_json: '{}',
  });
}
