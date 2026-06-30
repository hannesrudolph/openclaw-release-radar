import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { assessIssueCrawlHealth } from '../../scripts/lib/doctor-health.mjs';

describe('doctor issue crawl health', () => {
  const latest = { tag: 'v1', scoredAt: '2026-06-30T01:00:00.000Z' };

  it('does not warn when issue crawl metadata is absent', () => {
    assert.deepEqual(assessIssueCrawlHealth(null, latest), { warnings: [], failures: [] });
  });

  it('warns when a newer issue crawl hit the page cap without persisting a score', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'page_cap',
      pagesFetched: 500,
      backfillCompleteAfterRun: false,
      scorePersisted: false,
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /hit page cap/.test(warning)));
    assert.ok(result.warnings.some((warning) => /did not mark issue backfill complete/.test(warning)));
  });

  it('fails when a page-capped crawl persisted or could have produced the latest score', () => {
    const persisted = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'page_cap',
      pagesFetched: 500,
      backfillCompleteAfterRun: false,
      scorePersisted: true,
    }, latest);
    assert.ok(persisted.failures.some((failure) => /hit page cap/.test(failure)));

    const possibleLatest = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'page_cap',
      pagesFetched: 500,
      backfillCompleteAfterRun: false,
      scorePersisted: false,
    }, latest);
    assert.ok(possibleLatest.failures.some((failure) => /hit page cap/.test(failure)));
  });

  it('warns when a failed evidence refresh happened after the latest score', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: ['[closure-proof] v1 failed: timeout'],
      scorePersisted: false,
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /evidence refresh failure/.test(warning)));
    assert.ok(result.warnings.some((warning) => /current score predates/.test(warning)));
  });

  it('fails when evidence refresh failures persisted or could have produced the latest score', () => {
    const persisted = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: ['[reachability] v1 failed: git object missing'],
      scorePersisted: true,
    }, latest);
    assert.ok(persisted.failures.some((failure) => /evidence refresh failure/.test(failure)));

    const possibleLatest = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: ['[closure-evidence] v1 failed: API error'],
      scorePersisted: false,
    }, latest);
    assert.ok(possibleLatest.failures.some((failure) => /evidence refresh failure/.test(failure)));
  });

  it('fails when evidence refresh failures metadata is malformed', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      evidenceRefreshFailures: 'closure proof failed',
      scorePersisted: false,
    }, latest);

    assert.ok(result.failures.some((failure) => /must be an array/.test(failure)));
  });
});
