import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { assessDataFreshnessHealth, assessIssueCrawlHealth } from '../../scripts/lib/doctor-health.mjs';

describe('doctor data freshness health', () => {
  const latest = { tag: 'v1', scoredAt: '2026-06-30T01:00:00.000Z' };

  it('warns when issue evidence is stale at scoring time or now', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-27T01:00:00.000Z',
      issueUpdatedAgeHoursAtScore: 72,
      issueUpdatedAgeHoursNow: 73,
      sourceFetchedAtMax: '2026-06-30T00:59:00.000Z',
      sources: [],
    }, latest, { maxIssueLagHours: 48 });

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /old at scoring time/.test(warning)));
    assert.ok(result.warnings.some((warning) => /old now/.test(warning)));
  });

  it('fails when source evidence changed after the latest score', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-30T00:59:00.000Z',
      issueUpdatedAgeHoursAtScore: 0.02,
      issueUpdatedAgeHoursNow: 0.03,
      sourceFetchedAtMax: '2026-06-30T01:05:00.000Z',
      sources: [
        { source: 'issues', maxAt: '2026-06-30T00:59:00.000Z' },
        { source: 'issue_pr_links', maxAt: '2026-06-30T01:05:00.000Z' },
      ],
    }, latest);

    assert.ok(result.failures.some((failure) => /source evidence changed after latest score/.test(failure)));
    assert.ok(result.failures.some((failure) => /issue_pr_links/.test(failure)));
  });

  it('fails when populated freshness sources have no timestamps', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-30T00:59:00.000Z',
      issueUpdatedAgeHoursAtScore: 0.02,
      issueUpdatedAgeHoursNow: 0.03,
      sourceFetchedAtMax: '2026-06-30T00:59:00.000Z',
      sources: [
        { source: 'issue_fetches', count: 10, maxAt: null },
        { source: 'release_rows', count: 3, maxAt: null },
      ],
    }, latest);

    assert.ok(result.failures.some((failure) => /issue_fetches freshness/.test(failure)));
    assert.ok(result.failures.some((failure) => /release_rows freshness/.test(failure)));
  });

  it('fails when issue rows include updates after the latest score', () => {
    const result = assessDataFreshnessHealth({
      scoredAt: latest.scoredAt,
      issueUpdatedAtMax: '2026-06-30T01:05:00.000Z',
      issueUpdatedAgeHoursAtScore: -0.08,
      issueUpdatedAgeHoursNow: 0,
      sourceFetchedAtMax: '2026-06-30T00:59:00.000Z',
      sources: [],
    }, latest);

    assert.ok(result.failures.some((failure) => /issue data includes updates after latest score/.test(failure)));
  });
});

describe('doctor issue crawl health', () => {
  const latest = { tag: 'v1', scoredAt: '2026-06-30T01:00:00.000Z' };

  it('does not warn when issue crawl metadata is absent before any score exists', () => {
    assert.deepEqual(assessIssueCrawlHealth(null, null), { warnings: [], failures: [] });
  });

  it('warns when a scored release has no issue crawl metadata', () => {
    const result = assessIssueCrawlHealth(null, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /no issue crawl metadata/.test(warning)));
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

  it('warns when failed classifications happened after the latest score', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: ['[classify] issue #1 failed: timeout'],
      scorePersisted: false,
    }, latest);

    assert.equal(result.failures.length, 0);
    assert.ok(result.warnings.some((warning) => /classification failure/.test(warning)));
    assert.ok(result.warnings.some((warning) => /current score predates/.test(warning)));
  });

  it('fails when classification failures persisted or could have produced the latest score', () => {
    const persisted = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: ['[classify] issue #10 failed: rate limited'],
      scorePersisted: true,
    }, latest);
    assert.ok(persisted.failures.some((failure) => /classification failure/.test(failure)));

    const possibleLatest = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T00:30:00.000Z',
      finishedAt: '2026-06-30T00:59:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: ['[classify] issue #11 failed: bad response'],
      scorePersisted: false,
    }, latest);
    assert.ok(possibleLatest.failures.some((failure) => /classification failure/.test(failure)));
  });

  it('fails when classification failure metadata is malformed', () => {
    const result = assessIssueCrawlHealth({
      schemaVersion: 1,
      startedAt: '2026-06-30T02:00:00.000Z',
      finishedAt: '2026-06-30T02:05:00.000Z',
      stopReason: 'exhausted',
      classificationFailures: 'classification failed',
      scorePersisted: false,
    }, latest);

    assert.ok(result.failures.some((failure) => /classificationFailures must be an array/.test(failure)));
  });
});
