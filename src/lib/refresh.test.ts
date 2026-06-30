import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { __refreshTest } from './refresh.ts';

describe('refresh backfill completion', () => {
  it('does not mark issue backfill complete when pagination stops at the page cap', () => {
    for (const fullIssueBackfill of [false, true]) {
      for (const crossedOldestEver of [false, true]) {
        assert.equal(__refreshTest.shouldMarkBackfillComplete({
          fullIssueBackfill,
          crossedOldestEver,
          issuePaginationStopReason: 'page_cap',
        }), false);
      }
    }
  });

  it('does not mark issue backfill complete when page evidence fetching fails', () => {
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      fullIssueBackfill: false,
      crossedOldestEver: true,
      issuePaginationStopReason: 'evidence_failure',
    }), false);
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      fullIssueBackfill: true,
      crossedOldestEver: true,
      issuePaginationStopReason: 'evidence_failure',
    }), false);
  });

  it('marks full issue backfill complete only after exhausting the issue connection', () => {
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      fullIssueBackfill: true,
      crossedOldestEver: false,
      issuePaginationStopReason: 'exhausted',
    }), true);
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      fullIssueBackfill: true,
      crossedOldestEver: true,
      issuePaginationStopReason: 'early_stop',
    }), false);
  });

  it('marks normal backfill complete after crossing the monitored history boundary or exhausting pagination', () => {
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      fullIssueBackfill: false,
      crossedOldestEver: true,
      issuePaginationStopReason: 'early_stop',
    }), true);
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      fullIssueBackfill: false,
      crossedOldestEver: false,
      issuePaginationStopReason: 'exhausted',
    }), true);
    assert.equal(__refreshTest.shouldMarkBackfillComplete({
      fullIssueBackfill: false,
      crossedOldestEver: false,
      issuePaginationStopReason: 'early_stop',
    }), false);
  });

  it('drops stale prompt-sweep classifications only after exhausting pagination', () => {
    assert.equal(__refreshTest.shouldDropStaleClassificationsAfterPromptSweep('exhausted'), true);
    assert.equal(__refreshTest.shouldDropStaleClassificationsAfterPromptSweep('page_cap'), false);
    assert.equal(__refreshTest.shouldDropStaleClassificationsAfterPromptSweep('early_stop'), false);
  });

  it('refuses to score after page-capped issue pagination', () => {
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('page_cap'), true);
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('evidence_failure'), true);
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('exhausted'), false);
    assert.equal(__refreshTest.shouldRefuseScoreAfterIssuePagination('early_stop'), false);
  });

  it('refuses to score after any monitored-release evidence refresh failure', () => {
    assert.equal(__refreshTest.shouldRefuseScoreAfterEvidenceFailures([]), false);
    assert.equal(__refreshTest.shouldRefuseScoreAfterEvidenceFailures(['closure proof failed']), true);
  });

  it('formats score-blocking evidence refresh failures with source and scope', () => {
    assert.equal(
      __refreshTest.evidenceRefreshFailureMessage('release-checks', 'v2026.6.10', new Error('GraphQL missing contexts')),
      '[release-checks] v2026.6.10 failed: GraphQL missing contexts',
    );
    assert.equal(
      __refreshTest.evidenceRefreshFailureMessage('advisories', null, new Error('GraphQL unavailable')),
      '[advisories] failed: GraphQL unavailable',
    );
  });

  it('refuses to score after any issue classification failure', () => {
    assert.equal(__refreshTest.shouldRefuseScoreAfterClassificationFailures([]), false);
    assert.equal(__refreshTest.shouldRefuseScoreAfterClassificationFailures(['[classify] issue #1 failed: timeout']), true);
  });

  it('summarizes long failure lists before storing crawl metadata', () => {
    const failures = Array.from({ length: 27 }, (_, index) => `failure ${index + 1}`);
    const summarized = __refreshTest.summarizeFailures(failures);

    assert.equal(summarized.length, 26);
    assert.equal(summarized[0], 'failure 1');
    assert.equal(summarized[24], 'failure 25');
    assert.equal(summarized[25], '[summary] 2 additional failure(s) omitted');
  });
});
