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
});
