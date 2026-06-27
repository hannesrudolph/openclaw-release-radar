import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { __releaseScoringTest } from './releaseScoring.ts';

describe('release score explanations', () => {
  it('truncates issue titles at useful boundaries', () => {
    const title = 'Normal tool text outputs can degrade to "(see attached image)" placeholders in agent transcript rendering';
    assert.equal(
      __releaseScoringTest.truncateAtWordBoundary(title, 88),
      'Normal tool text outputs can degrade to "(see attached image)" placeholders in...',
    );
  });

  it('removes repetitive bug prefixes before explanation examples', () => {
    assert.equal(
      __releaseScoringTest.shortIssueTitle({ title: '[Bug]: web_search providers stopped working after upgrade' }),
      'web_search providers stopped working after upgrade',
    );
  });
});
