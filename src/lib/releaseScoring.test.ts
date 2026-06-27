import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  buildReleaseScoreRun,
  SCORE_EXPLANATION_LIMIT_CODES,
  SCORE_EXPLANATION_POSITIVE_CODES,
  SCORE_EXPLANATION_SCHEMA_VERSION,
  __releaseScoringTest,
} from './releaseScoring.ts';

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

  it('includes machine-readable detail entries beside prose', () => {
    const run = buildReleaseScoreRun({
      releaseLimit: 1,
      allFetchedTags: ['v2026.6.10'],
      stableTagsNewestFirst: ['v2026.6.10'],
      nowForRelease: (release) => Date.parse(release.scored_at ?? '2026-06-27T22:00:00Z'),
    });
    const explanation = run.scored[0].explanation;

    assert.equal(explanation.schemaVersion, SCORE_EXPLANATION_SCHEMA_VERSION);
    assert.equal(explanation.limits.length, explanation.limitDetails.length);
    assert.equal(explanation.positives.length, explanation.positiveDetails.length);
    assert.ok(explanation.limitDetails.every((detail, idx) => detail.text === explanation.limits[idx]));
    assert.ok(explanation.positiveDetails.every((detail, idx) => detail.text === explanation.positives[idx]));
    assert.ok(explanation.limitDetails.every((detail) => SCORE_EXPLANATION_LIMIT_CODES.includes(detail.code as any)));
    assert.ok(explanation.positiveDetails.every((detail) => SCORE_EXPLANATION_POSITIVE_CODES.includes(detail.code as any)));

    const closure = explanation.limitDetails.find((detail) => detail.code === 'closed_issues_not_counted_as_release_fixes');
    assert.ok(closure);
    assert.equal(typeof closure.metrics?.notCountedClosedCount, 'number');
    assert.ok(Object.keys(closure.buckets ?? {}).length > 0);

    const carryover = explanation.limitDetails.find((detail) => detail.code === 'source_carryover_risk');
    assert.ok(carryover);
    assert.ok((carryover.issueRefs?.length ?? 0) > 0);
    assert.ok(carryover.issueRefs?.every((issue) => Number.isInteger(issue.number) && issue.title));
  });
});
