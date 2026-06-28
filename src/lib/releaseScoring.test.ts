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

  it('excludes still-open reports from regression opened load', () => {
    const rows = [
      { number: 1, state: 'open' },
      { number: 2, state: 'closed' },
      { number: 3, state: 'closed-unverified' },
    ];
    assert.deepEqual(
      __releaseScoringTest.releaseRegressionOpenedRows(rows).map((row) => row.number),
      [2, 3],
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
    const labelTimeline = run.scored[0].gateEvidence.labelTimeline as any;
    const evidence = run.scored[0].debtEvidence as any;

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
    assert.equal(typeof closure.metrics?.unresolvedForReleaseCount, 'number');
    assert.equal(typeof closure.metrics?.unresolvedClosureRiskWeight, 'number');
    assert.equal(typeof closure.metrics?.cappedPenalty, 'number');
    assert.equal(typeof closure.metrics?.neutralOrNonActionableCount, 'number');
    assert.ok(Object.keys(closure.buckets ?? {}).length > 0);
    assert.ok(Object.keys(closure.riskBuckets ?? {}).length > 0);
    assert.ok((closure.issueRefs?.length ?? 0) >= 3);
    const closureExamples = ((run.scored[0].gateEvidence as any).fixProvenance?.closureProof?.examples ?? [])
      .filter((item: any) => item.status !== 'fixed_in_release');
    assert.deepEqual(
      closure.issueRefs?.map((item) => item.number),
      closureExamples.slice(0, closure.issueRefs?.length ?? 0).map((item: any) => item.number),
    );
    assert.ok(closureExamples.every((item: any, index: number) =>
      index === 0 || Number(closureExamples[index - 1].riskWeight ?? 0) >= Number(item.riskWeight ?? 0)));

    const carryover = explanation.limitDetails.find((detail) => detail.code === 'source_carryover_risk');
    assert.ok(carryover);
    assert.ok((carryover.issueRefs?.length ?? 0) > 0);
    assert.ok(carryover.issueRefs?.every((issue) => Number.isInteger(issue.number) && issue.title));
    const sampleEvidenceIssue = [
      ...(evidence.verifiedDebt ?? []),
      ...(evidence.carryoverDebt ?? []),
      ...(evidence.staleDebt ?? []),
      ...(evidence.openedFeltSerious ?? []),
    ].map((item: any) => item.issue ?? item).find((issue: any) => issue?.classification);
    assert.ok(sampleEvidenceIssue?.rawClassification);
    assert.ok(sampleEvidenceIssue?.classification);
    assert.equal(typeof sampleEvidenceIssue.classificationDiff, 'object');
    assert.equal(typeof labelTimeline.issueCount, 'number');
    assert.equal(typeof labelTimeline.historicalCurrentLabelFallbackAllowed, 'boolean');
  });

  it('explains incomplete classification coverage with issue references', () => {
    const explanation = __releaseScoringTest.buildScoreExplanation({
      conf: {
        status: 'eligible',
        components: { coverage: -0.8 },
        evidenceCoverage: 0.5,
      },
      input: {
        rawIssueCount: 2,
        classifiedIssueCount: 1,
      },
      debtEvidence: {
        unclassifiedIssues: [{
          number: 1002,
          title: 'unclassified blocker',
          url: 'https://example.test/issues/1002',
          state: 'open',
        }],
      },
      gateEvidence: {
        fixProvenance: {},
        artifactVerification: {},
      },
    } as any, false);
    const coverage = explanation.limitDetails.find((detail: any) =>
      detail.code === 'incomplete_classification_coverage',
    );
    assert.ok(coverage);
    assert.match(coverage.text, /1 attributed issues lack current classification evidence/);
    assert.equal(coverage.metrics?.rawIssueCount, 2);
    assert.equal(coverage.metrics?.classifiedIssueCount, 1);
    assert.equal(coverage.metrics?.missingClassificationCount, 1);
    assert.deepEqual(coverage.issueRefs?.map((issue: any) => issue.number), [1002]);
  });
});
