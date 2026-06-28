import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  ARTIFACT_VERIFICATION_SCHEMA_VERSION,
  buildReleaseScoreRun,
  ISSUE_EVIDENCE_SCHEMA_VERSION,
  LABEL_TIMELINE_SCHEMA_VERSION,
  RELEASE_CHECKS_SCHEMA_VERSION,
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
    assert.equal(evidence.schemaVersion, ISSUE_EVIDENCE_SCHEMA_VERSION);
    assert.equal(explanation.limits.length, explanation.limitDetails.length);
    assert.equal(explanation.positives.length, explanation.positiveDetails.length);
    assert.ok(explanation.limitDetails.every((detail, idx) => detail.text === explanation.limits[idx]));
    assert.ok(explanation.positiveDetails.every((detail, idx) => detail.text === explanation.positives[idx]));
    assert.ok(explanation.limitDetails.every((detail) => SCORE_EXPLANATION_LIMIT_CODES.includes(detail.code as any)));
    assert.ok(explanation.positiveDetails.every((detail) => SCORE_EXPLANATION_POSITIVE_CODES.includes(detail.code as any)));

    const opened = explanation.limitDetails.find((detail) => detail.code === 'field_visible_reports_opened');
    assert.ok(opened);
    assert.equal(typeof opened.metrics?.openedCount, 'number');
    assert.equal(typeof opened.metrics?.stillOpenCount, 'number');
    assert.equal(typeof opened.metrics?.closedCount, 'number');
    assert.equal(
      Number(opened.metrics?.openedCount ?? 0),
      Number(opened.metrics?.stillOpenCount ?? 0) + Number(opened.metrics?.closedCount ?? 0),
    );
    assert.ok((opened.issueRefs?.length ?? 0) >= Math.min(3, Number(opened.metrics?.stillOpenCount ?? opened.metrics?.openedCount ?? 0)));

    const closure = explanation.limitDetails.find((detail) => detail.code === 'closed_issues_not_counted_as_release_fixes');
    assert.ok(closure);
    assert.equal(typeof closure.metrics?.notCountedClosedCount, 'number');
    assert.equal(typeof closure.metrics?.unresolvedForReleaseCount, 'number');
    assert.equal(typeof closure.metrics?.unresolvedClosureRiskWeight, 'number');
    assert.equal(typeof closure.metrics?.cappedPenalty, 'number');
    if ((closure.metrics?.unresolvedClosureRiskWeight ?? 0) >= 80) {
      assert.equal(typeof closure.metrics?.scoreCeiling, 'number');
    }
    assert.equal(typeof closure.metrics?.neutralOrNonActionableCount, 'number');
    assert.equal(typeof closure.metrics?.neutralHighImpactCount, 'number');
    assert.equal(typeof closure.metrics?.neutralBugShapedCount, 'number');
    assert.ok(Object.keys(closure.buckets ?? {}).length > 0);
    assert.ok(Object.keys(closure.riskBuckets ?? {}).length > 0);
    assert.ok((closure.issueRefs?.length ?? 0) >= 3);
    const closureProof = (run.scored[0].gateEvidence as any).fixProvenance?.closureProof ?? {};
    const releaseChecks = (run.scored[0].gateEvidence as any).releaseChecks;
    const artifactVerification = (run.scored[0].gateEvidence as any).artifactVerification;
    if (releaseChecks) assert.equal(releaseChecks.schemaVersion, RELEASE_CHECKS_SCHEMA_VERSION);
    assert.equal(artifactVerification.schemaVersion, ARTIFACT_VERIFICATION_SCHEMA_VERSION);
    const nonFixedClosureStatuses = Object.entries(closureProof.byStatus ?? {})
      .filter(([status, count]) => status !== 'fixed_in_release' && Number(count ?? 0) > 0)
      .map(([status]) => status);
    assert.ok(closureProof.examplesByStatus);
    for (const status of nonFixedClosureStatuses) {
      assert.ok(
        (closureProof.examplesByStatus[status]?.length ?? 0) > 0,
        `expected representative example for closure status ${status}`,
      );
      assert.ok(closureProof.examplesByStatus[status].every((example: any) => example.status === status));
    }
    if ((closure.metrics?.neutralHighImpactCount ?? 0) > 0 || (closure.metrics?.neutralBugShapedCount ?? 0) > 0) {
      assert.ok((closureProof.neutralAuditExamples?.length ?? 0) > 0);
      assert.ok(closure.issueRefs?.some((issue) =>
        closureProof.neutralAuditExamples.some((example: any) => example.number === issue.number)));
    }
    const closureExamples = (closureProof.examples ?? [])
      .filter((item: any) => item.status !== 'fixed_in_release');
    assert.deepEqual(
      closure.issueRefs?.slice(0, 3).map((item) => item.number),
      closureExamples.slice(0, Math.min(3, closure.issueRefs?.length ?? 0)).map((item: any) => item.number),
    );
    assert.ok(closureExamples.every((item: any, index: number) =>
      index === 0 || Number(closureExamples[index - 1].riskWeight ?? 0) >= Number(item.riskWeight ?? 0)));

    const carryover = explanation.limitDetails.find((detail) => detail.code === 'source_carryover_risk');
    assert.ok(carryover);
    assert.ok((carryover.metrics?.count ?? 0) > 0);
    assert.equal(carryover.metrics?.storedExampleCount, (run.scored[0].debtEvidence as any).carryoverDebt.length);
    assert.ok((carryover.metrics?.storedExampleWeight ?? 0) <= (carryover.metrics?.rawWeight ?? 0));
    assert.equal(typeof carryover.metrics?.byInstallImpactClass, 'object');
    assert.ok(Object.keys(carryover.metrics?.byInstallImpactClass ?? {}).length > 0);
    assert.ok((carryover.issueRefs?.length ?? 0) >= 3);
    assert.ok(carryover.issueRefs?.every((issue) => Number.isInteger(issue.number) && issue.title));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.installImpactClass === 'string'));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.installImpactMultiplier === 'number'));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.weight === 'number'));

    const stale = explanation.limitDetails.find((detail) => detail.code === 'stale_low_confidence_evidence');
    assert.ok(stale);
    assert.ok((stale.metrics?.count ?? 0) > 0);
    assert.equal(stale.metrics?.storedExampleCount, (run.scored[0].debtEvidence as any).staleDebt.length);
    assert.ok((stale.metrics?.storedExampleWeight ?? 0) <= (stale.metrics?.rawWeight ?? 0));
    assert.equal(typeof stale.metrics?.byInstallImpactClass, 'object');
    assert.ok(Object.keys(stale.metrics?.byInstallImpactClass ?? {}).length > 0);
    assert.ok((stale.issueRefs?.length ?? 0) > 0);
    assert.ok(stale.issueRefs?.every((issue) => Number.isInteger(issue.number) && issue.title));
    assert.ok(stale.issueRefs?.some((issue) => typeof issue.weight === 'number'));
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
    assert.equal(labelTimeline.schemaVersion, LABEL_TIMELINE_SCHEMA_VERSION);
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
