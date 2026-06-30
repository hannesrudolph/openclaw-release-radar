import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  ARTIFACT_VERIFICATION_SCHEMA_VERSION,
  buildReleaseScoreRun,
  GATE_EVIDENCE_SCHEMA_VERSION,
  ISSUE_EVIDENCE_SCHEMA_VERSION,
  LABEL_TIMELINE_SCHEMA_VERSION,
  RELEASE_CHECKS_SCHEMA_VERSION,
  SCORE_EXPLANATION_DETAIL_LABELS,
  SCORE_COMPONENTS_SCHEMA_VERSION,
  SCORE_EXPLANATION_LIMIT_CODES,
  SCORE_EXPLANATION_POSITIVE_CODES,
  SCORE_EXPLANATION_SCHEMA_VERSION,
  SCORE_INPUT_SCHEMA_VERSION,
  scoreTagWindow,
  __releaseScoringTest,
} from './releaseScoring.ts';

describe('release score explanations', () => {
  it('builds stable scoring tag windows from mixed release rows', () => {
    assert.deepEqual(scoreTagWindow([
      { tag: 'v3', prerelease: 0 },
      { tag: 'v3-beta.1', prerelease: 1 },
      { tag: 'v2', prerelease: false },
      { tag: 'v1', prerelease: null },
    ]), {
      allFetchedTags: ['v3', 'v3-beta.1', 'v2', 'v1'],
      stableTagsNewestFirst: ['v3', 'v2', 'v1'],
    });
  });

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

    assert.equal(run.scored[0].input.schemaVersion, SCORE_INPUT_SCHEMA_VERSION);
    assert.equal((run.scored[0].conf as any).components != null, true);
    assert.equal(explanation.schemaVersion, SCORE_EXPLANATION_SCHEMA_VERSION);
    assert.equal(SCORE_COMPONENTS_SCHEMA_VERSION, 1);
    assert.equal(evidence.schemaVersion, ISSUE_EVIDENCE_SCHEMA_VERSION);
    assert.equal(run.scored[0].gateEvidence.schemaVersion, GATE_EVIDENCE_SCHEMA_VERSION);
    assert.equal(explanation.limits.length, explanation.limitDetails.length);
    assert.equal(explanation.positives.length, explanation.positiveDetails.length);
    assert.ok(explanation.limitDetails.every((detail, idx) => detail.text === explanation.limits[idx]));
    assert.ok(explanation.positiveDetails.every((detail, idx) => detail.text === explanation.positives[idx]));
    assert.ok(explanation.limitDetails.every((detail) => SCORE_EXPLANATION_LIMIT_CODES.includes(detail.code as any)));
    assert.ok(explanation.positiveDetails.every((detail) => SCORE_EXPLANATION_POSITIVE_CODES.includes(detail.code as any)));
    const detailLabels = SCORE_EXPLANATION_DETAIL_LABELS as Record<string, string>;
    assert.ok(explanation.limitDetails.every((detail) => detail.label === detailLabels[detail.code]));
    assert.ok(explanation.positiveDetails.every((detail) => detail.label === detailLabels[detail.code]));
    assert.equal(explanation.scoreLedger?.schemaVersion, 1);
    assert.equal(explanation.scoreLedger?.finalScore, run.scored[0].conf.score);
    assert.equal(explanation.scoreLedger?.status, run.scored[0].conf.status);
    assert.ok((explanation.scoreLedger?.rows.length ?? 0) >= 10);
    const ledgerSubtotal = Math.round((explanation.scoreLedger?.rows ?? []).reduce((sum, row) => sum + row.points, 0) * 1000) / 1000;
    assert.equal(explanation.scoreLedger?.subtotalBeforeCaps, ledgerSubtotal);
    assert.equal(explanation.scoreLedger?.rows[0]?.key, 'base');
    assert.ok(explanation.scoreLedger?.rows.some((row) => row.key === 'closureRisk' && row.metric != null));

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
    const unresolvedClosureCount = Number(closure.metrics?.unresolvedForReleaseCount ?? 0);
    assert.ok(unresolvedClosureCount > 0);
    assert.equal(run.scored[0].input.unresolvedClosureIssueCount, unresolvedClosureCount);
    assert.match(run.scored[0].conf.reason, new RegExp(`${unresolvedClosureCount} unresolved closed-release issues`));
    assert.ok((closure.issueRefs?.length ?? 0) >= 3);
    const closureProof = (run.scored[0].gateEvidence as any).fixProvenance?.closureProof ?? {};
    const releaseChecks = (run.scored[0].gateEvidence as any).releaseChecks;
    const artifactVerification = (run.scored[0].gateEvidence as any).artifactVerification;
    if (releaseChecks) {
      assert.equal(releaseChecks.schemaVersion, RELEASE_CHECKS_SCHEMA_VERSION);
      assert.equal(releaseChecks.contextCount, releaseChecks.total);
      assert.equal(releaseChecks.shownContextCount, releaseChecks.contexts.length);
      assert.equal(releaseChecks.contextsTruncated, releaseChecks.shownContextCount < releaseChecks.contextCount);
    }
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
    assert.ok(closure.issueRefs?.every((issue) => issue.proof?.status && issue.proof.statusLabel));
    assert.ok(closure.issueRefs?.some((issue) => issue.proof?.riskDispositionLabel));
    const unresolvedRiskDispositions = Object.entries(closure.riskBuckets ?? {})
      .filter(([disposition, count]) =>
        ['open_canonical_risk', 'known_not_in_release', 'unsupported_closure_claim', 'missing_evidence']
          .includes(disposition) && Number(count ?? 0) > 0)
      .map(([disposition]) => disposition);
    for (const disposition of unresolvedRiskDispositions.slice(0, 5)) {
      assert.ok(
        closure.issueRefs?.some((issue) => issue.proof?.riskDisposition === disposition),
        `expected closure explanation issueRefs to include ${disposition}`,
      );
    }
    assert.ok(closure.issueRefs?.some((issue) =>
      issue.proof?.canonicalIssue?.number ||
      (issue.proof?.openPrs?.length ?? 0) > 0 ||
      (issue.proof?.reachablePrs?.length ?? 0) > 0 ||
      (issue.proof?.notReachablePrs?.length ?? 0) > 0));
    assert.ok(closureExamples.every((item: any, index: number) =>
      index === 0 || Number(closureExamples[index - 1].riskWeight ?? 0) >= Number(item.riskWeight ?? 0)));

    const carryover = explanation.limitDetails.find((detail) => detail.code === 'source_carryover_risk');
    assert.ok(carryover);
    assert.equal(carryover.label, 'Open unconfirmed issue risk');
    assert.ok((carryover.metrics?.count ?? 0) > 0);
    assert.equal(run.scored[0].input.carryoverDebtIssueCount, carryover.metrics?.count);
    assert.match(run.scored[0].conf.reason, new RegExp(`${carryover.metrics?.count} open unconfirmed issues`));
    assert.equal(typeof carryover.metrics?.maxPenalty, 'number');
    assert.equal(typeof carryover.metrics?.capApplied, 'boolean');
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
    assert.equal(run.scored[0].input.staleDebtIssueCount, stale.metrics?.count);
    assert.equal(typeof stale.metrics?.maxPenalty, 'number');
    assert.equal(typeof stale.metrics?.capApplied, 'boolean');
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

  it('explains verified field-blocker debt with issue references', () => {
    const explanation = __releaseScoringTest.buildScoreExplanation({
      conf: {
        status: 'eligible',
        components: { verifiedDebt: -1.2 },
        evidenceCoverage: 1,
      },
      input: {
        rawIssueCount: 1,
        classifiedIssueCount: 1,
        verifiedDebtWeight: 30,
      },
      debtEvidence: {
        debtSummary: {
          verified: {
            count: 1,
            weight: 30,
            storedWeight: 30,
            byInstallImpactClass: { state_data: 1 },
          },
        },
        verifiedDebt: [{
          tier: 'verified',
          weight: 30,
          installImpactClass: 'state_data',
          installImpactMultiplier: 1,
          issue: {
            number: 1003,
            title: 'release-local data loss after upgrade',
            url: 'https://example.test/issues/1003',
            state: 'open',
          },
        }],
      },
      gateEvidence: {
        fixProvenance: {},
        artifactVerification: {},
      },
    } as any, false);
    const verified = explanation.limitDetails.find((detail: any) =>
      detail.code === 'verified_field_blocker_debt',
    );
    assert.ok(verified);
    assert.match(verified.text, /verified field-blocker debt/);
    assert.equal(verified.metrics?.count, 1);
    assert.equal(verified.metrics?.rawWeight, 30);
    assert.equal(verified.metrics?.cappedPenalty, 1.2);
    assert.equal(verified.metrics?.maxPenalty, 2);
    assert.equal(verified.metrics?.capApplied, false);
    assert.deepEqual(verified.metrics?.byInstallImpactClass, { state_data: 1 });
    assert.deepEqual(verified.issueRefs?.map((issue: any) => issue.number), [1003]);
    assert.equal(verified.issueRefs?.[0]?.weight, 30);
    assert.equal(verified.issueRefs?.[0]?.installImpactClass, 'state_data');
  });
});
