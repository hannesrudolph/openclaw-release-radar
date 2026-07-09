import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  auditPreviewCatalog,
  buildPreviewReleasePlan,
  buildPreviewScoreReport,
  parsePreviewScoreArgs,
} from '../../scripts/lib/preview-score-runtime.ts';

const EVALUATED_AT = '2026-07-08T12:34:56.000Z';
const DIGEST = 'a'.repeat(64);

function release(
  tag: string,
  publishedAt: string,
  catalogRank: number,
  {
    prerelease = 0,
    active = 1,
  }: {
    prerelease?: number;
    active?: number;
  } = {},
) {
  return {
    tag,
    published_at: publishedAt,
    prerelease,
    catalog_active: active,
    catalog_rank: catalogRank,
    catalog_digest: DIGEST,
  };
}

const catalog = [
  release('v9001.7.1', '2026-07-01T00:00:00Z', 0),
  release('v9001.6.11', '2026-06-30T00:00:00Z', 1),
  release('v9001.6.10', '2026-06-10T00:00:00Z', 2),
  release('v9001.6.5-beta.1', '2026-06-05T00:00:00Z', 3, {
    prerelease: 1,
  }),
  release('v9001.5.31', '2026-05-31T00:00:00Z', 4),
  release('v9001.6.1-inactive', '2026-06-01T00:00:00Z', 5, {
    active: 0,
  }),
];

function integrity(summary: Record<string, unknown> = {}) {
  return { summary, problem: null, error: null };
}

function classification() {
  return {
    summary: {
      failedCount: 0,
      issueCount: 0,
      missingSnapshotCount: 0,
      invalidSnapshotCount: 0,
      commentDigestMismatchCount: 0,
      missingClassificationCount: 0,
      staleClassificationCount: 0,
      classifierSourceIdentityMismatchCount: 0,
      invalidRawClassificationCount: 0,
    },
    error: null,
  };
}

function completeness() {
  return integrity({
    complete: true,
    problems: [],
    missingClosureEvidenceCount: 0,
  });
}

function result(row: any, rating: number) {
  const scoreLedger = {
    evaluatedAt: EVALUATED_AT,
    digest: DIGEST,
    evidence: { manifests: [] },
  };
  return {
    rel: row,
    scoredAt: EVALUATED_AT,
    analysisCompleteness: {
      complete: true,
      missingClosureEvidence: [],
    },
    conf: {
      score: rating,
      status: 'eligible',
      band: 'solid',
      reason: 'complete evidence',
    },
    input: {
      rawIssueCount: 0,
      classifiedIssueCount: 0,
    },
    scoreLedger,
    explanation: { scoreLedger },
    authorityReferences: [],
  };
}

function readyRelease() {
  return {
    ready: true,
    reasons: [],
    scoreLedgerProblems: [],
    issueTimeline: integrity({ ambiguousReopenCount: 0, issueCount: 0 }),
    issueStateSnapshots: integrity({ failedCount: 0, candidateIssueCount: 0 }),
    fixCreditProblems: [],
  };
}

function reportFixture() {
  const range = parsePreviewScoreArgs(
    ['--db-path', 'fixture.db', '--month', '2026-06'],
    { cwd: '/tmp' },
  ).range;
  const plan = buildPreviewReleasePlan(catalog, range);
  const newest = plan.selectedNewestFirst[0];
  const oldest = plan.selectedNewestFirst[1];
  const run = {
    scored: [
      result(newest, 8.7),
      result(oldest, 8.1),
    ],
    sourceIdentity: { digest: DIGEST },
    oldestScoredStableTag: oldest.tag,
    oldestScoredStablePredecessorTag:
      plan.oldestScoredStablePredecessorTag,
    predecessorByReleaseTag: plan.predecessorByReleaseTag,
    predecessorBoundaryProblems: [],
  };
  const scoreBundle: any = {
    evaluatedAt: EVALUATED_AT,
    plan,
    run,
    classificationAudits: {
      [newest.tag]: classification(),
      [oldest.tag]: classification(),
    },
    completenessAudits: {
      [newest.tag]: completeness(),
      [oldest.tag]: completeness(),
    },
    closureAudits: {
      [newest.tag]: integrity({ rawClosedCount: 0, proofRowCount: 0 }),
      [oldest.tag]: integrity({ rawClosedCount: 0, proofRowCount: 0 }),
    },
    reachabilityAudits: {
      [newest.tag]: integrity({ candidateCount: 0, rowCount: 0 }),
      [oldest.tag]: integrity({ candidateCount: 0, rowCount: 0 }),
    },
    predecessorReachabilityAudit: integrity({
      candidateCount: 0,
      rowCount: 0,
    }),
    readiness: {
      ready: true,
      reasons: [],
      issueCatalogSnapshotLedger: integrity({
        snapshotCount: 1,
        rowCount: 0,
        consumptionCount: 1,
        orphanRowCount: 0,
        problems: [],
      }),
      scoreAuthorityProblems: [],
      crawl: {
        ready: true,
        problems: [],
        error: null,
        schemaVersion: 4,
        stopReason: 'exhausted',
        crawlMode: 'exhaustive',
        finishedAt: EVALUATED_AT,
        scorePersisted: true,
      },
      stableReleaseWindow: integrity({
        missingPublishedAtCount: 0,
        duplicatePublishedAtCount: 0,
        duplicateReleaseCount: 0,
      }),
      activeRefresh: {
        active: false,
        attemptRunId: null,
        leaseName: null,
        leaseHolderId: null,
        leaseExpiresAt: null,
      },
      activeScoreBlockingIngestionFailures: {
        count: 0,
        examples: [],
      },
      releases: {
        [newest.tag]: readyRelease(),
        [oldest.tag]: readyRelease(),
      },
    },
  };
  const inspection = {
    missingTables: [],
    activeCatalog: catalog,
    capture: null,
    latestCatalogOperation: null,
    terminalReceipt: null,
    consumptionByRun: null,
    consumptionByDeclaredSnapshot: null,
    snapshot: null,
  };
  const audit = {
    reasons: [],
    classifierKnownTags: [newest.tag, oldest.tag],
    issueCrawlMetadata: {},
    identities: {
      catalogOperation: { runId: 'refresh-fixture' },
      releaseCatalog: { receiptId: DIGEST },
      terminalReceipt: { receiptId: DIGEST },
      issueCatalogSnapshot: { snapshotId: DIGEST },
      issueCatalogConsumption: { contentHash: DIGEST },
    },
    evidenceCounts: {
      activeReleases: 5,
      activeStableReleases: 4,
      selectedStableReleases: 2,
      issueCatalogSnapshotRows: 0,
      issueCatalogSnapshotPages: 0,
      consumedIssueRows: 0,
      consumedIssuePages: 0,
    },
  };
  return {
    plan,
    scoreBundle,
    build: () => buildPreviewScoreReport({
      databasePath: '/tmp/fixture.db',
      range,
      inspection: inspection as any,
      audit: audit as any,
      scoreBundle,
      evaluatedAt: EVALUATED_AT,
      generatedAt: EVALUATED_AT,
    }) as any,
  };
}

describe('score preview batch report', () => {
  it('strictly parses an explicit database path and half-open inclusive date selectors', () => {
    const month = parsePreviewScoreArgs(
      ['--db-path', './radar.db', '--month', '2026-06'],
      { cwd: '/tmp/preview' },
    );
    assert.equal(month.databasePath, '/tmp/preview/radar.db');
    assert.equal(month.range.from, '2026-06-01');
    assert.equal(month.range.through, '2026-06-30');
    assert.equal(
      month.range.endExclusiveMs,
      Date.parse('2026-07-01T00:00:00.000Z'),
    );

    const explicit = parsePreviewScoreArgs([
      '--db-path=/tmp/radar.db',
      '--from=2026-06-10',
      '--through=2026-06-10',
    ]);
    assert.equal(
      explicit.range.endExclusiveMs - explicit.range.startMs,
      24 * 60 * 60 * 1000,
    );

    for (const args of [
      ['--month', '2026-06'],
      ['--db-path', 'radar.db'],
      ['--db-path', 'radar.db', '--month', '2026-06', '--month', '2026-07'],
      ['--db-path', 'radar.db', '--month', '2026-06', '--from', '2026-06-01'],
      ['--db-path', 'radar.db', '--from', '2026-06-31', '--through', '2026-07-01'],
      ['--db-path', 'radar.db', '--month', '2026-06', '--unknown', 'value'],
    ]) {
      assert.throws(() => parsePreviewScoreArgs(args));
    }
  });

  it('selects active stable June releases in canonical newest-first order with the boundary predecessor', () => {
    const range = parsePreviewScoreArgs(
      ['--db-path', 'radar.db', '--month', '2026-06'],
    ).range;
    const plan = buildPreviewReleasePlan(catalog, range);

    assert.deepEqual(
      plan.selectedNewestFirst.map((row) => row.tag),
      ['v9001.6.11', 'v9001.6.10'],
    );
    assert.deepEqual(plan.predecessorByReleaseTag, {
      'v9001.6.11': 'v9001.6.10',
      'v9001.6.10': 'v9001.5.31',
    });
    assert.equal(plan.oldestScoredStablePredecessorTag, 'v9001.5.31');
  });

  it('fails closed on a newer catalog operation without a successful receipt or consumption', () => {
    const range = parsePreviewScoreArgs(
      ['--db-path', 'radar.db', '--month', '2026-06'],
    ).range;
    const audit = auditPreviewCatalog({
      missingTables: [],
      activeCatalog: catalog,
      capture: {
        receiptId: DIGEST,
        operationRunId: 'refresh-older',
        sourceKind: 'github_graphql',
        repository: 'openclaw/openclaw',
        observedAt: EVALUATED_AT,
        activeCatalogDigest: DIGEST,
        activeReleaseCount: 5,
        contentHash: DIGEST,
      },
      latestCatalogOperation: {
        runId: 'refresh-newer',
        operation: 'refresh',
        trigger: 'manual',
        startedAt: EVALUATED_AT,
        codeRevision: DIGEST,
        effectiveConfigHash: DIGEST,
        contentHash: DIGEST,
      },
      terminalReceipt: null,
      consumptionByRun: null,
      consumptionByDeclaredSnapshot: null,
      snapshot: null,
    }, range);

    assert.ok(audit.reasons.some((reason) =>
      reason.includes(
        'latest release catalog capture belongs to operation refresh-older, ' +
        'not latest catalog operation refresh-newer',
      )));
    assert.ok(audit.reasons.some((reason) =>
      reason.includes(
        'latest catalog operation refresh-newer has no terminal receipt',
      )));
    assert.ok(audit.reasons.some((reason) =>
      reason.includes(
        'latest catalog operation refresh-newer has no matching ' +
        'issue catalog snapshot consumption',
      )));
  });

  it('withholds the provisional rating for every score-input integrity gate', () => {
    const cases: Array<{
      name: string;
      reason: RegExp;
      mutate(fixture: ReturnType<typeof reportFixture>): void;
    }> = [
      {
        name: 'classification coverage',
        reason: /classification coverage is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.run.scored[0].input.rawIssueCount = 1;
        },
      },
      {
        name: 'classification integrity',
        reason: /classification integrity is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.classificationAudits['v9001.6.11'] = {
            ...classification(),
            summary: {
              ...classification().summary,
              failedCount: 1,
              missingClassificationCount: 1,
            },
          };
        },
      },
      {
        name: 'current closure completeness',
        reason: /current closure-analysis completeness is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.completenessAudits['v9001.6.11'] = {
            summary: {
              complete: false,
              problems: ['current missing_evidence closure row remains'],
            },
            problem: 'current missing_evidence closure row remains',
            error: null,
          };
        },
      },
      {
        name: 'declared analysis completeness',
        reason: /analysisCompleteness is false/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.run.scored[0].analysisCompleteness = {
            complete: false,
            missingClosureEvidence: [{ issueNumber: 42 }],
          };
        },
      },
      {
        name: 'closure proof integrity',
        reason: /closure proof integrity is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.closureAudits['v9001.6.11'] = {
            summary: { missingCount: 1 },
            problem: 'closure proof evidence is not current',
            error: null,
          };
        },
      },
      {
        name: 'PR reachability integrity',
        reason: /PR reachability integrity is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.reachabilityAudits['v9001.6.11'] = {
            summary: { missingCount: 1 },
            problem: 'PR reachability evidence is not current',
            error: null,
          };
        },
      },
      {
        name: 'issue timeline readiness',
        reason: /issue timeline readiness is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.readiness.releases['v9001.6.11'] = {
            ...readyRelease(),
            ready: false,
            reasons: ['issue timeline readiness is incomplete'],
          };
        },
      },
      {
        name: 'issue state readiness',
        reason: /issue state snapshot readiness is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.readiness.releases['v9001.6.11'] = {
            ...readyRelease(),
            ready: false,
            reasons: ['issue state snapshot readiness is incomplete'],
          };
        },
      },
      {
        name: 'crawl readiness',
        reason: /issue crawl readiness is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.readiness.ready = false;
          scoreBundle.readiness.reasons = [
            'issue crawl readiness is incomplete: pagination is not exhaustive',
          ];
        },
      },
      {
        name: 'snapshot ledger readiness',
        reason: /issue catalog snapshot ledger readiness is incomplete/,
        mutate: ({ scoreBundle }) => {
          scoreBundle.readiness.ready = false;
          scoreBundle.readiness.reasons = [
            'issue catalog snapshot ledger readiness is incomplete: hash mismatch',
          ];
        },
      },
    ];

    for (const testCase of cases) {
      const fixture = reportFixture();
      testCase.mutate(fixture);
      const report = fixture.build();
      const row = report.releases[0];
      assert.equal(row.status, 'unrated', testCase.name);
      assert.equal(row.rating, null, testCase.name);
      assert.match(row.reasons.join('; '), testCase.reason, testCase.name);
      assert.doesNotMatch(JSON.stringify(row), /8\.7/, testCase.name);
    }
  });

  it('emits each selected row once with one evaluatedAt and withholds incomplete ratings', () => {
    const fixture = reportFixture();
    const complete = fixture.build();
    assert.equal(complete.order, 'catalog_rank_asc_newest_first');
    assert.equal(complete.batchIntegrity.exactOnce, true);
    assert.deepEqual(
      complete.releases.map((row: any) => row.tag),
      ['v9001.6.11', 'v9001.6.10'],
    );
    assert.ok(complete.releases.every(
      (row: any) => row.evaluatedAt === EVALUATED_AT,
    ));
    assert.equal(complete.predecessorBoundary.predecessorTag, 'v9001.5.31');
    assert.deepEqual(
      complete.releases.map((row: any) => row.rating),
      [8.7, 8.1],
    );
    assert.equal('recommendedTag' in complete, false);

    fixture.scoreBundle.closureAudits['v9001.6.11'] = {
      summary: { missingCount: 1 },
      problem: 'v9001.6.11: closure proof evidence is not current',
      error: null,
    };
    let incomplete = fixture.build();
    assert.equal(incomplete.releases[0].status, 'unrated');
    assert.equal(incomplete.releases[0].rating, null);
    assert.doesNotMatch(JSON.stringify(incomplete.releases[0]), /8\.7/);

    fixture.scoreBundle.closureAudits['v9001.6.11'] =
      integrity({ rawClosedCount: 0, proofRowCount: 0 });
    fixture.scoreBundle.readiness.releases['v9001.6.11'] = {
      ...readyRelease(),
      ready: false,
      reasons: ['issue state snapshot readiness is incomplete'],
    };
    incomplete = fixture.build();
    assert.equal(incomplete.releases[0].rating, null);

    fixture.scoreBundle.readiness.releases['v9001.6.11'] = readyRelease();
    fixture.scoreBundle.predecessorReachabilityAudit = {
      summary: { missingCount: 1 },
      problem: 'v9001.5.31: PR reachability evidence is not current',
      error: null,
    };
    incomplete = fixture.build();
    assert.equal(incomplete.releases[1].rating, null);

    fixture.scoreBundle.predecessorReachabilityAudit =
      integrity({ candidateCount: 0, rowCount: 0 });
    fixture.scoreBundle.run.scored.push(
      result(fixture.plan.selectedNewestFirst[0], 9.9),
    );
    incomplete = fixture.build();
    assert.equal(incomplete.batchIntegrity.exactOnce, false);
    assert.equal(incomplete.releases.length, 2);
    assert.ok(incomplete.releases.every(
      (row: any) => row.status === 'unrated' && row.rating === null,
    ));
    assert.doesNotMatch(JSON.stringify(incomplete.releases), /9\.9/);
  });
});
