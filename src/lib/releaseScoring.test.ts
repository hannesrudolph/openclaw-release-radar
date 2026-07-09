import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  buildExclusiveIssueRiskLedger,
  installConfidence,
  scoreCommentBodyDigest,
  scoreExplanationAuditProblems,
  selectRecommendation,
} from './score.ts';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
  serializeCommentEvidence,
} from './commentEvidence.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownsTestDir = assignedWorkerDatabasePath === null;
const testDir = assignedWorkerDatabasePath
  ? dirname(assignedWorkerDatabasePath)
  : mkdtempSync(join(tmpdir(), 'radar-release-scoring-test-'));
const testDatabasePath =
  assignedWorkerDatabasePath ?? join(testDir, 'radar.db');
if (assignedWorkerDatabasePath) {
  assert.equal(
    process.env.DB_PATH,
    assignedWorkerDatabasePath,
    'guarded release scoring tests must use their assigned private database',
  );
  assert.ok(
    process.env.DOTENV_CONFIG_PATH,
    'guarded release scoring tests require the runner-assigned empty dotenv path',
  );
} else {
  process.env.DB_PATH = testDatabasePath;
  const emptyDotenvPath = join(testDir, 'empty.env');
  writeFileSync(emptyDotenvPath, '', { flag: 'wx', mode: 0o600 });
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
}
let scoring: typeof import('./releaseScoring.ts');
let radarDb: typeof import('./db.ts');

before(async () => {
  scoring = await import('./releaseScoring.ts');
  radarDb = await import('./db.ts');
});

after(() => {
  radarDb.db.close();
  if (ownsTestDir) rmSync(testDir, { recursive: true, force: true });
});

function authoritativeComment(
  id: number,
  login: string,
  body: string,
  overrides: Record<string, any> = {},
) {
  const { user: userOverrides, ...commentOverrides } = overrides;
  return {
    id,
    node_id: `IC_${id}`,
    node_type: 'IssueComment',
    url: `https://example.test/comments/${id}`,
    user: {
      id: `U_${login}`,
      login,
      type: 'User',
      ...(userOverrides ?? {}),
    },
    author_association: null,
    body,
    created_at: '2026-06-12T00:00:00Z',
    updated_at: '2026-06-12T00:00:00Z',
    ...commentOverrides,
  };
}

function testAuthorityReference(
  subjectIdentity: string,
  subjectKind: 'comment' | 'label_event' = 'comment',
) {
  return {
    subjectKind,
    subjectIdentity,
    resolutionHash: 'a'.repeat(64),
    evidenceDigest: 'b'.repeat(64),
    authorizedForScoring: true as const,
  };
}

function scoringReleaseRow(
  tag: string,
  publishedAt: string,
  catalogRank: number,
  overrides: Record<string, unknown> = {},
) {
  return {
    tag,
    node_id: `R_${tag}`,
    catalog_tag_commit_oid: `oid-${tag}`,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease: 0,
    catalog_rank: catalogRank,
    catalog_digest: 'catalog-digest',
    catalog_active: 1,
    body: '',
    breaking_count: 0,
    fixes_count: 0,
    changes_count: 0,
    highlights_count: 0,
    pr_refs_count: 0,
    beta_count: 0,
    hours_to_next_release: null,
    hours_to_next_stable: null,
    ...overrides,
  } as any;
}

function closureAuthorityBinding(input: {
  candidateId: string;
  issueNumber: number;
  claim: Record<string, unknown>;
  authorized?: boolean;
  repositoryNameWithOwner?: string;
  createdAt?: string;
  updatedAt?: string;
  sourceNodeId?: string;
  spanStart?: number;
}) {
  const createdAt = input.createdAt ?? '2026-07-04T00:00:00Z';
  return {
    candidate: {
      candidateId: input.candidateId,
      repository: {
        nameWithOwner:
          input.repositoryNameWithOwner ?? 'openclaw/openclaw',
      },
      issue: { number: input.issueNumber },
      source: {
        kind: 'comment',
        nodeId: input.sourceNodeId ?? `COMMENT_${input.candidateId}`,
        createdAt,
        updatedAt: input.updatedAt ?? createdAt,
      },
      span: input.spanStart == null
        ? null
        : { start: input.spanStart, end: input.spanStart + 1 },
      claim: input.claim,
    },
    resolution: {
      candidateId: input.candidateId,
      issueNumber: input.issueNumber,
      authorizedForScoring: input.authorized !== false,
    },
  } as any;
}

function authoritativeCommentSnapshot(input: {
  issueNumber: number;
  issueNodeId: string;
  issueAuthorNodeId: string;
  issueAuthorLogin: string;
  issueUpdatedAt: string;
  comments: ReturnType<typeof authoritativeComment>[];
}) {
  const repositoryNodeId = 'REPO-node-openclaw';
  const snapshotIdentity = {
    repositoryNodeId,
    issueNodeId: input.issueNodeId,
    issueNodeType: 'Issue',
    issueAuthor: {
      nodeId: input.issueAuthorNodeId,
      login: input.issueAuthorLogin,
      actorType: 'User',
    },
  };
  const sweep = {
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: input.comments.length,
    comments: input.comments,
    snapshotIdentity,
  };
  const firstSweep = commentEvidenceSweepIdentity({
    ...sweep,
    sweepOrdinal: 1,
  });
  const secondSweep = commentEvidenceSweepIdentity({
    ...sweep,
    sweepOrdinal: 2,
  });
  const stabilization = commentEvidenceStabilizationIdentity(
    firstSweep,
    secondSweep,
    2,
  );
  return {
    issue_number: input.issueNumber,
    repository_node_id: repositoryNodeId,
    issue_node_id: input.issueNodeId,
    issue_author_node_id: input.issueAuthorNodeId,
    issue_author_login: input.issueAuthorLogin,
    issue_author_type: 'User',
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    comment_count: input.comments.length,
    fetched_comment_count: input.comments.length,
    latest_comment_updated_at: input.comments.at(-1)?.updated_at ?? null,
    comments_digest: commentEvidenceDigest(input.comments.length, input.comments),
    authority_digest: secondSweep.authorityDigest,
    issue_updated_at: input.issueUpdatedAt,
    comments_json: serializeCommentEvidence(input.comments),
    stabilization_json: JSON.stringify(stabilization),
    stabilization_identity_digest: stabilization.identityDigest,
  };
}

function explanationResult(overrides: Record<string, any> = {}) {
  const status = overrides.status ?? 'eligible';
  const score = Object.hasOwn(overrides, 'score') ? overrides.score : 6;
  const components = Object.hasOwn(overrides, 'components')
    ? overrides.components
    : status === 'wait' || status === 'skip-cve'
      ? null
      : {};
  const result = {
    rel: { tag: overrides.tag ?? 'v-test' },
    scoredAt: '2026-06-10T00:00:00Z',
    conf: {
      status,
      score,
      band: status === 'wait' ? 'wait' : status.startsWith('skip-') ? 'skip' : 'ok',
      hotfix: status === 'skip-hotfix',
      components,
      evidenceCoverage: 1,
      reason: overrides.reason ?? 'test reason',
    },
    input: {
      publishedAt: '2026-06-01T00:00:00Z',
      isLatest: true,
      hoursToNextStable: null,
      hasHotfixSuccessor: false,
      betaCount: 0,
      breakingCount: 0,
      feltOpenedWeight: 0,
      feltClosedWeight: 0,
      verifiedDebtWeight: 0,
      carryoverDebtWeight: 0,
      staleDebtWeight: 0,
      unresolvedClosureRiskWeight: 0,
      affirmativeClosureRiskCeilingWeight: 0,
      rawIssueCount: 0,
      classifiedIssueCount: 0,
      cveAffected: false,
      cveLoad: 0,
      ...overrides.input,
    },
    debtEvidence: {
      verifiedDebt: [],
      carryoverDebt: [],
      staleDebt: [],
      openedFeltSerious: [],
      ...overrides.debtEvidence,
    },
    gateEvidence: {
      fixProvenance: {},
      artifactVerification: {},
      ...overrides.gateEvidence,
    },
  } as any;
  const aliasElection = buildExclusiveIssueRiskLedger([
    ['verified', result.input.verifiedDebtWeight],
    ['carryover', result.input.carryoverDebtWeight],
    ['stale', result.input.staleDebtWeight],
    ['closureRisk', result.input.unresolvedClosureRiskWeight],
    ['regression', result.input.feltOpenedWeight],
  ].flatMap(([channel, weight], index) =>
    typeof weight === 'number' && weight > 0
      ? [{
          aliasGroup: `explanation:${channel}:${index}`,
          channel,
          weight,
          issueNumber: index + 1,
        }]
      : [],
  ) as any);
  const groupsFor = (channel: string) => aliasElection.groups.filter((group) =>
    group.selectedChannel === channel);
  const evidenceSources = [
    ...(['verified', 'carryover', 'stale'] as const).map((channel) => ({
      key: channel === 'verified'
        ? 'verifiedDebt'
        : channel === 'carryover'
          ? 'carryoverDebt'
          : 'staleDebt',
      refs: groupsFor(channel).map((group) => ({
        kind: 'issue',
        identity: `issue:${group.issueNumber}:alias:${group.aliasGroup}`,
        payload: {
          aliasGroup: group.aliasGroup,
          tier: channel,
          weight: group.selectedWeight,
        },
      })),
    })),
    {
      key: 'closureRisk',
      refs: groupsFor('closureRisk').map((group) => ({
        kind: 'closure_group',
        identity: `closure:${group.aliasGroup}`,
        payload: {
          key: group.aliasGroup,
          weight: group.selectedWeight,
        },
      })),
    },
    {
      key: 'regressionOpened',
      refs: groupsFor('regression').map((group) => ({
        kind: 'issue',
        identity: `issue:${group.issueNumber}:alias:${group.aliasGroup}`,
        payload: {
          aliasGroup: group.aliasGroup,
          countedWeight: group.selectedWeight,
        },
      })),
    },
    {
      key: 'advisories',
      refs: result.input.cveAffected
        ? [{
            kind: 'advisory',
            identity: 'advisory:test-affected',
            payload: {
              affected: true,
              load: result.input.cveLoad,
            },
          }]
        : [],
    },
  ];
  const ledgerConfidence = installConfidence(result.input, Date.parse(result.scoredAt));
  result.scoreLedger = scoring.__releaseScoringTest.buildScoreLedgerV2({
    input: result.input,
    confidence: ledgerConfidence,
    now: Date.parse(result.scoredAt),
    aliasElection,
    evidenceSources,
  });
  return result;
}

describe('release score explanations', () => {
  it('exports one fail-closed current-score completeness diagnostic', () => {
    const missing = {
      issueNumber: 1003,
      status: 'direct_fix_commit_reachability_unknown',
      title: 'fix commit reachability is unknown',
      sentiment: 'negative',
      severity: 'high',
      functionality: 'core',
      scope: 'broad',
      affectedUsers: 'many',
      potentialRiskWeight: 4.875,
    };
    const declaredIncomplete = scoring.currentScoreCompletenessDiagnostic({
      tag: 'v-test',
      analysisCompleteness: {
        complete: false,
        missingClosureEvidence: [],
      },
      currentMissingClosureEvidence: [],
    });
    const liveMissing = scoring.currentScoreCompletenessDiagnostic({
      tag: 'v-test',
      analysisCompleteness: {
        complete: true,
        missingClosureEvidence: [],
      },
      currentMissingClosureEvidence: [missing],
    });

    assert.equal(declaredIncomplete.schemaVersion, 1);
    assert.equal(declaredIncomplete.complete, false);
    assert.deepEqual(declaredIncomplete.causes, ['analysis_completeness_false']);
    assert.ok(declaredIncomplete.problems.some((problem) =>
      /analysisCompleteness\.complete must be true/.test(problem)));
    assert.equal(liveMissing.complete, false);
    assert.deepEqual(liveMissing.causes, ['score_affecting_missing_closure_evidence']);
    assert.deepEqual(liveMissing.missingClosureEvidence, [missing]);
    assert.equal(liveMissing.missingClosureEvidenceCount, 1);
    assert.equal(liveMissing.potentialMissingClosureRiskWeight, 4.875);
    assert.ok(liveMissing.problems.some((problem) =>
      /score-affecting negative missing_evidence row #1003/.test(problem)));
  });

  it('builds stable scoring tag windows in deterministic release-recency order', () => {
    assert.deepEqual(scoring.scoreTagWindow([
      { tag: 'v1', prerelease: null, published_at: '2026-06-01T00:00:00Z' },
      { tag: 'v3-beta.1', prerelease: 1, published_at: '2026-06-03T01:00:00Z' },
      { tag: 'v2', prerelease: false, published_at: '2026-06-02T00:00:00Z' },
      { tag: 'v3', prerelease: 0, published_at: '2026-06-03T00:00:00Z' },
    ]), {
      allFetchedTags: ['v3-beta.1', 'v3', 'v2', 'v1'],
      stableTagsNewestFirst: ['v3', 'v2', 'v1'],
    });
  });

  it('binds reordered and historical score rows to canonical release identity', () => {
    const beta = scoringReleaseRow(
      'v2026.6.12-beta.1',
      '2026-06-12T00:00:00Z',
      0,
      { prerelease: 1 },
    );
    const latest = scoringReleaseRow(
      'v2026.6.11',
      '2026-06-11T00:00:00Z',
      1,
      {
        breaking_count: 2,
        beta_count: 3,
        hours_to_next_stable: null,
      },
    );
    const older = scoringReleaseRow(
      'v2026.6.10',
      '2026-06-10T00:00:00Z',
      2,
      { hours_to_next_stable: 24 },
    );
    const activeCatalog = [beta, latest, older];
    const reordered = scoring.__releaseScoringTest.bindSuppliedScoreReleases(
      [{ ...older }, { ...latest }],
      activeCatalog,
    );
    const canonicalLatest =
      scoring.__releaseScoringTest.canonicalLatestStableRelease(activeCatalog);

    assert.throws(
      () => scoring.__releaseScoringTest.bindSuppliedScoreReleases(
        [{ ...beta }],
        activeCatalog,
      ),
      /v2026\.6\.12-beta\.1: release is not an active stable release/,
    );
    assert.deepEqual(reordered.map((release: any) => release.tag), [
      latest.tag,
      older.tag,
    ]);
    assert.equal(reordered[0], latest);
    assert.equal(canonicalLatest, latest);
    assert.equal(
      scoring.__releaseScoringTest.isCanonicalLatestStableRelease(
        reordered[0],
        canonicalLatest,
      ),
      true,
    );
    assert.equal(
      scoring.__releaseScoringTest.isCanonicalLatestStableRelease(
        { ...latest, node_id: 'R_tampered' },
        canonicalLatest,
      ),
      false,
    );

    const historicalOnly =
      scoring.__releaseScoringTest.bindSuppliedScoreReleases(
        [{ ...older }],
        activeCatalog,
      );
    assert.deepEqual(historicalOnly.map((release: any) => release.tag), [older.tag]);
    assert.equal(
      scoring.__releaseScoringTest.isCanonicalLatestStableRelease(
        historicalOnly[0],
        canonicalLatest,
      ),
      false,
    );

    for (const [field, value] of [
      ['node_id', 'R_tampered'],
      ['catalog_tag_commit_oid', 'oid-tampered'],
      ['published_at', '2026-06-09T00:00:00Z'],
      ['breaking_count', 99],
      ['beta_count', 99],
      ['hours_to_next_stable', 999],
    ] as const) {
      assert.throws(
        () => scoring.__releaseScoringTest.bindSuppliedScoreReleases(
          [{ ...latest, [field]: value }],
          activeCatalog,
        ),
        new RegExp(`canonical release binding mismatch in .*${field}`),
      );
    }
  });

  it('derives every scored predecessor from the supplied stable catalog boundary', () => {
    const context = scoring.__releaseScoringTest.deriveReleasePredecessors([
      { tag: 'v3', prerelease: 0, published_at: '2026-06-03T00:00:00Z' },
      { tag: 'v2', prerelease: 0, published_at: '2026-06-02T00:00:00Z' },
    ] as any, ['v4', 'v3', 'v2', 'v1'], 'v1');

    assert.deepEqual(context.predecessorByReleaseTag, {
      v3: 'v2',
      v2: 'v1',
    });
    assert.equal(context.oldestScoredStableTag, 'v2');
    assert.equal(context.oldestScoredStablePredecessorTag, 'v1');
    assert.deepEqual(context.problems, []);

    const missing = scoring.__releaseScoringTest.deriveReleasePredecessors([
      { tag: 'v2', prerelease: 0, published_at: '2026-06-02T00:00:00Z' },
    ] as any, ['v2'], null);
    assert.ok(missing.problems.some((problem: string) =>
      problem.includes('has no immediate predecessor')));
    assert.ok(missing.problems.some((problem: string) =>
      problem.includes('missing its explicit predecessor boundary')));
  });

  it('truncates issue titles at useful boundaries', () => {
    const title = 'Normal tool text outputs can degrade to "(see attached image)" placeholders in agent transcript rendering';
    assert.equal(
      scoring.__releaseScoringTest.truncateAtWordBoundary(title, 88),
      'Normal tool text outputs can degrade to "(see attached image)" placeholders in...',
    );
  });

  it('removes repetitive bug prefixes before explanation examples', () => {
    assert.equal(
      scoring.__releaseScoringTest.shortIssueTitle({ title: '[Bug]: web_search providers stopped working after upgrade' }),
      'web_search providers stopped working after upgrade',
    );
    assert.equal(
      scoring.__releaseScoringTest.shortIssueTitle({ title: '[Bug]:' }),
      'untitled report',
    );
  });

  it('excludes placeholder issue titles from prose examples', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      debtEvidence: {
        openedFeltSerious: [
          { issue: { number: 1, title: '[Bug]:', state: 'closed', url: 'https://example.test/1' } },
          { issue: { number: 2, title: 'Gateway stalls after update', state: 'closed', url: 'https://example.test/2' } },
        ],
      },
    }), false);
    const opened = explanation.limitDetails.find((detail: any) =>
      detail.code === 'field_visible_reports_opened');
    assert.doesNotMatch(opened?.text ?? '', /#1\b|\[Bug\]:/);
    assert.match(opened?.text ?? '', /#2 Gateway stalls after update/);
  });

  it('excludes still-open reports from regression opened load', () => {
    const rows = [
      { number: 1, state: 'open', title: 'open regression' },
      { number: 2, state: 'closed', title: 'closed regression' },
      { number: 3, state: 'closed-unverified', title: 'closed unverified regression' },
    ];
    assert.deepEqual(
      scoring.__releaseScoringTest.releaseRegressionOpenedRows(rows).map((row) => row.number),
      [2, 3],
    );
    assert.deepEqual(
      scoring.__releaseScoringTest.releaseLinkedIssueRows(rows, 'v2026.6.11').map((row) => row.number),
      [1, 2, 3],
    );
  });

  // Historical baseline identity; current assertions require authoritative exclusion.
  it('ignores display-only classifier attribution but excludes explicit release mismatches', () => {
    const wrongReleaseCommentEvidence =
      scoring.__releaseScoringTest.exactReleaseLocalEvidence(
        { title: 'Comment-only release evidence', body: '' },
        'v2026.6.10',
        [authoritativeComment(
          980,
          'wrong-release-reporter',
          'Confirming this still reproduces on v2026.6.10.',
        )],
        '2026-06-10T00:00:00Z',
        testAuthorityReference,
      );
    const targetReleaseCommentEvidence =
      scoring.__releaseScoringTest.exactReleaseLocalEvidence(
        { title: 'Comment-only release evidence', body: '' },
        'v2026.6.11',
        [authoritativeComment(
          981,
          'target-release-reporter',
          'Confirming this still reproduces on v2026.6.11.',
        )],
        '2026-06-11T00:00:00Z',
        testAuthorityReference,
      );
    assert.ok(wrongReleaseCommentEvidence);
    assert.ok(targetReleaseCommentEvidence);

    const rows = [
      { number: 1, state: 'closed', affects_version: 'v2026.6.11' },
      { number: 2, state: 'closed', affects_version: 'v2026.6.10' },
      { number: 3, state: 'closed', affects_version: null },
      { number: 4, state: 'closed', affects_version: null, title: 'failure in v2026.5.12' },
      {
        number: 5,
        state: 'closed',
        affects_version: 'v2026.6.10',
        title: 'Failure reproduced on v2026.6.11',
      },
      {
        number: 6,
        state: 'closed',
        affects_version: 'v2026.6.10',
        releaseLocalEvidence: targetReleaseCommentEvidence,
      },
      {
        number: 7,
        state: 'closed',
        affects_version: null,
        title: 'Session state is lost',
        body: 'Session state is lost only on v2026.6.10 after upgrade.',
      },
      {
        number: 8,
        state: 'closed',
        affects_version: null,
        title: 'Comment-only release evidence',
        releaseLocalEvidence: wrongReleaseCommentEvidence,
      },
      {
        number: 9,
        state: 'closed',
        affects_version: null,
        title: 'Tracking the session failure',
        body: 'Planning a fix for v2026.6.10.',
      },
      {
        number: 10,
        state: 'closed',
        affects_version: 'v2026.6.10',
        title: 'Session state is lost',
        body: 'Observed session state loss on v2026.6.11 after upgrade.',
      },
      {
        number: 11,
        state: 'closed',
        affects_version: 'v2026.6.11',
        releaseExplicitlyUnaffected: true,
      },
    ];
    assert.deepEqual(
      scoring.__releaseScoringTest.releaseRegressionOpenedRows(rows, 'v2026.6.11')
        .map((row: any) => row.number),
      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    );
    assert.deepEqual(
      scoring.__releaseScoringTest.releaseLinkedIssueRows(rows, 'v2026.6.11')
        .map((row: any) => row.number),
      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    );
  });

  it('requires independent exact-version evidence for release-local debt', () => {
    const release = { tag: 'v2026.6.11', published_at: '2026-06-11T00:00:00Z' };
    assert.equal(scoring.__releaseScoringTest.isReleaseLocalDebtIssue({
      affects_version: 'v2026.6.11',
      created_at: '2026-06-12T00:00:00Z',
    }, release), false);
    assert.equal(scoring.__releaseScoringTest.isReleaseLocalDebtIssue({
      affects_version: 'v2026.6.11',
      created_at: '2026-06-12T00:00:00Z',
      title: 'Failure on current main',
    }, release), false);
    assert.equal(scoring.__releaseScoringTest.isReleaseLocalDebtIssue({
      affects_version: 'v2026.6.11',
      created_at: '2026-06-12T00:00:00Z',
      title: 'Nightly v2026.6.11 loses session state',
    }, release), false);
    assert.equal(scoring.__releaseScoringTest.isReleaseLocalDebtIssue({
      affects_version: 'v2026.6.11',
      created_at: '2026-06-12T00:00:00Z',
      title: 'Unparsed build crashes during startup',
    }, release), false);
    assert.equal(scoring.__releaseScoringTest.isReleaseLocalDebtIssue({
      affects_version: 'v2026.6.11',
      created_at: '2026-06-12T00:00:00Z',
      title: 'Failure in v2026.6.10',
    }, release), false);
    assert.deepEqual(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'Session state is lost after upgrading to 2026.6.11',
    }, release.tag), {
      kind: 'exact-version',
      source: 'title',
      version: 'v2026.6.11',
      snippet: 'Session state is lost after upgrading to 2026.6.11',
    });
    assert.deepEqual(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'Session state is lost',
      body: 'Observed session state loss on v2026.6.11 after upgrade.',
    }, release.tag), {
      kind: 'exact-version',
      source: 'body',
      version: 'v2026.6.11',
      snippet: 'Observed session state loss on v2026.6.11 after upgrade.',
    });
    assert.deepEqual(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'Session state is lost',
      body: '',
    }, release.tag, [authoritativeComment(
      991,
      'second-reporter',
      'Confirming this still reproduces on v2026.6.11.',
      {
        url: 'https://example.test/issues/99#issuecomment-991',
      },
    )], release.published_at, testAuthorityReference), {
      kind: 'exact-version',
      source: 'comment',
      version: 'v2026.6.11',
      snippet: 'Confirming this still reproduces on v2026.6.11.',
      commentId: 991,
      commentUrl: 'https://example.test/issues/99#issuecomment-991',
      commentNodeId: 'IC_991',
      author: 'second-reporter',
      actorNodeId: 'U_second-reporter',
      actorType: 'User',
      association: null,
      occurredAt: '2026-06-12T00:00:00Z',
      updatedAt: '2026-06-12T00:00:00Z',
      commentBodyDigest: scoreCommentBodyDigest(
        'Confirming this still reproduces on v2026.6.11.',
      ),
      authorityReference: testAuthorityReference('IC_991'),
    });
    assert.equal(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'Session state is lost',
      body: '',
    }, release.tag, [authoritativeComment(
      992,
      'clawsweeper',
      'v2026.6.11 contains related lock handling and this should stay open.',
      {
        url: 'https://example.test/issues/99#issuecomment-992',
        user: { type: 'Bot' },
      },
    )], release.published_at), null);
    assert.equal(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'v2026.6.11 unaffected; only v2026.6.10 fails',
    }, release.tag), null);
    assert.equal(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'Works on v2026.6.11 but fails on v2026.6.10',
    }, release.tag), null);
    assert.equal(scoring.__releaseScoringTest.releaseExplicitlyUnaffected({
      title: 'The failure is still not fixed in v2026.6.11',
    }, release.tag), false);
    assert.ok(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'The failure is still not fixed in v2026.6.11',
    }, release.tag));
    assert.equal(scoring.__releaseScoringTest.isReleaseLocalDebtIssue({
      affects_version: 'v2026.6.10',
      created_at: '2026-06-01T00:00:00Z',
      title: 'Session state is lost in v2026.6.11',
    }, release), true);
  });

  it('requires an adverse clause and rejects planning or future-release mentions in titles and bodies', () => {
    const releaseTag = 'v2026.6.11';
    const rejected = [
      'Milestone v2026.6.11 tracks the session-loss failure.',
      'Planning v2026.6.11 for the crash fix.',
      'Backport the timeout fix to v2026.6.11.',
      'Release notes for v2026.6.11 document the prior failure.',
      'Informational tracking for v2026.6.11: login remains broken on main.',
      'The crash will be fixed in v2026.6.11.',
      'Future release v2026.6.11 is expected to fix the regression.',
    ];
    for (const text of rejected) {
      assert.equal(
        scoring.__releaseScoringTest.exactReleaseLocalEvidence({ title: text }, releaseTag),
        null,
        text,
      );
      assert.equal(
        scoring.__releaseScoringTest.exactReleaseLocalEvidence({
          title: 'Session issue',
          body: text,
        }, releaseTag),
        null,
        text,
      );
    }

    assert.deepEqual(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'Session loss affects v2026.6.10 and v2026.6.11 after upgrade',
    }, releaseTag), {
      kind: 'exact-version',
      source: 'title',
      version: releaseTag,
      snippet: 'Session loss affects v2026.6.10 and v2026.6.11 after upgrade',
    });
    assert.ok(scoring.__releaseScoringTest.exactReleaseLocalEvidence({
      title: 'Session issue',
      body: 'The login regression reproduces on v2026.6.11 after upgrade.',
    }, releaseTag));
  });

  it('requires post-publication adverse comment evidence for #88058/#90781/#92291 locality', () => {
    const evidence = (
      number: number,
      releaseTag: string,
      publishedAt: string,
      body: string,
      createdAt: string,
    ) => scoring.__releaseScoringTest.exactReleaseLocalEvidence(
      { title: `Issue #${number}`, body: '' },
      releaseTag,
      [authoritativeComment(
        number * 10,
        `reporter-${number}`,
        body,
        {
          url: `https://example.test/issues/${number}#issuecomment-${number * 10}`,
          created_at: createdAt,
          updated_at: createdAt,
        },
      )],
      publishedAt,
      testAuthorityReference,
    );

    assert.equal(evidence(
      88058,
      'v2026.6.6',
      '2026-06-12T11:04:42Z',
      'Corroborating repro on v2026.6.6 from a second Control UI installation.',
      '2026-06-06T09:30:25Z',
    ), null);

    assert.deepEqual(evidence(
      90781,
      'v2026.6.5',
      '2026-06-09T18:13:20Z',
      'Live repro on 2026.6.5: the narrative is generated, then dropped on read-back.',
      '2026-06-19T21:56:12Z',
    ), {
      kind: 'exact-version',
      source: 'comment',
      version: 'v2026.6.5',
      snippet: 'Live repro on 2026.6.5: the narrative is generated, then dropped on read-back.',
      commentId: 907810,
      commentUrl: 'https://example.test/issues/90781#issuecomment-907810',
      commentNodeId: 'IC_907810',
      author: 'reporter-90781',
      actorNodeId: 'U_reporter-90781',
      actorType: 'User',
      association: null,
      occurredAt: '2026-06-19T21:56:12Z',
      updatedAt: '2026-06-19T21:56:12Z',
      commentBodyDigest: scoreCommentBodyDigest(
        'Live repro on 2026.6.5: the narrative is generated, then dropped on read-back.',
      ),
      authorityReference: testAuthorityReference('IC_907810'),
    });

    assert.deepEqual(evidence(
      92291,
      'v2026.5.27',
      '2026-05-28T11:41:42Z',
      'Independent confirmation of this on 2026.5.27: cron edit silently dropped schedule.tz.',
      '2026-06-12T09:40:00Z',
    ), {
      kind: 'exact-version',
      source: 'comment',
      version: 'v2026.5.27',
      snippet: 'Independent confirmation of this on 2026.5.27: cron edit silently dropped schedule.tz.',
      commentId: 922910,
      commentUrl: 'https://example.test/issues/92291#issuecomment-922910',
      commentNodeId: 'IC_922910',
      author: 'reporter-92291',
      actorNodeId: 'U_reporter-92291',
      actorType: 'User',
      association: null,
      occurredAt: '2026-06-12T09:40:00Z',
      updatedAt: '2026-06-12T09:40:00Z',
      commentBodyDigest: scoreCommentBodyDigest(
        'Independent confirmation of this on 2026.5.27: cron edit silently dropped schedule.tz.',
      ),
      authorityReference: testAuthorityReference('IC_922910'),
    });
  });

  it('rejects #44502 similar-issue claims as exact release locality', () => {
    assert.equal(scoring.__releaseScoringTest.exactReleaseLocalEvidence(
      { title: 'Discord routing issue', body: '' },
      'v2026.3.11',
      [authoritativeComment(
        4051744088,
        'BlackWatch0',
        'I can reproduce a similar issue with the Feishu plugin on v2026.3.11 as well.',
        {
          url: 'https://example.test/issues/44502#issuecomment-4051744088',
          created_at: '2026-03-13T01:55:58Z',
          updated_at: '2026-03-13T01:55:58Z',
        },
      )],
      '2026-03-12T00:00:00Z',
    ), null);
  });

  // Historical baseline identity; raw prose alone no longer excludes interval attribution.
  it('excludes #98197 explicit unaffected claims from locality, regression, and closure risk', () => {
    const row = {
      number: 98197,
      state: 'closed',
      affects_version: 'v2026.6.11',
      title: 'SSE sanitizer regression on main (not in any 6.11 release)',
      body: 'Not in any released build. The entire 6.11 line is clean.',
    };
    assert.equal(scoring.__releaseScoringTest.exactReleaseLocalEvidence(
      row,
      'v2026.6.11',
    ), null);
    assert.equal(scoring.__releaseScoringTest.releaseExplicitlyUnaffected(
      row,
      'v2026.6.11',
    ), true);
    assert.deepEqual(scoring.__releaseScoringTest.releaseLinkedIssueRows(
      [row],
      'v2026.6.11',
    ), [row]);
    assert.deepEqual(scoring.__releaseScoringTest.releaseRegressionOpenedRows(
      [row],
      'v2026.6.11',
    ), [row]);
    assert.deepEqual(scoring.__releaseScoringTest.releaseLinkedIssueRows(
      [{ ...row, releaseExplicitlyUnaffected: true }],
      'v2026.6.11',
    ), []);
    assert.deepEqual(scoring.__releaseScoringTest.releaseRegressionOpenedRows(
      [{ ...row, releaseExplicitlyUnaffected: true }],
      'v2026.6.11',
    ), []);
    assert.deepEqual(scoring.__releaseScoringTest.releaseClosureRiskCandidateRows(
      [row],
      'v2026.6.11',
    ), []);
    assert.deepEqual(scoring.__releaseScoringTest.releaseClosureRiskCandidateRows(
      [{ issue_number: 98197, title: 'Main-only SSE sanitizer regression' }],
      'v2026.6.11',
      new Map([[98197, { body: 'This is not in any released build.' }]]),
    ), []);

    for (const text of [
      'This is not in any 6.11 release.',
      'This is not in any released build.',
      'The 6.11 builds/line are clean.',
    ]) {
      assert.equal(scoring.__releaseScoringTest.releaseExplicitlyUnaffected(
        { title: text },
        'v2026.6.11',
      ), true, text);
    }
  });

  it('requires authorized immutable closure claims for release exclusion and claim-neutral closure risk', () => {
    const deniedUnaffected = closureAuthorityBinding({
      candidateId: 'b'.repeat(64),
      issueNumber: 98197,
      authorized: false,
      claim: {
        kind: 'release_local',
        assertion: 'not_affected',
        releaseTag: 'v2026.6.11',
      },
    });
    const affected = closureAuthorityBinding({
      candidateId: 'c'.repeat(64),
      issueNumber: 98197,
      claim: {
        kind: 'release_local',
        assertion: 'affected',
        releaseTag: 'v2026.6.11',
      },
    });
    assert.equal(
      scoring.__releaseScoringTest.selectAuthorizedReleaseNotAffectedClaim(
        [deniedUnaffected, affected],
        'v2026.6.11',
      ),
      null,
    );

    const laterUnaffected = closureAuthorityBinding({
      candidateId: 'd'.repeat(64),
      issueNumber: 98197,
      createdAt: '2026-07-04T02:00:00Z',
      claim: {
        kind: 'release_local',
        assertion: 'not_affected',
        releaseTag: '2026.6.11',
      },
    });
    const firstUnaffected = closureAuthorityBinding({
      candidateId: 'a'.repeat(64),
      issueNumber: 98197,
      createdAt: '2026-07-04T01:00:00Z',
      claim: {
        kind: 'release_local',
        assertion: 'not_affected',
        releaseTag: 'v2026.6.11',
      },
    });
    assert.equal(
      scoring.__releaseScoringTest.selectAuthorizedReleaseNotAffectedClaim(
        [laterUnaffected, firstUnaffected],
        'v2026.6.11',
      )?.candidate.candidateId,
      laterUnaffected.candidate.candidateId,
    );

    for (const assertion of ['affected', 'not_fixed'] as const) {
      const laterContradiction = closureAuthorityBinding({
        candidateId: '0'.repeat(64),
        issueNumber: 98197,
        createdAt: '2026-07-04T03:00:00Z',
        claim: {
          kind: 'release_local',
          assertion,
          releaseTag: 'v2026.6.11',
        },
      });
      assert.equal(
        scoring.__releaseScoringTest.selectAuthorizedReleaseNotAffectedClaim(
          [laterContradiction, firstUnaffected],
          'v2026.6.11',
        ),
        null,
        assertion,
      );
    }

    const nonActionableRationale = closureAuthorityBinding({
      candidateId: '4'.repeat(64),
      issueNumber: 98197,
      sourceNodeId: 'COMMENT_non_actionable_conflict',
      spanStart: 0,
      claim: {
        kind: 'closure_rationale',
        rationale: 'not_reproducible',
      },
    });
    const ongoingFailure = closureAuthorityBinding({
      candidateId: '5'.repeat(64),
      issueNumber: 98197,
      sourceNodeId: 'COMMENT_non_actionable_conflict',
      spanStart: 50,
      claim: {
        kind: 'field_confirmation',
        confirmation: 'still_failing',
      },
    });
    assert.deepEqual(
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        status: 'not_planned',
        sourceIssueNumber: 98197,
        canonicalIssueNumbers: [],
        claimsByIssue: new Map([[
          98197,
          [ongoingFailure, nonActionableRationale],
        ]]),
      }),
      { required: true, satisfied: false, claims: [] },
    );

    const deniedWithdrawal = closureAuthorityBinding({
      candidateId: 'e'.repeat(64),
      issueNumber: 10,
      authorized: false,
      claim: {
        kind: 'reporter_action',
        action: 'withdrawn',
      },
    });
    assert.deepEqual(
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        status: 'reporter_withdrawn',
        sourceIssueNumber: 10,
        canonicalIssueNumbers: [],
        claimsByIssue: new Map([[10, [deniedWithdrawal]]]),
      }),
      { required: true, satisfied: false, claims: [] },
    );

    const withdrawal = closureAuthorityBinding({
      candidateId: 'f'.repeat(64),
      issueNumber: 10,
      claim: {
        kind: 'reporter_action',
        action: 'requested_closure',
      },
    });
    const withdrawalSelection =
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        status: 'reporter_withdrawn',
        sourceIssueNumber: 10,
        canonicalIssueNumbers: [],
        claimsByIssue: new Map([[10, [withdrawal, deniedWithdrawal]]]),
      });
    assert.equal(withdrawalSelection.required, true);
    assert.equal(withdrawalSelection.satisfied, true);
    assert.deepEqual(
      withdrawalSelection.claims.map((claim) => claim.candidate.candidateId),
      [withdrawal.candidate.candidateId],
    );

    const sourceDuplicate = closureAuthorityBinding({
      candidateId: '1'.repeat(64),
      issueNumber: 20,
      claim: {
        kind: 'duplicate_or_superseded',
        relation: 'duplicate',
        target: {
          resource: 'issue',
          repositoryNameWithOwner: 'openclaw/openclaw',
          number: 21,
        },
      },
    });
    const canonicalRationale = closureAuthorityBinding({
      candidateId: '2'.repeat(64),
      issueNumber: 21,
      claim: {
        kind: 'closure_rationale',
        rationale: 'not_reproducible',
      },
    });
    const incompleteCanonical =
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        status: 'duplicate_to_non_actionable_canonical',
        sourceIssueNumber: 20,
        canonicalIssueNumbers: [21],
        claimsByIssue: new Map([[20, [sourceDuplicate]]]),
      });
    assert.equal(incompleteCanonical.required, true);
    assert.equal(incompleteCanonical.satisfied, false);

    const canonicalSelection =
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        status: 'duplicate_to_non_actionable_canonical',
        sourceIssueNumber: 20,
        canonicalIssueNumbers: [20, 21],
        claimsByIssue: new Map([
          [20, [sourceDuplicate]],
          [21, [canonicalRationale]],
        ]),
      });
    assert.equal(canonicalSelection.required, true);
    assert.equal(canonicalSelection.satisfied, true);
    assert.deepEqual(
      canonicalSelection.claims.map((claim) => claim.candidate.candidateId),
      [
        sourceDuplicate.candidate.candidateId,
        canonicalRationale.candidate.candidateId,
      ],
    );

    assert.deepEqual(
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        status: 'non_bug_neutral',
        sourceIssueNumber: 30,
        canonicalIssueNumbers: [],
        claimsByIssue: new Map(),
      }),
      { required: false, satisfied: true, claims: [] },
    );
  });

  it('binds canonical authority to the proof-producing local terminal', () => {
    const targetlessSource = closureAuthorityBinding({
      candidateId: '1'.repeat(64),
      issueNumber: 10,
      claim: {
        kind: 'duplicate_or_superseded',
        relation: 'duplicate',
        target: null,
      },
    });
    const foreignSource = closureAuthorityBinding({
      candidateId: '2'.repeat(64),
      issueNumber: 10,
      claim: {
        kind: 'duplicate_or_superseded',
        relation: 'duplicate',
        target: {
          resource: 'issue',
          repositoryNameWithOwner: 'other/repo',
          number: 20,
        },
      },
    });
    const localSource = closureAuthorityBinding({
      candidateId: '9'.repeat(64),
      issueNumber: 10,
      claim: {
        kind: 'duplicate_or_superseded',
        relation: 'duplicate',
        target: {
          resource: 'issue',
          repositoryNameWithOwner: 'openclaw/openclaw',
          number: 20,
        },
      },
    });
    const intermediateRationale = closureAuthorityBinding({
      candidateId: '0'.repeat(64),
      issueNumber: 20,
      claim: {
        kind: 'closure_rationale',
        rationale: 'not_reproducible',
      },
    });
    const foreignTerminalRationale = closureAuthorityBinding({
      candidateId: '3'.repeat(64),
      issueNumber: 30,
      repositoryNameWithOwner: 'other/repo',
      claim: {
        kind: 'closure_rationale',
        rationale: 'not_reproducible',
      },
    });
    const localTerminalRationale = closureAuthorityBinding({
      candidateId: '8'.repeat(64),
      issueNumber: 30,
      claim: {
        kind: 'closure_rationale',
        rationale: 'not_reproducible',
      },
    });
    const authorityInput = {
      status: 'duplicate_to_non_actionable_canonical',
      sourceIssueNumber: 10,
      canonicalIssueNumbers: [30, 10, 20],
      evidenceJson: JSON.stringify({
        canonicalResolution: {
          terminalIssue: {
            number: 30,
            url: 'https://github.com/openclaw/openclaw/issues/30',
          },
          terminalProof: {
            status: 'not_planned',
            concreteNonActionableRationale: true,
          },
          blockingBranch: [10, 20, 30],
          branches: [{
            path: [10, 20, 30],
            terminalIssue: {
              number: 30,
              url: 'https://github.com/openclaw/openclaw/issues/30',
            },
            terminalProof: {
              status: 'not_planned',
              concreteNonActionableRationale: true,
            },
          }],
        },
      }),
    };

    assert.deepEqual(
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        ...authorityInput,
        claimsByIssue: new Map([
          [10, [targetlessSource, foreignSource]],
          [20, [intermediateRationale]],
          [30, [localTerminalRationale]],
        ]),
      }),
      { required: true, satisfied: false, claims: [] },
    );

    assert.deepEqual(
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        ...authorityInput,
        claimsByIssue: new Map([
          [10, [localSource]],
          [20, [intermediateRationale]],
          [30, [foreignTerminalRationale]],
        ]),
      }),
      { required: true, satisfied: false, claims: [] },
    );

    const selected =
      scoring.__releaseScoringTest.selectClosureDispositionAuthority({
        ...authorityInput,
        claimsByIssue: new Map([
          [10, [targetlessSource, foreignSource, localSource]],
          [20, [intermediateRationale]],
          [30, [foreignTerminalRationale, localTerminalRationale]],
        ]),
      });
    assert.equal(selected.satisfied, true);
    assert.deepEqual(
      selected.claims.map((claim) => claim.candidate.candidateId),
      [
        localSource.candidate.candidateId,
        localTerminalRationale.candidate.candidateId,
      ],
    );
  });

  it('rejects #87561/#98565/#90378 bot-applied labels and post-cutoff label leakage', () => {
    for (const [number, actor] of [
      [87561, 'ClawSweeper'],
      [98565, 'barnacle'],
      [90378, 'triage-agent[bot]'],
    ] as const) {
      radarDb.upsertIssue({
        number,
        node_id: `I_${number}`,
        state: 'closed',
        title: `v2026.7.4 bot-label case ${number}`,
        body: 'No independent human reproduction.',
        author: 'reporter',
        author_node_id: `U_reporter_${number}`,
        author_type: 'User',
        author_association: 'CONTRIBUTOR',
        html_url: `https://example.test/issues/${number}`,
        created_at: '2026-07-04T00:00:00Z',
        updated_at: '2026-07-04T00:00:00Z',
        closed_at: '2026-07-05T00:00:00Z',
        comments: 0,
        labels: JSON.stringify(['bug', 'P0', 'P1', 'regression']),
        is_bot: 0,
      });
      for (const label of ['P0', 'P1', 'regression']) {
        radarDb.upsertIssueLabelEvent({
          issue_number: number,
          issue_node_id: `I_${number}`,
          event_id: `${number}-${label}`,
          action: 'labeled',
          label_name: label,
          actor_node_id: `B_${number}`,
          actor_login: actor,
          actor_type: 'Bot',
          created_at: '2026-07-04T01:00:00Z',
        });
      }
      const evidence = scoring.issueFieldEvidence(
        radarDb.getIssue(number) as any,
        ['bug', 'P0', 'P1', 'regression'],
        '2026-07-04T12:00:00Z',
      );
      assert.deepEqual(evidence.confirmationReasons, []);
      assert.equal(evidence.humanReporterCount, 1);
    }

    const lateNumber = 99111;
    radarDb.upsertIssue({
      number: lateNumber,
      state: 'closed',
      title: 'v2026.7.4 late human priority',
      body: null,
      author: 'reporter',
      author_association: 'NONE',
      html_url: `https://example.test/issues/${lateNumber}`,
      created_at: '2026-07-04T00:00:00Z',
      updated_at: '2026-07-04T00:00:00Z',
      closed_at: '2026-07-05T00:00:00Z',
      comments: 0,
      labels: JSON.stringify(['P0']),
      is_bot: 0,
    });
    radarDb.upsertIssueLabelEvent({
      issue_number: lateNumber,
      event_id: `${lateNumber}-P0`,
      action: 'labeled',
      label_name: 'P0',
      actor_login: 'human-maintainer',
      created_at: '2026-07-05T00:00:00Z',
    });
    assert.deepEqual(
      scoring.issueFieldEvidence(
        radarDb.getIssue(lateNumber) as any,
        ['P0'],
        '2026-07-04T12:00:00Z',
      ).confirmationReasons,
      [],
    );
  });

  it('filters bot-applied priority labels before severity overrides at the score cutoff', () => {
    const seed = (number: number, actor: string) => {
      radarDb.upsertIssue({
        number,
        state: 'open',
        title: `Regression actor case ${number}`,
        body: null,
        author: 'reporter',
        author_association: 'NONE',
        html_url: `https://example.test/issues/${number}`,
        created_at: '2026-07-04T00:00:00Z',
        updated_at: '2026-07-04T00:00:00Z',
        closed_at: null,
        comments: 0,
        labels: JSON.stringify(['bug', 'regression', 'impact:message-loss']),
        is_bot: 0,
      });
      radarDb.upsertClassification(number, {
        sentiment: 'negative',
        severity: 'medium',
        scope: 'moderate',
        functionality: 'integration',
        affectedUsers: 'some',
        workaroundStatus: 'unknown',
        duplicateCluster: null,
        affectsVersion: null,
        confidence: 0.8,
        rationale: 'baseline',
      }, '2026-07-04T00:30:00Z', scoring.PROMPT_VERSION);
      radarDb.upsertIssueLabelEvent({
        issue_number: number,
        event_id: `${number}-regression`,
        action: 'labeled',
        label_name: 'regression',
        actor_login: actor,
        created_at: '2026-07-04T01:00:00Z',
      });
    };
    seed(99301, 'openclaw-barnacle');
    seed(99302, 'human-maintainer');
    const classificationRow = {
      title: 'Regression actor case',
      sentiment: 'negative',
      severity: 'medium',
      scope: 'moderate',
      functionality: 'integration',
      affected_users: 'some',
      has_workaround: 0,
      workaround_status: 'unknown',
      duplicate_cluster: null,
      affects_version: null,
      confidence: 0.8,
      rationale: 'baseline',
    };

    const botLabels = scoring.__releaseScoringTest.scoringLabelsAtCutoff(
      99301,
      ['bug', 'regression', 'impact:message-loss'],
      '2026-07-04T12:00:00Z',
      () => null,
    );
    assert.deepEqual(botLabels, []);
    assert.equal(
      scoring.classifyIssueRowWithLabels(classificationRow as any, botLabels, {
        labelActors: { regression: 'openclaw-barnacle' },
      }).severity,
      'medium',
    );

    const deniedHumanInfo = scoring.scoringLabelInfoAtCutoff(
      99302,
      ['bug', 'regression', 'impact:message-loss'],
      '2026-07-04T12:00:00Z',
      () => null,
    );
    assert.deepEqual(deniedHumanInfo.labels, []);
    assert.deepEqual(deniedHumanInfo.authorizedScoringLabels, []);
    assert.equal(deniedHumanInfo.labelActors.regression, 'human-maintainer');
    assert.equal(
      scoring.classifyIssueRowWithLabels(
        classificationRow as any,
        deniedHumanInfo.labels,
        deniedHumanInfo,
      ).severity,
      'medium',
    );

    const booleanOnlyInfo = scoring.scoringLabelInfoAtCutoff(
      99302,
      ['bug', 'regression', 'impact:message-loss'],
      '2026-07-04T12:00:00Z',
      (() => true) as any,
    );
    assert.deepEqual(booleanOnlyInfo.labels, []);
    assert.deepEqual(booleanOnlyInfo.authorizedScoringLabels, []);
    assert.deepEqual(booleanOnlyInfo.authorityReferences, {});

    const humanInfo = scoring.scoringLabelInfoAtCutoff(
      99302,
      ['bug', 'regression', 'impact:message-loss'],
      '2026-07-04T12:00:00Z',
      (eventId: string) => eventId === '99302-regression'
        ? {
            subjectKind: 'label_event',
            subjectIdentity: eventId,
            resolutionHash: 'a'.repeat(64),
            evidenceDigest: 'b'.repeat(64),
            authorizedForScoring: true,
          }
        : null,
    );
    assert.deepEqual(
      humanInfo.labels,
      ['regression'],
    );
    assert.deepEqual(humanInfo.authorizedScoringLabels, ['regression']);
    assert.equal(
      scoring.classifyIssueRowWithLabels(
        classificationRow as any,
        humanInfo.labels,
        humanInfo,
      ).severity,
      'high',
    );
  });

  it('fails closed when field evidence lacks a complete cached comment payload', () => {
    const number = 99222;
    radarDb.upsertIssue({
      number,
      state: 'closed',
      title: 'v2026.7.4 missing comments',
      body: null,
      author: 'reporter',
      author_association: 'NONE',
      html_url: `https://example.test/issues/${number}`,
      created_at: '2026-07-04T00:00:00Z',
      updated_at: '2026-07-04T00:00:00Z',
      closed_at: '2026-07-05T00:00:00Z',
      comments: 1,
      labels: '[]',
      is_bot: 0,
    });
    assert.throws(
      () => scoring.issueFieldEvidence(
        radarDb.getIssue(number) as any,
        [],
        '2026-07-04T12:00:00Z',
      ),
      /cached comment payload failed validation/,
    );
  });

  it('keeps later-fixed issues as debt for each older affected release', () => {
    const releaseFixtures = [
      ['v9001.3.0', '2041-01-20T00:00:00Z'],
      ['v9001.2.0', '2041-01-10T00:00:00Z'],
      ['v9001.1.0', '2041-01-01T00:00:00Z'],
      ['v9001.0.0', '2040-12-20T00:00:00Z'],
    ] as const;
    for (const [tag, publishedAt] of releaseFixtures) {
      const tagCommitOid = createHash('sha1')
        .update(`release-scoring-test:${tag}`)
        .digest('hex');
      radarDb.upsertRelease({
        tag,
        node_id: `R_${tag}`,
        catalog_tag_commit_oid: tagCommitOid,
        name: tag,
        published_at: publishedAt,
        html_url: `https://example.test/releases/${tag}`,
        prerelease: false,
        body: '',
      });
      radarDb.upsertReleaseCommit({
        tag,
        tag_commit_oid: tagCommitOid,
        committed_at: publishedAt,
      });
    }
    radarDb.replaceActiveReleaseCatalog(
      releaseFixtures.map(([tag]) => {
        const release = radarDb.getRelease(tag)!;
        return {
          node_id: release.node_id!,
          catalog_tag_commit_oid: release.catalog_tag_commit_oid!,
          tag: release.tag,
          name: release.name,
          published_at: release.published_at!,
          created_at: release.created_at!,
          updated_at: release.updated_at!,
          html_url: release.html_url,
          prerelease: release.prerelease === 1,
          body: release.body,
        };
      }),
      { capture: { source: 'test_fixture' } },
    );
    radarDb.upsertIssue({
      number: 99001,
      node_id: 'I_99001',
      state: 'closed',
      title: 'P0 state loss affects v9001.1.0 and v9001.2.0',
      author: 'reporter',
      author_node_id: 'U_reporter-99001',
      author_type: 'User',
      author_association: 'NONE',
      html_url: 'https://example.test/issues/99001',
      created_at: '2041-01-02T00:00:00Z',
      updated_at: '2041-01-21T00:00:00Z',
      closed_at: '2041-01-21T00:00:00Z',
      comments: 2,
      unique_human_commenters: 1,
      maintainer_commenters: 0,
      contributor_commenters: 0,
      commenter_scan_truncated: 0,
      reaction_total: 0,
      positive_reactions: 0,
      labels: JSON.stringify(['P0', 'bug']),
      is_bot: 0,
    });
    const issueComments = [
      authoritativeComment(
        9900101,
        'reporter',
        'Initial diagnostics.',
        {
          url: 'https://example.test/issues/99001#issuecomment-9900101',
          user: { id: 'U_reporter-99001' },
          author_association: 'NONE',
          created_at: '2041-01-02T00:30:00Z',
          updated_at: '2041-01-02T00:30:00Z',
        },
      ),
      authoritativeComment(
        9900102,
        'second-reporter',
        'Can confirm, I reproduced the same issue.',
        {
          url: 'https://example.test/issues/99001#issuecomment-9900102',
          author_association: 'CONTRIBUTOR',
          created_at: '2041-01-02T01:00:00Z',
          updated_at: '2041-01-02T01:00:00Z',
        },
      ),
    ];
    const issueCommentsDigest = commentEvidenceDigest(issueComments.length, issueComments);
    radarDb.upsertIssueCommentSnapshot(authoritativeCommentSnapshot({
      issueNumber: 99001,
      issueNodeId: 'I_99001',
      issueAuthorNodeId: 'U_reporter-99001',
      issueAuthorLogin: 'reporter',
      issueUpdatedAt: '2041-01-21T00:00:00Z',
      comments: issueComments,
    }));
    radarDb.upsertClassification(99001, {
      sentiment: 'negative',
      severity: 'critical',
      scope: 'broad',
      functionality: 'core',
      affectedUsers: 'many',
      workaroundStatus: 'none',
      duplicateCluster: null,
      affectsVersion: 'v9001.3.0',
      confidence: 0.99,
      rationale: 'classifier points at the fix release and must not control historical debt',
    }, '2041-01-21T00:00:00Z', scoring.PROMPT_VERSION);
    radarDb.upsertIssueLabelSnapshot({
      issue_number: 99001,
      snapshot_at: '2041-01-02T01:00:00Z',
      labels_json: JSON.stringify(['P0', 'bug']),
    });
    radarDb.upsertIssueLabelEvent({
      issue_number: 99001,
      event_id: 'label-p0-99001',
      action: 'labeled',
      label_name: 'P0',
      actor_login: 'human-maintainer',
      created_at: '2041-01-02T00:15:00Z',
    });
    radarDb.upsertIssueClosureEvent({
      issue_number: 99001,
      event_id: 'closed-99001',
      closed_at: '2041-01-21T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    radarDb.upsertIssueClosureProof({
      release_tag: 'v9001.3.0',
      issue_number: 99001,
      status: 'fixed_in_release',
      summary: 'Fix is reachable from v9001.3.0.',
      evidence_json: JSON.stringify({ releaseTag: 'v9001.3.0' }),
    });

    const run = scoring.buildReleaseScoreRun({
      releases: ['v9001.1.0', 'v9001.2.0', 'v9001.3.0']
        .map((tag) => radarDb.getRelease(tag)),
      allFetchedTags: ['v9001.3.0', 'v9001.2.0', 'v9001.1.0'],
      stableTagsNewestFirst: ['v9001.3.0', 'v9001.2.0', 'v9001.1.0', 'v9001.0.0'],
      oldestScoredStablePredecessorTag: 'v9001.0.0',
      nowForRelease: () => Date.parse('2041-01-22T00:00:00Z'),
    } as any);
    const byTag = new Map(run.scored.map((result) => [result.rel.tag, result]));

    for (const tag of ['v9001.1.0', 'v9001.2.0']) {
      const result = byTag.get(tag)!;
      assert.ok(result.input.verifiedDebtWeight > 0, `${tag} should retain historical debt`);
      const debt = (result.debtEvidence.verifiedDebt as any[])
        .find((item) => item.issue?.number === 99001);
      assert.ok(debt);
      assert.equal(debt.issue.state, 'closed');
      assert.equal(debt.releaseScopedState, 'open');
      assert.deepEqual(debt.releaseLocalEvidence, {
        kind: 'exact-version',
        source: 'title',
        version: tag,
        snippet: 'P0 state loss affects v9001.1.0 and v9001.2.0',
      });
    }
    assert.equal(byTag.get('v9001.3.0')?.input.verifiedDebtWeight, 0);
    assert.ok((byTag.get('v9001.3.0')?.debtEvidence.verifiedFixed as any[])
      .some((issue) => issue.number === 99001));
  });

  it('uses nested issue state for opened-report explanation counts', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      debtEvidence: {
        openedFeltSerious: [
          {
            state: 'closed',
            issue: { number: 1, title: 'still open', state: 'open', url: 'https://example.test/1' },
          },
          {
            state: 'open',
            issue: { number: 2, title: 'already closed', state: 'closed', url: 'https://example.test/2' },
          },
        ],
      },
    }), false);
    const opened = explanation.limitDetails.find((detail: any) =>
      detail.code === 'field_visible_reports_opened',
    );
    assert.equal(opened?.metrics?.openedCount, 2);
    assert.equal(opened?.metrics?.stillOpenCount, 1);
    assert.deepEqual(opened?.issueRefs?.map((issue: any) => issue.number), [1]);
  });

  it('uses each active install gate as the limiting reason instead of model ceiling', () => {
    const cases = [
      {
        status: 'skip-cve',
        score: 3.2,
        reason: 'known medium-or-higher security advisory exposure',
        code: 'cve_install_gate',
        input: { cveAffected: true, cveLoad: 4 },
        verdict: /security advisory install gate/,
      },
      {
        status: 'wait',
        score: null,
        reason: 'only 0.5d old - no settle signal yet',
        code: 'settle_time_gate',
        verdict: /settle-time gate/,
      },
      {
        status: 'skip-hotfix',
        score: 4.9,
        reason: 'maintainers shipped a hotfix patch on top of it',
        code: 'hotfix_successor_gate',
        input: { hasHotfixSuccessor: true, hoursToNextStable: 8 },
        verdict: /hotfix successor gate/,
      },
    ];
    for (const item of cases) {
      const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult(item), false);
      assert.ok(explanation.limitDetails.some((detail: any) => detail.code === item.code));
      assert.ok(!explanation.limitDetails.some((detail: any) =>
        detail.code === 'model_ceiling_and_capped_confidence'));
      assert.match(explanation.verdict, item.verdict);
      assert.match(explanation.verdict, new RegExp(item.reason.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    }
  });

  it('binds waiting release findings to suppressed evidence components', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(
      explanationResult({
        status: 'wait',
        score: null,
        input: {
          publishedAt: '2026-06-09T20:00:00Z',
          releaseCheckState: 'SUCCESS',
          releaseCheckTotal: 2,
          releaseCheckSuccess: 2,
          artifactVerified: true,
          ciReportVerified: true,
          releaseIntegrityPresent: true,
          releaseShaMatches: true,
        },
        gateEvidence: {
          releaseChecks: {
            state: 'SUCCESS',
            total: 2,
            success: 2,
            failure: 0,
            pending: 0,
          },
          artifactVerification: {
            verified: true,
            releaseShaMatches: true,
            ciReportVerified: true,
            releaseValidationVerified: true,
          },
        },
      }),
      false,
    );
    assert.ok(explanation.limitDetails.some((detail: any) =>
      detail.code === 'settle_time_gate'));
    assert.ok(explanation.positiveDetails.some((detail: any) =>
      detail.code === 'release_checks_passed'));
    assert.ok(explanation.positiveDetails.some((detail: any) =>
      detail.code === 'artifact_verified'));
    for (const code of ['releaseVerification', 'artifactVerification']) {
      const operation = explanation.scoreLedger.operations.find(
        (item: any) => item.code === code,
      );
      assert.ok(operation);
      assert.equal(operation.applied, false);
      assert.equal(operation.before, null);
      assert.equal(operation.after, null);
      assert.equal(
        operation.operands.find((operand: any) =>
          operand.name === 'suppressedByStatus')?.value,
        'wait',
      );
    }
    assert.deepEqual(
      scoreExplanationAuditProblems(explanation, explanation.scoreLedger),
      [],
    );
    const releaseChecksAudit = explanation.scoreLedger.explanationAudit.details
      .find((detail: any) => detail.code === 'release_checks_passed');
    const artifactAudit = explanation.scoreLedger.explanationAudit.details
      .find((detail: any) => detail.code === 'artifact_verified');
    assert.deepEqual(
      releaseChecksAudit.operations.map((operation: any) => operation.code),
      ['releaseVerification'],
    );
    assert.deepEqual(
      artifactAudit.operations.map((operation: any) => operation.code),
      ['artifactVerification'],
    );
  });

  it('aligns release-check explanation predicates with scored check states', () => {
    const failed = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      gateEvidence: {
        releaseChecks: { state: 'FAILURE', total: 2, success: 2, failure: 0, pending: 0 },
      },
    }), false);
    assert.ok(failed.limitDetails.some((detail: any) => detail.code === 'release_checks_failed'));
    assert.ok(!failed.positiveDetails.some((detail: any) => detail.code === 'release_checks_passed'));

    const pending = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      gateEvidence: {
        releaseChecks: { state: 'PENDING', total: 2, success: 2, failure: 0, pending: 0 },
      },
    }), false);
    assert.ok(pending.limitDetails.some((detail: any) => detail.code === 'release_checks_pending'));
    assert.ok(!pending.positiveDetails.some((detail: any) => detail.code === 'release_checks_passed'));

    const expected = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      gateEvidence: {
        releaseChecks: { state: 'EXPECTED', total: 2, success: 0, failure: 0, pending: 0 },
      },
    }), false);
    assert.ok(expected.limitDetails.some((detail: any) => detail.code === 'release_checks_pending'));
    assert.ok(!expected.limitDetails.some((detail: any) => detail.code === 'release_checks_failed'));

    const inconsistent = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      gateEvidence: {
        releaseChecks: { state: 'SUCCESS', total: 2, success: 2, failure: 1, pending: 0 },
      },
    }), false);
    assert.ok(inconsistent.limitDetails.some((detail: any) => detail.code === 'release_checks_failed'));
    assert.ok(!inconsistent.positiveDetails.some((detail: any) => detail.code === 'release_checks_passed'));

    const passed = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      gateEvidence: {
        releaseChecks: { state: 'SUCCESS', total: 3, success: 2, failure: 0, pending: 0, skipped: 1 },
      },
    }), false);
    const passedDetail = passed.positiveDetails.find((detail: any) => detail.code === 'release_checks_passed');
    assert.equal(passedDetail?.text, '2 of 3 release checks passed; none failed or are pending, and 1 was skipped.');
    assert.equal(passedDetail?.metrics?.skipped, 1);
    assert.ok(!passed.limitDetails.some((detail: any) =>
      ['release_checks_failed', 'release_checks_pending'].includes(detail.code)));
  });

  it('retains adverse release-check contexts ahead of successful rows at the cap', () => {
    const successful = Array.from({ length: 30 }, (_, index) => ({
      type: 'CheckRun',
      name: `successful-${String(index).padStart(2, '0')}`,
      workflowName: 'CI',
      status: 'COMPLETED',
      conclusion: 'SUCCESS',
      url: `https://example.test/checks/success-${index}`,
    }));
    const input = [
      ...successful,
      {
        type: 'CheckRun',
        name: 'pending-z',
        workflowName: 'CI',
        status: 'IN_PROGRESS',
        conclusion: null,
        url: 'https://example.test/checks/pending-z',
      },
      {
        type: 'StatusContext',
        name: 'failure-z',
        workflowName: null,
        status: null,
        conclusion: 'FAILURE',
        url: 'https://example.test/checks/failure-z',
      },
      {
        type: 'CheckRun',
        name: 'error-a',
        workflowName: 'CI',
        status: 'COMPLETED',
        conclusion: 'ERROR',
        url: 'https://example.test/checks/error-a',
      },
      {
        type: 'CheckRun',
        name: 'action-required-a',
        workflowName: 'CI',
        status: 'COMPLETED',
        conclusion: 'ACTION_REQUIRED',
        url: 'https://example.test/checks/action-required-a',
      },
    ];
    const aggregate = {
      state: 'FAILURE',
      failure: 3,
      pending: 1,
    };
    const contexts = scoring.__releaseScoringTest.releaseCheckContextsForEvidence(
      input,
      aggregate,
    ) as Array<Record<string, unknown>>;
    const reversed = scoring.__releaseScoringTest.releaseCheckContextsForEvidence(
      input.slice().reverse(),
      aggregate,
    ) as Array<Record<string, unknown>>;

    assert.equal(contexts.length, 25);
    assert.deepEqual(
      contexts.slice(0, 4).map((context) => context.name),
      ['failure-z', 'error-a', 'action-required-a', 'pending-z'],
    );
    assert.ok(contexts.slice(4).every((context) => context.conclusion === 'SUCCESS'));
    assert.deepEqual(reversed, contexts);
  });

  it('does not retain successful-only links for an adverse aggregate check state', () => {
    const successful = {
      type: 'CheckRun',
      name: 'build',
      workflowName: 'CI',
      status: 'COMPLETED',
      conclusion: 'SUCCESS',
      url: 'https://example.test/checks/build',
    };
    assert.deepEqual(
      scoring.__releaseScoringTest.releaseCheckContextsForEvidence([successful], {
        state: 'FAILURE',
        failure: 1,
        pending: 0,
      }),
      [],
    );

    const retained = scoring.__releaseScoringTest.releaseCheckContextsForEvidence([
      successful,
      {
        type: 'CheckRun',
        name: 'pending-without-link',
        workflowName: 'CI',
        status: 'QUEUED',
        conclusion: null,
        url: null,
      },
    ], {
      state: 'PENDING',
      failure: 0,
      pending: 1,
    }) as Array<Record<string, unknown>>;
    assert.deepEqual(retained.map((context) => context.name), ['pending-without-link']);
  });

  it('describes artifact evidence without claiming the tarball was built from the release SHA', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      components: { artifactVerification: 0.1 },
      gateEvidence: {
        artifactVerification: {
          receiptId: `artifact-receipt-v2:${'a'.repeat(64)}`,
          verified: true,
          releaseShaMatches: true,
          ciReportVerified: false,
          releaseValidationVerified: false,
          ciReportMismatch: 'evidence report missing',
          artifact: {
            state: 'release_bound',
            registryState: 'registry_verified',
            releaseBindingState: 'release_bound',
            registryAvailability: 'available',
            registryVerified: true,
            releaseBound: true,
            tarballByteCount: 123,
            mismatch: null,
            reason: null,
          },
        },
      },
    }), false);
    const positive = explanation.positiveDetails.find((detail: any) => detail.code === 'artifact_verified');
    const limit = explanation.limitDetails.find((detail: any) => detail.code === 'missing_full_release_evidence_report');
    assert.match(positive?.text ?? '', /downloaded npm tarball bytes match the registry SRI digest/i);
    assert.match(positive?.text ?? '', /release binding matches the release tag commit/i);
    assert.doesNotMatch(positive?.text ?? '', /package .* release SHA match|built from/i);
    assert.match(limit?.text ?? '', /full release evidence report is not verified/i);
    assert.match(limit?.text ?? '', /tarball byte and release-binding checks passed separately/i);
    assert.ok(!explanation.limitDetails.some((detail: any) =>
      detail.code === 'artifact_verification_incomplete'));
  });

  it('explains each incomplete artifact state without inventing verification', () => {
    const cases = [
      {
        name: 'missing observation',
        artifactVerification: {},
        pattern: /No immutable artifact observation is bound/i,
      },
      {
        name: 'registry mismatch',
        artifactVerification: {
          receiptId: `artifact-receipt-v2:${'a'.repeat(64)}`,
          releaseShaMatches: true,
          verified: false,
          artifact: {
            state: 'mismatch',
            registryState: 'mismatch',
            releaseBindingState: 'mismatch',
            registryAvailability: 'available',
            registryVerified: false,
            releaseBound: false,
            tarballByteCount: 123,
            mismatch: 'registry tarball integrity mismatch',
            reason: 'registry tarball integrity mismatch',
          },
        },
        pattern: /registry tarball integrity mismatch/i,
      },
      {
        name: 'release binding unknown',
        artifactVerification: {
          receiptId: `artifact-receipt-v2:${'a'.repeat(64)}`,
          releaseShaMatches: true,
          verified: false,
          artifact: {
            state: 'registry_verified',
            registryState: 'registry_verified',
            releaseBindingState: 'unknown',
            registryAvailability: 'available',
            registryVerified: true,
            releaseBound: false,
            tarballByteCount: 123,
            mismatch: null,
            reason: 'release SHA missing',
          },
        },
        pattern: /not fully bound.*release SHA missing/i,
      },
      {
        name: 'current tag mismatch',
        artifactVerification: {
          receiptId: `artifact-receipt-v2:${'a'.repeat(64)}`,
          releaseShaMatches: false,
          verified: true,
          artifact: {
            state: 'release_bound',
            registryState: 'registry_verified',
            releaseBindingState: 'release_bound',
            registryAvailability: 'available',
            registryVerified: true,
            releaseBound: true,
            tarballByteCount: 123,
            mismatch: null,
            reason: null,
          },
        },
        pattern: /same commit currently being scored/i,
      },
    ];
    for (const item of cases) {
      const explanation = scoring.__releaseScoringTest.buildScoreExplanation(
        explanationResult({
          gateEvidence: {
            artifactVerification: item.artifactVerification,
          },
        }),
        false,
      );
      const detail = explanation.limitDetails.find((candidate: any) =>
        candidate.code === 'artifact_verification_incomplete');
      assert.match(detail?.text ?? '', item.pattern, item.name);
      const auditDetail = explanation.scoreLedger.explanationAudit.details.find(
        (candidate: any) =>
          candidate.code === 'artifact_verification_incomplete',
      );
      assert.deepEqual(
        auditDetail?.operations?.map((operation: any) => operation.code),
        ['artifactVerification'],
      );
    }
  });

  it('records final score rounding as an ordered operation and explanation context', () => {
    const input = {
      ...explanationResult().input,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 1,
      releaseCheckSuccess: 1,
    };
    const now = Date.parse('2026-06-10T00:00:00Z');
    const confidence = installConfidence(input, now);
    const ledger = scoring.__releaseScoringTest.buildScoreLedgerV2({
      input,
      confidence,
      now,
    });
    const rounding = ledger.operations.find((operation: any) => operation.code === 'finalRound');
    assert.equal(rounding?.formulaCode, 'score.round_1_decimal.v1');
    assert.notEqual(rounding?.before, rounding?.after);
    assert.equal(rounding?.after, confidence.score);

    const result = explanationResult({ input });
    result.scoreLedger = ledger;
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(result, false);
    const roundingDetail = explanation.limitDetails.find((detail: any) =>
      detail.code === 'score_rounding');
    const componentSubtotal = Math.round(Number(rounding?.before) * 1000) / 1000;
    assert.ok(roundingDetail);
    assert.equal(roundingDetail.metrics?.scoreAffecting, false);
    assert.equal(roundingDetail.metrics?.operationCode, 'finalRound');
    assert.equal(roundingDetail.metrics?.operationSequence, rounding?.sequence);
    assert.equal(roundingDetail.metrics?.formulaCode, 'score.round_1_decimal.v1');
    assert.equal(roundingDetail.metrics?.componentSubtotal, componentSubtotal);
    assert.equal(roundingDetail.metrics?.finalScore, confidence.score);
    assert.equal(roundingDetail.metrics?.sourcePrecisionDecimals, 3);
    assert.equal(roundingDetail.metrics?.finalPrecisionDecimals, 1);
    assert.equal(roundingDetail.metrics?.roundingChangedScore, true);
    assert.match(
      roundingDetail.text,
      /Rounds the three-decimal component subtotal to the one-decimal final score/,
    );
    assert.ok(roundingDetail.text.includes(
      `${componentSubtotal.toFixed(3)} to ${Number(confidence.score).toFixed(1)}`,
    ));
    assert.ok(explanation.limits.includes(roundingDetail.text));
  });

  it('does not list zero-penalty audit-only closure flags as score limits', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      components: { closureRisk: -0.1, closureRiskCeiling: 0 },
      input: {
        unresolvedClosureIssueCount: 1,
        unresolvedClosureRiskWeight: 1,
      },
      gateEvidence: {
        fixProvenance: {
          closureProof: {
            creditedCount: 0,
            notCreditedCount: 2,
            analyzedClosedCount: 2,
            byStatus: { closed_without_release_fix_proof: 1, non_bug_neutral: 1 },
            byRiskDisposition: { missing_evidence: 1, neutral_or_non_actionable: 1 },
            riskSummary: {
              unresolvedForReleaseCount: 1,
              knownNotInReleaseCount: 0,
              openCanonicalRiskCount: 0,
              unsupportedClosureClaimCount: 0,
              missingEvidenceCount: 1,
              neutralOrNonActionableCount: 1,
              neutralHighImpactCount: 0,
              neutralBugShapedCount: 1,
            },
            examples: [{
              number: 1,
              title: 'missing proof',
              status: 'closed_without_release_fix_proof',
              riskDisposition: 'missing_evidence',
              riskWeight: 1,
              evidence: {},
            }],
            neutralAuditExamples: [{
              number: 2,
              title: 'not actionable',
              status: 'non_bug_neutral',
              riskDisposition: 'neutral_or_non_actionable',
              riskWeight: 0,
              evidence: {},
            }],
          },
        },
      },
    }), false);
    assert.ok(explanation.limitDetails.some((detail) =>
      detail.code === 'closed_issues_not_counted_as_release_fixes'));
    assert.ok(!explanation.limitDetails.some((detail) =>
      detail.code === 'audit_only_closed_issue_flags'));
  });

  it('uses exact score-10 wording without claiming a remaining gap', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      score: 10,
      components: {},
    }), true);
    assert.ok(explanation.limitDetails.some((detail: any) => detail.code === 'no_remaining_score_gap'));
    assert.ok(!explanation.limitDetails.some((detail: any) =>
      detail.code === 'model_ceiling_and_capped_confidence'));
    assert.match(explanation.verdict, /exactly 10\.0/);
    assert.doesNotMatch(explanation.verdict, /below 10|remaining gap/i);
  });

  it('emits complete canonical summaries for every recommendation decision code', () => {
    const withinTolerance = [
      { rel: { tag: 'v-new', published_at: '2026-07-04T04:00:00Z' }, conf: { status: 'eligible', score: 7.3 } },
      { rel: { tag: 'v-high', published_at: '2026-07-04T03:00:00Z' }, conf: { status: 'eligible', score: 7.7 } },
      { rel: { tag: 'v-low', published_at: '2026-07-04T02:00:00Z' }, conf: { status: 'eligible', score: 6.9 } },
      { rel: { tag: 'v-gated', published_at: '2026-07-04T01:00:00Z' }, conf: { status: 'skip-cve', score: 4.0 } },
    ] as any;
    const firstSelection = selectRecommendation(withinTolerance.map((item: any) => ({
      tag: item.rel.tag,
      publishedAt: item.rel.published_at,
      status: item.conf.status,
      score: item.conf.score,
    })));
    const first = scoring.__releaseScoringTest.recommendationDecisionsForRun(
      withinTolerance,
      firstSelection,
    );
    assert.equal(first.get('v-new')?.decisionCode, 'newest_within_confidence_tolerance');
    assert.equal(first.get('v-high')?.decisionCode, 'newer_release_within_tolerance_selected');
    assert.equal(first.get('v-low')?.decisionCode, 'below_recommendation_threshold');
    assert.equal(first.get('v-gated')?.decisionCode, 'install_gate_active');

    const higherConfidence = [
      { rel: { tag: 'v-newer', published_at: '2026-07-04T03:00:00Z' }, conf: { status: 'eligible', score: 7.0 } },
      { rel: { tag: 'v-highest', published_at: '2026-07-04T02:00:00Z' }, conf: { status: 'eligible', score: 8.0 } },
      { rel: { tag: 'v-older', published_at: '2026-07-04T01:00:00Z' }, conf: { status: 'eligible', score: 7.5 } },
    ] as any;
    const secondSelection = selectRecommendation(higherConfidence.map((item: any) => ({
      tag: item.rel.tag,
      publishedAt: item.rel.published_at,
      status: item.conf.status,
      score: item.conf.score,
    })));
    const second = scoring.__releaseScoringTest.recommendationDecisionsForRun(
      higherConfidence,
      secondSelection,
    );
    assert.equal(second.get('v-highest')?.decisionCode, 'highest_confidence');
    assert.equal(second.get('v-newer')?.decisionCode, 'higher_confidence_release_selected');
    const highestHumanSummary = scoring.__releaseScoringTest.humanRecommendationDecisionSummary(
      second.get('v-highest')!,
    );
    assert.match(highestHumanSummary, /highest audited score/);
    assert.match(highestHumanSummary, /newest release wins when scores are equal/);

    const decisions = [...first.values(), ...second.values()];
    const codes = new Set(decisions.map((decision: any) => decision.decisionCode));
    assert.deepEqual(codes, new Set([
      'highest_confidence',
      'newest_within_confidence_tolerance',
      'higher_confidence_release_selected',
      'newer_release_within_tolerance_selected',
      'below_recommendation_threshold',
      'install_gate_active',
    ]));
    for (const decision of decisions) {
      assert.match(decision.summary, new RegExp(`Decision ${decision.decisionCode}:`));
      assert.match(decision.summary, new RegExp(`release ${decision.releaseTag.replace('-', '\\-')} \\(`));
      assert.match(decision.summary, /selected .+ \(score (?:n\/a|[0-9.]+)\)/);
      assert.match(decision.summary, /highest-scoring qualifying release .+ \(score (?:n\/a|[0-9.]+)\)/);
      assert.match(decision.summary, /threshold 7\.0; recency tolerance 0\.5\./);
      assert.equal(decision.summary, scoring.__releaseScoringTest.recommendationDecisionSummary(decision));
    }
  });

  it('includes machine-readable detail entries beside prose', () => {
    const issue = (number: number, title: string, state = 'open') => ({
      number,
      title,
      state,
      url: `https://example.test/issues/${number}`,
      rawClassification: { severity: 'high' },
      classification: { severity: 'high' },
      classificationDiff: {},
    });
    const carryoverDebt = [1, 2, 3].map((number) => ({
      tier: 'carryover',
      weight: 2,
      fieldConfirmed: false,
      clusterReleaseLocal: number === 1,
      installImpactClass: 'provider',
      installImpactMultiplier: 0.8,
      issue: issue(100 + number, `carryover ${number}`),
    }));
    const staleDebt = [{
      tier: 'stale',
      weight: 1,
      fieldConfirmed: false,
      clusterReleaseLocal: true,
      installImpactClass: 'general',
      installImpactMultiplier: 1,
      issue: issue(201, 'stale evidence'),
    }];
    const closureFixtureExamples = [
      {
        number: 301,
        title: 'canonical remains open',
        status: 'duplicate_to_open_canonical',
        statusLabel: 'Duplicate to open canonical',
        riskDisposition: 'open_canonical_risk',
        riskDispositionLabel: 'Open canonical risk',
        riskWeight: 5,
        evidence: {
          canonicalResolution: {
            path: [301, 401],
            terminalIssue: { number: 401, title: 'canonical issue', state: 'open' },
          },
        },
      },
      {
        number: 302,
        title: 'fix is after release',
        status: 'fixed_after_release',
        statusLabel: 'Fixed after release',
        riskDisposition: 'known_not_in_release',
        riskDispositionLabel: 'Known not in release',
        riskWeight: 4,
        evidence: {
          relatedPrContext: {
            notReachable: [{ number: 9002, title: 'later fix PR', state: 'MERGED' }],
          },
        },
      },
      {
        number: 303,
        title: 'missing closure evidence',
        status: 'closed_without_release_fix_proof',
        statusLabel: 'Closed without release fix proof',
        riskDisposition: 'missing_evidence',
        riskDispositionLabel: 'Missing evidence',
        riskWeight: 3,
        evidence: {
          relatedPrContext: {
            open: [{ number: 9003, title: 'open fix PR', state: 'OPEN' }],
          },
        },
      },
    ];
    const synthetic = explanationResult({
      score: 6.5,
      reason: '3 inherited/carryover issue groups; 3 unresolved closed-release risk groups',
      components: {
        verifiedDebt: 0,
        carryoverDebt: -0.12,
        staleDebt: -0.1,
        closureRisk: -0.3,
        coverage: 0,
        survival: 0.5,
        shakeout: 0,
        regression: -0.2,
        breaking: 0,
        releaseVerification: 0,
        artifactVerification: 0,
        closureRiskCeiling: 0,
      },
      input: {
        feltOpenedWeight: 3,
        carryoverDebtWeight: 6,
        carryoverDebtIssueCount: 3,
        staleDebtWeight: 1,
        staleDebtIssueCount: 1,
        unresolvedClosureIssueCount: 3,
        unresolvedClosureRiskWeight: 12,
        affirmativeClosureRiskCeilingWeight: 12,
      },
      debtEvidence: {
        schemaVersion: scoring.ISSUE_EVIDENCE_SCHEMA_VERSION,
        debtSummary: {
          carryover: { count: 3, weight: 6, storedWeight: 6, byInstallImpactClass: { provider: 3 } },
          stale: { count: 1, weight: 1, storedWeight: 1, byInstallImpactClass: { general: 1 } },
        },
        carryoverDebt,
        staleDebt,
        openedFeltSerious: [
          { fieldConfirmed: true, issue: issue(1, 'open regression') },
          { fieldConfirmed: true, issue: issue(2, 'closed regression', 'closed') },
          { fieldConfirmed: true, issue: issue(3, 'another closed regression', 'closed') },
        ],
      },
      gateEvidence: {
        schemaVersion: scoring.GATE_EVIDENCE_SCHEMA_VERSION,
        labelTimeline: {
          schemaVersion: scoring.LABEL_TIMELINE_SCHEMA_VERSION,
          issueCount: 7,
          historicalCurrentLabelFallbackAllowed: false,
        },
        artifactVerification: { schemaVersion: scoring.ARTIFACT_VERIFICATION_SCHEMA_VERSION },
        fixProvenance: {
          closureProof: {
            creditedCount: 0,
            notCreditedCount: 3,
            analyzedClosedCount: 3,
            byStatus: {
              duplicate_to_open_canonical: 1,
              fixed_after_release: 1,
              closed_without_release_fix_proof: 1,
            },
            byRiskDisposition: {
              open_canonical_risk: 1,
              known_not_in_release: 1,
              missing_evidence: 1,
            },
            riskSummary: {
              unresolvedForReleaseCount: 3,
              unresolvedWeightedRisk: 12,
              resolvedByCanonicalReleaseFixCount: 0,
              resolvedByReleaseFixProofCount: 0,
              knownNotInReleaseCount: 1,
              openCanonicalRiskCount: 1,
              unsupportedClosureClaimCount: 0,
              neutralOrNonActionableCount: 0,
              neutralHighImpactCount: 0,
              neutralBugShapedCount: 0,
              missingEvidenceCount: 1,
            },
            examples: closureFixtureExamples,
            examplesByStatus: {
              duplicate_to_open_canonical: [closureFixtureExamples[0]],
              fixed_after_release: [closureFixtureExamples[1]],
              closed_without_release_fix_proof: [closureFixtureExamples[2]],
            },
          },
        },
      },
    });
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(synthetic, false);
    const labelTimeline = synthetic.gateEvidence.labelTimeline as any;
    const evidence = synthetic.debtEvidence as any;
    const run = {
      scored: [{
        input: { ...synthetic.input, schemaVersion: scoring.SCORE_INPUT_SCHEMA_VERSION },
        conf: synthetic.conf,
        explanation,
        gateEvidence: synthetic.gateEvidence,
        debtEvidence: {
          ...evidence,
          schemaVersion: scoring.ISSUE_EVIDENCE_SCHEMA_VERSION,
        },
      }],
    };

    assert.equal(run.scored[0].input.schemaVersion, scoring.SCORE_INPUT_SCHEMA_VERSION);
    assert.equal((run.scored[0].conf as any).components != null, true);
    assert.equal(explanation.schemaVersion, scoring.SCORE_EXPLANATION_SCHEMA_VERSION);
    assert.equal(scoring.SCORE_COMPONENTS_SCHEMA_VERSION, 1);
    assert.equal(evidence.schemaVersion, scoring.ISSUE_EVIDENCE_SCHEMA_VERSION);
    assert.equal(run.scored[0].gateEvidence.schemaVersion, scoring.GATE_EVIDENCE_SCHEMA_VERSION);
    assert.equal(explanation.limits.length, explanation.limitDetails.length);
    assert.equal(explanation.positives.length, explanation.positiveDetails.length);
    assert.ok(explanation.limitDetails.every((detail, idx) => detail.text === explanation.limits[idx]));
    assert.ok(explanation.positiveDetails.every((detail, idx) => detail.text === explanation.positives[idx]));
    assert.ok(explanation.limitDetails.every((detail) => scoring.SCORE_EXPLANATION_LIMIT_CODES.includes(detail.code as any)));
    assert.ok(explanation.positiveDetails.every((detail) => scoring.SCORE_EXPLANATION_POSITIVE_CODES.includes(detail.code as any)));
    const detailLabels = scoring.SCORE_EXPLANATION_DETAIL_LABELS as Record<string, string>;
    assert.ok(explanation.limitDetails.every((detail) => detail.label === detailLabels[detail.code]));
    assert.ok(explanation.positiveDetails.every((detail) => detail.label === detailLabels[detail.code]));
    assert.equal(explanation.scoreLedger?.schemaVersion, 2);
    const replayedConfidence = installConfidence(synthetic.input, Date.parse(synthetic.scoredAt));
    assert.equal(explanation.scoreLedger?.finalScore, replayedConfidence.score);
    assert.equal(explanation.scoreLedger?.status, replayedConfidence.status);
    assert.equal(explanation.scoreLedger?.ledgerType, 'ScoreLedgerV2');
    assert.ok((explanation.scoreLedger?.operations.length ?? 0) >= 10);
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
    assert.equal(typeof closure.metrics?.scoredUnresolvedRiskGroupCount, 'number');
    assert.equal(typeof closure.metrics?.scoredUnresolvedRiskWeight, 'number');
    assert.equal(closure.metrics?.affirmativeClosureRiskCeilingWeight, 12);
    assert.equal(typeof closure.metrics?.rawUnresolvedRiskGroupCount, 'number');
    assert.equal(typeof closure.metrics?.rawNotCountedClosedIssueCount, 'number');
    assert.equal(typeof closure.metrics?.rawAnalyzedClosedIssueCount, 'number');
    assert.equal(typeof closure.metrics?.cappedPenalty, 'number');
    if (closure.metrics?.scoreCeiling != null) {
      assert.equal(typeof closure.metrics?.scoreCeiling, 'number');
      assert.equal(typeof closure.metrics?.noticeableClosureRiskThreshold, 'number');
      assert.equal(typeof closure.metrics?.heavyClosureRiskThreshold, 'number');
    }
    assert.equal(typeof closure.metrics?.neutralOrNonActionableCount, 'number');
    assert.equal(typeof closure.metrics?.neutralHighImpactCount, 'number');
    assert.equal(typeof closure.metrics?.neutralBugShapedCount, 'number');
    assert.ok(Object.keys(closure.buckets ?? {}).length > 0);
    assert.ok(Object.keys(closure.riskBuckets ?? {}).length > 0);
    assert.equal(closure.riskBuckets?.neutral_or_non_actionable, undefined);
    const closureProof = (run.scored[0].gateEvidence as any).fixProvenance?.closureProof ?? {};
    const unresolvedClosureCount = Number(closure.metrics?.scoredUnresolvedRiskGroupCount ?? 0);
    assert.ok(unresolvedClosureCount > 0);
    assert.equal(run.scored[0].input.unresolvedClosureIssueCount, unresolvedClosureCount);
    assert.match(run.scored[0].conf.reason, new RegExp(`${unresolvedClosureCount} unresolved closed-release risk groups`));
    assert.equal(closure.metrics?.rawUnresolvedRiskGroupCount, closureProof.riskSummary.unresolvedForReleaseCount);
    assert.match(closure.text, /deduplicated closed-issue risk groups contribute to this score/);
    assert.match(closure.text, /raw closure-proof audit/);
    assert.ok((closure.issueRefs?.length ?? 0) >= 3);
    const releaseChecks = (run.scored[0].gateEvidence as any).releaseChecks;
    const artifactVerification = (run.scored[0].gateEvidence as any).artifactVerification;
    if (releaseChecks) {
      assert.equal(releaseChecks.schemaVersion, scoring.RELEASE_CHECKS_SCHEMA_VERSION);
      assert.equal(releaseChecks.contextCount, releaseChecks.total);
      assert.equal(releaseChecks.shownContextCount, releaseChecks.contexts.length);
      assert.equal(releaseChecks.contextsTruncated, releaseChecks.shownContextCount < releaseChecks.contextCount);
    }
    assert.equal(artifactVerification.schemaVersion, scoring.ARTIFACT_VERIFICATION_SCHEMA_VERSION);
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
    assert.ok(!explanation.limitDetails.some((detail) =>
      detail.code === 'audit_only_closed_issue_flags'));
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

    const carryover = explanation.limitDetails.find((detail) => detail.code === 'open_unconfirmed_issue_risk');
    assert.ok(carryover);
    assert.equal(carryover.label, 'Open inherited/carryover context');
    assert.ok((carryover.metrics?.count ?? 0) > 0);
    assert.equal(run.scored[0].input.carryoverDebtIssueCount, carryover.metrics?.count);
    assert.match(run.scored[0].conf.reason, new RegExp(`${carryover.metrics?.count} inherited/carryover issue groups`));
    assert.match(carryover.text, /contributes a 0\.12 point penalty/);
    assert.equal(carryover.metrics?.maxPenalty, 0.35);
    assert.equal(carryover.metrics?.capApplied, false);
    assert.equal(carryover.metrics?.scoreAffecting, true);
    assert.equal(carryover.metrics?.storedExampleCount, (run.scored[0].debtEvidence as any).carryoverDebt.length);
    assert.ok((carryover.metrics?.storedExampleWeight ?? 0) <= (carryover.metrics?.rawWeight ?? 0));
    assert.equal(typeof carryover.metrics?.byInstallImpactClass, 'object');
    assert.ok(Object.keys(carryover.metrics?.byInstallImpactClass ?? {}).length > 0);
    assert.ok((carryover.issueRefs?.length ?? 0) >= 3);
    assert.ok(carryover.issueRefs?.every((issue) => Number.isInteger(issue.number) && issue.title));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.installImpactClass === 'string'));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.installImpactMultiplier === 'number'));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.weight === 'number'));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.scoringReason === 'string' && /release-local|source\/static|field/.test(issue.scoringReason)));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.fieldConfirmed === 'boolean'));
    assert.ok(carryover.issueRefs?.some((issue) => typeof issue.releaseLocal === 'boolean'));

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
    assert.equal(labelTimeline.schemaVersion, scoring.LABEL_TIMELINE_SCHEMA_VERSION);
    assert.equal(typeof labelTimeline.historicalCurrentLabelFallbackAllowed, 'boolean');
  });

  it('explains incomplete classification coverage with issue references', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      components: { coverage: -0.8 },
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
    }), false);
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

  it('explains score-affecting missing closure evidence as incomplete and unscored', () => {
    const result = explanationResult({
      score: 8.7,
      components: {
        base: 7.5,
        verifiedDebt: 0,
        carryoverDebt: 0,
        staleDebt: 0,
        closureRisk: 0,
        closureRiskCeiling: 0,
        coverage: 0,
        survival: 1.2,
        shakeout: 0,
        regression: 0,
        breaking: 0,
        releaseVerification: 0,
        artifactVerification: 0,
      },
      input: {
        unresolvedClosureIssueCount: 0,
        unresolvedClosureRiskWeight: 0,
        affirmativeClosureRiskCeilingWeight: 0,
      },
    });
    result.analysisCompleteness = {
      complete: false,
      missingClosureEvidence: [{
        issueNumber: 1003,
        status: 'direct_fix_commit_reachability_unknown',
        title: 'fix commit reachability is unknown',
        sentiment: 'negative',
        severity: 'high',
        functionality: 'core',
        scope: 'broad',
        affectedUsers: 'many',
        potentialRiskWeight: 4.875,
      }],
    };

    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(result, false);
    const incomplete = explanation.limitDetails.find((detail: any) =>
      detail.code === 'incomplete_closure_evidence',
    );
    assert.ok(incomplete);
    assert.match(incomplete.text, /#1003 status=direct_fix_commit_reachability_unknown/);
    assert.match(incomplete.text, /contributes 0 closure-risk points/);
    assert.match(incomplete.text, /cannot apply a score ceiling/);
    assert.equal(incomplete.metrics?.analysisComplete, false);
    assert.equal(incomplete.metrics?.contributesScorePoints, false);
    assert.deepEqual(incomplete.issueRefs?.map((issue: any) => issue.number), [1003]);
  });

  it('explains verified field-blocker debt with issue references', () => {
    const explanation = scoring.__releaseScoringTest.buildScoreExplanation(explanationResult({
      components: { verifiedDebt: -1.2 },
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
    }), false);
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
