import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  applyExclusiveIssueRiskLedger,
  buildScoreLedgerV2,
  buildExclusiveIssueRiskLedger,
  explainFeltLoad,
  fieldConfirmationFor,
  installConfidence,
  pickRecommended,
  bandFor,
  cveDecayLoad,
  explainOpenDebtLoad,
  feltLoad,
  openDebtLoad,
  REC_THRESHOLD,
  RECOMMENDATION_RECENCY_TOLERANCE,
  scoreCommentBodyDigest,
  semanticHumanConfirmationReasons,
  scoreLedgerV2Problems,
  withinDecimalTolerance,
  type InstallInput,
} from './score.ts';
import { aggregateClosureRisk } from './closureRiskAggregation.ts';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  repositoryPermissionObservationRowHash,
  type RepositoryPermissionObservation,
} from './labelAuthority.ts';
import {
  buildScoreAuthorityReference,
  buildScoreAuthorityResolution,
  buildScoreCommentAuthorityResolution,
} from './scoreAuthorityResolution.ts';

// Install Confidence contract — answers "should I install this stable?".
// Gates (security advisory / too-new / hotfix) override; otherwise a graded 0–10 from
// age/cadence-invariant signals (survival, shakeout, regression balance, breaking).

const NOW = Date.parse('2026-05-30T00:00:00Z');
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();
const hoursAgo = (h: number) => new Date(NOW - h * 3_600_000).toISOString();
const round1 = (value: number) => Math.round(value * 10) / 10;
const round3 = (value: number) => Math.round(value * 1000) / 1000;
const scoreComponentKeys = [
  'base',
  'verifiedDebt',
  'carryoverDebt',
  'staleDebt',
  'closureRisk',
  'coverage',
  'survival',
  'shakeout',
  'regression',
  'breaking',
  'releaseVerification',
  'artifactVerification',
] as const;

function scoreLabelAuthorityReference(input: {
  eventId: string;
  label: string;
  issueNumber?: number;
  eventTime?: string;
}) {
  const eventTime = input.eventTime ?? '2026-06-11T12:00:00Z';
  const actorNodeId = 'U_human-maintainer';
  const repositoryNodeId = 'R_score-test';
  const permissionBase: RepositoryPermissionObservation = {
    kind: 'repository_permission_observation',
    evidenceId: `permission-${input.eventId}`,
    sourceIdentity: `permission:${input.eventId}`,
    repositoryNodeId,
    repository: 'owner/repo',
    actorNodeId,
    actorLogin: 'human-maintainer',
    actorType: 'User',
    actorAssociation: 'MEMBER',
    permission: 'maintain',
    observedAt: new Date(Date.parse(eventTime) - 3_600_000).toISOString(),
    runHash: 'a'.repeat(64),
  };
  const permission = {
    ...permissionBase,
    rowHash: repositoryPermissionObservationRowHash(permissionBase),
  };
  const resolution = buildScoreAuthorityResolution({
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: `label-event:${input.eventId}`,
      repositoryNodeId,
      repository: 'owner/repo',
      issueNumber: input.issueNumber ?? 1,
      eventId: input.eventId,
      action: 'labeled',
      label: input.label,
      eventTime,
      actor: {
        nodeId: actorNodeId,
        login: 'human-maintainer',
        type: 'User',
        association: 'MEMBER',
      },
    },
    permissionObservations: [permission],
    approvedRosterEntries: [],
  });
  return buildScoreAuthorityReference(
    'label_event',
    input.eventId,
    resolution,
  );
}

function scoreCommentAuthorityReference(input: {
  issueNumber: number;
  issueNodeId: string;
  issueAuthorNodeId: string;
  issueAuthorType: string;
  commentNodeId: string;
  commentId: number;
  commentUrl: string;
  actorNodeId: string;
  commentCreatedAt: string;
  commentUpdatedAt: string;
  commentBodyDigest: string;
  claimSnippet: string;
}) {
  const resolution = buildScoreCommentAuthorityResolution({
    ...input,
    actorType: 'User',
  });
  return buildScoreAuthorityReference(
    'comment',
    input.commentNodeId,
    resolution,
  );
}

function mk(over: Partial<InstallInput> = {}): InstallInput {
  const unresolvedClosureRiskWeight = over.unresolvedClosureRiskWeight ?? 0;
  return {
    publishedAt: daysAgo(10),
    isLatest: false,
    hoursToNextStable: 24, // a "typical" stable lifetime → neutral survival
    hasHotfixSuccessor: false,
    betaCount: 0,
    breakingCount: 0,
    feltOpenedWeight: 0,
    feltClosedWeight: 0,
    verifiedDebtWeight: 0,
    carryoverDebtWeight: 0,
    staleDebtWeight: 0,
    unresolvedClosureRiskWeight,
    affirmativeClosureRiskCeilingWeight:
      over.affirmativeClosureRiskCeilingWeight ?? unresolvedClosureRiskWeight,
    rawIssueCount: 0,
    classifiedIssueCount: 0,
    cveAffected: false,
    cveLoad: 0,
    ...over,
  };
}

function aliasElectionForInput(input: InstallInput) {
  const candidates = [
    ['verified', input.verifiedDebtWeight],
    ['carryover', input.carryoverDebtWeight],
    ['stale', input.staleDebtWeight],
    ['closureRisk', input.unresolvedClosureRiskWeight],
    ['regression', input.feltOpenedWeight],
  ] as const;
  return buildExclusiveIssueRiskLedger(candidates
    .filter(([, weight]) => weight > 0)
    .map(([channel, weight], index) => ({
      aliasGroup: `synthetic:${channel}:${index}`,
      channel,
      weight,
      issueNumber: index + 1,
    })));
}

function evidenceSourcesForAliasElection(
  aliasElection: ReturnType<typeof buildExclusiveIssueRiskLedger>,
) {
  const byChannel = new Map(
    (['verified', 'carryover', 'stale', 'closureRisk', 'regression'] as const)
      .map((channel) => [channel, aliasElection.groups.filter((group) =>
        group.selectedChannel === channel)]),
  );
  return [
    ...(['verified', 'carryover', 'stale'] as const).map((channel) => ({
      key: channel === 'verified'
        ? 'verifiedDebt'
        : channel === 'carryover'
          ? 'carryoverDebt'
          : 'staleDebt',
      refs: (byChannel.get(channel) ?? []).map((group) => ({
        kind: 'issue',
        identity: `issue:${group.issueNumber ?? 'unknown'}:alias:${group.aliasGroup}`,
        payload: {
          aliasGroup: group.aliasGroup,
          tier: channel,
          weight: group.selectedWeight,
        },
      })),
    })),
    {
      key: 'closureRisk',
      refs: (byChannel.get('closureRisk') ?? []).map((group) => ({
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
      refs: (byChannel.get('regression') ?? []).map((group) => ({
        kind: 'issue',
        identity: `issue:${group.issueNumber ?? 'unknown'}:alias:${group.aliasGroup}`,
        payload: {
          aliasGroup: group.aliasGroup,
          countedWeight: group.selectedWeight,
        },
      })),
    },
  ];
}

function scoreLedgerRiskArgs(input: InstallInput) {
  const aliasElection = aliasElectionForInput(input);
  return {
    aliasElection,
    evidenceSources: evidenceSourcesForAliasElection(aliasElection),
  };
}

const score = (over: Partial<InstallInput> = {}) => installConfidence(mk(over), NOW).score!;
const cappedDebtPenalty = (loads: {
  verified: number;
  carryover: number;
  stale: number;
}): number => {
  const components = installConfidence(mk({
    verifiedDebtWeight: loads.verified,
    carryoverDebtWeight: loads.carryover,
    staleDebtWeight: loads.stale,
  }), NOW).components!;
  return -(components.verifiedDebt + components.carryoverDebt + components.staleDebt);
};
const isRecommendationEligible = (
  result: ReturnType<typeof installConfidence>,
): boolean => pickRecommended([{
  tag: 'candidate',
  status: result.status,
  score: result.score,
}]) === 'candidate';

describe('installConfidence — gates', () => {
  it('advisory-affected → skip-cve compatibility status, scored below any install', () => {
    const clean = installConfidence(mk(), NOW).score!;
    const r = installConfidence(mk({ cveAffected: true, cveLoad: 20 }), NOW);
    assert.equal(r.status, 'skip-cve');
    assert.equal(r.band, 'skip');                 // status drives band → never recommended
    assert.ok(r.score! < clean, `advisory gate should score below the clean baseline (${r.score} vs ${clean})`);
  });

  it('skip-cve ranks by own-CVE severity: heavier load scores lower', () => {
    const light = installConfidence(mk({ cveAffected: true, cveLoad: 4 }), NOW).score!;
    const heavy = installConfidence(mk({ cveAffected: true, cveLoad: 27 }), NOW).score!;
    assert.ok(heavy < light, `heavier load should score lower (${heavy} vs ${light})`);
  });

  it('skip-cve does NOT inherit the maintenance base (a Skip never outranks an install)', () => {
    // Two CVE-affected releases with the SAME CVE load but very different maintenance
    // quality must score the SAME — maintenance is irrelevant once it is don't-install.
    const wellTended = mk({ cveAffected: true, cveLoad: 10, betaCount: 14, hoursToNextStable: 96 });
    const shortLived = mk({ cveAffected: true, cveLoad: 10, betaCount: 0, hoursToNextStable: 9 });
    assert.equal(installConfidence(wellTended, NOW).score, installConfidence(shortLived, NOW).score);
    // And both stay below 5 (never above an installable release).
    assert.ok(installConfidence(wellTended, NOW).score! < 5);
  });

  it('a distant-only CVE (load ≈ 0) is the mildest skip but still below 5', () => {
    const r = installConfidence(mk({ cveAffected: true, cveLoad: 0 }), NOW);
    assert.equal(r.status, 'skip-cve');
    assert.ok(r.score != null && r.score < 5, `skip-cve must read < 5, got ${r.score}`);
  });

  it('turning cveAffected false to true never raises an existing numeric score', () => {
    const adverse = mk({
      verifiedDebtWeight: 100,
      carryoverDebtWeight: 100,
      staleDebtWeight: 100,
      unresolvedClosureRiskWeight: 100,
      feltOpenedWeight: 100,
      breakingCount: 10,
      releaseCheckState: 'FAILURE',
      releaseCheckTotal: 2,
      releaseCheckFailure: 2,
      artifactMismatch: 'registry mismatch',
    });
    const before = installConfidence(adverse, NOW);
    const after = installConfidence({ ...adverse, cveAffected: true, cveLoad: 0 }, NOW);
    assert.equal(after.status, 'skip-cve');
    assert.ok(before.score != null && after.score != null);
    assert.ok(after.score <= before.score, `CVE gate raised score (${before.score} -> ${after.score})`);
  });

  it('younger than the settle window → wait, no score', () => {
    const r = installConfidence(mk({ publishedAt: hoursAgo(5) }), NOW);
    assert.equal(r.status, 'wait');
    assert.equal(r.score, null);
    assert.equal(r.band, 'wait');
  });

  it('fails closed for unavailable, invalid, and future publication dates', () => {
    const invalidDates = [
      null,
      '',
      'not-a-publication-date',
      new Date(NOW + 1).toISOString(),
      new Date(NOW + 365 * 86_400_000).toISOString(),
    ];
    for (const publishedAt of invalidDates) {
      const result = installConfidence(mk({
        isLatest: true,
        hoursToNextStable: null,
        publishedAt,
      }), NOW);
      assert.equal(result.status, 'wait', `expected wait for ${String(publishedAt)}`);
      assert.equal(result.score, null);
      assert.equal(result.components, null);
      assert.match(result.reason, /publication date unavailable, invalid, or in the future/);
      assert.doesNotMatch(result.reason, /Infinity|NaN/);
    }
  });

  it('a `-N` hotfix successor → skip-hotfix, reads below 5', () => {
    const r = installConfidence(mk({ hasHotfixSuccessor: true }), NOW);
    assert.equal(r.status, 'skip-hotfix');
    assert.equal(r.band, 'skip');
    assert.ok(r.score != null && r.score < 5, `expected <5, got ${r.score}`);
  });

  it('replaced by next stable within the emergency window → skip-hotfix', () => {
    const r = installConfidence(mk({ hoursToNextStable: 3 }), NOW);
    assert.equal(r.status, 'skip-hotfix');
    assert.ok(r.score != null && r.score < 5);
  });

  it('the latest (no successor) is still scored once past the settle window', () => {
    const r = installConfidence(mk({ isLatest: true, hoursToNextStable: null, publishedAt: daysAgo(3) }), NOW);
    assert.equal(r.status, 'eligible');
    assert.ok(typeof r.score === 'number');
  });

  it('uses the same survival curve for equal latest and historical exposure', () => {
    const latest = installConfidence(mk({
      isLatest: true,
      publishedAt: hoursAgo(72),
      hoursToNextStable: null,
    }), NOW);
    const historical = installConfidence(mk({
      isLatest: false,
      publishedAt: daysAgo(10),
      hoursToNextStable: 72,
    }), NOW);
    assert.equal(latest.components?.survival, historical.components?.survival);
  });
});

describe('installConfidence — graded signals', () => {
  it('eligible baseline (typical lifetime, no other signal) starts in the ok band', () => {
    const r = installConfidence(mk(), NOW);
    assert.equal(r.status, 'eligible');
    assert.ok(r.score! >= 7 && r.score! < 8, `expected ok baseline, got ${r.score}`);
  });

  it('longer survival before the next stable scores higher', () => {
    assert.ok(score({ hoursToNextStable: 96 }) > score({ hoursToNextStable: 24 }));
    assert.ok(score({ hoursToNextStable: 24 }) > score({ hoursToNextStable: 8 }));
  });

  it('more beta shakeout raises confidence', () => {
    assert.ok(score({ betaCount: 10 }) > score({ betaCount: 0 }));
  });

  it('net-fixing visible bugs beats net-breaking', () => {
    const fixing = score({ feltClosedWeight: 40, feltOpenedWeight: 10 });
    const breaking = score({ feltClosedWeight: 10, feltOpenedWeight: 40 });
    assert.ok(fixing > breaking, `fixing ${fixing} should beat breaking ${breaking}`);
  });

  it('visible-bug balance is shrunk toward neutral on low volume', () => {
    // A couple of visible bugs barely moves the score (no noisy 0%-fixed slam).
    const tiny = score({ feltOpenedWeight: 2, feltClosedWeight: 0 });
    assert.ok(Math.abs(tiny - score()) < 0.6, `low volume should barely move (${tiny} vs ${score()})`);
  });

  it('breaking changes lower the score', () => {
    assert.ok(score({ breakingCount: 3 }) < score({ breakingCount: 0 }));
  });

  it('successful release checks add a small capped verification bump', () => {
    const unchecked = score();
    const checked = score({ releaseCheckState: 'SUCCESS', releaseCheckTotal: 7, releaseCheckSuccess: 4 });
    const manyChecked = score({ releaseCheckState: 'SUCCESS', releaseCheckTotal: 70, releaseCheckSuccess: 70 });
    assert.ok(checked > unchecked, `checked ${checked} should beat unchecked ${unchecked}`);
    assert.ok(manyChecked - unchecked <= 0.5, `release checks must stay capped (${manyChecked} vs ${unchecked})`);
  });

  it('failed release checks penalize more than pending checks', () => {
    const pending = score({ releaseCheckState: 'PENDING', releaseCheckTotal: 7, releaseCheckPending: 2 });
    const expected = score({ releaseCheckState: 'EXPECTED', releaseCheckTotal: 7 });
    const failed = score({ releaseCheckState: 'FAILURE', releaseCheckTotal: 7, releaseCheckFailure: 1 });
    assert.ok(failed < pending, `failed ${failed} should be below pending ${pending}`);
    assert.equal(expected, score({ releaseCheckState: 'PENDING', releaseCheckTotal: 7 }));
  });

  it('adding a failed check never weakens an existing pending penalty', () => {
    const pending = score({
      releaseCheckState: 'PENDING',
      releaseCheckTotal: 1_000_000_000,
      releaseCheckPending: 1_000_000_000,
      releaseCheckFailure: 0,
    });
    const failed = score({
      releaseCheckState: 'FAILURE',
      releaseCheckTotal: 1_000_000_001,
      releaseCheckPending: 1_000_000_000,
      releaseCheckFailure: 1,
    });
    assert.ok(failed <= pending, `adding a failure raised score (${pending} -> ${failed})`);
  });

  it('verified artifacts add a small capped confidence bump', () => {
    const unchecked = score();
    const verified = score({ artifactVerified: true, ciReportVerified: true, releaseIntegrityPresent: true, releaseShaMatches: true });
    assert.ok(verified > unchecked);
    assert.ok(verified - unchecked <= 0.5);
  });

  it('withholds artifact credit unless the release commit binding is proven true', () => {
    const unchecked = score();
    const unknownBinding = score({
      artifactVerified: true,
      releaseIntegrityPresent: true,
    });
    const mismatchedBinding = score({
      artifactVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: false,
    });
    assert.equal(unknownBinding, unchecked);
    assert.equal(mismatchedBinding, unchecked);
  });

  it('artifact mismatches penalize release confidence', () => {
    const verified = score({ artifactVerified: true, releaseIntegrityPresent: true, releaseShaMatches: true });
    const mismatch = score({ artifactVerified: false, artifactMismatch: 'registry integrity mismatch' });
    assert.ok(mismatch < verified);
  });

  it('missing release evidence report offsets artifact confidence without wiping npm verification', () => {
    const verified = score({ artifactVerified: true, releaseIntegrityPresent: true, releaseShaMatches: true });
    const missingReport = score({
      artifactVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
      ciReportMismatch: 'release evidence report not found',
    });
    assert.ok(missingReport < verified);
    assert.ok(missingReport > score({ artifactMismatch: 'registry integrity mismatch' }));
  });

  it('verified open debt lowers the score even when reign balance is neutral', () => {
    assert.ok(score({ verifiedDebtWeight: 1 }) > score({ verifiedDebtWeight: 30 }));
  });

  it('carryover debt is audit-only while stale debt remains capped below verified blockers', () => {
    const base = score();
    const verified = score({ verifiedDebtWeight: 100 });
    const carryover = score({ carryoverDebtWeight: 100 });
    const stale = score({ staleDebtWeight: 100 });
    assert.ok(verified < carryover);
    assert.equal(carryover, base);
    assert.ok(stale > verified);
  });

  it('capped source-only and weak evidence do not drag a clean well-proven release below solid', () => {
    const result = installConfidence(mk({
      publishedAt: daysAgo(10),
      isLatest: true,
      hoursToNextStable: null,
      betaCount: 6,
      feltOpenedWeight: 6,
      feltClosedWeight: 45,
      verifiedDebtWeight: 0,
      carryoverDebtWeight: 500,
      carryoverDebtIssueCount: 200,
      staleDebtWeight: 500,
      unresolvedClosureRiskWeight: 0,
      rawIssueCount: 3000,
      classifiedIssueCount: 3000,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    }), NOW);

    assert.equal(result.status, 'eligible');
    assert.equal(result.band, 'solid');
    assert.ok(result.score != null && result.score >= 8, `expected a solid score, got ${result.score}`);
    assert.equal(Math.abs(result.components?.verifiedDebt ?? NaN), 0);
    assert.equal(result.components?.carryoverDebt, 0);
    assert.equal(result.components?.staleDebt, -0.2);
    assert.equal(Math.abs(result.components?.closureRisk ?? NaN), 0);
    assert.match(result.reason, /200 inherited\/carryover issue groups \(audit weight 500; 0 score points\)/);
  });

  it('short reason uses issue counts beside risk weights when available', () => {
    const result = installConfidence(mk({
      isLatest: true,
      carryoverDebtWeight: 506.12,
      carryoverDebtIssueCount: 228,
      unresolvedClosureRiskWeight: 93.35,
      unresolvedClosureIssueCount: 118,
    }), NOW);

    assert.match(result.reason, /228 inherited\/carryover issue groups \(audit weight 506; 0 score points\)/);
    assert.match(result.reason, /118 unresolved closed-release risk groups \(risk weight 93\)/);
    assert.doesNotMatch(result.reason, /506 open unconfirmed issue-risk weight/);
  });

  it('discloses low positive verified blocker debt in the short reason', () => {
    const result = installConfidence(mk({
      isLatest: true,
      verifiedDebtWeight: 1.476,
    }), NOW);

    assert.match(result.reason, /1 field-confirmed blocker risk/);
  });

  it('uses singular and plural grammar for verified debt issue counts', () => {
    const singular = installConfidence(mk({
      verifiedDebtWeight: 1.476,
      verifiedDebtIssueCount: 1,
    }), NOW);
    const plural = installConfidence(mk({
      verifiedDebtWeight: 1.476,
      verifiedDebtIssueCount: 2,
    }), NOW);

    assert.match(singular.reason, /1 field-confirmed blocker issue \(risk weight 1\)/);
    assert.match(plural.reason, /2 field-confirmed blocker issues \(risk weight 1\)/);
  });

  it('omits verified blocker debt from the short reason when weight and count are zero', () => {
    const result = installConfidence(mk({
      verifiedDebtWeight: 0,
      verifiedDebtIssueCount: 0,
    }), NOW);

    assert.doesNotMatch(result.reason, /field-confirmed blocker/);
  });

  it('unresolved closed-release risk lowers confidence but stays capped', () => {
    const base = installConfidence(mk(), NOW);
    const some = installConfidence(mk({ unresolvedClosureRiskWeight: 8 }), NOW);
    const heavy = installConfidence(mk({ unresolvedClosureRiskWeight: 800 }), NOW);
    assert.ok(some.score! < base.score!);
    assert.ok(heavy.score! < some.score!);
    assert.ok((base.score! - heavy.score!) <= 0.6);
    assert.equal(heavy.components?.closureRisk, -0.5);
  });

  it('heavy weighted unresolved closure risk blocks solid scores', () => {
    const risky = installConfidence(mk({
      hoursToNextStable: 96,
      betaCount: 10,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
      unresolvedClosureRiskWeight: 79.9,
      unresolvedClosureIssueCount: 118,
    }), NOW);

    assert.equal(risky.score, 7.9);
    assert.equal(risky.band, 'ok');
    assert.equal(risky.components?.closureRiskCeiling, 7.9);
  });

  it('does not apply a score ceiling from raw issue volume alone', () => {
    const result = installConfidence(mk({
      unresolvedClosureRiskWeight: 5,
      unresolvedClosureIssueCount: 500,
    }), NOW);
    assert.equal(result.components?.closureRiskCeiling, 0);
  });

  it('uses the separate affirmative closure weight for ceilings without duplicating penalty', () => {
    const result = installConfidence(mk({
      hoursToNextStable: 96,
      betaCount: 10,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
      unresolvedClosureRiskWeight: 0,
      affirmativeClosureRiskCeilingWeight: 80,
    }), NOW);

    assert.equal(Math.abs(result.components?.closureRisk ?? NaN), 0);
    assert.equal(result.components?.closureRiskCeiling, 7.9);
    assert.equal(result.score, 7.9);
  });

  it('applies affirmative closure ceilings at the exact weighted thresholds', () => {
    const strong = {
      hoursToNextStable: 96,
      betaCount: 10,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
      unresolvedClosureRiskWeight: 0,
    } satisfies Partial<InstallInput>;
    const ceiling = (weight: number) => installConfidence(mk({
      ...strong,
      affirmativeClosureRiskCeilingWeight: weight,
    }), NOW).components?.closureRiskCeiling;

    assert.equal(ceiling(39.999), 0);
    assert.equal(ceiling(40), 8.4);
    assert.equal(ceiling(59.999), 8.4);
    assert.equal(ceiling(60), 7.9);
  });

  it('moderate unresolved closure risk caps very high scores without blocking solid outright', () => {
    const risky = installConfidence(mk({
      hoursToNextStable: 96,
      betaCount: 10,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
      unresolvedClosureRiskWeight: 45,
      unresolvedClosureIssueCount: 20,
    }), NOW);

    assert.equal(risky.score, 8.4);
    assert.equal(risky.band, 'solid');
    assert.equal(risky.components?.closureRiskCeiling, 8.4);
  });

  it('heavy unresolved closed-release risk caps otherwise strong eligible scores below solid', () => {
    const strong = installConfidence(mk({
      hoursToNextStable: 96,
      betaCount: 10,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    }), NOW);
    const risky = installConfidence(mk({
      hoursToNextStable: 96,
      betaCount: 10,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
      unresolvedClosureRiskWeight: 160,
    }), NOW);
    assert.ok(strong.score! >= 8);
    assert.equal(risky.score, 7.9);
    assert.equal(risky.components?.closureRiskCeiling, 7.9);
  });

  it('incomplete evidence coverage lowers confidence', () => {
    const complete = installConfidence(mk({ rawIssueCount: 100, classifiedIssueCount: 100 }), NOW);
    const partial = installConfidence(mk({ rawIssueCount: 100, classifiedIssueCount: 40 }), NOW);
    assert.ok(partial.score! < complete.score!);
    assert.equal(partial.evidenceCoverage, 0.4);
  });

  it('score never leaves [0,10] under extreme inputs', () => {
    const lo = installConfidence(mk({ hoursToNextStable: 1, breakingCount: 99, feltOpenedWeight: 500, feltClosedWeight: 0 }), NOW).score!;
    const hi = installConfidence(mk({ hoursToNextStable: 100000, betaCount: 999, feltClosedWeight: 999, feltOpenedWeight: 0 }), NOW).score!;
    assert.ok(lo >= 0 && lo <= 10 && hi >= 0 && hi <= 10);
  });

  it('retains precision when an adjustment is inserted before a closure cap', () => {
    const result = installConfidence(mk({
      isLatest: true,
      hoursToNextStable: null,
      betaCount: 1,
      breakingCount: 3,
      feltOpenedWeight: 50,
      feltClosedWeight: 50,
      staleDebtWeight: 1,
      unresolvedClosureRiskWeight: 40,
      rawIssueCount: 100,
      classifiedIssueCount: 100,
    }), NOW);
    const components = result.components!;
    assert.equal(result.score, 8.3);
    assert.equal(components.closureRiskCeiling, 8.4);

    const displayedSubtotal = round3(scoreComponentKeys.reduce(
      (sum, key) => sum + round3(components[key]),
      0,
    ));
    const initiallyCapped = round3(Math.min(displayedSubtotal, components.closureRiskCeiling));
    const precisionAdjustment = round3(result.score! - initiallyCapped);
    const adjustedSubtotal = round3(displayedSubtotal + precisionAdjustment);
    const scoreAfterCaps = round3(Math.min(adjustedSubtotal, components.closureRiskCeiling));
    assert.equal(scoreAfterCaps, result.score);

    const legacyRoundedSubtotal = round3(scoreComponentKeys.reduce(
      (sum, key) => sum + round1(components[key]),
      0,
    ));
    const legacyAdjustment = round3(
      result.score! - Math.min(legacyRoundedSubtotal, components.closureRiskCeiling),
    );
    const legacyScoreAfterCaps = round3(Math.min(
      legacyRoundedSubtotal + legacyAdjustment,
      components.closureRiskCeiling,
    ));
    assert.equal(legacyScoreAfterCaps, 8.4);
  });

  it('keeps range clamps distinct and reconciles generated scores after caps', () => {
    const upperClamped = installConfidence(mk({
      isLatest: true,
      hoursToNextStable: null,
      betaCount: 999,
      feltClosedWeight: 999,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 70,
      releaseCheckSuccess: 70,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    }), NOW);
    const lowerClamped = installConfidence(mk({
      hoursToNextStable: 6,
      breakingCount: 99,
      feltOpenedWeight: 999,
      verifiedDebtWeight: 999,
      carryoverDebtWeight: 999,
      staleDebtWeight: 999,
      unresolvedClosureRiskWeight: 999,
      rawIssueCount: 100,
      classifiedIssueCount: 0,
      releaseCheckState: 'FAILURE',
      releaseCheckTotal: 10,
      releaseCheckFailure: 10,
      artifactMismatch: 'mismatch',
    }), NOW);
    assert.ok((upperClamped.scoreRangeClamp ?? 0) < 0);
    assert.ok((lowerClamped.scoreRangeClamp ?? 0) > 0);
    const closureCapped = installConfidence(mk({
      hoursToNextStable: 96,
      betaCount: 999,
      feltClosedWeight: 999,
      unresolvedClosureRiskWeight: 45,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 70,
      releaseCheckSuccess: 70,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    }), NOW);
    assert.equal(closureCapped.score, closureCapped.components?.closureRiskCeiling);

    let sawHotfixCap = false;
    for (let index = 0; index < 600; index += 1) {
      const isLatest = index % 2 === 0;
      const result = installConfidence(mk({
        isLatest,
        hoursToNextStable: isLatest ? null : (index * 17) % 240,
        hasHotfixSuccessor: !isLatest && index % 19 === 0,
        betaCount: (index * 13) % 120,
        breakingCount: (index * 7) % 24,
        feltOpenedWeight: (index * 29) % 520,
        feltClosedWeight: (index * 43) % 520,
        verifiedDebtWeight: (index * 31) % 500,
        carryoverDebtWeight: (index * 37) % 500,
        staleDebtWeight: (index * 41) % 500,
        unresolvedClosureRiskWeight: (index * 47) % 200,
        rawIssueCount: 100,
        classifiedIssueCount: (index * 53) % 101,
        releaseCheckState: index % 3 === 0 ? 'SUCCESS' : index % 3 === 1 ? 'FAILURE' : 'PENDING',
        releaseCheckTotal: 10,
        releaseCheckSuccess: index % 11,
        releaseCheckFailure: index % 17 === 0 ? 1 : 0,
        releaseCheckPending: index % 13 === 0 ? 1 : 0,
        artifactVerified: index % 2 === 0,
        ciReportVerified: index % 5 === 0,
        releaseIntegrityPresent: true,
        releaseShaMatches: true,
      }), NOW);
      const components = result.components;
      assert.ok(components);

      const scoreBeforeRangeClamp = scoreComponentKeys.reduce(
        (sum, key) => sum + components[key],
        0,
      );
      const expectedRangeClamp =
        Math.max(0, Math.min(10, scoreBeforeRangeClamp)) - scoreBeforeRangeClamp;
      assert.ok(Math.abs((result.scoreRangeClamp ?? NaN) - expectedRangeClamp) < 1e-12);

      const scoreBeforeCaps = scoreBeforeRangeClamp + (result.scoreRangeClamp ?? 0);
      let exactAfterCaps = scoreBeforeCaps;
      if (components.closureRiskCeiling > 0) {
        exactAfterCaps = Math.min(exactAfterCaps, components.closureRiskCeiling);
      }
      if (result.status === 'skip-hotfix') {
        exactAfterCaps = Math.min(exactAfterCaps, 4.9);
        sawHotfixCap = true;
      }
      assert.equal(result.score, round1(exactAfterCaps));

      const displayedSubtotal = round3(
        scoreComponentKeys.reduce((sum, key) => sum + round3(components[key]), 0) +
        round3(result.scoreRangeClamp ?? 0),
      );
      const capWasBinding = exactAfterCaps < scoreBeforeCaps;
      const precisionTarget = capWasBinding ? scoreBeforeCaps : result.score;
      const precisionAdjustment = round3(precisionTarget - displayedSubtotal);
      const adjustedSubtotal = round3(displayedSubtotal + precisionAdjustment);
      let scoreAfterCaps = adjustedSubtotal;
      if (components.closureRiskCeiling > 0) {
        scoreAfterCaps = round3(Math.min(scoreAfterCaps, components.closureRiskCeiling));
      }
      if (result.status === 'skip-hotfix') {
        scoreAfterCaps = round3(Math.min(scoreAfterCaps, 4.9));
      }
      assert.equal(scoreAfterCaps, result.score);
    }

    assert.equal(sawHotfixCap, true);
  });
});

describe('bandFor — number and label agree', () => {
  it('maps rounded score to band at the documented cutoffs', () => {
    assert.equal(bandFor(8.0, 'eligible'), 'solid');
    assert.equal(bandFor(7.0, 'eligible'), 'ok');
    assert.equal(bandFor(6.9, 'eligible'), 'caution');
    assert.equal(bandFor(5.4, 'eligible'), 'weak');
    assert.equal(bandFor(9.9, 'skip-hotfix'), 'skip');
    assert.equal(bandFor(null, 'wait'), 'wait');
  });
});

describe('cveDecayLoad — geometric decay by distance', () => {
  it('full weight (×1.0) at distance 0 (severity = the weight)', () => {
    assert.equal(cveDecayLoad([{ severity: 'medium', distance: 0 }]), 2);
  });

  it('decays ×0.3 per step back', () => {
    assert.ok(Math.abs(cveDecayLoad([{ severity: 'medium', distance: 1 }]) - 0.6) < 1e-9);  // 2×0.3
    assert.ok(Math.abs(cveDecayLoad([{ severity: 'medium', distance: 2 }]) - 0.18) < 1e-9); // 2×0.09
  });

  it('severity scales the load (critical 4× a low)', () => {
    assert.equal(
      cveDecayLoad([{ severity: 'critical', distance: 0 }]) / cveDecayLoad([{ severity: 'low', distance: 0 }]),
      4,
    );
  });

  it('zero weight beyond the 10-release window', () => {
    assert.equal(cveDecayLoad([{ severity: 'high', distance: 10 }]), 0);
  });

  it('load sums across advisories', () => {
    assert.ok(Math.abs(cveDecayLoad([
      { severity: 'medium', distance: 0 }, { severity: 'high', distance: 0 },
    ]) - 5) < 1e-9); // 2 + 3
  });
});

describe('feltLoad — reach-weighted visible bugs', () => {
  const fc = (over = {}) => ({ sentiment: 'negative', severity: 'high', functionality: 'integration', scope: 'moderate', affectedUsers: 'some', ...over });

  it('counts core / integration / provider high+critical negatives', () => {
    assert.ok(feltLoad([fc({ functionality: 'integration' })]) > 0);
    assert.ok(feltLoad([fc({ functionality: 'provider' })]) > 0);
    assert.ok(feltLoad([fc({ functionality: 'core' })]) > 0);
  });

  it('ignores docs, medium/low severity, and non-negative', () => {
    assert.equal(feltLoad([fc({ functionality: 'docs' })]), 0);
    assert.equal(feltLoad([fc({ severity: 'medium' })]), 0);
    assert.equal(feltLoad([fc({ sentiment: 'positive' })]), 0);
  });

  it('weights by reach: a broad bug hitting many dwarfs a niche one hitting few', () => {
    const broad = feltLoad([fc({ scope: 'broad', affectedUsers: 'many' })]);
    const niche = feltLoad([fc({ scope: 'niche', affectedUsers: 'few' })]);
    assert.ok(broad > niche * 3, `broad ${broad} should be >3× niche ${niche}`);
  });

  it('does not count source-repro-only automation findings as field regression load', () => {
    assert.equal(feltLoad([fc({ labels: ['clawsweeper:source-repro'], confidence: 0.95 })]), 0);
    assert.equal(feltLoad([fc({ labels: ['bug', 'regression', 'P1', 'clawsweeper:source-repro'], confidence: 0.95 })]), 0);
    assert.equal(feltLoad([
      fc({ issueNumber: 1, author: 'alice', duplicateCluster: 'confirmed-source-report', labels: ['clawsweeper:source-repro'] }),
      fc({ issueNumber: 2, author: 'bob', duplicateCluster: 'confirmed-source-report', labels: ['clawsweeper:source-repro'] }),
    ]), 0);
  });

  it('does not let classifier-only duplicate slugs merge independent regression reports', () => {
    const one = feltLoad([fc({ issueNumber: 1, duplicateCluster: 'same-regression' })]);
    const repeated = feltLoad([
      fc({ issueNumber: 1, duplicateCluster: 'same-regression' }),
      fc({ issueNumber: 2, duplicateCluster: 'same-regression' }),
      fc({ issueNumber: 3, duplicateCluster: 'same-regression' }),
    ]);
    assert.equal(repeated, one * 3);
  });

  it('keeps normalized classifier-cluster variants descriptive rather than authoritative', () => {
    const variants = [
      'Provider Failure',
      ' provider failure ',
      'PROVIDER FAILURE',
      'Provider\t\nFailure',
      'Provider   Failure',
    ];
    const one = feltLoad([fc({ issueNumber: 1, duplicateCluster: variants[0] })]);
    const repeated = feltLoad(variants.map((duplicateCluster, index) =>
      fc({ issueNumber: index + 1, duplicateCluster })
    ));
    assert.equal(repeated, one * variants.length);
  });

  it('unifies classifier clusters bridged by canonical issue aliases', () => {
    const analysis = explainFeltLoad([
      fc({ issueNumber: 1, duplicateCluster: 'alpha', canonicalIssueNumbers: [99] }),
      fc({ issueNumber: 2, duplicateCluster: 'beta', canonicalIssueNumbers: [99] }),
    ]);
    assert.equal(analysis.evidence.filter((item) => item.counted).length, 1);
  });

  it('adding a classifier-slug collision never lowers regression load or score penalty', () => {
    const first = fc({
      issueNumber: 301,
      duplicateCluster: 'model-says-same',
      scope: 'broad',
      affectedUsers: 'many',
    });
    const second = fc({
      issueNumber: 302,
      duplicateCluster: 'MODEL-SAYS-SAME',
      scope: 'moderate',
      affectedUsers: 'some',
    });
    const before = feltLoad([first]);
    const after = feltLoad([first, second]);
    assert.ok(after >= before);
    assert.ok(score({ feltOpenedWeight: after }) <= score({ feltOpenedWeight: before }));
  });

  it('namespaces cluster, issue, and row identities to prevent collisions', () => {
    const one = feltLoad([fc({ issueNumber: 7 })]);
    const separate = feltLoad([
      fc({ issueNumber: 7 }),
      fc({ issueNumber: 8, duplicateCluster: 'issue:7' }),
      fc({ duplicateCluster: '   ' }),
    ]);
    assert.equal(separate, one * 3);
  });
});

describe('semantic human confirmation', () => {
  const issueIdentity = {
    issueNodeId: 'I_semantic-confirmation',
    issueAuthor: {
      nodeId: 'U_original-reporter',
      login: 'original-reporter',
      actorType: 'User',
    },
  } as const;
  const authoritativeComment = (
    id: number,
    login: string,
    body: string,
    overrides: Record<string, any> = {},
  ) => {
    const { user: userOverrides, ...commentOverrides } = overrides;
    return {
      id,
      node_id: `IC_${id}`,
      node_type: 'IssueComment',
      url: `https://example.test/comments/${id}`,
      user: {
        id: `U_${login}`,
        node_id: `U_${login}`,
        login,
        type: 'User',
        ...(userOverrides ?? {}),
      },
      author_association: 'NONE',
      body,
      created_at: '2026-07-04T10:00:00Z',
      updated_at: '2026-07-04T10:00:00Z',
      ...commentOverrides,
    };
  };

  it('extracts #98416-style independent reproduction with auditable comment identity', () => {
    const reasons = semanticHumanConfirmationReasons({
      issueNumber: 98416,
      ...issueIdentity,
      cutoff: '2026-07-04T12:00:00Z',
      comments: [authoritativeComment(
        9841601,
        'community-contributor',
        'Can confirm, I reproduced the same issue on v2026.7.4.',
        {
        url: 'https://github.com/openclaw/openclaw/issues/98416#issuecomment-9841601',
        author_association: 'CONTRIBUTOR',
        },
      )],
    });
    assert.equal(reasons.length, 1);
    assert.deepEqual(reasons[0], {
      code: 'independent_human_reproduction',
      source: 'comment',
      author: 'community-contributor',
      association: 'CONTRIBUTOR',
      occurredAt: '2026-07-04T10:00:00Z',
      updatedAt: '2026-07-04T10:00:00Z',
      commentId: 9841601,
      commentUrl: 'https://github.com/openclaw/openclaw/issues/98416#issuecomment-9841601',
      issueNodeId: 'I_semantic-confirmation',
      issueAuthorNodeId: 'U_original-reporter',
      issueAuthorType: 'User',
      commentNodeId: 'IC_9841601',
      commentNodeType: 'IssueComment',
      actorNodeId: 'U_community-contributor',
      actorType: 'User',
      commentBodyDigest: scoreCommentBodyDigest(
        'Can confirm, I reproduced the same issue on v2026.7.4.',
      ),
      snippet: 'Can confirm, I reproduced the same issue on v2026.7.4.',
      authorityReference: scoreCommentAuthorityReference({
        issueNumber: 98416,
        issueNodeId: 'I_semantic-confirmation',
        issueAuthorNodeId: 'U_original-reporter',
        issueAuthorType: 'User',
        commentNodeId: 'IC_9841601',
        commentId: 9841601,
        commentUrl:
          'https://github.com/openclaw/openclaw/issues/98416#issuecomment-9841601',
        actorNodeId: 'U_community-contributor',
        commentCreatedAt: '2026-07-04T10:00:00Z',
        commentUpdatedAt: '2026-07-04T10:00:00Z',
        commentBodyDigest: scoreCommentBodyDigest(
          'Can confirm, I reproduced the same issue on v2026.7.4.',
        ),
        claimSnippet:
          'Can confirm, I reproduced the same issue on v2026.7.4.',
      }),
    });
  });

  it('excludes bots, the original reporter, negation, and post-cutoff edits', () => {
    const reasons = semanticHumanConfirmationReasons({
      issueNumber: 98416,
      ...issueIdentity,
      cutoff: '2026-07-04T12:00:00Z',
      comments: [
        authoritativeComment(1, 'renamed-reporter', 'Can confirm.', {
          user: {
            node_id: 'U_original-reporter',
            type: 'User',
          },
        }),
        authoritativeComment(2, 'ClawSweeper', 'Can confirm.', {
          user: { type: 'Bot' },
        }),
        authoritativeComment(3, 'barnacle', 'Same issue.', {
          user: { type: 'Bot' },
        }),
        authoritativeComment(6, 'openclaw-barnacle', 'I reproduced this.', {
          user: { type: 'Bot' },
        }),
        authoritativeComment(4, 'human-a', 'I cannot reproduce this.'),
        authoritativeComment(5, 'human-b', 'I reproduced this.', {
          updated_at: '2026-07-04T13:00:00Z',
        }),
      ],
    });
    assert.deepEqual(reasons, []);
  });

  it('recognizes concrete adverse reproduction claims from real issue language', () => {
    const phrases = [
      'Here are additional live reproduction details from v2026.7.4.',
      'VK is also affected: delivery drops queued messages after reconnect.',
      'I hit the same class of failure in production.',
      'Sharing an additional anonymized reproduction from a customer workspace.',
      'Slack reproduction: messages are dropped after reconnect.',
      'Production data point confirming user-visible message loss on two workspaces.',
      'I hit Error while sending the message.',
      'Confirming this still reproduces unchanged on v2026.6.11.',
      'We hit a case that leaves the parent permanently un-resumable.',
      'Live repro on 2026.6.5: the narrative is generated, then dropped on read-back.',
      'Corroborating repro on v2026.6.6 from a second Control UI installation.',
      'Independent confirmation of this on 2026.5.27: cron edit silently dropped schedule.tz.',
      'The same class of leakage observed on another production gateway.',
      'The same class of failure observed after the reconnect.',
      'The gateway is still broken on v2026.7.4: startup exits with ECONNREFUSED after login.',
      'The regression is still not fixed: reconnect drops the first queued message.',
      'The failure is still reproducing on every restart.',
      'The issue persists after a clean install: messages are dropped after reconnect.',
      'This is 100% reproducible on Windows.',
      'The fix does NOT resolve the message loss.',
    ];
    const reasons = semanticHumanConfirmationReasons({
      issueNumber: 98416,
      ...issueIdentity,
      cutoff: '2026-07-04T12:00:00Z',
      comments: phrases.map((body, index) =>
        authoritativeComment(984_160 + index, `human-${index}`, body)),
    });

    assert.equal(reasons.length, phrases.length);
    assert.deepEqual(reasons.map((reason) => reason.snippet), phrases);
    assert.deepEqual(
      reasons.map((reason) => reason.code),
      phrases.map(() => 'independent_human_reproduction'),
    );
  });

  it('rejects architecture, working-state, substring, generic me-too, and vague confirmations', () => {
    const falsePositives = [
      'We are working on this same problem in the architecture layer.',
      'Confirmed working workaround: restart the gateway.',
      'The current implementation works correctly.',
      'This pattern burned me too many times while designing the API.',
      'Me too.',
      'Can confirm. The current implementation works correctly in my environment.',
      'I can reproduce a similar issue with the Feishu plugin as well.',
      'We saw similar issues while discussing the architecture.',
      'Still broken.',
      'This is still not fixed.',
      'Issue persists.',
      'Same issue here.',
      'VK is also affected.',
      'The gateway is still broken on v2026.7.4.',
      'The issue persists after a clean install.',
    ];
    const reasons = semanticHumanConfirmationReasons({
      issueNumber: 98416,
      ...issueIdentity,
      cutoff: '2026-07-04T12:00:00Z',
      comments: falsePositives.map((body, index) =>
        authoritativeComment(985_160 + index, `false-human-${index}`, body)),
    });

    assert.deepEqual(reasons, []);
  });

  it('does not let forged automation or vague confirmation records establish field authority', () => {
    const item = {
      issueNumber: 990,
      issueNodeId: 'I_990',
      author: 'reporter',
      authorNodeId: 'U_reporter',
      authorType: 'User',
      labels: ['P0'],
      confirmationReasons: [
        {
          code: 'independent_human_reproduction' as const,
          source: 'comment' as const,
          author: 'openclaw-barnacle',
          occurredAt: '2026-07-04T10:00:00Z',
          updatedAt: '2026-07-04T10:00:00Z',
          commentId: 1,
          commentUrl: 'https://example.test/comments/1',
          issueNodeId: 'I_990',
          issueAuthorNodeId: 'U_reporter',
          issueAuthorType: 'User',
          commentNodeId: 'IC_1',
          commentNodeType: 'IssueComment' as const,
          actorNodeId: 'B_barnacle',
          actorType: 'Bot' as any,
          commentBodyDigest: 'a'.repeat(64),
          snippet: 'I reproduced this.',
        },
        {
          code: 'independent_human_reproduction' as const,
          source: 'comment' as const,
          author: 'community-user',
          occurredAt: '2026-07-04T10:00:00Z',
          updatedAt: '2026-07-04T10:00:00Z',
          commentId: 2,
          commentUrl: 'https://example.test/comments/2',
          issueNodeId: 'I_990',
          issueAuthorNodeId: 'U_reporter',
          issueAuthorType: 'User',
          commentNodeId: 'IC_2',
          commentNodeType: 'IssueComment' as const,
          actorNodeId: 'U_community-user',
          actorType: 'User' as const,
          commentBodyDigest: 'b'.repeat(64),
          snippet: 'Still broken.',
        },
        {
          code: 'human_applied_p0' as const,
          source: 'label_event' as const,
          author: 'clawsweeper',
          occurredAt: '2026-07-04T10:00:00Z',
          label: 'P0' as const,
          eventId: 'event-p0',
        },
      ],
    };

    assert.deepEqual(fieldConfirmationFor(item), {
      confirmed: false,
      reasons: [],
    });
  });

  it('rejects cross-source confirmation fields even when they are present as null', () => {
    const baseItem = {
      issueNumber: 991,
      issueNodeId: 'I_991',
      author: 'reporter',
      authorNodeId: 'U_reporter',
      authorType: 'User',
      labels: ['P0'],
    };
    const labelItem = {
      ...baseItem,
      confirmationReasons: [{
        code: 'human_applied_p0' as const,
        source: 'label_event' as const,
        author: 'human-maintainer',
        occurredAt: '2026-07-04T10:00:00Z',
        label: 'P0' as const,
        eventId: 'event-p0',
        association: null,
        commentUrl: null,
      }],
    };
    const commentItem = {
      ...baseItem,
      confirmationReasons: [{
        code: 'independent_human_reproduction' as const,
        source: 'comment' as const,
        author: 'community-user',
        association: 'NONE',
        occurredAt: '2026-07-04T10:00:00Z',
        updatedAt: '2026-07-04T10:00:00Z',
        commentId: 3,
        commentUrl: 'https://example.test/comments/3',
        issueNodeId: 'I_991',
        issueAuthorNodeId: 'U_reporter',
        issueAuthorType: 'User',
        commentNodeId: 'IC_3',
        commentNodeType: 'IssueComment' as const,
        actorNodeId: 'U_community-user',
        actorType: 'User' as const,
        commentBodyDigest: 'c'.repeat(64),
        snippet: 'I reproduced this crash after upgrading.',
        label: null,
      }],
    };

    assert.deepEqual(fieldConfirmationFor(labelItem as any), {
      confirmed: false,
      reasons: [],
    });
    assert.deepEqual(fieldConfirmationFor(commentItem as any), {
      confirmed: false,
      reasons: [],
    });
  });
});

describe('openDebtLoad — current issue debt', () => {
  const exactReleaseEvidence = (version = 'v2026.6.10') => ({
    kind: 'exact-version' as const,
    source: 'title' as const,
    version,
    snippet: `Failure in ${version}`,
  });
  const commentConfirmation = (author = 'second-reporter') => ({
    code: 'independent_human_reproduction' as const,
    source: 'comment' as const,
    author,
    occurredAt: '2026-06-11T12:00:00Z',
    updatedAt: '2026-06-11T12:00:00Z',
    commentId: 123,
    commentUrl: 'https://example.test/issues/1#issuecomment-123',
    issueNodeId: 'I_1',
    issueAuthorNodeId: 'U_reporter',
    issueAuthorType: 'User',
    commentNodeId: 'IC_123',
    commentNodeType: 'IssueComment' as const,
    actorNodeId: `U_${author}`,
    actorType: 'User' as const,
    commentBodyDigest: scoreCommentBodyDigest(
      'Can confirm, I reproduced this.',
    ),
    snippet: 'Can confirm, I reproduced this.',
    authorityReference: scoreCommentAuthorityReference({
      issueNumber: 1,
      issueNodeId: 'I_1',
      issueAuthorNodeId: 'U_reporter',
      issueAuthorType: 'User',
      commentNodeId: 'IC_123',
      commentId: 123,
      commentUrl: 'https://example.test/issues/1#issuecomment-123',
      actorNodeId: `U_${author}`,
      commentCreatedAt: '2026-06-11T12:00:00Z',
      commentUpdatedAt: '2026-06-11T12:00:00Z',
      commentBodyDigest: scoreCommentBodyDigest(
        'Can confirm, I reproduced this.',
      ),
      claimSnippet: 'Can confirm, I reproduced this.',
    }),
  });
  const labelConfirmation = (label: 'P0' | 'P1' | 'regression') => ({
    code: ({
      P0: 'human_applied_p0',
      P1: 'human_applied_p1',
      regression: 'human_applied_regression',
    } as const)[label],
    source: 'label_event' as const,
    author: 'human-maintainer',
    occurredAt: '2026-06-11T12:00:00Z',
    label,
    eventId: `event-${label}`,
    authorityReference: scoreLabelAuthorityReference({
      eventId: `event-${label}`,
      label,
    }),
  });
  const dc = (over: Record<string, any> = {}) => ({
    issueNumber: 1,
    issueNodeId: 'I_1',
    author: 'reporter',
    authorNodeId: 'U_reporter',
    authorType: 'User',
    state: 'open',
    sentiment: 'negative',
    severity: 'high',
    functionality: 'core',
    scope: 'moderate',
    affectedUsers: 'some',
    workaroundStatus: 'unknown',
    confidence: 0.9,
    duplicateCluster: null,
    ...(over.releaseLocal === true
      ? { releaseLocalEvidence: exactReleaseEvidence() }
      : {}),
    ...over,
  });

  it('ignores closed, positive, docs, and low-severity rows', () => {
    assert.deepEqual(openDebtLoad([dc({ state: 'closed' })]), { verified: 0, carryover: 0, stale: 0 });
    assert.deepEqual(openDebtLoad([dc({ sentiment: 'positive' })]), { verified: 0, carryover: 0, stale: 0 });
    assert.deepEqual(openDebtLoad([dc({ functionality: 'docs' })]), { verified: 0, carryover: 0, stale: 0 });
    assert.deepEqual(openDebtLoad([dc({ severity: 'low' })]), { verified: 0, carryover: 0, stale: 0 });
  });

  it('keeps classifier-only duplicate reports independent', () => {
    const one = openDebtLoad([dc({ duplicateCluster: 'same-bug', affectsVersion: 'v2026.6.10' })]).carryover;
    const repeated = openDebtLoad([
      dc({ issueNumber: 1, duplicateCluster: 'same-bug', affectsVersion: 'v2026.6.10' }),
      dc({ issueNumber: 2, duplicateCluster: 'same-bug', affectsVersion: 'v2026.6.10' }),
    ]).carryover;
    assert.equal(repeated, one * 2);
  });

  it('does not merge normalized classifier slug variants or namespaced issue identities', () => {
    const clusterVariants = ['Same Bug', ' same bug ', 'SAME\tBUG'];
    const clustered = openDebtLoad(clusterVariants.map((duplicateCluster, index) =>
      dc({ issueNumber: index + 1, duplicateCluster })
    ));
    const oneCluster = openDebtLoad([dc({ issueNumber: 1, duplicateCluster: 'same bug' })]);
    assert.equal(clustered.carryover, oneCluster.carryover * clusterVariants.length);

    const namespaced = openDebtLoad([
      dc({ issueNumber: 42, duplicateCluster: null }),
      dc({ issueNumber: 43, duplicateCluster: 'issue:42' }),
    ]);
    const oneIssue = openDebtLoad([dc({ issueNumber: 42, duplicateCluster: null })]);
    assert.equal(namespaced.verified, oneIssue.verified * 2);
  });

  it('does not use LLM duplicate-cluster reporter breadth as field/community evidence', () => {
    const clustered = openDebtLoad([
      dc({
        issueNumber: 201,
        duplicateCluster: 'reported-by-two-users',
        author: 'alice',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
      dc({
        issueNumber: 202,
        duplicateCluster: 'reported-by-two-users',
        author: 'bob',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(clustered.verified, 0);
    assert.ok(clustered.stale > 0);
  });

  it('keeps debt, regression load, score, and eligibility invariant to model confidence', () => {
    const objectiveEvidence = {
      issueNumber: 225,
      labels: [],
      releaseLocal: false,
      functionality: 'core',
      severity: 'high',
      scope: 'broad',
      affectedUsers: 'many',
    };
    const lowConfidence = dc({ ...objectiveEvidence, confidence: 0 });
    const highConfidence = dc({ ...objectiveEvidence, confidence: 1 });
    const lowDebt = explainOpenDebtLoad([lowConfidence]);
    const highDebt = explainOpenDebtLoad([highConfidence]);
    const lowFelt = feltLoad([lowConfidence]);
    const highFelt = feltLoad([highConfidence]);
    const lowResult = installConfidence(mk({
      carryoverDebtWeight: lowDebt.loads.carryover,
      feltOpenedWeight: lowFelt,
    }), NOW);
    const highResult = installConfidence(mk({
      carryoverDebtWeight: highDebt.loads.carryover,
      feltOpenedWeight: highFelt,
    }), NOW);

    assert.deepEqual(highDebt.loads, lowDebt.loads);
    assert.equal(highDebt.evidence[0]?.tier, lowDebt.evidence[0]?.tier);
    assert.equal(highDebt.evidence[0]?.weight, lowDebt.evidence[0]?.weight);
    assert.equal(highFelt, lowFelt);
    assert.equal(highResult.score, lowResult.score);
    assert.equal(isRecommendationEligible(highResult), isRecommendationEligible(lowResult));
  });

  it('does not count openclaw-barnacle as a human issue reporter', () => {
    const explanation = explainOpenDebtLoad([
      dc({
        issueNumber: 230,
        author: 'openclaw-barnacle',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);

    assert.equal(explanation.evidence[0]?.humanReporterCount, 0);
    assert.equal(explanation.loads.verified, 0);
  });

  it('does not transfer confirmation or release locality across classifier-cluster members', () => {
    const clustered = openDebtLoad([
      dc({
        issueNumber: 211,
        duplicateCluster: 'old-root-fresh-dupe',
        author: 'alice',
        labels: [],
        releaseLocal: false,
        functionality: 'core',
        severity: 'critical',
        scope: 'broad',
        confirmationReasons: [commentConfirmation('independent-generic-reporter')],
      }),
      dc({
        issueNumber: 212,
        duplicateCluster: 'old-root-fresh-dupe',
        author: 'bob',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'critical',
        scope: 'broad',
      }),
    ]);
    assert.equal(clustered.verified, 0);
    assert.ok(clustered.carryover > 0);
    assert.ok(clustered.stale > 0);
  });

  it('keeps independent debt entries across tiers when only classifier slugs match', () => {
    const explanation = explainOpenDebtLoad([
      dc({
        issueNumber: 213,
        duplicateCluster: 'mixed-tier-cluster',
        labels: ['stale'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
      dc({
        issueNumber: 214,
        duplicateCluster: 'mixed-tier-cluster',
        labels: [],
        releaseLocal: false,
        functionality: 'core',
        severity: 'critical',
        scope: 'broad',
      }),
    ]);
    assert.equal(explanation.evidence.filter((item) => item.duplicateCluster === 'mixed-tier-cluster').length, 2);
    assert.deepEqual(
      explanation.evidence
        .filter((item) => item.duplicateCluster === 'mixed-tier-cluster')
        .map((item) => item.tier)
        .sort(),
      ['carryover', 'stale'],
    );
  });

  it('keeps release-unresolved closed issues in debt accounting', () => {
    const explanation = explainOpenDebtLoad([
      dc({
        issueNumber: 230,
        state: 'closed-unverified',
        labels: ['bug', 'regression'],
        severity: 'high',
        functionality: 'core',
        scope: 'broad',
      }),
    ]);
    assert.equal(explanation.evidence.length, 1);
    assert.equal(explanation.evidence[0].releaseScopedState, 'closed-unverified');
    assert.ok(explanation.loads.carryover > 0);
  });

  it('keeps 100 unchanged carryover groups visible without changing the score', () => {
    const explanation = explainOpenDebtLoad(Array.from({ length: 100 }, (_, index) =>
      dc({
        issueNumber: 10_000 + index,
        duplicateCluster: `carryover-${index}`,
        releaseLocal: false,
        labels: [],
      })
    ));
    const baseline = installConfidence(mk(), NOW);
    const withCarryover = installConfidence(mk({
      carryoverDebtWeight: explanation.loads.carryover,
      carryoverDebtIssueCount: explanation.evidence.length,
    }), NOW);

    assert.equal(explanation.evidence.length, 100);
    assert.ok(explanation.loads.carryover > 0);
    assert.equal(withCarryover.components?.carryoverDebt, 0);
    assert.equal(withCarryover.score, baseline.score);
  });

  it('keeps classifier-slug peers additive instead of electing one contribution', () => {
    const explanation = explainOpenDebtLoad([
      dc({
        issueNumber: 231,
        duplicateCluster: 'strongest-adverse',
        labels: ['P0'],
        releaseLocal: true,
        severity: 'high',
        functionality: 'core',
        scope: 'moderate',
        affectedUsers: 'few',
        confidence: 0.65,
      }),
      dc({
        issueNumber: 232,
        duplicateCluster: 'strongest-adverse',
        releaseLocal: false,
        severity: 'critical',
        functionality: 'core',
        scope: 'broad',
        affectedUsers: 'many',
        confidence: 1,
      }),
    ]);
    assert.equal(explanation.evidence.length, 2);
    assert.deepEqual(
      explanation.evidence.map((item) => item.issueNumber).sort((a, b) => Number(a) - Number(b)),
      [231, 232],
    );
  });

  it('records install-impact class and multiplier in debt evidence', () => {
    const explanation = explainOpenDebtLoad([
      dc({
        issueNumber: 215,
        title: 'provider catalog lookup fails',
        labels: ['bug', 'impact:auth-provider'],
        functionality: 'provider',
        severity: 'high',
      }),
    ]);
    assert.equal(explanation.evidence[0]?.installImpactClass, 'provider');
    assert.equal(explanation.evidence[0]?.installImpactMultiplier, 0.65);
  });

  it('does not treat commenter participation alone as field confirmation', () => {
    const discussed = openDebtLoad([
      dc({
        issueNumber: 203,
        uniqueHumanCommenterCount: 2,
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(discussed.verified, 0);
    assert.ok(discussed.stale > 0);
  });

  it('does not let duplicate issue authors confirm high-impact integration regressions', () => {
    const confirmed = openDebtLoad([
      dc({
        issueNumber: 219,
        duplicateCluster: 'integration-regression',
        author: 'alice',
        releaseLocal: true,
        functionality: 'integration',
        severity: 'high',
        scope: 'broad',
      }),
      dc({
        issueNumber: 220,
        duplicateCluster: 'integration-regression',
        author: 'bob',
        releaseLocal: true,
        functionality: 'integration',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(confirmed.verified, 0);
    assert.ok(confirmed.carryover > 0);
  });

  it('does not let closed duplicate-cluster members confirm an open report', () => {
    const debt = openDebtLoad([
      dc({
        issueNumber: 221,
        state: 'open',
        duplicateCluster: 'mixed-state-cluster',
        author: 'alice',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
      dc({
        issueNumber: 222,
        state: 'closed',
        duplicateCluster: 'mixed-state-cluster',
        author: 'bob',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(debt.verified, 0);
    assert.ok(debt.stale > 0);
  });

  it('does not use maintainer-only comments as field/community confirmation', () => {
    const discussed = openDebtLoad([
      dc({
        issueNumber: 216,
        uniqueHumanCommenterCount: 2,
        maintainerCommenterCount: 2,
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(discussed.verified, 0);
    assert.ok(discussed.stale > 0);
  });

  it('does not use maintainer duplicate reporters as field/community confirmation', () => {
    const clustered = openDebtLoad([
      dc({
        issueNumber: 217,
        duplicateCluster: 'maintainer-only-cluster',
        author: 'maintainer-a',
        authorAssociation: 'MEMBER',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
      dc({
        issueNumber: 218,
        duplicateCluster: 'maintainer-only-cluster',
        author: 'maintainer-b',
        authorAssociation: 'OWNER',
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(clustered.verified, 0);
    assert.ok(clustered.stale > 0);
  });

  it('does not use raw comment volume alone as field/community evidence', () => {
    const discussed = openDebtLoad([
      dc({
        issueNumber: 204,
        comments: 12,
        uniqueHumanCommenterCount: 0,
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(discussed.verified, 0);
    assert.ok(discussed.stale > 0);
  });

  it('reduces debt for confirmed workarounds', () => {
    const blocker = {
      releaseLocal: true,
      labels: ['P0'],
      functionality: 'core',
      severity: 'high',
      scope: 'broad',
      confirmationReasons: [labelConfirmation('P0')],
    };
    const none = openDebtLoad([dc({ ...blocker, workaroundStatus: 'none' })]).verified;
    const confirmed = openDebtLoad([dc({ ...blocker, workaroundStatus: 'confirmed' })]).verified;
    assert.ok(confirmed < none);
  });

  it('keeps old source-repro evidence in capped stale debt, not verified release debt', () => {
    const sourceOnly = openDebtLoad([
      dc({
        issueNumber: 99,
        labels: ['clawsweeper:source-repro'],
        releaseLocal: false,
        affectsVersion: null,
      }),
    ]);
    assert.equal(sourceOnly.verified, 0);
    assert.equal(sourceOnly.carryover, 0);
    assert.ok(sourceOnly.stale > 0);
  });

  it('does not treat release-local source-repro-only issues as verified field debt', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 100,
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
      }),
    ]);
    assert.equal(local.verified, 0);
    assert.ok(local.stale > 0);
  });

  it('does not treat sweeper-only workflow labels as verified field debt', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 101,
        labels: [
          'clawsweeper:source-repro',
          'clawsweeper:fix-shape-clear',
          'clawsweeper:no-new-fix-pr',
          'clawsweeper:needs-maintainer-review',
        ],
        releaseLocal: true,
        functionality: 'core',
        severity: 'critical',
        scope: 'broad',
        affectedUsers: 'many',
      }),
    ]);
    assert.equal(local.verified, 0);
    assert.ok(local.stale > 0);
  });

  it('treats release-local P0 core blockers as verified field debt', () => {
    const explanation = explainOpenDebtLoad([
      dc({
        issueNumber: 102,
        labels: ['P0'],
        confirmationReasons: [labelConfirmation('P0')],
        releaseLocal: true,
        functionality: 'core',
        severity: 'critical',
        scope: 'moderate',
        affectedUsers: 'some',
      }),
    ]);
    assert.ok(explanation.loads.verified > 0);
    assert.deepEqual(
      explanation.evidence[0]?.releaseLocalEvidence,
      exactReleaseEvidence(),
    );
  });

  it('treats release-local P1 bug regressions as verified field debt', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 103,
        labels: ['bug', 'regression', 'P1'],
        confirmationReasons: [
          labelConfirmation('P1'),
          labelConfirmation('regression'),
        ],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
        affectedUsers: 'some',
      }),
    ]);
    assert.ok(local.verified > 0);
  });

  it('does not treat P1 alone as verified field debt', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 104,
        labels: ['P1'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
        affectedUsers: 'some',
      }),
    ]);
    assert.equal(local.verified, 0);
    assert.ok(local.carryover > 0);
  });

  it('does not let classifier-only affectsVersion stand in for exact release evidence', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 105,
        labels: ['P0'],
        releaseLocal: true,
        releaseLocalEvidence: undefined,
        affectsVersion: 'v2026.6.10',
        functionality: 'core',
        severity: 'critical',
        scope: 'broad',
        affectedUsers: 'many',
      }),
    ]);
    assert.equal(local.verified, 0);
    assert.ok(local.carryover > 0);
  });

  it('does not let timing-only releaseLocal state stand in for exact release evidence', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 106,
        labels: ['P0'],
        releaseLocal: true,
        releaseLocalEvidence: undefined,
        createdAt: '2026-06-11T12:00:00Z',
        functionality: 'core',
        severity: 'critical',
        scope: 'broad',
        affectedUsers: 'many',
      }),
    ]);
    assert.equal(local.verified, 0);
    assert.ok(local.carryover > 0);
  });

  it('does not let structurally invalid release-local evidence establish verified debt', () => {
    const malformedEvidence = [
      {
        ...exactReleaseEvidence(),
        commentId: null,
      },
      {
        kind: 'exact-version',
        source: 'comment',
        version: 'v2026.6.10',
        snippet: 'The crash reproduces on v2026.6.10.',
        commentId: 123,
        commentUrl: 'https://example.test/issues/1#issuecomment-123',
        commentNodeId: 'IC_123',
        author: 'second-reporter',
        actorNodeId: 'U_second-reporter',
        actorType: 'User',
        occurredAt: '2026-06-11T12:00:00Z',
        updatedAt: '2026-06-11T12:00:00Z',
        commentBodyDigest: 'd'.repeat(64),
      },
    ];
    for (const releaseLocalEvidence of malformedEvidence) {
      const explanation = explainOpenDebtLoad([
        dc({
          issueNumber: 107,
          labels: ['P0'],
          confirmationReasons: [labelConfirmation('P0')],
          releaseLocal: true,
          releaseLocalEvidence,
          functionality: 'core',
          severity: 'critical',
          scope: 'broad',
          affectedUsers: 'many',
        }),
      ]);
      assert.equal(explanation.loads.verified, 0);
      assert.ok(explanation.loads.carryover > 0);
      assert.equal(explanation.evidence[0]?.releaseLocalEvidence, undefined);
      assert.equal(explanation.evidence[0]?.clusterReleaseLocal, false);
    }
  });

  it('does not let needs-live-repro issues drive visible regression load', () => {
    const load = feltLoad([
      dc({
        labels: ['bug', 'regression', 'P1', 'clawsweeper:needs-live-repro'],
        functionality: 'provider',
        severity: 'critical',
        confidence: 0.5,
      }),
    ]);
    assert.equal(load, 0);
  });

  it('does not count source-repro clusters as field-visible from LLM reporter grouping', () => {
    const solo = feltLoad([
      dc({ labels: ['clawsweeper:source-repro'], author: 'alice' }),
    ]);
    const clustered = feltLoad([
      dc({ labels: ['clawsweeper:source-repro'], author: 'alice', duplicateCluster: 'same-visible-bug' }),
      dc({ labels: ['clawsweeper:source-repro'], author: 'bob', duplicateCluster: 'same-visible-bug' }),
    ]);
    assert.equal(solo, 0);
    assert.equal(clustered, 0);
  });

  it('keeps reactions and neutral discussion volume out of source-only debt weight', () => {
    const plain = openDebtLoad([
      dc({ labels: ['clawsweeper:source-repro'], releaseLocal: true, functionality: 'core', severity: 'high', scope: 'broad' }),
    ]);
    const reacted = openDebtLoad([
      dc({
        labels: ['clawsweeper:source-repro'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
        comments: 40,
        uniqueHumanCommenterCount: 12,
        contributorCommenterCount: 8,
        positiveReactionCount: 10,
      }),
    ]);
    assert.equal(reacted.verified, 0);
    assert.equal(reacted.stale, plain.stale);
  });

  it('keeps discussion and reaction volume out of inherited carryover weight', () => {
    const plain = openDebtLoad([
      dc({ labels: [], releaseLocal: false }),
    ]);
    const discussed = openDebtLoad([
      dc({
        labels: [],
        releaseLocal: false,
        comments: 40,
        uniqueHumanCommenterCount: 12,
        contributorCommenterCount: 8,
        positiveReactionCount: 20,
      }),
    ]);
    assert.equal(discussed.carryover, plain.carryover);
  });

  it('keeps discussion and reaction volume out of regression weight', () => {
    const plain = feltLoad([dc({ labels: [] })]);
    const discussed = feltLoad([dc({
      labels: [],
      comments: 40,
      uniqueHumanCommenterCount: 12,
      contributorCommenterCount: 8,
      positiveReactionCount: 20,
    })]);
    assert.equal(discussed, plain);
    assert.equal(
      score({ feltOpenedWeight: discussed }),
      score({ feltOpenedWeight: plain }),
    );
  });

  it('keeps affected-user reach and score weight invariant across raw participation counts', () => {
    const semantic = dc({
      title: 'The default Windows configuration exits during startup',
      affectedUsers: 'unknown',
      labels: [],
      releaseLocal: false,
    });
    const quietDebt = openDebtLoad([semantic]);
    const busyDebt = openDebtLoad([{
      ...semantic,
      comments: 500,
      humanReporterCount: 75,
      uniqueHumanCommenterCount: 120,
      maintainerCommenterCount: 20,
      contributorCommenterCount: 30,
      reactionTotal: 1_000,
      positiveReactionCount: 900,
    }]);
    const quietRegression = feltLoad([semantic]);
    const busyRegression = feltLoad([{
      ...semantic,
      comments: 500,
      humanReporterCount: 75,
      uniqueHumanCommenterCount: 120,
      maintainerCommenterCount: 20,
      contributorCommenterCount: 30,
      reactionTotal: 1_000,
      positiveReactionCount: 900,
    }]);

    assert.deepEqual(busyDebt, quietDebt);
    assert.equal(busyRegression, quietRegression);
    assert.equal(
      score({ carryoverDebtWeight: busyDebt.carryover, feltOpenedWeight: busyRegression }),
      score({ carryoverDebtWeight: quietDebt.carryover, feltOpenedWeight: quietRegression }),
    );
  });

  it('dampens security/design debt compared with install-impact data loss', () => {
    const dataLoss = openDebtLoad([
      dc({
        title: 'sessions cleanup prunes fresh cron sessions',
        labels: ['clawsweeper:source-repro', 'impact:data-loss'],
        functionality: 'core',
        severity: 'critical',
        scope: 'broad',
        affectedUsers: 'many',
      }),
    ]).stale;
    const security = openDebtLoad([
      dc({
        title: 'Installer executes downloaded scripts without validation',
        labels: ['security', 'impact:security', 'clawsweeper:source-repro'],
        functionality: 'core',
        severity: 'high',
        scope: 'broad',
        affectedUsers: 'many',
      }),
    ]).stale;
    assert.ok(security > 0);
    assert.ok(security < dataLoss);
  });

  it('does not let a security label reduce verified installer debt or improve recommendation eligibility', () => {
    const installerBlocker = dc({
      title: 'Installer executes downloaded scripts without validation',
      labels: ['P0', 'impact:security'],
      releaseLocal: true,
      confirmationReasons: [labelConfirmation('P0')],
      functionality: 'core',
      severity: 'high',
      scope: 'broad',
      affectedUsers: 'many',
    });
    const beforeDebt = explainOpenDebtLoad([installerBlocker]);
    const afterDebt = explainOpenDebtLoad([{
      ...installerBlocker,
      labels: [...installerBlocker.labels, 'security'],
    }]);
    const before = installConfidence(mk({
      verifiedDebtWeight: beforeDebt.loads.verified,
    }), NOW);
    const after = installConfidence(mk({
      verifiedDebtWeight: afterDebt.loads.verified,
    }), NOW);

    assert.equal(beforeDebt.evidence[0]?.installImpactClass, 'state_data');
    assert.equal(afterDebt.evidence[0]?.installImpactClass, 'security');
    assert.equal(afterDebt.evidence[0]?.installImpactMultiplier, beforeDebt.evidence[0]?.installImpactMultiplier);
    assert.ok(afterDebt.loads.verified >= beforeDebt.loads.verified);
    assert.ok(after.score! <= before.score!, `security label raised score (${before.score} -> ${after.score})`);
    assert.ok(!isRecommendationEligible(after) || isRecommendationEligible(before));
  });

  it('dampens provider catalog issues compared with core state loss', () => {
    const core = openDebtLoad([
      dc({
        title: 'session transcript split mid-run',
        labels: ['clawsweeper:source-repro', 'impact:data-loss'],
        functionality: 'core',
        severity: 'critical',
        scope: 'moderate',
        affectedUsers: 'some',
      }),
    ]).stale;
    const provider = openDebtLoad([
      dc({
        title: 'Google vertex models cannot be overridden via openclaw.json',
        labels: ['bug', 'impact:auth-provider', 'clawsweeper:source-repro'],
        functionality: 'provider',
        severity: 'critical',
        scope: 'moderate',
        affectedUsers: 'some',
      }),
    ]).stale;
    assert.ok(provider > 0);
    assert.ok(provider < core);
  });
});

describe('pickRecommended — strongest eligible with bounded recency preference', () => {
  it('does not let a materially weaker newer release outrank the strongest candidate', () => {
    const tag = pickRecommended([
      { tag: 'v3', status: 'wait', score: null },          // too new
      { tag: 'v2', status: 'eligible', score: REC_THRESHOLD },
      { tag: 'v1', status: 'eligible', score: 9.0 },
    ]);
    assert.equal(tag, 'v1');
  });

  it('prefers the newest candidate within the confidence tolerance', () => {
    const tag = pickRecommended([
      { tag: 'v3', status: 'eligible', score: 7.5 },
      { tag: 'v2', status: 'eligible', score: 7.5 + RECOMMENDATION_RECENCY_TOLERANCE },
      { tag: 'v1', status: 'eligible', score: 7.9 },
    ]);
    assert.equal(tag, 'v3');
  });

  it('uses decimal-safe tolerance at the reported 8.3 vs 7.8 boundary', () => {
    assert.equal(withinDecimalTolerance(7.8, 8.3, 0.5), true);
    assert.equal(pickRecommended([
      {
        tag: 'v-new',
        publishedAt: '2026-07-04T00:00:00Z',
        status: 'eligible',
        score: 7.8,
      },
      {
        tag: 'v-old',
        publishedAt: '2026-07-03T00:00:00Z',
        status: 'eligible',
        score: 8.3,
      },
    ]), 'v-new');
  });

  it('uses release recency rather than caller array order', () => {
    const releases = [
      {
        tag: 'v2026.7.3',
        publishedAt: '2026-07-03T00:00:00Z',
        status: 'eligible' as const,
        score: 8.3,
      },
      {
        tag: 'v2026.7.4',
        publishedAt: '2026-07-04T00:00:00Z',
        status: 'eligible' as const,
        score: 7.8,
      },
    ];
    assert.equal(pickRecommended(releases), 'v2026.7.4');
    assert.equal(pickRecommended(releases.slice().reverse()), 'v2026.7.4');
  });

  it('skips hotfixed / gated / weak releases below the threshold', () => {
    const tag = pickRecommended([
      { tag: 'v4', status: 'skip-hotfix', score: 4.9 },
      { tag: 'v3', status: 'skip-cve', score: 1.5 },
      { tag: 'v2', status: 'eligible', score: 6.9 },
      { tag: 'v1', status: 'eligible', score: 8.0 }, // first that qualifies
    ]);
    assert.equal(tag, 'v1');
  });

  it('returns null when nothing qualifies', () => {
    assert.equal(
      pickRecommended([
        { tag: 'v2', status: 'wait', score: null },
        { tag: 'v1', status: 'skip-hotfix', score: 4.0 },
      ]),
      null,
    );
  });
});

describe('exclusive issue risk ledger', () => {
  it('charges one alias group in exactly one adverse channel', () => {
    const debt = explainOpenDebtLoad([
      {
        issueNumber: 1,
        state: 'closed-unverified',
        aliasGroup: 'issue:1',
        sentiment: 'negative',
        severity: 'critical',
        functionality: 'core',
        scope: 'broad',
        affectedUsers: 'many',
        labels: [],
      },
    ]);
    const regression = explainFeltLoad([
      {
        issueNumber: 1,
        aliasGroup: 'issue:1',
        sentiment: 'negative',
        severity: 'high',
        functionality: 'integration',
        scope: 'moderate',
        affectedUsers: 'some',
      },
    ]);
    const closureRisk = aggregateClosureRisk([{
      issueNumber: 1,
      aliasGroup: 'issue:1',
      disposition: 'missing_evidence',
      weight: 8,
    }]);
    const accounting = applyExclusiveIssueRiskLedger({ debt, regression, closureRisk });
    const selectedChannels = [
      accounting.debt.loads.verified > 0 || accounting.debt.loads.stale > 0,
      accounting.regression.load > 0,
      accounting.closureRisk.unresolvedWeightedRisk > 0,
    ].filter(Boolean);
    assert.equal(selectedChannels.length, 1);
    assert.equal(accounting.debt.loads.carryover, 0);
    assert.equal(accounting.ledger.groups.length, 1);
    assert.equal(
      accounting.ledger.totalsByChannel.carryover,
      accounting.debt.loads.carryover,
    );
  });

  it('keeps a heavy affirmative closure ceiling when verified debt wins the alias channel', () => {
    const debt = explainOpenDebtLoad([{
      issueNumber: 1,
      state: 'closed-unverified',
      aliasGroup: 'issue:1',
      sentiment: 'negative',
      severity: 'critical',
      functionality: 'core',
      scope: 'broad',
      affectedUsers: 'many',
      releaseLocal: true,
      releaseLocalEvidence: {
        kind: 'exact-version',
        source: 'body',
        version: 'v2026.7.4',
        snippet: 'OpenClaw v2026.7.4 fails for all default installs.',
      },
      labels: ['P0'],
      confirmationReasons: [{
        code: 'human_applied_p0',
        source: 'label_event',
        author: 'maintainer',
        occurredAt: '2026-07-04T00:00:00Z',
        label: 'P0',
        eventId: 'label-p0-issue-1',
        authorityReference: scoreLabelAuthorityReference({
          eventId: 'label-p0-issue-1',
          label: 'P0',
          issueNumber: 1,
          eventTime: '2026-07-04T00:00:00Z',
        }),
      }],
    }]);
    const regression = explainFeltLoad([]);
    const affirmativeClosureRisk = aggregateClosureRisk([{
      issueNumber: 1,
      aliasGroup: 'issue:1',
      disposition: 'known_not_in_release',
      weight: 80,
    }]);
    const accounting = applyExclusiveIssueRiskLedger({
      debt,
      regression,
      closureRisk: affirmativeClosureRisk,
    });
    const result = installConfidence(mk({
      hoursToNextStable: 96,
      betaCount: 10,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 7,
      releaseCheckSuccess: 7,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
      verifiedDebtWeight: accounting.debt.loads.verified,
      unresolvedClosureRiskWeight: accounting.closureRisk.unresolvedWeightedRisk,
      affirmativeClosureRiskCeilingWeight:
        affirmativeClosureRisk.unresolvedWeightedRisk,
    }), NOW);

    assert.ok(accounting.debt.loads.verified > 0);
    assert.equal(accounting.closureRisk.unresolvedWeightedRisk, 0);
    assert.equal(Math.abs(result.components?.closureRisk ?? NaN), 0);
    assert.equal(result.components?.closureRiskCeiling, 7.9);
    assert.equal(result.score, 7.9);
  });

  it('never replaces a stronger group contribution with a weaker duplicate row', () => {
    const before = buildExclusiveIssueRiskLedger([{
      aliasGroup: 'issue:1',
      channel: 'verified',
      weight: 10,
      issueNumber: 1,
    }]);
    const after = buildExclusiveIssueRiskLedger([
      {
        aliasGroup: 'issue:1',
        channel: 'verified',
        weight: 10,
        issueNumber: 1,
      },
      {
        aliasGroup: 'issue:1',
        channel: 'stale',
        weight: 0.1,
        issueNumber: 2,
      },
    ]);
    assert.ok(after.groups[0].adversePoints >= before.groups[0].adversePoints);
    assert.equal(after.groups[0].selectedChannel, 'verified');
  });

  it('elects the locally strongest contribution independently of saturated unrelated tiers', () => {
    const targetCandidates = [
      {
        aliasGroup: 'target',
        channel: 'stale' as const,
        weight: 1.4625,
        issueNumber: 2,
      },
      {
        aliasGroup: 'target',
        channel: 'verified' as const,
        weight: 7.333,
        issueNumber: 3,
      },
    ];
    const isolated = buildExclusiveIssueRiskLedger(targetCandidates);
    const withSaturatedBackground = buildExclusiveIssueRiskLedger([
      {
        aliasGroup: 'verified-background',
        channel: 'verified',
        weight: 400,
        issueNumber: 1,
      },
      ...targetCandidates,
    ]);
    const isolatedTarget = isolated.groups.find((group) => group.aliasGroup === 'target');
    const backgroundTarget = withSaturatedBackground.groups.find((group) =>
      group.aliasGroup === 'target');

    assert.equal(isolatedTarget?.selectedChannel, 'verified');
    assert.deepEqual(backgroundTarget, isolatedTarget);
    assert.ok(
      (backgroundTarget?.adversePoints ?? 0) >=
        Math.max(...targetCandidates.map((candidate) =>
          buildExclusiveIssueRiskLedger([candidate]).groups[0].adversePoints)),
    );
  });

  it('keeps each alias election unchanged when unrelated groups are added', () => {
    const groupB = [
      { aliasGroup: 'group-b', channel: 'regression' as const, weight: 363.6, issueNumber: 2 },
      { aliasGroup: 'group-b', channel: 'verified' as const, weight: 83.6, issueNumber: 2 },
    ];
    const isolated = buildExclusiveIssueRiskLedger(groupB);
    const combined = buildExclusiveIssueRiskLedger([
      { aliasGroup: 'group-a', channel: 'closureRisk', weight: 315.6, issueNumber: 1 },
      { aliasGroup: 'group-a', channel: 'verified', weight: 409.3, issueNumber: 1 },
      ...groupB,
    ]);

    assert.deepEqual(
      combined.groups.find((group) => group.aliasGroup === 'group-b'),
      isolated.groups[0],
    );
    assert.equal(isolated.groups[0].selectedChannel, 'verified');
  });

  it('does not let legacy search bounds alter the deterministic local election', () => {
    const candidates = [
      { aliasGroup: 'group-a', channel: 'verified' as const, weight: 2 },
      { aliasGroup: 'group-a', channel: 'stale' as const, weight: 2 },
    ];
    assert.deepEqual(
      buildExclusiveIssueRiskLedger(candidates, { maxSearchNodes: 1 }),
      buildExclusiveIssueRiskLedger(candidates),
    );
  });

  it('keeps one versus many duplicate reports invariant across every score and fix channel', () => {
    for (const channel of [
      'verified',
      'carryover',
      'stale',
      'closureRisk',
      'regression',
    ] as const) {
      const one = buildExclusiveIssueRiskLedger([{
        aliasGroup: 'issue:99',
        channel,
        weight: 4,
        issueNumber: 99,
      }]);
      const many = buildExclusiveIssueRiskLedger(Array.from({ length: 20 }, (_, index) => ({
        aliasGroup: 'issue:99',
        channel,
        weight: 4,
        issueNumber: 99 + index,
      })));
      assert.deepEqual(many.totalsByChannel, one.totalsByChannel, channel);
      assert.equal(many.groups.length, 1, channel);

      const inputFor = (ledger: ReturnType<typeof buildExclusiveIssueRiskLedger>) => mk({
        verifiedDebtWeight: ledger.totalsByChannel.verified,
        carryoverDebtWeight: ledger.totalsByChannel.carryover,
        staleDebtWeight: ledger.totalsByChannel.stale,
        unresolvedClosureRiskWeight: ledger.totalsByChannel.closureRisk,
        affirmativeClosureRiskCeilingWeight: ledger.totalsByChannel.closureRisk,
        feltOpenedWeight: ledger.totalsByChannel.regression,
      });
      assert.equal(
        installConfidence(inputFor(many), NOW).score,
        installConfidence(inputFor(one), NOW).score,
        channel,
      );
    }

    const fixedReport = {
      aliasGroup: 'issue:99',
      sentiment: 'negative',
      severity: 'high',
      functionality: 'core',
      scope: 'broad',
      affectedUsers: 'many',
    };
    const oneFixCredit = feltLoad([{ ...fixedReport, issueNumber: 99 }]);
    const manyFixCredit = feltLoad(Array.from({ length: 20 }, (_, index) => ({
      ...fixedReport,
      issueNumber: 99 + index,
    })));
    assert.equal(manyFixCredit, oneFixCredit);
    assert.equal(
      installConfidence(mk({ feltClosedWeight: manyFixCredit }), NOW).score,
      installConfidence(mk({ feltClosedWeight: oneFixCredit }), NOW).score,
    );
  });
});

describe('adverse transition monotonicity properties', () => {
  it('never raises numeric score across randomized adverse transitions', () => {
    const random = deterministicRandom(0x20_2026);
    for (let index = 0; index < 500; index++) {
      const base = {
        verifiedDebtWeight: random() * 50,
        carryoverDebtWeight: random() * 50,
        staleDebtWeight: random() * 50,
        unresolvedClosureRiskWeight: random() * 80,
        feltOpenedWeight: random() * 40,
        feltClosedWeight: random() * 40,
        breakingCount: Math.floor(random() * 4),
      };
      for (const field of [
        'verifiedDebtWeight',
        'carryoverDebtWeight',
        'staleDebtWeight',
        'unresolvedClosureRiskWeight',
        'feltOpenedWeight',
        'breakingCount',
      ] as const) {
        const before = score(base);
        const after = score({
          ...base,
          [field]: base[field] + (field === 'breakingCount' ? 1 : random() * 20 + 0.01),
        });
        assert.ok(after <= before, `${field} raised score (${before} -> ${after})`);
      }

      const pending = Math.floor(random() * 1_000_000);
      const failures = Math.floor(random() * 20);
      const beforeChecks = score({
        releaseCheckState: failures > 0 ? 'FAILURE' : pending > 0 ? 'PENDING' : null,
        releaseCheckTotal: pending + failures,
        releaseCheckPending: pending,
        releaseCheckFailure: failures,
      });
      const afterChecks = score({
        releaseCheckState: 'FAILURE',
        releaseCheckTotal: pending + failures + 1,
        releaseCheckPending: pending,
        releaseCheckFailure: failures + 1,
      });
      assert.ok(afterChecks <= beforeChecks, `check failures raised score (${beforeChecks} -> ${afterChecks})`);

      const cveLoad = random() * 40;
      const beforeAffected = installConfidence(mk({ ...base, cveAffected: false, cveLoad: 0 }), NOW);
      const afterAffected = installConfidence(mk({ ...base, cveAffected: true, cveLoad }), NOW);
      assert.ok(beforeAffected.score != null && afterAffected.score != null);
      assert.ok(
        afterAffected.score <= beforeAffected.score,
        `cveAffected false->true raised score (${beforeAffected.score} -> ${afterAffected.score})`,
      );
      const beforeCve = installConfidence(mk({ cveAffected: true, cveLoad }), NOW);
      const afterCve = installConfidence(mk({ cveAffected: true, cveLoad: cveLoad + random() * 10 }), NOW);
      assert.equal(beforeCve.status, 'skip-cve');
      assert.equal(afterCve.status, 'skip-cve');
      assert.ok(afterCve.score! <= beforeCve.score!, `CVE exposure raised score (${beforeCve.score} -> ${afterCve.score})`);
    }
  });

  it('never weakens a group election or changes unrelated groups for stronger cross-tier duplicates', () => {
    const random = deterministicRandom(0xded0_2026);
    for (let index = 0; index < 500; index++) {
      const background = [
        {
          aliasGroup: 'verified-background',
          channel: 'verified' as const,
          weight: 0.01 + random() * 600,
          issueNumber: 1,
        },
        {
          aliasGroup: 'stale-background',
          channel: 'stale' as const,
          weight: 0.01 + random() * 100,
          issueNumber: 2,
        },
      ];
      const target = {
        aliasGroup: 'target',
        channel: 'stale' as const,
        weight: 0.01 + random() * 50,
        issueNumber: 3,
      };
      const strongerDuplicate = {
        aliasGroup: 'target',
        channel: 'verified' as const,
        weight: 1 + random() * 20,
        issueNumber: 4,
      };
      const beforeLedger = buildExclusiveIssueRiskLedger([...background, target]);
      const afterLedger = buildExclusiveIssueRiskLedger([...background, target, strongerDuplicate]);
      const beforeTarget = beforeLedger.groups.find((group) => group.aliasGroup === 'target')!;
      const afterTarget = afterLedger.groups.find((group) => group.aliasGroup === 'target')!;
      assert.ok(
        afterTarget.adversePoints + Number.EPSILON >= beforeTarget.adversePoints,
        `case ${index}: target adverse contribution fell`,
      );
      assert.deepEqual(
        afterLedger.groups.filter((group) => group.aliasGroup !== 'target'),
        beforeLedger.groups.filter((group) => group.aliasGroup !== 'target'),
        `case ${index}: unrelated group election changed`,
      );
    }
  });

  it('never improves debt, score, or recommendation eligibility when security is the only added label', () => {
    const random = deterministicRandom(0x5ec0_2026);
    const cases = [
      {
        title: 'Installer migration loses session state',
        labels: ['P0', 'impact:session-state'],
        functionality: 'core',
      },
      {
        title: 'Provider catalog authentication fails',
        labels: ['P0', 'impact:auth-provider'],
        functionality: 'provider',
      },
      {
        title: 'Message delivery drops queued output',
        labels: ['P0', 'impact:message-loss'],
        functionality: 'integration',
      },
      {
        title: 'Runtime command exits unexpectedly',
        labels: ['P0'],
        functionality: 'core',
      },
    ] as const;
    for (let index = 0; index < 500; index++) {
      const variant = cases[Math.floor(random() * cases.length)];
      const issue = {
        issueNumber: index + 1,
        state: 'open',
        title: variant.title,
        labels: [...variant.labels],
        sentiment: 'negative',
        severity: random() < 0.5 ? 'high' : 'critical',
        functionality: variant.functionality,
        scope: random() < 0.5 ? 'moderate' : 'broad',
        affectedUsers: random() < 0.5 ? 'some' : 'many',
        workaroundStatus: 'unknown',
        confidence: 0.65 + random() * 0.35,
        releaseLocal: true,
        releaseLocalEvidence: {
          kind: 'exact-version' as const,
          source: 'title' as const,
          version: 'v2026.7.4',
          snippet: `Failure in v2026.7.4: ${variant.title}`,
        },
        confirmationReasons: [{
          code: 'human_applied_p0' as const,
          source: 'label_event' as const,
          author: 'human-maintainer',
          occurredAt: '2026-07-04T00:00:00Z',
          label: 'P0',
          eventId: `security-property-${index}`,
        }],
      };
      const beforeDebt = explainOpenDebtLoad([issue]);
      const afterDebt = explainOpenDebtLoad([{
        ...issue,
        labels: [...issue.labels, 'security'],
      }]);
      const shared = {
        feltOpenedWeight: random() * 10,
        betaCount: Math.floor(random() * 4),
      };
      const before = installConfidence(mk({
        ...shared,
        verifiedDebtWeight: beforeDebt.loads.verified,
      }), NOW);
      const after = installConfidence(mk({
        ...shared,
        verifiedDebtWeight: afterDebt.loads.verified,
      }), NOW);

      assert.ok(
        afterDebt.loads.verified + Number.EPSILON >= beforeDebt.loads.verified,
        `case ${index}: security label reduced debt`,
      );
      assert.ok(after.score! <= before.score!, `case ${index}: score rose (${before.score} -> ${after.score})`);
      assert.ok(
        !isRecommendationEligible(after) || isRecommendationEligible(before),
        `case ${index}: recommendation became eligible`,
      );
    }
  });
});

describe('ScoreLedgerV2', () => {
  it('keeps the 26th evidence identity in the exhaustive manifest while previews stay capped', () => {
    const input = mk({ verifiedDebtWeight: 5 });
    const confidence = installConfidence(input, NOW);
    const aliasElection = buildExclusiveIssueRiskLedger(
      Array.from({ length: 26 }, (_, index) => ({
        aliasGroup: `issue:${index + 1}`,
        channel: 'verified' as const,
        weight: 5 / 26,
        issueNumber: index + 1,
      })),
    );
    const ledger = buildScoreLedgerV2({
      input,
      confidence,
      now: NOW,
      aliasElection,
      evidenceSources: [{
        key: 'verifiedDebt',
        refs: Array.from({ length: 26 }, (_, index) => ({
          kind: 'issue',
          identity: `issue:${index + 1}`,
          payload: {
            issueNumber: index + 1,
            aliasGroup: `issue:${index + 1}`,
            tier: 'verified',
            weight: 5 / 26,
          },
        })),
      }],
    });
    const manifest = ledger.evidence.manifests.find((item) => item.key === 'verifiedDebt')!;
    const preview = ledger.evidence.previews.find((item) => item.key === 'verifiedDebt')!;
    assert.equal(manifest.count, 26);
    assert.equal(manifest.refs.length, 26);
    assert.equal(preview.refs.length, 25);
    assert.equal(preview.truncated, true);
    assert.ok(manifest.refs.some((ref) => ref.identity === 'issue:26'));
    assert.deepEqual(scoreLedgerV2Problems(ledger, { input, confidence }), []);

    const tampered = structuredClone(ledger);
    tampered.evidence.manifests.find((item) => item.key === 'verifiedDebt')!.refs[25].digest =
      '0'.repeat(64);
    assert.ok(scoreLedgerV2Problems(tampered, { input, confidence }).some((problem) =>
      /manifest verifiedDebt digest|semantic replay|ledger digest/.test(problem)));
  });

  it('records binding upper and lower score range clamps explicitly', () => {
    const upperInput = mk({
      isLatest: true,
      publishedAt: daysAgo(365),
      hoursToNextStable: null,
      betaCount: 1_000,
      feltClosedWeight: 1_000,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 1_000,
      releaseCheckSuccess: 1_000,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    });
    const lowerInput = mk({
      hoursToNextStable: 1,
      breakingCount: 100,
      verifiedDebtWeight: 1e9,
      staleDebtWeight: 1e9,
      unresolvedClosureRiskWeight: 1e9,
      rawIssueCount: 100,
      classifiedIssueCount: 0,
      feltOpenedWeight: 1e9,
      releaseCheckState: 'FAILURE',
      releaseCheckFailure: 100,
      artifactMismatch: 'mismatch',
    });
    for (const [input, expectedAfter] of [[upperInput, 10], [lowerInput, 0]] as const) {
      const confidence = installConfidence(input, NOW);
      const ledger = buildScoreLedgerV2({
        input,
        confidence,
        now: NOW,
        ...scoreLedgerRiskArgs(input),
      });
      const operation = ledger.operations.find((item) => item.code === 'scoreRangeClamp')!;
      assert.equal(operation.applied, true);
      assert.equal(operation.after, expectedAfter);
      assert.deepEqual(scoreLedgerV2Problems(ledger, { input, confidence }), []);
    }
  });

  it('records CVE gate arithmetic, counterfactual binding, and advisory identities', () => {
    const input = mk({ cveAffected: true, cveLoad: 18 });
    const confidence = installConfidence(input, NOW);
    const ledger = buildScoreLedgerV2({
      input,
      confidence,
      now: NOW,
      evidenceSources: [{
        key: 'advisories',
        refs: [{
          kind: 'advisory',
          identity: 'advisory:GHSA-test:npm:openclaw:<2',
          payload: {
            ghsaId: 'GHSA-test',
            package: 'npm/openclaw',
            vulnerableRange: '<2',
            severity: 'high',
          },
        }],
      }],
    });
    assert.equal(ledger.status, 'skip-cve');
    assert.equal(ledger.cveGate.affected, true);
    assert.equal(ledger.cveGate.selectedScore, confidence.score);
    const gateRow = ledger.rows.find((row) => row.key === 'cveGate')!;
    assert.ok(gateRow.points < 0);
    assert.equal(round3(10 + gateRow.points), confidence.score);
    assert.equal(gateRow.kind, 'penalty');
    assert.ok(ledger.operations.some((item) =>
      item.code === 'cveCounterfactualMinimum' &&
      item.after === confidence.score));
    assert.equal(
      ledger.evidence.manifests.find((item) => item.key === 'advisories')?.count,
      1,
    );
    assert.deepEqual(scoreLedgerV2Problems(ledger, { input, confidence }), []);
  });

  it('binds settle, hotfix, and closure predicates at their exact boundaries', () => {
    const cases = [
      {
        input: mk({ isLatest: true, hoursToNextStable: null, publishedAt: hoursAgo(24) }),
        code: 'settlePredicate',
        expected: true,
      },
      {
        input: mk({ isLatest: true, hoursToNextStable: null, publishedAt: new Date(NOW - 24 * 3_600_000 - 1).toISOString() }),
        code: 'settlePredicate',
        expected: true,
      },
      {
        input: mk({ isLatest: true, hoursToNextStable: null, publishedAt: new Date(NOW - 24 * 3_600_000 + 1).toISOString() }),
        code: 'settlePredicate',
        expected: false,
      },
      {
        input: mk({ hoursToNextStable: 6 }),
        code: 'hotfixPredicate',
        expected: false,
      },
      {
        input: mk({ hoursToNextStable: 6 - 1e-6 }),
        code: 'hotfixPredicate',
        expected: true,
      },
      {
        input: mk({ affirmativeClosureRiskCeilingWeight: 40 }),
        code: 'noticeableClosurePredicate',
        expected: true,
      },
      {
        input: mk({ affirmativeClosureRiskCeilingWeight: 60 }),
        code: 'heavyClosurePredicate',
        expected: true,
      },
    ];
    for (const testCase of cases) {
      const confidence = installConfidence(testCase.input, NOW);
      const ledger = buildScoreLedgerV2({
        input: testCase.input,
        confidence,
        now: NOW,
      });
      assert.equal(
        ledger.operations.find((item) => item.code === testCase.code)?.predicateResult,
        testCase.expected,
      );
      assert.deepEqual(scoreLedgerV2Problems(ledger, {
        input: testCase.input,
        confidence,
        scoredAt: new Date(NOW).toISOString(),
      }), []);
    }
  });

  it('retains gated component evidence without applying it to wait or CVE scores', () => {
    const waitInput = mk({
      publishedAt: hoursAgo(4),
      verifiedDebtWeight: 3,
      carryoverDebtWeight: 2,
      staleDebtWeight: 1,
      unresolvedClosureRiskWeight: 4,
      feltOpenedWeight: 5,
      feltClosedWeight: 1,
      rawIssueCount: 10,
      classifiedIssueCount: 8,
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 2,
      releaseCheckSuccess: 2,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    });
    const waitConfidence = installConfidence(waitInput, NOW);
    const waitRisk = scoreLedgerRiskArgs(waitInput);
    const waitLedger = buildScoreLedgerV2({
      input: waitInput,
      confidence: waitConfidence,
      now: NOW,
      aliasElection: waitRisk.aliasElection,
      evidenceSources: [
        ...waitRisk.evidenceSources,
        {
          key: 'releaseChecks',
          refs: [{
            kind: 'release_check',
            identity: 'check:wait:build',
            payload: { state: 'SUCCESS' },
          }],
        },
        {
          key: 'artifact',
          refs: [{
            kind: 'artifact',
            identity: 'artifact:wait',
            payload: { verified: true },
          }],
        },
      ],
    });
    assert.equal(waitLedger.status, 'wait');
    assert.equal(waitLedger.finalScore, null);
    for (const code of [
      'verifiedDebt',
      'carryoverDebt',
      'staleDebt',
      'closureRisk',
      'coverage',
      'regression',
      'releaseVerification',
      'artifactVerification',
    ]) {
      const operation = waitLedger.operations.find((item) => item.code === code);
      assert.ok(operation, `missing gated wait operation ${code}`);
      assert.equal(operation.kind, 'component');
      assert.equal(operation.applied, false);
      assert.equal(operation.before, null);
      assert.equal(operation.after, null);
      assert.equal(
        operation.operands.find((operand) =>
          operand.name === 'suppressedByStatus')?.value,
        'wait',
      );
    }
    assert.ok(
      Number(
        waitLedger.operations.find((item) =>
          item.code === 'releaseVerification')?.boundedPoints,
      ) > 0,
    );
    assert.ok(
      Number(
        waitLedger.operations.find((item) =>
          item.code === 'artifactVerification')?.boundedPoints,
      ) > 0,
    );
    assert.deepEqual(
      scoreLedgerV2Problems(waitLedger, {
        input: waitInput,
        confidence: waitConfidence,
      }),
      [],
    );

    const cveInput = mk({
      cveAffected: true,
      cveLoad: 12,
      releaseCheckState: 'FAILURE',
      releaseCheckTotal: 1,
      releaseCheckFailure: 1,
      artifactMismatch: 'registry integrity mismatch',
    });
    const cveConfidence = installConfidence(cveInput, NOW);
    const cveLedger = buildScoreLedgerV2({
      input: cveInput,
      confidence: cveConfidence,
      now: NOW,
      evidenceSources: [
        {
          key: 'advisories',
          refs: [{
            kind: 'advisory',
            identity: 'advisory:cve-gated-components',
            payload: { affected: true, load: 12 },
          }],
        },
        {
          key: 'releaseChecks',
          refs: [{
            kind: 'release_check',
            identity: 'check:cve:build',
            payload: { state: 'FAILURE' },
          }],
        },
        {
          key: 'artifact',
          refs: [{
            kind: 'artifact',
            identity: 'artifact:cve',
            payload: { mismatch: true },
          }],
        },
      ],
    });
    assert.equal(cveLedger.status, 'skip-cve');
    for (const code of ['releaseVerification', 'artifactVerification']) {
      const operation = cveLedger.operations.find((item) => item.code === code);
      assert.ok(operation, `missing gated CVE operation ${code}`);
      assert.equal(operation.applied, false);
      assert.equal(operation.before, cveLedger.finalScore);
      assert.equal(operation.after, cveLedger.finalScore);
      assert.ok(Number(operation.boundedPoints) < 0);
      assert.equal(
        operation.operands.find((operand) =>
          operand.name === 'suppressedByStatus')?.value,
        'skip-cve',
      );
    }
    assert.deepEqual(
      scoreLedgerV2Problems(cveLedger, {
        input: cveInput,
        confidence: cveConfidence,
      }),
      [],
    );
  });

  it('keeps eligible verification components score-affecting', () => {
    const input = mk({
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 2,
      releaseCheckSuccess: 2,
      artifactVerified: true,
      ciReportVerified: true,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    });
    const confidence = installConfidence(input, NOW);
    const ledger = buildScoreLedgerV2({
      input,
      confidence,
      now: NOW,
    });
    for (const code of ['releaseVerification', 'artifactVerification']) {
      const operation = ledger.operations.find((item) => item.code === code);
      assert.ok(operation);
      assert.equal(operation.applied, true);
      assert.equal(
        Number(operation.after),
        Number(operation.before) + Number(operation.boundedPoints),
      );
      assert.equal(
        operation.operands.some((operand) =>
          operand.name === 'suppressedByStatus'),
        false,
      );
    }
    assert.deepEqual(
      scoreLedgerV2Problems(ledger, { input, confidence }),
      [],
    );
  });

  it('persists and replays the complete exclusive alias-channel election', () => {
    const aliasElection = buildExclusiveIssueRiskLedger([
      { aliasGroup: 'issue:1', channel: 'verified', weight: 3, issueNumber: 1 },
      { aliasGroup: 'issue:1', channel: 'closureRisk', weight: 20, issueNumber: 1 },
      { aliasGroup: 'issue:2', channel: 'stale', weight: 5, issueNumber: 2 },
      { aliasGroup: 'issue:2', channel: 'regression', weight: 8, issueNumber: 2 },
    ]);
    const input = mk({
      verifiedDebtWeight: aliasElection.totalsByChannel.verified,
      staleDebtWeight: aliasElection.totalsByChannel.stale,
      unresolvedClosureRiskWeight: aliasElection.totalsByChannel.closureRisk,
      feltOpenedWeight: aliasElection.totalsByChannel.regression,
    });
    const confidence = installConfidence(input, NOW);
    const ledger = buildScoreLedgerV2({
      input,
      confidence,
      now: NOW,
      evidenceSources: evidenceSourcesForAliasElection(aliasElection),
      aliasElection,
    });
    assert.deepEqual(ledger.aliasElection.groups, aliasElection.groups);
    assert.deepEqual(scoreLedgerV2Problems(ledger, { input, confidence }), []);

    const tampered = structuredClone(ledger);
    tampered.aliasElection.groups[0].selectedChannel = 'carryover';
    assert.ok(scoreLedgerV2Problems(tampered, { input, confidence }).some((problem) =>
      /aliasElection/.test(problem)));
  });

  it('keeps randomized derivations and signed gap items exactly reconciled', () => {
    const random = deterministicRandom(0x5c0e_2026);
    for (let index = 0; index < 300; index++) {
      const cveAffected = random() < 0.12;
      const input = mk({
        isLatest: random() < 0.5,
        hoursToNextStable: random() < 0.2 ? 2 + random() * 8 : 6 + random() * 200,
        betaCount: Math.floor(random() * 20),
        breakingCount: Math.floor(random() * 12),
        feltOpenedWeight: random() * 100,
        feltClosedWeight: random() * 100,
        verifiedDebtWeight: random() * 100,
        staleDebtWeight: random() * 100,
        unresolvedClosureRiskWeight: random() * 100,
        affirmativeClosureRiskCeilingWeight: random() * 100,
        rawIssueCount: 100,
        classifiedIssueCount: 100,
        cveAffected,
        cveLoad: random() * 40,
      });
      const confidence = installConfidence(input, NOW);
      const riskArgs = scoreLedgerRiskArgs(input);
      const ledger = buildScoreLedgerV2({
        input,
        confidence,
        now: NOW,
        aliasElection: riskArgs.aliasElection,
        evidenceSources: [
          ...riskArgs.evidenceSources,
          ...(cveAffected ? [{
            key: 'advisories',
            refs: [{
              kind: 'advisory',
              identity: `advisory:${index}`,
              payload: { index },
            }],
          }] : []),
        ],
      });
      assert.deepEqual(scoreLedgerV2Problems(ledger, { input, confidence }), []);
      if (confidence.score != null) {
        const gapSum = ledger.gapToTen.items.reduce((sum, item) => sum + item.points, 0);
        assert.ok(Math.abs(gapSum - (10 - confidence.score)) < 1e-9);
      }
    }
  });

  it('rejects nonzero debt without source-row evidence and rejects alias totals that drift from input', () => {
    const input = mk({ verifiedDebtWeight: 5 });
    const confidence = installConfidence(input, NOW);
    const aliasElection = aliasElectionForInput(input);
    assert.throws(
      () => buildScoreLedgerV2({
        input,
        confidence,
        now: NOW,
        aliasElection,
      }),
      /manifest verifiedDebt is missing elected alias|cannot be empty for nonzero verified debt/,
    );
    assert.throws(
      () => buildScoreLedgerV2({
        input: { ...input, verifiedDebtWeight: 6 },
        confidence: installConfidence({ ...input, verifiedDebtWeight: 6 }, NOW),
        now: NOW,
        aliasElection,
        evidenceSources: evidenceSourcesForAliasElection(aliasElection),
      }),
      /alias election verified total must match InstallInput.verifiedDebtWeight/,
    );
  });

  it('rejects tampered source-row operand weights even when manifest and ledger digests are recomputed', () => {
    const input = mk({ verifiedDebtWeight: 5 });
    const confidence = installConfidence(input, NOW);
    const riskArgs = scoreLedgerRiskArgs(input);
    const ledger = buildScoreLedgerV2({
      input,
      confidence,
      now: NOW,
      ...riskArgs,
    });
    const tampered = structuredClone(ledger);
    const manifest = tampered.evidence.manifests.find((item) =>
      item.key === 'verifiedDebt')!;
    manifest.refs[0].scoringOperand!.weight = 4;
    assert.ok(scoreLedgerV2Problems(tampered, { input, confidence }).some((problem) =>
      /weight .* does not match the elected operand|operand total/.test(problem)));
  });
});

describe('finite scoring weights', () => {
  it('rejects every non-finite InstallInput weight before scoring or ledger creation', () => {
    for (const field of [
      'feltOpenedWeight',
      'feltClosedWeight',
      'verifiedDebtWeight',
      'carryoverDebtWeight',
      'staleDebtWeight',
      'unresolvedClosureRiskWeight',
      'affirmativeClosureRiskCeilingWeight',
      'cveLoad',
    ] as const) {
      for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
        assert.throws(
          () => installConfidence(mk({ [field]: value }), NOW),
          new RegExp(`InstallInput\\.${field} must be a finite number`),
        );
      }
    }
  });

  it('rejects non-finite alias candidate weights instead of silently dropping them', () => {
    assert.throws(
      () => buildExclusiveIssueRiskLedger([{
        aliasGroup: 'issue:1',
        channel: 'verified',
        weight: Number.NaN,
      }]),
      /non-finite weight/,
    );
  });
});

function deterministicRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state / 0x1_0000_0000;
  };
}
