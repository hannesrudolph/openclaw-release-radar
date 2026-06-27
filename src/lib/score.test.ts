import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  installConfidence,
  pickRecommended,
  bandFor,
  cveDecayLoad,
  feltLoad,
  openDebtLoad,
  REC_THRESHOLD,
  type InstallInput,
} from './score.ts';

// Install Confidence contract — answers "should I install this stable?".
// Gates (CVE / too-new / hotfix) override; otherwise a graded 0–10 from
// age/cadence-invariant signals (survival, shakeout, regression balance, breaking).

const NOW = Date.parse('2026-05-30T00:00:00Z');
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();
const hoursAgo = (h: number) => new Date(NOW - h * 3_600_000).toISOString();

function mk(over: Partial<InstallInput> = {}): InstallInput {
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
    rawIssueCount: 0,
    classifiedIssueCount: 0,
    cveAffected: false,
    cveLoad: 0,
    ...over,
  };
}
const score = (over: Partial<InstallInput> = {}) => installConfidence(mk(over), NOW).score!;

describe('installConfidence — gates', () => {
  it('CVE-affected → skip-cve status, scored below any install', () => {
    const clean = installConfidence(mk(), NOW).score!;
    const r = installConfidence(mk({ cveAffected: true, cveLoad: 20 }), NOW);
    assert.equal(r.status, 'skip-cve');
    assert.equal(r.band, 'skip');                 // status drives band → never recommended
    assert.ok(r.score! < clean, `CVE should score below the clean baseline (${r.score} vs ${clean})`);
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

  it('younger than the settle window → wait, no score', () => {
    const r = installConfidence(mk({ publishedAt: hoursAgo(5) }), NOW);
    assert.equal(r.status, 'wait');
    assert.equal(r.score, null);
    assert.equal(r.band, 'wait');
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
    const failed = score({ releaseCheckState: 'FAILURE', releaseCheckTotal: 7, releaseCheckFailure: 1 });
    assert.ok(failed < pending, `failed ${failed} should be below pending ${pending}`);
  });

  it('verified artifacts add a small capped confidence bump', () => {
    const unchecked = score();
    const verified = score({ artifactVerified: true, releaseIntegrityPresent: true, releaseShaMatches: true });
    assert.ok(verified > unchecked);
    assert.ok(verified - unchecked <= 0.5);
  });

  it('artifact mismatches penalize release confidence', () => {
    const verified = score({ artifactVerified: true, releaseIntegrityPresent: true, releaseShaMatches: true });
    const mismatch = score({ artifactVerified: false, artifactMismatch: 'registry integrity mismatch' });
    assert.ok(mismatch < verified);
  });

  it('verified open debt lowers the score even when reign balance is neutral', () => {
    assert.ok(score({ verifiedDebtWeight: 1 }) > score({ verifiedDebtWeight: 30 }));
  });

  it('carryover and stale debt are capped below verified blocker debt', () => {
    const base = score();
    const verified = score({ verifiedDebtWeight: 100 });
    const carryover = score({ carryoverDebtWeight: 100 });
    const stale = score({ staleDebtWeight: 100 });
    assert.ok(verified < carryover);
    assert.ok(carryover < base);
    assert.ok(stale > verified);
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
    assert.ok(feltLoad([fc({ labels: ['bug', 'regression', 'P1', 'clawsweeper:source-repro'], confidence: 0.95 })]) > 0);
  });
});

describe('openDebtLoad — current issue debt', () => {
  const dc = (over = {}) => ({
    issueNumber: 1,
    state: 'open',
    sentiment: 'negative',
    severity: 'high',
    functionality: 'core',
    scope: 'moderate',
    affectedUsers: 'some',
    workaroundStatus: 'unknown',
    confidence: 0.9,
    duplicateCluster: null,
    ...over,
  });

  it('ignores closed, positive, docs, and low-severity rows', () => {
    assert.deepEqual(openDebtLoad([dc({ state: 'closed' })]), { verified: 0, carryover: 0, stale: 0 });
    assert.deepEqual(openDebtLoad([dc({ sentiment: 'positive' })]), { verified: 0, carryover: 0, stale: 0 });
    assert.deepEqual(openDebtLoad([dc({ functionality: 'docs' })]), { verified: 0, carryover: 0, stale: 0 });
    assert.deepEqual(openDebtLoad([dc({ severity: 'low' })]), { verified: 0, carryover: 0, stale: 0 });
  });

  it('deduplicates repeated reports by cluster', () => {
    const one = openDebtLoad([dc({ duplicateCluster: 'same-bug', affectsVersion: 'v2026.6.10' })]).verified;
    const repeated = openDebtLoad([
      dc({ issueNumber: 1, duplicateCluster: 'same-bug', affectsVersion: 'v2026.6.10' }),
      dc({ issueNumber: 2, duplicateCluster: 'same-bug', affectsVersion: 'v2026.6.10' }),
    ]).verified;
    assert.equal(repeated, one);
  });

  it('uses duplicate-cluster reporter breadth as field/community evidence', () => {
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
    assert.ok(clustered.verified > 0);
  });

  it('uses unique human commenters as field/community evidence for source-repro findings', () => {
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
    assert.ok(discussed.verified > 0);
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
    assert.ok(discussed.carryover > 0);
  });

  it('reduces debt for confirmed workarounds', () => {
    const blocker = { releaseLocal: true, labels: ['P0'], functionality: 'core', severity: 'high', scope: 'broad' };
    const none = openDebtLoad([dc({ ...blocker, workaroundStatus: 'none' })]).verified;
    const confirmed = openDebtLoad([dc({ ...blocker, workaroundStatus: 'confirmed' })]).verified;
    assert.ok(confirmed < none);
  });

  it('does not treat old source-repro carryover as verified release debt', () => {
    const carryover = openDebtLoad([
      dc({
        issueNumber: 99,
        labels: ['clawsweeper:source-repro'],
        releaseLocal: false,
        affectsVersion: null,
      }),
    ]);
    assert.equal(carryover.verified, 0);
    assert.ok(carryover.carryover > 0);
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
    assert.ok(local.carryover > 0);
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
    assert.ok(local.carryover > 0);
  });

  it('treats release-local P0 core blockers as verified field debt', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 102,
        labels: ['P0'],
        releaseLocal: true,
        functionality: 'core',
        severity: 'critical',
        scope: 'moderate',
        affectedUsers: 'some',
      }),
    ]);
    assert.ok(local.verified > 0);
  });

  it('treats release-local P1 bug regressions as verified field debt', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 103,
        labels: ['bug', 'regression', 'P1'],
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

  it('ignores classifier affectsVersion for verified field debt promotion', () => {
    const local = openDebtLoad([
      dc({
        issueNumber: 105,
        labels: ['P0'],
        releaseLocal: false,
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

  it('counts source-repro clusters as field-visible only with reporter breadth', () => {
    const solo = feltLoad([
      dc({ labels: ['clawsweeper:source-repro'], author: 'alice' }),
    ]);
    const clustered = feltLoad([
      dc({ labels: ['clawsweeper:source-repro'], author: 'alice', duplicateCluster: 'same-visible-bug' }),
      dc({ labels: ['clawsweeper:source-repro'], author: 'bob', duplicateCluster: 'same-visible-bug' }),
    ]);
    assert.equal(solo, 0);
    assert.ok(clustered > 0);
  });

  it('lets reactions lift weight without verifying source-only findings', () => {
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
        positiveReactionCount: 10,
      }),
    ]);
    assert.equal(reacted.verified, 0);
    assert.ok(reacted.carryover > plain.carryover);
  });
});

describe('pickRecommended — newest eligible at or above threshold', () => {
  it('picks the newest eligible release scoring ≥ threshold', () => {
    const tag = pickRecommended([
      { tag: 'v3', status: 'wait', score: null },          // too new
      { tag: 'v2', status: 'eligible', score: REC_THRESHOLD }, // newest qualifying
      { tag: 'v1', status: 'eligible', score: 9.0 },        // higher but older
    ]);
    assert.equal(tag, 'v2');
  });

  it('skips hotfixed / gated / weak releases below the threshold', () => {
    const tag = pickRecommended([
      { tag: 'v4', status: 'skip-hotfix', score: 4.9 },
      { tag: 'v3', status: 'skip-cve', score: 1.5 },
      { tag: 'v2', status: 'eligible', score: 5.0 }, // eligible but "weak" (< 5.5)
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
