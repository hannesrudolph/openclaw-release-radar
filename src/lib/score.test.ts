import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { scoreRelease, type IssueInput } from './score.ts';
import type { IssueClassification } from './llm.ts';

// Tests for the pure scoring function. Pins down the agent-watch-derived contract:
// - Empty input → neutral 5, not perfect 10 (no signal ≠ stable).
// - Score floor at 1.0 (Unstable still distinguishable from "grey").
// - Per-issue cap and other-drop cap prevent any one signal from dominating.

const NOW = Date.parse('2024-07-01T00:00:00Z');
const RELEASE_PUB = '2024-06-15T00:00:00Z'; // ~16 days before NOW, well past 3h grace

function mkClass(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'medium',
    scope: 'moderate',
    functionality: 'integration',
    affectedUsers: 'some',
    workaroundStatus: 'none',
    duplicateCluster: null,
    affectsVersion: 'v1.0.0',
    confidence: 1.0,
    rationale: '',
    ...overrides,
  };
}

function mkIssue(
  num: number,
  cls: IssueClassification,
  opts: { updatedAt?: string; comments?: number; isBot?: boolean } = {},
): IssueInput {
  return {
    number: num,
    updatedAt: opts.updatedAt ?? '2024-06-30T00:00:00Z', // fresh by default
    commentCount: opts.comments ?? 0,
    isBot: opts.isBot ?? false,
    classification: cls,
  };
}

describe('scoreRelease', () => {
  it('empty input → neutral 5 baseline (insufficient signal)', () => {
    const s = scoreRelease([], RELEASE_PUB, NOW);
    assert.equal(s.finalScore, 5);
    assert.equal(s.riskIndex, 0);
    assert.equal(s.negativeIssues, 0);
    assert.equal(s.positiveIssues, 0);
    assert.equal(s.state, 'insufficient');
  });

  it('release younger than 3h → analyzing, neutral 5', () => {
    const justPublished = new Date(NOW - 60 * 60 * 1000).toISOString(); // 1h ago
    const issues = [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core' }))];
    const s = scoreRelease(issues, justPublished, NOW);
    assert.equal(s.finalScore, 5);
    assert.equal(s.state, 'analyzing');
  });

  it('only neutral/positive issues → insufficient (5), not a perfect 10', () => {
    // Product framing: the dashboard answers "should I install this release?". A
    // handful of "works for me" comments is not enough to declare a release stable —
    // it just means we have no negative signal yet. Treat the same as empty input.
    const issues = [
      mkIssue(1, mkClass({ sentiment: 'neutral' })),
      mkIssue(2, mkClass({ sentiment: 'positive' })),
    ];
    const s = scoreRelease(issues, RELEASE_PUB, NOW);
    assert.equal(s.finalScore, 5);
    assert.equal(s.riskIndex, 0);
    assert.equal(s.state, 'insufficient');
  });

  it('single fresh core+critical bug → score in Risky/Mixed range, not 0', () => {
    const issues = [mkIssue(1, mkClass({ severity: 'critical', scope: 'broad', functionality: 'core' }))];
    const s = scoreRelease(issues, RELEASE_PUB, NOW);
    assert.ok(s.finalScore < 10, `expected < 10, got ${s.finalScore}`);
    assert.ok(s.finalScore >= 1, `expected >= floor 1, got ${s.finalScore}`);
    assert.ok(s.riskIndex > 0);
    assert.equal(s.negativeIssues, 1);
  });

  it('severity escalates core risk: critical > high > medium', () => {
    // Use core+critical/high to land in the "core-serious" bucket so weight maps to riskIndex.
    const mk = (sev: IssueClassification['severity']) =>
      scoreRelease(
        [mkIssue(1, mkClass({ severity: sev, functionality: 'core' }))],
        RELEASE_PUB,
        NOW,
      ).riskIndex;
    assert.ok(mk('critical') > mk('high'), `critical (${mk('critical')}) > high (${mk('high')})`);
    // medium isn't "core-serious" so it goes to other-drop, riskIndex (= effectiveCore) = 0.
    assert.equal(mk('medium'), 0);
  });

  it('positive offsets the other-drop bucket first', () => {
    // A medium severity bug lands in "other" (not core-serious). Positive evidence should
    // cancel it before nibbling at core.
    const neg = mkIssue(1, mkClass({ sentiment: 'negative', severity: 'medium' }));
    const pos = mkIssue(2, mkClass({ sentiment: 'positive' }));
    const withPos = scoreRelease([neg, pos], RELEASE_PUB, NOW).finalScore;
    const withoutPos = scoreRelease([neg], RELEASE_PUB, NOW).finalScore;
    assert.ok(withPos > withoutPos, `pos should soften: with=${withPos}, without=${withoutPos}`);
  });

  it('workaroundStatus dampens severity progressively (none > partial > confirmed)', () => {
    const ri = (ws: IssueClassification['workaroundStatus']) =>
      scoreRelease(
        [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core', workaroundStatus: ws }))],
        RELEASE_PUB,
        NOW,
      ).riskIndex;
    assert.ok(ri('none') > ri('partial'), `none (${ri('none')}) should hit harder than partial (${ri('partial')})`);
    assert.ok(ri('partial') > ri('confirmed'), `partial > confirmed`);
  });

  it('bot-generated issues are down-weighted', () => {
    const human = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core' }), { isBot: false })],
      RELEASE_PUB,
      NOW,
    ).riskIndex;
    const bot = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core' }), { isBot: true })],
      RELEASE_PUB,
      NOW,
    ).riskIndex;
    assert.ok(bot < human, `bot (${bot}) should weigh less than human (${human})`);
    // Bot multiplier is 0.3, so expect a roughly ~70% reduction.
    assert.ok(bot < human * 0.5, `bot weight should be substantially below human`);
  });

  it('peer median floor lifts at-median rated releases below 5.5 up to 5.5', () => {
    // Build a release with enough negative signal that the baseline lands below 5.5.
    // 4 critical+broad+core+many issues → riskIndex ≈ 16, score ≈ 3.1.
    const issues = Array.from({ length: 4 }, (_, i) =>
      mkIssue(i + 1, mkClass({ severity: 'critical', scope: 'broad', functionality: 'core', affectedUsers: 'many' })),
    );
    const baseline = scoreRelease(issues, RELEASE_PUB, NOW).finalScore;
    assert.ok(baseline < 5.5, `baseline must be < 5.5 for this test to mean anything (got ${baseline})`);

    // Median exactly equal to this release's signal → at-or-below condition holds → floor applies.
    const { weightedNegSum } = scoreRelease(issues, RELEASE_PUB, NOW);
    const floored = scoreRelease(issues, RELEASE_PUB, NOW, weightedNegSum);
    assert.equal(floored.finalScore, 5.5, `at-median release should be lifted to 5.5, got ${floored.finalScore}`);
  });

  it('peer median floor does NOT apply when signal exceeds the median', () => {
    const issues = Array.from({ length: 4 }, (_, i) =>
      mkIssue(i + 1, mkClass({ severity: 'critical', scope: 'broad', functionality: 'core', affectedUsers: 'many' })),
    );
    const { weightedNegSum, finalScore } = scoreRelease(issues, RELEASE_PUB, NOW);
    // Median lower than this release's signal → release is above-average-bad → no floor.
    const noFloor = scoreRelease(issues, RELEASE_PUB, NOW, weightedNegSum * 0.5);
    assert.equal(noFloor.finalScore, finalScore, 'above-median signal should not get the peer floor');
  });

  it('floor: finalScore never drops below 1 under heavy load', () => {
    const issues = Array.from({ length: 20 }, (_, i) =>
      mkIssue(
        i + 1,
        mkClass({ severity: 'critical', scope: 'broad', functionality: 'core', affectedUsers: 'many' }),
      ),
    );
    const s = scoreRelease(issues, RELEASE_PUB, NOW);
    assert.ok(s.finalScore >= 1 && s.finalScore <= 10, `out of range: ${s.finalScore}`);
    assert.equal(s.finalScore, 1, `expected floor=1 under saturation, got ${s.finalScore}`);
  });

  it('other-drop is capped at ~2 points regardless of niche count', () => {
    // 50 niche/integration bugs — would crash the score in the old model. New model caps at -2.
    const issues = Array.from({ length: 50 }, (_, i) =>
      mkIssue(i + 1, mkClass({ severity: 'medium', scope: 'niche', functionality: 'integration' })),
    );
    const s = scoreRelease(issues, RELEASE_PUB, NOW);
    // coreRisk is 0 (none are core-serious), so coreScore=10. otherDrop maxes at 2.
    // Expect finalScore around 10 - 2 = 8, with some slack.
    assert.ok(s.finalScore >= 7.5 && s.finalScore <= 10, `50 niche bugs should cap drop near 2, got ${s.finalScore}`);
  });

  it('per-issue cap: a pathological single issue cannot single-handedly crash the score', () => {
    // Single core+critical with 1000 comments — discussion boost would blow up uncapped.
    const issues = [
      mkIssue(1, mkClass({ severity: 'critical', scope: 'broad', functionality: 'core', affectedUsers: 'many' }), {
        comments: 1000,
      }),
    ];
    const s = scoreRelease(issues, RELEASE_PUB, NOW);
    // Per-issue cap = 4, scoreFromRiskIndex(4) with new formula ≈ 7.
    assert.ok(s.finalScore >= 5, `single capped issue shouldn't drop below ~5, got ${s.finalScore}`);
  });

  it('older issues still register but with reduced weight (recency floor 0.55)', () => {
    const fresh = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core' }), { updatedAt: '2024-06-30T00:00:00Z' })],
      RELEASE_PUB,
      NOW,
    ).riskIndex;
    const old = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core' }), { updatedAt: '2022-06-30T00:00:00Z' })],
      RELEASE_PUB,
      NOW,
    ).riskIndex;
    assert.ok(fresh > old, `fresh (${fresh}) should exceed old (${old})`);
    // Recency formula floors at 0.55, so old issues still contribute substantially.
    assert.ok(old / fresh > 0.4, `old/fresh ratio (${old / fresh}) should be > 0.4 (recency floor)`);
  });
});
