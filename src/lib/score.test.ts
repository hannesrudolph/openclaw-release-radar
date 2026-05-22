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
    hasWorkaround: false,
    duplicateCluster: null,
    affectsVersion: 'v1.0.0',
    confidence: 1.0,
    rationale: '',
    ...overrides,
  };
}

function mkIssue(num: number, cls: IssueClassification, opts: { updatedAt?: string; comments?: number } = {}): IssueInput {
  return {
    number: num,
    updatedAt: opts.updatedAt ?? '2024-06-30T00:00:00Z', // fresh by default
    commentCount: opts.comments ?? 0,
    publishedAt: RELEASE_PUB,
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

  it('only neutral/positive issues → coreScore stays at 10, no other-drop → 10', () => {
    const issues = [
      mkIssue(1, mkClass({ sentiment: 'neutral' })),
      mkIssue(2, mkClass({ sentiment: 'positive' })),
    ];
    const s = scoreRelease(issues, RELEASE_PUB, NOW);
    assert.equal(s.finalScore, 10);
    assert.equal(s.riskIndex, 0);
    assert.equal(s.state, 'rated');
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

  it('hasWorkaround dampens severity', () => {
    const noFix = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core', hasWorkaround: false }))],
      RELEASE_PUB,
      NOW,
    ).riskIndex;
    const withFix = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'critical', functionality: 'core', hasWorkaround: true }))],
      RELEASE_PUB,
      NOW,
    ).riskIndex;
    assert.ok(noFix > withFix, `no-workaround (${noFix}) should hit harder than with-workaround (${withFix})`);
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
    // Per-issue cap = 5, so coreRiskIndex <= 5. scoreFromRiskIndex(5) ≈ 4.45.
    assert.ok(s.finalScore >= 3, `single capped issue shouldn't drop below ~3, got ${s.finalScore}`);
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
