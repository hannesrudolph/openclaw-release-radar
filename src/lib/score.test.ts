import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { scoreRelease, type IssueInput } from './score.ts';
import type { IssueClassification } from './llm.ts';

// Tests for the pure scoring function. No DB, no network.
// These pin down the contract so anyone tuning constants (HALF_LIFE_DAYS, the 4.2/1.35
// curve, severity multipliers) gets immediate feedback if behaviour drifts.

const NOW = Date.parse('2024-07-01T00:00:00Z');

function mkClass(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'medium',
    scope: 'moderate',
    functionality: 'integration',
    affectedUsers: 'some',
    hasWorkaround: false,
    duplicateCluster: null,
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
    classification: cls,
  };
}

describe('scoreRelease', () => {
  it('empty input → perfect score, no risk', () => {
    const s = scoreRelease([], NOW);
    assert.equal(s.finalScore, 10);
    assert.equal(s.riskIndex, 0);
    assert.equal(s.negativeIssues, 0);
    assert.equal(s.positiveIssues, 0);
  });

  it('all neutral issues → perfect score', () => {
    const issues = [
      mkIssue(1, mkClass({ sentiment: 'neutral' })),
      mkIssue(2, mkClass({ sentiment: 'neutral' })),
    ];
    const s = scoreRelease(issues, NOW);
    assert.equal(s.finalScore, 10);
    assert.equal(s.riskIndex, 0);
  });

  it('all positive feedback → perfect score', () => {
    const issues = [
      mkIssue(1, mkClass({ sentiment: 'positive' })),
      mkIssue(2, mkClass({ sentiment: 'positive' })),
    ];
    const s = scoreRelease(issues, NOW);
    assert.equal(s.finalScore, 10);
    assert.equal(s.riskIndex, 0);
    assert.equal(s.positiveIssues, 2);
  });

  it('single fresh negative critical → score drops, riskIndex > 0', () => {
    const issues = [mkIssue(1, mkClass({ severity: 'critical', scope: 'broad', functionality: 'core' }))];
    const s = scoreRelease(issues, NOW);
    assert.ok(s.finalScore < 10, `expected score < 10, got ${s.finalScore}`);
    assert.ok(s.riskIndex > 0);
    assert.equal(s.negativeIssues, 1);
  });

  it('severity escalates risk: critical > high > medium > low', () => {
    const mk = (sev: IssueClassification['severity']) =>
      scoreRelease([mkIssue(1, mkClass({ severity: sev }))], NOW).riskIndex;
    assert.ok(mk('critical') > mk('high'), `critical (${mk('critical')}) should exceed high (${mk('high')})`);
    assert.ok(mk('high') > mk('medium'));
    assert.ok(mk('medium') > mk('low'));
  });

  it('equal-strength positive cancels negative back toward 10', () => {
    // Same classification shape, mirrored sentiment — should fully cancel.
    const neg = mkIssue(1, mkClass({ sentiment: 'negative' }));
    const pos = mkIssue(2, mkClass({ sentiment: 'positive' }));
    const s = scoreRelease([neg, pos], NOW);
    assert.equal(s.riskIndex, 0, 'positive should cancel negative entirely');
    assert.equal(s.finalScore, 10);
  });

  it('recency matters: old issue contributes less than fresh', () => {
    const fresh = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'high' }), { updatedAt: '2024-06-30T00:00:00Z' })],
      NOW,
    ).riskIndex;
    const old = scoreRelease(
      [mkIssue(1, mkClass({ severity: 'high' }), { updatedAt: '2023-06-30T00:00:00Z' })], // ~1y old
      NOW,
    ).riskIndex;
    assert.ok(fresh > old, `fresh (${fresh}) should outweigh old (${old})`);
    assert.ok(old > 0, 'old issue should still register some risk');
  });

  it('hasWorkaround dampens the negative contribution', () => {
    const noFix = scoreRelease([mkIssue(1, mkClass({ severity: 'high', hasWorkaround: false }))], NOW).riskIndex;
    const withFix = scoreRelease([mkIssue(1, mkClass({ severity: 'high', hasWorkaround: true }))], NOW).riskIndex;
    assert.ok(noFix > withFix, `no-workaround (${noFix}) should hit harder than with-workaround (${withFix})`);
  });

  it('finalScore stays clamped to [0, 10] under heavy load', () => {
    // 20 fresh critical broad core bugs — should saturate the curve.
    const issues = Array.from({ length: 20 }, (_, i) =>
      mkIssue(i + 1, mkClass({ severity: 'critical', scope: 'broad', functionality: 'core', affectedUsers: 'many' })),
    );
    const s = scoreRelease(issues, NOW);
    assert.ok(s.finalScore >= 0 && s.finalScore <= 10, `out of range: ${s.finalScore}`);
    assert.ok(s.finalScore < 1, `expected near-zero under heavy load, got ${s.finalScore}`);
  });
});
