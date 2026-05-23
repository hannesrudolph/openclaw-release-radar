import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { applyLabelOverrides } from './labelOverrides.ts';
import type { IssueClassification } from './llm.ts';

// Baseline classification — represents typical "LLM said: medium moderate integration".
function mk(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'medium',
    scope: 'moderate',
    functionality: 'integration',
    affectedUsers: 'some',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.7,
    rationale: '',
    ...overrides,
  };
}

describe('applyLabelOverrides', () => {
  it('no labels → identity', () => {
    const base = mk();
    const out = applyLabelOverrides(base, []);
    assert.deepEqual(out, base);
  });

  it('unrelated routing labels → identity', () => {
    const base = mk();
    const out = applyLabelOverrides(base, ['P2', 'clawsweeper:fix-shape-clear', 'size: M']);
    assert.deepEqual(out, base);
  });

  it('enhancement → sentiment forced to neutral', () => {
    const out = applyLabelOverrides(mk(), ['enhancement']);
    assert.equal(out.sentiment, 'neutral');
  });

  it('stale → sentiment neutral + confidence capped at 0.5', () => {
    const out = applyLabelOverrides(mk({ confidence: 0.9 }), ['stale']);
    assert.equal(out.sentiment, 'neutral');
    assert.ok(out.confidence <= 0.5);
  });

  it('not-repro-on-main → sentiment neutral + confidence capped at 0.6', () => {
    const out = applyLabelOverrides(mk({ confidence: 1.0 }), ['clawsweeper:not-repro-on-main']);
    assert.equal(out.sentiment, 'neutral');
    assert.ok(out.confidence <= 0.6);
  });

  it('impact:data-loss → severity critical AND functionality core', () => {
    const out = applyLabelOverrides(
      mk({ severity: 'medium', functionality: 'integration' }),
      ['impact:data-loss'],
    );
    assert.equal(out.severity, 'critical');
    assert.equal(out.functionality, 'core');
  });

  it('impact:data-loss does NOT downgrade severity already at critical', () => {
    const out = applyLabelOverrides(mk({ severity: 'critical' }), ['impact:data-loss']);
    assert.equal(out.severity, 'critical');
  });

  it('P0 → severity critical', () => {
    const out = applyLabelOverrides(mk({ severity: 'low' }), ['P0']);
    assert.equal(out.severity, 'critical');
  });

  it('beta-blocker → severity critical', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['beta-blocker']);
    assert.equal(out.severity, 'critical');
  });

  it('impact:security raises medium → high; keeps critical at critical', () => {
    const out1 = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:security']);
    assert.equal(out1.severity, 'high');
    const out2 = applyLabelOverrides(mk({ severity: 'critical' }), ['impact:security']);
    assert.equal(out2.severity, 'critical');
  });

  it('impact:security: docs functionality → core', () => {
    const out = applyLabelOverrides(mk({ functionality: 'docs' }), ['impact:security']);
    assert.equal(out.functionality, 'core');
  });

  it('impact:crash-loop raises low → high', () => {
    const out = applyLabelOverrides(mk({ severity: 'low' }), ['impact:crash-loop']);
    assert.equal(out.severity, 'high');
  });

  it('impact:session-state raises medium → high', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:session-state']);
    assert.equal(out.severity, 'high');
  });

  it('impact:message-loss raises medium → high', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:message-loss']);
    assert.equal(out.severity, 'high');
  });

  it('impact:auth-provider raises medium → high', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:auth-provider']);
    assert.equal(out.severity, 'high');
  });

  it('regression bumps severity one rung', () => {
    assert.equal(applyLabelOverrides(mk({ severity: 'low' }), ['regression']).severity, 'medium');
    assert.equal(applyLabelOverrides(mk({ severity: 'medium' }), ['regression']).severity, 'high');
    assert.equal(applyLabelOverrides(mk({ severity: 'high' }), ['regression']).severity, 'critical');
    assert.equal(applyLabelOverrides(mk({ severity: 'critical' }), ['regression']).severity, 'critical');
  });

  it('regression + impact:crash-loop compounds: medium → high (impact) → critical (regression)', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['regression', 'impact:crash-loop']);
    assert.equal(out.severity, 'critical');
  });

  it('clawsweeper:source-repro → confidence ≥ 0.9', () => {
    const out = applyLabelOverrides(mk({ confidence: 0.5 }), ['clawsweeper:source-repro']);
    assert.ok(out.confidence >= 0.9);
  });

  it('clawsweeper:current-main-repro → confidence ≥ 0.9', () => {
    const out = applyLabelOverrides(mk({ confidence: 0.3 }), ['clawsweeper:current-main-repro']);
    assert.ok(out.confidence >= 0.9);
  });

  it('clawsweeper:needs-info → confidence ≤ 0.5', () => {
    const out = applyLabelOverrides(mk({ confidence: 0.9 }), ['clawsweeper:needs-info']);
    assert.ok(out.confidence <= 0.5);
  });

  it('clawsweeper:needs-live-repro → confidence ≤ 0.5', () => {
    const out = applyLabelOverrides(mk({ confidence: 0.95 }), ['clawsweeper:needs-live-repro']);
    assert.ok(out.confidence <= 0.5);
  });

  it('passthrough fields are preserved', () => {
    const base = mk({
      duplicateCluster: 'ollama-timeout',
      affectsVersion: 'v2026.5.20',
      affectedUsers: 'many',
      workaroundStatus: 'confirmed',
      scope: 'broad',
    });
    const out = applyLabelOverrides(base, ['impact:data-loss']);
    assert.equal(out.duplicateCluster, 'ollama-timeout');
    assert.equal(out.affectsVersion, 'v2026.5.20');
    assert.equal(out.affectedUsers, 'many');
    assert.equal(out.workaroundStatus, 'confirmed');
    assert.equal(out.scope, 'broad');
  });

  it('multiple overrides at once: enhancement + impact:data-loss → critical neutral', () => {
    // Edge case: maintainer mistakenly tagged a critical feature request.
    // Our rules apply both — sentiment becomes neutral (no bug claim) AND severity
    // hardens, because if it ever IS a bug we want it correctly weighted.
    const out = applyLabelOverrides(mk(), ['enhancement', 'impact:data-loss']);
    assert.equal(out.sentiment, 'neutral');
    assert.equal(out.severity, 'critical');
  });
});
