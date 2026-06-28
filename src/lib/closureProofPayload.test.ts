import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { closureRiskWeightForRow } from './closureProofPayload.ts';

describe('closure proof risk weighting', () => {
  it('weights unresolved closure risk by disposition and issue classification', () => {
    const severe = closureRiskWeightForRow({
      status: 'duplicate_to_open_canonical',
      sentiment: 'negative',
      severity: 'critical',
      functionality: 'core',
      scope: 'broad',
      affected_users: 'many',
    });
    const narrow = closureRiskWeightForRow({
      status: 'already_present_claim',
      sentiment: 'negative',
      severity: 'medium',
      functionality: 'integration',
      scope: 'niche',
      affected_users: 'few',
    });
    assert.ok(severe > narrow * 40, `expected severe canonical risk ${severe} to dominate narrow claim ${narrow}`);
  });

  it('excludes credited fixes and neutral closures from unresolved closure risk', () => {
    const base = {
      sentiment: 'negative',
      severity: 'critical',
      functionality: 'core',
      scope: 'broad',
      affected_users: 'many',
    };
    assert.equal(closureRiskWeightForRow({ ...base, status: 'fixed_in_release' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_neutral' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'fixed_after_release', sentiment: 'neutral' }), 0);
  });
});
