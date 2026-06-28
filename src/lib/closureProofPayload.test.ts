import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  CLOSURE_PROOF_SCHEMA_VERSION,
  RELEASE_FIX_CREDIT_SCHEMA_VERSION,
  closureRiskDisposition,
  closureRiskWeightForRow,
} from './closureProofPayload.ts';

describe('closure proof risk weighting', () => {
  it('publishes a stable payload schema version', () => {
    assert.equal(CLOSURE_PROOF_SCHEMA_VERSION, 1);
    assert.equal(RELEASE_FIX_CREDIT_SCHEMA_VERSION, 1);
  });

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

  it('keeps latest-version repro requests as unresolved unsupported closure risk', () => {
    const weight = closureRiskWeightForRow({
      status: 'repro_requested',
      sentiment: 'negative',
      severity: 'high',
      functionality: 'integration',
      scope: 'moderate',
      affected_users: 'some',
    });
    assert.equal(closureRiskDisposition('repro_requested'), 'unsupported_closure_claim');
    assert.ok(weight > 0);
  });

  it('weights no-release-fix proof shapes as unresolved unsupported closure risk', () => {
    for (const status of ['linked_closing_pr_not_merged', 'related_pr_without_release_fix', 'closed_without_release_fix_proof']) {
      const weight = closureRiskWeightForRow({
        status,
        sentiment: 'negative',
        severity: 'high',
        functionality: 'core',
        scope: 'moderate',
        affected_users: 'some',
      });
      assert.equal(closureRiskDisposition(status), 'unsupported_closure_claim');
      assert.ok(weight > 0, `${status} should carry unresolved risk`);
    }
    assert.equal(closureRiskDisposition('linked_closing_pr_reachability_unknown'), 'missing_evidence');
    assert.ok(closureRiskWeightForRow({
      status: 'linked_closing_pr_reachability_unknown',
      sentiment: 'negative',
      severity: 'high',
      functionality: 'core',
      scope: 'moderate',
      affected_users: 'some',
    }) > 0);
  });

  it('counts bare admin not-planned closures as unresolved unsupported risk', () => {
    const weight = closureRiskWeightForRow({
      status: 'admin_not_planned_unverified',
      sentiment: 'negative',
      severity: 'critical',
      functionality: 'core',
      scope: 'moderate',
      affected_users: 'some',
    });
    assert.equal(closureRiskDisposition('admin_not_planned_unverified'), 'unsupported_closure_claim');
    assert.ok(weight > 0);
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
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_fixed_in_release' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_fixed_after_release' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_linked_without_merge' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_duplicate_to_open_canonical' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_superseded_to_open_pr' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_duplicate_to_closed_canonical_missing_proof' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'non_bug_not_actionable' }), 0);
    assert.equal(closureRiskWeightForRow({ ...base, status: 'fixed_after_release', sentiment: 'neutral' }), 0);
  });
});
