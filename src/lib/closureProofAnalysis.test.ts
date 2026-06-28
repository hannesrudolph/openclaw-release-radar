import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { __closureProofAnalysisTest } from './closureProofAnalysis.ts';
import type { ClosureProofResult } from './closureProof.ts';

function result(status: ClosureProofResult['status'], summary = status): ClosureProofResult {
  return { status, summary, evidence: {} };
}

describe('closure proof canonical roll-up', () => {
  it('classifies duplicate closures by terminal canonical fixed-after proof', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map([[20, result('fixed_after_release', 'Canonical was fixed after this tag.')]]),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_after_release');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'fixed_after_release',
      summary: 'Canonical was fixed after this tag.',
    });
  });
});
