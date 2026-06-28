import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { __closureProofAnalysisTest } from './closureProofAnalysis.ts';
import type { ClosureProofResult } from './closureProof.ts';

function result(status: ClosureProofResult['status'], summary = status): ClosureProofResult {
  return { status, summary, evidence: {} };
}

describe('closure proof canonical roll-up', () => {
  it('expands canonical chains from fetched canonical issue comments', async () => {
    const graph = new Map([[10, [20]]]);
    const comments = new Map<number, any[]>([
      [10, [{ body: 'Canonical: #20' }]],
    ]);

    await __closureProofAnalysisTest.expandCanonicalGraph(
      graph,
      comments,
      [20],
      async (numbers: number[]) => new Map(numbers.map((number) => [
        number,
        number === 20 ? [{ body: 'Root-cause tracker: #30' }] : [],
      ])),
    );

    assert.deepEqual(graph.get(20), [30]);
    assert.deepEqual(__closureProofAnalysisTest.canonicalIssueNumbersReachableFrom(10, graph), [20, 30]);
  });

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
