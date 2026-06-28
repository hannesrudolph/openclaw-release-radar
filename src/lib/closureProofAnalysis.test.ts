import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { __closureProofAnalysisTest } from './closureProofAnalysis.ts';
import { closureRationaleComments } from './closureProof.ts';
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

  it('classifies duplicate closures by terminal canonical fixed-in-release proof', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map([[20, result('fixed_in_release', 'Canonical was fixed in this tag.')]]),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_in_release');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'fixed_in_release',
      summary: 'Canonical was fixed in this tag.',
    });
  });

  it('recognizes common duplicate-of text as canonical graph targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Closing this as duplicate of https://github.com/openclaw/openclaw/issues/96857.',
      ),
      [96857],
    );
  });

  it('ignores stale canonical comments when building source closure graph edges', () => {
    const comments = [
      { created_at: '2026-06-20T10:00:00Z', body: 'Keep open. Canonical: #96857' },
      { created_at: '2026-06-28T10:00:00Z', body: 'Closing as not planned.' },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(closureComments, 10),
      [],
    );
  });

  it('ignores close-time keep-open canonical review comments', () => {
    const comments = [
      { created_at: '2026-06-28T10:00:00Z', body: 'Keep open: this is the canonical report. Canonical: #96857' },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(closureComments, []);
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(closureComments, 10),
      [],
    );
  });

  it('keeps close-time canonical comments as source closure graph edges', () => {
    const comments = [
      { created_at: '2026-06-28T10:00:00Z', body: 'Closing as duplicate of #96857.' },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(closureComments, 10),
      [96857],
    );
  });
});
