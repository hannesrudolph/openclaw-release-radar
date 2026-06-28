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

  it('classifies closed canonical targets without terminal proof as missing evidence', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [96343] },
      new Map([[10, [96343]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_to_closed_canonical_missing_proof');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalIssue?.number, 96343);
  });

  it('classifies closed canonical targets with missing terminal timeline as missing evidence', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [96343] },
      new Map([[10, [96343]]]),
      new Map([[96343, result('no_timeline_event', 'Canonical has no close event.')]]),
    );

    assert.equal(adjusted.status, 'duplicate_to_closed_canonical_missing_proof');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'no_timeline_event',
      summary: 'Canonical has no close event.',
    });
  });

  it('classifies duplicate closures with open PR context as open canonical risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      97322,
      result('duplicate_or_superseded', 'Closed as superseded.'),
      {
        canonicalIssues: [],
        linkedPrs: [{
          number: 85651,
          title: 'feat(continuation): context-pressure-aware continuation',
          state: 'OPEN',
          merged: 0,
          source: 'ClosureComment.prMention',
        }],
      },
      new Map([[97322, []]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'superseded_to_open_pr');
    assert.equal((adjusted.evidence.canonicalOpenPrs as any[])[0].number, 85651);
  });

  it('keeps cross-reference-only open PRs as related context, not canonical closure proof', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      96343,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [],
        linkedPrs: [{
          number: 96358,
          title: 'fix(cron): preserve action-critical command output',
          state: 'OPEN',
          merged: 0,
          source: 'CrossReferencedEvent',
        }],
      },
      new Map([[96343, []]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_with_open_pr_context');
    assert.equal((adjusted.evidence.relatedOpenPrs as any[])[0].number, 96358);
    assert.equal(adjusted.evidence.canonicalOpenPrs, undefined);
  });

  it('classifies non-bug duplicate closures by open canonical target without scoring risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('non_bug_duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [50103] },
      new Map([[10, [50103]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'non_bug_duplicate_to_open_canonical');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalIssue?.number, 50103);
  });

  it('classifies non-bug duplicate closures with open PR context without scoring risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('non_bug_duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [],
        linkedPrs: [{
          number: 85651,
          title: 'feat(continuation): context-pressure-aware continuation',
          state: 'OPEN',
          merged: 0,
          source: 'ClosureComment.prMention',
        }],
      },
      new Map([[10, []]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'non_bug_superseded_to_open_pr');
  });

  it('recognizes common duplicate-of text as canonical graph targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Closing this as duplicate of https://github.com/openclaw/openclaw/issues/96857.',
      ),
      [96857],
    );
  });

  it('recognizes close-time duplicate and canonical tracker wording as graph targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Closing this as a duplicate of #96857. Keeping the upstream discussion centralized there.',
      ),
      [96857],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as a duplicate of the open canonical tracker #60841, not as fixed.',
      ),
      [60841],
    );
  });

  it('does not treat canonical PR links as canonical issue targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Canonical path: Open PR https://github.com/openclaw/openclaw/pull/85651 owns this feature work.',
      ),
      [],
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

  it('builds fallback commit proof from eligible referenced commits only', () => {
    const rows = [
      {
        issue_number: 10,
        commit_oid: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        commit_message_headline: 'fix(cli): preserve channel routing',
        referenced_at: '2026-06-28T10:00:01Z',
        actor_login: 'maintainer',
        event_id: 'ref-ok',
        closed_at: '2026-06-28T10:00:00Z',
      },
      {
        issue_number: 10,
        commit_oid: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        commit_message_headline: 'docs: mention related issue',
        referenced_at: '2026-06-28T10:00:01Z',
        actor_login: 'maintainer',
        event_id: 'ref-docs',
        closed_at: '2026-06-28T10:00:00Z',
      },
      {
        issue_number: 10,
        commit_oid: 'cccccccccccccccccccccccccccccccccccccccc',
        commit_message_headline: 'fix(cli): too late to prove final closure',
        referenced_at: '2026-06-28T10:00:03Z',
        actor_login: 'maintainer',
        event_id: 'ref-late',
        closed_at: '2026-06-28T10:00:00Z',
      },
      {
        issue_number: 10,
        commit_oid: 'short',
        commit_message_headline: 'fix(cli): short hash',
        referenced_at: '2026-06-28T10:00:01Z',
        actor_login: 'maintainer',
        event_id: 'ref-short',
        closed_at: '2026-06-28T10:00:00Z',
      },
    ];

    const mentions = __closureProofAnalysisTest.commitReferenceMentionsFromRows(rows).get(10) ?? [];
    assert.deepEqual(mentions.map((item: any) => ({
      commitOid: item.commitOid,
      source: item.source,
      referencedAt: item.referencedAt,
      snippet: item.snippet,
      author: item.author,
      trustedSource: item.trustedSource,
    })), [{
      commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      source: 'ReferencedEvent.commit',
      referencedAt: '2026-06-28T10:00:01Z',
      snippet: 'GitHub ReferencedEvent same-repo commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: fix(cli): preserve channel routing',
      author: 'maintainer',
      trustedSource: true,
    }]);
  });
});
