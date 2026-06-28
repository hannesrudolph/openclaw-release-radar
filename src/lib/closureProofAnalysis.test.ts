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

  it('uses later-release terminal fix proof for closed canonical targets', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
      () => ({
        status: 'fixed_in_release',
        summary: 'Canonical was fixed in a later release.',
        evidence: {},
        releaseTag: 'v2',
        timing: 'after',
        sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
        terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
        crossRelease: true,
      }),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_after_release');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'fixed_in_release',
      summary: 'Canonical was fixed in a later release.',
      releaseTag: 'v2',
      timing: 'after',
      crossRelease: true,
      sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
      terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
    });
  });

  it('uses non-fix cross-release terminal proof to avoid missing-proof status', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
      () => ({
        status: 'not_planned',
        summary: 'Canonical was closed as non-actionable.',
        evidence: {},
        releaseTag: 'v2',
        timing: 'after',
        sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
        terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
        crossRelease: true,
      }),
    );

    assert.equal(adjusted.status, 'duplicate_to_non_actionable_canonical');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalProof.status, 'not_planned');
  });

  it('classifies closed canonical terminal risk by terminal disposition', () => {
    const baseArgs = [
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
    ] as const;

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'not_planned_with_open_pr_context', summary: 'Open PR remains.', evidence: {} }),
    ).status, 'duplicate_to_open_pr_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'not_planned_fixed_after_release', summary: 'Fixed after.', evidence: {} }),
    ).status, 'duplicate_to_known_not_in_release_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'linked_closing_pr_not_merged', summary: 'Unmerged PR.', evidence: {} }),
    ).status, 'duplicate_to_unverified_closed_canonical');
  });

  it('selects closed terminal canonical issues without existing cross-release proof for evidence backfill', () => {
    const graph = new Map([
      [10, [20]],
      [11, [30]],
      [12, [40]],
    ]);
    const selected = __closureProofAnalysisTest.terminalCanonicalIssuesNeedingEvidence(
      'v1',
      [10, 11, 12],
      graph,
      (number: number) => {
        if (number === 20) return { number, title: 'closed missing', state: 'closed', url: null };
        if (number === 30) return { number, title: 'open canonical', state: 'open', url: null };
        return { number, title: 'closed with proof', state: 'closed', url: null };
      },
      (_releaseTag: string, number: number) => number === 40
        ? {
          status: 'fixed_after_release',
          summary: 'Already proved elsewhere.',
          evidence: {},
          releaseTag: 'v2',
          timing: 'after',
          crossRelease: true,
        }
        : null,
    );

    assert.deepEqual(selected, [20]);
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

  it('classifies related PR references without release-fix proof separately', () => {
    const adjusted = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{
          number: 123,
          title: 'related work',
          state: 'MERGED',
          merged: 1,
          source: 'CrossReferencedEvent',
        }],
      },
    );

    assert.equal(adjusted.status, 'related_pr_without_release_fix');
  });

  it('classifies not-planned closures with reachable proof separately from bare admin closures', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        hasReachableFixCommit: true,
        linkedPrs: [],
      },
    );

    assert.equal(adjusted.status, 'not_planned_with_release_fix_proof');
  });

  it('classifies not-planned closures with open PR context separately', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{
          number: 97423,
          state: 'OPEN',
          merged: 0,
          source: 'CrossReferencedEvent',
        }],
      },
    );

    assert.equal(adjusted.status, 'not_planned_with_open_pr_context');
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
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as duplicate/superseded. Canonical path: Keep https://github.com/openclaw/openclaw/issues/76042 as the active tracker.',
      ),
      [76042],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as a duplicate: https://github.com/openclaw/openclaw/issues/67016 is open and already tracks this.',
      ),
      [67016],
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
