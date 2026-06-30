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

  it('does not return the source issue as reachable canonical context when cycles loop back', () => {
    const graph = new Map([
      [10, [20]],
      [20, [10]],
    ]);

    assert.deepEqual(__closureProofAnalysisTest.canonicalIssueNumbersReachableFrom(10, graph), [20]);
  });

  it('classifies canonical cycles with open issues as open canonical risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      88864,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [91154] },
      new Map([
        [88864, [91154]],
        [91154, [88864]],
      ]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_to_open_canonical');
    assert.equal((adjusted.evidence.canonicalResolution as any).cycle, true);
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalIssue.number, 91154);
    assert.equal((adjusted.evidence.canonicalResolution as any).cycleTerminalIssue.number, 91154);
  });

  it('lets canonical fix proof resolve a cycle before falling back to cycle risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20],
        canonicalFixCommitProof: [{ status: 'reachable', sourceIssueNumber: 20 }],
      },
      new Map([
        [10, [20]],
        [20, [10]],
      ]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_in_release');
    assert.equal((adjusted.evidence.canonicalResolution as any).cycle, true);
  });

  it('uses trusted reachable closure-comment fix proof before open duplicate canonical risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20],
        relatedPrContext: {
          reachable: [{
            number: 95328,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.fixProof',
            title: 'fix(sessions): reset stale origin fields',
          }],
        },
      },
      new Map([[10, [20]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_with_release_fix_proof');
    assert.equal((adjusted.evidence.reachableTrustedFixProofPrs as any[])[0].number, 95328);
  });

  it('preserves trusted fix proof when the same PR has lower-priority mention evidence', () => {
    const linkedPrs = [
      {
        number: 95328,
        repositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.prMention',
        title: 'related mention',
        state: 'MERGED',
        merged: 1,
      },
      {
        number: 95328,
        repositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        title: 'fix(sessions): reset stale origin fields',
        state: 'MERGED',
        merged: 1,
      },
    ];
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20],
        linkedPrs,
        relatedPrContext: {
          reachable: linkedPrs
            .sort(__closureProofAnalysisTest.compareLinkedPrEvidencePriority)
            .slice(0, 1),
        },
      },
      new Map([[10, [20]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_with_release_fix_proof');
    assert.equal((adjusted.evidence.reachableTrustedFixProofPrs as any[])[0].source, 'ClosureComment.fixProof');
  });

  it('keeps self-only canonical references as cycle risk when no terminal exists', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [10] },
      new Map([[10, [10]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'canonical_cycle_or_self_reference');
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

  it('keeps weak not-planned cross-release terminal proof unresolved', () => {
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

    assert.equal(adjusted.status, 'duplicate_to_unverified_closed_canonical');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalProof.status, 'not_planned');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalProof.concreteNonActionableRationale, undefined);
  });

  it('uses concrete non-actionable cross-release terminal proof to neutralize duplicate risk', () => {
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
        evidence: {
          nonActionableRationaleComments: [{
            author: 'maintainer',
            snippet: 'Close: this is outside the OpenClaw source repository.',
          }],
        },
        releaseTag: 'v2',
        timing: 'after',
        sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
        terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
        crossRelease: true,
      }),
    );

    assert.equal(adjusted.status, 'duplicate_to_non_actionable_canonical');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'not_planned',
      summary: 'Canonical was closed as non-actionable.',
      concreteNonActionableRationale: true,
      releaseTag: 'v2',
      timing: 'after',
      crossRelease: true,
      sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
      terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
    });
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
    ).status, 'duplicate_to_closed_canonical');
  });

  it('classifies closed canonical targets with concrete non-resolution proof separately', () => {
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
      () => ({ status: 'linked_closing_pr_closed_unmerged', summary: 'Closed unmerged.', evidence: {} }),
    ).status, 'duplicate_to_closed_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'closed_without_release_fix_proof', summary: 'No release proof.', evidence: {} }),
    ).status, 'duplicate_to_closed_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'related_open_pr_context', summary: 'Open related PR.', evidence: {} }),
    ).status, 'duplicate_to_open_pr_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'duplicate_or_superseded', summary: 'Still points elsewhere.', evidence: {} }),
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

  it('separates related PR context by reachability before generic no-fix status', () => {
    const reachable = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 123, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          reachable: [{ number: 123, repositoryNameWithOwner: 'openclaw/openclaw' }],
        },
      },
    );
    const notReachable = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 124, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          notReachable: [{ number: 124, repositoryNameWithOwner: 'openclaw/openclaw' }],
        },
      },
    );
    const unknown = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 125, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          unknownReachability: [{ number: 125, repositoryNameWithOwner: 'openclaw/openclaw' }],
        },
      },
    );

    assert.equal(reachable.status, 'related_merged_pr_reachable_context_without_fix_credit');
    assert.equal(notReachable.status, 'related_merged_pr_not_reachable_context');
    assert.equal(unknown.status, 'related_merged_pr_reachability_unknown');
  });

  it('separates open, closed-unmerged, and external closing PR context', () => {
    const open = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 123, state: 'OPEN', merged: 0 }],
        relatedPrContext: { open: [{ number: 123 }] },
      },
    );
    const closed = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 124, state: 'CLOSED', merged: 0 }],
        relatedPrContext: { closedUnmerged: [{ number: 124 }] },
      },
    );
    const external = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 27, repositoryNameWithOwner: 'openclaw/fs-safe', state: 'MERGED', merged: 1 }],
        relatedPrContext: { externalClosing: [{ number: 27, repositoryNameWithOwner: 'openclaw/fs-safe' }] },
      },
    );

    assert.equal(open.status, 'related_open_pr_context');
    assert.equal(closed.status, 'related_closed_unmerged_pr_context');
    assert.equal(external.status, 'external_repo_closing_pr_unscored');
  });

  it('separates open linked closing PRs from closed unmerged PRs', () => {
    const open = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('linked_closing_pr_not_merged', 'No merge.'),
      {
        linkedPrs: [{
          number: 123,
          source: 'closedByPullRequestsReferences',
          willCloseTarget: 1,
          state: 'OPEN',
          merged: 0,
        }],
      },
      'v1',
      new Map(),
    );
    const closed = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('linked_closing_pr_not_merged', 'No merge.'),
      {
        linkedPrs: [{
          number: 124,
          source: 'closedByPullRequestsReferences',
          willCloseTarget: 1,
          state: 'CLOSED',
          merged: 0,
        }],
      },
      'v1',
      new Map(),
    );

    assert.equal(open.status, 'linked_closing_pr_open');
    assert.equal(closed.status, 'linked_closing_pr_closed_unmerged');
  });

  it('classifies title-only author deletion requests as reporter withdrawal', () => {
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      { title: '[deleted by author request]', linkedPrs: [] },
      'v1',
      new Map(),
    );

    assert.equal(adjusted.status, 'reporter_withdrawn');
  });

  it('splits fixed-after release proof by later stable reachability', () => {
    const evidence = {
      notReachableFixCommits: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
      hasNotReachableFixCommit: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map([['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', {
        releaseTag: 'v2',
        publishedAt: '2026-06-02T00:00:00Z',
        proofType: 'commit',
        commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      }]]),
    );

    assert.equal(adjusted.status, 'fixed_in_later_release');
    assert.deepEqual((evidence as any).laterFixProof, {
      releaseTag: 'v2',
      publishedAt: '2026-06-02T00:00:00Z',
      proofType: 'commit',
      commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    });
  });

  it('marks fixed-after proof after latest scored stable separately', () => {
    const evidence = {
      linkedPrs: [{
        number: 99,
        repositoryNameWithOwner: 'openclaw/openclaw',
        merged: 1,
        mergedAt: '2026-06-03T00:00:00Z',
        source: 'ClosedEvent.closer',
      }],
      hasNotReachableClosingPr: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map(),
      () => ({ tag: 'v2', published_at: '2026-06-02T00:00:00Z' }),
    );

    assert.equal(adjusted.status, 'fixed_after_latest_release');
    assert.equal((evidence as any).unscoredFixProof.timing, 'after_latest_release');
  });

  it('marks fixed-after proof skipped by later scored stables separately', () => {
    const evidence = {
      notReachableFixCommits: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
      fixCommitProof: [{
        commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        referencedAt: '2026-06-01T12:00:00Z',
        status: 'not_reachable',
      }],
      hasNotReachableFixCommit: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map(),
      () => ({ tag: 'v2', published_at: '2026-06-02T00:00:00Z' }),
    );

    assert.equal(adjusted.status, 'fixed_skipped_by_later_releases');
    assert.equal((evidence as any).unscoredFixProof.timing, 'skipped_by_later_releases');
  });

  it('prefers after-latest proof over older skipped proof candidates', () => {
    const evidence = {
      linkedPrs: [{
        number: 10,
        repositoryNameWithOwner: 'openclaw/openclaw',
        merged: 1,
        mergedAt: '2026-06-01T12:00:00Z',
        source: 'ClosedEvent.closer',
      }, {
        number: 11,
        repositoryNameWithOwner: 'openclaw/openclaw',
        merged: 1,
        mergedAt: '2026-06-03T12:00:00Z',
        source: 'ClosedEvent.closer',
      }],
      hasNotReachableClosingPr: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map(),
      () => ({ tag: 'v2', published_at: '2026-06-02T00:00:00Z' }),
    );

    assert.equal(adjusted.status, 'fixed_after_latest_release');
    assert.equal((evidence as any).unscoredFixProof.proofTime, '2026-06-03T12:00:00Z');
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

  it('classifies not-planned closures with trusted reachable closure-comment fix proof as release proof', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 88764, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          reachable: [{
            number: 88764,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.fixProof',
            title: 'fix(update): recognize manual-update launchd jobs',
          }],
        },
      },
    );

    assert.equal(adjusted.status, 'not_planned_with_release_fix_proof');
    assert.equal((adjusted.evidence.reachableTrustedFixProofPrs as any[])[0].number, 88764);
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

  it('classifies no-context not-planned closures with open PR context separately', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_no_context', 'No close-time context.'),
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

  it('classifies not-planned related PR context by reachability', () => {
    const reachable = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 123, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          reachable: [{ number: 123, repositoryNameWithOwner: 'openclaw/openclaw' }],
        },
      },
    );
    const notReachable = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 124, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          notReachable: [{ number: 124, repositoryNameWithOwner: 'openclaw/openclaw' }],
        },
      },
    );
    const unknown = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 125, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          unknownReachability: [{ number: 125, repositoryNameWithOwner: 'openclaw/openclaw' }],
        },
      },
    );
    const closed = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 126, state: 'CLOSED', merged: 0 }],
        relatedPrContext: {
          closedUnmerged: [{ number: 126, repositoryNameWithOwner: 'openclaw/openclaw' }],
        },
      },
    );

    assert.equal(reachable.status, 'not_planned_related_merged_pr_reachable_context_without_fix_credit');
    assert.equal(notReachable.status, 'not_planned_related_merged_pr_not_reachable_context');
    assert.equal(unknown.status, 'not_planned_related_merged_pr_reachability_unknown');
    assert.equal(closed.status, 'not_planned_related_closed_unmerged_pr_context');
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
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as duplicate/superseded: this is covered by broader reports, especially #88562 and #90774.',
      ),
      [88562, 90774],
    );
  });

  it('does not treat canonical PR links as canonical issue targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Canonical path: Open PR https://github.com/openclaw/openclaw/pull/85651 owns this feature work.',
      ),
      [],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as superseded. Canonical path: Open PR #85651 owns this feature work.',
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

  it('filters canonical graph targets to real issues when PR numbers are also referenced', () => {
    const comments = [
      {
        created_at: '2026-06-28T10:00:00Z',
        body: 'Close as duplicate. Canonical path: use PR #86281 for implementation and issue #86773 for the remaining tracker.',
      },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(
        closureComments,
        10,
        (number: number) => number === 86773,
      ),
      [86773],
    );
  });

  it('promotes neutral closure rows with strong bug evidence before proof classification', () => {
    const result = __closureProofAnalysisTest.effectiveClosureProofClassification({
      title: '[Bug]: Cron announce delivery reports success but message never arrives',
      labels: JSON.stringify(['stale', 'clawsweeper:source-repro', 'impact:message-loss']),
      sentiment: 'negative',
      severity: 'medium',
      scope: 'moderate',
      functionality: 'integration',
      affected_users: 'some',
      has_workaround: 0,
      workaround_status: 'unknown',
      duplicate_cluster: null,
      affects_version: null,
      confidence: 0.7,
      rationale: '',
    });

    assert.equal(result.rawClassification.sentiment, 'negative');
    assert.equal(result.classification.sentiment, 'negative');
    assert.equal(result.classificationDiff.sentiment, undefined);
  });

  it('restores neutralized stale bug evidence to negative closure risk', () => {
    const result = __closureProofAnalysisTest.effectiveClosureProofClassification({
      title: 'Gateway lazy-spawns duplicate stdio MCP children with identical ppid+config (memory + CPU leak)',
      labels: JSON.stringify(['stale', 'P1', 'impact:crash-loop', 'impact:session-state']),
      sentiment: 'neutral',
      severity: 'medium',
      scope: 'moderate',
      functionality: 'core',
      affected_users: 'many',
      has_workaround: 0,
      workaround_status: 'unknown',
      duplicate_cluster: null,
      affects_version: null,
      confidence: 0.7,
      rationale: '',
    });

    assert.equal(result.rawClassification.sentiment, 'neutral');
    assert.equal(result.classification.sentiment, 'negative');
    assert.deepEqual(result.classificationDiff.sentiment, { raw: 'neutral', effective: 'negative' });
  });

  it('uses release-cutoff labels instead of current labels for closure proof classification', () => {
    const result = __closureProofAnalysisTest.effectiveClosureProofClassification(
      {
        number: 42,
        title: 'Provider setup confusion',
        labels: JSON.stringify(['stale']),
        sentiment: 'negative',
        severity: 'medium',
        scope: 'moderate',
        functionality: 'provider',
        affected_users: 'some',
        has_workaround: 0,
        workaround_status: 'unknown',
        duplicate_cluster: null,
        affects_version: null,
        confidence: 0.7,
        rationale: '',
      },
      '2026-06-01T00:00:00Z',
      () => [],
      () => 1,
      () => 0,
    );

    assert.deepEqual(result.currentLabels, ['stale']);
    assert.deepEqual(result.labels, []);
    assert.equal(result.labelSource, 'timeline');
    assert.equal(result.labelCutoffAt, '2026-06-01T00:00:00Z');
    assert.equal(result.classification.sentiment, 'negative');
  });

  it('marks missing classification rows without promoting closure proof credit', () => {
    const classification = __closureProofAnalysisTest.effectiveClosureProofClassification({
      title: '[Bug]: closed issue still needs classification',
      labels: JSON.stringify(['bug']),
      sentiment: null,
      severity: null,
      scope: null,
      functionality: null,
      affected_users: null,
      has_workaround: null,
      workaround_status: null,
      duplicate_cluster: null,
      affects_version: null,
      confidence: null,
      rationale: null,
      classification_issue_number: null,
      classification_prompt_version: null,
    });
    assert.equal((classification as any).missingClassification, true);
    assert.equal(classification.classification.sentiment, 'neutral');
    assert.equal(classification.classification.confidence, 0);

    const proof = __closureProofAnalysisTest.missingClassificationClosureProof({
      classification_issue_number: null,
      classification_prompt_version: null,
    });
    assert.equal(proof.status, 'unknown');
    assert.equal((proof.evidence as any).missingClassification, true);
  });

  it('builds referenced commit context from eligible same-repo commit references only', () => {
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

  it('does not use referenced commit context as fallback fix proof', () => {
    assert.equal(__closureProofAnalysisTest.shouldUseReferencedCommitProof({
      directMentionCount: 0,
      reachableClosingPrCount: 0,
    }), false);
  });

  it('does not use referenced commit fallback when reachable PR or direct commit proof already exists', () => {
    assert.equal(__closureProofAnalysisTest.shouldUseReferencedCommitProof({
      directMentionCount: 0,
      reachableClosingPrCount: 1,
    }), false);
    assert.equal(__closureProofAnalysisTest.shouldUseReferencedCommitProof({
      directMentionCount: 1,
      reachableClosingPrCount: 0,
    }), false);
  });
});
