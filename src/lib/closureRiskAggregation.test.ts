import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  aggregateClosureRisk,
  allCanonicalIssueNumbersFromEvidence,
  buildIssueAliasGroups,
  canonicalIssueNumbersFromEvidence,
} from './closureRiskAggregation.ts';

describe('closure risk aggregation', () => {
  it('counts one risk group for duplicate reports sharing a canonical issue', () => {
    const result = aggregateClosureRisk([
      { issueNumber: 1, canonicalIssueNumber: 99, duplicateCluster: 'a', disposition: 'open_canonical_risk', weight: 2 },
      { issueNumber: 2, canonicalIssueNumber: 99, duplicateCluster: 'b', disposition: 'open_canonical_risk', weight: 3 },
      { issueNumber: 3, canonicalIssueNumber: 99, disposition: 'open_canonical_risk', weight: 1 },
    ]);

    assert.equal(result.unresolvedForReleaseCount, 1);
    assert.equal(result.unresolvedWeightedRisk, 3);
    assert.deepEqual(result.weightedRiskByDisposition, { open_canonical_risk: 3 });
  });

  it('keeps classifier-only duplicate slugs as independent risk', () => {
    const result = aggregateClosureRisk([
      { issueNumber: 1, duplicateCluster: 'same-bug', disposition: 'known_not_in_release', weight: 2 },
      { issueNumber: 2, duplicateCluster: 'same-bug', disposition: 'known_not_in_release', weight: 1 },
      { issueNumber: 3, disposition: 'unsupported_closure_claim', weight: 0.5 },
    ]);

    assert.equal(result.unresolvedForReleaseCount, 3);
    assert.equal(result.unresolvedWeightedRisk, 3.5);
  });

  it('prefers the stronger disposition when equal-weight evidence shares a group', () => {
    const result = aggregateClosureRisk([
      { issueNumber: 1, canonicalIssueNumber: 99, duplicateCluster: 'same', disposition: 'known_not_in_release', weight: 2 },
      { issueNumber: 2, canonicalIssueNumber: 99, duplicateCluster: 'same', disposition: 'missing_evidence', weight: 2 },
    ]);

    assert.deepEqual(result.weightedRiskByDisposition, { missing_evidence: 2 });
  });

  it('unifies explicit canonical aliases without absorbing classifier-only peers', () => {
    const result = aggregateClosureRisk([
      {
        issueNumber: 1,
        duplicateCluster: 'alpha',
        canonicalIssueNumbers: [99],
        disposition: 'known_not_in_release',
        weight: 2,
      },
      {
        issueNumber: 2,
        duplicateCluster: 'beta',
        canonicalIssueNumbers: [99],
        disposition: 'missing_evidence',
        weight: 4,
      },
      {
        issueNumber: 3,
        duplicateCluster: ' ALPHA ',
        disposition: 'unsupported_closure_claim',
        weight: 3,
      },
    ]);

    assert.equal(result.unresolvedForReleaseCount, 2);
    assert.equal(result.unresolvedWeightedRisk, 7);
    assert.deepEqual(result.weightedRiskByDisposition, {
      missing_evidence: 4,
      unsupported_closure_claim: 3,
    });
  });

  it('never reduces risk when an unrelated row reuses a classifier slug', () => {
    const before = aggregateClosureRisk([
      {
        issueNumber: 701,
        duplicateCluster: 'classifier-says-same',
        disposition: 'missing_evidence',
        weight: 5,
      },
    ]);
    const after = aggregateClosureRisk([
      ...before.groups.map(({ key: _key, ...item }) => item),
      {
        issueNumber: 702,
        duplicateCluster: 'CLASSIFIER-SAYS-SAME',
        disposition: 'open_canonical_risk',
        weight: 4,
      },
    ]);

    assert.equal(before.unresolvedWeightedRisk, 5);
    assert.equal(after.unresolvedWeightedRisk, 9);
    assert.equal(after.unresolvedForReleaseCount, 2);
  });

  it('keeps independent canonical terminals additive when duplicate closures share a cluster', () => {
    const result = aggregateClosureRisk([
      {
        issueNumber: 101,
        duplicateCluster: 'shared-classifier-cluster',
        disposition: 'open_canonical_risk',
        weight: 7,
      },
      {
        issueNumber: 202,
        duplicateCluster: 'shared-classifier-cluster',
        disposition: 'open_canonical_risk',
        weight: 5,
      },
      {
        issueNumber: 301,
        duplicateCluster: 'shared-classifier-cluster',
        canonicalIssueNumber: 101,
        disposition: 'unsupported_closure_claim',
        weight: 1,
      },
      {
        issueNumber: 302,
        duplicateCluster: 'shared-classifier-cluster',
        canonicalIssueNumber: 202,
        disposition: 'unsupported_closure_claim',
        weight: 1,
      },
    ]);

    assert.equal(result.unresolvedForReleaseCount, 2);
    assert.equal(result.unresolvedWeightedRisk, 12);
    assert.deepEqual(result.weightedRiskByDisposition, { open_canonical_risk: 12 });
    assert.deepEqual(result.groups.map((group) => group.issueNumber), [101, 202]);
  });

  it('aggregates shared-cluster canonical terminals independently of row order', () => {
    const rows = [
      {
        issueNumber: 101,
        duplicateCluster: 'shared-classifier-cluster',
        disposition: 'open_canonical_risk',
        weight: 7,
      },
      {
        issueNumber: 301,
        duplicateCluster: 'shared-classifier-cluster',
        canonicalIssueNumber: 101,
        disposition: 'unsupported_closure_claim',
        weight: 1,
      },
      {
        issueNumber: 202,
        duplicateCluster: 'shared-classifier-cluster',
        disposition: 'open_canonical_risk',
        weight: 5,
      },
      {
        issueNumber: 302,
        duplicateCluster: 'shared-classifier-cluster',
        canonicalIssueNumber: 202,
        disposition: 'unsupported_closure_claim',
        weight: 1,
      },
    ];

    assert.deepEqual(
      aggregateClosureRisk(rows),
      aggregateClosureRisk([...rows].reverse()),
    );
  });

  it('does not reduce canonical risk when shared-cluster duplicate closures are added', () => {
    const canonicalRows = [
      {
        issueNumber: 101,
        duplicateCluster: 'shared-classifier-cluster',
        disposition: 'open_canonical_risk',
        weight: 7,
      },
      {
        issueNumber: 202,
        duplicateCluster: 'shared-classifier-cluster',
        disposition: 'open_canonical_risk',
        weight: 5,
      },
    ];
    const before = aggregateClosureRisk(canonicalRows);
    const after = aggregateClosureRisk([
      ...canonicalRows,
      {
        issueNumber: 301,
        duplicateCluster: 'shared-classifier-cluster',
        canonicalIssueNumber: 101,
        disposition: 'unsupported_closure_claim',
        weight: 1,
      },
      {
        issueNumber: 302,
        duplicateCluster: 'shared-classifier-cluster',
        canonicalIssueNumber: 202,
        disposition: 'unsupported_closure_claim',
        weight: 1,
      },
    ]);

    assert.equal(before.unresolvedWeightedRisk, 12);
    assert.ok(after.unresolvedWeightedRisk >= before.unresolvedWeightedRisk);
    assert.equal(after.unresolvedWeightedRisk, 12);
  });

  it('does not let zero-weight bridges merge independent risk groups', () => {
    const rows = [
      {
        issueNumber: 101,
        disposition: 'missing_evidence',
        weight: 7,
      },
      {
        issueNumber: 202,
        disposition: 'open_canonical_risk',
        weight: 5,
      },
      {
        issueNumber: 303,
        canonicalIssueNumbers: [101, 202],
        disposition: 'unsupported_closure_claim',
        weight: 0,
      },
    ];

    for (const orderedRows of [rows, [...rows].reverse()]) {
      const result = aggregateClosureRisk(orderedRows);
      assert.equal(result.unresolvedForReleaseCount, 2);
      assert.equal(result.unresolvedWeightedRisk, 12);
      assert.deepEqual(
        result.groups.map((group) => group.issueNumber),
        [101, 202],
      );
    }
  });

  it('builds deterministic groups regardless of row order', () => {
    const rows = [
      { issueNumber: 12, duplicateCluster: 'second', canonicalIssueNumbers: [40] },
      { issueNumber: 10, duplicateCluster: 'first', canonicalIssueNumbers: [40] },
      { issueNumber: 11, duplicateCluster: 'FIRST' },
    ];
    const forward = buildIssueAliasGroups(rows);
    const reverse = buildIssueAliasGroups([...rows].reverse());

    assert.deepEqual(forward.groups, reverse.groups);
    assert.equal(forward.keyFor(rows[0]), 'issue:10');
    assert.equal(forward.keyFor(rows[2]), 'issue:11');
  });

  it('extracts all canonical proof aliases used by dependency evidence', () => {
    assert.deepEqual(allCanonicalIssueNumbersFromEvidence(JSON.stringify({
      canonicalIssues: [20],
      canonicalIssueDetails: [{ number: 30 }],
      canonicalResolution: {
        path: [10, 20],
        terminalIssues: [{ number: 40 }],
        branches: [{
          path: [10, 50],
          terminalProof: { terminalIssueNumber: 60 },
        }],
      },
    })), [10, 20, 30, 40, 50, 60]);
  });

  it('does not bridge #98671 sibling branches #97877 and #98416', () => {
    const evidence = {
      canonicalIssues: [97877, 98416],
      canonicalResolution: {
        path: [98671, 97877],
        terminalIssue: { number: 97877 },
        terminalIssues: [{ number: 97877 }, { number: 98416 }],
        branches: [
          { path: [98671, 97877], terminalIssue: { number: 97877 } },
          { path: [98671, 98416], terminalIssue: { number: 98416 } },
        ],
      },
    };
    const aliases = canonicalIssueNumbersFromEvidence(evidence);
    assert.deepEqual(aliases, [97877, 98671]);
    assert.ok(!aliases.includes(98416));

    const before = aggregateClosureRisk([
      { issueNumber: 97877, disposition: 'missing_evidence', weight: 4 },
      { issueNumber: 98416, disposition: 'open_canonical_risk', weight: 3 },
    ]);
    const after = aggregateClosureRisk([
      { issueNumber: 97877, disposition: 'missing_evidence', weight: 4 },
      { issueNumber: 98416, disposition: 'open_canonical_risk', weight: 3 },
      {
        issueNumber: 98671,
        canonicalIssueNumbers: aliases,
        disposition: 'unsupported_closure_claim',
        weight: 0.1,
      },
    ]);

    assert.equal(before.unresolvedWeightedRisk, 7);
    assert.equal(after.unresolvedWeightedRisk, 7);
    assert.equal(after.unresolvedForReleaseCount, 2);
  });

  it('uses blocking branch metadata instead of a stale primary path', () => {
    const aliases = canonicalIssueNumbersFromEvidence({
      canonicalResolution: {
        path: [98671, 97877],
        terminalIssue: { number: 98416 },
        blockingBranch: [98671, 98416],
        branches: [
          { path: [98671, 97877], terminalIssue: { number: 97877 } },
          { path: [98671, 98416], terminalIssue: { number: 98416 } },
        ],
      },
    });

    assert.deepEqual(aliases, [98416, 98671]);
    assert.ok(!aliases.includes(97877));
  });

  it('uses the changed terminal branch instead of fusing it with a stale path', () => {
    const aliases = canonicalIssueNumbersFromEvidence({
      canonicalResolution: {
        path: [98671, 97877],
        terminalIssue: { number: 98416 },
        branches: [
          { path: [98671, 97877], terminalIssue: { number: 97877 } },
          { path: [98671, 98416], terminalIssue: { number: 98416 } },
        ],
      },
    });

    assert.deepEqual(aliases, [98416, 98671]);
    assert.ok(!aliases.includes(97877));
  });

  it('rejects a stale blocking branch when the selected terminal moved to a sibling', () => {
    const aliases = canonicalIssueNumbersFromEvidence({
      canonicalResolution: {
        path: [98671, 97877],
        terminalIssue: { number: 98416 },
        blockingBranch: [98671, 97877],
        branches: [
          { path: [98671, 97877], terminalIssue: { number: 97877 } },
          { path: [98671, 98416], terminalIssue: { number: 98416 } },
        ],
      },
    });

    assert.deepEqual(aliases, [98416, 98671]);
    assert.ok(!aliases.includes(97877));
  });

  it('selects the adverse sibling regardless of issue-number or branch ordering', () => {
    for (const [neutralIssueNumber, adverseIssueNumber] of [
      [97877, 98416],
      [98416, 97877],
    ] as const) {
      const neutralBranch = {
        path: [98671, neutralIssueNumber],
        terminalIssue: { number: neutralIssueNumber, state: 'closed' },
        terminalProof: { status: 'non_bug_neutral' },
      };
      const adverseBranch = {
        path: [98671, adverseIssueNumber],
        terminalIssue: { number: adverseIssueNumber, state: 'closed' },
        terminalProof: { status: 'closed_without_release_fix_proof' },
      };
      const aliases = canonicalIssueNumbersFromEvidence({
        canonicalResolution: {
          path: neutralBranch.path,
          terminalIssue: neutralBranch.terminalIssue,
          branches: neutralIssueNumber < adverseIssueNumber
            ? [neutralBranch, adverseBranch]
            : [adverseBranch, neutralBranch],
        },
      });

      assert.deepEqual(aliases, [adverseIssueNumber, 98671].sort((a, b) => a - b));
      assert.ok(!aliases.includes(neutralIssueNumber));
    }
  });

  it('does not use a favorable fixed branch as the identity for a fixed-after roll-up', () => {
    for (const [fixedIssueNumber, fixedAfterIssueNumber] of [
      [97877, 98416],
      [98416, 97877],
    ] as const) {
      const aliases = canonicalIssueNumbersFromEvidence({
        canonicalResolution: {
          path: [98671, fixedIssueNumber],
          terminalIssue: { number: fixedIssueNumber, state: 'closed' },
          branches: [
            {
              path: [98671, fixedIssueNumber],
              terminalIssue: { number: fixedIssueNumber, state: 'closed' },
              fixedInRelease: true,
              currentTagContainsFix: true,
              fixedAfterRelease: false,
              terminalProof: { status: 'fixed_in_release' },
            },
            {
              path: [98671, fixedAfterIssueNumber],
              terminalIssue: { number: fixedAfterIssueNumber, state: 'closed' },
              fixedInRelease: false,
              currentTagContainsFix: false,
              fixedAfterRelease: true,
              terminalProof: { status: 'fixed_after_release' },
            },
          ],
        },
      });

      assert.deepEqual(
        aliases,
        [fixedAfterIssueNumber, 98671].sort((left, right) => left - right),
      );
      assert.ok(!aliases.includes(fixedIssueNumber));
    }
  });

  it('chooses a deterministic single fallback when only canonicalIssues exist', () => {
    const evidence = { canonicalIssues: [98416, 97877] };
    assert.deepEqual(canonicalIssueNumbersFromEvidence(evidence), [97877]);
    assert.deepEqual(canonicalIssueNumbersFromEvidence({
      canonicalIssues: [...evidence.canonicalIssues].reverse(),
    }), [97877]);
  });

  it('adding a low-weight multi-branch adverse row never reduces aggregate load', () => {
    const random = deterministicRandom(0x98671);
    for (let index = 0; index < 500; index++) {
      const firstIssue = 100_000 + index * 3;
      const secondIssue = firstIssue + 1;
      const bridgeIssue = firstIssue + 2;
      const firstWeight = 0.5 + random() * 10;
      const secondWeight = 0.5 + random() * 10;
      const bridgeWeight = random() * Math.min(firstWeight, secondWeight);
      const branches = random() < 0.5
        ? [firstIssue, secondIssue]
        : [secondIssue, firstIssue];
      const aliases = canonicalIssueNumbersFromEvidence({
        canonicalIssues: branches,
        canonicalResolution: {
          branches: branches.map((issueNumber) => ({
            path: [bridgeIssue, issueNumber],
            terminalIssue: { number: issueNumber },
          })),
        },
      });
      const baseRows = [
        { issueNumber: firstIssue, disposition: 'missing_evidence', weight: firstWeight },
        { issueNumber: secondIssue, disposition: 'open_canonical_risk', weight: secondWeight },
      ];
      const before = aggregateClosureRisk(baseRows);
      const after = aggregateClosureRisk([
        ...baseRows,
        {
          issueNumber: bridgeIssue,
          canonicalIssueNumbers: aliases,
          disposition: 'unsupported_closure_claim',
          weight: bridgeWeight,
        },
      ]);
      assert.ok(
        after.unresolvedWeightedRisk >= before.unresolvedWeightedRisk,
        `bridge reduced load at iteration ${index}`,
      );
    }
  });
});

function deterministicRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state / 0x1_0000_0000;
  };
}
