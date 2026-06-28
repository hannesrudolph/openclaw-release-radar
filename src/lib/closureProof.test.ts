import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { classifyClosureProof, type ClosureProofInput } from './closureProof.ts';

function input(overrides: Partial<ClosureProofInput>): ClosureProofInput {
  return {
    issueNumber: 1,
    sentiment: 'negative',
    stateReasons: ['COMPLETED'],
    closureActors: ['maintainer'],
    hasClosureEvent: true,
    hasClosingLink: false,
    hasMergedClosingPr: false,
    hasReachableClosingPr: false,
    hasNotReachableClosingPr: false,
    comments: [],
    ...overrides,
  };
}

describe('classifyClosureProof', () => {
  it('credits reachable merged closing PRs as fixed in release', () => {
    const result = classifyClosureProof(input({
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasReachableClosingPr: true,
    }));
    assert.equal(result.status, 'fixed_in_release');
  });

  it('credits named reachable fix commits as fixed in release', () => {
    const result = classifyClosureProof(input({
      hasReachableFixCommit: true,
      reachableFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
      comments: [{ author: 'maintainer', body: 'Fixed on main in cfeaf6897fd89201b71ff7d5285e48c5a382ac9a.' }],
    }));
    assert.equal(result.status, 'fixed_in_release');
    assert.deepEqual(result.evidence.reachableFixCommits, ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a']);
  });

  it('classifies merged but unreachable PR fixes as fixed after release', () => {
    const result = classifyClosureProof(input({
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasNotReachableClosingPr: true,
    }));
    assert.equal(result.status, 'fixed_after_release');
  });

  it('classifies unreachable fix commits as fixed after release', () => {
    const result = classifyClosureProof(input({
      hasNotReachableFixCommit: true,
      notReachableFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
    }));
    assert.equal(result.status, 'fixed_after_release');
  });

  it('does not credit reachable PRs when the closure reason is not completed', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasReachableClosingPr: true,
      comments: [{
        author: 'bot',
        body: 'Close as superseded.\nCanonical: #95750',
      }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
    assert.deepEqual(result.evidence.canonicalIssues, [95750]);
  });

  it('recognizes duplicate or superseded closure comments', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      comments: [{ author: 'bot', body: 'Close as duplicate/superseded by the broader tracker.' }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
  });

  it('extracts common duplicate target comments as canonical issues', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      comments: [{ author: 'bot', body: 'Closing as duplicate of https://github.com/openclaw/openclaw/issues/96857.' }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
    assert.deepEqual(result.evidence.canonicalIssues, [96857]);
  });

  it('uses close-time comments that say closing this as a duplicate', () => {
    const result = classifyClosureProof(input({
      closedAt: '2026-06-25T22:25:56Z',
      stateReasons: ['DUPLICATE'],
      comments: [{
        author: 'reporter',
        createdAt: '2026-06-25T22:25:55Z',
        body: 'Closing this as a duplicate of #96857. Keeping the upstream discussion centralized there.',
      }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
    assert.equal(result.evidence.closureContextCommentCount, 1);
    assert.deepEqual(result.evidence.canonicalIssues, [96857]);
  });

  it('extracts open canonical tracker references from duplicate comments', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      comments: [{
        author: 'bot',
        body: 'Close as a duplicate of the open canonical tracker #60841, not as fixed.',
      }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
    assert.deepEqual(result.evidence.canonicalIssues, [60841]);
  });

  it('does not treat negated duplicate discussion as duplicate closure rationale', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      comments: [{ author: 'bot', body: 'This is not a duplicate; closing as expected behavior.' }],
    }));
    assert.equal(result.status, 'not_planned');
  });

  it('recognizes reporter-refiled issues as replacement context, not missing fix proof', () => {
    const result = classifyClosureProof(input({
      issueAuthor: 'reporter',
      closureActors: ['reporter'],
      comments: [{ author: 'reporter', body: 'Reopened as English version: #96333' }],
    }));
    assert.equal(result.status, 'reporter_replaced');
    assert.equal(result.evidence.reporterSelfClosed, true);
  });

  it('recognizes reporter withdrawals as non-fix closure context', () => {
    const result = classifyClosureProof(input({
      issueAuthor: 'reporter',
      closureActors: ['reporter'],
      comments: [{ author: 'reporter', body: 'Apologies, please ignore.' }],
    }));
    assert.equal(result.status, 'reporter_withdrawn');
  });

  it('separates latest-version repro requests from generic missing code proof', () => {
    const result = classifyClosureProof(input({
      closedAt: '2026-06-28T02:41:48Z',
      comments: [{
        author: 'maintainer',
        createdAt: '2026-06-28T02:41:48Z',
        body: 'Please file a new issue if this still repos with latest imsg and openclaw',
      }],
    }));
    assert.equal(result.status, 'repro_requested');
    assert.equal(result.evidence.closureContextCommentCount, 1);
    assert.equal((result.evidence.matchingComments as any[]).length, 1);
  });

  it('does not classify broad future-failure follow-up wording as a latest-version repro request', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      closedAt: '2026-06-27T20:36:35Z',
      comments: [{
        author: 'bot',
        createdAt: '2026-06-27T20:23:27Z',
        body: 'Close as superseded: the issue is tracked in an active continuation PR. Open a new issue only if that surface lands and still fails on main or a release.',
      }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
  });

  it('does not infer reporter withdrawal from maintainer-only closure wording', () => {
    const result = classifyClosureProof(input({
      issueAuthor: 'reporter',
      closureActors: ['maintainer'],
      comments: [{ author: 'maintainer', body: 'Could not reproduce anymore, closing as not planned.' }],
    }));
    assert.equal(result.status, 'not_planned');
  });

  it('separates unexplained reporter self-closures from missing maintainer fix proof', () => {
    const result = classifyClosureProof(input({
      issueAuthor: 'reporter',
      closureActors: ['reporter'],
      comments: [],
    }));
    assert.equal(result.status, 'reporter_self_closed');
  });

  it('recognizes already-present claims without treating them as release proof', () => {
    const result = classifyClosureProof(input({
      comments: [{ author: 'bot', body: 'Current main and tagged releases already implement this behavior.' }],
    }));
    assert.equal(result.status, 'already_present_claim');
    assert.deepEqual(result.evidence.canonicalIssues, []);
  });

  it('does not use stale review comments as the closure rationale', () => {
    const result = classifyClosureProof(input({
      closedAt: '2026-06-25T01:31:42Z',
      comments: [{
        author: 'bot',
        createdAt: '2026-06-18T19:14:00Z',
        body: 'Keep open. Current main and v2026.6.8 still run this path serially.',
      }],
    }));
    assert.equal(result.status, 'no_code_proof');
    assert.equal(result.evidence.closureContextCommentCount, 0);
    assert.deepEqual(result.evidence.matchingComments, []);
  });

  it('does not treat keep-open current-main review text as an already-present closure claim', () => {
    const result = classifyClosureProof(input({
      comments: [{
        author: 'bot',
        body: 'Keep open: current main and the latest release still lack the required fallback before closing this issue.',
      }],
    }));
    assert.equal(result.status, 'no_code_proof');
  });

  it('uses close-time comments as the closure rationale', () => {
    const result = classifyClosureProof(input({
      closedAt: '2026-06-25T01:31:42Z',
      comments: [{
        author: 'bot',
        createdAt: '2026-06-24T19:14:00Z',
        body: 'Close: current main and tagged releases already implement this behavior.',
      }],
    }));
    assert.equal(result.status, 'already_present_claim');
    assert.equal(result.evidence.closureContextCommentCount, 1);
  });

  it('keeps stale not-planned admin closures as unsupported risk when no close-time rationale exists', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      closedAt: '2026-06-27T21:45:31Z',
      comments: [{
        author: 'bot',
        createdAt: '2026-06-20T21:45:31Z',
        body: 'Current main already contains related cache-size work.',
      }],
    }));
    assert.equal(result.status, 'admin_not_planned_unverified');
    assert.equal(result.evidence.closureContextCommentCount, 0);
  });

  it('keeps outside-repository not-planned closures neutral when close-time rationale is concrete', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      closedAt: '2026-06-27T21:45:31Z',
      comments: [{
        author: 'bot',
        createdAt: '2026-06-27T21:44:31Z',
        body: 'Close: this lives outside the OpenClaw source repository and is plugin-owned, so it is not actionable as core work.',
      }],
    }));
    assert.equal(result.status, 'not_planned');
    assert.equal(result.evidence.closureContextCommentCount, 1);
  });

  it('keeps duplicate/superseded closures distinct from already-present claims', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['COMPLETED'],
      comments: [{
        author: 'bot',
        body: 'Current main already contains the fix. Root-cause cluster relationship: duplicate.\nCanonical: #96660',
      }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
    assert.deepEqual(result.evidence.canonicalIssues, [96660]);
  });

  it('keeps duplicate/superseded closures distinct from main-only claims', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      comments: [{
        author: 'bot',
        body: 'Close as superseded: current main already has part of this, and the remaining work is tracked by the canonical issue.\nCanonical: #94518',
      }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
    assert.deepEqual(result.evidence.canonicalIssues, [94518]);
  });

  it('lets reachable proof override stale current-main-only claims', () => {
    const result = classifyClosureProof(input({
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasReachableClosingPr: true,
      comments: [{
        author: 'bot',
        body: 'Current main already fixes this path, but stable v2026.6.10 predates the fix.',
      }],
    }));
    assert.equal(result.status, 'fixed_in_release');
  });

  it('separates current-main-only claims from missing release proof', () => {
    const result = classifyClosureProof(input({
      comments: [{
        author: 'bot',
        body: 'Current main already fixes this path, but stable v2026.6.10 predates the fix.',
      }],
    }));
    assert.equal(result.status, 'main_only_claim');
  });

  it('separates neutral closed items from bug evidence', () => {
    const result = classifyClosureProof(input({ sentiment: 'neutral' }));
    assert.equal(result.status, 'non_bug_neutral');
  });

  it('preserves reachable proof shape for neutral closed items without fix credit', () => {
    const result = classifyClosureProof(input({
      sentiment: 'neutral',
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasReachableClosingPr: true,
    }));
    assert.equal(result.status, 'non_bug_fixed_in_release');
  });

  it('preserves not-reachable proof shape for neutral closed items', () => {
    const result = classifyClosureProof(input({
      sentiment: 'neutral',
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasNotReachableClosingPr: true,
    }));
    assert.equal(result.status, 'non_bug_fixed_after_release');
  });

  it('preserves unmerged linked PR shape for neutral closed items', () => {
    const result = classifyClosureProof(input({
      sentiment: 'neutral',
      hasClosingLink: true,
      hasMergedClosingPr: false,
    }));
    assert.equal(result.status, 'non_bug_linked_without_merge');
  });

  it('preserves duplicate closure shape for neutral items', () => {
    const result = classifyClosureProof(input({
      sentiment: 'neutral',
      stateReasons: ['NOT_PLANNED'],
      comments: [{ author: 'bot', body: 'Close as duplicate of #1234.' }],
    }));
    assert.equal(result.status, 'non_bug_duplicate_or_superseded');
    assert.deepEqual(result.evidence.canonicalIssues, [1234]);
  });

  it('preserves concrete non-actionable rationale for neutral items', () => {
    const result = classifyClosureProof(input({
      sentiment: 'neutral',
      stateReasons: ['NOT_PLANNED'],
      comments: [{
        author: 'bot',
        body: 'Close: this lives outside the OpenClaw source repository and is plugin-owned.',
      }],
    }));
    assert.equal(result.status, 'non_bug_not_actionable');
    assert.equal((result.evidence.nonActionableRationaleComments as any[]).length, 1);
  });

  it('keeps missing closure timeline evidence visible even for neutral items', () => {
    const result = classifyClosureProof(input({
      sentiment: 'neutral',
      hasClosureEvent: false,
    }));
    assert.equal(result.status, 'no_timeline_event');
  });

  it('identifies missing timeline evidence', () => {
    const result = classifyClosureProof(input({ hasClosureEvent: false }));
    assert.equal(result.status, 'no_timeline_event');
  });
});
