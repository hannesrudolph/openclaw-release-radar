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

  it('separates current-main-only claims from release-present claims', () => {
    const result = classifyClosureProof(input({
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasReachableClosingPr: true,
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

  it('identifies missing timeline evidence', () => {
    const result = classifyClosureProof(input({ hasClosureEvent: false }));
    assert.equal(result.status, 'no_timeline_event');
  });
});
