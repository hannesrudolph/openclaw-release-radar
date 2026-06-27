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

  it('classifies merged but unreachable PR fixes as fixed after release', () => {
    const result = classifyClosureProof(input({
      hasClosingLink: true,
      hasMergedClosingPr: true,
      hasNotReachableClosingPr: true,
    }));
    assert.equal(result.status, 'fixed_after_release');
  });

  it('recognizes duplicate or superseded closure comments', () => {
    const result = classifyClosureProof(input({
      stateReasons: ['NOT_PLANNED'],
      comments: [{ author: 'bot', body: 'Close as duplicate/superseded by the broader tracker.' }],
    }));
    assert.equal(result.status, 'duplicate_or_superseded');
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
