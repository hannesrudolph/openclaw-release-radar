import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { __releaseReachabilityTest } from './releaseReachability.ts';

describe('release reachability helpers', () => {
  it('distinguishes true non-ancestry from git errors', () => {
    const reachable = __releaseReachabilityTest.interpretMergeBaseResult(
      { status: 0, stdout: '', stderr: '', signal: null } as any,
      'merge_commit_in_release_history',
    );
    assert.equal(reachable.status, 'reachable');
    assert.equal(reachable.evidence.evidence, 'merge_commit_in_release_history');

    const notReachable = __releaseReachabilityTest.interpretMergeBaseResult(
      { status: 1, stdout: '', stderr: '', signal: null } as any,
      'merge_commit_in_release_history',
    );
    assert.equal(notReachable.status, 'not_reachable');
    assert.equal(notReachable.evidence.evidence, 'not_reachable_from_release_tag');

    const error = __releaseReachabilityTest.interpretMergeBaseResult(
      { status: 128, stdout: '', stderr: 'fatal: bad object', signal: null } as any,
      'merge_commit_in_release_history',
    );
    assert.equal(error.status, 'unknown');
    assert.equal(error.evidence.evidence, 'merge_base_error');
    assert.equal(error.evidence.status, 128);
    assert.equal(error.evidence.stderr, 'fatal: bad object');
  });
});
