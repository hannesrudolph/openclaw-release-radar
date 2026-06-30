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

  it('emits typed evidence with commit identity and command diagnostics', () => {
    const tagCommitOid = 'a'.repeat(40);
    const checkedCommitOid = 'b'.repeat(40);
    const evidence = __releaseReachabilityTest.reachabilityEvidence({
      evidence: 'commit_fetch_failed',
      tagCommitOid,
      checkedCommitOid,
      baseRefName: 'main',
      command: { status: 128, stdout: '', stderr: 'fatal: bad object', signal: null } as any,
    });

    assert.equal(evidence.schemaVersion, 1);
    assert.equal(evidence.evidence, 'commit_fetch_failed');
    assert.equal(evidence.method, 'git-merge-base');
    assert.equal(evidence.tagCommitOid, tagCommitOid);
    assert.equal(evidence.checkedCommitOid, checkedCommitOid);
    assert.equal(evidence.baseRefName, 'main');
    assert.equal(evidence.commandStatus, 128);
    assert.equal(evidence.stderr, 'fatal: bad object');
  });

  it('exports every persisted reachability evidence reason as known', () => {
    assert.ok(__releaseReachabilityTest.KNOWN_REACHABILITY_EVIDENCE_REASONS.includes('merge_commit_in_release_history'));
    assert.ok(__releaseReachabilityTest.KNOWN_REACHABILITY_EVIDENCE_REASONS.includes('not_reachable_from_release_tag'));
    assert.ok(__releaseReachabilityTest.KNOWN_REACHABILITY_EVIDENCE_REASONS.includes('merge_base_error'));
  });
});
