import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  KNOWN_REACHABILITY_EVIDENCE_REASONS,
  REACHABILITY_EVIDENCE_SCHEMA_VERSION,
  REACHABILITY_EVIDENCE_VALIDATION_REASON_CODES,
  REACHABILITY_METHOD,
  validateReachabilityEvidence,
  type ReachabilityEvidenceValidationInput,
  type ReachabilityEvidenceValidationReasonCode,
} from './reachabilityEvidence.ts';

const tagCommitOid = 'a'.repeat(40);
const checkedCommitOid = 'b'.repeat(40);
const repositoryNameWithOwner = 'openclaw/openclaw';

function evidence(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: REACHABILITY_EVIDENCE_SCHEMA_VERSION,
    evidence: 'merge_commit_in_release_history',
    method: REACHABILITY_METHOD,
    tagCommitOid,
    checkedCommitOid,
    baseRefName: 'main',
    commandStatus: 0,
    stdout: null,
    stderr: null,
    signal: null,
    timedOut: false,
    outputLimitExceeded: false,
    aborted: false,
    ...overrides,
  };
}

function prInput(
  overrides: Partial<ReachabilityEvidenceValidationInput> = {},
): ReachabilityEvidenceValidationInput {
  return {
    evidence: evidence(),
    method: REACHABILITY_METHOD,
    status: 'reachable',
    identity: {
      kind: 'pull_request',
      tagCommitOid,
      checkedCommitOid,
      baseRefName: 'main',
    },
    ...overrides,
  };
}

function directInput(
  overrides: Partial<ReachabilityEvidenceValidationInput> = {},
): ReachabilityEvidenceValidationInput {
  return {
    evidence: evidence({
      evidence: 'fix_commit_in_release_history',
      repositoryNameWithOwner,
      baseRefName: null,
    }),
    method: REACHABILITY_METHOD,
    status: 'reachable',
    identity: {
      kind: 'direct_commit',
      repositoryNameWithOwner,
      tagCommitOid,
      checkedCommitOid,
    },
    ...overrides,
  };
}

function boundaryInput(
  overrides: Partial<ReachabilityEvidenceValidationInput> = {},
): ReachabilityEvidenceValidationInput {
  return {
    evidence: evidence({
      evidence: 'predecessor_release_in_target_history',
      repositoryNameWithOwner,
      baseRefName: null,
    }),
    method: REACHABILITY_METHOD,
    status: 'reachable',
    identity: {
      kind: 'release_boundary',
      repositoryNameWithOwner,
      tagCommitOid,
      checkedCommitOid,
    },
    ...overrides,
  };
}

function assertInvalid(
  input: ReachabilityEvidenceValidationInput,
  reasonCode: ReachabilityEvidenceValidationReasonCode,
): void {
  assert.deepEqual(validateReachabilityEvidence(input), {
    valid: false,
    reasonCode,
  });
}

describe('reachability evidence validation', () => {
  it('accepts consistent PR and direct-commit proof identities', () => {
    const prReachable = validateReachabilityEvidence(prInput());
    assert.equal(prReachable.valid, true);
    assert.equal(prReachable.valid && prReachable.confirmedUnavailable, false);

    assert.equal(validateReachabilityEvidence(prInput({
      status: 'not_reachable',
      evidence: evidence({
        evidence: 'not_reachable_from_release_tag',
        commandStatus: 1,
      }),
    })).valid, true);

    assert.equal(validateReachabilityEvidence(prInput({
      status: 'unknown',
      identity: {
        kind: 'pull_request',
        tagCommitOid,
        checkedCommitOid: null,
        baseRefName: 'main',
      },
      evidence: evidence({
        evidence: 'merge_commit_oid_unavailable',
        checkedCommitOid: null,
        commandStatus: null,
      }),
    })).valid, true);

    const prUnavailable = validateReachabilityEvidence(prInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'commit_unavailable',
        commandStatus: 128,
        stderr: 'fatal: remote error: upload-pack: not our ref',
        confirmedUnavailable: true,
      }),
    }));
    assert.equal(prUnavailable.valid, true);
    assert.equal(prUnavailable.valid && prUnavailable.confirmedUnavailable, true);

    assert.equal(validateReachabilityEvidence(directInput()).valid, true);
    assert.equal(validateReachabilityEvidence(directInput({
      status: 'not_reachable',
      evidence: evidence({
        evidence: 'not_reachable_from_release_tag',
        repositoryNameWithOwner,
        baseRefName: null,
        commandStatus: 1,
      }),
    })).valid, true);
    assert.equal(validateReachabilityEvidence(directInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'merge_base_error',
        repositoryNameWithOwner,
        baseRefName: null,
        commandStatus: null,
        stderr: 'spawn failed',
      }),
    })).valid, true);
    assert.equal(validateReachabilityEvidence(directInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'commit_unavailable',
        repositoryNameWithOwner,
        baseRefName: null,
        commandStatus: null,
        timedOut: true,
        confirmedUnavailable: true,
      }),
    })).valid, true);
    assert.equal(validateReachabilityEvidence(boundaryInput()).valid, true);
    assert.equal(validateReachabilityEvidence(boundaryInput({
      status: 'not_reachable',
      evidence: evidence({
        evidence: 'not_reachable_from_release_tag',
        repositoryNameWithOwner,
        baseRefName: null,
        commandStatus: 1,
      }),
    })).valid, true);
  });

  it('rejects malformed shape, schema, method, status, and reason combinations', () => {
    assertInvalid(prInput({ evidence: '{' }), 'malformed_json');
    assertInvalid(prInput({ evidence: [] }), 'evidence_not_object');

    const missingField = evidence();
    delete missingField.commandStatus;
    assertInvalid(prInput({ evidence: missingField }), 'missing_required_field');
    assertInvalid(prInput({
      evidence: evidence({ schemaVersion: 2 }),
    }), 'schema_version_mismatch');
    assertInvalid(prInput({ method: 'graph-walk' }), 'method_mismatch');
    assertInvalid(prInput({
      evidence: evidence({ method: 'graph-walk' }),
    }), 'method_mismatch');
    assertInvalid({
      ...prInput(),
      status: 'invalid' as ReachabilityEvidenceValidationInput['status'],
    }, 'invalid_status');
    assertInvalid(prInput({
      evidence: evidence({ evidence: 'invented_reason' }),
    }), 'unknown_reason');
    assertInvalid(prInput({
      status: 'unknown',
    }), 'status_reason_mismatch');
  });

  it('enforces proof-kind-specific reachable and unavailable reasons', () => {
    assertInvalid(prInput({
      evidence: evidence({ evidence: 'fix_commit_in_release_history' }),
    }), 'proof_kind_reason_mismatch');
    assertInvalid(directInput({
      evidence: evidence({
        evidence: 'merge_commit_in_release_history',
        baseRefName: null,
      }),
    }), 'proof_kind_reason_mismatch');
    assertInvalid(directInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'merge_commit_oid_unavailable',
        checkedCommitOid: null,
        baseRefName: null,
        commandStatus: null,
      }),
    }), 'proof_kind_reason_mismatch');
    assertInvalid(prInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'merge_commit_oid_unavailable',
        commandStatus: null,
      }),
    }), 'proof_kind_reason_mismatch');
    assertInvalid(directInput({
      evidence: evidence({
        evidence: 'predecessor_release_in_target_history',
        repositoryNameWithOwner,
        baseRefName: null,
      }),
    }), 'proof_kind_reason_mismatch');
    assertInvalid(boundaryInput({
      evidence: evidence({
        evidence: 'fix_commit_in_release_history',
        repositoryNameWithOwner,
        baseRefName: null,
      }),
    }), 'proof_kind_reason_mismatch');
  });

  it('rejects inconsistent tag, checked-commit, and base-ref identities', () => {
    assertInvalid(prInput({
      identity: {
        kind: 'pull_request',
        tagCommitOid: 'short',
        checkedCommitOid,
        baseRefName: 'main',
      },
    }), 'invalid_tag_commit_oid');
    assertInvalid(prInput({
      evidence: evidence({ tagCommitOid: 'c'.repeat(40) }),
    }), 'tag_commit_oid_mismatch');
    assertInvalid(prInput({
      evidence: evidence({ checkedCommitOid: 'short' }),
    }), 'invalid_checked_commit_oid');
    assertInvalid(prInput({
      evidence: evidence({ checkedCommitOid: 'c'.repeat(40) }),
    }), 'checked_commit_oid_mismatch');
    assertInvalid(prInput({
      identity: {
        kind: 'pull_request',
        tagCommitOid,
        checkedCommitOid,
        baseRefName: '',
      },
    }), 'invalid_base_ref');
    assertInvalid(prInput({
      evidence: evidence({ baseRefName: 'develop' }),
    }), 'base_ref_mismatch');
    assertInvalid(directInput({
      evidence: evidence({
        evidence: 'fix_commit_in_release_history',
        repositoryNameWithOwner,
        baseRefName: 'main',
      }),
    }), 'base_ref_mismatch');
  });

  it('requires exact repository identity for direct and release-boundary proof', () => {
    assertInvalid(directInput({
      evidence: evidence({
        evidence: 'fix_commit_in_release_history',
        baseRefName: null,
      }),
    }), 'invalid_repository_identity');
    assertInvalid(directInput({
      identity: {
        kind: 'direct_commit',
        repositoryNameWithOwner: 'openclaw',
        tagCommitOid,
        checkedCommitOid,
      },
    }), 'invalid_repository_identity');
    assertInvalid(directInput({
      evidence: evidence({
        evidence: 'fix_commit_in_release_history',
        repositoryNameWithOwner: 'other/repository',
        baseRefName: null,
      }),
    }), 'repository_identity_mismatch');
    assert.equal(validateReachabilityEvidence(directInput({
      identity: {
        kind: 'direct_commit',
        repositoryNameWithOwner: 'OpenClaw/OpenClaw',
        tagCommitOid,
        checkedCommitOid,
      },
    })).valid, true);
  });

  it('rejects contradictory command statuses and diagnostics', () => {
    assertInvalid(prInput({
      evidence: evidence({ commandStatus: 1 }),
    }), 'command_status_reason_mismatch');
    assertInvalid(prInput({
      status: 'not_reachable',
      evidence: evidence({
        evidence: 'not_reachable_from_release_tag',
        commandStatus: 0,
      }),
    }), 'command_status_reason_mismatch');
    assertInvalid(prInput({
      evidence: evidence({ timedOut: true }),
    }), 'command_status_reason_mismatch');
    assertInvalid(directInput({
      evidence: evidence({
        evidence: 'fix_commit_in_release_history',
        repositoryNameWithOwner,
        baseRefName: null,
        processTreeTerminationFailed: true,
      }),
    }), 'command_status_reason_mismatch');
    assertInvalid(directInput({
      evidence: evidence({
        evidence: 'fix_commit_in_release_history',
        repositoryNameWithOwner,
        baseRefName: null,
        processTreeTerminationFailed: 'yes',
      }),
    }), 'invalid_process_tree_diagnostics');
    assertInvalid(prInput({
      evidence: evidence({ commandStatus: 0.5 }),
    }), 'invalid_command_status');
    assertInvalid(prInput({
      evidence: evidence({ stderr: '' }),
    }), 'invalid_command_diagnostics');
    assertInvalid(prInput({
      evidence: evidence({ stderr: '   ' }),
    }), 'invalid_command_diagnostics');
    assertInvalid(prInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'merge_base_error',
        commandStatus: 1,
      }),
    }), 'command_status_reason_mismatch');
    assertInvalid(prInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'commit_fetch_failed',
        commandStatus: 0,
        stderr: 'fatal output despite success',
      }),
    }), 'command_status_reason_mismatch');
    assertInvalid(prInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'commit_fetch_failed',
        commandStatus: null,
      }),
    }), 'unknown_error_evidence_missing');
    assertInvalid(prInput({
      status: 'unknown',
      identity: {
        kind: 'pull_request',
        tagCommitOid,
        checkedCommitOid: null,
        baseRefName: 'main',
      },
      evidence: evidence({
        evidence: 'merge_commit_oid_unavailable',
        checkedCommitOid: null,
        commandStatus: 128,
      }),
    }), 'command_status_reason_mismatch');
  });

  it('requires confirmed-unavailable evidence only for unavailable commits', () => {
    assertInvalid(prInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'commit_unavailable',
        commandStatus: 128,
      }),
    }), 'confirmed_unavailable_mismatch');
    assertInvalid(prInput({
      status: 'unknown',
      evidence: evidence({
        evidence: 'commit_unavailable',
        commandStatus: 128,
        confirmedUnavailable: false,
      }),
    }), 'confirmed_unavailable_mismatch');
    assertInvalid(prInput({
      evidence: evidence({ confirmedUnavailable: true }),
    }), 'confirmed_unavailable_mismatch');
  });

  it('exports stable evidence and validation reason codes', () => {
    assert.deepEqual(KNOWN_REACHABILITY_EVIDENCE_REASONS, [
      'merge_commit_in_release_history',
      'fix_commit_in_release_history',
      'predecessor_release_in_target_history',
      'not_reachable_from_release_tag',
      'release_commit_unavailable',
      'release_commit_fetch_failed',
      'merge_commit_oid_unavailable',
      'commit_fetch_failed',
      'commit_unavailable',
      'merge_base_error',
    ]);
    assert.ok(REACHABILITY_EVIDENCE_VALIDATION_REASON_CODES.includes('status_reason_mismatch'));
    assert.ok(REACHABILITY_EVIDENCE_VALIDATION_REASON_CODES.includes('confirmed_unavailable_mismatch'));
    assert.ok(REACHABILITY_EVIDENCE_VALIDATION_REASON_CODES.includes('repository_identity_mismatch'));
  });
});
