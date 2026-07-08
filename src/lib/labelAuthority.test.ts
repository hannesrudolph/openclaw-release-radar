import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  LABEL_AUTHORITY_PERMISSION_MAX_AGE_MS,
  LABEL_AUTHORITY_POLICY_VERSION,
  LABEL_AUTHORITY_PURPOSE,
  approvedMaintainerRosterEntryRowHash,
  canonicalLabelAuthorityEvidenceJson,
  canonicalLabelAuthorityResolutionJson,
  labelAuthorityEvidenceDigest,
  labelAuthorityEvidenceProblems,
  labelAuthorityResolutionProblems,
  partitionLabelAuthority,
  repositoryPermissionObservationRowHash,
  resolveLabelAuthority,
  type ApprovedMaintainerRosterEntry,
  type LabelAuthorityEvidence,
  type RepositoryPermissionObservation,
} from './labelAuthority.ts';

const EVENT_TIME = '2026-07-04T12:00:00.000Z';
const REPOSITORY_NODE_ID = 'R_openclaw';
const ACTOR_NODE_ID = 'U_maintainer';
const RUN_HASH = 'a'.repeat(64);
const ROSTER_RUN_HASH = 'b'.repeat(64);
const KEYRING_DIGEST = 'c'.repeat(64);

function permission(
  overrides: Partial<RepositoryPermissionObservation> = {},
): RepositoryPermissionObservation {
  const base: RepositoryPermissionObservation = {
    kind: 'repository_permission_observation',
    evidenceId: 'permission-1',
    sourceIdentity: 'github-permission-snapshot:permission-1',
    repositoryNodeId: REPOSITORY_NODE_ID,
    repository: 'openclaw/openclaw',
    actorNodeId: ACTOR_NODE_ID,
    actorLogin: 'maintainer',
    actorType: 'User',
    actorAssociation: 'MEMBER',
    permission: 'maintain',
    observedAt: '2026-07-04T11:00:00.000Z',
    runHash: RUN_HASH,
    ...overrides,
  };
  return {
    ...base,
    rowHash: overrides.rowHash ?? repositoryPermissionObservationRowHash(base),
  };
}

function roster(
  overrides: Partial<ApprovedMaintainerRosterEntry> = {},
): ApprovedMaintainerRosterEntry {
  const base: ApprovedMaintainerRosterEntry = {
    kind: 'approved_roster_entry',
    evidenceId: 'roster-1',
    sourceIdentity: 'approved-roster:roster-1',
    approvalId: 'approval-1',
    approvedAt: '2026-07-04T10:00:00.000Z',
    repositoryNodeId: REPOSITORY_NODE_ID,
    repository: 'openclaw/openclaw',
    actorNodeId: ACTOR_NODE_ID,
    actorLogin: 'maintainer',
    actorType: 'User',
    actorAssociation: 'MEMBER',
    role: 'maintain',
    effectiveFrom: '2026-01-01T00:00:00.000Z',
    effectiveUntil: null,
    rosterSequence: 1,
    rosterRunDigest: ROSTER_RUN_HASH,
    signerKeyId: 'key-1',
    keyringDigest: KEYRING_DIGEST,
    signatureVerifiedAt: '2026-07-04T10:00:01.000Z',
    ...overrides,
  };
  return {
    ...base,
    rowHash: overrides.rowHash ?? approvedMaintainerRosterEntryRowHash(base),
  };
}

function evidence(
  overrides: {
    event?: Partial<LabelAuthorityEvidence['event']> & {
      actor?: Partial<LabelAuthorityEvidence['event']['actor']>;
    };
    permissions?: readonly RepositoryPermissionObservation[];
    roster?: readonly ApprovedMaintainerRosterEntry[];
  } = {},
): LabelAuthorityEvidence {
  const event = overrides.event ?? {};
  const { actor: actorOverrides, ...eventOverrides } = event;
  return {
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: 'github-label-event:label-event-1',
      repositoryNodeId: REPOSITORY_NODE_ID,
      repository: 'openclaw/openclaw',
      issueNumber: 42,
      eventId: 'label-event-1',
      action: 'labeled',
      label: 'P0',
      eventTime: EVENT_TIME,
      actor: {
        nodeId: ACTOR_NODE_ID,
        login: 'maintainer',
        type: 'User',
        association: 'MEMBER',
        ...actorOverrides,
      },
      ...eventOverrides,
    },
    permissionObservations: overrides.permissions ?? [],
    approvedRosterEntries: overrides.roster ?? [],
  };
}

describe('node-ID authority decisions', () => {
  it('authorizes only fresh maintain/admin collaborator evidence for the same node IDs', () => {
    for (const repositoryPermission of ['maintain', 'admin'] as const) {
      const input = evidence({
        permissions: [permission({ permission: repositoryPermission })],
      });
      const result = resolveLabelAuthority(input);
      assert.equal(result.purpose, LABEL_AUTHORITY_PURPOSE);
      assert.equal(result.decision, 'authorized_for_scoring');
      assert.equal(result.authority, 'maintainer_human');
      assert.equal(result.reason, 'authorized_by_repository_permission');
      assert.equal(result.repositoryNodeId, REPOSITORY_NODE_ID);
      assert.equal(result.actorNodeId, ACTOR_NODE_ID);
      assert.equal(result.policyVersion, LABEL_AUTHORITY_POLICY_VERSION);
      assert.equal(result.authorizedForScoring, true);
      assert.deepEqual(result.proofIds, ['label-event:label-event-1', 'permission-1']);
    }
  });

  it('rejects the same login when the actor node ID differs', () => {
    const result = resolveLabelAuthority(evidence({
      permissions: [permission({
        actorNodeId: 'U_different',
        actorLogin: 'maintainer',
      })],
    }));
    assert.equal(result.decision, 'denied_for_scoring');
    assert.equal(result.reason, 'permission_actor_identity_mismatch');
    assert.equal(result.authorizedForScoring, false);
  });

  it('accepts renamed logins and repository display names when node IDs are unchanged', () => {
    const result = resolveLabelAuthority(evidence({
      event: {
        repository: 'renamed-owner/renamed-repo',
        actor: {
          login: 'new-maintainer-name',
          association: 'COLLABORATOR',
        },
      },
      permissions: [permission({
        repository: 'legacy-owner/legacy-repo',
        actorLogin: 'old-maintainer-name',
        actorAssociation: 'MEMBER',
      })],
    }));
    assert.equal(result.reason, 'authorized_by_repository_permission');
    assert.equal(result.actorLogin, 'new-maintainer-name');
    assert.equal(result.authorizedForScoring, true);
  });

  it('rejects repository node-ID mismatches even when display names match', () => {
    const result = resolveLabelAuthority(evidence({
      permissions: [permission({ repositoryNodeId: 'R_other' })],
    }));
    assert.equal(result.reason, 'permission_repository_identity_mismatch');
    assert.equal(result.authorizedForScoring, false);
  });
});

describe('permission fail-closed cases', () => {
  it('rejects write and lesser permissions', () => {
    for (const repositoryPermission of ['write', 'triage', 'read', 'none'] as const) {
      const result = resolveLabelAuthority(evidence({
        permissions: [permission({ permission: repositoryPermission })],
      }));
      assert.equal(result.reason, 'insufficient_repository_permission');
      assert.equal(result.authorizedForScoring, false);
    }
  });

  it('rejects stale and postdated observations', () => {
    const staleAt = new Date(
      Date.parse(EVENT_TIME) - LABEL_AUTHORITY_PERMISSION_MAX_AGE_MS - 1,
    ).toISOString();
    const stale = resolveLabelAuthority(evidence({
      permissions: [permission({ observedAt: staleAt })],
    }));
    assert.equal(stale.reason, 'stale_permission_observation');

    const postdated = resolveLabelAuthority(evidence({
      permissions: [permission({ observedAt: '2026-07-04T12:00:00.001Z' })],
    }));
    assert.equal(
      postdated.reason,
      'current_permission_cannot_prove_prior_authority',
    );
  });

  it('rejects conflicting latest permissions and permission/roster conflicts', () => {
    const conflictingPermissions = resolveLabelAuthority(evidence({
      permissions: [
        permission({
          evidenceId: 'permission-maintain',
          sourceIdentity: 'permission:maintain',
          permission: 'maintain',
        }),
        permission({
          evidenceId: 'permission-write',
          sourceIdentity: 'permission:write',
          permission: 'write',
        }),
      ],
    }));
    assert.equal(conflictingPermissions.reason, 'conflicting_authority_evidence');

    const permissionRosterConflict = resolveLabelAuthority(evidence({
      permissions: [permission({ permission: 'write' })],
      roster: [roster()],
    }));
    assert.equal(permissionRosterConflict.reason, 'conflicting_authority_evidence');
    assert.equal(permissionRosterConflict.authorizedForScoring, false);
  });

  it('rejects bot and missing canonical identities', () => {
    const bot = resolveLabelAuthority(evidence({
      event: { actor: { type: 'Bot', login: 'service[bot]' } },
    }));
    assert.equal(bot.reason, 'actor_is_bot');

    const missingActor = resolveLabelAuthority(evidence({
      event: { actor: { nodeId: null } },
    }));
    assert.equal(missingActor.reason, 'actor_node_id_is_missing');

    const missingRepository = resolveLabelAuthority(evidence({
      event: { repositoryNodeId: null },
    }));
    assert.equal(missingRepository.reason, 'repository_node_id_is_missing');
  });

  it('rejects tampered row hashes as malformed authority evidence', () => {
    const result = resolveLabelAuthority(evidence({
      permissions: [permission({ rowHash: '0'.repeat(64) })],
    }));
    assert.equal(result.reason, 'malformed_authority_evidence');
    assert.equal(result.authorizedForScoring, false);
  });
});

describe('signed roster authority', () => {
  it('authorizes an effective verified roster entry for the same node IDs', () => {
    const result = resolveLabelAuthority(evidence({ roster: [roster()] }));
    assert.equal(result.source, 'approved_roster');
    assert.equal(result.reason, 'authorized_by_approved_roster');
    assert.equal(result.authorizedForScoring, true);
  });

  it('accepts retrospective effective intervals only when signature proof is present', () => {
    const signed = resolveLabelAuthority(evidence({
      roster: [roster({
        approvedAt: '2026-08-01T00:00:00Z',
        signatureVerifiedAt: '2026-08-01T00:00:01Z',
        effectiveFrom: '2026-06-01T00:00:00Z',
        effectiveUntil: '2026-07-31T23:59:59Z',
      })],
    }));
    assert.equal(signed.reason, 'authorized_by_approved_roster');

    const unsigned = resolveLabelAuthority(evidence({
      roster: [roster({
        rosterRunDigest: null,
        signerKeyId: null,
        keyringDigest: null,
        signatureVerifiedAt: null,
      })],
    }));
    assert.equal(unsigned.reason, 'malformed_authority_evidence');
    assert.equal(unsigned.authorizedForScoring, false);
  });

  it('rejects roster identity mismatch and inactive intervals', () => {
    const mismatch = resolveLabelAuthority(evidence({
      roster: [roster({ actorNodeId: 'U_other' })],
    }));
    assert.equal(mismatch.reason, 'roster_actor_identity_mismatch');

    const inactive = resolveLabelAuthority(evidence({
      roster: [roster({ effectiveFrom: '2026-07-05T00:00:00Z' })],
    }));
    assert.equal(inactive.reason, 'approved_roster_not_effective_at_event');
  });
});

describe('canonical authority evidence', () => {
  it('sorts proof IDs and evidence independently of input order', () => {
    const first = evidence({
      permissions: [
        permission({
          evidenceId: 'permission-b',
          sourceIdentity: 'permission:b',
          observedAt: '2026-07-04T11:00:00Z',
        }),
        permission({
          evidenceId: 'permission-a',
          sourceIdentity: 'permission:a',
          observedAt: '2026-07-04T10:00:00Z',
        }),
      ],
    });
    const second = evidence({
      event: { eventTime: '2026-07-04T06:00:00-06:00' },
      permissions: [...(first.permissionObservations ?? [])].reverse(),
    });
    assert.equal(
      canonicalLabelAuthorityEvidenceJson(first),
      canonicalLabelAuthorityEvidenceJson(second),
    );
    assert.equal(labelAuthorityEvidenceDigest(first), labelAuthorityEvidenceDigest(second));
    assert.deepEqual(resolveLabelAuthority(first).proofIds, [
      'label-event:label-event-1',
      'permission-a',
      'permission-b',
    ]);
  });

  it('validates canonical resolutions and detects tamper', () => {
    const input = evidence({ permissions: [permission()] });
    const result = resolveLabelAuthority(input);
    assert.deepEqual(labelAuthorityEvidenceProblems(input), []);
    assert.deepEqual(labelAuthorityResolutionProblems(result, input), []);
    assert.equal(canonicalLabelAuthorityResolutionJson(result), JSON.stringify(result));
    assert.match(
      labelAuthorityResolutionProblems({
        ...result,
        evidenceDigest: '0'.repeat(64),
      }, input).join('\n'),
      /does not match canonical evidence resolution/,
    );
    assert.match(
      labelAuthorityResolutionProblems({
        ...result,
        decision: 'denied_for_scoring',
        authorizedForScoring: false,
      }).join('\n'),
      /denied scoring decisions cannot use an authorizing reason/,
    );
    assert.match(
      labelAuthorityResolutionProblems({
        ...result,
        authority: 'unknown',
      }).join('\n'),
      /require maintainer_human authority/,
    );
    assert.match(
      labelAuthorityResolutionProblems({
        ...result,
        source: 'approved_roster',
      }).join('\n'),
      /reason does not match its authority source/,
    );
  });

  it('keeps denied labels for display but excludes them from scoring', () => {
    const authorized = resolveLabelAuthority(evidence({
      event: { label: 'P0', eventId: 'event-p0' },
      permissions: [permission()],
    }));
    const denied = resolveLabelAuthority(evidence({
      event: { label: 'regression', eventId: 'event-regression' },
    }));
    const labels = partitionLabelAuthority([denied, authorized]);
    assert.deepEqual(labels.displayLabels, ['P0', 'regression']);
    assert.deepEqual(labels.authorizedScoringLabels, ['P0']);
  });
});
