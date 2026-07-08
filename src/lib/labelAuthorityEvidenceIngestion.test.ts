import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  APPROVED_ROSTER_KEYRING_PURPOSE,
  APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
  APPROVED_ROSTER_PURPOSE,
  APPROVED_ROSTER_SIGNATURE_ALGORITHM,
  APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
  ApprovedRosterVerificationError,
  approvedMaintainerRosterChainState,
  approvedMaintainerRosterSnapshotProblems,
  buildApprovedMaintainerRosterChainState,
  buildApprovedMaintainerRosterKeyring,
  buildApprovedMaintainerRosterSnapshot,
  buildRepositoryCollaboratorPermissionSnapshot,
  canonicalApprovedMaintainerRosterChainStateJson,
  canonicalApprovedMaintainerRosterKeyringMetadataJson,
  repositoryCollaboratorPermissionSnapshotProblems,
  signApprovedMaintainerRosterManifest,
  type ApprovedMaintainerRosterChainState,
  type ApprovedMaintainerRosterUnsignedManifest,
} from './labelAuthorityEvidenceIngestion.ts';

const REPOSITORY_NODE_ID = 'R_openclaw';
const SECRET = Buffer.alloc(32, 7).toString('base64');
const OTHER_SECRET = Buffer.alloc(32, 9).toString('base64');
const VERIFIED_AT = '2026-07-04T18:00:01.000Z';

function keyring(overrides: Record<string, unknown> = {}) {
  return buildApprovedMaintainerRosterKeyring({
    schemaVersion: APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
    purpose: APPROVED_ROSTER_KEYRING_PURPOSE,
    repositoryNodeId: REPOSITORY_NODE_ID,
    repository: 'openclaw/openclaw',
    keys: [{
      keyId: 'key-1',
      algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
      secret: SECRET,
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2026-12-31T23:59:59Z',
      revokedAt: null,
    }],
    ...overrides,
  });
}

function unsignedRoster(
  overrides: Partial<ApprovedMaintainerRosterUnsignedManifest> = {},
): ApprovedMaintainerRosterUnsignedManifest {
  return {
    schemaVersion: APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
    purpose: APPROVED_ROSTER_PURPOSE,
    repositoryNodeId: REPOSITORY_NODE_ID,
    repository: 'openclaw/openclaw',
    approvalId: 'approval-1',
    approvedAt: '2026-07-04T18:00:00Z',
    sequence: 1,
    priorDigest: null,
    signerKeyId: 'key-1',
    entries: [{
      actorNodeId: 'U_alice',
      login: 'Alice',
      actorType: 'User',
      association: 'MEMBER',
      role: 'maintain',
      effectiveFrom: '2026-01-01T00:00:00Z',
      effectiveUntil: null,
    }],
    ...overrides,
  };
}

function signedSnapshot(
  manifest: ApprovedMaintainerRosterUnsignedManifest = unsignedRoster(),
  previousState: ApprovedMaintainerRosterChainState | null = null,
  verificationKeyring = keyring(),
) {
  const signed = signApprovedMaintainerRosterManifest(manifest, verificationKeyring);
  return buildApprovedMaintainerRosterSnapshot(signed, {
    keyring: verificationKeyring,
    expectedRepositoryNodeId: REPOSITORY_NODE_ID,
    previousState,
    verifiedAt: VERIFIED_AT,
  });
}

function errorCode(callback: () => unknown): string {
  try {
    callback();
  } catch (error) {
    assert.ok(error instanceof ApprovedRosterVerificationError);
    return error.code;
  }
  assert.fail('expected verification failure');
}

describe('collaborator authority evidence ingestion', () => {
  it('uses repository and actor node IDs for canonical row/run hashes', () => {
    const first = buildRepositoryCollaboratorPermissionSnapshot({
      repositoryNodeId: REPOSITORY_NODE_ID,
      repository: 'OpenClaw/OpenClaw',
      observedAt: '2026-07-04T12:00:00-06:00',
      exhaustive: true,
      complete: true,
      totalCount: 2,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      rows: [
        {
          nodeId: 'U_zed',
          login: 'same-login',
          actorType: 'User',
          association: 'COLLABORATOR',
          permission: 'read',
        },
        {
          nodeId: 'U_alice',
          login: 'same-login',
          actorType: 'User',
          association: 'MEMBER',
          permission: 'maintain',
        },
      ],
    });
    const second = buildRepositoryCollaboratorPermissionSnapshot({
      repositoryNodeId: REPOSITORY_NODE_ID,
      repository: 'openclaw/openclaw',
      observedAt: '2026-07-04T18:00:00Z',
      exhaustive: true,
      complete: true,
      totalCount: 2,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      rows: [...first.rows].reverse(),
    });

    assert.deepEqual(first.rows.map((row) => row.nodeId), ['U_alice', 'U_zed']);
    assert.equal(first.repositoryNodeId, REPOSITORY_NODE_ID);
    assert.match(first.runHash ?? '', /^[0-9a-f]{64}$/);
    assert.equal(first.runHash, second.runHash);
    assert.equal(first.contentDigest, second.contentDigest);
    assert.deepEqual(repositoryCollaboratorPermissionSnapshotProblems(first), []);
    assert.equal(new Set(first.rows.map((row) => row.rowHash)).size, 2);
  });

  it('rejects missing/duplicate node IDs, bots, incomplete runs, and tamper', () => {
    const base = {
      repositoryNodeId: REPOSITORY_NODE_ID,
      repository: 'openclaw/openclaw',
      observedAt: '2026-07-04T18:00:00Z',
      exhaustive: true,
      complete: true,
      totalCount: 1,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
    } as const;
    assert.throws(
      () => buildRepositoryCollaboratorPermissionSnapshot({
        ...base,
        rows: [{ login: 'alice', actorType: 'User', permission: 'maintain' }],
      }),
      /actor node ID is missing or non-canonical/,
    );
    assert.throws(
      () => buildRepositoryCollaboratorPermissionSnapshot({
        ...base,
        totalCount: 2,
        rows: [
          {
            nodeId: 'U_same',
            login: 'alice',
            actorType: 'User',
            permission: 'maintain',
          },
          {
            nodeId: 'U_same',
            login: 'renamed-alice',
            actorType: 'User',
            permission: 'admin',
          },
        ],
      }),
      /duplicate actor node ID/,
    );
    assert.throws(
      () => buildRepositoryCollaboratorPermissionSnapshot({
        ...base,
        rows: [{
          nodeId: 'B_service',
          login: 'service[bot]',
          actorType: 'Bot',
          permission: 'maintain',
        }],
      }),
      /actorType must be User/,
    );
    assert.throws(
      () => buildRepositoryCollaboratorPermissionSnapshot({
        ...base,
        exhaustive: false,
        rows: [{
          nodeId: 'U_alice',
          login: 'alice',
          actorType: 'User',
          permission: 'maintain',
        }],
      }),
      /must be exhaustive and complete/,
    );

    const snapshot = buildRepositoryCollaboratorPermissionSnapshot({
      ...base,
      rows: [{
        nodeId: 'U_alice',
        login: 'alice',
        actorType: 'User',
        permission: 'maintain',
      }],
    });
    assert.match(
      repositoryCollaboratorPermissionSnapshotProblems({
        ...snapshot,
        contentDigest: '0'.repeat(64),
      })[0],
      /immutable metadata/,
    );
  });
});

describe('signed roster verification', () => {
  it('verifies HMAC-SHA256 without exposing key material in output', () => {
    const verificationKeyring = keyring();
    const snapshot = signedSnapshot(unsignedRoster(), null, verificationKeyring);
    assert.equal(snapshot.repositoryNodeId, REPOSITORY_NODE_ID);
    assert.equal(snapshot.sequence, 1);
    assert.equal(snapshot.entries[0].actorNodeId, 'U_alice');
    assert.equal(snapshot.entries[0].actorLogin, 'alice');
    assert.equal(snapshot.entries[0].rosterRunDigest, snapshot.runHash);
    assert.equal(snapshot.signatureVerifiedAt, VERIFIED_AT);
    assert.deepEqual(
      approvedMaintainerRosterSnapshotProblems(snapshot, {
        keyring: verificationKeyring,
        verifiedAt: VERIFIED_AT,
      }),
      [],
    );

    const persistedKeyring = canonicalApprovedMaintainerRosterKeyringMetadataJson(
      verificationKeyring,
    );
    assert.doesNotMatch(persistedKeyring, new RegExp(SECRET));
    assert.doesNotMatch(JSON.stringify(snapshot), new RegExp(SECRET));
  });

  it('is deterministic across entry order, login case, and timestamp spelling', () => {
    const verificationKeyring = keyring();
    const entries = [
      {
        actorNodeId: 'U_bob',
        login: 'Bob',
        actorType: 'User' as const,
        association: null,
        role: 'admin' as const,
        effectiveFrom: '2026-01-01T00:00:00Z',
        effectiveUntil: null,
      },
      {
        actorNodeId: 'U_alice',
        login: 'Alice',
        actorType: 'User' as const,
        association: 'MEMBER',
        role: 'maintain' as const,
        effectiveFrom: '2026-01-01T00:00:00Z',
        effectiveUntil: null,
      },
    ];
    const firstSigned = signApprovedMaintainerRosterManifest(
      unsignedRoster({ entries }),
      verificationKeyring,
    );
    const secondSigned = signApprovedMaintainerRosterManifest(
      unsignedRoster({
        approvedAt: '2026-07-04T12:00:00-06:00',
        entries: [...entries].reverse().map((entry) => ({
          ...entry,
          login: entry.login.toLowerCase(),
        })),
      }),
      verificationKeyring,
    );
    const first = buildApprovedMaintainerRosterSnapshot(firstSigned, {
      keyring: verificationKeyring,
      verifiedAt: VERIFIED_AT,
    });
    const second = buildApprovedMaintainerRosterSnapshot(secondSigned, {
      keyring: verificationKeyring,
      verifiedAt: VERIFIED_AT,
    });
    assert.equal(first.runHash, second.runHash);
    assert.equal(first.contentDigest, second.contentDigest);
    assert.equal(first.signature, second.signature);
  });

  it('rejects bad, expired, unknown, revoked keys and invalid signatures', () => {
    assert.equal(
      errorCode(() => keyring({
        keys: [{
          keyId: 'key-1',
          algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
          secret: Buffer.alloc(8, 1).toString('base64'),
          validFrom: '2026-01-01T00:00:00Z',
          validUntil: null,
          revokedAt: null,
        }],
      })),
      'invalid_keyring',
    );

    const expiredKeyring = keyring({
      keys: [{
        keyId: 'key-1',
        algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
        secret: SECRET,
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: '2026-07-01T00:00:00Z',
        revokedAt: null,
      }],
    });
    const expiredSigned = signApprovedMaintainerRosterManifest(
      unsignedRoster(),
      expiredKeyring,
    );
    assert.equal(
      errorCode(() => buildApprovedMaintainerRosterSnapshot(expiredSigned, {
        keyring: expiredKeyring,
        verifiedAt: VERIFIED_AT,
      })),
      'key_expired',
    );

    const revokedKeyring = keyring({
      keys: [{
        keyId: 'key-1',
        algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
        secret: SECRET,
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: null,
        revokedAt: '2026-07-04T17:00:00Z',
      }],
    });
    const revokedSigned = signApprovedMaintainerRosterManifest(
      unsignedRoster(),
      revokedKeyring,
    );
    assert.equal(
      errorCode(() => buildApprovedMaintainerRosterSnapshot(revokedSigned, {
        keyring: revokedKeyring,
        verifiedAt: VERIFIED_AT,
      })),
      'key_revoked',
    );

    const verificationKeyring = keyring();
    const signed = signApprovedMaintainerRosterManifest(
      unsignedRoster(),
      verificationKeyring,
    );
    assert.equal(
      errorCode(() => buildApprovedMaintainerRosterSnapshot({
        ...signed,
        signerKeyId: 'missing-key',
      }, {
        keyring: verificationKeyring,
        verifiedAt: VERIFIED_AT,
      })),
      'unknown_key',
    );
    assert.equal(
      errorCode(() => buildApprovedMaintainerRosterSnapshot({
        ...signed,
        signature: '0'.repeat(64),
      }, {
        keyring: verificationKeyring,
        verifiedAt: VERIFIED_AT,
      })),
      'invalid_signature',
    );
  });

  it('rejects rollback, replay, fork, sequence gaps, and prior-digest mismatch', () => {
    const verificationKeyring = keyring();
    const first = signedSnapshot(unsignedRoster(), null, verificationKeyring);
    const firstState = approvedMaintainerRosterChainState(first);
    const secondManifest = unsignedRoster({
      approvalId: 'approval-2',
      approvedAt: '2026-07-04T18:00:00.500Z',
      sequence: 2,
      priorDigest: first.runHash ?? null,
    });
    const second = signedSnapshot(secondManifest, firstState, verificationKeyring);
    const secondState = approvedMaintainerRosterChainState(second);
    assert.deepEqual(
      approvedMaintainerRosterSnapshotProblems(second, {
        previousState: firstState,
      }),
      [],
    );
    const secondSigned = signApprovedMaintainerRosterManifest(
      secondManifest,
      verificationKeyring,
    );

    assert.equal(
      errorCode(() => buildApprovedMaintainerRosterSnapshot(secondSigned, {
        keyring: verificationKeyring,
        previousState: secondState,
        verifiedAt: VERIFIED_AT,
      })),
      'sequence_replay',
    );
    assert.equal(
      errorCode(() => {
        const rollback = signApprovedMaintainerRosterManifest(
          unsignedRoster({ approvalId: 'rollback' }),
          verificationKeyring,
        );
        buildApprovedMaintainerRosterSnapshot(rollback, {
          keyring: verificationKeyring,
          previousState: secondState,
          verifiedAt: VERIFIED_AT,
        });
      }),
      'sequence_rollback',
    );
    assert.equal(
      errorCode(() => {
        const fork = signApprovedMaintainerRosterManifest({
          ...secondManifest,
          approvalId: 'forked-approval-2',
        }, verificationKeyring);
        buildApprovedMaintainerRosterSnapshot(fork, {
          keyring: verificationKeyring,
          previousState: secondState,
          verifiedAt: VERIFIED_AT,
        });
      }),
      'sequence_fork',
    );
    assert.equal(
      errorCode(() => {
        const gap = signApprovedMaintainerRosterManifest(unsignedRoster({
          approvalId: 'approval-4',
          sequence: 4,
          priorDigest: second.runHash ?? null,
        }), verificationKeyring);
        buildApprovedMaintainerRosterSnapshot(gap, {
          keyring: verificationKeyring,
          previousState: secondState,
          verifiedAt: VERIFIED_AT,
        });
      }),
      'sequence_gap',
    );
    assert.equal(
      errorCode(() => {
        const badPrior = signApprovedMaintainerRosterManifest(unsignedRoster({
          approvalId: 'approval-3',
          sequence: 3,
          priorDigest: '0'.repeat(64),
        }), verificationKeyring);
        buildApprovedMaintainerRosterSnapshot(badPrior, {
          keyring: verificationKeyring,
          previousState: secondState,
          verifiedAt: VERIFIED_AT,
        });
      }),
      'prior_digest_mismatch',
    );
  });

  it('canonicalizes and validates external chain checkpoints', () => {
    const state = buildApprovedMaintainerRosterChainState({
      schemaVersion: 1,
      purpose: APPROVED_ROSTER_PURPOSE,
      repositoryNodeId: REPOSITORY_NODE_ID,
      sequence: 3,
      runDigest: 'a'.repeat(64),
    });
    assert.equal(
      canonicalApprovedMaintainerRosterChainStateJson(state),
      `{"purpose":"${APPROVED_ROSTER_PURPOSE}",` +
        `"repositoryNodeId":"${REPOSITORY_NODE_ID}",` +
        `"runDigest":"${'a'.repeat(64)}",` +
        `"schemaVersion":1,"sequence":3}`,
    );
    assert.throws(
      () => buildApprovedMaintainerRosterChainState({
        ...state,
        sequence: 0,
      }),
      /sequence must be a positive integer/,
    );
    assert.throws(
      () => buildApprovedMaintainerRosterChainState({
        ...state,
        extra: true,
      }),
      /chain state keys are invalid; unknown: extra/,
    );
  });

  it('rejects repository mismatch and detects snapshot tamper', () => {
    const verificationKeyring = keyring();
    const signed = signApprovedMaintainerRosterManifest(
      unsignedRoster(),
      verificationKeyring,
    );
    assert.equal(
      errorCode(() => buildApprovedMaintainerRosterSnapshot(signed, {
        keyring: verificationKeyring,
        expectedRepositoryNodeId: 'R_other',
        verifiedAt: VERIFIED_AT,
      })),
      'repository_mismatch',
    );

    const otherKeyring = keyring({
      repositoryNodeId: 'R_other',
      keys: [{
        keyId: 'key-1',
        algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
        secret: OTHER_SECRET,
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: null,
        revokedAt: null,
      }],
    });
    assert.equal(
      errorCode(() => buildApprovedMaintainerRosterSnapshot(signed, {
        keyring: otherKeyring,
        verifiedAt: VERIFIED_AT,
      })),
      'repository_mismatch',
    );

    const snapshot = buildApprovedMaintainerRosterSnapshot(signed, {
      keyring: verificationKeyring,
      verifiedAt: VERIFIED_AT,
    });
    assert.match(
      approvedMaintainerRosterSnapshotProblems({
        ...snapshot,
        entries: [{
          ...snapshot.entries[0],
          role: 'admin',
        }],
      })[0],
      /immutable metadata/,
    );
    const forgedRunHash = 'd'.repeat(64);
    assert.match(
      approvedMaintainerRosterSnapshotProblems({
        ...snapshot,
        snapshotId: `approved-roster:v2:${forgedRunHash}`,
        runHash: forgedRunHash,
        sourceIdentity: `operator-config:approved-roster:v2:${forgedRunHash}`,
        entries: snapshot.entries.map((entry) => ({
          ...entry,
          rosterRunDigest: forgedRunHash,
        })),
      })[0],
      /immutable metadata/,
    );

    const alternateVerifiedAt = '2026-07-04T12:00:01-06:00';
    assert.match(
      approvedMaintainerRosterSnapshotProblems({
        ...snapshot,
        signatureVerifiedAt: alternateVerifiedAt,
        entries: snapshot.entries.map((entry) => ({
          ...entry,
          signatureVerifiedAt: alternateVerifiedAt,
        })),
      })[0],
      /timestamps must be canonical UTC/,
    );

    assert.match(
      approvedMaintainerRosterSnapshotProblems({
        ...snapshot,
        repository: 'OpenClaw/OpenClaw',
        entries: snapshot.entries.map((entry) => ({
          ...entry,
          repository: 'OpenClaw/OpenClaw',
        })),
      })[0],
      /repository must be canonical owner\/repo/,
    );

    assert.match(
      approvedMaintainerRosterSnapshotProblems({
        ...snapshot,
        unexpected: true,
      } as any)[0],
      /snapshot keys are invalid; unknown: unexpected/,
    );
  });
});
