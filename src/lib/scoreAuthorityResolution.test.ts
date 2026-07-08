import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  repositoryPermissionObservationRowHash,
  type LabelAuthorityEvidence,
  type RepositoryPermissionObservation,
} from './labelAuthority.ts';
import {
  SCORE_AUTHORITY_PURPOSE,
  buildReleaseScoreAuditHistoryV2Seal,
  buildScoreClosureClaimAuthorityResolution,
  buildScoreCommentAuthorityResolution,
  buildScoreAuthorityReference,
  buildScoreAuthorityResolution,
  buildScoreAuthorityResolutionRun,
  canonicalScoreAuthorityReferenceJson,
  canonicalScoreAuthoritySubjectResolutionJson,
  canonicalReleaseScoreAuditHistoryV2SealJson,
  canonicalScoreAuthorityResolutionRunJson,
  releaseScoreAuditHistoryV2SealProblems,
  scoreAuthorityReferenceDigest,
  scoreAuthorityReferenceProblems,
  scoreClosureClaimAuthorityResolutionProblems,
  scoreCommentAuthorityResolutionProblems,
  scoreAuthorityResolutionProblems,
  scoreAuthorityResolutionRunProblems,
  type ScoreClosureClaimAuthorityEvidence,
  type ScoreCommentAuthorityEvidence,
  type ScoreAuthorityResolution,
  type ScoreAuthorityResolutionSubject,
} from './scoreAuthorityResolution.ts';
import {
  extractClosureClaimCandidates,
  type ClosureClaimCandidate,
  type ClosureClaimKind,
} from './closureClaimCandidates.ts';

const RUN_HASH = 'a'.repeat(64);
const SOURCE_IDENTITY_DIGEST = 'b'.repeat(64);

function permission(
  overrides: Partial<RepositoryPermissionObservation> = {},
): RepositoryPermissionObservation {
  const base: RepositoryPermissionObservation = {
    kind: 'repository_permission_observation',
    evidenceId: 'proof-b',
    sourceIdentity: 'permission:proof-b',
    repositoryNodeId: 'R_repo',
    repository: 'owner/repo',
    actorNodeId: 'U_actor',
    actorLogin: 'renamed-actor',
    actorType: 'User',
    actorAssociation: 'MEMBER',
    permission: 'maintain',
    observedAt: '2026-07-04T11:00:00Z',
    runHash: RUN_HASH,
    ...overrides,
  };
  return {
    ...base,
    rowHash: overrides.rowHash ?? repositoryPermissionObservationRowHash(base),
  };
}

function evidence(
  overrides: Partial<LabelAuthorityEvidence> = {},
): LabelAuthorityEvidence {
  return {
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: 'event:1',
      repositoryNodeId: 'R_repo',
      repository: 'owner/repo',
      issueNumber: 1,
      eventId: 'event-1',
      action: 'labeled',
      label: 'P0',
      eventTime: '2026-07-04T12:00:00Z',
      actor: {
        nodeId: 'U_actor',
        login: 'actor',
        type: 'User',
        association: 'MEMBER',
      },
    },
    permissionObservations: [permission()],
    approvedRosterEntries: [],
    ...overrides,
  };
}

function subject(
  resolution: ScoreAuthorityResolution,
  overrides: Partial<ScoreAuthorityResolutionSubject> = {},
): ScoreAuthorityResolutionSubject {
  return {
    releaseTag: 'v1.2.3',
    issueNumber: 1,
    subjectKind: 'label_event',
    subjectIdentity: resolution.eventId,
    candidateId: null,
    resolution,
    ...overrides,
  };
}

function commentEvidence(
  overrides: Partial<ScoreCommentAuthorityEvidence> = {},
): ScoreCommentAuthorityEvidence {
  return {
    issueNumber: 1,
    issueNodeId: 'I_issue',
    issueAuthorNodeId: 'U_reporter',
    issueAuthorType: 'User',
    commentNodeId: 'IC_comment',
    commentId: 101,
    commentUrl: 'https://github.com/owner/repo/issues/1#issuecomment-101',
    actorNodeId: 'U_independent',
    actorType: 'User',
    commentCreatedAt: '2026-07-04T12:00:00Z',
    commentUpdatedAt: '2026-07-04T12:05:00Z',
    commentBodyDigest: 'c'.repeat(64),
    claimSnippet: 'Can confirm, reconnect drops the queued message.',
    ...overrides,
  };
}

function closureClaimCandidate(
  kind: ClosureClaimKind,
  input: {
    body?: string;
    actorNodeId?: string;
    actorLogin?: string;
    actorType?: string;
    closureEvent?: boolean;
  } = {},
): ClosureClaimCandidate {
  const actorNodeId = input.actorNodeId ?? 'U_actor';
  const actorLogin = input.actorLogin ?? 'actor';
  const actorType = input.actorType ?? 'User';
  const result = input.closureEvent
    ? extractClosureClaimCandidates({
        repository: {
          nodeId: 'R_repo',
          nameWithOwner: 'owner/repo',
        },
        issue: {
          nodeId: 'I_issue',
          number: 1,
          author: {
            nodeId: 'U_reporter',
            login: 'reporter',
            type: 'User',
          },
        },
        closureEvents: [{
          nodeId: 'CE_final',
          actor: {
            nodeId: actorNodeId,
            login: actorLogin,
            type: actorType,
          },
          occurredAt: '2026-07-04T12:00:00Z',
          stateReason: 'COMPLETED',
          closer: {
            nodeId: 'PR_42',
            type: 'PullRequest',
            number: 42,
            repositoryNameWithOwner: 'owner/repo',
          },
        }],
      })
    : extractClosureClaimCandidates({
        repository: {
          nodeId: 'R_repo',
          nameWithOwner: 'owner/repo',
        },
        issue: {
          nodeId: 'I_issue',
          number: 1,
          author: {
            nodeId: 'U_reporter',
            login: 'reporter',
            type: 'User',
          },
        },
        comments: [{
          nodeId: 'IC_claim',
          databaseId: 101,
          url: 'https://github.com/owner/repo/issues/1#issuecomment-101',
          actor: {
            nodeId: actorNodeId,
            login: actorLogin,
            type: actorType,
          },
          createdAt: '2026-07-04T12:00:00Z',
          updatedAt: '2026-07-04T12:00:00Z',
          body: input.body ?? 'Fixed by PR #42.',
        }],
      });
  const candidate = result.candidates.find((item) => item.claimKind === kind);
  assert.ok(candidate, `expected ${kind} candidate`);
  return candidate;
}

function closureEvidence(
  candidate: ClosureClaimCandidate,
  overrides: Partial<ScoreClosureClaimAuthorityEvidence> = {},
): ScoreClosureClaimAuthorityEvidence {
  return {
    candidate,
    extractionReceiptId: 'd'.repeat(64),
    extractionReceiptContentHash: 'e'.repeat(64),
    issueAuthorNodeId: 'U_reporter',
    issueAuthorType: 'User',
    permissionObservations: candidate.source.actor.nodeId === 'U_actor'
      ? [permission()]
      : [],
    approvedRosterEntries: [],
    finalClosure: candidate.source.kind === 'closure_event'
      ? {
          sourceIdentity: 'issue-state-snapshot:final',
          issueNodeId: 'I_issue',
          eventId: 'CE_final',
          occurredAt: '2026-07-04T12:00:00Z',
          actorNodeId: 'U_actor',
          actorType: 'User',
        }
      : null,
    ...overrides,
  };
}

describe('score authority resolution rows', () => {
  it('records explicit purpose, decision, reason, and sorted proof IDs', () => {
    const input = evidence({
      permissionObservations: [
        permission({
          evidenceId: 'proof-z',
          sourceIdentity: 'permission:proof-z',
          observedAt: '2026-07-04T10:00:00Z',
        }),
        permission({
          evidenceId: 'proof-a',
          sourceIdentity: 'permission:proof-a',
          observedAt: '2026-07-04T11:00:00Z',
        }),
      ],
    });
    const row = buildScoreAuthorityResolution(input);
    assert.equal(row.purpose, SCORE_AUTHORITY_PURPOSE);
    assert.equal(row.decision, 'authorized_for_scoring');
    assert.equal(row.reason, 'authorized_by_repository_permission');
    assert.deepEqual(row.proofIds, [
      'label-event:event-1',
      'proof-a',
      'proof-z',
    ]);
    assert.match(row.resolutionHash, /^[0-9a-f]{64}$/);
    assert.deepEqual(scoreAuthorityResolutionProblems(row, input), []);
  });

  it('produces a non-scoring row for missing canonical identity', () => {
    const input = evidence({
      event: {
        ...evidence().event,
        actor: {
          ...evidence().event.actor,
          nodeId: null,
        },
      },
      permissionObservations: [],
    });
    const row = buildScoreAuthorityResolution(input);
    assert.equal(row.decision, 'denied_for_scoring');
    assert.equal(row.reason, 'actor_node_id_is_missing');
    assert.equal(row.actorNodeId, null);
  });

  it('detects deterministic row tamper', () => {
    const row = buildScoreAuthorityResolution(evidence());
    assert.match(
      scoreAuthorityResolutionProblems({
        ...row,
        label: 'tampered-label',
      }).join('\n'),
      /hash does not match canonical resolution/,
    );
    assert.match(
      scoreAuthorityResolutionProblems({
        ...row,
        decision: 'denied_for_scoring',
        reason: 'authorized_by_repository_permission',
        resolutionHash: '0'.repeat(64),
      }).join('\n'),
      /denied score authority decisions cannot use an authorizing reason/,
    );
  });
});

describe('score authority references', () => {
  it('binds and freezes the exact authorized subject resolution', () => {
    const resolution = buildScoreAuthorityResolution(evidence());
    const reference = buildScoreAuthorityReference(
      'label_event',
      resolution.eventId,
      resolution,
    );
    assert.equal(Object.isFrozen(reference), true);
    assert.deepEqual(scoreAuthorityReferenceProblems(reference), []);
    assert.equal(
      canonicalScoreAuthorityReferenceJson(reference),
      JSON.stringify({
        authorizedForScoring: true,
        evidenceDigest: reference.evidenceDigest,
        resolutionHash: reference.resolutionHash,
        subjectIdentity: resolution.eventId,
        subjectKind: 'label_event',
      }),
    );
    assert.match(scoreAuthorityReferenceDigest(reference), /^[0-9a-f]{64}$/);
  });

  it('rejects denied, mismatched, and tampered references', () => {
    const authorized = buildScoreAuthorityResolution(evidence());
    const denied = buildScoreAuthorityResolution(evidence({
      permissionObservations: [],
    }));
    assert.throws(
      () => buildScoreAuthorityReference(
        'label_event',
        denied.eventId,
        denied,
      ),
      /not authorized for scoring/,
    );
    assert.throws(
      () => buildScoreAuthorityReference(
        'label_event',
        'different-event',
        authorized,
      ),
      /does not match resolution subject/,
    );
    const reference = buildScoreAuthorityReference(
      'label_event',
      authorized.eventId,
      authorized,
    );
    const tampered = {
      ...reference,
      resolutionHash: 'not-a-sha256',
    };
    assert.notDeepEqual(scoreAuthorityReferenceProblems(tampered), []);
    assert.throws(
      () => scoreAuthorityReferenceDigest(tampered),
      /Cannot digest invalid score authority reference/,
    );
  });
});

describe('score comment authority resolution rows', () => {
  it('binds canonical comment and actor node identities without trusting login', () => {
    const first = buildScoreCommentAuthorityResolution(commentEvidence());
    const renamed = buildScoreCommentAuthorityResolution(commentEvidence());
    assert.equal(first.authority, 'independent_human');
    assert.equal(first.reason, 'independent_human_reproduction');
    assert.equal(
      canonicalScoreAuthoritySubjectResolutionJson(first),
      canonicalScoreAuthoritySubjectResolutionJson(renamed),
    );
    assert.deepEqual(
      scoreCommentAuthorityResolutionProblems(first, commentEvidence()),
      [],
    );
  });

  it('rejects bots, reporter self-confirmation, and identity tamper', () => {
    assert.throws(
      () => buildScoreCommentAuthorityResolution(commentEvidence({
        actorType: 'Bot' as any,
      })),
      /actorType must be User/,
    );
    assert.throws(
      () => buildScoreCommentAuthorityResolution(commentEvidence({
        actorNodeId: 'U_reporter',
      })),
      /must be independent/,
    );
    const resolution = buildScoreCommentAuthorityResolution(commentEvidence());
    assert.match(
      scoreCommentAuthorityResolutionProblems({
        ...resolution,
        commentNodeId: 'IC_tampered',
      }).join('\n'),
      /hash does not match canonical resolution|evidenceDigest does not match evidence/,
    );
  });

  it('persists comment subjects in the same immutable authority run', () => {
    const resolution = buildScoreCommentAuthorityResolution(commentEvidence());
    const run = buildScoreAuthorityResolutionRun({
      authorityRunId: 'authority-run-comment',
      sourceIdentitySchemaVersion: 2,
      sourceIdentityDigest: SOURCE_IDENTITY_DIGEST,
      previousContentHash: null,
      recordedAt: '2026-07-04T18:00:00Z',
      rows: [{
        releaseTag: null,
        issueNumber: 1,
        subjectKind: 'comment',
        subjectIdentity: resolution.commentNodeId,
        candidateId: null,
        resolution,
      }],
    });
    assert.equal(run.rows[0].subjectKind, 'comment');
    assert.equal(run.rows[0].authority, 'independent_human');
    assert.deepEqual(scoreAuthorityResolutionRunProblems(run), []);
  });
});

describe('score authority resolution runs', () => {
  it('sorts subjects into deterministic persisted rows before hashing', () => {
    const first = buildScoreAuthorityResolution(evidence());
    const second = buildScoreAuthorityResolution(evidence({
      event: {
        ...evidence().event,
        eventId: 'event-2',
        label: 'regression',
      },
      permissionObservations: [permission({
        evidenceId: 'proof-c',
        sourceIdentity: 'permission:proof-c',
      })],
    }));
    const input = {
      authorityRunId: 'authority-run-1',
      sourceIdentitySchemaVersion: 2,
      sourceIdentityDigest: SOURCE_IDENTITY_DIGEST,
      previousContentHash: null,
    } as const;
    const forward = buildScoreAuthorityResolutionRun({
      ...input,
      recordedAt: '2026-07-04T18:00:00Z',
      rows: [
        subject(first),
        subject(second, { issueNumber: 2 }),
      ],
    });
    const reverse = buildScoreAuthorityResolutionRun({
      ...input,
      recordedAt: '2026-07-04T12:00:00-06:00',
      rows: [
        subject(second, { issueNumber: 2 }),
        subject(first),
      ],
    });

    assert.equal(forward.contentHash, reverse.contentHash);
    assert.equal(
      canonicalScoreAuthorityResolutionRunJson(forward),
      canonicalScoreAuthorityResolutionRunJson(reverse),
    );
    assert.deepEqual(forward.rows.map((row) => [
      row.rowOrdinal,
      row.subjectIdentity,
    ]), [
      [0, 'event-1'],
      [1, 'event-2'],
    ]);
    assert.ok(forward.rows.every((row) => /^[0-9a-f]{64}$/.test(row.contentHash)));
    assert.ok(forward.rows.every((row) =>
      row.resolutionJson === JSON.stringify(JSON.parse(row.resolutionJson))));
    assert.deepEqual(scoreAuthorityResolutionRunProblems(forward), []);
  });

  it('binds canonical row and run hashes to all persisted contract fields', () => {
    const resolution = buildScoreAuthorityResolution(evidence());
    const run = buildScoreAuthorityResolutionRun({
      authorityRunId: 'authority-run-1',
      sourceIdentitySchemaVersion: 2,
      sourceIdentityDigest: SOURCE_IDENTITY_DIGEST,
      previousContentHash: 'f'.repeat(64),
      recordedAt: '2026-07-04T18:00:00Z',
      rows: [subject(resolution)],
    });
    for (const tampered of [
      { ...run, sourceIdentitySchemaVersion: 3 },
      { ...run, sourceIdentityDigest: 'e'.repeat(64) },
      { ...run, previousContentHash: 'd'.repeat(64) },
      {
        ...run,
        rows: [{
          ...run.rows[0],
          authority: 'unknown' as const,
        }],
      },
    ]) {
      assert.notDeepEqual(scoreAuthorityResolutionRunProblems(tampered), []);
    }
  });

  it('rejects duplicate subjects, unsupported kinds, and label-event identity drift', () => {
    const resolution = buildScoreAuthorityResolution(evidence());
    const input = {
      authorityRunId: 'authority-run-1',
      sourceIdentitySchemaVersion: 2,
      sourceIdentityDigest: SOURCE_IDENTITY_DIGEST,
      previousContentHash: null,
      recordedAt: '2026-07-04T18:00:00Z',
    } as const;
    assert.throws(
      () => buildScoreAuthorityResolutionRun({
        ...input,
        rows: [
          subject(resolution),
          subject(resolution, { issueNumber: 2 }),
        ],
      }),
      /duplicate subject/,
    );
    assert.throws(
      () => buildScoreAuthorityResolutionRun({
        ...input,
        rows: [subject(resolution, { subjectIdentity: 'different-event' })],
      }),
      /must equal the event ID/,
    );
    assert.throws(
      () => buildScoreAuthorityResolutionRun({
        ...input,
        rows: [{
          ...subject(resolution),
          subjectKind: 'release' as any,
          subjectIdentity: 'claim-1',
        } as unknown as ScoreAuthorityResolutionSubject],
      }),
      /subject kind is invalid/,
    );
  });
});

describe('score closure claim authority resolution', () => {
  it('authorizes maintainer claims only from node-bound permission or roster evidence', () => {
    const candidate = closureClaimCandidate('fix_proof', {
      actorLogin: 'actor-before-rename',
    });
    const authorized = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(candidate, {
        permissionObservations: [permission({
          actorLogin: 'actor-after-rename',
          actorAssociation: 'NONE',
        })],
      }),
    );
    assert.equal(authorized.authority, 'maintainer_human');
    assert.equal(authorized.reason, 'authorized_by_repository_permission');
    assert.equal(authorized.authorizedForScoring, true);
    assert.deepEqual(
      scoreClosureClaimAuthorityResolutionProblems(
        authorized,
        closureEvidence(candidate, {
          permissionObservations: [permission({
            actorLogin: 'actor-after-rename',
            actorAssociation: 'NONE',
          })],
        }),
      ),
      [],
    );

    const denied = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(candidate, {
        permissionObservations: [permission({
          actorAssociation: 'OWNER',
          permission: 'read',
        })],
      }),
    );
    assert.equal(denied.authorizedForScoring, false);
    assert.equal(denied.reason, 'insufficient_repository_permission');
  });

  it('authorizes immutable human field confirmation without maintainer status', () => {
    const human = closureClaimCandidate('field_confirmation', {
      body: 'I can reproduce the same failure in production.',
      actorNodeId: 'U_customer',
      actorLogin: 'customer',
    });
    const authorized = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(human),
    );
    assert.equal(authorized.authority, 'independent_human');
    assert.equal(authorized.reason, 'authorized_human_field_confirmation');
    assert.equal(authorized.authorizedForScoring, true);

    const bot = closureClaimCandidate('field_confirmation', {
      body: 'I can reproduce the same failure in production.',
      actorNodeId: 'B_ci',
      actorLogin: 'ci[bot]',
      actorType: 'Bot',
    });
    const denied = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(bot),
    );
    assert.equal(denied.authority, 'automation');
    assert.equal(denied.reason, 'actor_is_bot');
    assert.equal(denied.authorizedForScoring, false);
  });

  it('requires exact persisted issue-author node identity for reporter actions', () => {
    const candidate = closureClaimCandidate('reporter_action', {
      body: 'I refiled this as #2 with a smaller reproduction.',
      actorNodeId: 'U_reporter',
      actorLogin: 'reporter-renamed',
    });
    const authorized = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(candidate),
    );
    assert.equal(authorized.reason, 'authorized_reporter_action');
    assert.equal(authorized.authority, 'independent_human');
    assert.equal(authorized.authorizedForScoring, true);

    const denied = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(candidate, {
        issueAuthorNodeId: 'U_different_reporter',
      }),
    );
    assert.equal(denied.reason, 'reporter_identity_mismatch');
    assert.equal(denied.authorizedForScoring, false);
  });

  it('requires closure-event claims to match the authoritative final closure actor and event', () => {
    const candidate = closureClaimCandidate('closure_rationale', {
      closureEvent: true,
    });
    const authorizedEvidence = closureEvidence(candidate);
    const authorized = buildScoreClosureClaimAuthorityResolution(
      authorizedEvidence,
    );
    assert.equal(authorized.authorizedForScoring, true);
    assert.equal(authorized.finalClosureEventId, 'CE_final');

    const absent = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(candidate, { finalClosure: null }),
    );
    assert.equal(absent.reason, 'final_closure_evidence_absent');
    assert.equal(absent.authorizedForScoring, false);

    const mismatched = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(candidate, {
        finalClosure: {
          ...authorizedEvidence.finalClosure!,
          actorNodeId: 'U_other_actor',
        },
      }),
    );
    assert.equal(mismatched.reason, 'final_closure_identity_mismatch');
    assert.equal(mismatched.authorizedForScoring, false);
  });

  it('persists closure subjects only when row identity and candidate ID agree', () => {
    const candidate = closureClaimCandidate('fix_proof');
    const resolution = buildScoreClosureClaimAuthorityResolution(
      closureEvidence(candidate),
    );
    const run = buildScoreAuthorityResolutionRun({
      authorityRunId: 'authority-run-closure-claim',
      sourceIdentitySchemaVersion: 13,
      sourceIdentityDigest: SOURCE_IDENTITY_DIGEST,
      previousContentHash: null,
      recordedAt: '2026-07-04T18:00:00Z',
      rows: [{
        releaseTag: 'v1.2.3',
        issueNumber: 1,
        subjectKind: 'closure_claim',
        subjectIdentity: resolution.candidateId,
        candidateId: resolution.candidateId,
        resolution,
      }],
    });
    assert.deepEqual(scoreAuthorityResolutionRunProblems(run), []);
    assert.equal(run.rows[0].subjectKind, 'closure_claim');
    assert.equal(run.rows[0].candidateId, resolution.candidateId);
    assert.throws(
      () => buildScoreAuthorityResolutionRun({
        authorityRunId: 'authority-run-closure-claim-invalid',
        sourceIdentitySchemaVersion: 13,
        sourceIdentityDigest: SOURCE_IDENTITY_DIGEST,
        previousContentHash: run.contentHash,
        recordedAt: '2026-07-04T18:01:00Z',
        rows: [{
          releaseTag: 'v1.2.3',
          issueNumber: 1,
          subjectKind: 'closure_claim',
          subjectIdentity: resolution.candidateId,
          candidateId: 'different-candidate',
          resolution,
        }],
      }),
      /candidate ID must equal the resolution candidate ID/,
    );
  });

  it('detects closure authority resolution tampering', () => {
    const candidate = closureClaimCandidate('reporter_action', {
      body: 'I refiled this as #2 with a smaller reproduction.',
      actorNodeId: 'U_reporter',
    });
    const evidence = closureEvidence(candidate);
    const resolution = buildScoreClosureClaimAuthorityResolution(evidence);
    assert.match(resolution.resolutionHash, /^[0-9a-f]{64}$/);
    assert.notDeepEqual(
      scoreClosureClaimAuthorityResolutionProblems({
        ...resolution,
        issueAuthorNodeId: 'U_attacker',
      }),
      [],
    );
    assert.notDeepEqual(
      scoreClosureClaimAuthorityResolutionProblems({
        ...resolution,
        resolutionHash: '0'.repeat(64),
      }),
      [],
    );
  });
});

describe('release score audit history v2 seals', () => {
  it('normalizes timestamps and hashes the exact history-authority linkage', () => {
    const input = {
      historyRunId: 'history-run-1',
      authorityRunId: 'authority-run-1',
      historyRowCount: 2,
      historyRowsContentHash: 'c'.repeat(64),
      authorityRowCount: 1,
      authorityRowsContentHash: 'd'.repeat(64),
      previousContentHash: 'e'.repeat(64),
    } as const;
    const utc = buildReleaseScoreAuditHistoryV2Seal({
      ...input,
      sealedAt: '2026-07-04T18:00:00Z',
    });
    const offset = buildReleaseScoreAuditHistoryV2Seal({
      ...input,
      sealedAt: '2026-07-04T12:00:00-06:00',
    });

    assert.equal(utc.contentHash, offset.contentHash);
    assert.equal(
      canonicalReleaseScoreAuditHistoryV2SealJson(utc),
      canonicalReleaseScoreAuditHistoryV2SealJson(offset),
    );
    assert.deepEqual(releaseScoreAuditHistoryV2SealProblems(utc), []);
  });

  it('detects linkage, projection, predecessor, and content tamper', () => {
    const seal = buildReleaseScoreAuditHistoryV2Seal({
      historyRunId: 'history-run-1',
      authorityRunId: 'authority-run-1',
      sealedAt: '2026-07-04T18:00:00Z',
      historyRowCount: 2,
      historyRowsContentHash: 'c'.repeat(64),
      authorityRowCount: 1,
      authorityRowsContentHash: 'd'.repeat(64),
      previousContentHash: 'e'.repeat(64),
    });
    for (const tampered of [
      { ...seal, historyRunId: 'history-run-2' },
      { ...seal, authorityRunId: 'authority-run-2' },
      { ...seal, historyRowCount: 3 },
      { ...seal, historyRowsContentHash: 'f'.repeat(64) },
      { ...seal, authorityRowCount: 2 },
      { ...seal, authorityRowsContentHash: 'a'.repeat(64) },
      { ...seal, previousContentHash: null },
      { ...seal, contentHash: '0'.repeat(64) },
    ]) {
      assert.notDeepEqual(releaseScoreAuditHistoryV2SealProblems(tampered), []);
    }
  });
});
