import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  assertClosureClaimCandidate,
  assertClosureClaimExtractionReceipt,
  assertImmutableClosureClaimCandidate,
  buildClosureClaimCandidateLedgerEntry,
  buildClosureClaimExtractionReceipt,
  buildClosureClaimSourceSnapshotLedgerEntry,
  closureClaimCandidateProblems,
  closureClaimCandidateSetDigest,
  closureClaimCandidateSourceTextMatches,
  closureClaimExtractionReceiptProblems,
  closureClaimIssueBodyDigest,
  extractClosureClaimCandidates,
  mergeClosureClaimCandidates,
  type ClosureClaimActorIdentity,
  type ClosureClaimCandidate,
  type ClosureClaimExtractionInput,
  type ClosureClaimTextSource,
} from './closureClaimCandidates.ts';

const repository = {
  nodeId: 'REPOSITORY_openclaw',
  nameWithOwner: 'openclaw/openclaw',
};
const reporter = actor('ACTOR_reporter', 'reporter');
const maintainer = actor('ACTOR_maintainer', 'maintainer');

function actor(
  nodeId: string | null,
  login: string | null,
  type: string | null = 'User',
): ClosureClaimActorIdentity {
  return { nodeId, login, type };
}

function comment(
  nodeId: string | null,
  body: string,
  overrides: Partial<ClosureClaimTextSource> = {},
): ClosureClaimTextSource {
  return {
    nodeId,
    databaseId: nodeId == null ? null : Number(nodeId.replace(/\D/g, '')) || 1,
    url: nodeId == null ? null : `https://github.com/openclaw/openclaw/issues/42#issuecomment-${nodeId}`,
    actor: maintainer,
    createdAt: '2026-07-04T01:00:00Z',
    updatedAt: '2026-07-04T01:00:00Z',
    body,
    ...overrides,
  };
}

function input(overrides: Partial<ClosureClaimExtractionInput> = {}): ClosureClaimExtractionInput {
  return {
    repository,
    issue: {
      nodeId: 'ISSUE_42',
      number: 42,
      author: reporter,
    },
    comments: [],
    closureEvents: [],
    ...overrides,
  };
}

function claims(result: ReturnType<typeof extractClosureClaimCandidates>, kind: string) {
  return result.candidates.filter((candidate) => candidate.claimKind === kind);
}

describe('immutable authority-neutral closure claim candidates', () => {
  it('extracts every claim family without assigning trust or authority', () => {
    const result = extractClosureClaimCandidates(input({
      issueBody: {
        nodeId: 'ISSUE_BODY_42',
        actor: reporter,
        createdAt: '2026-07-04T00:00:00Z',
        updatedAt: '2026-07-04T00:00:00Z',
        body: 'Affects v2026.6.1 and still fails in production.',
      },
      comments: [
        comment('COMMENT_1', 'Closing as duplicate of #9001.'),
        comment(
          'COMMENT_2',
          'Fixed by PR #812 and commit 0123456789abcdef0123456789abcdef01234567 in v2026.6.2.',
          { createdAt: '2026-07-04T01:01:00Z', updatedAt: '2026-07-04T01:01:00Z' },
        ),
        comment(
          'COMMENT_3',
          'We can reproduce the same failure in our production deployment.',
          {
            actor: actor('ACTOR_customer', 'customer'),
            createdAt: '2026-07-04T01:02:00Z',
            updatedAt: '2026-07-04T01:02:00Z',
          },
        ),
        comment(
          'COMMENT_4',
          'I refiled this as #9002 with a smaller reproduction.',
          {
            actor: reporter,
            createdAt: '2026-07-04T01:03:00Z',
            updatedAt: '2026-07-04T01:03:00Z',
          },
        ),
      ],
    }));

    assert.deepEqual(
      [...new Set(result.candidates.map((candidate) => candidate.claimKind))].sort(),
      [
        'closure_rationale',
        'duplicate_or_superseded',
        'field_confirmation',
        'fix_proof',
        'release_local',
        'reporter_action',
      ],
    );
    assert.equal(result.rejections.length, 0);
    assert.ok(result.candidates.every((candidate) => candidate.eligibility === 'immutable'));
    assert.ok(result.candidates.every((candidate) => candidate.candidateId?.startsWith('sha256:')));
    assert.ok(result.candidates.every((candidate) => candidate.sourceIdentity?.startsWith('sha256:')));
    assert.ok(result.candidates.every((candidate) =>
      !('trusted' in candidate) &&
      !('authorized' in candidate) &&
      !('authority' in candidate)));

    const duplicate = claims(result, 'duplicate_or_superseded')[0];
    assert.deepEqual(duplicate.claim, {
      kind: 'duplicate_or_superseded',
      relation: 'duplicate',
      target: {
        resource: 'issue',
        repositoryNameWithOwner: 'openclaw/openclaw',
        number: 9001,
      },
    });
    const reporterAction = claims(result, 'reporter_action')[0];
    assert.equal((reporterAction.claim as any).reporterNodeId, reporter.nodeId);
  });

  it('uses active author text only and respects negation and quoted boundaries', () => {
    const result = extractClosureClaimCandidates(input({
      comments: [
        comment('COMMENT_10', [
          '> Closing as duplicate of #100.',
          'The prior comment said "fixed in v2026.6.1" but that was stale.',
          'Prefix "fixed in v2026.6.3" suffix must remain quoted history.',
          '```',
          'We can reproduce this in production.',
          '```',
          'This is not a duplicate.',
          'Emoji before proof: 🔒 It is not fixed in v2026.6.2 and still fails in production.',
        ].join('\n')),
        comment(
          'COMMENT_11',
          'I cannot reproduce this and I am not seeing the same failure.',
          {
            actor: actor('ACTOR_other', 'other'),
            createdAt: '2026-07-04T01:01:00Z',
            updatedAt: '2026-07-04T01:01:00Z',
          },
        ),
      ],
    }));

    assert.equal(claims(result, 'duplicate_or_superseded').length, 0);
    assert.equal(claims(result, 'field_confirmation').length, 1);
    assert.deepEqual(
      claims(result, 'release_local').map((candidate) => candidate.claim),
      [{
        kind: 'release_local',
        assertion: 'not_fixed',
        releaseTag: 'v2026.6.2',
      }],
    );
    assert.equal(
      claims(result, 'fix_proof').some((candidate) =>
        candidate.canonicalClaimJson.includes('v2026.6.1')),
      false,
    );
  });

  it('binds mixed release clauses to tag-specific assertions', () => {
    const result = extractClosureClaimCandidates(input({
      comments: [comment(
        'COMMENT_mixed_release_claims',
        [
          'v2026.6.10 is unaffected, while v2026.6.11 is affected.',
          'v2026.6.12 is not fixed, whereas v2026.6.13 is fixed.',
        ].join(' '),
      )],
    }));

    assert.deepEqual(
      claims(result, 'release_local').map((candidate) => candidate.claim),
      [
        {
          kind: 'release_local',
          assertion: 'not_affected',
          releaseTag: 'v2026.6.10',
        },
        {
          kind: 'release_local',
          assertion: 'affected',
          releaseTag: 'v2026.6.11',
        },
        {
          kind: 'release_local',
          assertion: 'not_fixed',
          releaseTag: 'v2026.6.12',
        },
        {
          kind: 'release_local',
          assertion: 'fixed',
          releaseTag: 'v2026.6.13',
        },
      ],
    );
  });

  it('binds repository, issue, source, actor, timestamps, text, claim, and span deterministically', () => {
    const first = extractClosureClaimCandidates(input({
      comments: [comment('COMMENT_20', 'Closing as superseded by #9010.')],
    }));
    const replay = extractClosureClaimCandidates(input({
      comments: [comment('COMMENT_20', 'Closing as superseded by #9010.')],
    }));
    assert.deepEqual(replay, first);

    const candidate = claims(first, 'duplicate_or_superseded')[0];
    assert.equal(closureClaimCandidateProblems(candidate).length, 0);
    assert.doesNotThrow(() => assertClosureClaimCandidate(candidate));
    assert.equal(
      closureClaimCandidateSourceTextMatches(candidate, 'Closing as superseded by #9010.'),
      true,
    );
    assert.equal(
      closureClaimCandidateSourceTextMatches(candidate, 'Closing as superseded by #9011.'),
      false,
    );
    assert.match(candidate.canonicalSourceIdentityJson ?? '', /REPOSITORY_openclaw/);
    assert.match(candidate.canonicalSourceIdentityJson ?? '', /ACTOR_maintainer/);
    assert.equal(candidate.canonicalClaimJson, JSON.stringify({
      kind: 'duplicate_or_superseded',
      relation: 'superseded',
      target: {
        number: 9010,
        repositoryNameWithOwner: 'openclaw/openclaw',
        resource: 'issue',
      },
    }));
  });

  it('keeps edits immutable, deduplicates exact replay, and preserves old candidates when merged', () => {
    const originalSource = comment('COMMENT_30', 'Closing as duplicate of #9100.');
    const editedSource = comment('COMMENT_30', 'Closing as duplicate of #9200.', {
      updatedAt: '2026-07-04T02:00:00Z',
    });
    const original = extractClosureClaimCandidates(input({
      comments: [originalSource, structuredClone(originalSource)],
    }));
    const edited = extractClosureClaimCandidates(input({
      comments: [editedSource],
    }));
    const together = extractClosureClaimCandidates(input({
      comments: [editedSource, originalSource],
    }));

    assert.equal(claims(original, 'duplicate_or_superseded').length, 1);
    assert.notEqual(original.candidates[0].sourceIdentity, edited.candidates[0].sourceIdentity);
    assert.notEqual(original.candidates[0].candidateId, edited.candidates[0].candidateId);
    assert.deepEqual(
      claims(together, 'duplicate_or_superseded').map((candidate) => candidate.candidateId),
      mergeClosureClaimCandidates(original.candidates, edited.candidates)
        .filter((candidate) => candidate.claimKind === 'duplicate_or_superseded')
        .map((candidate) => candidate.candidateId),
    );
    assert.deepEqual(
      claims(together, 'duplicate_or_superseded')
        .map((candidate) => (candidate.claim as any).target.number),
      [9100, 9200],
    );
  });

  it('rejects conflicting same-revision replay and orders independently of input order', () => {
    const early = comment('COMMENT_40', 'Closing as duplicate of #9400.', {
      createdAt: '2026-07-04T01:00:00Z',
      updatedAt: '2026-07-04T01:00:00Z',
    });
    const late = comment('COMMENT_41', 'Fixed in v2026.6.4.', {
      createdAt: '2026-07-04T02:00:00Z',
      updatedAt: '2026-07-04T02:00:00Z',
    });
    const forward = extractClosureClaimCandidates(input({ comments: [early, late] }));
    const reverse = extractClosureClaimCandidates(input({ comments: [late, early] }));
    assert.deepEqual(reverse, forward);

    const conflict = extractClosureClaimCandidates(input({
      comments: [
        early,
        { ...early, body: 'Closing as duplicate of #9999.' },
      ],
    }));
    assert.equal(conflict.candidates.length, 0);
    assert.deepEqual(conflict.rejections.map((rejection) => rejection.code), [
      'conflicting_source_replay',
    ]);
  });

  it('makes missing identities display-only and rejects malformed sources without inferred IDs', () => {
    const result = extractClosureClaimCandidates(input({
      repository: {
        ...repository,
        nodeId: null,
      },
      issue: {
        nodeId: null,
        number: 42,
        author: reporter,
      },
      comments: [
        comment(null, 'Closing as duplicate of #9500.', {
          actor: actor(null, 'maintainer', null),
        }),
        comment('COMMENT_bad', 'Fixed in v2026.6.5.', {
          createdAt: null,
        }),
      ],
    }));

    assert.equal(result.candidates.length, 2);
    for (const candidate of result.candidates) {
      assert.equal(candidate.eligibility, 'display_only');
      assert.equal(candidate.candidateId, null);
      assert.equal(candidate.sourceIdentity, null);
      assert.equal(candidate.canonicalSourceIdentityJson, null);
      assert.deepEqual(candidate.identityProblems, [
        'missing_repository_node_id',
        'missing_issue_node_id',
        'missing_source_node_id',
        'missing_actor_node_id',
        'missing_actor_type',
      ]);
      assert.equal(closureClaimCandidateProblems(candidate).length, 0);
    }
    assert.equal(result.rejections.length, 1);
    assert.equal(result.rejections[0].sourceNodeId, 'COMMENT_bad');
    assert.equal(result.rejections[0].code, 'invalid_source');
    assert.match(result.rejections[0].detail, /createdAt/);
  });

  it('uses actor node identity rather than login for reporter actions and source identity', () => {
    const result = extractClosureClaimCandidates(input({
      comments: [
        comment('COMMENT_50', 'Please close this.', {
          actor: actor('ACTOR_reporter', 'same-login'),
        }),
        comment('COMMENT_51', 'Please close this.', {
          actor: actor('ACTOR_impostor', 'same-login'),
          createdAt: '2026-07-04T01:01:00Z',
          updatedAt: '2026-07-04T01:01:00Z',
        }),
      ],
      issue: {
        nodeId: 'ISSUE_42',
        number: 42,
        author: actor('ACTOR_reporter', 'same-login'),
      },
    }));

    assert.equal(claims(result, 'reporter_action').length, 1);

    const firstActor = extractClosureClaimCandidates(input({
      comments: [comment('COMMENT_actor', 'Closing as duplicate of #9550.', {
        actor: actor('ACTOR_first', 'same-login'),
      })],
    }));
    const secondActor = extractClosureClaimCandidates(input({
      comments: [comment('COMMENT_actor', 'Closing as duplicate of #9550.', {
        actor: actor('ACTOR_second', 'same-login'),
      })],
    }));
    assert.notEqual(
      claims(firstActor, 'duplicate_or_superseded')[0].sourceIdentity,
      claims(secondActor, 'duplicate_or_superseded')[0].sourceIdentity,
    );
    assert.equal(
      claims(firstActor, 'duplicate_or_superseded')[0].source.actor.login,
      claims(secondActor, 'duplicate_or_superseded')[0].source.actor.login,
    );
  });

  it('extracts structured closure-event rationale, fix proof, and reporter action', () => {
    const result = extractClosureClaimCandidates(input({
      closureEvents: [{
        nodeId: 'EVENT_closed_1',
        url: 'https://github.com/openclaw/openclaw/issues/42#event-1',
        actor: reporter,
        occurredAt: '2026-07-04T03:00:00Z',
        stateReason: 'COMPLETED',
        closer: {
          nodeId: 'PR_NODE_812',
          type: 'PullRequest',
          number: 812,
          oid: 'abcdef0123456789abcdef0123456789abcdef01',
          repositoryNameWithOwner: 'openclaw/openclaw',
        },
      }],
    }));

    assert.deepEqual(
      result.candidates.map((candidate) => candidate.claimKind),
      ['fix_proof', 'fix_proof', 'closure_rationale', 'reporter_action'],
    );
    assert.ok(result.candidates.every((candidate) =>
      candidate.source.textFormat === 'canonical_event_json'));
    assert.deepEqual(
      claims(result, 'fix_proof').map((candidate) => (candidate.claim as any).proofType),
      ['commit', 'pull_request'],
    );
  });

  it('keeps actor-attributed manual closure rationale without fabricating fix proof', () => {
    const result = extractClosureClaimCandidates(input({
      closureEvents: [{
        nodeId: 'CE_lADOQb6kR87neGc5zwAAAAZUHWvV',
        url: 'https://github.com/openclaw/openclaw/issues/6731#event-1',
        actor: actor('BOT_kgDOEFkMNA', 'clawsweeper', 'Bot'),
        occurredAt: '2026-06-25T06:35:15Z',
        stateReason: 'NOT_PLANNED',
        closer: null,
      }],
    }));

    assert.deepEqual(
      result.candidates.map((candidate) => candidate.claimKind),
      ['closure_rationale'],
    );
    assert.deepEqual(
      claims(result, 'closure_rationale')[0].claim,
      {
        kind: 'closure_rationale',
        rationale: 'not_planned',
      },
    );
    assert.deepEqual(claims(result, 'fix_proof'), []);
  });

  it('detects candidate tampering and produces stable set replay digests', () => {
    const result = extractClosureClaimCandidates(input({
      comments: [comment('COMMENT_60', 'Closing as duplicate of #9600.')],
    }));
    assert.equal(
      closureClaimCandidateSetDigest(result.candidates, result.rejections),
      result.digest,
    );

    const original = claims(result, 'duplicate_or_superseded')[0];
    const claimTampered = structuredClone(original) as ClosureClaimCandidate;
    (claimTampered.claim as any).target.number = 9601;
    assert.ok(closureClaimCandidateProblems(claimTampered).some((problem) =>
      /canonicalClaimJson|candidateId/.test(problem)));

    const actorTampered = structuredClone(original) as ClosureClaimCandidate;
    actorTampered.source.actor.nodeId = 'ACTOR_attacker';
    assert.ok(closureClaimCandidateProblems(actorTampered).some((problem) =>
      /canonicalSourceIdentityJson|sourceIdentity|candidateId/.test(problem)));

    const digestTampered = structuredClone(original) as ClosureClaimCandidate;
    digestTampered.source.textDigest = `sha256:${'0'.repeat(64)}`;
    assert.ok(closureClaimCandidateProblems(digestTampered).some((problem) =>
      /canonicalSourceIdentityJson|sourceIdentity|candidateId/.test(problem)));

    const excerptTampered = structuredClone(original) as ClosureClaimCandidate;
    excerptTampered.excerpt = 'tampered excerpt';
    assert.ok(closureClaimCandidateProblems(excerptTampered).some((problem) =>
      /candidateId/.test(problem)));

    assert.throws(
      () => mergeClosureClaimCandidates([claimTampered], []),
      /Invalid closure claim candidate/,
    );
  });

  it('builds one immutable source ledger entry for multiple same-kind claims', () => {
    const result = extractClosureClaimCandidates(input({
      comments: [comment(
        'COMMENT_70',
        'Fixed by PR #9700 and PR #9701 in v2026.6.7.',
      )],
    }));
    const fixClaims = claims(result, 'fix_proof');
    assert.ok(fixClaims.length >= 3);

    const sourceEntries = fixClaims.map(buildClosureClaimSourceSnapshotLedgerEntry);
    assert.equal(
      new Set(sourceEntries.map((entry) => entry.sourceIdentity)).size,
      1,
    );
    assert.equal(
      new Set(sourceEntries.map((entry) => entry.sourceRevisionIdentity)).size,
      1,
    );
    assert.equal(
      new Set(sourceEntries.map((entry) => entry.contentHash)).size,
      1,
    );

    const candidateEntries = fixClaims.map(buildClosureClaimCandidateLedgerEntry);
    assert.equal(
      new Set(candidateEntries.map((entry) => entry.candidateId)).size,
      candidateEntries.length,
    );
    assert.equal(
      new Set(candidateEntries.map((entry) => entry.contentHash)).size,
      candidateEntries.length,
    );
    assert.ok(candidateEntries.every((entry) =>
      entry.sourceIdentity === sourceEntries[0].sourceIdentity));
  });

  it('refuses to build immutable ledger entries from display-only evidence', () => {
    const result = extractClosureClaimCandidates(input({
      comments: [comment(null, 'Closing as duplicate of #9800.', {
        actor: actor(null, 'display-only', null),
      })],
    }));
    const candidate = result.candidates[0];
    assert.equal(candidate.eligibility, 'display_only');
    assert.throws(
      () => assertImmutableClosureClaimCandidate(candidate),
      /display-only/,
    );
    assert.throws(
      () => buildClosureClaimSourceSnapshotLedgerEntry(candidate),
      /display-only/,
    );
    assert.throws(
      () => buildClosureClaimCandidateLedgerEntry(candidate),
      /display-only/,
    );
  });

  it('builds a deterministic exact-set extraction receipt', () => {
    const extraction = extractClosureClaimCandidates(input({
      comments: [
        comment('COMMENT_80', 'Fixed by PR #9800 in v2026.7.4.'),
        comment('COMMENT_81', 'Closing as duplicate of #9801.', {
          createdAt: '2026-07-04T02:00:00Z',
          updatedAt: '2026-07-04T02:00:00Z',
        }),
      ],
    }));
    const binding = {
      repository: {
        nodeId: 'REPOSITORY_openclaw',
        nameWithOwner: 'openclaw/openclaw',
      },
      issue: {
        nodeId: 'ISSUE_42',
        number: 42,
        revision: 7,
        updatedAt: '2026-07-04T03:00:00Z',
        bodyDigest: closureClaimIssueBodyDigest('issue body'),
        authorNodeId: 'ACTOR_reporter',
        authorType: 'User',
      },
      commentSnapshot: {
        revision: 8,
        authorityDigest: '1'.repeat(64),
        stabilizationIdentityDigest: '2'.repeat(64),
      },
      stateSnapshot: {
        revision: 9,
        authorityDigest: '3'.repeat(64),
        stabilizationIdentityDigest: '4'.repeat(64),
      },
    };
    const receipt = buildClosureClaimExtractionReceipt(binding, extraction);
    const replay = buildClosureClaimExtractionReceipt(
      structuredClone(binding),
      structuredClone(extraction),
    );

    assert.deepEqual(replay, receipt);
    assert.equal(receipt.candidateCount, extraction.candidates.length);
    assert.deepEqual(
      receipt.members.map((member) => member.candidateId),
      extraction.candidates
        .map((candidate) => candidate.candidateId as string)
        .sort(),
    );
    assert.deepEqual(
      receipt.members.map((member) => member.ordinal),
      receipt.members.map((_, index) => index),
    );
    assert.equal(closureClaimExtractionReceiptProblems(receipt).length, 0);
    assert.doesNotThrow(() => assertClosureClaimExtractionReceipt(receipt));
  });

  it('records an explicit immutable zero-candidate extraction', () => {
    const extraction = extractClosureClaimCandidates(input({
      issueBody: {
        nodeId: 'ISSUE_42',
        actor: reporter,
        createdAt: '2026-07-04T00:00:00Z',
        updatedAt: '2026-07-04T03:00:00Z',
        body: 'Diagnostic logs are attached.',
      },
    }));
    assert.equal(extraction.candidates.length, 0);
    const receipt = buildClosureClaimExtractionReceipt({
      repository: {
        nodeId: 'REPOSITORY_openclaw',
        nameWithOwner: 'openclaw/openclaw',
      },
      issue: {
        nodeId: 'ISSUE_42',
        number: 42,
        revision: 1,
        updatedAt: '2026-07-04T03:00:00Z',
        bodyDigest: closureClaimIssueBodyDigest('Diagnostic logs are attached.'),
        authorNodeId: 'ACTOR_reporter',
        authorType: 'User',
      },
      commentSnapshot: {
        revision: 1,
        authorityDigest: '5'.repeat(64),
        stabilizationIdentityDigest: '6'.repeat(64),
      },
      stateSnapshot: {
        revision: 1,
        authorityDigest: '7'.repeat(64),
        stabilizationIdentityDigest: '8'.repeat(64),
      },
    }, extraction);

    assert.equal(receipt.candidateCount, 0);
    assert.deepEqual(receipt.members, []);
    assert.match(receipt.candidateSetDigest, /^[0-9a-f]{64}$/);
    assert.match(receipt.receiptId, /^[0-9a-f]{64}$/);
    assert.match(receipt.contentHash, /^[0-9a-f]{64}$/);
  });

  it('rejects receipt tampering, rejected extraction, and mismatched issue identity', () => {
    const extraction = extractClosureClaimCandidates(input({
      comments: [comment('COMMENT_90', 'Closing as duplicate of #9900.')],
    }));
    const binding = {
      repository: {
        nodeId: 'REPOSITORY_openclaw',
        nameWithOwner: 'openclaw/openclaw',
      },
      issue: {
        nodeId: 'ISSUE_42',
        number: 42,
        revision: 1,
        updatedAt: '2026-07-04T03:00:00Z',
        bodyDigest: closureClaimIssueBodyDigest(''),
        authorNodeId: 'ACTOR_reporter',
        authorType: 'User',
      },
      commentSnapshot: {
        revision: 1,
        authorityDigest: '9'.repeat(64),
        stabilizationIdentityDigest: 'a'.repeat(64),
      },
      stateSnapshot: {
        revision: 1,
        authorityDigest: 'b'.repeat(64),
        stabilizationIdentityDigest: 'c'.repeat(64),
      },
    };
    const receipt = buildClosureClaimExtractionReceipt(binding, extraction);
    const tampered = structuredClone(receipt);
    tampered.members[0].candidateContentHash = '0'.repeat(64);
    assert.ok(closureClaimExtractionReceiptProblems(tampered).some((problem) =>
      /candidateSetDigest|canonicalReceiptJson|contentHash/.test(problem)));

    const rejected = extractClosureClaimCandidates(input({
      comments: [comment('COMMENT_bad_receipt', 'Fixed in v2026.7.4.', {
        createdAt: null,
      })],
    }));
    assert.throws(
      () => buildClosureClaimExtractionReceipt(binding, rejected),
      /cannot authorize rejected source evidence/,
    );
    assert.throws(
      () => buildClosureClaimExtractionReceipt({
        ...binding,
        issue: {
          ...binding.issue,
          nodeId: 'ISSUE_other',
        },
      }, extraction),
      /does not match the extraction receipt evidence binding/,
    );
  });
});
