import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  canonicalCommentActorIdentity,
  canonicalCommentSourceIdentity,
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
  isExactIssueReporterComment,
  parseCachedCommentEvidence,
  serializeCommentEvidence,
} from './commentEvidence.ts';

describe('comment evidence cache', () => {
  const issueIdentity = {
    repositoryNodeId: 'REPO-node-openclaw',
    issueNodeId: 'ISSUE-node-1',
    issueNodeType: 'Issue',
    issueAuthor: {
      nodeId: 'ACTOR-reporter',
      login: 'reporter',
      actorType: 'User',
    },
  };
  const comments = [
    {
      id: 2,
      node_id: 'COMMENT-node-2',
      node_type: 'IssueComment',
      body: 'second',
      created_at: '2026-01-02T00:00:00Z',
      updated_at: '2026-01-02T01:00:00Z',
      author_association: 'MEMBER',
      url: 'https://example.test/comments/2',
      user: {
        id: 'ACTOR-maintainer',
        login: 'maintainer',
        type: 'User',
      },
    },
    {
      id: 1,
      node_id: 'COMMENT-node-1',
      node_type: 'IssueComment',
      body: 'first',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: null,
      author_association: 'CONTRIBUTOR',
      url: 'https://example.test/comments/1',
      user: {
        id: 'ACTOR-reporter',
        login: 'reporter',
        type: 'User',
      },
    },
  ];

  it('uses a stable digest independent of response ordering', () => {
    assert.equal(
      commentEvidenceDigest(2, comments, issueIdentity),
      commentEvidenceDigest(2, [...comments].reverse(), issueIdentity),
    );
  });

  it('binds repository, issue, comment, actor, and actor-type identities into the digest', () => {
    const baseline = commentEvidenceDigest(2, comments, issueIdentity);
    const variants = [
      {
        comments,
        identity: {
          ...issueIdentity,
          repositoryNodeId: 'REPO-node-other',
        },
      },
      {
        comments,
        identity: { ...issueIdentity, issueNodeId: 'ISSUE-node-other' },
      },
      {
        comments,
        identity: {
          ...issueIdentity,
          issueAuthor: {
            ...issueIdentity.issueAuthor,
            nodeId: 'ACTOR-other-reporter',
          },
        },
      },
      {
        comments: comments.map((comment, index) => index === 0
          ? { ...comment, node_id: 'COMMENT-node-other' }
          : comment),
        identity: issueIdentity,
      },
      {
        comments: comments.map((comment, index) => index === 0
          ? {
              ...comment,
              user: { ...comment.user, id: 'ACTOR-other-maintainer' },
            }
          : comment),
        identity: issueIdentity,
      },
      {
        comments: comments.map((comment, index) => index === 0
          ? {
              ...comment,
              user: { ...comment.user, type: 'Bot' },
            }
          : comment),
        identity: issueIdentity,
      },
    ];

    for (const variant of variants) {
      assert.notEqual(
        commentEvidenceDigest(2, variant.comments, variant.identity),
        baseline,
      );
    }
  });

  it('authorizes reporters only by exact canonical issue-author node identity', () => {
    const reporterComment = comments[1];
    assert.equal(
      isExactIssueReporterComment(issueIdentity.issueAuthor, {
        ...reporterComment,
        user: {
          ...reporterComment.user,
          login: 'renamed-reporter',
        },
        author_association: 'NONE',
      }),
      true,
    );
    assert.equal(
      isExactIssueReporterComment(issueIdentity.issueAuthor, {
        ...reporterComment,
        user: {
          ...reporterComment.user,
          id: 'ACTOR-impostor',
          login: 'reporter',
        },
        author_association: 'OWNER',
      }),
      false,
    );
    assert.equal(
      isExactIssueReporterComment(issueIdentity.issueAuthor, {
        ...reporterComment,
        user: null,
      }),
      false,
    );
    assert.equal(
      isExactIssueReporterComment(
        { nodeId: null, login: 'reporter', actorType: 'User' },
        reporterComment,
      ),
      false,
    );
  });

  it('preserves bot actor types without treating login or association as identity', () => {
    const botComment = {
      ...comments[0],
      user: {
        id: 'ACTOR-release-bot',
        login: 'release-bot',
        type: 'Bot',
      },
      author_association: 'OWNER',
    };
    assert.deepEqual(canonicalCommentActorIdentity(botComment), {
      source: 'github',
      nodeType: 'Bot',
      nodeId: 'ACTOR-release-bot',
    });
    assert.equal(
      isExactIssueReporterComment(
        {
          nodeId: 'ACTOR-release-bot',
          login: 'old-release-bot-name',
          actorType: 'Bot',
        },
        botComment,
      ),
      true,
    );
    assert.equal(
      isExactIssueReporterComment(
        {
          nodeId: 'ACTOR-release-bot',
          login: 'release-bot',
          actorType: 'User',
        },
        botComment,
      ),
      false,
    );
  });

  it('keeps immutable comment identity stable across edits while digesting edit content', () => {
    const edited = {
      ...comments[0],
      body: 'second, edited',
      updated_at: '2026-01-03T01:00:00Z',
    };
    assert.deepEqual(
      canonicalCommentSourceIdentity(edited),
      canonicalCommentSourceIdentity(comments[0]),
    );
    assert.notEqual(
      commentEvidenceDigest(1, [edited]),
      commentEvidenceDigest(1, [comments[0]]),
    );
  });

  it('keeps legacy rows without node IDs display-only', () => {
    const legacy = {
      ...comments[1],
      node_id: null,
      user: { login: 'reporter' },
    };
    assert.equal(canonicalCommentSourceIdentity(legacy), null);
    assert.equal(canonicalCommentActorIdentity(legacy), null);
    assert.equal(
      isExactIssueReporterComment(issueIdentity.issueAuthor, legacy),
      false,
    );
    const digest = commentEvidenceDigest(1, [legacy]);
    assert.deepEqual(
      parseCachedCommentEvidence(serializeCommentEvidence([legacy]), 1, digest),
      [legacy],
    );
  });

  it('stabilizes only complete canonical issue, comment, and actor identities', () => {
    const firstSweep = commentEvidenceSweepIdentity({
      sweepOrdinal: 1,
      issueUpdatedAt: '2026-01-02T01:00:00Z',
      totalCount: comments.length,
      comments,
      snapshotIdentity: issueIdentity,
    });
    const secondSweep = commentEvidenceSweepIdentity({
      sweepOrdinal: 2,
      issueUpdatedAt: '2026-01-02T01:00:00Z',
      totalCount: comments.length,
      comments: [...comments].reverse(),
      snapshotIdentity: issueIdentity,
    });
    const stabilization = commentEvidenceStabilizationIdentity(
      firstSweep,
      secondSweep,
      2,
    );

    assert.equal(firstSweep.authorityDigest, secondSweep.authorityDigest);
    assert.equal(stabilization.firstSweep.sweepOrdinal, 1);
    assert.equal(stabilization.secondSweep.sweepOrdinal, 2);
    assert.match(stabilization.identityDigest, /^[0-9a-f]{64}$/);
    assert.throws(
      () => commentEvidenceStabilizationIdentity(
        {
          ...firstSweep,
          identityDigest: '0'.repeat(64),
        },
        secondSweep,
        2,
      ),
      /first sweep identity digest mismatch/,
    );

    assert.throws(
      () => commentEvidenceSweepIdentity({
        sweepOrdinal: 1,
        issueUpdatedAt: '2026-01-02T01:00:00Z',
        totalCount: comments.length,
        comments,
        snapshotIdentity: {
          ...issueIdentity,
          repositoryNodeId: null,
        },
      }),
      /canonical repository node identity/,
    );
    assert.throws(
      () => commentEvidenceSweepIdentity({
        sweepOrdinal: 1,
        issueUpdatedAt: '2026-01-02T01:00:00Z',
        totalCount: comments.length,
        comments,
        snapshotIdentity: {
          ...issueIdentity,
          issueNodeId: null,
        },
      }),
      /canonical Issue node identity/,
    );
    assert.throws(
      () => commentEvidenceSweepIdentity({
        sweepOrdinal: 1,
        issueUpdatedAt: '2026-01-02T01:00:00Z',
        totalCount: comments.length,
        comments: comments.map((comment, index) => index === 0
          ? { ...comment, node_type: null }
          : comment),
        snapshotIdentity: issueIdentity,
      }),
      /canonical IssueComment node identities/,
    );
    assert.throws(
      () => commentEvidenceSweepIdentity({
        sweepOrdinal: 1,
        issueUpdatedAt: '2026-01-02T01:00:00Z',
        totalCount: comments.length,
        comments: comments.map((comment, index) => index === 0
          ? {
              ...comment,
              user: {
                login: comment.user.login,
              },
            }
          : comment),
        snapshotIdentity: issueIdentity,
      }),
      /canonical actor identity/,
    );
  });

  it('binds persisted proof URLs into the digest', () => {
    const changedUrl = comments.map((comment, index) => (
      index === 0 ? { ...comment, url: 'https://example.test/comments/replaced' } : comment
    ));

    assert.notEqual(
      commentEvidenceDigest(2, comments),
      commentEvidenceDigest(2, changedUrl),
    );
    assert.equal(
      parseCachedCommentEvidence(
        serializeCommentEvidence(changedUrl),
        2,
        commentEvidenceDigest(2, comments),
      ),
      null,
    );
  });

  it('keeps tied timestamps order-independent when IDs establish order', () => {
    const tiedTimestamps = comments.map((comment) => ({
      ...comment,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T01:00:00Z',
    }));

    assert.equal(
      commentEvidenceDigest(2, tiedTimestamps),
      commentEvidenceDigest(2, [...tiedTimestamps].reverse()),
    );
  });

  it('rejects ambiguous records tied on timestamp without IDs', () => {
    const ambiguous = comments.map((comment) => ({
      ...comment,
      id: null,
      node_id: null,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T01:00:00Z',
    }));

    assert.throws(
      () => commentEvidenceDigest(2, ambiguous),
      /Ambiguous comment evidence order/,
    );
    assert.equal(
      parseCachedCommentEvidence(
        serializeCommentEvidence(ambiguous),
        2,
        commentEvidenceDigest(2, comments),
      ),
      null,
    );
  });

  it('uses immutable node IDs to deterministically order comments without database IDs', () => {
    const tied = comments.map((comment) => ({
      ...comment,
      id: null,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T01:00:00Z',
    }));
    assert.equal(
      commentEvidenceDigest(2, tied),
      commentEvidenceDigest(2, [...tied].reverse()),
    );
  });

  it('rejects duplicate comment IDs even when timestamps differ', () => {
    const duplicates = comments.map((comment) => ({ ...comment, id: 1 }));

    assert.throws(
      () => commentEvidenceDigest(2, duplicates),
      /Duplicate comment evidence ID 1/,
    );
    assert.equal(
      parseCachedCommentEvidence(
        serializeCommentEvidence(duplicates),
        2,
        commentEvidenceDigest(2, comments),
      ),
      null,
    );
  });

  it('rejects duplicate or conflicting canonical node identities', () => {
    const duplicateNodeIds = comments.map((comment) => ({
      ...comment,
      node_id: 'COMMENT-duplicate',
    }));
    assert.throws(
      () => commentEvidenceDigest(2, duplicateNodeIds),
      /Duplicate comment evidence node ID COMMENT-duplicate/,
    );

    const conflictingCommentAliases = [{
      ...comments[0],
      nodeId: 'COMMENT-conflict',
    }];
    assert.throws(
      () => commentEvidenceDigest(1, conflictingCommentAliases),
      /comment node ID aliases conflict/,
    );

    const conflictingActorAliases = [{
      ...comments[0],
      user: {
        ...comments[0].user,
        node_id: 'ACTOR-conflict',
      },
    }];
    assert.throws(
      () => commentEvidenceDigest(1, conflictingActorAliases),
      /comment actor node ID aliases conflict/,
    );
    assert.equal(
      isExactIssueReporterComment(
        issueIdentity.issueAuthor,
        conflictingActorAliases[0],
      ),
      false,
    );
  });

  it('rejects partial actor identity and count drift', () => {
    assert.throws(
      () => commentEvidenceDigest(1, [{
        ...comments[0],
        user: {
          ...comments[0].user,
          type: null,
        },
      }]),
      /actor node ID requires a canonical actor type/,
    );
    assert.throws(
      () => commentEvidenceDigest(2, comments.slice(0, 1)),
      /count 1 does not match total count 2/,
    );
  });

  it('accepts complete digest-matching cached comments', () => {
    const digest = commentEvidenceDigest(2, comments, issueIdentity);
    assert.deepEqual(
      parseCachedCommentEvidence(
        serializeCommentEvidence(comments),
        2,
        digest,
        issueIdentity,
      ),
      comments,
    );
  });

  it('rejects non-snake-case comment timestamp fields', () => {
    const {
      created_at: createdAt,
      updated_at: updatedAt,
      ...withoutSnakeCaseTimestamps
    } = comments[0];
    const malformed = [{
      ...withoutSnakeCaseTimestamps,
      createdAt,
      updatedAt,
    }];

    assert.throws(
      () => commentEvidenceDigest(1, malformed),
      /must use snake-case created_at and updated_at timestamps/,
    );
    assert.equal(
      parseCachedCommentEvidence(
        serializeCommentEvidence(malformed),
        1,
        commentEvidenceDigest(2, comments),
      ),
      null,
    );
  });

  it('rejects unbound fields in comments, actors, and snapshot identities', () => {
    assert.throws(
      () => commentEvidenceDigest(1, [{
        ...comments[0],
        unboundEvidence: true,
      } as any]),
      /unknown field unboundEvidence/,
    );
    assert.throws(
      () => commentEvidenceDigest(1, [{
        ...comments[0],
        user: {
          ...comments[0].user,
          unboundIdentity: true,
        },
      } as any]),
      /unknown field unboundIdentity/,
    );
    assert.throws(
      () => commentEvidenceDigest(2, comments, {
        ...issueIdentity,
        issueNumber: 1,
      } as any),
      /snapshot identity has unknown field issueNumber/,
    );
    assert.throws(
      () => commentEvidenceDigest(2, comments, {
        ...issueIdentity,
        issueAuthor: {
          ...issueIdentity.issueAuthor,
          databaseId: 1,
        },
      } as any),
      /issue author identity has unknown field databaseId/i,
    );
  });

  it('rejects invalid or reversed comment timestamps', () => {
    const invalidRows = [
      { ...comments[0], created_at: 'not-a-timestamp' },
      { ...comments[0], updated_at: 'not-a-timestamp' },
      {
        ...comments[0],
        created_at: '2026-01-02T00:00:00Z',
        updated_at: '2026-01-01T23:59:59Z',
      },
    ];

    for (const row of invalidRows) {
      assert.throws(
        () => commentEvidenceDigest(1, [row]),
        /invalid created_at|invalid updated_at|updated_at before created_at/,
      );
      assert.equal(
        parseCachedCommentEvidence(
          serializeCommentEvidence([row]),
          1,
          commentEvidenceDigest(2, comments),
        ),
        null,
      );
    }
  });

  it('rejects malformed, incomplete, and digest-mismatched caches', () => {
    const digest = commentEvidenceDigest(2, comments);
    assert.equal(parseCachedCommentEvidence(null, 2, digest), null);
    assert.equal(parseCachedCommentEvidence('{bad json', 2, digest), null);
    assert.equal(parseCachedCommentEvidence(serializeCommentEvidence(comments.slice(0, 1)), 2, digest), null);
    assert.equal(parseCachedCommentEvidence(serializeCommentEvidence(comments), 2, 'bad-digest'), null);
  });
});
