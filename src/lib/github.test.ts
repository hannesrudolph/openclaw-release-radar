import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { __githubTest } from './github.ts';

describe('GitHub GraphQL mapping', () => {
  it('maps releases into the existing REST-shaped contract', () => {
    const release = __githubTest.mapRelease({
      tagName: 'v2026.6.11',
      name: 'openclaw 2026.6.11',
      publishedAt: '2026-06-24T23:37:32Z',
      url: 'https://github.com/openclaw/openclaw/releases/tag/v2026.6.11',
      isPrerelease: false,
      isDraft: false,
      description: '### Fixes',
    });

    assert.deepEqual(release, {
      tag_name: 'v2026.6.11',
      name: 'openclaw 2026.6.11',
      published_at: '2026-06-24T23:37:32Z',
      html_url: 'https://github.com/openclaw/openclaw/releases/tag/v2026.6.11',
      prerelease: false,
      draft: false,
      body: '### Fixes',
    });
  });

  it('maps issues and labels into the existing REST-shaped contract', () => {
    const issue = __githubTest.mapIssue({
      number: 42,
      title: 'Regression in gateway',
      body: null,
      state: 'CLOSED',
      author: { login: 'maintainer' },
      authorAssociation: 'MEMBER',
      createdAt: '2026-06-20T00:00:00Z',
      updatedAt: '2026-06-21T00:00:00Z',
      closedAt: '2026-06-22T00:00:00Z',
      url: 'https://github.com/openclaw/openclaw/issues/42',
      comments: { totalCount: 3 },
      reactionGroups: [
        { content: 'THUMBS_UP', reactors: { totalCount: 4 } },
        { content: 'CONFUSED', reactors: { totalCount: 1 } },
      ],
      labels: { nodes: [{ name: 'bug' }, null, { name: 'impact:discord' }], pageInfo: { hasNextPage: false, endCursor: null } },
    });

    assert.equal(issue.state, 'closed');
    assert.equal(issue.user?.login, 'maintainer');
    assert.equal(issue.author_association, 'MEMBER');
    assert.equal(issue.comments, 3);
    assert.equal(issue.reaction_total, 5);
    assert.equal(issue.positive_reactions, 4);
    assert.deepEqual(issue.labels, [{ name: 'bug' }, { name: 'impact:discord' }]);
  });

  it('fails closed when issue score evidence connections are missing', () => {
    const issueNode = {
      number: 42,
      title: 'Regression in gateway',
      body: null,
      state: 'CLOSED',
      author: { login: 'maintainer' },
      authorAssociation: 'MEMBER',
      createdAt: '2026-06-20T00:00:00Z',
      updatedAt: '2026-06-21T00:00:00Z',
      closedAt: '2026-06-22T00:00:00Z',
      url: 'https://github.com/openclaw/openclaw/issues/42',
      comments: { totalCount: 3 },
      reactionGroups: [],
      labels: { nodes: [], pageInfo: { hasNextPage: false, endCursor: null } },
    };

    assert.throws(
      () => __githubTest.mapIssue({ ...issueNode, labels: null }),
      /issue #42 labels connection/,
    );
    assert.throws(
      () => __githubTest.mapIssue({ ...issueNode, labels: { nodes: null, pageInfo: { hasNextPage: false, endCursor: null } } }),
      /issue #42 labels connection missing nodes/,
    );
    assert.throws(
      () => __githubTest.mapIssue({ ...issueNode, reactionGroups: null }),
      /issue #42 missing reactionGroups/,
    );
  });

  it('validates GraphQL connections and pagination cursors', () => {
    const connection = __githubTest.requireGraphqlConnection(
      { nodes: [{ name: 'bug' }], pageInfo: { hasNextPage: false, endCursor: null } },
      'test.labels',
    );

    assert.equal(connection.nodes.length, 1);
    assert.equal(__githubTest.nextGraphqlPageCursor(connection.pageInfo, 'test.labels'), null);
    assert.equal(
      __githubTest.nextGraphqlPageCursor({ hasNextPage: true, endCursor: 'cursor-1' }, 'test.labels'),
      'cursor-1',
    );
    assert.throws(
      () => __githubTest.requireGraphqlConnection({ nodes: null, pageInfo: { hasNextPage: false, endCursor: null } }, 'test.labels'),
      /test\.labels connection missing nodes/,
    );
    assert.throws(
      () => __githubTest.requireGraphqlConnection({ nodes: [], pageInfo: null }, 'test.labels'),
      /test\.labels connection missing pageInfo/,
    );
    assert.throws(
      () => __githubTest.nextGraphqlPageCursor({ hasNextPage: true, endCursor: null }, 'test.labels'),
      /test\.labels pageInfo hasNextPage without endCursor/,
    );
  });

  it('builds one GraphQL query with aliased issue comment lookups', () => {
    const query = __githubTest.buildIssueCommentsBatchQuery(2);

    assert.match(query, /\$number0: Int!/);
    assert.match(query, /\$number1: Int!/);
    assert.match(query, /\$after0: String/);
    assert.match(query, /\$after1: String/);
    assert.match(query, /issue0: issue\(number: \$number0\)/);
    assert.match(query, /issue1: issue\(number: \$number1\)/);
    assert.match(query, /comments\(first: \$first, after: \$after0, orderBy: \{field: UPDATED_AT, direction: ASC\}\)/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(query, /authorAssociation/);
    assert.match(query, /updatedAt/);
  });

  it('maps issue comments with edit timestamps', () => {
    const comment = __githubTest.mapComment({
      databaseId: 42,
      author: { login: 'clawsweeper' },
      authorAssociation: 'CONTRIBUTOR',
      body: 'Close: current main and v2026.6.8 implement this behavior.',
      createdAt: '2026-06-07T15:44:06Z',
      updatedAt: '2026-06-19T15:29:09Z',
    });

    assert.deepEqual(comment, {
      id: 42,
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
      body: 'Close: current main and v2026.6.8 implement this behavior.',
      created_at: '2026-06-07T15:44:06Z',
      updated_at: '2026-06-19T15:29:09Z',
    });
  });

  it('builds one GraphQL query with aliased issue lookups by number', () => {
    const query = __githubTest.buildIssuesBatchQuery(2);

    assert.match(query, /\$number0: Int!/);
    assert.match(query, /\$number1: Int!/);
    assert.match(query, /issue0: issue\(number: \$number0\)/);
    assert.match(query, /issue1: issue\(number: \$number1\)/);
    assert.match(query, /body/);
    assert.match(query, /authorAssociation/);
    assert.match(query, /labels\(first: 100\)/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('paginates current issue labels', () => {
    const query = __githubTest.buildIssueLabelsQuery();

    assert.match(query, /\$after: String/);
    assert.match(query, /labels\(first: 100, after: \$after\)/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('builds one GraphQL query with aliased issue label timeline lookups', () => {
    const query = __githubTest.buildIssueLabelEventsBatchQuery(2);

    assert.match(query, /\$after0: String/);
    assert.match(query, /\$after1: String/);
    assert.match(query, /LABELED_EVENT/);
    assert.match(query, /UNLABELED_EVENT/);
    assert.match(query, /issue0: issue\(number: \$number0\)/);
    assert.match(query, /issue1: issue\(number: \$number1\)/);
    assert.match(query, /timelineItems\(first: 100, after: \$after0/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(query, /label \{ name \}/);
  });

  it('extracts closure-comment PR evidence without trusting bare issue refs', () => {
    const mentions = __githubTest.closureCommentPrMentions(9000, [
      {
        body: 'I found the merged PR that appears to have closed this: [#95532: fix path](https://api.github.com/repos/openclaw/openclaw/pulls/95532).',
        created_at: '2026-06-24T10:00:00Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'See also #12345 and issue #95532 for context; neither line says this is a PR.',
        created_at: '2026-06-24T11:00:00Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'The release note points at https://github.com/openclaw/openclaw/pull/96025.',
        created_at: '2026-06-24T12:00:00Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'The merged PR #96040 fixes this report.',
        created_at: '2026-06-24T13:00:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'I found the merged PR that appears to have closed this: #87998. This does not need to stay open separately.',
        created_at: '2026-06-24T14:00:00Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'This is fixed on `main` by #95900 / 2aa9d676356455102fe4189e5e5d470c06eead94. Closing as fixed on main; users on 2026.6.10 will pick this up with the next release.',
        created_at: '2026-06-25T15:05:01Z',
        user: { login: 'obviyus' },
        author_association: 'MEMBER',
      },
      {
        body: 'Fixed on current main, primarily by #88630 (`b4cdd9211957875df0d301ccc40e2935ba26829f`, merged June 10, 2026).',
        created_at: '2026-06-25T15:06:01Z',
        user: { login: 'steipete' },
        author_association: 'MEMBER',
      },
      {
        body: 'Marking this fixed by the linked upstream patch. Canonical PR: #85475.',
        created_at: '2026-06-25T15:07:01Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
    ]);

    assert.deepEqual(mentions, [
      {
        issueNumber: 9000,
        prNumber: 85475,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-25T15:07:01Z',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 87998,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-24T14:00:00Z',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 88630,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-25T15:06:01Z',
        author: 'steipete',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 95532,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-24T10:00:00Z',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 95900,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-25T15:05:01Z',
        author: 'obviyus',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 96040,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        referencedAt: '2026-06-24T13:00:00Z',
        author: 'maintainer',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
    ]);
  });

  it('extracts trusted canonical PR context without marking it fix proof', () => {
    const mentions = __githubTest.closureCommentPrMentions(97322, [
      {
        body: 'Close as superseded: this is tracked in the active continuation work. Canonical path: Open PR https://github.com/openclaw/openclaw/pull/85651 owns this feature work.',
        created_at: '2026-06-27T20:23:27Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'Maybe the release note points at https://github.com/openclaw/openclaw/pull/85652.',
        created_at: '2026-06-27T20:24:27Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
    ]);

    assert.deepEqual(mentions, [{
      issueNumber: 97322,
      prNumber: 85651,
      prRepositoryOwner: 'openclaw',
      prRepositoryName: 'openclaw',
      prRepositoryNameWithOwner: 'openclaw/openclaw',
      source: 'ClosureComment.prMention',
      referencedAt: '2026-06-27T20:23:27Z',
      author: 'clawsweeper',
      authorAssociation: 'CONTRIBUTOR',
      trustedSource: true,
    }]);
  });

  it('preserves repository identity from trusted cross-repo PR URLs', () => {
    const mentions = __githubTest.closureCommentPrMentions(101, [{
      body: 'Close as superseded: Canonical path: Open PR https://github.com/openclaw/clownfish/pull/147 owns the external adapter work.',
      created_at: '2026-06-27T20:23:27Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
    }]);

    assert.deepEqual(mentions, [{
      issueNumber: 101,
      prNumber: 147,
      prRepositoryOwner: 'openclaw',
      prRepositoryName: 'clownfish',
      prRepositoryNameWithOwner: 'openclaw/clownfish',
      source: 'ClosureComment.prMention',
      referencedAt: '2026-06-27T20:23:27Z',
      author: 'clawsweeper',
      authorAssociation: 'CONTRIBUTOR',
      trustedSource: true,
    }]);
  });

  it('extracts closure-comment commit proof without trusting incidental hashes', () => {
    const mentions = __githubTest.closureCommentCommitMentions(97222, [
      {
        body: 'Fix provenance: Commit `cfeaf6897fd89201b71ff7d5285e48c5a382ac9a` is titled `fix(cron): clear payload model overrides`. Release provenance: v2026.6.10 contains the same behavior.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'Codex review notes: reviewed against c5d34c8376f8aa32744786cae0473c60e39ef444.',
        created_at: '2026-06-27T09:05:25Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'Fixed by commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.',
        created_at: '2026-06-27T09:06:25Z',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'Fixed on main in https://github.com/openclaw/openclaw/commit/dfb44912ed285a0163c576c727632d00cfdf39f3.',
        created_at: '2026-06-27T09:07:25Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'This traces the root cause to https://github.com/openclaw/openclaw/commit/ab0a633ab98b4676370eec31eee57d2fbe163647.',
        created_at: '2026-06-27T09:08:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
    ]);

    assert.deepEqual(mentions, [
      {
        issueNumber: 97222,
        commitOid: 'ab0a633ab98b4676370eec31eee57d2fbe163647',
        referencedAt: '2026-06-27T09:08:25Z',
        sourceIssueNumber: 97222,
        snippet: 'This traces the root cause to https://github.com/openclaw/openclaw/commit/ab0a633ab98b4676370eec31eee57d2fbe163647.',
        source: 'ClosureComment.fixProof',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 97222,
        commitOid: 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
        referencedAt: '2026-06-27T09:04:25Z',
        sourceIssueNumber: 97222,
        snippet: 'Fix provenance: Commit `cfeaf6897fd89201b71ff7d5285e48c5a382ac9a` is titled `fix(cron): clear payload model overrides`. Release provenance: v2026.6.10 contains the same behavior.',
        source: 'ClosureComment.fixProof',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 97222,
        commitOid: 'dfb44912ed285a0163c576c727632d00cfdf39f3',
        referencedAt: '2026-06-27T09:07:25Z',
        sourceIssueNumber: 97222,
        snippet: 'Fixed on main in https://github.com/openclaw/openclaw/commit/dfb44912ed285a0163c576c727632d00cfdf39f3.',
        source: 'ClosureComment.fixProof',
        author: 'maintainer',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
    ]);
  });

  it('does not extract fix proof from keep-open review comments', () => {
    const comments = [{
      body: 'Codex review: keeping this open for maintainer follow-up. Keep open: current main and v2026.6.6 still lack the requested guard. Release provenance: v2026.6.6 commit 8c802aa683510c7f7503597b54c3021733245e59 is not sufficient.',
      created_at: '2026-06-15T16:31:00Z',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
    }];

    assert.deepEqual(__githubTest.closureCommentCommitMentions(92315, comments), []);
    assert.deepEqual(__githubTest.closureCommentPrMentions(92315, comments), []);
  });

  it('does not accept abbreviated commit hashes as closure proof without resolution', () => {
    const mentions = __githubTest.closureCommentCommitMentions(97222, [
      {
        body: 'Fixed by commit cfeaf6897fd8.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
    ]);

    assert.deepEqual(mentions, []);
  });

  it('accepts abbreviated commit hashes only after resolver expansion', () => {
    const full = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const mentions = __githubTest.closureCommentCommitMentions(97222, [
      {
        body: 'Fixed by commit cfeaf6897fd8.',
        created_at: '2026-06-27T09:04:25Z',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
    ], 97222, (prefix) => prefix === 'cfeaf6897fd8' ? full : null);

    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].commitOid, full);
    assert.equal(mentions[0].source, 'ClosureComment.fixProof');
  });

  it('resolves fixed-on-current-main short SHA closure proof', () => {
    const full = 'd05e4a4bc6f22aaaa17ca566568556d46a67dee9';
    const mentions = __githubTest.closureCommentCommitMentions(88712, [
      {
        body: 'Fixed on current `main` by `d05e4a4bc6` / #88698-era gateway channel runtime follow-up.',
        created_at: '2026-05-31T18:03:10Z',
        user: { login: 'steipete' },
        author_association: 'MEMBER',
      },
    ], 88712, (prefix) => prefix === 'd05e4a4bc6' ? full : null);

    assert.equal(mentions.length, 1);
    assert.equal(mentions[0].commitOid, full);
    assert.equal(mentions[0].author, 'steipete');
  });

  it('identifies missing issue aliases in GraphQL partial-error messages', () => {
    const indexes = __githubTest.missingIssueIndexesFromGraphqlError(
      new Error('GitHub GraphQL error: NOT_FOUND repository.issue21 Could not resolve to an Issue with the number of 95854.'),
    );

    assert.deepEqual(indexes, [21]);
  });

  it('marks missing issue aliases done during partial-error recovery', () => {
    const done = new Set<number>();
    const missing: Array<{ issueNumber: number; aliasIndex: number }> = [];
    const skipped = __githubTest.skipMissingIssueAliases(
      new Error('GitHub GraphQL error: NOT_FOUND repository.issue1 Could not resolve to an Issue with the number of 95854.'),
      [100, 200, 300],
      done,
      (event: { issueNumber: number; aliasIndex: number }) => missing.push(event),
    );

    assert.equal(skipped, 1);
    assert.deepEqual([...done], [200]);
    assert.deepEqual(missing, [{ issueNumber: 200, aliasIndex: 1 }]);
  });

  it('classifies transient GraphQL errors as retryable without retrying missing aliases', () => {
    assert.equal(__githubTest.shouldRetryGraphqlErrors([{
      type: 'RATE_LIMITED',
      message: 'You have exceeded a secondary rate limit. Please wait a few minutes before you try again.',
      path: ['repository', 'issues'],
    }]), true);
    assert.equal(__githubTest.shouldRetryGraphqlErrors([{
      type: 'INTERNAL',
      message: 'Something went wrong while executing your query. Please retry.',
    }]), true);
    assert.equal(__githubTest.shouldRetryGraphqlErrors([{
      type: 'NOT_FOUND',
      message: 'Could not resolve to an Issue with the number of 95854.',
      path: ['repository', 'issue1'],
    }]), false);
    assert.equal(__githubTest.shouldRetryGraphqlErrors([
      {
        type: 'RATE_LIMITED',
        message: 'You have exceeded a secondary rate limit.',
      },
      {
        type: 'NOT_FOUND',
        message: 'Could not resolve to an Issue with the number of 95854.',
        path: ['repository', 'issue1'],
      },
    ]), false);
  });

  it('builds one GraphQL query with aliased pull request fix lookups', () => {
    const query = __githubTest.buildPullRequestFixesBatchQuery(2);

    assert.match(query, /\$number0: Int!/);
    assert.match(query, /\$number1: Int!/);
    assert.match(query, /pr0: pullRequest\(number: \$number0\)/);
    assert.match(query, /pr1: pullRequest\(number: \$number1\)/);
    assert.match(query, /repository \{ name nameWithOwner url owner \{ login \} \}/);
    assert.match(query, /mergeCommit \{ oid \}/);
  });

  it('paginates issue closure proof connections', () => {
    const batch = __githubTest.buildIssueFixEvidenceBatchQuery(1);
    const prRefs = __githubTest.buildIssueClosedByPrRefsQuery();
    const timeline = __githubTest.buildIssueFixTimelineQuery();

    assert.match(batch, /closedByPullRequestsReferences\(first: 100, includeClosedPrs: true\)/);
    assert.match(batch, /repository \{ name nameWithOwner url owner \{ login \} \}/);
    assert.match(batch, /timelineItems\(first: 100, itemTypes: \[CLOSED_EVENT, REOPENED_EVENT, CROSS_REFERENCED_EVENT, REFERENCED_EVENT\]\)/);
    assert.match(batch, /\.\.\. on ReopenedEvent \{\s*id createdAt actor \{ login \}\s*\}/);
    assert.match(batch, /\.\.\. on ReferencedEvent \{\s*id createdAt isCrossRepository isDirectReference actor \{ login \}/);
    assert.match(batch, /commit \{ oid committedDate url messageHeadline \}/);
    assert.match(batch, /commitRepository \{\s*name\s*nameWithOwner\s*owner \{ login \}\s*\}/);
    assert.match(batch, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(prRefs, /closedByPullRequestsReferences\(first: 100, after: \$after, includeClosedPrs: true\)/);
    assert.match(prRefs, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(timeline, /timelineItems\(first: 100, after: \$after, itemTypes: \[CLOSED_EVENT, REOPENED_EVENT, CROSS_REFERENCED_EVENT, REFERENCED_EVENT\]\)/);
    assert.match(timeline, /\.\.\. on ReopenedEvent \{\s*id createdAt actor \{ login \}\s*\}/);
    assert.match(timeline, /\.\.\. on ReferencedEvent \{\s*id createdAt isCrossRepository isDirectReference actor \{ login \}/);
    assert.match(timeline, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('paginates release status check contexts', () => {
    const query = __githubTest.buildReleaseCommitQuery();

    assert.match(query, /\$after: String/);
    assert.match(query, /contexts\(first: 100, after: \$after\)/);
    assert.match(query, /totalCount/);
    assert.match(query, /pageInfo \{ hasNextPage endCursor \}/);
  });

  it('groups active security vulnerability nodes by advisory', () => {
    const advisories = __githubTest.mapSecurityVulnerabilities([
      {
        vulnerableVersionRange: '< 2026.5.2',
        firstPatchedVersion: { identifier: '2026.5.2' },
        package: { ecosystem: 'NPM', name: 'openclaw' },
        advisory: {
          ghsaId: 'GHSA-live',
          identifiers: [
            { type: 'GHSA', value: 'GHSA-live' },
            { type: 'CVE', value: 'CVE-2026-0001' },
          ],
          summary: 'Live advisory',
          severity: 'MODERATE',
          publishedAt: '2026-06-18T20:44:06Z',
          permalink: 'https://github.com/advisories/GHSA-live',
          withdrawnAt: null,
        },
      },
      {
        vulnerableVersionRange: '< 2026.4.1',
        firstPatchedVersion: null,
        package: { ecosystem: 'NPM', name: 'openclaw' },
        advisory: {
          ghsaId: 'GHSA-live',
          identifiers: [{ type: 'GHSA', value: 'GHSA-live' }],
          summary: 'Live advisory',
          severity: 'MODERATE',
          publishedAt: '2026-06-18T20:44:06Z',
          permalink: 'https://github.com/advisories/GHSA-live',
          withdrawnAt: null,
        },
      },
      {
        vulnerableVersionRange: '< 2026.1.1',
        firstPatchedVersion: null,
        package: { ecosystem: 'NPM', name: 'openclaw' },
        advisory: {
          ghsaId: 'GHSA-withdrawn',
          identifiers: [{ type: 'GHSA', value: 'GHSA-withdrawn' }],
          summary: 'Withdrawn advisory',
          severity: 'HIGH',
          publishedAt: '2026-06-16T00:00:00Z',
          permalink: 'https://github.com/advisories/GHSA-withdrawn',
          withdrawnAt: '2026-06-17T00:00:00Z',
        },
      },
    ]);

    assert.equal(advisories.length, 1);
    assert.equal(advisories[0].ghsa_id, 'GHSA-live');
    assert.equal(advisories[0].cve_id, 'CVE-2026-0001');
    assert.equal(advisories[0].severity, 'medium');
    assert.equal(advisories[0].vulnerabilities.length, 2);
    assert.equal(advisories[0].vulnerabilities[0].patched_versions, '2026.5.2');
    assert.equal(advisories[0].vulnerabilities[1].patched_versions, '2026.4.1');
  });
});
