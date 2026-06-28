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
    ]);

    assert.deepEqual(mentions, [
      {
        issueNumber: 9000,
        prNumber: 95532,
        referencedAt: '2026-06-24T10:00:00Z',
        author: 'clawsweeper',
        authorAssociation: 'CONTRIBUTOR',
        trustedSource: true,
      },
      {
        issueNumber: 9000,
        prNumber: 96040,
        referencedAt: '2026-06-24T13:00:00Z',
        author: 'maintainer',
        authorAssociation: 'MEMBER',
        trustedSource: true,
      },
    ]);
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
    ]);

    assert.deepEqual(mentions, [
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
    ]);
  });

  it('builds one GraphQL query with aliased pull request fix lookups', () => {
    const query = __githubTest.buildPullRequestFixesBatchQuery(2);

    assert.match(query, /\$number0: Int!/);
    assert.match(query, /\$number1: Int!/);
    assert.match(query, /pr0: pullRequest\(number: \$number0\)/);
    assert.match(query, /pr1: pullRequest\(number: \$number1\)/);
    assert.match(query, /mergeCommit \{ oid \}/);
  });

  it('paginates issue closure proof connections', () => {
    const batch = __githubTest.buildIssueFixEvidenceBatchQuery(1);
    const prRefs = __githubTest.buildIssueClosedByPrRefsQuery();
    const timeline = __githubTest.buildIssueFixTimelineQuery();

    assert.match(batch, /closedByPullRequestsReferences\(first: 100, includeClosedPrs: true\)/);
    assert.match(batch, /timelineItems\(first: 100, itemTypes: \[CLOSED_EVENT, REOPENED_EVENT, CROSS_REFERENCED_EVENT\]\)/);
    assert.match(batch, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(prRefs, /closedByPullRequestsReferences\(first: 100, after: \$after, includeClosedPrs: true\)/);
    assert.match(prRefs, /pageInfo \{ hasNextPage endCursor \}/);
    assert.match(timeline, /timelineItems\(first: 100, after: \$after, itemTypes: \[CLOSED_EVENT, REOPENED_EVENT, CROSS_REFERENCED_EVENT\]\)/);
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
