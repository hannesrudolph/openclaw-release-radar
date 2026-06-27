import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { IssueClassification } from './llm.ts';

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-${name}-`)), 'radar.db');
}

async function freshDb(name: string) {
  process.env.DB_PATH = dbPath(name);
  return import(`./db.ts?case=${name}-${Date.now()}-${Math.random()}`);
}

function classification(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affectedUsers: 'some',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.9,
    rationale: '',
    ...overrides,
  };
}

function seedRelease(db: any, tag = 'v1', publishedAt = '2026-06-01T00:00:00Z') {
  db.upsertRelease({
    tag,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/${tag}`,
    prerelease: false,
    body: '',
  });
  db.upsertReleaseCommit({
    tag,
    tag_commit_oid: `${tag}-commit`,
    committed_at: publishedAt,
  });
}

function seedIssue(
  db: any,
  number: number,
  closedAt: string | null = '2026-06-02T00:00:00Z',
  createdAt = '2026-06-01T12:00:00Z',
) {
  db.upsertIssue({
    number,
    state: closedAt ? 'closed' : 'open',
    title: `issue ${number}`,
    author: 'tester',
    html_url: `https://example.test/issues/${number}`,
    created_at: createdAt,
    updated_at: closedAt ?? createdAt,
    closed_at: closedAt,
    comments: 0,
    labels: '[]',
    is_bot: 0,
  });
  db.upsertClassification(number, classification(), closedAt ?? createdAt, 1);
}

function seedPr(db: any, pr: number, merged = true) {
  db.upsertPullRequestFix({
    pr_number: pr,
    title: `PR ${pr}`,
    url: `https://example.test/pull/${pr}`,
    state: 'MERGED',
    merged: merged ? 1 : 0,
    merged_at: merged ? '2026-05-31T00:00:00Z' : null,
    merge_commit_oid: `merge-${pr}`,
    base_ref_name: 'main',
  });
}

function seedClosure(db: any, issue: number, reason = 'COMPLETED', closedAt = '2026-06-02T00:00:00Z') {
  db.upsertIssueClosureEvent({
    issue_number: issue,
    event_id: `closed-${issue}`,
    closed_at: closedAt,
    actor_login: 'maintainer',
    state_reason: reason,
    closer_type: null,
    closer_number: null,
    closer_oid: null,
    raw_json: '{}',
  });
}

describe('release fix provenance', () => {
  it('round-trips issue community signal columns through issue and release views', async () => {
    const db = await freshDb('issue-community');
    seedRelease(db, 'v1');
    db.upsertIssue({
      number: 9001,
      state: 'open',
      title: 'community-backed issue',
      author: 'reporter',
      author_association: 'NONE',
      html_url: 'https://example.test/issues/9001',
      created_at: '2026-06-01T12:00:00Z',
      updated_at: '2026-06-02T12:00:00Z',
      closed_at: null,
      comments: 12,
      unique_human_commenters: 4,
      maintainer_commenters: 1,
      contributor_commenters: 2,
      commenter_scan_truncated: 1,
      reaction_total: 9,
      positive_reactions: 7,
      labels: '["bug"]',
      is_bot: 0,
    });
    db.upsertClassification(9001, classification(), '2026-06-02T12:00:00Z', 1);

    const issue = db.getIssue(9001) as any;
    assert.equal(issue.author_association, 'NONE');
    assert.equal(issue.unique_human_commenters, 4);
    assert.equal(issue.maintainer_commenters, 1);
    assert.equal(issue.contributor_commenters, 2);
    assert.equal(issue.commenter_scan_truncated, 1);
    assert.equal(issue.reaction_total, 9);
    assert.equal(issue.positive_reactions, 7);

    const releaseIssue = db.issuesForVersion('v1').find((row: any) => row.number === 9001);
    assert.equal(releaseIssue?.unique_human_commenters, 4);
    assert.equal(releaseIssue?.positive_reactions, 7);
  });

  it('stores reachability per tag and updates by tag/pr', async () => {
    const db = await freshDb('reachability');
    seedRelease(db, 'v1');
    seedRelease(db, 'v2', '2026-06-03T00:00:00Z');

    db.upsertReleasePrReachability({
      tag: 'v1',
      pr_number: 10,
      tag_commit_oid: 'v1-commit',
      merge_commit_oid: 'merge-10',
      base_ref_name: 'main',
      status: 'unknown',
      evidence_json: '{"first":true}',
    });
    db.upsertReleasePrReachability({
      tag: 'v2',
      pr_number: 10,
      tag_commit_oid: 'v2-commit',
      merge_commit_oid: 'merge-10',
      base_ref_name: 'main',
      status: 'not_reachable',
      evidence_json: '{}',
    });
    db.upsertReleasePrReachability({
      tag: 'v1',
      pr_number: 10,
      tag_commit_oid: 'v1-commit',
      merge_commit_oid: 'merge-10',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{"updated":true}',
    });

    const rows = db.db.prepare(`
      SELECT tag, pr_number, status, method, evidence_json
      FROM release_pr_reachability
      ORDER BY tag
    `).all().map((row: any) => ({ ...row }));
    assert.deepEqual(rows, [
      { tag: 'v1', pr_number: 10, status: 'reachable', method: 'git-merge-base', evidence_json: '{"updated":true}' },
      { tag: 'v2', pr_number: 10, status: 'not_reachable', method: 'git-merge-base', evidence_json: '{}' },
    ]);
  });

  it('stores release check rollup evidence with the release commit', async () => {
    const db = await freshDb('release-checks');
    seedRelease(db, 'v1');

    db.upsertReleaseCommit({
      tag: 'v1',
      tag_commit_oid: 'commit-1',
      committed_at: '2026-06-01T00:00:00Z',
      check_state: 'SUCCESS',
      check_total: 4,
      check_success: 3,
      check_failure: 0,
      check_pending: 0,
      check_skipped: 1,
      check_contexts_json: '[{"name":"build","conclusion":"SUCCESS"}]',
    });

    const row = db.getReleaseCommit('v1') as any;
    assert.equal(row.check_state, 'SUCCESS');
    assert.equal(row.check_total, 4);
    assert.equal(row.check_success, 3);
    assert.equal(row.check_skipped, 1);
    assert.equal(row.check_contexts_json, '[{"name":"build","conclusion":"SUCCESS"}]');
  });

  it('reconstructs issue labels at a cutoff from label timeline events', async () => {
    const db = await freshDb('label-events');
    seedRelease(db, 'v1');
    seedIssue(db, 7101, null);

    db.upsertIssueLabelEvent({
      issue_number: 7101,
      event_id: 'label-1',
      action: 'labeled',
      label_name: 'bug',
      actor_login: 'reporter',
      created_at: '2026-06-01T13:00:00Z',
    });
    db.upsertIssueLabelEvent({
      issue_number: 7101,
      event_id: 'label-2',
      action: 'labeled',
      label_name: 'P1',
      actor_login: 'maintainer',
      created_at: '2026-06-02T00:00:00Z',
    });
    db.upsertIssueLabelEvent({
      issue_number: 7101,
      event_id: 'label-3',
      action: 'unlabeled',
      label_name: 'P1',
      actor_login: 'maintainer',
      created_at: '2026-06-03T00:00:00Z',
    });

    assert.deepEqual(db.labelsForIssueAt(7101, ['fallback'], '2026-06-01T14:00:00Z'), ['bug']);
    assert.deepEqual(db.labelsForIssueAt(7101, ['fallback'], '2026-06-02T12:00:00Z').sort(), ['P1', 'bug']);
    assert.deepEqual(db.labelsForIssueAt(7101, ['fallback'], '2026-06-04T00:00:00Z'), ['bug']);
    assert.deepEqual(db.labelsForIssueAt(9999, ['fallback'], '2026-06-04T00:00:00Z'), ['fallback']);
  });

  it('counts only completed issues fixed by merged reachable PRs', async () => {
    const db = await freshDb('verified-fixed');
    seedRelease(db, 'v1');

    for (const n of [1, 2, 3, 4]) seedIssue(db, n);
    for (const n of [1, 2, 3]) seedClosure(db, n);
    seedClosure(db, 4, 'NOT_PLANNED');
    seedPr(db, 101, true);
    seedPr(db, 102, true);
    seedPr(db, 103, false);

    for (const [issue, pr, status] of [
      [1, 101, 'reachable'],
      [2, 102, 'not_reachable'],
      [3, 103, 'reachable'],
      [4, 101, 'reachable'],
    ] as const) {
      db.upsertIssuePrLink({
        issue_number: issue,
        pr_number: pr,
        source: 'closedByPullRequestsReferences',
        will_close_target: 1,
        referenced_at: '2026-06-02T00:00:00Z',
      });
      db.upsertReleasePrReachability({
        tag: 'v1',
        pr_number: pr,
        tag_commit_oid: 'v1-commit',
        merge_commit_oid: `merge-${pr}`,
        base_ref_name: 'main',
        status,
        evidence_json: '{}',
      });
    }

    assert.deepEqual(db.verifiedFixedForRelease('v1').map((row: any) => row.number), [1]);
  });

  it('keeps unverified closures visible but excludes verified fixes', async () => {
    const db = await freshDb('unverified-closed');
    seedRelease(db, 'v3', '2026-07-01T00:00:00Z');
    seedRelease(db, 'v4', '2026-07-05T00:00:00Z');

    for (const n of [301, 302, 303, 304]) seedIssue(db, n, '2026-07-02T00:00:00Z', '2026-07-01T12:00:00Z');
    for (const n of [301, 302, 303, 304]) seedClosure(db, n, 'COMPLETED', '2026-07-02T00:00:00Z');
    seedIssue(db, 305, '2026-06-30T00:00:00Z', '2026-06-29T12:00:00Z');
    seedIssue(db, 306, '2026-07-06T00:00:00Z', '2026-07-05T12:00:00Z');
    seedClosure(db, 305, 'COMPLETED', '2026-06-30T00:00:00Z');
    seedClosure(db, 306, 'COMPLETED', '2026-07-06T00:00:00Z');
    seedPr(db, 201, true);
    seedPr(db, 202, true);

    db.upsertIssuePrLink({ issue_number: 301, pr_number: 201, source: 'closedByPullRequestsReferences', will_close_target: 1, referenced_at: null });
    db.upsertReleasePrReachability({ tag: 'v3', pr_number: 201, tag_commit_oid: 'v3-commit', merge_commit_oid: 'merge-201', base_ref_name: 'main', status: 'reachable', evidence_json: '{}' });
    db.upsertIssuePrLink({ issue_number: 302, pr_number: 202, source: 'closedByPullRequestsReferences', will_close_target: 1, referenced_at: null });
    db.upsertReleasePrReachability({ tag: 'v3', pr_number: 202, tag_commit_oid: 'v3-commit', merge_commit_oid: 'merge-202', base_ref_name: 'main', status: 'not_reachable', evidence_json: '{}' });

    assert.deepEqual(db.verifiedFixedForRelease('v3').map((row: any) => row.number), [301]);
    assert.deepEqual(db.unverifiedClosedForRelease('v3').map((row: any) => row.number).sort((a: number, b: number) => a - b), [302, 303, 304]);
  });
});
