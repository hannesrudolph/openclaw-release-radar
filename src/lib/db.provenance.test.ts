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

function seedRelease(db: any, tag = 'v1', publishedAt = '2026-06-01T00:00:00Z', prerelease = false) {
  db.upsertRelease({
    tag,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/${tag}`,
    prerelease,
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
  it('uses the next stable release, not prereleases, for issue attribution windows', async () => {
    const db = await freshDb('stable-attribution-window');
    seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
    seedRelease(db, 'v1-beta', '2026-06-02T00:00:00Z', true);
    seedRelease(db, 'v2', '2026-06-03T00:00:00Z');
    seedIssue(db, 7001, null, '2026-06-02T12:00:00Z');

    assert.ok(db.issuesForVersion('v1').some((row: any) => row.number === 7001));
    assert.equal(db.issueCountForVersion('v1'), 1);
  });

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
      pr_number: 11,
      tag_commit_oid: null,
      merge_commit_oid: null,
      base_ref_name: 'main',
      status: 'unknown',
      evidence_json: '{"missing":true}',
    });
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
      SELECT tag, pr_number, tag_commit_oid, merge_commit_oid, status, method, evidence_json
      FROM release_pr_reachability
      ORDER BY tag, pr_number
    `).all().map((row: any) => ({ ...row }));
    assert.deepEqual(rows, [
      { tag: 'v1', pr_number: 10, tag_commit_oid: 'v1-commit', merge_commit_oid: 'merge-10', status: 'reachable', method: 'git-merge-base', evidence_json: '{"updated":true}' },
      { tag: 'v1', pr_number: 11, tag_commit_oid: null, merge_commit_oid: null, status: 'unknown', method: 'git-merge-base', evidence_json: '{"missing":true}' },
      { tag: 'v2', pr_number: 10, tag_commit_oid: 'v2-commit', merge_commit_oid: 'merge-10', status: 'not_reachable', method: 'git-merge-base', evidence_json: '{}' },
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

  it('stores release artifact metadata and registry verification', async () => {
    const db = await freshDb('release-artifacts');
    seedRelease(db, 'v1');

    db.updateReleaseDerivedStats({
      tag: 'v1',
      breaking_count: 0,
      fixes_count: 0,
      changes_count: 0,
      highlights_count: 0,
      pr_refs_count: 0,
      beta_count: 0,
      hours_to_next_release: null,
      hours_to_next_stable: null,
      npm_package_url: 'https://www.npmjs.com/package/openclaw/v/1.0.0',
      release_tarball_url: 'https://registry.npmjs.org/openclaw/-/openclaw-1.0.0.tgz',
      release_integrity: 'sha512-test',
      release_sha: 'commit-1',
      full_release_ci_report_url: 'https://example.test/report.md',
    });
    db.updateReleaseArtifactVerification({
      tag: 'v1',
      registry_version: '1.0.0',
      registry_integrity: 'sha512-test',
      registry_tarball_url: 'https://registry.npmjs.org/openclaw/-/openclaw-1.0.0.tgz',
      ci_report_verified: 1,
      ci_report_mismatch: null,
      artifact_verified: 1,
      artifact_mismatch: null,
    });

    const row = db.getRelease('v1') as any;
    assert.equal(row.release_integrity, 'sha512-test');
    assert.equal(row.release_sha, 'commit-1');
    assert.equal(row.registry_version, '1.0.0');
    assert.equal(row.registry_integrity, 'sha512-test');
    assert.equal(row.ci_report_verified, 1);
    assert.equal(row.artifact_verified, 1);
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
    assert.deepEqual(
      db.labelsForIssueAt(9999, ['fallback'], '2026-06-04T00:00:00Z', { useFallbackWhenNoEvents: false }),
      [],
    );
  });

  it('counts only completed issues fixed by merged reachable PRs or proof rows', async () => {
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

  it('credits completed closures with reachable commit proof rows', async () => {
    const db = await freshDb('verified-commit-proof');
    seedRelease(db, 'v-commit', '2027-01-01T00:00:00Z');
    seedIssue(db, 5, '2027-01-02T00:00:00Z', '2027-01-01T12:00:00Z');
    seedClosure(db, 5, 'COMPLETED', '2027-01-02T00:00:00Z');
    db.upsertIssueClosureProof({
      release_tag: 'v-commit',
      issue_number: 5,
      status: 'fixed_in_release',
      summary: 'Closed by a fix/source commit reachable from this release tag.',
      evidence_json: JSON.stringify({
        stateReasons: ['COMPLETED'],
        hasReachableFixCommit: true,
        reachableFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
      }),
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-commit').map((row: any) => row.number), [5]);
    assert.deepEqual(db.unverifiedClosedForRelease('v-commit').map((row: any) => row.number), []);
  });

  it('does not carry reachable fix credit across release windows', async () => {
    const db = await freshDb('verified-window');
    seedRelease(db, 'v-old', '2026-06-01T00:00:00Z');
    seedRelease(db, 'v-new', '2026-06-10T00:00:00Z');
    seedIssue(db, 41, '2026-06-11T00:00:00Z', '2026-06-10T12:00:00Z');
    seedClosure(db, 41, 'COMPLETED', '2026-06-11T00:00:00Z');
    seedPr(db, 241, true);
    db.upsertIssuePrLink({
      issue_number: 41,
      pr_number: 241,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-06-11T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-old',
      pr_number: 241,
      tag_commit_oid: 'v-old-commit',
      merge_commit_oid: 'merge-241',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });
    db.upsertReleasePrReachability({
      tag: 'v-new',
      pr_number: 241,
      tag_commit_oid: 'v-new-commit',
      merge_commit_oid: 'merge-241',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-old').map((row: any) => row.number), []);
    assert.deepEqual(db.verifiedFixedForRelease('v-new').map((row: any) => row.number), [41]);
  });

  it('does not count neutral completed closures as stability fix credit', async () => {
    const db = await freshDb('neutral-fix-credit');
    seedRelease(db, 'v-neutral', '2026-10-01T00:00:00Z');
    seedIssue(db, 51, '2026-10-02T00:00:00Z', '2026-10-01T12:00:00Z');
    db.upsertClassification(51, classification({ sentiment: 'neutral', severity: 'low' }), '2026-10-02T00:00:00Z', 1);
    seedClosure(db, 51, 'COMPLETED', '2026-10-02T00:00:00Z');
    seedPr(db, 251, true);
    db.upsertIssuePrLink({
      issue_number: 51,
      pr_number: 251,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-10-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-neutral',
      pr_number: 251,
      tag_commit_oid: 'v-neutral-commit',
      merge_commit_oid: 'merge-251',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-neutral').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-neutral').map((row: any) => row.number), [51]);
  });

  it('credits closure-comment fix proof only when merged and reachable', async () => {
    const db = await freshDb('comment-mentioned-pr');
    seedRelease(db, 'v-comment');

    for (const n of [11, 12, 13, 14]) seedIssue(db, n);
    for (const n of [11, 12, 13]) seedClosure(db, n);
    seedClosure(db, 14, 'NOT_PLANNED');
    seedPr(db, 211, true);
    seedPr(db, 212, true);
    seedPr(db, 213, false);
    seedPr(db, 214, true);

    for (const [issue, pr, status] of [
      [11, 211, 'reachable'],
      [12, 212, 'not_reachable'],
      [13, 213, 'reachable'],
      [14, 214, 'reachable'],
    ] as const) {
      db.upsertIssuePrLink({
        issue_number: issue,
        pr_number: pr,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-06-02T00:00:00Z',
      });
      db.upsertReleasePrReachability({
        tag: 'v-comment',
        pr_number: pr,
        tag_commit_oid: 'v-comment-commit',
        merge_commit_oid: `merge-${pr}`,
        base_ref_name: 'main',
        status,
        evidence_json: '{}',
      });
    }

    assert.deepEqual(db.verifiedFixedForRelease('v-comment').map((row: any) => row.number), [11]);
  });

  it('does not credit broad closure-comment PR mentions as fix proof', async () => {
    const db = await freshDb('comment-pr-reference');
    seedRelease(db, 'v-reference', '2026-08-01T00:00:00Z');
    seedIssue(db, 21, '2026-08-02T00:00:00Z', '2026-08-01T12:00:00Z');
    seedClosure(db, 21, 'COMPLETED', '2026-08-02T00:00:00Z');
    seedPr(db, 221, true);
    db.upsertIssuePrLink({
      issue_number: 21,
      pr_number: 221,
      source: 'ClosureComment.prMention',
      will_close_target: null,
      referenced_at: '2026-06-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-reference',
      pr_number: 221,
      tag_commit_oid: 'v-reference-commit',
      merge_commit_oid: 'merge-221',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-reference').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-reference').map((row: any) => row.number), [21]);
  });

  it('uses the final closure event for fix credit', async () => {
    const db = await freshDb('final-closure');
    seedRelease(db, 'v-final', '2026-09-01T00:00:00Z');
    seedIssue(db, 31, '2026-09-03T00:00:00Z', '2026-09-01T12:00:00Z');
    seedPr(db, 231, true);
    db.upsertIssueClosureEvent({
      issue_number: 31,
      event_id: 'closed-31-first',
      closed_at: '2026-09-02T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    db.upsertIssueClosureEvent({
      issue_number: 31,
      event_id: 'closed-31-final',
      closed_at: '2026-09-03T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'NOT_PLANNED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    db.upsertIssuePrLink({
      issue_number: 31,
      pr_number: 231,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-09-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-final',
      pr_number: 231,
      tag_commit_oid: 'v-final-commit',
      merge_commit_oid: 'merge-231',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-final').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-final').map((row: any) => row.number), [31]);
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
