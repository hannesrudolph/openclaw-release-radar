import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { IssueClassification } from './llm.ts';
import { ReleaseAuditReader } from '../../scripts/lib/release-audit-reader.mjs';

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-${name}-`)), 'radar.db');
}

async function freshDb(name: string) {
  return (await freshDbWithPath(name)).db;
}

async function freshDbWithPath(name: string) {
  const path = dbPath(name);
  process.env.DB_PATH = path;
  const db = await import(`./db.ts?case=${name}-${Date.now()}-${Math.random()}`);
  return { db, path };
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

function seedReopen(db: any, issue: number, reopenedAt = '2026-06-02T12:00:00Z') {
  db.upsertIssueReopenEvent({
    issue_number: issue,
    event_id: `reopened-${issue}-${reopenedAt}`,
    reopened_at: reopenedAt,
    actor_login: 'maintainer',
    raw_json: '{}',
  });
}

describe('release fix provenance', () => {
  it('tracks release-row source freshness for score-affecting metadata', async () => {
    const db = await freshDb('release-row-freshness');
    seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
    db.updateReleaseDerivedStats({
      tag: 'v1',
      breaking_count: 1,
      fixes_count: 2,
      changes_count: 3,
      highlights_count: 4,
      pr_refs_count: 5,
      beta_count: 0,
      hours_to_next_release: null,
      hours_to_next_stable: null,
      npm_package_url: 'https://example.test/pkg',
      release_tarball_url: 'https://example.test/tarball',
      release_integrity: 'sha512-test',
      release_sha: 'sha-test',
      full_release_ci_report_url: 'https://example.test/ci',
      full_release_validation_url: 'https://example.test/validation',
    });
    db.updateReleaseArtifactVerification({
      tag: 'v1',
      registry_version: '1.0.0',
      registry_integrity: 'sha512-registry',
      registry_tarball_url: 'https://example.test/registry.tgz',
      ci_report_verified: 1,
      ci_report_mismatch: null,
      release_validation_verified: 1,
      release_validation_mismatch: null,
      artifact_verified: 1,
      artifact_mismatch: null,
    });

    const release = db.getRelease('v1');
    assert.ok(release);
    assert.ok(Date.parse(String(release.release_metadata_fetched_at)));
    assert.ok(Date.parse(String(release.release_derived_fetched_at)));
    assert.ok(Date.parse(String(release.release_artifact_checked_at)));

    const releaseMetadata = db.releaseDataFreshness('v1').sources.find((source: any) => source.source === 'release_metadata');
    assert.ok(releaseMetadata);
    assert.ok(Date.parse(String(releaseMetadata.maxAt)));
    assert.ok(db.dataFreshnessCacheDigest().count > 0);
  });

  it('tracks local issue fetch freshness separately from GitHub issue updated_at', async () => {
    const db = await freshDb('issue-fetch-freshness');
    seedRelease(db, 'v-fetch', '2036-06-01T00:00:00Z');
    seedIssue(db, 6101, null, '2036-06-01T12:00:00Z');

    const issue = db.getIssue(6101);
    assert.ok(issue);
    assert.ok(Date.parse(String(issue.fetched_at)));

    const freshness = db.releaseDataFreshness('v-fetch');
    const issueRows = freshness.sources.find((source: any) => source.source === 'issue_rows');
    const issueFetches = freshness.sources.find((source: any) => source.source === 'issue_fetches');
    assert.ok(issueRows);
    assert.ok(issueFetches);
    assert.equal(issueRows.maxAt, '2036-06-01T12:00:00Z');
    assert.ok(Date.parse(String(issueFetches.maxAt)));
    assert.notEqual(issueFetches.maxAt, issueRows.maxAt);
    assert.ok(db.dataFreshnessCacheDigest().digest);
  });

  it('uses the next stable release, not prereleases, for issue attribution windows', async () => {
    const db = await freshDb('stable-attribution-window');
    seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
    seedRelease(db, 'v1-beta', '2026-06-02T00:00:00Z', true);
    seedRelease(db, 'v2', '2026-06-03T00:00:00Z');
    seedIssue(db, 7001, null, '2026-06-02T12:00:00Z');

    assert.ok(db.issuesForVersion('v1').some((row: any) => row.number === 7001));
    assert.equal(db.issueCountForVersion('v1'), 1);
  });

  it('does not attribute issues closed before a release until a reopen interval overlaps it', async () => {
    const db = await freshDb('reopen-interval-attribution');
    seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
    seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
    seedIssue(db, 7002, '2026-06-15T00:00:00Z', '2026-05-01T00:00:00Z');
    seedClosure(db, 7002, 'COMPLETED', '2026-05-02T00:00:00Z');
    seedReopen(db, 7002, '2026-06-12T00:00:00Z');
    db.upsertIssueClosureEvent({
      issue_number: 7002,
      event_id: 'closed-7002-final',
      closed_at: '2026-06-15T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });

    assert.ok(!db.issuesForVersion('v1').some((row: any) => row.number === 7002));
    assert.ok(db.issuesForVersion('v2').some((row: any) => row.number === 7002));
  });

  it('uses open intervals for audit source freshness issue universes', async () => {
    const db = await freshDb('source-freshness-reopen-interval');
    seedRelease(db, 'v-source-old', '2026-06-01T00:00:00Z');
    seedRelease(db, 'v-source-new', '2026-06-10T00:00:00Z');
    seedIssue(db, 7011, null, '2026-06-09T00:00:00Z');
    seedIssue(db, 7012, '2026-06-15T00:00:00Z', '2026-05-01T00:00:00Z');
    seedClosure(db, 7012, 'COMPLETED', '2026-05-02T00:00:00Z');
    seedReopen(db, 7012, '2026-06-12T00:00:00Z');
    db.upsertIssue({
      ...(db.getIssue(7012) as any),
      updated_at: '2026-06-15T00:00:00Z',
      closed_at: '2026-06-15T00:00:00Z',
    });
    db.upsertClassification(7012, classification(), '2026-06-15T00:00:00Z', 1);

    const reader = new ReleaseAuditReader(db.db);
    const oldIssueRows = reader.sourceFreshnessFor('v-source-old').find((row: any) => row.source === 'issue_rows');
    const newIssueRows = reader.sourceFreshnessFor('v-source-new').find((row: any) => row.source === 'issue_rows');
    assert.equal(oldIssueRows.max_ts, '2026-06-09T00:00:00Z');
    assert.equal(newIssueRows.max_ts, '2026-06-15T00:00:00Z');
  });

  it('falls back to issue closed_at when closure timeline events are missing', async () => {
    const db = await freshDb('interval-fallback');
    seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
    seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
    seedIssue(db, 7003, '2026-06-02T00:00:00Z', '2026-05-01T00:00:00Z');

    assert.ok(db.issuesForVersion('v1').some((row: any) => row.number === 7003));
    assert.ok(!db.issuesForVersion('v2').some((row: any) => row.number === 7003));
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

  it('score audit freshness digest changes when audit payload changes', async () => {
    const db = await freshDb('score-audit-freshness');
    const audit = {
      release_tag: 'v1',
      scored_at: '2026-06-02T00:00:00Z',
      score_model_version: 'test-model',
      prompt_version: 1,
      final_score: 7.5,
      status: 'eligible',
      band: 'ok',
      recommended: 1,
      input_json: '{"rawIssueCount":1}',
      components_json: '{"components":{}}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{"a":1}',
    };
    db.upsertReleaseScoreAudit(audit);
    const first = db.releaseScoreAuditFreshness();
    db.upsertReleaseScoreAudit({
      ...audit,
      gate_evidence_json: '{"a":2}',
    });
    const second = db.releaseScoreAuditFreshness();

    assert.ok(first.count >= 1);
    assert.equal(second.count, first.count);
    assert.equal(first.max_scored_at, audit.scored_at);
    assert.equal(second.max_scored_at, audit.scored_at);
    assert.notEqual(first.digest, second.digest);
  });

  it('public release row freshness digest changes when emitted score fields change', async () => {
    const db = await freshDb('public-release-row-freshness');
    seedRelease(db, 'v1');
    const score = {
      tag: 'v1',
      final_score: 7.5,
      negative_issues: 1,
      positive_issues: 0,
      state: 'eligible',
      recommended: 1,
      score_reason: 'first reason',
      broken_surfaces: '[]',
      closed_serious_fixed: 0,
      opened_serious_during_reign: 1,
      scored_at: '2026-06-02T00:00:00Z',
    };
    db.updateReleaseScore(score);
    const first = db.publicReleaseRowsFreshness(10);
    db.updateReleaseScore({
      ...score,
      score_reason: 'second reason',
    });
    const second = db.publicReleaseRowsFreshness(10);

    assert.ok(first.count >= 1);
    assert.equal(second.count, first.count);
    assert.equal(first.max_scored_at, score.scored_at);
    assert.equal(second.max_scored_at, score.scored_at);
    assert.notEqual(first.digest, second.digest);
  });

  it('public issue summary freshness digest changes when emitted issue fields change', async () => {
    const db = await freshDb('public-issue-summary-freshness');
    seedRelease(db, 'v1');
    seedIssue(db, 9101, null, '2026-06-01T12:00:00Z');

    const first = db.publicIssueSummaryFreshness(10);
    db.upsertIssue({
      number: 9101,
      state: 'open',
      title: 'issue 9101 updated title',
      author: 'tester',
      html_url: 'https://example.test/issues/9101',
      created_at: '2026-06-01T12:00:00Z',
      updated_at: '2026-06-01T12:00:00Z',
      closed_at: null,
      comments: 0,
      labels: '[]',
      is_bot: 0,
    });
    const second = db.publicIssueSummaryFreshness(10);

    assert.ok(first.count >= 2);
    assert.equal(second.count, first.count);
    assert.equal(second.max_ts, first.max_ts);
    assert.notEqual(first.digest, second.digest);
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
      full_release_validation_url: 'https://github.com/openclaw/openclaw/actions/runs/1',
    });
    db.updateReleaseArtifactVerification({
      tag: 'v1',
      registry_version: '1.0.0',
      registry_integrity: 'sha512-test',
      registry_tarball_url: 'https://registry.npmjs.org/openclaw/-/openclaw-1.0.0.tgz',
      ci_report_verified: 1,
      ci_report_mismatch: null,
      release_validation_verified: 1,
      release_validation_mismatch: null,
      artifact_verified: 1,
      artifact_mismatch: null,
    });

    const row = db.getRelease('v1') as any;
    assert.equal(row.release_integrity, 'sha512-test');
    assert.equal(row.release_sha, 'commit-1');
    assert.equal(row.registry_version, '1.0.0');
    assert.equal(row.registry_integrity, 'sha512-test');
    assert.equal(row.ci_report_verified, 1);
    assert.equal(row.full_release_validation_url, 'https://github.com/openclaw/openclaw/actions/runs/1');
    assert.equal(row.release_validation_verified, 1);
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

  it('uses label snapshots at cutoff when timeline events are absent', async () => {
    const db = await freshDb('label-snapshot-cutoff');
    db.upsertIssueLabelSnapshot({
      issue_number: 7201,
      snapshot_at: '2026-06-02T00:00:00Z',
      labels_json: JSON.stringify(['bug', 'P1']),
    });
    db.upsertIssueLabelSnapshot({
      issue_number: 7201,
      snapshot_at: '2026-06-03T00:00:00Z',
      labels_json: JSON.stringify(['bug']),
    });

    assert.deepEqual(
      db.labelsForIssueAt(7201, ['fallback'], '2026-06-02T12:00:00Z', {
        useFallbackWhenNoEvents: false,
        useSnapshotWhenNoEvents: true,
      }).sort(),
      ['P1', 'bug'],
    );
    assert.deepEqual(
      db.labelsForIssueAt(7201, ['fallback'], '2026-06-03T12:00:00Z', {
        useFallbackWhenNoEvents: false,
        useSnapshotWhenNoEvents: true,
      }),
      ['bug'],
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

  it('deletes stale closure-comment PR links without removing GitHub closure links', async () => {
    const db = await freshDb('stale-comment-pr-links');
    seedRelease(db, 'v-stale-comment-link');
    seedIssue(db, 61);

    for (const [source, pr] of [
      ['closedByPullRequestsReferences', 261],
      ['ClosureComment.fixProof', 262],
      ['ClosureComment.prMention', 263],
    ] as const) {
      db.upsertIssuePrLink({
        issue_number: 61,
        pr_number: pr,
        source,
        will_close_target: source === 'closedByPullRequestsReferences' ? 1 : null,
        referenced_at: '2026-06-02T00:00:00Z',
      });
    }

    db.deleteCommentIssuePrLinksForIssues([61]);

    const remaining = db.db.prepare(`
      SELECT source
      FROM issue_pr_links
      WHERE issue_number=61
      ORDER BY source
    `).all().map((row: any) => row.source);
    assert.deepEqual(remaining, ['closedByPullRequestsReferences']);
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

  it('uses the release-window closure event when later closure events exist', async () => {
    const db = await freshDb('window-closure-event');
    seedRelease(db, 'v-window-old', '2028-09-01T00:00:00Z');
    seedRelease(db, 'v-window-new', '2028-09-10T00:00:00Z');
    seedIssue(db, 32, '2028-09-02T00:00:00Z', '2028-09-01T12:00:00Z');
    seedPr(db, 232, true);
    db.upsertIssueClosureEvent({
      issue_number: 32,
      event_id: 'closed-32-window',
      closed_at: '2028-09-02T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    db.upsertIssueClosureEvent({
      issue_number: 32,
      event_id: 'closed-32-later',
      closed_at: '2028-09-12T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'NOT_PLANNED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    db.upsertIssuePrLink({
      issue_number: 32,
      pr_number: 232,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2028-09-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-window-old',
      pr_number: 232,
      tag_commit_oid: 'v-window-old-commit',
      merge_commit_oid: 'merge-232',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-window-old').map((row: any) => row.number), [32]);
    assert.deepEqual(db.unverifiedClosedForRelease('v-window-old').map((row: any) => row.number), []);
  });

  it('matches final closure events when GitHub timestamps differ by one second', async () => {
    const db = await freshDb('closure-timestamp-skew');
    seedRelease(db, 'v-skew', '2028-10-01T00:00:00Z');
    seedIssue(db, 33, '2028-10-02T00:00:00Z', '2028-10-01T12:00:00Z');
    seedIssue(db, 34, '2028-10-02T00:00:00Z', '2028-10-01T12:00:00Z');
    seedPr(db, 233, true);
    seedPr(db, 234, true);
    db.upsertIssueClosureEvent({
      issue_number: 33,
      event_id: 'closed-33-skew',
      closed_at: '2028-10-02T00:00:01Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: 'PullRequest',
      closer_number: 233,
      closer_oid: 'merge-233',
      raw_json: '{}',
    });
    db.upsertIssueClosureEvent({
      issue_number: 34,
      event_id: 'closed-34-real-mismatch',
      closed_at: '2028-10-02T00:00:03Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: 'PullRequest',
      closer_number: 234,
      closer_oid: 'merge-234',
      raw_json: '{}',
    });
    for (const [issue, pr] of [[33, 233], [34, 234]] as const) {
      db.upsertIssuePrLink({
        issue_number: issue,
        pr_number: pr,
        source: 'ClosedEvent.closer',
        will_close_target: 1,
        referenced_at: '2028-10-02T00:00:00Z',
      });
      db.upsertReleasePrReachability({
        tag: 'v-skew',
        pr_number: pr,
        tag_commit_oid: 'v-skew-commit',
        merge_commit_oid: `merge-${pr}`,
        base_ref_name: 'main',
        status: 'reachable',
        evidence_json: '{}',
      });
    }

    assert.deepEqual(db.verifiedFixedForRelease('v-skew').map((row: any) => row.number), [33]);
    assert.deepEqual(db.unverifiedClosedForRelease('v-skew').map((row: any) => row.number), [34]);
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
