import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { IssueClassification } from './llm.ts';

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-release-scoring-guard-${name}-`)), 'radar.db');
}

async function freshModules(name: string) {
  const path = dbPath(name);
  process.env.DB_PATH = path;
  const db = await import(`./db.ts?release-scoring-guard-${name}-${Date.now()}-${Math.random()}`);
  const scoring = await import(`./releaseScoring.ts?release-scoring-guard-${name}-${Date.now()}-${Math.random()}`);
  return { db, scoring, dir: dirname(path) };
}

function classification(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'high',
    scope: 'broad',
    functionality: 'core',
    affectedUsers: 'many',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.95,
    rationale: 'test classification',
    ...overrides,
  };
}

function seedRelease(db: any, tag: string, publishedAt: string) {
  db.upsertRelease({
    tag,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease: false,
    body: '',
  });
  db.upsertReleaseCommit({
    tag,
    tag_commit_oid: `${tag}-commit`,
    committed_at: publishedAt,
  });
}

function seedIssue(db: any, input: {
  number: number;
  title: string;
  state: 'open' | 'closed';
  createdAt: string;
  closedAt?: string | null;
}) {
  db.upsertIssue({
    number: input.number,
    state: input.state,
    title: input.title,
    author: 'reporter',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${input.number}`,
    created_at: input.createdAt,
    updated_at: input.closedAt ?? input.createdAt,
    closed_at: input.closedAt ?? null,
    comments: 1,
    unique_human_commenters: 1,
    maintainer_commenters: 0,
    contributor_commenters: 0,
    commenter_scan_truncated: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: JSON.stringify(['bug']),
    is_bot: 0,
  });
  db.upsertClassification(input.number, classification(), input.closedAt ?? input.createdAt, 1);
}

function seedReopen(db: any, issueNumber: number, reopenedAt: string) {
  db.upsertIssueReopenEvent({
    issue_number: issueNumber,
    event_id: `reopened-${issueNumber}-${reopenedAt}`,
    reopened_at: reopenedAt,
    actor_login: 'maintainer',
    raw_json: '{}',
  });
}

describe('release scoring timeline guard', () => {
  it('refuses to persist scores when issue open-interval evidence is ambiguous', async () => {
    const { db, scoring, dir } = await freshModules('ambiguous-open-interval');
    try {
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
      seedIssue(db, {
        number: 9201,
        title: 'reopened issue missing prior close event',
        state: 'closed',
        createdAt: '2026-05-01T00:00:00Z',
        closedAt: '2026-06-15T00:00:00Z',
      });
      seedReopen(db, 9201, '2026-06-12T00:00:00Z');

      const run = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v1')],
        allFetchedTags: ['v2', 'v1'],
        stableTagsNewestFirst: ['v2', 'v1'],
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });

      assert.throws(
        () => scoring.persistReleaseScoreRun(run),
        /issue open-interval evidence is ambiguous/,
      );
      assert.equal(db.getRelease('v1')?.final_score, null);
      assert.equal(db.getReleaseScoreAudit('v1'), undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
