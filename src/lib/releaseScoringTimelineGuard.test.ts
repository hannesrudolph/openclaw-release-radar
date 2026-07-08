import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { IssueClassification } from './llm.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-release-scoring-guard-${name}-`)), 'radar.db');
}

async function freshModules(name: string) {
  const path = assignedWorkerDatabasePath ?? dbPath(name);
  if (assignedWorkerDatabasePath) {
    assert.equal(
      process.env.DB_PATH,
      assignedWorkerDatabasePath,
      'guarded timeline scoring tests must use their assigned private database',
    );
    assert.ok(
      process.env.DOTENV_CONFIG_PATH,
      'guarded timeline scoring tests require the runner-assigned empty dotenv path',
    );
  } else {
    process.env.DB_PATH = path;
    const emptyDotenvPath = join(dirname(path), 'empty.env');
    writeFileSync(emptyDotenvPath, '', { flag: 'wx', mode: 0o600 });
    process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
  }
  const db = await import(`./db.ts?release-scoring-guard-${name}-${Date.now()}-${Math.random()}`);
  const scoring = await import(`./releaseScoring.ts?release-scoring-guard-${name}-${Date.now()}-${Math.random()}`);
  return {
    db,
    scoring,
    dir: dirname(path),
    ownsDir: assignedWorkerDatabasePath === null,
  };
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
  const tagCommitOid = createHash('sha1')
    .update(`release-scoring-timeline:${tag}`)
    .digest('hex');
  db.upsertRelease({
    tag,
    node_id: `R_${tag}`,
    catalog_tag_commit_oid: tagCommitOid,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease: false,
    body: '',
  });
  db.upsertReleaseCommit({
    tag,
    tag_commit_oid: tagCommitOid,
    committed_at: publishedAt,
  });
}

function activateCatalog(db: any, tagsNewestFirst: string[]): void {
  db.replaceActiveReleaseCatalog(
    tagsNewestFirst.map((tag) => {
      const release = db.getRelease(tag);
      return {
        node_id: release.node_id,
        catalog_tag_commit_oid: release.catalog_tag_commit_oid,
        tag: release.tag,
        name: release.name,
        published_at: release.published_at,
        created_at: release.created_at,
        updated_at: release.updated_at,
        html_url: release.html_url,
        prerelease: release.prerelease === 1,
        body: release.body,
      };
    }),
    { capture: { source: 'test_fixture' } },
  );
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
    comments: 0,
    unique_human_commenters: 0,
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
    const { db, scoring, dir, ownsDir } =
      await freshModules('ambiguous-open-interval');
    try {
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
      activateCatalog(db, ['v2', 'v1']);
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
      if (ownsDir) rmSync(dir, { recursive: true, force: true });
    }
  });
});
