import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { IssueClassification } from './llm.ts';

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-release-scoring-${name}-`)), 'radar.db');
}

async function freshModules(name: string) {
  const path = dbPath(name);
  process.env.DB_PATH = path;
  const db = await import(`./db.ts?release-scoring-${name}-${Date.now()}-${Math.random()}`);
  const scoring = await import(`./releaseScoring.ts?release-scoring-${name}-${Date.now()}-${Math.random()}`);
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
  updatedAt?: string;
  closedAt?: string | null;
  labels?: string[];
  classification?: IssueClassification | null;
}) {
  db.upsertIssue({
    number: input.number,
    state: input.state,
    title: input.title,
    author: 'reporter',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${input.number}`,
    created_at: input.createdAt,
    updated_at: input.updatedAt ?? input.closedAt ?? input.createdAt,
    closed_at: input.closedAt ?? null,
    comments: 1,
    unique_human_commenters: 1,
    maintainer_commenters: 0,
    contributor_commenters: 0,
    commenter_scan_truncated: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: JSON.stringify(input.labels ?? ['bug']),
    is_bot: 0,
  });
  if (input.classification !== null) {
    db.upsertClassification(
      input.number,
      input.classification ?? classification(),
      input.updatedAt ?? input.closedAt ?? input.createdAt,
      1,
    );
  }
  db.upsertIssueLabelSnapshot({
    issue_number: input.number,
    snapshot_at: '2026-06-10T23:00:00Z',
    labels_json: JSON.stringify(input.labels ?? ['bug']),
  });
}

function seedClosure(db: any, issueNumber: number, closedAt: string) {
  db.upsertIssueClosureEvent({
    issue_number: issueNumber,
    event_id: `closed-${issueNumber}`,
    closed_at: closedAt,
    actor_login: 'maintainer',
    state_reason: 'COMPLETED',
    closer_type: null,
    closer_number: null,
    closer_oid: null,
    raw_json: '{}',
  });
}

function seedClosureProof(db: any, releaseTag: string, issueNumber: number, status: string) {
  db.upsertIssueClosureProof({
    release_tag: releaseTag,
    issue_number: issueNumber,
    status,
    summary: status,
    evidence_json: JSON.stringify({ status }),
  });
}

describe('release scoring DB bridge', () => {
  it('turns DB closure/open-debt evidence into install score inputs', async () => {
    const { db, scoring, dir } = await freshModules('score-input-evidence');
    try {
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      seedRelease(db, 'v2', '2026-06-10T00:00:00Z');

      seedIssue(db, {
        number: 9101,
        title: 'verified fixed core regression',
        state: 'closed',
        createdAt: '2026-06-01T12:00:00Z',
        closedAt: '2026-06-02T00:00:00Z',
      });
      seedClosure(db, 9101, '2026-06-02T00:00:00Z');
      seedClosureProof(db, 'v1', 9101, 'fixed_in_release');

      seedIssue(db, {
        number: 9102,
        title: 'closed after release without tag proof',
        state: 'closed',
        createdAt: '2026-06-01T13:00:00Z',
        closedAt: '2026-06-03T00:00:00Z',
      });
      seedClosure(db, 9102, '2026-06-03T00:00:00Z');
      seedClosureProof(db, 'v1', 9102, 'fixed_after_release');

      seedIssue(db, {
        number: 9103,
        title: 'release local broad regression still open',
        state: 'open',
        createdAt: '2026-06-01T14:00:00Z',
        labels: ['P1', 'bug', 'regression'],
      });

      seedIssue(db, {
        number: 9104,
        title: 'unclassified release issue',
        state: 'open',
        createdAt: '2026-06-01T15:00:00Z',
        classification: null,
      });

      seedIssue(db, {
        number: 9105,
        title: 'messages silently dropped after provider timeout',
        state: 'open',
        createdAt: '2026-06-01T16:00:00Z',
        labels: ['stale', 'clawsweeper:source-repro', 'impact:message-loss'],
        classification: classification({
          sentiment: 'neutral',
          severity: 'high',
          functionality: 'integration',
          scope: 'moderate',
          affectedUsers: 'some',
          confidence: 0.8,
        }),
      });
      seedIssue(db, {
        number: 9106,
        title: 'old product question',
        state: 'open',
        createdAt: '2026-06-01T17:00:00Z',
        labels: ['stale'],
        classification: classification({
          sentiment: 'neutral',
          severity: 'high',
          functionality: 'integration',
          scope: 'moderate',
          affectedUsers: 'some',
          confidence: 0.8,
        }),
      });

      const release = db.getRelease('v1');
      const run = scoring.buildReleaseScoreRun({
        releases: [release],
        allFetchedTags: ['v2', 'v1'],
        stableTagsNewestFirst: ['v2', 'v1'],
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      const scored = run.scored[0];
      const staleDebt = scored.debtEvidence.staleDebt as any[];

      assert.ok(scored.input.verifiedDebtWeight > 0);
      assert.ok(scored.input.staleDebtWeight > 0);
      const riskSummary = scored.gateEvidence.fixProvenance.closureProof.riskSummary;
      assert.equal(scored.input.unresolvedClosureRiskWeight, riskSummary.unresolvedWeightedRisk);
      assert.ok(scored.debtEvidence.unverifiedClosed.some((issue: any) => issue.number === 9102));
      assert.equal(scored.input.rawIssueCount, 6);
      assert.equal(scored.input.classifiedIssueCount, 5);
      assert.ok((scored.conf.components?.closureRisk ?? 0) < 0);
      assert.ok((scored.conf.components?.coverage ?? 0) < 0);
      assert.ok(staleDebt.some((item) => item.issue?.number === 9105));
      assert.ok(!staleDebt.some((item) => item.issue?.number === 9106));
      const rescued = staleDebt.find((item) => item.issue?.number === 9105);
      assert.equal(rescued.debtClassification.sentiment, 'negative');
      assert.deepEqual(rescued.debtClassificationDiff.sentiment, { raw: 'neutral', effective: 'negative' });
      assert.equal(rescued.issue.classification.sentiment, 'neutral');
      assert.throws(
        () => scoring.persistReleaseScoreRun(run),
        /complete classification coverage: v1 5\/6/,
      );
      assert.equal(db.getRelease('v1')?.final_score, null);
    } finally {
      try { db.db.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
