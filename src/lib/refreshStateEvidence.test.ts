import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type {
  GhIssueClosureEvent,
  GhIssueCommitReference,
  GhIssueFixEvidence,
  GhIssueFixEvidenceConnectionSnapshot,
  GhIssuePrLink,
  GhIssueReopenEvent,
} from './github.ts';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
} from './stateEventSnapshot.ts';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownsTestDir = assignedWorkerDatabasePath === null;
const testDir = assignedWorkerDatabasePath
  ? dirname(assignedWorkerDatabasePath)
  : mkdtempSync(join(tmpdir(), 'radar-refresh-state-suite-'));
const path = assignedWorkerDatabasePath ?? join(testDir, 'radar.db');
if (assignedWorkerDatabasePath) {
  assert.equal(
    process.env.DB_PATH,
    assignedWorkerDatabasePath,
    'refresh state evidence tests must use their assigned worker database',
  );
} else {
  process.env.DB_PATH = path;
}
process.env.REFRESH_MINUTES = '0';
let refresh: typeof import('./refresh.ts');
let db: typeof import('./db.ts');

before(async () => {
  refresh = await import('./refresh.ts');
  db = await import('./db.ts');
});

after(() => {
  try { db.db.close(); } catch { /* already closed */ }
  if (ownsTestDir) rmSync(testDir, { recursive: true, force: true });
});

function connectionSnapshot(
  identities: string[],
  contents: unknown[],
): GhIssueFixEvidenceConnectionSnapshot {
  assert.equal(identities.length, contents.length);
  const totalCount = identities.length;
  return {
    totalCount,
    observedTotalCount: totalCount,
    postBoundaryGrowthCount: 0,
    fetchedCount: totalCount,
    terminalFirstNIdentity: identities.at(-1) ?? null,
    identityDigest: createHash('sha256')
      .update(JSON.stringify([totalCount, identities]))
      .digest('hex'),
    contentDigest: createHash('sha256')
      .update(JSON.stringify([totalCount, contents]))
      .digest('hex'),
    sourceOrder: 'CONNECTION_ASC',
  };
}

function stateEvidence(input: {
  issueNumber: number;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  closureEvents?: GhIssueClosureEvent[];
  reopenEvents?: GhIssueReopenEvent[];
  prLinks?: GhIssuePrLink[];
  commitReferences?: GhIssueCommitReference[];
}): GhIssueFixEvidence {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = `ISSUE-node-${input.issueNumber}`;
  const closureEvents = input.closureEvents ?? [];
  const reopenEvents = input.reopenEvents ?? [];
  const normalizedEvents = normalizeIssueStateEvents([
    ...closureEvents.map((event) => ({
      eventId: event.eventId,
      eventNodeType: event.eventType,
      type: 'closed' as const,
      occurredAt: event.closedAt ?? '',
      connectionOrdinal: event.connectionOrdinal,
      actorNodeId: event.actorNodeId,
      actorLogin: event.actorLogin,
      actorType: event.actorType,
      stateReason: event.stateReason,
      closerNodeId: event.closerNodeId,
      closerType: event.closerType,
      closerNumber: event.closerNumber,
      closerOid: event.closerOid,
    })),
    ...reopenEvents.map((event) => ({
      eventId: event.eventId,
      eventNodeType: event.eventType,
      type: 'reopened' as const,
      occurredAt: event.reopenedAt ?? '',
      connectionOrdinal: event.connectionOrdinal,
      actorNodeId: event.actorNodeId,
      actorLogin: event.actorLogin,
      actorType: event.actorType,
      stateReason: null,
      closerNodeId: null,
      closerType: null,
      closerNumber: null,
      closerOid: null,
    })),
  ]);
  const sweep = {
    repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId,
    issueNodeType: 'Issue' as const,
    issueState: input.issueState,
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: normalizedEvents.length,
    events: normalizedEvents,
  };
  const firstSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 1,
  });
  const secondSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 2,
  });
  return {
    repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    stateSnapshot: {
      schemaVersion: ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
      repositoryNodeId,
      issueNumber: input.issueNumber,
      issueState: input.issueState,
      issueUpdatedAt: input.issueUpdatedAt,
      totalCount: normalizedEvents.length,
      fetchedCount: normalizedEvents.length,
      eventsDigest: issueStateEventsDigest(normalizedEvents, {
        repositoryNodeId,
        issueNodeId,
        issueNodeType: 'Issue',
      }),
      authorityDigest: secondSweep.sweepDigest,
      sweepIdentity: secondSweep,
      sweepCount: 2,
      stabilized: true,
      stabilization: issueStateEventStabilizationIdentity(
        firstSweep,
        secondSweep,
        2,
      ),
    },
    connectionSnapshots: {
      closedByPullRequestsReferences: connectionSnapshot([], []),
      stateEvents: connectionSnapshot(
        normalizedEvents.map((event) => event.eventId),
        normalizedEvents,
      ),
      referenceEvents: connectionSnapshot(
        (input.commitReferences ?? []).map((reference) => reference.eventId),
        input.commitReferences ?? [],
      ),
    },
    closureEvents,
    reopenEvents,
    prLinks: input.prLinks ?? [],
    pullRequests: [],
    commitReferences: input.commitReferences ?? [],
  };
}

function closeEvent(issueNumber: number): GhIssueClosureEvent {
  return {
    issueNumber,
    eventId: `close-${issueNumber}`,
    eventType: 'ClosedEvent',
    closedAt: '2026-06-30T00:00:00Z',
    connectionOrdinal: 0,
    actorNodeId: 'ACTOR-maintainer',
    actorLogin: 'maintainer',
    actorType: 'User',
    stateReason: 'COMPLETED',
    closerType: 'Commit',
    closerNumber: null,
    closerNodeId: `COMMIT-node-${issueNumber}`,
    closerOid: 'a'.repeat(40),
    raw: { id: `close-${issueNumber}` },
  };
}

function reopenEvent(issueNumber: number): GhIssueReopenEvent {
  return {
    issueNumber,
    eventId: `reopen-${issueNumber}`,
    eventType: 'ReopenedEvent',
    reopenedAt: '2026-06-30T01:00:00Z',
    connectionOrdinal: 1,
    actorNodeId: 'ACTOR-maintainer',
    actorLogin: 'maintainer',
    actorType: 'User',
    raw: { id: `reopen-${issueNumber}` },
  };
}

describe('refresh state evidence persistence', () => {
  it('persists commit references fetched with canonical issue state evidence', () => {
    refresh.__refreshTest.persistIssueStateEvidence(stateEvidence({
      issueNumber: 123,
      issueState: 'open',
      issueUpdatedAt: '2026-06-30T00:00:00Z',
      commitReferences: [{
        issueNumber: 123,
        eventId: 'ref-123',
        commitOid: 'a'.repeat(40),
        commitMessageHeadline: 'fix gateway delivery',
        commitRepositoryOwner: 'openclaw',
        commitRepositoryName: 'openclaw',
        commitRepositoryNameWithOwner: 'openclaw/openclaw',
        isCrossRepository: false,
        isDirectReference: true,
        referencedAt: '2026-06-30T00:00:00Z',
        actorLogin: 'maintainer',
        raw: { id: 'ref-123' },
      }],
    }));

    const row = db.db.prepare(
      'SELECT * FROM issue_commit_references WHERE event_id=?',
    ).get('ref-123') as any;
    assert.equal(row.issue_number, 123);
    assert.equal(row.issue_node_id, 'ISSUE-node-123');
    assert.equal(row.commit_oid, 'a'.repeat(40));
    assert.equal(row.commit_repository_name_with_owner, 'openclaw/openclaw');
    assert.equal(row.is_cross_repository, 0);
    assert.equal(row.is_direct_reference, 1);
    assert.ok(Date.parse(row.fetched_at));
    assert.equal(
      db.getIssueStateEventSnapshot(123)?.repository_node_id,
      'REPO-node-openclaw',
    );
  });

  it('atomically replaces disappeared state events while preserving comment-derived PR links', () => {
    const issueNumber = 321;
    const close = closeEvent(issueNumber);
    const reopen = reopenEvent(issueNumber);
    db.replaceActiveReleaseCatalog([{
      node_id: 'RE-state-refresh',
      catalog_tag_commit_oid: 'a'.repeat(40),
      tag: 'v-state-refresh',
      name: 'v-state-refresh',
      published_at: '2026-06-29T00:00:00Z',
      created_at: '2026-06-29T00:00:00Z',
      updated_at: '2026-06-29T00:00:00Z',
      html_url: 'https://example.test/releases/v-state-refresh',
      prerelease: false,
      body: '',
    }]);
    db.upsertIssue({
      number: issueNumber,
      node_id: `ISSUE-node-${issueNumber}`,
      state: 'open',
      title: 'state snapshot replacement',
      author: 'reporter',
      html_url: `https://example.test/issues/${issueNumber}`,
      created_at: '2026-06-28T00:00:00Z',
      updated_at: '2026-06-30T01:00:00Z',
      closed_at: null,
      comments: 0,
      labels: '[]',
      is_bot: 0,
    });
    refresh.__refreshTest.persistIssueStateEvidence(stateEvidence({
      issueNumber,
      issueState: 'open',
      issueUpdatedAt: '2026-06-30T01:00:00Z',
      closureEvents: [close],
      reopenEvents: [reopen],
      prLinks: [{
        issueNumber,
        prNumber: 88,
        prRepositoryOwner: 'openclaw',
        prRepositoryName: 'openclaw',
        prRepositoryNameWithOwner: 'openclaw/openclaw',
        source: 'CrossReferencedEvent',
        willCloseTarget: false,
        referencedAt: '2026-06-30T00:15:00Z',
      }],
      commitReferences: [{
        issueNumber,
        eventId: 'commit-ref-321',
        commitOid: 'b'.repeat(40),
        commitMessageHeadline: 'fix issue 321',
        commitRepositoryOwner: 'openclaw',
        commitRepositoryName: 'openclaw',
        commitRepositoryNameWithOwner: 'openclaw/openclaw',
        isCrossRepository: false,
        isDirectReference: true,
        referencedAt: '2026-06-30T00:20:00Z',
        actorLogin: 'maintainer',
        raw: { id: 'commit-ref-321' },
      }],
    }));
    db.upsertIssuePrLink({
      issue_number: issueNumber,
      issue_node_id: `ISSUE-node-${issueNumber}`,
      pr_number: 55,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-06-30T00:30:00Z',
      source_comment_database_id: 999,
      source_comment_url: 'https://example.test/comments/999',
    });

    db.upsertIssue({
      number: issueNumber,
      node_id: `ISSUE-node-${issueNumber}`,
      state: 'closed',
      title: 'state snapshot replacement',
      author: 'reporter',
      html_url: `https://example.test/issues/${issueNumber}`,
      created_at: '2026-06-28T00:00:00Z',
      updated_at: '2026-06-30T02:00:00Z',
      closed_at: close.closedAt,
      comments: 0,
      labels: '[]',
      is_bot: 0,
    });
    refresh.__refreshTest.persistIssueStateEvidence(stateEvidence({
      issueNumber,
      issueState: 'closed',
      issueUpdatedAt: '2026-06-30T02:00:00Z',
      closureEvents: [close],
    }));

    assert.equal(
      (db.db.prepare(
        'SELECT COUNT(*) AS count FROM issue_reopen_events WHERE issue_number=?',
      ).get(issueNumber) as any).count,
      0,
    );
    assert.equal(
      (db.db.prepare(
        'SELECT COUNT(*) AS count FROM issue_closure_events WHERE issue_number=?',
      ).get(issueNumber) as any).count,
      1,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_pr_links
        WHERE issue_number=? AND source='ClosureComment.fixProof'
      `).get(issueNumber) as any).count,
      1,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_pr_links
        WHERE issue_number=? AND source='CrossReferencedEvent'
      `).get(issueNumber) as any).count,
      0,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_commit_references
        WHERE issue_number=?
      `).get(issueNumber) as any).count,
      0,
    );
    const snapshot = db.getIssueStateEventSnapshot(issueNumber);
    assert.equal(snapshot?.repository_node_id, 'REPO-node-openclaw');
    assert.equal(snapshot?.issue_node_id, `ISSUE-node-${issueNumber}`);
    assert.equal(snapshot?.issue_state, 'closed');
    assert.equal(snapshot?.total_count, 1);
    assert.equal(snapshot?.fetched_count, 1);
    assert.equal(snapshot?.sweep_count, 2);
    assert.equal(snapshot?.stabilized, 1);
    assert.equal(db.releaseIssueStateSnapshotIntegrity('v-state-refresh').failedCount, 0);
  });
});
