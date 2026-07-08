import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyClosureProof, closureRationaleComments } from './closureProof.ts';
import type { ClosureProofResult } from './closureProof.ts';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
  serializeCommentEvidence,
} from './commentEvidence.ts';
import type {
  GhIssueClosureEvent,
  GhIssueCommentSnapshot,
  GhIssueFixEvidence,
  GhIssueFixEvidenceConnectionSnapshot,
} from './github.ts';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
} from './stateEventSnapshot.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const tsx = join(root, 'node_modules', '.bin', 'tsx');
let __closureProofAnalysisTest: typeof import('./closureProofAnalysis.ts').__closureProofAnalysisTest;
let createClosureProofRunContext: typeof import('./closureProofAnalysis.ts').createClosureProofRunContext;
let refreshClosureEvidenceForRelease: typeof import('./closureProofAnalysis.ts').refreshClosureEvidenceForRelease;
let mainDb: typeof import('./db.ts').db;
let upsertIssue: typeof import('./db.ts').upsertIssue;
let replaceActiveReleaseCatalog: typeof import('./db.ts').replaceActiveReleaseCatalog;
let upsertClassification: typeof import('./db.ts').upsertClassification;
let upsertIssueCommentSnapshot: typeof import('./db.ts').upsertIssueCommentSnapshot;
let classifierSourceIdentity: typeof import('./db.ts').classifierSourceIdentity;

before(async () => {
  ({
    __closureProofAnalysisTest,
    createClosureProofRunContext,
    refreshClosureEvidenceForRelease,
  } = await import('./closureProofAnalysis.ts'));
  ({
    db: mainDb,
    upsertIssue,
    replaceActiveReleaseCatalog,
    upsertClassification,
    upsertIssueCommentSnapshot,
    classifierSourceIdentity,
  } = await import('./db.ts'));
});

after(() => {
  mainDb.close();
});

function result(status: ClosureProofResult['status'], summary = status): ClosureProofResult {
  return { status, summary, evidence: {} };
}

function canonicalIssue(number: number, state: string) {
  return {
    number,
    title: `issue ${number}`,
    state,
    url: null,
  };
}

function seedSnapshotIssue(
  number: number,
  comments: number,
  updatedAt: string,
): void {
  upsertIssue({
    number,
    node_id: snapshotIssueNodeId(number),
    state: 'closed',
    title: `Snapshot issue ${number}`,
    author: 'reporter',
    author_node_id: snapshotIssueAuthorNodeId(number),
    author_type: 'User',
    html_url: `https://example.test/issues/${number}`,
    created_at: '2026-07-01T00:00:00Z',
    updated_at: updatedAt,
    closed_at: updatedAt,
    comments,
    labels: '[]',
    is_bot: 0,
  });
}

function snapshotIssueNodeId(issueNumber: number): string {
  return `I_snapshot_${issueNumber}`;
}

function snapshotIssueAuthorNodeId(issueNumber: number): string {
  return `U_snapshot_reporter_${issueNumber}`;
}

function remoteCommentSnapshot(
  issueNumber: number,
  issueUpdatedAt: string,
  comments: ReturnType<typeof closureComment>[],
): GhIssueCommentSnapshot {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = snapshotIssueNodeId(issueNumber);
  const issueAuthor = {
    nodeId: snapshotIssueAuthorNodeId(issueNumber),
    actorType: 'User',
    login: 'reporter',
  };
  const snapshotIdentity = {
    repositoryNodeId,
    issueNodeId,
    issueNodeType: 'Issue' as const,
    issueAuthor,
  };
  const firstSweep = commentEvidenceSweepIdentity({
    sweepOrdinal: 1,
    issueUpdatedAt,
    totalCount: comments.length,
    comments,
    snapshotIdentity,
  });
  const secondSweep = commentEvidenceSweepIdentity({
    sweepOrdinal: 2,
    issueUpdatedAt,
    totalCount: comments.length,
    comments,
    snapshotIdentity,
  });
  return {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    issueAuthor,
    issueUpdatedAt,
    totalCount: comments.length,
    comments,
    commentsDigest: commentEvidenceDigest(comments.length, comments),
    authorityDigest: secondSweep.authorityDigest,
    stabilization: commentEvidenceStabilizationIdentity(
      firstSweep,
      secondSweep,
      2,
    ),
  };
}

function fixEvidenceConnectionSnapshot(
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

function stateEventEvidenceFixture(
  issueNumber: number,
  issueUpdatedAt: string,
  closerNumber: number,
): GhIssueFixEvidence {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = snapshotIssueNodeId(issueNumber);
  const close = {
    issueNumber,
    eventId: `CE_snapshot_${issueNumber}`,
    eventType: 'ClosedEvent',
    closedAt: issueUpdatedAt,
    connectionOrdinal: 0,
    actorNodeId: `U_snapshot_maintainer_${issueNumber}`,
    actorLogin: 'maintainer',
    actorType: 'User',
    stateReason: 'COMPLETED',
    closerType: 'PullRequest',
    closerNumber,
    closerNodeId: `PR_snapshot_${closerNumber}`,
    closerOid: 'c'.repeat(40),
    raw: { id: `CE_snapshot_${issueNumber}` },
  } satisfies GhIssueClosureEvent;
  const normalizedEvents = normalizeIssueStateEvents([{
    eventId: close.eventId,
    eventNodeType: close.eventType,
    type: 'closed',
    occurredAt: close.closedAt,
    connectionOrdinal: close.connectionOrdinal,
    actorNodeId: close.actorNodeId,
    actorLogin: close.actorLogin,
    actorType: close.actorType,
    stateReason: close.stateReason,
    closerNodeId: close.closerNodeId,
    closerType: close.closerType,
    closerNumber: close.closerNumber,
    closerOid: close.closerOid,
  }]);
  const sweepInput = {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue' as const,
    issueState: 'closed' as const,
    issueUpdatedAt,
    totalCount: normalizedEvents.length,
    events: normalizedEvents,
  };
  const firstSweep = issueStateEventSweepIdentity({
    ...sweepInput,
    sweepOrdinal: 1,
  });
  const secondSweep = issueStateEventSweepIdentity({
    ...sweepInput,
    sweepOrdinal: 2,
  });
  return {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    stateSnapshot: {
      schemaVersion: ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
      repositoryNodeId,
      issueNumber,
      issueState: 'closed',
      issueUpdatedAt,
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
      closedByPullRequestsReferences: fixEvidenceConnectionSnapshot([], []),
      stateEvents: fixEvidenceConnectionSnapshot(
        normalizedEvents.map((event) => event.eventId),
        normalizedEvents,
      ),
      referenceEvents: fixEvidenceConnectionSnapshot([], []),
    },
    closureEvents: [close],
    reopenEvents: [],
    prLinks: [],
    pullRequests: [],
    commitReferences: [],
  };
}

function seedReconciledCommentEvidence(
  issueNumber: number,
  snapshot: ReturnType<typeof remoteCommentSnapshot>,
): void {
  upsertIssueCommentSnapshot({
    issue_number: issueNumber,
    repository_node_id: snapshot.repositoryNodeId,
    issue_node_id: snapshot.issueNodeId,
    issue_author_node_id: snapshot.issueAuthor?.nodeId ?? null,
    issue_author_login: snapshot.issueAuthor?.login ?? null,
    issue_author_type: snapshot.issueAuthor?.actorType ?? null,
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    comment_count: snapshot.totalCount,
    fetched_comment_count: snapshot.comments.length,
    latest_comment_updated_at: snapshot.comments.at(-1)?.updated_at ?? null,
    comments_digest: snapshot.commentsDigest,
    authority_digest: snapshot.authorityDigest,
    issue_updated_at: snapshot.issueUpdatedAt,
    comments_json: serializeCommentEvidence(snapshot.comments),
    stabilization_json: JSON.stringify(snapshot.stabilization),
    stabilization_identity_digest: snapshot.stabilization.identityDigest,
  });
  upsertClassification(
    issueNumber,
    {
      sentiment: 'negative',
      severity: 'medium',
      scope: 'moderate',
      functionality: 'core',
      affectedUsers: 'some',
      workaroundStatus: 'unknown',
      duplicateCluster: null,
      affectsVersion: null,
      confidence: 0.9,
      rationale: '',
    },
    snapshot.issueUpdatedAt,
    6,
    snapshot.commentsDigest,
    classifierSourceIdentity(['v-test'], 6),
  );
}

function runIsolatedAnalysisScript(name: string, body: string): void {
  const dir = mkdtempSync(join(tmpdir(), `radar-closure-analysis-${name}-`));
  const path = join(dir, 'radar.db');
  const script = `
    import assert from 'node:assert/strict';
    import { createHash } from 'node:crypto';
    (async () => {
      const dbModule = await import('./src/lib/db.ts');
      const analysisModule = await import('./src/lib/closureProofAnalysis.ts');
      const commentEvidenceModule = await import('./src/lib/commentEvidence.ts');
      const db = dbModule.default ?? dbModule;
      const analysis = analysisModule.default ?? analysisModule;
      const commentEvidence = commentEvidenceModule.default ?? commentEvidenceModule;
      const classification = {
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
      };
      const releaseCatalog = new Map();
      function seedRelease(
        tag,
        publishedAt = '2026-07-01T00:00:00Z',
        catalogTagCommitOid = createHash('sha1').update('release:' + tag).digest('hex'),
      ) {
        releaseCatalog.set(tag, {
          node_id: 'R_' + createHash('sha256').update(tag).digest('hex'),
          catalog_tag_commit_oid: catalogTagCommitOid,
          tag,
          name: tag,
          published_at: publishedAt,
          created_at: publishedAt,
          updated_at: publishedAt,
          html_url: 'https://example.test/releases/' + tag,
          prerelease: false,
          body: '',
        });
        db.replaceActiveReleaseCatalog(
          [...releaseCatalog.values()].sort((left, right) =>
            Date.parse(right.published_at) - Date.parse(left.published_at) ||
            left.tag.localeCompare(right.tag)
          ),
          { capture: { source: 'test_fixture' } },
        );
      }
      function seedIssue(number, closedAt) {
        db.upsertIssue({
          number,
          state: 'closed',
          title: 'Bug issue ' + number,
          author: 'reporter',
          html_url: 'https://example.test/issues/' + number,
          created_at: '2026-07-01T12:00:00Z',
          updated_at: closedAt,
          closed_at: closedAt,
          comments: 0,
          labels: '[]',
          is_bot: 0,
        });
        db.upsertClassification(number, classification, closedAt, 1);
      }
      function seedClosure(issueNumber, eventId, closedAt, closerType = null, closerNumber = null) {
        db.upsertIssueClosureEvent({
          issue_number: issueNumber,
          event_id: eventId,
          closed_at: closedAt,
          actor_login: 'maintainer',
          state_reason: 'COMPLETED',
          closer_type: closerType,
          closer_number: closerNumber,
          closer_oid: closerNumber == null ? null : 'merge-' + closerNumber,
          raw_json: '{}',
        });
      }
      function seedReopen(issueNumber, reopenedAt) {
        db.upsertIssueReopenEvent({
          issue_number: issueNumber,
          event_id: 'reopened-' + issueNumber + '-' + reopenedAt,
          reopened_at: reopenedAt,
          actor_login: 'maintainer',
          raw_json: '{}',
        });
      }
      function seedPr(prNumber) {
        db.upsertPullRequestFix({
          pr_number: prNumber,
          title: 'PR ' + prNumber,
          url: 'https://example.test/pull/' + prNumber,
          state: 'MERGED',
          merged: 1,
          merged_at: '2026-07-02T00:00:00Z',
          merge_commit_oid: 'merge-' + prNumber,
          base_ref_name: 'main',
        });
      }
      function seedReachability(tag, prNumber) {
        db.upsertReleasePrReachability({
          tag,
          pr_number: prNumber,
          tag_commit_oid: 'tag-' + tag,
          merge_commit_oid: 'merge-' + prNumber,
          base_ref_name: 'main',
          status: 'reachable',
          evidence_json: '{}',
        });
      }
      function prepared(tag, issueNumbers) {
        return {
          releaseTag: tag,
          analysisStartedAt: '2026-07-04T00:00:00Z',
          labelCutoff: null,
          issueNumbers,
          sourceIssueNumbers: new Set(issueNumbers),
          allCommentsByIssue: new Map(issueNumbers.map((number) => [number, []])),
          canonicalGraph: new Map(),
          analysisIssueNumbers: issueNumbers,
        };
      }
      function seedAuthoritativeCommentSnapshot(tag, issueNumber, issueUpdatedAt, sourceComments) {
        const repositoryNodeId = 'R_openclaw_openclaw';
        const issueNodeId = 'I_' + issueNumber;
        const issueAuthor = {
          nodeId: 'U_reporter_' + issueNumber,
          actorType: 'User',
          login: 'reporter',
        };
        const comments = sourceComments.map((comment, index) => ({
          ...comment,
          node_id: comment.node_id ?? 'IC_' + issueNumber + '_' + comment.id,
          node_type: comment.node_type ?? 'IssueComment',
          user: {
            ...comment.user,
            id: comment.user?.id ?? 'U_' + issueNumber + '_' + index,
            type: comment.user?.type ?? 'User',
            login: comment.user?.login ?? 'unknown',
          },
        }));
        const snapshotIdentity = {
          repositoryNodeId,
          issueNodeId,
          issueNodeType: 'Issue',
          issueAuthor,
        };
        const firstSweep = commentEvidence.commentEvidenceSweepIdentity({
          sweepOrdinal: 1,
          issueUpdatedAt,
          totalCount: comments.length,
          comments,
          snapshotIdentity,
        });
        const secondSweep = commentEvidence.commentEvidenceSweepIdentity({
          sweepOrdinal: 2,
          issueUpdatedAt,
          totalCount: comments.length,
          comments,
          snapshotIdentity,
        });
        const snapshot = {
          repositoryNodeId,
          issueNumber,
          issueNodeId,
          issueNodeType: 'Issue',
          issueAuthor,
          issueUpdatedAt,
          totalCount: comments.length,
          comments,
          commentsDigest: commentEvidence.commentEvidenceDigest(
            comments.length,
            comments,
          ),
          authorityDigest: secondSweep.authorityDigest,
          stabilization: commentEvidence.commentEvidenceStabilizationIdentity(
            firstSweep,
            secondSweep,
            2,
          ),
        };
        db.db.prepare(
          'UPDATE issues SET node_id=?, author_node_id=?, author_type=?, comments=? WHERE number=?'
        ).run(
          issueNodeId,
          issueAuthor.nodeId,
          issueAuthor.actorType,
          comments.length,
          issueNumber,
        );
        db.upsertIssueCommentSnapshot({
          issue_number: issueNumber,
          repository_node_id: repositoryNodeId,
          issue_node_id: issueNodeId,
          issue_author_node_id: issueAuthor.nodeId,
          issue_author_login: issueAuthor.login,
          issue_author_type: issueAuthor.actorType,
          schema_version: commentEvidence.AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
          comment_count: comments.length,
          fetched_comment_count: comments.length,
          latest_comment_updated_at: comments.at(-1)?.updated_at ?? null,
          comments_digest: snapshot.commentsDigest,
          authority_digest: snapshot.authorityDigest,
          issue_updated_at: issueUpdatedAt,
          comments_json: commentEvidence.serializeCommentEvidence(comments),
          stabilization_json: JSON.stringify(snapshot.stabilization),
          stabilization_identity_digest: snapshot.stabilization.identityDigest,
        });
        db.upsertClassification(
          issueNumber,
          classification,
          issueUpdatedAt,
          1,
          snapshot.commentsDigest,
          db.classifierSourceIdentity([tag], 1),
        );
        return snapshot;
      }
      ${body}
      db.db.close();
    })().catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
  `;
  try {
    const childEnv = {
      ...process.env,
      DB_PATH: path,
      NODE_ENV: 'test',
    };
    if (!childEnv.RADAR_TEST_WRITER_LOCK_TOKEN) {
      childEnv.RADAR_TEST_PROCESS_LOCK_ROOT = dir;
      childEnv.RADAR_TEST_RUN_ID =
        `closure-analysis-${name}-${process.pid}`;
      childEnv.RADAR_TEST_TEMP_ROOT = dir;
    }
    const run = spawnSync(tsx, ['-e', script], {
      cwd: root,
      env: childEnv,
      encoding: 'utf8',
    });
    assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('closure proof canonical roll-up', () => {
  describe('release tag anchor commit proof', () => {
    const releaseTagCommit = 'e085fa1a3ffd32d0ea6917e1e6fb4ecbffbb77d2';
    const cases = [
      { issueNumber: 98314, implementationCommit: '1'.repeat(40) },
      { issueNumber: 98401, implementationCommit: '2'.repeat(40) },
      { issueNumber: 98939, implementationCommit: '3'.repeat(40) },
    ];

    for (const fixture of cases) {
      it(`does not credit #${fixture.issueNumber} from the reachable release tag anchor`, () => {
        const mentions = [
          {
            issueNumber: fixture.issueNumber,
            commitOid: fixture.implementationCommit,
            referencedAt: '2026-07-01T12:00:00Z',
            sourceIssueNumber: fixture.issueNumber,
            snippet: `Fixed by ${fixture.implementationCommit}`,
            source: 'ClosureComment.fixProof' as const,
            author: 'maintainer',
            authorAssociation: 'MEMBER',
            trustedSource: true,
          },
          {
            issueNumber: fixture.issueNumber,
            commitOid: releaseTagCommit,
            referencedAt: '2026-07-01T12:00:00Z',
            sourceIssueNumber: fixture.issueNumber,
            snippet: `Release tag anchor ${releaseTagCommit}`,
            source: 'ClosureComment.fixProof' as const,
            author: 'maintainer',
            authorAssociation: 'MEMBER',
            trustedSource: true,
          },
        ];
        const directProof = __closureProofAnalysisTest.commitProofEvidence(
          mentions,
          new Map([
            [fixture.implementationCommit, {
              commitOid: fixture.implementationCommit,
              tagCommitOid: releaseTagCommit,
              status: 'not_reachable',
              evidence: 'not_ancestor',
            }],
            [releaseTagCommit, {
              commitOid: releaseTagCommit,
              tagCommitOid: releaseTagCommit,
              status: 'reachable',
              evidence: 'same_commit',
            }],
          ]),
        );
        const creditableProof =
          __closureProofAnalysisTest.creditableDirectCommitProof(directProof);
        const reachableFixCommits = creditableProof
          .filter((item: any) => item.status === 'reachable')
          .map((item: any) => item.commitOid);
        const notReachableFixCommits = creditableProof
          .filter((item: any) => item.status === 'not_reachable')
          .map((item: any) => item.commitOid);
        const proof = classifyClosureProof({
          issueNumber: fixture.issueNumber,
          issueAuthor: 'reporter',
          closedAt: '2026-07-01T12:00:00Z',
          sentiment: 'negative',
          stateReasons: ['COMPLETED'],
          closureActors: ['maintainer'],
          hasClosureEvent: true,
          hasClosingLink: false,
          hasMergedClosingPr: false,
          hasReachableClosingPr: false,
          hasNotReachableClosingPr: false,
          hasReachableFixCommit: reachableFixCommits.length > 0,
          hasNotReachableFixCommit: notReachableFixCommits.length > 0,
          hasUnknownFixCommit: false,
          reachableFixCommits,
          notReachableFixCommits,
          unknownFixCommits: [],
          comments: [],
        });

        assert.equal(proof.status, 'fixed_after_release');
        assert.deepEqual(reachableFixCommits, []);
        assert.deepEqual(notReachableFixCommits, [fixture.implementationCommit]);
        assert.equal(directProof.find((item: any) => item.commitOid === releaseTagCommit)?.releaseTagAnchor, true);
        assert.equal(directProof.find((item: any) => item.commitOid === releaseTagCommit)?.creditEligible, false);
      });
    }

    it('preserves distinct reachable implementation commits as direct fix proof', () => {
      const implementationCommit = '4'.repeat(40);
      const directProof = __closureProofAnalysisTest.commitProofEvidence(
        [{
          issueNumber: 99001,
          commitOid: implementationCommit,
          referencedAt: '2026-07-01T12:00:00Z',
          sourceIssueNumber: 99001,
          snippet: `Fixed by ${implementationCommit}`,
          source: 'ClosureComment.fixProof',
          author: 'maintainer',
          authorAssociation: 'MEMBER',
          trustedSource: true,
        }],
        new Map([[implementationCommit, {
          commitOid: implementationCommit,
          tagCommitOid: releaseTagCommit,
          status: 'reachable',
          evidence: 'ancestor',
        }]]),
      );

      assert.equal(directProof[0].releaseTagAnchor, false);
      assert.equal(directProof[0].creditEligible, true);
      assert.deepEqual(
        __closureProofAnalysisTest.creditableDirectCommitProof(directProof)
          .map((item: any) => item.commitOid),
        [implementationCommit],
      );
    });

    it('does not suppress a direct closer that equals the tag commit', () => {
      const directProof = __closureProofAnalysisTest.commitProofEvidence(
        [{
          issueNumber: 99002,
          commitOid: releaseTagCommit,
          referencedAt: '2026-07-01T12:00:00Z',
          sourceIssueNumber: 99002,
          snippet: `GitHub ClosedEvent closer commit ${releaseTagCommit}`,
          source: 'ClosedEvent.closer',
          author: null,
          authorAssociation: null,
          trustedSource: true,
        }],
        new Map([[releaseTagCommit, {
          commitOid: releaseTagCommit,
          tagCommitOid: releaseTagCommit,
          status: 'reachable',
          evidence: 'same_commit',
        }]]),
      );

      assert.equal(directProof[0].releaseTagAnchor, false);
      assert.equal(directProof[0].creditEligible, true);
    });

    it('does not let an explicitly non-creditable tag anchor resolve a canonical branch', () => {
      const canonicalProof = __closureProofAnalysisTest.commitProofEvidence(
        [{
          issueNumber: 10,
          commitOid: releaseTagCommit,
          referencedAt: '2026-07-01T12:00:00Z',
          sourceIssueNumber: 20,
          snippet: `Release tag anchor ${releaseTagCommit}`,
          source: 'ClosureComment.fixProof',
          author: 'maintainer',
          authorAssociation: 'MEMBER',
          trustedSource: true,
        }],
        new Map([[releaseTagCommit, {
          commitOid: releaseTagCommit,
          tagCommitOid: releaseTagCommit,
          status: 'reachable',
          evidence: 'same_commit',
        }]]),
      );

      const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
        10,
        result('duplicate_or_superseded', 'Closed as duplicate.'),
        {
          canonicalIssues: [20],
          canonicalFixCommitProof: canonicalProof,
        },
        new Map([[10, [20]]]),
        new Map(),
        null,
        () => null,
        (number: number) => canonicalIssue(number, number === 20 ? 'open' : 'closed'),
      );

      assert.equal(canonicalProof[0].creditEligible, false);
      assert.equal(adjusted.status, 'duplicate_to_open_canonical');
      assert.equal(
        (adjusted.evidence.canonicalResolution as any).branches[0].fixedInRelease,
        false,
      );
    });

    it('separates target containment from strict first-containing credit', () => {
      const creditedCommit = '4'.repeat(40);
      const carryoverCommit = '5'.repeat(40);
      const unknownCommit = '6'.repeat(40);
      const targetAbsentCommit = '7'.repeat(40);
      const commitProof = [
        { commitOid: creditedCommit, status: 'reachable' },
        { commitOid: carryoverCommit, status: 'reachable' },
        { commitOid: unknownCommit, status: 'unknown' },
        { commitOid: targetAbsentCommit, status: 'not_reachable' },
      ].map((item) => ({
        issueNumber: 99003,
        referencedAt: '2026-07-01T12:00:00Z',
        sourceIssueNumber: 99003,
        snippet: `proof ${item.commitOid}`,
        source: 'ClosedEvent.closer' as const,
        author: null,
        authorAssociation: null,
        trustedSource: true,
        tagCommitOid: releaseTagCommit,
        evidence: 'test',
        releaseTagAnchor: false,
        creditEligible: true,
        ...item,
      }));
      const proofByCommit = new Map([
        [creditedCommit, {
          commitOid: creditedCommit,
          creditEligible: true,
          reasonCode: 'first_containing_direct_commit',
        }],
        [carryoverCommit, {
          commitOid: carryoverCommit,
          creditEligible: false,
          reasonCode: 'predecessor_contains_commit',
        }],
        [unknownCommit, {
          commitOid: unknownCommit,
          creditEligible: false,
          reasonCode: 'git_evidence_unavailable',
        }],
        [targetAbsentCommit, {
          commitOid: targetAbsentCommit,
          creditEligible: false,
          reasonCode: 'target_commit_not_reachable',
        }],
      ]);

      const summary =
        __closureProofAnalysisTest.summarizeDirectCommitFirstContainingProofs({
          releaseTag: 'v-target',
          issueNumber: 99003,
          commitProof: commitProof as any,
          proofByCommit: proofByCommit as any,
        });

      assert.deepEqual(summary.targetReachableFixCommits, [
        creditedCommit,
        carryoverCommit,
      ]);
      assert.deepEqual(summary.reachableFixCommits, [creditedCommit]);
      assert.deepEqual(summary.predecessorContainedFixCommits, [carryoverCommit]);
      assert.deepEqual(summary.firstContainingUnknownFixCommits, [unknownCommit]);
      assert.deepEqual(summary.notReachableFixCommits, [targetAbsentCommit]);
      assert.deepEqual(summary.unknownFixCommits, [unknownCommit]);
      assert.equal(summary.hasReachableFixCommit, true);
      assert.equal(summary.hasNotReachableFixCommit, true);
      assert.equal(summary.hasUnknownFixCommit, true);
    });

    it('uses target containment as closure proof when first-containing credit is withheld', () => {
      const carryoverCommit = '8'.repeat(40);
      const summary =
        __closureProofAnalysisTest.summarizeDirectCommitFirstContainingProofs({
          releaseTag: 'v-target',
          issueNumber: 99004,
          commitProof: [{
            commitOid: carryoverCommit,
            status: 'reachable',
          }] as any,
          proofByCommit: new Map([[
            carryoverCommit,
            {
              commitOid: carryoverCommit,
              creditEligible: false,
              reasonCode: 'predecessor_contains_commit',
            },
          ]]) as any,
        });

      assert.equal(summary.hasReachableFixCommit, true);
      assert.deepEqual(summary.targetReachableFixCommits, [carryoverCommit]);
      assert.deepEqual(summary.reachableFixCommits, []);
      assert.deepEqual(summary.predecessorContainedFixCommits, [carryoverCommit]);
      assert.equal(classifyClosureProof({
        issueNumber: 99004,
        issueAuthor: 'reporter',
        closedAt: '2026-07-01T12:00:00Z',
        sentiment: 'negative',
        stateReasons: ['COMPLETED'],
        closureActors: ['maintainer'],
        hasClosureEvent: true,
        hasClosingLink: false,
        hasMergedClosingPr: false,
        hasReachableClosingPr: false,
        hasNotReachableClosingPr: false,
        ...summary,
        comments: [],
      }).status, 'fixed_in_release');
    });

    it('fails closed when any direct-commit candidate lacks first-containing proof', () => {
      const commitOid = '9'.repeat(40);
      assert.throws(
        () => __closureProofAnalysisTest.summarizeDirectCommitFirstContainingProofs({
          releaseTag: 'v-target',
          issueNumber: 99005,
          commitProof: [{
            commitOid,
            status: 'reachable',
          }] as any,
          proofByCommit: new Map(),
        }),
        /proof coverage is incomplete for v-target issue #99005/,
      );
    });
  });

  it('accepts fetched comments beyond a stale DB count and records metadata drift', async () => {
    const issueNumber = 990_001;
    seedSnapshotIssue(issueNumber, 1, '2026-07-03T00:00:00Z');
    const comments = [
      closureComment(101, '2026-07-02T01:00:00Z'),
      closureComment(102, '2026-07-02T02:00:00Z'),
    ];
    const snapshot = remoteCommentSnapshot(issueNumber, '2026-07-03T01:00:00Z', comments);
    const context = createClosureProofRunContext();
    let calls = 0;

    const fetched = await __closureProofAnalysisTest.commentsForIssues(
      context,
      [issueNumber],
      {
        allowMetadataDrift: true,
        fetchSnapshots: async () => {
          calls++;
          return new Map([[issueNumber, snapshot]]);
        },
      },
    );

    assert.equal(calls, 1);
    assert.equal(fetched.get(issueNumber)?.length, 2);
    assert.equal(
      (mainDb.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(issueNumber) as { count: number }).count,
      0,
    );
    assert.deepEqual(
      __closureProofAnalysisTest.closureProofCommentSnapshotDriftIssueNumbers(context),
      [issueNumber],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.unresolvedCommentSnapshotMetadataDriftIssueNumbers(
        context,
        [issueNumber],
      ),
      [issueNumber],
    );
  });

  it('discovers a zero-to-one comment transition from the remote snapshot', async () => {
    const issueNumber = 990_002;
    seedSnapshotIssue(issueNumber, 0, '2026-07-03T00:00:00Z');
    const snapshot = remoteCommentSnapshot(
      issueNumber,
      '2026-07-03T00:05:00Z',
      [closureComment(201, '2026-07-03T00:04:00Z')],
    );
    const context = createClosureProofRunContext();

    const fetched = await __closureProofAnalysisTest.commentsForIssues(
      context,
      [issueNumber],
      {
        allowMetadataDrift: true,
        fetchSnapshots: async () => new Map([[issueNumber, snapshot]]),
      },
    );

    assert.equal(fetched.get(issueNumber)?.[0]?.id, 201);
    assert.equal(
      (mainDb.prepare(`
        SELECT COUNT(*) AS count
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(issueNumber) as { count: number }).count,
      0,
    );
    assert.deepEqual(
      __closureProofAnalysisTest.closureProofCommentSnapshotDriftIssueNumbers(context),
      [issueNumber],
    );
  });

  it('reuses a reconciled stable remote snapshot within the run without rewriting it', async () => {
    const issueNumber = 990_003;
    const issueUpdatedAt = '2026-07-03T02:00:00Z';
    seedSnapshotIssue(issueNumber, 2, issueUpdatedAt);
    const snapshot = remoteCommentSnapshot(issueNumber, issueUpdatedAt, [
      closureComment(301, '2026-07-03T01:00:00Z'),
      closureComment(302, '2026-07-03T01:30:00Z'),
    ]);
    seedReconciledCommentEvidence(issueNumber, snapshot);
    const context = createClosureProofRunContext();
    let calls = 0;
    const fetchSnapshots = async () => {
      calls++;
      return new Map([[issueNumber, snapshot]]);
    };

    await __closureProofAnalysisTest.commentsForIssues(
      context,
      [issueNumber],
      { fetchSnapshots },
    );
    const second = await __closureProofAnalysisTest.commentsForIssues(
      context,
      [issueNumber],
      {
        fetchSnapshots: async () => {
          throw new Error('run cache was not reused');
        },
      },
    );

    assert.equal(calls, 1);
    assert.deepEqual(second.get(issueNumber), snapshot.comments);
    assert.deepEqual(
      __closureProofAnalysisTest.closureProofCommentSnapshotDriftIssueNumbers(context),
      [],
    );
    const persisted = mainDb.prepare(`
      SELECT schema_version, verified_at, comment_count, fetched_comment_count,
             comments_digest, issue_updated_at, comments_json
      FROM issue_comment_snapshots
      WHERE issue_number=?
    `).get(issueNumber) as Record<string, unknown>;
    assert.equal(
      persisted.schema_version,
      AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    );
    assert.equal(Number.isFinite(Date.parse(String(persisted.verified_at))), true);
    assert.equal(persisted.comment_count, snapshot.totalCount);
    assert.equal(persisted.fetched_comment_count, snapshot.comments.length);
    assert.equal(persisted.comments_digest, snapshot.commentsDigest);
    assert.equal(persisted.issue_updated_at, snapshot.issueUpdatedAt);
    assert.equal(persisted.comments_json, serializeCommentEvidence(snapshot.comments));
  });

  it('reports issue-updated-at drift even when the comment count is unchanged', async () => {
    const issueNumber = 990_004;
    seedSnapshotIssue(issueNumber, 1, '2026-07-03T03:00:00Z');
    const snapshot = remoteCommentSnapshot(
      issueNumber,
      '2026-07-03T03:15:00Z',
      [closureComment(401, '2026-07-03T02:30:00Z')],
    );
    const context = createClosureProofRunContext();

    await __closureProofAnalysisTest.commentsForIssues(
      context,
      [issueNumber],
      {
        allowMetadataDrift: true,
        fetchSnapshots: async () => new Map([[issueNumber, snapshot]]),
      },
    );

    assert.deepEqual(
      __closureProofAnalysisTest.closureProofCommentSnapshotDriftIssueNumbers(context, [issueNumber]),
      [issueNumber],
    );
    seedSnapshotIssue(issueNumber, snapshot.totalCount, snapshot.issueUpdatedAt);
    seedReconciledCommentEvidence(issueNumber, snapshot);
    assert.deepEqual(
      __closureProofAnalysisTest.unresolvedCommentSnapshotMetadataDriftIssueNumbers(
        context,
        [issueNumber],
      ),
      [],
    );
  });

  it('returns actionable snapshot drift from release evidence refresh', async () => {
    const issueNumber = 990_007;
    const releaseTag = 'v-comment-drift';
    replaceActiveReleaseCatalog(
      [{
        node_id: `R_${createHash('sha256').update(releaseTag).digest('hex')}`,
        catalog_tag_commit_oid: createHash('sha1')
          .update(`release:${releaseTag}`)
          .digest('hex'),
        tag: releaseTag,
        name: releaseTag,
        published_at: '2026-07-10T00:00:00Z',
        created_at: '2026-07-10T00:00:00Z',
        updated_at: '2026-07-10T00:00:00Z',
        html_url: `https://example.test/releases/${releaseTag}`,
        prerelease: false,
        body: '',
      }],
      { capture: { source: 'test_fixture' } },
    );
    seedSnapshotIssue(issueNumber, 0, '2026-07-11T00:00:00Z');
    const snapshot = remoteCommentSnapshot(
      issueNumber,
      '2026-07-11T01:00:00Z',
      [closureComment(701, '2026-07-11T00:30:00Z')],
    );
    const context = createClosureProofRunContext();
    await __closureProofAnalysisTest.commentsForIssues(
      context,
      [issueNumber],
      {
        allowMetadataDrift: true,
        fetchSnapshots: async () => new Map([[issueNumber, snapshot]]),
      },
    );

    const refreshed = await refreshClosureEvidenceForRelease(releaseTag, context);

    assert.equal(refreshed.issueCount, 1);
    assert.equal(refreshed.refreshedIssueCount, 0);
    assert.equal(refreshed.reusedIssueCount, 0);
    assert.equal(refreshed.deferredIssueCount, 1);
    assert.deepEqual(refreshed.issueMetadataDriftIssueNumbers, [issueNumber]);
  });

  it('keeps state snapshot metadata drift unresolved until issue and comment metadata agree', () => {
    const issueNumber = 990_008;
    const issueUpdatedAt = '2026-07-11T02:00:00Z';
    seedSnapshotIssue(issueNumber, 0, issueUpdatedAt);
    const snapshot = remoteCommentSnapshot(issueNumber, issueUpdatedAt, []);
    const context = createClosureProofRunContext();
    context.commentSnapshotsByIssue.set(issueNumber, snapshot);
    context.commentsByIssue.set(issueNumber, []);
    context.stateSnapshotMetadataDriftIssueNumbers.add(issueNumber);
    const evidence = stateEventEvidenceFixture(
      issueNumber,
      '2026-07-11T01:59:59Z',
      908,
    );
    context.fixEvidenceByIssue.set(issueNumber, evidence);

    assert.deepEqual(
      __closureProofAnalysisTest.unresolvedStateSnapshotMetadataDriftIssueNumbers(context),
      [issueNumber],
    );
    evidence.stateSnapshot.issueUpdatedAt = issueUpdatedAt;
    assert.deepEqual(
      __closureProofAnalysisTest.unresolvedStateSnapshotMetadataDriftIssueNumbers(context),
      [],
    );
  });

  it('refuses persisted state snapshot reuse when full projection parity is corrupted', () => {
    const issueNumber = 990_009;
    const issueUpdatedAt = '2026-07-11T03:00:00Z';
    seedSnapshotIssue(issueNumber, 0, issueUpdatedAt);
    const commentSnapshot = remoteCommentSnapshot(issueNumber, issueUpdatedAt, []);
    const context = createClosureProofRunContext();
    context.commentSnapshotsByIssue.set(issueNumber, commentSnapshot);
    context.commentsByIssue.set(issueNumber, []);
    const evidence = stateEventEvidenceFixture(issueNumber, issueUpdatedAt, 909);
    const close = evidence.closureEvents[0];
    __closureProofAnalysisTest.replaceVerifiedIssueStateEventSnapshot(evidence);
    assert.equal(
      __closureProofAnalysisTest.persistedIssueStateSnapshotMatchesAcceptedEvidence(
        context,
        issueNumber,
      ),
      true,
    );

    mainDb.prepare(`
      UPDATE issue_closure_events
      SET actor_login='tampered', closer_number=999
      WHERE event_id=?
    `).run(close.eventId);
    assert.equal(
      __closureProofAnalysisTest.persistedIssueStateSnapshotMatchesAcceptedEvidence(
        context,
        issueNumber,
      ),
      false,
    );

    __closureProofAnalysisTest.replaceVerifiedIssueStateEventSnapshot(evidence);
    assert.equal(
      __closureProofAnalysisTest.persistedIssueStateSnapshotMatchesAcceptedEvidence(
        context,
        issueNumber,
      ),
      true,
    );
  });

  it('rejects cross-repository, cross-issue, and issue-node state evidence before persistence', () => {
    const evidence = stateEventEvidenceFixture(
      990_010,
      '2026-07-11T04:00:00Z',
      910,
    );
    assert.throws(
      () => __closureProofAnalysisTest.replaceVerifiedIssueStateEventSnapshot({
        ...evidence,
        stateSnapshot: {
          ...evidence.stateSnapshot,
          repositoryNodeId: 'REPO-node-other',
        },
      }),
      /repository identity .* does not match fix evidence/,
    );
    assert.throws(
      () => __closureProofAnalysisTest.replaceVerifiedIssueStateEventSnapshot({
        ...evidence,
        stateSnapshot: {
          ...evidence.stateSnapshot,
          issueNumber: evidence.issueNumber + 1,
        },
      }),
      /does not match fix evidence issue/,
    );
    assert.throws(
      () => __closureProofAnalysisTest.replaceVerifiedIssueStateEventSnapshot({
        ...evidence,
        issueNodeId: 'ISSUE-node-other',
      }),
      /issue node identity or events do not match the fix evidence/,
    );
  });

  it('never reuses a persisted local payload before remote verification', async () => {
    const issueNumber = 990_005;
    const issueUpdatedAt = '2026-07-03T04:00:00Z';
    seedSnapshotIssue(issueNumber, 1, issueUpdatedAt);
    const staleComments = [closureComment(501, '2026-07-03T03:00:00Z')];
    const staleDigest = commentEvidenceDigest(1, staleComments);
    mainDb.prepare(`
      INSERT INTO issue_comment_snapshots (
        issue_number, schema_version, fetched_at, verified_at, comment_count, fetched_comment_count,
        latest_comment_updated_at, comments_digest, issue_updated_at, comments_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      issueNumber,
      2,
      '2026-07-03T03:30:00Z',
      '2026-07-03T03:30:00Z',
      1,
      1,
      staleComments[0].updated_at,
      staleDigest,
      issueUpdatedAt,
      serializeCommentEvidence(staleComments),
    );
    upsertClassification(
      issueNumber,
      {
        sentiment: 'negative',
        severity: 'medium',
        scope: 'moderate',
        functionality: 'core',
        affectedUsers: 'some',
        workaroundStatus: 'unknown',
        duplicateCluster: null,
        affectsVersion: null,
        confidence: 0.9,
        rationale: '',
      },
      issueUpdatedAt,
      6,
      staleDigest,
      classifierSourceIdentity(['v-test'], 6),
    );
    const remote = remoteCommentSnapshot(
      issueNumber,
      issueUpdatedAt,
      [closureComment(502, '2026-07-03T03:45:00Z')],
    );
    const context = createClosureProofRunContext();
    let calls = 0;

    const fetched = await __closureProofAnalysisTest.commentsForIssues(
      context,
      [issueNumber],
      {
        allowMetadataDrift: true,
        fetchSnapshots: async () => {
          calls++;
          return new Map([[issueNumber, remote]]);
        },
      },
    );

    assert.equal(calls, 1);
    assert.equal(fetched.get(issueNumber)?.[0]?.id, 502);
    const persisted = mainDb.prepare(`
      SELECT comments_digest, comments_json
      FROM issue_comment_snapshots
      WHERE issue_number=?
    `).get(issueNumber) as { comments_digest: string; comments_json: string };
    assert.equal(persisted.comments_digest, staleDigest);
    assert.equal(persisted.comments_json, serializeCommentEvidence(staleComments));
    assert.deepEqual(
      __closureProofAnalysisTest.unresolvedCommentSnapshotMetadataDriftIssueNumbers(
        context,
        [issueNumber],
      ),
      [issueNumber],
    );
  });

  it('rejects malformed accepted snapshot payloads before persistence', () => {
    const issueNumber = 990_006;
    const valid = remoteCommentSnapshot(
      issueNumber,
      '2026-07-03T05:00:00Z',
      [closureComment(601, '2026-07-03T04:30:00Z')],
    );
    assert.throws(
      () => __closureProofAnalysisTest.acceptedClosureCommentSnapshot(
        issueNumber,
        {
          ...valid,
          comments: [{ ...valid.comments[0], id: 0 }],
        },
      ),
      /invalid ID indexes 0/,
    );
  });

  it('refuses a manual proof write while the shared refresh lease is held elsewhere', () => {
    runIsolatedAnalysisScript('manual-proof-lease', `
      seedRelease('v-lease');
      assert.equal(
        db.acquireRefreshLease(
          db.REFRESH_WRITE_LEASE_NAME,
          'other-refresh',
          new Date().toISOString(),
          db.REFRESH_WRITE_LEASE_TTL_MS,
        ),
        true,
      );
      await assert.rejects(
        () => analysis.analyzeClosureProofsForRelease('v-lease', {
          persistScoreAuditPayload: false,
        }),
        /refresh already running in another process/,
      );
    `);
  });

  it('limits closure-comment PR proof to comments effectively dated in the final closure window', () => {
    const comments = [
      {
        body: 'Fixed by PR #1001.',
        created_at: '2026-07-03T11:00:00Z',
        updated_at: '2026-07-03T11:05:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Fixed by PR #1002.',
        created_at: '2026-07-03T09:00:00Z',
        updated_at: '2026-07-03T09:00:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Fixed by PR #1003.',
        created_at: '2026-07-03T12:01:00Z',
        updated_at: '2026-07-03T12:01:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Fixed by PR #1004.',
        created_at: '2026-07-03T11:30:00Z',
        updated_at: '2026-07-03T12:01:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Fixed by PR #1005.',
        created_at: '2026-06-20T11:30:00Z',
        updated_at: '2026-07-03T11:59:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
    ].map((comment, index) => ({
      ...comment,
      id: 20_001 + index,
      node_id: `IC_final_window_${index}`,
      node_type: 'IssueComment',
      user: {
        ...comment.user,
        id: `U_final_window_${index}`,
        type: 'User',
      },
    }));

    const mentions = __closureProofAnalysisTest.closureCommentPrMentionsForFinalClosure(
      9000,
      comments as any,
      {
        closedAt: '2026-07-03T12:00:00Z',
        finalReopenedAt: '2026-07-03T10:00:00Z',
      },
    );

    assert.deepEqual(mentions.map((mention: any) => mention.prNumber), [1001, 1005]);
  });

  it('fails closed at ambiguous same-second close and reopen boundaries', () => {
    const window = {
      closedAt: '2026-07-03T12:00:00.500Z',
      finalReopenedAt: '2026-07-03T11:00:00.500Z',
      closureActors: [],
    };

    assert.equal(
      __closureProofAnalysisTest.closureCommentIsInFinalClosureWindow(
        { created_at: '2026-07-03T12:00:00.500Z' },
        window,
      ),
      false,
    );
    assert.equal(
      __closureProofAnalysisTest.closureCommentIsInFinalClosureWindow(
        { created_at: '2026-07-03T11:00:00.500Z' },
        window,
      ),
      false,
    );
    assert.equal(
      __closureProofAnalysisTest.closureCommentIsInFinalClosureWindow(
        { created_at: '2026-07-03T11:00:00.501Z' },
        window,
      ),
      true,
    );
    assert.equal(
      __closureProofAnalysisTest.closureCommentIsInFinalClosureWindow(
        { created_at: '2026-07-03T12:00:00.499Z' },
        window,
      ),
      true,
    );
  });

  it('retries permissively cached PR misses when a later lookup is strict', async () => {
    const context = createClosureProofRunContext();
    const lookup = {
      prNumber: 99001,
      prRepositoryNameWithOwner: 'openclaw/openclaw',
    };
    const key = 'openclaw/openclaw#99001';
    let calls = 0;
    const lookupPullRequests = async (_lookups: any[], options: any = {}) => {
      calls++;
      if (calls === 1) {
        options.onMissingPullRequest?.({
          repositoryNameWithOwner: 'openclaw/openclaw',
          prNumber: 99001,
        });
        return new Map();
      }
      return new Map([[key, {
        number: 99001,
        repositoryOwner: 'openclaw',
        repositoryName: 'openclaw',
        repositoryNameWithOwner: 'openclaw/openclaw',
        repositoryUrl: 'https://github.com/openclaw/openclaw',
        title: 'Recovered strict lookup',
        url: 'https://github.com/openclaw/openclaw/pull/99001',
        state: 'MERGED',
        merged: true,
        mergedAt: '2026-07-03T10:00:00Z',
        mergeCommitOid: 'a'.repeat(40),
        baseRefName: 'main',
      }]]);
    };

    const permissive = await __closureProofAnalysisTest.pullRequestsForLookups(
      context,
      [lookup],
      {},
      lookupPullRequests as any,
    );
    assert.equal(permissive.size, 0);
    assert.equal(context.pullRequestsByKey.get(key), null);
    assert.equal(context.permissiveMissingPullRequestKeys?.has(key), true);

    const strict = await __closureProofAnalysisTest.pullRequestsForLookups(
      context,
      [lookup],
      { allowMissing: false },
      lookupPullRequests as any,
    );
    assert.equal(calls, 2);
    assert.equal(strict.get(key)?.number, 99001);
    assert.equal(context.permissiveMissingPullRequestKeys?.has(key), false);

    const concurrentContext = createClosureProofRunContext();
    let releasePermissive!: () => void;
    const permissiveGate = new Promise<void>((resolve) => {
      releasePermissive = resolve;
    });
    let concurrentCalls = 0;
    const concurrentLookup = async (_lookups: any[], options: any = {}) => {
      concurrentCalls++;
      if (concurrentCalls === 1) {
        await permissiveGate;
        options.onMissingPullRequest?.({
          repositoryNameWithOwner: 'openclaw/openclaw',
          prNumber: 99001,
        });
        return new Map();
      }
      return lookupPullRequests(_lookups, options);
    };
    const pendingPermissive = __closureProofAnalysisTest.pullRequestsForLookups(
      concurrentContext,
      [lookup],
      {},
      concurrentLookup as any,
    );
    const pendingStrict = __closureProofAnalysisTest.pullRequestsForLookups(
      concurrentContext,
      [lookup],
      { allowMissing: false },
      concurrentLookup as any,
    );
    releasePermissive();

    await pendingPermissive;
    const concurrentStrict = await pendingStrict;
    assert.equal(concurrentCalls, 2);
    assert.equal(concurrentStrict.get(key)?.number, 99001);
  });

  it('refreshes confirmed-missing PR metadata without turning absence into a transport failure', async () => {
    const context = createClosureProofRunContext();
    const lookup = {
      prNumber: 99002,
      prRepositoryNameWithOwner: 'openclaw/openclaw',
    };
    const key = 'openclaw/openclaw#99002';
    context.pullRequestsByKey.set(key, null);
    context.permissiveMissingPullRequestKeys?.add(key);
    let calls = 0;
    const lookupPullRequests = async (_lookups: any[], options: any = {}) => {
      calls++;
      options.onMissingPullRequest?.({
        repositoryNameWithOwner: 'openclaw/openclaw',
        prNumber: 99002,
      });
      return new Map();
    };

    const refreshed = await __closureProofAnalysisTest.pullRequestsForLookups(
      context,
      [lookup],
      { allowMissing: true, refreshMissing: true },
      lookupPullRequests as any,
    );
    assert.equal(calls, 1);
    assert.equal(refreshed.size, 0);
    assert.equal(context.pullRequestsByKey.get(key), null);
    assert.equal(context.permissiveMissingPullRequestKeys?.has(key), true);
  });

  it('never patches the current score audit and rejects the legacy opt-in', () => {
    runIsolatedAnalysisScript('score-audit-opt-in', `
      seedRelease('v-audit');
      db.upsertReleaseScoreAudit({
        release_tag: 'v-audit',
        scored_at: '2026-07-02T00:00:00Z',
        score_model_version: 'test-model',
        prompt_version: 1,
        final_score: 7.5,
        status: 'eligible',
        band: 'ok',
        recommended: 1,
        input_json: '{"schemaVersion":1,"rawIssueCount":0,"classifiedIssueCount":0}',
        components_json: '{"schemaVersion":1,"components":{},"explanation":{"schemaVersion":1}}',
        issue_evidence_json: '{"schemaVersion":1}',
        gate_evidence_json: '{"schemaVersion":1,"fixProvenance":{"verifiedFixedCount":0,"unverifiedClosedCount":0}}',
      });
      const original = db.getReleaseScoreAudit('v-audit').gate_evidence_json;
      await analysis.analyzeClosureProofsForRelease('v-audit', {
        preparedDependencies: prepared('v-audit', []),
        refreshPrReachability: false,
      });
      assert.equal(db.getReleaseScoreAudit('v-audit').gate_evidence_json, original);

      await assert.rejects(
        () => analysis.analyzeClosureProofsForRelease('v-audit', {
          preparedDependencies: prepared('v-audit', []),
          refreshPrReachability: false,
          persistScoreAuditPayload: true,
        }),
        /persistScoreAuditPayload=true is disabled.*rebuilding and sealing the full score run/,
      );
      assert.equal(db.getReleaseScoreAudit('v-audit').gate_evidence_json, original);
    `);
  });

  it('persists #99730 close rationale and rejects an untrusted equivalent', () => {
    runIsolatedAnalysisScript('issue-99730-close-rationale', `
      const tag = 'v2026.6.11';
      const closedAt = '2026-07-04T02:25:29Z';
      seedRelease(tag, '2026-06-30T16:06:39Z');
      const trustedComment = {
        id: 4880068765,
        url: 'https://github.com/openclaw/openclaw/issues/99730#issuecomment-4880068765',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
        body: 'Thanks for the report. I gave this a fresh shell check against current main, and I could not reproduce it anymore.\\n\\nClose: the exact npm version-mismatch report no longer reproduces because the current registry tarball identifies OpenClaw 2026.6.11; distinct package-parity reports remain open separately.',
        created_at: '2026-07-04T00:53:24Z',
        updated_at: '2026-07-04T02:25:28Z',
      };
      const untrustedComment = {
        ...trustedComment,
        id: 4880068766,
        url: 'https://github.com/openclaw/openclaw/issues/99731#issuecomment-4880068766',
        user: { login: 'drive-by-user' },
        author_association: 'NONE',
      };
      for (const [issueNumber, comment, closer] of [
        [99730, trustedComment, 'clawsweeper'],
        [99731, untrustedComment, 'maintainer'],
      ]) {
        const comments = [comment];
        const digest = commentEvidence.commentEvidenceDigest(1, comments);
        db.upsertIssue({
          number: issueNumber,
          state: 'closed',
          title: 'npm publish installs prior version',
          author: 'reporter',
          html_url: 'https://github.com/openclaw/openclaw/issues/' + issueNumber,
          created_at: '2026-07-04T00:52:07Z',
          updated_at: closedAt,
          closed_at: closedAt,
          comments: 1,
          labels: '["bug","regression","P2"]',
          is_bot: 0,
        });
        db.upsertIssueCommentSnapshot({
          issue_number: issueNumber,
          schema_version: 2,
          comment_count: 1,
          fetched_comment_count: 1,
          latest_comment_updated_at: comment.updated_at,
          comments_digest: digest,
          issue_updated_at: closedAt,
          comments_json: commentEvidence.serializeCommentEvidence(comments),
        });
        db.upsertClassification(
          issueNumber,
          classification,
          closedAt,
          1,
          digest,
        );
        db.upsertIssueClosureEvent({
          issue_number: issueNumber,
          event_id: 'closed-' + issueNumber,
          closed_at: closedAt,
          actor_login: closer,
          state_reason: 'NOT_PLANNED',
          closer_type: null,
          closer_number: null,
          closer_oid: null,
          raw_json: '{}',
        });
      }
      const dependencies = prepared(tag, [99730, 99731]);
      dependencies.allCommentsByIssue = new Map([
        [99730, [trustedComment]],
        [99731, [untrustedComment]],
      ]);
      await analysis.analyzeClosureProofsForRelease(tag, {
        preparedDependencies: dependencies,
        refreshPrReachability: false,
      });

      const trustedRow = db.db.prepare(
        'SELECT status, evidence_json FROM issue_closure_proofs WHERE release_tag=? AND issue_number=?'
      ).get(tag, 99730);
      const trustedEvidence = JSON.parse(trustedRow.evidence_json);
      assert.equal(trustedRow.status, 'not_planned');
      assert.equal(trustedEvidence.closureContextCommentCount, 1);
      assert.deepEqual(trustedEvidence.canonicalIssues, []);
      assert.deepEqual(trustedEvidence.linkedPrs, []);
      assert.deepEqual(trustedEvidence.fixCommitProof, []);
      assert.deepEqual(trustedEvidence.directFixCommitProof, []);
      assert.equal(trustedEvidence.nonActionableRationaleComments[0].databaseId, 4880068765);
      assert.equal(trustedEvidence.nonActionableRationaleComments[0].url, trustedComment.url);
      assert.equal(trustedEvidence.nonActionableRationaleComments[0].author, 'clawsweeper');
      assert.equal(trustedEvidence.nonActionableRationaleComments[0].createdAt, trustedComment.created_at);
      assert.equal(trustedEvidence.nonActionableRationaleComments[0].updatedAt, trustedComment.updated_at);

      const untrustedRow = db.db.prepare(
        'SELECT status, evidence_json FROM issue_closure_proofs WHERE release_tag=? AND issue_number=?'
      ).get(tag, 99731);
      const untrustedEvidence = JSON.parse(untrustedRow.evidence_json);
      assert.equal(untrustedRow.status, 'admin_not_planned_no_context');
      assert.equal(untrustedEvidence.closureContextCommentCount, 0);
      assert.deepEqual(untrustedEvidence.nonActionableRationaleComments, []);
    `);
  });

  it('credits only final-window comment proof and the final closure event PR', () => {
    runIsolatedAnalysisScript('final-closure-attribution', `
      const tag = 'v-final-window';
      const finalClosedAt = '2026-07-03T12:00:00Z';
      seedRelease(tag);
      for (const issueNumber of [1, 2, 3, 4, 5, 6, 7]) {
        seedIssue(issueNumber, finalClosedAt);
        seedPr(500 + issueNumber);
        seedReachability(tag, 500 + issueNumber);
      }

      seedClosure(1, 'closed-1-final', finalClosedAt);
      db.upsertIssuePrLink({
        issue_number: 1,
        pr_number: 501,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-07-03T11:30:00Z',
      });

      seedClosure(2, 'closed-2-final', finalClosedAt);
      db.upsertIssuePrLink({
        issue_number: 2,
        pr_number: 502,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-07-03T12:01:00Z',
      });

      seedClosure(3, 'closed-3-first', '2026-07-02T09:00:00Z');
      seedReopen(3, '2026-07-02T10:00:00Z');
      seedClosure(3, 'closed-3-final', finalClosedAt);
      db.upsertIssuePrLink({
        issue_number: 3,
        pr_number: 503,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-07-02T09:00:00Z',
      });

      seedClosure(4, 'closed-4-first', '2026-07-02T09:00:00Z', 'PullRequest', 504);
      seedReopen(4, '2026-07-02T10:00:00Z');
      seedClosure(4, 'closed-4-final', finalClosedAt);
      db.upsertIssuePrLink({
        issue_number: 4,
        pr_number: 504,
        source: 'ClosedEvent.closer',
        will_close_target: 1,
        referenced_at: '2026-07-02T09:00:00Z',
      });
      db.upsertIssuePrLink({
        issue_number: 4,
        pr_number: 504,
        source: 'closedByPullRequestsReferences',
        will_close_target: 1,
        referenced_at: '2026-07-02T09:00:00Z',
      });

      seedClosure(5, 'closed-5-final', finalClosedAt, 'PullRequest', 505);
      db.upsertIssuePrLink({
        issue_number: 5,
        pr_number: 505,
        source: 'closedByPullRequestsReferences',
        will_close_target: 1,
        referenced_at: finalClosedAt,
      });

      seedClosure(6, 'closed-6-final', finalClosedAt);
      db.upsertIssuePrLink({
        issue_number: 6,
        pr_number: 506,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: finalClosedAt,
      });

      seedClosure(7, 'closed-7-first', '2026-07-03T10:00:00Z');
      seedReopen(7, '2026-07-03T11:00:00Z');
      seedClosure(7, 'closed-7-final', finalClosedAt);
      db.upsertIssuePrLink({
        issue_number: 7,
        pr_number: 507,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-07-03T11:00:00Z',
      });

      seedIssue(8, '2026-07-03T12:00:00.500Z');
      seedPr(508);
      seedReachability(tag, 508);
      seedClosure(8, 'closed-8-final', '2026-07-03T12:00:00.500Z');
      db.upsertIssuePrLink({
        issue_number: 8,
        pr_number: 508,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-07-03T12:00:00.499Z',
      });

      seedIssue(9, finalClosedAt);
      seedPr(509);
      seedReachability(tag, 509);
      seedClosure(9, 'closed-9-first', '2026-07-03T10:00:00Z');
      seedReopen(9, '2026-07-03T11:00:00.500Z');
      seedClosure(9, 'closed-9-final', finalClosedAt);
      db.upsertIssuePrLink({
        issue_number: 9,
        pr_number: 509,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-07-03T11:00:00.501Z',
      });

      await analysis.analyzeClosureProofsForRelease(tag, {
        preparedDependencies: prepared(tag, [1, 2, 3, 4, 5, 6, 7, 8, 9]),
        refreshPrReachability: false,
      });
      const statuses = Object.fromEntries(db.db.prepare(
        'SELECT issue_number, status FROM issue_closure_proofs WHERE release_tag=? ORDER BY issue_number'
      ).all(tag).map((row) => [row.issue_number, row.status]));

      assert.equal(statuses[1], 'fixed_in_release');
      assert.equal(statuses[2], 'closed_without_release_fix_proof');
      assert.equal(statuses[3], 'closed_without_release_fix_proof');
      assert.equal(statuses[4], 'closed_without_release_fix_proof');
      assert.equal(statuses[5], 'fixed_in_release');
      assert.equal(statuses[6], 'closed_without_release_fix_proof');
      assert.equal(statuses[7], 'closed_without_release_fix_proof');
      assert.equal(statuses[8], 'fixed_in_release');
      assert.equal(statuses[9], 'fixed_in_release');
      for (const issueNumber of [1, 5, 8, 9]) {
        const evidence = JSON.parse(db.db.prepare(
          'SELECT evidence_json FROM issue_closure_proofs WHERE release_tag=? AND issue_number=?'
        ).get(tag, issueNumber).evidence_json);
        assert.equal(evidence.linkedPrs[0].trustedFixProof, 1);
      }
    `);
  });

  it('uses exactly the final close event by timestamp and connection ordinal', () => {
    runIsolatedAnalysisScript('final-close-event-order', `
      const tag = 'v-final-close-order';
      const finalClosedAt = '2026-07-03T12:00:00Z';
      seedRelease(tag);
      for (const issueNumber of [1, 2]) {
        seedIssue(issueNumber, finalClosedAt);
        seedPr(500 + issueNumber);
        seedReachability(tag, 500 + issueNumber);
      }

      db.upsertIssueClosureEvent({
        issue_number: 1,
        event_id: 'close-1-completed',
        closed_at: '2026-07-03T11:59:59Z',
        connection_ordinal: 0,
        actor_login: 'old-contributor',
        state_reason: 'COMPLETED',
        closer_type: 'PullRequest',
        closer_number: 501,
        closer_oid: 'merge-501',
        raw_json: '{}',
      });
      db.upsertIssueClosureEvent({
        issue_number: 1,
        event_id: 'close-1-not-planned',
        closed_at: finalClosedAt,
        connection_ordinal: 1,
        actor_login: 'final-contributor',
        state_reason: 'NOT_PLANNED',
        closer_type: null,
        closer_number: null,
        closer_oid: null,
        raw_json: '{}',
      });
      db.upsertIssuePrLink({
        issue_number: 1,
        pr_number: 501,
        source: 'ClosedEvent.closer',
        will_close_target: 1,
        referenced_at: '2026-07-03T11:59:59Z',
      });

      db.upsertIssueClosureEvent({
        issue_number: 2,
        event_id: 'close-2-completed',
        closed_at: finalClosedAt,
        connection_ordinal: 0,
        actor_login: 'old-contributor',
        state_reason: 'COMPLETED',
        closer_type: 'PullRequest',
        closer_number: 502,
        closer_oid: 'merge-502',
        raw_json: '{}',
      });
      db.upsertIssueClosureEvent({
        issue_number: 2,
        event_id: 'close-2-not-planned',
        closed_at: finalClosedAt,
        connection_ordinal: 1,
        actor_login: 'final-ordinal-contributor',
        state_reason: 'NOT_PLANNED',
        closer_type: null,
        closer_number: null,
        closer_oid: null,
        raw_json: '{}',
      });
      db.upsertIssuePrLink({
        issue_number: 2,
        pr_number: 502,
        source: 'ClosedEvent.closer',
        will_close_target: 1,
        referenced_at: finalClosedAt,
      });

      const oldCommit = 'a'.repeat(40);
      const dependencies = prepared(tag, [1, 2]);
      dependencies.allCommentsByIssue = new Map([
        [1, [
          {
            body: 'Fixed by commit ' + oldCommit + '.',
            created_at: '2026-07-03T11:59:58Z',
            user: { login: 'old-contributor' },
            author_association: 'CONTRIBUTOR',
          },
          {
            body: 'Close: expected behavior.',
            created_at: '2026-07-03T11:59:59Z',
            user: { login: 'final-contributor' },
            author_association: 'CONTRIBUTOR',
          },
        ]],
        [2, []],
      ]);
      await analysis.analyzeClosureProofsForRelease(tag, {
        preparedDependencies: dependencies,
        refreshPrReachability: false,
      });

      const proofs = db.db.prepare(
        'SELECT issue_number, status, evidence_json FROM issue_closure_proofs WHERE release_tag=? ORDER BY issue_number'
      ).all(tag);
      const first = JSON.parse(proofs[0].evidence_json);
      const second = JSON.parse(proofs[1].evidence_json);
      assert.equal(proofs[0].status, 'not_planned');
      assert.equal(proofs[1].status, 'admin_not_planned_no_context');
      assert.deepEqual(first.stateReasons, ['NOT_PLANNED']);
      assert.deepEqual(first.closureActors, ['final-contributor']);
      assert.deepEqual(first.directFixCommitProof, []);
      assert.deepEqual(first.linkedPrs, []);
      assert.deepEqual(second.stateReasons, ['NOT_PLANNED']);
      assert.deepEqual(second.closureActors, ['final-ordinal-contributor']);
      assert.deepEqual(second.linkedPrs, []);
    `);
  });

  it('accepts 0/1/2-second final-close skew and rejects 3 seconds', () => {
    runIsolatedAnalysisScript('final-close-event-mismatch', `
      const issueClosedAt = '2026-07-03T12:00:00Z';
      for (const skewSeconds of [0, 1, 2]) {
        const tag = 'v-final-close-skew-' + skewSeconds;
        const issueNumber = 100 + skewSeconds;
        seedRelease(tag);
        seedIssue(issueNumber, issueClosedAt);
        seedClosure(
          issueNumber,
          'close-skew-' + skewSeconds,
          new Date(Date.parse(issueClosedAt) - skewSeconds * 1000).toISOString(),
        );
        await analysis.analyzeClosureProofsForRelease(tag, {
          preparedDependencies: prepared(tag, [issueNumber]),
          refreshPrReachability: false,
        });
        assert.equal(db.closureProofRows(tag).length, 1);
      }

      const rejectedTag = 'v-final-close-skew-3';
      seedRelease(rejectedTag);
      seedIssue(103, issueClosedAt);
      seedClosure(103, 'close-skew-3', '2026-07-03T11:59:57Z');
      await assert.rejects(
        () => analysis.analyzeClosureProofsForRelease(rejectedTag, {
          preparedDependencies: prepared(rejectedTag, [103]),
          refreshPrReachability: false,
        }),
        /Issue #103 closed_at .* does not match selected final closure event/,
      );
      assert.equal(db.closureProofRows(rejectedTag).length, 0);

      for (const skewSeconds of [1, 2]) {
        analysis.__closureProofAnalysisTest.assertIssueClosedAtMatchesSelectedFinalEvent(
          200 + skewSeconds,
          issueClosedAt,
          new Date(Date.parse(issueClosedAt) + skewSeconds * 1000).toISOString(),
        );
      }
      assert.throws(
        () => analysis.__closureProofAnalysisTest.assertIssueClosedAtMatchesSelectedFinalEvent(
          203,
          issueClosedAt,
          '2026-07-03T12:00:03Z',
        ),
        /does not match selected final closure event/,
      );
    `);
  });

  it('uses the selected close event, not the issue timestamp, for canonical comment ordering', () => {
    runIsolatedAnalysisScript('canonical-selected-close-order', `
      const tag = 'v-canonical-selected-close';
      const issueClosedAt = '2026-07-03T12:00:00.500Z';
      const eventClosedAt = '2026-07-03T11:59:59.500Z';
      seedRelease(tag);
      for (const issueNumber of [1, 2]) {
        seedIssue(issueNumber, issueClosedAt);
        seedClosure(issueNumber, 'close-' + issueNumber, eventClosedAt);
      }
      db.upsertIssueClosureProof({
        release_tag: tag,
        issue_number: 1,
        status: 'direct_fix_commit_reachability_unknown',
        summary: 'Stale direct commit reachability.',
        evidence_json: JSON.stringify({
          directFixCommitProof: [{ status: 'unknown' }],
        }),
      });
      db.db.prepare(
        'UPDATE issue_closure_proofs SET checked_at=? WHERE release_tag=? AND issue_number=?'
      ).run('2000-01-01T00:00:00Z', tag, 1);
      db.upsertIssue({
        number: 20,
        state: 'open',
        title: 'Canonical issue',
        author: 'reporter',
        html_url: 'https://example.test/issues/20',
        created_at: '2026-07-01T12:00:00Z',
        updated_at: issueClosedAt,
        closed_at: null,
        comments: 0,
        labels: '[]',
        is_bot: 0,
      });

      const exactBoundaryComment = {
        id: 1001,
        url: 'https://example.test/comments/1001',
        body: 'Closing as duplicate of issue #20.',
        created_at: eventClosedAt,
        updated_at: eventClosedAt,
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      };
      const provablyBeforeComment = {
        ...exactBoundaryComment,
        id: 1002,
        url: 'https://example.test/comments/1002',
        created_at: '2026-07-03T11:59:59.499Z',
        updated_at: '2026-07-03T11:59:59.499Z',
      };
      const context = analysis.createClosureProofRunContext({
        assertCanWrite: () => {},
      });
      for (const [issueNumber, comments] of [
        [1, [exactBoundaryComment]],
        [2, [provablyBeforeComment]],
        [20, []],
      ]) {
        context.commentSnapshotsByIssue.set(
          issueNumber,
          seedAuthoritativeCommentSnapshot(
            tag,
            issueNumber,
            issueClosedAt,
            comments,
          ),
        );
      }

      const discovered = await analysis.discoverClosureProofDependenciesForRelease(tag, {
        runContext: context,
        refreshCommentPrMentionEvidence: false,
      });
      assert.deepEqual(discovered.canonicalGraph.get(1), []);
      assert.deepEqual(discovered.canonicalGraph.get(2), [20]);
      assert.equal(db.closureProofRows(tag).length, 0);
    `);
  });

  it('expires unknown direct-commit proof and recomputes it to reachable', () => {
    runIsolatedAnalysisScript('direct-commit-unknown-retry', `
      const predecessorTag = 'v-direct-commit-prior';
      const tag = 'v-direct-commit-retry';
      const issueNumber = 301;
      const predecessorCommit = 'c'.repeat(40);
      const releaseCommit = 'a'.repeat(40);
      const fixCommit = 'b'.repeat(40);
      const closedAt = '2026-07-03T12:00:00Z';
      const checkedAt = '2030-01-01T00:00:00.000Z';
      const checkedAtMs = Date.parse(checkedAt);
      seedRelease(predecessorTag, '2026-07-02T00:00:00Z', predecessorCommit);
      seedRelease(tag, '2026-07-03T00:00:00Z', releaseCommit);
      db.upsertReleaseCommit({
        tag: predecessorTag,
        tag_commit_oid: predecessorCommit,
        committed_at: '2026-07-02T00:00:00Z',
      });
      db.upsertReleaseCommit({
        tag,
        tag_commit_oid: releaseCommit,
        committed_at: '2026-07-03T00:00:00Z',
      });
      seedIssue(issueNumber, closedAt);
      seedClosure(issueNumber, 'close-direct-commit', closedAt);
      db.upsertIssueClosureProof({
        release_tag: tag,
        issue_number: issueNumber,
        status: 'direct_fix_commit_reachability_unknown',
        summary: 'Direct fix commit reachability is unknown.',
        evidence_json: JSON.stringify({
          directFixCommitProof: [{
            commitOid: fixCommit,
            status: 'unknown',
            evidence: 'commit_unavailable',
          }],
        }),
      });
      db.db.prepare(
        'UPDATE issue_closure_proofs SET checked_at=? WHERE release_tag=? AND issue_number=?'
      ).run(checkedAt, tag, issueNumber);

      assert.equal(
        analysis.__closureProofAnalysisTest.invalidateExpiredUnknownDirectCommitProofs(
          tag,
          checkedAtMs + analysis.__closureProofAnalysisTest.UNKNOWN_REACHABILITY_RETRY_MS,
        ),
        0,
      );
      assert.equal(db.closureProofRows(tag).length, 1);
      assert.equal(
        analysis.__closureProofAnalysisTest.invalidateExpiredUnknownDirectCommitProofs(
          tag,
          checkedAtMs + analysis.__closureProofAnalysisTest.UNKNOWN_REACHABILITY_RETRY_MS + 1,
        ),
        1,
      );
      assert.equal(db.closureProofRows(tag).length, 0);

      const dependencies = prepared(tag, [issueNumber]);
      dependencies.allCommentsByIssue.set(issueNumber, [{
        id: 30101,
        url: 'https://example.test/comments/30101',
        body: 'Close: fixed by commit ' + fixCommit + '.',
        created_at: '2026-07-03T11:59:59Z',
        updated_at: '2026-07-03T11:59:59Z',
        node_id: 'IC_direct_commit_retry',
        node_type: 'IssueComment',
        user: {
          id: 'U_direct_commit_maintainer',
          type: 'User',
          login: 'maintainer',
        },
        author_association: 'MEMBER',
      }]);
      const remoteTagChecks = [];
      const ancestryChecks = [];
      await analysis.analyzeClosureProofsForRelease(tag, {
        preparedDependencies: dependencies,
        refreshPrReachability: false,
        reachabilityContext: {
          concurrency: 1,
          inspectRepository: async () => ({
            status: 'ready',
            shallow: false,
            command: {
              status: 0,
              stdout: '',
              stderr: '',
              signal: null,
            },
          }),
          ensureObject: async () => ({ status: 'available' }),
          resolveRemoteTagCommit: async (remoteTag) => {
            remoteTagChecks.push(remoteTag);
            const tagCommitOid = remoteTag === tag
              ? releaseCommit
              : remoteTag === predecessorTag
                ? predecessorCommit
                : null;
            assert.ok(tagCommitOid, 'unexpected remote tag ' + remoteTag);
            return {
              status: 'resolved',
              tagCommitOid,
              command: {
                status: 0,
                stdout: tagCommitOid + '\\trefs/tags/' + remoteTag + '\\n',
                stderr: '',
                signal: null,
              },
            };
          },
          checkAncestor: async (commitOid, tagCommitOid) => {
            ancestryChecks.push([commitOid, tagCommitOid]);
            return {
              status: commitOid === fixCommit && tagCommitOid === predecessorCommit
                ? 1
                : 0,
              stdout: '',
              stderr: '',
              signal: null,
            };
          },
        },
      });

      const proof = db.closureProofRows(tag)[0];
      const evidence = JSON.parse(proof.evidence_json);
      assert.deepEqual(remoteTagChecks, [tag, predecessorTag]);
      assert.deepEqual(ancestryChecks, [
        [fixCommit, releaseCommit],
        [predecessorCommit, releaseCommit],
        [fixCommit, predecessorCommit],
        [fixCommit, releaseCommit],
      ]);
      assert.equal(proof.status, 'fixed_in_release');
      assert.equal(evidence.directFixCommitProof[0].status, 'reachable');
      assert.equal(evidence.directFixCommitProof[0].commitOid, fixCommit);
      assert.equal(
        evidence.directCommitFirstContainingProofs[0].reasonCode,
        'first_containing_direct_commit',
      );
    `);
  });

  it('rolls an earlier canonical fix across duplicate cluster members without direct fix credit', () => {
    runIsolatedAnalysisScript('earlier-canonical-fix-cluster', `
      const priorTag = 'v-prior';
      const tag = 'v-current';
      const canonicalIssueNumber = 20;
      const duplicateIssueNumbers = [1, 2];
      const canonicalClosedAt = '2026-07-01T18:00:00Z';
      const duplicateClosedAt = '2026-07-03T12:00:00Z';

      seedRelease(priorTag, '2026-07-01T00:00:00Z');
      seedRelease(tag, '2026-07-02T00:00:00Z');
      seedIssue(canonicalIssueNumber, canonicalClosedAt);
      seedClosure(
        canonicalIssueNumber,
        'closed-canonical',
        canonicalClosedAt,
        'PullRequest',
        900,
      );
      seedPr(900);
      seedReachability(tag, 900);
      db.upsertIssuePrLink({
        issue_number: canonicalIssueNumber,
        pr_number: 900,
        source: 'ClosedEvent.closer',
        will_close_target: 1,
        referenced_at: canonicalClosedAt,
      });
      db.upsertIssueClosureProof({
        release_tag: priorTag,
        issue_number: canonicalIssueNumber,
        status: 'fixed_in_release',
        summary: 'Canonical fix was credited by the earlier release audit.',
        evidence_json: '{}',
      });

      const allCommentsByIssue = new Map([[canonicalIssueNumber, []]]);
      for (const issueNumber of duplicateIssueNumbers) {
        seedIssue(issueNumber, duplicateClosedAt);
        seedClosure(issueNumber, 'closed-duplicate-' + issueNumber, duplicateClosedAt);
        allCommentsByIssue.set(issueNumber, [{
          id: 10_000 + issueNumber,
          url: 'https://example.test/comments/' + issueNumber,
          user: { login: 'maintainer' },
          author_association: 'MEMBER',
          body: 'Closing as duplicate of issue #' + canonicalIssueNumber + '.',
          created_at: '2026-07-03T11:30:00Z',
          updated_at: '2026-07-03T11:30:00Z',
        }]);
      }

      await analysis.analyzeClosureProofsForRelease(tag, {
        preparedDependencies: {
          releaseTag: tag,
          analysisStartedAt: '2026-07-04T00:00:00Z',
          labelCutoff: null,
          issueNumbers: duplicateIssueNumbers,
          sourceIssueNumbers: new Set(duplicateIssueNumbers),
          allCommentsByIssue,
          canonicalGraph: new Map([
            [1, [canonicalIssueNumber]],
            [2, [canonicalIssueNumber]],
            [canonicalIssueNumber, []],
          ]),
          analysisIssueNumbers: [...duplicateIssueNumbers, canonicalIssueNumber],
        },
        refreshPrReachability: false,
      });

      const proofRows = db.db.prepare(
        'SELECT issue_number, status, summary, evidence_json FROM issue_closure_proofs WHERE release_tag=? ORDER BY issue_number'
      ).all(tag);
      assert.deepEqual(
        proofRows.map((row) => [row.issue_number, row.status]),
        [
          [1, 'duplicate_to_fixed_in_release'],
          [2, 'duplicate_to_fixed_in_release'],
        ],
      );
      assert.equal(proofRows.some((row) => row.status === 'fixed_in_release'), false);
      for (const row of proofRows) {
        assert.match(row.summary, /reachable from this release tag/i);
        assert.match(row.summary, /without direct fix credit/i);
        assert.doesNotMatch(row.summary, /fixed in this release/i);
        const evidence = JSON.parse(row.evidence_json);
        assert.equal(evidence.canonicalResolution.currentTagContainsAllCanonicalFixes, true);
        assert.equal(evidence.canonicalResolution.branches[0].currentTagContainsFix, true);
      }

      const payloadModuleImport = await import('./src/lib/closureProofPayload.ts');
      const payloadModule = payloadModuleImport.default ?? payloadModuleImport;
      const payload = payloadModule.closureProofPayload(tag);
      assert.equal(payload.creditedCount, 0);
      assert.equal(payload.notCreditedCount, 2);
      assert.equal(payload.riskSummary.resolvedByCanonicalReleaseFixCount, 2);
      assert.equal(payload.riskSummary.unresolvedForReleaseCount, 0);
      assert.equal(payload.riskSummary.unresolvedWeightedRisk, 0);
    `);
  });

  it('includes transitive canonical nodes in revision baselines and the dependency snapshot', () => {
    runIsolatedAnalysisScript('transitive-canonical-dependencies', `
      const tag = 'v-transitive';
      const closedAt = '2026-07-03T12:00:00Z';
      seedRelease(tag);
      for (const issueNumber of [1, 20, 30]) {
        seedIssue(issueNumber, closedAt);
        seedClosure(issueNumber, 'closed-' + issueNumber, closedAt);
      }
      seedPr(930);
      seedReachability(tag, 930);
      seedClosure(30, 'closed-30-by-pr', closedAt, 'PullRequest', 930);
      db.upsertIssuePrLink({
        issue_number: 30,
        pr_number: 930,
        source: 'ClosedEvent.closer',
        will_close_target: 1,
        referenced_at: closedAt,
      });

      const duplicateComment = (issueNumber, targetNumber) => [{
        id: 20_000 + issueNumber,
        url: 'https://example.test/comments/' + issueNumber,
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
        body: 'Closing as duplicate of issue #' + targetNumber + '.',
        created_at: '2026-07-03T11:30:00Z',
        updated_at: '2026-07-03T11:30:00Z',
      }];
      const runContext = analysis.createClosureProofRunContext({
        assertCanWrite: () => {},
      });

      await analysis.analyzeClosureProofsForRelease(tag, {
        runContext,
        preparedDependencies: {
          releaseTag: tag,
          analysisStartedAt: '2026-07-04T00:00:00Z',
          labelCutoff: null,
          issueNumbers: [1],
          sourceIssueNumbers: new Set([1]),
          allCommentsByIssue: new Map([
            [1, duplicateComment(1, 20)],
            [20, duplicateComment(20, 30)],
            [30, []],
          ]),
          canonicalGraph: new Map([
            [1, [20]],
            [20, [30]],
            [30, []],
          ]),
          analysisIssueNumbers: [1],
        },
        refreshPrReachability: false,
      });

      assert.deepEqual(
        [...runContext.issueEvidenceRevisionsByIssue.keys()].sort((left, right) => left - right),
        [1, 20, 30],
      );
      const snapshot = db.getReleaseClosureDependencySnapshot(tag);
      assert.ok(snapshot);
      assert.deepEqual(JSON.parse(snapshot.issue_numbers_json), [1, 20, 30]);
      assert.equal(
        db.db.prepare(
          'SELECT status FROM issue_closure_proofs WHERE release_tag=? AND issue_number=1'
        ).get(tag).status,
        'duplicate_to_fixed_in_release',
      );
      const evidence = JSON.parse(db.db.prepare(
        'SELECT evidence_json FROM issue_closure_proofs WHERE release_tag=? AND issue_number=1'
      ).get(tag).evidence_json);
      assert.deepEqual(evidence.canonicalIssues, [20, 30]);
    `);
  });

  it('persists every branching, transitive, and cyclic canonical graph node', () => {
    runIsolatedAnalysisScript('branching-cycle-canonical-dependencies', `
      const tag = 'v-branch-cycle';
      const closedAt = '2026-07-03T12:00:00Z';
      seedRelease(tag);
      for (const issueNumber of [1, 20, 30, 40]) {
        seedIssue(issueNumber, closedAt);
        seedClosure(issueNumber, 'closed-' + issueNumber, closedAt);
      }
      const duplicateComment = (issueNumber, targetNumbers) => [{
        id: 30_000 + issueNumber,
        url: 'https://example.test/comments/' + issueNumber,
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
        body: targetNumbers.map((targetNumber) =>
          'Closing as duplicate of issue #' + targetNumber + '.'
        ).join('\\n'),
        created_at: '2026-07-03T11:30:00Z',
        updated_at: '2026-07-03T11:30:00Z',
      }];

      await analysis.analyzeClosureProofsForRelease(tag, {
        preparedDependencies: {
          releaseTag: tag,
          analysisStartedAt: '2026-07-04T00:00:00Z',
          labelCutoff: null,
          issueNumbers: [1],
          sourceIssueNumbers: new Set([1]),
          allCommentsByIssue: new Map([
            [1, duplicateComment(1, [20, 30])],
            [20, duplicateComment(20, [40])],
            [30, []],
            [40, duplicateComment(40, [20])],
          ]),
          canonicalGraph: new Map([
            [1, [20, 30]],
            [20, [40]],
            [30, []],
            [40, [20]],
          ]),
          analysisIssueNumbers: [1],
        },
        refreshPrReachability: false,
      });

      const snapshot = db.getReleaseClosureDependencySnapshot(tag);
      assert.ok(snapshot);
      assert.deepEqual(JSON.parse(snapshot.issue_numbers_json), [1, 20, 30, 40]);
      const proof = db.db.prepare(
        'SELECT evidence_json FROM issue_closure_proofs WHERE release_tag=? AND issue_number=1'
      ).get(tag);
      const evidence = JSON.parse(proof.evidence_json);
      assert.deepEqual(evidence.canonicalIssues, [20, 30, 40]);
      assert.deepEqual(
        evidence.canonicalResolution.branches.map((branch) => branch.path),
        [[1, 20, 40, 20], [1, 30]],
      );
      assert.equal(evidence.canonicalResolution.cycle, true);
    `);
  });

  it('expands canonical chains from fetched canonical issue comments', async () => {
    const graph = new Map([[10, [20]]]);
    const comments = new Map<number, any[]>([
      [10, [{
        body: 'Closing as duplicate of #20.',
        created_at: '2026-06-28T10:00:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      }]],
    ]);

    await __closureProofAnalysisTest.expandCanonicalGraph(
      graph,
      comments,
      [20],
      async (numbers: number[]) => new Map(numbers.map((number) => [
        number,
        number === 20 ? [{
          body: 'Closing as duplicate. Root-cause tracker: #30',
          created_at: '2026-06-28T10:00:00Z',
          user: { login: 'maintainer' },
          author_association: 'MEMBER',
        }] : [],
      ])),
      false,
      (numbers: number[]) => new Map(numbers.map((number) => [
        number,
        {
          closedAt: '2026-06-28T10:05:00Z',
          finalReopenedAt: null,
          closureActors: ['maintainer'],
        },
      ])),
      () => true,
    );

    assert.deepEqual(graph.get(20), [30]);
    assert.deepEqual(__closureProofAnalysisTest.canonicalIssueNumbersReachableFrom(10, graph), [20, 30]);
  });

  it('rejects third-party canonical edges unless the commenter is the final closer', () => {
    const comments = [
      {
        body: 'Closing as duplicate of #20.',
        created_at: '2026-06-28T10:00:00Z',
        user: { login: 'drive-by-user' },
        author_association: 'NONE',
      },
      {
        body: 'Closing as duplicate of #30.',
        created_at: '2026-06-28T10:01:00Z',
        user: { login: 'reporter-closer' },
        author_association: 'NONE',
      },
      {
        body: 'Closing as duplicate of #40.',
        created_at: '2026-06-28T10:02:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
    ];

    assert.deepEqual(
      __closureProofAnalysisTest.trustedCanonicalIssueNumbersFromComments(
        comments as any,
        10,
        {
          closedAt: '2026-06-28T10:05:00Z',
          finalReopenedAt: null,
          closureActors: ['reporter-closer'],
        },
        () => true,
      ),
      [30, 40],
    );
  });

  it('accepts generic closure rationale only from trusted participants', () => {
    const comments = [
      {
        body: 'Close: no longer reproducible.',
        user: { login: 'drive-by-user' },
        author_association: 'NONE',
      },
      {
        body: 'Close: I am withdrawing my report.',
        user: { login: 'reporter' },
        author_association: 'NONE',
      },
      {
        body: 'Close: verified as expected behavior.',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Close: final review completed.',
        user: { login: 'release-closer' },
        author_association: 'CONTRIBUTOR',
      },
      {
        body: 'Close: exact mismatch no longer reproduces.',
        user: { login: 'clawsweeper' },
        author_association: 'CONTRIBUTOR',
      },
    ];

    assert.deepEqual(
      __closureProofAnalysisTest.trustedClosureRationaleComments(
        comments as any,
        'reporter',
        ['release-closer'],
      ).map((comment: any) => comment.user.login),
      ['reporter', 'maintainer', 'release-closer'],
    );
  });

  it('rejects post-close and pre-final-reopen canonical or fix-proof comments', () => {
    const comments = [
      {
        body: 'Closing as duplicate of issue #20.\nFixed by PR #200.',
        created_at: '2026-07-03T10:30:00Z',
        updated_at: '2026-07-03T11:00:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Closing as duplicate of issue #30.\nFixed by PR #300.',
        created_at: '2026-07-03T12:01:00Z',
        updated_at: '2026-07-03T12:01:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Closing as duplicate of issue #40.\nFixed by PR #400.',
        created_at: '2026-07-03T11:30:00Z',
        updated_at: '2026-07-03T12:01:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
      {
        body: 'Closing as duplicate of issue #50.\nFixed by PR #500.',
        created_at: '2026-07-03T09:00:00Z',
        updated_at: '2026-07-03T09:00:00Z',
        user: { login: 'maintainer' },
        author_association: 'MEMBER',
      },
    ].map((comment, index) => ({
      ...comment,
      id: 30_001 + index,
      node_id: `IC_close_boundary_${index}`,
      node_type: 'IssueComment',
      user: {
        ...comment.user,
        id: `U_close_boundary_${index}`,
        type: 'User',
      },
    }));
    const finalWindow = {
      closedAt: '2026-07-03T12:00:00Z',
      finalReopenedAt: '2026-07-03T10:00:00Z',
    };

    assert.deepEqual(
      __closureProofAnalysisTest.trustedCanonicalIssueNumbersFromComments(
        comments as any,
        10,
        {
          ...finalWindow,
          closureActors: ['maintainer'],
        },
        () => true,
      ),
      [20],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.closureCommentPrMentionsForFinalClosure(
        10,
        comments as any,
        finalWindow,
      ).map((mention: any) => mention.prNumber),
      [200],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.closureRationaleCommentsForFinalClosure(
        comments as any,
        finalWindow,
      ).map((comment: any) => comment.body),
      [comments[0].body],
    );
  });

  it('keeps edited explicit-close rationale when other issues remain open', () => {
    const comments = [{
      id: 4880068765,
      url: 'https://github.com/openclaw/openclaw/issues/99730#issuecomment-4880068765',
      user: { login: 'clawsweeper' },
      author_association: 'CONTRIBUTOR',
      body: 'Thanks for the report. I gave this a fresh shell check against current `main`, and I could not reproduce it anymore.\n\nClose: the exact npm version-mismatch report no longer reproduces because the current registry tarball identifies OpenClaw 2026.6.11; distinct 6.11 dist-parity and local update-prefix reports remain open separately.',
      created_at: '2026-07-04T00:53:24Z',
      updated_at: '2026-07-04T02:25:28Z',
    }];

    const rationale = __closureProofAnalysisTest.closureRationaleCommentsForFinalClosure(
      comments as any,
      {
        closedAt: '2026-07-04T02:25:29Z',
        finalReopenedAt: null,
      },
    );

    assert.deepEqual(rationale, comments);
  });

  it('applies close-window and keep-open filtering to downstream canonical comments', async () => {
    const graph = new Map([[10, [20]]]);
    const comments = new Map<number, any[]>();

    await __closureProofAnalysisTest.expandCanonicalGraph(
      graph,
      comments,
      [20],
      async () => new Map([[
        20,
        [
          {
            body: 'Closing as duplicate of #30.',
            created_at: '2026-06-20T10:00:00Z',
            user: { login: 'maintainer' },
            author_association: 'MEMBER',
          },
          {
            body: 'Keep open: canonical tracker is #40.',
            created_at: '2026-06-28T10:00:00Z',
            user: { login: 'maintainer' },
            author_association: 'MEMBER',
          },
        ],
      ]]),
      false,
      () => new Map([[
        20,
        {
          closedAt: '2026-06-28T10:05:00Z',
          finalReopenedAt: null,
          closureActors: ['maintainer'],
        },
      ]]),
      () => true,
    );

    assert.deepEqual(graph.get(20), []);
    assert.deepEqual(__closureProofAnalysisTest.canonicalIssueNumbersReachableFrom(10, graph), [20]);
  });

  it('requires every canonical branch to resolve before granting fixed credit', () => {
    const graph = new Map([[10, [20, 30]]]);
    const issue = (number: number, state: string) => ({
      number,
      title: `issue ${number}`,
      state,
      url: null,
    });
    const fixedResults = new Map([[20, result('fixed_in_release', 'Branch 20 fixed.')]]);
    const conflictingEvidence = {
      canonicalIssues: [20, 30],
      relatedPrContext: {
        reachable: [{
          number: 999,
          repositoryNameWithOwner: 'openclaw/openclaw',
          source: 'ClosureComment.fixProof',
        }],
      },
    };

    const openConflict = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      conflictingEvidence,
      graph,
      fixedResults,
      null,
      () => null,
      (number: number) => issue(number, number === 30 ? 'open' : 'closed'),
    );
    assert.equal(openConflict.status, 'duplicate_to_open_canonical');
    assert.deepEqual((openConflict.evidence.canonicalResolution as any).blockingBranch, [10, 30]);

    const unresolvedConflict = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      conflictingEvidence,
      graph,
      fixedResults,
      null,
      () => null,
      (number: number) => issue(number, 'closed'),
    );
    assert.equal(unresolvedConflict.status, 'duplicate_to_closed_canonical_missing_proof');
    assert.deepEqual((unresolvedConflict.evidence.canonicalResolution as any).blockingBranch, [10, 30]);

    const allFixed = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20, 30] },
      graph,
      new Map([
        [20, result('fixed_in_release', 'Branch 20 fixed.')],
        [30, result('fixed_in_release', 'Branch 30 fixed.')],
      ]),
      null,
      () => null,
      (number: number) => issue(number, 'closed'),
    );
    assert.equal(allFixed.status, 'duplicate_to_fixed_in_release');
    assert.equal((allFixed.evidence.canonicalResolution as any).branches.length, 2);
  });

  it('selects the worst credible branch regardless of canonical issue-number ordering', () => {
    for (const [neutralIssueNumber, adverseIssueNumber] of [
      [20, 30],
      [30, 20],
    ] as const) {
      const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
        10,
        result('duplicate_or_superseded', 'Closed as duplicate.'),
        { canonicalIssues: [neutralIssueNumber, adverseIssueNumber] },
        new Map([[10, [neutralIssueNumber, adverseIssueNumber]]]),
        new Map([
          [neutralIssueNumber, result('non_bug_neutral', 'Neutral canonical branch.')],
          [adverseIssueNumber, result(
            'closed_without_release_fix_proof',
            'Canonical branch remains adverse.',
          )],
        ]),
        null,
        () => null,
        (number: number) => canonicalIssue(number, 'closed'),
      );
      const resolution = adjusted.evidence.canonicalResolution as any;

      assert.equal(adjusted.status, 'duplicate_to_closed_canonical');
      assert.deepEqual(resolution.path, [10, adverseIssueNumber]);
      assert.deepEqual(resolution.blockingBranch, [10, adverseIssueNumber]);
      assert.equal(resolution.terminalIssue.number, adverseIssueNumber);
      assert.equal(
        resolution.terminalProof.status,
        'closed_without_release_fix_proof',
      );
    }
  });

  it('keeps fixed-after roll-up identity on the limiting branch regardless of issue-number ordering', () => {
    for (const [fixedIssueNumber, fixedAfterIssueNumber] of [
      [20, 30],
      [30, 20],
    ] as const) {
      const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
        10,
        result('duplicate_or_superseded', 'Closed as duplicate.'),
        { canonicalIssues: [fixedIssueNumber, fixedAfterIssueNumber] },
        new Map([[10, [fixedIssueNumber, fixedAfterIssueNumber]]]),
        new Map([
          [fixedIssueNumber, result('fixed_in_release', 'Fixed in this release.')],
          [fixedAfterIssueNumber, result('fixed_after_release', 'Fixed after this release.')],
        ]),
        null,
        () => null,
        (number: number) => canonicalIssue(number, 'closed'),
      );
      const resolution = adjusted.evidence.canonicalResolution as any;

      assert.equal(adjusted.status, 'duplicate_to_fixed_after_release');
      assert.deepEqual(resolution.path, [10, fixedAfterIssueNumber]);
      assert.deepEqual(resolution.blockingBranch, [10, fixedAfterIssueNumber]);
      assert.equal(resolution.terminalIssue.number, fixedAfterIssueNumber);
      assert.equal(resolution.terminalProof.status, 'fixed_after_release');
    }
  });

  it('keeps an open terminal risky when only an intermediate canonical issue has commit proof', () => {
    const graph = new Map([
      [10, [20]],
      [20, [30]],
    ]);
    const evidence = {
      canonicalIssues: [20],
      canonicalFixCommitProof: [{
        status: 'reachable',
        sourceIssueNumber: 20,
        commitOid: 'a'.repeat(40),
      }],
    };
    const issue = (number: number) =>
      canonicalIssue(number, number === 30 ? 'open' : 'closed');

    const intermediateOnly = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      evidence,
      graph,
      new Map(),
      null,
      () => null,
      issue,
    );
    assert.equal(intermediateOnly.status, 'duplicate_to_open_canonical');
    assert.deepEqual(
      (intermediateOnly.evidence.canonicalResolution as any).blockingBranch,
      [10, 20, 30],
    );

    const terminalProof = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        ...evidence,
        canonicalFixCommitProof: [{
          status: 'reachable',
          sourceIssueNumber: 30,
          commitOid: 'b'.repeat(40),
        }],
      },
      graph,
      new Map(),
      null,
      () => null,
      issue,
    );
    assert.equal(terminalProof.status, 'duplicate_to_fixed_in_release');
  });

  it('does not let reachable related PR fallback resolve one fixed and one unresolved canonical branch', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20, 30],
        relatedPrContext: {
          reachable: [{
            number: 999,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.fixProof',
          }],
        },
      },
      new Map([[10, [20, 30]]]),
      new Map([
        [20, result('fixed_in_release', 'Branch 20 fixed.')],
        [30, result('closed_without_release_fix_proof', 'Branch 30 remains unresolved.')],
      ]),
      null,
      () => null,
      (number: number) => canonicalIssue(number, 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_related_merged_pr_reachable_context_without_fix_credit');
    assert.notEqual(adjusted.status, 'duplicate_with_release_fix_proof');
    assert.deepEqual(
      (adjusted.evidence.canonicalResolution as any).branches.map((branch: any) => ({
        path: branch.path,
        fixedInRelease: branch.fixedInRelease,
        terminalStatus: branch.terminalProof?.status,
      })),
      [
        { path: [10, 20], fixedInRelease: true, terminalStatus: 'fixed_in_release' },
        { path: [10, 30], fixedInRelease: false, terminalStatus: 'closed_without_release_fix_proof' },
      ],
    );
  });

  it('does not return the source issue as reachable canonical context when cycles loop back', () => {
    const graph = new Map([
      [10, [20]],
      [20, [10]],
    ]);

    assert.deepEqual(__closureProofAnalysisTest.canonicalIssueNumbersReachableFrom(10, graph), [20]);
  });

  it('classifies canonical cycles with open issues as open canonical risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      88864,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [91154] },
      new Map([
        [88864, [91154]],
        [91154, [88864]],
      ]),
      new Map(),
      null,
      () => null,
      (number: number) => canonicalIssue(number, number === 91154 ? 'open' : 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_to_open_canonical');
    assert.equal((adjusted.evidence.canonicalResolution as any).cycle, true);
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalIssue.number, 91154);
    assert.equal((adjusted.evidence.canonicalResolution as any).cycleTerminalIssue.number, 91154);
  });

  it('lets canonical fix proof resolve a cycle before falling back to cycle risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20],
        canonicalFixCommitProof: [{ status: 'reachable', sourceIssueNumber: 20 }],
      },
      new Map([
        [10, [20]],
        [20, [10]],
      ]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_in_release');
    assert.equal((adjusted.evidence.canonicalResolution as any).cycle, true);
  });

  it('uses trusted reachable closure-comment fix proof before open duplicate canonical risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20],
        relatedPrContext: {
          reachable: [{
            number: 95328,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.fixProof',
            title: 'fix(sessions): reset stale origin fields',
          }],
        },
      },
      new Map([[10, [20]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_with_release_fix_proof');
    assert.equal((adjusted.evidence.reachableTrustedFixProofPrs as any[])[0].number, 95328);
  });

  it('does not let source-issue PR proof bypass an explicitly open canonical terminal', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20],
        relatedPrContext: {
          reachable: [{
            number: 95329,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.fixProof',
          }],
        },
      },
      new Map([[10, [20]]]),
      new Map(),
      null,
      () => null,
      (number: number) => canonicalIssue(number, number === 20 ? 'open' : 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_to_open_canonical');
  });

  it('preserves trusted fix proof when the same PR has lower-priority mention evidence', () => {
    const linkedPrs = [
      {
        number: 95328,
        repositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.prMention',
        title: 'related mention',
        state: 'MERGED',
        merged: 1,
      },
      {
        number: 95328,
        repositoryNameWithOwner: 'openclaw/openclaw',
        source: 'ClosureComment.fixProof',
        title: 'fix(sessions): reset stale origin fields',
        state: 'MERGED',
        merged: 1,
      },
    ];
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [20],
        linkedPrs,
        relatedPrContext: {
          reachable: linkedPrs
            .sort(__closureProofAnalysisTest.compareLinkedPrEvidencePriority)
            .slice(0, 1),
        },
      },
      new Map([[10, [20]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_with_release_fix_proof');
    assert.equal((adjusted.evidence.reachableTrustedFixProofPrs as any[])[0].source, 'ClosureComment.fixProof');
  });

  it('keeps self-only canonical references as cycle risk when no terminal exists', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [10] },
      new Map([[10, [10]]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'canonical_cycle_or_self_reference');
  });

  it('classifies duplicate closures by terminal canonical fixed-after proof', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map([[20, result('fixed_after_release', 'Canonical was fixed after this tag.')]]),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_after_release');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'fixed_after_release',
      summary: 'Canonical was fixed after this tag.',
    });
  });

  it('classifies duplicate closures by terminal canonical fixed-in-release proof', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map([[20, result('fixed_in_release', 'Canonical was fixed in this tag.')]]),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_in_release');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'fixed_in_release',
      summary: 'Canonical was fixed in this tag.',
    });
  });

  it('classifies closed canonical targets without terminal proof as missing evidence', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [96343] },
      new Map([[10, [96343]]]),
      new Map(),
      null,
      () => null,
      (number: number) => canonicalIssue(number, 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_to_closed_canonical_missing_proof');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalIssue?.number, 96343);
  });

  it('classifies closed canonical targets with missing terminal timeline as missing evidence', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [96343] },
      new Map([[10, [96343]]]),
      new Map([[96343, result('no_timeline_event', 'Canonical has no close event.')]]),
      null,
      () => null,
      (number: number) => canonicalIssue(number, 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_to_closed_canonical_missing_proof');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'no_timeline_event',
      summary: 'Canonical has no close event.',
    });
  });

  it('uses later-release terminal fix proof for closed canonical targets', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
      () => ({
        status: 'fixed_in_release',
        summary: 'Canonical was fixed in a later release.',
        evidence: {},
        releaseTag: 'v2',
        timing: 'after',
        sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
        terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
        crossRelease: true,
      }),
      (number: number) => canonicalIssue(number, 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_to_fixed_after_release');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'fixed_in_release',
      summary: 'Canonical was fixed in a later release.',
      releaseTag: 'v2',
      timing: 'after',
      crossRelease: true,
      sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
      terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
    });
  });

  it('requires current analyzer and dependency evidence for cross-release fallback proof', () => {
    runIsolatedAnalysisScript('cross-release-proof-freshness', `
      const versionsModule = await import('./src/lib/analysisVersions.ts');
      const versions = versionsModule.default ?? versionsModule;
      const sourceTag = 'v-source';
      const proofTag = 'v-proof';
      seedRelease(sourceTag, '2026-07-01T00:00:00Z');
      seedRelease(proofTag, '2026-07-02T00:00:00Z');
      seedRelease('v-next', '2026-07-03T00:00:00Z');
      seedIssue(20, '2026-07-02T12:00:00Z');
      seedClosure(20, 'close-proof-20', '2026-07-02T12:00:00Z');

      const currentEvidence = JSON.stringify({
        proofAnalyzerVersion: versions.CLOSURE_PROOF_ANALYZER_VERSION,
      });
      db.upsertIssueClosureProof({
        release_tag: proofTag,
        issue_number: 20,
        status: 'fixed_in_release',
        summary: 'Current cross-release proof.',
        evidence_json: currentEvidence,
      });
      db.replaceReleaseClosureDependencySnapshot(
        db.releaseClosureDependencyIdentity(proofTag, [20]),
      );

      assert.equal(
        analysis.__closureProofAnalysisTest.crossReleaseTerminalProofForIssue(
          sourceTag,
          20,
        )?.status,
        'fixed_in_release',
      );

      db.db.prepare(
        'UPDATE issue_closure_proofs SET evidence_json=? WHERE release_tag=? AND issue_number=?'
      ).run(JSON.stringify({
        proofAnalyzerVersion: versions.CLOSURE_PROOF_ANALYZER_VERSION - 1,
      }), proofTag, 20);
      assert.equal(
        analysis.__closureProofAnalysisTest.crossReleaseTerminalProofForIssue(
          sourceTag,
          20,
        ),
        null,
      );

      db.db.prepare(
        'UPDATE issue_closure_proofs SET evidence_json=? WHERE release_tag=? AND issue_number=?'
      ).run(currentEvidence, proofTag, 20);
      assert.equal(
        analysis.__closureProofAnalysisTest.crossReleaseTerminalProofForIssue(
          sourceTag,
          20,
        )?.status,
        'fixed_in_release',
      );

      db.db.prepare(
        'UPDATE issues SET updated_at=? WHERE number=?'
      ).run('2099-01-01T00:00:00Z', 20);
      assert.equal(
        analysis.__closureProofAnalysisTest.crossReleaseTerminalProofForIssue(
          sourceTag,
          20,
        ),
        null,
      );
    `);
  });

  it('keeps weak not-planned cross-release terminal proof unresolved', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
      () => ({
        status: 'not_planned',
        summary: 'Canonical was closed as non-actionable.',
        evidence: {},
        releaseTag: 'v2',
        timing: 'after',
        sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
        terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
        crossRelease: true,
      }),
      (number: number) => canonicalIssue(number, 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_to_unverified_closed_canonical');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalProof.status, 'not_planned');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalProof.concreteNonActionableRationale, undefined);
  });

  it('uses concrete non-actionable cross-release terminal proof to neutralize duplicate risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
      () => ({
        status: 'not_planned',
        summary: 'Canonical was closed as non-actionable.',
        evidence: {
          nonActionableRationaleComments: [{
            author: 'maintainer',
            snippet: 'Close: this is outside the OpenClaw source repository.',
          }],
        },
        releaseTag: 'v2',
        timing: 'after',
        sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
        terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
        crossRelease: true,
      }),
      (number: number) => canonicalIssue(number, 'closed'),
    );

    assert.equal(adjusted.status, 'duplicate_to_non_actionable_canonical');
    assert.deepEqual((adjusted.evidence.canonicalResolution as any).terminalProof, {
      status: 'not_planned',
      summary: 'Canonical was closed as non-actionable.',
      concreteNonActionableRationale: true,
      releaseTag: 'v2',
      timing: 'after',
      crossRelease: true,
      sourceReleasePublishedAt: '2026-06-01T00:00:00Z',
      terminalReleasePublishedAt: '2026-06-02T00:00:00Z',
    });
  });

  it('classifies closed canonical terminal risk by terminal disposition', () => {
    const baseArgs = [
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
    ] as const;

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'not_planned_with_open_pr_context', summary: 'Open PR remains.', evidence: {} }),
      (number: number) => canonicalIssue(number, 'closed'),
    ).status, 'duplicate_to_open_pr_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'not_planned_fixed_after_release', summary: 'Fixed after.', evidence: {} }),
      (number: number) => canonicalIssue(number, 'closed'),
    ).status, 'duplicate_to_known_not_in_release_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'linked_closing_pr_not_merged', summary: 'Unmerged PR.', evidence: {} }),
      (number: number) => canonicalIssue(number, 'closed'),
    ).status, 'duplicate_to_closed_canonical');
  });

  it('classifies closed canonical targets with concrete non-resolution proof separately', () => {
    const baseArgs = [
      10,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [20] },
      new Map([[10, [20]]]),
      new Map(),
      'v1',
    ] as const;

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'linked_closing_pr_closed_unmerged', summary: 'Closed unmerged.', evidence: {} }),
      (number: number) => canonicalIssue(number, 'closed'),
    ).status, 'duplicate_to_closed_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'closed_without_release_fix_proof', summary: 'No release proof.', evidence: {} }),
      (number: number) => canonicalIssue(number, 'closed'),
    ).status, 'duplicate_to_closed_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'related_open_pr_context', summary: 'Open related PR.', evidence: {} }),
      (number: number) => canonicalIssue(number, 'closed'),
    ).status, 'duplicate_to_open_pr_canonical');

    assert.equal(__closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      ...baseArgs,
      () => ({ status: 'duplicate_or_superseded', summary: 'Still points elsewhere.', evidence: {} }),
      (number: number) => canonicalIssue(number, 'closed'),
    ).status, 'duplicate_to_unverified_closed_canonical');
  });

  it('selects every closed terminal canonical issue for current-tag analysis despite cross-release proof', () => {
    const graph = new Map([
      [10, [20]],
      [11, [30]],
      [12, [40]],
    ]);
    const selected = __closureProofAnalysisTest.terminalCanonicalIssuesNeedingEvidence(
      'v1',
      [10, 11, 12],
      graph,
      (number: number) => {
        if (number === 20) return { number, title: 'closed missing', state: 'closed', url: null };
        if (number === 30) return { number, title: 'open canonical', state: 'open', url: null };
        return { number, title: 'closed with proof', state: 'closed', url: null };
      },
      (_releaseTag: string, number: number) => number === 40
        ? {
          status: 'fixed_after_release',
          summary: 'Already proved elsewhere.',
          evidence: {},
          releaseTag: 'v2',
          timing: 'after',
          crossRelease: true,
        }
        : null,
    );

    assert.deepEqual(selected, [20, 40]);
  });

  it('classifies duplicate closures with open PR context as open canonical risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      97322,
      result('duplicate_or_superseded', 'Closed as superseded.'),
      {
        canonicalIssues: [],
        linkedPrs: [{
          number: 85651,
          title: 'feat(continuation): context-pressure-aware continuation',
          state: 'OPEN',
          merged: 0,
          source: 'ClosureComment.prMention',
        }],
      },
      new Map([[97322, []]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'superseded_to_open_pr');
    assert.equal((adjusted.evidence.canonicalOpenPrs as any[])[0].number, 85651);
  });

  it('keeps cross-reference-only open PRs as raw provenance without changing duplicate status', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      96343,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [],
        linkedPrs: [{
          number: 96358,
          title: 'fix(cron): preserve action-critical command output',
          state: 'OPEN',
          merged: 0,
          source: 'CrossReferencedEvent',
        }],
      },
      new Map([[96343, []]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_or_superseded');
    assert.equal((adjusted.evidence.linkedPrs as any[])[0].number, 96358);
    assert.equal(adjusted.evidence.relatedOpenPrs, undefined);
    assert.equal(adjusted.evidence.canonicalOpenPrs, undefined);
  });

  it('allows will-close cross-references to remain status-bearing duplicate context', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      96343,
      result('duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [],
        linkedPrs: [{
          number: 96358,
          title: 'fix(cron): preserve action-critical command output',
          state: 'OPEN',
          merged: 0,
          source: 'CrossReferencedEvent',
          willCloseTarget: 1,
        }],
      },
      new Map([[96343, []]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'duplicate_with_open_pr_context');
    assert.equal((adjusted.evidence.relatedOpenPrs as any[])[0].number, 96358);
  });

  it('classifies non-bug duplicate closures by open canonical target without scoring risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('non_bug_duplicate_or_superseded', 'Closed as duplicate.'),
      { canonicalIssues: [50103] },
      new Map([[10, [50103]]]),
      new Map(),
      null,
      () => null,
      (number: number) => canonicalIssue(number, 'open'),
    );

    assert.equal(adjusted.status, 'non_bug_duplicate_to_open_canonical');
    assert.equal((adjusted.evidence.canonicalResolution as any).terminalIssue?.number, 50103);
  });

  it('classifies non-bug duplicate closures with open PR context without scoring risk', () => {
    const adjusted = __closureProofAnalysisTest.adjustCanonicalDuplicateStatus(
      10,
      result('non_bug_duplicate_or_superseded', 'Closed as duplicate.'),
      {
        canonicalIssues: [],
        linkedPrs: [{
          number: 85651,
          title: 'feat(continuation): context-pressure-aware continuation',
          state: 'OPEN',
          merged: 0,
          source: 'ClosureComment.prMention',
        }],
      },
      new Map([[10, []]]),
      new Map(),
    );

    assert.equal(adjusted.status, 'non_bug_superseded_to_open_pr');
  });

  it('classifies related PR references without release-fix proof separately', () => {
    const adjusted = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{
          number: 123,
          title: 'related work',
          state: 'MERGED',
          merged: 1,
          source: 'ClosureComment.prMention',
        }],
      },
    );

    assert.equal(adjusted.status, 'related_pr_without_release_fix');
  });

  it('separates related PR context by reachability before generic no-fix status', () => {
    const reachable = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 123, state: 'MERGED', merged: 1, source: 'ClosureComment.prMention' }],
        relatedPrContext: {
          reachable: [{
            number: 123,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );
    const notReachable = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 124, state: 'MERGED', merged: 1, source: 'ClosureComment.prMention' }],
        relatedPrContext: {
          notReachable: [{
            number: 124,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );
    const unknown = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 125, state: 'MERGED', merged: 1, source: 'ClosureComment.prMention' }],
        relatedPrContext: {
          unknownReachability: [{
            number: 125,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );

    assert.equal(reachable.status, 'related_merged_pr_reachable_context_without_fix_credit');
    assert.equal(notReachable.status, 'related_merged_pr_not_reachable_context');
    assert.equal(unknown.status, 'related_merged_pr_reachability_unknown');
  });

  it('separates open, closed-unmerged, and external closing PR context', () => {
    const open = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 123, state: 'OPEN', merged: 0, source: 'ClosureComment.prMention' }],
        relatedPrContext: { open: [{ number: 123, source: 'ClosureComment.prMention' }] },
      },
    );
    const closed = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{ number: 124, state: 'CLOSED', merged: 0, source: 'ClosureComment.prMention' }],
        relatedPrContext: { closedUnmerged: [{ number: 124, source: 'ClosureComment.prMention' }] },
      },
    );
    const external = __closureProofAnalysisTest.adjustNoReleaseFixProofStatus(
      result('closed_without_release_fix_proof', 'No proof.'),
      {
        linkedPrs: [{
          number: 27,
          repositoryNameWithOwner: 'openclaw/fs-safe',
          state: 'MERGED',
          merged: 1,
          source: 'ClosedEvent.closer',
        }],
        relatedPrContext: {
          externalClosing: [{
            number: 27,
            repositoryNameWithOwner: 'openclaw/fs-safe',
            source: 'ClosedEvent.closer',
          }],
        },
      },
    );

    assert.equal(open.status, 'related_open_pr_context');
    assert.equal(closed.status, 'related_closed_unmerged_pr_context');
    assert.equal(external.status, 'external_repo_closing_pr_unscored');
  });

  it('separates open linked closing PRs from closed unmerged PRs', () => {
    const open = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('linked_closing_pr_not_merged', 'No merge.'),
      {
        linkedPrs: [{
          number: 123,
          source: 'closedByPullRequestsReferences',
          willCloseTarget: 1,
          state: 'OPEN',
          merged: 0,
        }],
      },
      'v1',
      new Map(),
    );
    const closed = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('linked_closing_pr_not_merged', 'No merge.'),
      {
        linkedPrs: [{
          number: 124,
          source: 'closedByPullRequestsReferences',
          willCloseTarget: 1,
          state: 'CLOSED',
          merged: 0,
        }],
      },
      'v1',
      new Map(),
    );

    assert.equal(open.status, 'linked_closing_pr_open');
    assert.equal(closed.status, 'linked_closing_pr_closed_unmerged');
  });

  it('classifies title-only author deletion requests as reporter withdrawal', () => {
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      { title: '[deleted by author request]', linkedPrs: [] },
      'v1',
      new Map(),
    );

    assert.equal(adjusted.status, 'reporter_withdrawn');
  });

  it('splits fixed-after release proof by later stable reachability', () => {
    const evidence = {
      notReachableFixCommits: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
      hasNotReachableFixCommit: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map([['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', {
        releaseTag: 'v2',
        publishedAt: '2026-06-02T00:00:00Z',
        proofType: 'commit',
        commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      }]]),
    );

    assert.equal(adjusted.status, 'fixed_in_later_release');
    assert.deepEqual((evidence as any).laterFixProof, {
      releaseTag: 'v2',
      publishedAt: '2026-06-02T00:00:00Z',
      proofType: 'commit',
      commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    });
  });

  it('marks fixed-after proof after latest scored stable separately', () => {
    const evidence = {
      linkedPrs: [{
        number: 99,
        repositoryNameWithOwner: 'openclaw/openclaw',
        merged: 1,
        mergedAt: '2026-06-03T00:00:00Z',
        source: 'ClosedEvent.closer',
      }],
      hasNotReachableClosingPr: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map(),
      () => ({ tag: 'v2', published_at: '2026-06-02T00:00:00Z' }),
    );

    assert.equal(adjusted.status, 'fixed_after_latest_release');
    assert.equal((evidence as any).unscoredFixProof.timing, 'after_latest_release');
  });

  it('marks fixed-after proof skipped by later scored stables separately', () => {
    const evidence = {
      notReachableFixCommits: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
      fixCommitProof: [{
        commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        referencedAt: '2026-06-01T12:00:00Z',
        status: 'not_reachable',
      }],
      hasNotReachableFixCommit: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map(),
      () => ({ tag: 'v2', published_at: '2026-06-02T00:00:00Z' }),
    );

    assert.equal(adjusted.status, 'fixed_skipped_by_later_releases');
    assert.equal((evidence as any).unscoredFixProof.timing, 'skipped_by_later_releases');
  });

  it('prefers after-latest proof over older skipped proof candidates', () => {
    const evidence = {
      linkedPrs: [{
        number: 10,
        repositoryNameWithOwner: 'openclaw/openclaw',
        merged: 1,
        mergedAt: '2026-06-01T12:00:00Z',
        source: 'ClosedEvent.closer',
      }, {
        number: 11,
        repositoryNameWithOwner: 'openclaw/openclaw',
        merged: 1,
        mergedAt: '2026-06-03T12:00:00Z',
        source: 'ClosedEvent.closer',
      }],
      hasNotReachableClosingPr: true,
    };
    const adjusted = __closureProofAnalysisTest.adjustClosureProofStatus(
      result('fixed_after_release', 'Fix exists after this tag.'),
      evidence,
      'v1',
      new Map(),
      () => ({ tag: 'v2', published_at: '2026-06-02T00:00:00Z' }),
    );

    assert.equal(adjusted.status, 'fixed_after_latest_release');
    assert.equal((evidence as any).unscoredFixProof.proofTime, '2026-06-03T12:00:00Z');
  });

  it('classifies not-planned closures with reachable proof separately from bare admin closures', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        hasReachableFixCommit: true,
        linkedPrs: [],
      },
    );

    assert.equal(adjusted.status, 'not_planned_with_release_fix_proof');
  });

  it('classifies not-planned closures with unknown direct fix commit proof separately', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        hasUnknownFixCommit: true,
        unknownFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
        linkedPrs: [],
      },
    );

    assert.equal(adjusted.status, 'not_planned_direct_fix_commit_reachability_unknown');
  });

  it('classifies not-planned closures with trusted reachable closure-comment fix proof as release proof', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 88764, state: 'MERGED', merged: 1 }],
        relatedPrContext: {
          reachable: [{
            number: 88764,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.fixProof',
            title: 'fix(update): recognize manual-update launchd jobs',
          }],
        },
      },
    );

    assert.equal(adjusted.status, 'not_planned_with_release_fix_proof');
    assert.equal((adjusted.evidence.reachableTrustedFixProofPrs as any[])[0].number, 88764);
  });

  it('keeps non-closing cross-references from changing not-planned status', () => {
    const evidence = {
      stateReasons: ['NOT_PLANNED'],
      linkedPrs: [{
        number: 97423,
        state: 'OPEN',
        merged: 0,
        source: 'CrossReferencedEvent',
      }],
    };
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      evidence,
    );

    assert.equal(adjusted.status, 'admin_not_planned_unverified');
    assert.equal(evidence.linkedPrs[0].number, 97423);
  });

  it('keeps post-closure and high-fanout cross-reference provenance out of no-context status', () => {
    const evidence = {
      stateReasons: ['NOT_PLANNED'],
      linkedPrs: [{
        number: 97423,
        state: 'OPEN',
        merged: 0,
        source: 'CrossReferencedEvent',
        referencedAt: '2026-07-03T07:14:31Z',
      }, {
        number: 74163,
        state: 'OPEN',
        merged: 0,
        source: 'CrossReferencedEvent',
        referencedAt: '2026-04-29T06:54:54Z',
      }],
    };
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_no_context', 'No close-time context.'),
      evidence,
    );

    assert.equal(adjusted.status, 'admin_not_planned_no_context');
    assert.equal(evidence.linkedPrs.length, 2);
  });

  it('classifies trusted final-window open PR mentions as not-planned context', () => {
    const adjusted = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{
          number: 97423,
          state: 'OPEN',
          merged: 0,
          source: 'ClosureComment.prMention',
        }],
        relatedPrContext: {
          open: [{
            number: 97423,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );

    assert.equal(adjusted.status, 'not_planned_with_open_pr_context');
  });

  it('classifies not-planned related PR context by reachability', () => {
    const reachable = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 123, state: 'MERGED', merged: 1, source: 'ClosureComment.prMention' }],
        relatedPrContext: {
          reachable: [{
            number: 123,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );
    const notReachable = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 124, state: 'MERGED', merged: 1, source: 'ClosureComment.prMention' }],
        relatedPrContext: {
          notReachable: [{
            number: 124,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );
    const unknown = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 125, state: 'MERGED', merged: 1, source: 'ClosureComment.prMention' }],
        relatedPrContext: {
          unknownReachability: [{
            number: 125,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );
    const closed = __closureProofAnalysisTest.adjustNotPlannedEvidenceStatus(
      result('admin_not_planned_unverified', 'No rationale.'),
      {
        stateReasons: ['NOT_PLANNED'],
        linkedPrs: [{ number: 126, state: 'CLOSED', merged: 0, source: 'ClosureComment.prMention' }],
        relatedPrContext: {
          closedUnmerged: [{
            number: 126,
            repositoryNameWithOwner: 'openclaw/openclaw',
            source: 'ClosureComment.prMention',
          }],
        },
      },
    );

    assert.equal(reachable.status, 'not_planned_related_merged_pr_reachable_context_without_fix_credit');
    assert.equal(notReachable.status, 'not_planned_related_merged_pr_not_reachable_context');
    assert.equal(unknown.status, 'not_planned_related_merged_pr_reachability_unknown');
    assert.equal(closed.status, 'not_planned_related_closed_unmerged_pr_context');
  });

  it('recognizes common duplicate-of text as canonical graph targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Closing this as duplicate of https://github.com/openclaw/openclaw/issues/96857.',
      ),
      [96857],
    );
  });

  it('recognizes close-time duplicate and canonical tracker wording as graph targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Closing this as a duplicate of #96857. Keeping the upstream discussion centralized there.',
      ),
      [96857],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as a duplicate of the open canonical tracker #60841, not as fixed.',
      ),
      [60841],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as duplicate/superseded. Canonical path: Keep https://github.com/openclaw/openclaw/issues/76042 as the active tracker.',
      ),
      [76042],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as a duplicate: https://github.com/openclaw/openclaw/issues/67016 is open and already tracks this.',
      ),
      [67016],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as duplicate/superseded: this is covered by broader reports, especially #88562 and #90774.',
      ),
      [88562, 90774],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Consolidating this into #96463.',
      ),
      [96463],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Superseded by a clearer safety-focused report: #99253',
      ),
      [99253],
    );
  });

  it('does not treat canonical PR links as canonical issue targets', () => {
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Canonical path: Open PR https://github.com/openclaw/openclaw/pull/85651 owns this feature work.',
      ),
      [],
    );
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromText(
        'Close as superseded. Canonical path: Open PR #85651 owns this feature work.',
      ),
      [],
    );
  });

  it('ignores stale canonical comments when building source closure graph edges', () => {
    const comments = [
      { created_at: '2026-06-20T10:00:00Z', body: 'Keep open. Canonical: #96857' },
      { created_at: '2026-06-28T10:00:00Z', body: 'Closing as not planned.' },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(closureComments, 10),
      [],
    );
  });

  it('ignores close-time keep-open canonical review comments', () => {
    const comments = [
      { created_at: '2026-06-28T10:00:00Z', body: 'Keep open: this is the canonical report. Canonical: #96857' },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(closureComments, []);
    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(closureComments, 10),
      [],
    );
  });

  it('keeps close-time canonical comments as source closure graph edges', () => {
    const comments = [
      { created_at: '2026-06-28T10:00:00Z', body: 'Closing as duplicate of #96857.' },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(closureComments, 10),
      [96857],
    );
  });

  it('filters canonical graph targets to real issues when PR numbers are also referenced', () => {
    const comments = [
      {
        created_at: '2026-06-28T10:00:00Z',
        body: 'Close as duplicate. Canonical path: use PR #86281 for implementation and issue #86773 for the remaining tracker.',
      },
    ];
    const closureComments = closureRationaleComments(comments, '2026-06-28T10:05:00Z');

    assert.deepEqual(
      __closureProofAnalysisTest.canonicalIssueNumbersFromComments(
        closureComments,
        10,
        (number: number) => number === 86773,
      ),
      [86773],
    );
  });

  it('promotes neutral closure rows with strong bug evidence before proof classification', () => {
    const result = __closureProofAnalysisTest.effectiveClosureProofClassification({
      title: '[Bug]: Cron announce delivery reports success but message never arrives',
      labels: JSON.stringify(['stale', 'clawsweeper:source-repro', 'impact:message-loss']),
      sentiment: 'negative',
      severity: 'medium',
      scope: 'moderate',
      functionality: 'integration',
      affected_users: 'some',
      has_workaround: 0,
      workaround_status: 'unknown',
      duplicate_cluster: null,
      affects_version: null,
      confidence: 0.7,
      rationale: '',
    });

    assert.equal(result.rawClassification.sentiment, 'negative');
    assert.equal(result.classification.sentiment, 'negative');
    assert.equal(result.classificationDiff.sentiment, undefined);
  });

  it('restores neutralized stale bug evidence to negative closure risk', () => {
    const labels = ['stale', 'P1', 'impact:crash-loop', 'impact:session-state'];
    const result = __closureProofAnalysisTest.effectiveClosureProofClassification(
      {
        number: 86774,
        title: 'Gateway lazy-spawns duplicate stdio MCP children with identical ppid+config (memory + CPU leak)',
        labels: JSON.stringify(labels),
        sentiment: 'neutral',
        severity: 'medium',
        scope: 'moderate',
        functionality: 'core',
        affected_users: 'many',
        has_workaround: 0,
        workaround_status: 'unknown',
        duplicate_cluster: null,
        affects_version: null,
        confidence: 0.7,
        rationale: '',
      },
      null,
      (_issueNumber, currentLabels) => currentLabels,
      () => labels.length,
      () => 0,
      (_issueNumber, label) => ({
        event_id: `label-${label}`,
        action: 'labeled',
        label_name: label,
        actor_login: label === 'P1' ? 'human-maintainer' : 'openclaw-barnacle',
        actor_type: label === 'P1' ? 'User' : 'Bot',
        created_at: '2026-06-01T00:00:00Z',
      }),
      (eventId) => eventId === 'label-P1'
        ? {
            subjectKind: 'label_event',
            subjectIdentity: eventId,
            resolutionHash: 'a'.repeat(64),
            evidenceDigest: 'b'.repeat(64),
            authorizedForScoring: true,
          }
        : null,
    );

    assert.equal(result.rawClassification.sentiment, 'neutral');
    assert.equal(result.classification.sentiment, 'negative');
    assert.deepEqual(result.classificationDiff.sentiment, { raw: 'neutral', effective: 'negative' });
    assert.deepEqual(result.labelActors, {
      stale: 'openclaw-barnacle',
      P1: 'human-maintainer',
      'impact:crash-loop': 'openclaw-barnacle',
      'impact:session-state': 'openclaw-barnacle',
    });
  });

  it('uses release-cutoff labels instead of current labels for closure proof classification', () => {
    const result = __closureProofAnalysisTest.effectiveClosureProofClassification(
      {
        number: 42,
        title: 'Provider setup confusion',
        labels: JSON.stringify(['stale']),
        sentiment: 'negative',
        severity: 'medium',
        scope: 'moderate',
        functionality: 'provider',
        affected_users: 'some',
        has_workaround: 0,
        workaround_status: 'unknown',
        duplicate_cluster: null,
        affects_version: null,
        confidence: 0.7,
        rationale: '',
      },
      '2026-06-01T00:00:00Z',
      () => [],
      () => 1,
      () => 0,
    );

    assert.deepEqual(result.currentLabels, ['stale']);
    assert.deepEqual(result.labels, []);
    assert.equal(result.labelSource, 'timeline');
    assert.equal(result.labelCutoffAt, '2026-06-01T00:00:00Z');
    assert.equal(result.classification.sentiment, 'negative');
  });

  it('marks missing classification rows without promoting closure proof credit', () => {
    const classification = __closureProofAnalysisTest.effectiveClosureProofClassification({
      title: '[Bug]: closed issue still needs classification',
      labels: JSON.stringify(['bug']),
      sentiment: null,
      severity: null,
      scope: null,
      functionality: null,
      affected_users: null,
      has_workaround: null,
      workaround_status: null,
      duplicate_cluster: null,
      affects_version: null,
      confidence: null,
      rationale: null,
      classification_issue_number: null,
      classification_prompt_version: null,
    });
    assert.equal((classification as any).missingClassification, true);
    assert.equal(classification.classification.sentiment, 'neutral');
    assert.equal(classification.classification.confidence, 0);

    const proof = __closureProofAnalysisTest.missingClassificationClosureProof({
      classification_issue_number: null,
      classification_prompt_version: null,
    });
    assert.equal(proof.status, 'unknown');
    assert.equal((proof.evidence as any).missingClassification, true);

    const unknownCommitProof = __closureProofAnalysisTest.missingClassificationClosureProof({
      classification_issue_number: null,
      classification_prompt_version: null,
    }, {
      hasUnknownFixCommit: true,
      unknownFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
    });
    assert.equal(unknownCommitProof.status, 'direct_fix_commit_reachability_unknown');
    assert.equal((unknownCommitProof.evidence as any).hasUnknownFixCommit, true);
    assert.deepEqual((unknownCommitProof.evidence as any).unknownFixCommits, ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a']);
  });

  it('builds referenced commit context from eligible same-repo commit references only', () => {
    const rows = [
      {
        issue_number: 10,
        commit_oid: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        commit_message_headline: 'fix(cli): preserve channel routing',
        referenced_at: '2026-06-28T10:00:01Z',
        actor_login: 'maintainer',
        event_id: 'ref-ok',
        closed_at: '2026-06-28T10:00:00Z',
      },
      {
        issue_number: 10,
        commit_oid: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        commit_message_headline: 'docs: mention related issue',
        referenced_at: '2026-06-28T10:00:01Z',
        actor_login: 'maintainer',
        event_id: 'ref-docs',
        closed_at: '2026-06-28T10:00:00Z',
      },
      {
        issue_number: 10,
        commit_oid: 'cccccccccccccccccccccccccccccccccccccccc',
        commit_message_headline: 'fix(cli): too late to prove final closure',
        referenced_at: '2026-06-28T10:00:03Z',
        actor_login: 'maintainer',
        event_id: 'ref-late',
        closed_at: '2026-06-28T10:00:00Z',
      },
      {
        issue_number: 10,
        commit_oid: 'short',
        commit_message_headline: 'fix(cli): short hash',
        referenced_at: '2026-06-28T10:00:01Z',
        actor_login: 'maintainer',
        event_id: 'ref-short',
        closed_at: '2026-06-28T10:00:00Z',
      },
    ];

    const mentions = __closureProofAnalysisTest.commitReferenceMentionsFromRows(rows).get(10) ?? [];
    assert.deepEqual(mentions.map((item: any) => ({
      commitOid: item.commitOid,
      source: item.source,
      referencedAt: item.referencedAt,
      snippet: item.snippet,
      author: item.author,
      trustedSource: item.trustedSource,
    })), [{
      commitOid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      source: 'ReferencedEvent.commit',
      referencedAt: '2026-06-28T10:00:01Z',
      snippet: 'GitHub ReferencedEvent same-repo commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: fix(cli): preserve channel routing',
      author: 'maintainer',
      trustedSource: true,
    }]);
  });

  it('does not use referenced commit context as fallback fix proof', () => {
    assert.equal(__closureProofAnalysisTest.shouldUseReferencedCommitProof({
      directMentionCount: 0,
      reachableClosingPrCount: 0,
    }), false);
  });

  it('does not use referenced commit fallback when reachable PR or direct commit proof already exists', () => {
    assert.equal(__closureProofAnalysisTest.shouldUseReferencedCommitProof({
      directMentionCount: 0,
      reachableClosingPrCount: 1,
    }), false);
    assert.equal(__closureProofAnalysisTest.shouldUseReferencedCommitProof({
      directMentionCount: 1,
      reachableClosingPrCount: 0,
    }), false);
  });
});

function closureComment(id: number, timestamp: string) {
  return {
    id,
    node_id: `IC_${id}`,
    node_type: 'IssueComment' as const,
    url: `https://example.test/comments/${id}`,
    user: {
      id: `U_commenter_${id}`,
      login: `user-${id}`,
      type: 'User' as const,
    },
    author_association: 'CONTRIBUTOR',
    body: `comment ${id}`,
    created_at: timestamp,
    updated_at: timestamp,
  };
}
