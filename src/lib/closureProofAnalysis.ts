import { config } from '../config';
import {
  CLOSURE_PROOF_ANALYZER_VERSION,
  RAW_CLOSURE_EVIDENCE_SCHEMA_VERSION,
} from './analysisVersions';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
} from './commentEvidence';
import {
  acquireRenewableRefreshLease,
  assertIssueEvidenceRevisions,
  db,
  closureEvidenceIssuesNeedingRefresh,
  deleteCommentIssuePrLinksForIssues,
  deleteIssueClosureProofsForRelease,
  deleteIssueCommitReferencesForIssues,
  deleteStateDerivedIssuePrLinksForIssues,
  getRelease,
  getIssue,
  validateIssueStateEventSnapshot,
  issueLabelEventCount,
  issueLabelSnapshotCountAt,
  issueEvidenceRevisions,
  labelsForIssueAt,
  latestIssueLabelEventAt,
  markIssueClosureEvidenceRefreshed,
  releaseClosureDependencyMembership,
  releaseClosureDependencyIdentity,
  releaseClosureProofIntegrity,
  replaceReleaseClosureDependencySnapshot,
  replaceIssueStateEventSnapshot,
  runInWriteTransaction,
  upsertIssueClosureProof,
  upsertIssueCommitReference,
  upsertIssuePrLink,
  upsertPullRequestFix,
  type IssueEvidenceRevision,
} from './db';
import { classifyClosureProof, closureRationaleComments, type ClosureProofResult, type ClosureProofStatus } from './closureProof';
import { closureRiskDisposition } from './closureProofTaxonomy';
import { creditedFixLinkSql } from './fixProvenance';
import {
  closureCommentCommitMentions,
  closureCommentPrMentions,
  listIssueCommentSnapshotsBatch,
  listIssueFixEvidenceBatch,
  listPullRequestFixesBatch,
  pullRequestKey,
  type ClosureCommentCommitMention,
  type GhComment,
  type GhIssueCommentSnapshot,
  type GhIssueFixEvidence,
  type GhPullRequestFix,
  type PullRequestLookup,
} from './github';
import {
  applyClosureRiskSentimentHint,
  applyLabelOverrides,
  applyTitleFunctionalityHint,
  applyTitleIssueShapeHint,
} from './labelOverrides';
import type { IssueClassification } from './llm';
import { releaseLabelCutoff } from './labelCutoff';
import {
  labelEventAuthorityReference,
  scoringLabelInfoAtCutoff,
} from './scoringLabelAuthority';
import {
  checkDirectCommitFirstContainingReleaseBulk,
  checkReleaseCommitReachability,
  checkReleasePrReachability,
  createReleaseReachabilityRefreshContext,
  resolveCommitOidPrefix,
  UNKNOWN_REACHABILITY_RETRY_MS,
  type CommitReachability,
  type DirectCommitFirstContainingResult,
  type ReleaseReachabilityRefreshContext,
} from './releaseReachability';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  assertAuthoritativeIssueStateEvents,
  issueStateEventSweepDigest,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
} from './stateEventSnapshot';
import { throwIfAborted } from './cooperativeCancellation';

export interface ClosureProofAnalysisResult {
  releaseTag: string;
  analyzed: number;
  buckets: Record<string, number>;
  rawEvidence: {
    closureEvents: number;
    reopenEvents: number;
    prLinks: number;
    pullRequests: number;
    commitReferences: number;
  };
}

export interface AnalyzeClosureProofOptions {
  persistScoreAuditPayload?: false;
  refreshCommentPrMentionEvidence?: boolean;
  refreshPrReachability?: boolean;
  runContext?: ClosureProofRunContext;
  preparedDependencies?: ClosureProofPreparedDependencies;
  reachabilityContext?: ReleaseReachabilityRefreshContext;
}

export interface ClosureProofRunContext {
  signal?: AbortSignal;
  commentSnapshotsByIssue: Map<number, GhIssueCommentSnapshot>;
  commentSnapshotRequests: Map<number, Promise<GhIssueCommentSnapshot>>;
  commentsByIssue: Map<number, GhComment[]>;
  commentSnapshotMetadataDriftIssueNumbers: Set<number>;
  stateSnapshotMetadataDriftIssueNumbers: Set<number>;
  fixEvidenceByIssue: Map<number, GhIssueFixEvidence>;
  fixEvidenceRequests: Map<number, Promise<GhIssueFixEvidence | null>>;
  pullRequestsByKey: Map<string, GhPullRequestFix | null>;
  pullRequestRequests: Map<string, Promise<GhPullRequestFix | null>>;
  permissiveMissingPullRequestKeys?: Set<string>;
  assertCanWrite?: (stage: string) => void;
  issueEvidenceRevisionsByIssue: Map<number, IssueEvidenceRevision>;
}

export interface ClosureProofPreparedDependencies {
  releaseTag: string;
  analysisStartedAt: string;
  labelCutoff: string | null;
  issueNumbers: number[];
  sourceIssueNumbers: Set<number>;
  allCommentsByIssue: Map<number, GhComment[]>;
  canonicalGraph: Map<number, number[]>;
  analysisIssueNumbers: number[];
}

export function createClosureProofRunContext(
  options: {
    assertCanWrite?: (stage: string) => void;
    signal?: AbortSignal;
  } = {},
): ClosureProofRunContext {
  return {
    signal: options.signal,
    commentSnapshotsByIssue: new Map(),
    commentSnapshotRequests: new Map(),
    commentsByIssue: new Map(),
    commentSnapshotMetadataDriftIssueNumbers: new Set(),
    stateSnapshotMetadataDriftIssueNumbers: new Set(),
    fixEvidenceByIssue: new Map(),
    fixEvidenceRequests: new Map(),
    pullRequestsByKey: new Map(),
    pullRequestRequests: new Map(),
    permissiveMissingPullRequestKeys: new Set(),
    assertCanWrite: options.assertCanWrite,
    issueEvidenceRevisionsByIssue: new Map(),
  };
}

async function withClosureProofWriteLease<T>(
  runContext: ClosureProofRunContext | undefined,
  operation: string,
  work: (context: ClosureProofRunContext) => Promise<T>,
): Promise<T> {
  if (runContext?.assertCanWrite) return work(runContext);
  const lease = acquireRenewableRefreshLease(`closure-proof:${operation}`);
  const context = runContext ?? createClosureProofRunContext();
  const previousAssertCanWrite = context.assertCanWrite;
  context.assertCanWrite = (stage) => lease.assertHeld(stage);
  try {
    return await work(context);
  } finally {
    context.assertCanWrite = previousAssertCanWrite;
    lease.release();
  }
}

const trackedPrRepositorySqlLiteral = `${config.github.owner}/${config.github.repo}`.replace(/'/g, "''");
const trackedPrRepositoryNameWithOwner = `${config.github.owner}/${config.github.repo}`;
const FINAL_CLOSURE_COMMENT_LOOKBACK_MS = 72 * 60 * 60 * 1000;
const FINAL_CLOSURE_TIMESTAMP_TOLERANCE_MS = 2_000;
const CLOSURE_COMMENT_LINK_SOURCES = ['ClosureComment.fixProof', 'ClosureComment.prMention'] as const;
const CLOSURE_COMMENT_LINK_SOURCES_SQL = CLOSURE_COMMENT_LINK_SOURCES.map((source) => `'${source}'`).join(', ');
const STATUS_BEARING_PR_SOURCES = new Set([
  'closedByPullRequestsReferences',
  'ClosedEvent.closer',
  ...CLOSURE_COMMENT_LINK_SOURCES,
]);
const AGGREGATE_CREDITED_FIX_LINK_SQL = creditedFixLinkSql('l', 'p');
const FINAL_CLOSURE_EVENT_CTES = `
ranked_closure AS (
  SELECT
    event.*,
    ROW_NUMBER() OVER (
      PARTITION BY event.issue_number
      ORDER BY
        julianday(event.closed_at) DESC,
        event.connection_ordinal DESC,
        event.event_id DESC
    ) AS final_close_rank
  FROM issue_closure_events event
  WHERE event.closed_at IS NOT NULL
),
final_closure AS (
  SELECT *
  FROM ranked_closure
  WHERE final_close_rank=1
)
`;
const LINKED_PR_SOURCE_PRIORITY_SQL = `
  CASE l2.source
    WHEN 'closedByPullRequestsReferences' THEN 0
    WHEN 'ClosedEvent.closer' THEN 1
    WHEN 'ClosureComment.fixProof' THEN 2
    WHEN 'ClosureComment.prMention' THEN 3
    ELSE 4
  END
`;

export function issueStateSnapshotMetadataMatches(
  evidence: GhIssueFixEvidence | undefined,
  issue: Pick<
    NonNullable<ReturnType<typeof getIssue>>,
    'number' | 'node_id' | 'state' | 'updated_at'
  > | undefined,
  commentSnapshot: Pick<
    GhIssueCommentSnapshot,
    'repositoryNodeId' | 'issueNumber' | 'issueNodeId' | 'issueNodeType' | 'issueUpdatedAt'
  > | undefined,
): boolean {
  const stateSnapshot = evidence?.stateSnapshot;
  return !!stateSnapshot &&
    !!issue &&
    !!commentSnapshot &&
    stateSnapshot.schemaVersion === ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION &&
    evidence.repositoryNodeId === commentSnapshot.repositoryNodeId &&
    stateSnapshot.repositoryNodeId === evidence.repositoryNodeId &&
    stateSnapshot.issueNumber === issue.number &&
    stateSnapshot.issueNumber === commentSnapshot.issueNumber &&
    evidence.issueNodeId === issue.node_id &&
    evidence.issueNodeId === commentSnapshot.issueNodeId &&
    evidence.issueNodeType === 'Issue' &&
    commentSnapshot.issueNodeType === 'Issue' &&
    stateSnapshot.issueState === issue.state &&
    stateSnapshot.issueUpdatedAt === issue.updated_at &&
    stateSnapshot.issueUpdatedAt === commentSnapshot.issueUpdatedAt &&
    stateSnapshot.fetchedCount === stateSnapshot.totalCount &&
    stateSnapshot.sweepCount >= 2 &&
    stateSnapshot.stabilized === true &&
    stateSnapshot.stabilization?.sweepCount === stateSnapshot.sweepCount &&
    stateSnapshot.stabilization.secondSweep.sweepDigest === stateSnapshot.authorityDigest;
}

export function replaceVerifiedIssueStateEventSnapshot(
  evidence: GhIssueFixEvidence,
): void {
  const snapshot = evidence.stateSnapshot;
  const stabilization = snapshot.stabilization;
  if (snapshot.repositoryNodeId !== evidence.repositoryNodeId) {
    throw new Error(
      `Issue #${evidence.issueNumber} state-event snapshot repository identity ` +
      `${snapshot.repositoryNodeId} does not match fix evidence ${evidence.repositoryNodeId}`,
    );
  }
  if (snapshot.issueNumber !== evidence.issueNumber) {
    throw new Error(
      `State-event snapshot issue #${snapshot.issueNumber} does not match fix evidence ` +
      `issue #${evidence.issueNumber}`,
    );
  }
  if (
    typeof evidence.issueNodeId !== 'string' ||
    evidence.issueNodeId.length === 0 ||
    evidence.issueNodeId.trim() !== evidence.issueNodeId ||
    evidence.issueNodeType !== 'Issue'
  ) {
    throw new Error(
      `Issue #${evidence.issueNumber} fix evidence is missing a canonical Issue node identity`,
    );
  }
  if (!snapshot.stabilized || !stabilization) {
    throw new Error(
      `Issue #${evidence.issueNumber} state-event snapshot is missing stabilization proof`,
    );
  }
  const normalizedEvents = normalizeIssueStateEvents([
    ...evidence.closureEvents.map((event) => {
      if (event.issueNumber !== evidence.issueNumber) {
        throw new Error(
          `Closure event ${event.eventId} belongs to issue #${event.issueNumber}, ` +
          `not #${evidence.issueNumber}`,
        );
      }
      return {
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
      };
    }),
    ...evidence.reopenEvents.map((event) => {
      if (event.issueNumber !== evidence.issueNumber) {
        throw new Error(
          `Reopen event ${event.eventId} belongs to issue #${event.issueNumber}, ` +
          `not #${evidence.issueNumber}`,
        );
      }
      return {
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
      };
    }),
  ]);
  assertAuthoritativeIssueStateEvents(normalizedEvents);
  const identity = {
    repositoryNodeId: evidence.repositoryNodeId,
    issueNodeId: evidence.issueNodeId,
    issueNodeType: evidence.issueNodeType,
  };
  if (issueStateEventsDigest(normalizedEvents, identity) !== snapshot.eventsDigest) {
    throw new Error(
      `Issue #${evidence.issueNumber} state-event snapshot issue node identity or events ` +
      `do not match the fix evidence`,
    );
  }
  const authorityDigest = issueStateEventSweepDigest({
    repositoryNodeId: evidence.repositoryNodeId,
    issueNumber: evidence.issueNumber,
    issueNodeId: evidence.issueNodeId,
    issueNodeType: evidence.issueNodeType,
    issueState: snapshot.issueState,
    issueUpdatedAt: snapshot.issueUpdatedAt,
    totalCount: snapshot.totalCount,
    events: normalizedEvents,
  });
  if (
    authorityDigest !== snapshot.authorityDigest ||
    snapshot.sweepIdentity.sweepDigest !== authorityDigest ||
    stabilization.secondSweep.sweepDigest !== authorityDigest
  ) {
    throw new Error(
      `Issue #${evidence.issueNumber} state-event snapshot authority identity ` +
      `does not match the fix evidence`,
    );
  }
  runInWriteTransaction(() => {
    replaceIssueStateEventSnapshot({
      issue_number: evidence.issueNumber,
      repository_node_id: evidence.repositoryNodeId,
      issue_node_id: evidence.issueNodeId,
      issue_node_type: evidence.issueNodeType,
      schema_version: snapshot.schemaVersion,
      issue_state: snapshot.issueState,
      issue_updated_at: snapshot.issueUpdatedAt,
      total_count: snapshot.totalCount,
      fetched_count: snapshot.fetchedCount,
      events_digest: snapshot.eventsDigest,
      authority_digest: snapshot.authorityDigest,
      sweep_count: snapshot.sweepCount,
      stabilized: snapshot.stabilized,
      stabilization,
      closure_events: evidence.closureEvents.map((event) => ({
        issue_number: event.issueNumber,
        issue_node_id: evidence.issueNodeId,
        event_id: event.eventId,
        closed_at: event.closedAt,
        connection_ordinal: event.connectionOrdinal,
        actor_node_id: event.actorNodeId,
        actor_login: event.actorLogin,
        actor_type: event.actorType,
        state_reason: event.stateReason,
        closer_type: event.closerType,
        closer_number: event.closerNumber,
        closer_node_id: event.closerNodeId,
        closer_oid: event.closerOid,
        raw_json: JSON.stringify(event.raw),
      })),
      reopen_events: evidence.reopenEvents.map((event) => ({
        issue_number: event.issueNumber,
        issue_node_id: evidence.issueNodeId,
        event_id: event.eventId,
        reopened_at: event.reopenedAt,
        connection_ordinal: event.connectionOrdinal,
        actor_node_id: event.actorNodeId,
        actor_login: event.actorLogin,
        actor_type: event.actorType,
        raw_json: JSON.stringify(event.raw),
      })),
    });
    deleteStateDerivedIssuePrLinksForIssues([evidence.issueNumber]);
    deleteIssueCommitReferencesForIssues([evidence.issueNumber]);
    for (const link of evidence.prLinks) {
      upsertIssuePrLink({
        issue_number: link.issueNumber,
        issue_node_id: evidence.issueNodeId,
        pr_repository_owner: link.prRepositoryOwner,
        pr_repository_name: link.prRepositoryName,
        pr_repository_name_with_owner: link.prRepositoryNameWithOwner,
        pr_number: link.prNumber,
        source: link.source,
        will_close_target: link.willCloseTarget == null ? null : link.willCloseTarget ? 1 : 0,
        referenced_at: link.referencedAt,
      });
    }
    for (const ref of evidence.commitReferences) {
      upsertIssueCommitReference({
        issue_number: ref.issueNumber,
        issue_node_id: evidence.issueNodeId,
        event_id: ref.eventId,
        commit_oid: ref.commitOid,
        commit_message_headline: ref.commitMessageHeadline,
        commit_repository_owner: ref.commitRepositoryOwner,
        commit_repository_name: ref.commitRepositoryName,
        commit_repository_name_with_owner: ref.commitRepositoryNameWithOwner,
        is_cross_repository: ref.isCrossRepository ? 1 : 0,
        is_direct_reference: ref.isDirectReference ? 1 : 0,
        referenced_at: ref.referencedAt,
        actor_login: ref.actorLogin,
        raw_json: JSON.stringify(ref.raw),
      });
    }
    for (const pr of evidence.pullRequests) {
      upsertPullRequestFix({
        pr_repository_owner: pr.repositoryOwner,
        pr_repository_name: pr.repositoryName,
        pr_repository_name_with_owner: pr.repositoryNameWithOwner,
        pr_number: pr.number,
        title: pr.title,
        url: pr.url,
        state: pr.state,
        merged: pr.merged ? 1 : 0,
        merged_at: pr.mergedAt,
        merge_commit_oid: pr.mergeCommitOid,
        base_ref_name: pr.baseRefName,
      });
    }
  });
}

function finalClosureCommentLinkSql(linkAlias: string, closureAlias: string): string {
  return `(
    ${closureAlias}.event_id IS NOT NULL
    AND ${linkAlias}.referenced_at IS NOT NULL
    AND julianday(${linkAlias}.referenced_at) < julianday(${closureAlias}.closed_at)
    AND julianday(${linkAlias}.referenced_at) >= julianday(${closureAlias}.closed_at, '-${FINAL_CLOSURE_COMMENT_LOOKBACK_MS / (60 * 60 * 1000)} hours')
    AND (
      ${closureAlias}.final_reopened_at IS NULL
      OR julianday(${linkAlias}.referenced_at) > julianday(${closureAlias}.final_reopened_at)
    )
  )`;
}

function finalClosureCreditedFixLinkSql(
  linkAlias: string,
  prAlias: string,
  closureAlias: string,
): string {
  const creditedLinkSql = linkAlias === 'l' && prAlias === 'p'
    ? AGGREGATE_CREDITED_FIX_LINK_SQL
    : creditedFixLinkSql(linkAlias, prAlias);
  return `(
    ${creditedLinkSql}
    AND (
      (
        ${linkAlias}.source='ClosureComment.fixProof'
        AND ${finalClosureCommentLinkSql(linkAlias, closureAlias)}
      )
      OR (
        ${linkAlias}.source!='ClosureComment.fixProof'
        AND ${closureAlias}.closer_type='PullRequest'
        AND ${closureAlias}.closer_number=${linkAlias}.pr_number
      )
    )
  )`;
}

function finalClosureLinkedPrContextSql(linkAlias: string, closureAlias: string): string {
  return `(
    (
      ${linkAlias}.source IN (${CLOSURE_COMMENT_LINK_SOURCES_SQL})
      AND ${finalClosureCommentLinkSql(linkAlias, closureAlias)}
    )
    OR (
      ${linkAlias}.source IN ('closedByPullRequestsReferences', 'ClosedEvent.closer')
      AND ${closureAlias}.closer_type='PullRequest'
      AND ${closureAlias}.closer_number=${linkAlias}.pr_number
    )
    OR ${linkAlias}.source NOT IN (
      ${CLOSURE_COMMENT_LINK_SOURCES_SQL},
      'closedByPullRequestsReferences',
      'ClosedEvent.closer'
    )
  )`;
}

const closedIssueRowsStmt = db.prepare(`
WITH target AS (
  SELECT * FROM releases WHERE tag=? AND catalog_active=1
)
SELECT DISTINCT
  i.number,
  i.title,
  i.closed_at
FROM issues i
JOIN target
WHERE i.closed_at IS NOT NULL
  AND target.published_at IS NOT NULL
  AND i.closed_at >= target.published_at
  AND i.closed_at < COALESCE(
    (SELECT MIN(next.published_at) FROM releases next
     WHERE next.published_at > target.published_at
       AND next.prerelease=0
       AND next.catalog_active=1),
    '9999-12-31T23:59:59Z'
  )
ORDER BY i.closed_at DESC
`);

const allClosedIssueRowsStmt = db.prepare(`
WITH target AS (
  SELECT * FROM releases WHERE tag=? AND catalog_active=1
)
SELECT DISTINCT i.number
FROM issues i
JOIN target
WHERE i.closed_at IS NOT NULL
  AND target.published_at IS NOT NULL
  AND i.closed_at >= target.published_at
  AND i.closed_at < COALESCE(
    (SELECT MIN(next.published_at) FROM releases next
     WHERE next.published_at > target.published_at
       AND next.prerelease=0
       AND next.catalog_active=1),
    '9999-12-31T23:59:59Z'
  )
ORDER BY i.number DESC
`);

const aggregateRowsStmt = db.prepare(`
WITH selected(issue_number) AS (
  SELECT value FROM json_each(?)
),
${FINAL_CLOSURE_EVENT_CTES},
window_closure AS (
  SELECT
    e.*,
    wi.closed_at AS issue_closed_at,
    (
      SELECT r.reopened_at
      FROM issue_reopen_events r
      WHERE r.issue_number=e.issue_number
        AND r.reopened_at IS NOT NULL
        AND (
          julianday(r.reopened_at) < julianday(e.closed_at)
          OR (
            julianday(r.reopened_at)=julianday(e.closed_at)
            AND r.connection_ordinal < e.connection_ordinal
          )
        )
      ORDER BY
        julianday(r.reopened_at) DESC,
        r.connection_ordinal DESC,
        r.event_id DESC
      LIMIT 1
    ) AS final_reopened_at
  FROM final_closure e
  JOIN issues wi
    ON wi.number=e.issue_number
)
SELECT
  i.number,
  i.title,
  i.author,
  i.labels,
  i.closed_at,
  c.issue_number AS classification_issue_number,
  c.prompt_version AS classification_prompt_version,
  c.sentiment,
  c.severity,
  c.scope,
  c.functionality,
  c.affected_users,
  c.has_workaround,
  c.workaround_status,
  c.duplicate_cluster,
  c.affects_version,
  c.confidence,
  c.rationale,
  e.state_reason AS state_reasons,
  e.actor_login AS closure_actors,
  e.closed_at AS closure_event_closed_at,
  e.connection_ordinal AS closure_event_connection_ordinal,
  e.final_reopened_at,
  CASE WHEN e.event_id IS NULL THEN 0 ELSE 1 END AS closure_events,
    COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${finalClosureCreditedFixLinkSql('l', 'p', 'e')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
      THEN l.pr_repository_name_with_owner || '#' || l.pr_number END
  ) AS closing_links,
  COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${finalClosureCreditedFixLinkSql('l', 'p', 'e')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
       AND p.merged=1
      THEN p.pr_repository_name_with_owner || '#' || p.pr_number END
  ) AS merged_closing_prs,
  COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${finalClosureCreditedFixLinkSql('l', 'p', 'e')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
       AND p.merged=1
       AND rpr.status='reachable'
      THEN p.pr_repository_name_with_owner || '#' || p.pr_number END
  ) AS reachable_closing_prs,
  COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${finalClosureCreditedFixLinkSql('l', 'p', 'e')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
       AND p.merged=1
       AND rpr.status='not_reachable'
      THEN p.pr_repository_name_with_owner || '#' || p.pr_number END
  ) AS not_reachable_closing_prs,
  GROUP_CONCAT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${finalClosureCreditedFixLinkSql('l', 'p', 'e')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
      THEN p.pr_repository_name_with_owner || '#' || p.pr_number || ':' || COALESCE(p.title, '')
    END
  ) AS closing_prs,
  GROUP_CONCAT(DISTINCT CASE
    WHEN e.state_reason='COMPLETED'
     AND e.closer_type='Commit'
     AND e.closer_oid IS NOT NULL
    THEN e.closer_oid
    END
  ) AS direct_closer_commits,
  (
      SELECT COALESCE(json_group_array(json_object(
        'number', linked.pr_number,
        'repositoryOwner', linked.pr_repository_owner,
        'repositoryName', linked.pr_repository_name,
        'repositoryNameWithOwner', linked.pr_repository_name_with_owner,
        'source', linked.source,
        'trustedFixProof', linked.trusted_fix_proof,
      'willCloseTarget', linked.will_close_target,
      'referencedAt', linked.referenced_at,
      'sourceCommentDatabaseId', linked.source_comment_database_id,
      'sourceCommentUrl', linked.source_comment_url,
      'metadataMissing', CASE WHEN linked.metadata_pr_number IS NULL THEN 1 ELSE 0 END,
      'title', linked.title,
      'url', linked.url,
      'state', linked.state,
      'merged', linked.merged,
      'mergedAt', linked.merged_at
    )), '[]')
    FROM (
        SELECT DISTINCT
          l2.pr_repository_owner,
          l2.pr_repository_name,
          l2.pr_repository_name_with_owner,
          l2.pr_number,
        l2.source,
        l2.will_close_target,
        l2.referenced_at,
        l2.source_comment_database_id,
        l2.source_comment_url,
        p2.pr_number AS metadata_pr_number,
        p2.title,
        p2.url,
        p2.state,
        p2.merged,
        p2.merged_at,
        CASE
          WHEN e.state_reason='COMPLETED'
           AND ${finalClosureCreditedFixLinkSql('l2', 'p2', 'e')}
           AND l2.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
          THEN 1
          ELSE 0
        END AS trusted_fix_proof
      FROM issue_pr_links l2
        LEFT JOIN pull_request_fixes p2 ON p2.pr_repository_name_with_owner=l2.pr_repository_name_with_owner AND p2.pr_number=l2.pr_number
      WHERE l2.issue_number=i.number
        AND ${finalClosureLinkedPrContextSql('l2', 'e')}
        ORDER BY
          CASE WHEN p2.state='OPEN' AND p2.merged=0 THEN 0 ELSE 1 END,
          l2.pr_repository_name_with_owner,
          l2.pr_number,
          ${LINKED_PR_SOURCE_PRIORITY_SQL}
    ) linked
  ) AS linked_prs_json
FROM selected
JOIN issues i ON i.number=selected.issue_number
LEFT JOIN classifications c ON c.issue_number=i.number
LEFT JOIN window_closure e ON e.issue_number=i.number
LEFT JOIN issue_pr_links l ON l.issue_number=i.number
  LEFT JOIN pull_request_fixes p ON p.pr_repository_name_with_owner=l.pr_repository_name_with_owner AND p.pr_number=l.pr_number
  LEFT JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_repository_name_with_owner=l.pr_repository_name_with_owner AND rpr.pr_number=l.pr_number
GROUP BY i.number
ORDER BY i.closed_at DESC
`);

const issueCommitReferenceRowsStmt = db.prepare(`
WITH selected(issue_number) AS (
  SELECT value FROM json_each(?)
)
SELECT
  r.issue_number,
  r.commit_oid,
  r.commit_message_headline,
  r.referenced_at,
  r.actor_login,
  r.event_id,
  i.closed_at
FROM issue_commit_references r
JOIN selected s ON s.issue_number=r.issue_number
JOIN issues i ON i.number=r.issue_number
WHERE r.is_direct_reference=1
  AND r.is_cross_repository=0
  AND r.commit_repository_name_with_owner=?
ORDER BY r.referenced_at
`);

const releasePublishedAtStmt = db.prepare(`
SELECT published_at FROM releases WHERE tag=? AND catalog_active=1
`);

const activeStableReleaseBoundaryRowsStmt = db.prepare(`
SELECT tag
FROM releases
WHERE prerelease=0
  AND catalog_active=1
ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC, tag
`);

function immediateStablePredecessorTag(targetTag: string): string | null {
  const rows = activeStableReleaseBoundaryRowsStmt.all() as Array<{ tag: string }>;
  const targetIndex = rows.findIndex((row) => row.tag === targetTag);
  return targetIndex >= 0 ? rows[targetIndex + 1]?.tag ?? null : null;
}

const crossReleaseTerminalProofRowsStmt = db.prepare(`
SELECT p.release_tag, p.status, p.summary, p.evidence_json, r.published_at
FROM issue_closure_proofs p
LEFT JOIN releases r ON r.tag=p.release_tag
WHERE p.issue_number=?
  AND p.release_tag!=?
  AND r.catalog_active=1
ORDER BY r.published_at IS NULL, r.published_at DESC, p.release_tag DESC
`);

const laterStableReleaseTagsStmt = db.prepare(`
SELECT later.tag
FROM releases source
JOIN releases later
  ON later.prerelease=0
 AND later.published_at > source.published_at
 AND later.catalog_active=1
WHERE source.tag=?
  AND source.catalog_active=1
ORDER BY later.published_at ASC
`);

const latestStableReleaseStmt = db.prepare(`
SELECT tag, published_at
FROM releases
WHERE prerelease=0
  AND catalog_active=1
ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC
LIMIT 1
`);

const laterPrReachabilityStmt = db.prepare(`
SELECT rpr.tag, r.published_at
FROM releases source
JOIN release_pr_reachability rpr
  ON rpr.pr_repository_name_with_owner=?
 AND rpr.pr_number=?
 AND rpr.status='reachable'
JOIN releases r
  ON r.tag=rpr.tag
 AND r.prerelease=0
 AND r.published_at > source.published_at
 AND r.catalog_active=1
WHERE source.tag=?
  AND source.catalog_active=1
ORDER BY r.published_at ASC
LIMIT 1
`);

const releasePrReachabilityStatusStmt = db.prepare(`
SELECT status, tag_commit_oid, merge_commit_oid, method, evidence_json
FROM release_pr_reachability
WHERE tag=?
  AND pr_repository_name_with_owner=?
  AND pr_number=?
`);

const issueExistsStmt = db.prepare(`SELECT 1 FROM issues WHERE number=?`);
const issueFinalClosureContextRowsStmt = db.prepare(`
WITH ${FINAL_CLOSURE_EVENT_CTES}
SELECT
  i.number,
  i.closed_at AS issue_closed_at,
  closure.closed_at AS final_closed_at,
  closure.connection_ordinal AS final_connection_ordinal,
  closure.actor_login AS final_actor_login,
  (
    SELECT r.reopened_at
    FROM issue_reopen_events r
    WHERE r.issue_number=i.number
      AND r.reopened_at IS NOT NULL
      AND closure.event_id IS NOT NULL
      AND (
        julianday(r.reopened_at) < julianday(closure.closed_at)
        OR (
          julianday(r.reopened_at)=julianday(closure.closed_at)
          AND r.connection_ordinal < closure.connection_ordinal
        )
      )
    ORDER BY
      julianday(r.reopened_at) DESC,
      r.connection_ordinal DESC,
      r.event_id DESC
    LIMIT 1
  ) AS final_reopened_at
FROM issues i
LEFT JOIN final_closure closure ON closure.issue_number=i.number
WHERE i.number IN (SELECT value FROM json_each(?))
`);
const issueCommentMetadataRowsStmt = db.prepare(`
SELECT
  issues.number,
  issues.updated_at,
  issues.comments,
  snapshots.schema_version AS snapshot_schema_version,
  snapshots.issue_updated_at AS snapshot_issue_updated_at,
  snapshots.comment_count AS snapshot_comment_count,
  snapshots.fetched_comment_count AS snapshot_fetched_comment_count,
  snapshots.comments_digest AS snapshot_comments_digest,
  snapshots.repository_node_id AS snapshot_repository_node_id,
  snapshots.issue_node_id AS snapshot_issue_node_id,
  snapshots.issue_author_node_id AS snapshot_issue_author_node_id,
  snapshots.issue_author_login AS snapshot_issue_author_login,
  snapshots.issue_author_type AS snapshot_issue_author_type,
  snapshots.authority_digest AS snapshot_authority_digest,
  snapshots.stabilization_identity_digest AS snapshot_stabilization_identity_digest,
  classifications.classified_updated_at,
  classifications.classified_comments_digest,
  classifications.source_identity_digest AS classification_source_identity_digest
FROM issues
LEFT JOIN issue_comment_snapshots snapshots ON snapshots.issue_number=issues.number
LEFT JOIN classifications ON classifications.issue_number=issues.number
WHERE issues.number IN (SELECT value FROM json_each(?))
`);
const mutablePullRequestLookupsStmt = db.prepare(`
SELECT DISTINCT
  links.pr_repository_owner,
  links.pr_repository_name,
  links.pr_repository_name_with_owner,
  links.pr_number
FROM issue_pr_links links
LEFT JOIN pull_request_fixes pull
  ON pull.pr_repository_name_with_owner=links.pr_repository_name_with_owner
 AND pull.pr_number=links.pr_number
WHERE pull.pr_number IS NULL
   OR (
     UPPER(COALESCE(pull.state, ''))='OPEN'
     AND (
       pull.checked_at IS NULL
       OR unixepoch(pull.checked_at) < unixepoch('now', '-' || ? || ' minutes')
     )
   )
   OR (
     pull.merged=0
     AND UPPER(COALESCE(pull.state, ''))!='OPEN'
     AND (
       pull.checked_at IS NULL
       OR unixepoch(pull.checked_at) < unixepoch('now', '-' || ? || ' minutes')
     )
   )
ORDER BY links.pr_repository_name_with_owner, links.pr_number
`);
const deleteExpiredUnknownDirectCommitProofsStmt = db.prepare(`
DELETE FROM issue_closure_proofs
WHERE release_tag=?
  AND checked_at < ?
  AND EXISTS (
    SELECT 1
    FROM json_each(
      CASE WHEN json_valid(issue_closure_proofs.evidence_json)
        THEN issue_closure_proofs.evidence_json
        ELSE '{}'
      END,
      '$.directFixCommitProof'
    ) proof
    WHERE json_extract(proof.value, '$.status')='unknown'
  )
`);

export async function discoverClosureProofDependenciesForRelease(
  releaseTag: string,
  options: {
    runContext?: ClosureProofRunContext;
    refreshCommentPrMentionEvidence?: boolean;
  } = {},
): Promise<ClosureProofPreparedDependencies> {
  if (!options.runContext?.assertCanWrite) {
    return withClosureProofWriteLease(
      options.runContext,
      `discover:${releaseTag}`,
      (runContext) => discoverClosureProofDependenciesForRelease(releaseTag, {
        ...options,
        runContext,
      }),
    );
  }
  const runContext = options.runContext;
  assertClosureProofWriteAllowed(runContext, `unknown direct commit proof freshness for ${releaseTag}`);
  invalidateExpiredUnknownDirectCommitProofs(releaseTag);
  const refreshCommentPrMentions = options.refreshCommentPrMentionEvidence ?? true;
  const analysisStartedAt = new Date().toISOString();
  const release = getRelease(releaseTag);
  const labelCutoff = release ? releaseLabelCutoff(release, analysisStartedAt) : null;
  const closedRows = closedIssueRowsStmt.all(releaseTag) as Array<{ number: number }>;
  const issueNumbers = closedRows.map((row) => row.number);
  const sourceIssueNumbers = new Set(issueNumbers);
  const commentsByIssue = await commentsForIssues(runContext, issueNumbers);
  const sourceAggregateRows = issueNumbers.length
    ? aggregateRowsStmt.all(JSON.stringify(issueNumbers), releaseTag) as Array<any>
    : [];
  const allCommentsByIssue = runContext.commentsByIssue;
  const canonicalIssueNumbers = new Set<number>();
  const canonicalGraph = new Map<number, number[]>();
  const sourceClosureContextByIssue = new Map(sourceAggregateRows.map((row: any) => [
    Number(row.number),
    {
      closedAt: (row.closure_event_closed_at ?? row.closed_at) as string | null,
      finalReopenedAt: row.final_reopened_at as string | null,
      closureActors: splitCsv(row.closure_actors),
    },
  ]));
  for (const issueNumber of issueNumbers) {
    const numbers = trustedCanonicalIssueNumbersFromComments(
      commentsByIssue.get(issueNumber) ?? [],
      issueNumber,
      sourceClosureContextByIssue.get(issueNumber),
      knownIssueNumber,
    );
    canonicalGraph.set(issueNumber, numbers);
    for (const number of numbers) canonicalIssueNumbers.add(number);
  }
  await expandCanonicalGraph(
    canonicalGraph,
    allCommentsByIssue,
    [...canonicalIssueNumbers],
    (numbers) => commentsForIssues(runContext, numbers),
    false,
  );
  const terminalCanonicalIssuesToBackfill = terminalCanonicalIssuesNeedingEvidence(releaseTag, issueNumbers, canonicalGraph);
  if (terminalCanonicalIssuesToBackfill.length) {
    await refreshRawClosureEvidence(terminalCanonicalIssuesToBackfill, runContext);
    await commentsForIssues(runContext, terminalCanonicalIssuesToBackfill);
  }
  const analysisIssueNumbers = closureProofDependencyIssueNumbers(
    issueNumbers,
    canonicalGraph,
    terminalCanonicalIssuesToBackfill,
  );
  if (refreshCommentPrMentions) {
    await refreshClosureCommentPrMentionEvidence(analysisIssueNumbers, allCommentsByIssue, runContext);
  }
  return {
    releaseTag,
    analysisStartedAt,
    labelCutoff,
    issueNumbers,
    sourceIssueNumbers,
    allCommentsByIssue,
    canonicalGraph,
    analysisIssueNumbers,
  };
}

export async function refreshMutablePullRequestMetadata(
  runContext?: ClosureProofRunContext,
): Promise<number> {
  if (!runContext?.assertCanWrite) {
    return withClosureProofWriteLease(
      runContext,
      'mutable-pr-metadata',
      (leasedContext) => refreshMutablePullRequestMetadata(leasedContext),
    );
  }
  const lookups = (mutablePullRequestLookupsStmt.all(
    config.refresh.openPullRequestRefreshMinutes,
    config.refresh.closedPullRequestRefreshMinutes,
  ) as unknown as Array<{
    pr_repository_owner: string;
    pr_repository_name: string;
    pr_repository_name_with_owner: string;
    pr_number: number;
  }>).map((row) => ({
    prNumber: row.pr_number,
    prRepositoryOwner: row.pr_repository_owner,
    prRepositoryName: row.pr_repository_name,
    prRepositoryNameWithOwner: row.pr_repository_name_with_owner,
  }));
  const pullRequests = await pullRequestsForLookups(runContext, lookups, {
    allowMissing: true,
    refreshMissing: true,
  });
  assertClosureProofWriteAllowed(runContext, 'mutable pull request metadata persistence');
  runInWriteTransaction(() => {
    assertClosureProofWriteAllowed(
      runContext,
      'mutable pull request metadata persistence transaction',
    );
    for (const pullRequest of pullRequests.values()) {
      upsertPullRequestFix({
        pr_repository_owner: pullRequest.repositoryOwner,
        pr_repository_name: pullRequest.repositoryName,
        pr_repository_name_with_owner: pullRequest.repositoryNameWithOwner,
        pr_number: pullRequest.number,
        title: pullRequest.title,
        url: pullRequest.url,
        state: pullRequest.state,
        merged: pullRequest.merged ? 1 : 0,
        merged_at: pullRequest.mergedAt,
        merge_commit_oid: pullRequest.mergeCommitOid,
        base_ref_name: pullRequest.baseRefName,
      });
    }
  });
  return pullRequests.size;
}

export async function analyzeClosureProofsForRelease(
  releaseTag: string,
  options: AnalyzeClosureProofOptions = {},
): Promise<ClosureProofAnalysisResult> {
  if (!options.runContext?.assertCanWrite) {
    return withClosureProofWriteLease(
      options.runContext,
      `analyze:${releaseTag}`,
      (runContext) => analyzeClosureProofsForRelease(releaseTag, {
        ...options,
        runContext,
      }),
    );
  }
  const legacyPersistScoreAuditPayload = (
    options as AnalyzeClosureProofOptions & { persistScoreAuditPayload?: unknown }
  ).persistScoreAuditPayload;
  if (legacyPersistScoreAuditPayload !== undefined && legacyPersistScoreAuditPayload !== false) {
    throw new Error(
      'persistScoreAuditPayload=true is disabled because closure proof analysis cannot mutate ' +
      'the current score audit without rebuilding and sealing the full score run',
    );
  }
  const refreshPrReachability = options.refreshPrReachability ?? true;
  throwIfAborted(options.runContext!.signal);
  const prepared = options.preparedDependencies ?? await discoverClosureProofDependenciesForRelease(releaseTag, {
    runContext: options.runContext,
    refreshCommentPrMentionEvidence: options.refreshCommentPrMentionEvidence,
  });
  if (prepared.releaseTag !== releaseTag) {
    throw new Error(`Prepared closure-proof dependencies for ${prepared.releaseTag} cannot analyze ${releaseTag}`);
  }
  const {
    labelCutoff,
    issueNumbers,
    sourceIssueNumbers,
    allCommentsByIssue,
    canonicalGraph,
    analysisIssueNumbers: preparedAnalysisIssueNumbers,
  } = prepared;
  const analysisIssueNumbers = closureProofDependencyIssueNumbers(
    issueNumbers,
    canonicalGraph,
    preparedAnalysisIssueNumbers,
  );
  captureClosureIssueRevisionBaselines(options.runContext!, analysisIssueNumbers);
  const reachabilityContext = options.reachabilityContext ??
    createReleaseReachabilityRefreshContext({
      signal: options.runContext!.signal,
    });
  if (refreshPrReachability) {
    await checkReleasePrReachability(releaseTag, {
      context: reachabilityContext,
      signal: options.runContext!.signal,
      assertCanWrite: options.runContext!.assertCanWrite,
    });
  }
  const rawEvidence = rawClosureEvidenceCounts(issueNumbers);
  const aggregateRows = analysisIssueNumbers.length
    ? aggregateRowsStmt.all(JSON.stringify(analysisIssueNumbers), releaseTag) as Array<any>
    : [];
  assertAggregateFinalClosureAuthority(aggregateRows);
  const aggregateByIssue = new Map(aggregateRows.map((row: any) => [Number(row.number), row]));
  const closureWindowIssueNumbers = uniqueNumbers([
    ...analysisIssueNumbers,
    ...analysisIssueNumbers.flatMap((issueNumber) =>
      canonicalIssueNumbersReachableFrom(issueNumber, canonicalGraph)),
  ]);
  const finalClosureWindowByIssue = finalClosureWindowsForIssues(closureWindowIssueNumbers);
  const closureContextCommentsByIssue = new Map<number, GhComment[]>();
  for (const issueNumber of analysisIssueNumbers) {
    closureContextCommentsByIssue.set(
      issueNumber,
      closureRationaleCommentsForFinalClosure(
        allCommentsByIssue.get(issueNumber) ?? [],
        finalClosureWindowByIssue.get(issueNumber),
      ),
    );
  }
  const commitMentionsByIssue = new Map<number, ClosureCommentCommitMention[]>();
  const canonicalCommitMentionsByIssue = new Map<number, ClosureCommentCommitMention[]>();
  const referencedCommitMentionsByIssue = commitReferenceMentionsByIssue(analysisIssueNumbers);
  const useReferencedCommitProofIssues = new Set<number>();
  const allCommitOids = new Set<string>();
  for (const issueNumber of analysisIssueNumbers) {
    const directMentions = closureCommentCommitMentions(
      issueNumber,
      closureContextCommentsByIssue.get(issueNumber) ?? [],
      issueNumber,
      resolveCommitOidPrefix,
      {
        finalClosureActors: finalClosureWindowByIssue.get(issueNumber)?.closureActors ?? [],
      },
    );
    const canonicalMentions = canonicalIssueNumbersReachableFrom(issueNumber, canonicalGraph).flatMap((canonicalIssueNumber) =>
      closureCommentCommitMentions(
        issueNumber,
        closureRationaleCommentsForFinalClosure(
          allCommentsByIssue.get(canonicalIssueNumber) ?? [],
          finalClosureWindowByIssue.get(canonicalIssueNumber),
        ),
        canonicalIssueNumber,
        resolveCommitOidPrefix,
        {
          finalClosureActors:
            finalClosureWindowByIssue.get(canonicalIssueNumber)?.closureActors ?? [],
        },
      ),
    );
    const mentions = [...directMentions, ...canonicalMentions];
    commitMentionsByIssue.set(issueNumber, mentions);
    canonicalCommitMentionsByIssue.set(issueNumber, canonicalMentions);
    for (const mention of mentions) allCommitOids.add(mention.commitOid);
    const row = aggregateByIssue.get(issueNumber);
    if (shouldUseReferencedCommitProof({
      directMentionCount: directMentions.length,
      reachableClosingPrCount: Number(row?.reachable_closing_prs ?? 0),
    })) {
      useReferencedCommitProofIssues.add(issueNumber);
    }
  }
  for (const row of aggregateRows) {
    for (const commitOid of splitCsv(row.direct_closer_commits)) {
      if (fullCommitOidRe.test(commitOid)) allCommitOids.add(commitOid.toLowerCase());
    }
  }
  const commitReachability = await checkReleaseCommitReachability(releaseTag, [...allCommitOids], {
    context: reachabilityContext,
  });
  const predecessorTag = immediateStablePredecessorTag(releaseTag);
  const directCommitFirstContainingProofs = await checkDirectCommitFirstContainingReleaseBulk(
    [...allCommitOids]
      .sort()
      .map((commitOid) => ({
        repositoryNameWithOwner: trackedPrRepositoryNameWithOwner,
        commitOid,
        targetTag: releaseTag,
        predecessorTag,
      })),
    { context: reachabilityContext },
  );
  const directCommitFirstContainingProofByCommit = new Map(
    directCommitFirstContainingProofs.map((proof) => [proof.commitOid, proof]),
  );
  const laterCommitReachability = await laterReachableReleaseByCommit(
    releaseTag,
    commitReachability,
    reachabilityContext,
  );
  const preparedRows: Array<{
    issueNumber: number;
    result: ClosureProofResult;
    evidence: Record<string, unknown>;
  }> = [];

  for (const row of aggregateRows) {
    const trustedClosureComments = trustedClosureRationaleComments(
      closureContextCommentsByIssue.get(row.number) ?? [],
      row.author,
      splitCsv(row.closure_actors),
    );
    const comments = trustedClosureComments.map((comment) => ({
      id: comment.id,
      issueNumber: row.number,
      url: comment.url ?? null,
      author: comment.user?.login ?? null,
      body: comment.body,
      createdAt: comment.created_at,
      updatedAt: comment.updated_at ?? null,
    }));
    const canonicalMentionKeys = new Set(
      (canonicalCommitMentionsByIssue.get(row.number) ?? [])
        .map((mention) => `${mention.sourceIssueNumber}:${mention.commitOid}`),
    );
    const directMentions = (commitMentionsByIssue.get(row.number) ?? [])
      .filter((mention) => !canonicalMentionKeys.has(`${mention.sourceIssueNumber}:${mention.commitOid}`));
    const closureCommitMentions = directClosureCommitMentions(
      row.number,
      row.direct_closer_commits,
      row.closure_event_closed_at ?? row.closed_at,
    );
    const directCommitProof = commitProofEvidence([
      ...directMentions,
      ...(useReferencedCommitProofIssues.has(row.number) ? referencedCommitMentionsByIssue.get(row.number) ?? [] : []),
      ...closureCommitMentions,
    ], commitReachability);
    const canonicalCommitProof = commitProofEvidence(
      canonicalCommitMentionsByIssue.get(row.number) ?? [],
      commitReachability,
    );
    const trustedCanonicalIssues = canonicalIssueNumbersReachableFrom(
      row.number,
      canonicalGraph,
    );
    const releaseTagAnchorCommitContext = directCommitProof.filter((item) => item.releaseTagAnchor);
    const commitProof = creditableDirectCommitProof(directCommitProof);
    const fixCommitSummary = summarizeDirectCommitFirstContainingProofs({
      releaseTag,
      issueNumber: row.number,
      commitProof,
      proofByCommit: directCommitFirstContainingProofByCommit,
    });
    const issueDirectCommitFirstContainingProofs =
      fixCommitSummary.directCommitFirstContainingProofs;
    const closureClassification = effectiveClosureProofClassification(row, labelCutoff);
    const result = closureClassification.missingClassification
      ? missingClassificationClosureProof(row, fixCommitSummary)
      : classifyClosureProof({
        issueNumber: row.number,
        issueAuthor: row.author,
        closedAt: row.closed_at,
        sentiment: closureClassification.classification.sentiment,
        stateReasons: splitCsv(row.state_reasons),
        closureActors: splitCsv(row.closure_actors),
        hasClosureEvent: Number(row.closure_events ?? 0) > 0,
        hasClosingLink: Number(row.closing_links ?? 0) > 0,
        hasMergedClosingPr: Number(row.merged_closing_prs ?? 0) > 0,
        hasReachableClosingPr: Number(row.reachable_closing_prs ?? 0) > 0,
        hasNotReachableClosingPr: Number(row.not_reachable_closing_prs ?? 0) > 0,
        ...fixCommitSummary,
        comments,
      });
    const linkedPrs = enrichLinkedPrReachability(releaseTag, parseJsonArray(row.linked_prs_json));
    const evidence: Record<string, unknown> = {
      ...result.evidence,
      title: row.title,
      closedAt: row.closed_at,
      closureClassification,
      closureEventClosedAt: splitCsv(row.closure_event_closed_at),
      closingPrs: splitCsv(row.closing_prs),
      linkedPrs,
      fixCommitProof: commitProof,
      canonicalFixCommitProof: canonicalCommitProof,
      directFixCommitProof: directCommitProof,
      directCommitFirstContainingProofs: issueDirectCommitFirstContainingProofs,
      ...(releaseTagAnchorCommitContext.length > 0
        ? { releaseTagAnchorCommitContext }
        : {}),
      referencedCommitContext: referencedCommitMentionsByIssue.get(row.number) ?? [],
      canonicalFixCommitProofCount: canonicalCommitMentionsByIssue.get(row.number)?.length ?? 0,
      canonicalIssues: trustedCanonicalIssues,
      canonicalIssueDetails: canonicalIssueDetails(row.number, trustedCanonicalIssues),
    };
    const relatedPrContext = relatedPrContextEvidence(releaseTag, evidence);
    if (hasRelatedPrContext(relatedPrContext)) evidence.relatedPrContext = relatedPrContext;
    preparedRows.push({
      issueNumber: row.number,
      result: adjustClosureProofStatus(result, evidence, releaseTag, laterCommitReachability),
      evidence,
    });
  }

  for (const item of preparedRows) {
    const canonicalIssues = canonicalIssueNumbersReachableFrom(
      item.issueNumber,
      canonicalGraph,
    );
    item.evidence.canonicalIssues = canonicalIssues;
    item.evidence.canonicalIssueDetails = canonicalIssueDetails(
      item.issueNumber,
      canonicalIssues,
    );
  }
  const resultByIssue = new Map(preparedRows.map((item) => [item.issueNumber, item.result]));

  const proofRows = preparedRows.filter((item) => sourceIssueNumbers.has(item.issueNumber)).map((item) => {
    const adjusted = adjustCanonicalDuplicateStatus(item.issueNumber, item.result, item.evidence, canonicalGraph, resultByIssue, releaseTag);
    return {
      release_tag: releaseTag,
      issue_number: item.issueNumber,
      status: adjusted.status,
      summary: adjusted.summary,
      evidence_json: JSON.stringify({
        ...adjusted.evidence,
        proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
      }),
    };
  });
  const counts = new Map<string, number>();
  for (const row of proofRows) {
    counts.set(row.status, (counts.get(row.status) ?? 0) + 1);
  }
  const dependencyMembership = releaseClosureDependencyMembership(issueNumbers, proofRows);
  if (dependencyMembership.invalidEvidenceCount > 0) {
    throw new Error(
      `Closure proof construction produced ${dependencyMembership.invalidEvidenceCount} ` +
      `invalid evidence row(s) for ${releaseTag}`,
    );
  }
  const persistedDependencyIssueNumbers = new Set(dependencyMembership.issueNumbers);
  const omittedGraphIssueNumbers = analysisIssueNumbers.filter(
    (issueNumber) => !persistedDependencyIssueNumbers.has(issueNumber),
  );
  if (omittedGraphIssueNumbers.length > 0) {
    throw new Error(
      `Closure proof construction omitted canonical graph issue(s) for ${releaseTag}: ` +
      omittedGraphIssueNumbers.map((issueNumber) => `#${issueNumber}`).join(', '),
    );
  }
  const dependencyIdentity = releaseClosureDependencyIdentity(
    releaseTag,
    dependencyMembership.issueNumbers,
  );

  assertClosureProofWriteAllowed(options.runContext, `closure proof persistence for ${releaseTag}`);
  runInWriteTransaction(() => {
    assertClosureProofWriteAllowed(
      options.runContext,
      `closure proof persistence transaction for ${releaseTag}`,
    );
    deleteIssueClosureProofsForRelease(releaseTag);
    assertClosureIssueRevisions(options.runContext!, analysisIssueNumbers);
    for (const row of proofRows) upsertIssueClosureProof(row);
    replaceReleaseClosureDependencySnapshot(dependencyIdentity);
  });

  return {
    releaseTag,
    analyzed: proofRows.length,
    buckets: Object.fromEntries([...counts.entries()].sort((a, b) => b[1] - a[1])),
    rawEvidence,
  };
}

function commitProofEvidence(
  mentions: ClosureCommentCommitMention[],
  reachability: Map<string, CommitReachability>,
): Array<ClosureCommentCommitMention & {
  status: CommitReachability['status'];
  tagCommitOid: string | null;
  evidence: string;
  releaseTagAnchor: boolean;
  creditEligible: boolean;
}> {
  return mentions.map((mention) => {
    const result = reachability.get(mention.commitOid);
    const tagCommitOid = result?.tagCommitOid?.toLowerCase() ?? null;
    const releaseTagAnchor = mention.source === 'ClosureComment.fixProof' &&
      tagCommitOid != null &&
      mention.commitOid.toLowerCase() === tagCommitOid;
    return {
      ...mention,
      status: result?.status ?? 'unknown',
      tagCommitOid: result?.tagCommitOid ?? null,
      evidence: result?.evidence ?? 'reachability_not_checked',
      releaseTagAnchor,
      creditEligible: !releaseTagAnchor,
    };
  });
}

function creditableDirectCommitProof<T extends { creditEligible?: boolean }>(proof: T[]): T[] {
  return proof.filter((item) => item.creditEligible !== false);
}

type DirectCommitProofEvidenceRow = ReturnType<typeof commitProofEvidence>[number];

function summarizeDirectCommitFirstContainingProofs(input: {
  releaseTag: string;
  issueNumber: number;
  commitProof: DirectCommitProofEvidenceRow[];
  proofByCommit: ReadonlyMap<string, DirectCommitFirstContainingResult>;
}) {
  const issueCommitOids = unique(input.commitProof.map((item) => item.commitOid));
  const directCommitFirstContainingProofs = issueCommitOids
    .map((commitOid) => input.proofByCommit.get(commitOid))
    .filter((proof): proof is DirectCommitFirstContainingResult => proof != null);
  if (directCommitFirstContainingProofs.length !== issueCommitOids.length) {
    throw new Error(
      `Direct-commit first-containing proof coverage is incomplete for ` +
      `${input.releaseTag} issue #${input.issueNumber}`,
    );
  }
  const targetReachableFixCommits = unique(
    input.commitProof
      .filter((item) => item.status === 'reachable')
      .map((item) => item.commitOid),
  );
  const targetNotReachableFixCommits = unique(
    input.commitProof
      .filter((item) => item.status === 'not_reachable')
      .map((item) => item.commitOid),
  );
  const targetUnknownFixCommits = unique(
    input.commitProof
      .filter((item) => item.status === 'unknown')
      .map((item) => item.commitOid),
  );
  const reachableFixCommits = unique(
    directCommitFirstContainingProofs
      .filter((proof) => proof.creditEligible === true)
      .map((proof) => proof.commitOid),
  );
  const predecessorContainedFixCommits = unique(
    directCommitFirstContainingProofs
      .filter((proof) => proof.reasonCode === 'predecessor_contains_commit')
      .map((proof) => proof.commitOid),
  );
  const firstContainingUnknownFixCommits = unique(
    directCommitFirstContainingProofs
      .filter((proof) =>
        proof.creditEligible !== true &&
        proof.reasonCode !== 'predecessor_contains_commit' &&
        proof.reasonCode !== 'target_commit_not_reachable')
      .map((proof) => proof.commitOid),
  );
  const notReachableFixCommits = targetNotReachableFixCommits;
  const unknownFixCommits = unique([
    ...targetUnknownFixCommits,
    ...firstContainingUnknownFixCommits,
  ]);
  return {
    hasReachableFixCommit: targetReachableFixCommits.length > 0,
    hasNotReachableFixCommit: notReachableFixCommits.length > 0,
    hasUnknownFixCommit: unknownFixCommits.length > 0,
    reachableFixCommits,
    notReachableFixCommits,
    unknownFixCommits,
    targetReachableFixCommits,
    targetNotReachableFixCommits,
    targetUnknownFixCommits,
    predecessorContainedFixCommits,
    firstContainingUnknownFixCommits,
    directCommitFirstContainingProofs,
  };
}

function shouldUseReferencedCommitProof({
  directMentionCount,
  reachableClosingPrCount,
}: {
  directMentionCount: number;
  reachableClosingPrCount: number;
}): boolean {
  void directMentionCount;
  void reachableClosingPrCount;
  return false;
}

function enrichLinkedPrReachability(releaseTag: string, rawLinkedPrs: unknown[]): unknown[] {
  return rawLinkedPrs.map((item) => {
    if (!item || typeof item !== 'object') return item;
    const pr = item as Record<string, unknown>;
    const repo = String(pr.repositoryNameWithOwner ?? '');
    const prNumber = Number(pr.number ?? 0);
    const merged = Number(pr.merged ?? 0) === 1;
    if (!Number.isInteger(prNumber) || prNumber <= 0 || !merged) {
      return pr;
    }
    if (repo !== trackedPrRepositoryNameWithOwner) {
      return {
        ...pr,
        reachabilityStatus: 'external_repo_unchecked',
        reachabilityMethod: null,
        tagCommitOid: null,
        mergeCommitOid: null,
        reachabilityEvidence: 'external_repository_not_checked_against_openclaw_release_tag',
      };
    }
    const reachability = releasePrReachabilityStatusStmt.get(releaseTag, repo, prNumber) as {
      status: string;
      tag_commit_oid: string | null;
      merge_commit_oid: string | null;
      method: string | null;
      evidence_json?: string | null;
    } | undefined;
    const reachabilityEvidence = parseObjectJson(reachability?.evidence_json ?? null);
    return {
      ...pr,
      reachabilityStatus: reachability?.status ?? 'unknown',
      reachabilityMethod: reachability?.method ?? null,
      tagCommitOid: reachability?.tag_commit_oid ?? null,
      mergeCommitOid: reachability?.merge_commit_oid ?? null,
      reachabilityEvidence: typeof reachabilityEvidence.evidence === 'string'
        ? reachabilityEvidence.evidence
        : reachability ? 'reachability_checked' : 'reachability_not_checked',
    };
  });
}

function parseObjectJson(value: unknown): Record<string, unknown> {
  if (!value) return {};
  try {
    const parsed = JSON.parse(String(value));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function effectiveClosureProofClassification(
  row: any,
  labelCutoff: string | null = null,
  labelResolver = labelsForIssueAt,
  eventCount = issueLabelEventCount,
  snapshotCountAt = issueLabelSnapshotCountAt,
  labelEventResolver = latestIssueLabelEventAt,
  eventAuthorizedForScoring = labelEventAuthorityReference,
): {
  labels: string[];
  currentLabels: string[];
  labelCutoffAt: string | null;
  labelSource: 'current' | 'timeline' | 'snapshot' | 'missing_timeline';
  labelTimelineEventCount: number;
  labelSnapshotCount: number;
  labelActors: Record<string, string | null>;
  rawClassification: IssueClassification;
  classification: IssueClassification;
  classificationDiff: Record<string, { raw: unknown; effective: unknown }>;
  missingClassification: boolean;
  promptVersion: number | null;
} {
  const issueNumber = Number(row.number ?? row.issue_number ?? 0);
  const currentLabels = parseJsonArray(row.labels).filter((label): label is string => typeof label === 'string');
  const labelTimelineEventCount = Number.isInteger(issueNumber) && issueNumber > 0 ? eventCount(issueNumber) : 0;
  const labelSnapshotCount = Number.isInteger(issueNumber) && issueNumber > 0 ? snapshotCountAt(issueNumber, labelCutoff) : 0;
  const labelsAtCutoff = Number.isInteger(issueNumber) && issueNumber > 0
    ? labelResolver(issueNumber, currentLabels, labelCutoff, {
      useFallbackWhenNoEvents: labelCutoff == null,
      useSnapshotWhenNoEvents: labelCutoff != null,
    })
    : currentLabels;
  const labelAuthority = Number.isInteger(issueNumber) && issueNumber > 0
    ? scoringLabelInfoAtCutoff(
        issueNumber,
        labelsAtCutoff,
        labelCutoff,
        eventAuthorizedForScoring,
        labelEventResolver,
      )
    : {
        labels: labelsAtCutoff,
        authorizedScoringLabels: [],
        labelActors: Object.fromEntries(
          labelsAtCutoff.map((label) => [label, null]),
        ),
        authorityReferences: {},
      };
  const labels = labelAuthority.labels;
  const labelActors = labelAuthority.labelActors;
  const labelSource = closureProofLabelSource(labelCutoff, labelTimelineEventCount, labelSnapshotCount);
  const labelEvidence = {
    labels,
    currentLabels,
    labelCutoffAt: labelCutoff,
    labelSource,
    labelTimelineEventCount,
    labelSnapshotCount,
    labelActors,
  };
  if (!hasClassification(row)) {
    const fallback = missingClassificationFallback(row);
    return {
      ...labelEvidence,
      rawClassification: fallback,
      classification: fallback,
      classificationDiff: {},
      missingClassification: true,
      promptVersion: null,
    };
  }
  const rawClassification = rowToClassification(row);
  const classification = applyClosureRiskSentimentHint(
    applyTitleIssueShapeHint(
      applyLabelOverrides(
        applyTitleFunctionalityHint(rawClassification, row.title ?? ''),
        labels,
        labelAuthority,
      ),
      row.title ?? '',
      labels,
      labelAuthority,
    ),
    row.title ?? '',
    labels,
    labelAuthority,
  );
  return {
    ...labelEvidence,
    rawClassification,
    classification,
    classificationDiff: classificationDiff(rawClassification, classification),
    missingClassification: false,
    promptVersion: typeof row.classification_prompt_version === 'number' ? row.classification_prompt_version : null,
  };
}

function closureProofLabelSource(
  labelCutoff: string | null,
  timelineEventCount: number,
  snapshotCount: number,
): 'current' | 'timeline' | 'snapshot' | 'missing_timeline' {
  if (labelCutoff == null) return 'current';
  if (timelineEventCount > 0) return 'timeline';
  if (snapshotCount > 0) return 'snapshot';
  return 'missing_timeline';
}

function hasClassification(row: any): boolean {
  return typeof row.sentiment === 'string' &&
    typeof row.severity === 'string' &&
    typeof row.scope === 'string' &&
    typeof row.functionality === 'string' &&
    typeof row.affected_users === 'string';
}

function missingClassificationFallback(row: any): IssueClassification {
  return {
    sentiment: 'neutral',
    severity: 'low',
    scope: 'niche',
    functionality: 'docs',
    affectedUsers: 'unknown',
    workaroundStatus: 'unknown',
    duplicateCluster: row.duplicate_cluster ?? null,
    affectsVersion: row.affects_version ?? null,
    confidence: 0,
    rationale: 'missing classification evidence',
  };
}

function missingClassificationClosureProof(
  row: any,
  fixCommitSummary: {
    hasReachableFixCommit?: boolean;
    hasNotReachableFixCommit?: boolean;
    hasUnknownFixCommit?: boolean;
    reachableFixCommits?: string[];
    notReachableFixCommits?: string[];
    unknownFixCommits?: string[];
    targetReachableFixCommits?: string[];
    targetNotReachableFixCommits?: string[];
    targetUnknownFixCommits?: string[];
    predecessorContainedFixCommits?: string[];
    firstContainingUnknownFixCommits?: string[];
    directCommitFirstContainingProofs?: DirectCommitFirstContainingResult[];
  } = {},
): ClosureProofResult {
  const evidence = {
    missingClassification: true,
    classificationIssueNumber: row.classification_issue_number ?? null,
    classificationPromptVersion: row.classification_prompt_version ?? null,
    hasReachableFixCommit: fixCommitSummary.hasReachableFixCommit === true,
    hasNotReachableFixCommit: fixCommitSummary.hasNotReachableFixCommit === true,
    hasUnknownFixCommit: fixCommitSummary.hasUnknownFixCommit === true,
    reachableFixCommits: fixCommitSummary.reachableFixCommits ?? [],
    notReachableFixCommits: fixCommitSummary.notReachableFixCommits ?? [],
    unknownFixCommits: fixCommitSummary.unknownFixCommits ?? [],
    targetReachableFixCommits: fixCommitSummary.targetReachableFixCommits ?? [],
    targetNotReachableFixCommits: fixCommitSummary.targetNotReachableFixCommits ?? [],
    targetUnknownFixCommits: fixCommitSummary.targetUnknownFixCommits ?? [],
    predecessorContainedFixCommits: fixCommitSummary.predecessorContainedFixCommits ?? [],
    firstContainingUnknownFixCommits: fixCommitSummary.firstContainingUnknownFixCommits ?? [],
    directCommitFirstContainingProofs: fixCommitSummary.directCommitFirstContainingProofs ?? [],
  };
  if (fixCommitSummary.hasUnknownFixCommit) {
    return {
      status: 'direct_fix_commit_reachability_unknown',
      summary: 'Closed issue lacks current classification evidence, and named fix/source commit reachability is missing or unknown; release-fix credit is withheld until evidence backfill succeeds.',
      evidence,
    };
  }
  return {
    status: 'unknown',
    summary: 'Closed issue lacks current classification evidence; release-fix credit is withheld until classification backfill succeeds.',
    evidence,
  };
}

function rowToClassification(row: any): IssueClassification {
  const workaroundStatus = ['none', 'partial', 'confirmed', 'unknown'].includes(row.workaround_status ?? '')
    ? row.workaround_status as IssueClassification['workaroundStatus']
    : Number(row.has_workaround ?? 0) === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment as IssueClassification['sentiment'],
    severity: row.severity as IssueClassification['severity'],
    scope: row.scope as IssueClassification['scope'],
    functionality: row.functionality as IssueClassification['functionality'],
    affectedUsers: row.affected_users as IssueClassification['affectedUsers'],
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster ?? null,
    affectsVersion: row.affects_version ?? null,
    confidence: typeof row.confidence === 'number' ? row.confidence : 0.5,
    rationale: row.rationale ?? '',
  };
}

function classificationDiff(
  raw: IssueClassification,
  effective: IssueClassification,
): Record<string, { raw: unknown; effective: unknown }> {
  const out: Record<string, { raw: unknown; effective: unknown }> = {};
  for (const key of [
    'sentiment',
    'severity',
    'scope',
    'functionality',
    'affectedUsers',
    'workaroundStatus',
    'confidence',
  ] as const) {
    if (raw[key] !== effective[key]) out[key] = { raw: raw[key], effective: effective[key] };
  }
  return out;
}

const fullCommitOidRe = /^[0-9a-f]{40}$/i;
const fixShapedCommitHeadlineRe = /\b(fix(?:e[sd])?|resolv(?:e[sd])?|repair(?:ed)?|patch(?:ed)?|address(?:ed)?)\b/i;
const concreteNonActionableTerminalRe = /\b(won't fix|wont fix|expected behavior|working as intended|by design|outside\s+(?:the\s+)?OpenClaw\s+source|outside\s+(?:the\s+)?(?:repo|repository)|repo(?:sitory)?\s+boundary|plugin-owned|not\s+present\s+in\s+(?:the\s+)?OpenClaw\s+source|not\s+actionable|out\s+of\s+scope|unsupported)\b/i;

function commitReferenceMentionsByIssue(issueNumbers: number[]): Map<number, ClosureCommentCommitMention[]> {
  const byIssue = new Map<number, ClosureCommentCommitMention[]>();
  if (!issueNumbers.length) return byIssue;
  const repoNameWithOwner = `${config.github.owner}/${config.github.repo}`;
  const rows = issueCommitReferenceRowsStmt.all(JSON.stringify(issueNumbers), repoNameWithOwner) as Array<{
    issue_number: number;
    commit_oid: string;
    commit_message_headline: string | null;
    referenced_at: string | null;
    actor_login: string | null;
    event_id: string;
    closed_at: string | null;
  }>;
  return commitReferenceMentionsFromRows(rows);
}

function commitReferenceMentionsFromRows(rows: Array<{
  issue_number: number;
  commit_oid: string;
  commit_message_headline: string | null;
  referenced_at: string | null;
  actor_login: string | null;
  event_id: string;
  closed_at: string | null;
}>): Map<number, ClosureCommentCommitMention[]> {
  const byIssue = new Map<number, ClosureCommentCommitMention[]>();
  for (const row of rows) {
    const commitOid = String(row.commit_oid ?? '').toLowerCase();
    if (!fullCommitOidRe.test(commitOid)) continue;
    const headline = row.commit_message_headline ?? '';
    if (!fixShapedCommitHeadlineRe.test(headline)) continue;
    const referencedAtMs = row.referenced_at ? Date.parse(row.referenced_at) : NaN;
    const closedAtMs = row.closed_at ? Date.parse(row.closed_at) : NaN;
    if (!Number.isFinite(referencedAtMs) || !Number.isFinite(closedAtMs) || referencedAtMs > closedAtMs + 2000) continue;
    const mention: ClosureCommentCommitMention = {
      issueNumber: row.issue_number,
      commitOid,
      referencedAt: row.referenced_at,
      sourceIssueNumber: row.issue_number,
      snippet: `GitHub ReferencedEvent same-repo commit ${commitOid}: ${headline}`.slice(0, 500),
      source: 'ReferencedEvent.commit',
      author: row.actor_login,
      authorAssociation: null,
      trustedSource: true,
    };
    const list = byIssue.get(row.issue_number) ?? [];
    if (!list.some((item) => item.commitOid === mention.commitOid && item.source === mention.source)) {
      list.push(mention);
      byIssue.set(row.issue_number, list);
    }
  }
  for (const [issueNumber, list] of byIssue) {
    byIssue.set(issueNumber, list.sort((a, b) => a.commitOid.localeCompare(b.commitOid)));
  }
  return byIssue;
}

function directClosureCommitMentions(
  issueNumber: number,
  rawCommitOids: unknown,
  referencedAt: string | null,
): ClosureCommentCommitMention[] {
  return unique(splitCsv(rawCommitOids).map((commitOid) => commitOid.toLowerCase()))
    .filter((commitOid) => fullCommitOidRe.test(commitOid))
    .map((commitOid) => ({
      issueNumber,
      commitOid,
      referencedAt,
      sourceIssueNumber: issueNumber,
      snippet: `GitHub ClosedEvent closer commit ${commitOid}`,
      source: 'ClosedEvent.closer' as const,
      author: null,
      authorAssociation: null,
      trustedSource: true,
    }));
}

function canonicalIssueNumbersFromComments(
  comments: GhComment[],
  sourceIssueNumber: number,
  issueNumberAllowed: (number: number) => boolean = () => true,
): number[] {
  const numbers = new Set<number>();
  for (const comment of comments) {
    for (const number of canonicalIssueNumbersFromText(comment.body ?? '')) {
      if (number !== sourceIssueNumber && issueNumberAllowed(number)) numbers.add(number);
    }
  }
  return [...numbers].sort((a, b) => a - b);
}

type CanonicalClosureContext = {
  closedAt: string | null;
  finalReopenedAt: string | null;
  closureActors: string[];
};

const TRUSTED_CLOSURE_RATIONALE_ASSOCIATIONS = new Set(['OWNER', 'MEMBER', 'COLLABORATOR']);

function normalizeCanonicalLogin(login: string | null | undefined): string {
  return String(login ?? '').trim().toLowerCase();
}

function trustedClosureRationaleComments(
  comments: GhComment[],
  issueAuthor: string | null | undefined,
  closureActors: string[],
): GhComment[] {
  const trustedAuthors = new Set([
    normalizeCanonicalLogin(issueAuthor),
    ...closureActors.map(normalizeCanonicalLogin),
  ].filter(Boolean));
  return comments.filter((comment) => {
    const author = normalizeCanonicalLogin(comment.user?.login);
    const association = String(comment.author_association ?? '').toUpperCase();
    return TRUSTED_CLOSURE_RATIONALE_ASSOCIATIONS.has(association) ||
      (!!author && trustedAuthors.has(author));
  });
}

function trustedCanonicalIssueNumbersFromComments(
  comments: GhComment[],
  sourceIssueNumber: number,
  context: CanonicalClosureContext | undefined,
  issueNumberAllowed: (number: number) => boolean = () => true,
): number[] {
  if (!context?.closedAt) return [];
  const closureActors = new Set(context.closureActors.map(normalizeCanonicalLogin).filter(Boolean));
  const trustedComments = closureRationaleCommentsForFinalClosure(comments, {
    closedAt: context.closedAt,
    finalReopenedAt: context.finalReopenedAt,
    closureActors: context.closureActors,
  }).filter((comment) => {
    const author = normalizeCanonicalLogin(comment.user?.login);
    const association = String(comment.author_association ?? '').toUpperCase();
    return TRUSTED_CLOSURE_RATIONALE_ASSOCIATIONS.has(association) ||
      (!!author && closureActors.has(author));
  });
  return canonicalIssueNumbersFromComments(trustedComments, sourceIssueNumber, issueNumberAllowed);
}

function canonicalClosureContextsForIssues(issueNumbers: number[]): Map<number, CanonicalClosureContext> {
  return selectedFinalClosureContextsForIssues(issueNumbers);
}

function canonicalIssueNumbersFromText(text: string): number[] {
  const numbers = new Set<number>();
  const canonicalReferenceRes = [
    /^\s*(?:\*\*)?(?:canonical|canonical path|root-cause tracker|root cause tracker)(?:\*\*)?\s*:\s*(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)/gim,
    /^\s*(?:\*\*)?(?:canonical|canonical path|root-cause tracker|root cause tracker|root-cause cluster|root cause cluster)(?:\*\*)?\s*:\s*.{0,240}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/|#)(\d+)/gim,
    /\b(?:canonical|root-cause|root cause)\s+(?:issue|tracker|report)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
    /\b(?:canonical path|canonical|root-cause|root cause|root-cause cluster|root cause cluster)\b.{0,240}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/|#)(\d+)/gim,
    /\b(?:close[sd]?|closing)\s+as\s+(?:a\s+)?(?:duplicate|dupe|superseded)\s*:\s*(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
    /\b(?:as\s+(?:a\s+)?)?(?:duplicate|dupe|superseded)\s+(?:of|by)\s+(?:the\s+)?(?:open\s+|closed\s+)?(?:canonical\s+)?(?:(?:issue|tracker|report)\s+)?(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
    /\b(?:tracked|centralized|consolidated)\s+(?:in|under|by)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
    /\bconsolidat(?:e|es|ed|ing)\s+(?:this\s+)?(?:issue\s+|report\s+)?(?:in|into|under)\s+.{0,160}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/|#)(\d+)\b/gim,
    /\bsuperseded\s+by\b.{0,160}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/|#)(\d+)\b/gim,
  ];
  for (const re of canonicalReferenceRes) {
    re.lastIndex = 0;
    for (const match of text.matchAll(re)) {
      if (shouldSkipBarePrCanonicalMatch(text, match)) continue;
      const number = Number(match[1]);
      if (Number.isInteger(number) && number > 0) numbers.add(number);
    }
  }
  for (const number of canonicalIssueNumbersFromSignalLines(text)) numbers.add(number);
  return [...numbers].sort((a, b) => a - b);
}

async function commentsForIssues(
  runContext: ClosureProofRunContext,
  issueNumbers: number[],
  options: {
    allowMetadataDrift?: boolean;
    fetchSnapshots?: typeof listIssueCommentSnapshotsBatch;
  } = {},
): Promise<Map<number, GhComment[]>> {
  const requested = uniqueNumbers(issueNumbers);
  const fetchSnapshots = options.fetchSnapshots ?? listIssueCommentSnapshotsBatch;
  const missing = requested.filter((issueNumber) =>
    !runContext.commentSnapshotsByIssue.has(issueNumber) &&
    !runContext.commentSnapshotRequests.has(issueNumber)
  );
  if (missing.length) {
    throwIfAborted(runContext.signal);
    captureClosureIssueRevisionBaselines(runContext, missing);
    const batch = fetchSnapshots(missing, { signal: runContext.signal }).then((fetched) => {
      const accepted = new Map<number, GhIssueCommentSnapshot>();
      for (const issueNumber of missing) {
        const snapshot = fetched.get(issueNumber);
        if (!snapshot) {
          throw new Error(`GitHub comment snapshot missing requested issue #${issueNumber}`);
        }
        accepted.set(
          issueNumber,
          acceptedClosureCommentSnapshot(issueNumber, snapshot),
        );
      }
      recordCommentSnapshotMetadataDrift(runContext, accepted);
      for (const [issueNumber, snapshot] of accepted) {
        runContext.commentSnapshotsByIssue.set(issueNumber, snapshot);
        runContext.commentsByIssue.set(issueNumber, snapshot.comments);
      }
      return accepted;
    });
    for (const issueNumber of missing) {
      const request = batch.then((fetched) => {
        const snapshot = fetched.get(issueNumber);
        if (!snapshot) {
          throw new Error(`GitHub comment snapshot missing requested issue #${issueNumber}`);
        }
        return snapshot;
      });
      runContext.commentSnapshotRequests.set(issueNumber, request);
      void request.then(
        () => runContext.commentSnapshotRequests.delete(issueNumber),
        () => runContext.commentSnapshotRequests.delete(issueNumber),
      );
    }
  }
  await Promise.all(requested.map(async (issueNumber) => {
    if (runContext.commentSnapshotsByIssue.has(issueNumber)) return;
    const snapshot = await runContext.commentSnapshotRequests.get(issueNumber);
    if (!snapshot) {
      throw new Error(`No accepted comment snapshot available for issue #${issueNumber}`);
    }
    runContext.commentSnapshotsByIssue.set(issueNumber, snapshot);
    runContext.commentsByIssue.set(issueNumber, snapshot.comments);
  }));
  for (const issueNumber of requested) {
    const snapshot = runContext.commentSnapshotsByIssue.get(issueNumber);
    if (!snapshot) {
      throw new Error(`No accepted comment snapshot available for issue #${issueNumber}`);
    }
    runContext.commentsByIssue.set(issueNumber, snapshot.comments);
  }
  const unresolvedDrift = unresolvedCommentSnapshotMetadataDriftIssueNumbers(runContext, requested);
  if (!options.allowMetadataDrift && unresolvedDrift.length) {
    throw new Error(
      `Closure comment snapshot metadata drift for issue(s) ${unresolvedDrift.map((number) => `#${number}`).join(', ')}; ` +
      `reconcile full issue and classification state before closure proof`,
    );
  }
  return new Map(requested.map((issueNumber) => [
    issueNumber,
    runContext.commentSnapshotsByIssue.get(issueNumber)?.comments ?? [],
  ]));
}

async function fixEvidenceForIssues(
  runContext: ClosureProofRunContext,
  issueNumbers: number[],
): Promise<Map<number, GhIssueFixEvidence>> {
  const requested = uniqueNumbers(issueNumbers);
  const missing = requested.filter((issueNumber) =>
    !runContext.fixEvidenceByIssue.has(issueNumber) &&
    !runContext.fixEvidenceRequests.has(issueNumber)
  );
  if (missing.length) {
    throwIfAborted(runContext.signal);
    const batch = listIssueFixEvidenceBatch(missing, {
      signal: runContext.signal,
    }).then((fetched) => {
      for (const issueNumber of missing) {
        const evidence = fetched.get(issueNumber);
        if (evidence) runContext.fixEvidenceByIssue.set(issueNumber, evidence);
      }
      return fetched;
    });
    for (const issueNumber of missing) {
      const request = batch.then((fetched) => fetched.get(issueNumber) ?? null);
      runContext.fixEvidenceRequests.set(issueNumber, request);
      void request.then(
        () => runContext.fixEvidenceRequests.delete(issueNumber),
        () => runContext.fixEvidenceRequests.delete(issueNumber),
      );
    }
  }
  await Promise.all(requested.map(async (issueNumber) => {
    if (runContext.fixEvidenceByIssue.has(issueNumber)) return;
    const evidence = await runContext.fixEvidenceRequests.get(issueNumber);
    if (evidence) runContext.fixEvidenceByIssue.set(issueNumber, evidence);
  }));
  return new Map(requested.flatMap((issueNumber) => {
    const evidence = runContext.fixEvidenceByIssue.get(issueNumber);
    return evidence ? [[issueNumber, evidence] as const] : [];
  }));
}

function persistedIssueStateSnapshotMatchesAcceptedEvidence(
  runContext: ClosureProofRunContext,
  issueNumber: number,
): boolean {
  const validation = validateIssueStateEventSnapshot(issueNumber);
  const persisted = validation.snapshot;
  const issue = getIssue(issueNumber);
  const commentSnapshot = runContext.commentSnapshotsByIssue.get(issueNumber);
  return validation.reusable &&
    !!persisted &&
    !!issue &&
    !!commentSnapshot &&
    persisted.issue_number === issue.number &&
    persisted.issue_node_id === issue.node_id &&
    persisted.issue_node_id === commentSnapshot.issueNodeId &&
    persisted.issue_node_type === 'Issue' &&
    persisted.schema_version === ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION &&
    persisted.issue_state === issue.state &&
    persisted.issue_updated_at === issue.updated_at &&
    persisted.issue_updated_at === commentSnapshot.issueUpdatedAt &&
    persisted.fetched_count === persisted.total_count &&
    persisted.authority_digest != null &&
    persisted.stabilization_json != null &&
    persisted.stabilization_identity_digest != null;
}

export function unresolvedStateSnapshotMetadataDriftIssueNumbers(
  runContext: ClosureProofRunContext,
  candidates?: number[],
): number[] {
  const selected = candidates
    ? uniqueNumbers(candidates).filter((issueNumber) =>
        runContext.stateSnapshotMetadataDriftIssueNumbers.has(issueNumber))
    : [...runContext.stateSnapshotMetadataDriftIssueNumbers];
  return selected.filter((issueNumber) => !issueStateSnapshotMetadataMatches(
    runContext.fixEvidenceByIssue.get(issueNumber),
    getIssue(issueNumber),
    runContext.commentSnapshotsByIssue.get(issueNumber),
  ));
}

async function pullRequestsForLookups(
  runContext: ClosureProofRunContext,
  lookups: PullRequestLookup[],
  options: { allowMissing?: boolean; refreshMissing?: boolean } = {},
  lookupPullRequests: typeof listPullRequestFixesBatch = listPullRequestFixesBatch,
): Promise<Map<string, GhPullRequestFix>> {
  const permissiveMissingPullRequestKeys = runContext.permissiveMissingPullRequestKeys ??= new Set();
  const lookupByKey = new Map<string, PullRequestLookup>();
  for (const lookup of lookups) {
    if (!Number.isInteger(lookup.prNumber) || lookup.prNumber <= 0) continue;
    const key = pullRequestKey(
      lookup.prRepositoryNameWithOwner ??
        (lookup.prRepositoryOwner && lookup.prRepositoryName
          ? `${lookup.prRepositoryOwner}/${lookup.prRepositoryName}`
          : trackedPrRepositoryNameWithOwner),
      lookup.prNumber,
    );
    lookupByKey.set(key, lookup);
  }
  const allowMissing = options.allowMissing !== false;
  const refreshMissing = options.refreshMissing === true;
  const missingKeys = [...lookupByKey.keys()].filter((key) =>
    (
      !runContext.pullRequestsByKey.has(key) ||
      (refreshMissing && runContext.pullRequestsByKey.get(key) === null) ||
      (!allowMissing &&
        runContext.pullRequestsByKey.get(key) === null &&
        permissiveMissingPullRequestKeys.has(key))
    ) &&
    !runContext.pullRequestRequests.has(key)
  );
  if (missingKeys.length) {
    const missingLookups = missingKeys.map((key) => lookupByKey.get(key)!);
    const missingFromGithub = new Set<string>();
    const lookupOptions = {
      signal: runContext.signal,
      ...(!allowMissing
        ? {}
        : {
        onMissingPullRequest: ({ repositoryNameWithOwner, prNumber }: {
          repositoryNameWithOwner: string;
          prNumber: number;
        }) => {
          missingFromGithub.add(pullRequestKey(repositoryNameWithOwner, prNumber));
        },
        }),
    };
    throwIfAborted(runContext.signal);
    const batch = lookupPullRequests(missingLookups, lookupOptions).then((fetched) => {
      for (const key of missingKeys) {
        const pullRequest = fetched.get(key) ?? null;
        if (!pullRequest && !allowMissing) {
          throw new Error(`Strict pull request lookup returned no result for ${key}`);
        }
        runContext.pullRequestsByKey.set(key, pullRequest);
        if (pullRequest) permissiveMissingPullRequestKeys.delete(key);
        else if (allowMissing) permissiveMissingPullRequestKeys.add(key);
      }
      for (const key of missingFromGithub) {
        runContext.pullRequestsByKey.set(key, null);
        permissiveMissingPullRequestKeys.add(key);
      }
      return fetched;
    });
    for (const key of missingKeys) {
      const request = batch.then((fetched) => fetched.get(key) ?? null);
      runContext.pullRequestRequests.set(key, request);
      void request.then(
        () => runContext.pullRequestRequests.delete(key),
        () => runContext.pullRequestRequests.delete(key),
      );
    }
  }
  await Promise.all([...lookupByKey.keys()].map(async (key) => {
    if (runContext.pullRequestsByKey.has(key)) return;
    const pullRequest = await runContext.pullRequestRequests.get(key);
    runContext.pullRequestsByKey.set(key, pullRequest ?? null);
  }));
  if (!allowMissing && [...lookupByKey.keys()].some((key) =>
    runContext.pullRequestsByKey.get(key) === null &&
    permissiveMissingPullRequestKeys.has(key)
  )) {
    return pullRequestsForLookups(runContext, [...lookupByKey.values()], options, lookupPullRequests);
  }
  return new Map([...lookupByKey.keys()].flatMap((key) => {
    const pullRequest = runContext.pullRequestsByKey.get(key);
    return pullRequest ? [[key, pullRequest] as const] : [];
  }));
}

type FinalClosureWindow = {
  closedAt: string;
  finalReopenedAt: string | null;
  closureActors: string[];
};

type ClosureCommentTimestamp = {
  created_at?: string | null;
  createdAt?: string | null;
  updated_at?: string | null;
  updatedAt?: string | null;
};

function assertAggregateFinalClosureAuthority(rows: Array<Record<string, unknown>>): void {
  for (const row of rows) {
    if (Number(row.closure_events ?? 0) === 0) continue;
    assertIssueClosedAtMatchesSelectedFinalEvent(
      Number(row.number),
      String(row.closed_at ?? ''),
      String(row.closure_event_closed_at ?? ''),
    );
  }
}

function selectedFinalClosureContextsForIssues(
  issueNumbers: number[],
): Map<number, CanonicalClosureContext> {
  if (!issueNumbers.length) return new Map();
  const rows = issueFinalClosureContextRowsStmt.all(
    JSON.stringify(uniqueNumbers(issueNumbers)),
  ) as unknown as Array<{
    number: number;
    issue_closed_at: string | null;
    final_closed_at: string | null;
    final_connection_ordinal: number | null;
    final_actor_login: string | null;
    final_reopened_at: string | null;
  }>;
  return new Map(rows.flatMap((row) => {
    if (!row.issue_closed_at) return [];
    if (row.final_closed_at) {
      assertIssueClosedAtMatchesSelectedFinalEvent(
        row.number,
        row.issue_closed_at,
        row.final_closed_at,
      );
    }
    return [[row.number, {
      closedAt: row.final_closed_at ?? row.issue_closed_at,
      finalReopenedAt: row.final_reopened_at ?? null,
      closureActors: row.final_actor_login ? [row.final_actor_login] : [],
    }] as const];
  }));
}

function assertIssueClosedAtMatchesSelectedFinalEvent(
  issueNumber: number,
  issueClosedAt: string,
  finalEventClosedAt: string,
): void {
  const issueClosedAtMs = Date.parse(issueClosedAt);
  const finalEventClosedAtMs = Date.parse(finalEventClosedAt);
  if (
    !Number.isFinite(issueClosedAtMs) ||
    !Number.isFinite(finalEventClosedAtMs) ||
    Math.abs(issueClosedAtMs - finalEventClosedAtMs) > FINAL_CLOSURE_TIMESTAMP_TOLERANCE_MS
  ) {
    throw new Error(
      `Issue #${issueNumber} closed_at ${JSON.stringify(issueClosedAt)} does not match ` +
      `selected final closure event ${JSON.stringify(finalEventClosedAt)}`,
    );
  }
}

function finalClosureWindowsForIssues(issueNumbers: number[]): Map<number, FinalClosureWindow> {
  return new Map(
    [...selectedFinalClosureContextsForIssues(issueNumbers)]
      .flatMap(([issueNumber, context]) => context.closedAt
        ? [[issueNumber, {
          closedAt: context.closedAt,
          finalReopenedAt: context.finalReopenedAt,
          closureActors: context.closureActors,
        }] as const]
        : []),
  );
}

function latestReopenBeforeFinalClosure(
  reopenedAtValues: Array<string | null | undefined>,
  closedAt: string,
): string | null {
  const closedMs = Date.parse(closedAt);
  if (!Number.isFinite(closedMs)) return null;
  return reopenedAtValues
    .filter((value): value is string => !!value)
    .filter((value) => {
      const reopenedMs = Date.parse(value);
      return Number.isFinite(reopenedMs) && reopenedMs <= closedMs;
    })
    .sort((left, right) => Date.parse(right) - Date.parse(left))[0] ?? null;
}

function closureCommentIsInFinalClosureWindow(
  comment: ClosureCommentTimestamp,
  window: FinalClosureWindow,
): boolean {
  const closedMs = Date.parse(window.closedAt);
  const createdAt = comment.createdAt ?? comment.created_at ?? null;
  const updatedAt = comment.updatedAt ?? comment.updated_at ?? null;
  const createdMs = createdAt ? Date.parse(createdAt) : Number.NaN;
  const updatedMs = updatedAt ? Date.parse(updatedAt) : Number.NaN;
  if (!Number.isFinite(closedMs) || !Number.isFinite(createdMs)) return false;
  if (Number.isFinite(updatedMs) && updatedMs > closedMs) return false;
  const effectiveMs = Number.isFinite(updatedMs) && updatedMs > createdMs
    ? updatedMs
    : createdMs;
  const reopenedMs = window.finalReopenedAt ? Date.parse(window.finalReopenedAt) : Number.NaN;
  return effectiveMs >= closedMs - FINAL_CLOSURE_COMMENT_LOOKBACK_MS &&
    effectiveMs < closedMs &&
    (!Number.isFinite(reopenedMs) || effectiveMs > reopenedMs);
}

function invalidateExpiredUnknownDirectCommitProofs(
  releaseTag: string,
  nowMs = Date.now(),
): number {
  if (!Number.isFinite(nowMs)) {
    throw new Error(`Unknown reachability retry clock must be finite, got ${nowMs}`);
  }
  const cutoff = new Date(nowMs - UNKNOWN_REACHABILITY_RETRY_MS).toISOString();
  return Number(deleteExpiredUnknownDirectCommitProofsStmt.run(releaseTag, cutoff).changes ?? 0);
}

function closureRationaleCommentsForFinalClosure<T extends ClosureCommentTimestamp>(
  comments: T[],
  window: FinalClosureWindow | undefined,
): T[] {
  if (!window) return [];
  return closureRationaleComments(
    comments.filter((comment) => closureCommentIsInFinalClosureWindow(comment, window)),
    window.closedAt,
  );
}

function closureCommentPrMentionsForFinalClosure(
  issueNumber: number,
  comments: GhComment[],
  window: FinalClosureWindow | undefined,
) {
  if (!window) return [];
  return closureCommentPrMentions(
    issueNumber,
    comments.filter((comment) => closureCommentIsInFinalClosureWindow(comment, window)),
    { finalClosureActors: window.closureActors },
  );
}

function validateClosureCommentSnapshot(expectedCount: number, comments: GhComment[]): {
  complete: boolean;
  expectedCount: number;
  fetchedCount: number;
  invalidIdIndexes: number[];
  duplicateIds: number[];
} {
  const invalidIdIndexes: number[] = [];
  const idCounts = new Map<number, number>();
  comments.forEach((comment, index) => {
    const id = comment.id;
    if (!Number.isInteger(id) || id <= 0) {
      invalidIdIndexes.push(index);
      return;
    }
    idCounts.set(id, (idCounts.get(id) ?? 0) + 1);
  });
  const duplicateIds = [...idCounts.entries()]
    .filter(([, count]) => count > 1)
    .map(([id]) => id)
    .sort((left, right) => left - right);
  return {
    complete:
      Number.isInteger(expectedCount) &&
      expectedCount >= 0 &&
      comments.length === expectedCount &&
      invalidIdIndexes.length === 0 &&
      duplicateIds.length === 0,
    expectedCount,
    fetchedCount: comments.length,
    invalidIdIndexes,
    duplicateIds,
  };
}

function assertCompleteClosureCommentSnapshot(
  issueNumber: number,
  expectedCount: number,
  comments: GhComment[],
): void {
  const validation = validateClosureCommentSnapshot(expectedCount, comments);
  if (validation.complete) return;
  throw new Error(
    `Refusing incomplete closure comment snapshot for issue #${issueNumber}: ` +
    `expected ${validation.expectedCount} from the remote snapshot, fetched ${validation.fetchedCount}, ` +
    `invalid ID indexes ${validation.invalidIdIndexes.join(',') || 'none'}, ` +
    `duplicate IDs ${validation.duplicateIds.join(',') || 'none'}`,
  );
}

function acceptedClosureCommentSnapshot(
  requestedIssueNumber: number,
  snapshot: GhIssueCommentSnapshot,
): GhIssueCommentSnapshot {
  if (snapshot.issueNumber !== requestedIssueNumber) {
    throw new Error(
      `GitHub comment snapshot key #${requestedIssueNumber} returned issue #${snapshot.issueNumber}`,
    );
  }
  if (!snapshot.issueUpdatedAt || !Number.isFinite(Date.parse(snapshot.issueUpdatedAt))) {
    throw new Error(`GitHub comment snapshot for issue #${requestedIssueNumber} has invalid issueUpdatedAt`);
  }
  const canonical = {
    ...snapshot,
    comments: [...snapshot.comments].sort(compareClosureCommentOrder),
  };
  assertCompleteClosureCommentSnapshot(
    requestedIssueNumber,
    canonical.totalCount,
    canonical.comments,
  );
  const computedDigest = commentEvidenceDigest(canonical.totalCount, canonical.comments);
  if (computedDigest !== canonical.commentsDigest) {
    throw new Error(
      `GitHub comment snapshot digest mismatch for issue #${requestedIssueNumber}: ` +
      `expected ${canonical.commentsDigest}, computed ${computedDigest}`,
    );
  }
  if (!canonical.issueAuthor) {
    throw new Error(
      `GitHub comment snapshot for issue #${requestedIssueNumber} is missing issue author identity`,
    );
  }
  const computedAuthorityDigest = commentEvidenceDigest(
    canonical.totalCount,
    canonical.comments,
    {
      repositoryNodeId: canonical.repositoryNodeId,
      issueNodeId: canonical.issueNodeId,
      issueNodeType: canonical.issueNodeType,
      issueAuthor: canonical.issueAuthor,
    },
  );
  if (computedAuthorityDigest !== canonical.authorityDigest) {
    throw new Error(
      `GitHub comment snapshot authority digest mismatch for issue #${requestedIssueNumber}: ` +
      `expected ${canonical.authorityDigest}, computed ${computedAuthorityDigest}`,
    );
  }
  return canonical;
}

function compareClosureCommentOrder(left: GhComment, right: GhComment): number {
  const created = compareNullableCommentOrderField(left.created_at, right.created_at);
  if (created !== 0) return created;
  const updated = compareNullableCommentOrderField(left.updated_at, right.updated_at);
  if (updated !== 0) return updated;
  return left.id - right.id;
}

function compareNullableCommentOrderField(
  left: string | null | undefined,
  right: string | null | undefined,
): number {
  if (left === right) return 0;
  if (left == null) return -1;
  if (right == null) return 1;
  return left.localeCompare(right);
}

type IssueCommentMetadata = {
  number: number;
  updated_at: string;
  comments: number;
  snapshot_schema_version: number | null;
  snapshot_issue_updated_at: string | null;
  snapshot_comment_count: number | null;
  snapshot_fetched_comment_count: number | null;
  snapshot_comments_digest: string | null;
  snapshot_repository_node_id: string | null;
  snapshot_issue_node_id: string | null;
  snapshot_issue_author_node_id: string | null;
  snapshot_issue_author_login: string | null;
  snapshot_issue_author_type: string | null;
  snapshot_authority_digest: string | null;
  snapshot_stabilization_identity_digest: string | null;
  classified_updated_at: string | null;
  classified_comments_digest: string | null;
  classification_source_identity_digest: string | null;
};

function issueCommentMetadata(issueNumbers: number[]): Map<number, IssueCommentMetadata> {
  if (!issueNumbers.length) return new Map();
  return new Map(
    (issueCommentMetadataRowsStmt.all(JSON.stringify(uniqueNumbers(issueNumbers))) as unknown as IssueCommentMetadata[])
      .map((row) => [row.number, row]),
  );
}

function snapshotTokenDiffersFromIssueMetadata(
  snapshot: GhIssueCommentSnapshot,
  issue: IssueCommentMetadata | undefined,
): boolean {
  return !issue ||
    issue.updated_at !== snapshot.issueUpdatedAt ||
    issue.comments !== snapshot.totalCount ||
    issue.snapshot_schema_version !== AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION ||
    issue.snapshot_issue_updated_at !== snapshot.issueUpdatedAt ||
    issue.snapshot_comment_count !== snapshot.totalCount ||
    issue.snapshot_fetched_comment_count !== snapshot.comments.length ||
    issue.snapshot_comments_digest !== snapshot.commentsDigest ||
    issue.snapshot_repository_node_id !== snapshot.repositoryNodeId ||
    issue.snapshot_issue_node_id !== snapshot.issueNodeId ||
    issue.snapshot_issue_author_node_id !== snapshot.issueAuthor?.nodeId ||
    issue.snapshot_issue_author_login !== snapshot.issueAuthor?.login ||
    issue.snapshot_issue_author_type !== snapshot.issueAuthor?.actorType ||
    issue.snapshot_authority_digest !== snapshot.authorityDigest ||
    issue.snapshot_stabilization_identity_digest !== snapshot.stabilization.identityDigest ||
    issue.classified_updated_at !== snapshot.issueUpdatedAt ||
    issue.classified_comments_digest !== snapshot.commentsDigest ||
    !issue.classification_source_identity_digest;
}

function recordCommentSnapshotMetadataDrift(
  runContext: ClosureProofRunContext,
  snapshotsByIssue: Map<number, GhIssueCommentSnapshot>,
): void {
  const metadata = issueCommentMetadata([...snapshotsByIssue.keys()]);
  for (const [issueNumber, snapshot] of snapshotsByIssue) {
    if (snapshotTokenDiffersFromIssueMetadata(snapshot, metadata.get(issueNumber))) {
      runContext.commentSnapshotMetadataDriftIssueNumbers.add(issueNumber);
    }
  }
}

export function unresolvedCommentSnapshotMetadataDriftIssueNumbers(
  runContext: ClosureProofRunContext,
  issueNumbers: number[],
): number[] {
  const requested = uniqueNumbers(issueNumbers);
  const metadata = issueCommentMetadata(requested);
  const drifted = requested.filter((issueNumber) => {
    const snapshot = runContext.commentSnapshotsByIssue.get(issueNumber);
    return !!snapshot && snapshotTokenDiffersFromIssueMetadata(snapshot, metadata.get(issueNumber));
  });
  for (const issueNumber of drifted) {
    runContext.commentSnapshotMetadataDriftIssueNumbers.add(issueNumber);
  }
  return drifted;
}

export function closureProofCommentSnapshotDriftIssueNumbers(
  runContext: ClosureProofRunContext,
  issueNumbers?: number[],
): number[] {
  const requested = issueNumbers ? new Set(uniqueNumbers(issueNumbers)) : null;
  return uniqueNumbers([...runContext.commentSnapshotMetadataDriftIssueNumbers])
    .filter((issueNumber) => !requested || requested.has(issueNumber));
}

function captureClosureIssueRevisionBaselines(
  runContext: ClosureProofRunContext,
  issueNumbers: number[],
): void {
  const missing = uniqueNumbers(issueNumbers).filter(
    (issueNumber) => !runContext.issueEvidenceRevisionsByIssue.has(issueNumber),
  );
  for (const [issueNumber, revision] of issueEvidenceRevisions(missing)) {
    runContext.issueEvidenceRevisionsByIssue.set(issueNumber, revision);
  }
}

function assertClosureIssueRevisions(
  runContext: ClosureProofRunContext,
  issueNumbers: number[],
): void {
  captureClosureIssueRevisionBaselines(runContext, issueNumbers);
  const expected = new Map(uniqueNumbers(issueNumbers).map((issueNumber) => {
    const revision = runContext.issueEvidenceRevisionsByIssue.get(issueNumber);
    if (!revision) throw new Error(`Missing closure evidence revision baseline for issue #${issueNumber}`);
    return [issueNumber, revision] as const;
  }));
  assertIssueEvidenceRevisions(expected);
}

function canonicalIssueNumbersFromSignalLines(text: string): number[] {
  const numbers = new Set<number>();
  const signalRe = /\b(?:canonical path|covered by|broader\s+(?:reports?|issues?|trackers?)|especially)\b/i;
  for (const line of text.split(/\n+/)) {
    if (!signalRe.test(line)) continue;
    const prContext = /\b(?:PR|pull request)\b|\/pull\//i.test(line);
    for (const match of line.matchAll(/https?:\/\/github\.com\/openclaw\/openclaw\/issues\/(\d+)\b|#(\d+)\b/gim)) {
      if (prContext && !match[1] && !isBareIssueReference(line, match)) continue;
      const number = Number(match[1] ?? match[2]);
      if (Number.isInteger(number) && number > 0) numbers.add(number);
    }
  }
  return [...numbers].sort((a, b) => a - b);
}

function shouldSkipBarePrCanonicalMatch(text: string, match: RegExpMatchArray): boolean {
  const matchedText = match[0] ?? '';
  if (/\/issues\//i.test(matchedText)) return false;
  const index = typeof match.index === 'number' ? match.index : -1;
  const lineStart = index >= 0 ? text.lastIndexOf('\n', index) + 1 : 0;
  const lineEnd = index >= 0 ? text.indexOf('\n', index) : -1;
  const line = text.slice(lineStart, lineEnd >= 0 ? lineEnd : undefined);
  return /\b(?:PR|pull request)\b|\/pull\//i.test(line) && !isBareIssueReference(line, match);
}

function isBareIssueReference(line: string, match: RegExpMatchArray): boolean {
  if (typeof match.index !== 'number') return false;
  return /\b(?:issue|tracker|report)\s*$/i.test(line.slice(Math.max(0, match.index - 24), match.index));
}

async function expandCanonicalGraph(
  canonicalGraph: Map<number, number[]>,
  commentsByIssue: Map<number, GhComment[]>,
  seedIssueNumbers: number[],
  fetchComments: (issueNumbers: number[]) => Promise<Map<number, GhComment[]>>,
  _persistFetchedCommentSnapshots = false,
  closureContextLookup: (issueNumbers: number[]) => Map<number, CanonicalClosureContext> = canonicalClosureContextsForIssues,
  issueNumberAllowed: (number: number) => boolean = knownIssueNumber,
): Promise<void> {
  const parsed = new Set(canonicalGraph.keys());
  let frontier = uniqueNumbers(seedIssueNumbers.filter((number) => Number.isInteger(number)));
  for (let depth = 0; depth < 8 && frontier.length; depth++) {
    const missing = frontier.filter((number) => !commentsByIssue.has(number));
    if (missing.length) {
      const fetched = await fetchComments(missing);
      for (const number of missing) commentsByIssue.set(number, fetched.get(number) ?? []);
    }
    const closureContexts = closureContextLookup(frontier);
    const nextFrontier: number[] = [];
    for (const issueNumber of frontier) {
      if (parsed.has(issueNumber)) continue;
      parsed.add(issueNumber);
      const targets = trustedCanonicalIssueNumbersFromComments(
        commentsByIssue.get(issueNumber) ?? [],
        issueNumber,
        closureContexts.get(issueNumber),
        issueNumberAllowed,
      );
      canonicalGraph.set(issueNumber, targets);
      for (const target of targets) {
        if (!parsed.has(target)) nextFrontier.push(target);
      }
    }
    frontier = uniqueNumbers(nextFrontier);
  }
}

function canonicalIssueNumbersReachableFrom(sourceIssueNumber: number, graph: Map<number, number[]>): number[] {
  const resolution = canonicalResolution(sourceIssueNumber, graph);
  return uniqueNumbers(resolution.branches.flatMap((branch) =>
    branch.path.slice(1).filter((number) => number !== sourceIssueNumber)));
}

function terminalCanonicalIssuesNeedingEvidence(
  releaseTag: string,
  sourceIssueNumbers: number[],
  canonicalGraph: Map<number, number[]>,
  issueDetailsLookup = issueDetails,
  _terminalProofLookup = crossReleaseTerminalProofForIssue,
): number[] {
  const sourceSet = new Set(sourceIssueNumbers);
  const terminals = new Set<number>();
  for (const issueNumber of sourceIssueNumbers) {
    const resolution = canonicalResolution(issueNumber, canonicalGraph, issueDetailsLookup);
    for (const terminalIssue of resolution.terminalIssues) {
      const terminalNumber = terminalIssue.number;
      if (sourceSet.has(terminalNumber) || terminalIssue.state !== 'closed') continue;
      // Prior audits are fallback context only. Every closed terminal must be
      // re-evaluated against the current tag's reachability.
      terminals.add(terminalNumber);
    }
  }
  return [...terminals].sort((a, b) => a - b);
}

function adjustCanonicalDuplicateStatus(
  sourceIssueNumber: number,
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
  canonicalGraph: Map<number, number[]>,
  resultByIssue: Map<number, ClosureProofResult> = new Map(),
  sourceReleaseTag: string | null = null,
  terminalProofLookup = crossReleaseTerminalProofForIssue,
  issueDetailsLookup: (number: number) => CanonicalIssueDetails | null = issueDetails,
): ClosureProofResult {
  const nonBugDuplicate = result.status === 'non_bug_duplicate_or_superseded';
  if (result.status !== 'duplicate_or_superseded' && !nonBugDuplicate) return { ...result, evidence };
  const resolution = canonicalResolution(sourceIssueNumber, canonicalGraph, issueDetailsLookup);
  const canonicalFixCommitProof = Array.isArray(evidence.canonicalFixCommitProof)
    ? evidence.canonicalFixCommitProof
    : [];
  const creditableCanonicalFixCommitProof =
    creditableDirectCommitProof(canonicalFixCommitProof);
  const relevantBranches = resolution.branches.filter((branch) => branch.path.length > 1);
  const branchContexts = relevantBranches.map((branch) => {
    const terminalIssueNumber = branch.terminalIssue?.number ?? null;
    const currentWindowTerminalProof = terminalIssueNumber == null
      ? null
      : resultByIssue.get(terminalIssueNumber) ?? null;
    const crossReleaseTerminalProof = (!currentWindowTerminalProof ||
      currentWindowTerminalProof.status === 'no_timeline_event' ||
      currentWindowTerminalProof.status === 'unknown') &&
      sourceReleaseTag &&
      terminalIssueNumber != null
      ? terminalProofLookup(sourceReleaseTag, terminalIssueNumber)
      : null;
    const terminalProof = currentWindowTerminalProof ?? crossReleaseTerminalProof;
    const branchFixCommitProof = creditableCanonicalFixCommitProof.filter((item: any) => {
      const proofSourceIssueNumber = Number(item?.sourceIssueNumber);
      return (Number.isInteger(proofSourceIssueNumber) && branch.path.includes(proofSourceIssueNumber)) ||
        (!Number.isInteger(proofSourceIssueNumber) && relevantBranches.length === 1);
    });
    const terminalFixCommitProof = terminalIssueNumber == null
      ? []
      : branchFixCommitProof.filter((item: any) =>
        Number(item?.sourceIssueNumber) === terminalIssueNumber);
    const hasReachableCanonicalFixCommit = branchFixCommitProof.some((item: any) => item?.status === 'reachable');
    const hasNotReachableCanonicalFixCommit = branchFixCommitProof.some((item: any) => item?.status === 'not_reachable');
    const hasReachableTerminalFixCommit = terminalFixCommitProof.some((item: any) => item?.status === 'reachable');
    const terminalIsOpen = branch.terminalIssue?.state === 'open';
    const fixedInRelease = currentWindowTerminalProof?.status === 'fixed_in_release' ||
      (terminalIsOpen ? hasReachableTerminalFixCommit : hasReachableCanonicalFixCommit);
    const fixedAfterRelease = !terminalIsOpen && (
      currentWindowTerminalProof?.status === 'fixed_after_release' ||
      hasNotReachableCanonicalFixCommit ||
      (crossReleaseTerminalProof?.timing === 'after' && isTerminalFixProof(crossReleaseTerminalProof.status))
    );
    return {
      ...branch,
      currentWindowTerminalProof,
      crossReleaseTerminalProof,
      terminalProof,
      branchFixCommitProof,
      terminalFixCommitProof,
      hasReachableCanonicalFixCommit,
      hasNotReachableCanonicalFixCommit,
      hasReachableTerminalFixCommit,
      fixedInRelease,
      fixedAfterRelease,
      openIssue: openIssueInCanonicalBranch(sourceIssueNumber, branch, issueDetailsLookup),
    };
  });
  const primaryBranch = branchContexts[0] ?? null;
  const terminalProof = primaryBranch?.terminalProof ?? null;
  const allBranchesFixedInRelease = branchContexts.length > 0 &&
    branchContexts.every((branch) => branch.fixedInRelease);
  const allBranchesFixed = branchContexts.length > 0 &&
    branchContexts.every((branch) => branch.fixedInRelease || branch.fixedAfterRelease);
  const allBranchesResolvedForDirectProof = branchContexts.length > 0 &&
    branchContexts.every((branch) => {
      if (branch.fixedInRelease || branch.fixedAfterRelease) return true;
      if (!branch.terminalProof) return false;
      return closureRiskDisposition(branch.terminalProof.status) === 'neutral_or_non_actionable' &&
        terminalProofCanResolveAsNonActionable(branch.terminalProof);
    });
  const nextEvidence = {
    ...evidence,
    canonicalResolution: {
      ...resolution,
      ...(terminalProof ? { terminalProof: terminalProofEvidence(terminalProof) } : {}),
      branches: branchContexts.map((branch) => ({
        path: branch.path,
        terminalIssue: branch.terminalIssue,
        cycle: branch.cycle,
        selfReference: branch.selfReference,
        truncated: branch.truncated,
        fixedInRelease: branch.fixedInRelease,
        currentTagContainsFix: branch.fixedInRelease,
        fixedAfterRelease: branch.fixedAfterRelease,
        ...(branch.terminalProof ? { terminalProof: terminalProofEvidence(branch.terminalProof) } : {}),
      })),
      currentTagContainsAllCanonicalFixes: allBranchesFixedInRelease,
    },
  };
  if (allBranchesFixedInRelease) {
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_to_fixed_in_release' : 'duplicate_to_fixed_in_release',
      summary: `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; every canonical branch has fix proof reachable from this release tag, containing the duplicate risk without direct fix credit for this duplicate.`,
      evidence: nextEvidence,
    };
  }
  if (allBranchesFixed) {
    const fixedAfterBranch = branchContexts
      .filter((branch) => branch.fixedAfterRelease)
      .sort((left, right) => compareCanonicalPaths(left.path, right.path))[0] ?? null;
    const canonicalResolution = fixedAfterBranch
      ? canonicalResolutionForSelectedBranch(
        nextEvidence.canonicalResolution as Record<string, unknown>,
        fixedAfterBranch,
      )
      : nextEvidence.canonicalResolution;
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_to_fixed_after_release' : 'duplicate_to_fixed_after_release',
      summary: `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; every canonical branch has fix proof, but at least one branch is not fixed in this release tag.`,
      evidence: { ...nextEvidence, canonicalResolution },
    };
  }
  const blockingOpenBranch = branchContexts.find((branch) =>
    !!branch.openIssue && !branch.fixedInRelease && !branch.fixedAfterRelease);
  if (blockingOpenBranch?.openIssue) {
    const canonicalResolution = canonicalResolutionForSelectedBranch(
      nextEvidence.canonicalResolution as Record<string, unknown>,
      blockingOpenBranch,
      {
        terminalIssue: blockingOpenBranch.openIssue,
        terminalProof: null,
        cycleTerminalIssue: blockingOpenBranch.cycle
          ? blockingOpenBranch.openIssue
          : null,
      },
    );
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_to_open_canonical' : 'duplicate_to_open_canonical',
      summary: `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; at least one canonical branch remains open.`,
      evidence: { ...nextEvidence, canonicalResolution },
    };
  }
  const reachableTrustedFixProofPrs = trustedReachableFixProofPrs(nextEvidence);
  if (!nonBugDuplicate && reachableTrustedFixProofPrs.length > 0 && branchContexts.length <= 1) {
    return {
      status: 'duplicate_with_release_fix_proof',
      summary: 'Closed as duplicate/superseded, but trusted closure-comment fix proof is reachable from this release tag; this resolves closure risk without direct GitHub fix-credit.',
      evidence: { ...nextEvidence, reachableTrustedFixProofPrs },
    };
  }
  const unresolvedCycleBranch = branchContexts.find((branch) =>
    (branch.cycle || branch.selfReference || branch.truncated) &&
    !branch.fixedInRelease &&
    !branch.fixedAfterRelease);
  if (unresolvedCycleBranch) {
    return {
      status: 'canonical_cycle_or_self_reference',
      summary: 'Closed as duplicate/superseded, but at least one canonical branch cycles, self-references, or exceeds the resolution depth.',
      evidence: {
        ...nextEvidence,
        canonicalResolution: canonicalResolutionForSelectedBranch(
          nextEvidence.canonicalResolution as Record<string, unknown>,
          unresolvedCycleBranch,
          {
            cycleTerminalIssue: unresolvedCycleBranch.cycle
              ? unresolvedCycleBranch.terminalIssue
              : null,
          },
        ),
      },
    };
  }
  const missingProofBranch = branchContexts.find((branch) =>
    branch.terminalIssue?.state === 'closed' &&
    !branch.fixedInRelease &&
    !branch.fixedAfterRelease &&
    (!branch.terminalProof ||
      branch.terminalProof.status === 'no_timeline_event' ||
      branch.terminalProof.status === 'unknown'));
  if (missingProofBranch?.terminalIssue) {
    const canonicalResolution = canonicalResolutionForSelectedBranch(
      nextEvidence.canonicalResolution as Record<string, unknown>,
      missingProofBranch,
    );
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_to_closed_canonical_missing_proof' : 'duplicate_to_closed_canonical_missing_proof',
      summary: `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; at least one closed canonical branch lacks complete closure proof.`,
      evidence: { ...nextEvidence, canonicalResolution },
    };
  }
  if (!nonBugDuplicate && reachableTrustedFixProofPrs.length > 0 && allBranchesResolvedForDirectProof) {
    return {
      status: 'duplicate_with_release_fix_proof',
      summary: 'Closed as duplicate/superseded, but trusted closure-comment fix proof is reachable from this release tag; this resolves closure risk without direct GitHub fix-credit.',
      evidence: { ...nextEvidence, reachableTrustedFixProofPrs },
    };
  }
  const prContext = openPrContext(evidence);
  if (prContext.canonical.length) {
    return {
      status: nonBugDuplicate ? 'non_bug_superseded_to_open_pr' : 'superseded_to_open_pr',
      summary: `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; trusted close-time context points to an open, unmerged PR.`,
      evidence: { ...nextEvidence, canonicalOpenPrs: prContext.canonical },
    };
  }
  if (prContext.related.length) {
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_with_open_pr_context' : 'duplicate_with_open_pr_context',
      summary: `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; related open PR references exist, but no trusted close-time note marks them as canonical.`,
      evidence: { ...nextEvidence, relatedOpenPrs: prContext.related },
    };
  }
  const relatedContext = relatedPrContextFromPayload(evidence);
  const relatedPrStatus = duplicateRelatedPrContextStatus(nonBugDuplicate, relatedContext, nextEvidence);
  if (relatedPrStatus) return relatedPrStatus;
  const conservativeTerminalBranch = worstCredibleCanonicalTerminalBranch(
    branchContexts.filter((branch) =>
      branch.terminalIssue?.state === 'closed' &&
      branch.terminalProof &&
      !branch.fixedInRelease &&
      !branch.fixedAfterRelease),
  );
  if (conservativeTerminalBranch?.terminalProof) {
    return closedCanonicalRollup(nonBugDuplicate, conservativeTerminalBranch.terminalProof, {
      ...nextEvidence,
      canonicalResolution: canonicalResolutionForSelectedBranch(
        nextEvidence.canonicalResolution as Record<string, unknown>,
        conservativeTerminalBranch,
      ),
    });
  }
  return { ...result, evidence: nextEvidence };
}

function canonicalResolutionForSelectedBranch(
  resolution: Record<string, unknown>,
  branch: CanonicalBranchResolution & {
    terminalProof?: TerminalProofForCanonical | null;
  },
  options: {
    terminalIssue?: CanonicalIssueDetails | null;
    terminalProof?: TerminalProofForCanonical | null;
    cycleTerminalIssue?: CanonicalIssueDetails | null;
  } = {},
): Record<string, unknown> {
  const {
    path: _stalePath,
    terminalIssue: _staleTerminalIssue,
    terminalProof: _staleTerminalProof,
    blockingBranch: _staleBlockingBranch,
    cycleTerminalIssue: _staleCycleTerminalIssue,
    ...sharedResolution
  } = resolution;
  const terminalIssue = options.terminalIssue === undefined
    ? branch.terminalIssue
    : options.terminalIssue;
  const terminalProof = options.terminalProof === undefined
    ? branch.terminalProof ?? null
    : options.terminalProof;
  return {
    ...sharedResolution,
    path: [...branch.path],
    terminalIssue,
    blockingBranch: [...branch.path],
    ...(terminalProof ? { terminalProof: terminalProofEvidence(terminalProof) } : {}),
    ...(options.cycleTerminalIssue
      ? { cycleTerminalIssue: options.cycleTerminalIssue }
      : {}),
  };
}

function worstCredibleCanonicalTerminalBranch<
  T extends CanonicalBranchResolution & {
    terminalProof: TerminalProofForCanonical | null;
  },
>(branches: T[]): T | null {
  return branches
    .slice()
    .sort(compareCanonicalTerminalBranchRisk)[0] ?? null;
}

function compareCanonicalTerminalBranchRisk(
  left: CanonicalBranchResolution & {
    terminalProof: TerminalProofForCanonical | null;
  },
  right: CanonicalBranchResolution & {
    terminalProof: TerminalProofForCanonical | null;
  },
): number {
  const priorityDelta = canonicalTerminalProofRiskPriority(right.terminalProof) -
    canonicalTerminalProofRiskPriority(left.terminalProof);
  if (priorityDelta !== 0) return priorityDelta;
  const statusDelta = String(left.terminalProof?.status ?? '')
    .localeCompare(String(right.terminalProof?.status ?? ''));
  if (statusDelta !== 0) return statusDelta;
  return compareCanonicalPaths(left.path, right.path);
}

function canonicalTerminalProofRiskPriority(
  proof: TerminalProofForCanonical | null,
): number {
  if (!proof) return -1;
  const disposition = closureRiskDisposition(proof.status);
  if (disposition === 'open_canonical_risk') return 5;
  if (disposition === 'known_not_in_release') return 4;
  if (disposition === 'missing_evidence') return 3;
  if (disposition === 'unsupported_closure_claim') return 2;
  if (disposition === 'neutral_or_non_actionable') {
    return terminalProofCanResolveAsNonActionable(proof) ? 0 : 2;
  }
  return 1;
}

function compareCanonicalPaths(left: readonly number[], right: readonly number[]): number {
  const sharedLength = Math.min(left.length, right.length);
  for (let index = 0; index < sharedLength; index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

function duplicateRelatedPrContextStatus(
  nonBugDuplicate: boolean,
  context: RelatedPrContext,
  evidence: Record<string, unknown>,
): ClosureProofResult | null {
  const prefix = nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded';
  if (context.reachable.length > 0) {
    return {
      status: nonBugDuplicate
        ? 'non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit'
        : 'duplicate_related_merged_pr_reachable_context_without_fix_credit',
      summary: `${prefix}; related PR work is reachable from this release tag, but no trusted closing or fix proof is credited for this issue.`,
      evidence,
    };
  }
  if (context.notReachable.length > 0) {
    return {
      status: nonBugDuplicate
        ? 'non_bug_duplicate_related_merged_pr_not_reachable_context'
        : 'duplicate_related_merged_pr_not_reachable_context',
      summary: `${prefix}; related merged PR work exists, but it is not reachable from this release tag.`,
      evidence,
    };
  }
  if (context.unknownReachability.length > 0) {
    return {
      status: nonBugDuplicate
        ? 'non_bug_duplicate_related_merged_pr_reachability_unknown'
        : 'duplicate_related_merged_pr_reachability_unknown',
      summary: `${prefix}; related merged PR work exists, but release-tag reachability has not been proven.`,
      evidence,
    };
  }
  if (context.closedUnmerged.length > 0) {
    return {
      status: nonBugDuplicate
        ? 'non_bug_duplicate_related_closed_unmerged_pr_context'
        : 'duplicate_related_closed_unmerged_pr_context',
      summary: `${prefix}; related PR context exists, but the referenced PRs closed without merging.`,
      evidence,
    };
  }
  const hasRelatedPrs = context.externalClosing.length > 0 ||
    context.open.length > 0 ||
    context.closedUnmerged.length > 0 ||
    context.notReachable.length > 0 ||
    context.reachable.length > 0 ||
    context.unknownReachability.length > 0;
  return hasRelatedPrs
    ? {
      status: nonBugDuplicate
        ? 'non_bug_duplicate_related_pr_without_release_fix'
        : 'duplicate_related_pr_without_release_fix',
      summary: `${prefix}; related PR references exist, but none is credited as trusted release-fix proof for this issue.`,
      evidence,
    }
    : null;
}

function openIssueInCanonicalBranch(
  sourceIssueNumber: number,
  branch: CanonicalBranchResolution,
  issueDetailsLookup: (number: number) => CanonicalIssueDetails | null = issueDetails,
): CanonicalIssueDetails | null {
  for (const number of uniqueNumbers(branch.path.filter((item) => item !== sourceIssueNumber))) {
    const issue = issueDetailsLookup(number);
    if (issue?.state === 'open') return issue;
  }
  return null;
}

function closedCanonicalRollup(
  nonBugDuplicate: boolean,
  terminalProof: TerminalProofForCanonical,
  evidence: Record<string, unknown>,
): ClosureProofResult {
  if (nonBugDuplicate) {
    return {
      status: 'non_bug_duplicate_to_closed_canonical',
      summary: 'Non-negative item closed as duplicate/superseded; canonical issue is also closed without reachable release-fix proof.',
      evidence,
    };
  }
  const terminalDisposition = closureRiskDisposition(terminalProof.status);
  if (
    terminalDisposition === 'neutral_or_non_actionable' &&
    terminalProofCanResolveAsNonActionable(terminalProof)
  ) {
    return {
      status: 'duplicate_to_non_actionable_canonical',
      summary: 'Closed as duplicate/superseded; canonical issue closed with non-actionable or non-bug terminal proof.',
      evidence,
    };
  }
  if (terminalDisposition === 'known_not_in_release') {
    return {
      status: 'duplicate_to_known_not_in_release_canonical',
      summary: 'Closed as duplicate/superseded; canonical terminal proof is known not to be in this release tag.',
      evidence,
    };
  }
  if (terminalDisposition === 'open_canonical_risk') {
    return {
      status: 'duplicate_to_open_pr_canonical',
      summary: 'Closed as duplicate/superseded; canonical issue is closed but terminal proof still points to open PR or canonical risk.',
      evidence,
    };
  }
  if (terminalProof.status === 'related_open_pr_context') {
    return {
      status: 'duplicate_to_open_pr_canonical',
      summary: 'Closed as duplicate/superseded; canonical issue is closed but terminal proof still points to open PR context.',
      evidence,
    };
  }
  if (terminalDisposition === 'unsupported_closure_claim' && terminalProof.status !== 'duplicate_or_superseded') {
    return {
      status: 'duplicate_to_closed_canonical',
      summary: 'Closed as duplicate/superseded; canonical issue is also closed with terminal proof that is not release-fix credit.',
      evidence,
    };
  }
  return {
    status: 'duplicate_to_unverified_closed_canonical',
    summary: 'Closed as duplicate/superseded; canonical issue is closed but terminal proof does not establish release resolution.',
    evidence,
  };
}

type TerminalProofForCanonical = ClosureProofResult & {
  releaseTag?: string;
  timing?: 'after' | 'same_or_before' | 'unknown';
  sourceReleasePublishedAt?: string | null;
  terminalReleasePublishedAt?: string | null;
  crossRelease?: boolean;
};

function crossReleaseTerminalProofForIssue(
  sourceReleaseTag: string,
  terminalIssueNumber: number,
): TerminalProofForCanonical | null {
  const sourceRelease = releasePublishedAtStmt.get(sourceReleaseTag) as { published_at: string | null } | undefined;
  const sourcePublishedAt = sourceRelease?.published_at ?? null;
  const rows = crossReleaseTerminalProofRowsStmt.all(terminalIssueNumber, sourceReleaseTag) as Array<{
    release_tag: string;
    status: ClosureProofStatus;
    summary: string;
    evidence_json: string | null;
    published_at: string | null;
  }>;
  const integrityByRelease = new Map<string, boolean>();
  const candidates = rows
    .map((row) => {
      const evidence = parseEvidenceObject(row.evidence_json);
      if (Number(evidence.proofAnalyzerVersion) !== CLOSURE_PROOF_ANALYZER_VERSION) {
        return null;
      }
      let dependencyEvidenceCurrent = integrityByRelease.get(row.release_tag);
      if (dependencyEvidenceCurrent === undefined) {
        const integrity = releaseClosureProofIntegrity(row.release_tag);
        dependencyEvidenceCurrent =
          integrity.missingCount === 0 &&
          integrity.extraCount === 0 &&
          integrity.staleCount === 0 &&
          integrity.analyzerVersionMismatchCount === 0 &&
          integrity.dependencySnapshotMissingCount === 0 &&
          integrity.dependencySnapshotMismatchCount === 0 &&
          integrity.dependencySnapshotSchemaMismatchCount === 0 &&
          integrity.dependencySnapshotMembershipMismatchCount === 0 &&
          integrity.dependencyReferencedIssueMissingCount === 0 &&
          integrity.dependencyEvidenceInvalidCount === 0;
        integrityByRelease.set(row.release_tag, dependencyEvidenceCurrent);
      }
      if (!dependencyEvidenceCurrent) return null;
      const timing = releaseTiming(sourcePublishedAt, row.published_at);
      return {
        status: row.status,
        summary: row.summary,
        evidence,
        releaseTag: row.release_tag,
        timing,
        sourceReleasePublishedAt: sourcePublishedAt,
        terminalReleasePublishedAt: row.published_at,
        crossRelease: true,
        priority: terminalProofPriority(row.status, timing),
      };
    })
    .filter((candidate): candidate is NonNullable<typeof candidate> => candidate != null)
    .sort((a, b) => a.priority - b.priority ||
      String(b.terminalReleasePublishedAt ?? '').localeCompare(String(a.terminalReleasePublishedAt ?? '')));
  const best = candidates[0];
  if (!best) return null;
  const { priority: _priority, ...proof } = best;
  return proof;
}

function terminalProofEvidence(proof: TerminalProofForCanonical): Record<string, unknown> {
  const base = {
    status: proof.status,
    summary: proof.summary,
    ...(terminalProofHasConcreteNonActionableRationale(proof) ? { concreteNonActionableRationale: true } : {}),
  };
  if (proof.crossRelease !== true) return base;
  return {
    ...base,
    releaseTag: proof.releaseTag ?? null,
    timing: proof.timing ?? null,
    crossRelease: proof.crossRelease === true,
    sourceReleasePublishedAt: proof.sourceReleasePublishedAt ?? null,
    terminalReleasePublishedAt: proof.terminalReleasePublishedAt ?? null,
  };
}

function terminalProofCanResolveAsNonActionable(proof: TerminalProofForCanonical): boolean {
  return proof.status !== 'not_planned' || terminalProofHasConcreteNonActionableRationale(proof);
}

function terminalProofHasConcreteNonActionableRationale(proof: TerminalProofForCanonical): boolean {
  const evidence = proof.evidence && typeof proof.evidence === 'object' && !Array.isArray(proof.evidence)
    ? proof.evidence as Record<string, unknown>
    : {};
  if (Array.isArray(evidence.nonActionableRationaleComments) && evidence.nonActionableRationaleComments.length > 0) {
    return true;
  }
  const comments = Array.isArray(evidence.matchingComments) ? evidence.matchingComments : [];
  return comments.some((comment) => {
    const snippet = comment && typeof comment === 'object'
      ? (comment as Record<string, unknown>).snippet
      : null;
    return concreteNonActionableTerminalRe.test(String(snippet ?? ''));
  });
}

function parseEvidenceObject(json: string | null): Record<string, unknown> {
  if (!json) return {};
  try {
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function releaseTiming(sourcePublishedAt: string | null, terminalPublishedAt: string | null): 'after' | 'same_or_before' | 'unknown' {
  const sourceMs = sourcePublishedAt ? Date.parse(sourcePublishedAt) : NaN;
  const terminalMs = terminalPublishedAt ? Date.parse(terminalPublishedAt) : NaN;
  if (!Number.isFinite(sourceMs) || !Number.isFinite(terminalMs)) return 'unknown';
  return terminalMs > sourceMs ? 'after' : 'same_or_before';
}

async function laterReachableReleaseByCommit(
  sourceReleaseTag: string,
  currentReachability: Map<string, CommitReachability>,
  reachabilityContext?: ReleaseReachabilityRefreshContext,
): Promise<Map<string, LaterFixRelease>> {
  const remaining = [...currentReachability.values()]
    .filter((result) => result.status === 'not_reachable')
    .map((result) => result.commitOid);
  const releases = laterStableReleaseTagsStmt.all(sourceReleaseTag) as Array<{ tag: string }>;
  const laterByCommit = new Map<string, LaterFixRelease>();
  if (!remaining.length || !releases.length) return laterByCommit;
  let pending = unique(remaining);
  for (const release of releases) {
    if (!pending.length) break;
    const reachability = await checkReleaseCommitReachability(release.tag, pending, {
      context: reachabilityContext,
    });
    const nextPending: string[] = [];
    for (const commitOid of pending) {
      const result = reachability.get(commitOid);
      if (result?.status === 'reachable') {
        const published = releasePublishedAtStmt.get(release.tag) as { published_at: string | null } | undefined;
        laterByCommit.set(commitOid, {
          releaseTag: release.tag,
          publishedAt: published?.published_at ?? null,
          proofType: 'commit',
          commitOid,
        });
      } else {
        nextPending.push(commitOid);
      }
    }
    pending = nextPending;
  }
  return laterByCommit;
}

function terminalProofPriority(status: string, timing: 'after' | 'same_or_before' | 'unknown'): number {
  if (timing === 'after' && isTerminalFixProof(status)) return 0;
  if (!['no_timeline_event', 'unknown'].includes(status)) return 1;
  return 2;
}

function isTerminalFixProof(status: string): boolean {
  return status === 'fixed_in_release' || status === 'fixed_after_release';
}

function adjustClosureProofStatus(
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
  releaseTag: string,
  laterCommitReachability: Map<string, LaterFixRelease>,
  latestStableReleaseLookup = latestStableRelease,
): ClosureProofResult {
  const adjusted = adjustNotPlannedEvidenceStatus(
    adjustLinkedClosingPrStatus(
      adjustAdminTitleOnlyStatus(adjustNoReleaseFixProofStatus(result, evidence), evidence),
      evidence,
    ),
    evidence,
  );
  return adjustFixedAfterReleaseStatus(adjusted, evidence, releaseTag, laterCommitReachability, latestStableReleaseLookup);
}

function adjustAdminTitleOnlyStatus(
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
): ClosureProofResult {
  if (!isAdminNotPlannedRiskStatus(result.status)) return result;
  const title = String(evidence.title ?? '');
  if (/\b(?:deleted|withdrawn)\s+by\s+author\s+request\b/i.test(title)) {
    return {
      ...result,
      status: 'reporter_withdrawn',
      summary: 'Title indicates the reporter withdrew or requested deletion; closure is not release fix proof.',
    };
  }
  return result;
}

function adjustLinkedClosingPrStatus(
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
): ClosureProofResult {
  const negativeLinked = result.status === 'linked_closing_pr_not_merged';
  const nonBugLinked = result.status === 'non_bug_linked_without_merge';
  if (!negativeLinked && !nonBugLinked) return result;
  const closingPrs = linkedClosingPrEvidence(evidence);
  if (closingPrs.some((pr) => String(pr.state ?? '').toUpperCase() === 'OPEN' && Number(pr.merged ?? 0) !== 1)) {
    return {
      ...result,
      status: negativeLinked ? 'linked_closing_pr_open' : 'non_bug_linked_pr_open',
      summary: negativeLinked
        ? 'A linked closing PR exists and remains open, so the closure points to unresolved PR work.'
        : 'Non-negative item has an open linked closing PR; not scored as bug fix credit.',
    };
  }
  if (closingPrs.some((pr) => String(pr.state ?? '').toUpperCase() === 'CLOSED' && Number(pr.merged ?? 0) !== 1)) {
    return {
      ...result,
      status: negativeLinked ? 'linked_closing_pr_closed_unmerged' : 'non_bug_linked_pr_closed_unmerged',
      summary: negativeLinked
        ? 'A linked closing PR exists, but it was closed without merging.'
        : 'Non-negative item has a linked closing PR that closed without merging.',
    };
  }
  return result;
}

type LaterFixRelease = {
  releaseTag: string;
  publishedAt: string | null;
  proofType: 'pr' | 'commit';
  prNumber?: number;
  prRepositoryNameWithOwner?: string;
  commitOid?: string;
};

type UnscoredFixProof = {
  timing: 'after_latest_release' | 'skipped_by_later_releases' | 'unknown';
  proofTime: string | null;
  latestScoredReleaseTag: string | null;
  latestScoredReleasePublishedAt: string | null;
  proofType: 'pr' | 'commit' | 'unknown';
  prNumber?: number;
  prRepositoryNameWithOwner?: string;
  commitOid?: string;
};

function adjustFixedAfterReleaseStatus(
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
  releaseTag: string,
  laterCommitReachability: Map<string, LaterFixRelease>,
  latestStableReleaseLookup = latestStableRelease,
): ClosureProofResult {
  const fixedAfter = result.status === 'fixed_after_release';
  const nonBugFixedAfter = result.status === 'non_bug_fixed_after_release';
  if (!fixedAfter && !nonBugFixedAfter) return result;
  const later = earliestLaterFixRelease([
    ...laterPrFixReleases(releaseTag, evidence),
    ...laterCommitFixReleases(evidence, laterCommitReachability),
  ]);
  if (later) {
    evidence.laterFixProof = later;
    return {
      ...result,
      status: fixedAfter ? 'fixed_in_later_release' : 'non_bug_fixed_in_later_release',
      summary: fixedAfter
        ? `Fix proof is not in this release tag, but is reachable from later stable ${later.releaseTag}.`
        : `Non-negative item has fix proof reachable from later stable ${later.releaseTag}; not scored as bug fix credit.`,
    };
  }
  const unscored = unscoredFixProof(evidence, latestStableReleaseLookup);
  if (unscored.timing !== 'unknown') evidence.unscoredFixProof = unscored;
  if (unscored.timing === 'after_latest_release') {
    return {
      ...result,
      status: fixedAfter ? 'fixed_after_latest_release' : 'non_bug_fixed_after_latest_release',
      summary: fixedAfter
        ? 'Fix proof exists after the latest scored stable release; no scored stable contains it yet.'
        : 'Non-negative item has fix proof after the latest scored stable release.',
    };
  }
  if (unscored.timing === 'skipped_by_later_releases') {
    return {
      ...result,
      status: fixedAfter ? 'fixed_skipped_by_later_releases' : 'non_bug_fixed_skipped_by_later_releases',
      summary: fixedAfter
        ? 'Fix proof predates a later scored stable release, but no scored stable contains it.'
        : 'Non-negative item has fix proof skipped by later scored stable releases.',
    };
  }
  return {
    ...result,
    status: fixedAfter ? 'fixed_not_in_scored_releases' : 'non_bug_fixed_not_in_scored_releases',
    summary: fixedAfter
      ? 'Fix proof exists, but no scored stable release currently contains it.'
      : 'Non-negative item has fix proof that is not reachable from any scored stable release.',
  };
}

function latestStableRelease(): { tag: string; published_at: string | null } | undefined {
  return latestStableReleaseStmt.get() as { tag: string; published_at: string | null } | undefined;
}

function unscoredFixProof(
  evidence: Record<string, unknown>,
  latestStableReleaseLookup = latestStableRelease,
): UnscoredFixProof {
  const latest = latestStableReleaseLookup();
  const latestMs = latest?.published_at ? Date.parse(latest.published_at) : NaN;
  const proofs = validProofTimes([
    ...notReachablePrProofTimes(evidence),
    ...notReachableCommitProofTimes(evidence),
  ]);
  const proof = Number.isFinite(latestMs)
    ? earliestProofTime(proofs.filter((item) => Date.parse(String(item.proofTime)) > latestMs)) ?? earliestProofTime(proofs)
    : earliestProofTime(proofs);
  const proofTime = proof?.proofTime ?? null;
  if (!proof || !proofTime || !Number.isFinite(latestMs)) {
    return {
      timing: 'unknown',
      proofTime,
      latestScoredReleaseTag: latest?.tag ?? null,
      latestScoredReleasePublishedAt: latest?.published_at ?? null,
      proofType: proof?.proofType ?? 'unknown',
      prRepositoryNameWithOwner: proof?.prRepositoryNameWithOwner,
      prNumber: proof?.prNumber,
      commitOid: proof?.commitOid,
    };
  }
  return {
    timing: Date.parse(proofTime) > latestMs ? 'after_latest_release' : 'skipped_by_later_releases',
    proofTime,
    latestScoredReleaseTag: latest?.tag ?? null,
    latestScoredReleasePublishedAt: latest?.published_at ?? null,
    proofType: proof.proofType,
    prRepositoryNameWithOwner: proof.prRepositoryNameWithOwner,
    prNumber: proof.prNumber,
    commitOid: proof.commitOid,
  };
}

function notReachablePrProofTimes(evidence: Record<string, unknown>): UnscoredFixProof[] {
  const linkedPrs = Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs as Array<Record<string, unknown>> : [];
  const proofTimes: UnscoredFixProof[] = [];
  const seen = new Set<string>();
  for (const pr of linkedPrs) {
    const repo = String(pr.repositoryNameWithOwner ?? '');
    const prNumber = Number(pr.number ?? 0);
    const mergedAt = typeof pr.mergedAt === 'string' ? pr.mergedAt : null;
    if (repo !== trackedPrRepositoryNameWithOwner || !Number.isInteger(prNumber) || prNumber <= 0 || !mergedAt) continue;
    if (Number(pr.merged ?? 0) !== 1) continue;
    const source = String(pr.source ?? '');
    if (!['closedByPullRequestsReferences', 'ClosedEvent.closer', 'ClosureComment.fixProof'].includes(source)) continue;
    const key = `${repo}#${prNumber}`;
    if (seen.has(key)) continue;
    seen.add(key);
    proofTimes.push({
      timing: 'unknown',
      proofTime: mergedAt,
      latestScoredReleaseTag: null,
      latestScoredReleasePublishedAt: null,
      proofType: 'pr',
      prRepositoryNameWithOwner: repo,
      prNumber,
    });
  }
  return proofTimes;
}

function notReachableCommitProofTimes(evidence: Record<string, unknown>): UnscoredFixProof[] {
  const proofs = Array.isArray(evidence.fixCommitProof) ? evidence.fixCommitProof as Array<Record<string, unknown>> : [];
  return proofs
    .filter((proof) => proof.status === 'not_reachable' && typeof proof.referencedAt === 'string')
    .map((proof) => ({
      timing: 'unknown' as const,
      proofTime: String(proof.referencedAt),
      latestScoredReleaseTag: null,
      latestScoredReleasePublishedAt: null,
      proofType: 'commit' as const,
      commitOid: String(proof.commitOid ?? ''),
    }));
}

function earliestProofTime(proofs: UnscoredFixProof[]): UnscoredFixProof | null {
  return validProofTimes(proofs)[0] ?? null;
}

function validProofTimes(proofs: UnscoredFixProof[]): UnscoredFixProof[] {
  return proofs
    .filter((proof) => proof.proofTime && Number.isFinite(Date.parse(proof.proofTime)))
    .sort((a, b) => String(a.proofTime).localeCompare(String(b.proofTime)));
}

function laterPrFixReleases(releaseTag: string, evidence: Record<string, unknown>): LaterFixRelease[] {
  const linkedPrs = Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs as Array<Record<string, unknown>> : [];
  const releases: LaterFixRelease[] = [];
  const seen = new Set<string>();
  for (const pr of linkedPrs) {
    const repo = String(pr.repositoryNameWithOwner ?? '');
    const prNumber = Number(pr.number ?? 0);
    if (repo !== trackedPrRepositoryNameWithOwner || !Number.isInteger(prNumber) || prNumber <= 0) continue;
    if (Number(pr.merged ?? 0) !== 1) continue;
    const source = String(pr.source ?? '');
    if (!['closedByPullRequestsReferences', 'ClosedEvent.closer', 'ClosureComment.fixProof'].includes(source)) continue;
    const key = `${repo}#${prNumber}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const row = laterPrReachabilityStmt.get(repo, prNumber, releaseTag) as { tag: string; published_at: string | null } | undefined;
    if (!row) continue;
    releases.push({
      releaseTag: row.tag,
      publishedAt: row.published_at ?? null,
      proofType: 'pr',
      prRepositoryNameWithOwner: repo,
      prNumber,
    });
  }
  return releases;
}

function laterCommitFixReleases(
  evidence: Record<string, unknown>,
  laterCommitReachability: Map<string, LaterFixRelease>,
): LaterFixRelease[] {
  const commits = Array.isArray(evidence.notReachableFixCommits) ? evidence.notReachableFixCommits as unknown[] : [];
  return commits
    .map((commit) => laterCommitReachability.get(String(commit)))
    .filter((item): item is LaterFixRelease => !!item);
}

function earliestLaterFixRelease(releases: LaterFixRelease[]): LaterFixRelease | null {
  return [...releases].sort((a, b) =>
    String(a.publishedAt ?? '').localeCompare(String(b.publishedAt ?? '')) ||
    a.releaseTag.localeCompare(b.releaseTag))[0] ?? null;
}

function adjustNoReleaseFixProofStatus(
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
): ClosureProofResult {
  if (result.status !== 'closed_without_release_fix_proof') return result;
  const linkedPrs = statusBearingLinkedPrEvidence(evidence);
  if (linkedPrs.length === 0) return result;
  const context = relatedPrContextFromPayload(evidence);
  if (context.externalClosing.length > 0) {
    return {
      ...result,
      status: 'external_repo_closing_pr_unscored',
      summary: 'GitHub closure points to a merged PR in another repository; OpenClaw release inclusion is not proven by the release tag.',
    };
  }
  if (context.open.length > 0) {
    return {
      ...result,
      status: 'related_open_pr_context',
      summary: 'Related PR context remains open, so the closure is not trusted release-fix proof.',
    };
  }
  if (context.reachable.length > 0) {
    return {
      ...result,
      status: 'related_merged_pr_reachable_context_without_fix_credit',
      summary: 'Related PR work is reachable from this release tag, but no trusted closing or fix proof is credited for this issue.',
    };
  }
  if (context.notReachable.length > 0) {
    return {
      ...result,
      status: 'related_merged_pr_not_reachable_context',
      summary: 'Related merged PR work exists, but it is not reachable from this release tag.',
    };
  }
  if (context.unknownReachability.length > 0) {
    return {
      ...result,
      status: 'related_merged_pr_reachability_unknown',
      summary: 'Related merged PR work exists, but release-tag reachability has not been proven.',
    };
  }
  if (context.closedUnmerged.length > 0) {
    return {
      ...result,
      status: 'related_closed_unmerged_pr_context',
      summary: 'Related PR context exists, but the referenced PRs closed without merging.',
    };
  }
  return {
    ...result,
    status: 'related_pr_without_release_fix',
    summary: 'Related PR references exist, but none is credited as trusted release-fix proof for this issue.',
  };
}

function linkedClosingPrEvidence(evidence: Record<string, unknown>): Array<Record<string, unknown>> {
  return statusBearingLinkedPrEvidence(evidence).filter((pr) =>
    Number(pr.willCloseTarget ?? 0) === 1 ||
    String(pr.source ?? '') === 'closedByPullRequestsReferences' ||
    String(pr.source ?? '') === 'ClosedEvent.closer'
  );
}

function adjustNotPlannedEvidenceStatus(
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
): ClosureProofResult {
  if (!isAdminNotPlannedRiskStatus(result.status)) return result;
  const linkedPrs = statusBearingLinkedPrEvidence(evidence);
  if (evidence.hasReachableFixCommit === true || evidence.hasReachableClosingPr === true) {
    return {
      ...result,
      status: 'not_planned_with_release_fix_proof',
      summary: 'Closed as not planned, but trusted release-reachable fix proof exists; this resolves closure risk without direct GitHub fix-credit.',
    };
  }
  const reachableTrustedFixProofPrs = trustedReachableFixProofPrs(evidence);
  if (reachableTrustedFixProofPrs.length > 0) {
    return {
      ...result,
      status: 'not_planned_with_release_fix_proof',
      summary: 'Closed as not planned, but trusted closure-comment fix proof is reachable from this release tag; this resolves closure risk without direct GitHub fix-credit.',
      evidence: { ...result.evidence, ...evidence, reachableTrustedFixProofPrs },
    };
  }
  if (evidence.hasNotReachableFixCommit === true || evidence.hasNotReachableClosingPr === true) {
    return {
      ...result,
      status: 'not_planned_fixed_after_release',
      summary: 'Closed as not planned with fix proof that is not reachable from this release tag.',
    };
  }
  if (evidence.hasUnknownFixCommit === true) {
    return {
      ...result,
      status: 'not_planned_direct_fix_commit_reachability_unknown',
      summary: 'Closed as not planned with direct fix/source commit proof whose release-tag reachability is missing or unknown.',
    };
  }
  if (linkedPrs.some((pr) => String(pr.state ?? '').toUpperCase() === 'OPEN' && Number(pr.merged ?? 0) !== 1)) {
    return {
      ...result,
      status: 'not_planned_with_open_pr_context',
      summary: 'Closed as not planned while related open PR context still exists; no reachable release-fix proof is credited.',
    };
  }
  if (linkedPrs.some((pr) => Number(pr.willCloseTarget ?? 0) === 1 && Number(pr.merged ?? 0) !== 1)) {
    return {
      ...result,
      status: 'not_planned_linked_pr_not_merged',
      summary: 'Closed as not planned with a linked closing PR that is not merged or has unknown merge state.',
    };
  }
  if (linkedPrs.length > 0) {
    const context = relatedPrContextFromPayload(evidence);
    if (context.reachable.length > 0) {
      return {
        ...result,
        status: 'not_planned_related_merged_pr_reachable_context_without_fix_credit',
        summary: 'Closed as not planned with related PR work reachable from this release tag, but no trusted closing or fix proof is credited for this issue.',
      };
    }
    if (context.notReachable.length > 0) {
      return {
        ...result,
        status: 'not_planned_related_merged_pr_not_reachable_context',
        summary: 'Closed as not planned with related merged PR work that is not reachable from this release tag.',
      };
    }
    if (context.unknownReachability.length > 0) {
      return {
        ...result,
        status: 'not_planned_related_merged_pr_reachability_unknown',
        summary: 'Closed as not planned with related merged PR work whose release-tag reachability is unknown.',
      };
    }
    if (context.closedUnmerged.length > 0) {
      return {
        ...result,
        status: 'not_planned_related_closed_unmerged_pr_context',
        summary: 'Closed as not planned with related PR context that closed without merging.',
      };
    }
    return {
      ...result,
      status: 'not_planned_related_pr_without_release_fix',
      summary: 'Closed as not planned with related PR references, but none is credited as trusted release-fix proof for this issue.',
    };
  }
  return result;
}

function isAdminNotPlannedRiskStatus(status: string): boolean {
  return status === 'admin_not_planned_unverified' || status === 'admin_not_planned_no_context';
}

type RelatedPrContext = {
  externalClosing: Array<Record<string, unknown>>;
  open: Array<Record<string, unknown>>;
  closedUnmerged: Array<Record<string, unknown>>;
  notReachable: Array<Record<string, unknown>>;
  reachable: Array<Record<string, unknown>>;
  unknownReachability: Array<Record<string, unknown>>;
};

function emptyRelatedPrContext(): RelatedPrContext {
  return {
    externalClosing: [],
    open: [],
    closedUnmerged: [],
    notReachable: [],
    reachable: [],
    unknownReachability: [],
  };
}

function hasRelatedPrContext(context: RelatedPrContext): boolean {
  return Object.values(context).some((items) => items.length > 0);
}

function relatedPrContextFromPayload(evidence: Record<string, unknown>): RelatedPrContext {
  const raw = evidence.relatedPrContext;
  if (!raw || typeof raw !== 'object') return emptyRelatedPrContext();
  const context = raw as Record<string, unknown>;
  return {
    externalClosing: statusBearingPrRows(context.externalClosing),
    open: statusBearingPrRows(context.open),
    closedUnmerged: statusBearingPrRows(context.closedUnmerged),
    notReachable: statusBearingPrRows(context.notReachable),
    reachable: statusBearingPrRows(context.reachable),
    unknownReachability: statusBearingPrRows(context.unknownReachability),
  };
}

function statusBearingPrRows(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value)
    ? value.filter(isStatusBearingPrEvidence)
    : [];
}

function statusBearingLinkedPrEvidence(evidence: Record<string, unknown>): Array<Record<string, unknown>> {
  return statusBearingPrRows(evidence.linkedPrs);
}

function isStatusBearingPrEvidence(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const pr = value as Record<string, unknown>;
  return Number(pr.willCloseTarget ?? 0) === 1 ||
    STATUS_BEARING_PR_SOURCES.has(String(pr.source ?? ''));
}

function trustedReachableFixProofPrs(evidence: Record<string, unknown>): Array<Record<string, unknown>> {
  return relatedPrContextFromPayload(evidence).reachable.filter((pr) =>
    String(pr.source ?? '') === 'ClosureComment.fixProof' &&
    String(pr.repositoryNameWithOwner ?? '').toLowerCase() === trackedPrRepositoryNameWithOwner.toLowerCase());
}

function relatedPrContextEvidence(
  releaseTag: string,
  evidence: Record<string, unknown>,
): RelatedPrContext {
  const linkedPrs = statusBearingLinkedPrEvidence(evidence)
    .slice()
    .sort(compareLinkedPrEvidencePriority);
  const context = emptyRelatedPrContext();
  const seen = new Set<string>();
  for (const pr of linkedPrs) {
    const repo = String(pr.repositoryNameWithOwner ?? '');
    const prNumber = Number(pr.number ?? 0);
    if (!Number.isInteger(prNumber) || prNumber <= 0) continue;
    const source = String(pr.source ?? '');
    const state = String(pr.state ?? '').toUpperCase();
    const merged = Number(pr.merged ?? 0) === 1;
    const key = `${repo}#${prNumber}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const item = {
      ...pr,
      number: prNumber,
      repositoryNameWithOwner: repo,
      source: pr.source ?? null,
      state,
      merged: merged ? 1 : 0,
      title: pr.title ?? null,
      url: pr.url ?? null,
      mergedAt: pr.mergedAt ?? null,
    };
    const isClosingSource = Number(pr.willCloseTarget ?? 0) === 1 ||
      source === 'closedByPullRequestsReferences' ||
      source === 'ClosedEvent.closer';
    if (repo !== trackedPrRepositoryNameWithOwner) {
      if (isClosingSource && merged) context.externalClosing.push(item);
      continue;
    }
    if (state === 'OPEN' && !merged) {
      context.open.push(item);
      continue;
    }
    if (state === 'CLOSED' && !merged) {
      context.closedUnmerged.push(item);
      continue;
    }
    if (!merged) continue;
    const reachability = releasePrReachabilityStatusStmt.get(releaseTag, repo, prNumber) as {
      status: string;
      tag_commit_oid: string | null;
      merge_commit_oid: string | null;
      method: string | null;
    } | undefined;
    const reachedItem = {
      ...item,
      reachabilityStatus: reachability?.status ?? 'unknown',
      reachabilityMethod: reachability?.method ?? null,
      mergeCommitOid: reachability?.merge_commit_oid ?? null,
    };
    if (reachability?.status === 'reachable') context.reachable.push(reachedItem);
    else if (reachability?.status === 'not_reachable') context.notReachable.push(reachedItem);
    else context.unknownReachability.push(reachedItem);
  }
  return {
    externalClosing: context.externalClosing.slice(0, 10),
    open: context.open.slice(0, 10),
    closedUnmerged: context.closedUnmerged.slice(0, 10),
    notReachable: context.notReachable.slice(0, 10),
    reachable: context.reachable.slice(0, 10),
    unknownReachability: context.unknownReachability.slice(0, 10),
  };
}

function compareLinkedPrEvidencePriority(left: Record<string, unknown>, right: Record<string, unknown>): number {
  const leftOpen = String(left.state ?? '').toUpperCase() === 'OPEN' && Number(left.merged ?? 0) !== 1 ? 0 : 1;
  const rightOpen = String(right.state ?? '').toUpperCase() === 'OPEN' && Number(right.merged ?? 0) !== 1 ? 0 : 1;
  if (leftOpen !== rightOpen) return leftOpen - rightOpen;
  const leftRepo = String(left.repositoryNameWithOwner ?? '');
  const rightRepo = String(right.repositoryNameWithOwner ?? '');
  if (leftRepo !== rightRepo) return leftRepo.localeCompare(rightRepo);
  const leftNumber = Number(left.number ?? 0);
  const rightNumber = Number(right.number ?? 0);
  if (leftNumber !== rightNumber) return leftNumber - rightNumber;
  return linkedPrSourcePriority(left.source) - linkedPrSourcePriority(right.source);
}

function linkedPrSourcePriority(source: unknown): number {
  switch (String(source ?? '')) {
    case 'closedByPullRequestsReferences': return 0;
    case 'ClosedEvent.closer': return 1;
    case 'ClosureComment.fixProof': return 2;
    case 'ClosureComment.prMention': return 3;
    default: return 4;
  }
}

type CanonicalIssueDetails = {
  number: number;
  title: string | null;
  state: string | null;
  url: string | null;
};

type CanonicalBranchResolution = {
  path: number[];
  terminalIssue: CanonicalIssueDetails | null;
  cycle: boolean;
  selfReference: boolean;
  truncated: boolean;
};

type CanonicalResolution = CanonicalBranchResolution & {
  branches: CanonicalBranchResolution[];
  terminalIssues: CanonicalIssueDetails[];
};

function canonicalResolution(
  sourceIssueNumber: number,
  graph: Map<number, number[]>,
  issueDetailsLookup: (number: number) => CanonicalIssueDetails | null = issueDetails,
): CanonicalResolution {
  const branches: CanonicalBranchResolution[] = [];
  const walk = (current: number, path: number[], depth: number): void => {
    const targets = uniqueNumbers((graph.get(current) ?? []).filter((number) => Number.isInteger(number)));
    if (!targets.length) {
      branches.push({
        path,
        terminalIssue: current === sourceIssueNumber ? null : issueDetailsLookup(current),
        cycle: false,
        selfReference: false,
        truncated: false,
      });
      return;
    }
    for (const target of targets) {
      const nextPath = [...path, target];
      if (path.includes(target)) {
        branches.push({
          path: nextPath,
          terminalIssue: issueDetailsLookup(target),
          cycle: true,
          selfReference: target === sourceIssueNumber,
          truncated: false,
        });
        continue;
      }
      if (depth >= 7) {
        branches.push({
          path: nextPath,
          terminalIssue: issueDetailsLookup(target),
          cycle: false,
          selfReference: false,
          truncated: true,
        });
        continue;
      }
      walk(target, nextPath, depth + 1);
    }
  };
  walk(sourceIssueNumber, [sourceIssueNumber], 0);
  if (!branches.length) {
    branches.push({
      path: [sourceIssueNumber],
      terminalIssue: null,
      cycle: false,
      selfReference: false,
      truncated: false,
    });
  }
  const primary = branches[0];
  const terminalIssues = new Map<number, CanonicalIssueDetails>();
  for (const branch of branches) {
    if (branch.terminalIssue) terminalIssues.set(branch.terminalIssue.number, branch.terminalIssue);
  }
  return {
    ...primary,
    cycle: branches.some((branch) => branch.cycle),
    selfReference: branches.some((branch) => branch.selfReference),
    truncated: branches.some((branch) => branch.truncated),
    branches,
    terminalIssues: [...terminalIssues.values()].sort((left, right) => left.number - right.number),
  };
}

export const __closureProofAnalysisTest = {
  FINAL_CLOSURE_TIMESTAMP_TOLERANCE_MS,
  UNKNOWN_REACHABILITY_RETRY_MS,
  adjustClosureProofStatus,
  adjustCanonicalDuplicateStatus,
  adjustNotPlannedEvidenceStatus,
  adjustNoReleaseFixProofStatus,
  canonicalIssueNumbersFromText,
  canonicalIssueNumbersFromComments,
  trustedCanonicalIssueNumbersFromComments,
  trustedClosureRationaleComments,
  effectiveClosureProofClassification,
  enrichLinkedPrReachability,
  commitProofEvidence,
  creditableDirectCommitProof,
  summarizeDirectCommitFirstContainingProofs,
  commitReferenceMentionsFromRows,
  shouldUseReferencedCommitProof,
  compareLinkedPrEvidencePriority,
  expandCanonicalGraph,
  canonicalIssueNumbersReachableFrom,
  canonicalResolution,
  terminalCanonicalIssuesNeedingEvidence,
  crossReleaseTerminalProofForIssue,
  missingClassificationClosureProof,
  closureCommentIsInFinalClosureWindow,
  assertIssueClosedAtMatchesSelectedFinalEvent,
  invalidateExpiredUnknownDirectCommitProofs,
  closureRationaleCommentsForFinalClosure,
  closureCommentPrMentionsForFinalClosure,
  commentsForIssues,
  closureProofCommentSnapshotDriftIssueNumbers,
  acceptedClosureCommentSnapshot,
  issueStateSnapshotMetadataMatches,
  pullRequestsForLookups,
  persistedIssueStateSnapshotMatchesAcceptedEvidence,
  replaceVerifiedIssueStateEventSnapshot,
  unresolvedStateSnapshotMetadataDriftIssueNumbers,
  unresolvedCommentSnapshotMetadataDriftIssueNumbers,
  validateClosureCommentSnapshot,
};

function issueDetails(number: number): { number: number; title: string | null; state: string | null; url: string | null } | null {
  const row = db.prepare(`SELECT number, title, state, html_url FROM issues WHERE number=?`).get(number) as {
    number: number;
    title: string;
    state: string;
    html_url: string | null;
  } | undefined;
  return row ? { number: row.number, title: row.title, state: row.state, url: row.html_url ?? null } : {
    number,
    title: null,
    state: null,
    url: null,
  };
}

export async function refreshClosureEvidenceForRelease(
  releaseTag: string,
  runContext?: ClosureProofRunContext,
): Promise<ClosureProofAnalysisResult['rawEvidence'] & {
  issueCount: number;
  refreshedIssueCount: number;
  reusedIssueCount: number;
  deferredIssueCount: number;
  issueMetadataDriftIssueNumbers: number[];
}> {
  if (!runContext?.assertCanWrite) {
    return withClosureProofWriteLease(
      runContext,
      `refresh-evidence:${releaseTag}`,
      (leasedContext) => refreshClosureEvidenceForRelease(releaseTag, leasedContext),
    );
  }
  const rows = allClosedIssueRowsStmt.all(releaseTag) as Array<{ number: number }>;
  const issueNumbers = rows.map((row) => row.number);
  const rawEvidence = await refreshRawClosureEvidence(issueNumbers, runContext);
  return { issueCount: issueNumbers.length, ...rawEvidence };
}

function rawClosureEvidenceCounts(issueNumbers: number[]): ClosureProofAnalysisResult['rawEvidence'] {
  if (!issueNumbers.length) return { closureEvents: 0, reopenEvents: 0, prLinks: 0, pullRequests: 0, commitReferences: 0 };
  const selected = JSON.stringify(issueNumbers);
  const row = db.prepare(`
    WITH selected(issue_number) AS (
      SELECT value FROM json_each(?)
    )
    SELECT
      (SELECT COUNT(DISTINCT e.event_id)
       FROM issue_closure_events e
       JOIN selected s ON s.issue_number=e.issue_number) AS closureEvents,
      (SELECT COUNT(DISTINCT r.event_id)
       FROM issue_reopen_events r
       JOIN selected s ON s.issue_number=r.issue_number) AS reopenEvents,
      (SELECT COUNT(*)
       FROM issue_pr_links l
       JOIN selected s ON s.issue_number=l.issue_number) AS prLinks,
        (SELECT COUNT(DISTINCT p.pr_repository_name_with_owner || '#' || p.pr_number)
         FROM pull_request_fixes p
         JOIN issue_pr_links l ON l.pr_repository_name_with_owner=p.pr_repository_name_with_owner AND l.pr_number=p.pr_number
         JOIN selected s ON s.issue_number=l.issue_number) AS pullRequests,
      (SELECT COUNT(DISTINCT c.event_id)
       FROM issue_commit_references c
       JOIN selected s ON s.issue_number=c.issue_number) AS commitReferences
  `).get(selected) as {
    closureEvents: number;
    reopenEvents: number;
    prLinks: number;
    pullRequests: number;
    commitReferences: number;
  } | undefined;
  return {
    closureEvents: Number(row?.closureEvents ?? 0),
    reopenEvents: Number(row?.reopenEvents ?? 0),
    prLinks: Number(row?.prLinks ?? 0),
    pullRequests: Number(row?.pullRequests ?? 0),
    commitReferences: Number(row?.commitReferences ?? 0),
  };
}

async function refreshRawClosureEvidence(
  issueNumbers: number[],
  runContext: ClosureProofRunContext = createClosureProofRunContext(),
): Promise<ClosureProofAnalysisResult['rawEvidence'] & {
  refreshedIssueCount: number;
  reusedIssueCount: number;
  deferredIssueCount: number;
  issueMetadataDriftIssueNumbers: number[];
}> {
  const requestedIssueNumbers = uniqueNumbers(issueNumbers);
  const commentsByIssue = await commentsForIssues(runContext, requestedIssueNumbers, {
    allowMetadataDrift: true,
  });
  const issueMetadataDrift = new Set(unresolvedCommentSnapshotMetadataDriftIssueNumbers(
    runContext,
    requestedIssueNumbers,
  ));
  const eligibleIssueNumbers = requestedIssueNumbers.filter((issueNumber) => !issueMetadataDrift.has(issueNumber));
  const issueNumbersToRefresh = uniqueNumbers([
    ...closureEvidenceIssuesNeedingRefresh(
      eligibleIssueNumbers,
      RAW_CLOSURE_EVIDENCE_SCHEMA_VERSION,
    ),
    ...eligibleIssueNumbers.filter((issueNumber) =>
      !persistedIssueStateSnapshotMatchesAcceptedEvidence(runContext, issueNumber)),
  ]);
  let refreshedIssueCount = 0;
  for (let offset = 0; offset < issueNumbersToRefresh.length; offset += 20) {
    throwIfAborted(runContext.signal);
    const chunk = issueNumbersToRefresh.slice(offset, offset + 20);
    const evidence = await fixEvidenceForIssues(runContext, chunk);
    const stableChunk = chunk.filter((issueNumber) => {
      const matches = issueStateSnapshotMetadataMatches(
        evidence.get(issueNumber),
        getIssue(issueNumber),
        runContext.commentSnapshotsByIssue.get(issueNumber),
      );
      if (!matches) {
        issueMetadataDrift.add(issueNumber);
        runContext.stateSnapshotMetadataDriftIssueNumbers.add(issueNumber);
      }
      return matches;
    });
    if (stableChunk.length === 0) continue;
    const finalClosureWindows = finalClosureWindowsForIssues(stableChunk);
    for (const issueNumber of stableChunk) {
      const item = evidence.get(issueNumber);
      if (!item) continue;
      const window = finalClosureWindows.get(item.issueNumber);
      if (!window) continue;
      window.finalReopenedAt = latestReopenBeforeFinalClosure(
        item.reopenEvents.map((event) => event.reopenedAt),
        window.closedAt,
      );
    }
    const commentMentions = stableChunk.flatMap((issueNumber) =>
      closureCommentPrMentionsForFinalClosure(
        issueNumber,
        commentsByIssue.get(issueNumber) ?? [],
        finalClosureWindows.get(issueNumber),
      ),
    );
    const mentionedPrs = await pullRequestsForLookups(
      runContext,
      commentMentions.map((mention) => ({
        prNumber: mention.prNumber,
        prRepositoryOwner: mention.prRepositoryOwner,
        prRepositoryName: mention.prRepositoryName,
        prRepositoryNameWithOwner: mention.prRepositoryNameWithOwner,
      })),
    );
    assertClosureProofWriteAllowed(runContext, 'raw closure evidence persistence');
    runInWriteTransaction(() => {
      assertClosureProofWriteAllowed(
        runContext,
        'raw closure evidence persistence transaction',
      );
      deleteCommentIssuePrLinksForIssues(stableChunk);
      assertClosureIssueRevisions(runContext, stableChunk);
      for (const issueNumber of stableChunk) {
        const item = evidence.get(issueNumber);
        if (!item) {
          throw new Error(`Missing verified issue state evidence for #${issueNumber}`);
        }
        replaceVerifiedIssueStateEventSnapshot(item);
      }
      for (const mention of commentMentions) {
        const pr = mentionedPrs.get(pullRequestKey(mention.prRepositoryNameWithOwner, mention.prNumber));
        upsertIssuePrLink({
          issue_number: mention.issueNumber,
          pr_repository_owner: mention.prRepositoryOwner,
          pr_repository_name: mention.prRepositoryName,
          pr_repository_name_with_owner: mention.prRepositoryNameWithOwner,
          pr_number: mention.prNumber,
          source: mention.source,
            will_close_target: null,
            referenced_at: mention.referencedAt,
            source_comment_database_id: mention.sourceCommentDatabaseId ?? null,
            source_comment_url: mention.sourceCommentUrl ?? null,
        });
        if (!pr) continue;
        upsertPullRequestFix({
          pr_repository_owner: pr.repositoryOwner,
          pr_repository_name: pr.repositoryName,
          pr_repository_name_with_owner: pr.repositoryNameWithOwner,
          pr_number: pr.number,
          title: pr.title,
          url: pr.url,
          state: pr.state,
          merged: pr.merged ? 1 : 0,
          merged_at: pr.mergedAt,
          merge_commit_oid: pr.mergeCommitOid,
          base_ref_name: pr.baseRefName,
        });
      }
      markIssueClosureEvidenceRefreshed(stableChunk, RAW_CLOSURE_EVIDENCE_SCHEMA_VERSION);
    });
    refreshedIssueCount += stableChunk.length;
  }
  const issueMetadataDriftIssueNumbers = [...issueMetadataDrift].sort((a, b) => a - b);
  return {
    ...rawClosureEvidenceCounts(issueNumbers),
    refreshedIssueCount,
    reusedIssueCount: eligibleIssueNumbers.length - issueNumbersToRefresh.length,
    deferredIssueCount: issueMetadataDriftIssueNumbers.length,
    issueMetadataDriftIssueNumbers,
  };
}

async function refreshClosureCommentPrMentionEvidence(
  issueNumbers: number[],
  commentsByIssue: Map<number, GhComment[]>,
  runContext: ClosureProofRunContext = createClosureProofRunContext(),
): Promise<void> {
  const finalClosureWindows = finalClosureWindowsForIssues(issueNumbers);
  const commentMentions = issueNumbers.flatMap((issueNumber) =>
    closureCommentPrMentionsForFinalClosure(
      issueNumber,
      commentsByIssue.get(issueNumber) ?? [],
      finalClosureWindows.get(issueNumber),
    ),
  );
  const mentionedPrs = await pullRequestsForLookups(
    runContext,
    commentMentions.map((mention) => ({
      prNumber: mention.prNumber,
      prRepositoryOwner: mention.prRepositoryOwner,
      prRepositoryName: mention.prRepositoryName,
      prRepositoryNameWithOwner: mention.prRepositoryNameWithOwner,
    })),
  );
  assertClosureProofWriteAllowed(runContext, 'closure comment PR mention persistence');
  runInWriteTransaction(() => {
    assertClosureProofWriteAllowed(
      runContext,
      'closure comment PR mention persistence transaction',
    );
    deleteCommentIssuePrLinksForIssues(issueNumbers);
    assertClosureIssueRevisions(runContext, issueNumbers);
    for (const mention of commentMentions) {
      const pr = mentionedPrs.get(pullRequestKey(mention.prRepositoryNameWithOwner, mention.prNumber));
      upsertIssuePrLink({
        issue_number: mention.issueNumber,
        pr_repository_owner: mention.prRepositoryOwner,
        pr_repository_name: mention.prRepositoryName,
        pr_repository_name_with_owner: mention.prRepositoryNameWithOwner,
        pr_number: mention.prNumber,
        source: mention.source,
        will_close_target: null,
        referenced_at: mention.referencedAt,
        source_comment_database_id: mention.sourceCommentDatabaseId ?? null,
        source_comment_url: mention.sourceCommentUrl ?? null,
      });
      if (!pr) continue;
      upsertPullRequestFix({
        pr_repository_owner: pr.repositoryOwner,
        pr_repository_name: pr.repositoryName,
        pr_repository_name_with_owner: pr.repositoryNameWithOwner,
        pr_number: pr.number,
        title: pr.title,
        url: pr.url,
        state: pr.state,
        merged: pr.merged ? 1 : 0,
        merged_at: pr.mergedAt,
        merge_commit_oid: pr.mergeCommitOid,
        base_ref_name: pr.baseRefName,
      });
    }
  });
}

function splitCsv(value: unknown): string[] {
  if (!value) return [];
  return String(value).split(',').map((item) => item.trim()).filter(Boolean);
}

function parseJsonArray(value: unknown): unknown[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
  } catch {
    return [];
  }
}

function openPrContext(evidence: Record<string, unknown>): {
  canonical: Array<Record<string, unknown>>;
  related: Array<Record<string, unknown>>;
} {
  const openPrs = statusBearingLinkedPrEvidence(evidence)
    .filter((item): item is Record<string, unknown> => {
      const state = String(item.state ?? '').toUpperCase();
      return state === 'OPEN' && Number(item.merged ?? 0) === 0;
    });
  return {
    canonical: openPrs.filter((item) => item.source === 'ClosureComment.prMention').slice(0, 5),
    related: openPrs.filter((item) => item.source !== 'ClosureComment.prMention').slice(0, 5),
  };
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function uniqueNumbers(values: number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}

function closureProofDependencyIssueNumbers(
  sourceIssueNumbers: number[],
  canonicalGraph: Map<number, number[]>,
  additionalIssueNumbers: number[] = [],
): number[] {
  return uniqueNumbers([
    ...sourceIssueNumbers,
    ...additionalIssueNumbers,
    ...canonicalGraph.keys(),
    ...[...canonicalGraph.values()].flat(),
  ]);
}

function assertClosureProofWriteAllowed(
  runContext: ClosureProofRunContext | undefined,
  stage: string,
): void {
  throwIfAborted(runContext?.signal);
  if (!runContext?.assertCanWrite) {
    throw new Error(`Closure proof write "${stage}" requires the shared refresh lease`);
  }
  runContext.assertCanWrite(stage);
}

function knownIssueNumber(number: number): boolean {
  return !!issueExistsStmt.get(number);
}

function canonicalIssueDetails(sourceIssueNumber: number, numbers: number[]): Array<{
  number: number;
  title: string | null;
  state: string | null;
  url: string | null;
}> {
  const stmt = db.prepare(`SELECT number, title, state, html_url FROM issues WHERE number=?`);
  return numbers
    .filter((number) => number !== sourceIssueNumber)
    .flatMap((number) => {
      const row = stmt.get(number) as { number: number; title: string; state: string; html_url: string | null } | undefined;
      if (!row) return [];
      return {
        number: row.number,
        title: row.title,
        state: row.state,
        url: row.html_url ?? null,
      };
    });
}
