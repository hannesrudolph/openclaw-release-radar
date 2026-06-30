import { createHash } from 'node:crypto';
import { config } from '../config';
import {
  db,
  deleteCommentIssuePrLinksForIssues,
  deleteIssueClosureProofsForRelease,
  deleteIssuePrLinksForIssues,
  getRelease,
  issueLabelEventCount,
  issueLabelSnapshotCountAt,
  labelsForIssueAt,
  runInWriteTransaction,
  upsertIssueClosureEvent,
  upsertIssueCommentSnapshot,
  upsertIssueClosureProof,
  upsertIssueCommitReference,
  upsertIssuePrLink,
  upsertIssueReopenEvent,
  upsertPullRequestFix,
} from './db';
import { classifyClosureProof, closureRationaleComments, type ClosureProofResult, type ClosureProofStatus } from './closureProof';
import { closureRiskDisposition } from './closureProofTaxonomy';
import { creditedFixLinkSql } from './fixProvenance';
import { closureCommentCommitMentions, closureCommentPrMentions, listIssueCommentsBatch, listIssueFixEvidenceBatch, listPullRequestFixesBatch, pullRequestKey, type ClosureCommentCommitMention, type GhComment } from './github';
import { applyClosureRiskSentimentHint, applyLabelOverrides, applyTitleFunctionalityHint, applyTitleIssueShapeHint } from './labelOverrides';
import type { IssueClassification } from './llm';
import { persistClosureProofInScoreAudit } from './closureProofPayload';
import { releaseLabelCutoff } from './labelCutoff';
import { checkReleaseCommitReachability, checkReleasePrReachability, resolveCommitOidPrefix, type CommitReachability } from './releaseReachability';

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
  persistScoreAuditPayload?: boolean;
  refreshCommentPrMentionEvidence?: boolean;
}

const trackedPrRepositorySqlLiteral = `${config.github.owner}/${config.github.repo}`.replace(/'/g, "''");
const trackedPrRepositoryNameWithOwner = `${config.github.owner}/${config.github.repo}`;
const LINKED_PR_SOURCE_PRIORITY_SQL = `
  CASE l2.source
    WHEN 'closedByPullRequestsReferences' THEN 0
    WHEN 'ClosedEvent.closer' THEN 1
    WHEN 'ClosureComment.fixProof' THEN 2
    WHEN 'ClosureComment.prMention' THEN 3
    ELSE 4
  END
`;

const closedIssueRowsStmt = db.prepare(`
WITH target AS (
  SELECT * FROM releases WHERE tag=?
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
     WHERE next.published_at > target.published_at AND next.prerelease=0),
    '9999-12-31T23:59:59Z'
  )
ORDER BY i.closed_at DESC
`);

const allClosedIssueRowsStmt = db.prepare(`
WITH target AS (
  SELECT * FROM releases WHERE tag=?
)
SELECT DISTINCT i.number
FROM issues i
JOIN target
WHERE i.closed_at IS NOT NULL
  AND target.published_at IS NOT NULL
  AND i.closed_at >= target.published_at
  AND i.closed_at < COALESCE(
    (SELECT MIN(next.published_at) FROM releases next
     WHERE next.published_at > target.published_at AND next.prerelease=0),
    '9999-12-31T23:59:59Z'
  )
ORDER BY i.number DESC
`);

const aggregateRowsStmt = db.prepare(`
WITH selected(issue_number) AS (
  SELECT value FROM json_each(?)
),
window_closure AS (
  SELECT e.*
  FROM issue_closure_events e
  JOIN issues wi
    ON wi.number=e.issue_number
   AND ABS(unixepoch(wi.closed_at) - unixepoch(e.closed_at)) <= 2
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
  GROUP_CONCAT(DISTINCT e.state_reason) AS state_reasons,
  GROUP_CONCAT(DISTINCT e.actor_login) AS closure_actors,
  GROUP_CONCAT(DISTINCT e.closed_at) AS closure_event_closed_at,
  COUNT(DISTINCT e.event_id) AS closure_events,
    COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${creditedFixLinkSql('l')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
      THEN l.pr_repository_name_with_owner || '#' || l.pr_number END
  ) AS closing_links,
  COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${creditedFixLinkSql('l')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
       AND p.merged=1
      THEN p.pr_repository_name_with_owner || '#' || p.pr_number END
  ) AS merged_closing_prs,
  COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${creditedFixLinkSql('l')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
       AND p.merged=1
       AND rpr.status='reachable'
      THEN p.pr_repository_name_with_owner || '#' || p.pr_number END
  ) AS reachable_closing_prs,
  COUNT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${creditedFixLinkSql('l')}
       AND l.pr_repository_name_with_owner='${trackedPrRepositorySqlLiteral}'
       AND p.merged=1
       AND rpr.status='not_reachable'
      THEN p.pr_repository_name_with_owner || '#' || p.pr_number END
  ) AS not_reachable_closing_prs,
  GROUP_CONCAT(DISTINCT CASE
      WHEN e.state_reason='COMPLETED'
       AND ${creditedFixLinkSql('l')}
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
      'willCloseTarget', linked.will_close_target,
      'referencedAt', linked.referenced_at,
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
        p2.title,
        p2.url,
        p2.state,
        p2.merged,
        p2.merged_at
      FROM issue_pr_links l2
        LEFT JOIN pull_request_fixes p2 ON p2.pr_repository_name_with_owner=l2.pr_repository_name_with_owner AND p2.pr_number=l2.pr_number
      WHERE l2.issue_number=i.number
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
SELECT published_at FROM releases WHERE tag=?
`);

const crossReleaseTerminalProofRowsStmt = db.prepare(`
SELECT p.release_tag, p.status, p.summary, p.evidence_json, r.published_at
FROM issue_closure_proofs p
LEFT JOIN releases r ON r.tag=p.release_tag
WHERE p.issue_number=?
  AND p.release_tag!=?
ORDER BY r.published_at IS NULL, r.published_at DESC, p.release_tag DESC
`);

const laterStableReleaseTagsStmt = db.prepare(`
SELECT later.tag
FROM releases source
JOIN releases later
  ON later.prerelease=0
 AND later.published_at > source.published_at
WHERE source.tag=?
ORDER BY later.published_at ASC
`);

const latestStableReleaseStmt = db.prepare(`
SELECT tag, published_at
FROM releases
WHERE prerelease=0
ORDER BY published_at DESC
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
WHERE source.tag=?
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

export async function analyzeClosureProofsForRelease(
  releaseTag: string,
  options: AnalyzeClosureProofOptions = {},
): Promise<ClosureProofAnalysisResult> {
  const persistScoreAuditPayload = options.persistScoreAuditPayload ?? true;
  const refreshCommentPrMentions = options.refreshCommentPrMentionEvidence ?? true;
  const analysisStartedAt = new Date().toISOString();
  const release = getRelease(releaseTag);
  const labelCutoff = release ? releaseLabelCutoff(release, analysisStartedAt) : null;
  const closedRows = closedIssueRowsStmt.all(releaseTag) as Array<{ number: number }>;
  const issueNumbers = closedRows.map((row) => row.number);
  const sourceIssueNumbers = new Set(issueNumbers);
  const sourceAggregateRows = issueNumbers.length
    ? aggregateRowsStmt.all(JSON.stringify(issueNumbers), releaseTag) as Array<any>
    : [];
  const commentsByIssue = await listIssueCommentsBatch(issueNumbers);
  persistCommentSnapshots(commentsByIssue);
  const allCommentsByIssue = new Map(commentsByIssue);
  const canonicalIssueNumbers = new Set<number>();
  const canonicalGraph = new Map<number, number[]>();
  const sourceClosedAtByIssue = new Map(sourceAggregateRows.map((row: any) => [Number(row.number), row.closed_at as string | null]));
  for (const issueNumber of issueNumbers) {
    const closureContextComments = closureRationaleComments(commentsByIssue.get(issueNumber) ?? [], sourceClosedAtByIssue.get(issueNumber));
    const numbers = canonicalIssueNumbersFromComments(closureContextComments, issueNumber, knownIssueNumber);
    canonicalGraph.set(issueNumber, numbers);
    for (const number of numbers) canonicalIssueNumbers.add(number);
  }
  await expandCanonicalGraph(canonicalGraph, allCommentsByIssue, [...canonicalIssueNumbers]);
  const terminalCanonicalIssuesToBackfill = terminalCanonicalIssuesNeedingEvidence(releaseTag, issueNumbers, canonicalGraph);
  if (terminalCanonicalIssuesToBackfill.length) {
    await refreshRawClosureEvidence(terminalCanonicalIssuesToBackfill);
    await checkReleasePrReachability(releaseTag);
    const missingComments = terminalCanonicalIssuesToBackfill.filter((number) => !allCommentsByIssue.has(number));
    if (missingComments.length) {
      const fetched = await listIssueCommentsBatch(missingComments);
      persistCommentSnapshots(fetched);
      for (const number of missingComments) allCommentsByIssue.set(number, fetched.get(number) ?? []);
    }
  }
  const analysisIssueNumbers = uniqueNumbers([...issueNumbers, ...terminalCanonicalIssuesToBackfill]);
  if (refreshCommentPrMentions) {
    await refreshClosureCommentPrMentionEvidence(analysisIssueNumbers, allCommentsByIssue);
  }
  await checkReleasePrReachability(releaseTag);
  const rawEvidence = rawClosureEvidenceCounts(issueNumbers);
  const aggregateRows = analysisIssueNumbers.length
    ? aggregateRowsStmt.all(JSON.stringify(analysisIssueNumbers), releaseTag) as Array<any>
    : [];
  const aggregateByIssue = new Map(aggregateRows.map((row: any) => [Number(row.number), row]));
  const closedAtByIssue = new Map(aggregateRows.map((row: any) => [Number(row.number), row.closed_at as string | null]));
  const closureContextCommentsByIssue = new Map<number, GhComment[]>();
  for (const issueNumber of analysisIssueNumbers) {
    closureContextCommentsByIssue.set(
      issueNumber,
      closureRationaleComments(allCommentsByIssue.get(issueNumber) ?? [], closedAtByIssue.get(issueNumber)),
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
    );
    const canonicalMentions = canonicalIssueNumbersReachableFrom(issueNumber, canonicalGraph).flatMap((canonicalIssueNumber) =>
      closureCommentCommitMentions(
        issueNumber,
        allCommentsByIssue.get(canonicalIssueNumber) ?? [],
        canonicalIssueNumber,
        resolveCommitOidPrefix,
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
  const commitReachability = await checkReleaseCommitReachability(releaseTag, [...allCommitOids]);
  const laterCommitReachability = await laterReachableReleaseByCommit(releaseTag, commitReachability);
  const preparedRows: Array<{
    issueNumber: number;
    result: ClosureProofResult;
    evidence: Record<string, unknown>;
  }> = [];

  for (const row of aggregateRows) {
    const comments = (allCommentsByIssue.get(row.number) ?? []).map((comment) => ({
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
    const closureCommitMentions = directClosureCommitMentions(row.number, row.direct_closer_commits, row.closed_at);
    const directCommitProof = commitProofEvidence([
      ...directMentions,
      ...(useReferencedCommitProofIssues.has(row.number) ? referencedCommitMentionsByIssue.get(row.number) ?? [] : []),
      ...closureCommitMentions,
    ], commitReachability);
    const canonicalCommitProof = commitProofEvidence(
      canonicalCommitMentionsByIssue.get(row.number) ?? [],
      commitReachability,
    );
    const commitProof = directCommitProof;
    const reachableFixCommits = unique(commitProof.filter((item) => item.status === 'reachable').map((item) => item.commitOid));
    const notReachableFixCommits = unique(commitProof.filter((item) => item.status === 'not_reachable').map((item) => item.commitOid));
    const closureClassification = effectiveClosureProofClassification(row, labelCutoff);
    const result = closureClassification.missingClassification
      ? missingClassificationClosureProof(row)
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
        hasReachableFixCommit: reachableFixCommits.length > 0,
        hasNotReachableFixCommit: notReachableFixCommits.length > 0,
        reachableFixCommits,
        notReachableFixCommits,
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
      referencedCommitContext: referencedCommitMentionsByIssue.get(row.number) ?? [],
      canonicalFixCommitProofCount: canonicalCommitMentionsByIssue.get(row.number)?.length ?? 0,
      canonicalIssueDetails: canonicalIssueDetails(row.number, (result.evidence.canonicalIssues ?? []) as number[]),
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
    const canonicalIssues = Array.isArray(item.evidence.canonicalIssues)
      ? (item.evidence.canonicalIssues as unknown[])
        .filter((n): n is number => typeof n === 'number' && knownIssueNumber(n))
      : [];
    canonicalGraph.set(item.issueNumber, canonicalIssues);
  }
  const resultByIssue = new Map(preparedRows.map((item) => [item.issueNumber, item.result]));

  const proofRows = preparedRows.filter((item) => sourceIssueNumbers.has(item.issueNumber)).map((item) => {
    const adjusted = adjustCanonicalDuplicateStatus(item.issueNumber, item.result, item.evidence, canonicalGraph, resultByIssue, releaseTag);
    return {
      release_tag: releaseTag,
      issue_number: item.issueNumber,
      status: adjusted.status,
      summary: adjusted.summary,
      evidence_json: JSON.stringify(adjusted.evidence),
    };
  });
  const counts = new Map<string, number>();
  for (const row of proofRows) {
    counts.set(row.status, (counts.get(row.status) ?? 0) + 1);
  }

  runInWriteTransaction(() => {
    deleteIssueClosureProofsForRelease(releaseTag);
    for (const row of proofRows) upsertIssueClosureProof(row);
    if (persistScoreAuditPayload) persistClosureProofInScoreAudit(releaseTag);
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
}> {
  return mentions.map((mention) => {
    const result = reachability.get(mention.commitOid);
    return {
      ...mention,
      status: result?.status ?? 'unknown',
      tagCommitOid: result?.tagCommitOid ?? null,
      evidence: result?.evidence ?? 'reachability_not_checked',
    };
  });
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
): {
  labels: string[];
  currentLabels: string[];
  labelCutoffAt: string | null;
  labelSource: 'current' | 'timeline' | 'snapshot' | 'missing_timeline';
  labelTimelineEventCount: number;
  labelSnapshotCount: number;
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
  const labels = Number.isInteger(issueNumber) && issueNumber > 0
    ? labelResolver(issueNumber, currentLabels, labelCutoff, {
      useFallbackWhenNoEvents: labelCutoff == null,
      useSnapshotWhenNoEvents: labelCutoff != null,
    })
    : currentLabels;
  const labelSource = closureProofLabelSource(labelCutoff, labelTimelineEventCount, labelSnapshotCount);
  const labelEvidence = {
    labels,
    currentLabels,
    labelCutoffAt: labelCutoff,
    labelSource,
    labelTimelineEventCount,
    labelSnapshotCount,
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
      ),
      row.title ?? '',
      labels,
    ),
    row.title ?? '',
    labels,
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

function missingClassificationClosureProof(row: any): ClosureProofResult {
  return {
    status: 'unknown',
    summary: 'Closed issue lacks current classification evidence; release-fix credit is withheld until classification backfill succeeds.',
    evidence: {
      missingClassification: true,
      classificationIssueNumber: row.classification_issue_number ?? null,
      classificationPromptVersion: row.classification_prompt_version ?? null,
    },
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

function persistCommentSnapshots(commentsByIssue: Map<number, GhComment[]>): void {
  if (commentsByIssue.size === 0) return;
  runInWriteTransaction(() => {
    for (const [issueNumber, comments] of commentsByIssue) {
      upsertIssueCommentSnapshot({
        issue_number: issueNumber,
        comment_count: comments.length,
        fetched_comment_count: comments.length,
        latest_comment_updated_at: latestCommentUpdatedAt(comments),
        comments_digest: commentDigest(comments),
      });
    }
  });
}

function latestCommentUpdatedAt(comments: GhComment[]): string | null {
  return comments
    .map((comment) => comment.updated_at ?? comment.created_at ?? null)
    .filter((value): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

function commentDigest(comments: GhComment[]): string {
  const hash = createHash('sha256');
  hash.update(JSON.stringify(comments
    .map((comment) => ({
      id: comment.id,
      author: comment.user?.login ?? null,
      association: comment.author_association ?? null,
      body: comment.body,
      createdAt: comment.created_at,
      updatedAt: comment.updated_at,
    }))
    .sort((a, b) => String(a.updatedAt ?? a.createdAt ?? '').localeCompare(String(b.updatedAt ?? b.createdAt ?? '')) ||
      Number(a.id ?? 0) - Number(b.id ?? 0))));
  return hash.digest('hex');
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
  fetchComments: (issueNumbers: number[]) => Promise<Map<number, GhComment[]>> = listIssueCommentsBatch,
  persistFetchedCommentSnapshots = true,
): Promise<void> {
  const parsed = new Set(canonicalGraph.keys());
  let frontier = uniqueNumbers(seedIssueNumbers.filter((number) => Number.isInteger(number)));
  for (let depth = 0; depth < 8 && frontier.length; depth++) {
    const missing = frontier.filter((number) => !commentsByIssue.has(number));
    if (missing.length) {
      const fetched = await fetchComments(missing);
      if (persistFetchedCommentSnapshots) persistCommentSnapshots(fetched);
      for (const number of missing) commentsByIssue.set(number, fetched.get(number) ?? []);
    }
    const nextFrontier: number[] = [];
    for (const issueNumber of frontier) {
      if (parsed.has(issueNumber)) continue;
      parsed.add(issueNumber);
      const targets = canonicalIssueNumbersFromComments(
        commentsByIssue.get(issueNumber) ?? [],
        issueNumber,
        knownIssueNumber,
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
  const path = canonicalResolution(sourceIssueNumber, graph).path;
  return uniqueNumbers(path.slice(1).filter((number) => number !== sourceIssueNumber));
}

function terminalCanonicalIssuesNeedingEvidence(
  releaseTag: string,
  sourceIssueNumbers: number[],
  canonicalGraph: Map<number, number[]>,
  issueDetailsLookup = issueDetails,
  terminalProofLookup = crossReleaseTerminalProofForIssue,
): number[] {
  const sourceSet = new Set(sourceIssueNumbers);
  const terminals = new Set<number>();
  for (const issueNumber of sourceIssueNumbers) {
    const resolution = canonicalResolution(issueNumber, canonicalGraph);
    const terminalNumber = resolution.terminalIssue?.number;
    if (!terminalNumber || sourceSet.has(terminalNumber)) continue;
    const terminalIssue = issueDetailsLookup(terminalNumber);
    if (terminalIssue?.state !== 'closed') continue;
    if (terminalProofLookup(releaseTag, terminalNumber)) continue;
    terminals.add(terminalNumber);
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
): ClosureProofResult {
  const nonBugDuplicate = result.status === 'non_bug_duplicate_or_superseded';
  if (result.status !== 'duplicate_or_superseded' && !nonBugDuplicate) return { ...result, evidence };
  const resolution = canonicalResolution(sourceIssueNumber, canonicalGraph);
  const currentWindowTerminalProof = resolution.terminalIssue?.number == null
    ? null
    : resultByIssue.get(resolution.terminalIssue.number) ?? null;
  const crossReleaseTerminalProof = (!currentWindowTerminalProof || currentWindowTerminalProof.status === 'no_timeline_event' || currentWindowTerminalProof.status === 'unknown') &&
    sourceReleaseTag &&
    resolution.terminalIssue?.number != null
    ? terminalProofLookup(sourceReleaseTag, resolution.terminalIssue.number)
    : null;
  const terminalProof = currentWindowTerminalProof ?? crossReleaseTerminalProof;
  const canonicalFixCommitProof = Array.isArray(evidence.canonicalFixCommitProof)
    ? evidence.canonicalFixCommitProof
    : [];
  const hasReachableCanonicalFixCommit = canonicalFixCommitProof.some((item: any) => item?.status === 'reachable');
  const hasNotReachableCanonicalFixCommit = canonicalFixCommitProof.some((item: any) => item?.status === 'not_reachable');
  const nextEvidence = {
    ...evidence,
    canonicalResolution: terminalProof
      ? {
        ...resolution,
        terminalProof: terminalProofEvidence(terminalProof),
      }
      : resolution,
  };
  if ((currentWindowTerminalProof?.status === 'fixed_in_release') || hasReachableCanonicalFixCommit) {
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_to_fixed_in_release' : 'duplicate_to_fixed_in_release',
      summary: hasReachableCanonicalFixCommit
        ? `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical fix/source commit is reachable from this release tag.`
        : `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical issue was fixed in this release tag.`,
      evidence: nextEvidence,
    };
  }
  const reachableTrustedFixProofPrs = trustedReachableFixProofPrs(nextEvidence);
  if (!nonBugDuplicate && reachableTrustedFixProofPrs.length > 0) {
    return {
      status: 'duplicate_with_release_fix_proof',
      summary: 'Closed as duplicate/superseded, but trusted closure-comment fix proof is reachable from this release tag; this resolves closure risk without direct GitHub fix-credit.',
      evidence: { ...nextEvidence, reachableTrustedFixProofPrs },
    };
  }
  if (
    currentWindowTerminalProof?.status === 'fixed_after_release' ||
    hasNotReachableCanonicalFixCommit ||
    (crossReleaseTerminalProof?.timing === 'after' && isTerminalFixProof(crossReleaseTerminalProof.status))
  ) {
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_to_fixed_after_release' : 'duplicate_to_fixed_after_release',
      summary: crossReleaseTerminalProof?.timing === 'after' && isTerminalFixProof(crossReleaseTerminalProof.status)
        ? `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical issue has terminal fix proof in a later release audit.`
        : hasNotReachableCanonicalFixCommit
        ? `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical fix/source commit is not reachable from this release tag.`
        : `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical issue was fixed after this release tag.`,
      evidence: nextEvidence,
    };
  }
  const openCycleTerminalIssue = resolution.cycle || resolution.selfReference
    ? openIssueInCanonicalPath(sourceIssueNumber, resolution)
    : null;
  if (resolution.terminalIssue?.state === 'open' || openCycleTerminalIssue) {
    const canonicalResolution = {
      ...(nextEvidence.canonicalResolution as Record<string, unknown>),
      ...(openCycleTerminalIssue ? { terminalIssue: openCycleTerminalIssue, cycleTerminalIssue: openCycleTerminalIssue } : {}),
    };
    return {
      status: nonBugDuplicate ? 'non_bug_duplicate_to_open_canonical' : 'duplicate_to_open_canonical',
      summary: `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical issue remains open.`,
      evidence: { ...nextEvidence, canonicalResolution },
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
  if (resolution.terminalIssue?.state === 'closed') {
    if (!terminalProof || terminalProof.status === 'no_timeline_event' || terminalProof.status === 'unknown') {
      return {
        status: nonBugDuplicate ? 'non_bug_duplicate_to_closed_canonical_missing_proof' : 'duplicate_to_closed_canonical_missing_proof',
        summary: terminalProof
          ? `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical issue is closed, but canonical closure proof is missing or incomplete.`
          : `${nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded'}; canonical issue is closed, but no canonical closure proof was available for this release audit.`,
        evidence: nextEvidence,
      };
    }
    return closedCanonicalRollup(nonBugDuplicate, terminalProof, nextEvidence);
  }
  if (resolution.cycle || resolution.selfReference) {
    return {
      status: 'canonical_cycle_or_self_reference',
      summary: 'Closed as duplicate/superseded, but canonical reference loops back to the same issue.',
      evidence: nextEvidence,
    };
  }
  return { ...result, evidence: nextEvidence };
}

function duplicateRelatedPrContextStatus(
  nonBugDuplicate: boolean,
  context: RelatedPrContext,
  evidence: Record<string, unknown>,
): ClosureProofResult | null {
  const prefix = nonBugDuplicate ? 'Non-negative item closed as duplicate/superseded' : 'Closed as duplicate/superseded';
  const reachableTrustedFixProofPrs = trustedReachableFixProofPrs(evidence);
  if (!nonBugDuplicate && reachableTrustedFixProofPrs.length > 0) {
    return {
      status: 'duplicate_with_release_fix_proof',
      summary: `${prefix}; trusted closure-comment fix proof is reachable from this release tag, resolving closure risk without direct GitHub fix-credit.`,
      evidence: { ...evidence, reachableTrustedFixProofPrs },
    };
  }
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

function openIssueInCanonicalPath(
  sourceIssueNumber: number,
  resolution: ReturnType<typeof canonicalResolution>,
): { number: number; title: string | null; state: string | null; url: string | null } | null {
  for (const number of uniqueNumbers(resolution.path.filter((item) => item !== sourceIssueNumber))) {
    const issue = issueDetails(number);
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
  const candidates = rows
    .map((row) => {
      const timing = releaseTiming(sourcePublishedAt, row.published_at);
      return {
        status: row.status,
        summary: row.summary,
        evidence: parseEvidenceObject(row.evidence_json),
        releaseTag: row.release_tag,
        timing,
        sourceReleasePublishedAt: sourcePublishedAt,
        terminalReleasePublishedAt: row.published_at,
        crossRelease: true,
        priority: terminalProofPriority(row.status, timing),
      };
    })
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
    const reachability = await checkReleaseCommitReachability(release.tag, pending);
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
  const linkedPrs = Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs : [];
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
  const linkedPrs = Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs as Array<Record<string, unknown>> : [];
  return linkedPrs.filter((pr) => {
    const source = String(pr.source ?? '');
    return Number(pr.willCloseTarget ?? 0) === 1 ||
      source === 'closedByPullRequestsReferences' ||
      source === 'ClosedEvent.closer';
  });
}

function adjustNotPlannedEvidenceStatus(
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
): ClosureProofResult {
  if (!isAdminNotPlannedRiskStatus(result.status)) return result;
  const linkedPrs = Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs as Array<Record<string, unknown>> : [];
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
    externalClosing: Array.isArray(context.externalClosing) ? context.externalClosing as Array<Record<string, unknown>> : [],
    open: Array.isArray(context.open) ? context.open as Array<Record<string, unknown>> : [],
    closedUnmerged: Array.isArray(context.closedUnmerged) ? context.closedUnmerged as Array<Record<string, unknown>> : [],
    notReachable: Array.isArray(context.notReachable) ? context.notReachable as Array<Record<string, unknown>> : [],
    reachable: Array.isArray(context.reachable) ? context.reachable as Array<Record<string, unknown>> : [],
    unknownReachability: Array.isArray(context.unknownReachability) ? context.unknownReachability as Array<Record<string, unknown>> : [],
  };
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
  const linkedPrs = Array.isArray(evidence.linkedPrs)
    ? [...evidence.linkedPrs as Array<Record<string, unknown>>].sort(compareLinkedPrEvidencePriority)
    : [];
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

function canonicalResolution(
  sourceIssueNumber: number,
  graph: Map<number, number[]>,
): {
  path: number[];
  terminalIssue: { number: number; title: string | null; state: string | null; url: string | null } | null;
  cycle: boolean;
  selfReference: boolean;
} {
  const path = [sourceIssueNumber];
  const seen = new Set(path);
  let current = sourceIssueNumber;
  let selfReference = false;
  for (let depth = 0; depth < 8; depth++) {
    const targets = (graph.get(current) ?? []).filter((number) => Number.isInteger(number));
    const next = targets.find((number) => number !== current);
    if (!next) {
      selfReference = targets.includes(current);
      break;
    }
    if (seen.has(next)) {
      path.push(next);
      return { path, terminalIssue: issueDetails(next), cycle: true, selfReference: next === sourceIssueNumber };
    }
    path.push(next);
    seen.add(next);
    current = next;
  }
  return {
    path,
    terminalIssue: path.length > 1 ? issueDetails(path[path.length - 1]) : null,
    cycle: false,
    selfReference,
  };
}

export const __closureProofAnalysisTest = {
  adjustClosureProofStatus,
  adjustCanonicalDuplicateStatus,
  adjustNotPlannedEvidenceStatus,
  adjustNoReleaseFixProofStatus,
  canonicalIssueNumbersFromText,
  canonicalIssueNumbersFromComments,
  effectiveClosureProofClassification,
  enrichLinkedPrReachability,
  commitReferenceMentionsFromRows,
  shouldUseReferencedCommitProof,
  compareLinkedPrEvidencePriority,
  expandCanonicalGraph,
  canonicalIssueNumbersReachableFrom,
  terminalCanonicalIssuesNeedingEvidence,
  missingClassificationClosureProof,
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

export async function refreshClosureEvidenceForRelease(releaseTag: string): Promise<ClosureProofAnalysisResult['rawEvidence'] & {
  issueCount: number;
}> {
  const rows = allClosedIssueRowsStmt.all(releaseTag) as Array<{ number: number }>;
  const issueNumbers = rows.map((row) => row.number);
  const rawEvidence = await refreshRawClosureEvidence(issueNumbers);
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

async function refreshRawClosureEvidence(issueNumbers: number[]): Promise<ClosureProofAnalysisResult['rawEvidence']> {
  let closureEvents = 0;
  let reopenEvents = 0;
  let prLinks = 0;
  let pullRequests = 0;
  let commitReferences = 0;
  for (let offset = 0; offset < issueNumbers.length; offset += 20) {
    const chunk = issueNumbers.slice(offset, offset + 20);
    const [evidence, commentsByIssue] = await Promise.all([
      listIssueFixEvidenceBatch(chunk),
      listIssueCommentsBatch(chunk),
    ]);
    persistCommentSnapshots(commentsByIssue);
    const commentMentions = chunk.flatMap((issueNumber) =>
      closureCommentPrMentions(issueNumber, commentsByIssue.get(issueNumber) ?? []),
    );
    const mentionedPrs = await listPullRequestFixesBatch(commentMentions.map((mention) => ({
      prNumber: mention.prNumber,
      prRepositoryOwner: mention.prRepositoryOwner,
      prRepositoryName: mention.prRepositoryName,
      prRepositoryNameWithOwner: mention.prRepositoryNameWithOwner,
    })));
    runInWriteTransaction(() => {
      deleteIssuePrLinksForIssues(chunk);
      for (const item of evidence.values()) {
        for (const event of item.closureEvents) {
          upsertIssueClosureEvent({
            issue_number: event.issueNumber,
            event_id: event.eventId,
            closed_at: event.closedAt,
            actor_login: event.actorLogin,
            state_reason: event.stateReason,
            closer_type: event.closerType,
            closer_number: event.closerNumber,
            closer_oid: event.closerOid,
            raw_json: JSON.stringify(event.raw),
          });
          closureEvents++;
        }
        for (const event of item.reopenEvents) {
          upsertIssueReopenEvent({
            issue_number: event.issueNumber,
            event_id: event.eventId,
            reopened_at: event.reopenedAt,
            actor_login: event.actorLogin,
            raw_json: JSON.stringify(event.raw),
          });
          reopenEvents++;
        }
        for (const link of item.prLinks) {
          upsertIssuePrLink({
            issue_number: link.issueNumber,
            pr_repository_owner: link.prRepositoryOwner,
            pr_repository_name: link.prRepositoryName,
            pr_repository_name_with_owner: link.prRepositoryNameWithOwner,
            pr_number: link.prNumber,
            source: link.source,
            will_close_target: link.willCloseTarget == null ? null : link.willCloseTarget ? 1 : 0,
            referenced_at: link.referencedAt,
          });
          prLinks++;
        }
        for (const ref of item.commitReferences) {
          upsertIssueCommitReference({
            issue_number: ref.issueNumber,
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
          commitReferences++;
        }
        for (const pr of item.pullRequests) {
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
          pullRequests++;
        }
      }
      for (const mention of commentMentions) {
        const pr = mentionedPrs.get(pullRequestKey(mention.prRepositoryNameWithOwner, mention.prNumber));
        if (!pr) continue;
        upsertIssuePrLink({
          issue_number: mention.issueNumber,
          pr_repository_owner: mention.prRepositoryOwner,
          pr_repository_name: mention.prRepositoryName,
          pr_repository_name_with_owner: mention.prRepositoryNameWithOwner,
          pr_number: mention.prNumber,
          source: mention.source,
          will_close_target: null,
          referenced_at: mention.referencedAt,
        });
        prLinks++;
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
        pullRequests++;
      }
    });
  }
  return { closureEvents, reopenEvents, prLinks, pullRequests, commitReferences };
}

async function refreshClosureCommentPrMentionEvidence(
  issueNumbers: number[],
  commentsByIssue: Map<number, GhComment[]>,
): Promise<void> {
  const commentMentions = issueNumbers.flatMap((issueNumber) =>
    closureCommentPrMentions(issueNumber, commentsByIssue.get(issueNumber) ?? []),
  );
  const mentionedPrs = await listPullRequestFixesBatch(commentMentions.map((mention) => ({
    prNumber: mention.prNumber,
    prRepositoryOwner: mention.prRepositoryOwner,
    prRepositoryName: mention.prRepositoryName,
    prRepositoryNameWithOwner: mention.prRepositoryNameWithOwner,
  })));
  runInWriteTransaction(() => {
    deleteCommentIssuePrLinksForIssues(issueNumbers);
    for (const mention of commentMentions) {
      const pr = mentionedPrs.get(pullRequestKey(mention.prRepositoryNameWithOwner, mention.prNumber));
      if (!pr) continue;
      upsertIssuePrLink({
        issue_number: mention.issueNumber,
        pr_repository_owner: mention.prRepositoryOwner,
        pr_repository_name: mention.prRepositoryName,
        pr_repository_name_with_owner: mention.prRepositoryNameWithOwner,
        pr_number: mention.prNumber,
        source: mention.source,
        will_close_target: null,
        referenced_at: mention.referencedAt,
      });
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
  const linkedPrs = Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs : [];
  const openPrs = linkedPrs
    .filter((item): item is Record<string, unknown> => {
      if (!item || typeof item !== 'object') return false;
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
