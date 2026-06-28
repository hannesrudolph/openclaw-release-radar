import { config } from '../config';
import { db, deleteIssueClosureProofsForRelease, upsertIssueClosureEvent, upsertIssueClosureProof, upsertIssueCommitReference, upsertIssuePrLink, upsertIssueReopenEvent, upsertPullRequestFix } from './db';
import { classifyClosureProof, closureRationaleComments, type ClosureProofResult, type ClosureProofStatus } from './closureProof';
import { creditedFixLinkSql } from './fixProvenance';
import { closureCommentCommitMentions, closureCommentPrMentions, listIssueCommentsBatch, listIssueFixEvidenceBatch, listPullRequestFixesBatch, type ClosureCommentCommitMention, type GhComment } from './github';
import { persistClosureProofInScoreAudit } from './closureProofPayload';
import { checkReleaseCommitReachability, type CommitReachability } from './releaseReachability';

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

const closedIssueRowsStmt = db.prepare(`
WITH target AS (
  SELECT * FROM releases WHERE tag=?
)
SELECT DISTINCT
  i.number,
  i.title,
  i.closed_at,
  c.sentiment
FROM issues i
JOIN classifications c ON c.issue_number=i.number
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
JOIN classifications c ON c.issue_number=i.number
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
  i.closed_at,
  c.sentiment,
  GROUP_CONCAT(DISTINCT e.state_reason) AS state_reasons,
  GROUP_CONCAT(DISTINCT e.actor_login) AS closure_actors,
  GROUP_CONCAT(DISTINCT e.closed_at) AS closure_event_closed_at,
  COUNT(DISTINCT e.event_id) AS closure_events,
  COUNT(DISTINCT CASE
    WHEN e.state_reason='COMPLETED'
     AND ${creditedFixLinkSql('l')}
    THEN l.pr_number END
  ) AS closing_links,
  COUNT(DISTINCT CASE
    WHEN e.state_reason='COMPLETED'
     AND ${creditedFixLinkSql('l')}
     AND p.merged=1
    THEN p.pr_number END
  ) AS merged_closing_prs,
  COUNT(DISTINCT CASE
    WHEN e.state_reason='COMPLETED'
     AND ${creditedFixLinkSql('l')}
     AND p.merged=1
     AND rpr.status='reachable'
    THEN p.pr_number END
  ) AS reachable_closing_prs,
  COUNT(DISTINCT CASE
    WHEN e.state_reason='COMPLETED'
     AND ${creditedFixLinkSql('l')}
     AND p.merged=1
     AND rpr.status='not_reachable'
    THEN p.pr_number END
  ) AS not_reachable_closing_prs,
  GROUP_CONCAT(DISTINCT CASE
    WHEN e.state_reason='COMPLETED'
     AND ${creditedFixLinkSql('l')}
    THEN p.pr_number || ':' || COALESCE(p.title, '')
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
      LEFT JOIN pull_request_fixes p2 ON p2.pr_number=l2.pr_number
      WHERE l2.issue_number=i.number
      ORDER BY CASE WHEN p2.state='OPEN' AND p2.merged=0 THEN 0 ELSE 1 END, l2.pr_number
    ) linked
  ) AS linked_prs_json
FROM selected
JOIN issues i ON i.number=selected.issue_number
LEFT JOIN classifications c ON c.issue_number=i.number
LEFT JOIN window_closure e ON e.issue_number=i.number
LEFT JOIN issue_pr_links l ON l.issue_number=i.number
LEFT JOIN pull_request_fixes p ON p.pr_number=l.pr_number
LEFT JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_number=l.pr_number
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

export async function analyzeClosureProofsForRelease(releaseTag: string): Promise<ClosureProofAnalysisResult> {
  const closedRows = closedIssueRowsStmt.all(releaseTag) as Array<{ number: number }>;
  const issueNumbers = closedRows.map((row) => row.number);
  const rawEvidence = rawClosureEvidenceCounts(issueNumbers);
  const aggregateRows = issueNumbers.length
    ? aggregateRowsStmt.all(JSON.stringify(issueNumbers), releaseTag) as Array<any>
    : [];
  const aggregateByIssue = new Map(aggregateRows.map((row: any) => [Number(row.number), row]));
  const commentsByIssue = await listIssueCommentsBatch(issueNumbers);
  const allCommentsByIssue = new Map(commentsByIssue);
  const canonicalIssueNumbers = new Set<number>();
  const canonicalGraph = new Map<number, number[]>();
  const closedAtByIssue = new Map(aggregateRows.map((row: any) => [Number(row.number), row.closed_at as string | null]));
  for (const issueNumber of issueNumbers) {
    const numbers = canonicalIssueNumbersFromComments(
      closureRationaleComments(commentsByIssue.get(issueNumber) ?? [], closedAtByIssue.get(issueNumber)),
      issueNumber,
    );
    canonicalGraph.set(issueNumber, numbers);
    for (const number of numbers) canonicalIssueNumbers.add(number);
  }
  await expandCanonicalGraph(canonicalGraph, allCommentsByIssue, [...canonicalIssueNumbers]);
  const commitMentionsByIssue = new Map<number, ClosureCommentCommitMention[]>();
  const canonicalCommitMentionsByIssue = new Map<number, ClosureCommentCommitMention[]>();
  const referencedCommitMentionsByIssue = commitReferenceMentionsByIssue(issueNumbers);
  const useReferencedCommitProofIssues = new Set<number>();
  const allCommitOids = new Set<string>();
  for (const issueNumber of issueNumbers) {
    const directMentions = closureCommentCommitMentions(issueNumber, commentsByIssue.get(issueNumber) ?? []);
    const canonicalMentions = canonicalIssueNumbersReachableFrom(issueNumber, canonicalGraph).flatMap((canonicalIssueNumber) =>
        closureCommentCommitMentions(
          issueNumber,
          allCommentsByIssue.get(canonicalIssueNumber) ?? [],
          canonicalIssueNumber,
        ),
    );
    const mentions = [...directMentions, ...canonicalMentions];
    commitMentionsByIssue.set(issueNumber, mentions);
    canonicalCommitMentionsByIssue.set(issueNumber, canonicalMentions);
    for (const mention of mentions) allCommitOids.add(mention.commitOid);
    const row = aggregateByIssue.get(issueNumber);
    const hasMergedClosingPr = Number(row?.merged_closing_prs ?? 0) > 0;
    const hasDirectClosureCommit = splitCsv(row?.direct_closer_commits).some((commitOid) => fullCommitOidRe.test(commitOid));
    if (directMentions.length === 0 && !hasMergedClosingPr && !hasDirectClosureCommit) {
      useReferencedCommitProofIssues.add(issueNumber);
      for (const mention of referencedCommitMentionsByIssue.get(issueNumber) ?? []) allCommitOids.add(mention.commitOid);
    }
  }
  for (const row of aggregateRows) {
    for (const commitOid of splitCsv(row.direct_closer_commits)) {
      if (fullCommitOidRe.test(commitOid)) allCommitOids.add(commitOid.toLowerCase());
    }
  }
  const commitReachability = await checkReleaseCommitReachability(releaseTag, [...allCommitOids]);
  const counts = new Map<string, number>();
  deleteIssueClosureProofsForRelease(releaseTag);
  const preparedRows: Array<{
    issueNumber: number;
    result: ClosureProofResult;
    evidence: Record<string, unknown>;
  }> = [];

  for (const row of aggregateRows) {
    const comments = (commentsByIssue.get(row.number) ?? []).map((comment) => ({
      author: comment.user?.login ?? null,
      body: comment.body,
      createdAt: comment.created_at,
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
    const result = classifyClosureProof({
      issueNumber: row.number,
      issueAuthor: row.author,
      closedAt: row.closed_at,
      sentiment: row.sentiment,
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
    const evidence: Record<string, unknown> = {
      ...result.evidence,
      title: row.title,
      closedAt: row.closed_at,
      closureEventClosedAt: splitCsv(row.closure_event_closed_at),
      closingPrs: splitCsv(row.closing_prs),
      linkedPrs: parseJsonArray(row.linked_prs_json),
      fixCommitProof: commitProof,
      canonicalFixCommitProof: canonicalCommitProof,
      directFixCommitProof: directCommitProof,
      canonicalFixCommitProofCount: canonicalCommitMentionsByIssue.get(row.number)?.length ?? 0,
      canonicalIssueDetails: canonicalIssueDetails(row.number, (result.evidence.canonicalIssues ?? []) as number[]),
    };
    preparedRows.push({ issueNumber: row.number, result, evidence });
  }

  for (const item of preparedRows) {
    const canonicalIssues = Array.isArray(item.evidence.canonicalIssues)
      ? (item.evidence.canonicalIssues as unknown[]).filter((n): n is number => typeof n === 'number')
      : [];
    canonicalGraph.set(item.issueNumber, canonicalIssues);
  }
  const resultByIssue = new Map(preparedRows.map((item) => [item.issueNumber, item.result]));

  for (const item of preparedRows) {
    const adjusted = adjustCanonicalDuplicateStatus(item.issueNumber, item.result, item.evidence, canonicalGraph, resultByIssue);
    upsertIssueClosureProof({
      release_tag: releaseTag,
      issue_number: item.issueNumber,
      status: adjusted.status,
      summary: adjusted.summary,
      evidence_json: JSON.stringify(adjusted.evidence),
    });
    counts.set(adjusted.status, (counts.get(adjusted.status) ?? 0) + 1);
  }
  persistClosureProofInScoreAudit(releaseTag);

  return {
    releaseTag,
    analyzed: aggregateRows.length,
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

const fullCommitOidRe = /^[0-9a-f]{40}$/i;
const fixShapedCommitHeadlineRe = /\b(fix(?:e[sd])?|resolv(?:e[sd])?|repair(?:ed)?|patch(?:ed)?|address(?:ed)?)\b/i;

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

function canonicalIssueNumbersFromComments(comments: GhComment[], sourceIssueNumber: number): number[] {
  const numbers = new Set<number>();
  for (const comment of comments) {
    for (const number of canonicalIssueNumbersFromText(comment.body ?? '')) {
      if (number !== sourceIssueNumber) numbers.add(number);
    }
  }
  return [...numbers].sort((a, b) => a - b);
}

function canonicalIssueNumbersFromText(text: string): number[] {
  const numbers = new Set<number>();
  const canonicalReferenceRes = [
    /^\s*(?:\*\*)?(?:canonical|canonical path|root-cause tracker|root cause tracker)(?:\*\*)?\s*:\s*(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)/gim,
    /\b(?:canonical|root-cause|root cause)\s+(?:issue|tracker|report)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
    /\b(?:as\s+(?:a\s+)?)?(?:duplicate|dupe|superseded)\s+(?:of|by)\s+(?:the\s+)?(?:open\s+|closed\s+)?(?:canonical\s+)?(?:(?:issue|tracker|report)\s+)?(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
    /\b(?:tracked|centralized|consolidated)\s+(?:in|under|by)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
  ];
  for (const re of canonicalReferenceRes) {
    re.lastIndex = 0;
    for (const match of text.matchAll(re)) {
      const number = Number(match[1]);
      if (Number.isInteger(number) && number > 0) numbers.add(number);
    }
  }
  return [...numbers].sort((a, b) => a - b);
}

async function expandCanonicalGraph(
  canonicalGraph: Map<number, number[]>,
  commentsByIssue: Map<number, GhComment[]>,
  seedIssueNumbers: number[],
  fetchComments: (issueNumbers: number[]) => Promise<Map<number, GhComment[]>> = listIssueCommentsBatch,
): Promise<void> {
  const parsed = new Set(canonicalGraph.keys());
  let frontier = uniqueNumbers(seedIssueNumbers.filter((number) => Number.isInteger(number)));
  for (let depth = 0; depth < 8 && frontier.length; depth++) {
    const missing = frontier.filter((number) => !commentsByIssue.has(number));
    if (missing.length) {
      const fetched = await fetchComments(missing);
      for (const number of missing) commentsByIssue.set(number, fetched.get(number) ?? []);
    }
    const nextFrontier: number[] = [];
    for (const issueNumber of frontier) {
      if (parsed.has(issueNumber)) continue;
      parsed.add(issueNumber);
      const targets = canonicalIssueNumbersFromComments(commentsByIssue.get(issueNumber) ?? [], issueNumber);
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
  return path.slice(1);
}

function adjustCanonicalDuplicateStatus(
  sourceIssueNumber: number,
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
  canonicalGraph: Map<number, number[]>,
  resultByIssue: Map<number, ClosureProofResult> = new Map(),
): ClosureProofResult {
  if (result.status !== 'duplicate_or_superseded') return { ...result, evidence };
  const resolution = canonicalResolution(sourceIssueNumber, canonicalGraph);
  const terminalProof = resolution.terminalIssue?.number == null
    ? null
    : resultByIssue.get(resolution.terminalIssue.number) ?? null;
  const canonicalFixCommitProof = Array.isArray(evidence.canonicalFixCommitProof)
    ? evidence.canonicalFixCommitProof
    : [];
  const hasReachableCanonicalFixCommit = canonicalFixCommitProof.some((item: any) => item?.status === 'reachable');
  const hasNotReachableCanonicalFixCommit = canonicalFixCommitProof.some((item: any) => item?.status === 'not_reachable');
  const nextEvidence = {
    ...evidence,
    canonicalResolution: terminalProof
      ? { ...resolution, terminalProof: { status: terminalProof.status, summary: terminalProof.summary } }
      : resolution,
  };
  if (resolution.cycle || resolution.selfReference) {
    return {
      status: 'canonical_cycle_or_self_reference',
      summary: 'Closed as duplicate/superseded, but canonical reference loops back to the same issue.',
      evidence: nextEvidence,
    };
  }
  if (terminalProof?.status === 'fixed_in_release' || hasReachableCanonicalFixCommit) {
    return {
      status: 'duplicate_to_fixed_in_release',
      summary: hasReachableCanonicalFixCommit
        ? 'Closed as duplicate/superseded; canonical fix/source commit is reachable from this release tag.'
        : 'Closed as duplicate/superseded; canonical issue was fixed in this release tag.',
      evidence: nextEvidence,
    };
  }
  if (terminalProof?.status === 'fixed_after_release' || hasNotReachableCanonicalFixCommit) {
    return {
      status: 'duplicate_to_fixed_after_release',
      summary: hasNotReachableCanonicalFixCommit
        ? 'Closed as duplicate/superseded; canonical fix/source commit is not reachable from this release tag.'
        : 'Closed as duplicate/superseded; canonical issue was fixed after this release tag.',
      evidence: nextEvidence,
    };
  }
  if (resolution.terminalIssue?.state === 'open') {
    return {
      status: 'duplicate_to_open_canonical',
      summary: 'Closed as duplicate/superseded; canonical issue remains open.',
      evidence: nextEvidence,
    };
  }
  const prContext = openPrContext(evidence);
  if (prContext.canonical.length) {
    return {
      status: 'superseded_to_open_pr',
      summary: 'Closed as duplicate/superseded; trusted close-time context points to an open, unmerged PR.',
      evidence: { ...nextEvidence, canonicalOpenPrs: prContext.canonical },
    };
  }
  if (prContext.related.length) {
    return {
      status: 'duplicate_with_open_pr_context',
      summary: 'Closed as duplicate/superseded; related open PR references exist, but no trusted close-time note marks them as canonical.',
      evidence: { ...nextEvidence, relatedOpenPrs: prContext.related },
    };
  }
  if (resolution.terminalIssue?.state === 'closed') {
    return {
      status: 'duplicate_to_closed_canonical',
      summary: 'Closed as duplicate/superseded; canonical issue is also closed.',
      evidence: nextEvidence,
    };
  }
  return { ...result, evidence: nextEvidence };
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
  adjustCanonicalDuplicateStatus,
  canonicalIssueNumbersFromText,
  canonicalIssueNumbersFromComments,
  commitReferenceMentionsFromRows,
  expandCanonicalGraph,
  canonicalIssueNumbersReachableFrom,
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
      (SELECT COUNT(DISTINCT p.pr_number)
       FROM pull_request_fixes p
       JOIN issue_pr_links l ON l.pr_number=p.pr_number
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
    const commentMentions = chunk.flatMap((issueNumber) =>
      closureCommentPrMentions(issueNumber, commentsByIssue.get(issueNumber) ?? []),
    );
    const mentionedPrs = await listPullRequestFixesBatch(commentMentions.map((mention) => mention.prNumber));
    for (const mention of commentMentions) {
      const pr = mentionedPrs.get(mention.prNumber);
      if (!pr) continue;
      upsertIssuePrLink({
        issue_number: mention.issueNumber,
        pr_number: mention.prNumber,
        source: mention.source,
        will_close_target: null,
        referenced_at: mention.referencedAt,
      });
      prLinks++;
      upsertPullRequestFix({
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
  return { closureEvents, reopenEvents, prLinks, pullRequests, commitReferences };
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

function canonicalIssueDetails(sourceIssueNumber: number, numbers: number[]): Array<{
  number: number;
  title: string | null;
  state: string | null;
  url: string | null;
}> {
  const stmt = db.prepare(`SELECT number, title, state, html_url FROM issues WHERE number=?`);
  return numbers
    .filter((number) => number !== sourceIssueNumber)
    .map((number) => {
      const row = stmt.get(number) as { number: number; title: string; state: string; html_url: string | null } | undefined;
      return {
        number,
        title: row?.title ?? null,
        state: row?.state ?? null,
        url: row?.html_url ?? null,
      };
    });
}
