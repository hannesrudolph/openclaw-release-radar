import { db, deleteIssueClosureProofsForRelease, upsertIssueClosureEvent, upsertIssueClosureProof, upsertIssuePrLink, upsertPullRequestFix } from './db';
import { classifyClosureProof, type ClosureProofResult, type ClosureProofStatus } from './closureProof';
import { CLOSURE_COMMENT_FIX_PROOF_SOURCE, creditedFixLinkSql } from './fixProvenance';
import { closureCommentCommitMentions, closureCommentPrMentions, listIssueCommentsBatch, listIssueFixEvidenceBatch, listPullRequestFixesBatch, type ClosureCommentCommitMention, type GhComment } from './github';
import { persistClosureProofInScoreAudit } from './closureProofPayload';
import { checkReleaseCommitReachability, type CommitReachability } from './releaseReachability';

export interface ClosureProofAnalysisResult {
  releaseTag: string;
  analyzed: number;
  buckets: Record<string, number>;
  rawEvidence: {
    closureEvents: number;
    prLinks: number;
    pullRequests: number;
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
latest_closure AS (
  SELECT issue_number, MAX(closed_at) AS closed_at
  FROM issue_closure_events
  GROUP BY issue_number
),
final_closure AS (
  SELECT e.*
  FROM issue_closure_events e
  JOIN latest_closure latest
    ON latest.issue_number=e.issue_number
   AND latest.closed_at=e.closed_at
)
SELECT
  i.number,
  i.title,
  i.closed_at,
  c.sentiment,
  GROUP_CONCAT(DISTINCT e.state_reason) AS state_reasons,
  GROUP_CONCAT(DISTINCT e.actor_login) AS closure_actors,
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
  ) AS closing_prs
FROM selected
JOIN issues i ON i.number=selected.issue_number
LEFT JOIN classifications c ON c.issue_number=i.number
LEFT JOIN final_closure e ON e.issue_number=i.number
LEFT JOIN issue_pr_links l ON l.issue_number=i.number
LEFT JOIN pull_request_fixes p ON p.pr_number=l.pr_number
LEFT JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_number=l.pr_number
GROUP BY i.number
ORDER BY i.closed_at DESC
`);

export async function analyzeClosureProofsForRelease(releaseTag: string): Promise<ClosureProofAnalysisResult> {
  const closedRows = closedIssueRowsStmt.all(releaseTag) as Array<{ number: number }>;
  const issueNumbers = closedRows.map((row) => row.number);
  const rawEvidence = rawClosureEvidenceCounts(issueNumbers);
  const aggregateRows = issueNumbers.length
    ? aggregateRowsStmt.all(JSON.stringify(issueNumbers), releaseTag) as Array<any>
    : [];
  const commentsByIssue = await listIssueCommentsBatch(issueNumbers);
  const directCanonicalIssuesByIssue = new Map<number, number[]>();
  const canonicalIssueNumbers = new Set<number>();
  for (const issueNumber of issueNumbers) {
    const numbers = canonicalIssueNumbersFromComments(commentsByIssue.get(issueNumber) ?? [], issueNumber);
    directCanonicalIssuesByIssue.set(issueNumber, numbers);
    for (const number of numbers) canonicalIssueNumbers.add(number);
  }
  const canonicalCommentsByIssue = await listIssueCommentsBatch(
    [...canonicalIssueNumbers].filter((number) => !issueNumbers.includes(number)),
  );
  const commitMentionsByIssue = new Map<number, ClosureCommentCommitMention[]>();
  const allCommitOids = new Set<string>();
  for (const issueNumber of issueNumbers) {
    const mentions = [
      ...closureCommentCommitMentions(issueNumber, commentsByIssue.get(issueNumber) ?? []),
      ...(directCanonicalIssuesByIssue.get(issueNumber) ?? []).flatMap((canonicalIssueNumber) =>
        closureCommentCommitMentions(
          issueNumber,
          commentsByIssue.get(canonicalIssueNumber) ?? canonicalCommentsByIssue.get(canonicalIssueNumber) ?? [],
          canonicalIssueNumber,
        ),
      ),
    ];
    commitMentionsByIssue.set(issueNumber, mentions);
    for (const mention of mentions) allCommitOids.add(mention.commitOid);
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
    const commitProof = commitProofEvidence(commitMentionsByIssue.get(row.number) ?? [], commitReachability);
    const reachableFixCommits = unique(commitProof.filter((item) => item.status === 'reachable').map((item) => item.commitOid));
    const notReachableFixCommits = unique(commitProof.filter((item) => item.status === 'not_reachable').map((item) => item.commitOid));
    const result = classifyClosureProof({
      issueNumber: row.number,
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
      closingPrs: splitCsv(row.closing_prs),
      fixCommitProof: commitProof,
      canonicalIssueDetails: canonicalIssueDetails(row.number, (result.evidence.canonicalIssues ?? []) as number[]),
    };
    preparedRows.push({ issueNumber: row.number, result, evidence });
  }

  const canonicalGraph = new Map<number, number[]>();
  for (const item of preparedRows) {
    const canonicalIssues = Array.isArray(item.evidence.canonicalIssues)
      ? (item.evidence.canonicalIssues as unknown[]).filter((n): n is number => typeof n === 'number')
      : [];
    canonicalGraph.set(item.issueNumber, canonicalIssues);
  }

  for (const item of preparedRows) {
    const adjusted = adjustCanonicalDuplicateStatus(item.issueNumber, item.result, item.evidence, canonicalGraph);
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
  const canonicalLineRe = /^\s*(?:\*\*)?(?:canonical|root-cause tracker|root cause tracker)(?:\*\*)?\s*:\s*(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)/gim;
  for (const match of text.matchAll(canonicalLineRe)) {
    const number = Number(match[1]);
    if (Number.isInteger(number) && number > 0) numbers.add(number);
  }
  return [...numbers].sort((a, b) => a - b);
}

function adjustCanonicalDuplicateStatus(
  sourceIssueNumber: number,
  result: ClosureProofResult,
  evidence: Record<string, unknown>,
  canonicalGraph: Map<number, number[]>,
): ClosureProofResult {
  if (result.status !== 'duplicate_or_superseded') return { ...result, evidence };
  const resolution = canonicalResolution(sourceIssueNumber, canonicalGraph);
  const nextEvidence = { ...evidence, canonicalResolution: resolution };
  if (resolution.cycle || resolution.selfReference) {
    return {
      status: 'canonical_cycle_or_self_reference',
      summary: 'Closed as duplicate/superseded, but canonical reference loops back to the same issue.',
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
  if (!issueNumbers.length) return { closureEvents: 0, prLinks: 0, pullRequests: 0 };
  const selected = JSON.stringify(issueNumbers);
  const row = db.prepare(`
    WITH selected(issue_number) AS (
      SELECT value FROM json_each(?)
    )
    SELECT
      (SELECT COUNT(DISTINCT e.event_id)
       FROM issue_closure_events e
       JOIN selected s ON s.issue_number=e.issue_number) AS closureEvents,
      (SELECT COUNT(*)
       FROM issue_pr_links l
       JOIN selected s ON s.issue_number=l.issue_number) AS prLinks,
      (SELECT COUNT(DISTINCT p.pr_number)
       FROM pull_request_fixes p
       JOIN issue_pr_links l ON l.pr_number=p.pr_number
       JOIN selected s ON s.issue_number=l.issue_number) AS pullRequests
  `).get(selected) as { closureEvents: number; prLinks: number; pullRequests: number } | undefined;
  return {
    closureEvents: Number(row?.closureEvents ?? 0),
    prLinks: Number(row?.prLinks ?? 0),
    pullRequests: Number(row?.pullRequests ?? 0),
  };
}

async function refreshRawClosureEvidence(issueNumbers: number[]): Promise<ClosureProofAnalysisResult['rawEvidence']> {
  let closureEvents = 0;
  let prLinks = 0;
  let pullRequests = 0;
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
        source: CLOSURE_COMMENT_FIX_PROOF_SOURCE,
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
  return { closureEvents, prLinks, pullRequests };
}

function splitCsv(value: unknown): string[] {
  if (!value) return [];
  return String(value).split(',').map((item) => item.trim()).filter(Boolean);
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
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
