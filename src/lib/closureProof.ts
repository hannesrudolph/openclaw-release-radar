import type { ClosureProofStatus } from './closureProofTaxonomy';
export type { ClosureProofStatus } from './closureProofTaxonomy';

export interface ClosureProofInput {
  issueNumber: number;
  issueAuthor?: string | null;
  closedAt?: string | null;
  sentiment?: string | null;
  stateReasons: string[];
  closureActors: string[];
  hasClosureEvent: boolean;
  hasClosingLink: boolean;
  hasMergedClosingPr: boolean;
  hasReachableClosingPr: boolean;
  hasNotReachableClosingPr: boolean;
  hasReachableFixCommit?: boolean;
  hasNotReachableFixCommit?: boolean;
  reachableFixCommits?: string[];
  notReachableFixCommits?: string[];
  comments: Array<{ author?: string | null; body?: string | null; createdAt?: string | null; updatedAt?: string | null }>;
}

export interface ClosureProofResult {
  status: ClosureProofStatus;
  summary: string;
  evidence: Record<string, unknown>;
}

const DUPLICATE_RE = /\b(duplicate|dupe|superseded|canonical|already tracked|broader .*tracker|belongs under)\b/i;
const DUPLICATE_RATIONALE_RE = /\b(?:close[sd]?|closing|closed)\s+(?:this\s+)?(?:as\s+)?(?:a\s+)?(?:duplicate|dupe|superseded|already tracked|covered by|belongs under)\b|\b(?:as\s+(?:a\s+)?)?(?:duplicate|dupe|superseded)\s+(?:of|by)\s+(?:the\s+)?(?:open\s+|closed\s+)?(?:canonical\s+)?(?:(?:issue|tracker|report)\s+)?(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?\d+\b|\b(?:tracked|centralized|consolidated)\s+(?:in|under|by)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?\d+\b/i;
const NOT_DUPLICATE_RE = /\b(?:not|isn't|is not|wasn't|was not|no longer)\s+(?:a\s+)?(?:duplicate|dupe|superseded)\b/i;
const ALREADY_PRESENT_RE = /\b(already implemented|already fixed|tagged releases? already|already contains|already covered|implemented in current|current `?main`?.{0,80}\b(?:already|now)\s+(?:has|contains|includes|implements?|fix(?:e[sd])?)|current `?main`?.{0,80}\bv20\d{2}\.\d+\.\d+\s+(?:already\s+)?(?:has|contains|includes|implements?|fix(?:e[sd])?))\b/i;
const MAIN_ONLY_RE = /\b(current-main-only|main-only|v20\d{2}\.\d+\.\d+\s+(?:still\s+)?(?:predates|does not contain|doesn't contain)|latest release(?: tag)?(?: inspected here)? does not contain|stable v20\d{2}\.\d+\.\d+\s+predates|not yet in (?:the )?(?:latest )?release)\b/i;
const NO_PLAN_RE = /\b(not planned|won't fix|wont fix|expected behavior|working as intended|by design)\b/i;
const NON_ACTIONABLE_RATIONALE_RE = /\b(won't fix|wont fix|expected behavior|working as intended|by design|outside\s+(?:the\s+)?OpenClaw\s+source|outside\s+(?:the\s+)?(?:repo|repository)|repo(?:sitory)?\s+boundary|plugin-owned|plugin\s+scope|ClawHub|not\s+present\s+in\s+(?:the\s+)?OpenClaw\s+source|not\s+actionable|out\s+of\s+scope|unsupported|no longer reproduc(?:e|es|ible)|not reproducible|non-reproducible|could not reproduce|does not reproduce|contract (?:was )?clarified|supported alternative|decision:)\b/i;
const REPORTER_REPLACED_RE = /\b(?:reopened|refiled|opened|moved)\s+(?:as|in|under|to)\b.{0,80}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#\d+\b/i;
const REPORTER_WITHDRAWN_RE = /\b(?:please ignore|ignore this|closed by reporter|privacy concerns?|pii|personally identifiable|withdrawn|false alarm|opened by mistake|my mistake|resolved on my side|no longer reproduc(?:e|ible)|not reproducible anymore)\b/i;
const REPRO_REQUESTED_RE = /\b(?:(?:please\s+)?(?:file|open)\s+(?:a\s+)?fresh\s+issue|please\s+(?:file|open)\s+(?:a\s+)?new\s+issue)\b.{0,160}\bif\b.{0,160}\b(?:still|continues?|fails?|repro(?:s|duces?)?)\b|\b(?:please\s+)?(?:file|open)\s+(?:a\s+)?new\s+issue\b.{0,80}\bif\s+(?:this|it)\s+still\s+(?:repo(?:s)?|repro(?:s|duces?)?)\b.{0,80}\b(?:latest|current|newer)\b|\bif\s+(?:this|it)\s+still\s+(?:repo(?:s)?|repro(?:s|duces?)?)\b.{0,80}\b(?:latest|current|newer)\b.{0,80}\b(?:please\s+)?(?:file|open)\s+(?:a\s+)?new\s+issue\b/i;
const KEEP_OPEN_RE = /\b(?:keep(?:ing)?|stay|remain)\s+(?:this\s+)?open\b|\bbefore closing this issue\b/i;
const CLOSURE_RATIONALE_RE = /\b(?:close[sd]?|closing)\s*:|\b(?:close[sd]?|closing)\s+(?:this\s+)?(?:here\s+)?(?:as|because|since|for|out|in favor of|fixed|not planned)\b|\b(?:close[sd]?|closing)\s+(?:this\s+)?(?:issue|report)\b|\bfixed\s+on\s+(?:current\s+)?`?main`?\b|\bcanonical\s+(?:PR|pull request)\s*:\s*#\d+\b|\broot\s+cause\s+to\s+https?:\/\/github\.com\/openclaw\/openclaw\/commit\/[0-9a-f]{40}\b|\busers?\s+on\s+v?20\d{2}\.\d+\.\d+\s+will\s+pick\s+this\s+up\s+with\s+the\s+next\s+release\b|\bnot planned\b|\bwon't fix\b|\bwont fix\b|\bexpected behavior\b|\bworking as intended\b|\bby design\b|\boutside\s+(?:the\s+)?OpenClaw\s+source\b|\b(?:file|open)\s+(?:a\s+)?new\s+issue\b.{0,80}\bif\s+(?:this|it)\s+still\s+(?:repo(?:s)?|repro(?:s|duces?)?)\b.{0,80}\b(?:latest|current|newer)\b/i;
const CANONICAL_REFERENCE_RES = [
  /^\s*(?:\*\*)?(?:canonical|canonical path|root-cause tracker|root cause tracker)(?:\*\*)?\s*:\s*(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)/gim,
  /^\s*(?:\*\*)?(?:canonical|canonical path|root-cause tracker|root cause tracker|root-cause cluster|root cause cluster)(?:\*\*)?\s*:\s*.{0,240}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/|#)(\d+)/gim,
  /\b(?:canonical|root-cause|root cause)\s+(?:issue|tracker|report)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
  /\b(?:canonical path|canonical|root-cause|root cause|root-cause cluster|root cause cluster)\b.{0,240}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/|#)(\d+)/gim,
  /\b(?:close[sd]?|closing)\s+as\s+(?:a\s+)?(?:duplicate|dupe|superseded)\s*:\s*(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
  /\b(?:as\s+(?:a\s+)?)?(?:duplicate|dupe|superseded)\s+(?:of|by)\s+(?:the\s+)?(?:open\s+|closed\s+)?(?:canonical\s+)?(?:(?:issue|tracker|report)\s+)?(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
  /\b(?:tracked|centralized|consolidated)\s+(?:in|under|by)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)\b/gim,
];
const CLOSURE_CONTEXT_BEFORE_MS = 72 * 60 * 60 * 1000;
const CLOSURE_CONTEXT_AFTER_MS = 60 * 60 * 1000;

export function classifyClosureProof(input: ClosureProofInput): ClosureProofResult {
  const closureContextComments = closureRationaleComments(input.comments, input.closedAt);
  const combinedComments = closureContextComments.map((comment) => comment.body ?? '').join('\n');
  const reasons = new Set(input.stateReasons.filter(Boolean));
  const issueAuthor = normalizeLogin(input.issueAuthor);
  const closureActors = input.closureActors.map(normalizeLogin).filter(Boolean);
  const reporterSelfClosed = !!issueAuthor && closureActors.includes(issueAuthor);
  const issueAuthorComments = closureContextComments
    .filter((comment) => {
      const author = normalizeLogin(comment.author);
      return !!author && author === issueAuthor;
    })
    .map((comment) => comment.body ?? '')
    .join('\n');
  const evidence = {
    issueAuthor: input.issueAuthor ?? null,
    stateReasons: input.stateReasons,
    closureActors: input.closureActors,
    reporterSelfClosed,
    closureContextCommentCount: closureContextComments.length,
    hasClosingLink: input.hasClosingLink,
    hasMergedClosingPr: input.hasMergedClosingPr,
    hasReachableClosingPr: input.hasReachableClosingPr,
    hasNotReachableClosingPr: input.hasNotReachableClosingPr,
    hasReachableFixCommit: input.hasReachableFixCommit === true,
    hasNotReachableFixCommit: input.hasNotReachableFixCommit === true,
    reachableFixCommits: input.reachableFixCommits ?? [],
    notReachableFixCommits: input.notReachableFixCommits ?? [],
    matchingComments: matchingCommentSnippets(closureContextComments),
    nonActionableRationaleComments: nonActionableRationaleSnippets(closureContextComments),
    canonicalIssues: canonicalIssueNumbers(combinedComments),
  };

  if (!input.hasClosureEvent) {
    return {
      status: 'no_timeline_event',
      summary: 'Closed issue has no fetched GitHub closure timeline event.',
      evidence,
    };
  }

  const hasCompletedClosure = reasons.has('COMPLETED');
  const reporterContext = issueAuthorComments || (reporterSelfClosed ? combinedComments : '');

  if (input.sentiment && input.sentiment !== 'negative') {
    if (hasCompletedClosure && (input.hasReachableClosingPr || input.hasReachableFixCommit)) {
      return {
        status: 'non_bug_fixed_in_release',
        summary: input.hasReachableClosingPr
          ? 'Non-negative item closed by a merged PR reachable from this release tag; not scored as bug fix credit.'
          : 'Non-negative item closed by a fix/source commit reachable from this release tag; not scored as bug fix credit.',
        evidence,
      };
    }
    if (hasCompletedClosure && ((input.hasMergedClosingPr && input.hasNotReachableClosingPr) || input.hasNotReachableFixCommit)) {
      return {
        status: 'non_bug_fixed_after_release',
        summary: input.hasNotReachableFixCommit
          ? 'Non-negative item has fix/source commit proof, but that commit is not reachable from this release tag.'
          : 'Non-negative item has merged PR proof, but that PR is not reachable from this release tag.',
        evidence,
      };
    }
    if (hasCompletedClosure && input.hasClosingLink && !input.hasMergedClosingPr) {
      return {
        status: 'non_bug_linked_without_merge',
        summary: 'Non-negative item has a linked closing PR, but it is not merged or its merge state is unknown.',
        evidence,
      };
    }
    if (hasDuplicateOrSupersededSignal(combinedComments, reasons)) {
      return {
        status: 'non_bug_duplicate_or_superseded',
        summary: 'Non-negative item was closed as duplicate, superseded, or moved under another tracker.',
        evidence,
      };
    }
    if (evidence.nonActionableRationaleComments.length > 0) {
      return {
        status: 'non_bug_not_actionable',
        summary: 'Non-negative item was closed with concrete non-actionable or out-of-repository rationale.',
        evidence,
      };
    }
    return {
      status: 'non_bug_neutral',
      summary: 'Closed item is not negative bug evidence.',
      evidence,
    };
  }

  if (hasCompletedClosure && (input.hasReachableClosingPr || input.hasReachableFixCommit)) {
    return {
      status: 'fixed_in_release',
      summary: input.hasReachableClosingPr
        ? 'Closed by a merged PR reachable from this release tag.'
        : 'Closed by a fix/source commit reachable from this release tag.',
      evidence,
    };
  }

  if (hasCompletedClosure && ((input.hasMergedClosingPr && input.hasNotReachableClosingPr) || input.hasNotReachableFixCommit)) {
    return {
      status: 'fixed_after_release',
      summary: input.hasNotReachableFixCommit
        ? 'Closed by a fix/source commit, but that commit is not reachable from this release tag.'
        : 'Closed by a merged PR, but that PR is not reachable from this release tag.',
      evidence,
    };
  }

  if (REPORTER_REPLACED_RE.test(reporterContext)) {
    return {
      status: 'reporter_replaced',
      summary: 'Reporter refiled or replaced this issue, so the closure is not release fix proof.',
      evidence,
    };
  }

  if (REPORTER_WITHDRAWN_RE.test(reporterContext)) {
    return {
      status: 'reporter_withdrawn',
      summary: 'Reporter withdrew, ignored, or closed the report for non-fix reasons.',
      evidence,
    };
  }

  if (REPRO_REQUESTED_RE.test(combinedComments)) {
    return {
      status: 'repro_requested',
      summary: 'Closed with a request to file a fresh report if the issue still reproduces on the latest version; no release fix proof is linked.',
      evidence,
    };
  }

  if (hasDuplicateOrSupersededSignal(combinedComments, reasons)) {
    return {
      status: 'duplicate_or_superseded',
      summary: 'Closed as duplicate, superseded, or moved under a broader tracker.',
      evidence,
    };
  }

  if (evidence.nonActionableRationaleComments.length > 0) {
    return {
      status: 'not_planned',
      summary: 'Closed with concrete non-actionable, not-reproducible, or out-of-repository rationale.',
      evidence,
    };
  }

  if (MAIN_ONLY_RE.test(combinedComments)) {
    return {
      status: 'main_only_claim',
      summary: 'Closure says the fix is on current main, but not in this release tag.',
      evidence,
    };
  }

  if (ALREADY_PRESENT_RE.test(combinedComments)) {
    return {
      status: 'already_present_claim',
      summary: 'Closure says the behavior is already implemented, but no hard code proof is reachable from this release tag.',
      evidence,
    };
  }

  if (reporterSelfClosed) {
    return {
      status: 'reporter_self_closed',
      summary: 'Reporter self-closed the issue without linked release fix proof or ongoing failure context.',
      evidence,
    };
  }

  if (reasons.has('NOT_PLANNED') && !NON_ACTIONABLE_RATIONALE_RE.test(combinedComments)) {
    return {
      status: 'admin_not_planned_unverified',
      summary: 'Closed as not planned without trusted release-fix proof or a concrete non-actionable rationale.',
      evidence,
    };
  }

  if (reasons.has('NOT_PLANNED') || NO_PLAN_RE.test(combinedComments)) {
    return {
      status: 'not_planned',
      summary: 'Closed with close-time rationale that the report is not actionable as a direct release fix.',
      evidence,
    };
  }

  if (hasCompletedClosure && input.hasClosingLink && input.hasMergedClosingPr) {
    return {
      status: 'linked_closing_pr_reachability_unknown',
      summary: 'A merged closing PR exists, but release-tag reachability is missing or unknown.',
      evidence,
    };
  }

  if (input.hasClosingLink && !input.hasMergedClosingPr) {
    return {
      status: 'linked_closing_pr_not_merged',
      summary: 'A linked PR exists, but it is not merged or its merge state is unknown.',
      evidence,
    };
  }

  return {
    status: 'closed_without_release_fix_proof',
    summary: 'Closed without linked release-fix PR or fix/source commit proof for this release tag.',
    evidence,
  };
}

function normalizeLogin(login: string | null | undefined): string {
  return String(login ?? '').trim().toLowerCase();
}

export function closureRationaleComments<T extends { createdAt?: string | null; created_at?: string | null; updatedAt?: string | null; updated_at?: string | null }>(
  comments: T[],
  closedAt: string | null | undefined,
): T[] {
  if (!closedAt) return comments;
  const closedMs = Date.parse(closedAt);
  if (!Number.isFinite(closedMs)) return comments;
  return comments.filter((comment) => {
    const createdAt = comment.createdAt ?? comment.created_at ?? null;
    const updatedAt = comment.updatedAt ?? comment.updated_at ?? null;
    const createdMs = createdAt ? Date.parse(createdAt) : Number.NaN;
    const updatedMs = updatedAt ? Date.parse(updatedAt) : Number.NaN;
    const effectiveMs = Number.isFinite(updatedMs) && (!Number.isFinite(createdMs) || updatedMs > createdMs)
      ? updatedMs
      : createdMs;
    if (Number.isFinite(effectiveMs) &&
      effectiveMs >= closedMs - CLOSURE_CONTEXT_BEFORE_MS &&
      effectiveMs <= closedMs + CLOSURE_CONTEXT_AFTER_MS) {
      const body = 'body' in comment ? String(comment.body ?? '').replace(/\s+/g, ' ') : '';
      return CLOSURE_RATIONALE_RE.test(body) && !KEEP_OPEN_RE.test(body);
    }
    return false;
  });
}

function canonicalIssueNumbers(text: string): number[] {
  const numbers = new Set<number>();
  for (const re of CANONICAL_REFERENCE_RES) {
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

function canonicalIssueNumbersFromSignalLines(text: string): number[] {
  const numbers = new Set<number>();
  const signalRe = /\b(?:covered by|broader\s+(?:reports?|issues?|trackers?)|especially)\b/i;
  for (const line of text.split(/\n+/)) {
    if (!signalRe.test(line)) continue;
    const prContext = /\b(?:PR|pull request)\b|\/pull\//i.test(line);
    for (const match of line.matchAll(/https?:\/\/github\.com\/openclaw\/openclaw\/issues\/(\d+)\b|#(\d+)\b/gim)) {
      if (prContext && !match[1]) continue;
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
  return /\b(?:PR|pull request)\b|\/pull\//i.test(line);
}

function hasDuplicateOrSupersededSignal(text: string, reasons: Set<string>): boolean {
  if (reasons.has('DUPLICATE')) return true;
  if (!DUPLICATE_RE.test(text)) return false;
  if (canonicalIssueNumbers(text).length > 0) return true;
  const lines = text.split(/\n+/).map((line) => line.trim()).filter(Boolean);
  return lines.some((line) => DUPLICATE_RATIONALE_RE.test(line) && !NOT_DUPLICATE_RE.test(line));
}

function matchingCommentSnippets(comments: ClosureProofInput['comments']): Array<{
  author: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  snippet: string;
}> {
  return comments
    .filter((comment) => {
      const body = comment.body ?? '';
      return DUPLICATE_RE.test(body) || ALREADY_PRESENT_RE.test(body) || MAIN_ONLY_RE.test(body) || NO_PLAN_RE.test(body) ||
        REPORTER_REPLACED_RE.test(body) || REPORTER_WITHDRAWN_RE.test(body) || REPRO_REQUESTED_RE.test(body);
    })
    .slice(-3)
    .map((comment) => ({
      author: comment.author ?? null,
      createdAt: comment.createdAt ?? null,
      updatedAt: comment.updatedAt ?? null,
      snippet: (comment.body ?? '').replace(/\s+/g, ' ').slice(0, 500),
    }));
}

function nonActionableRationaleSnippets(comments: ClosureProofInput['comments']): Array<{
  author: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  snippet: string;
}> {
  return comments
    .filter((comment) => NON_ACTIONABLE_RATIONALE_RE.test(comment.body ?? ''))
    .slice(-3)
    .map((comment) => ({
      author: comment.author ?? null,
      createdAt: comment.createdAt ?? null,
      updatedAt: comment.updatedAt ?? null,
      snippet: (comment.body ?? '').replace(/\s+/g, ' ').slice(0, 500),
    }));
}
