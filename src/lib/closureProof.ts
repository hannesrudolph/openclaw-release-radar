export type ClosureProofStatus =
  | 'fixed_in_release'
  | 'fixed_after_release'
  | 'duplicate_or_superseded'
  | 'not_planned'
  | 'already_present_claim'
  | 'no_code_proof'
  | 'no_timeline_event'
  | 'non_bug_neutral'
  | 'unknown';

export interface ClosureProofInput {
  issueNumber: number;
  sentiment?: string | null;
  stateReasons: string[];
  closureActors: string[];
  hasClosureEvent: boolean;
  hasClosingLink: boolean;
  hasMergedClosingPr: boolean;
  hasReachableClosingPr: boolean;
  hasNotReachableClosingPr: boolean;
  comments: Array<{ author?: string | null; body?: string | null; createdAt?: string | null }>;
}

export interface ClosureProofResult {
  status: ClosureProofStatus;
  summary: string;
  evidence: Record<string, unknown>;
}

const DUPLICATE_RE = /\b(duplicate|dupe|superseded|canonical|already tracked|broader .*tracker|belongs under)\b/i;
const ALREADY_PRESENT_RE = /\b(already implemented|already fixed|current main|tagged releases? already|already contains|already covered|implemented in current)\b/i;
const NO_PLAN_RE = /\b(not planned|won't fix|wont fix|expected behavior|working as intended|by design)\b/i;
const CANONICAL_LINE_RE = /^\s*(?:\*\*)?(?:canonical|root-cause tracker|root cause tracker)(?:\*\*)?\s*:\s*(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?(\d+)/gim;

export function classifyClosureProof(input: ClosureProofInput): ClosureProofResult {
  const combinedComments = input.comments.map((comment) => comment.body ?? '').join('\n');
  const reasons = new Set(input.stateReasons.filter(Boolean));
  const evidence = {
    stateReasons: input.stateReasons,
    closureActors: input.closureActors,
    hasClosingLink: input.hasClosingLink,
    hasMergedClosingPr: input.hasMergedClosingPr,
    hasReachableClosingPr: input.hasReachableClosingPr,
    hasNotReachableClosingPr: input.hasNotReachableClosingPr,
    matchingComments: matchingCommentSnippets(input.comments),
    canonicalIssues: canonicalIssueNumbers(combinedComments),
  };

  if (input.sentiment && input.sentiment !== 'negative') {
    return {
      status: 'non_bug_neutral',
      summary: 'Closed item is not negative bug evidence.',
      evidence,
    };
  }

  if (!input.hasClosureEvent) {
    return {
      status: 'no_timeline_event',
      summary: 'Closed issue has no fetched GitHub closure timeline event.',
      evidence,
    };
  }

  if (input.hasReachableClosingPr) {
    return {
      status: 'fixed_in_release',
      summary: 'Closed by a merged PR reachable from this release tag.',
      evidence,
    };
  }

  if (input.hasMergedClosingPr && input.hasNotReachableClosingPr) {
    return {
      status: 'fixed_after_release',
      summary: 'Closed by a merged PR, but that PR is not reachable from this release tag.',
      evidence,
    };
  }

  if (ALREADY_PRESENT_RE.test(combinedComments)) {
    return {
      status: 'already_present_claim',
      summary: 'Closure comment claims the behavior is already implemented, but no reachable closing PR proof is attached.',
      evidence,
    };
  }

  if (reasons.has('DUPLICATE') || DUPLICATE_RE.test(combinedComments)) {
    return {
      status: 'duplicate_or_superseded',
      summary: 'Closed as duplicate, superseded, or moved under a broader tracker.',
      evidence,
    };
  }

  if (reasons.has('NOT_PLANNED') || NO_PLAN_RE.test(combinedComments)) {
    return {
      status: 'not_planned',
      summary: 'Closed as not planned or not actionable as a direct fix.',
      evidence,
    };
  }

  if (input.hasClosingLink && !input.hasMergedClosingPr) {
    return {
      status: 'no_code_proof',
      summary: 'A closing PR link exists, but the PR is not merged or merge state is unknown.',
      evidence,
    };
  }

  return {
    status: 'no_code_proof',
    summary: 'Closed without code proof tied to this release.',
    evidence,
  };
}

function canonicalIssueNumbers(text: string): number[] {
  const numbers = new Set<number>();
  CANONICAL_LINE_RE.lastIndex = 0;
  for (const match of text.matchAll(CANONICAL_LINE_RE)) {
    const number = Number(match[1]);
    if (Number.isInteger(number) && number > 0) numbers.add(number);
  }
  return [...numbers].sort((a, b) => a - b);
}

function matchingCommentSnippets(comments: ClosureProofInput['comments']): Array<{
  author: string | null;
  createdAt: string | null;
  snippet: string;
}> {
  return comments
    .filter((comment) => {
      const body = comment.body ?? '';
      return DUPLICATE_RE.test(body) || ALREADY_PRESENT_RE.test(body) || NO_PLAN_RE.test(body);
    })
    .slice(-3)
    .map((comment) => ({
      author: comment.author ?? null,
      createdAt: comment.createdAt ?? null,
      snippet: (comment.body ?? '').replace(/\s+/g, ' ').slice(0, 500),
    }));
}
