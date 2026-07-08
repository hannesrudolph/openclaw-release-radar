import type { ClosureProofStatus } from './closureProofTaxonomy';
import type { DirectCommitFirstContainingResult } from './releaseReachability';
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
  comments: Array<{
    id?: number | null;
    issueNumber?: number | null;
    url?: string | null;
    author?: string | null;
    body?: string | null;
    createdAt?: string | null;
    updatedAt?: string | null;
  }>;
}

export interface ClosureProofResult {
  status: ClosureProofStatus;
  summary: string;
  evidence: Record<string, unknown>;
}

const DUPLICATE_RE = /\b(duplicate|dupe|superseded|consolidat(?:e|ed|ing)|canonical|already tracked|already-active|already active|broader .*tracker|belongs under|matches\b.{0,120}\b(?:tracked|canonical|duplicate|same))\b/i;
const DUPLICATE_RATIONALE_RE = /\b(?:close[sd]?|closing|closed)\s+(?:this\s+)?(?:as\s+)?(?:a\s+)?(?:duplicate|dupe|superseded|already tracked|covered by|belongs under)\b|\b(?:this\s+is\s+now|now)\s+(?:a\s+)?(?:duplicate|dupe|superseded)\b|\b(?:this\s+report\s+)?matches\b.{0,160}\b(?:already-active|already active|canonical|duplicate|same)\b|\b(?:as\s+(?:a\s+)?)?(?:duplicate|dupe|superseded)\s+(?:of|by)\s+(?:the\s+)?(?:open\s+|closed\s+)?(?:canonical\s+)?(?:(?:issue|tracker|report)\s+)?(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?\d+\b|\b(?:tracked|centralized|consolidated)\s+(?:in|under|by)\s+(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#?\d+\b|\bconsolidat(?:e|es|ed|ing)\s+(?:this\s+)?(?:issue\s+|report\s+)?(?:in|into|under)\s+.{0,120}#\d+\b|\bsuperseded\s+by\b.{0,160}(?:issue|tracker|report)?\s*:?\s*#\d+\b/i;
const NOT_DUPLICATE_RE = /\b(?:not|isn't|is not|wasn't|was not|no longer)\s+(?:a\s+)?(?:duplicate|dupe|superseded)\b/i;
const ALREADY_PRESENT_RE = /\b(already implemented|already fixed|tagged releases? already|already contains|already covered|implemented in current|current `?main`?.{0,80}\b(?:already|now)\s+(?:has|contains|includes|implements?|fix(?:e[sd])?)|current `?main`?.{0,80}\bv20\d{2}\.\d+\.\d+\s+(?:already\s+)?(?:has|contains|includes|implements?|fix(?:e[sd])?))\b/i;
const MAIN_ONLY_RE = /\b(current-main-only|main-only|v20\d{2}\.\d+\.\d+\s+(?:still\s+)?(?:predates|does not contain|doesn't contain)|latest release(?: tag)?(?: inspected here)? does not contain|stable v20\d{2}\.\d+\.\d+\s+predates|not yet in (?:the )?(?:latest )?release)\b/i;
const NO_PLAN_RE = /\b(not planned|won't fix|wont fix|expected behavior|working as intended|by design)\b/i;
const NON_ACTIONABLE_RATIONALE_RE = /\b(won't fix|wont fix|expected behavior|working as intended|by design|outside\s+(?:the\s+)?OpenClaw\s+source|outside\s+(?:the\s+)?(?:repo|repository)|repo(?:sitory)?\s+boundary|wrong\s+(?:repo|repository|service)|not\s+OpenClaw-related|not\s+affiliated|please\s+file\s+(?:under|upstream|against)|plugin-owned|plugin\s+scope|plugin\/community path|external\s+(?:package|plugin|client)|separately published|deprecated and no longer (?:ships|maintained)|no longer maintained|use\s+(?:the\s+)?built-in\b|ClawHub|not\s+present\s+in\s+(?:the\s+)?OpenClaw\s+source|not\s+actionable|out\s+of\s+scope|unsupported|no longer reproduc(?:e|es|ible)|not reproducible|non-reproducible|could not reproduce|could not reproduce it anymore|does not reproduce|contract (?:was )?clarified|supported alternative|decision:)\b/i;
const DECISIVE_NON_ACTIONABLE_RATIONALE_RE = /\b(?:the\s+)?(?:reported\s+)?(?:camera\s+)?permission\s+belongs?\s+to\s+Google Play services\s*,?\s+not\s+OpenClaw\b|\bGoogle Code Scanner\b.{0,160}\bpermissionless\s+for\s+the\s+calling\s+app\b|\bsupported\s+path\s*:\s*(?:use|follow|grant|open|paste|enter)\b.{0,180}\b(?:permission|scanner|settings|setup\s+code|paste|enter)\b|\bOpenClaw\s+is\s+not\s+affiliated\s+with\b.{1,160}\bissues?\b.{0,100}\bshould\s+not\s+be\s+(?:submitted|filed|reported)\s+here\b/i;
const NON_ACTIONABLE_UNCERTAINTY_RE = /\b(?:maybe|perhaps|unclear|uncertain|whether|under investigation|investigating|still\s+need(?:s)?\s+to|need(?:s)?\s+to\s+(?:verify|confirm|investigate|determine|test|check))\b/i;
const NON_ACTIONABLE_CLAUSE_BREAK_RE = /(?:[\r\n]+|[.!?;]+|\b(?:but|however|yet|nevertheless)\b)/i;
const EXPLICIT_ONGOING_FAILURE_RE = /\b(?:still|continues?\s+to|keeps?\s+on)\s+(?:fails?|failing|breaks?|broken|reproduces?|errors?)\b|\b(?:fails?|failing|broken|reproduces?)\b.{0,40}\b(?:on|in)\s+(?:the\s+)?(?:latest|current|newest)(?:\s+(?:release|version|build))?\b/gi;
const NEGATED_ONGOING_FAILURE_PREFIX_RE = /\b(?:no\s+longer|never|not|does\s+not|doesn[’']t|did\s+not|didn[’']t|cannot|can[’']t|could\s+not|couldn[’']t)\s*$/i;
const REPORTER_REPLACED_RE = /\b(?:reopened|refiled|opened|moved)\s+(?:as|in|under|to)\b.{0,80}(?:https?:\/\/github\.com\/openclaw\/openclaw\/issues\/)?#\d+\b/i;
const REPORTER_WITHDRAWN_RE = /\b(?:please ignore|ignore this|closed by reporter|privacy concerns?|pii|personally identifiable|withdrawn|false alarm|opened by mistake|my mistake|resolved on my side|no longer reproduc(?:e|ible)|not reproducible anymore)\b/i;
const REPRO_REQUESTED_RE = /\b(?:(?:please\s+)?(?:file|open)\s+(?:a\s+)?fresh\s+issue|please\s+(?:file|open)\s+(?:a\s+)?new\s+issue)\b.{0,160}\bif\b.{0,160}\b(?:still|continues?|fails?|repro(?:s|duces?)?)\b|\b(?:please\s+)?(?:file|open)\s+(?:a\s+)?new\s+issue\b.{0,80}\bif\s+(?:this|it)\s+still\s+(?:repo(?:s)?|repro(?:s|duces?)?)\b.{0,80}\b(?:latest|current|newer)\b|\bif\s+(?:this|it)\s+still\s+(?:repo(?:s)?|repro(?:s|duces?)?)\b.{0,80}\b(?:latest|current|newer)\b.{0,80}\b(?:please\s+)?(?:file|open)\s+(?:a\s+)?new\s+issue\b|\bif\s+this\s+is\s+still\s+(?:an\s+)?issue\b.{0,180}\b(?:retry|try|test|recheck)\b.{0,120}\b(?:latest|current|newer)\b.{0,220}\b(?:open|file)\s+(?:a\s+)?(?:new|fresh)\s+issue\b|\bif\b.{0,80}\bstill\s+happens\b.{0,80}\b(?:latest|current|newer)\b.{0,120}\b(?:open|file)\s+(?:a\s+)?(?:new|fresh)\s+issue\b/i;
const INSUFFICIENT_INFO_RE = /\b(?:stale\/insufficient-info|insufficient[-\s]?info|insufficient information|missing enough reproduction detail|not enough (?:evidence|information|details)|without (?:those|the) (?:details|logs|trace)|no reply from (?:the )?author|there has been no reply|never arrived|cannot identify .* without (?:that|the) trace)\b/i;
const CURRENT_SUBJECT_KEEP_OPEN_RE = /\b(?:keep(?:ing)?|leave)\s+(?:this(?:\s+(?:issue|report|tracker))?\s+)?open\b|\bthis(?:\s+(?:issue|report|tracker))?\s+(?:(?:should|must|needs?\s+to)\s+)?(?:stay|remain)\s+(?:open|unresolved)\b|\bbefore closing this issue\b/i;
const GENERIC_KEEP_OPEN_RE = /\b(?:stay|remain)\s+(?:open|unresolved)\b/i;
const NOT_KEEP_OPEN_RE = /\b(?:does\s+not|doesn't|do\s+not|don't|no\s+need\s+to|need\s+not)\s+(?:need\s+to\s+)?(?:stay|remain|keep|keeping)\s+(?:this\s+)?open\b|\brather\s+than\s+keeping\b.{0,120}\bopen\b|\bnot\s+keeping\b.{0,120}\bopen\b/i;
const OTHER_ISSUES_KEEP_OPEN_RE = /\b(?:separate|distinct|other|remaining|canonical|broader)\b.{0,160}\b(?:issues?|reports?|trackers?)\b.{0,80}\b(?:remain|stay)\s+open\b|\b(?:issues?|reports?|trackers?)\b.{0,80}\b(?:remain|stay)\s+open\s+(?:separately|elsewhere)\b|\bkeep(?:ing)?\s+(?:the\s+)?(?:separate|distinct|other|remaining)\b.{0,160}\b(?:issues?|reports?|trackers?)\s+open\b/i;
const CLOSURE_RATIONALE_RE = /\b(?:close[sd]?|closing)\s*:|\bclosing\s*[—-]|\bclosing\s+after\b.{0,160}\b(?:verification|testing|review|inspection)\b|\b(?:close[sd]?|closing)\s+due\s+to\s+inactivity\b|\b(?:close[sd]?|closing)\s+(?:this\s+)?(?:here\s+)?(?:as|because|since|for|out|in favor of|fixed|not planned)\b|\bso\s+i[’']?m\s+closing\s+this\s+here\b|\b(?:close[sd]?|closing)\s+(?:this\s+)?(?:issue|report)\b|\b(?:this\s+is\s+now|now)\s+(?:a\s+)?(?:duplicate|dupe|superseded)\b|\b(?:this\s+report\s+)?matches\b.{0,160}\b(?:already-active|already active|canonical|duplicate|same)\b|\bconsolidat(?:e|es|ed|ing)\s+(?:this\s+)?(?:issue\s+|report\s+)?(?:in|into|under)\s+.{0,160}#\d+\b|\bsuperseded\s+by\b.{0,160}#\d+\b|\brefil(?:e|ed|ing)\b.{0,160}#\d+\b|\bfixed\s+on\s+(?:current\s+)?`?main`?\b|\bcanonical\s+(?:PR|pull request)\s*:\s*#\d+\b|\broot\s+cause\s+to\s+https?:\/\/github\.com\/openclaw\/openclaw\/commit\/[0-9a-f]{40}\b|\busers?\s+on\s+v?20\d{2}\.\d+\.\d+\s+will\s+pick\s+this\s+up\s+with\s+the\s+next\s+release\b|\bnot planned\b|\bwon't fix\b|\bwont fix\b|\bexpected behavior\b|\bworking as intended\b|\bby design\b|\boutside\s+(?:the\s+)?OpenClaw\s+source\b|\b(?:file|open)\s+(?:a\s+)?new\s+issue\b.{0,80}\bif\s+(?:this|it)\s+still\s+(?:repo(?:s)?|repro(?:s|duces?)?)\b.{0,80}\b(?:latest|current|newer)\b|\bif\s+this\s+is\s+still\s+(?:an\s+)?issue\b.{0,180}\b(?:latest|current|newer)\b/i;
const CANONICAL_REFERENCE_RES = [
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
const CLOSURE_CONTEXT_BEFORE_MS = 72 * 60 * 60 * 1000;
const CLOSURE_CONTEXT_AFTER_MS = 60 * 60 * 1000;

export function classifyClosureProof(input: ClosureProofInput): ClosureProofResult {
  const closureContextComments = closureRationaleComments(input.comments, input.closedAt);
  const combinedComments = closureContextComments.map((comment) => comment.body ?? '').join('\n');
  const nonActionableState = nonActionableRationaleState(combinedComments);
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
    hasUnknownFixCommit: input.hasUnknownFixCommit === true,
    reachableFixCommits: input.reachableFixCommits ?? [],
    notReachableFixCommits: input.notReachableFixCommits ?? [],
    unknownFixCommits: input.unknownFixCommits ?? [],
    targetReachableFixCommits: input.targetReachableFixCommits ?? [],
    targetNotReachableFixCommits: input.targetNotReachableFixCommits ?? [],
    targetUnknownFixCommits: input.targetUnknownFixCommits ?? [],
    predecessorContainedFixCommits: input.predecessorContainedFixCommits ?? [],
    firstContainingUnknownFixCommits: input.firstContainingUnknownFixCommits ?? [],
    directCommitFirstContainingProofs: input.directCommitFirstContainingProofs ?? [],
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
  const duplicateOrSuperseded = hasDuplicateOrSupersededSignal(combinedComments, reasons);

  if (input.sentiment && input.sentiment !== 'negative') {
    if (duplicateOrSuperseded) {
      return {
        status: 'non_bug_duplicate_or_superseded',
        summary: 'Non-negative item was closed as duplicate, superseded, or moved under another tracker.',
        evidence,
      };
    }
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
    if (hasCompletedClosure && input.hasUnknownFixCommit) {
      return {
        status: 'non_bug_direct_fix_commit_reachability_unknown',
        summary: 'Non-negative item has fix/source commit proof, but release-tag reachability is missing or unknown.',
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

  if (duplicateOrSuperseded) {
    return {
      status: 'duplicate_or_superseded',
      summary: 'Closed as duplicate, superseded, or moved under a broader tracker.',
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

  if (hasCompletedClosure && input.hasUnknownFixCommit) {
    return {
      status: 'direct_fix_commit_reachability_unknown',
      summary: 'A named fix/source commit proof exists, but release-tag reachability is missing or unknown.',
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

  if (INSUFFICIENT_INFO_RE.test(combinedComments)) {
    return {
      status: 'insufficient_info',
      summary: 'Closed because requested reproduction detail, logs, or trace evidence was missing; no release fix proof is linked.',
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

  if (reasons.has('NOT_PLANNED') && !nonActionableState.supported) {
    if (closureContextComments.length === 0) {
      return {
        status: 'admin_not_planned_no_context',
        summary: 'Closed as not planned without trusted close-time rationale, release-fix proof, or non-actionable context.',
        evidence,
      };
    }
    return {
      status: 'admin_not_planned_unverified',
      summary: 'Closed as not planned without trusted release-fix proof or a concrete non-actionable rationale.',
      evidence,
    };
  }

  if (
    (reasons.has('NOT_PLANNED') || NO_PLAN_RE.test(combinedComments)) &&
    !nonActionableState.unresolvedVeto
  ) {
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
  const ordered = comments
    .map((comment, index) => ({
      comment,
      index,
      effectiveMs: commentEffectiveMs(comment),
    }))
    .sort((left, right) => {
      const leftFinite = Number.isFinite(left.effectiveMs);
      const rightFinite = Number.isFinite(right.effectiveMs);
      if (leftFinite && rightFinite && left.effectiveMs !== right.effectiveMs) {
        return left.effectiveMs - right.effectiveMs;
      }
      if (leftFinite !== rightFinite) return leftFinite ? -1 : 1;
      return left.index - right.index;
    });
  return ordered.flatMap(({ comment, effectiveMs }) => {
    if (
      Number.isFinite(effectiveMs) &&
      effectiveMs >= closedMs - CLOSURE_CONTEXT_BEFORE_MS &&
      effectiveMs <= closedMs + CLOSURE_CONTEXT_AFTER_MS
    ) {
      const rawBody = 'body' in comment ? String(comment.body ?? '') : '';
      const normalizedBody = rawBody.replace(/\s+/g, ' ');
      const relevant =
        CLOSURE_RATIONALE_RE.test(normalizedBody) ||
        hasNonActionableRationale(normalizedBody) ||
        hasExplicitOngoingFailure(normalizedBody);
      return relevant && !isClosureKeepOpenComment(rawBody) ? [comment] : [];
    }
    return [];
  });
}

function commentEffectiveMs(comment: {
  createdAt?: string | null;
  created_at?: string | null;
  updatedAt?: string | null;
  updated_at?: string | null;
}): number {
  const createdAt = comment.createdAt ?? comment.created_at ?? null;
  const updatedAt = comment.updatedAt ?? comment.updated_at ?? null;
  const createdMs = createdAt ? Date.parse(createdAt) : Number.NaN;
  const updatedMs = updatedAt ? Date.parse(updatedAt) : Number.NaN;
  return Number.isFinite(updatedMs) &&
      (!Number.isFinite(createdMs) || updatedMs > createdMs)
    ? updatedMs
    : createdMs;
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

export function isClosureKeepOpenComment(text: string): boolean {
  return text
    .split(/\n+/)
    .map((line) => line.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .some((line) => {
      if (NOT_KEEP_OPEN_RE.test(line)) return false;
      if (CURRENT_SUBJECT_KEEP_OPEN_RE.test(line)) return true;
      if (OTHER_ISSUES_KEEP_OPEN_RE.test(line)) return false;
      return GENERIC_KEEP_OPEN_RE.test(line);
    });
}

function hasNonActionableRationale(text: string): boolean {
  return nonActionableRationaleState(text).supported;
}

function nonActionableRationaleState(text: string): {
  supported: boolean;
  unresolvedVeto: boolean;
} {
  let supported = false;
  let unresolvedVeto = false;
  for (const signal of nonActionableRationaleSignals(text)) {
    if (signal === 'veto') {
      supported = false;
      unresolvedVeto = true;
      continue;
    }
    supported = true;
    unresolvedVeto = false;
  }
  return { supported, unresolvedVeto };
}

function nonActionableRationaleSignals(text: string): Array<'support' | 'veto'> {
  const signals: Array<'support' | 'veto'> = [];
  for (const clause of text.split(NON_ACTIONABLE_CLAUSE_BREAK_RE)) {
    if (
      NON_ACTIONABLE_UNCERTAINTY_RE.test(clause) ||
      hasExplicitOngoingFailure(clause)
    ) {
      signals.push('veto');
      continue;
    }
    if (DECISIVE_NON_ACTIONABLE_RATIONALE_RE.test(clause) || NON_ACTIONABLE_RATIONALE_RE.test(clause)) {
      signals.push('support');
    }
  }
  return signals;
}

function hasExplicitOngoingFailure(text: string): boolean {
  EXPLICIT_ONGOING_FAILURE_RE.lastIndex = 0;
  for (const match of text.matchAll(EXPLICIT_ONGOING_FAILURE_RE)) {
    const start = match.index ?? 0;
    const prefix = text.slice(Math.max(0, start - 100), start);
    if (/\bif\b[^.!?;]{0,100}$/i.test(prefix)) continue;
    if (NEGATED_ONGOING_FAILURE_PREFIX_RE.test(prefix)) continue;
    return true;
  }
  return false;
}

function hasDuplicateOrSupersededSignal(text: string, reasons: Set<string>): boolean {
  if (reasons.has('DUPLICATE')) return true;
  if (!DUPLICATE_RE.test(text)) return false;
  if (NOT_DUPLICATE_RE.test(text)) return false;
  if (canonicalIssueNumbers(text).length > 0) return true;
  const lines = text.split(/\n+/).map((line) => line.trim()).filter(Boolean);
  return lines.some((line) => DUPLICATE_RATIONALE_RE.test(line));
}

function matchingCommentSnippets(comments: ClosureProofInput['comments']): Array<{
  databaseId?: number | null;
  issueNumber?: number | null;
  url?: string | null;
  author: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  snippet: string;
}> {
  return comments
    .filter((comment) => {
      const body = comment.body ?? '';
      return DUPLICATE_RE.test(body) || ALREADY_PRESENT_RE.test(body) || MAIN_ONLY_RE.test(body) || NO_PLAN_RE.test(body) ||
        REPORTER_REPLACED_RE.test(body) || REPORTER_WITHDRAWN_RE.test(body) || REPRO_REQUESTED_RE.test(body) ||
        INSUFFICIENT_INFO_RE.test(body) || hasExplicitOngoingFailure(body);
    })
    .slice(-3)
    .map((comment) => ({
      ...commentReferenceFields(comment),
      author: comment.author ?? null,
      createdAt: comment.createdAt ?? null,
      updatedAt: comment.updatedAt ?? null,
      snippet: (comment.body ?? '').replace(/\s+/g, ' ').slice(0, 500),
    }));
}

function nonActionableRationaleSnippets(comments: ClosureProofInput['comments']): Array<{
  databaseId?: number | null;
  issueNumber?: number | null;
  url?: string | null;
  author: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  snippet: string;
}> {
  let supported = false;
  const supportingComments: ClosureProofInput['comments'] = [];
  for (const comment of comments) {
    let commentSupports = false;
    for (const signal of nonActionableRationaleSignals(comment.body ?? '')) {
      if (signal === 'veto') {
        supported = false;
        commentSupports = false;
        supportingComments.length = 0;
        continue;
      }
      supported = true;
      commentSupports = true;
    }
    if (supported && commentSupports) supportingComments.push(comment);
  }
  if (!supported) return [];
  return supportingComments
    .slice(-3)
    .map((comment) => ({
      ...commentReferenceFields(comment),
      author: comment.author ?? null,
      createdAt: comment.createdAt ?? null,
      updatedAt: comment.updatedAt ?? null,
      snippet: (comment.body ?? '').replace(/\s+/g, ' ').slice(0, 500),
    }));
}

function commentReferenceFields(comment: ClosureProofInput['comments'][number]): {
  databaseId?: number | null;
  issueNumber?: number | null;
  url?: string | null;
} {
  const databaseId = Number(comment.id ?? 0);
  const issueNumber = Number(comment.issueNumber ?? 0);
  const fields: { databaseId?: number; issueNumber?: number; url?: string } = {};
  if (Number.isInteger(databaseId) && databaseId > 0) fields.databaseId = databaseId;
  if (Number.isInteger(issueNumber) && issueNumber > 0) fields.issueNumber = issueNumber;
  if (typeof comment.url === 'string' && comment.url) fields.url = comment.url;
  return fields;
}
