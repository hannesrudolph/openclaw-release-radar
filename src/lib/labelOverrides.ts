import type {
  AffectedUsers,
  Functionality,
  IssueClassification,
  Scope,
  Sentiment,
  Severity,
  WorkaroundStatus,
} from './llm';

// Deterministic post-processing on top of LLM output.
//
// CORE MODEL: labels carry one of three kinds of signal — categorization, severity,
// or factual state — and we must NOT conflate them.
//
//   * `impact:*` labels = CATEGORIZATION ONLY.
//     ClawSweeper bot stamps these via keyword-matching on the issue body. They
//     correctly identify WHICH surface is touched ("message delivery", "session
//     state", "auth providers") but say NOTHING about how bad the bug is. We
//     translate them into `functionality` only. The single exception is
//     `impact:data-loss`, which is event-based ("data has been lost") rather
//     than category-based, and warrants a severity floor.
//
//   * `P0`, `beta-blocker`, `regression` = MAINTAINER PRIORITIZATION.
//     A human maintainer deciding "this is critical" or "this regressed". These
//     DO override severity (raise only, never lower).
//
//   * `enhancement`, `stale`, `clawsweeper:not-repro-on-main` = FACTUAL STATE.
//     Override sentiment to neutral — they assert "this isn't actually an open
//     actionable bug right now."
//
//   * `clawsweeper:*-repro` / `needs-info` / `needs-live-repro` = VERIFICATION.
//     Override confidence based on how well the issue is reproduced.
//
// Severity is otherwise the LLM's job — it reads the body + comments and judges
// the actual badness. Previously we floored severity to "high" on every
// `impact:session-state` / `impact:message-loss` / `impact:auth-provider` label,
// which produced ~93% high+core classifications because ClawSweeper attaches
// those to nearly every issue. This file no longer does that.

const SEVERITY_BY_RANK: Severity[] = ['low', 'medium', 'high', 'critical'];
const SEVERITY_RANK: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function bumpSeverity(s: Severity): Severity {
  return SEVERITY_BY_RANK[Math.min(3, SEVERITY_RANK[s] + 1)];
}

function clamp01(x: number): number {
  if (Number.isNaN(x)) return 0.5;
  return Math.max(0, Math.min(1, x));
}

// `impact:*` labels map to a functionality area. We only trust hints that are
// event-based and rare — i.e., where a false positive is unlikely. ClawSweeper
// keyword-stamps `impact:session-state`, `impact:crash-loop`, `impact:security`
// on anything mentioning "session", "crash", "security" — these labels touch
// ~60% of issues, and routing all of them to `core` produced ~76% core-serious
// classification (real number was likely ~15%), which crashed every recent
// release to the 1.0 floor. We now leave functionality to the LLM for those
// keyword-based labels and only override on:
//   - `impact:data-loss` — event-based ("data has been lost"), rare, severe
//   - `impact:message-loss` / `impact:auth-provider` — refine docs/unknown toward
//      the right surface but never elevate to core
// `impact:data-loss` is *also* a severity floor (handled separately below).
const FUNCTIONALITY_HINTS: Readonly<Record<string, Functionality>> = Object.freeze({
  'impact:data-loss':     'core',
  'impact:message-loss':  'integration',
  'impact:auth-provider': 'provider',
});

const FUNCTIONALITY_PRIORITY: Functionality[] = ['core', 'provider', 'integration', 'docs'];

function chooseFunctionality(
  current: Functionality,
  labelNames: string[],
): Functionality {
  const hinted: Functionality[] = [];
  for (const name of labelNames) {
    const hint = FUNCTIONALITY_HINTS[name];
    if (hint) hinted.push(hint);
  }
  if (hinted.length === 0) return current;
  // Pick the most-core hint among the labels present. The hints we keep here
  // are all trustworthy (event-based / explicit), so they OVERRIDE the LLM
  // — including when they would route DOWN from core to integration/provider.
  // The previous "up-cast only" rule preserved LLM bias on core: gpt-4o-mini
  // marks any chat/Discord/Telegram issue as core, and the override silently
  // accepted that. Now an `impact:message-loss` issue resolves to integration
  // even if the LLM said core.
  hinted.sort(
    (a, b) => FUNCTIONALITY_PRIORITY.indexOf(a) - FUNCTIONALITY_PRIORITY.indexOf(b),
  );
  return hinted[0];
}

// Title-based functionality inference. gpt-4o-mini systematically marks any bug
// touching a third-party channel/provider name as `core`, even with explicit
// anti-inflation examples in the prompt. Heuristic safety net: if the title
// names a channel or provider, route the bug to integration/provider — channel
// adapters and provider quirks do NOT break OpenClaw's core engine.
const CHANNEL_RE = /\b(telegram|discord|slack|feishu|whatsapp|mattermost|imessage|tiktok|lark|wechat|weixin|kakao|kakaotalk|line bot|signal)\b/i;
const PROVIDER_RE = /\b(ollama|openai|anthropic|claude|llama\.cpp|llama\b|codex|deepseek|xai|minimax|bedrock|gemini|mistral|qwen)\b/i;
// Plugin / subagent / MCP + control-UI / dashboard / webchat — extension and UI
// surfaces, not the core engine. A broken dashboard or WebChat channel adapter
// doesn't break OpenClaw's gateway/CLI itself.
const EXTENSION_RE = /\b(plugin|subagent|mcp|control[- ]ui|dashboard|webchat|skills?[- ]ui)\b/i;
const NON_BUG_TITLE_RE = /\b(feature|feedback|roadmap|proposal|support|question|how do i|should support|preserve or explicitly support)\b|^\s*\[(feature|feedback|proposal|backup)\]/i;
const STRONG_BUG_LABELS = new Set(['bug', 'regression', 'P0', 'beta-blocker']);
const CLOSURE_RISK_IMPACT_LABELS = new Set([
  'impact:auth-provider',
  'impact:crash-loop',
  'impact:data-loss',
  'impact:message-loss',
  'impact:security',
  'impact:session-state',
]);
const BUG_SHAPED_TITLE_RE = /\b(bug|fail(?:s|ed|ure)?|error|crash|stuck|regression|broken|lost|timeout|leak|silently|dropped|corrupt|deadlock|stall|never executed|not executed)\b/i;

export function inferFunctionalityFromTitle(title: string): Functionality | undefined {
  if (CHANNEL_RE.test(title))   return 'integration';
  if (PROVIDER_RE.test(title))  return 'provider';
  if (EXTENSION_RE.test(title)) return 'integration';
  return undefined;
}

// Apply only when LLM picked `core` — otherwise trust the LLM (it might have
// correctly identified that, e.g., "Telegram session-storage corruption" is
// genuinely a core/session bug that mentions Telegram incidentally).
export function applyTitleFunctionalityHint(
  c: IssueClassification,
  title: string,
): IssueClassification {
  if (c.functionality !== 'core') return c;
  const hint = inferFunctionalityFromTitle(title);
  return hint ? { ...c, functionality: hint } : c;
}

export function applyTitleIssueShapeHint(
  c: IssueClassification,
  title: string,
  labelNames: string[] = [],
): IssueClassification {
  const hasStrongBugLabel = labelNames.some((label) => STRONG_BUG_LABELS.has(label));
  if (!hasStrongBugLabel && NON_BUG_TITLE_RE.test(title)) {
    return {
      ...c,
      sentiment: 'neutral',
      severity: c.severity === 'critical' || c.severity === 'high' ? 'medium' : c.severity,
      confidence: Math.min(c.confidence, 0.65),
    };
  }
  return c;
}

export function applyClosureRiskSentimentHint(
  c: IssueClassification,
  title: string,
  labelNames: string[] = [],
): IssueClassification {
  if (c.sentiment === 'negative' || c.sentiment === 'positive') return c;
  const has = (name: string): boolean => labelNames.includes(name);
  const hasAny = (names: Iterable<string>): boolean => {
    for (const name of names) if (has(name)) return true;
    return false;
  };
  const hasStrongBugLabel = hasAny(STRONG_BUG_LABELS);
  const hasRepro = has('clawsweeper:source-repro') || has('clawsweeper:current-main-repro');
  const hasImpact = hasAny(CLOSURE_RISK_IMPACT_LABELS);
  const hasDataLoss = has('impact:data-loss');
  const hasMaintainerPriority = has('P0') || has('P1') || has('beta-blocker') || has('regression');
  const affectsKnownRelease = typeof c.affectsVersion === 'string' && c.affectsVersion.trim() !== '';
  const bugShapedTitle = BUG_SHAPED_TITLE_RE.test(title);
  const featureOnly = has('enhancement') && !hasRepro && !affectsKnownRelease && !hasDataLoss && !bugShapedTitle;
  if (featureOnly) return c;
  const hasClosureRiskSignal = hasStrongBugLabel ||
    hasDataLoss ||
    (hasRepro && hasImpact) ||
    (bugShapedTitle && (hasImpact || hasRepro || hasMaintainerPriority || affectsKnownRelease)) ||
    (affectsKnownRelease && (hasImpact || hasRepro || bugShapedTitle));
  return hasClosureRiskSignal ? { ...c, sentiment: 'negative' } : c;
}

export function applyLabelOverrides(
  c: IssueClassification,
  labelNames: string[],
): IssueClassification {
  const has = (name: string): boolean => labelNames.includes(name);
  const hasAny = (...names: string[]): boolean => names.some((n) => labelNames.includes(n));

  let sentiment: Sentiment = c.sentiment;
  let severity: Severity = c.severity;
  const scope: Scope = c.scope;
  let functionality: Functionality = c.functionality;
  const affectedUsers: AffectedUsers = c.affectedUsers;
  const workaroundStatus: WorkaroundStatus = c.workaroundStatus;
  let confidence = c.confidence;

  // --- Sentiment overrides (factual state) --------------------------------
  if (has('enhancement')) {
    sentiment = 'neutral';
  }
  if (has('stale')) {
    sentiment = 'neutral';
    confidence = Math.min(confidence, 0.5);
  }
  if (has('clawsweeper:not-repro-on-main')) {
    sentiment = 'neutral';
    confidence = Math.min(confidence, 0.6);
  }

  // --- Functionality hints (impact:* categorization) ----------------------
  functionality = chooseFunctionality(functionality, labelNames);

  // --- Severity overrides (event-based + maintainer prioritization) -------
  // impact:data-loss is event-based — the maintainer is asserting data CAN be
  // lost or corrupted. This is not a category; it's a fact about consequence.
  if (has('impact:data-loss')) {
    severity = 'critical';
  }
  // P0 / beta-blocker = explicit emergency from a human.
  if (hasAny('P0', 'beta-blocker')) {
    severity = 'critical';
  }
  // Regression = "something that used to work no longer works." This deserves
  // a bump because regressions are categorically worse than fresh bugs at the
  // same surface (users were relying on it).
  if (has('regression')) {
    severity = bumpSeverity(severity);
  }

  // --- Confidence overrides (verification status) -------------------------
  if (hasAny('clawsweeper:source-repro', 'clawsweeper:current-main-repro')) {
    confidence = Math.max(confidence, 0.9);
  }
  if (hasAny('clawsweeper:needs-info', 'clawsweeper:needs-live-repro')) {
    confidence = Math.min(confidence, 0.5);
  }

  return {
    sentiment,
    severity,
    scope,
    functionality,
    affectedUsers,
    workaroundStatus,
    duplicateCluster: c.duplicateCluster,
    affectsVersion: c.affectsVersion,
    confidence: clamp01(confidence),
    rationale: c.rationale,
  };
}
