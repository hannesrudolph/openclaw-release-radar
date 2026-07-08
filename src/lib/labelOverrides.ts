import type {
  AffectedUsers,
  Functionality,
  IssueClassification,
  Scope,
  Sentiment,
  Severity,
  WorkaroundStatus,
} from './llm';
import {
  scoreAuthorityReferenceProblems,
  type ScoreAuthorityReference,
} from './scoreAuthorityResolution';

// Deterministic post-processing on top of LLM output.
//
// CORE MODEL: labels carry categorization metadata by default. A label may
// directly change sentiment, severity, or confidence only when the caller
// supplies the named non-automation actor responsible for its current state.
//
//   * `impact:*` labels = CATEGORIZATION BY DEFAULT.
//     ClawSweeper bot stamps these via keyword-matching on the issue body. They
//     correctly identify WHICH surface is touched ("message delivery", "session
//     state", "auth providers") but say NOTHING about how bad the bug is. We
//     translate them into `functionality` only. The single human-applied exception is
//     `impact:data-loss`, which is event-based ("data has been lost") rather
//     than category-based, and warrants a severity floor.
//
//   * Human-applied `P0`, `beta-blocker`, `regression` = MAINTAINER PRIORITIZATION.
//     A human maintainer deciding "this is critical" or "this regressed". These
//     DO override severity (raise only, never lower).
//
//   * Human-applied `enhancement`, `stale`, `clawsweeper:not-repro-on-main` =
//     FACTUAL STATE.
//     Override sentiment to neutral — they assert "this isn't actually an open
//     actionable bug right now."
//
//   * Human-applied `clawsweeper:*-repro` / `needs-info` / `needs-live-repro` =
//     VERIFICATION.
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
// Human-applied `impact:data-loss` is *also* a severity floor (handled below).
const FUNCTIONALITY_HINTS: Readonly<Record<string, Functionality>> = Object.freeze({
  'impact:data-loss':     'core',
  'impact:message-loss':  'integration',
  'impact:auth-provider': 'provider',
});

const FUNCTIONALITY_PRIORITY: Functionality[] = [
  'core',
  'provider',
  'integration',
  'tooling',
  'docs',
];

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

// Title-based functionality inference. The model systematically marks some
// non-runtime work as a runtime surface, even with explicit anti-inflation
// examples in the prompt. Tooling must name developer infrastructure directly;
// CI/test/build context alone is not enough to zero a runtime failure.
const TOOLING_RE = new RegExp([
  String.raw`\b(?:test|testing)\s+(?:infrastructure|suite|runner|harness|fixtures?|coverage)\b`,
  String.raw`\bfixture\s+harness\b`,
  String.raw`\b(?:unit|integration|end[- ]to[- ]end|e2e|smoke|snapshot|flaky)\s+tests?\b`,
  String.raw`\b(?:ci|continuous integration|github actions?)\s+(?:workflow|jobs?|pipeline|runner)\b`,
  String.raw`\bbuild[- ]only\b`,
  String.raw`\bbuild\s+(?:pipeline|system|scripts?|tooling)\b`,
  String.raw`\b(?:lint(?:er|ing)?|eslint|prettier|type[- ]?check(?:er|ing)?|type checking|developer tooling|dev tooling)\b`,
  String.raw`\b(?:code|source)\s+(?:formatter|formatting)\b`,
  String.raw`\bformatting\s+(?:checks?|tooling)\b`,
  String.raw`\b(?:test harness|fixture)\s+(?:issue|failure|bug)\b`,
].join('|'), 'i');
const CHANNEL_RE = /\b(telegram|discord|slack|feishu|whatsapp|mattermost|imessage|tiktok|lark|wechat|weixin|kakao|kakaotalk|line bot|signal)\b/i;
const PROVIDER_RE = /\b(ollama|openai|anthropic|claude|llama\.cpp|llama\b|codex|deepseek|xai|minimax|bedrock|gemini|mistral|qwen)\b/i;
// Plugin / subagent / MCP + control-UI / dashboard / webchat — extension and UI
// surfaces, not the core engine. A broken dashboard or WebChat channel adapter
// doesn't break OpenClaw's gateway/CLI itself.
const EXTENSION_RE = /\b(plugin|subagent|mcp|control[- ]ui|dashboard|webchat|skills?[- ]ui)\b/i;
const RUNTIME_FAILURE_TARGET_SOURCE = [
  String.raw`\b(?:install(?:er|ation)?|updates?|gateway|startup|boot|cli|chat|sessions?|auth(?:entication)?|login|exec(?:ution)?|approvals?|doctor|daemon|storage)\b`,
  String.raw`\b(?:messages?|message delivery|webhooks?|channels?|adapters?|requests?|responses?|streams?|tool calls?|providers?|inference|embeddings?)\b`,
  CHANNEL_RE.source,
  PROVIDER_RE.source,
  EXTENSION_RE.source,
].join('|');
const RUNTIME_FAILURE_SIGNAL_SOURCE = [
  String.raw`fail(?:s|ed|ing|ure)?|error(?:s|ed|ing)?|break(?:s|ing)?|broke|broken|crash(?:es|ed|ing)?`,
  String.raw`hang(?:s|ing)?|time(?:s|d)?\s*out|timeout(?:s|ed)?|drop(?:s|ped|ping)?|lost|leak(?:s|ed|ing)?`,
  String.raw`corrupt(?:s|ed|ing)?|deadlock(?:s|ed|ing)?|stall(?:s|ed|ing)?|reject(?:s|ed|ing)?`,
  String.raw`stuck|unavailable|unusable|wrong|cannot|can't|unable`,
  String.raw`(?:does|did|will)\s+not\s+(?:work|start|open|load|send|receive|connect|run)`,
].join('|');
const TOOLING_SUBJECT_SOURCE = [
  String.raw`tests?|testing|suite|runner|harness|fixtures?|coverage`,
  String.raw`ci|workflow|jobs?|pipeline|build`,
  String.raw`lint(?:er|ing)?|eslint|prettier|type[- ]?check(?:er|ing)?|format(?:ter|ting)?`,
].join('|');
const RUNTIME_FAILURE_TARGET_RE = new RegExp(
  String.raw`(?:${RUNTIME_FAILURE_TARGET_SOURCE})` +
    String.raw`(?:(?!\b(?:${TOOLING_SUBJECT_SOURCE})\b).){0,80}` +
    String.raw`\b(?:${RUNTIME_FAILURE_SIGNAL_SOURCE})\b`,
  'i',
);
const FAILED_RUNTIME_SURFACE_RE = new RegExp(
  String.raw`\b(?:failed|failing|broken|dropped|lost|corrupted|stuck|unavailable|wrong|rejected)\s+` +
    String.raw`(?:messages?|message delivery|requests?|responses?|webhooks?|sessions?|authentication|login|gateway|startup|cli|daemon|storage)\b`,
  'i',
);
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
const SCORE_AUTHORITY_LABELS = new Set([
  ...STRONG_BUG_LABELS,
  ...CLOSURE_RISK_IMPACT_LABELS,
  'P1',
  'clawsweeper:current-main-repro',
  'clawsweeper:needs-info',
  'clawsweeper:needs-live-repro',
  'clawsweeper:not-repro-on-main',
  'clawsweeper:source-repro',
  'enhancement',
  'stale',
]);
const BUG_SHAPED_TITLE_RE = /\b(bug|fail(?:s|ed|ure)?|error|crash|stuck|regression|broken|lost|timeout|leak|silently|dropped|corrupt|deadlock|stall|never executed|not executed)\b/i;

export interface LabelOverrideAuthority {
  // Actor responsible for the label's current applied state. This is provenance
  // only and cannot grant scoring authority.
  labelActors?: Readonly<Record<string, string | null | undefined>>;
  // Immutable authorization decisions are the only source of scoring authority.
  // Missing or empty authority fails closed.
  authorizedScoringLabels?: ReadonlySet<string> | readonly string[];
  authorityReferences?: Readonly<
    Record<string, ScoreAuthorityReference | undefined>
  >;
}

export function labelAuthorizedForScoring(
  labelName: string,
  authority: LabelOverrideAuthority | undefined,
): boolean {
  const authorized = authority?.authorizedScoringLabels;
  if (!authorized) return false;
  const listed = typeof (authorized as ReadonlySet<string>).has === 'function'
    ? (authorized as ReadonlySet<string>).has(labelName)
    : (authorized as readonly string[]).includes(labelName);
  if (!listed) return false;
  const reference = authority?.authorityReferences?.[labelName];
  return scoreAuthorityReferenceProblems(reference).length === 0 &&
    reference?.subjectKind === 'label_event';
}

export function labelUsesScoreAuthority(labelName: string): boolean {
  return SCORE_AUTHORITY_LABELS.has(labelName);
}

function isHumanAppliedLabel(
  labelName: string,
  authority: LabelOverrideAuthority | undefined,
): boolean {
  return labelAuthorizedForScoring(labelName, authority);
}

function inferRuntimeFailureFunctionalityFromTitle(
  title: string,
): Functionality | undefined {
  if (
    !RUNTIME_FAILURE_TARGET_RE.test(title) &&
    !FAILED_RUNTIME_SURFACE_RE.test(title)
  ) {
    return undefined;
  }
  if (CHANNEL_RE.test(title))   return 'integration';
  if (PROVIDER_RE.test(title))  return 'provider';
  if (EXTENSION_RE.test(title)) return 'integration';
  return 'core';
}

export function inferFunctionalityFromTitle(title: string): Functionality | undefined {
  const runtimeFailure = inferRuntimeFailureFunctionalityFromTitle(title);
  if (runtimeFailure) return runtimeFailure;
  if (TOOLING_RE.test(title)) return 'tooling';
  if (CHANNEL_RE.test(title))   return 'integration';
  if (PROVIDER_RE.test(title))  return 'provider';
  if (EXTENSION_RE.test(title)) return 'integration';
  return undefined;
}

// Title-only tooling hints cannot replace a body-grounded runtime classification
// with zero-weight tooling. Conversely, an explicit runtime-failure title can
// repair model-selected tooling. Existing channel/provider/extension routing
// remains core-only because incidental names must not rewrite one non-core
// runtime surface into another.
export function applyTitleFunctionalityHint(
  c: IssueClassification,
  title: string,
): IssueClassification {
  if (c.functionality === 'tooling') {
    const runtimeFailure = inferRuntimeFailureFunctionalityFromTitle(title);
    return runtimeFailure
      ? { ...c, functionality: runtimeFailure }
      : c;
  }
  if (c.functionality !== 'core') return c;
  const hint = inferFunctionalityFromTitle(title);
  return hint && hint !== 'tooling'
    ? { ...c, functionality: hint }
    : c;
}

export function applyTitleIssueShapeHint(
  c: IssueClassification,
  title: string,
  labelNames: string[] = [],
  authority?: LabelOverrideAuthority,
): IssueClassification {
  const hasStrongBugLabel = labelNames.some((label) =>
    STRONG_BUG_LABELS.has(label) && isHumanAppliedLabel(label, authority));
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
  authority?: LabelOverrideAuthority,
): IssueClassification {
  if (c.sentiment === 'negative' || c.sentiment === 'positive') return c;
  const has = (name: string): boolean => labelNames.includes(name);
  const hasTrusted = (name: string): boolean =>
    has(name) && isHumanAppliedLabel(name, authority);
  const hasAnyTrusted = (names: Iterable<string>): boolean => {
    for (const name of names) if (hasTrusted(name)) return true;
    return false;
  };
  const hasStrongBugLabel = hasAnyTrusted(STRONG_BUG_LABELS);
  const hasRepro = hasTrusted('clawsweeper:source-repro') ||
    hasTrusted('clawsweeper:current-main-repro');
  const hasImpact = hasAnyTrusted(CLOSURE_RISK_IMPACT_LABELS);
  const hasDataLoss = hasTrusted('impact:data-loss');
  const hasMaintainerPriority = hasTrusted('P0') ||
    hasTrusted('P1') ||
    hasTrusted('beta-blocker') ||
    hasTrusted('regression');
  const affectsKnownRelease = typeof c.affectsVersion === 'string' && c.affectsVersion.trim() !== '';
  const bugShapedTitle = BUG_SHAPED_TITLE_RE.test(title);
  if (!hasStrongBugLabel && NON_BUG_TITLE_RE.test(title)) return c;
  const featureOnly = hasTrusted('enhancement') &&
    !hasRepro &&
    !affectsKnownRelease &&
    !hasDataLoss &&
    !bugShapedTitle;
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
  authority?: LabelOverrideAuthority,
): IssueClassification {
  const has = (name: string): boolean => labelNames.includes(name);
  const hasTrusted = (name: string): boolean =>
    has(name) && isHumanAppliedLabel(name, authority);
  const hasAnyTrusted = (...names: string[]): boolean =>
    names.some((name) => hasTrusted(name));

  let sentiment: Sentiment = c.sentiment;
  let severity: Severity = c.severity;
  const scope: Scope = c.scope;
  let functionality: Functionality = c.functionality;
  const affectedUsers: AffectedUsers = c.affectedUsers;
  const workaroundStatus: WorkaroundStatus = c.workaroundStatus;
  let confidence = c.confidence;

  // --- Sentiment overrides (factual state) --------------------------------
  if (hasTrusted('enhancement')) {
    sentiment = 'neutral';
  }
  if (hasTrusted('stale')) {
    sentiment = 'neutral';
    confidence = Math.min(confidence, 0.5);
  }
  if (hasTrusted('clawsweeper:not-repro-on-main')) {
    sentiment = 'neutral';
    confidence = Math.min(confidence, 0.6);
  }

  // --- Functionality hints (impact:* categorization) ----------------------
  functionality = chooseFunctionality(functionality, labelNames);

  // --- Severity overrides (event-based + maintainer prioritization) -------
  // impact:data-loss is event-based — the maintainer is asserting data CAN be
  // lost or corrupted. This is not a category; it's a fact about consequence.
  if (hasTrusted('impact:data-loss')) {
    severity = 'critical';
  }
  // P0 / beta-blocker = explicit emergency from a human.
  if (hasAnyTrusted('P0', 'beta-blocker')) {
    severity = 'critical';
  }
  // Regression = "something that used to work no longer works." This deserves
  // a bump because regressions are categorically worse than fresh bugs at the
  // same surface (users were relying on it).
  if (hasTrusted('regression')) {
    severity = bumpSeverity(severity);
  }

  // --- Confidence overrides (verification status) -------------------------
  if (hasAnyTrusted('clawsweeper:source-repro', 'clawsweeper:current-main-repro')) {
    confidence = Math.max(confidence, 0.9);
  }
  if (hasAnyTrusted('clawsweeper:needs-info', 'clawsweeper:needs-live-repro')) {
    confidence = Math.min(confidence, 0.5);
  }

  return {
    sentiment,
    severity,
    scope,
    functionality,
    affectedUsers,
    ...(typeof c.hasWorkaround === 'boolean' ? { hasWorkaround: c.hasWorkaround } : {}),
    workaroundStatus,
    duplicateCluster: c.duplicateCluster,
    affectsVersion: c.affectsVersion,
    confidence: clamp01(confidence),
    rationale: c.rationale,
  };
}
