import type {
  AffectedUsers,
  Functionality,
  IssueClassification,
  Scope,
  Sentiment,
  Severity,
  WorkaroundStatus,
} from './llm';

// Deterministic post-processing on top of LLM output. The LLM still drives most of
// the classification — these overrides are a safety net for labels that openclaw
// maintainers attach with explicit semantic meaning. A maintainer who attaches
// `impact:data-loss` is asserting the bug can lose data; we should not let the LLM
// downgrade that to medium.
//
// Rules are intentionally one-directional: severity is only ever raised, never
// lowered. The exceptions are sentiment (→ neutral) and confidence (→ down) when
// the labels explicitly signal "this isn't actually a confirmed bug" (stale,
// not-repro-on-main, enhancement).

const SEVERITY_BY_RANK: Severity[] = ['low', 'medium', 'high', 'critical'];
const SEVERITY_RANK: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function raiseSeverity(current: Severity, atLeast: Severity): Severity {
  return SEVERITY_RANK[current] >= SEVERITY_RANK[atLeast] ? current : atLeast;
}

function bumpSeverity(s: Severity): Severity {
  return SEVERITY_BY_RANK[Math.min(3, SEVERITY_RANK[s] + 1)];
}

function clamp01(x: number): number {
  if (Number.isNaN(x)) return 0.5;
  return Math.max(0, Math.min(1, x));
}

export function applyLabelOverrides(
  c: IssueClassification,
  labelNames: string[],
): IssueClassification {
  const has = (name: string): boolean => labelNames.includes(name);
  const hasAny = (...names: string[]): boolean => names.some((n) => labelNames.includes(n));

  // Snapshot — overrides only widen severity / change sentiment, never shrink.
  let sentiment: Sentiment = c.sentiment;
  let severity: Severity = c.severity;
  const scope: Scope = c.scope;
  let functionality: Functionality = c.functionality;
  const affectedUsers: AffectedUsers = c.affectedUsers;
  const workaroundStatus: WorkaroundStatus = c.workaroundStatus;
  let confidence = c.confidence;

  // --- Sentiment overrides -------------------------------------------------
  // enhancement = feature request, even if title says "[Bug]".
  if (has('enhancement')) {
    sentiment = 'neutral';
  }
  // stale issues are no longer actionable signal.
  if (has('stale')) {
    sentiment = 'neutral';
    confidence = Math.min(confidence, 0.5);
  }
  // ClawSweeper explicitly verified the issue no longer reproduces on main.
  if (has('clawsweeper:not-repro-on-main')) {
    sentiment = 'neutral';
    confidence = Math.min(confidence, 0.6);
  }

  // --- Severity floors (impact:* and explicit priority labels) ------------
  // impact:data-loss → critical. Maintainer asserts data can be lost/corrupted.
  if (has('impact:data-loss')) {
    severity = 'critical';
    if (functionality === 'docs' || functionality === 'integration') {
      functionality = 'core';
    }
  }
  // P0 / beta-blocker = explicit emergency priority.
  if (hasAny('P0', 'beta-blocker')) {
    severity = 'critical';
  }
  // impact:security = at minimum high (often critical), and it's a core concern.
  if (has('impact:security')) {
    severity = raiseSeverity(severity, 'high');
    if (functionality === 'docs') functionality = 'core';
  }
  // impact:crash-loop = process-level availability failure → at minimum high.
  if (has('impact:crash-loop')) {
    severity = raiseSeverity(severity, 'high');
  }
  // impact:session-state = state corruption/drift → at minimum high.
  if (has('impact:session-state')) {
    severity = raiseSeverity(severity, 'high');
  }
  // impact:message-loss = delivery failure → at minimum high.
  if (has('impact:message-loss')) {
    severity = raiseSeverity(severity, 'high');
  }
  // impact:auth-provider = auth/provider breakage → at minimum high.
  if (has('impact:auth-provider')) {
    severity = raiseSeverity(severity, 'high');
  }

  // --- Regression: bump severity one rung (capped at critical) -------------
  // A regression of a "low" bug becomes medium, medium becomes high, etc.
  // Combined with impact:* floors this can compound (high → critical when both
  // regression AND impact:crash-loop apply, which is correct).
  if (has('regression')) {
    severity = bumpSeverity(severity);
  }

  // --- Confidence boosts / drops from ClawSweeper repro signals -----------
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
