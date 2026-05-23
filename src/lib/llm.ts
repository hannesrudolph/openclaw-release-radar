import { config } from '../config';
import type { GhComment, GhIssue } from './github';

// 7-dimension classification, matches agent-watch taxonomy.
export type Sentiment = 'negative' | 'positive' | 'neutral';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Scope = 'broad' | 'moderate' | 'niche';
export type Functionality = 'core' | 'integration' | 'provider' | 'docs';
export type AffectedUsers = 'many' | 'some' | 'few' | 'unknown';
export type WorkaroundStatus = 'none' | 'partial' | 'confirmed' | 'unknown';

export interface IssueClassification {
  sentiment: Sentiment;
  severity: Severity;
  scope: Scope;
  functionality: Functionality;
  affectedUsers: AffectedUsers;
  workaroundStatus: WorkaroundStatus;
  duplicateCluster: string | null; // short label like "ollama-timeout" — same label across dupes
  affectsVersion: string | null;   // explicit release tag this issue affects, or null if not stated
  confidence: number;              // 0..1
  rationale: string;               // kept for DB compat, no longer generated
}

// Bumped whenever SYSTEM_PROMPT (or extraction logic) changes shape. Stored alongside each
// classification — refresh.ts re-classifies anything written under an older version, so a
// prompt fix automatically reshapes the whole dataset on the next cron tick.
export const PROMPT_VERSION = 2;

// Attribution philosophy (mirrors agent-watch):
// - The LLM is asked to identify the affected release ONLY when the issue explicitly
//   mentions one, or it's obvious from a stack trace / log / "I'm running vX.Y.Z" line.
// - When unclear, return null. Unattributed issues are intentionally ignored by scoring
//   so that long-running open bugs don't drag down every release.
//
// Bias correction (v2): gpt-4o-mini systematically picked the maximum on every axis —
// 78% high/broad/many, 97% core — because openclaw triage labels (P1, impact:crash-loop,
// impact:message-loss) read as panic to the model. The anchors below pull the default
// toward the middle and reserve the top of each scale for genuine showstoppers.
const SYSTEM_PROMPT = `You classify GitHub issues for the OpenClaw open-source project to estimate release stability.
Return ONLY a JSON object with these exact keys (no extra fields, no markdown):

{
  "sentiment":       "negative" | "positive" | "neutral",
  "severity":        "critical" | "high" | "medium" | "low",
  "scope":           "broad" | "moderate" | "niche",
  "functionality":   "core" | "integration" | "provider" | "docs",
  "affected_users":  "many" | "some" | "few" | "unknown",
  "workaroundStatus": "none" | "partial" | "confirmed" | "unknown",
  "duplicateCluster": "<kebab-slug>" | null,
  "affectsVersion":  "<exact-tag-from-known-list>" | null,
  "confidence":      0.0..1.0
}

Default toward the middle of each scale. Reserve the top rungs for issues where the
evidence is unambiguous. Triage labels alone (P1, impact:*, clawsweeper:*) are NOT
evidence — they are routing tags maintainers attach to almost every new bug, often
before reproduction. Look at the body and comments to judge the real impact.

SEVERITY anchors:
- "critical": confirmed data loss, security CVE, total outage of the gateway/CLI for
  users on default config. Do NOT use just because the title says "crash" — most crashes
  are condition-specific.
- "high": main flow broken under a common configuration; user-visible regression with
  no workaround. Default for confirmed bugs touching install/auth/chat/exec.
- "medium": bug under a specific setup, cosmetic regression, broken edge case, or
  any bug where a workaround is documented. THIS IS THE DEFAULT for routine bug reports.
- "low": typo, doc nit, log noise, very-niche edge case.

SCOPE anchors:
- "broad": affects users across multiple OSes / multiple providers / both CLI and UI.
- "moderate": affects one OS family, one major provider, or one surface (CLI-only,
  UI-only, gateway-only). DEFAULT for most bugs.
- "niche": one provider + one OS + one config combination, or behind a non-default flag.

FUNCTIONALITY anchors:
- "core": install, gateway boot, chat send/receive, session storage, auth, exec approval,
  the doctor command. The things that break "OpenClaw" itself.
- "integration": third-party surfaces — Telegram, Feishu, WebChat, Slack, IDE plugins,
  control UI. The chat works locally but a delivery channel is broken.
- "provider": specific model providers — Ollama, OpenAI, Anthropic, Codex, embeddings.
  The gateway works but one provider misbehaves.
- "docs": only documentation or examples.

AFFECTED_USERS anchors:
- "many": clearly reported by multiple distinct users in comments, OR default config on
  the most common platforms (macOS + Linux + Windows out of the box).
- "some": one OS family, one provider, one common config. DEFAULT when the reporter
  describes a real bug but you can't tell how widespread.
- "few": specific hardware, specific corporate proxy, specific exotic config.
- "unknown": no signal at all (issue is one line, no setup info, no comments).

SENTIMENT rules:
- Bug reports describing breakage → "negative".
- Feature requests, enhancements, "would be nice if…" → "neutral", EVEN IF the title
  says "[Bug]". Read the body. \`enhancement\` label or "Proposed solution" / "Alternatives
  considered" sections are strong signals of a feature request.
- Questions, support requests, "how do I…" → "neutral".
- Users explicitly saying something works well or thanking maintainers → "positive".

WORKAROUND:
- "confirmed": explicit working workaround or merged fix mentioned in the thread.
- "partial": workaround exists but is fragile, manual, or only works sometimes.
- "none": comments explicitly say no workaround is known.
- "unknown": no discussion of workaround either way. Use this freely.

duplicateCluster: short kebab-case tag for the underlying bug (e.g. "ollama-proxy-loopback").
Use the SAME tag for clearly duplicate issues. null if unique.

affectsVersion: set when the issue body, title, or comments mention a specific release
version. The mention can be in ANY of these forms — treat them all as equivalent:
  * "v2026.5.18", "2026.5.18", "OpenClaw 2026.5.18", "version 2026.5.18"
  * stack traces with the version
  * "Observed on X.Y.Z", "running X.Y.Z", "since X.Y.Z", "in X.Y.Z-beta.N"
Return the value as it appears in the known-tags list (e.g. always with the "v" prefix
if the canonical tag uses one). If the version mentioned doesn't match ANY known tag,
pick the closest one only if you're highly confident — otherwise return null.
Return null when no version is mentioned at all (e.g. "X is broken" with no version
context). Unattributed issues are dropped from scoring rather than dumped on the latest
release, so it's safe to be aggressive about matching when a version IS mentioned.

confidence: lower (≤0.6) when the issue body is empty/one-liner, when labels and body
disagree, or when you had to guess scope/users from setup hints. Higher (≥0.8) only when
the body unambiguously describes impact, surface, and reproduction.`;

interface OpenAIResp {
  choices: { message: { content: string } }[];
}

function buildUserMessage(
  issue: GhIssue,
  comments: GhComment[],
  knownTags: string[],
): string {
  const body = (issue.body ?? '').slice(0, 3000);
  const recentComments = comments
    .slice(-10)
    .map((c) => `@${c.user?.login ?? 'unknown'}: ${(c.body ?? '').slice(0, 800)}`)
    .join('\n---\n');
  return [
    `Known release tags (most recent first): ${knownTags.slice(0, 15).join(', ') || '(none)'}`,
    '',
    `Issue #${issue.number} (${issue.state})`,
    `Title: ${issue.title}`,
    `Author: @${issue.user?.login ?? 'unknown'}`,
    `Created: ${issue.created_at}`,
    `Comments count: ${issue.comments}`,
    `Labels: ${issue.labels.map((l) => l.name).join(', ') || '(none)'}`,
    '',
    'BODY:',
    body || '(empty)',
    '',
    'RECENT COMMENTS:',
    recentComments || '(none)',
  ].join('\n');
}

// Map an LLM-returned version reference to a canonical known tag.
// LLMs sometimes drop the "v" prefix or vice versa; we accept both forms so a
// mention of "2026.5.7" still matches the canonical tag "v2026.5.7".
function resolveAffectsVersion(
  raw: string | null | undefined,
  knownTags: string[],
): string | null {
  if (!raw || typeof raw !== 'string') return null;
  const candidate = raw.trim();
  if (!candidate) return null;
  if (knownTags.includes(candidate)) return candidate;
  const stripped = candidate.startsWith('v') ? candidate.slice(1) : candidate;
  for (const tag of knownTags) {
    const tagStripped = tag.startsWith('v') ? tag.slice(1) : tag;
    if (tagStripped === stripped) return tag; // return canonical form
  }
  return null;
}

export async function classifyIssue(
  issue: GhIssue,
  comments: GhComment[],
  knownTags: string[],
): Promise<IssueClassification> {
  if (!config.openai.apiKey) throw new Error('OPENAI_API_KEY is not set');

  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.openai.apiKey}`,
    },
    body: JSON.stringify({
      model: config.openai.model,
      temperature: 0.1,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: buildUserMessage(issue, comments, knownTags) },
      ],
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`OpenAI ${res.status}: ${text.slice(0, 300)}`);
  }

  const data = (await res.json()) as OpenAIResp;
  const raw = data.choices?.[0]?.message?.content ?? '{}';
  let parsed: Partial<IssueClassification>;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`OpenAI returned non-JSON: ${raw.slice(0, 200)}`);
  }

  const normalized = normalize(parsed);
  normalized.affectsVersion = resolveAffectsVersion(normalized.affectsVersion, knownTags);
  return normalized;
}

function normalize(r: Partial<IssueClassification>): IssueClassification {
  const sentiments: Sentiment[] = ['negative', 'positive', 'neutral'];
  const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
  const scopes: Scope[] = ['broad', 'moderate', 'niche'];
  const funcs: Functionality[] = ['core', 'integration', 'provider', 'docs'];
  const users: AffectedUsers[] = ['many', 'some', 'few', 'unknown'];
  const workarounds: WorkaroundStatus[] = ['none', 'partial', 'confirmed', 'unknown'];

  const oneOf = <T extends string>(val: unknown, allowed: T[], fallback: T): T =>
    allowed.includes(val as T) ? (val as T) : fallback;

  // Back-compat: older LLM responses might still send `hasWorkaround: true|false`.
  // Map them to the new enum so a re-prompt isn't strictly required.
  const wsRaw = (r as any).workaroundStatus
    ?? (typeof (r as any).hasWorkaround === 'boolean'
      ? ((r as any).hasWorkaround ? 'confirmed' : 'unknown')
      : undefined);

  return {
    sentiment: oneOf(r.sentiment, sentiments, 'neutral'),
    severity: oneOf(r.severity, severities, 'low'),
    scope: oneOf(r.scope, scopes, 'niche'),
    functionality: oneOf(r.functionality, funcs, 'integration'),
    affectedUsers: oneOf((r as any).affected_users ?? r.affectedUsers, users, 'unknown'),
    workaroundStatus: oneOf(wsRaw, workarounds, 'unknown'),
    duplicateCluster:
      typeof r.duplicateCluster === 'string' && r.duplicateCluster.trim()
        ? r.duplicateCluster.trim().toLowerCase()
        : null,
    affectsVersion:
      typeof r.affectsVersion === 'string' && r.affectsVersion.trim()
        ? r.affectsVersion.trim()
        : null,
    confidence: clamp01(typeof r.confidence === 'number' ? r.confidence : 0.5),
    rationale: typeof r.rationale === 'string' ? r.rationale.slice(0, 400) : '',
  };
}

function clamp01(x: number): number {
  if (Number.isNaN(x)) return 0.5;
  return Math.max(0, Math.min(1, x));
}
