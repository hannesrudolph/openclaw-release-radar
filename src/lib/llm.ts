import { config } from '../config';
import type { GhComment, GhIssue } from './github';

// 7-dimension classification, matches agent-watch taxonomy.
export type Sentiment = 'negative' | 'positive' | 'neutral';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Scope = 'broad' | 'moderate' | 'niche';
export type Functionality = 'core' | 'integration' | 'provider' | 'docs';
export type AffectedUsers = 'many' | 'some' | 'few' | 'unknown';

export interface IssueClassification {
  sentiment: Sentiment;
  severity: Severity;
  scope: Scope;
  functionality: Functionality;
  affectedUsers: AffectedUsers;
  hasWorkaround: boolean;
  duplicateCluster: string | null; // short label like "ollama-timeout" — same label across dupes
  affectsVersion: string | null;   // best-effort tag this issue likely affects
  confidence: number;              // 0..1
  rationale: string;               // 1 sentence
}

const SYSTEM_PROMPT = `You classify GitHub issues for the OpenClaw open-source project to estimate release stability.
Return ONLY a JSON object with these exact keys (no extra fields, no markdown):

{
  "sentiment":       "negative" | "positive" | "neutral",
  "severity":        "critical" | "high" | "medium" | "low",
  "scope":           "broad" | "moderate" | "niche",
  "functionality":   "core" | "integration" | "provider" | "docs",
  "affected_users":  "many" | "some" | "few" | "unknown",
  "hasWorkaround":   true | false,
  "duplicateCluster": "<kebab-slug>" | null,
  "affectsVersion":  "<tag>" | null,
  "confidence":      0.0..1.0,
  "rationale":       "<one sentence>"
}

Be conservative. Critical rules:
- An issue is "core" + "critical" + "broad" ONLY if it breaks main functionality for ALL users
  without specific conditions. A bug requiring a niche provider, OS, or config is NOT broad/critical.
- Feature requests and questions → sentiment "neutral".
- Users saying something works well → sentiment "positive".
- Bug reports → sentiment "negative".
- duplicateCluster: short kebab-case tag for the underlying bug (e.g. "ollama-timeout").
  Use the SAME tag for clearly duplicate issues. null if unique.
- affectsVersion: best guess of the release tag from body/comments. null if unclear.`;

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

  return normalize(parsed);
}

function normalize(r: Partial<IssueClassification>): IssueClassification {
  const sentiments: Sentiment[] = ['negative', 'positive', 'neutral'];
  const severities: Severity[] = ['critical', 'high', 'medium', 'low'];
  const scopes: Scope[] = ['broad', 'moderate', 'niche'];
  const funcs: Functionality[] = ['core', 'integration', 'provider', 'docs'];
  const users: AffectedUsers[] = ['many', 'some', 'few', 'unknown'];

  const oneOf = <T extends string>(val: unknown, allowed: T[], fallback: T): T =>
    allowed.includes(val as T) ? (val as T) : fallback;

  return {
    sentiment: oneOf(r.sentiment, sentiments, 'neutral'),
    severity: oneOf(r.severity, severities, 'low'),
    scope: oneOf(r.scope, scopes, 'niche'),
    functionality: oneOf(r.functionality, funcs, 'integration'),
    affectedUsers: oneOf((r as any).affected_users ?? r.affectedUsers, users, 'unknown'),
    hasWorkaround: Boolean(r.hasWorkaround),
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
