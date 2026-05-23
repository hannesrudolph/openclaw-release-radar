import { Router } from 'express';
import { config } from '../config';
import { getCached, setCached } from '../lib/cache';
import {
  getRefreshState,
  getRelease,
  issuesForVersion,
  listReleasesDb,
} from '../lib/refresh';

export const api = Router();

api.get('/health', (_req, res) => {
  res.json({ ok: true, repo: `${config.github.owner}/${config.github.repo}` });
});

// UI config — lets the frontend respect server-side limits without hardcoding.
api.get('/config', (_req, res) => {
  res.json({
    releases: config.limits.releases,
    refreshMinutes: config.refresh.intervalMinutes,
  });
});

api.get('/status', (_req, res) => {
  res.json(getRefreshState());
});

api.get('/releases', (_req, res) => {
  const rows = listReleasesDb(config.limits.releases);
  res.json(
    rows.map((r) => ({
      tag: r.tag,
      name: r.name,
      publishedAt: r.published_at,
      htmlUrl: r.html_url,
      finalScore: r.final_score,
      riskIndex: r.risk_index,
      negativeIssues: r.negative_issues,
      positiveIssues: r.positive_issues,
      state: r.state,
      scoredAt: r.scored_at,
    })),
  );
});

api.get('/release/:tag', (req, res) => {
  const rel = getRelease(req.params.tag);
  if (!rel) {
    res.status(404).json({ error: 'release not found' });
    return;
  }
  const issues = issuesForVersion(rel.tag).map(serializeIssue);
  res.json({
    tag: rel.tag,
    name: rel.name,
    publishedAt: rel.published_at,
    htmlUrl: rel.html_url,
    finalScore: rel.final_score,
    riskIndex: rel.risk_index,
    negativeIssues: rel.negative_issues,
    positiveIssues: rel.positive_issues,
    state: rel.state,
    scoredAt: rel.scored_at,
    issues,
  });
});

// ── Public API ────────────────────────────────────────────────────────────────
// Single endpoint with everything needed to understand release stability.
//
// score:      1–10 (10 = stable, 5 = neutral/insufficient signal, 1 = unstable floor)
// grade:      stable | mostly-stable | mixed | risky | unstable | insufficient
// riskIndex:  effective core-risk after positive cancellation (higher = worse)
// sentiment:  negative | positive | neutral
// severity:   critical | high | medium | low
// scope:      broad (most users) | moderate | niche (specific config/OS)
// hasWorkaround: true if a known workaround exists for the issue
// confidence: 0–1, how confident the LLM is in its classification
//
// Attribution: only issues where the LLM extracted an explicit version mention
// from the issue body/comments are counted toward a release. Unattributed bugs
// are intentionally dropped (the "long tail of open bugs" doesn't pollute every
// release). A release with no attributed issues scores 5 (neutral baseline),
// not 10 — absence of signal is not evidence of stability.
//
// Data refreshes on a configurable interval (REFRESH_MINUTES). scoredAt = last time
// score was computed for this specific release.

function buildPublicPayload() {
  const { lastRefreshAt } = getRefreshState();
  const allReleases = listReleasesDb(config.limits.releases);

  const releases = allReleases.map((r) => {
    const issues = issuesForVersion(r.tag).map((i) => ({
      number:         i.number,
      title:          i.title,
      url:            i.html_url,
      state:          i.state,
      sentiment:      i.sentiment,
      severity:       i.severity,
      scope:          i.scope,
      hasWorkaround:  i.has_workaround === 1,
      confidence:     i.confidence,
      rationale:      i.rationale,
    }));

    return {
      tag:            r.tag,
      publishedAt:    r.published_at,
      url:            r.html_url,
      score:          r.final_score,
      grade:          scoreToGrade(r.final_score, r.state),
      riskIndex:      r.risk_index,
      negativeIssues: r.negative_issues ?? 0,
      positiveIssues: r.positive_issues ?? 0,
      state:          r.state,
      scoredAt:       r.scored_at,
      issues,
    };
  });

  return {
    repo:      `${config.github.owner}/${config.github.repo}`,
    updatedAt: lastRefreshAt,
    releases,
  };
}

api.get('/public', (_req, res) => {
  const hit = getCached();
  if (hit) { res.json(hit); return; }
  const data = buildPublicPayload();
  setCached(data);
  res.json(data);
});

// Grade thresholds ported from agent-watch. We prefer the explicit `state` written
// by the scorer when present — that's the authoritative answer to "do we have signal
// for this release?". The numeric fallback band (4.9–5.1) catches legacy rows scored
// before `state` existed.
function scoreToGrade(score: number | null, state: string | null): string {
  if (state === 'analyzing')    return 'analyzing';
  if (state === 'insufficient') return 'insufficient';
  if (score == null)            return 'pending';
  if (score >= 8.2)             return 'stable';
  if (score >= 6.8)             return 'mostly-stable';
  if (score > 5.1)              return 'mixed';
  if (score >= 4.9)             return 'insufficient';
  if (score >= 3.5)             return 'risky';
  return 'unstable';
}

function serializeIssue(r: {
  number: number;
  title: string;
  state: string;
  html_url: string;
  author: string | null;
  comments: number;
  updated_at: string;
  sentiment: string;
  severity: string;
  scope: string;
  functionality: string;
  affected_users: string;
  has_workaround: number;
  duplicate_cluster: string | null;
  confidence: number;
  rationale: string | null;
}) {
  return {
    number: r.number,
    title: r.title,
    state: r.state,
    htmlUrl: r.html_url,
    author: r.author,
    comments: r.comments,
    updatedAt: r.updated_at,
    sentiment: r.sentiment,
    severity: r.severity,
    scope: r.scope,
    functionality: r.functionality,
    affectedUsers: r.affected_users,
    hasWorkaround: r.has_workaround === 1,
    duplicateCluster: r.duplicate_cluster,
    confidence: r.confidence,
    rationale: r.rationale,
  };
}
