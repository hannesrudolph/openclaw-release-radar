import { Router } from 'express';
import { config } from '../config';
import { getCached, setCached } from '../lib/cache';
import {
  getRefreshState,
  getRelease,
  issuesOpenDuring,
  listReleasesDb,
  refresh,
} from '../lib/refresh';
import type { ReleaseRow } from '../lib/db';

// For each release, the "lifetime window" is [published_at, next_newer.published_at).
// Latest release has no upper bound (end = null → treated as "now" by issuesOpenDuring).
// allReleases must be sorted by published_at DESC (as returned by listReleasesDb).
function releaseWindow(
  rel: ReleaseRow,
  allReleases: ReleaseRow[],
): { start: string; end: string | null } | null {
  if (!rel.published_at) return null;
  const start = rel.published_at;
  let end: string | null = null;
  for (const r of allReleases) {
    if (!r.published_at) continue;
    if (r.published_at > start && (end === null || r.published_at < end)) {
      end = r.published_at;
    }
  }
  return { start, end };
}

export const api = Router();

api.get('/health', (_req, res) => {
  res.json({ ok: true, repo: `${config.github.owner}/${config.github.repo}` });
});

// UI config — lets the frontend respect server-side limits without hardcoding.
api.get('/config', (_req, res) => {
  res.json({
    stableReleases: config.limits.stableReleases,
    betaReleases:   config.limits.betaReleases,
  });
});

api.get('/status', (_req, res) => {
  res.json(getRefreshState());
});

api.get('/releases', (_req, res) => {
  const rows = listReleasesDb(Math.min(100, (config.limits.stableReleases + config.limits.betaReleases) * 6));
  res.json(
    rows.map((r) => ({
      tag: r.tag,
      name: r.name,
      publishedAt: r.published_at,
      htmlUrl: r.html_url,
      prerelease: r.prerelease === 1,
      finalScore: r.final_score,
      riskIndex: r.risk_index,
      negativeIssues: r.negative_issues,
      positiveIssues: r.positive_issues,
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
  const allReleases = listReleasesDb(Math.min(100, (config.limits.stableReleases + config.limits.betaReleases) * 6));
  const win = releaseWindow(rel, allReleases);
  const issues = win
    ? issuesOpenDuring(win.start, win.end).map(serializeIssue)
    : [];
  res.json({
    tag: rel.tag,
    name: rel.name,
    publishedAt: rel.published_at,
    htmlUrl: rel.html_url,
    prerelease: rel.prerelease === 1,
    finalScore: rel.final_score,
    riskIndex: rel.risk_index,
    negativeIssues: rel.negative_issues,
    positiveIssues: rel.positive_issues,
    scoredAt: rel.scored_at,
    issues,
  });
});

// ── Public API ────────────────────────────────────────────────────────────────
// Single endpoint with everything needed to understand release stability.
//
// score:      0–10 (10 = perfectly stable, 0 = on fire)
// grade:      stable | mostly-stable | mixed | risky | unstable | pending
// riskIndex:  raw aggregated risk before score conversion (higher = worse)
// sentiment:  negative | positive | neutral
// severity:   critical | high | medium | low
// scope:      broad (most users) | moderate | niche (specific config/OS)
// hasWorkaround: true if a known workaround exists for the issue
// confidence: 0–1, how confident the LLM is in its classification
// rationale:  one-sentence explanation from the LLM
//
// Data refreshes every 30 min via cron. scoredAt = last time score was computed.

function buildPublicPayload() {
  const { lastRefreshAt } = getRefreshState();
  const allReleases = listReleasesDb(Math.min(100, (config.limits.stableReleases + config.limits.betaReleases) * 6));

  const releases = allReleases.map((r, idx) => {
    // allReleases is sorted DESC by published_at, so the next-newer release is at idx-1.
    // Latest (idx=0) has no upper bound → null = "open until now".
    const start = r.published_at;
    const end = idx === 0 ? null : (allReleases[idx - 1].published_at ?? null);
    const pool = start ? issuesOpenDuring(start, end) : [];
    const issues = pool.map((i) => ({
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
      prerelease:     r.prerelease === 1,
      score:          r.final_score,
      grade:          scoreToGrade(r.final_score),
      riskIndex:      r.risk_index,
      negativeIssues: r.negative_issues ?? 0,
      positiveIssues: r.positive_issues ?? 0,
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

function scoreToGrade(score: number | null): string {
  if (score == null) return 'pending';
  if (score >= 8.0)  return 'stable';
  if (score >= 6.0)  return 'mostly-stable';
  if (score >= 4.0)  return 'mixed';
  if (score >= 2.0)  return 'risky';
  return 'unstable';
}

api.post('/refresh', async (req, res) => {
  const adminToken = config.adminToken;
  if (adminToken) {
    const provided = req.headers['x-admin-token'];
    if (provided !== adminToken) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
  }
  try {
    const result = await refresh();
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ ok: false, error: (e as Error).message });
  }
});

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
