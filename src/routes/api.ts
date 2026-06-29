import { Router } from 'express';
import { config } from '../config';
import { getCached, setCached } from '../lib/cache';
import {
  getRefreshState,
  classifyIssueRowWithLabels,
  issuesForVersion,
  listReleasesDb,
  openedDuringReign,
} from '../lib/refresh';
import {
  comparisonReleases,
  dataFreshnessCacheDigest,
  getLastScoredAt,
  getRelease,
  getReleaseScoreAudit,
  latestScoredStableReleaseTag,
  latestComparisonSnapshot,
  labelsForIssueAt,
  listAdvisories,
  releaseDataFreshness,
  releaseScoreAuditFreshness,
  type AdvisoryRow,
} from '../lib/db';
import {
  closureProofAuditRows,
  enrichGateEvidenceWithClosureProof,
  CLOSURE_RISK_DISPOSITIONS,
} from '../lib/closureProofPayload';
import { releaseLabelCutoff } from '../lib/labelCutoff';
import { matchesRange, firstPatchedVersion, stableDistance } from '../lib/versionMatch';
import { bandFor, isFeltSignal, type InstallStatus } from '../lib/score';
import { surfaceOf } from '../lib/surfaces';
import { SCORE_HISTORY_CHART_LIMIT } from '../lib/historyWindow';

export const api = Router();

// How many stables after a version we still count its CVEs for the BADGE. 0 =
// only CVEs patched in the very next stable — i.e. "this version's own disclosed
// vulnerabilities". This deliberately differs from the cumulative `< X` match:
// GitHub ranges have no lower bound, so the raw count grows with age (the oldest
// release showed "42 CVE", which looks alarming and falsely flatters the newest).
// The windowed count is age-fair (reflects how leaky THIS version was, not how old
// it is) and matches what the decayed score actually weighs. NOTE: this is display
// only — the skip-cve STATUS still trips on ANY medium+ match (security ≠ decay).
const CVE_BADGE_WINDOW = 0;
const CLOSURE_PROOF_AUDIT_SCHEMA_VERSION = 1;
const CLOSURE_PROOF_AUDIT_DEFAULT_LIMIT = 50;
const CLOSURE_PROOF_AUDIT_MAX_LIMIT = 100;

// Cross-reference each release tag against cached advisories. `affected` = CVEs in
// this version's own window (see CVE_BADGE_WINDOW); `patched` = CVEs whose fix first
// shipped in this exact release. A release that's merely "newer than the patch" is
// NOT credited as patching.
function advisoryStatusFor(tag: string, all: AdvisoryRow[], stableTags: string[]) {
  const norm = tag.replace(/^v/i, '');
  const affected: AdvisoryRow[] = [];
  const patched: AdvisoryRow[] = [];
  for (const a of all) {
    if (
      matchesRange(tag, a.vulnerable_version_range) &&
      stableDistance(tag, a.patched_versions, stableTags) <= CVE_BADGE_WINDOW
    ) {
      affected.push(a);
    }
    const first = firstPatchedVersion(a.patched_versions);
    if (first && (first === tag || first.replace(/^v/i, '') === norm)) patched.push(a);
  }
  return { affected, patched };
}

// Parse the stored broken-surfaces JSON (see lib/surfaces.ts) defensively.
function parseBrokenSurfaces(json: string | null): Array<{ label: string; icon: string; count: number }> {
  if (!json) return [];
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function summarizeAdvisories(list: AdvisoryRow[]) {
  const by = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const a of list) by[a.severity] = (by[a.severity] ?? 0) + 1;
  return {
    total: list.length,
    bySeverity: by,
    items: list.map((a) => ({
      ghsaId: a.ghsa_id,
      cveId: a.cve_id,
      severity: a.severity,
      summary: a.summary,
      url: a.html_url,
      patchedVersion: firstPatchedVersion(a.patched_versions),
    })),
  };
}

function parseJson<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function boundedInteger(
  raw: unknown,
  fallback: number,
  min: number,
  max: number,
): number {
  const value = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : fallback;
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

function closureProofAuditResponseRow(row: ReturnType<typeof closureProofAuditRows>[number]) {
  return {
    issueNumber: row.number,
    title: row.title,
    url: row.url,
    closedAt: row.closedAt,
    status: row.status,
    summary: row.summary,
    riskDisposition: row.riskDisposition,
    riskWeight: row.riskWeight,
    checkedAt: row.checkedAt,
    labels: row.labels,
    classification: row.classification,
    classificationDiff: row.classificationDiff,
    evidence: compactClosureProofEvidence(row.evidence),
  };
}

function compactClosureProofEvidence(evidence: unknown) {
  const raw = evidence && typeof evidence === 'object' ? evidence as Record<string, unknown> : {};
  return {
    stateReasons: arrayOf(raw.stateReasons, compactScalar),
    closureActors: arrayOf(raw.closureActors, compactScalar),
    closureContextCommentCount: raw.closureContextCommentCount ?? null,
    hasClosingLink: raw.hasClosingLink === true,
    hasMergedClosingPr: raw.hasMergedClosingPr === true,
    hasReachableClosingPr: raw.hasReachableClosingPr === true,
    hasNotReachableClosingPr: raw.hasNotReachableClosingPr === true,
    hasReachableFixCommit: raw.hasReachableFixCommit === true,
    hasNotReachableFixCommit: raw.hasNotReachableFixCommit === true,
    canonicalIssues: arrayOf(raw.canonicalIssues, compactScalar),
    canonicalIssueDetails: arrayOf(raw.canonicalIssueDetails, compactIssueRef),
    canonicalResolution: compactCanonicalResolution(raw.canonicalResolution),
    closingPrs: arrayOf(raw.closingPrs, compactScalar),
    linkedPrs: arrayOf(raw.linkedPrs, compactPrRef),
    relatedPrContext: compactRelatedPrContext(raw.relatedPrContext),
    reachableTrustedFixProofPrs: arrayOf(raw.reachableTrustedFixProofPrs, compactPrRef),
    matchingComments: arrayOf(raw.matchingComments, compactCommentRef, 5),
    nonActionableRationaleComments: arrayOf(raw.nonActionableRationaleComments, compactCommentRef, 5),
    fixCommitProof: arrayOf(raw.fixCommitProof, compactCommitProof),
    canonicalFixCommitProof: arrayOf(raw.canonicalFixCommitProof, compactCommitProof),
    reachableFixCommits: arrayOf(raw.reachableFixCommits, compactScalar),
    notReachableFixCommits: arrayOf(raw.notReachableFixCommits, compactScalar),
  };
}

function compactRelatedPrContext(value: unknown) {
  const raw = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    externalClosing: arrayOf(raw.externalClosing, compactPrRef),
    open: arrayOf(raw.open, compactPrRef),
    closedUnmerged: arrayOf(raw.closedUnmerged, compactPrRef),
    notReachable: arrayOf(raw.notReachable, compactPrRef),
    reachable: arrayOf(raw.reachable, compactPrRef),
    unknownReachability: arrayOf(raw.unknownReachability, compactPrRef),
  };
}

function compactCanonicalResolution(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    path: arrayOf(raw.path, compactScalar),
    terminalIssue: compactIssueRef(raw.terminalIssue),
    terminalProof: raw.terminalProof && typeof raw.terminalProof === 'object'
      ? {
        status: (raw.terminalProof as Record<string, unknown>).status ?? null,
        summary: (raw.terminalProof as Record<string, unknown>).summary ?? null,
        crossRelease: (raw.terminalProof as Record<string, unknown>).crossRelease === true,
        releaseTag: (raw.terminalProof as Record<string, unknown>).releaseTag ?? null,
        timing: (raw.terminalProof as Record<string, unknown>).timing ?? null,
      }
      : null,
    cycle: raw.cycle === true,
    selfReference: raw.selfReference === true,
  };
}

function arrayOf<T>(value: unknown, mapper: (item: unknown) => T | null, limit = 50): T[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, limit).map(mapper).filter((item): item is T => item != null);
}

function compactScalar(value: unknown): string | number | boolean | null {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  return null;
}

function compactIssueRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const number = Number(raw.number ?? raw.issueNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : typeof raw.html_url === 'string' ? raw.html_url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
  };
}

function compactPrRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const number = Number(raw.number ?? raw.prNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    repositoryNameWithOwner: typeof raw.repositoryNameWithOwner === 'string' ? raw.repositoryNameWithOwner : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
    merged: raw.merged === 1 || raw.merged === true || typeof raw.mergedAt === 'string',
    mergedAt: typeof raw.mergedAt === 'string' ? raw.mergedAt : null,
    reachabilityStatus: typeof raw.reachabilityStatus === 'string' ? raw.reachabilityStatus : null,
    reachabilityMethod: typeof raw.reachabilityMethod === 'string' ? raw.reachabilityMethod : null,
    reachabilityEvidence: typeof raw.reachabilityEvidence === 'string' ? raw.reachabilityEvidence : null,
    mergeCommitOid: typeof raw.mergeCommitOid === 'string' ? raw.mergeCommitOid : null,
  };
}

function compactCommentRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    author: typeof raw.author === 'string' ? raw.author : null,
    createdAt: typeof raw.createdAt === 'string' ? raw.createdAt : null,
    updatedAt: typeof raw.updatedAt === 'string' ? raw.updatedAt : null,
    snippet: typeof raw.snippet === 'string' ? raw.snippet : null,
  };
}

function compactCommitProof(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    commitOid: typeof raw.commitOid === 'string' ? raw.commitOid : null,
    shortOid: typeof raw.shortOid === 'string' ? raw.shortOid : null,
    status: typeof raw.status === 'string' ? raw.status : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    evidence: typeof raw.evidence === 'string' ? raw.evidence : null,
    snippet: typeof raw.snippet === 'string' ? raw.snippet : null,
  };
}

function normalizeComparison(row: Record<string, unknown> | undefined) {
  if (!row) return null;
  return {
    schemaVersion: COMPARISON_UPSTREAM_SCHEMA_VERSION,
    snapshotId: row.snapshot_id,
    tag: row.tag,
    score: row.score,
    band: row.band,
    status: row.status,
    recommended: row.recommended === 1,
    reason: row.reason,
    negativeIssues: row.negative_issues,
    positiveIssues: row.positive_issues,
    totalAttributedIssues: row.total_attributed_issues,
    visibleIssues: parseJson(String(row.visible_issues_json ?? '[]'), [] as unknown[]),
    rawCardText: row.raw_card_text,
  };
}

function normalizeComparisonSnapshot(row: ReturnType<typeof latestComparisonSnapshot>) {
  if (!row) return null;
  return {
    id: row.id,
    sourceUrl: row.source_url,
    capturedAt: row.captured_at,
    pageTitle: row.page_title,
  };
}

api.get('/health', (_req, res) => {
  res.json({ ok: true, repo: `${config.github.owner}/${config.github.repo}` });
});

// UI config — lets the frontend respect server-side limits without hardcoding.
api.get('/config', (_req, res) => {
  res.json({
    schemaVersion: CONFIG_PAYLOAD_SCHEMA_VERSION,
    releases: config.limits.releases,
    refreshMinutes: config.refresh.intervalMinutes,
  });
});

api.get('/status', (_req, res) => {
  const state = getRefreshState();
  const lastScoredAt = getLastScoredAt();
  const latestScoredTag = latestScoredStableReleaseTag();
  res.json({
    schemaVersion: STATUS_PAYLOAD_SCHEMA_VERSION,
    ...state,
    lastRefreshAt: state.processLastRefreshAt,
    processLastRefreshAt: state.processLastRefreshAt,
    lastScoredAt,
    dataFreshness: latestScoredTag ? releaseDataFreshness(latestScoredTag) : null,
  });
});

// Maintainer-signal counts mined from the release-notes body + neighbouring releases.
// See lib/releaseNotes.ts. These are exposed for the UI to render without further
// computation, but the UI is intentionally NOT consuming them yet — we want to watch
// the numbers settle across a few refresh cycles before deciding how to surface them.
//
// `breakingCount` semantics: for a stable release, this is the AGGREGATE of its
// own `### Breaking` bullets plus those in every beta in the chain back to the
// previous stable. The maintainer typically lists a breaking change in the beta
// that introduced it and does NOT repeat the bullet when the stable promotes —
// so the stable's own body alone undercounts breakage that ships in it. See
// `computeAggregateBreaking` in lib/releaseNotes.ts. `fixesCount` / `changesCount`
// stay own-only because changelog generators DO re-list those at promotion.
function maintainerSignals(r: {
  breaking_count: number;
  fixes_count: number;
  changes_count: number;
  highlights_count: number;
  pr_refs_count: number;
  beta_count: number;
  hours_to_next_release: number | null;
  hours_to_next_stable: number | null;
}) {
  return {
    breakingCount:      r.breaking_count,
    fixesCount:         r.fixes_count,
    changesCount:       r.changes_count,
    highlightsCount:    r.highlights_count,
    prRefsCount:        r.pr_refs_count,
    betaCount:          r.beta_count,
    hoursToNextRelease: r.hours_to_next_release,
    hoursToNextStable:  r.hours_to_next_stable,
  };
}

const SCORE_AUDIT_SUMMARY_SCHEMA_VERSION = 1;
const LOCAL_AUDIT_SCHEMA_VERSION = 1;
const COMPARISON_PAYLOAD_SCHEMA_VERSION = 1;
const COMPARISON_UPSTREAM_SCHEMA_VERSION = 1;
const COMPARISON_DELTA_SCHEMA_VERSION = 1;
const STATUS_PAYLOAD_SCHEMA_VERSION = 1;
const CONFIG_PAYLOAD_SCHEMA_VERSION = 1;
const RELEASE_ROW_SCHEMA_VERSION = 1;
const RELEASE_HISTORY_ROW_SCHEMA_VERSION = 1;

function scoreAuditSummary(audit: ReturnType<typeof getReleaseScoreAudit>) {
  if (!audit) return null;
  const components = parseJson(audit.components_json, null) as any;
  const input = parseJson(audit.input_json, null) as any;
  return {
    schemaVersion: SCORE_AUDIT_SUMMARY_SCHEMA_VERSION,
    modelVersion: audit.score_model_version,
    promptVersion: audit.prompt_version,
    evidenceCoverage: components?.evidenceCoverage ?? null,
    rawIssueCount: input?.rawIssueCount ?? null,
    classifiedIssueCount: input?.classifiedIssueCount ?? null,
  };
}

function scoreExplanation(audit: ReturnType<typeof getReleaseScoreAudit>) {
  if (!audit) return null;
  const components = parseJson(audit.components_json, null) as any;
  return components?.explanation ?? null;
}

function freshnessForRelease(
  release: { tag: string; published_at: string | null; hours_to_next_stable?: number | null },
  audit: ReturnType<typeof getReleaseScoreAudit>,
) {
  const labelRelease = {
    ...release,
    hours_to_next_stable: release.hours_to_next_stable ?? null,
  };
  return {
    ...releaseDataFreshness(release.tag),
    labelCutoffAt: releaseLabelCutoff(labelRelease, audit?.scored_at ?? null),
  };
}

api.get('/releases', (_req, res) => {
  const rows = listReleasesDb(config.limits.releases);
  const advisories = listAdvisories();
  const stableTags = rows.map((r) => r.tag); // newest-first; used for CVE recency window
  res.json(
    rows.map((r) => {
      const status = advisoryStatusFor(r.tag, advisories, stableTags);
      const audit = getReleaseScoreAudit(r.tag);
      return {
        schemaVersion: RELEASE_ROW_SCHEMA_VERSION,
        tag: r.tag,
        name: r.name,
        publishedAt: r.published_at,
        htmlUrl: r.html_url,
        finalScore: r.final_score,                 // Install Confidence 0–10 (null when 'wait')
        band: bandFor(r.final_score, (r.state ?? 'eligible') as InstallStatus),
        status: r.state,                           // wait | skip-cve | skip-hotfix | eligible
        recommended: r.recommended === 1,
        reason: r.score_reason,
        brokenSurfaces: parseBrokenSurfaces(r.broken_surfaces),
        negativeIssues: r.negative_issues,
        positiveIssues: r.positive_issues,
        closedSeriousFixed: r.closed_serious_fixed,
        openedSeriousDuringReign: r.opened_serious_during_reign,
        scoredAt: r.scored_at,
        scoreAudit: scoreAuditSummary(audit),
        explanation: scoreExplanation(audit),
        dataFreshness: freshnessForRelease(r, audit),
        advisories: {
          affected: summarizeAdvisories(status.affected),
          patched: summarizeAdvisories(status.patched),
        },
        maintainerSignals: maintainerSignals(r),
      };
    }),
  );
});

api.get('/releases/history', (_req, res) => {
  const rows = listReleasesDb(SCORE_HISTORY_CHART_LIMIT);
  res.json(
    rows.map((r) => ({
      schemaVersion: RELEASE_HISTORY_ROW_SCHEMA_VERSION,
      tag: r.tag,
      publishedAt: r.published_at,
      finalScore: r.final_score,
    })),
  );
});

api.get('/comparison', (_req, res) => {
  const snapshot = normalizeComparisonSnapshot(latestComparisonSnapshot());
  const upstreamByTag = new Map(comparisonReleases().map((row) => [String(row.tag), row]));
  const releases = listReleasesDb(config.limits.releases).map((release) => {
    const audit = getReleaseScoreAudit(release.tag);
    const upstream = normalizeComparison(upstreamByTag.get(release.tag));
    const localScore = release.final_score;
    const upstreamScore = typeof upstream?.score === 'number' ? upstream.score : null;
    return {
      tag: release.tag,
      local: {
        schemaVersion: LOCAL_AUDIT_SCHEMA_VERSION,
        score: localScore,
        band: bandFor(localScore, (release.state ?? 'eligible') as InstallStatus),
        status: release.state,
        recommended: release.recommended === 1,
        reason: release.score_reason,
        negativeIssues: release.negative_issues,
        positiveIssues: release.positive_issues,
        scoredAt: release.scored_at,
        dataFreshness: freshnessForRelease(release, audit),
        modelVersion: audit?.score_model_version ?? null,
        components: parseJson(audit?.components_json, null),
        input: parseJson(audit?.input_json, null),
        gateEvidence: enrichGateEvidenceWithClosureProof(release.tag, parseJson(audit?.gate_evidence_json, null)),
      },
      upstream,
      delta: {
        schemaVersion: COMPARISON_DELTA_SCHEMA_VERSION,
        score: localScore != null && upstreamScore != null ? Math.round((localScore - upstreamScore) * 10) / 10 : null,
        negativeIssues:
          release.negative_issues != null && typeof upstream?.negativeIssues === 'number'
            ? release.negative_issues - upstream.negativeIssues
            : null,
      },
    };
  });
  res.json({ schemaVersion: COMPARISON_PAYLOAD_SCHEMA_VERSION, snapshot, releases });
});

api.get('/releases/:tag/review', (req, res) => {
  const tag = req.params.tag;
  const release = getRelease(tag);
  if (!release) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  const audit = getReleaseScoreAudit(tag);
  const gateEvidence = enrichGateEvidenceWithClosureProof(tag, parseJson(audit?.gate_evidence_json, null));
  const payload: Record<string, unknown> = {
    tag,
    local: {
      schemaVersion: LOCAL_AUDIT_SCHEMA_VERSION,
      score: release.final_score,
      band: bandFor(release.final_score, (release.state ?? 'eligible') as InstallStatus),
      status: release.state,
      recommended: release.recommended === 1,
      reason: release.score_reason,
      negativeIssues: release.negative_issues,
      positiveIssues: release.positive_issues,
      scoredAt: release.scored_at,
      dataFreshness: freshnessForRelease(release, audit),
      modelVersion: audit?.score_model_version ?? null,
      promptVersion: audit?.prompt_version ?? null,
      input: parseJson(audit?.input_json, null),
      components: parseJson(audit?.components_json, null),
      issueEvidence: parseJson(audit?.issue_evidence_json, null),
      gateEvidence,
    },
  };
  if (req.query.includeComparison === '1') {
    payload.snapshot = normalizeComparisonSnapshot(latestComparisonSnapshot());
    payload.upstream = normalizeComparison(comparisonReleases().find((row) => row.tag === tag));
  }
  res.json(payload);
});

api.get('/releases/:tag/review/closure-proofs', (req, res) => {
  const tag = req.params.tag;
  const release = getRelease(tag);
  if (!release) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  const statusFilter = typeof req.query.status === 'string' && req.query.status.trim()
    ? req.query.status.trim()
    : null;
  const riskDispositionFilter = typeof req.query.riskDisposition === 'string' && req.query.riskDisposition.trim()
    ? req.query.riskDisposition.trim()
    : null;
  if (riskDispositionFilter && !(CLOSURE_RISK_DISPOSITIONS as readonly string[]).includes(riskDispositionFilter)) {
    res.status(400).json({ error: 'invalid riskDisposition', riskDisposition: riskDispositionFilter });
    return;
  }
  const limit = boundedInteger(req.query.limit, CLOSURE_PROOF_AUDIT_DEFAULT_LIMIT, 1, CLOSURE_PROOF_AUDIT_MAX_LIMIT);
  const cursor = boundedInteger(req.query.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
  const allRows = closureProofAuditRows(tag)
    .filter((row) => !statusFilter || row.status === statusFilter)
    .filter((row) => !riskDispositionFilter || row.riskDisposition === riskDispositionFilter);
  const pageRows = allRows.slice(cursor, cursor + limit).map(closureProofAuditResponseRow);
  const nextCursor = cursor + pageRows.length < allRows.length ? cursor + pageRows.length : null;
  res.json({
    schemaVersion: CLOSURE_PROOF_AUDIT_SCHEMA_VERSION,
    tag,
    filters: {
      status: statusFilter,
      riskDisposition: riskDispositionFilter,
    },
    total: allRows.length,
    limit,
    cursor,
    nextCursor,
    rows: pageRows,
  });
});

// ── Public API ────────────────────────────────────────────────────────────────
// Single endpoint answering "which stable should I install right now?".
//
// score:       Install Confidence 0–10 (higher = stronger install confidence under current audit gates). null when 'wait'.
// band:        solid | ok | caution | weak | skip | wait
// status:      eligible | skip-cve | skip-hotfix | wait
// recommended: true for the single newest release that passed all gates and scores
//              at or above the recommendation threshold.
// reason:      short human explanation of the verdict.
// sentiment / severity / scope / hasWorkaround / confidence: per-issue LLM context.
//
// The score is NOT issue-volume based (that is confounded by how long/popular a
// release was). It comes from age/cadence-invariant signals: known CVEs, settle
// age, hotfix succession, stable-to-stable survival, beta shakeout depth, and the
// serious-bug close/open balance during the release's reign. See lib/score.ts.
//
// Data refreshes on a configurable interval (REFRESH_MINUTES). scoredAt = last time
// the score was computed for this specific release.

// Under window-based attribution one issue often affects multiple releases, so
// returning every attributed issue per release inflates the payload (we observed
// 5 MB for openclaw with ~1100 negs × 10 releases). For the public-API surface
// we cap to the most relevant issues per release: negatives first, sorted by
// effective severity/reach, then positives.
const PUBLIC_ISSUES_PER_RELEASE = 25;
const PUBLIC_PAYLOAD_SCHEMA_VERSION = 1;
const PUBLIC_RELEASE_SCHEMA_VERSION = 1;
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SENTIMENT_RANK: Record<string, number> = { negative: 0, positive: 1, neutral: 2 };
const SCOPE_RANK: Record<string, number> = { broad: 0, moderate: 1, niche: 2 };
const USERS_RANK: Record<string, number> = { many: 0, some: 1, few: 2, unknown: 3 };

function publicCacheKey(
  freshness = releaseScoreAuditFreshness(),
  sourceFreshness = dataFreshnessCacheDigest(),
): string {
  return [
    PUBLIC_PAYLOAD_SCHEMA_VERSION,
    freshness.max_scored_at ?? '',
    freshness.count,
    freshness.digest,
    sourceFreshness.max_ts ?? '',
    sourceFreshness.count,
    sourceFreshness.digest,
  ].join(':');
}

function comparePublicIssueSignal(
  a: { classification: { sentiment: string; severity: string; scope: string; affectedUsers: string } },
  b: { classification: { sentiment: string; severity: string; scope: string; affectedUsers: string } },
): number {
  const sentiment = (SENTIMENT_RANK[a.classification.sentiment] ?? 9) - (SENTIMENT_RANK[b.classification.sentiment] ?? 9);
  if (sentiment !== 0) return sentiment;
  const severity = (SEVERITY_RANK[a.classification.severity] ?? 9) - (SEVERITY_RANK[b.classification.severity] ?? 9);
  if (severity !== 0) return severity;
  const scope = (SCOPE_RANK[a.classification.scope] ?? 9) - (SCOPE_RANK[b.classification.scope] ?? 9);
  if (scope !== 0) return scope;
  return (USERS_RANK[a.classification.affectedUsers] ?? 9) - (USERS_RANK[b.classification.affectedUsers] ?? 9);
}

function buildPublicPayload() {
  const { processLastRefreshAt } = getRefreshState();
  const lastScoredAt = getLastScoredAt();
  // Only the focused window (config.limits.releases, default 10) carries full
  // evidence + My-install scoring. The chart still plots SCORE_HISTORY_CHART_LIMIT
  // (20) points, but releases 11–20 are frozen rows from past runs: on the client
  // they have no /public detail, so My-install falls back to their stored global
  // score — comparative trend context only, not re-filtered per profile.
  const allReleases = listReleasesDb(config.limits.releases);

  const releases = allReleases.map((r) => {
    const audit = getReleaseScoreAudit(r.tag);
    const auditSummary = scoreAuditSummary(audit);
    const labelCutoff = releaseLabelCutoff(r, audit?.scored_at ?? null);
    const classifyPublicIssue = (i: ReturnType<typeof issuesForVersion>[number]) => {
      const labels = labelsForIssueAt(i.number, parseJson(i.labels, [] as string[]), labelCutoff, {
        useFallbackWhenNoEvents: labelCutoff == null,
        useSnapshotWhenNoEvents: labelCutoff != null,
      });
      return { issue: i, classification: classifyIssueRowWithLabels(i, labels), labels };
    };
    const all = issuesForVersion(r.tag);
    const sorted = all.map(classifyPublicIssue).sort(comparePublicIssueSignal);
    const issueSummary = ({ issue: i, classification }: typeof sorted[number]) => ({
      number:        i.number,
      title:         i.title,
      url:           i.html_url,
      state:         i.state,
      closedAt:      i.closed_at,
      surface:       ((surface) => surface ? { label: surface.label, icon: surface.icon } : null)(surfaceOf(i.title)),
      sentiment:     classification.sentiment,
      severity:      classification.severity,
      scope:         classification.scope,
      affectedUsers: classification.affectedUsers,
      hasWorkaround: classification.workaroundStatus === 'confirmed' || i.has_workaround === 1,
      confidence:    classification.confidence,
      rationale:     classification.rationale,
    });
    const topIssues = sorted.slice(0, PUBLIC_ISSUES_PER_RELEASE).map(issueSummary);
    const watchIssues = openedDuringReign(r.tag)
      .map(classifyPublicIssue)
      .filter(({ issue, classification, labels }) => issue.state === 'open' && isFeltSignal({
        ...classification,
        issueNumber: issue.number,
        title: issue.title,
        duplicateCluster: issue.duplicate_cluster,
        author: issue.author,
        authorAssociation: issue.author_association,
        isBot: issue.is_bot,
        comments: issue.comments,
        uniqueHumanCommenterCount: issue.unique_human_commenters,
        maintainerCommenterCount: issue.maintainer_commenters,
        contributorCommenterCount: issue.contributor_commenters,
        commenterScanTruncated: issue.commenter_scan_truncated,
        reactionTotal: issue.reaction_total,
        positiveReactionCount: issue.positive_reactions,
        labels,
      }))
      .sort(comparePublicIssueSignal)
      .slice(0, PUBLIC_ISSUES_PER_RELEASE)
      .map(issueSummary);

    return {
      schemaVersion:     PUBLIC_RELEASE_SCHEMA_VERSION,
      tag:               r.tag,
      publishedAt:       r.published_at,
      url:               r.html_url,
      score:             r.final_score,
      band:              bandFor(r.final_score, (r.state ?? 'eligible') as InstallStatus),
      status:            r.state,
      recommended:       r.recommended === 1,
      reason:            r.score_reason,
      negativeIssues:    r.negative_issues ?? 0,
      positiveIssues:    r.positive_issues ?? 0,
      scoredAt:          r.scored_at,
      scoreAudit:        auditSummary,
      explanation:       scoreExplanation(audit),
      dataFreshness:     freshnessForRelease(r, audit),
      totalAttributedIssues: all.length,
      issues:            topIssues,
      watchIssues,
    };
  });

  return {
    schemaVersion: PUBLIC_PAYLOAD_SCHEMA_VERSION,
    repo:      `${config.github.owner}/${config.github.repo}`,
    updatedAt: lastScoredAt ?? processLastRefreshAt,
    releases,
  };
}

api.get('/public', (_req, res) => {
  const cacheKey = publicCacheKey();
  const hit = getCached(cacheKey);
  if (hit) { res.json(hit); return; }
  const data = buildPublicPayload();
  setCached(data, publicCacheKey());
  res.json(data);
});
