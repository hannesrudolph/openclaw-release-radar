import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { assessDataFreshnessHealth, assessIssueCrawlHealth } from './lib/doctor-health.mjs';

const SCHEMA_VERSION = 1;
const CORE_TABLES = [
  'releases',
  'issues',
  'classifications',
  'release_score_audits',
  'release_commits',
  'issue_closure_proofs',
  'issue_closure_events',
  'issue_reopen_events',
  'issue_pr_links',
  'issue_commit_references',
  'pull_request_fixes',
  'release_pr_reachability',
  'issue_label_events',
  'issue_label_snapshots',
  'advisories',
  'comparison_snapshots',
  'comparison_releases',
];

export function buildDoctorReport({
  dbPath = process.env.DB_PATH ?? './data/radar.db',
  now = new Date(),
  maxIssueLagHours = 48,
  failOnWarnings = false,
} = {}) {
  const resolvedPath = resolve(dbPath);
  const failures = [];
  const warnings = [];
  const report = {
    schemaVersion: SCHEMA_VERSION,
    ok: false,
    generatedAt: now.toISOString(),
    db: {
      path: resolvedPath,
      exists: existsSync(resolvedPath),
      sizeBytes: null,
      readOnly: true,
    },
    strict: {
      failOnWarnings: failOnWarnings === true,
      maxIssueLagHours,
    },
    tables: {},
    latestScoredStable: null,
    recommendation: null,
    freshness: null,
    ingestion: null,
    coverage: null,
    closureProof: null,
    reachability: null,
    comparison: null,
    warnings,
    failures,
  };

  if (!report.db.exists) {
    failures.push(`database not found: ${resolvedPath}`);
    return finish(report, { failOnWarnings });
  }

  report.db.sizeBytes = statSync(resolvedPath).size;
  if (report.db.sizeBytes <= 0) failures.push(`database is empty: ${resolvedPath}`);

  const db = new DatabaseSync(resolvedPath, { readOnly: true });
  try {
    db.exec('PRAGMA query_only = ON');
    for (const table of CORE_TABLES) {
      report.tables[table] = tableSummary(db, table);
    }
    for (const table of ['releases', 'issues', 'classifications', 'release_score_audits']) {
      if ((report.tables[table]?.count ?? 0) <= 0) failures.push(`core table ${table} has no rows`);
    }

    report.recommendation = recommendationSummary(db);
    if (report.recommendation.scoredStableCount > 0 && report.recommendation.recommendedCount !== 1) {
      failures.push(`expected exactly one recommended scored stable release, found ${report.recommendation.recommendedCount}`);
    }

    const latest = latestScoredStable(db);
    report.latestScoredStable = latest;
    if (!latest) {
      failures.push('no scored stable release found');
      return finish(report, { failOnWarnings });
    }
    if (!latest.auditPresent) failures.push(`${latest.tag}: missing release_score_audits row`);
    if (latest.finalScore !== latest.auditFinalScore) {
      failures.push(`${latest.tag}: release final_score (${latest.finalScore}) does not match audit final_score (${latest.auditFinalScore})`);
    }
    if (latest.scoredAt !== latest.auditScoredAt) {
      failures.push(`${latest.tag}: release scored_at (${latest.scoredAt}) does not match audit scored_at (${latest.auditScoredAt})`);
    }

    const audit = getAudit(db, latest.tag);
    const input = parseJson(audit?.input_json, {});
    const gate = parseJson(audit?.gate_evidence_json, {});
    const issueEvidence = parseJson(audit?.issue_evidence_json, {});
    report.coverage = coverageSummary(input, issueEvidence);
    if (Number(report.coverage.classifiedIssueCount ?? 0) < Number(report.coverage.rawIssueCount ?? 0)) {
      failures.push(`${latest.tag}: incomplete classification coverage (${report.coverage.classifiedIssueCount}/${report.coverage.rawIssueCount})`);
    }

    report.freshness = freshnessSummary(db, latest.tag, latest.scoredAt, now);
    const freshnessHealth = assessDataFreshnessHealth(report.freshness, latest, { maxIssueLagHours });
    warnings.push(...freshnessHealth.warnings);
    failures.push(...freshnessHealth.failures);

    report.ingestion = ingestionSummary(db, latest);
    const crawlHealth = assessIssueCrawlHealth(report.ingestion.issueCrawl, latest);
    warnings.push(...crawlHealth.warnings);
    failures.push(...crawlHealth.failures);
    if (report.ingestion.commenterScanTruncatedIssueCount > 0) {
      warnings.push(`${latest.tag}: ${report.ingestion.commenterScanTruncatedIssueCount} issue row(s) have truncated comment scans`);
    }

    report.closureProof = closureProofSummary(db, latest.tag, gate);
    if (report.closureProof.rawClosedWindowCount !== report.closureProof.proofRowCount) {
      failures.push(`${latest.tag}: closure proof rows (${report.closureProof.proofRowCount}) do not cover raw closed release-window issues (${report.closureProof.rawClosedWindowCount})`);
    }
    if (report.closureProof.auditAnalyzedClosedCount != null &&
      report.closureProof.auditAnalyzedClosedCount !== report.closureProof.proofRowCount) {
      failures.push(`${latest.tag}: audit analyzedClosedCount (${report.closureProof.auditAnalyzedClosedCount}) does not match proof rows (${report.closureProof.proofRowCount})`);
    }

    report.reachability = reachabilitySummary(db, latest.tag);
    report.comparison = comparisonSummary(db);
  } finally {
    db.close();
  }

  return finish(report, { failOnWarnings });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = buildDoctorReport({
    dbPath: args['db-path'] ?? process.env.DB_PATH ?? './data/radar.db',
    maxIssueLagHours: Number(args['max-issue-lag-hours'] ?? 48),
    failOnWarnings: args['fail-on-warnings'] === true,
  });
  if (args['api-base']) {
    report.api = await apiSummary(String(args['api-base']).replace(/\/$/, ''));
    verifyApiAgainstDb(report);
  }
  report.ok = report.failures.length === 0 && (args['fail-on-warnings'] !== true || report.warnings.length === 0);
  console.log(JSON.stringify(report, null, 2));
  if (!report.ok) process.exit(1);
}

function finish(report, { failOnWarnings = false } = {}) {
  report.ok = report.failures.length === 0 && (failOnWarnings !== true || report.warnings.length === 0);
  return report;
}

function tableSummary(db, table) {
  const present = !!db.prepare(`
    SELECT 1 AS present
    FROM sqlite_master
    WHERE type='table' AND name=?
  `).get(table);
  if (!present) return { present: false, count: 0, maxAt: null };
  const maxExpr = ({
    releases: 'MAX(scored_at)',
    issues: 'MAX(updated_at)',
    classifications: 'MAX(classified_at)',
    release_score_audits: 'MAX(scored_at)',
    release_commits: 'MAX(fetched_at)',
    issue_closure_proofs: 'MAX(checked_at)',
    issue_closure_events: 'MAX(fetched_at)',
    issue_reopen_events: 'MAX(fetched_at)',
    issue_pr_links: 'MAX(fetched_at)',
    issue_commit_references: 'MAX(fetched_at)',
    pull_request_fixes: 'MAX(fetched_at)',
    release_pr_reachability: 'MAX(checked_at)',
    issue_label_events: 'MAX(fetched_at)',
    issue_label_snapshots: 'MAX(fetched_at)',
    advisories: 'MAX(fetched_at)',
    comparison_snapshots: 'MAX(captured_at)',
    comparison_releases: 'NULL',
  })[table] ?? 'NULL';
  const row = db.prepare(`SELECT COUNT(*) AS count, ${maxExpr} AS maxAt FROM ${table}`).get();
  return { present: true, count: Number(row?.count ?? 0), maxAt: row?.maxAt ?? null };
}

function recommendationSummary(db) {
  const scoredStableCount = scalar(db, `
    SELECT COUNT(*) FROM releases
    WHERE prerelease=0 AND final_score IS NOT NULL
  `);
  const recommendedRows = db.prepare(`
    SELECT tag, final_score, state, scored_at
    FROM releases
    WHERE prerelease=0 AND final_score IS NOT NULL AND recommended=1
    ORDER BY published_at DESC
  `).all();
  return {
    scoredStableCount,
    recommendedCount: recommendedRows.length,
    recommended: recommendedRows,
  };
}

function latestScoredStable(db) {
  const row = db.prepare(`
    SELECT r.tag, r.final_score, r.state, r.recommended, r.score_reason, r.scored_at,
           a.final_score AS audit_final_score,
           a.scored_at AS audit_scored_at,
           a.score_model_version,
           a.prompt_version
    FROM releases r
    LEFT JOIN release_score_audits a ON a.release_tag=r.tag
    WHERE r.prerelease=0 AND r.final_score IS NOT NULL
    ORDER BY r.published_at DESC
    LIMIT 1
  `).get();
  if (!row) return null;
  return {
    tag: row.tag,
    finalScore: row.final_score,
    state: row.state,
    recommended: row.recommended === 1,
    reason: row.score_reason,
    scoredAt: row.scored_at,
    auditPresent: row.audit_scored_at != null,
    auditFinalScore: row.audit_final_score ?? null,
    auditScoredAt: row.audit_scored_at ?? null,
    modelVersion: row.score_model_version ?? null,
    promptVersion: row.prompt_version ?? null,
  };
}

function getAudit(db, tag) {
  return db.prepare(`SELECT * FROM release_score_audits WHERE release_tag=?`).get(tag);
}

function coverageSummary(input, issueEvidence) {
  return {
    rawIssueCount: Number(input.rawIssueCount ?? 0),
    classifiedIssueCount: Number(input.classifiedIssueCount ?? 0),
    evidenceCoverage: input.rawIssueCount > 0
      ? round(Number(input.classifiedIssueCount ?? 0) / Number(input.rawIssueCount ?? 0), 4)
      : 1,
    debtSummary: issueEvidence?.debtSummary ?? null,
    storedExamples: {
      verifiedDebt: Array.isArray(issueEvidence?.verifiedDebt) ? issueEvidence.verifiedDebt.length : 0,
      carryoverDebt: Array.isArray(issueEvidence?.carryoverDebt) ? issueEvidence.carryoverDebt.length : 0,
      staleDebt: Array.isArray(issueEvidence?.staleDebt) ? issueEvidence.staleDebt.length : 0,
      openedFeltSerious: Array.isArray(issueEvidence?.openedFeltSerious) ? issueEvidence.openedFeltSerious.length : 0,
      verifiedFixed: Array.isArray(issueEvidence?.verifiedFixed) ? issueEvidence.verifiedFixed.length : 0,
      unverifiedClosed: Array.isArray(issueEvidence?.unverifiedClosed) ? issueEvidence.unverifiedClosed.length : 0,
      unclassifiedIssues: Array.isArray(issueEvidence?.unclassifiedIssues) ? issueEvidence.unclassifiedIssues.length : 0,
    },
  };
}

function freshnessSummary(db, tag, scoredAt, now) {
  const issueUniverse = issueUniverseFreshness(db, tag);
  const releaseRowsFreshnessSql = tableHasColumns(db, 'releases', [
    'release_metadata_fetched_at',
    'release_derived_fetched_at',
    'release_artifact_checked_at',
  ])
    ? `
    UNION ALL
    SELECT 'release_rows', COUNT(*) AS count, MAX(updated_at) AS maxAt
    FROM (
      SELECT release_metadata_fetched_at AS updated_at FROM releases
      UNION ALL SELECT release_derived_fetched_at FROM releases
      UNION ALL SELECT release_artifact_checked_at FROM releases
    )`
    : '';
  const sourceRows = db.prepare(`
    SELECT 'issues' AS source, COUNT(*) AS count, MAX(updated_at) AS maxAt FROM issues
    UNION ALL SELECT 'classifications', COUNT(*), MAX(classified_at) FROM classifications
    UNION ALL SELECT 'issue_label_events', COUNT(*), MAX(fetched_at) FROM issue_label_events
    UNION ALL SELECT 'issue_label_snapshots', COUNT(*), MAX(fetched_at) FROM issue_label_snapshots
    UNION ALL SELECT 'issue_closure_proofs', COUNT(*), MAX(checked_at) FROM issue_closure_proofs
    UNION ALL SELECT 'issue_closure_events', COUNT(*), MAX(fetched_at) FROM issue_closure_events
    UNION ALL SELECT 'issue_reopen_events', COUNT(*), MAX(fetched_at) FROM issue_reopen_events
    UNION ALL SELECT 'issue_pr_links', COUNT(*), MAX(fetched_at) FROM issue_pr_links
    UNION ALL SELECT 'issue_commit_references', COUNT(*), MAX(fetched_at) FROM issue_commit_references
    UNION ALL SELECT 'pull_request_fixes', COUNT(*), MAX(fetched_at) FROM pull_request_fixes
    UNION ALL SELECT 'release_pr_reachability', COUNT(*), MAX(checked_at) FROM release_pr_reachability
    ${releaseRowsFreshnessSql}
    UNION ALL SELECT 'release_commits', COUNT(*), MAX(fetched_at) FROM release_commits
    UNION ALL SELECT 'advisories', COUNT(*), MAX(fetched_at) FROM advisories
  `).all();
  const sourceFetchedAtMax = maxTimestamp(sourceRows.map((row) => row.maxAt ?? null));
  return {
    scoredAt,
    issueUniverseCount: issueUniverse.count,
    issueUpdatedAtMax: issueUniverse.issueUpdatedAtMax,
    issueUpdatedAgeHoursAtScore: ageHours(issueUniverse.issueUpdatedAtMax, scoredAt),
    issueUpdatedAgeHoursNow: ageHours(issueUniverse.issueUpdatedAtMax, now.toISOString()),
    sourceFetchedAtMax,
    sourceFetchedAgeHoursAtScore: ageHours(sourceFetchedAtMax, scoredAt),
    sources: sourceRows.map((row) => ({
      source: row.source,
      count: Number(row.count ?? 0),
      maxAt: row.maxAt ?? null,
      ageHoursAtScore: ageHours(row.maxAt ?? null, scoredAt),
    })),
  };
}

function issueUniverseFreshness(db, tag) {
  const row = db.prepare(`
    WITH target AS (
      SELECT
        tag,
        published_at AS start_at,
        COALESCE(
          (SELECT MIN(next.published_at)
           FROM releases next
           WHERE next.published_at > releases.published_at
             AND next.prerelease = 0),
          '9999-12-31T23:59:59Z'
        ) AS end_at
      FROM releases
      WHERE tag=?
    ),
    issue_open_intervals AS (
      SELECT
        i.number AS issue_number,
        i.created_at AS open_at,
        COALESCE(
          (SELECT MIN(c.closed_at)
           FROM issue_closure_events c
           WHERE c.issue_number=i.number
             AND c.closed_at > i.created_at),
          i.closed_at
        ) AS close_at
      FROM issues i
      UNION ALL
      SELECT
        r.issue_number,
        r.reopened_at AS open_at,
        COALESCE(
          (SELECT MIN(c.closed_at)
           FROM issue_closure_events c
           WHERE c.issue_number=r.issue_number
             AND c.closed_at > r.reopened_at),
          CASE WHEN i.closed_at > r.reopened_at THEN i.closed_at ELSE NULL END
        ) AS close_at
      FROM issue_reopen_events r
      JOIN issues i ON i.number=r.issue_number
      WHERE r.reopened_at IS NOT NULL
    )
    SELECT COUNT(*) AS count, MAX(i.updated_at) AS issueUpdatedAtMax
    FROM issues i
    JOIN target
    WHERE target.start_at IS NOT NULL
      AND EXISTS (
        SELECT 1
        FROM issue_open_intervals interval
        WHERE interval.issue_number=i.number
          AND interval.open_at < target.end_at
          AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
      )
  `).get(tag);
  return {
    count: Number(row?.count ?? 0),
    issueUpdatedAtMax: row?.issueUpdatedAtMax ?? null,
  };
}

function closureProofSummary(db, tag, gate) {
  const rawClosedWindowCount = scalar(db, `
    SELECT COUNT(*)
    FROM issues i
    JOIN releases target ON target.tag=?
    WHERE target.published_at IS NOT NULL
      AND i.closed_at IS NOT NULL
      AND i.closed_at >= target.published_at
      AND i.closed_at < COALESCE(
            (SELECT MIN(next.published_at)
             FROM releases next
             WHERE next.published_at > target.published_at
               AND next.prerelease = 0),
            '9999-12-31T23:59:59Z'
          )
  `, tag);
  const rows = db.prepare(`
    SELECT status, COUNT(*) AS count
    FROM issue_closure_proofs
    WHERE release_tag=?
    GROUP BY status
    ORDER BY count DESC
  `).all(tag);
  const byStatus = Object.fromEntries(rows.map((row) => [row.status, Number(row.count ?? 0)]));
  const proofRowCount = rows.reduce((sum, row) => sum + Number(row.count ?? 0), 0);
  const closureProof = gate?.fixProvenance?.closureProof ?? null;
  const releaseFixCredit = gate?.fixProvenance?.releaseFixCredit ?? null;
  return {
    rawClosedWindowCount,
    proofRowCount,
    fixedInReleaseCount: byStatus.fixed_in_release ?? 0,
    notCreditedCount: proofRowCount - (byStatus.fixed_in_release ?? 0),
    byStatus,
    auditAnalyzedClosedCount: releaseFixCredit?.analyzedClosedCount ?? closureProof?.analyzedClosedCount ?? null,
    auditRiskSummary: closureProof?.riskSummary ?? null,
  };
}

function reachabilitySummary(db, tag) {
  const rows = db.prepare(`
    SELECT status, COUNT(*) AS count
    FROM release_pr_reachability
    WHERE tag=?
    GROUP BY status
    ORDER BY status
  `).all(tag);
  return {
    total: rows.reduce((sum, row) => sum + Number(row.count ?? 0), 0),
    byStatus: Object.fromEntries(rows.map((row) => [row.status, Number(row.count ?? 0)])),
  };
}

function comparisonSummary(db) {
  const snapshot = db.prepare(`
    SELECT id, source_url, captured_at, page_title
    FROM comparison_snapshots
    ORDER BY captured_at DESC, id DESC
    LIMIT 1
  `).get();
  if (!snapshot) return { latestSnapshot: null, releaseCount: 0 };
  return {
    latestSnapshot: {
      id: snapshot.id,
      sourceUrl: snapshot.source_url,
      capturedAt: snapshot.captured_at,
      pageTitle: snapshot.page_title,
    },
    releaseCount: scalar(db, `SELECT COUNT(*) FROM comparison_releases WHERE snapshot_id=?`, snapshot.id),
  };
}

function ingestionSummary(db, latest) {
  return {
    issueCrawl: parseJson(getMetaValue(db, 'issue_crawl_last_run'), null),
    commenterScanTruncatedIssueCount: latest?.tag ? commenterScanTruncatedIssueCount(db, latest.tag) : 0,
  };
}

function getMetaValue(db, key) {
  const row = db.prepare(`SELECT value FROM meta WHERE key=?`).get(key);
  return row?.value ?? null;
}

function commenterScanTruncatedIssueCount(db, tag) {
  return scalar(db, `
    WITH target AS (
      SELECT
        tag,
        published_at AS start_at,
        COALESCE(
          (SELECT MIN(next.published_at)
           FROM releases next
           WHERE next.published_at > releases.published_at
             AND next.prerelease = 0),
          '9999-12-31T23:59:59Z'
        ) AS end_at
      FROM releases
      WHERE tag=?
    ),
    issue_open_intervals AS (
      SELECT
        i.number AS issue_number,
        i.created_at AS open_at,
        COALESCE(
          (SELECT MIN(c.closed_at)
           FROM issue_closure_events c
           WHERE c.issue_number=i.number
             AND c.closed_at > i.created_at),
          i.closed_at
        ) AS close_at
      FROM issues i
      UNION ALL
      SELECT
        r.issue_number,
        r.reopened_at AS open_at,
        COALESCE(
          (SELECT MIN(c.closed_at)
           FROM issue_closure_events c
           WHERE c.issue_number=r.issue_number
             AND c.closed_at > r.reopened_at),
          CASE WHEN i.closed_at > r.reopened_at THEN i.closed_at ELSE NULL END
        ) AS close_at
      FROM issue_reopen_events r
      JOIN issues i ON i.number=r.issue_number
      WHERE r.reopened_at IS NOT NULL
    )
    SELECT COUNT(DISTINCT i.number)
    FROM issues i
    JOIN target
    WHERE target.start_at IS NOT NULL
      AND i.commenter_scan_truncated=1
      AND EXISTS (
        SELECT 1
        FROM issue_open_intervals interval
        WHERE interval.issue_number=i.number
          AND interval.open_at < target.end_at
          AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
      )
  `, tag);
}

async function apiSummary(apiBase) {
  try {
    const [status, publicPayload] = await Promise.all([
      fetchJson(`${apiBase}/api/status`),
      fetchJson(`${apiBase}/api/public`),
    ]);
    const recommended = (publicPayload.releases ?? []).filter((release) => release.recommended);
    return {
      apiBase,
      status: {
        lastScoredAt: status.lastScoredAt ?? null,
        lastError: status.lastError ?? null,
        refreshing: status.refreshing === true,
      },
      public: {
        releaseCount: publicPayload.releases?.length ?? 0,
        recommendedCount: recommended.length,
        recommendedTag: recommended[0]?.tag ?? null,
      },
    };
  } catch (error) {
    return { apiBase, error: error.message };
  }
}

function verifyApiAgainstDb(report) {
  if (!report.api) return;
  if (report.api.error) {
    report.failures.push(`api check failed: ${report.api.error}`);
    return;
  }
  const expectedRecommendedTag = report.recommendation?.recommended?.[0]?.tag ?? null;
  const expectedScoredAt = report.tables?.releases?.maxAt ?? null;
  const apiRecommendedCount = Number(report.api.public?.recommendedCount ?? 0);
  const apiRecommendedTag = report.api.public?.recommendedTag ?? null;
  const apiLastScoredAt = report.api.status?.lastScoredAt ?? null;
  if (report.api.status?.refreshing === true) {
    report.failures.push('api status reports refresh in progress');
  }
  if (report.api.status?.lastError) {
    report.failures.push(`api status reports lastError: ${report.api.status.lastError}`);
  }
  if (apiRecommendedCount !== 1) {
    report.failures.push(`api public recommended count (${apiRecommendedCount}) must be 1`);
  }
  if (apiRecommendedTag !== expectedRecommendedTag) {
    report.failures.push(`api public recommended tag (${apiRecommendedTag}) must match DB recommended tag (${expectedRecommendedTag})`);
  }
  if (apiLastScoredAt !== expectedScoredAt) {
    report.failures.push(`api status lastScoredAt (${apiLastScoredAt}) must match DB max scored_at (${expectedScoredAt})`);
  }
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

function scalar(db, sql, ...args) {
  const row = db.prepare(sql).get(...args);
  if (!row) return 0;
  return Number(Object.values(row)[0] ?? 0);
}

function tableHasColumns(db, table, columns) {
  const existing = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((col) => col.name));
  return columns.every((column) => existing.has(column));
}

function parseJson(json, fallback) {
  if (!json) return fallback;
  try {
    return JSON.parse(json);
  } catch {
    return fallback;
  }
}

function maxTimestamp(values) {
  return values
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

function ageHours(sourceAt, targetAt) {
  if (!sourceAt || !targetAt) return null;
  const sourceMs = Date.parse(sourceAt);
  const targetMs = Date.parse(targetAt);
  if (!Number.isFinite(sourceMs) || !Number.isFinite(targetMs)) return null;
  return round((targetMs - sourceMs) / 3_600_000, 2);
}

function round(value, digits = 3) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
