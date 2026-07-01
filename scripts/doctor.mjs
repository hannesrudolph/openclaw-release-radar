import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import {
  assessDataFreshnessHealth,
  assessDurableIngestionEvidenceFailureHealth,
  assessIssueCrawlHealth,
} from './lib/doctor-health.mjs';
import {
  SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  scoreSourceIdentityForDb,
} from '../src/lib/scoreSourceIdentity.ts';

const SCHEMA_VERSION = 1;
const TRACKED_PR_REPOSITORY = `${process.env.GITHUB_OWNER ?? 'openclaw'}/${process.env.GITHUB_REPO ?? 'openclaw'}`;
const CORE_TABLES = [
  'releases',
  'issues',
  'classifications',
  'release_score_audits',
  'release_commits',
  'issue_comment_snapshots',
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
  'ingestion_evidence_failures',
  'comparison_snapshots',
  'comparison_releases',
];

export function buildDoctorReport({
  dbPath = process.env.DB_PATH ?? './data/radar.db',
  now = new Date(),
  maxIssueLagHours = 48,
  failOnWarnings = false,
  sourceIdentityForDb = scoreSourceIdentityForDb,
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
    scorePersistence: null,
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
      failures.push('no audited stable release found');
      return finish(report, { failOnWarnings });
    }
    if (!latest.auditPresent) failures.push(`${latest.tag}: missing release_score_audits row`);
    if (latest.finalScore !== latest.auditFinalScore) {
      failures.push(`${latest.tag}: release final_score (${latest.finalScore}) does not match audit final_score (${latest.auditFinalScore})`);
    }
    if (latest.scoredAt !== latest.auditScoredAt) {
      failures.push(`${latest.tag}: release scored_at (${latest.scoredAt}) does not match audit scored_at (${latest.auditScoredAt})`);
    }

    report.scorePersistence = scorePersistenceSummary(db, report.recommendation);
    if (!report.scorePersistence.sourceIdentityColumnPresent) {
      failures.push('release_score_audits.source_identity_json is missing; start the writable app once to run migrations, then rescore');
    }
    if (!report.scorePersistence.present) {
      failures.push('score persistence metadata is missing');
    } else if (!report.scorePersistence.valid) {
      failures.push('score persistence metadata is malformed');
    } else {
      if (report.scorePersistence.maxReleaseScoredAt !== report.scorePersistence.meta.maxScoredAt) {
        failures.push(`score persistence maxScoredAt (${report.scorePersistence.meta.maxScoredAt}) does not match release rows (${report.scorePersistence.maxReleaseScoredAt})`);
      }
      if (report.scorePersistence.maxAuditScoredAt !== report.scorePersistence.meta.maxScoredAt) {
        failures.push(`score persistence maxScoredAt (${report.scorePersistence.meta.maxScoredAt}) does not match audit rows (${report.scorePersistence.maxAuditScoredAt})`);
      }
      if (report.scorePersistence.scoredStableCount !== report.scorePersistence.auditedStableCount) {
        failures.push(`score persistence scored stable row count (${report.scorePersistence.scoredStableCount}) does not match audited stable rows (${report.scorePersistence.auditedStableCount})`);
      }
      if (JSON.stringify(report.scorePersistence.scoredStableTags) !== JSON.stringify(report.scorePersistence.meta.releaseTags ?? [])) {
        failures.push('score persistence releaseTags do not match scored stable release rows');
      }
      if (report.scorePersistence.auditedStableCount !== report.scorePersistence.meta.scoredReleaseCount) {
        failures.push(`score persistence scoredReleaseCount (${report.scorePersistence.meta.scoredReleaseCount}) does not match audited stable rows (${report.scorePersistence.auditedStableCount})`);
      }
      if (JSON.stringify(report.scorePersistence.auditedStableTags) !== JSON.stringify(report.scorePersistence.meta.releaseTags ?? [])) {
        failures.push('score persistence releaseTags do not match audited stable rows');
      }
      if (report.scorePersistence.auditModelVersions.length !== 1 ||
        report.scorePersistence.auditModelVersions[0] !== report.scorePersistence.meta.scoreModelVersion) {
        failures.push('score persistence scoreModelVersion does not match audited stable rows');
      }
      if (report.scorePersistence.auditPromptVersions.length !== 1 ||
        report.scorePersistence.auditPromptVersions[0] !== report.scorePersistence.meta.promptVersion) {
        failures.push('score persistence promptVersion does not match audited stable rows');
      }
      if (report.recommendation.recommended?.[0]?.tag && report.scorePersistence.meta.recommendedTag !== report.recommendation.recommended[0].tag) {
        failures.push(`score persistence recommendedTag (${report.scorePersistence.meta.recommendedTag}) does not match recommendation (${report.recommendation.recommended[0].tag})`);
      }
      if (report.scorePersistence.missingAuditTags.length > 0) {
        failures.push(`score persistence missing release_score_audits rows for scored stable releases: ${report.scorePersistence.missingAuditTags.join(', ')}`);
      }
      if (report.scorePersistence.orphanAuditTags.length > 0) {
        failures.push(`score persistence has audit rows without scored stable release rows: ${report.scorePersistence.orphanAuditTags.join(', ')}`);
      }
      if (report.scorePersistence.releaseAuditMismatches.length > 0) {
        const examples = report.scorePersistence.releaseAuditMismatches
          .slice(0, 5)
          .map((row) => `${row.tag} ${row.field} release=${JSON.stringify(row.release)} audit=${JSON.stringify(row.audit)}`)
          .join('; ');
        failures.push(`score persistence release/audit field mismatch: ${examples}`);
      }
      const currentSourceIdentity = sourceIdentityForDb(db);
      report.scorePersistence.sourceIdentity.current = sourceIdentitySummary(currentSourceIdentity);
      report.scorePersistence.sourceIdentity.matchesCurrent =
        report.scorePersistence.sourceIdentity.persisted?.digest === currentSourceIdentity.digest;
      if (report.scorePersistence.sourceIdentity.missingTags.length > 0) {
        failures.push(`score persistence source identity missing for: ${report.scorePersistence.sourceIdentity.missingTags.join(', ')}`);
      }
      if (report.scorePersistence.sourceIdentity.malformedTags.length > 0) {
        failures.push(`score persistence source identity malformed for: ${report.scorePersistence.sourceIdentity.malformedTags.join(', ')}`);
      }
      if (report.scorePersistence.sourceIdentity.persistedIdentityCount !== 1) {
        failures.push(`score persistence audits must share one source identity manifest, found ${report.scorePersistence.sourceIdentity.persistedIdentityCount}`);
      }
      if (report.scorePersistence.meta.sourceIdentitySchemaVersion !== SCORE_SOURCE_IDENTITY_SCHEMA_VERSION) {
        failures.push(`score persistence sourceIdentitySchemaVersion (${report.scorePersistence.meta.sourceIdentitySchemaVersion}) must equal ${SCORE_SOURCE_IDENTITY_SCHEMA_VERSION}`);
      }
      if (report.scorePersistence.meta.sourceIdentityDigest !== report.scorePersistence.sourceIdentity.persisted?.digest) {
        failures.push(`score persistence sourceIdentityDigest (${report.scorePersistence.meta.sourceIdentityDigest}) does not match audit rows (${report.scorePersistence.sourceIdentity.persisted?.digest ?? 'missing'})`);
      }
      if (report.scorePersistence.meta.sourceIdentityRowCount !== report.scorePersistence.sourceIdentity.persisted?.rowCount) {
        failures.push(`score persistence sourceIdentityRowCount (${report.scorePersistence.meta.sourceIdentityRowCount}) does not match audit rows (${report.scorePersistence.sourceIdentity.persisted?.rowCount ?? 'missing'})`);
      }
      if (report.scorePersistence.meta.sourceIdentitySourceCount !== report.scorePersistence.sourceIdentity.persisted?.sourceCount) {
        failures.push(`score persistence sourceIdentitySourceCount (${report.scorePersistence.meta.sourceIdentitySourceCount}) does not match audit rows (${report.scorePersistence.sourceIdentity.persisted?.sourceCount ?? 'missing'})`);
      }
      if (!report.scorePersistence.sourceIdentity.matchesCurrent) {
        failures.push(`score source identity drift: persisted ${report.scorePersistence.sourceIdentity.persisted?.digest ?? 'missing'}, current ${currentSourceIdentity.digest}`);
      }
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
    const durableFailureHealth = assessDurableIngestionEvidenceFailureHealth(report.ingestion.durableEvidenceFailures, latest);
    warnings.push(...durableFailureHealth.warnings);
    failures.push(...durableFailureHealth.failures);
    if (report.ingestion.commenterScanTruncatedIssueCount > 0) {
      warnings.push(`${latest.tag}: ${report.ingestion.commenterScanTruncatedIssueCount} issue row(s) have truncated comment scans`);
    }

    report.closureProof = closureProofSummary(db, latest.tag, gate);
    if (report.closureProof.rawClosedWindowCount !== report.closureProof.proofRowCount) {
      failures.push(`${latest.tag}: closure proof rows (${report.closureProof.proofRowCount}) do not cover raw closed release-window issues (${report.closureProof.rawClosedWindowCount})`);
    }
    if (report.closureProof.integrity.failedCount > 0) {
      failures.push(`${latest.tag}: closure proof evidence is stale or incomplete ` +
        `(missing=${report.closureProof.integrity.missingCount}, extra=${report.closureProof.integrity.extraCount}, stale=${report.closureProof.integrity.staleCount})`);
    }
    if (report.closureProof.auditAnalyzedClosedCount != null &&
      report.closureProof.auditAnalyzedClosedCount !== report.closureProof.proofRowCount) {
      failures.push(`${latest.tag}: audit analyzedClosedCount (${report.closureProof.auditAnalyzedClosedCount}) does not match proof rows (${report.closureProof.proofRowCount})`);
    }

    report.reachability = reachabilitySummary(db, latest.tag);
    if (report.reachability.integrity.failedCount > 0) {
      failures.push(`${latest.tag}: PR reachability evidence is stale or incomplete ` +
        `(missing=${report.reachability.integrity.missingCount}, extra=${report.reachability.integrity.extraCount}, ` +
        `stale=${report.reachability.integrity.staleCount}, mismatched=${report.reachability.integrity.mismatchedCount})`);
    }
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
    issue_comment_snapshots: 'MAX(fetched_at)',
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
    WHERE r.prerelease=0
      AND (
        r.final_score IS NOT NULL
        OR a.release_tag IS NOT NULL
      )
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
  const issueFetchFreshnessSql = tableHasColumns(db, 'issues', ['fetched_at'])
    ? `
    UNION ALL SELECT 'issue_fetches', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issues`
    : '';
  const issueCommentFreshnessSql = tableHasColumns(db, 'issue_comment_snapshots', ['fetched_at'])
    ? `
    UNION ALL SELECT 'issue_comments', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_comment_snapshots`
    : '';
  const releaseRowsFreshnessSql = tableHasColumns(db, 'releases', [
    'release_metadata_fetched_at',
    'release_derived_fetched_at',
    'release_artifact_checked_at',
  ])
    ? `
    UNION ALL
    SELECT 'release_rows', COUNT(*) AS count, COALESCE(SUM(CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END), 0) AS nullCount, MAX(updated_at) AS maxAt
    FROM (
      SELECT release_metadata_fetched_at AS updated_at FROM releases
      UNION ALL SELECT release_derived_fetched_at FROM releases
      UNION ALL SELECT release_artifact_checked_at FROM releases
    )`
    : '';
  const sourceRows = db.prepare(`
    SELECT 'issues' AS source, COUNT(*) AS count, COALESCE(SUM(CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END), 0) AS nullCount, MAX(updated_at) AS maxAt FROM issues
    ${issueFetchFreshnessSql}
    ${issueCommentFreshnessSql}
    UNION ALL SELECT 'classifications', COUNT(*), COALESCE(SUM(CASE WHEN classified_at IS NULL THEN 1 ELSE 0 END), 0), MAX(classified_at) FROM classifications
    UNION ALL SELECT 'issue_label_events', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_label_events
    UNION ALL SELECT 'issue_label_snapshots', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_label_snapshots
    UNION ALL SELECT 'issue_closure_proofs', COUNT(*), COALESCE(SUM(CASE WHEN checked_at IS NULL THEN 1 ELSE 0 END), 0), MAX(checked_at) FROM issue_closure_proofs
    UNION ALL SELECT 'issue_closure_events', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_closure_events
    UNION ALL SELECT 'issue_reopen_events', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_reopen_events
    UNION ALL SELECT 'issue_pr_links', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_pr_links
    UNION ALL SELECT 'issue_commit_references', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_commit_references
    UNION ALL SELECT 'pull_request_fixes', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM pull_request_fixes
    UNION ALL SELECT 'release_pr_reachability', COUNT(*), COALESCE(SUM(CASE WHEN checked_at IS NULL THEN 1 ELSE 0 END), 0), MAX(checked_at) FROM release_pr_reachability
    ${releaseRowsFreshnessSql}
    UNION ALL SELECT 'release_commits', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM release_commits
    UNION ALL SELECT 'advisories', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM advisories
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
      nullCount: Number(row.nullCount ?? 0),
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
    integrity: closureProofIntegritySummary(db, tag),
    auditAnalyzedClosedCount: releaseFixCredit?.analyzedClosedCount ?? closureProof?.analyzedClosedCount ?? null,
    auditRiskSummary: closureProof?.riskSummary ?? null,
  };
}

function closureProofIntegritySummary(db, tag) {
  const issueCommentDependencySql = tableHasColumns(db, 'issue_comment_snapshots', ['fetched_at'])
    ? `UNION ALL SELECT MAX(s.fetched_at) FROM issue_comment_snapshots s JOIN raw_closed c ON c.number=s.issue_number`
    : '';
  const counts = db.prepare(`
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
    raw_closed AS (
      SELECT i.number
      FROM issues i
      JOIN target
      WHERE target.start_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.start_at
        AND i.closed_at < target.end_at
    ),
    proofs AS (
      SELECT issue_number, checked_at
      FROM issue_closure_proofs
      WHERE release_tag=?
    ),
    linked_prs AS (
      SELECT DISTINCT l.pr_repository_name_with_owner, l.pr_number
      FROM issue_pr_links l
      JOIN raw_closed c ON c.number=l.issue_number
    ),
    dependency_sources AS (
      SELECT MAX(i.updated_at) AS max_ts FROM issues i JOIN raw_closed c ON c.number=i.number
      UNION ALL SELECT MAX(i.fetched_at) FROM issues i JOIN raw_closed c ON c.number=i.number
      UNION ALL SELECT MAX(c.classified_at) FROM classifications c JOIN raw_closed r ON r.number=c.issue_number
      ${issueCommentDependencySql}
      UNION ALL SELECT MAX(e.fetched_at) FROM issue_label_events e JOIN raw_closed c ON c.number=e.issue_number
      UNION ALL SELECT MAX(s.fetched_at) FROM issue_label_snapshots s JOIN raw_closed c ON c.number=s.issue_number
      UNION ALL SELECT MAX(e.fetched_at) FROM issue_closure_events e JOIN raw_closed c ON c.number=e.issue_number
      UNION ALL SELECT MAX(r.fetched_at) FROM issue_reopen_events r JOIN raw_closed c ON c.number=r.issue_number
      UNION ALL SELECT MAX(l.fetched_at) FROM issue_pr_links l JOIN raw_closed c ON c.number=l.issue_number
      UNION ALL SELECT MAX(c.fetched_at) FROM issue_commit_references c JOIN raw_closed r ON r.number=c.issue_number
      UNION ALL SELECT MAX(p.fetched_at)
        FROM pull_request_fixes p
        JOIN linked_prs u
          ON u.pr_repository_name_with_owner=p.pr_repository_name_with_owner
         AND u.pr_number=p.pr_number
      UNION ALL SELECT MAX(r.checked_at)
        FROM release_pr_reachability r
        JOIN linked_prs u
          ON u.pr_repository_name_with_owner=r.pr_repository_name_with_owner
         AND u.pr_number=r.pr_number
        WHERE r.tag=?
    ),
    dependency AS (
      SELECT MAX(max_ts) AS max_ts FROM dependency_sources
    )
    SELECT
      (SELECT COUNT(*) FROM raw_closed c LEFT JOIN proofs p ON p.issue_number=c.number WHERE p.issue_number IS NULL) AS missingCount,
      (SELECT COUNT(*) FROM proofs p LEFT JOIN raw_closed c ON c.number=p.issue_number WHERE c.number IS NULL) AS extraCount,
      (SELECT COUNT(*) FROM proofs p JOIN dependency d WHERE d.max_ts IS NOT NULL AND unixepoch(p.checked_at) < unixepoch(d.max_ts)) AS staleCount,
      (SELECT max_ts FROM dependency) AS dependencyMaxAt,
      (SELECT MIN(checked_at) FROM proofs) AS minProofCheckedAt
  `).get(tag, tag, tag);
  const summary = {
    missingCount: Number(counts?.missingCount ?? 0),
    extraCount: Number(counts?.extraCount ?? 0),
    staleCount: Number(counts?.staleCount ?? 0),
    dependencyMaxAt: counts?.dependencyMaxAt ?? null,
    minProofCheckedAt: counts?.minProofCheckedAt ?? null,
    failedCount: 0,
  };
  summary.failedCount = summary.missingCount + summary.extraCount + summary.staleCount;
  return summary;
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
    integrity: reachabilityIntegritySummary(db, tag),
  };
}

function reachabilityIntegritySummary(db, tag) {
  const counts = db.prepare(`
    WITH candidates AS (
      SELECT
        p.pr_repository_name_with_owner,
        p.pr_number,
        p.merge_commit_oid,
        p.base_ref_name,
        p.fetched_at AS dependency_fetched_at
      FROM pull_request_fixes p
      JOIN issue_pr_links l
        ON l.pr_repository_name_with_owner=p.pr_repository_name_with_owner
       AND l.pr_number=p.pr_number
      WHERE p.merged=1
        AND p.pr_repository_name_with_owner=?
      GROUP BY p.pr_repository_name_with_owner, p.pr_number, p.merge_commit_oid, p.base_ref_name
    ),
    rows AS (
      SELECT *
      FROM release_pr_reachability
      WHERE tag=?
        AND pr_repository_name_with_owner=?
    )
    SELECT
      (SELECT COUNT(*) FROM candidates) AS candidateCount,
      (SELECT COUNT(*) FROM rows) AS rowCount,
      (SELECT COUNT(*) FROM candidates c LEFT JOIN rows r
         ON r.pr_repository_name_with_owner=c.pr_repository_name_with_owner AND r.pr_number=c.pr_number
       WHERE r.pr_number IS NULL) AS missingCount,
      (SELECT COUNT(*) FROM rows r LEFT JOIN candidates c
         ON c.pr_repository_name_with_owner=r.pr_repository_name_with_owner AND c.pr_number=r.pr_number
       WHERE c.pr_number IS NULL) AS extraCount,
      (SELECT COUNT(*) FROM candidates c JOIN rows r
         ON r.pr_repository_name_with_owner=c.pr_repository_name_with_owner AND r.pr_number=c.pr_number
       WHERE unixepoch(r.checked_at) < unixepoch(c.dependency_fetched_at)) AS staleCount,
      (SELECT COUNT(*) FROM candidates c JOIN rows r
         ON r.pr_repository_name_with_owner=c.pr_repository_name_with_owner AND r.pr_number=c.pr_number
       WHERE r.status != 'unknown'
         AND (COALESCE(r.merge_commit_oid, '') != COALESCE(c.merge_commit_oid, '')
          OR COALESCE(r.base_ref_name, '') != COALESCE(c.base_ref_name, ''))) AS mismatchedCount
  `).get(TRACKED_PR_REPOSITORY, tag, TRACKED_PR_REPOSITORY);
  const summary = {
    candidateCount: Number(counts?.candidateCount ?? 0),
    rowCount: Number(counts?.rowCount ?? 0),
    missingCount: Number(counts?.missingCount ?? 0),
    extraCount: Number(counts?.extraCount ?? 0),
    staleCount: Number(counts?.staleCount ?? 0),
    mismatchedCount: Number(counts?.mismatchedCount ?? 0),
    failedCount: 0,
  };
  summary.failedCount = summary.missingCount + summary.extraCount + summary.staleCount + summary.mismatchedCount;
  return summary;
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
    durableEvidenceFailures: durableIngestionEvidenceFailureSummary(db, latest),
  };
}

function scorePersistenceSummary(db) {
  const raw = getMetaValue(db, 'score_persistence_last_run');
  const meta = parseJson(raw, null);
  const sourceIdentityColumnPresent = tableHasColumns(db, 'release_score_audits', ['source_identity_json']);
  const releaseStats = db.prepare(`
    SELECT COUNT(*) AS count, MAX(scored_at) AS maxScoredAt
    FROM releases
    WHERE prerelease=0
      AND (
        final_score IS NOT NULL
        OR scored_at IS NOT NULL
      )
  `).get();
  const auditStats = db.prepare(`
    SELECT COUNT(*) AS count, MAX(a.scored_at) AS maxScoredAt
    FROM release_score_audits a
    JOIN releases r ON r.tag=a.release_tag
    WHERE r.prerelease=0
  `).get();
  const auditRows = db.prepare(`
    SELECT a.release_tag, a.score_model_version, a.prompt_version,
           ${sourceIdentityColumnPresent ? 'a.source_identity_json' : 'NULL'} AS source_identity_json
    FROM release_score_audits a
    JOIN releases r ON r.tag=a.release_tag
    WHERE r.prerelease=0
    ORDER BY r.published_at IS NULL, r.published_at DESC
  `).all();
  const scoredRows = db.prepare(`
    SELECT tag
    FROM releases
    WHERE prerelease=0
      AND (
        final_score IS NOT NULL
        OR scored_at IS NOT NULL
      )
    ORDER BY published_at IS NULL, published_at DESC
  `).all();
  const missingAuditTags = db.prepare(`
    SELECT r.tag
    FROM releases r
    LEFT JOIN release_score_audits a ON a.release_tag=r.tag
    WHERE r.prerelease=0
      AND (
        r.final_score IS NOT NULL
        OR r.scored_at IS NOT NULL
      )
      AND a.release_tag IS NULL
    ORDER BY r.published_at IS NULL, r.published_at DESC
  `).all().map((row) => row.tag);
  const orphanAuditTags = db.prepare(`
    SELECT a.release_tag
    FROM release_score_audits a
    LEFT JOIN releases r ON r.tag=a.release_tag
    WHERE r.tag IS NULL
      OR r.prerelease != 0
      OR (
        r.final_score IS NULL
        AND r.scored_at IS NULL
      )
    ORDER BY a.release_tag
  `).all().map((row) => row.release_tag);
  const parityRows = db.prepare(`
    SELECT r.tag,
           r.final_score AS release_final_score,
           a.final_score AS audit_final_score,
           r.scored_at AS release_scored_at,
           a.scored_at AS audit_scored_at,
           r.state AS release_status,
           a.status AS audit_status,
           r.recommended AS release_recommended,
           a.recommended AS audit_recommended
    FROM releases r
    JOIN release_score_audits a ON a.release_tag=r.tag
    WHERE r.prerelease=0
      AND (
        r.final_score IS NOT NULL
        OR r.scored_at IS NOT NULL
      )
    ORDER BY r.published_at IS NULL, r.published_at DESC
  `).all();
  const releaseAuditMismatches = parityRows.flatMap((row) => releaseAuditMismatchesForRow(row));
  const sourceIdentityRows = auditRows.map((row) => ({
    tag: row.release_tag,
    identity: parseJson(row.source_identity_json, null),
  }));
  const validSourceIdentityRows = sourceIdentityRows.filter((row) => isScoreSourceIdentity(row.identity));
  const persistedSourceIdentity = validSourceIdentityRows[0]?.identity ?? null;
  const persistedIdentities = [...new Set(validSourceIdentityRows.map((row) => JSON.stringify(row.identity)))];
  return {
    present: typeof raw === 'string' && raw.length > 0,
    valid: !!meta && typeof meta === 'object' && !Array.isArray(meta) && meta.schemaVersion === 2,
    sourceIdentityColumnPresent,
    meta,
    auditedStableCount: Number(auditStats?.count ?? 0),
    scoredStableCount: Number(releaseStats?.count ?? 0),
    maxReleaseScoredAt: releaseStats?.maxScoredAt ?? null,
    maxAuditScoredAt: auditStats?.maxScoredAt ?? null,
    scoredStableTags: scoredRows.map((row) => row.tag),
    auditedStableTags: auditRows.map((row) => row.release_tag),
    auditModelVersions: [...new Set(auditRows.map((row) => row.score_model_version))],
    auditPromptVersions: [...new Set(auditRows.map((row) => row.prompt_version))],
    missingAuditTags,
    orphanAuditTags,
    releaseAuditMismatches,
    sourceIdentity: {
      persisted: sourceIdentitySummary(persistedSourceIdentity),
      current: null,
      matchesCurrent: false,
      persistedIdentityCount: persistedIdentities.length,
      persistedDigests: [...new Set(validSourceIdentityRows.map((row) => row.identity.digest))],
      missingTags: sourceIdentityRows.filter((row) => row.identity == null).map((row) => row.tag),
      malformedTags: sourceIdentityRows
        .filter((row) => row.identity != null && !isScoreSourceIdentity(row.identity))
        .map((row) => row.tag),
    },
  };
}

function isScoreSourceIdentity(value) {
  return !!value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    value.schemaVersion === SCORE_SOURCE_IDENTITY_SCHEMA_VERSION &&
    value.sourceMode === 'current_db' &&
    value.scope === 'score_input_database' &&
    value.algorithm === 'sha256' &&
    typeof value.digest === 'string' &&
    /^[0-9a-f]{64}$/.test(value.digest) &&
    Number.isInteger(value.rowCount) &&
    value.rowCount >= 0 &&
    Number.isInteger(value.sourceCount) &&
    value.sourceCount > 0 &&
    Array.isArray(value.sources) &&
    value.sources.length === value.sourceCount &&
    value.sources.every((source) =>
      source &&
      typeof source === 'object' &&
      !Array.isArray(source) &&
      typeof source.source === 'string' &&
      source.source.length > 0 &&
      Number.isInteger(source.count) &&
      source.count >= 0 &&
      typeof source.digest === 'string' &&
      /^[0-9a-f]{64}$/.test(source.digest));
}

function sourceIdentitySummary(identity) {
  if (!isScoreSourceIdentity(identity)) return null;
  return {
    schemaVersion: identity.schemaVersion,
    sourceMode: identity.sourceMode,
    scope: identity.scope,
    algorithm: identity.algorithm,
    digest: identity.digest,
    rowCount: identity.rowCount,
    sourceCount: identity.sourceCount,
  };
}

function releaseAuditMismatchesForRow(row) {
  return [
    ['final_score', row.release_final_score, row.audit_final_score],
    ['scored_at', row.release_scored_at, row.audit_scored_at],
    ['status', row.release_status, row.audit_status],
    ['recommended', row.release_recommended, row.audit_recommended],
  ]
    .filter(([, releaseValue, auditValue]) => releaseValue !== auditValue)
    .map(([field, releaseValue, auditValue]) => ({
      tag: row.tag,
      field,
      release: releaseValue,
      audit: auditValue,
    }));
}

function durableIngestionEvidenceFailureSummary(db, latest) {
  const present = tableHasColumns(db, 'ingestion_evidence_failures', [
    'id',
    'run_id',
    'occurred_at',
    'source',
    'message',
    'scoring_blocking',
  ]);
  const empty = {
    present,
    blockingAfterLatestScoreCount: 0,
    bySource: {},
    recentAfterLatestScore: [],
  };
  if (!present || !latest?.scoredAt) return empty;
  const rows = db.prepare(`
    SELECT id, run_id, occurred_at, source, scope, release_tag, issue_number,
           pr_repository_name_with_owner, pr_number, message, context_json
    FROM ingestion_evidence_failures
    WHERE scoring_blocking = 1
      AND occurred_at > ?
    ORDER BY occurred_at DESC, id DESC
    LIMIT 10
  `).all(latest.scoredAt);
  const bySourceRows = db.prepare(`
    SELECT source, COUNT(*) AS count, MAX(occurred_at) AS maxAt
    FROM ingestion_evidence_failures
    WHERE scoring_blocking = 1
      AND occurred_at > ?
    GROUP BY source
    ORDER BY count DESC, source
  `).all(latest.scoredAt);
  const total = bySourceRows.reduce((sum, row) => sum + Number(row.count ?? 0), 0);
  return {
    present,
    blockingAfterLatestScoreCount: total,
    bySource: Object.fromEntries(bySourceRows.map((row) => [
      row.source,
      { count: Number(row.count ?? 0), maxAt: row.maxAt ?? null },
    ])),
    recentAfterLatestScore: rows.map((row) => ({
      id: Number(row.id),
      runId: row.run_id,
      occurredAt: row.occurred_at,
      source: row.source,
      scope: row.scope ?? null,
      releaseTag: row.release_tag ?? null,
      issueNumber: row.issue_number ?? null,
      prRepositoryNameWithOwner: row.pr_repository_name_with_owner ?? null,
      prNumber: row.pr_number ?? null,
      message: row.message,
      context: parseJson(row.context_json, null),
    })),
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
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
