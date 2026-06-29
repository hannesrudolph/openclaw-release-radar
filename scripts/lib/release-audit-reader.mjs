import { existsSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

const CREDITED_FIX_LINK_SQL =
  "(l.will_close_target = 1 OR l.source IN ('closedByPullRequestsReferences', 'ClosedEvent.closer', 'ClosureComment.fixProof'))";

export function openReleaseAuditReader(dbPath) {
  if (!existsSync(dbPath)) {
    throw new Error(`Database not found: ${dbPath}`);
  }
  const db = new DatabaseSync(dbPath, { readOnly: true });
  db.exec('PRAGMA query_only = ON');
  return new ReleaseAuditReader(db);
}

export class ReleaseAuditReader {
  constructor(db) {
    this.db = db;
  }

  close() {
    this.db.close();
  }

  listReleases(limit = 10, options = {}) {
    return this.db.prepare(`
      SELECT *
      FROM releases
      WHERE prerelease = 0
        AND (? = 0 OR final_score IS NOT NULL)
      ORDER BY published_at IS NULL, published_at DESC
      LIMIT ?
    `).all(options.scoredOnly ? 1 : 0, limit);
  }

  scoredStableReleaseCount() {
    const row = this.db.prepare(`
      SELECT COUNT(*) AS count
      FROM releases
      WHERE prerelease = 0
        AND final_score IS NOT NULL
    `).get();
    return Number(row?.count ?? 0);
  }

  closedDuringReign(tag) {
    return this.db.prepare(`
      SELECT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN releases target ON target.tag = ?
      WHERE
        target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0),
              '9999-12-31T23:59:59Z'
            )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  rawClosedDuringReign(tag) {
    return this.db.prepare(`
      SELECT i.*
      FROM issues i
      JOIN releases target ON target.tag = ?
      WHERE
        target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0),
              '9999-12-31T23:59:59Z'
            )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  verifiedFixedForRelease(tag) {
    return this.db.prepare(`
      WITH target AS (
        SELECT * FROM releases WHERE tag=?
      ),
      window_closure AS (
        SELECT e.*
        FROM issue_closure_events e
        JOIN issues wi
          ON wi.number=e.issue_number
         AND ABS(unixepoch(wi.closed_at) - unixepoch(e.closed_at)) <= 2
      )
      SELECT DISTINCT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN target
      WHERE
        target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0),
              '9999-12-31T23:59:59Z'
            )
        AND EXISTS (
          SELECT 1
          FROM window_closure e
          WHERE e.issue_number = i.number
            AND e.state_reason = 'COMPLETED'
        )
        AND (
          EXISTS (
            SELECT 1
            FROM issue_closure_proofs proof
            WHERE proof.release_tag = target.tag
              AND proof.issue_number = i.number
              AND proof.status = 'fixed_in_release'
          )
          OR (
            NOT EXISTS (
              SELECT 1
              FROM issue_closure_proofs proof
            WHERE proof.release_tag = target.tag
              AND proof.issue_number = i.number
          )
          AND c.sentiment = 'negative'
          AND EXISTS (
              SELECT 1
              FROM window_closure e
                JOIN issue_pr_links l ON l.issue_number = e.issue_number
                JOIN pull_request_fixes p ON p.pr_repository_name_with_owner = l.pr_repository_name_with_owner AND p.pr_number = l.pr_number
                JOIN release_pr_reachability rpr ON rpr.tag = target.tag AND rpr.pr_repository_name_with_owner = p.pr_repository_name_with_owner AND rpr.pr_number = p.pr_number
              WHERE e.issue_number = i.number
                AND e.state_reason = 'COMPLETED'
                AND p.merged = 1
                AND rpr.status = 'reachable'
                AND ${CREDITED_FIX_LINK_SQL}
            )
          )
        )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  unverifiedClosedForRelease(tag) {
    return this.db.prepare(`
      SELECT DISTINCT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN releases target ON target.tag = ?
      WHERE
        target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0),
              '9999-12-31T23:59:59Z'
            )
        AND NOT EXISTS (
          WITH window_closure AS (
            SELECT e.*
            FROM issue_closure_events e
            JOIN issues wi
              ON wi.number=e.issue_number
             AND ABS(unixepoch(wi.closed_at) - unixepoch(e.closed_at)) <= 2
          )
          SELECT 1
          FROM issue_closure_proofs proof
          WHERE proof.release_tag = target.tag
            AND proof.issue_number = i.number
            AND proof.status = 'fixed_in_release'
          UNION ALL
          SELECT 1
          FROM window_closure e
            JOIN issue_pr_links l ON l.issue_number = e.issue_number
            JOIN pull_request_fixes p ON p.pr_repository_name_with_owner = l.pr_repository_name_with_owner AND p.pr_number = l.pr_number
            JOIN release_pr_reachability rpr ON rpr.tag = target.tag AND rpr.pr_repository_name_with_owner = p.pr_repository_name_with_owner AND rpr.pr_number = p.pr_number
          WHERE e.issue_number = i.number
            AND c.sentiment = 'negative'
            AND e.state_reason = 'COMPLETED'
            AND p.merged = 1
            AND rpr.status = 'reachable'
            AND ${CREDITED_FIX_LINK_SQL}
            AND NOT EXISTS (
              SELECT 1
              FROM issue_closure_proofs proof
              WHERE proof.release_tag = target.tag
                AND proof.issue_number = i.number
            )
        )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  proofRowsFor(tag) {
    const release = this.db.prepare(`SELECT tag, published_at, hours_to_next_stable FROM releases WHERE tag=?`).get(tag);
    const audit = this.getReleaseScoreAudit(tag);
    const cutoff = releaseLabelCutoff(release, audit?.scored_at ?? null);
    const rows = this.db.prepare(`
      SELECT p.release_tag, p.issue_number, p.status, p.summary, p.evidence_json, p.checked_at,
             i.title, i.labels,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale
      FROM issue_closure_proofs p
      JOIN issues i ON i.number=p.issue_number
      LEFT JOIN classifications c ON c.issue_number=p.issue_number
      WHERE p.release_tag=?
      ORDER BY p.issue_number
    `).all(tag);
    return rows.map((row) => ({
      ...row,
      effective_labels: labelsForIssueAt(this.db, row.issue_number, parseLabels(row.labels), cutoff, {
        useFallbackWhenNoEvents: cutoff == null,
        useSnapshotWhenNoEvents: cutoff != null,
      }),
    }));
  }

  tableExists(name) {
    const row = this.db.prepare(`
      SELECT 1 AS present
      FROM sqlite_master
      WHERE type='table' AND name=?
    `).get(name);
    return !!row;
  }

  sourceFreshnessFor(tag) {
    const commitReferenceFreshnessSql = this.tableExists('issue_commit_references')
      ? `UNION ALL
      SELECT 'issue_commit_references', MAX(c.fetched_at)
      FROM issue_commit_references c JOIN closed_universe u ON u.number=c.issue_number`
      : `UNION ALL
      SELECT 'issue_commit_references', NULL`;
    return this.db.prepare(`
      WITH target AS (
        SELECT tag, published_at,
               COALESCE(
                 (SELECT MIN(next.published_at)
                  FROM releases next
                  WHERE next.published_at > releases.published_at
                    AND next.prerelease=0),
                 '9999-12-31T23:59:59Z'
               ) AS end_at
        FROM releases
        WHERE tag=?
      ),
      issue_universe AS (
        SELECT DISTINCT i.number
        FROM issues i
        JOIN target
        WHERE i.created_at < target.end_at
          AND (i.closed_at IS NULL OR i.closed_at > target.published_at)
      ),
      closed_universe AS (
        SELECT DISTINCT i.number
        FROM issues i
        JOIN target
        WHERE i.closed_at IS NOT NULL
          AND i.closed_at >= target.published_at
          AND i.closed_at < target.end_at
      ),
        pr_universe AS (
          SELECT DISTINCT l.pr_repository_name_with_owner, l.pr_number
          FROM issue_pr_links l
          JOIN closed_universe c ON c.number=l.issue_number
          WHERE ${CREDITED_FIX_LINK_SQL}
      )
      SELECT 'release_metadata' AS source, MAX(updated_at) AS max_ts
      FROM (
        SELECT fetched_at AS updated_at FROM release_commits WHERE tag=?
        UNION ALL
        SELECT fetched_at FROM advisories
      )
      UNION ALL
      SELECT 'issue_rows', MAX(i.updated_at)
      FROM issues i JOIN issue_universe u ON u.number=i.number
      UNION ALL
      SELECT 'classification_rows', MAX(c.classified_at)
      FROM classifications c JOIN issue_universe u ON u.number=c.issue_number
      UNION ALL
      SELECT 'label_events', MAX(e.fetched_at)
      FROM issue_label_events e JOIN issue_universe u ON u.number=e.issue_number
      UNION ALL
      SELECT 'label_snapshots', MAX(s.fetched_at)
      FROM issue_label_snapshots s JOIN issue_universe u ON u.number=s.issue_number
      UNION ALL
      SELECT 'closure_events', MAX(e.fetched_at)
      FROM issue_closure_events e JOIN closed_universe u ON u.number=e.issue_number
      UNION ALL
      SELECT 'reopen_events', MAX(r.fetched_at)
      FROM issue_reopen_events r JOIN issue_universe u ON u.number=r.issue_number
      UNION ALL
      SELECT 'issue_pr_links', MAX(l.fetched_at)
      FROM issue_pr_links l JOIN closed_universe u ON u.number=l.issue_number
      ${commitReferenceFreshnessSql}
      UNION ALL
        SELECT 'pull_request_fixes', MAX(p.fetched_at)
        FROM pull_request_fixes p JOIN pr_universe u ON u.pr_repository_name_with_owner=p.pr_repository_name_with_owner AND u.pr_number=p.pr_number
        UNION ALL
        SELECT 'release_pr_reachability', MAX(r.checked_at)
        FROM release_pr_reachability r JOIN pr_universe u ON u.pr_repository_name_with_owner=r.pr_repository_name_with_owner AND u.pr_number=r.pr_number
      WHERE r.tag=?
    `).all(tag, tag, tag);
  }

  prReachabilityEvidenceForIssue(tag, issueNumber) {
    return this.db.prepare(`
      SELECT l.issue_number,
               l.pr_repository_name_with_owner,
               l.pr_number,
               l.source,
             l.will_close_target,
             p.merged,
             p.merge_commit_oid,
             rpr.status,
             rpr.tag_commit_oid,
             rpr.evidence_json,
             rc.tag_commit_oid AS release_tag_commit_oid
      FROM issue_pr_links l
        JOIN pull_request_fixes p ON p.pr_repository_name_with_owner=l.pr_repository_name_with_owner AND p.pr_number=l.pr_number
        JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_repository_name_with_owner=l.pr_repository_name_with_owner AND rpr.pr_number=l.pr_number
      LEFT JOIN release_commits rc ON rc.tag=rpr.tag
      WHERE l.issue_number=?
        ORDER BY l.pr_repository_name_with_owner, l.pr_number
    `).all(tag, issueNumber);
  }

  prReachabilityRowsForRelease(tag) {
    return this.db.prepare(`
      SELECT r.*,
             p.title,
             p.url,
             p.state,
             p.merged,
             p.merged_at,
             p.merge_commit_oid AS pr_merge_commit_oid,
             p.base_ref_name AS pr_base_ref_name
      FROM release_pr_reachability r
      LEFT JOIN pull_request_fixes p
        ON p.pr_repository_name_with_owner=r.pr_repository_name_with_owner
       AND p.pr_number=r.pr_number
      WHERE r.tag=?
      ORDER BY r.pr_repository_name_with_owner, r.pr_number
    `).all(tag);
  }

  getReleaseScoreAudit(tag) {
    return this.db.prepare(`
      SELECT *
      FROM release_score_audits
      WHERE release_tag=?
    `).get(tag);
  }
}

function releaseLabelCutoff(rel, now = null) {
  if (!rel?.published_at) return null;
  if (rel.hours_to_next_stable == null) {
    const millis = typeof now === 'string' ? Date.parse(now) : typeof now === 'number' ? now : NaN;
    return Number.isFinite(millis) ? new Date(millis).toISOString() : null;
  }
  const publishedAt = Date.parse(rel.published_at);
  if (!Number.isFinite(publishedAt)) return null;
  return new Date(publishedAt + Number(rel.hours_to_next_stable) * 3_600_000).toISOString();
}

function parseLabels(raw) {
  try {
    const value = raw ? JSON.parse(raw) : [];
    return Array.isArray(value) ? value.filter((label) => typeof label === 'string') : [];
  } catch {
    return [];
  }
}

function labelsForIssueAt(db, issueNumber, fallbackLabels, cutoff, options = {}) {
  const eventCount = Number(db.prepare(`
    SELECT COUNT(*) AS count FROM issue_label_events WHERE issue_number=?
  `).get(issueNumber)?.count ?? 0);
  if (eventCount === 0) {
    if (options.useSnapshotWhenNoEvents && cutoff) {
      const snapshot = db.prepare(`
        SELECT labels_json
        FROM issue_label_snapshots
        WHERE issue_number=?
          AND snapshot_at <= ?
        ORDER BY snapshot_at DESC
        LIMIT 1
      `).get(issueNumber, cutoff);
      const labels = parseLabels(snapshot?.labels_json);
      if (labels.length) return labels;
    }
    return options.useFallbackWhenNoEvents === false ? [] : fallbackLabels;
  }
  const labels = new Set();
  const rows = db.prepare(`
    SELECT action, label_name
    FROM issue_label_events
    WHERE issue_number=?
      AND (? IS NULL OR created_at <= ?)
    ORDER BY created_at ASC, event_id ASC
  `).all(issueNumber, cutoff, cutoff);
  for (const row of rows) {
    if (row.action === 'labeled') labels.add(row.label_name);
    else if (row.action === 'unlabeled') labels.delete(row.label_name);
  }
  return [...labels];
}
