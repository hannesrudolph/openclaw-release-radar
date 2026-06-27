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

  listReleases(limit = 10) {
    return this.db.prepare(`
      SELECT *
      FROM releases
      WHERE prerelease = 0
      ORDER BY published_at IS NULL, published_at DESC
      LIMIT ?
    `).all(limit);
  }

  closedDuringReign(tag) {
    return this.db.prepare(`
      SELECT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at
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

  verifiedFixedForRelease(tag) {
    return this.db.prepare(`
      WITH target AS (
        SELECT * FROM releases WHERE tag=?
      ),
      latest_closure AS (
        SELECT issue_number, MAX(closed_at) AS closed_at
        FROM issue_closure_events
        GROUP BY issue_number
      ),
      final_closure AS (
        SELECT e.*
        FROM issue_closure_events e
        JOIN latest_closure latest
          ON latest.issue_number=e.issue_number
         AND latest.closed_at=e.closed_at
      )
      SELECT DISTINCT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN target
      JOIN final_closure e ON e.issue_number = i.number
      JOIN issue_pr_links l ON l.issue_number = i.number
      JOIN pull_request_fixes p ON p.pr_number = l.pr_number
      JOIN release_pr_reachability rpr ON rpr.tag = target.tag AND rpr.pr_number = p.pr_number
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
        AND c.sentiment = 'negative'
        AND e.state_reason = 'COMPLETED'
        AND p.merged = 1
        AND rpr.status = 'reachable'
        AND ${CREDITED_FIX_LINK_SQL}
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  unverifiedClosedForRelease(tag) {
    return this.db.prepare(`
      SELECT DISTINCT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at
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
          WITH latest_closure AS (
            SELECT issue_number, MAX(closed_at) AS closed_at
            FROM issue_closure_events
            GROUP BY issue_number
          ),
          final_closure AS (
            SELECT e.*
            FROM issue_closure_events e
            JOIN latest_closure latest
              ON latest.issue_number=e.issue_number
             AND latest.closed_at=e.closed_at
          )
          SELECT 1
          FROM final_closure e
          JOIN issue_pr_links l ON l.issue_number = e.issue_number
          JOIN pull_request_fixes p ON p.pr_number = l.pr_number
          JOIN release_pr_reachability rpr ON rpr.tag = target.tag AND rpr.pr_number = p.pr_number
          WHERE e.issue_number = i.number
            AND c.sentiment = 'negative'
            AND e.state_reason = 'COMPLETED'
            AND p.merged = 1
            AND rpr.status = 'reachable'
            AND ${CREDITED_FIX_LINK_SQL}
        )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  proofRowsFor(tag) {
    return this.db.prepare(`
      SELECT release_tag, issue_number, status, summary, evidence_json, checked_at
      FROM issue_closure_proofs
      WHERE release_tag=?
      ORDER BY issue_number
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
