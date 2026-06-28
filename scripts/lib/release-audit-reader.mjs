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
         AND wi.closed_at=e.closed_at
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
        AND c.sentiment = 'negative'
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
            AND EXISTS (
              SELECT 1
              FROM window_closure e
              JOIN issue_pr_links l ON l.issue_number = e.issue_number
              JOIN pull_request_fixes p ON p.pr_number = l.pr_number
              JOIN release_pr_reachability rpr ON rpr.tag = target.tag AND rpr.pr_number = p.pr_number
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
             AND wi.closed_at=e.closed_at
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
          JOIN pull_request_fixes p ON p.pr_number = l.pr_number
          JOIN release_pr_reachability rpr ON rpr.tag = target.tag AND rpr.pr_number = p.pr_number
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
    const cutoff = releaseLabelCutoff(release);
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
      }),
    }));
  }

  prReachabilityEvidenceForIssue(tag, issueNumber) {
    return this.db.prepare(`
      SELECT l.issue_number,
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
      JOIN pull_request_fixes p ON p.pr_number=l.pr_number
      JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_number=l.pr_number
      LEFT JOIN release_commits rc ON rc.tag=rpr.tag
      WHERE l.issue_number=?
        AND ${CREDITED_FIX_LINK_SQL}
      ORDER BY l.pr_number
    `).all(tag, issueNumber);
  }

  getReleaseScoreAudit(tag) {
    return this.db.prepare(`
      SELECT *
      FROM release_score_audits
      WHERE release_tag=?
    `).get(tag);
  }
}

function releaseLabelCutoff(rel) {
  if (!rel?.published_at || rel.hours_to_next_stable == null) return null;
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
  if (eventCount === 0) return options.useFallbackWhenNoEvents === false ? [] : fallbackLabels;
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
