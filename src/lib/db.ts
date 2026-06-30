import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { config } from '../config';
import type { IssueClassification } from './llm';
import { creditedFixLinkSql } from './fixProvenance';

// node:sqlite is built into Node ≥ 22.5 (stable since 24). No native build, no prebuilds.

export const dbReadOnly = process.env.RADAR_DB_READ_ONLY === '1' || process.env.RADAR_DB_READ_ONLY === 'true';
const defaultPrRepositoryOwner = config.github.owner;
const defaultPrRepositoryName = config.github.repo;
const defaultPrRepositoryNameWithOwner = `${defaultPrRepositoryOwner}/${defaultPrRepositoryName}`;

type PrRepositoryIdentity = {
  pr_repository_owner: string;
  pr_repository_name: string;
  pr_repository_name_with_owner: string;
};

function normalizePrRepository(input: {
  pr_repository_owner?: string | null;
  pr_repository_name?: string | null;
  pr_repository_name_with_owner?: string | null;
  url?: string | null;
}): PrRepositoryIdentity {
  const explicitNameWithOwner = String(input.pr_repository_name_with_owner ?? '').trim();
  if (explicitNameWithOwner.includes('/')) {
    const [owner, name] = explicitNameWithOwner.split('/', 2);
    if (owner && name) {
      return {
        pr_repository_owner: owner,
        pr_repository_name: name,
        pr_repository_name_with_owner: `${owner}/${name}`,
      };
    }
  }
  const owner = String(input.pr_repository_owner ?? '').trim();
  const name = String(input.pr_repository_name ?? '').trim();
  if (owner && name) {
    return {
      pr_repository_owner: owner,
      pr_repository_name: name,
      pr_repository_name_with_owner: `${owner}/${name}`,
    };
  }
  const parsed = prRepositoryFromUrl(input.url ?? null);
  if (parsed) return parsed;
  return {
    pr_repository_owner: defaultPrRepositoryOwner,
    pr_repository_name: defaultPrRepositoryName,
    pr_repository_name_with_owner: defaultPrRepositoryNameWithOwner,
  };
}

function prRepositoryFromUrl(url: string | null): PrRepositoryIdentity | null {
  const match = String(url ?? '').match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/pull\/\d+(?:[/?#].*)?$/i);
  if (!match) return null;
  return {
    pr_repository_owner: match[1],
    pr_repository_name: match[2],
    pr_repository_name_with_owner: `${match[1]}/${match[2]}`,
  };
}

if (!dbReadOnly) mkdirSync(dirname(config.db.path), { recursive: true });

export const db = dbReadOnly
  ? new DatabaseSync(config.db.path, { readOnly: true })
  : new DatabaseSync(config.db.path);

export function runInWriteTransaction<T>(fn: () => T): T {
  db.exec('BEGIN');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
// WAL improves concurrent reads but isn't supported on every mount (FUSE, some NFS).
// Fall back to the default rollback journal if it fails.
if (!dbReadOnly) {
  try {
    db.exec('PRAGMA journal_mode = WAL');
  } catch (e) {
    console.warn('[db] WAL not supported on this filesystem, falling back to default journal:', (e as Error).message);
  }
}
db.exec('PRAGMA foreign_keys = ON');
if (dbReadOnly) db.exec('PRAGMA query_only = ON');

if (!dbReadOnly) {
db.exec(`
CREATE TABLE IF NOT EXISTS releases (
  tag TEXT PRIMARY KEY,
  name TEXT,
  published_at TEXT,
  html_url TEXT,
  prerelease INTEGER NOT NULL DEFAULT 0,
  final_score REAL,
  risk_index REAL,
  negative_issues INTEGER,
  positive_issues INTEGER,
  scored_at TEXT,
  state TEXT,
  closed_serious_fixed INTEGER NOT NULL DEFAULT 0,
  fix_bonus REAL NOT NULL DEFAULT 0,
  opened_serious_during_reign INTEGER NOT NULL DEFAULT 0,
  -- Raw release-notes body. Stored verbatim so we can re-mine if the parser grows new signals.
  body TEXT,
  -- Maintainer-signal counts parsed from body by lib/releaseNotes.ts.
  -- breaking_count: bullets under "### Breaking" — explicit API/config breakage.
  -- fixes_count:    bullets under "### Fixes" — bugs the team owned and closed.
  -- changes_count:  bullets under "### Changes" — features/refactors shipped.
  -- highlights_count: bullets under "### Highlights" — items the team called out.
  -- pr_refs_count:  distinct #NNNNN PR refs across the entire body.
  -- beta_count:     prereleases between this stable and the previous stable (shake-out depth).
  -- hours_to_next_release: hours until the next release of ANY kind (incl. betas).
  -- hours_to_next_stable:  hours until the next STABLE — the install-relevant "how long
  --                        did this stay the current version" signal (betas ignored).
  -- recommended:    1 for the single release the Install Confidence model recommends.
  breaking_count INTEGER NOT NULL DEFAULT 0,
  fixes_count INTEGER NOT NULL DEFAULT 0,
  changes_count INTEGER NOT NULL DEFAULT 0,
  highlights_count INTEGER NOT NULL DEFAULT 0,
  pr_refs_count INTEGER NOT NULL DEFAULT 0,
  beta_count INTEGER NOT NULL DEFAULT 0,
  hours_to_next_release REAL,
  hours_to_next_stable REAL,
  recommended INTEGER NOT NULL DEFAULT 0,
  -- Short human explanation of the Install Confidence verdict, from lib/score.ts.
  score_reason TEXT,
  npm_package_url TEXT,
  release_tarball_url TEXT,
  release_integrity TEXT,
  release_sha TEXT,
  full_release_ci_report_url TEXT,
  full_release_validation_url TEXT,
  registry_version TEXT,
  registry_integrity TEXT,
  registry_tarball_url TEXT,
  ci_report_verified INTEGER NOT NULL DEFAULT 0,
  ci_report_mismatch TEXT,
  release_validation_verified INTEGER NOT NULL DEFAULT 0,
  release_validation_mismatch TEXT,
  artifact_verified INTEGER NOT NULL DEFAULT 0,
  artifact_mismatch TEXT,
  release_metadata_fetched_at TEXT,
  release_derived_fetched_at TEXT,
  release_artifact_checked_at TEXT,
  -- JSON array of the top product surfaces this release breaks (visible regressions),
  -- e.g. [{"label":"Discord","icon":"discord","count":11}]. See lib/surfaces.ts.
  broken_surfaces TEXT
);

CREATE TABLE IF NOT EXISTS issues (
  number INTEGER PRIMARY KEY,
  state TEXT NOT NULL,
  title TEXT NOT NULL,
  author TEXT,
  author_association TEXT,
  html_url TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT,
  comments INTEGER NOT NULL,
  unique_human_commenters INTEGER NOT NULL DEFAULT 0,
  maintainer_commenters INTEGER NOT NULL DEFAULT 0,
  contributor_commenters INTEGER NOT NULL DEFAULT 0,
  commenter_scan_truncated INTEGER NOT NULL DEFAULT 0,
  reaction_total INTEGER NOT NULL DEFAULT 0,
  positive_reactions INTEGER NOT NULL DEFAULT 0,
  labels TEXT NOT NULL DEFAULT '[]',
  is_bot INTEGER NOT NULL DEFAULT 0,
  fetched_at TEXT
);

CREATE TABLE IF NOT EXISTS classifications (
  issue_number INTEGER PRIMARY KEY,
  sentiment TEXT NOT NULL,
  severity TEXT NOT NULL,
  scope TEXT NOT NULL,
  functionality TEXT NOT NULL,
  affected_users TEXT NOT NULL,
  has_workaround INTEGER NOT NULL,
  workaround_status TEXT NOT NULL DEFAULT 'unknown',
  duplicate_cluster TEXT,
  affects_version TEXT,
  confidence REAL NOT NULL,
  rationale TEXT,
  classified_at TEXT NOT NULL,
  classified_updated_at TEXT NOT NULL,
  prompt_version INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (issue_number) REFERENCES issues(number) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_classifications_version ON classifications(affects_version);
CREATE INDEX IF NOT EXISTS idx_issues_updated ON issues(updated_at);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- GitHub Security Advisories cached for the repo. Refreshed on each cycle.
-- vulnerable_version_range / patched_versions are stored verbatim as GitHub
-- returns them; the matching logic lives in lib/versionMatch.ts.
CREATE TABLE IF NOT EXISTS advisories (
  ghsa_id TEXT PRIMARY KEY,
  cve_id TEXT,
  summary TEXT NOT NULL,
  severity TEXT NOT NULL,
  html_url TEXT NOT NULL,
  published_at TEXT,
  vulnerable_version_range TEXT,
  patched_versions TEXT,
  fetched_at TEXT NOT NULL
);

-- Rendered upstream web UI snapshots used for side-by-side model comparison.
-- These are deliberately separate from radar data so clearing/rebuilding the
-- local model never destroys the external benchmark.
CREATE TABLE IF NOT EXISTS comparison_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_url TEXT NOT NULL,
  captured_at TEXT NOT NULL,
  page_title TEXT NOT NULL,
  page_text TEXT NOT NULL,
  raw_html TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS comparison_releases (
  snapshot_id INTEGER NOT NULL,
  tag TEXT NOT NULL,
  name TEXT,
  published_at TEXT,
  html_url TEXT NOT NULL,
  displayed_date TEXT,
  score REAL,
  band TEXT,
  status TEXT,
  recommended INTEGER NOT NULL DEFAULT 0,
  reason TEXT,
  negative_issues INTEGER,
  positive_issues INTEGER,
  total_attributed_issues INTEGER,
  visible_issues_json TEXT NOT NULL DEFAULT '[]',
  raw_card_text TEXT NOT NULL,
  PRIMARY KEY (snapshot_id, tag),
  FOREIGN KEY (snapshot_id) REFERENCES comparison_snapshots(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_comparison_releases_tag ON comparison_releases(tag);

CREATE TABLE IF NOT EXISTS release_score_audits (
  release_tag TEXT PRIMARY KEY,
  scored_at TEXT NOT NULL,
  score_model_version TEXT NOT NULL,
  prompt_version INTEGER NOT NULL,
  final_score REAL,
  status TEXT NOT NULL,
  band TEXT NOT NULL,
  recommended INTEGER NOT NULL DEFAULT 0,
  input_json TEXT NOT NULL,
  components_json TEXT,
  issue_evidence_json TEXT NOT NULL,
  gate_evidence_json TEXT NOT NULL,
  FOREIGN KEY (release_tag) REFERENCES releases(tag) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS release_commits (
  tag TEXT PRIMARY KEY,
  tag_commit_oid TEXT,
  committed_at TEXT,
  check_state TEXT,
  check_total INTEGER NOT NULL DEFAULT 0,
  check_success INTEGER NOT NULL DEFAULT 0,
  check_failure INTEGER NOT NULL DEFAULT 0,
  check_pending INTEGER NOT NULL DEFAULT 0,
  check_skipped INTEGER NOT NULL DEFAULT 0,
  check_contexts_json TEXT NOT NULL DEFAULT '[]',
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issue_closure_events (
  issue_number INTEGER NOT NULL,
  event_id TEXT PRIMARY KEY,
  closed_at TEXT,
  actor_login TEXT,
  state_reason TEXT,
  closer_type TEXT,
  closer_number INTEGER,
  closer_oid TEXT,
  raw_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issue_reopen_events (
  issue_number INTEGER NOT NULL,
  event_id TEXT PRIMARY KEY,
  reopened_at TEXT,
  actor_login TEXT,
  raw_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issue_pr_links (
  issue_number INTEGER NOT NULL,
  pr_repository_owner TEXT NOT NULL,
  pr_repository_name TEXT NOT NULL,
  pr_repository_name_with_owner TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  source TEXT NOT NULL,
  will_close_target INTEGER,
  referenced_at TEXT,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (issue_number, pr_repository_name_with_owner, pr_number, source)
);

CREATE TABLE IF NOT EXISTS issue_commit_references (
  issue_number INTEGER NOT NULL,
  event_id TEXT PRIMARY KEY,
  commit_oid TEXT NOT NULL,
  commit_message_headline TEXT,
  commit_repository_owner TEXT,
  commit_repository_name TEXT,
  commit_repository_name_with_owner TEXT,
  is_cross_repository INTEGER NOT NULL DEFAULT 0,
  is_direct_reference INTEGER NOT NULL DEFAULT 0,
  referenced_at TEXT,
  actor_login TEXT,
  raw_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issue_label_events (
  issue_number INTEGER NOT NULL,
  event_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  label_name TEXT NOT NULL,
  actor_login TEXT,
  created_at TEXT NOT NULL,
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issue_label_snapshots (
  issue_number INTEGER NOT NULL,
  snapshot_at TEXT NOT NULL,
  labels_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (issue_number, snapshot_at)
);

CREATE TABLE IF NOT EXISTS issue_closure_proofs (
  release_tag TEXT NOT NULL,
  issue_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  PRIMARY KEY (release_tag, issue_number)
);

CREATE TABLE IF NOT EXISTS pull_request_fixes (
  pr_repository_owner TEXT NOT NULL,
  pr_repository_name TEXT NOT NULL,
  pr_repository_name_with_owner TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  title TEXT,
  url TEXT,
  state TEXT,
  merged INTEGER NOT NULL DEFAULT 0,
  merged_at TEXT,
  merge_commit_oid TEXT,
  base_ref_name TEXT,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (pr_repository_name_with_owner, pr_number)
);

CREATE TABLE IF NOT EXISTS release_pr_reachability (
  tag TEXT NOT NULL,
  pr_repository_owner TEXT NOT NULL,
  pr_repository_name TEXT NOT NULL,
  pr_repository_name_with_owner TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  tag_commit_oid TEXT,
  merge_commit_oid TEXT,
  base_ref_name TEXT,
  status TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'git-merge-base',
  evidence_json TEXT NOT NULL DEFAULT '{}',
  checked_at TEXT NOT NULL,
  PRIMARY KEY (tag, pr_repository_name_with_owner, pr_number)
);

CREATE TABLE IF NOT EXISTS ingestion_evidence_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  source TEXT NOT NULL,
  scope TEXT,
  release_tag TEXT,
  issue_number INTEGER,
  pr_repository_name_with_owner TEXT,
  pr_number INTEGER,
  message TEXT NOT NULL,
  context_json TEXT,
  scoring_blocking INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_issue_closure_events_issue ON issue_closure_events(issue_number);
CREATE INDEX IF NOT EXISTS idx_issue_reopen_events_issue_time ON issue_reopen_events(issue_number, reopened_at);
CREATE INDEX IF NOT EXISTS idx_issue_pr_links_issue ON issue_pr_links(issue_number);
CREATE INDEX IF NOT EXISTS idx_issue_commit_references_issue ON issue_commit_references(issue_number);
CREATE INDEX IF NOT EXISTS idx_issue_label_events_issue_time ON issue_label_events(issue_number, created_at);
CREATE INDEX IF NOT EXISTS idx_issue_label_snapshots_issue_time ON issue_label_snapshots(issue_number, snapshot_at);
CREATE INDEX IF NOT EXISTS idx_issue_closure_proofs_release ON issue_closure_proofs(release_tag, status);
CREATE INDEX IF NOT EXISTS idx_release_pr_reachability_tag ON release_pr_reachability(tag);
CREATE INDEX IF NOT EXISTS idx_ingestion_evidence_failures_occurred ON ingestion_evidence_failures(occurred_at);
CREATE INDEX IF NOT EXISTS idx_ingestion_evidence_failures_run ON ingestion_evidence_failures(run_id);
CREATE INDEX IF NOT EXISTS idx_ingestion_evidence_failures_release ON ingestion_evidence_failures(release_tag, occurred_at);
`);

// Idempotent migrations for existing DBs. ALTER TABLE ADD COLUMN errors if the
// column already exists, so we swallow the error rather than guard it.
for (const sql of [
  `ALTER TABLE issues ADD COLUMN is_bot INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE issues ADD COLUMN author_association TEXT`,
  `ALTER TABLE issues ADD COLUMN unique_human_commenters INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE issues ADD COLUMN maintainer_commenters INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE issues ADD COLUMN contributor_commenters INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE issues ADD COLUMN commenter_scan_truncated INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE issues ADD COLUMN reaction_total INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE issues ADD COLUMN positive_reactions INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE issues ADD COLUMN fetched_at TEXT`,
  `ALTER TABLE release_commits ADD COLUMN check_state TEXT`,
  `ALTER TABLE release_commits ADD COLUMN check_total INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE release_commits ADD COLUMN check_success INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE release_commits ADD COLUMN check_failure INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE release_commits ADD COLUMN check_pending INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE release_commits ADD COLUMN check_skipped INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE release_commits ADD COLUMN check_contexts_json TEXT NOT NULL DEFAULT '[]'`,
  `ALTER TABLE classifications ADD COLUMN workaround_status TEXT NOT NULL DEFAULT 'unknown'`,
  `ALTER TABLE classifications ADD COLUMN prompt_version INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN state TEXT`,
  `ALTER TABLE releases ADD COLUMN closed_serious_fixed INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN fix_bonus REAL NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN opened_serious_during_reign INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN body TEXT`,
  `ALTER TABLE releases ADD COLUMN breaking_count INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN fixes_count INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN changes_count INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN highlights_count INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN pr_refs_count INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN beta_count INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN hours_to_next_release REAL`,
  `ALTER TABLE releases ADD COLUMN hours_to_next_stable REAL`,
  `ALTER TABLE releases ADD COLUMN recommended INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN score_reason TEXT`,
  `ALTER TABLE releases ADD COLUMN npm_package_url TEXT`,
  `ALTER TABLE releases ADD COLUMN release_tarball_url TEXT`,
  `ALTER TABLE releases ADD COLUMN release_integrity TEXT`,
  `ALTER TABLE releases ADD COLUMN release_sha TEXT`,
  `ALTER TABLE releases ADD COLUMN full_release_ci_report_url TEXT`,
  `ALTER TABLE releases ADD COLUMN full_release_validation_url TEXT`,
  `ALTER TABLE releases ADD COLUMN registry_version TEXT`,
  `ALTER TABLE releases ADD COLUMN registry_integrity TEXT`,
  `ALTER TABLE releases ADD COLUMN registry_tarball_url TEXT`,
  `ALTER TABLE releases ADD COLUMN ci_report_verified INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN ci_report_mismatch TEXT`,
  `ALTER TABLE releases ADD COLUMN release_validation_verified INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN release_validation_mismatch TEXT`,
  `ALTER TABLE releases ADD COLUMN artifact_verified INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN artifact_mismatch TEXT`,
  `ALTER TABLE releases ADD COLUMN release_metadata_fetched_at TEXT`,
  `ALTER TABLE releases ADD COLUMN release_derived_fetched_at TEXT`,
  `ALTER TABLE releases ADD COLUMN release_artifact_checked_at TEXT`,
  `ALTER TABLE releases ADD COLUMN broken_surfaces TEXT`,
  `ALTER TABLE issue_commit_references ADD COLUMN commit_message_headline TEXT`,
]) {
  try { db.exec(sql); } catch { /* column already exists */ }
}

try {
  const issueCrawlFinishedAt = (() => {
    const row = db.prepare(`SELECT value FROM meta WHERE key='issue_crawl_last_run'`).get() as { value?: string } | undefined;
    if (!row?.value) return null;
    try {
      const parsed = JSON.parse(row.value);
      return typeof parsed.finishedAt === 'string' ? parsed.finishedAt : null;
    } catch {
      return null;
    }
  })();
  db.prepare(`
    UPDATE issues
    SET fetched_at=COALESCE(?, updated_at)
    WHERE fetched_at IS NULL
  `).run(issueCrawlFinishedAt);
  db.exec(`
    UPDATE releases
    SET
      release_metadata_fetched_at=COALESCE(
        release_metadata_fetched_at,
        (SELECT MAX(fetched_at) FROM release_commits WHERE release_commits.tag=releases.tag),
        scored_at,
        published_at
      ),
      release_derived_fetched_at=COALESCE(
        release_derived_fetched_at,
        (SELECT MAX(fetched_at) FROM release_commits WHERE release_commits.tag=releases.tag),
        scored_at,
        published_at
      ),
      release_artifact_checked_at=COALESCE(
        release_artifact_checked_at,
        (SELECT MAX(fetched_at) FROM release_commits WHERE release_commits.tag=releases.tag),
        scored_at,
        published_at
      )
    WHERE release_metadata_fetched_at IS NULL
       OR release_derived_fetched_at IS NULL
       OR release_artifact_checked_at IS NULL
  `);
} catch {
  // Best-effort backfill for DBs that predate freshness columns/tables.
}

try {
  const tableColumns = (table: string) =>
    db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string; notnull: number; pk: number }>;
  const hasCompositePrKey = (table: string) => {
    const cols = tableColumns(table);
    const repoCol = cols.find((col) => col.name === 'pr_repository_name_with_owner');
    return !!repoCol && repoCol.pk > 0;
  };

  if (!hasCompositePrKey('pull_request_fixes')) {
    const rows = db.prepare(`SELECT * FROM pull_request_fixes`).all() as Array<any>;
    db.exec(`DROP TABLE IF EXISTS pull_request_fixes_next`);
    db.exec(`
    CREATE TABLE pull_request_fixes_next (
      pr_repository_owner TEXT NOT NULL,
      pr_repository_name TEXT NOT NULL,
      pr_repository_name_with_owner TEXT NOT NULL,
      pr_number INTEGER NOT NULL,
      title TEXT,
      url TEXT,
      state TEXT,
      merged INTEGER NOT NULL DEFAULT 0,
      merged_at TEXT,
      merge_commit_oid TEXT,
      base_ref_name TEXT,
      fetched_at TEXT NOT NULL,
      PRIMARY KEY (pr_repository_name_with_owner, pr_number)
    )`);
    const insert = db.prepare(`
      INSERT OR REPLACE INTO pull_request_fixes_next (
        pr_repository_owner, pr_repository_name, pr_repository_name_with_owner,
        pr_number, title, url, state, merged, merged_at, merge_commit_oid, base_ref_name, fetched_at
      )
      VALUES (
        :pr_repository_owner, :pr_repository_name, :pr_repository_name_with_owner,
        :pr_number, :title, :url, :state, :merged, :merged_at, :merge_commit_oid, :base_ref_name, :fetched_at
      )
    `);
    for (const row of rows) {
      const repo = normalizePrRepository(row);
      insert.run({
        ...repo,
        pr_number: row.pr_number,
        title: row.title ?? null,
        url: row.url ?? null,
        state: row.state ?? null,
        merged: Number(row.merged ?? 0),
        merged_at: row.merged_at ?? null,
        merge_commit_oid: row.merge_commit_oid ?? null,
        base_ref_name: row.base_ref_name ?? null,
        fetched_at: row.fetched_at ?? new Date().toISOString(),
      });
    }
    db.exec(`DROP TABLE pull_request_fixes`);
    db.exec(`ALTER TABLE pull_request_fixes_next RENAME TO pull_request_fixes`);
  }

  if (!hasCompositePrKey('issue_pr_links')) {
    const rows = db.prepare(`
      SELECT l.*,
        (
          SELECT p.url
          FROM pull_request_fixes p
          WHERE p.pr_number=l.pr_number
          ORDER BY CASE WHEN p.pr_repository_name_with_owner=? THEN 0 ELSE 1 END
          LIMIT 1
        ) AS pr_url
      FROM issue_pr_links l
    `).all(defaultPrRepositoryNameWithOwner) as Array<any>;
    db.exec(`DROP TABLE IF EXISTS issue_pr_links_next`);
    db.exec(`
    CREATE TABLE issue_pr_links_next (
      issue_number INTEGER NOT NULL,
      pr_repository_owner TEXT NOT NULL,
      pr_repository_name TEXT NOT NULL,
      pr_repository_name_with_owner TEXT NOT NULL,
      pr_number INTEGER NOT NULL,
      source TEXT NOT NULL,
      will_close_target INTEGER,
      referenced_at TEXT,
      fetched_at TEXT NOT NULL,
      PRIMARY KEY (issue_number, pr_repository_name_with_owner, pr_number, source)
    )`);
    const insert = db.prepare(`
      INSERT OR REPLACE INTO issue_pr_links_next (
        issue_number, pr_repository_owner, pr_repository_name, pr_repository_name_with_owner,
        pr_number, source, will_close_target, referenced_at, fetched_at
      )
      VALUES (
        :issue_number, :pr_repository_owner, :pr_repository_name, :pr_repository_name_with_owner,
        :pr_number, :source, :will_close_target, :referenced_at, :fetched_at
      )
    `);
    for (const row of rows) {
      const repo = normalizePrRepository({
        pr_repository_owner: row.pr_repository_owner,
        pr_repository_name: row.pr_repository_name,
        pr_repository_name_with_owner: row.pr_repository_name_with_owner,
        url: row.pr_url,
      });
      insert.run({
        ...repo,
        issue_number: row.issue_number,
        pr_number: row.pr_number,
        source: row.source,
        will_close_target: row.will_close_target ?? null,
        referenced_at: row.referenced_at ?? null,
        fetched_at: row.fetched_at ?? new Date().toISOString(),
      });
    }
    db.exec(`DROP TABLE issue_pr_links`);
    db.exec(`ALTER TABLE issue_pr_links_next RENAME TO issue_pr_links`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_issue_pr_links_issue ON issue_pr_links(issue_number)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_issue_pr_links_pr ON issue_pr_links(pr_repository_name_with_owner, pr_number)`);
  }

  const reachabilityCols = tableColumns('release_pr_reachability');
  const reachabilityNeedsMigration = !hasCompositePrKey('release_pr_reachability') ||
    (reachabilityCols.find((col) => col.name === 'tag_commit_oid')?.notnull ?? 0) !== 0 ||
    (reachabilityCols.find((col) => col.name === 'merge_commit_oid')?.notnull ?? 0) !== 0;
  if (reachabilityNeedsMigration) {
    const hasTagCommit = reachabilityCols.some((col) => col.name === 'tag_commit_oid');
    const hasMergeCommit = reachabilityCols.some((col) => col.name === 'merge_commit_oid');
    const rows = db.prepare(`
      SELECT
        tag,
        pr_number,
        ${hasTagCommit ? 'tag_commit_oid' : 'NULL'} AS tag_commit_oid,
        ${hasMergeCommit ? 'merge_commit_oid' : 'NULL'} AS merge_commit_oid,
        base_ref_name,
        status,
        method,
        evidence_json,
        checked_at
      FROM release_pr_reachability
    `).all() as Array<any>;
    db.exec(`DROP TABLE IF EXISTS release_pr_reachability_next`);
    db.exec(`
    CREATE TABLE release_pr_reachability_next (
      tag TEXT NOT NULL,
      pr_repository_owner TEXT NOT NULL,
      pr_repository_name TEXT NOT NULL,
      pr_repository_name_with_owner TEXT NOT NULL,
      pr_number INTEGER NOT NULL,
      tag_commit_oid TEXT,
      merge_commit_oid TEXT,
      base_ref_name TEXT,
      status TEXT NOT NULL,
      method TEXT NOT NULL DEFAULT 'git-merge-base',
      evidence_json TEXT NOT NULL DEFAULT '{}',
      checked_at TEXT NOT NULL,
      PRIMARY KEY (tag, pr_repository_name_with_owner, pr_number)
    )`);
    const insert = db.prepare(`
      INSERT OR REPLACE INTO release_pr_reachability_next (
        tag, pr_repository_owner, pr_repository_name, pr_repository_name_with_owner,
        pr_number, tag_commit_oid, merge_commit_oid, base_ref_name, status, method, evidence_json, checked_at
      )
      VALUES (
        :tag, :pr_repository_owner, :pr_repository_name, :pr_repository_name_with_owner,
        :pr_number, :tag_commit_oid, :merge_commit_oid, :base_ref_name, :status, :method, :evidence_json, :checked_at
      )
    `);
    for (const row of rows) {
      insert.run({
        tag: row.tag,
        pr_number: row.pr_number,
        ...normalizePrRepository(row),
        tag_commit_oid: row.tag_commit_oid ?? null,
        merge_commit_oid: row.merge_commit_oid ?? null,
        base_ref_name: row.base_ref_name ?? null,
        status: row.status,
        method: row.method ?? 'git-merge-base',
        evidence_json: row.evidence_json ?? '{}',
        checked_at: row.checked_at ?? new Date().toISOString(),
      });
    }
    db.exec(`DROP TABLE release_pr_reachability`);
    db.exec(`ALTER TABLE release_pr_reachability_next RENAME TO release_pr_reachability`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_release_pr_reachability_tag ON release_pr_reachability(tag)`);
  }
} catch {
  // The main CREATE TABLE block handles first-run setup; this only repairs old local schemas.
}

try {
  db.exec(`CREATE INDEX IF NOT EXISTS idx_issue_pr_links_pr ON issue_pr_links(pr_repository_name_with_owner, pr_number)`);
} catch {
  // If a very old schema could not be repaired, later verification will surface the real failure.
}
}

// Bot detection. Cheap, deterministic, no extra LLM tokens.
// Markers we consider bot-generated:
//   - login ends with [bot] (GitHub's convention for app installations)
//   - login matches a known automation pattern (dependabot, renovate, …)
// Maintainer triage tools (e.g. `clawsweeper:*` labels) describe workflow stage on issues
// filed by real humans — they MUST NOT trigger bot detection. Earlier the regex looked at
// labels and treated `clawsweeper:needs-live-repro` as evidence of bot authorship, which
// dampened 91% of real bug reports and made every release look stable-by-mistake.
// Marked issues are NOT excluded from scoring — they're down-weighted in score.ts.
const BOT_AUTHOR_RE = /\[bot\]$|^(github-actions|dependabot|renovate(-bot)?|mergify|stale)$/i;

export function detectBot(author: string | null, _labelsJson: string): boolean {
  if (author && BOT_AUTHOR_RE.test(author)) return true;
  return false;
}

// ---------- releases ----------
export interface ReleaseRow {
  tag: string;
  name: string | null;
  published_at: string | null;
  html_url: string;
  prerelease: number;
  final_score: number | null;
  risk_index: number | null;
  negative_issues: number | null;
  positive_issues: number | null;
  scored_at: string | null;
  // 'analyzing' (<3h grace), 'insufficient' (no negative signal), 'rated', or null
  // for pre-migration rows that haven't been re-scored yet.
  state: string | null;
  // Core-serious bugs closed during this release's reign — the "fixes credit".
  closed_serious_fixed: number;
  // Score points added by those fixes (already included in final_score).
  fix_bonus: number;
  // Core-serious bugs OPENED during this release's reign — informational only,
  // surfaces "this release shipped fixes but also brought regressions" without
  // penalising the score (would create a fight with the recommendation block).
  opened_serious_during_reign: number;
  // Raw release-notes body (markdown). Kept so we can re-mine if the parser
  // grows new signals without re-fetching from GitHub.
  body: string | null;
  // Maintainer-signal counts. See db.ts CREATE TABLE comment block for what
  // each one means.
  breaking_count: number;
  fixes_count: number;
  changes_count: number;
  highlights_count: number;
  pr_refs_count: number;
  beta_count: number;
  hours_to_next_release: number | null;
  hours_to_next_stable: number | null;
  recommended: number;
  score_reason: string | null;
  npm_package_url: string | null;
  release_tarball_url: string | null;
  release_integrity: string | null;
  release_sha: string | null;
  full_release_ci_report_url: string | null;
  full_release_validation_url: string | null;
  registry_version: string | null;
  registry_integrity: string | null;
  registry_tarball_url: string | null;
  ci_report_verified: number;
  ci_report_mismatch: string | null;
  release_validation_verified: number;
  release_validation_mismatch: string | null;
  artifact_verified: number;
  artifact_mismatch: string | null;
  release_metadata_fetched_at: string | null;
  release_derived_fetched_at: string | null;
  release_artifact_checked_at: string | null;
  broken_surfaces: string | null;
}

const upsertReleaseStmt = db.prepare(`
INSERT INTO releases (tag, name, published_at, html_url, prerelease, body, release_metadata_fetched_at)
VALUES (:tag, :name, :published_at, :html_url, :prerelease, :body, :release_metadata_fetched_at)
ON CONFLICT(tag) DO UPDATE SET
  name=excluded.name,
  published_at=excluded.published_at,
  html_url=excluded.html_url,
  prerelease=excluded.prerelease,
  body=excluded.body,
  release_metadata_fetched_at=excluded.release_metadata_fetched_at
`);

export function upsertRelease(r: {
  tag: string;
  name: string | null;
  published_at: string | null;
  html_url: string;
  prerelease: boolean;
  body: string | null;
}): void {
  upsertReleaseStmt.run({
    ...r,
    prerelease: r.prerelease ? 1 : 0,
    release_metadata_fetched_at: new Date().toISOString(),
  });
}

const updateReleaseDerivedStatsStmt = db.prepare(`
UPDATE releases SET
  breaking_count=:breaking_count,
  fixes_count=:fixes_count,
  changes_count=:changes_count,
  highlights_count=:highlights_count,
  pr_refs_count=:pr_refs_count,
  beta_count=:beta_count,
  hours_to_next_release=:hours_to_next_release,
  hours_to_next_stable=:hours_to_next_stable,
  npm_package_url=:npm_package_url,
  release_tarball_url=:release_tarball_url,
  release_integrity=:release_integrity,
  release_sha=:release_sha,
  full_release_ci_report_url=:full_release_ci_report_url,
  full_release_validation_url=:full_release_validation_url,
  release_derived_fetched_at=:release_derived_fetched_at
WHERE tag=:tag
`);

export function updateReleaseDerivedStats(args: {
  tag: string;
  breaking_count: number;
  fixes_count: number;
  changes_count: number;
  highlights_count: number;
  pr_refs_count: number;
  beta_count: number;
  hours_to_next_release: number | null;
  hours_to_next_stable: number | null;
  npm_package_url?: string | null;
  release_tarball_url?: string | null;
  release_integrity?: string | null;
  release_sha?: string | null;
  full_release_ci_report_url?: string | null;
  full_release_validation_url?: string | null;
}): void {
  updateReleaseDerivedStatsStmt.run({
    ...args,
    npm_package_url: args.npm_package_url ?? null,
    release_tarball_url: args.release_tarball_url ?? null,
    release_integrity: args.release_integrity ?? null,
    release_sha: args.release_sha ?? null,
    full_release_ci_report_url: args.full_release_ci_report_url ?? null,
    full_release_validation_url: args.full_release_validation_url ?? null,
    release_derived_fetched_at: new Date().toISOString(),
  });
}

const updateReleaseArtifactVerificationStmt = db.prepare(`
UPDATE releases SET
  registry_version=:registry_version,
  registry_integrity=:registry_integrity,
  registry_tarball_url=:registry_tarball_url,
  ci_report_verified=:ci_report_verified,
  ci_report_mismatch=:ci_report_mismatch,
  release_validation_verified=:release_validation_verified,
  release_validation_mismatch=:release_validation_mismatch,
  artifact_verified=:artifact_verified,
  artifact_mismatch=:artifact_mismatch,
  release_artifact_checked_at=:release_artifact_checked_at
WHERE tag=:tag
`);

export function updateReleaseArtifactVerification(args: {
  tag: string;
  registry_version: string | null;
  registry_integrity: string | null;
  registry_tarball_url: string | null;
  ci_report_verified: number;
  ci_report_mismatch: string | null;
  release_validation_verified: number;
  release_validation_mismatch: string | null;
  artifact_verified: number;
  artifact_mismatch: string | null;
}): void {
  updateReleaseArtifactVerificationStmt.run({
    ...args,
    release_artifact_checked_at: new Date().toISOString(),
  });
}

// Install Confidence score writer. final_score is the 0–10 IC (NULL when 'wait').
// `state` carries the install status: 'wait' | 'skip-cve' | 'skip-hotfix' | 'eligible'.
// risk_index / fix_bonus are legacy columns from the old model — left untouched here.
const updateScoreStmt = db.prepare(`
UPDATE releases SET final_score=:final_score,
  negative_issues=:negative_issues, positive_issues=:positive_issues,
  state=:state, recommended=:recommended, score_reason=:score_reason,
  broken_surfaces=:broken_surfaces,
  closed_serious_fixed=:closed_serious_fixed,
  opened_serious_during_reign=:opened_serious_during_reign,
  scored_at=:scored_at
WHERE tag=:tag
`);

export function updateReleaseScore(args: {
  tag: string;
  final_score: number | null;
  negative_issues: number;
  positive_issues: number;
  state: string;
  recommended: number;
  score_reason: string;
  broken_surfaces: string;
  closed_serious_fixed: number;
  opened_serious_during_reign: number;
  scored_at?: string;
}): void {
  updateScoreStmt.run({ ...args, scored_at: args.scored_at ?? new Date().toISOString() });
}

export interface ReleaseScoreAuditInput {
  release_tag: string;
  scored_at: string;
  score_model_version: string;
  prompt_version: number;
  final_score: number | null;
  status: string;
  band: string;
  recommended: number;
  input_json: string;
  components_json: string | null;
  issue_evidence_json: string;
  gate_evidence_json: string;
}

const upsertReleaseScoreAuditStmt = db.prepare(`
INSERT INTO release_score_audits (
  release_tag, scored_at, score_model_version, prompt_version, final_score,
  status, band, recommended, input_json, components_json, issue_evidence_json,
  gate_evidence_json
)
VALUES (
  :release_tag, :scored_at, :score_model_version, :prompt_version, :final_score,
  :status, :band, :recommended, :input_json, :components_json, :issue_evidence_json,
  :gate_evidence_json
)
ON CONFLICT(release_tag) DO UPDATE SET
  scored_at=excluded.scored_at,
  score_model_version=excluded.score_model_version,
  prompt_version=excluded.prompt_version,
  final_score=excluded.final_score,
  status=excluded.status,
  band=excluded.band,
  recommended=excluded.recommended,
  input_json=excluded.input_json,
  components_json=excluded.components_json,
  issue_evidence_json=excluded.issue_evidence_json,
  gate_evidence_json=excluded.gate_evidence_json
`);

export function upsertReleaseScoreAudit(input: ReleaseScoreAuditInput): void {
  upsertReleaseScoreAuditStmt.run(input as unknown as Record<string, string | number | null>);
}

export interface ReleaseScoreAuditRow extends ReleaseScoreAuditInput {}

const getReleaseScoreAuditStmt = db.prepare(`SELECT * FROM release_score_audits WHERE release_tag=?`);
export function getReleaseScoreAudit(tag: string): ReleaseScoreAuditRow | undefined {
  return getReleaseScoreAuditStmt.get(tag) as ReleaseScoreAuditRow | undefined;
}

const releaseScoreAuditFreshnessStmt = db.prepare(`
SELECT
  release_tag,
  scored_at,
  score_model_version,
  prompt_version,
  final_score,
  status,
  band,
  recommended,
  input_json,
  components_json,
  issue_evidence_json,
  gate_evidence_json
FROM release_score_audits
ORDER BY release_tag
`);
export function releaseScoreAuditFreshness(): { count: number; max_scored_at: string | null; digest: string } {
  const rows = releaseScoreAuditFreshnessStmt.all() as Array<Record<string, unknown>>;
  const hash = createHash('sha256');
  let maxScoredAt: string | null = null;
  for (const row of rows) {
    const scoredAt = typeof row.scored_at === 'string' ? row.scored_at : null;
    if (scoredAt && (!maxScoredAt || scoredAt > maxScoredAt)) maxScoredAt = scoredAt;
    hash.update(JSON.stringify(row));
    hash.update('\n');
  }
  return {
    count: rows.length,
    max_scored_at: maxScoredAt,
    digest: hash.digest('hex'),
  };
}

const publicReleaseRowsFreshnessStmt = db.prepare(`
SELECT
  tag,
  published_at,
  html_url,
  final_score,
  state,
  recommended,
  score_reason,
  negative_issues,
  positive_issues,
  scored_at,
  broken_surfaces,
  closed_serious_fixed,
  opened_serious_during_reign
FROM releases
ORDER BY published_at DESC
LIMIT ?
`);
export function publicReleaseRowsFreshness(limit: number): { count: number; max_scored_at: string | null; digest: string } {
  const rows = publicReleaseRowsFreshnessStmt.all(Math.max(1, Math.floor(limit))) as Array<Record<string, unknown>>;
  const hash = createHash('sha256');
  let maxScoredAt: string | null = null;
  for (const row of rows) {
    const scoredAt = typeof row.scored_at === 'string' ? row.scored_at : null;
    if (scoredAt && (!maxScoredAt || scoredAt > maxScoredAt)) maxScoredAt = scoredAt;
    hash.update(JSON.stringify(row));
    hash.update('\n');
  }
  return {
    count: rows.length,
    max_scored_at: maxScoredAt,
    digest: hash.digest('hex'),
  };
}

const publicIssueSummaryFreshnessStmt = db.prepare(`
WITH target_releases AS (
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
  WHERE prerelease=0
  ORDER BY published_at DESC
  LIMIT ?
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
),
issue_universe AS (
  SELECT DISTINCT i.number
  FROM issues i
  JOIN target_releases target
  WHERE target.start_at IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM issue_open_intervals interval
      WHERE interval.issue_number=i.number
        AND interval.open_at < target.end_at
        AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
    )
)
SELECT
  'issue' AS source,
  CAST(i.number AS TEXT) AS item_key,
  i.updated_at AS max_ts,
  i.number AS a,
  i.state AS b,
  i.title AS c,
  i.author AS d,
  i.author_association AS e,
  i.html_url AS f,
  i.created_at AS g,
  i.updated_at AS h,
  i.closed_at AS i,
  i.comments AS j,
  i.unique_human_commenters AS k,
  i.maintainer_commenters AS l,
  i.contributor_commenters AS m,
  i.commenter_scan_truncated AS n,
  i.reaction_total AS o,
  i.positive_reactions AS p,
  i.labels AS q,
  i.is_bot AS r
FROM issues i
JOIN issue_universe u ON u.number=i.number
UNION ALL
SELECT
  'classification' AS source,
  CAST(c.issue_number AS TEXT) AS item_key,
  c.classified_at AS max_ts,
  c.issue_number AS a,
  c.sentiment AS b,
  c.severity AS c,
  c.scope AS d,
  c.functionality AS e,
  c.affected_users AS f,
  c.has_workaround AS g,
  c.workaround_status AS h,
  c.duplicate_cluster AS i,
  c.affects_version AS j,
  c.confidence AS k,
  c.rationale AS l,
  c.classified_at AS m,
  c.classified_updated_at AS n,
  c.prompt_version AS o,
  NULL AS p,
  NULL AS q,
  NULL AS r
FROM classifications c
JOIN issue_universe u ON u.number=c.issue_number
UNION ALL
SELECT
  'label_event' AS source,
  CAST(e.issue_number AS TEXT) || ':' || e.event_id AS item_key,
  e.fetched_at AS max_ts,
  e.issue_number AS a,
  e.event_id AS b,
  e.action AS c,
  e.label_name AS d,
  e.actor_login AS e,
  e.created_at AS f,
  e.fetched_at AS g,
  NULL AS h,
  NULL AS i,
  NULL AS j,
  NULL AS k,
  NULL AS l,
  NULL AS m,
  NULL AS n,
  NULL AS o,
  NULL AS p,
  NULL AS q,
  NULL AS r
FROM issue_label_events e
JOIN issue_universe u ON u.number=e.issue_number
UNION ALL
SELECT
  'label_snapshot' AS source,
  CAST(s.issue_number AS TEXT) || ':' || s.snapshot_at AS item_key,
  s.fetched_at AS max_ts,
  s.issue_number AS a,
  s.snapshot_at AS b,
  s.labels_json AS c,
  s.fetched_at AS d,
  NULL AS e,
  NULL AS f,
  NULL AS g,
  NULL AS h,
  NULL AS i,
  NULL AS j,
  NULL AS k,
  NULL AS l,
  NULL AS m,
  NULL AS n,
  NULL AS o,
  NULL AS p,
  NULL AS q,
  NULL AS r
FROM issue_label_snapshots s
JOIN issue_universe u ON u.number=s.issue_number
ORDER BY source, item_key
`);

export function publicIssueSummaryFreshness(limit: number): { count: number; max_ts: string | null; digest: string } {
  const rows = publicIssueSummaryFreshnessStmt.all(Math.max(1, Math.floor(limit))) as Array<Record<string, unknown> & { max_ts?: string | null }>;
  const hash = createHash('sha256');
  let maxTs: string | null = null;
  for (const row of rows) {
    const ts = typeof row.max_ts === 'string' ? row.max_ts : null;
    if (ts && (!maxTs || ts > maxTs)) maxTs = ts;
    hash.update(JSON.stringify(row));
    hash.update('\n');
  }
  return {
    count: rows.length,
    max_ts: maxTs,
    digest: hash.digest('hex'),
  };
}

export interface ReleaseDataFreshnessSource {
  source: string;
  count: number;
  nullCount: number;
  maxAt: string | null;
  ageHoursAtScore: number | null;
}

export interface ReleaseDataFreshness {
  schemaVersion: 1;
  tag: string;
  scoredAt: string | null;
  issueUpdatedAtMax: string | null;
  issueUpdatedAgeHoursAtScore: number | null;
  closureProofCheckedAtMax: string | null;
  sourceFetchedAtMax: string | null;
  sourceFetchedAgeHoursAtScore: number | null;
  sources: ReleaseDataFreshnessSource[];
}

function tableHasColumns(table: string, columns: string[]): boolean {
  const existing = new Set((db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((col) => col.name));
  return columns.every((column) => existing.has(column));
}

const hasReleaseRowFreshnessColumns = tableHasColumns('releases', [
  'release_metadata_fetched_at',
  'release_derived_fetched_at',
  'release_artifact_checked_at',
]);
const hasIssueFetchFreshnessColumn = tableHasColumns('issues', ['fetched_at']);

const releaseDataFreshnessStmt = db.prepare(`
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
),
issue_universe AS (
  SELECT DISTINCT i.number
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
),
closed_universe AS (
  SELECT DISTINCT i.number
  FROM issues i
  JOIN target
  WHERE i.closed_at IS NOT NULL
    AND i.closed_at >= target.start_at
    AND i.closed_at < target.end_at
),
pr_universe AS (
  SELECT DISTINCT l.pr_repository_name_with_owner, l.pr_number
  FROM issue_pr_links l
  JOIN closed_universe c ON c.number=l.issue_number
  WHERE ${creditedFixLinkSql('l')}
),
	sources(source, count, null_count, max_ts) AS (
	  SELECT 'release_metadata', COUNT(*), COALESCE(SUM(CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END), 0), MAX(updated_at)
	  FROM (
	    ${hasReleaseRowFreshnessColumns ? `
	    SELECT r.release_metadata_fetched_at AS updated_at FROM releases r JOIN target ON target.tag=r.tag
    UNION ALL
    SELECT r.release_derived_fetched_at FROM releases r JOIN target ON target.tag=r.tag
    UNION ALL
    SELECT r.release_artifact_checked_at FROM releases r JOIN target ON target.tag=r.tag
    UNION ALL
    ` : ''}
    SELECT fetched_at AS updated_at FROM release_commits WHERE tag=?
    UNION ALL
    SELECT fetched_at FROM advisories
	  )
	  UNION ALL
	  SELECT 'issue_rows', COUNT(*), COALESCE(SUM(CASE WHEN i.updated_at IS NULL THEN 1 ELSE 0 END), 0), MAX(i.updated_at)
	  FROM issues i JOIN issue_universe u ON u.number=i.number
	  ${hasIssueFetchFreshnessColumn ? `UNION ALL
	  SELECT 'issue_fetches', COUNT(*), COALESCE(SUM(CASE WHEN i.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(i.fetched_at)
	  FROM issues i JOIN issue_universe u ON u.number=i.number` : ''}
	  UNION ALL
	  SELECT 'classification_rows', COUNT(*), COALESCE(SUM(CASE WHEN c.classified_at IS NULL THEN 1 ELSE 0 END), 0), MAX(c.classified_at)
	  FROM classifications c JOIN issue_universe u ON u.number=c.issue_number
	  UNION ALL
	  SELECT 'label_events', COUNT(*), COALESCE(SUM(CASE WHEN e.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(e.fetched_at)
	  FROM issue_label_events e JOIN issue_universe u ON u.number=e.issue_number
	  UNION ALL
	  SELECT 'label_snapshots', COUNT(*), COALESCE(SUM(CASE WHEN s.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(s.fetched_at)
	  FROM issue_label_snapshots s JOIN issue_universe u ON u.number=s.issue_number
	  UNION ALL
	  SELECT 'closure_proofs', COUNT(*), COALESCE(SUM(CASE WHEN p.checked_at IS NULL THEN 1 ELSE 0 END), 0), MAX(p.checked_at)
	  FROM issue_closure_proofs p
	  JOIN target ON target.tag=p.release_tag
	  UNION ALL
	  SELECT 'closure_events', COUNT(*), COALESCE(SUM(CASE WHEN e.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(e.fetched_at)
	  FROM issue_closure_events e JOIN closed_universe u ON u.number=e.issue_number
	  UNION ALL
	  SELECT 'reopen_events', COUNT(*), COALESCE(SUM(CASE WHEN r.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(r.fetched_at)
	  FROM issue_reopen_events r JOIN issue_universe u ON u.number=r.issue_number
	  UNION ALL
	  SELECT 'issue_pr_links', COUNT(*), COALESCE(SUM(CASE WHEN l.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(l.fetched_at)
	  FROM issue_pr_links l JOIN closed_universe u ON u.number=l.issue_number
	  UNION ALL
	  SELECT 'issue_commit_references', COUNT(*), COALESCE(SUM(CASE WHEN c.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(c.fetched_at)
	  FROM issue_commit_references c JOIN closed_universe u ON u.number=c.issue_number
	  UNION ALL
	  SELECT 'pull_request_fixes', COUNT(*), COALESCE(SUM(CASE WHEN p.fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(p.fetched_at)
	  FROM pull_request_fixes p
	  JOIN pr_universe u ON u.pr_repository_name_with_owner=p.pr_repository_name_with_owner AND u.pr_number=p.pr_number
	  UNION ALL
	  SELECT 'release_pr_reachability', COUNT(*), COALESCE(SUM(CASE WHEN r.checked_at IS NULL THEN 1 ELSE 0 END), 0), MAX(r.checked_at)
	  FROM release_pr_reachability r
	  JOIN pr_universe u ON u.pr_repository_name_with_owner=r.pr_repository_name_with_owner AND u.pr_number=r.pr_number
	  WHERE r.tag=?
	)
	SELECT source, count, null_count, max_ts
	FROM sources
	ORDER BY source
	`);

const latestScoredStableReleaseTagStmt = db.prepare(`
SELECT tag
FROM releases r
WHERE r.prerelease=0
  AND (
    r.final_score IS NOT NULL
    OR EXISTS (
      SELECT 1
      FROM release_score_audits a
      WHERE a.release_tag=r.tag
    )
  )
ORDER BY published_at DESC
LIMIT 1
`);

export function latestScoredStableReleaseTag(): string | null {
  const row = latestScoredStableReleaseTagStmt.get() as { tag: string } | undefined;
  return row?.tag ?? null;
}

export function releaseDataFreshness(tag: string): ReleaseDataFreshness {
  const audit = getReleaseScoreAudit(tag);
  const scoredAt = audit?.scored_at ?? null;
  const rows = releaseDataFreshnessStmt.all(tag, tag, tag) as Array<{ source: string; count: number; null_count: number; max_ts: string | null }>;
  const sources = rows.map((row) => ({
    source: row.source,
    count: Number(row.count ?? 0),
    nullCount: Number(row.null_count ?? 0),
    maxAt: row.max_ts ?? null,
    ageHoursAtScore: ageHoursAtScore(row.max_ts ?? null, scoredAt),
  }));
  const sourceFetchedAtMax = maxTimestamp(sources.map((source) => source.maxAt));
  const issueUpdatedAtMax = sources.find((source) => source.source === 'issue_rows')?.maxAt ?? null;
  const closureProofCheckedAtMax = sources.find((source) => source.source === 'closure_proofs')?.maxAt ?? null;
  return {
    schemaVersion: 1,
    tag,
    scoredAt,
    issueUpdatedAtMax,
    issueUpdatedAgeHoursAtScore: ageHoursAtScore(issueUpdatedAtMax, scoredAt),
    closureProofCheckedAtMax,
    sourceFetchedAtMax,
    sourceFetchedAgeHoursAtScore: ageHoursAtScore(sourceFetchedAtMax, scoredAt),
    sources,
  };
}

const dataFreshnessCacheRowsStmt = db.prepare(`
SELECT 'issues' AS source, COUNT(*) AS count, COALESCE(SUM(CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END), 0) AS null_count, MAX(updated_at) AS max_ts FROM issues
${hasIssueFetchFreshnessColumn ? `UNION ALL SELECT 'issue_fetches', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issues` : ''}
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
${hasReleaseRowFreshnessColumns ? `UNION ALL
SELECT 'release_rows', COUNT(*) AS count, COALESCE(SUM(CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END), 0) AS null_count, MAX(updated_at) AS max_ts
FROM (
  SELECT release_metadata_fetched_at AS updated_at FROM releases
  UNION ALL SELECT release_derived_fetched_at FROM releases
  UNION ALL SELECT release_artifact_checked_at FROM releases
)` : ''}
UNION ALL SELECT 'release_commits', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM release_commits
UNION ALL SELECT 'advisories', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM advisories
`);

export function dataFreshnessCacheDigest(): { count: number; max_ts: string | null; digest: string } {
  const rows = dataFreshnessCacheRowsStmt.all() as Array<{ source: string; count: number; max_ts: string | null }>;
  const hash = createHash('sha256');
  let count = 0;
  let maxTs: string | null = null;
  for (const row of rows) {
    count += Number(row.count ?? 0);
    if (row.max_ts && (!maxTs || row.max_ts > maxTs)) maxTs = row.max_ts;
    hash.update(JSON.stringify(row));
    hash.update('\n');
  }
  return { count, max_ts: maxTs, digest: hash.digest('hex') };
}

function ageHoursAtScore(sourceAt: string | null, scoredAt: string | null): number | null {
  if (!sourceAt || !scoredAt) return null;
  const sourceMs = Date.parse(sourceAt);
  const scoredMs = Date.parse(scoredAt);
  if (!Number.isFinite(sourceMs) || !Number.isFinite(scoredMs)) return null;
  return Math.round(((scoredMs - sourceMs) / 3_600_000) * 100) / 100;
}

function maxTimestamp(values: Array<string | null>): string | null {
  return values
    .filter((value): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

const updateReleaseScoreAuditGateEvidenceStmt = db.prepare(`
UPDATE release_score_audits
SET gate_evidence_json=?
WHERE release_tag=?
`);

export function updateReleaseScoreAuditGateEvidence(tag: string, gateEvidenceJson: string): void {
  updateReleaseScoreAuditGateEvidenceStmt.run(gateEvidenceJson, tag);
}

export interface ReleaseCommitInput {
  tag: string;
  tag_commit_oid: string | null;
  committed_at: string | null;
  check_state?: string | null;
  check_total?: number;
  check_success?: number;
  check_failure?: number;
  check_pending?: number;
  check_skipped?: number;
  check_contexts_json?: string;
}

const upsertReleaseCommitStmt = db.prepare(`
INSERT INTO release_commits (
  tag, tag_commit_oid, committed_at, check_state, check_total, check_success,
  check_failure, check_pending, check_skipped, check_contexts_json, fetched_at
)
VALUES (
  :tag, :tag_commit_oid, :committed_at, :check_state, :check_total, :check_success,
  :check_failure, :check_pending, :check_skipped, :check_contexts_json, :fetched_at
)
ON CONFLICT(tag) DO UPDATE SET
  tag_commit_oid=excluded.tag_commit_oid,
  committed_at=excluded.committed_at,
  check_state=excluded.check_state,
  check_total=excluded.check_total,
  check_success=excluded.check_success,
  check_failure=excluded.check_failure,
  check_pending=excluded.check_pending,
  check_skipped=excluded.check_skipped,
  check_contexts_json=excluded.check_contexts_json,
  fetched_at=excluded.fetched_at
`);

export function upsertReleaseCommit(input: ReleaseCommitInput): void {
  upsertReleaseCommitStmt.run({
    ...input,
    check_state: input.check_state ?? null,
    check_total: input.check_total ?? 0,
    check_success: input.check_success ?? 0,
    check_failure: input.check_failure ?? 0,
    check_pending: input.check_pending ?? 0,
    check_skipped: input.check_skipped ?? 0,
    check_contexts_json: input.check_contexts_json ?? '[]',
    fetched_at: new Date().toISOString(),
  });
}

export interface ReleaseCommitRow {
  tag: string;
  tag_commit_oid: string | null;
  committed_at: string | null;
  check_state: string | null;
  check_total: number;
  check_success: number;
  check_failure: number;
  check_pending: number;
  check_skipped: number;
  check_contexts_json: string;
  fetched_at: string;
}

const getReleaseCommitStmt = db.prepare(`SELECT * FROM release_commits WHERE tag=?`);
export function getReleaseCommit(tag: string): ReleaseCommitRow | undefined {
  return getReleaseCommitStmt.get(tag) as ReleaseCommitRow | undefined;
}

export interface IssueClosureEventInput {
  issue_number: number;
  event_id: string;
  closed_at: string | null;
  actor_login: string | null;
  state_reason: string | null;
  closer_type: string | null;
  closer_number: number | null;
  closer_oid: string | null;
  raw_json: string;
}

export interface IssueLabelEventInput {
  issue_number: number;
  event_id: string;
  action: string;
  label_name: string;
  actor_login: string | null;
  created_at: string;
}

const upsertIssueLabelEventStmt = db.prepare(`
INSERT INTO issue_label_events (
  issue_number, event_id, action, label_name, actor_login, created_at, fetched_at
)
VALUES (
  :issue_number, :event_id, :action, :label_name, :actor_login, :created_at, :fetched_at
)
ON CONFLICT(event_id) DO UPDATE SET
  issue_number=excluded.issue_number,
  action=excluded.action,
  label_name=excluded.label_name,
  actor_login=excluded.actor_login,
  created_at=excluded.created_at,
  fetched_at=excluded.fetched_at
`);

export function upsertIssueLabelEvent(input: IssueLabelEventInput): void {
  upsertIssueLabelEventStmt.run({ ...input, fetched_at: new Date().toISOString() });
}

export interface IssueLabelSnapshotInput {
  issue_number: number;
  snapshot_at: string;
  labels_json: string;
}

const upsertIssueLabelSnapshotStmt = db.prepare(`
INSERT INTO issue_label_snapshots (
  issue_number, snapshot_at, labels_json, fetched_at
)
VALUES (
  :issue_number, :snapshot_at, :labels_json, :fetched_at
)
ON CONFLICT(issue_number, snapshot_at) DO UPDATE SET
  labels_json=excluded.labels_json,
  fetched_at=excluded.fetched_at
`);

export function upsertIssueLabelSnapshot(input: IssueLabelSnapshotInput): void {
  upsertIssueLabelSnapshotStmt.run({ ...input, fetched_at: new Date().toISOString() });
}

const issueLabelEventsUntilStmt = db.prepare(`
SELECT action, label_name
FROM issue_label_events
WHERE issue_number=?
  AND (? IS NULL OR created_at <= ?)
ORDER BY created_at ASC, event_id ASC
`);

const issueLabelEventCountStmt = db.prepare(`SELECT COUNT(*) AS count FROM issue_label_events WHERE issue_number=?`);
const issueLabelSnapshotAtStmt = db.prepare(`
SELECT labels_json
FROM issue_label_snapshots
WHERE issue_number=?
  AND snapshot_at <= ?
ORDER BY snapshot_at DESC
LIMIT 1
`);
const issueLabelSnapshotCountAtStmt = db.prepare(`
SELECT COUNT(*) AS count
FROM issue_label_snapshots
WHERE issue_number=?
  AND snapshot_at <= ?
`);

export function issueLabelEventCount(issueNumber: number): number {
  return Number((issueLabelEventCountStmt.get(issueNumber) as { count: number }).count ?? 0);
}

export function issueLabelSnapshotCountAt(issueNumber: number, cutoff: string | null): number {
  if (!cutoff) return 0;
  return Number((issueLabelSnapshotCountAtStmt.get(issueNumber, cutoff) as { count: number }).count ?? 0);
}

export function labelSnapshotForIssueAt(issueNumber: number, cutoff: string | null): string[] | null {
  if (!cutoff) return null;
  const row = issueLabelSnapshotAtStmt.get(issueNumber, cutoff) as { labels_json: string } | undefined;
  if (!row?.labels_json) return null;
  try {
    const labels = JSON.parse(row.labels_json);
    return Array.isArray(labels) ? labels.filter((label): label is string => typeof label === 'string') : null;
  } catch {
    return null;
  }
}

export function labelsForIssueAt(
  issueNumber: number,
  fallbackLabels: string[],
  cutoff: string | null,
  options: { useFallbackWhenNoEvents?: boolean; useSnapshotWhenNoEvents?: boolean } = {},
): string[] {
  const eventCount = issueLabelEventCount(issueNumber);
  if (eventCount === 0) {
    if (options.useSnapshotWhenNoEvents && cutoff) {
      const snapshot = labelSnapshotForIssueAt(issueNumber, cutoff);
      if (snapshot) return snapshot;
    }
    return options.useFallbackWhenNoEvents === false ? [] : fallbackLabels;
  }
  const labels = new Set<string>();
  const rows = issueLabelEventsUntilStmt.all(issueNumber, cutoff, cutoff) as Array<{ action: string; label_name: string }>;
  for (const row of rows) {
    if (row.action === 'labeled') labels.add(row.label_name);
    else if (row.action === 'unlabeled') labels.delete(row.label_name);
  }
  return [...labels];
}

export interface IssueClosureProofInput {
  release_tag: string;
  issue_number: number;
  status: string;
  summary: string;
  evidence_json: string;
}

const upsertIssueClosureProofStmt = db.prepare(`
INSERT INTO issue_closure_proofs (
  release_tag, issue_number, status, summary, evidence_json, checked_at
)
VALUES (
  :release_tag, :issue_number, :status, :summary, :evidence_json, :checked_at
)
ON CONFLICT(release_tag, issue_number) DO UPDATE SET
  status=excluded.status,
  summary=excluded.summary,
  evidence_json=excluded.evidence_json,
  checked_at=excluded.checked_at
`);

export function upsertIssueClosureProof(input: IssueClosureProofInput): void {
  upsertIssueClosureProofStmt.run({ ...input, checked_at: new Date().toISOString() });
}

const deleteIssueClosureProofsForReleaseStmt = db.prepare(`DELETE FROM issue_closure_proofs WHERE release_tag=?`);
export function deleteIssueClosureProofsForRelease(releaseTag: string): void {
  deleteIssueClosureProofsForReleaseStmt.run(releaseTag);
}

export interface IssueClosureProofRow extends IssueClosureProofInput {
  checked_at: string;
}

export interface ClosureProofJoinedRow extends IssueClosureProofRow {
  title: string;
  html_url: string | null;
  closed_at: string | null;
  labels: string;
  sentiment: string | null;
  severity: string | null;
  scope: string | null;
  functionality: string | null;
  affected_users: string | null;
  has_workaround: number | null;
  workaround_status: string | null;
  duplicate_cluster: string | null;
  affects_version: string | null;
  confidence: number | null;
  rationale: string | null;
}

const closureProofSummaryStmt = db.prepare(`
SELECT status, COUNT(*) AS count
FROM issue_closure_proofs
WHERE release_tag=?
GROUP BY status
ORDER BY count DESC
`);

export function closureProofSummary(releaseTag: string): Array<{ status: string; count: number }> {
  return closureProofSummaryStmt.all(releaseTag) as Array<{ status: string; count: number }>;
}

const closureProofRiskRowsStmt = db.prepare(`
SELECT p.status,
       p.issue_number,
       i.title,
       i.labels,
       c.sentiment,
       c.severity,
       c.scope,
       c.functionality,
       c.affected_users,
       c.has_workaround,
       c.workaround_status,
       c.duplicate_cluster,
       c.affects_version,
       c.confidence,
       c.rationale,
       COUNT(*) AS count
FROM issue_closure_proofs p
JOIN issues i ON i.number=p.issue_number
LEFT JOIN classifications c ON c.issue_number=p.issue_number
WHERE p.release_tag=?
GROUP BY p.status, p.issue_number, i.title, i.labels,
         c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
         c.has_workaround, c.workaround_status, c.duplicate_cluster,
         c.affects_version, c.confidence, c.rationale
ORDER BY count DESC
`);

export interface ClosureProofRiskRow {
  status: string;
  issue_number: number;
  title: string;
  labels: string;
  sentiment: string | null;
  severity: string | null;
  scope: string | null;
  functionality: string | null;
  affected_users: string | null;
  has_workaround: number | null;
  workaround_status: string | null;
  duplicate_cluster: string | null;
  affects_version: string | null;
  confidence: number | null;
  rationale: string | null;
  count: number;
}

export function closureProofRiskRows(releaseTag: string): ClosureProofRiskRow[] {
  return closureProofRiskRowsStmt.all(releaseTag) as unknown as ClosureProofRiskRow[];
}

const closureProofExamplesStmt = db.prepare(`
SELECT p.*, i.title, i.html_url, i.closed_at, i.labels,
       c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
       c.confidence, c.rationale
FROM issue_closure_proofs p
JOIN issues i ON i.number=p.issue_number
LEFT JOIN classifications c ON c.issue_number=p.issue_number
WHERE p.release_tag=?
ORDER BY
  CASE p.status
    WHEN 'duplicate_to_open_canonical' THEN 0
    WHEN 'duplicate_with_release_fix_proof' THEN 1
    WHEN 'fixed_after_release' THEN 2
    WHEN 'already_present_claim' THEN 3
    WHEN 'duplicate_to_closed_canonical' THEN 4
    WHEN 'canonical_cycle_or_self_reference' THEN 5
    WHEN 'duplicate_or_superseded' THEN 6
    WHEN 'repro_requested' THEN 7
    WHEN 'reporter_replaced' THEN 8
    WHEN 'reporter_withdrawn' THEN 9
    WHEN 'reporter_self_closed' THEN 10
    WHEN 'no_code_proof' THEN 11
    ELSE 12
  END,
  i.closed_at DESC
LIMIT ?
`);

export function closureProofExamples(releaseTag: string, limit = 25): ClosureProofJoinedRow[] {
  return closureProofExamplesStmt.all(releaseTag, limit) as unknown as ClosureProofJoinedRow[];
}

const closureProofRowsStmt = db.prepare(`
SELECT p.*, i.title, i.html_url, i.closed_at, i.labels,
       c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
       c.confidence, c.rationale
FROM issue_closure_proofs p
JOIN issues i ON i.number=p.issue_number
LEFT JOIN classifications c ON c.issue_number=p.issue_number
WHERE p.release_tag=?
`);

export function closureProofRows(releaseTag: string): ClosureProofJoinedRow[] {
  return closureProofRowsStmt.all(releaseTag) as unknown as ClosureProofJoinedRow[];
}

const upsertIssueClosureEventStmt = db.prepare(`
INSERT INTO issue_closure_events (
  issue_number, event_id, closed_at, actor_login, state_reason,
  closer_type, closer_number, closer_oid, raw_json, fetched_at
)
VALUES (
  :issue_number, :event_id, :closed_at, :actor_login, :state_reason,
  :closer_type, :closer_number, :closer_oid, :raw_json, :fetched_at
)
ON CONFLICT(event_id) DO UPDATE SET
  issue_number=excluded.issue_number,
  closed_at=excluded.closed_at,
  actor_login=excluded.actor_login,
  state_reason=excluded.state_reason,
  closer_type=excluded.closer_type,
  closer_number=excluded.closer_number,
  closer_oid=excluded.closer_oid,
  raw_json=excluded.raw_json,
  fetched_at=excluded.fetched_at
`);

export function upsertIssueClosureEvent(input: IssueClosureEventInput): void {
  upsertIssueClosureEventStmt.run({ ...input, fetched_at: new Date().toISOString() });
}

export interface IssueReopenEventInput {
  issue_number: number;
  event_id: string;
  reopened_at: string | null;
  actor_login: string | null;
  raw_json: string;
}

const upsertIssueReopenEventStmt = db.prepare(`
INSERT INTO issue_reopen_events (
  issue_number, event_id, reopened_at, actor_login, raw_json, fetched_at
)
VALUES (
  :issue_number, :event_id, :reopened_at, :actor_login, :raw_json, :fetched_at
)
ON CONFLICT(event_id) DO UPDATE SET
  issue_number=excluded.issue_number,
  reopened_at=excluded.reopened_at,
  actor_login=excluded.actor_login,
  raw_json=excluded.raw_json,
  fetched_at=excluded.fetched_at
`);

export function upsertIssueReopenEvent(input: IssueReopenEventInput): void {
  upsertIssueReopenEventStmt.run({ ...input, fetched_at: new Date().toISOString() });
}

export interface IssuePrLinkInput {
  issue_number: number;
  pr_repository_owner?: string | null;
  pr_repository_name?: string | null;
  pr_repository_name_with_owner?: string | null;
  pr_number: number;
  source: string;
  will_close_target: number | null;
  referenced_at: string | null;
}

const upsertIssuePrLinkStmt = db.prepare(`
INSERT INTO issue_pr_links (
  issue_number, pr_repository_owner, pr_repository_name, pr_repository_name_with_owner,
  pr_number, source, will_close_target, referenced_at, fetched_at
)
VALUES (
  :issue_number, :pr_repository_owner, :pr_repository_name, :pr_repository_name_with_owner,
  :pr_number, :source, :will_close_target, :referenced_at, :fetched_at
)
ON CONFLICT(issue_number, pr_repository_name_with_owner, pr_number, source) DO UPDATE SET
  pr_repository_owner=excluded.pr_repository_owner,
  pr_repository_name=excluded.pr_repository_name,
  will_close_target=excluded.will_close_target,
  referenced_at=excluded.referenced_at,
  fetched_at=excluded.fetched_at
`);

export function upsertIssuePrLink(input: IssuePrLinkInput): void {
  upsertIssuePrLinkStmt.run({
    ...input,
    ...normalizePrRepository(input),
    fetched_at: new Date().toISOString(),
  });
}

const deleteIssuePrLinksForIssuesStmt = db.prepare(`
DELETE FROM issue_pr_links
WHERE issue_number IN (SELECT value FROM json_each(?))
`);

export function deleteIssuePrLinksForIssues(issueNumbers: number[]): void {
  if (!issueNumbers.length) return;
  deleteIssuePrLinksForIssuesStmt.run(JSON.stringify(issueNumbers));
}

const deleteCommentIssuePrLinksForIssuesStmt = db.prepare(`
DELETE FROM issue_pr_links
WHERE issue_number IN (SELECT value FROM json_each(?))
  AND source IN ('ClosureComment.fixProof', 'ClosureComment.prMention')
`);

export function deleteCommentIssuePrLinksForIssues(issueNumbers: number[]): void {
  if (!issueNumbers.length) return;
  deleteCommentIssuePrLinksForIssuesStmt.run(JSON.stringify(issueNumbers));
}

export interface IssueCommitReferenceInput {
  issue_number: number;
  event_id: string;
  commit_oid: string;
  commit_message_headline: string | null;
  commit_repository_owner: string | null;
  commit_repository_name: string | null;
  commit_repository_name_with_owner: string | null;
  is_cross_repository: number;
  is_direct_reference: number;
  referenced_at: string | null;
  actor_login: string | null;
  raw_json: string;
}

const upsertIssueCommitReferenceStmt = db.prepare(`
INSERT INTO issue_commit_references (
  issue_number, event_id, commit_oid, commit_message_headline, commit_repository_owner, commit_repository_name,
  commit_repository_name_with_owner, is_cross_repository, is_direct_reference,
  referenced_at, actor_login, raw_json, fetched_at
)
VALUES (
  :issue_number, :event_id, :commit_oid, :commit_message_headline, :commit_repository_owner, :commit_repository_name,
  :commit_repository_name_with_owner, :is_cross_repository, :is_direct_reference,
  :referenced_at, :actor_login, :raw_json, :fetched_at
)
ON CONFLICT(event_id) DO UPDATE SET
  issue_number=excluded.issue_number,
  commit_oid=excluded.commit_oid,
  commit_message_headline=excluded.commit_message_headline,
  commit_repository_owner=excluded.commit_repository_owner,
  commit_repository_name=excluded.commit_repository_name,
  commit_repository_name_with_owner=excluded.commit_repository_name_with_owner,
  is_cross_repository=excluded.is_cross_repository,
  is_direct_reference=excluded.is_direct_reference,
  referenced_at=excluded.referenced_at,
  actor_login=excluded.actor_login,
  raw_json=excluded.raw_json,
  fetched_at=excluded.fetched_at
`);

export function upsertIssueCommitReference(input: IssueCommitReferenceInput): void {
  upsertIssueCommitReferenceStmt.run({ ...input, fetched_at: new Date().toISOString() });
}

export interface PullRequestFixInput {
  pr_repository_owner?: string | null;
  pr_repository_name?: string | null;
  pr_repository_name_with_owner?: string | null;
  pr_number: number;
  title: string | null;
  url: string | null;
  state: string | null;
  merged: number;
  merged_at: string | null;
  merge_commit_oid: string | null;
  base_ref_name: string | null;
}

const upsertPullRequestFixStmt = db.prepare(`
INSERT INTO pull_request_fixes (
  pr_repository_owner, pr_repository_name, pr_repository_name_with_owner,
  pr_number, title, url, state, merged, merged_at, merge_commit_oid, base_ref_name, fetched_at
)
VALUES (
  :pr_repository_owner, :pr_repository_name, :pr_repository_name_with_owner,
  :pr_number, :title, :url, :state, :merged, :merged_at, :merge_commit_oid, :base_ref_name, :fetched_at
)
ON CONFLICT(pr_repository_name_with_owner, pr_number) DO UPDATE SET
  pr_repository_owner=excluded.pr_repository_owner,
  pr_repository_name=excluded.pr_repository_name,
  title=excluded.title,
  url=excluded.url,
  state=excluded.state,
  merged=excluded.merged,
  merged_at=excluded.merged_at,
  merge_commit_oid=excluded.merge_commit_oid,
  base_ref_name=excluded.base_ref_name,
  fetched_at=excluded.fetched_at
`);

export function upsertPullRequestFix(input: PullRequestFixInput): void {
  upsertPullRequestFixStmt.run({
    ...input,
    ...normalizePrRepository(input),
    fetched_at: new Date().toISOString(),
  });
}

export interface ReleasePrReachabilityInput {
  tag: string;
  pr_repository_owner?: string | null;
  pr_repository_name?: string | null;
  pr_repository_name_with_owner?: string | null;
  pr_number: number;
  tag_commit_oid: string | null;
  merge_commit_oid: string | null;
  base_ref_name: string | null;
  status: 'reachable' | 'not_reachable' | 'unknown';
  method?: string;
  evidence_json: string;
}

const reachabilityStatuses = new Set(['reachable', 'not_reachable', 'unknown']);
const reachabilityEvidenceReasons = new Set([
  'merge_commit_in_release_history',
  'fix_commit_in_release_history',
  'not_reachable_from_release_tag',
  'release_commit_unavailable',
  'release_commit_fetch_failed',
  'merge_commit_oid_unavailable',
  'commit_fetch_failed',
  'commit_unavailable',
  'merge_base_error',
]);
const fullCommitOidRe = /^[0-9a-f]{40}$/;

const upsertReleasePrReachabilityStmt = db.prepare(`
INSERT INTO release_pr_reachability (
  tag, pr_repository_owner, pr_repository_name, pr_repository_name_with_owner,
  pr_number, tag_commit_oid, merge_commit_oid, base_ref_name, status, method, evidence_json, checked_at
)
VALUES (
  :tag, :pr_repository_owner, :pr_repository_name, :pr_repository_name_with_owner,
  :pr_number, :tag_commit_oid, :merge_commit_oid, :base_ref_name, :status, :method, :evidence_json, :checked_at
)
ON CONFLICT(tag, pr_repository_name_with_owner, pr_number) DO UPDATE SET
  pr_repository_owner=excluded.pr_repository_owner,
  pr_repository_name=excluded.pr_repository_name,
  tag_commit_oid=excluded.tag_commit_oid,
  merge_commit_oid=excluded.merge_commit_oid,
  base_ref_name=excluded.base_ref_name,
  status=excluded.status,
  method=excluded.method,
  evidence_json=excluded.evidence_json,
  checked_at=excluded.checked_at
`);

export function upsertReleasePrReachability(input: ReleasePrReachabilityInput): void {
  upsertReleasePrReachabilityStmt.run({
    ...input,
    ...normalizePrRepository(input),
    method: input.method ?? 'git-merge-base',
    checked_at: new Date().toISOString(),
  });
}

const deleteReleasePrReachabilityForReleaseStmt = db.prepare(`DELETE FROM release_pr_reachability WHERE tag=?`);
export function deleteReleasePrReachabilityForRelease(tag: string): void {
  deleteReleasePrReachabilityForReleaseStmt.run(tag);
}

export function replaceReleasePrReachabilityForRelease(tag: string, rows: ReleasePrReachabilityInput[]): void {
  const prepared = rows.map((row) => validateReleasePrReachabilityInput(tag, row));
  runInWriteTransaction(() => {
    deleteReleasePrReachabilityForReleaseStmt.run(tag);
    for (const row of prepared) {
      upsertReleasePrReachabilityStmt.run({
        ...row,
        method: row.method ?? 'git-merge-base',
        checked_at: new Date().toISOString(),
      });
    }
  });
}

function validateReleasePrReachabilityInput(tag: string, input: ReleasePrReachabilityInput): ReleasePrReachabilityInput {
  if (input.tag !== tag) {
    throw new Error(`Reachability row tag ${JSON.stringify(input.tag)} does not match replacement tag ${JSON.stringify(tag)}`);
  }
  if (!reachabilityStatuses.has(input.status)) {
    throw new Error(`Reachability row for ${tag} PR #${input.pr_number} has invalid status ${JSON.stringify(input.status)}`);
  }
  const normalized = normalizePrRepository(input);
  if (!normalized.pr_repository_name_with_owner.includes('/')) {
    throw new Error(`Reachability row for ${tag} PR #${input.pr_number} has invalid repository identity`);
  }
  if (!Number.isInteger(input.pr_number) || input.pr_number <= 0) {
    throw new Error(`Reachability row for ${tag} has invalid PR number ${JSON.stringify(input.pr_number)}`);
  }
  const evidence = parseJsonObject(input.evidence_json);
  if (evidence.schemaVersion !== 1 || typeof evidence.evidence !== 'string' || !reachabilityEvidenceReasons.has(evidence.evidence)) {
    throw new Error(`Reachability row for ${tag} PR #${input.pr_number} has invalid evidence JSON`);
  }
  if ((input.status === 'reachable' || input.status === 'not_reachable') &&
    (!input.tag_commit_oid || !fullCommitOidRe.test(input.tag_commit_oid) ||
      !input.merge_commit_oid || !fullCommitOidRe.test(input.merge_commit_oid))) {
    throw new Error(`Reachability row for ${tag} PR #${input.pr_number} is ${input.status} without full tag and merge commit OIDs`);
  }
  return {
    ...input,
    ...normalized,
    method: input.method ?? 'git-merge-base',
  };
}

function parseJsonObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  } catch {
    // handled below
  }
  throw new Error('Expected JSON object');
}

export interface ReleasePrReachabilityRow {
  tag: string;
  pr_repository_owner: string;
  pr_repository_name: string;
  pr_repository_name_with_owner: string;
  pr_number: number;
  tag_commit_oid: string | null;
  merge_commit_oid: string | null;
  base_ref_name: string | null;
  status: 'reachable' | 'not_reachable' | 'unknown';
  method: string;
  evidence_json: string;
  checked_at: string;
  title: string | null;
  url: string | null;
  state: string | null;
  merged: number | null;
  merged_at: string | null;
  pr_merge_commit_oid: string | null;
  pr_base_ref_name: string | null;
}

const releasePrReachabilityRowsStmt = db.prepare(`
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
ORDER BY
  CASE r.status
    WHEN 'not_reachable' THEN 0
    WHEN 'unknown' THEN 1
    WHEN 'reachable' THEN 2
    ELSE 3
  END,
  r.pr_repository_name_with_owner,
  r.pr_number
`);

export function releasePrReachabilityRows(tag: string): ReleasePrReachabilityRow[] {
  return releasePrReachabilityRowsStmt.all(tag) as unknown as ReleasePrReachabilityRow[];
}

export interface IngestionEvidenceFailureInput {
  run_id: string;
  occurred_at?: string | null;
  source: string;
  scope?: string | null;
  release_tag?: string | null;
  issue_number?: number | null;
  pr_repository_name_with_owner?: string | null;
  pr_number?: number | null;
  message: string;
  context_json?: string | null;
  scoring_blocking?: number | boolean | null;
}

export interface IngestionEvidenceFailureRow {
  id: number;
  run_id: string;
  occurred_at: string;
  source: string;
  scope: string | null;
  release_tag: string | null;
  issue_number: number | null;
  pr_repository_name_with_owner: string | null;
  pr_number: number | null;
  message: string;
  context_json: string | null;
  scoring_blocking: number;
}

const hasIngestionEvidenceFailuresTable = tableHasColumns('ingestion_evidence_failures', [
  'id',
  'run_id',
  'occurred_at',
  'source',
  'message',
  'scoring_blocking',
]);

const insertIngestionEvidenceFailureStmt = hasIngestionEvidenceFailuresTable ? db.prepare(`
INSERT INTO ingestion_evidence_failures (
  run_id, occurred_at, source, scope, release_tag, issue_number,
  pr_repository_name_with_owner, pr_number, message, context_json, scoring_blocking
)
VALUES (
  :run_id, :occurred_at, :source, :scope, :release_tag, :issue_number,
  :pr_repository_name_with_owner, :pr_number, :message, :context_json, :scoring_blocking
)
`) : null;

export function insertIngestionEvidenceFailure(input: IngestionEvidenceFailureInput): void {
  if (!insertIngestionEvidenceFailureStmt) return;
  insertIngestionEvidenceFailureStmt.run({
    run_id: input.run_id,
    occurred_at: input.occurred_at ?? new Date().toISOString(),
    source: input.source,
    scope: input.scope ?? null,
    release_tag: input.release_tag ?? null,
    issue_number: Number.isInteger(input.issue_number) ? input.issue_number : null,
    pr_repository_name_with_owner: input.pr_repository_name_with_owner ?? null,
    pr_number: Number.isInteger(input.pr_number) ? input.pr_number : null,
    message: input.message,
    context_json: input.context_json ?? null,
    scoring_blocking: input.scoring_blocking === false || input.scoring_blocking === 0 ? 0 : 1,
  } as any);
}

const listRecentIngestionEvidenceFailuresStmt = hasIngestionEvidenceFailuresTable ? db.prepare(`
SELECT *
FROM ingestion_evidence_failures
ORDER BY occurred_at DESC, id DESC
LIMIT ?
`) : null;

export function listRecentIngestionEvidenceFailures(limit = 25): IngestionEvidenceFailureRow[] {
  if (!listRecentIngestionEvidenceFailuresStmt) return [];
  return listRecentIngestionEvidenceFailuresStmt.all(Math.max(1, Math.floor(limit))) as unknown as IngestionEvidenceFailureRow[];
}

const ingestionEvidenceFailuresAfterStmt = hasIngestionEvidenceFailuresTable ? db.prepare(`
SELECT *
FROM ingestion_evidence_failures
WHERE scoring_blocking = 1
  AND occurred_at > ?
ORDER BY occurred_at DESC, id DESC
LIMIT ?
`) : null;

export function ingestionEvidenceFailuresAfter(timestamp: string, limit = 25): IngestionEvidenceFailureRow[] {
  if (!ingestionEvidenceFailuresAfterStmt) return [];
  return ingestionEvidenceFailuresAfterStmt.all(timestamp, Math.max(1, Math.floor(limit))) as unknown as IngestionEvidenceFailureRow[];
}

const ingestionEvidenceFailureSourceCountsAfterStmt = hasIngestionEvidenceFailuresTable ? db.prepare(`
SELECT source, COUNT(*) AS count, MAX(occurred_at) AS maxAt
FROM ingestion_evidence_failures
WHERE scoring_blocking = 1
  AND occurred_at > ?
GROUP BY source
ORDER BY count DESC, source
`) : null;

export function ingestionEvidenceFailureSourceCountsAfter(timestamp: string): Array<{ source: string; count: number; maxAt: string | null }> {
  if (!ingestionEvidenceFailureSourceCountsAfterStmt) return [];
  return ingestionEvidenceFailureSourceCountsAfterStmt.all(timestamp).map((row: any) => ({
    source: String(row.source),
    count: Number(row.count ?? 0),
    maxAt: row.maxAt ?? null,
  }));
}

// Stable-only view. Prereleases live in the DB for derived-stat computation
// (beta_count, hours_to_next_release) but are not surfaced to scoring or the
// API — the UI is "should I install this stable release?", betas don't get
// installed individually by end users.
const listReleasesStmt = db.prepare(`
SELECT * FROM releases WHERE prerelease = 0 ORDER BY published_at IS NULL, published_at DESC LIMIT ?
`);

export function listReleasesDb(limit = 20): ReleaseRow[] {
  return listReleasesStmt.all(limit) as unknown as ReleaseRow[];
}

const getReleaseStmt = db.prepare(`SELECT * FROM releases WHERE tag=?`);
export function getRelease(tag: string): ReleaseRow | undefined {
  return getReleaseStmt.get(tag) as ReleaseRow | undefined;
}

const lastScoredAtStmt = db.prepare(`SELECT MAX(scored_at) AS ts FROM releases`);
export function getLastScoredAt(): string | null {
  const row = lastScoredAtStmt.get() as { ts: string | null };
  return row?.ts ?? null;
}

// ---------- issues ----------
export interface IssueRow {
  number: number;
  state: string;
  title: string;
  author: string | null;
  author_association?: string | null;
  html_url: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  comments: number;
  unique_human_commenters?: number;
  maintainer_commenters?: number;
  contributor_commenters?: number;
  commenter_scan_truncated?: number;
  reaction_total?: number;
  positive_reactions?: number;
  labels: string;
  is_bot: number; // 0/1; computed at write time via detectBot()
  fetched_at?: string | null;
}

const upsertIssueStmt = db.prepare(`
INSERT INTO issues (
  number, state, title, author, author_association, html_url, created_at, updated_at, closed_at,
  comments, unique_human_commenters, maintainer_commenters, contributor_commenters, commenter_scan_truncated,
  reaction_total, positive_reactions, labels, is_bot, fetched_at
)
VALUES (
  :number, :state, :title, :author, :author_association, :html_url, :created_at, :updated_at, :closed_at,
  :comments, :unique_human_commenters, :maintainer_commenters, :contributor_commenters, :commenter_scan_truncated,
  :reaction_total, :positive_reactions, :labels, :is_bot, :fetched_at
)
ON CONFLICT(number) DO UPDATE SET
  state=excluded.state,
  title=excluded.title,
  author=excluded.author,
  author_association=excluded.author_association,
  html_url=excluded.html_url,
  created_at=excluded.created_at,
  updated_at=excluded.updated_at,
  closed_at=excluded.closed_at,
  comments=excluded.comments,
  unique_human_commenters=excluded.unique_human_commenters,
  maintainer_commenters=excluded.maintainer_commenters,
  contributor_commenters=excluded.contributor_commenters,
  commenter_scan_truncated=excluded.commenter_scan_truncated,
  reaction_total=excluded.reaction_total,
  positive_reactions=excluded.positive_reactions,
  labels=excluded.labels,
  is_bot=excluded.is_bot,
  fetched_at=excluded.fetched_at
`);

export function upsertIssue(i: IssueRow): void {
  upsertIssueStmt.run({
    ...i,
    author_association: i.author_association ?? null,
    unique_human_commenters: i.unique_human_commenters ?? 0,
    maintainer_commenters: i.maintainer_commenters ?? 0,
    contributor_commenters: i.contributor_commenters ?? 0,
    commenter_scan_truncated: i.commenter_scan_truncated ?? 0,
    reaction_total: i.reaction_total ?? 0,
    positive_reactions: i.positive_reactions ?? 0,
    fetched_at: i.fetched_at ?? new Date().toISOString(),
  } as unknown as Record<string, string | number | null>);
}

const getIssueStmt = db.prepare(`SELECT * FROM issues WHERE number=?`);
export function getIssue(number: number): IssueRow | undefined {
  return getIssueStmt.get(number) as IssueRow | undefined;
}

// ---------- classifications ----------
// `has_workaround` is the legacy boolean — we keep writing it for back-compat with old
// rows, but new scoring code only reads `workaround_status`.
const upsertClassificationStmt = db.prepare(`
INSERT INTO classifications (issue_number, sentiment, severity, scope, functionality, affected_users,
  has_workaround, workaround_status, duplicate_cluster, affects_version, confidence, rationale,
  classified_at, classified_updated_at, prompt_version)
VALUES (:issue_number, :sentiment, :severity, :scope, :functionality, :affected_users,
  :has_workaround, :workaround_status, :duplicate_cluster, :affects_version, :confidence, :rationale,
  :classified_at, :classified_updated_at, :prompt_version)
ON CONFLICT(issue_number) DO UPDATE SET
  sentiment=excluded.sentiment,
  severity=excluded.severity,
  scope=excluded.scope,
  functionality=excluded.functionality,
  affected_users=excluded.affected_users,
  has_workaround=excluded.has_workaround,
  workaround_status=excluded.workaround_status,
  duplicate_cluster=excluded.duplicate_cluster,
  affects_version=excluded.affects_version,
  confidence=excluded.confidence,
  rationale=excluded.rationale,
  classified_at=excluded.classified_at,
  classified_updated_at=excluded.classified_updated_at,
  prompt_version=excluded.prompt_version
`);

export function upsertClassification(
  issueNumber: number,
  c: IssueClassification,
  issueUpdatedAt: string,
  promptVersion: number,
): void {
  upsertClassificationStmt.run({
    issue_number: issueNumber,
    sentiment: c.sentiment,
    severity: c.severity,
    scope: c.scope,
    functionality: c.functionality,
    affected_users: c.affectedUsers,
    has_workaround: c.workaroundStatus === 'confirmed' ? 1 : 0,
    workaround_status: c.workaroundStatus,
    duplicate_cluster: c.duplicateCluster,
    affects_version: c.affectsVersion,
    confidence: c.confidence,
    rationale: c.rationale,
    classified_at: new Date().toISOString(),
    classified_updated_at: issueUpdatedAt,
    prompt_version: promptVersion,
  });
}

export interface ClassificationRow {
  issue_number: number;
  sentiment: string;
  severity: string;
  scope: string;
  functionality: string;
  affected_users: string;
  has_workaround: number;
  workaround_status: string;
  duplicate_cluster: string | null;
  affects_version: string | null;
  confidence: number;
  rationale: string | null;
  classified_at: string;
  classified_updated_at: string;
  prompt_version: number;
}

const getClassificationStmt = db.prepare(`SELECT * FROM classifications WHERE issue_number=?`);
export function getClassification(issueNumber: number): ClassificationRow | undefined {
  return getClassificationStmt.get(issueNumber) as ClassificationRow | undefined;
}

// Joined view for scoring + UI
export interface JoinedIssue extends IssueRow, ClassificationRow {}

// Window-based attribution (carry-forward model).
//
// An issue affects release R if one of its open intervals overlaps R's reign:
//   - R reigns from R.published_at until the NEXT stable release is published
//     (or forever, if R is the latest).
//   - The initial issue-open interval starts at issue.created_at and ends at the
//     first fetched close event after creation, falling back to issue.closed_at
//     when timeline evidence is missing.
//   - Each fetched reopen event starts another open interval, ending at the next
//     fetched close event after that reopen, again falling back to issue.closed_at
//     when that is the only available close timestamp.
// At least one open interval must overlap the release reign.
//
// Why this model, not the previous LLM-mention-only approach:
//   * A bug filed during v5.4's reign and still open today AFFECTS v5.20 too —
//     it's not been fixed. The old model attributed it to v5.4 only (via the
//     LLM's explicit mention) or dropped it (no mention). Either way, v5.20
//     missed a real bug that exists in it.
//   * A bug closed before R was even published does NOT affect R — the fix
//     was already in by R's release date.
//   * A bug filed during R's reign and closed during R's reign DOES affect R
//     (someone hit it before it was fixed) — overlap captures this naturally.
//
// Properties:
//   - latest release accumulates EVERY currently-open bug from project history.
//     This is structurally correct: those bugs DO exist in latest. The release
//     will look worst-by-construction because it has the longest open-bug
//     debt. The dashboard layer (recommendation view) handles this via
//     age-normalised comparison.
//   - As bugs get closed over time, historical release scores improve —
//     stored data tells a more honest story of which past releases were
//     actually solid.
//
// LLM's `affects_version` is no longer used for attribution. It's kept in the
// row for display purposes only (UI can show "user explicitly said v5.18").
const issuesForVersionStmt = db.prepare(`
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
SELECT i.*,
       c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
       c.confidence, c.rationale, c.classified_at, c.classified_updated_at
FROM issues i
JOIN classifications c ON c.issue_number = i.number
JOIN target
WHERE
  target.start_at IS NOT NULL
  AND EXISTS (
    SELECT 1
    FROM issue_open_intervals interval
    WHERE interval.issue_number=i.number
      AND interval.open_at < target.end_at
      AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
  )
ORDER BY i.updated_at DESC
`);

export function issuesForVersion(tag: string): JoinedIssue[] {
  return issuesForVersionStmt.all(tag) as unknown as JoinedIssue[];
}

const issueCountForVersionStmt = db.prepare(`
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
SELECT COUNT(DISTINCT i.number) AS count
FROM issues i
JOIN target
WHERE
  target.start_at IS NOT NULL
  AND EXISTS (
    SELECT 1
    FROM issue_open_intervals interval
    WHERE interval.issue_number=i.number
      AND interval.open_at < target.end_at
      AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
  )
`);

export function issueCountForVersion(tag: string): number {
  return Number((issueCountForVersionStmt.get(tag) as { count: number }).count ?? 0);
}

const unclassifiedIssuesForVersionStmt = db.prepare(`
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
SELECT i.*
FROM issues i
JOIN target
LEFT JOIN classifications c ON c.issue_number=i.number
WHERE
  target.start_at IS NOT NULL
  AND c.issue_number IS NULL
  AND EXISTS (
    SELECT 1
    FROM issue_open_intervals interval
    WHERE interval.issue_number=i.number
      AND interval.open_at < target.end_at
      AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
  )
ORDER BY
  CASE i.state WHEN 'open' THEN 0 ELSE 1 END,
  i.updated_at DESC
LIMIT ?
`);

export function unclassifiedIssuesForVersion(tag: string, limit = 25): IssueRow[] {
  return unclassifiedIssuesForVersionStmt.all(tag, limit) as unknown as IssueRow[];
}

// Issues with final close timestamps during a release's reign — the "fixes
// credit" universe for that release. Earlier close events do not count after a
// reopen/reclose; only the final issue.closed_at belongs to one stable window.
// Used by scoring to give credit for active maintenance: a release with many
// final-closed core-serious fixes should score noticeably higher than one that
// closes zero, even if inherited debt is similar.
const closedDuringReignStmt = db.prepare(`
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
        (SELECT MIN(next.published_at) FROM releases next
         WHERE next.published_at > target.published_at AND next.prerelease = 0),
        '9999-12-31T23:59:59Z'
      )
ORDER BY i.closed_at DESC
`);

export function closedDuringReign(tag: string): JoinedIssue[] {
  return closedDuringReignStmt.all(tag) as unknown as JoinedIssue[];
}

const verifiedFixedForReleaseStmt = db.prepare(`
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
       c.confidence, c.rationale, c.classified_at, c.classified_updated_at
FROM issues i
JOIN classifications c ON c.issue_number = i.number
JOIN target
WHERE
  target.published_at IS NOT NULL
  AND i.closed_at IS NOT NULL
  AND i.closed_at >= target.published_at
  AND i.closed_at < COALESCE(
        (SELECT MIN(next.published_at) FROM releases next
         WHERE next.published_at > target.published_at AND next.prerelease = 0),
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
          AND ${creditedFixLinkSql('l')}
      )
    )
  )
ORDER BY i.closed_at DESC
`);

export function verifiedFixedForRelease(tag: string): JoinedIssue[] {
  return verifiedFixedForReleaseStmt.all(tag) as unknown as JoinedIssue[];
}

const unverifiedClosedForReleaseStmt = db.prepare(`
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
        (SELECT MIN(next.published_at) FROM releases next
         WHERE next.published_at > target.published_at AND next.prerelease = 0),
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
      AND ${creditedFixLinkSql('l')}
      AND NOT EXISTS (
        SELECT 1
        FROM issue_closure_proofs proof
        WHERE proof.release_tag = target.tag
          AND proof.issue_number = i.number
      )
  )
ORDER BY i.closed_at DESC
`);

export function unverifiedClosedForRelease(tag: string): JoinedIssue[] {
  return unverifiedClosedForReleaseStmt.all(tag) as unknown as JoinedIssue[];
}

// Issues OPENED during a release's reign — the "regressions introduced" signal.
// An issue counts as opened-during-R if its created_at falls inside R's reign
// window. Mirror of closedDuringReign. We don't currently penalise the score
// for this (would create new contradictions with the recommendation block),
// but we surface the count so users can see "this release closed 50 critical
// bugs and opened 150 during the same window" and judge for themselves.
const openedDuringReignStmt = db.prepare(`
SELECT i.*,
       c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
       c.confidence, c.rationale, c.classified_at, c.classified_updated_at
FROM issues i
JOIN classifications c ON c.issue_number = i.number
JOIN releases target ON target.tag = ?
WHERE
  target.published_at IS NOT NULL
  AND i.created_at >= target.published_at
  AND i.created_at < COALESCE(
        (SELECT MIN(next.published_at) FROM releases next
         WHERE next.published_at > target.published_at AND next.prerelease = 0),
        '9999-12-31T23:59:59Z'
      )
ORDER BY i.created_at DESC
`);

export function openedDuringReign(tag: string): JoinedIssue[] {
  return openedDuringReignStmt.all(tag) as unknown as JoinedIssue[];
}

// Count classifications written under a prompt version older than the current one.
// Used by refresh.ts to detect "a prompt bump happened — we have legacy rows that
// the pagination shortcut would skip" and disable the early-stop for one run.
const countStaleClsStmt = db.prepare(
  `SELECT COUNT(*) AS n FROM classifications WHERE prompt_version < ?`,
);
export function countStaleClassifications(currentPromptVersion: number): number {
  const row = countStaleClsStmt.get(currentPromptVersion) as { n: number };
  return row?.n ?? 0;
}

// Drop classification rows older than the current prompt version. Used by
// refresh.ts after a full sweep — issues with updated_at far enough in the
// past that GitHub pagination never returns them will otherwise keep their
// stale prompt_version forever and force the (expensive) prompt-sweep mode
// every refresh. Dropping the row is safe: if the issue ever resurfaces in
// pagination (e.g. a new comment lands), it will be re-classified fresh.
const deleteStaleClsStmt = db.prepare(
  `DELETE FROM classifications WHERE prompt_version < ?`,
);
export function deleteStaleClassifications(currentPromptVersion: number): number {
  const res = deleteStaleClsStmt.run(currentPromptVersion);
  return Number(res.changes ?? 0);
}

// ---------- advisories ----------
export interface AdvisoryRow {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: string;
  html_url: string;
  published_at: string | null;
  vulnerable_version_range: string | null;
  patched_versions: string | null;
  fetched_at: string;
}

const upsertAdvisoryStmt = db.prepare(`
INSERT INTO advisories (ghsa_id, cve_id, summary, severity, html_url, published_at,
  vulnerable_version_range, patched_versions, fetched_at)
VALUES (:ghsa_id, :cve_id, :summary, :severity, :html_url, :published_at,
  :vulnerable_version_range, :patched_versions, :fetched_at)
ON CONFLICT(ghsa_id) DO UPDATE SET
  cve_id=excluded.cve_id,
  summary=excluded.summary,
  severity=excluded.severity,
  html_url=excluded.html_url,
  published_at=excluded.published_at,
  vulnerable_version_range=excluded.vulnerable_version_range,
  patched_versions=excluded.patched_versions,
  fetched_at=excluded.fetched_at
`);

export function upsertAdvisory(a: Omit<AdvisoryRow, 'fetched_at'>): void {
  upsertAdvisoryStmt.run({ ...a, fetched_at: new Date().toISOString() });
}

const listAdvisoriesStmt = db.prepare(`SELECT * FROM advisories ORDER BY published_at DESC NULLS LAST`);
export function listAdvisories(): AdvisoryRow[] {
  return listAdvisoriesStmt.all() as unknown as AdvisoryRow[];
}

// ---------- meta ----------
// Key/value scratchpad for one-shot flags (e.g. "have we done the full back-fill yet").
const getMetaStmt = db.prepare(`SELECT value FROM meta WHERE key = ?`);
const setMetaStmt = db.prepare(
  `INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
);

export function getMeta(key: string): string | null {
  const row = getMetaStmt.get(key) as { value: string } | undefined;
  return row?.value ?? null;
}

export function setMeta(key: string, value: string): void {
  setMetaStmt.run(key, value);
}

// ---------- upstream comparison snapshots ----------
export interface ComparisonReleaseInput {
  tag: string;
  name: string | null;
  published_at: string | null;
  html_url: string;
  displayed_date: string | null;
  score: number | null;
  band: string | null;
  status: string | null;
  recommended: boolean;
  reason: string | null;
  negative_issues: number | null;
  positive_issues: number | null;
  total_attributed_issues: number | null;
  visible_issues: unknown[];
  raw_card_text: string;
}

export interface ComparisonSnapshotInput {
  source_url: string;
  captured_at: string;
  page_title: string;
  page_text: string;
  raw_html: string;
  releases: ComparisonReleaseInput[];
}

const insertComparisonSnapshotStmt = db.prepare(`
INSERT INTO comparison_snapshots (source_url, captured_at, page_title, page_text, raw_html)
VALUES (:source_url, :captured_at, :page_title, :page_text, :raw_html)
`);

const insertComparisonReleaseStmt = db.prepare(`
INSERT INTO comparison_releases (
  snapshot_id, tag, name, published_at, html_url, displayed_date, score, band,
  status, recommended, reason, negative_issues, positive_issues,
  total_attributed_issues, visible_issues_json, raw_card_text
)
VALUES (
  :snapshot_id, :tag, :name, :published_at, :html_url, :displayed_date, :score, :band,
  :status, :recommended, :reason, :negative_issues, :positive_issues,
  :total_attributed_issues, :visible_issues_json, :raw_card_text
)
`);

export function saveComparisonSnapshot(input: ComparisonSnapshotInput): number {
  db.exec('BEGIN');
  try {
    const result = insertComparisonSnapshotStmt.run({
      source_url: input.source_url,
      captured_at: input.captured_at,
      page_title: input.page_title,
      page_text: input.page_text,
      raw_html: input.raw_html,
    });
    const snapshotId = Number(result.lastInsertRowid);

    for (const release of input.releases) {
      insertComparisonReleaseStmt.run({
        snapshot_id: snapshotId,
        tag: release.tag,
        name: release.name,
        published_at: release.published_at,
        html_url: release.html_url,
        displayed_date: release.displayed_date,
        score: release.score,
        band: release.band,
        status: release.status,
        recommended: release.recommended ? 1 : 0,
        reason: release.reason,
        negative_issues: release.negative_issues,
        positive_issues: release.positive_issues,
        total_attributed_issues: release.total_attributed_issues,
        visible_issues_json: JSON.stringify(release.visible_issues),
        raw_card_text: release.raw_card_text,
      });
    }

    db.exec('COMMIT');
    return snapshotId;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function latestComparisonSnapshot(): {
  id: number;
  source_url: string;
  captured_at: string;
  page_title: string;
  page_text: string;
} | undefined {
  return db.prepare(`
    SELECT id, source_url, captured_at, page_title, page_text
    FROM comparison_snapshots
    ORDER BY id DESC
    LIMIT 1
  `).get() as {
    id: number;
    source_url: string;
    captured_at: string;
    page_title: string;
    page_text: string;
  } | undefined;
}

export function comparisonReleases(snapshotId?: number): Array<Record<string, unknown>> {
  if (snapshotId !== undefined) {
    return db.prepare(`
      SELECT * FROM comparison_releases
      WHERE snapshot_id=?
      ORDER BY published_at DESC, tag DESC
    `).all(snapshotId) as Array<Record<string, unknown>>;
  }
  return db.prepare(`
    SELECT * FROM comparison_releases
    WHERE snapshot_id=(SELECT MAX(id) FROM comparison_snapshots)
    ORDER BY published_at DESC, tag DESC
  `).all() as Array<Record<string, unknown>>;
}
