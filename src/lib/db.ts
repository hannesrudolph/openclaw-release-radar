import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { config } from '../config';
import type { IssueClassification } from './llm';

// node:sqlite is built into Node ≥ 22.5 (stable since 24). No native build, no prebuilds.

mkdirSync(dirname(config.db.path), { recursive: true });

export const db = new DatabaseSync(config.db.path);
// WAL improves concurrent reads but isn't supported on every mount (FUSE, some NFS).
// Fall back to the default rollback journal if it fails.
try {
  db.exec('PRAGMA journal_mode = WAL');
} catch (e) {
  console.warn('[db] WAL not supported on this filesystem, falling back to default journal:', (e as Error).message);
}
db.exec('PRAGMA foreign_keys = ON');

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
  registry_version TEXT,
  registry_integrity TEXT,
  registry_tarball_url TEXT,
  ci_report_verified INTEGER NOT NULL DEFAULT 0,
  ci_report_mismatch TEXT,
  artifact_verified INTEGER NOT NULL DEFAULT 0,
  artifact_mismatch TEXT,
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
  is_bot INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS issue_pr_links (
  issue_number INTEGER NOT NULL,
  pr_number INTEGER NOT NULL,
  source TEXT NOT NULL,
  will_close_target INTEGER,
  referenced_at TEXT,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (issue_number, pr_number, source)
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
  pr_number INTEGER PRIMARY KEY,
  title TEXT,
  url TEXT,
  state TEXT,
  merged INTEGER NOT NULL DEFAULT 0,
  merged_at TEXT,
  merge_commit_oid TEXT,
  base_ref_name TEXT,
  fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS release_pr_reachability (
  tag TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  tag_commit_oid TEXT NOT NULL,
  merge_commit_oid TEXT NOT NULL,
  base_ref_name TEXT,
  status TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'git-merge-base',
  evidence_json TEXT NOT NULL DEFAULT '{}',
  checked_at TEXT NOT NULL,
  PRIMARY KEY (tag, pr_number)
);

CREATE INDEX IF NOT EXISTS idx_issue_closure_events_issue ON issue_closure_events(issue_number);
CREATE INDEX IF NOT EXISTS idx_issue_pr_links_issue ON issue_pr_links(issue_number);
CREATE INDEX IF NOT EXISTS idx_issue_label_events_issue_time ON issue_label_events(issue_number, created_at);
CREATE INDEX IF NOT EXISTS idx_issue_closure_proofs_release ON issue_closure_proofs(release_tag, status);
CREATE INDEX IF NOT EXISTS idx_release_pr_reachability_tag ON release_pr_reachability(tag);
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
  `ALTER TABLE releases ADD COLUMN registry_version TEXT`,
  `ALTER TABLE releases ADD COLUMN registry_integrity TEXT`,
  `ALTER TABLE releases ADD COLUMN registry_tarball_url TEXT`,
  `ALTER TABLE releases ADD COLUMN ci_report_verified INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN ci_report_mismatch TEXT`,
  `ALTER TABLE releases ADD COLUMN artifact_verified INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE releases ADD COLUMN artifact_mismatch TEXT`,
  `ALTER TABLE releases ADD COLUMN broken_surfaces TEXT`,
]) {
  try { db.exec(sql); } catch { /* column already exists */ }
}

try {
  const cols = db.prepare(`PRAGMA table_info(release_pr_reachability)`).all() as Array<{ name: string }>;
  if (cols.length > 0 && !cols.some((col) => col.name === 'tag_commit_oid')) {
    db.exec(`DROP TABLE release_pr_reachability`);
    db.exec(`
    CREATE TABLE release_pr_reachability (
      tag TEXT NOT NULL,
      pr_number INTEGER NOT NULL,
      tag_commit_oid TEXT NOT NULL,
      merge_commit_oid TEXT NOT NULL,
      base_ref_name TEXT,
      status TEXT NOT NULL,
      method TEXT NOT NULL DEFAULT 'git-merge-base',
      evidence_json TEXT NOT NULL DEFAULT '{}',
      checked_at TEXT NOT NULL,
      PRIMARY KEY (tag, pr_number)
    )`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_release_pr_reachability_tag ON release_pr_reachability(tag)`);
  }
} catch {
  // The main CREATE TABLE block handles first-run setup; this only repairs old local schemas.
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
  registry_version: string | null;
  registry_integrity: string | null;
  registry_tarball_url: string | null;
  ci_report_verified: number;
  ci_report_mismatch: string | null;
  artifact_verified: number;
  artifact_mismatch: string | null;
  broken_surfaces: string | null;
}

const upsertReleaseStmt = db.prepare(`
INSERT INTO releases (tag, name, published_at, html_url, prerelease, body)
VALUES (:tag, :name, :published_at, :html_url, :prerelease, :body)
ON CONFLICT(tag) DO UPDATE SET
  name=excluded.name,
  published_at=excluded.published_at,
  html_url=excluded.html_url,
  prerelease=excluded.prerelease,
  body=excluded.body
`);

export function upsertRelease(r: {
  tag: string;
  name: string | null;
  published_at: string | null;
  html_url: string;
  prerelease: boolean;
  body: string | null;
}): void {
  upsertReleaseStmt.run({ ...r, prerelease: r.prerelease ? 1 : 0 });
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
  full_release_ci_report_url=:full_release_ci_report_url
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
}): void {
  updateReleaseDerivedStatsStmt.run({
    ...args,
    npm_package_url: args.npm_package_url ?? null,
    release_tarball_url: args.release_tarball_url ?? null,
    release_integrity: args.release_integrity ?? null,
    release_sha: args.release_sha ?? null,
    full_release_ci_report_url: args.full_release_ci_report_url ?? null,
  });
}

const updateReleaseArtifactVerificationStmt = db.prepare(`
UPDATE releases SET
  registry_version=:registry_version,
  registry_integrity=:registry_integrity,
  registry_tarball_url=:registry_tarball_url,
  ci_report_verified=:ci_report_verified,
  ci_report_mismatch=:ci_report_mismatch,
  artifact_verified=:artifact_verified,
  artifact_mismatch=:artifact_mismatch
WHERE tag=:tag
`);

export function updateReleaseArtifactVerification(args: {
  tag: string;
  registry_version: string | null;
  registry_integrity: string | null;
  registry_tarball_url: string | null;
  ci_report_verified: number;
  ci_report_mismatch: string | null;
  artifact_verified: number;
  artifact_mismatch: string | null;
}): void {
  updateReleaseArtifactVerificationStmt.run(args);
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

const issueLabelEventsUntilStmt = db.prepare(`
SELECT action, label_name
FROM issue_label_events
WHERE issue_number=?
  AND (? IS NULL OR created_at <= ?)
ORDER BY created_at ASC, event_id ASC
`);

const issueLabelEventCountStmt = db.prepare(`SELECT COUNT(*) AS count FROM issue_label_events WHERE issue_number=?`);

export function labelsForIssueAt(issueNumber: number, fallbackLabels: string[], cutoff: string | null): string[] {
  const eventCount = Number((issueLabelEventCountStmt.get(issueNumber) as { count: number }).count ?? 0);
  if (eventCount === 0) return fallbackLabels;
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

export interface IssueClosureProofRow extends IssueClosureProofInput {
  checked_at: string;
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

const closureProofExamplesStmt = db.prepare(`
SELECT p.*, i.title, i.html_url, i.closed_at, c.sentiment, c.severity, c.functionality
FROM issue_closure_proofs p
JOIN issues i ON i.number=p.issue_number
LEFT JOIN classifications c ON c.issue_number=p.issue_number
WHERE p.release_tag=?
ORDER BY
  CASE p.status
    WHEN 'fixed_after_release' THEN 0
    WHEN 'already_present_claim' THEN 1
    WHEN 'duplicate_or_superseded' THEN 2
    WHEN 'no_code_proof' THEN 3
    ELSE 4
  END,
  i.closed_at DESC
LIMIT ?
`);

export function closureProofExamples(releaseTag: string, limit = 25): Array<IssueClosureProofRow & {
  title: string;
  html_url: string | null;
  closed_at: string | null;
  sentiment: string | null;
  severity: string | null;
  functionality: string | null;
}> {
  return closureProofExamplesStmt.all(releaseTag, limit) as unknown as Array<IssueClosureProofRow & {
    title: string;
    html_url: string | null;
    closed_at: string | null;
    sentiment: string | null;
    severity: string | null;
    functionality: string | null;
  }>;
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

export interface IssuePrLinkInput {
  issue_number: number;
  pr_number: number;
  source: string;
  will_close_target: number | null;
  referenced_at: string | null;
}

const upsertIssuePrLinkStmt = db.prepare(`
INSERT INTO issue_pr_links (issue_number, pr_number, source, will_close_target, referenced_at, fetched_at)
VALUES (:issue_number, :pr_number, :source, :will_close_target, :referenced_at, :fetched_at)
ON CONFLICT(issue_number, pr_number, source) DO UPDATE SET
  will_close_target=excluded.will_close_target,
  referenced_at=excluded.referenced_at,
  fetched_at=excluded.fetched_at
`);

export function upsertIssuePrLink(input: IssuePrLinkInput): void {
  upsertIssuePrLinkStmt.run({ ...input, fetched_at: new Date().toISOString() });
}

export interface PullRequestFixInput {
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
  pr_number, title, url, state, merged, merged_at, merge_commit_oid, base_ref_name, fetched_at
)
VALUES (
  :pr_number, :title, :url, :state, :merged, :merged_at, :merge_commit_oid, :base_ref_name, :fetched_at
)
ON CONFLICT(pr_number) DO UPDATE SET
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
  upsertPullRequestFixStmt.run({ ...input, fetched_at: new Date().toISOString() });
}

export interface ReleasePrReachabilityInput {
  tag: string;
  pr_number: number;
  tag_commit_oid: string;
  merge_commit_oid: string;
  base_ref_name: string | null;
  status: 'reachable' | 'not_reachable' | 'unknown';
  method?: string;
  evidence_json: string;
}

const upsertReleasePrReachabilityStmt = db.prepare(`
INSERT INTO release_pr_reachability (
  tag, pr_number, tag_commit_oid, merge_commit_oid, base_ref_name, status, method,
  evidence_json, checked_at
)
VALUES (
  :tag, :pr_number, :tag_commit_oid, :merge_commit_oid, :base_ref_name, :status, :method,
  :evidence_json, :checked_at
)
ON CONFLICT(tag, pr_number) DO UPDATE SET
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
    method: input.method ?? 'git-merge-base',
    checked_at: new Date().toISOString(),
  });
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
}

const upsertIssueStmt = db.prepare(`
INSERT INTO issues (
  number, state, title, author, author_association, html_url, created_at, updated_at, closed_at,
  comments, unique_human_commenters, maintainer_commenters, contributor_commenters, commenter_scan_truncated,
  reaction_total, positive_reactions, labels, is_bot
)
VALUES (
  :number, :state, :title, :author, :author_association, :html_url, :created_at, :updated_at, :closed_at,
  :comments, :unique_human_commenters, :maintainer_commenters, :contributor_commenters, :commenter_scan_truncated,
  :reaction_total, :positive_reactions, :labels, :is_bot
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
  is_bot=excluded.is_bot
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
// An issue affects release R if its existence window overlaps R's reign:
//   - R reigns from R.published_at until the NEXT release is published
//     (or forever, if R is the latest).
//   - The issue exists from issue.created_at until issue.closed_at
//     (or forever, if still open).
// These two windows must overlap.
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
SELECT i.*,
       c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
       c.confidence, c.rationale, c.classified_at, c.classified_updated_at
FROM issues i
JOIN classifications c ON c.issue_number = i.number
JOIN releases target ON target.tag = ?
WHERE
  target.published_at IS NOT NULL
  -- Issue was filed before target's reign ended (next release published).
  -- For the latest release there is no "next", so we use a sentinel far future.
  AND i.created_at < COALESCE(
        (SELECT MIN(next.published_at) FROM releases next
         WHERE next.published_at > target.published_at),
        '9999-12-31T23:59:59Z'
      )
  -- Issue was not closed before target's reign started — i.e., the bug was
  -- still live when the user installed target, or was filed during R's reign.
  AND (i.closed_at IS NULL OR i.closed_at > target.published_at)
ORDER BY i.updated_at DESC
`);

export function issuesForVersion(tag: string): JoinedIssue[] {
  return issuesForVersionStmt.all(tag) as unknown as JoinedIssue[];
}

const issueCountForVersionStmt = db.prepare(`
SELECT COUNT(*) AS count
FROM issues i
JOIN releases target ON target.tag = ?
WHERE
  target.published_at IS NOT NULL
  AND i.created_at < COALESCE(
        (SELECT MIN(next.published_at) FROM releases next
         WHERE next.published_at > target.published_at),
        '9999-12-31T23:59:59Z'
      )
  AND (i.closed_at IS NULL OR i.closed_at > target.published_at)
`);

export function issueCountForVersion(tag: string): number {
  return Number((issueCountForVersionStmt.get(tag) as { count: number }).count ?? 0);
}

// Issues CLOSED during a release's reign — the "fixes credit" for that release.
// An issue counts as fixed-by-R if its closed_at falls inside R's reign window
// [R.published_at, next_release.published_at). This is what the release shipped
// in terms of resolved bugs. Used by scoring to give credit for active maintenance:
// a release that closes 100 core-serious issues during its reign should score
// noticeably higher than one that closes zero, even if its inherited debt is similar.
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
SELECT DISTINCT i.*,
       c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
       c.confidence, c.rationale, c.classified_at, c.classified_updated_at
FROM issues i
JOIN classifications c ON c.issue_number = i.number
JOIN issue_closure_events e ON e.issue_number = i.number
JOIN issue_pr_links l ON l.issue_number = i.number
JOIN pull_request_fixes p ON p.pr_number = l.pr_number
JOIN release_pr_reachability rpr ON rpr.tag = ? AND rpr.pr_number = p.pr_number
WHERE
  e.state_reason = 'COMPLETED'
  AND p.merged = 1
  AND rpr.status = 'reachable'
  AND (l.will_close_target = 1 OR l.source IN ('closedByPullRequestsReferences', 'ClosedEvent.closer'))
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
    SELECT 1
    FROM issue_closure_events e
    JOIN issue_pr_links l ON l.issue_number = e.issue_number
    JOIN pull_request_fixes p ON p.pr_number = l.pr_number
    JOIN release_pr_reachability rpr ON rpr.tag = target.tag AND rpr.pr_number = p.pr_number
    WHERE e.issue_number = i.number
      AND e.state_reason = 'COMPLETED'
      AND p.merged = 1
      AND rpr.status = 'reachable'
      AND (l.will_close_target = 1 OR l.source IN ('closedByPullRequestsReferences', 'ClosedEvent.closer'))
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
