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
  scored_at TEXT
);

CREATE TABLE IF NOT EXISTS issues (
  number INTEGER PRIMARY KEY,
  state TEXT NOT NULL,
  title TEXT NOT NULL,
  author TEXT,
  html_url TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT,
  comments INTEGER NOT NULL,
  labels TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS classifications (
  issue_number INTEGER PRIMARY KEY,
  sentiment TEXT NOT NULL,
  severity TEXT NOT NULL,
  scope TEXT NOT NULL,
  functionality TEXT NOT NULL,
  affected_users TEXT NOT NULL,
  has_workaround INTEGER NOT NULL,
  duplicate_cluster TEXT,
  affects_version TEXT,
  confidence REAL NOT NULL,
  rationale TEXT,
  classified_at TEXT NOT NULL,
  classified_updated_at TEXT NOT NULL,
  FOREIGN KEY (issue_number) REFERENCES issues(number) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_classifications_version ON classifications(affects_version);
CREATE INDEX IF NOT EXISTS idx_issues_updated ON issues(updated_at);
`);

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
}

const upsertReleaseStmt = db.prepare(`
INSERT INTO releases (tag, name, published_at, html_url, prerelease)
VALUES (:tag, :name, :published_at, :html_url, :prerelease)
ON CONFLICT(tag) DO UPDATE SET
  name=excluded.name,
  published_at=excluded.published_at,
  html_url=excluded.html_url,
  prerelease=excluded.prerelease
`);

export function upsertRelease(r: {
  tag: string;
  name: string | null;
  published_at: string | null;
  html_url: string;
  prerelease: boolean;
}): void {
  upsertReleaseStmt.run({ ...r, prerelease: r.prerelease ? 1 : 0 });
}

const updateScoreStmt = db.prepare(`
UPDATE releases SET final_score=:final_score, risk_index=:risk_index,
  negative_issues=:negative_issues, positive_issues=:positive_issues, scored_at=:scored_at
WHERE tag=:tag
`);

export function updateReleaseScore(args: {
  tag: string;
  final_score: number;
  risk_index: number;
  negative_issues: number;
  positive_issues: number;
}): void {
  updateScoreStmt.run({ ...args, scored_at: new Date().toISOString() });
}

const listReleasesStmt = db.prepare(`
SELECT * FROM releases ORDER BY published_at IS NULL, published_at DESC LIMIT ?
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
  html_url: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  comments: number;
  labels: string;
}

const upsertIssueStmt = db.prepare(`
INSERT INTO issues (number, state, title, author, html_url, created_at, updated_at, closed_at, comments, labels)
VALUES (:number, :state, :title, :author, :html_url, :created_at, :updated_at, :closed_at, :comments, :labels)
ON CONFLICT(number) DO UPDATE SET
  state=excluded.state,
  title=excluded.title,
  author=excluded.author,
  html_url=excluded.html_url,
  created_at=excluded.created_at,
  updated_at=excluded.updated_at,
  closed_at=excluded.closed_at,
  comments=excluded.comments,
  labels=excluded.labels
`);

export function upsertIssue(i: IssueRow): void {
  upsertIssueStmt.run(i as unknown as Record<string, string | number | null>);
}

const getIssueStmt = db.prepare(`SELECT * FROM issues WHERE number=?`);
export function getIssue(number: number): IssueRow | undefined {
  return getIssueStmt.get(number) as IssueRow | undefined;
}

// ---------- classifications ----------
const upsertClassificationStmt = db.prepare(`
INSERT INTO classifications (issue_number, sentiment, severity, scope, functionality, affected_users,
  has_workaround, duplicate_cluster, affects_version, confidence, rationale, classified_at, classified_updated_at)
VALUES (:issue_number, :sentiment, :severity, :scope, :functionality, :affected_users,
  :has_workaround, :duplicate_cluster, :affects_version, :confidence, :rationale, :classified_at, :classified_updated_at)
ON CONFLICT(issue_number) DO UPDATE SET
  sentiment=excluded.sentiment,
  severity=excluded.severity,
  scope=excluded.scope,
  functionality=excluded.functionality,
  affected_users=excluded.affected_users,
  has_workaround=excluded.has_workaround,
  duplicate_cluster=excluded.duplicate_cluster,
  affects_version=excluded.affects_version,
  confidence=excluded.confidence,
  rationale=excluded.rationale,
  classified_at=excluded.classified_at,
  classified_updated_at=excluded.classified_updated_at
`);

export function upsertClassification(issueNumber: number, c: IssueClassification, issueUpdatedAt: string): void {
  upsertClassificationStmt.run({
    issue_number: issueNumber,
    sentiment: c.sentiment,
    severity: c.severity,
    scope: c.scope,
    functionality: c.functionality,
    affected_users: c.affectedUsers,
    has_workaround: c.hasWorkaround ? 1 : 0,
    duplicate_cluster: c.duplicateCluster,
    affects_version: c.affectsVersion,
    confidence: c.confidence,
    rationale: c.rationale,
    classified_at: new Date().toISOString(),
    classified_updated_at: issueUpdatedAt,
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
  duplicate_cluster: string | null;
  affects_version: string | null;
  confidence: number;
  rationale: string | null;
  classified_at: string;
  classified_updated_at: string;
}

const getClassificationStmt = db.prepare(`SELECT * FROM classifications WHERE issue_number=?`);
export function getClassification(issueNumber: number): ClassificationRow | undefined {
  return getClassificationStmt.get(issueNumber) as ClassificationRow | undefined;
}

// Joined view for scoring + UI
export interface JoinedIssue extends IssueRow, ClassificationRow {}

const issuesForVersionStmt = db.prepare(`
SELECT i.*, c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.duplicate_cluster, c.affects_version, c.confidence,
       c.rationale, c.classified_at, c.classified_updated_at
FROM issues i
JOIN classifications c ON c.issue_number = i.number
WHERE c.affects_version = ?
ORDER BY i.updated_at DESC
`);

export function issuesForVersion(tag: string): JoinedIssue[] {
  return issuesForVersionStmt.all(tag) as unknown as JoinedIssue[];
}

const issuesWithoutVersionStmt = db.prepare(`
SELECT i.*, c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
       c.has_workaround, c.duplicate_cluster, c.affects_version, c.confidence,
       c.rationale, c.classified_at, c.classified_updated_at
FROM issues i
JOIN classifications c ON c.issue_number = i.number
WHERE c.affects_version IS NULL
ORDER BY i.updated_at DESC
`);

export function issuesWithoutVersion(): JoinedIssue[] {
  return issuesWithoutVersionStmt.all() as unknown as JoinedIssue[];
}
