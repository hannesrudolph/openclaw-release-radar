import { createHash } from 'node:crypto';

export const SCORE_SOURCE_IDENTITY_SCHEMA_VERSION = 1;

export type ScoreSourceIdentitySchemaVersion = typeof SCORE_SOURCE_IDENTITY_SCHEMA_VERSION;
export type ScoreSourceIdentityAlgorithm = 'sha256';
export type ScoreSourceIdentityMode = 'current_db';
export type ScoreSourceIdentityScope = 'score_input_database';
export type ScoreSourceIdentitySourceName =
  | 'releases'
  | 'release_commits'
  | 'advisories'
  | 'issues'
  | 'classifications'
  | 'issue_comment_snapshots'
  | 'issue_label_events'
  | 'issue_label_snapshots'
  | 'issue_closure_proofs'
  | 'issue_closure_events'
  | 'issue_reopen_events'
  | 'issue_pr_links'
  | 'issue_commit_references'
  | 'pull_request_fixes'
  | 'release_pr_reachability';

export interface ScoreSourceIdentitySource {
  source: ScoreSourceIdentitySourceName;
  count: number;
  digest: string;
}

export interface ScoreSourceIdentity {
  schemaVersion: ScoreSourceIdentitySchemaVersion;
  sourceMode: ScoreSourceIdentityMode;
  scope: ScoreSourceIdentityScope;
  algorithm: ScoreSourceIdentityAlgorithm;
  rowCount: number;
  sourceCount: number;
  digest: string;
  sources: ScoreSourceIdentitySource[];
}

export interface ScoreSourceIdentityStatement {
  all(): unknown[];
}

export interface ScoreSourceIdentityDatabase {
  prepare(sql: string): ScoreSourceIdentityStatement;
}

type JsonScalar = string | number | boolean | null;

interface ScoreSourceTableSpec {
  source: ScoreSourceIdentitySourceName;
  table: ScoreSourceIdentitySourceName;
  columns: readonly string[];
  orderBy: readonly string[];
}

const ALGORITHM: ScoreSourceIdentityAlgorithm = 'sha256';
const SOURCE_MODE: ScoreSourceIdentityMode = 'current_db';
const SCOPE: ScoreSourceIdentityScope = 'score_input_database';

const RELEASE_SCORE_OUTPUT_COLUMNS = [
  'final_score',
  'risk_index',
  'negative_issues',
  'positive_issues',
  'scored_at',
  'state',
  'closed_serious_fixed',
  'fix_bonus',
  'opened_serious_during_reign',
  'recommended',
  'score_reason',
  'broken_surfaces',
] as const;

const RELEASE_SOURCE_COLUMNS = [
  'tag',
  'name',
  'published_at',
  'html_url',
  'prerelease',
  'body',
  'breaking_count',
  'fixes_count',
  'changes_count',
  'highlights_count',
  'pr_refs_count',
  'beta_count',
  'hours_to_next_release',
  'hours_to_next_stable',
  'npm_package_url',
  'release_tarball_url',
  'release_integrity',
  'release_sha',
  'full_release_ci_report_url',
  'full_release_validation_url',
  'registry_version',
  'registry_integrity',
  'registry_tarball_url',
  'ci_report_verified',
  'ci_report_mismatch',
  'release_validation_verified',
  'release_validation_mismatch',
  'artifact_verified',
  'artifact_mismatch',
  'release_metadata_fetched_at',
  'release_derived_fetched_at',
  'release_artifact_checked_at',
] as const;

const SCORE_SOURCE_TABLES = [
  {
    source: 'releases',
    table: 'releases',
    orderBy: ['tag'],
    columns: RELEASE_SOURCE_COLUMNS,
  },
  {
    source: 'release_commits',
    table: 'release_commits',
    orderBy: ['tag'],
    columns: [
      'tag',
      'tag_commit_oid',
      'committed_at',
      'check_state',
      'check_total',
      'check_success',
      'check_failure',
      'check_pending',
      'check_skipped',
      'check_contexts_json',
      'fetched_at',
    ],
  },
  {
    source: 'advisories',
    table: 'advisories',
    orderBy: ['advisory_key'],
    columns: [
      'advisory_key',
      'ghsa_id',
      'cve_id',
      'summary',
      'severity',
      'html_url',
      'published_at',
      'package_ecosystem',
      'package_name',
      'vulnerable_version_range',
      'patched_versions',
      'fetched_at',
    ],
  },
  {
    source: 'issues',
    table: 'issues',
    orderBy: ['number'],
    columns: [
      'number',
      'state',
      'title',
      'author',
      'author_association',
      'html_url',
      'created_at',
      'updated_at',
      'closed_at',
      'comments',
      'unique_human_commenters',
      'maintainer_commenters',
      'contributor_commenters',
      'commenter_scan_truncated',
      'reaction_total',
      'positive_reactions',
      'labels',
      'is_bot',
      'fetched_at',
    ],
  },
  {
    source: 'classifications',
    table: 'classifications',
    orderBy: ['issue_number'],
    columns: [
      'issue_number',
      'sentiment',
      'severity',
      'scope',
      'functionality',
      'affected_users',
      'has_workaround',
      'workaround_status',
      'duplicate_cluster',
      'affects_version',
      'confidence',
      'rationale',
      'classified_at',
      'classified_updated_at',
      'prompt_version',
    ],
  },
  {
    source: 'issue_comment_snapshots',
    table: 'issue_comment_snapshots',
    orderBy: ['issue_number'],
    columns: [
      'issue_number',
      'fetched_at',
      'comment_count',
      'fetched_comment_count',
      'latest_comment_updated_at',
      'comments_digest',
    ],
  },
  {
    source: 'issue_label_events',
    table: 'issue_label_events',
    orderBy: ['event_id'],
    columns: [
      'issue_number',
      'event_id',
      'action',
      'label_name',
      'actor_login',
      'created_at',
      'fetched_at',
    ],
  },
  {
    source: 'issue_label_snapshots',
    table: 'issue_label_snapshots',
    orderBy: ['issue_number', 'snapshot_at'],
    columns: ['issue_number', 'snapshot_at', 'labels_json', 'fetched_at'],
  },
  {
    source: 'issue_closure_proofs',
    table: 'issue_closure_proofs',
    orderBy: ['release_tag', 'issue_number'],
    columns: ['release_tag', 'issue_number', 'status', 'summary', 'evidence_json', 'checked_at'],
  },
  {
    source: 'issue_closure_events',
    table: 'issue_closure_events',
    orderBy: ['event_id'],
    columns: [
      'issue_number',
      'event_id',
      'closed_at',
      'actor_login',
      'state_reason',
      'closer_type',
      'closer_number',
      'closer_oid',
      'raw_json',
      'fetched_at',
    ],
  },
  {
    source: 'issue_reopen_events',
    table: 'issue_reopen_events',
    orderBy: ['event_id'],
    columns: ['issue_number', 'event_id', 'reopened_at', 'actor_login', 'raw_json', 'fetched_at'],
  },
  {
    source: 'issue_pr_links',
    table: 'issue_pr_links',
    orderBy: ['issue_number', 'pr_repository_name_with_owner', 'pr_number', 'source'],
    columns: [
      'issue_number',
      'pr_repository_owner',
      'pr_repository_name',
      'pr_repository_name_with_owner',
      'pr_number',
      'source',
      'will_close_target',
      'referenced_at',
      'fetched_at',
    ],
  },
  {
    source: 'issue_commit_references',
    table: 'issue_commit_references',
    orderBy: ['event_id'],
    columns: [
      'issue_number',
      'event_id',
      'commit_oid',
      'commit_message_headline',
      'commit_repository_owner',
      'commit_repository_name',
      'commit_repository_name_with_owner',
      'is_cross_repository',
      'is_direct_reference',
      'referenced_at',
      'actor_login',
      'raw_json',
      'fetched_at',
    ],
  },
  {
    source: 'pull_request_fixes',
    table: 'pull_request_fixes',
    orderBy: ['pr_repository_name_with_owner', 'pr_number'],
    columns: [
      'pr_repository_owner',
      'pr_repository_name',
      'pr_repository_name_with_owner',
      'pr_number',
      'title',
      'url',
      'state',
      'merged',
      'merged_at',
      'merge_commit_oid',
      'base_ref_name',
      'fetched_at',
    ],
  },
  {
    source: 'release_pr_reachability',
    table: 'release_pr_reachability',
    orderBy: ['tag', 'pr_repository_name_with_owner', 'pr_number'],
    columns: [
      'tag',
      'pr_repository_owner',
      'pr_repository_name',
      'pr_repository_name_with_owner',
      'pr_number',
      'tag_commit_oid',
      'merge_commit_oid',
      'base_ref_name',
      'status',
      'method',
      'evidence_json',
      'checked_at',
    ],
  },
] as const satisfies readonly ScoreSourceTableSpec[];

assertNoExcludedReleaseColumns(RELEASE_SOURCE_COLUMNS);

export function scoreSourceIdentityForDb(database: ScoreSourceIdentityDatabase): ScoreSourceIdentity {
  const sources = SCORE_SOURCE_TABLES.map((source) => sourceIdentityForTable(database, source));
  const rowCount = sources.reduce((sum, source) => sum + source.count, 0);
  const digestHash = createHash(ALGORITHM);

  updateHashLine(digestHash, [
    'score_source_identity',
    {
      schemaVersion: SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
      sourceMode: SOURCE_MODE,
      scope: SCOPE,
      algorithm: ALGORITHM,
    },
  ]);

  for (const source of sources) {
    updateHashLine(digestHash, ['source', source.source, source.count, source.digest]);
  }

  return {
    schemaVersion: SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
    sourceMode: SOURCE_MODE,
    scope: SCOPE,
    algorithm: ALGORITHM,
    rowCount,
    sourceCount: sources.length,
    digest: digestHash.digest('hex'),
    sources,
  };
}

function sourceIdentityForTable(
  database: ScoreSourceIdentityDatabase,
  source: ScoreSourceTableSpec,
): ScoreSourceIdentitySource {
  const rows = database.prepare(selectSql(source)).all();
  if (!Array.isArray(rows)) {
    throw new TypeError(`Malformed query result for ${source.source}: expected array from all()`);
  }

  const hash = createHash(ALGORITHM);
  updateHashLine(hash, ['source_columns', source.source, source.table, source.columns]);
  updateHashLine(hash, ['source_order', source.source, source.table, source.orderBy]);

  rows.forEach((row, index) => {
    const rowObject = asRecord(row, source.source, index);
    const values = source.columns.map((column) => normalizeColumnValue(rowObject, source.source, index, column));
    updateHashLine(hash, ['row', source.source, source.table, values]);
  });

  return {
    source: source.source,
    count: rows.length,
    digest: hash.digest('hex'),
  };
}

function selectSql(source: ScoreSourceTableSpec): string {
  const columns = source.columns.map(quoteIdentifier).join(', ');
  const orderBy = source.orderBy.map(quoteIdentifier).join(', ');
  return `SELECT ${columns} FROM ${quoteIdentifier(source.table)} ORDER BY ${orderBy}`;
}

function quoteIdentifier(identifier: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
    throw new TypeError(`Invalid SQL identifier: ${identifier}`);
  }
  return `"${identifier}"`;
}

function asRecord(row: unknown, source: string, index: number): Record<string, unknown> {
  if (!row || typeof row !== 'object' || Array.isArray(row)) {
    throw new TypeError(`Malformed query row for ${source} at index ${index}: expected object`);
  }
  return row as Record<string, unknown>;
}

function normalizeColumnValue(
  row: Record<string, unknown>,
  source: string,
  index: number,
  column: string,
): JsonScalar {
  if (!Object.prototype.hasOwnProperty.call(row, column)) {
    throw new TypeError(`Malformed query row for ${source} at index ${index}: missing column ${column}`);
  }

  const value = row[column];
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Malformed query row for ${source} at index ${index}: non-finite number in ${column}`);
    }
    return value;
  }
  if (typeof value === 'bigint') {
    if (
      value >= BigInt(Number.MIN_SAFE_INTEGER) &&
      value <= BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      return Number(value);
    }
    return value.toString();
  }

  throw new TypeError(
    `Malformed query row for ${source} at index ${index}: unsupported value in ${column}`,
  );
}

function updateHashLine(hash: ReturnType<typeof createHash>, value: readonly unknown[]): void {
  hash.update(JSON.stringify(value));
  hash.update('\n');
}

function assertNoExcludedReleaseColumns(columns: readonly string[]): void {
  const excluded = new Set<string>(RELEASE_SCORE_OUTPUT_COLUMNS);
  const includedExcludedColumns = columns.filter((column) => excluded.has(column));
  if (includedExcludedColumns.length > 0) {
    throw new Error(`Release score output columns cannot be source identity inputs: ${includedExcludedColumns.join(', ')}`);
  }
}
