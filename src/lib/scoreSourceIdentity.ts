import { createHash } from 'node:crypto';
import { config } from '../config';
import {
  ADVISORY_SNAPSHOT_META_KEY,
  ADVISORY_SNAPSHOT_V2_META_KEY,
} from './advisorySnapshot';
import { codeRevisionFromEnv, normalizeCodeRevision } from './codeRevision';
import { canonicalJson } from './operationReceipts';
import {
  REC_THRESHOLD,
  RECOMMENDATION_RECENCY_TOLERANCE,
} from './score';
import {
  releaseArtifactObservationFromStorageRecord,
  releaseArtifactReceiptFromStorageRecord,
  type ReleaseArtifactIdentity,
  type ReleaseArtifactObservation,
  type ReleaseArtifactObservationStorageRecord,
  type ReleaseArtifactReceipt,
  type ReleaseArtifactReceiptStorageRecord,
} from './releaseArtifactReceipt';
import {
  buildReleaseArtifactPublication,
  parseReleaseArtifactPublication,
  releaseArtifactPublicationLink,
  releaseArtifactSemanticProjection,
  releaseIdentityKey,
} from './releaseArtifactPublication';
import {
  buildReleaseArtifactPublicationScope,
  releaseArtifactPublicationScopeLinkProblems,
  releaseArtifactPublicationScopeScoreProblems,
  type ReleaseArtifactPublicationScope,
} from './releaseArtifactPublicationScope';

export const SCORE_SOURCE_IDENTITY_SCHEMA_VERSION = 17;
export const SUPPORTED_SCORE_SOURCE_IDENTITY_SCHEMA_VERSIONS = [
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
] as const;
export const SCORE_EFFECTIVE_CONFIG_SCHEMA_VERSION = 1;

export type ScoreSourceIdentitySchemaVersion = typeof SCORE_SOURCE_IDENTITY_SCHEMA_VERSION;
export type ScoreSourceIdentityAlgorithm = 'sha256';
export type ScoreSourceIdentityMode = 'current_db';
export type ScoreSourceIdentityScope = 'score_input_database';
export type ScoreSourceIdentitySourceName =
  | 'releases'
  | 'release_commits'
  | 'advisories'
  | 'advisory_snapshot'
  | 'advisory_snapshot_v2'
  | 'advisory_snapshot_v2_history'
  | 'advisory_snapshot_v2_rows'
  | 'issues'
  | 'classifications'
  | 'issue_comment_snapshots'
  | 'issue_label_events'
  | 'repository_collaborator_permission_snapshots'
  | 'repository_collaborator_permission_rows'
  | 'approved_maintainer_roster_snapshots'
  | 'approved_maintainer_roster_entries'
  | 'issue_label_evidence_snapshots'
  | 'issue_label_evidence_rows'
  | 'repository_collaborator_permission_snapshots_v2'
  | 'repository_collaborator_permission_rows_v2'
  | 'signed_maintainer_roster_snapshots'
  | 'signed_maintainer_roster_entries'
  | 'closure_claim_source_snapshots'
  | 'closure_claim_candidates'
  | 'closure_claim_extraction_receipts'
  | 'closure_claim_extraction_receipt_members'
  | 'issue_label_snapshots'
  | 'issue_closure_proofs'
  | 'issue_closure_events'
  | 'issue_reopen_events'
  | 'issue_state_event_snapshots'
  | 'issue_pr_links'
  | 'issue_commit_references'
  | 'pull_request_fixes'
  | 'release_pr_reachability'
  | 'release_closure_dependency_snapshots'
  | 'release_artifact_receipts';

export interface ScoreSourceIdentitySource {
  source: ScoreSourceIdentitySourceName;
  count: number;
  digest: string;
}

export interface ScoreEffectiveScoringConfig {
  schemaVersion: typeof SCORE_EFFECTIVE_CONFIG_SCHEMA_VERSION;
  repository: {
    owner: string;
    repo: string;
  };
  monitoredReleaseLimit: number;
  recommendation: {
    policyCode: 'highest_confidence_with_recency_tolerance';
    threshold: number;
    recencyTolerance: number;
  };
}

export interface ScoreSourceRuntimeIdentity {
  codeRevision: string;
  effectiveScoringConfig: ScoreEffectiveScoringConfig;
  effectiveScoringConfigDigest: string;
}

export interface ScoreSourceIdentity {
  schemaVersion: ScoreSourceIdentitySchemaVersion;
  sourceMode: ScoreSourceIdentityMode;
  scope: ScoreSourceIdentityScope;
  algorithm: ScoreSourceIdentityAlgorithm;
  codeRevision: string;
  effectiveScoringConfig: ScoreEffectiveScoringConfig;
  effectiveScoringConfigDigest: string;
  rowCount: number;
  sourceCount: number;
  digest: string;
  sources: ScoreSourceIdentitySource[];
}

export interface ScoreSourceIdentityOptions {
  codeRevision?: string | null;
  effectiveScoringConfig?: ScoreEffectiveScoringConfig;
  artifactObservationRunId?: string | null;
}

export interface ScoreSourceIdentityStatement {
  iterate?: () => IterableIterator<unknown>;
  all?: () => unknown[];
}

export interface ScoreSourceIdentityDatabase {
  prepare(sql: string): ScoreSourceIdentityStatement;
}

type JsonScalar = string | number | boolean | null;

interface ScoreSourceTableSpec {
  source: ScoreSourceIdentitySourceName;
  table: string;
  columns: readonly string[];
  orderBy: readonly string[];
  where?: string;
}

const ALGORITHM: ScoreSourceIdentityAlgorithm = 'sha256';
const SOURCE_MODE: ScoreSourceIdentityMode = 'current_db';
const SCOPE: ScoreSourceIdentityScope = 'score_input_database';
const LEGACY_MANIFEST_KEYS = [
  'schemaVersion',
  'sourceMode',
  'scope',
  'algorithm',
  'rowCount',
  'sourceCount',
  'digest',
  'sources',
] as const;
const MANIFEST_KEYS = [
  'schemaVersion',
  'sourceMode',
  'scope',
  'algorithm',
  'codeRevision',
  'effectiveScoringConfig',
  'effectiveScoringConfigDigest',
  'rowCount',
  'sourceCount',
  'digest',
  'sources',
] as const;
const SOURCE_KEYS = ['source', 'count', 'digest'] as const;
const EFFECTIVE_CONFIG_KEYS = [
  'schemaVersion',
  'repository',
  'monitoredReleaseLimit',
  'recommendation',
] as const;
const EFFECTIVE_CONFIG_REPOSITORY_KEYS = ['owner', 'repo'] as const;
const EFFECTIVE_CONFIG_RECOMMENDATION_KEYS = [
  'policyCode',
  'threshold',
  'recencyTolerance',
] as const;
const CODE_REVISION_ENV_KEYS = [
  'RADAR_CODE_REVISION',
  'CODE_REVISION',
  'GITHUB_SHA',
  'RENDER_GIT_COMMIT',
  'VERCEL_GIT_COMMIT_SHA',
  'CF_PAGES_COMMIT_SHA',
  'SOURCE_VERSION',
] as const;
let cachedDefaultCodeRevision: {
  envKey: string;
  value: string | null;
} | null = null;

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
  'node_id',
  'catalog_tag_commit_oid',
  'name',
  'published_at',
  'created_at',
  'updated_at',
  'html_url',
  'prerelease',
  'catalog_rank',
  'catalog_digest',
  'catalog_active',
  'body',
  'breaking_count',
  'fixes_count',
  'changes_count',
  'highlights_count',
  'pr_refs_count',
  'beta_count',
  'hours_to_next_release',
  'hours_to_next_stable',
] as const;

const SCORE_SOURCE_TABLES = [
  {
    source: 'releases',
    table: 'releases',
    orderBy: ['catalog_rank', 'tag'],
    columns: RELEASE_SOURCE_COLUMNS,
    where: 'catalog_active=1',
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
    where: 'EXISTS (SELECT 1 FROM releases active_release WHERE active_release.tag=release_commits.tag AND active_release.catalog_active=1)',
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
    source: 'advisory_snapshot',
    table: 'meta',
    orderBy: ['key'],
    columns: ['key', 'value'],
    where: `key='${ADVISORY_SNAPSHOT_META_KEY}'`,
  },
  {
    source: 'advisory_snapshot_v2',
    table: 'meta',
    orderBy: ['key'],
    columns: ['key', 'value'],
    where: `key='${ADVISORY_SNAPSHOT_V2_META_KEY}'`,
  },
  {
    source: 'advisory_snapshot_v2_history',
    table: 'advisory_snapshot_v2_history',
    orderBy: ['id'],
    columns: [
      'id',
      'schema_version',
      'captured_at',
      'repository_owner',
      'repository_name',
      'repository_url',
      'target_ecosystem',
      'target_package_name',
      'source_hash',
      'catalog_hash',
      'score_hash',
      'score_ready',
      'row_count',
      'score_row_count',
      'score_content_digest',
      'snapshot_json',
      'previous_content_hash',
      'content_hash',
    ],
    where:
      `id=(SELECT CAST(json_extract(value, '$.snapshotId') AS INTEGER) ` +
      `FROM meta WHERE key='${ADVISORY_SNAPSHOT_V2_META_KEY}')`,
  },
  {
    source: 'advisory_snapshot_v2_rows',
    table: 'advisory_snapshot_v2_rows',
    orderBy: ['snapshot_id', 'range_identity'],
    columns: [
      'snapshot_id',
      'range_identity',
      'ghsa_id',
      'package_ecosystem',
      'package_name',
      'vulnerable_version_range',
      'state',
      'target_package',
      'score_eligible',
      'audit_only',
      'row_json',
      'row_hash',
    ],
    where:
      `snapshot_id=(SELECT CAST(json_extract(value, '$.snapshotId') AS INTEGER) ` +
      `FROM meta WHERE key='${ADVISORY_SNAPSHOT_V2_META_KEY}')`,
  },
  {
    source: 'issues',
    table: 'issues',
    orderBy: ['number'],
    columns: [
      'number',
      'node_id',
      'state',
      'title',
      'body',
      'author',
      'author_node_id',
      'author_type',
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
      'raw_json',
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
      'classified_comments_digest',
      'prompt_version',
      'source_identity_json',
      'source_identity_digest',
      'classification_origin',
      'raw_model_output',
      'provenance_json',
    ],
  },
  {
    source: 'issue_comment_snapshots',
    table: 'issue_comment_snapshots',
    orderBy: ['issue_number'],
    columns: [
      'issue_number',
      'issue_node_id',
      'schema_version',
      'fetched_at',
      'verified_at',
      'comment_count',
      'fetched_comment_count',
      'latest_comment_updated_at',
      'comments_digest',
      'issue_updated_at',
      'comments_json',
    ],
  },
  {
    source: 'issue_label_events',
    table: 'issue_label_events',
    orderBy: ['event_id'],
    columns: [
      'issue_number',
      'issue_node_id',
      'event_id',
      'action',
      'label_name',
      'actor_node_id',
      'actor_login',
      'actor_type',
      'created_at',
      'raw_json',
      'fetched_at',
    ],
  },
  {
    source: 'issue_label_evidence_snapshots',
    table: 'issue_label_evidence_snapshots',
    orderBy: ['issue_node_id', 'captured_at', 'snapshot_id'],
    columns: [
      'snapshot_id',
      'schema_version',
      'repository',
      'repository_node_id',
      'issue_number',
      'issue_node_id',
      'captured_at',
      'issue_updated_at',
      'total_count',
      'fetched_count',
      'page_count',
      'sweep_count',
      'stabilized',
      'rows_content_hash',
      'source_identity',
      'content_hash',
    ],
  },
  {
    source: 'issue_label_evidence_rows',
    table: 'issue_label_evidence_rows',
    orderBy: ['snapshot_id', 'connection_ordinal'],
    columns: [
      'snapshot_id',
      'connection_ordinal',
      'event_node_id',
      'action',
      'label_name',
      'label_node_id',
      'actor_node_id',
      'actor_login',
      'actor_type',
      'created_at',
      'raw_json',
      'source_identity',
      'content_hash',
    ],
  },
  {
    source: 'repository_collaborator_permission_snapshots_v2',
    table: 'repository_collaborator_permission_snapshots_v2',
    orderBy: ['repository_node_id', 'observed_at', 'snapshot_id'],
    columns: [
      'snapshot_id',
      'schema_version',
      'repository',
      'repository_node_id',
      'observed_at',
      'exhaustive',
      'complete',
      'total_count',
      'row_count',
      'page_count',
      'pages_fetched',
      'sweep_count',
      'rows_content_hash',
      'raw_json',
      'source_identity',
      'content_hash',
    ],
  },
  {
    source: 'repository_collaborator_permission_rows_v2',
    table: 'repository_collaborator_permission_rows_v2',
    orderBy: ['snapshot_id', 'source_ordinal'],
    columns: [
      'snapshot_id',
      'source_ordinal',
      'actor_node_id',
      'actor_login',
      'actor_type',
      'permission',
      'raw_json',
      'source_identity',
      'content_hash',
    ],
  },
  {
    source: 'signed_maintainer_roster_snapshots',
    table: 'signed_maintainer_roster_snapshots',
    orderBy: ['repository_node_id', 'approved_at', 'snapshot_id'],
    columns: [
      'snapshot_id',
      'schema_version',
      'purpose',
      'repository',
      'repository_node_id',
      'approval_id',
      'approved_at',
      'sequence',
      'prior_digest',
      'signer_key_id',
      'keyring_digest',
      'signature_algorithm',
      'signature',
      'signature_verified_at',
      'signed_payload_json',
      'row_count',
      'rows_content_hash',
      'source_identity',
      'content_hash',
    ],
  },
  {
    source: 'signed_maintainer_roster_entries',
    table: 'signed_maintainer_roster_entries',
    orderBy: ['snapshot_id', 'entry_ordinal'],
    columns: [
      'snapshot_id',
      'entry_ordinal',
      'evidence_id',
      'actor_node_id',
      'actor_login',
      'actor_type',
      'actor_association',
      'role',
      'effective_from',
      'effective_until',
      'raw_json',
      'source_identity',
      'content_hash',
    ],
  },
  {
    source: 'closure_claim_source_snapshots',
    table: 'closure_claim_source_snapshots',
    orderBy: ['issue_node_id', 'source_identity'],
    columns: [
      'source_identity',
      'schema_version',
      'source_revision_identity',
      'repository',
      'repository_node_id',
      'issue_number',
      'issue_node_id',
      'source_kind',
      'source_node_id',
      'source_database_id',
      'source_url',
      'actor_node_id',
      'actor_login',
      'actor_type',
      'created_at',
      'updated_at',
      'text_format',
      'text_digest',
      'canonical_source_json',
      'content_hash',
      'captured_at',
    ],
  },
  {
    source: 'closure_claim_candidates',
    table: 'closure_claim_candidates',
    orderBy: ['issue_node_id', 'candidate_id'],
    columns: [
      'candidate_id',
      'schema_version',
      'source_identity',
      'issue_number',
      'issue_node_id',
      'candidate_kind',
      'canonical_claim_json',
      'excerpt',
      'span_start',
      'span_end',
      'canonical_candidate_json',
      'content_hash',
      'captured_at',
    ],
  },
  {
    source: 'closure_claim_extraction_receipts',
    table: 'closure_claim_extraction_receipts',
    orderBy: ['issue_node_id', 'receipt_id'],
    columns: [
      'receipt_id',
      'schema_version',
      'extraction_schema_version',
      'repository',
      'repository_node_id',
      'issue_number',
      'issue_node_id',
      'issue_revision',
      'issue_updated_at',
      'issue_body_digest',
      'issue_author_node_id',
      'issue_author_type',
      'comment_snapshot_revision',
      'comment_authority_digest',
      'comment_stabilization_identity_digest',
      'state_snapshot_revision',
      'state_authority_digest',
      'state_stabilization_identity_digest',
      'extraction_digest',
      'candidate_set_digest',
      'candidate_count',
      'canonical_receipt_json',
      'content_hash',
      'captured_at',
    ],
  },
  {
    source: 'closure_claim_extraction_receipt_members',
    table: 'closure_claim_extraction_receipt_members',
    orderBy: ['receipt_id', 'member_ordinal'],
    columns: [
      'receipt_id',
      'member_ordinal',
      'candidate_id',
      'candidate_content_hash',
      'source_identity',
      'content_hash',
    ],
  },
  {
    source: 'issue_label_snapshots',
    table: 'issue_label_snapshots',
    orderBy: ['issue_number', 'snapshot_at'],
    columns: ['issue_number', 'issue_node_id', 'snapshot_at', 'labels_json', 'fetched_at'],
  },
  {
    source: 'issue_closure_proofs',
    table: 'issue_closure_proofs',
    orderBy: ['release_tag', 'issue_number'],
    columns: ['release_tag', 'issue_number', 'status', 'summary', 'evidence_json', 'checked_at'],
    where: 'EXISTS (SELECT 1 FROM releases active_release WHERE active_release.tag=issue_closure_proofs.release_tag AND active_release.catalog_active=1)',
  },
  {
    source: 'issue_closure_events',
    table: 'issue_closure_events',
    orderBy: ['event_id'],
    columns: [
      'issue_number',
      'issue_node_id',
      'event_id',
      'closed_at',
      'connection_ordinal',
      'actor_node_id',
      'actor_login',
      'state_reason',
      'closer_type',
      'closer_number',
      'closer_node_id',
      'closer_oid',
      'raw_json',
      'fetched_at',
    ],
  },
  {
    source: 'issue_reopen_events',
    table: 'issue_reopen_events',
    orderBy: ['event_id'],
    columns: [
      'issue_number',
      'issue_node_id',
      'event_id',
      'reopened_at',
      'connection_ordinal',
      'actor_node_id',
      'actor_login',
      'raw_json',
      'fetched_at',
    ],
  },
  {
    source: 'issue_state_event_snapshots',
    table: 'issue_state_event_snapshots',
    orderBy: ['issue_number'],
    columns: [
      'issue_number',
      'issue_node_id',
      'issue_node_type',
      'schema_version',
      'issue_state',
      'issue_updated_at',
      'total_count',
      'fetched_count',
      'events_digest',
      'authority_digest',
      'events_json',
      'sweep_count',
      'stabilized',
      'stabilization_json',
      'stabilization_identity_digest',
      'revision',
      'fetched_at',
      'verified_at',
    ],
  },
  {
    source: 'issue_pr_links',
    table: 'issue_pr_links',
    orderBy: ['issue_number', 'pr_repository_name_with_owner', 'pr_number', 'source'],
    columns: [
      'issue_number',
      'issue_node_id',
      'pr_repository_owner',
      'pr_repository_name',
      'pr_repository_name_with_owner',
      'pr_number',
      'pr_node_id',
      'source',
      'source_node_id',
      'will_close_target',
      'referenced_at',
      'source_comment_database_id',
      'source_comment_url',
      'raw_json',
      'fetched_at',
    ],
  },
  {
    source: 'issue_commit_references',
    table: 'issue_commit_references',
    orderBy: ['event_id'],
    columns: [
      'issue_number',
      'issue_node_id',
      'event_id',
      'commit_oid',
      'commit_message_headline',
      'commit_repository_owner',
      'commit_repository_name',
      'commit_repository_name_with_owner',
      'is_cross_repository',
      'is_direct_reference',
      'referenced_at',
      'actor_node_id',
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
      'node_id',
      'repository_node_id',
      'title',
      'url',
      'state',
      'merged',
      'merged_at',
      'merge_commit_oid',
      'base_ref_name',
      'raw_json',
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
    where: 'EXISTS (SELECT 1 FROM releases active_release WHERE active_release.tag=release_pr_reachability.tag AND active_release.catalog_active=1)',
  },
  {
    source: 'release_closure_dependency_snapshots',
    table: 'release_closure_dependency_snapshots',
    orderBy: ['release_tag'],
    columns: [
      'release_tag',
      'schema_version',
      'analyzer_version',
      'issue_numbers_json',
      'dependency_digest',
      'dependency_row_count',
      'captured_at',
    ],
    where: 'EXISTS (SELECT 1 FROM releases active_release WHERE active_release.tag=release_closure_dependency_snapshots.release_tag AND active_release.catalog_active=1)',
  },
] as const satisfies readonly ScoreSourceTableSpec[];

const RELEASE_ARTIFACT_SEMANTIC_SOURCE_COLUMNS = [
  'release',
  'receiptId',
  'evidenceIdentity',
  'evidenceReportIdentity',
  'canonicalReceiptJson',
] as const;

const LEGACY_SCHEMA_9_AUTHORITY_SOURCE_NAMES = [
  'repository_collaborator_permission_snapshots',
  'repository_collaborator_permission_rows',
  'approved_maintainer_roster_snapshots',
  'approved_maintainer_roster_entries',
] as const satisfies readonly ScoreSourceIdentitySourceName[];
const RAW_SCHEMA_10_AUTHORITY_SOURCE_NAMES = [
  'issue_label_evidence_snapshots',
  'issue_label_evidence_rows',
  'repository_collaborator_permission_snapshots_v2',
  'repository_collaborator_permission_rows_v2',
  'signed_maintainer_roster_snapshots',
  'signed_maintainer_roster_entries',
  'closure_claim_source_snapshots',
  'closure_claim_candidates',
  'closure_claim_extraction_receipts',
  'closure_claim_extraction_receipt_members',
] as const satisfies readonly ScoreSourceIdentitySourceName[];

function scoreSourceNamesForSchema(
  schemaVersion: number,
): ScoreSourceIdentitySourceName[] {
  const currentNames: ScoreSourceIdentitySourceName[] = [
    ...SCORE_SOURCE_TABLES.map((source) => source.source),
    'release_artifact_receipts',
  ];
  if (schemaVersion >= 17) return currentNames;
  const withoutArtifactReceipts = currentNames.filter((source) =>
    source !== 'release_artifact_receipts');
  if (schemaVersion >= 16) return withoutArtifactReceipts;
  const withoutAdvisoryV2 = withoutArtifactReceipts.filter((source) =>
    source !== 'advisory_snapshot_v2' &&
    source !== 'advisory_snapshot_v2_history' &&
    source !== 'advisory_snapshot_v2_rows');
  if (schemaVersion >= 14) return withoutAdvisoryV2;
  if (schemaVersion === 13) {
    return withoutAdvisoryV2.filter((source) =>
      source !== 'closure_claim_extraction_receipts' &&
      source !== 'closure_claim_extraction_receipt_members');
  }
  if (schemaVersion >= 10) {
    return withoutAdvisoryV2.filter((source) =>
      source !== 'closure_claim_source_snapshots' &&
      source !== 'closure_claim_extraction_receipts' &&
      source !== 'closure_claim_extraction_receipt_members');
  }
  const rawAuthorityNames = new Set<ScoreSourceIdentitySourceName>(
    RAW_SCHEMA_10_AUTHORITY_SOURCE_NAMES,
  );
  const names: ScoreSourceIdentitySourceName[] = withoutAdvisoryV2.filter(
    (source) => !rawAuthorityNames.has(source),
  );
  if (schemaVersion === 9) {
    const insertionIndex = names.indexOf('issue_label_events') + 1;
    names.splice(insertionIndex, 0, ...LEGACY_SCHEMA_9_AUTHORITY_SOURCE_NAMES);
  }
  return schemaVersion >= 7
    ? names
    : names.filter((source) => source !== 'advisory_snapshot');
}

assertNoExcludedReleaseColumns(RELEASE_SOURCE_COLUMNS);

export function currentEffectiveScoringConfig(): ScoreEffectiveScoringConfig {
  return canonicalEffectiveScoringConfig({
    schemaVersion: SCORE_EFFECTIVE_CONFIG_SCHEMA_VERSION,
    repository: {
      owner: config.github.owner,
      repo: config.github.repo,
    },
    monitoredReleaseLimit: config.limits.releases,
    recommendation: {
      policyCode: 'highest_confidence_with_recency_tolerance',
      threshold: REC_THRESHOLD,
      recencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
    },
  });
}

export function scoreEffectiveScoringConfigDigest(
  effectiveScoringConfig: ScoreEffectiveScoringConfig,
): string {
  return createHash(ALGORITHM)
    .update('score_effective_config_v1\0')
    .update(canonicalJson(effectiveScoringConfig))
    .digest('hex');
}

export function scoreSourceRuntimeIdentity(
  options: ScoreSourceIdentityOptions = {},
): ScoreSourceRuntimeIdentity {
  const configuredRevision = Object.prototype.hasOwnProperty.call(options, 'codeRevision')
    ? options.codeRevision
    : defaultCodeRevision();
  const codeRevision = normalizeCodeRevision(configuredRevision);
  if (!codeRevision) {
    throw new Error('Score source identity requires deterministic code revision provenance');
  }
  const effectiveScoringConfig = canonicalEffectiveScoringConfig(
    options.effectiveScoringConfig ?? currentEffectiveScoringConfig(),
  );
  return {
    codeRevision,
    effectiveScoringConfig,
    effectiveScoringConfigDigest:
      scoreEffectiveScoringConfigDigest(effectiveScoringConfig),
  };
}

function defaultCodeRevision(): string | null {
  const envKey = canonicalJson(CODE_REVISION_ENV_KEYS.map((key) =>
    process.env[key] ?? null));
  if (cachedDefaultCodeRevision?.envKey === envKey) {
    return cachedDefaultCodeRevision.value;
  }
  const value = codeRevisionFromEnv();
  cachedDefaultCodeRevision = { envKey, value };
  return value;
}

export function scoreSourceRuntimeIdentityCacheKey(
  options: ScoreSourceIdentityOptions = {},
): string {
  const runtime = scoreSourceRuntimeIdentity(options);
  return createHash(ALGORITHM)
    .update('score_source_runtime_identity_v1\0')
    .update(canonicalJson(runtime))
    .digest('hex');
}

export function scoreSourceIdentityForDb(
  database: ScoreSourceIdentityDatabase,
  options: ScoreSourceIdentityOptions = {},
): ScoreSourceIdentity {
  const runtime = scoreSourceRuntimeIdentity(options);
  const sources = [
    ...SCORE_SOURCE_TABLES.map((source) =>
      sourceIdentityForTable(database, source)),
    releaseArtifactReceiptSourceIdentity(
      database,
      options,
      runtime.effectiveScoringConfig,
    ),
  ];
  const rowCount = sources.reduce((sum, source) => sum + source.count, 0);

  return {
    schemaVersion: SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
    sourceMode: SOURCE_MODE,
    scope: SCOPE,
    algorithm: ALGORITHM,
    ...runtime,
    rowCount,
    sourceCount: sources.length,
    digest: scoreSourceIdentityManifestDigest(
      sources,
      SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
      runtime,
    ),
    sources,
  };
}

export function scoreSourceIdentityManifestDigest(
  sources: readonly Pick<ScoreSourceIdentitySource, 'source' | 'count' | 'digest'>[],
  schemaVersion = SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  runtimeIdentity?: ScoreSourceRuntimeIdentity,
): string {
  const digestHash = createHash(ALGORITHM);
  updateHashLine(digestHash, [
    'score_source_identity',
    {
      schemaVersion,
      sourceMode: SOURCE_MODE,
      scope: SCOPE,
      algorithm: ALGORITHM,
    },
  ]);
  if (schemaVersion >= 8) {
    const runtime = runtimeIdentity ?? scoreSourceRuntimeIdentity();
    updateHashLine(digestHash, [
      'runtime',
      runtime.codeRevision,
      runtime.effectiveScoringConfigDigest,
    ]);
  }
  for (const source of sources) {
    updateHashLine(digestHash, ['source', source.source, source.count, source.digest]);
  }
  return digestHash.digest('hex');
}

export function scoreSourceIdentityManifestProblems(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return ['manifest must be an object'];
  }
  const manifest = value as Record<string, unknown>;
  const problems: string[] = [];
  const schemaVersion = Number(manifest.schemaVersion);
  const expectedKeys = schemaVersion >= 8 ? MANIFEST_KEYS : LEGACY_MANIFEST_KEYS;
  const manifestKeys = Object.keys(manifest).sort();
  const expectedManifestKeys = [...expectedKeys].sort();
  if (JSON.stringify(manifestKeys) !== JSON.stringify(expectedManifestKeys)) {
    problems.push(`manifest keys must equal ${expectedKeys.join(', ')}`);
  }
  if (!SUPPORTED_SCORE_SOURCE_IDENTITY_SCHEMA_VERSIONS.includes(
    schemaVersion as (typeof SUPPORTED_SCORE_SOURCE_IDENTITY_SCHEMA_VERSIONS)[number],
  )) {
    problems.push(
      `schemaVersion must equal one of ${SUPPORTED_SCORE_SOURCE_IDENTITY_SCHEMA_VERSIONS.join(', ')}`,
    );
  }
  if (manifest.sourceMode !== SOURCE_MODE) problems.push(`sourceMode must equal ${SOURCE_MODE}`);
  if (manifest.scope !== SCOPE) problems.push(`scope must equal ${SCOPE}`);
  if (manifest.algorithm !== ALGORITHM) problems.push(`algorithm must equal ${ALGORITHM}`);
  if (schemaVersion >= 8) {
    if (
      typeof manifest.codeRevision !== 'string' ||
      normalizeCodeRevision(manifest.codeRevision) !== manifest.codeRevision
    ) {
      problems.push('codeRevision must be a normalized deterministic revision');
    }
    problems.push(...scoreEffectiveScoringConfigProblems(
      manifest.effectiveScoringConfig,
    ));
    if (
      typeof manifest.effectiveScoringConfigDigest !== 'string' ||
      !/^[0-9a-f]{64}$/.test(manifest.effectiveScoringConfigDigest)
    ) {
      problems.push(
        'effectiveScoringConfigDigest must be a lowercase SHA-256 hex string',
      );
    } else if (
      scoreEffectiveScoringConfigProblems(manifest.effectiveScoringConfig).length === 0 &&
      manifest.effectiveScoringConfigDigest !== scoreEffectiveScoringConfigDigest(
        canonicalEffectiveScoringConfig(
          manifest.effectiveScoringConfig as ScoreEffectiveScoringConfig,
        ),
      )
    ) {
      problems.push(
        'effectiveScoringConfigDigest does not match effectiveScoringConfig',
      );
    }
  }
  if (!Number.isInteger(manifest.rowCount) || Number(manifest.rowCount) < 0) {
    problems.push('rowCount must be a non-negative integer');
  }
  if (!Number.isInteger(manifest.sourceCount) || Number(manifest.sourceCount) < 0) {
    problems.push('sourceCount must be a non-negative integer');
  }
  if (typeof manifest.digest !== 'string' || !/^[0-9a-f]{64}$/.test(manifest.digest)) {
    problems.push('digest must be a lowercase SHA-256 hex string');
  }
  if (!Array.isArray(manifest.sources)) {
    problems.push('sources must be an array');
    return problems;
  }

  const expectedNames = scoreSourceNamesForSchema(schemaVersion);
  const actualNames: string[] = [];
  let computedRowCount = 0;
  for (let index = 0; index < manifest.sources.length; index++) {
    const source = manifest.sources[index];
    if (!source || typeof source !== 'object' || Array.isArray(source)) {
      problems.push(`sources[${index}] must be an object`);
      continue;
    }
    const record = source as Record<string, unknown>;
    const sourceKeys = Object.keys(record).sort();
    const expectedSourceKeys = [...SOURCE_KEYS].sort();
    if (JSON.stringify(sourceKeys) !== JSON.stringify(expectedSourceKeys)) {
      problems.push(`sources[${index}] keys must equal ${SOURCE_KEYS.join(', ')}`);
    }
    if (typeof record.source !== 'string' || !record.source) {
      problems.push(`sources[${index}].source must be a non-empty string`);
    } else {
      actualNames.push(record.source);
    }
    if (!Number.isInteger(record.count) || Number(record.count) < 0) {
      problems.push(`sources[${index}].count must be a non-negative integer`);
    } else {
      computedRowCount += Number(record.count);
    }
    if (typeof record.digest !== 'string' || !/^[0-9a-f]{64}$/.test(record.digest)) {
      problems.push(`sources[${index}].digest must be a lowercase SHA-256 hex string`);
    }
  }
  if (manifest.sources.length !== expectedNames.length) {
    problems.push(`sources must contain exactly ${expectedNames.length} entries`);
  }
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    problems.push('sources must match the canonical source list and order');
  }
  if (new Set(actualNames).size !== actualNames.length) {
    problems.push('sources must not contain duplicate source names');
  }
  if (manifest.sourceCount !== expectedNames.length) {
    problems.push(`sourceCount must equal ${expectedNames.length}`);
  }
  if (manifest.rowCount !== computedRowCount) {
    problems.push(`rowCount must equal the sum of source counts (${computedRowCount})`);
  }

  if (problems.length === 0) {
    const expectedDigest = scoreSourceIdentityManifestDigest(
      manifest.sources as ScoreSourceIdentitySource[],
      schemaVersion,
      schemaVersion >= 8
        ? {
            codeRevision: manifest.codeRevision as string,
            effectiveScoringConfig:
              canonicalEffectiveScoringConfig(
                manifest.effectiveScoringConfig as ScoreEffectiveScoringConfig,
              ),
            effectiveScoringConfigDigest:
              manifest.effectiveScoringConfigDigest as string,
          }
        : undefined,
    );
    if (manifest.digest !== expectedDigest) {
      problems.push('digest does not match the ordered source manifest');
    }
  }
  return problems;
}

function canonicalEffectiveScoringConfig(
  value: ScoreEffectiveScoringConfig,
): ScoreEffectiveScoringConfig {
  const problems = scoreEffectiveScoringConfigProblems(value);
  if (problems.length > 0) {
    throw new TypeError(`Invalid effective scoring config: ${problems.join('; ')}`);
  }
  return JSON.parse(canonicalJson(value)) as ScoreEffectiveScoringConfig;
}

function scoreEffectiveScoringConfigProblems(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return ['effectiveScoringConfig must be an object'];
  }
  const record = value as Record<string, unknown>;
  const problems: string[] = [];
  if (!sameKeys(record, EFFECTIVE_CONFIG_KEYS)) {
    problems.push(
      `effectiveScoringConfig keys must equal ${EFFECTIVE_CONFIG_KEYS.join(', ')}`,
    );
  }
  if (record.schemaVersion !== SCORE_EFFECTIVE_CONFIG_SCHEMA_VERSION) {
    problems.push(
      `effectiveScoringConfig.schemaVersion must equal ${SCORE_EFFECTIVE_CONFIG_SCHEMA_VERSION}`,
    );
  }
  if (
    !Number.isInteger(record.monitoredReleaseLimit) ||
    Number(record.monitoredReleaseLimit) <= 0
  ) {
    problems.push(
      'effectiveScoringConfig.monitoredReleaseLimit must be a positive integer',
    );
  }

  const repository = record.repository;
  if (!repository || typeof repository !== 'object' || Array.isArray(repository)) {
    problems.push('effectiveScoringConfig.repository must be an object');
  } else {
    const repositoryRecord = repository as Record<string, unknown>;
    if (!sameKeys(repositoryRecord, EFFECTIVE_CONFIG_REPOSITORY_KEYS)) {
      problems.push(
        `effectiveScoringConfig.repository keys must equal ` +
        EFFECTIVE_CONFIG_REPOSITORY_KEYS.join(', '),
      );
    }
    for (const field of EFFECTIVE_CONFIG_REPOSITORY_KEYS) {
      if (typeof repositoryRecord[field] !== 'string' || !repositoryRecord[field]) {
        problems.push(
          `effectiveScoringConfig.repository.${field} must be a non-empty string`,
        );
      }
    }
  }

  const recommendation = record.recommendation;
  if (
    !recommendation ||
    typeof recommendation !== 'object' ||
    Array.isArray(recommendation)
  ) {
    problems.push('effectiveScoringConfig.recommendation must be an object');
  } else {
    const recommendationRecord = recommendation as Record<string, unknown>;
    if (!sameKeys(recommendationRecord, EFFECTIVE_CONFIG_RECOMMENDATION_KEYS)) {
      problems.push(
        `effectiveScoringConfig.recommendation keys must equal ` +
        EFFECTIVE_CONFIG_RECOMMENDATION_KEYS.join(', '),
      );
    }
    if (
      recommendationRecord.policyCode !==
      'highest_confidence_with_recency_tolerance'
    ) {
      problems.push(
        'effectiveScoringConfig.recommendation.policyCode is invalid',
      );
    }
    for (const field of ['threshold', 'recencyTolerance'] as const) {
      if (
        typeof recommendationRecord[field] !== 'number' ||
        !Number.isFinite(recommendationRecord[field])
      ) {
        problems.push(
          `effectiveScoringConfig.recommendation.${field} must be finite`,
        );
      }
    }
  }
  return problems;
}

function sameKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  return JSON.stringify(Object.keys(value).sort()) ===
    JSON.stringify([...expected].sort());
}

function releaseArtifactReceiptSourceIdentity(
  database: ScoreSourceIdentityDatabase,
  options: ScoreSourceIdentityOptions,
  effectiveScoringConfig: ScoreEffectiveScoringConfig,
): ScoreSourceIdentitySource {
  const runId = options.artifactObservationRunId == null
    ? null
    : canonicalRunId(options.artifactObservationRunId);
  const receiptRows = queryScoreSourceRows(database, {
    source: 'release_artifact_receipts',
    table: 'release_artifact_verification_receipts',
    columns: [
      'receipt_id',
      'schema_version',
      'release_repository',
      'release_tag',
      'release_node_id',
      'release_tag_commit_oid',
      'release_published_at',
      'evidence_identity',
      'canonical_receipt_json',
      'previous_content_hash',
      'content_hash',
    ],
    orderBy: ['id'],
  });
  const observationRows = queryScoreSourceRows(database, {
    source: 'release_artifact_receipts',
    table: 'release_artifact_verification_observations',
    columns: [
      'observation_id',
      'schema_version',
      'run_id',
      'observed_at',
      'release_repository',
      'release_tag',
      'release_node_id',
      'release_tag_commit_oid',
      'release_published_at',
      'receipt_id',
      'receipt_content_hash',
      'canonical_observation_json',
      'previous_content_hash',
      'content_hash',
    ],
    orderBy: ['id'],
  });
  const receipts = new Map<string, ReleaseArtifactReceipt>();
  for (const row of receiptRows) {
    const receipt = releaseArtifactReceiptFromStorageRecord(
      row as unknown as ReleaseArtifactReceiptStorageRecord,
    );
    if (receipts.has(receipt.receiptId)) {
      throw new Error(
        `Duplicate release artifact receipt ${JSON.stringify(receipt.receiptId)}`,
      );
    }
    receipts.set(receipt.receiptId, receipt);
  }
  const observations = observationRows.map((row) =>
    releaseArtifactObservationFromStorageRecord(
      row as unknown as ReleaseArtifactObservationStorageRecord,
    ));

  const selected = runId
    ? activeRunArtifactObservations(
        database,
        runId,
        observations,
        receipts,
        effectiveScoringConfig,
      )
    : publishedArtifactObservations(
        database,
        observations,
        receipts,
        effectiveScoringConfig,
      );
  const projections = selected
    .map(({ receipt }) => releaseArtifactSemanticProjection(receipt))
    .sort((left, right) =>
      releaseIdentityKey(left.release as ReleaseArtifactIdentity).localeCompare(
        releaseIdentityKey(right.release as ReleaseArtifactIdentity),
      ));

  const hash = createHash(ALGORITHM);
  updateHashLine(hash, [
    'source_columns',
    'release_artifact_receipts',
    'semantic_release_artifact_receipts',
    RELEASE_ARTIFACT_SEMANTIC_SOURCE_COLUMNS,
  ]);
  updateHashLine(hash, [
    'source_order',
    'release_artifact_receipts',
    'semantic_release_artifact_receipts',
    ['release.repository', 'release.tag', 'release.releaseNodeId'],
  ]);
  for (const projection of projections) {
    updateHashLine(hash, [
      'row',
      'release_artifact_receipts',
      'semantic_release_artifact_receipts',
      RELEASE_ARTIFACT_SEMANTIC_SOURCE_COLUMNS.map((column) =>
        projection[column]),
    ]);
  }
  return {
    source: 'release_artifact_receipts',
    count: projections.length,
    digest: hash.digest('hex'),
  };
}

function activeRunArtifactObservations(
  database: ScoreSourceIdentityDatabase,
  runId: string,
  observations: ReleaseArtifactObservation[],
  receipts: Map<string, ReleaseArtifactReceipt>,
  effectiveScoringConfig: ScoreEffectiveScoringConfig,
): Array<{
  observation: ReleaseArtifactObservation;
  receipt: ReleaseArtifactReceipt;
}> {
  const terminalRows = queryScoreSourceRows(database, {
    source: 'release_artifact_receipts',
    table: 'refresh_capture_receipts',
    columns: ['run_id', 'status', 'payload_json'],
    orderBy: ['id'],
  }).filter((row) => row.run_id === runId);
  if (terminalRows.length > 1) {
    throw new Error(`Artifact observation run ${JSON.stringify(runId)} has duplicate receipts`);
  }
  const terminal = terminalRows[0];
  if (terminal && terminal.status !== 'success') {
    throw new Error(
      `Artifact observation run ${JSON.stringify(runId)} terminated as ` +
      `${JSON.stringify(terminal.status)}`,
    );
  }
  if (terminal?.status === 'success') {
    return publicationArtifactObservations(
      terminal.payload_json,
      runId,
      observations,
      receipts,
      database,
      effectiveScoringConfig,
    );
  }
  const selected = observations
    .filter((observation) => observation.runId === runId)
    .map((observation) => ({
      observation,
      receipt: requiredArtifactReceipt(receipts, observation),
    }));
  assertArtifactReleaseCoverage(database, selected, effectiveScoringConfig);
  return selected;
}

function publishedArtifactObservations(
  database: ScoreSourceIdentityDatabase,
  observations: ReleaseArtifactObservation[],
  receipts: Map<string, ReleaseArtifactReceipt>,
  effectiveScoringConfig: ScoreEffectiveScoringConfig,
): Array<{
  observation: ReleaseArtifactObservation;
  receipt: ReleaseArtifactReceipt;
}> {
  const metaRows = queryScoreSourceRows(database, {
    source: 'release_artifact_receipts',
    table: 'meta',
    columns: ['key', 'value'],
    orderBy: ['key'],
    where: `key='score_persistence_last_run'`,
  });
  const meta = parseJsonRecord(metaRows[0]?.value);
  const operationRunId =
    meta?.source === 'refresh' &&
    meta.operationReceiptRequired === true &&
    typeof meta.operationRunId === 'string' &&
    meta.operationRunId
      ? meta.operationRunId
      : null;
  if (!operationRunId) return [];
  const receiptRows = queryScoreSourceRows(database, {
    source: 'release_artifact_receipts',
    table: 'refresh_capture_receipts',
    columns: ['run_id', 'status', 'payload_json'],
    orderBy: ['id'],
  }).filter((row) => row.run_id === operationRunId);
  if (receiptRows.length !== 1) {
    throw new Error(
      `Published score run ${JSON.stringify(operationRunId)} must have one terminal receipt`,
    );
  }
  const terminal = receiptRows[0];
  if (terminal.status !== 'success') {
    throw new Error(
      `Published score run ${JSON.stringify(operationRunId)} is not successful`,
    );
  }
  const payload = parseJsonRecord(terminal.payload_json);
  if (Number(payload?.schemaVersion ?? 0) < 2) {
    return [];
  }
  return publicationArtifactObservations(
    terminal.payload_json,
    operationRunId,
    observations,
    receipts,
    database,
    effectiveScoringConfig,
  );
}

function publicationArtifactObservations(
  payloadJson: unknown,
  runId: string,
  observations: ReleaseArtifactObservation[],
  receipts: Map<string, ReleaseArtifactReceipt>,
  database?: ScoreSourceIdentityDatabase,
  effectiveScoringConfig?: ScoreEffectiveScoringConfig,
): Array<{
  observation: ReleaseArtifactObservation;
  receipt: ReleaseArtifactReceipt;
}> {
  const payload = parseJsonRecord(payloadJson);
  if (
    !payload ||
    (
      payload.schemaVersion !== 2 &&
      payload.schemaVersion !== 3
    )
  ) {
    throw new Error(
      `Artifact publication run ${JSON.stringify(runId)} has unsupported payload schema`,
    );
  }
  const publication = parseReleaseArtifactPublication(payload.releaseArtifacts);
  const selected = observations
    .filter((observation) => observation.runId === runId)
    .map((observation) => ({
      observation,
      receipt: requiredArtifactReceipt(receipts, observation),
    }));
  const expected = buildReleaseArtifactPublication(
    selected.map(({ observation, receipt }) =>
      releaseArtifactPublicationLink(observation, receipt)),
  );
  if (canonicalJson(publication) !== canonicalJson(expected)) {
    throw new Error(
      `Artifact publication run ${JSON.stringify(runId)} does not bind its exact observation set`,
    );
  }
  const releaseTags = Array.isArray(payload.releaseTags)
    ? payload.releaseTags.filter((tag): tag is string => typeof tag === 'string')
    : [];
  if (payload.schemaVersion === 2 && (
    releaseTags.length !== publication.links.length ||
    canonicalJson([...releaseTags].sort()) !==
      canonicalJson(publication.links.map((link) => link.release.tag).sort())
  )) {
    throw new Error(
      `Artifact publication run ${JSON.stringify(runId)} does not match its score release tags`,
    );
  }
  if (payload.schemaVersion === 3) {
    const scoreMetadata = parseJsonRecord(payload.scoreMetadata);
    const predecessorByReleaseTag = parseJsonRecord(
      scoreMetadata?.predecessorByReleaseTag,
    );
    const metadataReleaseTags = Array.isArray(scoreMetadata?.releaseTags)
      ? scoreMetadata.releaseTags.filter(
        (tag): tag is string => typeof tag === 'string',
      )
      : [];
    const problems = releaseArtifactPublicationScopeLinkProblems(
      publication,
      payload.releaseArtifactScope,
    );
    if (
      !predecessorByReleaseTag ||
      canonicalJson([...metadataReleaseTags].sort()) !==
        canonicalJson([...releaseTags].sort())
    ) {
      problems.push(
        'release artifact scope has no matching durable score metadata',
      );
    } else {
      problems.push(...releaseArtifactPublicationScopeScoreProblems(
        payload.releaseArtifactScope,
        {
          scoredReleaseTags: releaseTags,
          predecessorByReleaseTag:
            predecessorByReleaseTag as Record<string, string | null>,
        },
      ));
    }
    if (problems.length > 0) {
      throw new Error(
        `Artifact publication run ${JSON.stringify(runId)} has invalid scope: ` +
        `${[...new Set(problems)].join('; ')}`,
      );
    }
  } else if (database && effectiveScoringConfig) {
    const expectedScope = activeCatalogArtifactScope(
      database,
      effectiveScoringConfig,
    );
    if (
      canonicalJson([...releaseTags].sort()) !==
      canonicalJson([...expectedScope.scoredReleaseTags].sort())
    ) {
      throw new Error(
        `Legacy artifact publication run ${JSON.stringify(runId)} does not ` +
        'match the active scored release window',
      );
    }
  }
  return selected;
}

function assertArtifactReleaseCoverage(
  database: ScoreSourceIdentityDatabase,
  selected: Array<{
    observation: ReleaseArtifactObservation;
    receipt: ReleaseArtifactReceipt;
  }>,
  effectiveScoringConfig: ScoreEffectiveScoringConfig,
): void {
  const expectedScope = activeCatalogArtifactScope(
    database,
    effectiveScoringConfig,
  );
  const expectedTags = [
    ...expectedScope.scoredReleaseTags,
    ...expectedScope.dependencyReleaseTags,
  ].sort();
  const selectedTags = selected.map(({ receipt }) => receipt.release.tag).sort();
  if (
    new Set(selectedTags).size !== selectedTags.length ||
    canonicalJson(expectedTags) !== canonicalJson(selectedTags)
  ) {
    throw new Error(
      'Artifact verification set does not exactly cover the active ' +
      'scored/dependency release scope',
    );
  }
}

function activeCatalogArtifactScope(
  database: ScoreSourceIdentityDatabase,
  effectiveScoringConfig: ScoreEffectiveScoringConfig,
): ReleaseArtifactPublicationScope {
  const activeRows = queryScoreSourceRows(database, {
    source: 'release_artifact_receipts',
    table: 'releases',
    columns: ['tag'],
    orderBy: ['catalog_rank', 'tag'],
    where: 'catalog_active=1 AND prerelease=0',
  });
  const activeTags = activeRows.map((row) =>
    requiredString(row.tag, 'active release tag'));
  const scoredReleaseTags = activeTags.slice(
    0,
    effectiveScoringConfig.monitoredReleaseLimit,
  );
  const predecessorByReleaseTag: Record<string, string | null> = {};
  for (const tag of scoredReleaseTags) {
    const index = activeTags.indexOf(tag);
    predecessorByReleaseTag[tag] = activeTags[index + 1] ?? null;
  }
  return buildReleaseArtifactPublicationScope({
    scoredReleaseTags,
    predecessorByReleaseTag,
  });
}

function requiredArtifactReceipt(
  receipts: Map<string, ReleaseArtifactReceipt>,
  observation: ReleaseArtifactObservation,
): ReleaseArtifactReceipt {
  const receipt = receipts.get(observation.receiptId);
  if (!receipt) {
    throw new Error(
      `Artifact observation ${observation.observationId} references a missing receipt`,
    );
  }
  releaseArtifactPublicationLink(observation, receipt);
  return receipt;
}

function queryScoreSourceRows(
  database: ScoreSourceIdentityDatabase,
  spec: ScoreSourceTableSpec,
): Record<string, unknown>[] {
  const statement = database.prepare(selectSql(spec));
  return [...statementRows(statement, spec.source)].map((row, index) =>
    asRecord(row, spec.source, index));
}

function parseJsonRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value === 'string') {
    try {
      return parseJsonRecord(JSON.parse(value));
    } catch {
      return null;
    }
  }
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function canonicalRunId(value: string): string {
  if (!value || value.trim() !== value) {
    throw new Error('Artifact observation run ID must be canonical');
  }
  return value;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`${label} is missing or noncanonical`);
  }
  return value;
}

function requiredGitOid(value: unknown, label: string): string {
  const oid = requiredString(value, label);
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(oid)) {
    throw new Error(`${label} is malformed`);
  }
  return oid;
}

function canonicalTimestamp(value: unknown, label: string): string {
  const timestamp = requiredString(value, label);
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) throw new Error(`${label} is invalid`);
  return new Date(parsed).toISOString();
}

function sourceIdentityForTable(
  database: ScoreSourceIdentityDatabase,
  source: ScoreSourceTableSpec,
): ScoreSourceIdentitySource {
  const statement = database.prepare(selectSql(source));
  const rows = statementRows(statement, source.source);

  const hash = createHash(ALGORITHM);
  updateHashLine(hash, ['source_columns', source.source, source.table, source.columns]);
  updateHashLine(hash, ['source_order', source.source, source.table, source.orderBy]);

  let count = 0;
  for (const row of rows) {
    const index = count++;
    const rowObject = asRecord(row, source.source, index);
    const values = source.columns.map((column) => normalizeColumnValue(rowObject, source.source, index, column));
    updateHashLine(hash, ['row', source.source, source.table, values]);
  }

  return {
    source: source.source,
    count,
    digest: hash.digest('hex'),
  };
}

function statementRows(
  statement: ScoreSourceIdentityStatement,
  source: ScoreSourceIdentitySourceName,
): Iterable<unknown> {
  if (typeof statement.iterate === 'function') {
    const rows = statement.iterate();
    if (!rows || typeof rows[Symbol.iterator] !== 'function') {
      throw new TypeError(`Malformed query result for ${source}: expected iterable from iterate()`);
    }
    return rows;
  }
  if (typeof statement.all === 'function') {
    const rows = statement.all();
    if (!Array.isArray(rows)) {
      throw new TypeError(`Malformed query result for ${source}: expected array from all()`);
    }
    return rows;
  }
  throw new TypeError(`Malformed statement for ${source}: expected iterate() or all()`);
}

function selectSql(source: ScoreSourceTableSpec): string {
  const columns = source.columns.map(quoteIdentifier).join(', ');
  const orderBy = source.orderBy.map(quoteIdentifier).join(', ');
  const where = source.where ? ` WHERE ${source.where}` : '';
  return `SELECT ${columns} FROM ${quoteIdentifier(source.table)}${where} ORDER BY ${orderBy}`;
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
