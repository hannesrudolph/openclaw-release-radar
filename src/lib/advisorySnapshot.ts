import { createHash } from 'node:crypto';
import {
  compareVersions,
  firstPatchedVersion,
  matchesRange,
  rangeValidationError,
} from './versionMatch';
import type {
  GhAdvisory,
  GhAdvisoryReconciliationInputs,
  GhAdvisorySourceObservations,
  GhRepositoryAdvisoryCatalogObservation,
  GhSecurityVulnerabilityCatalogObservation,
  GhSecurityVulnerabilityRangeObservation,
  GhSourceRetrievalWindow,
} from './github';
import {
  operationCaptureReceiptSemanticIdentity,
} from './operationReceiptIdentity';
import { repositoryAdvisoryCatalogContentDigest } from './advisoryCatalogDigest';

export const ADVISORY_SNAPSHOT_META_KEY = 'advisory_snapshot_last_run';
export const ADVISORY_SNAPSHOT_META_SCHEMA_VERSION = 1;
export const ADVISORY_SNAPSHOT_V2_META_KEY = 'advisory_snapshot_v2_last_run';
const NORMALIZED_ADVISORY_SEVERITIES = new Set([
  'low',
  'medium',
  'high',
  'critical',
]);

export interface AdvisorySnapshotContentRow {
  advisory_key: string;
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: string;
  html_url: string;
  published_at: string | null;
  package_ecosystem: string | null;
  package_name: string | null;
  vulnerable_version_range: string | null;
  patched_versions: string | null;
}

export interface ExpectedAdvisoryPackage {
  ecosystem: string;
  packageName: string;
}

export const DEFAULT_EXPECTED_ADVISORY_PACKAGE: ExpectedAdvisoryPackage = {
  ecosystem: 'npm',
  packageName: 'openclaw',
};

export interface AdvisorySnapshotRowProblem {
  code:
    | 'malformed_row'
    | 'package_mismatch'
    | 'advisory_key_mismatch'
    | 'duplicate_canonical_identity';
  advisoryKey: string;
  detail: string;
}

export interface AdvisorySnapshotCompletenessMetadata {
  schemaVersion: typeof ADVISORY_SNAPSHOT_META_SCHEMA_VERSION;
  source: 'github-security-vulnerabilities';
  sourceOrder: 'UPDATED_AT_ASC' | 'UPDATED_AT_DESC';
  ecosystem: string;
  packageName: string;
  capturedAt: string;
  exhausted: boolean;
  stabilized: boolean;
  totalCount: number;
  nodeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  sourceDigest: string;
  advisoryCount: number;
  activeAdvisoryCount: number;
  withdrawnAdvisoryCount: number;
  rowCount: number;
  contentDigest: string;
}

export interface AdvisorySnapshotCompletenessProblem {
  code:
    | 'missing_metadata'
    | 'invalid_metadata'
    | 'package_mismatch'
    | 'incomplete_sweep'
    | 'count_mismatch'
    | 'digest_mismatch'
    | 'row_problem';
  detail: string;
}

export function advisoryVulnerabilityKey(
  ghsaId: string,
  ecosystem: string | null,
  packageName: string | null,
  vulnerableVersionRange: string | null,
): string {
  return [
    ghsaId,
    String(ecosystem ?? '').toLowerCase(),
    String(packageName ?? '').toLowerCase(),
    String(vulnerableVersionRange ?? ''),
  ].map((part) => encodeURIComponent(part)).join(':');
}

export function advisorySnapshotContentHash(rows: AdvisorySnapshotContentRow[]): string {
  const ordered = rows.slice().sort((left, right) =>
    Buffer.compare(Buffer.from(left.advisory_key, 'utf8'), Buffer.from(right.advisory_key, 'utf8')));
  return createHash('sha256')
    .update(JSON.stringify(ordered.map((row) => [
      row.advisory_key,
      row.ghsa_id,
      row.cve_id,
      row.summary,
      row.severity,
      row.html_url,
      row.published_at,
      row.package_ecosystem,
      row.package_name,
      row.vulnerable_version_range,
      row.patched_versions,
    ])))
    .digest('hex');
}

export function advisorySnapshotRowProblems(
  rows: AdvisorySnapshotContentRow[],
  expected: ExpectedAdvisoryPackage,
): AdvisorySnapshotRowProblem[] {
  const expectedEcosystem = expected.ecosystem.trim().toLowerCase();
  const expectedPackageName = expected.packageName.trim().toLowerCase();
  const seenCanonicalIdentities = new Set<string>();
  const problems: AdvisorySnapshotRowProblem[] = [];

  for (const row of rows) {
    const advisoryKey = String(row.advisory_key ?? '');
    const ghsaId = String(row.ghsa_id ?? '').trim();
    const ecosystem = String(row.package_ecosystem ?? '').trim().toLowerCase();
    const packageName = String(row.package_name ?? '').trim().toLowerCase();
    const vulnerableVersionRange = String(row.vulnerable_version_range ?? '');
    const severity = String(row.severity ?? '');
    if (!advisoryKey || !ghsaId || !String(row.summary ?? '').trim() ||
      !severity.trim() || !String(row.html_url ?? '').trim() ||
      !vulnerableVersionRange.trim()) {
      problems.push({
        code: 'malformed_row',
        advisoryKey,
        detail: 'required advisory snapshot fields are missing',
      });
      continue;
    }
    if (!NORMALIZED_ADVISORY_SEVERITIES.has(severity)) {
      problems.push({
        code: 'malformed_row',
        advisoryKey,
        detail: `invalid_severity:${JSON.stringify(severity)}; expected low, medium, high, or critical`,
      });
    }

    const rangeError = rangeValidationError(vulnerableVersionRange);
    if (rangeError) {
      problems.push({
        code: 'malformed_row',
        advisoryKey,
        detail: `malformed_vulnerable_range:${rangeError}`,
      });
    }

    if (row.patched_versions != null) {
      const patch = firstPatchedVersion(row.patched_versions);
      if (!patch) {
        problems.push({
          code: 'malformed_row',
          advisoryKey,
          detail: `malformed_patch_metadata:could not identify a first patched version from ` +
            `${JSON.stringify(row.patched_versions)}`,
        });
      } else if (!rangeError && matchesRange(patch, vulnerableVersionRange)) {
        problems.push({
          code: 'malformed_row',
          advisoryKey,
          detail: `patched_version_still_vulnerable:${patch} satisfies ` +
            `${JSON.stringify(vulnerableVersionRange)}`,
        });
      }
    }

    if (ecosystem !== expectedEcosystem || packageName !== expectedPackageName) {
      problems.push({
        code: 'package_mismatch',
        advisoryKey,
        detail: `${ecosystem || 'missing'}/${packageName || 'missing'} != ` +
          `${expectedEcosystem}/${expectedPackageName}`,
      });
    }

    const canonicalKey = advisoryVulnerabilityKey(
      ghsaId,
      ecosystem,
      packageName,
      vulnerableVersionRange,
    );
    if (advisoryKey !== canonicalKey) {
      problems.push({
        code: 'advisory_key_mismatch',
        advisoryKey,
        detail: `expected ${canonicalKey}`,
      });
    }
    if (seenCanonicalIdentities.has(canonicalKey)) {
      problems.push({
        code: 'duplicate_canonical_identity',
        advisoryKey,
        detail: canonicalKey,
      });
    }
    seenCanonicalIdentities.add(canonicalKey);
  }

  return problems;
}

export function advisorySnapshotCompletenessProblems(
  metadata: unknown,
  rows: AdvisorySnapshotContentRow[],
  expected: ExpectedAdvisoryPackage,
): AdvisorySnapshotCompletenessProblem[] {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return [{ code: 'missing_metadata', detail: 'advisory snapshot completeness metadata is missing' }];
  }

  const value = metadata as Partial<AdvisorySnapshotCompletenessMetadata>;
  const problems: AdvisorySnapshotCompletenessProblem[] = [];
  const expectedEcosystem = expected.ecosystem.trim().toLowerCase();
  const expectedPackageName = expected.packageName.trim().toLowerCase();
  const ecosystem = String(value.ecosystem ?? '').trim().toLowerCase();
  const packageName = String(value.packageName ?? '').trim().toLowerCase();
  const integerFields: Array<keyof AdvisorySnapshotCompletenessMetadata> = [
    'totalCount',
    'nodeCount',
    'pageCount',
    'pagesFetched',
    'sweepCount',
    'advisoryCount',
    'activeAdvisoryCount',
    'withdrawnAdvisoryCount',
    'rowCount',
  ];
  const validIntegerFields = integerFields.every((field) =>
    Number.isInteger(value[field]) && Number(value[field]) >= 0);

  if (
    value.schemaVersion !== ADVISORY_SNAPSHOT_META_SCHEMA_VERSION ||
    value.source !== 'github-security-vulnerabilities' ||
    !['UPDATED_AT_ASC', 'UPDATED_AT_DESC'].includes(String(value.sourceOrder)) ||
    typeof value.capturedAt !== 'string' ||
    !Number.isFinite(Date.parse(value.capturedAt)) ||
    typeof value.sourceDigest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.sourceDigest) ||
    typeof value.contentDigest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.contentDigest)
  ) {
    problems.push({
      code: 'invalid_metadata',
      detail: 'schema, source, timestamp, or digest fields are invalid',
    });
  }
  for (const field of integerFields) {
    const count = value[field];
    if (!Number.isInteger(count) || Number(count) < 0) {
      problems.push({
        code: 'invalid_metadata',
        detail: `${String(field)} must be a non-negative integer`,
      });
    }
  }
  if (ecosystem !== expectedEcosystem || packageName !== expectedPackageName) {
    problems.push({
      code: 'package_mismatch',
      detail: `${ecosystem || 'missing'}/${packageName || 'missing'} != ` +
        `${expectedEcosystem}/${expectedPackageName}`,
    });
  }
  if (
    value.exhausted !== true ||
    value.stabilized !== true ||
    !Number.isInteger(value.sweepCount) ||
    Number(value.sweepCount) < 2
  ) {
    problems.push({
      code: 'incomplete_sweep',
      detail: 'advisory pagination must be exhausted and stable across two consecutive sweeps',
    });
  }
  const countMismatches: string[] = [];
  if (validIntegerFields) {
    const totalCount = Number(value.totalCount);
    const nodeCount = Number(value.nodeCount);
    const pageCount = Number(value.pageCount);
    const pagesFetched = Number(value.pagesFetched);
    const sweepCount = Number(value.sweepCount);
    const advisoryCount = Number(value.advisoryCount);
    const activeAdvisoryCount = Number(value.activeAdvisoryCount);
    const withdrawnAdvisoryCount = Number(value.withdrawnAdvisoryCount);
    const rowCount = Number(value.rowCount);

    if (nodeCount !== totalCount) {
      countMismatches.push(`nodeCount ${nodeCount} != totalCount ${totalCount}`);
    }
    if (rowCount !== rows.length) {
      countMismatches.push(`rowCount ${rowCount} != persisted rows ${rows.length}`);
    }
    if (rowCount !== activeAdvisoryCount) {
      countMismatches.push(
        `rowCount ${rowCount} != activeAdvisoryCount ${activeAdvisoryCount}`,
      );
    }
    if (activeAdvisoryCount + withdrawnAdvisoryCount !== advisoryCount) {
      countMismatches.push(
        `activeAdvisoryCount ${activeAdvisoryCount} + withdrawnAdvisoryCount ` +
          `${withdrawnAdvisoryCount} != advisoryCount ${advisoryCount}`,
      );
    }
    if (advisoryCount > nodeCount || (nodeCount > 0 && advisoryCount === 0)) {
      countMismatches.push(
        `advisoryCount ${advisoryCount} is impossible for nodeCount ${nodeCount}`,
      );
    }
    if (pageCount < 1) {
      countMismatches.push(`pageCount ${pageCount} must include the completed fetch page`);
    }
    const minimumPagesFetched = sweepCount >= 2
      ? (2 * pageCount) + Math.max(0, sweepCount - 2)
      : pageCount;
    if (pagesFetched < minimumPagesFetched) {
      countMismatches.push(
        `pagesFetched ${pagesFetched} < minimum ${minimumPagesFetched} for ` +
          `pageCount ${pageCount} and sweepCount ${sweepCount}`,
      );
    }
  }
  if (countMismatches.length > 0) {
    problems.push({
      code: 'count_mismatch',
      detail: countMismatches.join('; '),
    });
  }

  const contentDigest = advisorySnapshotContentHash(rows);
  if (value.contentDigest !== contentDigest) {
    problems.push({
      code: 'digest_mismatch',
      detail: `contentDigest ${String(value.contentDigest ?? 'missing')} != ${contentDigest}`,
    });
  }
  for (const rowProblem of advisorySnapshotRowProblems(rows, expected)) {
    problems.push({
      code: 'row_problem',
      detail: `${rowProblem.code}:${rowProblem.advisoryKey}:${rowProblem.detail}`,
    });
  }
  return problems;
}

export const COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION = 2;
export const COMPOUND_ADVISORY_AUTHORITY_POLICY_SCHEMA_VERSION = 1;
export const COMPOUND_ADVISORY_AUTHORITY_POLICY = {
  schemaVersion: COMPOUND_ADVISORY_AUTHORITY_POLICY_SCHEMA_VERSION,
  name: 'graphql_global_with_complete_repository_fallback',
} as const;

export interface CompoundAdvisoryAuthorityPolicy {
  schemaVersion: typeof COMPOUND_ADVISORY_AUTHORITY_POLICY_SCHEMA_VERSION;
  name: typeof COMPOUND_ADVISORY_AUTHORITY_POLICY.name;
}

export type CompoundAdvisorySource =
  | 'graphql-security-vulnerabilities'
  | 'repository-security-advisories-rest'
  | 'compound-reconciliation';

export interface AdvisoryRepositoryIdentity {
  owner: string;
  name: string;
  url: string;
}

export interface CompoundAdvisorySnapshotInput {
  capturedAt: string;
  repository: AdvisoryRepositoryIdentity;
  target?: ExpectedAdvisoryPackage;
  authorityPolicy?: CompoundAdvisoryAuthorityPolicy | null;
  observations?: GhAdvisorySourceObservations;
  sources?: {
    graphql: GhSecurityVulnerabilityCatalogObservation;
    repositoryRest: GhRepositoryAdvisoryCatalogObservation;
  };
  graphql?: GhSecurityVulnerabilityCatalogObservation;
  repositoryRest?: GhRepositoryAdvisoryCatalogObservation;
  reconciliation?: GhAdvisoryReconciliationInputs | null;
}

export type CompoundAdvisoryProblemCode =
  | 'invalid_snapshot_input'
  | 'invalid_repository_identity'
  | 'invalid_source_observation'
  | 'incomplete_graphql_source'
  | 'unproven_repository_completeness'
  | 'count_mismatch'
  | 'digest_mismatch'
  | 'duplicate_source_advisory'
  | 'conflicting_source_advisory_metadata'
  | 'duplicate_source_range'
  | 'overlapping_source_ranges'
  | 'wrong_repository_url'
  | 'malformed_target_range'
  | 'malformed_foreign_range'
  | 'malformed_target_patch'
  | 'malformed_foreign_patch'
  | 'missing_reconciliation'
  | 'conflicting_reconciliation'
  | 'declared_reconciliation_mismatch'
  | 'withdrawn_state_conflict';

export interface CompoundAdvisorySnapshotProblem {
  code: CompoundAdvisoryProblemCode;
  severity: 'blocking' | 'audit';
  source: CompoundAdvisorySource;
  rangeIdentity: string | null;
  detail: string;
}

export interface CompoundAdvisorySourceCounts {
  advisoryCount: number;
  activeAdvisoryCount: number;
  withdrawnAdvisoryCount: number;
  otherStateAdvisoryCount: number;
  rangeCount: number;
  activeRangeCount: number;
  withdrawnRangeCount: number;
  otherStateRangeCount: number;
  packageCount: number;
  targetRangeCount: number;
  foreignRangeCount: number;
}

export interface CompoundAdvisoryPaginationProof {
  exhausted: boolean;
  stabilized: boolean;
  completenessProven: boolean;
  totalCount: number | null;
  nodeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  terminalPageEvidence:
    | 'graphql-total-count'
    | 'link-exhausted'
    | 'unproven-no-link';
}

export interface CompoundAdvisorySourceSnapshot<T> {
  source: Exclude<CompoundAdvisorySource, 'compound-reconciliation'>;
  observation: T;
  counts: CompoundAdvisorySourceCounts;
  pagination: CompoundAdvisoryPaginationProof;
}

export type CompoundAdvisoryRangeState =
  | 'active'
  | 'withdrawn'
  | 'other'
  | 'conflicted';

export interface CompoundAdvisoryRangeSourceObservation {
  source: Exclude<CompoundAdvisorySource, 'compound-reconciliation'>;
  state: Exclude<CompoundAdvisoryRangeState, 'conflicted'>;
  repositoryOwned: boolean;
  firstPatchedVersion: string | null;
  patchedVersions: string | null;
  updatedAt: string | null;
}

export interface CompoundAdvisoryRangeRow {
  identity: string;
  ghsaId: string;
  ecosystem: string;
  packageName: string;
  vulnerableVersionRange: string;
  targetPackage: boolean;
  repositoryOwned: boolean;
  packageGlobalOnly: boolean;
  state: CompoundAdvisoryRangeState;
  scoreEligible: boolean;
  auditOnly: boolean;
  sourceObservations: CompoundAdvisoryRangeSourceObservation[];
  advisory: {
    cveId: string | null;
    summary: string;
    severity: GhAdvisory['severity'];
    state: GhAdvisory['state'];
    publishedAt: string | null;
    withdrawnAt: string | null;
    htmlUrl: string;
  } | null;
}

export interface CompoundAdvisoryCatalogCounts {
  advisoryCount: number;
  activeAdvisoryCount: number;
  withdrawnAdvisoryCount: number;
  otherStateAdvisoryCount: number;
  rangeCount: number;
  activeRangeCount: number;
  withdrawnRangeCount: number;
  otherStateRangeCount: number;
  packageCount: number;
  targetRangeCount: number;
  foreignRangeCount: number;
  sourceObservationCount: number;
  scoreEligibleRangeCount: number;
}

export interface CompoundAdvisoryReconciliation {
  status: 'reconciled' | 'divergent' | 'blocked';
  declared: boolean;
  restActiveTargetRangeCount: number;
  restWithdrawnTargetRangeCount: number;
  reconciledRangeCount: number;
  missingRangeIdentities: string[];
  conflictingRangeIdentities: string[];
  additionalGraphqlRangeIdentities: string[];
  contentHash: string;
}

export interface CompoundAdvisoryScoreProjection {
  ready: boolean;
  rangeCount: number;
  rangeIdentities: string[];
  rows: CompoundAdvisoryRangeRow[];
  hash: string;
}

export interface CompoundAdvisorySnapshot {
  schemaVersion: typeof COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION;
  authorityPolicy?: CompoundAdvisoryAuthorityPolicy;
  capturedAt: string;
  repository: AdvisoryRepositoryIdentity;
  target: ExpectedAdvisoryPackage;
  sourceObservations: {
    graphql: CompoundAdvisorySourceSnapshot<GhSecurityVulnerabilityCatalogObservation>;
    repositoryRest: CompoundAdvisorySourceSnapshot<GhRepositoryAdvisoryCatalogObservation>;
  };
  counts: CompoundAdvisoryCatalogCounts;
  rows: CompoundAdvisoryRangeRow[];
  reconciliation: CompoundAdvisoryReconciliation;
  problems: CompoundAdvisorySnapshotProblem[];
  blockingProblems: CompoundAdvisorySnapshotProblem[];
  auditProblems: CompoundAdvisorySnapshotProblem[];
  hashes: {
    sourceHash: string;
    catalogHash: string;
    scoreHash: string;
  };
  sourceHash: string;
  catalogHash: string;
  scoreHash: string;
  score: CompoundAdvisoryScoreProjection;
}

export interface CompoundAdvisorySnapshotMetadata {
  schemaVersion: typeof COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION;
  snapshotId: number;
  capturedAt: string;
  repository: AdvisoryRepositoryIdentity;
  target: ExpectedAdvisoryPackage;
  sourceHash: string;
  catalogHash: string;
  scoreHash: string;
  contentHash: string;
  previousContentHash: string | null;
  rowCount: number;
  scoreRowCount: number;
  scoreReady: true;
  scoreContentDigest: string;
}

export function compoundAdvisorySnapshotMetadataDigest(
  metadata: CompoundAdvisorySnapshotMetadata,
): string {
  return createHash('sha256')
    .update(canonicalJson(metadata))
    .digest('hex');
}

export function compoundAdvisoryReceiptBindingProblems(
  value: unknown,
  expected: CompoundAdvisorySnapshotMetadata,
): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return ['advisory catalog receipt binding is missing'];
  }
  const catalog = value as Record<string, unknown>;
  const metadata =
    catalog.metadata && typeof catalog.metadata === 'object' &&
      !Array.isArray(catalog.metadata)
      ? catalog.metadata as Record<string, unknown>
      : null;
  const problems: string[] = [];
  if (catalog.metaKey !== ADVISORY_SNAPSHOT_V2_META_KEY) {
    problems.push('meta key does not identify advisory snapshot v2');
  }
  if (!metadata || canonicalJson(metadata) !== canonicalJson(expected)) {
    problems.push('metadata does not match the immutable advisory snapshot');
  }
  if (catalog.metadataDigest !== compoundAdvisorySnapshotMetadataDigest(expected)) {
    problems.push('metadata digest does not match the immutable advisory snapshot');
  }
  if (catalog.snapshotId !== expected.snapshotId) {
    problems.push('snapshot id does not match the immutable advisory snapshot');
  }
  if (catalog.sourceHash !== expected.sourceHash) {
    problems.push('source hash does not match the immutable advisory snapshot');
  }
  if (catalog.catalogHash !== expected.catalogHash) {
    problems.push('catalog hash does not match the immutable advisory snapshot');
  }
  if (catalog.scoreHash !== expected.scoreHash) {
    problems.push('score hash does not match the immutable advisory snapshot');
  }
  if (catalog.contentHash !== expected.contentHash) {
    problems.push('ledger content hash does not match the immutable advisory snapshot');
  }
  if (catalog.contentDigest !== expected.scoreContentDigest) {
    problems.push('score content digest does not match the immutable advisory snapshot');
  }
  if (Number(catalog.advisoryCount) !== expected.scoreRowCount) {
    problems.push('advisory count does not match the score projection');
  }
  if (Number(catalog.rowCount) !== expected.scoreRowCount) {
    problems.push('row count does not match the score projection');
  }
  if (Number(catalog.catalogRowCount) !== expected.rowCount) {
    problems.push('catalog row count does not match the immutable advisory snapshot');
  }
  if (Number(catalog.scoreRowCount) !== expected.scoreRowCount) {
    problems.push('score row count does not match the score projection');
  }
  return problems;
}

export interface CompoundAdvisoryPublicationAttempt {
  runId: string;
  startedAt: string;
}

export interface CompoundAdvisoryPublicationReceipt {
  receiptId: string;
  runId: string;
  status: string;
  finishedAt: string;
  durationMs: number;
  stageEventCount: number;
  stageChainHash: string | null;
  payloadJson: string;
}

export interface CompoundAdvisorySnapshotPublicationAuthorization {
  schemaVersion: 1;
  snapshotId: number;
  metadataDigest: string;
  receiptId: string;
  runId: string;
  receiptSemanticIdentity: string;
  operationStartedAt: string;
  finishedAt: string;
}

export interface CompoundAdvisorySnapshotPublicationAuthorizationReport {
  authorizations: CompoundAdvisorySnapshotPublicationAuthorization[];
  authorizedSnapshotIds: number[];
  stagedSnapshotIds: number[];
  problems: string[];
}

export const COMPOUND_ADVISORY_AUDIT_PROJECTION_SCHEMA_VERSION = 1;
export const COMPOUND_ADVISORY_AUDIT_SOURCE_MODE =
  'receipt_authorized_compound_advisory_v2' as const;

export interface CompoundAdvisorySnapshotAuditProjectionInput {
  snapshots: Array<{ metadata: CompoundAdvisorySnapshotMetadata }>;
  activeMetadata: CompoundAdvisorySnapshotMetadata | null;
  integrityProblems?: string[];
  activeProjectionProblems?: string[];
  attempts: CompoundAdvisoryPublicationAttempt[];
  receipts: CompoundAdvisoryPublicationReceipt[];
  operationLedgerProblems?: string[];
}

export interface CompoundAdvisorySnapshotAuditProjection {
  schemaVersion: typeof COMPOUND_ADVISORY_AUDIT_PROJECTION_SCHEMA_VERSION;
  sourceMode: typeof COMPOUND_ADVISORY_AUDIT_SOURCE_MODE;
  verified: boolean;
  snapshotCount: number;
  latestSnapshotId: number | null;
  activeSnapshotId: number | null;
  activeMetadata: CompoundAdvisorySnapshotMetadata | null;
  activeMetadataDigest: string | null;
  activeContentHash: string | null;
  activeScoreContentDigest: string | null;
  activeRowCount: number | null;
  activeScoreRowCount: number | null;
  activeProjectionVerified: boolean;
  authorizingReceipt: CompoundAdvisorySnapshotPublicationAuthorization | null;
  authorizedSnapshotIds: number[];
  authorizedSnapshotCount: number;
  stagedSnapshotIds: number[];
  stagedSnapshotCount: number;
  integrityProblems: string[];
  activeProjectionProblems: string[];
  operationLedgerProblems: string[];
  authorizationProblems: string[];
  problems: string[];
  failedCount: number;
}

function normalizedAdvisoryAuditProblems(
  problems: readonly string[] | undefined,
): string[] {
  return [...new Set(
    (problems ?? [])
      .filter((problem): problem is string => typeof problem === 'string')
      .map((problem) => problem.trim())
      .filter(Boolean),
  )].sort();
}

export function buildCompoundAdvisorySnapshotAuditProjection(
  input: CompoundAdvisorySnapshotAuditProjectionInput,
): CompoundAdvisorySnapshotAuditProjection {
  const operationLedgerProblems = normalizedAdvisoryAuditProblems(
    input.operationLedgerProblems,
  );
  const authorization = compoundAdvisorySnapshotPublicationAuthorizations({
    snapshots: input.snapshots,
    attempts: input.attempts,
    receipts: input.receipts,
    operationLedgerProblems,
  });
  const activeMetadata = input.activeMetadata;
  const activeSnapshotId = activeMetadata?.snapshotId ?? null;
  const snapshotIds = input.snapshots
    .map(({ metadata }) => metadata.snapshotId)
    .filter((snapshotId) =>
      Number.isSafeInteger(snapshotId) && snapshotId > 0);
  const latestSnapshotId = snapshotIds.length > 0
    ? Math.max(...snapshotIds)
    : null;
  const matchingActiveMetadata = activeSnapshotId == null
    ? []
    : input.snapshots.filter(
        ({ metadata }) => metadata.snapshotId === activeSnapshotId,
      );
  const activeProjectionProblems = normalizedAdvisoryAuditProblems([
    ...(input.activeProjectionProblems ?? []),
    ...(activeMetadata == null
      ? ['active advisory snapshot v2 metadata is missing']
      : []),
    ...(activeMetadata != null && matchingActiveMetadata.length !== 1
      ? [
          `active advisory snapshot v2 ${activeSnapshotId} must identify ` +
          'exactly one immutable snapshot',
        ]
      : []),
    ...(
      activeMetadata != null &&
      matchingActiveMetadata.length === 1 &&
      canonicalJson(matchingActiveMetadata[0].metadata) !==
        canonicalJson(activeMetadata)
        ? [
            `active advisory snapshot v2 ${activeSnapshotId} metadata does ` +
            'not match its immutable ledger entry',
          ]
        : []
    ),
  ]);
  const activeAuthorizations = activeSnapshotId == null
    ? []
    : authorization.authorizations.filter(
        (candidate) => candidate.snapshotId === activeSnapshotId,
      );
  const authorizationProblems = normalizedAdvisoryAuditProblems([
    ...authorization.problems.filter(
      (problem) => !problem.startsWith('operation receipt ledger: '),
    ),
    ...(activeSnapshotId != null && activeAuthorizations.length !== 1
      ? [
          `active advisory snapshot v2 ${activeSnapshotId} must have ` +
          'exactly one successful receipt authorization',
        ]
      : []),
  ]);
  const integrityProblems = normalizedAdvisoryAuditProblems(
    input.integrityProblems,
  );
  const activeProjectionVerified =
    activeMetadata != null && activeProjectionProblems.length === 0;
  const authorizingReceipt =
    activeAuthorizations.length === 1 ? activeAuthorizations[0] : null;
  const problems = normalizedAdvisoryAuditProblems([
    ...integrityProblems.map((problem) => `integrity: ${problem}`),
    ...activeProjectionProblems.map(
      (problem) => `active projection: ${problem}`,
    ),
    ...operationLedgerProblems.map(
      (problem) => `operation receipt ledger: ${problem}`,
    ),
    ...authorizationProblems.map(
      (problem) => `publication authorization: ${problem}`,
    ),
  ]);
  return {
    schemaVersion: COMPOUND_ADVISORY_AUDIT_PROJECTION_SCHEMA_VERSION,
    sourceMode: COMPOUND_ADVISORY_AUDIT_SOURCE_MODE,
    verified: problems.length === 0,
    snapshotCount: input.snapshots.length,
    latestSnapshotId,
    activeSnapshotId,
    activeMetadata,
    activeMetadataDigest: activeMetadata
      ? compoundAdvisorySnapshotMetadataDigest(activeMetadata)
      : null,
    activeContentHash: activeMetadata?.contentHash ?? null,
    activeScoreContentDigest: activeMetadata?.scoreContentDigest ?? null,
    activeRowCount: activeMetadata?.rowCount ?? null,
    activeScoreRowCount: activeMetadata?.scoreRowCount ?? null,
    activeProjectionVerified,
    authorizingReceipt,
    authorizedSnapshotIds: authorization.authorizedSnapshotIds,
    authorizedSnapshotCount: authorization.authorizedSnapshotIds.length,
    stagedSnapshotIds: authorization.stagedSnapshotIds,
    stagedSnapshotCount: authorization.stagedSnapshotIds.length,
    integrityProblems,
    activeProjectionProblems,
    operationLedgerProblems,
    authorizationProblems,
    problems,
    failedCount: problems.length,
  };
}

export function compoundAdvisorySnapshotPublicationAuthorizations(input: {
  snapshots: Array<{ metadata: CompoundAdvisorySnapshotMetadata }>;
  attempts: CompoundAdvisoryPublicationAttempt[];
  receipts: CompoundAdvisoryPublicationReceipt[];
  operationLedgerProblems?: string[];
}): CompoundAdvisorySnapshotPublicationAuthorizationReport {
  const operationLedgerProblems = input.operationLedgerProblems ?? [];
  if (operationLedgerProblems.length > 0) {
    return {
      authorizations: [],
      authorizedSnapshotIds: [],
      stagedSnapshotIds: input.snapshots
        .map((snapshot) => snapshot.metadata.snapshotId)
        .sort((left, right) => left - right),
      problems: operationLedgerProblems.map(
        (problem) => `operation receipt ledger: ${problem}`,
      ),
    };
  }

  const problems: string[] = [];
  const snapshotsById = new Map<number, CompoundAdvisorySnapshotMetadata>();
  for (const { metadata } of input.snapshots) {
    if (snapshotsById.has(metadata.snapshotId)) {
      problems.push(
        `duplicate advisory snapshot v2 metadata for snapshot ${metadata.snapshotId}`,
      );
      continue;
    }
    snapshotsById.set(metadata.snapshotId, metadata);
  }
  const attemptsByRun = new Map<string, CompoundAdvisoryPublicationAttempt>();
  for (const attempt of input.attempts) {
    if (attemptsByRun.has(attempt.runId)) {
      problems.push(
        `duplicate refresh operation attempt for run ${JSON.stringify(attempt.runId)}`,
      );
      continue;
    }
    attemptsByRun.set(attempt.runId, attempt);
  }

  const authorizations: CompoundAdvisorySnapshotPublicationAuthorization[] = [];
  const authorizedBySnapshot = new Map<
    number,
    CompoundAdvisorySnapshotPublicationAuthorization
  >();
  for (const receipt of input.receipts) {
    if (receipt.status !== 'success') continue;
    let payload: Record<string, unknown> | null = null;
    try {
      const parsed = JSON.parse(receipt.payloadJson) as unknown;
      payload = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : null;
    } catch {
      payload = null;
    }
    if (!payload) {
      problems.push(
        `successful refresh receipt ${JSON.stringify(receipt.receiptId)} ` +
        'has malformed payload JSON',
      );
      continue;
    }
    const payloadSchemaVersion = Number(payload.schemaVersion);
    const catalog = payload.advisoryCatalog;
    if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog)) {
      if (payloadSchemaVersion >= 3) {
        problems.push(
          `schema-${payloadSchemaVersion} successful refresh receipt ` +
          `${JSON.stringify(receipt.receiptId)} has no advisory v2 binding`,
        );
      }
      continue;
    }
    const catalogRecord = catalog as Record<string, unknown>;
    if (catalogRecord.metaKey !== ADVISORY_SNAPSHOT_V2_META_KEY) {
      problems.push(
        `successful refresh receipt ${JSON.stringify(receipt.receiptId)} ` +
        'contains an unsupported advisory catalog binding',
      );
      continue;
    }
    const snapshotId = Number(catalogRecord.snapshotId);
    if (!Number.isSafeInteger(snapshotId) || snapshotId <= 0) {
      problems.push(
        `successful refresh receipt ${JSON.stringify(receipt.receiptId)} ` +
        'has no valid advisory snapshot v2 id',
      );
      continue;
    }
    const metadata = snapshotsById.get(snapshotId);
    if (!metadata) {
      problems.push(
        `successful refresh receipt ${JSON.stringify(receipt.receiptId)} ` +
        `references missing advisory snapshot v2 ${snapshotId}`,
      );
      continue;
    }
    const bindingProblems = compoundAdvisoryReceiptBindingProblems(
      catalogRecord,
      metadata,
    );
    if (bindingProblems.length > 0) {
      problems.push(
        `successful refresh receipt ${JSON.stringify(receipt.receiptId)} ` +
        `does not authorize advisory snapshot v2 ${snapshotId}: ` +
        bindingProblems.join('; '),
      );
      continue;
    }
    const attempt = attemptsByRun.get(receipt.runId);
    const startedAtMs = Date.parse(attempt?.startedAt ?? '');
    const capturedAtMs = Date.parse(metadata.capturedAt);
    const finishedAtMs = Date.parse(receipt.finishedAt);
    if (
      !attempt ||
      !Number.isFinite(startedAtMs) ||
      !Number.isFinite(capturedAtMs) ||
      !Number.isFinite(finishedAtMs) ||
      capturedAtMs < startedAtMs ||
      capturedAtMs > finishedAtMs
    ) {
      problems.push(
        `successful refresh receipt ${JSON.stringify(receipt.receiptId)} ` +
        `has invalid publication timing for advisory snapshot v2 ${snapshotId}`,
      );
      continue;
    }
    const authorization: CompoundAdvisorySnapshotPublicationAuthorization = {
      schemaVersion: 1,
      snapshotId,
      metadataDigest: compoundAdvisorySnapshotMetadataDigest(metadata),
      receiptId: receipt.receiptId,
      runId: receipt.runId,
      receiptSemanticIdentity: operationCaptureReceiptSemanticIdentity({
        receiptId: receipt.receiptId,
        runId: receipt.runId,
        status: receipt.status,
        finishedAt: receipt.finishedAt,
        durationMs: receipt.durationMs,
        stageEventCount: receipt.stageEventCount,
        stageChainHash: receipt.stageChainHash,
        payloadJson: receipt.payloadJson,
      }),
      operationStartedAt: attempt.startedAt,
      finishedAt: receipt.finishedAt,
    };
    const existing = authorizedBySnapshot.get(snapshotId);
    if (existing) {
      problems.push(
        `advisory snapshot v2 ${snapshotId} has duplicate successful receipt ` +
        `authorization from ${JSON.stringify(existing.receiptId)} and ` +
        JSON.stringify(receipt.receiptId),
      );
      continue;
    }
    authorizedBySnapshot.set(snapshotId, authorization);
    authorizations.push(authorization);
  }

  authorizations.sort((left, right) =>
    left.snapshotId - right.snapshotId ||
    left.receiptId.localeCompare(right.receiptId));
  const authorizedSnapshotIds = authorizations.map(
    (authorization) => authorization.snapshotId,
  );
  const authorizedIds = new Set(authorizedSnapshotIds);
  const stagedSnapshotIds = [...snapshotsById.keys()]
    .filter((snapshotId) => !authorizedIds.has(snapshotId))
    .sort((left, right) => left - right);
  return {
    authorizations,
    authorizedSnapshotIds,
    stagedSnapshotIds,
    problems: [...new Set(problems)],
  };
}

type CompoundAdvisoryAuthorityMode =
  | 'legacy_strict'
  | typeof COMPOUND_ADVISORY_AUTHORITY_POLICY.name;

interface LegacySecurityVulnerabilityRangeObservation {
  ghsaId: string;
  ecosystem: string;
  packageName: string;
  vulnerableVersionRange: string;
  firstPatchedVersion: string | null;
  updatedAt: string;
  identity: string;
}

interface LegacySecurityVulnerabilityCatalogObservation {
  source: 'graphql-security-vulnerabilities';
  retrieval: GhSourceRetrievalWindow;
  ecosystem: string;
  packageName: string;
  exhausted: true;
  stabilized: true;
  totalCount: number;
  nodeCount: number;
  uniqueRangeCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  digest: string;
  identityDigest: string;
  ranges: LegacySecurityVulnerabilityRangeObservation[];
  rangeIdentities: string[];
}

interface NormalizedGraphqlRangeBase {
  source: 'graphql-security-vulnerabilities';
  identity: string;
  ghsaId: string;
  state: 'active' | 'withdrawn';
  ecosystem: string;
  packageName: string;
  vulnerableVersionRange: string;
  firstPatchedVersion: string | null;
  updatedAt: string;
  validRange: boolean;
}

interface NormalizedLegacyGraphqlRange extends NormalizedGraphqlRangeBase {
  authorityShape: 'legacy';
  state: 'active';
}

interface NormalizedCurrentGraphqlRange extends NormalizedGraphqlRangeBase {
  authorityShape: 'current';
  cveId: string | null;
  summary: string;
  severity: GhAdvisory['severity'];
  htmlUrl: string;
  publishedAt: string;
  withdrawnAt: string | null;
}

type NormalizedGraphqlRange =
  | NormalizedLegacyGraphqlRange
  | NormalizedCurrentGraphqlRange;

interface NormalizedRepositoryRange {
  source: 'repository-security-advisories-rest';
  identity: string;
  ghsaId: string;
  ecosystem: string;
  packageName: string;
  vulnerableVersionRange: string;
  patchedVersions: string | null;
  state: Exclude<CompoundAdvisoryRangeState, 'conflicted'>;
  targetPackage: boolean;
  validRange: boolean;
  advisory: GhAdvisory;
}

interface VersionIntervalBound {
  version: string;
  inclusive: boolean;
}

interface VersionInterval {
  lower: VersionIntervalBound | null;
  upper: VersionIntervalBound | null;
}

const VERSION_TOKEN_SOURCE_V2 =
  String.raw`[vV]?\d+(?:\.\d+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?` +
  String.raw`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?`;
const RANGE_CLAUSE_RE_V2 = new RegExp(
  `(<=|>=|<|>|==?)?\\s*(${VERSION_TOKEN_SOURCE_V2})`,
  'g',
);

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (value === undefined) return 'null';
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort(compareBinary).map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
}

function compoundHash(domain: string, value: unknown): string {
  return createHash('sha256')
    .update(`${domain}\0${canonicalJson(value)}`)
    .digest('hex');
}

function resolveCompoundAdvisoryAuthorityPolicy(
  value: CompoundAdvisoryAuthorityPolicy | null | undefined,
): {
  mode: CompoundAdvisoryAuthorityMode;
  marker: CompoundAdvisoryAuthorityPolicy | null;
} {
  if (value === null) {
    return { mode: 'legacy_strict', marker: null };
  }
  if (value === undefined) {
    return {
      mode: COMPOUND_ADVISORY_AUTHORITY_POLICY.name,
      marker: { ...COMPOUND_ADVISORY_AUTHORITY_POLICY },
    };
  }
  if (
    value.schemaVersion !== COMPOUND_ADVISORY_AUTHORITY_POLICY_SCHEMA_VERSION ||
    value.name !== COMPOUND_ADVISORY_AUTHORITY_POLICY.name ||
    canonicalJson(value) !== canonicalJson(COMPOUND_ADVISORY_AUTHORITY_POLICY)
  ) {
    throw new Error(
      `Unsupported compound advisory authority policy: ${canonicalJson(value)}`,
    );
  }
  return {
    mode: COMPOUND_ADVISORY_AUTHORITY_POLICY.name,
    marker: { ...COMPOUND_ADVISORY_AUTHORITY_POLICY },
  };
}

export function canonicalCompoundAdvisorySnapshotJson(
  snapshot: CompoundAdvisorySnapshot,
): string {
  return canonicalJson(snapshot);
}

export function canonicalCompoundAdvisoryRangeRowJson(
  row: CompoundAdvisoryRangeRow,
): string {
  return canonicalJson(row);
}

export function compoundAdvisorySnapshotRowContentHash(
  row: CompoundAdvisoryRangeRow,
): string {
  return createHash('sha256')
    .update(
      `openclaw-release-radar.advisory-snapshot-row.v2\0` +
      canonicalCompoundAdvisoryRangeRowJson(row),
    )
    .digest('hex');
}

export function compoundAdvisorySnapshotLedgerContentHash(input: {
  capturedAt: string;
  repository: AdvisoryRepositoryIdentity;
  target: ExpectedAdvisoryPackage;
  sourceHash: string;
  catalogHash: string;
  scoreHash: string;
  rowCount: number;
  scoreRowCount: number;
  scoreContentDigest: string;
  snapshotJson: string;
  previousContentHash: string | null;
}): string {
  return compoundHash('openclaw-release-radar.advisory-snapshot-ledger.v2', input);
}

function nativeJsonHash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function normalizedAdvisoryText(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

function normalizedPackageIdentity(
  ecosystem: string | null | undefined,
  packageName: string | null | undefined,
): ExpectedAdvisoryPackage {
  return {
    ecosystem: String(ecosystem ?? '').trim().toLowerCase(),
    packageName: String(packageName ?? '').trim().toLowerCase(),
  };
}

export function advisoryRangeIdentityV2(
  ghsaId: string,
  ecosystem: string | null | undefined,
  packageName: string | null | undefined,
  vulnerableVersionRange: string | null | undefined,
): string {
  const packageIdentity = normalizedPackageIdentity(ecosystem, packageName);
  return [
    ghsaId.trim(),
    packageIdentity.ecosystem,
    packageIdentity.packageName,
    normalizedAdvisoryText(String(vulnerableVersionRange ?? '')),
  ].map((part) => encodeURIComponent(part)).join(':');
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort(compareBinary);
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function normalizedTimestamp(value: unknown): unknown {
  return isTimestamp(value)
    ? new Date(Date.parse(value)).toISOString()
    : value;
}

function normalizedSourceRetrievalWindow(value: unknown): GhSourceRetrievalWindow {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return value as GhSourceRetrievalWindow;
  }
  const record = value as Record<string, unknown>;
  return {
    ...record,
    ...(Object.prototype.hasOwnProperty.call(record, 'startedAt')
      ? { startedAt: normalizedTimestamp(record.startedAt) }
      : {}),
    ...(Object.prototype.hasOwnProperty.call(record, 'completedAt')
      ? { completedAt: normalizedTimestamp(record.completedAt) }
      : {}),
  } as unknown as GhSourceRetrievalWindow;
}

function normalizedSourceRetrievalProperty(
  observation: { retrieval?: unknown },
): { retrieval?: GhSourceRetrievalWindow } {
  if (!Object.prototype.hasOwnProperty.call(observation, 'retrieval')) {
    return {};
  }
  return {
    retrieval: normalizedSourceRetrievalWindow(observation.retrieval),
  };
}

function validateSourceRetrievalWindow(
  source: Exclude<CompoundAdvisorySource, 'compound-reconciliation'>,
  value: unknown,
  capturedAt: string,
  problems: CompoundAdvisorySnapshotProblem[],
): void {
  if (value == null) {
    addCompoundProblem(problems, {
      code: 'invalid_source_observation',
      severity: 'blocking',
      source,
      detail: `${source} retrieval window is missing`,
    });
    return;
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    addCompoundProblem(problems, {
      code: 'invalid_source_observation',
      severity: 'blocking',
      source,
      detail: `${source} retrieval window must contain startedAt and completedAt timestamps`,
    });
    return;
  }

  const retrieval = value as Record<string, unknown>;
  if (!isTimestamp(retrieval.startedAt) || !isTimestamp(retrieval.completedAt)) {
    addCompoundProblem(problems, {
      code: 'invalid_source_observation',
      severity: 'blocking',
      source,
      detail: `${source} retrieval window contains an invalid timestamp`,
    });
    return;
  }

  const startedAtMs = Date.parse(retrieval.startedAt);
  const completedAtMs = Date.parse(retrieval.completedAt);
  if (completedAtMs < startedAtMs) {
    addCompoundProblem(problems, {
      code: 'invalid_source_observation',
      severity: 'blocking',
      source,
      detail: `${source} retrieval completedAt predates startedAt`,
    });
    return;
  }
  if (isTimestamp(capturedAt) && completedAtMs > Date.parse(capturedAt)) {
    addCompoundProblem(problems, {
      code: 'invalid_snapshot_input',
      severity: 'blocking',
      source: 'compound-reconciliation',
      detail: `capturedAt ${capturedAt} predates ${source} retrieval completion ` +
        `${retrieval.completedAt}`,
    });
  }
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0;
}

function sameStringArray(left: string[], right: string[]): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function problemSortKey(problem: CompoundAdvisorySnapshotProblem): string {
  return [
    problem.severity,
    problem.code,
    problem.source,
    problem.rangeIdentity ?? '',
    problem.detail,
  ].join('\0');
}

function addCompoundProblem(
  problems: CompoundAdvisorySnapshotProblem[],
  problem: Omit<CompoundAdvisorySnapshotProblem, 'rangeIdentity'> & {
    rangeIdentity?: string | null;
  },
): void {
  problems.push({
    ...problem,
    rangeIdentity: problem.rangeIdentity ?? null,
  });
}

function canonicalRepositoryUrl(owner: string, name: string): string {
  return `https://github.com/${owner}/${name}`;
}

function validCanonicalRepositoryUrl(
  value: string,
  owner: string,
  name: string,
): boolean {
  try {
    const url = new URL(value);
    const parts = url.pathname.split('/').filter(Boolean);
    return (
      url.origin === 'https://github.com' &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === '' &&
      parts.length === 2 &&
      parts[0].toLowerCase() === owner.toLowerCase() &&
      parts[1].toLowerCase() === name.toLowerCase() &&
      value === canonicalRepositoryUrl(parts[0], parts[1])
    );
  } catch {
    return false;
  }
}

function validRepositoryAdvisoryUrl(
  value: string,
  owner: string,
  name: string,
  ghsaId: string,
): boolean {
  try {
    const url = new URL(value);
    const parts = url.pathname.split('/').filter(Boolean);
    return (
      url.origin === 'https://github.com' &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === '' &&
      parts.length === 5 &&
      parts[0].toLowerCase() === owner.toLowerCase() &&
      parts[1].toLowerCase() === name.toLowerCase() &&
      parts[2] === 'security' &&
      parts[3] === 'advisories' &&
      parts[4] === ghsaId
    );
  } catch {
    return false;
  }
}

function normalizedRepositoryState(
  state: GhAdvisory['state'],
): Exclude<CompoundAdvisoryRangeState, 'conflicted'> {
  if (state === 'published') return 'active';
  if (state === 'withdrawn') return 'withdrawn';
  return 'other';
}

function tighterLowerBoundV2(
  current: VersionIntervalBound | null,
  candidate: VersionIntervalBound,
): VersionIntervalBound {
  if (!current) return candidate;
  const comparison = compareVersions(candidate.version, current.version);
  if (comparison > 0) return candidate;
  if (comparison < 0) return current;
  return current.inclusive && !candidate.inclusive ? candidate : current;
}

function tighterUpperBoundV2(
  current: VersionIntervalBound | null,
  candidate: VersionIntervalBound,
): VersionIntervalBound {
  if (!current) return candidate;
  const comparison = compareVersions(candidate.version, current.version);
  if (comparison < 0) return candidate;
  if (comparison > 0) return current;
  return current.inclusive && !candidate.inclusive ? candidate : current;
}

function versionInterval(range: string): VersionInterval | null {
  if (rangeValidationError(range)) return null;
  const interval: VersionInterval = { lower: null, upper: null };
  for (const match of normalizedAdvisoryText(range).matchAll(RANGE_CLAUSE_RE_V2)) {
    const operator = match[1] ?? '=';
    const version = match[2];
    if (operator === '=' || operator === '==') {
      const exact = { version, inclusive: true };
      interval.lower = tighterLowerBoundV2(interval.lower, exact);
      interval.upper = tighterUpperBoundV2(interval.upper, exact);
    } else if (operator === '>' || operator === '>=') {
      interval.lower = tighterLowerBoundV2(interval.lower, {
        version,
        inclusive: operator === '>=',
      });
    } else {
      interval.upper = tighterUpperBoundV2(interval.upper, {
        version,
        inclusive: operator === '<=',
      });
    }
  }
  return interval;
}

function versionIntervalsOverlap(leftRange: string, rightRange: string): boolean {
  const left = versionInterval(leftRange);
  const right = versionInterval(rightRange);
  if (!left || !right) return false;
  const lower = !left.lower
    ? right.lower
    : !right.lower
      ? left.lower
      : compareVersions(left.lower.version, right.lower.version) > 0
        ? left.lower
        : compareVersions(left.lower.version, right.lower.version) < 0
          ? right.lower
          : {
              version: left.lower.version,
              inclusive: left.lower.inclusive && right.lower.inclusive,
            };
  const upper = !left.upper
    ? right.upper
    : !right.upper
      ? left.upper
      : compareVersions(left.upper.version, right.upper.version) < 0
        ? left.upper
        : compareVersions(left.upper.version, right.upper.version) > 0
          ? right.upper
          : {
              version: left.upper.version,
              inclusive: left.upper.inclusive && right.upper.inclusive,
            };
  if (!lower || !upper) return true;
  const comparison = compareVersions(lower.version, upper.version);
  return comparison < 0 || (comparison === 0 && lower.inclusive && upper.inclusive);
}

function validatePatchMetadata(
  patched: string | null,
  vulnerableRange: string,
): string | null {
  if (patched == null) return null;
  const patch = firstPatchedVersion(patched);
  if (!patch) {
    return `could not identify a first patched version from ${JSON.stringify(patched)}`;
  }
  if (!rangeValidationError(vulnerableRange) && matchesRange(patch, vulnerableRange)) {
    return `patched version ${patch} still satisfies ${JSON.stringify(vulnerableRange)}`;
  }
  return null;
}

function detectDuplicateAndOverlappingRanges(
  ranges: Array<{
    identity: string;
    ghsaId: string;
    ecosystem: string;
    packageName: string;
    vulnerableVersionRange: string;
    validRange: boolean;
  }>,
  source: Exclude<CompoundAdvisorySource, 'compound-reconciliation'>,
  problems: CompoundAdvisorySnapshotProblem[],
): void {
  const byIdentity = new Map<string, number>();
  for (const range of ranges) {
    byIdentity.set(range.identity, (byIdentity.get(range.identity) ?? 0) + 1);
  }
  for (const [identity, count] of byIdentity) {
    if (count <= 1) continue;
    addCompoundProblem(problems, {
      code: 'duplicate_source_range',
      severity: 'blocking',
      source,
      rangeIdentity: identity,
      detail: `${source} repeated canonical range identity ${identity} ${count} times`,
    });
  }

  const groups = new Map<string, typeof ranges>();
  for (const range of ranges) {
    if (!range.validRange) continue;
    const key = [range.ghsaId, range.ecosystem, range.packageName].join('\0');
    const group = groups.get(key) ?? [];
    group.push(range);
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    const ordered = group.slice().sort((left, right) =>
      compareBinary(left.identity, right.identity));
    for (let leftIndex = 0; leftIndex < ordered.length; leftIndex++) {
      for (let rightIndex = leftIndex + 1; rightIndex < ordered.length; rightIndex++) {
        const left = ordered[leftIndex];
        const right = ordered[rightIndex];
        if (left.identity === right.identity) continue;
        if (!versionIntervalsOverlap(
          left.vulnerableVersionRange,
          right.vulnerableVersionRange,
        )) {
          continue;
        }
        addCompoundProblem(problems, {
          code: 'overlapping_source_ranges',
          severity: 'blocking',
          source,
          rangeIdentity: left.identity,
          detail: `${left.identity} overlaps ${right.identity}`,
        });
        addCompoundProblem(problems, {
          code: 'overlapping_source_ranges',
          severity: 'blocking',
          source,
          rangeIdentity: right.identity,
          detail: `${right.identity} overlaps ${left.identity}`,
        });
      }
    }
  }
}

function validateGraphqlAdvisoryMetadataConsistency(
  ranges: NormalizedCurrentGraphqlRange[],
  problems: CompoundAdvisorySnapshotProblem[],
): void {
  const byGhsaId = new Map<string, NormalizedCurrentGraphqlRange[]>();
  for (const range of ranges) {
    const group = byGhsaId.get(range.ghsaId) ?? [];
    group.push(range);
    byGhsaId.set(range.ghsaId, group);
  }

  for (const [ghsaId, group] of byGhsaId) {
    if (group.length <= 1) continue;
    const conflictingFields: string[] = [];
    const recordConflict = (field: string, values: unknown[]): void => {
      if (new Set(values.map((value) => canonicalJson(value))).size > 1) {
        conflictingFields.push(field);
      }
    };
    recordConflict('state', group.map((range) => range.state));
    recordConflict('severity', group.map((range) => range.severity));
    recordConflict('CVE id', group.map((range) => range.cveId));
    recordConflict('summary', group.map((range) => range.summary));
    recordConflict('publishedAt', group.map((range) => range.publishedAt));
    recordConflict('withdrawnAt', group.map((range) => range.withdrawnAt));
    if (conflictingFields.length === 0) continue;

    const detail = `GraphQL advisory ${ghsaId} has inconsistent advisory-level metadata ` +
      `across ranges: ${conflictingFields.join(', ')}`;
    for (const range of group) {
      addCompoundProblem(problems, {
        code: 'conflicting_source_advisory_metadata',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: range.identity,
        detail,
      });
    }
  }
}

function normalizedGraphqlObservation(
  observation: GhSecurityVulnerabilityCatalogObservation,
): GhSecurityVulnerabilityCatalogObservation {
  const ranges = observation.ranges
    .map((range) => ({ ...range }))
    .sort((left, right) => {
      const identityComparison = compareBinary(left.identity, right.identity);
      return identityComparison || compareBinary(canonicalJson(left), canonicalJson(right));
    });
  return {
    ...observation,
    ...normalizedSourceRetrievalProperty(observation),
    ranges,
    rangeIdentities: observation.rangeIdentities.slice().sort(compareBinary),
  };
}

function normalizedLegacyGraphqlObservation(
  observation: GhSecurityVulnerabilityCatalogObservation,
): GhSecurityVulnerabilityCatalogObservation {
  const legacy = observation as unknown as LegacySecurityVulnerabilityCatalogObservation;
  const ranges = legacy.ranges
    .map((range) => ({ ...range }))
    .sort((left, right) => {
      const identityComparison = compareBinary(left.identity, right.identity);
      return identityComparison || compareBinary(canonicalJson(left), canonicalJson(right));
    });
  return {
    ...legacy,
    ...normalizedSourceRetrievalProperty(legacy),
    ranges,
    rangeIdentities: legacy.rangeIdentities.slice().sort(compareBinary),
  } as unknown as GhSecurityVulnerabilityCatalogObservation;
}

function normalizedRestObservation(
  observation: GhRepositoryAdvisoryCatalogObservation,
): GhRepositoryAdvisoryCatalogObservation {
  const advisories = observation.advisories.map((advisory) => ({
    ...advisory,
    vulnerabilities: advisory.vulnerabilities
      .map((vulnerability) => ({
        ...vulnerability,
        package: vulnerability.package ? { ...vulnerability.package } : null,
      }))
      .sort((left, right) => {
        const identityComparison = compareBinary(
          advisoryRangeIdentityV2(
            advisory.ghsa_id,
            left.package?.ecosystem,
            left.package?.name,
            left.vulnerable_version_range,
          ),
          advisoryRangeIdentityV2(
            advisory.ghsa_id,
            right.package?.ecosystem,
            right.package?.name,
            right.vulnerable_version_range,
          ),
        );
        return identityComparison ||
          compareBinary(canonicalJson(left), canonicalJson(right));
      }),
  })).sort((left, right) => {
    const ghsaComparison = compareBinary(left.ghsa_id, right.ghsa_id);
    return ghsaComparison || compareBinary(canonicalJson(left), canonicalJson(right));
  });
  return {
    ...observation,
    ...normalizedSourceRetrievalProperty(observation),
    advisories,
    allRangeIdentities: observation.allRangeIdentities.slice().sort(compareBinary),
    targetRangeIdentities: observation.targetRangeIdentities.slice().sort(compareBinary),
  };
}

function emptySourceCounts(): CompoundAdvisorySourceCounts {
  return {
    advisoryCount: 0,
    activeAdvisoryCount: 0,
    withdrawnAdvisoryCount: 0,
    otherStateAdvisoryCount: 0,
    rangeCount: 0,
    activeRangeCount: 0,
    withdrawnRangeCount: 0,
    otherStateRangeCount: 0,
    packageCount: 0,
    targetRangeCount: 0,
    foreignRangeCount: 0,
  };
}

function validateLegacyGraphqlObservation(
  observation: GhSecurityVulnerabilityCatalogObservation,
  target: ExpectedAdvisoryPackage,
  problems: CompoundAdvisorySnapshotProblem[],
): { ranges: NormalizedLegacyGraphqlRange[]; counts: CompoundAdvisorySourceCounts } {
  const legacy = observation as unknown as LegacySecurityVulnerabilityCatalogObservation;
  const ranges: NormalizedLegacyGraphqlRange[] = legacy.ranges.map((range, index) => {
    const packageIdentity = normalizedPackageIdentity(range.ecosystem, range.packageName);
    const identity = advisoryRangeIdentityV2(
      String(range.ghsaId ?? ''),
      packageIdentity.ecosystem,
      packageIdentity.packageName,
      String(range.vulnerableVersionRange ?? ''),
    );
    const rangeError = rangeValidationError(range.vulnerableVersionRange);
    if (
      !String(range.ghsaId ?? '').trim() ||
      packageIdentity.ecosystem !== target.ecosystem ||
      packageIdentity.packageName !== target.packageName ||
      !isTimestamp(range.updatedAt)
    ) {
      addCompoundProblem(problems, {
        code: 'invalid_source_observation',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: `GraphQL range ${index} has invalid target identity or updatedAt`,
      });
    }
    if (range.identity !== identity) {
      addCompoundProblem(problems, {
        code: 'invalid_source_observation',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: `GraphQL range identity ${JSON.stringify(range.identity)} != ${identity}`,
      });
    }
    if (rangeError) {
      addCompoundProblem(problems, {
        code: 'malformed_target_range',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: rangeError,
      });
    }
    const patchError = validatePatchMetadata(
      range.firstPatchedVersion,
      range.vulnerableVersionRange,
    );
    if (patchError) {
      addCompoundProblem(problems, {
        code: 'malformed_target_patch',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: patchError,
      });
    }
    return {
      authorityShape: 'legacy',
      source: 'graphql-security-vulnerabilities',
      identity,
      ghsaId: range.ghsaId,
      state: 'active',
      ecosystem: packageIdentity.ecosystem,
      packageName: packageIdentity.packageName,
      vulnerableVersionRange: normalizedAdvisoryText(range.vulnerableVersionRange),
      firstPatchedVersion: range.firstPatchedVersion,
      updatedAt: range.updatedAt,
      validRange: !rangeError,
    };
  });

  detectDuplicateAndOverlappingRanges(
    ranges,
    'graphql-security-vulnerabilities',
    problems,
  );

  const identities = ranges.map((range) => range.identity).sort(compareBinary);
  const uniqueIdentities = sortedUnique(identities);
  const expectedIdentityDigest = nativeJsonHash(uniqueIdentities);
  const byIdentity = new Map(ranges.map((range) => [range.identity, range]));
  const expectedDigest = nativeJsonHash([
    legacy.totalCount,
    uniqueIdentities.map((identity) => {
      const range = byIdentity.get(identity)!;
      return [identity, range.firstPatchedVersion, range.updatedAt];
    }),
  ]);
  const countDetails: string[] = [];
  if (legacy.totalCount !== ranges.length) {
    countDetails.push(`totalCount ${legacy.totalCount} != rows ${ranges.length}`);
  }
  if (legacy.nodeCount !== ranges.length) {
    countDetails.push(`nodeCount ${legacy.nodeCount} != rows ${ranges.length}`);
  }
  if (legacy.uniqueRangeCount !== uniqueIdentities.length) {
    countDetails.push(
      `uniqueRangeCount ${legacy.uniqueRangeCount} != identities ${uniqueIdentities.length}`,
    );
  }
  if (!sameStringArray(legacy.rangeIdentities, uniqueIdentities)) {
    countDetails.push('rangeIdentities do not match canonical GraphQL rows');
  }
  if (countDetails.length > 0) {
    addCompoundProblem(problems, {
      code: 'count_mismatch',
      severity: 'blocking',
      source: 'graphql-security-vulnerabilities',
      detail: countDetails.join('; '),
    });
  }
  if (
    legacy.source !== 'graphql-security-vulnerabilities' ||
    legacy.exhausted !== true ||
    legacy.stabilized !== true ||
    legacy.ecosystem !== target.ecosystem ||
    legacy.packageName !== target.packageName ||
    !isNonNegativeInteger(legacy.pageCount) ||
    legacy.pageCount < 1 ||
    !isNonNegativeInteger(legacy.pagesFetched) ||
    !isNonNegativeInteger(legacy.sweepCount) ||
    legacy.sweepCount < 2 ||
    legacy.pagesFetched <
      (2 * legacy.pageCount) + Math.max(0, legacy.sweepCount - 2)
  ) {
    addCompoundProblem(problems, {
      code: 'incomplete_graphql_source',
      severity: 'blocking',
      source: 'graphql-security-vulnerabilities',
      detail: 'GraphQL ranges must be target-bound, exhaustive, and stable across complete sweeps',
    });
  }
  if (
    legacy.identityDigest !== expectedIdentityDigest ||
    legacy.digest !== expectedDigest
  ) {
    addCompoundProblem(problems, {
      code: 'digest_mismatch',
      severity: 'blocking',
      source: 'graphql-security-vulnerabilities',
      detail: 'GraphQL source digests do not match canonical rows',
    });
  }

  const counts = emptySourceCounts();
  counts.advisoryCount = new Set(ranges.map((range) => range.ghsaId)).size;
  counts.activeAdvisoryCount = counts.advisoryCount;
  counts.rangeCount = ranges.length;
  counts.activeRangeCount = ranges.length;
  counts.packageCount = new Set(ranges.map((range) =>
    `${range.ecosystem}\0${range.packageName}`)).size;
  counts.targetRangeCount = ranges.length;
  return { ranges, counts };
}

function validateGraphqlObservation(
  observation: GhSecurityVulnerabilityCatalogObservation,
  target: ExpectedAdvisoryPackage,
  problems: CompoundAdvisorySnapshotProblem[],
): { ranges: NormalizedCurrentGraphqlRange[]; counts: CompoundAdvisorySourceCounts } {
  const ranges: NormalizedCurrentGraphqlRange[] = observation.ranges.map((range, index) => {
    const packageIdentity = normalizedPackageIdentity(range.ecosystem, range.packageName);
    const identity = advisoryRangeIdentityV2(
      String(range.ghsaId ?? ''),
      packageIdentity.ecosystem,
      packageIdentity.packageName,
      String(range.vulnerableVersionRange ?? ''),
    );
    const rangeError = rangeValidationError(range.vulnerableVersionRange);
    const withdrawnAtValid =
      range.withdrawnAt === null || isTimestamp(range.withdrawnAt);
    let htmlUrlValid = false;
    try {
      const htmlUrl = new URL(range.htmlUrl);
      htmlUrlValid =
        htmlUrl.origin === 'https://github.com' &&
        htmlUrl.pathname === `/advisories/${range.ghsaId}` &&
        !htmlUrl.search &&
        !htmlUrl.hash;
    } catch {
      htmlUrlValid = false;
    }
    if (
      !String(range.ghsaId ?? '').trim() ||
      (range.cveId != null && !/^CVE-\d{4}-\d{4,}$/.test(range.cveId)) ||
      !String(range.summary ?? '').trim() ||
      !NORMALIZED_ADVISORY_SEVERITIES.has(range.severity) ||
      !htmlUrlValid ||
      !isTimestamp(range.publishedAt) ||
      !withdrawnAtValid ||
      (
        range.withdrawnAt !== null &&
        Date.parse(range.withdrawnAt) < Date.parse(range.publishedAt)
      ) ||
      packageIdentity.ecosystem !== target.ecosystem ||
      packageIdentity.packageName !== target.packageName ||
      !isTimestamp(range.updatedAt) ||
      Date.parse(range.updatedAt) <
        Date.parse(range.withdrawnAt ?? range.publishedAt)
    ) {
      addCompoundProblem(problems, {
        code: 'invalid_source_observation',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: `GraphQL range ${index} has invalid advisory metadata, target identity, or timestamps`,
      });
    }
    if (range.identity !== identity) {
      addCompoundProblem(problems, {
        code: 'invalid_source_observation',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: `GraphQL range identity ${JSON.stringify(range.identity)} != ${identity}`,
      });
    }
    if (rangeError) {
      addCompoundProblem(problems, {
        code: 'malformed_target_range',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: rangeError,
      });
    }
    const patchError = validatePatchMetadata(
      range.firstPatchedVersion,
      range.vulnerableVersionRange,
    );
    if (patchError) {
      addCompoundProblem(problems, {
        code: 'malformed_target_patch',
        severity: 'blocking',
        source: 'graphql-security-vulnerabilities',
        rangeIdentity: identity,
        detail: patchError,
      });
    }
    return {
      authorityShape: 'current',
      source: 'graphql-security-vulnerabilities',
      identity,
      ghsaId: range.ghsaId,
      cveId: range.cveId,
      summary: range.summary,
      severity: range.severity,
      htmlUrl: range.htmlUrl,
      publishedAt: range.publishedAt,
      withdrawnAt: range.withdrawnAt,
      state: range.withdrawnAt === null ? 'active' : 'withdrawn',
      ecosystem: packageIdentity.ecosystem,
      packageName: packageIdentity.packageName,
      vulnerableVersionRange: normalizedAdvisoryText(range.vulnerableVersionRange),
      firstPatchedVersion: range.firstPatchedVersion,
      updatedAt: range.updatedAt,
      validRange: !rangeError,
    };
  });

  validateGraphqlAdvisoryMetadataConsistency(ranges, problems);
  detectDuplicateAndOverlappingRanges(
    ranges,
    'graphql-security-vulnerabilities',
    problems,
  );

  const identities = ranges.map((range) => range.identity).sort(compareBinary);
  const uniqueIdentities = sortedUnique(identities);
  const expectedIdentityDigest = nativeJsonHash(uniqueIdentities);
  const byIdentity = new Map(ranges.map((range) => [range.identity, range]));
  const expectedDigest = nativeJsonHash([
    observation.totalCount,
    uniqueIdentities.map((identity) => {
      const range = byIdentity.get(identity)!;
      return [
        identity,
        range.cveId,
        range.summary,
        range.severity,
        range.htmlUrl,
        range.publishedAt,
        range.withdrawnAt,
        range.firstPatchedVersion,
        range.updatedAt,
      ];
    }),
  ]);
  const countDetails: string[] = [];
  if (observation.totalCount !== ranges.length) {
    countDetails.push(`totalCount ${observation.totalCount} != rows ${ranges.length}`);
  }
  if (observation.nodeCount !== ranges.length) {
    countDetails.push(`nodeCount ${observation.nodeCount} != rows ${ranges.length}`);
  }
  if (observation.uniqueRangeCount !== uniqueIdentities.length) {
    countDetails.push(
      `uniqueRangeCount ${observation.uniqueRangeCount} != identities ${uniqueIdentities.length}`,
    );
  }
  if (!sameStringArray(observation.rangeIdentities, uniqueIdentities)) {
    countDetails.push('rangeIdentities do not match canonical GraphQL rows');
  }
  if (countDetails.length > 0) {
    addCompoundProblem(problems, {
      code: 'count_mismatch',
      severity: 'blocking',
      source: 'graphql-security-vulnerabilities',
      detail: countDetails.join('; '),
    });
  }
  if (
    observation.source !== 'graphql-security-vulnerabilities' ||
    observation.exhausted !== true ||
    observation.stabilized !== true ||
    observation.ecosystem !== target.ecosystem ||
    observation.packageName !== target.packageName ||
    !isNonNegativeInteger(observation.pageCount) ||
    observation.pageCount < 1 ||
    !isNonNegativeInteger(observation.pagesFetched) ||
    !isNonNegativeInteger(observation.sweepCount) ||
    observation.sweepCount < 2 ||
    observation.pagesFetched <
      (2 * observation.pageCount) + Math.max(0, observation.sweepCount - 2)
  ) {
    addCompoundProblem(problems, {
      code: 'incomplete_graphql_source',
      severity: 'blocking',
      source: 'graphql-security-vulnerabilities',
      detail: 'GraphQL ranges must be target-bound, exhaustive, and stable across complete sweeps',
    });
  }
  if (
    observation.identityDigest !== expectedIdentityDigest ||
    observation.digest !== expectedDigest
  ) {
    addCompoundProblem(problems, {
      code: 'digest_mismatch',
      severity: 'blocking',
      source: 'graphql-security-vulnerabilities',
      detail: `GraphQL source digests do not match canonical rows`,
    });
  }

  const counts = emptySourceCounts();
  const advisoryStates = new Map<string, Set<NormalizedGraphqlRange['state']>>();
  for (const range of ranges) {
    const states = advisoryStates.get(range.ghsaId) ?? new Set();
    states.add(range.state);
    advisoryStates.set(range.ghsaId, states);
  }
  counts.advisoryCount = advisoryStates.size;
  counts.activeAdvisoryCount = [...advisoryStates.values()]
    .filter((states) => states.size === 1 && states.has('active')).length;
  counts.withdrawnAdvisoryCount = [...advisoryStates.values()]
    .filter((states) => !states.has('active') && states.has('withdrawn')).length;
  counts.otherStateAdvisoryCount = [...advisoryStates.values()]
    .filter((states) => states.has('active') && states.has('withdrawn')).length;
  counts.rangeCount = ranges.length;
  counts.activeRangeCount = ranges.filter((range) => range.state === 'active').length;
  counts.withdrawnRangeCount = ranges.filter((range) => range.state === 'withdrawn').length;
  counts.packageCount = new Set(ranges.map((range) =>
    `${range.ecosystem}\0${range.packageName}`)).size;
  counts.targetRangeCount = ranges.length;
  return { ranges, counts };
}

function validateRepositoryObservation(
  observation: GhRepositoryAdvisoryCatalogObservation,
  repository: AdvisoryRepositoryIdentity,
  target: ExpectedAdvisoryPackage,
  problems: CompoundAdvisorySnapshotProblem[],
  authorityMode: CompoundAdvisoryAuthorityMode,
): { ranges: NormalizedRepositoryRange[]; counts: CompoundAdvisorySourceCounts } {
  const ranges: NormalizedRepositoryRange[] = [];
  const advisoryStates = new Map<string, Exclude<CompoundAdvisoryRangeState, 'conflicted'>>();
  const advisoryIds = new Map<string, number>();

  observation.advisories.forEach((advisory, advisoryIndex) => {
    const ghsaId = String(advisory.ghsa_id ?? '').trim();
    const state = normalizedRepositoryState(advisory.state);
    const publishedAtMs = Date.parse(String(advisory.published_at ?? ''));
    const withdrawnAtMs = Date.parse(String(advisory.withdrawn_at ?? ''));
    const updatedAtMs = Date.parse(String(advisory.updated_at ?? ''));
    const currentMetadataValid =
      (
        advisory.cve_id === null ||
        /^CVE-\d{4}-\d{4,}$/.test(String(advisory.cve_id))
      ) &&
      isTimestamp(advisory.updated_at) &&
      (
        !['published', 'withdrawn'].includes(advisory.state) ||
        isTimestamp(advisory.published_at)
      ) &&
      (
        advisory.state !== 'published' ||
        advisory.withdrawn_at === null
      ) &&
      (
        advisory.state !== 'withdrawn' ||
        isTimestamp(advisory.withdrawn_at)
      ) &&
      (
        !Number.isFinite(publishedAtMs) ||
        !Number.isFinite(withdrawnAtMs) ||
        withdrawnAtMs >= publishedAtMs
      ) &&
      (
        !Number.isFinite(publishedAtMs) ||
        !Number.isFinite(updatedAtMs) ||
        updatedAtMs >= publishedAtMs
      ) &&
      (
        !Number.isFinite(withdrawnAtMs) ||
        !Number.isFinite(updatedAtMs) ||
        updatedAtMs >= withdrawnAtMs
      );
    advisoryStates.set(ghsaId, state);
    advisoryIds.set(ghsaId, (advisoryIds.get(ghsaId) ?? 0) + 1);
    if (
      !ghsaId ||
      !String(advisory.summary ?? '').trim() ||
      !NORMALIZED_ADVISORY_SEVERITIES.has(advisory.severity) ||
      !['published', 'closed', 'withdrawn', 'triage', 'draft'].includes(advisory.state) ||
      (advisory.published_at != null && !isTimestamp(advisory.published_at)) ||
      (advisory.withdrawn_at != null && !isTimestamp(advisory.withdrawn_at)) ||
      (
        authorityMode !== 'legacy_strict' &&
        !currentMetadataValid
      )
    ) {
      addCompoundProblem(problems, {
        code: 'invalid_source_observation',
        severity: 'blocking',
        source: 'repository-security-advisories-rest',
        detail: `repository advisory ${advisoryIndex} has invalid identity, metadata, or state`,
      });
    }
    if (!validRepositoryAdvisoryUrl(advisory.html_url, repository.owner, repository.name, ghsaId)) {
      addCompoundProblem(problems, {
        code: 'wrong_repository_url',
        severity: 'blocking',
        source: 'repository-security-advisories-rest',
        detail: `${JSON.stringify(advisory.html_url)} is not an advisory URL for ` +
          `${repository.owner}/${repository.name}/${ghsaId}`,
      });
    }

    advisory.vulnerabilities.forEach((vulnerability, vulnerabilityIndex) => {
      const packageIdentity = normalizedPackageIdentity(
        vulnerability.package?.ecosystem,
        vulnerability.package?.name,
      );
      const vulnerableVersionRange = String(
        vulnerability.vulnerable_version_range ?? '',
      );
      const identity = advisoryRangeIdentityV2(
        ghsaId,
        packageIdentity.ecosystem,
        packageIdentity.packageName,
        vulnerableVersionRange,
      );
      const targetPackage =
        packageIdentity.ecosystem === target.ecosystem &&
        packageIdentity.packageName === target.packageName;
      const rangeError = rangeValidationError(vulnerableVersionRange);
      const missingPackageIdentity =
        !packageIdentity.ecosystem || !packageIdentity.packageName;
      const explicitForeignPackageEvidence =
        !packageIdentity.ecosystem &&
        Boolean(packageIdentity.packageName) &&
        packageIdentity.packageName !== target.packageName &&
        rangeError == null;
      const blockingMissingPackageIdentity =
        missingPackageIdentity && !explicitForeignPackageEvidence;
      if (
        missingPackageIdentity ||
        !vulnerableVersionRange.trim()
      ) {
        addCompoundProblem(problems, {
          code: 'invalid_source_observation',
          severity:
            targetPackage ||
            (
              blockingMissingPackageIdentity &&
              state === 'active' &&
              observation.completeness.terminalPageProven
            )
              ? 'blocking'
              : 'audit',
          source: 'repository-security-advisories-rest',
          rangeIdentity: identity,
          detail: `repository advisory ${ghsaId} range ${vulnerabilityIndex} ` +
            `is missing package or range identity`,
        });
      }
      if (rangeError) {
        addCompoundProblem(problems, {
          code: targetPackage ? 'malformed_target_range' : 'malformed_foreign_range',
          severity: targetPackage ? 'blocking' : 'audit',
          source: 'repository-security-advisories-rest',
          rangeIdentity: identity,
          detail: rangeError,
        });
      }
      const patchError = validatePatchMetadata(
        vulnerability.patched_versions,
        vulnerableVersionRange,
      );
      if (patchError) {
        addCompoundProblem(problems, {
          code: targetPackage ? 'malformed_target_patch' : 'malformed_foreign_patch',
          severity: targetPackage ? 'blocking' : 'audit',
          source: 'repository-security-advisories-rest',
          rangeIdentity: identity,
          detail: patchError,
        });
      }
      ranges.push({
        source: 'repository-security-advisories-rest',
        identity,
        ghsaId,
        ecosystem: packageIdentity.ecosystem,
        packageName: packageIdentity.packageName,
        vulnerableVersionRange: normalizedAdvisoryText(vulnerableVersionRange),
        patchedVersions: vulnerability.patched_versions,
        state,
        targetPackage,
        validRange: !rangeError,
        advisory,
      });
    });
  });

  for (const [ghsaId, count] of advisoryIds) {
    if (count <= 1) continue;
    addCompoundProblem(problems, {
      code: 'duplicate_source_advisory',
      severity: 'blocking',
      source: 'repository-security-advisories-rest',
      detail: `repository source repeated ${ghsaId} ${count} times`,
    });
  }
  detectDuplicateAndOverlappingRanges(
    ranges,
    'repository-security-advisories-rest',
    problems,
  );

  const allIdentities = ranges.map((range) => range.identity).sort(compareBinary);
  const uniqueAllIdentities = sortedUnique(allIdentities);
  const targetIdentities = sortedUnique(
    ranges.filter((range) => range.targetPackage).map((range) => range.identity),
  );
  const boundaryEvidence = [
    observation.completeness.boundaryEvidence.updatedAtDesc,
    observation.completeness.boundaryEvidence.updatedAtAsc,
  ];
  const boundaryEvidenceValid = boundaryEvidence.every((boundary) =>
    isNonNegativeInteger(boundary.pageCount) &&
    boundary.pageCount >= 1 &&
    isNonNegativeInteger(boundary.sweepCount) &&
    boundary.sweepCount >= 2 &&
    (
      (
        boundary.mode === 'link-exhausted' &&
        boundary.linkHeaderPresent === true &&
        boundary.pageCount >= 2
      ) ||
      (
        boundary.mode === 'single-page-no-link' &&
        boundary.linkHeaderPresent === false &&
        boundary.pageCount === 1
      )
    ));
  const terminalEvidenceValid = observation.completeness.terminalPageProven
    ? (
        observation.completeness.terminalPageEvidence === 'link-exhausted' &&
        observation.completeness.terminalPageLinkHeaderPresent === true &&
        boundaryEvidence.every((boundary) => boundary.mode === 'link-exhausted')
      )
    : (
        observation.completeness.terminalPageEvidence === 'unproven-no-link' &&
        observation.completeness.terminalPageLinkHeaderPresent === false &&
        boundaryEvidence.every((boundary) => boundary.mode === 'single-page-no-link')
      );
  const expectedIdentityDigest = nativeJsonHash([
    observation.advisories.length,
    observation.advisories
      .map((advisory) => [
        advisory.ghsa_id,
        ranges
          .filter((range) => range.advisory === advisory)
          .map((range) => range.identity)
          .sort(compareBinary),
      ])
      .sort((left, right) => compareBinary(String(left[0]), String(right[0]))),
  ]);
  const expectedTargetIdentityDigest = nativeJsonHash(targetIdentities);
  const countDetails: string[] = [];
  if (observation.observedAdvisoryCount !== observation.advisories.length) {
    countDetails.push(
      `observedAdvisoryCount ${observation.observedAdvisoryCount} != advisories ` +
        `${observation.advisories.length}`,
    );
  }
  if (observation.observedRangeCount !== ranges.length) {
    countDetails.push(
      `observedRangeCount ${observation.observedRangeCount} != ranges ${ranges.length}`,
    );
  }
  if (observation.targetRangeCount !== targetIdentities.length) {
    countDetails.push(
      `targetRangeCount ${observation.targetRangeCount} != target ranges ` +
        `${targetIdentities.length}`,
    );
  }
  if (!sameStringArray(observation.allRangeIdentities, uniqueAllIdentities)) {
    countDetails.push('allRangeIdentities do not match canonical repository rows');
  }
  if (!sameStringArray(observation.targetRangeIdentities, targetIdentities)) {
    countDetails.push('targetRangeIdentities do not match canonical repository rows');
  }
  if (
    observation.exhausted &&
    observation.totalCount !== observation.advisories.length
  ) {
    countDetails.push(
      `totalCount ${String(observation.totalCount)} != advisories ` +
        `${observation.advisories.length}`,
    );
  }
  if (!observation.exhausted && observation.totalCount !== null) {
    countDetails.push('unproven repository completeness must retain totalCount null');
  }
  if (countDetails.length > 0) {
    addCompoundProblem(problems, {
      code: 'count_mismatch',
      severity: 'blocking',
      source: 'repository-security-advisories-rest',
      detail: countDetails.join('; '),
    });
  }
  if (
    observation.source !== 'repository-security-advisories-rest' ||
    observation.stabilized !== true ||
    !isNonNegativeInteger(observation.pageCount) ||
    observation.pageCount < 1 ||
    !isNonNegativeInteger(observation.pagesFetched) ||
    !isNonNegativeInteger(observation.sweepCount) ||
    observation.sweepCount < 4 ||
    observation.pagesFetched < observation.pageCount * observation.sweepCount ||
    observation.completeness.crossOrderVerified !== true ||
    observation.completeness.enumeratedCount !== observation.advisories.length ||
    observation.completeness.remoteTotalCount !== null ||
    observation.exhausted !== observation.completeness.terminalPageProven ||
    !boundaryEvidenceValid ||
    !terminalEvidenceValid
  ) {
    addCompoundProblem(problems, {
      code: 'invalid_source_observation',
      severity: 'blocking',
      source: 'repository-security-advisories-rest',
      detail: 'repository REST observation has inconsistent stabilization or pagination metadata',
    });
  }
  if (!observation.completeness.terminalPageProven) {
    addCompoundProblem(problems, {
      code: 'unproven_repository_completeness',
      severity: 'audit',
      source: 'repository-security-advisories-rest',
      detail: 'stable no-Link repository pages do not prove repository-global exhaustion',
    });
  }
  if (
    !isSha256(observation.digest) ||
    (
      authorityMode !== 'legacy_strict' &&
      observation.digest !==
        repositoryAdvisoryCatalogContentDigest(observation.advisories)
    ) ||
    observation.identityDigest !== expectedIdentityDigest ||
    observation.targetIdentityDigest !== expectedTargetIdentityDigest
  ) {
    addCompoundProblem(problems, {
      code: 'digest_mismatch',
      severity: 'blocking',
      source: 'repository-security-advisories-rest',
      detail: 'repository REST identity digests do not match canonical rows',
    });
  }

  const counts = emptySourceCounts();
  counts.advisoryCount = advisoryIds.size;
  counts.activeAdvisoryCount = [...advisoryStates.values()]
    .filter((state) => state === 'active').length;
  counts.withdrawnAdvisoryCount = [...advisoryStates.values()]
    .filter((state) => state === 'withdrawn').length;
  counts.otherStateAdvisoryCount = [...advisoryStates.values()]
    .filter((state) => state === 'other').length;
  counts.rangeCount = ranges.length;
  counts.activeRangeCount = ranges.filter((range) => range.state === 'active').length;
  counts.withdrawnRangeCount = ranges.filter((range) => range.state === 'withdrawn').length;
  counts.otherStateRangeCount = ranges.filter((range) => range.state === 'other').length;
  counts.packageCount = new Set(ranges.map((range) =>
    `${range.ecosystem}\0${range.packageName}`)).size;
  counts.targetRangeCount = ranges.filter((range) => range.targetPackage).length;
  counts.foreignRangeCount = ranges.length - counts.targetRangeCount;
  return { ranges, counts };
}

function declaredReconciliationProblems(
  declared: GhAdvisoryReconciliationInputs | null | undefined,
  target: ExpectedAdvisoryPackage,
  graphql: GhSecurityVulnerabilityCatalogObservation,
  repositoryRest: GhRepositoryAdvisoryCatalogObservation,
  problems: CompoundAdvisorySnapshotProblem[],
  authorityMode: CompoundAdvisoryAuthorityMode,
): void {
  if (!declared) return;
  const declaredTarget = normalizedPackageIdentity(
    declared.target.ecosystem,
    declared.target.packageName,
  );
  const graphqlIdentities = sortedUnique(graphql.ranges.map((range) =>
    advisoryRangeIdentityV2(
      range.ghsaId,
      range.ecosystem,
      range.packageName,
      range.vulnerableVersionRange,
    )));
  const restTargetIdentities = sortedUnique(repositoryRest.advisories.flatMap((advisory) =>
    advisory.vulnerabilities.flatMap((vulnerability) => {
      const packageIdentity = normalizedPackageIdentity(
        vulnerability.package?.ecosystem,
        vulnerability.package?.name,
      );
      if (
        packageIdentity.ecosystem !== target.ecosystem ||
        packageIdentity.packageName !== target.packageName
      ) {
        return [];
      }
      return [advisoryRangeIdentityV2(
        advisory.ghsa_id,
        packageIdentity.ecosystem,
        packageIdentity.packageName,
        vulnerability.vulnerable_version_range,
      )];
    })));
  const details: string[] = [];
  if (
    declaredTarget.ecosystem !== target.ecosystem ||
    declaredTarget.packageName !== target.packageName
  ) {
    details.push('declared target package does not match snapshot target');
  }
  if (
    declared.graphqlSecurityVulnerabilities.totalCount !== graphql.totalCount ||
    declared.graphqlSecurityVulnerabilities.rangeCount !== graphqlIdentities.length ||
    declared.graphqlSecurityVulnerabilities.identityDigest !==
      nativeJsonHash(graphqlIdentities) ||
    !sameStringArray(
      declared.graphqlSecurityVulnerabilities.rangeIdentities.slice().sort(compareBinary),
      graphqlIdentities,
    )
  ) {
    details.push('declared GraphQL reconciliation input conflicts with source rows');
  }
  if (
    declared.repositoryAdvisories.totalCount !== repositoryRest.totalCount ||
    declared.repositoryAdvisories.observedAdvisoryCount !==
      repositoryRest.observedAdvisoryCount ||
    declared.repositoryAdvisories.targetRangeCount !== restTargetIdentities.length ||
    declared.repositoryAdvisories.identityDigest !== nativeJsonHash(restTargetIdentities) ||
    !sameStringArray(
      declared.repositoryAdvisories.rangeIdentities.slice().sort(compareBinary),
      restTargetIdentities,
    ) ||
    declared.repositoryAdvisories.completenessProven !==
      repositoryRest.completeness.terminalPageProven
  ) {
    details.push('declared REST reconciliation input conflicts with source rows');
  }
  if (details.length > 0) {
    addCompoundProblem(problems, {
      code: authorityMode === 'legacy_strict'
        ? 'conflicting_reconciliation'
        : 'declared_reconciliation_mismatch',
      severity: 'blocking',
      source: 'compound-reconciliation',
      detail: details.join('; '),
    });
  }
}

function buildCompoundRows(
  graphqlRanges: NormalizedGraphqlRange[],
  repositoryRanges: NormalizedRepositoryRange[],
  ineligibleRangeIdentities: Set<string>,
  target: ExpectedAdvisoryPackage,
  repositoryCompletenessProven: boolean,
  authorityMode: CompoundAdvisoryAuthorityMode,
): CompoundAdvisoryRangeRow[] {
  const byIdentity = new Map<string, {
    graphql: NormalizedGraphqlRange[];
    repository: NormalizedRepositoryRange[];
  }>();
  const graphqlGhsaIds = new Set(graphqlRanges.map((range) => range.ghsaId));
  const repositoryGhsaIds = new Set(repositoryRanges.map((range) => range.ghsaId));
  for (const range of graphqlRanges) {
    const entry = byIdentity.get(range.identity) ?? { graphql: [], repository: [] };
    entry.graphql.push(range);
    byIdentity.set(range.identity, entry);
  }
  for (const range of repositoryRanges) {
    const entry = byIdentity.get(range.identity) ?? { graphql: [], repository: [] };
    entry.repository.push(range);
    byIdentity.set(range.identity, entry);
  }

  return [...byIdentity.entries()].map(([identity, observations]) => {
    const graphql = observations.graphql[0] ?? null;
    const repository = observations.repository[0] ?? null;
    const base = graphql ?? repository!;
    const hasGraphql = observations.graphql.length > 0;
    const ghsaHasGraphqlAuthority = graphqlGhsaIds.has(base.ghsaId);
    const repositoryStates = new Set(
      observations.repository.map((range) => range.state),
    );
    const state: CompoundAdvisoryRangeState = authorityMode === 'legacy_strict'
      ? hasGraphql && repositoryStates.has('withdrawn')
        ? 'conflicted'
        : hasGraphql || repositoryStates.has('active')
          ? 'active'
          : repositoryStates.has('withdrawn')
            ? 'withdrawn'
            : 'other'
      : graphql?.state ?? repository?.state ?? 'other';
    const graphqlScoreEligible =
      hasGraphql &&
      (
        authorityMode === 'legacy_strict' ||
        graphql!.state === 'active'
      ) &&
      graphql!.validRange &&
      graphql!.ecosystem === target.ecosystem &&
      graphql!.packageName === target.packageName &&
      state === 'active';
    const repositoryFallbackScoreEligible =
      authorityMode !== 'legacy_strict' &&
      !ghsaHasGraphqlAuthority &&
      repositoryCompletenessProven &&
      repository != null &&
      repository.state === 'active' &&
      repository.validRange &&
      repository.targetPackage;
    const scoreEligible =
      (graphqlScoreEligible || repositoryFallbackScoreEligible) &&
      !ineligibleRangeIdentities.has(identity);
    const sourceObservations: CompoundAdvisoryRangeSourceObservation[] = [
      ...observations.graphql.map((range) => ({
        source: range.source,
        state: authorityMode === 'legacy_strict' ? 'active' as const : range.state,
        repositoryOwned: false,
        firstPatchedVersion: range.firstPatchedVersion,
        patchedVersions: null,
        updatedAt: range.updatedAt,
      })),
      ...observations.repository.map((range) => ({
        source: range.source,
        state: range.state,
        repositoryOwned: true,
        firstPatchedVersion: firstPatchedVersion(range.patchedVersions),
        patchedVersions: range.patchedVersions,
        updatedAt: null,
      })),
    ].sort((left, right) => compareBinary(canonicalJson(left), canonicalJson(right)));
    return {
      identity,
      ghsaId: base.ghsaId,
      ecosystem: base.ecosystem,
      packageName: base.packageName,
      vulnerableVersionRange: base.vulnerableVersionRange,
      targetPackage:
        base.ecosystem === target.ecosystem &&
        base.packageName === target.packageName,
      repositoryOwned: authorityMode === 'legacy_strict'
        ? observations.repository.length > 0
        : repositoryGhsaIds.has(base.ghsaId),
      packageGlobalOnly: authorityMode === 'legacy_strict'
        ? hasGraphql && observations.repository.length === 0
        : hasGraphql && !repositoryGhsaIds.has(base.ghsaId),
      state,
      scoreEligible,
      auditOnly: !scoreEligible,
      sourceObservations,
      advisory: authorityMode !== 'legacy_strict' &&
          graphql?.authorityShape === 'current'
        ? {
            cveId: graphql.cveId,
            summary: graphql.summary,
            severity: graphql.severity,
            state: graphql.state === 'active' ? 'published' as const : 'withdrawn' as const,
            publishedAt: graphql.publishedAt,
            withdrawnAt: graphql.withdrawnAt,
            htmlUrl: graphql.htmlUrl,
          }
        : repository
          ? {
              cveId: repository.advisory.cve_id,
              summary: repository.advisory.summary,
              severity: repository.advisory.severity,
              state: repository.advisory.state,
              publishedAt: repository.advisory.published_at,
              withdrawnAt: repository.advisory.withdrawn_at,
              htmlUrl: repository.advisory.html_url,
            }
          : null,
    };
  }).sort((left, right) => compareBinary(left.identity, right.identity));
}

function catalogCounts(
  rows: CompoundAdvisoryRangeRow[],
  graphqlRangeCount: number,
  repositoryRangeCount: number,
): CompoundAdvisoryCatalogCounts {
  const advisoryStates = new Map<string, Set<CompoundAdvisoryRangeState>>();
  for (const row of rows) {
    const states = advisoryStates.get(row.ghsaId) ?? new Set();
    states.add(row.state);
    advisoryStates.set(row.ghsaId, states);
  }
  return {
    advisoryCount: advisoryStates.size,
    activeAdvisoryCount: [...advisoryStates.values()]
      .filter((states) => states.has('active')).length,
    withdrawnAdvisoryCount: [...advisoryStates.values()]
      .filter((states) => !states.has('active') && states.has('withdrawn')).length,
    otherStateAdvisoryCount: [...advisoryStates.values()]
      .filter((states) =>
        !states.has('active') &&
        !states.has('withdrawn') &&
        (states.has('other') || states.has('conflicted'))).length,
    rangeCount: rows.length,
    activeRangeCount: rows.filter((row) => row.state === 'active').length,
    withdrawnRangeCount: rows.filter((row) => row.state === 'withdrawn').length,
    otherStateRangeCount: rows.filter((row) =>
      row.state === 'other' || row.state === 'conflicted').length,
    packageCount: new Set(rows.map((row) =>
      `${row.ecosystem}\0${row.packageName}`)).size,
    targetRangeCount: rows.filter((row) => row.targetPackage).length,
    foreignRangeCount: rows.filter((row) => !row.targetPackage).length,
    sourceObservationCount: graphqlRangeCount + repositoryRangeCount,
    scoreEligibleRangeCount: rows.filter((row) => row.scoreEligible).length,
  };
}

function sourcePagination(
  graphql: GhSecurityVulnerabilityCatalogObservation,
  repositoryRest: GhRepositoryAdvisoryCatalogObservation,
): {
  graphql: CompoundAdvisoryPaginationProof;
  repositoryRest: CompoundAdvisoryPaginationProof;
} {
  return {
    graphql: {
      exhausted: graphql.exhausted,
      stabilized: graphql.stabilized,
      completenessProven: graphql.exhausted && graphql.stabilized,
      totalCount: graphql.totalCount,
      nodeCount: graphql.nodeCount,
      pageCount: graphql.pageCount,
      pagesFetched: graphql.pagesFetched,
      sweepCount: graphql.sweepCount,
      terminalPageEvidence: 'graphql-total-count',
    },
    repositoryRest: {
      exhausted: repositoryRest.exhausted,
      stabilized: repositoryRest.stabilized,
      completenessProven: repositoryRest.completeness.terminalPageProven,
      totalCount: repositoryRest.totalCount,
      nodeCount: repositoryRest.observedAdvisoryCount,
      pageCount: repositoryRest.pageCount,
      pagesFetched: repositoryRest.pagesFetched,
      sweepCount: repositoryRest.sweepCount,
      terminalPageEvidence: repositoryRest.completeness.terminalPageEvidence,
    },
  };
}

function resolvedSources(input: CompoundAdvisorySnapshotInput): {
  graphql: GhSecurityVulnerabilityCatalogObservation;
  repositoryRest: GhRepositoryAdvisoryCatalogObservation;
} {
  const graphql = input.sources?.graphql ??
    input.observations?.securityVulnerabilities ??
    input.graphql;
  const repositoryRest = input.sources?.repositoryRest ??
    input.observations?.repositoryAdvisories ??
    input.repositoryRest;
  if (!graphql || !repositoryRest) {
    throw new Error(
      'Compound advisory snapshot requires GraphQL and repository REST source observations',
    );
  }
  return { graphql, repositoryRest };
}

export function buildCompoundAdvisorySnapshot(
  input: CompoundAdvisorySnapshotInput,
): CompoundAdvisorySnapshot {
  const problems: CompoundAdvisorySnapshotProblem[] = [];
  const authorityPolicy = resolveCompoundAdvisoryAuthorityPolicy(
    input.authorityPolicy,
  );
  const targetInput = input.target ?? DEFAULT_EXPECTED_ADVISORY_PACKAGE;
  const target = normalizedPackageIdentity(
    targetInput.ecosystem,
    targetInput.packageName,
  );
  const repository = {
    owner: String(input.repository?.owner ?? '').trim(),
    name: String(input.repository?.name ?? '').trim(),
    url: String(input.repository?.url ?? ''),
  };
  if (!isTimestamp(input.capturedAt)) {
    addCompoundProblem(problems, {
      code: 'invalid_snapshot_input',
      severity: 'blocking',
      source: 'compound-reconciliation',
      detail: 'capturedAt must be a valid timestamp',
    });
  }
  if (!target.ecosystem || !target.packageName) {
    addCompoundProblem(problems, {
      code: 'invalid_snapshot_input',
      severity: 'blocking',
      source: 'compound-reconciliation',
      detail: 'target package identity must be non-empty',
    });
  }
  if (
    !repository.owner ||
    !repository.name ||
    !validCanonicalRepositoryUrl(repository.url, repository.owner, repository.name)
  ) {
    addCompoundProblem(problems, {
      code: 'invalid_repository_identity',
      severity: 'blocking',
      source: 'compound-reconciliation',
      detail: `repository identity must use canonical URL ` +
        `${canonicalRepositoryUrl(repository.owner, repository.name)}`,
    });
  }

  const sourceInput = resolvedSources(input);
  const graphql = authorityPolicy.mode === 'legacy_strict'
    ? normalizedLegacyGraphqlObservation(sourceInput.graphql)
    : normalizedGraphqlObservation(sourceInput.graphql);
  const repositoryRest = normalizedRestObservation(sourceInput.repositoryRest);
  validateSourceRetrievalWindow(
    'graphql-security-vulnerabilities',
    graphql.retrieval,
    input.capturedAt,
    problems,
  );
  validateSourceRetrievalWindow(
    'repository-security-advisories-rest',
    repositoryRest.retrieval,
    input.capturedAt,
    problems,
  );
  const graphqlValidation = authorityPolicy.mode === 'legacy_strict'
    ? validateLegacyGraphqlObservation(graphql, target, problems)
    : validateGraphqlObservation(graphql, target, problems);
  const repositoryValidation = validateRepositoryObservation(
    repositoryRest,
    repository,
    target,
    problems,
    authorityPolicy.mode,
  );
  declaredReconciliationProblems(
    input.reconciliation,
    target,
    graphql,
    repositoryRest,
    problems,
    authorityPolicy.mode,
  );

  const graphqlGhsaIds = new Set(
    graphqlValidation.ranges.map((range) => range.ghsaId),
  );
  const repositoryGhsaByIdentity = new Map(
    repositoryValidation.ranges.map((range) => [range.identity, range.ghsaId]),
  );
  const coveredRepositoryProblemCodes = new Set<CompoundAdvisoryProblemCode>([
    'invalid_source_observation',
    'overlapping_source_ranges',
    'malformed_target_range',
    'malformed_target_patch',
  ]);
  const coveredRepositoryDivergenceIdentities = new Set<string>();
  for (const problem of problems) {
    if (
      authorityPolicy.mode === 'legacy_strict' ||
      problem.source !== 'repository-security-advisories-rest' ||
      !problem.rangeIdentity ||
      !coveredRepositoryProblemCodes.has(problem.code)
    ) {
      continue;
    }
    const ghsaId = repositoryGhsaByIdentity.get(problem.rangeIdentity);
    if (ghsaId && graphqlGhsaIds.has(ghsaId)) {
      if (problem.severity === 'blocking') {
        problem.severity = 'audit';
      }
      coveredRepositoryDivergenceIdentities.add(problem.rangeIdentity);
    }
  }

  const graphqlByIdentity = new Map(
    graphqlValidation.ranges.map((range) => [range.identity, range]),
  );
  const graphqlByGhsaId = new Map<string, NormalizedGraphqlRange[]>();
  const graphqlByAdvisoryPackage = new Map<string, NormalizedGraphqlRange[]>();
  for (const range of graphqlValidation.ranges) {
    const ghsaGroup = graphqlByGhsaId.get(range.ghsaId) ?? [];
    ghsaGroup.push(range);
    graphqlByGhsaId.set(range.ghsaId, ghsaGroup);
    const key = [range.ghsaId, range.ecosystem, range.packageName].join('\0');
    const group = graphqlByAdvisoryPackage.get(key) ?? [];
    group.push(range);
    graphqlByAdvisoryPackage.set(key, group);
  }

  const reconciled = new Set<string>();
  const missing = new Set<string>();
  const conflicting = new Set<string>();
  const reconciliationProblems = new Set<string>();
  const touchedGraphqlIdentities = new Set<string>();
  for (const identity of coveredRepositoryDivergenceIdentities) {
    conflicting.add(identity);
    const ghsaId = repositoryGhsaByIdentity.get(identity);
    for (const range of ghsaId ? graphqlByGhsaId.get(ghsaId) ?? [] : []) {
      touchedGraphqlIdentities.add(range.identity);
    }
  }
  const restActiveTarget = repositoryValidation.ranges.filter((range) =>
    range.targetPackage && range.state === 'active');
  const restWithdrawnTarget = repositoryValidation.ranges.filter((range) =>
    range.targetPackage && range.state === 'withdrawn');
  const restOtherTarget = repositoryValidation.ranges.filter((range) =>
    range.targetPackage && range.state === 'other');

  for (const range of restActiveTarget) {
    if (!range.validRange) {
      if (authorityPolicy.mode === 'legacy_strict') {
        reconciliationProblems.add(range.identity);
      }
      continue;
    }
    const exact = graphqlByIdentity.get(range.identity);
    if (!exact) {
      const key = [range.ghsaId, range.ecosystem, range.packageName].join('\0');
      const sameAdvisoryPackage = graphqlByAdvisoryPackage.get(key) ?? [];
      if (sameAdvisoryPackage.length > 0) {
        conflicting.add(range.identity);
        for (const candidate of sameAdvisoryPackage) {
          touchedGraphqlIdentities.add(candidate.identity);
        }
        addCompoundProblem(problems, {
          code: 'conflicting_reconciliation',
          severity: authorityPolicy.mode === 'legacy_strict' ? 'blocking' : 'audit',
          source: 'compound-reconciliation',
          rangeIdentity: range.identity,
          detail: authorityPolicy.mode === 'legacy_strict'
            ? `repository target range conflicts with GraphQL ranges ` +
              `${sameAdvisoryPackage.map((candidate) => candidate.identity).join(', ')}`
            : `repository target range differs from authoritative GraphQL ranges ` +
            `${sameAdvisoryPackage.map((candidate) => candidate.identity).join(', ')}`,
        });
      } else {
        missing.add(range.identity);
        addCompoundProblem(problems, {
          code: 'missing_reconciliation',
          severity: authorityPolicy.mode === 'legacy_strict' ? 'blocking' : 'audit',
          source: 'compound-reconciliation',
          rangeIdentity: range.identity,
          detail: authorityPolicy.mode === 'legacy_strict'
            ? 'active repository target range has no GraphQL package-global observation'
            : 'repository-only target range has no package-global GraphQL advisory',
        });
      }
      if (authorityPolicy.mode === 'legacy_strict') {
        reconciliationProblems.add(range.identity);
      }
      continue;
    }
    if (
      authorityPolicy.mode !== 'legacy_strict' &&
      exact.state !== 'active'
    ) {
      touchedGraphqlIdentities.add(exact.identity);
      conflicting.add(range.identity);
      addCompoundProblem(problems, {
        code: 'withdrawn_state_conflict',
        severity: 'audit',
        source: 'compound-reconciliation',
        rangeIdentity: range.identity,
        detail: 'active repository range is superseded by withdrawn GraphQL state',
      });
      continue;
    }
    const restPatch = firstPatchedVersion(range.patchedVersions);
    if (
      exact.firstPatchedVersion != null &&
      restPatch != null &&
      compareVersions(exact.firstPatchedVersion, restPatch) !== 0
    ) {
      touchedGraphqlIdentities.add(exact.identity);
      conflicting.add(range.identity);
      if (authorityPolicy.mode === 'legacy_strict') {
        reconciliationProblems.add(range.identity);
      }
      addCompoundProblem(problems, {
        code: 'conflicting_reconciliation',
        severity: authorityPolicy.mode === 'legacy_strict' ? 'blocking' : 'audit',
        source: 'compound-reconciliation',
        rangeIdentity: range.identity,
        detail: authorityPolicy.mode === 'legacy_strict'
          ? `GraphQL first patched version ${exact.firstPatchedVersion} != ` +
            `repository first patched version ${restPatch}`
          : `authoritative GraphQL first patched version ${exact.firstPatchedVersion} != ` +
            `repository first patched version ${restPatch}`,
      });
      continue;
    }
    const metadataConflicts = authorityPolicy.mode !== 'legacy_strict' &&
        exact.authorityShape === 'current'
      ? [
          exact.cveId !== range.advisory.cve_id ? 'CVE id' : null,
          normalizedAdvisoryText(exact.summary) !==
            normalizedAdvisoryText(range.advisory.summary)
            ? 'summary'
            : null,
          exact.severity !== range.advisory.severity ? 'severity' : null,
          exact.publishedAt !== range.advisory.published_at ? 'publishedAt' : null,
        ].filter((value): value is string => value != null)
      : [];
    if (metadataConflicts.length > 0) {
      touchedGraphqlIdentities.add(exact.identity);
      conflicting.add(range.identity);
      addCompoundProblem(problems, {
        code: 'conflicting_reconciliation',
        severity: 'audit',
        source: 'compound-reconciliation',
        rangeIdentity: range.identity,
        detail: `authoritative GraphQL and repository advisory metadata disagree on ` +
          metadataConflicts.join(', '),
      });
      continue;
    }
    touchedGraphqlIdentities.add(exact.identity);
    reconciled.add(range.identity);
  }
  for (const range of restWithdrawnTarget) {
    const exact = graphqlByIdentity.get(range.identity);
    if (!exact) continue;
    touchedGraphqlIdentities.add(range.identity);
    if (authorityPolicy.mode === 'legacy_strict') {
      conflicting.add(range.identity);
      reconciliationProblems.add(range.identity);
      addCompoundProblem(problems, {
        code: 'withdrawn_state_conflict',
        severity: 'blocking',
        source: 'compound-reconciliation',
        rangeIdentity: range.identity,
        detail: 'withdrawn repository range is still present in the active GraphQL catalog',
      });
      continue;
    }
    if (exact.state === 'active') {
      conflicting.add(range.identity);
      addCompoundProblem(problems, {
        code: 'withdrawn_state_conflict',
        severity: 'audit',
        source: 'compound-reconciliation',
        rangeIdentity: range.identity,
        detail: 'withdrawn repository range is superseded by active GraphQL state',
      });
      continue;
    }
    const metadataConflicts = exact.authorityShape === 'current'
      ? [
          exact.cveId !== range.advisory.cve_id ? 'CVE id' : null,
          normalizedAdvisoryText(exact.summary) !==
            normalizedAdvisoryText(range.advisory.summary)
            ? 'summary'
            : null,
          exact.severity !== range.advisory.severity ? 'severity' : null,
          exact.publishedAt !== range.advisory.published_at ? 'publishedAt' : null,
          exact.withdrawnAt !== range.advisory.withdrawn_at ? 'withdrawnAt' : null,
        ].filter((value): value is string => value != null)
      : [];
    if (metadataConflicts.length > 0) {
      conflicting.add(range.identity);
      addCompoundProblem(problems, {
        code: 'conflicting_reconciliation',
        severity: 'audit',
        source: 'compound-reconciliation',
        rangeIdentity: range.identity,
        detail: `authoritative GraphQL and repository withdrawn advisory metadata disagree on ` +
          metadataConflicts.join(', '),
      });
      continue;
    }
    reconciled.add(range.identity);
  }
  if (authorityPolicy.mode !== 'legacy_strict') {
    for (const range of restOtherTarget) {
      const graphqlRanges = graphqlByGhsaId.get(range.ghsaId) ?? [];
      if (graphqlRanges.length === 0) continue;
      conflicting.add(range.identity);
      for (const graphqlRange of graphqlRanges) {
        touchedGraphqlIdentities.add(graphqlRange.identity);
      }
      addCompoundProblem(problems, {
        code: 'conflicting_reconciliation',
        severity: 'audit',
        source: 'compound-reconciliation',
        rangeIdentity: range.identity,
        detail: `repository advisory state ${JSON.stringify(range.advisory.state)} ` +
          `differs from authoritative GraphQL state`,
      });
    }
  }
  for (const identity of coveredRepositoryDivergenceIdentities) {
    reconciled.delete(identity);
  }

  if (
    authorityPolicy.mode !== 'legacy_strict' &&
    missing.size > 0 &&
    !repositoryRest.completeness.terminalPageProven
  ) {
    addCompoundProblem(problems, {
      code: 'unproven_repository_completeness',
      severity: 'blocking',
      source: 'repository-security-advisories-rest',
      detail: `${missing.size} repository-only target range(s) require a complete ` +
        `repository advisory catalog before they can become score authority`,
    });
  }

  const additionalGraphqlRangeIdentities = sortedUnique(
    graphqlValidation.ranges
      .filter((range) => !touchedGraphqlIdentities.has(range.identity))
      .map((range) => range.identity),
  );
  const ineligibleRangeIdentities = new Set([
    ...(authorityPolicy.mode === 'legacy_strict'
      ? [...reconciliationProblems]
      : []),
    ...problems.flatMap((problem) =>
      problem.severity === 'blocking' && problem.rangeIdentity
        ? [problem.rangeIdentity]
        : []),
  ]);
  const rows = buildCompoundRows(
    graphqlValidation.ranges,
    repositoryValidation.ranges,
    ineligibleRangeIdentities,
    target,
    repositoryRest.completeness.terminalPageProven,
    authorityPolicy.mode,
  );
  const counts = catalogCounts(
    rows,
    graphqlValidation.ranges.length,
    repositoryValidation.ranges.length,
  );

  problems.sort((left, right) =>
    compareBinary(problemSortKey(left), problemSortKey(right)));
  const blockingProblems = problems.filter((problem) => problem.severity === 'blocking');
  const auditProblems = problems.filter((problem) => problem.severity === 'audit');
  const pagination = sourcePagination(graphql, repositoryRest);
  const reconciliationContent = {
    restActiveTargetRangeCount: restActiveTarget.length,
    restWithdrawnTargetRangeCount: restWithdrawnTarget.length,
    reconciledRangeIdentities: sortedUnique([...reconciled]),
    missingRangeIdentities: sortedUnique([...missing]),
    conflictingRangeIdentities: sortedUnique([...conflicting]),
    additionalGraphqlRangeIdentities,
  };
  const reconciliationBlocked = problems.some((problem) =>
    problem.severity === 'blocking' &&
    (
      problem.code === 'missing_reconciliation' ||
      problem.code === 'conflicting_reconciliation' ||
      problem.code === 'declared_reconciliation_mismatch' ||
      problem.code === 'withdrawn_state_conflict' ||
      problem.code === 'unproven_repository_completeness'
    ));
  const reconciliationDivergent =
    missing.size > 0 || conflicting.size > 0;
  const reconciliationStatusBlocked = authorityPolicy.mode === 'legacy_strict'
    ? reconciliationBlocked ||
      restActiveTarget.some((range) => !range.validRange)
    : blockingProblems.length > 0;
  const reconciliation: CompoundAdvisoryReconciliation = {
    status: reconciliationStatusBlocked
      ? 'blocked'
      : authorityPolicy.mode !== 'legacy_strict' && reconciliationDivergent
        ? 'divergent'
        : 'reconciled',
    declared: input.reconciliation != null,
    restActiveTargetRangeCount: restActiveTarget.length,
    restWithdrawnTargetRangeCount: restWithdrawnTarget.length,
    reconciledRangeCount: reconciled.size,
    missingRangeIdentities: reconciliationContent.missingRangeIdentities,
    conflictingRangeIdentities: reconciliationContent.conflictingRangeIdentities,
    additionalGraphqlRangeIdentities,
    contentHash: compoundHash(
      'openclaw-release-radar.advisory-reconciliation.v2',
      reconciliationContent,
    ),
  };
  const authorityPolicyHashBinding = authorityPolicy.marker
    ? { authorityPolicy: authorityPolicy.marker }
    : {};

  const sourceHash = compoundHash(
    'openclaw-release-radar.advisory-source.v2',
    {
      repository,
      target,
      ...authorityPolicyHashBinding,
      graphql,
      repositoryRest,
    },
  );
  const catalogHash = compoundHash(
    'openclaw-release-radar.advisory-catalog.v2',
    {
      repository,
      target,
      ...authorityPolicyHashBinding,
      counts,
      rows,
      reconciliation: {
        status: reconciliation.status,
        restActiveTargetRangeCount: reconciliation.restActiveTargetRangeCount,
        restWithdrawnTargetRangeCount: reconciliation.restWithdrawnTargetRangeCount,
        reconciledRangeCount: reconciliation.reconciledRangeCount,
        missingRangeIdentities: reconciliation.missingRangeIdentities,
        conflictingRangeIdentities: reconciliation.conflictingRangeIdentities,
        additionalGraphqlRangeIdentities:
          reconciliation.additionalGraphqlRangeIdentities,
        contentHash: reconciliation.contentHash,
      },
    },
  );
  const scoreRows = rows.filter((row) => row.scoreEligible);
  const scoreHash = compoundHash(
    'openclaw-release-radar.advisory-score.v2',
    {
      repository,
      target,
      ...authorityPolicyHashBinding,
      rows: scoreRows.map((row) => {
        const graphqlObservation = row.sourceObservations.find((observation) =>
          observation.source === 'graphql-security-vulnerabilities');
        const repositoryObservation = row.sourceObservations.find((observation) =>
          observation.source === 'repository-security-advisories-rest');
        const authorityObservation = graphqlObservation ?? repositoryObservation ?? null;
        const common = {
          identity: row.identity,
          ghsaId: row.ghsaId,
          ecosystem: row.ecosystem,
          packageName: row.packageName,
          vulnerableVersionRange: row.vulnerableVersionRange,
        };
        if (authorityPolicy.mode === 'legacy_strict') {
          return {
            ...common,
            firstPatchedVersion: graphqlObservation?.firstPatchedVersion ?? null,
            state: row.state,
          };
        }
        return {
          ...common,
          firstPatchedVersion: authorityObservation?.firstPatchedVersion ?? null,
          advisory: row.advisory,
          state: authorityObservation?.state ?? row.state,
        };
      }),
    },
  );
  const score: CompoundAdvisoryScoreProjection = {
    ready: blockingProblems.length === 0,
    rangeCount: scoreRows.length,
    rangeIdentities: scoreRows.map((row) => row.identity),
    rows: scoreRows,
    hash: scoreHash,
  };

  return {
    schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    ...(authorityPolicy.marker
      ? { authorityPolicy: authorityPolicy.marker }
      : {}),
    capturedAt: input.capturedAt,
    repository,
    target,
    sourceObservations: {
      graphql: {
        source: 'graphql-security-vulnerabilities',
        observation: graphql,
        counts: graphqlValidation.counts,
        pagination: pagination.graphql,
      },
      repositoryRest: {
        source: 'repository-security-advisories-rest',
        observation: repositoryRest,
        counts: repositoryValidation.counts,
        pagination: pagination.repositoryRest,
      },
    },
    counts,
    rows,
    reconciliation,
    problems,
    blockingProblems,
    auditProblems,
    hashes: { sourceHash, catalogHash, scoreHash },
    sourceHash,
    catalogHash,
    scoreHash,
    score,
  };
}

export const buildAdvisorySnapshotV2 = buildCompoundAdvisorySnapshot;
export const createCompoundAdvisorySnapshot = buildCompoundAdvisorySnapshot;
export type AdvisorySnapshotV2 = CompoundAdvisorySnapshot;
export type AdvisorySnapshotV2Input = CompoundAdvisorySnapshotInput;

export function compoundAdvisorySnapshotIntegrityProblems(
  snapshot: CompoundAdvisorySnapshot,
): string[] {
  const problems: string[] = [];
  if (snapshot.schemaVersion !== COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION) {
    problems.push(
      `schemaVersion ${String(snapshot.schemaVersion)} != ` +
        COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    );
    return problems;
  }
  let rebuilt: CompoundAdvisorySnapshot;
  const authorityPolicyPresent = Object.prototype.hasOwnProperty.call(
    snapshot,
    'authorityPolicy',
  );
  try {
    rebuilt = buildCompoundAdvisorySnapshot({
      capturedAt: snapshot.capturedAt,
      repository: snapshot.repository,
      target: snapshot.target,
      authorityPolicy: authorityPolicyPresent
        ? snapshot.authorityPolicy
        : null,
      sources: {
        graphql: snapshot.sourceObservations.graphql.observation,
        repositoryRest: snapshot.sourceObservations.repositoryRest.observation,
      },
    });
  } catch (error) {
    return [
      `snapshot sources cannot be rebuilt: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    ];
  }
  const rebuiltAuthorityPolicyPresent = Object.prototype.hasOwnProperty.call(
    rebuilt,
    'authorityPolicy',
  );
  if (
    authorityPolicyPresent !== rebuiltAuthorityPolicyPresent ||
    canonicalJson(snapshot.authorityPolicy) !== canonicalJson(rebuilt.authorityPolicy)
  ) {
    problems.push('authority policy does not match canonical source reconstruction');
  }
  const comparisons: Array<[string, unknown, unknown]> = [
    ['repository', snapshot.repository, rebuilt.repository],
    ['target', snapshot.target, rebuilt.target],
    ['source observations', snapshot.sourceObservations, rebuilt.sourceObservations],
    ['counts', snapshot.counts, rebuilt.counts],
    ['rows', snapshot.rows, rebuilt.rows],
    ['problems', snapshot.problems, rebuilt.problems],
    ['blocking problems', snapshot.blockingProblems, rebuilt.blockingProblems],
    ['audit problems', snapshot.auditProblems, rebuilt.auditProblems],
    ['source hash', snapshot.sourceHash, rebuilt.sourceHash],
    ['catalog hash', snapshot.catalogHash, rebuilt.catalogHash],
    ['score hash', snapshot.scoreHash, rebuilt.scoreHash],
    ['hash bundle', snapshot.hashes, rebuilt.hashes],
    ['score projection', snapshot.score, rebuilt.score],
  ];
  for (const [label, actual, expected] of comparisons) {
    if (canonicalJson(actual) !== canonicalJson(expected)) {
      problems.push(`${label} does not match canonical source reconstruction`);
    }
  }
  const reconciliationWithoutDeclared = (
    value: CompoundAdvisoryReconciliation,
  ): Omit<CompoundAdvisoryReconciliation, 'declared'> => {
    const { declared: _declared, ...rest } = value;
    return rest;
  };
  if (
    canonicalJson(reconciliationWithoutDeclared(snapshot.reconciliation)) !==
    canonicalJson(reconciliationWithoutDeclared(rebuilt.reconciliation))
  ) {
    problems.push('reconciliation does not match canonical source reconstruction');
  }
  return problems;
}

export function assertCompoundAdvisorySnapshotScoreable(
  snapshot: CompoundAdvisorySnapshot,
): void {
  const integrityProblems = compoundAdvisorySnapshotIntegrityProblems(snapshot);
  if (integrityProblems.length > 0) {
    throw new Error(
      `Compound advisory snapshot integrity failed: ${integrityProblems.join('; ')}`,
    );
  }
  if (snapshot.score.ready) return;
  throw new Error(
    `Compound advisory snapshot is not scoreable: ` +
      snapshot.blockingProblems.map((problem) =>
        `${problem.code}:${problem.detail}`).join('; '),
  );
}

export function compoundAdvisoryScoreRows(
  snapshot: CompoundAdvisorySnapshot,
): AdvisorySnapshotContentRow[] {
  assertCompoundAdvisorySnapshotScoreable(snapshot);
  const rows = snapshot.score.rows.map((row): AdvisorySnapshotContentRow => {
    const advisory = row.advisory;
    const graphql = row.sourceObservations.find((observation) =>
      observation.source === 'graphql-security-vulnerabilities');
    const repository = row.sourceObservations.find((observation) =>
      observation.source === 'repository-security-advisories-rest');
    const authority = graphql ?? repository;
    if (!advisory || advisory.state !== 'published' || !authority) {
      throw new Error(
        `Score-eligible advisory range ${row.identity} lacks active advisory authority metadata`,
      );
    }
    return {
      advisory_key: row.identity,
      ghsa_id: row.ghsaId,
      cve_id: advisory.cveId,
      summary: advisory.summary,
      severity: advisory.severity,
      html_url: advisory.htmlUrl,
      published_at: advisory.publishedAt,
      package_ecosystem: row.ecosystem,
      package_name: row.packageName,
      vulnerable_version_range: row.vulnerableVersionRange,
      patched_versions: graphql
        ? graphql.firstPatchedVersion
        : repository?.patchedVersions ?? null,
    };
  }).sort((left, right) => compareBinary(left.advisory_key, right.advisory_key));
  const rowProblems = advisorySnapshotRowProblems(rows, snapshot.target);
  if (rowProblems.length > 0) {
    throw new Error(
      `Compound advisory score projection is invalid: ` +
        rowProblems.map((problem) =>
          `${problem.code}:${problem.advisoryKey}:${problem.detail}`).join('; '),
    );
  }
  return rows;
}
