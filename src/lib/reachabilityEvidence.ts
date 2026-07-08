export const REACHABILITY_EVIDENCE_SCHEMA_VERSION = 1 as const;
export const REACHABILITY_METHOD = 'git-merge-base' as const;

export const REACHABILITY_STATUSES = [
  'reachable',
  'not_reachable',
  'unknown',
] as const;

export type ReachabilityStatus = typeof REACHABILITY_STATUSES[number];

export const KNOWN_REACHABILITY_EVIDENCE_REASONS = [
  'merge_commit_in_release_history',
  'fix_commit_in_release_history',
  'predecessor_release_in_target_history',
  'not_reachable_from_release_tag',
  'release_commit_unavailable',
  'release_commit_fetch_failed',
  'merge_commit_oid_unavailable',
  'commit_fetch_failed',
  'commit_unavailable',
  'merge_base_error',
] as const;

export type ReachabilityEvidenceReason =
  typeof KNOWN_REACHABILITY_EVIDENCE_REASONS[number];

export const REACHABILITY_EVIDENCE_VALIDATION_REASON_CODES = [
  'malformed_json',
  'evidence_not_object',
  'missing_required_field',
  'schema_version_mismatch',
  'method_mismatch',
  'invalid_status',
  'unknown_reason',
  'status_reason_mismatch',
  'proof_kind_reason_mismatch',
  'invalid_repository_identity',
  'repository_identity_mismatch',
  'catalog_proof_missing',
  'catalog_proof_unexpected',
  'catalog_proof_not_object',
  'catalog_proof_keys_mismatch',
  'invalid_catalog_digest',
  'catalog_digest_mismatch',
  'invalid_catalog_receipt_id',
  'catalog_receipt_id_mismatch',
  'invalid_release_node_id',
  'release_node_id_mismatch',
  'invalid_checked_release_node_id',
  'checked_release_node_id_mismatch',
  'invalid_tag_commit_oid',
  'tag_commit_oid_mismatch',
  'invalid_checked_commit_oid',
  'checked_commit_oid_mismatch',
  'invalid_base_ref',
  'base_ref_mismatch',
  'invalid_command_status',
  'invalid_command_diagnostics',
  'invalid_process_tree_diagnostics',
  'command_status_reason_mismatch',
  'unknown_error_evidence_missing',
  'confirmed_unavailable_mismatch',
] as const;

export type ReachabilityEvidenceValidationReasonCode =
  typeof REACHABILITY_EVIDENCE_VALIDATION_REASON_CODES[number];

export interface ReachabilityCatalogProofIdentity {
  catalogDigest: string;
  catalogReceiptId: string;
  releaseNodeId: string;
  checkedReleaseNodeId: string | null;
}

export interface PullRequestReachabilityProofIdentity {
  kind: 'pull_request';
  tagCommitOid: string;
  checkedCommitOid: string | null;
  baseRefName: string | null;
  catalogProof?: ReachabilityCatalogProofIdentity;
}

export interface DirectCommitReachabilityProofIdentity {
  kind: 'direct_commit';
  repositoryNameWithOwner: string;
  tagCommitOid: string;
  checkedCommitOid: string;
  catalogProof?: ReachabilityCatalogProofIdentity;
}

export interface ReleaseBoundaryReachabilityProofIdentity {
  kind: 'release_boundary';
  repositoryNameWithOwner: string;
  tagCommitOid: string;
  checkedCommitOid: string;
  catalogProof?: ReachabilityCatalogProofIdentity;
}

export type ReachabilityProofIdentity =
  | PullRequestReachabilityProofIdentity
  | DirectCommitReachabilityProofIdentity
  | ReleaseBoundaryReachabilityProofIdentity;

export type TrustedDbReachabilityProofIdentity =
  ReachabilityProofIdentity & {
    catalogProof: ReachabilityCatalogProofIdentity;
  };

export interface ReachabilityEvidence {
  schemaVersion: typeof REACHABILITY_EVIDENCE_SCHEMA_VERSION;
  evidence: ReachabilityEvidenceReason;
  method: typeof REACHABILITY_METHOD;
  repositoryNameWithOwner?: string;
  catalogProof?: ReachabilityCatalogProofIdentity;
  tagCommitOid: string;
  checkedCommitOid: string | null;
  baseRefName: string | null;
  commandStatus: number | null;
  stdout: string | null;
  stderr: string | null;
  signal: string | null;
  timedOut: boolean;
  outputLimitExceeded: boolean;
  aborted: boolean;
  processTreeTerminationFailed?: boolean;
  confirmedUnavailable?: true;
}

export interface ReachabilityEvidenceValidationInput {
  evidence: unknown;
  method: string;
  status: ReachabilityStatus;
  identity: ReachabilityProofIdentity;
}

export type ReachabilityEvidenceValidationResult =
  | {
      valid: true;
      evidence: ReachabilityEvidence;
      confirmedUnavailable: boolean;
    }
  | {
      valid: false;
      reasonCode: ReachabilityEvidenceValidationReasonCode;
    };

const FULL_COMMIT_OID_RE = /^[0-9a-f]{40}$/;
const REQUIRED_FIELDS = [
  'schemaVersion',
  'evidence',
  'method',
  'tagCommitOid',
  'checkedCommitOid',
  'baseRefName',
  'commandStatus',
  'stdout',
  'stderr',
  'signal',
  'timedOut',
  'outputLimitExceeded',
  'aborted',
] as const;
const STATUS_SET = new Set<string>(REACHABILITY_STATUSES);
const REASON_SET = new Set<string>(KNOWN_REACHABILITY_EVIDENCE_REASONS);
const CATALOG_PROOF_KEYS = [
  'catalogDigest',
  'catalogReceiptId',
  'releaseNodeId',
  'checkedReleaseNodeId',
] as const;

export function validateReachabilityEvidence(
  input: ReachabilityEvidenceValidationInput,
): ReachabilityEvidenceValidationResult {
  const parsed = parseEvidence(input.evidence);
  if (!parsed.valid) return parsed;
  const evidence = parsed.evidence;

  if (REQUIRED_FIELDS.some((field) => !hasOwn(evidence, field))) {
    return invalid('missing_required_field');
  }
  if (evidence.schemaVersion !== REACHABILITY_EVIDENCE_SCHEMA_VERSION) {
    return invalid('schema_version_mismatch');
  }
  if (input.method !== REACHABILITY_METHOD || evidence.method !== REACHABILITY_METHOD) {
    return invalid('method_mismatch');
  }
  if (!STATUS_SET.has(input.status)) return invalid('invalid_status');
  if (typeof evidence.evidence !== 'string' || !REASON_SET.has(evidence.evidence)) {
    return invalid('unknown_reason');
  }

  const reason = evidence.evidence as ReachabilityEvidenceReason;
  if (statusForReason(reason) !== input.status) {
    return invalid('status_reason_mismatch');
  }
  if (!reasonIsAllowedForIdentity(reason, input.identity)) {
    return invalid('proof_kind_reason_mismatch');
  }

  if (input.identity.kind !== 'pull_request') {
    if (!isRepositoryIdentity(input.identity.repositoryNameWithOwner) ||
      !isRepositoryIdentity(evidence.repositoryNameWithOwner)) {
      return invalid('invalid_repository_identity');
    }
    if (normalizeRepositoryIdentity(evidence.repositoryNameWithOwner) !==
      normalizeRepositoryIdentity(input.identity.repositoryNameWithOwner)) {
      return invalid('repository_identity_mismatch');
    }
  }

  const catalogProofProblem = catalogProofValidationProblem(
    evidence.catalogProof,
    hasOwn(evidence, 'catalogProof'),
    input.identity,
  );
  if (catalogProofProblem) return invalid(catalogProofProblem);

  if (!isFullCommitOid(input.identity.tagCommitOid) || !isFullCommitOid(evidence.tagCommitOid)) {
    return invalid('invalid_tag_commit_oid');
  }
  if (normalizeOid(evidence.tagCommitOid) !== normalizeOid(input.identity.tagCommitOid)) {
    return invalid('tag_commit_oid_mismatch');
  }

  if (!identityCheckedCommitIsValid(input.identity, reason) ||
    !evidenceCheckedCommitIsValid(evidence.checkedCommitOid, reason)) {
    return invalid('invalid_checked_commit_oid');
  }
  if (normalizeNullableOid(evidence.checkedCommitOid) !==
    normalizeNullableOid(input.identity.checkedCommitOid)) {
    return invalid('checked_commit_oid_mismatch');
  }

  if (!baseRefIsValid(evidence.baseRefName) ||
    (input.identity.kind === 'pull_request' && !baseRefIsValid(input.identity.baseRefName))) {
    return invalid('invalid_base_ref');
  }
  const expectedBaseRefName = input.identity.kind === 'pull_request'
    ? input.identity.baseRefName
    : null;
  if (evidence.baseRefName !== expectedBaseRefName) {
    return invalid('base_ref_mismatch');
  }

  if (!commandStatusIsValid(evidence.commandStatus)) {
    return invalid('invalid_command_status');
  }
  if (!commandDiagnosticsAreValid(evidence)) {
    return invalid('invalid_command_diagnostics');
  }
  if (hasOwn(evidence, 'processTreeTerminationFailed') &&
    typeof evidence.processTreeTerminationFailed !== 'boolean') {
    return invalid('invalid_process_tree_diagnostics');
  }

  const confirmedUnavailablePresent = hasOwn(evidence, 'confirmedUnavailable');
  if (reason === 'commit_unavailable') {
    if (evidence.confirmedUnavailable !== true) {
      return invalid('confirmed_unavailable_mismatch');
    }
  } else if (confirmedUnavailablePresent) {
    return invalid('confirmed_unavailable_mismatch');
  }

  if (reason === 'merge_commit_oid_unavailable') {
    if (evidence.commandStatus !== null || hasCommandDiagnostics(evidence)) {
      return invalid('command_status_reason_mismatch');
    }
  } else if (input.status === 'reachable') {
    if (evidence.commandStatus !== 0 || hasCommandDiagnostics(evidence)) {
      return invalid('command_status_reason_mismatch');
    }
  } else if (input.status === 'not_reachable') {
    if (evidence.commandStatus !== 1 || hasCommandDiagnostics(evidence)) {
      return invalid('command_status_reason_mismatch');
    }
  } else {
    if (evidence.commandStatus === 0 ||
      (reason === 'merge_base_error' && evidence.commandStatus === 1)) {
      return invalid('command_status_reason_mismatch');
    }
    if (!hasUnknownErrorEvidence(evidence)) {
      return invalid('unknown_error_evidence_missing');
    }
  }

  return {
    valid: true,
    evidence: evidence as unknown as ReachabilityEvidence,
    confirmedUnavailable: reason === 'commit_unavailable',
  };
}

function parseEvidence(
  value: unknown,
): { valid: true; evidence: Record<string, unknown> } |
  { valid: false; reasonCode: ReachabilityEvidenceValidationReasonCode } {
  let parsed = value;
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value);
    } catch {
      return invalid('malformed_json');
    }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return invalid('evidence_not_object');
  }
  return { valid: true, evidence: parsed as Record<string, unknown> };
}

function catalogProofValidationProblem(
  evidenceValue: unknown,
  evidencePresent: boolean,
  identity: ReachabilityProofIdentity,
): ReachabilityEvidenceValidationReasonCode | null {
  const expected = identity.catalogProof;
  if (!expected) {
    return evidencePresent ? 'catalog_proof_unexpected' : null;
  }
  if (!evidencePresent) return 'catalog_proof_missing';

  const expectedProblem = catalogProofShapeProblem(expected, identity.kind);
  if (expectedProblem) return expectedProblem;
  if (!isRecord(evidenceValue)) return 'catalog_proof_not_object';
  if (!hasExactKeys(evidenceValue, CATALOG_PROOF_KEYS)) {
    return 'catalog_proof_keys_mismatch';
  }

  const evidenceProblem = catalogProofShapeProblem(evidenceValue, identity.kind);
  if (evidenceProblem) return evidenceProblem;
  if (evidenceValue.catalogDigest !== expected.catalogDigest) {
    return 'catalog_digest_mismatch';
  }
  if (evidenceValue.catalogReceiptId !== expected.catalogReceiptId) {
    return 'catalog_receipt_id_mismatch';
  }
  if (evidenceValue.releaseNodeId !== expected.releaseNodeId) {
    return 'release_node_id_mismatch';
  }
  if (evidenceValue.checkedReleaseNodeId !== expected.checkedReleaseNodeId) {
    return 'checked_release_node_id_mismatch';
  }
  return null;
}

function catalogProofShapeProblem(
  value: ReachabilityCatalogProofIdentity | Record<string, unknown>,
  proofKind: ReachabilityProofIdentity['kind'],
): ReachabilityEvidenceValidationReasonCode | null {
  if (!isSha256(value.catalogDigest)) return 'invalid_catalog_digest';
  if (!isSha256(value.catalogReceiptId)) return 'invalid_catalog_receipt_id';
  if (!isCanonicalNodeId(value.releaseNodeId)) return 'invalid_release_node_id';
  if (proofKind === 'release_boundary') {
    if (!isCanonicalNodeId(value.checkedReleaseNodeId)) {
      return 'invalid_checked_release_node_id';
    }
  } else if (value.checkedReleaseNodeId !== null) {
    return 'invalid_checked_release_node_id';
  }
  return null;
}

function reasonIsAllowedForIdentity(
  reason: ReachabilityEvidenceReason,
  identity: ReachabilityProofIdentity,
): boolean {
  if (reason === 'merge_commit_in_release_history') {
    return identity.kind === 'pull_request';
  }
  if (reason === 'fix_commit_in_release_history') {
    return identity.kind === 'direct_commit';
  }
  if (reason === 'predecessor_release_in_target_history') {
    return identity.kind === 'release_boundary';
  }
  if (reason === 'merge_commit_oid_unavailable') {
    return identity.kind === 'pull_request' && identity.checkedCommitOid === null;
  }
  return identity.kind === 'pull_request' ||
    identity.kind === 'direct_commit' ||
    identity.kind === 'release_boundary';
}

function statusForReason(reason: ReachabilityEvidenceReason): ReachabilityStatus {
  if (reason === 'merge_commit_in_release_history' ||
    reason === 'fix_commit_in_release_history' ||
    reason === 'predecessor_release_in_target_history') {
    return 'reachable';
  }
  if (reason === 'not_reachable_from_release_tag') return 'not_reachable';
  return 'unknown';
}

function identityCheckedCommitIsValid(
  identity: ReachabilityProofIdentity,
  reason: ReachabilityEvidenceReason,
): boolean {
  if (reason === 'merge_commit_oid_unavailable') {
    return identity.kind === 'pull_request' && identity.checkedCommitOid === null;
  }
  return isFullCommitOid(identity.checkedCommitOid);
}

function evidenceCheckedCommitIsValid(
  value: unknown,
  reason: ReachabilityEvidenceReason,
): boolean {
  if (reason === 'merge_commit_oid_unavailable') return value === null;
  return isFullCommitOid(value);
}

function isFullCommitOid(value: unknown): value is string {
  return typeof value === 'string' && FULL_COMMIT_OID_RE.test(normalizeOid(value));
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isCanonicalNodeId(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.trim() === value;
}

function normalizeOid(value: string): string {
  return value.trim().toLowerCase();
}

function isRepositoryIdentity(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const normalized = value.trim();
  return /^[^/\s]+\/[^/\s]+$/.test(normalized);
}

function normalizeRepositoryIdentity(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeNullableOid(value: unknown): string | null {
  return typeof value === 'string' ? normalizeOid(value) : null;
}

function baseRefIsValid(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && value.trim().length > 0);
}

function commandStatusIsValid(value: unknown): value is number | null {
  return value === null || (Number.isInteger(value) && Number(value) >= 0);
}

function commandDiagnosticsAreValid(evidence: Record<string, unknown>): boolean {
  return nullableNonEmptyStringIsValid(evidence.stdout) &&
    nullableNonEmptyStringIsValid(evidence.stderr) &&
    nullableNonEmptyStringIsValid(evidence.signal) &&
    typeof evidence.timedOut === 'boolean' &&
    typeof evidence.outputLimitExceeded === 'boolean' &&
    typeof evidence.aborted === 'boolean';
}

function nullableNonEmptyStringIsValid(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && value.trim().length > 0);
}

function hasCommandDiagnostics(evidence: Record<string, unknown>): boolean {
  return evidence.stdout !== null ||
    evidence.stderr !== null ||
    evidence.signal !== null ||
    evidence.timedOut === true ||
    evidence.outputLimitExceeded === true ||
    evidence.aborted === true ||
    evidence.processTreeTerminationFailed === true;
}

function hasUnknownErrorEvidence(evidence: Record<string, unknown>): boolean {
  return (typeof evidence.commandStatus === 'number' && evidence.commandStatus !== 0) ||
    hasCommandDiagnostics(evidence);
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const canonicalExpected = [...expected].sort();
  return actual.length === canonicalExpected.length &&
    actual.every((key, index) => key === canonicalExpected[index]);
}

function invalid(
  reasonCode: ReachabilityEvidenceValidationReasonCode,
): { valid: false; reasonCode: ReachabilityEvidenceValidationReasonCode } {
  return { valid: false, reasonCode };
}
