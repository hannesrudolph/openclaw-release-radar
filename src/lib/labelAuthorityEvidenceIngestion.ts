import {
  createHash,
  createHmac,
  timingSafeEqual,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  approvedMaintainerRosterEntryRowHash,
  labelAuthorityEvidenceProblems,
  repositoryPermissionObservationRowHash,
  type ApprovedMaintainerRosterEntry,
  type LabelAuthorityEvidence,
  type RepositoryPermission,
  type RepositoryPermissionObservation,
} from './labelAuthority';

export const COLLABORATOR_PERMISSION_SNAPSHOT_SCHEMA_VERSION = 2 as const;
export const APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION = 2 as const;
export const APPROVED_ROSTER_KEYRING_SCHEMA_VERSION = 1 as const;
export const APPROVED_ROSTER_CHAIN_STATE_SCHEMA_VERSION = 1 as const;
export const APPROVED_ROSTER_PURPOSE = 'label_authority_approved_roster' as const;
export const APPROVED_ROSTER_KEYRING_PURPOSE =
  'label_authority_approved_roster_keyring' as const;
export const APPROVED_ROSTER_SIGNATURE_ALGORITHM = 'hmac-sha256' as const;

const PERMISSIONS = new Set<RepositoryPermission>([
  'admin',
  'maintain',
  'write',
  'triage',
  'read',
  'none',
]);
const ROSTER_MANIFEST_KEYS = new Set([
  'schemaVersion',
  'purpose',
  'repositoryNodeId',
  'repository',
  'approvalId',
  'approvedAt',
  'sequence',
  'priorDigest',
  'signerKeyId',
  'entries',
  'signature',
]);
const ROSTER_ENTRY_KEYS = new Set([
  'actorNodeId',
  'login',
  'actorType',
  'association',
  'role',
  'effectiveFrom',
  'effectiveUntil',
]);
const KEYRING_KEYS = new Set([
  'schemaVersion',
  'purpose',
  'repositoryNodeId',
  'repository',
  'keys',
]);
const KEYRING_ENTRY_KEYS = new Set([
  'keyId',
  'algorithm',
  'secret',
  'validFrom',
  'validUntil',
  'revokedAt',
]);
const CHAIN_STATE_KEYS = new Set([
  'schemaVersion',
  'purpose',
  'repositoryNodeId',
  'sequence',
  'runDigest',
]);
const APPROVED_ROSTER_SNAPSHOT_KEYS = new Set([
  'snapshotId',
  'schemaVersion',
  'purpose',
  'repositoryNodeId',
  'repository',
  'approvalId',
  'approvedAt',
  'sequence',
  'priorDigest',
  'signerKeyId',
  'keyringDigest',
  'signatureAlgorithm',
  'signature',
  'signatureVerifiedAt',
  'rowCount',
  'contentDigest',
  'rowsContentHash',
  'signedPayloadJson',
  'contentHash',
  'runHash',
  'sourceIdentity',
  'entries',
]);
const APPROVED_ROSTER_SNAPSHOT_ENTRY_KEYS = new Set([
  'kind',
  'evidenceId',
  'sourceIdentity',
  'approvalId',
  'approvedAt',
  'repositoryNodeId',
  'repository',
  'actorNodeId',
  'actorLogin',
  'actorType',
  'actorAssociation',
  'role',
  'effectiveFrom',
  'effectiveUntil',
  'rosterSequence',
  'rosterRunDigest',
  'signerKeyId',
  'keyringDigest',
  'signatureVerifiedAt',
  'entryOrdinal',
  'rawJson',
  'contentHash',
  'rowHash',
]);
const KEYRING_SECRETS = new WeakMap<object, ReadonlyMap<string, Buffer>>();

export interface RepositoryCollaboratorPermissionInputRow {
  readonly nodeId?: string;
  readonly login: string;
  readonly actorType: string;
  readonly association?: string | null;
  readonly permission: RepositoryPermission;
}

export interface RepositoryCollaboratorPermissionRow
  extends RepositoryCollaboratorPermissionInputRow {
  readonly evidenceId: string;
  readonly sourceIdentity: string;
  readonly sourceOrdinal?: number;
  readonly actorNodeId?: string;
  readonly actorLogin?: string;
  readonly rawJson?: string;
  readonly contentHash?: string;
  readonly rowHash?: string;
  readonly runHash?: string;
}

export interface RepositoryCollaboratorPermissionSnapshot {
  readonly snapshotId: string;
  readonly schemaVersion: typeof COLLABORATOR_PERMISSION_SNAPSHOT_SCHEMA_VERSION;
  readonly repositoryNodeId?: string;
  readonly repository: string;
  readonly observedAt: string;
  readonly exhaustive: true;
  readonly complete: true;
  readonly totalCount: number;
  readonly rowCount: number;
  readonly pageCount: number;
  readonly pagesFetched: number;
  readonly sweepCount: number;
  readonly contentDigest: string;
  readonly rowsContentHash?: string;
  readonly rawJson?: string;
  readonly contentHash?: string;
  readonly runHash?: string;
  readonly sourceIdentity: string;
  readonly rows: readonly RepositoryCollaboratorPermissionRow[];
}

export interface ApprovedMaintainerRosterManifestEntry {
  readonly actorNodeId: string;
  readonly login: string;
  readonly actorType: 'User';
  readonly association: string | null;
  readonly role: 'maintain' | 'admin';
  readonly effectiveFrom: string;
  readonly effectiveUntil: string | null;
}

export interface ApprovedMaintainerRosterUnsignedManifest {
  readonly schemaVersion: typeof APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION;
  readonly purpose: typeof APPROVED_ROSTER_PURPOSE;
  readonly repositoryNodeId: string;
  readonly repository: string;
  readonly approvalId: string;
  readonly approvedAt: string;
  readonly sequence: number;
  readonly priorDigest: string | null;
  readonly signerKeyId: string;
  readonly entries: readonly ApprovedMaintainerRosterManifestEntry[];
}

export interface ApprovedMaintainerRosterManifest
  extends ApprovedMaintainerRosterUnsignedManifest {
  readonly signature: string;
}

export interface ApprovedMaintainerRosterSnapshot {
  readonly snapshotId: string;
  readonly schemaVersion: typeof APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION;
  readonly purpose?: typeof APPROVED_ROSTER_PURPOSE;
  readonly repositoryNodeId?: string;
  readonly repository: string;
  readonly approvalId: string;
  readonly approvedAt: string;
  readonly sequence?: number;
  readonly priorDigest?: string | null;
  readonly signerKeyId?: string;
  readonly keyringDigest?: string;
  readonly signatureAlgorithm?: typeof APPROVED_ROSTER_SIGNATURE_ALGORITHM;
  readonly signature?: string;
  readonly signatureVerifiedAt?: string;
  readonly rowCount: number;
  readonly contentDigest: string;
  readonly rowsContentHash?: string;
  readonly signedPayloadJson?: string;
  readonly contentHash?: string;
  readonly runHash?: string;
  readonly sourceIdentity: string;
  readonly entries: readonly ApprovedMaintainerRosterEntry[];
}

export interface ApprovedMaintainerRosterKeyringManifestKey {
  readonly keyId: string;
  readonly algorithm: typeof APPROVED_ROSTER_SIGNATURE_ALGORITHM;
  readonly secret: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
  readonly revokedAt: string | null;
}

export interface ApprovedMaintainerRosterKeyringManifest {
  readonly schemaVersion: typeof APPROVED_ROSTER_KEYRING_SCHEMA_VERSION;
  readonly purpose: typeof APPROVED_ROSTER_KEYRING_PURPOSE;
  readonly repositoryNodeId: string;
  readonly repository: string;
  readonly keys: readonly ApprovedMaintainerRosterKeyringManifestKey[];
}

export interface ApprovedMaintainerRosterVerificationKey {
  readonly keyId: string;
  readonly algorithm: typeof APPROVED_ROSTER_SIGNATURE_ALGORITHM;
  readonly keyFingerprint: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
  readonly revokedAt: string | null;
}

export interface ApprovedMaintainerRosterVerificationKeyring {
  readonly schemaVersion: typeof APPROVED_ROSTER_KEYRING_SCHEMA_VERSION;
  readonly purpose: typeof APPROVED_ROSTER_KEYRING_PURPOSE;
  readonly repositoryNodeId: string;
  readonly repository: string;
  readonly keyringDigest: string;
  readonly keys: readonly ApprovedMaintainerRosterVerificationKey[];
}

export interface ApprovedMaintainerRosterChainState {
  readonly schemaVersion: typeof APPROVED_ROSTER_CHAIN_STATE_SCHEMA_VERSION;
  readonly purpose: typeof APPROVED_ROSTER_PURPOSE;
  readonly repositoryNodeId: string;
  readonly sequence: number;
  readonly runDigest: string;
}

export type ApprovedRosterVerificationErrorCode =
  | 'invalid_manifest'
  | 'invalid_keyring'
  | 'repository_mismatch'
  | 'unknown_key'
  | 'key_not_yet_valid'
  | 'key_expired'
  | 'key_revoked'
  | 'invalid_signature'
  | 'manifest_postdated'
  | 'sequence_rollback'
  | 'sequence_replay'
  | 'sequence_fork'
  | 'sequence_gap'
  | 'prior_digest_mismatch';

export class ApprovedRosterVerificationError extends Error {
  readonly code: ApprovedRosterVerificationErrorCode;

  constructor(code: ApprovedRosterVerificationErrorCode, message: string) {
    super(message);
    this.name = 'ApprovedRosterVerificationError';
    this.code = code;
  }
}

export interface ApprovedMaintainerRosterVerificationOptions {
  readonly keyring?: ApprovedMaintainerRosterVerificationKeyring;
  readonly expectedRepositoryNodeId?: string;
  readonly previousState?: ApprovedMaintainerRosterChainState | null;
  readonly verifiedAt?: string;
}

export function loadApprovedMaintainerRosterChainState(
  path: string,
  options: { readFile?: (path: string) => string } = {},
): ApprovedMaintainerRosterChainState {
  return buildApprovedMaintainerRosterChainState(
    parseJsonFile(path, 'Approved roster chain state', options.readFile),
  );
}

export function buildApprovedMaintainerRosterChainState(
  value: unknown,
): ApprovedMaintainerRosterChainState {
  if (!isRecord(value)) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster chain state must be an object',
    );
  }
  assertExactKeys(
    value,
    CHAIN_STATE_KEYS,
    'approved roster chain state',
    'invalid_manifest',
  );
  if (value.schemaVersion !== APPROVED_ROSTER_CHAIN_STATE_SCHEMA_VERSION) {
    throw verificationError(
      'invalid_manifest',
      `Approved roster chain state schemaVersion must be ` +
        APPROVED_ROSTER_CHAIN_STATE_SCHEMA_VERSION,
    );
  }
  if (value.purpose !== APPROVED_ROSTER_PURPOSE) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster chain state purpose is invalid',
    );
  }
  const repositoryNodeId = requireNodeIdForVerification(
    value.repositoryNodeId,
    'Approved roster chain state repository node ID is invalid',
    'invalid_manifest',
  );
  if (!Number.isInteger(value.sequence) || Number(value.sequence) <= 0) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster chain state sequence must be a positive integer',
    );
  }
  if (!isSha256(value.runDigest)) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster chain state runDigest must be lowercase SHA-256 hex',
    );
  }
  return deepFreeze({
    schemaVersion: APPROVED_ROSTER_CHAIN_STATE_SCHEMA_VERSION,
    purpose: APPROVED_ROSTER_PURPOSE,
    repositoryNodeId,
    sequence: Number(value.sequence),
    runDigest: String(value.runDigest),
  });
}

export function canonicalApprovedMaintainerRosterChainStateJson(
  state: ApprovedMaintainerRosterChainState,
): string {
  return canonicalJson(buildApprovedMaintainerRosterChainState(state));
}

export function buildRepositoryCollaboratorPermissionSnapshot(input: {
  repositoryNodeId?: string;
  repository: string;
  observedAt: string;
  exhaustive: boolean;
  complete: boolean;
  totalCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  rows: readonly RepositoryCollaboratorPermissionInputRow[];
}): RepositoryCollaboratorPermissionSnapshot {
  const repositoryNodeId = requireNodeId(
    input.repositoryNodeId,
    'collaborator snapshot repository node ID',
  );
  const repository = normalizeRepository(input.repository);
  const observedAt = normalizeTimestamp(input.observedAt, 'collaborator snapshot observedAt');
  if (!isRepository(repository)) {
    throw new TypeError('Collaborator permission snapshot repository must be canonical owner/repo');
  }
  if (input.exhaustive !== true || input.complete !== true) {
    throw new TypeError('Collaborator permission snapshot must be exhaustive and complete');
  }
  for (const [field, value] of [
    ['totalCount', input.totalCount],
    ['pageCount', input.pageCount],
    ['pagesFetched', input.pagesFetched],
    ['sweepCount', input.sweepCount],
  ] as const) {
    if (!Number.isInteger(value) || value < (field === 'totalCount' ? 0 : 1)) {
      throw new TypeError(`Collaborator permission snapshot ${field} is invalid`);
    }
  }

  const canonicalRows = input.rows
    .map((row) => ({
      nodeId: requireNodeId(row.nodeId, 'collaborator actor node ID'),
      login: normalizeLogin(row.login),
      actorType: requiredString(row.actorType, 'actorType'),
      association: normalizeOptionalText(row.association),
      permission: normalizePermission(row.permission),
    }))
    .sort((left, right) =>
      compareBinary(left.nodeId, right.nodeId) ||
      compareBinary(left.login, right.login));
  const duplicateNodeId = canonicalRows.find((row, index) =>
    index > 0 && row.nodeId === canonicalRows[index - 1].nodeId);
  if (duplicateNodeId) {
    throw new TypeError(
      `Collaborator permission snapshot has duplicate actor node ID ${duplicateNodeId.nodeId}`,
    );
  }
  if (canonicalRows.length !== input.totalCount) {
    throw new TypeError(
      `Collaborator permission snapshot row count ${canonicalRows.length} ` +
        `does not match totalCount ${input.totalCount}`,
    );
  }

  const rowsWithHashes = canonicalRows.map((row) => {
    const observation: RepositoryPermissionObservation = {
      kind: 'repository_permission_observation',
      evidenceId: 'pending',
      sourceIdentity: 'pending',
      repositoryNodeId,
      repository,
      actorNodeId: row.nodeId,
      actorLogin: row.login,
      actorType: row.actorType,
      actorAssociation: row.association,
      permission: row.permission,
      observedAt,
    };
    return {
      ...row,
      rowHash: repositoryPermissionObservationRowHash(observation),
    };
  });
  const contentDigest = sha256Json([
    'repository_collaborator_permissions_v2',
    repositoryNodeId,
    rowsWithHashes.map((row) => row.rowHash),
  ]);
  const runHash = sha256Json([
    'repository_collaborator_permission_run_v2',
    repositoryNodeId,
    repository,
    observedAt,
    input.totalCount,
    input.pageCount,
    input.pagesFetched,
    input.sweepCount,
    contentDigest,
  ]);
  const sourceIdentity =
    `github-graphql:repository.collaborators:v2:${runHash}`;
  const rawJson = canonicalJson({
    repositoryNodeId,
    repository,
    observedAt,
    rows: rowsWithHashes.map((row) => ({
      actorNodeId: row.nodeId,
      actorLogin: row.login,
      actorType: row.actorType,
      association: row.association,
      permission: row.permission,
    })),
  });
  const rows = rowsWithHashes.map((row, sourceOrdinal) => {
    const rowRawJson = canonicalJson({
      actorNodeId: row.nodeId,
      actorLogin: row.login,
      actorType: row.actorType,
      association: row.association,
      permission: row.permission,
    });
    const evidence: RepositoryPermissionObservation = {
      kind: 'repository_permission_observation',
      evidenceId: `collaborator-permission:v2:${row.rowHash}`,
      sourceIdentity:
        `github-graphql:repository.collaborators:row:v2:${row.rowHash}`,
      repositoryNodeId,
      repository,
      actorNodeId: row.nodeId,
      actorLogin: row.login,
      actorType: row.actorType,
      actorAssociation: row.association,
      permission: row.permission,
      observedAt,
      sourceOrdinal,
      rawJson: rowRawJson,
      contentHash: row.rowHash,
      rowHash: row.rowHash,
      runHash,
    };
    assertAuthorityEvidenceItem(evidence, observedAt);
    return {
      nodeId: row.nodeId,
      login: row.login,
      actorType: row.actorType,
      association: row.association,
      permission: row.permission,
      evidenceId: evidence.evidenceId,
      sourceIdentity: evidence.sourceIdentity,
      sourceOrdinal,
      actorNodeId: row.nodeId,
      actorLogin: row.login,
      rawJson: rowRawJson,
      contentHash: row.rowHash,
      rowHash: row.rowHash,
      runHash,
    };
  });

  return deepFreeze({
    snapshotId: `collaborator-permissions:v2:${runHash}`,
    schemaVersion: COLLABORATOR_PERMISSION_SNAPSHOT_SCHEMA_VERSION,
    repositoryNodeId,
    repository,
    observedAt,
    exhaustive: true,
    complete: true,
    totalCount: input.totalCount,
    rowCount: rows.length,
    pageCount: input.pageCount,
    pagesFetched: input.pagesFetched,
    sweepCount: input.sweepCount,
    contentDigest,
    rowsContentHash: contentDigest,
    rawJson,
    contentHash: runHash,
    runHash,
    sourceIdentity,
    rows,
  });
}

export function repositoryCollaboratorPermissionSnapshotProblems(
  value: RepositoryCollaboratorPermissionSnapshot,
): string[] {
  try {
    const rebuilt = buildRepositoryCollaboratorPermissionSnapshot({
      repositoryNodeId: value.repositoryNodeId,
      repository: value.repository,
      observedAt: value.observedAt,
      exhaustive: value.exhaustive,
      complete: value.complete,
      totalCount: value.totalCount,
      pageCount: value.pageCount,
      pagesFetched: value.pagesFetched,
      sweepCount: value.sweepCount,
      rows: value.rows,
    });
    return canonicalJson(rebuilt) === canonicalJson(value)
      ? []
      : ['collaborator permission snapshot immutable metadata does not match its rows'];
  } catch (error) {
    return [safeErrorMessage(error)];
  }
}

export function loadApprovedMaintainerRosterKeyring(
  path: string,
  options: { readFile?: (path: string) => string } = {},
): ApprovedMaintainerRosterVerificationKeyring {
  return buildApprovedMaintainerRosterKeyring(
    parseJsonFile(path, 'Approved roster keyring', options.readFile),
  );
}

export function buildApprovedMaintainerRosterKeyring(
  value: unknown,
): ApprovedMaintainerRosterVerificationKeyring {
  if (!isRecord(value)) {
    throw verificationError('invalid_keyring', 'Approved roster keyring must be an object');
  }
  assertExactKeys(value, KEYRING_KEYS, 'approved roster keyring', 'invalid_keyring');
  if (value.schemaVersion !== APPROVED_ROSTER_KEYRING_SCHEMA_VERSION) {
    throw verificationError(
      'invalid_keyring',
      `Approved roster keyring schemaVersion must be ` +
        APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
    );
  }
  if (value.purpose !== APPROVED_ROSTER_KEYRING_PURPOSE) {
    throw verificationError('invalid_keyring', 'Approved roster keyring purpose is invalid');
  }
  const repositoryNodeId = requireNodeIdForVerification(
    value.repositoryNodeId,
    'Approved roster keyring repository node ID is invalid',
    'invalid_keyring',
  );
  const repository = normalizeRepository(
    requiredStringForVerification(
      value.repository,
      'Approved roster keyring repository is invalid',
      'invalid_keyring',
    ),
  );
  if (!isRepository(repository)) {
    throw verificationError(
      'invalid_keyring',
      'Approved roster keyring repository must be canonical owner/repo',
    );
  }
  if (!Array.isArray(value.keys) || value.keys.length === 0) {
    throw verificationError(
      'invalid_keyring',
      'Approved roster keyring must contain at least one key',
    );
  }

  const secrets = new Map<string, Buffer>();
  const keys = value.keys.map((item, index) => {
    if (!isRecord(item)) {
      throw verificationError(
        'invalid_keyring',
        `Approved roster keyring keys[${index}] must be an object`,
      );
    }
    assertExactKeys(
      item,
      KEYRING_ENTRY_KEYS,
      `approved roster keyring keys[${index}]`,
      'invalid_keyring',
    );
    const keyId = requiredStringForVerification(
      item.keyId,
      `Approved roster keyring keys[${index}].keyId is invalid`,
      'invalid_keyring',
    );
    if (secrets.has(keyId)) {
      throw verificationError(
        'invalid_keyring',
        `Approved roster keyring has duplicate key ID ${keyId}`,
      );
    }
    if (item.algorithm !== APPROVED_ROSTER_SIGNATURE_ALGORITHM) {
      throw verificationError(
        'invalid_keyring',
        `Approved roster key ${keyId} algorithm is invalid`,
      );
    }
    const secret = decodeKeySecret(item.secret, keyId);
    const validFrom = normalizeTimestampForVerification(
      item.validFrom,
      `Approved roster key ${keyId} validFrom is invalid`,
      'invalid_keyring',
    );
    const validUntil = item.validUntil == null
      ? null
      : normalizeTimestampForVerification(
          item.validUntil,
          `Approved roster key ${keyId} validUntil is invalid`,
          'invalid_keyring',
        );
    const revokedAt = item.revokedAt == null
      ? null
      : normalizeTimestampForVerification(
          item.revokedAt,
          `Approved roster key ${keyId} revokedAt is invalid`,
          'invalid_keyring',
        );
    if (validUntil != null && Date.parse(validUntil) < Date.parse(validFrom)) {
      throw verificationError(
        'invalid_keyring',
        `Approved roster key ${keyId} validity interval is invalid`,
      );
    }
    secrets.set(keyId, secret);
    return {
      keyId,
      algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
      keyFingerprint: sha256Buffer(
        Buffer.concat([
          Buffer.from('approved-roster-key-fingerprint-v1\0'),
          secret,
        ]),
      ),
      validFrom,
      validUntil,
      revokedAt,
    };
  }).sort((left, right) => compareBinary(left.keyId, right.keyId));
  const keyringDigest = sha256Json([
    'approved_maintainer_roster_keyring_v1',
    repositoryNodeId,
    repository,
    keys.map((key) => [
      key.keyId,
      key.algorithm,
      key.keyFingerprint,
      key.validFrom,
      key.validUntil,
      key.revokedAt,
    ]),
  ]);
  const keyring = deepFreeze({
    schemaVersion: APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
    purpose: APPROVED_ROSTER_KEYRING_PURPOSE,
    repositoryNodeId,
    repository,
    keyringDigest,
    keys,
  });
  KEYRING_SECRETS.set(keyring, secrets);
  return keyring;
}

export function canonicalApprovedMaintainerRosterKeyringMetadataJson(
  keyring: ApprovedMaintainerRosterVerificationKeyring,
): string {
  return canonicalJson(keyring);
}

export function signApprovedMaintainerRosterManifest(
  input: ApprovedMaintainerRosterUnsignedManifest,
  keyring: ApprovedMaintainerRosterVerificationKeyring,
): ApprovedMaintainerRosterManifest {
  const canonical = canonicalUnsignedRosterManifest(input, keyring);
  const secret = keySecret(keyring, canonical.signerKeyId);
  const signature = hmacSignature(secret, rosterSignaturePayload(canonical));
  return deepFreeze({
    ...canonical.manifest,
    entries: canonical.entries.map((entry) => entry.manifestEntry),
    signature,
  });
}

export function loadApprovedMaintainerRosterSnapshot(
  path: string,
  options: ApprovedMaintainerRosterVerificationOptions & {
    readFile?: (path: string) => string;
    keyringPath?: string;
  } = {},
): ApprovedMaintainerRosterSnapshot {
  const keyring = options.keyring ?? (
    options.keyringPath == null
      ? undefined
      : loadApprovedMaintainerRosterKeyring(options.keyringPath, {
          readFile: options.readFile,
        })
  );
  return buildApprovedMaintainerRosterSnapshot(
    parseJsonFile(path, 'Approved roster config', options.readFile),
    { ...options, keyring },
  );
}

export function buildApprovedMaintainerRosterSnapshot(
  value: unknown,
  options: ApprovedMaintainerRosterVerificationOptions = {},
): ApprovedMaintainerRosterSnapshot {
  const keyring = options.keyring;
  if (!keyring || !KEYRING_SECRETS.has(keyring)) {
    throw verificationError(
      'invalid_keyring',
      'Approved roster verification requires a validated keyring',
    );
  }
  if (!isRecord(value)) {
    throw verificationError('invalid_manifest', 'Approved roster manifest must be an object');
  }
  assertExactKeys(value, ROSTER_MANIFEST_KEYS, 'approved roster manifest', 'invalid_manifest');
  if (!isSha256(value.signature)) {
    throw verificationError(
      'invalid_signature',
      'Approved roster signature must be lowercase HMAC-SHA256 hex',
    );
  }
  const canonical = canonicalUnsignedRosterManifest(
    value as unknown as ApprovedMaintainerRosterUnsignedManifest,
    keyring,
  );
  const signature = String(value.signature);
  const verifiedAt = normalizeTimestampForVerification(
    options.verifiedAt ?? new Date().toISOString(),
    'Approved roster verifiedAt is invalid',
    'invalid_manifest',
  );
  if (Date.parse(canonical.manifest.approvedAt) > Date.parse(verifiedAt)) {
    throw verificationError(
      'manifest_postdated',
      'Approved roster approval time is later than verification time',
    );
  }
  if (
    options.expectedRepositoryNodeId != null &&
    canonical.manifest.repositoryNodeId !== options.expectedRepositoryNodeId
  ) {
    throw verificationError(
      'repository_mismatch',
      'Approved roster repository node ID does not match the expected repository',
    );
  }
  if (canonical.manifest.repositoryNodeId !== keyring.repositoryNodeId) {
    throw verificationError(
      'repository_mismatch',
      'Approved roster repository node ID does not match the keyring repository',
    );
  }

  const key = keyring.keys.find((item) => item.keyId === canonical.signerKeyId);
  if (!key) {
    throw verificationError(
      'unknown_key',
      `Approved roster references unknown key ID ${canonical.signerKeyId}`,
    );
  }
  const approvedAtMs = Date.parse(canonical.manifest.approvedAt);
  if (approvedAtMs < Date.parse(key.validFrom)) {
    throw verificationError(
      'key_not_yet_valid',
      `Approved roster key ${key.keyId} was not valid at approval time`,
    );
  }
  if (key.validUntil != null && approvedAtMs > Date.parse(key.validUntil)) {
    throw verificationError(
      'key_expired',
      `Approved roster key ${key.keyId} was expired at approval time`,
    );
  }
  if (key.revokedAt != null && approvedAtMs >= Date.parse(key.revokedAt)) {
    throw verificationError(
      'key_revoked',
      `Approved roster key ${key.keyId} was revoked at approval time`,
    );
  }

  const expectedSignature = hmacSignature(
    keySecret(keyring, key.keyId),
    rosterSignaturePayload(canonical),
  );
  if (!safeHexEqual(signature, expectedSignature)) {
    throw verificationError('invalid_signature', 'Approved roster signature is invalid');
  }

  const contentDigest = sha256Json([
    'approved_maintainer_roster_rows_v2',
    canonical.manifest.repositoryNodeId,
    canonical.manifest.sequence,
    canonical.entries.map((entry) => entry.rowHash),
  ]);
  const payloadDigest = sha256(
    `approved-maintainer-roster-payload-v2\0${rosterSignaturePayload(canonical)}`,
  );
  const runHash = sha256Json([
    'approved_maintainer_roster_run_v2',
    payloadDigest,
    keyring.keyringDigest,
    signature,
  ]);
  assertRosterChain(
    canonical.manifest,
    runHash,
    options.previousState ?? null,
  );

  const sourceIdentity = `operator-config:approved-roster:v2:${runHash}`;
  const signedPayloadJson = rosterSignaturePayload(canonical);
  const entries = canonical.entries.map((entry, entryOrdinal) => {
    const entryRawJson = canonicalJson(entry.manifestEntry);
    const approvedEntry: ApprovedMaintainerRosterEntry = {
      kind: 'approved_roster_entry',
      evidenceId: `approved-roster-entry:v2:${entry.rowHash}`,
      sourceIdentity: `operator-config:approved-roster:entry:v2:${entry.rowHash}`,
      approvalId: canonical.manifest.approvalId,
      approvedAt: canonical.manifest.approvedAt,
      repositoryNodeId: canonical.manifest.repositoryNodeId,
      repository: canonical.manifest.repository,
      actorNodeId: entry.manifestEntry.actorNodeId,
      actorLogin: entry.manifestEntry.login,
      actorType: entry.manifestEntry.actorType,
      actorAssociation: entry.manifestEntry.association,
      role: entry.manifestEntry.role,
      effectiveFrom: entry.manifestEntry.effectiveFrom,
      effectiveUntil: entry.manifestEntry.effectiveUntil,
      rosterSequence: canonical.manifest.sequence,
      rosterRunDigest: runHash,
      signerKeyId: canonical.signerKeyId,
      keyringDigest: keyring.keyringDigest,
      signatureVerifiedAt: verifiedAt,
      entryOrdinal,
      rawJson: entryRawJson,
      contentHash: entry.rowHash,
      rowHash: entry.rowHash,
    };
    assertAuthorityEvidenceItem(approvedEntry, entry.manifestEntry.effectiveFrom);
    return approvedEntry;
  });

  return deepFreeze({
    snapshotId: `approved-roster:v2:${runHash}`,
    schemaVersion: APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
    purpose: APPROVED_ROSTER_PURPOSE,
    repositoryNodeId: canonical.manifest.repositoryNodeId,
    repository: canonical.manifest.repository,
    approvalId: canonical.manifest.approvalId,
    approvedAt: canonical.manifest.approvedAt,
    sequence: canonical.manifest.sequence,
    priorDigest: canonical.manifest.priorDigest,
    signerKeyId: canonical.signerKeyId,
    keyringDigest: keyring.keyringDigest,
    signatureAlgorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
    signature,
    signatureVerifiedAt: verifiedAt,
    rowCount: entries.length,
    contentDigest,
    rowsContentHash: contentDigest,
    signedPayloadJson,
    contentHash: runHash,
    runHash,
    sourceIdentity,
    entries,
  });
}

export function approvedMaintainerRosterChainState(
  snapshot: ApprovedMaintainerRosterSnapshot,
): ApprovedMaintainerRosterChainState {
  if (
    snapshot.purpose !== APPROVED_ROSTER_PURPOSE ||
    !snapshot.repositoryNodeId ||
    !Number.isInteger(snapshot.sequence) ||
    Number(snapshot.sequence) <= 0 ||
    !isSha256(snapshot.runHash)
  ) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster snapshot cannot produce a valid chain state',
    );
  }
  return buildApprovedMaintainerRosterChainState({
    schemaVersion: APPROVED_ROSTER_CHAIN_STATE_SCHEMA_VERSION,
    purpose: APPROVED_ROSTER_PURPOSE,
    repositoryNodeId: snapshot.repositoryNodeId,
    sequence: snapshot.sequence as number,
    runDigest: snapshot.runHash,
  });
}

export function approvedMaintainerRosterSnapshotProblems(
  value: ApprovedMaintainerRosterSnapshot,
  options: ApprovedMaintainerRosterVerificationOptions = {},
): string[] {
  try {
    if (!isRecord(value)) {
      return ['approved roster snapshot must be an object'];
    }
    assertExactKeys(
      value as unknown as Record<string, unknown>,
      APPROVED_ROSTER_SNAPSHOT_KEYS,
      'approved roster snapshot',
      'invalid_manifest',
    );
    if (!Array.isArray(value.entries)) {
      return ['approved roster snapshot entries must be an array'];
    }
    for (const [index, entry] of value.entries.entries()) {
      if (!isRecord(entry)) {
        return [`approved roster snapshot entries[${index}] must be an object`];
      }
      assertExactKeys(
        entry,
        APPROVED_ROSTER_SNAPSHOT_ENTRY_KEYS,
        `approved roster snapshot entries[${index}]`,
        'invalid_manifest',
      );
    }
    if (
      value.schemaVersion !== APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION ||
      value.purpose !== APPROVED_ROSTER_PURPOSE ||
      !value.repositoryNodeId ||
      !Number.isInteger(value.sequence) ||
      value.sequence == null ||
      value.priorDigest === undefined ||
      !value.signerKeyId ||
      !isSha256(value.keyringDigest) ||
      value.signatureAlgorithm !== APPROVED_ROSTER_SIGNATURE_ALGORITHM ||
      !isSha256(value.signature) ||
      !value.signatureVerifiedAt ||
      !isSha256(value.runHash)
    ) {
      return ['approved roster snapshot is missing signed authority metadata'];
    }
    if (value.sequence <= 0) {
      return ['approved roster snapshot sequence must be a positive integer'];
    }
    requireNodeId(value.repositoryNodeId, 'approved roster repository node ID');
    const repository = normalizeRepository(value.repository);
    if (!isRepository(repository) || repository !== value.repository) {
      return ['approved roster snapshot repository must be canonical owner/repo'];
    }
    requiredString(value.approvalId, 'approved roster approvalId');
    if (!Number.isInteger(value.rowCount) || value.rowCount < 0) {
      return ['approved roster snapshot rowCount must be a non-negative integer'];
    }
    if (
      !isSha256(value.contentDigest) ||
      !isSha256(value.rowsContentHash) ||
      !isSha256(value.contentHash)
    ) {
      return ['approved roster snapshot digests must be lowercase SHA-256 hex'];
    }
    if (!(value.priorDigest == null || isSha256(value.priorDigest))) {
      return ['approved roster snapshot priorDigest must be SHA-256 or null'];
    }
    const approvedAt = normalizeTimestamp(value.approvedAt, 'approvedAt');
    const signatureVerifiedAt = normalizeTimestamp(
      value.signatureVerifiedAt,
      'signatureVerifiedAt',
    );
    if (
      value.approvedAt !== approvedAt ||
      value.signatureVerifiedAt !== signatureVerifiedAt
    ) {
      return ['approved roster snapshot timestamps must be canonical UTC'];
    }
    if (Date.parse(approvedAt) > Date.parse(signatureVerifiedAt)) {
      return ['approved roster signature verification predates approval'];
    }
    for (const entry of value.entries) {
      try {
        assertAuthorityEvidenceItem(entry, entry.effectiveFrom);
      } catch {
        return ['approved roster snapshot immutable metadata does not match its entries'];
      }
      const entryApprovedAt = normalizeTimestamp(entry.approvedAt, 'entry approvedAt');
      const entryEffectiveFrom = normalizeTimestamp(
        entry.effectiveFrom,
        'entry effectiveFrom',
      );
      const entryEffectiveUntil = entry.effectiveUntil == null
        ? null
        : normalizeTimestamp(entry.effectiveUntil, 'entry effectiveUntil');
      const entrySignatureVerifiedAt = normalizeTimestamp(
        entry.signatureVerifiedAt ?? '',
        'entry signatureVerifiedAt',
      );
      if (
        entry.actorLogin !== normalizeLogin(entry.actorLogin) ||
        entry.approvedAt !== entryApprovedAt ||
        entry.effectiveFrom !== entryEffectiveFrom ||
        entry.effectiveUntil !== entryEffectiveUntil ||
        entry.signatureVerifiedAt !== entrySignatureVerifiedAt
      ) {
        return ['approved roster snapshot entries must use canonical identity and timestamps'];
      }
      if (
        entry.approvalId !== value.approvalId ||
        entry.approvedAt !== value.approvedAt ||
        entry.repositoryNodeId !== value.repositoryNodeId ||
        entry.repository !== value.repository ||
        entry.rosterSequence !== value.sequence ||
        entry.rosterRunDigest !== value.runHash ||
        entry.signerKeyId !== value.signerKeyId ||
        entry.keyringDigest !== value.keyringDigest ||
        entry.signatureVerifiedAt !== value.signatureVerifiedAt
      ) {
        return ['approved roster snapshot entry provenance does not match its snapshot'];
      }
    }
    const unsigned: ApprovedMaintainerRosterUnsignedManifest = {
      schemaVersion: value.schemaVersion,
      purpose: value.purpose,
      repositoryNodeId: value.repositoryNodeId,
      repository: value.repository,
      approvalId: value.approvalId,
      approvedAt: value.approvedAt,
      sequence: value.sequence,
      priorDigest: value.priorDigest,
      signerKeyId: value.signerKeyId,
      entries: value.entries.map((entry) => ({
        actorNodeId: entry.actorNodeId ?? '',
        login: entry.actorLogin,
        actorType: 'User',
        association: entry.actorAssociation ?? null,
        role: entry.role,
        effectiveFrom: entry.effectiveFrom,
        effectiveUntil: entry.effectiveUntil,
      })),
    };
    if (options.keyring) {
      const rebuilt = buildApprovedMaintainerRosterSnapshot(
        { ...unsigned, signature: value.signature },
        {
          ...options,
          verifiedAt: value.signatureVerifiedAt,
        },
      );
      return canonicalJson(rebuilt) === canonicalJson(value)
        ? []
        : ['approved roster snapshot immutable metadata does not match its entries'];
    }
    const rowHashes = value.entries.map((entry) =>
      approvedMaintainerRosterEntryRowHash(entry));
    const canonicalEntries = value.entries.map((entry, index) => ({
      manifestEntry: {
        actorNodeId: entry.actorNodeId ?? '',
        login: normalizeLogin(entry.actorLogin),
        actorType: 'User' as const,
        association: entry.actorAssociation ?? null,
        role: entry.role,
        effectiveFrom: normalizeTimestamp(entry.effectiveFrom, 'effectiveFrom'),
        effectiveUntil: entry.effectiveUntil == null
          ? null
          : normalizeTimestamp(entry.effectiveUntil, 'effectiveUntil'),
      },
      rowHash: rowHashes[index],
    })).sort((left, right) =>
      compareBinary(left.manifestEntry.actorNodeId, right.manifestEntry.actorNodeId) ||
      compareBinary(left.manifestEntry.effectiveFrom, right.manifestEntry.effectiveFrom) ||
      compareBinary(
        left.manifestEntry.effectiveUntil ?? '',
        right.manifestEntry.effectiveUntil ?? '',
      ) ||
      compareBinary(left.rowHash, right.rowHash));
    assertNonOverlappingRosterEntries(
      canonicalEntries.map((entry) => entry.manifestEntry),
    );
    const canonicalRowHashes = canonicalEntries.map((entry) => entry.rowHash);
    const rowHashMismatch = value.entries.some((entry, index) =>
      entry.rowHash !== rowHashes[index]);
    const contentDigest = sha256Json([
      'approved_maintainer_roster_rows_v2',
      value.repositoryNodeId,
      value.sequence,
      canonicalRowHashes,
    ]);
    const signaturePayload = canonicalJson({
      schemaVersion: value.schemaVersion,
      purpose: value.purpose,
      repositoryNodeId: value.repositoryNodeId,
      repository: normalizeRepository(value.repository),
      approvalId: value.approvalId,
      approvedAt: normalizeTimestamp(value.approvedAt, 'approvedAt'),
      sequence: value.sequence,
      priorDigest: value.priorDigest,
      signerKeyId: value.signerKeyId,
      entries: canonicalEntries.map((entry) => ({
        ...entry.manifestEntry,
        rowHash: entry.rowHash,
      })),
    });
    const payloadDigest = sha256(
      `approved-maintainer-roster-payload-v2\0${signaturePayload}`,
    );
    const runHash = sha256Json([
      'approved_maintainer_roster_run_v2',
      payloadDigest,
      value.keyringDigest,
      value.signature,
    ]);
    if (Object.prototype.hasOwnProperty.call(options, 'previousState')) {
      assertRosterChain(unsigned, runHash, options.previousState ?? null);
    }
    const keyringMatches = value.entries.every((entry) =>
      entry.keyringDigest === value.keyringDigest &&
      entry.signerKeyId === value.signerKeyId &&
      entry.rosterSequence === value.sequence &&
      entry.rosterRunDigest === value.runHash &&
      entry.signatureVerifiedAt === value.signatureVerifiedAt);
    const canonicalOrder = value.entries.every((entry, index) =>
      entry.rowHash === canonicalRowHashes[index] &&
      entry.entryOrdinal === index);
    const entryIdsMatch = value.entries.every((entry) =>
      entry.rowHash != null &&
      entry.evidenceId === `approved-roster-entry:v2:${entry.rowHash}` &&
      entry.sourceIdentity ===
        `operator-config:approved-roster:entry:v2:${entry.rowHash}` &&
      entry.contentHash === entry.rowHash &&
      entry.rawJson === canonicalJson({
        actorNodeId: entry.actorNodeId,
        login: entry.actorLogin,
        actorType: entry.actorType,
        association: entry.actorAssociation ?? null,
        role: entry.role,
        effectiveFrom: entry.effectiveFrom,
        effectiveUntil: entry.effectiveUntil,
      }));
    if (
      rowHashMismatch ||
      !canonicalOrder ||
      !entryIdsMatch ||
      value.rowCount !== value.entries.length ||
      value.contentDigest !== contentDigest ||
      value.rowsContentHash !== contentDigest ||
      value.signedPayloadJson !== signaturePayload ||
      value.runHash !== runHash ||
      value.contentHash !== runHash ||
      !keyringMatches ||
      value.snapshotId !== `approved-roster:v2:${value.runHash}` ||
      value.sourceIdentity !== `operator-config:approved-roster:v2:${value.runHash}`
    ) {
      return ['approved roster snapshot immutable metadata does not match its entries'];
    }
    return [];
  } catch (error) {
    return [safeErrorMessage(error)];
  }
}

interface CanonicalRosterEntry {
  manifestEntry: ApprovedMaintainerRosterManifestEntry;
  rowHash: string;
}

interface CanonicalUnsignedRoster {
  manifest: Omit<ApprovedMaintainerRosterUnsignedManifest, 'entries'>;
  signerKeyId: string;
  entries: CanonicalRosterEntry[];
}

function canonicalUnsignedRosterManifest(
  value: ApprovedMaintainerRosterUnsignedManifest,
  keyring: ApprovedMaintainerRosterVerificationKeyring,
): CanonicalUnsignedRoster {
  if (!isRecord(value)) {
    throw verificationError('invalid_manifest', 'Approved roster manifest must be an object');
  }
  for (const key of ROSTER_MANIFEST_KEYS) {
    if (key === 'signature') continue;
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw verificationError(
        'invalid_manifest',
        `Approved roster manifest is missing ${key}`,
      );
    }
  }
  if (value.schemaVersion !== APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION) {
    throw verificationError(
      'invalid_manifest',
      `Approved roster manifest schemaVersion must be ` +
        APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
    );
  }
  if (value.purpose !== APPROVED_ROSTER_PURPOSE) {
    throw verificationError('invalid_manifest', 'Approved roster manifest purpose is invalid');
  }
  const repositoryNodeId = requireNodeIdForVerification(
    value.repositoryNodeId,
    'Approved roster repository node ID is invalid',
    'invalid_manifest',
  );
  const repository = normalizeRepository(
    requiredStringForVerification(
      value.repository,
      'Approved roster repository is invalid',
      'invalid_manifest',
    ),
  );
  if (!isRepository(repository)) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster repository must be canonical owner/repo',
    );
  }
  const approvalId = requiredStringForVerification(
    value.approvalId,
    'Approved roster approvalId is invalid',
    'invalid_manifest',
  );
  const approvedAt = normalizeTimestampForVerification(
    value.approvedAt,
    'Approved roster approvedAt is invalid',
    'invalid_manifest',
  );
  if (!Number.isInteger(value.sequence) || value.sequence <= 0) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster sequence must be a positive integer',
    );
  }
  if (!(value.priorDigest == null || isSha256(value.priorDigest))) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster priorDigest must be SHA-256 or null',
    );
  }
  const signerKeyId = requiredStringForVerification(
    value.signerKeyId,
    'Approved roster signerKeyId is invalid',
    'invalid_manifest',
  );
  if (!Array.isArray(value.entries)) {
    throw verificationError('invalid_manifest', 'Approved roster entries must be an array');
  }

  const entries = value.entries.map((entry, index) => {
    const manifestEntry = canonicalRosterManifestEntry(entry, index);
    const rowHash = approvedMaintainerRosterEntryRowHash({
      kind: 'approved_roster_entry',
      evidenceId: 'pending',
      sourceIdentity: 'pending',
      approvalId,
      approvedAt,
      repositoryNodeId,
      repository,
      actorNodeId: manifestEntry.actorNodeId,
      actorLogin: manifestEntry.login,
      actorType: manifestEntry.actorType,
      actorAssociation: manifestEntry.association,
      role: manifestEntry.role,
      effectiveFrom: manifestEntry.effectiveFrom,
      effectiveUntil: manifestEntry.effectiveUntil,
      rosterSequence: value.sequence,
      signerKeyId,
      keyringDigest: keyring.keyringDigest,
    });
    return { manifestEntry, rowHash };
  }).sort((left, right) =>
    compareBinary(left.manifestEntry.actorNodeId, right.manifestEntry.actorNodeId) ||
    compareBinary(left.manifestEntry.effectiveFrom, right.manifestEntry.effectiveFrom) ||
    compareBinary(left.manifestEntry.effectiveUntil ?? '', right.manifestEntry.effectiveUntil ?? '') ||
    compareBinary(left.rowHash, right.rowHash));
  assertNonOverlappingRosterEntries(entries.map((entry) => entry.manifestEntry));

  return {
    manifest: {
      schemaVersion: APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
      purpose: APPROVED_ROSTER_PURPOSE,
      repositoryNodeId,
      repository,
      approvalId,
      approvedAt,
      sequence: value.sequence,
      priorDigest: value.priorDigest ?? null,
      signerKeyId,
    },
    signerKeyId,
    entries,
  };
}

function rosterSignaturePayload(value: CanonicalUnsignedRoster): string {
  return canonicalJson({
    ...value.manifest,
    entries: value.entries.map((entry) => ({
      ...entry.manifestEntry,
      rowHash: entry.rowHash,
    })),
  });
}

function canonicalRosterManifestEntry(
  value: unknown,
  index: number,
): ApprovedMaintainerRosterManifestEntry {
  if (!isRecord(value)) {
    throw verificationError(
      'invalid_manifest',
      `Approved roster entries[${index}] must be an object`,
    );
  }
  assertExactKeys(
    value,
    ROSTER_ENTRY_KEYS,
    `approved roster entries[${index}]`,
    'invalid_manifest',
  );
  const actorNodeId = requireNodeIdForVerification(
    value.actorNodeId,
    `Approved roster entries[${index}].actorNodeId is invalid`,
    'invalid_manifest',
  );
  const login = normalizeLogin(
    requiredStringForVerification(
      value.login,
      `Approved roster entries[${index}].login is invalid`,
      'invalid_manifest',
    ),
  );
  if (value.actorType !== 'User') {
    throw verificationError(
      'invalid_manifest',
      `Approved roster entries[${index}].actorType must be User`,
    );
  }
  const association = normalizeOptionalText(value.association);
  if (value.association != null && association == null) {
    throw verificationError(
      'invalid_manifest',
      `Approved roster entries[${index}].association is invalid`,
    );
  }
  if (value.role !== 'maintain' && value.role !== 'admin') {
    throw verificationError(
      'invalid_manifest',
      `Approved roster entries[${index}].role is invalid`,
    );
  }
  const effectiveFrom = normalizeTimestampForVerification(
    value.effectiveFrom,
    `Approved roster entries[${index}].effectiveFrom is invalid`,
    'invalid_manifest',
  );
  const effectiveUntil = value.effectiveUntil == null
    ? null
    : normalizeTimestampForVerification(
        value.effectiveUntil,
        `Approved roster entries[${index}].effectiveUntil is invalid`,
        'invalid_manifest',
      );
  if (
    effectiveUntil != null &&
    Date.parse(effectiveUntil) < Date.parse(effectiveFrom)
  ) {
    throw verificationError(
      'invalid_manifest',
      `Approved roster entries[${index}].effectiveUntil precedes effectiveFrom`,
    );
  }
  return {
    actorNodeId,
    login,
    actorType: 'User',
    association,
    role: value.role,
    effectiveFrom,
    effectiveUntil,
  };
}

function assertNonOverlappingRosterEntries(
  entries: readonly ApprovedMaintainerRosterManifestEntry[],
): void {
  const previousByNodeId = new Map<string, ApprovedMaintainerRosterManifestEntry>();
  for (const entry of entries) {
    const previous = previousByNodeId.get(entry.actorNodeId);
    if (previous) {
      const previousUntil = previous.effectiveUntil == null
        ? Number.POSITIVE_INFINITY
        : Date.parse(previous.effectiveUntil);
      if (Date.parse(entry.effectiveFrom) <= previousUntil) {
        throw verificationError(
          'invalid_manifest',
          `Approved roster entries for actor node ID ${entry.actorNodeId} ` +
            `have overlapping effective intervals`,
        );
      }
    }
    previousByNodeId.set(entry.actorNodeId, entry);
  }
}

function assertRosterChain(
  manifest: CanonicalUnsignedRoster['manifest'],
  runHash: string,
  previous: ApprovedMaintainerRosterChainState | null,
): void {
  if (previous == null) {
    if (manifest.sequence !== 1) {
      throw verificationError(
        'sequence_gap',
        'Approved roster initial sequence must be 1',
      );
    }
    if (manifest.priorDigest !== null) {
      throw verificationError(
        'prior_digest_mismatch',
        'Approved roster initial priorDigest must be null',
      );
    }
    return;
  }
  if (
    previous.schemaVersion !== APPROVED_ROSTER_CHAIN_STATE_SCHEMA_VERSION ||
    previous.purpose !== APPROVED_ROSTER_PURPOSE ||
    !isNodeId(previous.repositoryNodeId) ||
    !Number.isInteger(previous.sequence) ||
    previous.sequence <= 0 ||
    !isSha256(previous.runDigest)
  ) {
    throw verificationError(
      'invalid_manifest',
      'Approved roster prior chain state is invalid',
    );
  }
  if (manifest.repositoryNodeId !== previous.repositoryNodeId) {
    throw verificationError(
      'repository_mismatch',
      'Approved roster repository node ID does not match prior chain state',
    );
  }
  if (manifest.sequence < previous.sequence) {
    throw verificationError(
      'sequence_rollback',
      'Approved roster sequence would roll back accepted state',
    );
  }
  if (manifest.sequence === previous.sequence) {
    throw verificationError(
      runHash === previous.runDigest ? 'sequence_replay' : 'sequence_fork',
      runHash === previous.runDigest
        ? 'Approved roster sequence was already accepted'
        : 'Approved roster sequence conflicts with accepted state',
    );
  }
  if (manifest.sequence !== previous.sequence + 1) {
    throw verificationError(
      'sequence_gap',
      'Approved roster sequence must advance by exactly one',
    );
  }
  if (manifest.priorDigest !== previous.runDigest) {
    throw verificationError(
      'prior_digest_mismatch',
      'Approved roster priorDigest does not match accepted state',
    );
  }
}

function assertAuthorityEvidenceItem(
  item: RepositoryPermissionObservation | ApprovedMaintainerRosterEntry,
  eventTime: string,
): void {
  const evidence: LabelAuthorityEvidence = {
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: 'operator-validation:label-event',
      repositoryNodeId: item.repositoryNodeId,
      repository: item.repository,
      issueNumber: 1,
      eventId: 'operator-validation-event',
      action: 'labeled',
      label: 'operator-validation',
      eventTime,
      actor: {
        nodeId: item.actorNodeId,
        login: item.actorLogin,
        type: item.actorType,
        association: item.actorAssociation,
      },
    },
    permissionObservations:
      item.kind === 'repository_permission_observation' ? [item] : [],
    approvedRosterEntries:
      item.kind === 'approved_roster_entry' ? [item] : [],
  };
  const problems = labelAuthorityEvidenceProblems(evidence);
  if (problems.length > 0) {
    throw new TypeError(`Invalid label authority evidence item: ${problems.join('; ')}`);
  }
}

function keySecret(
  keyring: ApprovedMaintainerRosterVerificationKeyring,
  keyId: string,
): Buffer {
  const secret = KEYRING_SECRETS.get(keyring)?.get(keyId);
  if (!secret) {
    throw verificationError(
      'unknown_key',
      `Approved roster references unknown key ID ${keyId}`,
    );
  }
  return secret;
}

function decodeKeySecret(value: unknown, keyId: string): Buffer {
  if (
    typeof value !== 'string' ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw verificationError(
      'invalid_keyring',
      `Approved roster key ${keyId} secret encoding is invalid`,
    );
  }
  const secret = Buffer.from(value, 'base64');
  if (secret.length < 32 || secret.toString('base64') !== value) {
    throw verificationError(
      'invalid_keyring',
      `Approved roster key ${keyId} must contain at least 32 bytes`,
    );
  }
  return secret;
}

function hmacSignature(secret: Buffer, payload: string): string {
  return createHmac('sha256', secret)
    .update(`approved-maintainer-roster-signature-v2\0${payload}`)
    .digest('hex');
}

function safeHexEqual(left: string, right: string): boolean {
  if (!isSha256(left) || !isSha256(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function parseJsonFile(
  path: string,
  label: string,
  readFile?: (path: string) => string,
): unknown {
  if (typeof path !== 'string' || !path.trim() || path.trim() !== path) {
    throw new TypeError(`${label} path must be an explicit normalized path`);
  }
  if (!isAbsolute(path)) throw new TypeError(`${label} path must be absolute`);
  const raw = (readFile ?? ((filePath) => readFileSync(filePath, 'utf8')))(path);
  try {
    return JSON.parse(raw);
  } catch {
    throw new TypeError(`${label} is not valid JSON`);
  }
}

function normalizePermission(value: RepositoryPermission): RepositoryPermission {
  const permission = String(value).toLowerCase() as RepositoryPermission;
  if (!PERMISSIONS.has(permission)) {
    throw new TypeError(`Unsupported repository collaborator permission ${String(value)}`);
  }
  return permission;
}

function normalizeRepository(value: string): string {
  return requiredString(value, 'repository').toLowerCase();
}

function normalizeLogin(value: string): string {
  const login = requiredString(value, 'login').toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,38})(?:\[bot\])?$/.test(login)) {
    throw new TypeError(`Invalid GitHub login ${value}`);
  }
  return login;
}

function normalizeOptionalText(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== 'string' || !value || value.trim() !== value) return null;
  return value;
}

function normalizeTimestamp(value: string, field: string): string {
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch)) throw new TypeError(`${field} must be a valid timestamp`);
  return new Date(epoch).toISOString();
}

function normalizeTimestampForVerification(
  value: unknown,
  message: string,
  code: ApprovedRosterVerificationErrorCode,
): string {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw verificationError(code, message);
  }
  return new Date(Date.parse(value)).toISOString();
}

function requiredString(value: unknown, field: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    throw new TypeError(`${field} must be a normalized non-empty string`);
  }
  return value;
}

function requiredStringForVerification(
  value: unknown,
  message: string,
  code: ApprovedRosterVerificationErrorCode,
): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    throw verificationError(code, message);
  }
  return value;
}

function requireNodeId(value: unknown, field: string): string {
  if (!isNodeId(value)) throw new TypeError(`${field} is missing or non-canonical`);
  return value;
}

function requireNodeIdForVerification(
  value: unknown,
  message: string,
  code: ApprovedRosterVerificationErrorCode,
): string {
  if (!isNodeId(value)) throw verificationError(code, message);
  return value;
}

function isNodeId(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    value.trim() === value;
}

function isRepository(value: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,38})\/[a-z0-9_.-]{1,100}$/.test(value) &&
    !value.endsWith('/.') &&
    !value.endsWith('/..');
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, any> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function assertExactKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  context: string,
  code: ApprovedRosterVerificationErrorCode,
): void {
  const unknown = Object.keys(value)
    .filter((key) => !allowed.has(key))
    .sort(compareBinary);
  const missing = [...allowed]
    .filter((key) => !Object.prototype.hasOwnProperty.call(value, key))
    .sort(compareBinary);
  if (unknown.length > 0 || missing.length > 0) {
    throw verificationError(
      code,
      `${context} keys are invalid` +
        `${unknown.length > 0 ? `; unknown: ${unknown.join(', ')}` : ''}` +
        `${missing.length > 0 ? `; missing: ${missing.join(', ')}` : ''}`,
    );
  }
}

function verificationError(
  code: ApprovedRosterVerificationErrorCode,
  message: string,
): ApprovedRosterVerificationError {
  return new ApprovedRosterVerificationError(code, message);
}

function safeErrorMessage(error: unknown): string {
  if (error instanceof ApprovedRosterVerificationError) {
    return `${error.code}: ${error.message}`;
  }
  return error instanceof Error ? error.message : String(error);
}

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  return `{${Object.keys(value as Record<string, unknown>)
    .sort(compareBinary)
    .map((key) =>
      `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
    .join(',')}}`;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function sha256Buffer(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

function sha256Json(value: unknown): string {
  return sha256(canonicalJson(value));
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value as Record<string, unknown>)) {
      deepFreeze(item);
    }
  }
  return value;
}
