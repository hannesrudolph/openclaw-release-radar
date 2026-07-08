import { createHash } from 'node:crypto';
import { canonicalJson } from './operationReceipts';

export const RELEASE_CATALOG_CAPTURE_RECEIPT_SCHEMA_VERSION = 1;
export const RELEASE_CATALOG_CAPTURE_RECEIPT_HASH_DOMAIN =
  'release-catalog-capture-receipt-v1';
export const RELEASE_CATALOG_CAPTURE_RECEIPT_ID_DOMAIN =
  'release-catalog-capture-receipt-id-v1';

export type ReleaseCatalogCaptureSource =
  | 'github_graphql'
  | 'test_fixture';

export interface ReleaseCatalogCaptureSweep {
  repositoryNodeId: string;
  repositoryNameWithOwner: string;
  digest: string;
  totalCount: number;
  nodeCount: number;
  publishedCount: number;
  draftCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  sweepPageCounts: number[];
  exhausted: true;
  stabilized: true;
  sourceOrder: 'CREATED_AT_DESC';
}

export interface ReleaseCatalogCaptureLatestStable {
  nodeId: string;
  tag: string;
  tagCommitOid: string;
  publishedAt: string;
}

export interface ReleaseCatalogCaptureActiveCatalog {
  digest: string;
  releaseCount: number;
  stableCount: number;
  prereleaseCount: number;
  tags: string[];
  latestStable: ReleaseCatalogCaptureLatestStable | null;
}

export interface ReleaseCatalogActiveProjectionRow {
  catalog_rank?: number | null;
  node_id: string | null;
  catalog_tag_commit_oid: string | null;
  tag: string;
  name: string | null;
  published_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  html_url: string;
  prerelease: boolean | number;
  body: string | null;
}

export interface ReleaseCatalogActiveProjection
  extends ReleaseCatalogCaptureActiveCatalog {
  schemaVersion: 1;
}

export interface ReleaseCatalogCaptureReceiptPayload {
  schemaVersion: typeof RELEASE_CATALOG_CAPTURE_RECEIPT_SCHEMA_VERSION;
  source: ReleaseCatalogCaptureSource;
  repository: string;
  observedAt: string;
  operationRunId: string | null;
  operation: string | null;
  operationAttemptContentHash: string | null;
  remoteCatalog: ReleaseCatalogCaptureSweep | null;
  activeCatalog: ReleaseCatalogCaptureActiveCatalog;
}

export interface ReleaseCatalogCaptureReceiptHashInput {
  payload: ReleaseCatalogCaptureReceiptPayload;
  previousContentHash: string | null;
}

export interface ReleaseCatalogCaptureReceiptStorageRow {
  id: number;
  receipt_id: string;
  operation_run_id: string | null;
  source_kind: string;
  repository: string;
  observed_at: string;
  active_catalog_digest: string;
  active_release_count: number;
  payload_json: string;
  previous_content_hash: string | null;
  content_hash: string;
}

export interface ReleaseCatalogCaptureOperationAttemptRow {
  run_id: string;
  operation: string;
  started_at: string;
  effective_config_json: string;
  content_hash: string;
}

export interface ReleaseCatalogCaptureTerminalReceiptRow {
  run_id: string;
  status: string;
  finished_at: string;
  payload_json: string;
}

export interface ReleaseCatalogCaptureLedgerVerification {
  receiptCount: number;
  latestReceiptId: string | null;
  latestOperationRunId: string | null;
  latestSource: ReleaseCatalogCaptureSource | null;
  latestPayload: ReleaseCatalogCaptureReceiptPayload | null;
  ledgerProblems: string[];
  currentProblems: string[];
  problems: string[];
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const OID_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const TOP_LEVEL_KEYS = new Set([
  'schemaVersion',
  'source',
  'repository',
  'observedAt',
  'operationRunId',
  'operation',
  'operationAttemptContentHash',
  'remoteCatalog',
  'activeCatalog',
]);
const REMOTE_CATALOG_KEYS = new Set([
  'repositoryNodeId',
  'repositoryNameWithOwner',
  'digest',
  'totalCount',
  'nodeCount',
  'publishedCount',
  'draftCount',
  'pageCount',
  'pagesFetched',
  'sweepCount',
  'sweepPageCounts',
  'exhausted',
  'stabilized',
  'sourceOrder',
]);
const ACTIVE_CATALOG_KEYS = new Set([
  'digest',
  'releaseCount',
  'stableCount',
  'prereleaseCount',
  'tags',
  'latestStable',
]);
const LATEST_STABLE_KEYS = new Set([
  'nodeId',
  'tag',
  'tagCommitOid',
  'publishedAt',
]);

export function projectReleaseCatalogActiveRows(
  rows: readonly ReleaseCatalogActiveProjectionRow[],
): ReleaseCatalogActiveProjection {
  const tags = new Set<string>();
  const nodeIds = new Set<string>();
  const normalized = rows.map((row, index) => {
    if (
      row.catalog_rank != null &&
      (!Number.isSafeInteger(row.catalog_rank) || row.catalog_rank !== index)
    ) {
      throw new Error(
        `Active release catalog ${row.tag} has non-canonical rank ` +
        `${String(row.catalog_rank)} at position ${index}`,
      );
    }
    if (!row.tag || row.tag.trim() !== row.tag) {
      throw new Error('Active release catalog contains an invalid tag');
    }
    if (!row.node_id || row.node_id.trim() !== row.node_id) {
      throw new Error(
        `Active release catalog release ${row.tag} is missing node_id`,
      );
    }
    if (!OID_PATTERN.test(String(row.catalog_tag_commit_oid ?? '').toLowerCase())) {
      throw new Error(
        `Active release catalog release ${row.tag} has invalid catalog tag commit OID`,
      );
    }
    if (tags.has(row.tag)) {
      throw new Error(
        `Active release catalog contains duplicate tag ${row.tag}`,
      );
    }
    if (nodeIds.has(row.node_id)) {
      throw new Error(
        `Active release catalog contains duplicate node_id ${row.node_id}`,
      );
    }
    const prerelease =
      row.prerelease === true || row.prerelease === 1
        ? 1
        : row.prerelease === false || row.prerelease === 0
          ? 0
          : null;
    if (prerelease == null) {
      throw new Error(
        `Active release catalog release ${row.tag} has invalid prerelease state`,
      );
    }
    for (const [field, value] of [
      ['published_at', row.published_at],
      ['created_at', row.created_at],
      ['updated_at', row.updated_at],
    ] as const) {
      if (
        typeof value !== 'string' ||
        !Number.isFinite(Date.parse(value))
      ) {
        throw new Error(
          `Active release catalog ${row.tag} has invalid ${field} ` +
          `${String(value)}`,
        );
      }
    }
    if (!row.html_url || row.html_url.trim() !== row.html_url) {
      throw new Error(
        `Active release catalog release ${row.tag} has invalid html_url`,
      );
    }
    tags.add(row.tag);
    nodeIds.add(row.node_id);
    return {
      catalog_rank: index,
      node_id: row.node_id,
      catalog_tag_commit_oid:
        String(row.catalog_tag_commit_oid).toLowerCase(),
      tag: row.tag,
      name: row.name,
      published_at: row.published_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
      html_url: row.html_url,
      prerelease,
      body: row.body,
    };
  });
  const digest = createHash('sha256')
    .update(JSON.stringify([
      'active_release_catalog',
      1,
      normalized.map((row) => [
        row.catalog_rank,
        row.node_id,
        row.catalog_tag_commit_oid,
        row.tag,
        row.name,
        row.published_at,
        row.created_at,
        row.updated_at,
        row.html_url,
        row.prerelease,
        row.body,
      ]),
    ]))
    .digest('hex');
  const latestStable =
    normalized.find((row) => row.prerelease === 0) ?? null;
  return {
    schemaVersion: 1,
    digest,
    releaseCount: normalized.length,
    stableCount:
      normalized.filter((row) => row.prerelease === 0).length,
    prereleaseCount:
      normalized.filter((row) => row.prerelease === 1).length,
    tags: normalized.map((row) => row.tag),
    latestStable: latestStable
      ? {
          nodeId: latestStable.node_id,
          tag: latestStable.tag,
          tagCommitOid: latestStable.catalog_tag_commit_oid,
          publishedAt: latestStable.published_at!,
        }
      : null,
  };
}

export function releaseCatalogCaptureReceiptPayloadProblems(
  payload: unknown,
): string[] {
  const problems: string[] = [];
  if (!isRecord(payload)) {
    return ['catalog capture receipt payload must be an object'];
  }
  problems.push(...unknownKeyProblems(
    payload,
    TOP_LEVEL_KEYS,
    'catalog capture receipt payload',
  ));
  if (payload.schemaVersion !== RELEASE_CATALOG_CAPTURE_RECEIPT_SCHEMA_VERSION) {
    problems.push(
      `catalog capture receipt schemaVersion must equal ` +
        `${RELEASE_CATALOG_CAPTURE_RECEIPT_SCHEMA_VERSION}`,
    );
  }
  if (payload.source !== 'github_graphql' && payload.source !== 'test_fixture') {
    problems.push('catalog capture receipt source is unsupported');
  }
  if (!isRepository(payload.repository)) {
    problems.push('catalog capture receipt repository must use owner/name');
  }
  if (!isCanonicalTimestamp(payload.observedAt)) {
    problems.push(
      'catalog capture receipt observedAt must be a canonical ISO timestamp',
    );
  }

  const operationRunId =
    typeof payload.operationRunId === 'string' &&
    payload.operationRunId.length > 0 &&
    payload.operationRunId.trim() === payload.operationRunId
      ? payload.operationRunId
      : null;
  const operation =
    typeof payload.operation === 'string' &&
    payload.operation.length > 0 &&
    payload.operation.trim() === payload.operation
      ? payload.operation
      : null;
  if (payload.source === 'github_graphql') {
    if (operationRunId == null) {
      problems.push('GitHub catalog capture receipt requires operationRunId');
    }
    if (operation == null) {
      problems.push('GitHub catalog capture receipt requires operation');
    }
    if (!SHA256_PATTERN.test(String(payload.operationAttemptContentHash ?? ''))) {
      problems.push(
        'GitHub catalog capture receipt requires an operation attempt content hash',
      );
    }
  } else {
    if (payload.operationRunId !== null) {
      problems.push(
        'test fixture catalog capture receipt cannot carry operationRunId',
      );
    }
    if (payload.operation !== null) {
      problems.push('test fixture catalog capture receipt cannot carry operation');
    }
    if (payload.operationAttemptContentHash !== null) {
      problems.push(
        'test fixture catalog capture receipt cannot carry an operation attempt hash',
      );
    }
  }

  if (payload.source === 'github_graphql') {
    problems.push(...releaseCatalogCaptureSweepProblems(payload.remoteCatalog));
  } else if (payload.remoteCatalog !== null) {
    problems.push(
      'test fixture catalog capture receipt cannot carry remoteCatalog',
    );
  }

  problems.push(
    ...releaseCatalogCaptureActiveCatalogProblems(payload.activeCatalog),
  );
  const remote = isRecord(payload.remoteCatalog)
    ? payload.remoteCatalog
    : null;
  const active = isRecord(payload.activeCatalog)
    ? payload.activeCatalog
    : null;
  if (
    payload.source === 'github_graphql' &&
    remote &&
    active &&
    remote.publishedCount !== active.releaseCount
  ) {
    problems.push(
      'GitHub catalog capture receipt active release count must equal remote published count',
    );
  }
  if (
    payload.source === 'github_graphql' &&
    remote &&
    remote.repositoryNameWithOwner !== payload.repository
  ) {
    problems.push(
      'GitHub catalog capture receipt repository must match remote repository identity',
    );
  }
  return [...new Set(problems)];
}

function releaseCatalogCaptureSweepProblems(value: unknown): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) {
    return ['GitHub catalog capture receipt remoteCatalog is missing'];
  }
  problems.push(...unknownKeyProblems(
    value,
    REMOTE_CATALOG_KEYS,
    'GitHub catalog capture receipt remoteCatalog',
  ));
  if (!SHA256_PATTERN.test(String(value.digest ?? ''))) {
    problems.push('GitHub catalog capture receipt remote digest must be sha256');
  }
  if (
    typeof value.repositoryNodeId !== 'string' ||
    !value.repositoryNodeId ||
    value.repositoryNodeId.trim() !== value.repositoryNodeId
  ) {
    problems.push(
      'GitHub catalog capture receipt repositoryNodeId must be canonical',
    );
  }
  if (!isRepository(value.repositoryNameWithOwner)) {
    problems.push(
      'GitHub catalog capture receipt repositoryNameWithOwner must use owner/name',
    );
  }
  for (const key of [
    'totalCount',
    'nodeCount',
    'publishedCount',
    'draftCount',
    'pageCount',
    'pagesFetched',
    'sweepCount',
  ] as const) {
    if (!isNonnegativeInteger(value[key])) {
      problems.push(
        `GitHub catalog capture receipt ${key} must be a non-negative integer`,
      );
    }
  }
  if (value.nodeCount !== value.totalCount) {
    problems.push(
      'GitHub catalog capture receipt nodeCount must equal totalCount',
    );
  }
  if (value.publishedCount + value.draftCount !== value.nodeCount) {
    problems.push(
      'GitHub catalog capture receipt published and draft counts must equal nodeCount',
    );
  }
  if (!Number.isSafeInteger(value.pageCount) || value.pageCount <= 0) {
    problems.push(
      'GitHub catalog capture receipt pageCount must be positive',
    );
  }
  if (!Number.isSafeInteger(value.sweepCount) || value.sweepCount < 2) {
    problems.push(
      'GitHub catalog capture receipt sweepCount must prove stabilization',
    );
  }
  if (
    !Array.isArray(value.sweepPageCounts) ||
    value.sweepPageCounts.some(
      (count) => !Number.isSafeInteger(count) || count <= 0,
    )
  ) {
    problems.push(
      'GitHub catalog capture receipt sweepPageCounts must contain positive integers',
    );
  } else {
    if (value.sweepPageCounts.length !== value.sweepCount) {
      problems.push(
        'GitHub catalog capture receipt sweepPageCounts length must equal sweepCount',
      );
    }
    if (value.sweepPageCounts.at(-1) !== value.pageCount) {
      problems.push(
        'GitHub catalog capture receipt pageCount must equal the final sweep page count',
      );
    }
    const exactPagesFetched = value.sweepPageCounts.reduce(
      (sum, count) => sum + count,
      0,
    );
    if (value.pagesFetched !== exactPagesFetched) {
      problems.push(
        'GitHub catalog capture receipt pagesFetched must equal the exact per-sweep page total',
      );
    }
  }
  if (value.exhausted !== true) {
    problems.push('GitHub catalog capture receipt must prove exhaustion');
  }
  if (value.stabilized !== true) {
    problems.push('GitHub catalog capture receipt must prove stabilization');
  }
  if (value.sourceOrder !== 'CREATED_AT_DESC') {
    problems.push(
      'GitHub catalog capture receipt sourceOrder must equal CREATED_AT_DESC',
    );
  }
  return problems;
}

function releaseCatalogCaptureActiveCatalogProblems(value: unknown): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) {
    return ['catalog capture receipt activeCatalog is missing'];
  }
  problems.push(...unknownKeyProblems(
    value,
    ACTIVE_CATALOG_KEYS,
    'catalog capture receipt activeCatalog',
  ));
  if (!SHA256_PATTERN.test(String(value.digest ?? ''))) {
    problems.push('catalog capture receipt active digest must be sha256');
  }
  for (const key of [
    'releaseCount',
    'stableCount',
    'prereleaseCount',
  ] as const) {
    if (!isNonnegativeInteger(value[key])) {
      problems.push(
        `catalog capture receipt ${key} must be a non-negative integer`,
      );
    }
  }
  if (value.stableCount + value.prereleaseCount !== value.releaseCount) {
    problems.push(
      'catalog capture receipt stable and prerelease counts must equal releaseCount',
    );
  }
  if (
    !Array.isArray(value.tags) ||
    value.tags.some(
      (tag) =>
        typeof tag !== 'string' ||
        !tag ||
        tag.trim() !== tag,
    )
  ) {
    problems.push(
      'catalog capture receipt tags must be canonical non-empty strings',
    );
  } else {
    if (value.tags.length !== value.releaseCount) {
      problems.push(
        'catalog capture receipt tag count must equal releaseCount',
      );
    }
    if (new Set(value.tags).size !== value.tags.length) {
      problems.push('catalog capture receipt tags must be unique');
    }
  }

  if (value.stableCount === 0) {
    if (value.latestStable !== null) {
      problems.push(
        'catalog capture receipt without stable releases cannot carry latestStable',
      );
    }
    return problems;
  }
  if (!isRecord(value.latestStable)) {
    problems.push('catalog capture receipt latestStable is missing');
    return problems;
  }
  problems.push(...unknownKeyProblems(
    value.latestStable,
    LATEST_STABLE_KEYS,
    'catalog capture receipt latestStable',
  ));
  if (
    typeof value.latestStable.nodeId !== 'string' ||
    !value.latestStable.nodeId ||
    value.latestStable.nodeId.trim() !== value.latestStable.nodeId
  ) {
    problems.push(
      'catalog capture receipt latestStable nodeId must be canonical',
    );
  }
  if (
    typeof value.latestStable.tag !== 'string' ||
    !value.latestStable.tag ||
    value.latestStable.tag.trim() !== value.latestStable.tag
  ) {
    problems.push(
      'catalog capture receipt latestStable tag must be canonical',
    );
  } else if (
    Array.isArray(value.tags) &&
    !value.tags.includes(value.latestStable.tag)
  ) {
    problems.push(
      'catalog capture receipt latestStable tag is not in tags',
    );
  }
  if (
    typeof value.latestStable.tagCommitOid !== 'string' ||
    !OID_PATTERN.test(value.latestStable.tagCommitOid)
  ) {
    problems.push(
      'catalog capture receipt latestStable tagCommitOid must be a lowercase commit OID',
    );
  }
  if (!isCanonicalGithubTimestamp(value.latestStable.publishedAt)) {
    problems.push(
      'catalog capture receipt latestStable publishedAt must be a canonical ISO timestamp',
    );
  }
  return problems;
}

export function releaseCatalogCaptureReceiptContentHash(
  input: ReleaseCatalogCaptureReceiptHashInput,
): string {
  const problems = releaseCatalogCaptureReceiptPayloadProblems(input.payload);
  if (problems.length > 0) {
    throw new Error(
      `Invalid catalog capture receipt payload: ${problems.join('; ')}`,
    );
  }
  if (
    input.previousContentHash !== null &&
    !SHA256_PATTERN.test(input.previousContentHash)
  ) {
    throw new Error(
      'Catalog capture receipt previousContentHash must be null or sha256',
    );
  }
  return createHash('sha256')
    .update(`${RELEASE_CATALOG_CAPTURE_RECEIPT_HASH_DOMAIN}\0`)
    .update(canonicalJson({
      payload: input.payload,
      previousContentHash: input.previousContentHash,
    }))
    .digest('hex');
}

export function releaseCatalogCaptureReceiptId(contentHash: string): string {
  if (!SHA256_PATTERN.test(contentHash)) {
    throw new Error('Catalog capture receipt content hash must be sha256');
  }
  return createHash('sha256')
    .update(`${RELEASE_CATALOG_CAPTURE_RECEIPT_ID_DOMAIN}\0${contentHash}`)
    .digest('hex');
}

export function verifyReleaseCatalogCaptureReceiptLedger(input: {
  receipts: readonly ReleaseCatalogCaptureReceiptStorageRow[];
  attempts: readonly ReleaseCatalogCaptureOperationAttemptRow[];
  terminalReceipts: readonly ReleaseCatalogCaptureTerminalReceiptRow[];
  expectedRepository: string;
  activeCatalog: ReleaseCatalogCaptureActiveCatalog;
  allowTestFixture?: boolean;
  pendingOperationRunId?: string | null;
}): ReleaseCatalogCaptureLedgerVerification {
  const ledgerProblems: string[] = [];
  const currentProblems: string[] = [];
  const attemptsByRun = new Map(
    input.attempts.map((attempt) => [String(attempt.run_id), attempt]),
  );
  const terminalReceiptsByRun = new Map(
    input.terminalReceipts.map((receipt) => [
      String(receipt.run_id),
      receipt,
    ]),
  );
  const receipts = [...input.receipts].sort(
    (left, right) => Number(left.id) - Number(right.id),
  );
  const parsedPayloads = new Map<number, ReleaseCatalogCaptureReceiptPayload>();
  const catalogReceiptRunIds = new Set<string>();
  const seenStorageIds = new Set<number>();
  const seenReceiptIds = new Set<string>();
  const seenContentHashes = new Set<string>();
  let previousContentHash: string | null = null;

  for (let index = 0; index < receipts.length; index++) {
    const row = receipts[index];
    const prefix =
      `catalog receipt ${JSON.stringify(String(row.receipt_id ?? ''))}`;
    if (!Number.isSafeInteger(row.id) || row.id <= 0) {
      ledgerProblems.push(`${prefix} has invalid storage ID`);
    } else if (seenStorageIds.has(row.id)) {
      ledgerProblems.push(`${prefix} duplicates storage ID ${row.id}`);
    }
    seenStorageIds.add(row.id);
    if (!SHA256_PATTERN.test(String(row.receipt_id ?? ''))) {
      ledgerProblems.push(`${prefix} has invalid receipt ID`);
    } else if (seenReceiptIds.has(row.receipt_id)) {
      ledgerProblems.push(`${prefix} duplicates its receipt ID`);
    }
    seenReceiptIds.add(row.receipt_id);
    if (!SHA256_PATTERN.test(String(row.content_hash ?? ''))) {
      ledgerProblems.push(`${prefix} has invalid content hash`);
    } else if (seenContentHashes.has(row.content_hash)) {
      ledgerProblems.push(`${prefix} duplicates its content hash`);
    }
    seenContentHashes.add(row.content_hash);
    if ((row.previous_content_hash ?? null) !== previousContentHash) {
      ledgerProblems.push(`${prefix} previous content hash mismatch`);
    }

    let payload: ReleaseCatalogCaptureReceiptPayload | null = null;
    try {
      const parsed = JSON.parse(String(row.payload_json));
      if (
        !isRecord(parsed) ||
        canonicalJson(parsed) !== row.payload_json
      ) {
        ledgerProblems.push(`${prefix} payload_json is not canonical`);
      }
      const payloadProblems =
        releaseCatalogCaptureReceiptPayloadProblems(parsed);
      if (payloadProblems.length > 0) {
        ledgerProblems.push(
          ...payloadProblems.map((problem) => `${prefix}: ${problem}`),
        );
      } else {
        payload = parsed as ReleaseCatalogCaptureReceiptPayload;
        parsedPayloads.set(row.id, payload);
      }
    } catch (error) {
      ledgerProblems.push(
        `${prefix} has invalid payload_json: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }

    if (payload) {
      if (
        row.source_kind !== payload.source ||
        (row.operation_run_id ?? null) !== payload.operationRunId ||
        row.repository !== payload.repository ||
        row.observed_at !== payload.observedAt ||
        row.active_catalog_digest !== payload.activeCatalog.digest ||
        row.active_release_count !== payload.activeCatalog.releaseCount
      ) {
        ledgerProblems.push(
          `${prefix} storage columns do not match its canonical payload`,
        );
      }
      try {
        const contentHash = releaseCatalogCaptureReceiptContentHash({
          payload,
          previousContentHash,
        });
        if (row.content_hash !== contentHash) {
          ledgerProblems.push(`${prefix} content hash mismatch`);
        }
        if (row.receipt_id !== releaseCatalogCaptureReceiptId(contentHash)) {
          ledgerProblems.push(`${prefix} receipt ID mismatch`);
        }
      } catch (error) {
        ledgerProblems.push(
          `${prefix} hash verification failed: ` +
          `${error instanceof Error ? error.message : String(error)}`,
        );
      }

      if (payload.source === 'test_fixture') {
        if (input.allowTestFixture !== true) {
          ledgerProblems.push(
            `${prefix} uses forbidden test_fixture authority`,
          );
        }
      } else {
        catalogReceiptRunIds.add(payload.operationRunId!);
        const attempt = attemptsByRun.get(payload.operationRunId!);
        if (!attempt) {
          ledgerProblems.push(
            `${prefix} references a missing refresh operation attempt`,
          );
        } else {
          if (
            payload.operation !== attempt.operation ||
            payload.operationAttemptContentHash !== attempt.content_hash
          ) {
            ledgerProblems.push(
              `${prefix} does not bind the exact refresh operation attempt`,
            );
          }
          if (!isCanonicalTimestamp(attempt.started_at)) {
            ledgerProblems.push(
              `${prefix} refresh operation attempt has invalid started_at`,
            );
          } else if (
            Date.parse(payload.observedAt) < Date.parse(attempt.started_at)
          ) {
            ledgerProblems.push(
              `${prefix} predates its refresh operation attempt`,
            );
          }
          const configuredRepository =
            repositoryFromEffectiveConfig(attempt.effective_config_json);
          if (configuredRepository !== payload.repository) {
            ledgerProblems.push(
              `${prefix} repository does not match the operation effective config`,
            );
          }
        }
        const terminal =
          terminalReceiptsByRun.get(payload.operationRunId!);
        if (!terminal && index < receipts.length - 1) {
          ledgerProblems.push(
            `${prefix} has no terminal receipt before a later catalog capture`,
          );
        } else if (terminal) {
          if (
            !['success', 'failure', 'abandoned'].includes(terminal.status)
          ) {
            ledgerProblems.push(
              `${prefix} has an invalid terminal receipt status`,
            );
          }
          if (!isCanonicalTimestamp(terminal.finished_at)) {
            ledgerProblems.push(
              `${prefix} terminal receipt has invalid finished_at`,
            );
          } else if (
            Date.parse(payload.observedAt) >
            Date.parse(terminal.finished_at)
          ) {
            ledgerProblems.push(
              `${prefix} was observed after its terminal receipt`,
            );
          }
        }
      }
    }
    previousContentHash = row.content_hash;
  }

  if (input.allowTestFixture !== true) {
    for (const terminal of input.terminalReceipts) {
      const runId = String(terminal.run_id);
      if (
        terminal.status === 'success' &&
        attemptsByRun.has(runId) &&
        !catalogReceiptRunIds.has(runId)
      ) {
        ledgerProblems.push(
          `successful refresh operation ${JSON.stringify(runId)} has no ` +
          `release catalog capture receipt`,
        );
      }
    }
  }

  const latest = receipts.at(-1) ?? null;
  const latestPayload = latest
    ? parsedPayloads.get(latest.id) ?? null
    : null;
  if (!latest || !latestPayload) {
    currentProblems.push(
      'active release catalog has no valid immutable capture receipt',
    );
  } else {
    if (latestPayload.repository !== input.expectedRepository) {
      currentProblems.push(
        'latest catalog capture receipt repository does not match configuration',
      );
    }
    if (
      canonicalJson(latestPayload.activeCatalog) !==
      canonicalJson(input.activeCatalog)
    ) {
      currentProblems.push(
        'latest catalog capture receipt does not match the exact active catalog projection',
      );
    }
    if (latestPayload.source === 'test_fixture') {
      if (input.allowTestFixture !== true) {
        currentProblems.push(
          'test_fixture catalog receipt cannot authorize product reads or promotion',
        );
      }
    } else {
      const terminal =
        terminalReceiptsByRun.get(latestPayload.operationRunId!);
      if (!terminal) {
        if (
          input.pendingOperationRunId !== latestPayload.operationRunId
        ) {
          currentProblems.push(
            'latest GitHub catalog capture has no same-run terminal receipt',
          );
        }
      } else if (terminal.status !== 'success') {
        currentProblems.push(
          `latest GitHub catalog capture run terminated with ${terminal.status}`,
        );
      } else {
        currentProblems.push(
          ...successfulTerminalCatalogBindingProblems(
            latestPayload,
            terminal,
          ),
        );
      }
    }
  }

  const uniqueLedgerProblems = [...new Set(ledgerProblems)];
  const uniqueCurrentProblems = [...new Set(currentProblems)];
  return {
    receiptCount: receipts.length,
    latestReceiptId: latest?.receipt_id ?? null,
    latestOperationRunId: latestPayload?.operationRunId ?? null,
    latestSource: latestPayload?.source ?? null,
    latestPayload,
    ledgerProblems: uniqueLedgerProblems,
    currentProblems: uniqueCurrentProblems,
    problems: [
      ...new Set([
        ...uniqueLedgerProblems,
        ...uniqueCurrentProblems,
      ]),
    ],
  };
}

function successfulTerminalCatalogBindingProblems(
  payload: ReleaseCatalogCaptureReceiptPayload,
  terminal: ReleaseCatalogCaptureTerminalReceiptRow,
): string[] {
  const problems: string[] = [];
  let terminalPayload: Record<string, any> | null = null;
  try {
    const parsed = JSON.parse(terminal.payload_json);
    if (
      !isRecord(parsed) ||
      canonicalJson(parsed) !== terminal.payload_json
    ) {
      problems.push(
        'same-run success receipt payload is not canonical',
      );
    } else {
      terminalPayload = parsed;
    }
  } catch {
    problems.push('same-run success receipt payload is invalid');
  }
  if (!terminalPayload) return problems;
  if (terminalPayload.operation !== payload.operation) {
    problems.push(
      'same-run success receipt operation does not match the catalog capture',
    );
  }
  const releaseCatalog = isRecord(terminalPayload.releaseCatalog)
    ? terminalPayload.releaseCatalog
    : null;
  const attestation = isRecord(releaseCatalog?.attestation)
    ? releaseCatalog.attestation
    : null;
  const local = isRecord(attestation?.localActiveCatalog)
    ? attestation.localActiveCatalog
    : null;
  if (
    !payload.remoteCatalog ||
    releaseCatalog?.digest !== payload.remoteCatalog.digest ||
    releaseCatalog?.nodeCount !== payload.remoteCatalog.nodeCount ||
    releaseCatalog?.totalCount !== payload.remoteCatalog.totalCount
  ) {
    problems.push(
      'same-run success receipt does not bind the captured remote catalog',
    );
  }
  if (
    local?.digest !== payload.activeCatalog.digest ||
    local?.releaseCount !== payload.activeCatalog.releaseCount ||
    canonicalJson(attestation?.latestStable ?? null) !==
      canonicalJson(payload.activeCatalog.latestStable)
  ) {
    problems.push(
      'same-run success receipt does not bind the captured active catalog',
    );
  }
  return problems;
}

function repositoryFromEffectiveConfig(value: string): string | null {
  try {
    const parsed = JSON.parse(value);
    if (!isRecord(parsed) || canonicalJson(parsed) !== value) return null;
    const github = isRecord(parsed.github) ? parsed.github : null;
    const owner = github?.owner;
    const repo = github?.repo;
    return (
      typeof owner === 'string' &&
      typeof repo === 'string' &&
      isRepository(`${owner}/${repo}`)
    )
      ? `${owner}/${repo}`
      : null;
  } catch {
    return null;
  }
}

function unknownKeyProblems(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string,
): string[] {
  return Object.keys(value)
    .filter((key) => !allowed.has(key))
    .sort()
    .map((key) => `${label} has unsupported field ${key}`);
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) && new Date(epoch).toISOString() === value;
}

function isCanonicalGithubTimestamp(value: unknown): value is string {
  if (isCanonicalTimestamp(value)) return true;
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
  ) {
    return false;
  }
  const epoch = Date.parse(value);
  return (
    Number.isFinite(epoch) &&
    new Date(epoch).toISOString() === value.replace(/Z$/, '.000Z')
  );
}

function isRepository(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[^/\s]+\/[^/\s]+$/.test(value)
  );
}

function isNonnegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isRecord(value: unknown): value is Record<string, any> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
