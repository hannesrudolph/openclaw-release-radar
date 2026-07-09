import { resolve } from 'node:path';

const DAY_MS = 24 * 60 * 60 * 1000;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export type PreviewDateRange = {
  selector: 'range' | 'month';
  month: string | null;
  from: string;
  through: string;
  startMs: number;
  endExclusiveMs: number;
};

export type PreviewReleaseRow = {
  tag: string;
  published_at: string | null;
  prerelease: number;
  catalog_active: number;
  catalog_rank: number | null;
  catalog_digest: string | null;
  [key: string]: unknown;
};

type PreviewCatalogCapture = {
  receiptId: string;
  operationRunId: string | null;
  sourceKind: string;
  repository: string;
  observedAt: string;
  activeCatalogDigest: string;
  activeReleaseCount: number;
  contentHash: string;
};

type PreviewCatalogOperation = {
  runId: string;
  operation: string;
  trigger: string;
  startedAt: string;
  codeRevision: string;
  effectiveConfigHash: string;
  contentHash: string;
};

type PreviewTerminalReceipt = {
  receiptId: string;
  runId: string;
  status: string;
  finishedAt: string;
  payloadJson: string;
  contentHash: string;
};

type PreviewSnapshotConsumption = {
  snapshotId: string;
  repository: string;
  runId: string;
  consumedAt: string;
  processedRowCount: number;
  processedPageCount: number;
  snapshotContentHash: string;
  contentHash: string;
};

type PreviewIssueCatalogSnapshot = {
  snapshotId: string;
  repository: string;
  capturedAt: string;
  rowCount: number;
  pageCount: number;
  membershipDigest: string;
  contentDigest: string;
  contentHash: string;
};

export type PreviewInspection = {
  missingTables: string[];
  activeCatalog: PreviewReleaseRow[];
  capture: PreviewCatalogCapture | null;
  latestCatalogOperation: PreviewCatalogOperation | null;
  terminalReceipt: PreviewTerminalReceipt | null;
  consumptionByRun: PreviewSnapshotConsumption | null;
  consumptionByDeclaredSnapshot: PreviewSnapshotConsumption | null;
  snapshot: PreviewIssueCatalogSnapshot | null;
};

type TerminalReceiptBindings = {
  payloadProblem: string | null;
  releaseTags: string[] | null;
  issueCrawlMetadata: Record<string, unknown> | null;
  snapshot: {
    snapshotId: string | null;
    contentHash: string | null;
    consumedByRunId: string | null;
    consumptionContentHash: string | null;
  } | null;
  attestation: {
    snapshotId: string | null;
    snapshotContentHash: string | null;
  } | null;
};

export type PreviewCatalogAudit = {
  reasons: string[];
  classifierKnownTags: string[] | null;
  issueCrawlMetadata: Record<string, unknown> | null;
  identities: ReturnType<typeof previewCatalogIdentities>;
  evidenceCounts: ReturnType<typeof previewCatalogEvidenceCounts>;
};

export type PreviewReleasePlan = {
  activeReleaseCount: number;
  stableTagsNewestFirst: string[];
  selectedNewestFirst: PreviewReleaseRow[];
  predecessorByReleaseTag: Record<string, string | null>;
  oldestScoredStablePredecessorTag: string | null;
};

type ClassificationAudit = {
  summary: Record<string, unknown> | null;
  error: string | null;
};

type IntegrityAudit = {
  summary: Record<string, unknown> | null;
  problem: string | null;
  error: string | null;
};

type PreviewReleaseReadinessAudit = {
  ready: boolean;
  reasons: string[];
  scoreLedgerProblems: string[];
  issueTimeline: IntegrityAudit;
  issueStateSnapshots: IntegrityAudit;
  fixCreditProblems: string[];
};

type PreviewReadinessAudit = {
  ready: boolean;
  reasons: string[];
  issueCatalogSnapshotLedger: IntegrityAudit;
  scoreAuthorityProblems: string[];
  crawl: {
    ready: boolean;
    problems: string[];
    error: string | null;
    schemaVersion: number | null;
    stopReason: string | null;
    crawlMode: string | null;
    finishedAt: string | null;
    scorePersisted: boolean | null;
  };
  stableReleaseWindow: IntegrityAudit;
  activeRefresh: {
    active: boolean;
    attemptRunId: string | null;
    leaseName: string | null;
    leaseHolderId: string | null;
    leaseExpiresAt: string | null;
  };
  activeScoreBlockingIngestionFailures: {
    count: number;
    examples: Array<{
      id: number | null;
      runId: string | null;
      occurredAt: string | null;
      source: string | null;
      scope: string | null;
      releaseTag: string | null;
      issueNumber: number | null;
    }>;
  };
  releases: Record<string, PreviewReleaseReadinessAudit>;
};

export type PreviewScoreBundle = {
  evaluatedAt: string;
  plan: PreviewReleasePlan;
  run: Record<string, any> | null;
  classificationAudits: Record<string, ClassificationAudit>;
  completenessAudits: Record<string, IntegrityAudit>;
  closureAudits: Record<string, IntegrityAudit>;
  reachabilityAudits: Record<string, IntegrityAudit>;
  predecessorReachabilityAudit: IntegrityAudit | null;
  readiness: PreviewReadinessAudit;
};

type PreviewInspectionDatabase = {
  prepare(sql: string): {
    all(...args: unknown[]): unknown[];
    get(...args: unknown[]): unknown;
  };
};

let openedDatabaseModule: { db: { close(): void } } | null = null;

export function parsePreviewScoreArgs(
  argv: string[],
  { cwd = process.cwd() }: { cwd?: string } = {},
): {
  databasePath: string;
  range: PreviewDateRange;
} {
  const allowed = new Set(['db-path', 'from', 'through', 'month']);
  const values = new Map<string, string>();

  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (!argument.startsWith('--')) {
      throw new Error(`Unexpected positional argument ${JSON.stringify(argument)}`);
    }
    const equalsIndex = argument.indexOf('=');
    const key = argument.slice(2, equalsIndex === -1 ? undefined : equalsIndex);
    if (!allowed.has(key)) throw new Error(`Unknown option --${key}`);
    if (values.has(key)) throw new Error(`Option --${key} may only be specified once`);

    let value: string;
    if (equalsIndex !== -1) {
      value = argument.slice(equalsIndex + 1);
    } else {
      const next = argv[index + 1];
      if (!next || next.startsWith('--')) {
        throw new Error(`Option --${key} requires a value`);
      }
      value = next;
      index++;
    }
    if (!value || value.trim() !== value) {
      throw new Error(`Option --${key} requires a non-empty value without surrounding whitespace`);
    }
    values.set(key, value);
  }

  const databasePath = values.get('db-path');
  if (!databasePath) {
    throw new Error('Missing required option --db-path');
  }
  const month = values.get('month') ?? null;
  const from = values.get('from') ?? null;
  const through = values.get('through') ?? null;
  if (month && (from || through)) {
    throw new Error('--month cannot be combined with --from or --through');
  }
  if (!month && (!from || !through)) {
    throw new Error('Specify either --month YYYY-MM or both --from and --through');
  }

  return {
    databasePath: resolve(cwd, databasePath),
    range: month
      ? previewMonthRange(month)
      : previewExplicitRange(from!, through!),
  };
}

export function buildPreviewReleasePlan(
  activeCatalog: PreviewReleaseRow[],
  range: PreviewDateRange,
): PreviewReleasePlan {
  const activeRows = activeCatalog.filter((release) =>
    Number(release.catalog_active) === 1);
  const stableNewestFirst = activeRows
    .filter((release) => Number(release.prerelease) === 0)
    .slice()
    .sort(compareCatalogNewestFirst);
  const selectedNewestFirst = stableNewestFirst.filter((release) => {
    const publishedAt = releasePublishedAtMs(release);
    return publishedAt >= range.startMs && publishedAt < range.endExclusiveMs;
  });
  const stableTagsNewestFirst = stableNewestFirst.map((release) => release.tag);
  const predecessorByReleaseTag = Object.fromEntries(
    selectedNewestFirst.map((release) => {
      const index = stableTagsNewestFirst.indexOf(release.tag);
      return [
        release.tag,
        index >= 0 ? stableTagsNewestFirst[index + 1] ?? null : null,
      ];
    }),
  );
  const oldestScoredTag = selectedNewestFirst.at(-1)?.tag ?? null;

  return {
    activeReleaseCount: activeRows.length,
    stableTagsNewestFirst,
    selectedNewestFirst,
    predecessorByReleaseTag,
    oldestScoredStablePredecessorTag: oldestScoredTag
      ? predecessorByReleaseTag[oldestScoredTag] ?? null
      : null,
  };
}

export function readPreviewInspection(
  database: PreviewInspectionDatabase,
): PreviewInspection {
  const requiredTables = [
    'releases',
    'release_catalog_capture_receipts',
    'refresh_operation_attempts',
    'refresh_capture_receipts',
    'issue_catalog_snapshot_consumptions',
    'issue_catalog_snapshots',
  ];
  const existingTables = new Set(
    (database.prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type='table'
    `).all() as Array<Record<string, unknown>>)
      .map((row) => String(row.name ?? '')),
  );
  const missingTables = requiredTables.filter((table) => !existingTables.has(table));
  const activeCatalog = existingTables.has('releases')
    ? database.prepare(`
        SELECT *
        FROM releases
        WHERE catalog_active=1
        ORDER BY
          catalog_rank IS NULL,
          catalog_rank,
          published_at DESC,
          tag
      `).all() as PreviewReleaseRow[]
    : [];
  const capture = existingTables.has('release_catalog_capture_receipts')
    ? mapCatalogCapture(database.prepare(`
        SELECT
          receipt_id AS receiptId,
          operation_run_id AS operationRunId,
          source_kind AS sourceKind,
          repository,
          observed_at AS observedAt,
          active_catalog_digest AS activeCatalogDigest,
          active_release_count AS activeReleaseCount,
          content_hash AS contentHash
        FROM release_catalog_capture_receipts
        ORDER BY id DESC
        LIMIT 1
      `).get())
    : null;
  const latestCatalogOperation =
    existingTables.has('refresh_operation_attempts')
      ? mapCatalogOperation(database.prepare(`
          SELECT
            run_id AS runId,
            operation,
            trigger,
            started_at AS startedAt,
            code_revision AS codeRevision,
            effective_config_hash AS effectiveConfigHash,
            content_hash AS contentHash
          FROM refresh_operation_attempts
          ORDER BY started_at DESC, run_id DESC
          LIMIT 1
        `).get())
      : null;
  const terminalReceipt =
    latestCatalogOperation && existingTables.has('refresh_capture_receipts')
      ? mapTerminalReceipt(database.prepare(`
          SELECT
            receipt_id AS receiptId,
            run_id AS runId,
            status,
            finished_at AS finishedAt,
            payload_json AS payloadJson,
            content_hash AS contentHash
          FROM refresh_capture_receipts
          WHERE run_id=?
        `).get(latestCatalogOperation.runId))
      : null;
  const bindings = terminalReceiptBindings(terminalReceipt?.payloadJson ?? null);
  const consumptionByRun =
    latestCatalogOperation &&
    existingTables.has('issue_catalog_snapshot_consumptions')
      ? mapSnapshotConsumption(database.prepare(`
          SELECT
            snapshot_id AS snapshotId,
            repository,
            run_id AS runId,
            consumed_at AS consumedAt,
            processed_row_count AS processedRowCount,
            processed_page_count AS processedPageCount,
            snapshot_content_hash AS snapshotContentHash,
            content_hash AS contentHash
          FROM issue_catalog_snapshot_consumptions
          WHERE run_id=?
        `).get(latestCatalogOperation.runId))
      : null;
  const declaredSnapshotId = bindings.snapshot?.snapshotId ?? null;
  const consumptionByDeclaredSnapshot =
    declaredSnapshotId &&
    existingTables.has('issue_catalog_snapshot_consumptions')
      ? mapSnapshotConsumption(database.prepare(`
          SELECT
            snapshot_id AS snapshotId,
            repository,
            run_id AS runId,
            consumed_at AS consumedAt,
            processed_row_count AS processedRowCount,
            processed_page_count AS processedPageCount,
            snapshot_content_hash AS snapshotContentHash,
            content_hash AS contentHash
          FROM issue_catalog_snapshot_consumptions
          WHERE snapshot_id=?
        `).get(declaredSnapshotId))
      : null;
  const snapshotId = declaredSnapshotId ?? consumptionByRun?.snapshotId ?? null;
  const snapshot =
    snapshotId && existingTables.has('issue_catalog_snapshots')
      ? mapIssueCatalogSnapshot(database.prepare(`
          SELECT
            snapshot_id AS snapshotId,
            repository,
            captured_at AS capturedAt,
            row_count AS rowCount,
            page_count AS pageCount,
            membership_digest AS membershipDigest,
            content_digest AS contentDigest,
            content_hash AS contentHash
          FROM issue_catalog_snapshots
          WHERE snapshot_id=?
        `).get(snapshotId))
      : null;

  return {
    missingTables,
    activeCatalog,
    capture,
    latestCatalogOperation,
    terminalReceipt,
    consumptionByRun,
    consumptionByDeclaredSnapshot,
    snapshot,
  };
}

export function auditPreviewCatalog(
  inspection: PreviewInspection,
  range: PreviewDateRange,
): PreviewCatalogAudit {
  const reasons = inspection.missingTables.map((table) =>
    `required database table ${table} is missing`);
  const plan = buildPreviewReleasePlan(inspection.activeCatalog, range);
  const capture = inspection.capture;
  const operation = inspection.latestCatalogOperation;
  const terminal = inspection.terminalReceipt;
  const bindings = terminalReceiptBindings(terminal?.payloadJson ?? null);

  if (!capture) {
    reasons.push('active release catalog has no capture receipt');
  } else {
    if (!capture.operationRunId) {
      reasons.push('latest release catalog capture is not bound to a catalog operation');
    } else if (operation && capture.operationRunId !== operation.runId) {
      reasons.push(
        `latest release catalog capture belongs to operation ${capture.operationRunId}, ` +
        `not latest catalog operation ${operation.runId}`,
      );
    }
    if (capture.sourceKind !== 'github_graphql') {
      reasons.push(
        `latest release catalog capture source is ${capture.sourceKind}, not github_graphql`,
      );
    }
    if (!SHA256_PATTERN.test(capture.receiptId)) {
      reasons.push('latest release catalog capture receipt ID is not SHA-256');
    }
    if (!SHA256_PATTERN.test(capture.contentHash)) {
      reasons.push('latest release catalog capture content hash is not SHA-256');
    }
    if (!SHA256_PATTERN.test(capture.activeCatalogDigest)) {
      reasons.push('latest release catalog digest is not SHA-256');
    }
    if (capture.activeReleaseCount !== plan.activeReleaseCount) {
      reasons.push(
        `latest release catalog capture declares ${capture.activeReleaseCount} active releases, ` +
        `but the active catalog contains ${plan.activeReleaseCount}`,
      );
    }
    const activeDigests = [
      ...new Set(
        inspection.activeCatalog
          .map((release) => release.catalog_digest)
          .filter((value): value is string => typeof value === 'string'),
      ),
    ];
    if (
      activeDigests.length !== 1 ||
      activeDigests[0] !== capture.activeCatalogDigest
    ) {
      reasons.push(
        'active release rows do not share the latest release catalog capture digest',
      );
    }
  }

  if (!operation) {
    reasons.push('refresh operation ledger has no latest catalog operation');
  } else {
    if (!SHA256_PATTERN.test(operation.contentHash)) {
      reasons.push('latest catalog operation content hash is not SHA-256');
    }
    if (!SHA256_PATTERN.test(operation.effectiveConfigHash)) {
      reasons.push('latest catalog operation effective config hash is not SHA-256');
    }
    if (!isCanonicalIsoTimestamp(operation.startedAt)) {
      reasons.push('latest catalog operation startedAt is not a canonical ISO timestamp');
    }
    if (!terminal) {
      reasons.push(
        `latest catalog operation ${operation.runId} has no terminal receipt`,
      );
    } else {
      if (terminal.runId !== operation.runId) {
        reasons.push(
          `terminal receipt run ${terminal.runId} does not match catalog operation ` +
          operation.runId,
        );
      }
      if (terminal.status !== 'success') {
        reasons.push(
          `latest catalog operation ${operation.runId} terminal receipt status is ` +
          `${terminal.status}, not success`,
        );
      }
      if (!SHA256_PATTERN.test(terminal.receiptId)) {
        reasons.push('latest catalog operation terminal receipt ID is not SHA-256');
      }
      if (!SHA256_PATTERN.test(terminal.contentHash)) {
        reasons.push('latest catalog operation terminal receipt content hash is not SHA-256');
      }
      if (!isCanonicalIsoTimestamp(terminal.finishedAt)) {
        reasons.push(
          'latest catalog operation terminal receipt finishedAt is not a canonical ISO timestamp',
        );
      }
    }
  }

  const consumption = inspection.consumptionByRun;
  if (operation) {
    if (!consumption) {
      const otherConsumption = inspection.consumptionByDeclaredSnapshot;
      reasons.push(
        otherConsumption
          ? `issue catalog snapshot ${otherConsumption.snapshotId} was consumed by ` +
            `${otherConsumption.runId}, not latest catalog operation ${operation.runId}`
          : `latest catalog operation ${operation.runId} has no matching ` +
            'issue catalog snapshot consumption',
      );
    } else {
      if (consumption.runId !== operation.runId) {
        reasons.push(
          `issue catalog consumption run ${consumption.runId} does not match latest ` +
          `catalog operation ${operation.runId}`,
        );
      }
      if (!SHA256_PATTERN.test(consumption.contentHash)) {
        reasons.push('issue catalog consumption content hash is not SHA-256');
      }
      if (!SHA256_PATTERN.test(consumption.snapshotContentHash)) {
        reasons.push('issue catalog consumption snapshot content hash is not SHA-256');
      }
      if (capture && consumption.repository !== capture.repository) {
        reasons.push(
          `issue catalog consumption repository ${consumption.repository} does not match ` +
          `release catalog repository ${capture.repository}`,
        );
      }
    }
  }

  if (terminal?.status === 'success') {
    if (bindings.payloadProblem) reasons.push(bindings.payloadProblem);
    if (!bindings.releaseTags) {
      reasons.push(
        'successful terminal receipt does not contain a valid releaseTags classifier identity',
      );
    }
    const crawl = bindings.issueCrawlMetadata;
    if (!crawl) {
      reasons.push(
        'successful terminal receipt does not contain issue crawl metadata',
      );
    } else {
      if (crawl.schemaVersion !== 4) {
        reasons.push(
          `successful terminal receipt issue crawl schema is ` +
          `${String(crawl.schemaVersion)}, not 4`,
        );
      }
      if (crawl.stopReason !== 'exhausted' || crawl.crawlMode !== 'exhaustive') {
        reasons.push(
          `successful terminal receipt issue crawl is ` +
          `${String(crawl.crawlMode ?? 'unknown')}/${String(crawl.stopReason ?? 'unknown')}, ` +
          'not exhaustive/exhausted',
        );
      }
      if (crawl.backfillCompleteAfterRun !== true) {
        reasons.push(
          'successful terminal receipt issue crawl has no proven exhaustive baseline',
        );
      }
      const evidenceFailures = Array.isArray(crawl.evidenceRefreshFailures)
        ? crawl.evidenceRefreshFailures
        : null;
      if (!evidenceFailures || evidenceFailures.length > 0) {
        reasons.push(
          evidenceFailures
            ? `successful terminal receipt issue crawl has ${evidenceFailures.length} ` +
              'evidence refresh failure(s)'
            : 'successful terminal receipt issue crawl evidence failures are malformed',
        );
      }
      const classificationFailures = Array.isArray(crawl.classificationFailures)
        ? crawl.classificationFailures
        : null;
      if (!classificationFailures || classificationFailures.length > 0) {
        reasons.push(
          classificationFailures
            ? `successful terminal receipt issue crawl has ${classificationFailures.length} ` +
              'classification failure(s)'
            : 'successful terminal receipt issue crawl classification failures are malformed',
        );
      }
      if (crawl.scorePersisted !== true) {
        reasons.push(
          'successful terminal receipt issue crawl is not bound to persisted score inputs',
        );
      }
    }
    const declaredSnapshot = bindings.snapshot;
    if (!declaredSnapshot) {
      reasons.push(
        'successful terminal receipt does not identify its consumed issue catalog snapshot',
      );
    } else {
      if (
        !declaredSnapshot.snapshotId ||
        !SHA256_PATTERN.test(declaredSnapshot.snapshotId)
      ) {
        reasons.push(
          'successful terminal receipt issue catalog snapshot ID is not SHA-256',
        );
      }
      if (
        !declaredSnapshot.contentHash ||
        declaredSnapshot.contentHash !== declaredSnapshot.snapshotId
      ) {
        reasons.push(
          'successful terminal receipt issue catalog snapshot content hash does not match its ID',
        );
      }
      if (declaredSnapshot.consumedByRunId !== operation?.runId) {
        reasons.push(
          `successful terminal receipt issue catalog snapshot was consumed by ` +
          `${declaredSnapshot.consumedByRunId ?? 'no run'}, not catalog operation ` +
          `${operation?.runId ?? 'unknown'}`,
        );
      }
      if (
        !declaredSnapshot.consumptionContentHash ||
        !SHA256_PATTERN.test(declaredSnapshot.consumptionContentHash)
      ) {
        reasons.push(
          'successful terminal receipt issue catalog consumption content hash is not SHA-256',
        );
      }
    }

    if (consumption) {
      if (
        bindings.snapshot?.snapshotId &&
        consumption.snapshotId !== bindings.snapshot.snapshotId
      ) {
        reasons.push(
          `issue catalog consumption snapshot ${consumption.snapshotId} does not match ` +
          `terminal receipt snapshot ${bindings.snapshot.snapshotId}`,
        );
      }
      if (
        bindings.snapshot?.consumptionContentHash &&
        consumption.contentHash !== bindings.snapshot.consumptionContentHash
      ) {
        reasons.push(
          'issue catalog consumption content hash does not match the terminal receipt',
        );
      }
      if (
        bindings.snapshot?.contentHash &&
        consumption.snapshotContentHash !== bindings.snapshot.contentHash
      ) {
        reasons.push(
          'issue catalog consumption snapshot content hash does not match the terminal receipt',
        );
      }
    }

    const snapshot = inspection.snapshot;
    if (!snapshot) {
      reasons.push(
        `issue catalog snapshot ${
          bindings.snapshot?.snapshotId ?? inspection.consumptionByRun?.snapshotId ?? 'unknown'
        } is missing`,
      );
    } else {
      if (
        bindings.snapshot?.snapshotId &&
        snapshot.snapshotId !== bindings.snapshot.snapshotId
      ) {
        reasons.push('stored issue catalog snapshot ID does not match the terminal receipt');
      }
      if (
        bindings.snapshot?.contentHash &&
        snapshot.contentHash !== bindings.snapshot.contentHash
      ) {
        reasons.push(
          'stored issue catalog snapshot content hash does not match the terminal receipt',
        );
      }
      if (
        inspection.consumptionByRun &&
        snapshot.contentHash !== inspection.consumptionByRun.snapshotContentHash
      ) {
        reasons.push(
          'stored issue catalog snapshot content hash does not match its consumption',
        );
      }
      if (
        inspection.consumptionByRun &&
        snapshot.rowCount !== inspection.consumptionByRun.processedRowCount
      ) {
        reasons.push(
          `issue catalog consumption processed ${inspection.consumptionByRun.processedRowCount} ` +
          `rows, but snapshot ${snapshot.snapshotId} contains ${snapshot.rowCount}`,
        );
      }
      if (
        inspection.consumptionByRun &&
        snapshot.pageCount !== inspection.consumptionByRun.processedPageCount
      ) {
        reasons.push(
          `issue catalog consumption processed ${inspection.consumptionByRun.processedPageCount} ` +
          `pages, but snapshot ${snapshot.snapshotId} contains ${snapshot.pageCount}`,
        );
      }
      if (capture && snapshot.repository !== capture.repository) {
        reasons.push(
          `stored issue catalog snapshot repository ${snapshot.repository} does not match ` +
          `release catalog repository ${capture.repository}`,
        );
      }
    }

    if (
      bindings.attestation &&
      bindings.snapshot &&
      (
        bindings.attestation.snapshotId !== bindings.snapshot.snapshotId ||
        bindings.attestation.snapshotContentHash !== bindings.snapshot.contentHash
      )
    ) {
      reasons.push(
        'successful terminal receipt issue catalog attestation does not bind its consumed snapshot',
      );
    }
  }

  return {
    reasons: uniqueStrings(reasons),
    classifierKnownTags: bindings.releaseTags,
    issueCrawlMetadata: bindings.issueCrawlMetadata,
    identities: previewCatalogIdentities(inspection),
    evidenceCounts: previewCatalogEvidenceCounts(inspection, plan),
  };
}

export function previewInspectionDriftReasons(
  before: PreviewInspection,
  after: PreviewInspection,
): string[] {
  const reasons: string[] = [];
  if (
    identityPair(before.latestCatalogOperation) !==
    identityPair(after.latestCatalogOperation)
  ) {
    reasons.push('latest catalog operation changed while the preview batch was scored');
  }
  if (
    identityPair(before.capture) !== identityPair(after.capture) ||
    activeCatalogIdentity(before.activeCatalog) !==
      activeCatalogIdentity(after.activeCatalog)
  ) {
    reasons.push('active release catalog identity changed while the preview batch was scored');
  }
  if (identityPair(before.terminalReceipt) !== identityPair(after.terminalReceipt)) {
    reasons.push('catalog operation terminal receipt changed while the preview batch was scored');
  }
  if (identityPair(before.consumptionByRun) !== identityPair(after.consumptionByRun)) {
    reasons.push('issue catalog snapshot consumption changed while the preview batch was scored');
  }
  if (identityPair(before.snapshot) !== identityPair(after.snapshot)) {
    reasons.push('issue catalog snapshot identity changed while the preview batch was scored');
  }
  return reasons;
}

export async function buildScorePreview({
  range,
  classifierKnownTags,
  issueCrawlMetadata,
  evaluatedAt,
}: {
  range: PreviewDateRange;
  classifierKnownTags: string[];
  issueCrawlMetadata: Record<string, unknown> | null;
  evaluatedAt: string;
}): Promise<PreviewScoreBundle> {
  const evaluatedAtMs = Date.parse(evaluatedAt);
  if (!Number.isFinite(evaluatedAtMs) || new Date(evaluatedAtMs).toISOString() !== evaluatedAt) {
    throw new Error('Preview evaluatedAt must be a canonical ISO timestamp');
  }
  const database = await import('../../src/lib/db');
  openedDatabaseModule = database;
  const scoring = await import('../../src/lib/releaseScoring');
  const labelCutoff = await import('../../src/lib/labelCutoff');
  const score = await import('../../src/lib/score');
  const refresh = await import('../../src/lib/refresh');

  const activeCatalog = database.listActiveReleaseCatalogDb() as PreviewReleaseRow[];
  const plan = buildPreviewReleasePlan(activeCatalog, range);
  const run = plan.selectedNewestFirst.length === 0
    ? null
    : scoring.buildReleaseScoreRun({
        releases: plan.selectedNewestFirst as any,
        allFetchedTags: activeCatalog.map((release) => release.tag),
        stableTagsNewestFirst: plan.stableTagsNewestFirst,
        oldestScoredStablePredecessorTag:
          plan.oldestScoredStablePredecessorTag,
        nowForRelease: () => evaluatedAtMs,
      }) as unknown as Record<string, any>;
  const classificationAudits: Record<string, ClassificationAudit> = {};
  const completenessAudits: Record<string, IntegrityAudit> = {};
  for (const result of Array.isArray(run?.scored) ? run.scored : []) {
    const tag = String(result.rel?.tag ?? '');
    try {
      classificationAudits[tag] = {
        summary: database.releaseCommentClassificationIntegrity(
          tag,
          scoring.PROMPT_VERSION,
          classifierKnownTags,
          targetEvidenceIssueNumbers(result),
        ) as unknown as Record<string, unknown>,
        error: null,
      };
    } catch (error) {
      classificationAudits[tag] = {
        summary: null,
        error: errorMessage(error),
      };
    }
    completenessAudits[tag] = integrityAudit(
      () => scoring.currentScoreCompletenessDiagnostic({
        tag,
        labelCutoff: labelCutoff.releaseLabelCutoff(
          result.rel,
          result.scoredAt,
        ),
        analysisCompleteness: result.analysisCompleteness,
      }),
      currentCompletenessProblem,
    );
  }
  const closureAudits = Object.fromEntries(
    plan.selectedNewestFirst.map((release) => [
      release.tag,
      integrityAudit(
        () => database.releaseClosureProofIntegrity(release.tag, 3),
        (summary) =>
          database.formatReleaseClosureProofIntegrityFailure(summary as any),
      ),
    ]),
  );
  const reachabilityAudits = Object.fromEntries(
    plan.selectedNewestFirst.map((release) => [
      release.tag,
      integrityAudit(
        () => database.releasePrReachabilityIntegrity(release.tag, 3),
        (summary) =>
          database.formatReleasePrReachabilityIntegrityFailure(summary as any),
      ),
    ]),
  );
  const predecessorReachabilityAudit =
    plan.oldestScoredStablePredecessorTag
      ? integrityAudit(
          () => database.releasePrReachabilityIntegrity(
            plan.oldestScoredStablePredecessorTag!,
            3,
          ),
          (summary) =>
            database.formatReleasePrReachabilityIntegrityFailure(summary as any),
        )
      : null;
  const readiness = buildPreviewReadinessAudit({
    database,
    scoring,
    score,
    refresh,
    run,
    plan,
    issueCrawlMetadata,
    evaluatedAtMs,
  });

  return {
    evaluatedAt,
    plan,
    run,
    classificationAudits,
    completenessAudits,
    closureAudits,
    reachabilityAudits,
    predecessorReachabilityAudit,
    readiness,
  };
}

function buildPreviewReadinessAudit({
  database,
  scoring,
  score,
  refresh,
  run,
  plan,
  issueCrawlMetadata,
  evaluatedAtMs,
}: {
  database: any;
  scoring: any;
  score: any;
  refresh: any;
  run: Record<string, any> | null;
  plan: PreviewReleasePlan;
  issueCrawlMetadata: Record<string, unknown> | null;
  evaluatedAtMs: number;
}): PreviewReadinessAudit {
  const reasons: string[] = [];
  let crawlProblems: string[] = [];
  let crawlError: string | null = null;
  if (!issueCrawlMetadata) {
    crawlProblems = ['issue crawl metadata is missing'];
  } else {
    try {
      const rawBaseline = database.getMeta(
        refresh.ISSUE_CRAWL_BASELINE_META_KEY,
      );
      let storedBaseline: unknown = null;
      if (rawBaseline) {
        try {
          storedBaseline = JSON.parse(rawBaseline);
        } catch {
          storedBaseline = rawBaseline;
        }
      }
      crawlProblems = refresh.__refreshTest.issueCrawlMetadataProblems(
        issueCrawlMetadata,
        storedBaseline,
        { forScorePersistence: true },
      ).map(String);
      if (issueCrawlMetadata.scorePersisted !== true) {
        crawlProblems.push('scorePersisted must be true in the successful receipt');
      }
      if (
        typeof issueCrawlMetadata.finishedAt !== 'string' ||
        !Number.isFinite(Date.parse(issueCrawlMetadata.finishedAt))
      ) {
        crawlProblems.push('finishedAt must be a valid timestamp');
      }
    } catch (error) {
      crawlError = errorMessage(error);
    }
  }
  if (crawlError) {
    reasons.push(`issue crawl readiness audit failed: ${crawlError}`);
  }
  if (crawlProblems.length > 0) {
    reasons.push(
      `issue crawl readiness is incomplete: ${uniqueStrings(crawlProblems).join('; ')}`,
    );
  }
  const crawl = {
    ready: crawlError == null && crawlProblems.length === 0,
    problems: uniqueStrings(crawlProblems),
    error: crawlError,
    schemaVersion: finiteCount(issueCrawlMetadata?.schemaVersion),
    stopReason: nullableString(issueCrawlMetadata?.stopReason),
    crawlMode: nullableString(issueCrawlMetadata?.crawlMode),
    finishedAt: nullableString(issueCrawlMetadata?.finishedAt),
    scorePersisted:
      typeof issueCrawlMetadata?.scorePersisted === 'boolean'
        ? issueCrawlMetadata.scorePersisted
        : null,
  };

  const issueCatalogSnapshotLedger = integrityAudit(
    () => database.issueCatalogSnapshotLedgerIntegrity(),
    issueCatalogSnapshotLedgerProblem,
  );
  appendIntegrityReason(
    reasons,
    'issue catalog snapshot ledger readiness',
    issueCatalogSnapshotLedger,
  );

  const stableReleaseWindow = integrityAudit(
    () => database.stableReleaseWindowIntegrity(3),
    (summary) =>
      database.formatStableReleaseWindowIntegrityFailure(summary),
  );
  appendIntegrityReason(
    reasons,
    'stable release window readiness',
    stableReleaseWindow,
  );

  const activeRefresh = previewRefreshActivity(database, evaluatedAtMs);
  if (activeRefresh.active) {
    reasons.push(
      `score-input refresh is active` +
      (activeRefresh.attemptRunId
        ? ` for operation ${activeRefresh.attemptRunId}`
        : activeRefresh.leaseName
          ? ` under lease ${activeRefresh.leaseName}`
          : ''),
    );
  }

  let activeFailureCount: number | null = null;
  let activeFailureRows: Array<Record<string, any>> = [];
  try {
    activeFailureRows = database.listActiveIngestionEvidenceFailures(25);
    const countRow = database.db.prepare(`
      SELECT COUNT(*) AS count
      FROM ingestion_evidence_failures
      WHERE scoring_blocking=1
        AND superseded_by_run_id IS NULL
    `).get() as { count?: unknown } | undefined;
    activeFailureCount = finiteCount(countRow?.count);
  } catch (error) {
    reasons.push(
      `score-blocking ingestion readiness audit failed: ${errorMessage(error)}`,
    );
  }
  if (activeFailureCount == null) {
    activeFailureCount = activeFailureRows.length;
  }
  if (activeFailureCount > 0) {
    reasons.push(
      `${activeFailureCount} active score-blocking ingestion ` +
      `${activeFailureCount === 1 ? 'failure remains' : 'failures remain'} unsuperseded`,
    );
  }
  const activeScoreBlockingIngestionFailures = {
    count: activeFailureCount,
    examples: activeFailureRows.map((row) => ({
      id: finiteCount(row.id),
      runId: nullableString(row.run_id),
      occurredAt: nullableString(row.occurred_at),
      source: nullableString(row.source),
      scope: nullableString(row.scope),
      releaseTag: nullableString(row.release_tag),
      issueNumber: finiteCount(row.issue_number),
    })),
  };

  if (run && !SHA256_PATTERN.test(String(run.sourceIdentity?.digest ?? ''))) {
    reasons.push('score source identity digest is missing or malformed');
  }
  let scoreAuthorityProblems: string[] = [];
  if (run) {
    try {
      const inspectAuthority =
        scoring.__releaseScorePersistenceTest?.scoreAuthorityManifestProblems;
      scoreAuthorityProblems = typeof inspectAuthority === 'function'
        ? inspectAuthority(run).map(String)
        : ['score authority manifest verifier is unavailable'];
    } catch (error) {
      scoreAuthorityProblems = [
        `score authority manifest audit failed: ${errorMessage(error)}`,
      ];
    }
    if (scoreAuthorityProblems.length > 0) {
      reasons.push(
        `score authority readiness is incomplete: ` +
        boundedProblems(scoreAuthorityProblems).join('; '),
      );
    }
  }
  const resultsByTag = new Map<string, Record<string, any>>();
  for (const result of Array.isArray(run?.scored) ? run.scored : []) {
    const tag = String(result.rel?.tag ?? '');
    if (tag && !resultsByTag.has(tag)) resultsByTag.set(tag, result);
  }
  const releases = Object.fromEntries(
    plan.selectedNewestFirst.map((release) => {
      const releaseReasons: string[] = [];
      const result = resultsByTag.get(release.tag);
      const scoreLedgerProblems = result
        ? score.scoreLedgerV2Problems(result.scoreLedger, {
            input: result.input,
            confidence: result.conf,
            scoredAt: result.scoredAt,
          }).map(String)
        : ['score result is missing'];
      if (
        result &&
        JSON.stringify(result.scoreLedger) !==
          JSON.stringify(result.explanation?.scoreLedger)
      ) {
        scoreLedgerProblems.push(
          'score result and explanation score ledgers do not match',
        );
      }
      releaseReasons.push(
        ...scoreLedgerProblems.map((problem) =>
          `score ledger readiness: ${problem}`),
      );

      const issueTimeline = integrityAudit(
        () => database.releaseIssueTimelineIntegrity(release.tag, 3),
        (summary) =>
          database.formatReleaseIssueTimelineIntegrityFailure(summary),
      );
      appendIntegrityReason(
        releaseReasons,
        'issue timeline readiness',
        issueTimeline,
      );
      const issueStateSnapshots = integrityAudit(
        () => database.releaseIssueStateSnapshotIntegrity(release.tag, 3),
        (summary) =>
          database.formatReleaseIssueStateSnapshotIntegrityFailure(summary),
      );
      appendIntegrityReason(
        releaseReasons,
        'issue state snapshot readiness',
        issueStateSnapshots,
      );

      const releaseFixCredit = record(
        record(result?.gateEvidence)?.fixProvenance,
      )?.releaseFixCredit;
      const fixCreditProblems = record(releaseFixCredit)
        ? database.releaseFixCreditPayloadProblems(
            release.tag,
            releaseFixCredit,
            { requireDecisionDetails: true },
          ).map(String)
        : ['releaseFixCredit payload is missing'];
      releaseReasons.push(
        ...fixCreditProblems.map((problem) =>
          `fix-credit readiness: ${problem}`),
      );
      return [
        release.tag,
        {
          ready: releaseReasons.length === 0,
          reasons: uniqueStrings(releaseReasons),
          scoreLedgerProblems: uniqueStrings(scoreLedgerProblems),
          issueTimeline,
          issueStateSnapshots,
          fixCreditProblems: uniqueStrings(fixCreditProblems),
        },
      ];
    }),
  ) as Record<string, PreviewReleaseReadinessAudit>;

  return {
    ready:
      reasons.length === 0 &&
      Object.values(releases).every((release) => release.ready),
    reasons: uniqueStrings(reasons),
    issueCatalogSnapshotLedger,
    scoreAuthorityProblems: uniqueStrings(scoreAuthorityProblems),
    crawl,
    stableReleaseWindow,
    activeRefresh,
    activeScoreBlockingIngestionFailures,
    releases,
  };
}

export function buildPreviewScoreReport({
  databasePath,
  range,
  inspection,
  audit,
  scoreBundle,
  additionalReasons = [],
  scoreError = null,
  evaluatedAt,
  generatedAt = new Date().toISOString(),
}: {
  databasePath: string;
  range: PreviewDateRange;
  inspection: PreviewInspection;
  audit: PreviewCatalogAudit;
  scoreBundle: PreviewScoreBundle | null;
  additionalReasons?: string[];
  scoreError?: string | null;
  evaluatedAt: string;
  generatedAt?: string;
}): Record<string, unknown> {
  const plan = buildPreviewReleasePlan(inspection.activeCatalog, range);
  const globalReasons = [
    ...audit.reasons,
    ...additionalReasons,
  ];
  if (scoreError) globalReasons.push(`score batch failed: ${scoreError}`);

  const run = scoreBundle?.run;
  const expectedTags = plan.selectedNewestFirst.map((release) => release.tag);
  const scoredRows = Array.isArray(run?.scored)
    ? run.scored as Array<Record<string, any>>
    : [];
  const scoredTags = scoredRows.map((result) =>
    String(result.rel?.tag ?? ''));
  const scoredTagCounts = new Map<string, number>();
  for (const tag of scoredTags) {
    scoredTagCounts.set(tag, (scoredTagCounts.get(tag) ?? 0) + 1);
  }
  const expectedTagSet = new Set(expectedTags);
  const missingTags = expectedTags.filter((tag) => !scoredTagCounts.has(tag));
  const duplicateTags = [...scoredTagCounts.entries()]
    .filter(([, count]) => count > 1)
    .map(([tag]) => tag)
    .sort();
  const extraTags = [...scoredTagCounts.keys()]
    .filter((tag) => !expectedTagSet.has(tag))
    .sort();
  const exactOnce =
    missingTags.length === 0 &&
    duplicateTags.length === 0 &&
    extraTags.length === 0 &&
    scoredRows.length === expectedTags.length;

  if (scoreBundle) {
    const plannedScoreTags = scoreBundle.plan.selectedNewestFirst
      .map((release) => release.tag);
    if (JSON.stringify(expectedTags) !== JSON.stringify(plannedScoreTags)) {
      globalReasons.push(
        'selected release catalog changed between inspection and score construction',
      );
    }
    if (scoreBundle.evaluatedAt !== evaluatedAt) {
      globalReasons.push(
        `score batch evaluatedAt ${scoreBundle.evaluatedAt} does not match report ` +
        `evaluatedAt ${evaluatedAt}`,
      );
    }
  } else if (expectedTags.length > 0) {
    globalReasons.push('score batch was not constructed for the selected releases');
  }
  if (!exactOnce && expectedTags.length > 0) {
    globalReasons.push(
      `score batch result coverage is not exact ` +
      `(missing=${formatTagList(missingTags)}, duplicate=${formatTagList(duplicateTags)}, ` +
      `extra=${formatTagList(extraTags)}, rows=${scoredRows.length}, expected=${expectedTags.length})`,
    );
  }
  const runOrderMatchesCatalog =
    JSON.stringify(scoredTags) === JSON.stringify(expectedTags);
  if (exactOnce && !runOrderMatchesCatalog) {
    globalReasons.push(
      'score batch result order does not match canonical active-catalog order',
    );
  }
  const evaluationProblems = scoredRows.flatMap((result) => {
    const tag = String(result.rel?.tag ?? 'unknown');
    const problems: string[] = [];
    if (result.scoredAt !== evaluatedAt) {
      problems.push(
        `${tag} scoredAt ${String(result.scoredAt ?? 'missing')} does not match ` +
        `shared evaluatedAt ${evaluatedAt}`,
      );
    }
    if (result.scoreLedger?.evaluatedAt !== evaluatedAt) {
      problems.push(
        `${tag} score ledger evaluatedAt ` +
        `${String(result.scoreLedger?.evaluatedAt ?? 'missing')} does not match ` +
        `shared evaluatedAt ${evaluatedAt}`,
      );
    }
    return problems;
  });
  globalReasons.push(...evaluationProblems);

  const predecessorProblems = Array.isArray(run?.predecessorBoundaryProblems)
    ? run.predecessorBoundaryProblems.map(String)
    : [];
  for (const release of plan.selectedNewestFirst) {
    const expectedPredecessor =
      plan.predecessorByReleaseTag[release.tag] ?? null;
    const actualPredecessor =
      run?.predecessorByReleaseTag?.[release.tag] ?? null;
    if (run && actualPredecessor !== expectedPredecessor) {
      predecessorProblems.push(
        `${release.tag} predecessor ${actualPredecessor ?? 'none'} does not match ` +
        `catalog predecessor ${expectedPredecessor ?? 'none'}`,
      );
    }
  }
  const oldestSelectedTag = plan.selectedNewestFirst.at(-1)?.tag ?? null;
  if (
    run &&
    (
      run.oldestScoredStableTag !== oldestSelectedTag ||
      (run.oldestScoredStablePredecessorTag ?? null) !==
        plan.oldestScoredStablePredecessorTag
    )
  ) {
    predecessorProblems.push(
      `run predecessor boundary ${String(run.oldestScoredStableTag ?? 'none')} -> ` +
      `${String(run.oldestScoredStablePredecessorTag ?? 'none')} does not match ` +
      `catalog boundary ${oldestSelectedTag ?? 'none'} -> ` +
      `${plan.oldestScoredStablePredecessorTag ?? 'none'}`,
    );
  }
  if (predecessorProblems.length > 0) {
    globalReasons.push(
      `predecessor context is incomplete: ${predecessorProblems.join('; ')}`,
    );
  }
  if (scoreBundle) {
    globalReasons.push(...scoreBundle.readiness.reasons);
    if (
      scoreBundle.readiness.ready !== true &&
      scoreBundle.readiness.reasons.length === 0
    ) {
      globalReasons.push('score-input readiness is not ready');
    }
  }
  const uniqueGlobalReasons = uniqueStrings(globalReasons);
  const resultsByTag = new Map<string, Record<string, any>>();
  for (const result of scoredRows) {
    const tag = String(result.rel?.tag ?? '');
    if (tag && !resultsByTag.has(tag)) resultsByTag.set(tag, result);
  }

  const releases = plan.selectedNewestFirst.map((release) => {
    const result = resultsByTag.get(release.tag) as Record<string, any> | undefined;
    const releaseReasons = [...uniqueGlobalReasons];
    const classificationAudit =
      scoreBundle?.classificationAudits[release.tag] ?? null;
    const completenessAudit =
      scoreBundle?.completenessAudits[release.tag] ?? null;
    const closureAudit = scoreBundle?.closureAudits[release.tag] ?? null;
    const reachabilityAudit =
      scoreBundle?.reachabilityAudits[release.tag] ?? null;
    const predecessorTag =
      plan.predecessorByReleaseTag[release.tag] ?? null;
    const predecessorReachabilityAudit = predecessorTag
      ? scoreBundle?.reachabilityAudits[predecessorTag] ??
        (
          predecessorTag === plan.oldestScoredStablePredecessorTag
            ? scoreBundle?.predecessorReachabilityAudit
            : null
        )
      : null;
    const readinessAudit =
      scoreBundle?.readiness.releases[release.tag] ?? null;
    if (!result) {
      releaseReasons.push('score batch did not return a result for this release');
    }
    if (result) {
      if (!audit.classifierKnownTags?.includes(release.tag)) {
        releaseReasons.push(
          `successful terminal receipt classifier identity does not include ${release.tag}`,
        );
      }
      const rawIssueCount = finiteCount(result.input?.rawIssueCount);
      const classifiedIssueCount = finiteCount(result.input?.classifiedIssueCount);
      if (
        rawIssueCount == null ||
        classifiedIssueCount == null ||
        classifiedIssueCount !== rawIssueCount
      ) {
        releaseReasons.push(
          rawIssueCount != null && classifiedIssueCount != null
            ? `classification coverage is incomplete: ${classifiedIssueCount} of ` +
              `${rawIssueCount} attributed issues are classified`
            : 'classification coverage counts are missing or invalid',
        );
      }
      if (classificationAudit?.error) {
        releaseReasons.push(
          `classification integrity audit failed: ${classificationAudit.error}`,
        );
      } else if (classificationAudit?.summary) {
        const failedCount = finiteCount(
          classificationAudit.summary.failedCount,
        );
        if (failedCount == null || failedCount > 0) {
          releaseReasons.push(
            classificationIntegrityReason(classificationAudit.summary),
          );
        }
      } else {
        releaseReasons.push('classification integrity audit is missing');
      }
      if (!completenessAudit) {
        releaseReasons.push('current closure-analysis completeness audit is missing');
      } else {
        appendIntegrityReason(
          releaseReasons,
          'current closure-analysis completeness',
          completenessAudit,
        );
      }
      if (!closureAudit) {
        releaseReasons.push('closure proof integrity audit is missing');
      } else {
        appendIntegrityReason(
          releaseReasons,
          'closure proof integrity',
          closureAudit,
        );
      }
      if (!reachabilityAudit) {
        releaseReasons.push('PR reachability integrity audit is missing');
      } else {
        appendIntegrityReason(
          releaseReasons,
          'PR reachability integrity',
          reachabilityAudit,
        );
      }
      if (!predecessorTag) {
        releaseReasons.push(
          'release has no immediate older stable predecessor boundary',
        );
      } else if (!predecessorReachabilityAudit) {
        releaseReasons.push(
          `predecessor ${predecessorTag} PR reachability integrity audit is missing`,
        );
      } else {
        appendIntegrityReason(
          releaseReasons,
          `predecessor ${predecessorTag} PR reachability integrity`,
          predecessorReachabilityAudit,
        );
      }
      if (result.analysisCompleteness?.complete !== true) {
        const missing = Array.isArray(
          result.analysisCompleteness?.missingClosureEvidence,
        )
          ? result.analysisCompleteness.missingClosureEvidence
          : [];
        releaseReasons.push(
          `analysisCompleteness is false with ${missing.length} missing closure ` +
          `evidence ${missing.length === 1 ? 'row' : 'rows'}`,
        );
      }
      if (!readinessAudit) {
        releaseReasons.push('score-input readiness audit is missing');
      } else {
        releaseReasons.push(...readinessAudit.reasons);
        if (
          readinessAudit.ready !== true &&
          readinessAudit.reasons.length === 0
        ) {
          releaseReasons.push('score-input readiness is not ready for this release');
        }
      }
      if (result.conf?.score == null) {
        releaseReasons.push(
          `score disposition ${String(result.conf?.status ?? 'unknown')} did not ` +
          `produce a numeric rating` +
          (typeof result.conf?.reason === 'string' && result.conf.reason
            ? `: ${result.conf.reason}`
            : ''),
        );
      }
      if (
        result.conf?.score != null &&
        !Number.isFinite(Number(result.conf.score))
      ) {
        releaseReasons.push('score result contains a non-finite numeric rating');
      }
    }

    const reasons = uniqueStrings(releaseReasons);
    const numericRating = finiteNumber(result?.conf?.score);
    const rated = reasons.length === 0 && numericRating != null;
    return {
      tag: release.tag,
      publishedAt: release.published_at,
      evaluatedAt,
      predecessorTag,
      rating: rated ? numericRating : null,
      status: rated ? 'rated' : 'unrated',
      scoreDisposition: nullableString(result?.conf?.status),
      band: rated ? result?.conf?.band ?? null : null,
      ratingReason: rated ? result?.conf?.reason ?? null : null,
      reasons,
      evidenceCounts: result
        ? releaseEvidenceCounts(
            result,
            classificationAudit,
            closureAudit,
            reachabilityAudit,
          )
        : null,
      classificationIntegrity: classificationAudit,
      currentClosureAnalysisCompleteness: completenessAudit,
      closureProofIntegrity: closureAudit,
      reachabilityIntegrity: reachabilityAudit,
      predecessorReachabilityIntegrity: predecessorReachabilityAudit,
      readiness: readinessAudit,
      analysisCompleteness: result
        ? releaseAnalysisCompleteness(result)
        : null,
      evidenceManifests: result
        ? releaseEvidenceManifests(result)
        : [],
      scoreLedgerDigest: result?.scoreLedger?.digest ?? null,
    };
  });
  const ratedCount = releases.filter((release) => release.status === 'rated').length;
  const reportStatus = releases.length === 0
    ? 'empty'
    : ratedCount === releases.length
      ? 'rated'
      : ratedCount === 0
        ? 'unrated'
        : 'partial';

  return {
    schemaVersion: 1,
    generatedAt,
    evaluatedAt,
    databasePath,
    range: {
      selector: range.selector,
      month: range.month,
      from: range.from,
      through: range.through,
      inclusive: true,
      start: new Date(range.startMs).toISOString(),
      endExclusive: new Date(range.endExclusiveMs).toISOString(),
    },
    order: 'catalog_rank_asc_newest_first',
    status: reportStatus,
    auditReasons: uniqueGlobalReasons,
    catalog: audit.identities,
    evidenceCounts: audit.evidenceCounts,
    scoreSourceIdentityDigest: run?.sourceIdentity?.digest ?? null,
    batchIntegrity: {
      exactOnce,
      runOrderMatchesCatalog,
      expectedCount: expectedTags.length,
      resultCount: scoredRows.length,
      expectedTags,
      resultTags: scoredTags,
      missingTags,
      duplicateTags,
      extraTags,
      evaluationProblems,
    },
    predecessorBoundary: {
      oldestSelectedTag,
      predecessorTag: plan.oldestScoredStablePredecessorTag,
      predecessorByReleaseTag: plan.predecessorByReleaseTag,
      problems: uniqueStrings(predecessorProblems),
      reachabilityIntegrity:
        scoreBundle?.predecessorReachabilityAudit ?? null,
    },
    readiness: scoreBundle?.readiness ?? null,
    deferredGates: [{
      gate: 'persisted_semantic_readiness',
      status: 'not_applicable',
      reason:
        'Read-only preview does not write a sealed score audit publication, ' +
        'authority run, history seal, or persisted selection.',
    }],
    releaseCount: releases.length,
    ratedCount,
    unratedCount: releases.length - ratedCount,
    releases,
  };
}

export function closeScorePreviewDatabase(): void {
  openedDatabaseModule?.db.close();
  openedDatabaseModule = null;
}

function previewExplicitRange(from: string, through: string): PreviewDateRange {
  const startMs = parseUtcDate(from, '--from');
  const throughMs = parseUtcDate(through, '--through');
  if (startMs > throughMs) {
    throw new Error('--from must not be later than --through');
  }
  return {
    selector: 'range',
    month: null,
    from,
    through,
    startMs,
    endExclusiveMs: throughMs + DAY_MS,
  };
}

function previewMonthRange(month: string): PreviewDateRange {
  const match = /^(\d{4})-(\d{2})$/.exec(month);
  if (!match) throw new Error('--month must use YYYY-MM');
  const year = Number(match[1]);
  const monthNumber = Number(match[2]);
  if (monthNumber < 1 || monthNumber > 12) {
    throw new Error('--month must use a month from 01 through 12');
  }
  const from = `${match[1]}-${match[2]}-01`;
  const through =
    `${match[1]}-${match[2]}-${String(daysInMonth(year, monthNumber)).padStart(2, '0')}`;
  return {
    ...previewExplicitRange(from, through),
    selector: 'month',
    month,
  };
}

function parseUtcDate(value: string, label: string): number {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error(`${label} must use YYYY-MM-DD`);
  }
  const timestamp = Date.parse(`${value}T00:00:00.000Z`);
  if (
    !Number.isFinite(timestamp) ||
    new Date(timestamp).toISOString().slice(0, 10) !== value
  ) {
    throw new Error(`${label} must be a valid calendar date`);
  }
  return timestamp;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
      ? 29
      : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function compareCatalogNewestFirst(
  left: PreviewReleaseRow,
  right: PreviewReleaseRow,
): number {
  const leftRank = Number.isInteger(left.catalog_rank)
    ? Number(left.catalog_rank)
    : Number.MAX_SAFE_INTEGER;
  const rightRank = Number.isInteger(right.catalog_rank)
    ? Number(right.catalog_rank)
    : Number.MAX_SAFE_INTEGER;
  return leftRank - rightRank ||
    releasePublishedAtMs(right) - releasePublishedAtMs(left) ||
    left.tag.localeCompare(right.tag);
}

function releasePublishedAtMs(release: PreviewReleaseRow): number {
  const timestamp = Date.parse(String(release.published_at ?? ''));
  if (!Number.isFinite(timestamp)) {
    throw new Error(
      `Active stable release ${JSON.stringify(release.tag)} has invalid published_at`,
    );
  }
  return timestamp;
}

function mapCatalogCapture(value: unknown): PreviewCatalogCapture | null {
  const row = record(value);
  return row
    ? {
        receiptId: String(row.receiptId),
        operationRunId: nullableString(row.operationRunId),
        sourceKind: String(row.sourceKind),
        repository: String(row.repository),
        observedAt: String(row.observedAt),
        activeCatalogDigest: String(row.activeCatalogDigest),
        activeReleaseCount: Number(row.activeReleaseCount),
        contentHash: String(row.contentHash),
      }
    : null;
}

function mapCatalogOperation(value: unknown): PreviewCatalogOperation | null {
  const row = record(value);
  return row
    ? {
        runId: String(row.runId),
        operation: String(row.operation),
        trigger: String(row.trigger),
        startedAt: String(row.startedAt),
        codeRevision: String(row.codeRevision),
        effectiveConfigHash: String(row.effectiveConfigHash),
        contentHash: String(row.contentHash),
      }
    : null;
}

function mapTerminalReceipt(value: unknown): PreviewTerminalReceipt | null {
  const row = record(value);
  return row
    ? {
        receiptId: String(row.receiptId),
        runId: String(row.runId),
        status: String(row.status),
        finishedAt: String(row.finishedAt),
        payloadJson: String(row.payloadJson),
        contentHash: String(row.contentHash),
      }
    : null;
}

function mapSnapshotConsumption(
  value: unknown,
): PreviewSnapshotConsumption | null {
  const row = record(value);
  return row
    ? {
        snapshotId: String(row.snapshotId),
        repository: String(row.repository),
        runId: String(row.runId),
        consumedAt: String(row.consumedAt),
        processedRowCount: Number(row.processedRowCount),
        processedPageCount: Number(row.processedPageCount),
        snapshotContentHash: String(row.snapshotContentHash),
        contentHash: String(row.contentHash),
      }
    : null;
}

function mapIssueCatalogSnapshot(
  value: unknown,
): PreviewIssueCatalogSnapshot | null {
  const row = record(value);
  return row
    ? {
        snapshotId: String(row.snapshotId),
        repository: String(row.repository),
        capturedAt: String(row.capturedAt),
        rowCount: Number(row.rowCount),
        pageCount: Number(row.pageCount),
        membershipDigest: String(row.membershipDigest),
        contentDigest: String(row.contentDigest),
        contentHash: String(row.contentHash),
      }
    : null;
}

function terminalReceiptBindings(payloadJson: string | null): TerminalReceiptBindings {
  if (!payloadJson) {
    return {
      payloadProblem: null,
      releaseTags: null,
      issueCrawlMetadata: null,
      snapshot: null,
      attestation: null,
    };
  }
  let payload: Record<string, unknown>;
  try {
    const parsed = JSON.parse(payloadJson);
    const parsedRecord = record(parsed);
    if (!parsedRecord) throw new Error('payload is not an object');
    payload = parsedRecord;
  } catch (error) {
    return {
      payloadProblem:
        `terminal receipt payload is invalid JSON: ${errorMessage(error)}`,
      releaseTags: null,
      issueCrawlMetadata: null,
      snapshot: null,
      attestation: null,
    };
  }
  const releaseTags = stringArray(payload.releaseTags);
  const issueCrawl = record(payload.issueCrawl);
  const metadata = record(issueCrawl?.metadata);
  const snapshot = record(metadata?.catalogSnapshot);
  const attestation = record(metadata?.catalogAttestation);
  return {
    payloadProblem: null,
    releaseTags,
    issueCrawlMetadata: metadata,
    snapshot: snapshot
      ? {
          snapshotId: nullableString(snapshot.snapshotId),
          contentHash: nullableString(snapshot.contentHash),
          consumedByRunId: nullableString(snapshot.consumedByRunId),
          consumptionContentHash:
            nullableString(snapshot.consumptionContentHash),
        }
      : null,
    attestation: attestation
      ? {
          snapshotId: nullableString(attestation.snapshotId),
          snapshotContentHash:
            nullableString(attestation.snapshotContentHash),
        }
      : null,
  };
}

function previewCatalogIdentities(inspection: PreviewInspection) {
  const capture = inspection.capture;
  const operation = inspection.latestCatalogOperation;
  const terminal = inspection.terminalReceipt;
  const snapshot = inspection.snapshot;
  const consumption = inspection.consumptionByRun;
  return {
    catalogOperation: operation
      ? {
          runId: operation.runId,
          operation: operation.operation,
          trigger: operation.trigger,
          startedAt: operation.startedAt,
          codeRevision: operation.codeRevision,
          effectiveConfigHash: operation.effectiveConfigHash,
          contentHash: operation.contentHash,
        }
      : null,
    releaseCatalog: capture
      ? {
          receiptId: capture.receiptId,
          receiptContentHash: capture.contentHash,
          operationRunId: capture.operationRunId,
          sourceKind: capture.sourceKind,
          repository: capture.repository,
          observedAt: capture.observedAt,
          catalogDigest: capture.activeCatalogDigest,
          activeReleaseCount: capture.activeReleaseCount,
        }
      : null,
    terminalReceipt: terminal
      ? {
          receiptId: terminal.receiptId,
          receiptContentHash: terminal.contentHash,
          runId: terminal.runId,
          status: terminal.status,
          finishedAt: terminal.finishedAt,
        }
      : null,
    issueCatalogSnapshot: snapshot
      ? {
          snapshotId: snapshot.snapshotId,
          contentHash: snapshot.contentHash,
          repository: snapshot.repository,
          capturedAt: snapshot.capturedAt,
          membershipDigest: snapshot.membershipDigest,
          contentDigest: snapshot.contentDigest,
        }
      : null,
    issueCatalogConsumption: consumption
      ? {
          contentHash: consumption.contentHash,
          snapshotId: consumption.snapshotId,
          snapshotContentHash: consumption.snapshotContentHash,
          runId: consumption.runId,
          repository: consumption.repository,
          consumedAt: consumption.consumedAt,
        }
      : null,
  };
}

function previewCatalogEvidenceCounts(
  inspection: PreviewInspection,
  plan: PreviewReleasePlan,
) {
  return {
    activeReleases: plan.activeReleaseCount,
    activeStableReleases: plan.stableTagsNewestFirst.length,
    selectedStableReleases: plan.selectedNewestFirst.length,
    issueCatalogSnapshotRows: inspection.snapshot?.rowCount ?? null,
    issueCatalogSnapshotPages: inspection.snapshot?.pageCount ?? null,
    consumedIssueRows:
      inspection.consumptionByRun?.processedRowCount ?? null,
    consumedIssuePages:
      inspection.consumptionByRun?.processedPageCount ?? null,
  };
}

function targetEvidenceIssueNumbers(result: Record<string, any>): number[] {
  const rows = Array.isArray(result.debtEvidence?.targetEvidenceAttribution)
    ? result.debtEvidence.targetEvidenceAttribution
    : [];
  return [
    ...new Set(
      rows
        .map((row: Record<string, unknown>) => Number(row.issueNumber))
        .filter((value: number) => Number.isInteger(value) && value > 0),
    ),
  ].sort((left, right) => left - right);
}

function classificationIntegrityReason(
  summary: Record<string, unknown>,
): string {
  const fields = [
    ['issues', 'issueCount'],
    ['missingSnapshots', 'missingSnapshotCount'],
    ['invalidSnapshots', 'invalidSnapshotCount'],
    ['commentDigestMismatches', 'commentDigestMismatchCount'],
    ['missingClassifications', 'missingClassificationCount'],
    ['staleClassifications', 'staleClassificationCount'],
    ['classifierIdentityMismatches', 'classifierSourceIdentityMismatchCount'],
    ['invalidRawClassifications', 'invalidRawClassificationCount'],
  ] as const;
  return `classification integrity is incomplete (${fields
    .map(([label, key]) => `${label}=${finiteCount(summary[key]) ?? 'invalid'}`)
    .join(', ')})`;
}

function currentCompletenessProblem(
  summary: Record<string, unknown>,
): string | null {
  const problems = Array.isArray(summary.problems)
    ? summary.problems.map(String).filter(Boolean)
    : null;
  if (!problems) {
    return 'current completeness diagnostic problems are missing';
  }
  if (problems.length > 0) {
    return boundedProblems(problems).join('; ');
  }
  return summary.complete === true
    ? null
    : 'current completeness diagnostic is not complete';
}

function issueCatalogSnapshotLedgerProblem(
  summary: Record<string, unknown>,
): string | null {
  if (!Array.isArray(summary.problems)) {
    return 'issue catalog snapshot ledger problems are missing';
  }
  const problems = summary.problems.map((problem) => {
    const row = record(problem);
    if (!row) return String(problem);
    const snapshotId = nullableString(row.snapshotId);
    const detail = nullableString(row.detail) ?? 'unknown ledger problem';
    return snapshotId ? `${snapshotId}: ${detail}` : detail;
  });
  if (problems.length > 0) {
    return `${problems.length} ledger ${problems.length === 1 ? 'problem' : 'problems'}: ` +
      boundedProblems(problems).join('; ');
  }
  return finiteCount(summary.orphanRowCount) === 0
    ? null
    : 'issue catalog snapshot ledger orphan row count is missing or nonzero';
}

function releaseEvidenceCounts(
  result: Record<string, any>,
  classificationAudit: ClassificationAudit | null,
  closureAudit: IntegrityAudit | null,
  reachabilityAudit: IntegrityAudit | null,
) {
  const rawIssueCount = finiteCount(result.input?.rawIssueCount);
  const classifiedIssueCount = finiteCount(result.input?.classifiedIssueCount);
  const manifests = releaseEvidenceManifests(result);
  return {
    rawIssues: rawIssueCount,
    classifiedIssues: classifiedIssueCount,
    unclassifiedIssues:
      rawIssueCount != null && classifiedIssueCount != null
        ? Math.max(0, rawIssueCount - classifiedIssueCount)
        : null,
    classificationIntegrityFailures:
      finiteCount(classificationAudit?.summary?.failedCount) ?? null,
    missingClosureEvidence: Array.isArray(
      result.analysisCompleteness?.missingClosureEvidence,
    )
      ? result.analysisCompleteness.missingClosureEvidence.length
      : null,
    rawClosedIssues:
      finiteCount(closureAudit?.summary?.rawClosedCount),
    closureProofRows:
      finiteCount(closureAudit?.summary?.proofRowCount),
    reachabilityCandidates:
      finiteCount(reachabilityAudit?.summary?.candidateCount),
    reachabilityRows:
      finiteCount(reachabilityAudit?.summary?.rowCount),
    authorityReferences: Array.isArray(result.authorityReferences)
      ? result.authorityReferences.length
      : null,
    evidenceManifestCount: manifests.length,
    evidenceReferenceCount: manifests.reduce(
      (sum, manifest) => sum + (finiteCount(manifest.count) ?? 0),
      0,
    ),
  };
}

function releaseAnalysisCompleteness(result: Record<string, any>) {
  const missing = Array.isArray(
    result.analysisCompleteness?.missingClosureEvidence,
  )
    ? result.analysisCompleteness.missingClosureEvidence
    : [];
  return {
    complete: result.analysisCompleteness?.complete === true,
    missingClosureEvidenceCount: missing.length,
    missingClosureEvidence: missing.map((row: Record<string, unknown>) => ({
      issueNumber: finiteCount(row.issueNumber),
      status: nullableString(row.status),
      potentialRiskWeight: finiteNumber(row.potentialRiskWeight),
    })),
  };
}

function releaseEvidenceManifests(result: Record<string, any>) {
  const manifests = Array.isArray(result.scoreLedger?.evidence?.manifests)
    ? result.scoreLedger.evidence.manifests
    : [];
  return manifests.map((manifest: Record<string, any>) => {
    const refs = Array.isArray(manifest.refs) ? manifest.refs : [];
    return {
      key: String(manifest.key ?? ''),
      count: finiteCount(manifest.count),
      digest: nullableString(manifest.digest),
      exhaustive: manifest.exhaustive === true,
      identities: refs.map((ref: Record<string, unknown>) => ({
        kind: nullableString(ref.kind),
        identity: nullableString(ref.identity),
        digest: nullableString(ref.digest),
      })),
    };
  });
}

function integrityAudit(
  read: () => unknown,
  formatFailure: (summary: Record<string, unknown>) => string | null,
): IntegrityAudit {
  try {
    const summary = record(read());
    if (!summary) throw new Error('integrity audit did not return an object');
    return {
      summary,
      problem: formatFailure(summary),
      error: null,
    };
  } catch (error) {
    return {
      summary: null,
      problem: null,
      error: errorMessage(error),
    };
  }
}

function appendIntegrityReason(
  reasons: string[],
  label: string,
  audit: IntegrityAudit,
): void {
  if (audit.error) {
    reasons.push(`${label} audit failed: ${audit.error}`);
  } else if (audit.problem) {
    reasons.push(`${label} is incomplete: ${audit.problem}`);
  } else if (!audit.summary) {
    reasons.push(`${label} audit result is missing`);
  }
}

function previewRefreshActivity(
  database: any,
  nowMs: number,
): PreviewReadinessAudit['activeRefresh'] {
  const attempts = database.listRefreshOperationAttempts();
  const receiptRunIds = new Set(
    database.listRefreshCaptureReceipts().map(
      (receipt: Record<string, unknown>) => String(receipt.run_id),
    ),
  );
  const activeLeases = database.listRefreshLeases()
    .filter((lease: Record<string, unknown>) =>
      Date.parse(String(lease.expires_at ?? '')) > nowMs);
  const activeLeaseByName = new Map(
    activeLeases.map((lease: Record<string, unknown>) => [
      String(lease.name),
      lease,
    ]),
  );
  const activeAttempt = newestByTimestamp(
    attempts
      .filter((attempt: Record<string, unknown>) =>
        !receiptRunIds.has(String(attempt.run_id)))
      .filter((attempt: Record<string, unknown>) => {
        const lease = activeLeaseByName.get(String(attempt.lease_name));
        return lease?.holder_id === attempt.lease_holder_id;
      }),
    (attempt) => String(attempt.started_at ?? ''),
  );
  const activeLease = activeAttempt
    ? activeLeaseByName.get(String(activeAttempt.lease_name)) ?? null
    : newestByTimestamp(
        activeLeases,
        (lease) => String(lease.acquired_at ?? ''),
      );
  return {
    active: activeLeases.length > 0,
    attemptRunId: nullableString(activeAttempt?.run_id),
    leaseName: nullableString(activeLease?.name),
    leaseHolderId: nullableString(activeLease?.holder_id),
    leaseExpiresAt: nullableString(activeLease?.expires_at),
  };
}

function newestByTimestamp<T extends Record<string, unknown>>(
  rows: T[],
  timestamp: (row: T) => string,
): T | null {
  return rows.reduce<T | null>((newest, row) => {
    if (!newest) return row;
    return Date.parse(timestamp(row)) >= Date.parse(timestamp(newest))
      ? row
      : newest;
  }, null);
}

function formatTagList(tags: string[]): string {
  return tags.length > 0 ? tags.join(', ') : 'none';
}

function activeCatalogIdentity(rows: PreviewReleaseRow[]): string {
  return JSON.stringify(
    rows
      .filter((release) => Number(release.catalog_active) === 1)
      .slice()
      .sort(compareCatalogNewestFirst)
      .map((release) => [
        release.tag,
        release.catalog_rank,
        release.catalog_digest,
        release.published_at,
        release.prerelease,
      ]),
  );
}

function identityPair(value: unknown): string {
  const row = record(value);
  if (!row) return 'null';
  return JSON.stringify([
    row.receiptId ?? row.snapshotId ?? row.contentHash ?? null,
    row.contentHash ?? row.receiptContentHash ?? null,
    row.operationRunId ?? row.runId ?? null,
  ]);
}

function record(value: unknown): Record<string, any> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, any>
    : null;
}

function nullableString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value;
}

function stringArray(value: unknown): string[] | null {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((item) =>
      typeof item !== 'string' ||
      !item ||
      item.trim() !== item)
  ) {
    return null;
  }
  const values = value.map(String);
  return new Set(values).size === values.length ? values : null;
}

function finiteCount(value: unknown): number | null {
  if (
    typeof value !== 'number' &&
    (typeof value !== 'string' || value.trim().length === 0)
  ) {
    return null;
  }
  const number = Number(value);
  return Number.isInteger(number) && number >= 0 ? number : null;
}

function finiteNumber(value: unknown): number | null {
  if (
    typeof value !== 'number' &&
    (typeof value !== 'string' || value.trim().length === 0)
  ) {
    return null;
  }
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function boundedProblems(problems: string[], limit = 10): string[] {
  const unique = uniqueStrings(problems);
  if (unique.length <= limit) return unique;
  return [
    ...unique.slice(0, limit),
    `+${unique.length - limit} more`,
  ];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
