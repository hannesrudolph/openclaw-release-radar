import { createHash } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { config } from '../../src/config.ts';
import { CLOSURE_PROOF_ANALYZER_VERSION } from '../../src/lib/analysisVersions.ts';
import { canonicalizeGitSha } from '../../src/lib/artifactVerification.ts';
import {
  scoreSourceIdentityForDb,
  scoreSourceIdentityManifestProblems,
} from '../../src/lib/scoreSourceIdentity.ts';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  assertAuthoritativeIssueStateEvents,
  issueStateEventSweepDigest,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
  parseIssueStateEventStabilizationIdentity,
} from '../../src/lib/stateEventSnapshot.ts';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from '../../src/lib/scoreHistoryLedger.ts';
import {
  releaseScoreAuditHistoryV2SealProblems,
  scoreAuthorityResolutionRunProblems,
} from '../../src/lib/scoreAuthorityResolution.ts';
import {
  ADVISORY_SNAPSHOT_META_KEY,
  COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
  advisorySnapshotCompletenessProblems,
  advisorySnapshotContentHash,
  buildCompoundAdvisorySnapshotAuditProjection,
} from '../../src/lib/advisorySnapshot.ts';
import {
  verifyOperationReceiptLedger,
} from '../../src/lib/operationReceipts.ts';
import {
  releaseArtifactPublicationLink,
} from '../../src/lib/releaseArtifactPublication.ts';
import {
  releaseArtifactObservationFromStorageRecord,
  releaseArtifactReceiptFromStorageRecord,
} from '../../src/lib/releaseArtifactReceipt.ts';
import {
  compoundAdvisorySnapshotSummary,
  currentScoreReceiptProblems,
  issueCatalogSnapshotSummary,
  operationReceiptSummary,
  releaseCatalogProvenanceSummary,
} from '../doctor.mjs';

const CREDITED_FIX_LINK_SQL =
  "(l.will_close_target = 1 OR l.source IN ('closedByPullRequestsReferences', 'ClosedEvent.closer', 'ClosureComment.fixProof'))";
const CREDITED_FIX_LINK_SQL_FOR_LINK =
  "(link.will_close_target = 1 OR link.source IN ('closedByPullRequestsReferences', 'ClosedEvent.closer', 'ClosureComment.fixProof'))";
const RELEASE_CLOSURE_DEPENDENCY_SNAPSHOT_SCHEMA_VERSION = 2;

function assertAuditDatabasePath(db, dbPath) {
  const main = db.prepare('PRAGMA database_list').all()
    .find((row) => row.name === 'main');
  const openedPath = typeof main?.file === 'string' && main.file
    ? realpathSync(main.file)
    : null;
  const requestedPath = realpathSync(dbPath);
  if (openedPath !== requestedPath) {
    throw new Error(
      `Release audit database connection ${openedPath ?? 'unknown'} does not match ` +
      `requested path ${requestedPath}`,
    );
  }
}

function queryOnlyEnabled(db) {
  const row = db.prepare('PRAGMA query_only').get();
  return Number(
    row?.query_only ?? Object.values(row ?? {})[0] ?? 0,
  ) === 1;
}

function requiredCanonicalAuditString(value, label) {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value;
}

function operationArtifactLedgerRows(db) {
  return {
    artifactReceipts: db.prepare(`
      SELECT *
      FROM release_artifact_verification_receipts
      ORDER BY id
    `).all().map(releaseArtifactReceiptFromStorageRecord),
    artifactObservations: db.prepare(`
      SELECT *
      FROM release_artifact_verification_observations
      ORDER BY id
    `).all().map(releaseArtifactObservationFromStorageRecord),
  };
}

function releaseArtifactIdentityFromActiveRow(row) {
  const repository = `${config.github.owner}/${config.github.repo}`;
  if (!/^[^/\s]+\/[^/\s]+$/.test(repository)) {
    throw new Error('Configured artifact release repository must be owner/name');
  }
  const tagCommitOid = canonicalizeGitSha(
    row.catalog_tag_commit_oid,
    'active release catalog tag commit OID',
  );
  if (!tagCommitOid.value) {
    throw new Error(
      tagCommitOid.problem ?? 'Active release catalog tag commit OID is invalid',
    );
  }
  const publishedAtMs = Date.parse(row.published_at);
  if (!Number.isFinite(publishedAtMs)) {
    throw new Error('Active release published_at must be a valid timestamp');
  }
  return {
    repository,
    tag: requiredCanonicalAuditString(row.tag, 'active release tag'),
    releaseNodeId: requiredCanonicalAuditString(
      row.node_id,
      'active release node ID',
    ),
    catalogTagCommitOid: tagCommitOid.value,
    publishedAt: new Date(publishedAtMs).toISOString(),
  };
}

function sameReleaseArtifactIdentity(left, right) {
  return (
    left.repository === right.repository &&
    left.tag === right.tag &&
    left.releaseNodeId === right.releaseNodeId &&
    left.catalogTagCommitOid === right.catalogTagCommitOid &&
    left.publishedAt === right.publishedAt
  );
}

function advisorySnapshotMetadataFromAuditHeader(header) {
  return {
    schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    snapshotId: Number(header.id),
    capturedAt: header.captured_at,
    repository: {
      owner: header.repository_owner,
      name: header.repository_name,
      url: header.repository_url,
    },
    target: {
      ecosystem: header.target_ecosystem,
      packageName: header.target_package_name,
    },
    sourceHash: header.source_hash,
    catalogHash: header.catalog_hash,
    scoreHash: header.score_hash,
    contentHash: header.content_hash,
    previousContentHash: header.previous_content_hash ?? null,
    rowCount: Number(header.row_count),
    scoreRowCount: Number(header.score_row_count),
    scoreReady: true,
    scoreContentDigest: header.score_content_digest,
  };
}

function readScoreAuthorityEvidence(db) {
  const storedRows = db.prepare(`
    SELECT *
    FROM score_authority_resolution_rows
    ORDER BY authority_run_id, row_ordinal
  `).all();
  const rowsByRun = new Map();
  for (const row of storedRows) {
    const rows = rowsByRun.get(row.authority_run_id) ?? [];
    rows.push({
      authorityRunId: row.authority_run_id,
      rowOrdinal: Number(row.row_ordinal),
      releaseTag: row.release_tag ?? null,
      issueNumber: Number(row.issue_number),
      subjectKind: row.subject_kind,
      subjectIdentity: row.subject_identity,
      candidateId: row.candidate_id ?? null,
      authority: row.authority,
      reason: row.reason,
      authorizedForScoring: Number(row.authorized_for_scoring) === 1,
      evidenceDigest: row.evidence_digest,
      resolutionJson: row.resolution_json,
      contentHash: row.content_hash,
    });
    rowsByRun.set(row.authority_run_id, rows);
  }
  const authorityRuns = db.prepare(`
    SELECT rowid AS storage_ordinal, *
    FROM score_authority_resolution_runs
    ORDER BY rowid
  `).all().map((row) => ({
    authorityRunId: row.authority_run_id,
    schemaVersion: Number(row.schema_version),
    policyVersion: Number(row.policy_version),
    sourceIdentitySchemaVersion: Number(row.source_identity_schema_version),
    sourceIdentityDigest: row.source_identity_digest,
    recordedAt: row.recorded_at,
    rowCount: Number(row.row_count),
    rowsContentHash: row.rows_content_hash,
    previousContentHash: row.previous_content_hash ?? null,
    contentHash: row.content_hash,
    rows: rowsByRun.get(row.authority_run_id) ?? [],
  }));
  const historyV2Seals = db.prepare(`
    SELECT *
    FROM release_score_audit_history_v2_seals
    ORDER BY id
  `).all().map((row) => ({
    id: Number(row.id),
    schemaVersion: Number(row.schema_version),
    historyRunId: row.history_run_id,
    authorityRunId: row.authority_run_id,
    sealedAt: row.sealed_at,
    historyRowCount: Number(row.history_row_count),
    historyRowsContentHash: row.history_rows_content_hash,
    authorityRowCount: Number(row.authority_row_count),
    authorityRowsContentHash: row.authority_rows_content_hash,
    previousContentHash: row.previous_content_hash ?? null,
    contentHash: row.content_hash,
  }));
  return { authorityRuns, historyV2Seals };
}

export function openReleaseAuditReader(dbPath, options = {}) {
  if (!existsSync(dbPath)) {
    throw new Error(`Database not found: ${dbPath}`);
  }
  const providedDatabase = options.database ?? null;
  const db = providedDatabase ?? new DatabaseSync(dbPath, { readOnly: true });
  const closeDatabase = options.closeDatabase ?? (providedDatabase == null);
  let snapshotStarted = false;
  let restoreQueryOnly = false;
  try {
    assertAuditDatabasePath(db, dbPath);
    if (db.isTransaction) {
      throw new Error(
        'Release audit reader requires an idle database connection to pin its snapshot',
      );
    }
    restoreQueryOnly = !queryOnlyEnabled(db);
    if (restoreQueryOnly) db.exec('PRAGMA query_only = ON');
    db.exec('BEGIN');
    snapshotStarted = true;
    // BEGIN is deferred; force a read so WAL visibility is fixed before verification.
    db.prepare('SELECT COUNT(*) AS count FROM sqlite_schema').get();
    if (options.verifyReleaseCatalog !== false) {
      const releaseCatalog = releaseCatalogProvenanceSummary(db, {
        allowTestFixture: options.allowTestFixtureCatalog === true,
      });
      if (releaseCatalog.failedCount > 0) {
        throw new Error(
          `Release audit reader rejected the active release catalog: ` +
          releaseCatalog.problems.slice(0, 6).join('; '),
        );
      }
    }
    return new ReleaseAuditReader(db, {
      closeDatabase,
      restoreQueryOnly: restoreQueryOnly && !closeDatabase,
      snapshotActive: true,
    });
  } catch (error) {
    const cleanupErrors = [];
    if (snapshotStarted && db.isTransaction) {
      try {
        db.exec('ROLLBACK');
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    if (restoreQueryOnly && providedDatabase) {
      try {
        db.exec('PRAGMA query_only = OFF');
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    if (!providedDatabase) {
      try {
        db.close();
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        'Release audit reader open and cleanup both failed',
      );
    }
    throw error;
  }
}

export class ReleaseAuditReader {
  constructor(db, options = {}) {
    this.db = db;
    this.cachedScoreSourceIdentity = null;
    this.closeDatabase = options.closeDatabase ?? true;
    this.restoreQueryOnly = options.restoreQueryOnly ?? false;
    this.snapshotActive = options.snapshotActive ?? false;
    this.closed = false;
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    const cleanupErrors = [];
    if (this.snapshotActive) {
      if (!this.db.isTransaction) {
        cleanupErrors.push(
          new Error('Release audit snapshot transaction ended before reader close'),
        );
      } else {
        try {
          this.db.exec('ROLLBACK');
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      this.snapshotActive = false;
    }
    if (this.restoreQueryOnly && !this.closeDatabase) {
      try {
        this.db.exec('PRAGMA query_only = OFF');
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (this.closeDatabase) {
      try {
        this.db.close();
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length === 1) throw cleanupErrors[0];
    if (cleanupErrors.length > 1) {
      throw new AggregateError(
        cleanupErrors,
        'Release audit reader cleanup failed',
      );
    }
  }

  assertSnapshotActive() {
    if (
      this.closed ||
      !this.snapshotActive ||
      !this.db.isTransaction
    ) {
      throw new Error('Release audit snapshot transaction is not active');
    }
  }

  scoreSourceIdentity({ refresh = false } = {}) {
    if (refresh || !this.cachedScoreSourceIdentity) {
      this.cachedScoreSourceIdentity = scoreSourceIdentityForDb(this.db);
    }
    return this.cachedScoreSourceIdentity;
  }

  scorePublicationIntegrity() {
    const currentAudits = this.db.prepare(`
      SELECT release_tag, scored_at, score_model_version, prompt_version, final_score,
             status, band, recommended, input_json, components_json,
             issue_evidence_json, gate_evidence_json, source_identity_json,
             authority_run_id
      FROM release_score_audits
      ORDER BY release_tag
    `).all();
    const historyRows = this.db.prepare(`
      SELECT *
      FROM release_score_audit_history
      ORDER BY run_id, release_tag
    `).all();
    const seals = this.db.prepare(`
      SELECT *
      FROM release_score_audit_history_runs
      ORDER BY id
    `).all();
    const { authorityRuns, historyV2Seals } =
      readScoreAuthorityEvidence(this.db);
    const forecasts = this.db.prepare(`
      SELECT decision_id, audit_history_run_id, source_identity_json
      FROM release_validation_forecasts
      ORDER BY id
    `).all();
    const historyByRun = new Map();
    for (const row of historyRows) {
      const rows = historyByRun.get(row.run_id) ?? [];
      rows.push(row);
      historyByRun.set(row.run_id, rows);
    }
    const sealByRun = new Map(seals.map((seal) => [seal.run_id, seal]));
    const authorityRunById = new Map(
      authorityRuns.map((run) => [run.authorityRunId, run]),
    );
    const historyV2SealByRun = new Map(
      historyV2Seals.map((seal) => [seal.historyRunId, seal]),
    );
    const invalidRunIds = new Set();
    const invalidAuthorityRunIds = new Set();
    const invalidHistoryV2RunIds = new Set();
    const failures = [];
    let previousContentHash = null;
    for (const seal of seals) {
      const rows = historyByRun.get(seal.run_id) ?? [];
      const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(rows);
      const contentHash = releaseScoreAuditHistoryRunContentHash({
        runId: seal.run_id,
        recordedAt: seal.recorded_at,
        rowCount: Number(seal.row_count),
        rowsContentHash: seal.rows_content_hash,
        previousContentHash: seal.previous_content_hash ?? null,
      });
      const recordedAts = new Set(rows.map((row) => row.recorded_at));
      if (
        rows.length === 0 ||
        (seal.previous_content_hash ?? null) !== previousContentHash ||
        Number(seal.row_count) !== rows.length ||
        seal.rows_content_hash !== rowsContentHash ||
        seal.content_hash !== contentHash ||
        recordedAts.size !== 1 ||
        !recordedAts.has(seal.recorded_at)
      ) {
        invalidRunIds.add(seal.run_id);
        failures.push(`score history run ${seal.run_id} has an invalid seal or chain link`);
      }
      previousContentHash = seal.content_hash;
    }
    for (const runId of historyByRun.keys()) {
      if (!sealByRun.has(runId)) {
        invalidRunIds.add(runId);
        failures.push(`score history run ${runId} is missing its immutable seal`);
      }
    }
    for (const seal of seals) {
      if (!historyByRun.has(seal.run_id)) {
        invalidRunIds.add(seal.run_id);
        failures.push(`score history seal ${seal.run_id} has no rows`);
      }
    }
    let previousAuthorityContentHash = null;
    for (const run of authorityRuns) {
      const problems = scoreAuthorityResolutionRunProblems(run);
      if (run.previousContentHash !== previousAuthorityContentHash) {
        problems.push('previous content hash does not match authority chain');
      }
      if (problems.length > 0) {
        invalidAuthorityRunIds.add(run.authorityRunId);
        failures.push(
          `score authority run ${run.authorityRunId} is invalid: ` +
          problems.join(', '),
        );
      }
      previousAuthorityContentHash = run.contentHash;
    }
    let previousHistoryV2ContentHash = null;
    for (const seal of historyV2Seals) {
      const { id: _id, ...canonicalSeal } = seal;
      const problems = releaseScoreAuditHistoryV2SealProblems(canonicalSeal);
      if (seal.previousContentHash !== previousHistoryV2ContentHash) {
        problems.push('previous content hash does not match history v2 chain');
      }
      const historySeal = sealByRun.get(seal.historyRunId);
      const historyRowsForSeal = historyByRun.get(seal.historyRunId) ?? [];
      const authorityRun = authorityRunById.get(seal.authorityRunId);
      if (!historySeal || !authorityRun) {
        problems.push('linked history or authority run is missing');
      } else {
        if (
          seal.sealedAt !== historySeal.recorded_at ||
          authorityRun.recordedAt !== historySeal.recorded_at ||
          seal.historyRowCount !== Number(historySeal.row_count) ||
          seal.historyRowsContentHash !== historySeal.rows_content_hash ||
          seal.authorityRowCount !== authorityRun.rowCount ||
          seal.authorityRowsContentHash !== authorityRun.rowsContentHash ||
          historyRowsForSeal.some((row) =>
            row.authority_run_id !== authorityRun.authorityRunId)
        ) {
          problems.push('v2 seal does not exactly bind linked runs and rows');
        }
        for (const row of historyRowsForSeal) {
          const sourceIdentity = parseJson(row.source_identity_json, null);
          if (
            sourceIdentity?.schemaVersion !==
              authorityRun.sourceIdentitySchemaVersion ||
            sourceIdentity?.digest !== authorityRun.sourceIdentityDigest
          ) {
            problems.push(
              `history row ${row.release_tag} source identity does not match authority run`,
            );
          }
        }
      }
      if (problems.length > 0) {
        invalidHistoryV2RunIds.add(seal.historyRunId);
        failures.push(
          `score history v2 seal ${seal.historyRunId} is invalid: ` +
          problems.join(', '),
        );
      }
      previousHistoryV2ContentHash = seal.contentHash;
    }
    for (const seal of seals) {
      if (!historyV2SealByRun.has(seal.run_id)) {
        invalidHistoryV2RunIds.add(seal.run_id);
        failures.push(`score history run ${seal.run_id} is missing its v2 seal`);
      }
    }

    const historyManifestProblems = new Map();
    let historySourceManifestFailureCount = 0;
    for (const row of historyRows) {
      const problems = sourceManifestProblems(row.source_identity_json);
      historyManifestProblems.set(`${row.run_id}\0${row.release_tag}`, problems);
      if (problems.length > 0) historySourceManifestFailureCount++;
    }
    let currentSourceManifestFailureCount = 0;
    for (const audit of currentAudits) {
      const problems = sourceManifestProblems(audit.source_identity_json);
      if (problems.length === 0) continue;
      currentSourceManifestFailureCount++;
      failures.push(
        `current audit ${audit.release_tag} has invalid source provenance: ${problems.join(', ')}`,
      );
    }

    const scorePersistence = parseJson(
      this.db.prepare(`
        SELECT value FROM meta WHERE key='score_persistence_last_run'
      `).get()?.value,
      null,
    );
    const currentRunId = scorePersistence?.schemaVersion === 2 &&
      typeof scorePersistence.historyRunId === 'string'
      ? scorePersistence.historyRunId
      : null;
    const currentRunSeal = currentRunId ? sealByRun.get(currentRunId) ?? null : null;
    const currentAuthorityRunId =
      typeof scorePersistence?.authorityRunId === 'string'
        ? scorePersistence.authorityRunId
        : null;
    const currentAuthorityRun = currentAuthorityRunId
      ? authorityRunById.get(currentAuthorityRunId) ?? null
      : null;
    const currentHistoryV2Seal = currentRunId
      ? historyV2SealByRun.get(currentRunId) ?? null
      : null;
    const latestRunSeal = seals.at(-1) ?? null;
    if (
      !currentRunId ||
      !currentRunSeal ||
      invalidRunIds.has(currentRunId) ||
      latestRunSeal?.run_id !== currentRunId ||
      latestRunSeal?.content_hash !== scorePersistence?.historyRunContentHash
    ) {
      failures.push('score persistence does not identify the valid current sealed history tip');
    }
    if (
      !currentAuthorityRunId ||
      !currentAuthorityRun ||
      invalidAuthorityRunIds.has(currentAuthorityRunId) ||
      currentAuthorityRun.contentHash !==
        scorePersistence?.authorityRunContentHash ||
      !currentHistoryV2Seal ||
      invalidHistoryV2RunIds.has(currentRunId) ||
      currentHistoryV2Seal.authorityRunId !== currentAuthorityRunId ||
      currentHistoryV2Seal.contentHash !==
        scorePersistence?.historyV2SealContentHash
    ) {
      failures.push(
        'score persistence does not identify valid current authority and history v2 tips',
      );
    }
    const currentHistoryRows = currentRunId ? historyByRun.get(currentRunId) ?? [] : [];
    const currentHistoryByTag = new Map(
      currentHistoryRows.map((row) => [row.release_tag, row]),
    );
    const currentAuditByTag = new Map(
      currentAudits.map((row) => [row.release_tag, row]),
    );
    const receiptSummary = operationReceiptSummary(this.db);
    const currentReceiptProblems = currentScoreReceiptProblems(this.db, scorePersistence);
    const receiptProblems = [...new Set([
      ...(receiptSummary.problems ?? []).map((problem) => `refresh receipt ledger: ${problem}`),
      ...currentReceiptProblems.map(
        (problem) => `current score tip receipt authorization failed: ${problem}`,
      ),
    ])];
    failures.push(...receiptProblems);
    const publicationDigests = {};
    const publicationAuthorityBindings = {};
    let currentTipSourceManifestFailureCount = 0;
    let currentAuditHistoryFailureCount = 0;
    for (const audit of currentAudits) {
      const historyRow = currentHistoryByTag.get(audit.release_tag);
      if (
        !historyRow ||
        scoreAuditSemanticContent(audit) !== scoreAuditSemanticContent(historyRow) ||
        audit.authority_run_id !== currentAuthorityRunId ||
        historyRow?.authority_run_id !== currentAuthorityRunId
      ) {
        currentAuditHistoryFailureCount++;
        failures.push(
          `current audit ${audit.release_tag} does not match the recorded sealed history tip`,
        );
      }
    }
    for (const historyRow of currentHistoryRows) {
      const problems = historyManifestProblems.get(
        `${historyRow.run_id}\0${historyRow.release_tag}`,
      ) ?? [];
      if (problems.length > 0) {
        currentTipSourceManifestFailureCount++;
        failures.push(
          `current history ${historyRow.run_id}/${historyRow.release_tag} has invalid source provenance: ` +
          problems.join(', '),
        );
      }
      if (!currentAuditByTag.has(historyRow.release_tag)) {
        currentAuditHistoryFailureCount++;
        failures.push(
          `current history ${historyRow.run_id}/${historyRow.release_tag} has no current audit row`,
        );
      }
      if (
        currentRunSeal &&
        currentRunId === currentRunSeal.run_id &&
        !invalidRunIds.has(currentRunId) &&
        currentAuthorityRun &&
        !invalidAuthorityRunIds.has(currentAuthorityRun.authorityRunId) &&
        currentHistoryV2Seal &&
        !invalidHistoryV2RunIds.has(currentRunId)
      ) {
        publicationDigests[historyRow.release_tag] = createHash('sha256')
          .update(
            `sealed-release-score-audit-v2\0${JSON.stringify([
              currentRunSeal.run_id,
              currentRunSeal.content_hash,
              currentRunSeal.rows_content_hash,
              currentAuthorityRun.contentHash,
              currentHistoryV2Seal.contentHash,
              scoreAuditSemanticContent(historyRow),
            ])}`,
          )
          .digest('hex');
        publicationAuthorityBindings[historyRow.release_tag] = {
          authorityRunId: currentAuthorityRun.authorityRunId,
          authorityRunContentHash: currentAuthorityRun.contentHash,
          historyV2SealContentHash: currentHistoryV2Seal.contentHash,
        };
      }
    }

    let forecastSourceManifestFailureCount = 0;
    let forecastHistorySourceManifestFailureCount = 0;
    for (const forecast of forecasts) {
      const forecastProblems = sourceManifestProblems(forecast.source_identity_json);
      if (forecastProblems.length > 0) {
        forecastSourceManifestFailureCount++;
        failures.push(
          `forecast ${forecast.decision_id} has invalid source provenance: ` +
          forecastProblems.join(', '),
        );
      }
      const referencedRows = historyByRun.get(forecast.audit_history_run_id) ?? [];
      const referencedAuthorityRunIds = new Set(
        referencedRows.map((row) => row.authority_run_id),
      );
      const referencedAuthorityRunId =
        referencedAuthorityRunIds.size === 1 &&
          typeof [...referencedAuthorityRunIds][0] === 'string'
          ? [...referencedAuthorityRunIds][0]
          : null;
      const referencedAuthorityRun = referencedAuthorityRunId
        ? authorityRunById.get(referencedAuthorityRunId) ?? null
        : null;
      const referencedHistoryV2Seal = historyV2SealByRun.get(
        forecast.audit_history_run_id,
      ) ?? null;
      if (
        referencedRows.length === 0 ||
        !sealByRun.has(forecast.audit_history_run_id) ||
        invalidRunIds.has(forecast.audit_history_run_id) ||
        !referencedAuthorityRun ||
        invalidAuthorityRunIds.has(referencedAuthorityRunId) ||
        !referencedHistoryV2Seal ||
        invalidHistoryV2RunIds.has(forecast.audit_history_run_id) ||
        referencedHistoryV2Seal.authorityRunId !== referencedAuthorityRunId
      ) {
        failures.push(
          `forecast ${forecast.decision_id} references an invalid score history run ` +
          forecast.audit_history_run_id,
        );
      }
      for (const historyRow of referencedRows) {
        const problems = historyManifestProblems.get(
          `${historyRow.run_id}\0${historyRow.release_tag}`,
        ) ?? [];
        if (problems.length === 0) continue;
        forecastHistorySourceManifestFailureCount++;
        failures.push(
          `forecast ${forecast.decision_id} references invalid history provenance ` +
          `${historyRow.run_id}/${historyRow.release_tag}: ${problems.join(', ')}`,
        );
      }
    }

    return {
      currentAuditCount: currentAudits.length,
      historyRowCount: historyRows.length,
      authorityRunCount: authorityRuns.length,
      historyV2SealCount: historyV2Seals.length,
      invalidAuthorityRunCount: invalidAuthorityRunIds.size,
      invalidHistoryV2SealCount: invalidHistoryV2RunIds.size,
      historySourceManifestFailureCount,
      currentSourceManifestFailureCount,
      currentTipSourceManifestFailureCount,
      currentAuditHistoryFailureCount,
      forecastSourceManifestFailureCount,
      forecastHistorySourceManifestFailureCount,
      operationReceiptFailureCount: receiptProblems.length,
      publicationDigests,
      publicationAuthorityBindings,
      failures,
      failedCount: failures.length,
    };
  }

  advisorySnapshotAuditProjection(
    v2Summary = null,
    { observedAt = new Date().toISOString() } = {},
  ) {
    const v2 = v2Summary ?? compoundAdvisorySnapshotSummary(this.db);
    const activeProjectionProblemSet = new Set([
      'current advisory v2 metadata does not identify an intact ledger entry',
      'active advisory rows do not match the selected v2 score projection',
    ]);
    const integrityProblems = (v2.problems ?? []).filter(
      (problem) => !activeProjectionProblemSet.has(problem),
    );
    if (Number(v2.failedCount ?? 0) > (v2.problems ?? []).length) {
      integrityProblems.push(
        `advisory snapshot v2 integrity retained ${(v2.problems ?? []).length} ` +
        `of ${v2.failedCount} reported failure(s)`,
      );
    }
    const activeProjectionProblems = (v2.problems ?? []).filter(
      (problem) => activeProjectionProblemSet.has(problem),
    );
    let snapshots = [];
    try {
      snapshots = this.db.prepare(`
        SELECT *
        FROM advisory_snapshot_v2_history
        ORDER BY id
      `).all().map((header) => ({
        metadata: advisorySnapshotMetadataFromAuditHeader(header),
      }));
    } catch (error) {
      integrityProblems.push(
        `advisory snapshot v2 metadata could not be read: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
    let attempts = [];
    let stageEvents = [];
    let receipts = [];
    let leases = [];
    let operationLedgerProblems = [];
    try {
      attempts = this.db.prepare(`
        SELECT * FROM refresh_operation_attempts ORDER BY started_at, run_id
      `).all();
      stageEvents = this.db.prepare(`
        SELECT * FROM refresh_operation_stage_events ORDER BY run_id, sequence
      `).all();
      receipts = this.db.prepare(`
        SELECT * FROM refresh_capture_receipts ORDER BY id
      `).all();
      leases = this.db.prepare(`
        SELECT * FROM refresh_leases ORDER BY name
      `).all();
      const artifactLedger = operationArtifactLedgerRows(this.db);
      operationLedgerProblems = verifyOperationReceiptLedger({
        attempts,
        stageEvents,
        receipts,
        leases,
        ...artifactLedger,
        artifactMembershipPolicy: 'strict',
        observedAt,
      }).problems;
    } catch (error) {
      operationLedgerProblems = [
        `operation receipt ledger could not be read: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      ];
    }
    return buildCompoundAdvisorySnapshotAuditProjection({
      snapshots,
      activeMetadata: v2.activeMetadata ?? null,
      integrityProblems,
      activeProjectionProblems,
      attempts: attempts.map((attempt) => ({
        runId: attempt.run_id,
        startedAt: attempt.started_at,
      })),
      receipts: receipts.map((receipt) => ({
        receiptId: receipt.receipt_id,
        runId: receipt.run_id,
        status: receipt.status,
        finishedAt: receipt.finished_at,
        durationMs: Number(receipt.duration_ms),
        stageEventCount: Number(receipt.stage_event_count),
        stageChainHash: receipt.stage_chain_hash ?? null,
        payloadJson: receipt.payload_json,
      })),
      operationLedgerProblems,
    });
  }

  advisorySnapshotIntegrity() {
    const rows = this.db.prepare(`
      SELECT advisory_key, ghsa_id, cve_id, summary, severity, html_url, published_at,
             package_ecosystem, package_name, vulnerable_version_range, patched_versions
      FROM advisories
      ORDER BY advisory_key
    `).all();
    const metadataRow = this.db.prepare(`SELECT value FROM meta WHERE key=?`)
      .get(ADVISORY_SNAPSHOT_META_KEY);
    let metadata = null;
    try {
      metadata = metadataRow?.value ? JSON.parse(metadataRow.value) : null;
    } catch {
      metadata = metadataRow?.value ?? null;
    }
    const latestSnapshot = this.db.prepare(`
      SELECT id, captured_at, row_count, content_hash
      FROM advisory_snapshot_history
      ORDER BY id DESC
      LIMIT 1
    `).get() ?? null;
    const contentDigest = advisorySnapshotContentHash(rows);
    const problems = advisorySnapshotCompletenessProblems(
      metadata,
      rows,
      { ecosystem: 'npm', packageName: process.env.GITHUB_REPO ?? 'openclaw' },
    ).map((problem) => `${problem.code}:${problem.detail}`);
    if (
      !latestSnapshot ||
      Number(latestSnapshot.row_count) !== rows.length ||
      latestSnapshot.content_hash !== contentDigest
    ) {
      problems.push(
        `latest_snapshot_mismatch:latest immutable advisory snapshot must match ` +
        `${rows.length} current row(s) and digest ${contentDigest}`,
      );
    }
    const v2 = compoundAdvisorySnapshotSummary(this.db);
    const auditProjection = this.advisorySnapshotAuditProjection(v2);
    return {
      schemaVersion: 2,
      sourceMode: 'compound_advisory_v2_first',
      metadata,
      rowCount: rows.length,
      contentDigest,
      latestSnapshot,
      v2,
      auditProjection,
      legacyCompatibility: {
        metadata,
        rowCount: rows.length,
        contentDigest,
        latestSnapshot,
        problems,
        failedCount: problems.length,
      },
      problems: auditProjection.problems,
      failedCount: auditProjection.failedCount,
    };
  }

  issueCrawlMetadata() {
    return {
      issueCrawl: parseJson(
        this.db.prepare(`SELECT value FROM meta WHERE key='issue_crawl_last_run'`).get()?.value,
        null,
      ),
      baseline: parseJson(
        this.db.prepare(`SELECT value FROM meta WHERE key='issue_crawl_exhaustive_baseline'`).get()?.value,
        null,
      ),
    };
  }

  issueCatalogSnapshotIntegrity(now = new Date()) {
    return issueCatalogSnapshotSummary(this.db, now);
  }

  listReleases(limit = 10, options = {}) {
    return this.db.prepare(`
      SELECT *
      FROM releases r
      WHERE r.prerelease = 0
        AND r.catalog_active = 1
        AND (? = 0 OR r.final_score IS NOT NULL OR EXISTS (
          SELECT 1 FROM release_score_audits a WHERE a.release_tag=r.tag
        ))
      ORDER BY catalog_rank IS NULL, catalog_rank, published_at IS NULL, published_at DESC
      LIMIT ?
    `).all(options.scoredOnly ? 1 : 0, limit);
  }

  scoredStableReleaseCount() {
    const row = this.db.prepare(`
      SELECT COUNT(*) AS count
      FROM releases r
      WHERE r.prerelease = 0
        AND r.catalog_active = 1
        AND (r.final_score IS NOT NULL OR EXISTS (
          SELECT 1 FROM release_score_audits a WHERE a.release_tag=r.tag
        ))
    `).get();
    return Number(row?.count ?? 0);
  }

  getRelease(tag) {
    return this.db.prepare(`
      SELECT *
      FROM releases
      WHERE tag=?
        AND catalog_active=1
        AND prerelease=0
    `).get(tag);
  }

  activeReleaseBoundaryRows() {
    return this.db.prepare(`
      SELECT tag, published_at, catalog_rank, prerelease
      FROM releases
      WHERE catalog_active=1
      ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC, tag
    `).all();
  }

  stableReleaseBoundaryRows() {
    return this.db.prepare(`
      SELECT
        release.tag,
        release.published_at,
        release.catalog_rank,
        release.catalog_tag_commit_oid,
        release_commit.tag_commit_oid AS resolved_tag_commit_oid
      FROM releases release
      LEFT JOIN release_commits release_commit ON release_commit.tag=release.tag
      WHERE release.catalog_active=1
        AND release.prerelease=0
      ORDER BY release.catalog_rank IS NULL, release.catalog_rank,
               release.published_at DESC, release.tag
    `).all();
  }

  releaseArtifactVerificationForAudit(tag, runId) {
    const releaseTag = requiredCanonicalAuditString(tag, 'scored release tag');
    const artifactRunId = requiredCanonicalAuditString(
      runId,
      'artifact observation run ID',
    );
    const releaseRows = this.db.prepare(`
      SELECT tag, node_id, catalog_tag_commit_oid, published_at
      FROM releases
      WHERE tag=?
        AND catalog_active=1
      ORDER BY rowid
    `).all(releaseTag);
    if (releaseRows.length !== 1) {
      throw new Error(
        `Artifact audit selection for ${JSON.stringify(releaseTag)} requires ` +
        `exactly one active release row; found ${releaseRows.length}`,
      );
    }
    const release = releaseArtifactIdentityFromActiveRow(releaseRows[0]);
    if (release.tag !== releaseTag) {
      throw new Error(
        `Active release identity for ${JSON.stringify(releaseTag)} is inconsistent`,
      );
    }

    const observationRows = this.db.prepare(`
      SELECT
        observation_id,
        schema_version,
        run_id,
        observed_at,
        release_repository,
        release_tag,
        release_node_id,
        release_tag_commit_oid,
        release_published_at,
        receipt_id,
        receipt_content_hash,
        canonical_observation_json,
        previous_content_hash,
        content_hash
      FROM release_artifact_verification_observations
      WHERE run_id=?
        AND release_tag=?
      ORDER BY id
    `).all(artifactRunId, releaseTag);
    if (observationRows.length === 0) return null;
    if (observationRows.length !== 1) {
      throw new Error(
        `Artifact audit selection for ${JSON.stringify(releaseTag)} in run ` +
        `${JSON.stringify(artifactRunId)} requires exactly one observation; ` +
        `found ${observationRows.length}`,
      );
    }
    const observation = releaseArtifactObservationFromStorageRecord(
      observationRows[0],
    );
    if (
      observation.runId !== artifactRunId ||
      !sameReleaseArtifactIdentity(observation.release, release)
    ) {
      throw new Error(
        `Artifact observation ${JSON.stringify(observation.observationId)} ` +
        'does not match the active scored release identity and run',
      );
    }

    const receiptRows = this.db.prepare(`
      SELECT
        receipt_id,
        schema_version,
        release_repository,
        release_tag,
        release_node_id,
        release_tag_commit_oid,
        release_published_at,
        evidence_identity,
        canonical_receipt_json,
        previous_content_hash,
        content_hash
      FROM release_artifact_verification_receipts
      WHERE receipt_id=?
      ORDER BY id
    `).all(observation.receiptId);
    if (receiptRows.length !== 1) {
      throw new Error(
        `Artifact observation ${JSON.stringify(observation.observationId)} ` +
        `requires exactly one receipt; found ${receiptRows.length}`,
      );
    }
    const receipt = releaseArtifactReceiptFromStorageRecord(receiptRows[0]);
    releaseArtifactPublicationLink(observation, receipt);
    if (!sameReleaseArtifactIdentity(receipt.release, release)) {
      throw new Error(
        `Artifact receipt ${JSON.stringify(receipt.receiptId)} does not match ` +
        'the active scored release identity',
      );
    }
    return { observation, receipt };
  }

  closedDuringReign(tag) {
    return this.db.prepare(`
      SELECT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version, c.classification_origin, c.raw_model_output, c.provenance_json
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN releases target ON target.tag = ?
      WHERE
        target.catalog_active=1
        AND target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0
                 AND next.catalog_active = 1),
              '9999-12-31T23:59:59Z'
            )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  rawClosedDuringReign(tag) {
    return this.db.prepare(`
      SELECT i.*
      FROM issues i
      JOIN releases target ON target.tag = ?
      WHERE
        target.catalog_active=1
        AND target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0
                 AND next.catalog_active = 1),
              '9999-12-31T23:59:59Z'
            )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  verifiedFixedForRelease(tag) {
    return this.db.prepare(`
      WITH target AS (
        SELECT * FROM releases WHERE tag=? AND catalog_active=1
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
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version, c.classification_origin, c.raw_model_output, c.provenance_json
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN target
      WHERE
        target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0
                 AND next.catalog_active = 1),
              '9999-12-31T23:59:59Z'
            )
        AND EXISTS (
          SELECT 1
          FROM window_closure e
          WHERE e.issue_number = i.number
            AND e.state_reason = 'COMPLETED'
        )
        AND EXISTS (
          SELECT 1
          FROM issue_closure_proofs proof
          WHERE proof.release_tag = target.tag
            AND proof.issue_number = i.number
            AND proof.status = 'fixed_in_release'
        )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  unverifiedClosedForRelease(tag) {
    return this.db.prepare(`
      SELECT DISTINCT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version, c.classification_origin, c.raw_model_output, c.provenance_json
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN releases target ON target.tag = ?
      WHERE
        target.catalog_active=1
        AND target.published_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.published_at
        AND i.closed_at < COALESCE(
              (SELECT MIN(next.published_at)
               FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0
                 AND next.catalog_active = 1),
              '9999-12-31T23:59:59Z'
            )
        AND NOT EXISTS (
          SELECT 1
          FROM issue_closure_proofs proof
          WHERE proof.release_tag = target.tag
            AND proof.issue_number = i.number
            AND proof.status = 'fixed_in_release'
        )
      ORDER BY i.closed_at DESC
    `).all(tag);
  }

  proofRowsFor(tag) {
    const release = this.db.prepare(`
      SELECT tag, published_at, hours_to_next_stable
      FROM releases
      WHERE tag=? AND catalog_active=1
    `).get(tag);
    const audit = this.getReleaseScoreAudit(tag);
    const cutoff = releaseLabelCutoff(release, audit?.scored_at ?? null);
    const rows = this.db.prepare(`
      SELECT p.release_tag, p.issue_number, p.status, p.summary, p.evidence_json, p.checked_at,
             i.title, i.labels,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.prompt_version, c.classification_origin,
             c.raw_model_output, c.provenance_json
      FROM issue_closure_proofs p
      JOIN issues i ON i.number=p.issue_number
      LEFT JOIN classifications c ON c.issue_number=p.issue_number
      WHERE p.release_tag=?
      ORDER BY p.issue_number
    `).all(tag);
    return rows.map((row) => ({
      ...row,
      effective_labels: labelsForIssueAt(this.db, row.issue_number, parseLabels(row.labels), cutoff, {
        useFallbackWhenNoEvents: cutoff == null,
        useSnapshotWhenNoEvents: cutoff != null,
      }),
    }));
  }

  issueNumbersForVersion(tag) {
    return this.issuesForVersion(tag).map((row) => Number(row.number));
  }

  issuesForVersion(tag) {
    return this.db.prepare(`
      WITH target AS (
        SELECT
          tag,
          published_at AS start_at,
          COALESCE(
            (SELECT MIN(next.published_at)
             FROM releases next
             WHERE next.published_at > releases.published_at
               AND next.prerelease = 0
               AND next.catalog_active = 1),
            '9999-12-31T23:59:59Z'
          ) AS end_at
        FROM releases
        WHERE tag=?
          AND catalog_active=1
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
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version, c.classification_origin, c.raw_model_output, c.provenance_json
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
    `).all(tag);
  }

  openedDuringReign(tag) {
    return this.db.prepare(`
      SELECT i.*,
             c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
             c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
             c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
             c.prompt_version, c.classification_origin, c.raw_model_output, c.provenance_json
      FROM issues i
      JOIN classifications c ON c.issue_number = i.number
      JOIN releases target ON target.tag = ?
      WHERE
        target.catalog_active=1
        AND target.published_at IS NOT NULL
        AND i.created_at >= target.published_at
        AND i.created_at < COALESCE(
              (SELECT MIN(next.published_at) FROM releases next
               WHERE next.published_at > target.published_at
                 AND next.prerelease = 0
                 AND next.catalog_active = 1),
              '9999-12-31T23:59:59Z'
            )
      ORDER BY i.created_at DESC
    `).all(tag);
  }

  labelsForIssueAt(issueNumber, fallbackLabels, cutoff, options = {}) {
    return labelsForIssueAt(this.db, issueNumber, fallbackLabels, cutoff, options);
  }

  tableExists(name) {
    const row = this.db.prepare(`
      SELECT 1 AS present
      FROM sqlite_master
      WHERE type='table' AND name=?
    `).get(name);
    return !!row;
  }

  tableHasColumns(name, columns) {
    if (!this.tableExists(name)) return false;
    const existing = new Set(this.db.prepare(`PRAGMA table_info(${name})`).all().map((col) => col.name));
    return columns.every((column) => existing.has(column));
  }

  sourceFreshnessFor(tag) {
    const issueFetchFreshnessSql = this.tableHasColumns('issues', ['fetched_at'])
      ? `UNION ALL
      SELECT 'issue_fetches', MAX(i.fetched_at)
      FROM issues i JOIN issue_universe u ON u.number=i.number`
      : '';
    const issueCommentFreshnessSql = this.tableHasColumns('issue_comment_snapshots', ['fetched_at'])
      ? `UNION ALL
      SELECT 'issue_comments', MAX(s.fetched_at)
      FROM issue_comment_snapshots s JOIN issue_universe u ON u.number=s.issue_number`
      : `UNION ALL
      SELECT 'issue_comments', NULL`;
    const commitReferenceFreshnessSql = this.tableExists('issue_commit_references')
      ? `UNION ALL
      SELECT 'issue_commit_references', MAX(c.fetched_at)
      FROM issue_commit_references c JOIN closed_universe u ON u.number=c.issue_number`
      : `UNION ALL
      SELECT 'issue_commit_references', NULL`;
    const releaseRowsFreshnessSql = this.tableHasColumns('releases', [
      'release_metadata_fetched_at',
      'release_derived_fetched_at',
      'release_artifact_checked_at',
    ])
      ? `
        SELECT r.release_metadata_fetched_at AS updated_at FROM releases r JOIN target ON target.tag=r.tag
        UNION ALL
        SELECT r.release_derived_fetched_at FROM releases r JOIN target ON target.tag=r.tag
        UNION ALL
        SELECT r.release_artifact_checked_at FROM releases r JOIN target ON target.tag=r.tag
        UNION ALL`
      : '';
    return this.db.prepare(`
      WITH target AS (
        SELECT tag, published_at,
               COALESCE(
                 (SELECT MIN(next.published_at)
                  FROM releases next
                  WHERE next.published_at > releases.published_at
                    AND next.prerelease=0
                    AND next.catalog_active=1),
                 '9999-12-31T23:59:59Z'
               ) AS end_at
        FROM releases
        WHERE tag=?
          AND catalog_active=1
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
        WHERE target.published_at IS NOT NULL
          AND EXISTS (
            SELECT 1
            FROM issue_open_intervals interval
            WHERE interval.issue_number=i.number
              AND interval.open_at < target.end_at
              AND (interval.close_at IS NULL OR interval.close_at > target.published_at)
          )
      ),
      closed_universe AS (
        SELECT DISTINCT i.number
        FROM issues i
        JOIN target
        WHERE i.closed_at IS NOT NULL
          AND i.closed_at >= target.published_at
          AND i.closed_at < target.end_at
      ),
        pr_universe AS (
          SELECT DISTINCT l.pr_repository_name_with_owner, l.pr_number
          FROM issue_pr_links l
          JOIN closed_universe c ON c.number=l.issue_number
          WHERE ${CREDITED_FIX_LINK_SQL}
      )
      SELECT 'release_metadata' AS source, MAX(updated_at) AS max_ts
      FROM (
        ${releaseRowsFreshnessSql}
        SELECT fetched_at AS updated_at FROM release_commits WHERE tag=?
        UNION ALL
        SELECT fetched_at FROM advisories
      )
      UNION ALL
      SELECT 'issue_rows', MAX(i.updated_at)
      FROM issues i JOIN issue_universe u ON u.number=i.number
      ${issueFetchFreshnessSql}
      ${issueCommentFreshnessSql}
      UNION ALL
      SELECT 'classification_rows', MAX(c.classified_at)
      FROM classifications c JOIN issue_universe u ON u.number=c.issue_number
      UNION ALL
      SELECT 'label_events', MAX(e.fetched_at)
      FROM issue_label_events e JOIN issue_universe u ON u.number=e.issue_number
      UNION ALL
      SELECT 'label_snapshots', MAX(s.fetched_at)
      FROM issue_label_snapshots s JOIN issue_universe u ON u.number=s.issue_number
      UNION ALL
      SELECT 'issue_state_event_snapshots', MAX(s.fetched_at)
      FROM issue_state_event_snapshots s JOIN issue_universe u ON u.number=s.issue_number
      UNION ALL
      SELECT 'closure_proofs', MAX(p.checked_at)
      FROM issue_closure_proofs p
      WHERE p.release_tag=?
      UNION ALL
      SELECT 'closure_events', MAX(e.fetched_at)
      FROM issue_closure_events e JOIN closed_universe u ON u.number=e.issue_number
      UNION ALL
      SELECT 'reopen_events', MAX(r.fetched_at)
      FROM issue_reopen_events r JOIN issue_universe u ON u.number=r.issue_number
      UNION ALL
      SELECT 'issue_pr_links', MAX(l.fetched_at)
      FROM issue_pr_links l JOIN closed_universe u ON u.number=l.issue_number
      ${commitReferenceFreshnessSql}
      UNION ALL
        SELECT 'release_closure_dependency_snapshots', MAX(s.captured_at)
        FROM release_closure_dependency_snapshots s
        WHERE s.release_tag=?
        UNION ALL
        SELECT 'pull_request_fixes', MAX(p.fetched_at)
        FROM pull_request_fixes p JOIN pr_universe u ON u.pr_repository_name_with_owner=p.pr_repository_name_with_owner AND u.pr_number=p.pr_number
        UNION ALL
        SELECT 'release_pr_reachability', MAX(r.checked_at)
        FROM release_pr_reachability r JOIN pr_universe u ON u.pr_repository_name_with_owner=r.pr_repository_name_with_owner AND u.pr_number=r.pr_number
      WHERE r.tag=?
    `).all(tag, tag, tag, tag, tag);
  }

  proofDependencyFreshnessForIssue(tag, issueNumber) {
    const hasIssueFetches = this.tableHasColumns('issues', ['fetched_at']);
    const hasIssueComments = this.tableHasColumns('issue_comment_snapshots', ['fetched_at']);
    const hasCommitReferences = this.tableExists('issue_commit_references');
    const issueFetchFreshnessSql = hasIssueFetches
      ? `UNION ALL
      SELECT 'issue_fetches', MAX(fetched_at)
      FROM issues
      WHERE number=?`
      : '';
    const issueCommentFreshnessSql = hasIssueComments
      ? `UNION ALL
      SELECT 'issue_comments', MAX(fetched_at)
      FROM issue_comment_snapshots
      WHERE issue_number=?`
      : `UNION ALL
      SELECT 'issue_comments', NULL`;
    const commitReferenceFreshnessSql = hasCommitReferences
      ? `UNION ALL
      SELECT 'issue_commit_references', MAX(c.fetched_at)
      FROM issue_commit_references c
      WHERE c.issue_number=?`
      : `UNION ALL
      SELECT 'issue_commit_references', NULL`;
    const params = [
      issueNumber,
      issueNumber,
      ...(hasIssueFetches ? [issueNumber] : []),
      ...(hasIssueComments ? [issueNumber] : []),
      issueNumber,
      issueNumber,
      issueNumber,
      issueNumber,
      issueNumber,
      issueNumber,
      issueNumber,
      ...(hasCommitReferences ? [issueNumber] : []),
      tag,
      tag,
    ];
    return this.db.prepare(`
      WITH linked_prs AS (
        SELECT DISTINCT pr_repository_name_with_owner, pr_number
        FROM issue_pr_links
        WHERE issue_number=?
      )
      SELECT 'issue_rows' AS source, MAX(updated_at) AS max_ts
      FROM issues
      WHERE number=?
      ${issueFetchFreshnessSql}
      ${issueCommentFreshnessSql}
      UNION ALL
      SELECT 'classification_rows', MAX(classified_at)
      FROM classifications
      WHERE issue_number=?
      UNION ALL
      SELECT 'label_events', MAX(fetched_at)
      FROM issue_label_events
      WHERE issue_number=?
      UNION ALL
      SELECT 'label_snapshots', MAX(fetched_at)
      FROM issue_label_snapshots
      WHERE issue_number=?
      UNION ALL
      SELECT 'issue_state_event_snapshots', MAX(fetched_at)
      FROM issue_state_event_snapshots
      WHERE issue_number=?
      UNION ALL
      SELECT 'closure_events', MAX(fetched_at)
      FROM issue_closure_events
      WHERE issue_number=?
      UNION ALL
      SELECT 'reopen_events', MAX(fetched_at)
      FROM issue_reopen_events
      WHERE issue_number=?
      UNION ALL
      SELECT 'issue_pr_links', MAX(fetched_at)
      FROM issue_pr_links
      WHERE issue_number=?
      ${commitReferenceFreshnessSql}
      UNION ALL
      SELECT 'pull_request_fixes', MAX(p.fetched_at)
      FROM pull_request_fixes p
      JOIN linked_prs l
        ON l.pr_repository_name_with_owner=p.pr_repository_name_with_owner
       AND l.pr_number=p.pr_number
      UNION ALL
      SELECT 'release_pr_reachability', MAX(r.checked_at)
      FROM release_pr_reachability r
      JOIN linked_prs l
        ON l.pr_repository_name_with_owner=r.pr_repository_name_with_owner
       AND l.pr_number=r.pr_number
      WHERE r.tag=?
      UNION ALL
      SELECT 'release_closure_dependency_snapshots', MAX(captured_at)
      FROM release_closure_dependency_snapshots
      WHERE release_tag=?
    `).all(...params);
  }

  issueStateSnapshotIntegrityForRelease(tag, exampleLimit = 10) {
    const rows = this.db.prepare(`
      WITH target AS (
        SELECT
          tag,
          published_at AS start_at,
          COALESCE(
            (SELECT MIN(next.published_at)
             FROM releases next
             WHERE next.published_at > releases.published_at
               AND next.prerelease = 0
               AND next.catalog_active = 1),
            '9999-12-31T23:59:59Z'
          ) AS end_at
        FROM releases
        WHERE tag=?
          AND catalog_active=1
      ),
      candidates AS (
        SELECT i.*
        FROM issues i
        JOIN target
        WHERE target.start_at IS NOT NULL
          AND i.created_at < target.end_at
          AND (
            i.state='open'
            OR i.closed_at IS NULL
            OR i.closed_at > target.start_at
          )
      ),
      projection_counts AS (
        SELECT
          candidate.number AS issue_number,
          (SELECT COUNT(*) FROM issue_closure_events close_event
           WHERE close_event.issue_number=candidate.number) AS closure_count,
          (SELECT COUNT(*) FROM issue_reopen_events reopen_event
           WHERE reopen_event.issue_number=candidate.number) AS reopen_count
        FROM candidates candidate
      ),
      latest_events AS (
        SELECT issue_number, event_type, occurred_at
        FROM (
          SELECT
            event.issue_number,
            event.event_type,
            event.occurred_at,
            event.event_id,
            ROW_NUMBER() OVER (
              PARTITION BY event.issue_number
              ORDER BY event.occurred_at DESC, event.event_id DESC
            ) AS rank
          FROM (
            SELECT issue_number, 'closed' AS event_type, closed_at AS occurred_at, event_id
            FROM issue_closure_events
            WHERE closed_at IS NOT NULL
            UNION ALL
            SELECT issue_number, 'reopened' AS event_type, reopened_at AS occurred_at, event_id
            FROM issue_reopen_events
            WHERE reopened_at IS NOT NULL
          ) event
        )
        WHERE rank=1
      )
      SELECT
        candidate.number AS issue_number,
        candidate.node_id AS current_issue_node_id,
        candidate.state AS current_state,
        candidate.updated_at,
        candidate.closed_at,
        snapshot.schema_version,
        snapshot.repository_node_id,
        snapshot.issue_node_id,
        snapshot.issue_node_type,
        snapshot.issue_state AS snapshot_state,
        snapshot.issue_updated_at,
        snapshot.total_count,
        snapshot.fetched_count,
        snapshot.events_digest,
        snapshot.authority_digest,
        snapshot.events_json,
        snapshot.sweep_count,
        snapshot.stabilized,
        snapshot.stabilization_json,
        snapshot.stabilization_identity_digest,
        COALESCE(projection.closure_count, 0) + COALESCE(projection.reopen_count, 0) AS projection_count,
        latest.event_type AS latest_event_type
      FROM candidates candidate
      LEFT JOIN issue_state_event_snapshots snapshot ON snapshot.issue_number=candidate.number
      LEFT JOIN projection_counts projection ON projection.issue_number=candidate.number
      LEFT JOIN latest_events latest ON latest.issue_number=candidate.number
      ORDER BY candidate.number
    `).all(tag);
    const projectedEventsByIssue = projectedIssueStateEventsForIssues(
      this.db,
      rows.map((row) => Number(row.issue_number)),
    );

    const report = {
      tag,
      candidateIssueCount: rows.length,
      missingSnapshotCount: 0,
      invalidSnapshotCount: 0,
      metadataMismatchCount: 0,
      projectionMismatchCount: 0,
      latestStateMismatchCount: 0,
      failedCount: 0,
      examples: [],
    };
    const addExample = (kind, issueNumber, detail) => {
      if (report.examples.length < Math.max(0, Math.floor(exampleLimit))) {
        report.examples.push({ kind, issueNumber, detail });
      }
    };

    for (const row of rows) {
      const issueNumber = Number(row.issue_number);
      if (row.schema_version == null) {
        report.missingSnapshotCount++;
        addExample('missing', issueNumber, 'issue is missing a verified state-event snapshot');
        continue;
      }
      let parsedEvents = null;
      try {
        parsedEvents = JSON.parse(String(row.events_json ?? ''));
      } catch {
        // Counted as invalid below.
      }
      const eventRows = Array.isArray(parsedEvents) ? parsedEvents : null;
      let normalizedEvents = null;
      let digestMatches = false;
      let authorityMatches = false;
      let stabilizationMatches = false;
      if (eventRows) {
        try {
          normalizedEvents = normalizeIssueStateEvents(eventRows);
          assertAuthoritativeIssueStateEvents(normalizedEvents);
          digestMatches = issueStateEventsDigest(normalizedEvents, {
            repositoryNodeId: row.repository_node_id,
            issueNodeId: row.issue_node_id,
            issueNodeType: row.issue_node_type,
          }) === row.events_digest;
          const authorityDigest = issueStateEventSweepDigest({
            repositoryNodeId: row.repository_node_id,
            issueNumber,
            issueNodeId: row.issue_node_id,
            issueNodeType: row.issue_node_type,
            issueState: row.snapshot_state,
            issueUpdatedAt: row.issue_updated_at,
            totalCount: Number(row.total_count),
            events: normalizedEvents,
          });
          authorityMatches = authorityDigest === row.authority_digest;
          const stabilization = parseIssueStateEventStabilizationIdentity(
            String(row.stabilization_json ?? ''),
          );
          stabilizationMatches =
            stabilization.sweepCount === Number(row.sweep_count) &&
            stabilization.secondSweep.sweepDigest === authorityDigest &&
            stabilization.identityDigest === row.stabilization_identity_digest;
        } catch {
          digestMatches = false;
          authorityMatches = false;
          stabilizationMatches = false;
        }
      }
      const totalCount = Number(row.total_count);
      const fetchedCount = Number(row.fetched_count);
      if (
        Number(row.schema_version) !== ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION ||
        !Number.isInteger(totalCount) ||
        totalCount < 0 ||
        fetchedCount !== totalCount ||
        eventRows == null ||
        eventRows.length !== totalCount ||
        !digestMatches ||
        !authorityMatches ||
        !stabilizationMatches ||
        typeof row.repository_node_id !== 'string' ||
        row.repository_node_id.length === 0 ||
        row.issue_node_id !== row.current_issue_node_id ||
        row.issue_node_type !== 'Issue' ||
        !Number.isInteger(Number(row.sweep_count)) ||
        Number(row.sweep_count) < 2 ||
        Number(row.stabilized) !== 1
      ) {
        report.invalidSnapshotCount++;
        addExample('invalid', issueNumber, 'state-event snapshot count, schema, stabilization, JSON, or digest is invalid');
      }
      if (
        row.snapshot_state !== row.current_state ||
        row.issue_updated_at !== row.updated_at ||
        row.issue_node_id !== row.current_issue_node_id
      ) {
        report.metadataMismatchCount++;
        addExample('metadata_mismatch', issueNumber, 'snapshot state or updated_at differs from the issue row');
      }
      const projectedEvents = projectedEventsByIssue.get(issueNumber) ?? [];
      if (
        normalizedEvents == null ||
        JSON.stringify(projectedEvents) !== JSON.stringify(normalizedEvents)
      ) {
        report.projectionMismatchCount++;
        addExample(
          'projection_mismatch',
          issueNumber,
          'projected close/reopen rows do not match the full snapshot event identity',
        );
      }
      const latestEventType = projectedEvents.at(-1)?.type ?? null;
      const latestMismatch =
        (row.current_state === 'open' && latestEventType === 'closed') ||
        (row.current_state === 'closed' && latestEventType === 'reopened') ||
        (row.current_state === 'closed' && totalCount === 0 && row.closed_at != null);
      if (latestMismatch) {
        report.latestStateMismatchCount++;
        addExample('latest_state_mismatch', issueNumber, 'latest state event does not agree with current issue state');
      }
    }
    report.failedCount =
      report.missingSnapshotCount +
      report.invalidSnapshotCount +
      report.metadataMismatchCount +
      report.projectionMismatchCount +
      report.latestStateMismatchCount;
    return report;
  }

  closureDependencySnapshotIntegrityForRelease(tag) {
    const snapshot = this.db.prepare(`
      SELECT *
      FROM release_closure_dependency_snapshots
      WHERE release_tag=?
    `).get(tag);
    const report = {
      tag,
      missingCount: 0,
      schemaMismatchCount: 0,
      membershipMismatchCount: 0,
      referencedIssueMissingCount: 0,
      evidenceInvalidCount: 0,
      identityMismatchCount: 0,
      failedCount: 0,
      snapshot,
      currentIdentity: null,
    };
    const rawClosedIssueNumbers = this.rawClosedDuringReign(tag)
      .map((row) => Number(row.number));
    const proofRows = this.db.prepare(`
      SELECT issue_number, evidence_json
      FROM issue_closure_proofs
      WHERE release_tag=?
      ORDER BY issue_number
    `).all(tag);
    const membership = releaseClosureDependencyMembership(
      rawClosedIssueNumbers,
      proofRows,
    );
    report.evidenceInvalidCount = membership.invalidEvidenceCount;
    if (membership.referencedIssueNumbers.length > 0) {
      report.referencedIssueMissingCount = Number(this.db.prepare(`
        WITH selected(issue_number) AS (
          SELECT CAST(value AS INTEGER) FROM json_each(?)
        )
        SELECT COUNT(*) AS count
        FROM selected
        LEFT JOIN issues issue ON issue.number=selected.issue_number
        WHERE issue.number IS NULL
      `).get(JSON.stringify(membership.referencedIssueNumbers))?.count ?? 0);
    }
    if (!snapshot) {
      report.missingCount = 1;
      report.failedCount =
        report.missingCount +
        report.referencedIssueMissingCount +
        report.evidenceInvalidCount;
      return report;
    }
    if (
      Number(snapshot.schema_version) !== RELEASE_CLOSURE_DEPENDENCY_SNAPSHOT_SCHEMA_VERSION ||
      Number(snapshot.analyzer_version) !== CLOSURE_PROOF_ANALYZER_VERSION
    ) {
      report.schemaMismatchCount = 1;
    }
    try {
      const issueNumbers = JSON.parse(snapshot.issue_numbers_json);
      if (!Array.isArray(issueNumbers)) throw new Error('issue_numbers_json must be an array');
      const normalizedIssueNumbers = [...new Set(issueNumbers.map(Number))]
        .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0)
        .sort((left, right) => left - right);
      if (
        JSON.stringify(normalizedIssueNumbers) !== snapshot.issue_numbers_json ||
        JSON.stringify(normalizedIssueNumbers) !== JSON.stringify(membership.issueNumbers)
      ) {
        report.membershipMismatchCount = 1;
      }
      report.currentIdentity = releaseClosureDependencyIdentity(
        this.db,
        tag,
        membership.issueNumbers,
      );
      if (
        report.currentIdentity.digest !== snapshot.dependency_digest ||
        report.currentIdentity.rowCount !== Number(snapshot.dependency_row_count)
      ) {
        report.identityMismatchCount = 1;
      }
    } catch {
      report.identityMismatchCount = 1;
    }
    report.failedCount =
      report.missingCount +
      report.schemaMismatchCount +
      report.membershipMismatchCount +
      report.referencedIssueMissingCount +
      report.evidenceInvalidCount +
      report.identityMismatchCount;
    return report;
  }

  prReachabilityEvidenceForIssue(tag, issueNumber) {
    return this.db.prepare(`
      SELECT l.issue_number,
               l.pr_repository_name_with_owner,
               l.pr_number,
               l.source,
             l.will_close_target,
             p.merged,
             p.merge_commit_oid,
             p.base_ref_name AS pr_base_ref_name,
             rpr.status,
             rpr.tag_commit_oid,
             rpr.merge_commit_oid AS reachability_merge_commit_oid,
             rpr.base_ref_name AS reachability_base_ref_name,
             rpr.method,
             rpr.evidence_json,
             rpr.checked_at,
             rc.tag_commit_oid AS release_tag_commit_oid
      FROM issue_pr_links l
        JOIN pull_request_fixes p ON p.pr_repository_name_with_owner=l.pr_repository_name_with_owner AND p.pr_number=l.pr_number
        JOIN release_pr_reachability rpr ON rpr.tag=? AND rpr.pr_repository_name_with_owner=l.pr_repository_name_with_owner AND rpr.pr_number=l.pr_number
      LEFT JOIN release_commits rc ON rc.tag=rpr.tag
      WHERE l.issue_number=?
        ORDER BY l.pr_repository_name_with_owner, l.pr_number
    `).all(tag, issueNumber);
  }

  fixCreditProofRowsForIssue(targetTag, predecessorTag, issueNumber) {
    return this.db.prepare(`
      SELECT
        link.pr_repository_name_with_owner,
        link.pr_number,
        group_concat(DISTINCT link.source) AS sources,
        fix.merged,
        fix.merge_commit_oid AS pr_merge_commit_oid,
        fix.base_ref_name AS pr_base_ref_name,
        target.status AS target_status,
        target.tag_commit_oid AS target_tag_commit_oid,
        target.merge_commit_oid AS target_merge_commit_oid,
        target.base_ref_name AS target_base_ref_name,
        target.method AS target_method,
        target.evidence_json AS target_evidence_json,
        target.checked_at AS target_checked_at,
        target_release.tag_commit_oid AS target_release_tag_commit_oid,
        predecessor.status AS predecessor_status,
        predecessor.tag_commit_oid AS predecessor_tag_commit_oid,
        predecessor.merge_commit_oid AS predecessor_merge_commit_oid,
        predecessor.base_ref_name AS predecessor_base_ref_name,
        predecessor.method AS predecessor_method,
        predecessor.evidence_json AS predecessor_evidence_json,
        predecessor.checked_at AS predecessor_checked_at,
        predecessor_release.tag_commit_oid AS predecessor_release_tag_commit_oid
      FROM issue_pr_links link
      LEFT JOIN pull_request_fixes fix
        ON fix.pr_repository_name_with_owner=link.pr_repository_name_with_owner
       AND fix.pr_number=link.pr_number
      LEFT JOIN release_pr_reachability target
        ON target.tag=?
       AND target.pr_repository_name_with_owner=link.pr_repository_name_with_owner
       AND target.pr_number=link.pr_number
      LEFT JOIN release_commits target_release ON target_release.tag=target.tag
      LEFT JOIN release_pr_reachability predecessor
        ON predecessor.tag=?
       AND predecessor.pr_repository_name_with_owner=link.pr_repository_name_with_owner
       AND predecessor.pr_number=link.pr_number
      LEFT JOIN release_commits predecessor_release ON predecessor_release.tag=predecessor.tag
      WHERE link.issue_number=?
        AND ${CREDITED_FIX_LINK_SQL_FOR_LINK}
      GROUP BY link.pr_repository_name_with_owner, link.pr_number
      ORDER BY link.pr_repository_name_with_owner, link.pr_number
    `).all(targetTag, predecessorTag, issueNumber);
  }

  prReachabilityRowsForRelease(tag) {
    return this.db.prepare(`
      SELECT r.*,
             rc.tag_commit_oid AS release_tag_commit_oid,
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
      LEFT JOIN release_commits rc ON rc.tag=r.tag
      WHERE r.tag=?
      ORDER BY r.pr_repository_name_with_owner, r.pr_number
    `).all(tag);
  }

  getReleaseScoreAudit(tag) {
    return this.db.prepare(`
      SELECT *
      FROM release_score_audits
      WHERE release_tag=?
    `).get(tag);
  }
}

export function releaseClosureDependencyMembership(rawClosedIssueNumbers, proofRows) {
  const issueNumbers = new Set(
    rawClosedIssueNumbers
      .map(Number)
      .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0),
  );
  const referencedIssueNumbers = new Set();
  let invalidEvidenceCount = 0;
  for (const row of proofRows) {
    let evidence;
    try {
      evidence = typeof row.evidence_json === 'string'
        ? JSON.parse(row.evidence_json)
        : row.evidence_json;
    } catch {
      invalidEvidenceCount++;
      continue;
    }
    if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
      invalidEvidenceCount++;
      continue;
    }
    for (const issueNumber of closureProofEvidenceIssueReferences(evidence)) {
      issueNumbers.add(issueNumber);
      referencedIssueNumbers.add(issueNumber);
    }
  }
  return {
    issueNumbers: [...issueNumbers].sort((left, right) => left - right),
    referencedIssueNumbers: [...referencedIssueNumbers].sort((left, right) => left - right),
    invalidEvidenceCount,
  };
}

function closureProofEvidenceIssueReferences(evidence) {
  const issueNumbers = new Set();
  const addNumber = (value) => {
    const issueNumber = Number(value);
    if (Number.isInteger(issueNumber) && issueNumber > 0) issueNumbers.add(issueNumber);
  };
  const addNumberArray = (value) => {
    if (Array.isArray(value)) value.forEach(addNumber);
  };
  const addIssueObject = (value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      addNumber(value.number);
    }
  };
  const addIssueObjectArray = (value) => {
    if (Array.isArray(value)) value.forEach(addIssueObject);
  };
  const addTerminalProof = (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    addNumber(value.issueNumber);
    addNumber(value.terminalIssueNumber);
    addNumber(value.sourceIssueNumber);
  };

  addNumberArray(evidence.canonicalIssues);
  addIssueObjectArray(evidence.canonicalIssueDetails);
  if (Array.isArray(evidence.canonicalFixCommitProof)) {
    for (const proof of evidence.canonicalFixCommitProof) {
      if (proof && typeof proof === 'object' && !Array.isArray(proof)) {
        addNumber(proof.sourceIssueNumber);
      }
    }
  }
  const resolution = evidence.canonicalResolution;
  if (resolution && typeof resolution === 'object' && !Array.isArray(resolution)) {
    addNumberArray(resolution.path);
    addNumberArray(resolution.blockingBranch);
    addIssueObject(resolution.terminalIssue);
    addIssueObjectArray(resolution.terminalIssues);
    addIssueObject(resolution.cycleTerminalIssue);
    addTerminalProof(resolution.terminalProof);
    if (Array.isArray(resolution.branches)) {
      for (const branch of resolution.branches) {
        if (!branch || typeof branch !== 'object' || Array.isArray(branch)) continue;
        addNumberArray(branch.path);
        addIssueObject(branch.terminalIssue);
        addTerminalProof(branch.terminalProof);
      }
    }
  }
  return [...issueNumbers].sort((left, right) => left - right);
}

function releaseClosureDependencyIdentity(db, releaseTag, issueNumbers) {
  const selected = [...new Set(issueNumbers)]
    .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0)
    .sort((left, right) => left - right);
  const selectedJson = JSON.stringify(selected);
  const selectedRows = (table, columns, orderBy) => db.prepare(`
    WITH selected(issue_number) AS (
      SELECT CAST(value AS INTEGER) FROM json_each(?)
    )
    SELECT ${columns}
    FROM ${table} row
    JOIN selected ON selected.issue_number=row.issue_number
    ORDER BY ${orderBy}
  `).all(selectedJson);
  const sources = [
    ['release', db.prepare(`
      SELECT
        release.tag, release.published_at, release.prerelease,
        release_commit.tag_commit_oid, release_commit.committed_at, release_commit.fetched_at
      FROM releases release
      LEFT JOIN release_commits release_commit ON release_commit.tag=release.tag
      WHERE release.tag=?
        AND release.catalog_active=1
    `).all(releaseTag)],
    ['issues', db.prepare(`
      WITH selected(issue_number) AS (
        SELECT CAST(value AS INTEGER) FROM json_each(?)
      )
      SELECT
        i.number, i.node_id, i.state, i.title, i.body, i.author_node_id, i.author_type,
        i.created_at, i.updated_at, i.closed_at, i.comments, i.labels, i.revision,
        c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
        c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
        c.confidence, c.rationale, c.classified_at, c.classified_updated_at,
        c.classified_comments_digest, c.prompt_version,
        c.source_identity_json, c.source_identity_digest, c.classification_origin,
        c.raw_model_output, c.provenance_json,
        c.revision AS classification_revision,
        comments.schema_version AS comment_schema_version,
        comments.repository_node_id AS comment_repository_node_id,
        comments.issue_node_id AS comment_issue_node_id,
        comments.issue_author_node_id, comments.issue_author_login,
        comments.issue_author_type,
        comments.comment_count, comments.fetched_comment_count,
        comments.comments_digest, comments.issue_updated_at AS comment_issue_updated_at,
        comments.authority_digest, comments.comments_json,
        comments.stabilization_json, comments.stabilization_identity_digest,
        comments.verified_at AS comment_verified_at,
        comments.revision AS comment_revision,
        state.repository_node_id AS state_repository_node_id,
        state.issue_node_id AS state_issue_node_id,
        state.issue_node_type AS state_issue_node_type,
        state.schema_version AS state_schema_version,
        state.issue_state, state.issue_updated_at AS state_issue_updated_at,
        state.total_count AS state_total_count, state.fetched_count AS state_fetched_count,
        state.events_digest, state.authority_digest AS state_authority_digest,
        state.events_json, state.sweep_count AS state_sweep_count,
        state.stabilized AS state_stabilized,
        state.stabilization_json AS state_stabilization_json,
        state.stabilization_identity_digest AS state_stabilization_identity_digest,
        state.verified_at AS state_verified_at,
        state.revision AS state_revision,
        closure_state.schema_version AS closure_evidence_schema_version,
        closure_state.issue_updated_at AS closure_evidence_issue_updated_at,
        closure_state.comments_digest AS closure_evidence_comments_digest,
        closure_state.checked_at AS closure_evidence_checked_at
      FROM selected
      LEFT JOIN issues i ON i.number=selected.issue_number
      LEFT JOIN classifications c ON c.issue_number=selected.issue_number
      LEFT JOIN issue_comment_snapshots comments ON comments.issue_number=selected.issue_number
      LEFT JOIN issue_state_event_snapshots state ON state.issue_number=selected.issue_number
      LEFT JOIN issue_closure_evidence_state closure_state ON closure_state.issue_number=selected.issue_number
      ORDER BY selected.issue_number
    `).all(selectedJson)],
    ['label_events', selectedRows(
      'issue_label_events',
      `row.issue_number, row.issue_node_id, row.event_id, row.action, row.label_name,
       row.actor_node_id, row.actor_login, row.actor_type, row.created_at, row.raw_json,
       row.fetched_at`,
      'row.issue_number, row.created_at, row.event_id',
    )],
    ['label_snapshots', selectedRows(
      'issue_label_snapshots',
      'row.issue_number, row.issue_node_id, row.snapshot_at, row.labels_json, row.fetched_at',
      'row.issue_number, row.snapshot_at',
    )],
    ['closure_events', selectedRows(
      'issue_closure_events',
      `row.issue_number, row.issue_node_id, row.event_id, row.closed_at,
       row.connection_ordinal, row.actor_node_id, row.actor_login, row.actor_type,
       row.state_reason,
       row.closer_type, row.closer_number, row.closer_node_id, row.closer_oid,
       row.raw_json, row.fetched_at`,
      'row.issue_number, unixepoch(row.closed_at), row.connection_ordinal, row.event_id',
    )],
    ['reopen_events', selectedRows(
      'issue_reopen_events',
      `row.issue_number, row.issue_node_id, row.event_id, row.reopened_at,
       row.connection_ordinal, row.actor_node_id, row.actor_login, row.actor_type,
       row.raw_json, row.fetched_at`,
      'row.issue_number, unixepoch(row.reopened_at), row.connection_ordinal, row.event_id',
    )],
    ['pr_links', selectedRows(
      'issue_pr_links',
      `row.issue_number, row.issue_node_id, row.pr_repository_name_with_owner,
       row.pr_number, row.pr_node_id, row.source, row.source_node_id,
       row.will_close_target, row.referenced_at, row.source_comment_database_id,
       row.source_comment_url, row.raw_json, row.fetched_at`,
      'row.issue_number, row.pr_repository_name_with_owner, row.pr_number, row.source',
    )],
    ['commit_references', selectedRows(
      'issue_commit_references',
      `row.issue_number, row.issue_node_id, row.event_id, row.commit_oid,
       row.commit_message_headline, row.commit_repository_name_with_owner,
       row.is_cross_repository, row.is_direct_reference, row.referenced_at,
       row.actor_node_id, row.actor_login, row.raw_json, row.fetched_at`,
      'row.issue_number, row.event_id',
    )],
    ['pull_requests', db.prepare(`
      WITH selected(issue_number) AS (
        SELECT CAST(value AS INTEGER) FROM json_each(?)
      ),
      keys AS (
        SELECT DISTINCT link.pr_repository_name_with_owner, link.pr_number
        FROM issue_pr_links link
        JOIN selected ON selected.issue_number=link.issue_number
      )
      SELECT
        fix.pr_repository_owner, fix.pr_repository_name,
        fix.pr_repository_name_with_owner, fix.pr_number,
        fix.node_id, fix.repository_node_id, fix.title, fix.url,
        fix.state, fix.merged, fix.merged_at, fix.merge_commit_oid,
        fix.base_ref_name, fix.raw_json, fix.fetched_at
      FROM pull_request_fixes fix
      JOIN keys
        ON keys.pr_repository_name_with_owner=fix.pr_repository_name_with_owner
       AND keys.pr_number=fix.pr_number
      ORDER BY fix.pr_repository_name_with_owner, fix.pr_number
    `).all(selectedJson)],
    ['reachability', db.prepare(`
      WITH selected(issue_number) AS (
        SELECT CAST(value AS INTEGER) FROM json_each(?)
      ),
      keys AS (
        SELECT DISTINCT link.pr_repository_name_with_owner, link.pr_number
        FROM issue_pr_links link
        JOIN selected ON selected.issue_number=link.issue_number
      )
      SELECT
        reachability.tag, reachability.pr_repository_owner,
        reachability.pr_repository_name, reachability.pr_repository_name_with_owner,
        reachability.pr_number, reachability.tag_commit_oid,
        reachability.merge_commit_oid, reachability.base_ref_name,
        reachability.status, reachability.method,
        reachability.evidence_json, reachability.checked_at
      FROM release_pr_reachability reachability
      JOIN keys
        ON keys.pr_repository_name_with_owner=reachability.pr_repository_name_with_owner
       AND keys.pr_number=reachability.pr_number
      WHERE reachability.tag=?
      ORDER BY reachability.pr_repository_name_with_owner, reachability.pr_number
    `).all(selectedJson, releaseTag)],
    ['cross_release_proofs', db.prepare(`
      WITH selected(issue_number) AS (
        SELECT CAST(value AS INTEGER) FROM json_each(?)
      )
      SELECT
        proof.release_tag, proof.issue_number, proof.status,
        proof.summary, proof.evidence_json
      FROM issue_closure_proofs proof
      JOIN selected ON selected.issue_number=proof.issue_number
      WHERE proof.release_tag != ?
      ORDER BY proof.issue_number, proof.release_tag
    `).all(selectedJson, releaseTag)],
  ];
  const hash = createHash('sha256');
  hash.update(JSON.stringify([
    'release_closure_dependency_identity',
    RELEASE_CLOSURE_DEPENDENCY_SNAPSHOT_SCHEMA_VERSION,
    releaseTag,
    selected,
  ]));
  let rowCount = 0;
  for (const [source, rows] of sources) {
    rowCount += rows.length;
    hash.update('\n');
    hash.update(JSON.stringify([source, rows]));
  }
  return {
    schemaVersion: RELEASE_CLOSURE_DEPENDENCY_SNAPSHOT_SCHEMA_VERSION,
    releaseTag,
    issueNumbers: selected,
    rowCount,
    digest: hash.digest('hex'),
  };
}

function releaseLabelCutoff(rel, now = null) {
  if (!rel?.published_at) return null;
  if (rel.hours_to_next_stable == null) {
    const millis = typeof now === 'string' ? Date.parse(now) : typeof now === 'number' ? now : NaN;
    return Number.isFinite(millis) ? new Date(millis).toISOString() : null;
  }
  const publishedAt = Date.parse(rel.published_at);
  if (!Number.isFinite(publishedAt)) return null;
  return new Date(publishedAt + Number(rel.hours_to_next_stable) * 3_600_000).toISOString();
}

function parseLabels(raw) {
  try {
    const value = raw ? JSON.parse(raw) : [];
    return Array.isArray(value) ? value.filter((label) => typeof label === 'string') : [];
  } catch {
    return [];
  }
}

function labelsForIssueAt(db, issueNumber, fallbackLabels, cutoff, options = {}) {
  const eventCount = Number(db.prepare(`
    SELECT COUNT(*) AS count FROM issue_label_events WHERE issue_number=?
  `).get(issueNumber)?.count ?? 0);
  if (eventCount === 0) {
    if (options.useSnapshotWhenNoEvents && cutoff) {
      const snapshot = db.prepare(`
        SELECT labels_json
        FROM issue_label_snapshots
        WHERE issue_number=?
          AND snapshot_at <= ?
        ORDER BY snapshot_at DESC
        LIMIT 1
      `).get(issueNumber, cutoff);
      const labels = parseLabels(snapshot?.labels_json);
      if (labels.length) return labels;
    }
    return options.useFallbackWhenNoEvents === false ? [] : fallbackLabels;
  }
  const labels = new Set();
  const rows = db.prepare(`
    SELECT action, label_name
    FROM issue_label_events
    WHERE issue_number=?
      AND (? IS NULL OR created_at <= ?)
    ORDER BY created_at ASC, event_id ASC
  `).all(issueNumber, cutoff, cutoff);
  for (const row of rows) {
    if (row.action === 'labeled') labels.add(row.label_name);
    else if (row.action === 'unlabeled') labels.delete(row.label_name);
  }
  return [...labels];
}

function projectedIssueStateEventsForIssues(db, issueNumbers) {
  const selected = [...new Set(issueNumbers)]
    .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0)
    .sort((left, right) => left - right);
  const byIssue = new Map(selected.map((issueNumber) => [issueNumber, []]));
  if (selected.length === 0) return byIssue;
  const rows = db.prepare(`
    WITH selected(issue_number) AS (
      SELECT CAST(value AS INTEGER) FROM json_each(?)
    )
    SELECT issue_number, event_id, event_node_type, event_type, occurred_at,
           connection_ordinal, actor_node_id, actor_login, actor_type, state_reason,
           closer_node_id, closer_type, closer_number, closer_oid
    FROM (
      SELECT
        close_event.issue_number,
        close_event.event_id,
        'ClosedEvent' AS event_node_type,
        'closed' AS event_type,
        close_event.closed_at AS occurred_at,
        close_event.connection_ordinal,
        close_event.actor_node_id,
        close_event.actor_login,
        close_event.actor_type,
        close_event.state_reason,
        close_event.closer_node_id,
        close_event.closer_type,
        close_event.closer_number,
        close_event.closer_oid
      FROM issue_closure_events close_event
      JOIN selected ON selected.issue_number=close_event.issue_number
      UNION ALL
      SELECT
        reopen_event.issue_number,
        reopen_event.event_id,
        'ReopenedEvent' AS event_node_type,
        'reopened' AS event_type,
        reopen_event.reopened_at AS occurred_at,
        reopen_event.connection_ordinal,
        reopen_event.actor_node_id,
        reopen_event.actor_login,
        reopen_event.actor_type,
        NULL AS state_reason,
        NULL AS closer_node_id,
        NULL AS closer_type,
        NULL AS closer_number,
        NULL AS closer_oid
      FROM issue_reopen_events reopen_event
      JOIN selected ON selected.issue_number=reopen_event.issue_number
    )
    ORDER BY issue_number, unixepoch(occurred_at), connection_ordinal, event_id
  `).all(JSON.stringify(selected));
  for (const row of rows) {
    const issueNumber = Number(row.issue_number);
    const events = byIssue.get(issueNumber) ?? [];
    events.push({
      eventId: row.event_id,
      eventNodeType: row.event_node_type,
      type: row.event_type,
      occurredAt: row.occurred_at,
      connectionOrdinal: Number(row.connection_ordinal),
      actorNodeId: row.actor_node_id ?? null,
      actorLogin: row.actor_login ?? null,
      actorType: row.actor_type ?? null,
      stateReason: row.state_reason ?? null,
      closerNodeId: row.closer_node_id ?? null,
      closerType: row.closer_type ?? null,
      closerNumber: row.closer_number == null ? null : Number(row.closer_number),
      closerOid: row.closer_oid ?? null,
    });
    byIssue.set(issueNumber, events);
  }
  for (const [issueNumber, events] of byIssue) {
    try {
      byIssue.set(issueNumber, normalizeIssueStateEvents(events));
    } catch {
      byIssue.set(issueNumber, null);
    }
  }
  return byIssue;
}

function parseJson(value, fallback) {
  try {
    return value == null ? fallback : JSON.parse(value);
  } catch {
    return fallback;
  }
}

function sourceManifestProblems(value) {
  return scoreSourceIdentityManifestProblems(parseJson(value, null));
}

function scoreAuditSemanticContent(row) {
  return JSON.stringify([
    row.release_tag,
    row.scored_at,
    row.score_model_version,
    Number(row.prompt_version),
    row.final_score ?? null,
    row.status,
    row.band,
    Number(row.recommended),
    row.input_json,
    row.components_json ?? null,
    row.issue_evidence_json,
    row.gate_evidence_json,
    row.source_identity_json,
    row.authority_run_id ?? null,
  ]);
}
