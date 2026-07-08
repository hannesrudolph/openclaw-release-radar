import { createHash } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import {
  assessDataFreshnessHealth,
  assessDurableIngestionEvidenceFailureHealth,
  assessIssueCrawlHealth,
} from './lib/doctor-health.mjs';
import {
  SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  scoreSourceIdentityForDb,
  scoreSourceIdentityManifestDigest,
  scoreSourceIdentityManifestProblems,
} from '../src/lib/scoreSourceIdentity.ts';
import {
  CLOSURE_PROOF_ANALYZER_VERSION,
  RAW_CLOSURE_EVIDENCE_SCHEMA_VERSION,
} from '../src/lib/analysisVersions.ts';
import {
  ADVISORY_SNAPSHOT_META_KEY,
  ADVISORY_SNAPSHOT_V2_META_KEY,
  COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
  advisorySnapshotCompletenessProblems,
  advisorySnapshotContentHash,
  advisorySnapshotRowProblems,
  canonicalCompoundAdvisoryRangeRowJson,
  canonicalCompoundAdvisorySnapshotJson,
  compoundAdvisoryReceiptBindingProblems,
  compoundAdvisoryScoreRows,
  compoundAdvisorySnapshotIntegrityProblems,
  compoundAdvisorySnapshotLedgerContentHash,
  compoundAdvisorySnapshotPublicationAuthorizations,
  compoundAdvisorySnapshotRowContentHash,
} from '../src/lib/advisorySnapshot.ts';
import { config } from '../src/config.ts';
import {
  PROMPT_VERSION,
  rawClassificationStorageProblems,
} from '../src/lib/llm.ts';
import { REC_THRESHOLD, SCORE_MODEL_VERSION } from '../src/lib/score.ts';
import {
  buildAdvisorySnapshotValidationEvidence,
  buildCompoundAdvisorySnapshotValidationEvidence,
  RELEASE_VALIDATION_OPPORTUNITIES,
  releaseCatalogAttestationProblems,
  releaseValidationScoreCommitTimingProblems,
  releaseValidationForecastTiming,
  validateReleaseValidationLedgerIntegrity,
} from '../src/lib/releaseValidation.ts';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from '../src/lib/scoreHistoryLedger.ts';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  assertAuthoritativeIssueStateEvents,
  issueStateEventSweepDigest,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
  parseIssueStateEventStabilizationIdentity,
} from '../src/lib/stateEventSnapshot.ts';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
} from '../src/lib/commentEvidence.ts';
import { validateReachabilityEvidence } from '../src/lib/reachabilityEvidence.ts';
import {
  canonicalJson as canonicalOperationJson,
  verifyOperationReceiptLedger,
  verifyOperationReceiptSemanticLinks,
} from '../src/lib/operationReceipts.ts';
import {
  releaseArtifactObservationFromStorageRecord,
  releaseArtifactReceiptFromStorageRecord,
} from '../src/lib/releaseArtifactReceipt.ts';
import {
  issueCatalogSnapshotLedgerProblems,
  issueCatalogSnapshotProblems,
  issueCatalogSnapshotResumeProblems,
  parseIssueCatalogIssueJson,
} from '../src/lib/issueCatalogSnapshot.ts';
import {
  projectReleaseCatalogActiveRows,
  verifyReleaseCatalogCaptureReceiptLedger,
} from '../src/lib/releaseCatalogReceipt.ts';
import {
  summarizeReleaseValidationProof,
} from '../src/lib/releaseValidationProofSummary.ts';
import {
  APPEND_ONLY_TRIGGER_SPECS,
  IMMUTABLE_LEDGER_TABLES,
  unconditionalAbortTriggerShape,
  undeclaredAppendOnlyTriggerShapes,
} from './lib/database-schema-manifest.mjs';

const SCHEMA_VERSION = 1;
const RELEASE_CLOSURE_DEPENDENCY_SNAPSHOT_SCHEMA_VERSION = 2;
const RELEASE_CATALOG_PROBLEM_LIMIT = 12;
const RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT = 6;
const RELEASE_CATALOG_FAILURE_EXAMPLE_LIMIT = 3;
const TRACKED_PR_REPOSITORY = `${process.env.GITHUB_OWNER ?? 'openclaw'}/${process.env.GITHUB_REPO ?? 'openclaw'}`;
const REQUIRED_SCORE_SOURCE_NAMES = [
  'issue_state_event_snapshots',
  'release_closure_dependency_snapshots',
];
const ADVISORY_SNAPSHOT_HISTORY_COLUMNS = [
  'id',
  'captured_at',
  'row_count',
  'content_hash',
];
const ADVISORY_SNAPSHOT_ROW_COLUMNS = [
  'snapshot_id',
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
];
const ADVISORY_SNAPSHOT_V2_HISTORY_COLUMNS = [
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
];
const ADVISORY_SNAPSHOT_V2_ROW_COLUMNS = [
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
];
const ISSUE_CATALOG_SNAPSHOT_HEADER_COLUMNS = [
  'id',
  'snapshot_id',
  'schema_version',
  'row_schema_version',
  'repository',
  'source',
  'source_order',
  'captured_at',
  'boundary_total_count',
  'observed_total_count',
  'post_boundary_growth_count',
  'terminal_node_id',
  'terminal_issue_number',
  'terminal_created_at',
  'fetched_count',
  'unique_count',
  'page_count',
  'pages_fetched',
  'sweep_count',
  'membership_digest',
  'content_digest',
  'last_request_cursor',
  'row_count',
  'row_schema_digest',
  'rows_content_hash',
  'previous_content_hash',
  'content_hash',
];
const ISSUE_CATALOG_SNAPSHOT_ROW_COLUMNS = [
  'snapshot_id',
  'source_ordinal',
  'issue_number',
  'node_id',
  'issue_json',
  'content_hash',
];
const ISSUE_CATALOG_SNAPSHOT_CONSUMPTION_COLUMNS = [
  'id',
  'schema_version',
  'snapshot_id',
  'repository',
  'run_id',
  'consumed_at',
  'processed_row_count',
  'processed_page_count',
  'snapshot_content_hash',
  'previous_content_hash',
  'content_hash',
];
const RELEASE_VALIDATION_PROOF_RECORD_TABLES = [
  {
    key: 'epochs',
    table: 'release_validation_proof_epochs',
    idColumn: 'proof_epoch_id',
    idField: 'proofEpochId',
  },
  {
    key: 'retirements',
    table: 'release_validation_proof_epoch_retirements',
    idColumn: 'retirement_id',
    idField: 'retirementId',
  },
  {
    key: 'policies',
    table: 'release_validation_policies',
    idColumn: 'policy_id',
    idField: 'policyId',
  },
  {
    key: 'cohorts',
    table: 'release_validation_cohorts',
    idColumn: 'cohort_id',
    idField: 'cohortId',
  },
  {
    key: 'catalogObservations',
    table: 'release_validation_catalog_observations',
    idColumn: 'observation_id',
    idField: 'observationId',
  },
  {
    key: 'catalogMembers',
    table: 'release_validation_catalog_members',
    idColumn: 'member_id',
    idField: 'memberId',
  },
  {
    key: 'catalogReconciliations',
    table: 'release_validation_catalog_reconciliations',
    idColumn: 'reconciliation_id',
    idField: 'reconciliationId',
  },
  {
    key: 'catalogReconciliationRows',
    table: 'release_validation_catalog_reconciliation_rows',
    idColumn: 'reconciliation_row_id',
    idField: 'reconciliationRowId',
  },
  {
    key: 'obligations',
    table: 'release_validation_obligations',
    idColumn: 'obligation_id',
    idField: 'obligationId',
  },
  {
    key: 'splitAssignments',
    table: 'release_validation_split_assignments',
    idColumn: 'assignment_id',
    idField: 'assignmentId',
  },
  {
    key: 'forecasts',
    table: 'release_validation_forecasts_v2',
    idColumn: 'forecast_id',
    idField: 'forecastId',
  },
  {
    key: 'outcomes',
    table: 'release_validation_outcomes_v2',
    idColumn: 'outcome_id',
    idField: 'outcomeId',
  },
  {
    key: 'observationBatches',
    table: 'release_validation_proof_observation_batches',
    idColumn: 'batch_id',
    idField: 'batchId',
  },
  {
    key: 'evaluationReceipts',
    table: 'release_validation_evaluation_receipts',
    idColumn: 'evaluation_id',
    idField: 'evaluationId',
  },
  {
    key: 'promotionReceipts',
    table: 'release_validation_promotion_receipts',
    idColumn: 'promotion_id',
    idField: 'promotionId',
  },
];
const CORE_TABLES = [...new Set([
  'meta',
  'releases',
  'issues',
  'classifications',
  'release_score_audits',
  'release_score_audit_history',
  'release_score_audit_history_runs',
  'release_validation_forecasts',
  'release_validation_opportunity_enrollments',
  'release_validation_outcome_observations',
  'release_validation_observation_batches',
  'release_commits',
  'issue_comment_snapshots',
  'issue_closure_evidence_state',
  'issue_closure_proofs',
  'issue_closure_events',
  'issue_reopen_events',
  'issue_state_event_snapshots',
  'issue_pr_links',
  'issue_commit_references',
  'pull_request_fixes',
  'release_pr_reachability',
  'release_closure_dependency_snapshots',
  'issue_label_events',
  'issue_label_snapshots',
  'advisories',
  'advisory_snapshot_history',
  'advisory_snapshot_rows',
  'advisory_snapshot_v2_history',
  'advisory_snapshot_v2_rows',
  'issue_catalog_snapshots',
  'issue_catalog_snapshot_rows',
  'issue_catalog_snapshot_consumptions',
  'refresh_leases',
  'refresh_operation_attempts',
  'refresh_operation_stage_events',
  'refresh_capture_receipts',
  ...RELEASE_VALIDATION_PROOF_RECORD_TABLES.map(({ table }) => table),
  'ingestion_evidence_failures',
  'comparison_snapshots',
  'comparison_releases',
  ...IMMUTABLE_LEDGER_TABLES,
])];

export function buildDoctorReport({
  dbPath = process.env.DB_PATH ?? './data/radar.db',
  now = new Date(),
  maxIssueLagHours = 48,
  failOnWarnings = false,
  sourceIdentityForDb = scoreSourceIdentityForDb,
} = {}) {
  const resolvedPath = resolve(dbPath);
  const failures = [];
  const warnings = [];
  const legacyFindings = [];
  const report = {
    schemaVersion: SCHEMA_VERSION,
    ok: false,
    generatedAt: now.toISOString(),
    db: {
      path: resolvedPath,
      exists: existsSync(resolvedPath),
      sizeBytes: null,
      readOnly: true,
    },
    strict: {
      failOnWarnings: failOnWarnings === true,
      maxIssueLagHours,
    },
    tables: {},
    latestScoredStable: null,
    recommendation: null,
    scorePersistence: null,
    scoreHistory: null,
    freshness: null,
    ingestion: null,
    coverage: null,
    classifications: null,
    stateSnapshots: null,
    closureProof: null,
    reachability: null,
    comparison: null,
    validation: null,
    advisorySnapshots: null,
    issueCatalogSnapshots: null,
    operationReceipts: null,
    releaseCatalogProvenance: null,
    validationProof: null,
    appendOnlyTriggers: null,
    performance: null,
    legacyFindings,
    warnings,
    failures,
  };

  if (!report.db.exists) {
    failures.push(`database not found: ${resolvedPath}`);
    return finish(report, { failOnWarnings });
  }

  report.db.sizeBytes = statSync(resolvedPath).size;
  if (report.db.sizeBytes <= 0) failures.push(`database is empty: ${resolvedPath}`);

  const db = new DatabaseSync(resolvedPath, { readOnly: true });
  try {
    db.exec('PRAGMA query_only = ON');
    for (const table of CORE_TABLES) {
      report.tables[table] = tableSummary(db, table);
      if (!report.tables[table].present) failures.push(`missing core table ${table}`);
    }
    report.performance = issueWindowPerformanceSummary(db);
    if (report.performance.failedCount > 0) {
      failures.push(
        `issue release-window index verification failed ` +
        `(missing=${report.performance.missingIndexCount}, ` +
        `unused=${report.performance.unusedPlanCount})`,
      );
    }
    report.appendOnlyTriggers = appendOnlyTriggerSummary(db);
    if (report.appendOnlyTriggers.failedCount > 0) {
      failures.push(
        `append-only trigger verification failed ` +
        `(missing=${report.appendOnlyTriggers.missingCount}, ` +
        `shape=${report.appendOnlyTriggers.shapeFailureCount}, ` +
        `behavior=${report.appendOnlyTriggers.behaviorFailureCount}, ` +
        `unexpected=${report.appendOnlyTriggers.unexpectedCount})`,
      );
    }
    report.operationReceipts = operationReceiptSummary(db, now);
    if (report.operationReceipts.failedCount > 0) {
      failures.push(
        `refresh operation receipt integrity failed for ` +
        `${report.operationReceipts.failedCount} item(s) ` +
        `(schema=${report.operationReceipts.schemaFailureCount}, ` +
        `hashChain=${report.operationReceipts.hashChainFailureCount}, ` +
        `semantics=${report.operationReceipts.semanticFailureCount}, ` +
        `links=${report.operationReceipts.linkFailureCount})`,
      );
    }
    report.releaseCatalogProvenance = releaseCatalogProvenanceSummary(db);
    if (report.releaseCatalogProvenance.failedCount > 0) {
      const examples = report.releaseCatalogProvenance.problems
        .slice(0, RELEASE_CATALOG_FAILURE_EXAMPLE_LIMIT)
        .join('; ');
      failures.push(
        `release catalog provenance verification failed ` +
        `(schema=${report.releaseCatalogProvenance.schemaFailureCount}, ` +
        `projection=${report.releaseCatalogProvenance.projectionProblemCount}, ` +
        `ledger=${report.releaseCatalogProvenance.ledgerProblemCount}, ` +
        `current=${report.releaseCatalogProvenance.currentProblemCount})` +
        (examples ? `: ${examples}` : ''),
      );
    }
    report.validationProof = canonicalValidationProofSummary(db, now);
    if (
      report.validationProof.status === 'invalid' ||
      report.validationProof.status === 'ambiguous_active_epochs' ||
      report.validationProof.status === 'measurable_but_failed'
    ) {
      failures.push(
        `canonical release validation proof is unhealthy ` +
        `(status=${report.validationProof.status}, ` +
        `problems=${report.validationProof.problems.length})`,
      );
    } else if (
      report.validationProof.status === 'uninitialized' ||
      report.validationProof.status === 'no_active_epoch' ||
      report.validationProof.status === 'insufficient'
    ) {
      warnings.push(
        `canonical release validation proof is not production-ready ` +
        `(status=${report.validationProof.status})`,
      );
    }
    report.advisorySnapshots = advisorySnapshotSummary(db);
    if (report.advisorySnapshots.legacySemanticWarningCount > 0) {
      const examples = report.advisorySnapshots.examples.legacySemanticProblems
        .slice(0, 3)
        .map((problem) =>
          `snapshot ${problem.snapshotId} ${problem.advisoryKey || 'unknown'} ${problem.detail}`)
        .join('; ');
      legacyFindings.push(
        `${report.advisorySnapshots.legacySemanticWarningCount} semantic incompatibility item(s) ` +
        `across ${report.advisorySnapshots.legacySemanticSnapshotCount} immutable historical ` +
        `advisory snapshot(s) are retained as legacy audit warnings and do not affect the current tip` +
        (examples ? `: ${examples}` : ''),
      );
    }
    if (report.advisorySnapshots.failedCount > 0) {
      failures.push(`advisory snapshot integrity failed for ${report.advisorySnapshots.failedCount} item(s) ` +
        `(schema=${report.advisorySnapshots.schemaFailureCount}, ` +
        `v2=${report.advisorySnapshots.v2.failedCount}, ` +
        `rowCount=${report.advisorySnapshots.rowCountMismatchCount}, ` +
        `contentHash=${report.advisorySnapshots.contentHashMismatchCount}, ` +
        `orphans=${report.advisorySnapshots.orphanRowCount}, ` +
        `malformedRows=${report.advisorySnapshots.malformedRowCount}, ` +
        `package=${report.advisorySnapshots.packageMismatchCount}, ` +
        `advisoryKey=${report.advisorySnapshots.advisoryKeyMismatchCount}, ` +
        `duplicateIdentity=${report.advisorySnapshots.duplicateCanonicalIdentityCount}, ` +
        `range=${report.advisorySnapshots.malformedRangeCount}, ` +
        `patch=${report.advisorySnapshots.patchMetadataFailureCount}, ` +
        `latestSemantic=${report.advisorySnapshots.latestSemanticFailureCount}, ` +
        `currentSemantic=${report.advisorySnapshots.currentSemanticFailureCount}, ` +
        `currentStructural=${report.advisorySnapshots.currentStructuralFailureCount}, ` +
        `legacySemanticWarnings=${report.advisorySnapshots.legacySemanticWarningCount}, ` +
        `completeness=${report.advisorySnapshots.completenessProblemCount}, ` +
        `latest=${report.advisorySnapshots.latestSnapshotMismatchCount})`);
    }
    report.issueCatalogSnapshots = issueCatalogSnapshotSummary(db, now);
    if (report.issueCatalogSnapshots.failedCount > 0) {
      failures.push(
        `issue catalog snapshot integrity failed for ` +
        `${report.issueCatalogSnapshots.failedCount} item(s) ` +
        `(schema=${report.issueCatalogSnapshots.schemaFailureCount}, ` +
        `ledger=${report.issueCatalogSnapshots.ledgerFailureCount}, ` +
        `consumption=${report.issueCatalogSnapshots.consumptionFailureCount}, ` +
        `crawlLink=${report.issueCatalogSnapshots.crawlLinkFailureCount}, ` +
        `orphans=${report.issueCatalogSnapshots.orphanRowCount})`,
      );
    }
    report.scoreHistory = scoreHistoryLedgerSummary(db);
    if (report.scoreHistory.failedCount > 0) {
      failures.push(`score history ledger integrity failed for ${report.scoreHistory.failedCount} item(s) ` +
        `(schema=${report.scoreHistory.schemaFailureCount}, ` +
        `missingSeals=${report.scoreHistory.missingSealCount}, ` +
        `orphanSeals=${report.scoreHistory.orphanSealCount}, ` +
        `chain=${report.scoreHistory.chainFailureCount}, ` +
        `rowCount=${report.scoreHistory.rowCountMismatchCount}, ` +
        `recordedAt=${report.scoreHistory.recordedAtMismatchCount}, ` +
        `rowsHash=${report.scoreHistory.rowsContentHashMismatchCount}, ` +
        `sealHash=${report.scoreHistory.contentHashMismatchCount}, ` +
        `authorityBinding=${report.scoreHistory.authorityRunBindingFailureCount}, ` +
        `canonicalTimestamps=${report.scoreHistory.canonicalTimestampFailureCount}, ` +
        `currentManifest=${report.scoreHistory.currentTipSourceManifestFailureCount}, ` +
        `currentMissing=${report.scoreHistory.currentAuditHistoryMissingCount}, ` +
        `currentMismatch=${report.scoreHistory.currentAuditHistoryMismatchCount}, ` +
        `currentExtra=${report.scoreHistory.currentHistoryAuditExtraCount})`);
    }
    for (const table of ['releases', 'issues', 'classifications', 'release_score_audits']) {
      if ((report.tables[table]?.count ?? 0) <= 0) failures.push(`core table ${table} has no rows`);
    }

    report.recommendation = recommendationSummary(db);
    const expectedRecommendedCount = report.recommendation.qualifyingStableCount > 0 ? 1 : 0;
    if (report.recommendation.recommendedCount !== expectedRecommendedCount) {
      failures.push(
        expectedRecommendedCount === 1
          ? `expected exactly one recommended scored stable release, found ${report.recommendation.recommendedCount}`
          : `expected zero recommended scored stable releases because none qualify, found ${report.recommendation.recommendedCount}`,
      );
    }

    const latest = latestScoredStable(db);
    report.latestScoredStable = latest;
    if (!latest) {
      failures.push('no audited stable release found');
      return finish(report, { failOnWarnings });
    }
    if (!latest.auditPresent) failures.push(`${latest.tag}: missing release_score_audits row`);
    if (latest.finalScore !== latest.auditFinalScore) {
      failures.push(`${latest.tag}: release final_score (${latest.finalScore}) does not match audit final_score (${latest.auditFinalScore})`);
    }
    if (latest.scoredAt !== latest.auditScoredAt) {
      failures.push(`${latest.tag}: release scored_at (${latest.scoredAt}) does not match audit scored_at (${latest.auditScoredAt})`);
    }

    report.scorePersistence = scorePersistenceSummary(db, report.recommendation);
    if (!report.scorePersistence.sourceIdentityColumnPresent) {
      failures.push('release_score_audits.source_identity_json is missing; start the writable app once to run migrations, then rescore');
    }
    if (!report.scorePersistence.present) {
      failures.push('score persistence metadata is missing');
    } else if (!report.scorePersistence.valid) {
      failures.push('score persistence metadata is malformed');
    } else {
      if (report.scorePersistence.maxReleaseScoredAt !== report.scorePersistence.meta.maxScoredAt) {
        failures.push(`score persistence maxScoredAt (${report.scorePersistence.meta.maxScoredAt}) does not match release rows (${report.scorePersistence.maxReleaseScoredAt})`);
      }
      if (report.scorePersistence.maxAuditScoredAt !== report.scorePersistence.meta.maxScoredAt) {
        failures.push(`score persistence maxScoredAt (${report.scorePersistence.meta.maxScoredAt}) does not match audit rows (${report.scorePersistence.maxAuditScoredAt})`);
      }
      if (report.scorePersistence.scoredStableCount !== report.scorePersistence.auditedStableCount) {
        failures.push(`score persistence scored stable row count (${report.scorePersistence.scoredStableCount}) does not match audited stable rows (${report.scorePersistence.auditedStableCount})`);
      }
      if (JSON.stringify(report.scorePersistence.scoredStableTags) !== JSON.stringify(report.scorePersistence.meta.releaseTags ?? [])) {
        failures.push('score persistence releaseTags do not match scored stable release rows');
      }
      if (report.scorePersistence.auditedStableCount !== report.scorePersistence.meta.scoredReleaseCount) {
        failures.push(`score persistence scoredReleaseCount (${report.scorePersistence.meta.scoredReleaseCount}) does not match audited stable rows (${report.scorePersistence.auditedStableCount})`);
      }
      if (JSON.stringify(report.scorePersistence.auditedStableTags) !== JSON.stringify(report.scorePersistence.meta.releaseTags ?? [])) {
        failures.push('score persistence releaseTags do not match audited stable rows');
      }
      if (report.scorePersistence.auditModelVersions.length !== 1 ||
        report.scorePersistence.auditModelVersions[0] !== report.scorePersistence.meta.scoreModelVersion) {
        failures.push('score persistence scoreModelVersion does not match audited stable rows');
      }
      if (report.scorePersistence.auditPromptVersions.length !== 1 ||
        report.scorePersistence.auditPromptVersions[0] !== report.scorePersistence.meta.promptVersion) {
        failures.push('score persistence promptVersion does not match audited stable rows');
      }
      if (report.scorePersistence.meta.historyRunId !== report.scoreHistory.latestRunId) {
        failures.push(
          `score persistence historyRunId (${report.scorePersistence.meta.historyRunId ?? null}) ` +
          `does not match score history tip (${report.scoreHistory.latestRunId ?? null})`,
        );
      }
      if (report.scorePersistence.meta.historyRunContentHash !== report.scoreHistory.latestContentHash) {
        failures.push(
          `score persistence historyRunContentHash does not match score history tip`,
        );
      }
      const currentReceiptProblems = currentScoreReceiptProblems(
        db,
        report.scorePersistence.meta,
      );
      report.operationReceipts.currentScoreTipFailureCount = currentReceiptProblems.length;
      report.operationReceipts.problems.push(...currentReceiptProblems);
      report.operationReceipts.failedCount += currentReceiptProblems.length;
      if (currentReceiptProblems.length > 0) {
        failures.push(
          `current score tip receipt authorization failed: ` +
          currentReceiptProblems.slice(0, 3).join('; '),
        );
      }
      const recommendedTag = report.recommendation.recommended?.[0]?.tag ?? null;
      if ((report.scorePersistence.meta.recommendedTag ?? null) !== recommendedTag) {
        failures.push(`score persistence recommendedTag (${report.scorePersistence.meta.recommendedTag ?? null}) does not match recommendation (${recommendedTag})`);
      }
      if (report.scorePersistence.missingAuditTags.length > 0) {
        failures.push(`score persistence missing release_score_audits rows for scored stable releases: ${report.scorePersistence.missingAuditTags.join(', ')}`);
      }
      if (report.scorePersistence.orphanAuditTags.length > 0) {
        failures.push(`score persistence has audit rows without scored stable release rows: ${report.scorePersistence.orphanAuditTags.join(', ')}`);
      }
      if (report.scorePersistence.releaseAuditMismatches.length > 0) {
        const examples = report.scorePersistence.releaseAuditMismatches
          .slice(0, 5)
          .map((row) => `${row.tag} ${row.field} release=${JSON.stringify(row.release)} audit=${JSON.stringify(row.audit)}`)
          .join('; ');
        failures.push(`score persistence release/audit field mismatch: ${examples}`);
      }
      if (report.scorePersistence.classificationCoverageMismatches.length > 0) {
        const examples = report.scorePersistence.classificationCoverageMismatches
          .slice(0, 5)
          .map((row) => `${row.tag} classified=${row.classifiedIssueCount} raw=${row.rawIssueCount}`)
          .join('; ');
        failures.push(
          `score persistence classification coverage must be exact for every audited stable release: ${examples}`,
        );
      }
      let currentSourceIdentity = null;
      try {
        currentSourceIdentity = sourceIdentityForDb(db);
        const currentManifestProblems = scoreSourceIdentityManifestProblems(currentSourceIdentity);
        if (currentManifestProblems.length > 0) {
          failures.push(
            `current score source identity is malformed: ${currentManifestProblems.join(', ')}`,
          );
          currentSourceIdentity = null;
        }
        report.scorePersistence.sourceIdentity.current = sourceIdentitySummary(currentSourceIdentity);
        report.scorePersistence.sourceIdentity.matchesCurrent =
          currentSourceIdentity != null &&
          JSON.stringify(report.scorePersistence.sourceIdentity.persistedManifest) ===
            JSON.stringify(currentSourceIdentity);
      } catch (error) {
        failures.push(`score source identity could not be computed: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (report.scorePersistence.sourceIdentity.missingTags.length > 0) {
        failures.push(`score persistence source identity missing for: ${report.scorePersistence.sourceIdentity.missingTags.join(', ')}`);
      }
      if (report.scorePersistence.sourceIdentity.malformedTags.length > 0) {
        failures.push(`score persistence source identity malformed for: ${report.scorePersistence.sourceIdentity.malformedTags.join(', ')}`);
      }
      if (report.scorePersistence.sourceIdentity.persistedIdentityCount !== 1) {
        failures.push(`score persistence audits must share one source identity manifest, found ${report.scorePersistence.sourceIdentity.persistedIdentityCount}`);
      }
      if (report.scorePersistence.sourceIdentity.missingRequiredSources.length > 0) {
        failures.push(
          `score persistence source identity is missing required sources: ` +
          report.scorePersistence.sourceIdentity.missingRequiredSources.join(', '),
        );
      }
      if (report.scorePersistence.meta.sourceIdentitySchemaVersion !== SCORE_SOURCE_IDENTITY_SCHEMA_VERSION) {
        failures.push(`score persistence sourceIdentitySchemaVersion (${report.scorePersistence.meta.sourceIdentitySchemaVersion}) must equal ${SCORE_SOURCE_IDENTITY_SCHEMA_VERSION}`);
      }
      if (report.scorePersistence.meta.sourceIdentityDigest !== report.scorePersistence.sourceIdentity.persisted?.digest) {
        failures.push(`score persistence sourceIdentityDigest (${report.scorePersistence.meta.sourceIdentityDigest}) does not match audit rows (${report.scorePersistence.sourceIdentity.persisted?.digest ?? 'missing'})`);
      }
      if (report.scorePersistence.meta.sourceIdentityRowCount !== report.scorePersistence.sourceIdentity.persisted?.rowCount) {
        failures.push(`score persistence sourceIdentityRowCount (${report.scorePersistence.meta.sourceIdentityRowCount}) does not match audit rows (${report.scorePersistence.sourceIdentity.persisted?.rowCount ?? 'missing'})`);
      }
      if (report.scorePersistence.meta.sourceIdentitySourceCount !== report.scorePersistence.sourceIdentity.persisted?.sourceCount) {
        failures.push(`score persistence sourceIdentitySourceCount (${report.scorePersistence.meta.sourceIdentitySourceCount}) does not match audit rows (${report.scorePersistence.sourceIdentity.persisted?.sourceCount ?? 'missing'})`);
      }
      if (currentSourceIdentity && !report.scorePersistence.sourceIdentity.matchesCurrent) {
        failures.push(`score source identity drift: persisted ${report.scorePersistence.sourceIdentity.persisted?.digest ?? 'missing'}, current ${currentSourceIdentity.digest}`);
      }
    }

    const audit = getAudit(db, latest.tag);
    const input = parseJson(audit?.input_json, {});
    const gate = parseJson(audit?.gate_evidence_json, {});
    const issueEvidence = parseJson(audit?.issue_evidence_json, {});
    report.coverage = coverageSummary(input, issueEvidence);
    if (Number(report.coverage.classifiedIssueCount ?? 0) !== Number(report.coverage.rawIssueCount ?? 0)) {
      failures.push(`${latest.tag}: incomplete classification coverage (${report.coverage.classifiedIssueCount}/${report.coverage.rawIssueCount})`);
    }
    report.classifications = classificationProvenanceSummary(db, audit);
    if (
      [
        'evidence-v21-human-confirmed-field',
        'evidence-v22-advisory-consistency',
        'evidence-v23-claim-provenance',
        'evidence-v24-linkage-integrity',
        'evidence-v25-closure-context',
        'evidence-v26-calibrated-evidence',
      ].includes(audit?.score_model_version) &&
      report.classifications.failedCount > 0
    ) {
      failures.push(
        `${latest.tag}: v21-compatible raw classification provenance is invalid ` +
        `(rows=${report.classifications.rowCount}, legacy=${report.classifications.legacyCount}, ` +
        `invalid=${report.classifications.invalidCount}, expectedPrompt=${PROMPT_VERSION})`,
      );
    }

    report.freshness = freshnessSummary(db, latest.tag, latest.scoredAt, now);
    const freshnessHealth = assessDataFreshnessHealth(report.freshness, latest, { maxIssueLagHours });
    warnings.push(...freshnessHealth.warnings);
    failures.push(...freshnessHealth.failures);

    report.ingestion = ingestionSummary(db, latest);
    const crawlHealth = assessIssueCrawlHealth(report.ingestion.issueCrawl, latest, {
      baseline: report.ingestion.issueCrawlBaseline,
      repository: `${config.github.owner}/${config.github.repo}`,
    });
    warnings.push(...crawlHealth.warnings);
    failures.push(...crawlHealth.failures);
    const durableFailureHealth = assessDurableIngestionEvidenceFailureHealth(report.ingestion.durableEvidenceFailures, latest);
    warnings.push(...durableFailureHealth.warnings);
    failures.push(...durableFailureHealth.failures);
    if (report.ingestion.commenterScanTruncatedIssueCount > 0) {
      warnings.push(`${latest.tag}: ${report.ingestion.commenterScanTruncatedIssueCount} issue row(s) have truncated comment scans`);
    }

    report.stateSnapshots = stateSnapshotSummary(db, latest.tag);
    if (report.stateSnapshots.failedCount > 0) {
      failures.push(`${latest.tag}: issue state-event snapshots are incomplete or inconsistent ` +
        `(schema=${report.stateSnapshots.schemaFailureCount}, ` +
        `missing=${report.stateSnapshots.missingSnapshotCount}, ` +
        `invalid=${report.stateSnapshots.invalidSnapshotCount}, ` +
        `metadata=${report.stateSnapshots.metadataMismatchCount}, ` +
        `projection=${report.stateSnapshots.projectionMismatchCount}, ` +
        `latestState=${report.stateSnapshots.latestStateMismatchCount})`);
    }

    report.closureProof = closureProofSummary(db, latest.tag, gate);
    if (report.closureProof.rawClosedWindowCount !== report.closureProof.proofRowCount) {
      failures.push(`${latest.tag}: closure proof rows (${report.closureProof.proofRowCount}) do not cover raw closed release-window issues (${report.closureProof.rawClosedWindowCount})`);
    }
    if (report.closureProof.integrity.failedCount > 0) {
      failures.push(`${latest.tag}: closure proof evidence is stale or incomplete, or has invalid dependency provenance ` +
        `(missing=${report.closureProof.integrity.missingCount}, ` +
        `extra=${report.closureProof.integrity.extraCount}, ` +
        `stale=${report.closureProof.integrity.staleCount}, ` +
        `analyzer=${report.closureProof.integrity.analyzerVersionMismatchCount}, ` +
        `dependencyMissing=${report.closureProof.integrity.dependencySnapshotMissingCount}, ` +
        `dependencySchema=${report.closureProof.integrity.dependencySnapshotSchemaMismatchCount}, ` +
        `dependencyAnalyzer=${report.closureProof.integrity.dependencySnapshotAnalyzerMismatchCount}, ` +
        `dependencyDigestMissing=${report.closureProof.integrity.dependencySnapshotDigestMissingCount}, ` +
        `dependencyMembership=${report.closureProof.integrity.dependencySnapshotMembershipMismatchCount}, ` +
        `dependencyMissingIssues=${report.closureProof.integrity.dependencyReferencedIssueMissingCount}, ` +
        `dependencyInvalidEvidence=${report.closureProof.integrity.dependencyEvidenceInvalidCount}, ` +
        `dependencyMismatch=${report.closureProof.integrity.dependencySnapshotMismatchCount})`);
    }
    if (report.closureProof.auditAnalyzedClosedCount != null &&
      report.closureProof.auditAnalyzedClosedCount !== report.closureProof.proofRowCount) {
      failures.push(`${latest.tag}: audit analyzedClosedCount (${report.closureProof.auditAnalyzedClosedCount}) does not match proof rows (${report.closureProof.proofRowCount})`);
    }
    if (report.closureProof.fixCreditIntegrity.failedCount > 0) {
      failures.push(`${latest.tag}: persisted releaseFixCredit is incomplete or inconsistent ` +
        `(missing=${report.closureProof.fixCreditIntegrity.missingPayloadCount}, ` +
        `schema=${report.closureProof.fixCreditIntegrity.schemaFailureCount}, ` +
        `counts=${report.closureProof.fixCreditIntegrity.countMismatchCount}, ` +
        `decisions=${report.closureProof.fixCreditIntegrity.decisionMismatchCount}, ` +
        `boundary=${report.closureProof.fixCreditIntegrity.boundaryMismatchCount})`);
    }

    report.reachability = reachabilitySummary(db, latest.tag);
    if (report.reachability.integrity.failedCount > 0) {
      failures.push(`${latest.tag}: PR reachability evidence is stale or incomplete ` +
        `(missing=${report.reachability.integrity.missingCount}, extra=${report.reachability.integrity.extraCount}, ` +
        `stale=${report.reachability.integrity.staleCount}, mismatched=${report.reachability.integrity.mismatchedCount}, ` +
        `invalidEvidence=${report.reachability.integrity.invalidEvidenceCount})`);
    }
    if (report.reachability.predecessorBoundaries.failedCount > 0) {
      failures.push(`persisted releaseFixCredit predecessor boundary validation failed ` +
        `(missingPayload=${report.reachability.predecessorBoundaries.missingPayloadCount}, ` +
        `missingTag=${report.reachability.predecessorBoundaries.missingPredecessorTagCount}, ` +
        `invalid=${report.reachability.predecessorBoundaries.invalidBoundaryCount}, ` +
        `reachability=${report.reachability.predecessorBoundaries.reachabilityFailureCount}, ` +
        `invalidEvidence=${report.reachability.predecessorBoundaries.strictEvidenceMismatchCount})`);
    }
    report.validation = validationLedgerSummary(db);
    if (report.validation.legacyLateForecastCount > 0) {
      legacyFindings.push(
        `${report.validation.legacyLateForecastCount} legacy validation forecast(s) fall outside ` +
        `their bounded opportunity window and will be excluded from evaluation`,
      );
    }
    if (report.validation.legacyDecisionSchemaCount > 0) {
      legacyFindings.push(
        `${report.validation.legacyDecisionSchemaCount} legacy validation forecast(s) use ` +
        `decision schema v1-v3 and remain readable but are excluded from current evaluation`,
      );
    }
    if (report.validation.legacyManifestCompatibilityWarningCount > 0) {
      const examples = report.validation.legacyManifestWarnings
        .slice(0, 3)
        .join('; ');
      legacyFindings.push(
        `${report.validation.legacyManifestCompatibilityWarningCount} structurally valid obsolete ` +
        `source manifest(s) belong only to legacy forecasts already excluded for out-of-window ` +
        `timing and do not affect active evaluation` +
        (examples ? `: ${examples}` : ''),
      );
    }
    if (report.validation.failedCount > 0) {
      failures.push(`validation ledger integrity failed for ${report.validation.failedCount} row(s) ` +
        `(forecastChain=${report.validation.forecastChainFailureCount}, ` +
        `forecastHash=${report.validation.forecastHashFailureCount}, ` +
        `forecastId=${report.validation.forecastDecisionIdFailureCount}, ` +
        `duplicateForecastSeries=${report.validation.duplicateForecastSeriesCount}, ` +
        `forecastSeriesUniqueIndex=${report.validation.forecastSeriesUniqueIndexFailureCount}, ` +
        `forecastSemantic=${report.validation.forecastSemanticFailureCount}, ` +
        `forecastManifest=${report.validation.forecastSourceManifestFailureCount}, ` +
        `historyManifest=${report.validation.referencedHistorySourceManifestFailureCount}, ` +
        `legacyManifestWarnings=${report.validation.legacyManifestCompatibilityWarningCount}, ` +
        `missingAuditRun=${report.validation.missingAuditRunCount}, ` +
        `outcomeChain=${report.validation.outcomeChainFailureCount}, ` +
        `outcomeHash=${report.validation.outcomeHashFailureCount}, ` +
        `outcomeId=${report.validation.outcomeObservationIdFailureCount}, ` +
        `missingDecision=${report.validation.missingDecisionCount}, ` +
        `advisoryV2Authorization=${report.validation.advisoryV2AuthorizationFailureCount}, ` +
        `advisoryProvenance=${report.validation.advisorySnapshotProvenanceFailureCount}, ` +
        `duplicateMatured=${report.validation.duplicateMaturedOutcomeCount}, ` +
        `maturedUniqueIndex=${report.validation.maturedUniqueIndexFailureCount})`);
    }
    report.comparison = comparisonSummary(db);
  } finally {
    db.close();
  }

  return finish(report, { failOnWarnings });
}

function canonicalValidationProofSummary(db, now) {
  try {
    return summarizeReleaseValidationProof(
      readDoctorReleaseValidationProofBundle(db),
      now.toISOString(),
    );
  } catch (error) {
    const problem =
      `release validation proof storage could not be summarized: ` +
      `${error instanceof Error ? error.message : String(error)}`;
    return {
      schemaVersion: 1,
      observedAt: now.toISOString(),
      status: 'invalid',
      valid: false,
      productionAuthorized: false,
      productionAuthorizationProblems: [problem],
      counts: null,
      activeEpochCount: 0,
      activeEpochIds: [],
      activeCohortCount: 0,
      activeCohortIds: [],
      currentEvaluation: null,
      currentProductionPromotion: null,
      latestCalibrationPromotion: null,
      problems: [problem],
    };
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = buildDoctorReport({
    dbPath: args['db-path'] ?? process.env.DB_PATH ?? './data/radar.db',
    maxIssueLagHours: Number(args['max-issue-lag-hours'] ?? 48),
    failOnWarnings: args['fail-on-warnings'] === true,
  });
  if (args['api-base']) {
    report.api = await apiSummary(String(args['api-base']).replace(/\/$/, ''));
    verifyApiAgainstDb(report);
  }
  report.ok = report.failures.length === 0 && (args['fail-on-warnings'] !== true || report.warnings.length === 0);
  console.log(JSON.stringify(report, null, 2));
  if (!report.ok) process.exit(1);
}

function finish(report, { failOnWarnings = false } = {}) {
  report.ok = report.failures.length === 0 && (failOnWarnings !== true || report.warnings.length === 0);
  return report;
}

function tableSummary(db, table) {
  const present = !!db.prepare(`
    SELECT 1 AS present
    FROM sqlite_master
    WHERE type='table' AND name=?
  `).get(table);
  if (!present) return { present: false, count: 0, maxAt: null };
  const maxColumn = ({
    releases: 'scored_at',
    issues: 'updated_at',
    classifications: 'classified_at',
    release_score_audits: 'scored_at',
    release_score_audit_history: 'recorded_at',
    release_score_audit_history_runs: 'recorded_at',
    release_validation_forecasts: 'recorded_at',
    release_validation_outcome_observations: 'observed_at',
    release_commits: 'fetched_at',
    issue_comment_snapshots: 'verified_at',
    issue_closure_evidence_state: 'checked_at',
    issue_closure_proofs: 'checked_at',
    issue_closure_events: 'fetched_at',
    issue_reopen_events: 'fetched_at',
    issue_state_event_snapshots: 'verified_at',
    issue_pr_links: 'fetched_at',
    issue_commit_references: 'fetched_at',
    pull_request_fixes: 'fetched_at',
    release_pr_reachability: 'checked_at',
    release_closure_dependency_snapshots: 'captured_at',
    issue_label_events: 'fetched_at',
    issue_label_snapshots: 'fetched_at',
    advisories: 'fetched_at',
    advisory_snapshot_history: 'captured_at',
    advisory_snapshot_v2_history: 'captured_at',
    refresh_leases: 'expires_at',
    refresh_operation_attempts: 'started_at',
    refresh_operation_stage_events: 'occurred_at',
    refresh_capture_receipts: 'finished_at',
    comparison_snapshots: 'captured_at',
  })[table] ?? null;
  const maxExpr = maxColumn && tableHasColumns(db, table, [maxColumn])
    ? `MAX(${maxColumn})`
    : 'NULL';
  const row = db.prepare(`SELECT COUNT(*) AS count, ${maxExpr} AS maxAt FROM ${table}`).get();
  return { present: true, count: Number(row?.count ?? 0), maxAt: row?.maxAt ?? null };
}

function issueWindowPerformanceSummary(db) {
  const required = [
    { name: 'idx_issues_created_at', columns: ['created_at'] },
    { name: 'idx_issues_closed_at', columns: ['closed_at'] },
  ];
  if (!tablePresent(db, 'issues')) {
    return {
      requiredIndexes: required.map((index) => ({ ...index, present: false, actualColumns: [] })),
      plans: [],
      missingIndexCount: required.length,
      unusedPlanCount: 0,
      failedCount: required.length,
    };
  }
  const indexes = new Map(
    db.prepare(`PRAGMA index_list(issues)`).all().map((row) => [String(row.name), row]),
  );
  const requiredIndexes = required.map((index) => {
    const present = indexes.has(index.name);
    const actualColumns = present
      ? db.prepare(`PRAGMA index_info("${index.name}")`).all().map((column) => String(column.name))
      : [];
    return {
      ...index,
      present: present && JSON.stringify(actualColumns) === JSON.stringify(index.columns),
      actualColumns,
    };
  });
  const planSpecs = [
    {
      name: 'issues_created_release_window',
      expectedIndex: 'idx_issues_created_at',
      sql: `
        EXPLAIN QUERY PLAN
        SELECT number
        FROM issues
        WHERE created_at >= ? AND created_at < ?
        ORDER BY created_at DESC
      `,
    },
    {
      name: 'issues_closed_release_window',
      expectedIndex: 'idx_issues_closed_at',
      sql: `
        EXPLAIN QUERY PLAN
        SELECT number
        FROM issues
        WHERE closed_at >= ? AND closed_at < ?
        ORDER BY closed_at DESC
      `,
    },
  ];
  const plans = planSpecs.map((plan) => {
    const details = db.prepare(plan.sql)
      .all('2000-01-01T00:00:00Z', '9999-12-31T23:59:59Z')
      .map((row) => String(row.detail ?? ''));
    return {
      name: plan.name,
      expectedIndex: plan.expectedIndex,
      usesExpectedIndex: details.some((detail) => detail.includes(plan.expectedIndex)),
      details,
    };
  });
  const missingIndexCount = requiredIndexes.filter((index) => !index.present).length;
  const unusedPlanCount = plans.filter((plan) => !plan.usesExpectedIndex).length;
  return {
    requiredIndexes,
    plans,
    missingIndexCount,
    unusedPlanCount,
    failedCount: missingIndexCount + unusedPlanCount,
  };
}

function appendOnlyTriggerSummary(db) {
  const rows = db.prepare(`
    SELECT name, tbl_name AS table_name, sql
    FROM sqlite_schema
    WHERE type='trigger'
    ORDER BY name
  `).all();
  const byName = new Map(rows.map((row) => [row.name, row]));
  const unexpected = undeclaredAppendOnlyTriggerShapes(rows);
  const checks = [];
  let missingCount = 0;
  let shapeFailureCount = 0;
  for (const spec of APPEND_ONLY_TRIGGER_SPECS) {
    const row = byName.get(spec.name);
    if (!row || typeof row.sql !== 'string') {
      missingCount++;
      checks.push({ ...spec, present: false, shapeValid: false, behaviorValid: false });
      continue;
    }
    const parsed = unconditionalAbortTriggerShape(row);
    const shapeValid =
      parsed?.name === spec.name &&
      parsed.table === spec.table &&
      parsed.event === spec.event &&
      parsed.message === spec.message;
    if (!shapeValid) shapeFailureCount++;
    checks.push({
      ...spec,
      present: true,
      shapeValid,
      behaviorValid: false,
    });
  }
  const specsByTable = new Map();
  for (const spec of APPEND_ONLY_TRIGGER_SPECS) {
    const specs = specsByTable.get(spec.table) ?? [];
    specs.push(spec);
    specsByTable.set(spec.table, specs);
  }
  const tableSpecs = [...specsByTable.entries()]
    .map(([table, specs]) => ({ table, specs }));
  const tableChecks = tableSpecs.map(({ table, specs }) => {
    const updateSpec = specs.find((spec) => spec.event === 'UPDATE');
    const deleteSpec = specs.find((spec) => spec.event === 'DELETE');
    const updateCheck = checks.find(
      (candidate) => candidate.name === updateSpec?.name,
    );
    const deleteCheck = checks.find(
      (candidate) => candidate.name === deleteSpec?.name,
    );
    const updateProbe = updateCheck?.shapeValid && updateSpec
      ? probeAppendOnlyTable(
          table,
          [expectedAppendOnlyTriggerSql(updateSpec)],
          updateSpec.message,
        )
      : invalidAppendOnlyProbe('required UPDATE trigger is missing or malformed');
    const deleteProbe = deleteCheck?.shapeValid && deleteSpec
      ? probeAppendOnlyTable(
          table,
          [expectedAppendOnlyTriggerSql(deleteSpec)],
          deleteSpec.message,
        )
      : invalidAppendOnlyProbe('required DELETE trigger is missing or malformed');
    if (updateCheck?.present) {
      updateCheck.behaviorValid = updateProbe.update.valid;
      if (updateProbe.update.error) {
        updateCheck.behaviorError = updateProbe.update.error;
      }
    }
    if (deleteCheck?.present) {
      deleteCheck.behaviorValid =
        deleteProbe.delete.valid && deleteProbe.replace.valid;
      const error = [
        deleteProbe.delete.error,
        deleteProbe.replace.error,
      ].filter(Boolean).join('; ');
      if (error) deleteCheck.behaviorError = error;
    }
    const recursiveTriggersEnabled =
      updateProbe.recursiveTriggersEnabled &&
      deleteProbe.recursiveTriggersEnabled;
    const valid =
      recursiveTriggersEnabled &&
      updateProbe.update.valid &&
      deleteProbe.delete.valid &&
      deleteProbe.replace.valid;
    return {
      table,
      recursiveTriggersEnabled,
      update: updateProbe.update,
      delete: deleteProbe.delete,
      replace: deleteProbe.replace,
      valid,
    };
  });
  const behaviorFailureCount = checks.filter(
    (check) => check.present && !check.behaviorValid,
  ).length;
  const unexpectedCount = unexpected.length;
  return {
    requiredCount: APPEND_ONLY_TRIGGER_SPECS.length,
    requiredTableCount: tableChecks.length,
    presentCount: APPEND_ONLY_TRIGGER_SPECS.length - missingCount,
    missingCount,
    shapeFailureCount,
    behaviorFailureCount,
    unexpectedCount,
    failedCount:
      missingCount +
      shapeFailureCount +
      behaviorFailureCount +
      unexpectedCount,
    unexpected,
    checks,
    tableChecks,
  };
}

function expectedAppendOnlyTriggerSql(spec) {
  return `
    CREATE TRIGGER ${spec.name}
    BEFORE ${spec.event} ON ${spec.table}
    BEGIN
      SELECT RAISE(ABORT, '${spec.message}');
    END
  `;
}

function invalidAppendOnlyProbe(error) {
  return {
    recursiveTriggersEnabled: false,
    update: { valid: false, error },
    delete: { valid: false, error },
    replace: { valid: false, error },
    valid: false,
  };
}

function probeAppendOnlyTable(table, triggerSql, message) {
  const probe = new DatabaseSync(':memory:');
  try {
    const quotedTable = `"${table.replaceAll('"', '""')}"`;
    probe.exec(`
      PRAGMA recursive_triggers = ON;
      CREATE TABLE ${quotedTable} (
        id INTEGER PRIMARY KEY,
        value TEXT NOT NULL
      );
      INSERT INTO ${quotedTable}(id, value) VALUES (1, 'original');
      ${triggerSql.join(';\n')}
    `);
    const recursiveTriggersEnabled =
      Number(probe.prepare(`PRAGMA recursive_triggers`).get()?.recursive_triggers) === 1;
    const update = probeRejectedMutation(
      probe,
      quotedTable,
      `UPDATE ${quotedTable} SET value='changed' WHERE id=1`,
      message,
    );
    const deleteProbe = probeRejectedMutation(
      probe,
      quotedTable,
      `DELETE FROM ${quotedTable} WHERE id=1`,
      message,
    );
    const replace = probeRejectedMutation(
      probe,
      quotedTable,
      `INSERT OR REPLACE INTO ${quotedTable}(id, value) VALUES (1, 'replacement')`,
      message,
    );
    const valid = recursiveTriggersEnabled &&
      update.valid &&
      deleteProbe.valid &&
      replace.valid;
    return {
      recursiveTriggersEnabled,
      update,
      delete: deleteProbe,
      replace,
      valid,
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      recursiveTriggersEnabled: false,
      update: { valid: false, error: detail },
      delete: { valid: false, error: detail },
      replace: { valid: false, error: detail },
      valid: false,
    };
  } finally {
    probe.close();
  }
}

function probeRejectedMutation(db, quotedTable, sql, expectedMessage) {
  db.exec('SAVEPOINT append_only_probe');
  let blocked = false;
  let errorMessage = '';
  try {
    db.exec(sql);
  } catch (error) {
    blocked = true;
    errorMessage = error instanceof Error ? error.message : String(error);
  }
  const row = db.prepare(`SELECT value FROM ${quotedTable} WHERE id=1`).get();
  const unchanged = row?.value === 'original';
  db.exec('ROLLBACK TO append_only_probe; RELEASE append_only_probe');
  const restored = db.prepare(`SELECT value FROM ${quotedTable} WHERE id=1`).get()?.value ===
    'original';
  const valid = blocked &&
    unchanged &&
    restored &&
    errorMessage.includes(expectedMessage);
  return {
    valid,
    error: valid
      ? null
      : `blocked=${blocked} unchanged=${unchanged} restored=${restored} ` +
        `message=${JSON.stringify(errorMessage)}`,
  };
}

export function issueCatalogSnapshotSummary(db, now = new Date()) {
  const historySchema = requiredTableSchemaSummary(
    db,
    'issue_catalog_snapshots',
    ISSUE_CATALOG_SNAPSHOT_HEADER_COLUMNS,
  );
  const rowSchema = requiredTableSchemaSummary(
    db,
    'issue_catalog_snapshot_rows',
    ISSUE_CATALOG_SNAPSHOT_ROW_COLUMNS,
  );
  const consumptionSchema = requiredTableSchemaSummary(
    db,
    'issue_catalog_snapshot_consumptions',
    ISSUE_CATALOG_SNAPSHOT_CONSUMPTION_COLUMNS,
  );
  const schemaFailureCount =
    (historySchema.present ? historySchema.missingColumns.length : 1) +
    (rowSchema.present ? rowSchema.missingColumns.length : 1) +
    (consumptionSchema.present ? consumptionSchema.missingColumns.length : 1);
  const summary = {
    schema: {
      history: historySchema,
      rows: rowSchema,
      consumptions: consumptionSchema,
    },
    schemaFailureCount,
    snapshotCount: historySchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM issue_catalog_snapshots')
      : 0,
    rowCount: rowSchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM issue_catalog_snapshot_rows')
      : 0,
    consumptionCount: consumptionSchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM issue_catalog_snapshot_consumptions')
      : 0,
    orphanRowCount: 0,
    ledgerFailureCount: 0,
    consumptionFailureCount: 0,
    crawlLinkFailureCount: 0,
    failedCount: schemaFailureCount,
    latest: null,
    examples: [],
  };
  if (schemaFailureCount > 0) return summary;

  const headers = db.prepare(`
    SELECT
      id,
      snapshot_id AS snapshotId,
      schema_version AS schemaVersion,
      row_schema_version AS rowSchemaVersion,
      repository,
      source,
      source_order AS sourceOrder,
      captured_at AS capturedAt,
      boundary_total_count AS boundaryTotalCount,
      observed_total_count AS observedTotalCount,
      post_boundary_growth_count AS postBoundaryGrowthCount,
      terminal_node_id AS terminalNodeId,
      terminal_issue_number AS terminalIssueNumber,
      terminal_created_at AS terminalCreatedAt,
      fetched_count AS fetchedCount,
      unique_count AS uniqueCount,
      page_count AS pageCount,
      pages_fetched AS pagesFetched,
      sweep_count AS sweepCount,
      membership_digest AS membershipDigest,
      content_digest AS contentDigest,
      last_request_cursor AS lastRequestCursor,
      row_count AS rowCount,
      row_schema_digest AS rowSchemaDigest,
      rows_content_hash AS rowsContentHash,
      previous_content_hash AS previousContentHash,
      content_hash AS contentHash
    FROM issue_catalog_snapshots
    ORDER BY id
  `).all().map((row) => ({
    ...row,
    id: Number(row.id),
    schemaVersion: Number(row.schemaVersion),
    rowSchemaVersion: Number(row.rowSchemaVersion),
    boundaryTotalCount: Number(row.boundaryTotalCount),
    observedTotalCount: Number(row.observedTotalCount),
    postBoundaryGrowthCount: Number(row.postBoundaryGrowthCount),
    terminalIssueNumber:
      row.terminalIssueNumber == null ? null : Number(row.terminalIssueNumber),
    fetchedCount: Number(row.fetchedCount),
    uniqueCount: Number(row.uniqueCount),
    pageCount: Number(row.pageCount),
    pagesFetched: Number(row.pagesFetched),
    sweepCount: Number(row.sweepCount),
    rowCount: Number(row.rowCount),
  }));
  const rows = db.prepare(`
    SELECT
      snapshot_id AS snapshotId,
      source_ordinal AS sourceOrdinal,
      issue_number AS issueNumber,
      node_id AS nodeId,
      issue_json AS issueJson,
      content_hash AS contentHash
    FROM issue_catalog_snapshot_rows
    ORDER BY snapshot_id, source_ordinal
  `).all().map((row) => {
    const issueJson = String(row.issueJson);
    let issue = parseIssueCatalogIssueJson(issueJson);
    if (!issue) {
      try {
        issue = JSON.parse(issueJson);
      } catch {
        issue = {};
      }
    }
    return {
      snapshotId: String(row.snapshotId),
      sourceOrdinal: Number(row.sourceOrdinal),
      issueNumber: Number(row.issueNumber),
      nodeId: String(row.nodeId),
      issueJson,
      contentHash: String(row.contentHash),
      issue,
    };
  });
  const consumptions = db.prepare(`
    SELECT
      id,
      schema_version AS schemaVersion,
      snapshot_id AS snapshotId,
      repository,
      run_id AS runId,
      consumed_at AS consumedAt,
      processed_row_count AS processedRowCount,
      processed_page_count AS processedPageCount,
      snapshot_content_hash AS snapshotContentHash,
      previous_content_hash AS previousContentHash,
      content_hash AS contentHash
    FROM issue_catalog_snapshot_consumptions
    ORDER BY id
  `).all().map((row) => ({
    ...row,
    id: Number(row.id),
    schemaVersion: Number(row.schemaVersion),
    processedRowCount: Number(row.processedRowCount),
    processedPageCount: Number(row.processedPageCount),
  }));
  const rowsBySnapshot = new Map();
  for (const row of rows) {
    const attached = rowsBySnapshot.get(row.snapshotId) ?? [];
    attached.push(row);
    rowsBySnapshot.set(row.snapshotId, attached);
  }
  const headerIds = new Set(headers.map((header) => header.snapshotId));
  summary.orphanRowCount = rows.filter((row) => !headerIds.has(row.snapshotId)).length;
  const snapshots = headers.map((header) => ({
    header,
    rows: rowsBySnapshot.get(header.snapshotId) ?? [],
  }));
  const ledgerProblems = issueCatalogSnapshotLedgerProblems(
    snapshots,
    summary.orphanRowCount,
  );
  summary.ledgerFailureCount = ledgerProblems.length;
  summary.examples = ledgerProblems.slice(0, 10);

  const snapshotsById = new Map(snapshots.map((snapshot) => [
    snapshot.header.snapshotId,
    snapshot,
  ]));
  const consumptionsBySnapshotId = new Map();
  const consumptionProblems = [];
  let previousConsumptionContentHash = null;
  for (const consumption of consumptions) {
    const snapshot = snapshotsById.get(consumption.snapshotId) ?? null;
    const problems = issueCatalogSnapshotConsumptionProblems(
      consumption,
      snapshot,
      previousConsumptionContentHash,
    );
    for (const detail of problems) {
      consumptionProblems.push({ snapshotId: consumption.snapshotId, detail });
    }
    if (consumptionsBySnapshotId.has(consumption.snapshotId)) {
      consumptionProblems.push({
        snapshotId: consumption.snapshotId,
        detail: 'snapshot has more than one consumption row',
      });
    }
    consumptionsBySnapshotId.set(consumption.snapshotId, consumption);
    previousConsumptionContentHash = consumption.contentHash;
  }
  summary.consumptionFailureCount = consumptionProblems.length;
  summary.examples.push(...consumptionProblems.slice(
    0,
    Math.max(0, 10 - summary.examples.length),
  ));

  const crawlMetadataRow = db.prepare(`
    SELECT value FROM meta WHERE key='issue_crawl_last_run'
  `).get();
  let crawlMetadata = null;
  try {
    crawlMetadata = crawlMetadataRow?.value ? JSON.parse(crawlMetadataRow.value) : null;
  } catch {
    crawlMetadata = null;
  }
  const crawlSnapshot = crawlMetadata?.catalogSnapshot;
  if (crawlSnapshot != null) {
    const linked = snapshotsById.get(crawlSnapshot.snapshotId) ?? null;
    const consumption = consumptionsBySnapshotId.get(crawlSnapshot.snapshotId) ?? null;
    const pagination = crawlMetadata?.pagination;
    const attestation = crawlMetadata?.catalogAttestation;
    const consumptionClaimed =
      crawlMetadata?.scorePersisted === true ||
      crawlSnapshot.consumedAt != null ||
      crawlSnapshot.consumedByRunId != null ||
      crawlSnapshot.consumptionContentHash != null;
    const linkProblems = [];
    if (crawlSnapshot.schemaVersion !== 1) {
      linkProblems.push('catalogSnapshot schemaVersion must equal 1');
    }
    if (
      !isSha256Hex(crawlSnapshot.snapshotId) ||
      crawlSnapshot.contentHash !== crawlSnapshot.snapshotId
    ) {
      linkProblems.push('catalogSnapshot snapshotId/contentHash must be the same SHA-256');
    }
    if (!linked) {
      linkProblems.push('catalogSnapshot does not reference a persisted snapshot');
    } else {
      if (crawlMetadata.repository !== linked.header.repository) {
        linkProblems.push('catalogSnapshot repository does not match issue crawl');
      }
      if (crawlSnapshot.capturedAt !== linked.header.capturedAt) {
        linkProblems.push('catalogSnapshot capturedAt does not match persisted header');
      }
      if (crawlSnapshot.contentHash !== linked.header.contentHash) {
        linkProblems.push('catalogSnapshot contentHash does not match persisted header');
      }
      if (
        pagination?.membershipDigest !== linked.header.membershipDigest ||
        pagination?.contentDigest !== linked.header.contentDigest ||
        pagination?.boundaryTotalCount !== linked.header.boundaryTotalCount ||
        pagination?.observedTotalCount !== linked.header.observedTotalCount ||
        pagination?.fetchedCount !== linked.header.rowCount ||
        pagination?.pageCount !== linked.header.pageCount
      ) {
        linkProblems.push('catalogSnapshot does not match issue crawl pagination metadata');
      }
    }
    if (typeof crawlSnapshot.resumed !== 'boolean') {
      linkProblems.push('catalogSnapshot resumed must be boolean');
    }
    if (!['missing', 'invalid', 'stale', 'consumed', 'resumable'].includes(crawlSnapshot.priorStatus)) {
      linkProblems.push('catalogSnapshot priorStatus is invalid');
    }
    if (crawlSnapshot.resumed !== (crawlSnapshot.priorStatus === 'resumable')) {
      linkProblems.push('catalogSnapshot resumed must match priorStatus resumable');
    }
    if (!Number.isInteger(crawlSnapshot.maxAgeHours) || crawlSnapshot.maxAgeHours <= 0) {
      linkProblems.push('catalogSnapshot maxAgeHours must be a positive integer');
    }
    if (consumptionClaimed) {
      if (!consumption) {
        linkProblems.push('catalogSnapshot consumption does not reference a persisted consumption');
      } else {
        if (crawlSnapshot.consumedAt !== consumption.consumedAt) {
          linkProblems.push('catalogSnapshot consumedAt does not match persisted consumption');
        }
        if (crawlSnapshot.consumedByRunId !== consumption.runId) {
          linkProblems.push('catalogSnapshot consumedByRunId does not match persisted consumption');
        }
        if (crawlSnapshot.consumptionContentHash !== consumption.contentHash) {
          linkProblems.push(
            'catalogSnapshot consumptionContentHash does not match persisted consumption',
          );
        }
      }
    }
    if (crawlMetadata?.scorePersisted === true) {
      if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
        linkProblems.push('catalogAttestation must be present for a score-persisted crawl');
      } else {
        if (attestation.schemaVersion !== 1) {
          linkProblems.push('catalogAttestation schemaVersion must equal 1');
        }
        if (
          attestation.snapshotId !== crawlSnapshot.snapshotId ||
          attestation.snapshotContentHash !== crawlSnapshot.contentHash
        ) {
          linkProblems.push('catalogAttestation does not bind the consumed catalog snapshot');
        }
        if (!isTimestamp(attestation.observedAt)) {
          linkProblems.push('catalogAttestation observedAt must be a valid timestamp');
        } else if (
          isTimestamp(crawlSnapshot.consumedAt) &&
          Date.parse(attestation.observedAt) < Date.parse(crawlSnapshot.consumedAt)
        ) {
          linkProblems.push('catalogAttestation cannot predate snapshot consumption');
        }
        if (
          attestation.totalCount !== pagination?.boundaryTotalCount ||
          attestation.membershipDigest !== pagination?.membershipDigest ||
          attestation.contentDigest !== pagination?.contentDigest
        ) {
          linkProblems.push('catalogAttestation does not match issue crawl pagination');
        }
        if (
          !Number.isInteger(attestation.finalSweepCount) ||
          attestation.finalSweepCount < 1
        ) {
          linkProblems.push('catalogAttestation finalSweepCount must be at least 1');
        }
        if (
          !Number.isInteger(attestation.finalPagesFetched) ||
          attestation.finalPagesFetched < attestation.finalSweepCount
        ) {
          linkProblems.push('catalogAttestation finalPagesFetched must cover every final sweep');
        }
      }
    }
    summary.crawlLinkFailureCount = linkProblems.length;
    summary.examples.push(...linkProblems.slice(0, Math.max(0, 10 - summary.examples.length))
      .map((detail) => ({
        snapshotId: crawlSnapshot.snapshotId ?? null,
        detail,
      })));
  }
  summary.failedCount =
    summary.schemaFailureCount +
    summary.ledgerFailureCount +
    summary.consumptionFailureCount +
    summary.crawlLinkFailureCount;

  const latest = [...snapshots]
    .reverse()
    .find((snapshot) => snapshot.header.repository === TRACKED_PR_REPOSITORY) ?? null;
  if (latest) {
    const integrityProblems = issueCatalogSnapshotProblems(latest, {
      repository: TRACKED_PR_REPOSITORY,
    });
    const consumption = consumptionsBySnapshotId.get(latest.header.snapshotId) ?? null;
    const resumeProblems = integrityProblems.length === 0 && !consumption
      ? issueCatalogSnapshotResumeProblems(latest, {
          repository: TRACKED_PR_REPOSITORY,
          now,
          maxAgeMs: config.refresh.issueCatalogSnapshotMaxAgeHours * 60 * 60 * 1000,
        })
      : integrityProblems;
    summary.latest = {
      snapshotId: latest.header.snapshotId,
      repository: latest.header.repository,
      capturedAt: latest.header.capturedAt,
      rowCount: latest.header.rowCount,
      membershipDigest: latest.header.membershipDigest,
      contentDigest: latest.header.contentDigest,
      maxAgeHours: config.refresh.issueCatalogSnapshotMaxAgeHours,
      consumption: consumption
        ? {
            runId: consumption.runId,
            consumedAt: consumption.consumedAt,
            processedRowCount: consumption.processedRowCount,
            processedPageCount: consumption.processedPageCount,
            contentHash: consumption.contentHash,
          }
        : null,
      status: integrityProblems.length > 0
        ? 'invalid'
        : consumption
          ? 'consumed'
          : resumeProblems.length > 0
            ? 'stale'
            : 'resumable',
      resumeProblems,
    };
  }
  return summary;
}

function issueCatalogSnapshotConsumptionProblems(
  consumption,
  snapshot,
  expectedPreviousContentHash,
) {
  const problems = [];
  if (consumption.schemaVersion !== 1) {
    problems.push('consumption schemaVersion must equal 1');
  }
  if (!consumption.snapshotId) problems.push('consumption snapshotId must be non-empty');
  if (!consumption.repository) problems.push('consumption repository must be non-empty');
  if (!consumption.runId) problems.push('consumption runId must be non-empty');
  if (!isTimestamp(consumption.consumedAt)) {
    problems.push('consumption consumedAt must be a valid timestamp');
  }
  if (
    !Number.isInteger(consumption.processedRowCount) ||
    consumption.processedRowCount < 0
  ) {
    problems.push('consumption processedRowCount must be a non-negative integer');
  }
  if (
    !Number.isInteger(consumption.processedPageCount) ||
    consumption.processedPageCount < 0
  ) {
    problems.push('consumption processedPageCount must be a non-negative integer');
  }
  if (!isSha256Hex(consumption.snapshotContentHash)) {
    problems.push('consumption snapshotContentHash must be SHA-256');
  }
  if (
    consumption.previousContentHash != null &&
    !isSha256Hex(consumption.previousContentHash)
  ) {
    problems.push('consumption previousContentHash must be SHA-256 or null');
  }
  if (consumption.previousContentHash !== expectedPreviousContentHash) {
    problems.push('consumption previousContentHash does not match the preceding consumption');
  }
  if (!snapshot) {
    problems.push('consumption referenced snapshot is missing');
  } else {
    if (snapshot.header.repository !== consumption.repository) {
      problems.push('consumption repository does not match the referenced snapshot');
    }
    if (snapshot.header.contentHash !== consumption.snapshotContentHash) {
      problems.push('consumption snapshotContentHash does not match the referenced snapshot');
    }
    if (snapshot.header.rowCount !== consumption.processedRowCount) {
      problems.push('consumption processedRowCount does not match the referenced snapshot');
    }
    if (snapshot.header.pageCount !== consumption.processedPageCount) {
      problems.push('consumption processedPageCount does not match the referenced snapshot');
    }
    if (
      isTimestamp(snapshot.header.capturedAt) &&
      isTimestamp(consumption.consumedAt) &&
      Date.parse(consumption.consumedAt) < Date.parse(snapshot.header.capturedAt)
    ) {
      problems.push('consumption cannot predate the referenced snapshot');
    }
  }
  const expectedContentHash = createHash('sha256')
    .update(canonicalOperationJson([
      'issue-catalog-snapshot-consumption-v1',
      consumption.schemaVersion,
      consumption.snapshotId,
      consumption.repository,
      consumption.runId,
      consumption.consumedAt,
      consumption.processedRowCount,
      consumption.processedPageCount,
      consumption.snapshotContentHash,
      consumption.previousContentHash,
    ]))
    .digest('hex');
  if (consumption.contentHash !== expectedContentHash) {
    problems.push('consumption contentHash does not match the canonical consumption payload');
  }
  return [...new Set(problems)];
}

export function compoundAdvisorySnapshotSummary(db) {
  const historySchema = requiredTableSchemaSummary(
    db,
    'advisory_snapshot_v2_history',
    ADVISORY_SNAPSHOT_V2_HISTORY_COLUMNS,
  );
  const rowSchema = requiredTableSchemaSummary(
    db,
    'advisory_snapshot_v2_rows',
    ADVISORY_SNAPSHOT_V2_ROW_COLUMNS,
  );
  const schemaFailureCount =
    (historySchema.present ? historySchema.missingColumns.length : 1) +
    (rowSchema.present ? rowSchema.missingColumns.length : 1);
  const summary = {
    snapshotCount: historySchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM advisory_snapshot_v2_history')
      : 0,
    rowCount: rowSchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM advisory_snapshot_v2_rows')
      : 0,
    schema: {
      history: historySchema,
      rows: rowSchema,
    },
    schemaFailureCount,
    chainFailureCount: 0,
    headerFailureCount: 0,
    rowFailureCount: 0,
    orphanRowCount: 0,
    currentMetadataFailureCount: 0,
    activeProjectionFailureCount: 0,
    latestSnapshotId: null,
    latestMetadata: null,
    activeSnapshotId: null,
    activeMetadata: null,
    stagedSnapshotCount: 0,
    failedCount: schemaFailureCount,
    problems: [],
  };
  if (schemaFailureCount > 0) {
    if (!historySchema.present) {
      summary.problems.push('advisory_snapshot_v2_history table is missing');
    } else if (historySchema.missingColumns.length > 0) {
      summary.problems.push(
        `advisory_snapshot_v2_history is missing columns: ` +
        historySchema.missingColumns.join(', '),
      );
    }
    if (!rowSchema.present) {
      summary.problems.push('advisory_snapshot_v2_rows table is missing');
    } else if (rowSchema.missingColumns.length > 0) {
      summary.problems.push(
        `advisory_snapshot_v2_rows is missing columns: ` +
        rowSchema.missingColumns.join(', '),
      );
    }
    return summary;
  }

  const headers = db.prepare(`
    SELECT *
    FROM advisory_snapshot_v2_history
    ORDER BY id
  `).all();
  const storedRows = db.prepare(`
    SELECT *
    FROM advisory_snapshot_v2_rows
    ORDER BY snapshot_id, range_identity
  `).all();
  const rowsBySnapshot = new Map();
  for (const row of storedRows) {
    const snapshotId = Number(row.snapshot_id);
    const rows = rowsBySnapshot.get(snapshotId) ?? [];
    rows.push(row);
    rowsBySnapshot.set(snapshotId, rows);
  }
  const headerIds = new Set(headers.map((header) => Number(header.id)));
  for (const row of storedRows) {
    if (headerIds.has(Number(row.snapshot_id))) continue;
    summary.orphanRowCount++;
    if (summary.problems.length < 25) {
      summary.problems.push(
        `orphan row ${String(row.range_identity)} references snapshot ${row.snapshot_id}`,
      );
    }
  }

  let previousContentHash = null;
  let latestMetadata = null;
  const snapshotsById = new Map();
  const scoreRowsById = new Map();
  const metadataById = new Map();
  for (const header of headers) {
    const snapshotId = Number(header.id);
    const entryProblems = [];
    let snapshot = null;
    let scoreRows = null;
    try {
      snapshot = JSON.parse(header.snapshot_json);
    } catch {
      entryProblems.push('snapshot_json is not valid JSON');
    }
    if (snapshot) {
      entryProblems.push(...compoundAdvisorySnapshotIntegrityProblems(snapshot));
      try {
        scoreRows = compoundAdvisoryScoreRows(snapshot);
      } catch (error) {
        entryProblems.push(
          `score projection is not valid: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (
        snapshot.repository?.owner !== config.github.owner ||
        snapshot.repository?.name !== config.github.repo ||
        snapshot.repository?.url !==
          `https://github.com/${config.github.owner}/${config.github.repo}`
      ) {
        entryProblems.push('repository identity does not match configured repository');
      }
      if (
        snapshot.target?.ecosystem !== 'npm' ||
        snapshot.target?.packageName !== config.github.repo.toLowerCase()
      ) {
        entryProblems.push('target package identity does not match configured package');
      }
      if (header.snapshot_json !== canonicalCompoundAdvisorySnapshotJson(snapshot)) {
        entryProblems.push('snapshot_json is not canonical');
      }
      if (
        Number(header.schema_version) !== COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION ||
        header.captured_at !== snapshot.capturedAt ||
        header.repository_owner !== snapshot.repository?.owner ||
        header.repository_name !== snapshot.repository?.name ||
        header.repository_url !== snapshot.repository?.url ||
        header.target_ecosystem !== snapshot.target?.ecosystem ||
        header.target_package_name !== snapshot.target?.packageName ||
        header.source_hash !== snapshot.sourceHash ||
        header.catalog_hash !== snapshot.catalogHash ||
        header.score_hash !== snapshot.scoreHash ||
        Number(header.score_ready) !== 1 ||
        Number(header.row_count) !== snapshot.rows?.length
      ) {
        entryProblems.push('header fields do not match the canonical snapshot');
      }
      if (scoreRows) {
        const scoreContentDigest = advisorySnapshotContentHash(scoreRows);
        if (
          Number(header.score_row_count) !== scoreRows.length ||
          header.score_content_digest !== scoreContentDigest
        ) {
          entryProblems.push('score projection counts or digest do not match the snapshot');
        }
        const expectedContentHash = compoundAdvisorySnapshotLedgerContentHash({
          capturedAt: snapshot.capturedAt,
          repository: snapshot.repository,
          target: snapshot.target,
          sourceHash: snapshot.sourceHash,
          catalogHash: snapshot.catalogHash,
          scoreHash: snapshot.scoreHash,
          rowCount: snapshot.rows.length,
          scoreRowCount: scoreRows.length,
          scoreContentDigest,
          snapshotJson: header.snapshot_json,
          previousContentHash: header.previous_content_hash ?? null,
        });
        if (header.content_hash !== expectedContentHash) {
          entryProblems.push('ledger content_hash does not match the canonical entry');
        }
      }

      const attachedRows = rowsBySnapshot.get(snapshotId) ?? [];
      if (attachedRows.length !== snapshot.rows?.length) {
        entryProblems.push(
          `stored row count ${attachedRows.length} != snapshot row count ` +
          `${snapshot.rows?.length ?? 'missing'}`,
        );
      } else {
        for (let index = 0; index < attachedRows.length; index++) {
          const stored = attachedRows[index];
          const expected = snapshot.rows[index];
          const expectedJson = canonicalCompoundAdvisoryRangeRowJson(expected);
          if (
            Number(stored.snapshot_id) !== snapshotId ||
            stored.range_identity !== expected.identity ||
            stored.ghsa_id !== expected.ghsaId ||
            stored.package_ecosystem !== expected.ecosystem ||
            stored.package_name !== expected.packageName ||
            stored.vulnerable_version_range !== expected.vulnerableVersionRange ||
            stored.state !== expected.state ||
            Number(stored.target_package) !== Number(expected.targetPackage) ||
            Number(stored.score_eligible) !== Number(expected.scoreEligible) ||
            Number(stored.audit_only) !== Number(expected.auditOnly) ||
            stored.row_json !== expectedJson ||
            stored.row_hash !== compoundAdvisorySnapshotRowContentHash(expected)
          ) {
            entryProblems.push(`stored row ${expected.identity} does not match snapshot_json`);
          }
        }
      }
    }
    if ((header.previous_content_hash ?? null) !== previousContentHash) {
      summary.chainFailureCount++;
      entryProblems.push('previous_content_hash does not match the prior ledger entry');
    }
    previousContentHash = header.content_hash;
    if (entryProblems.length > 0) {
      summary.headerFailureCount++;
      summary.rowFailureCount += entryProblems.filter((problem) =>
        problem.startsWith('stored row') ||
        problem.startsWith('stored row count')).length;
      for (const problem of entryProblems) {
        if (summary.problems.length >= 25) break;
        summary.problems.push(`snapshot ${snapshotId}: ${problem}`);
      }
    }
    latestMetadata = snapshot && scoreRows
      ? compoundAdvisoryMetadataFromHeader(header)
      : null;
    if (snapshot) snapshotsById.set(snapshotId, snapshot);
    if (scoreRows) scoreRowsById.set(snapshotId, scoreRows);
    if (latestMetadata) metadataById.set(snapshotId, latestMetadata);
    summary.latestSnapshotId = snapshotId;
  }

  const metadataRow = db.prepare(`SELECT value FROM meta WHERE key=?`)
    .get(ADVISORY_SNAPSHOT_V2_META_KEY);
  let currentMetadata = null;
  try {
    currentMetadata = metadataRow?.value ? JSON.parse(metadataRow.value) : null;
  } catch {
    currentMetadata = metadataRow?.value ?? null;
  }
  summary.latestMetadata = latestMetadata;
  const activeSnapshotId = Number(currentMetadata?.snapshotId);
  const activeMetadata = Number.isInteger(activeSnapshotId) && activeSnapshotId > 0
    ? metadataById.get(activeSnapshotId) ?? null
    : null;
  const activeSnapshot = Number.isInteger(activeSnapshotId) && activeSnapshotId > 0
    ? snapshotsById.get(activeSnapshotId) ?? null
    : null;
  const activeScoreRows = Number.isInteger(activeSnapshotId) && activeSnapshotId > 0
    ? scoreRowsById.get(activeSnapshotId) ?? null
    : null;
  summary.activeSnapshotId = Number.isInteger(activeSnapshotId) && activeSnapshotId > 0
    ? activeSnapshotId
    : null;
  summary.activeMetadata = activeMetadata;
  summary.stagedSnapshotCount = summary.activeSnapshotId == null
    ? headers.length
    : headers.filter((header) => Number(header.id) > summary.activeSnapshotId).length;
  if (
    !activeMetadata ||
    canonicalOperationJson(currentMetadata) !== canonicalOperationJson(activeMetadata)
  ) {
    summary.currentMetadataFailureCount = 1;
    summary.problems.push(
      'current advisory v2 metadata does not identify an intact ledger entry',
    );
  }

  const activeRows = db.prepare(`
    SELECT advisory_key, ghsa_id, cve_id, summary, severity, html_url, published_at,
           package_ecosystem, package_name, vulnerable_version_range, patched_versions
    FROM advisories
    ORDER BY advisory_key
  `).all().map(normalizeAdvisorySnapshotRow);
  if (
    !activeSnapshot ||
    !activeScoreRows ||
    canonicalOperationJson(activeRows) !== canonicalOperationJson(activeScoreRows) ||
    advisorySnapshotContentHash(activeRows) !== activeMetadata?.scoreContentDigest
  ) {
    summary.activeProjectionFailureCount = 1;
    summary.problems.push(
      'active advisory rows do not match the selected v2 score projection',
    );
  }

  summary.failedCount =
    summary.schemaFailureCount +
    summary.chainFailureCount +
    summary.headerFailureCount +
    summary.orphanRowCount +
    summary.currentMetadataFailureCount +
    summary.activeProjectionFailureCount;
  summary.problems = [...new Set(summary.problems)].slice(0, 25);
  return summary;
}

function compoundAdvisoryMetadataFromHeader(header) {
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

function advisorySnapshotSummary(db) {
  const v2 = compoundAdvisorySnapshotSummary(db);
  const currentSchema = requiredTableSchemaSummary(
    db,
    'advisories',
    [...ADVISORY_SNAPSHOT_ROW_COLUMNS.filter((column) => column !== 'snapshot_id'), 'fetched_at'],
  );
  const historySchema = requiredTableSchemaSummary(
    db,
    'advisory_snapshot_history',
    ADVISORY_SNAPSHOT_HISTORY_COLUMNS,
  );
  const rowSchema = requiredTableSchemaSummary(
    db,
    'advisory_snapshot_rows',
    ADVISORY_SNAPSHOT_ROW_COLUMNS,
  );
  const schemaFailureCount =
    (currentSchema.present ? currentSchema.missingColumns.length : 1) +
    (historySchema.present ? historySchema.missingColumns.length : 1) +
    (rowSchema.present ? rowSchema.missingColumns.length : 1);
  const summary = {
    expectedPackage: {
      ecosystem: 'npm',
      packageName: config.github.repo,
    },
    snapshotCount: historySchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM advisory_snapshot_history')
      : 0,
    rowCount: rowSchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM advisory_snapshot_rows')
      : 0,
    schema: {
      current: currentSchema,
      history: historySchema,
      rows: rowSchema,
    },
    schemaFailureCount,
    rowCountMismatchCount: 0,
    contentHashMismatchCount: 0,
    orphanRowCount: 0,
    malformedRowCount: 0,
    packageMismatchCount: 0,
    advisoryKeyMismatchCount: 0,
    duplicateCanonicalIdentityCount: 0,
    malformedRangeCount: 0,
    patchMetadataFailureCount: 0,
    latestSemanticFailureCount: 0,
    currentSemanticFailureCount: 0,
    currentStructuralFailureCount: 0,
    legacySemanticWarningCount: 0,
    legacySemanticSnapshotCount: 0,
    completenessProblemCount: 0,
    latestSnapshotMismatchCount: 0,
    completenessMetadata: null,
    failedCount: schemaFailureCount + v2.failedCount,
    v2,
    examples: {
      rowCountMismatches: [],
      contentHashMismatches: [],
      orphanRows: [],
      rowProblems: [],
      latestSemanticProblems: [],
      currentSemanticProblems: [],
      currentStructuralProblems: [],
      legacySemanticProblems: [],
      completenessProblems: [],
    },
  };
  if (schemaFailureCount > 0) return summary;

  const headers = db.prepare(`
    SELECT id, captured_at, row_count, content_hash
    FROM advisory_snapshot_history
    ORDER BY id
  `).all().map((row) => ({
    snapshotId: Number(row.id),
    capturedAt: row.captured_at,
    rowCount: Number(row.row_count),
    contentHash: String(row.content_hash ?? ''),
  }));
  const rows = db.prepare(`
    SELECT snapshot_id, advisory_key, ghsa_id, cve_id, summary, severity, html_url,
           published_at, package_ecosystem, package_name, vulnerable_version_range,
           patched_versions
    FROM advisory_snapshot_rows
    ORDER BY snapshot_id, advisory_key
  `).all().map((row) => ({
    snapshotId: Number(row.snapshot_id),
    content: normalizeAdvisorySnapshotRow(row),
  }));
  const rowsBySnapshot = new Map();
  for (const row of rows) {
    const snapshotRows = rowsBySnapshot.get(row.snapshotId) ?? [];
    snapshotRows.push(row.content);
    rowsBySnapshot.set(row.snapshotId, snapshotRows);
  }

  const headerIds = new Set(headers.map((header) => header.snapshotId));
  const orphanRows = rows.filter((row) => !headerIds.has(row.snapshotId));
  summary.orphanRowCount = orphanRows.length;
  summary.examples.orphanRows = orphanRows.slice(0, 10).map((row) => ({
    snapshotId: row.snapshotId,
    advisoryKey: row.content.advisory_key,
  }));

  for (const header of headers) {
    const attachedRows = rowsBySnapshot.get(header.snapshotId) ?? [];
    if (!Number.isInteger(header.rowCount) || header.rowCount < 0 ||
      header.rowCount !== attachedRows.length) {
      summary.rowCountMismatchCount++;
      if (summary.examples.rowCountMismatches.length < 10) {
        summary.examples.rowCountMismatches.push({
          snapshotId: header.snapshotId,
          expected: header.rowCount,
          actual: attachedRows.length,
        });
      }
    }
    const computedContentHash = advisorySnapshotContentHash(attachedRows);
    if (header.contentHash !== computedContentHash) {
      summary.contentHashMismatchCount++;
      if (summary.examples.contentHashMismatches.length < 10) {
        summary.examples.contentHashMismatches.push({
          snapshotId: header.snapshotId,
          expected: header.contentHash,
          actual: computedContentHash,
        });
      }
    }
  }

  const latestSnapshotId = headers.at(-1)?.snapshotId ?? null;
  const legacySemanticSnapshotIds = new Set();
  for (const [snapshotId, snapshotRows] of rowsBySnapshot) {
    const problems = advisorySnapshotRowProblems(snapshotRows, summary.expectedPackage);
    for (const problem of problems) {
      if (problem.code === 'malformed_row') summary.malformedRowCount++;
      if (problem.code === 'package_mismatch') summary.packageMismatchCount++;
      if (problem.code === 'advisory_key_mismatch') summary.advisoryKeyMismatchCount++;
      if (problem.code === 'duplicate_canonical_identity') {
        summary.duplicateCanonicalIdentityCount++;
      }
      if (problem.detail.startsWith('malformed_vulnerable_range:')) summary.malformedRangeCount++;
      if (
        problem.detail.startsWith('malformed_patch_metadata:') ||
        problem.detail.startsWith('patched_version_still_vulnerable:')
      ) {
        summary.patchMetadataFailureCount++;
      }
      const example = { snapshotId, ...problem };
      if (problem.code === 'malformed_row') {
        if (snapshotId === latestSnapshotId) {
          summary.latestSemanticFailureCount++;
          if (summary.examples.latestSemanticProblems.length < 10) {
            summary.examples.latestSemanticProblems.push(example);
          }
        } else {
          summary.legacySemanticWarningCount++;
          legacySemanticSnapshotIds.add(snapshotId);
          if (summary.examples.legacySemanticProblems.length < 10) {
            summary.examples.legacySemanticProblems.push(example);
          }
        }
      }
      if (summary.examples.rowProblems.length < 10) {
        summary.examples.rowProblems.push(example);
      }
    }
  }
  summary.legacySemanticSnapshotCount = legacySemanticSnapshotIds.size;

  const currentRows = db.prepare(`
    SELECT advisory_key, ghsa_id, cve_id, summary, severity, html_url, published_at,
           package_ecosystem, package_name, vulnerable_version_range, patched_versions
    FROM advisories
    ORDER BY advisory_key
  `).all().map(normalizeAdvisorySnapshotRow);
  const metadataRow = db.prepare(`SELECT value FROM meta WHERE key=?`).get(ADVISORY_SNAPSHOT_META_KEY);
  try {
    summary.completenessMetadata = metadataRow?.value ? JSON.parse(metadataRow.value) : null;
  } catch {
    summary.completenessMetadata = metadataRow?.value ?? null;
  }
  const currentRowProblems = advisorySnapshotRowProblems(
    currentRows,
    summary.expectedPackage,
  );
  for (const problem of currentRowProblems) {
    if (problem.code === 'malformed_row') {
      summary.currentSemanticFailureCount++;
      if (summary.examples.currentSemanticProblems.length < 10) {
        summary.examples.currentSemanticProblems.push(problem);
      }
    } else {
      summary.currentStructuralFailureCount++;
      if (summary.examples.currentStructuralProblems.length < 10) {
        summary.examples.currentStructuralProblems.push(problem);
      }
    }
  }
  const completenessProblems = advisorySnapshotCompletenessProblems(
    summary.completenessMetadata,
    currentRows,
    summary.expectedPackage,
  ).filter((problem) => problem.code !== 'row_problem');
  summary.completenessProblemCount = completenessProblems.length;
  summary.examples.completenessProblems = completenessProblems.slice(0, 10);
  const latestHeader = headers.at(-1) ?? null;
  if (
    !latestHeader ||
    latestHeader.rowCount !== currentRows.length ||
    latestHeader.contentHash !== advisorySnapshotContentHash(currentRows)
  ) {
    summary.latestSnapshotMismatchCount = 1;
  }

  summary.failedCount = summary.schemaFailureCount +
    summary.v2.failedCount +
    summary.rowCountMismatchCount +
    summary.contentHashMismatchCount +
    summary.orphanRowCount +
    summary.packageMismatchCount +
    summary.advisoryKeyMismatchCount +
    summary.duplicateCanonicalIdentityCount +
    summary.latestSemanticFailureCount +
    summary.currentSemanticFailureCount +
    summary.currentStructuralFailureCount +
    summary.completenessProblemCount +
    summary.latestSnapshotMismatchCount;
  return summary;
}

function scoreHistoryLedgerSummary(db) {
  const currentAuditColumns = ['authority_run_id'];
  const historyColumns = [
    'id', 'run_id', 'recorded_at', 'release_tag', 'scored_at',
    'score_model_version', 'prompt_version', 'final_score', 'status', 'band',
    'recommended', 'input_json', 'components_json', 'issue_evidence_json',
    'gate_evidence_json', 'source_identity_json', 'authority_run_id',
  ];
  const runColumns = [
    'id', 'run_id', 'recorded_at', 'row_count', 'rows_content_hash',
    'previous_content_hash', 'content_hash',
  ];
  const authorityRunColumns = [
    'authority_run_id', 'recorded_at', 'source_identity_schema_version',
    'source_identity_digest', 'content_hash',
  ];
  const historyV2SealColumns = [
    'history_run_id', 'authority_run_id', 'sealed_at', 'content_hash',
  ];
  const currentAuditSchema = requiredTableSchemaSummary(
    db,
    'release_score_audits',
    currentAuditColumns,
  );
  const historySchema = requiredTableSchemaSummary(
    db,
    'release_score_audit_history',
    historyColumns,
  );
  const runSchema = requiredTableSchemaSummary(
    db,
    'release_score_audit_history_runs',
    runColumns,
  );
  const authorityRunSchema = requiredTableSchemaSummary(
    db,
    'score_authority_resolution_runs',
    authorityRunColumns,
  );
  const historyV2SealSchema = requiredTableSchemaSummary(
    db,
    'release_score_audit_history_v2_seals',
    historyV2SealColumns,
  );
  const schemaFailureCount =
    (currentAuditSchema.present ? currentAuditSchema.missingColumns.length : 1) +
    (historySchema.present ? historySchema.missingColumns.length : 1) +
    (runSchema.present ? runSchema.missingColumns.length : 1) +
    (authorityRunSchema.present ? authorityRunSchema.missingColumns.length : 1) +
    (historyV2SealSchema.present ? historyV2SealSchema.missingColumns.length : 1);
  const summary = {
    historyRowCount: historySchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM release_score_audit_history')
      : 0,
    runCount: runSchema.present
      ? scalar(db, 'SELECT COUNT(*) FROM release_score_audit_history_runs')
      : 0,
    schema: {
      currentAudits: currentAuditSchema,
      history: historySchema,
      runs: runSchema,
      authorityRuns: authorityRunSchema,
      historyV2Seals: historyV2SealSchema,
    },
    schemaFailureCount,
    missingSealCount: 0,
    orphanSealCount: 0,
    chainFailureCount: 0,
    rowCountMismatchCount: 0,
    recordedAtMismatchCount: 0,
    rowsContentHashMismatchCount: 0,
    contentHashMismatchCount: 0,
    authorityRunBindingFailureCount: 0,
    canonicalTimestampFailureCount: 0,
    sourceManifestFailureCount: 0,
    currentTipSourceManifestFailureCount: 0,
    currentAuditHistoryMissingCount: 0,
    currentAuditHistoryMismatchCount: 0,
    currentHistoryAuditExtraCount: 0,
    latestRunId: null,
    latestContentHash: null,
    failedCount: schemaFailureCount,
    examples: [],
    authorityBindingProblems: [],
    canonicalTimestampProblems: [],
  };
  if (schemaFailureCount > 0) return summary;

  const historyRows = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    ORDER BY run_id, release_tag
  `).all();
  const rowsByRun = new Map();
  for (const row of historyRows) {
    const rows = rowsByRun.get(row.run_id) ?? [];
    rows.push(row);
    rowsByRun.set(row.run_id, rows);
    addCanonicalTimestampProblem(
      summary,
      `score history ${row.run_id}/${row.release_tag} recorded_at`,
      row.recorded_at,
    );
    addCanonicalTimestampProblem(
      summary,
      `score history ${row.run_id}/${row.release_tag} scored_at`,
      row.scored_at,
    );
    const manifestProblems = scoreSourceManifestProblems(row.source_identity_json);
    if (manifestProblems.length > 0) {
      summary.sourceManifestFailureCount++;
      if (summary.examples.length < 10) {
        summary.examples.push({
          code: 'invalid_source_manifest',
          runId: row.run_id,
          releaseTag: row.release_tag,
          problems: manifestProblems,
        });
      }
    }
  }
  const seals = db.prepare(`
    SELECT *
    FROM release_score_audit_history_runs
    ORDER BY id
  `).all();
  const sealsByRun = new Map(seals.map((seal) => [seal.run_id, seal]));
  const authorityRuns = db.prepare(`
    SELECT *
    FROM score_authority_resolution_runs
    ORDER BY rowid
  `).all();
  const authorityRunsById = new Map(
    authorityRuns.map((run) => [run.authority_run_id, run]),
  );
  const historyV2Seals = db.prepare(`
    SELECT *
    FROM release_score_audit_history_v2_seals
    ORDER BY id
  `).all();
  const historyV2SealsByRun = new Map(
    historyV2Seals.map((seal) => [seal.history_run_id, seal]),
  );
  for (const run of authorityRuns) {
    addCanonicalTimestampProblem(
      summary,
      `score authority run ${run.authority_run_id} recorded_at`,
      run.recorded_at,
    );
    if (!normalizedNonEmptyString(run.authority_run_id)) {
      addAuthorityBindingProblem(
        summary,
        'score authority run authority_run_id must be a non-null normalized string',
      );
    }
  }
  for (const seal of historyV2Seals) {
    addCanonicalTimestampProblem(
      summary,
      `score history v2 seal ${seal.history_run_id} sealed_at`,
      seal.sealed_at,
    );
    if (!normalizedNonEmptyString(seal.authority_run_id)) {
      addAuthorityBindingProblem(
        summary,
        `score history v2 seal ${seal.history_run_id} authority_run_id ` +
          'must be a non-null normalized string',
      );
    }
  }

  for (const runId of rowsByRun.keys()) {
    if (!sealsByRun.has(runId)) {
      summary.missingSealCount++;
      if (summary.examples.length < 10) summary.examples.push({ code: 'missing_seal', runId });
    }
  }
  for (const seal of seals) {
    if (!rowsByRun.has(seal.run_id)) {
      summary.orphanSealCount++;
      if (summary.examples.length < 10) {
        summary.examples.push({ code: 'orphan_seal', runId: seal.run_id });
      }
    }
  }

  let previousContentHash = null;
  for (const seal of seals) {
    addCanonicalTimestampProblem(
      summary,
      `score history run ${seal.run_id} recorded_at`,
      seal.recorded_at,
    );
    if ((seal.previous_content_hash ?? null) !== previousContentHash) {
      summary.chainFailureCount++;
      if (summary.examples.length < 10) {
        summary.examples.push({ code: 'chain_mismatch', runId: seal.run_id });
      }
    }
    const rows = rowsByRun.get(seal.run_id) ?? [];
    const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(rows);
    if (Number(seal.row_count) !== rows.length) summary.rowCountMismatchCount++;
    if (seal.rows_content_hash !== rowsContentHash) {
      summary.rowsContentHashMismatchCount++;
    }
    const contentHash = releaseScoreAuditHistoryRunContentHash({
      runId: seal.run_id,
      recordedAt: seal.recorded_at,
      rowCount: Number(seal.row_count),
      rowsContentHash: seal.rows_content_hash,
      previousContentHash: seal.previous_content_hash ?? null,
    });
    if (seal.content_hash !== contentHash) summary.contentHashMismatchCount++;
    const recordedAts = new Set(rows.map((row) => row.recorded_at));
    if (recordedAts.size !== 1 || !recordedAts.has(seal.recorded_at)) {
      summary.recordedAtMismatchCount++;
    }
    const authorityIds = rows.map((row) =>
      normalizedNonEmptyString(row.authority_run_id));
    const distinctAuthorityIds = new Set(authorityIds.filter(Boolean));
    if (
      authorityIds.some((authorityRunId) => authorityRunId == null) ||
      distinctAuthorityIds.size !== 1
    ) {
      addAuthorityBindingProblem(
        summary,
        `score history run ${seal.run_id} must bind every row to one non-null authority_run_id`,
      );
    }
    const authorityRunId = distinctAuthorityIds.size === 1
      ? [...distinctAuthorityIds][0]
      : null;
    const authorityRun = authorityRunId
      ? authorityRunsById.get(authorityRunId) ?? null
      : null;
    const historyV2Seal = historyV2SealsByRun.get(seal.run_id) ?? null;
    if (authorityRunId && !authorityRun) {
      addAuthorityBindingProblem(
        summary,
        `score history run ${seal.run_id} authority run ${authorityRunId} is missing`,
      );
    }
    if (!historyV2Seal) {
      addAuthorityBindingProblem(
        summary,
        `score history run ${seal.run_id} has no history v2 seal`,
      );
    } else if (
      !authorityRunId ||
      historyV2Seal.authority_run_id !== authorityRunId
    ) {
      addAuthorityBindingProblem(
        summary,
        `score history run ${seal.run_id} rows and v2 seal do not bind the same authority_run_id`,
      );
    }
    if (
      authorityRun &&
      (
        authorityRun.recorded_at !== seal.recorded_at ||
        historyV2Seal?.sealed_at !== seal.recorded_at
      )
    ) {
      addAuthorityBindingProblem(
        summary,
        `score history run ${seal.run_id}, authority run, and v2 seal timestamps must match exactly`,
      );
    }
    previousContentHash = seal.content_hash;
    summary.latestRunId = seal.run_id;
    summary.latestContentHash = seal.content_hash;
  }
  const scorePersistence = parseJson(
    getMetaValue(db, 'score_persistence_last_run'),
    null,
  );
  const currentRunId = scorePersistence?.schemaVersion === 2 &&
    typeof scorePersistence.historyRunId === 'string'
    ? scorePersistence.historyRunId
    : null;
  const currentHistoryRows = currentRunId ? rowsByRun.get(currentRunId) ?? [] : [];
  addCanonicalTimestampProblem(
    summary,
    'score persistence persistedAt',
    scorePersistence?.persistedAt,
  );
  addCanonicalTimestampProblem(
    summary,
    'score persistence minScoredAt',
    scorePersistence?.minScoredAt,
  );
  addCanonicalTimestampProblem(
    summary,
    'score persistence maxScoredAt',
    scorePersistence?.maxScoredAt,
  );
  for (const field of ['historyRecordedAt', 'commitNotBefore', 'commitNotAfter']) {
    addCanonicalTimestampProblem(
      summary,
      `score persistence commitTiming.${field}`,
      scorePersistence?.commitTiming?.[field],
    );
  }
  if (scorePersistence?.forecastPlan != null) {
    addCanonicalTimestampProblem(
      summary,
      'score persistence forecastPlan.preflightAt',
      scorePersistence.forecastPlan?.preflightAt,
    );
  }
  summary.currentTipSourceManifestFailureCount = currentHistoryRows.filter(
    (row) => scoreSourceManifestProblems(row.source_identity_json).length > 0,
  ).length;
  const currentAuditSourceIdentity = tableHasColumns(
    db,
    'release_score_audits',
    ['source_identity_json'],
  )
    ? 'source_identity_json'
    : 'NULL AS source_identity_json';
  const currentAudits = db.prepare(`
    SELECT release_tag, scored_at, score_model_version, prompt_version, final_score,
           status, band, recommended, input_json, components_json,
           issue_evidence_json, gate_evidence_json, ${currentAuditSourceIdentity},
           authority_run_id
    FROM release_score_audits
    ORDER BY release_tag
  `).all();
  const currentAuditByTag = new Map(currentAudits.map((row) => [row.release_tag, row]));
  const currentHistoryByTag = new Map(
    currentHistoryRows.map((row) => [row.release_tag, row]),
  );
  const currentAuthorityRunId = normalizedNonEmptyString(
    scorePersistence?.authorityRunId,
  );
  const currentHistoryAuthorityIds = new Set(
    currentHistoryRows
      .map((row) => normalizedNonEmptyString(row.authority_run_id))
      .filter(Boolean),
  );
  const currentHistoryV2Seal = currentRunId
    ? historyV2SealsByRun.get(currentRunId) ?? null
    : null;
  const currentAuthorityRun = currentAuthorityRunId
    ? authorityRunsById.get(currentAuthorityRunId) ?? null
    : null;
  if (!currentAuthorityRunId) {
    addAuthorityBindingProblem(
      summary,
      'score persistence authorityRunId must be a non-null normalized string',
    );
  }
  if (
    currentHistoryRows.length > 0 &&
    (
      currentHistoryAuthorityIds.size !== 1 ||
      !currentAuthorityRunId ||
      !currentHistoryAuthorityIds.has(currentAuthorityRunId)
    )
  ) {
    addAuthorityBindingProblem(
      summary,
      'current score history rows do not exactly bind score persistence authorityRunId',
    );
  }
  if (!currentAuthorityRun) {
    addAuthorityBindingProblem(
      summary,
      `current score authority run ${currentAuthorityRunId ?? 'missing'} does not exist`,
    );
  } else if (currentAuthorityRun.content_hash !== scorePersistence?.authorityRunContentHash) {
    addAuthorityBindingProblem(
      summary,
      'current score authority run content hash does not match score persistence metadata',
    );
  }
  if (
    !currentHistoryV2Seal ||
    currentHistoryV2Seal.authority_run_id !== currentAuthorityRunId ||
    currentHistoryV2Seal.content_hash !== scorePersistence?.historyV2SealContentHash
  ) {
    addAuthorityBindingProblem(
      summary,
      'current score history v2 seal does not exactly bind score persistence authority metadata',
    );
  }
  for (const audit of currentAudits) {
    addCanonicalTimestampProblem(
      summary,
      `current score audit ${audit.release_tag} scored_at`,
      audit.scored_at,
    );
    const historyRow = currentHistoryByTag.get(audit.release_tag);
    if (!historyRow) {
      summary.currentAuditHistoryMissingCount++;
      continue;
    }
    if (scoreAuditSemanticContent(audit) !== scoreAuditSemanticContent(historyRow)) {
      summary.currentAuditHistoryMismatchCount++;
    }
    if (
      !currentAuthorityRunId ||
      normalizedNonEmptyString(audit.authority_run_id) !== currentAuthorityRunId ||
      normalizedNonEmptyString(historyRow.authority_run_id) !== currentAuthorityRunId
    ) {
      addAuthorityBindingProblem(
        summary,
        `current score audit ${audit.release_tag}, history row, and metadata ` +
          'do not bind the same non-null authority_run_id',
      );
    }
  }
  for (const historyRow of currentHistoryRows) {
    if (!currentAuditByTag.has(historyRow.release_tag)) {
      summary.currentHistoryAuditExtraCount++;
    }
  }
  summary.failedCount = summary.schemaFailureCount +
    summary.missingSealCount +
    summary.orphanSealCount +
    summary.chainFailureCount +
    summary.rowCountMismatchCount +
    summary.recordedAtMismatchCount +
    summary.rowsContentHashMismatchCount +
    summary.contentHashMismatchCount +
    summary.authorityRunBindingFailureCount +
    summary.canonicalTimestampFailureCount +
    summary.currentTipSourceManifestFailureCount +
    summary.currentAuditHistoryMissingCount +
    summary.currentAuditHistoryMismatchCount +
    summary.currentHistoryAuditExtraCount;
  return summary;
}

function addAuthorityBindingProblem(summary, problem) {
  summary.authorityRunBindingFailureCount++;
  if (summary.authorityBindingProblems.length < 20) {
    summary.authorityBindingProblems.push(problem);
  }
}

function addCanonicalTimestampProblem(summary, context, value) {
  if (isCanonicalTimestamp(value)) return;
  summary.canonicalTimestampFailureCount++;
  if (summary.canonicalTimestampProblems.length < 20) {
    summary.canonicalTimestampProblems.push(
      `${context} must be canonical UTC millisecond time, got ${JSON.stringify(value ?? null)}`,
    );
  }
}

function normalizedNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0 && value.trim() === value
    ? value
    : null;
}

function operationArtifactLedgerRows(db) {
  const problems = [];
  const parseRows = (table, parser, label) =>
    db.prepare(`
      SELECT *
      FROM ${table}
      ORDER BY id
    `).all().flatMap((row) => {
      try {
        return [parser(row)];
      } catch (error) {
        problems.push(
          `${label} ${JSON.stringify(
            String(row.receipt_id ?? row.observation_id ?? row.id ?? 'unknown'),
          )} could not be reconstructed: ` +
          `${error instanceof Error ? error.message : String(error)}`,
        );
        return [];
      }
    });
  return {
    artifactReceipts: parseRows(
      'release_artifact_verification_receipts',
      releaseArtifactReceiptFromStorageRecord,
      'release artifact receipt',
    ),
    artifactObservations: parseRows(
      'release_artifact_verification_observations',
      releaseArtifactObservationFromStorageRecord,
      'release artifact observation',
    ),
    problems,
  };
}

export function operationReceiptSummary(db, now = new Date()) {
  const requiredColumns = {
    refresh_operation_attempts: [
      'run_id', 'operation', 'trigger', 'started_at', 'lease_name',
      'lease_holder_id', 'lease_expires_at', 'code_revision',
      'effective_config_json', 'effective_config_hash', 'content_hash',
    ],
    refresh_operation_stage_events: [
      'id', 'event_id', 'run_id', 'sequence', 'stage', 'status', 'occurred_at',
      'duration_ms', 'counts_json', 'details_json', 'previous_content_hash',
      'content_hash',
    ],
    refresh_capture_receipts: [
      'id', 'receipt_id', 'run_id', 'status', 'finished_at', 'duration_ms',
      'stage_event_count', 'stage_chain_hash', 'payload_json',
      'previous_content_hash', 'content_hash',
    ],
    release_artifact_verification_receipts: [
      'id', 'receipt_id', 'schema_version', 'release_repository', 'release_tag',
      'release_node_id', 'release_tag_commit_oid', 'release_published_at',
      'evidence_identity', 'canonical_receipt_json', 'previous_content_hash',
      'content_hash',
    ],
    release_artifact_verification_observations: [
      'id', 'observation_id', 'schema_version', 'run_id', 'observed_at',
      'release_repository', 'release_tag', 'release_node_id',
      'release_tag_commit_oid', 'release_published_at', 'receipt_id',
      'receipt_content_hash', 'canonical_observation_json',
      'previous_content_hash', 'content_hash',
    ],
    release_score_audit_history: [
      'id', 'run_id', 'recorded_at', 'release_tag', 'scored_at',
      'score_model_version', 'prompt_version', 'final_score', 'status', 'band',
      'recommended', 'input_json', 'components_json', 'issue_evidence_json',
      'gate_evidence_json', 'source_identity_json', 'authority_run_id',
    ],
    release_score_audit_history_runs: [
      'id', 'run_id', 'recorded_at', 'row_count', 'rows_content_hash',
      'previous_content_hash', 'content_hash',
    ],
    release_validation_forecasts: [
      'id', 'decision_id', 'opportunity_code', 'recorded_at',
      'latest_release_tag', 'latest_release_published_at', 'selected_tag',
      'audit_history_run_id', 'score_model_version', 'prompt_version',
      'policy_code', 'candidate_scores_json', 'decision_json',
      'source_identity_json', 'code_revision', 'previous_content_hash',
      'content_hash',
    ],
    score_authority_resolution_runs: [
      'authority_run_id', 'schema_version', 'policy_version',
      'source_identity_schema_version', 'source_identity_digest',
      'recorded_at', 'row_count', 'rows_content_hash',
      'previous_content_hash', 'content_hash',
    ],
    score_authority_resolution_rows: [
      'authority_run_id', 'row_ordinal', 'release_tag', 'issue_number',
      'subject_kind', 'subject_identity', 'candidate_id', 'authority', 'reason',
      'authorized_for_scoring', 'evidence_digest', 'resolution_json',
      'content_hash',
    ],
    release_score_audit_history_v2_seals: [
      'id', 'schema_version', 'history_run_id', 'authority_run_id', 'sealed_at',
      'history_row_count', 'history_rows_content_hash', 'authority_row_count',
      'authority_rows_content_hash', 'previous_content_hash', 'content_hash',
    ],
  };
  const schema = Object.fromEntries(
    Object.entries(requiredColumns).map(([table, columns]) => [
      table,
      requiredTableSchemaSummary(db, table, columns),
    ]),
  );
  const schemaFailureCount = Object.values(schema).reduce(
    (sum, table) => sum + (table.present ? table.missingColumns.length : 1),
    0,
  );
  const summary = {
    schema,
    schemaFailureCount,
    attemptCount: 0,
    stageEventCount: 0,
    receiptCount: 0,
    artifactReceiptCount: 0,
    artifactObservationCount: 0,
    successCount: 0,
    failureCount: 0,
    abandonedCount: 0,
    unterminatedRunIds: [],
    activeUnterminatedRunIds: [],
    invalidUnterminatedRunIds: [],
    hashChainFailureCount: 0,
    semanticFailureCount: 0,
    semanticLinkFailureCount: 0,
    ledgerFailureCount: 0,
    linkFailureCount: 0,
    currentScoreTipFailureCount: 0,
    failedCount: schemaFailureCount,
    problems: [],
  };
  if (schemaFailureCount > 0) return summary;

  const attempts = db.prepare(`
    SELECT *
    FROM refresh_operation_attempts
    ORDER BY started_at, run_id
  `).all();
  const stageEvents = db.prepare(`
    SELECT *
    FROM refresh_operation_stage_events
    ORDER BY run_id, sequence
  `).all();
  const receipts = db.prepare(`
    SELECT *
    FROM refresh_capture_receipts
    ORDER BY id
  `).all();
  const leases = db.prepare(`
    SELECT *
    FROM refresh_leases
    ORDER BY name
  `).all();
  const {
    problems: artifactLedgerProblems,
    ...artifactLedger
  } = operationArtifactLedgerRows(db);
  const verification = verifyOperationReceiptLedger({
    attempts,
    stageEvents,
    receipts,
    leases,
    ...artifactLedger,
    artifactMembershipPolicy: 'strict',
    observedAt: now.toISOString(),
  });
  summary.attemptCount = attempts.length;
  summary.stageEventCount = stageEvents.length;
  summary.receiptCount = receipts.length;
  summary.artifactReceiptCount = verification.artifactReceiptCount ?? 0;
  summary.artifactObservationCount = verification.artifactObservationCount ?? 0;
  summary.successCount = receipts.filter((receipt) => receipt.status === 'success').length;
  summary.failureCount = receipts.filter((receipt) => receipt.status === 'failure').length;
  summary.abandonedCount = receipts.filter((receipt) => receipt.status === 'abandoned').length;
  summary.unterminatedRunIds = verification.unterminatedRunIds;
  summary.activeUnterminatedRunIds = verification.activeUnterminatedRunIds;
  summary.invalidUnterminatedRunIds = verification.invalidUnterminatedRunIds;
  summary.hashChainFailureCount = verification.hashChainProblems.length;
  const ledgerProblems = [...new Set([
    ...artifactLedgerProblems,
    ...verification.problems,
  ])];
  summary.semanticFailureCount =
    artifactLedgerProblems.length + verification.semanticProblems.length;
  summary.ledgerFailureCount = ledgerProblems.length;
  summary.problems.push(...ledgerProblems);
  const authorityRowsByRun = new Map();
  for (const row of db.prepare(`
    SELECT *
    FROM score_authority_resolution_rows
    ORDER BY authority_run_id, row_ordinal
  `).all()) {
    const rows = authorityRowsByRun.get(row.authority_run_id) ?? [];
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
    authorityRowsByRun.set(row.authority_run_id, rows);
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
    rows: authorityRowsByRun.get(row.authority_run_id) ?? [],
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
  let validationProof = emptyDoctorReleaseValidationProofBundle();
  try {
    validationProof = readDoctorReleaseValidationProofBundle(db);
  } catch (error) {
    summary.semanticLinkFailureCount++;
    summary.problems.push(
      `release validation proof storage could not be reconstructed: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const semanticLinks = verifyOperationReceiptSemanticLinks({
    attempts,
    receipts,
    historyRows: db.prepare(`
      SELECT *
      FROM release_score_audit_history
      ORDER BY recorded_at, id
    `).all(),
    historyRuns: db.prepare(`
      SELECT *
      FROM release_score_audit_history_runs
      ORDER BY id
    `).all(),
    forecasts: db.prepare(`
      SELECT *
      FROM release_validation_forecasts
      ORDER BY id
    `).all(),
    authorityRuns,
    historyV2Seals,
    validationProof,
  });
  summary.semanticLinkFailureCount += semanticLinks.problems.length;
  summary.problems.push(...semanticLinks.problems);

  for (const receipt of receipts.filter((row) => row.status === 'success')) {
    const payload = parseJson(receipt.payload_json, null);
    const linkProblems = operationSuccessReceiptLinkProblems(db, receipt, payload);
    summary.linkFailureCount += linkProblems.length;
    summary.problems.push(...linkProblems);
  }
  summary.failedCount = summary.schemaFailureCount +
    summary.ledgerFailureCount +
    summary.semanticLinkFailureCount +
    summary.linkFailureCount;
  return summary;
}

function emptyDoctorReleaseValidationProofBundle() {
  return Object.fromEntries(
    RELEASE_VALIDATION_PROOF_RECORD_TABLES.map(({ key }) => [key, []]),
  );
}

function readDoctorReleaseValidationProofBundle(db) {
  const existingTables = new Set(
    db.prepare(`
      SELECT name
      FROM sqlite_schema
      WHERE type='table'
    `).all().map((row) => row.name),
  );
  const present = RELEASE_VALIDATION_PROOF_RECORD_TABLES.filter(({ table }) =>
    existingTables.has(table));
  if (present.length === 0) {
    return emptyDoctorReleaseValidationProofBundle();
  }
  if (present.length !== RELEASE_VALIDATION_PROOF_RECORD_TABLES.length) {
    throw new Error(
      `proof storage is partially migrated: ${present.length}/` +
      `${RELEASE_VALIDATION_PROOF_RECORD_TABLES.length} tables exist`,
    );
  }

  const bundle = emptyDoctorReleaseValidationProofBundle();
  for (const spec of RELEASE_VALIDATION_PROOF_RECORD_TABLES) {
    const rows = db.prepare(`
      SELECT
        rowid AS storage_ordinal,
        ${spec.idColumn} AS projected_id,
        content_hash AS projected_content_hash,
        record_json
      FROM ${spec.table}
      ORDER BY rowid
    `).all();
    for (const row of rows) {
      if (typeof row.record_json !== 'string') {
        throw new Error(
          `${spec.table} row ${row.storage_ordinal} has no record_json`,
        );
      }
      let record;
      try {
        record = JSON.parse(row.record_json);
      } catch (error) {
        throw new Error(
          `${spec.table} row ${row.storage_ordinal} has invalid record_json`,
          { cause: error },
        );
      }
      if (
        !record ||
        typeof record !== 'object' ||
        Array.isArray(record) ||
        row.record_json !== canonicalOperationJson(record)
      ) {
        throw new Error(
          `${spec.table} row ${row.storage_ordinal} has non-canonical record_json`,
        );
      }
      if (
        record[spec.idField] !== row.projected_id ||
        record.contentHash !== row.projected_content_hash
      ) {
        throw new Error(
          `${spec.table} row ${row.storage_ordinal} diverges from its ` +
          `immutable ID or content-hash projection`,
        );
      }
      bundle[spec.key].push(record);
    }
  }
  return bundle;
}

function operationSuccessReceiptLinkProblems(db, receipt, payload) {
  const prefix = `receipt ${receipt.receipt_id}`;
  const problems = [];
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return [`${prefix} success payload must be an object`];
  }
  const scoreHistory = payload.scoreHistory;
  const historyRunId = typeof scoreHistory?.runId === 'string'
    ? scoreHistory.runId
    : null;
  const historyContentHash = typeof scoreHistory?.contentHash === 'string'
    ? scoreHistory.contentHash
    : null;
  const historySeal = historyRunId
    ? db.prepare(`
        SELECT run_id, content_hash
        FROM release_score_audit_history_runs
        WHERE run_id=?
      `).get(historyRunId)
    : null;
  if (!historyRunId || !historyContentHash || !historySeal) {
    problems.push(`${prefix} is missing its score history run/seal link`);
  } else if (historySeal.content_hash !== historyContentHash) {
    problems.push(`${prefix} score history seal hash does not match`);
  }

  const releaseTags = Array.isArray(payload.releaseTags)
    ? payload.releaseTags.filter((tag) => typeof tag === 'string')
    : [];
  const historyTags = historyRunId
    ? db.prepare(`
        SELECT release_tag
        FROM release_score_audit_history
        WHERE run_id=?
        ORDER BY release_tag
      `).all(historyRunId).map((row) => row.release_tag)
    : [];
  if (
    releaseTags.length === 0 ||
    canonicalOperationJson([...releaseTags].sort()) !==
      canonicalOperationJson([...historyTags].sort())
  ) {
    problems.push(`${prefix} release tags do not match score history output`);
  }

  const recommendedTags = historyRunId
    ? db.prepare(`
        SELECT release_tag
        FROM release_score_audit_history
        WHERE run_id=? AND recommended=1
        ORDER BY release_tag
      `).all(historyRunId).map((row) => row.release_tag)
    : [];
  const selectedTag = payload.recommendation?.selectedTag ?? null;
  if (
    recommendedTags.length > 1 ||
    selectedTag !== (recommendedTags[0] ?? null)
  ) {
    problems.push(`${prefix} recommendation does not match score history output`);
  }

  const issueCrawl = payload.issueCrawl;
  if (
    issueCrawl?.metaKey !== 'issue_crawl_last_run' ||
    !issueCrawl.metadata ||
    typeof issueCrawl.metadataDigest !== 'string'
  ) {
    problems.push(`${prefix} is missing issue crawl metadata linkage`);
  } else {
    const digest = createHash('sha256')
      .update(canonicalOperationJson(issueCrawl.metadata))
      .digest('hex');
    if (digest !== issueCrawl.metadataDigest) {
      problems.push(`${prefix} issue crawl metadata digest does not match`);
    }
  }

  if (!isSha256Hex(payload.releaseCatalog?.digest)) {
    problems.push(`${prefix} release catalog digest is missing or malformed`);
  }
  problems.push(...scoreReceiptAdvisoryProblems(db, payload.advisoryCatalog, prefix));

  const forecast = payload.forecast;
  const decisionIds = Array.isArray(forecast?.decisionIds)
    ? forecast.decisionIds.filter((decisionId) => typeof decisionId === 'string')
    : [];
  const capturesByDecision = new Map(
    (Array.isArray(forecast?.captures) ? forecast.captures : [])
      .filter((capture) =>
        capture &&
        typeof capture === 'object' &&
        typeof capture.decisionId === 'string')
      .map((capture) => [capture.decisionId, capture]),
  );
  if (forecast?.eligibilityOutcome === 'not_eligible') {
    if (decisionIds.length !== 0) {
      problems.push(`${prefix} not-eligible forecast outcome must have no decision IDs`);
    }
  } else if (
    forecast?.eligibilityOutcome === 'eligible_and_captured' ||
    forecast?.eligibilityOutcome === 'already_captured'
  ) {
    if (decisionIds.length === 0) {
      problems.push(`${prefix} eligible forecast outcome has no decision IDs`);
    }
    for (const decisionId of decisionIds) {
      const capture = capturesByDecision.get(decisionId);
      const forecastRow = db.prepare(`
        SELECT audit_history_run_id
        FROM release_validation_forecasts
        WHERE decision_id=?
      `).get(decisionId);
      if (!forecastRow) {
        problems.push(`${prefix} forecast decision ${decisionId} is missing`);
      } else if (
        capture?.status === 'inserted' &&
        forecastRow.audit_history_run_id !== historyRunId
      ) {
        problems.push(
          `${prefix} newly inserted forecast decision ${decisionId} ` +
          'does not link to its score run',
        );
      } else if (
        capture?.status !== 'inserted' &&
        capture?.status !== 'already_captured'
      ) {
        problems.push(`${prefix} forecast decision ${decisionId} has invalid capture status`);
      }
    }
  } else {
    problems.push(`${prefix} forecast eligibility outcome is missing`);
  }
  return problems;
}

export function currentScoreReceiptProblems(db, meta) {
  const problems = [];
  const historyRunId = normalizedNonEmptyString(meta?.historyRunId);
  const historyOperationRunId = historyRunId?.startsWith('refresh:')
    ? normalizedNonEmptyString(historyRunId.slice('refresh:'.length))
    : null;
  const linkedReceipts = historyRunId
    ? db.prepare(`
        SELECT *
        FROM refresh_capture_receipts
        WHERE status='success'
        ORDER BY id
      `).all().flatMap((receipt) => {
        const payload = parseJson(receipt.payload_json, null);
        return payload?.scoreHistory?.runId === historyRunId
          ? [{ receipt, payload }]
          : [];
      })
    : [];
  const immutableRefreshReceipt = linkedReceipts.find(
    ({ payload }) => payload?.scoreMetadata?.source === 'refresh',
  ) ?? null;
  const expectsRefreshReceipt =
    meta?.source === 'refresh' ||
    meta?.operationReceiptRequired === true ||
    historyOperationRunId != null ||
    immutableRefreshReceipt != null;
  if (!expectsRefreshReceipt) return [];
  if (meta?.source !== 'refresh') {
    problems.push(
      'current score source does not match immutable refresh receipt/history semantics',
    );
  }
  if (meta.operationReceiptRequired !== true) {
    problems.push('current refresh score cannot disable operation receipt authorization');
  }
  if (linkedReceipts.length > 1) {
    problems.push(
      `current refresh score history tip is claimed by ${linkedReceipts.length} success receipts`,
    );
  }
  const runId = historyOperationRunId ??
    immutableRefreshReceipt?.receipt.run_id ??
    normalizedNonEmptyString(meta.operationRunId);
  if (!runId) return [...problems, 'current refresh score operationRunId is missing'];
  if (normalizedNonEmptyString(meta.operationRunId) !== runId) {
    problems.push(
      `current refresh score operationRunId does not match immutable history/receipt run ${runId}`,
    );
  }
  const attempt = db.prepare(`
    SELECT * FROM refresh_operation_attempts WHERE run_id=?
  `).get(runId);
  const receipt = db.prepare(`
    SELECT * FROM refresh_capture_receipts WHERE run_id=?
  `).get(runId);
  if (!attempt) problems.push(`current refresh score ${runId} has no operation attempt`);
  if (!receipt) return [...problems, `current refresh score ${runId} has no terminal receipt`];
  if (receipt.status !== 'success') {
    return [...problems, `current refresh score ${runId} terminal receipt is ${receipt.status}`];
  }
  const payload = parseJson(receipt.payload_json, null);
  problems.push(...operationSuccessReceiptLinkProblems(db, receipt, payload));
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return problems;
  if (
    payload.schemaVersion !== 1 &&
    payload.schemaVersion !== 2 &&
    payload.schemaVersion !== 3
  ) {
    problems.push('current refresh score receipt payload schema is unsupported');
  }
  if (
    Number(meta.sourceIdentitySchemaVersion ?? 0) >= 17 &&
    payload.schemaVersion !== 2 &&
    payload.schemaVersion !== 3
  ) {
    problems.push(
      'schema-17 current refresh score requires a release artifact publication receipt',
    );
  }
  const receiptScoreMetadata = payload.scoreMetadata;
  if (
    !receiptScoreMetadata ||
    typeof receiptScoreMetadata !== 'object' ||
    Array.isArray(receiptScoreMetadata)
  ) {
    problems.push('current refresh score receipt is missing immutable score metadata');
  } else {
    if (
      receiptScoreMetadata.schemaVersion !== 2 ||
      receiptScoreMetadata.source !== 'refresh' ||
      receiptScoreMetadata.operationReceiptRequired !== true ||
      receiptScoreMetadata.operationRunId !== receipt.run_id ||
      receiptScoreMetadata.historyRunId !== meta.historyRunId ||
      receiptScoreMetadata.historyRunContentHash !== meta.historyRunContentHash ||
      receiptScoreMetadata.authorityRunId !== meta.authorityRunId ||
      receiptScoreMetadata.authorityRunContentHash !== meta.authorityRunContentHash ||
      receiptScoreMetadata.historyV2SealContentHash !== meta.historyV2SealContentHash
    ) {
      problems.push(
        'current refresh score receipt metadata does not bind immutable refresh publication semantics',
      );
    }
    const currentComparableMetadata = { ...meta };
    delete currentComparableMetadata.publicationRecovery;
    if (
      canonicalOperationJson(receiptScoreMetadata) !==
      canonicalOperationJson(currentComparableMetadata)
    ) {
      problems.push(
        'current refresh score receipt metadata snapshot does not match current score metadata',
      );
    }
  }
  if (
    typeof meta.codeRevision !== 'string' ||
    attempt?.code_revision !== meta.codeRevision ||
    payload.codeRevision !== meta.codeRevision
  ) {
    problems.push('current refresh score code revision does not match attempt and receipt');
  }
  if (payload.operation !== attempt?.operation || payload.trigger !== attempt?.trigger) {
    problems.push('current refresh score operation/trigger does not match attempt');
  }
  const historySeal = db.prepare(`
    SELECT * FROM release_score_audit_history_runs WHERE run_id=?
  `).get(meta.historyRunId);
  const scoreHistory = payload.scoreHistory;
  if (
    scoreHistory?.runId !== meta.historyRunId ||
    scoreHistory?.contentHash !== meta.historyRunContentHash ||
    scoreHistory?.persistedAt !== historySeal?.recorded_at ||
    scoreHistory?.persistedAt !== meta.persistedAt
  ) {
    problems.push('current refresh score receipt does not bind the score history tip');
  }
  const scoreAuthority = payload.scoreAuthority;
  const authorityRun = db.prepare(`
    SELECT *
    FROM score_authority_resolution_runs
    WHERE authority_run_id=?
  `).get(meta.authorityRunId);
  const historyV2Seal = db.prepare(`
    SELECT *
    FROM release_score_audit_history_v2_seals
    WHERE history_run_id=?
  `).get(meta.historyRunId);
  if (
    scoreAuthority?.runId !== meta.authorityRunId ||
    scoreAuthority?.contentHash !== meta.authorityRunContentHash ||
    scoreAuthority?.historyV2SealContentHash !== meta.historyV2SealContentHash ||
    authorityRun?.content_hash !== meta.authorityRunContentHash ||
    historyV2Seal?.authority_run_id !== meta.authorityRunId ||
    historyV2Seal?.content_hash !== meta.historyV2SealContentHash
  ) {
    problems.push(
      'current refresh score receipt does not bind the authority run and history v2 seal',
    );
  }
  const commitProblems = releaseValidationScoreCommitTimingProblems(
    payload.scoreCommit,
    {
      recordedAt: payload.scoreCommit?.commitNotAfter ?? '',
      historyRunId: meta.historyRunId ?? '',
      historyRunContentHash: meta.historyRunContentHash ?? null,
      historyRecordedAt: historySeal?.recorded_at ?? null,
      authorityRunId: meta.authorityRunId ?? null,
      authorityRunContentHash: meta.authorityRunContentHash ?? null,
      historyV2SealContentHash: meta.historyV2SealContentHash ?? null,
    },
  );
  if (
    commitProblems.length > 0 ||
    canonicalOperationJson(payload.scoreCommit) !==
      canonicalOperationJson(meta.commitTiming)
  ) {
    problems.push(
      `current refresh score commit timing is invalid: ` +
      (commitProblems.join('; ') || 'metadata mismatch'),
    );
  }

  const issueMetadata = parseJson(
    db.prepare(`SELECT value FROM meta WHERE key='issue_crawl_last_run'`).get()?.value,
    null,
  );
  const issueDigest = issueMetadata
    ? createHash('sha256').update(canonicalOperationJson(issueMetadata)).digest('hex')
    : null;
  if (
    canonicalOperationJson(payload.issueCrawl?.metadata) !==
      canonicalOperationJson(issueMetadata) ||
    payload.issueCrawl?.metadataDigest !== issueDigest ||
    meta.issueCrawlMetadataDigest !== issueDigest
  ) {
    problems.push('current refresh score issue crawl digest is not authoritative');
  }

  problems.push(...scoreReceiptAdvisoryProblems(
    db,
    payload.advisoryCatalog,
    'current refresh score',
    { requireCurrent: true },
  ));

  const receiptAttestation = payload.releaseCatalog?.attestation;
  const catalogProblems = releaseCatalogAttestationProblems(receiptAttestation);
  const currentCatalog = currentActiveReleaseCatalogForDoctor(db);
  if (
    catalogProblems.length > 0 ||
    currentCatalog.problems.length > 0 ||
    canonicalOperationJson(receiptAttestation) !==
      canonicalOperationJson(meta.catalogAttestation) ||
    receiptAttestation?.localActiveCatalog?.digest !== currentCatalog.digest ||
    receiptAttestation?.localActiveCatalog?.releaseCount !== currentCatalog.releaseCount ||
    canonicalOperationJson(receiptAttestation?.latestStable) !==
      canonicalOperationJson(currentCatalog.latestStable)
  ) {
    problems.push(
      `current refresh score release catalog attestation is not authoritative: ` +
      ([...catalogProblems, ...currentCatalog.problems].join('; ') || 'current catalog mismatch'),
    );
  }

  problems.push(...currentScoreForecastReceiptProblems(db, meta, payload));
  return [...new Set(problems)];
}

function scoreReceiptAdvisoryProblems(
  db,
  advisoryCatalog,
  prefix,
  { requireCurrent = false } = {},
) {
  const currentSummary = requireCurrent
    ? compoundAdvisorySnapshotSummary(db)
    : null;
  if (currentSummary?.failedCount > 0) {
    return [
      `${prefix} advisory v2 ledger is not authoritative: ` +
      (currentSummary.problems.slice(0, 3).join('; ') || 'ledger integrity failure'),
    ];
  }
  if (!advisoryCatalog || typeof advisoryCatalog !== 'object' ||
    Array.isArray(advisoryCatalog)) {
    return [`${prefix} advisory v2 ledger is not authoritative: receipt catalog is missing`];
  }
  const receiptMetadata = advisoryCatalog.metadata;
  if (!receiptMetadata || typeof receiptMetadata !== 'object' ||
    Array.isArray(receiptMetadata)) {
    return [`${prefix} advisory v2 ledger is not authoritative: receipt metadata is missing`];
  }
  const snapshotId = advisoryCatalog.snapshotId;
  const header = Number.isSafeInteger(snapshotId) && snapshotId > 0
    ? db.prepare(`
        SELECT *
        FROM advisory_snapshot_v2_history
        WHERE id=?
      `).get(snapshotId)
    : null;
  const expectedMetadata = requireCurrent
    ? currentSummary?.activeMetadata
    : header
      ? compoundAdvisoryMetadataFromHeader(header)
      : null;
  const bindingProblems = expectedMetadata
    ? compoundAdvisoryReceiptBindingProblems(advisoryCatalog, expectedMetadata)
    : ['receipt references a missing advisory snapshot v2 ledger entry'];
  if (
    !expectedMetadata ||
    (requireCurrent && snapshotId !== currentSummary?.activeSnapshotId) ||
    bindingProblems.length > 0
  ) {
    return [
      `${prefix} advisory v2 ledger is not authoritative: ` +
      (bindingProblems.join('; ') || 'receipt metadata or ledger projection mismatch'),
    ];
  }
  return [];
}

function currentScoreForecastReceiptProblems(db, meta, payload) {
  const problems = [];
  const forecast = payload.forecast;
  const attestation = payload.releaseCatalog?.attestation;
  const latestTag = attestation?.latestStable?.tag;
  const latestPublishedAt = attestation?.latestStable?.publishedAt;
  const recordedAt = payload.scoreCommit?.commitNotAfter;
  const expectedCodes = Object.keys(RELEASE_VALIDATION_OPPORTUNITIES)
    .filter((opportunityCode) => releaseValidationForecastTiming({
      opportunity_code: opportunityCode,
      recorded_at: recordedAt,
      latest_release_published_at: latestPublishedAt,
    }).valid);
  const captures = Array.isArray(forecast?.captures) ? forecast.captures : [];
  if (
    canonicalOperationJson(captures.map((capture) => capture?.opportunityCode)) !==
    canonicalOperationJson(expectedCodes)
  ) {
    problems.push('current refresh score forecast capture set is not exact');
  }
  const planSlots = Array.isArray(meta.forecastPlan?.slots) ? meta.forecastPlan.slots : [];
  const preflightAtMs = Date.parse(meta.forecastPlan?.preflightAt ?? '');
  const expectedPlanCodes = Number.isFinite(preflightAtMs)
    ? Object.entries(RELEASE_VALIDATION_OPPORTUNITIES)
      .filter(([, opportunity]) =>
        preflightAtMs <
        Date.parse(latestPublishedAt) + opportunity.maxAgeHours * 3_600_000)
      .map(([opportunityCode]) => opportunityCode)
    : [];
  if (
    meta.forecastPlan?.schemaVersion !== 1 ||
    meta.forecastPlan?.preflightAt !== payload.scoreCommit?.commitNotBefore ||
    canonicalOperationJson(planSlots.map((slot) => slot?.opportunityCode)) !==
      canonicalOperationJson(expectedPlanCodes)
  ) {
    problems.push('current refresh score forecast preflight plan is invalid');
  }
  const historyRows = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    WHERE run_id=?
    ORDER BY release_tag
  `).all(meta.historyRunId);
  for (const capture of captures) {
    const row = db.prepare(`
      SELECT * FROM release_validation_forecasts WHERE decision_id=?
    `).get(capture?.decisionId);
    const decision = parseJson(row?.decision_json, null);
    const planned = planSlots.find((slot) =>
      slot?.opportunityCode === capture?.opportunityCode);
    if (
      !row ||
      decision?.schemaVersion !== 4 ||
      row.opportunity_code !== capture?.opportunityCode ||
      row.latest_release_tag !== latestTag ||
      row.latest_release_published_at !== latestPublishedAt ||
      row.score_model_version !== meta.scoreModelVersion ||
      row.prompt_version !== meta.promptVersion ||
      row.code_revision !== meta.codeRevision
    ) {
      problems.push(`current refresh score forecast ${capture?.decisionId ?? 'missing'} has the wrong slot`);
      continue;
    }
    if (capture.status === 'inserted') {
      if (row.audit_history_run_id !== meta.historyRunId || planned?.existingDecisionId != null) {
        problems.push(`current refresh score forecast ${row.decision_id} was not newly history-bound`);
      }
    } else if (capture.status === 'already_captured') {
      if (
        planned?.existingDecisionId !== row.decision_id ||
        planned?.existingContentHash !== row.content_hash ||
        !doctorForecastSemanticallyMatchesHistory(row, historyRows)
      ) {
        problems.push(`current refresh score forecast ${row.decision_id} is not an equivalent prior capture`);
      }
    } else {
      problems.push(`current refresh score forecast ${row.decision_id} has invalid capture status`);
    }
  }
  const decisionIds = captures.map((capture) => capture?.decisionId);
  const newDecisionIds = captures
    .filter((capture) => capture?.status === 'inserted')
    .map((capture) => capture?.decisionId);
  const existingDecisionIds = captures
    .filter((capture) => capture?.status === 'already_captured')
    .map((capture) => capture?.decisionId);
  if (
    canonicalOperationJson(forecast?.decisionIds ?? []) !== canonicalOperationJson(decisionIds) ||
    canonicalOperationJson(forecast?.newDecisionIds ?? []) !== canonicalOperationJson(newDecisionIds) ||
    canonicalOperationJson(forecast?.existingDecisionIds ?? []) !==
      canonicalOperationJson(existingDecisionIds)
  ) {
    problems.push('current refresh score forecast decision sets are invalid');
  }
  const expectedOutcome = captures.length === 0
    ? 'not_eligible'
    : newDecisionIds.length > 0
      ? 'eligible_and_captured'
      : 'already_captured';
  if (forecast?.eligibilityOutcome !== expectedOutcome) {
    problems.push('current refresh score forecast eligibility outcome is invalid');
  }
  return problems;
}

function doctorForecastSemanticallyMatchesHistory(forecast, historyRows) {
  const candidates = parseJson(forecast.candidate_scores_json, [])
    .map((candidate) => candidate?.auditSnapshot ?? candidate?.audit_snapshot)
    .filter((row) => row && typeof row === 'object' && !Array.isArray(row))
    .map(doctorForecastAuditSemantics)
    .sort((left, right) => String(left.release_tag).localeCompare(String(right.release_tag)));
  const current = historyRows
    .map(doctorForecastAuditSemantics)
    .sort((left, right) => String(left.release_tag).localeCompare(String(right.release_tag)));
  return canonicalOperationJson(candidates) === canonicalOperationJson(current);
}

function doctorForecastAuditSemantics(row) {
  return {
    release_tag: row.release_tag,
    score_model_version: row.score_model_version,
    prompt_version: row.prompt_version,
    final_score: row.final_score,
    status: row.status,
    band: row.band,
    recommended: row.recommended,
    input_json: row.input_json,
    components_json: row.components_json ?? null,
    issue_evidence_json: row.issue_evidence_json,
    gate_evidence_json: row.gate_evidence_json,
    source_identity_json: row.source_identity_json,
  };
}

export function releaseCatalogProvenanceSummary(db, options = {}) {
  const expectedRepository = `${config.github.owner}/${config.github.repo}`;
  const requiredColumns = {
    releases: [
      'catalog_rank',
      'node_id',
      'catalog_tag_commit_oid',
      'tag',
      'name',
      'published_at',
      'created_at',
      'updated_at',
      'html_url',
      'prerelease',
      'body',
      'catalog_digest',
      'catalog_active',
    ],
    release_catalog_capture_receipts: [
      'id',
      'receipt_id',
      'operation_run_id',
      'source_kind',
      'repository',
      'observed_at',
      'active_catalog_digest',
      'active_release_count',
      'payload_json',
      'previous_content_hash',
      'content_hash',
    ],
    refresh_operation_attempts: [
      'run_id',
      'operation',
      'started_at',
      'effective_config_json',
      'content_hash',
    ],
    refresh_capture_receipts: [
      'run_id',
      'status',
      'finished_at',
      'payload_json',
    ],
  };
  const schema = Object.fromEntries(
    Object.entries(requiredColumns).map(([table, columns]) => [
      table,
      requiredTableSchemaSummary(db, table, columns),
    ]),
  );
  const schemaProblems = Object.entries(schema).flatMap(([table, state]) => {
    if (!state.present) return [`release catalog provenance table ${table} is missing`];
    return state.missingColumns.map((column) =>
      `release catalog provenance table ${table} is missing column ${column}`);
  });
  const summary = {
    status: 'invalid',
    verifierInvoked: false,
    expectedRepository,
    schema,
    schemaFailureCount: schemaProblems.length,
    projectionProblemCount: 0,
    ledgerProblemCount: 0,
    currentProblemCount: 0,
    projectionProblems: [],
    ledgerProblems: [],
    currentProblems: [],
    omittedProjectionProblemCount: 0,
    omittedLedgerProblemCount: 0,
    omittedCurrentProblemCount: 0,
    receiptCount: 0,
    attemptCount: 0,
    terminalReceiptCount: 0,
    activeCatalog: null,
    latestReceipt: null,
    problemCount: schemaProblems.length,
    omittedProblemCount: Math.max(
      0,
      schemaProblems.length - RELEASE_CATALOG_PROBLEM_LIMIT,
    ),
    failedCount: schemaProblems.length,
    problems: schemaProblems.slice(0, RELEASE_CATALOG_PROBLEM_LIMIT),
  };
  if (schemaProblems.length > 0) return summary;

  const projection = currentActiveReleaseCatalogForDoctor(db);
  const activeCatalog = {
    digest: projection.digest,
    releaseCount: projection.releaseCount,
    stableCount: projection.stableCount,
    prereleaseCount: projection.prereleaseCount,
    tags: projection.tags,
    latestStable: projection.latestStable,
  };
  const receipts = db.prepare(`
    SELECT
      id, receipt_id, operation_run_id, source_kind, repository, observed_at,
      active_catalog_digest, active_release_count, payload_json,
      previous_content_hash, content_hash
    FROM release_catalog_capture_receipts
    ORDER BY id
  `).all();
  const attempts = db.prepare(`
    SELECT run_id, operation, started_at, effective_config_json, content_hash
    FROM refresh_operation_attempts
    ORDER BY started_at, run_id
  `).all();
  const terminalReceipts = db.prepare(`
    SELECT run_id, status, finished_at, payload_json
    FROM refresh_capture_receipts
    ORDER BY id
  `).all();
  let verification;
  try {
    verification = verifyReleaseCatalogCaptureReceiptLedger({
      receipts,
      attempts,
      terminalReceipts,
      expectedRepository,
      activeCatalog,
      allowTestFixture: options.allowTestFixture === true,
      pendingOperationRunId: null,
    });
  } catch (error) {
    const problem =
      `release catalog provenance verifier threw: ` +
      `${error instanceof Error ? error.message : String(error)}`;
    return {
      ...summary,
      verifierInvoked: true,
      projectionProblemCount: projection.problems.length,
      ledgerProblemCount: 1,
      projectionProblems: projection.problems.slice(
        0,
        RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
      ),
      ledgerProblems: [problem],
      omittedProjectionProblemCount: Math.max(
        0,
        projection.problems.length - RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
      ),
      receiptCount: receipts.length,
      attemptCount: attempts.length,
      terminalReceiptCount: terminalReceipts.length,
      activeCatalog: boundedReleaseCatalogProjection(projection),
      problemCount: projection.problems.length + 1,
      omittedProblemCount: Math.max(
        0,
        projection.problems.length + 1 - RELEASE_CATALOG_PROBLEM_LIMIT,
      ),
      failedCount: projection.problems.length + 1,
      problems: [
        ...projection.problems.map((item) =>
          `active release catalog projection: ${item}`),
        problem,
      ].slice(0, RELEASE_CATALOG_PROBLEM_LIMIT),
    };
  }

  const projectionProblems = projection.problems.map((problem) =>
    `active release catalog projection: ${problem}`);
  const allProblems = [
    ...new Set([
      ...projectionProblems,
      ...verification.problems,
    ]),
  ];
  const latestTerminal = verification.latestOperationRunId == null
    ? null
    : terminalReceipts.find((receipt) =>
      receipt.run_id === verification.latestOperationRunId) ?? null;
  return {
    ...summary,
    status: allProblems.length === 0 ? 'verified' : 'invalid',
    verifierInvoked: true,
    projectionProblemCount: projectionProblems.length,
    ledgerProblemCount: verification.ledgerProblems.length,
    currentProblemCount: verification.currentProblems.length,
    projectionProblems: projectionProblems.slice(
      0,
      RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
    ),
    ledgerProblems: verification.ledgerProblems.slice(
      0,
      RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
    ),
    currentProblems: verification.currentProblems.slice(
      0,
      RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
    ),
    omittedProjectionProblemCount: Math.max(
      0,
      projectionProblems.length - RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
    ),
    omittedLedgerProblemCount: Math.max(
      0,
      verification.ledgerProblems.length -
        RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
    ),
    omittedCurrentProblemCount: Math.max(
      0,
      verification.currentProblems.length -
        RELEASE_CATALOG_CATEGORY_PROBLEM_LIMIT,
    ),
    receiptCount: verification.receiptCount,
    attemptCount: attempts.length,
    terminalReceiptCount: terminalReceipts.length,
    activeCatalog: boundedReleaseCatalogProjection(projection),
    latestReceipt: verification.latestPayload == null
      ? null
      : {
          receiptId: verification.latestReceiptId,
          operationRunId: verification.latestOperationRunId,
          source: verification.latestSource,
          repository: verification.latestPayload.repository,
          observedAt: verification.latestPayload.observedAt,
          activeCatalogDigest:
            verification.latestPayload.activeCatalog.digest,
          activeReleaseCount:
            verification.latestPayload.activeCatalog.releaseCount,
          terminalStatus: latestTerminal?.status ?? null,
        },
    problemCount: allProblems.length,
    omittedProblemCount: Math.max(
      0,
      allProblems.length - RELEASE_CATALOG_PROBLEM_LIMIT,
    ),
    failedCount: allProblems.length,
    problems: allProblems.slice(0, RELEASE_CATALOG_PROBLEM_LIMIT),
  };
}

export function currentActiveReleaseCatalogForDoctor(db) {
  const rows = db.prepare(`
    SELECT catalog_rank, node_id, catalog_tag_commit_oid, tag, name, published_at,
           created_at, updated_at, html_url, prerelease, body, catalog_digest
    FROM releases
    WHERE catalog_active=1
    ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC, tag
  `).all();
  try {
    const projection = projectReleaseCatalogActiveRows(rows);
    const storedDigests = new Set(rows.map((row) => row.catalog_digest));
    const problems = [];
    if (rows.length === 0) {
      problems.push('active release catalog projection is empty');
    } else if (
      storedDigests.size !== 1 ||
      storedDigests.has(null) ||
      !storedDigests.has(projection.digest)
    ) {
      problems.push('active release catalog rows do not match their stored digest');
    }
    return {
      ...projection,
      problems,
    };
  } catch (error) {
    return {
      schemaVersion: 1,
      digest: null,
      releaseCount: rows.length,
      stableCount: rows.filter((row) => row.prerelease === 0).length,
      prereleaseCount: rows.filter((row) => row.prerelease === 1).length,
      tags: rows
        .map((row) => row.tag)
        .filter((tag) => typeof tag === 'string'),
      latestStable: null,
      problems: [
        `projection is invalid: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
}

function boundedReleaseCatalogProjection(projection) {
  const tags = Array.isArray(projection.tags) ? projection.tags : [];
  return {
    digest: projection.digest,
    releaseCount: projection.releaseCount,
    stableCount: projection.stableCount,
    prereleaseCount: projection.prereleaseCount,
    latestStable: projection.latestStable,
    tagSample: tags.slice(0, 10),
    omittedTagCount: Math.max(0, tags.length - 10),
  };
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function requiredTableSchemaSummary(db, table, requiredColumns) {
  const present = tablePresent(db, table);
  const existingColumns = present
    ? db.prepare(`PRAGMA table_info(${table})`).all().map((column) => column.name)
    : [];
  const existing = new Set(existingColumns);
  return {
    present,
    missingColumns: requiredColumns.filter((column) => !existing.has(column)),
  };
}

function normalizeAdvisorySnapshotRow(row) {
  return {
    advisory_key: requiredSnapshotString(row.advisory_key),
    ghsa_id: requiredSnapshotString(row.ghsa_id),
    cve_id: nullableSnapshotString(row.cve_id),
    summary: requiredSnapshotString(row.summary),
    severity: requiredSnapshotString(row.severity),
    html_url: requiredSnapshotString(row.html_url),
    published_at: nullableSnapshotString(row.published_at),
    package_ecosystem: nullableSnapshotString(row.package_ecosystem),
    package_name: nullableSnapshotString(row.package_name),
    vulnerable_version_range: nullableSnapshotString(row.vulnerable_version_range),
    patched_versions: nullableSnapshotString(row.patched_versions),
  };
}

function requiredSnapshotString(value) {
  return typeof value === 'string' ? value : '';
}

function nullableSnapshotString(value) {
  if (value == null) return null;
  return typeof value === 'string' ? value : null;
}

function validationLedgerSummary(db) {
  const requiredColumns = {
    release_validation_forecasts: [
      'id', 'decision_id', 'opportunity_code', 'recorded_at', 'latest_release_tag',
      'latest_release_published_at', 'selected_tag', 'audit_history_run_id',
      'score_model_version', 'prompt_version', 'policy_code', 'candidate_scores_json',
      'decision_json', 'source_identity_json', 'code_revision', 'previous_content_hash',
      'content_hash',
    ],
    release_validation_outcome_observations: [
      'id', 'observation_id', 'decision_id', 'horizon_code', 'observed_at', 'status',
      'outcome_json', 'source_identity_json', 'previous_content_hash', 'content_hash',
    ],
    release_score_audit_history: [
      'id', 'run_id', 'recorded_at', 'release_tag', 'scored_at', 'score_model_version',
      'prompt_version', 'final_score', 'status', 'band', 'recommended', 'input_json',
      'components_json', 'issue_evidence_json', 'gate_evidence_json',
      'source_identity_json', 'authority_run_id',
    ],
    release_score_audit_history_runs: [
      'id', 'run_id', 'recorded_at', 'row_count', 'rows_content_hash',
      'previous_content_hash', 'content_hash',
    ],
    score_authority_resolution_runs: [
      'authority_run_id', 'schema_version', 'policy_version',
      'source_identity_schema_version', 'source_identity_digest',
      'recorded_at', 'row_count', 'rows_content_hash',
      'previous_content_hash', 'content_hash',
    ],
    score_authority_resolution_rows: [
      'authority_run_id', 'row_ordinal', 'release_tag', 'issue_number',
      'subject_kind', 'subject_identity', 'candidate_id', 'authority', 'reason',
      'authorized_for_scoring', 'evidence_digest', 'resolution_json',
      'content_hash',
    ],
    release_score_audit_history_v2_seals: [
      'id', 'schema_version', 'history_run_id', 'authority_run_id', 'sealed_at',
      'history_row_count', 'history_rows_content_hash', 'authority_row_count',
      'authority_rows_content_hash', 'previous_content_hash', 'content_hash',
    ],
    advisory_snapshot_history: ADVISORY_SNAPSHOT_HISTORY_COLUMNS,
    advisory_snapshot_rows: ADVISORY_SNAPSHOT_ROW_COLUMNS,
    advisory_snapshot_v2_history: ADVISORY_SNAPSHOT_V2_HISTORY_COLUMNS,
    advisory_snapshot_v2_rows: ADVISORY_SNAPSHOT_V2_ROW_COLUMNS,
    refresh_operation_attempts: [
      'run_id', 'operation', 'trigger', 'started_at', 'lease_name',
      'lease_holder_id', 'lease_expires_at', 'code_revision',
      'effective_config_json', 'effective_config_hash', 'content_hash',
    ],
    refresh_operation_stage_events: [
      'id', 'event_id', 'run_id', 'sequence', 'stage', 'status', 'occurred_at',
      'duration_ms', 'counts_json', 'details_json', 'previous_content_hash',
      'content_hash',
    ],
    refresh_capture_receipts: [
      'id', 'receipt_id', 'run_id', 'status', 'finished_at', 'duration_ms',
      'stage_event_count', 'stage_chain_hash', 'payload_json',
      'previous_content_hash', 'content_hash',
    ],
    refresh_leases: [
      'name', 'holder_id', 'acquired_at', 'expires_at',
    ],
  };
  const schemaFailureCount = Object.entries(requiredColumns).reduce(
    (sum, [table, columns]) =>
      sum + Number(!tablePresent(db, table) || !tableHasColumns(db, table, columns)),
    0,
  );
  if (schemaFailureCount > 0) {
    return {
      forecastCount: 0,
      outcomeCount: 0,
      forecastChainFailureCount: 0,
      forecastHashFailureCount: 0,
      forecastContentHashFailureCount: 0,
      forecastDecisionIdFailureCount: 0,
      duplicateForecastSeriesCount: 0,
      forecastSeriesUniqueIndexFailureCount: 0,
      legacyLateForecastCount: 0,
      legacyDecisionSchemaCount: 0,
      missingAuditRunCount: 0,
      scoreAuthorityFailureCount: 0,
      authorityRunIntegrityFailureCount: 0,
      authorityChainFailureCount: 0,
      historyV2SealIntegrityFailureCount: 0,
      historyV2ChainFailureCount: 0,
      scoreAuthorityBindingFailureCount: 0,
      forecastSemanticFailureCount: 0,
      forecastSourceManifestFailureCount: 0,
      referencedHistorySourceManifestFailureCount: 0,
      legacyForecastSourceManifestWarningCount: 0,
      legacyReferencedHistorySourceManifestWarningCount: 0,
      legacyManifestCompatibilityWarningCount: 0,
      legacyManifestWarnings: [],
      outcomeChainFailureCount: 0,
      outcomeHashFailureCount: 0,
      outcomeContentHashFailureCount: 0,
      outcomeObservationIdFailureCount: 0,
      missingDecisionCount: 0,
      advisoryV2AuthorizationFailureCount: 0,
      advisorySnapshotProvenanceFailureCount: 0,
      authorizedAdvisoryV2SnapshotCount: 0,
      stagedAdvisoryV2SnapshotCount: 0,
      duplicateMaturedOutcomeCount: 0,
      maturedUniqueIndexFailureCount: 0,
      failedCount: schemaFailureCount,
    };
  }
  const forecasts = db.prepare(`
    SELECT *
    FROM release_validation_forecasts
    ORDER BY id
  `).all();
  const outcomes = db.prepare(`
    SELECT *
    FROM release_validation_outcome_observations
    ORDER BY id
  `).all();
  const auditHistory = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    ORDER BY recorded_at, id
  `).all();
  const auditHistoryRuns = db.prepare(`
    SELECT *
    FROM release_score_audit_history_runs
    ORDER BY id
  `).all();
  const authorityRowsByRun = new Map();
  for (const row of db.prepare(`
    SELECT *
    FROM score_authority_resolution_rows
    ORDER BY authority_run_id, row_ordinal
  `).all()) {
    const rows = authorityRowsByRun.get(row.authority_run_id) ?? [];
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
    authorityRowsByRun.set(row.authority_run_id, rows);
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
    rows: authorityRowsByRun.get(row.authority_run_id) ?? [],
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
  const legacyAdvisorySnapshots = buildAdvisorySnapshotValidationEvidence(
    db.prepare(`
      SELECT id, captured_at, row_count, content_hash
      FROM advisory_snapshot_history
      ORDER BY id
    `).all(),
    db.prepare(`
      SELECT snapshot_id, advisory_key, ghsa_id, cve_id, summary, severity, html_url,
             published_at, package_ecosystem, package_name, vulnerable_version_range,
             patched_versions
      FROM advisory_snapshot_rows
      ORDER BY snapshot_id, advisory_key
    `).all(),
  );
  const operationAttempts = db.prepare(`
    SELECT *
    FROM refresh_operation_attempts
    ORDER BY started_at, run_id
  `).all();
  const operationStageEvents = db.prepare(`
    SELECT *
    FROM refresh_operation_stage_events
    ORDER BY run_id, sequence
  `).all();
  const operationReceipts = db.prepare(`
    SELECT *
    FROM refresh_capture_receipts
    ORDER BY id
  `).all();
  const operationLeases = db.prepare(`
    SELECT *
    FROM refresh_leases
    ORDER BY name
  `).all();
  const {
    problems: operationArtifactLedgerProblems,
    ...operationArtifactLedger
  } = operationArtifactLedgerRows(db);
  const operationLedger = verifyOperationReceiptLedger({
    attempts: operationAttempts,
    stageEvents: operationStageEvents,
    receipts: operationReceipts,
    leases: operationLeases,
    ...operationArtifactLedger,
    artifactMembershipPolicy: 'strict',
    observedAt: new Date().toISOString(),
  });
  const compoundSnapshotProblems = [];
  const compoundSnapshots = db.prepare(`
    SELECT *
    FROM advisory_snapshot_v2_history
    ORDER BY id
  `).all().flatMap((header) => {
    try {
      const snapshot = JSON.parse(header.snapshot_json);
      return [{
        metadata: compoundAdvisoryMetadataFromHeader(header),
        scoreRows: compoundAdvisoryScoreRows(snapshot),
      }];
    } catch (error) {
      compoundSnapshotProblems.push(
        `advisory snapshot v2 ${header.id} cannot be reconstructed for validation: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
      return [];
    }
  });
  const advisoryAuthorization =
    compoundAdvisorySnapshotPublicationAuthorizations({
      snapshots: compoundSnapshots,
      attempts: operationAttempts.map((attempt) => ({
        runId: attempt.run_id,
        startedAt: attempt.started_at,
      })),
      receipts: operationReceipts.map((receipt) => ({
        receiptId: receipt.receipt_id,
        runId: receipt.run_id,
        status: receipt.status,
        finishedAt: receipt.finished_at,
        durationMs: Number(receipt.duration_ms),
        stageEventCount: Number(receipt.stage_event_count),
        stageChainHash: receipt.stage_chain_hash ?? null,
        payloadJson: receipt.payload_json,
      })),
      operationLedgerProblems: [
        ...operationArtifactLedgerProblems,
        ...operationLedger.problems,
      ],
    });
  const advisoryAuthorizationProblems = [
    ...compoundSnapshotProblems,
    ...advisoryAuthorization.problems,
  ];
  const advisorySnapshots = [
    ...legacyAdvisorySnapshots,
    ...buildCompoundAdvisorySnapshotValidationEvidence(
      compoundSnapshots,
      advisoryAuthorization.authorizations,
    ),
  ];
  const integrity = validateReleaseValidationLedgerIntegrity({
    forecasts,
    observations: outcomes,
    auditHistory,
    auditHistoryRuns,
    authorityRuns,
    historyV2Seals,
    advisorySnapshots,
    expectedAdvisoryPackage: {
      ecosystem: 'npm',
      packageName: config.github.repo,
    },
  });
  const legacyExcludedForecastIds = new Set(
    forecasts
      .filter(isLegacyDecisionSchemaForecast)
      .map((forecast) => forecast.decision_id),
  );
  const sourceManifestIntegrity = validationSourceManifestIntegrity(
    forecasts,
    auditHistory,
    legacyExcludedForecastIds,
  );
  const duplicateMaturedOutcomeCount = Number(db.prepare(`
    SELECT COUNT(*) AS count
    FROM (
      SELECT decision_id, horizon_code
      FROM release_validation_outcome_observations
      WHERE status='matured'
      GROUP BY decision_id, horizon_code
      HAVING COUNT(*) > 1
    )
  `).get()?.count ?? 0);
  const duplicateForecastSeriesCount = integrity.forecasts.duplicateSeriesIdentityCount;
  const legacyLateForecastCount = forecasts.filter(isLegacyOutOfWindowForecast).length;
  const legacyDecisionSchemaCount = legacyExcludedForecastIds.size;
  const forecastSeriesUniqueIndexFailureCount = hasForecastSeriesUniqueIndex(db) ? 0 : 1;
  const maturedUniqueIndexFailureCount = hasMaturedOutcomeUniqueIndex(db) ? 0 : 1;
  const forecastHashFailureCount = integrity.forecasts.contentHashFailureCount +
    integrity.forecasts.decisionIdFailureCount;
  const outcomeHashFailureCount = integrity.outcomes.contentHashFailureCount +
    integrity.outcomes.observationIdFailureCount;
  const missingAuditRunCount = integrity.forecasts.missingRunSealCount +
    integrity.forecasts.invalidRunSealCount;
  const failedCount = integrity.failedCount +
    advisoryAuthorizationProblems.length +
    sourceManifestIntegrity.failedCount +
    forecastSeriesUniqueIndexFailureCount +
    duplicateMaturedOutcomeCount +
    maturedUniqueIndexFailureCount;
  return {
    forecastCount: forecasts.length,
    outcomeCount: outcomes.length,
    forecastChainFailureCount: integrity.forecasts.chainFailureCount,
    forecastHashFailureCount,
    forecastContentHashFailureCount: integrity.forecasts.contentHashFailureCount,
    forecastDecisionIdFailureCount: integrity.forecasts.decisionIdFailureCount,
    duplicateForecastSeriesCount,
    forecastSeriesUniqueIndexFailureCount,
    legacyLateForecastCount,
    legacyDecisionSchemaCount,
    missingAuditRunCount,
    scoreAuthorityFailureCount: integrity.scoreAuthority.failedCount,
    authorityRunIntegrityFailureCount:
      integrity.scoreAuthority.authorityRunIntegrityFailureCount,
    authorityChainFailureCount:
      integrity.scoreAuthority.authorityChainFailureCount,
    historyV2SealIntegrityFailureCount:
      integrity.scoreAuthority.historyV2SealIntegrityFailureCount,
    historyV2ChainFailureCount:
      integrity.scoreAuthority.historyV2ChainFailureCount,
    scoreAuthorityBindingFailureCount:
      integrity.scoreAuthority.missingAuthorityRunReferenceCount +
      integrity.scoreAuthority.missingHistoryRunReferenceCount +
      integrity.scoreAuthority.bindingMismatchCount,
    forecastSemanticFailureCount:
      integrity.forecasts.provenanceFailureCount + sourceManifestIntegrity.failedCount,
    forecastSourceManifestFailureCount:
      sourceManifestIntegrity.forecastSourceManifestFailureCount,
    referencedHistorySourceManifestFailureCount:
      sourceManifestIntegrity.referencedHistorySourceManifestFailureCount,
    legacyForecastSourceManifestWarningCount:
      sourceManifestIntegrity.legacyForecastSourceManifestWarningCount,
    legacyReferencedHistorySourceManifestWarningCount:
      sourceManifestIntegrity.legacyReferencedHistorySourceManifestWarningCount,
    legacyManifestCompatibilityWarningCount:
      sourceManifestIntegrity.legacyManifestCompatibilityWarningCount,
    legacyManifestWarnings: sourceManifestIntegrity.warnings,
    outcomeChainFailureCount: integrity.outcomes.chainFailureCount,
    outcomeHashFailureCount,
    outcomeContentHashFailureCount: integrity.outcomes.contentHashFailureCount,
    outcomeObservationIdFailureCount: integrity.outcomes.observationIdFailureCount,
    missingDecisionCount: integrity.outcomes.missingDecisionCount,
    advisoryV2AuthorizationFailureCount: advisoryAuthorizationProblems.length,
    advisorySnapshotProvenanceFailureCount:
      integrity.advisorySnapshots.provenanceFailureCount,
    authorizedAdvisoryV2SnapshotCount:
      advisoryAuthorization.authorizedSnapshotIds.length,
    stagedAdvisoryV2SnapshotCount:
      advisoryAuthorization.stagedSnapshotIds.length,
    duplicateMaturedOutcomeCount,
    maturedUniqueIndexFailureCount,
    errors: [
      ...integrity.errors,
      ...advisoryAuthorizationProblems,
      ...sourceManifestIntegrity.errors,
    ],
    failedCount,
  };
}

function validationSourceManifestIntegrity(
  forecasts,
  auditHistory,
  legacyExcludedForecastIds,
) {
  const historyByRun = new Map();
  for (const row of auditHistory) {
    const rows = historyByRun.get(row.run_id) ?? [];
    rows.push(row);
    historyByRun.set(row.run_id, rows);
  }
  const errors = [];
  const warnings = [];
  let forecastSourceManifestFailureCount = 0;
  let referencedHistorySourceManifestFailureCount = 0;
  let legacyForecastSourceManifestWarningCount = 0;
  let legacyReferencedHistorySourceManifestWarningCount = 0;
  for (const forecast of forecasts) {
    const legacyExcluded = legacyExcludedForecastIds.has(forecast.decision_id);
    const forecastAssessment = scoreSourceManifestAssessment(forecast.source_identity_json);
    if (forecastAssessment.strictProblems.length > 0) {
      if (legacyExcluded && forecastAssessment.obsoleteStructurallyValid) {
        legacyForecastSourceManifestWarningCount++;
        warnings.push(
          `Forecast ${forecast.decision_id} uses obsolete source schema ` +
          `${forecastAssessment.schemaVersion}`,
        );
      } else {
        forecastSourceManifestFailureCount++;
        const problems = legacyExcluded && forecastAssessment.obsoleteProblems.length > 0
          ? [
              ...forecastAssessment.strictProblems,
              ...forecastAssessment.obsoleteProblems.map((problem) =>
                `obsolete manifest structure: ${problem}`),
            ]
          : forecastAssessment.strictProblems;
        errors.push(
          `Forecast ${forecast.decision_id} source identity is invalid: ` +
          problems.join(', '),
        );
      }
    }
    for (const historyRow of historyByRun.get(forecast.audit_history_run_id) ?? []) {
      const historyAssessment = scoreSourceManifestAssessment(historyRow.source_identity_json);
      if (historyAssessment.strictProblems.length === 0) continue;
      if (legacyExcluded && historyAssessment.obsoleteStructurallyValid) {
        legacyReferencedHistorySourceManifestWarningCount++;
        warnings.push(
          `Forecast ${forecast.decision_id} references ${historyRow.run_id}/` +
          `${historyRow.release_tag} with obsolete source schema ` +
          `${historyAssessment.schemaVersion}`,
        );
      } else {
        referencedHistorySourceManifestFailureCount++;
        const problems = legacyExcluded && historyAssessment.obsoleteProblems.length > 0
          ? [
              ...historyAssessment.strictProblems,
              ...historyAssessment.obsoleteProblems.map((problem) =>
                `obsolete manifest structure: ${problem}`),
            ]
          : historyAssessment.strictProblems;
        errors.push(
          `Forecast ${forecast.decision_id} references invalid history provenance ` +
          `${historyRow.run_id}/${historyRow.release_tag}: ` +
          problems.join(', '),
        );
      }
    }
  }
  return {
    forecastSourceManifestFailureCount,
    referencedHistorySourceManifestFailureCount,
    legacyForecastSourceManifestWarningCount,
    legacyReferencedHistorySourceManifestWarningCount,
    legacyManifestCompatibilityWarningCount:
      legacyForecastSourceManifestWarningCount +
      legacyReferencedHistorySourceManifestWarningCount,
    failedCount:
      forecastSourceManifestFailureCount +
      referencedHistorySourceManifestFailureCount,
    errors,
    warnings,
  };
}

function isLegacyOutOfWindowForecast(forecast) {
  const decision = parseJson(forecast.decision_json, {});
  const timing = releaseValidationForecastTiming(forecast);
  return Number(decision?.schemaVersion ?? 2) < 3 &&
    (timing.reason === 'before_window' || timing.reason === 'after_window');
}

function isLegacyDecisionSchemaForecast(forecast) {
  const decision = parseJson(forecast.decision_json, {});
  return Number(decision?.schemaVersion ?? 0) !== 4;
}

function hasForecastSeriesUniqueIndex(db) {
  const withoutRevision = [
    'opportunity_code',
    'latest_release_tag',
    'score_model_version',
    'prompt_version',
  ];
  const withRevision = [...withoutRevision, 'code_revision'];
  const legacyColumns = ['opportunity_code', 'latest_release_tag'];
  const fullUniqueIndexes = db.prepare(`
    PRAGMA index_list(release_validation_forecasts)
  `).all().filter((index) => Number(index.unique) === 1);
  const keyColumns = (index) => db.prepare(
    `PRAGMA index_xinfo("${String(index.name).replaceAll('"', '""')}")`,
  ).all()
    .filter((column) => Number(column.key) === 1)
    .sort((left, right) => Number(left.seqno) - Number(right.seqno))
    .map((column) => column.name);
  const indexSql = (index) => String(db.prepare(`
    SELECT sql FROM sqlite_schema WHERE type='index' AND name=?
  `).get(index.name)?.sql ?? '').trim();
  const hasWithoutRevision = fullUniqueIndexes.some((index) =>
    Number(index.partial) === 1 &&
    JSON.stringify(keyColumns(index)) === JSON.stringify(withoutRevision) &&
    /WHERE\s+code_revision\s+IS\s+NULL\s*$/i.test(indexSql(index)));
  const hasWithRevision = fullUniqueIndexes.some((index) =>
    Number(index.partial) === 1 &&
    JSON.stringify(keyColumns(index)) === JSON.stringify(withRevision) &&
    /WHERE\s+code_revision\s+IS\s+NOT\s+NULL\s*$/i.test(indexSql(index)));
  const hasLegacy = fullUniqueIndexes.some((index) => {
    if (Number(index.partial) !== 0) return false;
    const columns = keyColumns(index);
    return (
      columns.length === legacyColumns.length &&
      legacyColumns.every((column) => columns.includes(column)
    )) || JSON.stringify(columns) === JSON.stringify(withoutRevision);
  });
  return hasWithoutRevision && hasWithRevision && !hasLegacy;
}

function hasMaturedOutcomeUniqueIndex(db) {
  const indexes = db.prepare(`
    PRAGMA index_list(release_validation_outcome_observations)
  `).all();
  return indexes.some((index) => {
    if (Number(index.unique) !== 1 || Number(index.partial) !== 1) return false;
    const columns = db.prepare(
      `PRAGMA index_info("${String(index.name).replaceAll('"', '""')}")`,
    ).all().map((column) => column.name);
    if (JSON.stringify(columns) !== JSON.stringify(['decision_id', 'horizon_code'])) return false;
    const sql = String(db.prepare(`
      SELECT sql
      FROM sqlite_schema
      WHERE type='index' AND name=?
    `).get(index.name)?.sql ?? '');
    return /WHERE\s+status\s*=\s*['"]matured['"]\s*$/i.test(sql.trim());
  });
}

function tablePresent(db, table) {
  return !!db.prepare(`
    SELECT 1 AS present
    FROM sqlite_master
    WHERE type='table' AND name=?
  `).get(table);
}

function recommendationSummary(db) {
  const scoredStableCount = scalar(db, `
    SELECT COUNT(*) FROM releases
    WHERE prerelease=0 AND catalog_active=1 AND final_score IS NOT NULL
  `);
  const recommendedRows = db.prepare(`
    SELECT tag, final_score, state, scored_at
    FROM releases
    WHERE prerelease=0 AND catalog_active=1 AND final_score IS NOT NULL AND recommended=1
    ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC
  `).all();
  const qualifyingStableCount = scalar(db, `
    SELECT COUNT(*) FROM releases
    WHERE prerelease=0
      AND catalog_active=1
      AND state='eligible'
      AND final_score >= ${REC_THRESHOLD}
  `);
  return {
    scoredStableCount,
    qualifyingStableCount,
    recommendedCount: recommendedRows.length,
    recommended: recommendedRows,
  };
}

function latestScoredStable(db) {
  const row = db.prepare(`
    SELECT r.tag, r.final_score, r.state, r.recommended, r.score_reason, r.scored_at,
           a.final_score AS audit_final_score,
           a.scored_at AS audit_scored_at,
           a.score_model_version,
           a.prompt_version
    FROM releases r
    LEFT JOIN release_score_audits a ON a.release_tag=r.tag
    WHERE r.prerelease=0
      AND r.catalog_active=1
      AND (
        r.final_score IS NOT NULL
        OR a.release_tag IS NOT NULL
      )
    ORDER BY r.catalog_rank IS NULL, r.catalog_rank, r.published_at DESC
    LIMIT 1
  `).get();
  if (!row) return null;
  return {
    tag: row.tag,
    finalScore: row.final_score,
    state: row.state,
    recommended: row.recommended === 1,
    reason: row.score_reason,
    scoredAt: row.scored_at,
    auditPresent: row.audit_scored_at != null,
    auditFinalScore: row.audit_final_score ?? null,
    auditScoredAt: row.audit_scored_at ?? null,
    modelVersion: row.score_model_version ?? null,
    promptVersion: row.prompt_version ?? null,
  };
}

function getAudit(db, tag) {
  return db.prepare(`SELECT * FROM release_score_audits WHERE release_tag=?`).get(tag);
}

function coverageSummary(input, issueEvidence) {
  return {
    rawIssueCount: Number(input.rawIssueCount ?? 0),
    classifiedIssueCount: Number(input.classifiedIssueCount ?? 0),
    evidenceCoverage: input.rawIssueCount > 0
      ? round(Number(input.classifiedIssueCount ?? 0) / Number(input.rawIssueCount ?? 0), 4)
      : 1,
    debtSummary: issueEvidence?.debtSummary ?? null,
    storedExamples: {
      verifiedDebt: Array.isArray(issueEvidence?.verifiedDebt) ? issueEvidence.verifiedDebt.length : 0,
      carryoverDebt: Array.isArray(issueEvidence?.carryoverDebt) ? issueEvidence.carryoverDebt.length : 0,
      staleDebt: Array.isArray(issueEvidence?.staleDebt) ? issueEvidence.staleDebt.length : 0,
      openedFeltSerious: Array.isArray(issueEvidence?.openedFeltSerious) ? issueEvidence.openedFeltSerious.length : 0,
      verifiedFixed: Array.isArray(issueEvidence?.verifiedFixed) ? issueEvidence.verifiedFixed.length : 0,
      unverifiedClosed: Array.isArray(issueEvidence?.unverifiedClosed) ? issueEvidence.unverifiedClosed.length : 0,
      unclassifiedIssues: Array.isArray(issueEvidence?.unclassifiedIssues) ? issueEvidence.unclassifiedIssues.length : 0,
    },
  };
}

function classificationProvenanceSummary(db, audit) {
  const promptVersion = Number(audit?.prompt_version);
  if (!Number.isInteger(promptVersion)) {
    return { rowCount: 0, legacyCount: 0, invalidCount: 1, failedCount: 1 };
  }
  const rows = db.prepare(`
    SELECT *
    FROM classifications
    WHERE prompt_version=?
    ORDER BY issue_number
  `).all(promptVersion);
  let legacyCount = 0;
  let invalidCount = 0;
  for (const row of rows) {
    if (row.classification_origin !== 'raw_model') legacyCount++;
    if (rawClassificationStorageProblems(row, promptVersion).length > 0) invalidCount++;
  }
  return {
    rowCount: rows.length,
    legacyCount,
    invalidCount,
    failedCount: legacyCount + invalidCount,
  };
}

function freshnessSummary(db, tag, scoredAt, now) {
  const issueUniverse = issueUniverseFreshness(db, tag);
  const issueObservationColumn = tableHasColumns(db, 'issues', ['checked_at']) ? 'checked_at' : 'fetched_at';
  const issueFetchFreshnessSql = tableHasColumns(db, 'issues', [issueObservationColumn])
    ? `
    UNION ALL SELECT 'issue_fetches', COUNT(*), COALESCE(SUM(CASE WHEN ${issueObservationColumn} IS NULL THEN 1 ELSE 0 END), 0), MAX(${issueObservationColumn}) FROM issues`
    : '';
  const issueCommentFreshnessSql = tableHasColumns(db, 'issue_comment_snapshots', ['verified_at'])
    ? `
    UNION ALL SELECT 'issue_comments', COUNT(*), COALESCE(SUM(CASE WHEN verified_at IS NULL THEN 1 ELSE 0 END), 0), MAX(verified_at)
    FROM issue_comment_snapshots
    WHERE schema_version=${AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION}`
    : '';
  const issueStateSnapshotFreshnessSql = tableHasColumns(
    db,
    'issue_state_event_snapshots',
    ['verified_at'],
  )
    ? `
    UNION ALL SELECT 'issue_state_event_snapshots', COUNT(*),
      COALESCE(SUM(CASE WHEN verified_at IS NULL THEN 1 ELSE 0 END), 0),
      MAX(verified_at)
    FROM issue_state_event_snapshots`
    : '';
  const closureDependencySnapshotFreshnessSql = tableHasColumns(
    db,
    'release_closure_dependency_snapshots',
    ['captured_at'],
  )
    ? `
    UNION ALL SELECT 'release_closure_dependency_snapshots', COUNT(*),
      COALESCE(SUM(CASE WHEN captured_at IS NULL THEN 1 ELSE 0 END), 0),
      MAX(captured_at)
    FROM release_closure_dependency_snapshots`
    : '';
  const releaseRowsFreshnessSql = tableHasColumns(db, 'releases', [
    'release_metadata_fetched_at',
    'release_derived_fetched_at',
    'release_artifact_checked_at',
  ])
    ? `
    UNION ALL
    SELECT 'release_rows', COUNT(*) AS count, COALESCE(SUM(CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END), 0) AS nullCount, MAX(updated_at) AS maxAt
    FROM (
      SELECT release_metadata_fetched_at AS updated_at FROM releases WHERE catalog_active=1
      UNION ALL SELECT release_derived_fetched_at FROM releases WHERE catalog_active=1
      UNION ALL SELECT release_artifact_checked_at FROM releases WHERE catalog_active=1
    )`
    : '';
  const sourceRows = db.prepare(`
    SELECT 'issues' AS source, COUNT(*) AS count, COALESCE(SUM(CASE WHEN updated_at IS NULL THEN 1 ELSE 0 END), 0) AS nullCount, MAX(updated_at) AS maxAt FROM issues
    ${issueFetchFreshnessSql}
    ${issueCommentFreshnessSql}
    UNION ALL SELECT 'classifications', COUNT(*), COALESCE(SUM(CASE WHEN classified_at IS NULL THEN 1 ELSE 0 END), 0), MAX(classified_at) FROM classifications
    UNION ALL SELECT 'issue_label_events', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_label_events
    UNION ALL SELECT 'issue_label_snapshots', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_label_snapshots
    UNION ALL SELECT 'issue_closure_proofs', COUNT(*), COALESCE(SUM(CASE WHEN checked_at IS NULL THEN 1 ELSE 0 END), 0), MAX(checked_at) FROM issue_closure_proofs
    UNION ALL SELECT 'issue_closure_events', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_closure_events
    UNION ALL SELECT 'issue_reopen_events', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_reopen_events
    ${issueStateSnapshotFreshnessSql}
    UNION ALL SELECT 'issue_pr_links', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_pr_links
    UNION ALL SELECT 'issue_commit_references', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM issue_commit_references
    UNION ALL SELECT 'pull_request_fixes', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM pull_request_fixes
    UNION ALL SELECT 'release_pr_reachability', COUNT(*), COALESCE(SUM(CASE WHEN checked_at IS NULL THEN 1 ELSE 0 END), 0), MAX(checked_at) FROM release_pr_reachability
    ${closureDependencySnapshotFreshnessSql}
    ${releaseRowsFreshnessSql}
    UNION ALL SELECT 'release_commits', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM release_commits
    UNION ALL SELECT 'advisories', COUNT(*), COALESCE(SUM(CASE WHEN fetched_at IS NULL THEN 1 ELSE 0 END), 0), MAX(fetched_at) FROM advisories
  `).all();
  const sourceFetchedAtMax = maxTimestamp(sourceRows.map((row) => row.maxAt ?? null));
  return {
    scoredAt,
    issueUniverseCount: issueUniverse.count,
    issueUpdatedAtMax: issueUniverse.issueUpdatedAtMax,
    issueUpdatedAgeHoursAtScore: ageHours(issueUniverse.issueUpdatedAtMax, scoredAt),
    issueUpdatedAgeHoursNow: ageHours(issueUniverse.issueUpdatedAtMax, now.toISOString()),
    sourceFetchedAtMax,
    sourceFetchedAgeHoursAtScore: ageHours(sourceFetchedAtMax, scoredAt),
    sources: sourceRows.map((row) => ({
      source: row.source,
      count: Number(row.count ?? 0),
      nullCount: Number(row.nullCount ?? 0),
      maxAt: row.maxAt ?? null,
      ageHoursAtScore: ageHours(row.maxAt ?? null, scoredAt),
    })),
  };
}

function issueUniverseFreshness(db, tag) {
  const row = db.prepare(`
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
    SELECT COUNT(*) AS count, MAX(i.updated_at) AS issueUpdatedAtMax
    FROM issues i
    JOIN target
    WHERE target.start_at IS NOT NULL
      AND EXISTS (
        SELECT 1
        FROM issue_open_intervals interval
        WHERE interval.issue_number=i.number
          AND interval.open_at < target.end_at
          AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
      )
  `).get(tag);
  return {
    count: Number(row?.count ?? 0),
    issueUpdatedAtMax: row?.issueUpdatedAtMax ?? null,
  };
}

function stateSnapshotSummary(db, tag, exampleLimit = 10) {
  const requiredColumns = {
    releases: ['tag', 'published_at', 'prerelease'],
    issues: ['number', 'node_id', 'state', 'updated_at', 'closed_at', 'created_at'],
    issue_closure_events: [
      'issue_number', 'issue_node_id', 'event_id', 'closed_at', 'connection_ordinal',
      'actor_node_id', 'actor_login', 'actor_type', 'state_reason',
      'closer_node_id', 'closer_type', 'closer_number', 'closer_oid',
    ],
    issue_reopen_events: [
      'issue_number', 'issue_node_id', 'event_id', 'reopened_at', 'connection_ordinal',
      'actor_node_id', 'actor_login', 'actor_type',
    ],
    issue_state_event_snapshots: [
      'issue_number',
      'repository_node_id',
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
      'verified_at',
    ],
  };
  const schema = Object.fromEntries(
    Object.entries(requiredColumns).map(([table, columns]) => [
      table,
      requiredTableSchemaSummary(db, table, columns),
    ]),
  );
  const schemaFailureCount = Object.values(schema).reduce(
    (sum, table) => sum + (table.present ? table.missingColumns.length : 1),
    0,
  );
  const summary = {
    tag,
    candidateIssueCount: 0,
    schema,
    schemaFailureCount,
    missingSnapshotCount: 0,
    invalidSnapshotCount: 0,
    metadataMismatchCount: 0,
    projectionMismatchCount: 0,
    latestStateMismatchCount: 0,
    failedCount: schemaFailureCount,
    examples: [],
  };
  if (schemaFailureCount > 0) return summary;

  const rows = db.prepare(`
    WITH target AS (
      SELECT
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
      SELECT issue_number, event_type
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
      snapshot.verified_at,
      COALESCE(projection.closure_count, 0) +
        COALESCE(projection.reopen_count, 0) AS projection_count,
      latest.event_type AS latest_event_type
    FROM candidates candidate
    LEFT JOIN issue_state_event_snapshots snapshot
      ON snapshot.issue_number=candidate.number
    LEFT JOIN projection_counts projection
      ON projection.issue_number=candidate.number
    LEFT JOIN latest_events latest
      ON latest.issue_number=candidate.number
    ORDER BY candidate.number
  `).all(tag);
  summary.candidateIssueCount = rows.length;
  const projectedEventsByIssue = projectedIssueStateEventsForIssues(
    db,
    rows.map((row) => Number(row.issue_number)),
  );

  const addExample = (kind, issueNumber, detail) => {
    if (summary.examples.length < exampleLimit) {
      summary.examples.push({ kind, issueNumber, detail });
    }
  };
  for (const row of rows) {
    const issueNumber = Number(row.issue_number);
    if (row.schema_version == null) {
      summary.missingSnapshotCount++;
      addExample('missing', issueNumber, 'issue is missing a verified state-event snapshot');
      continue;
    }
    const events = parseJson(row.events_json, null);
    const eventArray = Array.isArray(events) ? events : null;
    let normalizedEvents = null;
    let digestMatches = false;
    let authorityMatches = false;
    let stabilizationMatches = false;
    if (eventArray) {
      try {
        normalizedEvents = normalizeIssueStateEvents(eventArray);
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
      eventArray === null ||
      eventArray.length !== totalCount ||
      !digestMatches ||
      !authorityMatches ||
      !stabilizationMatches ||
      typeof row.repository_node_id !== 'string' ||
      row.repository_node_id.length === 0 ||
      row.issue_node_id !== row.current_issue_node_id ||
      row.issue_node_type !== 'Issue' ||
      !Number.isInteger(Number(row.sweep_count)) ||
      Number(row.sweep_count) < 2 ||
      Number(row.stabilized) !== 1 ||
      !isTimestamp(row.verified_at)
    ) {
      summary.invalidSnapshotCount++;
      addExample('invalid', issueNumber, 'state-event snapshot schema, count, stabilization, JSON, digest, or verification time is invalid');
    }
    if (
      row.snapshot_state !== row.current_state ||
      row.issue_updated_at !== row.updated_at ||
      row.issue_node_id !== row.current_issue_node_id
    ) {
      summary.metadataMismatchCount++;
      addExample('metadata_mismatch', issueNumber, 'snapshot state or updated_at differs from the current issue row');
    }
    const projectedEvents = projectedEventsByIssue.get(issueNumber) ?? [];
    if (
      normalizedEvents == null ||
      JSON.stringify(projectedEvents) !== JSON.stringify(normalizedEvents)
    ) {
      summary.projectionMismatchCount++;
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
      summary.latestStateMismatchCount++;
      addExample('latest_state_mismatch', issueNumber, 'latest projected state event does not agree with the current issue state');
    }
  }
  summary.failedCount =
    summary.schemaFailureCount +
    summary.missingSnapshotCount +
    summary.invalidSnapshotCount +
    summary.metadataMismatchCount +
    summary.projectionMismatchCount +
    summary.latestStateMismatchCount;
  return summary;
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

function closureProofSummary(db, tag, gate) {
  const rawClosedIssueNumbers = releaseWindowClosedIssueNumbers(db, tag);
  const rawClosedWindowCount = rawClosedIssueNumbers.length;
  const rows = db.prepare(`
    SELECT status, COUNT(*) AS count
    FROM issue_closure_proofs
    WHERE release_tag=?
    GROUP BY status
    ORDER BY count DESC
  `).all(tag);
  const byStatus = Object.fromEntries(rows.map((row) => [row.status, Number(row.count ?? 0)]));
  const proofRowCount = rows.reduce((sum, row) => sum + Number(row.count ?? 0), 0);
  const closureProof = gate?.fixProvenance?.closureProof ?? null;
  const releaseFixCredit = gate?.fixProvenance?.releaseFixCredit ?? null;
  const decisions = Array.isArray(releaseFixCredit?.decisions)
    ? releaseFixCredit.decisions
    : [];
  const computedDecisionCounts = countFixCreditDecisions(decisions);
  const containedFixedInReleaseCount = byStatus.fixed_in_release ?? 0;
  const creditedDecisionCount = computedDecisionCounts.credited;
  const auditCreditedDecisionCount = integerOrNull(
    releaseFixCredit?.decisionCounts?.credited ??
    releaseFixCredit?.countedClosedCount ??
    closureProof?.creditedCount,
  );
  const auditNotCreditedCount = integerOrNull(
    releaseFixCredit?.notCountedClosedCount ??
    closureProof?.notCreditedCount,
  );
  return {
    rawClosedWindowCount,
    proofRowCount,
    fixedInReleaseCount: containedFixedInReleaseCount,
    containedFixedInReleaseCount,
    creditedDecisionCount,
    auditCreditedDecisionCount,
    withheldDecisionCount: computedDecisionCounts.withheld,
    invalidDecisionCount: computedDecisionCounts.invalid,
    containedNotCreditedCount: containedFixedInReleaseCount - creditedDecisionCount,
    notCreditedCount: auditNotCreditedCount ?? proofRowCount - creditedDecisionCount,
    byStatus,
    integrity: closureProofIntegritySummary(db, tag, rawClosedIssueNumbers),
    fixCreditIntegrity: fixCreditIntegritySummary(
      db,
      tag,
      releaseFixCredit,
      closureProof,
      proofRowCount,
    ),
    auditAnalyzedClosedCount: releaseFixCredit?.analyzedClosedCount ?? closureProof?.analyzedClosedCount ?? null,
    auditRiskSummary: closureProof?.riskSummary ?? null,
  };
}

function closureProofIntegritySummary(db, tag, rawClosedIssueNumbers) {
  const issueCommentDependencySql = tableHasColumns(db, 'issue_comment_snapshots', ['fetched_at'])
    ? `UNION ALL SELECT MAX(s.fetched_at) FROM issue_comment_snapshots s JOIN raw_closed c ON c.number=s.issue_number`
    : '';
  const proofEvidenceSql = tableHasColumns(db, 'issue_closure_proofs', ['evidence_json'])
    ? 'evidence_json'
    : 'NULL AS evidence_json';
  const counts = db.prepare(`
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
    raw_closed AS (
      SELECT i.number
      FROM issues i
      JOIN target
      WHERE target.start_at IS NOT NULL
        AND i.closed_at IS NOT NULL
        AND i.closed_at >= target.start_at
        AND i.closed_at < target.end_at
    ),
    proofs AS (
      SELECT issue_number, checked_at, ${proofEvidenceSql}
      FROM issue_closure_proofs
      WHERE release_tag=?
    ),
    linked_prs AS (
      SELECT DISTINCT l.pr_repository_name_with_owner, l.pr_number
      FROM issue_pr_links l
      JOIN raw_closed c ON c.number=l.issue_number
    ),
    dependency_sources AS (
      SELECT MAX(i.updated_at) AS max_ts FROM issues i JOIN raw_closed c ON c.number=i.number
      UNION ALL SELECT MAX(i.fetched_at) FROM issues i JOIN raw_closed c ON c.number=i.number
      UNION ALL SELECT MAX(c.classified_at) FROM classifications c JOIN raw_closed r ON r.number=c.issue_number
      ${issueCommentDependencySql}
      UNION ALL SELECT MAX(e.fetched_at) FROM issue_label_events e JOIN raw_closed c ON c.number=e.issue_number
      UNION ALL SELECT MAX(s.fetched_at) FROM issue_label_snapshots s JOIN raw_closed c ON c.number=s.issue_number
      UNION ALL SELECT MAX(e.fetched_at) FROM issue_closure_events e JOIN raw_closed c ON c.number=e.issue_number
      UNION ALL SELECT MAX(r.fetched_at) FROM issue_reopen_events r JOIN raw_closed c ON c.number=r.issue_number
      UNION ALL SELECT MAX(l.fetched_at) FROM issue_pr_links l JOIN raw_closed c ON c.number=l.issue_number
      UNION ALL SELECT MAX(c.fetched_at) FROM issue_commit_references c JOIN raw_closed r ON r.number=c.issue_number
      UNION ALL SELECT MAX(p.fetched_at)
        FROM pull_request_fixes p
        JOIN linked_prs u
          ON u.pr_repository_name_with_owner=p.pr_repository_name_with_owner
         AND u.pr_number=p.pr_number
      UNION ALL SELECT MAX(r.checked_at)
        FROM release_pr_reachability r
        JOIN linked_prs u
          ON u.pr_repository_name_with_owner=r.pr_repository_name_with_owner
         AND u.pr_number=r.pr_number
        WHERE r.tag=?
    ),
    dependency AS (
      SELECT MAX(max_ts) AS max_ts FROM dependency_sources
    )
    SELECT
      (SELECT COUNT(*) FROM raw_closed c LEFT JOIN proofs p ON p.issue_number=c.number WHERE p.issue_number IS NULL) AS missingCount,
      (SELECT COUNT(*) FROM proofs p LEFT JOIN raw_closed c ON c.number=p.issue_number WHERE c.number IS NULL) AS extraCount,
      (SELECT COUNT(*) FROM proofs p JOIN dependency d WHERE d.max_ts IS NOT NULL AND unixepoch(p.checked_at) < unixepoch(d.max_ts)) AS staleCount,
      (SELECT COUNT(*) FROM proofs WHERE COALESCE(json_extract(evidence_json, '$.proofAnalyzerVersion'), 0) != ${CLOSURE_PROOF_ANALYZER_VERSION}) AS analyzerVersionMismatchCount,
      (SELECT max_ts FROM dependency) AS dependencyMaxAt,
      (SELECT MIN(checked_at) FROM proofs) AS minProofCheckedAt
  `).get(tag, tag, tag);
  const dependencySnapshot = closureDependencySnapshotSummary(
    db,
    tag,
    rawClosedIssueNumbers,
  );
  const summary = {
    missingCount: Number(counts?.missingCount ?? 0),
    extraCount: Number(counts?.extraCount ?? 0),
    staleCount: Number(counts?.staleCount ?? 0),
    analyzerVersionMismatchCount: Number(counts?.analyzerVersionMismatchCount ?? 0),
    dependencyMaxAt: counts?.dependencyMaxAt ?? null,
    minProofCheckedAt: counts?.minProofCheckedAt ?? null,
    dependencySnapshot,
    dependencySnapshotMissingCount: dependencySnapshot.missingCount,
    dependencySnapshotSchemaMismatchCount:
      dependencySnapshot.schemaFailureCount +
      dependencySnapshot.schemaVersionMismatchCount,
    dependencySnapshotAnalyzerMismatchCount:
      dependencySnapshot.analyzerVersionMismatchCount,
    dependencySnapshotDigestMissingCount:
      dependencySnapshot.digestMissingCount,
    dependencySnapshotMembershipMismatchCount:
      dependencySnapshot.issueNumbersMismatchCount,
    dependencyReferencedIssueMissingCount:
      dependencySnapshot.referencedIssueMissingCount,
    dependencyEvidenceInvalidCount:
      dependencySnapshot.evidenceInvalidCount,
    dependencySnapshotMismatchCount:
      dependencySnapshot.issueNumbersInvalidCount +
      dependencySnapshot.issueNumbersMismatchCount +
      dependencySnapshot.referencedIssueMissingCount +
      dependencySnapshot.evidenceInvalidCount +
      dependencySnapshot.digestMismatchCount +
      dependencySnapshot.rowCountInvalidCount +
      dependencySnapshot.rowCountMismatchCount +
      dependencySnapshot.capturedAtInvalidCount +
      dependencySnapshot.sourceSchemaFailureCount,
    failedCount: 0,
  };
  summary.failedCount = summary.missingCount + summary.extraCount + summary.staleCount +
    summary.analyzerVersionMismatchCount +
    summary.dependencySnapshot.failedCount;
  return summary;
}

function releaseWindowClosedIssueNumbers(db, tag) {
  if (!tableHasColumns(db, 'releases', ['tag', 'published_at', 'prerelease']) ||
    !tableHasColumns(db, 'issues', ['number', 'closed_at'])) {
    return [];
  }
  return db.prepare(`
    SELECT i.number
    FROM issues i
    JOIN releases target ON target.tag=?
    WHERE target.catalog_active=1
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
    ORDER BY i.number
  `).all(tag).map((row) => Number(row.number));
}

function countFixCreditDecisions(decisions) {
  return decisions.reduce((counts, decision) => {
    if (decision?.status === 'credited') counts.credited++;
    else if (decision?.status === 'withheld') counts.withheld++;
    else counts.invalid++;
    return counts;
  }, { credited: 0, withheld: 0, invalid: 0 });
}

function fixCreditIntegritySummary(
  db,
  tag,
  releaseFixCredit,
  closureProof,
  proofRowCount,
) {
  const summary = {
    present: !!releaseFixCredit && typeof releaseFixCredit === 'object' &&
      !Array.isArray(releaseFixCredit),
    missingPayloadCount: 0,
    schemaFailureCount: 0,
    countMismatchCount: 0,
    decisionMismatchCount: 0,
    boundaryMismatchCount: 0,
    failedCount: 0,
    predecessorTag: null,
    expectedPredecessorTag: null,
    decisionCounts: { credited: 0, withheld: 0, invalid: 0 },
    examples: [],
  };
  const addProblem = (kind, detail) => {
    summary[`${kind}Count`]++;
    if (summary.examples.length < 10) summary.examples.push({ kind, detail });
  };
  if (!summary.present) {
    summary.missingPayloadCount = 1;
    summary.failedCount = 1;
    summary.examples.push({
      kind: 'missingPayload',
      detail: 'releaseFixCredit payload is missing',
    });
    return summary;
  }

  if (releaseFixCredit.schemaVersion !== 1) {
    addProblem('schemaFailure', 'releaseFixCredit schemaVersion must be 1');
  }
  if (releaseFixCredit.targetTag !== tag) {
    addProblem('boundaryMismatch', `targetTag must equal ${tag}`);
  }
  const predecessorTag = typeof releaseFixCredit.predecessorTag === 'string' &&
    releaseFixCredit.predecessorTag.length > 0
    ? releaseFixCredit.predecessorTag
    : null;
  summary.predecessorTag = predecessorTag;
  const boundary = releaseBoundaryCheck(db, tag, predecessorTag);
  summary.expectedPredecessorTag = boundary.expectedPredecessorTag;
  if (!boundary.valid) {
    addProblem('boundaryMismatch', boundary.detail);
  }

  const fixedIssueNumbers = db.prepare(`
    SELECT issue_number
    FROM issue_closure_proofs
    WHERE release_tag=? AND status='fixed_in_release'
    ORDER BY issue_number
  `).all(tag).map((row) => Number(row.issue_number));
  const decisions = Array.isArray(releaseFixCredit.decisions)
    ? releaseFixCredit.decisions
    : null;
  if (!decisions) {
    addProblem('decisionMismatch', 'releaseFixCredit decisions must be an array');
  }
  const computed = countFixCreditDecisions(decisions ?? []);
  summary.decisionCounts = computed;
  const persistedDecisionCounts = releaseFixCredit.decisionCounts &&
    typeof releaseFixCredit.decisionCounts === 'object' &&
    !Array.isArray(releaseFixCredit.decisionCounts)
    ? releaseFixCredit.decisionCounts
    : null;
  if (!persistedDecisionCounts) {
    addProblem('decisionMismatch', 'releaseFixCredit decisionCounts must be an object');
  } else {
    for (const status of ['credited', 'withheld', 'invalid']) {
      if (persistedDecisionCounts[status] !== computed[status]) {
        addProblem('decisionMismatch', `decisionCounts.${status} must match decisions`);
      }
    }
  }

  const decisionIssueNumbers = [];
  for (const decision of decisions ?? []) {
    const issueNumber = Number(decision?.issueNumber);
    if (
      !decision ||
      typeof decision !== 'object' ||
      Array.isArray(decision) ||
      decision.schemaVersion !== 1 ||
      !Number.isInteger(issueNumber) ||
      issueNumber <= 0 ||
      decision.targetTag !== tag ||
      decision.predecessorTag !== predecessorTag
    ) {
      addProblem('decisionMismatch', `fix-credit decision ${issueNumber || 'unknown'} has invalid identity or boundary metadata`);
      continue;
    }
    decisionIssueNumbers.push(issueNumber);
    if (decision.status === 'credited' && !hasStrictCreditedProof(decision, tag, predecessorTag)) {
      addProblem('decisionMismatch', `credited decision #${issueNumber} lacks strict target/predecessor reachability proof`);
    }
  }
  decisionIssueNumbers.sort((left, right) => left - right);
  if (JSON.stringify(decisionIssueNumbers) !== JSON.stringify(fixedIssueNumbers)) {
    addProblem('decisionMismatch', 'decision issue numbers must match fixed_in_release closure proof rows');
  }

  const containedFixedCount = fixedIssueNumbers.length;
  const expectedCounts = {
    countedClosedCount: computed.credited,
    notCountedClosedCount: proofRowCount - computed.credited,
    analyzedClosedCount: proofRowCount,
    containedFixedCount,
    containedNotCreditedCount: containedFixedCount - computed.credited,
  };
  for (const [field, expected] of Object.entries(expectedCounts)) {
    if (releaseFixCredit[field] !== expected) {
      addProblem('countMismatch', `${field} must equal ${expected}`);
    }
  }
  if (!closureProof || typeof closureProof !== 'object' || Array.isArray(closureProof)) {
    addProblem('schemaFailure', 'closureProof payload is missing');
  } else {
    const closureExpected = {
      analyzedClosedCount: proofRowCount,
      creditedCount: computed.credited,
      notCreditedCount: proofRowCount - computed.credited,
      containedFixedCount,
      containedNotCreditedCount: containedFixedCount - computed.credited,
    };
    for (const [field, expected] of Object.entries(closureExpected)) {
      if (closureProof[field] !== expected) {
        addProblem('countMismatch', `closureProof.${field} must equal ${expected}`);
      }
    }
  }
  if (computed.invalid > 0) {
    addProblem('decisionMismatch', 'persisted fix-credit decisions must not include invalid decisions');
  }
  summary.failedCount =
    summary.missingPayloadCount +
    summary.schemaFailureCount +
    summary.countMismatchCount +
    summary.decisionMismatchCount +
    summary.boundaryMismatchCount;
  return summary;
}

function hasStrictCreditedProof(decision, targetTag, predecessorTag) {
  if (!Array.isArray(decision?.proofIdentities)) return false;
  return decision.proofIdentities.some((proof) => {
    if (proof?.kind === 'trusted_pull_request') {
      return proof.target?.tag === targetTag &&
        proof.target?.strictValid === true &&
        proof.target?.status === 'reachable' &&
        proof.predecessor?.tag === predecessorTag &&
        proof.predecessor?.strictValid === true &&
        proof.predecessor?.status === 'not_reachable';
    }
    if (proof?.kind === 'direct_commit') {
      return proof.strictValid === true &&
        proof.validationReasonCode == null &&
        proof.targetTag === targetTag &&
        proof.predecessorTag === predecessorTag &&
        proof.status === 'credited' &&
        proof.reasonCode === 'first_containing_direct_commit' &&
        proof.creditEligible === true &&
        proof.target?.tag === targetTag &&
        proof.target?.strictValid === true &&
        proof.target?.status === 'reachable' &&
        proof.predecessor?.tag === predecessorTag &&
        proof.predecessor?.strictValid === true &&
        proof.predecessor?.status === 'not_reachable' &&
        proof.releaseAncestry?.tag === targetTag &&
        proof.releaseAncestry?.strictValid === true &&
        proof.releaseAncestry?.status === 'reachable';
    }
    return false;
  });
}

export { hasStrictCreditedProof as doctorHasStrictCreditedProof };

function releaseBoundaryCheck(db, targetTag, predecessorTag) {
  const target = db.prepare(`
    SELECT tag, published_at, prerelease
    FROM releases
    WHERE tag=?
      AND catalog_active=1
  `).get(targetTag);
  const expected = target?.published_at
    ? db.prepare(`
        SELECT tag
        FROM releases
        WHERE prerelease=0
          AND catalog_active=1
          AND published_at IS NOT NULL
          AND published_at < ?
        ORDER BY published_at DESC, tag DESC
        LIMIT 1
      `).get(target.published_at)?.tag ?? null
    : null;
  if (!predecessorTag) {
    return {
      valid: false,
      expectedPredecessorTag: expected,
      detail: 'predecessorTag must name the immediate older stable release',
    };
  }
  const predecessor = db.prepare(`
    SELECT tag, published_at, prerelease
    FROM releases
    WHERE tag=?
      AND catalog_active=1
  `).get(predecessorTag);
  const valid =
    !!target &&
    target.prerelease === 0 &&
    isTimestamp(target.published_at) &&
    !!predecessor &&
    predecessor.prerelease === 0 &&
    isTimestamp(predecessor.published_at) &&
    Date.parse(predecessor.published_at) < Date.parse(target.published_at) &&
    predecessorTag === expected;
  return {
    valid,
    expectedPredecessorTag: expected,
    detail: valid
      ? 'valid immediate stable predecessor'
      : `predecessorTag ${predecessorTag} must equal immediate stable predecessor ${expected ?? 'missing'}`,
  };
}

function closureDependencySnapshotSummary(db, tag, expectedIssueNumbers) {
  const requiredColumns = [
    'release_tag',
    'schema_version',
    'analyzer_version',
    'issue_numbers_json',
    'dependency_digest',
    'dependency_row_count',
    'captured_at',
  ];
  const schema = requiredTableSchemaSummary(
    db,
    'release_closure_dependency_snapshots',
    requiredColumns,
  );
  const schemaFailureCount = schema.present ? schema.missingColumns.length : 1;
  const summary = {
    present: false,
    schema,
    schemaFailureCount,
    missingCount: 0,
    schemaVersionMismatchCount: 0,
    analyzerVersionMismatchCount: 0,
    issueNumbersInvalidCount: 0,
    issueNumbersMismatchCount: 0,
    referencedIssueMissingCount: 0,
    evidenceInvalidCount: 0,
    digestMissingCount: 0,
    digestMismatchCount: 0,
    rowCountInvalidCount: 0,
    rowCountMismatchCount: 0,
    capturedAtInvalidCount: 0,
    sourceSchemaFailureCount: 0,
    persisted: null,
    current: null,
    failedCount: schemaFailureCount,
  };
  if (schemaFailureCount > 0) return summary;
  const sourceSchema = closureDependencySourceSchema(db);
  summary.sourceSchemaFailureCount = sourceSchema.failedCount;
  let expectedMembership = {
    issueNumbers: [...new Set(expectedIssueNumbers)].sort((left, right) => left - right),
    referencedIssueNumbers: [],
    invalidEvidenceCount: 0,
  };
  if (sourceSchema.failedCount === 0) {
    const proofRows = db.prepare(`
      SELECT issue_number, evidence_json
      FROM issue_closure_proofs
      WHERE release_tag=?
      ORDER BY issue_number
    `).all(tag);
    expectedMembership = releaseClosureDependencyMembership(
      expectedIssueNumbers,
      proofRows,
    );
    summary.evidenceInvalidCount = expectedMembership.invalidEvidenceCount;
    if (expectedMembership.referencedIssueNumbers.length > 0) {
      const missingReferencedIssues = db.prepare(`
        WITH selected(issue_number) AS (
          SELECT CAST(value AS INTEGER) FROM json_each(?)
        )
        SELECT selected.issue_number
        FROM selected
        LEFT JOIN issues issue ON issue.number=selected.issue_number
        WHERE issue.number IS NULL
        ORDER BY selected.issue_number
      `).all(JSON.stringify(expectedMembership.referencedIssueNumbers));
      summary.referencedIssueMissingCount = missingReferencedIssues.length;
    }
  }
  const row = db.prepare(`
    SELECT *
    FROM release_closure_dependency_snapshots
    WHERE release_tag=?
  `).get(tag);
  if (!row) {
    summary.missingCount = 1;
    summary.failedCount =
      summary.schemaFailureCount +
      summary.missingCount +
      summary.referencedIssueMissingCount +
      summary.evidenceInvalidCount +
      summary.sourceSchemaFailureCount;
    return summary;
  }
  summary.present = true;
  const issueNumbers = parseJson(row.issue_numbers_json, null);
  const normalizedIssueNumbers = Array.isArray(issueNumbers)
    ? [...new Set(issueNumbers.map(Number))]
      .filter((value) => Number.isInteger(value) && value > 0)
      .sort((left, right) => left - right)
    : null;
  const canonicalIssueNumbersJson = normalizedIssueNumbers
    ? JSON.stringify(normalizedIssueNumbers)
    : null;
  const missingExpectedIssueNumbers = normalizedIssueNumbers
    ? expectedMembership.issueNumbers.filter(
      (issueNumber) => !normalizedIssueNumbers.includes(issueNumber),
    )
    : expectedMembership.issueNumbers;
  const extraIssueNumbers = normalizedIssueNumbers
    ? normalizedIssueNumbers.filter(
      (issueNumber) => !expectedMembership.issueNumbers.includes(issueNumber),
    )
    : [];
  const digestPresent = typeof row.dependency_digest === 'string' &&
    /^[0-9a-f]{64}$/.test(row.dependency_digest);
  const persistedRowCount = Number(row.dependency_row_count);
  summary.persisted = {
    schemaVersion: Number(row.schema_version),
    analyzerVersion: Number(row.analyzer_version),
    issueNumberCount: normalizedIssueNumbers?.length ?? null,
    expectedIssueNumberCount: expectedMembership.issueNumbers.length,
    omittedExpectedIssueNumbers: missingExpectedIssueNumbers.slice(0, 10),
    extraIssueNumbers: extraIssueNumbers.slice(0, 10),
    dependencyDigest: row.dependency_digest ?? null,
    dependencyRowCount: Number.isInteger(persistedRowCount) ? persistedRowCount : null,
    capturedAt: row.captured_at ?? null,
  };
  if (Number(row.schema_version) !== RELEASE_CLOSURE_DEPENDENCY_SNAPSHOT_SCHEMA_VERSION) {
    summary.schemaVersionMismatchCount = 1;
  }
  if (Number(row.analyzer_version) !== CLOSURE_PROOF_ANALYZER_VERSION) {
    summary.analyzerVersionMismatchCount = 1;
  }
  if (!normalizedIssueNumbers ||
    canonicalIssueNumbersJson !== row.issue_numbers_json) {
    summary.issueNumbersInvalidCount = 1;
  } else if (missingExpectedIssueNumbers.length > 0 || extraIssueNumbers.length > 0) {
    summary.issueNumbersMismatchCount = 1;
  }
  if (!digestPresent) summary.digestMissingCount = 1;
  if (!Number.isInteger(persistedRowCount) || persistedRowCount < 0) {
    summary.rowCountInvalidCount = 1;
  }
  if (!isTimestamp(row.captured_at)) summary.capturedAtInvalidCount = 1;

  if (normalizedIssueNumbers && sourceSchema.failedCount === 0) {
    const current = releaseClosureDependencyIdentityForDb(
      db,
      tag,
      expectedMembership.issueNumbers,
    );
    summary.current = {
      schemaVersion: current.schemaVersion,
      releaseTag: current.releaseTag,
      issueNumberCount: current.issueNumbers.length,
      rowCount: current.rowCount,
      digest: current.digest,
    };
    if (
      digestPresent &&
      current.digest !== row.dependency_digest
    ) {
      summary.digestMismatchCount = 1;
    }
    if (
      Number.isInteger(persistedRowCount) &&
      current.rowCount !== persistedRowCount
    ) {
      summary.rowCountMismatchCount = 1;
    }
  }
  summary.failedCount =
    summary.schemaFailureCount +
    summary.missingCount +
    summary.schemaVersionMismatchCount +
    summary.analyzerVersionMismatchCount +
    summary.issueNumbersInvalidCount +
    summary.issueNumbersMismatchCount +
    summary.referencedIssueMissingCount +
    summary.evidenceInvalidCount +
    summary.digestMissingCount +
    summary.digestMismatchCount +
    summary.rowCountInvalidCount +
    summary.rowCountMismatchCount +
    summary.capturedAtInvalidCount +
    summary.sourceSchemaFailureCount;
  return summary;
}

function releaseClosureDependencyMembership(rawClosedIssueNumbers, proofRows) {
  const issueNumbers = new Set(
    rawClosedIssueNumbers
      .map(Number)
      .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0),
  );
  const referencedIssueNumbers = new Set();
  let invalidEvidenceCount = 0;
  for (const row of proofRows) {
    const evidence = parseJson(row.evidence_json, null);
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

function closureDependencySourceSchema(db) {
  const required = {
    releases: ['tag', 'published_at', 'prerelease', 'catalog_active'],
    release_commits: ['tag', 'tag_commit_oid', 'committed_at', 'fetched_at'],
    issues: [
      'number', 'node_id', 'state', 'title', 'body', 'author_node_id', 'author_type',
      'created_at', 'updated_at', 'closed_at', 'comments', 'labels', 'revision',
    ],
    classifications: [
      'issue_number', 'sentiment', 'severity', 'scope', 'functionality',
      'affected_users', 'has_workaround', 'workaround_status',
      'duplicate_cluster', 'affects_version', 'confidence', 'rationale',
      'classified_at', 'classified_updated_at', 'classified_comments_digest',
      'prompt_version', 'source_identity_json', 'source_identity_digest',
      'classification_origin', 'raw_model_output', 'provenance_json', 'revision',
    ],
    issue_comment_snapshots: [
      'issue_number', 'schema_version', 'repository_node_id', 'issue_node_id',
      'issue_author_node_id',
      'issue_author_login', 'issue_author_type', 'comment_count',
      'fetched_comment_count', 'comments_digest', 'issue_updated_at',
      'authority_digest', 'comments_json', 'stabilization_json',
      'stabilization_identity_digest', 'verified_at', 'revision',
    ],
    issue_state_event_snapshots: [
      'issue_number', 'repository_node_id', 'issue_node_id', 'issue_node_type',
      'schema_version',
      'issue_state', 'issue_updated_at', 'total_count', 'fetched_count',
      'events_digest', 'authority_digest', 'events_json', 'sweep_count', 'stabilized',
      'stabilization_json', 'stabilization_identity_digest', 'verified_at', 'revision',
    ],
    issue_closure_evidence_state: [
      'issue_number', 'schema_version', 'issue_updated_at', 'comments_digest',
      'checked_at',
    ],
    issue_label_events: [
      'issue_number', 'issue_node_id', 'event_id', 'action', 'label_name',
      'actor_node_id', 'actor_login', 'actor_type', 'created_at', 'raw_json',
      'fetched_at',
    ],
    issue_label_snapshots: [
      'issue_number', 'issue_node_id', 'snapshot_at', 'labels_json', 'fetched_at',
    ],
    issue_closure_events: [
      'issue_number', 'issue_node_id', 'event_id', 'closed_at',
      'connection_ordinal', 'actor_node_id', 'actor_login', 'actor_type', 'state_reason',
      'closer_type', 'closer_number', 'closer_node_id', 'closer_oid',
      'raw_json', 'fetched_at',
    ],
    issue_reopen_events: [
      'issue_number', 'issue_node_id', 'event_id', 'reopened_at',
      'connection_ordinal', 'actor_node_id', 'actor_login', 'actor_type', 'raw_json',
      'fetched_at',
    ],
    issue_pr_links: [
      'issue_number', 'issue_node_id', 'pr_repository_name_with_owner',
      'pr_number', 'pr_node_id', 'source', 'source_node_id',
      'will_close_target', 'referenced_at', 'source_comment_database_id',
      'source_comment_url', 'raw_json', 'fetched_at',
    ],
    issue_commit_references: [
      'issue_number', 'issue_node_id', 'event_id', 'commit_oid',
      'commit_message_headline', 'commit_repository_name_with_owner',
      'is_cross_repository', 'is_direct_reference', 'referenced_at',
      'actor_node_id', 'actor_login', 'raw_json', 'fetched_at',
    ],
    pull_request_fixes: [
      'pr_repository_owner', 'pr_repository_name', 'pr_repository_name_with_owner',
      'pr_number', 'node_id', 'repository_node_id', 'title', 'url', 'state',
      'merged', 'merged_at', 'merge_commit_oid', 'base_ref_name', 'raw_json', 'fetched_at',
    ],
    release_pr_reachability: [
      'tag', 'pr_repository_owner', 'pr_repository_name',
      'pr_repository_name_with_owner', 'pr_number', 'tag_commit_oid',
      'merge_commit_oid', 'base_ref_name', 'status', 'method',
      'evidence_json', 'checked_at',
    ],
    issue_closure_proofs: [
      'release_tag', 'issue_number', 'status', 'summary', 'evidence_json',
      'checked_at',
    ],
  };
  const tables = Object.fromEntries(
    Object.entries(required).map(([table, columns]) => [
      table,
      requiredTableSchemaSummary(db, table, columns),
    ]),
  );
  return {
    tables,
    failedCount: Object.values(tables).reduce(
      (sum, table) => sum + (table.present ? table.missingColumns.length : 1),
      0,
    ),
  };
}

function releaseClosureDependencyIdentityForDb(db, releaseTag, issueNumbers) {
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
        release_commit.tag_commit_oid, release_commit.committed_at,
        release_commit.fetched_at
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
        c.has_workaround, c.workaround_status, c.duplicate_cluster,
        c.affects_version, c.confidence, c.rationale, c.classified_at,
        c.classified_updated_at, c.classified_comments_digest,
        c.prompt_version, c.source_identity_json, c.source_identity_digest,
        c.classification_origin, c.raw_model_output, c.provenance_json,
        c.revision AS classification_revision,
        comments.schema_version AS comment_schema_version,
        comments.repository_node_id AS comment_repository_node_id,
        comments.issue_node_id AS comment_issue_node_id,
        comments.issue_author_node_id, comments.issue_author_login,
        comments.issue_author_type,
        comments.comment_count, comments.fetched_comment_count,
        comments.comments_digest,
        comments.issue_updated_at AS comment_issue_updated_at,
        comments.authority_digest, comments.comments_json,
        comments.stabilization_json, comments.stabilization_identity_digest,
        comments.verified_at AS comment_verified_at,
        comments.revision AS comment_revision,
        state.repository_node_id AS state_repository_node_id,
        state.issue_node_id AS state_issue_node_id,
        state.issue_node_type AS state_issue_node_type,
        state.schema_version AS state_schema_version,
        state.issue_state,
        state.issue_updated_at AS state_issue_updated_at,
        state.total_count AS state_total_count,
        state.fetched_count AS state_fetched_count,
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
      LEFT JOIN issue_comment_snapshots comments
        ON comments.issue_number=selected.issue_number
      LEFT JOIN issue_state_event_snapshots state
        ON state.issue_number=selected.issue_number
      LEFT JOIN issue_closure_evidence_state closure_state
        ON closure_state.issue_number=selected.issue_number
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
      ORDER BY reachability.pr_repository_name_with_owner,
        reachability.pr_number
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

function reachabilitySummary(db, tag) {
  const rows = tableHasColumns(db, 'release_pr_reachability', ['tag', 'status'])
    ? db.prepare(`
        SELECT status, COUNT(*) AS count
        FROM release_pr_reachability
        WHERE tag=?
        GROUP BY status
        ORDER BY status
      `).all(tag)
    : [];
  const integrity = reachabilityIntegritySummary(db, tag);
  const predecessorBoundaries = predecessorBoundaryReachabilitySummary(db);
  return {
    total: rows.reduce((sum, row) => sum + Number(row.count ?? 0), 0),
    byStatus: Object.fromEntries(rows.map((row) => [row.status, Number(row.count ?? 0)])),
    integrity,
    strictEvidenceMismatchCount:
      integrity.invalidEvidenceCount +
      predecessorBoundaries.strictEvidenceMismatchCount,
    predecessorBoundaries,
  };
}

function reachabilityIntegritySummary(db, tag) {
  const required = {
    release_commits: ['tag', 'tag_commit_oid'],
    issue_pr_links: [
      'pr_repository_name_with_owner',
      'pr_number',
    ],
    pull_request_fixes: [
      'pr_repository_name_with_owner',
      'pr_number',
      'merged',
      'merge_commit_oid',
      'base_ref_name',
      'fetched_at',
    ],
    release_pr_reachability: [
      'tag',
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
  };
  const schema = Object.fromEntries(
    Object.entries(required).map(([table, columns]) => [
      table,
      requiredTableSchemaSummary(db, table, columns),
    ]),
  );
  const schemaFailureCount = Object.values(schema).reduce(
    (sum, table) => sum + (table.present ? table.missingColumns.length : 1),
    0,
  );
  const empty = {
    schema,
    schemaFailureCount,
    candidateCount: 0,
    rowCount: 0,
    missingCount: 0,
    extraCount: 0,
    staleCount: 0,
    identityMismatchCount: 0,
    evidenceMismatchCount: 0,
    invalidEvidenceCount: 0,
    evidenceValidationReasonCounts: {},
    mismatchedCount: 0,
    failedCount: schemaFailureCount,
  };
  if (schemaFailureCount > 0) return empty;

  const counts = db.prepare(`
    WITH candidates AS (
      SELECT
        p.pr_repository_name_with_owner,
        p.pr_number,
        p.merge_commit_oid,
        p.base_ref_name,
        p.fetched_at AS dependency_fetched_at
      FROM pull_request_fixes p
      JOIN issue_pr_links l
        ON l.pr_repository_name_with_owner=p.pr_repository_name_with_owner
       AND l.pr_number=p.pr_number
      WHERE p.merged=1
        AND p.pr_repository_name_with_owner=?
      GROUP BY p.pr_repository_name_with_owner, p.pr_number, p.merge_commit_oid, p.base_ref_name
    ),
    rows AS (
      SELECT r.*, release.tag_commit_oid AS current_tag_commit_oid
      FROM release_pr_reachability r
      LEFT JOIN release_commits release ON release.tag=r.tag
      WHERE r.tag=?
        AND pr_repository_name_with_owner=?
    )
    SELECT
      (SELECT COUNT(*) FROM candidates) AS candidateCount,
      (SELECT COUNT(*) FROM rows) AS rowCount,
      (SELECT COUNT(*) FROM candidates c LEFT JOIN rows r
         ON r.pr_repository_name_with_owner=c.pr_repository_name_with_owner AND r.pr_number=c.pr_number
       WHERE r.pr_number IS NULL) AS missingCount,
      (SELECT COUNT(*) FROM rows r LEFT JOIN candidates c
         ON c.pr_repository_name_with_owner=r.pr_repository_name_with_owner AND c.pr_number=r.pr_number
       WHERE c.pr_number IS NULL) AS extraCount,
      (SELECT COUNT(*) FROM candidates c JOIN rows r
         ON r.pr_repository_name_with_owner=c.pr_repository_name_with_owner AND r.pr_number=c.pr_number
       WHERE unixepoch(r.checked_at) < unixepoch(c.dependency_fetched_at)) AS staleCount,
      (SELECT COUNT(*) FROM candidates c JOIN rows r
         ON r.pr_repository_name_with_owner=c.pr_repository_name_with_owner AND r.pr_number=c.pr_number
       WHERE COALESCE(r.tag_commit_oid, '') != COALESCE(r.current_tag_commit_oid, '')
          OR (
            r.status != 'unknown'
            AND (
              COALESCE(r.merge_commit_oid, '') != COALESCE(c.merge_commit_oid, '')
              OR COALESCE(r.base_ref_name, '') != COALESCE(c.base_ref_name, '')
            )
          )) AS identityMismatchCount
  `).get(TRACKED_PR_REPOSITORY, tag, TRACKED_PR_REPOSITORY);
  const reachabilityRows = db.prepare(`
    SELECT *
    FROM release_pr_reachability
    WHERE tag=? AND pr_repository_name_with_owner=?
    ORDER BY pr_repository_name_with_owner, pr_number
  `).all(tag, TRACKED_PR_REPOSITORY);
  const evidenceValidationReasonCounts = {};
  let invalidEvidenceCount = 0;
  for (const row of reachabilityRows) {
    const validation = validateReachabilityEvidence({
      evidence: row.evidence_json,
      method: row.method,
      status: row.status,
      identity: {
        kind: 'pull_request',
        tagCommitOid: row.tag_commit_oid ?? '',
        checkedCommitOid: row.merge_commit_oid ?? null,
        baseRefName: row.base_ref_name ?? null,
      },
    });
    if (validation.valid) continue;
    invalidEvidenceCount++;
    evidenceValidationReasonCounts[validation.reasonCode] =
      (evidenceValidationReasonCounts[validation.reasonCode] ?? 0) + 1;
  }
  const identityMismatchCount = Number(counts?.identityMismatchCount ?? 0);
  const summary = {
    schema,
    schemaFailureCount,
    candidateCount: Number(counts?.candidateCount ?? 0),
    rowCount: Number(counts?.rowCount ?? 0),
    missingCount: Number(counts?.missingCount ?? 0),
    extraCount: Number(counts?.extraCount ?? 0),
    staleCount: Number(counts?.staleCount ?? 0),
    identityMismatchCount,
    evidenceMismatchCount: invalidEvidenceCount,
    invalidEvidenceCount,
    evidenceValidationReasonCounts,
    mismatchedCount: identityMismatchCount + invalidEvidenceCount,
    failedCount: 0,
  };
  summary.failedCount =
    summary.schemaFailureCount +
    summary.missingCount +
    summary.extraCount +
    summary.staleCount +
    summary.mismatchedCount;
  return summary;
}

function predecessorBoundaryReachabilitySummary(db) {
  const required = {
    releases: ['tag', 'published_at', 'prerelease'],
    release_score_audits: ['release_tag', 'gate_evidence_json'],
  };
  const schema = Object.fromEntries(
    Object.entries(required).map(([table, columns]) => [
      table,
      requiredTableSchemaSummary(db, table, columns),
    ]),
  );
  const schemaFailureCount = Object.values(schema).reduce(
    (sum, table) => sum + (table.present ? table.missingColumns.length : 1),
    0,
  );
  const summary = {
    schema,
    schemaFailureCount,
    auditCount: 0,
    missingPayloadCount: 0,
    missingPredecessorTagCount: 0,
    invalidBoundaryCount: 0,
    unscoredBoundaryCount: 0,
    reachabilityFailureCount: 0,
    strictEvidenceMismatchCount: 0,
    failedCount: schemaFailureCount,
    references: [],
    unscored: [],
  };
  if (schemaFailureCount > 0) return summary;

  const auditRows = db.prepare(`
    SELECT audit.release_tag, audit.gate_evidence_json
    FROM release_score_audits audit
    JOIN releases release ON release.tag=audit.release_tag
    WHERE release.prerelease=0
      AND release.catalog_active=1
    ORDER BY release.catalog_rank IS NULL, release.catalog_rank, release.published_at DESC, audit.release_tag DESC
  `).all();
  summary.auditCount = auditRows.length;
  const auditedTags = new Set(auditRows.map((row) => row.release_tag));
  const unscoredByTag = new Map();
  for (const audit of auditRows) {
    const gate = parseJson(audit.gate_evidence_json, null);
    const payload = gate?.fixProvenance?.releaseFixCredit;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      summary.missingPayloadCount++;
      summary.references.push({
        targetTag: audit.release_tag,
        predecessorTag: null,
        valid: false,
        issue: 'releaseFixCredit payload is missing',
      });
      continue;
    }
    const predecessorTag = typeof payload.predecessorTag === 'string' &&
      payload.predecessorTag.length > 0
      ? payload.predecessorTag
      : null;
    if (!predecessorTag) summary.missingPredecessorTagCount++;
    const boundary = releaseBoundaryCheck(db, audit.release_tag, predecessorTag);
    if (!boundary.valid) summary.invalidBoundaryCount++;
    summary.references.push({
      targetTag: audit.release_tag,
      predecessorTag,
      expectedPredecessorTag: boundary.expectedPredecessorTag,
      valid: boundary.valid,
      issue: boundary.valid ? null : boundary.detail,
    });
    if (predecessorTag && !auditedTags.has(predecessorTag)) {
      const targets = unscoredByTag.get(predecessorTag) ?? [];
      targets.push(audit.release_tag);
      unscoredByTag.set(predecessorTag, targets);
    }
  }

  for (const [boundaryTag, targetTags] of unscoredByTag) {
    const integrity = reachabilityIntegritySummary(db, boundaryTag);
    summary.unscored.push({
      tag: boundaryTag,
      targetTags,
      integrity,
    });
    summary.reachabilityFailureCount += integrity.failedCount;
    summary.strictEvidenceMismatchCount += integrity.invalidEvidenceCount;
  }
  summary.unscoredBoundaryCount = summary.unscored.length;
  summary.failedCount =
    summary.schemaFailureCount +
    summary.missingPayloadCount +
    summary.missingPredecessorTagCount +
    summary.invalidBoundaryCount +
    summary.reachabilityFailureCount;
  return summary;
}

function comparisonSummary(db) {
  const snapshot = db.prepare(`
    SELECT id, source_url, captured_at, page_title
    FROM comparison_snapshots
    ORDER BY captured_at DESC, id DESC
    LIMIT 1
  `).get();
  if (!snapshot) return { latestSnapshot: null, releaseCount: 0 };
  return {
    latestSnapshot: {
      id: snapshot.id,
      sourceUrl: snapshot.source_url,
      capturedAt: snapshot.captured_at,
      pageTitle: snapshot.page_title,
    },
    releaseCount: scalar(db, `SELECT COUNT(*) FROM comparison_releases WHERE snapshot_id=?`, snapshot.id),
  };
}

function ingestionSummary(db, latest) {
  return {
    issueCrawl: parseJson(getMetaValue(db, 'issue_crawl_last_run'), null),
    issueCrawlBaseline: parseJson(getMetaValue(db, 'issue_crawl_exhaustive_baseline'), null),
    commenterScanTruncatedIssueCount: latest?.tag ? commenterScanTruncatedIssueCount(db, latest.tag) : 0,
    closureEvidenceCache: closureEvidenceCacheSummary(db),
    durableEvidenceFailures: durableIngestionEvidenceFailureSummary(db, latest),
  };
}

function closureEvidenceCacheSummary(db) {
  if (!tableHasColumns(db, 'issue_closure_evidence_state', [
    'issue_number',
    'schema_version',
    'issue_updated_at',
    'comments_digest',
    'checked_at',
  ])) {
    return { present: false };
  }
  const row = db.prepare(`
    WITH proof_issues AS (
      SELECT DISTINCT proof.issue_number
      FROM issue_closure_proofs proof
      JOIN release_score_audits audit ON audit.release_tag=proof.release_tag
    ),
    current AS (
      SELECT state.issue_number
      FROM issue_closure_evidence_state state
      JOIN proof_issues proof ON proof.issue_number=state.issue_number
      JOIN issues issue ON issue.number=state.issue_number
      JOIN issue_comment_snapshots comments ON comments.issue_number=state.issue_number
      WHERE state.schema_version=${RAW_CLOSURE_EVIDENCE_SCHEMA_VERSION}
        AND state.issue_updated_at=issue.updated_at
        AND state.comments_digest=comments.comments_digest
        AND comments.issue_updated_at=issue.updated_at
        AND comments.comments_json IS NOT NULL
        AND comments.fetched_comment_count=comments.comment_count
    )
    SELECT
      (SELECT COUNT(*) FROM proof_issues) AS proofIssueCount,
      (SELECT COUNT(*) FROM current) AS reusableIssueCount,
      (SELECT COUNT(*) FROM proof_issues) - (SELECT COUNT(*) FROM current) AS refreshRequiredIssueCount,
      (SELECT COUNT(*) FROM issue_closure_evidence_state) AS totalStateCount,
      (SELECT MAX(checked_at) FROM issue_closure_evidence_state) AS maxCheckedAt,
      (SELECT COUNT(*) FROM issue_comment_snapshots WHERE comments_json IS NOT NULL) AS cachedCommentIssueCount
  `).get();
  return {
    present: true,
    proofIssueCount: Number(row?.proofIssueCount ?? 0),
    reusableIssueCount: Number(row?.reusableIssueCount ?? 0),
    refreshRequiredIssueCount: Number(row?.refreshRequiredIssueCount ?? 0),
    totalStateCount: Number(row?.totalStateCount ?? 0),
    maxCheckedAt: row?.maxCheckedAt ?? null,
    cachedCommentIssueCount: Number(row?.cachedCommentIssueCount ?? 0),
  };
}

function scorePersistenceSummary(db) {
  const raw = getMetaValue(db, 'score_persistence_last_run');
  const meta = parseJson(raw, null);
  const sourceIdentityColumnPresent = tableHasColumns(db, 'release_score_audits', ['source_identity_json']);
  const releaseStats = db.prepare(`
    SELECT COUNT(*) AS count, MAX(scored_at) AS maxScoredAt
    FROM releases
    WHERE prerelease=0
      AND catalog_active=1
      AND (
        final_score IS NOT NULL
        OR scored_at IS NOT NULL
      )
  `).get();
  const auditStats = db.prepare(`
    SELECT COUNT(*) AS count, MAX(a.scored_at) AS maxScoredAt
    FROM release_score_audits a
    JOIN releases r ON r.tag=a.release_tag
    WHERE r.prerelease=0
      AND r.catalog_active=1
  `).get();
  const auditRows = db.prepare(`
    SELECT a.release_tag, a.score_model_version, a.prompt_version, a.input_json,
           ${sourceIdentityColumnPresent ? 'a.source_identity_json' : 'NULL'} AS source_identity_json
    FROM release_score_audits a
    JOIN releases r ON r.tag=a.release_tag
    WHERE r.prerelease=0
      AND r.catalog_active=1
    ORDER BY r.catalog_rank IS NULL, r.catalog_rank, r.published_at IS NULL, r.published_at DESC
  `).all();
  const scoredRows = db.prepare(`
    SELECT tag
    FROM releases
    WHERE prerelease=0
      AND catalog_active=1
      AND (
        final_score IS NOT NULL
        OR scored_at IS NOT NULL
      )
    ORDER BY catalog_rank IS NULL, catalog_rank, published_at IS NULL, published_at DESC
  `).all();
  const missingAuditTags = db.prepare(`
    SELECT r.tag
    FROM releases r
    LEFT JOIN release_score_audits a ON a.release_tag=r.tag
    WHERE r.prerelease=0
      AND r.catalog_active=1
      AND (
        r.final_score IS NOT NULL
        OR r.scored_at IS NOT NULL
      )
      AND a.release_tag IS NULL
    ORDER BY r.catalog_rank IS NULL, r.catalog_rank, r.published_at IS NULL, r.published_at DESC
  `).all().map((row) => row.tag);
  const orphanAuditTags = db.prepare(`
    SELECT a.release_tag
    FROM release_score_audits a
    LEFT JOIN releases r ON r.tag=a.release_tag
    WHERE r.tag IS NULL
      OR (
        r.catalog_active=1
        AND (
          r.prerelease != 0
          OR (
            r.final_score IS NULL
            AND r.scored_at IS NULL
          )
        )
      )
    ORDER BY a.release_tag
  `).all().map((row) => row.release_tag);
  const parityRows = db.prepare(`
    SELECT r.tag,
           r.final_score AS release_final_score,
           a.final_score AS audit_final_score,
           r.scored_at AS release_scored_at,
           a.scored_at AS audit_scored_at,
           r.state AS release_status,
           a.status AS audit_status,
           r.recommended AS release_recommended,
           a.recommended AS audit_recommended
    FROM releases r
    JOIN release_score_audits a ON a.release_tag=r.tag
    WHERE r.prerelease=0
      AND r.catalog_active=1
      AND (
        r.final_score IS NOT NULL
        OR r.scored_at IS NOT NULL
      )
    ORDER BY r.catalog_rank IS NULL, r.catalog_rank, r.published_at IS NULL, r.published_at DESC
  `).all();
  const releaseAuditMismatches = parityRows.flatMap((row) => releaseAuditMismatchesForRow(row));
  const classificationCoverageMismatches = auditRows.flatMap((row) => {
    const input = parseJson(row.input_json, null);
    const rawIssueCount = Number(input?.rawIssueCount);
    const classifiedIssueCount = Number(input?.classifiedIssueCount);
    if (
      Number.isInteger(rawIssueCount) &&
      rawIssueCount >= 0 &&
      Number.isInteger(classifiedIssueCount) &&
      classifiedIssueCount >= 0 &&
      classifiedIssueCount === rawIssueCount
    ) {
      return [];
    }
    return [{
      tag: row.release_tag,
      rawIssueCount: Number.isFinite(rawIssueCount) ? rawIssueCount : null,
      classifiedIssueCount: Number.isFinite(classifiedIssueCount)
        ? classifiedIssueCount
        : null,
    }];
  });
  const sourceIdentityRows = auditRows.map((row) => ({
    tag: row.release_tag,
    identity: parseJson(row.source_identity_json, null),
  }));
  const validSourceIdentityRows = sourceIdentityRows.filter((row) => isScoreSourceIdentity(row.identity));
  const persistedSourceIdentity = validSourceIdentityRows[0]?.identity ?? null;
  const persistedIdentities = [...new Set(validSourceIdentityRows.map((row) => JSON.stringify(row.identity)))];
  const persistedSourceNames = new Set(
    Array.isArray(persistedSourceIdentity?.sources)
      ? persistedSourceIdentity.sources.map((source) => source?.source)
      : [],
  );
  return {
    present: typeof raw === 'string' && raw.length > 0,
    valid: !!meta && typeof meta === 'object' && !Array.isArray(meta) && meta.schemaVersion === 2,
    sourceIdentityColumnPresent,
    meta,
    auditedStableCount: Number(auditStats?.count ?? 0),
    scoredStableCount: Number(releaseStats?.count ?? 0),
    maxReleaseScoredAt: releaseStats?.maxScoredAt ?? null,
    maxAuditScoredAt: auditStats?.maxScoredAt ?? null,
    scoredStableTags: scoredRows.map((row) => row.tag),
    auditedStableTags: auditRows.map((row) => row.release_tag),
    auditModelVersions: [...new Set(auditRows.map((row) => row.score_model_version))],
    auditPromptVersions: [...new Set(auditRows.map((row) => row.prompt_version))],
    missingAuditTags,
    orphanAuditTags,
    releaseAuditMismatches,
    classificationCoverageMismatches,
    sourceIdentity: {
      persisted: sourceIdentitySummary(persistedSourceIdentity),
      persistedManifest: persistedSourceIdentity,
      current: null,
      matchesCurrent: false,
      persistedIdentityCount: persistedIdentities.length,
      persistedDigests: [...new Set(validSourceIdentityRows.map((row) => row.identity.digest))],
      missingRequiredSources: REQUIRED_SCORE_SOURCE_NAMES.filter(
        (source) => !persistedSourceNames.has(source),
      ),
      missingTags: sourceIdentityRows.filter((row) => row.identity == null).map((row) => row.tag),
      malformedTags: sourceIdentityRows
        .filter((row) => row.identity != null && !isScoreSourceIdentity(row.identity))
        .map((row) => row.tag),
    },
  };
}

function isScoreSourceIdentity(value) {
  return scoreSourceIdentityManifestProblems(value).length === 0;
}

function sourceIdentitySummary(identity) {
  if (!isScoreSourceIdentity(identity)) return null;
  return {
    schemaVersion: identity.schemaVersion,
    sourceMode: identity.sourceMode,
    scope: identity.scope,
    algorithm: identity.algorithm,
    digest: identity.digest,
    rowCount: identity.rowCount,
    sourceCount: identity.sourceCount,
  };
}

function releaseAuditMismatchesForRow(row) {
  return [
    ['final_score', row.release_final_score, row.audit_final_score],
    ['scored_at', row.release_scored_at, row.audit_scored_at],
    ['status', row.release_status, row.audit_status],
    ['recommended', row.release_recommended, row.audit_recommended],
  ]
    .filter(([, releaseValue, auditValue]) => releaseValue !== auditValue)
    .map(([field, releaseValue, auditValue]) => ({
      tag: row.tag,
      field,
      release: releaseValue,
      audit: auditValue,
    }));
}

function durableIngestionEvidenceFailureSummary(db, latest) {
  const present = tableHasColumns(db, 'ingestion_evidence_failures', [
    'id',
    'run_id',
    'occurred_at',
    'source',
    'message',
    'scoring_blocking',
  ]);
  const empty = {
    present,
    blockingAfterLatestScoreCount: 0,
    bySource: {},
    recentAfterLatestScore: [],
  };
  if (!present || !latest?.scoredAt) return empty;
  const rows = db.prepare(`
    SELECT id, run_id, occurred_at, source, scope, release_tag, issue_number,
           pr_repository_name_with_owner, pr_number, message, context_json
    FROM ingestion_evidence_failures
    WHERE scoring_blocking = 1
      AND occurred_at > ?
    ORDER BY occurred_at DESC, id DESC
    LIMIT 10
  `).all(latest.scoredAt);
  const bySourceRows = db.prepare(`
    SELECT source, COUNT(*) AS count, MAX(occurred_at) AS maxAt
    FROM ingestion_evidence_failures
    WHERE scoring_blocking = 1
      AND occurred_at > ?
    GROUP BY source
    ORDER BY count DESC, source
  `).all(latest.scoredAt);
  const total = bySourceRows.reduce((sum, row) => sum + Number(row.count ?? 0), 0);
  return {
    present,
    blockingAfterLatestScoreCount: total,
    bySource: Object.fromEntries(bySourceRows.map((row) => [
      row.source,
      { count: Number(row.count ?? 0), maxAt: row.maxAt ?? null },
    ])),
    recentAfterLatestScore: rows.map((row) => ({
      id: Number(row.id),
      runId: row.run_id,
      occurredAt: row.occurred_at,
      source: row.source,
      scope: row.scope ?? null,
      releaseTag: row.release_tag ?? null,
      issueNumber: row.issue_number ?? null,
      prRepositoryNameWithOwner: row.pr_repository_name_with_owner ?? null,
      prNumber: row.pr_number ?? null,
      message: row.message,
      context: parseJson(row.context_json, null),
    })),
  };
}

function getMetaValue(db, key) {
  if (!tablePresent(db, 'meta')) return null;
  const row = db.prepare(`SELECT value FROM meta WHERE key=?`).get(key);
  return row?.value ?? null;
}

function commenterScanTruncatedIssueCount(db, tag) {
  return scalar(db, `
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
    SELECT COUNT(DISTINCT i.number)
    FROM issues i
    JOIN target
    WHERE target.start_at IS NOT NULL
      AND i.commenter_scan_truncated=1
      AND EXISTS (
        SELECT 1
        FROM issue_open_intervals interval
        WHERE interval.issue_number=i.number
          AND interval.open_at < target.end_at
          AND (interval.close_at IS NULL OR interval.close_at > target.start_at)
      )
  `, tag);
}

async function apiSummary(apiBase) {
  try {
    const [status, publicPayload, health] = await Promise.all([
      fetchJson(`${apiBase}/api/status`),
      fetchJson(`${apiBase}/api/public`),
      fetchJson(`${apiBase}/api/health`),
    ]);
    const recommended = (publicPayload.releases ?? []).filter((release) => release.recommended);
    return {
      apiBase,
      status: {
        lastScoredAt: status.lastScoredAt ?? null,
        lastError: status.lastError ?? null,
        refreshing: status.refreshing === true,
      },
      public: {
        releaseCount: publicPayload.releases?.length ?? 0,
        recommendedCount: recommended.length,
        recommendedTag: recommended[0]?.tag ?? null,
      },
      health,
    };
  } catch (error) {
    return { apiBase, error: error.message };
  }
}

export function verifyApiAgainstDb(report) {
  if (!report.api) return;
  if (report.api.error) {
    report.failures.push(`api check failed: ${report.api.error}`);
    return;
  }
  const expectedRecommendedTag = report.recommendation?.recommended?.[0]?.tag ?? null;
  const expectedRecommendedCount = Number(report.recommendation?.recommendedCount ?? 0);
  const expectedScoredAt = report.tables?.releases?.maxAt ?? null;
  const apiRecommendedCount = Number(report.api.public?.recommendedCount ?? 0);
  const apiRecommendedTag = report.api.public?.recommendedTag ?? null;
  const apiLastScoredAt = report.api.status?.lastScoredAt ?? null;
  if (report.api.status?.refreshing === true) {
    report.failures.push('api status reports refresh in progress');
  }
  if (report.api.status?.lastError) {
    report.failures.push(`api status reports lastError: ${report.api.status.lastError}`);
  }
  if (apiRecommendedCount !== expectedRecommendedCount) {
    report.failures.push(
      `api public recommended count (${apiRecommendedCount}) must match DB count (${expectedRecommendedCount})`,
    );
  }
  if (apiRecommendedTag !== expectedRecommendedTag) {
    report.failures.push(`api public recommended tag (${apiRecommendedTag}) must match DB recommended tag (${expectedRecommendedTag})`);
  }
  if (apiLastScoredAt !== expectedScoredAt) {
    report.failures.push(`api status lastScoredAt (${apiLastScoredAt}) must match DB max scored_at (${expectedScoredAt})`);
  }
  const health = report.api.health;
  const expectedCurrentReleaseTag = report.latestScoredStable?.tag ?? null;
  const expectedCheckNames = [
    'closureProof',
    'database',
    'ingestion',
    'recommendation',
    'releaseWindow',
    'scoreAudit',
    'sourceIdentity',
  ];
  if (health?.schemaVersion !== 1) {
    report.failures.push(`api health schemaVersion (${health?.schemaVersion ?? null}) must be 1`);
  }
  if (health?.ok !== true || health?.status !== 'ready') {
    report.failures.push(
      `api health must report ok=true and status=ready, got ` +
      `ok=${JSON.stringify(health?.ok)} status=${JSON.stringify(health?.status)}`,
    );
  }
  if (health?.repo !== TRACKED_PR_REPOSITORY) {
    report.failures.push(
      `api health repo (${health?.repo ?? null}) must match ${TRACKED_PR_REPOSITORY}`,
    );
  }
  if (health?.currentRelease?.tag !== expectedCurrentReleaseTag) {
    report.failures.push(
      `api health current release (${health?.currentRelease?.tag ?? null}) must match ` +
      `DB latest scored stable (${expectedCurrentReleaseTag})`,
    );
  }
  if (!Array.isArray(health?.failures) || health.failures.length !== 0) {
    report.failures.push(
      `api health failures must be an empty array, found ` +
      `${Array.isArray(health?.failures) ? health.failures.length : 'non-array'}`,
    );
  }
  const actualCheckNames = health?.checks && typeof health.checks === 'object' &&
    !Array.isArray(health.checks)
    ? Object.keys(health.checks).sort()
    : [];
  if (JSON.stringify(actualCheckNames) !== JSON.stringify(expectedCheckNames)) {
    report.failures.push(
      `api health readiness checks (${actualCheckNames.join(', ') || 'missing'}) must equal ` +
      expectedCheckNames.join(', '),
    );
  }
  for (const name of expectedCheckNames) {
    if (health?.checks?.[name]?.ok !== true) {
      report.failures.push(`api health readiness check ${name} must report ok=true`);
    }
  }
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

function scalar(db, sql, ...args) {
  const row = db.prepare(sql).get(...args);
  if (!row) return 0;
  return Number(Object.values(row)[0] ?? 0);
}

function tableHasColumns(db, table, columns) {
  const existing = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((col) => col.name));
  return columns.every((column) => existing.has(column));
}

function parseJson(json, fallback) {
  if (!json) return fallback;
  try {
    return JSON.parse(json);
  } catch {
    return fallback;
  }
}

function scoreSourceManifestProblems(json) {
  const manifest = parseJson(json, null);
  return scoreSourceIdentityManifestProblems(manifest);
}

function scoreSourceManifestAssessment(json) {
  const manifest = parseJson(json, null);
  const strictProblems = scoreSourceIdentityManifestProblems(manifest);
  const obsoleteProblems = obsoleteScoreSourceManifestStructuralProblems(manifest);
  return {
    strictProblems,
    obsoleteProblems,
    obsoleteStructurallyValid:
      strictProblems.length > 0 && obsoleteProblems.length === 0,
    schemaVersion: Number(manifest?.schemaVersion),
  };
}

function obsoleteScoreSourceManifestStructuralProblems(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return ['manifest must be an object'];
  }
  const problems = [];
  const expectedManifestKeys = [
    'schemaVersion',
    'sourceMode',
    'scope',
    'algorithm',
    'rowCount',
    'sourceCount',
    'digest',
    'sources',
  ].sort();
  if (JSON.stringify(Object.keys(manifest).sort()) !== JSON.stringify(expectedManifestKeys)) {
    problems.push(`manifest keys must equal ${expectedManifestKeys.join(', ')}`);
  }
  const schemaVersion = Number(manifest.schemaVersion);
  if (!Number.isInteger(schemaVersion) || schemaVersion <= 0 ||
    schemaVersion >= SCORE_SOURCE_IDENTITY_SCHEMA_VERSION) {
    problems.push(
      `schemaVersion must be an obsolete positive integer below ` +
      `${SCORE_SOURCE_IDENTITY_SCHEMA_VERSION}`,
    );
  }
  if (manifest.sourceMode !== 'current_db') problems.push('sourceMode must equal current_db');
  if (manifest.scope !== 'score_input_database') {
    problems.push('scope must equal score_input_database');
  }
  if (manifest.algorithm !== 'sha256') problems.push('algorithm must equal sha256');
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

  const sourceNames = [];
  let rowCount = 0;
  for (let index = 0; index < manifest.sources.length; index++) {
    const source = manifest.sources[index];
    if (!source || typeof source !== 'object' || Array.isArray(source)) {
      problems.push(`sources[${index}] must be an object`);
      continue;
    }
    if (JSON.stringify(Object.keys(source).sort()) !==
      JSON.stringify(['count', 'digest', 'source'])) {
      problems.push(`sources[${index}] keys must equal source, count, digest`);
    }
    if (typeof source.source !== 'string' || !source.source) {
      problems.push(`sources[${index}].source must be a non-empty string`);
    } else {
      sourceNames.push(source.source);
    }
    if (!Number.isInteger(source.count) || Number(source.count) < 0) {
      problems.push(`sources[${index}].count must be a non-negative integer`);
    } else {
      rowCount += Number(source.count);
    }
    if (typeof source.digest !== 'string' || !/^[0-9a-f]{64}$/.test(source.digest)) {
      problems.push(`sources[${index}].digest must be a lowercase SHA-256 hex string`);
    }
  }
  if (manifest.sourceCount !== manifest.sources.length) {
    problems.push(`sourceCount must equal sources.length (${manifest.sources.length})`);
  }
  if (manifest.rowCount !== rowCount) {
    problems.push(`rowCount must equal the sum of source counts (${rowCount})`);
  }
  if (new Set(sourceNames).size !== sourceNames.length) {
    problems.push('sources must not contain duplicate source names');
  }
  if (problems.length === 0) {
    const digest = scoreSourceIdentityManifestDigest(manifest.sources, schemaVersion);
    if (manifest.digest !== digest) {
      problems.push('digest does not match the ordered source manifest');
    }
  }
  return problems;
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
    row.authority_run_id,
  ]);
}

function integerOrNull(value) {
  return Number.isInteger(value) ? Number(value) : null;
}

function isTimestamp(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function isCanonicalTimestamp(value) {
  if (typeof value !== 'string') return false;
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) && new Date(epoch).toISOString() === value;
}

function maxTimestamp(values) {
  return values
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

function ageHours(sourceAt, targetAt) {
  if (!sourceAt || !targetAt) return null;
  const sourceMs = Date.parse(sourceAt);
  const targetMs = Date.parse(targetAt);
  if (!Number.isFinite(sourceMs) || !Number.isFinite(targetMs)) return null;
  return round((targetMs - sourceMs) / 3_600_000, 2);
}

function round(value, digits = 3) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
