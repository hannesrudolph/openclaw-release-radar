import { spawn, spawnSync } from 'node:child_process';
import { strict as assert } from 'node:assert';
import { createHash, randomUUID } from 'node:crypto';
import dotenv from 'dotenv';
import {
  chmodSync,
  chownSync,
  closeSync,
  existsSync,
  fstatSync,
  ftruncateSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { buildDoctorReport } from './doctor.mjs';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from '../src/lib/scoreHistoryLedger.ts';
import {
  canonicalJson as canonicalOperationJson,
  operationCaptureReceiptContentHash,
  operationCaptureReceiptSemanticIdentity,
  verifyOperationReceiptLedger,
} from '../src/lib/operationReceipts.ts';
import {
  projectReleaseCatalogActiveRows,
  verifyReleaseCatalogCaptureReceiptLedger,
} from '../src/lib/releaseCatalogReceipt.ts';
import { fetchReleaseCatalogForRepository } from '../src/lib/github.ts';
import { openReleaseAuditReader } from './lib/release-audit-reader.mjs';
import {
  IMMUTABLE_LEDGER_TABLES as CANONICAL_IMMUTABLE_LEDGER_TABLES,
  REQUIRED_APPEND_ONLY_TRIGGERS as CANONICAL_REQUIRED_APPEND_ONLY_TRIGGERS,
  appendOnlyTriggerShape,
  undeclaredAppendOnlyTriggerShapes,
} from './lib/database-schema-manifest.mjs';

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TSX_CLI = join(PROJECT_ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const DEFAULT_INSTALL_BASE = '/opt/openclaw-release-radar';
const DEFAULT_DEPLOYMENT_LOCK_PATH =
  '/opt/openclaw-release-radar/shared/deploy-promotion.lock';
const PENDING_DEPLOY_DIRECTORY = '.pending-deploy';
const SQLITE_FAMILY_SUFFIXES = Object.freeze([
  '',
  '-wal',
  '-shm',
  '-journal',
]);
const SQLITE_SIDECAR_SUFFIXES = SQLITE_FAMILY_SUFFIXES.slice(1);
export const INSTALLER_PENDING_STATE_SCHEMA_VERSION = 4;
export const INSTALLER_PENDING_STATE_HASH_DOMAIN =
  'installer-pending-promotion-v2';
export const PROMOTION_AUTHORIZATION_SCHEMA_VERSION = 1;
export const PROMOTION_AUTHORIZATION_HASH_DOMAIN =
  'quality-db-promotion-authorization-v1';
export const PROMOTION_VALIDATION_REPORT_HASH_DOMAIN =
  'quality-db-promotion-validation-report-v1';
export const INHERITED_DEPLOYMENT_LOCK_PROOF_SCHEMA_VERSION = 1;
export const INHERITED_DEPLOYMENT_LOCK_PROOF_METHOD =
  'linux-proc-fdinfo-flock';
export const INSTALLER_PENDING_STATE_FIELDS = Object.freeze([
  'pending_schema_version',
  'promotion_required',
  'transaction_id',
  'deadline_epoch',
  'release_name',
  'github_sha',
  'artifact_digest',
  'release_dir',
  'release_created',
  'previous_current_present',
  'previous_current_target',
  'tarball',
  'tarball_sha256',
  'tarball_size_bytes',
  'runtime_env_path',
  'runtime_env_created',
  'database_path',
  'db_snapshot_path',
  'db_snapshot_sha256',
  'quality_database_path',
  'required_score_receipt_id',
]);
const HISTORY_TABLE = 'release_score_audit_history';
const HISTORY_RUN_TABLE = 'release_score_audit_history_runs';
const FORECAST_TABLE = 'release_validation_forecasts';
const OPERATION_ATTEMPT_TABLE = 'refresh_operation_attempts';
const OPERATION_STAGE_EVENT_TABLE = 'refresh_operation_stage_events';
const OPERATION_RECEIPT_TABLE = 'refresh_capture_receipts';
const RELEASE_CATALOG_RECEIPT_TABLE =
  'release_catalog_capture_receipts';
const ARTIFACT_RECEIPT_TABLE = 'release_artifact_verification_receipts';
const ARTIFACT_OBSERVATION_TABLE =
  'release_artifact_verification_observations';
const OPERATION_RECEIPT_TABLES = [
  OPERATION_ATTEMPT_TABLE,
  OPERATION_STAGE_EVENT_TABLE,
  OPERATION_RECEIPT_TABLE,
];
const RELEASE_CATALOG_RECEIPT_COLUMNS = [
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
];
const RELEASE_CATALOG_LIVE_IDENTITY_COLUMNS = [
  'catalog_rank',
  'tag',
  'node_id',
  'catalog_tag_commit_oid',
  'prerelease',
  'published_at',
  'created_at',
  'updated_at',
  'html_url',
  'name',
  'body',
];
const OPERATION_ATTEMPT_COLUMNS = [
  'run_id',
  'operation',
  'trigger',
  'started_at',
  'lease_name',
  'lease_holder_id',
  'lease_expires_at',
  'code_revision',
  'effective_config_json',
  'effective_config_hash',
  'content_hash',
];
const OPERATION_STAGE_EVENT_COLUMNS = [
  'event_id',
  'run_id',
  'sequence',
  'stage',
  'status',
  'occurred_at',
  'duration_ms',
  'counts_json',
  'details_json',
  'previous_content_hash',
  'content_hash',
];
const OPERATION_RECEIPT_COLUMNS = [
  'receipt_id',
  'run_id',
  'status',
  'finished_at',
  'duration_ms',
  'stage_event_count',
  'stage_chain_hash',
  'payload_json',
  'previous_content_hash',
  'content_hash',
];
const OPERATION_RECEIPT_SEMANTIC_COLUMNS = OPERATION_RECEIPT_COLUMNS.filter(
  (column) => column !== 'previous_content_hash' && column !== 'content_hash',
);
const FORECAST_SERIES_IDENTITY_COLUMNS_WITHOUT_REVISION = [
  'opportunity_code',
  'latest_release_tag',
  'score_model_version',
  'prompt_version',
];
const FORECAST_SERIES_IDENTITY_COLUMNS_WITH_REVISION = [
  ...FORECAST_SERIES_IDENTITY_COLUMNS_WITHOUT_REVISION,
  'code_revision',
];
const CANONICAL_VALIDATION_PROOF_TABLES = [
  'release_validation_proof_epochs',
  'release_validation_proof_epoch_retirements',
  'release_validation_policies',
  'release_validation_cohorts',
  'release_validation_catalog_observations',
  'release_validation_catalog_members',
  'release_validation_catalog_reconciliations',
  'release_validation_catalog_reconciliation_rows',
  'release_validation_obligations',
  'release_validation_split_assignments',
  'release_validation_forecasts_v2',
  'release_validation_outcomes_v2',
  'release_validation_proof_observation_batches',
  'release_validation_evaluation_receipts',
  'release_validation_promotion_receipts',
];
const HISTORY_COLUMNS = [
  'run_id',
  'recorded_at',
  'release_tag',
  'scored_at',
  'score_model_version',
  'prompt_version',
  'final_score',
  'status',
  'band',
  'recommended',
  'input_json',
  'components_json',
  'issue_evidence_json',
  'gate_evidence_json',
  'source_identity_json',
  'authority_run_id',
];
const HISTORY_CONTENT_COLUMNS = HISTORY_COLUMNS.filter((column) => column !== 'run_id');
export const PROMOTION_IMMUTABLE_LEDGER_TABLES =
  CANONICAL_IMMUTABLE_LEDGER_TABLES;
const IMMUTABLE_LEDGER_TABLES = PROMOTION_IMMUTABLE_LEDGER_TABLES;
const SOURCE_REQUIRED_LEDGER_TABLES = IMMUTABLE_LEDGER_TABLES.filter(
  (table) =>
    table !== HISTORY_TABLE &&
    table !== HISTORY_RUN_TABLE &&
    table !== RELEASE_CATALOG_RECEIPT_TABLE &&
    !OPERATION_RECEIPT_TABLES.includes(table),
);
const PRESERVED_DESTINATION_TABLES = [
  'ingestion_evidence_failures',
  'comparison_snapshots',
  'comparison_releases',
];
const SCORE_EVIDENCE_SNAPSHOT_TABLES = [
  'issue_state_event_snapshots',
  'release_closure_dependency_snapshots',
];
const DESTINATION_DRIFT_TABLES = [
  ...PRESERVED_DESTINATION_TABLES,
  ...SCORE_EVIDENCE_SNAPSHOT_TABLES,
];
const CANONICAL_SCORE_EVIDENCE_SCHEMAS = [
  {
    table: 'issue_state_event_snapshots',
    columns: [
      ['issue_number', 'INTEGER', 0, 1, null],
      ['repository_node_id', 'TEXT', 0, 0, null],
      ['issue_node_id', 'TEXT', 0, 0, null],
      ['issue_node_type', 'TEXT', 0, 0, null],
      ['schema_version', 'INTEGER', 1, 0, null],
      ['issue_state', 'TEXT', 1, 0, null],
      ['issue_updated_at', 'TEXT', 1, 0, null],
      ['total_count', 'INTEGER', 1, 0, null],
      ['fetched_count', 'INTEGER', 1, 0, null],
      ['events_digest', 'TEXT', 1, 0, null],
      ['authority_digest', 'TEXT', 0, 0, null],
      ['events_json', 'TEXT', 1, 0, null],
      ['sweep_count', 'INTEGER', 1, 0, '0'],
      ['stabilized', 'INTEGER', 1, 0, '0'],
      ['stabilization_json', 'TEXT', 0, 0, null],
      ['stabilization_identity_digest', 'TEXT', 0, 0, null],
      ['revision', 'INTEGER', 1, 0, '1'],
      ['fetched_at', 'TEXT', 1, 0, null],
      ['verified_at', 'TEXT', 1, 0, null],
    ],
    indexes: [
      {
        name: 'idx_issue_state_event_snapshots_verified',
        unique: 0,
        partial: 0,
        origin: 'c',
        columns: ['verified_at'],
      },
    ],
  },
  {
    table: 'release_closure_dependency_snapshots',
    columns: [
      ['release_tag', 'TEXT', 0, 1, null],
      ['schema_version', 'INTEGER', 1, 0, null],
      ['analyzer_version', 'INTEGER', 1, 0, null],
      ['issue_numbers_json', 'TEXT', 1, 0, null],
      ['dependency_digest', 'TEXT', 1, 0, null],
      ['dependency_row_count', 'INTEGER', 1, 0, null],
      ['captured_at', 'TEXT', 1, 0, null],
    ],
    indexes: [
      {
        name: null,
        unique: 1,
        partial: 0,
        origin: 'pk',
        columns: ['release_tag'],
      },
    ],
  },
];
const MATURED_OUTCOME_INDEX = 'idx_release_validation_outcomes_one_matured';
export const PROMOTION_REQUIRED_APPEND_ONLY_TRIGGERS =
  CANONICAL_REQUIRED_APPEND_ONLY_TRIGGERS;
const REQUIRED_APPEND_ONLY_TRIGGERS =
  PROMOTION_REQUIRED_APPEND_ONLY_TRIGGERS;

export function parsePromotionArgs(argv, environment = process.env) {
  const values = {};
  const flags = new Set();
  const valueArgs = new Set([
    'source',
    'destination',
    'rollback-backup',
    'deployment-transaction-id',
    'release-name',
    'release-sha',
    'artifact-digest',
    'pending-state-hash',
    'required-score-receipt-id',
    'deployment-lock-fd',
  ]);
  const flagArgs = new Set(['apply', 'dry-run', 'help']);

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!arg.startsWith('--')) throw new Error(`Unexpected positional argument: ${arg}`);
    const key = arg.slice(2);
    if (flagArgs.has(key)) {
      flags.add(key);
      continue;
    }
    if (!valueArgs.has(key)) throw new Error(`Unknown option: --${key}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`--${key} requires a value`);
    values[key] = value;
    index++;
  }

  if (flags.has('help')) return { help: true };
  if (!values.source || !values.destination) {
    throw new Error('Both --source and --destination are required');
  }
  if (flags.has('apply') && flags.has('dry-run')) {
    throw new Error('--apply and --dry-run are mutually exclusive');
  }
  const deploymentKeys = [
    'deployment-transaction-id',
    'release-name',
    'release-sha',
    'artifact-digest',
    'pending-state-hash',
    'required-score-receipt-id',
  ];
  const deploymentValuesPresent = deploymentKeys.filter((key) => values[key] != null);
  if (environment.RADAR_DEPLOY_LOCK_HELD === '1') {
    throw new Error(
      'RADAR_DEPLOY_LOCK_HELD no longer authorizes promotion; ' +
      'the installer must pass its locked file descriptor with --deployment-lock-fd',
    );
  }
  if (
    deploymentValuesPresent.length > 0 &&
    deploymentValuesPresent.length !== deploymentKeys.length
  ) {
    throw new Error(
      `Installer-owned promotion requires all deployment transaction options: ` +
      deploymentKeys.map((key) => `--${key}`).join(', '),
    );
  }
  if (deploymentValuesPresent.length === 0 && values['deployment-lock-fd'] != null) {
    throw new Error(
      '--deployment-lock-fd may be used only with an installer-owned deployment transaction',
    );
  }
  if (deploymentValuesPresent.length > 0 && values['deployment-lock-fd'] == null) {
    throw new Error(
      'Installer-owned promotion requires --deployment-lock-fd with the inherited locked descriptor',
    );
  }
  const inheritedLockFd = values['deployment-lock-fd'] == null
    ? null
    : parseInheritedDeploymentLockFd(values['deployment-lock-fd']);
  const deploymentTransaction = deploymentValuesPresent.length === 0
    ? null
    : {
        transactionId: values['deployment-transaction-id'],
        releaseName: values['release-name'],
        releaseSha: values['release-sha'],
        artifactDigest: values['artifact-digest'],
        pendingStateHash: values['pending-state-hash'],
        requiredScoreReceiptId: values['required-score-receipt-id'],
        inheritedLockFd,
      };
  if (deploymentTransaction && !flags.has('apply')) {
    throw new Error('Installer-owned promotion requires --apply');
  }
  if (deploymentTransaction && !values['rollback-backup']) {
    throw new Error('Installer-owned promotion requires --rollback-backup');
  }
  if (
    deploymentTransaction &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      .test(deploymentTransaction.transactionId)
  ) {
    throw new Error('--deployment-transaction-id must be a UUID');
  }
  if (
    deploymentTransaction &&
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(deploymentTransaction.releaseName)
  ) {
    throw new Error('--release-name must be a safe basename');
  }
  if (
    deploymentTransaction &&
    !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(deploymentTransaction.releaseSha)
  ) {
    throw new Error('--release-sha must be a lowercase full object ID');
  }
  if (
    deploymentTransaction &&
    !/^sha256:[0-9a-f]{64}$/.test(deploymentTransaction.artifactDigest)
  ) {
    throw new Error('--artifact-digest must use sha256:<64 lowercase hex characters>');
  }
  if (
    deploymentTransaction &&
    !/^[0-9a-f]{64}$/.test(deploymentTransaction.pendingStateHash)
  ) {
    throw new Error('--pending-state-hash must be 64 lowercase hexadecimal characters');
  }
  if (
    deploymentTransaction &&
    !/^[0-9a-f]{64}$/.test(deploymentTransaction.requiredScoreReceiptId)
  ) {
    throw new Error('--required-score-receipt-id must be 64 lowercase hexadecimal characters');
  }
  return {
    help: false,
    sourcePath: values.source,
    destinationPath: values.destination,
    rollbackBackupPath: values['rollback-backup'] ?? null,
    deploymentTransaction,
    apply: flags.has('apply'),
    explicitDryRun: flags.has('dry-run'),
  };
}

export async function promoteQualityDb(options, dependencies = {}) {
  const apply = options.apply === true;
  if (!apply) return promoteQualityDbUnlocked(options, dependencies);

  const installerOwned = options.deploymentTransaction != null;
  const lockPath = installerOwned
    ? canonicalInstallerDeploymentLockPath(options.destinationPath)
    : options.lockPath ??
      process.env.RADAR_DEPLOY_LOCK_PATH ??
      DEFAULT_DEPLOYMENT_LOCK_PATH;
  const lockTimeoutSeconds = positiveInteger(
    options.lockTimeoutSeconds ??
      process.env.RADAR_DEPLOY_LOCK_TIMEOUT_SECONDS ??
      120,
    'deployment lock timeout',
  );
  const acquireLock =
    dependencies.acquireDeploymentLock ??
    acquireDeploymentLock;
  if (installerOwned) {
    const inheritedLockFd =
      options.deploymentTransaction?.inheritedLockFd;
    if (!Number.isInteger(inheritedLockFd) || inheritedLockFd < 3) {
      throw new Error(
        'Installer-owned promotion requires a concrete inherited deployment lock descriptor',
      );
    }
    const verifyInheritedLock =
      dependencies.verifyInheritedDeploymentLock ??
      verifyInheritedDeploymentLock;
    const inheritedLock = normalizeInheritedDeploymentLock(
      verifyInheritedLock({
        path: lockPath,
        fd: inheritedLockFd,
      }),
      {
        path: lockPath,
        fd: inheritedLockFd,
      },
    );
    inheritedLock.assertHeld('before installer-owned promotion');
    const verifiedDeploymentTransaction = verifiedInstallerDeploymentTransaction(
      options.deploymentTransaction,
    );
    const result = await promoteQualityDbUnlocked({
      ...options,
      deploymentTransaction: verifiedDeploymentTransaction,
    }, {
      ...dependencies,
      assertDeploymentLockHeld: inheritedLock.assertHeld,
    });
    return {
      ...result,
      deploymentLock: {
        path: lockPath,
        timeoutSeconds: lockTimeoutSeconds,
        sharedWithInstaller: true,
        inheritedFromInstaller: true,
        transactionId: verifiedDeploymentTransaction.transactionId,
        proof: inheritedLock.proof,
      },
    };
  }
  const deploymentLock = normalizeDeploymentLock(await acquireLock({
    path: lockPath,
    timeoutSeconds: lockTimeoutSeconds,
    flockBin: process.env.RADAR_DEPLOY_FLOCK_BIN ?? 'flock',
  }));
  try {
    const result = await promoteQualityDbUnlocked(options, {
      ...dependencies,
      assertDeploymentLockHeld: deploymentLock.assertHeld,
    });
    return {
      ...result,
      deploymentLock: {
        path: lockPath,
        timeoutSeconds: lockTimeoutSeconds,
        sharedWithInstaller: true,
      },
    };
  } finally {
    await deploymentLock.release();
  }
}

async function promoteQualityDbUnlocked(options, dependencies = {}) {
  const deps = {
    doctor: buildPromotionDoctorReport,
    verifyScore: verifyPromotionScore,
    verifyReleaseAudit: verifyPromotionReleaseAudit,
    verifyValidation: verifyPromotionValidation,
    verifyGithubReleaseCatalog: verifyPromotionGithubReleaseCatalog,
    latestEvaluationReceipt: latestCanonicalEvaluationReceipt,
    recordPromotion: recordCanonicalPromotion,
    readAdvisoryAuditProjection: readPromotionAdvisoryAuditProjection,
    listHolders: listDestinationHolders,
    now: () => new Date(),
    rename: renameSync,
    restoreRename: renameSync,
    readMetadata: readFileMetadata,
    cloneWithMetadata: cloneFileWithMetadata,
    copyContents: copyContentsPreservingMetadata,
    snapshotDatabase: vacuumInto,
    fsyncPath,
    fsyncDirectory,
    assertDeploymentLockHeld: () => {},
    ...dependencies,
  };
  const operationNow = deps.now();
  const doctor = (doctorOptions) => deps.doctor({ ...doctorOptions, now: operationNow });
  const sourcePath = resolveRequiredDatabase(options.sourcePath, 'source');
  const destinationPath = resolveRequiredDatabase(options.destinationPath, 'destination');
  const apply = options.apply === true;
  const explicitDryRun = options.explicitDryRun === true;
  const deploymentTransaction = options.deploymentTransaction ?? null;
  const pendingDeploymentAuthorization = assertNoPendingDeployment(
    destinationPath,
    deploymentTransaction,
  );
  let sourceFileIdentity = fileIdentity(sourcePath);
  const destinationFileIdentity = fileIdentity(destinationPath);
  assertDistinctDatabases(
    sourceFileIdentity,
    destinationFileIdentity,
    'Source',
    'destination',
  );
  const rollbackBackupPath = options.rollbackBackupPath == null
    ? null
    : resolveRequiredDatabase(options.rollbackBackupPath, 'rollback backup');
  const rollbackBackupFileIdentity = rollbackBackupPath == null
    ? null
    : fileIdentity(rollbackBackupPath);
  if (rollbackBackupFileIdentity) {
    assertDistinctDatabases(
      sourceFileIdentity,
      rollbackBackupFileIdentity,
      'Source',
      'rollback backup',
    );
    assertDistinctDatabases(
      destinationFileIdentity,
      rollbackBackupFileIdentity,
      'Destination',
      'rollback backup',
    );
  }
  if (pendingDeploymentAuthorization) {
    if (pendingDeploymentAuthorization.qualityDatabasePath !== sourceFileIdentity.realPath) {
      throw new Error(
        `Installer pending-deploy quality database does not match promotion source: ` +
        `${pendingDeploymentAuthorization.qualityDatabasePath} != ${sourceFileIdentity.realPath}`,
      );
    }
    if (
      rollbackBackupFileIdentity == null ||
      pendingDeploymentAuthorization.rollbackBackupPath !==
        rollbackBackupFileIdentity.realPath
    ) {
      throw new Error(
        `Installer pending-deploy rollback backup does not match promotion backup: ` +
        `${pendingDeploymentAuthorization.rollbackBackupPath} != ` +
        `${rollbackBackupFileIdentity?.realPath ?? 'missing'}`,
      );
    }
  }
  if (apply && destinationFileIdentity.linkCount !== 1) {
    throw new Error(
      `Destination database must have exactly one hard link before apply; ` +
      `found ${destinationFileIdentity.linkCount}: ${destinationPath}`,
    );
  }
  const destinationMetadata = deps.readMetadata(destinationPath);

  const initialDestinationActivity = inspectDatabaseActivity(
    deps,
    destinationPath,
    {
      phase: 'initial-destination',
      label: 'destination database at invocation',
    },
  );
  const initialHolders = initialDestinationActivity.holders;
  if (initialHolders.length > 0) {
    if (!apply && explicitDryRun) {
      // VACUUM INTO provides a consistent logical snapshot without mutating the live DB.
    } else {
      throw holderError(destinationPath, initialHolders);
    }
  }
  if (apply && initialDestinationActivity.refreshLeases.activeCount > 0) {
    throw activeLeaseError(
      destinationPath,
      initialDestinationActivity.refreshLeases,
      'destination database at invocation',
    );
  }

  const destinationDirectory = dirname(destinationPath);
  const stem = join(
    destinationDirectory,
    `.${basename(destinationPath)}.promotion-${process.pid}-${randomUUID()}`,
  );
  const sourceSnapshotPath = `${stem}.source.sqlite`;
  const sourceAfterStagingSnapshotPath = `${stem}.source-after-staging.sqlite`;
  const sourceBeforeGithubSnapshotPath = `${stem}.source-before-github.sqlite`;
  const sourceFinalBoundarySnapshotPath = `${stem}.source-final-boundary.sqlite`;
  const destinationSnapshotPath = `${stem}.destination.sqlite`;
  const finalDestinationSnapshotPath = `${stem}.destination-final.sqlite`;
  const installPath = `${stem}.install.sqlite`;
  const temporaryPaths = [
    sourceSnapshotPath,
    sourceAfterStagingSnapshotPath,
    sourceBeforeGithubSnapshotPath,
    sourceFinalBoundarySnapshotPath,
    destinationSnapshotPath,
    finalDestinationSnapshotPath,
    installPath,
  ];
  let backupPath = null;
  let unverifiedBackupPath = null;
  let backupVerification = null;
  let backupDoctor = null;
  let backupFileIdentity = null;
  let stagedFileIdentity = null;
  let oldDestinationIdentity = null;
  let swapAttempted = false;
  let swapSucceeded = false;

  try {
    const sourceActivityBeforeSnapshot = inspectDatabaseActivity(
      deps,
      sourcePath,
      {
        phase: 'source-before-snapshot',
        label: 'source database before snapshot',
      },
    );
    assertSourceActivityAllowsApply(sourcePath, sourceActivityBeforeSnapshot, apply);
    sourceFileIdentity = normalizeReadInspectionSqliteFamily(
      sourceFileIdentity,
      sourcePath,
      'Source database family changed during initial activity inspection',
    );
    deps.snapshotDatabase(sourcePath, sourceSnapshotPath);
    normalizeReadInspectionSqliteFamily(
      sourceFileIdentity,
      sourcePath,
      'Source database family changed identity while its promotion snapshot was created',
    );
    const sourceActivityAfterSnapshot = inspectDatabaseActivity(
      deps,
      sourcePath,
      {
        phase: 'source-after-snapshot',
        label: 'source database after snapshot',
      },
    );
    assertSourceActivityAllowsApply(sourcePath, sourceActivityAfterSnapshot, apply);
    normalizeReadInspectionSqliteFamily(
      sourceFileIdentity,
      sourcePath,
      'Source database family changed during post-snapshot activity inspection',
    );
    deps.snapshotDatabase(destinationPath, destinationSnapshotPath);

    const sourceVerification = verifyDatabase(sourceSnapshotPath, 'source snapshot', {
      requireScoreEvidenceSnapshots: true,
    });
    const sourceGithubReleaseCatalog = await deps.verifyGithubReleaseCatalog({
      dbPath: sourceSnapshotPath,
      label: 'source snapshot',
      runtimeEnvPath:
        pendingDeploymentAuthorization?.runtimeEnvPath ?? null,
      observedAt: operationNow.toISOString(),
    });
    assertReleaseCatalogReceiptRepositoryMatchesGithub(
      sourceVerification.releaseCatalogReceipt,
      sourceGithubReleaseCatalog,
      'Source snapshot',
    );
    const sourceDeploymentAuthorization = verifyDeploymentSourceAuthorization(
      sourceSnapshotPath,
      deploymentTransaction,
    );
    const destinationVerification = verifyDatabase(destinationSnapshotPath, 'destination snapshot');
    const sourceExpectedEvaluationReceipt = deps.latestEvaluationReceipt(
      sourceSnapshotPath,
      'source snapshot',
    );
    const sourceValidation = requireValidatedPromotionResult(
      deps.verifyValidation({
        dbPath: sourceSnapshotPath,
        label: 'source snapshot',
        expectedReceipt: sourceExpectedEvaluationReceipt,
      }),
      {
        label: 'source snapshot',
        expectedEvaluationReceipt: sourceExpectedEvaluationReceipt,
      },
    );
    const sourceValidationIdentity = promotionValidationIdentity(
      sourceValidation,
      'source snapshot',
    );
    const sourceDoctor = verifyDoctor(doctor, sourceSnapshotPath, 'source snapshot');
    const sourceAdvisoryAuditProjection = requireVerifiedAdvisoryAuditProjection(
      deps.readAdvisoryAuditProjection({
        dbPath: sourceSnapshotPath,
        label: 'source snapshot',
        observedAt: operationNow.toISOString(),
      }),
      'source snapshot',
    );
    const destinationDoctor = inspectDoctor(doctor, destinationSnapshotPath, 'destination snapshot');
    assertSchemaCompatibility(sourceVerification, destinationVerification);
    const sourceLeaseSnapshot = refreshLeaseSummary(
      sourceSnapshotPath,
      operationNow,
      'source snapshot',
    );
    const destinationLeaseSnapshot = refreshLeaseSummary(
      destinationSnapshotPath,
      operationNow,
      'destination snapshot',
    );
    if (apply && sourceLeaseSnapshot.activeCount > 0) {
      throw activeLeaseError(sourcePath, sourceLeaseSnapshot, 'source snapshot');
    }
    if (apply && destinationLeaseSnapshot.activeCount > 0) {
      throw activeLeaseError(destinationPath, destinationLeaseSnapshot, 'destination snapshot');
    }
    const historyMerge = assertDestinationHistoryAndPublicationContained(
      sourceSnapshotPath,
      destinationSnapshotPath,
    );
    const scorePersistenceMerge = {
      updated: false,
      strategy: 'source-authoritative',
      previousTip: historyMerge.sourceTip,
      finalTip: historyMerge.finalTip,
      equalTipPublicationParityChecked:
        historyMerge.equalTipPublicationParityChecked,
    };
    assertDestinationLedgersContained(sourceSnapshotPath, destinationSnapshotPath);

    const leaseSanitization = stripRefreshLeases(
      sourceSnapshotPath,
      operationNow,
      'staged promotion',
    );
    assert.equal(
      leaseSanitization.strippedCount,
      sourceLeaseSnapshot.rowCount,
      'Staged promotion did not strip every source refresh lease row',
    );
    const preservationMerge = mergeDestinationPreservedTables(
      sourceSnapshotPath,
      destinationSnapshotPath,
    );
    const operationReceiptMerge = mergeDestinationOperationReceipts(
      sourceSnapshotPath,
      destinationSnapshotPath,
    );
    const prePromotionStagedVerification = verifyDatabase(
      sourceSnapshotPath,
      'staged promotion before promotion receipt',
      {
      requireScoreEvidenceSnapshots: true,
      },
    );
    const stagedQualityGate = verifyStagedQualityGate({
      doctor,
      verifyScore: deps.verifyScore,
      verifyReleaseAudit: deps.verifyReleaseAudit,
      verifyValidation: deps.verifyValidation,
      latestEvaluationReceipt: deps.latestEvaluationReceipt,
      dbPath: sourceSnapshotPath,
      label: 'staged promotion',
    });
    const stagedValidationIdentity = promotionValidationIdentity(
      stagedQualityGate.validation,
      'staged promotion',
    );
    assertPromotionValidationIdentityEqual(
      sourceValidationIdentity,
      stagedValidationIdentity,
    );
    const promotionReceiptInput = {
      dbPath: sourceSnapshotPath,
      label: 'staged promotion',
      environment: 'production',
      promotedAt: operationNow.toISOString(),
      evaluation:
        stagedQualityGate.validation.canonicalEvaluationReceipt,
      sourceProofHash: sourceVerification.logicalContentDigest,
      destinationProofHash: destinationVerification.logicalContentDigest,
    };
    const canonicalPromotionReceipt = validateCanonicalPromotionReceiptSummary(
      deps.recordPromotion(promotionReceiptInput),
      promotionReceiptInput,
      'staged promotion',
    );
    verifyRecordedCanonicalPromotionReceipt(
      sourceSnapshotPath,
      canonicalPromotionReceipt,
      promotionReceiptInput,
      'staged promotion',
    );
    const stagedVerification = verifyDatabase(
      sourceSnapshotPath,
      'staged promotion with promotion receipt',
      { requireScoreEvidenceSnapshots: true },
    );
    assertGithubReleaseCatalogProofStillMatchesDatabase(
      sourceGithubReleaseCatalog,
      sourceSnapshotPath,
      'staged promotion with promotion receipt',
    );
    const stagedDoctor = verifyDoctor(
      doctor,
      sourceSnapshotPath,
      'staged promotion with promotion receipt',
    );
    const stagedAdvisoryAuditProjection = requireVerifiedAdvisoryAuditProjection(
      deps.readAdvisoryAuditProjection({
        dbPath: sourceSnapshotPath,
        label: 'staged promotion with promotion receipt',
        observedAt: operationNow.toISOString(),
      }),
      'staged promotion with promotion receipt',
    );
    assertAdvisoryAuditProjectionEqual(
      sourceAdvisoryAuditProjection,
      stagedAdvisoryAuditProjection,
      'Staged promotion changed the receipt-authorized advisory public-audit projection',
    );
    const stagedQualityVerification = {
      score: stagedQualityGate.score,
      releaseAudit: stagedQualityGate.releaseAudit,
      validation: stagedQualityGate.validation,
    };
    const stagedLeaseSummary = refreshLeaseSummary(
      sourceSnapshotPath,
      operationNow,
      'staged promotion',
    );
    assert.equal(
      stagedLeaseSummary.rowCount,
      0,
      'Staged promotion retains refresh lease rows',
    );
    assertSourceIdentityPreserved(sourceDoctor, stagedDoctor);
    assert.equal(
      stagedVerification.schemaDigest,
      prePromotionStagedVerification.schemaDigest,
      'staged promotion schema differs from the source snapshot',
    );
    assert.equal(
      stagedVerification.immutableLedgers[HISTORY_TABLE].rowCount,
      historyMerge.finalRows,
      'staged promotion history identity does not match the verified merge',
    );
    const sourceAfterStagingRevalidation = revalidateSourceDatabase({
      dependencies: deps,
      sourcePath,
      expectedFileIdentity: sourceFileIdentity,
      expectedDatabaseIdentity: sourceVerification,
      snapshotPath: sourceAfterStagingSnapshotPath,
      phase: 'source-after-staging',
      label: 'source database after promotion staging',
      apply,
    });

    const result = {
      mode: apply ? 'apply' : 'dry-run',
      explicitDryRun,
      reportValidity: {
        schemaVersion: 1,
        generatedAt: operationNow.toISOString(),
        durableEvidence: false,
        authorizesLaterApply: false,
        applyRequiresFreshActivityRevalidation: true,
      },
      deploymentTransaction: deploymentTransaction
        ? {
            schemaVersion: 1,
            ...deploymentTransaction,
            pendingDeploymentAuthorization,
            sourceAuthorization: sourceDeploymentAuthorization,
          }
        : null,
      activity: {
        schemaVersion: 1,
        source: {
          active:
            sourceActivityBeforeSnapshot.active ||
            sourceActivityAfterSnapshot.active ||
            sourceLeaseSnapshot.activeCount > 0 ||
            sourceAfterStagingRevalidation.active,
          beforeSnapshot: sourceActivityBeforeSnapshot,
          afterSnapshot: sourceActivityAfterSnapshot,
          afterStaging: sourceAfterStagingRevalidation,
          snapshotRefreshLeases: sourceLeaseSnapshot,
        },
        destination: {
          active:
            initialDestinationActivity.active ||
            destinationLeaseSnapshot.activeCount > 0,
          atInvocation: initialDestinationActivity,
          snapshotRefreshLeases: destinationLeaseSnapshot,
        },
        applyRevalidation: null,
      },
      source: {
        file: sourceFileIdentity,
        database: sourceVerification,
        doctor: doctorIdentity(sourceDoctor),
        validation: sourceValidation,
        snapshotProof: {
          method: 'VACUUM INTO',
          fileIdentityStable: true,
          holdersBefore: sourceActivityBeforeSnapshot.holders,
          holdersAfter: sourceActivityAfterSnapshot.holders,
          refreshLeases: sourceLeaseSnapshot,
          integrityVerified: true,
          doctorVerified: true,
          stagedLeaseRowsStripped: leaseSanitization.strippedCount,
          stagedLeaseRowsRemaining: stagedLeaseSummary.rowCount,
          afterStagingRevalidation: sourceAfterStagingRevalidation,
        },
      },
      destination: {
        file: destinationFileIdentity,
        database: destinationVerification,
        doctor: doctorIdentity(destinationDoctor),
        refreshLeases: destinationLeaseSnapshot,
      },
      staged: {
        database: stagedVerification,
        doctor: doctorIdentity(stagedDoctor),
        qualityVerification: stagedQualityVerification,
        canonicalPromotionReceipt,
        refreshLeases: stagedLeaseSummary,
      },
      advisoryPublicAuditProjection: {
        source: advisoryAuditProjectionEvidence(sourceAdvisoryAuditProjection),
        staged: advisoryAuditProjectionEvidence(stagedAdvisoryAuditProjection),
        install: null,
        installed: null,
        exactAcrossCompletedStages: true,
      },
      githubReleaseCatalog: {
        source: sourceGithubReleaseCatalog,
        beforeSwap: null,
        exactAcrossCompletedStages: true,
      },
      holders: initialHolders,
      leaseSanitization,
      preservationMerge,
      operationReceiptMerge,
      historyMerge,
      scorePersistenceMerge,
      promotionAuthorization: null,
      metadataPreservation: null,
      rollbackBackup: null,
      applied: false,
      backupPath: null,
    };

    if (!apply) return result;

    const sourceApplyRevalidation = revalidateSourceDatabase({
      dependencies: deps,
      sourcePath,
      expectedFileIdentity: sourceFileIdentity,
      expectedDatabaseIdentity: sourceVerification,
      snapshotPath: sourceAfterStagingSnapshotPath,
      phase: 'source-before-final-snapshot',
      label: 'source database apply revalidation',
      apply: true,
    });
    const destinationApplyRevalidation = inspectDatabaseActivity(
      deps,
      destinationPath,
      {
        phase: 'before-final-snapshot',
        label: 'destination database apply revalidation',
      },
    );
    if (destinationApplyRevalidation.holders.length > 0) {
      throw holderError(destinationPath, destinationApplyRevalidation.holders);
    }
    if (destinationApplyRevalidation.refreshLeases.activeCount > 0) {
      throw activeLeaseError(
        destinationPath,
        destinationApplyRevalidation.refreshLeases,
        'destination database apply revalidation',
      );
    }
    result.activity.applyRevalidation = {
      required: true,
      beforeFinalSnapshot: {
        source: sourceApplyRevalidation,
        destination: destinationApplyRevalidation,
      },
      immediatelyBeforeSwap: null,
      beforeSuccess: null,
    };
    assertFileMetadataEqual(
      destinationMetadata,
      deps.readMetadata(destinationPath),
      'Destination metadata changed while the promotion was staged',
    );

    deps.snapshotDatabase(destinationPath, finalDestinationSnapshotPath);
    const finalDestinationVerification = verifyDatabase(
      finalDestinationSnapshotPath,
      'final destination snapshot',
    );
    const finalDestinationDoctor = inspectDoctor(
      doctor,
      finalDestinationSnapshotPath,
      'final destination snapshot',
    );
    const finalDestinationLeaseSummary = refreshLeaseSummary(
      finalDestinationSnapshotPath,
      operationNow,
      'final destination snapshot',
    );
    if (finalDestinationLeaseSummary.activeCount > 0) {
      throw activeLeaseError(
        destinationPath,
        finalDestinationLeaseSummary,
        'final destination snapshot',
      );
    }
    assertSchemaCompatibility(sourceVerification, finalDestinationVerification);
    assertImmutableLedgersEqual(
      destinationVerification,
      finalDestinationVerification,
      'Destination immutable ledgers changed while the promotion was staged',
    );
    assertDestinationDriftTablesEqual(
      destinationVerification,
      finalDestinationVerification,
      'Destination evidence changed while the promotion was staged',
    );
    assertDestinationHistoryAndPublicationContained(
      sourceSnapshotPath,
      finalDestinationSnapshotPath,
    );
    assertDestinationLedgersContained(sourceSnapshotPath, finalDestinationSnapshotPath);

    checkpointAndClearSidecars(destinationPath);
    assertNoSidecars(destinationPath, 'after destination checkpoint');
    const checkpointedDestinationVerification = verifyDatabase(
      destinationPath,
      'checkpointed destination',
    );
    const checkpointedDestinationDoctor = inspectDoctor(
      doctor,
      destinationPath,
      'checkpointed destination',
    );
    assertDatabaseIdentityEqual(
      finalDestinationVerification,
      checkpointedDestinationVerification,
      'Checkpointed destination differs from the verified final destination snapshot',
    );
    assertDoctorIdentityEqual(
      finalDestinationDoctor,
      checkpointedDestinationDoctor,
      'Checkpointed destination doctor result differs from the verified final destination snapshot',
    );
    clearReadInspectionSidecars(
      destinationPath,
      'after checkpointed destination doctor inspection',
    );
    const holdersAfterCheckpoint = inspectHolders(
      deps,
      destinationPath,
      'after-checkpoint',
    );
    if (holdersAfterCheckpoint.length > 0) throw holderError(destinationPath, holdersAfterCheckpoint);
    assertNoSidecars(destinationPath, 'immediately before promotion swap');
    assertFileMetadataEqual(
      destinationMetadata,
      deps.readMetadata(destinationPath),
      'Destination metadata changed before promotion finalization',
    );

    const nextBackupPath =
      rollbackBackupPath ?? uniqueBackupPath(destinationPath, operationNow);
    if (rollbackBackupPath == null) {
      unverifiedBackupPath = nextBackupPath;
      prepareMetadataPreservingDatabase({
        metadataSourcePath: destinationPath,
        contentSourcePath: finalDestinationSnapshotPath,
        outputPath: nextBackupPath,
        expectedMetadata: destinationMetadata,
        dependencies: deps,
        label: 'promotion backup',
      });
    }
    const preparedBackupVerification = verifyDatabase(nextBackupPath, 'promotion backup');
    const preparedBackupDoctor = inspectDoctor(doctor, nextBackupPath, 'promotion backup');
    assertDatabaseIdentityEqual(
      finalDestinationVerification,
      preparedBackupVerification,
      'Promotion backup differs from the verified final destination snapshot',
    );
    assertDoctorIdentityEqual(
      finalDestinationDoctor,
      preparedBackupDoctor,
      'Promotion backup doctor result differs from the verified final destination snapshot',
    );
    assertFileMetadataEqual(
      destinationMetadata,
      deps.readMetadata(nextBackupPath),
      'Promotion backup did not preserve destination owner, group, mode, ACLs, and xattrs',
    );
    clearReadInspectionSidecars(
      nextBackupPath,
      'after promotion backup verification',
    );
    backupPath = nextBackupPath;
    unverifiedBackupPath = null;
    backupVerification = preparedBackupVerification;
    backupDoctor = preparedBackupDoctor;
    backupFileIdentity = fileIdentity(backupPath);
    const liveDestinationIdentity = fileIdentity(destinationPath);
    if (
      backupFileIdentity.device === liveDestinationIdentity.device &&
      backupFileIdentity.inode === liveDestinationIdentity.inode
    ) {
      throw new Error(`Promotion backup must be independent from the live destination inode: ${backupPath}`);
    }
    deps.fsyncPath(backupPath);
    deps.fsyncDirectory(destinationDirectory);

    prepareMetadataPreservingDatabase({
      metadataSourcePath: destinationPath,
      contentSourcePath: sourceSnapshotPath,
      outputPath: installPath,
      expectedMetadata: destinationMetadata,
      dependencies: deps,
      label: 'metadata-preserving staged promotion',
    });
    const installVerification = verifyDatabase(installPath, 'metadata-preserving staged promotion', {
      requireScoreEvidenceSnapshots: true,
    });
    const installDoctor = verifyDoctor(doctor, installPath, 'metadata-preserving staged promotion');
    const installAdvisoryAuditProjection = requireVerifiedAdvisoryAuditProjection(
      deps.readAdvisoryAuditProjection({
        dbPath: installPath,
        label: 'metadata-preserving staged promotion',
        observedAt: operationNow.toISOString(),
      }),
      'metadata-preserving staged promotion',
    );
    assertDatabaseIdentityEqual(
      stagedVerification,
      installVerification,
      'Metadata-preserving staged promotion differs from the verified staged database',
    );
    assertDoctorIdentityEqual(
      stagedDoctor,
      installDoctor,
      'Metadata-preserving staged promotion doctor result differs from the verified stage',
    );
    assertAdvisoryAuditProjectionEqual(
      sourceAdvisoryAuditProjection,
      installAdvisoryAuditProjection,
      'Metadata-preserving staged promotion changed the receipt-authorized advisory public-audit projection',
    );
    result.advisoryPublicAuditProjection.install =
      advisoryAuditProjectionEvidence(installAdvisoryAuditProjection);
    clearReadInspectionSidecars(
      installPath,
      'after metadata-preserving staged promotion verification',
    );
    stagedFileIdentity = fileIdentity(installPath);

    const sourceActivityBeforeGithubVerification = revalidateSourceDatabase({
      dependencies: deps,
      sourcePath,
      expectedFileIdentity: sourceFileIdentity,
      expectedDatabaseIdentity: sourceVerification,
      snapshotPath: sourceBeforeGithubSnapshotPath,
      phase: 'source-before-final-github-verification',
      label: 'source database before final GitHub verification',
      apply: true,
    });
    const beforeSwapGithubReleaseCatalog =
      await deps.verifyGithubReleaseCatalog({
        dbPath: sourceSnapshotPath,
        label: 'source database immediately before swap',
        runtimeEnvPath:
          pendingDeploymentAuthorization?.runtimeEnvPath ?? null,
        observedAt: deps.now().toISOString(),
      });
    assertReleaseCatalogReceiptRepositoryMatchesGithub(
      stagedVerification.releaseCatalogReceipt,
      beforeSwapGithubReleaseCatalog,
      'Source database immediately before swap',
    );
    result.githubReleaseCatalog.beforeSwap =
      beforeSwapGithubReleaseCatalog;
    const sourceActivityImmediatelyBeforeSwap = revalidateSourceDatabase({
      dependencies: deps,
      sourcePath,
      expectedFileIdentity: sourceFileIdentity,
      expectedDatabaseIdentity: sourceVerification,
      snapshotPath: sourceFinalBoundarySnapshotPath,
      phase: 'source-immediately-before-swap',
      label: 'source database immediately before swap',
      apply: true,
    });
    const immediateDestinationVerification = verifyDatabase(
      destinationPath,
      'destination immediately before promotion swap',
    );
    assertDatabaseIdentityEqual(
      checkpointedDestinationVerification,
      immediateDestinationVerification,
      'Destination logical contents changed immediately before promotion swap',
    );
    clearReadInspectionSidecars(
      destinationPath,
      'after immediate destination inspection',
    );
    assertFileMetadataEqual(
      destinationMetadata,
      deps.readMetadata(destinationPath),
      'Destination metadata changed immediately before promotion swap',
    );
    const destinationIdentityImmediatelyBeforeSwap =
      fileIdentity(destinationPath);
    assertFileIdentityEqual(
      destinationFileIdentity,
      destinationIdentityImmediatelyBeforeSwap,
      'Destination database path changed inode before promotion swap',
    );
    oldDestinationIdentity = {
      ...destinationIdentityImmediatelyBeforeSwap,
      family: [
        ...destinationFileIdentity.family,
        ...destinationIdentityImmediatelyBeforeSwap.family,
      ],
    };
    const holdersImmediatelyBeforeSwap = inspectHolders(
      deps,
      destinationPath,
      'immediately-before-swap',
    );
    if (holdersImmediatelyBeforeSwap.length > 0) {
      throw holderRaceError(
        destinationPath,
        'immediately before swap',
        holdersImmediatelyBeforeSwap,
      );
    }
    const destinationLeaseImmediatelyBeforeSwap = refreshLeaseSummary(
      destinationPath,
      deps.now(),
      'destination database immediately before swap',
    );
    if (destinationLeaseImmediatelyBeforeSwap.activeCount > 0) {
      throw activeLeaseError(
        destinationPath,
        destinationLeaseImmediatelyBeforeSwap,
        'destination database immediately before swap',
      );
    }
    clearReadInspectionSidecars(
      destinationPath,
      'after immediate pre-swap activity revalidation',
    );
    assertNoSidecars(destinationPath, 'at the promotion swap boundary');
    deps.assertDeploymentLockHeld('immediately before promotion swap');
    const sourceBoundaryHold = recheckSourceBoundary({
      dependencies: deps,
      sourcePath,
      expectedFileIdentity: sourceFileIdentity,
      phase: 'source-at-swap-boundary',
      label: 'source database at the promotion swap boundary',
      apply: true,
    });
    result.activity.applyRevalidation.immediatelyBeforeSwap = {
      sourceBeforeGithubVerification:
        sourceActivityBeforeGithubVerification,
      source: sourceActivityImmediatelyBeforeSwap,
      sourceBoundaryHold,
      destination: {
        observedAt: destinationLeaseImmediatelyBeforeSwap.observedAt,
        active:
          holdersImmediatelyBeforeSwap.length > 0 ||
          destinationLeaseImmediatelyBeforeSwap.activeCount > 0,
        holderCount: holdersImmediatelyBeforeSwap.length,
        holders: holdersImmediatelyBeforeSwap,
        refreshLeases: destinationLeaseImmediatelyBeforeSwap,
      },
    };

    swapAttempted = true;
    try {
      deps.rename(installPath, destinationPath);
      swapSucceeded = true;
    } catch (error) {
      swapSucceeded = stagedFileIdentity
        ? fileMatchesIdentity(destinationPath, stagedFileIdentity)
        : false;
      throw error;
    }
    deps.fsyncDirectory(destinationDirectory);
    const holdersImmediatelyAfterSwap = inspectHolders(
      deps,
      destinationPath,
      'immediately-after-swap',
    );
    const oldInodeWritersImmediatelyAfterSwap = inspectHolders(
      deps,
      destinationPath,
      'old-inode-immediately-after-swap',
      { identity: oldDestinationIdentity, writersOnly: true },
    );
    if (
      holdersImmediatelyAfterSwap.length > 0 ||
      oldInodeWritersImmediatelyAfterSwap.length > 0
    ) {
      throw holderRaceError(
        destinationPath,
        'immediately after swap',
        [...holdersImmediatelyAfterSwap, ...oldInodeWritersImmediatelyAfterSwap],
      );
    }
    assertNoSidecars(destinationPath, 'after promotion swap');

    const installedFileIdentity = fileIdentity(destinationPath);
    if (
      installedFileIdentity.device !== stagedFileIdentity.device ||
      installedFileIdentity.inode !== stagedFileIdentity.inode
    ) {
      throw new Error(
        `Installed destination does not identify the verified staged inode; rollback backup: ${backupPath}`,
      );
    }
    const installedVerification = verifyDatabase(destinationPath, 'installed destination', {
      requireScoreEvidenceSnapshots: true,
    });
    const installedDoctor = verifyDoctor(doctor, destinationPath, 'installed destination');
    const installedAdvisoryAuditProjection = requireVerifiedAdvisoryAuditProjection(
      deps.readAdvisoryAuditProjection({
        dbPath: destinationPath,
        label: 'installed destination',
        observedAt: operationNow.toISOString(),
      }),
      'installed destination',
    );
    assertDatabaseIdentityEqual(
      stagedVerification,
      installedVerification,
      'Installed destination logical contents differ from the verified staged promotion',
    );
    assertDoctorIdentityEqual(
      stagedDoctor,
      installedDoctor,
      'Installed destination doctor result differs from the verified staged promotion',
    );
    assertAdvisoryAuditProjectionEqual(
      sourceAdvisoryAuditProjection,
      installedAdvisoryAuditProjection,
      'Installed destination changed the receipt-authorized advisory public-audit projection',
    );
    result.advisoryPublicAuditProjection.installed =
      advisoryAuditProjectionEvidence(installedAdvisoryAuditProjection);
    const installedMetadata = deps.readMetadata(destinationPath);
    assertFileMetadataEqual(
      destinationMetadata,
      installedMetadata,
      'Installed destination did not preserve owner, group, mode, ACLs, and xattrs',
    );
    assertNoSidecars(destinationPath, 'after installed destination verification');
    const successActivity = inspectDatabaseActivity(
      deps,
      destinationPath,
      {
        phase: 'before-success',
        label: 'installed destination before success',
      },
    );
    const oldInodeWritersBeforeSuccess = inspectHolders(
      deps,
      destinationPath,
      'old-inode-before-success',
      { identity: oldDestinationIdentity, writersOnly: true },
    );
    if (successActivity.holders.length > 0 || oldInodeWritersBeforeSuccess.length > 0) {
      throw holderRaceError(
        destinationPath,
        'before success could be reported',
        [...successActivity.holders, ...oldInodeWritersBeforeSuccess],
      );
    }
    if (successActivity.refreshLeases.activeCount > 0) {
      throw activeLeaseError(
        destinationPath,
        successActivity.refreshLeases,
        'installed destination before success',
      );
    }
    clearReadInspectionSidecars(
      destinationPath,
      'after final success activity revalidation',
    );
    deps.assertDeploymentLockHeld('before promotion success');
    const finalInstalledFileIdentity = fileIdentity(destinationPath);
    assertFileIdentityEqual(
      installedFileIdentity,
      finalInstalledFileIdentity,
      'Installed destination path changed after final verification',
    );
    const installedPhysicalSha256 = sha256File(destinationPath);
    assertFileIdentityEqual(
      finalInstalledFileIdentity,
      fileIdentity(destinationPath),
      'Installed destination path changed while its physical digest was computed',
    );
    const installedDatabase = {
      logicalContentDigest: installedVerification.logicalContentDigest,
      schemaDigest: installedVerification.schemaDigest,
      physicalSha256: installedPhysicalSha256,
    };

    result.promotionAuthorization = buildPromotionAuthorization({
      sourceDatabase: sourceActivityImmediatelyBeforeSwap.database,
      installedDatabase,
      validationIdentity: stagedValidationIdentity,
      promotionReceipt: canonicalPromotionReceipt,
      githubReleaseCatalog: beforeSwapGithubReleaseCatalog,
    });
    result.applied = true;
    result.backupPath = backupPath;
    result.destination.file = installedFileIdentity;
    result.destination.database = installedVerification;
    result.destination.doctor = doctorIdentity(installedDoctor);
    result.destination.refreshLeases = successActivity.refreshLeases;
    result.activity.applyRevalidation.beforeSuccess = successActivity;
    result.metadataPreservation = {
      destination: metadataSummary(installedMetadata),
      backup: metadataSummary(deps.readMetadata(backupPath)),
      verified: true,
    };
    result.rollbackBackup = {
      externallyPrepared: rollbackBackupPath != null,
      file: backupFileIdentity,
      database: backupVerification,
      doctor: doctorIdentity(backupDoctor),
      metadata: metadataSummary(deps.readMetadata(backupPath)),
      verifiedAgainstPrePromotionDestination: true,
    };
    return result;
  } catch (error) {
    if (
      backupPath &&
      backupFileIdentity &&
      swapSucceeded &&
      backupVerification &&
      backupDoctor
    ) {
      const rollback = attemptAutomaticRollback({
        destinationPath,
        destinationDirectory,
        backupPath,
        backupFileIdentity,
        backupVerification,
        backupDoctor,
        expectedMetadata: destinationMetadata,
        dependencies: { ...deps, doctor },
        temporaryPaths,
      });
      if (rollback.restored) {
        throw new Error(
          `Promotion failed after the swap; the original destination was restored automatically. ` +
          `Backup retained at ${backupPath}: ${errorMessage(error)}`,
        );
      }
      throw new Error(
        `Promotion failed after the swap and automatic rollback did not complete. ` +
        `${rollback.reason} Rollback backup: ${backupPath}. Cause: ${errorMessage(error)}`,
      );
    }
    if (backupPath && swapAttempted) {
      throw new Error(
        `Promotion swap failed; the original destination remains unchanged. ` +
        `Backup retained at ${backupPath}: ${errorMessage(error)}`,
      );
    }
    if (backupPath) {
      throw new Error(
        `Promotion finalization failed before the swap. Backup retained at ${backupPath}: ` +
        errorMessage(error),
      );
    }
    throw error;
  } finally {
    if (unverifiedBackupPath) {
      removeSqliteFamily(unverifiedBackupPath);
    }
    for (const path of temporaryPaths) {
      removeSqliteFamily(path);
    }
  }
}

function buildPromotionDoctorReport(options) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'tableExists');
  const installCompatibility = typeof globalThis.tableExists !== 'function';
  if (installCompatibility) {
    Object.defineProperty(globalThis, 'tableExists', {
      configurable: true,
      value: (db, table) => tableExists(db, table),
    });
  }
  try {
    const report = buildDoctorReport(options);
    const promotionImmutableLedgers = promotionImmutableLedgerDoctorSummary(options.dbPath);
    const failures = Array.isArray(report.failures) ? [...report.failures] : [];
    if (!promotionImmutableLedgers.ok) {
      failures.push(
        `promotion immutable ledger verification failed: ` +
        `${promotionImmutableLedgers.error ?? 'unknown error'}`,
      );
    }
    return {
      ...report,
      ok: report.ok === true && promotionImmutableLedgers.ok,
      failures,
      promotionImmutableLedgers,
    };
  } finally {
    if (installCompatibility) {
      if (descriptor) Object.defineProperty(globalThis, 'tableExists', descriptor);
      else delete globalThis.tableExists;
    }
  }
}

export function promotionImmutableLedgerDoctorSummary(
  dbPath = process.env.DB_PATH ?? './data/radar.db',
) {
  const db = new DatabaseSync(resolve(dbPath), { readOnly: true, timeout: 10_000 });
  try {
    const tables = Object.fromEntries(
      IMMUTABLE_LEDGER_TABLES.map((table) => [table, tableIdentity(db, table)]),
    );
    verifyAppendOnlyTriggers(db, 'promotion doctor');
    return {
      ok: true,
      error: null,
      tableCount: IMMUTABLE_LEDGER_TABLES.length,
      tableDigest: digestJson(tables),
      tables,
      appendOnlyTriggerCount: REQUIRED_APPEND_ONLY_TRIGGERS.length,
      appendOnlyTriggerDigest: digestJson(REQUIRED_APPEND_ONLY_TRIGGERS),
    };
  } catch (error) {
    return {
      ok: false,
      error: errorMessage(error),
      tableCount: IMMUTABLE_LEDGER_TABLES.length,
      tableDigest: null,
      tables: null,
      appendOnlyTriggerCount: REQUIRED_APPEND_ONLY_TRIGGERS.length,
      appendOnlyTriggerDigest: digestJson(REQUIRED_APPEND_ONLY_TRIGGERS),
    };
  } finally {
    db.close();
  }
}

function resolveRequiredDatabase(inputPath, label) {
  if (typeof inputPath !== 'string' || !inputPath.trim()) {
    throw new Error(`${label} database path is required`);
  }
  const path = resolve(inputPath);
  if (!existsSync(path)) throw new Error(`${label} database does not exist: ${path}`);
  const info = lstatSync(path);
  if (info.isSymbolicLink()) throw new Error(`${label} database must not be a symbolic link: ${path}`);
  if (!info.isFile()) throw new Error(`${label} database is not a regular file: ${path}`);
  return path;
}

function fileIdentity(path) {
  const family = sqliteFamilyIdentity(path);
  const main = family[0];
  if (!main.exists) {
    throw new Error(`Database does not exist while reading identity: ${path}`);
  }
  return {
    path,
    realPath: main.resolvedPath,
    device: main.device,
    inode: main.inode,
    sizeBytes: main.sizeBytes,
    linkCount: main.linkCount,
    family,
  };
}

function sqliteFamilyIdentity(databasePath) {
  const family = SQLITE_FAMILY_SUFFIXES.map((suffix) =>
    sqliteFamilyMemberIdentity(`${databasePath}${suffix}`, suffix));
  assertNoInternalSqliteFamilyAliases(family, databasePath);
  return family;
}

function sqliteFamilyMemberIdentity(memberPath, suffix) {
  const path = resolve(memberPath);
  let pathInfo;
  try {
    pathInfo = lstatSync(path, { bigint: true });
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      throw new Error(
        `Could not inspect SQLite family member: ${path}`,
        { cause: error },
      );
    }
    return {
      suffix,
      path,
      resolvedPath: resolveThroughExistingAncestor(path),
      exists: false,
      device: null,
      inode: null,
      sizeBytes: null,
      linkCount: null,
      modifiedAtNs: null,
      changedAtNs: null,
    };
  }
  if (pathInfo.isSymbolicLink() || !pathInfo.isFile()) {
    throw new Error(
      `SQLite family member must be a regular non-symlink file: ${path}`,
    );
  }
  const realPath = realpathSync(path);
  const info = statSync(realPath, { bigint: true });
  if (pathInfo.dev !== info.dev || pathInfo.ino !== info.ino) {
    throw new Error(`SQLite family member changed while inspected: ${path}`);
  }
  return {
    suffix,
    path,
    resolvedPath: realPath,
    exists: true,
    device: String(info.dev),
    inode: String(info.ino),
    sizeBytes: Number(info.size),
    linkCount: Number(info.nlink),
    modifiedAtNs: String(info.mtimeNs),
    changedAtNs: String(info.ctimeNs),
  };
}

function resolveThroughExistingAncestor(path) {
  let current = resolve(path);
  const missingSegments = [];
  for (;;) {
    try {
      return resolve(realpathSync(current), ...missingSegments);
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw new Error(
          `Could not resolve SQLite family member: ${path}`,
          { cause: error },
        );
      }
      const parent = dirname(current);
      if (parent === current) return resolve(path);
      missingSegments.unshift(basename(current));
      current = parent;
    }
  }
}

function assertNoInternalSqliteFamilyAliases(family, databasePath) {
  for (let leftIndex = 0; leftIndex < family.length; leftIndex++) {
    for (let rightIndex = leftIndex + 1; rightIndex < family.length; rightIndex++) {
      const left = family[leftIndex];
      const right = family[rightIndex];
      if (sqliteFamilyMembersAlias(left, right)) {
        throw new Error(
          `SQLite database family contains path or inode aliases: ` +
          `${left.path} aliases ${right.path} for ${databasePath}`,
        );
      }
    }
  }
}

function assertDistinctDatabases(
  source,
  destination,
  sourceLabel = 'Source',
  destinationLabel = 'destination',
) {
  for (const sourceMember of source.family) {
    for (const destinationMember of destination.family) {
      if (!sqliteFamilyMembersAlias(sourceMember, destinationMember)) continue;
      throw new Error(
        `${sourceLabel} and ${destinationLabel} must identify distinct database files ` +
        `across their SQLite families: ${sourceMember.path} aliases ` +
        `${destinationMember.path}`,
      );
    }
  }
}

function sqliteFamilyMembersAlias(left, right) {
  if (left.resolvedPath === right.resolvedPath) return true;
  return (
    left.exists &&
    right.exists &&
    left.device === right.device &&
    left.inode === right.inode
  );
}

function assertFileIdentityEqual(expected, actual, message) {
  if (
    expected.realPath !== actual.realPath ||
    expected.device !== actual.device ||
    expected.inode !== actual.inode ||
    expected.linkCount !== actual.linkCount
  ) {
    throw new Error(message);
  }
}

function normalizeReadInspectionSqliteFamily(
  expectedIdentity,
  databasePath,
  message,
) {
  const observedIdentity = fileIdentity(databasePath);
  assertFileIdentityEqual(expectedIdentity, observedIdentity, message);
  assertSqliteMainStorageIdentityEqual(
    expectedIdentity.family[0],
    observedIdentity.family[0],
    message,
  );
  for (const suffix of ['-wal', '-journal']) {
    const expectedMember = expectedIdentity.family.find(
      (member) => member.suffix === suffix,
    );
    const observedMember = observedIdentity.family.find(
      (member) => member.suffix === suffix,
    );
    for (const member of [expectedMember, observedMember]) {
      if (member?.exists && member.sizeBytes > 0) {
        throw new Error(
          `${message}: non-empty SQLite ${suffix.slice(1)} sidecar ` +
          `${member.path}`,
        );
      }
    }
  }
  removeSqliteSidecars(databasePath);
  assertNoSidecars(databasePath, message);
  const normalizedIdentity = fileIdentity(databasePath);
  assertFileIdentityEqual(expectedIdentity, normalizedIdentity, message);
  assertSqliteMainStorageIdentityEqual(
    expectedIdentity.family[0],
    normalizedIdentity.family[0],
    message,
  );
  return normalizedIdentity;
}

function assertSqliteMainStorageIdentityEqual(expected, actual, message) {
  if (
    expected.path !== actual.path ||
    expected.suffix !== '' ||
    actual.suffix !== '' ||
    expected.resolvedPath !== actual.resolvedPath ||
    expected.exists !== actual.exists ||
    expected.device !== actual.device ||
    expected.inode !== actual.inode ||
    expected.sizeBytes !== actual.sizeBytes ||
    expected.linkCount !== actual.linkCount ||
    expected.modifiedAtNs !== actual.modifiedAtNs ||
    expected.changedAtNs !== actual.changedAtNs
  ) {
    throw new Error(message);
  }
}

function sqliteFamilyPaths(databasePath) {
  return SQLITE_FAMILY_SUFFIXES.map((suffix) => `${databasePath}${suffix}`);
}

function sqliteSidecarPaths(databasePath) {
  return SQLITE_SIDECAR_SUFFIXES.map((suffix) => `${databasePath}${suffix}`);
}

function removeSqliteFamily(databasePath) {
  for (const path of sqliteFamilyPaths(databasePath)) {
    rmSync(path, { force: true });
  }
}

function removeSqliteSidecars(databasePath) {
  for (const path of sqliteSidecarPaths(databasePath)) {
    rmSync(path, { force: true });
  }
}

function vacuumInto(sourcePath, snapshotPath) {
  removeSqliteFamily(snapshotPath);
  const db = new DatabaseSync(sourcePath, { readOnly: true, timeout: 10_000 });
  try {
    db.prepare('VACUUM INTO ?').run(snapshotPath);
  } finally {
    db.close();
  }
}

function verifyDatabase(path, label, {
  requireScoreEvidenceSnapshots = false,
} = {}) {
  const db = new DatabaseSync(path, { readOnly: true, timeout: 10_000 });
  try {
    const integrityRows = db.prepare('PRAGMA integrity_check').all();
    const integrityFailures = integrityRows
      .map((row) => String(Object.values(row)[0]))
      .filter((value) => value !== 'ok');
    if (integrityFailures.length > 0) {
      throw new Error(`${label} failed integrity_check: ${integrityFailures.join('; ')}`);
    }
    const foreignKeyFailures = db.prepare('PRAGMA foreign_key_check').all();
    if (foreignKeyFailures.length > 0) {
      throw new Error(`${label} failed foreign_key_check: ${JSON.stringify(foreignKeyFailures.slice(0, 10))}`);
    }
    verifyHistorySchema(db, label);
    verifyHistoryRunSchema(db, label);
    verifyForecastSeriesSchema(db, label);
    verifyMaturedOutcomeIndex(db, label);
    verifyAppendOnlyTriggers(db, label);
    verifyScoreEvidenceSnapshotSchemas(db, label, {
      required: requireScoreEvidenceSnapshots,
    });
    verifyHistoryRunLedger(db, label);
    verifyOperationReceiptLedgerRows(db, label);
    const releaseCatalogReceipt =
      verifyReleaseCatalogCaptureReceiptLedgerRows(db, label);
    return {
      ...databaseIdentity(db),
      releaseCatalogReceipt: {
        receiptCount: releaseCatalogReceipt.receiptCount,
        latestReceiptId: releaseCatalogReceipt.latestReceiptId,
        latestOperationRunId: releaseCatalogReceipt.latestOperationRunId,
        latestSource: releaseCatalogReceipt.latestSource,
        latestRepository:
          releaseCatalogReceipt.latestPayload?.repository ?? null,
      },
    };
  } finally {
    db.close();
  }
}

function verifyScoreEvidenceSnapshotSchemas(db, label, { required }) {
  for (const spec of CANONICAL_SCORE_EVIDENCE_SCHEMAS) {
    if (!tableExists(db, spec.table)) {
      if (required) {
        throw new Error(`${label} is missing canonical score-evidence table ${spec.table}`);
      }
      continue;
    }

    const actualColumns = db.prepare(`PRAGMA table_info(${quoteIdentifier(spec.table)})`).all()
      .sort((left, right) => Number(left.cid) - Number(right.cid))
      .map((column) => [
        String(column.name),
        String(column.type ?? '').toUpperCase(),
        Number(column.notnull ?? 0),
        Number(column.pk ?? 0),
        normalizeSqlDefault(column.dflt_value),
      ]);
    if (JSON.stringify(actualColumns) !== JSON.stringify(spec.columns)) {
      throw new Error(`${label} has non-canonical columns or constraints for ${spec.table}`);
    }

    const indexes = db.prepare(`PRAGMA index_list(${quoteIdentifier(spec.table)})`).all();
    for (const expected of spec.indexes) {
      const index = indexes.find((candidate) =>
        (expected.name == null || candidate.name === expected.name) &&
        Number(candidate.unique ?? 0) === expected.unique &&
        Number(candidate.partial ?? 0) === expected.partial &&
        String(candidate.origin ?? '') === expected.origin &&
        JSON.stringify(indexKeyColumns(db, candidate.name)) ===
          JSON.stringify(expected.columns));
      if (!index) {
        const indexLabel = expected.name ?? `${expected.origin}(${expected.columns.join(', ')})`;
        throw new Error(
          `${label} is missing canonical index ${indexLabel} on ${spec.table}`,
        );
      }
    }
  }
}

function verifyForecastSeriesSchema(db, label) {
  const legacyColumns = ['opportunity_code', 'latest_release_tag'];
  const indexes = db.prepare(`PRAGMA index_list(${FORECAST_TABLE})`).all()
    .filter((index) => Number(index.unique) === 1);
  const indexSql = (index) => String(db.prepare(`
    SELECT sql FROM sqlite_schema WHERE type='index' AND name=?
  `).get(index.name)?.sql ?? '').trim();
  const hasWithoutRevision = indexes.some((index) =>
    Number(index.partial) === 1 &&
    JSON.stringify(indexKeyColumns(db, index.name)) ===
      JSON.stringify(FORECAST_SERIES_IDENTITY_COLUMNS_WITHOUT_REVISION) &&
    /WHERE\s+code_revision\s+IS\s+NULL\s*$/i.test(indexSql(index)));
  const hasWithRevision = indexes.some((index) =>
    Number(index.partial) === 1 &&
    JSON.stringify(indexKeyColumns(db, index.name)) ===
      JSON.stringify(FORECAST_SERIES_IDENTITY_COLUMNS_WITH_REVISION) &&
    /WHERE\s+code_revision\s+IS\s+NOT\s+NULL\s*$/i.test(indexSql(index)));
  const hasLegacyForecastUnique = indexes.some((index) => {
    if (Number(index.partial) !== 0) return false;
    const columns = indexKeyColumns(db, index.name);
    return (
      columns.length === legacyColumns.length &&
      legacyColumns.every((column) => columns.includes(column)
    )) || JSON.stringify(columns) ===
      JSON.stringify(FORECAST_SERIES_IDENTITY_COLUMNS_WITHOUT_REVISION);
  });
  if (!hasWithoutRevision || !hasWithRevision || hasLegacyForecastUnique) {
    throw new Error(
      `${label} is missing revision-aware partial unique indexes on ${FORECAST_TABLE}, ` +
      `or still enforces a legacy identity that omits code_revision`,
    );
  }
}

function verifyHistorySchema(db, label) {
  const columns = db.prepare(`PRAGMA table_info(${HISTORY_TABLE})`).all();
  const byName = new Map(columns.map((column) => [column.name, column]));
  for (const column of HISTORY_COLUMNS) {
    if (!byName.has(column)) throw new Error(`${label} is missing ${HISTORY_TABLE}.${column}`);
  }
  const indexes = db.prepare(`PRAGMA index_list(${HISTORY_TABLE})`).all();
  const hasRunReleaseUnique = indexes.some((index) => {
    if (Number(index.unique) !== 1 || Number(index.partial) !== 0) return false;
    return JSON.stringify(indexKeyColumns(db, index.name)) ===
      JSON.stringify(['run_id', 'release_tag']);
  });
  if (!hasRunReleaseUnique) {
    throw new Error(
      `${label} is missing a full, enforcing UNIQUE(run_id, release_tag) on ${HISTORY_TABLE}`,
    );
  }
}

function verifyHistoryRunSchema(db, label) {
  const requiredColumns = [
    'id',
    'run_id',
    'recorded_at',
    'row_count',
    'rows_content_hash',
    'previous_content_hash',
    'content_hash',
  ];
  const columns = db.prepare(`PRAGMA table_info(${HISTORY_RUN_TABLE})`).all();
  const existing = new Set(columns.map((column) => column.name));
  const missing = requiredColumns.filter((column) => !existing.has(column));
  if (missing.length > 0) {
    throw new Error(`${label} is missing ${HISTORY_RUN_TABLE} columns: ${missing.join(', ')}`);
  }
  for (const column of ['run_id', 'content_hash']) {
    const enforcing = db.prepare(`PRAGMA index_list(${HISTORY_RUN_TABLE})`).all().some((index) =>
      Number(index.unique) === 1 &&
      Number(index.partial) === 0 &&
      JSON.stringify(indexKeyColumns(db, index.name)) === JSON.stringify([column]));
    if (!enforcing) {
      throw new Error(
        `${label} is missing a full, enforcing UNIQUE(${column}) on ${HISTORY_RUN_TABLE}`,
      );
    }
  }
}

function verifyHistoryRunLedger(db, label) {
  const rowsByRun = runsById(readHistoryRows(db));
  const seals = readHistoryRunSeals(db);
  const sealsByRun = new Map(seals.map((seal) => [seal.run_id, seal]));
  for (const runId of rowsByRun.keys()) {
    if (!sealsByRun.has(runId)) {
      throw new Error(`${label} history run ${JSON.stringify(runId)} is missing its immutable seal`);
    }
  }
  for (const seal of seals) {
    const rows = rowsByRun.get(seal.run_id);
    if (!rows) {
      throw new Error(`${label} history run seal ${JSON.stringify(seal.run_id)} has no rows`);
    }
  }

  let previousContentHash = null;
  for (const seal of seals) {
    const rows = rowsByRun.get(seal.run_id);
    const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(rows);
    const expectedContentHash = releaseScoreAuditHistoryRunContentHash({
      runId: seal.run_id,
      recordedAt: seal.recorded_at,
      rowCount: Number(seal.row_count),
      rowsContentHash: seal.rows_content_hash,
      previousContentHash: seal.previous_content_hash ?? null,
    });
    const recordedAts = new Set(rows.map((row) => row.recorded_at));
    if (
      (seal.previous_content_hash ?? null) !== previousContentHash ||
      Number(seal.row_count) !== rows.length ||
      seal.rows_content_hash !== rowsContentHash ||
      seal.content_hash !== expectedContentHash ||
      recordedAts.size !== 1 ||
      !recordedAts.has(seal.recorded_at)
    ) {
      throw new Error(
        `${label} history run seal chain is invalid at ${JSON.stringify(seal.run_id)}`,
      );
    }
    previousContentHash = seal.content_hash;
  }
}

function verifyMaturedOutcomeIndex(db, label) {
  const table = 'release_validation_outcome_observations';
  const index = db.prepare(`PRAGMA index_list(${table})`).all()
    .find((candidate) => candidate.name === MATURED_OUTCOME_INDEX);
  const sql = String(db.prepare(`
    SELECT sql
    FROM sqlite_schema
    WHERE type='index' AND name=?
  `).get(MATURED_OUTCOME_INDEX)?.sql ?? '');
  const predicate = sql.match(/\bWHERE\b([\s\S]*)$/i)?.[1] ?? '';
  if (
    !index ||
    Number(index.unique) !== 1 ||
    Number(index.partial) !== 1 ||
    JSON.stringify(indexKeyColumns(db, index.name)) !==
      JSON.stringify(['decision_id', 'horizon_code']) ||
    normalizeIndexPredicate(predicate) !== "status='matured'"
  ) {
    throw new Error(
      `${label} is missing the enforcing partial unique index ${MATURED_OUTCOME_INDEX}`,
    );
  }
}

function verifyAppendOnlyTriggers(db, label) {
  const triggers = db.prepare(`
    SELECT name, tbl_name, sql
    FROM sqlite_schema
    WHERE type='trigger'
  `).all();
  const appendOnlyTriggers = triggers
    .map(appendOnlyTriggerShape)
    .filter(Boolean);
  const byName = new Map(
    appendOnlyTriggers.map((trigger) => [trigger.name, trigger]),
  );
  for (const [name, table, event] of REQUIRED_APPEND_ONLY_TRIGGERS) {
    const trigger = byName.get(name);
    if (
      !trigger ||
      trigger.table !== table ||
      trigger.event !== event
    ) {
      throw new Error(`${label} is missing required append-only trigger ${name}`);
    }
  }
  const [undeclared] = undeclaredAppendOnlyTriggerShapes(triggers);
  if (undeclared) {
    throw new Error(
      `${label} has undeclared append-only trigger ${undeclared.name} on ` +
      `${undeclared.table}; add the table to the canonical promotion immutable-ledger manifest`,
    );
  }
}

function databaseIdentity(db) {
  const schemaRows = db.prepare(`
    SELECT type, name, tbl_name, sql
    FROM sqlite_schema
    WHERE name NOT LIKE 'sqlite_%'
    ORDER BY type, name
  `).all();
  const historyRows = readHistoryRows(db);
  const immutableLedgers = Object.fromEntries(
    IMMUTABLE_LEDGER_TABLES.map((table) => [table, tableIdentity(db, table)]),
  );
  const destinationDriftTables = Object.fromEntries(
    DESTINATION_DRIFT_TABLES.map((table) => [
      table,
      tableIdentity(db, table, {
        allowMissing: SCORE_EVIDENCE_SNAPSHOT_TABLES.includes(table),
      }),
    ]),
  );
  const logicalTables = db.prepare(`
    SELECT name
    FROM sqlite_schema
    WHERE type='table'
      AND (name NOT LIKE 'sqlite_%' OR name='sqlite_sequence')
    ORDER BY name
  `).all().map((row) => row.name);
  const logicalContents = Object.fromEntries(
    logicalTables.map((table) => [table, tableIdentity(db, table)]),
  );
  const schemaObjectKeys = schemaRows.map((row) => `${row.type}:${row.name}`);
  const tableColumns = Object.fromEntries(
    logicalTables
      .filter((table) => table !== 'sqlite_sequence')
      .map((table) => [
        table,
        db.prepare(`PRAGMA table_info("${escapeIdentifier(table)}")`).all().map((column) => ({
          name: column.name,
          type: String(column.type ?? '').toUpperCase(),
          notnull: Number(column.notnull ?? 0),
          pk: Number(column.pk ?? 0),
        })),
      ]),
  );
  const scoreMeta = tableExists(db, 'meta')
    ? db.prepare(`SELECT value FROM meta WHERE key='score_persistence_last_run'`).get()?.value ?? null
    : null;
  return {
    applicationId: pragmaScalar(db, 'application_id'),
    userVersion: pragmaScalar(db, 'user_version'),
    schemaDigest: digestJson(schemaRows),
    schemaObjectKeys,
    tableColumns,
    logicalContentDigest: digestJson(logicalContents),
    immutableLedgerDigest: digestJson(immutableLedgers),
    immutableLedgers,
    destinationDriftTableDigest: digestJson(destinationDriftTables),
    destinationDriftTables,
    historyRowCount: historyRows.length,
    historyDigest: digestJson(historyRows.map(historyRowContent)),
    scorePersistenceDigest: digestText(scoreMeta),
  };
}

function assertSchemaCompatibility(source, destination) {
  if (source.applicationId !== destination.applicationId ||
    source.userVersion < destination.userVersion) {
    throw new Error(
      `Source schema is older or incompatible with the destination ` +
      `(source user_version=${source.userVersion}, destination user_version=${destination.userVersion}); ` +
      `migrate the source database before promotion`,
    );
  }
  if (
    source.userVersion === destination.userVersion &&
    source.schemaDigest !== destination.schemaDigest
  ) {
    throw new Error(
      `Source schema digest differs from the destination at equal user_version ` +
      `${source.userVersion}; migrate both databases to one canonical schema ` +
      `before promotion`,
    );
  }
  const destinationObjects = new Set(destination.schemaObjectKeys ?? []);
  const sourceOnlyTriggers = (source.schemaObjectKeys ?? [])
    .filter((key) =>
      key.startsWith('trigger:') && !destinationObjects.has(key));
  if (sourceOnlyTriggers.length > 0) {
    throw new Error(
      `Source schema has triggers absent from the destination: ` +
      sourceOnlyTriggers.join(', '),
    );
  }
  const sourceObjects = new Set(source.schemaObjectKeys ?? []);
  const missingObjects = (destination.schemaObjectKeys ?? [])
    .filter((key) => !sourceObjects.has(key));
  const incompatibleColumns = [];
  for (const [table, destinationColumns] of Object.entries(destination.tableColumns ?? {})) {
    const sourceColumns = new Map(
      (source.tableColumns?.[table] ?? []).map((column) => [column.name, column]),
    );
    for (const destinationColumn of destinationColumns) {
      const sourceColumn = sourceColumns.get(destinationColumn.name);
      if (!sourceColumn ||
        sourceColumn.type !== destinationColumn.type ||
        destinationColumn.notnull === 1 && sourceColumn.notnull !== 1 ||
        destinationColumn.pk > 0 && sourceColumn.pk !== destinationColumn.pk) {
        incompatibleColumns.push(`${table}.${destinationColumn.name}`);
      }
    }
  }
  if (missingObjects.length > 0 || incompatibleColumns.length > 0) {
    throw new Error(
      `Source schema is older or incompatible with the destination ` +
      `(missing objects=${missingObjects.join(', ') || 'none'}; ` +
      `incompatible columns=${incompatibleColumns.join(', ') || 'none'}); ` +
      `migrate the source database before promotion`,
    );
  }
}

function assertDestinationLedgersContained(sourcePath, destinationPath) {
  const source = new DatabaseSync(sourcePath, { readOnly: true, timeout: 10_000 });
  const destination = new DatabaseSync(destinationPath, { readOnly: true, timeout: 10_000 });
  try {
    assertDestinationReleaseCatalogReceiptChainPrefix(source, destination);
    assertActiveReleaseCatalogsCanonical(source, destination);
    for (const table of SOURCE_REQUIRED_LEDGER_TABLES) {
      const sourceRows = tableCanonicalRows(source, table);
      const destinationRows = tableCanonicalRows(destination, table);
      const available = rowMultiset(sourceRows);
      const missing = [];
      for (const row of destinationRows) {
        const count = available.get(row) ?? 0;
        if (count <= 0) missing.push(row);
        else available.set(row, count - 1);
      }
      if (missing.length > 0) {
        throw new Error(
          `Destination immutable ledger ${table} contains ${missing.length} row(s) absent from ` +
          `the source; promotion would drop verified ledger evidence`,
        );
      }
    }
  } finally {
    destination.close();
    source.close();
  }
}

function assertActiveReleaseCatalogsCanonical(source, destination) {
  const sourceRows = activeReleaseCatalogEvolutionRows(source);
  const destinationRows = activeReleaseCatalogEvolutionRows(destination);
  assertCanonicalActiveReleaseCatalogOrder(sourceRows, 'Source');
  assertCanonicalActiveReleaseCatalogOrder(destinationRows, 'Destination');
}

function assertCanonicalActiveReleaseCatalogOrder(rows, label) {
  for (let index = 1; index < rows.length; index++) {
    const previous = rows[index - 1];
    const current = rows[index];
    if (compareActiveReleaseCatalogPublicationOrder(previous, current) <= 0) {
      continue;
    }
    throw new Error(
      `${label} active release catalog is not in canonical publication order ` +
      `between ranks ${index - 1} and ${index}: ` +
      `${JSON.stringify(previous.tag)} published at ${previous.published_at} ` +
      `precedes ${JSON.stringify(current.tag)} published at ${current.published_at}; ` +
      'catalog order must be published_at descending, then binary tag and node_id',
    );
  }
}

function compareActiveReleaseCatalogPublicationOrder(left, right) {
  const publishedDifference =
    requiredActiveReleasePublishedTimestamp(right) -
    requiredActiveReleasePublishedTimestamp(left);
  return publishedDifference ||
    Buffer.compare(Buffer.from(left.tag, 'utf8'), Buffer.from(right.tag, 'utf8')) ||
    Buffer.compare(
      Buffer.from(left.node_id, 'utf8'),
      Buffer.from(right.node_id, 'utf8'),
    );
}

function requiredActiveReleasePublishedTimestamp(row) {
  const timestamp = Date.parse(row.published_at);
  if (!Number.isFinite(timestamp)) {
    throw new Error(
      `Active release catalog row ${JSON.stringify(row.tag)} has invalid ` +
      `published_at ${JSON.stringify(row.published_at)}`,
    );
  }
  return timestamp;
}

function activeReleaseCatalogEvolutionRows(db) {
  return db.prepare(`
    SELECT
      catalog_rank,
      tag,
      node_id,
      lower(catalog_tag_commit_oid) AS catalog_tag_commit_oid,
      prerelease,
      published_at
    FROM releases
    WHERE catalog_active=1
    ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC, tag
  `).all().map((row, index) => {
    if (row.catalog_rank !== index) {
      throw new Error(
        `Active release catalog has non-canonical rank ` +
        `${String(row.catalog_rank)} at position ${index}`,
      );
    }
    return {
      tag: String(row.tag),
      node_id: String(row.node_id),
      catalog_tag_commit_oid: String(row.catalog_tag_commit_oid),
      prerelease: Number(row.prerelease),
      published_at: String(row.published_at),
    };
  });
}

function assertDestinationReleaseCatalogReceiptChainPrefix(source, destination) {
  const sourceRows = source.prepare(`
    SELECT ${RELEASE_CATALOG_RECEIPT_COLUMNS.join(', ')}
    FROM ${RELEASE_CATALOG_RECEIPT_TABLE}
    ORDER BY id
  `).all();
  const destinationRows = destination.prepare(`
    SELECT ${RELEASE_CATALOG_RECEIPT_COLUMNS.join(', ')}
    FROM ${RELEASE_CATALOG_RECEIPT_TABLE}
    ORDER BY id
  `).all();
  if (destinationRows.length > sourceRows.length) {
    throw new Error(
      `Destination release catalog capture receipt chain is ahead of the source by ` +
      `${destinationRows.length - sourceRows.length} receipt(s); promotion would drop ` +
      'immutable catalog authority',
    );
  }
  const mismatchIndex = destinationRows.findIndex((row, index) =>
    rowCanonicalContent(RELEASE_CATALOG_RECEIPT_COLUMNS, row) !==
    rowCanonicalContent(RELEASE_CATALOG_RECEIPT_COLUMNS, sourceRows[index]));
  if (mismatchIndex >= 0) {
    throw new Error(
      `Destination release catalog capture receipt chain is not the exact ordered ` +
      `prefix of the source at receipt index ${mismatchIndex}; promotion refuses to ` +
      'rewrite or reorder immutable catalog authority',
    );
  }
}

function assertImmutableLedgersEqual(expected, actual, message) {
  if (expected.immutableLedgerDigest === actual.immutableLedgerDigest) return;
  const changed = IMMUTABLE_LEDGER_TABLES.filter((table) =>
    expected.immutableLedgers[table]?.digest !== actual.immutableLedgers[table]?.digest ||
    expected.immutableLedgers[table]?.rowCount !== actual.immutableLedgers[table]?.rowCount);
  throw new Error(`${message}: ${changed.join(', ') || 'unknown immutable ledger'}`);
}

function assertDestinationDriftTablesEqual(expected, actual, message) {
  if (expected.destinationDriftTableDigest === actual.destinationDriftTableDigest) return;
  const changed = DESTINATION_DRIFT_TABLES.filter((table) =>
    expected.destinationDriftTables[table]?.present !== actual.destinationDriftTables[table]?.present ||
    expected.destinationDriftTables[table]?.digest !== actual.destinationDriftTables[table]?.digest ||
    expected.destinationDriftTables[table]?.rowCount !== actual.destinationDriftTables[table]?.rowCount);
  throw new Error(`${message}: ${changed.join(', ') || 'unknown destination table'}`);
}

function assertDatabaseIdentityEqual(expected, actual, message) {
  const expectedIdentity = {
    applicationId: expected.applicationId,
    userVersion: expected.userVersion,
    schemaDigest: expected.schemaDigest,
    logicalContentDigest: expected.logicalContentDigest,
    immutableLedgerDigest: expected.immutableLedgerDigest,
    scorePersistenceDigest: expected.scorePersistenceDigest,
  };
  const actualIdentity = {
    applicationId: actual.applicationId,
    userVersion: actual.userVersion,
    schemaDigest: actual.schemaDigest,
    logicalContentDigest: actual.logicalContentDigest,
    immutableLedgerDigest: actual.immutableLedgerDigest,
    scorePersistenceDigest: actual.scorePersistenceDigest,
  };
  if (digestJson(expectedIdentity) !== digestJson(actualIdentity)) {
    throw new Error(message);
  }
}

function refreshLeaseSummary(path, now, label) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new Error(`${label} refresh lease inspection requires a valid observation time`);
  }
  const db = new DatabaseSync(path, { readOnly: true, timeout: 10_000 });
  try {
    const rows = refreshLeaseRows(db, label);
    const leases = rows.map((row) => {
      const expiresAtMs = Date.parse(String(row.expires_at));
      const malformedExpiry = !Number.isFinite(expiresAtMs);
      return {
        name: String(row.name),
        holderId: String(row.holder_id),
        acquiredAt: String(row.acquired_at),
        expiresAt: String(row.expires_at),
        malformedExpiry,
        active: malformedExpiry || expiresAtMs > now.getTime(),
      };
    });
    const activeLeases = leases.filter((row) => row.active);
    const staleLeases = leases.filter((row) => !row.active);
    return {
      observedAt: now.toISOString(),
      rowCount: rows.length,
      activeCount: activeLeases.length,
      staleCount: staleLeases.length,
      rowsDigest: digestJson(rows.map((row) => [
        row.name,
        row.holder_id,
        row.acquired_at,
        row.expires_at,
      ])),
      activeLeases,
      staleLeases,
    };
  } finally {
    db.close();
  }
}

function stripRefreshLeases(path, now, label) {
  const before = refreshLeaseSummary(path, now, label);
  const db = new DatabaseSync(path, { timeout: 10_000 });
  let strippedCount = 0;
  try {
    db.exec('BEGIN IMMEDIATE');
    try {
      strippedCount = Number(db.prepare('DELETE FROM refresh_leases').run().changes);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  } finally {
    db.close();
  }
  const after = refreshLeaseSummary(path, now, `${label} after lease stripping`);
  if (strippedCount !== before.rowCount || after.rowCount !== 0) {
    throw new Error(
      `${label} refresh lease stripping was incomplete ` +
      `(before=${before.rowCount}, stripped=${strippedCount}, remaining=${after.rowCount})`,
    );
  }
  return {
    sourceRows: before.rowCount,
    sourceActiveRows: before.activeCount,
    sourceRowsDigest: before.rowsDigest,
    strippedCount,
    remainingCount: after.rowCount,
    proof: 'captured from the verified VACUUM INTO snapshot and deleted from the staged copy',
  };
}

function refreshLeaseRows(db, label) {
  const columns = new Set(
    db.prepare('PRAGMA table_info(refresh_leases)').all().map((column) => column.name),
  );
  const required = ['name', 'holder_id', 'acquired_at', 'expires_at'];
  const missing = required.filter((column) => !columns.has(column));
  if (missing.length > 0) {
    throw new Error(`${label} is missing refresh_leases columns: ${missing.join(', ')}`);
  }
  return db.prepare(`
    SELECT name, holder_id, acquired_at, expires_at
    FROM refresh_leases
    ORDER BY name
  `).all();
}

function readOperationReceiptLedger(db, label = 'database') {
  return {
    attempts: db.prepare(`
      SELECT ${OPERATION_ATTEMPT_COLUMNS.join(', ')}
      FROM ${OPERATION_ATTEMPT_TABLE}
      ORDER BY started_at, run_id
    `).all(),
    stageEvents: db.prepare(`
      SELECT id, ${OPERATION_STAGE_EVENT_COLUMNS.join(', ')}
      FROM ${OPERATION_STAGE_EVENT_TABLE}
      ORDER BY run_id, sequence
    `).all(),
    receipts: db.prepare(`
      SELECT id, ${OPERATION_RECEIPT_COLUMNS.join(', ')}
      FROM ${OPERATION_RECEIPT_TABLE}
      ORDER BY id
    `).all(),
    artifactReceipts: readOperationArtifactReceiptLedger(db, label),
    artifactObservations: readOperationArtifactObservationLedger(db, label),
  };
}

function verifyOperationReceiptLedgerRows(db, label) {
  const ledger = readOperationReceiptLedger(db, label);
  const verification = verifyOperationReceiptLedger({
    ...ledger,
    artifactMembershipPolicy: 'strict',
  });
  if (verification.problems.length > 0) {
    throw new Error(
      `${label} failed refresh operation receipt integrity: ` +
      verification.problems.slice(0, 10).join('; '),
    );
  }
  return verification;
}

function verifyReleaseCatalogCaptureReceiptLedgerRows(db, label) {
  let exactActiveCatalog;
  try {
    exactActiveCatalog = readExactActiveReleaseCatalogProjection(db);
  } catch (error) {
    throw new Error(
      `${label} failed active release catalog projection: ${errorMessage(error)}`,
    );
  }
  const {
    rows: _activeCatalogRows,
    ...activeCatalog
  } = exactActiveCatalog;
  const verification = verifyReleaseCatalogCaptureReceiptLedger({
    receipts: db.prepare(`
      SELECT ${RELEASE_CATALOG_RECEIPT_COLUMNS.join(', ')}
      FROM ${RELEASE_CATALOG_RECEIPT_TABLE}
      ORDER BY id
    `).all(),
    attempts: db.prepare(`
      SELECT run_id, operation, started_at, effective_config_json, content_hash
      FROM ${OPERATION_ATTEMPT_TABLE}
      ORDER BY started_at, run_id
    `).all(),
    terminalReceipts: db.prepare(`
      SELECT run_id, status, finished_at, payload_json
      FROM ${OPERATION_RECEIPT_TABLE}
      ORDER BY id
    `).all(),
    expectedRepository: configuredPromotionRepository(),
    activeCatalog,
    allowTestFixture: false,
  });
  if (verification.problems.length > 0) {
    const projectionMismatch = verification.currentProblems.includes(
      'latest catalog capture receipt does not match the exact active catalog projection',
    );
    const projectionDetail = projectionMismatch
      ? `; receipt active catalog=${
          canonicalOperationJson(
            verification.latestPayload?.activeCatalog ?? null,
        )
        }; database active catalog=${canonicalOperationJson(activeCatalog)}`
      : '';
    throw new Error(
      `${label} failed release catalog capture receipt integrity: ` +
      verification.problems.slice(0, 10).join('; ') +
      projectionDetail,
    );
  }
  return verification;
}

function readExactActiveReleaseCatalogProjection(db) {
  const storedRows = db.prepare(`
    SELECT
      catalog_rank,
      node_id,
      catalog_tag_commit_oid,
      tag,
      name,
      published_at,
      created_at,
      updated_at,
      html_url,
      prerelease,
      body,
      catalog_digest
    FROM releases
    WHERE catalog_active=1
    ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC, tag
  `).all();
  const rows = storedRows.map((row) => ({
    catalog_rank: row.catalog_rank,
    node_id: row.node_id,
    catalog_tag_commit_oid:
      String(row.catalog_tag_commit_oid ?? '').toLowerCase(),
    tag: String(row.tag),
    name: row.name,
    published_at: row.published_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    html_url: String(row.html_url),
    prerelease: Number(row.prerelease),
    body: row.body,
  }));
  const projected = projectReleaseCatalogActiveRows(rows);
  const storedDigests =
    new Set(storedRows.map((row) => row.catalog_digest));
  if (
    rows.length === 0 ||
    storedRows.some((row, index) => row.catalog_rank !== index) ||
    storedDigests.size !== 1 ||
    storedDigests.has(null) ||
    !storedDigests.has(projected.digest)
  ) {
    throw new Error(
      'active release catalog rows do not match their exact stored digest and rank',
    );
  }
  return {
    digest: projected.digest,
    releaseCount: projected.releaseCount,
    stableCount: projected.stableCount,
    prereleaseCount: projected.prereleaseCount,
    tags: projected.tags,
    latestStable: projected.latestStable,
    rows,
  };
}

function readExactGithubAuthorizedReleaseCatalogProjection(db, label) {
  const activeCatalog = readExactActiveReleaseCatalogProjection(db);
  const outsideRows = db.prepare(`
    SELECT tag, catalog_active
    FROM releases
    WHERE catalog_active IS NOT 1
    ORDER BY tag
  `).all();
  if (outsideRows.length > 0) {
    const examples = outsideRows.slice(0, 10).map((row) =>
      `${JSON.stringify(String(row.tag))} ` +
      `(catalog_active=${String(row.catalog_active)})`);
    throw new Error(
      `${label} release catalog contains ${outsideRows.length} row(s) outside ` +
      `the exact active GitHub catalog: ${examples.join(', ')}`,
    );
  }
  return activeCatalog;
}

export async function verifyPromotionGithubReleaseCatalog({
  dbPath,
  label,
  runtimeEnvPath = null,
  observedAt = new Date().toISOString(),
  fetchCatalog = fetchReleaseCatalogForRepository,
}) {
  const github = promotionGithubConfiguration(runtimeEnvPath);
  let catalog;
  try {
    catalog = await fetchCatalog({
      owner: github.owner,
      repo: github.repo,
      token: github.token,
    });
  } catch (error) {
    throw new Error(
      `${label} failed independent GitHub GraphQL release catalog fetch: ` +
      errorMessage(error),
    );
  }
  const remote = projectPromotionGithubReleaseCatalog(catalog);
  const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 10_000 });
  let local;
  try {
    local = readExactGithubAuthorizedReleaseCatalogProjection(db, label);
  } finally {
    db.close();
  }
  if (
    local.rows.length !== remote.rows.length ||
    canonicalOperationJson(local.rows) !==
      canonicalOperationJson(remote.rows)
  ) {
    throw new Error(
      `${label} active release catalog does not exactly match independent ` +
      `GitHub GraphQL authority for ${github.owner}/${github.repo}: ` +
      promotionGithubCatalogMismatch(remote.rows, local.rows),
    );
  }
  const normalizedObservedAt = canonicalTimestamp(
    observedAt,
    `${label} GitHub catalog observation`,
  );
  return {
    schemaVersion: 1,
    source: 'independent_github_graphql',
    repository: `${github.owner}/${github.repo}`,
    observedAt: normalizedObservedAt,
    configurationSource: github.source,
    remoteCatalog: {
      digest: remote.remoteDigest,
      totalCount: remote.totalCount,
      nodeCount: remote.nodeCount,
      publishedCount: remote.rows.length,
      draftCount: remote.draftCount,
      pageCount: remote.pageCount,
      pagesFetched: remote.pagesFetched,
      sweepCount: remote.sweepCount,
      sweepPageCounts: remote.sweepPageCounts,
      exhausted: true,
      stabilized: true,
      sourceOrder: 'CREATED_AT_DESC',
    },
    activeCatalog: {
      digest: remote.projection.digest,
      releaseCount: remote.projection.releaseCount,
      stableCount: remote.projection.stableCount,
      prereleaseCount: remote.projection.prereleaseCount,
      tags: remote.projection.tags,
      latestStable: remote.projection.latestStable,
    },
    exactIdentityMatch: true,
  };
}

function assertGithubReleaseCatalogProofStillMatchesDatabase(
  proof,
  dbPath,
  label,
) {
  const identity = promotionGithubReleaseCatalogAuthorizationIdentity(
    proof,
    label,
  );
  const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 10_000 });
  try {
    const current = readExactGithubAuthorizedReleaseCatalogProjection(
      db,
      label,
    );
    if (
      current.digest !== identity.activeCatalogDigest ||
      current.releaseCount !== identity.activeReleaseCount ||
      canonicalOperationJson(current.tags) !==
        canonicalOperationJson(identity.activeReleaseTags)
    ) {
      throw new Error(
        `${label} active release catalog changed after independent GitHub ` +
        'authority was verified',
      );
    }
  } finally {
    db.close();
  }
}

function assertReleaseCatalogReceiptRepositoryMatchesGithub(
  releaseCatalogReceipt,
  githubReleaseCatalog,
  label,
) {
  const receiptRepository = releaseCatalogReceipt?.latestRepository ?? null;
  const githubRepository = githubReleaseCatalog?.repository ?? null;
  if (
    typeof receiptRepository !== 'string' ||
    typeof githubRepository !== 'string' ||
    receiptRepository !== githubRepository
  ) {
    throw new Error(
      `${label} release-catalog receipt repository ` +
      `${JSON.stringify(receiptRepository)} does not exactly match ` +
      `independently fetched GitHub repository ` +
      `${JSON.stringify(githubRepository)}`,
    );
  }
}

function promotionGithubConfiguration(runtimeEnvPath) {
  if (runtimeEnvPath != null) {
    const path = canonicalPromotionEnvironmentFile(
      runtimeEnvPath,
      'installer runtime env',
    );
    const environment = dotenv.parse(readFileSync(path));
    return githubConfigurationFromEnvironment(environment, {
      kind: 'installer-runtime-env',
      path,
    });
  }

  const configuredPath =
    process.env.DOTENV_CONFIG_PATH ?? join(PROJECT_ROOT, '.env');
  let dotenvEnvironment = {};
  let dotenvSource = null;
  if (existsSync(configuredPath)) {
    const path = canonicalPromotionEnvironmentFile(
      configuredPath,
      'promotion dotenv',
    );
    dotenvEnvironment = dotenv.parse(readFileSync(path));
    dotenvSource = path;
  } else if (process.env.DOTENV_CONFIG_PATH) {
    throw new Error(
      `Configured promotion dotenv does not exist: ${configuredPath}`,
    );
  }
  return githubConfigurationFromEnvironment(
    { ...dotenvEnvironment, ...process.env },
    {
      kind: dotenvSource ? 'process-env-with-dotenv' : 'process-env',
      path: dotenvSource,
    },
  );
}

function githubConfigurationFromEnvironment(environment, source) {
  const owner = canonicalGithubRepositoryPart(
    environment.GITHUB_OWNER ?? 'openclaw',
    'owner',
  );
  const repo = canonicalGithubRepositoryPart(
    environment.GITHUB_REPO ?? 'openclaw',
    'repository',
  );
  const token = canonicalGithubToken(
    environment.GITHUB_TOKEN ??
      environment.GITHUB_PERSONAL_ACCESS_TOKEN,
  );
  return { owner, repo, token, source };
}

function canonicalPromotionEnvironmentFile(path, label) {
  const resolved = resolve(path);
  let info;
  try {
    info = lstatSync(resolved);
  } catch (error) {
    throw new Error(
      `${label} is unavailable at ${resolved}: ${errorMessage(error)}`,
    );
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symlink file: ${resolved}`);
  }
  return realpathSync(resolved);
}

function canonicalGithubRepositoryPart(value, label) {
  if (
    typeof value !== 'string' ||
    !value ||
    value.trim() !== value ||
    value.includes('/') ||
    /\s/.test(value)
  ) {
    throw new Error(`Promotion GitHub ${label} is invalid`);
  }
  return value;
}

function canonicalGithubToken(value) {
  if (
    typeof value !== 'string' ||
    !value ||
    value.trim() !== value ||
    /[\r\n\0]/.test(value)
  ) {
    throw new Error(
      'Promotion requires GITHUB_TOKEN or GITHUB_PERSONAL_ACCESS_TOKEN',
    );
  }
  return value;
}

function projectPromotionGithubReleaseCatalog(catalog) {
  const metadata = catalog?.metadata;
  const releases = catalog?.releases;
  if (!metadata || !Array.isArray(releases)) {
    throw new Error('Independent GitHub release catalog is malformed');
  }
  const sweepPageCounts = Array.isArray(metadata.sweepPageCounts)
    ? metadata.sweepPageCounts.map(Number)
    : null;
  if (
    metadata.exhausted !== true ||
    metadata.stabilized !== true ||
    !Number.isSafeInteger(metadata.totalCount) ||
    metadata.totalCount < 0 ||
    metadata.nodeCount !== metadata.totalCount ||
    releases.length !== metadata.nodeCount ||
    !Number.isSafeInteger(metadata.pageCount) ||
    metadata.pageCount <= 0 ||
    !Number.isSafeInteger(metadata.pagesFetched) ||
    metadata.pagesFetched <= 0 ||
    !Number.isSafeInteger(metadata.sweepCount) ||
    metadata.sweepCount < 2 ||
    !sweepPageCounts ||
    sweepPageCounts.length !== metadata.sweepCount ||
    sweepPageCounts.some(
      (count) => !Number.isSafeInteger(count) || count <= 0,
    ) ||
    sweepPageCounts.reduce((sum, count) => sum + count, 0) !==
      metadata.pagesFetched ||
    sweepPageCounts.at(-1) !== metadata.pageCount ||
    !/^[0-9a-f]{64}$/.test(String(metadata.digest ?? '')) ||
    metadata.sourceOrder !== 'CREATED_AT_DESC'
  ) {
    throw new Error(
      'Independent GitHub release catalog is not exhaustive and stabilized',
    );
  }

  const nodeIds = new Set();
  const tags = new Set();
  let draftCount = 0;
  const rows = [];
  for (const [index, release] of releases.entries()) {
    if (!release || typeof release !== 'object') {
      throw new Error(`Independent GitHub release row ${index} is invalid`);
    }
    const nodeId = canonicalGithubReleaseValue(
      release.node_id,
      `release row ${index} node_id`,
    );
    const tag = canonicalGithubReleaseValue(
      release.tag_name,
      `release row ${index} tag`,
    );
    if (nodeIds.has(nodeId) || tags.has(tag)) {
      throw new Error(
        `Independent GitHub release catalog contains duplicate identity ${tag}`,
      );
    }
    nodeIds.add(nodeId);
    tags.add(tag);
    if (typeof release.draft !== 'boolean') {
      throw new Error(`Independent GitHub release ${tag} has invalid draft state`);
    }
    if (typeof release.prerelease !== 'boolean') {
      throw new Error(
        `Independent GitHub release ${tag} has invalid prerelease state`,
      );
    }
    if (release.draft) {
      draftCount++;
      continue;
    }
    if (release.published_at == null) {
      throw new Error(
        `Independent published GitHub release ${tag} is missing published_at`,
      );
    }
    rows.push({
      catalog_rank: 0,
      node_id: nodeId,
      catalog_tag_commit_oid: canonicalGithubReleaseOid(
        release.tag_commit_oid,
        tag,
      ),
      tag,
      name: release.name == null
        ? null
        : canonicalGithubReleaseText(release.name, `${tag} name`),
      published_at: canonicalTimestamp(
        release.published_at,
        `${tag} published_at`,
      ),
      created_at: canonicalTimestamp(
        release.created_at,
        `${tag} created_at`,
      ),
      updated_at: canonicalTimestamp(
        release.updated_at,
        `${tag} updated_at`,
      ),
      html_url: canonicalGithubReleaseValue(
        release.html_url,
        `${tag} html_url`,
      ),
      prerelease: release.prerelease ? 1 : 0,
      body: release.body == null
        ? null
        : canonicalGithubReleaseText(release.body, `${tag} body`),
    });
  }
  rows.sort(compareActiveReleaseCatalogPublicationOrder);
  const rankedRows = rows.map((row, catalogRank) => ({
    ...row,
    catalog_rank: catalogRank,
  }));
  const projection = projectReleaseCatalogActiveRows(rankedRows);
  return {
    rows: rankedRows,
    projection,
    remoteDigest: String(metadata.digest),
    totalCount: Number(metadata.totalCount),
    nodeCount: Number(metadata.nodeCount),
    draftCount,
    pageCount: Number(metadata.pageCount),
    pagesFetched: Number(metadata.pagesFetched),
    sweepCount: Number(metadata.sweepCount),
    sweepPageCounts,
  };
}

function promotionGithubCatalogMismatch(expectedRows, actualRows) {
  const expectedTags = new Set(expectedRows.map((row) => row.tag));
  const actualTags = new Set(actualRows.map((row) => row.tag));
  const missingTags = [...expectedTags].filter((tag) => !actualTags.has(tag));
  const unexpectedTags = [...actualTags].filter(
    (tag) => !expectedTags.has(tag),
  );
  const limit = Math.max(expectedRows.length, actualRows.length);
  let firstMismatch = null;
  for (let index = 0; index < limit; index++) {
    const expected = expectedRows[index];
    const actual = actualRows[index];
    if (!expected || !actual) {
      firstMismatch =
        `rank ${index} expected ${expected?.tag ?? '<none>'}, ` +
        `found ${actual?.tag ?? '<none>'}`;
      break;
    }
    const changed = RELEASE_CATALOG_LIVE_IDENTITY_COLUMNS.filter(
      (column) => expected[column] !== actual[column],
    );
    if (changed.length > 0) {
      firstMismatch =
        `rank ${index} tag ${JSON.stringify(expected.tag)} changed ` +
        changed.join(', ');
      break;
    }
  }
  return [
    missingTags.length > 0
      ? `missing live tags ${missingTags.slice(0, 10).join(', ')}`
      : null,
    unexpectedTags.length > 0
      ? `unexpected candidate tags ${unexpectedTags.slice(0, 10).join(', ')}`
      : null,
    firstMismatch,
  ].filter(Boolean).join('; ') || 'catalog identity differs';
}

function canonicalGithubReleaseValue(value, label) {
  if (
    typeof value !== 'string' ||
    !value ||
    value.trim() !== value ||
    /[\r\n\0]/.test(value)
  ) {
    throw new Error(`Independent GitHub ${label} is invalid`);
  }
  return value;
}

function canonicalGithubReleaseText(value, label) {
  if (typeof value !== 'string' || value.includes('\0')) {
    throw new Error(`Independent GitHub ${label} is invalid`);
  }
  return value;
}

function canonicalGithubReleaseOid(value, tag) {
  const normalized = String(value ?? '').toLowerCase();
  if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(normalized)) {
    throw new Error(
      `Independent GitHub release ${tag} has invalid tag commit OID`,
    );
  }
  return normalized;
}

function canonicalTimestamp(value, label) {
  if (typeof value !== 'string') {
    throw new Error(`${label} must be a timestamp`);
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${label} must be a valid timestamp`);
  }
  return value;
}

function configuredPromotionRepository() {
  const owner = process.env.GITHUB_OWNER ?? 'openclaw';
  const repo = process.env.GITHUB_REPO ?? 'openclaw';
  if (
    !owner ||
    !repo ||
    owner.trim() !== owner ||
    repo.trim() !== repo ||
    owner.includes('/') ||
    repo.includes('/') ||
    /\s/.test(owner) ||
    /\s/.test(repo)
  ) {
    throw new Error('Promotion GitHub repository configuration is invalid');
  }
  return `${owner}/${repo}`;
}

function readOperationArtifactReceiptLedger(db, label) {
  return db.prepare(`
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
      content_hash
    FROM ${ARTIFACT_RECEIPT_TABLE}
    ORDER BY id
  `).all().map((row) => {
    const rowLabel =
      `${label} artifact receipt ${JSON.stringify(String(row.receipt_id))}`;
    const canonicalReceipt = parseCanonicalLedgerObject(
      row.canonical_receipt_json,
      `${rowLabel} canonical receipt`,
    );
    const release = operationArtifactReleaseFromStorageRow(row);
    if (
      Number(row.schema_version) !== 2 ||
      canonicalReceipt.schemaVersion !== 2
    ) {
      throw new Error(`${rowLabel} has unsupported schema version`);
    }
    if (
      canonicalOperationJson(canonicalReceipt.release) !==
      canonicalOperationJson(release)
    ) {
      throw new Error(`${rowLabel} canonical release differs from storage columns`);
    }
    if (typeof canonicalReceipt.evidenceReportIdentity !== 'string') {
      throw new Error(`${rowLabel} has no canonical evidence report identity`);
    }
    return {
      receiptId: String(row.receipt_id),
      release,
      evidenceIdentity: String(row.evidence_identity),
      evidenceReportIdentity: canonicalReceipt.evidenceReportIdentity,
      contentHash: String(row.content_hash),
    };
  });
}

function readOperationArtifactObservationLedger(db, label) {
  return db.prepare(`
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
      content_hash
    FROM ${ARTIFACT_OBSERVATION_TABLE}
    ORDER BY id
  `).all().map((row) => {
    const rowLabel =
      `${label} artifact observation ` +
      JSON.stringify(String(row.observation_id));
    const release = operationArtifactReleaseFromStorageRow(row);
    const expectedCanonicalObservation = {
      schemaVersion: 1,
      observationId: String(row.observation_id),
      runId: String(row.run_id),
      observedAt: String(row.observed_at),
      release,
      receiptId: String(row.receipt_id),
      receiptContentHash: String(row.receipt_content_hash),
    };
    const canonicalObservation = parseCanonicalLedgerObject(
      row.canonical_observation_json,
      `${rowLabel} canonical observation`,
    );
    if (
      Number(row.schema_version) !== 1 ||
      canonicalOperationJson(canonicalObservation) !==
      canonicalOperationJson(expectedCanonicalObservation)
    ) {
      throw new Error(
        `${rowLabel} canonical observation differs from storage columns`,
      );
    }
    return {
      observationId: String(row.observation_id),
      runId: String(row.run_id),
      release,
      receiptId: String(row.receipt_id),
      receiptContentHash: String(row.receipt_content_hash),
      contentHash: String(row.content_hash),
    };
  });
}

function operationArtifactReleaseFromStorageRow(row) {
  return {
    repository: String(row.release_repository),
    tag: String(row.release_tag),
    releaseNodeId: String(row.release_node_id),
    catalogTagCommitOid: String(row.release_tag_commit_oid),
    publishedAt: String(row.release_published_at),
  };
}

function parseCanonicalLedgerObject(value, label) {
  let parsed;
  try {
    parsed = JSON.parse(String(value));
  } catch {
    throw new Error(`${label} is malformed JSON`);
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error(`${label} must be an object`);
  }
  return parsed;
}

function mergeDestinationPreservedTables(stagedPath, destinationSnapshotPath) {
  const staged = new DatabaseSync(stagedPath, { timeout: 10_000 });
  const destination = new DatabaseSync(destinationSnapshotPath, {
    readOnly: true,
    timeout: 10_000,
  });
  const report = {};
  try {
    staged.exec('BEGIN IMMEDIATE');
    try {
      for (const table of PRESERVED_DESTINATION_TABLES) {
        const columns = tableColumns(staged, table);
        const primaryKeyColumns = columns
          .filter((column) => column.pk > 0)
          .sort((left, right) => left.pk - right.pk)
          .map((column) => column.name);
        if (primaryKeyColumns.length === 0) {
          throw new Error(
            `Destination-preserved table ${table} has no primary key; promotion cannot merge it safely`,
          );
        }
        const columnNames = columns.map((column) => column.name);
        const quotedColumns = columnNames.map(quoteIdentifier).join(', ');
        const sourceRows = staged.prepare(
          `SELECT ${quotedColumns} FROM ${quoteIdentifier(table)}`,
        ).all();
        const destinationRows = destination.prepare(
          `SELECT ${quotedColumns} FROM ${quoteIdentifier(table)}`,
        ).all();
        const lookup = staged.prepare(
          `SELECT ${quotedColumns} FROM ${quoteIdentifier(table)} WHERE ` +
          primaryKeyColumns.map((column) => `${quoteIdentifier(column)} IS ?`).join(' AND '),
        );
        const insert = staged.prepare(
          `INSERT INTO ${quoteIdentifier(table)} (${quotedColumns}) ` +
          `VALUES (${columnNames.map(() => '?').join(', ')})`,
        );
        let insertedRows = 0;
        let deduplicatedRows = 0;

        for (const row of destinationRows) {
          const primaryKey = primaryKeyColumns.map((column) => row[column]);
          const existing = lookup.get(...primaryKey);
          if (existing) {
            if (
              rowCanonicalContent(columnNames, existing) !==
              rowCanonicalContent(columnNames, row)
            ) {
              throw new Error(
                `Destination-preserved table ${table} has a primary-key conflict at ` +
                `${JSON.stringify(primaryKey.map(normalizeSqliteValue))}; ` +
                `promotion cannot preserve both rows without changing evidence identity`,
              );
            }
            deduplicatedRows++;
            continue;
          }
          insert.run(...columnNames.map((column) => row[column]));
          insertedRows++;
        }

        report[table] = {
          sourceRows: sourceRows.length,
          destinationRows: destinationRows.length,
          insertedRows,
          deduplicatedRows,
          finalRows: sourceRows.length + insertedRows,
        };
      }
      staged.exec('COMMIT');
    } catch (error) {
      staged.exec('ROLLBACK');
      throw error;
    }

    for (const table of PRESERVED_DESTINATION_TABLES) {
      assertTableRowsContained(
        staged,
        destination,
        table,
        `Destination-preserved table ${table} was not retained exactly`,
      );
      const finalRowCount = tableCanonicalRows(staged, table).length;
      if (finalRowCount !== report[table].finalRows) {
        throw new Error(
          `Destination-preserved table ${table} row count mismatch: ` +
          `expected ${report[table].finalRows}, found ${finalRowCount}`,
        );
      }
    }
    return report;
  } finally {
    destination.close();
    staged.close();
  }
}

function assertTableRowsContained(container, required, table, message) {
  const available = rowMultiset(tableCanonicalRows(container, table));
  const missing = [];
  for (const row of tableCanonicalRows(required, table)) {
    const count = available.get(row) ?? 0;
    if (count <= 0) missing.push(row);
    else available.set(row, count - 1);
  }
  if (missing.length > 0) throw new Error(`${message}: ${missing.length} row(s) missing`);
}

function tableColumns(db, table) {
  const columns = db.prepare(`PRAGMA table_xinfo(${quoteIdentifier(table)})`).all()
    .filter((column) => Number(column.hidden ?? 0) === 0)
    .sort((left, right) => Number(left.cid) - Number(right.cid))
    .map((column) => ({
      name: String(column.name),
      pk: Number(column.pk ?? 0),
    }));
  if (columns.length === 0) throw new Error(`Required table is missing or empty-schema: ${table}`);
  return columns;
}

function rowCanonicalContent(columns, row) {
  return JSON.stringify(columns.map((column) => normalizeSqliteValue(row[column])));
}

function mergeDestinationOperationReceipts(stagedPath, destinationSnapshotPath) {
  const staged = new DatabaseSync(stagedPath, { timeout: 10_000 });
  const destination = new DatabaseSync(destinationSnapshotPath, {
    readOnly: true,
    timeout: 10_000,
  });
  try {
    const sourceLedger = readOperationReceiptLedger(staged);
    const destinationLedger = readOperationReceiptLedger(destination);
    const sourceVerification = verifyOperationReceiptLedgerRows(
      staged,
      'source snapshot before refresh operation receipt merge',
    );
    const destinationVerification = verifyOperationReceiptLedgerRows(
      destination,
      'destination snapshot before refresh operation receipt merge',
    );
    const sourceReceiptsByRun = new Map(
      sourceLedger.receipts.map((row) => [String(row.run_id), row]),
    );
    for (const row of destinationLedger.receipts) {
      const existing = sourceReceiptsByRun.get(String(row.run_id));
      if (
        existing &&
        rowCanonicalContent(OPERATION_RECEIPT_SEMANTIC_COLUMNS, existing) !==
          rowCanonicalContent(OPERATION_RECEIPT_SEMANTIC_COLUMNS, row)
      ) {
        throw new Error(
          `Refresh capture receipt ${JSON.stringify(row.run_id)} conflicts between the ` +
          'source and destination; promotion cannot preserve both terminal results',
        );
      }
    }

    const receiptTriggerRows = staged.prepare(`
      SELECT name, sql
      FROM sqlite_schema
      WHERE type='trigger'
        AND name IN ('refresh_capture_receipts_no_update', 'refresh_capture_receipts_no_delete')
      ORDER BY name
    `).all();
    if (receiptTriggerRows.length !== 2 || receiptTriggerRows.some((row) => !row.sql)) {
      throw new Error('Source snapshot is missing append-only refresh capture receipt triggers');
    }

    const attemptLookup = staged.prepare(`
      SELECT ${OPERATION_ATTEMPT_COLUMNS.join(', ')}
      FROM ${OPERATION_ATTEMPT_TABLE}
      WHERE run_id=?
    `);
    const attemptInsert = staged.prepare(`
      INSERT INTO ${OPERATION_ATTEMPT_TABLE} (${OPERATION_ATTEMPT_COLUMNS.join(', ')})
      VALUES (${OPERATION_ATTEMPT_COLUMNS.map(() => '?').join(', ')})
    `);
    const eventByIdLookup = staged.prepare(`
      SELECT ${OPERATION_STAGE_EVENT_COLUMNS.join(', ')}
      FROM ${OPERATION_STAGE_EVENT_TABLE}
      WHERE event_id=?
    `);
    const eventBySequenceLookup = staged.prepare(`
      SELECT ${OPERATION_STAGE_EVENT_COLUMNS.join(', ')}
      FROM ${OPERATION_STAGE_EVENT_TABLE}
      WHERE run_id=? AND sequence=?
    `);
    const eventInsert = staged.prepare(`
      INSERT INTO ${OPERATION_STAGE_EVENT_TABLE} (${OPERATION_STAGE_EVENT_COLUMNS.join(', ')})
      VALUES (${OPERATION_STAGE_EVENT_COLUMNS.map(() => '?').join(', ')})
    `);
    const receiptInsertWithId = staged.prepare(`
      INSERT INTO ${OPERATION_RECEIPT_TABLE} (id, ${OPERATION_RECEIPT_COLUMNS.join(', ')})
      VALUES (?, ${OPERATION_RECEIPT_COLUMNS.map(() => '?').join(', ')})
    `);
    const receiptInsert = staged.prepare(`
      INSERT INTO ${OPERATION_RECEIPT_TABLE} (${OPERATION_RECEIPT_COLUMNS.join(', ')})
      VALUES (${OPERATION_RECEIPT_COLUMNS.map(() => '?').join(', ')})
    `);
    let insertedAttempts = 0;
    let deduplicatedAttempts = 0;
    let insertedStageEvents = 0;
    let deduplicatedStageEvents = 0;
    let deduplicatedReceipts = 0;
    let appendedSourceReceipts = 0;
    let rehashedSourceReceipts = 0;

    staged.exec('BEGIN IMMEDIATE');
    try {
      for (const row of destinationLedger.attempts) {
        const existing = attemptLookup.get(row.run_id);
        if (existing) {
          if (
            rowCanonicalContent(OPERATION_ATTEMPT_COLUMNS, existing) !==
            rowCanonicalContent(OPERATION_ATTEMPT_COLUMNS, row)
          ) {
            throw new Error(
              `Refresh operation attempt ${JSON.stringify(row.run_id)} conflicts between ` +
              'the source and destination',
            );
          }
          deduplicatedAttempts++;
          continue;
        }
        attemptInsert.run(...OPERATION_ATTEMPT_COLUMNS.map((column) => row[column]));
        insertedAttempts++;
      }

      for (const row of destinationLedger.stageEvents) {
        const existingById = eventByIdLookup.get(row.event_id);
        const existingBySequence = eventBySequenceLookup.get(row.run_id, row.sequence);
        const existing = existingById ?? existingBySequence;
        if (existing) {
          if (
            rowCanonicalContent(OPERATION_STAGE_EVENT_COLUMNS, existing) !==
            rowCanonicalContent(OPERATION_STAGE_EVENT_COLUMNS, row)
          ) {
            throw new Error(
              `Refresh operation stage event ${JSON.stringify(row.event_id)} conflicts between ` +
              'the source and destination',
            );
          }
          deduplicatedStageEvents++;
          continue;
        }
        eventInsert.run(...OPERATION_STAGE_EVENT_COLUMNS.map((column) => row[column]));
        insertedStageEvents++;
      }

      staged.exec(`
        DROP TRIGGER refresh_capture_receipts_no_update;
        DROP TRIGGER refresh_capture_receipts_no_delete;
        DELETE FROM ${OPERATION_RECEIPT_TABLE};
        DELETE FROM sqlite_sequence WHERE name='${OPERATION_RECEIPT_TABLE}';
      `);

      for (const row of destinationLedger.receipts) {
        receiptInsertWithId.run(
          row.id,
          ...OPERATION_RECEIPT_COLUMNS.map((column) => row[column]),
        );
        if (sourceReceiptsByRun.has(String(row.run_id))) deduplicatedReceipts++;
      }

      let previousContentHash =
        destinationLedger.receipts.at(-1)?.content_hash ?? null;
      const destinationReceiptRuns = new Set(
        destinationLedger.receipts.map((row) => String(row.run_id)),
      );
      for (const row of sourceLedger.receipts) {
        if (destinationReceiptRuns.has(String(row.run_id))) continue;
        const contentHash = operationCaptureReceiptContentHash({
          receiptId: String(row.receipt_id),
          runId: String(row.run_id),
          status: String(row.status),
          finishedAt: String(row.finished_at),
          durationMs: Number(row.duration_ms),
          stageEventCount: Number(row.stage_event_count),
          stageChainHash: row.stage_chain_hash == null ? null : String(row.stage_chain_hash),
          payloadJson: String(row.payload_json),
          previousContentHash,
        });
        const merged = {
          ...row,
          previous_content_hash: previousContentHash,
          content_hash: contentHash,
        };
        receiptInsert.run(
          ...OPERATION_RECEIPT_COLUMNS.map((column) => merged[column]),
        );
        appendedSourceReceipts++;
        if (
          row.previous_content_hash !== previousContentHash ||
          row.content_hash !== contentHash
        ) {
          rehashedSourceReceipts++;
        }
        previousContentHash = contentHash;
      }

      for (const trigger of receiptTriggerRows) staged.exec(String(trigger.sql));
      staged.exec('COMMIT');
    } catch (error) {
      staged.exec('ROLLBACK');
      throw error;
    }

    const mergedLedger = readOperationReceiptLedger(staged);
    const mergedVerification = verifyOperationReceiptLedgerRows(
      staged,
      'staged promotion after refresh operation receipt merge',
    );
    assertRowsContainedByColumns(
      mergedLedger.attempts,
      sourceLedger.attempts,
      OPERATION_ATTEMPT_COLUMNS,
      'Source refresh operation attempts were not preserved exactly',
    );
    assertRowsContainedByColumns(
      mergedLedger.attempts,
      destinationLedger.attempts,
      OPERATION_ATTEMPT_COLUMNS,
      'Destination refresh operation attempts were not preserved exactly',
    );
    assertRowsContainedByColumns(
      mergedLedger.stageEvents,
      sourceLedger.stageEvents,
      OPERATION_STAGE_EVENT_COLUMNS,
      'Source refresh stage events were not preserved exactly',
    );
    assertRowsContainedByColumns(
      mergedLedger.stageEvents,
      destinationLedger.stageEvents,
      OPERATION_STAGE_EVENT_COLUMNS,
      'Destination refresh stage events were not preserved exactly',
    );
    assertRowsContainedByColumns(
      mergedLedger.receipts,
      sourceLedger.receipts,
      OPERATION_RECEIPT_SEMANTIC_COLUMNS,
      'Source refresh capture receipt payloads were not preserved',
    );
    const mergedDestinationPrefix = mergedLedger.receipts.slice(
      0,
      destinationLedger.receipts.length,
    );
    if (
      mergedDestinationPrefix.length !== destinationLedger.receipts.length ||
      mergedDestinationPrefix.some((row, index) =>
        rowCanonicalContent(['id', ...OPERATION_RECEIPT_COLUMNS], row) !==
        rowCanonicalContent(
          ['id', ...OPERATION_RECEIPT_COLUMNS],
          destinationLedger.receipts[index],
        ))
    ) {
      throw new Error('Destination refresh capture receipt chain was not preserved as the merged prefix');
    }
    const mergedReceiptsByRun = new Map(
      mergedLedger.receipts.map((row) => [String(row.run_id), row]),
    );
    const identityMappings = sourceLedger.receipts.map((sourceRow) => {
      const mergedRow = mergedReceiptsByRun.get(String(sourceRow.run_id));
      if (!mergedRow) {
        throw new Error(
          `Source refresh capture receipt ${JSON.stringify(sourceRow.receipt_id)} ` +
          'has no merged identity mapping',
        );
      }
      const originalSemanticIdentity = receiptSemanticIdentity(sourceRow);
      const mergedSemanticIdentity = receiptSemanticIdentity(mergedRow);
      if (originalSemanticIdentity !== mergedSemanticIdentity) {
        throw new Error(
          `Source refresh capture receipt ${JSON.stringify(sourceRow.receipt_id)} ` +
          'changed semantic identity during merge',
        );
      }
      return {
        runId: String(sourceRow.run_id),
        receiptId: String(sourceRow.receipt_id),
        mergedRunId: String(mergedRow.run_id),
        mergedReceiptId: String(mergedRow.receipt_id),
        originalHashes: {
          previousContentHash: sourceRow.previous_content_hash ?? null,
          contentHash: String(sourceRow.content_hash),
        },
        mergedHashes: {
          previousContentHash: mergedRow.previous_content_hash ?? null,
          contentHash: String(mergedRow.content_hash),
        },
        semanticIdentity: {
          originalDigest: originalSemanticIdentity,
          mergedDigest: mergedSemanticIdentity,
          unchanged: true,
        },
      };
    });

    return {
      source: sourceVerification,
      destination: destinationVerification,
      merged: mergedVerification,
      attempts: {
        sourceRows: sourceLedger.attempts.length,
        destinationRows: destinationLedger.attempts.length,
        insertedRows: insertedAttempts,
        deduplicatedRows: deduplicatedAttempts,
        finalRows: mergedLedger.attempts.length,
      },
      stageEvents: {
        sourceRows: sourceLedger.stageEvents.length,
        destinationRows: destinationLedger.stageEvents.length,
        insertedRows: insertedStageEvents,
        deduplicatedRows: deduplicatedStageEvents,
        finalRows: mergedLedger.stageEvents.length,
      },
      receipts: {
        sourceRows: sourceLedger.receipts.length,
        destinationRows: destinationLedger.receipts.length,
        deduplicatedRows: deduplicatedReceipts,
        appendedSourceRows: appendedSourceReceipts,
        rehashedSourceRows: rehashedSourceReceipts,
        finalRows: mergedLedger.receipts.length,
        destinationChainPreservedAsPrefix: true,
        identityMappings,
      },
    };
  } finally {
    destination.close();
    staged.close();
  }
}

function receiptSemanticIdentity(row) {
  return operationCaptureReceiptSemanticIdentity({
    receiptId: String(row.receipt_id),
    runId: String(row.run_id),
    status: String(row.status),
    finishedAt: String(row.finished_at),
    durationMs: Number(row.duration_ms),
    stageEventCount: Number(row.stage_event_count),
    stageChainHash:
      row.stage_chain_hash == null ? null : String(row.stage_chain_hash),
    payloadJson: String(row.payload_json),
  });
}

function rowMultisetForColumns(rows, columns) {
  const counts = new Map();
  for (const row of rows) {
    const content = rowCanonicalContent(columns, row);
    counts.set(content, (counts.get(content) ?? 0) + 1);
  }
  return counts;
}

function assertRowsContainedByColumns(containerRows, requiredRows, columns, message) {
  const available = rowMultisetForColumns(containerRows, columns);
  let missingCount = 0;
  for (const row of requiredRows) {
    const content = rowCanonicalContent(columns, row);
    const count = available.get(content) ?? 0;
    if (count <= 0) missingCount++;
    else available.set(content, count - 1);
  }
  if (missingCount > 0) throw new Error(`${message}: ${missingCount} row(s) missing`);
}

function assertDestinationHistoryAndPublicationContained(
  sourcePath,
  destinationSnapshotPath,
) {
  const source = new DatabaseSync(sourcePath, {
    readOnly: true,
    timeout: 10_000,
  });
  const destination = new DatabaseSync(destinationSnapshotPath, {
    readOnly: true,
    timeout: 10_000,
  });
  try {
    const sourceRows = readHistoryRows(source);
    const destinationRows = readHistoryRows(destination);
    const sourceRuns = runsById(sourceRows);
    const destinationRuns = runsById(destinationRows);
    const sourceSeals = readHistoryRunSeals(source);
    const destinationSeals = readHistoryRunSeals(destination);
    const sourceSealContents = sourceSeals.map(historyRunSealContent);
    const destinationSealContents = destinationSeals.map(historyRunSealContent);
    const destinationIsSourcePrefix = isArrayPrefix(
      destinationSealContents,
      sourceSealContents,
    );
    const sourceIsDestinationPrefix = isArrayPrefix(
      sourceSealContents,
      destinationSealContents,
    );
    if (!destinationIsSourcePrefix) {
      if (sourceIsDestinationPrefix) {
        throw new Error(
          `Destination score history is ahead of the source by ` +
          `${destinationSeals.length - sourceSeals.length} sealed run(s); ` +
          `promotion refuses to merge or rewrite a destination-ahead publication`,
        );
      }
      throw new Error(
        'Destination score history run seals diverge from the source run chain; ' +
        'promotion cannot safely rewrite or drop sealed history',
      );
    }

    for (const seal of destinationSeals) {
      const runId = seal.run_id;
      const rows = destinationRuns.get(runId) ?? [];
      const sourceRowsForRun = sourceRuns.get(runId);
      if (
        !sourceRowsForRun ||
        runSignature(sourceRowsForRun) !== runSignature(rows)
      ) {
        throw new Error(
          `Destination score history run ${JSON.stringify(runId)} conflicts with a sealed ` +
          `source run; promotion refuses to discard authority-bound history fields`,
        );
      }
    }

    const equalTipPublicationParityChecked =
      sourceSeals.length === destinationSeals.length;
    if (equalTipPublicationParityChecked) {
      assertCurrentScorePublicationEqual(source, destination);
    }

    return {
      sourceRows: sourceRows.length,
      destinationRows: destinationRows.length,
      insertedRows: 0,
      insertedRuns: 0,
      deduplicatedRows: destinationRows.length,
      finalRows: sourceRows.length,
      sourceTip: historyTip(sourceSeals),
      destinationTip: historyTip(destinationSeals),
      finalTip: historyTip(sourceSeals),
      destinationContainedAsPrefix: true,
      equalTipPublicationParityChecked,
      remappedRuns: [],
    };
  } finally {
    destination.close();
    source.close();
  }
}

function assertCurrentScorePublicationEqual(source, destination) {
  const sourceMeta = scorePersistencePublicationMetadata(
    source,
    'source snapshot',
  );
  const destinationMeta = scorePersistencePublicationMetadata(
    destination,
    'destination snapshot',
  );
  if (sourceMeta.raw !== destinationMeta.raw) {
    throw new Error(
      `Destination current score publication metadata differs at an equal sealed history tip; ` +
      `promotion refuses to choose between incomparable authority/v2 publication identities`,
    );
  }

  assertOptionalTableProjectionEqual(
    source,
    destination,
    'release_score_audits',
    (db) => tableCanonicalRows(db, 'release_score_audits'),
    'current release score audits',
  );
  assertOptionalTableProjectionEqual(
    source,
    destination,
    'releases',
    currentReleaseScoreProjection,
    'current release score projection',
  );
}

function scorePersistencePublicationMetadata(db, label) {
  if (!tableExists(db, 'meta')) return { raw: null, value: null };
  const raw = db.prepare(`
    SELECT value
    FROM meta
    WHERE key='score_persistence_last_run'
  `).get()?.value ?? null;
  if (raw == null) return { raw: null, value: null };
  let value;
  try {
    value = JSON.parse(String(raw));
  } catch {
    throw new Error(`${label} score_persistence_last_run metadata is malformed`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} score_persistence_last_run metadata is not an object`);
  }
  return { raw: String(raw), value };
}

function assertOptionalTableProjectionEqual(
  source,
  destination,
  table,
  projection,
  label,
) {
  const sourcePresent = tableExists(source, table);
  const destinationPresent = tableExists(destination, table);
  if (!sourcePresent && !destinationPresent) return;
  if (!sourcePresent || !destinationPresent) {
    throw new Error(
      `Destination ${label} cannot be compared because ${table} is missing from one database`,
    );
  }
  if (digestJson(projection(source)) !== digestJson(projection(destination))) {
    throw new Error(
      `Destination ${label} differs at an equal sealed history tip; ` +
      `promotion would discard a current publication`,
    );
  }
}

function currentReleaseScoreProjection(db) {
  const columns = [
    'tag',
    'final_score',
    'negative_issues',
    'positive_issues',
    'state',
    'recommended',
    'score_reason',
    'broken_surfaces',
    'closed_serious_fixed',
    'opened_serious_during_reign',
    'scored_at',
  ];
  const existing = new Set(tableColumns(db, 'releases').map((column) => column.name));
  const missing = columns.filter((column) => !existing.has(column));
  if (missing.length > 0) {
    throw new Error(
      `Current release score projection is missing releases columns: ${missing.join(', ')}`,
    );
  }
  return db.prepare(`
    SELECT ${columns.map(quoteIdentifier).join(', ')}
    FROM releases
    WHERE final_score IS NOT NULL
       OR scored_at IS NOT NULL
       OR state IS NOT NULL
       OR recommended != 0
       OR score_reason IS NOT NULL
    ORDER BY tag
  `).all().map((row) =>
    columns.map((column) => normalizeSqliteValue(row[column])));
}

function readHistoryRows(db) {
  return db.prepare(`
    SELECT ${HISTORY_COLUMNS.join(', ')}
    FROM ${HISTORY_TABLE}
    ORDER BY run_id, release_tag
  `).all();
}

function readHistoryRunSeals(db) {
  return db.prepare(`
    SELECT
      run_id, recorded_at, row_count, rows_content_hash,
      previous_content_hash, content_hash
    FROM ${HISTORY_RUN_TABLE}
    ORDER BY id
  `).all();
}

function historyRunSealContent(seal) {
  return JSON.stringify([
    seal.run_id,
    seal.recorded_at,
    Number(seal.row_count),
    seal.rows_content_hash,
    seal.previous_content_hash ?? null,
    seal.content_hash,
  ]);
}

function historyTip(seals) {
  const seal = seals.at(-1);
  return seal
    ? {
        runId: seal.run_id,
        contentHash: seal.content_hash,
      }
    : null;
}

function isArrayPrefix(prefix, values) {
  return prefix.length <= values.length &&
    prefix.every((value, index) => value === values[index]);
}

function tableIdentity(db, table, { allowMissing = false } = {}) {
  if (!tableExists(db, table)) {
    if (!allowMissing) throw new Error(`Required identity table is missing: ${table}`);
    return {
      present: false,
      rowCount: 0,
      digest: digestJson([]),
    };
  }
  const rows = tableCanonicalRows(db, table);
  return {
    present: true,
    rowCount: rows.length,
    digest: digestJson(rows),
  };
}

function tableCanonicalRows(db, table) {
  const columns = db.prepare(`PRAGMA table_xinfo("${escapeIdentifier(table)}")`).all()
    .filter((column) => Number(column.hidden ?? 0) === 0)
    .sort((left, right) => Number(left.cid) - Number(right.cid))
    .map((column) => column.name);
  if (columns.length === 0) throw new Error(`Immutable ledger table is missing or empty-schema: ${table}`);
  const rows = db.prepare(`SELECT * FROM "${escapeIdentifier(table)}"`).all()
    .map((row) => JSON.stringify(columns.map((column) => normalizeSqliteValue(row[column]))));
  rows.sort();
  return rows;
}

function rowMultiset(rows) {
  const counts = new Map();
  for (const row of rows) counts.set(row, (counts.get(row) ?? 0) + 1);
  return counts;
}

function runsById(rows) {
  const runs = new Map();
  for (const row of rows) {
    const run = runs.get(row.run_id) ?? [];
    run.push(row);
    runs.set(row.run_id, run);
  }
  return runs;
}

function runSignature(rows) {
  return JSON.stringify(
    [...rows]
      .sort((left, right) => left.release_tag.localeCompare(right.release_tag))
      .map(historyRowContent),
  );
}

function historyRowContent(row) {
  return HISTORY_CONTENT_COLUMNS.map((column) => normalizeSqliteValue(row[column]));
}

function normalizeSqliteValue(value) {
  if (value instanceof Uint8Array) {
    return { type: 'blob', base64: Buffer.from(value).toString('base64') };
  }
  return typeof value === 'bigint' ? value.toString() : value ?? null;
}

function verifyDoctor(doctor, dbPath, label) {
  const report = inspectDoctor(doctor, dbPath, label, { failOnWarnings: true });
  if (report.ok !== true) {
    const failures = Array.isArray(report.failures) ? report.failures : [];
    const warnings = Array.isArray(report.warnings) ? report.warnings : [];
    throw new Error(
      `${label} failed doctor: ` +
      `${failures.join('; ') || warnings.join('; ') || 'unknown doctor failure'}`,
    );
  }
  return report;
}

function inspectDoctor(doctor, dbPath, label, { failOnWarnings = false } = {}) {
  let report;
  try {
    report = doctor({ dbPath, failOnWarnings });
  } catch (error) {
    throw new Error(`${label} is not doctor-compatible: ${errorMessage(error)}`);
  }
  if (!report || typeof report !== 'object') throw new Error(`${label} returned an invalid doctor report`);
  return report;
}

function verifyPromotionScore({ dbPath, label }) {
  return runProductionVerifier({
    dbPath,
    label,
    name: 'full score recomputation',
    script: 'scripts/verify-new-scoring.mjs',
    args: ['--all'],
  });
}

function verifyPromotionReleaseAudit({ dbPath, label }) {
  return runProductionVerifier({
    dbPath,
    label,
    name: 'full release-audit invariants',
    script: 'scripts/verify-release-audit-invariants.mjs',
    args: ['--all'],
  });
}

function verifyPromotionValidation({ dbPath, label, expectedReceipt = null }) {
  const script = 'scripts/validation/evaluate-score-quality.mjs';
  const canonicalExpectedReceipt =
    expectedReceipt ?? latestCanonicalEvaluationReceipt(dbPath, label);
  const args = [
    '--require-recorded',
    '--evaluated-at',
    canonicalExpectedReceipt.evaluatedAt,
  ];
  const result = spawnSync(process.execPath, [TSX_CLI, script, ...args], {
    cwd: PROJECT_ROOT,
    env: {
      ...canonicalPromotionEnvironment(dbPath),
      RADAR_DB_READ_ONLY: '1',
    },
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(
      `${label} could not run prospective validation evaluation: ${errorMessage(result.error)}`,
    );
  }
  let report;
  try {
    report = JSON.parse(String(result.stdout ?? '').trim());
  } catch {
    const output = [result.stdout, result.stderr]
      .map((value) => String(value ?? '').trim())
      .filter(Boolean)
      .join('\n');
    throw new Error(
      `${label} prospective validation evaluation returned malformed JSON: ` +
      `${output || `exit ${result.status}`}`,
    );
  }
  const validation = validatePromotionValidationReport(report, result.status, label);
  const canonicalEvaluationReceipt =
    validatePromotionEvaluationBinding(
      report.canonicalEvaluationReceipt,
      canonicalExpectedReceipt,
      label,
    );
  return {
    name: 'prospective validation evaluation',
    script,
    args,
    passed: true,
    ...validation,
    canonicalEvaluationReceipt,
    report,
  };
}

function recordCanonicalPromotion({
  dbPath,
  label,
  environment,
  promotedAt,
  evaluation,
  sourceProofHash,
  destinationProofHash,
}) {
  const script = 'scripts/validation/record-promotion.mjs';
  const args = [
    '--environment',
    environment,
    '--promoted-at',
    promotedAt,
    '--evaluation-id',
    evaluation.evaluationId,
    '--evaluation-content-hash',
    evaluation.contentHash,
    '--source-proof-hash',
    sourceProofHash,
    '--destination-proof-hash',
    destinationProofHash,
  ];
  const env = canonicalPromotionEnvironment(dbPath);
  const result = spawnSync(process.execPath, [TSX_CLI, script, ...args], {
    cwd: PROJECT_ROOT,
    env,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const output = [result.stdout, result.stderr]
      .map((value) => String(value ?? '').trim())
      .filter(Boolean)
      .join('\n');
    throw new Error(
      `${label} could not record its canonical promotion receipt: ` +
      `${result.error ? errorMessage(result.error) : output || `exit ${result.status}`}`,
    );
  }
  let receipt;
  try {
    receipt = JSON.parse(String(result.stdout ?? '').trim());
  } catch {
    throw new Error(
      `${label} canonical promotion recorder returned malformed JSON`,
    );
  }
  return validateCanonicalPromotionReceiptSummary(receipt, {
    environment,
    promotedAt,
    evaluation,
    sourceProofHash,
    destinationProofHash,
  }, label);
}

function validateCanonicalPromotionReceiptSummary(
  receipt,
  expected,
  label,
) {
  if (!receipt || Array.isArray(receipt) || typeof receipt !== 'object') {
    throw new Error(`${label} canonical promotion receipt must be an object`);
  }
  const expectedFields = {
    environment: expected.environment,
    promotedAt: expected.promotedAt,
    evaluationId: expected.evaluation.evaluationId,
    evaluationContentHash: expected.evaluation.contentHash,
    sourceProofHash: expected.sourceProofHash,
    destinationProofHash: expected.destinationProofHash,
  };
  for (const [field, value] of Object.entries(expectedFields)) {
    if (receipt[field] !== value) {
      throw new Error(
        `${label} canonical promotion receipt ${field} does not match ` +
        `the verified promotion input`,
      );
    }
  }
  if (
    receipt.schemaVersion !== 1 ||
    !/^[0-9a-f]{64}$/.test(String(receipt.promotionId ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(receipt.contentHash ?? '')) ||
    !(
      receipt.persistence === 'inserted' &&
      receipt.insertedCount === 1 &&
      receipt.equivalentCount === 0
    ) &&
    !(
      receipt.persistence === 'already_captured' &&
      receipt.insertedCount === 0 &&
      receipt.equivalentCount === 0
    )
  ) {
    throw new Error(
      `${label} canonical promotion receipt has invalid identity or ` +
      `persistence counts`,
    );
  }
  return { ...receipt };
}

function verifyRecordedCanonicalPromotionReceipt(
  dbPath,
  receipt,
  expected,
  label,
) {
  const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 10_000 });
  try {
    if (!tableExists(db, 'release_validation_promotion_receipts')) {
      throw new Error(`${label} has no canonical promotion receipt table`);
    }
    const row = db.prepare(`
      SELECT promotion_id, content_hash, record_json
      FROM release_validation_promotion_receipts
      WHERE promotion_id = ?
    `).get(receipt.promotionId);
    if (!row) {
      throw new Error(
        `${label} canonical promotion receipt identity was not recorded`,
      );
    }
    const record = parseCanonicalLedgerObject(
      row.record_json,
      `${label} canonical promotion receipt record`,
    );
    const exact = {
      promotionId: receipt.promotionId,
      contentHash: receipt.contentHash,
      environment: expected.environment,
      promotedAt: expected.promotedAt,
      evaluationId: expected.evaluation.evaluationId,
      evaluationContentHash: expected.evaluation.contentHash,
      sourceProofHash: expected.sourceProofHash,
      destinationProofHash: expected.destinationProofHash,
    };
    if (
      String(row.promotion_id) !== exact.promotionId ||
      String(row.content_hash) !== exact.contentHash
    ) {
      throw new Error(
        `${label} canonical promotion receipt identity/content hash drifted ` +
        `from the recorded immutable receipt`,
      );
    }
    for (const [field, value] of Object.entries(exact)) {
      if (record[field] !== value) {
        throw new Error(
          `${label} canonical promotion receipt ${field} drifted from the ` +
          `recorded immutable receipt`,
        );
      }
    }
  } finally {
    db.close();
  }
}

export function canonicalPromotionEnvironment(
  dbPath,
  baseEnvironment = process.env,
) {
  const environment = {
    ...baseEnvironment,
    DB_PATH: dbPath,
    RADAR_DB_BOOTSTRAP_MODE: 'existing',
    REFRESH_ON_STARTUP: 'false',
    REFRESH_MINUTES: '0',
  };
  delete environment.RADAR_DB_READ_ONLY;
  return environment;
}

function latestCanonicalEvaluationReceipt(dbPath, label) {
  const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 10_000 });
  try {
    if (!tableExists(db, 'release_validation_evaluation_receipts')) {
      throw new Error(
        `${label} has no canonical validation evaluation receipt table`,
      );
    }
    const row = db.prepare(`
      SELECT
        evaluation_id,
        evaluated_at,
        status,
        content_hash
      FROM release_validation_evaluation_receipts
      ORDER BY evaluated_at DESC, epoch_sequence DESC, evaluation_id DESC
      LIMIT 1
    `).get();
    if (!row) {
      throw new Error(
        `${label} has no recorded canonical validation evaluation receipt`,
      );
    }
    return {
      evaluationId: String(row.evaluation_id),
      evaluatedAt: String(row.evaluated_at),
      status: String(row.status),
      contentHash: String(row.content_hash),
    };
  } finally {
    db.close();
  }
}

export function validatePromotionEvaluationBinding(
  actual,
  expected,
  label = 'candidate',
) {
  if (!actual || typeof actual !== 'object' || Array.isArray(actual)) {
    throw new Error(
      `${label} has no canonical evaluation receipt binding`,
    );
  }
  if (
    !/^[0-9a-f]{64}$/.test(String(actual.evaluationId ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(actual.contentHash ?? '')) ||
    !Number.isFinite(Date.parse(actual.evaluatedAt)) ||
    !['validated', 'insufficient', 'measurable_but_failed']
      .includes(actual.status)
  ) {
    throw new Error(
      `${label} canonical evaluation receipt binding is malformed`,
    );
  }
  const required = {
    evaluationId: expected.evaluationId,
    contentHash: expected.contentHash,
    evaluatedAt: expected.evaluatedAt,
    status: expected.status,
    persistence: 'already_captured',
    insertedCount: 0,
    equivalentCount: 0,
  };
  for (const [field, value] of Object.entries(required)) {
    if (actual[field] !== value) {
      throw new Error(
        `${label} canonical evaluation receipt ${field} does not match ` +
        `the recorded immutable receipt`,
      );
    }
  }
  return { ...actual };
}

export function validatePromotionValidationReport(
  report,
  exitCode,
  label = 'candidate',
  { minimumGeneratedAt = null } = {},
) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error(`${label} prospective validation report must be an object`);
  }
  if (Number(report.schemaVersion) !== 4) {
    throw new Error(
      `${label} prospective validation report schemaVersion must equal 4`,
    );
  }
  if (!Array.isArray(report.errors)) {
    throw new Error(`${label} prospective validation report errors must be an array`);
  }
  if (report.errors.length > 0) {
    throw new Error(
      `${label} prospective validation report contains integrity or semantic errors: ` +
      report.errors.slice(0, 10).join('; '),
    );
  }
  const generatedAtMs = Date.parse(report.generatedAt);
  if (!Number.isFinite(generatedAtMs)) {
    throw new Error(
      `${label} prospective validation report generatedAt must be a valid timestamp`,
    );
  }
  if (
    minimumGeneratedAt != null &&
    generatedAtMs < new Date(minimumGeneratedAt).getTime()
  ) {
    throw new Error(
      `${label} prospective validation report is stale: generatedAt ` +
      `${report.generatedAt} predates this promotion`,
    );
  }
  const currentStratum = report.currentStratum;
  if (!currentStratum || typeof currentStratum !== 'object' || Array.isArray(currentStratum)) {
    throw new Error(
      `${label} prospective validation report currentStratum must be an object`,
    );
  }
  const hidesFailedMeasurableModel =
    currentStratum.status === 'measurable_but_failed' ||
    (
      currentStratum.sampleSufficient === true &&
      currentStratum.qualityPassed === false
    );
  if (hidesFailedMeasurableModel) {
    throw new Error(
      `${label} prospective validation report hides a failed measurable model`,
    );
  }
  if (report.status === 'validated') {
    if (
      exitCode !== 0 ||
      report.failureClass != null ||
      currentStratum.status !== 'validated' ||
      currentStratum.sampleSufficient !== true ||
      currentStratum.qualityPassed !== true
    ) {
      throw new Error(
        `${label} prospective validation report is internally inconsistent for validated status`,
      );
    }
    return {
      status: 'validated',
      validated: true,
      exitCode,
    };
  }
  if (report.status === 'insufficient') {
    throw new Error(
      `${label} prospective validation report is not explicitly validated ` +
      `(status insufficient, failureClass ${String(report.failureClass ?? 'unknown')})`,
    );
  }
  if (report.status === 'measurable_but_failed') {
    throw new Error(
      `${label} prospective validation evaluation failed measurably ` +
      `(${String(report.failureClass ?? 'unknown failure')})`,
    );
  }
  throw new Error(
    `${label} prospective validation report has unsupported status ` +
    `${JSON.stringify(report.status)}`,
  );
}

function requireValidatedPromotionResult(
  result,
  { label, expectedEvaluationReceipt },
) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error(`${label} prospective validation result must be an object`);
  }
  if (
    result.passed !== true ||
    result.status !== 'validated' ||
    result.validated !== true
  ) {
    throw new Error(
      `${label} prospective validation result is not explicitly validated ` +
      `(status ${JSON.stringify(result.status)}, validated ${JSON.stringify(result.validated)})`,
    );
  }
  const validated = validatePromotionValidationReport(
    result.report,
    result.exitCode,
    label,
  );
  assert.equal(
    validated.status,
    result.status,
    `${label} prospective validation result status differs from its report`,
  );
  assert.equal(
    validated.validated,
    result.validated,
    `${label} prospective validation result flag differs from its report`,
  );
  const actualEvaluatedAtMs = Date.parse(
    result.canonicalEvaluationReceipt?.evaluatedAt,
  );
  const expectedEvaluatedAtMs = Date.parse(
    expectedEvaluationReceipt?.evaluatedAt,
  );
  if (
    Number.isFinite(actualEvaluatedAtMs) &&
    Number.isFinite(expectedEvaluatedAtMs) &&
    actualEvaluatedAtMs < expectedEvaluatedAtMs
  ) {
    throw new Error(
      `${label} prospective validation report is stale: evaluation receipt ` +
      `${result.canonicalEvaluationReceipt.evaluatedAt} predates latest ` +
      `recorded receipt ${expectedEvaluationReceipt.evaluatedAt}`,
    );
  }
  const canonicalEvaluationReceipt = validatePromotionEvaluationBinding(
    result.canonicalEvaluationReceipt,
    expectedEvaluationReceipt,
    label,
  );
  if (
    canonicalEvaluationReceipt.status !== 'validated' ||
    canonicalEvaluationReceipt.evaluatedAt !== result.report.generatedAt
  ) {
    throw new Error(
      `${label} validated report is not bound to its exact canonical ` +
      `evaluation receipt`,
    );
  }
  return {
    ...result,
    canonicalEvaluationReceipt,
  };
}

function promotionValidationIdentity(validation, label) {
  const report = validation?.report;
  const evaluation = validation?.canonicalEvaluationReceipt;
  if (!report || Array.isArray(report) || typeof report !== 'object') {
    throw new Error(`${label} has no exact validation report identity`);
  }
  if (
    !evaluation ||
    Array.isArray(evaluation) ||
    typeof evaluation !== 'object' ||
    !/^[0-9a-f]{64}$/.test(String(evaluation.evaluationId ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(evaluation.contentHash ?? '')) ||
    !Number.isFinite(Date.parse(evaluation.evaluatedAt)) ||
    evaluation.status !== 'validated'
  ) {
    throw new Error(`${label} has no exact validated evaluation receipt identity`);
  }
  return {
    validationReport: {
      schemaVersion: Number(report.schemaVersion),
      generatedAt: String(report.generatedAt),
      status: String(report.status),
      contentHash: digestDomainSeparatedJson(
        PROMOTION_VALIDATION_REPORT_HASH_DOMAIN,
        report,
      ),
    },
    evaluationReceipt: {
      evaluationId: String(evaluation.evaluationId),
      contentHash: String(evaluation.contentHash),
      evaluatedAt: String(evaluation.evaluatedAt),
      status: String(evaluation.status),
    },
  };
}

function assertPromotionValidationIdentityEqual(expected, actual) {
  if (
    canonicalOperationJson(expected.validationReport) !==
    canonicalOperationJson(actual.validationReport)
  ) {
    throw new Error(
      'Staged promotion validation report identity drifted from the verified source report',
    );
  }
  if (
    canonicalOperationJson(expected.evaluationReceipt) !==
    canonicalOperationJson(actual.evaluationReceipt)
  ) {
    throw new Error(
      'Staged promotion evaluation receipt identity drifted from the verified source receipt',
    );
  }
}

function buildPromotionAuthorization({
  sourceDatabase,
  installedDatabase,
  validationIdentity,
  promotionReceipt,
  githubReleaseCatalog,
}) {
  const sourceIdentity = {
    applicationId: sourceDatabase?.applicationId,
    userVersion: sourceDatabase?.userVersion,
    logicalContentDigest: sourceDatabase?.logicalContentDigest,
    schemaDigest: sourceDatabase?.schemaDigest,
  };
  if (
    !Number.isInteger(sourceIdentity.applicationId) ||
    !Number.isInteger(sourceIdentity.userVersion) ||
    sourceIdentity.userVersion < 0 ||
    !/^[0-9a-f]{64}$/.test(String(sourceIdentity.logicalContentDigest ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(sourceIdentity.schemaDigest ?? ''))
  ) {
    throw new Error(
      'Applied promotion has no stable current source logical/schema identity',
    );
  }
  const installedIdentity = {
    logicalContentDigest: installedDatabase?.logicalContentDigest,
    schemaDigest: installedDatabase?.schemaDigest,
    physicalSha256: installedDatabase?.physicalSha256,
  };
  if (
    !/^[0-9a-f]{64}$/.test(
      String(installedIdentity.logicalContentDigest ?? ''),
    ) ||
    !/^[0-9a-f]{64}$/.test(String(installedIdentity.schemaDigest ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(installedIdentity.physicalSha256 ?? ''))
  ) {
    throw new Error(
      'Applied promotion has no stable installed logical/schema/physical identity',
    );
  }
  const promotionReceiptIdentity = {
    promotionId: promotionReceipt?.promotionId,
    contentHash: promotionReceipt?.contentHash,
  };
  if (
    !/^[0-9a-f]{64}$/.test(String(promotionReceiptIdentity.promotionId ?? '')) ||
    !/^[0-9a-f]{64}$/.test(String(promotionReceiptIdentity.contentHash ?? ''))
  ) {
    throw new Error(
      'Applied promotion has no stable canonical promotion receipt identity',
    );
  }
  const githubReleaseCatalogIdentity =
    promotionGithubReleaseCatalogAuthorizationIdentity(
      githubReleaseCatalog,
      'promotion authorization',
    );
  const payload = {
    schemaVersion: PROMOTION_AUTHORIZATION_SCHEMA_VERSION,
    phase: 'applied',
    sourceDatabase: sourceIdentity,
    installedDatabase: installedIdentity,
    validationReport: { ...validationIdentity.validationReport },
    evaluationReceipt: { ...validationIdentity.evaluationReceipt },
    promotionReceipt: promotionReceiptIdentity,
    githubReleaseCatalog: githubReleaseCatalogIdentity,
  };
  return {
    ...payload,
    contentHash: digestDomainSeparatedJson(
      PROMOTION_AUTHORIZATION_HASH_DOMAIN,
      payload,
    ),
  };
}

function promotionGithubReleaseCatalogAuthorizationIdentity(proof, label) {
  const repository = String(proof?.repository ?? '');
  const observedAt = String(proof?.observedAt ?? '');
  const remoteCatalogDigest = String(
    proof?.remoteCatalog?.digest ?? '',
  );
  const activeCatalogDigest = String(
    proof?.activeCatalog?.digest ?? '',
  );
  const activeReleaseCount = Number(
    proof?.activeCatalog?.releaseCount,
  );
  const activeReleaseTags = proof?.activeCatalog?.tags;
  if (
    proof?.schemaVersion !== 1 ||
    proof?.source !== 'independent_github_graphql' ||
    proof?.exactIdentityMatch !== true ||
    !/^[^/\s]+\/[^/\s]+$/.test(repository) ||
    !Number.isFinite(Date.parse(observedAt)) ||
    !/^[0-9a-f]{64}$/.test(remoteCatalogDigest) ||
    !/^[0-9a-f]{64}$/.test(activeCatalogDigest) ||
    !Number.isSafeInteger(activeReleaseCount) ||
    activeReleaseCount <= 0 ||
    !Array.isArray(activeReleaseTags) ||
    activeReleaseTags.length !== activeReleaseCount ||
    activeReleaseTags.some(
      (tag) =>
        typeof tag !== 'string' ||
        !tag ||
        tag.trim() !== tag,
    )
  ) {
    throw new Error(
      `${label} has no exact independent GitHub release catalog proof`,
    );
  }
  return {
    schemaVersion: 1,
    source: 'independent_github_graphql',
    repository,
    observedAt,
    remoteCatalogDigest,
    activeCatalogDigest,
    activeReleaseCount,
    activeReleaseTags: [...activeReleaseTags],
    exactIdentityMatch: true,
  };
}

function verifyStagedQualityGate({
  doctor,
  verifyScore,
  verifyReleaseAudit,
  verifyValidation,
  latestEvaluationReceipt,
  dbPath,
  label,
}) {
  const failures = [];
  let doctorReport = null;
  let score = null;
  let releaseAudit = null;
  let validation = null;
  try {
    doctorReport = verifyDoctor(doctor, dbPath, label);
  } catch (error) {
    failures.push(errorMessage(error));
  }
  try {
    score = verifyScore({ dbPath, label });
  } catch (error) {
    failures.push(errorMessage(error));
  }
  try {
    releaseAudit = verifyReleaseAudit({ dbPath, label });
  } catch (error) {
    failures.push(errorMessage(error));
  }
  try {
    const expectedEvaluationReceipt = latestEvaluationReceipt(dbPath, label);
    validation = requireValidatedPromotionResult(
      verifyValidation({
        dbPath,
        label,
        expectedReceipt: expectedEvaluationReceipt,
      }),
      {
        label,
        expectedEvaluationReceipt,
      },
    );
  } catch (error) {
    failures.push(errorMessage(error));
  }
  if (failures.length > 0) {
    throw new Error(`${label} failed full quality verification: ${failures.join(' | ')}`);
  }
  return {
    doctor: doctorReport,
    score,
    releaseAudit,
    validation,
  };
}

function assertNoPendingDeployment(destinationPath, deploymentTransaction = null) {
  const existing = [];
  for (const pendingPath of pendingDeployPaths(destinationPath)) {
    let info;
    try {
      info = lstatSync(pendingPath);
    } catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw new Error(
        `Could not inspect installer pending-deploy marker ${pendingPath}: ` +
        errorMessage(error),
      );
    }
    existing.push({ pendingPath, info });
  }
  if (deploymentTransaction == null) {
    if (existing.length === 0) return null;
    const [{ pendingPath, info }] = existing;
    const markerType = info.isDirectory() && !info.isSymbolicLink()
      ? 'directory'
      : 'malformed path';
    throw new Error(
      `Refusing quality database promotion while installer pending-deploy ` +
      `${markerType} exists: ${pendingPath}. Installer rollback may restore ` +
      `the pre-deploy snapshot over ${destinationPath}.`,
    );
  }
  if (deploymentTransaction.lockHeldByInstaller !== true) {
    throw new Error(
      'Installer-owned promotion requires verified inherited deployment lock proof',
    );
  }
  if (existing.length !== 1) {
    throw new Error(
      `Installer-owned promotion requires exactly one pending-deploy marker; ` +
      `found ${existing.length}`,
    );
  }
  const [{ pendingPath, info }] = existing;
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(
      `Installer pending-deploy marker must be a non-symlink directory: ${pendingPath}`,
    );
  }
  const fields = Object.fromEntries(
    INSTALLER_PENDING_STATE_FIELDS.map((field) => [
      field,
      readSingleLineFile(join(pendingPath, field), `installer pending field ${field}`),
    ]),
  );
  if (
    fields.pending_schema_version !==
      String(INSTALLER_PENDING_STATE_SCHEMA_VERSION)
  ) {
    throw new Error(
      `Installer pending-deploy schema ${fields.pending_schema_version} is unsupported; ` +
      `expected ${INSTALLER_PENDING_STATE_SCHEMA_VERSION}`,
    );
  }
  const recordedHash = readSingleLineFile(
    join(pendingPath, 'pending_state_hash'),
    'installer pending state hash',
  );
  const computedHash = installerPendingStateHash(fields);
  if (recordedHash !== computedHash) {
    throw new Error(
      `Installer pending-deploy identity hash mismatch: expected ${recordedHash}, ` +
      `computed ${computedHash}`,
    );
  }
  if (deploymentTransaction.pendingStateHash !== recordedHash) {
    throw new Error(
      `Deployment transaction pending-state hash does not match installer state: ` +
      `${deploymentTransaction.pendingStateHash} != ${recordedHash}`,
    );
  }
  const expected = {
    transaction_id: deploymentTransaction.transactionId,
    release_name: deploymentTransaction.releaseName,
    github_sha: deploymentTransaction.releaseSha,
    artifact_digest: deploymentTransaction.artifactDigest,
    required_score_receipt_id: deploymentTransaction.requiredScoreReceiptId,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (fields[field] !== value) {
      throw new Error(
        `Installer pending-deploy ${field} does not match deployment transaction: ` +
        `${fields[field]} != ${value}`,
      );
    }
  }
  if (realpathSync(fields.database_path) !== realpathSync(destinationPath)) {
    throw new Error(
      `Installer pending-deploy database path does not match promotion destination: ` +
      `${fields.database_path} != ${destinationPath}`,
    );
  }
  return {
    path: pendingPath,
    pendingStateHash: recordedHash,
    transactionId: fields.transaction_id,
    databasePath: realpathSync(fields.database_path),
    rollbackBackupPath: realpathSync(fields.db_snapshot_path),
    runtimeEnvPath: realpathSync(fields.runtime_env_path),
    qualityDatabasePath: realpathSync(fields.quality_database_path),
    requiredScoreReceiptId: fields.required_score_receipt_id,
    verified: true,
  };
}

function pendingDeployPaths(destinationPath) {
  const paths = new Set([
    join(
      resolve(process.env.RADAR_INSTALL_BASE ?? DEFAULT_INSTALL_BASE),
      PENDING_DEPLOY_DIRECTORY,
    ),
  ]);
  const destinationDirectory = dirname(destinationPath);
  if (basename(destinationDirectory) === 'shared') {
    paths.add(join(dirname(destinationDirectory), PENDING_DEPLOY_DIRECTORY));
  }
  return [...paths];
}

function readSingleLineFile(path, label) {
  let value;
  try {
    value = readFileSync(path, 'utf8');
  } catch (error) {
    throw new Error(`Could not read ${label} at ${path}: ${errorMessage(error)}`);
  }
  if (value.includes('\0')) {
    throw new Error(`${label} contains a NUL byte: ${path}`);
  }
  const lines = value.replace(/\n$/, '').split(/\r?\n/);
  if (lines.length !== 1) {
    throw new Error(`${label} must contain exactly one line: ${path}`);
  }
  return lines[0];
}

export function installerPendingStateHash(fields) {
  return digestText(
    `${INSTALLER_PENDING_STATE_HASH_DOMAIN}\0${JSON.stringify(
      INSTALLER_PENDING_STATE_FIELDS.map((field) => fields[field]),
    )}`,
  );
}

function verifyDeploymentSourceAuthorization(dbPath, deploymentTransaction) {
  if (deploymentTransaction == null) return null;
  const db = new DatabaseSync(dbPath, { readOnly: true, timeout: 10_000 });
  try {
    const metaRow = db.prepare(
      `SELECT value FROM meta WHERE key='score_persistence_last_run'`,
    ).get();
    let scorePersistence;
    try {
      scorePersistence = JSON.parse(String(metaRow?.value ?? 'null'));
    } catch {
      throw new Error(
        'Installer-owned promotion source has malformed score_persistence_last_run metadata',
      );
    }
    if (
      scorePersistence == null ||
      typeof scorePersistence !== 'object' ||
      Array.isArray(scorePersistence)
    ) {
      throw new Error(
        'Installer-owned promotion source is missing score_persistence_last_run metadata',
      );
    }
    if (scorePersistence.operationReceiptRequired !== true) {
      throw new Error(
        'Installer-owned promotion source does not require an operation receipt',
      );
    }
    const runId = String(scorePersistence.operationRunId ?? '');
    if (!runId) {
      throw new Error(
        'Installer-owned promotion source does not bind the current score to an operation run',
      );
    }
    if (scorePersistence.codeRevision !== deploymentTransaction.releaseSha) {
      throw new Error(
        `Installer-owned promotion source code revision ` +
        `${JSON.stringify(scorePersistence.codeRevision)} does not match release SHA ` +
        deploymentTransaction.releaseSha,
      );
    }
    const receipt = db.prepare(`
      SELECT
        receipt_id,
        run_id,
        status,
        payload_json
      FROM refresh_capture_receipts
      WHERE run_id=?
    `).get(runId);
    const attempt = db.prepare(`
      SELECT run_id, code_revision
      FROM refresh_operation_attempts
      WHERE run_id=?
    `).get(runId);
    if (!receipt || !attempt) {
      throw new Error(
        `Installer-owned promotion source is missing the current score attempt or receipt for ${runId}`,
      );
    }
    if (receipt.receipt_id !== deploymentTransaction.requiredScoreReceiptId) {
      throw new Error(
        `Installer-owned promotion source receipt ${receipt.receipt_id} does not match required ` +
        deploymentTransaction.requiredScoreReceiptId,
      );
    }
    if (receipt.status !== 'success') {
      throw new Error(
        `Installer-owned promotion source receipt ${receipt.receipt_id} is not successful`,
      );
    }
    if (attempt.code_revision !== deploymentTransaction.releaseSha) {
      throw new Error(
        `Installer-owned promotion source attempt revision ${attempt.code_revision} ` +
        `does not match release SHA ${deploymentTransaction.releaseSha}`,
      );
    }
    let payload;
    try {
      payload = JSON.parse(String(receipt.payload_json));
    } catch {
      throw new Error(
        `Installer-owned promotion source receipt ${receipt.receipt_id} has malformed payload JSON`,
      );
    }
    if (payload?.codeRevision !== deploymentTransaction.releaseSha) {
      throw new Error(
        `Installer-owned promotion source receipt payload revision ` +
        `${JSON.stringify(payload?.codeRevision)} does not match release SHA ` +
        deploymentTransaction.releaseSha,
      );
    }
    return {
      schemaVersion: 1,
      runId,
      receiptId: receipt.receipt_id,
      receiptStatus: receipt.status,
      codeRevision: attempt.code_revision,
      verified: true,
    };
  } finally {
    db.close();
  }
}

function runProductionVerifier({ dbPath, label, name, script, args }) {
  const result = spawnSync(process.execPath, [TSX_CLI, script, ...args], {
    cwd: PROJECT_ROOT,
    env: {
      ...canonicalPromotionEnvironment(dbPath),
      RADAR_DB_READ_ONLY: '1',
    },
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`${label} could not run ${name}: ${errorMessage(result.error)}`);
  }
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr]
      .map((value) => String(value ?? '').trim())
      .filter(Boolean)
      .join('\n');
    throw new Error(
      `${label} failed ${name}: ${output || `exit ${result.status}`}`,
    );
  }
  return {
    name,
    script,
    args,
    passed: true,
  };
}

function doctorIdentity(report) {
  return {
    ok: report.ok === true,
    failureCount: Array.isArray(report.failures) ? report.failures.length : 0,
    latestScoredTag: report.latestScoredStable?.tag ?? null,
    latestScoredAt: report.latestScoredStable?.scoredAt ?? null,
    currentSourceIdentityDigest: report.scorePersistence?.sourceIdentity?.current?.digest ?? null,
    persistedSourceIdentityDigest: report.scorePersistence?.sourceIdentity?.persisted?.digest ?? null,
    promotionImmutableLedgerDigest:
      report.promotionImmutableLedgers?.tableDigest ?? null,
    promotionAppendOnlyTriggerDigest:
      report.promotionImmutableLedgers?.appendOnlyTriggerDigest ?? null,
    reportDigest: digestJson(stableDoctorReport(report)),
  };
}

function stableDoctorReport(report) {
  const stable = structuredClone(report);
  delete stable.generatedAt;
  delete stable.db;
  return stable;
}

function assertDoctorIdentityEqual(expectedReport, actualReport, message) {
  if (digestJson(doctorIdentity(expectedReport)) !== digestJson(doctorIdentity(actualReport))) {
    throw new Error(message);
  }
}

function assertSourceIdentityPreserved(sourceDoctor, stagedDoctor) {
  const sourceIdentity = doctorIdentity(sourceDoctor);
  const stagedIdentity = doctorIdentity(stagedDoctor);
  if (
    !sourceIdentity.currentSourceIdentityDigest ||
    sourceIdentity.currentSourceIdentityDigest !== stagedIdentity.currentSourceIdentityDigest ||
    sourceIdentity.persistedSourceIdentityDigest !== stagedIdentity.persistedSourceIdentityDigest
  ) {
    throw new Error('Staged promotion does not preserve the verified quality database source identity');
  }
}

export function readPromotionAdvisoryAuditProjection({
  dbPath,
  label,
  observedAt,
}) {
  const reader = openReleaseAuditReader(dbPath);
  try {
    return reader.advisorySnapshotAuditProjection(null, { observedAt });
  } catch (error) {
    throw new Error(
      `${label} advisory public-audit projection could not be reconstructed: ` +
      errorMessage(error),
    );
  } finally {
    reader.close();
  }
}

function requireVerifiedAdvisoryAuditProjection(projection, label) {
  if (
    !projection ||
    projection.schemaVersion !== 1 ||
    projection.sourceMode !== 'receipt_authorized_compound_advisory_v2' ||
    projection.verified !== true ||
    projection.activeProjectionVerified !== true ||
    projection.activeMetadata == null ||
    projection.authorizingReceipt == null ||
    Number(projection.failedCount ?? -1) !== 0 ||
    !Array.isArray(projection.problems) ||
    projection.problems.length !== 0
  ) {
    const problems = Array.isArray(projection?.problems)
      ? projection.problems.join('; ')
      : 'projection is missing or malformed';
    throw new Error(
      `${label} does not have a verified receipt-authorized advisory public-audit projection: ` +
      (problems || 'required verification fields are missing or inconsistent'),
    );
  }
  return projection;
}

function advisoryAuditProjectionEvidence(projection) {
  return {
    digest: digestJson(projection),
    projection,
  };
}

function assertAdvisoryAuditProjectionEqual(expected, actual, message) {
  if (digestJson(expected) !== digestJson(actual)) {
    throw new Error(message);
  }
}

function revalidateSourceDatabase({
  dependencies,
  sourcePath,
  expectedFileIdentity,
  expectedDatabaseIdentity,
  snapshotPath,
  phase,
  label,
  apply,
}) {
  normalizeReadInspectionSqliteFamily(
    expectedFileIdentity,
    sourcePath,
    `${label} changed inode or path identity in its SQLite family before revalidation`,
  );
  const beforeSnapshot = inspectDatabaseActivity(
    dependencies,
    sourcePath,
    { phase, label },
  );
  assertSourceActivityAllowsApply(sourcePath, beforeSnapshot, apply);
  dependencies.snapshotDatabase(sourcePath, snapshotPath);
  const database = verifyDatabase(snapshotPath, `${label} snapshot`, {
    requireScoreEvidenceSnapshots: true,
  });
  assertDatabaseIdentityEqual(
    expectedDatabaseIdentity,
    database,
    `${label} logical contents or database identity drifted`,
  );
  normalizeReadInspectionSqliteFamily(
    expectedFileIdentity,
    sourcePath,
    `${label} changed inode or path identity in its SQLite family during revalidation`,
  );
  const afterSnapshot = inspectDatabaseActivity(
    dependencies,
    sourcePath,
    {
      phase: `${phase}-after-snapshot`,
      label: `${label} after snapshot`,
    },
  );
  assertSourceActivityAllowsApply(sourcePath, afterSnapshot, apply);
  normalizeReadInspectionSqliteFamily(
    expectedFileIdentity,
    sourcePath,
    `${label} changed its SQLite family during post-snapshot activity inspection`,
  );
  return {
    observedAt: afterSnapshot.observedAt,
    active: beforeSnapshot.active || afterSnapshot.active,
    holderCount: beforeSnapshot.holderCount + afterSnapshot.holderCount,
    holders: [...beforeSnapshot.holders, ...afterSnapshot.holders],
    refreshLeases: afterSnapshot.refreshLeases,
    beforeSnapshot,
    afterSnapshot,
    fileIdentityStable: true,
    databaseIdentityStable: true,
    database,
  };
}

function recheckSourceBoundary({
  dependencies,
  sourcePath,
  expectedFileIdentity,
  phase,
  label,
  apply,
}) {
  normalizeReadInspectionSqliteFamily(
    expectedFileIdentity,
    sourcePath,
    `${label} changed its SQLite family before the final activity check`,
  );
  const activity = inspectDatabaseActivity(
    dependencies,
    sourcePath,
    { phase, label },
  );
  assertSourceActivityAllowsApply(sourcePath, activity, apply);
  normalizeReadInspectionSqliteFamily(
    expectedFileIdentity,
    sourcePath,
    `${label} changed its SQLite family during the final activity check`,
  );
  return {
    ...activity,
    fileIdentityStable: true,
  };
}

function inspectDatabaseActivity(dependencies, path, { phase, label }) {
  const observedAt = dependencies.now();
  if (!(observedAt instanceof Date) || !Number.isFinite(observedAt.getTime())) {
    throw new Error(`${label} activity inspection requires a valid observation time`);
  }
  const holders = inspectHolders(dependencies, path, phase);
  const refreshLeases = refreshLeaseSummary(path, observedAt, label);
  return {
    observedAt: observedAt.toISOString(),
    active: holders.length > 0 || refreshLeases.activeCount > 0,
    holderCount: holders.length,
    holders,
    refreshLeases,
  };
}

function assertSourceActivityAllowsApply(sourcePath, activity, apply) {
  if (!apply) return;
  if (activity.holders.length > 0) {
    throw sourceHolderError(sourcePath, activity.holders);
  }
  if (activity.refreshLeases.activeCount > 0) {
    throw activeLeaseError(sourcePath, activity.refreshLeases, 'source database');
  }
}

function inspectHolders(dependencies, path, phase, options = {}) {
  const holders = dependencies.listHolders(path, { phase, ...options });
  if (!Array.isArray(holders)) {
    throw new Error(`Holder inspection returned an invalid result during ${phase}`);
  }
  return holders.map((holder) => ({
    ...holder,
    phase,
    paths: Array.isArray(holder.paths) ? holder.paths : [],
    accesses: Array.isArray(holder.accesses) ? holder.accesses : [],
  }));
}

export function listDestinationHolders(destinationPath, {
  identity = null,
  writersOnly = false,
} = {}) {
  const identityMembers = identity == null
    ? []
    : sqliteHolderIdentityMembers(identity);
  const paths = identity
    ? []
    : sqliteFamilyPaths(destinationPath)
      .filter((path) => existsSync(path));
  if ((!identity && paths.length === 0) || (identity && identityMembers.length === 0)) {
    return [];
  }
  const args = identity
    ? ['-a', '+L1', '-FpcfaDin']
    : ['-FpcfaDin'];
  if (!identity) args.push('--', ...paths);
  const result = spawnSync('lsof', args, {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error) throw new Error(`Could not inspect destination holders: ${errorMessage(result.error)}`);
  if (result.status !== 0 && result.status !== 1) {
    throw new Error(`lsof failed while inspecting destination holders: ${result.stderr.trim()}`);
  }

  const holdersByPid = new Map();
  let currentProcess = null;
  let currentFile = null;
  const flushFile = () => {
    if (!currentProcess || !currentFile || currentProcess.pid === process.pid) return;
    if (!Number.isSafeInteger(currentProcess.pid) || currentProcess.pid <= 0) return;
    if (identity) {
      const device = normalizeLsofDevice(currentFile.device);
      const inode = String(currentFile.inode ?? '');
      if (!identityMembers.some((member) =>
        device === member.device && inode === member.inode)) {
        return;
      }
    }
    if (
      writersOnly &&
      currentFile.access != null &&
      currentFile.access !== 'w' &&
      currentFile.access !== 'u'
    ) {
      return;
    }
    const holder = holdersByPid.get(currentProcess.pid) ?? {
      pid: currentProcess.pid,
      command: currentProcess.command,
      paths: [],
      accesses: [],
    };
    holder.command ??= currentProcess.command;
    if (currentFile.name && !holder.paths.includes(currentFile.name)) {
      holder.paths.push(currentFile.name);
    }
    const access = currentFile.access ?? 'unknown';
    if (!holder.accesses.includes(access)) holder.accesses.push(access);
    holdersByPid.set(holder.pid, holder);
  };

  for (const line of result.stdout.split('\n')) {
    if (!line) continue;
    const type = line[0];
    const value = line.slice(1);
    if (type === 'p') {
      flushFile();
      currentFile = null;
      currentProcess = { pid: Number(value), command: null };
    } else if (type === 'c' && currentProcess) {
      currentProcess.command = value;
    } else if (type === 'f' && currentProcess) {
      flushFile();
      currentFile = {
        descriptor: value,
        access: null,
        device: null,
        inode: null,
        name: null,
      };
    } else if (type === 'a' && currentFile) {
      currentFile.access = value;
    } else if (type === 'D' && currentFile) {
      currentFile.device = value;
    } else if (type === 'i' && currentFile) {
      currentFile.inode = value;
    } else if (type === 'n' && currentFile) {
      currentFile.name = value;
    }
  }
  flushFile();
  return [...holdersByPid.values()].sort((left, right) => left.pid - right.pid);
}

function sqliteHolderIdentityMembers(identity) {
  const members = Array.isArray(identity.family)
    ? identity.family
    : [identity];
  const seen = new Set();
  return members
    .filter((member) =>
      member &&
      typeof member.device === 'string' &&
      typeof member.inode === 'string')
    .filter((member) => {
      const key = `${member.device}:${member.inode}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .map((member) => ({
      device: member.device,
      inode: member.inode,
    }));
}

function normalizeLsofDevice(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return BigInt(value).toString();
  } catch {
    return null;
  }
}

function readFileMetadata(path) {
  const info = statSync(path, { bigint: true });
  return {
    uid: String(info.uid),
    gid: String(info.gid),
    mode: Number(info.mode & 0o7777n),
    acl: readAclMetadata(path),
    xattrs: readExtendedAttributeMetadata(path),
  };
}

function readAclMetadata(path) {
  if (process.platform === 'darwin') {
    const output = runMetadataCommand('/bin/ls', ['-lde', path], 'read destination ACLs');
    return {
      format: 'darwin-ls-le',
      entries: output.split('\n').slice(1).map((line) => line.trim()).filter(Boolean),
    };
  }
  if (process.platform === 'linux') {
    const output = runMetadataCommand(
      'getfacl',
      ['-c', '--absolute-names', path],
      'read destination ACLs',
    );
    return {
      format: 'posix-getfacl',
      entries: output.split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#')),
    };
  }
  throw new Error(`ACL preservation is not supported on ${process.platform}`);
}

function readExtendedAttributeMetadata(path) {
  if (process.platform === 'darwin') {
    const names = runMetadataCommand('/usr/bin/xattr', [path], 'list destination xattrs')
      .split('\n')
      .map((name) => name.trim())
      .filter(Boolean)
      .sort();
    return {
      format: 'darwin-xattr-hex',
      entries: names.map((name) => [
        name,
        runMetadataCommand(
          '/usr/bin/xattr',
          ['-px', name, path],
          `read destination xattr ${name}`,
        ).replace(/\s+/g, '').toLowerCase(),
      ]),
    };
  }
  if (process.platform === 'linux') {
    const output = runMetadataCommand(
      'getfattr',
      ['--absolute-names', '-d', '-m', '-', '-e', 'hex', path],
      'read destination xattrs',
    );
    return {
      format: 'linux-getfattr-hex',
      entries: output.split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))
        .sort(),
    };
  }
  throw new Error(`Extended-attribute preservation is not supported on ${process.platform}`);
}

function runMetadataCommand(command, args, action) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) throw new Error(`Could not ${action}: ${errorMessage(result.error)}`);
  if (result.status !== 0) {
    throw new Error(`Could not ${action}: ${String(result.stderr ?? '').trim() || `exit ${result.status}`}`);
  }
  return String(result.stdout ?? '').trimEnd();
}

function cloneFileWithMetadata(sourcePath, destinationPath) {
  removeSqliteFamily(destinationPath);
  if (process.platform === 'darwin') {
    runMetadataCommand('/bin/cp', ['-p', sourcePath, destinationPath], 'clone file metadata');
    return;
  }
  if (process.platform === 'linux') {
    runMetadataCommand(
      '/bin/cp',
      ['--preserve=all', '--', sourcePath, destinationPath],
      'clone file metadata',
    );
    return;
  }
  throw new Error(`Metadata-preserving file cloning is not supported on ${process.platform}`);
}

function copyContentsPreservingMetadata(sourcePath, destinationPath) {
  const sourceFd = openSync(sourcePath, 'r');
  const destinationFd = openSync(destinationPath, 'r+');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    ftruncateSync(destinationFd, 0);
    for (;;) {
      const bytesRead = readSync(sourceFd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      let written = 0;
      while (written < bytesRead) {
        written += writeSync(
          destinationFd,
          buffer,
          written,
          bytesRead - written,
          null,
        );
      }
    }
    fsyncSync(destinationFd);
  } finally {
    closeSync(destinationFd);
    closeSync(sourceFd);
  }
}

function sha256File(path) {
  const fd = openSync(path, 'r');
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const bytesRead = readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest('hex');
}

function prepareMetadataPreservingDatabase({
  metadataSourcePath,
  contentSourcePath,
  outputPath,
  expectedMetadata,
  dependencies,
  label,
}) {
  dependencies.cloneWithMetadata(metadataSourcePath, outputPath);
  dependencies.copyContents(contentSourcePath, outputPath);
  restoreOwnerGroupAndMode(outputPath, expectedMetadata);
  const actualMetadata = dependencies.readMetadata(outputPath);
  assertFileMetadataEqual(
    expectedMetadata,
    actualMetadata,
    `${label} could not preserve owner, group, mode, ACLs, and xattrs`,
  );
  dependencies.fsyncPath(outputPath);
  return actualMetadata;
}

function restoreOwnerGroupAndMode(path, expectedMetadata) {
  let info = statSync(path, { bigint: true });
  if (String(info.uid) !== expectedMetadata.uid || String(info.gid) !== expectedMetadata.gid) {
    chownSync(path, Number(expectedMetadata.uid), Number(expectedMetadata.gid));
    info = statSync(path, { bigint: true });
  }
  if (Number(info.mode & 0o7777n) !== expectedMetadata.mode) {
    chmodSync(path, expectedMetadata.mode);
  }
}

function assertFileMetadataEqual(expected, actual, message) {
  if (digestJson(expected) !== digestJson(actual)) throw new Error(message);
}

function metadataSummary(metadata) {
  return {
    uid: metadata.uid,
    gid: metadata.gid,
    mode: `0${metadata.mode.toString(8)}`,
    aclEntryCount: metadata.acl.entries.length,
    xattrCount: metadata.xattrs.entries.length,
    digest: digestJson(metadata),
  };
}

function checkpointAndClearSidecars(destinationPath) {
  const db = new DatabaseSync(destinationPath, { timeout: 10_000 });
  try {
    const checkpoint = db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
    if (Number(checkpoint?.busy ?? 0) !== 0) {
      throw new Error(`Destination WAL checkpoint remained busy: ${JSON.stringify(checkpoint)}`);
    }
  } finally {
    db.close();
  }
  removeSqliteSidecars(destinationPath);
}

function clearReadInspectionSidecars(destinationPath, label) {
  for (const suffix of ['-wal', '-journal']) {
    const sidecarPath = `${destinationPath}${suffix}`;
    if (existsSync(sidecarPath) && statSync(sidecarPath).size > 0) {
      throw new Error(
        `${label} found a non-empty SQLite ${suffix.slice(1)} sidecar; ` +
        `database contents may have changed after verification`,
      );
    }
  }
  removeSqliteSidecars(destinationPath);
  assertNoSidecars(destinationPath, label);
}

function assertNoSidecars(destinationPath, label) {
  const sidecars = sqliteSidecarPaths(destinationPath)
    .filter((path) => existsSync(path));
  if (sidecars.length > 0) {
    throw new Error(
      `${label} found stale or recreated SQLite sidecar(s): ${sidecars.join(', ')}`,
    );
  }
}

function attemptAutomaticRollback({
  destinationPath,
  destinationDirectory,
  backupPath,
  backupFileIdentity,
  backupVerification,
  backupDoctor,
  expectedMetadata,
  dependencies,
  temporaryPaths,
}) {
  let holders;
  try {
    holders = inspectHolders(
      dependencies,
      destinationPath,
      'before-rollback-sidecar-clear',
    );
  } catch (error) {
    return {
      restored: false,
      reason: `Could not inspect destination holders before rollback: ${errorMessage(error)}.`,
    };
  }
  if (holders.length > 0) {
    return {
      restored: false,
      reason: `Automatic rollback was blocked by active holders ` +
        `(${holderSummary(holders)}).`,
    };
  }
  try {
    removeSqliteSidecars(destinationPath);
    assertNoSidecars(destinationPath, 'before automatic rollback activity inspection');
  } catch (error) {
    return {
      restored: false,
      reason: `Could not clear failed destination sidecars before rollback: ${errorMessage(error)}.`,
    };
  }

  let activity;
  try {
    activity = inspectDatabaseActivity(
      dependencies,
      destinationPath,
      {
        phase: 'before-rollback',
        label: 'installed destination before automatic rollback',
      },
    );
  } catch (error) {
    return {
      restored: false,
      reason: `Could not inspect destination activity before rollback: ${errorMessage(error)}.`,
    };
  }
  if (activity.holders.length > 0) {
    return {
      restored: false,
      reason: `Automatic rollback was blocked by active holders ` +
        `(${holderSummary(activity.holders)}).`,
    };
  }
  if (activity.refreshLeases.activeCount > 0) {
    return {
      restored: false,
      reason: `Automatic rollback was blocked by active refresh leases ` +
        `(${activity.refreshLeases.activeLeases
          .map((lease) => `${lease.name}:${lease.holderId}`)
          .join('; ')}).`,
    };
  }

  const rollbackPath = join(
    destinationDirectory,
    `.${basename(destinationPath)}.rollback-${process.pid}-${randomUUID()}.sqlite`,
  );
  temporaryPaths.push(rollbackPath);
  try {
    removeSqliteSidecars(destinationPath);
    assertNoSidecars(destinationPath, 'before automatic rollback');
    assertFileIdentityEqual(
      backupFileIdentity,
      fileIdentity(backupPath),
      'Retained promotion backup changed path or inode before automatic rollback',
    );
    const retainedBackupVerificationBefore = verifyDatabase(
      backupPath,
      'retained promotion backup before automatic rollback',
    );
    const retainedBackupDoctorBefore = inspectDoctor(
      dependencies.doctor,
      backupPath,
      'retained promotion backup before automatic rollback',
    );
    assertDatabaseIdentityEqual(
      backupVerification,
      retainedBackupVerificationBefore,
      'Retained promotion backup logical contents changed before automatic rollback',
    );
    assertDoctorIdentityEqual(
      backupDoctor,
      retainedBackupDoctorBefore,
      'Retained promotion backup doctor result changed before automatic rollback',
    );
    assertFileMetadataEqual(
      expectedMetadata,
      dependencies.readMetadata(backupPath),
      'Retained promotion backup metadata changed before automatic rollback',
    );
    clearReadInspectionSidecars(
      backupPath,
      'after retained promotion backup pre-rollback verification',
    );
    dependencies.cloneWithMetadata(backupPath, rollbackPath);
    restoreOwnerGroupAndMode(rollbackPath, expectedMetadata);
    assertFileMetadataEqual(
      expectedMetadata,
      dependencies.readMetadata(rollbackPath),
      'Rollback copy did not preserve destination metadata',
    );
    const rollbackVerification = verifyDatabase(
      rollbackPath,
      'verified automatic rollback candidate',
    );
    const rollbackDoctor = inspectDoctor(
      dependencies.doctor,
      rollbackPath,
      'verified automatic rollback candidate',
    );
    assertDatabaseIdentityEqual(
      backupVerification,
      rollbackVerification,
      'Automatic rollback candidate differs from the retained promotion backup',
    );
    assertDoctorIdentityEqual(
      backupDoctor,
      rollbackDoctor,
      'Automatic rollback candidate doctor result differs from the retained promotion backup',
    );
    clearReadInspectionSidecars(
      rollbackPath,
      'after automatic rollback candidate verification',
    );
    assertFileIdentityEqual(
      backupFileIdentity,
      fileIdentity(backupPath),
      'Retained promotion backup changed path or inode while the rollback candidate was built',
    );
    const retainedBackupVerificationAfter = verifyDatabase(
      backupPath,
      'retained promotion backup after rollback candidate creation',
    );
    const retainedBackupDoctorAfter = inspectDoctor(
      dependencies.doctor,
      backupPath,
      'retained promotion backup after rollback candidate creation',
    );
    assertDatabaseIdentityEqual(
      backupVerification,
      retainedBackupVerificationAfter,
      'Retained promotion backup logical contents changed while the rollback candidate was built',
    );
    assertDoctorIdentityEqual(
      backupDoctor,
      retainedBackupDoctorAfter,
      'Retained promotion backup doctor result changed while the rollback candidate was built',
    );
    clearReadInspectionSidecars(
      backupPath,
      'after retained promotion backup post-clone verification',
    );
    dependencies.fsyncPath(rollbackPath);
    dependencies.assertDeploymentLockHeld('before automatic rollback restore');
    dependencies.restoreRename(rollbackPath, destinationPath);
    dependencies.fsyncDirectory(destinationDirectory);
    assertNoSidecars(destinationPath, 'after automatic rollback');
    const restoredVerification = verifyDatabase(destinationPath, 'restored destination');
    const restoredDoctor = inspectDoctor(dependencies.doctor, destinationPath, 'restored destination');
    assertDatabaseIdentityEqual(
      backupVerification,
      restoredVerification,
      'Restored destination differs from the retained promotion backup',
    );
    assertDoctorIdentityEqual(
      backupDoctor,
      restoredDoctor,
      'Restored destination doctor result differs from the retained promotion backup',
    );
    assertFileMetadataEqual(
      expectedMetadata,
      dependencies.readMetadata(destinationPath),
      'Restored destination metadata differs from the original destination',
    );
    const restoredActivity = inspectDatabaseActivity(
      dependencies,
      destinationPath,
      {
        phase: 'after-rollback',
        label: 'restored destination after automatic rollback',
      },
    );
    if (restoredActivity.holders.length > 0) {
      throw holderRaceError(
        destinationPath,
        'after automatic rollback',
        restoredActivity.holders,
      );
    }
    if (restoredActivity.refreshLeases.activeCount > 0) {
      throw activeLeaseError(
        destinationPath,
        restoredActivity.refreshLeases,
        'restored destination after automatic rollback',
      );
    }
    clearReadInspectionSidecars(
      destinationPath,
      'after automatic rollback activity revalidation',
    );
    assertNoSidecars(destinationPath, 'after restored destination verification');
    return {
      restored: true,
      beforeRollback: activity,
      afterRollback: restoredActivity,
    };
  } catch (error) {
    return {
      restored: false,
      reason: `Automatic rollback failed: ${errorMessage(error)}.`,
    };
  }
}

function holderError(destinationPath, holders) {
  const summary = holderSummary(holders);
  return new Error(
    `Destination database has active holders (${summary}). ` +
    `Stop them with the operator-managed service workflow, verify the service is quiescent, ` +
    `then rerun --apply. Only explicit --dry-run may inspect a live destination: ${destinationPath}`,
  );
}

function sourceHolderError(sourcePath, holders) {
  return new Error(
    `Source database has active holders (${holderSummary(holders)}). ` +
    `Stop the candidate server or refresh workflow and rerun --apply. ` +
    `Apply always revalidates the live source and cannot use an earlier dry-run report: ${sourcePath}`,
  );
}

function holderRaceError(destinationPath, phase, holders) {
  return new Error(
    `Destination holder race detected ${phase} (${holderSummary(holders)}). ` +
    `Promotion will not report success; rollback backup is retained for ${destinationPath}`,
  );
}

function activeLeaseError(destinationPath, leaseSummary, label) {
  const leases = leaseSummary.activeLeases
    .map((lease) => `${lease.name}:${lease.holderId} expires=${lease.expiresAt}`)
    .join('; ');
  return new Error(
    `${label} has ${leaseSummary.activeCount} active or malformed refresh lease(s) ` +
    `(${leases}). Stop the owning refresh workflow and rerun promotion: ${destinationPath}`,
  );
}

function holderSummary(holders) {
  return holders
    .map((holder) => {
      const access = holder.accesses?.length ? ` access=${holder.accesses.join('/')}` : '';
      return `${holder.pid}:${holder.command ?? 'unknown'} [${holder.paths.join(', ')}]${access}`;
    })
    .join('; ');
}

function uniqueBackupPath(destinationPath, now) {
  const stamp = now.toISOString().replace(/[-:.]/g, '');
  const base = `${destinationPath}.pre-promotion-${stamp}.bak`;
  if (sqliteFamilyPaths(base).every((path) => !existsSync(path))) return base;
  for (let suffix = 1; ; suffix++) {
    const candidate = `${base}.${suffix}`;
    if (sqliteFamilyPaths(candidate).every((path) => !existsSync(path))) {
      return candidate;
    }
  }
}

function parseInheritedDeploymentLockFd(value) {
  if (!/^[0-9]+$/.test(String(value))) {
    throw new Error('--deployment-lock-fd must be an integer file descriptor');
  }
  const fd = Number(value);
  if (!Number.isSafeInteger(fd) || fd < 3) {
    throw new Error('--deployment-lock-fd must be an integer file descriptor >= 3');
  }
  return fd;
}

function canonicalInstallerDeploymentLockPath(destinationPath) {
  const destinationDirectory = dirname(realpathSync(resolve(destinationPath)));
  if (basename(destinationDirectory) !== 'shared') {
    throw new Error(
      'Installer-owned promotion destination must be inside the installation shared directory',
    );
  }
  return join(destinationDirectory, 'deploy-promotion.lock');
}

function verifiedInstallerDeploymentTransaction(transaction) {
  return {
    transactionId: transaction.transactionId,
    releaseName: transaction.releaseName,
    releaseSha: transaction.releaseSha,
    artifactDigest: transaction.artifactDigest,
    pendingStateHash: transaction.pendingStateHash,
    requiredScoreReceiptId: transaction.requiredScoreReceiptId,
    lockHeldByInstaller: true,
  };
}

function positiveInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

export function verifyInheritedDeploymentLock({
  path,
  fd,
}, dependencies = {}) {
  if ((dependencies.platform ?? process.platform) !== 'linux') {
    throw new Error(
      'Installer-owned inherited deployment lock proof requires Linux /proc fdinfo',
    );
  }
  if (typeof path !== 'string' || !path.startsWith('/')) {
    throw new Error('inherited deployment lock path must be absolute');
  }
  if (!Number.isSafeInteger(fd) || fd < 3) {
    throw new Error('inherited deployment lock file descriptor must be an integer >= 3');
  }

  const inspectFd =
    dependencies.fstat ??
    ((descriptor) => fstatSync(descriptor, { bigint: true }));
  const inspectPath =
    dependencies.stat ??
    ((target) => statSync(target, { bigint: true }));
  const inspectLink =
    dependencies.lstat ??
    ((target) => lstatSync(target, { bigint: true }));
  const readFdInfo =
    dependencies.readFdInfo ??
    ((descriptor) =>
      readFileSync(`/proc/self/fdinfo/${descriptor}`, 'utf8'));
  const parent = dirname(path);
  const parentInfo = inspectLink(parent);
  if (!parentInfo.isDirectory()) {
    throw new Error(`deployment lock directory does not exist: ${parent}`);
  }
  if (parentInfo.isSymbolicLink()) {
    throw new Error(`deployment lock directory must not be a symlink: ${parent}`);
  }
  const pathLinkInfo = inspectLink(path);
  if (!pathLinkInfo.isFile() || pathLinkInfo.isSymbolicLink()) {
    throw new Error(
      `deployment lock path must be a regular non-symlink file: ${path}`,
    );
  }

  let descriptorInfo;
  try {
    descriptorInfo = inspectFd(fd);
  } catch (error) {
    throw new Error(
      `inherited deployment lock file descriptor ${fd} is not open: ` +
      errorMessage(error),
    );
  }
  if (!descriptorInfo.isFile()) {
    throw new Error(
      `inherited deployment lock file descriptor ${fd} is not a regular file`,
    );
  }
  const expectedIdentity = lockFileIdentity(inspectPath(path));
  const descriptorIdentity = lockFileIdentity(descriptorInfo);
  assertInheritedLockIdentity(
    descriptorIdentity,
    expectedIdentity,
    fd,
    path,
    'initial inherited lock verification',
  );

  const assertHeld = (label = 'inherited deployment lock boundary') => {
    let currentDescriptorInfo;
    let currentPathInfo;
    let fdInfo;
    try {
      currentDescriptorInfo = inspectFd(fd);
      currentPathInfo = inspectPath(path);
      fdInfo = readFdInfo(fd);
    } catch (error) {
      throw new Error(
        `could not verify inherited deployment lock before ${label}: ` +
        errorMessage(error),
      );
    }
    if (!currentDescriptorInfo.isFile() || !currentPathInfo.isFile()) {
      throw new Error(
        `inherited deployment lock is no longer a regular file before ${label}: ${path}`,
      );
    }
    assertInheritedLockIdentity(
      lockFileIdentity(currentDescriptorInfo),
      expectedIdentity,
      fd,
      path,
      label,
    );
    assertInheritedLockIdentity(
      lockFileIdentity(currentPathInfo),
      expectedIdentity,
      fd,
      path,
      label,
    );
    if (!fdInfoHasExclusiveFlock(fdInfo, expectedIdentity.inode)) {
      throw new Error(
        `inherited deployment lock file descriptor ${fd} does not carry ` +
        `the exclusive FLOCK lock before ${label}: ${path}`,
      );
    }
  };
  assertHeld('inherited lock proof acquisition');

  return {
    assertHeld,
    proof: {
      schemaVersion: INHERITED_DEPLOYMENT_LOCK_PROOF_SCHEMA_VERSION,
      method: INHERITED_DEPLOYMENT_LOCK_PROOF_METHOD,
      fd,
      path,
      device: expectedIdentity.device,
      inode: expectedIdentity.inode,
      lockType: 'exclusive',
      verified: true,
    },
  };
}

function normalizeInheritedDeploymentLock(lock, expected) {
  const proof = lock?.proof;
  if (
    !lock ||
    typeof lock !== 'object' ||
    typeof lock.assertHeld !== 'function' ||
    !proof ||
    typeof proof !== 'object' ||
    proof.schemaVersion !== INHERITED_DEPLOYMENT_LOCK_PROOF_SCHEMA_VERSION ||
    proof.method !== INHERITED_DEPLOYMENT_LOCK_PROOF_METHOD ||
    proof.fd !== expected.fd ||
    proof.path !== expected.path ||
    proof.lockType !== 'exclusive' ||
    proof.verified !== true
  ) {
    throw new Error(
      'inherited deployment lock verification returned an invalid proof',
    );
  }
  return {
    assertHeld: lock.assertHeld.bind(lock),
    proof: { ...proof },
  };
}

function lockFileIdentity(info) {
  return {
    device: String(info.dev),
    inode: String(info.ino),
  };
}

function assertInheritedLockIdentity(actual, expected, fd, path, label) {
  if (
    actual.device !== expected.device ||
    actual.inode !== expected.inode
  ) {
    throw new Error(
      `inherited deployment lock file descriptor ${fd} does not match ` +
      `${path} before ${label}`,
    );
  }
}

function fdInfoHasExclusiveFlock(fdInfo, expectedInode) {
  for (const line of String(fdInfo).split(/\r?\n/)) {
    const match = line.match(
      /^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+\S+\s+(?:[0-9a-fA-F]+:){2}([0-9]+)\s+0\s+EOF\s*$/,
    );
    if (match?.[1] === expectedInode) return true;
  }
  return false;
}

export async function acquireDeploymentLock({
  path,
  timeoutSeconds,
  flockBin = 'flock',
}) {
  if (typeof path !== 'string' || !path.startsWith('/')) {
    throw new Error('deployment lock path must be absolute');
  }
  const normalizedTimeout = positiveInteger(
    timeoutSeconds,
    'deployment lock timeout',
  );
  const parent = dirname(path);
  if (!existsSync(parent) || !lstatSync(parent).isDirectory()) {
    throw new Error(`deployment lock directory does not exist: ${parent}`);
  }
  if (lstatSync(parent).isSymbolicLink()) {
    throw new Error(`deployment lock directory must not be a symlink: ${parent}`);
  }
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) {
    throw new Error(`deployment lock file must not be a symlink: ${path}`);
  }

  const child = spawn(
    flockBin,
    [
      '-w',
      String(normalizedTimeout),
      path,
      'sh',
      '-c',
      'printf "LOCKED\\n"; cat >/dev/null',
    ],
    {
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  let stdout = '';
  let stderr = '';
  let acquired = false;
  let settled = false;

  const exit = new Promise((resolveExit) => {
    child.once('exit', (code, signal) => {
      exitResult = { code, signal };
      resolveExit({ code, signal });
    });
  });
  let exitResult = null;
  const acquisition = new Promise((resolveAcquired, rejectAcquired) => {
    const fail = (error) => {
      if (settled) return;
      settled = true;
      rejectAcquired(error);
    };
    child.once('error', (error) => {
      fail(new Error(`failed to start deployment lock command: ${error.message}`));
    });
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
      if (!acquired && stdout.includes('LOCKED\n')) {
        acquired = true;
        settled = true;
        resolveAcquired();
      }
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.once('exit', (code, signal) => {
      if (acquired) return;
      fail(new Error(
        `timed out waiting for deployment lock ${path}` +
        (stderr.trim() ? `: ${stderr.trim()}` : '') +
        (signal ? ` (signal ${signal})` : code == null ? '' : ` (exit ${code})`),
      ));
    });
  });

  await acquisition;
  let released = false;
  let lossReported = false;
  const lock = {
    assertHeld(label = 'deployment lock boundary') {
      if (released) {
        throw new Error(`deployment lock was already released before ${label}: ${path}`);
      }
      const result = exitResult;
      if (
        result ||
        child.exitCode != null ||
        child.signalCode != null ||
        child.stdin.destroyed ||
        !child.stdin.writable
      ) {
        lossReported = true;
        throw deploymentLockLostError(path, label, result ?? {
          code: child.exitCode,
          signal: child.signalCode,
        });
      }
      const probe = spawnSync(flockBin, ['-n', path, 'true'], {
        encoding: 'utf8',
      });
      if (probe.error) {
        throw new Error(
          `could not verify deployment lock ownership before ${label}: ` +
          errorMessage(probe.error),
        );
      }
      if (probe.status === 0) {
        lossReported = true;
        throw deploymentLockLostError(path, label, exitResult);
      }
      if (probe.status !== 1) {
        throw new Error(
          `deployment lock ownership probe failed before ${label}: ` +
          `${String(probe.stderr ?? '').trim() || `exit ${probe.status}`}`,
        );
      }
    },
    async release() {
      if (released) return;
      released = true;
      if (!child.stdin.destroyed) child.stdin.end();
      const result = await exit;
      if (result.code !== 0 && !lossReported) {
        throw new Error(
          `deployment lock holder exited abnormally for ${path}` +
          (result.signal ? ` (signal ${result.signal})` : ` (exit ${result.code})`),
        );
      }
    },
  };
  return lock;
}

function normalizeDeploymentLock(lock) {
  if (typeof lock === 'function') {
    return {
      assertHeld:
        typeof lock.assertHeld === 'function'
          ? lock.assertHeld.bind(lock)
          : () => {},
      release: lock,
    };
  }
  if (
    !lock ||
    typeof lock !== 'object' ||
    typeof lock.assertHeld !== 'function' ||
    typeof lock.release !== 'function'
  ) {
    throw new Error('deployment lock acquisition returned an invalid lock handle');
  }
  return lock;
}

function deploymentLockLostError(path, label, result) {
  return new Error(
    `deployment lock holder exited after acquisition before ${label}: ${path}` +
    (result?.signal
      ? ` (signal ${result.signal})`
      : result?.code == null
        ? ''
        : ` (exit ${result.code})`),
  );
}

function fsyncPath(path) {
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function fsyncDirectory(path) {
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function tableExists(db, table) {
  return !!db.prepare(`SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?`).get(table);
}

function indexKeyColumns(db, indexName) {
  return db.prepare(`PRAGMA index_xinfo("${escapeIdentifier(indexName)}")`).all()
    .filter((column) => Number(column.key) === 1)
    .sort((left, right) => Number(left.seqno) - Number(right.seqno))
    .map((column) => column.name);
}

function normalizeIndexPredicate(predicate) {
  let normalized = String(predicate)
    .trim()
    .replace(/;$/, '')
    .replace(/["`\[\]]/g, '')
    .replace(/\s+/g, '')
    .toLowerCase();
  while (normalized.startsWith('(') && normalized.endsWith(')')) {
    normalized = normalized.slice(1, -1);
  }
  return normalized;
}

function normalizeSqlDefault(value) {
  if (value == null) return null;
  let normalized = String(value).trim();
  while (normalized.startsWith('(') && normalized.endsWith(')')) {
    normalized = normalized.slice(1, -1).trim();
  }
  return normalized.replace(/^'(.*)'$/, '$1');
}

function pragmaScalar(db, name) {
  const row = db.prepare(`PRAGMA ${name}`).get();
  return Number(Object.values(row ?? {})[0] ?? 0);
}

function digestJson(value) {
  return digestText(JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item));
}

function digestDomainSeparatedJson(domain, value) {
  return digestText(`${domain}\0${canonicalOperationJson(value)}`);
}

function digestText(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex');
}

function escapeIdentifier(value) {
  return String(value).replaceAll('"', '""');
}

function quoteIdentifier(value) {
  return `"${escapeIdentifier(value)}"`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function fileMatchesIdentity(path, identity) {
  try {
    const current = fileIdentity(path);
    return current.device === identity.device && current.inode === identity.inode;
  } catch {
    return false;
  }
}

function usage() {
  return `Usage:
  npm run promote:quality-db -- --source <quality.db> --destination <primary.db> [--dry-run]
  npm run promote:quality-db -- --source <quality.db> --destination <primary.db> --apply
  openclaw-release-radar-install-release activate ... <quality.db> <score-receipt-id>

The default is a dry-run. Apply never stops processes. The operator must stop and later
restart the service, stop candidate activity, clear active source and destination refresh
leases, and verify both databases are quiescent. Dry-run activity observations are not
durable evidence and never authorize a later apply; apply always revalidates both databases.
Active destination holders are allowed only with an explicit --dry-run. Apply holds
RADAR_DEPLOY_LOCK_PATH (default ${DEFAULT_DEPLOYMENT_LOCK_PATH}) for the complete operation,
using the same flock lock as release activation and rollback. The release installer invokes
apply with a verified pending transaction, --deployment-lock-fd pointing to its inherited
exclusive flock descriptor, and its independently prepared pre-promotion rollback snapshot.
The descriptor must refer to the canonical shared/deploy-promotion.lock inode and remain locked
through every swap, success, and rollback boundary. Those internal arguments are not an
operator API.`;
}

async function main() {
  const args = parsePromotionArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }
  const report = await promoteQualityDb(args);
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(errorMessage(error));
    process.exitCode = 1;
  });
}
